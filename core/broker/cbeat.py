"""Cryptographically Bound Execution Authorization Token (CBEAT) implementation.

Binds approval ID, project, repository, audit run, baseline commit, execution ID,
finding set, scope/evidence/test digests, retry limit, expiry, and single-use nonce
into a canonical deterministic Ed25519-signed token.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Any

from broker.constants import ERR_ALGORITHM_DOWNGRADE, PROTOCOL_VERSION
from broker.crypto import (
    canonical_json_encode,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    sha256_digest,
)
from broker.exceptions import BrokerSecurityError

CBEAT_ALG_ED25519 = "ED25519"
CBEAT_ALG_CNG_ECDSA_P256 = "CNG_ECDSA_P256"
CBEAT_CNG_DOMAIN_SEP = b"ANTIGRAVITY-CBEAT-CNG-ECDSA-P256-V1\x00"


@dataclass(frozen=True)
class CbeatPayload:
    """Canonical CBEAT token payload schema."""

    approval_id: str
    project_key: str
    repo_path: str
    run_id: str
    base_commit: str
    execution_id: str
    approved_finding_ids: tuple[str, ...]
    evidence_digest: str
    allowed_scope_digest: str
    test_policy_digest: str
    max_repair_attempts: int
    issued_at: str
    expires_at: str
    single_use_nonce: str
    protocol_version: str = PROTOCOL_VERSION

    def to_canonical_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary with sorted finding IDs."""
        return {
            "allowed_scope_digest": self.allowed_scope_digest,
            "approval_id": self.approval_id,
            "approved_finding_ids": sorted(list(self.approved_finding_ids)),
            "base_commit": self.base_commit,
            "evidence_digest": self.evidence_digest,
            "execution_id": self.execution_id,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "max_repair_attempts": int(self.max_repair_attempts),
            "project_key": self.project_key,
            "protocol_version": self.protocol_version,
            "repo_path": self.repo_path,
            "run_id": self.run_id,
            "single_use_nonce": self.single_use_nonce,
            "test_policy_digest": self.test_policy_digest,
        }

    def canonical_bytes(self) -> bytes:
        """Produce deterministic canonical bytes for signing/verification."""
        return canonical_json_encode(self.to_canonical_dict())

    def digest(self) -> str:
        """SHA-256 digest of the canonical payload."""
        return sha256_digest(self.canonical_bytes())


@dataclass(frozen=True)
class CbeatToken:
    """Complete signed CBEAT token."""

    payload: CbeatPayload
    signature_hex: str
    public_key_hex: str
    signature_algorithm: str = CBEAT_ALG_ED25519
    key_id: str | None = None
    tpm_backed: bool = False

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "payload": self.payload.to_canonical_dict(),
            "signature_hex": self.signature_hex,
            "public_key_hex": self.public_key_hex,
            "payload_digest": self.payload.digest(),
            "signature_algorithm": self.signature_algorithm,
        }
        if self.key_id is not None:
            out["key_id"] = self.key_id
        if self.signature_algorithm != CBEAT_ALG_ED25519:
            out["tpm_backed"] = bool(self.tpm_backed)
        return out


class CbeatSigner:
    """Abstract signer interface for CBEAT authorization tokens."""

    def sign_payload(self, payload: CbeatPayload) -> CbeatToken:
        raise NotImplementedError

    def get_public_key_bytes(self) -> bytes:
        raise NotImplementedError

    def get_public_key_hex(self) -> str:
        return self.get_public_key_bytes().hex()


class EphemeralCbeatSigner(CbeatSigner):
    """Test-only ephemeral memory signer.

    Used exclusively for test harnesses in NEXT-21C-B2.
    Production key custody is strictly deferred to NEXT-21C-B4 (Windows Service CNG).
    """

    def __init__(self, private_key: bytes | None = None, public_key: bytes | None = None):
        if private_key is None or public_key is None:
            sk, pk = generate_ed25519_keypair()
            self._private_key = sk
            self._public_key = pk
        else:
            self._private_key = private_key
            self._public_key = public_key

    def sign_payload(self, payload: CbeatPayload) -> CbeatToken:
        canonical_bytes = payload.canonical_bytes()
        sig = ed25519_sign(canonical_bytes, self._private_key, self._public_key)
        return CbeatToken(
            payload=payload,
            signature_hex=sig.hex(),
            public_key_hex=self._public_key.hex(),
        )

    def get_public_key_bytes(self) -> bytes:
        return self._public_key


class CbeatVerifier:
    """Verifies CBEAT tokens against authoritative public key(s) and pinned algorithm policy."""

    def __init__(
        self,
        trusted_public_key: bytes | None = None,
        *,
        trusted_public_keys: dict[str, bytes] | None = None,
        allowed_algorithms: set[str] | frozenset[str] | tuple[str, ...] | None = None,
        require_cng: bool = False,
    ) -> None:
        self._trusted_public_key = trusted_public_key
        self._trusted_public_keys = dict(trusted_public_keys) if trusted_public_keys is not None else None
        self._require_cng = bool(require_cng)
        if allowed_algorithms is not None:
            self._allowed_algorithms = frozenset(allowed_algorithms)
        elif require_cng:
            self._allowed_algorithms = frozenset({CBEAT_ALG_CNG_ECDSA_P256})
        elif trusted_public_key is not None and len(trusted_public_key) == 72 and trusted_public_key[:4] == b"ECS1":
            self._allowed_algorithms = frozenset({CBEAT_ALG_CNG_ECDSA_P256})
        elif trusted_public_key is not None and len(trusted_public_key) == 32:
            self._allowed_algorithms = frozenset({CBEAT_ALG_ED25519})
        else:
            self._allowed_algorithms = frozenset({CBEAT_ALG_ED25519, CBEAT_ALG_CNG_ECDSA_P256})

    def _is_trusted_key(self, pk_bytes: bytes, key_id: str | None) -> bool:
        if self._trusted_public_keys is not None:
            if not self._trusted_public_keys:
                return False
            if key_id is not None:
                return self._trusted_public_keys.get(key_id) == pk_bytes
            return pk_bytes in self._trusted_public_keys.values()
        if self._trusted_public_key is not None:
            return pk_bytes == self._trusted_public_key
        return False

    def verify_signature(self, token_data: dict[str, Any]) -> tuple[bool, str, CbeatPayload | None]:
        """Verify the cryptographic signature and structure of a CBEAT token dictionary."""
        try:
            payload_dict = token_data.get("payload")
            sig_hex = token_data.get("signature_hex")
            pk_hex = token_data.get("public_key_hex")
            alg = str(token_data.get("signature_algorithm") or CBEAT_ALG_ED25519)
            key_id = token_data.get("key_id")

            if not payload_dict or not sig_hex or not pk_hex:
                return False, "Missing payload, signature_hex, or public_key_hex in CBEAT token", None

            if alg not in self._allowed_algorithms:
                return False, f"Algorithm '{alg}' rejected by verifier policy (allowed={sorted(self._allowed_algorithms)}, code={ERR_ALGORITHM_DOWNGRADE})", None

            if self._require_cng and alg == CBEAT_ALG_ED25519:
                return False, "Ephemeral Ed25519 tokens are rejected when CNG custody is required", None

            pk_bytes = bytes.fromhex(pk_hex)
            if not self._is_trusted_key(pk_bytes, str(key_id) if key_id is not None else None):
                return False, "Token signed with untrusted public key", None

            sig_bytes = bytes.fromhex(sig_hex)
            if len(sig_bytes) != 64:
                return False, f"Invalid signature length ({len(sig_bytes)} != 64)", None

            # Reconstruct typed payload
            payload = CbeatPayload(
                approval_id=str(payload_dict["approval_id"]),
                project_key=str(payload_dict["project_key"]),
                repo_path=str(payload_dict["repo_path"]),
                run_id=str(payload_dict["run_id"]),
                base_commit=str(payload_dict["base_commit"]),
                execution_id=str(payload_dict["execution_id"]),
                approved_finding_ids=tuple(str(x) for x in payload_dict["approved_finding_ids"]),
                evidence_digest=str(payload_dict["evidence_digest"]),
                allowed_scope_digest=str(payload_dict["allowed_scope_digest"]),
                test_policy_digest=str(payload_dict["test_policy_digest"]),
                max_repair_attempts=int(payload_dict["max_repair_attempts"]),
                issued_at=str(payload_dict["issued_at"]),
                expires_at=str(payload_dict["expires_at"]),
                single_use_nonce=str(payload_dict["single_use_nonce"]),
                protocol_version=str(payload_dict.get("protocol_version", PROTOCOL_VERSION)),
            )

            canonical_bytes = payload.canonical_bytes()
            if alg == CBEAT_ALG_CNG_ECDSA_P256:
                from broker.cng import verify_cng_ecdsa_p256_signature

                digest = hashlib.sha256(CBEAT_CNG_DOMAIN_SEP + canonical_bytes).digest()
                if not verify_cng_ecdsa_p256_signature(pk_bytes, digest, sig_bytes):
                    return False, "CNG ECDSA_P256 digital signature verification failed (tampered payload or invalid key)", None
            elif alg == CBEAT_ALG_ED25519:
                if not ed25519_verify(sig_bytes, canonical_bytes, pk_bytes):
                    return False, "Ed25519 digital signature verification failed (tampered payload or invalid key)", None
            else:
                return False, f"Unsupported signature algorithm '{alg}'", None

            return True, "Signature valid", payload
        except Exception as exc:
            return False, f"Malformed CBEAT token: {exc}", None


def build_cbeat_payload(
    approval_id: str,
    project_key: str,
    repo_path: str,
    run_id: str,
    base_commit: str,
    execution_id: str,
    approved_finding_ids: list[str],
    evidence_digest: str,
    allowed_scope_digest: str,
    test_policy_digest: str,
    max_repair_attempts: int = 2,
    ttl_seconds: int = 3600,
    single_use_nonce: str | None = None,
) -> CbeatPayload:
    """Construct a canonical CbeatPayload with validated invariants."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_seconds))
    if single_use_nonce is None:
        single_use_nonce = secrets.token_hex(16)

    return CbeatPayload(
        approval_id=approval_id,
        project_key=project_key,
        repo_path=repo_path,
        run_id=run_id,
        base_commit=base_commit,
        execution_id=execution_id,
        approved_finding_ids=tuple(sorted(approved_finding_ids)),
        evidence_digest=evidence_digest,
        allowed_scope_digest=allowed_scope_digest,
        test_policy_digest=test_policy_digest,
        max_repair_attempts=max_repair_attempts,
        issued_at=now,
        expires_at=expires,
        single_use_nonce=single_use_nonce,
        protocol_version=PROTOCOL_VERSION,
    )

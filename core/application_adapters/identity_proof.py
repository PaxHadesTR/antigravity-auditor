"""Challenge-response HMAC-SHA256 adapter proof manager & NEXT-22C verifier bridge."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import hmac
import secrets
import time
from typing import Callable

from broker.security import ClientIdentity
from entitlement_router.privacy import validate_opaque_id
from mcp_gateway.authenticated_context import (
    AdapterIdentityProof,
    AdapterProofVerifier,
)

from application_adapters.contracts import (
    AdapterChallenge,
    AdapterProofVerificationResult,
    IdentityVerificationStatus,
    ProcessObservation,
    SignedAdapterProof,
)
from application_adapters.credential_provider import (
    AdapterCredentialProvider,
    DisabledProductionCredentialProvider,
)

DEFAULT_CHALLENGE_TTL_SECONDS = 60
MAX_CHALLENGE_TTL_SECONDS = 300
ALLOWED_CLOCK_SKEW_SECONDS = 5


def build_canonical_proof_message(
    *,
    key_id: str,
    key_version: int,
    challenge_id: str,
    nonce: str,
    adapter_id: str,
    application_id: str,
    application_instance_id: str,
    pid: int,
    process_creation_time_100ns: int,
    os_sid: str,
    issued_at_epoch: int,
    expires_at_epoch: int,
    expected_parent_pid: int | None = None,
    expected_parent_creation_time_100ns: int | None = None,
) -> bytes:
    """Domain-separated canonical payload for HMAC-SHA256 challenge-response."""
    fields = (
        "next22d-adapter-proof-v1",
        key_id,
        str(int(key_version)),
        challenge_id,
        nonce,
        adapter_id,
        application_id,
        application_instance_id,
        str(int(pid)),
        str(int(process_creation_time_100ns)),
        os_sid,
        str(int(issued_at_epoch)),
        str(int(expires_at_epoch)),
        str(int(expected_parent_pid)) if expected_parent_pid is not None else "",
        str(int(expected_parent_creation_time_100ns)) if expected_parent_creation_time_100ns is not None else "",
    )
    return "|".join(fields).encode("utf-8")


class ChallengeReplayCache:
    """Bounded replay guard rejecting duplicate nonces/challenge IDs."""

    def __init__(self, max_entries: int = 4096) -> None:
        self._seen: set[tuple[str, str]] = set()
        self._order: deque[tuple[str, str]] = deque()
        self._max_entries = max(64, int(max_entries))

    def has_seen(self, challenge_id: str, nonce: str) -> bool:
        return (challenge_id, nonce) in self._seen

    def mark_consumed(self, challenge_id: str, nonce: str) -> bool:
        key = (challenge_id, nonce)
        if key in self._seen:
            return False
        if len(self._order) >= self._max_entries:
            oldest = self._order.popleft()
            self._seen.discard(oldest)
        self._seen.add(key)
        self._order.append(key)
        return True


class AdapterChallengeManager:
    """Issues, signs (test-only), and verifies fresh process-bound HMAC adapter proofs."""

    def __init__(
        self,
        *,
        credential_provider: AdapterCredentialProvider | None = None,
        clock: Callable[[], int] | None = None,
        ttl_seconds: int = DEFAULT_CHALLENGE_TTL_SECONDS,
    ) -> None:
        self.credential_provider: AdapterCredentialProvider = (
            credential_provider or DisabledProductionCredentialProvider()
        )
        self._clock = clock or (lambda: int(time.time()))
        self._ttl_seconds = max(5, min(int(ttl_seconds), MAX_CHALLENGE_TTL_SECONDS))
        self._issued_challenges: dict[str, AdapterChallenge] = {}
        self._replay_cache = ChallengeReplayCache()

    def issue_challenge(
        self,
        *,
        adapter_id: str,
        application_id: str,
        application_instance_id: str,
        process_obs: ProcessObservation,
        os_identity: ClientIdentity,
        key_id: str,
        key_version: int = 1,
    ) -> AdapterChallenge:
        if not os_identity.verified_by_os or not os_identity.sid:
            raise PermissionError("Cannot issue adapter challenge without verified OS SID.")
        if process_obs.process_creation_time_100ns is None:
            raise PermissionError("Cannot bind adapter challenge without process creation time.")
        now = int(self._clock())
        challenge = AdapterChallenge(
            challenge_id=f"chl-{secrets.token_hex(12)}",
            nonce=secrets.token_hex(16),
            adapter_id=adapter_id,
            application_id=application_id,
            application_instance_id=application_instance_id,
            expected_pid=int(process_obs.pid),
            expected_creation_time_100ns=int(process_obs.process_creation_time_100ns),
            expected_os_sid=os_identity.sid,
            key_id=key_id,
            key_version=int(key_version),
            issued_at_epoch=now,
            expires_at_epoch=now + self._ttl_seconds,
            expected_parent_pid=process_obs.parent_pid,
            expected_parent_creation_time_100ns=process_obs.parent_creation_time_100ns,
        )
        # Drop expired challenges so a long-lived host does not accumulate them.
        for cid in [c for c, ch in self._issued_challenges.items() if ch.expires_at_epoch < now]:
            del self._issued_challenges[cid]
        self._issued_challenges[challenge.challenge_id] = challenge
        return challenge

    def sign_challenge(
        self,
        challenge: AdapterChallenge,
        *,
        signing_provider: AdapterCredentialProvider | None = None,
    ) -> SignedAdapterProof:
        provider = signing_provider or self.credential_provider
        if not provider.is_enabled:
            raise PermissionError("CREDENTIAL_PROVIDER_DISABLED: Cannot sign adapter challenge.")
        msg = build_canonical_proof_message(
            key_id=challenge.key_id,
            key_version=challenge.key_version,
            challenge_id=challenge.challenge_id,
            nonce=challenge.nonce,
            adapter_id=challenge.adapter_id,
            application_id=challenge.application_id,
            application_instance_id=challenge.application_instance_id,
            pid=challenge.expected_pid,
            process_creation_time_100ns=challenge.expected_creation_time_100ns,
            os_sid=challenge.expected_os_sid,
            issued_at_epoch=challenge.issued_at_epoch,
            expires_at_epoch=challenge.expires_at_epoch,
            expected_parent_pid=challenge.expected_parent_pid,
            expected_parent_creation_time_100ns=challenge.expected_parent_creation_time_100ns,
        )
        mac = provider.sign_digest(challenge.key_id, challenge.key_version, msg)
        return SignedAdapterProof(
            challenge_id=challenge.challenge_id,
            nonce=challenge.nonce,
            key_id=challenge.key_id,
            key_version=challenge.key_version,
            adapter_id=challenge.adapter_id,
            application_id=challenge.application_id,
            application_instance_id=challenge.application_instance_id,
            pid=challenge.expected_pid,
            process_creation_time_100ns=challenge.expected_creation_time_100ns,
            expected_os_sid=challenge.expected_os_sid,
            issued_at_epoch=challenge.issued_at_epoch,
            expires_at_epoch=challenge.expires_at_epoch,
            proof_hmac=mac,
            expected_parent_pid=challenge.expected_parent_pid,
            expected_parent_creation_time_100ns=challenge.expected_parent_creation_time_100ns,
        )

    def verify_proof(
        self,
        proof: SignedAdapterProof | None,
        *,
        os_identity: ClientIdentity | None,
        process_obs: ProcessObservation | None,
    ) -> AdapterProofVerificationResult:
        if not self.credential_provider.is_enabled:
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.UNVERIFIED,
                reason_code="CREDENTIAL_PROVIDER_DISABLED",
                reason="Adapter credential provider is disabled; application_id defaults to UNKNOWN.",
                audit_evidence={"provider_enabled": False},
            )

        if proof is None:
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.UNVERIFIED,
                reason_code="MISSING_ADAPTER_PROOF",
                reason="No signed adapter proof supplied; application_id remains UNKNOWN.",
                audit_evidence={"proof_present": False},
            )

        audit_base = proof.to_audit_dict()
        if os_identity is None or not os_identity.verified_by_os or not os_identity.sid:
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="OS_IDENTITY_UNVERIFIED",
                reason="Adapter proof requires OS-verified ClientIdentity.",
                audit_evidence=audit_base,
            )

        if os_identity.is_low_integrity or os_identity.integrity_level.upper() in ("LOW", "UNTRUSTED", "UNKNOWN"):
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="LOW_INTEGRITY_REJECTED",
                reason="Low-integrity client process cannot verify adapter identity.",
                audit_evidence=audit_base,
            )

        if proof.expected_os_sid != os_identity.sid:
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="OS_SID_MISMATCH",
                reason="Proof SID does not match OS-verified ClientIdentity SID.",
                audit_evidence=audit_base,
            )

        if process_obs is None or process_obs.process_creation_time_100ns is None:
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="PROCESS_EVIDENCE_MISSING",
                reason="Adapter proof requires PID and process creation time binding.",
                audit_evidence=audit_base,
            )

        if (
            int(proof.pid) != int(process_obs.pid)
            or int(proof.process_creation_time_100ns) != int(process_obs.process_creation_time_100ns)
        ):
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="PROCESS_BINDING_MISMATCH",
                reason="Adapter proof PID or creation time does not match observed adapter process.",
                audit_evidence=audit_base,
            )

        if (
            proof.expected_parent_pid is not None
            and process_obs.parent_pid is not None
            and int(proof.expected_parent_pid) != int(process_obs.parent_pid)
        ) or (
            proof.expected_parent_creation_time_100ns is not None
            and process_obs.parent_creation_time_100ns is not None
            and int(proof.expected_parent_creation_time_100ns) != int(process_obs.parent_creation_time_100ns)
        ):
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="PARENT_PROCESS_MISMATCH",
                reason="Observed parent process PID or creation time does not match challenge binding.",
                audit_evidence=audit_base,
            )

        issued = self._issued_challenges.get(proof.challenge_id)
        if issued is None:
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="UNKNOWN_CHALLENGE_ID",
                reason="Adapter challenge_id was not issued by this session.",
                audit_evidence=audit_base,
            )

        if (
            issued.nonce != proof.nonce
            or issued.adapter_id != proof.adapter_id
            or issued.application_id != proof.application_id
            or issued.application_instance_id != proof.application_instance_id
            or issued.key_id != proof.key_id
            or issued.key_version != proof.key_version
        ):
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="CHALLENGE_BINDING_MISMATCH",
                reason="Proof metadata does not match the issued server challenge.",
                audit_evidence=audit_base,
            )

        if self._replay_cache.has_seen(proof.challenge_id, proof.nonce):
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="PROOF_REPLAYED",
                reason="Challenge nonce already consumed; replay rejected.",
                audit_evidence=audit_base,
            )

        now = int(self._clock())
        if proof.issued_at_epoch > now + ALLOWED_CLOCK_SKEW_SECONDS or now > proof.expires_at_epoch:
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="PROOF_EXPIRED_OR_FUTURE",
                reason="Adapter challenge-response proof is outside its valid freshness window.",
                audit_evidence=audit_base,
            )

        key = self.credential_provider.get_key(proof.key_id, proof.key_version)
        if key is None:
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="KEY_NOT_FOUND",
                reason="Adapter key ID/version not provisioned.",
                audit_evidence=audit_base,
            )

        msg = build_canonical_proof_message(
            key_id=proof.key_id,
            key_version=proof.key_version,
            challenge_id=proof.challenge_id,
            nonce=proof.nonce,
            adapter_id=proof.adapter_id,
            application_id=proof.application_id,
            application_instance_id=proof.application_instance_id,
            pid=proof.pid,
            process_creation_time_100ns=proof.process_creation_time_100ns,
            os_sid=proof.expected_os_sid,
            issued_at_epoch=proof.issued_at_epoch,
            expires_at_epoch=proof.expires_at_epoch,
            expected_parent_pid=proof.expected_parent_pid,
            expected_parent_creation_time_100ns=proof.expected_parent_creation_time_100ns,
        )
        expected_hmac = hmac.new(key, msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_hmac, proof.proof_hmac or ""):
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="INVALID_ADAPTER_HMAC",
                reason="HMAC-SHA256 verification failed in constant-time comparison.",
                audit_evidence=audit_base,
            )

        if not self._replay_cache.mark_consumed(proof.challenge_id, proof.nonce):
            return AdapterProofVerificationResult(
                verified=False,
                status=IdentityVerificationStatus.REJECTED,
                reason_code="PROOF_REPLAYED",
                reason="Challenge nonce already consumed; replay rejected.",
                audit_evidence=audit_base,
            )

        return AdapterProofVerificationResult(
            verified=True,
            status=IdentityVerificationStatus.VERIFIED,
            reason_code="ADAPTER_CHALLENGE_PROOF_VERIFIED",
            reason="Process-bound HMAC-SHA256 challenge-response verified (test/non-production provider).",
            application_id=proof.application_id,
            application_instance_id=proof.application_instance_id,
            adapter_id=proof.adapter_id,
            production_ready=False,
            audit_evidence={**audit_base, "replay_consumed": True},
        )


@dataclass
class ChallengeBoundAdapterProofVerifier(AdapterProofVerifier):
    """Bridges SignedAdapterProof / AdapterChallengeManager into NEXT-22C CallerIdentityResolver."""

    challenge_manager: AdapterChallengeManager
    process_obs: ProcessObservation | None = None
    _last_results: dict[str, AdapterProofVerificationResult] | None = None

    def register_signed_proof(self, signed_proof: SignedAdapterProof) -> AdapterIdentityProof:
        if self._last_results is None:
            self._last_results = {}
        validate_opaque_id(signed_proof.challenge_id, field_name="challenge_id")
        return AdapterIdentityProof(
            application_id=signed_proof.application_id,
            application_instance_id=signed_proof.application_instance_id,
            adapter_id=signed_proof.adapter_id,
            proof_token=f"chlref:{signed_proof.challenge_id}",
            expected_os_sid=signed_proof.expected_os_sid,
            proof_method="hmac_sha256_challenge_v1",
        )

    def bind_proofs(self) -> dict[str, SignedAdapterProof]:
        if not hasattr(self, "_signed_by_id"):
            self._signed_by_id: dict[str, SignedAdapterProof] = {}
        return self._signed_by_id

    def to_gateway_proof(self, signed_proof: SignedAdapterProof) -> AdapterIdentityProof:
        self.bind_proofs()[signed_proof.challenge_id] = signed_proof
        return self.register_signed_proof(signed_proof)

    def verify(
        self,
        proof: AdapterIdentityProof,
        *,
        os_identity: ClientIdentity | None,
    ) -> tuple[bool, str]:
        tok = proof.proof_token or ""
        if not tok.startswith("chlref:"):
            return False, "UNSUPPORTED_ADAPTER_PROOF_FORMAT"
        cid = tok.split("chlref:", 1)[1]
        signed = self.bind_proofs().get(cid)
        res = self.challenge_manager.verify_proof(
            signed,
            os_identity=os_identity,
            process_obs=self.process_obs,
        )
        if self._last_results is None:
            self._last_results = {}
        self._last_results[cid] = res
        return res.verified, res.reason_code

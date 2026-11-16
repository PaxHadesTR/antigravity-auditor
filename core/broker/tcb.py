"""Trusted Confirmation Boundary (B4B-TCB) for Antigravity Auditor NEXT-21C-B4-B.

Addresses RISK-B2R-02 (sequential Medium-IL call chain bypassing human approval):
- Binds interactive human confirmation cryptographically to canonical transaction
  details computed authoritatively inside BrokerDatabaseAdapter.
- Enforces CSPRNG single-use challenges with bounded TTL and atomic SQLite consumption.
- Verifies FIDO2 / WebAuthn ES256 assertions using native Windows `bcrypt.dll`
  (`BCryptVerifySignature`) against server-pinned authenticator public keys only.
- Exposes real OS Windows Hello / `webauthn.dll` capability & interactive invocation
  interfaces without faking UI, exporting biometric secrets, auto-enrolling
  credentials, or mistaking Windows UAC / High-IL elevation for per-transaction consent.
"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
import hashlib
import json
import os
import secrets
import shutil
import subprocess
from typing import Any

from broker.cng import verify_cng_ecdsa_p256_signature
from broker.constants import (
    ERR_ACCESS_DENIED,
    ERR_APPROVAL_EXPIRED,
    ERR_CONFIRMATION_FAILED,
    ERR_CONFIRMATION_REQUIRED,
    ERR_REPLAY_ATTEMPT,
    ERR_SCOPE_VIOLATION,
)
from broker.crypto import canonical_json_encode, sha256_digest
from broker.exceptions import (
    BrokerConfirmationError,
    BrokerConfirmationRequiredError,
    BrokerSchemaError,
    BrokerSecurityError,
)
from broker.security import is_windows

TCB_DOMAIN_SEP = "ANTIGRAVITY-TCB-V1"
TCB_PROOF_WEBAUTHN_ES256 = "WEBAUTHN_ES256"
TCB_DEFAULT_RP_ID = "antigravity-auditor.local"
TCB_DEFAULT_ORIGIN = "https://antigravity-auditor.local"
TCB_DEFAULT_TTL_SECONDS = 120
TCB_MIN_TTL_SECONDS = 10
TCB_MAX_TTL_SECONDS = 600

# WebAuthn / CTAP2 authenticatorData flags (W3C WebAuthn Level 2/3)
WEBAUTHN_FLAG_UP = 0x01  # User Present
WEBAUTHN_FLAG_UV = 0x04  # User Verified
WEBAUTHN_FLAG_BE = 0x08
WEBAUTHN_FLAG_BS = 0x10
WEBAUTHN_FLAG_AT = 0x40
WEBAUTHN_FLAG_ED = 0x80

# Caller-supplied parameters that MUST NEVER be trusted as Trusted Confirmation
FORBIDDEN_TCB_OVERRIDE_PARAMS = frozenset({
    "bypass_tcb",
    "tcb_override",
    "confirmed",
    "user_verified",
    "uac_elevated",
    "elevation_verified",
    "skip_confirmation",
    "public_key_hex",
    "trusted_public_key",
})


def b64url_encode_nopad(data: bytes) -> str:
    """RFC 4648 base64url encoding without '=' padding (WebAuthn standard)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode_nopad(text: str) -> bytes:
    """Decode RFC 4648 base64url (with or without padding) or standard base64."""
    if not isinstance(text, str) or not text:
        raise BrokerSchemaError("Base64url input must be a non-empty string.")
    cleaned = text.strip()
    pad_len = (-len(cleaned)) % 4
    try:
        return base64.urlsafe_b64decode(cleaned + ("=" * pad_len))
    except Exception as exc:
        raise BrokerSchemaError(f"Invalid base64url payload: {exc}") from exc


def ec_public_key_to_ecs1(public_key_bytes: bytes) -> bytes:
    """Normalize a P-256 public key into 72-byte CNG BCRYPT_ECCPUBLIC_BLOB (`ECS1`).

    Accepts:
    - 72-byte CNG `ECS1` blob (`b"ECS1\\x20\\x00\\x00\\x00" + X(32) + Y(32)`)
    - 65-byte SEC1 uncompressed EC point (`0x04 || X(32) || Y(32)`)
    """
    if len(public_key_bytes) == 72 and public_key_bytes[:8] == b"ECS1\x20\x00\x00\x00":
        return public_key_bytes
    if len(public_key_bytes) == 65 and public_key_bytes[0] == 0x04:
        return b"ECS1\x20\x00\x00\x00" + public_key_bytes[1:]
    raise BrokerConfirmationError(
        "Trusted authenticator public key must be a 72-byte CNG ECS1 blob or 65-byte uncompressed P-256 point.",
        code=ERR_CONFIRMATION_FAILED,
    )


def normalize_ecdsa_p256_signature(signature: bytes) -> bytes:
    """Normalize IEEE P1363 (64B `r||s`) or ASN.1 DER ECDSA signature into 64-byte `r||s`."""
    if len(signature) == 64:
        return signature

    # Strict ASN.1 DER SEQ { INTEGER r, INTEGER s }
    if len(signature) < 8 or signature[0] != 0x30:
        raise BrokerConfirmationError("Invalid ECDSA signature encoding.", code=ERR_CONFIRMATION_FAILED)
    seq_len = signature[1]
    if seq_len & 0x80 or 2 + seq_len != len(signature):
        raise BrokerConfirmationError("Malformed DER ECDSA sequence length.", code=ERR_CONFIRMATION_FAILED)

    pos = 2
    coords: list[bytes] = []
    for _ in range(2):
        if pos + 2 > len(signature) or signature[pos] != 0x02:
            raise BrokerConfirmationError("Malformed DER ECDSA integer tag.", code=ERR_CONFIRMATION_FAILED)
        int_len = signature[pos + 1]
        pos += 2
        if int_len == 0 or pos + int_len > len(signature):
            raise BrokerConfirmationError("Malformed DER ECDSA integer length.", code=ERR_CONFIRMATION_FAILED)
        raw_int = signature[pos : pos + int_len]
        pos += int_len
        if raw_int[0] & 0x80:
            raise BrokerConfirmationError("Negative integer in DER ECDSA signature.", code=ERR_CONFIRMATION_FAILED)
        if len(raw_int) > 1 and raw_int[0] == 0x00 and not (raw_int[1] & 0x80):
            raise BrokerConfirmationError("Non-canonical DER ECDSA integer padding.", code=ERR_CONFIRMATION_FAILED)
        trimmed = raw_int[1:] if (len(raw_int) > 1 and raw_int[0] == 0x00) else raw_int
        if len(trimmed) == 0 or all(b == 0 for b in trimmed):
            raise BrokerConfirmationError("Zero scalar in DER ECDSA signature.", code=ERR_CONFIRMATION_FAILED)
        if len(trimmed) > 32:
            raise BrokerConfirmationError("Oversized P-256 signature scalar.", code=ERR_CONFIRMATION_FAILED)
        coords.append(trimmed.rjust(32, b"\x00"))

    if pos != len(signature):
        raise BrokerConfirmationError("Trailing bytes in DER ECDSA signature.", code=ERR_CONFIRMATION_FAILED)
    return coords[0] + coords[1]


def compute_tcb_request_digest(
    *,
    project_key: str,
    repo_path: str,
    run_id: str,
    base_commit: str,
    execution_id: str,
    approved_finding_ids: list[str] | tuple[str, ...],
    evidence_digest: str,
    allowed_scope_digest: str,
    test_policy_digest: str,
    max_repair_attempts: int = 2,
    working_tree_hash: str = "",
) -> str:
    """Compute canonical SHA-256 hex digest binding exact approved transaction parameters."""
    payload = {
        "tcb_version": "TCB-V1",
        "project_key": str(project_key),
        "repo_path": str(repo_path),
        "run_id": str(run_id),
        "base_commit": str(base_commit),
        "execution_id": str(execution_id),
        "approved_finding_ids": sorted(str(fid) for fid in approved_finding_ids),
        "evidence_digest": str(evidence_digest),
        "allowed_scope_digest": str(allowed_scope_digest),
        "test_policy_digest": str(test_policy_digest),
        "max_repair_attempts": int(max_repair_attempts),
        "working_tree_hash": str(working_tree_hash or ""),
    }
    return sha256_digest(canonical_json_encode(payload))


def compute_tcb_binding_digest(
    challenge_id: str,
    challenge_nonce: str,
    canonical_request_digest: str,
) -> bytes:
    """Compute domain-separated 32-byte WebAuthn challenge digest from challenge + request."""
    material = f"{TCB_DOMAIN_SEP}:{challenge_id}:{challenge_nonce}:{canonical_request_digest}".encode("utf-8")
    return hashlib.sha256(material).digest()


def mint_challenge_id() -> str:
    return f"TCB-{secrets.token_hex(12)}"


def mint_challenge_nonce() -> str:
    return secrets.token_hex(16)


@dataclass(frozen=True)
class TcbTrustedAuthenticator:
    """Server-pinned trusted authenticator public key (never supplied by RPC client)."""

    credential_id: str
    public_key_ecs1: bytes
    rp_id: str = TCB_DEFAULT_RP_ID
    allowed_origins: tuple[str, ...] = (TCB_DEFAULT_ORIGIN,)
    label: str = ""

    @classmethod
    def from_public_key(
        cls,
        credential_id: str,
        public_key_bytes: bytes,
        *,
        rp_id: str = TCB_DEFAULT_RP_ID,
        allowed_origins: tuple[str, ...] = (TCB_DEFAULT_ORIGIN,),
        label: str = "",
    ) -> "TcbTrustedAuthenticator":
        return cls(
            credential_id=str(credential_id),
            public_key_ecs1=ec_public_key_to_ecs1(public_key_bytes),
            rp_id=str(rp_id),
            allowed_origins=tuple(str(o) for o in allowed_origins),
            label=str(label),
        )


@dataclass(frozen=True)
class TcbPolicy:
    """Immutable server-side Trusted Confirmation policy."""

    require_tcb: bool = False
    rp_id: str = TCB_DEFAULT_RP_ID
    allowed_origins: tuple[str, ...] = (TCB_DEFAULT_ORIGIN,)
    default_ttl_seconds: int = TCB_DEFAULT_TTL_SECONDS
    require_up: bool = True
    require_uv: bool = True
    strict_monotonic_sign_count: bool = True


@dataclass(frozen=True)
class TcbVerifiedProof:
    """Verified confirmation proof metadata ready for audit logging & DB atomic update."""

    proof_type: str
    challenge_id: str
    credential_id: str
    rp_id_hash_hex: str
    flags: int
    user_present: bool
    user_verified: bool
    sign_count: int


class TcbVerifier:
    """Verifies broker-issued TCB challenges and WebAuthn ES256 confirmation assertions."""

    def __init__(
        self,
        *,
        policy: TcbPolicy | None = None,
        trusted_authenticators: dict[str, TcbTrustedAuthenticator] | None = None,
    ) -> None:
        self.policy = policy or TcbPolicy()
        self._authenticators: dict[str, TcbTrustedAuthenticator] = dict(trusted_authenticators or {})

    @property
    def configured_authenticator_ids(self) -> list[str]:
        return sorted(self._authenticators.keys())

    @property
    def has_trusted_authenticators(self) -> bool:
        return bool(self._authenticators)

    def get_status_summary(self) -> dict[str, Any]:
        return {
            "require_tcb": self.policy.require_tcb,
            "rp_id": self.policy.rp_id,
            "allowed_origins": list(self.policy.allowed_origins),
            "default_ttl_seconds": self.policy.default_ttl_seconds,
            "trusted_authenticator_count": len(self._authenticators),
            "trusted_credential_ids": self.configured_authenticator_ids,
        }

    def verify_confirmation_proof(
        self,
        confirmation: dict[str, Any] | None,
        *,
        expected_challenge_id: str,
        expected_challenge_nonce: str,
        expected_request_digest: str,
        previous_sign_count: int = 0,
    ) -> TcbVerifiedProof:
        """Fail-closed verification of a Trusted Confirmation proof dict."""
        if confirmation is None or not isinstance(confirmation, dict):
            raise BrokerConfirmationRequiredError(
                "Trusted Confirmation proof is required for execution authorization.",
                code=ERR_CONFIRMATION_REQUIRED,
            )

        # Reject caller attempts to inject override booleans or public keys
        spoofed = sorted(k for k in FORBIDDEN_TCB_OVERRIDE_PARAMS if k in confirmation)
        if spoofed:
            raise BrokerSecurityError(
                f"Forbidden client-supplied TCB override/key fields rejected: {', '.join(spoofed)}.",
                code=ERR_ACCESS_DENIED,
                data={"forbidden_fields": spoofed},
            )

        if not self._authenticators:
            raise BrokerConfirmationRequiredError(
                "No server-pinned trusted TCB authenticators configured (AUTHENTICATOR_UNAVAILABLE).",
                code=ERR_CONFIRMATION_REQUIRED,
                data={"status": "AUTHENTICATOR_UNAVAILABLE"},
            )

        proof_type = str(confirmation.get("proof_type") or "")
        if proof_type != TCB_PROOF_WEBAUTHN_ES256:
            raise BrokerConfirmationError(
                f"Unsupported or missing TCB proof_type '{proof_type}'. "
                f"Expected '{TCB_PROOF_WEBAUTHN_ES256}'. UAC elevation/booleans are never accepted.",
                code=ERR_CONFIRMATION_FAILED,
            )

        challenge_id = str(confirmation.get("challenge_id") or "")
        challenge_nonce = str(confirmation.get("challenge_nonce") or "")
        credential_id = str(confirmation.get("credential_id") or "")
        if challenge_id != expected_challenge_id or challenge_nonce != expected_challenge_nonce:
            raise BrokerConfirmationError(
                "TCB confirmation challenge_id or challenge_nonce mismatch.",
                code=ERR_CONFIRMATION_FAILED,
            )

        auth_entry = self._authenticators.get(credential_id)
        if auth_entry is None:
            raise BrokerConfirmationError(
                f"Untrusted or unknown TCB credential_id '{credential_id}'.",
                code=ERR_CONFIRMATION_FAILED,
            )

        # 1. Decode and validate clientDataJSON
        client_data_raw = confirmation.get("client_data_json_b64")
        if client_data_raw is not None:
            client_data_bytes = b64url_decode_nopad(str(client_data_raw))
        elif confirmation.get("client_data_json") is not None:
            client_data_bytes = str(confirmation["client_data_json"]).encode("utf-8")
        else:
            raise BrokerConfirmationError("Missing client_data_json in TCB proof.", code=ERR_CONFIRMATION_FAILED)

        try:
            client_data = json.loads(client_data_bytes.decode("utf-8"))
        except Exception as exc:
            raise BrokerConfirmationError(f"Malformed clientDataJSON: {exc}", code=ERR_CONFIRMATION_FAILED) from exc

        if not isinstance(client_data, dict):
            raise BrokerConfirmationError("clientDataJSON must be a JSON object.", code=ERR_CONFIRMATION_FAILED)

        if client_data.get("type") != "webauthn.get":
            raise BrokerConfirmationError(
                f"Invalid WebAuthn clientDataJSON.type '{client_data.get('type')}'.",
                code=ERR_CONFIRMATION_FAILED,
            )

        origin = str(client_data.get("origin") or "")
        allowed_origins = set(auth_entry.allowed_origins) & set(self.policy.allowed_origins)
        if not allowed_origins:
            allowed_origins = set(auth_entry.allowed_origins)
        if origin not in allowed_origins:
            raise BrokerConfirmationError(
                f"WebAuthn origin '{origin}' rejected (allowed={sorted(allowed_origins)}).",
                code=ERR_CONFIRMATION_FAILED,
            )

        expected_binding = compute_tcb_binding_digest(
            expected_challenge_id, expected_challenge_nonce, expected_request_digest
        )
        expected_challenge_b64 = b64url_encode_nopad(expected_binding)
        if str(client_data.get("challenge") or "") != expected_challenge_b64:
            raise BrokerConfirmationError(
                "WebAuthn clientDataJSON.challenge does not match canonical request binding digest.",
                code=ERR_CONFIRMATION_FAILED,
            )

        # 2. Decode and verify CTAP2 / WebAuthn authenticatorData
        auth_data_b64 = confirmation.get("authenticator_data_b64")
        if auth_data_b64 is None:
            raise BrokerConfirmationError("Missing authenticator_data_b64 in TCB proof.", code=ERR_CONFIRMATION_FAILED)
        auth_data = b64url_decode_nopad(str(auth_data_b64))
        if len(auth_data) < 37:
            raise BrokerConfirmationError("authenticatorData shorter than 37 bytes.", code=ERR_CONFIRMATION_FAILED)

        rp_hash = auth_data[:32]
        expected_rp_hash = hashlib.sha256(auth_entry.rp_id.encode("utf-8")).digest()
        if rp_hash != expected_rp_hash:
            raise BrokerConfirmationError("WebAuthn rpIdHash mismatch.", code=ERR_CONFIRMATION_FAILED)

        flags = int(auth_data[32])
        user_present = bool(flags & WEBAUTHN_FLAG_UP)
        user_verified = bool(flags & WEBAUTHN_FLAG_UV)
        if self.policy.require_up and not user_present:
            raise BrokerConfirmationError(
                "WebAuthn assertion rejected: User Presence (UP=1) flag is not set.",
                code=ERR_CONFIRMATION_FAILED,
            )
        if self.policy.require_uv and not user_verified:
            raise BrokerConfirmationError(
                "WebAuthn assertion rejected: User Verification (UV=1) flag is not set.",
                code=ERR_CONFIRMATION_FAILED,
            )

        sign_count = int.from_bytes(auth_data[33:37], "big")
        if self.policy.strict_monotonic_sign_count and sign_count <= int(previous_sign_count):
            raise BrokerConfirmationError(
                f"WebAuthn signCount rollback or replay detected ({sign_count} <= {previous_sign_count}).",
                code=ERR_REPLAY_ATTEMPT,
            )

        # 3. Verify ES256 assertion signature via native Windows bcrypt.dll
        sig_b64 = confirmation.get("signature_b64")
        if sig_b64 is None:
            raise BrokerConfirmationError("Missing signature_b64 in TCB proof.", code=ERR_CONFIRMATION_FAILED)
        raw_sig = b64url_decode_nopad(str(sig_b64))
        p1363_sig = normalize_ecdsa_p256_signature(raw_sig)

        client_data_hash = hashlib.sha256(client_data_bytes).digest()
        signed_digest = hashlib.sha256(auth_data + client_data_hash).digest()
        sig_ok = verify_cng_ecdsa_p256_signature(auth_entry.public_key_ecs1, signed_digest, p1363_sig)
        if not sig_ok:
            raise BrokerConfirmationError(
                "WebAuthn ES256 assertion cryptographic signature verification failed.",
                code=ERR_CONFIRMATION_FAILED,
            )

        return TcbVerifiedProof(
            proof_type=TCB_PROOF_WEBAUTHN_ES256,
            challenge_id=challenge_id,
            credential_id=credential_id,
            rp_id_hash_hex=rp_hash.hex(),
            flags=flags,
            user_present=user_present,
            user_verified=user_verified,
            sign_count=sign_count,
        )


def _is_interactive_user_session() -> bool:
    """Return True if process runs in an interactive user logon session (SessionId > 0)."""
    if not is_windows():
        return False
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetCurrentProcessId.argtypes = []
        k32.GetCurrentProcessId.restype = wintypes.DWORD
        k32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        k32.ProcessIdToSessionId.restype = wintypes.BOOL
        sid = wintypes.DWORD(0)
        ok = k32.ProcessIdToSessionId(k32.GetCurrentProcessId(), ctypes.byref(sid))
        return bool(ok and sid.value > 0)
    except Exception:
        return False


def probe_webauthn_platform_authenticator() -> dict[str, Any]:
    """Query native `webauthn.dll` for API version and User-Verifying Platform Authenticator availability."""
    if not is_windows():
        return {"supported": False, "available": False, "api_version": 0}
    try:
        wa = ctypes.WinDLL("webauthn.dll")
        wa.WebAuthNGetApiVersionNumber.argtypes = []
        wa.WebAuthNGetApiVersionNumber.restype = wintypes.DWORD
        wa.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.argtypes = [ctypes.POINTER(wintypes.BOOL)]
        wa.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.restype = ctypes.c_long

        api_ver = int(wa.WebAuthNGetApiVersionNumber())
        uvpa = wintypes.BOOL(0)
        hr = wa.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(ctypes.byref(uvpa))
        return {
            "supported": True,
            "api_version": api_ver,
            "hr": hex(hr & 0xFFFFFFFF),
            "available": bool(hr == 0 and uvpa.value),
        }
    except Exception as exc:
        return {"supported": False, "available": False, "error": str(exc)}


def probe_windows_hello_consent_availability(*, timeout_seconds: int = 10) -> dict[str, Any]:
    """Query WinRT `Windows.Security.Credentials.UI.UserConsentVerifier::CheckAvailabilityAsync` read-only."""
    if not is_windows():
        return {"supported": False, "availability": "NotSupported"}
    ps_exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not ps_exe:
        return {"supported": False, "availability": "PowerShellUnavailable"}

    ps_script = (
        "$ErrorActionPreference='Stop'; "
        "Add-Type -AssemblyName System.Runtime.WindowsRuntime; "
        "[void][Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]; "
        "$op=[Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync(); "
        "$avail=[Windows.Security.Credentials.UI.UserConsentVerifierAvailability]; "
        "$asTask=[System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { "
        "$_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and "
        "$_.GetGenericArguments().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -like 'IAsyncOperation*' } | Select-Object -First 1; "
        "$task=$asTask.MakeGenericMethod($avail).Invoke($null, @($op)); "
        "$task.Wait(); Write-Output $task.Result.ToString()"
    )
    try:
        proc = subprocess.run(
            [ps_exe, "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        out = (proc.stdout or "").strip()
        return {
            "supported": True,
            "returncode": proc.returncode,
            "availability": out if proc.returncode == 0 and out else "Unavailable",
            "available": proc.returncode == 0 and out == "Available",
            "stderr": (proc.stderr or "").strip() if proc.returncode != 0 else "",
        }
    except Exception as exc:
        return {"supported": False, "availability": "Error", "available": False, "error": str(exc)}


def request_windows_hello_interactive_consent(
    prompt_message: str,
    *,
    interactive_human_present: bool = False,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Invoke native OS Windows Hello Consent UI ONLY when interactive Session-1 human tap is requested.

    Fails closed when running in Session 0 or without explicit interactive desktop permission;
    never auto-confirms and never displays fake UI.
    """
    if not _is_interactive_user_session():
        return {
            "verified": False,
            "status": "SESSION_0_OR_NON_INTERACTIVE_REJECTED",
            "detail": "Windows Hello UI cannot run in Session 0.",
        }
    if not interactive_human_present:
        return {
            "verified": False,
            "status": "NOT_EXECUTED_INTERACTIVE_HUMAN_GESTURE_REQUIRED",
            "detail": "Live Windows Hello prompt requires physical human gesture (interactive_human_present=True).",
        }
    ps_exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not ps_exe:
        return {"verified": False, "status": "POWERSHELL_UNAVAILABLE"}

    # Clean single-line prompt string
    safe_prompt = prompt_message.replace("\r", " ").replace("\n", " ")[:200]
    b64_msg = base64.b64encode(safe_prompt.encode("utf-8")).decode("ascii")
    ps_script = (
        "$ErrorActionPreference='Stop'; "
        "Add-Type -AssemblyName System.Runtime.WindowsRuntime; "
        f"$msg=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{b64_msg}')); "
        "[void][Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]; "
        "$op=[Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($msg); "
        "$resT=[Windows.Security.Credentials.UI.UserConsentVerificationResult]; "
        "$m=[System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { "
        "$_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and "
        "$_.GetParameters()[0].ParameterType.Name -like 'IAsyncOperation*' } | Select-Object -First 1; "
        "$task=$m.MakeGenericMethod($resT).Invoke($null, @($op)); "
        "$task.Wait(); Write-Output $task.Result.ToString()"
    )
    proc = subprocess.run(
        [ps_exe, "-NoProfile", "-Command", ps_script],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    result_str = (proc.stdout or "").strip()
    return {
        "verified": proc.returncode == 0 and result_str == "Verified",
        "status": result_str or "FAILED",
        "returncode": proc.returncode,
    }

"""Provider-neutral contracts for NEXT-22D application adapters & identity binding."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any

from entitlement_router.privacy import redact_text, sanitize_for_output, validate_opaque_id

ADAPTER_PACKAGE_VERSION = "2026.11.14-next22d.1"

# Canonical product display labels safe for non-PII adapter telemetry (arbitrary user strings stay redacted).
CANONICAL_APPLICATION_LABELS: dict[str, str] = {
    "antigravity": "Google Antigravity",
    "claude_desktop": "Anthropic Claude Desktop",
    "codex": "OpenAI Codex (CLI / Desktop / IDE)",
    "claude_code": "Anthropic Claude Code CLI",
}

SECRET_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]+KEY-----"),
)


def contains_secret_material(text: str) -> bool:
    """Return True if *text* matches any high-confidence secret/credential pattern."""
    if not text:
        return False
    return any(pat.search(text) is not None for pat in SECRET_REDACTION_PATTERNS)


class AdapterInstallState(str, Enum):
    INSTALLED = "INSTALLED"
    NOT_INSTALLED = "NOT_INSTALLED"
    UNKNOWN = "UNKNOWN"


class IdentityVerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


class SignatureStatus(str, Enum):
    SIGNED_TRUSTED = "SIGNED_TRUSTED"
    UNSIGNED = "UNSIGNED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ApplicationAdapterProfile:
    """Static + refreshed-discovery metadata for one target application family."""

    application_id: str
    application_family: str
    display_name: str
    install_state: AdapterInstallState = AdapterInstallState.UNKNOWN
    installed_version: str | None = None
    packaging: str = "unknown"
    config_scopes: dict[str, str] = field(default_factory=dict)
    preferred_legacy_protocol_version: str = "2025-11-25"
    modern_runtime_wire_verified: bool = False
    modern_runtime_support_status: str = "ADAPTER_CONTRACT_ONLY_NOT_VERIFIED"
    default_compatibility_hints: dict[str, Any] = field(default_factory=dict)
    process_match_hints: tuple[str, ...] = ()
    discovery_evidence_source: str = "static_adapter_profile"
    observed_at: str | None = None
    live_tested: bool = False
    live_authenticated: bool = False
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_opaque_id(self.application_id, field_name="application_id")
        object.__setattr__(self, "modern_runtime_wire_verified", False)
        object.__setattr__(self, "live_tested", False)
        object.__setattr__(self, "live_authenticated", False)

    def sanitized_application_label(self) -> str:
        """Return a canonical product label only if it matches the safe built-in label map.

        Arbitrary caller-supplied display strings remain redacted so global PII protections stay intact.
        """
        canonical = CANONICAL_APPLICATION_LABELS.get(self.application_id)
        if canonical is not None and self.display_name == canonical:
            return canonical
        return "<REDACTED>"

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "application_id": self.application_id,
                "application_family": self.application_family,
                "application_label": self.sanitized_application_label(),
                "display_name": self.display_name,
                "install_state": self.install_state.value,
                "installed_version": self.installed_version,
                "packaging": self.packaging,
                "config_scopes": dict(self.config_scopes),
                "preferred_legacy_protocol_version": self.preferred_legacy_protocol_version,
                "modern_runtime_wire_verified": False,
                "modern_runtime_support_status": self.modern_runtime_support_status,
                "default_compatibility_hints": dict(self.default_compatibility_hints),
                "process_match_hints": list(self.process_match_hints),
                "discovery_evidence_source": self.discovery_evidence_source,
                "observed_at": self.observed_at,
                "live_tested": False,
                "live_authenticated": False,
                "limitations": list(self.limitations),
            }
        )


@dataclass(frozen=True)
class ProcessObservation:
    """Read-only OS process evidence; NEVER alone sufficient to prove application identity."""

    pid: int
    process_creation_time_100ns: int | None = None
    process_creation_time_iso: str | None = None
    user_sid_hash: str | None = None
    user_sid_observed: bool = False
    session_id: int | None = None
    integrity_level: str = "UNKNOWN"
    executable_path: str | None = None
    executable_sha256: str | None = None
    signature_status: SignatureStatus = SignatureStatus.UNKNOWN
    signature_error_code: int | None = None
    parent_pid: int | None = None
    parent_image_path: str | None = None
    parent_creation_time_100ns: int | None = None
    verified_by_os: bool = False
    proves_application_identity: bool = False
    observation_errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # Part 7.2: OS observation records telemetry only; never proves application identity alone.
        object.__setattr__(self, "proves_application_identity", False)

    def to_sanitized_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "pid": self.pid,
                "process_creation_time_100ns": self.process_creation_time_100ns,
                "process_creation_time_iso": self.process_creation_time_iso,
                "user_sid_hash": self.user_sid_hash,
                "user_sid_observed": self.user_sid_observed,
                "session_id": self.session_id,
                "integrity_level": self.integrity_level,
                "executable_path": self.executable_path,
                "executable_sha256": self.executable_sha256,
                "signature_status": self.signature_status.value,
                "signature_error_code": self.signature_error_code,
                "parent_pid": self.parent_pid,
                "parent_image_path": self.parent_image_path,
                "parent_creation_time_100ns": self.parent_creation_time_100ns,
                "verified_by_os": self.verified_by_os,
                "proves_application_identity": False,
                "observation_errors": list(self.observation_errors),
            }
        )


@dataclass(frozen=True)
class AdapterChallenge:
    """Server-issued cryptographic challenge for one adapter instance and OS process."""

    challenge_id: str
    nonce: str
    adapter_id: str
    application_id: str
    application_instance_id: str
    expected_pid: int
    expected_creation_time_100ns: int
    expected_os_sid: str
    key_id: str
    key_version: int
    issued_at_epoch: int
    expires_at_epoch: int
    expected_parent_pid: int | None = None
    expected_parent_creation_time_100ns: int | None = None

    def __post_init__(self) -> None:
        validate_opaque_id(self.challenge_id, field_name="challenge_id")
        validate_opaque_id(self.adapter_id, field_name="adapter_id")
        validate_opaque_id(self.application_id, field_name="application_id")
        validate_opaque_id(self.application_instance_id, field_name="application_instance_id")
        validate_opaque_id(self.key_id, field_name="key_id")

    def to_audit_dict(self) -> dict[str, Any]:
        """Return safe non-secret challenge metadata for diagnostics/audit logs."""
        return sanitize_for_output(
            {
                "challenge_id": self.challenge_id,
                "nonce_prefix": self.nonce[:8] + "..." if len(self.nonce) > 8 else "redacted",
                "adapter_id": self.adapter_id,
                "application_id": self.application_id,
                "application_instance_id": self.application_instance_id,
                "expected_pid": self.expected_pid,
                "expected_creation_time_100ns": self.expected_creation_time_100ns,
                "key_id": self.key_id,
                "key_version": self.key_version,
                "issued_at_epoch": self.issued_at_epoch,
                "expires_at_epoch": self.expires_at_epoch,
            }
        )


@dataclass(frozen=True)
class SignedAdapterProof:
    """Challenge-response HMAC-SHA256 adapter proof bound to process identity and SID."""

    challenge_id: str
    nonce: str
    key_id: str
    key_version: int
    adapter_id: str
    application_id: str
    application_instance_id: str
    pid: int
    process_creation_time_100ns: int
    expected_os_sid: str
    issued_at_epoch: int
    expires_at_epoch: int
    proof_hmac: str
    expected_parent_pid: int | None = None
    expected_parent_creation_time_100ns: int | None = None
    proof_method: str = "hmac_sha256_challenge_v1"

    def __post_init__(self) -> None:
        validate_opaque_id(self.challenge_id, field_name="challenge_id")
        validate_opaque_id(self.adapter_id, field_name="adapter_id")
        validate_opaque_id(self.application_id, field_name="application_id")
        validate_opaque_id(self.application_instance_id, field_name="application_instance_id")
        validate_opaque_id(self.key_id, field_name="key_id")

    def __repr__(self) -> str:
        return (
            f"SignedAdapterProof(challenge_id={self.challenge_id!r}, "
            f"adapter_id={self.adapter_id!r}, application_id={self.application_id!r}, "
            f"key_id={self.key_id!r}, key_version={self.key_version}, proof_hmac='<redacted>')"
        )

    def to_audit_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "challenge_id": self.challenge_id,
                "key_id": self.key_id,
                "key_version": self.key_version,
                "adapter_id": self.adapter_id,
                "application_id": self.application_id,
                "application_instance_id": self.application_instance_id,
                "pid": self.pid,
                "process_creation_time_100ns": self.process_creation_time_100ns,
                "issued_at_epoch": self.issued_at_epoch,
                "expires_at_epoch": self.expires_at_epoch,
                "proof_method": self.proof_method,
                "proof_hmac_present": bool(self.proof_hmac),
            }
        )


@dataclass(frozen=True)
class AdapterProofVerificationResult:
    """Outcome of verifying a SignedAdapterProof against OS + process + challenge evidence."""

    verified: bool
    status: IdentityVerificationStatus
    reason_code: str
    reason: str
    application_id: str = "UNKNOWN"
    application_instance_id: str | None = None
    adapter_id: str | None = None
    production_ready: bool = False
    audit_evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Part 7.3: test/ephemeral HMAC verification never asserts production provisioning readiness.
        object.__setattr__(self, "production_ready", False)
        if not self.verified:
            object.__setattr__(self, "application_id", "UNKNOWN")

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "verified": self.verified,
                "status": self.status.value,
                "reason_code": self.reason_code,
                "reason": redact_text(self.reason),
                "application_id": self.application_id,
                "application_instance_id": self.application_instance_id,
                "adapter_id": self.adapter_id,
                "production_ready": False,
                "audit_evidence": self.audit_evidence,
            }
        )


@dataclass(frozen=True)
class AdapterConfigPreview:
    """Validated, unapplied, secret-free configuration preview or package artifact."""

    application_id: str
    scope_name: str
    target_path: str
    content_format: str  # json | toml | dxt_manifest
    content_text: str
    validation_ok: bool
    validation_errors: tuple[str, ...] = ()
    applied: bool = False
    secret_free: bool = True
    manual_install_steps: tuple[str, ...] = ()
    rollback_steps: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "applied", False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "application_id": self.application_id,
            "scope_name": self.scope_name,
            "target_path": self.target_path,
            "content_format": self.content_format,
            "applied": False,
            "secret_free": self.secret_free,
            "validation_ok": self.validation_ok,
            "validation_errors": list(self.validation_errors),
            "content_text": self.content_text,
            "manual_install_steps": list(self.manual_install_steps),
            "rollback_steps": list(self.rollback_steps),
            "warnings": list(self.warnings),
        }

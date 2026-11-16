"""Authenticated caller identity model and OS/adapter boundary resolver for NEXT-22C."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
from typing import Any, Protocol

from broker.security import ClientIdentity
from entitlement_router.privacy import (
    SecretOrPiiIntakeError,
    sanitize_for_output,
    validate_opaque_id,
)
from mcp_gateway.contracts import (
    UNIVERSAL_MINIMUM_READ_SCOPES,
    AuthMethod,
    ProtocolEra,
)
from mcp_gateway.untrusted_hints import UntrustedClientHints


@dataclass(frozen=True)
class ProtocolContext:
    protocol_era: ProtocolEra = ProtocolEra.LEGACY
    protocol_version: str = "2024-11-05"
    transport: str = "stdio"
    negotiated_session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_era": self.protocol_era.value,
            "protocol_version": self.protocol_version,
            "transport": self.transport,
            "negotiated_session_id": self.negotiated_session_id,
        }


@dataclass(frozen=True)
class AdapterIdentityProof:
    """Verifiable proof for an application adapter; environment variables and basenames do NOT count."""

    application_id: str
    application_instance_id: str
    adapter_id: str
    proof_token: str
    expected_os_sid: str | None = None
    proof_method: str = "hmac_sha256"

    def __post_init__(self) -> None:
        validate_opaque_id(self.application_id, field_name="application_id")
        validate_opaque_id(self.application_instance_id, field_name="application_instance_id")
        validate_opaque_id(self.adapter_id, field_name="adapter_id")


class AdapterProofVerifier(Protocol):
    """Provider-neutral adapter proof verification contract (concrete app adapters belong to NEXT-22D)."""

    def verify(
        self,
        proof: AdapterIdentityProof,
        *,
        os_identity: ClientIdentity | None,
    ) -> tuple[bool, str]:
        """Return (verified, reason)."""


class SharedSecretAdapterProofVerifier:
    """Verifies adapter identity proofs using HMAC-SHA256 bound to OS SID (never env vars or clientInfo)."""

    def __init__(self, adapter_keys: dict[str, bytes] | None = None) -> None:
        self._adapter_keys: dict[str, bytes] = dict(adapter_keys or {})

    def register_adapter_key(self, adapter_id: str, secret_key: bytes) -> None:
        validate_opaque_id(adapter_id, field_name="adapter_id")
        self._adapter_keys[adapter_id] = secret_key

    def build_expected_token(
        self,
        *,
        adapter_id: str,
        application_id: str,
        application_instance_id: str,
        os_sid: str,
    ) -> str:
        key = self._adapter_keys[adapter_id]
        msg = f"{adapter_id}|{application_id}|{application_instance_id}|{os_sid}".encode("utf-8")
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    def verify(
        self,
        proof: AdapterIdentityProof,
        *,
        os_identity: ClientIdentity | None,
    ) -> tuple[bool, str]:
        if os_identity is None or not os_identity.verified_by_os:
            return False, "ADAPTER_PROOF_REQUIRES_OS_IDENTITY"
        # Same rule as stdio_entry: anything below Medium (LOW, UNTRUSTED) or unknown is not a trusted caller.
        if os_identity.is_low_integrity or os_identity.integrity_level.upper() in ("LOW", "UNTRUSTED", "UNKNOWN"):
            return False, "LOW_INTEGRITY_ADAPTER_REJECTED"
        if proof.expected_os_sid and proof.expected_os_sid != os_identity.sid:
            return False, "ADAPTER_OS_SID_MISMATCH"
        key = self._adapter_keys.get(proof.adapter_id)
        if not key:
            return False, "UNKNOWN_OR_UNTRUSTED_ADAPTER"
        expected = self.build_expected_token(
            adapter_id=proof.adapter_id,
            application_id=proof.application_id,
            application_instance_id=proof.application_instance_id,
            os_sid=os_identity.sid,
        )
        if not hmac.compare_digest(expected, proof.proof_token):
            return False, "INVALID_ADAPTER_SIGNATURE"
        return True, "ADAPTER_IDENTITY_VERIFIED"


@dataclass(frozen=True)
class AuthenticatedCallerContext:
    """Verified provider-neutral internal caller context (separate from UntrustedClientHints)."""

    principal_id: str
    application_id: str = "UNKNOWN"
    application_instance_id: str | None = None
    adapter_id: str | None = None
    account_context_id: str | None = None
    workspace_context_id: str | None = None
    authentication_method: AuthMethod = AuthMethod.UNKNOWN
    authorization_scopes: frozenset[str] = field(default_factory=frozenset)
    allowed_user_profile_ids: frozenset[str] = field(default_factory=frozenset)
    allowed_account_context_ids: frozenset[str] = field(default_factory=frozenset)
    operating_system_identity: dict[str, Any] = field(default_factory=dict)
    verified_application_identity: bool = False
    protocol_context: ProtocolContext = field(default_factory=ProtocolContext)
    context_evidence_refs: tuple[str, ...] = ()
    policy_generation: int = 1
    entitlement_generation: int = 1
    diagnostic_reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_opaque_id(self.principal_id, field_name="principal_id")
        if self.application_id != "UNKNOWN":
            validate_opaque_id(self.application_id, field_name="application_id")
        if self.application_instance_id is not None:
            validate_opaque_id(self.application_instance_id, field_name="application_instance_id")
        if self.adapter_id is not None:
            validate_opaque_id(self.adapter_id, field_name="adapter_id")
        if self.account_context_id is not None:
            validate_opaque_id(self.account_context_id, field_name="account_context_id")
        if self.workspace_context_id is not None:
            validate_opaque_id(self.workspace_context_id, field_name="workspace_context_id")
        for uid in self.allowed_user_profile_ids:
            validate_opaque_id(uid, field_name="allowed_user_profile_id")
        for aid in self.allowed_account_context_ids:
            validate_opaque_id(aid, field_name="allowed_account_context_id")

    @property
    def is_authenticated(self) -> bool:
        return self.authentication_method not in (AuthMethod.UNAUTHENTICATED, AuthMethod.UNKNOWN)

    @property
    def is_unknown_application(self) -> bool:
        return (not self.verified_application_identity) or self.application_id == "UNKNOWN"

    def to_sanitized_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "principal_id": self.principal_id,
                "application_id": self.application_id,
                "application_instance_id": self.application_instance_id,
                "adapter_id": self.adapter_id,
                "account_context_id": self.account_context_id,
                "workspace_context_id": self.workspace_context_id,
                "authentication_method": self.authentication_method.value,
                "authorization_scopes": sorted(self.authorization_scopes),
                "allowed_user_profile_ids": sorted(self.allowed_user_profile_ids),
                "allowed_account_context_ids": sorted(self.allowed_account_context_ids),
                "operating_system_identity": self.operating_system_identity,
                "verified_application_identity": self.verified_application_identity,
                "protocol_context": self.protocol_context.to_dict(),
                "context_evidence_refs": list(self.context_evidence_refs),
                "policy_generation": self.policy_generation,
                "entitlement_generation": self.entitlement_generation,
                "diagnostic_reasons": list(self.diagnostic_reasons),
            }
        )


def _derive_opaque_principal_from_sid(sid: str) -> str:
    digest = hashlib.sha256(sid.encode("utf-8")).hexdigest()[:16]
    return f"os-sid-{digest}"


class CallerIdentityResolver:
    """Resolves verified caller contexts without trusting clientInfo, env vars, or model IDs."""

    def __init__(self, adapter_verifier: AdapterProofVerifier | None = None) -> None:
        self.adapter_verifier = adapter_verifier or SharedSecretAdapterProofVerifier()

    def resolve_local_windows_caller(
        self,
        *,
        os_identity: ClientIdentity | None,
        claimed_sid: str | None = None,
        adapter_proof: AdapterIdentityProof | None = None,
        untrusted_hints: UntrustedClientHints | None = None,
        requested_scopes: frozenset[str] | set[str] | None = None,
        permitted_scopes_for_sid: frozenset[str] | None = None,
        allowed_user_profile_ids: frozenset[str] = frozenset(),
        allowed_account_context_ids: frozenset[str] = frozenset(),
        account_context_id: str | None = None,
        workspace_context_id: str | None = None,
        protocol_context: ProtocolContext | None = None,
        policy_generation: int = 1,
        entitlement_generation: int = 1,
        auth_method: AuthMethod = AuthMethod.LOCAL_WIN32_NAMED_PIPE,
    ) -> AuthenticatedCallerContext:
        """Bind caller context from verified Win32 ClientIdentity and optional cryptographic adapter proof.

        - Ignores untrusted_hints (clientInfo, declared_application_family, claimed_env_application, claimed_model_id)
          for authentication and application identity.
        - Unknown or unproven application identity always resolves to application_id='UNKNOWN' and clamps scopes
          to minimum universally authorized read-only unless OS+adapter verification permits more.
        """
        diagnostics: list[str] = []
        evidence_refs: list[str] = []
        pctx = protocol_context or ProtocolContext()

        if untrusted_hints is not None:
            if untrusted_hints.client_name:
                diagnostics.append("UNTRUSTED_CLIENT_INFO_NOT_USED_FOR_IDENTITY")
            if untrusted_hints.claimed_env_application:
                diagnostics.append("UNTRUSTED_ENV_APPLICATION_IGNORED")
            if untrusted_hints.claimed_model_id:
                diagnostics.append("UNTRUSTED_MODEL_ID_IGNORED_FOR_IDENTITY")

        if os_identity is None or not os_identity.verified_by_os or not os_identity.sid:
            return AuthenticatedCallerContext(
                principal_id="unauthenticated-anon",
                application_id="UNKNOWN",
                authentication_method=AuthMethod.UNAUTHENTICATED,
                authorization_scopes=frozenset(),
                operating_system_identity={"verified_by_os": False},
                verified_application_identity=False,
                protocol_context=pctx,
                context_evidence_refs=("identity:os:missing",),
                policy_generation=policy_generation,
                entitlement_generation=entitlement_generation,
                diagnostic_reasons=tuple(diagnostics + ["OS_IDENTITY_UNVERIFIED"]),
            )

        if claimed_sid and claimed_sid.strip() != os_identity.sid:
            return AuthenticatedCallerContext(
                principal_id=_derive_opaque_principal_from_sid(os_identity.sid),
                application_id="UNKNOWN",
                authentication_method=AuthMethod.UNAUTHENTICATED,
                authorization_scopes=frozenset(),
                operating_system_identity={
                    "pid": os_identity.pid,
                    "sid_hash": hashlib.sha256(os_identity.sid.encode("utf-8")).hexdigest()[:16],
                    "integrity_level": os_identity.integrity_level,
                    "verified_by_os": os_identity.verified_by_os,
                    "sid_mismatch": True,
                },
                verified_application_identity=False,
                protocol_context=pctx,
                context_evidence_refs=("identity:os:sid_mismatch",),
                policy_generation=policy_generation,
                entitlement_generation=entitlement_generation,
                diagnostic_reasons=tuple(diagnostics + ["OS_SID_MISMATCH_REJECTED"]),
            )

        # Same rule as stdio_entry: anything below Medium (LOW, UNTRUSTED) or unknown is not a trusted caller.
        if os_identity.is_low_integrity or os_identity.integrity_level.upper() in ("LOW", "UNTRUSTED", "UNKNOWN"):
            return AuthenticatedCallerContext(
                principal_id=_derive_opaque_principal_from_sid(os_identity.sid),
                application_id="UNKNOWN",
                authentication_method=AuthMethod.UNAUTHENTICATED,
                authorization_scopes=frozenset(),
                operating_system_identity={
                    "pid": os_identity.pid,
                    "sid_hash": hashlib.sha256(os_identity.sid.encode("utf-8")).hexdigest()[:16],
                    "integrity_level": os_identity.integrity_level,
                    "verified_by_os": os_identity.verified_by_os,
                    "is_low_integrity": True,
                },
                verified_application_identity=False,
                protocol_context=pctx,
                context_evidence_refs=("identity:os:low_il_rejected",),
                policy_generation=policy_generation,
                entitlement_generation=entitlement_generation,
                diagnostic_reasons=tuple(diagnostics + ["LOW_INTEGRITY_REJECTED"]),
            )

        principal_id = _derive_opaque_principal_from_sid(os_identity.sid)
        os_info = {
            "pid": os_identity.pid,
            "sid_hash": hashlib.sha256(os_identity.sid.encode("utf-8")).hexdigest()[:16],
            "integrity_level": os_identity.integrity_level,
            "is_appcontainer": os_identity.is_appcontainer,
            "is_elevated": os_identity.is_elevated,
            "verified_by_os": True,
        }
        evidence_refs.append(f"identity:os:{principal_id}:{os_identity.integrity_level}")

        verified_app = False
        app_id = "UNKNOWN"
        app_inst_id: str | None = None
        adapter_id: str | None = None

        if adapter_proof is not None:
            ok_proof, proof_reason = self.adapter_verifier.verify(adapter_proof, os_identity=os_identity)
            diagnostics.append(proof_reason)
            if ok_proof:
                verified_app = True
                app_id = adapter_proof.application_id
                app_inst_id = adapter_proof.application_instance_id
                adapter_id = adapter_proof.adapter_id
                evidence_refs.append(f"identity:adapter:{adapter_id}:verified")
            else:
                evidence_refs.append(f"identity:adapter:rejected:{proof_reason}")
        else:
            diagnostics.append("APPLICATION_IDENTITY_NOT_PROVEN_UNKNOWN")

        base_permitted = (
            set(permitted_scopes_for_sid)
            if permitted_scopes_for_sid is not None
            else set(UNIVERSAL_MINIMUM_READ_SCOPES)
        )
        if requested_scopes is not None:
            effective_scopes = base_permitted & set(requested_scopes)
        else:
            effective_scopes = base_permitted

        # Unknown application or missing account verification: clamp to minimum safe read-only if requested
        # or prevent account/execution scopes without verified provenance.
        if not verified_app:
            effective_scopes = effective_scopes & set(UNIVERSAL_MINIMUM_READ_SCOPES)
            resolved_acct: str | None = None
            resolved_users: frozenset[str] = frozenset()
            resolved_accts: frozenset[str] = frozenset()
            if account_context_id is not None:
                diagnostics.append("ACCOUNT_CONTEXT_WITHHELD_WITHOUT_VERIFIED_APP")
        else:
            resolved_users = frozenset(allowed_user_profile_ids)
            resolved_accts = frozenset(allowed_account_context_ids)
            if account_context_id is not None:
                try:
                    cleaned_acct = validate_opaque_id(account_context_id, field_name="account_context_id")
                except SecretOrPiiIntakeError:
                    cleaned_acct = None
                if cleaned_acct and (not resolved_accts or cleaned_acct in resolved_accts):
                    resolved_acct = cleaned_acct
                    if not resolved_accts:
                        resolved_accts = frozenset({cleaned_acct})
                else:
                    resolved_acct = None
                    diagnostics.append("REQUESTED_ACCOUNT_OUTSIDE_CALLER_SCOPE")
            else:
                resolved_acct = None

        return AuthenticatedCallerContext(
            principal_id=principal_id,
            application_id=app_id,
            application_instance_id=app_inst_id,
            adapter_id=adapter_id,
            account_context_id=resolved_acct,
            workspace_context_id=workspace_context_id if verified_app else None,
            authentication_method=auth_method,
            authorization_scopes=frozenset(effective_scopes),
            allowed_user_profile_ids=resolved_users,
            allowed_account_context_ids=resolved_accts,
            operating_system_identity=os_info,
            verified_application_identity=verified_app,
            protocol_context=pctx,
            context_evidence_refs=tuple(evidence_refs),
            policy_generation=policy_generation,
            entitlement_generation=entitlement_generation,
            diagnostic_reasons=tuple(diagnostics),
        )

    def resolve_remote_http_caller(
        self,
        *,
        bearer_token: str | None = None,
        os_identity: ClientIdentity | None = None,
    ) -> AuthenticatedCallerContext:
        """Remote Streamable HTTP deployment is explicitly disabled in NEXT-22C.

        Never reuses local Windows OS identity for remote HTTP requests and rejects unverified tokens.
        """
        _ = (bearer_token, os_identity)
        return AuthenticatedCallerContext(
            principal_id="remote-http-disabled",
            application_id="UNKNOWN",
            authentication_method=AuthMethod.UNAUTHENTICATED,
            authorization_scopes=frozenset(),
            operating_system_identity={"verified_by_os": False, "remote_http_disabled": True},
            verified_application_identity=False,
            protocol_context=ProtocolContext(transport="streamable_http"),
            context_evidence_refs=("identity:remote_http:disabled_in_next22c",),
            diagnostic_reasons=("REMOTE_HTTP_DEPLOYMENT_DISABLED",),
        )

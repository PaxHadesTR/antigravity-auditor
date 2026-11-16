"""Strictly untrusted protocol and client metadata container for NEXT-22C.

Untrusted hints may inform compatibility presentation heuristics only after validation,
but MUST NEVER grant authentication, application identity proof, account entitlement,
or tool authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from entitlement_router.privacy import redact_text, sanitize_for_output


@dataclass(frozen=True)
class UntrustedClientHints:
    """Protocol metadata supplied by the peer without cryptographic/OS identity proof."""

    client_name: str | None = None
    client_version: str | None = None
    declared_protocol_version: str | None = None
    declared_capabilities: dict[str, Any] = field(default_factory=dict)
    declared_application_family: str | None = None
    claimed_model_id: str | None = None
    claimed_account_hint: str | None = None
    claimed_env_application: str | None = None

    @property
    def is_trusted_identity(self) -> bool:
        return False

    @property
    def grants_authorization(self) -> bool:
        return False

    @classmethod
    def from_mcp_params(
        cls,
        params: dict[str, Any] | None,
        *,
        claimed_env_application: str | None = None,
    ) -> "UntrustedClientHints":
        p = params if isinstance(params, dict) else {}
        client_info = p.get("clientInfo") if isinstance(p.get("clientInfo"), dict) else {}
        caps = p.get("capabilities") if isinstance(p.get("capabilities"), dict) else {}

        raw_name = client_info.get("name")
        raw_ver = client_info.get("version")
        raw_proto = p.get("protocolVersion") or p.get("protocol_version")
        raw_family = client_info.get("applicationFamily") or p.get("application_family")
        raw_model = p.get("model_id") or p.get("model") or client_info.get("model")
        raw_acct = p.get("account_context_id") or client_info.get("account")

        return cls(
            client_name=redact_text(str(raw_name))[:128] if raw_name is not None else None,
            client_version=redact_text(str(raw_ver))[:64] if raw_ver is not None else None,
            declared_protocol_version=redact_text(str(raw_proto))[:32] if raw_proto is not None else None,
            declared_capabilities=sanitize_for_output(dict(caps)),
            declared_application_family=redact_text(str(raw_family))[:64] if raw_family is not None else None,
            claimed_model_id=redact_text(str(raw_model))[:128] if raw_model is not None else None,
            claimed_account_hint=redact_text(str(raw_acct))[:128] if raw_acct is not None else None,
            claimed_env_application=(
                redact_text(str(claimed_env_application))[:64]
                if claimed_env_application is not None
                else None
            ),
        )

    def to_sanitized_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "trusted": False,
                "client_name": self.client_name,
                "client_version": self.client_version,
                "declared_protocol_version": self.declared_protocol_version,
                "declared_capabilities": self.declared_capabilities,
                "declared_application_family": self.declared_application_family,
                "claimed_model_id": self.claimed_model_id,
                "claimed_account_hint": self.claimed_account_hint,
                "claimed_env_application": self.claimed_env_application,
            }
        )

"""Application-neutral Client Compatibility Profile resolver (NEXT-22C + NEXT-22A evidence)."""

from __future__ import annotations

from typing import Any

from mcp_gateway.authenticated_context import AuthenticatedCallerContext
from mcp_gateway.contracts import (
    LEGACY_STRUCTURED_OUTPUT_MIN_DATE,
    ClientCompatibilityProfile,
    CompatibilityState,
    LEGACY_SUPPORTED_PROTOCOL_VERSIONS,
    MODERN_CONTRACT_PROTOCOL_VERSIONS,
    MODERN_MIN_PROTOCOL_DATE,
    ProtocolEra,
    parse_strict_protocol_date,
    utc_now_iso,
)
from mcp_gateway.untrusted_hints import UntrustedClientHints


def classify_protocol_era(protocol_version: str | None) -> ProtocolEra:
    """Classify an MCP protocol version into LEGACY, MODERN, UNSUPPORTED, or UNKNOWN."""
    if protocol_version is None:
        return ProtocolEra.UNKNOWN
    if not isinstance(protocol_version, str):
        return ProtocolEra.UNSUPPORTED
    ver = protocol_version.strip()
    if not ver:
        return ProtocolEra.UNKNOWN
    parsed = parse_strict_protocol_date(ver)
    if parsed is None:
        return ProtocolEra.UNSUPPORTED
    if ver in LEGACY_SUPPORTED_PROTOCOL_VERSIONS:
        return ProtocolEra.LEGACY
    if ver in MODERN_CONTRACT_PROTOCOL_VERSIONS or parsed >= MODERN_MIN_PROTOCOL_DATE:
        return ProtocolEra.MODERN
    return ProtocolEra.UNSUPPORTED


def _state_from_bool_cap(val: Any) -> CompatibilityState:
    if val is True:
        return CompatibilityState.USER_REPORTED
    if val is False:
        return CompatibilityState.NOT_SUPPORTED
    return CompatibilityState.UNKNOWN


def _extract_next22a_app_observation(
    discovery_report: dict[str, Any] | None,
    application_id: str,
) -> tuple[str | None, str | None, str]:
    """Read historical NEXT-22A observation for application_id without inferring live connection."""
    if not discovery_report or application_id in ("", "UNKNOWN"):
        return None, None, "none"
    apps = discovery_report.get("applications")
    if not isinstance(apps, dict):
        return None, None, "none"
    entry = apps.get(application_id)
    if not isinstance(entry, dict):
        return None, None, "none"
    install_state = str(entry.get("installation_state") or "").lower()
    if install_state == "not_installed":
        return None, str(entry.get("observed_at") or discovery_report.get("generated_at") or utc_now_iso()), "next22a_not_installed"
    version = entry.get("version") or entry.get("runtime_version")
    ts = str(entry.get("observed_at") or discovery_report.get("generated_at") or utc_now_iso())
    return (str(version) if version else None), ts, f"next22a_historical:{install_state or 'observed'}"


class ClientProfileResolver:
    """Resolves ClientCompatibilityProfile strictly separate from entitlement & authorization."""

    def resolve(
        self,
        *,
        caller: AuthenticatedCallerContext,
        untrusted_hints: UntrustedClientHints | None = None,
        transport: str | None = None,
        protocol_version: str | None = None,
        discovery_report: dict[str, Any] | None = None,
        override_states: dict[str, CompatibilityState] | None = None,
        output_constraints: dict[str, Any] | None = None,
        live_verified: bool = False,
    ) -> ClientCompatibilityProfile:
        hints = untrusted_hints or UntrustedClientHints()
        eff_transport = transport or caller.protocol_context.transport or "unknown"
        eff_proto = protocol_version or caller.protocol_context.protocol_version or hints.declared_protocol_version or "2024-11-05"
        era = classify_protocol_era(eff_proto)

        # Preserve verified application_id only; never promote untrusted clientInfo to application identity.
        app_id = caller.application_id if caller.verified_application_identity else "UNKNOWN"
        app_version, hist_ts, hist_src = _extract_next22a_app_observation(discovery_report, app_id)

        caps = dict(hints.declared_capabilities)
        tools_cap = caps.get("tools") if isinstance(caps.get("tools"), dict) else {}
        subs_cap = caps.get("subscriptions") if isinstance(caps.get("subscriptions"), dict) else {}

        # Conservative defaults: UNKNOWN stays UNKNOWN (never downgraded to NOT_SUPPORTED without evidence).
        parsed_proto = parse_strict_protocol_date(eff_proto)
        structured_state = (
            CompatibilityState.DOCUMENTED
            if (
                era == ProtocolEra.LEGACY
                and parsed_proto is not None
                and parsed_proto >= LEGACY_STRUCTURED_OUTPUT_MIN_DATE
            )
            or era == ProtocolEra.MODERN
            else _state_from_bool_cap(caps.get("structuredOutput") if "structuredOutput" in caps else caps.get("structuredContent"))
        )
        list_refresh_state = (
            _state_from_bool_cap(tools_cap.get("listChanged"))
            if "listChanged" in tools_cap
            else CompatibilityState.UNKNOWN
        )
        notification_state = (
            CompatibilityState.USER_REPORTED
            if (tools_cap.get("listChanged") is True or "notifications" in caps)
            else CompatibilityState.UNKNOWN
        )
        subscription_state = (
            CompatibilityState.NOT_SUPPORTED
            if era == ProtocolEra.LEGACY
            else (_state_from_bool_cap(subs_cap.get("listen")) if era == ProtocolEra.MODERN else CompatibilityState.UNKNOWN)
        )
        pagination_state = _state_from_bool_cap(caps.get("pagination"))
        progress_state = _state_from_bool_cap(caps.get("progress"))
        task_state = _state_from_bool_cap(caps.get("tasks"))
        elicitation_state = _state_from_bool_cap(caps.get("elicitation"))

        overrides = override_states or {}
        structured_state = overrides.get("structured_output_state", structured_state)
        list_refresh_state = overrides.get("tool_list_refresh_state", list_refresh_state)
        notification_state = overrides.get("notification_state", notification_state)
        subscription_state = overrides.get("subscription_state", subscription_state)
        pagination_state = overrides.get("pagination_state", pagination_state)
        progress_state = overrides.get("progress_state", progress_state)
        task_state = overrides.get("task_support_state", task_state)
        elicitation_state = overrides.get("elicitation_state", elicitation_state)

        constraints = {"max_items": 50, "max_text_chars": 4096, "prefer_concise_text": False}
        if output_constraints:
            constraints.update(output_constraints)

        source_parts = ["protocol_negotiation"] if hints.declared_protocol_version or caller.protocol_context else ["default_conservative"]
        if hist_src != "none":
            source_parts.append(hist_src)
        if override_states:
            source_parts.append("explicit_profile_override")

        return ClientCompatibilityProfile(
            application_id=app_id,
            application_version=app_version,
            adapter_version=caller.adapter_id,
            transport=eff_transport,
            protocol_era=era,
            protocol_version=eff_proto,
            client_capabilities=caps,
            structured_output_state=structured_state,
            tool_list_refresh_state=list_refresh_state,
            notification_state=notification_state,
            subscription_state=subscription_state,
            pagination_state=pagination_state,
            progress_state=progress_state,
            task_support_state=task_state,
            elicitation_state=elicitation_state,
            output_constraints=constraints,
            evidence_source="+".join(source_parts),
            observation_timestamp=hist_ts or utc_now_iso(),
            live_verified=live_verified,
        )

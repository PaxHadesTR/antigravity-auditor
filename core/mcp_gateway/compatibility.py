"""Conservative protocol and client feature compatibility evaluation for NEXT-22C."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_gateway.contracts import (
    CanonicalToolManifest,
    ClientCompatibilityProfile,
    CompatibilityState,
    ProtocolEra,
)

_POSITIVE_STATES = frozenset(
    {
        CompatibilityState.VERIFIED,
        CompatibilityState.DOCUMENTED,
        CompatibilityState.CONFIGURED,
        CompatibilityState.USER_REPORTED,
    }
)


@dataclass(frozen=True)
class FeatureCompatibility:
    supports_structured_output: bool
    supports_output_schemas: bool
    supports_list_changed_notifications: bool
    supports_subscriptions: bool
    supports_pagination: bool
    supports_progress: bool
    max_items: int
    max_text_chars: int
    prefer_concise_text: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "supports_structured_output": self.supports_structured_output,
            "supports_output_schemas": self.supports_output_schemas,
            "supports_list_changed_notifications": self.supports_list_changed_notifications,
            "supports_subscriptions": self.supports_subscriptions,
            "supports_pagination": self.supports_pagination,
            "supports_progress": self.supports_progress,
            "max_items": self.max_items,
            "max_text_chars": self.max_text_chars,
            "prefer_concise_text": self.prefer_concise_text,
        }


def evaluate_feature_compatibility(profile: ClientCompatibilityProfile) -> FeatureCompatibility:
    """Compute conservative runtime feature flags; UNKNOWN falls back safely without breaking reads."""
    structured = profile.structured_output_state in _POSITIVE_STATES
    list_changed = (
        profile.protocol_era == ProtocolEra.LEGACY
        and profile.tool_list_refresh_state in _POSITIVE_STATES
        and profile.notification_state in _POSITIVE_STATES
    )
    subscriptions = (
        profile.protocol_era == ProtocolEra.MODERN
        and profile.subscription_state in _POSITIVE_STATES
    )
    # Pagination works cleanly even when client support is UNKNOWN (cursor optional in response).
    pagination = profile.pagination_state not in (CompatibilityState.NOT_SUPPORTED, CompatibilityState.ERROR)
    progress = profile.progress_state in _POSITIVE_STATES

    constraints = profile.output_constraints or {}
    max_items = max(1, min(int(constraints.get("max_items", 50)), 200))
    max_text_chars = max(128, min(int(constraints.get("max_text_chars", 4096)), 32000))
    prefer_concise = bool(constraints.get("prefer_concise_text", not structured))

    return FeatureCompatibility(
        supports_structured_output=structured,
        supports_output_schemas=structured,
        supports_list_changed_notifications=list_changed,
        supports_subscriptions=subscriptions,
        supports_pagination=pagination,
        supports_progress=progress,
        max_items=max_items,
        max_text_chars=max_text_chars,
        prefer_concise_text=prefer_concise,
    )


def tool_meets_minimum_features(
    tool: CanonicalToolManifest,
    profile: ClientCompatibilityProfile,
) -> tuple[bool, list[str]]:
    """Verify required minimum client features (compatibility only, NEVER authorization)."""
    if not tool.minimum_client_features:
        return True, []
    compat = evaluate_feature_compatibility(profile)
    missing: list[str] = []
    for req in tool.minimum_client_features:
        if req == "structured_output" and not compat.supports_structured_output:
            missing.append("MISSING_FEATURE:structured_output")
        elif req == "subscriptions" and not compat.supports_subscriptions:
            missing.append("MISSING_FEATURE:subscriptions")
        elif req == "pagination" and not compat.supports_pagination:
            missing.append("MISSING_FEATURE:pagination")
    return len(missing) == 0, missing

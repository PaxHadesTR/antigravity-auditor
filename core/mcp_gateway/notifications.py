"""Capability-gated MCP notification and modern subscription coordinator for NEXT-22C."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_gateway.compatibility import evaluate_feature_compatibility
from mcp_gateway.contracts import ClientCompatibilityProfile, ProtocolEra, utc_now_iso


@dataclass
class SubscriptionRecord:
    subscription_id: str
    principal_id: str
    channel: str
    created_at: str = field(default_factory=utc_now_iso)


class NotificationManager:
    """Routes tool-list change signals without emitting unsolicited notifications."""

    def __init__(self) -> None:
        self._subscriptions: dict[str, dict[str, SubscriptionRecord]] = {}
        self._emitted_events: list[dict[str, Any]] = []

    def subscribe(
        self,
        *,
        principal_id: str,
        profile: ClientCompatibilityProfile,
        channel: str = "tools/list",
    ) -> tuple[bool, dict[str, Any]]:
        if profile.protocol_era != ProtocolEra.MODERN:
            return False, {
                "accepted": False,
                "reason": "subscriptions/listen requires MODERN protocol era.",
                "protocol_era": profile.protocol_era.value,
            }
        compat = evaluate_feature_compatibility(profile)
        if not compat.supports_subscriptions:
            return False, {
                "accepted": False,
                "reason": "Client compatibility profile does not support subscriptions/listen.",
            }
        sub_id = f"sub:{principal_id}:{channel}"
        rec = SubscriptionRecord(subscription_id=sub_id, principal_id=principal_id, channel=channel)
        self._subscriptions.setdefault(principal_id, {})[channel] = rec
        return True, {
            "accepted": True,
            "subscriptionId": rec.subscription_id,
            "channel": rec.channel,
            "runtimeWireVerified": False,
            "runtimeSupportStatus": "ADAPTER_CONTRACT_ONLY_NOT_VERIFIED",
        }

    def list_subscriptions(self, principal_id: str) -> list[str]:
        return sorted(self._subscriptions.get(principal_id, {}).keys())

    def emit_tools_changed(
        self,
        *,
        principal_id: str,
        profile: ClientCompatibilityProfile,
        catalog_version: str,
        reason: str,
    ) -> dict[str, Any] | None:
        """Build a tool-list change notification ONLY if client protocol and capabilities permit it."""
        compat = evaluate_feature_compatibility(profile)
        if profile.protocol_era == ProtocolEra.LEGACY:
            if not compat.supports_list_changed_notifications:
                return None
            msg = {
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed",
                "params": {
                    "catalogVersion": catalog_version,
                    "reason": reason,
                },
            }
            self._emitted_events.append({"principal_id": principal_id, "era": "LEGACY", "msg": msg})
            return msg

        if profile.protocol_era == ProtocolEra.MODERN:
            subs = self._subscriptions.get(principal_id, {})
            if not compat.supports_subscriptions or "tools/list" not in subs:
                return None
            msg = {
                "jsonrpc": "2.0",
                "method": "notifications/subscriptions/event",
                "params": {
                    "subscriptionId": subs["tools/list"].subscription_id,
                    "channel": "tools/list",
                    "catalogVersion": catalog_version,
                    "reason": reason,
                },
            }
            self._emitted_events.append({"principal_id": principal_id, "era": "MODERN", "msg": msg})
            return msg

        return None

    @property
    def emitted_events(self) -> list[dict[str, Any]]:
        return list(self._emitted_events)

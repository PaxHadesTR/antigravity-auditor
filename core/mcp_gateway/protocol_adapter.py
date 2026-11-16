"""Legacy (<= 2025-11-25) and Modern (>= 2026-07-28) MCP protocol compatibility adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp_gateway.compatibility import evaluate_feature_compatibility
from mcp_gateway.contracts import (
    GATEWAY_VERSION,
    LEGACY_SUPPORTED_PROTOCOL_VERSIONS,
    MODERN_CONTRACT_PROTOCOL_VERSIONS,
    MODERN_MIN_PROTOCOL_DATE,
    CanonicalToolManifest,
    ClientCompatibilityProfile,
    ProtocolEra,
    parse_strict_protocol_date,
)

JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602


@dataclass(frozen=True)
class ProtocolNegotiationOutcome:
    accepted: bool
    era: ProtocolEra
    protocol_version: str
    runtime_wire_verified: bool
    runtime_support_status: str
    reason: str
    fallback_applied: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "era": self.era.value,
            "protocol_version": self.protocol_version,
            "runtime_wire_verified": self.runtime_wire_verified,
            "runtime_support_status": self.runtime_support_status,
            "reason": self.reason,
            "fallback_applied": self.fallback_applied,
        }


def paginate_items(
    items: list[dict[str, Any]],
    *,
    cursor: str | None = None,
    page_size: int = 50,
) -> tuple[list[dict[str, Any]], str | None]:
    """Deterministic offset-cursor pagination over ordered lists."""
    start = 0
    if cursor is not None:
        if not str(cursor).isdigit():
            raise ValueError(f"Invalid pagination cursor: '{cursor}'")
        start = int(cursor)
        if start < 0:
            raise ValueError(f"Negative pagination cursor: '{cursor}'")
    limit = max(1, min(int(page_size), 200))
    window = items[start : start + limit]
    next_idx = start + len(window)
    next_cursor = str(next_idx) if next_idx < len(items) else None
    return window, next_cursor


def to_wire_json_schema(schema: Any) -> Any:
    """Standard JSON Schema for MCP clients.

    Internal schemas use the OpenAPI-style ``"nullable": true``; JSON Schema validators (e.g. the official MCP
    SDK checking ``structuredContent``) ignore that keyword and reject ``null``. On the wire it becomes a type
    union (``["integer", "null"]``)."""
    if isinstance(schema, list):
        return [to_wire_json_schema(x) for x in schema]
    if not isinstance(schema, dict):
        return schema
    out: dict[str, Any] = {}
    for k, v in schema.items():
        if k == "nullable":
            continue  # the OpenAPI keyword itself
        if k in ("properties", "patternProperties", "$defs", "definitions") and isinstance(v, dict):
            # keys here are property / definition *names*, not schema keywords
            out[k] = {name: to_wire_json_schema(sub) for name, sub in v.items()}
        else:
            out[k] = to_wire_json_schema(v)
    if schema.get("nullable") is True:
        if "type" in out:
            types = out["type"] if isinstance(out["type"], list) else [out["type"]]
            if "null" not in types:
                types = [*types, "null"]
            out["type"] = types
        if isinstance(out.get("enum"), list) and None not in out["enum"]:
            out["enum"] = [*out["enum"], None]  # enum restricts every type, so null must be listed too
    return out


def render_tool_entry(
    tool: CanonicalToolManifest,
    profile: ClientCompatibilityProfile,
) -> dict[str, Any]:
    """Render a CanonicalToolManifest item for MCP `tools/list` or `server/discover`."""
    compat = evaluate_feature_compatibility(profile)
    entry: dict[str, Any] = {
        "name": tool.tool_name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": to_wire_json_schema(tool.input_schema),
        "annotations": {
            "toolGroup": tool.tool_group.value,
            "riskClass": tool.risk_class.value,
            "readOnlyHint": not tool.execution_mutating and tool.tool_group.value in ("CORE_READ", "PROJECT_READ", "EVIDENCE_READ", "ROUTING_READ", "PLANNING"),
            "catalogVersion": tool.catalog_version,
            "schemaVersion": tool.schema_version,
        },
    }
    if compat.supports_output_schemas and tool.output_schema is not None:
        entry["outputSchema"] = to_wire_json_schema(tool.output_schema)
    return entry


class LegacyProtocolAdapter:
    """MCP Legacy Era (<= 2025-11-25): stateful `initialize` handshake & legacy notifications."""

    era = ProtocolEra.LEGACY
    runtime_wire_verified = True
    runtime_support_status = "STDIO_LEGACY_SUPPORTED"

    def negotiate_initialize(self, params: dict[str, Any]) -> ProtocolNegotiationOutcome:
        requested = params.get("protocolVersion")
        if requested is None:
            return ProtocolNegotiationOutcome(
                accepted=True,
                era=ProtocolEra.LEGACY,
                protocol_version=LEGACY_SUPPORTED_PROTOCOL_VERSIONS[-1],
                runtime_wire_verified=True,
                runtime_support_status=self.runtime_support_status,
                reason="Defaulted to latest supported legacy MCP protocol version.",
                fallback_applied=True,
            )
        req_str = str(requested).strip()
        if req_str in LEGACY_SUPPORTED_PROTOCOL_VERSIONS:
            return ProtocolNegotiationOutcome(
                accepted=True,
                era=ProtocolEra.LEGACY,
                protocol_version=req_str,
                runtime_wire_verified=True,
                runtime_support_status=self.runtime_support_status,
                reason=f"Accepted supported legacy protocol version '{req_str}'.",
            )
        return ProtocolNegotiationOutcome(
            accepted=False,
            era=ProtocolEra.UNSUPPORTED,
            protocol_version=req_str,
            runtime_wire_verified=False,
            runtime_support_status="UNSUPPORTED_PROTOCOL_VERSION",
            reason=f"Unsupported legacy initialize protocolVersion '{req_str}'. Supported: {LEGACY_SUPPORTED_PROTOCOL_VERSIONS}",
        )

    def build_initialize_result(
        self,
        *,
        protocol_version: str,
        profile: ClientCompatibilityProfile,
    ) -> dict[str, Any]:
        compat = evaluate_feature_compatibility(profile)
        return {
            "protocolVersion": protocol_version,
            "capabilities": {
                "tools": {
                    "listChanged": bool(compat.supports_list_changed_notifications),
                },
            },
            "serverInfo": {
                "name": "antigravity-auditor",
                "version": GATEWAY_VERSION,
            },
        }


class ModernProtocolAdapter:
    """MCP Modern Era (>= 2026-07-28) internal compatibility contract.

    IMPORTANT: No external modern Streamable HTTP MCP SDK / installed modern client wire
    session is live-tested in NEXT-22C. `runtime_wire_verified` remains False (`NOT_VERIFIED`).
    """

    era = ProtocolEra.MODERN
    runtime_wire_verified = False
    runtime_support_status = "ADAPTER_CONTRACT_ONLY_NOT_VERIFIED"

    def validate_request_version(self, params: dict[str, Any]) -> ProtocolNegotiationOutcome:
        req = params.get("protocolVersion") or params.get("protocol_version")
        if req is None or (isinstance(req, str) and not req.strip()):
            return ProtocolNegotiationOutcome(
                accepted=False,
                era=ProtocolEra.UNSUPPORTED,
                protocol_version="UNKNOWN",
                runtime_wire_verified=False,
                runtime_support_status="MISSING_MODERN_PROTOCOL_VERSION",
                reason="Modern MCP protocol requires per-request protocolVersion (>= 2026-07-28).",
            )
        if not isinstance(req, str):
            return ProtocolNegotiationOutcome(
                accepted=False,
                era=ProtocolEra.UNSUPPORTED,
                protocol_version=str(req),
                runtime_wire_verified=False,
                runtime_support_status="UNSUPPORTED_MODERN_PROTOCOL_VERSION",
                reason="Protocol version must be a strict YYYY-MM-DD calendar date string.",
            )
        req_str = req.strip()
        parsed_date = parse_strict_protocol_date(req_str)
        if parsed_date is None:
            return ProtocolNegotiationOutcome(
                accepted=False,
                era=ProtocolEra.UNSUPPORTED,
                protocol_version=req_str,
                runtime_wire_verified=False,
                runtime_support_status="UNSUPPORTED_MODERN_PROTOCOL_VERSION",
                reason=f"Protocol version '{req_str}' is not a valid strict YYYY-MM-DD calendar date.",
            )
        if req_str in MODERN_CONTRACT_PROTOCOL_VERSIONS or parsed_date >= MODERN_MIN_PROTOCOL_DATE:
            return ProtocolNegotiationOutcome(
                accepted=True,
                era=ProtocolEra.MODERN,
                protocol_version=req_str,
                runtime_wire_verified=False,
                runtime_support_status=self.runtime_support_status,
                reason=f"Accepted modern protocol contract '{req_str}' (live wire NOT_VERIFIED).",
            )
        return ProtocolNegotiationOutcome(
            accepted=False,
            era=ProtocolEra.UNSUPPORTED,
            protocol_version=req_str,
            runtime_wire_verified=False,
            runtime_support_status="UNSUPPORTED_MODERN_PROTOCOL_VERSION",
            reason=f"Protocol version '{req_str}' is not valid for modern MCP era (>= 2026-07-28).",
        )

    def build_server_discover_result(
        self,
        *,
        protocol_version: str,
        profile: ClientCompatibilityProfile,
        visible_tools: list[dict[str, Any]],
        next_cursor: str | None = None,
    ) -> dict[str, Any]:
        compat = evaluate_feature_compatibility(profile)
        out: dict[str, Any] = {
            "protocolVersion": protocol_version,
            "serverInfo": {
                "name": "antigravity-auditor",
                "version": GATEWAY_VERSION,
            },
            "capabilities": {
                "tools": {"listChanged": False},
                "subscriptions": {"listen": bool(compat.supports_subscriptions)},
                "structuredOutput": bool(compat.supports_structured_output),
            },
            "runtimeSupportStatus": self.runtime_support_status,
            "runtimeWireVerified": self.runtime_wire_verified,
            "tools": visible_tools,
        }
        if next_cursor is not None:
            out["nextCursor"] = next_cursor
        return out

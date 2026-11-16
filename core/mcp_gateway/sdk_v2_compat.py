"""Qualification-only MCP Python SDK v2.3.0 compatibility bridge for AdaptiveMCPGateway.

Architectural boundary (NEXT-22E):
- Optional/experimental qualification bridge ONLY; does NOT replace `core/mcp_server.py`,
  `MCPStdioServer`, `CommonStdioAdapterHost`, or `BrokerClient`.
- Zero mandatory dependency on `mcp`: imports safely in normal runtimes where SDK v2 is absent.
- Delegates ALL tool discovery, schema checks, authorization, redaction, and output bounds
  directly to NEXT-22C `AdaptiveMCPGateway` on every invocation (no trust in prior `tools/list`).
- Preserves `REMOTE_MCP_DISABLED = True` for production operation.
"""

from __future__ import annotations

import contextlib
import importlib.metadata
import inspect
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from mcp_gateway.authenticated_context import AuthenticatedCallerContext
from mcp_gateway.contracts import (
    GATEWAY_VERSION,
    UNIVERSAL_MINIMUM_READ_SCOPES,
    ClientCompatibilityProfile,
    GatewayErrorCode,
    ProtocolEra,
)
from mcp_gateway.gateway import AdaptiveMCPGateway, _default_unknown_caller
from mcp_gateway.untrusted_hints import UntrustedClientHints

REMOTE_MCP_DISABLED = True
SDK_COMPATIBILITY_DECISION = "SUITABLE_AS_OPTIONAL_COMPATIBILITY_BRIDGE"

try:
    import anyio
    import anyio.lowlevel
    import mcp as _mcp_pkg
    import mcp_types as _mcp_types
    from mcp.server.context import ServerRequestContext as _ServerRequestContext
    from mcp.server.lowlevel.server import NotificationOptions as _NotificationOptions
    from mcp.server.lowlevel.server import Server as _SDKServer
    from mcp.server.stdio import stdio_server as _stdio_server
    from mcp.server.subscriptions import (
        InMemorySubscriptionBus as _InMemorySubscriptionBus,
        ListenHandler as _ListenHandler,
        PromptsListChanged as _PromptsListChanged,
        ResourcesListChanged as _ResourcesListChanged,
        ResourceUpdated as _ResourceUpdated,
        ToolsListChanged as _ToolsListChanged,
    )
    from mcp.server.transport_security import DEFAULT_MAX_REQUEST_BODY_SIZE, TransportSecuritySettings
    from mcp.shared.exceptions import MCPError as _MCPError
    from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS

    SDK_V2_AVAILABLE = True
    try:
        SDK_V2_VERSION: str | None = importlib.metadata.version("mcp")
    except importlib.metadata.PackageNotFoundError:
        SDK_V2_VERSION = getattr(_mcp_pkg, "__version__", "unknown")
    try:
        MCP_TYPES_VERSION: str | None = importlib.metadata.version("mcp-types")
    except importlib.metadata.PackageNotFoundError:
        MCP_TYPES_VERSION = "unknown"
except ImportError:  # pragma: no cover - verified in non-SDK environment
    _mcp_pkg = None  # type: ignore[assignment]
    _mcp_types = None  # type: ignore[assignment]
    _ServerRequestContext = Any  # type: ignore[assignment,misc]
    _NotificationOptions = None  # type: ignore[assignment]
    _SDKServer = None  # type: ignore[assignment]
    _stdio_server = None  # type: ignore[assignment]
    _InMemorySubscriptionBus = None  # type: ignore[assignment]
    _ListenHandler = None  # type: ignore[assignment]
    _PromptsListChanged = None  # type: ignore[assignment]
    _ResourcesListChanged = None  # type: ignore[assignment]
    _ResourceUpdated = None  # type: ignore[assignment]
    _ToolsListChanged = None  # type: ignore[assignment]
    DEFAULT_MAX_REQUEST_BODY_SIZE = 4 * 1024 * 1024
    TransportSecuritySettings = None  # type: ignore[assignment]
    _MCPError = RuntimeError  # type: ignore[assignment,misc]
    HANDSHAKE_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
    MODERN_PROTOCOL_VERSIONS = ("2026-07-28",)
    SDK_V2_AVAILABLE = False
    SDK_V2_VERSION = None
    MCP_TYPES_VERSION = None


class SDKv2UnavailableError(RuntimeError):
    """Raised when SDK v2 qualification bridge is invoked outside the isolated SDK venv."""


def get_sdk_v2_status() -> dict[str, Any]:
    """Return non-mutating runtime availability summary for SDK v2 qualification."""
    return {
        "sdk_v2_available": SDK_V2_AVAILABLE,
        "sdk_v2_version": SDK_V2_VERSION,
        "mcp_types_version": MCP_TYPES_VERSION,
        "remote_mcp_disabled": REMOTE_MCP_DISABLED,
        "compatibility_decision": SDK_COMPATIBILITY_DECISION,
        "production_entrypoint_replaced": False,
    }


def _require_sdk_v2() -> None:
    if not SDK_V2_AVAILABLE:
        raise SDKv2UnavailableError(
            "Official MCP Python SDK v2 is not installed in this environment. "
            "Use the isolated NEXT-22E qualification venv for wire verification."
        )


def _dump_model_or_dict(val: Any) -> Any:
    if val is None:
        return None
    if hasattr(val, "model_dump"):
        return val.model_dump(by_alias=True, mode="json", exclude_none=True)
    if isinstance(val, dict):
        return dict(val)
    return None


def _extract_untrusted_hints(ctx: _ServerRequestContext[Any]) -> UntrustedClientHints:
    """Convert SDK per-connection or per-request client claims into strictly untrusted hints."""
    session = ctx.session
    caps = _dump_model_or_dict(session.client_capabilities) or {}
    client_info: dict[str, Any] = {}
    if getattr(session, "client_params", None) is not None and getattr(session.client_params, "client_info", None) is not None:
        client_info = _dump_model_or_dict(session.client_params.client_info) or {}
    meta_dict = _dump_model_or_dict(ctx.meta) or {}
    if not client_info and isinstance(meta_dict.get("io.modelcontextprotocol/clientInfo"), dict):
        client_info = dict(meta_dict["io.modelcontextprotocol/clientInfo"])

    protocol_version = ctx.protocol_version or getattr(session, "protocol_version", None)
    return UntrustedClientHints.from_mcp_params(
        {
            "clientInfo": client_info,
            "capabilities": caps,
            "protocolVersion": str(protocol_version) if protocol_version else None,
        }
    )


def _to_sdk_tool(entry: dict[str, Any]) -> Any:
    """Convert a NEXT-22C rendered catalog entry to an `mcp_types.Tool` object."""
    raw_ann = entry.get("annotations") if isinstance(entry.get("annotations"), dict) else {}
    sdk_ann = _mcp_types.ToolAnnotations(
        readOnlyHint=bool(raw_ann.get("readOnlyHint", True)),
        destructiveHint=False,
        idempotentHint=True,
    )
    return _mcp_types.Tool(
        name=entry["name"],
        title=entry.get("title"),
        description=entry.get("description"),
        inputSchema=entry["inputSchema"],
        outputSchema=entry.get("outputSchema"),
        annotations=sdk_ann,
    )


@dataclass
class GatewaySDKv2Bridge:
    """Bridges an AdaptiveMCPGateway instance onto an official MCP SDK v2.3.0 `Server`.

    Every `tools/list`, `tools/call`, and `subscriptions/listen` request evaluates
    the live caller context directly against `gateway.authz` with zero reliance
    on previously cached or listed tools.
    """

    gateway: AdaptiveMCPGateway
    caller_context: AuthenticatedCallerContext | None = None
    caller_context_provider: Callable[[], AuthenticatedCallerContext] | None = None
    notify_tools_changed: bool = True
    # Qualification-only test hooks (inert in normal operation)
    delay_before_privileged_work_seconds: float = 0.0
    stray_stdout_noise: str | None = None
    enable_read_only_multi_round_trip_probe: bool = False
    cancelled_calls: list[str] = field(default_factory=list)
    executed_calls: list[str] = field(default_factory=list)
    _subscription_bus: Any = field(init=False, default=None)
    _listen_handler: Any = field(init=False, default=None)

    def __post_init__(self) -> None:
        _require_sdk_v2()
        self._subscription_bus = _InMemorySubscriptionBus()
        self._listen_handler = _ListenHandler(self._subscription_bus)

    def current_caller(self) -> AuthenticatedCallerContext:
        if self.caller_context_provider is not None:
            return self.caller_context_provider()
        if self.caller_context is not None:
            return self.caller_context
        return _default_unknown_caller()

    def _resolve_profile(
        self,
        caller: AuthenticatedCallerContext,
        ctx: _ServerRequestContext[Any],
    ) -> tuple[UntrustedClientHints, ClientCompatibilityProfile]:
        hints = _extract_untrusted_hints(ctx)
        eff_proto = ctx.protocol_version or getattr(ctx.session, "protocol_version", None)
        prof = self.gateway.profile_resolver.resolve(
            caller=caller,
            untrusted_hints=hints,
            transport=caller.protocol_context.transport or "stdio",
            protocol_version=eff_proto,
            discovery_report=self.gateway.discovery_report,
            live_verified=False,
        )
        return hints, prof

    def _get_tool_input_schema(self, tool_name: str) -> dict[str, Any] | None:
        manifest = self.gateway.catalog.get(tool_name)
        return dict(manifest.input_schema) if manifest is not None else None

    async def _on_list_tools(
        self,
        ctx: _ServerRequestContext[Any],
        params: Any,
    ) -> Any:
        caller = self.current_caller()
        _, profile = self._resolve_profile(caller, ctx)
        cursor = getattr(params, "cursor", None) if params is not None else None
        try:
            tools_dicts, next_cursor, _ = self.gateway.compute_visible_tools(
                caller=caller,
                profile=profile,
                cursor=cursor,
            )
        except ValueError as exc:
            raise _MCPError(code=_mcp_types.INVALID_PARAMS, message=str(exc)) from exc
        sdk_tools = [_to_sdk_tool(item) for item in tools_dicts]
        return _mcp_types.ListToolsResult(tools=sdk_tools, nextCursor=next_cursor)

    async def _on_call_tool(
        self,
        ctx: _ServerRequestContext[Any],
        params: Any,
    ) -> Any:
        if self.stray_stdout_noise:
            # Qualification probe: proves SDK stdio fd diversion keeps stdout wire clean even on stray print().
            print(self.stray_stdout_noise)

        tool_name = str(params.name)
        arguments = dict(params.arguments) if isinstance(getattr(params, "arguments", None), dict) else {}

        # Cooperative cancellation point BEFORE performing any privileged/Gateway lookup work.
        try:
            if self.delay_before_privileged_work_seconds > 0:
                await anyio.sleep(self.delay_before_privileged_work_seconds)
            await anyio.lowlevel.checkpoint()
        except anyio.get_cancelled_exc_class():
            self.cancelled_calls.append(tool_name)
            raise

        caller = self.current_caller()
        hints, profile = self._resolve_profile(caller, ctx)

        # Optional 2026-07-28 multi-round-trip read-only qualification flow using InputRequiredResult.
        if (
            self.enable_read_only_multi_round_trip_probe
            and profile.protocol_era == ProtocolEra.MODERN
            and tool_name == "auditor_gateway_capabilities"
        ):
            input_responses = getattr(params, "input_responses", None)
            request_state = getattr(params, "request_state", None)
            if not input_responses or request_state != "next22e_readonly_probe_round1":
                return _mcp_types.InputRequiredResult(
                    inputRequests={
                        "confirm_view": _mcp_types.ElicitRequest(
                            params=_mcp_types.ElicitRequestFormParams(
                                message="Select read-only summary detail level",
                                requestedSchema={
                                    "type": "object",
                                    "properties": {"detail": {"type": "string", "default": "summary"}},
                                    "required": ["detail"],
                                },
                            )
                        )
                    },
                    requestState="next22e_readonly_probe_round1",
                )

        # Re-evaluate canonical Gateway catalog, schema, authz, execution_authorized=False, and redaction.
        gateway_result = self.gateway.call_tool(
            tool_name=tool_name,
            arguments=arguments,
            caller=caller,
            profile=profile,
            untrusted_hints=hints,
        )
        self.executed_calls.append(tool_name)

        text_items = [
            _mcp_types.TextContent(type="text", text=str(block.get("text", "")))
            for block in gateway_result.get("content", [])
            if isinstance(block, dict)
        ] or [_mcp_types.TextContent(type="text", text=json.dumps(gateway_result, ensure_ascii=False))]

        structured = gateway_result.get("structuredContent") if isinstance(gateway_result.get("structuredContent"), dict) else None
        is_error = bool(gateway_result.get("isError", False))
        # Ensure structuredContent is omitted whenever protocol compatibility disables structured output.
        if is_error or profile.protocol_version in ("2024-11-05", "2025-03-26"):
            structured = None

        return _mcp_types.CallToolResult(
            content=text_items,
            structuredContent=structured,
            isError=is_error,
        )

    async def _on_subscriptions_listen(
        self,
        ctx: _ServerRequestContext[Any],
        params: Any,
    ) -> Any:
        """Gate modern `subscriptions/listen` behind active caller authorization before delegating."""
        caller = self.current_caller()
        _, profile = self._resolve_profile(caller, ctx)
        if profile.protocol_era != ProtocolEra.MODERN:
            raise _MCPError(
                code=_mcp_types.INVALID_REQUEST,
                message="PROTOCOL_ERA_MISMATCH: subscriptions/listen requires MODERN protocol (>= 2026-07-28).",
            )
        if not caller.verified_application_identity:
            raise _MCPError(
                code=-32001,
                message="UNAUTHORIZED_SUBSCRIPTION: verified application identity required for subscriptions/listen.",
                data={"error_code": GatewayErrorCode.UNKNOWN_IDENTITY_READONLY_ONLY.value},
            )
        if not UNIVERSAL_MINIMUM_READ_SCOPES.issubset(caller.authorization_scopes):
            raise _MCPError(
                code=-32001,
                message="UNAUTHORIZED_SUBSCRIPTION: missing core:read scope.",
                data={"error_code": GatewayErrorCode.MISSING_SCOPE.value},
            )
        if caller.policy_generation < self.gateway.authz.min_active_policy_generation:
            raise _MCPError(
                code=-32001,
                message="STALE_POLICY_GENERATION: caller subscription rejected.",
                data={
                    "error_code": GatewayErrorCode.UNAUTHORIZED_CALLER.value,
                    "reason_code": "STALE_POLICY_GENERATION",
                },
            )
        # Ensure subscription notifications are authorized without ever leaking cross-account data.
        return await self._listen_handler(ctx, params)

    async def publish_tools_changed_if_authorized(
        self,
        *,
        target_caller: AuthenticatedCallerContext | None = None,
        reason: str = "catalog_refreshed",
    ) -> bool:
        """Publish `ToolsListChanged` onto the modern subscription bus ONLY if caller is still authorized."""
        caller = target_caller or self.current_caller()
        if not caller.verified_application_identity or caller.policy_generation < self.gateway.authz.min_active_policy_generation:
            return False
        if not UNIVERSAL_MINIMUM_READ_SCOPES.issubset(caller.authorization_scopes):
            return False
        await self._subscription_bus.publish(_ToolsListChanged())
        return True

    async def publish_resource_updated_if_authorized(
        self,
        *,
        uri: str,
        required_workspace_context_id: str | None = None,
        required_account_context_id: str | None = None,
        target_caller: AuthenticatedCallerContext | None = None,
    ) -> bool:
        """Gate account/workspace-scoped resource notifications strictly by caller context."""
        caller = target_caller or self.current_caller()
        if not caller.verified_application_identity:
            return False
        if required_workspace_context_id is not None and caller.workspace_context_id != required_workspace_context_id:
            return False
        if required_account_context_id is not None:
            if required_account_context_id not in caller.allowed_account_context_ids:
                return False
        await self._subscription_bus.publish(_ResourceUpdated(uri=uri))
        return True

    def build_lowlevel_server(self) -> Any:
        """Construct a fresh official SDK `Server` wired to this bridge."""
        async def _list_resources(_ctx: Any, _params: Any) -> Any:
            return _mcp_types.ListResourcesResult(resources=[])

        async def _list_prompts(_ctx: Any, _params: Any) -> Any:
            return _mcp_types.ListPromptsResult(prompts=[])

        return _SDKServer(
            name="antigravity-auditor",
            version=GATEWAY_VERSION,
            instructions="Read-only Adaptive MCP Gateway compatibility bridge (qualification mode; execution_authorized=false).",
            get_tool_input_schema=self._get_tool_input_schema,
            on_list_tools=self._on_list_tools,
            on_call_tool=self._on_call_tool,
            on_list_resources=_list_resources,
            on_list_prompts=_list_prompts,
            on_subscriptions_listen=self._on_subscriptions_listen,
        )

    async def run_stdio_async(self) -> None:
        """Serve dual-era MCP (`2024-11-05`..`2025-11-25` and `2026-07-28`) over process stdio."""
        server = self.build_lowlevel_server()
        opts = server.create_initialization_options(
            notification_options=_NotificationOptions(tools_changed=self.notify_tools_changed)
        )
        async with _stdio_server() as (read_stream, write_stream):
            # Flush any buffered pre-server output while fd 1 is diverted to stderr, then
            # redirect Python `sys.stdout` to `sys.stderr` so buffered `print()` calls cannot
            # flush onto fd 1 after `stdio_server()` restores the wire descriptor at exit.
            with contextlib.redirect_stdout(sys.stderr):
                try:
                    await server.run(read_stream, write_stream, opts)
                finally:
                    sys.stdout.flush()
                    sys.stderr.flush()

    def serve_stdio(self) -> None:
        """Synchronous entrypoint for qualification stdio subprocess harness."""
        anyio.run(self.run_stdio_async)

    def build_loopback_asgi_app(self, *, stateless_http: bool = True, max_request_body_size: int = 1024 * 1024) -> Any:
        """Build a strict localhost-only Starlette app for Part 8 loopback compatibility study."""
        server = self.build_lowlevel_server()
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*"],
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*"],
        )
        return server.streamable_http_app(
            streamable_http_path="/mcp",
            stateless_http=stateless_http,
            max_request_body_size=max_request_body_size,
            transport_security=security,
            host="127.0.0.1",
        )


__all__ = [
    "GatewaySDKv2Bridge",
    "HANDSHAKE_PROTOCOL_VERSIONS",
    "MCP_TYPES_VERSION",
    "MODERN_PROTOCOL_VERSIONS",
    "REMOTE_MCP_DISABLED",
    "SDK_COMPATIBILITY_DECISION",
    "SDK_V2_AVAILABLE",
    "SDK_V2_VERSION",
    "SDKv2UnavailableError",
    "get_sdk_v2_status",
]

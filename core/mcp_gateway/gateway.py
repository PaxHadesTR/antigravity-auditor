"""Central Adaptive MCP Gateway orchestrating discovery, compatibility, authorization, and routing."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any


class _BoundedSessionMap(OrderedDict):
    """Per-principal compatibility hints with LRU eviction, so a long-lived host cannot grow without bound."""

    def __init__(self, max_entries: int = 256) -> None:
        super().__init__()
        self._max_entries = max_entries

    def __setitem__(self, key: Any, value: Any) -> None:
        super().__setitem__(key, value)
        self.move_to_end(key)
        while len(self) > self._max_entries:
            self.popitem(last=False)

from entitlement_router.privacy import SecretOrPiiIntakeError, sanitize_for_output
from mcp_server import AuditorMCPDispatcher, validate_strict_schema
from mcp_gateway.authenticated_context import (
    AuthenticatedCallerContext,
    CallerIdentityResolver,
)
from mcp_gateway.authorization_resolver import AuthorizationResolver
from mcp_gateway.catalog_cache import CatalogCache
from mcp_gateway.catalog_registry import CanonicalCatalogRegistry
from mcp_gateway.client_profile_resolver import ClientProfileResolver, classify_protocol_era
from mcp_gateway.compatibility import evaluate_feature_compatibility
from mcp_gateway.contracts import (
    AuthMethod,
    ClientCompatibilityProfile,
    GATEWAY_VERSION,
    GatewayErrorCode,
    ProtocolEra,
    utc_now_iso,
)
from mcp_gateway.notifications import NotificationManager
from mcp_gateway.output_adapter import OutputAdapter
from mcp_gateway.protocol_adapter import (
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    LegacyProtocolAdapter,
    ModernProtocolAdapter,
    paginate_items,
    render_tool_entry,
)
from mcp_gateway.routing_tools import RoutingToolBridge
from mcp_gateway.untrusted_hints import UntrustedClientHints


def _default_unknown_caller() -> AuthenticatedCallerContext:
    return AuthenticatedCallerContext(
        principal_id="unknown-unverified-caller",
        application_id="UNKNOWN",
        authentication_method=AuthMethod.UNKNOWN,
        authorization_scopes=frozenset(),
        verified_application_identity=False,
        operating_system_identity={"verified_by_os": False},
        context_evidence_refs=("identity:default:unknown",),
        diagnostic_reasons=("NO_AUTHENTICATED_CALLER_CONTEXT",),
    )


class AdaptiveMCPGateway:
    """Application-neutral Adaptive MCP Gateway facade around AuditorMCPDispatcher & CapabilityModelRouter."""

    def __init__(
        self,
        *,
        dispatcher: AuditorMCPDispatcher | None = None,
        catalog_registry: CanonicalCatalogRegistry | None = None,
        identity_resolver: CallerIdentityResolver | None = None,
        profile_resolver: ClientProfileResolver | None = None,
        authorization_resolver: AuthorizationResolver | None = None,
        catalog_cache: CatalogCache | None = None,
        notification_manager: NotificationManager | None = None,
        output_adapter: OutputAdapter | None = None,
        routing_bridge: RoutingToolBridge | None = None,
        discovery_report: dict[str, Any] | None = None,
    ) -> None:
        self.dispatcher = dispatcher
        self.catalog = catalog_registry or CanonicalCatalogRegistry()
        self.identity_resolver = identity_resolver or CallerIdentityResolver()
        self.profile_resolver = profile_resolver or ClientProfileResolver()
        self.authz = authorization_resolver or AuthorizationResolver()
        self.cache = catalog_cache or CatalogCache()
        self.notifications = notification_manager or NotificationManager()
        self.output_adapter = output_adapter or OutputAdapter()
        self.routing_bridge = routing_bridge or RoutingToolBridge()
        self.discovery_report = discovery_report

        self.legacy_adapter = LegacyProtocolAdapter()
        self.modern_adapter = ModernProtocolAdapter()

        # Session compatibility hints per principal (NEVER stores authorization state).
        self._session_profiles: dict[str, ClientCompatibilityProfile] = _BoundedSessionMap()
        self._session_eras: dict[str, ProtocolEra] = _BoundedSessionMap()
        self._audit_events: list[dict[str, Any]] = []

    def _append_audit_event(self, event: dict[str, Any]) -> None:
        sanitized = sanitize_for_output({"timestamp": utc_now_iso(), **event})
        self._audit_events.append(sanitized)
        if len(self._audit_events) > 500:
            self._audit_events = self._audit_events[-500:]

    @property
    def audit_events(self) -> list[dict[str, Any]]:
        return list(self._audit_events)

    def resolve_profile_for_request(
        self,
        *,
        caller: AuthenticatedCallerContext,
        untrusted_hints: UntrustedClientHints | None = None,
        transport: str | None = None,
        protocol_version: str | None = None,
    ) -> ClientCompatibilityProfile:
        cached_prof = self._session_profiles.get(caller.principal_id)
        if cached_prof is not None:
            same_proto = protocol_version is None or protocol_version == cached_prof.protocol_version
            no_new_caps = untrusted_hints is None or not untrusted_hints.declared_capabilities
            if same_proto and no_new_caps:
                return cached_prof
        eff_proto = protocol_version or (
            untrusted_hints.declared_protocol_version if untrusted_hints else None
        ) or caller.protocol_context.protocol_version
        return self.profile_resolver.resolve(
            caller=caller,
            untrusted_hints=untrusted_hints,
            transport=transport or caller.protocol_context.transport,
            protocol_version=eff_proto,
            discovery_report=self.discovery_report,
            live_verified=False,
        )

    def compute_visible_tools(
        self,
        *,
        caller: AuthenticatedCallerContext,
        profile: ClientCompatibilityProfile,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> tuple[list[dict[str, Any]], str | None, dict[str, Any]]:
        """Return deterministically ordered, filtered, and isolated tool catalog page."""
        authz_policy_state = f"min_pgen={self.authz.min_active_policy_generation}|exec={self.authz.allow_execution_tools}"
        cache_hit = False
        cached = self.cache.get(
            caller=caller,
            profile=profile,
            catalog_version=self.catalog.catalog_version,
            manifest_sha256=self.catalog.manifest_sha256,
            authz_policy_state=authz_policy_state,
        )
        if cached is not None:
            all_rendered = list(cached.tools_payload)
            cache_key = cached.cache_key
            cache_hit = True
        else:
            all_rendered = []
            for tool in self.catalog.list_ordered():
                vis = self.authz.evaluate_visibility(caller=caller, tool=tool, profile=profile)
                if vis.allowed:
                    all_rendered.append(render_tool_entry(tool, profile))
            cache_key = self.cache.put(
                caller=caller,
                profile=profile,
                catalog_version=self.catalog.catalog_version,
                manifest_sha256=self.catalog.manifest_sha256,
                authz_policy_state=authz_policy_state,
                tools_payload=all_rendered,
                metadata={"tool_count": len(all_rendered)},
            )

        compat = evaluate_feature_compatibility(profile)
        page_size = limit if limit is not None else compat.max_items
        paged, next_cursor = paginate_items(all_rendered, cursor=cursor, page_size=page_size)
        meta = {
            "cache_hit": cache_hit,
            "cache_key_prefix": cache_key[:16],
            "total_visible": len(all_rendered),
            "catalog_version": self.catalog.catalog_version,
            "manifest_sha256": self.catalog.manifest_sha256,
        }
        return paged, next_cursor, meta

    def explain_catalog_filter(
        self,
        *,
        caller: AuthenticatedCallerContext,
        profile: ClientCompatibilityProfile,
    ) -> dict[str, Any]:
        """Diagnostic trace showing exact included vs excluded tools per caller/profile."""
        included: list[dict[str, Any]] = []
        excluded: list[dict[str, Any]] = []
        for tool in self.catalog.list_ordered():
            vis = self.authz.evaluate_visibility(caller=caller, tool=tool, profile=profile)
            row = {
                "tool_name": tool.tool_name,
                "tool_group": tool.tool_group.value,
                "required_scopes": list(tool.required_authorization_scopes),
                "reason_codes": list(vis.reason_codes),
                "reason": vis.reason,
            }
            if vis.allowed:
                included.append(row)
            else:
                excluded.append(row)
        return sanitize_for_output(
            {
                "principal_id": caller.principal_id,
                "application_id": caller.application_id,
                "verified_application_identity": caller.verified_application_identity,
                "authorization_scopes": sorted(caller.authorization_scopes),
                "included_count": len(included),
                "excluded_count": len(excluded),
                "included": included,
                "excluded": excluded,
            }
        )

    def _gateway_capabilities_handler(
        self,
        caller: AuthenticatedCallerContext,
        profile: ClientCompatibilityProfile,
    ) -> dict[str, Any]:
        compat = evaluate_feature_compatibility(profile)
        return sanitize_for_output(
            {
                "gateway_version": GATEWAY_VERSION,
                "catalog_version": self.catalog.catalog_version,
                "protocol_era": profile.protocol_era.value,
                "protocol_version": profile.protocol_version,
                "application_id": caller.application_id,
                "verified_application_identity": caller.verified_application_identity,
                "compatibility_state": compat.to_dict(),
                "authorization_scopes": sorted(caller.authorization_scopes),
                "diagnostic_reasons": list(caller.diagnostic_reasons),
                "execution_authorized": False,
            }
        )

    def call_tool(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any] | None,
        caller: AuthenticatedCallerContext,
        profile: ClientCompatibilityProfile | None = None,
        untrusted_hints: UntrustedClientHints | None = None,
    ) -> dict[str, Any]:
        """Execute the single 15-step tool validation pipeline (Part 11)."""
        eff_profile = profile or self.resolve_profile_for_request(
            caller=caller,
            untrusted_hints=untrusted_hints,
        )

        # Step 4: Validate tool existence
        tool = self.catalog.get(tool_name)
        if tool is None:
            self._append_audit_event(
                {
                    "event": "tool_call_rejected",
                    "principal_id": caller.principal_id,
                    "tool_name": tool_name,
                    "error_code": GatewayErrorCode.TOOL_NOT_FOUND.value,
                }
            )
            return self.output_adapter.format_error(
                message=f"Unknown MCP tool: {tool_name}",
                error_code=GatewayErrorCode.TOOL_NOT_FOUND.value,
                profile=eff_profile,
            )

        # Step 5: Validate input schema strictly
        args = arguments if isinstance(arguments, dict) else {}
        try:
            validate_strict_schema(args, tool.input_schema, f"input({tool.tool_name})")
        except Exception as exc:
            self._append_audit_event(
                {
                    "event": "tool_call_schema_rejected",
                    "principal_id": caller.principal_id,
                    "tool_name": tool.tool_name,
                    "error": str(exc),
                }
            )
            return self.output_adapter.format_error(
                message=str(exc),
                error_code=GatewayErrorCode.SCHEMA_VALIDATION_FAILED.value,
                profile=eff_profile,
            )

        # Steps 6-10: Scope, re-evaluated authorization, risk, governance & lease checks
        decision = self.authz.authorize_tool_call(
            caller=caller,
            tool=tool,
            arguments=args,
            untrusted_hints=untrusted_hints,
        )
        if not decision.allowed:
            err_code = (
                decision.error_code.value
                if decision.error_code is not None
                else GatewayErrorCode.UNAUTHORIZED_CALLER.value
            )
            self._append_audit_event(
                {
                    "event": "tool_call_unauthorized",
                    "principal_id": caller.principal_id,
                    "application_id": caller.application_id,
                    "tool_name": tool.tool_name,
                    "error_code": err_code,
                    "reason_codes": list(decision.reason_codes),
                }
            )
            return self.output_adapter.format_error(
                message=decision.reason,
                error_code=err_code,
                details={"reason_codes": list(decision.reason_codes)},
                profile=eff_profile,
            )

        # Step 11: Invoke the existing canonical handler
        try:
            if tool.implementation_handler == "gateway.capabilities":
                raw_result = self._gateway_capabilities_handler(caller, eff_profile)
            elif tool.implementation_handler.startswith("routing."):
                raw_result = self.routing_bridge.handle_tool(tool.implementation_handler, args, caller)
            else:
                if self.dispatcher is None:
                    raise RuntimeError(
                        f"Dispatcher handler unavailable for '{tool.tool_name}'."
                    )
                raw_result = self.dispatcher.call_tool(tool.tool_name, args)

            # Steps 12-14: Schema check, redaction, compatibility formatting
            formatted = self.output_adapter.format_result(
                tool=tool,
                raw_result=raw_result,
                profile=eff_profile,
            )
        except SecretOrPiiIntakeError as exc:
            self._append_audit_event(
                {
                    "event": "tool_call_privacy_rejected",
                    "principal_id": caller.principal_id,
                    "tool_name": tool.tool_name,
                    "error": str(exc),
                }
            )
            return self.output_adapter.format_error(
                message=str(exc),
                error_code=GatewayErrorCode.SECRET_OR_PII_REJECTED.value,
                profile=eff_profile,
            )
        except PermissionError as exc:
            # Execution tools refuse for a missing/insufficient approval, not for a cross-account access.
            code = (
                GatewayErrorCode.GOVERNANCE_APPROVAL_REQUIRED
                if tool_name in ("auditor_start_execution", "auditor_authorize_execution")
                else GatewayErrorCode.CROSS_ACCOUNT_DENIED
            )
            return self.output_adapter.format_error(
                message=str(exc),
                error_code=code.value,
                profile=eff_profile,
            )
        except Exception as exc:
            self._append_audit_event(
                {
                    "event": "tool_call_error",
                    "principal_id": caller.principal_id,
                    "tool_name": tool.tool_name,
                    "error": str(exc),
                }
            )
            return self.output_adapter.format_error(
                message=str(exc),
                error_code=GatewayErrorCode.INTERNAL_HANDLER_ERROR.value,
                profile=eff_profile,
            )

        # Step 15: Append safe redacted audit evidence
        self._append_audit_event(
            {
                "event": "tool_call_succeeded",
                "principal_id": caller.principal_id,
                "application_id": caller.application_id,
                "tool_name": tool.tool_name,
                "protocol_era": eff_profile.protocol_era.value,
            }
        )
        return formatted

    def handle_jsonrpc_message(
        self,
        msg: dict[str, Any],
        *,
        caller_context: AuthenticatedCallerContext | None = None,
    ) -> dict[str, Any] | None:
        """Process a single JSON-RPC 2.0 MCP message under strict Gateway boundaries."""
        if not isinstance(msg, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": JSONRPC_INVALID_REQUEST, "message": "Message must be a JSON object."},
            }

        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

        if msg_id is None:
            return None

        caller = caller_context if caller_context is not None else _default_unknown_caller()
        hints = UntrustedClientHints.from_mcp_params(params)

        try:
            # Strict era separation: initialize is LEGACY only; server/discover & subscriptions/listen are MODERN only.
            if method == "initialize":
                if self._session_eras.get(caller.principal_id) == ProtocolEra.MODERN:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": JSONRPC_INVALID_REQUEST,
                            "message": "PROTOCOL_ERA_MISMATCH: initialize is invalid on a MODERN protocol session.",
                        },
                    }
                neg = self.legacy_adapter.negotiate_initialize(params)
                if not neg.accepted:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": JSONRPC_INVALID_PARAMS,
                            "message": neg.reason,
                            "data": {"error_code": GatewayErrorCode.UNSUPPORTED_PROTOCOL_VERSION.value},
                        },
                    }
                prof = self.profile_resolver.resolve(
                    caller=caller,
                    untrusted_hints=hints,
                    transport=caller.protocol_context.transport,
                    protocol_version=neg.protocol_version,
                    discovery_report=self.discovery_report,
                )
                self._session_profiles[caller.principal_id] = prof
                self._session_eras[caller.principal_id] = ProtocolEra.LEGACY
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": self.legacy_adapter.build_initialize_result(
                        protocol_version=neg.protocol_version,
                        profile=prof,
                    ),
                }

            if method == "server/discover":
                if self._session_eras.get(caller.principal_id) == ProtocolEra.LEGACY:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": JSONRPC_INVALID_REQUEST,
                            "message": "PROTOCOL_ERA_MISMATCH: server/discover requires MODERN protocol context, not LEGACY initialize.",
                        },
                    }
                neg = self.modern_adapter.validate_request_version(params)
                if not neg.accepted:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": JSONRPC_INVALID_PARAMS,
                            "message": neg.reason,
                            "data": {"error_code": GatewayErrorCode.UNSUPPORTED_PROTOCOL_VERSION.value},
                        },
                    }
                prof = self.profile_resolver.resolve(
                    caller=caller,
                    untrusted_hints=hints,
                    transport=caller.protocol_context.transport,
                    protocol_version=neg.protocol_version,
                    discovery_report=self.discovery_report,
                )
                self._session_profiles[caller.principal_id] = prof
                self._session_eras[caller.principal_id] = ProtocolEra.MODERN
                tools, next_cursor, _ = self.compute_visible_tools(
                    caller=caller,
                    profile=prof,
                    cursor=params.get("cursor"),
                    limit=params.get("limit"),
                )
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": self.modern_adapter.build_server_discover_result(
                        protocol_version=neg.protocol_version,
                        profile=prof,
                        visible_tools=tools,
                        next_cursor=next_cursor,
                    ),
                }

            if method == "subscriptions/listen":
                req_proto = hints.declared_protocol_version
                if self._session_eras.get(caller.principal_id) == ProtocolEra.LEGACY and not req_proto:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": JSONRPC_INVALID_REQUEST,
                            "message": "PROTOCOL_ERA_MISMATCH: subscriptions/listen is unsupported in LEGACY era.",
                        },
                    }
                prof = self.resolve_profile_for_request(
                    caller=caller,
                    untrusted_hints=hints if req_proto else None,
                    protocol_version=req_proto,
                )
                if prof.protocol_era != ProtocolEra.MODERN:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": JSONRPC_INVALID_REQUEST,
                            "message": "PROTOCOL_ERA_MISMATCH: subscriptions/listen requires MODERN protocol (>= 2026-07-28).",
                        },
                    }
                ok_sub, sub_res = self.notifications.subscribe(
                    principal_id=caller.principal_id,
                    profile=prof,
                    channel=str(params.get("channel") or "tools/list"),
                )
                if not ok_sub:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": JSONRPC_INVALID_PARAMS, "message": str(sub_res.get("reason"))},
                    }
                return {"jsonrpc": "2.0", "id": msg_id, "result": sub_res}

            if method == "ping":
                return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
            if method == "resources/list":
                return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}}
            if method == "prompts/list":
                return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}

            if method == "tools/list":
                req_proto = hints.declared_protocol_version
                if req_proto and classify_protocol_era(req_proto) == ProtocolEra.UNSUPPORTED:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": JSONRPC_INVALID_PARAMS,
                            "message": f"Unsupported protocolVersion '{req_proto}'.",
                        },
                    }
                prof = self.resolve_profile_for_request(
                    caller=caller,
                    untrusted_hints=hints if req_proto else None,
                    protocol_version=req_proto,
                )
                tools, next_cursor, _ = self.compute_visible_tools(
                    caller=caller,
                    profile=prof,
                    cursor=params.get("cursor"),
                    limit=params.get("limit"),
                )
                res: dict[str, Any] = {"tools": tools}
                if next_cursor is not None:
                    res["nextCursor"] = next_cursor
                return {"jsonrpc": "2.0", "id": msg_id, "result": res}

            if method == "tools/call":
                req_proto = hints.declared_protocol_version
                if req_proto and classify_protocol_era(req_proto) == ProtocolEra.UNSUPPORTED:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": JSONRPC_INVALID_PARAMS,
                            "message": f"Unsupported protocolVersion '{req_proto}'.",
                        },
                    }
                prof = self.resolve_profile_for_request(
                    caller=caller,
                    untrusted_hints=hints if req_proto else None,
                    protocol_version=req_proto,
                )
                tool_name = str(params.get("name") or "")
                tool_args = params.get("arguments")
                if tool_args is not None and not isinstance(tool_args, dict):
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": JSONRPC_INVALID_PARAMS, "message": "tools/call 'arguments' must be an object."},
                    }
                call_res = self.call_tool(
                    tool_name=tool_name,
                    arguments=tool_args if isinstance(tool_args, dict) else {},
                    caller=caller,
                    profile=prof,
                    untrusted_hints=hints,
                )
                return {"jsonrpc": "2.0", "id": msg_id, "result": call_res}

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": JSONRPC_METHOD_NOT_FOUND, "message": f"Method not found: {method}"},
            }
        except (ValueError, TypeError) as exc:
            # Malformed client parameters (pagination cursor/limit, ...) are invalid params, not server errors.
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": JSONRPC_INVALID_PARAMS, "message": str(exc)},
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32603, "message": str(exc)},
            }

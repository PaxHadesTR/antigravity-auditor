"""Independent per-request authorization and visibility filtering for NEXT-22C."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from entitlement_router.privacy import sanitize_for_output
from mcp_gateway.authenticated_context import AuthenticatedCallerContext
from mcp_gateway.compatibility import evaluate_feature_compatibility, tool_meets_minimum_features
from mcp_gateway.contracts import (
    AuthMethod,
    CanonicalToolManifest,
    ClientCompatibilityProfile,
    GatewayErrorCode,
    ToolGroup,
)
from mcp_gateway.untrusted_hints import UntrustedClientHints


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason_codes: tuple[str, ...]
    reason: str
    error_code: GatewayErrorCode | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "allowed": self.allowed,
                "reason_codes": list(self.reason_codes),
                "reason": self.reason,
                "error_code": self.error_code.value if self.error_code else None,
                "diagnostics": self.diagnostics,
            }
        )


CallerRevocationHook = Callable[[AuthenticatedCallerContext, CanonicalToolManifest], tuple[bool, str | None]]


class AuthorizationResolver:
    """Separates `tools/list` visibility from authoritative per-call authorization.

    Tool visibility is NEVER treated as authorization. Every `tools/call` re-evaluates
    caller identity, live revocation/policy generation, scopes, account boundaries,
    and governance preconditions.
    """

    def __init__(
        self,
        *,
        allow_execution_tools: bool = True,
        min_active_policy_generation: int = 1,
        revocation_hook: CallerRevocationHook | None = None,
    ) -> None:
        self.allow_execution_tools = allow_execution_tools
        self.min_active_policy_generation = min_active_policy_generation
        self.revocation_hook = revocation_hook

    def _check_base_caller_health(
        self,
        caller: AuthenticatedCallerContext,
    ) -> AuthorizationDecision | None:
        if not caller.is_authenticated or caller.authentication_method == AuthMethod.UNAUTHENTICATED:
            return AuthorizationDecision(
                allowed=False,
                error_code=GatewayErrorCode.UNAUTHORIZED_CALLER,
                reason_codes=("UNAUTHENTICATED_CALLER",),
                reason="Caller is not authenticated.",
            )
        os_id = caller.operating_system_identity or {}
        if os_id.get("remote_http_disabled"):
            return AuthorizationDecision(
                allowed=False,
                error_code=GatewayErrorCode.REMOTE_HTTP_DISABLED,
                reason_codes=("REMOTE_HTTP_DEPLOYMENT_DISABLED",),
                reason="Remote HTTP transport is disabled in NEXT-22C.",
            )
        if os_id.get("sid_mismatch"):
            return AuthorizationDecision(
                allowed=False,
                error_code=GatewayErrorCode.SID_MISMATCH,
                reason_codes=("OS_SID_MISMATCH",),
                reason="OS security identifier mismatch.",
            )
        if os_id.get("is_low_integrity") or str(os_id.get("integrity_level", "")).upper() in ("LOW", "UNTRUSTED", "UNKNOWN"):
            return AuthorizationDecision(
                allowed=False,
                error_code=GatewayErrorCode.LOW_INTEGRITY_REJECTED,
                reason_codes=("LOW_INTEGRITY_REJECTED",),
                reason="Low integrity callers are not permitted.",
            )
        if caller.policy_generation < self.min_active_policy_generation:
            return AuthorizationDecision(
                allowed=False,
                error_code=GatewayErrorCode.UNAUTHORIZED_CALLER,
                reason_codes=("EXPIRED_POLICY_GENERATION",),
                reason=(
                    f"Caller policy generation {caller.policy_generation} is older than active "
                    f"minimum {self.min_active_policy_generation}."
                ),
            )
        return None

    def evaluate_visibility(
        self,
        *,
        caller: AuthenticatedCallerContext,
        tool: CanonicalToolManifest,
        profile: ClientCompatibilityProfile,
    ) -> AuthorizationDecision:
        """Compute whether `tool` should be listed in `tools/list` for compatibility & UX."""
        base_err = self._check_base_caller_health(caller)
        if base_err is not None:
            return base_err

        missing_scopes = [s for s in tool.required_authorization_scopes if s not in caller.authorization_scopes]
        if missing_scopes:
            return AuthorizationDecision(
                allowed=False,
                error_code=GatewayErrorCode.MISSING_SCOPE,
                reason_codes=tuple(f"MISSING_SCOPE:{s}" for s in missing_scopes),
                reason=f"Caller lacks required scopes for listing: {missing_scopes}",
            )

        if caller.is_unknown_application and tool.tool_group != ToolGroup.CORE_READ:
            return AuthorizationDecision(
                allowed=False,
                error_code=GatewayErrorCode.UNKNOWN_IDENTITY_READONLY_ONLY,
                reason_codes=("UNKNOWN_APP_IDENTITY_LIMITED_TO_CORE_READ",),
                reason="Unknown application identity exposes only minimum universally safe read-only tools.",
            )

        if tool.execution_mutating and not self.allow_execution_tools:
            return AuthorizationDecision(
                allowed=False,
                error_code=GatewayErrorCode.EXECUTION_DISABLED_FOR_CALLER,
                reason_codes=("EXECUTION_TOOLS_DISABLED_BY_POLICY",),
                reason="Execution control tools are disabled in the active Gateway policy.",
            )

        ok_compat, missing_feats = tool_meets_minimum_features(tool, profile)
        if not ok_compat:
            return AuthorizationDecision(
                allowed=False,
                reason_codes=tuple(missing_feats),
                reason=f"Client compatibility lacks required features: {missing_feats}",
            )

        compat = evaluate_feature_compatibility(profile)
        return AuthorizationDecision(
            allowed=True,
            reason_codes=("VISIBLE",),
            reason="Tool meets caller scope and compatibility criteria.",
            diagnostics={"compatibility": compat.to_dict()},
        )

    def authorize_tool_call(
        self,
        *,
        caller: AuthenticatedCallerContext,
        tool: CanonicalToolManifest,
        arguments: dict[str, Any],
        untrusted_hints: UntrustedClientHints | None = None,
    ) -> AuthorizationDecision:
        """Authoritative per-invocation authorization check (independent of `tools/list` visibility)."""
        reasons: list[str] = []
        if untrusted_hints is not None and untrusted_hints.claimed_model_id:
            reasons.append("MODEL_HINT_IGNORED_FOR_AUTHORIZATION")

        base_err = self._check_base_caller_health(caller)
        if base_err is not None:
            return base_err

        if self.revocation_hook is not None:
            still_ok, revoke_reason = self.revocation_hook(caller, tool)
            if not still_ok:
                return AuthorizationDecision(
                    allowed=False,
                    error_code=GatewayErrorCode.UNAUTHORIZED_CALLER,
                    reason_codes=("AUTHORIZATION_REVOKED_OR_STALE",),
                    reason=revoke_reason or "Caller authorization revoked or policy expired.",
                    diagnostics={"notes": reasons},
                )

        if caller.is_unknown_application and tool.tool_group != ToolGroup.CORE_READ:
            return AuthorizationDecision(
                allowed=False,
                error_code=GatewayErrorCode.UNKNOWN_IDENTITY_READONLY_ONLY,
                reason_codes=("UNKNOWN_APP_IDENTITY_EXECUTION_FORBIDDEN",),
                reason=(
                    f"Tool '{tool.tool_name}' ({tool.tool_group.value}) requires verified application/account "
                    "scope; unknown callers are limited to CORE_READ."
                ),
                diagnostics={"notes": reasons},
            )

        missing_scopes = [s for s in tool.required_authorization_scopes if s not in caller.authorization_scopes]
        if missing_scopes:
            return AuthorizationDecision(
                allowed=False,
                error_code=GatewayErrorCode.MISSING_SCOPE,
                reason_codes=tuple(f"MISSING_SCOPE:{s}" for s in missing_scopes),
                reason=f"Caller is missing required authorization scope(s): {missing_scopes}",
                diagnostics={"notes": reasons},
            )

        if tool.execution_mutating and not self.allow_execution_tools:
            return AuthorizationDecision(
                allowed=False,
                error_code=GatewayErrorCode.EXECUTION_DISABLED_FOR_CALLER,
                reason_codes=("EXECUTION_DISABLED_BY_GATEWAY_POLICY",),
                reason=f"Execution tool '{tool.tool_name}' is disabled in this Gateway policy.",
                diagnostics={"notes": reasons},
            )

        # Enforce account & user profile isolation on routing/account-scoped arguments (and fail closed if unbound)
        if tool.tool_group in (ToolGroup.ROUTING_READ, ToolGroup.PLANNING):
            if not caller.allowed_user_profile_ids:
                return AuthorizationDecision(
                    allowed=False,
                    error_code=GatewayErrorCode.CROSS_PRINCIPAL_DENIED,
                    reason_codes=("NO_USER_PROFILE_BOUND_TO_CALLER",),
                    reason="Caller has no bound user_profile_id allowlist.",
                    diagnostics={"notes": reasons},
                )
            req_user = arguments.get("user_profile_id")
            if req_user is not None:
                if req_user not in caller.allowed_user_profile_ids:
                    return AuthorizationDecision(
                        allowed=False,
                        error_code=GatewayErrorCode.CROSS_PRINCIPAL_DENIED,
                        reason_codes=("CROSS_USER_PROFILE_DENIED",),
                        reason=f"Caller is not authorized for user_profile_id '{req_user}'.",
                        diagnostics={"notes": reasons},
                    )

            req_acct = arguments.get("account_context_id")
            if req_acct is not None:
                allowed_accts = set(caller.allowed_account_context_ids)
                if caller.account_context_id:
                    allowed_accts.add(caller.account_context_id)
                if req_acct not in allowed_accts:
                    return AuthorizationDecision(
                        allowed=False,
                        error_code=GatewayErrorCode.CROSS_ACCOUNT_DENIED,
                        reason_codes=("CROSS_ACCOUNT_ACCESS_DENIED",),
                        reason=f"Caller is not authorized for account_context_id '{req_acct}'.",
                        diagnostics={"notes": reasons},
                    )

        # auditor_start_execution: the handler resolves and validates the approval itself (terminal approval found
        # by project, chat approval in simple mode, auto-approval policy, or an explicit approval_id) and refuses
        # with the way forward when there is none; a presence check here would only block valid forms.
        # Execution lease presence check before invoking mutating control plane handlers:
        if tool.requires_lease and tool.tool_name in ("auditor_update_finding_execution", "auditor_finalize_execution"):
            if not arguments.get("exec_id"):
                return AuthorizationDecision(
                    allowed=False,
                    error_code=GatewayErrorCode.EXECUTION_LEASE_REQUIRED,
                    reason_codes=("MISSING_EXEC_ID_LEASE",),
                    reason=f"{tool.tool_name} requires an active exec_id execution session.",
                )

        return AuthorizationDecision(
            allowed=True,
            reason_codes=tuple(["AUTHORIZED"] + reasons),
            reason="Per-request authorization checks passed.",
            diagnostics={"notes": reasons},
        )

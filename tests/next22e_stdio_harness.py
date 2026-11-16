"""Isolated subprocess test harness for NEXT-22E wire & resilience qualification.

Runs strictly inside disposable temporary test directories with synthetic data.
Never connects to production Named Pipes, production SQLite DBs, or live apps.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import warnings

CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from application_adapters import (
    ApplicationAdapterRegistry,
    CommonStdioAdapterHost,
    InMemoryBrokerTransport,
)
from db import initialize
from entitlement_router.contracts import (
    AccountContextRecord,
    ApplicationInstanceRecord,
    AuthenticationMode,
    CapabilityDimension,
    CapabilityState,
    ConfidenceLevel,
    CostPolicy,
    EntitlementState,
    ModelCapabilityEvidence,
    ModelEffortProfile,
    ModelEntitlementObservation,
    ModelIdentityRecord,
    NormalizedEffort,
    QuotaObservation,
    QuotaState,
    SubscriptionSource,
    UserProfileRecord,
    UserRoutingPolicy,
)
from entitlement_router.registry import EntitlementRegistry
from mcp_gateway import (
    AdaptiveMCPGateway,
    AuthMethod,
    AuthenticatedCallerContext,
    GatewaySDKv2Bridge,
    ProtocolContext,
    RoutingToolBridge,
    UNIVERSAL_MINIMUM_READ_SCOPES,
)
from mcp_server import AuditorMCPDispatcher


def build_disposable_gateway(tmp_db: Path) -> AdaptiveMCPGateway:
    """Create a completely isolated disposable DB + EntitlementRegistry + Gateway."""
    initialize(tmp_db)
    reg = EntitlementRegistry()
    reg.register_user(UserProfileRecord(user_profile_id="usr-qual"))
    reg.set_policy(
        UserRoutingPolicy(
            policy_id="pol-qual",
            user_profile_id="usr-qual",
            api_billing_allowed=False,
        )
    )
    reg.register_application(
        ApplicationInstanceRecord(
            application_instance_id="app-qual-agy",
            user_profile_id="usr-qual",
            application_id="antigravity",
            installation_state="installed",
            version="2.32.1.0",
        )
    )
    reg.register_account(
        AccountContextRecord(
            account_context_id="acct-qual-agy",
            user_profile_id="usr-qual",
            application_instance_id="app-qual-agy",
            application_id="antigravity",
            provider="google",
            authentication_mode=AuthenticationMode.SUBSCRIPTION,
            subscription_source=SubscriptionSource.USER_DECLARED,
            subscription_tier="pro",
        )
    )
    reg.register_model_identity(
        ModelIdentityRecord(
            application_id="antigravity",
            application_model_id="gemini-4-hydrogen-high",
            provider="google",
            model_family="gemini-4-hydrogen",
            reasoning_effort_variant="HIGH",
        )
    )
    reg.record_entitlement(
        ModelEntitlementObservation(
            observation_id="obs-ent-22e-1",
            account_context_id="acct-qual-agy",
            application_instance_id="app-qual-agy",
            application_id="antigravity",
            model_id="gemini-4-hydrogen-high",
            state=EntitlementState.USER_CONFIRMED_SELECTABLE,
            provenance="USER_DECLARED",
            confidence=ConfidenceLevel.MEDIUM,
            evidence_ref="fixture:next22e",
            observed_at="2026-11-14T13:00:00Z",
        )
    )
    reg.record_capability_evidence(
        ModelCapabilityEvidence(
            evidence_id="cap-22e-1",
            application_id="antigravity",
            application_model_id="gemini-4-hydrogen-high",
            dimension=CapabilityDimension.CODING,
            status=CapabilityState.VERIFIED,
            evidence_source="next22e_fixture",
            confidence=ConfidenceLevel.HIGH,
            evidence_ref="fixture:cap",
            observed_at="2026-11-14T13:00:00Z",
        )
    )
    reg.register_effort_profile(
        ModelEffortProfile(
            application_id="antigravity",
            application_model_id="gemini-4-hydrogen-high",
            account_context_id="acct-qual-agy",
            supported_efforts=(NormalizedEffort.HIGH,),
            default_effort=NormalizedEffort.HIGH,
            provenance="RUNTIME_OBSERVED",
            evidence_ref="fixture:effort",
            observed_at="2026-11-14T13:00:00Z",
        )
    )
    reg.record_quota(
        QuotaObservation(
            observation_id="obs-q-22e-1",
            account_context_id="acct-qual-agy",
            model_id="gemini-4-hydrogen-high",
            usage_category="model",
            quota_state=QuotaState.AVAILABLE,
            remaining_percentage=90.0,
            source="next22e_fixture",
            evidence_ref="fixture:quota",
            observed_at="2026-11-14T13:00:00Z",
        )
    )
    dispatcher = AuditorMCPDispatcher(db_path=tmp_db, app_home=tmp_db.parent)
    return AdaptiveMCPGateway(
        dispatcher=dispatcher,
        routing_bridge=RoutingToolBridge(registry=reg),
    )


def build_caller(kind: str) -> AuthenticatedCallerContext:
    if kind == "unknown":
        return AuthenticatedCallerContext(
            principal_id="qual-unknown",
            application_id="UNKNOWN",
            authentication_method=AuthMethod.UNKNOWN,
            authorization_scopes=frozenset(),
            verified_application_identity=False,
            operating_system_identity={"verified_by_os": False},
            protocol_context=ProtocolContext(transport="stdio"),
        )
    if kind == "auth_unknown_app":
        return AuthenticatedCallerContext(
            principal_id="qual-auth-unknown-app",
            application_id="UNKNOWN",
            authentication_method=AuthMethod.LOCAL_TEST_PRINCIPAL,
            authorization_scopes=frozenset({"core:read", "project:read", "routing:read"}),
            verified_application_identity=False,
            operating_system_identity={"verified_by_os": True},
            workspace_context_id="proj-qual",
            protocol_context=ProtocolContext(transport="stdio"),
        )
    if kind == "verified_readonly":
        return AuthenticatedCallerContext(
            principal_id="qual-readonly",
            application_id="antigravity",
            authentication_method=AuthMethod.LOCAL_TEST_PRINCIPAL,
            authorization_scopes=UNIVERSAL_MINIMUM_READ_SCOPES,
            verified_application_identity=True,
            operating_system_identity={"verified_by_os": True},
            workspace_context_id="proj-qual",
            allowed_user_profile_ids=frozenset({"usr-qual"}),
            allowed_account_context_ids=frozenset({"acct-qual-agy"}),
            protocol_context=ProtocolContext(transport="stdio"),
        )
    if kind == "stale_policy":
        return AuthenticatedCallerContext(
            principal_id="qual-stale",
            application_id="antigravity",
            authentication_method=AuthMethod.LOCAL_TEST_PRINCIPAL,
            authorization_scopes=frozenset({"core:read", "project:read", "evidence:read", "routing:read", "planning:read"}),
            verified_application_identity=True,
            operating_system_identity={"verified_by_os": True},
            policy_generation=0,
            workspace_context_id="proj-qual",
            allowed_user_profile_ids=frozenset({"usr-qual"}),
            allowed_account_context_ids=frozenset({"acct-qual-agy"}),
            protocol_context=ProtocolContext(transport="stdio"),
        )
    return AuthenticatedCallerContext(
        principal_id="qual-full",
        application_id="antigravity",
        authentication_method=AuthMethod.LOCAL_TEST_PRINCIPAL,
        authorization_scopes=frozenset({"core:read", "project:read", "evidence:read", "routing:read", "planning:read"}),
        verified_application_identity=True,
        operating_system_identity={"verified_by_os": True},
        workspace_context_id="proj-qual",
        allowed_user_profile_ids=frozenset({"usr-qual"}),
        allowed_account_context_ids=frozenset({"acct-qual-agy"}),
        protocol_context=ProtocolContext(transport="stdio"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NEXT-22E isolated stdio qualification server.")
    parser.add_argument("--mode", choices=("legacy-adapter", "sdk-bridge"), required=True)
    parser.add_argument("--db-path", required=True)
    parser.add_argument(
        "--caller",
        choices=("verified_full", "verified_readonly", "unknown", "auth_unknown_app", "stale_policy", "revoke_after_list"),
        default="verified_full",
    )
    parser.add_argument("--stray-stdout-noise", default=None)
    parser.add_argument("--delay-before-work", type=float, default=0.0)
    parser.add_argument("--enable-multi-round-trip", action="store_true")
    parser.add_argument("--crash-after-calls", type=int, default=0)
    parser.add_argument("--emit-warning", action="store_true")
    parser.add_argument("--marker-file", default=None)
    args = parser.parse_args(argv)

    # Suppress unintended stdout leakage from Python warnings inside child processes
    if args.emit_warning:
        warnings.warn("NEXT-22E qualification warning (must stay on stderr, never stdout)", UserWarning)

    gw = build_disposable_gateway(Path(args.db_path))

    if args.mode == "legacy-adapter":
        caller = build_caller("unknown" if args.caller == "unknown" else args.caller)
        transport = InMemoryBrokerTransport(gw)
        host = CommonStdioAdapterHost(
            transport=transport,
            caller_context=caller,
            application_profile_id="antigravity",
        )
        return host.serve_streams(sys.stdin.buffer, sys.stdout.buffer)

    # SDK v2 Compatibility Bridge subprocess mode
    if args.caller == "stale_policy":
        gw.authz.min_active_policy_generation = 2
        provider = lambda: build_caller("stale_policy")
    elif args.caller == "revoke_after_list":
        # Starts with routing:read during initial list_tools, then revokes to core:read once listed!
        state = {"revoked": False}
        orig_compute = gw.compute_visible_tools

        def _compute_and_revoke(**kwargs):
            res = orig_compute(**kwargs)
            state["revoked"] = True
            return res

        gw.compute_visible_tools = _compute_and_revoke  # type: ignore[method-assign]
        provider = lambda: build_caller("verified_readonly" if state["revoked"] else "verified_full")
    else:
        provider = lambda: build_caller(args.caller)

    bridge = GatewaySDKv2Bridge(
        gateway=gw,
        caller_context_provider=provider,
        delay_before_privileged_work_seconds=args.delay_before_work,
        stray_stdout_noise=args.stray_stdout_noise,
        enable_read_only_multi_round_trip_probe=args.enable_multi_round_trip,
    )

    if args.marker_file or args.crash_after_calls > 0:
        orig_call = bridge._on_call_tool

        async def _tracked_call(ctx, params):
            res = await orig_call(ctx, params)
            if args.marker_file:
                Path(args.marker_file).write_text(f"executed:{len(bridge.executed_calls)}", encoding="utf-8")
            if args.crash_after_calls > 0 and len(bridge.executed_calls) >= args.crash_after_calls:
                os._exit(2)
            return res

        bridge._on_call_tool = _tracked_call  # type: ignore[method-assign]

    bridge.serve_stdio()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

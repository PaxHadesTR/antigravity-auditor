"""Comprehensive test suite for NEXT-22C Adaptive MCP Gateway & Client-Aware Tool Catalog."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from broker.security import ClientIdentity
from db import connect, initialize
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
    AdapterIdentityProof,
    AuthMethod,
    AuthenticatedCallerContext,
    AuthorizationResolver,
    CATALOG_VERSION,
    CallerIdentityResolver,
    CanonicalCatalogRegistry,
    CanonicalToolManifest,
    CatalogCache,
    CompatibilityState,
    GatewayErrorCode,
    ModernProtocolAdapter,
    PermissionClass,
    ProtocolContext,
    ProtocolEra,
    ResultSizePolicy,
    RiskClass,
    SharedSecretAdapterProofVerifier,
    ToolGroup,
    UntrustedClientHints,
    build_scoped_cache_key,
    classify_protocol_era,
    parse_strict_protocol_date,
)
from mcp_gateway.routing_tools import RoutingToolBridge
from mcp_server import AuditorMCPDispatcher, MCPStdioServer, TOOL_DEFINITIONS


def _os_id(
    *,
    sid: str = "S-1-5-21-1000-2000-3000-1001",
    pid: int = 4242,
    il: str = "MEDIUM",
    low: bool = False,
    verified: bool = True,
) -> ClientIdentity:
    return ClientIdentity(
        pid=pid,
        sid=sid,
        integrity_level=il,
        is_low_integrity=low,
        verified_by_os=verified,
    )


def _setup_disposable_gateway_env(tmp_path: Path) -> tuple[Path, AuditorMCPDispatcher, EntitlementRegistry, SharedSecretAdapterProofVerifier]:
    db_path = tmp_path / "disposable_auditor.db"
    repo_path = tmp_path / "repo"
    (repo_path / "src").mkdir(parents=True, exist_ok=True)
    (repo_path / "src" / "app.py").write_text("def ok():\n    return True\n", encoding="utf-8")

    initialize(db_path)
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id)
               VALUES('proj-alpha', 'Alpha Repo', ?, 'agy-proj-1')""",
            (str(repo_path),),
        )
        conn.execute(
            """INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash)
               VALUES('RUN-GW-1', 'proj-alpha', 'DISPATCHED', 'aaa1111', 'bbb2222')"""
        )
        conn.commit()

    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)

    reg = EntitlementRegistry()
    reg.register_user(UserProfileRecord(user_profile_id="usr-alice"))
    reg.register_user(UserProfileRecord(user_profile_id="usr-bob"))
    reg.set_policy(UserRoutingPolicy(policy_id="pol-alice", user_profile_id="usr-alice", api_billing_allowed=False))
    reg.set_policy(UserRoutingPolicy(policy_id="pol-bob", user_profile_id="usr-bob", api_billing_allowed=False))

    # Alice has TWO separate application accounts: Antigravity (subscription) & Codex (API_KEY)
    reg.register_application(
        ApplicationInstanceRecord(
            application_instance_id="app-alice-agy",
            user_profile_id="usr-alice",
            application_id="antigravity",
            installation_state="installed",
            version="2.31.2.0",
        )
    )
    reg.register_application(
        ApplicationInstanceRecord(
            application_instance_id="app-alice-codex",
            user_profile_id="usr-alice",
            application_id="codex",
            installation_state="installed",
            version="0.169.0",
        )
    )
    reg.register_account(
        AccountContextRecord(
            account_context_id="acct-alice-agy",
            user_profile_id="usr-alice",
            application_instance_id="app-alice-agy",
            application_id="antigravity",
            provider="google",
            authentication_mode=AuthenticationMode.SUBSCRIPTION,
            subscription_source=SubscriptionSource.USER_DECLARED,
            subscription_tier="pro",
        )
    )
    reg.register_account(
        AccountContextRecord(
            account_context_id="acct-alice-codex",
            user_profile_id="usr-alice",
            application_instance_id="app-alice-codex",
            application_id="codex",
            provider="openai",
            authentication_mode=AuthenticationMode.API_KEY,
        )
    )

    for mid, fam, prov, app_id, acct_id in [
        ("gemini-4-hydrogen-high", "gemini-4-hydrogen", "google", "antigravity", "acct-alice-agy"),
        ("gemini-4-argon-high", "gemini-4-argon", "google", "antigravity", "acct-alice-agy"),
        ("gpt-5.6-luna", "gpt-5", "openai", "codex", "acct-alice-codex"),
    ]:
        reg.register_model_identity(
            ModelIdentityRecord(
                application_id=app_id,
                application_model_id=mid,
                provider=prov,
                model_family=fam,
            )
        )
        reg.record_entitlement(
            ModelEntitlementObservation(
                observation_id=f"obs-{acct_id}-{mid}",
                account_context_id=acct_id,
                application_instance_id=f"app-alice-{'agy' if app_id == 'antigravity' else 'codex'}",
                application_id=app_id,
                model_id=mid,
                state=EntitlementState.USER_CONFIRMED_SELECTABLE,
                provenance="USER_DECLARED",
                confidence=ConfidenceLevel.MEDIUM,
                evidence_ref=f"fixture:{acct_id}:{mid}",
                observed_at="2026-11-14T09:00:00Z",
            )
        )
        reg.record_quota(
            QuotaObservation(
                observation_id=f"q-{acct_id}-{mid}",
                account_context_id=acct_id,
                model_id=mid,
                usage_category="model",
                quota_state=QuotaState.AVAILABLE,
                remaining_percentage=90.0,
                source="fixture",
                evidence_ref=f"fixture:quota:{acct_id}:{mid}",
                observed_at="2026-11-14T09:00:00Z",
            )
        )
        reg.register_effort_profile(
            ModelEffortProfile(
                application_id=app_id,
                application_model_id=mid,
                account_context_id=acct_id,
                supported_efforts=(NormalizedEffort.HIGH, NormalizedEffort.MEDIUM),
                default_effort=NormalizedEffort.HIGH,
                provenance="RUNTIME_OBSERVED",
                evidence_ref=f"fixture:effort:{mid}",
                observed_at="2026-11-14T09:00:00Z",
            )
        )
        for dim in (
            CapabilityDimension.REASONING,
            CapabilityDimension.CODING,
            CapabilityDimension.DEBUGGING,
            CapabilityDimension.ADVERSARIAL_VERIFICATION,
        ):
            reg.record_capability_evidence(
                ModelCapabilityEvidence(
                    evidence_id=f"ev-{mid}-{dim.value}",
                    application_id=app_id,
                    application_model_id=mid,
                    dimension=dim,
                    status=CapabilityState.VERIFIED,
                    evidence_source="fixture",
                    confidence=ConfidenceLevel.HIGH,
                    evidence_ref=f"fixture:cap:{mid}:{dim.value}",
                    observed_at="2026-11-14T09:00:00Z",
                )
            )

    # Bob has separate account
    reg.register_application(
        ApplicationInstanceRecord(
            application_instance_id="app-bob-claude",
            user_profile_id="usr-bob",
            application_id="claude_desktop",
            installation_state="installed",
            version="5.11492.2.0",
        )
    )
    reg.register_account(
        AccountContextRecord(
            account_context_id="acct-bob-claude",
            user_profile_id="usr-bob",
            application_instance_id="app-bob-claude",
            application_id="claude_desktop",
            provider="anthropic",
            authentication_mode=AuthenticationMode.SUBSCRIPTION,
        )
    )

    verifier = SharedSecretAdapterProofVerifier()
    verifier.register_adapter_key("adp-agy-1", b"super-secret-adapter-key-agy")
    verifier.register_adapter_key("adp-codex-1", b"super-secret-adapter-key-codex")
    return db_path, dispatcher, reg, verifier


def _make_verified_caller(
    resolver: CallerIdentityResolver,
    verifier: SharedSecretAdapterProofVerifier,
    *,
    sid: str = "S-1-5-21-1000-2000-3000-1001",
    adapter_id: str = "adp-agy-1",
    app_id: str = "antigravity",
    app_inst_id: str = "app-alice-agy",
    user_ids: frozenset[str] = frozenset({"usr-alice"}),
    acct_ids: frozenset[str] = frozenset({"acct-alice-agy"}),
    active_acct: str = "acct-alice-agy",
    scopes: frozenset[str] = frozenset({"core:read", "project:read", "routing:read"}),
    policy_generation: int = 1,
) -> AuthenticatedCallerContext:
    os_id = _os_id(sid=sid)
    tok = verifier.build_expected_token(
        adapter_id=adapter_id,
        application_id=app_id,
        application_instance_id=app_inst_id,
        os_sid=sid,
    )
    proof = AdapterIdentityProof(
        application_id=app_id,
        application_instance_id=app_inst_id,
        adapter_id=adapter_id,
        proof_token=tok,
        expected_os_sid=sid,
    )
    return resolver.resolve_local_windows_caller(
        os_identity=os_id,
        adapter_proof=proof,
        permitted_scopes_for_sid=scopes,
        allowed_user_profile_ids=user_ids,
        allowed_account_context_ids=acct_ids,
        account_context_id=active_acct,
        policy_generation=policy_generation,
    )


# ==============================================================================
# A. Tool Catalog
# ==============================================================================


def test_a01_canonical_catalog_preserves_existing_tools_and_adds_zero_execution_tools() -> None:
    cat = CanonicalCatalogRegistry()
    tools = cat.list_ordered()
    names = [t.tool_name for t in tools]

    existing_names = {t["name"] for t in TOOL_DEFINITIONS}
    assert existing_names.issubset(set(names))
    assert len(tools) == len(existing_names) + 6

    exec_tools = [t.tool_name for t in tools if t.tool_group == ToolGroup.EXECUTION]
    assert set(exec_tools) == {
        "auditor_start_execution",
        "auditor_update_finding_execution",
        "auditor_finalize_execution",
    }
    assert len(cat.manifest_sha256) == 64


def test_a02_duplicate_tool_rejected_and_deterministic_ordering() -> None:
    cat = CanonicalCatalogRegistry()
    dup = CanonicalToolManifest(
        tool_id="tool:dup_status",
        tool_name="auditor_get_status",
        title="Dup",
        description="Duplicate tool name",
        input_schema={"type": "object"},
        output_schema=None,
        tool_group=ToolGroup.CORE_READ,
        permission_class=PermissionClass.PUBLIC_SAFE_READ,
        required_authorization_scopes=("core:read",),
        minimum_client_features=(),
        result_size_policy=ResultSizePolicy(),
        risk_class=RiskClass.LOW,
        implementation_handler="none",
    )
    with pytest.raises(ValueError, match="Duplicate canonical tool registration"):
        cat.register(dup)

    cat2 = CanonicalCatalogRegistry()
    assert [t.tool_name for t in cat.list_ordered()] == [t.tool_name for t in cat2.list_ordered()]
    assert cat.manifest_sha256 == cat2.manifest_sha256


def test_a03_unknown_tool_empty_catalog_and_pagination(tmp_path: Path) -> None:
    _, dispatcher, reg, _ = _setup_disposable_gateway_env(tmp_path)
    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))

    # Default unauthenticated caller gets empty catalog and rejects unknown & real tools
    list_resp = gw.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    assert list_resp is not None
    assert list_resp["result"]["tools"] == []

    unk_resp = gw.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "nonexistent_tool", "arguments": {}}}
    )
    assert unk_resp is not None and unk_resp["result"]["isError"] is True
    assert GatewayErrorCode.TOOL_NOT_FOUND.value in unk_resp["result"]["content"][0]["text"]

    # Deterministic pagination with identical context
    auth_caller = AuthenticatedCallerContext(
        principal_id="usr-alice-p1",
        application_id="antigravity",
        verified_application_identity=True,
        authentication_method=AuthMethod.LOCAL_TEST_PRINCIPAL,
        authorization_scopes=frozenset({"core:read", "project:read", "routing:read"}),
        operating_system_identity={"verified_by_os": True, "integrity_level": "MEDIUM"},
    )
    p1 = gw.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"limit": 3}},
        caller_context=auth_caller,
    )
    assert p1 is not None
    t1 = [t["name"] for t in p1["result"]["tools"]]
    cur = p1["result"].get("nextCursor")
    assert len(t1) == 3 and cur == "3"

    p2 = gw.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {"cursor": cur, "limit": 3}},
        caller_context=auth_caller,
    )
    assert p2 is not None
    t2 = [t["name"] for t in p2["result"]["tools"]]
    assert len(set(t1) & set(t2)) == 0


# ==============================================================================
# B. Authentication & Identity Isolation
# ==============================================================================


def test_b01_spoofed_clientinfo_model_and_env_never_grant_app_or_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    monkeypatch.setenv("MCP_CLIENT_APP", "claude_desktop")
    resolver = CallerIdentityResolver(adapter_verifier=verifier)

    hints = UntrustedClientHints.from_mcp_params(
        {
            "protocolVersion": "2025-11-25",
            "clientInfo": {"name": "claude-desktop", "version": "5.11492.2.0", "model": "claude-opus-5-5-high"},
            "model_id": "gemini-4-hydrogen-high",
        },
        claimed_env_application="claude_desktop",
    )
    assert hints.is_trusted_identity is False
    assert hints.grants_authorization is False

    # OS identity verified, NO adapter proof -> application_id MUST remain UNKNOWN & clamped to core:read
    caller = resolver.resolve_local_windows_caller(
        os_identity=_os_id(),
        adapter_proof=None,
        untrusted_hints=hints,
        permitted_scopes_for_sid=frozenset({"core:read", "project:read", "routing:read", "execution:run"}),
        account_context_id="acct-alice-agy",
    )
    assert caller.application_id == "UNKNOWN"
    assert caller.verified_application_identity is False
    assert caller.account_context_id is None
    assert caller.authorization_scopes == frozenset({"core:read"})

    gw = AdaptiveMCPGateway(
        dispatcher=dispatcher,
        identity_resolver=resolver,
        routing_bridge=RoutingToolBridge(registry=reg),
    )
    listed = gw.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, caller_context=caller)
    assert listed is not None
    assert [t["name"] for t in listed["result"]["tools"]] == ["auditor_gateway_capabilities", "auditor_get_status"]


def test_b02_sid_mismatch_low_il_and_invalid_adapter_rejected(tmp_path: Path) -> None:
    _, _, _, verifier = _setup_disposable_gateway_env(tmp_path)
    resolver = CallerIdentityResolver(adapter_verifier=verifier)

    # SID mismatch -> unauthenticated
    c_sid = resolver.resolve_local_windows_caller(
        os_identity=_os_id(sid="S-1-5-21-REAL-1001"),
        claimed_sid="S-1-5-21-FAKE-9999",
    )
    assert c_sid.is_authenticated is False
    assert "OS_SID_MISMATCH_REJECTED" in c_sid.diagnostic_reasons

    # Low integrity -> unauthenticated
    c_low = resolver.resolve_local_windows_caller(
        os_identity=_os_id(il="LOW", low=True),
        permitted_scopes_for_sid=frozenset({"core:read", "project:read"}),
    )
    assert c_low.is_authenticated is False
    assert "LOW_INTEGRITY_REJECTED" in c_low.diagnostic_reasons

    # Forged adapter token -> UNKNOWN app identity
    bad_proof = AdapterIdentityProof(
        application_id="antigravity",
        application_instance_id="app-alice-agy",
        adapter_id="adp-agy-1",
        proof_token="0" * 64,
    )
    c_bad = resolver.resolve_local_windows_caller(
        os_identity=_os_id(),
        adapter_proof=bad_proof,
        permitted_scopes_for_sid=frozenset({"core:read", "routing:read"}),
    )
    assert c_bad.verified_application_identity is False
    assert c_bad.application_id == "UNKNOWN"


def test_b03_cross_account_cross_user_and_cross_app_data_isolated(tmp_path: Path) -> None:
    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    alice_agy_caller = _make_verified_caller(
        resolver,
        verifier,
        user_ids=frozenset({"usr-alice"}),
        acct_ids=frozenset({"acct-alice-agy"}),
        active_acct="acct-alice-agy",
    )
    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))

    # Cross-user profile attempt rejected
    r_user = gw.call_tool(
        tool_name="auditor_routing_list_accounts",
        arguments={"user_profile_id": "usr-bob"},
        caller=alice_agy_caller,
    )
    assert r_user["isError"] is True
    assert GatewayErrorCode.CROSS_PRINCIPAL_DENIED.value in r_user["content"][0]["text"]

    # Cross-account attempt (Alice's Antigravity token trying Codex account) rejected
    r_acct = gw.call_tool(
        tool_name="auditor_routing_inspect_models",
        arguments={"account_context_id": "acct-alice-codex"},
        caller=alice_agy_caller,
    )
    assert r_acct["isError"] is True
    assert GatewayErrorCode.CROSS_ACCOUNT_DENIED.value in r_acct["content"][0]["text"]

    # routing.plan only evaluates permitted account (acct-alice-agy), never leaks acct-alice-codex!
    r_plan = gw.call_tool(
        tool_name="auditor_routing_plan",
        arguments={
            "user_profile_id": "usr-alice",
            "task_profile": {
                "task_profile_id": "tp-1",
                "task_type": "CRITICAL_AUDIT",
                "risk": "CRITICAL",
                "roles": ["IMPLEMENTATION_WORKER", "INDEPENDENT_VERIFIER"],
                "required_capabilities": {
                    "IMPLEMENTATION_WORKER": ["REASONING", "CODING"],
                    "INDEPENDENT_VERIFIER": ["REASONING", "ADVERSARIAL_VERIFICATION"],
                },
                "required_effort": "HIGH",
            },
        },
        caller=alice_agy_caller,
    )
    assert r_plan["isError"] is False
    plan_txt = r_plan["content"][0]["text"]
    assert "READY_FOR_USER_REVIEW" in plan_txt
    assert "acct-alice-codex" not in plan_txt
    assert "gpt-5.6-luna" not in plan_txt
    assert '"execution_authorized": false' in plan_txt.lower()


def test_b04_remote_http_caller_rejected_and_never_reuses_local_windows_sid(tmp_path: Path) -> None:
    _, dispatcher, reg, _ = _setup_disposable_gateway_env(tmp_path)
    resolver = CallerIdentityResolver()
    remote = resolver.resolve_remote_http_caller(bearer_token="Bearer fake-token", os_identity=_os_id())
    assert remote.is_authenticated is False
    assert "REMOTE_HTTP_DEPLOYMENT_DISABLED" in remote.diagnostic_reasons

    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))
    res = gw.call_tool(tool_name="auditor_get_status", arguments={}, caller=remote)
    assert res["isError"] is True
    assert GatewayErrorCode.UNAUTHORIZED_CALLER.value in res["content"][0]["text"]


# ==============================================================================
# C. Authorization & Cache Separation
# ==============================================================================


def test_c01_hidden_tool_invoked_directly_still_rejected(tmp_path: Path) -> None:
    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    read_caller = _make_verified_caller(
        resolver,
        verifier,
        scopes=frozenset({"core:read", "project:read"}),
    )
    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))

    vis = gw.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, caller_context=read_caller)
    assert vis is not None
    listed_names = {t["name"] for t in vis["result"]["tools"]}
    assert "auditor_start_execution" not in listed_names

    # Direct invocation of hidden execution tool MUST be rejected
    call = gw.call_tool(
        tool_name="auditor_start_execution",
        arguments={"project_key": "proj-alpha", "approval_token": "tok-1234567890"},
        caller=read_caller,
    )
    assert call["isError"] is True
    assert GatewayErrorCode.MISSING_SCOPE.value in call["content"][0]["text"]


def test_c02_revoked_after_cache_and_expired_policy_generation_block_calls(tmp_path: Path) -> None:
    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    revoked_flag = {"revoked": False}

    def hook(caller: AuthenticatedCallerContext, _tool: CanonicalToolManifest) -> tuple[bool, str | None]:
        if revoked_flag["revoked"]:
            return False, "Caller session revoked."
        return True, None

    authz = AuthorizationResolver(min_active_policy_generation=1, revocation_hook=hook)
    gw = AdaptiveMCPGateway(dispatcher=dispatcher, authorization_resolver=authz, routing_bridge=RoutingToolBridge(registry=reg))
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    caller = _make_verified_caller(resolver, verifier, policy_generation=1)

    # Populates cache while active
    l1 = gw.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, caller_context=caller)
    assert l1 is not None and any(t["name"] == "auditor_get_context" for t in l1["result"]["tools"])

    # Revoke caller AFTER caching -> cache still holds old view if not bumped, yet tools/call MUST fail!
    revoked_flag["revoked"] = True
    c1 = gw.call_tool(tool_name="auditor_get_context", arguments={"project_key": "proj-alpha"}, caller=caller)
    assert c1["isError"] is True
    assert GatewayErrorCode.UNAUTHORIZED_CALLER.value in c1["content"][0]["text"]

    # Policy generation bump invalidates cached tool list and blocks stale caller
    revoked_flag["revoked"] = False
    authz.min_active_policy_generation = 2
    l2 = gw.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, caller_context=caller)
    assert l2 is not None and l2["result"]["tools"] == []


def test_c03_api_billing_disabled_and_legacy_governance_preserved(tmp_path: Path) -> None:
    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    codex_caller = _make_verified_caller(
        resolver,
        verifier,
        adapter_id="adp-codex-1",
        app_id="codex",
        app_inst_id="app-alice-codex",
        acct_ids=frozenset({"acct-alice-codex"}),
        active_acct="acct-alice-codex",
    )
    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))

    # Policy has api_billing_allowed=False -> API_KEY codex model blocked cleanly with execution_authorized=False
    plan_res = gw.call_tool(
        tool_name="auditor_routing_plan",
        arguments={
            "user_profile_id": "usr-alice",
            "task_profile": {
                "task_profile_id": "tp-codex",
                "risk": "LOW",
                "roles": ["IMPLEMENTATION_WORKER"],
                "required_capabilities": {"IMPLEMENTATION_WORKER": ["CODING"]},
                "required_effort": "HIGH",
            },
        },
        caller=codex_caller,
    )
    assert plan_res["isError"] is False
    txt = plan_res["content"][0]["text"]
    assert "BLOCKED_" in txt
    assert "API_BILLING_DISABLED" in txt
    assert '"execution_authorized": false' in txt.lower()

    # Legacy governance preserved: auditor_authorize_execution cannot succeed without verified/saved APPLY
    gov_caller = _make_verified_caller(
        resolver,
        verifier,
        scopes=frozenset({"core:read", "project:read", "governance:authorize"}),
    )
    auth_res = gw.call_tool(
        tool_name="auditor_authorize_execution",
        arguments={"project_key": "proj-alpha", "run_id": "RUN-GW-1", "confirmation": "YES"},
        caller=gov_caller,
    )
    assert auth_res["isError"] is True


# ==============================================================================
# D. Protocol Compatibility
# ==============================================================================


def test_d01_legacy_and_modern_eras_supported_without_mixing(tmp_path: Path) -> None:
    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    caller = _make_verified_caller(resolver, verifier)
    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))

    # Legacy 2025-11-25 handshake
    init_resp = gw.handle_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {"listChanged": True}},
                "clientInfo": {"name": "synthetic-legacy", "version": "1.0"},
            },
        },
        caller_context=caller,
    )
    assert init_resp is not None
    assert init_resp["result"]["protocolVersion"] == "2025-11-25"
    assert init_resp["result"]["capabilities"]["tools"]["listChanged"] is True

    # Modern method on Legacy session -> PROTOCOL_ERA_MISMATCH error
    mixed = gw.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 2, "method": "server/discover", "params": {"protocolVersion": "2026-07-28"}},
        caller_context=caller,
    )
    assert mixed is not None and "error" in mixed
    assert "PROTOCOL_ERA_MISMATCH" in mixed["error"]["message"]

    # Separate principal on Modern 2026-07-28 -> server/discover + subscriptions/listen contract
    caller_mod = _make_verified_caller(resolver, verifier, sid="S-1-5-21-1000-2000-3000-2002")
    disc = gw.handle_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "server/discover",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {"subscriptions": {"listen": True}, "structuredOutput": True},
            },
        },
        caller_context=caller_mod,
    )
    assert disc is not None and "result" in disc
    assert disc["result"]["runtimeWireVerified"] is False
    assert disc["result"]["runtimeSupportStatus"] == "ADAPTER_CONTRACT_ONLY_NOT_VERIFIED"

    sub = gw.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 4, "method": "subscriptions/listen", "params": {"protocolVersion": "2026-07-28"}},
        caller_context=caller_mod,
    )
    assert sub is not None and sub["result"]["accepted"] is True

    # Legacy initialize on Modern session rejected
    mix2 = gw.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 5, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
        caller_context=caller_mod,
    )
    assert mix2 is not None and "error" in mix2


def test_d02_unsupported_protocol_no_unsolicited_notifications_and_unknown_stays_unknown(tmp_path: Path) -> None:
    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    caller = _make_verified_caller(resolver, verifier)
    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))

    # Unsupported version rejected
    bad_init = gw.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}},
        caller_context=caller,
    )
    assert bad_init is not None and "error" in bad_init

    # Initialize without listChanged -> no unsolicited notification emitted
    ok_init = gw.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}}},
        caller_context=caller,
    )
    assert ok_init is not None
    assert ok_init["result"]["capabilities"]["tools"]["listChanged"] is False
    prof = gw.resolve_profile_for_request(caller=caller)
    assert prof.notification_state == CompatibilityState.UNKNOWN  # UNKNOWN not turned into NOT_SUPPORTED
    assert gw.notifications.emit_tools_changed(principal_id=caller.principal_id, profile=prof, catalog_version=CATALOG_VERSION, reason="test") is None


# ==============================================================================
# E. Dynamic Tool List & Cache Isolation
# ==============================================================================


def test_e01_cache_key_isolation_no_cross_user_contamination(tmp_path: Path) -> None:
    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    alice_c = _make_verified_caller(resolver, verifier, sid="S-1-5-21-ALICE", scopes=frozenset({"core:read", "project:read", "routing:read"}))
    bob_c = _make_verified_caller(resolver, verifier, sid="S-1-5-21-BOB", scopes=frozenset({"core:read"}))
    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))

    p_alice = gw.resolve_profile_for_request(caller=alice_c)
    p_bob = gw.resolve_profile_for_request(caller=bob_c)
    key_alice = build_scoped_cache_key(caller=alice_c, profile=p_alice, catalog_version=CATALOG_VERSION, manifest_sha256=gw.catalog.manifest_sha256)
    key_bob = build_scoped_cache_key(caller=bob_c, profile=p_bob, catalog_version=CATALOG_VERSION, manifest_sha256=gw.catalog.manifest_sha256)
    assert key_alice != key_bob

    res_a = gw.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, caller_context=alice_c)
    res_b = gw.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, caller_context=bob_c)
    assert res_a is not None and res_b is not None
    assert len(res_a["result"]["tools"]) > len(res_b["result"]["tools"])
    assert {t["name"] for t in res_b["result"]["tools"]} == {"auditor_gateway_capabilities", "auditor_get_status"}


# ==============================================================================
# F. Output Adaptation, Redaction & Legacy MCPStdioServer Bridge
# ==============================================================================


def test_f01_structured_vs_text_fallback_bounded_redacted_and_malformed(tmp_path: Path) -> None:
    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    caller = _make_verified_caller(resolver, verifier)
    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))

    # Unknown structured output (2024-11-05, no structured capability) -> concise text fallback, NO structuredContent
    prof_text = gw.profile_resolver.resolve(
        caller=caller,
        protocol_version="2024-11-05",
        output_constraints={"max_items": 2, "max_text_chars": 256},
    )
    res_text = gw.call_tool(tool_name="auditor_get_status", arguments={}, caller=caller, profile=prof_text)
    assert res_text["isError"] is False
    assert "structuredContent" not in res_text

    # Modern/2025-11-25 -> structuredContent included & secrets scrubbed
    prof_struct = gw.profile_resolver.resolve(caller=caller, protocol_version="2025-11-25")
    tool = gw.catalog.get("auditor_gateway_capabilities")
    assert tool is not None
    formatted = gw.output_adapter.format_result(
        tool=tool,
        raw_result={
            "gateway_version": "1",
            "catalog_version": "1",
            "protocol_era": "LEGACY",
            "protocol_version": "2025-11-25",
            "application_id": "antigravity",
            "verified_application_identity": True,
            "compatibility_state": {},
            "authorization_scopes": ["core:read"],
            "diagnostic_reasons": ["Bearer sk-secret-token-1234567890", "user@example.com"],
            "execution_authorized": False,
        },
        profile=prof_struct,
    )
    assert "structuredContent" in formatted
    dumped = json.dumps(formatted)
    assert "sk-secret-token-1234567890" not in dumped
    assert "user@example.com" not in dumped

    # Malformed non-dict output fails cleanly
    with pytest.raises(ValueError, match="Malformed handler output"):
        gw.output_adapter.format_result(tool=tool, raw_result=["not", "a", "dict"], profile=prof_struct)


def test_f02_mcp_stdio_server_accepts_gateway_and_preserves_legacy_mode(tmp_path: Path) -> None:
    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))
    stdio = MCPStdioServer(dispatcher, gateway=gw)
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    caller = _make_verified_caller(resolver, verifier)

    resp = stdio.handle_jsonrpc_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "auditor_gateway_capabilities", "arguments": {}}},
        caller_context=caller,
    )
    assert resp is not None
    assert resp["result"]["isError"] is False
    data = json.loads(resp["result"]["content"][0]["text"])
    assert data["application_id"] == "antigravity"
    assert data["verified_application_identity"] is True
    assert data["execution_authorized"] is False


def test_f03_routing_inspect_explain_next22a_history_and_explicit_truncation(tmp_path: Path) -> None:
    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    hist_discovery = {
        "generated_at": "2026-11-13T13:07:00Z",
        "applications": {
            "antigravity": {
                "installation_state": "installed",
                "version": "2.31.2.0",
                "observed_at": "2026-11-13T13:07:00Z",
            }
        },
    }
    gw = AdaptiveMCPGateway(
        dispatcher=dispatcher,
        routing_bridge=RoutingToolBridge(registry=reg),
        discovery_report=hist_discovery,
    )
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    caller = _make_verified_caller(resolver, verifier)

    prof = gw.profile_resolver.resolve(
        caller=caller,
        protocol_version="2025-11-25",
        discovery_report=hist_discovery,
    )
    assert prof.application_version == "2.31.2.0"
    assert prof.observation_timestamp == "2026-11-13T13:07:00Z"
    assert prof.live_verified is False

    # Inspect profile & explicit truncation test via max_items=1
    insp = gw.call_tool(
        tool_name="auditor_routing_inspect_profile",
        arguments={"user_profile_id": "usr-alice"},
        caller=caller,
    )
    assert insp["isError"] is False
    insp_data = json.loads(insp["content"][0]["text"])
    assert insp_data["account_count"] == 1  # only acct-alice-agy visible, never acct-alice-codex!

    # Bounded output triggers explicit _gatewayMeta.truncated
    tool = gw.catalog.get("auditor_routing_inspect_models")
    assert tool is not None
    small_prof = gw.profile_resolver.resolve(
        caller=caller,
        protocol_version="2025-11-25",
        output_constraints={"max_items": 1, "max_text_chars": 4096},
    )
    trunc_res = gw.output_adapter.format_result(
        tool=tool,
        raw_result={
            "read_only_planning": True,
            "execution_authorized": False,
            "account": {"account_context_id": "acct-alice-agy"},
            "model_count": 2,
            "models": [{"model_id": "m1"}, {"model_id": "m2"}],
        },
        profile=small_prof,
    )
    assert trunc_res.get("_gatewayMeta", {}).get("truncated") is True
    assert trunc_res["structuredContent"]["execution_authorized"] is False


# ==============================================================================
# G. Carry-Forward Hardening from NEXT-22C Independent Argon Review (Part 2)
# ==============================================================================


def test_g01_empty_user_profile_allowlist_and_cross_account_explain_fail_closed(tmp_path: Path) -> None:
    db_path, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    from entitlement_router.router import CapabilityModelRouter

    router = CapabilityModelRouter(reg)
    dec = router.plan(
        user_profile_id="usr-alice",
        task_profile={
            "task_profile_id": "tp-g01",
            "risk": "HIGH",
            "roles": ["IMPLEMENTATION_WORKER"],
            "required_capabilities": {"IMPLEMENTATION_WORKER": ["REASONING", "CODING"]},
            "required_efforts": {"IMPLEMENTATION_WORKER": "HIGH"},
        },
    )
    with connect(db_path) as conn:
        reg.persist_to_db(conn)
        conn.commit()

    # Construct caller bypassing CallerIdentityResolver with verified app + routing:read,
    # BUT empty allowed_user_profile_ids=frozenset().
    unbound_caller = AuthenticatedCallerContext(
        principal_id="win-sid:S-1-5-21-1000-2000-3000-1001",
        application_id="antigravity",
        verified_application_identity=True,
        authentication_method=AuthMethod.LOCAL_TEST_PRINCIPAL,
        authorization_scopes=frozenset({"core:read", "routing:read"}),
        allowed_user_profile_ids=frozenset(),
        allowed_account_context_ids=frozenset({"acct-alice-agy"}),
        account_context_id="acct-alice-agy",
        operating_system_identity={"verified_by_os": True, "integrity_level": "MEDIUM"},
    )

    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))
    # 1. Gateway-mediated calls must fail closed on BOTH routing.inspect_models & routing.explain_decision
    gw_models = gw.call_tool(
        tool_name="auditor_routing_inspect_models",
        arguments={"account_context_id": "acct-alice-agy"},
        caller=unbound_caller,
    )
    assert gw_models["isError"] is True
    assert GatewayErrorCode.CROSS_PRINCIPAL_DENIED.value in gw_models["content"][0]["text"]

    gw_explain = gw.call_tool(
        tool_name="auditor_routing_explain_decision",
        arguments={"decision_id": dec.decision_id},
        caller=unbound_caller,
    )
    assert gw_explain["isError"] is True
    assert GatewayErrorCode.CROSS_PRINCIPAL_DENIED.value in gw_explain["content"][0]["text"]

    # 2. Direct RoutingToolBridge invocation bypassing Gateway MUST ALSO fail closed (in-memory AND SQLite)
    mem_bridge = RoutingToolBridge(registry=reg)
    sql_bridge = RoutingToolBridge(routing_db_path=db_path)
    for br in (mem_bridge, sql_bridge):
        with pytest.raises(PermissionError, match="allowlist"):
            br.handle_tool("routing.inspect_models", {"account_context_id": "acct-alice-agy"}, unbound_caller)
        with pytest.raises(PermissionError, match="allowlist"):
            br.handle_tool("routing.explain_decision", {"decision_id": dec.decision_id}, unbound_caller)

    # 3. Same-user cross-account isolation in routing.explain_decision:
    # Alice's Antigravity decision cannot be explained by a caller bound ONLY to Alice's Codex account
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    codex_only_caller = _make_verified_caller(
        resolver,
        verifier,
        adapter_id="adp-codex-1",
        app_id="codex",
        app_inst_id="app-alice-codex",
        user_ids=frozenset({"usr-alice"}),
        acct_ids=frozenset({"acct-alice-codex"}),
        active_acct="acct-alice-codex",
    )
    if any(r.account_context_id == "acct-alice-agy" for r in dec.roles.values()):
        with pytest.raises(PermissionError, match="authorized scope"):
            mem_bridge.handle_tool("routing.explain_decision", {"decision_id": dec.decision_id}, codex_only_caller)

    # 4. Legitimate caller bound to usr-alice + acct-alice-agy succeeds cleanly with execution_authorized=False
    agy_caller = _make_verified_caller(
        resolver,
        verifier,
        user_ids=frozenset({"usr-alice"}),
        acct_ids=frozenset({"acct-alice-agy"}),
        active_acct="acct-alice-agy",
    )
    ok_models = gw.call_tool(
        tool_name="auditor_routing_inspect_models",
        arguments={"account_context_id": "acct-alice-agy"},
        caller=agy_caller,
    )
    assert ok_models["isError"] is False
    ok_explain = gw.call_tool(
        tool_name="auditor_routing_explain_decision",
        arguments={"decision_id": dec.decision_id},
        caller=agy_caller,
    )
    assert ok_explain["isError"] is False
    explain_data = json.loads(ok_explain["content"][0]["text"])
    assert explain_data["execution_authorized"] is False
    assert "acct-alice-codex" not in json.dumps(explain_data)


def test_g02_strict_protocol_date_validation_rejects_malformed_and_impossible_dates(tmp_path: Path) -> None:
    assert classify_protocol_era("2026-07-28") == ProtocolEra.MODERN
    assert classify_protocol_era("2025-11-25") == ProtocolEra.LEGACY
    assert classify_protocol_era("") == ProtocolEra.UNKNOWN
    assert classify_protocol_era(None) == ProtocolEra.UNKNOWN

    for invalid_ver in ("2026-02-30", "2026-13-01", "2026-7-28", "2026-07-28-extra", "invalid-version"):
        assert parse_strict_protocol_date(invalid_ver) is None
        assert classify_protocol_era(invalid_ver) == ProtocolEra.UNSUPPORTED

    modern = ModernProtocolAdapter()
    ok = modern.validate_request_version({"protocolVersion": "2026-07-28"})
    assert ok.accepted is True and ok.era == ProtocolEra.MODERN and ok.runtime_wire_verified is False

    for bad in ("2025-11-25", "2026-02-30", "2026-13-01", "2026-7-28", "2026-07-28-extra", "", None, "invalid-version"):
        res = modern.validate_request_version({"protocolVersion": bad} if bad is not None else {})
        assert res.accepted is False
        assert res.era == ProtocolEra.UNSUPPORTED
        assert res.runtime_wire_verified is False

    _, dispatcher, reg, verifier = _setup_disposable_gateway_env(tmp_path)
    resolver = CallerIdentityResolver(adapter_verifier=verifier)
    caller = _make_verified_caller(resolver, verifier)
    gw = AdaptiveMCPGateway(dispatcher=dispatcher, routing_bridge=RoutingToolBridge(registry=reg))
    for bad in ("2026-02-30", "2026-13-01", "2026-7-28", "2026-07-28-extra"):
        resp = gw.handle_jsonrpc_message(
            {"jsonrpc": "2.0", "id": 99, "method": "server/discover", "params": {"protocolVersion": bad}},
            caller_context=caller,
        )
        assert resp is not None and "error" in resp


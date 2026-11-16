"""Comprehensive Test Suite for NEXT-22B User-Aware Entitlement Registry & Capability-Based Model Router."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from db import check_database_integrity, connect, initialize
from entitlement_router import (
    AccountContextRecord,
    AccountScope,
    ApplicationInstanceRecord,
    AuthenticationMode,
    CandidateEligibility,
    CapabilityDimension,
    CapabilityModelRouter,
    CapabilityState,
    ConfidenceLevel,
    CostPolicy,
    EntitlementRegistry,
    EntitlementState,
    ModelCapabilityEvidence,
    ModelEffortProfile,
    ModelEntitlementObservation,
    ModelIdentityRecord,
    NormalizedEffort,
    QuotaObservation,
    QuotaState,
    RoutePlanStatus,
    RouterTaskRisk,
    SecretOrPiiIntakeError,
    SubscriptionSource,
    TaskProfile,
    TaskRole,
    UserProfileRecord,
    UserRoutingPolicy,
    VerifierIndependenceLevel,
    import_runtime_discovery_report,
    load_discovery_report_file,
    load_manual_profile_dict,
    validate_opaque_id,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = REPO_ROOT / "core" / "cli.py"


def _seed_identity_and_caps(
    reg: EntitlementRegistry,
    *,
    app_id: str,
    model_id: str,
    provider: str,
    family: str,
    caps: dict[CapabilityDimension, CapabilityState],
    efforts: tuple[NormalizedEffort, ...],
    default_effort: NormalizedEffort | None = None,
    managed_by_orchestrator: bool = False,
    version: str | None = None,
) -> None:
    reg.register_model_identity(
        ModelIdentityRecord(
            application_id=app_id,
            application_model_id=model_id,
            provider=provider,
            model_family=family,
            model_version=version,
            is_orchestrator_wrapper=managed_by_orchestrator,
        )
    )
    for idx, (dim, status) in enumerate(caps.items(), start=1):
        reg.record_capability_evidence(
            ModelCapabilityEvidence(
                evidence_id=f"cev-{app_id}-{model_id}-{dim.value}-{idx}",
                application_id=app_id,
                application_model_id=model_id,
                dimension=dim,
                status=status,
                evidence_source="synthetic_test_fixture",
                confidence=ConfidenceLevel.HIGH if status == CapabilityState.VERIFIED else ConfidenceLevel.MEDIUM,
                observed_at="2026-11-13T12:00:00Z",
                model_version=version,
                evidence_ref=f"fixture:{app_id}:{model_id}",
            )
        )
    reg.register_effort_profile(
        ModelEffortProfile(
            application_id=app_id,
            application_model_id=model_id,
            supported_efforts=efforts,
            raw_supported_efforts=tuple(e.value.lower() for e in efforts),
            default_effort=default_effort or (efforts[0] if efforts else NormalizedEffort.UNKNOWN),
            raw_default_effort=(default_effort or (efforts[0] if efforts else NormalizedEffort.UNKNOWN)).value.lower(),
            independently_configurable=len(efforts) > 1 and not managed_by_orchestrator,
            managed_by_orchestrator=managed_by_orchestrator,
            provenance="SYNTHETIC_FIXTURE",
            observed_at="2026-11-13T12:00:00Z",
            evidence_ref=f"fixture:effort:{app_id}:{model_id}",
        )
    )


def _add_account_model(
    reg: EntitlementRegistry,
    *,
    user_id: str,
    app_inst_id: str,
    app_id: str,
    acct_id: str,
    provider: str,
    auth_mode: AuthenticationMode,
    model_id: str,
    ent_state: EntitlementState,
    quota_state: QuotaState = QuotaState.AVAILABLE,
    subscription_tier: str | None = None,
    sub_source: SubscriptionSource = SubscriptionSource.UNKNOWN,
    observed_at: str = "2026-11-13T12:00:00Z",
    ent_expires_at: str | None = None,
    quota_expires_at: str | None = None,
    ws_allowed: tuple[str, ...] = (),
    ws_blocked: tuple[str, ...] = (),
) -> None:
    if user_id not in reg.users:
        reg.register_user(UserProfileRecord(user_profile_id=user_id))
    if app_inst_id not in reg.applications:
        reg.register_application(
            ApplicationInstanceRecord(
                application_instance_id=app_inst_id,
                user_profile_id=user_id,
                application_id=app_id,
                installation_state="installed",
                packaging_mode="conventional",
                observed_at=observed_at,
            )
        )
    if acct_id not in reg.accounts:
        reg.register_account(
            AccountContextRecord(
                account_context_id=acct_id,
                user_profile_id=user_id,
                application_instance_id=app_inst_id,
                application_id=app_id,
                provider=provider,
                authentication_mode=auth_mode,
                account_scope=AccountScope.USER_ACCOUNT,
                subscription_tier=subscription_tier,
                subscription_source=sub_source,
                entitlement_state=ent_state,
                workspace_allowed_models=ws_allowed,
                workspace_blocked_models=ws_blocked,
                observed_at=observed_at,
            )
        )
    obs_idx = len(reg.entitlement_history) + 1
    reg.record_entitlement(
        ModelEntitlementObservation(
            observation_id=f"obs-ent-{obs_idx:04d}",
            account_context_id=acct_id,
            application_instance_id=app_inst_id,
            application_id=app_id,
            model_id=model_id,
            state=ent_state,
            provenance=ent_state.value,
            confidence=ConfidenceLevel.HIGH,
            observed_at=observed_at,
            expires_at=ent_expires_at,
            evidence_ref=f"fixture:ent:{acct_id}:{model_id}:{obs_idx}",
        )
    )
    q_idx = len(reg.quota_history) + 1
    reg.record_quota(
        QuotaObservation(
            observation_id=f"obs-q-{q_idx:04d}",
            account_context_id=acct_id,
            model_id=model_id,
            usage_category="requests",
            quota_state=quota_state,
            observed_at=observed_at,
            expires_at=quota_expires_at,
            source="synthetic_fixture",
            evidence_ref=f"fixture:quota:{acct_id}:{model_id}:{q_idx}",
        )
    )


# ==============================================================================
# A. Account and Entitlement Tests
# ==============================================================================


def test_a01_multiple_accounts_per_app_and_scope_isolation() -> None:
    reg = EntitlementRegistry()
    _add_account_model(
        reg,
        user_id="usr-a1",
        app_inst_id="app-a1-codex",
        app_id="codex",
        acct_id="acct-codex-sub",
        provider="openai",
        auth_mode=AuthenticationMode.OAUTH_SUBSCRIPTION,
        model_id="gpt-5.6-luna",
        ent_state=EntitlementState.ACCOUNT_ENUMERATED,
        subscription_tier="pro",
        sub_source=SubscriptionSource.OFFICIAL_READ_ONLY_INTERFACE,
    )
    _add_account_model(
        reg,
        user_id="usr-a1",
        app_inst_id="app-a1-codex",
        app_id="codex",
        acct_id="acct-codex-api",
        provider="openai",
        auth_mode=AuthenticationMode.API_KEY,
        model_id="gpt-6.1-terra",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
    )

    assert len(reg.get_user_accounts("usr-a1")) == 2
    assert reg.get_effective_entitlement("acct-codex-sub", "gpt-6.1-terra").state == EntitlementState.UNKNOWN
    assert reg.get_effective_entitlement("acct-codex-api", "gpt-5.6-luna").state == EntitlementState.UNKNOWN
    assert reg.get_effective_entitlement("acct-codex-sub", "gpt-5.6-luna").state == EntitlementState.ACCOUNT_ENUMERATED


def test_a02_tier_metadata_never_grants_model_entitlement() -> None:
    reg = EntitlementRegistry()
    _add_account_model(
        reg,
        user_id="usr-tier",
        app_inst_id="app-tier-agy",
        app_id="antigravity",
        acct_id="acct-tier-ultra",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-argon-high",
        ent_state=EntitlementState.BUNDLED_CATALOG,
        subscription_tier="ultra",
        sub_source=SubscriptionSource.USER_DECLARED,
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-4-argon-high",
        provider="google",
        family="gemini-4-argon",
        caps={
            CapabilityDimension.CODING: CapabilityState.VERIFIED,
            CapabilityDimension.DEBUGGING: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.HIGH,),
    )
    plan = CapabilityModelRouter(reg).plan(
        user_profile_id="usr-tier",
        task_profile={
            "task_profile_id": "t-tier",
            "risk": "MEDIUM",
            "roles": ["IMPLEMENTATION_WORKER"],
        },
    )
    assert plan.status == RoutePlanStatus.BLOCKED_ENTITLEMENT
    assert plan.roles["implementation_worker"].model_id is None


def test_a03_historical_entitlement_preserved_and_stale_expires() -> None:
    reg = EntitlementRegistry()
    _add_account_model(
        reg,
        user_id="usr-hist",
        app_inst_id="app-hist-agy",
        app_id="antigravity",
        acct_id="acct-hist",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-hydrogen-high",
        ent_state=EntitlementState.RUNTIME_OBSERVED,
        observed_at="2026-11-10T10:00:00Z",
    )
    _add_account_model(
        reg,
        user_id="usr-hist",
        app_inst_id="app-hist-agy",
        app_id="antigravity",
        acct_id="acct-hist",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-hydrogen-high",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        observed_at="2026-11-12T10:00:00Z",
        ent_expires_at="2026-11-13T00:00:00Z",
    )
    history = reg.get_entitlement_history("acct-hist", "gemini-4-hydrogen-high")
    assert len(history) == 2
    assert history[0].state == EntitlementState.RUNTIME_OBSERVED
    assert history[1].state == EntitlementState.SELECTABLE_VERIFIED

    eff = reg.get_effective_entitlement("acct-hist", "gemini-4-hydrogen-high")
    assert eff.is_stale is True
    assert eff.state == EntitlementState.UNKNOWN


def test_a04_user_declared_vs_verified_and_configured_vs_selectable() -> None:
    reg = EntitlementRegistry()
    res = load_manual_profile_dict(
        reg,
        {
            "schema_version": "1.0.0",
            "user_profile_id": "usr-manual",
            "accounts": [
                {
                    "account_context_id": "acct-man-agy",
                    "application": "antigravity",
                    "provider": "google",
                    "authentication_mode": "SUBSCRIPTION",
                    "subscription_tier": "pro",
                    "known_available_models": ["gemini-4-hydrogen-high"],
                }
            ],
        },
    )
    assert res["loaded_models"] == 1
    eff = reg.get_effective_entitlement("acct-man-agy", "gemini-4-hydrogen-high")
    assert eff.state == EntitlementState.USER_DECLARED
    assert reg.accounts["acct-man-agy"].subscription_source == SubscriptionSource.USER_DECLARED


def test_a05_next22a_external_evidence_import_preserves_provenance() -> None:
    # Opt-in: a real runtime-discovery report contains machine-specific data, so none is committed.
    # Point AUDITOR_NEXT22A_EVIDENCE at a `cli.py runtime discover` JSON report to run this test.
    ev_env = os.environ.get("AUDITOR_NEXT22A_EVIDENCE")
    ev_file = Path(ev_env) if ev_env else None
    if ev_file is None or not ev_file.is_file():
        pytest.skip("Set AUDITOR_NEXT22A_EVIDENCE to a runtime-discovery report to run this test")
    report = load_discovery_report_file(ev_file)
    reg = EntitlementRegistry()
    summary = import_runtime_discovery_report(reg, report, user_profile_id="usr-next22a")

    assert summary["imported_applications"] == 4
    assert summary["imported_models"] == 30  # 18 agy + 12 codex

    # Codex 12 models remain BUNDLED_CATALOG
    codex_acct = "acct-usr-next22a-codex-discovered"
    codex_models = reg.list_models_for_account(codex_acct)
    assert len(codex_models) == 12
    for mid in codex_models:
        assert reg.get_effective_entitlement(codex_acct, mid).state == EntitlementState.BUNDLED_CATALOG

    # Antigravity 18 models remain RUNTIME_OBSERVED (not SELECTABLE_VERIFIED)
    agy_acct = "acct-usr-next22a-antigravity-discovered"
    agy_models = reg.list_models_for_account(agy_acct)
    assert len(agy_models) == 18
    for mid in agy_models:
        assert reg.get_effective_entitlement(agy_acct, mid).state == EntitlementState.RUNTIME_OBSERVED

    # Orchestrator effort is FIXED_INTERNAL, never assumed HIGH
    orch_eff = reg.get_effort_profile("antigravity", "gemini-pro-orchestrator-g1-pro")
    assert orch_eff is not None
    assert orch_eff.managed_by_orchestrator is True
    assert orch_eff.supported_efforts == (NormalizedEffort.FIXED_INTERNAL,)

    # Claude Code not installed -> zero account contexts or entitlements
    assert "acct-usr-next22a-claude-code-discovered" not in reg.accounts
    assert reg.applications["app-usr-next22a-claude-code"].installation_state == "not_installed"


# ==============================================================================
# B. Model Capability & Effort Tests
# ==============================================================================


def test_b01_conflicting_and_stale_capability_evidence_fails_closed() -> None:
    reg = EntitlementRegistry()
    reg.record_capability_evidence(
        ModelCapabilityEvidence(
            evidence_id="ev-c1",
            application_id="antigravity",
            application_model_id="test-model",
            dimension=CapabilityDimension.CODING,
            status=CapabilityState.DOCUMENTED,
            evidence_source="docs",
            confidence=ConfidenceLevel.MEDIUM,
            observed_at="2026-11-12T10:00:00Z",
        )
    )
    reg.record_capability_evidence(
        ModelCapabilityEvidence(
            evidence_id="ev-c2",
            application_id="antigravity",
            application_model_id="test-model",
            dimension=CapabilityDimension.CODING,
            status=CapabilityState.NOT_SUPPORTED,
            evidence_source="runtime_test",
            confidence=ConfidenceLevel.HIGH,
            observed_at="2026-11-12T11:00:00Z",
        )
    )
    eff = reg.get_effective_capability("antigravity", "test-model", CapabilityDimension.CODING)
    assert eff.conflict_detected is True
    assert eff.status == CapabilityState.UNKNOWN

    # Stale capability evidence -> UNKNOWN & stale
    reg.record_capability_evidence(
        ModelCapabilityEvidence(
            evidence_id="ev-stale",
            application_id="antigravity",
            application_model_id="stale-model",
            dimension=CapabilityDimension.REASONING,
            status=CapabilityState.VERIFIED,
            evidence_source="bench",
            confidence=ConfidenceLevel.HIGH,
            observed_at="2026-11-01T10:00:00Z",
            expires_at="2026-11-02T10:00:00Z",
        )
    )
    eff_stale = reg.get_effective_capability("antigravity", "stale-model", CapabilityDimension.REASONING)
    assert eff_stale.is_stale is True
    assert eff_stale.status == CapabilityState.UNKNOWN


def test_b02_model_version_change_and_unsupported_effort_rejected() -> None:
    reg = EntitlementRegistry()
    # Older version lacked LONG_CONTEXT; newer version has VERIFIED
    reg.record_capability_evidence(
        ModelCapabilityEvidence(
            evidence_id="ev-v1",
            application_id="codex",
            application_model_id="gpt-test",
            dimension=CapabilityDimension.LONG_CONTEXT,
            status=CapabilityState.NOT_SUPPORTED,
            evidence_source="v1_spec",
            confidence=ConfidenceLevel.HIGH,
            observed_at="2026-11-01T00:00:00Z",
            model_version="v1",
        )
    )
    reg.record_capability_evidence(
        ModelCapabilityEvidence(
            evidence_id="ev-v2",
            application_id="codex",
            application_model_id="gpt-test",
            dimension=CapabilityDimension.LONG_CONTEXT,
            status=CapabilityState.VERIFIED,
            evidence_source="v2_spec",
            confidence=ConfidenceLevel.HIGH,
            observed_at="2026-11-10T00:00:00Z",
            model_version="v2",
        )
    )
    eff = reg.get_effective_capability("codex", "gpt-test", CapabilityDimension.LONG_CONTEXT)
    assert eff.status == CapabilityState.VERIFIED
    assert eff.conflict_detected is False

    # High model does NOT imply XHIGH effort
    _add_account_model(
        reg,
        user_id="usr-eff",
        app_inst_id="app-eff",
        app_id="antigravity",
        acct_id="acct-eff",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-argon-high",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-4-argon-high",
        provider="google",
        family="gemini-4-argon",
        caps={CapabilityDimension.REASONING: CapabilityState.VERIFIED, CapabilityDimension.ARCHITECTURE: CapabilityState.VERIFIED},
        efforts=(NormalizedEffort.HIGH,),
    )
    plan = CapabilityModelRouter(reg).plan(
        user_profile_id="usr-eff",
        task_profile={
            "task_profile_id": "t-xhigh",
            "risk": "HIGH",
            "roles": ["ARCHITECT"],
            "required_efforts": {"ARCHITECT": "XHIGH"},
        },
    )
    assert plan.status == RoutePlanStatus.BLOCKED_CAPABILITY
    assert any("EFFORT_UNSUPPORTED" in e.reason_codes for e in plan.excluded_candidates)


# ==============================================================================
# C. Router & Verifier Independence Tests
# ==============================================================================


def test_c01_verifier_independence_same_family_and_unknown_family_blocked() -> None:
    reg = EntitlementRegistry()
    # Two models in the SAME family (gemini-4-argon-high & gemini-4-argon-medium) + one unknown family model
    for mid, eff in [("gemini-4-argon-high", NormalizedEffort.HIGH), ("gemini-4-argon-medium", NormalizedEffort.MEDIUM)]:
        _add_account_model(
            reg,
            user_id="usr-ind",
            app_inst_id="app-ind-agy",
            app_id="antigravity",
            acct_id="acct-ind-agy",
            provider="google",
            auth_mode=AuthenticationMode.SUBSCRIPTION,
            model_id=mid,
            ent_state=EntitlementState.SELECTABLE_VERIFIED,
        )
        _seed_identity_and_caps(
            reg,
            app_id="antigravity",
            model_id=mid,
            provider="google",
            family="gemini-4-argon",
            caps={
                CapabilityDimension.CODING: CapabilityState.VERIFIED,
                CapabilityDimension.DEBUGGING: CapabilityState.VERIFIED,
                CapabilityDimension.REASONING: CapabilityState.VERIFIED,
                CapabilityDimension.ADVERSARIAL_VERIFICATION: CapabilityState.VERIFIED,
            },
            efforts=(eff,),
        )

    _add_account_model(
        reg,
        user_id="usr-ind",
        app_inst_id="app-ind-agy",
        app_id="antigravity",
        acct_id="acct-ind-agy",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="mystery-model-x",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="mystery-model-x",
        provider="google",
        family="UNKNOWN",
        caps={
            CapabilityDimension.REASONING: CapabilityState.VERIFIED,
            CapabilityDimension.ADVERSARIAL_VERIFICATION: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.HIGH,),
    )

    plan = CapabilityModelRouter(reg).plan(
        user_profile_id="usr-ind",
        task_profile={
            "task_profile_id": "crit-1",
            "risk": "CRITICAL",
            "roles": ["IMPLEMENTATION_WORKER", "INDEPENDENT_VERIFIER"],
        },
    )
    assert plan.status == RoutePlanStatus.BLOCKED_INDEPENDENT_VERIFIER
    assert plan.roles["independent_verifier"].eligibility == "BLOCKED"
    assert plan.roles["independent_verifier"].model_id is None
    assert plan.verification_independence["satisfied"] is False


def test_c02_cross_provider_verifier_and_quota_exhaustion_and_unknown_quota() -> None:
    reg = EntitlementRegistry()
    _add_account_model(
        reg,
        user_id="usr-cp",
        app_inst_id="app-cp-agy",
        app_id="antigravity",
        acct_id="acct-cp-agy",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-hydrogen-high",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.AVAILABLE,
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-4-hydrogen-high",
        provider="google",
        family="gemini-4-hydrogen",
        caps={
            CapabilityDimension.CODING: CapabilityState.VERIFIED,
            CapabilityDimension.DEBUGGING: CapabilityState.VERIFIED,
            CapabilityDimension.REASONING: CapabilityState.VERIFIED,
            CapabilityDimension.ADVERSARIAL_VERIFICATION: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.HIGH,),
    )
    # Argon exhausted quota -> must be rejected
    _add_account_model(
        reg,
        user_id="usr-cp",
        app_inst_id="app-cp-agy",
        app_id="antigravity",
        acct_id="acct-cp-agy",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-argon-high",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.EXHAUSTED,
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-4-argon-high",
        provider="google",
        family="gemini-4-argon",
        caps={
            CapabilityDimension.REASONING: CapabilityState.VERIFIED,
            CapabilityDimension.ADVERSARIAL_VERIFICATION: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.HIGH,),
    )
    # Cross-provider Claude in same runtime with UNKNOWN quota -> CONDITIONAL
    _add_account_model(
        reg,
        user_id="usr-cp",
        app_inst_id="app-cp-agy",
        app_id="antigravity",
        acct_id="acct-cp-agy",
        provider="anthropic",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="claude-opus-5-5-high",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.UNKNOWN,
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="claude-opus-5-5-high",
        provider="anthropic",
        family="claude-opus-5.5",
        caps={
            CapabilityDimension.REASONING: CapabilityState.VERIFIED,
            CapabilityDimension.ADVERSARIAL_VERIFICATION: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.HIGH,),
    )
    reg.set_policy(
        UserRoutingPolicy(
            policy_id="pol-cp",
            user_profile_id="usr-cp",
            require_cross_provider_verifier=True,
        )
    )
    plan = CapabilityModelRouter(reg).plan(
        user_profile_id="usr-cp",
        task_profile={
            "task_profile_id": "crit-cp",
            "risk": "CRITICAL",
            "roles": ["IMPLEMENTATION_WORKER", "INDEPENDENT_VERIFIER"],
        },
    )
    assert plan.status == RoutePlanStatus.PROPOSED_CONDITIONAL
    assert plan.roles["implementation_worker"].model_id == "gemini-4-hydrogen-high"
    assert plan.roles["independent_verifier"].model_id == "claude-opus-5-5-high"
    assert plan.roles["independent_verifier"].eligibility == "CONDITIONAL"
    assert plan.verification_independence["checks"]["different_provider"] is True
    assert any(
        e.model_id == "gemini-4-argon-high" and "QUOTA_EXHAUSTED" in e.reason_codes
        for e in plan.excluded_candidates
    )


def test_c03_stale_quota_not_treated_as_available() -> None:
    reg = EntitlementRegistry()
    _add_account_model(
        reg,
        user_id="usr-sq",
        app_inst_id="app-sq",
        app_id="antigravity",
        acct_id="acct-sq",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-hydrogen-high",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.AVAILABLE,
        observed_at="2026-11-01T00:00:00Z",
        quota_expires_at="2026-11-02T00:00:00Z",
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-4-hydrogen-high",
        provider="google",
        family="gemini-4-hydrogen",
        caps={CapabilityDimension.CODING: CapabilityState.VERIFIED, CapabilityDimension.DEBUGGING: CapabilityState.VERIFIED},
        efforts=(NormalizedEffort.HIGH,),
    )
    plan = CapabilityModelRouter(reg).plan(
        user_profile_id="usr-sq",
        task_profile={"task_profile_id": "t-sq", "risk": "MEDIUM", "roles": ["IMPLEMENTATION_WORKER"]},
    )
    assert plan.status == RoutePlanStatus.PROPOSED_CONDITIONAL
    assert plan.roles["implementation_worker"].eligibility == "CONDITIONAL"
    assert plan.roles["implementation_worker"].quota_state == "UNKNOWN"


# ==============================================================================
# D. Synthetic User Profiles (A, B, C) & Enterprise Restrictions
# ==============================================================================


def _build_synthetic_profiles() -> EntitlementRegistry:
    reg = EntitlementRegistry()

    # Shared capability/identity metadata for synthetic models across apps
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-3.8-flash-high",
        provider="google",
        family="gemini-3.8-flash",
        caps={
            CapabilityDimension.CODING: CapabilityState.VERIFIED,
            CapabilityDimension.DEBUGGING: CapabilityState.VERIFIED,
            CapabilityDimension.REASONING: CapabilityState.DOCUMENTED,
            CapabilityDimension.ADVERSARIAL_VERIFICATION: CapabilityState.DOCUMENTED,
        },
        efforts=(NormalizedEffort.HIGH,),
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-4-hydrogen-high",
        provider="google",
        family="gemini-4-hydrogen",
        caps={
            CapabilityDimension.CODING: CapabilityState.VERIFIED,
            CapabilityDimension.DEBUGGING: CapabilityState.VERIFIED,
            CapabilityDimension.REASONING: CapabilityState.VERIFIED,
            CapabilityDimension.ARCHITECTURE: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.HIGH, NormalizedEffort.XHIGH),
        default_effort=NormalizedEffort.HIGH,
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-4-argon-high",
        provider="google",
        family="gemini-4-argon",
        caps={
            CapabilityDimension.REASONING: CapabilityState.VERIFIED,
            CapabilityDimension.ARCHITECTURE: CapabilityState.VERIFIED,
            CapabilityDimension.ADVERSARIAL_VERIFICATION: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.HIGH,),
    )
    _seed_identity_and_caps(
        reg,
        app_id="codex",
        model_id="gpt-5.6-luna",
        provider="openai",
        family="gpt-5.6",
        caps={
            CapabilityDimension.CODING: CapabilityState.VERIFIED,
            CapabilityDimension.DEBUGGING: CapabilityState.VERIFIED,
            CapabilityDimension.REASONING: CapabilityState.VERIFIED,
            CapabilityDimension.ADVERSARIAL_VERIFICATION: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.LOW, NormalizedEffort.MEDIUM, NormalizedEffort.HIGH, NormalizedEffort.XHIGH),
        default_effort=NormalizedEffort.MEDIUM,
    )
    _seed_identity_and_caps(
        reg,
        app_id="claude_desktop",
        model_id="claude-opus-5-5-high",
        provider="anthropic",
        family="claude-opus-5.5",
        caps={
            CapabilityDimension.REASONING: CapabilityState.VERIFIED,
            CapabilityDimension.ARCHITECTURE: CapabilityState.VERIFIED,
            CapabilityDimension.ADVERSARIAL_VERIFICATION: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.HIGH,),
    )

    # Profile A: Limited subscription access (only Flash High verified on Antigravity; Codex only bundled catalog)
    _add_account_model(
        reg,
        user_id="usr-profile-a",
        app_inst_id="app-pa-agy",
        app_id="antigravity",
        acct_id="acct-pa-agy",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-3.8-flash-high",
        ent_state=EntitlementState.USER_CONFIRMED_SELECTABLE,
        quota_state=QuotaState.AVAILABLE,
        subscription_tier="limited_sub",
        sub_source=SubscriptionSource.USER_DECLARED,
    )
    _add_account_model(
        reg,
        user_id="usr-profile-a",
        app_inst_id="app-pa-codex",
        app_id="codex",
        acct_id="acct-pa-codex",
        provider="openai",
        auth_mode=AuthenticationMode.UNKNOWN,
        model_id="gpt-5.6-luna",
        ent_state=EntitlementState.BUNDLED_CATALOG,
        quota_state=QuotaState.NOT_EXPOSED,
    )

    # Profile B: Expanded subscription access (Hydrogen + Argon + Codex OAuth subscription)
    _add_account_model(
        reg,
        user_id="usr-profile-b",
        app_inst_id="app-pb-agy",
        app_id="antigravity",
        acct_id="acct-pb-agy",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-hydrogen-high",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.AVAILABLE,
        subscription_tier="ultra",
        sub_source=SubscriptionSource.APPLICATION_RUNTIME,
    )
    _add_account_model(
        reg,
        user_id="usr-profile-b",
        app_inst_id="app-pb-agy",
        app_id="antigravity",
        acct_id="acct-pb-agy",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-argon-high",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.AVAILABLE,
        subscription_tier="ultra",
        sub_source=SubscriptionSource.APPLICATION_RUNTIME,
    )
    _add_account_model(
        reg,
        user_id="usr-profile-b",
        app_inst_id="app-pb-codex",
        app_id="codex",
        acct_id="acct-pb-codex",
        provider="openai",
        auth_mode=AuthenticationMode.OAUTH_SUBSCRIPTION,
        model_id="gpt-5.6-luna",
        ent_state=EntitlementState.ACCOUNT_ENUMERATED,
        quota_state=QuotaState.AVAILABLE,
        subscription_tier="pro",
        sub_source=SubscriptionSource.OFFICIAL_READ_ONLY_INTERFACE,
    )

    # Profile C: Mixed subscription and API-key access, API billing disabled by default
    _add_account_model(
        reg,
        user_id="usr-profile-c",
        app_inst_id="app-pc-agy",
        app_id="antigravity",
        acct_id="acct-pc-agy-sub",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-hydrogen-high",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.AVAILABLE,
        subscription_tier="pro",
        sub_source=SubscriptionSource.USER_DECLARED,
    )
    _add_account_model(
        reg,
        user_id="usr-profile-c",
        app_inst_id="app-pc-codex",
        app_id="codex",
        acct_id="acct-pc-codex-api",
        provider="openai",
        auth_mode=AuthenticationMode.API_KEY,
        model_id="gpt-5.6-luna",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.AVAILABLE,
    )
    # Default safe policy for Profile C has api_billing_allowed=False, subscription_only=True
    reg.set_policy(
        UserRoutingPolicy(
            policy_id="pol-pc",
            user_profile_id="usr-profile-c",
            subscription_only=True,
            api_billing_allowed=False,
            max_cost_policy=CostPolicy.DENY_UNSPECIFIED_COST,
        )
    )
    return reg


def test_d01_three_synthetic_profiles_produce_distinct_valid_plans() -> None:
    reg = _build_synthetic_profiles()
    router = CapabilityModelRouter(reg)
    crit_task = {
        "task_profile_id": "security-sensitive-implementation",
        "risk": "CRITICAL",
        "roles": ["IMPLEMENTATION_WORKER", "INDEPENDENT_VERIFIER"],
    }

    plan_a = router.plan(user_profile_id="usr-profile-a", task_profile=crit_task)
    plan_b = router.plan(user_profile_id="usr-profile-b", task_profile=crit_task)
    plan_c = router.plan(user_profile_id="usr-profile-c", task_profile=crit_task)

    # Profile A: Limited access -> worker Flash High, verifier BLOCKED (no independent model entitled)
    assert plan_a.status == RoutePlanStatus.BLOCKED_INDEPENDENT_VERIFIER
    assert plan_a.roles["implementation_worker"].model_id == "gemini-3.8-flash-high"
    assert plan_a.roles["independent_verifier"].eligibility == "BLOCKED"

    # Profile B: Expanded access -> READY_FOR_USER_REVIEW with distinct family verifier
    assert plan_b.status == RoutePlanStatus.READY_FOR_USER_REVIEW
    assert plan_b.roles["implementation_worker"].model_id in ("gemini-4-hydrogen-high", "gpt-5.6-luna")
    assert plan_b.roles["independent_verifier"].eligibility == "ACCEPTED"
    assert plan_b.verification_independence["satisfied"] is True

    # Profile C: API billing disabled blocks Codex API key verifier -> BLOCKED_INDEPENDENT_VERIFIER
    assert plan_c.status == RoutePlanStatus.BLOCKED_INDEPENDENT_VERIFIER
    assert plan_c.roles["implementation_worker"].model_id == "gemini-4-hydrogen-high"
    assert any(
        e.account_context_id == "acct-pc-codex-api" and "API_BILLING_DISABLED" in e.reason_codes
        for e in plan_c.excluded_candidates
    )
    assert plan_a.execution_authorized is False
    assert plan_b.execution_authorized is False
    assert plan_c.execution_authorized is False


def test_d02_enterprise_workspace_restrictions_enforced() -> None:
    reg = EntitlementRegistry()
    _add_account_model(
        reg,
        user_id="usr-ent",
        app_inst_id="app-ent",
        app_id="antigravity",
        acct_id="acct-ent",
        provider="google",
        auth_mode=AuthenticationMode.ENTERPRISE,
        model_id="gemini-4-hydrogen-high",
        ent_state=EntitlementState.ACCOUNT_ENUMERATED,
        quota_state=QuotaState.AVAILABLE,
        ws_blocked=("gemini-4-hydrogen-high",),
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-4-hydrogen-high",
        provider="google",
        family="gemini-4-hydrogen",
        caps={CapabilityDimension.CODING: CapabilityState.VERIFIED, CapabilityDimension.DEBUGGING: CapabilityState.VERIFIED},
        efforts=(NormalizedEffort.HIGH,),
    )
    plan = CapabilityModelRouter(reg).plan(
        user_profile_id="usr-ent",
        task_profile={"task_profile_id": "t-ent", "risk": "MEDIUM", "roles": ["IMPLEMENTATION_WORKER"]},
    )
    assert plan.status == RoutePlanStatus.BLOCKED_ENTITLEMENT
    assert any("WORKSPACE_BLOCKED_MODEL" in e.reason_codes for e in plan.excluded_candidates)


# ==============================================================================
# E. Security, Privacy, Persistence (Migration 006), & CLI Tests
# ==============================================================================


@pytest.mark.parametrize(
    "bad_id",
    [
        "user@example.com",
        "sk-ant-1234567890abcdef",
        "AIzaSyDummySecretValue1234567",
        "has spaces",
    ],
)
def test_e01_opaque_id_rejects_pii_and_secrets(bad_id: str) -> None:
    with pytest.raises(SecretOrPiiIntakeError):
        validate_opaque_id(bad_id, field_name="account_context_id")


def test_e02_manual_profile_rejects_secret_and_pii_intake() -> None:
    reg = EntitlementRegistry()
    for bad_payload in [
        {
            "schema_version": "1.0.0",
            "user_profile_id": "usr-bad",
            "accounts": [
                {
                    "account_context_id": "acct-1",
                    "application": "codex",
                    "provider": "openai",
                    "authentication_mode": "API_KEY",
                    "api_key": "sk-proj-secret1234567890",
                }
            ],
        },
        {
            "schema_version": "1.0.0",
            "user_profile_id": "usr-bad",
            "accounts": [
                {
                    "account_context_id": "acct-1",
                    "application": "antigravity",
                    "provider": "google",
                    "authentication_mode": "SUBSCRIPTION",
                    "email": "alice@example.com",
                }
            ],
        },
        {
            "schema_version": "1.0.0",
            "user_profile_id": "usr-bad",
            "accounts": [
                {
                    "account_context_id": "acct-1",
                    "application": "claude_desktop",
                    "provider": "anthropic",
                    "authentication_mode": "SUBSCRIPTION",
                    "notes": "-----BEGIN RSA PRIVATE KEY-----",
                }
            ],
        },
    ]:
        with pytest.raises(SecretOrPiiIntakeError):
            load_manual_profile_dict(reg, bad_payload)


def test_e03_disposable_sqlite_migration_006_and_roundtrip(tmp_path: Path) -> None:
    db_path = tmp_path / "disposable_next22b.db"
    initialize(db_path)

    integ = check_database_integrity(db_path)
    assert integ["ok"] is True

    reg = _build_synthetic_profiles()
    router = CapabilityModelRouter(reg)
    plan = router.plan(
        user_profile_id="usr-profile-b",
        task_profile={
            "task_profile_id": "db-roundtrip-task",
            "risk": "CRITICAL",
            "roles": ["IMPLEMENTATION_WORKER", "INDEPENDENT_VERIFIER"],
        },
    )

    with connect(db_path) as conn:
        versions = {int(r["version"]) for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
        assert {1, 2, 3, 4, 5, 6}.issubset(versions)
        reg.persist_to_db(conn)
        conn.commit()

        # Verify zero execution approvals created by route planning
        approvals_count = conn.execute("SELECT COUNT(*) FROM execution_approvals").fetchone()[0]
        assert approvals_count == 0

        hydrated = EntitlementRegistry.load_from_db(conn)
        assert len(hydrated.get_user_accounts("usr-profile-b")) == 2
        assert hydrated.get_effective_entitlement("acct-pb-codex", "gpt-5.6-luna").state == EntitlementState.ACCOUNT_ENUMERATED
        assert hydrated.get_effective_quota("acct-pb-agy", "gemini-4-hydrogen-high").state == QuotaState.AVAILABLE

        # Verify persisted decision + explanations
        dec_row = conn.execute("SELECT * FROM routing_decisions WHERE decision_id = ?", (plan.decision_id,)).fetchone()
        assert dec_row is not None
        assert dec_row["status"] == RoutePlanStatus.READY_FOR_USER_REVIEW.value
        exp_rows = conn.execute(
            "SELECT * FROM routing_candidate_explanations WHERE decision_id = ?", (plan.decision_id,)
        ).fetchall()
        assert len(exp_rows) == len(plan.candidate_evaluations)


def test_e04_migration_006_fault_rollback_preserves_preexisting_v5_db(tmp_path: Path) -> None:
    db_path = tmp_path / "fault_test.db"
    initialize(db_path)

    # Simulate a pre-v6 db by removing version 6 & v6 tables, then injecting fault before commit
    with connect(db_path) as conn:
        conn.execute("DELETE FROM schema_migrations WHERE version = 6")
        conn.execute("DROP TABLE routing_candidate_explanations")
        conn.commit()

    def _fault(_conn: sqlite3.Connection, stage: str) -> None:
        if stage == "before_commit":
            raise RuntimeError("Simulated mid-migration failure")

    with pytest.raises(RuntimeError, match="Simulated mid-migration failure"):
        initialize(db_path, _migration_fault_hook=_fault)

    with connect(db_path) as conn:
        versions = {int(r["version"]) for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
        assert 6 not in versions

    # Clean recovery works idempotently
    initialize(db_path)
    with connect(db_path) as conn:
        versions = {int(r["version"]) for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
        assert 6 in versions


def test_e05_cli_routing_commands_dry_run_without_touching_prod_db(tmp_path: Path) -> None:
    db_path = tmp_path / "cli_disposable.db"
    initialize(db_path)
    reg = _build_synthetic_profiles()
    plan = CapabilityModelRouter(reg).plan(
        user_profile_id="usr-profile-b",
        task_profile={
            "task_profile_id": "cli-test-task",
            "risk": "CRITICAL",
            "roles": ["IMPLEMENTATION_WORKER", "INDEPENDENT_VERIFIER"],
        },
        decision_id="dec-cli-test-001",
    )
    with connect(db_path) as conn:
        reg.persist_to_db(conn)
        conn.commit()

    task_file = tmp_path / "task.json"
    task_file.write_text(
        json.dumps(
            {
                "task_profile_id": "cli-plan-task",
                "risk": "CRITICAL",
                "roles": ["IMPLEMENTATION_WORKER", "INDEPENDENT_VERIFIER"],
            }
        ),
        encoding="utf-8",
    )

    nonexistent_prod_db = tmp_path / "must_not_be_created_prod.db"
    env = dict(**__import__("os").environ, ANTIGRAVITY_AUDITOR_DB=str(nonexistent_prod_db))

    for args in [
        ["routing", "inspect", "--db", str(db_path), "--user-profile", "usr-profile-b", "--json"],
        ["routing", "accounts", "--db", str(db_path), "--user-profile", "usr-profile-b", "--json"],
        ["routing", "models", "--db", str(db_path), "--user-profile", "usr-profile-b", "--account", "acct-pb-agy", "--json"],
        ["routing", "policy", "show", "--db", str(db_path), "--user-profile", "usr-profile-b", "--json"],
        ["routing", "plan", "--db", str(db_path), "--user-profile", "usr-profile-b", "--task-profile", str(task_file), "--json"],
        ["routing", "explain", "--db", str(db_path), "--decision-id", plan.decision_id, "--json"],
    ]:
        proc = subprocess.run(
            [sys.executable, str(CLI_PATH), *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=20,
            shell=False,
        )
        assert proc.returncode == 0, f"CLI failed for {args}: {proc.stderr}"
        parsed = json.loads(proc.stdout)
        assert isinstance(parsed, dict)

    assert not nonexistent_prod_db.exists()


def test_c04_orchestrator_fixed_internal_rejected_for_high_effort_and_fallback_filtered() -> None:
    reg = EntitlementRegistry()
    # Orchestrator with FIXED_INTERNAL effort
    _add_account_model(
        reg,
        user_id="usr-orch",
        app_inst_id="app-orch-agy",
        app_id="antigravity",
        acct_id="acct-orch-agy",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-pro-orchestrator-g1-pro",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.AVAILABLE,
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-pro-orchestrator-g1-pro",
        provider="google",
        family="UNKNOWN",
        caps={
            CapabilityDimension.REASONING: CapabilityState.VERIFIED,
            CapabilityDimension.ARCHITECTURE: CapabilityState.VERIFIED,
            CapabilityDimension.PARALLEL_AGENT_COORDINATION: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.FIXED_INTERNAL,),
        managed_by_orchestrator=True,
    )
    # Valid Hydrogen fallback/primary + API-key model that must NOT appear in fallback
    _add_account_model(
        reg,
        user_id="usr-orch",
        app_inst_id="app-orch-agy",
        app_id="antigravity",
        acct_id="acct-orch-agy",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-hydrogen-high",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.AVAILABLE,
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-4-hydrogen-high",
        provider="google",
        family="gemini-4-hydrogen",
        caps={
            CapabilityDimension.REASONING: CapabilityState.VERIFIED,
            CapabilityDimension.ARCHITECTURE: CapabilityState.VERIFIED,
            CapabilityDimension.PARALLEL_AGENT_COORDINATION: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.HIGH,),
    )
    _add_account_model(
        reg,
        user_id="usr-orch",
        app_inst_id="app-orch-codex",
        app_id="codex",
        acct_id="acct-orch-codex-api",
        provider="openai",
        auth_mode=AuthenticationMode.API_KEY,
        model_id="gpt-5.6-luna",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.AVAILABLE,
    )
    _seed_identity_and_caps(
        reg,
        app_id="codex",
        model_id="gpt-5.6-luna",
        provider="openai",
        family="gpt-5.6",
        caps={
            CapabilityDimension.REASONING: CapabilityState.VERIFIED,
            CapabilityDimension.ARCHITECTURE: CapabilityState.VERIFIED,
            CapabilityDimension.PARALLEL_AGENT_COORDINATION: CapabilityState.VERIFIED,
        },
        efforts=(NormalizedEffort.HIGH,),
    )

    plan = CapabilityModelRouter(reg).plan(
        user_profile_id="usr-orch",
        task_profile={
            "task_profile_id": "t-orch",
            "risk": "HIGH",
            "roles": ["CHIEF_ORCHESTRATOR"],
        },
    )
    assert plan.roles["chief_orchestrator"].model_id == "gemini-4-hydrogen-high"
    assert plan.fallback_candidates["chief_orchestrator"] == []
    assert any(
        e.model_id == "gemini-pro-orchestrator-g1-pro" and "EFFORT_FIXED_INTERNAL_UNVERIFIED" in e.reason_codes
        for e in plan.excluded_candidates
    )
    assert any(
        e.model_id == "gpt-5.6-luna" and "API_BILLING_DISABLED" in e.reason_codes
        for e in plan.excluded_candidates
    )


def test_c05_policy_blocked_better_model_excluded_with_explanation() -> None:
    reg = _build_synthetic_profiles()
    reg.set_policy(
        UserRoutingPolicy(
            policy_id="pol-block-hydro",
            user_profile_id="usr-profile-b",
            blocked_models=("gemini-4-hydrogen-high",),
        )
    )
    plan = CapabilityModelRouter(reg).plan(
        user_profile_id="usr-profile-b",
        task_profile={
            "task_profile_id": "t-blk",
            "risk": "HIGH",
            "roles": ["IMPLEMENTATION_WORKER"],
        },
    )
    assert plan.roles["implementation_worker"].model_id == "gpt-5.6-luna"
    assert any(
        e.model_id == "gemini-4-hydrogen-high" and "POLICY_BLOCKED_MODEL" in e.reason_codes
        for e in plan.excluded_candidates
    )


def test_e06_route_plan_scrubs_accidental_emails_and_tokens_in_output() -> None:
    reg = EntitlementRegistry()
    reg.register_user(UserProfileRecord(user_profile_id="usr-scrub", label="alice@example.com"))
    _add_account_model(
        reg,
        user_id="usr-scrub",
        app_inst_id="app-scrub",
        app_id="antigravity",
        acct_id="acct-scrub",
        provider="google",
        auth_mode=AuthenticationMode.SUBSCRIPTION,
        model_id="gemini-4-hydrogen-high",
        ent_state=EntitlementState.SELECTABLE_VERIFIED,
        quota_state=QuotaState.AVAILABLE,
    )
    _seed_identity_and_caps(
        reg,
        app_id="antigravity",
        model_id="gemini-4-hydrogen-high",
        provider="google",
        family="gemini-4-hydrogen",
        caps={CapabilityDimension.CODING: CapabilityState.VERIFIED, CapabilityDimension.DEBUGGING: CapabilityState.VERIFIED},
        efforts=(NormalizedEffort.HIGH,),
    )
    plan = CapabilityModelRouter(reg).plan(
        user_profile_id="usr-scrub",
        task_profile={"task_profile_id": "t-scrub", "risk": "LOW", "roles": ["IMPLEMENTATION_WORKER"]},
    )
    serialized = json.dumps(plan.to_dict())
    assert "alice@example.com" not in serialized
    assert "sk-" not in serialized
    assert "AIza" not in serialized


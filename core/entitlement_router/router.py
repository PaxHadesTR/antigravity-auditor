"""Deterministic Capability-Based Model Router for NEXT-22B."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from entitlement_router.contracts import (
    CONDITIONAL_ENTITLEMENT_STATES,
    DISALLOWED_ENTITLEMENT_STATES,
    VERIFIED_ENTITLEMENT_STATES,
    AccountContextRecord,
    ApplicationInstanceRecord,
    AuthenticationMode,
    CandidateEligibility,
    CandidateEvaluation,
    CapabilityDimension,
    CapabilityState,
    CostPolicy,
    EntitlementState,
    ModelIdentityRecord,
    NormalizedEffort,
    QuotaState,
    RoleAssignment,
    RoutePlan,
    RoutePlanStatus,
    RouterTaskRisk,
    TaskProfile,
    TaskRole,
    UserRoutingPolicy,
    VerifierIndependenceLevel,
    utc_now_iso,
)
from entitlement_router.registry import EffectiveCapability, EntitlementRegistry

_DEFAULT_ROLE_CAPABILITIES: dict[TaskRole, tuple[CapabilityDimension, ...]] = {
    TaskRole.CHIEF_ORCHESTRATOR: (
        CapabilityDimension.REASONING,
        CapabilityDimension.ARCHITECTURE,
        CapabilityDimension.PARALLEL_AGENT_COORDINATION,
    ),
    TaskRole.ARCHITECT: (
        CapabilityDimension.REASONING,
        CapabilityDimension.ARCHITECTURE,
    ),
    TaskRole.IMPLEMENTATION_WORKER: (
        CapabilityDimension.CODING,
        CapabilityDimension.DEBUGGING,
    ),
    TaskRole.FAST_WORKER: (
        CapabilityDimension.CODING,
    ),
    TaskRole.TEST_ENGINEER: (
        CapabilityDimension.CODING,
        CapabilityDimension.DEBUGGING,
    ),
    TaskRole.INDEPENDENT_VERIFIER: (
        CapabilityDimension.REASONING,
        CapabilityDimension.ADVERSARIAL_VERIFICATION,
    ),
    TaskRole.RECOVERY_ANALYST: (
        CapabilityDimension.REASONING,
        CapabilityDimension.DEBUGGING,
    ),
}

_ENTITLEMENT_RANK: dict[EntitlementState, int] = {
    EntitlementState.SELECTABLE_VERIFIED: 6,
    EntitlementState.INVOCATION_OBSERVED: 5,
    EntitlementState.ACCOUNT_ENUMERATED: 4,
    EntitlementState.USER_CONFIRMED_SELECTABLE: 3,
    EntitlementState.RUNTIME_OBSERVED: 2,
    EntitlementState.USER_DECLARED: 1,
    EntitlementState.CONFIGURED: 1,
}

_QUOTA_RANK: dict[QuotaState, int] = {
    QuotaState.AVAILABLE: 3,
    QuotaState.LOW: 2,
    QuotaState.UNKNOWN: 1,
    QuotaState.NOT_EXPOSED: 1,
}

_CAPABILITY_RANK: dict[CapabilityState, int] = {
    CapabilityState.VERIFIED: 4,
    CapabilityState.DOCUMENTED: 3,
    CapabilityState.USER_REPORTED: 2,
    CapabilityState.EXPERIMENTAL: 1,
}


def _default_required_effort(role: TaskRole, risk: RouterTaskRisk) -> NormalizedEffort:
    if role == TaskRole.FAST_WORKER:
        return NormalizedEffort.LOW if risk == RouterTaskRisk.LOW else NormalizedEffort.MEDIUM
    if risk in (RouterTaskRisk.HIGH, RouterTaskRisk.CRITICAL):
        return NormalizedEffort.HIGH
    if risk == RouterTaskRisk.MEDIUM:
        return NormalizedEffort.MEDIUM
    return NormalizedEffort.LOW


def _effort_order(eff: NormalizedEffort) -> int:
    return {
        NormalizedEffort.UNKNOWN: 0,
        NormalizedEffort.FIXED_INTERNAL: 0,
        NormalizedEffort.LOW: 1,
        NormalizedEffort.MEDIUM: 2,
        NormalizedEffort.HIGH: 3,
        NormalizedEffort.XHIGH: 4,
    }.get(eff, 0)


def _check_billing_policy(
    auth_mode: AuthenticationMode,
    policy: UserRoutingPolicy,
) -> tuple[bool, str | None, str | None]:
    """Return (allowed, reason_code, explanation)."""
    if auth_mode == AuthenticationMode.API_KEY:
        if policy.subscription_only or not policy.api_billing_allowed:
            return (
                False,
                "API_BILLING_DISABLED",
                "Candidate uses API_KEY authentication, but api_billing_allowed is False (subscription_only=True).",
            )
        if policy.max_cost_policy in (
            CostPolicy.DENY_UNSPECIFIED_COST,
            CostPolicy.FREE_OR_SUBSCRIPTION_ONLY,
        ):
            return (
                False,
                "COST_POLICY_DENIES_API_BILLING",
                f"Candidate uses API_KEY authentication, rejected by max_cost_policy={policy.max_cost_policy.value}.",
            )
        return True, None, None

    if auth_mode == AuthenticationMode.UNKNOWN:
        if policy.max_cost_policy == CostPolicy.DENY_UNSPECIFIED_COST or policy.subscription_only:
            return (
                False,
                "DENY_UNVERIFIED_BILLING",
                "Authentication/billing mode is UNKNOWN; DENY_UNVERIFIED_BILLING prevents unverified paid usage.",
            )
        return True, None, None

    # SUBSCRIPTION, OAUTH_SUBSCRIPTION, ENTERPRISE, ORGANIZATION_MANAGED, LOCAL_ONLY
    return True, None, None


def _evaluate_independence(
    primary_items: list[tuple[str, str, ModelIdentityRecord | None, str]],
    verifier_app: str,
    verifier_model: str,
    verifier_identity: ModelIdentityRecord | None,
    verifier_provider: str,
    required_level: VerifierIndependenceLevel,
) -> tuple[bool, list[str], dict[str, Any]]:
    """Evaluate independence dimensions against all assigned primary role models."""
    if not primary_items:
        return True, [], {
            "different_session": True,
            "different_model": True,
            "different_model_family": True,
            "different_provider": True,
        }

    v_canon = verifier_identity.canonical_model_id if verifier_identity else None
    v_family = verifier_identity.model_family if verifier_identity else "UNKNOWN"
    v_prov = (verifier_identity.provider if verifier_identity else verifier_provider or "unknown").lower()

    diff_model_all = True
    diff_family_all = True
    diff_provider_all = True
    failures: list[str] = []

    for p_app, p_model, p_ident, p_prov in primary_items:
        p_canon = p_ident.canonical_model_id if p_ident else None
        p_family = p_ident.model_family if p_ident else "UNKNOWN"
        p_prov_norm = (p_ident.provider if p_ident else p_prov or "unknown").lower()

        same_model = (verifier_model.lower() == p_model.lower()) or (
            bool(v_canon) and bool(p_canon) and v_canon.lower() == p_canon.lower()
        )
        if same_model:
            diff_model_all = False
            diff_family_all = False
            failures.append(f"SAME_MODEL_CANNOT_SELF_VERIFY ({verifier_model} == {p_model})")
            continue

        # Family check: both families must be known and distinct
        if v_family.upper() == "UNKNOWN" or p_family.upper() == "UNKNOWN":
            diff_family_all = False
            if required_level in (
                VerifierIndependenceLevel.DIFFERENT_MODEL_FAMILY,
                VerifierIndependenceLevel.DIFFERENT_PROVIDER,
            ):
                failures.append(
                    f"UNKNOWN_MODEL_FAMILY_NOT_INDEPENDENT (verifier_family={v_family}, primary_family={p_family})"
                )
        elif v_family.lower() == p_family.lower():
            diff_family_all = False
            failures.append(
                f"SAME_MODEL_FAMILY_NOT_INDEPENDENT ({v_family} == {p_family})"
            )

        # Provider check: both providers must be known and distinct
        if v_prov == "unknown" or p_prov_norm == "unknown" or v_prov == p_prov_norm:
            diff_provider_all = False
            if required_level == VerifierIndependenceLevel.DIFFERENT_PROVIDER:
                failures.append(
                    f"CROSS_PROVIDER_REQUIRED (verifier_provider={v_prov}, primary_provider={p_prov_norm})"
                )

    checks = {
        "different_session": True,
        "different_model": diff_model_all,
        "different_model_family": diff_family_all,
        "different_provider": diff_provider_all,
    }

    if required_level == VerifierIndependenceLevel.DIFFERENT_SESSION:
        ok = True
    elif required_level == VerifierIndependenceLevel.DIFFERENT_MODEL:
        ok = diff_model_all
    elif required_level == VerifierIndependenceLevel.DIFFERENT_MODEL_FAMILY:
        ok = diff_model_all and diff_family_all
    else:  # DIFFERENT_PROVIDER
        ok = diff_model_all and diff_family_all and diff_provider_all

    return ok, failures, checks


class CapabilityModelRouter:
    """Deterministic, explainable planner generating per-user RoutePlans."""

    def __init__(self, registry: EntitlementRegistry) -> None:
        self.registry = registry

    def plan(
        self,
        *,
        user_profile_id: str,
        task_profile: TaskProfile | dict[str, Any],
        as_of: datetime | None = None,
        decision_id: str | None = None,
    ) -> RoutePlan:
        """Generate an explainable RoutePlan without executing or authorizing anything."""
        dec_id = decision_id or f"dec-{uuid.uuid4().hex[:12]}"
        policy = self.registry.get_policy(user_profile_id)

        try:
            task = (
                task_profile
                if isinstance(task_profile, TaskProfile)
                else TaskProfile.from_dict(task_profile)
            )
        except Exception as exc:
            plan = RoutePlan(
                decision_id=dec_id,
                user_profile_id=user_profile_id,
                task_profile_id=str(
                    task_profile.get("task_profile_id", "invalid")
                    if isinstance(task_profile, dict)
                    else "invalid"
                ),
                risk="UNKNOWN",
                status=RoutePlanStatus.INVALID_TASK_PROFILE,
                roles={},
                billing={
                    "mode": "subscription_only" if policy.subscription_only else "mixed",
                    "api_billing_allowed": policy.api_billing_allowed,
                    "cost_state": policy.max_cost_policy.value.lower(),
                },
                quota={"state": "unknown"},
                excluded_candidates=(),
                candidate_evaluations=(),
                fallback_candidates={},
                required_confirmations=(f"Fix invalid task profile: {exc}",),
                evidence_refs=(),
                verification_independence={"required": False, "satisfied": False},
            )
            return plan

        user_accounts = self.registry.get_user_accounts(user_profile_id)
        installed_apps = [
            app
            for app in self.registry.applications.values()
            if app.user_profile_id == user_profile_id and app.installation_state in ("installed", "partial")
        ]

        # Enforce mandatory independent verifier on CRITICAL tasks when policy requires it
        roles_to_plan = list(task.roles)
        require_verifier = (
            task.require_independent_verifier
            if task.require_independent_verifier is not None
            else (task.risk == RouterTaskRisk.CRITICAL and policy.require_independent_verifier)
        )
        if require_verifier and TaskRole.INDEPENDENT_VERIFIER not in roles_to_plan:
            roles_to_plan.append(TaskRole.INDEPENDENT_VERIFIER)

        if not installed_apps or not user_accounts:
            blocked_roles = {
                r.value.lower(): RoleAssignment(
                    role=r,
                    application=None,
                    application_instance_id=None,
                    account_context_id=None,
                    provider=None,
                    model_id=None,
                    effort=None,
                    eligibility="BLOCKED",
                    entitlement_state=EntitlementState.UNKNOWN.value,
                    quota_state=QuotaState.UNKNOWN.value,
                    reason="No installed application runtime or account context available for user.",
                )
                for r in roles_to_plan
            }
            plan = RoutePlan(
                decision_id=dec_id,
                user_profile_id=user_profile_id,
                task_profile_id=task.task_profile_id,
                risk=task.risk.value,
                status=RoutePlanStatus.BLOCKED_NO_RUNTIME,
                roles=blocked_roles,
                billing={
                    "mode": "subscription_only" if policy.subscription_only else "mixed",
                    "api_billing_allowed": policy.api_billing_allowed,
                    "cost_state": policy.max_cost_policy.value.lower(),
                },
                quota={"state": "unknown"},
                excluded_candidates=(),
                candidate_evaluations=(),
                fallback_candidates={},
                required_confirmations=("Install or register at least one application runtime and account context.",),
                evidence_refs=(),
                verification_independence={
                    "required": require_verifier,
                    "satisfied": not require_verifier,
                    "status": "BLOCKED_NO_RUNTIME",
                },
            )
            self.registry.save_decision(plan)
            return plan

        # Build full candidate universe across all accounts & known models in those accounts
        candidate_pairs: list[tuple[ApplicationInstanceRecord, AccountContextRecord, str]] = []
        for acct in user_accounts:
            app_inst = self.registry.applications.get(acct.application_instance_id)
            if not app_inst:
                continue
            for mid in self.registry.list_models_for_account(acct.account_context_id):
                candidate_pairs.append((app_inst, acct, mid))

        # Order roles so primary roles are planned BEFORE INDEPENDENT_VERIFIER
        ordered_roles = [r for r in roles_to_plan if r != TaskRole.INDEPENDENT_VERIFIER]
        if TaskRole.INDEPENDENT_VERIFIER in roles_to_plan:
            ordered_roles.append(TaskRole.INDEPENDENT_VERIFIER)

        role_assignments: dict[str, RoleAssignment] = {}
        all_evaluations: list[CandidateEvaluation] = []
        excluded: list[CandidateEvaluation] = []
        fallback_map: dict[str, list[dict[str, Any]]] = {}
        confirmations: list[str] = []
        evidence_refs: set[str] = set()
        selected_primary_items: list[tuple[str, str, ModelIdentityRecord | None, str]] = []
        verifier_independence_info: dict[str, Any] = {
            "required": require_verifier,
            "satisfied": not require_verifier,
            "required_level": (
                VerifierIndependenceLevel.DIFFERENT_PROVIDER.value
                if policy.require_cross_provider_verifier
                else policy.minimum_verifier_independence.value
            ),
            "checks": {},
            "status": "NOT_REQUIRED" if not require_verifier else "PENDING",
        }

        for role in ordered_roles:
            req_caps = task.required_capabilities.get(role, _DEFAULT_ROLE_CAPABILITIES.get(role, ()))
            req_effort = task.required_efforts.get(role, _default_required_effort(role, task.risk))
            eff_indep_level = (
                VerifierIndependenceLevel.DIFFERENT_PROVIDER
                if policy.require_cross_provider_verifier
                else (
                    VerifierIndependenceLevel.DIFFERENT_MODEL_FAMILY
                    if task.risk == RouterTaskRisk.CRITICAL
                    and policy.minimum_verifier_independence
                    in (VerifierIndependenceLevel.DIFFERENT_SESSION, VerifierIndependenceLevel.DIFFERENT_MODEL)
                    else policy.minimum_verifier_independence
                )
            )
            if role == TaskRole.INDEPENDENT_VERIFIER:
                verifier_independence_info["required_level"] = eff_indep_level.value

            eligible_for_role: list[tuple[CandidateEvaluation, str | None, dict[str, Any]]] = []

            for app_inst, acct, model_id in candidate_pairs:
                ev, confirm_msg, indep_checks = self._evaluate_candidate(
                    role=role,
                    task=task,
                    policy=policy,
                    app_inst=app_inst,
                    acct=acct,
                    model_id=model_id,
                    req_caps=req_caps,
                    req_effort=req_effort,
                    primary_items=selected_primary_items,
                    required_independence=eff_indep_level,
                    as_of=as_of,
                    evidence_refs=evidence_refs,
                )
                all_evaluations.append(ev)
                if ev.eligibility in (CandidateEligibility.ACCEPTED, CandidateEligibility.CONDITIONAL):
                    eligible_for_role.append((ev, confirm_msg, indep_checks))
                else:
                    excluded.append(ev)

            if not eligible_for_role:
                block_reason = self._summarize_no_candidate_reason(role, all_evaluations)
                elig_str = "BLOCKED"
                if role == TaskRole.INDEPENDENT_VERIFIER:
                    verifier_independence_info["satisfied"] = False
                    verifier_independence_info["status"] = "BLOCKED_INDEPENDENT_VERIFIER_UNAVAILABLE"
                role_assignments[role.value.lower()] = RoleAssignment(
                    role=role,
                    application=None,
                    application_instance_id=None,
                    account_context_id=None,
                    provider=None,
                    model_id=None,
                    effort=None,
                    eligibility=elig_str,
                    entitlement_state=EntitlementState.UNKNOWN.value,
                    quota_state=QuotaState.UNKNOWN.value,
                    reason=block_reason,
                )
                fallback_map[role.value.lower()] = []
                continue

            # Deterministic ranking: score descending, then deterministic ID tie-breaker
            eligible_for_role.sort(
                key=lambda item: (
                    item[0].score,
                    item[0].application_id,
                    item[0].account_context_id,
                    item[0].model_id,
                ),
                reverse=True,
            )
            # Re-sort with deterministic ascending tie-breaker on IDs when scores tie
            best_score = eligible_for_role[0][0].score
            top_tied = [x for x in eligible_for_role if x[0].score == best_score]
            top_tied.sort(key=lambda item: (item[0].application_id, item[0].account_context_id, item[0].model_id))
            chosen, chosen_confirm, chosen_indep = top_tied[0]
            remaining = [x for x in eligible_for_role if x is not top_tied[0]]
            remaining.sort(
                key=lambda item: (
                    tuple(-s for s in item[0].score),
                    item[0].application_id,
                    item[0].account_context_id,
                    item[0].model_id,
                )
            )

            if chosen_confirm:
                confirmations.append(chosen_confirm)

            role_assignments[role.value.lower()] = RoleAssignment(
                role=role,
                application=chosen.application_id,
                application_instance_id=chosen.application_instance_id,
                account_context_id=chosen.account_context_id,
                provider=chosen.provider,
                model_id=chosen.model_id,
                effort=chosen.selected_effort,
                eligibility=chosen.eligibility.value,
                entitlement_state=chosen.entitlement_state,
                quota_state=chosen.quota_state,
                reason=chosen.explanation,
                independence_checks=chosen_indep,
            )

            if role != TaskRole.INDEPENDENT_VERIFIER:
                ident = self.registry.model_identities.get((chosen.application_id, chosen.model_id))
                selected_primary_items.append(
                    (chosen.application_id, chosen.model_id, ident, chosen.provider)
                )
            else:
                verifier_independence_info["satisfied"] = True
                verifier_independence_info["checks"] = chosen_indep
                verifier_independence_info["status"] = "VERIFIED_PLAN_INDEPENDENT"

            fallback_map[role.value.lower()] = [
                {
                    "application": fb.application_id,
                    "account_context_id": fb.account_context_id,
                    "provider": fb.provider,
                    "model_id": fb.model_id,
                    "effort": fb.selected_effort,
                    "eligibility": fb.eligibility.value,
                    "entitlement_state": fb.entitlement_state,
                    "quota_state": fb.quota_state,
                    "advisory_only": True,
                }
                for fb, _, _ in remaining
            ]

        overall_status = self._determine_overall_status(
            role_assignments=role_assignments,
            all_evaluations=all_evaluations,
            require_verifier=require_verifier,
            verifier_independence=verifier_independence_info,
        )

        # Summarize quota & billing state across selected roles
        selected_quotas = {
            ra.quota_state for ra in role_assignments.values() if ra.model_id is not None
        }
        quota_summary_state = (
            "AVAILABLE"
            if selected_quotas == {"AVAILABLE"}
            else ("UNKNOWN" if not selected_quotas or "UNKNOWN" in selected_quotas or "NOT_EXPOSED" in selected_quotas else ",".join(sorted(selected_quotas)))
        )

        plan = RoutePlan(
            decision_id=dec_id,
            user_profile_id=user_profile_id,
            task_profile_id=task.task_profile_id,
            risk=task.risk.value,
            status=overall_status,
            roles=role_assignments,
            billing={
                "mode": "subscription_only" if policy.subscription_only else "mixed",
                "api_billing_allowed": policy.api_billing_allowed,
                "cost_state": policy.max_cost_policy.value.lower(),
            },
            quota={"state": quota_summary_state.lower()},
            excluded_candidates=tuple(excluded),
            candidate_evaluations=tuple(all_evaluations),
            fallback_candidates=fallback_map,
            required_confirmations=tuple(dict.fromkeys(confirmations)),
            evidence_refs=tuple(sorted(evidence_refs)),
            verification_independence=verifier_independence_info,
        )
        self.registry.save_decision(plan)
        return plan

    def _evaluate_candidate(
        self,
        *,
        role: TaskRole,
        task: TaskProfile,
        policy: UserRoutingPolicy,
        app_inst: ApplicationInstanceRecord,
        acct: AccountContextRecord,
        model_id: str,
        req_caps: tuple[CapabilityDimension, ...],
        req_effort: NormalizedEffort,
        primary_items: list[tuple[str, str, ModelIdentityRecord | None, str]],
        required_independence: VerifierIndependenceLevel,
        as_of: datetime | None,
        evidence_refs: set[str],
    ) -> tuple[CandidateEvaluation, str | None, dict[str, Any]]:
        ident = self.registry.model_identities.get((acct.application_id, model_id))
        provider = (ident.provider if ident and ident.provider != "unknown" else acct.provider).lower()
        eff_ent = self.registry.get_effective_entitlement(acct.account_context_id, model_id, as_of=as_of)
        eff_quota = self.registry.get_effective_quota(acct.account_context_id, model_id, as_of=as_of)
        if eff_ent.observation and eff_ent.observation.evidence_ref:
            evidence_refs.add(eff_ent.observation.evidence_ref)
        if eff_quota.observation and eff_quota.observation.evidence_ref:
            evidence_refs.add(eff_quota.observation.evidence_ref)

        reasons: list[str] = []
        notes: list[str] = []
        conditional_reasons: list[str] = []
        unknown_reasons: list[str] = []

        # 1. Application installation state
        if app_inst.installation_state not in ("installed", "partial"):
            reasons.append("APP_NOT_INSTALLED")
            notes.append(
                f"Application '{acct.application_id}' installation_state is '{app_inst.installation_state}'."
            )

        # 2. Task & workspace & user policy filters
        if task.allowed_applications and acct.application_id not in task.allowed_applications:
            reasons.append("TASK_DISALLOWS_APPLICATION")
            notes.append(f"Task profile restricts applications to {list(task.allowed_applications)}.")

        if acct.workspace_blocked_models and model_id in acct.workspace_blocked_models:
            reasons.append("WORKSPACE_BLOCKED_MODEL")
            notes.append(f"Model '{model_id}' is blocked by workspace policy.")

        if acct.workspace_allowed_models and model_id not in acct.workspace_allowed_models:
            reasons.append("WORKSPACE_NOT_ALLOWLISTED")
            notes.append(f"Workspace restricts models to {list(acct.workspace_allowed_models)}.")

        if policy.blocked_providers and provider in policy.blocked_providers:
            reasons.append("POLICY_BLOCKED_PROVIDER")
            notes.append(f"Provider '{provider}' is in user blocked_providers.")

        if policy.allowed_providers and provider not in policy.allowed_providers:
            reasons.append("POLICY_PROVIDER_NOT_ALLOWED")
            notes.append(f"Provider '{provider}' is not in user allowed_providers.")

        if policy.blocked_models and model_id in policy.blocked_models:
            reasons.append("POLICY_BLOCKED_MODEL")
            notes.append(f"Model '{model_id}' is in user blocked_models.")

        if policy.allowed_models and model_id not in policy.allowed_models:
            reasons.append("POLICY_MODEL_NOT_ALLOWED")
            notes.append(f"Model '{model_id}' is not in user allowed_models.")

        # 3. Authentication & Billing policy
        bill_ok, bill_code, bill_msg = _check_billing_policy(acct.authentication_mode, policy)
        if not bill_ok and bill_code:
            reasons.append(bill_code)
            notes.append(bill_msg or "Billing policy rejected candidate.")

        # 4. Entitlement & selectability check
        ent_state = eff_ent.state
        if ent_state in DISALLOWED_ENTITLEMENT_STATES:
            if ent_state == EntitlementState.BUNDLED_CATALOG:
                reasons.append("BUNDLED_CATALOG_NOT_ENTITLEMENT")
                notes.append(
                    f"Model '{model_id}' is only in BUNDLED_CATALOG; bundled catalog does not establish account entitlement."
                )
            elif ent_state == EntitlementState.DOCUMENTED_ONLY:
                reasons.append("DOCUMENTED_ONLY_NOT_ENTITLEMENT")
                notes.append("Model is documented only without account or runtime availability.")
            else:
                reasons.append(f"ENTITLEMENT_{ent_state.value}")
                notes.append(eff_ent.reason)
        elif ent_state == EntitlementState.UNKNOWN:
            unknown_reasons.append("ENTITLEMENT_STALE_OR_UNKNOWN" if eff_ent.is_stale else "ENTITLEMENT_UNKNOWN")
            notes.append(eff_ent.reason)
        elif ent_state in CONDITIONAL_ENTITLEMENT_STATES:
            conditional_reasons.append(f"UNVERIFIED_ENTITLEMENT_{ent_state.value}")
            notes.append(
                f"Entitlement state is {ent_state.value} (requires account/selectability confirmation before dispatch)."
            )

        # 5. Quota check
        q_state = eff_quota.state
        if q_state in (QuotaState.EXHAUSTED, QuotaState.RATE_LIMITED, QuotaState.ERROR):
            reasons.append(f"QUOTA_{q_state.value}")
            notes.append(eff_quota.reason)
        elif q_state in (QuotaState.UNKNOWN, QuotaState.NOT_EXPOSED) or eff_quota.is_stale:
            conditional_reasons.append("QUOTA_STALE_OR_UNKNOWN" if eff_quota.is_stale else f"QUOTA_{q_state.value}")
            notes.append(eff_quota.reason)
        elif q_state == QuotaState.LOW:
            notes.append("Quota is LOW; candidate remains eligible with advisory warning.")

        # 6. Capability check
        cap_score_sum = 0
        for dim in req_caps:
            eff_cap: EffectiveCapability = self.registry.get_effective_capability(
                acct.application_id, model_id, dim, as_of=as_of
            )
            for ref in eff_cap.evidence_refs:
                evidence_refs.add(ref)
            if eff_cap.status == CapabilityState.NOT_SUPPORTED:
                reasons.append(f"CAPABILITY_NOT_SUPPORTED_{dim.value}")
                notes.append(f"Capability {dim.value} is NOT_SUPPORTED ({eff_cap.notes}).")
            elif eff_cap.status == CapabilityState.UNKNOWN:
                unknown_reasons.append(
                    f"CAPABILITY_CONFLICT_{dim.value}" if eff_cap.conflict_detected else f"CAPABILITY_UNKNOWN_{dim.value}"
                )
                notes.append(f"Capability {dim.value} is UNKNOWN ({eff_cap.notes}).")
            elif task.risk == RouterTaskRisk.CRITICAL and eff_cap.status not in (
                CapabilityState.VERIFIED,
                CapabilityState.DOCUMENTED,
            ):
                reasons.append(f"CAPABILITY_INSUFFICIENT_FOR_CRITICAL_{dim.value}")
                notes.append(
                    f"CRITICAL task requires VERIFIED or DOCUMENTED {dim.value}; found {eff_cap.status.value}."
                )
            elif eff_cap.status in (CapabilityState.USER_REPORTED, CapabilityState.EXPERIMENTAL):
                conditional_reasons.append(f"CAPABILITY_{eff_cap.status.value}_{dim.value}")
                cap_score_sum += _CAPABILITY_RANK.get(eff_cap.status, 0)
            else:
                cap_score_sum += _CAPABILITY_RANK.get(eff_cap.status, 0)

        # 7. Effort check (strictly per-application and per-model; never assume XHIGH!)
        effort_prof = self.registry.get_effort_profile(
            acct.application_id, model_id, acct.account_context_id
        )
        selected_effort_str: str | None = None
        if effort_prof is None:
            if req_effort != NormalizedEffort.UNKNOWN:
                unknown_reasons.append("EFFORT_PROFILE_UNKNOWN")
                notes.append(f"No reasoning effort profile recorded for {acct.application_id}:{model_id}.")
        else:
            if effort_prof.managed_by_orchestrator and NormalizedEffort.FIXED_INTERNAL in effort_prof.supported_efforts:
                if req_effort in (NormalizedEffort.HIGH, NormalizedEffort.XHIGH, NormalizedEffort.MEDIUM, NormalizedEffort.LOW):
                    reasons.append("EFFORT_FIXED_INTERNAL_UNVERIFIED")
                    notes.append(
                        f"Model '{model_id}' is managed internally by an Orchestrator with FIXED_INTERNAL effort; "
                        f"cannot guarantee requested {req_effort.value} effort."
                    )
                else:
                    selected_effort_str = NormalizedEffort.FIXED_INTERNAL.value.lower()
            else:
                req_ord = _effort_order(req_effort)
                satisfying = [
                    e for e in effort_prof.supported_efforts
                    if _effort_order(e) >= req_ord and e not in (NormalizedEffort.UNKNOWN, NormalizedEffort.FIXED_INTERNAL)
                ]
                if not satisfying:
                    reasons.append("EFFORT_UNSUPPORTED")
                    notes.append(
                        f"Required effort {req_effort.value} not in supported efforts "
                        f"{[e.value for e in effort_prof.supported_efforts]}."
                    )
                else:
                    if policy.preferred_effort in satisfying:
                        selected_effort_str = policy.preferred_effort.value.lower()
                    else:
                        best_eff = sorted(satisfying, key=_effort_order)[-1]
                        selected_effort_str = best_eff.value.lower()

        # 8. Independent verifier check (Part 10.4)
        indep_checks: dict[str, Any] = {}
        if role == TaskRole.INDEPENDENT_VERIFIER:
            indep_ok, indep_failures, indep_checks = _evaluate_independence(
                primary_items=primary_items,
                verifier_app=acct.application_id,
                verifier_model=model_id,
                verifier_identity=ident,
                verifier_provider=provider,
                required_level=required_independence,
            )
            if not indep_ok:
                reasons.extend(indep_failures)
                notes.extend(indep_failures)

        # Finalize eligibility classification
        confirm_msg: str | None = None
        if reasons:
            eligibility = CandidateEligibility.REJECTED
            all_codes = tuple(dict.fromkeys(reasons + unknown_reasons + conditional_reasons))
        elif unknown_reasons:
            eligibility = CandidateEligibility.UNKNOWN
            all_codes = tuple(dict.fromkeys(unknown_reasons + conditional_reasons))
        elif conditional_reasons:
            eligibility = CandidateEligibility.CONDITIONAL
            all_codes = tuple(dict.fromkeys(conditional_reasons))
            confirm_msg = (
                f"Role {role.value} candidate {acct.application_id}:{model_id} (account {acct.account_context_id}) "
                f"is CONDITIONAL ({', '.join(all_codes)}); confirm entitlement/quota before dispatch."
            )
        else:
            eligibility = CandidateEligibility.ACCEPTED
            all_codes = ("ELIGIBLE",)
            notes.append("All entitlement, billing, capability, effort, and quota checks passed.")

        pref_app_bonus = 1 if acct.application_id in policy.preferred_applications else 0
        pref_model_bonus = 1 if model_id in policy.preferred_models else 0
        accepted_bonus = 1 if eligibility == CandidateEligibility.ACCEPTED else 0
        score = (
            accepted_bonus,
            _ENTITLEMENT_RANK.get(ent_state, 0),
            _QUOTA_RANK.get(q_state, 0),
            pref_model_bonus,
            pref_app_bonus,
            cap_score_sum,
            _effort_order(NormalizedEffort.parse(selected_effort_str)) if selected_effort_str else 0,
        )

        ev = CandidateEvaluation(
            role=role,
            application_id=acct.application_id,
            application_instance_id=acct.application_instance_id,
            account_context_id=acct.account_context_id,
            provider=provider,
            model_id=model_id,
            eligibility=eligibility,
            reason_codes=all_codes,
            explanation=" ".join(notes) if notes else "Evaluated.",
            entitlement_state=ent_state.value,
            quota_state=q_state.value,
            authentication_mode=acct.authentication_mode.value,
            selected_effort=selected_effort_str,
            score=score,
        )
        return ev, confirm_msg, indep_checks

    @staticmethod
    def _summarize_no_candidate_reason(role: TaskRole, evals: list[CandidateEvaluation]) -> str:
        role_evals = [e for e in evals if e.role == role]
        if not role_evals:
            return f"No candidate models registered for role {role.value}."
        codes: list[str] = []
        for e in role_evals:
            codes.extend(e.reason_codes)
        unique_codes = ", ".join(dict.fromkeys(codes))
        return f"No eligible candidate for {role.value}; all {len(role_evals)} candidate(s) excluded ({unique_codes})."

    @staticmethod
    def _determine_overall_status(
        *,
        role_assignments: dict[str, RoleAssignment],
        all_evaluations: list[CandidateEvaluation],
        require_verifier: bool,
        verifier_independence: dict[str, Any],
    ) -> RoutePlanStatus:
        if require_verifier and not verifier_independence.get("satisfied", False):
            return RoutePlanStatus.BLOCKED_INDEPENDENT_VERIFIER

        blocked_roles = [r for r in role_assignments.values() if r.eligibility == "BLOCKED"]
        if blocked_roles:
            billing_codes = {"API_BILLING_DISABLED", "COST_POLICY_DENIES_API_BILLING", "DENY_UNVERIFIED_BILLING"}
            codes: set[str] = set()
            billing_only_blocked_candidate = False
            for b in blocked_roles:
                for ev in all_evaluations:
                    if ev.role == b.role:
                        codes.update(ev.reason_codes)
                        ev_codes = set(ev.reason_codes)
                        if ev_codes and ev_codes.issubset(billing_codes):
                            billing_only_blocked_candidate = True
            if billing_only_blocked_candidate:
                return RoutePlanStatus.BLOCKED_BILLING_POLICY
            if codes & billing_codes and not (
                codes & {"BUNDLED_CATALOG_NOT_ENTITLEMENT", "ENTITLEMENT_QUOTA_EXHAUSTED", "ENTITLEMENT_POLICY_BLOCKED"}
            ):
                return RoutePlanStatus.BLOCKED_BILLING_POLICY
            if any(c.startswith(("CAPABILITY_", "EFFORT_")) for c in codes) and not any(
                c.startswith(("ENTITLEMENT_", "BUNDLED_CATALOG", "QUOTA_")) for c in codes
            ):
                return RoutePlanStatus.BLOCKED_CAPABILITY
            return RoutePlanStatus.BLOCKED_ENTITLEMENT

        if any(r.eligibility == "CONDITIONAL" for r in role_assignments.values()):
            return RoutePlanStatus.PROPOSED_CONDITIONAL

        return RoutePlanStatus.READY_FOR_USER_REVIEW

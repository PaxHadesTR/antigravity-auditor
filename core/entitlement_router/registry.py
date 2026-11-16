"""Unified Entitlement, Capability, Effort, Quota, and Policy Registry for NEXT-22B."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from entitlement_router.contracts import (
    AccountContextRecord,
    AccountScope,
    ApplicationInstanceRecord,
    AuthenticationMode,
    CapabilityDimension,
    CapabilityState,
    ConfidenceLevel,
    EntitlementState,
    ModelCapabilityEvidence,
    ModelEffortProfile,
    ModelEntitlementObservation,
    ModelIdentityRecord,
    NormalizedEffort,
    QuotaObservation,
    QuotaState,
    RoutePlan,
    SubscriptionSource,
    UserProfileRecord,
    UserRoutingPolicy,
    utc_now_iso,
)
from entitlement_router.privacy import sanitize_for_output, validate_opaque_id


@dataclass(frozen=True)
class EffectiveEntitlement:
    """Resolved current entitlement status for (account_context_id, model_id)."""

    state: EntitlementState
    observation: ModelEntitlementObservation | None
    is_stale: bool
    reason: str
    history_count: int


@dataclass(frozen=True)
class EffectiveQuota:
    """Resolved current quota status for (account_context_id, model_id)."""

    state: QuotaState
    observation: QuotaObservation | None
    is_stale: bool
    reason: str


@dataclass(frozen=True)
class EffectiveCapability:
    """Resolved capability status for one dimension of a model."""

    dimension: CapabilityDimension
    status: CapabilityState
    confidence: ConfidenceLevel
    conflict_detected: bool
    is_stale: bool
    evidence_refs: tuple[str, ...]
    notes: str


_CAPABILITY_PRIORITY: dict[CapabilityState, int] = {
    CapabilityState.VERIFIED: 5,
    CapabilityState.DOCUMENTED: 4,
    CapabilityState.USER_REPORTED: 3,
    CapabilityState.EXPERIMENTAL: 2,
    CapabilityState.UNKNOWN: 1,
    CapabilityState.NOT_SUPPORTED: 0,
}

_CONFIDENCE_PRIORITY: dict[ConfidenceLevel, int] = {
    ConfidenceLevel.HIGH: 4,
    ConfidenceLevel.MEDIUM: 3,
    ConfidenceLevel.LOW: 2,
    ConfidenceLevel.UNVERIFIED: 1,
    ConfidenceLevel.UNKNOWN: 0,
}


class EntitlementRegistry:
    """In-memory + SQLite-serializable registry for user-aware entitlements, capabilities, efforts, and quotas."""

    def __init__(self) -> None:
        self.users: dict[str, UserProfileRecord] = {}
        self.applications: dict[str, ApplicationInstanceRecord] = {}
        self.accounts: dict[str, AccountContextRecord] = {}
        self.entitlement_history: list[ModelEntitlementObservation] = []
        self.quota_history: list[QuotaObservation] = []
        self.model_identities: dict[tuple[str, str], ModelIdentityRecord] = {}
        self.capability_evidence: list[ModelCapabilityEvidence] = []
        self.effort_profiles: dict[tuple[str, str, str | None], ModelEffortProfile] = {}
        self.policies: dict[str, UserRoutingPolicy] = {}
        self.decisions: dict[str, RoutePlan] = {}

    # ------------------------------------------------------------------
    # Registration helpers
    # ------------------------------------------------------------------

    def register_user(self, user: UserProfileRecord) -> UserProfileRecord:
        self.users[user.user_profile_id] = user
        return user

    def register_application(self, app: ApplicationInstanceRecord) -> ApplicationInstanceRecord:
        if app.user_profile_id not in self.users:
            self.register_user(UserProfileRecord(user_profile_id=app.user_profile_id))
        self.applications[app.application_instance_id] = app
        return app

    def register_account(self, account: AccountContextRecord) -> AccountContextRecord:
        if account.user_profile_id not in self.users:
            self.register_user(UserProfileRecord(user_profile_id=account.user_profile_id))
        if account.application_instance_id not in self.applications:
            raise ValueError(
                f"Unknown application_instance_id '{account.application_instance_id}' for account '{account.account_context_id}'."
            )
        self.accounts[account.account_context_id] = account
        return account

    def record_entitlement(self, obs: ModelEntitlementObservation) -> ModelEntitlementObservation:
        """Append an entitlement observation without overwriting historical records."""
        if obs.account_context_id not in self.accounts:
            raise ValueError(f"Unknown account_context_id '{obs.account_context_id}'.")
        self.entitlement_history.append(obs)
        return obs

    def record_quota(self, obs: QuotaObservation) -> QuotaObservation:
        """Append a quota observation without overwriting historical records."""
        if obs.account_context_id not in self.accounts:
            raise ValueError(f"Unknown account_context_id '{obs.account_context_id}'.")
        self.quota_history.append(obs)
        return obs

    def register_model_identity(self, identity: ModelIdentityRecord) -> ModelIdentityRecord:
        key = (identity.application_id, identity.application_model_id)
        self.model_identities[key] = identity
        return identity

    def record_capability_evidence(self, ev: ModelCapabilityEvidence) -> ModelCapabilityEvidence:
        self.capability_evidence.append(ev)
        return ev

    def register_effort_profile(self, profile: ModelEffortProfile) -> ModelEffortProfile:
        key = (profile.application_id, profile.application_model_id, profile.account_context_id)
        self.effort_profiles[key] = profile
        return profile

    def set_policy(self, policy: UserRoutingPolicy) -> UserRoutingPolicy:
        if policy.user_profile_id not in self.users:
            self.register_user(UserProfileRecord(user_profile_id=policy.user_profile_id))
        self.policies[policy.user_profile_id] = policy
        return policy

    def get_policy(self, user_profile_id: str) -> UserRoutingPolicy:
        if user_profile_id in self.policies:
            return self.policies[user_profile_id]
        return UserRoutingPolicy(
            policy_id=f"pol-default-{user_profile_id}",
            user_profile_id=user_profile_id,
        )

    def save_decision(self, plan: RoutePlan) -> RoutePlan:
        self.decisions[plan.decision_id] = plan
        return plan

    # ------------------------------------------------------------------
    # Resolution queries (pure, deterministic, staleness-aware)
    # ------------------------------------------------------------------

    def get_user_accounts(self, user_profile_id: str) -> list[AccountContextRecord]:
        return sorted(
            [a for a in self.accounts.values() if a.user_profile_id == user_profile_id],
            key=lambda a: (a.application_id, a.account_context_id),
        )

    def get_entitlement_history(
        self,
        account_context_id: str,
        model_id: str | None = None,
    ) -> list[ModelEntitlementObservation]:
        return [
            o
            for o in self.entitlement_history
            if o.account_context_id == account_context_id
            and (model_id is None or o.model_id == model_id)
        ]

    def list_models_for_account(self, account_context_id: str) -> list[str]:
        models = {
            o.model_id
            for o in self.entitlement_history
            if o.account_context_id == account_context_id
        }
        return sorted(models)

    def get_effective_entitlement(
        self,
        account_context_id: str,
        model_id: str,
        *,
        as_of: datetime | None = None,
    ) -> EffectiveEntitlement:
        matches = self.get_entitlement_history(account_context_id, model_id=model_id)
        if not matches:
            return EffectiveEntitlement(
                state=EntitlementState.UNKNOWN,
                observation=None,
                is_stale=False,
                reason="No entitlement observation recorded for this account and model.",
                history_count=0,
            )
        latest = sorted(matches, key=lambda o: (o.observed_at, o.observation_id))[-1]
        if latest.is_stale(as_of=as_of):
            return EffectiveEntitlement(
                state=EntitlementState.UNKNOWN,
                observation=latest,
                is_stale=True,
                reason=(
                    f"Latest entitlement observation ({latest.state.value}) expired at "
                    f"{latest.expires_at}; stale observation is not treated as current access."
                ),
                history_count=len(matches),
            )
        return EffectiveEntitlement(
            state=latest.state,
            observation=latest,
            is_stale=False,
            reason=f"Effective state {latest.state.value} from provenance {latest.provenance}.",
            history_count=len(matches),
        )

    def get_effective_quota(
        self,
        account_context_id: str,
        model_id: str | None = None,
        *,
        as_of: datetime | None = None,
    ) -> EffectiveQuota:
        model_matches = [
            q
            for q in self.quota_history
            if q.account_context_id == account_context_id and q.model_id == model_id
        ]
        acct_matches = [
            q
            for q in self.quota_history
            if q.account_context_id == account_context_id and q.model_id is None
        ]
        candidates = model_matches or acct_matches
        if not candidates:
            return EffectiveQuota(
                state=QuotaState.UNKNOWN,
                observation=None,
                is_stale=False,
                reason="No quota observation recorded; unknown quota is never assumed available.",
            )
        latest = sorted(candidates, key=lambda q: (q.observed_at, q.observation_id))[-1]
        if latest.is_stale(as_of=as_of):
            return EffectiveQuota(
                state=QuotaState.UNKNOWN,
                observation=latest,
                is_stale=True,
                reason=(
                    f"Latest quota observation ({latest.quota_state.value}) expired at "
                    f"{latest.expires_at}; stale quota is not current availability."
                ),
            )
        return EffectiveQuota(
            state=latest.quota_state,
            observation=latest,
            is_stale=False,
            reason=f"Quota state {latest.quota_state.value} observed via {latest.source}.",
        )

    def get_effective_capability(
        self,
        application_id: str,
        model_id: str,
        dimension: CapabilityDimension,
        *,
        as_of: datetime | None = None,
    ) -> EffectiveCapability:
        all_ev = [
            ev
            for ev in self.capability_evidence
            if ev.application_id == application_id
            and ev.application_model_id == model_id
            and ev.dimension == dimension
        ]
        if not all_ev:
            return EffectiveCapability(
                dimension=dimension,
                status=CapabilityState.UNKNOWN,
                confidence=ConfidenceLevel.UNKNOWN,
                conflict_detected=False,
                is_stale=False,
                evidence_refs=(),
                notes="No capability evidence recorded for this dimension.",
            )

        active = [ev for ev in all_ev if not ev.is_stale(as_of=as_of)]
        if not active:
            return EffectiveCapability(
                dimension=dimension,
                status=CapabilityState.UNKNOWN,
                confidence=ConfidenceLevel.UNKNOWN,
                conflict_detected=False,
                is_stale=True,
                evidence_refs=tuple(ev.evidence_id for ev in all_ev),
                notes="All capability evidence for this dimension has expired (stale).",
            )

        # Filter to latest model_version if multiple versions exist in evidence
        versions = [ev.model_version for ev in active if ev.model_version]
        if versions:
            latest_ver_ev = sorted(active, key=lambda ev: (ev.observed_at, ev.evidence_id))[-1]
            if latest_ver_ev.model_version:
                version_scoped = [
                    ev for ev in active if ev.model_version == latest_ver_ev.model_version
                ]
                if version_scoped:
                    active = version_scoped

        statuses = {ev.status for ev in active if ev.status != CapabilityState.UNKNOWN}
        has_not_supported = CapabilityState.NOT_SUPPORTED in statuses
        has_positive = bool(
            statuses
            & {
                CapabilityState.VERIFIED,
                CapabilityState.DOCUMENTED,
                CapabilityState.USER_REPORTED,
                CapabilityState.EXPERIMENTAL,
            }
        )
        refs = tuple(sorted({ev.evidence_id for ev in active}))

        if has_not_supported and has_positive:
            # Conflicting evidence: fail closed conservatively
            return EffectiveCapability(
                dimension=dimension,
                status=CapabilityState.UNKNOWN,
                confidence=ConfidenceLevel.LOW,
                conflict_detected=True,
                is_stale=False,
                evidence_refs=refs,
                notes="Conflicting capability evidence (both supported and NOT_SUPPORTED claims present).",
            )

        if has_not_supported:
            best_ns = sorted(
                [ev for ev in active if ev.status == CapabilityState.NOT_SUPPORTED],
                key=lambda ev: (_CONFIDENCE_PRIORITY[ev.confidence], ev.observed_at),
            )[-1]
            return EffectiveCapability(
                dimension=dimension,
                status=CapabilityState.NOT_SUPPORTED,
                confidence=best_ns.confidence,
                conflict_detected=False,
                is_stale=False,
                evidence_refs=refs,
                notes=best_ns.notes or "Capability marked NOT_SUPPORTED.",
            )

        best = sorted(
            active,
            key=lambda ev: (
                _CAPABILITY_PRIORITY[ev.status],
                _CONFIDENCE_PRIORITY[ev.confidence],
                ev.observed_at,
            ),
        )[-1]
        return EffectiveCapability(
            dimension=dimension,
            status=best.status,
            confidence=best.confidence,
            conflict_detected=False,
            is_stale=False,
            evidence_refs=refs,
            notes=best.notes or f"Capability {best.status.value} via {best.evidence_source}.",
        )

    def get_effort_profile(
        self,
        application_id: str,
        model_id: str,
        account_context_id: str | None = None,
    ) -> ModelEffortProfile | None:
        if account_context_id and (application_id, model_id, account_context_id) in self.effort_profiles:
            return self.effort_profiles[(application_id, model_id, account_context_id)]
        return self.effort_profiles.get((application_id, model_id, None))

    # ------------------------------------------------------------------
    # SQLite persistence (Migration 006 tables)
    # ------------------------------------------------------------------

    def persist_to_db(self, conn: sqlite3.Connection) -> None:
        """Persist current registry state into SQLite Migration 006 tables inside caller transaction or connection."""
        for u in self.users.values():
            conn.execute(
                """INSERT INTO account_profiles (user_profile_id, label, created_at, updated_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(user_profile_id) DO UPDATE SET
                       label=excluded.label,
                       updated_at=excluded.updated_at""",
                (u.user_profile_id, u.label, u.created_at, utc_now_iso()),
            )

        for app in self.applications.values():
            conn.execute(
                """INSERT INTO application_instances (
                       application_instance_id, user_profile_id, application_id,
                       installation_state, packaging_mode, version, executable_basename,
                       evidence_ref, observed_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(application_instance_id) DO UPDATE SET
                       installation_state=excluded.installation_state,
                       packaging_mode=excluded.packaging_mode,
                       version=excluded.version,
                       executable_basename=excluded.executable_basename,
                       evidence_ref=excluded.evidence_ref,
                       observed_at=excluded.observed_at""",
                (
                    app.application_instance_id,
                    app.user_profile_id,
                    app.application_id,
                    app.installation_state,
                    app.packaging_mode,
                    app.version,
                    app.executable_basename,
                    app.evidence_ref,
                    app.observed_at,
                ),
            )

        for acct in self.accounts.values():
            meta = json.dumps(
                sanitize_for_output(
                    {
                        "workspace_allowed_models": list(acct.workspace_allowed_models),
                        "workspace_blocked_models": list(acct.workspace_blocked_models),
                    }
                ),
                ensure_ascii=False,
                sort_keys=True,
            )
            conn.execute(
                """INSERT INTO application_account_contexts (
                       account_context_id, user_profile_id, application_instance_id, application_id,
                       provider, authentication_mode, account_scope, workspace_scope,
                       subscription_tier, subscription_source, entitlement_state,
                       metadata_json, observed_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(account_context_id) DO UPDATE SET
                       authentication_mode=excluded.authentication_mode,
                       account_scope=excluded.account_scope,
                       workspace_scope=excluded.workspace_scope,
                       subscription_tier=excluded.subscription_tier,
                       subscription_source=excluded.subscription_source,
                       entitlement_state=excluded.entitlement_state,
                       metadata_json=excluded.metadata_json,
                       observed_at=excluded.observed_at,
                       updated_at=excluded.updated_at""",
                (
                    acct.account_context_id,
                    acct.user_profile_id,
                    acct.application_instance_id,
                    acct.application_id,
                    acct.provider,
                    acct.authentication_mode.value,
                    acct.account_scope.value,
                    acct.workspace_scope,
                    acct.subscription_tier,
                    acct.subscription_source.value,
                    acct.entitlement_state.value,
                    meta,
                    acct.observed_at,
                    utc_now_iso(),
                ),
            )

        for obs in self.entitlement_history:
            conn.execute(
                """INSERT OR IGNORE INTO model_entitlement_observations (
                       observation_id, account_context_id, application_instance_id, application_id,
                       model_id, entitlement_state, provenance, confidence,
                       evidence_ref, notes, observed_at, expires_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    obs.observation_id,
                    obs.account_context_id,
                    obs.application_instance_id,
                    obs.application_id,
                    obs.model_id,
                    obs.state.value,
                    obs.provenance,
                    obs.confidence.value,
                    obs.evidence_ref,
                    obs.notes,
                    obs.observed_at,
                    obs.expires_at,
                ),
            )

        profile_ids: dict[tuple[str, str], str] = {}
        for (app_id, model_id), ident in self.model_identities.items():
            prof_id = f"cap-{app_id}-{model_id}"[:95]
            profile_ids[(app_id, model_id)] = prof_id
            conn.execute(
                """INSERT INTO model_capability_profiles (
                       capability_profile_id, application_id, application_model_id, provider,
                       canonical_model_id, model_version, model_family, variant,
                       reasoning_effort_variant, is_orchestrator_wrapper, orchestrator_wrapper_identity,
                       updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(application_id, application_model_id) DO UPDATE SET
                       provider=excluded.provider,
                       canonical_model_id=excluded.canonical_model_id,
                       model_version=excluded.model_version,
                       model_family=excluded.model_family,
                       variant=excluded.variant,
                       reasoning_effort_variant=excluded.reasoning_effort_variant,
                       is_orchestrator_wrapper=excluded.is_orchestrator_wrapper,
                       orchestrator_wrapper_identity=excluded.orchestrator_wrapper_identity,
                       updated_at=excluded.updated_at""",
                (
                    prof_id,
                    ident.application_id,
                    ident.application_model_id,
                    ident.provider,
                    ident.canonical_model_id,
                    ident.model_version,
                    ident.model_family,
                    ident.variant,
                    ident.reasoning_effort_variant,
                    1 if ident.is_orchestrator_wrapper else 0,
                    ident.orchestrator_wrapper_identity,
                    utc_now_iso(),
                ),
            )

        for ev in self.capability_evidence:
            key = (ev.application_id, ev.application_model_id)
            if key not in profile_ids:
                ident = ModelIdentityRecord(
                    application_id=ev.application_id,
                    application_model_id=ev.application_model_id,
                )
                self.register_model_identity(ident)
                prof_id = f"cap-{ev.application_id}-{ev.application_model_id}"[:95]
                profile_ids[key] = prof_id
                conn.execute(
                    """INSERT OR IGNORE INTO model_capability_profiles (
                           capability_profile_id, application_id, application_model_id, provider,
                           model_family, updated_at
                       ) VALUES (?, ?, ?, 'unknown', 'UNKNOWN', ?)""",
                    (prof_id, ev.application_id, ev.application_model_id, utc_now_iso()),
                )
            else:
                prof_id = profile_ids[key]

            conn.execute(
                """INSERT OR IGNORE INTO model_capability_evidence (
                       evidence_row_id, capability_profile_id, dimension, status,
                       evidence_source, confidence, model_version, evidence_ref,
                       notes, observed_at, expires_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ev.evidence_id,
                    prof_id,
                    ev.dimension.value,
                    ev.status.value,
                    ev.evidence_source,
                    ev.confidence.value,
                    ev.model_version,
                    ev.evidence_ref,
                    ev.notes,
                    ev.observed_at,
                    ev.expires_at,
                ),
            )

        for ep in self.effort_profiles.values():
            ep_id = f"eff-{ep.application_id}-{ep.application_model_id}-{ep.account_context_id or 'global'}"[:95]
            conn.execute(
                """INSERT INTO model_effort_profiles (
                       effort_profile_id, application_id, application_model_id, account_context_id,
                       supported_efforts_json, raw_supported_efforts_json, default_effort,
                       raw_default_effort, selected_effort, independently_configurable,
                       managed_by_orchestrator, orchestrator_structure_json, provenance,
                       evidence_ref, observed_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(effort_profile_id) DO UPDATE SET
                       supported_efforts_json=excluded.supported_efforts_json,
                       raw_supported_efforts_json=excluded.raw_supported_efforts_json,
                       default_effort=excluded.default_effort,
                       raw_default_effort=excluded.raw_default_effort,
                       selected_effort=excluded.selected_effort,
                       independently_configurable=excluded.independently_configurable,
                       managed_by_orchestrator=excluded.managed_by_orchestrator,
                       orchestrator_structure_json=excluded.orchestrator_structure_json,
                       provenance=excluded.provenance,
                       evidence_ref=excluded.evidence_ref,
                       observed_at=excluded.observed_at""",
                (
                    ep_id,
                    ep.application_id,
                    ep.application_model_id,
                    ep.account_context_id,
                    json.dumps([e.value for e in ep.supported_efforts]),
                    json.dumps(list(ep.raw_supported_efforts)),
                    ep.default_effort.value,
                    ep.raw_default_effort,
                    ep.selected_effort.value if ep.selected_effort else None,
                    1 if ep.independently_configurable else 0,
                    1 if ep.managed_by_orchestrator else 0,
                    json.dumps(ep.orchestrator_structure) if ep.orchestrator_structure else None,
                    ep.provenance,
                    ep.evidence_ref,
                    ep.observed_at,
                ),
            )

        for q in self.quota_history:
            conn.execute(
                """INSERT OR IGNORE INTO quota_observations (
                       quota_observation_id, account_context_id, model_id, usage_category,
                       quota_state, remaining_quantity, remaining_percentage, reset_at,
                       rate_limited, source, evidence_ref, observed_at, expires_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    q.observation_id,
                    q.account_context_id,
                    q.model_id,
                    q.usage_category,
                    q.quota_state.value,
                    q.remaining_quantity,
                    q.remaining_percentage,
                    q.reset_at,
                    1 if q.rate_limited else 0,
                    q.source,
                    q.evidence_ref,
                    q.observed_at,
                    q.expires_at,
                ),
            )

        for pol in self.policies.values():
            conn.execute(
                """INSERT INTO user_routing_preferences (
                       policy_id, user_profile_id, policy_json, schema_version, updated_at
                   ) VALUES (?, ?, ?, '1.0.0', ?)
                   ON CONFLICT(user_profile_id) DO UPDATE SET
                       policy_id=excluded.policy_id,
                       policy_json=excluded.policy_json,
                       updated_at=excluded.updated_at""",
                (
                    pol.policy_id,
                    pol.user_profile_id,
                    json.dumps(pol.to_dict(), ensure_ascii=False, sort_keys=True),
                    utc_now_iso(),
                ),
            )

        for dec in self.decisions.values():
            dec_dict = dec.to_dict()
            conn.execute(
                """INSERT INTO routing_decisions (
                       decision_id, user_profile_id, task_profile_id, risk, status, plan_json, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(decision_id) DO NOTHING""",
                (
                    dec.decision_id,
                    dec.user_profile_id,
                    dec.task_profile_id,
                    dec.risk,
                    dec.status.value,
                    json.dumps(dec_dict, ensure_ascii=False, sort_keys=True),
                    dec.created_at,
                ),
            )
            existing_exp = conn.execute(
                "SELECT 1 FROM routing_candidate_explanations WHERE decision_id = ? LIMIT 1",
                (dec.decision_id,),
            ).fetchone()
            if not existing_exp:
                for ev in dec.candidate_evaluations:
                    conn.execute(
                        """INSERT INTO routing_candidate_explanations (
                               decision_id, role, application_id, account_context_id, model_id,
                               eligibility, reason_codes_json, explanation_text, details_json
                           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            dec.decision_id,
                            ev.role.value,
                            ev.application_id,
                            ev.account_context_id,
                            ev.model_id,
                            ev.eligibility.value,
                            json.dumps(list(ev.reason_codes)),
                            ev.explanation,
                            json.dumps(ev.to_dict(), ensure_ascii=False, sort_keys=True),
                        ),
                    )

    @classmethod
    def load_from_db(cls, conn: sqlite3.Connection) -> EntitlementRegistry:
        """Hydrate an EntitlementRegistry from SQLite Migration 006 tables (read-only safe)."""
        reg = cls()
        for r in conn.execute("SELECT * FROM account_profiles").fetchall():
            reg.register_user(
                UserProfileRecord(
                    user_profile_id=str(r["user_profile_id"]),
                    label=r["label"],
                    created_at=str(r["created_at"]),
                )
            )
        for r in conn.execute("SELECT * FROM application_instances").fetchall():
            reg.register_application(
                ApplicationInstanceRecord(
                    application_instance_id=str(r["application_instance_id"]),
                    user_profile_id=str(r["user_profile_id"]),
                    application_id=str(r["application_id"]),
                    installation_state=str(r["installation_state"]),
                    packaging_mode=str(r["packaging_mode"]),
                    version=r["version"],
                    executable_basename=r["executable_basename"],
                    evidence_ref=r["evidence_ref"],
                    observed_at=str(r["observed_at"]),
                )
            )
        for r in conn.execute("SELECT * FROM application_account_contexts").fetchall():
            meta = json.loads(r["metadata_json"] or "{}")
            reg.register_account(
                AccountContextRecord(
                    account_context_id=str(r["account_context_id"]),
                    user_profile_id=str(r["user_profile_id"]),
                    application_instance_id=str(r["application_instance_id"]),
                    application_id=str(r["application_id"]),
                    provider=str(r["provider"]),
                    authentication_mode=AuthenticationMode.parse(r["authentication_mode"]),
                    account_scope=AccountScope.parse(r["account_scope"]),
                    workspace_scope=r["workspace_scope"],
                    subscription_tier=r["subscription_tier"],
                    subscription_source=SubscriptionSource.parse(r["subscription_source"]),
                    entitlement_state=EntitlementState.parse(r["entitlement_state"]),
                    workspace_allowed_models=tuple(meta.get("workspace_allowed_models") or ()),
                    workspace_blocked_models=tuple(meta.get("workspace_blocked_models") or ()),
                    observed_at=r["observed_at"],
                )
            )
        for r in conn.execute("SELECT * FROM model_entitlement_observations ORDER BY observed_at ASC").fetchall():
            reg.record_entitlement(
                ModelEntitlementObservation(
                    observation_id=str(r["observation_id"]),
                    account_context_id=str(r["account_context_id"]),
                    application_instance_id=str(r["application_instance_id"]),
                    application_id=str(r["application_id"]),
                    model_id=str(r["model_id"]),
                    state=EntitlementState.parse(r["entitlement_state"]),
                    provenance=str(r["provenance"]),
                    confidence=ConfidenceLevel.parse(r["confidence"]),
                    observed_at=str(r["observed_at"]),
                    expires_at=r["expires_at"],
                    evidence_ref=str(r["evidence_ref"]),
                    notes=r["notes"],
                )
            )
        prof_map: dict[str, tuple[str, str]] = {}
        for r in conn.execute("SELECT * FROM model_capability_profiles").fetchall():
            app_id = str(r["application_id"])
            m_id = str(r["application_model_id"])
            prof_map[str(r["capability_profile_id"])] = (app_id, m_id)
            reg.register_model_identity(
                ModelIdentityRecord(
                    application_id=app_id,
                    application_model_id=m_id,
                    provider=str(r["provider"]),
                    canonical_model_id=r["canonical_model_id"],
                    model_version=r["model_version"],
                    model_family=str(r["model_family"]),
                    variant=r["variant"],
                    reasoning_effort_variant=r["reasoning_effort_variant"],
                    is_orchestrator_wrapper=bool(r["is_orchestrator_wrapper"]),
                    orchestrator_wrapper_identity=r["orchestrator_wrapper_identity"],
                )
            )
        for r in conn.execute("SELECT * FROM model_capability_evidence ORDER BY observed_at ASC").fetchall():
            app_id, m_id = prof_map[str(r["capability_profile_id"])]
            reg.record_capability_evidence(
                ModelCapabilityEvidence(
                    evidence_id=str(r["evidence_row_id"]),
                    application_id=app_id,
                    application_model_id=m_id,
                    dimension=CapabilityDimension.parse(r["dimension"]),
                    status=CapabilityState.parse(r["status"]),
                    evidence_source=str(r["evidence_source"]),
                    confidence=ConfidenceLevel.parse(r["confidence"]),
                    observed_at=str(r["observed_at"]),
                    expires_at=r["expires_at"],
                    model_version=r["model_version"],
                    evidence_ref=r["evidence_ref"],
                    notes=r["notes"],
                )
            )
        for r in conn.execute("SELECT * FROM model_effort_profiles").fetchall():
            sup = tuple(NormalizedEffort.parse(x) for x in json.loads(r["supported_efforts_json"] or "[]"))
            raw_sup = tuple(str(x) for x in json.loads(r["raw_supported_efforts_json"] or "[]"))
            orch_struct = json.loads(r["orchestrator_structure_json"]) if r["orchestrator_structure_json"] else None
            reg.register_effort_profile(
                ModelEffortProfile(
                    application_id=str(r["application_id"]),
                    application_model_id=str(r["application_model_id"]),
                    account_context_id=r["account_context_id"],
                    supported_efforts=sup,
                    raw_supported_efforts=raw_sup,
                    default_effort=NormalizedEffort.parse(r["default_effort"]),
                    raw_default_effort=r["raw_default_effort"],
                    selected_effort=NormalizedEffort.parse(r["selected_effort"]) if r["selected_effort"] else None,
                    independently_configurable=bool(r["independently_configurable"]),
                    managed_by_orchestrator=bool(r["managed_by_orchestrator"]),
                    orchestrator_structure=orch_struct,
                    provenance=str(r["provenance"]),
                    evidence_ref=r["evidence_ref"],
                    observed_at=str(r["observed_at"]),
                )
            )
        for r in conn.execute("SELECT * FROM quota_observations ORDER BY observed_at ASC").fetchall():
            reg.record_quota(
                QuotaObservation(
                    observation_id=str(r["quota_observation_id"]),
                    account_context_id=str(r["account_context_id"]),
                    model_id=r["model_id"],
                    usage_category=str(r["usage_category"]),
                    quota_state=QuotaState.parse(r["quota_state"]),
                    remaining_quantity=r["remaining_quantity"],
                    remaining_percentage=r["remaining_percentage"],
                    reset_at=r["reset_at"],
                    rate_limited=bool(r["rate_limited"]),
                    observed_at=str(r["observed_at"]),
                    expires_at=r["expires_at"],
                    source=str(r["source"]),
                    evidence_ref=str(r["evidence_ref"]),
                )
            )
        for r in conn.execute("SELECT * FROM user_routing_preferences").fetchall():
            pol_data = json.loads(r["policy_json"])
            reg.set_policy(UserRoutingPolicy.from_dict(pol_data))
        return reg

    def export_account_model_matrix(self, user_profile_id: str, *, as_of: datetime | None = None) -> dict[str, Any]:
        """Build a clean per-account model access matrix with explicit provenance and quota."""
        accounts_out: list[dict[str, Any]] = []
        for acct in self.get_user_accounts(user_profile_id):
            app = self.applications.get(acct.application_instance_id)
            models_out: list[dict[str, Any]] = []
            for model_id in self.list_models_for_account(acct.account_context_id):
                eff_ent = self.get_effective_entitlement(acct.account_context_id, model_id, as_of=as_of)
                eff_quota = self.get_effective_quota(acct.account_context_id, model_id, as_of=as_of)
                effort_prof = self.get_effort_profile(acct.application_id, model_id, acct.account_context_id)
                ident = self.model_identities.get((acct.application_id, model_id))
                models_out.append(
                    {
                        "model_id": model_id,
                        "provider": ident.provider if ident else acct.provider,
                        "model_family": ident.model_family if ident else "UNKNOWN",
                        "is_orchestrator_wrapper": ident.is_orchestrator_wrapper if ident else False,
                        "effective_entitlement_state": eff_ent.state.value,
                        "entitlement_stale": eff_ent.is_stale,
                        "entitlement_provenance": eff_ent.observation.provenance if eff_ent.observation else "UNKNOWN",
                        "entitlement_evidence_ref": eff_ent.observation.evidence_ref if eff_ent.observation else None,
                        "observed_at": eff_ent.observation.observed_at if eff_ent.observation else None,
                        "history_count": eff_ent.history_count,
                        "quota_state": eff_quota.state.value,
                        "quota_stale": eff_quota.is_stale,
                        "supported_efforts": (
                            [e.value for e in effort_prof.supported_efforts] if effort_prof else ["UNKNOWN"]
                        ),
                    }
                )
            accounts_out.append(
                {
                    "account": acct.to_dict(),
                    "application_installation_state": app.installation_state if app else "unknown",
                    "application_version": app.version if app else None,
                    "models": models_out,
                }
            )
        return sanitize_for_output(
            {
                "user_profile_id": user_profile_id,
                "account_count": len(accounts_out),
                "accounts": accounts_out,
            }
        )

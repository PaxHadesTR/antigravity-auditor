"""Antigravity Auditor — Deterministic Task-Based Model Routing Policy Engine.

``route_model`` deterministically assigns every task a *routing tier* (ENTRY / STANDARD /
CRITICAL / CATASTROPHIC); the concrete model for a tier comes from the active, validated
routing table in ``model_registry`` (host/backend aware, hard-policy checked).

Policy invariants (unchanged by the routing table):
- LLMs must not choose their own models; tiers come from controller metadata only.
- Unvalidated evidence cannot authorize CRITICAL/CATASTROPHIC tiers (BLOCKED_EVIDENCE).
- No silent fallback: a tier whose model is unavailable or disallowed blocks the dispatch.
- Model independence requires different model *lines*, independently attested; differing
  reasoning levels of one line do not qualify.
- Repair Worker writable dispatch remains hard-disabled.
- Host hard policy (model_registry.HARD_POLICIES): Antigravity -> Gemini only, Flash retired.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from model_registry import (
    RoutingTable,
    RoutingTableError,
    RoutingTier,
    get_active_routing_table,
    hard_policy_violation,
    is_approved_model,
    is_scarce_model,
    model_effort,
    model_slug,
    same_model_line,
    split_model_ref,
)


POLICY_VERSION = "3.0.0-tiered-model-policy"


class ModelId(str, Enum):
    """Well-known model identifiers of the seed routing table.

    NOT the allow-list: dispatchability is decided by ``model_registry`` (hard policy +
    active routing table). ``is_approved`` is kept for backward compatibility and delegates.
    """

    GEMINI_4_HYDROGEN_MEDIUM = "gemini-4-hydrogen-medium"
    GEMINI_4_HYDROGEN_HIGH = "gemini-4-hydrogen-high"
    GEMINI_4_ARGON_MEDIUM = "gemini-4-argon-medium"
    GEMINI_4_ARGON_HIGH = "gemini-4-argon-high"

    @classmethod
    def is_approved(cls, model_str: str | None, db_path: Any | None = None) -> bool:
        if not model_str or not isinstance(model_str, str):
            return False
        return is_approved_model(model_str, db_path=db_path)


class ModelRef(str):
    """A dispatchable model slug. ``.value`` mirrors ``Enum.value`` for existing callers."""

    @property
    def value(self) -> str:
        return str(self)


class ReasoningLevel(str, Enum):
    """Supported reasoning effort levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"


class TaskType(str, Enum):
    """Standardized auditor task categories."""

    PRIMARY_AUDIT = "PRIMARY_AUDIT"
    REPOSITORY_EXPLORATION = "REPOSITORY_EXPLORATION"
    FINDING_CLASSIFICATION = "FINDING_CLASSIFICATION"
    ROUTINE_VERIFICATION = "ROUTINE_VERIFICATION"
    CRITICAL_VERIFICATION = "CRITICAL_VERIFICATION"
    ROUTINE_RED_TEAM = "ROUTINE_RED_TEAM"
    CRITICAL_RED_TEAM = "CRITICAL_RED_TEAM"
    REPAIR_PLANNING = "REPAIR_PLANNING"
    REPAIR_WORKER = "REPAIR_WORKER"
    TEST_SCENARIO_GENERATION = "TEST_SCENARIO_GENERATION"
    TEST_FAILURE_ANALYSIS = "TEST_FAILURE_ANALYSIS"
    REPORT_GENERATION = "REPORT_GENERATION"


class TaskRisk(str, Enum):
    """Risk tiers for tasks and findings."""

    NORMAL = "NORMAL"
    CRITICAL = "CRITICAL"
    CATASTROPHIC = "CATASTROPHIC"


class ExecutionIntent(str, Enum):
    """Execution intent distinguishing preliminary reviews from mandatory verifications."""

    PRELIMINARY_ANALYSIS = "PRELIMINARY_ANALYSIS"
    ROUTINE_VERIFICATION = "ROUTINE_VERIFICATION"
    REQUIRED_CRITICAL_VERIFICATION = "REQUIRED_CRITICAL_VERIFICATION"


class RoutingStatus(str, Enum):
    """Explicit status outcomes of the model routing decision."""

    READY = "READY"
    BLOCKED_EVIDENCE = "BLOCKED_EVIDENCE"
    BLOCKED_BUDGET = "BLOCKED_BUDGET"
    BLOCKED_MODEL_UNAVAILABLE = "BLOCKED_MODEL_UNAVAILABLE"
    BLOCKED_ATTESTATION = "BLOCKED_ATTESTATION"


# Categories that qualify for Argon Medium when validated and severity is HIGH/CRITICAL
ARGON_MEDIUM_CATEGORIES = {
    "DATABASE_INTEGRITY",
    "CRITICAL_MIGRATION",
    "CONCURRENCY_RACE_CONDITION",
    "AUTHORIZATION_SECURITY",
    "ARCHITECTURE_DECISION",
    "CRITICAL_TECHNICAL_DECISION",
}

# Categories that qualify for Argon High when validated and severity is CRITICAL
ARGON_HIGH_CATEGORIES = {
    "RCE",
    "REMOTE_CODE_EXECUTION",
    "AUTHENTICATION_BYPASS",
    "PRIVILEGE_ESCALATION",
    "SEVERE_AUTHORIZATION_BYPASS",
    "CRITICAL_REMOTE_DATA_EXPOSURE",
    "CATASTROPHIC_DATA_LOSS",
}

# Lightweight tasks routed to the ENTRY tier
ENTRY_TIER_TASKS = {
    TaskType.FINDING_CLASSIFICATION,
}


@dataclass(frozen=True)
class ModelRoutingRequest:
    """Structured, controller-generated metadata for model selection."""

    task_type: TaskType | str
    severity: str = "MEDIUM"  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    finding_category: str | None = None
    evidence_gate_status: str = "UNCHECKED"  # PASSED | FAILED | UNCHECKED | PENDING
    confidence: str = "LIKELY"  # CONFIRMED | LIKELY | SPECULATIVE
    execution_intent: ExecutionIntent | str = ExecutionIntent.ROUTINE_VERIFICATION
    audit_run_id: str | None = None
    finding_fingerprint: str | None = None
    primary_model_attestation: str | None = None
    # Model of the primary audit being verified: a verifier on the same model line moves to another line.
    primary_model: str | None = None
    explicit_operator_escalation: bool = False
    operator_escalation_reason: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def normalized_task_type(self) -> TaskType:
        if isinstance(self.task_type, TaskType):
            return self.task_type
        name = str(self.task_type).strip().upper()
        try:
            return TaskType[name]
        except KeyError:
            return TaskType.ROUTINE_VERIFICATION

    def normalized_intent(self) -> ExecutionIntent:
        if isinstance(self.execution_intent, ExecutionIntent):
            return self.execution_intent
        name = str(self.execution_intent).strip().upper()
        try:
            return ExecutionIntent[name]
        except KeyError:
            return ExecutionIntent.ROUTINE_VERIFICATION


@dataclass(frozen=True)
class ModelRoutingDecision:
    """Deterministic routing outcome."""

    selected_model: ModelRef | None
    reasoning_level: ReasoningLevel
    task_type: TaskType
    task_risk: TaskRisk
    decision_reason: str
    is_argon: bool
    routing_status: RoutingStatus = RoutingStatus.READY
    is_blocked: bool = False
    blocked_reason: str | None = None
    is_cross_model_required: bool = False
    is_preliminary: bool = False
    policy_version: str = POLICY_VERSION
    repair_writable_dispatch_enabled: bool = False
    routing_tier: RoutingTier | None = None
    backend: str = "agy"
    routing_table_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "selected_model": self.selected_model.value if self.selected_model else None,
            "reasoning_level": self.reasoning_level.value,
            "task_type": self.task_type.value,
            "task_risk": self.task_risk.value,
            "routing_status": self.routing_status.value,
            "is_blocked": self.is_blocked,
            "blocked_reason": self.blocked_reason,
            "decision_reason": self.decision_reason,
            "is_argon": self.is_argon,
            "is_cross_model_required": self.is_cross_model_required,
            "is_preliminary": self.is_preliminary,
            "policy_version": self.policy_version,
            "repair_writable_dispatch_enabled": self.repair_writable_dispatch_enabled,
            "routing_tier": self.routing_tier.value if self.routing_tier else None,
            "backend": self.backend,
            "routing_table_version": self.routing_table_version,
        }


_EFFORT_TO_REASONING = {
    "low": ReasoningLevel.LOW,
    "ultra": ReasoningLevel.MAX,
    "medium": ReasoningLevel.MEDIUM,
    "high": ReasoningLevel.HIGH,
    "xhigh": ReasoningLevel.XHIGH,
    "max": ReasoningLevel.MAX,
}


def _tier_decision(
    table: RoutingTable,
    tier: RoutingTier,
    *,
    task: TaskType,
    task_risk: TaskRisk,
    decision_reason: str,
    routing_status: RoutingStatus = RoutingStatus.READY,
    is_blocked: bool = False,
    blocked_reason: str | None = None,
    is_cross_model_required: bool = False,
    is_preliminary: bool = False,
) -> ModelRoutingDecision:
    """Resolve ``tier`` through the routing table; ``{model}`` in reasons is replaced by the slug.

    Fails closed (BLOCKED_MODEL_UNAVAILABLE) if the assigned model violates hard policy - there
    is never a silent fallback to another tier or model.
    """
    model_ref = table.assignments.get(tier) or ""
    violation = hard_policy_violation(model_ref, table.host) if model_ref else f"No model assigned to tier {tier.value}."
    if violation:
        return ModelRoutingDecision(
            selected_model=None,
            reasoning_level=ReasoningLevel.HIGH,
            task_type=task,
            task_risk=task_risk,
            routing_status=RoutingStatus.BLOCKED_MODEL_UNAVAILABLE,
            is_blocked=True,
            blocked_reason=f"MODEL_POLICY_VIOLATION: {violation}",
            decision_reason=f"{tier.value} tier model '{model_ref}' is not dispatchable; no fallback is attempted.",
            is_argon=False,
            is_cross_model_required=is_cross_model_required,
            is_preliminary=is_preliminary,
            routing_tier=tier,
            routing_table_version=table.version,
        )
    backend, slug = split_model_ref(model_ref)
    reasoning = _EFFORT_TO_REASONING.get(model_effort(model_ref) or "", ReasoningLevel.HIGH)
    return ModelRoutingDecision(
        selected_model=ModelRef(slug),
        reasoning_level=reasoning,
        task_type=task,
        task_risk=task_risk,
        routing_status=routing_status,
        is_blocked=is_blocked,
        blocked_reason=blocked_reason.replace("{model}", slug) if blocked_reason is not None else None,
        decision_reason=decision_reason.replace("{model}", slug),
        is_argon=is_scarce_model(model_ref, table.host),
        is_cross_model_required=is_cross_model_required,
        is_preliminary=is_preliminary,
        repair_writable_dispatch_enabled=False,
        routing_tier=tier,
        backend=backend,
        routing_table_version=table.version,
    )


VERIFICATION_TASKS = frozenset({TaskType.ROUTINE_VERIFICATION, TaskType.CRITICAL_VERIFICATION})


def route_model(
    request: ModelRoutingRequest,
    *,
    routing_table: RoutingTable | None = None,
    db_path: Any | None = None,
) -> ModelRoutingDecision:
    """Route a task (see ``_route_by_task``), then keep a verifier off the primary auditor's model line."""
    decision = _route_by_task(request, routing_table=routing_table, db_path=db_path)
    return _independent_verifier(request, decision, routing_table=routing_table, db_path=db_path)


def _independent_verifier(
    request: ModelRoutingRequest,
    decision: ModelRoutingDecision,
    *,
    routing_table: RoutingTable | None,
    db_path: Any | None,
) -> ModelRoutingDecision:
    """A verifier on the primary auditor's model line shares its blind spots, so verification that routed to
    such a model (ENTRY/STANDARD; the primary audit runs on STANDARD) moves to the CRITICAL tier, which the
    routing table guarantees is a different model line than STANDARD.

    Deterministic and controller-side (the primary model comes from the audit run, never from an LLM). Blocked
    decisions stay blocked: this never bypasses the evidence gate. A scarce CRITICAL model (e.g. Argon) is
    only used for critical verification, never for routine verification. Otherwise the decision is unchanged
    and finalization records the run as same-model verification.
    """
    primary = (request.primary_model or "").strip()
    if (
        not primary
        or decision.is_blocked
        or decision.is_preliminary
        or decision.selected_model is None
        or decision.task_type not in VERIFICATION_TASKS
        or decision.routing_tier not in (RoutingTier.ENTRY, RoutingTier.STANDARD)
        or not same_model_line(decision.selected_model.value, primary)
    ):
        return decision
    try:
        table = routing_table or get_active_routing_table(db_path=db_path)
    except RoutingTableError:
        return decision
    target = table.assignments.get(RoutingTier.CRITICAL) or ""
    if not target or same_model_line(target, primary):
        return decision
    if is_scarce_model(target, table.host) and decision.task_type != TaskType.CRITICAL_VERIFICATION:
        return decision
    return _tier_decision(
        table, RoutingTier.CRITICAL, task=decision.task_type, task_risk=decision.task_risk,
        decision_reason=(
            f"{decision.decision_reason} That model shares the primary auditor's model line ({primary}), so the "
            "verifier runs on the CRITICAL tier ({model}), a different model line (cross-model independence)."
        ),
        is_cross_model_required=True,
    )


def _route_by_task(
    request: ModelRoutingRequest,
    *,
    routing_table: RoutingTable | None = None,
    db_path: Any | None = None,
) -> ModelRoutingDecision:
    """Deterministically route a task to a routing tier and the tier's approved model.

    Strict Invariants:
    1. Primary Audit, exploration, repair planning, routine red-team and routine verification use STANDARD.
    2. Lightweight classification uses ENTRY.
    3. Critical independent verification (validated evidence) uses CRITICAL.
    4. Exceptionally critical security / data-loss cases (validated evidence) use CATASTROPHIC.
    5. Unvalidated evidence CANNOT authorize CRITICAL/CATASTROPHIC; critical verification remains
       BLOCKED_EVIDENCE (preliminary analysis may run on STANDARD).
    6. LLM self-classification cannot escalate the tier.
    7. Operator escalation requires explicit programmatic authorization.
    8. Repair Worker writable dispatch remains hard-disabled.
    9. An unavailable/disallowed tier model blocks (BLOCKED_MODEL_UNAVAILABLE); no silent fallback.
    """
    task = request.normalized_task_type()
    intent = request.normalized_intent()
    sev = (request.severity or "").strip().upper()
    cat = (request.finding_category or "").strip().upper()
    gate_passed = (request.evidence_gate_status or "").strip().upper() == "PASSED"

    try:
        table = routing_table or get_active_routing_table(db_path=db_path)
    except RoutingTableError as exc:
        return ModelRoutingDecision(
            selected_model=None,
            reasoning_level=ReasoningLevel.HIGH,
            task_type=task,
            task_risk=TaskRisk.NORMAL,
            routing_status=RoutingStatus.BLOCKED_MODEL_UNAVAILABLE,
            is_blocked=True,
            blocked_reason=f"ROUTING_TABLE_UNAVAILABLE: {exc}",
            decision_reason="No valid routing table; dispatch blocked (fail closed).",
            is_argon=False,
        )

    # 1. Primary Audit and Repository Exploration
    if task in (TaskType.PRIMARY_AUDIT, TaskType.REPOSITORY_EXPLORATION):
        return _tier_decision(
            table, RoutingTier.STANDARD, task=task, task_risk=TaskRisk.NORMAL,
            decision_reason=f"{task.value} routes to the STANDARD tier ({{model}}).",
        )

    # 2. Repair Planning (read-only plan mode)
    if task == TaskType.REPAIR_PLANNING:
        return _tier_decision(
            table, RoutingTier.STANDARD, task=task, task_risk=TaskRisk.NORMAL,
            decision_reason="Repair planning routes to the STANDARD tier ({model}) in read-only plan mode.",
        )

    # 3. Repair Worker writable execution: hard-disabled
    if task == TaskType.REPAIR_WORKER:
        return _tier_decision(
            table, RoutingTier.STANDARD, task=task, task_risk=TaskRisk.CRITICAL,
            routing_status=RoutingStatus.BLOCKED_MODEL_UNAVAILABLE,
            is_blocked=True,
            blocked_reason="REPAIR_WORKER_WRITABLE_DISPATCH_DISABLED: Repair worker writable execution is disabled.",
            decision_reason="Repair Worker writable dispatch is hard-disabled.",
        )

    # 4. Lightweight classification
    if task in ENTRY_TIER_TASKS:
        return _tier_decision(
            table, RoutingTier.ENTRY, task=task, task_risk=TaskRisk.NORMAL,
            decision_reason="Lightweight classification tasks route to the ENTRY tier ({model}).",
        )

    # 5. Routine Red-Team
    if task == TaskType.ROUTINE_RED_TEAM:
        return _tier_decision(
            table, RoutingTier.STANDARD, task=task, task_risk=TaskRisk.NORMAL,
            decision_reason="Routine Red-Team audit routes to the STANDARD tier ({model}).",
        )

    # 6. Catastrophic security / data-loss candidates
    # Like the CRITICAL tier, only critical verification / red-team tasks (or explicit operator escalation)
    # may reach CATASTROPHIC; e.g. a report-generation task about an RCE finding stays on STANDARD.
    is_catastrophic_candidate = (
        (task in (TaskType.CRITICAL_VERIFICATION, TaskType.CRITICAL_RED_TEAM) or request.explicit_operator_escalation)
        and sev == "CRITICAL"
        and (cat in ARGON_HIGH_CATEGORIES or (request.explicit_operator_escalation and "ARGON_HIGH" in (request.operator_escalation_reason or "").upper()))
    )

    if is_catastrophic_candidate:
        if not gate_passed:
            is_prelim = (intent == ExecutionIntent.PRELIMINARY_ANALYSIS)
            return _tier_decision(
                table, RoutingTier.STANDARD, task=task, task_risk=TaskRisk.CRITICAL,
                routing_status=RoutingStatus.READY if is_prelim else RoutingStatus.BLOCKED_EVIDENCE,
                is_blocked=not is_prelim,
                blocked_reason=(
                    "" if is_prelim else
                    f"CATASTROPHIC tier verification blocked: deterministic Evidence Gate status is {request.evidence_gate_status} (must be PASSED). Routed to the STANDARD tier ({{model}}) for preliminary review only."
                ),
                decision_reason=(
                    f"Preliminary analysis for unvalidated candidate ({cat}) routed to the STANDARD tier ({{model}}). "
                    f"Cannot finalize or confirm critical finding without CATASTROPHIC-tier verification."
                    if is_prelim else
                    f"CATASTROPHIC tier candidate finding ({cat}) blocked because "
                    f"Evidence Gate status is {request.evidence_gate_status} (must be PASSED). "
                    f"Routed to the STANDARD tier ({{model}}) for preliminary review only (BLOCKED from critical verification)."
                ),
                is_cross_model_required=True,
                is_preliminary=True,
            )

        return _tier_decision(
            table, RoutingTier.CATASTROPHIC, task=task, task_risk=TaskRisk.CATASTROPHIC,
            decision_reason=(
                f"Exceptionally critical case ({cat}, severity={sev}, evidence_gate=PASSED) "
                f"authorized for the CATASTROPHIC tier ({{model}})."
            ),
            is_cross_model_required=True,
        )

    # 7. Critical independent verification & complex architecture / database decisions
    is_critical_candidate = (
        (task in (TaskType.CRITICAL_VERIFICATION, TaskType.CRITICAL_RED_TEAM) or request.explicit_operator_escalation)
        and (sev in ("CRITICAL", "HIGH") or request.explicit_operator_escalation)
        and (cat in ARGON_MEDIUM_CATEGORIES or request.explicit_operator_escalation)
    )

    if is_critical_candidate:
        if not gate_passed and not request.explicit_operator_escalation:
            is_prelim = (intent == ExecutionIntent.PRELIMINARY_ANALYSIS)
            return _tier_decision(
                table, RoutingTier.STANDARD, task=task, task_risk=TaskRisk.CRITICAL,
                routing_status=RoutingStatus.READY if is_prelim else RoutingStatus.BLOCKED_EVIDENCE,
                is_blocked=not is_prelim,
                blocked_reason=(
                    "" if is_prelim else
                    f"CRITICAL tier verification blocked: deterministic Evidence Gate status is {request.evidence_gate_status} (must be PASSED). Routed to the STANDARD tier ({{model}}) for preliminary review only."
                ),
                decision_reason=(
                    f"Preliminary analysis for unvalidated candidate ({cat}) routed to the STANDARD tier ({{model}}). "
                    f"Cannot finalize or confirm critical finding without CRITICAL-tier verification."
                    if is_prelim else
                    f"CRITICAL tier candidate finding ({cat}) blocked because "
                    f"Evidence Gate status is {request.evidence_gate_status} (must be PASSED). "
                    f"Routed to the STANDARD tier ({{model}}) for preliminary review only (BLOCKED from critical verification)."
                ),
                is_cross_model_required=True,
                is_preliminary=True,
            )

        reason = (
            f"Explicit operator escalation to the CRITICAL tier ({{model}}): {request.operator_escalation_reason}"
            if request.explicit_operator_escalation
            else f"Critical verification for category {cat} (severity={sev}, evidence_gate=PASSED) routed to the CRITICAL tier ({{model}})."
        )
        return _tier_decision(
            table, RoutingTier.CRITICAL, task=task, task_risk=TaskRisk.CRITICAL,
            decision_reason=reason,
            is_cross_model_required=True,
        )

    # 8. All other verification / general tasks
    return _tier_decision(
        table, RoutingTier.STANDARD, task=task, task_risk=TaskRisk.NORMAL,
        decision_reason="Standard verification routes to the STANDARD tier ({model}).",
    )

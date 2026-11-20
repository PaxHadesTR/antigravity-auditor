"""Second-pass verification must not run on the primary auditor's model line when the routing table offers
another line: routine/critical verification that routed to such a model moves to the CRITICAL tier."""

from __future__ import annotations

import sys
from pathlib import Path
from types import MappingProxyType

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import model_registry as reg  # noqa: E402
from agy_adapter import AntigravityCliAdapter  # noqa: E402
from model_policy import ExecutionIntent, ModelRoutingRequest, RoutingStatus, TaskType, route_model  # noqa: E402
from model_registry import RoutingTable, RoutingTier  # noqa: E402

PRIMARY = "gemini-4-hydrogen-high"
# Shape of an evidence-chosen table: Neon above and below Hydrogen.
ACCOUNT = RoutingTable(
    host=reg.HOST_ANTIGRAVITY, version="test-account", source="TEST",
    assignments=MappingProxyType({
        RoutingTier.ENTRY: "agy:gemini-4-neon-medium",
        RoutingTier.STANDARD: "agy:gemini-4-hydrogen-high",
        RoutingTier.CRITICAL: "agy:gemini-4-neon-high",
        RoutingTier.CATASTROPHIC: "agy:gemini-4-neon-xhigh",
    }),
)
SEED = reg.SEED_ROUTING_TABLES[reg.HOST_ANTIGRAVITY]  # CRITICAL is Argon (scarce)


def _route(table: RoutingTable, **kw) -> object:
    kw.setdefault("task_type", TaskType.ROUTINE_VERIFICATION)
    kw.setdefault("severity", "MEDIUM")
    kw.setdefault("finding_category", "LOGIC")
    return route_model(ModelRoutingRequest(**kw), routing_table=table)


def test_routine_verification_leaves_the_primary_model_line() -> None:
    d = _route(ACCOUNT, primary_model=PRIMARY)
    assert not d.is_blocked
    assert d.selected_model.value == "gemini-4-neon-high"
    assert d.routing_tier == RoutingTier.CRITICAL
    assert d.is_cross_model_required
    assert "different model line" in d.decision_reason


def test_critical_verification_of_an_unmapped_category_also_leaves_the_line() -> None:
    d = _route(ACCOUNT, task_type=TaskType.CRITICAL_VERIFICATION, severity="CRITICAL",
               finding_category="SECURITY", primary_model=PRIMARY)
    assert d.selected_model.value == "gemini-4-neon-high"


def test_unchanged_without_a_primary_model_or_on_another_line() -> None:
    assert _route(ACCOUNT).selected_model.value == PRIMARY
    assert _route(ACCOUNT, primary_model="gemini-4-neon-high").selected_model.value == PRIMARY


def test_primary_audit_and_other_tasks_are_not_affected() -> None:
    d = _route(ACCOUNT, task_type=TaskType.PRIMARY_AUDIT, primary_model=PRIMARY)
    assert d.selected_model.value == PRIMARY and d.routing_tier == RoutingTier.STANDARD


def test_blocked_critical_verification_stays_blocked() -> None:
    d = _route(ACCOUNT, task_type=TaskType.CRITICAL_VERIFICATION, severity="CRITICAL",
               finding_category="DATABASE_INTEGRITY", evidence_gate_status="FAILED",
               execution_intent=ExecutionIntent.REQUIRED_CRITICAL_VERIFICATION, primary_model=PRIMARY)
    assert d.is_blocked and d.routing_status == RoutingStatus.BLOCKED_EVIDENCE


def test_scarce_critical_model_is_used_only_for_critical_verification() -> None:
    routine = _route(SEED, primary_model=PRIMARY)
    assert routine.selected_model.value == PRIMARY and not routine.is_argon
    critical = _route(SEED, task_type=TaskType.CRITICAL_VERIFICATION, severity="HIGH",
                      finding_category="SECURITY", primary_model=PRIMARY)
    assert critical.selected_model.value == "gemini-4-argon-medium" and critical.is_argon


def _adapter(calls: list) -> AntigravityCliAdapter:
    adapter = AntigravityCliAdapter(executable_override="agy-not-used")

    def fake_dispatch(**kwargs):
        calls.append(kwargs)
        raise OSError("dispatch reached")

    adapter.dispatch = fake_dispatch  # type: ignore[method-assign]
    return adapter


def test_adapter_accepts_the_independent_verifier_only_with_the_primary_model() -> None:
    """The adapter re-routes: without the primary model the CRITICAL-tier verifier would exceed the tier."""
    kw = dict(task_type=TaskType.CRITICAL_VERIFICATION, severity="HIGH", finding_category="SECURITY",
              execution_intent=ExecutionIntent.REQUIRED_CRITICAL_VERIFICATION, audit_run_id="RUN-1",
              model_id="gemini-4-argon-medium")
    calls: list = []
    res = _adapter(calls).start_new_conversation("x", **kw)
    assert not res.ok and res.status == "EXPLICIT_MODEL_EXCEEDS_TIER" and calls == []
    with pytest.raises(OSError):
        _adapter(calls).start_new_conversation("x", primary_model=PRIMARY, **kw)
    assert len(calls) == 1 and calls[0]["model_id"] == "gemini-4-argon-medium"


def test_worker_routes_the_verifier_off_the_primary_model_line(tmp_path: Path) -> None:
    """End to end through VerificationWorker: the run's primary model reaches routing and the adapter."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from db import connect, ingest_findings
    from test_second_pass_verification import _sample_candidate_findings, _seed_project_and_run
    from verification import VerificationWorker

    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-IND")
    with connect(db_path) as conn:
        conn.execute("UPDATE audit_runs SET primary_model=? WHERE run_id='RUN-IND'", (PRIMARY,))
        conn.commit()
    ingest_findings(db_path, project_key="pay", run_id="RUN-IND", findings=[_sample_candidate_findings()[0]],
                    report_dir=tmp_path / "reports", repo_path=repo_dir)

    seen: list[dict] = []

    class SpyAdapter:
        def discover_executable(self) -> Path:
            return tmp_path / "agy.exe"

        def start_new_conversation(self, prompt: str, **kwargs):
            seen.append(kwargs)
            raise RuntimeError("stop after routing")

    VerificationWorker(db_path=db_path, adapter=SpyAdapter(), app_home=tmp_path, worker_id="w").process_one_job()
    assert len(seen) == 1
    assert seen[0]["primary_model"] == PRIMARY
    # Test DB has no approved table: the seed's CRITICAL tier (Argon) serves the critical candidate.
    assert seen[0]["model_id"] == "gemini-4-argon-medium"

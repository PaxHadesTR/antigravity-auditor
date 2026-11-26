"""Verified findings whose proposed fix the verifier rejected get a new proposal from the repair planner and an
independent review; an accepted proposal makes the finding applicable, a rejected one changes nothing."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from model_policy import TaskType  # noqa: E402
from remediation_replan import replan_unsafe_remediations  # noqa: E402
from test_model_router_phase2 import make_dispatch_result  # noqa: E402
from test_verification_stuck_states import F1, RUN, _one, _seed, _verdict, _worker  # noqa: E402

UNSAFE = _verdict("F-ST-1", remediation_safe=False,
                  remediation_review="UNSAFE_REMEDIATION: rejecting all amounts breaks refunds.")


def _finalized_with_unsafe_fix(tmp_path: Path) -> Path:
    db_path = _seed(tmp_path)
    res = _worker(db_path, {"verification_results": [UNSAFE]}).process_one_job()
    assert res["finalize"]["status"] == "READY_FOR_REVIEW", res
    return db_path


def _adapter(*answers: dict[str, Any]) -> MagicMock:
    adapter = MagicMock()
    adapter.start_new_conversation.side_effect = [
        make_dispatch_result(response_text=json.dumps(a), ok=True, conversation_id=f"0000000{i}-2222-4333-8444-555555555555",
                             model=m)
        for i, (a, m) in enumerate(zip(answers, ("gemini-4-hydrogen-high", "gemini-4-argon-medium")))
    ]
    return adapter


PROPOSAL = {"proposals": [{"finding_id": "F-ST-1", "recommendation": "Reject amount < 0 in charge(); keep refunds "
                           "on their own path.", "addresses_objection": "Refunds no longer go through charge().",
                           "test_plan": "Negative charge raises; refund path unchanged."}]}


def test_accepted_proposal_makes_the_finding_applicable(tmp_path: Path) -> None:
    db_path = _finalized_with_unsafe_fix(tmp_path)
    assert _one(db_path, "SELECT remediation_safe, execution_eligible FROM findings") == (0, 0)
    adapter = _adapter(PROPOSAL, {"reviews": [{"finding_id": "F-ST-1", "remediation_safe": True,
                                                "remediation_review": "Safe: refunds keep their own path."}]})
    out = replan_unsafe_remediations(db_path, project_key="p2", run_id=RUN, adapter=adapter)
    assert out["status"] == "ACCEPTED" and out["accepted"] == ["F-ST-1"], out
    rec, safe, eligible, review = _one(db_path, "SELECT recommendation, remediation_safe, execution_eligible, "
                                                "remediation_review FROM findings")
    assert safe == 1 and eligible == 1 and "Test plan: Negative charge raises" in rec and review.startswith("Safe")
    assert _one(db_path, "SELECT reason FROM finding_history ORDER BY rowid DESC LIMIT 1")[0] == "REMEDIATION_REPLANNED"
    plan_call, review_call = adapter.start_new_conversation.call_args_list
    assert plan_call.kwargs["task_type"] == TaskType.REPAIR_PLANNING and plan_call.kwargs["isolated"] is True
    assert plan_call.kwargs["model_id"] == "gemini-4-hydrogen-high"
    # The reviewer is another model line than the planner (seed table: the CRITICAL tier, Argon).
    assert review_call.kwargs["model_id"] == "gemini-4-argon-medium"
    assert review_call.kwargs["primary_model"] == "gemini-4-hydrogen-high"
    assert "rejecting all amounts breaks refunds" in plan_call.args[0]  # the planner sees the objection


def test_rejected_proposal_changes_nothing(tmp_path: Path) -> None:
    db_path = _finalized_with_unsafe_fix(tmp_path)
    before = _one(db_path, "SELECT recommendation FROM findings")[0]
    adapter = _adapter(PROPOSAL, {"reviews": [{"finding_id": "F-ST-1", "remediation_safe": False,
                                                "remediation_review": "Still breaks the webhook replay path."}]})
    out = replan_unsafe_remediations(db_path, project_key="p2", run_id=RUN, adapter=adapter)
    assert out["status"] == "ALL_REJECTED" and out["rejected"][0]["reason"].startswith("Still breaks")
    assert _one(db_path, "SELECT recommendation, remediation_safe FROM findings") == (before, 0)


def test_unsafe_markers_in_the_review_still_reject(tmp_path: Path) -> None:
    db_path = _finalized_with_unsafe_fix(tmp_path)
    adapter = _adapter(PROPOSAL, {"reviews": [{"finding_id": "F-ST-1", "remediation_safe": True,
                                                "remediation_review": "INTRODUCES_REGRESSION in refunds."}]})
    out = replan_unsafe_remediations(db_path, project_key="p2", run_id=RUN, adapter=adapter)
    assert out["status"] == "ALL_REJECTED" and _one(db_path, "SELECT remediation_safe FROM findings")[0] == 0


def test_nothing_to_replan_makes_no_model_call(tmp_path: Path) -> None:
    db_path = _seed(tmp_path)
    _worker(db_path, {"verification_results": [_verdict("F-ST-1")]}).process_one_job()
    adapter = MagicMock()
    out = replan_unsafe_remediations(db_path, project_key="p2", run_id=RUN, adapter=adapter)
    assert out["status"] == "NOTHING_TO_REPLAN" and not adapter.start_new_conversation.called


def test_planner_failure_raises_and_changes_nothing(tmp_path: Path) -> None:
    db_path = _finalized_with_unsafe_fix(tmp_path)
    adapter = MagicMock()
    adapter.start_new_conversation.return_value = make_dispatch_result(ok=False, status="CLI_TIMEOUT")
    with pytest.raises(RuntimeError, match="remediation-proposals dispatch failed"):
        replan_unsafe_remediations(db_path, project_key="p2", run_id=RUN, adapter=adapter)
    assert _one(db_path, "SELECT remediation_safe FROM findings")[0] == 0

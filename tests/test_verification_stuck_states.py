"""Verification must not get stuck or lose verdicts: the worker finalizes its own submission, a sweep finalizes
submissions that were left unfinalized, incomplete answers are retried as a whole, permanent failures are not
retried, a verification is finalized once, and follow-up (-DISC) recovery keeps the reviewable report intact."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import agy_adapter  # noqa: E402
import db as db_module  # noqa: E402
import verification as v  # noqa: E402
from db import ingest_findings, recover_stale_runs  # noqa: E402
from test_model_router_phase2 import _seed_db, make_dispatch_result  # noqa: E402
from verification import VerificationWorker, finalize_submitted_verifications, finalize_verified_report  # noqa: E402

RUN = "RUN-STUCK-1"
F1 = {
    "finding_id": "F-ST-1", "fingerprint": "fp-st-1", "title": "Charge accepts negative amounts",
    "category": "DATA_INTEGRITY", "severity": "HIGH", "confidence": "LIKELY", "file_path": "src/payment.py",
    "symbol": "charge", "line_start": 1, "line_end": 4, "evidence": "def charge(amount: int):",
    "impact": "Refunds can be triggered through the charge path.", "recommendation": "Reject amount <= 0 early.",
}
F2 = {**F1, "finding_id": "F-ST-2", "fingerprint": "fp-st-2", "title": "Zero amount is accepted",
      "line_start": 2, "line_end": 3, "evidence": "    if amount < 0:"}


def _verdict(cid: str, verdict: str = "CONFIRMED", **over: Any) -> dict[str, Any]:
    item = {
        "candidate_finding_id": cid, "verdict": verdict, "verified_severity": "HIGH", "verified_confidence": "LIKELY",
        "technical_rationale": "Checked the charge path end to end.",
        "source_evidence": {"file_path": "src/payment.py", "line_start": 1, "line_end": 1, "symbol": "charge",
                            "excerpt": "def charge(amount: int):"},
        "remediation_review": "Safe, local change.", "acceptance_criteria": "Negative amounts are rejected.",
    }
    item.update(over)
    return item


def _seed(tmp_path: Path, findings: list[dict[str, Any]] | None = None) -> Path:
    db_path, repo_dir = _seed_db(tmp_path, run_id=RUN, status="ANALYZING")
    ingest_findings(db_path, project_key="p2", run_id=RUN, findings=findings or [F1],
                    repo_path=repo_dir, report_dir=tmp_path / "reports")
    return db_path


def _worker(db_path: Path, payload: Any, **kw: Any) -> VerificationWorker:
    worker = VerificationWorker(db_path, **kw)
    adapter = MagicMock()
    adapter.SUPPORTS_STRUCTURED_DELIVERY = True
    text = payload if isinstance(payload, str) else json.dumps(payload)
    adapter.start_new_conversation.return_value = make_dispatch_result(
        response_text=text, ok=True, conversation_id="11111111-2222-4333-8444-555555555555",
        model="gemini-4-neon-high",
    )
    worker.adapter = adapter
    return worker


def _one(db_path: Path, sql: str, *args: Any) -> Any:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(sql, args).fetchone()
    finally:
        conn.close()


def test_worker_finalizes_its_own_submission_and_refuses_a_second_finalization(tmp_path: Path) -> None:
    db_path = _seed(tmp_path)
    res = _worker(db_path, {"verification_results": [_verdict("F-ST-1")]}).process_one_job()
    assert res["structured_submission"] == "SUBMITTED"
    assert res["finalize"]["status"] == "READY_FOR_REVIEW", res
    assert _one(db_path, "SELECT status FROM audit_runs WHERE run_id=?", RUN)[0] == "READY_FOR_REVIEW"
    with pytest.raises(RuntimeError, match="cannot be finalized"):
        finalize_verified_report(db_path, audit_run_id=RUN, verification_run_id=res["verification_run_id"])


def test_unfinalized_submission_is_swept_instead_of_recovered_as_stale(tmp_path: Path) -> None:
    db_path = _seed(tmp_path)
    res = _worker(db_path, {"verification_results": [_verdict("F-ST-1")]}, auto_finalize=False).process_one_job()
    assert res["structured_submission"] == "SUBMITTED" and "finalize" not in res
    assert _one(db_path, "SELECT status FROM audit_runs WHERE run_id=?", RUN)[0] == "VERIFICATION_RUNNING"
    recover_stale_runs(db_path, project_key="p2", stale_timeout_seconds=0)
    assert _one(db_path, "SELECT status FROM audit_runs WHERE run_id=?", RUN)[0] == "VERIFICATION_RUNNING"
    assert finalize_submitted_verifications(db_path, project_key="p2", min_age_seconds=3600) == []  # grace period
    swept = finalize_submitted_verifications(db_path, project_key="p2", min_age_seconds=0)
    assert [s["status"] for s in swept] == ["READY_FOR_REVIEW"]
    assert _one(db_path, "SELECT status FROM audit_runs WHERE run_id=?", RUN)[0] == "READY_FOR_REVIEW"


@pytest.mark.parametrize("payload, needle", [
    ({"verification_results": []}, "missing ['F-ST-1']"),
    ({"verification_results": [_verdict("F-ST-1"), _verdict("F-ST-1")]}, "duplicated ['F-ST-1']"),
    ({"verification_results": [_verdict("F-ST-1"), _verdict("OTHER")]}, "unexpected ['OTHER']"),
    ({"verification_results": [_verdict("F-ST-1", technical_rationale="   ")]}, "empty 'technical_rationale'"),
    ({"verification_results": [_verdict("F-ST-1", "PARTIALLY_CONFIRMED")]}, "corrected_claim"),
])
def test_incomplete_answer_is_retried_as_a_whole(tmp_path: Path, payload: dict[str, Any], needle: str) -> None:
    db_path = _seed(tmp_path)
    res = _worker(db_path, payload).process_one_job()
    assert res["status"] == "RETRYABLE_FAILURE" and res["error_code"] == "STRUCTURED_OUTPUT_INCOMPLETE"
    assert needle in res["error_message"]
    job = _one(db_path, "SELECT status, attempt_count, max_attempts FROM verification_dispatch_queue")
    assert job[0] == "RETRYABLE_FAILURE" and job[1] < job[2]
    vrun = _one(db_path, "SELECT status, submission_count FROM audit_verification_runs")
    assert vrun[0] == "PENDING" and not vrun[1]


def test_rejected_submission_is_requeued_as_a_fresh_verification(tmp_path: Path) -> None:
    db_path = _seed(tmp_path)
    bad = _verdict("F-ST-1", source_evidence={"file_path": "../outside.py", "line_start": 1, "line_end": 1,
                                              "symbol": "charge", "excerpt": "x"})
    res = _worker(db_path, {"verification_results": [bad]}).process_one_job()
    assert res["structured_submission"] == "REJECTED" and res["requeued_job_id"]
    queued = _one(db_path, "SELECT status FROM verification_dispatch_queue WHERE job_id=?", res["requeued_job_id"])
    assert queued[0] == "QUEUED"
    assert _one(db_path, "SELECT status FROM audit_runs WHERE run_id=?", RUN)[0] == "VERIFICATION_PENDING"


def test_permanent_dispatch_failure_is_not_retried(tmp_path: Path) -> None:
    db_path = _seed(tmp_path)
    worker = _worker(db_path, "")
    worker.adapter.start_new_conversation.return_value = make_dispatch_result(
        ok=False, status="CLI_AUTHENTICATION_FAILED", error="sign-in required")
    res = worker.process_one_job()
    assert res["status"] == "FAILED" and res["attempt"] < res["max_attempts"]


def test_concurrency_slot_is_retried_not_blocked(tmp_path: Path) -> None:
    db_path = _seed(tmp_path)
    worker = _worker(db_path, "")
    busy = make_dispatch_result(ok=False, status="BLOCKED_BUDGET")
    worker.adapter.start_new_conversation.return_value = busy.__class__(
        **{**busy.__dict__, "error_code": "REJECTED_CONCURRENCY"})
    res = worker.process_one_job()
    assert res["status"] == "RETRYABLE_FAILURE"


def test_retries_may_dispatch_the_same_finding_again() -> None:
    import inspect

    src = inspect.getsource(VerificationWorker._process_claimed_job)
    assert "allow_budget_duplicate=attempt > 1" in src
    assert "allow_budget_duplicate" in inspect.signature(agy_adapter.AntigravityCliAdapter.start_new_conversation).parameters


def test_leases_outlive_one_verification_dispatch() -> None:
    import inspect

    assert v.VERIFICATION_LEASE_SECONDS > agy_adapter.VERIFICATION_TIMEOUT_SECONDS
    assert inspect.signature(VerificationWorker).parameters["lease_seconds"].default == v.VERIFICATION_LEASE_SECONDS
    lease = inspect.signature(db_module.reserve_argon_budget_atomic).parameters["lease_seconds"].default
    assert lease > agy_adapter.VERIFICATION_TIMEOUT_SECONDS


def test_disc_requeue_keeps_rejected_primaries_and_the_reviewable_report(tmp_path: Path) -> None:
    db_path = _seed(tmp_path, [F1, F2])
    disc = {**F1, "finding_id": "F-ST-D", "fingerprint": "fp-st-d", "title": "Missing upper bound",
            "line_start": 4, "line_end": 4, "evidence": "    return True"}
    payload = {"verification_results": [_verdict("F-ST-1"), _verdict("F-ST-2", "REJECTED")],
               "verifier_discovered_findings": [disc]}
    res = _worker(db_path, payload).process_one_job()
    follow = res["finalize"]["followup_verification_run_id"]
    assert follow and follow.endswith("-DISC")
    # The report of a run whose follow-up is still pending can already be under review (e.g. a later round).
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE audit_runs SET status='READY_FOR_REVIEW' WHERE run_id=?", (RUN,))
    conn.execute("UPDATE verification_dispatch_queue SET status='FAILED', attempt_count=1 WHERE verification_run_id=?",
                 (follow,))
    conn.commit()
    conn.close()
    out = v.recover_verification_job(db_path, project_key="p2", audit_run_id=RUN, action="requeue")
    assert out["verification_run_id"].endswith("-DISC")
    assert _one(db_path, "SELECT status FROM audit_runs WHERE run_id=?", RUN)[0] == "READY_FOR_REVIEW"
    assert _one(db_path, "SELECT status FROM candidate_findings WHERE candidate_finding_id='F-ST-2'")[0] == "REJECTED"

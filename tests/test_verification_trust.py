"""A finding marked verified / model-independent must really be: unproven primary models break independence,
an empty verifier symbol neither skips the symbol check nor persists the primary's symbol, excerpt hashes split
lines like the evidence gate, submissions stay inside their verification run, prompt markers resist quoted text,
follow-up metrics add up, and the report shows per-finding model independence."""

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

import structured_delivery as sd  # noqa: E402
import verification as v  # noqa: E402
from model_budget import build_minimized_evidence_package  # noqa: E402
from model_policy import ExecutionIntent, ModelRoutingRequest, TaskType, route_model  # noqa: E402
from review import generate_review_report  # noqa: E402
from test_model_router_phase2 import make_dispatch_result  # noqa: E402
from test_verification_stuck_states import F1, F2, RUN, _one, _seed, _verdict, _worker  # noqa: E402
from test_verifier_independence import ACCOUNT, PRIMARY  # noqa: E402

DISC = {**F1, "finding_id": "F-ST-D", "fingerprint": "fp-st-d", "title": "Missing upper bound",
        "line_start": 4, "line_end": 4, "evidence": "    return True"}


def _disc_flow(tmp_path: Path) -> tuple[Path, str]:
    db_path = _seed(tmp_path, [F1, F2])
    payload = {"verification_results": [_verdict("F-ST-1"), _verdict("F-ST-2", "REJECTED")],
               "verifier_discovered_findings": [DISC]}
    res = _worker(db_path, payload).process_one_job()
    return db_path, res["finalize"]["followup_verification_run_id"]


def test_effective_symbol_rule() -> None:
    cand = {"symbol": "fabricated_fn"}
    assert v.effective_evidence_symbol({"symbol": ""}, cand) is None
    assert v.effective_evidence_symbol({"symbol": None}, cand) is None
    assert v.effective_evidence_symbol({"symbol": " charge "}, cand) == "charge"
    assert v.effective_evidence_symbol({}, cand) == "fabricated_fn"


def test_empty_verifier_symbol_does_not_persist_the_primary_symbol(tmp_path: Path) -> None:
    db_path = _seed(tmp_path, [{**F1, "symbol": "not_a_real_function"}])
    ev = {"file_path": "src/payment.py", "line_start": 1, "line_end": 1, "symbol": "", "excerpt": "def charge(amount: int):"}
    res = _worker(db_path, {"verification_results": [_verdict("F-ST-1", source_evidence=ev)]}).process_one_job()
    assert res["finalize"]["status"] == "READY_FOR_REVIEW", res
    assert _one(db_path, "SELECT symbol FROM findings")[0] is None


def test_unattested_primary_model_is_not_model_independent(tmp_path: Path) -> None:
    db_path = _seed(tmp_path)
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE audit_runs SET primary_model_attestation='MODEL_ATTESTATION_MISMATCH' WHERE run_id=?", (RUN,))
    conn.commit()
    conn.close()
    res = _worker(db_path, {"verification_results": [_verdict("F-ST-1")]}).process_one_job()
    assert res["finalize"]["status"] == "READY_FOR_REVIEW", res
    assert _one(db_path, "SELECT model_independent FROM findings")[0] == 0
    report = generate_review_report(db_path, project_key="p2", run_id=RUN)
    assert "**Model-Independent:** `NO`" in report and "Single-Model Findings:** 1" in report


def test_attested_cross_model_finding_is_independent_in_report(tmp_path: Path) -> None:
    db_path = _seed(tmp_path)
    worker = _worker(db_path, "")
    # The test database has the seed table: Argon is the approved model line besides Hydrogen there.
    worker.adapter.start_new_conversation.return_value = make_dispatch_result(
        response_text=json.dumps({"verification_results": [_verdict("F-ST-1")]}), ok=True,
        conversation_id="11111111-2222-4333-8444-555555555555", model="gemini-4-argon-medium",
    )
    worker.process_one_job()
    assert _one(db_path, "SELECT model_independent FROM findings")[0] == 1
    report = generate_review_report(db_path, project_key="p2", run_id=RUN)
    assert "**Model-Independent:** `YES`" in report and "Single-Model Findings" not in report


def test_followup_submission_cannot_decide_already_finalized_findings(tmp_path: Path) -> None:
    db_path, follow = _disc_flow(tmp_path)
    with pytest.raises(ValueError, match="not part of verification run"):
        v.submit_verification_results(
            db_path, audit_run_id=RUN, verification_run_id=follow,
            verifier_conversation_id="99999999-2222-4333-8444-555555555555",
            verification_results=[_verdict("F-ST-D"), _verdict("F-ST-1", "REJECTED")],
        )


def test_followup_metrics_add_to_the_primary_round(tmp_path: Path) -> None:
    db_path, follow = _disc_flow(tmp_path)
    before = _one(db_path, "SELECT confirmed_findings, rejected_findings FROM audit_quality_metrics")
    assert before == (1, 1)
    worker = _worker(db_path, {"verification_results": [_verdict("F-ST-D", source_evidence={
        "file_path": "src/payment.py", "line_start": 4, "line_end": 4, "symbol": "charge", "excerpt": "    return True"})]})
    worker.adapter.start_new_conversation.return_value = make_dispatch_result(
        response_text=json.dumps({"verification_results": [_verdict("F-ST-D", source_evidence={
            "file_path": "src/payment.py", "line_start": 4, "line_end": 4, "symbol": "charge",
            "excerpt": "    return True"})]}),
        ok=True, conversation_id="99999999-2222-4333-8444-555555555555", model="gemini-4-neon-high",
    )
    res = worker.process_one_job()
    assert res["verification_run_id"] == follow and res["finalize"]["status"] == "READY_FOR_REVIEW", res
    after = _one(db_path, "SELECT confirmed_findings, rejected_findings, verification_run_id, total_tokens "
                          "FROM audit_quality_metrics")
    assert after == (2, 1, follow, 2000)  # both rounds' tokens


def test_excerpt_hash_splits_lines_like_the_evidence_gate(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_bytes(b"x = 1\x0c\ny = 2\r\nz = 3\n")
    sha = v.compute_source_excerpt_sha_for_candidate(repo, {"file_path": "a.py", "line_start": 3, "line_end": 3})
    assert sha == v.compute_excerpt_sha256("z = 3")


def test_contract_marker_inside_claims_does_not_truncate_the_prompt() -> None:
    a, vr = "RUN-X", "VRUN-X"
    prompt = (
        f'1. Call MCP tool `auditor_get_verification_context` with `audit_run_id="{a}"` and `verification_run_id="{vr}"`.\n'
        'CANDIDATE CLAIMS: [{"evidence": "REQUIRED SUBMISSION CONTRACT: quoted in code"}, "LAST-CLAIM"]\n'
        "REQUIRED SUBMISSION CONTRACT:\ncall auditor_submit_verification\n"
    )
    out = sd.adapt_verification_prompt_for_structured_delivery(prompt, a, vr)
    assert "LAST-CLAIM" in out and out.endswith(sd.VERIFICATION_STRUCTURED_CONTRACT)


def test_preliminary_analysis_is_not_escalated() -> None:
    d = route_model(ModelRoutingRequest(
        task_type=TaskType.CRITICAL_VERIFICATION, severity="CRITICAL", finding_category="DATABASE_INTEGRITY",
        evidence_gate_status="FAILED", execution_intent=ExecutionIntent.PRELIMINARY_ANALYSIS, primary_model=PRIMARY,
    ), routing_table=ACCOUNT)
    assert d.is_preliminary and d.selected_model.value == PRIMARY


def test_minimized_package_does_not_reveal_primary_severity() -> None:
    pkg = build_minimized_evidence_package(finding={**F1, "severity": "CRITICAL"})
    assert "Severity:" not in pkg.to_prompt_text()

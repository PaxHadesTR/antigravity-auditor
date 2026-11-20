"""Interface and cleanup fixes around verification: the broker goes through the real handlers, .git and skipped
directories are never evidence, conversation ids compare case-insensitively, duplicate discoveries are reported,
call statements are not method definitions, statuses and task types are strict, dispatch cost is recorded, and
audit-now resumes a parked verification."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import verification as v  # noqa: E402
from agy_adapter import parse_stream_json  # noqa: E402
from broker.db_adapter import BrokerDatabaseAdapter  # noqa: E402
from broker.exceptions import BrokerDatabaseError  # noqa: E402
from db import connect  # noqa: E402
from model_policy import ModelRoutingRequest  # noqa: E402
from test_audit_now_tool import _call, _run, env  # noqa: E402,F401
from test_verification_stuck_states import F1, RUN, _one, _seed, _verdict, _worker  # noqa: E402


def _broker_db(tmp_path: Path) -> Path:
    """The broker refuses a database named auditor.db (production guard): work on a copy."""
    import shutil

    src = _seed(tmp_path)
    dst = src.with_name("broker-test.db")
    shutil.copyfile(src, dst)
    return dst


def _vrun(db_path: Path) -> str:
    return _one(db_path, "SELECT verification_run_id FROM audit_verification_runs")[0]


def test_broker_finalize_goes_through_the_gates(tmp_path: Path) -> None:
    db_path = _broker_db(tmp_path)
    broker = BrokerDatabaseAdapter(db_path)
    with pytest.raises(BrokerDatabaseError, match="does not belong"):
        broker.finalize_verified_report_tx(verification_run_id=_vrun(db_path), project_key="other", run_id=RUN)
    # Nothing was submitted: the real handler refuses (the old broker path marked it FINALIZED).
    with pytest.raises(BrokerDatabaseError, match="cannot be finalized"):
        broker.finalize_verified_report_tx(verification_run_id=_vrun(db_path), project_key="p2", run_id=RUN)
    assert _one(db_path, "SELECT status FROM audit_runs WHERE run_id=?", RUN)[0] != "READY_FOR_REVIEW"


def test_broker_submit_goes_through_the_handler(tmp_path: Path) -> None:
    db_path = _broker_db(tmp_path)
    broker = BrokerDatabaseAdapter(db_path)
    with pytest.raises(BrokerDatabaseError, match="Unknown candidate_finding_id"):
        broker.submit_verification_tx(verification_run_id=_vrun(db_path), project_key="p2", run_id=RUN,
                                      results=[_verdict("NOPE")],
                                      verifier_conversation_id="11111111-2222-4333-8444-555555555555")


@pytest.mark.parametrize("path, forbidden", [
    (".git/config", True), (".GIT/HEAD", True), (".antigravity-audit/reports/x.md", True),
    ("src/git_helper.py", False), ("docs/.gitkeep", False),
])
def test_git_and_report_folders_are_never_evidence(path: str, forbidden: bool) -> None:
    assert v.is_forbidden_evidence_path(path) is forbidden


def test_skipped_directories_stay_out_of_candidate_hashes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "node_modules" / "pkg").mkdir(parents=True)
    (repo / "node_modules" / "pkg" / "index.js").write_text("x\n", encoding="utf-8")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    out = v.collect_repo_file_hashes_with_status(repo, ["node_modules/pkg/index.js", "a.py"])
    assert "a.py" in out["file_hashes"] and "node_modules/pkg/index.js" not in out["file_hashes"]


def test_conversation_ids_compare_case_insensitively(tmp_path: Path) -> None:
    db_path = _seed(tmp_path)
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE audit_runs SET agent_conversation_id='aaaaaaaa-2222-4333-8444-555555555555' WHERE run_id=?",
                 (RUN,))
    conn.commit()
    conn.close()
    with pytest.raises(RuntimeError, match="Independence violation"):
        v.submit_verification_results(db_path, audit_run_id=RUN, verification_run_id=_vrun(db_path),
                                      verifier_conversation_id="AAAAAAAA-2222-4333-8444-555555555555",
                                      verification_results=[_verdict("F-ST-1")])


def test_duplicate_discovery_is_reported(tmp_path: Path) -> None:
    db_path = _seed(tmp_path)
    out = v.submit_verification_results(
        db_path, audit_run_id=RUN, verification_run_id=_vrun(db_path),
        verifier_conversation_id="11111111-2222-4333-8444-555555555555",
        verification_results=[_verdict("F-ST-1")], verifier_discovered_findings=[dict(F1)],
    )
    assert out["duplicate_discoveries"] == ["F-ST-1"]


def _symbol_ok(tmp_path: Path, name: str, text: str, symbol: str, line: int) -> bool:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    ok, _code, _msg = v._verify_symbol_in_range(file_text=text, lines=lines, norm_path=name, sym_clean=symbol,
                                                line_start=line, line_end=line)
    return ok


def test_call_statements_are_not_method_definitions(tmp_path: Path) -> None:
    js = "helperCall(x)\nif (x > 0) {\n  run()\n}\n"
    assert not _symbol_ok(tmp_path, "a.js", js, "helperCall", 3)
    ret = "function outer() {\n  return helperCall(x)\n  if (y) {\n    run()\n  }\n}\n"
    assert not _symbol_ok(tmp_path, "b.js", ret, "helperCall", 4)
    cls = "class A {\n  helperCall(x) {\n    run()\n  }\n}\n"
    assert _symbol_ok(tmp_path, "c.js", cls, "helperCall", 3)
    java = "class A {\n  public void helperCall(int x)\n  {\n    run();\n  }\n}\n"
    assert _symbol_ok(tmp_path, "D.java", java, "helperCall", 4)


def test_lowercase_result_status_is_recognised() -> None:
    parsed = parse_stream_json('{"event":"result","result":{"status":"error","response":""}}\n')
    assert parsed.status == "ERROR"


def test_unknown_task_type_fails_closed() -> None:
    with pytest.raises(ValueError, match="Unknown task type"):
        ModelRoutingRequest(task_type="CRITICAL_VERFICATION").normalized_task_type()
    with pytest.raises(ValueError, match="Unknown execution intent"):
        ModelRoutingRequest(task_type="PRIMARY_AUDIT", execution_intent="BOGUS").normalized_intent()


def test_verification_run_records_its_dispatch_cost(tmp_path: Path) -> None:
    db_path = _seed(tmp_path)
    _worker(db_path, {"verification_results": [_verdict("F-ST-1")]}).process_one_job()
    tokens, duration, requested, observed = _one(
        db_path, "SELECT total_tokens, execution_duration, requested_model, observed_model FROM audit_verification_runs")
    assert tokens == 1000 and duration == 1.0 and requested == observed == "gemini-4-neon-high"
    # ... and the quality metrics carry it (they showed 0 before)
    m = _one(db_path, "SELECT total_tokens, requested_model, observed_model FROM audit_quality_metrics")
    assert m == (1000, "gemini-4-neon-high", "gemini-4-neon-high")


def test_audit_now_resumes_a_parked_verification(env: dict[str, Any]) -> None:  # noqa: F811
    _run(env, "R0", "COMPLETED")  # same code: a plain call would answer NO_CHANGES
    _run(env, "R1", "VERIFICATION_DISPATCHING")
    with connect(env["db"]) as conn:
        conn.execute("INSERT INTO audit_verification_runs(verification_run_id, audit_run_id, project_key, snapshot_id, "
                     "base_commit_sha, status, idempotency_key) VALUES('V1', 'R1', 'p', 'S1', 'abc', 'PENDING', 'iv1')")
        conn.execute("""INSERT INTO verification_dispatch_queue(job_id, audit_run_id, verification_run_id, project_key,
                        snapshot_id, idempotency_key, status, attempt_count, max_attempts, next_attempt_at)
                        VALUES('J1', 'R1', 'V1', 'p', 'S1', 'k1', 'RETRYABLE_FAILURE', 1, 3, '2000-01-01T00:00:00+00:00')""")
        conn.commit()
    res = _call(env)
    assert res["status"] == "STARTED", res

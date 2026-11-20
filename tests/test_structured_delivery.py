"""Structured (MCP-free) result delivery for headless agy audits and verifications, and the weekly
scheduled-audit pipeline. Headless `agy -p` auto-denies MCP tool calls, so scheduled runs must return JSON."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import cli  # noqa: E402
import structured_delivery as sd  # noqa: E402
from db import ingest_findings  # noqa: E402
from test_model_router_phase2 import _seed_db, make_dispatch_result  # noqa: E402
from verification import VerificationWorker  # noqa: E402

FINDING = {
    "finding_id": "F-SD-1", "fingerprint": "fp-sd-1", "title": "Charge accepts negative amounts",
    "category": "DATA_INTEGRITY", "severity": "HIGH", "confidence": "LIKELY", "file_path": "src/payment.py",
    "symbol": "charge", "line_start": 1, "line_end": 4, "evidence": "def charge(amount: int):",
    "impact": "Refunds can be triggered through the charge path.", "recommendation": "Reject amount <= 0 early.",
}


# --- schema conversion / parsing ----------------------------------------------------------------

def test_agent_schema_is_standard_json_schema() -> None:
    schema = sd.to_agent_json_schema(sd.PRIMARY_RESULT_SCHEMA)
    text = json.dumps(schema)
    assert '"nullable"' not in text and '"format"' not in text
    item = schema["properties"]["findings"]["items"]
    assert item["properties"]["file_path"]["type"] == ["string", "null"]
    assert item["additionalProperties"] is False
    # The server-side strict schema itself is untouched.
    assert sd.PRIMARY_RESULT_SCHEMA["properties"]["findings"]["items"]["properties"]["file_path"].get("nullable") is True


def test_parse_accepts_valid_payload_with_trailing_text() -> None:
    payload = sd.parse_structured_result(json.dumps({"findings": [FINDING]}) + "\nDone.", sd.PRIMARY_RESULT_SCHEMA)
    assert payload["findings"][0]["finding_id"] == "F-SD-1"


@pytest.mark.parametrize("text", [
    "I could not finish the audit.",
    '{"findings": "none"}',
    '{"findings": [], "extra": 1}',
    json.dumps({"findings": [{**FINDING, "sql": "DROP TABLE findings"}]}),
    json.dumps({"findings": [{k: v for k, v in FINDING.items() if k != "evidence"}]}),
])
def test_parse_rejects_invalid_payloads(text: str) -> None:
    with pytest.raises(sd.StructuredDeliveryError):
        sd.parse_structured_result(text, sd.PRIMARY_RESULT_SCHEMA)


def test_verification_schema_requires_results() -> None:
    assert sd.parse_structured_result('{"verification_results": []}', sd.VERIFICATION_RESULT_SCHEMA)
    with pytest.raises(sd.StructuredDeliveryError):
        sd.parse_structured_result('{"findings": []}', sd.VERIFICATION_RESULT_SCHEMA)


# --- prompt adaptation --------------------------------------------------------------------------

def test_prompt_adaptation_fails_loudly_when_markers_change() -> None:
    with pytest.raises(RuntimeError, match="marker"):
        sd.adapt_primary_prompt_for_structured_delivery("a prompt without the expected sections")
    with pytest.raises(RuntimeError, match="marker"):
        sd.adapt_verification_prompt_for_structured_delivery("no markers here", "RUN", "VRUN")


def test_verification_prompt_adaptation_removes_mcp_submission() -> None:
    prompt = (
        "HEADER\n1. Call MCP tool `auditor_get_verification_context` with `audit_run_id=\"RUN-1\"` and "
        "`verification_run_id=\"VRUN-1\"`.\n2. inspect\nREQUIRED SUBMISSION CONTRACT:\ninvoke the MCP tool "
        "`auditor_submit_verification` ...\n"
    )
    out = sd.adapt_verification_prompt_for_structured_delivery(prompt, "RUN-1", "VRUN-1")
    assert "invoke the MCP tool" not in out and "REQUIRED RESULT CONTRACT (STRUCTURED OUTPUT" in out
    assert "PRECEDENCE:" in out and out.startswith("HEADER")


# --- verification worker ------------------------------------------------------------------------

def _seed_candidate(tmp_path: Path, run_id: str) -> Path:
    db_path, repo_dir = _seed_db(tmp_path, run_id=run_id, status="ANALYZING")
    ingest_findings(db_path, project_key="p2", run_id=run_id, findings=[FINDING],
                    repo_path=repo_dir, report_dir=tmp_path / "reports")
    return db_path


def _structured_adapter(text: str) -> MagicMock:
    adapter = MagicMock()
    adapter.SUPPORTS_STRUCTURED_DELIVERY = True
    adapter.start_new_conversation.return_value = make_dispatch_result(
        response_text=text, ok=True, conversation_id="conv-sd-1", model="gemini-4-argon-medium",
    )
    return adapter


def test_worker_uses_isolated_structured_dispatch(tmp_path: Path) -> None:
    db_path = _seed_candidate(tmp_path, "RUN-SD-1")
    worker = VerificationWorker(db_path)
    worker.adapter = _structured_adapter('{"verification_results": []}')
    res = worker.process_one_job()
    kwargs = worker.adapter.start_new_conversation.call_args.kwargs
    assert kwargs["isolated"] is True and Path(kwargs["json_schema_path"]).is_file()
    prompt = worker.adapter.start_new_conversation.call_args.args[0]
    assert "invoke the MCP tool `auditor_submit_verification`" not in prompt
    # An empty answer covers none of the candidates: it is retried, never submitted.
    assert res["status"] == "RETRYABLE_FAILURE" and res["error_code"] == "STRUCTURED_OUTPUT_INCOMPLETE"


def test_worker_unparsable_answer_takes_retryable_path(tmp_path: Path) -> None:
    db_path = _seed_candidate(tmp_path, "RUN-SD-2")
    worker = VerificationWorker(db_path)
    worker.adapter = _structured_adapter("I verified everything, all good.")
    res = worker.process_one_job()
    assert res["status"] != "RUNNING"
    conn = sqlite3.connect(db_path)
    try:
        job = conn.execute("SELECT status, last_error_code FROM verification_dispatch_queue").fetchone()
    finally:
        conn.close()
    assert job[0] in ("RETRYABLE_FAILURE", "FAILED") and job[1] == "STRUCTURED_OUTPUT_INVALID"


def test_worker_rejected_submission_is_explicit(tmp_path: Path) -> None:
    db_path = _seed_candidate(tmp_path, "RUN-SD-3")
    worker = VerificationWorker(db_path)
    # Complete and schema-valid, but the handler rejects it: evidence path outside the repository.
    bad = {"verification_results": [{
        "candidate_finding_id": "F-SD-1", "verdict": "CONFIRMED", "verified_severity": "HIGH",
        "verified_confidence": "LIKELY", "technical_rationale": "Checked the charge path end to end.",
        "source_evidence": {"file_path": "../outside.py", "line_start": 1, "line_end": 4, "symbol": "charge",
                            "excerpt": "def charge(amount: int):"},
        "remediation_review": "Safe.", "acceptance_criteria": "Negative amounts are rejected.",
    }]}
    worker.adapter = _structured_adapter(json.dumps(bad))
    res = worker.process_one_job()
    assert res["structured_submission"] == "REJECTED"
    conn = sqlite3.connect(db_path)
    try:
        job = conn.execute("SELECT q.status, v.error_code FROM verification_dispatch_queue q JOIN audit_verification_runs v "
                           "USING (verification_run_id) ORDER BY q.rowid LIMIT 1").fetchone()
        run = conn.execute("SELECT status FROM audit_runs WHERE run_id='RUN-SD-3'").fetchone()
    finally:
        conn.close()
    # The rejected attempt stays explicit; the verification is requeued as a fresh one (attempts remain).
    assert job == ("FAILED", "STRUCTURED_SUBMIT_REJECTED") and run[0] == "VERIFICATION_PENDING"
    assert res["requeued_job_id"]


def test_interactive_adapters_keep_mcp_prompt(tmp_path: Path) -> None:
    db_path = _seed_candidate(tmp_path, "RUN-SD-4")
    worker = VerificationWorker(db_path)
    adapter = MagicMock(spec=["start_new_conversation", "discover_executable"])
    adapter.start_new_conversation.return_value = make_dispatch_result(
        response_text="", ok=True, conversation_id="conv-sd-4", model="gemini-4-argon-medium",
    )
    worker.adapter = adapter
    res = worker.process_one_job()
    kwargs = adapter.start_new_conversation.call_args.kwargs
    assert "isolated" not in kwargs and "json_schema_path" not in kwargs
    assert res["status"] == "RUNNING" and res["structured_submission"] == "NOT_APPLICABLE"


# --- scheduled-audit pipeline -------------------------------------------------------------------

class _Worker:
    def __init__(self, jobs: list[dict[str, Any] | None]) -> None:
        self.jobs = list(jobs)

    def process_one_job(self) -> dict[str, Any] | None:
        return self.jobs.pop(0) if self.jobs else None


def _pipeline(
    monkeypatch: pytest.MonkeyPatch,
    primary: Any,
    jobs: list[Any],
    finalize: Any,
    *,
    resumable: Any = None,
    retry_waits: list[Any] | None = None,
) -> dict[str, Any]:
    monkeypatch.setattr(cli, "dispatch", lambda project_key, **_kw: primary)
    monkeypatch.setattr(cli, "VerificationWorker", lambda *a, **k: _Worker(jobs))
    monkeypatch.setattr(cli, "finalize_verified_report", finalize)
    monkeypatch.setattr(cli, "_resumable_verification_run", lambda project_key: resumable)
    monkeypatch.setattr(cli, "_weekly_gate", lambda project_key, manual=False: None)
    waits = list(retry_waits or [])
    monkeypatch.setattr(cli, "_seconds_until_retry", lambda run_id: waits.pop(0) if waits else None)
    monkeypatch.setattr(cli, "_sleep", lambda s: None)
    return cli.scheduled_audit("p")


def test_pipeline_resumes_a_run_left_in_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    out = _pipeline(
        monkeypatch,
        None,  # dispatch would refuse: the project still has an active run
        [{"audit_run_id": "OLD", "status": "RUNNING", "structured_submission": "SUBMITTED"}],
        lambda db, **kw: seen.update(kw) or {"status": "READY_FOR_REVIEW"},
        resumable={"run_id": "OLD", "status": "VERIFICATION_PENDING", "verification_run_id": "V-OLD", "resumed": True},
    )
    assert out["result"] == "FINALIZED" and seen["audit_run_id"] == "OLD" and out["primary"]["resumed"] is True


def test_pipeline_waits_for_a_retryable_verification_job(monkeypatch: pytest.MonkeyPatch) -> None:
    out = _pipeline(
        monkeypatch,
        {"run_id": "R", "status": "VERIFICATION_PENDING", "verification_run_id": "V"},
        [
            {"audit_run_id": "R", "status": "RETRYABLE_FAILURE", "structured_submission": None},
            # -> waits for the job's back-off right away, then retries it
            {"audit_run_id": "R", "status": "RUNNING", "structured_submission": "SUBMITTED"},
        ],
        lambda db, **kw: {"status": "READY_FOR_REVIEW"},
        retry_waits=[30.0],
    )
    assert out["result"] == "FINALIZED"


def test_pipeline_finalizes_after_submitted_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fin(db, **kw):
        seen.update(kw)
        return {"status": "READY_FOR_REVIEW"}

    out = _pipeline(monkeypatch, {"run_id": "R", "status": "VERIFICATION_PENDING", "verification_run_id": "V"},
                    [{"audit_run_id": "R", "status": "RUNNING", "structured_submission": "SUBMITTED"}], fin)
    assert out["result"] == "FINALIZED" and seen["audit_run_id"] == "R" and seen["verification_run_id"] == "V"


@pytest.mark.parametrize("primary, jobs, expected", [
    (None, [], "PRIMARY_NOT_READY_FOR_VERIFICATION"),
    ({"run_id": "R", "status": "FAILED"}, [], "PRIMARY_NOT_READY_FOR_VERIFICATION"),
    ({"run_id": "R", "status": "VERIFICATION_PENDING"}, [None], "VERIFICATION_NOT_SUBMITTED"),
    ({"run_id": "R", "status": "VERIFICATION_PENDING"},
     [{"audit_run_id": "R", "status": "RUNNING", "structured_submission": "REJECTED"}], "VERIFICATION_NOT_SUBMITTED"),
])
def test_pipeline_stops_with_explicit_result(monkeypatch: pytest.MonkeyPatch, primary: Any, jobs: list[Any], expected: str) -> None:
    out = _pipeline(monkeypatch, primary, jobs, lambda *a, **k: pytest.fail("must not finalize"))
    assert out["result"] == expected


def test_pipeline_reports_finalize_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a, **k):
        raise RuntimeError("UNVERIFIABLE candidates remain")

    out = _pipeline(monkeypatch, {"run_id": "R", "status": "VERIFICATION_PENDING"},
                    [{"audit_run_id": "R", "status": "RUNNING", "structured_submission": "SUBMITTED"}], boom)
    assert out["result"] == "FINALIZE_BLOCKED" and "UNVERIFIABLE" in out["finalize_error"]


def test_register_sidecar_runs_the_pipeline() -> None:
    import inspect

    assert '"scheduled-audit", "--project", key' in inspect.getsource(cli.register)


# --- agy structured_output is authoritative (regression from the first real end-to-end run) ------

class _Res:
    def __init__(self, response_text: str, structured: Any) -> None:
        self.response_text = response_text
        self.events = [{"event": "step_update", "step_update": {}},
                       {"event": "result", "result": {"response": response_text, "structured_output": structured}}]


def test_structured_output_takes_precedence_over_response_text() -> None:
    good = {"findings": [FINDING]}
    # Real run: the plain response text held a different, schema-invalid object (missing 'title').
    stale = json.dumps({"findings": [{k: v for k, v in FINDING.items() if k != "title"}]})
    payload = sd.agent_result_payload(_Res(stale, good))
    assert payload == good
    assert sd.parse_structured_result(payload, sd.PRIMARY_RESULT_SCHEMA)["findings"][0]["title"] == FINDING["title"]


def test_falls_back_to_response_text_without_structured_output() -> None:
    res = _Res(json.dumps({"findings": []}), None)
    assert sd.agent_result_payload(res) == json.dumps({"findings": []})
    assert sd.structured_output_from_events([]) is None


def test_structured_output_is_still_server_validated() -> None:
    with pytest.raises(sd.StructuredDeliveryError):
        sd.parse_structured_result({"findings": [{"finding_id": "x"}]}, sd.PRIMARY_RESULT_SCHEMA)


def test_pipeline_runs_the_followup_verification_round(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []

    def fin(db, **kw):
        calls.append(kw["verification_run_id"])
        return {"status": "VERIFICATION_PENDING", "followup_verification_run_id": "V-DISC"} if len(calls) == 1 else {"status": "READY_FOR_REVIEW"}

    out = _pipeline(
        monkeypatch,
        {"run_id": "R", "status": "VERIFICATION_PENDING", "verification_run_id": "V"},
        [
            {"audit_run_id": "R", "status": "RUNNING", "structured_submission": "SUBMITTED"},
            {"audit_run_id": "R", "status": "RUNNING", "structured_submission": "SUBMITTED"},
        ],
        fin,
    )
    assert out["result"] == "FINALIZED" and calls == ["V", "V-DISC"]

"""APPLY auto-approval policy (terminal-configured, opt-in) and provider-quota handling."""

from __future__ import annotations

import builtins
import json
import sqlite3
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import apply_policy as ap  # noqa: E402
import cli  # noqa: E402
from agy_adapter import StreamJsonParseResult, check_quota_exhausted  # noqa: E402
from db import connect, initialize, ingest_findings  # noqa: E402
from mcp_server import AuditorMCPDispatcher  # noqa: E402
from test_model_router_phase2 import _seed_db, make_dispatch_result  # noqa: E402
from verification import VerificationWorker  # noqa: E402

FINDING = {
    "finding_id": "F-AP-1", "fingerprint": "fp-ap-1", "title": "Return explicit int", "category": "V7",
    "severity": "MEDIUM", "confidence": "CONFIRMED", "file_path": "mod.py", "symbol": "val",
    "line_start": 1, "line_end": 2, "evidence": "return 1", "impact": "type clarity",
    "recommendation": "add return annotation",
}


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


@pytest.fixture()
def ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A registered project with one second-pass VERIFIED MEDIUM finding and a saved APPLY decision."""
    db_path = tmp_path / "database" / "auditor.db"
    initialize(db_path)
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "CONFIG_PATH", tmp_path / "config" / "config.json")
    monkeypatch.setattr(cli, "SIDECAR_ROOT", tmp_path / "config" / "sidecars")
    monkeypatch.setattr(cli, "JSONL_PATH", tmp_path / "logs" / "audit-events.jsonl")
    repo = tmp_path / "svc1"
    repo.mkdir()
    for args in (["init"], ["config", "user.email", "t@example.com"], ["config", "user.name", "Test"]):
        _git(repo, *args)
    (repo / "mod.py").write_text("def val():\n    return 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")
    cli.register(cli.argparse.Namespace(key="svc1", path=str(repo), project_id="ag-1", name="S1", cron="0 3 * * 1",
                                        copy_omniapex_rules=False))
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    with connect(db_path) as conn:
        conn.execute("UPDATE projects SET min_free_mb=1 WHERE project_key='svc1'")
        conn.execute("INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash) "
                     "VALUES('R-AP', 'svc1', 'DISPATCHED', ?, 'th')", (head,))
        conn.commit()
    d = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)
    pub = d.call_tool("auditor_publish_report", {"project_key": "svc1", "run_id": "R-AP", "findings": [FINDING]})
    vrun = pub["verification_run_id"]
    d.call_tool("auditor_submit_verification", {
        "audit_run_id": "R-AP", "verification_run_id": vrun,
        "verifier_metadata": {"invocation_mechanism": "mcp_direct", "actual_subagent_invocations": 0},
        "verifier_conversation_id": "conv-verifier-ap-1",
        "verification_results": [{
            "candidate_finding_id": "F-AP-1", "verdict": "CONFIRMED", "verified_severity": "MEDIUM",
            "verified_confidence": "CONFIRMED", "technical_rationale": "Confirmed missing return annotation.",
            "source_evidence": {"file_path": "mod.py", "line_start": 1, "line_end": 2, "symbol": "val",
                                "evidence_excerpt": "return 1"},
            "remediation_review": "Adding -> int is safe.", "remediation_safe": True,
            "acceptance_criteria": "val() returns 1 with an int annotation.",
        }],
    })
    assert d.call_tool("auditor_finalize_verified_report",
                       {"audit_run_id": "R-AP", "verification_run_id": vrun})["status"] == "READY_FOR_REVIEW"
    d.call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-AP",
                                           "decisions": [{"finding_id": "F-AP-1", "decision": "APPLY"}]})
    return {"db": db_path, "repo": repo, "d": d}


def _set_policy(db: Path, key: str = "svc1", **overrides: Any) -> None:
    with connect(db) as conn:
        # The interactive fixture records no models, so its findings are single-model verified.
        base = {**ap.DEFAULT_POLICY, "enabled": True, "allow_single_model_verification": True}
        ap.set_policy(conn, key, {**base, **overrides}, updated_by="test")
        conn.commit()


def _approvals(db: Path) -> list[sqlite3.Row]:
    with connect(db) as conn:
        return conn.execute("SELECT * FROM execution_approvals").fetchall()


def _auto_start(ready: dict[str, Any]) -> dict[str, Any]:
    return ready["d"].call_tool("auditor_start_execution",
                                {"project_key": "svc1", "run_id": "R-AP", "auto_approve": True})


# --- policy evaluation ----------------------------------------------------------------------------------------


def test_auto_approval_is_off_by_default(ready: dict[str, Any]) -> None:
    with pytest.raises(PermissionError, match="disabled"):
        _auto_start(ready)
    assert _approvals(ready["db"]) == []


@pytest.mark.parametrize("overrides, reason", [
    ({"severities": ["LOW"]}, "severity MEDIUM"),
    ({"paths_deny": ["*.py"]}, "paths_deny"),
    ({"paths_allow": ["src/**"]}, "outside paths_allow"),
    ({"categories_deny": ["v7"]}, "categories_deny"),
    ({"categories_allow": ["SECURITY"]}, "not in categories_allow"),
    ({"max_findings": 0}, "exceed max_findings"),
    ({"max_per_day": 0}, "max_per_day"),
    ({"expires_at": "2020-01-01T00:00:00+00:00"}, "expired"),
])
def test_findings_outside_the_policy_are_refused(ready: dict[str, Any], overrides: dict, reason: str) -> None:
    _set_policy(ready["db"], **overrides)
    with pytest.raises(PermissionError, match=reason):
        _auto_start(ready)
    assert _approvals(ready["db"]) == []


def test_project_policy_overrides_the_global_default(ready: dict[str, Any]) -> None:
    _set_policy(ready["db"], "*")  # global: enabled
    _set_policy(ready["db"], "svc1", enabled=False)
    with connect(ready["db"]) as conn:
        ev = ap.evaluate(conn, "svc1", "R-AP")
    assert ev["eligible"] is False and ev["policy_source"] == "svc1"


def test_corrupted_stored_policy_is_treated_as_disabled(ready: dict[str, Any]) -> None:
    with connect(ready["db"]) as conn:
        ap.ensure_schema(conn)
        conn.execute("INSERT INTO apply_policies(project_key, policy_json, updated_by) VALUES('svc1', ?, 'x')",
                     (json.dumps({"enabled": True, "max_findings": "lots"}),))
        conn.commit()
        policy, source = ap.get_policy(conn, "svc1")
    assert policy["enabled"] is False and "INVALID" in source


def test_daily_budget_counts_previous_auto_approvals(ready: dict[str, Any]) -> None:
    _set_policy(ready["db"], max_per_day=1)
    assert _auto_start(ready)["authorization"]["mode"] == "auto_policy"
    with connect(ready["db"]) as conn:
        ev = ap.evaluate(conn, "svc1", "R-AP")
    assert any("max_per_day" in r for r in ev["reasons"])


def test_auto_approved_execution_is_delivered_as_a_review_branch(ready: dict[str, Any]) -> None:
    _set_policy(ready["db"])
    d = ready["d"]
    started = _auto_start(ready)
    assert started["authorization"]["mode"] == "auto_policy" and started["authorization"]["policy_source"] == "svc1"
    approvals = _approvals(ready["db"])
    assert len(approvals) == 1 and approvals[0]["authorized_by"].startswith("policy:svc1#")
    assert approvals[0]["status"] == "CONSUMED" and json.loads(approvals[0]["policy_snapshot"])["source"] == "svc1"
    exec_id, wt = started["exec_id"], Path(started["worktree_path"])
    d.call_tool("auditor_update_finding_execution",
                {"project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "begin"})
    (wt / "mod.py").write_text("def val() -> int:\n    return 1\n", encoding="utf-8")
    d.call_tool("auditor_update_finding_execution", {
        "project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "verify",
        "happy_test_passed": True, "adversarial_test_passed": True, "red_team_passed": True})
    fin = d.call_tool("auditor_finalize_execution",
                      {"project_key": "svc1", "exec_id": exec_id, "integration_test_passed": True})
    review = fin["review"]
    assert review["authorization"] == "auto_policy" and review["policy_violations"] == []
    assert review["merged"] is False and review["pushed"] is False
    assert "-> int" not in (ready["repo"] / "mod.py").read_text(encoding="utf-8")  # working tree untouched


def test_auto_approved_fix_beyond_the_policy_is_flagged(ready: dict[str, Any]) -> None:
    _set_policy(ready["db"], max_changed_files=1, paths_deny=["**/.env*", "tests/**"])
    d = ready["d"]
    started = _auto_start(ready)
    exec_id, wt = started["exec_id"], Path(started["worktree_path"])
    d.call_tool("auditor_update_finding_execution",
                {"project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "begin"})
    (wt / "mod.py").write_text("def val() -> int:\n    return 1\n", encoding="utf-8")
    # The red-team scope check only lets the target file and test files change; the policy can be stricter.
    (wt / "tests").mkdir()
    (wt / "tests" / "test_mod.py").write_text("def test_val():\n    assert True\n", encoding="utf-8")
    d.call_tool("auditor_update_finding_execution", {
        "project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "verify",
        "happy_test_passed": True, "adversarial_test_passed": True, "red_team_passed": True})
    review = d.call_tool("auditor_finalize_execution",
                         {"project_key": "svc1", "exec_id": exec_id, "integration_test_passed": True})["review"]
    v = " ".join(review["policy_violations"])
    assert "max_changed_files=1" in v and "tests/test_mod.py" in v and "beyond the auto-approval policy" in review["warning"]
    with connect(ready["db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='AUTO_APPLY_POLICY_EXCEEDED'"
                            ).fetchone()[0] == 1


def test_human_terminal_approval_is_reported_as_such(ready: dict[str, Any]) -> None:
    from db import authorize_execution

    auth = authorize_execution(ready["db"], project_key="svc1", run_id="R-AP",
                               confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION")
    started = ready["d"].call_tool("auditor_start_execution", {"project_key": "svc1", "approval_id": auth["approval_id"]})
    assert started["authorization"] == {"mode": "human_terminal"}


@pytest.mark.parametrize("args", [
    {"project_key": "svc1", "auto_approve": True},  # no run_id
    {"project_key": "svc1", "run_id": "R-AP", "auto_approve": True, "approval_id": "APPR-x123"},
    {"project_key": "svc1"},
])
def test_start_execution_needs_exactly_one_authorization(ready: dict[str, Any], args: dict) -> None:
    _set_policy(ready["db"])
    with pytest.raises(ValueError):
        ready["d"].call_tool("auditor_start_execution", args)


@pytest.mark.parametrize("pattern, path, hit", [
    ("*.py", "src/a/mod.py", True),
    ("src/**", "src/a/b.py", True),
    ("src/**", "lib/src/b.py", False),
    (".github/**", ".github/workflows/ci.yml", True),
    ("**/.env*", "app/.env.local", True),
    ("**/.env*", ".env", True),
    ("docs/*.md", "docs/sub/x.md", False),
    ("SRC/**", "src\\Mod.py", True),
])
def test_path_globs(pattern: str, path: str, hit: bool) -> None:
    policy = {**ap.DEFAULT_POLICY, "paths_deny": [pattern], "paths_allow": []}
    assert bool(ap.path_violations(policy, [path])) is hit


def test_invalid_policies_are_rejected() -> None:
    for bad in ({"severities": ["URGENT"]}, {"max_findings": -1}, {"enabled": "yes"}, {"surprise": 1},
                {"expires_at": "tomorrow"}, {"paths_deny": [""]}):
        with pytest.raises(ValueError):
            ap.validate_policy(bad)


# --- CLI: human-only writes ------------------------------------------------------------------------------------


def _policy_cli(monkeypatch: pytest.MonkeyPatch, argv: list[str], *, tty: bool = True, typed: str = "") -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: tty, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: tty, raising=False)
    monkeypatch.setattr(builtins, "input", lambda prompt="": typed)
    monkeypatch.setattr(sys, "argv", ["cli.py", "apply-policy", *argv])
    cli.main()


def test_policy_set_requires_a_terminal_and_the_typed_confirmation(ready: dict[str, Any],
                                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    argv = ["set", "--project", "svc1", "--enable", "--severities", "LOW,MEDIUM", "--paths-allow", "*.py",
            "--allow-single-model"]
    with pytest.raises(SystemExit) as exc:
        _policy_cli(monkeypatch, argv, tty=False)
    assert exc.value.code == 3
    with pytest.raises(SystemExit):
        _policy_cli(monkeypatch, argv, typed="yes")
    with connect(ready["db"]) as conn:
        assert ap.get_policy(conn, "svc1")[1] == "default"
    _policy_cli(monkeypatch, argv, typed="POLICY svc1")
    with connect(ready["db"]) as conn:
        policy, source = ap.get_policy(conn, "svc1")
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='APPLY_POLICY_SET'").fetchone()[0] == 1
    assert source == "svc1" and policy["enabled"] is True and policy["paths_allow"] == ["*.py"]
    assert _auto_start(ready)["authorization"]["mode"] == "auto_policy"


def test_policy_cli_check_show_and_remove(ready: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
                                          capsys: pytest.CaptureFixture[str]) -> None:
    _set_policy(ready["db"], "*")
    _policy_cli(monkeypatch, ["check", "--project", "svc1", "--run-id", "R-AP"], tty=False)
    assert '"eligible": true' in capsys.readouterr().out
    _policy_cli(monkeypatch, ["show", "--project", "svc1"], tty=False)
    assert '"source": "*"' in capsys.readouterr().out
    with pytest.raises(SystemExit):
        _policy_cli(monkeypatch, ["set", "--project", "nope", "--enable"], typed="POLICY nope")
    _policy_cli(monkeypatch, ["remove", "--project", "*"], typed="POLICY-REMOVE *")
    with connect(ready["db"]) as conn:
        assert ap.get_policy(conn, "svc1")[1] == "default"


def test_mcp_cannot_change_the_policy() -> None:
    from mcp_server import TOOL_DEFINITIONS

    names = {t["name"] for t in TOOL_DEFINITIONS}
    assert not any("policy" in n for n in names)


# --- provider quota ----------------------------------------------------------------------------------------------


def _parsed(events: list | None = None) -> StreamJsonParseResult:
    return StreamJsonParseResult(None, None, "FAILED", "", 0, 0, 0, 0, 0.0, [], list(events or []), 0, True)


@pytest.mark.parametrize("stderr, events, expected", [
    ("Error: RESOURCE_EXHAUSTED: Quota exceeded for model. Retry after 120s", None, (True, 120)),
    ("HTTP 429 Too Many Requests", None, (True, None)),
    ("You have reached your quota. Resets in 3h", None, (True, 10800)),
    ("model quota exhausted, try again in 15 minutes", None, (True, 900)),
    ("", [{"event": "error", "error": {"code": "RESOURCE_EXHAUSTED", "message": "x"}}], (True, None)),
    ("", [{"event": "result", "result": {"status": "ERROR", "error": "Rate limit exceeded"}}], (True, None)),
    ("connection reset by peer", None, (False, None)),
    ("SyntaxError at line 429", None, (False, None)),
    ("", [{"event": "assistant", "text": "the quota was exceeded in the code"}], (False, None)),
])
def test_quota_detection(stderr: str, events: list | None, expected: tuple) -> None:
    assert check_quota_exhausted(stderr, _parsed(events)) == expected


def _quota_worker(tmp_path: Path, retry_after: int | None) -> tuple[Path, VerificationWorker]:
    from unittest.mock import MagicMock

    db_path, repo_dir = _seed_db(tmp_path, run_id="RUN-Q", status="ANALYZING")
    ingest_findings(db_path, project_key="p2", run_id="RUN-Q", findings=[{
        **FINDING, "finding_id": "F-Q", "fingerprint": "fp-q", "file_path": "src/payment.py", "symbol": "charge",
        "line_start": 1, "line_end": 4, "evidence": "def charge(amount: int):", "severity": "HIGH"}],
        repo_path=repo_dir, report_dir=tmp_path / "reports")
    worker = VerificationWorker(db_path)
    adapter = MagicMock(spec=["start_new_conversation", "discover_executable"])
    adapter.start_new_conversation.return_value = replace(
        make_dispatch_result(ok=False, status="PROVIDER_QUOTA_EXHAUSTED", error="RESOURCE_EXHAUSTED"),
        error_code="PROVIDER_QUOTA_EXHAUSTED", retry_after_seconds=retry_after)
    worker.adapter = adapter
    return db_path, worker


@pytest.mark.parametrize("retry_after, min_wait", [(None, 3500), (7200, 7100), (5, 55)])
def test_quota_refusal_parks_the_job_without_spending_an_attempt(tmp_path: Path, retry_after: int | None,
                                                                  min_wait: int) -> None:
    from datetime import datetime, timezone

    db_path, worker = _quota_worker(tmp_path, retry_after)
    res = worker.process_one_job()
    assert res["status"] == "WAITING_PROVIDER_QUOTA"
    with connect(db_path) as conn:
        job = conn.execute("SELECT status, attempt_count, next_attempt_at, last_error_code "
                           "FROM verification_dispatch_queue").fetchone()
        run = conn.execute("SELECT status FROM audit_runs WHERE run_id='RUN-Q'").fetchone()
        ev = conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='VERIFICATION_WAITING_PROVIDER_QUOTA'"
                          ).fetchone()[0]
    assert job["status"] == "RETRYABLE_FAILURE" and job["attempt_count"] == 0
    assert job["last_error_code"] == "PROVIDER_QUOTA_EXHAUSTED" and run["status"] == "VERIFICATION_PENDING" and ev == 1
    wait = (datetime.fromisoformat(job["next_attempt_at"]) - datetime.now(timezone.utc)).total_seconds()
    assert wait >= min_wait
    # Not picked up again before the quota is expected back.
    assert worker.process_one_job() is None


def test_repeated_quota_refusals_never_exhaust_the_job(tmp_path: Path) -> None:
    db_path, worker = _quota_worker(tmp_path, 60)
    for _ in range(5):
        with connect(db_path) as conn:
            conn.execute("UPDATE verification_dispatch_queue SET next_attempt_at='2000-01-01T00:00:00+00:00'")
            conn.commit()
        assert worker.process_one_job()["status"] == "WAITING_PROVIDER_QUOTA"
    with connect(db_path) as conn:
        assert conn.execute("SELECT status FROM verification_dispatch_queue").fetchone()[0] == "RETRYABLE_FAILURE"


def test_quota_refusal_does_not_count_against_the_scarce_budget() -> None:
    from agy_adapter import AntigravityCliAdapter
    from model_budget import ArgonBudgetConfig, ModelBudgetTracker
    from model_policy import ExecutionIntent, TaskType
    from test_review_fixes_2026_11 import ARGON

    refused = replace(make_dispatch_result(ok=False, status="PROVIDER_QUOTA_EXHAUSTED", total_tokens=0),
                      error_code="PROVIDER_QUOTA_EXHAUSTED")
    tracker = ModelBudgetTracker(ArgonBudgetConfig(max_concurrent_jobs=1))
    adapter = AntigravityCliAdapter(executable_override="agy-not-used")
    adapter.dispatch = lambda **kw: refused  # type: ignore[method-assign]
    kwargs = dict(task_type=TaskType.CRITICAL_VERIFICATION, severity="CRITICAL", finding_category="DATABASE_INTEGRITY",
                  evidence_gate_status="PASSED", execution_intent=ExecutionIntent.REQUIRED_CRITICAL_VERIFICATION,
                  audit_run_id="RUN-QB", finding_fingerprint="fp-qb", budget_tracker=tracker, model_id=ARGON)
    first = adapter.start_new_conversation("x", **kwargs)
    second = adapter.start_new_conversation("x", **kwargs)  # same finding again: not REJECTED_DUPLICATE
    assert first.status == second.status == "PROVIDER_QUOTA_EXHAUSTED"
    assert tracker.get_run_usage("RUN-QB")["requests"] == 0


def _pipeline(monkeypatch: pytest.MonkeyPatch, dispatch: Any, jobs: list[Any]) -> dict[str, Any]:
    class _W:
        def __init__(self) -> None:
            self.jobs = list(jobs)

        def process_one_job(self) -> Any:
            return self.jobs.pop(0) if self.jobs else None

    monkeypatch.setattr(cli, "dispatch", dispatch)
    monkeypatch.setattr(cli, "VerificationWorker", lambda *a, **k: _W())
    monkeypatch.setattr(cli, "_resumable_verification_run", lambda project_key: None)
    monkeypatch.setattr(cli, "_weekly_gate", lambda project_key, manual=False: None)
    monkeypatch.setattr(cli, "_seconds_until_retry", lambda run_id: 3600.0)
    monkeypatch.setattr(cli, "_sleep", lambda s: pytest.fail("must not sleep an hour"))
    monkeypatch.setattr(cli, "finalize_verified_report", lambda *a, **k: pytest.fail("must not finalize"))
    return cli.scheduled_audit("p")


def test_pipeline_reports_a_verification_waiting_for_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    out = _pipeline(monkeypatch, lambda project_key: {"run_id": "R", "status": "VERIFICATION_PENDING"},
                    [{"audit_run_id": "R", "status": "WAITING_PROVIDER_QUOTA", "retry_at": "2026-11-16T10:00:00"}])
    assert out["result"] == "VERIFICATION_WAITING_PROVIDER_QUOTA" and out["retry_at"] == "2026-11-16T10:00:00"


def test_pipeline_reports_a_primary_audit_waiting_for_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(project_key: str) -> Any:
        raise cli.ProviderQuotaExhausted("quota exhausted", 900)

    out = _pipeline(monkeypatch, refuse, [])
    assert out["result"] == "PRIMARY_WAITING_PROVIDER_QUOTA" and out["primary"]["retry_after_seconds"] == 900
    assert out["primary"]["error"].startswith("PROVIDER_QUOTA_EXHAUSTED")


def test_quota_failed_primary_runs_do_not_count_toward_the_retry_limit() -> None:
    import inspect

    assert "NOT LIKE 'PROVIDER_QUOTA_EXHAUSTED%'" in inspect.getsource(cli.dispatch)


# --- review round 1 -----------------------------------------------------------------------------------------------


def _age_run(db_path: Path, run_id: str, days: float) -> None:
    from datetime import datetime, timedelta, timezone

    ts = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with connect(db_path) as conn:
        conn.execute("UPDATE audit_runs SET started_at=?, heartbeat_at=? WHERE run_id=?", (ts, ts, run_id))
        conn.commit()


def test_a_run_waiting_for_quota_survives_stale_recovery_for_weeks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from db import recover_stale_runs

    db_path, worker = _quota_worker(tmp_path, None)
    assert worker.process_one_job()["status"] == "WAITING_PROVIDER_QUOTA"
    _age_run(db_path, "RUN-Q", 8)  # a week later
    recover_stale_runs(db_path)
    with connect(db_path) as conn:
        assert conn.execute("SELECT status FROM audit_runs WHERE run_id='RUN-Q'").fetchone()[0] == "VERIFICATION_PENDING"
        assert conn.execute("SELECT status FROM verification_dispatch_queue").fetchone()[0] == "RETRYABLE_FAILURE"
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "JSONL_PATH", tmp_path / "events.jsonl")
    assert cli._resumable_verification_run("p2")["run_id"] == "RUN-Q"
    _age_run(db_path, "RUN-Q", 31)  # hard cap
    recover_stale_runs(db_path)
    with connect(db_path) as conn:
        assert conn.execute("SELECT status FROM audit_runs WHERE run_id='RUN-Q'").fetchone()[0] == "STALE"


def test_a_run_whose_jobs_are_exhausted_is_still_recovered(tmp_path: Path) -> None:
    from db import recover_stale_runs

    db_path, worker = _quota_worker(tmp_path, None)
    worker.process_one_job()
    with connect(db_path) as conn:
        conn.execute("UPDATE verification_dispatch_queue SET attempt_count=max_attempts")
        conn.commit()
    _age_run(db_path, "RUN-Q", 1)
    recover_stale_runs(db_path)
    with connect(db_path) as conn:
        # No job can make progress any more: the run no longer holds the project lock.
        assert conn.execute("SELECT status FROM audit_runs WHERE run_id='RUN-Q'").fetchone()[0] in (
            "STALE", "VERIFICATION_FAILED")


@pytest.mark.parametrize("path, expect", [
    ("src/../.github/workflows/ci.yml", "paths_deny"),
    ("src/./secrets//k.py", "paths_deny"),
    ("/etc/passwd", "leaves the repository"),
    ("C:/Windows/x.py", "leaves the repository"),
    ("..\\outside.py", "leaves the repository"),
    ("src/../../outside.py", "leaves the repository"),
])
def test_path_tricks_cannot_bypass_the_policy(path: str, expect: str) -> None:
    policy = ap.validate_policy({"paths_allow": ["src/**", ".github/**"], "paths_deny": [".github/**", "src/secrets/**"]})
    v = ap.path_violations(policy, [path])
    assert v and expect in v[0]


def test_concurrent_auto_approval_beyond_the_daily_limit_revokes_itself(ready: dict[str, Any],
                                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    _set_policy(ready["db"], max_per_day=1)
    assert _auto_start(ready)["authorization"]["mode"] == "auto_policy"  # consumes the day's only slot
    real = ap.evaluate
    # A concurrent caller that evaluated before the first approval was written:
    monkeypatch.setattr(ap, "evaluate", lambda *a, **k: {**real(*a, **k), "eligible": True, "reasons": []})
    with connect(ready["db"]) as conn:
        conn.execute("UPDATE execution_runs SET status='COMPLETED'")
        conn.commit()
    ready["d"].call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-AP",
                                                    "decisions": [{"finding_id": "F-AP-1", "decision": "APPLY"}]})
    with pytest.raises(PermissionError, match="concurrent"):
        ap.auto_authorize(ready["db"], project_key="svc1", run_id="R-AP")
    statuses = sorted(r["status"] for r in _approvals(ready["db"]))
    assert statuses == ["CONSUMED", "REVOKED"]


def test_corrupted_policy_does_not_crash_show_or_set(ready: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
                                                      capsys: pytest.CaptureFixture[str]) -> None:
    with connect(ready["db"]) as conn:
        ap.ensure_schema(conn)
        conn.execute("INSERT INTO apply_policies(project_key, policy_json, updated_by) VALUES('svc1', '{oops', 'x')")
        conn.commit()
    _policy_cli(monkeypatch, ["show"], tty=False)
    assert '"INVALID": true' in capsys.readouterr().out
    _policy_cli(monkeypatch, ["set", "--project", "svc1", "--enable"], typed="POLICY svc1")
    with connect(ready["db"]) as conn:
        policy, source = ap.get_policy(conn, "svc1")
    assert source == "svc1" and policy["enabled"] is True and policy["severities"] == ["LOW", "MEDIUM"]


def test_resumed_run_still_parked_for_quota_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_parked_for_provider_quota", lambda run_id: "2026-11-20T10:00:00+00:00")
    out = _pipeline(monkeypatch, lambda project_key: {"run_id": "R", "status": "VERIFICATION_PENDING"}, [])
    assert out["result"] == "VERIFICATION_WAITING_PROVIDER_QUOTA" and out["retry_at"].startswith("2026-11-20")

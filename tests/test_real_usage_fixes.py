"""Regressions for issues found by the real-usage scenario simulation (2026-11-16)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import cli  # noqa: E402
from db import check_database_integrity, connect, recover_stale_runs  # noqa: E402
from runtime_discovery.redaction import redact_report_text  # noqa: E402
from test_apply_policy_and_quota import _git, ready  # noqa: E402,F401  (fixture)


def _run_status(db: Path, run_id: str = "R-AP") -> str:
    with connect(db) as conn:
        return str(conn.execute("SELECT status FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()[0])


# --- the project lock is released once nothing is left to review --------------------------------------------------


def test_deciding_every_finding_completes_the_run_and_can_be_revised(ready: dict[str, Any]) -> None:
    d = ready["d"]
    res = d.call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-AP",
                                                 "decisions": [{"finding_id": "F-AP-1", "decision": "DISMISS"}]})
    assert res["run_completed"] is True and _run_status(ready["db"]) == "COMPLETED"
    # changing the mind later reopens the run (no newer audit exists yet)
    res = d.call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-AP",
                                                 "decisions": [{"finding_id": "F-AP-1", "decision": "APPLY"}]})
    assert res["run_completed"] is False and _run_status(ready["db"]) == "READY_FOR_REVIEW"


def test_apply_decision_keeps_the_run_open_for_execution(ready: dict[str, Any]) -> None:
    # the fixture already saved APPLY: the run must stay reviewable so it can be authorized
    assert _run_status(ready["db"]) == "READY_FOR_REVIEW"


def test_a_reviewed_run_cannot_be_reopened_after_a_newer_audit(ready: dict[str, Any]) -> None:
    d = ready["d"]
    d.call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-AP",
                                           "decisions": [{"finding_id": "F-AP-1", "decision": "DEFER"}]})
    with connect(ready["db"]) as conn:
        conn.execute("INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash, started_at) "
                     "VALUES('R-NEW', 'svc1', 'READY_FOR_REVIEW', 'x', 'th', datetime('now','+1 minute'))")
        conn.commit()
    with pytest.raises(RuntimeError, match="newer audit run 'R-NEW'"):
        d.call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-AP",
                                               "decisions": [{"finding_id": "F-AP-1", "decision": "DISMISS"}]})


# --- executions: activity-based staleness, unfinished work kept, worktree removed ----------------------------------


def _start(ready: dict[str, Any]) -> tuple[str, Path]:
    from db import authorize_execution

    auth = authorize_execution(ready["db"], project_key="svc1", run_id="R-AP",
                               confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION")
    st = ready["d"].call_tool("auditor_start_execution", {"project_key": "svc1", "approval_id": auth["approval_id"]})
    return st["exec_id"], Path(st["worktree_path"])


def test_an_active_long_execution_is_not_recovered_as_stale(ready: dict[str, Any]) -> None:
    exec_id, wt = _start(ready)
    with connect(ready["db"]) as conn:
        conn.execute("UPDATE execution_runs SET started_at=datetime('now','-3 hours')")
        conn.commit()
    ready["d"].call_tool("auditor_update_finding_execution",
                         {"project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "begin"})
    recover_stale_runs(ready["db"])
    with connect(ready["db"]) as conn:
        assert conn.execute("SELECT status FROM execution_runs").fetchone()[0] == "RUNNING"
    assert wt.exists()


def test_an_abandoned_execution_keeps_its_diff_and_loses_its_worktree(ready: dict[str, Any]) -> None:
    exec_id, wt = _start(ready)
    ready["d"].call_tool("auditor_update_finding_execution",
                         {"project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "begin"})
    (wt / "mod.py").write_text("def val() -> int:\n    return 1\n", encoding="utf-8")
    with connect(ready["db"]) as conn:
        conn.execute("UPDATE execution_runs SET started_at=datetime('now','-7 hours'), "
                     "heartbeat_at=datetime('now','-7 hours')")
        conn.commit()
    res = recover_stale_runs(ready["db"])
    assert res["recovered_execution_runs"] == [exec_id]
    patch = ready["db"].parent.parent / "quarantine" / "stale-executions" / f"{exec_id}.patch"
    assert patch.is_file() and "-> int" in patch.read_text(encoding="utf-8")
    assert not wt.exists()
    assert len(_git(ready["repo"], "worktree", "list").stdout.strip().splitlines()) == 1


# --- secrets and in-repo files ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("text, secret", [
    ('STRIPE_KEY = "sk-live-51HxYz0123456789abcdefABCDEF0123"', "sk-live-51HxYz"),
    ('password = "hunter2hunter"', "hunter2hunter"),
    ("DB_PASSWORD=Sup3rS3cretValue99", "Sup3rS3cretValue99"),
    ("postgres://admin:s3cr3t@db:5432/x", "s3cr3t"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----", "MIIEowIBAAKCAQEA"),
    ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345", "abcdefghijklmnopqrstuvwxyz012345"),
])
def test_reports_never_contain_secrets(text: str, secret: str) -> None:
    assert secret not in redact_report_text(text)


@pytest.mark.parametrize("text", [
    "Non-constant-time token comparison in auth.py",
    "Bearer tokens are compared with ==",
    'password = request.form["password"]',
    "token = get_token(user)",
    "secret = settings.SECRET_KEY",
    '"token_count": 123',
])
def test_report_redaction_keeps_ordinary_text(text: str) -> None:
    assert redact_report_text(text) == text


def test_in_repo_audit_folder_is_locally_git_excluded(tmp_path: Path) -> None:
    from verification import ensure_audit_dir_git_excluded

    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    ensure_audit_dir_git_excluded(repo)
    ensure_audit_dir_git_excluded(repo)  # idempotent
    (repo / ".antigravity-audit" / "reports").mkdir(parents=True)
    (repo / ".antigravity-audit" / "reports" / "x.md").write_text("x", encoding="utf-8")
    assert _git(repo, "status", "--porcelain").stdout.strip() == ""
    exclude = (repo / ".git" / "info" / "exclude").read_text(encoding="utf-8")
    assert exclude.count("/.antigravity-audit/") == 1


# --- operations -------------------------------------------------------------------------------------------------------


def test_corrupt_database_is_reported_not_raised(tmp_path: Path) -> None:
    from db import initialize

    db = tmp_path / "database" / "auditor.db"
    initialize(db)
    data = bytearray(db.read_bytes())
    for i in range(len(data) // 3, len(data) // 3 + 8192):
        if i < len(data):
            data[i] = 0x5A
    db.write_bytes(bytes(data))
    res = check_database_integrity(db)
    assert res["ok"] is False and ("DATABASE_CORRUPT" in res.get("error", "") or res.get("integrity_check") != ["ok"])


def test_weekly_pipeline_reports_primary_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(project_key: str) -> Any:
        raise FileNotFoundError("Antigravity CLI executable (agy.exe) not found")

    monkeypatch.setattr(cli, "dispatch", boom)
    monkeypatch.setattr(cli, "_resumable_verification_run", lambda project_key: None)
    monkeypatch.setattr(cli, "_weekly_gate", lambda project_key, manual=False: None)
    out = cli.scheduled_audit("p")
    assert out["result"] == "PRIMARY_FAILED" and "agy.exe" in out["primary"]["error"]


def test_integrity_check_command_reports_a_corrupt_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                           capsys: pytest.CaptureFixture[str]) -> None:
    from db import initialize

    db = tmp_path / "database" / "auditor.db"
    initialize(db)
    data = bytearray(db.read_bytes())
    for i in range(len(data) // 3, min(len(data), len(data) // 3 + 8192)):
        data[i] = 0x5A
    db.write_bytes(bytes(data))
    monkeypatch.setattr(cli, "DB_PATH", db)
    monkeypatch.setattr(sys, "argv", ["cli.py", "integrity-check"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1 and '"ok": false' in capsys.readouterr().out


def test_stale_cleanup_never_deletes_a_directory_outside_the_managed_worktrees(ready: dict[str, Any]) -> None:
    exec_id, wt = _start(ready)
    with connect(ready["db"]) as conn:
        # a damaged row pointing at the user's own repository
        conn.execute("UPDATE execution_runs SET worktree_path=?, started_at=datetime('now','-7 hours'), "
                     "heartbeat_at=datetime('now','-7 hours')", (str(ready["repo"]),))
        conn.commit()
    recover_stale_runs(ready["db"])
    assert (ready["repo"] / "mod.py").is_file() and (ready["repo"] / ".git").is_dir()


# --- review round 2 -----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("text, secret", [
    ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    ("Authorization: Bearer dev_token_123", "dev_token_123"),
    ('headers["Authorization"] = "Token abc123xyz"', "abc123xyz"),
])
def test_short_authorization_credentials_are_redacted(text: str, secret: str) -> None:
    assert secret not in redact_report_text(text)


def test_findings_json_is_redacted_before_serialization() -> None:
    import json

    from runtime_discovery.redaction import redact_report_obj

    out = json.dumps(redact_report_obj([{"evidence": 'api_key = "supersecret123"', "line_start": 3}]))
    assert "supersecret123" not in out and '"line_start": 3' in out


def test_deciding_during_an_active_execution_does_not_release_the_run(ready: dict[str, Any]) -> None:
    exec_id, _ = _start(ready)
    res = ready["d"].call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-AP",
                                                          "decisions": [{"finding_id": "F-AP-1", "decision": "DEFER"}]})
    assert res["run_completed"] is False and _run_status(ready["db"]) == "READY_FOR_REVIEW"


def test_same_second_older_run_does_not_block_reopening(ready: dict[str, Any]) -> None:
    d = ready["d"]
    with connect(ready["db"]) as conn:
        started = conn.execute("SELECT started_at FROM audit_runs WHERE run_id='R-AP'").fetchone()[0]
        # an OLDER run (lower rowid) that started in the same second
        conn.execute("INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash, started_at) "
                     "VALUES('R-OLD', 'svc1', 'COMPLETED', 'x', 'th', ?)", (started,))
        conn.execute("UPDATE audit_runs SET rowid=(SELECT MAX(rowid)+100 FROM audit_runs) WHERE run_id='R-AP'")
        conn.commit()
    d.call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-AP",
                                           "decisions": [{"finding_id": "F-AP-1", "decision": "DISMISS"}]})
    res = d.call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-AP",
                                                 "decisions": [{"finding_id": "F-AP-1", "decision": "DEFER"}]})
    assert res["counts"]["DEFER"] == 1

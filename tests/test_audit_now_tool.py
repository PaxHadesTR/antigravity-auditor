"""MCP auditor_audit_now: background launch of `cli.py audit-now` with quota guards. No real audit is spawned."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_launcher  # noqa: E402
from db import connect, initialize  # noqa: E402
from mcp_server import AuditorMCPDispatcher  # noqa: E402


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture()
def env(tmp_path: Path) -> dict[str, Any]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    db = tmp_path / "database" / "auditor.db"
    initialize(db)
    with connect(db) as conn:
        conn.execute("INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id) "
                     "VALUES('p', 'P', ?, 'ag')", (str(repo),))
        conn.commit()
    d = AuditorMCPDispatcher(db_path=db, app_home=tmp_path)
    spawned: list[dict[str, Any]] = []

    def fake_spawn(command: list[str], *, env: dict[str, str], log_path: Path) -> int:
        spawned.append({"command": command, "env": env, "log": log_path})
        return os.getpid()  # an alive pid: the launch counts as "preparing"

    d.audit_spawn = fake_spawn
    return {"d": d, "db": db, "repo": repo, "home": tmp_path, "spawned": spawned}


def _run(env: dict[str, Any], run_id: str, status: str, *, current_code: bool = True) -> None:
    from verification import compute_clean_working_tree_hash

    head = _git(env["repo"], "rev-parse", "HEAD") if current_code else "0" * 40
    with connect(env["db"]) as conn:
        conn.execute("INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash) "
                     "VALUES(?, 'p', ?, ?, ?)", (run_id, status, head, compute_clean_working_tree_hash(env["repo"])))
        conn.commit()


def _call(env: dict[str, Any], **args: Any) -> dict[str, Any]:
    return env["d"].call_tool("auditor_audit_now", {"project_key": "p", **args})


def test_first_audit_starts_in_the_background(env: dict[str, Any]) -> None:
    res = _call(env)
    assert res["status"] == "STARTED" and res["chat_audits_left_today"] == 2
    cmd = env["spawned"][0]["command"]
    assert cmd[-3:] == ["audit-now", "--project", "p"] and cmd[1].endswith("cli.py")
    assert env["spawned"][0]["env"]["ANTIGRAVITY_AUDITOR_DB"] == str(env["db"])
    with connect(env["db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type=?",
                            (audit_launcher.LAUNCH_EVENT,)).fetchone()[0] == 1


def test_second_call_while_preparing_does_not_spawn_again(env: dict[str, Any]) -> None:
    assert _call(env)["status"] == "STARTED"
    assert _call(env)["status"] == "ALREADY_RUNNING"
    assert len(env["spawned"]) == 1


def test_dead_launch_process_does_not_block(env: dict[str, Any]) -> None:
    assert _call(env)["status"] == "STARTED"
    lock = audit_launcher._lock_path(env["home"], "p")
    lock.write_text(json.dumps({"pid": 999999999}), encoding="utf-8")
    assert _call(env)["status"] == "STARTED"


def test_running_audit_is_reported(env: dict[str, Any]) -> None:
    _run(env, "R1", "VERIFICATION_PENDING")
    res = _call(env)
    assert res["status"] == "ALREADY_RUNNING" and res["run_id"] == "R1" and not env["spawned"]


def test_waiting_report_needs_explicit_replace(env: dict[str, Any]) -> None:
    _run(env, "R1", "READY_FOR_REVIEW")
    res = _call(env)
    assert res["status"] == "REPORT_WAITING_FOR_REVIEW" and res["run_id"] == "R1" and not env["spawned"]
    res = _call(env, replace_pending_report=True)
    assert res["status"] == "STARTED" and res["replaces_run_id"] == "R1"


def test_unchanged_code_needs_force(env: dict[str, Any]) -> None:
    _run(env, "R1", "COMPLETED")
    assert _call(env)["status"] == "NO_CHANGES" and not env["spawned"]
    assert _call(env, force=True)["status"] == "STARTED"


def test_changed_code_starts_without_force(env: dict[str, Any]) -> None:
    _run(env, "R1", "COMPLETED", current_code=False)
    assert _call(env)["status"] == "STARTED"


def test_daily_limit(env: dict[str, Any]) -> None:
    for _ in range(audit_launcher.DAILY_CHAT_AUDIT_LIMIT):
        assert _call(env)["status"] == "STARTED"
        audit_launcher._lock_path(env["home"], "p").unlink()  # the previous audit finished
    res = _call(env)
    assert res["status"] == "DAILY_LIMIT_REACHED" and "audit-now --project p" in res["hint"]
    assert len(env["spawned"]) == audit_launcher.DAILY_CHAT_AUDIT_LIMIT


def test_unknown_project_is_refused(env: dict[str, Any]) -> None:
    with pytest.raises(RuntimeError, match="not registered"):
        env["d"].call_tool("auditor_audit_now", {"project_key": "nope"})


def test_antigravity_caller_has_the_audit_run_scope() -> None:
    from application_adapters.stdio_entry import ANTIGRAVITY_STDIO_AUDIT_LIFECYCLE_SCOPES
    from mcp_gateway import CanonicalCatalogRegistry

    tool = next(t for t in CanonicalCatalogRegistry().list_ordered() if t.tool_name == "auditor_audit_now")
    assert set(tool.required_authorization_scopes) <= ANTIGRAVITY_STDIO_AUDIT_LIFECYCLE_SCOPES
    assert tool.execution_mutating is False


def test_real_spawn_runs_detached_and_logs(tmp_path: Path) -> None:
    log = tmp_path / "logs" / "x.log"
    pid = audit_launcher._spawn([sys.executable, "-c", "print('hello-from-audit')"], env=os.environ.copy(), log_path=log)
    assert pid > 0
    import time

    for _ in range(50):
        if not audit_launcher._pid_alive(pid):
            break
        time.sleep(0.1)
    assert "hello-from-audit" in log.read_text(encoding="utf-8")


# --- review fixes ----------------------------------------------------------------------------------------------


def test_concurrent_call_is_serialized(env: dict[str, Any]) -> None:
    with audit_launcher._LaunchMutex(env["home"] / "locks" / "audit-now-p.mutex") as held:
        assert held
        res = _call(env)
    assert res["status"] == "ALREADY_RUNNING" and not env["spawned"]
    assert _call(env)["status"] == "STARTED"  # released afterwards


def test_reused_pid_does_not_block(env: dict[str, Any]) -> None:
    lock = audit_launcher._lock_path(env["home"], "p")
    lock.parent.mkdir(parents=True, exist_ok=True)
    # an alive pid, but with a different creation time: another program now uses that pid
    lock.write_text(json.dumps({"pid": os.getpid(), "process_start": 1}), encoding="utf-8")
    assert _call(env)["status"] == "STARTED"


def test_malformed_lock_file_does_not_crash(env: dict[str, Any]) -> None:
    lock = audit_launcher._lock_path(env["home"], "p")
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(json.dumps({"pid": "bad"}), encoding="utf-8")
    assert _call(env)["status"] == "STARTED"


def test_waiting_report_with_a_pending_fix_is_not_replaced(env: dict[str, Any]) -> None:
    _run(env, "R1", "READY_FOR_REVIEW")
    with connect(env["db"]) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(execution_approvals)")}
        row = {"approval_id": "APPR-x", "project_key": "p", "run_id": "R1", "status": "AUTHORIZED",
               "expires_at": "2999-01-01T00:00:00+00:00", "approval_token": "t", "authorized_by": "user"}
        notnull = {r[1]: r for r in conn.execute("PRAGMA table_info(execution_approvals)")}
        for name, info in notnull.items():
            if info[3] and info[4] is None and name not in row:
                row[name] = "x"
        row = {k: v for k, v in row.items() if k in cols}
        conn.execute(f"INSERT INTO execution_approvals({','.join(row)}) VALUES({','.join('?' for _ in row)})",
                     tuple(row.values()))
        conn.commit()
    res = _call(env, replace_pending_report=True)
    assert res["status"] == "REPORT_IN_USE" and not env["spawned"]
    with connect(env["db"]) as conn:  # no daily slot used
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type=?",
                            (audit_launcher.LAUNCH_EVENT,)).fetchone()[0] == 0


def test_child_output_is_utf8(env: dict[str, Any]) -> None:
    _call(env)
    child_env = env["spawned"][0]["env"]
    assert child_env["PYTHONIOENCODING"] == "utf-8" and child_env["PYTHONUTF8"] == "1"

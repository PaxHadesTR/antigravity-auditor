"""Phase 0 hardening before the standalone move:
- a delivery whose process died (crash, reboot) is restarted, at most twice, then marked FAILED;
- every audit entry point claims the project's lock file under the launch mutex;
- the audited project's tests never see credentials from the environment."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import auto_delivery  # noqa: E402
from audit_launcher import _LaunchMutex, _lock_path, _process_start  # noqa: E402
from ci_check import project_test_environment  # noqa: E402
from db import connect  # noqa: E402
from test_auto_delivery import _stored, env  # noqa: E402,F401  (fixture)

DEAD_PID = 999_999_99  # no such process


def _set_state(env: dict[str, Any], **state: Any) -> str:
    raw = json.dumps({"project_key": "p", "run_id": "R1", "exec_id": "E1", "merge_blockers": [],
                      "queued_at": "2026-01-01T00:00:00Z", "log_path": str(env["db"].parent / "d.log"), **state})
    with connect(env["db"]) as conn:
        conn.execute("UPDATE execution_runs SET delivery_json=? WHERE exec_id='E1'", (raw,))
        conn.commit()
    return raw


def _events(env: dict[str, Any]) -> list[str]:
    with connect(env["db"]) as conn:
        return [r[0] for r in conn.execute("SELECT event_type FROM audit_events ORDER BY event_id")]


@pytest.fixture()
def spawned(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []
    monkeypatch.setattr(auto_delivery, "SPAWN", lambda cmd, *, env, log_path: calls.append(cmd) or DEAD_PID)
    return calls


def test_interrupted_delivery_is_restarted_and_then_runs(env: dict[str, Any], spawned: list[list[str]]) -> None:
    _set_state(env, status="RUNNING", pid=DEAD_PID, process_start=1, started_at="2026-01-01T00:00:00Z",
               steps=["pushed"])
    out = auto_delivery.recover_interrupted_deliveries(env["db"], env["db"].parent.parent)
    assert out == [{"exec_id": "E1", "status": "QUEUED", "attempt": 1}]
    assert spawned and spawned[0][-3:] == ["deliver", "--exec", "E1"]
    state = _stored(env)
    assert state["status"] == "QUEUED" and state["recovery_attempts"] == 1 and state["interrupted_status"] == "RUNNING"
    assert "DELIVERY_RECOVERED" in _events(env)
    # The restarted delivery runs normally (the spawned process would do this) and records its own pid.
    res = env["run"]()
    assert res["status"] == "MERGED", res
    assert res["pid"] == os.getpid()


def test_repeated_interruptions_end_in_failed(env: dict[str, Any], spawned: list[list[str]]) -> None:
    _set_state(env, status="RUNNING", pid=DEAD_PID, process_start=1, recovery_attempts=2)
    out = auto_delivery.recover_interrupted_deliveries(env["db"], env["db"].parent.parent)
    assert out == [{"exec_id": "E1", "status": "FAILED"}] and not spawned
    state = _stored(env)
    assert state["status"] == "FAILED" and "3 times" in state["reason"]
    assert _events(env)[-1] == "DELIVERY_FAILED"
    # A FAILED delivery is never picked up again.
    assert auto_delivery.recover_interrupted_deliveries(env["db"], env["db"].parent.parent) == []


def test_live_or_recent_deliveries_are_left_alone(env: dict[str, Any], spawned: list[list[str]]) -> None:
    me = os.getpid()
    _set_state(env, status="RUNNING", pid=me, process_start=_process_start(me))
    assert auto_delivery.recover_interrupted_deliveries(env["db"]) == []
    # Queued a moment ago, its process not recorded yet: not interrupted.
    now = auto_delivery._now()
    _set_state(env, status="QUEUED", queued_at=now)
    assert auto_delivery.recover_interrupted_deliveries(env["db"]) == []
    # RUNNING without a pid (older rows): only after the longest possible delivery.
    _set_state(env, status="RUNNING", started_at=now)
    assert auto_delivery.recover_interrupted_deliveries(env["db"]) == [] and not spawned
    _set_state(env, status="RUNNING", started_at="2026-01-01T00:00:00Z")
    assert auto_delivery.recover_interrupted_deliveries(env["db"])[0]["status"] == "QUEUED"


def test_a_concurrent_change_wins_over_the_recovery(env: dict[str, Any], spawned: list[list[str]],
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    _set_state(env, status="RUNNING", pid=DEAD_PID, process_start=1)
    real_swap = auto_delivery._swap

    def swap_after_someone_else(db_path: Path, exec_id: str, old_raw: str, state: dict[str, Any]) -> bool:
        _set_state(env, status="PR_OPEN", reason="finished meanwhile")
        return real_swap(db_path, exec_id, old_raw, state)

    monkeypatch.setattr(auto_delivery, "_swap", swap_after_someone_else)
    assert auto_delivery.recover_interrupted_deliveries(env["db"]) == [] and not spawned
    assert _stored(env)["status"] == "PR_OPEN"


def test_queue_delivery_does_not_overwrite_a_claim(env: dict[str, Any], tmp_path: Path,
                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    def spawn_and_claim(cmd: list[str], *, env: dict[str, str], log_path: Path) -> int:
        with connect(db) as conn:  # the child already claimed it before the parent records the pid
            state = json.loads(conn.execute("SELECT delivery_json FROM execution_runs WHERE exec_id='E1'").fetchone()[0])
            state.update(status="RUNNING", pid=os.getpid(), process_start=_process_start(os.getpid()))
            conn.execute("UPDATE execution_runs SET delivery_json=? WHERE exec_id='E1'", (json.dumps(state),))
            conn.commit()
        return DEAD_PID

    db = env["db"]
    monkeypatch.setattr(auto_delivery, "SPAWN", spawn_and_claim)
    auto_delivery.queue_delivery(db, tmp_path, project_key="p", run_id="R1", exec_id="E1",
                                 review={"branch": "b", "commit": "c"}, final_status="COMPLETED")
    stored = _stored(env)
    assert stored["status"] == "RUNNING" and stored["pid"] == os.getpid()


def test_scheduled_audit_claims_the_lock_under_the_mutex(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import cli

    monkeypatch.setattr(cli, "APP_HOME", tmp_path)
    monkeypatch.setattr(cli, "DB_PATH", tmp_path / "database" / "auditor.db")
    monkeypatch.setattr(cli, "AUDIT_LOCK_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(auto_delivery, "recover_interrupted_deliveries", lambda *a, **k: [])
    seen: list[Any] = []

    def pipeline(project_key: str, **kw: Any) -> dict[str, Any]:
        lock = _lock_path(tmp_path, project_key)
        seen.append(json.loads(lock.read_text(encoding="utf-8"))["pid"] if lock.exists() else None)
        return {"status": "OK"}

    monkeypatch.setattr(cli, "_scheduled_audit", pipeline)
    # Free mutex: the lock file names this process while the pipeline runs and is removed afterwards.
    assert cli.scheduled_audit("p")["status"] == "OK"
    assert seen == [os.getpid()] and not _lock_path(tmp_path, "p").exists()
    # Mutex held by another launcher: no lock is claimed (the database still refuses a second active run).
    with _LaunchMutex(tmp_path / "locks" / "audit-now-p.mutex") as held:
        assert held
        cli.scheduled_audit("p")
    assert seen[-1] is None


def test_project_tests_get_no_credentials() -> None:
    base = {
        "PATH": "C:/bin", "SystemRoot": "C:/Windows", "PYTHONPATH": "src", "LC_ALL": "C", "TEMP": "C:/t",
        "GH_TOKEN": "x", "GITHUB_TOKEN": "x", "AWS_SECRET_ACCESS_KEY": "x", "OPENAI_API_KEY": "x",
        "NODE_AUTH_TOKEN": "x", "NPM_CONFIG__AUTH": "x", "ANTIGRAVITY_AUDITOR_DB": "x", "DATABASE_URL": "x",
        "PROD_DB": "x", "MY_SETTING": "1", "MY_API_KEY": "x",
        "ANTIGRAVITY_AUDITOR_TEST_ENV_PASSTHROUGH": "MY_SETTING, MY_API_KEY",
    }
    env = project_test_environment(base)
    assert set(env) == {"PATH", "SystemRoot", "PYTHONPATH", "LC_ALL", "TEMP", "MY_SETTING"}


def test_restart_after_merge_records_merged_without_a_second_pr(env: dict[str, Any]) -> None:
    # The process died right after `gh pr merge` (or the user merged while it was down); recovery re-queued it.
    _set_state(env, status="QUEUED", recovery_attempts=1)
    env["gh"].prs = [{"number": 7, "url": "https://github.com/me/proj/pull/7", "headRefOid": env["sha"],
                      "isCrossRepository": False}]
    res = env["run"]()
    assert res["status"] == "MERGED" and "already_merged" in res["steps"], res
    assert not env["gh"].called("pr", "create") and not env["gh"].called("pr", "merge")
    from test_auto_delivery import BRANCH, _git

    assert not _git(env["remote"], "branch", "--list", BRANCH)  # the branch was not pushed again


def test_unknown_process_start_keeps_a_live_delivery(env: dict[str, Any], spawned: list[list[str]],
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    import audit_launcher

    monkeypatch.setattr(audit_launcher, "_process_start", lambda pid: 0)  # alive, start time unreadable
    _set_state(env, status="RUNNING", pid=1234, process_start=555)
    assert auto_delivery.recover_interrupted_deliveries(env["db"]) == [] and not spawned
    _set_state(env, status="RUNNING", pid=1234, process_start="555")
    assert auto_delivery.recover_interrupted_deliveries(env["db"]) == []


def test_quarantined_executions_are_not_delivered(env: dict[str, Any], spawned: list[list[str]]) -> None:
    _set_state(env, status="RUNNING", pid=DEAD_PID, process_start=1)
    with connect(env["db"]) as conn:
        conn.execute("UPDATE execution_runs SET status='QUARANTINED' WHERE exec_id='E1'")
        conn.commit()
    assert auto_delivery.recover_interrupted_deliveries(env["db"]) == [] and not spawned


def test_a_failed_queue_never_overwrites_a_claimed_delivery(env: dict[str, Any], tmp_path: Path,
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    db = env["db"]

    def spawn_and_claim(cmd: list[str], *, env: dict[str, str], log_path: Path) -> int:
        with connect(db) as conn:
            state = json.loads(conn.execute("SELECT delivery_json FROM execution_runs WHERE exec_id='E1'").fetchone()[0])
            state.update(status="RUNNING", pid=os.getpid())
            conn.execute("UPDATE execution_runs SET delivery_json=? WHERE exec_id='E1'", (json.dumps(state),))
            conn.commit()
        return DEAD_PID

    def broken_event(*a: Any, **k: Any) -> None:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(auto_delivery, "SPAWN", spawn_and_claim)
    monkeypatch.setattr(auto_delivery, "_event", broken_event)
    out = auto_delivery.queue_delivery(db, tmp_path, project_key="p", run_id="R1", exec_id="E1",
                                       review={"branch": "b", "commit": "c"}, final_status="COMPLETED")
    assert out["status"] == "FAILED"  # what the caller is told
    assert _stored(env)["status"] == "RUNNING"  # the running delivery is untouched


def test_proxy_and_tls_pass_but_credentials_in_values_do_not() -> None:
    base = {"HTTPS_PROXY": "http://proxy:8080", "https_proxy": "http://proxy:8080", "REQUESTS_CA_BUNDLE": "ca.pem",
            "GIT_CONFIG_GLOBAL": "g", "PIP_INDEX_URL": "https://user:s3cret@pypi.example/simple",
            "HTTP_PROXY": "http://bob:pw@proxy:8080", "UV_INDEX_URL": "https://pypi.example/simple"}
    env = project_test_environment(base)
    assert set(env) == {"HTTPS_PROXY", "https_proxy", "REQUESTS_CA_BUNDLE", "GIT_CONFIG_GLOBAL", "UV_INDEX_URL"}

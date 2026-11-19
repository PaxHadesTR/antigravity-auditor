"""Fixes from the end-to-end MCP review (2026-11-19): run_id defaults, undecided findings keep a run reviewable,
no audit while a fix runs, parked verification, start failures and logs visible, cache files never part of a fix,
and the auto_merge delivery queued by finalize."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import auto_delivery  # noqa: E402
from db import connect  # noqa: E402
from executor import _list_worktree_files  # noqa: E402
from project_settings import set_settings  # noqa: E402
from test_apply_policy_and_quota import ready  # noqa: E402,F401
from test_audit_now_tool import _call, _run, env  # noqa: E402,F401
from test_simple_approval_ci_and_tests import _fix  # noqa: E402


def _copy_finding(db: Path, new_id: str) -> None:
    with connect(db) as conn:
        row = dict(conn.execute("SELECT * FROM findings WHERE finding_id='F-AP-1'").fetchone())
        row.update(finding_id=new_id, fingerprint=f"fp-{new_id}", lifecycle="OPEN")
        conn.execute(f"INSERT INTO findings({','.join(row)}) VALUES({','.join('?' for _ in row)})", tuple(row.values()))
        conn.commit()


def _run_status(db: Path, run_id: str = "R-AP") -> str:
    with connect(db) as conn:
        return str(conn.execute("SELECT status FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()[0])


# --- run_id defaults (M2) ---------------------------------------------------------------------------------------


def test_save_decisions_and_list_default_to_the_latest_report(ready: dict[str, Any]) -> None:
    d = ready["d"]
    listed = d.call_tool("auditor_list_findings", {"project_key": "svc1"})
    assert listed["run_id"] == "R-AP" and listed["count"] >= 1
    assert d.call_tool("auditor_list_findings", {"project_key": "svc1", "all_runs": True})["run_id"] is None
    res = d.call_tool("auditor_save_decisions", {"project_key": "svc1",
                                                 "decisions": [{"finding_id": "F-AP-1", "decision": "DEFER"}]})
    assert res
    # every finding decided: the report is closed, so "the report" now means every run again
    assert d.call_tool("auditor_list_findings", {"project_key": "svc1"})["run_id"] is None


# --- undecided findings keep the run reviewable (M3) ------------------------------------------------------------


def test_undecided_finding_keeps_the_run_partial(ready: dict[str, Any]) -> None:
    _copy_finding(ready["db"], "F-AP-2")
    _fix(ready, {"project_key": "svc1", "chat_approved": True})
    assert _run_status(ready["db"]) == "PARTIAL"
    res = ready["d"].call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-AP",
                                                          "decisions": [{"finding_id": "F-AP-2", "decision": "DEFER"}]})
    assert res


def test_fully_decided_run_completes(ready: dict[str, Any]) -> None:
    _fix(ready, {"project_key": "svc1", "chat_approved": True})
    assert _run_status(ready["db"]) == "COMPLETED"


# --- auto_merge is queued by finalize ---------------------------------------------------------------------------


def test_finalize_queues_the_auto_merge_delivery(ready: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    spawned: list[list[str]] = []
    monkeypatch.setattr(auto_delivery, "SPAWN", lambda cmd, *, env, log_path: spawned.append(cmd) or 4321)
    with connect(ready["db"]) as conn:
        set_settings(conn, "svc1", delivery_mode="auto_merge")
        conn.commit()
    review = _fix(ready, {"project_key": "svc1", "chat_approved": True})["fin"]["review"]
    assert review["delivery"]["status"] == "QUEUED" and spawned and spawned[0][-1] == review["delivery"]["exec_id"]
    status = ready["d"].call_tool("auditor_get_status", {"project_key": "svc1"})["projects"][0]
    assert status["latest_delivery"]["exec_id"] == review["delivery"]["exec_id"]


def test_local_mode_queues_nothing(ready: dict[str, Any]) -> None:
    review = _fix(ready, {"project_key": "svc1", "chat_approved": True})["fin"]["review"]
    assert "delivery" not in review


# --- launcher: fix in progress (M4), parked verification (M5), log in status (M6) -------------------------------


def test_no_audit_while_a_fix_runs(env: dict[str, Any]) -> None:
    _run(env, "R1", "COMPLETED", current_code=False)
    with connect(env["db"]) as conn:
        cols = {r[1]: r for r in conn.execute("PRAGMA table_info(execution_runs)")}
        row = {"exec_id": "E-RUN", "project_key": "p", "run_id": "R1", "status": "RUNNING"}
        for name, info in cols.items():
            if info[3] and info[4] is None and name not in row and not info[5]:
                row[name] = "x"
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute(f"INSERT INTO execution_runs({','.join(row)}) VALUES({','.join('?' for _ in row)})",
                     tuple(row.values()))
        conn.commit()
    res = _call(env)
    assert res["status"] == "FIX_IN_PROGRESS" and not env["spawned"]


def _park(env: dict[str, Any], next_attempt: str) -> None:
    _run(env, "R1", "VERIFICATION_PENDING")
    with connect(env["db"]) as conn:
        cols = {r[1]: r for r in conn.execute("PRAGMA table_info(verification_dispatch_queue)")}
        row = {"job_id": "J1", "audit_run_id": "R1", "project_key": "p", "status": "RETRYABLE_FAILURE",
               "attempt_count": 1, "max_attempts": 3, "next_attempt_at": next_attempt,
               "last_error_code": "PROVIDER_QUOTA_EXHAUSTED"}
        for name, info in cols.items():
            if info[3] and info[4] is None and name not in row and not info[5]:
                row[name] = "x"
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute(f"INSERT INTO verification_dispatch_queue({','.join(row)}) VALUES({','.join('?' for _ in row)})",
                     tuple(row.values()))
        conn.commit()


def test_parked_verification_is_reported_until_due(env: dict[str, Any]) -> None:
    _park(env, "2999-01-01T00:00:00+00:00")
    res = _call(env)
    assert res["status"] == "VERIFICATION_PARKED" and "PROVIDER_QUOTA_EXHAUSTED" in res["hint"] and not env["spawned"]


def test_due_parked_verification_is_resumed(env: dict[str, Any]) -> None:
    _park(env, "2000-01-01T00:00:00+00:00")
    assert _call(env)["status"] == "STARTED" and env["spawned"]


def test_status_shows_the_latest_audit_log(env: dict[str, Any]) -> None:
    started = _call(env)
    proj = env["d"].call_tool("auditor_get_status", {"project_key": "p"})["projects"][0]
    assert proj["latest_audit_log"] == started["log_path"]


# --- caches are not part of a fix (M8) --------------------------------------------------------------------------


def test_worktree_snapshot_skips_caches(tmp_path: Path) -> None:
    (tmp_path / "pkg" / "__pycache__").mkdir(parents=True)
    (tmp_path / "pkg" / "__pycache__" / "m.cpython-315.pyc").write_bytes(b"x")
    (tmp_path / ".pytest_cache").mkdir()
    (tmp_path / ".pytest_cache" / "v").write_text("x", encoding="utf-8")
    (tmp_path / "pkg" / "m.py").write_text("x = 1\n", encoding="utf-8")
    assert set(_list_worktree_files(tmp_path)) == {"pkg/m.py"}



def test_running_cli_audit_holds_the_lock(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    import cli

    monkeypatch.setattr(cli, "APP_HOME", env["home"])
    seen: dict[str, Any] = {}

    def inner(project_key: str, **kw: Any) -> dict[str, Any]:
        _park(env, "2000-01-01T00:00:00+00:00")  # a weekly audit between its verification attempts
        seen["chat"] = _call(env)
        return {"result": "FINALIZED"}

    monkeypatch.setattr(cli, "_scheduled_audit", inner)
    cli.scheduled_audit("p")
    assert seen["chat"]["status"] == "ALREADY_RUNNING" and not env["spawned"]
    assert not (env["home"] / "locks" / "audit-now-p.json").exists()  # released afterwards


# --- model updates are visible in the status ----------------------------------------------------------------------


def test_status_shows_models_and_a_pending_proposal(env: dict[str, Any]) -> None:
    import model_routing_proposals as mrp

    st = env["d"].call_tool("auditor_get_status", {"project_key": "p"})
    assert st["models"]["active_table"]["assignments"]["STANDARD"].startswith("agy:")
    assert st["models"]["pending_proposal"] is None
    with connect(env["db"]) as conn:
        conn.execute(
            "INSERT INTO routing_table_versions(version_id, host, status, assignments_json, rationale_json, "
            "evidence_json, base_version, created_at) VALUES('RT-x', 'antigravity', 'PROPOSED', ?, ?, '{}', 'seed', "
            "'2026-11-19T00:00:00Z')",
            (json.dumps(st["models"]["active_table"]["assignments"]),
             json.dumps([{"tier": "CRITICAL", "from": "a", "to": "b", "changed": True}])))
        conn.commit()
    assert mrp.pending_proposal(env["db"]) is not None
    prop = env["d"].call_tool("auditor_get_status", {"project_key": "p"})["models"]["pending_proposal"]
    assert prop["version_id"] == "RT-x" and prop["changes"] == [{"tier": "CRITICAL", "from": "a", "to": "b"}]
    assert prop["approve_command"].endswith("models proposal approve RT-x")

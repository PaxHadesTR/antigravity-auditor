"""Regression tests for audit findings ARCH-02 and ARCH-06.

ARCH-02: ``auditor_get_status`` (CORE_READ, reachable even by UNKNOWN callers) must not
write to SQLite or the JSONL audit log when it detects a moved/missing repository.

ARCH-06: the stdio host's request budget is measured after the synchronous call has
finished; a completed (possibly state-changing) response must not be replaced with a
timeout error, otherwise clients retry and duplicate the write.
"""

from __future__ import annotations

import io
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import application_adapters.adapter_runtime as adapter_runtime  # noqa: E402
from application_adapters import CommonStdioAdapterHost, TestBrokerTransport  # noqa: E402
from db import connect, initialize  # noqa: E402
from mcp_server import AuditorMCPDispatcher  # noqa: E402
from recovery import detect_moved_repositories  # noqa: E402


def _snapshot(db_path: Path) -> dict[str, Any]:
    conn = sqlite3.connect(db_path)
    try:
        return {
            "projects": conn.execute(
                "SELECT project_key, health_status, repo_fingerprint, updated_at FROM projects ORDER BY project_key"
            ).fetchall(),
            "audit_events": conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
        }
    finally:
        conn.close()


def _setup_missing_repo_project(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    db_path = home / "database" / "auditor.db"
    initialize(db_path)
    missing_repo = tmp_path / "does-not-exist"
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects(
                project_key, display_name, repo_path, antigravity_project_id,
                repo_fingerprint, min_free_mb, health_status
            ) VALUES('ghost', 'Ghost Repo', ?, 'proj-ghost-1', 'fp-old', 1, 'HEALTHY')""",
            (str(missing_repo),),
        )
        conn.commit()
    return home, db_path


def test_arch02_get_status_reports_live_health_without_writing(tmp_path: Path) -> None:
    home, db_path = _setup_missing_repo_project(tmp_path)
    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=home)
    jsonl = dispatcher.jsonl_path
    jsonl_before = jsonl.read_bytes() if jsonl.exists() else None
    before = _snapshot(db_path)

    result = dispatcher.call_tool("auditor_get_status", {"project_key": "ghost"})

    # The caller still sees the live, accurate health ...
    assert [p["health_status"] for p in result["projects"]] == ["MOVED_OR_MISSING"]
    # ... but nothing was persisted.
    assert _snapshot(db_path) == before
    assert (jsonl.read_bytes() if jsonl.exists() else None) == jsonl_before


def test_arch02_get_status_all_projects_is_also_side_effect_free(tmp_path: Path) -> None:
    home, db_path = _setup_missing_repo_project(tmp_path)
    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=home)
    before = _snapshot(db_path)

    result = dispatcher.call_tool("auditor_get_status", {})

    assert {p["project_key"]: p["health_status"] for p in result["projects"]} == {"ghost": "MOVED_OR_MISSING"}
    assert _snapshot(db_path) == before


def test_arch02_default_persist_behaviour_is_unchanged_for_cli_and_executor(tmp_path: Path) -> None:
    home, db_path = _setup_missing_repo_project(tmp_path)
    jsonl = home / "logs" / "audit-events.jsonl"

    moved = detect_moved_repositories(db_path, project_key="ghost", jsonl_path=jsonl)

    assert moved[0]["health_status"] == "MOVED_OR_MISSING"
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT health_status FROM projects WHERE project_key='ghost'").fetchone()[0] == "MOVED_OR_MISSING"
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE event_type='REPO_MOVED_OR_MISSING'"
        ).fetchone()[0] == 1
    finally:
        conn.close()
    assert "REPO_MOVED_OR_MISSING" in jsonl.read_text(encoding="utf-8")


def test_arch06_slow_completed_request_returns_real_result(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def handler(req: dict[str, Any], _caller: Any) -> dict[str, Any]:
        calls.append(req["method"])
        return {"jsonrpc": "2.0", "id": req.get("id"), "result": {"published": True}}

    ticks = iter([0.0, 120.0])
    monkeypatch.setattr(adapter_runtime.time, "monotonic", lambda: next(ticks))
    stderr = io.StringIO()
    host = CommonStdioAdapterHost(transport=TestBrokerTransport(handler), stderr_stream=stderr, request_timeout_seconds=15.0)

    resp = host.process_raw_payload(b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{}}')

    assert resp == {"jsonrpc": "2.0", "id": 7, "result": {"published": True}}
    assert calls == ["tools/call"]
    assert host.requests_processed == 1
    assert "Slow request" in stderr.getvalue()
    assert "REQUEST_TIMEOUT_EXCEEDED" not in stderr.getvalue()
    host.close()


def test_arch06_fast_request_logs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(req: dict[str, Any], _caller: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req.get("id"), "result": {}}

    ticks = iter([0.0, 0.2])
    monkeypatch.setattr(adapter_runtime.time, "monotonic", lambda: next(ticks))
    stderr = io.StringIO()
    host = CommonStdioAdapterHost(transport=TestBrokerTransport(handler), stderr_stream=stderr)

    resp = host.process_raw_payload(b'{"jsonrpc":"2.0","id":1,"method":"ping"}')

    assert resp == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert "Slow request" not in stderr.getvalue()
    host.close()

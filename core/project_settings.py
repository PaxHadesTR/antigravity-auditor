"""Per-project settings the user changes only from a terminal: approval mode and the control plane's test command.

``approval_mode``
    ``simple`` (default): the agent lists the APPLY findings in the chat and, after the user's explicit yes,
    starts the fix with ``auditor_start_execution(chat_approved=true)``. ``strict``: a terminal approval
    (``cli.py approve``) is required; the agent then starts with only ``project_key`` (no ID to copy).
    Either way the result is only a local review branch; merging stays the user's decision.
``delivery_mode``
    ``local`` (default): the verified fix stays a local review branch. ``auto_merge``: the control plane (not
    the agent) pushes it, opens a PR, waits for GitHub CI and merges it when every gate passes; otherwise the
    PR stays open for the user. See ``auto_delivery.py``.
``test_command`` / ``test_timeout_seconds``
    What the control plane runs in the worktree after a fix (JSON list; NULL = detect from the repository).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

APPROVAL_MODES = ("simple", "strict")
DELIVERY_MODES = ("local", "auto_merge")
REVIEWABLE_RUN_STATES = ("READY_FOR_REVIEW", "PARTIAL")


def _delivery_mode(row: Any, keys: Any) -> str:
    mode = str(row["delivery_mode"] or "local") if "delivery_mode" in keys else "local"
    return mode if mode in DELIVERY_MODES else "local"  # unknown value: fail closed (no merge)


def get_settings(conn: sqlite3.Connection, project_key: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchone()
    if row is None:
        raise RuntimeError(f"Project '{project_key}' is not registered.")
    keys = row.keys()
    mode = str(row["approval_mode"] or "simple") if "approval_mode" in keys else "simple"
    raw_cmd = row["test_command"] if "test_command" in keys else None
    try:
        cmd = json.loads(raw_cmd) if raw_cmd else None
    except ValueError:
        cmd = None
    return {
        "project_key": project_key,
        "approval_mode": mode if mode in APPROVAL_MODES else "strict",  # unknown value: fail closed
        "delivery_mode": _delivery_mode(row, keys),
        "test_command": cmd,
        "test_timeout_seconds": (row["test_timeout_seconds"] if "test_timeout_seconds" in keys else None),
    }


def set_settings(
    conn: sqlite3.Connection,
    project_key: str,
    *,
    approval_mode: str | None = None,
    delivery_mode: str | None = None,
    test_command: list[str] | None = None,
    clear_test_command: bool = False,
    test_timeout_seconds: int | None = None,
) -> dict[str, Any]:
    get_settings(conn, project_key)  # raises for an unknown project
    if approval_mode is not None:
        if approval_mode not in APPROVAL_MODES:
            raise ValueError(f"approval_mode must be one of {APPROVAL_MODES}.")
        conn.execute("UPDATE projects SET approval_mode=?, updated_at=CURRENT_TIMESTAMP WHERE project_key=?",
                     (approval_mode, project_key))
    if delivery_mode is not None:
        if delivery_mode not in DELIVERY_MODES:
            raise ValueError(f"delivery_mode must be one of {DELIVERY_MODES}.")
        conn.execute("UPDATE projects SET delivery_mode=?, updated_at=CURRENT_TIMESTAMP WHERE project_key=?",
                     (delivery_mode, project_key))
    if clear_test_command:
        conn.execute("UPDATE projects SET test_command=NULL, updated_at=CURRENT_TIMESTAMP WHERE project_key=?",
                     (project_key,))
    elif test_command is not None:
        if not test_command or not all(isinstance(x, str) and x for x in test_command):
            raise ValueError("test_command must be a non-empty list of arguments.")
        conn.execute("UPDATE projects SET test_command=?, updated_at=CURRENT_TIMESTAMP WHERE project_key=?",
                     (json.dumps(test_command), project_key))
    if test_timeout_seconds is not None:
        if not 30 <= int(test_timeout_seconds) <= 7200:
            raise ValueError("test_timeout_seconds must be between 30 and 7200.")
        conn.execute("UPDATE projects SET test_timeout_seconds=?, updated_at=CURRENT_TIMESTAMP WHERE project_key=?",
                     (int(test_timeout_seconds), project_key))
    return get_settings(conn, project_key)


def latest_reviewable_run(conn: sqlite3.Connection, project_key: str) -> str | None:
    """The newest run whose findings can be decided/applied (what "the last report" means to the user)."""
    row = conn.execute(
        f"""SELECT run_id FROM audit_runs WHERE project_key=? AND status IN ({",".join("?" for _ in REVIEWABLE_RUN_STATES)})
            ORDER BY COALESCE(started_at, '') DESC, rowid DESC LIMIT 1""",
        (project_key, *REVIEWABLE_RUN_STATES),
    ).fetchone()
    return str(row[0]) if row else None


def resolve_run_id(conn: sqlite3.Connection, project_key: str, run_id: str | None) -> str:
    if run_id:
        return run_id
    latest = latest_reviewable_run(conn, project_key)
    if not latest:
        raise RuntimeError(f"Project '{project_key}' has no report waiting for review (READY_FOR_REVIEW).")
    return latest


def pending_terminal_approval(conn: sqlite3.Connection, project_key: str, run_id: str | None) -> Any:
    """The newest unexpired, unused terminal approval (not policy, not chat) for ``run_id`` -- by default the
    latest report waiting for review, so an approval given for an older run is never picked up silently."""
    from datetime import datetime, timezone

    run_id = run_id or latest_reviewable_run(conn, project_key)
    if not run_id:
        return None
    return conn.execute(
        """SELECT * FROM execution_approvals
           WHERE project_key=? AND run_id=? AND status='AUTHORIZED' AND expires_at > ?
             AND authorized_by NOT LIKE 'policy:%' AND authorized_by != 'chat'
           ORDER BY rowid DESC LIMIT 1""",
        (project_key, run_id, datetime.now(timezone.utc).isoformat()),
    ).fetchone()

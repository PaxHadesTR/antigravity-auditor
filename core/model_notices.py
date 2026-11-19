"""Antigravity Auditor — model notices for the chat (stored in ``notification_outbox``).

The weekly model work (new models, measurements, automatic table changes, proposals that need the user) runs
unattended. Each outcome the user should hear about is stored as a notice; ``auditor_get_status`` returns the
recent ones and marks them delivered, so the agent tells the user once (``new: true``) and later calls still
show the history.
"""

from __future__ import annotations

import json
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from db import connect

PROJECT_KEY = "_models"
KINDS = ("TABLE_CHANGED", "PROPOSAL_WAITING", "NEW_MODELS", "MODELS_REMOVED", "MEASURED")
NOTICE_DAYS = 14


def add_notice(db_path: Path, kind: str, payload: dict[str, Any]) -> None:
    if kind not in KINDS:
        raise ValueError(f"unknown notice kind {kind}")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with closing(connect(db_path)) as conn:
        conn.execute("INSERT INTO notification_outbox(project_key, event_type, payload, status, created_at) "
                     "VALUES(?, ?, ?, 'PENDING', ?)", (PROJECT_KEY, kind, json.dumps(payload, ensure_ascii=False), now))
        conn.commit()


def recent_notices(db_path: Path | None, *, mark_delivered: bool = True, days: int = NOTICE_DAYS) -> list[dict[str, Any]]:
    if db_path is None or not Path(db_path).is_file():
        return []
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with closing(connect(db_path)) as conn:
        rows = conn.execute(
            "SELECT notification_id, event_type, payload, status, created_at FROM notification_outbox "
            "WHERE project_key=? AND created_at>=? ORDER BY notification_id DESC LIMIT 20", (PROJECT_KEY, since),
        ).fetchall()
        pending = [r["notification_id"] for r in rows if r["status"] == "PENDING"]
        if mark_delivered and pending:
            conn.execute(f"UPDATE notification_outbox SET status='DELIVERED' WHERE notification_id IN "
                         f"({','.join('?' * len(pending))})", pending)
            conn.commit()
    out = []
    for r in rows:
        try:
            payload = json.loads(r["payload"])
        except ValueError:
            payload = {}
        out.append({"kind": r["event_type"], "created_at": r["created_at"], "new": r["status"] == "PENDING",
                    **payload})
    return out


def notices_from_sync(db_path: Path, result: dict[str, Any]) -> list[str]:
    """Store the notices a `models sync` result calls for; returns the kinds stored."""
    stored: list[str] = []
    added = [m.get("slug") if isinstance(m, dict) else m for m in (result.get("diff") or {}).get("added") or []]
    removed = [m.get("slug") if isinstance(m, dict) else m for m in (result.get("diff") or {}).get("removed") or []]
    meas = result.get("measurements") or {}
    if added:
        add_notice(db_path, "NEW_MODELS", {"models": added, "measured_now": sorted(meas.get("measured") or {}),
                                           "deferred": meas.get("deferred") or []})
        stored.append("NEW_MODELS")
    if removed:
        add_notice(db_path, "MODELS_REMOVED", {"models": removed})
        stored.append("MODELS_REMOVED")
    if meas.get("measured") and not added:
        add_notice(db_path, "MEASURED", {"models": sorted(meas["measured"]), "summary": meas.get("summary")})
        stored.append("MEASURED")
    auto = result.get("auto_approval") or {}
    proposal = result.get("proposal") or {}
    changes = [{k: r.get(k) for k in ("tier", "from", "to", "reason")}
               for r in proposal.get("rationale") or [] if r.get("changed")]
    if auto.get("status") == "APPROVED":
        from model_routing_proposals import auto_approval_summary

        last = auto_approval_summary(db_path).get("last_auto_approval") or {}
        add_notice(db_path, "TABLE_CHANGED", {"version_id": auto.get("version_id"), "changes": changes,
                                              "undo_command": last.get("undo_command")})
        stored.append("TABLE_CHANGED")
    elif auto.get("status") in ("LEFT_FOR_USER", "OFF") and proposal.get("version_id"):
        add_notice(db_path, "PROPOSAL_WAITING", {
            "version_id": proposal["version_id"], "changes": changes, "reasons": auto.get("reasons") or [],
            "approve_command": f"python core/cli.py models proposal approve {proposal['version_id']}"})
        stored.append("PROPOSAL_WAITING")
    return stored

"""Optional APPLY auto-approval policy (human-configured, terminal only).

By default every APPLY execution needs the interactive ``cli.py authorize-execution`` confirmation. A user who
runs the auditor like a server can opt in to a policy that lets the agent start an execution without that
confirmation, but only for findings inside limits the user chose (severity, category, paths, count, daily
budget, expiry). The policy is written only by ``cli.py apply-policy set`` (interactive terminal + typed
confirmation); no MCP tool can change it. Whatever the policy allows, the result is still only a local
review branch: nothing is merged or pushed.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

GLOBAL_KEY = "*"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

DEFAULT_POLICY: dict[str, Any] = {
    "enabled": False,
    "max_findings": 3,
    "severities": ["LOW", "MEDIUM"],
    "categories_allow": [],
    "categories_deny": [],
    "paths_allow": [],
    "paths_deny": [".github/**", "**/.env*", "**/*.pem", "**/*.key", "**/secrets/**"],
    "max_changed_files": 5,
    "max_per_day": 3,
    "expires_at": None,
    # Findings whose verification was not independent (same model line as the primary audit, or unknown /
    # unattested models) are human-only unless this is true.
    "allow_single_model_verification": False,
}

_INT_FIELDS = ("max_findings", "max_changed_files", "max_per_day")
_LIST_FIELDS = ("severities", "categories_allow", "categories_deny", "paths_allow", "paths_deny")


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS apply_policies (
            project_key TEXT PRIMARY KEY,
            policy_json TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(execution_approvals)").fetchall()}
    if cols and "policy_snapshot" not in cols:
        conn.execute("ALTER TABLE execution_approvals ADD COLUMN policy_snapshot TEXT")


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized copy; raise ValueError on anything malformed."""
    unknown = set(policy) - set(DEFAULT_POLICY)
    if unknown:
        raise ValueError(f"Unknown policy fields: {sorted(unknown)}")
    out: dict[str, Any] = {**DEFAULT_POLICY, **policy}
    for flag in ("enabled", "allow_single_model_verification"):
        if not isinstance(out[flag], bool):
            raise ValueError(f"'{flag}' must be true or false.")
    for key in _INT_FIELDS:
        val = out[key]
        if isinstance(val, bool) or not isinstance(val, int) or not (0 <= val <= 1000):
            raise ValueError(f"'{key}' must be an integer between 0 and 1000.")
    for key in _LIST_FIELDS:
        val = out[key]
        if not isinstance(val, list) or not all(isinstance(x, str) and x.strip() for x in val):
            raise ValueError(f"'{key}' must be a list of non-empty strings.")
        out[key] = [x.strip() for x in val]
    out["severities"] = [s.upper() for s in out["severities"]]
    bad = [s for s in out["severities"] if s not in SEVERITIES]
    if bad:
        raise ValueError(f"Unknown severities {bad}; allowed: {list(SEVERITIES)}.")
    out["categories_allow"] = [_norm_category(c) for c in out["categories_allow"]]
    out["categories_deny"] = [_norm_category(c) for c in out["categories_deny"]]
    for key in ("paths_allow", "paths_deny"):
        for pat in out[key]:
            _glob_regex(pat)  # raises on an invalid pattern
    exp = out["expires_at"]
    if exp is not None:
        if not isinstance(exp, str):
            raise ValueError("'expires_at' must be an ISO timestamp or null.")
        _parse_ts(exp)
    return out


def policy_hash(policy: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(policy, sort_keys=True).encode("utf-8")).hexdigest()


def get_policy(conn: sqlite3.Connection, project_key: str) -> tuple[dict[str, Any], str]:
    """Effective policy for a project and where it came from (project key, '*' or 'default')."""
    ensure_schema(conn)
    for key in (project_key, GLOBAL_KEY):
        row = conn.execute("SELECT policy_json FROM apply_policies WHERE project_key=?", (key,)).fetchone()
        if row:
            try:
                return validate_policy(json.loads(row[0])), key
            except (ValueError, json.JSONDecodeError):
                # A corrupted stored policy must never widen anything: treat it as disabled.
                return {**DEFAULT_POLICY, "enabled": False}, f"{key} (INVALID, disabled)"
    return dict(DEFAULT_POLICY), "default"


def list_policies(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    ensure_schema(conn)
    rows = conn.execute(
        "SELECT project_key, policy_json, updated_by, updated_at FROM apply_policies ORDER BY project_key"
    ).fetchall()
    out = []
    for r in rows:
        try:
            policy: Any = validate_policy(json.loads(r[1]))
        except (ValueError, TypeError, json.JSONDecodeError):
            policy = {"INVALID": True, "raw": str(r[1])[:200], "effective": "disabled"}
        out.append({"project_key": r[0], "policy": policy, "updated_by": r[2], "updated_at": r[3]})
    return out


def stored_policy(conn: sqlite3.Connection, project_key: str) -> dict[str, Any] | None:
    """The policy stored under exactly this key (None if absent or unreadable)."""
    ensure_schema(conn)
    row = conn.execute("SELECT policy_json FROM apply_policies WHERE project_key=?", (project_key,)).fetchone()
    if not row:
        return None
    try:
        return validate_policy(json.loads(row[0]))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def set_policy(conn: sqlite3.Connection, project_key: str, policy: dict[str, Any], *, updated_by: str) -> dict[str, Any]:
    ensure_schema(conn)
    normalized = validate_policy(policy)
    conn.execute(
        """INSERT INTO apply_policies(project_key, policy_json, updated_by, updated_at)
           VALUES(?, ?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(project_key) DO UPDATE SET
               policy_json=excluded.policy_json, updated_by=excluded.updated_by, updated_at=CURRENT_TIMESTAMP""",
        (project_key, json.dumps(normalized, sort_keys=True), updated_by),
    )
    return normalized


def remove_policy(conn: sqlite3.Connection, project_key: str) -> bool:
    ensure_schema(conn)
    return conn.execute("DELETE FROM apply_policies WHERE project_key=?", (project_key,)).rowcount > 0


def apply_candidates(conn: sqlite3.Connection, project_key: str, run_id: str) -> list[dict[str, Any]]:
    """Findings with an active APPLY decision for the run (exactly what an authorization would cover)."""
    rows = conn.execute(
        """SELECT f.finding_id, f.severity, f.category, f.title, f.file_path, f.line_start, f.line_end,
                  COALESCE(f.model_independent, 0) AS model_independent
           FROM findings f JOIN decisions d ON d.finding_id = f.finding_id
           WHERE f.project_key=? AND d.run_id=? AND d.superseded=0 AND d.decision='APPLY'
             AND f.lifecycle='OPEN'
           ORDER BY f.finding_id""",
        (project_key, run_id),
    ).fetchall()
    return [dict(r) for r in rows]


def evaluate(
    conn: sqlite3.Connection, project_key: str, run_id: str, *, now: datetime | None = None
) -> dict[str, Any]:
    """Would the policy auto-approve the run's current APPLY decisions? Returns per-finding reasons."""
    policy, source = get_policy(conn, project_key)
    now = now or datetime.now(timezone.utc)
    reasons: list[str] = []
    if not policy["enabled"]:
        reasons.append(f"auto-approval is disabled (policy: {source})")
    if policy["expires_at"] and _parse_ts(policy["expires_at"]) <= now:
        reasons.append(f"policy expired at {policy['expires_at']}")
    candidates = apply_candidates(conn, project_key, run_id)
    try:
        anomaly = conn.execute("SELECT evidence_anomaly_json FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()
    except sqlite3.OperationalError:  # database not migrated yet: no anomaly can have been recorded
        anomaly = None
    if anomaly and anomaly[0]:
        reasons.append("the verifier quoted evidence that is not in the code for another finding of this run "
                       "(evidence anomaly); fixes from this run need a terminal approval")
    if not candidates:
        reasons.append("no findings have an active APPLY decision for this run")
    if len(candidates) > policy["max_findings"]:
        reasons.append(f"{len(candidates)} findings exceed max_findings={policy['max_findings']}")
    used = _auto_approvals_since(conn, project_key, now - timedelta(days=1))
    if int(used) >= policy["max_per_day"]:
        reasons.append(f"{used} auto-approvals in the last 24h reached max_per_day={policy['max_per_day']}")

    findings = []
    for f in candidates:
        f_reasons = finding_violations(policy, f)
        findings.append({**f, "allowed": not f_reasons, "reasons": f_reasons})
    blocked = [f["finding_id"] for f in findings if not f["allowed"]]
    if blocked:
        reasons.append(f"findings outside the policy: {blocked}")
    return {
        "project_key": project_key,
        "run_id": run_id,
        "eligible": not reasons,
        "reasons": reasons,
        "policy_source": source,
        "policy_hash": policy_hash(policy),
        "policy": policy,
        "auto_approvals_last_24h": int(used),
        "findings": findings,
    }


def _auto_approvals_since(conn: sqlite3.Connection, project_key: str, since: datetime,
                          up_to_approval: str | None = None) -> int:
    sql = """SELECT COUNT(*) FROM execution_approvals
             WHERE project_key=? AND authorized_by LIKE 'policy:%' AND status != 'REVOKED' AND created_at >= ?"""
    params: list[Any] = [project_key, since.strftime("%Y-%m-%d %H:%M:%S")]
    if up_to_approval:
        sql += " AND rowid <= (SELECT rowid FROM execution_approvals WHERE approval_id=?)"
        params.append(up_to_approval)
    return int(conn.execute(sql, params).fetchone()[0])


def finding_violations(policy: dict[str, Any], finding: dict[str, Any]) -> list[str]:
    out: list[str] = []
    if not int(finding.get("model_independent") or 0) and not policy.get("allow_single_model_verification"):
        out.append("verified without an independent second model (terminal approval required, or "
                   "allow_single_model_verification)")
    sev = str(finding.get("severity") or "").upper()
    if sev not in policy["severities"]:
        out.append(f"severity {sev} not in {policy['severities']}")
    cat = _norm_category(str(finding.get("category") or ""))
    if policy["categories_allow"] and cat not in policy["categories_allow"]:
        out.append(f"category '{cat}' not in categories_allow")
    if cat in policy["categories_deny"]:
        out.append(f"category '{cat}' is in categories_deny")
    path = str(finding.get("file_path") or "")
    out.extend(path_violations(policy, [path] if path else []))
    if not path and policy["paths_allow"]:
        out.append("finding has no file path but paths_allow is set")
    return out


def path_violations(policy: dict[str, Any], paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        if _is_unsafe_path(p):
            out.append(f"path '{p}' is absolute or leaves the repository")
            continue
        norm = _norm_path(p)
        deny = next((pat for pat in policy["paths_deny"] if _glob_regex(pat).match(norm)), None)
        if deny:
            out.append(f"path '{p}' matches paths_deny '{deny}'")
        elif policy["paths_allow"] and not any(_glob_regex(pat).match(norm) for pat in policy["paths_allow"]):
            out.append(f"path '{p}' is outside paths_allow")
    return out


def changed_files_violations(policy: dict[str, Any], files: list[str]) -> list[str]:
    """Post-execution check of what the fix actually changed (the finding paths are only where it started)."""
    out = path_violations(policy, files)
    if len(files) > policy["max_changed_files"]:
        out.insert(0, f"{len(files)} changed files exceed max_changed_files={policy['max_changed_files']}")
    return out


def auto_authorize(
    db_path: Path, *, project_key: str, run_id: str, jsonl_path: Path | None = None, ttl_seconds: int = 600
) -> dict[str, Any]:
    """Authorize the run's APPLY decisions under the stored policy, or raise PermissionError with the reasons."""
    from db import authorize_execution, connect, record_event

    with connect(db_path) as conn:
        ev = evaluate(conn, project_key, run_id)
    if not ev["eligible"]:
        details = [f"{f['finding_id']}: {', '.join(f['reasons'])}" for f in ev["findings"] if not f["allowed"]]
        raise PermissionError(
            "Auto-approval refused: " + "; ".join(ev["reasons"]) + ("; " + "; ".join(details) if details else "")
            + f". A human can approve in a terminal: python core/cli.py authorize-execution --project {project_key} "
            f"--run-id {run_id}"
        )
    ids = [str(f["finding_id"]) for f in ev["findings"]]
    res = authorize_execution(
        db_path,
        project_key=project_key,
        run_id=run_id,
        authorized_by=f"policy:{ev['policy_source']}#{ev['policy_hash'][:12]}",
        ttl_seconds=ttl_seconds,
        confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
        jsonl_path=jsonl_path,
        expected_finding_ids=ids,  # decisions changed since the evaluation -> nothing is authorized
    )
    snapshot = {"source": ev["policy_source"], "hash": ev["policy_hash"], "policy": ev["policy"]}
    with connect(db_path) as conn:
        ensure_schema(conn)
        # Two concurrent auto-approvals can both pass the evaluation; the one that pushes the 24h count over
        # max_per_day revokes itself (counting only approvals up to and including this one).
        since = datetime.now(timezone.utc) - timedelta(days=1, minutes=1)
        if _auto_approvals_since(conn, project_key, since, up_to_approval=res["approval_id"]) > ev["policy"]["max_per_day"]:
            conn.execute("UPDATE execution_approvals SET status='REVOKED' WHERE approval_id=?", (res["approval_id"],))
            conn.commit()
            raise PermissionError(
                f"Auto-approval refused: max_per_day={ev['policy']['max_per_day']} reached by a concurrent approval."
            )
        conn.execute(
            "UPDATE execution_approvals SET policy_snapshot=? WHERE approval_id=?",
            (json.dumps(snapshot, sort_keys=True), res["approval_id"]),
        )
        record_event(
            conn,
            "EXECUTION_AUTO_AUTHORIZED",
            project_key=project_key,
            run_id=run_id,
            level="WARNING",
            details={"approval_id": res["approval_id"], "finding_ids": ids, "policy_source": ev["policy_source"],
                     "policy_hash": ev["policy_hash"]},
            jsonl_path=jsonl_path,
        )
        conn.commit()
    return {**res, "policy_source": ev["policy_source"], "policy_hash": ev["policy_hash"]}


def approval_policy_snapshot(conn: sqlite3.Connection, approval_id: str) -> dict[str, Any] | None:
    ensure_schema(conn)
    row = conn.execute(
        "SELECT authorized_by, policy_snapshot FROM execution_approvals WHERE approval_id=?", (approval_id,)
    ).fetchone()
    if not row or not str(row[0] or "").startswith("policy:"):
        return None
    try:
        snap = json.loads(row[1]) if row[1] else None
    except json.JSONDecodeError:
        snap = None
    # Auto-approved but the snapshot is missing/corrupt: check against the strictest reading (the defaults).
    return snap if isinstance(snap, dict) and isinstance(snap.get("policy"), dict) else {
        "source": "unknown", "hash": "", "policy": dict(DEFAULT_POLICY)}


def _norm_category(value: str) -> str:
    return " ".join(value.strip().upper().split())


def _norm_path(value: str) -> str:
    p = value.replace("\\", "/").strip()
    if not p:
        return ""
    p = posixpath.normpath(p)
    while p.startswith("./"):
        p = p[2:]
    return "" if p == "." else p.lstrip("/").lower()


def _is_unsafe_path(value: str) -> bool:
    p = value.replace("\\", "/").strip()
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        return True
    norm = posixpath.normpath(p) if p else ""
    return norm == ".." or norm.startswith("../")


_GLOB_CACHE: dict[str, re.Pattern[str]] = {}


def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Gitignore-like glob: '**' spans directories, '*' and '?' stay inside one segment; case-insensitive.
    A pattern without '/' matches the file name in any directory."""
    if pattern in _GLOB_CACHE:
        return _GLOB_CACHE[pattern]
    pat = _norm_path(pattern)
    if not pat:
        raise ValueError(f"Empty path pattern: {pattern!r}")
    if "/" not in pat.rstrip("/"):
        pat = "**/" + pat
    if pat.endswith("/"):
        pat += "**"
    out = []
    i = 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    rx = re.compile("^" + "".join(out) + "$")
    _GLOB_CACHE[pattern] = rx
    return rx


def _parse_ts(value: str) -> datetime:
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp {value!r}") from exc
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

"""Keep the user's checkout current before an audit and clean up merged fix branches (delivery modes
``pull_request`` and ``auto_merge``).

With PR delivery the fix is merged on GitHub, so the local checkout the auditor audits stays behind until someone
pulls; the next audit would then scan code without the fixes (or be skipped as "no changes"). Before an audit
``sync_checkout``:

1. fetches ``origin`` and fast-forwards the default branch **only** when the checkout is on that branch, has no
   uncommitted changes to tracked files and has no local commits (strictly behind). Anything else is left alone and
   reported (``BEHIND_NOT_UPDATED`` with the reason);
2. deletes ``audit-fix/...`` branches that this auditor created (recorded in ``execution_runs.review_branch``) once
   they are fully merged into ``origin/<default>``: locally, and on ``origin`` when the remote branch is merged too.

It never runs while an audit or a fix of the project is in progress, while an approved fix has not started yet, or
(for scheduled runs) while a report waits for the user's decisions: moving HEAD under them would make them stale.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from db import connect, record_event

SYNC_MODES = ("pull_request", "auto_merge")
ACTIVE_RUN_STATES = (
    "PREFLIGHT", "PRIMARY_AUDIT_RUNNING", "DISPATCHED", "ANALYZING", "VERIFICATION_PENDING",
    "VERIFICATION_DISPATCHING", "VERIFICATION_RUNNING", "EVIDENCE_VALIDATION",
)
WAITING_RUN_STATES = ("READY_FOR_REVIEW", "PENDING_APPROVAL")

Runner = Callable[[list[str], Path], subprocess.CompletedProcess]


def _default_runner(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=120, stdin=subprocess.DEVNULL)


RUN: Runner = _default_runner  # test seam


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return RUN(["git", *args], repo)


def _out(repo: Path, *args: str) -> str:
    res = _git(repo, *args)
    return (res.stdout or "").strip() if res.returncode == 0 else ""


def default_branch(repo: Path) -> str | None:
    """origin's default branch from the local remote HEAD, else main / master if origin has it."""
    ref = _out(repo, "symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD")
    if ref.startswith("origin/"):
        return ref[len("origin/"):]
    for name in ("main", "master"):
        if _git(repo, "rev-parse", "--verify", "-q", f"refs/remotes/origin/{name}").returncode == 0:
            return name
    return None


def commits_behind_origin(repo: Path, *, fetch: bool = True) -> int | None:
    """How many commits origin's default branch has that HEAD lacks (None: unknown, e.g. no remote)."""
    if fetch and _git(repo, "fetch", "-q", "origin").returncode != 0:
        return None
    default = default_branch(repo)
    if not default:
        return None
    count = _out(repo, "rev-list", "--count", f"HEAD..origin/{default}")
    return int(count) if count.isdigit() else None


def _busy_reason(conn: Any, project_key: str, *, manual: bool) -> str | None:
    q = ",".join("?" for _ in ACTIVE_RUN_STATES)
    if conn.execute(f"SELECT 1 FROM audit_runs WHERE project_key=? AND status IN ({q}) LIMIT 1",
                    (project_key, *ACTIVE_RUN_STATES)).fetchone():
        return "an audit of this project is in progress"
    if conn.execute("SELECT 1 FROM execution_runs WHERE project_key=? AND status IN ('PREFLIGHT','RUNNING','VERIFYING') "
                    "LIMIT 1", (project_key,)).fetchone():
        return "a fix of this project is running"
    if conn.execute("SELECT 1 FROM execution_approvals WHERE project_key=? AND status='AUTHORIZED' AND expires_at > ? "
                    "LIMIT 1", (project_key, datetime.now(timezone.utc).isoformat())).fetchone():
        return "an approved fix has not started yet"
    if not manual:
        w = ",".join("?" for _ in WAITING_RUN_STATES)
        if conn.execute(f"SELECT 1 FROM audit_runs WHERE project_key=? AND status IN ({w}) LIMIT 1",
                        (project_key, *WAITING_RUN_STATES)).fetchone():
            return "a report waits for your decisions"
    return None


def sync_checkout(db_path: Path, project_key: str, *, manual: bool, jsonl_path: Path | None = None) -> dict[str, Any]:
    """Fast-forward the clean default-branch checkout and delete merged fix branches (see the module docstring).
    Never raises: the audit goes on either way, and the outcome is recorded as a CHECKOUT_SYNC event."""
    out: dict[str, Any] = {"status": "SKIPPED"}
    try:
        with connect(db_path) as conn:
            project = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchone()
            if project is None:
                return {"status": "SKIPPED", "reason": "unknown project"}
            mode = str(project["delivery_mode"] or "local") if "delivery_mode" in project.keys() else "local"
            if mode not in SYNC_MODES:
                return {"status": "SKIPPED", "reason": f"delivery mode {mode}"}
            busy = _busy_reason(conn, project_key, manual=manual)
            branches = [str(r[0]) for r in conn.execute(
                "SELECT DISTINCT review_branch FROM execution_runs WHERE project_key=? AND review_branch LIKE 'audit-fix/%'",
                (project_key,))]
        if busy:
            return {"status": "SKIPPED", "reason": busy}
        repo = Path(str(project["repo_path"]))
        if _git(repo, "fetch", "-q", "--prune", "origin").returncode != 0:
            out = {"status": "FETCH_FAILED", "reason": "git fetch origin failed"}
            return out
        default = default_branch(repo)
        if not default:
            out = {"status": "SKIPPED", "reason": "origin has no default branch"}
            return out
        out = {"status": "UP_TO_DATE", "default_branch": default, "deleted_local": [], "deleted_remote": []}
        current = _out(repo, "symbolic-ref", "-q", "--short", "HEAD")
        behind = int(_out(repo, "rev-list", "--count", f"HEAD..origin/{default}") or 0)
        ahead = int(_out(repo, "rev-list", "--count", f"origin/{default}..HEAD") or 0)
        dirty = bool(_out(repo, "status", "--porcelain", "--untracked-files=no"))
        if behind:
            out["behind"] = behind
            if current != default:
                out.update(status="BEHIND_NOT_UPDATED", reason=f"the checkout is on '{current or 'a detached HEAD'}'")
            elif dirty:
                out.update(status="BEHIND_NOT_UPDATED", reason="the checkout has uncommitted changes")
            elif ahead:
                out.update(status="BEHIND_NOT_UPDATED", reason=f"the checkout has {ahead} local commit(s)")
            else:
                ff = _git(repo, "merge", "--ff-only", "-q", f"origin/{default}")
                if ff.returncode == 0:
                    out["status"] = "PULLED"
                else:
                    out.update(status="BEHIND_NOT_UPDATED", reason="fast-forward failed")
        current = _out(repo, "symbolic-ref", "-q", "--short", "HEAD")
        for branch in branches:
            ref = f"refs/heads/{branch}"
            if (branch != current and _git(repo, "rev-parse", "--verify", "-q", ref).returncode == 0
                    and _git(repo, "merge-base", "--is-ancestor", ref, f"origin/{default}").returncode == 0
                    and _git(repo, "branch", "-D", branch).returncode == 0):
                out["deleted_local"].append(branch)
            remote_ref = f"refs/remotes/origin/{branch}"
            if (_git(repo, "rev-parse", "--verify", "-q", remote_ref).returncode == 0
                    and _git(repo, "merge-base", "--is-ancestor", remote_ref, f"origin/{default}").returncode == 0
                    and _git(repo, "push", "-q", "origin", "--delete", branch).returncode == 0):
                out["deleted_remote"].append(branch)
        return out
    except Exception as exc:  # noqa: BLE001 - never block an audit on housekeeping
        out = {"status": "ERROR", "reason": f"{type(exc).__name__}: {exc}"[:300]}
        return out
    finally:
        if out.get("status") not in ("SKIPPED",):
            try:
                with connect(db_path) as conn:
                    record_event(conn, "CHECKOUT_SYNC", project_key=project_key,
                                 level="INFO" if out.get("status") in ("PULLED", "UP_TO_DATE") else "WARNING",
                                 details=out, jsonl_path=jsonl_path)
                    conn.commit()
            except Exception:  # noqa: BLE001
                pass

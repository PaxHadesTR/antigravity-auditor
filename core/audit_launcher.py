"""Start a manual audit from the agent chat (MCP ``auditor_audit_now``) without blocking the tool call.

The audit itself is exactly ``cli.py audit-now`` (read-only primary audit + second-pass verification, no code
change), launched as a separate background process. What this module adds are the guards that keep an agent from
spending the user's model quota by mistake or under the influence of repository text:

* one audit per project at a time (an active run, or a launched process that has not created its run yet);
  concurrent calls are serialized by an OS lock, so two calls cannot both pass the guards;
* no audit when the code has not changed since the last finished audit, unless ``force``;
* a report still waiting for the user's decisions is replaced only with ``replace_pending_report`` (and never while
  a fix of that report is running or approved);
* at most ``DAILY_CHAT_AUDIT_LIMIT`` chat-started audits per project in 24 h (the terminal command is unlimited).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from db import connect, record_event
from recovery import git_output

DAILY_CHAT_AUDIT_LIMIT = 3
LAUNCH_EVENT = "AUDIT_NOW_LAUNCHED_FROM_CHAT"
RUNNING_STATES = (
    "PREFLIGHT", "PRIMARY_AUDIT_RUNNING", "DISPATCHED", "ANALYZING", "VERIFICATION_PENDING",
    "VERIFICATION_DISPATCHING", "VERIFICATION_RUNNING", "EVIDENCE_VALIDATION",
)
WAITING_STATES = ("READY_FOR_REVIEW", "PENDING_APPROVAL")

_STILL_ACTIVE = 259  # Windows GetExitCodeProcess
_CHILDREN: list[subprocess.Popen] = []  # handles of launched audits (no ResourceWarning; reaped on later polls)


def _kernel32() -> Any:
    import ctypes
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k.OpenProcess.restype = wintypes.HANDLE
    k.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    k.GetExitCodeProcess.restype = wintypes.BOOL
    k.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
    k.GetProcessTimes.restype = wintypes.BOOL
    k.CloseHandle.argtypes = (wintypes.HANDLE,)
    k.CloseHandle.restype = wintypes.BOOL
    return k


def _process_start(pid: int) -> int | None:
    """Creation time of a running process (its identity against PID reuse), or None when it is not running."""
    if pid <= 0:
        return None
    if os.name != "nt":  # pragma: no cover - non-Windows: liveness only
        try:
            os.kill(pid, 0)
            return 0
        except OSError:
            return None
    import ctypes
    from ctypes import wintypes

    k = _kernel32()
    handle = k.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        code = wintypes.DWORD()
        if not k.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value != _STILL_ACTIVE:
            return None
        times = [wintypes.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
            return 0
        return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    finally:
        k.CloseHandle(handle)


def _pid_alive(pid: int) -> bool:
    return _process_start(pid) is not None


def _lock_path(app_home: Path, project_key: str) -> Path:
    return app_home / "locks" / f"audit-now-{project_key}.json"


def _launched_process(app_home: Path, project_key: str) -> dict[str, Any] | None:
    """The previously launched audit if it is still the same running process; a stale lock file is removed."""
    lock = _lock_path(app_home, project_key)
    try:
        info = json.loads(lock.read_text(encoding="utf-8"))
        pid = int(info.get("pid") or 0)
        recorded = info.get("process_start")
        recorded = int(recorded) if recorded is not None else None
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError, AttributeError):
        info, pid, recorded = None, 0, None
    start = _process_start(pid)
    if info is not None and start is not None and (recorded in (None, 0) or start in (0, recorded)):
        return info
    try:
        lock.unlink()
    except OSError:
        pass
    return None


class _LaunchMutex:
    """Exclusive per-project launch lock (OS byte-range lock): concurrent auditor_audit_now calls are serialized."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.fh: Any = None

    def __enter__(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt

                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:  # pragma: no cover - non-Windows
                import fcntl

                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            self.fh.close()
            self.fh = None
            return False

    def __exit__(self, *exc: Any) -> None:
        if self.fh is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:  # pragma: no cover
                import fcntl

                fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            self.fh.close()
            self.fh = None


def _spawn(command: list[str], *, env: dict[str, str], log_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    kwargs: dict[str, Any] = {"stdin": subprocess.DEVNULL, "env": env, "close_fds": True}
    _CHILDREN[:] = [c for c in _CHILDREN if c.poll() is None]
    with open(log_path, "ab") as log:
        kwargs.update(stdout=log, stderr=subprocess.STDOUT)
        if os.name == "nt":
            base = subprocess.CREATE_NEW_PROCESS_GROUP | 0x08000000  # CREATE_NO_WINDOW (no console pops up)
            try:  # outlive the MCP server (Antigravity may close it) when the job allows breakaway
                proc = subprocess.Popen(command, creationflags=base | 0x01000000, **kwargs)
            except OSError:
                proc = subprocess.Popen(command, creationflags=base, **kwargs)
        else:  # pragma: no cover
            proc = subprocess.Popen(command, start_new_session=True, **kwargs)
    _CHILDREN.append(proc)
    return proc.pid


def launch_audit_now(
    db_path: Path,
    app_home: Path,
    *,
    project_key: str,
    force: bool = False,
    replace_pending_report: bool = False,
    jsonl_path: Path | None = None,
    spawn: Callable[..., int] | None = None,
) -> dict[str, Any]:
    with _LaunchMutex(app_home / "locks" / f"audit-now-{project_key}.mutex") as acquired:
        if not acquired:
            return {"status": "ALREADY_RUNNING",
                    "hint": "Another request is starting an audit for this project right now; check auditor_get_status."}
        return _launch_locked(db_path, app_home, project_key=project_key, force=force,
                              replace_pending_report=replace_pending_report, jsonl_path=jsonl_path, spawn=spawn)


def _launch_locked(
    db_path: Path,
    app_home: Path,
    *,
    project_key: str,
    force: bool,
    replace_pending_report: bool,
    jsonl_path: Path | None,
    spawn: Callable[..., int] | None,
) -> dict[str, Any]:
    from db import recover_stale_runs
    from verification import compute_clean_working_tree_hash

    with connect(db_path) as conn:
        if conn.execute("SELECT 1 FROM projects WHERE project_key=? AND enabled=1", (project_key,)).fetchone() is None:
            raise RuntimeError(f"Project '{project_key}' is not registered or disabled.")
    # An audit that crashed long ago must not hold the project as "running" forever (same recovery as dispatch).
    recover_stale_runs(db_path, project_key=project_key, jsonl_path=jsonl_path)
    with connect(db_path) as conn:
        project = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchone()
        q = ",".join("?" for _ in RUNNING_STATES)
        running = conn.execute(
            f"SELECT run_id, status FROM audit_runs WHERE project_key=? AND status IN ({q}) ORDER BY rowid DESC LIMIT 1",
            (project_key, *RUNNING_STATES),
        ).fetchone()
        waiting = conn.execute(
            f"""SELECT run_id FROM audit_runs WHERE project_key=? AND status IN ({",".join("?" for _ in WAITING_STATES)})
                ORDER BY rowid DESC LIMIT 1""",
            (project_key, *WAITING_STATES),
        ).fetchone()
        last = conn.execute(
            """SELECT run_id, base_commit, working_tree_hash FROM audit_runs
               WHERE project_key=? AND status IN ('COMPLETED', 'PARTIAL', 'READY_FOR_REVIEW')
               ORDER BY rowid DESC LIMIT 1""",
            (project_key,),
        ).fetchone()
        busy = None
        if waiting is not None:
            busy = conn.execute(
                """SELECT 'a fix of it is running' FROM execution_runs
                     WHERE run_id=? AND status IN ('PREFLIGHT','RUNNING','VERIFYING')
                   UNION ALL
                   SELECT 'an approved fix of it has not been started yet' FROM execution_approvals
                     WHERE run_id=? AND status='AUTHORIZED' AND expires_at > ?""",
                (waiting["run_id"], waiting["run_id"], datetime.now(timezone.utc).isoformat()),
            ).fetchone()
        fixing = conn.execute(
            "SELECT exec_id FROM execution_runs WHERE project_key=? AND status IN ('PREFLIGHT','RUNNING','VERIFYING') "
            "LIMIT 1", (project_key,)).fetchone()
        parked = None
        if running is not None and running["status"] == "VERIFICATION_PENDING":
            # Its job waits for a retry (quota, transient error). Every audit process (chat, terminal, weekly) holds
            # the project's lock file, so with no live process (`proc` below) nothing is working on it.
            parked = conn.execute(
                """SELECT status, next_attempt_at, last_error_code, attempt_count, max_attempts
                     FROM verification_dispatch_queue WHERE audit_run_id=?
                      AND status IN ('QUEUED', 'RETRYABLE_FAILURE') AND attempt_count < max_attempts
                    ORDER BY rowid DESC LIMIT 1""",
                (running["run_id"],),
            ).fetchone()
        since = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        launched_today = int(conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE project_key=? AND event_type=? AND created_at >= ?",
            (project_key, LAUNCH_EVENT, since),
        ).fetchone()[0])

    proc = _launched_process(app_home, project_key)
    if running is not None and parked is not None and proc is None:
        due = not parked["next_attempt_at"] or str(parked["next_attempt_at"]) <= datetime.now(timezone.utc).isoformat()
        if not due:
            return {"status": "VERIFICATION_PARKED", "run_id": running["run_id"], "run_status": running["status"],
                    "hint": f"The audit's second-pass verification waits for a retry "
                            f"({parked['last_error_code'] or parked['status']}, next attempt at "
                            f"{parked['next_attempt_at']}). Ask again after that time to resume it."}
        # due: `audit-now` resumes the parked verification instead of starting a new audit
    elif running is not None:
        return {"status": "ALREADY_RUNNING", "run_id": running["run_id"], "run_status": running["status"],
                "hint": "An audit is in progress; check it with auditor_get_status."}
    if proc is not None:
        return {"status": "ALREADY_RUNNING", "pid": proc.get("pid"), "started_at": proc.get("started_at"),
                "hint": "An audit was just started and is preparing; check it with auditor_get_status."}
    if fixing is not None:
        return {"status": "FIX_IN_PROGRESS", "hint": f"A fix ({fixing['exec_id']}) is running on this project; "
                "start the audit after it is finalized."}
    if waiting is not None and not replace_pending_report:
        return {"status": "REPORT_WAITING_FOR_REVIEW", "run_id": waiting["run_id"],
                "hint": "The last report still waits for the user's decisions. Ask the user whether to replace it; "
                        "only if they say so, call again with replace_pending_report=true."}
    if busy is not None:
        return {"status": "REPORT_IN_USE", "run_id": waiting["run_id"],
                "hint": f"The waiting report cannot be replaced: {busy[0]}. Finish (or let expire) that fix first."}
    if waiting is None and last is not None and last["base_commit"] and not force:
        repo = Path(project["repo_path"])
        try:
            same = (git_output(repo, "rev-parse", "HEAD") == last["base_commit"]
                    and compute_clean_working_tree_hash(repo) == last["working_tree_hash"])
        except Exception:  # noqa: BLE001 - an unreadable repository is reported by the audit itself
            same = False
        if same:
            return {"status": "NO_CHANGES", "run_id": last["run_id"],
                    "hint": "The code has not changed since that audit. Ask the user; only if they still want a new "
                            "audit, call again with force=true."}
    if launched_today >= DAILY_CHAT_AUDIT_LIMIT:
        return {"status": "DAILY_LIMIT_REACHED", "limit": DAILY_CHAT_AUDIT_LIMIT,
                "hint": f"{DAILY_CHAT_AUDIT_LIMIT} audits were already started from the chat in 24 h. The user can "
                        f"still run one in a terminal: python core/cli.py audit-now --project {project_key}"}

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = app_home / "logs" / "audit-now" / f"{project_key}-{stamp}.log"
    env = os.environ.copy()
    env["ANTIGRAVITY_AUDITOR_HOME"] = str(app_home)
    env["ANTIGRAVITY_AUDITOR_DB"] = str(db_path)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    command = [sys.executable, str(Path(__file__).resolve().parent / "cli.py"), "audit-now", "--project", project_key]
    pid = (spawn or _spawn)(command, env=env, log_path=log_path)
    lock = _lock_path(app_home, project_key)
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(json.dumps({"pid": pid, "process_start": _process_start(pid), "started_at": stamp,
                                "log": str(log_path)}), encoding="utf-8")
    with connect(db_path) as conn:
        record_event(conn, LAUNCH_EVENT, project_key=project_key,
                     details={"pid": pid, "log": str(log_path), "force": force,
                              "replace_pending_report": replace_pending_report},
                     jsonl_path=jsonl_path)
        conn.commit()
    return {
        "status": "STARTED",
        "project_key": project_key,
        "pid": pid,
        "log_path": str(log_path),
        "replaces_run_id": waiting["run_id"] if waiting is not None else None,
        "chat_audits_left_today": DAILY_CHAT_AUDIT_LIMIT - launched_today - 1,
        "hint": "The audit runs in the background (usually 5-15 minutes). Tell the user; when they ask, check "
                "auditor_get_status. When the newest run is READY_FOR_REVIEW (or COMPLETED), show the report.",
    }

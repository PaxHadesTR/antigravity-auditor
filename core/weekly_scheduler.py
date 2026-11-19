"""Weekly run through the Windows Task Scheduler (replaces the Antigravity Sidecars).

The Sidecars (``builtin: schedule``) never fired on the user's machine, so neither the weekly audit nor the model
catalogue sync ran. One Windows scheduled task now runs ``cli.py weekly`` (``pythonw``, no console window):

1. ``models sync --probe --research-new --propose``: notices new models (e.g. a new Gemini line), probes them,
   researches model lines no research report covers yet, and stores a routing-table proposal for the user to
   approve (approval stays human-only);
2. ``scheduled-audit`` for every enabled registered project (the weekly gate still skips a project whose report
   waits for review or whose code did not change).

The task runs as the logged-on user (``agy``/``gh`` use the user's own login), starts when available after a missed
time (PC off at 04:00), and never runs twice at once. A marker file tells ``register`` not to create Sidecars.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

TASK_PATH = "\\AntigravityAuditor\\"
TASK_NAME = "Weekly"
DAYS = {"MON": "Monday", "TUE": "Tuesday", "WED": "Wednesday", "THU": "Thursday", "FRI": "Friday",
        "SAT": "Saturday", "SUN": "Sunday"}
MODELS_SYNC_SIDECAR_ID = "auditor-models-sync"

Runner = Callable[[list[str]], subprocess.CompletedProcess]


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
                          stdin=subprocess.DEVNULL)


RUN: Runner = _run


def marker_path(app_home: Path) -> Path:
    return app_home / "config" / "scheduler.json"


def uses_windows_task(app_home: Path) -> bool:
    try:
        return json.loads(marker_path(app_home).read_text(encoding="utf-8")).get("backend") == "windows_task"
    except (OSError, ValueError):
        return False


def _pythonw() -> str:
    cand = Path(sys.executable).with_name("pythonw.exe")
    return str(cand) if cand.is_file() else sys.executable


def _ps(script: str) -> subprocess.CompletedProcess:
    return RUN(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])


def _q(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def install(app_home: Path, cli_path: Path, *, day: str = "MON", time: str = "04:00") -> dict[str, Any]:
    day = day.upper()[:3]
    if day not in DAYS:
        raise ValueError(f"day must be one of {', '.join(DAYS)}")
    hh, _, mm = time.partition(":")
    if not (hh.isdigit() and mm.isdigit() and 0 <= int(hh) < 24 and 0 <= int(mm) < 60):
        raise ValueError("time must be HH:MM")
    script = "; ".join([
        "$ErrorActionPreference='Stop'",
        f"$a = New-ScheduledTaskAction -Execute {_q(_pythonw())} -Argument {_q(chr(34) + str(cli_path) + chr(34) + ' weekly')}"
        f" -WorkingDirectory {_q(str(app_home))}",
        f"$t = New-ScheduledTaskTrigger -Weekly -DaysOfWeek {DAYS[day]} -At {_q(f'{int(hh):02d}:{int(mm):02d}')}",
        "$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries"
        " -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 6)",
        f"Register-ScheduledTask -TaskPath {_q(TASK_PATH)} -TaskName {_q(TASK_NAME)} -Action $a -Trigger $t"
        " -Settings $s -Description 'Antigravity Auditor: model catalogue sync + weekly audits' -Force | Out-Null",
    ])
    res = _ps(script)
    if res.returncode != 0:
        raise RuntimeError(f"Register-ScheduledTask failed: {(res.stderr or res.stdout).strip()[:600]}")
    marker = marker_path(app_home)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"backend": "windows_task", "task": TASK_PATH + TASK_NAME, "day": day,
                                  "time": f"{int(hh):02d}:{int(mm):02d}"}, indent=2), encoding="utf-8")
    return {"status": "INSTALLED", "task": TASK_PATH + TASK_NAME, "day": DAYS[day], "time": time, **status()}


def status() -> dict[str, Any]:
    res = _ps(
        f"$t = Get-ScheduledTask -TaskPath {_q(TASK_PATH)} -TaskName {_q(TASK_NAME)} -ErrorAction SilentlyContinue; "
        "if ($t) { $i = $t | Get-ScheduledTaskInfo; "
        "[pscustomobject]@{state=[string]$t.State; last_run=[string]$i.LastRunTime; last_result=$i.LastTaskResult; "
        "next_run=[string]$i.NextRunTime} | ConvertTo-Json -Compress }")
    out = (res.stdout or "").strip()
    if res.returncode != 0 or not out:
        return {"installed": False}
    return {"installed": True, **json.loads(out)}


def remove(app_home: Path) -> dict[str, Any]:
    res = _ps(f"Unregister-ScheduledTask -TaskPath {_q(TASK_PATH)} -TaskName {_q(TASK_NAME)} -Confirm:$false")
    try:
        marker_path(app_home).unlink()
    except OSError:
        pass
    return {"status": "REMOVED" if res.returncode == 0 else "NOT_PRESENT"}


def remove_legacy_sidecars(app_home: Path, sidecar_root: Path, config_path: Path,
                           project_keys: list[str]) -> dict[str, Any]:
    """Back up and remove the auditor's own Sidecars (``<key>-audit`` and the models sync) and their config.json
    entries. Other Sidecars are left alone."""
    ids = [f"{k}-audit" for k in project_keys] + [MODELS_SYNC_SIDECAR_ID]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = app_home / "backups" / f"sidecars-{stamp}"
    removed: list[str] = []
    for sid in ids:
        d = sidecar_root / sid
        if (d / "sidecar.json").is_file():
            (backup / sid).mkdir(parents=True, exist_ok=True)
            shutil.copy2(d / "sidecar.json", backup / sid / "sidecar.json")
            (d / "sidecar.json").unlink()
            removed.append(str(d / "sidecar.json"))
        try:
            d.rmdir()  # a still-running Sidecar process may hold the folder; then the empty folder stays
        except OSError:
            pass
    if config_path.is_file():
        config = json.loads(config_path.read_text(encoding="utf-8-sig"))
        sidecars = config.get("sidecars") if isinstance(config, dict) else None
        if isinstance(sidecars, dict) and any(sid in sidecars for sid in ids):
            backup.mkdir(parents=True, exist_ok=True)
            shutil.copy2(config_path, backup / "config.json")
            for sid in ids:
                sidecars.pop(sid, None)
            tmp = config_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, config_path)
            removed.append(f"{config_path} entries")
    return {"removed": removed, "backup": str(backup) if removed else None}


def run_weekly(app_home: Path, db_path: Path, cli_path: Path, *, jsonl_path: Path | None = None,
               runner: Callable[..., subprocess.CompletedProcess] | None = None) -> dict[str, Any]:
    """The scheduled task's job. Each step is its own process so one failure does not stop the others."""
    from db import connect, record_event

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = app_home / "logs" / "weekly" / f"weekly-{stamp}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(ANTIGRAVITY_AUDITOR_HOME=str(app_home), ANTIGRAVITY_AUDITOR_DB=str(db_path),
               PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    with connect(db_path) as conn:
        keys = [r[0] for r in conn.execute(
            "SELECT project_key FROM projects WHERE enabled=1 ORDER BY project_key").fetchall()]
    steps = [("models-sync", ["models", "sync", "--probe", "--research-new", "--measure", "--propose"])]
    steps += [(f"audit:{k}", ["scheduled-audit", "--project", k]) for k in keys]
    results: list[dict[str, Any]] = []
    run = runner or subprocess.run
    console_py = Path(sys.executable).with_name("python.exe")
    py = str(console_py) if Path(sys.executable).name.lower() == "pythonw.exe" and console_py.is_file() else sys.executable
    with open(log_path, "a", encoding="utf-8") as log:
        for name, args in steps:
            log.write(f"\n===== {name} {datetime.now(timezone.utc).isoformat()} =====\n")
            log.flush()
            try:
                proc = run([py, str(cli_path), *args], stdout=log, stderr=subprocess.STDOUT, env=env,
                           stdin=subprocess.DEVNULL, timeout=4 * 3600,
                           creationflags=0x08000000 if os.name == "nt" else 0)
                code: Any = proc.returncode
            except (OSError, subprocess.TimeoutExpired) as exc:
                code = f"{type(exc).__name__}"
            results.append({"step": name, "exit_code": code})
            log.flush()
    summary = {"log_path": str(log_path), "steps": results}
    with connect(db_path) as conn:
        record_event(conn, "WEEKLY_RUN_FINISHED", details=summary,
                     level="INFO" if all(r["exit_code"] == 0 for r in results) else "WARNING", jsonl_path=jsonl_path)
        conn.commit()
    return summary

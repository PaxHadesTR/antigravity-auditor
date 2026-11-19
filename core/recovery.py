from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from db import (
    backup_database,
    check_database_integrity,
    connect,
     record_event,
    recover_stale_runs,
    verify_backup_restore,
)


def git_output(repo: Path, *args: str, timeout: int = 20) -> str:
    try:
        res = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return res.stdout.strip() if res.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


# Fingerprint that older versions stored for repositories without commits (or after a git timeout).
LEGACY_EMPTY_FINGERPRINT = hashlib.sha256(b"empty").hexdigest()[:24]


def _remove_git_worktree(worktree_path: Path) -> None:
    """Remove a linked worktree through Git (so .git/worktrees/<name> and its lock are cleaned), falling back
    to deleting the directory and pruning stale worktree metadata. A directory holding a real ``.git``
    folder is a main repository, never a linked worktree, and is left untouched."""
    if (worktree_path / ".git").is_dir():
        return
    common_dir = git_output(worktree_path, "rev-parse", "--path-format=absolute", "--git-common-dir")
    main_repo = Path(common_dir).parent if common_dir else None
    if main_repo is not None and main_repo.is_dir():
        try:
            subprocess.run(
                ["git", "-C", str(main_repo), "worktree", "remove", "--force", str(worktree_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    if worktree_path.exists():
        shutil.rmtree(worktree_path, ignore_errors=True)
    if main_repo is not None and main_repo.is_dir():
        git_output(main_repo, "worktree", "prune")


def compute_repo_fingerprint(repo: Path) -> str:
    """Stable repository identity fingerprint from the root commit; "" when it cannot be determined yet
    (no commits, git error or timeout) so that a placeholder is never compared as an identity."""
    root_commits = git_output(repo, "rev-list", "--max-parents=0", "HEAD")
    if not root_commits:
        root_commits = git_output(repo, "rev-parse", "HEAD")
    first_line = root_commits.splitlines()[0].strip() if root_commits else ""
    if not first_line:
        return ""
    return hashlib.sha256(first_line.encode("utf-8")).hexdigest()[:24]


def check_disk_space(target_path: Path, min_free_mb: int = 500) -> dict[str, Any]:
    """Verify sufficient free disk space before creating backups, audits, or worktrees."""
    probe = target_path
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    free_mb = round(usage.free / (1024 * 1024), 2)
    total_mb = round(usage.total / (1024 * 1024), 2)
    ok = free_mb >= min_free_mb
    if not ok:
        raise RuntimeError(
            f"Disk space guard triggered at {probe}: {free_mb} MB free is below required minimum {min_free_mb} MB."
        )
    return {
        "ok": True,
        "path": str(probe),
        "free_mb": free_mb,
        "total_mb": total_mb,
        "min_free_mb": min_free_mb,
    }


def _uri_to_path(uri: str) -> Path | None:
    if not uri.startswith("file://"):
        return None
    parsed = urllib.parse.urlparse(uri)
    raw_path = urllib.parse.unquote(parsed.path or "")
    if raw_path.startswith("/") and len(raw_path) >= 3 and raw_path[2] == ":":
        raw_path = raw_path[1:]
    try:
        return Path(raw_path).resolve()
    except OSError:
        return None


def discover_antigravity_projects(config_root: Path | None = None) -> list[dict[str, Any]]:
    """Inspect documented ~/.gemini/config/projects/*.json to discover Antigravity Project IDs and paths."""
    base = config_root or (Path.home() / ".gemini" / "config" / "projects")
    discovered: list[dict[str, Any]] = []
    if not base.is_dir():
        return discovered

    for json_file in sorted(base.glob("*.json")):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        proj_id = str(data.get("id") or "").strip()
        name = str(data.get("name") or "").strip()
        if not proj_id:
            continue
        folders: list[str] = []
        resources = (data.get("projectResources") or {}).get("resources") or []
        if isinstance(resources, list):
            for res in resources:
                if not isinstance(res, dict):
                    continue
                uri = res.get("folderUri") or (res.get("gitFolder") or {}).get("folderUri")
                if isinstance(uri, str):
                    resolved = _uri_to_path(uri)
                    if resolved:
                        folders.append(str(resolved))
        discovered.append({
            "project_id": proj_id,
            "name": name,
            "folders": folders,
            "config_file": str(json_file),
        })
    return discovered


def detect_project_id_for_path(repo_path: Path, config_root: Path | None = None) -> str | None:
    """Match a local repository path against discovered Antigravity projects."""
    target = repo_path.resolve()
    for item in discover_antigravity_projects(config_root):
        for folder_str in item["folders"]:
            try:
                folder = Path(folder_str).resolve()
                if folder == target or target.is_relative_to(folder) or folder.is_relative_to(target):
                    return str(item["project_id"])
            except (OSError, ValueError):
                continue
    return None


def detect_moved_repositories(
    db_path: Path,
    *,
    project_key: str | None = None,
    config_root: Path | None = None,
    jsonl_path: Path | None = None,
    persist: bool = True,
) -> list[dict[str, Any]]:
    """Detect whether registered repositories have moved, been deleted, or changed identity.

    With ``persist=False`` the health is computed and returned only: no fingerprint
    backfill, no ``projects.health_status`` update, no ``audit_events`` row and no
    JSONL line are written. Read-only callers (e.g. the ``auditor_get_status`` MCP
    tool, which is reachable with only ``core:read``) must use ``persist=False``
    (ARCH-02).
    """
    discovered_projects = {
        p["project_id"]: p for p in discover_antigravity_projects(config_root)
    }
    results: list[dict[str, Any]] = []

    with connect(db_path) as conn:
        sql = "SELECT * FROM projects"
        params: list[Any] = []
        if project_key:
            sql += " WHERE project_key=?"
            params.append(project_key)
        rows = conn.execute(sql, params).fetchall()

        for row in rows:
            key = str(row["project_key"])
            repo = Path(row["repo_path"])
            stored_fp = row["repo_fingerprint"]
            ag_id = str(row["antigravity_project_id"])
            status = "HEALTHY"
            reason = "OK"
            relocated_candidates: list[str] = []

            if ag_id in ("PENDING", "UNKNOWN", ""):
                status = "PENDING_PROJECT_ID"
                reason = "Project ID is pending detection or user enrollment."
            if not repo.is_dir():
                status = "MOVED_OR_MISSING"
                reason = f"Repository directory does not exist: {repo}"
            else:
                top = git_output(repo, "rev-parse", "--show-toplevel")
                if not top:
                    status = "MOVED_OR_MISSING"
                    reason = f"Directory is no longer a valid Git repository: {repo}"
                else:
                    current_fp = compute_repo_fingerprint(repo)
                    if stored_fp == LEGACY_EMPTY_FINGERPRINT:
                        stored_fp = ""  # placeholder from a commit-less repository, not an identity
                    if stored_fp and current_fp and stored_fp != current_fp:
                        status = "MOVED_OR_MISSING"
                        reason = f"Repository root commit fingerprint changed ({stored_fp} != {current_fp})"
                    elif not stored_fp and current_fp and persist:
                        conn.execute(
                            "UPDATE projects SET repo_fingerprint=? WHERE project_key=?",
                            (current_fp, key),
                        )

            if status == "MOVED_OR_MISSING" and ag_id in discovered_projects:
                for candidate in discovered_projects[ag_id]["folders"]:
                    cand_path = Path(candidate)
                    if cand_path.is_dir() and git_output(cand_path, "rev-parse", "--show-toplevel"):
                        relocated_candidates.append(str(cand_path))

            if persist and row["health_status"] != status:
                conn.execute(
                    "UPDATE projects SET health_status=?, updated_at=CURRENT_TIMESTAMP WHERE project_key=?",
                    (status, key),
                )
            if persist and status == "MOVED_OR_MISSING":
                record_event(
                    conn,
                    "REPO_MOVED_OR_MISSING",
                    project_key=key,
                    level="WARNING",
                    details={
                        "repo_path": str(repo),
                        "reason": reason,
                        "relocated_candidates": relocated_candidates,
                    },
                    jsonl_path=jsonl_path,
                )

            results.append({
                "project_key": key,
                "repo_path": str(repo),
                "health_status": status,
                "reason": reason,
                "relocated_candidates": relocated_candidates,
            })
        if persist:
            conn.commit()
    return results


def can_retry_run(
    db_path: Path,
    *,
    project_key: str,
    run_id: str,
) -> dict[str, Any]:
    """Check and increment bounded retry counter for a failed or stale audit run."""
    with connect(db_path) as conn:
        run = conn.execute(
            "SELECT r.*, p.max_retries AS project_max_retries FROM audit_runs r JOIN projects p ON p.project_key=r.project_key WHERE r.run_id=? AND r.project_key=?",
            (run_id, project_key),
        ).fetchone()
        if not run:
            raise RuntimeError(f"Audit run '{run_id}' not found for project '{project_key}'.")
        retry_count = int(run["retry_count"] or 0)
        max_retries = int(run["max_retries"] if run["max_retries"] is not None else (run["project_max_retries"] or 2))
        allowed = retry_count < max_retries
        return {
            "run_id": run_id,
            "project_key": project_key,
            "retry_count": retry_count,
            "max_retries": max_retries,
            "allowed": allowed,
        }


def quarantine_worktree(
    db_path: Path,
    *,
    project_key: str,
    exec_id: str,
    worktree_path: Path,
    reason: str,
    quarantine_root: Path | None = None,
    detach_worktree: bool = False,
    jsonl_path: Path | None = None,
) -> dict[str, Any]:
    """Quarantine a failed execution worktree, preserving its diagnostic diff and metadata."""
    with connect(db_path) as conn:
        exec_base = conn.execute("SELECT base_commit FROM execution_runs WHERE exec_id=?", (exec_id,)).fetchone()
        if not exec_base:
            # Fail before writing a bundle that no database row would ever reference.
            raise RuntimeError(f"Cannot quarantine unknown execution run '{exec_id}'.")
    # Against the execution's base commit: verified findings are already committed in the worktree.
    diff_base = str(exec_base[0] or "") or "HEAD"
    q_root = quarantine_root or (db_path.parent.parent / "quarantine")
    quarantine_id = f"QUAR-{exec_id}-{uuid.uuid4().hex[:6]}"
    bundle_dir = q_root / quarantine_id
    bundle_dir.mkdir(parents=True, exist_ok=True)
    patch_file = bundle_dir / "diagnostic.patch"
    meta_file = bundle_dir / "quarantine.json"

    if worktree_path.is_dir():
        try:
            diff_res = subprocess.run(
                ["git", "-C", str(worktree_path), "diff", "--binary", diff_base],
                capture_output=True,
                timeout=20,
            )
            patch_file.write_bytes(diff_res.stdout or b"")
        except (OSError, subprocess.TimeoutExpired):
            patch_file.write_text("Failed to capture git diff.\n", encoding="utf-8")
    else:
        patch_file.write_text("Worktree directory did not exist at quarantine time.\n", encoding="utf-8")

    meta = {
        "quarantine_id": quarantine_id,
        "project_key": project_key,
        "exec_id": exec_id,
        "worktree_path": str(worktree_path),
        "reason": reason,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    with connect(db_path) as conn:
        exec_row = conn.execute(
            "SELECT run_id FROM execution_runs WHERE exec_id=?",
            (exec_id,),
        ).fetchone()
        run_id = str(exec_row["run_id"]) if exec_row else None
        conn.execute(
            """INSERT INTO quarantined_worktrees(
                quarantine_id, project_key, exec_id, worktree_path, reason, preserved_diff_path, status
            ) VALUES(?, ?, ?, ?, ?, ?, 'QUARANTINED')""",
            (quarantine_id, project_key, exec_id, str(worktree_path), reason, str(patch_file)),
        )
        conn.execute(
            "UPDATE execution_runs SET status='QUARANTINED', finished_at=CURRENT_TIMESTAMP, error=? WHERE exec_id=?",
            (reason, exec_id),
        )
        record_event(
            conn,
            "WORKTREE_QUARANTINED",
            project_key=project_key,
            run_id=run_id,
            level="ERROR",
            details=meta,
            jsonl_path=jsonl_path,
        )
        conn.commit()

    if detach_worktree and worktree_path.is_dir():
        _remove_git_worktree(worktree_path)

    return {
        "quarantine_id": quarantine_id,
        "bundle_dir": str(bundle_dir),
        "preserved_diff_path": str(patch_file),
        "reason": reason,
    }


def run_health_and_recovery(
    db_path: Path,
    *,
    project_key: str | None = None,
    stale_timeout_seconds: int | None = None,
    min_free_mb: int = 500,
    create_verified_backup: bool = True,
    config_root: Path | None = None,
    jsonl_path: Path | None = None,
) -> dict[str, Any]:
    """Run full Phase 7 health & recovery cycle across registered projects."""
    disk = check_disk_space(db_path.parent, min_free_mb=min_free_mb)
    integrity = check_database_integrity(db_path)
    if not integrity["ok"]:
        raise RuntimeError(f"Database integrity check failed: {integrity}")

    backup_info: dict[str, Any] | None = None
    if create_verified_backup and db_path.is_file():
        b_path = backup_database(db_path, jsonl_path=jsonl_path)
        backup_info = verify_backup_restore(b_path)

    stale = recover_stale_runs(
        db_path,
        project_key=project_key,
        stale_timeout_seconds=stale_timeout_seconds,
        jsonl_path=jsonl_path,
    )
    repos = detect_moved_repositories(
        db_path,
        project_key=project_key,
        config_root=config_root,
        jsonl_path=jsonl_path,
    )
    return {
        "disk": disk,
        "integrity": integrity,
        "backup": backup_info,
        "stale_recovery": stale,
        "repositories": repos,
    }

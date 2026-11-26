from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from broker.client import BrokerClient

from db import (
    compute_file_blob_hash,
    connect,
    normalize_rel_path,
    record_event,
)
from recovery import (
    check_disk_space,
    detect_moved_repositories,
    git_output,
    quarantine_worktree,
)
from review import assert_not_markdown_checkbox
from verification import transition_audit_run_status, verify_snapshot_consistency

FORBIDDEN_SECRET_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    ".env.test",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "service-account.json",
    "secrets.json",
}
ALLOWED_ENV_TEMPLATES = {
    ".env.example",
    ".env.sample",
    ".env.template",
}
FORBIDDEN_SECRET_SUFFIXES = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".kdbx",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".wal",
    ".shm",
}
FORBIDDEN_SHARED_DIRS = {
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
}

RAW_PRINT_PATTERN = re.compile(r"^\+\s*print\s*\(", re.MULTILINE)
SECRET_DIFF_PATTERNS = [
    re.compile(r"^\+.*(AIza[0-9A-Za-z_-]{20,}|sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY)", re.MULTILINE),
]
DESTRUCTIVE_DIFF_PATTERNS = [
    re.compile(r"^\+.*(git\s+push\s+--force|git\s+reset\s+--hard|DROP\s+TABLE|DROP\s+DATABASE)", re.IGNORECASE | re.MULTILINE),
]


def is_forbidden_secret_or_db_file(rel_path: Path | str) -> bool:
    p = Path(str(rel_path).replace("\\", "/"))
    for part in p.parts:
        lower = part.lower()
        if lower in ALLOWED_ENV_TEMPLATES:
            continue
        if lower in FORBIDDEN_SECRET_NAMES or lower.startswith(".env."):
            return True
    name_lower = p.name.lower()
    if name_lower in ALLOWED_ENV_TEMPLATES:
        return False
    if name_lower in FORBIDDEN_SECRET_NAMES or name_lower.startswith(".env."):
        return True
    if p.suffix.lower() in FORBIDDEN_SECRET_SUFFIXES:
        return True
    return False


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    if hasattr(path, "is_junction") and path.is_junction():
        return True
    return False


def sanitize_and_verify_worktree_isolation(worktree_path: Path) -> dict[str, Any]:
    """Enforce Phase 5 worktree isolation: no shared mutable node_modules/.venv links and no secret/DB files."""
    removed_links: list[str] = []
    removed_forbidden_files: list[str] = []

    for root_str, dirs, files in os.walk(worktree_path, topdown=True, followlinks=False):
        root_path = Path(root_str)
        if ".git" in dirs:
            dirs.remove(".git")

        for d in list(dirs):
            d_path = root_path / d
            if _is_link_or_junction(d_path) or d.lower() in FORBIDDEN_SHARED_DIRS:
                if _is_link_or_junction(d_path):
                    try:
                        os.unlink(d_path)
                    except OSError:
                        shutil.rmtree(d_path, ignore_errors=True)
                    removed_links.append(str(d_path.relative_to(worktree_path)))
                    dirs.remove(d)
                elif d.lower() in ("node_modules", ".venv", "venv"):
                    shutil.rmtree(d_path, ignore_errors=True)
                    removed_links.append(str(d_path.relative_to(worktree_path)))
                    dirs.remove(d)

        for f in files:
            if f == ".git":
                continue
            f_path = root_path / f
            rel = f_path.relative_to(worktree_path)
            if _is_link_or_junction(f_path):
                try:
                    f_path.unlink()
                    removed_links.append(str(rel))
                except OSError:
                    pass
            elif is_forbidden_secret_or_db_file(rel):
                try:
                    f_path.unlink()
                    removed_forbidden_files.append(str(rel))
                except OSError:
                    pass

    return {
        "isolated": True,
        "removed_links": removed_links,
        "removed_forbidden_files": removed_forbidden_files,
    }


def revalidate_finding_against_repo(
    repo_path: Path,
    finding: dict[str, Any],
    *,
    expected_base_commit: str | None = None,
) -> dict[str, Any]:
    """Revalidate a selected finding against current HEAD and working tree before acting.

    Never blindly copies uncommitted patches: if uncommitted changes affect a finding's
    file, pauses the finding with SKIPPED_RECONCILIATION.
    """
    if not repo_path.is_dir():
        return {
            "valid": False,
            "status": "SKIPPED_RECONCILIATION",
            "reason": f"Repository path does not exist: {repo_path}",
        }
    current_head = git_output(repo_path, "rev-parse", "HEAD")
    if not current_head:
        return {
            "valid": False,
            "status": "SKIPPED_RECONCILIATION",
            "reason": "Unable to resolve current Git HEAD.",
        }

    eff_expected_commit = expected_base_commit or str(finding.get("base_commit_sha") or "")
    if eff_expected_commit and eff_expected_commit not in ("", "UNCOMMITTED_WORKTREE"):
        if current_head != eff_expected_commit:
            return {
                "valid": False,
                "status": "SKIPPED_RECONCILIATION",
                "reason": (
                    f"Repository Git HEAD changed from expected base commit "
                    f"({eff_expected_commit[:12]} -> {current_head[:12]})."
                ),
            }

    from ci_check import has_ci_config, is_ci_finding

    if is_ci_finding(finding):
        # The CI finding targets a file that does not exist yet; it is still valid while the repository has no CI.
        if has_ci_config(repo_path):
            return {
                "valid": False,
                "status": "SKIPPED_RECONCILIATION",
                "reason": "The repository has a CI configuration now; the CI finding no longer applies.",
            }
        return {
            "valid": True,
            "status": "REVALIDATED",
            "reason": "Repository still has no CI configuration.",
            "current_head": current_head,
        }

    file_path = normalize_rel_path(finding.get("file_path"))
    if file_path:
        # Check if uncommitted changes (staged, unstaged, or untracked) affect this file
        porcelain = git_output(repo_path, "status", "--porcelain=v1", "--", file_path)
        diff_head = git_output(repo_path, "diff", "HEAD", "--", file_path)
        if porcelain or diff_head:
            return {
                "valid": False,
                "status": "SKIPPED_RECONCILIATION",
                "reason": (
                    f"Uncommitted changes in working tree affect '{file_path}'. "
                    "Never blindly copying dirty patches; pausing finding for reconciliation."
                ),
            }

        target_file = (repo_path / file_path).resolve()
        try:
            target_file.relative_to(repo_path.resolve())
        except ValueError:
            return {
                "valid": False,
                "status": "SKIPPED_RECONCILIATION",
                "reason": f"Finding file_path '{file_path}' escapes repository root.",
            }

        if not target_file.is_file():
            return {
                "valid": False,
                "status": "SKIPPED_RECONCILIATION",
                "reason": f"Target file '{file_path}' no longer exists in repository.",
            }

        recorded_blob_hash = finding.get("file_blob_hash")
        current_blob_hash = compute_file_blob_hash(repo_path, file_path)
        if recorded_blob_hash and current_blob_hash and recorded_blob_hash != current_blob_hash:
            return {
                "valid": False,
                "status": "SKIPPED_RECONCILIATION",
                "reason": (
                    f"Target file '{file_path}' has changed at HEAD since audit run "
                    f"({recorded_blob_hash[:10]} != {current_blob_hash[:10]}); requires re-evaluation."
                ),
            }

        line_start = finding.get("line_start")
        line_end = finding.get("line_end")
        if line_start is not None:
            total_lines = len(target_file.read_text(encoding="utf-8", errors="replace").splitlines())
            if line_start > max(1, total_lines) or (line_end is not None and line_end > max(1, total_lines)):
                return {
                    "valid": False,
                    "status": "SKIPPED_RECONCILIATION",
                    "reason": f"Finding line range ({line_start}-{line_end}) exceeds file line count ({total_lines}).",
                }

    return {
        "valid": True,
        "status": "REVALIDATED",
        "reason": "Finding revalidated cleanly against current repository state.",
        "current_head": current_head,
    }


# Interpreter/test caches an agent's test run may leave behind: never part of a fix.
_CACHE_EXCLUDES = (":(exclude,glob)**/__pycache__/**", ":(exclude,glob)**/*.pyc", ":(exclude,glob)**/.pytest_cache/**")


def _list_worktree_files(worktree_path: Path) -> dict[str, bytes]:
    """Snapshot all non-.git files in worktree for deterministic per-finding checkpointing."""
    snapshot: dict[str, bytes] = {}
    for root_str, dirs, files in os.walk(worktree_path):
        for skip in (".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"):
            if skip in dirs:
                dirs.remove(skip)
        root_path = Path(root_str)
        for f in files:
            if f == ".git":
                continue
            full = root_path / f
            rel = full.relative_to(worktree_path).as_posix()
            if full.is_file() and not _is_link_or_junction(full):
                snapshot[rel] = full.read_bytes()
    return snapshot


def create_finding_checkpoint(
    worktree_path: Path,
    checkpoints_root: Path,
    exec_id: str,
    finding_id: str,
) -> dict[str, Any]:
    """Create a deterministic per-finding file snapshot checkpoint with path validation."""
    from broker.checkpoint import validate_safe_relative_path

    checkpoint_id = f"CHK-{finding_id}-{uuid.uuid4().hex[:8]}"
    chk_dir = checkpoints_root / exec_id / checkpoint_id
    files_dir = chk_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)

    snapshot = _list_worktree_files(worktree_path)
    manifest_files: dict[str, str] = {}
    for rel_posix, raw_bytes in snapshot.items():
        validate_safe_relative_path(rel_posix)
        dest = files_dir / rel_posix
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw_bytes)
        manifest_files[rel_posix] = hashlib.sha256(raw_bytes).hexdigest()

    manifest = {
        "checkpoint_id": checkpoint_id,
        "exec_id": exec_id,
        "finding_id": finding_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": manifest_files,
    }
    manifest_path = chk_dir / "checkpoint.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "checkpoint_id": checkpoint_id,
        "checkpoint_path": str(manifest_path),
        "file_count": len(manifest_files),
    }


def rollback_finding_checkpoint(worktree_path: Path, checkpoint_manifest_path: Path) -> dict[str, Any]:
    """Restore isolated worktree to the exact pre-finding checkpoint state safely via content-addressed verification."""
    from broker.checkpoint import safe_restore_checkpoint
    return safe_restore_checkpoint(worktree_path, checkpoint_manifest_path)


def compute_changed_files(before: dict[str, bytes], after: dict[str, bytes]) -> list[str]:
    changed: set[str] = set()
    for k, v in after.items():
        if k not in before or before[k] != v:
            changed.add(k)
    for k in before:
        if k not in after:
            changed.add(k)
    return sorted(changed)


def verify_red_team_diff(
    worktree_path: Path,
    *,
    before_snapshot: dict[str, bytes],
    after_snapshot: dict[str, bytes],
    finding: dict[str, Any],
    allowed_files: set[str] | None = None,
) -> dict[str, Any]:
    """Independent adversarial-red-team verification of per-finding worktree changes."""
    changed_files = compute_changed_files(before_snapshot, after_snapshot)
    if not changed_files:
        return {
            "passed": False,
            "notes": "Red-team check failed: no files were modified for this finding.",
            "changed_files": [],
        }

    # Check 1: Forbidden secret, credential, or database files
    for rel in changed_files:
        if is_forbidden_secret_or_db_file(rel):
            return {
                "passed": False,
                "notes": f"Red-team V4 violation: forbidden secret or database file touched: '{rel}'.",
                "changed_files": changed_files,
            }
        if _is_link_or_junction(worktree_path / rel):
            return {
                "passed": False,
                "notes": f"Red-team V4 violation: symlink/junction created at '{rel}'.",
                "changed_files": changed_files,
            }

    # Check 2: Scope enforcement (do not silently expand scope to unrelated production modules)
    target_rel = normalize_rel_path(finding.get("file_path"))
    if allowed_files is not None:
        normalized_allowed = {normalize_rel_path(p) for p in allowed_files}
    elif target_rel:
        normalized_allowed = {target_rel}
    else:
        normalized_allowed = set()

    from ci_check import WORKFLOWS_DIR, is_ci_finding

    ci_fix = is_ci_finding(finding)
    if normalized_allowed:
        for rel in changed_files:
            is_test_file = _is_test_path(rel)
            if ci_fix and rel.startswith(WORKFLOWS_DIR) and rel.endswith((".yml", ".yaml")):
                continue  # the CI finding may add any workflow file
            if rel not in normalized_allowed and not is_test_file:
                return {
                    "passed": False,
                    "notes": (
                        f"Red-team scope violation: modified '{rel}' which is outside approved finding target "
                        f"{sorted(normalized_allowed)}."
                    ),
                    "changed_files": changed_files,
                }

    # Check 3: Inspect unified git diff and newly added content for V1-V7 & observability violations
    diff_res = subprocess.run(
        ["git", "-C", str(worktree_path), "diff", "HEAD"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    diff_text = diff_res.stdout or ""

    for pattern in SECRET_DIFF_PATTERNS:
        if pattern.search(diff_text):
            return {
                "passed": False,
                "notes": "Red-team V4 violation: hardcoded secret/token pattern detected in diff.",
                "changed_files": changed_files,
            }

    for pattern in DESTRUCTIVE_DIFF_PATTERNS:
        if pattern.search(diff_text):
            return {
                "passed": False,
                "notes": "Red-team V5 violation: destructive git or SQL operation detected in diff.",
                "changed_files": changed_files,
            }

    # Check raw print() in modified non-test Python files
    for rel in changed_files:
        is_py = rel.endswith(".py")
        is_test = _is_test_path(rel)
        if is_py and not is_test and rel in after_snapshot:
            file_diff_res = subprocess.run(
                ["git", "-C", str(worktree_path), "diff", "HEAD", "--", rel],
                capture_output=True,
                text=True,
                timeout=15,
            )
            file_diff = file_diff_res.stdout or ""
            if RAW_PRINT_PATTERN.search(file_diff):
                return {
                    "passed": False,
                    "notes": f"Red-team Observability violation: raw print() added in production file '{rel}'.",
                    "changed_files": changed_files,
                }

    return {
        "passed": True,
        "notes": f"Red-team V1-V7 verification passed across {len(changed_files)} file(s).",
        "changed_files": changed_files,
    }


def _run_shell_test(worktree_path: Path, command: list[str] | None, timeout: int = 120) -> tuple[bool, str]:
    if not command:
        return True, "No external test command configured; treated as pass."
    from ci_check import project_test_environment

    env = project_test_environment()  # untrusted project code: no credentials from the environment
    try:
        res = subprocess.run(
            command,
            cwd=str(worktree_path),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        output = ((res.stdout or "") + "\n" + (res.stderr or "")).strip()[-1000:]
        return res.returncode == 0, output
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def _compensate_created_worktree(
    repo_path: Path,
    worktree_path: Path,
    branch_name: str | None = None,
) -> dict[str, Any]:
    """Deterministically remove an uncommitted/orphaned Git worktree, prune metadata, and delete its branch."""
    removed_wt = False
    pruned = False
    removed_branch = False
    errors: list[str] = []

    if repo_path.is_dir():
        try:
            rm_res = subprocess.run(
                ["git", "-C", str(repo_path), "worktree", "remove", "--force", str(worktree_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            removed_wt = rm_res.returncode == 0
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"git worktree remove failed: {exc}")

    if worktree_path.exists():
        try:
            shutil.rmtree(worktree_path, ignore_errors=True)
            removed_wt = not worktree_path.exists()
        except OSError as exc:
            errors.append(f"rmtree failed: {exc}")

    if repo_path.is_dir():
        try:
            pr_res = subprocess.run(
                ["git", "-C", str(repo_path), "worktree", "prune"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            pruned = pr_res.returncode == 0
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"git worktree prune failed: {exc}")

        if branch_name:
            try:
                br_res = subprocess.run(
                    ["git", "-C", str(repo_path), "branch", "-D", branch_name],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                removed_branch = br_res.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                pass

    return {
        "compensated": not worktree_path.exists(),
        "removed_worktree": removed_wt,
        "pruned_git_worktrees": pruned,
        "removed_branch": removed_branch,
        "errors": errors,
    }


def _record_worktree_op_out_of_band(
    db_path: Path,
    *,
    op_id: str,
    exec_id: str,
    project_key: str,
    run_id: str,
    approval_id: str,
    repo_path: str,
    worktree_path: str,
    branch_name: str,
    base_commit: str,
    status: str,
    error: str | None = None,
) -> None:
    """Persist worktree operation tracking when no outer write lock is held."""
    with connect(db_path) as op_conn:
        op_conn.execute(
            """INSERT INTO execution_worktree_ops(
                op_id, exec_id, project_key, run_id, approval_id,
                repo_path, worktree_path, branch_name, base_commit, status, error
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(op_id) DO UPDATE SET
                status=excluded.status,
                error=excluded.error,
                updated_at=CURRENT_TIMESTAMP""",
            (
                op_id,
                exec_id,
                project_key,
                run_id,
                approval_id,
                repo_path,
                worktree_path,
                branch_name,
                base_commit,
                status,
                error,
            ),
        )
        op_conn.commit()


def _is_test_path(rel: str) -> bool:
    """Test file by explicit convention (``test_*.py``, ``*_test.py``, ``conftest.py`` or a ``test``/``tests``
    directory) -- not any name that merely contains "test" (``attestation.py``, ``latest.py``)."""
    parts = [x for x in rel.replace("\\", "/").lower().split("/") if x]
    if not parts:
        return False
    name = parts[-1]
    stem = name.rsplit(".", 1)[0]
    return (
        any(d in ("test", "tests") for d in parts[:-1])
        or stem.startswith("test_")
        or stem.endswith("_test")
        or name == "conftest.py"
    )


def _broker_checkpoint_id(state: dict[str, Any], f_exec: dict[str, Any], finding_id: str) -> str:
    """Checkpoint id registered for ``finding_id`` (required by ``BrokerClient.restore_checkpoint``)."""
    chk_id = f_exec.get("checkpoint_id")
    if not chk_id:
        matching = next((c for c in state.get("checkpoints", []) if c.get("finding_id") == finding_id), None)
        chk_id = (matching or {}).get("checkpoint_id")
    if not chk_id:
        raise RuntimeError(f"No registered checkpoint for finding '{finding_id}'; cannot roll back via broker.")
    return str(chk_id)


def reconcile_interrupted_worktree_ops(
    db_path: Path,
    *,
    project_key: str | None = None,
) -> list[dict[str, Any]]:
    """Reconcile and clean up any orphaned Git worktrees left behind by an interrupted execution startup."""
    reconciled: list[dict[str, Any]] = []
    with connect(db_path) as conn:
        has_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='execution_worktree_ops'"
        ).fetchone()
        if not has_table:
            return reconciled
        sql = "SELECT * FROM execution_worktree_ops WHERE status IN ('PREPARING', 'WORKTREE_CREATED', 'COMPENSATION_FAILED')"
        params: list[Any] = []
        if project_key:
            sql += " AND project_key=?"
            params.append(project_key)
        rows = conn.execute(sql, params).fetchall()

        for row in rows:
            op_id = str(row["op_id"])
            exec_id = str(row["exec_id"])
            has_exec = conn.execute(
                "SELECT 1 FROM execution_runs WHERE exec_id=?",
                (exec_id,),
            ).fetchone()
            if has_exec:
                conn.execute(
                    "UPDATE execution_worktree_ops SET status='COMMITTED', updated_at=CURRENT_TIMESTAMP WHERE op_id=?",
                    (op_id,),
                )
                reconciled.append({"op_id": op_id, "exec_id": exec_id, "status": "COMMITTED"})
            else:
                comp = _compensate_created_worktree(
                    Path(row["repo_path"]),
                    Path(row["worktree_path"]),
                    row["branch_name"],
                )
                new_status = "COMPENSATED" if comp["compensated"] else "COMPENSATION_FAILED"
                err_txt = "; ".join(comp["errors"]) if comp["errors"] else row["error"]
                conn.execute(
                    "UPDATE execution_worktree_ops SET status=?, error=?, updated_at=CURRENT_TIMESTAMP WHERE op_id=?",
                    (new_status, err_txt, op_id),
                )
                reconciled.append({"op_id": op_id, "exec_id": exec_id, "status": new_status, **comp})
        conn.commit()
    return reconciled


def _validate_finding_lineage_and_eligibility(
    conn: Any,
    *,
    project_key: str,
    run_id: str,
    finding_id: str,
    require_open: bool = True,
) -> dict[str, Any]:
    """Re-verify finding eligibility, verification status, evidence status, remediation safety,
    and primary != verifier conversation independence at every execution security boundary.
    """
    run_row = conn.execute(
        "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
        (run_id, project_key),
    ).fetchone()
    if not run_row:
        raise RuntimeError(f"Audit run '{run_id}' not found for project '{project_key}'.")

    unresolved_vruns = conn.execute(
        """SELECT verification_run_id, status FROM audit_verification_runs
           WHERE audit_run_id=? AND status NOT IN ('FINALIZED', 'COMPLETED', 'ARCHIVED')""",
        (run_id,),
    ).fetchall()
    if unresolved_vruns:
        pending_desc = ", ".join(f"{r['verification_run_id']}({r['status']})" for r in unresolved_vruns)
        raise RuntimeError(
            f"Execution rejected: audit run '{run_id}' has unresolved verification run(s): {pending_desc}."
        )

    unverified_cands = conn.execute(
        """SELECT candidate_finding_id FROM candidate_findings
           WHERE run_id=? AND status='CANDIDATE'""",
        (run_id,),
    ).fetchall()
    if unverified_cands:
        cids = [str(r["candidate_finding_id"]) for r in unverified_cands]
        raise RuntimeError(
            f"Execution rejected: audit run '{run_id}' has unverified candidate finding(s): {cids}."
        )

    f_row = conn.execute(
        "SELECT * FROM findings WHERE finding_id=? AND project_key=?",
        (finding_id, project_key),
    ).fetchone()
    if not f_row:
        raise RuntimeError(f"Approved finding '{finding_id}' not found for project '{project_key}'.")
    if run_id not in (f_row["run_id"], f_row["last_seen_run_id"]):
        raise RuntimeError(
            f"Approved finding '{finding_id}' does not belong to audit run '{run_id}'."
        )
    if require_open and str(f_row["lifecycle"]) != "OPEN":
        raise RuntimeError(
            f"Approved finding '{finding_id}' is no longer OPEN (lifecycle={f_row['lifecycle']})."
        )
    if str(f_row["verification_status"] or "") not in ("VERIFIED", "CONFIRMED") or int(f_row["execution_eligible"] or 0) != 1:
        raise RuntimeError(f"Approved finding '{finding_id}' is not verified/execution-eligible.")
    if str(f_row["evidence_validation_status"] or "") not in ("PASSED", "VALID"):
        raise RuntimeError(f"Approved finding '{finding_id}' failed evidence validation.")

    f_keys = f_row.keys()
    rem_safe = (
        int(f_row["remediation_safe"])
        if ("remediation_safe" in f_keys and f_row["remediation_safe"] is not None)
        else 0
    )
    if rem_safe != 1:
        raise RuntimeError(f"Approved finding '{finding_id}' is marked remediation_safe=0.")

    f_vrun_id = str(
        (f_row["verification_run_id"] if "verification_run_id" in f_keys else None)
        or (f_row["verified_by_run_id"] if "verified_by_run_id" in f_keys else None)
        or ""
    ).strip()
    if not f_vrun_id:
        raise RuntimeError(f"Approved finding '{finding_id}' is missing verification_run_id lineage.")

    vrun_row = conn.execute(
        """SELECT * FROM audit_verification_runs
           WHERE verification_run_id=? AND audit_run_id=? AND status IN ('FINALIZED', 'COMPLETED')""",
        (f_vrun_id, run_id),
    ).fetchone()
    if not vrun_row:
        raise RuntimeError(
            f"Approved finding '{finding_id}' references unfinalized or mismatched verification_run_id '{f_vrun_id}'."
        )

    primary_conv = str(run_row["agent_conversation_id"] or "").strip()
    f_v_conv = str(f_row["verifier_conversation_id"] or vrun_row["verifier_conversation_id"] or "").strip()
    if not f_v_conv:
        raise RuntimeError(f"Approved finding '{finding_id}' is missing verifier_conversation_id.")
    if primary_conv and primary_conv == f_v_conv:
        raise RuntimeError(
            f"Independence violation for finding '{finding_id}': verifier_conversation_id matches primary conversation."
        )

    cand_row = conn.execute(
        """SELECT source_origin, discovered_by_conversation_id
           FROM candidate_findings
           WHERE run_id=? AND (candidate_finding_id=? OR canonical_finding_id=?)
           LIMIT 1""",
        (run_id, finding_id, finding_id),
    ).fetchone()
    if cand_row and str(cand_row["source_origin"] or "") == "VERIFIER_DISCOVERED":
        disc_conv = str(cand_row["discovered_by_conversation_id"] or "").strip()
        if disc_conv and disc_conv == f_v_conv:
            raise RuntimeError(
                f"Independence violation for verifier-discovered finding '{finding_id}': "
                "follow-up verifier conversation matches discovering conversation."
            )

    return dict(f_row)


def start_isolated_execution(
    db_path: Path | None = None,
    *,
    project_key: str,
    approval_token: str,
    worktrees_root: Path | None = None,
    min_free_mb: int = 500,
    jsonl_path: Path | None = None,
    _post_worktree_fault_hook: Callable[[Path], None] | None = None,
    broker_client: BrokerClient | None = None,
) -> dict[str, Any]:
    if broker_client is not None:
        return start_isolated_execution_broker(
            broker_client,
            project_key=project_key,
            approval_token=approval_token,
            worktrees_root=worktrees_root,
            min_free_mb=min_free_mb,
            jsonl_path=jsonl_path,
            _post_worktree_fault_hook=_post_worktree_fault_hook,
        )
    """Validate approval_token, audit run status, verification run status, and snapshot consistency
    atomically before consuming the token or creating an isolated Git worktree.
    If any step after `git worktree add` fails before `COMMIT`, compensates by removing and pruning
    the worktree and rolling back the database transaction so no orphan worktree or half-consumed
    token can remain.
    """
    assert_not_markdown_checkbox(approval_token, "approval_token")
    if not approval_token.startswith("agya_"):
        raise RuntimeError("Invalid approval_token format. Authorization must be issued via authorize_execution.")

    reconcile_interrupted_worktree_ops(db_path, project_key=project_key)

    now = datetime.now(timezone.utc)
    wt_base = worktrees_root or (db_path.parent.parent / "worktrees")

    worktree_created_info: tuple[Path, Path, str, str, str, str, str] | None = None
    # (repo_path, worktree_path, branch_name, op_id, exec_id, run_id, approval_id)

    conn = connect(db_path)
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        approval = conn.execute(
            "SELECT * FROM execution_approvals WHERE approval_token=? AND project_key=?",
            (approval_token, project_key),
        ).fetchone()
        if not approval:
            conn.execute("ROLLBACK")
            raise RuntimeError("Approval token was not found for this project.")
        if approval["status"] != "AUTHORIZED":
            conn.execute("ROLLBACK")
            raise RuntimeError(f"Approval token is not active (status={approval['status']}).")

        expires_dt = datetime.fromisoformat(str(approval["expires_at"]))
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=timezone.utc)
        if now >= expires_dt:
            conn.execute(
                "UPDATE execution_approvals SET status='EXPIRED' WHERE approval_id=?",
                (approval["approval_id"],),
            )
            conn.execute("COMMIT")
            raise RuntimeError("Approval token has expired; please re-authorize execution.")

        project = conn.execute(
            "SELECT * FROM projects WHERE project_key=?",
            (project_key,),
        ).fetchone()
        if not project:
            conn.execute("ROLLBACK")
            raise RuntimeError(f"Project '{project_key}' not found.")

        run_id = str(approval["run_id"])
        run_row = conn.execute(
            "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
            (run_id, project_key),
        ).fetchone()
        if not run_row:
            conn.execute("ROLLBACK")
            raise RuntimeError(f"Audit run '{run_id}' not found for project '{project_key}'.")
        if str(run_row["status"]) not in ("READY_FOR_REVIEW", "PARTIAL"):
            conn.execute("ROLLBACK")
            raise RuntimeError(
                f"Execution rejected: audit run '{run_id}' is in status '{run_row['status']}', "
                "expected 'READY_FOR_REVIEW' or 'PARTIAL'."
            )

        vrun_row = conn.execute(
            """SELECT * FROM audit_verification_runs
               WHERE audit_run_id=? AND status IN ('FINALIZED', 'COMPLETED')
               ORDER BY completed_at DESC, created_at DESC, rowid DESC LIMIT 1""",
            (run_id,),
        ).fetchone()
        if not vrun_row:
            conn.execute("ROLLBACK")
            raise RuntimeError(
                f"Execution rejected: audit run '{run_id}' does not have a completed second-pass verification run."
            )

        approved_finding_ids: list[str] = json.loads(str(approval["approved_finding_ids"]))
        if not approved_finding_ids:
            conn.execute("ROLLBACK")
            raise RuntimeError("Execution rejected: approval token contains no approved findings.")

        for fid in approved_finding_ids:
            _validate_finding_lineage_and_eligibility(
                conn,
                project_key=project_key,
                run_id=run_id,
                finding_id=fid,
                require_open=True,
            )

        repo_path = Path(project["repo_path"])
        if not repo_path.is_dir() or not (repo_path / ".git").exists():
            conn.execute("ROLLBACK")
            moved = detect_moved_repositories(db_path, project_key=project_key, jsonl_path=jsonl_path)
            if moved and moved[0]["health_status"] == "MOVED_OR_MISSING":
                raise RuntimeError(f"Cannot execute: repository moved or missing ({moved[0]['reason']}).")
            raise RuntimeError(f"Cannot execute: repository path invalid ({repo_path}).")

        # Re-validate snapshot consistency BEFORE consuming token or creating worktree
        consistency = verify_snapshot_consistency(conn, repo_path=repo_path, run_id=run_id)
        live_head = git_output(repo_path, "rev-parse", "HEAD")
        expected_commit = str(approval["base_commit"] or "")
        head_mismatch = bool(expected_commit and live_head and live_head != expected_commit)

        if not consistency["consistent"] or head_mismatch:
            stale_reason = str(
                consistency.get("reason")
                if not consistency["consistent"]
                else f"Git HEAD changed from {expected_commit} to {live_head}."
            )
            transition_audit_run_status(
                conn,
                run_id,
                "VERIFICATION_STALE",
                reason=f"Execution blocked due to stale repository snapshot: {stale_reason}",
                actor="executor",
                jsonl_path=jsonl_path,
            )
            conn.execute(
                """UPDATE audit_verification_runs
                   SET status='STALE', error_code='STALE_SNAPSHOT', error_message=?
                   WHERE audit_run_id=? AND status IN ('FINALIZED', 'COMPLETED', 'RUNNING', 'PENDING', 'DISPATCHING')""",
                (stale_reason, run_id),
            )
            record_event(
                conn,
                "EXECUTION_BLOCKED_STALE_SNAPSHOT",
                project_key=project_key,
                run_id=run_id,
                level="ERROR",
                details={
                    "approval_id": approval["approval_id"],
                    "code": consistency.get("code") or "STALE_GIT_HEAD_CHANGED",
                    "reason": stale_reason,
                },
                jsonl_path=jsonl_path,
            )
            conn.execute("COMMIT")
            raise RuntimeError(f"Execution blocked due to stale repository snapshot: {stale_reason}")

        check_disk_space(wt_base, min_free_mb=min_free_mb)

        base_commit = str(approval["base_commit"] or live_head)
        if not base_commit:
            conn.execute("ROLLBACK")
            raise RuntimeError("Unable to determine base_commit for isolated worktree.")

        exec_id = "EXEC-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        op_id = f"WTOP-{exec_id}"
        worktree_path = (wt_base / project_key / exec_id).resolve()
        worktree_path.parent.mkdir(parents=True, exist_ok=True)
        branch_name = f"audit-isolated/{exec_id.lower()}"

        res = subprocess.run(
            ["git", "-C", str(repo_path), "worktree", "add", "--detach", str(worktree_path), base_commit],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if res.returncode != 0:
            conn.execute("ROLLBACK")
            raise RuntimeError(f"Failed to create isolated git worktree: {(res.stderr or res.stdout).strip()}")

        worktree_created_info = (
            repo_path,
            worktree_path,
            branch_name,
            op_id,
            exec_id,
            run_id,
            str(approval["approval_id"]),
        )

        isolation_info = sanitize_and_verify_worktree_isolation(worktree_path)

        if _post_worktree_fault_hook is not None:
            _post_worktree_fault_hook(worktree_path)

        upd = conn.execute(
            "UPDATE execution_approvals SET status='CONSUMED' WHERE approval_id=? AND status='AUTHORIZED'",
            (approval["approval_id"],),
        )
        if upd.rowcount != 1:
            raise RuntimeError("Approval token is no longer active (concurrently consumed).")

        conn.execute(
            """INSERT INTO execution_worktree_ops(
                op_id, exec_id, project_key, run_id, approval_id,
                repo_path, worktree_path, branch_name, base_commit, status
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'COMMITTED')""",
            (
                op_id,
                exec_id,
                project_key,
                run_id,
                approval["approval_id"],
                str(repo_path),
                str(worktree_path),
                branch_name,
                base_commit,
            ),
        )

        conn.execute(
            """INSERT INTO execution_runs(
                exec_id, project_key, run_id, approval_id, status,
                worktree_path, branch_name, base_commit, working_tree_hash, max_retries
            ) VALUES(?, ?, ?, ?, 'RUNNING', ?, ?, ?, ?, ?)""",
            (
                exec_id,
                project_key,
                run_id,
                approval["approval_id"],
                str(worktree_path),
                branch_name,
                base_commit,
                approval["working_tree_hash"],
                int(project["max_retries"] or 2),
            ),
        )
        for fid in approved_finding_ids:
            f_exec_id = f"FEXEC-{exec_id}-{fid}"
            conn.execute(
                """INSERT INTO finding_executions(
                    finding_exec_id, exec_id, finding_id, status, repair_attempts
                ) VALUES(?, ?, ?, 'PENDING', 0)""",
                (f_exec_id, exec_id, fid),
            )
        record_event(
            conn,
            "EXECUTION_STARTED",
            project_key=project_key,
            run_id=run_id,
            details={
                "exec_id": exec_id,
                "worktree_path": str(worktree_path),
                "base_commit": base_commit,
                "approved_finding_ids": approved_finding_ids,
                "isolation": isolation_info,
            },
            jsonl_path=jsonl_path,
        )
        conn.execute("COMMIT")
        worktree_created_info = None
    except Exception as exc:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        if worktree_created_info is not None:
            c_repo, c_wt, c_br, c_op_id, c_exec_id, c_run_id, c_app_id = worktree_created_info
            comp = _compensate_created_worktree(c_repo, c_wt, c_br)
            try:
                _record_worktree_op_out_of_band(
                    db_path,
                    op_id=c_op_id,
                    exec_id=c_exec_id,
                    project_key=project_key,
                    run_id=c_run_id,
                    approval_id=c_app_id,
                    repo_path=str(c_repo),
                    worktree_path=str(c_wt),
                    branch_name=c_br,
                    base_commit=str(approval["base_commit"] if approval else ""),
                    status="COMPENSATED" if comp["compensated"] else "COMPENSATION_FAILED",
                    error=str(exc),
                )
            except Exception:
                pass
        raise
    finally:
        conn.close()

    return {
        "exec_id": exec_id,
        "project_key": project_key,
        "run_id": run_id,
        "worktree_path": str(worktree_path),
        "base_commit": base_commit,
        "approved_finding_ids": approved_finding_ids,
        "isolation": isolation_info,
    }


RemediationCallback = Callable[[Path, dict[str, Any], int], None]
TestCallback = Callable[[Path, dict[str, Any], int], tuple[bool, str]]
RedTeamCallback = Callable[[Path, dict[str, Any], list[str], int], tuple[bool, str]]


def execute_approved_findings(
    db_path: Path | None = None,
    *,
    project_key: str,
    approval_token: str,
    remediation_fn: RemediationCallback | None = None,
    happy_test_fn: TestCallback | None = None,
    adversarial_test_fn: TestCallback | None = None,
    red_team_fn: RedTeamCallback | None = None,
    integration_test_fn: Callable[[Path], tuple[bool, str]] | None = None,
    happy_test_cmd: list[str] | None = None,
    adversarial_test_cmd: list[str] | None = None,
    integration_test_cmd: list[str] | None = None,
    worktrees_root: Path | None = None,
    checkpoints_root: Path | None = None,
    quarantine_root: Path | None = None,
    min_free_mb: int = 500,
    jsonl_path: Path | None = None,
    broker_client: BrokerClient | None = None,
) -> dict[str, Any]:
    if broker_client is not None:
        return execute_approved_findings_broker(
            broker_client,
            project_key=project_key,
            approval_token=approval_token,
            remediation_fn=remediation_fn,
            happy_test_fn=happy_test_fn,
            adversarial_test_fn=adversarial_test_fn,
            red_team_fn=red_team_fn,
            integration_test_fn=integration_test_fn,
            happy_test_cmd=happy_test_cmd,
            adversarial_test_cmd=adversarial_test_cmd,
            integration_test_cmd=integration_test_cmd,
            worktrees_root=worktrees_root,
            checkpoints_root=checkpoints_root,
            quarantine_root=quarantine_root,
            min_free_mb=min_free_mb,
            jsonl_path=jsonl_path,
        )
    """Execute approved findings one at a time in an isolated Git worktree with checkpoints,
    dual-path tests, independent red-team verification, max 2 repair attempts, and integration tests.
    """
    session = start_isolated_execution(
        db_path,
        project_key=project_key,
        approval_token=approval_token,
        worktrees_root=worktrees_root,
        min_free_mb=min_free_mb,
        jsonl_path=jsonl_path,
    )
    exec_id = session["exec_id"]
    run_id = session["run_id"]
    worktree_path = Path(session["worktree_path"])
    chk_root = checkpoints_root or (db_path.parent.parent / "checkpoints")

    with connect(db_path) as conn:
        project = conn.execute(
            "SELECT * FROM projects WHERE project_key=?",
            (project_key,),
        ).fetchone()
        repo_path = Path(project["repo_path"])

    per_finding_results: list[dict[str, Any]] = []
    verified_finding_ids: list[str] = []
    rolled_back_ids: list[str] = []
    skipped_reconciliation_ids: list[str] = []

    for finding_id in session["approved_finding_ids"]:
        with connect(db_path) as conn:
            run_row = conn.execute(
                "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
                (run_id, project_key),
            ).fetchone()
            if not run_row or str(run_row["status"]) not in ("READY_FOR_REVIEW", "PARTIAL"):
                raise RuntimeError(
                    f"Execution rejected: audit run '{run_id}' is in status "
                    f"'{run_row['status'] if run_row else 'MISSING'}'."
                )
            finding = _validate_finding_lineage_and_eligibility(
                conn,
                project_key=project_key,
                run_id=run_id,
                finding_id=finding_id,
                require_open=True,
            )
            live_head = git_output(repo_path, "rev-parse", "HEAD")
            expected_commit = str(session["base_commit"] or "")
            if expected_commit and live_head != expected_commit:
                stale_reason = f"Git HEAD changed from {expected_commit} to {live_head}."
                if str(run_row["status"]) != "VERIFICATION_STALE":
                    transition_audit_run_status(
                        conn,
                        run_id,
                        "VERIFICATION_STALE",
                        reason=f"Execution blocked due to stale repository snapshot: {stale_reason}",
                        actor="executor",
                        jsonl_path=jsonl_path,
                    )
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='STALE', error_code='STALE_SNAPSHOT', error_message=?
                       WHERE audit_run_id=? AND status IN ('FINALIZED', 'COMPLETED', 'RUNNING', 'PENDING', 'DISPATCHING')""",
                    (stale_reason, run_id),
                )
                conn.commit()
                raise RuntimeError(f"Execution blocked due to stale repository snapshot: {stale_reason}")

        # Step 1: Revalidate against current main repo (never copy dirty uncommitted patches)
        reval = revalidate_finding_against_repo(
            repo_path,
            finding,
            expected_base_commit=session["base_commit"],
        )
        if not reval["valid"]:
            skipped_reconciliation_ids.append(finding_id)
            with connect(db_path) as conn:
                conn.execute(
                    """UPDATE finding_executions
                       SET status='SKIPPED_RECONCILIATION', finished_at=CURRENT_TIMESTAMP, error=?
                       WHERE exec_id=? AND finding_id=?""",
                    (reval["reason"], exec_id, finding_id),
                )
                record_event(
                    conn,
                    "FINDING_SKIPPED_RECONCILIATION",
                    project_key=project_key,
                    run_id=run_id,
                    level="WARNING",
                    details={"exec_id": exec_id, "finding_id": finding_id, "reason": reval["reason"]},
                    jsonl_path=jsonl_path,
                )
                conn.commit()
            per_finding_results.append({
                "finding_id": finding_id,
                "status": "SKIPPED_RECONCILIATION",
                "reason": reval["reason"],
                "repair_attempts": 0,
            })
            continue

        with connect(db_path) as conn:
            consistency = verify_snapshot_consistency(conn, repo_path=repo_path, run_id=run_id)
            if not consistency["consistent"]:
                stale_reason = str(consistency.get("reason") or "Snapshot consistency check failed.")
                run_row = conn.execute(
                    "SELECT status FROM audit_runs WHERE run_id=?",
                    (run_id,),
                ).fetchone()
                if run_row and str(run_row["status"]) != "VERIFICATION_STALE":
                    transition_audit_run_status(
                        conn,
                        run_id,
                        "VERIFICATION_STALE",
                        reason=f"Execution blocked due to stale repository snapshot: {stale_reason}",
                        actor="executor",
                        jsonl_path=jsonl_path,
                    )
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='STALE', error_code='STALE_SNAPSHOT', error_message=?
                       WHERE audit_run_id=? AND status IN ('FINALIZED', 'COMPLETED', 'RUNNING', 'PENDING', 'DISPATCHING')""",
                    (stale_reason, run_id),
                )
                conn.commit()
                raise RuntimeError(f"Execution blocked due to stale repository snapshot: {stale_reason}")

        # Step 2: Create pre-finding checkpoint inside isolated worktree
        chk = create_finding_checkpoint(worktree_path, chk_root, exec_id, finding_id)
        before_snapshot = _list_worktree_files(worktree_path)

        with connect(db_path) as conn:
            conn.execute(
                """UPDATE finding_executions
                   SET status='IN_PROGRESS', checkpoint_id=?, checkpoint_path=?
                   WHERE exec_id=? AND finding_id=?""",
                (chk["checkpoint_id"], chk["checkpoint_path"], exec_id, finding_id),
            )
            conn.commit()

        # Step 3: Execute with bounded repair loop (initial attempt 0 + max 2 repair attempts = 3 tries)
        repair_attempts = 0
        verified = False
        last_error = ""
        happy_ok = False
        adv_ok = False
        rt_ok = False
        rt_notes = ""
        changed_files: list[str] = []

        for attempt in range(0, 3):  # attempt 0 (initial), 1 (repair 1), 2 (repair 2)
            repair_attempts = attempt
            try:
                if remediation_fn is not None:
                    remediation_fn(worktree_path, finding, attempt)
            except Exception as exc:
                last_error = f"Remediation callback error on attempt {attempt}: {exc}"
                continue

            # Ensure worktree isolation wasn't violated
            sanitize_and_verify_worktree_isolation(worktree_path)
            after_snapshot = _list_worktree_files(worktree_path)

            # Targeted happy-path test
            if happy_test_fn is not None:
                happy_ok, happy_msg = happy_test_fn(worktree_path, finding, attempt)
            else:
                happy_ok, happy_msg = _run_shell_test(worktree_path, happy_test_cmd)

            # Targeted adversarial test
            if adversarial_test_fn is not None:
                adv_ok, adv_msg = adversarial_test_fn(worktree_path, finding, attempt)
            else:
                adv_ok, adv_msg = _run_shell_test(worktree_path, adversarial_test_cmd)

            # Independent adversarial-red-team verification
            rt_check = verify_red_team_diff(
                worktree_path,
                before_snapshot=before_snapshot,
                after_snapshot=after_snapshot,
                finding=finding,
            )
            rt_ok = bool(rt_check["passed"])
            rt_notes = str(rt_check["notes"])
            changed_files = list(rt_check["changed_files"])

            if rt_ok and red_team_fn is not None:
                custom_rt_ok, custom_rt_notes = red_team_fn(worktree_path, finding, changed_files, attempt)
                rt_ok = rt_ok and custom_rt_ok
                if custom_rt_notes:
                    rt_notes = f"{rt_notes} | {custom_rt_notes}"

            if happy_ok and adv_ok and rt_ok:
                verified = True
                last_error = ""
                break

            reasons: list[str] = []
            if not happy_ok:
                reasons.append(f"happy_test failed ({happy_msg})")
            if not adv_ok:
                reasons.append(f"adversarial_test failed ({adv_msg})")
            if not rt_ok:
                reasons.append(f"red_team failed ({rt_notes})")
            last_error = "; ".join(reasons)

            # If remediation_fn is None, retrying won't change state
            if remediation_fn is None:
                break

        if verified:
            verified_finding_ids.append(finding_id)
            with connect(db_path) as conn:
                conn.execute(
                    """UPDATE finding_executions
                       SET status='VERIFIED', repair_attempts=?, happy_test_passed=1,
                           adversarial_test_passed=1, red_team_passed=1, red_team_notes=?,
                           diff_summary=?, finished_at=CURRENT_TIMESTAMP, error=NULL
                       WHERE exec_id=? AND finding_id=?""",
                    (
                        repair_attempts,
                        rt_notes,
                        json.dumps({"changed_files": changed_files}),
                        exec_id,
                        finding_id,
                    ),
                )
                record_event(
                    conn,
                    "FINDING_EXECUTION_VERIFIED",
                    project_key=project_key,
                    run_id=run_id,
                    details={
                        "exec_id": exec_id,
                        "finding_id": finding_id,
                        "repair_attempts": repair_attempts,
                        "changed_files": changed_files,
                    },
                    jsonl_path=jsonl_path,
                )
                conn.commit()
            per_finding_results.append({
                "finding_id": finding_id,
                "status": "VERIFIED",
                "repair_attempts": repair_attempts,
                "changed_files": changed_files,
            })
        else:
            # Roll back isolated worktree to pre-finding checkpoint!
            rollback_finding_checkpoint(worktree_path, Path(chk["checkpoint_path"]))
            rolled_back_ids.append(finding_id)
            with connect(db_path) as conn:
                conn.execute(
                    """UPDATE finding_executions
                       SET status='ROLLED_BACK', repair_attempts=?, happy_test_passed=?,
                           adversarial_test_passed=?, red_team_passed=?, red_team_notes=?,
                           finished_at=CURRENT_TIMESTAMP, error=?
                       WHERE exec_id=? AND finding_id=?""",
                    (
                        repair_attempts,
                        1 if happy_ok else 0,
                        1 if adv_ok else 0,
                        1 if rt_ok else 0,
                        rt_notes,
                        last_error,
                        exec_id,
                        finding_id,
                    ),
                )
                record_event(
                    conn,
                    "FINDING_EXECUTION_ROLLED_BACK",
                    project_key=project_key,
                    run_id=run_id,
                    level="WARNING",
                    details={
                        "exec_id": exec_id,
                        "finding_id": finding_id,
                        "repair_attempts": repair_attempts,
                        "checkpoint_id": chk["checkpoint_id"],
                        "error": last_error,
                    },
                    jsonl_path=jsonl_path,
                )
                conn.commit()
            per_finding_results.append({
                "finding_id": finding_id,
                "status": "ROLLED_BACK",
                "repair_attempts": repair_attempts,
                "error": last_error,
            })

    # Step 4: Broader integration test across the isolated worktree
    integration_passed = True
    integration_msg = "Integration verification passed."
    if verified_finding_ids:
        if integration_test_fn is not None:
            integration_passed, integration_msg = integration_test_fn(worktree_path)
        elif integration_test_cmd is not None:
            integration_passed, integration_msg = _run_shell_test(worktree_path, integration_test_cmd)

    if verified_finding_ids and not integration_passed:
        q_info = quarantine_worktree(
            db_path,
            project_key=project_key,
            exec_id=exec_id,
            worktree_path=worktree_path,
            reason=f"Integration test suite failed: {integration_msg}",
            quarantine_root=quarantine_root,
            jsonl_path=jsonl_path,
        )
        return {
            "exec_id": exec_id,
            "project_key": project_key,
            "run_id": run_id,
            "status": "QUARANTINED",
            "worktree_path": str(worktree_path),
            "verified_finding_ids": [],
            "rolled_back_finding_ids": rolled_back_ids,
            "skipped_reconciliation_ids": skipped_reconciliation_ids,
            "quarantine": q_info,
            "findings": per_finding_results,
        }

    # Determine final execution status
    if verified_finding_ids and not rolled_back_ids and not skipped_reconciliation_ids:
        final_status = "COMPLETED"
        audit_run_status = "COMPLETED"
    elif verified_finding_ids:
        final_status = "PARTIAL"
        audit_run_status = "PARTIAL"
    elif skipped_reconciliation_ids and not rolled_back_ids:
        final_status = "PARTIAL"
        audit_run_status = "READY_FOR_REVIEW"
    else:
        final_status = "ROLLED_BACK"
        audit_run_status = "READY_FOR_REVIEW"

    with connect(db_path) as conn:
        run_row = conn.execute(
            "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
            (run_id, project_key),
        ).fetchone()
        if not run_row or str(run_row["status"]) not in ("READY_FOR_REVIEW", "PARTIAL"):
            raise RuntimeError(
                f"Execution finalization rejected: audit run '{run_id}' is in status "
                f"'{run_row['status'] if run_row else 'MISSING'}'."
            )
        live_head = git_output(repo_path, "rev-parse", "HEAD")
        expected_commit = str(session["base_commit"] or "")
        if expected_commit and live_head != expected_commit:
            stale_reason = f"Git HEAD changed from {expected_commit} to {live_head}."
            if str(run_row["status"]) != "VERIFICATION_STALE":
                transition_audit_run_status(
                    conn,
                    run_id,
                    "VERIFICATION_STALE",
                    reason=f"Execution finalization blocked due to stale repository snapshot: {stale_reason}",
                    actor="executor",
                    jsonl_path=jsonl_path,
                )
            conn.execute(
                """UPDATE audit_verification_runs
                   SET status='STALE', error_code='STALE_SNAPSHOT', error_message=?
                   WHERE audit_run_id=? AND status IN ('FINALIZED', 'COMPLETED', 'RUNNING', 'PENDING', 'DISPATCHING')""",
                (stale_reason, run_id),
            )
            conn.commit()
            raise RuntimeError(f"Execution finalization blocked due to stale repository snapshot: {stale_reason}")

        if not skipped_reconciliation_ids:
            consistency = verify_snapshot_consistency(conn, repo_path=repo_path, run_id=run_id)
            if not consistency["consistent"]:
                stale_reason = str(consistency.get("reason") or "Snapshot consistency check failed.")
                if str(run_row["status"]) != "VERIFICATION_STALE":
                    transition_audit_run_status(
                        conn,
                        run_id,
                        "VERIFICATION_STALE",
                        reason=f"Execution finalization blocked due to stale repository snapshot: {stale_reason}",
                        actor="executor",
                        jsonl_path=jsonl_path,
                    )
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='STALE', error_code='STALE_SNAPSHOT', error_message=?
                       WHERE audit_run_id=? AND status IN ('FINALIZED', 'COMPLETED', 'RUNNING', 'PENDING', 'DISPATCHING')""",
                    (stale_reason, run_id),
                )
                conn.commit()
                raise RuntimeError(f"Execution finalization blocked due to stale repository snapshot: {stale_reason}")

        for fid in verified_finding_ids:
            f_validated = _validate_finding_lineage_and_eligibility(
                conn,
                project_key=project_key,
                run_id=run_id,
                finding_id=fid,
                require_open=True,
            )
            reval = revalidate_finding_against_repo(
                repo_path,
                f_validated,
                expected_base_commit=session["base_commit"],
            )
            if not reval["valid"]:
                raise RuntimeError(
                    f"Execution finalization blocked: verified finding '{fid}' failed repository revalidation ({reval['reason']})."
                )
            f_curr = conn.execute("SELECT lifecycle, evidence_hash, file_blob_hash FROM findings WHERE finding_id=?", (fid,)).fetchone()
            prev_lc = f_curr["lifecycle"] if f_curr else "OPEN"
            conn.execute(
                "UPDATE findings SET lifecycle='RESOLVED', updated_at=CURRENT_TIMESTAMP WHERE finding_id=?",
                (fid,),
            )
            conn.execute(
                """INSERT INTO finding_history(
                    finding_id, project_key, run_id, from_lifecycle, to_lifecycle,
                    actor, reason, evidence_hash, file_blob_hash
                ) VALUES(?, ?, ?, ?, 'RESOLVED', 'executor', ?, ?, ?)""",
                (
                    fid,
                    project_key,
                    run_id,
                    prev_lc,
                    f"VERIFIED_IN_ISOLATED_WORKTREE ({exec_id})",
                    f_curr["evidence_hash"] if f_curr else None,
                    f_curr["file_blob_hash"] if f_curr else None,
                ),
            )
        conn.execute(
            """UPDATE execution_runs
               SET status=?, integration_test_passed=?, finished_at=CURRENT_TIMESTAMP
               WHERE exec_id=?""",
            (final_status, 1 if integration_passed else 0, exec_id),
        )
        conn.execute(
            "UPDATE audit_runs SET status=? WHERE run_id=?",
            (audit_run_status, run_id),
        )
        record_event(
            conn,
            "EXECUTION_FINALIZED",
            project_key=project_key,
            run_id=run_id,
            details={
                "exec_id": exec_id,
                "status": final_status,
                "verified_finding_ids": verified_finding_ids,
                "rolled_back_finding_ids": rolled_back_ids,
                "skipped_reconciliation_ids": skipped_reconciliation_ids,
                "worktree_path": str(worktree_path),
            },
            jsonl_path=jsonl_path,
        )
        conn.commit()

    return {
        "exec_id": exec_id,
        "project_key": project_key,
        "run_id": run_id,
        "status": final_status,
        "worktree_path": str(worktree_path),
        "verified_finding_ids": verified_finding_ids,
        "rolled_back_finding_ids": rolled_back_ids,
        "skipped_reconciliation_ids": skipped_reconciliation_ids,
        "findings": per_finding_results,
    }


def update_finding_execution_step(
    db_path: Path | None = None,
    *,
    project_key: str,
    exec_id: str,
    finding_id: str,
    action: str,
    happy_test_passed: bool | None = None,
    adversarial_test_passed: bool | None = None,
    red_team_passed: bool | None = None,
    notes: str | None = None,
    checkpoints_root: Path | None = None,
    jsonl_path: Path | None = None,
    broker_client: BrokerClient | None = None,
) -> dict[str, Any]:
    """Step-level controller for MCP-driven per-finding execution, checkpointing, and rollback."""
    if broker_client is not None:
        state = broker_client.get_execution_state(exec_id)
        if not state:
            raise RuntimeError(f"Execution run '{exec_id}' not found via broker.")
        exec_run = state.get("execution_run", {})
        exec_status = str(exec_run.get("status", ""))
        if exec_status not in ("RUNNING", "VERIFYING"):
            raise RuntimeError(f"Execution run '{exec_id}' is not active (status={exec_status}).")

        f_rows = state.get("findings", [])
        f_exec = next((r for r in f_rows if r.get("finding_id") == finding_id), None)
        if not f_exec:
            raise RuntimeError(f"Finding '{finding_id}' is not part of approved execution '{exec_id}'.")

        worktree_path = Path(exec_run.get("worktree_path", ""))
        repo_path = Path(exec_run.get("repo_path") or worktree_path)
        base_commit = str(exec_run.get("base_commit", ""))

        chk_root = checkpoints_root or (worktree_path.parent / "checkpoints")

        if action == "begin":
            chk = create_finding_checkpoint(worktree_path, chk_root, exec_id, finding_id)
            broker_client.register_checkpoint(
                checkpoint_id=chk["checkpoint_id"],
                exec_id=exec_id,
                finding_id=finding_id,
                base_commit=base_commit,
                checkpoint_path=chk["checkpoint_path"],
            )
            return {
                "exec_id": exec_id,
                "finding_id": finding_id,
                "status": "IN_PROGRESS",
                "checkpoint_id": chk["checkpoint_id"],
                "checkpoint_path": chk["checkpoint_path"],
            }

        elif action == "verify":
            chk_path = f_exec.get("checkpoint_path")
            if not chk_path:
                chk_rows = state.get("checkpoints", [])
                matching_chk = next((c for c in chk_rows if c.get("finding_id") == finding_id), None)
                if matching_chk:
                    chk_path = matching_chk.get("checkpoint_path") or matching_chk.get("manifest_path")
            if not chk_path:
                raise RuntimeError(f"Finding '{finding_id}' must call 'begin' to create a checkpoint before 'verify'.")

            chk_manifest = Path(chk_path)
            files_dir = chk_manifest.parent / "files"
            manifest_data = json.loads(chk_manifest.read_text(encoding="utf-8")) if chk_manifest.exists() else {}
            before_snapshot = {
                rel: (files_dir / rel).read_bytes()
                for rel in manifest_data.get("files", {})
                if (files_dir / rel).is_file()
            }
            sanitize_and_verify_worktree_isolation(worktree_path)
            after_snapshot = _list_worktree_files(worktree_path)
            rt_check = verify_red_team_diff(
                worktree_path,
                before_snapshot=before_snapshot,
                after_snapshot=after_snapshot,
                finding=f_exec,
            )
            effective_rt = bool(rt_check["passed"]) and (True if red_team_passed is None else bool(red_team_passed))
            effective_happy = bool(happy_test_passed)
            effective_adv = bool(adversarial_test_passed)
            current_repairs = int(f_exec.get("repair_attempts") or 0)

            if effective_happy and effective_adv and effective_rt:
                broker_res = broker_client.record_repair_attempt(
                    exec_id=exec_id,
                    finding_id=finding_id,
                    repair_attempt=current_repairs + 1,
                    happy_test_passed=1,
                    adversarial_test_passed=1,
                    red_team_passed=1,
                    red_team_notes=notes or rt_check.get("notes"),
                    diff_summary=json.dumps({"changed_files": rt_check.get("changed_files", [])}),
                )
                return {
                    "exec_id": exec_id,
                    "finding_id": finding_id,
                    "status": "VERIFIED",
                    "repair_attempts": current_repairs + 1,
                    "changed_files": rt_check["changed_files"],
                    "broker_result": broker_res,
                }

            if current_repairs < 2:
                next_repairs = current_repairs + 1
                broker_res = broker_client.record_repair_attempt(
                    exec_id=exec_id,
                    finding_id=finding_id,
                    repair_attempt=next_repairs,
                    happy_test_passed=1 if effective_happy else 0,
                    adversarial_test_passed=1 if effective_adv else 0,
                    red_team_passed=1 if effective_rt else 0,
                    red_team_notes=rt_check.get("notes"),
                    error=notes or rt_check.get("notes"),
                )
                return {
                    "exec_id": exec_id,
                    "finding_id": finding_id,
                    "status": "IN_PROGRESS",
                    "repair_attempts": next_repairs,
                    "remaining_repairs": 2 - next_repairs,
                    "error": notes or rt_check["notes"],
                    "broker_result": broker_res,
                }

            # Max 2 repair attempts exhausted -> restore checkpoint via broker
            broker_client.restore_checkpoint(
                checkpoint_id=_broker_checkpoint_id(state, f_exec, finding_id),
                exec_id=exec_id,
                worktree_path=str(worktree_path),
            )
            return {
                "exec_id": exec_id,
                "finding_id": finding_id,
                "status": "ROLLED_BACK",
                "repair_attempts": current_repairs,
                "error": f"Max 2 repair attempts exhausted: {notes or rt_check['notes']}",
            }

        elif action == "rollback":
            chk_path = f_exec.get("checkpoint_path")
            if not chk_path:
                chk_rows = state.get("checkpoints", [])
                matching_chk = next((c for c in chk_rows if c.get("finding_id") == finding_id), None)
                if matching_chk:
                    chk_path = matching_chk.get("checkpoint_path") or matching_chk.get("manifest_path")
            if chk_path:
                broker_client.restore_checkpoint(
                    checkpoint_id=_broker_checkpoint_id(state, f_exec, finding_id),
                    exec_id=exec_id,
                    worktree_path=str(worktree_path),
                )
            return {
                "exec_id": exec_id,
                "finding_id": finding_id,
                "status": "ROLLED_BACK",
            }
        else:
            raise RuntimeError(f"Unsupported finding execution action: {action}")

    chk_root = checkpoints_root or (db_path.parent.parent / "checkpoints")
    with connect(db_path) as conn:
        exec_row = conn.execute(
            "SELECT * FROM execution_runs WHERE exec_id=? AND project_key=?",
            (exec_id, project_key),
        ).fetchone()
        if not exec_row:
            raise RuntimeError(f"Execution run '{exec_id}' not found for project '{project_key}'.")
        if exec_row["status"] not in ("RUNNING", "VERIFYING"):
            raise RuntimeError(f"Execution run '{exec_id}' is not active (status={exec_row['status']}).")
        f_exec = conn.execute(
            "SELECT * FROM finding_executions WHERE exec_id=? AND finding_id=?",
            (exec_id, finding_id),
        ).fetchone()
        if not f_exec:
            raise RuntimeError(f"Finding '{finding_id}' is not part of approved execution '{exec_id}'.")
        finding_row = conn.execute(
            "SELECT * FROM findings WHERE finding_id=? AND project_key=?",
            (finding_id, project_key),
        ).fetchone()
        if not finding_row:
            raise RuntimeError(f"Approved finding '{finding_id}' not found for project '{project_key}'.")
        project_row = conn.execute(
            "SELECT * FROM projects WHERE project_key=?",
            (project_key,),
        ).fetchone()

    worktree_path = Path(exec_row["worktree_path"])
    repo_path = Path(project_row["repo_path"])
    finding = dict(finding_row)
    run_id = str(exec_row["run_id"])
    if action in ("begin", "verify") and "commit_sha" in f_exec.keys() and f_exec["commit_sha"]:
        raise RuntimeError(
            f"Finding '{finding_id}' is already verified and committed ({str(f_exec['commit_sha'])[:12]}); "
            "continue with the next finding or finalize."
        )

    if action in ("begin", "verify"):
        with connect(db_path) as conn:
            run_row = conn.execute(
                "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
                (run_id, project_key),
            ).fetchone()
            if not run_row or str(run_row["status"]) not in ("READY_FOR_REVIEW", "PARTIAL"):
                raise RuntimeError(
                    f"Execution step rejected: audit run '{run_id}' is in status "
                    f"'{run_row['status'] if run_row else 'MISSING'}'."
                )
            finding = _validate_finding_lineage_and_eligibility(
                conn,
                project_key=project_key,
                run_id=run_id,
                finding_id=finding_id,
                require_open=True,
            )
            consistency = verify_snapshot_consistency(conn, repo_path=repo_path, run_id=run_id)
            live_head = git_output(repo_path, "rev-parse", "HEAD")
            expected_commit = str(exec_row["base_commit"] or "")
            head_mismatch = bool(expected_commit and live_head != expected_commit)
            if not consistency["consistent"] or head_mismatch:
                stale_reason = str(
                    consistency.get("reason")
                    if not consistency["consistent"]
                    else f"Git HEAD changed from {expected_commit} to {live_head}."
                )
                if str(run_row["status"]) != "VERIFICATION_STALE":
                    transition_audit_run_status(
                        conn,
                        run_id,
                        "VERIFICATION_STALE",
                        reason=f"Execution step blocked due to stale repository snapshot: {stale_reason}",
                        actor="executor",
                        jsonl_path=jsonl_path,
                    )
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='STALE', error_code='STALE_SNAPSHOT', error_message=?
                       WHERE audit_run_id=? AND status IN ('FINALIZED', 'COMPLETED', 'RUNNING', 'PENDING', 'DISPATCHING')""",
                    (stale_reason, run_id),
                )
                conn.commit()
                raise RuntimeError(f"Execution step blocked due to stale repository snapshot: {stale_reason}")

    if action == "begin":
        reval = revalidate_finding_against_repo(
            repo_path,
            finding,
            expected_base_commit=str(exec_row["base_commit"]),
        )
        if not reval["valid"]:
            with connect(db_path) as conn:
                conn.execute(
                    """UPDATE finding_executions
                       SET status='SKIPPED_RECONCILIATION', finished_at=CURRENT_TIMESTAMP, error=?
                       WHERE exec_id=? AND finding_id=?""",
                    (reval["reason"], exec_id, finding_id),
                )
                conn.commit()
            return {"exec_id": exec_id, "finding_id": finding_id, "status": "SKIPPED_RECONCILIATION", "reason": reval["reason"]}

        chk = create_finding_checkpoint(worktree_path, chk_root, exec_id, finding_id)
        with connect(db_path) as conn:
            conn.execute(
                """UPDATE finding_executions
                   SET status='IN_PROGRESS', checkpoint_id=?, checkpoint_path=?
                   WHERE exec_id=? AND finding_id=?""",
                (chk["checkpoint_id"], chk["checkpoint_path"], exec_id, finding_id),
            )
            conn.commit()
        return {
            "exec_id": exec_id,
            "finding_id": finding_id,
            "status": "IN_PROGRESS",
            "checkpoint_id": chk["checkpoint_id"],
            "checkpoint_path": chk["checkpoint_path"],
        }

    if action == "verify":
        if not f_exec["checkpoint_path"]:
            raise RuntimeError(f"Finding '{finding_id}' must call 'begin' to create a checkpoint before 'verify'.")
        chk_manifest = Path(f_exec["checkpoint_path"])
        files_dir = chk_manifest.parent / "files"
        manifest_data = json.loads(chk_manifest.read_text(encoding="utf-8"))
        before_snapshot = {
            rel: (files_dir / rel).read_bytes()
            for rel in manifest_data.get("files", {})
            if (files_dir / rel).is_file()
        }
        sanitize_and_verify_worktree_isolation(worktree_path)
        after_snapshot = _list_worktree_files(worktree_path)
        rt_check = verify_red_team_diff(
            worktree_path,
            before_snapshot=before_snapshot,
            after_snapshot=after_snapshot,
            finding=finding,
        )
        effective_rt = bool(rt_check["passed"]) and (True if red_team_passed is None else bool(red_team_passed))
        effective_happy = bool(happy_test_passed)
        effective_adv = bool(adversarial_test_passed)
        current_repairs = int(f_exec["repair_attempts"] or 0)

        if effective_happy and effective_adv and effective_rt:
            # One commit per verified finding, so the review branch can be read and reverted finding by finding.
            commit_sha = _commit_finding(worktree_path, repo_path, finding)
            with connect(db_path) as conn:
                conn.execute(
                    """UPDATE finding_executions
                       SET status='VERIFIED', happy_test_passed=1, adversarial_test_passed=1,
                           red_team_passed=1, red_team_notes=?, diff_summary=?, finished_at=CURRENT_TIMESTAMP, error=NULL,
                           commit_sha=?
                       WHERE exec_id=? AND finding_id=?""",
                    (
                        notes or rt_check["notes"],
                        json.dumps({"changed_files": rt_check["changed_files"]}),
                        commit_sha,
                        exec_id,
                        finding_id,
                    ),
                )
                conn.commit()
            return {
                "exec_id": exec_id,
                "finding_id": finding_id,
                "status": "VERIFIED",
                "repair_attempts": current_repairs,
                "changed_files": rt_check["changed_files"],
                "commit": commit_sha,
            }

        # Verification failed: check bounded repair limit (max 2 repair attempts)
        if current_repairs < 2:
            next_repairs = current_repairs + 1
            with connect(db_path) as conn:
                conn.execute(
                    """UPDATE finding_executions
                       SET repair_attempts=?, happy_test_passed=?, adversarial_test_passed=?,
                           red_team_passed=?, red_team_notes=?, error=?
                       WHERE exec_id=? AND finding_id=?""",
                    (
                        next_repairs,
                        1 if effective_happy else 0,
                        1 if effective_adv else 0,
                        1 if effective_rt else 0,
                        rt_check["notes"],
                        notes or rt_check["notes"],
                        exec_id,
                        finding_id,
                    ),
                )
                conn.commit()
            return {
                "exec_id": exec_id,
                "finding_id": finding_id,
                "status": "IN_PROGRESS",
                "repair_attempts": next_repairs,
                "remaining_repairs": 2 - next_repairs,
                "error": notes or rt_check["notes"],
            }

        # Max 2 repair attempts exhausted -> automatic rollback to checkpoint
        rollback_finding_checkpoint(worktree_path, chk_manifest)
        with connect(db_path) as conn:
            conn.execute(
                """UPDATE finding_executions
                   SET status='ROLLED_BACK', happy_test_passed=?, adversarial_test_passed=?,
                       red_team_passed=?, red_team_notes=?, finished_at=CURRENT_TIMESTAMP, error=?
                   WHERE exec_id=? AND finding_id=?""",
                (
                    1 if effective_happy else 0,
                    1 if effective_adv else 0,
                    1 if effective_rt else 0,
                    rt_check["notes"],
                    f"Max 2 repair attempts exhausted: {notes or rt_check['notes']}",
                    exec_id,
                    finding_id,
                ),
            )
            conn.commit()
        return {
            "exec_id": exec_id,
            "finding_id": finding_id,
            "status": "ROLLED_BACK",
            "repair_attempts": current_repairs,
            "error": f"Max 2 repair attempts exhausted: {notes or rt_check['notes']}",
        }

    if action == "rollback":
        if "commit_sha" in f_exec.keys() and f_exec["commit_sha"]:
            raise RuntimeError(
                f"Finding '{finding_id}' is already verified and committed ({str(f_exec['commit_sha'])[:12]}) in the "
                "worktree; it cannot be rolled back any more. Finalize and drop it from the review branch "
                "(git revert) if it should not be merged."
            )
        if f_exec["checkpoint_path"]:
            rollback_finding_checkpoint(worktree_path, Path(f_exec["checkpoint_path"]))
        with connect(db_path) as conn:
            conn.execute(
                """UPDATE finding_executions
                   SET status='ROLLED_BACK', finished_at=CURRENT_TIMESTAMP, error=?
                   WHERE exec_id=? AND finding_id=?""",
                (notes or "Explicitly rolled back to checkpoint", exec_id, finding_id),
            )
            conn.commit()
        return {
            "exec_id": exec_id,
            "finding_id": finding_id,
            "status": "ROLLED_BACK",
        }

    raise RuntimeError(f"Unsupported finding execution action: {action}")


def finalize_isolated_execution(
    db_path: Path | None = None,
    *,
    project_key: str,
    exec_id: str,
    integration_test_passed: bool,
    notes: str | None = None,
    quarantine_root: Path | None = None,
    jsonl_path: Path | None = None,
    broker_client: BrokerClient | None = None,
    reports_root: Path | None = None,
) -> dict[str, Any]:
    """Finalize an MCP-driven isolated worktree execution after integration verification.

    Verified fixes are delivered as a commit on a new LOCAL review branch plus a patch file; the user's working
    tree and current branch are never touched, nothing is merged or pushed."""
    if broker_client is not None:
        state = broker_client.get_execution_state(exec_id)
        if not state:
            raise RuntimeError(f"Execution run '{exec_id}' not found via broker.")
        exec_run = state.get("execution_run", {})
        exec_status = str(exec_run.get("status", ""))
        if exec_status not in ("RUNNING", "VERIFYING"):
            raise RuntimeError(
                f"Cannot finalize execution '{exec_id}': execution run is not active (status={exec_status})."
            )

        worktree_path = Path(exec_run.get("worktree_path", ""))
        run_id = str(exec_run.get("run_id", ""))
        f_rows = state.get("findings", [])
        verified_ids = [str(r["finding_id"]) for r in f_rows if r.get("status") == "VERIFIED"]
        rolled_back_ids = [str(r["finding_id"]) for r in f_rows if r.get("status") in ("ROLLED_BACK", "FAILED")]
        skipped_ids = [str(r["finding_id"]) for r in f_rows if r.get("status") == "SKIPPED_RECONCILIATION"]
        pending_ids = [str(r["finding_id"]) for r in f_rows if r.get("status") in ("PENDING", "IN_PROGRESS", "REVALIDATED")]

        if pending_ids:
            raise RuntimeError(f"Cannot finalize execution '{exec_id}': findings still pending/in-progress: {pending_ids}")

        leases = state.get("leases", [])
        lease_id = leases[0]["lease_id"] if leases else "LEASE-DEFAULT"
        fencing_token = int(leases[0]["fencing_token"]) if leases else 1

        if not integration_test_passed:
            q_res = broker_client.quarantine_checkpoint(
                quarantine_id=f"QUAR-{exec_id}",
                project_key=project_key,
                exec_id=exec_id,
                worktree_path=str(worktree_path),
                reason=notes or "Integration test failed during step finalization",
            )
            return {
                "exec_id": exec_id,
                "project_key": project_key,
                "run_id": run_id,
                "status": "QUARANTINED",
                "worktree_path": str(worktree_path),
                "quarantined_finding_ids": verified_ids + rolled_back_ids + skipped_ids,
                "quarantine": q_res,
            }

        target_status = "COMPLETED" if (len(verified_ids) > 0 and len(rolled_back_ids) == 0 and len(skipped_ids) == 0) else ("PARTIAL" if len(verified_ids) > 0 else "FAILED")

        broker_res = broker_client.finalize_execution(
            exec_id=exec_id,
            status=target_status,
            integration_test_passed=1 if integration_test_passed else 0,
            lease_id=lease_id,
            fencing_token=fencing_token,
        )
        return {
            "exec_id": exec_id,
            "project_key": project_key,
            "run_id": run_id,
            "status": target_status,
            "worktree_path": str(worktree_path),
            "verified_finding_ids": verified_ids,
            "rolled_back_finding_ids": rolled_back_ids,
            "skipped_reconciliation_ids": skipped_ids,
            "broker_result": broker_res,
        }

    with connect(db_path) as conn:
        exec_row = conn.execute(
            "SELECT * FROM execution_runs WHERE exec_id=? AND project_key=?",
            (exec_id, project_key),
        ).fetchone()
        if not exec_row:
            raise RuntimeError(f"Execution run '{exec_id}' not found for project '{project_key}'.")
        if str(exec_row["status"]) not in ("RUNNING", "VERIFYING"):
            raise RuntimeError(
                f"Cannot finalize execution '{exec_id}': execution run is not active (status={exec_row['status']})."
            )
        project_row = conn.execute(
            "SELECT * FROM projects WHERE project_key=?",
            (project_key,),
        ).fetchone()
        f_rows = conn.execute(
            "SELECT * FROM finding_executions WHERE exec_id=?",
            (exec_id,),
        ).fetchall()

    worktree_path = Path(exec_row["worktree_path"])
    repo_path = Path(project_row["repo_path"])
    run_id = str(exec_row["run_id"])
    verified_ids = [str(r["finding_id"]) for r in f_rows if r["status"] == "VERIFIED"]
    rolled_back_ids = [str(r["finding_id"]) for r in f_rows if r["status"] == "ROLLED_BACK"]
    skipped_ids = [str(r["finding_id"]) for r in f_rows if r["status"] == "SKIPPED_RECONCILIATION"]
    pending_ids = [str(r["finding_id"]) for r in f_rows if r["status"] in ("PENDING", "IN_PROGRESS", "REVALIDATED")]

    if pending_ids:
        raise RuntimeError(f"Cannot finalize execution '{exec_id}': findings still pending/in-progress: {pending_ids}")

    if not integration_test_passed:
        q_info = quarantine_worktree(
            db_path,
            project_key=project_key,
            exec_id=exec_id,
            worktree_path=worktree_path,
            reason=notes or "Integration verification failed.",
            quarantine_root=quarantine_root,
            jsonl_path=jsonl_path,
        )
        return {
            "exec_id": exec_id,
            "project_key": project_key,
            "run_id": run_id,
            "status": "QUARANTINED",
            "quarantine": q_info,
        }

    final_status = "COMPLETED" if (verified_ids and not rolled_back_ids and not skipped_ids) else ("PARTIAL" if verified_ids else "ROLLED_BACK")
    audit_status = "COMPLETED" if final_status == "COMPLETED" else ("PARTIAL" if final_status == "PARTIAL" else "READY_FOR_REVIEW")

    with connect(db_path) as conn:
        run_row = conn.execute(
            "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
            (run_id, project_key),
        ).fetchone()
        if not run_row or str(run_row["status"]) not in ("READY_FOR_REVIEW", "PARTIAL"):
            raise RuntimeError(
                f"Execution finalization rejected: audit run '{run_id}' is in status "
                f"'{run_row['status'] if run_row else 'MISSING'}'."
            )
        consistency = verify_snapshot_consistency(conn, repo_path=repo_path, run_id=run_id)
        live_head = git_output(repo_path, "rev-parse", "HEAD")
        expected_commit = str(exec_row["base_commit"] or "")
        head_mismatch = bool(expected_commit and live_head != expected_commit)
        if (not skipped_ids and not consistency["consistent"]) or head_mismatch:
            stale_reason = str(
                consistency.get("reason")
                if not consistency["consistent"]
                else f"Git HEAD changed from {expected_commit} to {live_head}."
            )
            if str(run_row["status"]) != "VERIFICATION_STALE":
                transition_audit_run_status(
                    conn,
                    run_id,
                    "VERIFICATION_STALE",
                    reason=f"Execution finalization blocked due to stale repository snapshot: {stale_reason}",
                    actor="executor",
                    jsonl_path=jsonl_path,
                )
            conn.execute(
                """UPDATE audit_verification_runs
                   SET status='STALE', error_code='STALE_SNAPSHOT', error_message=?
                   WHERE audit_run_id=? AND status IN ('FINALIZED', 'COMPLETED', 'RUNNING', 'PENDING', 'DISPATCHING')""",
                (stale_reason, run_id),
            )
            conn.commit()
            raise RuntimeError(f"Execution finalization blocked due to stale repository snapshot: {stale_reason}")

        for fid in verified_ids:
            f_validated = _validate_finding_lineage_and_eligibility(
                conn,
                project_key=project_key,
                run_id=run_id,
                finding_id=fid,
                require_open=True,
            )
            reval = revalidate_finding_against_repo(
                repo_path,
                f_validated,
                expected_base_commit=str(exec_row["base_commit"]),
            )
            if not reval["valid"]:
                raise RuntimeError(
                    f"Execution finalization blocked: verified finding '{fid}' failed repository revalidation ({reval['reason']})."
                )
            f_curr = conn.execute("SELECT lifecycle, evidence_hash, file_blob_hash FROM findings WHERE finding_id=?", (fid,)).fetchone()
            prev_lc = f_curr["lifecycle"] if f_curr else "OPEN"
            conn.execute(
                "UPDATE findings SET lifecycle='RESOLVED', updated_at=CURRENT_TIMESTAMP WHERE finding_id=?",
                (fid,),
            )
            conn.execute(
                """INSERT INTO finding_history(
                    finding_id, project_key, run_id, from_lifecycle, to_lifecycle,
                    actor, reason, evidence_hash, file_blob_hash
                ) VALUES(?, ?, ?, ?, 'RESOLVED', 'executor', ?, ?, ?)""",
                (
                    fid,
                    project_key,
                    run_id,
                    prev_lc,
                    f"VERIFIED_IN_ISOLATED_WORKTREE ({exec_id})",
                    f_curr["evidence_hash"] if f_curr else None,
                    f_curr["file_blob_hash"] if f_curr else None,
                ),
            )
        review: dict[str, Any] | None = None
        conn.execute(
            "UPDATE execution_runs SET status=?, integration_test_passed=1, finished_at=CURRENT_TIMESTAMP WHERE exec_id=?",
            (final_status, exec_id),
        )
        if audit_status == "COMPLETED":
            # Findings of this report that nobody decided yet must stay decidable: keep the run reviewable.
            undecided = conn.execute(
                """SELECT COUNT(*) FROM findings
                   WHERE project_key=? AND (run_id=? OR last_seen_run_id=?) AND lifecycle='OPEN'""",
                (project_key, run_id, run_id),
            ).fetchone()[0]
            if undecided:
                audit_status = "PARTIAL"
        conn.execute(
            "UPDATE audit_runs SET status=? WHERE run_id=?",
            (audit_status, run_id),
        )
        record_event(
            conn,
            "EXECUTION_FINALIZED",
            project_key=project_key,
            run_id=run_id,
            details={
                "exec_id": exec_id,
                "status": final_status,
                "verified_finding_ids": verified_ids,
                "rolled_back_finding_ids": rolled_back_ids,
                "skipped_reconciliation_ids": skipped_ids,
            },
            jsonl_path=jsonl_path,
        )
        # Git delivery is the last step before the DB commit; if anything after the branch was created fails,
        # the branch is undone so a retry starts from the same state.
        try:
            if verified_ids:
                review = deliver_review_branch(
                    repo_path=repo_path,
                    worktree_path=worktree_path,
                    run_id=run_id,
                    exec_id=exec_id,
                    base_commit=str(exec_row["base_commit"] or ""),
                    finding_ids=verified_ids,
                    reports_root=reports_root or (Path(db_path).parent.parent / "reports"),
                )
                conn.execute(
                    "UPDATE execution_runs SET review_branch=?, review_commit=? WHERE exec_id=?",
                    (review["branch"], review.get("commit"), exec_id),
                )
                _check_auto_approval_limits(conn, exec_row, review, project_key, run_id, exec_id, jsonl_path)
                conn.execute(
                    """UPDATE finding_history SET reason=?
                       WHERE finding_id IN ({}) AND run_id=? AND to_lifecycle='RESOLVED'
                         AND reason=?""".format(",".join("?" for _ in verified_ids)),
                    (
                        f"FIX_ON_REVIEW_BRANCH {review['branch']} ({exec_id})",
                        *verified_ids,
                        run_id,
                        f"VERIFIED_IN_ISOLATED_WORKTREE ({exec_id})",
                    ),
                )
            conn.commit()
        except BaseException:
            if review and review.get("branch"):
                _undo_review_branch(repo_path, worktree_path, review["branch"])
            raise

    if review and review.get("branch"):
        # The control plane runs the project's tests itself on the committed result (not inside the DB
        # transaction: a test suite can take minutes). The branch is delivered either way; a failure is flagged.
        review["tests"] = _run_control_plane_tests(
            db_path, project_row, repo_path, worktree_path, project_key=project_key, run_id=run_id,
            exec_id=exec_id, jsonl_path=jsonl_path,
        )
        if review["tests"]["status"] in ("FAILED", "TIMEOUT", "ERROR"):
            note = (
                f"The project's tests did not pass on the review branch ({review['tests']['status']}); "
                "check tests.output_tail before merging."
            )
            review["warning"] = f"{review['warning']} {note}" if review.get("warning") else note
        # Only now that the DB records the branch: the isolated worktree is no longer needed.
        from recovery import _remove_git_worktree

        _remove_git_worktree(worktree_path)
        keys = project_row.keys()
        delivery_mode = str(project_row["delivery_mode"] or "local") if "delivery_mode" in keys else "local"
        if delivery_mode in ("pull_request", "auto_merge"):
            # Opt-in: the control plane (never the agent) pushes and opens a PR; auto_merge also merges when every
            # gate passes. The agent must not push or merge, so the manual push/merge commands are withdrawn.
            from auto_delivery import queue_delivery

            review["delivery"] = queue_delivery(
                Path(db_path), Path(db_path).resolve().parent.parent, project_key=project_key, run_id=run_id,
                exec_id=exec_id, review=review, final_status=final_status, jsonl_path=jsonl_path,
                mode=delivery_mode,
            )
            review["review_commands"] = [cmd for cmd in review.get("review_commands") or []
                                         if not cmd.startswith(("git push", "git merge", "git branch -D"))]

    return {
        "exec_id": exec_id,
        "project_key": project_key,
        "run_id": run_id,
        "status": final_status,
        "verified_finding_ids": verified_ids,
        "rolled_back_finding_ids": rolled_back_ids,
        "skipped_reconciliation_ids": skipped_ids,
        "review": review,
    }


def _git(cwd: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, timeout=timeout)


def _run_control_plane_tests(
    db_path: Path,
    project_row: Any,
    repo_path: Path,
    worktree_path: Path,
    *,
    project_key: str,
    run_id: str,
    exec_id: str,
    jsonl_path: Path | None,
) -> dict[str, Any]:
    from ci_check import detect_test_command, run_project_tests

    keys = project_row.keys()
    configured = project_row["test_command"] if "test_command" in keys else None
    timeout = project_row["test_timeout_seconds"] if "test_timeout_seconds" in keys else None
    # Detect from the worktree (the fix may have added the first tests); the venv is looked up in repo_path.
    command, source = detect_test_command(worktree_path, configured, venv_root=repo_path)
    result = run_project_tests(worktree_path, command, source=source, timeout_seconds=timeout)
    try:
        with connect(db_path) as conn:
            conn.execute("UPDATE execution_runs SET tests_json=? WHERE exec_id=?",
                         (json.dumps(result, ensure_ascii=False), exec_id))
            record_event(
                conn,
                "EXECUTION_TESTS_" + str(result["status"]),
                project_key=project_key,
                run_id=run_id,
                level="INFO" if result["status"] in ("PASSED", "NOT_CONFIGURED") else "WARNING",
                details={"exec_id": exec_id, **{k: v for k, v in result.items() if k != "output_tail"}},
                jsonl_path=jsonl_path,
            )
            conn.commit()
    except sqlite3.Error:
        pass  # the result is still returned to the caller
    return result


def _commit_identity(repo_path: Path) -> list[str]:
    """Fallback identity only for whatever the repository does not configure; never sign (a headless signing
    prompt would hang). Review commits are local artefacts, not releases."""
    identity: list[str] = ["-c", "commit.gpgsign=false"]
    if not _git(repo_path, "config", "user.name").stdout.strip():
        identity += ["-c", "user.name=Antigravity Auditor"]
    if not _git(repo_path, "config", "user.email").stdout.strip():
        identity += ["-c", "user.email=auditor@localhost"]
    return identity


def _commit_finding(worktree_path: Path, repo_path: Path, finding: dict[str, Any]) -> str:
    """Commit the current worktree changes as the verified fix of one finding (detached HEAD in the worktree).

    Commit hooks are skipped for these intermediate commits; the review branch is checked by the control plane's
    own test run (and the repository's CI on a pull request)."""
    add = _git(worktree_path, "add", "-A", "--", ".", *_CACHE_EXCLUDES)
    if add.returncode != 0:
        raise RuntimeError(f"git add failed in the worktree: {(add.stderr or add.stdout).strip()[:300]}")
    if not _git(worktree_path, "status", "--porcelain").stdout.strip():
        raise RuntimeError(f"Finding '{finding['finding_id']}' left no change to commit in the worktree.")
    title = re.sub(r"\s+", " ", str(finding.get("title") or "")).strip()[:72]
    message = (
        f"audit({finding['finding_id']}): {title}\n\n"
        f"Severity: {finding.get('severity')} | Category: {finding.get('category')} | File: {finding.get('file_path')}\n"
        "Verified in the auditor's isolated worktree; not merged or pushed by the auditor."
    )
    res = subprocess.run(
        ["git", "-C", str(worktree_path), *_commit_identity(repo_path), "commit", "-q", "--no-verify", "-m", message],
        capture_output=True, text=True, timeout=120,
    )
    if res.returncode != 0:
        raise RuntimeError(f"Committing finding '{finding['finding_id']}' failed: {(res.stderr or res.stdout).strip()[:300]}")
    return _git(worktree_path, "rev-parse", "HEAD").stdout.strip()


def _safe_slug(value: str) -> str:
    """Ref- and path-safe slug: [A-Za-z0-9._-], no '..', no leading/trailing '.' or '-'."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value)
    slug = re.sub(r"\.{2,}", "-", slug).strip("-.")
    return slug or "run"


def _review_branch_name(run_id: str, exec_id: str) -> str:
    return f"audit-fix/{_safe_slug(run_id).lower()}-{_safe_slug(exec_id.rsplit('-', 1)[-1]).lower()}"


def _check_auto_approval_limits(
    conn: Any,
    exec_row: Any,
    review: dict[str, Any],
    project_key: str,
    run_id: str,
    exec_id: str,
    jsonl_path: Path | None,
) -> None:
    """For a policy auto-approved execution, compare what the fix actually changed with the policy limits.
    The branch is still delivered (nothing is merged), but a violation is flagged prominently for review."""
    from apply_policy import approval_policy_snapshot, changed_files_violations

    snap = approval_policy_snapshot(conn, str(exec_row["approval_id"]))
    if snap is None:
        by = conn.execute("SELECT authorized_by FROM execution_approvals WHERE approval_id=?",
                          (str(exec_row["approval_id"]),)).fetchone()
        review["approval"] = "chat" if by and str(by[0] or "").startswith("chat") else "human_terminal"
        return
    violations = changed_files_violations(snap["policy"], list(review.get("files_changed") or []))
    review["approval"] = "auto_policy"
    review["policy_source"] = snap.get("source")
    review["policy_violations"] = violations
    if violations:
        review["warning"] = (
            "Auto-approved fix went beyond the auto-approval policy: " + "; ".join(violations)
            + ". Review the branch carefully before merging."
        )
        record_event(
            conn,
            "AUTO_APPLY_POLICY_EXCEEDED",
            project_key=project_key,
            run_id=run_id,
            level="WARNING",
            details={"exec_id": exec_id, "branch": review.get("branch"), "violations": violations},
            jsonl_path=jsonl_path,
        )


def _undo_review_branch(repo_path: Path, worktree_path: Path, branch: str) -> None:
    """Best-effort undo of a review branch created by deliver_review_branch: the worktree keeps the changes
    (uncommitted) and the branch ref is deleted, so finalization can simply be retried."""
    if _git(worktree_path, "symbolic-ref", "-q", "--short", "HEAD").stdout.strip() == branch:
        has_commit = _git(worktree_path, "rev-parse", "--verify", "-q", "HEAD").returncode == 0
        if has_commit and _git(worktree_path, "log", "-1", "--format=%s").stdout.startswith("Auditor fix for "):
            _git(worktree_path, "reset", "-q", "--mixed", "HEAD~1")
        _git(worktree_path, "switch", "-q", "--detach")
    _git(repo_path, "branch", "-D", branch)


def deliver_review_branch(
    *,
    repo_path: Path,
    worktree_path: Path,
    run_id: str,
    exec_id: str,
    base_commit: str,
    finding_ids: list[str],
    reports_root: Path,
) -> dict[str, Any]:
    """Commit the verified changes of an isolated worktree to a new local branch and write a patch file.

    The branch lives in the user's repository (linked worktrees share refs) but the user's working tree and
    checked-out branch are untouched. Nothing is merged or pushed: reviewing, merging or opening a PR is the
    user's decision. The isolated worktree is removed afterwards; the branch keeps the result."""
    status = _git(worktree_path, "status", "--porcelain")
    if status.returncode != 0:
        raise RuntimeError(f"Cannot read worktree status: {(status.stderr or status.stdout).strip()}")
    # Verified findings are committed one by one in the worktree; what is left uncommitted is delivered on top.
    committed = bool(base_commit) and _git(worktree_path, "rev-list", "--count", f"{base_commit}..HEAD").stdout.strip() not in ("", "0")
    if not status.stdout.strip() and not committed:
        raise RuntimeError(
            "Verified findings produced no changes in the isolated worktree; nothing to deliver. "
            "Roll the findings back or apply the fix before finalizing."
        )

    branch = _review_branch_name(run_id, exec_id)
    if _git(repo_path, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}").returncode == 0:
        raise RuntimeError(f"Review branch '{branch}' already exists; refusing to overwrite it.")
    sw = _git(worktree_path, "switch", "-c", branch)
    if sw.returncode != 0:
        raise RuntimeError(f"Cannot create review branch '{branch}': {(sw.stderr or sw.stdout).strip()}")
    try:
        return _commit_review_branch(
            repo_path=repo_path, worktree_path=worktree_path, branch=branch, run_id=run_id, exec_id=exec_id,
            base_commit=base_commit, finding_ids=finding_ids, reports_root=reports_root,
        )
    except BaseException:
        _undo_review_branch(repo_path, worktree_path, branch)
        raise


def _commit_review_branch(
    *,
    repo_path: Path,
    worktree_path: Path,
    branch: str,
    run_id: str,
    exec_id: str,
    base_commit: str,
    finding_ids: list[str],
    reports_root: Path,
) -> dict[str, Any]:
    add = _git(worktree_path, "add", "-A", "--", ".", *_CACHE_EXCLUDES)
    if add.returncode != 0:
        raise RuntimeError(f"git add failed: {(add.stderr or add.stdout).strip()}")
    per_finding = bool(base_commit) and _git(worktree_path, "rev-list", "--count", f"{base_commit}..HEAD").stdout.strip() not in ("", "0")
    if _git(worktree_path, "status", "--porcelain").stdout.strip():
        # Changes made after the last verified finding (integration fixes), or everything when the findings were
        # not committed one by one (executions started before per-finding commits existed).
        subject = (
            f"Auditor fix for {run_id}: remaining integration changes" if per_finding
            else f"Auditor fix for {run_id}: {', '.join(finding_ids)}"
        )
        message = (
            f"{subject}\n\n"
            f"Verified in isolated worktree {exec_id} (base {base_commit[:12]}).\n"
            "Review before merging; this commit was not merged or pushed by the auditor."
        )
        commit = subprocess.run(
            ["git", "-C", str(worktree_path), *_commit_identity(repo_path), "commit", "-q", "-m", message],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if commit.returncode != 0:
            raise RuntimeError(
                f"Committing the review branch failed (repository hooks or configuration?): "
                f"{(commit.stderr or commit.stdout).strip()[:500]}. The worktree is kept at {worktree_path}."
            )
    sha = _git(worktree_path, "rev-parse", "HEAD").stdout.strip()
    base_ref = base_commit or f"{sha}~1"
    files = [ln for ln in _git(worktree_path, "diff", "--name-only", base_ref, sha).stdout.splitlines() if ln]
    commits = [
        {"commit": ln.split(" ", 1)[0], "subject": ln.split(" ", 1)[1] if " " in ln else ""}
        for ln in _git(worktree_path, "log", "--reverse", "--format=%h %s", f"{base_ref}..{sha}").stdout.splitlines()
        if ln.strip()
    ]

    # The patch file is a convenience copy; the branch is the deliverable, so a patch write problem is reported
    # instead of failing the delivery.
    patch_path: Path | None = None
    patch_error: str | None = None
    fp = _git(worktree_path, "format-patch", "--stdout", f"{base_ref}..{sha}", timeout=120)
    if fp.returncode == 0:
        try:
            patch_dir = reports_root / _safe_slug(run_id)
            if not patch_dir.resolve().is_relative_to(reports_root.resolve()):
                raise OSError(f"patch directory escapes the reports folder: {patch_dir}")
            patch_dir.mkdir(parents=True, exist_ok=True)
            patch_path = patch_dir / f"{_safe_slug(exec_id)}.patch"
            patch_path.write_bytes(fp.stdout.encode("utf-8"))  # keep the patch's own line endings
        except OSError as exc:
            patch_path, patch_error = None, f"{type(exc).__name__}: {exc}"
    else:
        patch_error = (fp.stderr or fp.stdout).strip()[:300]

    base = base_ref
    return {
        "branch": branch,
        "commit": sha,
        "base_commit": base_commit,
        "files_changed": files,
        "commits": commits,
        "patch_path": str(patch_path) if patch_path is not None and patch_path.exists() else None,
        "patch_error": patch_error,
        "finding_ids": finding_ids,
        "merged": False,
        "pushed": False,
        "review_commands": [
            f"cd \"{repo_path}\"",
            f"git log --oneline {base[:12]}..{branch}",
            f"git diff {base[:12]}..{branch}",
            f"git push -u origin {branch}  # then open a PR: gh pr create --head {branch} --fill",
            f"git merge --no-ff --no-edit {branch}  # or merge locally instead of a PR",
            f"git branch -D {branch}  # discard",
        ],
    }


def start_isolated_execution_broker(
    broker_client: BrokerClient,
    *,
    project_key: str,
    approval_token: str,
    worktrees_root: Path | None = None,
    min_free_mb: int = 500,
    jsonl_path: Path | None = None,
    _post_worktree_fault_hook: Callable[[Path], None] | None = None,
) -> dict[str, Any]:
    """Start isolated execution exclusively via Broker IPC. Zero direct SQLite calls."""
    assert_not_markdown_checkbox(approval_token, "approval_token")
    ctx = broker_client.get_context(project_key=project_key)
    proj = ctx.get("project", {})
    repo_path = Path(proj.get("repo_path", ""))
    if not repo_path.is_dir() or not (repo_path / ".git").exists():
        raise RuntimeError(f"Cannot execute: repository path invalid ({repo_path}).")

    if approval_token.startswith("{"):
        try:
            token_data = json.loads(approval_token)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Cannot execute: approval_token is not valid JSON.") from exc
        payload = token_data.get("payload", {}) if isinstance(token_data, dict) else {}
        approval_id = str(payload.get("approval_id") or "")
        run_id = str(payload.get("run_id") or "")
        base_commit = str(payload.get("base_commit") or "")
        requested_ids = payload.get("approved_finding_ids", [])
        nonce = str(payload.get("single_use_nonce") or "")
        if not (approval_id and run_id and base_commit and nonce and isinstance(requested_ids, list)):
            raise RuntimeError("Cannot execute: approval_token payload is incomplete.")
        # The broker verifies the CBEAT signature and every binding (project, run, base commit, finding set,
        # nonce, expiry) against its authoritative record, then consumes the single-use approval -- all before
        # any worktree is created.
        verified = broker_client.verify_execution_approval(
            approval_id=approval_id,
            project_key=project_key,
            run_id=run_id,
            base_commit=base_commit,
            approved_finding_ids=[str(x) for x in requested_ids],
            cbeat_token=token_data,
        )
        if not verified or not verified.get("valid"):
            raise RuntimeError(f"Cannot execute: approval '{approval_id}' failed broker verification.")
        live_head = git_output(repo_path, "rev-parse", "HEAD")
        if live_head != base_commit:
            raise RuntimeError(
                f"Cannot execute: repository HEAD ({live_head or 'unknown'}) no longer matches the approved base "
                f"commit ({base_commit}); re-run the audit and approve again."
            )
        approved_finding_ids = list(verified.get("approved_finding_ids") or requested_ids)
    else:
        # Fail closed: only the structured approval token issued by authorize_execution is accepted. The former
        # fallback treated any other string as approval of every OPEN finding of the latest run.
        raise RuntimeError("Cannot execute: approval_token is not a structured approval token from authorize_execution.")

    # Same root as the direct path (<app home>/worktrees), not a fixed %LOCALAPPDATA% location.
    wt_base = worktrees_root or (
        Path(os.environ.get("ANTIGRAVITY_AUDITOR_HOME", str(Path(__file__).resolve().parents[1]))) / "worktrees")
    check_disk_space(wt_base, min_free_mb=min_free_mb)

    exec_id = "EXEC-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    worktree_path = (wt_base / project_key / exec_id).resolve()
    worktree_path.parent.mkdir(parents=True, exist_ok=True)
    branch_name = f"audit-isolated/{exec_id.lower()}"

    res = subprocess.run(
        ["git", "-C", str(repo_path), "worktree", "add", "--detach", str(worktree_path), base_commit],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if res.returncode != 0:
        raise RuntimeError(f"Failed to create isolated git worktree: {(res.stderr or res.stdout).strip()}")

    try:
        isolation_info = sanitize_and_verify_worktree_isolation(worktree_path)

        if _post_worktree_fault_hook is not None:
            _post_worktree_fault_hook(worktree_path)

        # The single-use approval is consumed only once the isolated worktree exists and is clean, so an
        # environment failure (disk space, git) does not burn it.
        broker_client.consume_execution_approval(approval_id, nonce)

        broker_client.register_execution_intent(
            exec_id=exec_id,
            project_key=project_key,
            run_id=run_id,
            approval_id=approval_id,
            base_commit=base_commit,
            working_tree_hash="tree-clean",
            worktree_path=str(worktree_path),
            branch_name=branch_name,
        )

        lease = broker_client.acquire_execution_lease(exec_id=exec_id, worker_id=f"worker-{os.getpid()}")
    except Exception:
        _compensate_created_worktree(repo_path, worktree_path, None)
        raise

    return {
        "exec_id": exec_id,
        "project_key": project_key,
        "run_id": run_id,
        "approval_id": approval_id,
        "worktree_path": str(worktree_path),
        "base_commit": base_commit,
        "approved_finding_ids": approved_finding_ids,
        "isolation": isolation_info,
        "lease": lease,
    }


def execute_approved_findings_broker(
    broker_client: BrokerClient,
    *,
    project_key: str,
    approval_token: str,
    remediation_fn: RemediationCallback | None = None,
    happy_test_fn: TestCallback | None = None,
    adversarial_test_fn: TestCallback | None = None,
    red_team_fn: RedTeamCallback | None = None,
    integration_test_fn: Callable[[Path], tuple[bool, str]] | None = None,
    happy_test_cmd: list[str] | None = None,
    adversarial_test_cmd: list[str] | None = None,
    integration_test_cmd: list[str] | None = None,
    worktrees_root: Path | None = None,
    checkpoints_root: Path | None = None,
    quarantine_root: Path | None = None,
    min_free_mb: int = 500,
    jsonl_path: Path | None = None,
) -> dict[str, Any]:
    """Execute approved findings exclusively via BrokerClient RPC. Zero direct SQLite calls."""
    session = start_isolated_execution_broker(
        broker_client,
        project_key=project_key,
        approval_token=approval_token,
        worktrees_root=worktrees_root,
        min_free_mb=min_free_mb,
        jsonl_path=jsonl_path,
    )
    exec_id = session["exec_id"]
    run_id = session["run_id"]
    worktree_path = Path(session["worktree_path"])
    lease = session.get("lease", {})
    chk_root = checkpoints_root or (worktree_path.parent.parent / "checkpoints")

    per_finding_results: list[dict[str, Any]] = []
    verified_finding_ids: list[str] = []
    rolled_back_ids: list[str] = []

    for finding_id in session["approved_finding_ids"]:
        chk = create_finding_checkpoint(worktree_path, chk_root, exec_id, finding_id)
        before_snapshot = _list_worktree_files(worktree_path)

        broker_client.register_checkpoint(
            checkpoint_id=chk["checkpoint_id"],
            exec_id=exec_id,
            finding_id=finding_id,
            base_commit=session["base_commit"],
            checkpoint_path=chk["checkpoint_path"],
        )

        verified = False
        last_error = ""
        happy_ok = False
        adv_ok = False
        rt_ok = False
        rt_notes = ""
        changed_files: list[str] = []

        finding_dict = {"finding_id": finding_id, "project_key": project_key}

        recorded_attempts = 0  # attempts recorded with the broker (contiguous 1, 2[, 3 if passing])
        for attempt in range(0, 3):
            try:
                if remediation_fn is not None:
                    remediation_fn(worktree_path, finding_dict, attempt)
            except Exception as exc:
                last_error = f"Remediation callback error on attempt {attempt}: {exc}"
                continue

            sanitize_and_verify_worktree_isolation(worktree_path)
            after_snapshot = _list_worktree_files(worktree_path)

            if happy_test_fn is not None:
                happy_ok, happy_msg = happy_test_fn(worktree_path, finding_dict, attempt)
            else:
                happy_ok, happy_msg = _run_shell_test(worktree_path, happy_test_cmd)

            if adversarial_test_fn is not None:
                adv_ok, adv_msg = adversarial_test_fn(worktree_path, finding_dict, attempt)
            else:
                adv_ok, adv_msg = _run_shell_test(worktree_path, adversarial_test_cmd)

            rt_check = verify_red_team_diff(
                worktree_path,
                before_snapshot=before_snapshot,
                after_snapshot=after_snapshot,
                finding=finding_dict,
            )
            rt_ok = bool(rt_check["passed"])
            rt_notes = str(rt_check["notes"])
            changed_files = list(rt_check["changed_files"])

            if rt_ok and red_team_fn is not None:
                custom_rt_ok, custom_rt_notes = red_team_fn(worktree_path, finding_dict, changed_files, attempt)
                rt_ok = rt_ok and custom_rt_ok
                if custom_rt_notes:
                    rt_notes = f"{rt_notes} | {custom_rt_notes}"

            # Record attempt via broker (attempt 0 records as 1, 1 as 2; the verification after the second repair
            # is recorded only when it passes -- a failing one is followed by the checkpoint rollback)
            if recorded_attempts < 2 or (happy_ok and adv_ok and rt_ok):
                recorded_attempts += 1
                broker_client.record_repair_attempt(
                    exec_id=exec_id,
                    finding_id=finding_id,
                    repair_attempt=recorded_attempts,
                    happy_test_passed=1 if happy_ok else 0,
                    adversarial_test_passed=1 if adv_ok else 0,
                    red_team_passed=1 if rt_ok else 0,
                    red_team_notes=rt_notes,
                )

            if happy_ok and adv_ok and rt_ok:
                verified = True
                last_error = ""
                break

            reasons: list[str] = []
            if not happy_ok:
                reasons.append(f"happy_test failed ({happy_msg})")
            if not adv_ok:
                reasons.append(f"adversarial_test failed ({adv_msg})")
            if not rt_ok:
                reasons.append(f"red_team failed ({rt_notes})")
            last_error = "; ".join(reasons)

            if remediation_fn is None:
                break

        if verified:
            verified_finding_ids.append(finding_id)
            per_finding_results.append({
                "finding_id": finding_id,
                "status": "VERIFIED",
                "repair_attempts": attempt,
                "changed_files": changed_files,
            })
        else:
            broker_client.restore_checkpoint(chk["checkpoint_id"], exec_id, str(worktree_path))
            rolled_back_ids.append(finding_id)
            per_finding_results.append({
                "finding_id": finding_id,
                "status": "ROLLED_BACK",
                "repair_attempts": attempt,
                "error": last_error,
            })

    integration_passed = True
    integration_msg = "Integration verification passed."
    if verified_finding_ids:
        if integration_test_fn is not None:
            integration_passed, integration_msg = integration_test_fn(worktree_path)
        elif integration_test_cmd is not None:
            integration_passed, integration_msg = _run_shell_test(worktree_path, integration_test_cmd)

    if verified_finding_ids and not integration_passed:
        broker_client.quarantine_checkpoint(
            quarantine_id=f"Q-{exec_id}",
            project_key=project_key,
            exec_id=exec_id,
            worktree_path=str(worktree_path),
            reason=f"Integration test suite failed: {integration_msg}",
        )
        return {
            "exec_id": exec_id,
            "project_key": project_key,
            "status": "QUARANTINED",
            "integration_passed": False,
            "per_finding_results": per_finding_results,
        }

    final_status = "COMPLETED" if (verified_finding_ids and not rolled_back_ids) else ("PARTIAL" if verified_finding_ids else "FAILED")
    broker_client.finalize_execution(
        exec_id=exec_id,
        status=final_status,
        integration_test_passed=1 if integration_passed else 0,
        lease_id=lease.get("lease_id", "lease-0"),
        fencing_token=int(lease.get("fencing_token", 1)),
    )

    return {
        "exec_id": exec_id,
        "project_key": project_key,
        "run_id": run_id,
        "status": final_status,
        "integration_passed": integration_passed,
        "verified_finding_ids": verified_finding_ids,
        "rolled_back_finding_ids": rolled_back_ids,
        "per_finding_results": per_finding_results,
        "worktree_path": str(worktree_path),
    }

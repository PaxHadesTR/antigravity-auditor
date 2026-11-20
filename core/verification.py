from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from broker.client import BrokerClient

from agentapi import AgentApiAdapter, is_valid_conversation_id

ALLOWED_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
ALLOWED_CONFIDENCES = ("CONFIRMED", "LIKELY", "SPECULATIVE")
ALLOWED_VERDICTS = ("CONFIRMED", "PARTIALLY_CONFIRMED", "REJECTED", "UNVERIFIABLE")
ALLOWED_VERIFICATION_STATUSES = (
    "CANDIDATE",
    "VERIFIED",
    "PARTIALLY_VERIFIED",
    "REJECTED",
    "UNVERIFIABLE",
    "LEGACY_UNVERIFIED",
    "STALE",
)
ALLOWED_AUDIT_RUN_STATUSES = (
    "IDLE",
    "PREFLIGHT",
    "PRIMARY_AUDIT_RUNNING",
    "DISPATCHED",
    "ANALYZING",
    "VERIFICATION_PENDING",
    "VERIFICATION_DISPATCHING",
    "VERIFICATION_RUNNING",
    "EVIDENCE_VALIDATION",
    "READY_FOR_REVIEW",
    "PENDING_APPROVAL",
    "VERIFICATION_FAILED",
    "VERIFICATION_BLOCKED",
    "VERIFICATION_STALE",
    "VERIFICATION_UNCERTAIN",
    "RECOVERABLE",
    "FAILED",
    "STALE",
    "COMPLETED",
    "PARTIAL",
    "ARCHIVED",
)
ALLOWED_QUEUE_STATUSES = (
    "QUEUED",
    "CLAIMED",
    "DISPATCHING",
    "RUNNING",
    "COMPLETED",
    "RETRYABLE_FAILURE",
    "BLOCKED_CONFIGURATION",
    "DISPATCH_UNCERTAIN",
    "FAILED",
)
ALLOWED_EVIDENCE_STATUSES = (
    "PENDING",
    "PASSED",
    "VALID",
    "FAILED",
    "INVALID",
    "UNVERIFIABLE",
    "STALE",
    "FABRICATED_REFERENCE",
    "UNCHECKED",
)

# Explicit state machine transition table enforced by Python control plane
ALLOWED_AUDIT_STATE_TRANSITIONS: dict[str, set[str]] = {
    "IDLE": {"PREFLIGHT", "ARCHIVED"},
    "PREFLIGHT": {
        "PRIMARY_AUDIT_RUNNING",
        "DISPATCHED",
        "VERIFICATION_PENDING",
        "FAILED",
        "STALE",
        "RECOVERABLE",
        "ARCHIVED",
    },
    "PRIMARY_AUDIT_RUNNING": {
        "VERIFICATION_PENDING",
        "FAILED",
        "STALE",
        "RECOVERABLE",
        "ARCHIVED",
    },
    "DISPATCHED": {
        "PRIMARY_AUDIT_RUNNING",
        "ANALYZING",
        "VERIFICATION_PENDING",
        "FAILED",
        "STALE",
        "RECOVERABLE",
        "ARCHIVED",
    },
    "ANALYZING": {
        "VERIFICATION_PENDING",
        "FAILED",
        "STALE",
        "RECOVERABLE",
        "ARCHIVED",
    },
    "VERIFICATION_PENDING": {
        "VERIFICATION_PENDING",
        "VERIFICATION_DISPATCHING",
        "VERIFICATION_RUNNING",
        "VERIFICATION_BLOCKED",
        "VERIFICATION_STALE",
        "VERIFICATION_FAILED",
        "VERIFICATION_UNCERTAIN",
        "RECOVERABLE",
        "FAILED",
        "STALE",
        "ARCHIVED",
    },
    "VERIFICATION_DISPATCHING": {
        "VERIFICATION_RUNNING",
        "VERIFICATION_UNCERTAIN",
        "VERIFICATION_BLOCKED",
        "VERIFICATION_FAILED",
        "VERIFICATION_STALE",
        "VERIFICATION_PENDING",
        "RECOVERABLE",
        "FAILED",
        "STALE",
        "ARCHIVED",
    },
    "VERIFICATION_RUNNING": {
        "VERIFICATION_RUNNING",
        "EVIDENCE_VALIDATION",
        "VERIFICATION_FAILED",
        "VERIFICATION_STALE",
        "VERIFICATION_BLOCKED",
        "VERIFICATION_UNCERTAIN",
        "RECOVERABLE",
        "FAILED",
        "STALE",
        "ARCHIVED",
    },
    "EVIDENCE_VALIDATION": {
        "READY_FOR_REVIEW",
        "VERIFICATION_PENDING",
        "VERIFICATION_FAILED",
        "VERIFICATION_STALE",
        "VERIFICATION_BLOCKED",
        "RECOVERABLE",
        "FAILED",
        "STALE",
        "ARCHIVED",
    },
    "READY_FOR_REVIEW": {
        "READY_FOR_REVIEW",
        "COMPLETED",
        "PARTIAL",
        "VERIFICATION_STALE",
        "STALE",
        "ARCHIVED",
    },
    "PENDING_APPROVAL": {
        "READY_FOR_REVIEW",
        "COMPLETED",
        "PARTIAL",
        "VERIFICATION_STALE",
        "STALE",
        "ARCHIVED",
    },
    "PARTIAL": {
        "PARTIAL",
        "COMPLETED",
        "READY_FOR_REVIEW",
        "VERIFICATION_STALE",
        "STALE",
        "ARCHIVED",
    },
    "VERIFICATION_FAILED": {
        "VERIFICATION_FAILED",
        "RECOVERABLE",
        "VERIFICATION_PENDING",
        "VERIFICATION_RUNNING",
        "FAILED",
        "ARCHIVED",
    },
    "VERIFICATION_BLOCKED": {
        "VERIFICATION_BLOCKED",
        "RECOVERABLE",
        "VERIFICATION_PENDING",
        "VERIFICATION_DISPATCHING",
        "VERIFICATION_RUNNING",
        "FAILED",
        "ARCHIVED",
    },
    "VERIFICATION_STALE": {
        "VERIFICATION_STALE",
        "RECOVERABLE",
        "FAILED",
        "ARCHIVED",
    },
    "VERIFICATION_UNCERTAIN": {
        "VERIFICATION_UNCERTAIN",
        "VERIFICATION_RUNNING",
        "RECOVERABLE",
        "VERIFICATION_PENDING",
        "FAILED",
        "ARCHIVED",
    },
    "RECOVERABLE": {
        "RECOVERABLE",
        "VERIFICATION_PENDING",
        "VERIFICATION_DISPATCHING",
        "VERIFICATION_RUNNING",
        "PREFLIGHT",
        "FAILED",
        "ARCHIVED",
    },
    "STALE": {
        "STALE",
        "RECOVERABLE",
        "VERIFICATION_PENDING",
        "FAILED",
        "ARCHIVED",
    },
    "FAILED": {
        "FAILED",
        "RECOVERABLE",
        "ARCHIVED",
    },
    "COMPLETED": {
        "COMPLETED",
        "READY_FOR_REVIEW",  # only a run completed by review (save_decisions reopens it to revise decisions)
        "ARCHIVED",
    },
    "ARCHIVED": {
        "ARCHIVED",
    },
}

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
DANGEROUS_REMEDIATION_PATTERNS = [
    re.compile(r"\b(git\s+push\s+--force|git\s+reset\s+--hard|DROP\s+TABLE|DROP\s+DATABASE|rm\s+-rf\s+/)\b", re.IGNORECASE),
    re.compile(r"\b(disable\s+auth|bypass\s+authentication|skip\s+permission|chmod\s+777)\b", re.IGNORECASE),
]
UNSAFE_REVIEW_MARKERS = [
    re.compile(r"\b(UNSAFE_REMEDIATION|REJECT_REMEDIATION|INTRODUCES_REGRESSION|DANGEROUS_REMEDIATION)\b", re.IGNORECASE),
]
SYMBOL_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:<>-]{0,255}$")


def is_forbidden_evidence_path(rel_path: str | Path) -> bool:
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


_SNAPSHOT_UNREADABLE_PATHS_FOR_TEST: set[str] = set()
_SNAPSHOT_CHUNK_HOOK_FOR_TEST: Any | None = None


def _is_link_or_junction(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if hasattr(path, "is_junction") and path.is_junction():
            return True
    except OSError:
        return True
    return False


def _is_link_or_junction_within_repo(repo_root: Path, target: Path) -> bool:
    if _is_link_or_junction(target):
        return True
    try:
        resolved_root = repo_root.resolve()
        curr = target.parent
        while True:
            if _is_link_or_junction(curr):
                return True
            if curr == resolved_root or curr.parent == curr:
                break
            curr = curr.parent
    except OSError:
        return True
    return False


def canonical_repo_path_key(rel_path: str | None, *, case_insensitive: bool | None = None) -> str:
    norm = normalize_path_str(rel_path)
    use_ci = (os.name == "nt") if case_insensitive is None else bool(case_insensitive)
    return norm.lower() if use_ci else norm


def resolve_repo_file_for_reading(repo_path: Path, rel_path: str) -> Path | None:
    norm = normalize_path_str(rel_path)
    if not norm:
        return None
    if norm.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", norm):
        return None
    parts = Path(norm).parts
    if not parts or ".." in parts:
        return None
    if is_forbidden_evidence_path(norm):
        return None
    try:
        resolved_repo = repo_path.resolve()
        unr_candidate = resolved_repo / norm
        if _is_link_or_junction_within_repo(resolved_repo, unr_candidate):
            return None
        target = unr_candidate.resolve()
        target.relative_to(resolved_repo)
        if _is_link_or_junction_within_repo(resolved_repo, target):
            return None
        if not target.is_file():
            return None
        return target
    except (OSError, ValueError):
        return None


def stream_file_sha256(
    path: Path,
    *,
    chunk_size: int = 1024 * 1024,
    _on_chunk_hook: Any | None = None,
) -> str:
    """Stream SHA-256 of any repository file without arbitrary size cutoffs and detect mid-hash modifications."""
    hook = _on_chunk_hook if _on_chunk_hook is not None else _SNAPSHOT_CHUNK_HOOK_FOR_TEST
    st1 = path.stat()
    digest = hashlib.sha256()
    bytes_read = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(max(4096, int(chunk_size)))
            if not chunk:
                break
            digest.update(chunk)
            bytes_read += len(chunk)
            if hook is not None:
                hook(path, bytes_read)
    st2 = path.stat()
    if (
        bytes_read != st1.st_size
        or st1.st_size != st2.st_size
        or st1.st_mtime_ns != st2.st_mtime_ns
    ):
        raise RuntimeError(f"File '{path}' changed while streaming SHA-256 hash.")
    return digest.hexdigest()


def assert_valid_audit_transition(current_status: str, target_status: str) -> None:
    if target_status not in ALLOWED_AUDIT_RUN_STATUSES:
        raise RuntimeError(f"Invalid target audit status: '{target_status}'")
    allowed = ALLOWED_AUDIT_STATE_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        raise RuntimeError(
            f"Illegal audit state transition: '{current_status}' -> '{target_status}'. "
            "Primary audits must pass second-pass verification and deterministic evidence validation before review."
        )


def transition_audit_run_status(
    conn: sqlite3.Connection,
    run_id: str,
    target_status: str,
    *,
    error: str | None = None,
    reason: str | None = None,
    report_path: str | None = None,
    finished: bool = False,
    actor: str | None = None,
    jsonl_path: Path | None = None,
) -> str:
    row = conn.execute("SELECT status FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()
    if not row:
        raise RuntimeError(f"Audit run '{run_id}' does not exist.")
    current_status = str(row["status"])
    assert_valid_audit_transition(current_status, target_status)

    effective_error = error if error is not None else reason
    fields = ["status = ?", "heartbeat_at = CURRENT_TIMESTAMP"]
    params: list[Any] = [target_status]
    if effective_error is not None:
        fields.append("error = ?")
        params.append(effective_error)
    if report_path is not None:
        fields.append("report_path = ?")
        params.append(report_path)
    if finished:
        fields.append("finished_at = CURRENT_TIMESTAMP")
    params.append(run_id)
    conn.execute(f"UPDATE audit_runs SET {', '.join(fields)} WHERE run_id = ?", params)
    return current_status


def compute_excerpt_sha256(text: str) -> str:
    normalized = "\n".join(" ".join(line.split()) for line in text.strip().splitlines() if line.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _git_head(repo_path: Path) -> str:
    try:
        res = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return res.stdout.strip() if res.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def compute_clean_working_tree_hash(repo_path: Path) -> str:
    """Compute working tree snapshot hash excluding `.antigravity-audit` and secret/DB files."""
    if not repo_path.is_dir():
        return ""
    head = _git_head(repo_path)
    digest = hashlib.sha256()
    skipped_dirs = {".git", ".antigravity-audit", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv", ".worktrees"}
    resolved_repo = repo_path.resolve()
    unreadable_test = {canonical_repo_path_key(p) for p in _SNAPSHOT_UNREADABLE_PATHS_FOR_TEST if p}
    if head:
        diff = subprocess.run(
            ["git", "-C", str(repo_path), "diff", "--binary", "HEAD", "--", ".", ":(exclude).antigravity-audit"],
            capture_output=True,
            timeout=25,
        )
        if diff.returncode == 0:
            digest.update(diff.stdout)
        untracked = subprocess.run(
            ["git", "-C", str(repo_path), "ls-files", "--others", "--exclude-standard", "-z"],
            capture_output=True,
            timeout=25,
        )
        if untracked.returncode == 0:
            for raw_name in sorted(untracked.stdout.split(b"\0")):
                if not raw_name:
                    continue
                rel_str = raw_name.decode("utf-8", errors="replace").replace("\\", "/")
                if any(part in skipped_dirs for part in Path(rel_str).parts):
                    continue
                if is_forbidden_evidence_path(rel_str):
                    continue
                unr = resolved_repo / rel_str
                if _is_link_or_junction_within_repo(resolved_repo, unr):
                    continue
                try:
                    candidate = unr.resolve()
                    candidate.relative_to(resolved_repo)
                    if candidate.is_file() and not _is_link_or_junction_within_repo(resolved_repo, candidate):
                        digest.update(rel_str.encode("utf-8"))
                        if (
                            canonical_repo_path_key(rel_str) in unreadable_test
                            or canonical_repo_path_key(str(candidate)) in unreadable_test
                        ):
                            digest.update(b"__UNREADABLE__")
                        else:
                            f_hex = stream_file_sha256(candidate)
                            digest.update(bytes.fromhex(f_hex))
                except (OSError, ValueError, RuntimeError):
                    digest.update(rel_str.encode("utf-8"))
                    digest.update(b"__UNREADABLE__")
        return digest.hexdigest()

    # Fallback deterministic directory tree hash when repo_path has no git commit (e.g. unit test fixtures)
    for root_str, dirs, files in os.walk(resolved_repo):
        for skip_dir in skipped_dirs:
            if skip_dir in dirs:
                dirs.remove(skip_dir)
        dirs[:] = [d for d in dirs if not _is_link_or_junction(Path(root_str) / d)]
        dirs.sort()
        root_p = Path(root_str)
        for fname in sorted(files):
            full = root_p / fname
            if _is_link_or_junction_within_repo(resolved_repo, full):
                continue
            try:
                rel = full.relative_to(resolved_repo).as_posix()
            except ValueError:
                continue
            if is_forbidden_evidence_path(rel):
                continue
            try:
                if full.is_file():
                    digest.update(rel.encode("utf-8"))
                    if (
                        canonical_repo_path_key(rel) in unreadable_test
                        or canonical_repo_path_key(str(full.resolve())) in unreadable_test
                    ):
                        digest.update(b"__UNREADABLE__")
                    else:
                        f_hex = stream_file_sha256(full)
                        digest.update(bytes.fromhex(f_hex))
            except (OSError, RuntimeError):
                digest.update(rel.encode("utf-8"))
                digest.update(b"__UNREADABLE__")
    return digest.hexdigest()


def collect_repo_file_hashes_with_status(
    repo_path: Path,
    candidate_paths: list[str | None] | None = None,
    *,
    _unreadable_paths_for_test: set[str] | None = None,
    _on_chunk_hook: Any | None = None,
) -> dict[str, Any]:
    """Collect streamed SHA-256 hashes of all safe source files in repo_path without size cutoffs.

    Marks `snapshot_complete=False` (fail-closed) if any repository file cannot be read or is modified mid-hash.
    """
    file_hashes: dict[str, str] = {}
    unreadable_files: list[str] = []
    if not repo_path.is_dir():
        return {
            "file_hashes": file_hashes,
            "snapshot_complete": True,
            "unreadable_files": [],
            "incomplete_reason": None,
        }
    resolved_repo = repo_path.resolve()
    unreadable_test = {
        canonical_repo_path_key(p)
        for p in ((_unreadable_paths_for_test or set()) | _SNAPSHOT_UNREADABLE_PATHS_FOR_TEST)
        if p
    }
    skip_dirs = (
        ".git",
        ".antigravity-audit",
        "__pycache__",
        ".pytest_cache",
        "node_modules",
        ".venv",
        "venv",
        ".worktrees",
    )

    for root_str, dirs, files in os.walk(resolved_repo):
        for skip_dir in skip_dirs:
            if skip_dir in dirs:
                dirs.remove(skip_dir)
        dirs[:] = [d for d in dirs if not _is_link_or_junction(Path(root_str) / d)]
        dirs.sort()
        root_p = Path(root_str)
        for fname in sorted(files):
            full = root_p / fname
            if _is_link_or_junction_within_repo(resolved_repo, full):
                continue
            try:
                rel = full.relative_to(resolved_repo).as_posix()
            except ValueError:
                continue
            if is_forbidden_evidence_path(rel):
                continue
            if (
                canonical_repo_path_key(rel) in unreadable_test
                or canonical_repo_path_key(str(full.resolve())) in unreadable_test
            ):
                unreadable_files.append(rel)
                continue
            try:
                if full.is_file():
                    file_hashes[rel] = stream_file_sha256(full, _on_chunk_hook=_on_chunk_hook)
            except (OSError, RuntimeError):
                unreadable_files.append(rel)

    if candidate_paths:
        existing_canonical = {canonical_repo_path_key(k): k for k in file_hashes}
        for raw_rel in candidate_paths:
            if not raw_rel:
                continue
            norm = normalize_path_str(raw_rel)
            if not norm or ".." in Path(norm).parts or Path(norm).is_absolute():
                continue
            if is_forbidden_evidence_path(norm):
                continue
            ckey = canonical_repo_path_key(norm)
            if ckey in unreadable_test:
                unreadable_files.append(norm)
                continue
            if norm in file_hashes or ckey in existing_canonical:
                continue
            try:
                unr_target = resolved_repo / norm
                if _is_link_or_junction_within_repo(resolved_repo, unr_target):
                    continue
                target = unr_target.resolve()
                target.relative_to(resolved_repo)
                if target.is_file() and not _is_link_or_junction_within_repo(resolved_repo, target):
                    file_hashes[norm] = stream_file_sha256(target, _on_chunk_hook=_on_chunk_hook)
                    existing_canonical[ckey] = norm
            except (OSError, ValueError, RuntimeError):
                if (resolved_repo / norm).exists():
                    unreadable_files.append(norm)

    unreadable_sorted = sorted(set(unreadable_files))
    return {
        "file_hashes": file_hashes,
        "snapshot_complete": len(unreadable_sorted) == 0,
        "unreadable_files": unreadable_sorted,
        "incomplete_reason": (
            f"Unreadable or mid-hash modified repository file(s): {', '.join(unreadable_sorted)}"
            if unreadable_sorted
            else None
        ),
    }


def collect_repo_file_hashes(repo_path: Path, candidate_paths: list[str | None] | None = None) -> dict[str, str]:
    """Collect SHA-256 hashes of safe source files in repo_path for snapshot binding."""
    return collect_repo_file_hashes_with_status(repo_path, candidate_paths)["file_hashes"]


def create_or_get_audit_snapshot(
    conn: sqlite3.Connection,
    *,
    project_key: str,
    run_id: str,
    repo_path: Path,
    candidate_paths: list[str | None] | None = None,
) -> dict[str, Any]:
    existing = conn.execute(
        "SELECT * FROM audit_snapshots WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if existing:
        ex_keys = existing.keys()
        snap_complete = (
            bool(int(existing["snapshot_complete"]))
            if ("snapshot_complete" in ex_keys and existing["snapshot_complete"] is not None)
            else True
        )
        inc_reason = existing["incomplete_reason"] if "incomplete_reason" in ex_keys else None
        return {
            "snapshot_id": str(existing["snapshot_id"]),
            "run_id": str(existing["run_id"]),
            "project_key": str(existing["project_key"]),
            "repo_path": str(existing["repo_path"]),
            "base_commit_sha": str(existing["base_commit_sha"]),
            "working_tree_hash": str(existing["working_tree_hash"]),
            "file_hashes": json.loads(str(existing["file_hashes_json"] or "{}")),
            "snapshot_complete": snap_complete,
            "incomplete_reason": inc_reason,
        }

    run = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()
    if not run:
        raise RuntimeError(f"Audit run '{run_id}' not found.")

    live_head = _git_head(repo_path)
    base_commit_sha = live_head or str(run["base_commit"] or "UNCOMMITTED_WORKTREE")
    working_tree = compute_clean_working_tree_hash(repo_path) or str(run["working_tree_hash"] or "EMPTY_TREE")
    hash_status = collect_repo_file_hashes_with_status(repo_path, candidate_paths)
    file_hashes = hash_status["file_hashes"]
    snapshot_complete = bool(hash_status["snapshot_complete"])
    incomplete_reason = hash_status["incomplete_reason"]

    snapshot_seed = f"{project_key}|{run_id}|{base_commit_sha}|{working_tree}"
    snapshot_id = "SNAP-" + hashlib.sha256(snapshot_seed.encode("utf-8")).hexdigest()[:16]

    conn.execute(
        """INSERT INTO audit_snapshots(
            snapshot_id, run_id, project_key, repo_path,
            base_commit_sha, working_tree_hash, file_hashes_json,
            snapshot_complete, incomplete_reason
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            snapshot_id,
            run_id,
            project_key,
            str(repo_path),
            base_commit_sha,
            working_tree,
            json.dumps(file_hashes, sort_keys=True),
            1 if snapshot_complete else 0,
            incomplete_reason,
        ),
    )
    conn.execute(
        "UPDATE audit_runs SET snapshot_id=?, base_commit=?, working_tree_hash=? WHERE run_id=?",
        (snapshot_id, base_commit_sha, working_tree, run_id),
    )
    return {
        "snapshot_id": snapshot_id,
        "run_id": run_id,
        "project_key": project_key,
        "repo_path": str(repo_path),
        "base_commit_sha": base_commit_sha,
        "working_tree_hash": working_tree,
        "file_hashes": file_hashes,
        "snapshot_complete": snapshot_complete,
        "incomplete_reason": incomplete_reason,
    }


def _build_canonical_hash_index(raw_hashes: dict[str, str]) -> tuple[dict[str, tuple[str, str]], str | None]:
    """Map canonical_repo_path_key -> (original_rel_path, sha256) and detect ambiguous case collisions."""
    index: dict[str, tuple[str, str]] = {}
    for rel, sha in sorted(raw_hashes.items()):
        norm = normalize_path_str(rel)
        if not norm:
            continue
        ckey = canonical_repo_path_key(norm)
        if ckey in index:
            prev_rel, prev_sha = index[ckey]
            if prev_rel != norm and prev_sha != sha:
                return (
                    index,
                    f"Ambiguous case-insensitive path collision between '{prev_rel}' and '{norm}'.",
                )
        else:
            index[ckey] = (norm, str(sha))
    return index, None


def verify_snapshot_consistency(
    conn: sqlite3.Connection,
    *,
    repo_path: Path,
    run_id: str,
    relevant_files: list[str] | None = None,
) -> dict[str, Any]:
    """Verify HEAD commit SHA, working tree snapshot, and file hashes remain consistent with audit snapshot."""
    snap = conn.execute("SELECT * FROM audit_snapshots WHERE run_id=?", (run_id,)).fetchone()
    if not snap:
        return {
            "consistent": False,
            "code": "MISSING_SNAPSHOT",
            "reason": f"No audit snapshot exists for run '{run_id}'.",
        }

    snap_keys = snap.keys()
    snap_complete = (
        bool(int(snap["snapshot_complete"]))
        if ("snapshot_complete" in snap_keys and snap["snapshot_complete"] is not None)
        else True
    )
    if not snap_complete:
        inc_reason = (
            str(snap["incomplete_reason"])
            if ("incomplete_reason" in snap_keys and snap["incomplete_reason"])
            else "Audit snapshot was marked incomplete due to unreadable files."
        )
        return {
            "consistent": False,
            "code": "SNAPSHOT_INCOMPLETE",
            "reason": inc_reason,
        }

    expected_commit = str(snap["base_commit_sha"])
    live_head = _git_head(repo_path)
    if live_head and expected_commit not in ("", "UNCOMMITTED_WORKTREE") and live_head != expected_commit:
        return {
            "consistent": False,
            "code": "STALE_COMMIT_SHA",
            "reason": (
                f"Repository HEAD commit changed since audit snapshot "
                f"({expected_commit[:12]} -> {live_head[:12]})."
            ),
        }

    snapshot_hashes: dict[str, str] = json.loads(str(snap["file_hashes_json"] or "{}"))
    curr_status = collect_repo_file_hashes_with_status(repo_path, relevant_files)
    if not curr_status["snapshot_complete"]:
        return {
            "consistent": False,
            "code": "SNAPSHOT_INCOMPLETE",
            "reason": str(
                curr_status["incomplete_reason"]
                or "Current repository contains unreadable or mid-hash modified files."
            ),
        }
    current_hashes: dict[str, str] = curr_status["file_hashes"]

    snap_idx, snap_collision = _build_canonical_hash_index(snapshot_hashes)
    if snap_collision:
        return {
            "consistent": False,
            "code": "AMBIGUOUS_CASE_COLLISION",
            "reason": snap_collision,
        }
    curr_idx, curr_collision = _build_canonical_hash_index(current_hashes)
    if curr_collision:
        return {
            "consistent": False,
            "code": "AMBIGUOUS_CASE_COLLISION",
            "reason": curr_collision,
        }

    relevant_ckeys = {
        canonical_repo_path_key(rel)
        for rel in (relevant_files or [])
        if rel and normalize_path_str(rel)
    }
    ckeys_to_check = relevant_ckeys | set(snap_idx.keys()) | set(curr_idx.keys())
    for ckey in sorted(ckeys_to_check):
        if not ckey:
            continue
        if ckey in snap_idx:
            snap_rel, snap_sha = snap_idx[ckey]
            curr_entry = curr_idx.get(ckey)
            if curr_entry is None:
                return {
                    "consistent": False,
                    "code": "STALE_FILE_DELETED",
                    "reason": f"File '{snap_rel}' present in audit snapshot was deleted or moved.",
                }
            curr_rel, curr_sha = curr_entry
            if curr_sha != snap_sha:
                return {
                    "consistent": False,
                    "code": "STALE_FILE_MODIFIED",
                    "reason": (
                        f"File '{snap_rel}' modified since primary audit snapshot "
                        f"({snap_sha[:10]} != {curr_sha[:10]})."
                    ),
                }
        elif ckey in curr_idx:
            curr_rel, _ = curr_idx[ckey]
            return {
                "consistent": False,
                "code": "STALE_UNTRACKED_FILE_ADDED",
                "reason": f"New or untracked file '{curr_rel}' was added since primary audit snapshot.",
            }

    expected_wt_hash = str(snap["working_tree_hash"] or "")
    if len(expected_wt_hash) == 64:
        live_wt_hash = compute_clean_working_tree_hash(repo_path)
        if live_wt_hash and live_wt_hash != expected_wt_hash:
            return {
                "consistent": False,
                "code": "STALE_WORKING_TREE_HASH",
                "reason": (
                    f"Repository working tree hash changed since audit snapshot "
                    f"({expected_wt_hash[:12]} -> {live_wt_hash[:12]})."
                ),
            }

    return {
        "consistent": True,
        "code": "OK",
        "reason": "Repository HEAD and snapshot file hashes match audit snapshot.",
        "snapshot_id": str(snap["snapshot_id"]),
        "base_commit_sha": expected_commit,
    }


def validate_raw_evidence_location(file_path: Any, line_start: Any, line_end: Any) -> tuple[bool, str, str]:
    """Validate path safety and line bounds on raw input before touching filesystem."""
    if not isinstance(file_path, str) or not file_path.strip():
        return False, "MISSING_FILE_PATH", "Evidence file_path must be a non-empty relative path."
    raw = file_path.strip()
    if raw.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", raw):
        return False, "ABSOLUTE_PATH_FORBIDDEN", f"Evidence file_path must be relative, got '{raw}'."
    norm = raw.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    parts = Path(norm).parts
    if not parts or ".." in parts:
        return False, "PATH_TRAVERSAL_FORBIDDEN", f"Path traversal is forbidden in evidence file_path: '{raw}'."
    if is_forbidden_evidence_path(norm):
        return False, "FORBIDDEN_SECRET_PATH", f"Forbidden secret, key, or database file in evidence: '{norm}'."
    if line_start is None or not isinstance(line_start, int) or isinstance(line_start, bool) or line_start < 1:
        return False, "INVALID_LINE_START", f"Invalid line_start: {line_start}"
    if line_end is None or not isinstance(line_end, int) or isinstance(line_end, bool) or line_end < 1:
        return False, "INVALID_LINE_END", f"Invalid line_end: {line_end}"
    if line_end < line_start:
        return False, "INVALID_LINE_RANGE", f"line_end ({line_end}) < line_start ({line_start})."
    return True, "OK", norm


SUPPORTED_C_FAMILY_EXTS = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".c",
    ".cpp",
    ".cc",
    ".cxx",
    ".h",
    ".hpp",
    ".cs",
    ".rs",
}
SUPPORTED_HASH_FAMILY_EXTS = {
    ".ps1",
    ".sh",
    ".bash",
    ".zsh",
    ".rb",
    ".yaml",
    ".yml",
    ".toml",
}


# Evidence-quality bounds for the gate (real verifier output: spans <= 44 lines, excerpts >= 400 chars).
MAX_EVIDENCE_LINE_SPAN = 200
MIN_EVIDENCE_EXCERPT_CHARS = 12


class UnverifiableEvidenceError(RuntimeError):
    """Raised when evidence syntax is ambiguous, malformed, or cannot be deterministically validated."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


_YAML_BLOCK_HEADER_RE = re.compile(r"(?:^|[:\-]\s*|\s)[|>][-+0-9]*\s*(?:#.*)?$")


def _neutralize_yaml_block_scalars(text: str) -> str:
    """Blank out quote and '#' characters inside YAML block scalars (``key: |`` / ``key: >``): their content is
    literal text (often a shell script), not YAML strings or comments. Line structure is preserved."""
    lines = text.split("\n")
    block_indent: int | None = None
    for idx, line in enumerate(lines):
        indent = len(line) - len(line.lstrip(" "))
        if block_indent is not None:
            if not line.strip() or indent > block_indent:
                lines[idx] = line.replace("'", " ").replace('"', " ").replace("#", " ")
                continue
            block_indent = None
        if line.lstrip().startswith("#"):
            continue  # a comment such as "# example: |" is not a block-scalar header
        code = line.split(" #", 1)[0].rstrip()
        if _YAML_BLOCK_HEADER_RE.search(code) and (":" in code or code.lstrip().startswith("-")):
            block_indent = indent
    return "\n".join(lines)


def _strip_comments_and_strings_per_line(file_text: str, ext: str) -> list[str]:
    """Lexically strip comments and string literals while preserving exact line numbers."""
    text = file_text.replace("\r\n", "\n").replace("\r", "\n")
    if ext in (".yaml", ".yml"):
        text = _neutralize_yaml_block_scalars(text)
    n = len(text)
    i = 0
    out: list[str] = []
    state = "CODE"
    is_c = ext in SUPPORTED_C_FAMILY_EXTS
    is_hash = ext in SUPPORTED_HASH_FAMILY_EXTS
    supports_backtick_str = ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go"}
    supports_regex_literal = ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
    is_shell = ext in {".sh", ".bash", ".zsh"}
    is_yaml = ext in {".yaml", ".yml"}
    is_toml = ext == ".toml"
    at_line_start = True
    # Code characters seen so far on the current line (decides regex-vs-division and YAML/TOML value position).
    line_code: list[str] = []
    end_marker = ""  # terminator of the current raw/verbatim/triple-quoted string

    def _prev_sig() -> str:
        for ch in reversed(line_code):
            if not ch.isspace():
                return ch
        return ""

    def _regex_allowed() -> bool:
        if "".join(line_code).rstrip().endswith(("++", "--")):
            return False  # i++ / x: division
        prev = _prev_sig()
        if prev == "" or prev in "(,=:[!&|?{};+-*%<>~^":
            return True
        tail = "".join(line_code).rstrip()
        m = re.search(r"([A-Za-z_$][\w$]*)$", tail)
        return bool(m and m.group(1) in {"return", "typeof", "case", "delete", "void", "throw", "in", "of", "yield", "await"})

    def _quote_starts_string() -> bool:
        # YAML/TOML: a quote starts a string only in key/value position or at the start of a word, so the
        # apostrophe in "it's" is text while `echo "x"` still quotes.
        if not (is_yaml or is_toml):
            return True
        if _prev_sig() in ("", ":", "-", "[", "{", ",", "=", "?"):
            return True
        return bool(line_code) and line_code[-1] in " \t"

    while i < n:
        c = text[i]
        if state == "CODE":
            if c == "\n":
                out.append("\n")
                at_line_start = True
                line_code.clear()
                i += 1
                continue
            if is_c:
                at_line_start = False
                if ext == ".cs" and (text[i : i + 2] == '@"' or text[i : i + 3] in ('$@"', '@$"')):
                    prefix = 2 if text[i] == "@" and text[i + 1] == '"' else 3
                    out.append(" " * prefix)
                    state = "VERBATIM_STR"
                    i += prefix
                    continue
                if ext == ".cs" and text[i : i + 3] == '"""':
                    out.append("   ")
                    state = "RAW_STR"
                    end_marker = '"""'
                    i += 3
                    continue
                if ext == ".rs" and c in "rb" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
                    m_raw = re.match(r"b?r(#*)\"", text[i:])
                    if m_raw:
                        out.append(" " * len(m_raw.group(0)))
                        state = "RAW_STR"
                        end_marker = '"' + m_raw.group(1)
                        i += len(m_raw.group(0))
                        continue
                if text[i : i + 2] == "//":
                    state = "LINE_COMMENT"
                    i += 2
                    continue
                if text[i : i + 2] == "/*":
                    out.append(" ")
                    state = "BLOCK_COMMENT"
                    i += 2
                    continue
                if c == "/" and supports_regex_literal and _regex_allowed():
                    j = i + 1
                    in_class = False
                    closed = False
                    while j < n and text[j] != "\n":
                        ch = text[j]
                        if ch == "\\":
                            j += 2
                            continue
                        if ch == "[":
                            in_class = True
                        elif ch == "]":
                            in_class = False
                        elif ch == "/" and not in_class:
                            closed = True
                            break
                        j += 1
                    if closed and j > i + 1:
                        out.append(" " * (j + 1 - i))
                        line_code.append("x")  # a regex literal is an operand
                        i = j + 1
                        continue
                if c == '"':
                    out.append(" ")
                    state = "DOUBLE_STR"
                    i += 1
                    continue
                if c == "'":
                    if ext == ".rs":
                        # Rust char literal ('x' or '\n') vs lifetime ('a)
                        is_char_lit = (
                            (i + 2 < n and text[i + 1] != "\\" and text[i + 2] == "'")
                            or (i + 3 < n and text[i + 1] == "\\" and text[i + 3] == "'")
                        )
                        if not is_char_lit:
                            out.append(c)
                            i += 1
                            continue
                    out.append(" ")
                    state = "SINGLE_STR"
                    i += 1
                    continue
                if c == "`" and supports_backtick_str:
                    out.append(" ")
                    state = "BACKTICK_STR"
                    i += 1
                    continue
            elif is_hash:
                if ext == ".ps1":
                    # Check for PowerShell here-string opening: @' or @" at end of line
                    if text[i : i + 2] in ("@'", '@"'):
                        marker = text[i : i + 2]
                        # Look ahead for rest of line
                        eol = text.find("\n", i + 2)
                        line_after = text[i + 2 :] if eol == -1 else text[i + 2 : eol]
                        if line_after.strip() == "":
                            if eol == -1:
                                raise UnverifiableEvidenceError(
                                    "UNVERIFIABLE_EVIDENCE",
                                    f"PowerShell here-string header '{marker}' unclosed at end of file.",
                                )
                            # Replace header and trailing horizontal whitespace up to eol with spaces, preserve newline
                            header_len = eol - i
                            out.append(" " * header_len)
                            out.append("\n")
                            state = "PS_SINGLE_HERE_STR" if marker == "@'" else "PS_DOUBLE_HERE_STR"
                            at_line_start = True
                            i = eol + 1
                            continue
                        else:
                            raise UnverifiableEvidenceError(
                                "UNVERIFIABLE_EVIDENCE",
                                f"PowerShell here-string header '{marker}' followed by invalid characters on same line.",
                            )
                    if text[i : i + 2] == "<#":
                        out.append(" ")
                        state = "PS_BLOCK_COMMENT"
                        i += 2
                        at_line_start = False
                        continue
                if c == "#":
                    # Shell and YAML: '#' starts a comment only at the start of a word (`${#x}`, `a#b` are code).
                    prev_char = text[i - 1] if i > 0 else "\n"
                    if not (is_shell or is_yaml) or prev_char in " \t\n" or (is_shell and prev_char == ";"):
                        state = "LINE_COMMENT"
                        i += 1
                        at_line_start = False
                        continue
                if is_toml and text[i : i + 3] in ("'''", '"""') and _quote_starts_string():
                    out.append("   ")
                    state = "RAW_STR"
                    end_marker = text[i : i + 3]
                    i += 3
                    at_line_start = False
                    continue
                if c == '"' and _quote_starts_string():
                    out.append(" ")
                    state = "DOUBLE_STR"
                    i += 1
                    at_line_start = False
                    continue
                if c == "'" and _quote_starts_string():
                    out.append(" ")
                    state = "SINGLE_STR"
                    i += 1
                    at_line_start = False
                    continue
            out.append(c)
            line_code.append(c)
            at_line_start = False
            i += 1
        elif state == "LINE_COMMENT":
            if c == "\n":
                out.append("\n")
                state = "CODE"
                at_line_start = True
            i += 1
        elif state == "BLOCK_COMMENT":
            if text[i : i + 2] == "*/":
                out.append(" ")
                state = "CODE"
                i += 2
                continue
            if c == "\n":
                out.append("\n")
            i += 1
        elif state == "PS_BLOCK_COMMENT":
            if text[i : i + 2] == "#>":
                out.append(" ")
                state = "CODE"
                i += 2
                continue
            if c == "\n":
                out.append("\n")
            i += 1
        elif state == "PS_SINGLE_HERE_STR":
            if at_line_start:
                if text[i : i + 2] == "'@":
                    out.append("  ")
                    i += 2
                    state = "CODE"
                    at_line_start = False
                    continue
                # Check for invalid indented terminator
                cur_eol = text.find("\n", i)
                line_content = text[i:] if cur_eol == -1 else text[i:cur_eol]
                stripped_line = line_content.lstrip(" \t")
                if stripped_line.startswith("'@") and line_content.startswith((" ", "\t")):
                    raise UnverifiableEvidenceError(
                        "UNVERIFIABLE_EVIDENCE",
                        "PowerShell here-string closing marker cannot be preceded by whitespace.",
                    )
                at_line_start = False
            if c == "\n":
                out.append("\n")
                at_line_start = True
                i += 1
            else:
                out.append(" ")
                i += 1
        elif state == "PS_DOUBLE_HERE_STR":
            if at_line_start:
                if text[i : i + 2] == '"@':
                    out.append("  ")
                    i += 2
                    state = "CODE"
                    at_line_start = False
                    continue
                cur_eol = text.find("\n", i)
                line_content = text[i:] if cur_eol == -1 else text[i:cur_eol]
                stripped_line = line_content.lstrip(" \t")
                if stripped_line.startswith('"@') and line_content.startswith((" ", "\t")):
                    raise UnverifiableEvidenceError(
                        "UNVERIFIABLE_EVIDENCE",
                        "PowerShell here-string closing marker cannot be preceded by whitespace.",
                    )
                at_line_start = False
            if c == "\n":
                out.append("\n")
                at_line_start = True
                i += 1
            else:
                out.append(" ")
                i += 1
        elif state == "DOUBLE_STR":
            esc = "`" if ext == ".ps1" else "\\"
            if c == esc and i + 1 < n:
                if text[i + 1] == "\n":
                    out.append("\n")
                i += 2
                continue
            if c == '"':
                out.append(" ")
                line_code.append("x")
                state = "CODE"
                i += 1
                continue
            if c == "\n":
                out.append("\n")
            i += 1
        elif state == "SINGLE_STR":
            # Shell and TOML single-quoted strings are literal (no escapes); PowerShell and YAML double the quote.
            backslash_escapes = not (ext == ".ps1" or is_shell or is_toml or is_yaml)
            if backslash_escapes and c == "\\" and i + 1 < n:
                if text[i + 1] == "\n":
                    out.append("\n")
                i += 2
                continue
            if c == "'":
                if (ext == ".ps1" or is_yaml) and i + 1 < n and text[i + 1] == "'":
                    i += 2
                    continue
                out.append(" ")
                line_code.append("x")
                state = "CODE"
                i += 1
                continue
            if c == "\n":
                out.append("\n")
            i += 1
        elif state == "VERBATIM_STR":
            # C# @"...": backslashes are literal, "" is an escaped quote.
            if c == '"':
                if i + 1 < n and text[i + 1] == '"':
                    i += 2
                    continue
                out.append(" ")
                line_code.append("x")
                state = "CODE"
                i += 1
                continue
            if c == "\n":
                out.append("\n")
            i += 1
        elif state == "RAW_STR":
            if end_marker == '"""' and is_toml and c == "\\" and i + 1 < n:
                # TOML multi-line *basic* strings support escapes (\" does not close the string)
                if text[i + 1] == "\n":
                    out.append("\n")
                i += 2
                continue
            if text.startswith(end_marker, i):
                out.append(" " * len(end_marker))
                line_code.append("x")
                state = "CODE"
                i += len(end_marker)
                continue
            if c == "\n":
                out.append("\n")
            i += 1
        elif state == "BACKTICK_STR":
            if ext != ".go" and c == "\\" and i + 1 < n:
                if text[i + 1] == "\n":
                    out.append("\n")
                i += 2
                continue
            if c == "`":
                out.append(" ")
                line_code.append("x")
                state = "CODE"
                i += 1
                continue
            if c == "\n":
                out.append("\n")
            i += 1

    if state in ("PS_SINGLE_HERE_STR", "PS_DOUBLE_HERE_STR"):
        raise UnverifiableEvidenceError(
            "UNVERIFIABLE_EVIDENCE",
            f"PowerShell here-string was not closed before end of file ({state}).",
        )
    if state in ("DOUBLE_STR", "SINGLE_STR", "BACKTICK_STR", "BLOCK_COMMENT", "PS_BLOCK_COMMENT", "VERBATIM_STR", "RAW_STR"):
        raise UnverifiableEvidenceError(
            "UNVERIFIABLE_EVIDENCE",
            f"File contains unclosed string or block comment ({state}).",
        )

    return "".join(out).split("\n")


def validate_single_finding_evidence(
    *,
    repo_path: Path,
    snapshot_info: dict[str, Any],
    candidate: dict[str, Any],
    source_evidence: dict[str, Any] | None = None,
    reviewed_file_hashes: dict[str, str] | None = None,
    _allow_candidate_excerpt_fallback: bool = False,
) -> dict[str, Any]:
    """Phase 4 Deterministic Evidence Verification Gate.

    Validates all 10 structural evidence guarantees:
    1. Relative repository path.
    2. No path traversal.
    3. Resolved path remains inside the repository (and is not a symlink/secret).
    4. File exists.
    5. File hash matches the audit snapshot.
    6. Line range is valid.
    7. Line range points to actual source content.
    8. Evidence excerpt hash matches and non-empty quoted excerpt exists in source.
    9. Symbol or function reference is structurally plausible and present in executable code.
    10. HEAD SHA and relevant working-tree snapshot remain consistent and complete.
    """
    if snapshot_info.get("snapshot_complete") is False:
        return {
            "passed": False,
            "status": "STALE",
            "code": "SNAPSHOT_INCOMPLETE",
            "reason": str(
                snapshot_info.get("incomplete_reason")
                or "Audit snapshot is incomplete due to unreadable repository files."
            ),
            "fabricated_reference": False,
            "stale": True,
        }

    ev = source_evidence or {}
    raw_path = ev.get("file_path") if ev.get("file_path") is not None else candidate.get("file_path")
    line_start = ev.get("line_start") if ev.get("line_start") is not None else candidate.get("line_start")
    line_end = ev.get("line_end") if ev.get("line_end") is not None else candidate.get("line_end")
    symbol = ev.get("symbol") if ev.get("symbol") is not None else candidate.get("symbol")

    ok_loc, code_loc, norm_or_msg = validate_raw_evidence_location(raw_path, line_start, line_end)
    if not ok_loc:
        status = "FABRICATED_REFERENCE" if code_loc in ("MISSING_FILE_PATH", "INVALID_LINE_START", "INVALID_LINE_END", "INVALID_LINE_RANGE") else "FAILED"
        return {
            "passed": False,
            "status": status,
            "code": code_loc,
            "reason": norm_or_msg,
            "fabricated_reference": status == "FABRICATED_REFERENCE",
            "stale": False,
        }
    norm_path = norm_or_msg

    try:
        resolved_repo = repo_path.resolve()
        unr_target = resolved_repo / norm_path
        if _is_link_or_junction_within_repo(resolved_repo, unr_target):
            return {
                "passed": False,
                "status": "FAILED",
                "code": "SYMLINK_FORBIDDEN",
                "reason": f"Evidence target '{norm_path}' traverses or points to a symlink or junction.",
                "fabricated_reference": False,
                "stale": False,
            }
        target = unr_target.resolve()
        target.relative_to(resolved_repo)
    except (OSError, ValueError):
        return {
            "passed": False,
            "status": "FAILED",
            "code": "PATH_OUTSIDE_REPO",
            "reason": f"Resolved path '{norm_path}' escapes repository root.",
            "fabricated_reference": False,
            "stale": False,
        }

    if _is_link_or_junction_within_repo(resolved_repo, target):
        return {
            "passed": False,
            "status": "FAILED",
            "code": "SYMLINK_FORBIDDEN",
            "reason": f"Evidence target '{norm_path}' is a symlink or junction.",
            "fabricated_reference": False,
            "stale": False,
        }

    snap_hashes: dict[str, str] = snapshot_info.get("file_hashes", {})
    snap_idx, snap_collision = _build_canonical_hash_index(snap_hashes)
    if snap_collision:
        return {
            "passed": False,
            "status": "INVALID",
            "code": "AMBIGUOUS_CASE_COLLISION",
            "reason": snap_collision,
            "fabricated_reference": False,
            "stale": False,
        }
    norm_ckey = canonical_repo_path_key(norm_path)

    if not target.is_file():
        if norm_path in snap_hashes or norm_ckey in snap_idx:
            return {
                "passed": False,
                "status": "STALE",
                "code": "STALE_FILE_MISSING",
                "reason": f"File '{norm_path}' existed at snapshot time but no longer exists.",
                "fabricated_reference": False,
                "stale": True,
            }
        return {
            "passed": False,
            "status": "FABRICATED_REFERENCE",
            "code": "FILE_NOT_FOUND",
            "reason": f"Referenced file '{norm_path}' does not exist in repository.",
            "fabricated_reference": True,
            "stale": False,
        }

    try:
        current_file_sha256 = stream_file_sha256(target)
        raw_bytes = target.read_bytes()
    except (OSError, RuntimeError) as read_exc:
        return {
            "passed": False,
            "status": "STALE",
            "code": "UNREADABLE_SOURCE_FILE",
            "reason": f"Failed to read or stream-hash '{norm_path}': {read_exc}",
            "fabricated_reference": False,
            "stale": True,
        }

    snap_entry = snap_idx.get(norm_ckey)
    expected_file_sha256 = (
        snap_hashes.get(norm_path)
        or (snap_entry[1] if snap_entry else None)
        or candidate.get("file_sha256")
    )

    if expected_file_sha256 and current_file_sha256 != expected_file_sha256:
        return {
            "passed": False,
            "status": "STALE",
            "code": "STALE_FILE_HASH",
            "reason": (
                f"File '{norm_path}' changed between snapshot and verification "
                f"({expected_file_sha256[:10]} != {current_file_sha256[:10]})."
            ),
            "fabricated_reference": False,
            "stale": True,
        }

    if ev.get("file_sha256") and str(ev["file_sha256"]).strip() != current_file_sha256:
        return {
            "passed": False,
            "status": "FAILED",
            "code": "MISMATCHED_EVIDENCE_FILE_SHA256",
            "reason": f"Verifier file_sha256 for '{norm_path}' does not match snapshot file hash.",
            "fabricated_reference": True,
            "stale": False,
        }

    if reviewed_file_hashes:
        rev_idx, rev_collision = _build_canonical_hash_index(
            {str(k): str(v) for k, v in reviewed_file_hashes.items() if k is not None and v is not None}
        )
        if rev_collision:
            return {
                "passed": False,
                "status": "INVALID",
                "code": "AMBIGUOUS_CASE_COLLISION",
                "reason": rev_collision,
                "fabricated_reference": False,
                "stale": False,
            }
        rev_expected = reviewed_file_hashes.get(norm_path) or (rev_idx[norm_ckey][1] if norm_ckey in rev_idx else None)
        if rev_expected is not None and str(rev_expected).strip() != current_file_sha256:
            return {
                "passed": False,
                "status": "FAILED",
                "code": "MISMATCHED_REVIEWED_FILE_HASH",
                "reason": f"reviewed_file_hashes['{norm_path}'] does not match snapshot file hash.",
                "fabricated_reference": True,
                "stale": False,
            }

    file_text = raw_bytes.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    lines = file_text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    total_lines = len(lines)

    if int(line_start) > total_lines or int(line_end) > total_lines:
        return {
            "passed": False,
            "status": "FABRICATED_REFERENCE",
            "code": "LINE_RANGE_OUT_OF_BOUNDS",
            "reason": (
                f"Line range {line_start}..{line_end} exceeds total lines ({total_lines}) in '{norm_path}'."
            ),
            "fabricated_reference": True,
            "stale": False,
        }

    excerpt_lines = lines[int(line_start) - 1 : int(line_end)]
    excerpt_text = "\n".join(excerpt_lines)
    if not excerpt_text.strip():
        return {
            "passed": False,
            "status": "FAILED",
            "code": "EMPTY_SOURCE_LINE_RANGE",
            "reason": f"Line range {line_start}..{line_end} in '{norm_path}' contains only whitespace.",
            "fabricated_reference": True,
            "stale": False,
        }

    actual_excerpt_sha256 = compute_excerpt_sha256(excerpt_text)

    # Check candidate snapshot excerpt hash if line range is unchanged
    cand_line_start = candidate.get("line_start")
    cand_line_end = candidate.get("line_end")
    cand_ev_sha = candidate.get("evidence_sha256")
    if (
        cand_ev_sha
        and cand_line_start == line_start
        and cand_line_end == line_end
        and canonical_repo_path_key(candidate.get("file_path")) == norm_ckey
    ):
        if cand_ev_sha != actual_excerpt_sha256:
            return {
                "passed": False,
                "status": "STALE",
                "code": "EXCERPT_HASH_DRIFT",
                "reason": f"Source excerpt hash at {norm_path}:{line_start}-{line_end} drifted from snapshot.",
                "fabricated_reference": False,
                "stale": True,
            }

    # CRIT-03: Require non-empty evidence excerpt in source_evidence (never accept hash-only evidence or JSON fallback flags)
    raw_ev_excerpt = ev.get("excerpt") if "excerpt" in ev else ev.get("evidence_excerpt")
    if not _allow_candidate_excerpt_fallback:
        if not isinstance(raw_ev_excerpt, str) or not raw_ev_excerpt.strip():
            return {
                "passed": False,
                "status": "INVALID",
                "code": "MISSING_EVIDENCE_EXCERPT",
                "reason": "Confirmed finding requires a non-empty excerpt in source_evidence (hash-only evidence without excerpt text is forbidden).",
                "fabricated_reference": True,
                "stale": False,
            }
        effective_excerpt = raw_ev_excerpt.replace("\r\n", "\n").replace("\r", "\n")
    else:
        if isinstance(raw_ev_excerpt, str) and raw_ev_excerpt.strip():
            effective_excerpt = raw_ev_excerpt.replace("\r\n", "\n").replace("\r", "\n")
        else:
            cand_ev = candidate.get("evidence")
            effective_excerpt = str(cand_ev).replace("\r\n", "\n").replace("\r", "\n") if isinstance(cand_ev, str) else ""

    # If verifier supplied an explicit excerpt_sha256 / evidence_sha256, verify it matches actual source excerpt hash
    supplied_excerpt_sha = ev.get("excerpt_sha256") or ev.get("evidence_sha256")
    if supplied_excerpt_sha:
        clean_supplied_sha = str(supplied_excerpt_sha).strip()
        effective_excerpt_sha = compute_excerpt_sha256(effective_excerpt) if effective_excerpt.strip() else ""
        if clean_supplied_sha not in (actual_excerpt_sha256, effective_excerpt_sha):
            return {
                "passed": False,
                "status": "FABRICATED_REFERENCE",
                "code": "MISMATCHED_EXCERPT_SHA256",
                "reason": (
                    f"Supplied excerpt_sha256 does not match actual source lines at "
                    f"{norm_path}:{line_start}-{line_end}."
                ),
                "fabricated_reference": True,
                "stale": False,
            }

    if (not _allow_candidate_excerpt_fallback) or (("excerpt" in ev or "evidence_excerpt" in ev) and effective_excerpt.strip()):
        norm_supplied = " ".join(effective_excerpt.strip().split())
        norm_window = " ".join(excerpt_text.split())
        if int(line_end) - int(line_start) + 1 > MAX_EVIDENCE_LINE_SPAN:
            return {
                "passed": False,
                "status": "INVALID",
                "code": "EVIDENCE_RANGE_TOO_WIDE",
                "reason": (
                    f"Line range {line_start}..{line_end} spans more than {MAX_EVIDENCE_LINE_SPAN} lines; "
                    "cite the specific lines that show the defect."
                ),
                "fabricated_reference": False,
                "stale": False,
            }
        window_lines = [" ".join(ln.split()) for ln in excerpt_text.split(chr(10))]
        quotes_full_line = any(len(wl) >= 3 and wl in norm_supplied for wl in window_lines)
        if (
            norm_supplied
            and len(norm_supplied) < min(len(norm_window), MIN_EVIDENCE_EXCERPT_CHARS)
            and not quotes_full_line
        ):
            # A trivial token ("return") is contained in almost any range and proves nothing; a short quote must
            # at least be a complete source line.
            return {
                "passed": False,
                "status": "INVALID",
                "code": "EXCERPT_TOO_SHORT",
                "reason": (
                    f"Quoted excerpt is shorter than {MIN_EVIDENCE_EXCERPT_CHARS} characters; quote the source "
                    f"lines at {norm_path}:{line_start}-{line_end} that show the defect."
                ),
                "fabricated_reference": False,
                "stale": False,
            }
        if not norm_supplied or norm_supplied not in norm_window:
            return {
                "passed": False,
                "status": "FABRICATED_REFERENCE",
                "code": "FABRICATED_CODE_EXCERPT",
                "reason": (
                    f"Quoted excerpt in source_evidence was not found within line range "
                    f"{line_start}..{line_end} of '{norm_path}'."
                ),
                "fabricated_reference": True,
                "stale": False,
            }

    # Check symbol plausibility and scoped AST/code presence in line_start..line_end when symbol is specified
    if symbol is not None and str(symbol).strip():
        sym_clean = str(symbol).strip()
        if not SYMBOL_PATTERN.match(sym_clean):
            return {
                "passed": False,
                "status": "FABRICATED_REFERENCE",
                "code": "MALFORMED_SYMBOL",
                "reason": f"Symbol '{sym_clean}' is not a valid structural identifier.",
                "fabricated_reference": True,
                "stale": False,
            }
        sym_ok, sym_code, sym_reason = _verify_symbol_in_range(
            file_text=file_text,
            lines=lines,
            norm_path=norm_path,
            sym_clean=sym_clean,
            line_start=int(line_start),
            line_end=int(line_end),
        )
        if not sym_ok:
            if sym_code.startswith("UNVERIFIABLE_"):
                return {
                    "passed": False,
                    "status": "UNVERIFIABLE",
                    "code": sym_code,
                    "reason": sym_reason,
                    "fabricated_reference": False,
                    "stale": False,
                }
            return {
                "passed": False,
                "status": "FABRICATED_REFERENCE",
                "code": sym_code,
                "reason": sym_reason,
                "fabricated_reference": True,
                "stale": False,
            }

    return {
        "passed": True,
        "status": "PASSED",
        "code": "OK",
        "reason": "All 10 deterministic source evidence checks passed.",
        "fabricated_reference": False,
        "stale": False,
        "metadata": {
            "file_path": norm_path,
            "line_start": int(line_start),
            "line_end": int(line_end),
            "symbol": str(symbol).strip() if symbol else None,
            "file_sha256": current_file_sha256,
            "evidence_sha256": actual_excerpt_sha256,
            "snapshot_id": str(snapshot_info["snapshot_id"]),
            "base_commit_sha": str(snapshot_info["base_commit_sha"]),
        },
    }


def _verify_symbol_in_range(
    *,
    file_text: str,
    lines: list[str],
    norm_path: str,
    sym_clean: str,
    line_start: int,
    line_end: int,
) -> tuple[bool, str, str]:
    leaf_symbol = [p for p in re.split(r"[.:<>-]+", sym_clean) if p][-1]
    token_re = re.compile(rf"\b{re.escape(leaf_symbol)}\b")
    ext = Path(norm_path).suffix.lower()

    if ext == ".py":
        try:
            tree = ast.parse(file_text)
        except SyntaxError as syn_exc:
            return (
                False,
                "UNVERIFIABLE_PYTHON_SYNTAX",
                f"Python file '{norm_path}' has a syntax error ({syn_exc.msg}) and cannot be AST-validated for symbol '{sym_clean}'.",
            )
        found_in_ast_anywhere = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name == leaf_symbol:
                    found_in_ast_anywhere = True
                    n_start = int(getattr(node, "lineno", line_start))
                    n_end = int(getattr(node, "end_lineno", None) or n_start)
                    if n_start <= line_end and n_end >= line_start:
                        return True, "OK", ""
            elif isinstance(node, ast.Name) and node.id == leaf_symbol:
                found_in_ast_anywhere = True
                n_line = int(getattr(node, "lineno", 0))
                if line_start <= n_line <= line_end:
                    return True, "OK", ""
            elif isinstance(node, ast.Attribute) and node.attr == leaf_symbol:
                found_in_ast_anywhere = True
                n_line = int(getattr(node, "lineno", 0))
                if line_start <= n_line <= line_end:
                    return True, "OK", ""
            elif isinstance(node, ast.arg) and node.arg == leaf_symbol:
                found_in_ast_anywhere = True
                n_line = int(getattr(node, "lineno", 0))
                if line_start <= n_line <= line_end:
                    return True, "OK", ""
            elif isinstance(node, ast.alias) and (node.name == leaf_symbol or node.asname == leaf_symbol):
                found_in_ast_anywhere = True
                n_line = int(getattr(node, "lineno", 0))
                if line_start <= n_line <= line_end:
                    return True, "OK", ""
        if found_in_ast_anywhere:
            return (
                False,
                "SYMBOL_OUTSIDE_LINE_RANGE",
                f"Referenced symbol '{sym_clean}' exists in '{norm_path}' but does not overlap line range {line_start}..{line_end}.",
            )
        return (
            False,
            "SYMBOL_NOT_FOUND_IN_FILE",
            f"Referenced symbol '{sym_clean}' was not found as a code symbol in '{norm_path}'.",
        )

    if ext not in SUPPORTED_C_FAMILY_EXTS and ext not in SUPPORTED_HASH_FAMILY_EXTS:
        return (
            False,
            "UNVERIFIABLE_SYMBOL_UNSUPPORTED_LANGUAGE",
            (
                f"Symbol validation for extension '{ext or '<none>'}' in '{norm_path}' is unsupported; "
                f"cannot deterministically verify symbol '{sym_clean}'."
            ),
        )

    try:
        stripped_lines = _strip_comments_and_strings_per_line(file_text, ext)
    except UnverifiableEvidenceError as uee:
        return (
            False,
            uee.code,
            f"Evidence in '{norm_path}' cannot be deterministically verified: {uee.message}",
        )
    while len(stripped_lines) < len(lines):
        stripped_lines.append("")

    code_lines_in_window = [stripped_lines[idx] for idx in range(line_start - 1, line_end)]
    if any(token_re.search(cl) for cl in code_lines_in_window):
        return True, "OK", ""

    # Check if an enclosing function/class/type definition above line_start spans line_start..line_end
    leaf = re.escape(leaf_symbol)
    def_patterns = [
        # keyword definitions: function f / func f / fn f / def f / class C / struct S / interface I / impl T
        re.compile(rf"\b(?:function|func|fn|def|class|struct|interface|impl|enum|trait|record)\s+{leaf}\b"),
        # Go receiver methods: func (s *Server) Handle(
        re.compile(rf"\bfunc\s*\([^)]*\)\s*{leaf}\s*\("),
        # JS/TS function values: const f = (...) => / const f = async function / f: function
        re.compile(rf"\b(?:const|let|var)\s+{leaf}\s*(?::[^=]+)?=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|[\w$]+\s*=>)"),
        re.compile(rf"(?:^|[\s,{{]){leaf}\s*:\s*(?:async\s*)?function\b"),
        # Method signatures (Java/C#/C++/JS/TS classes): [modifiers/return type] Name(params) [{] -- not a call statement
        re.compile(rf"^\s*(?:[\w<>\[\],.?*&:]+\s+)*{leaf}\s*(?:<[^>]*>)?\s*\([^;]*$"),
    ]

    def _is_definition(code_line: str) -> bool:
        return any(rx.search(code_line) for rx in def_patterns)

    for idx in range(line_start - 1, -1, -1):
        code_part = stripped_lines[idx]
        if _is_definition(code_part):
            if ext in SUPPORTED_C_FAMILY_EXTS or ext == ".ps1":
                brace_depth = 0
                saw_open = False
                closed_before_target = False
                for inner_idx in range(idx, line_start):
                    for ch in stripped_lines[inner_idx]:
                        if ch == "{":
                            brace_depth += 1
                            saw_open = True
                        elif ch == "}":
                            brace_depth -= 1
                    if saw_open and brace_depth <= 0 and inner_idx < line_start - 1:
                        closed_before_target = True
                        break
                if saw_open and not closed_before_target and brace_depth > 0:
                    return True, "OK", ""
            else:
                def_indent = len(lines[idx]) - len(lines[idx].lstrip())
                encloses = True
                for inner_idx in range(idx + 1, line_start):
                    stripped_inner = stripped_lines[inner_idx].strip()
                    if not stripped_inner:
                        continue
                    inner_indent = len(lines[inner_idx]) - len(lines[inner_idx].lstrip())
                    if inner_indent <= def_indent:
                        encloses = False
                        break
                if encloses:
                    return True, "OK", ""
            break

    if any(token_re.search(cl) for cl in stripped_lines):
        return (
            False,
            "SYMBOL_OUTSIDE_LINE_RANGE",
            f"Referenced symbol '{sym_clean}' exists in '{norm_path}' but does not overlap line range {line_start}..{line_end}.",
        )
    return (
        False,
        "SYMBOL_NOT_FOUND_IN_FILE",
        f"Referenced symbol '{sym_clean}' was not found as a code symbol in '{norm_path}'.",
    )


def normalize_path_str(file_path: str | None) -> str:
    if not file_path:
        return ""
    cleaned = file_path.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def compute_source_excerpt_sha_for_candidate(repo_path: Path | None, item: dict[str, Any]) -> str:
    """Compute source excerpt SHA-256 at candidate ingestion time if file and line range are valid."""
    if repo_path and item.get("file_path") and item.get("line_start") and item.get("line_end"):
        ok, _, norm = validate_raw_evidence_location(
            item.get("file_path"),
            item.get("line_start"),
            item.get("line_end"),
        )
        if ok:
            try:
                resolved_repo = repo_path.resolve()
                target = (resolved_repo / norm).resolve()
                target.relative_to(resolved_repo)
                if target.is_file() and not _is_link_or_junction(target):
                    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
                    ls = int(item["line_start"])
                    le = int(item["line_end"])
                    if 1 <= ls <= le <= len(lines):
                        excerpt = "\n".join(lines[ls - 1 : le])
                        if excerpt.strip():
                            return compute_excerpt_sha256(excerpt)
            except (OSError, ValueError):
                pass
    parts = [
        normalize_path_str(item.get("file_path")),
        str(item.get("symbol") or "").strip(),
        str(item.get("line_start") or ""),
        str(item.get("line_end") or ""),
        " ".join(str(item.get("evidence") or "").split()),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


PROHIBITIVE_REMEDIATION_PREFIX_RE = re.compile(
    r"\b("
    r"do\s+not|don't|never|avoid|forbid|forbidden|prohibit|prohibited|"
    r"remove|replace|eliminate|prevent|disallow|without|instead\s+of|"
    r"stop\s+using|refrain\s+from|asla|sakın|kullanma|kullanmayın|kaldır|yasakla|kaçın"
    r")\b",
    re.IGNORECASE,
)
PROHIBITIVE_REMEDIATION_SUFFIX_RE = re.compile(
    r"\b("
    r"is\s+forbidden|must\s+not\s+be\s+used|should\s+not\s+be\s+used|"
    r"kullanma|kullanmayın|yasaktır|kaldırılmalı|kullanılmamalı"
    r")\b",
    re.IGNORECASE,
)


def _is_prohibitive_clause(text: str, match_start: int, match_end: int) -> bool:
    clause_delims = [m.start() for m in re.finditer(r"[.;!\n]|(?:\b(?:but|however|instead)\b)", text, re.IGNORECASE)]
    clause_start = 0
    clause_end = len(text)
    for pos in clause_delims:
        if pos < match_start:
            clause_start = pos + 1
        elif pos >= match_end:
            clause_end = pos
            break
    prefix = text[clause_start:match_start]
    suffix = text[match_end:clause_end]
    return bool(
        PROHIBITIVE_REMEDIATION_PREFIX_RE.search(prefix)
        or PROHIBITIVE_REMEDIATION_SUFFIX_RE.search(suffix)
    )


def is_remediation_safe(recommendation: str, remediation_review: str, explicit_safe_flag: bool | None = None) -> tuple[bool, str]:
    """Evaluate whether the proposed remediation or verifier review indicates regression/danger."""
    if explicit_safe_flag is False:
        return False, "Verifier explicitly marked remediation_safe=False."
    rec_text = recommendation or ""
    for pat in DANGEROUS_REMEDIATION_PATTERNS:
        for m in pat.finditer(rec_text):
            if not _is_prohibitive_clause(rec_text, m.start(), m.end()):
                return False, f"Dangerous remediation pattern detected in recommendation: '{m.group(0)}'"
    for pat in UNSAFE_REVIEW_MARKERS:
        if pat.search(remediation_review or ""):
            return False, "Verifier remediation_review flagged regression or unsafe remediation."
    return True, "Remediation review passed safety checks."


def _compute_finding_fingerprint_local(project_key: str, item: dict[str, Any]) -> str:
    raw_fp = str(item.get("fingerprint") or "").strip()
    if raw_fp and len(raw_fp) >= 8:
        normalized_fp = " ".join(raw_fp.lower().split())
        if re.match(r"^[0-9a-f]{16,64}$", normalized_fp):
            return normalized_fp[:32]
        return hashlib.sha256(f"{project_key}:{normalized_fp}".encode("utf-8")).hexdigest()[:32]

    category = " ".join(str(item.get("category") or "").strip().upper().split())
    norm_path = normalize_path_str(item.get("file_path")).lower()
    symbol = " ".join(str(item.get("symbol") or "").strip().lower().split())
    title = " ".join(str(item.get("title") or "").strip().lower().split())
    seed = f"{project_key}|{category}|{norm_path}|{symbol}|{title}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def _compute_canonical_finding_id(project_key: str, fingerprint: str) -> str:
    digest = hashlib.sha256(f"{project_key}:{fingerprint}".encode("utf-8")).hexdigest()[:12]
    return f"F-{project_key}-{digest}"


def verify_cross_model_independence(
    primary_model: str | None,
    verifier_model: str | None,
    verifier_attestation_status: str | None,
    db_path: Path | None = None,
) -> tuple[bool, str]:
    """Verify that primary auditor and verifier models are distinct, approved, and runtime-attested.

    Invariants:
    1. Primary model must be approved and non-empty.
    2. Verifier model must be approved and non-empty.
    3. Primary and verifier models must be distinct model lines (differing reasoning levels of one
       line, e.g. Hydrogen High vs Hydrogen Medium, do NOT qualify).
    4. Verifier model must have runtime attestation status 'RUNTIME_ATTESTED'.
    """
    from model_registry import same_model_line, was_ever_approved_model

    p_clean = (primary_model or "").strip().lower()
    v_clean = (verifier_model or "").strip().lower()
    att_clean = (verifier_attestation_status or "").strip().upper()

    if not p_clean:
        return False, "Primary audit model is missing or unrecorded."
    if not v_clean:
        return False, "Verifier model is missing or unrecorded."
    # Judged against every table that was ever approved (seed, active, superseded): approving a new table
    # must not retroactively invalidate an audit whose models were approved when it ran.
    if not was_ever_approved_model(p_clean, db_path=db_path):
        return False, f"Primary model '{primary_model}' is not an approved model."
    if not was_ever_approved_model(v_clean, db_path=db_path):
        return False, f"Verifier model '{verifier_model}' is not an approved model."
    if p_clean == v_clean:
        return False, f"Model independence failed: Primary and verifier models are identical ('{p_clean}'). Differing reasoning levels or prompts do not satisfy cross-model independence."
    if same_model_line(p_clean, v_clean):
        return False, f"Model independence failed: '{p_clean}' and '{v_clean}' are reasoning levels of the same model line. Differing reasoning levels do not satisfy cross-model independence."
    if att_clean != "RUNTIME_ATTESTED":
        return False, f"Model attestation failed: Verifier model '{verifier_model}' attestation status is '{att_clean}' (must be 'RUNTIME_ATTESTED'). Self-reported or unverified models are rejected."

    return True, f"Cross-model independence verified: Primary '{p_clean}' vs Verifier '{v_clean}' (RUNTIME_ATTESTED)."


def derive_verification_trust(run_row: Any, vrun_row: Any) -> dict[str, Any]:
    """Derive verification trust status conservatively without trusting self-reported model metadata."""
    primary_conv = str(run_row["agent_conversation_id"] or "").strip() if run_row else ""
    verifier_conv = str(vrun_row["verifier_conversation_id"] or "").strip() if vrun_row else ""
    conv_independent = bool(
        verifier_conv
        and is_valid_conversation_id(verifier_conv)
        and (not primary_conv or primary_conv != verifier_conv)
    )
    vrun_keys = vrun_row.keys() if (vrun_row is not None and hasattr(vrun_row, "keys")) else ()
    run_keys = run_row.keys() if (run_row is not None and hasattr(run_row, "keys")) else ()

    primary_model = str(run_row["primary_model"] or "").strip() if (run_row and "primary_model" in run_keys and run_row["primary_model"]) else ""
    verifier_model = str(vrun_row["verifier_model_id"] or "").strip() if (vrun_row and "verifier_model_id" in vrun_keys and vrun_row["verifier_model_id"]) else ""
    attest_status = str(vrun_row["verifier_attestation_status"] or "").strip() if (vrun_row and "verifier_attestation_status" in vrun_keys and vrun_row["verifier_attestation_status"]) else ""
    model_source = (
        str(vrun_row["verifier_model_source"] or "UNVERIFIED")
        if ("verifier_model_source" in vrun_keys and vrun_row["verifier_model_source"])
        else "UNVERIFIED"
    )

    is_cross_ok, _ = verify_cross_model_independence(primary_model, verifier_model, attest_status)
    if is_cross_ok:
        model_ind_status = "CROSS_MODEL_INDEPENDENT"
        trust_mode = "INDEPENDENT_CONVERSATION_AND_MODEL_VERIFIED"
    elif conv_independent and primary_model and verifier_model and primary_model.lower() == verifier_model.lower():
        model_ind_status = "SAME_MODEL_DISTINCT_CONVERSATION"
        trust_mode = "INDEPENDENT_CONVERSATION_VERIFIED (SAME_MODEL)"
    elif conv_independent:
        model_ind_status = "MODEL_INDEPENDENCE_UNVERIFIED"
        trust_mode = "INDEPENDENT_CONVERSATION_VERIFIED (MODEL_INDEPENDENCE_UNVERIFIED)"
    else:
        model_ind_status = "UNVERIFIED"
        trust_mode = "UNVERIFIED"

    return {
        "conversation_independence_verified": conv_independent,
        "model_independence_verified": is_cross_ok,
        "model_independence_status": model_ind_status,
        "primary_model_id": primary_model or None,
        "verifier_model_id": verifier_model or None,
        "verifier_model_source": model_source,
        "verifier_attestation_status": attest_status or "MODEL_ATTESTATION_INCOMPLETE",
        "verification_trust_mode": trust_mode,
    }


def _select_candidates_for_verification_run(
    conn: sqlite3.Connection,
    audit_run_id: str,
    verification_run_id: str,
) -> list[sqlite3.Row]:
    """Select the exact unverified candidates belonging to the target verification run."""
    if verification_run_id.endswith("-DISC"):
        return conn.execute(
            """SELECT * FROM candidate_findings
               WHERE run_id=? AND source_origin='VERIFIER_DISCOVERED'
                 AND status != 'ARCHIVED' AND canonical_finding_id IS NULL
               ORDER BY candidate_finding_id""",
            (audit_run_id,),
        ).fetchall()

    primary_unpromoted = conn.execute(
        """SELECT * FROM candidate_findings
           WHERE run_id=? AND source_origin='PRIMARY'
             AND status != 'ARCHIVED'
             AND (canonical_finding_id IS NULL AND status != 'REJECTED')
           ORDER BY candidate_finding_id""",
        (audit_run_id,),
    ).fetchall()
    if primary_unpromoted:
        return primary_unpromoted

    disc_unpromoted = conn.execute(
        """SELECT * FROM candidate_findings
           WHERE run_id=? AND source_origin='VERIFIER_DISCOVERED'
             AND status != 'ARCHIVED' AND canonical_finding_id IS NULL
           ORDER BY candidate_finding_id""",
        (audit_run_id,),
    ).fetchall()
    if disc_unpromoted:
        return disc_unpromoted

    return conn.execute(
        """SELECT * FROM candidate_findings
           WHERE run_id=? AND source_origin='PRIMARY' AND status != 'ARCHIVED'
           ORDER BY candidate_finding_id""",
        (audit_run_id,),
    ).fetchall()


def _format_verification_prompt(
    *,
    project_key: str,
    display_name: str,
    repo_path: str,
    audit_run_id: str,
    vrun_id: str,
    snapshot_id: str,
    base_commit_sha: str,
    claims_block: list[dict[str, Any]],
    package_root: Path | None = None,
    trusted_skill_name: str = "independent-audit-verifier",
) -> str:
    """Pure formatting logic for second-pass verification prompt."""
    from skills import format_trusted_skill_section, load_trusted_skill_content

    # Trusted control-plane skill loading (fails closed if missing, invalid, or oversized)
    trusted_skill_content = load_trusted_skill_content(
        trusted_skill_name,
        package_root=package_root,
    )
    injected_skill_section = format_trusted_skill_section(
        trusted_skill_name,
        trusted_skill_content,
    )

    prompt = f"""You are executing a MANDATORY INDEPENDENT SECOND-PASS AUDIT VERIFICATION in a separate Antigravity conversation.

PROJECT IDENTITY & SNAPSHOT:
- Project Key: {project_key}
- Project Name: {display_name}
- Repository Path: {repo_path}
- Audit Run ID: {audit_run_id}
- Verification Run ID: {vrun_id}
- Snapshot ID: {snapshot_id}
- Base Commit SHA: {base_commit_sha}

=== WORKSPACE BOUNDARY & TOOL SEPARATION RULES ===
1. TRUSTED VERIFIER PROTOCOL: The operational protocol below is loaded by the trusted control plane. It is authoritative. Do NOT attempt to read external skill files or files in the Auditor installation directory.
2. UNTRUSTED AUDITED REPOSITORY: Inspect source files ONLY within the monitored repository path `{repo_path}`. Use supported read-only file inspection tools (`read_file`).
3. MCP DATA EXCHANGE: Use registered MCP tools (`auditor_get_verification_context`, `auditor_submit_verification`) to query verification context and submit verdicts.
4. PLAN MODE READ-ONLY: You are operating in `--mode plan`. Do NOT attempt to run shell or terminal commands.
5. NO REPOSITORY MUTATIONS: Do NOT modify, create, format, or delete any source files. Do NOT write files into the audited repository.

{injected_skill_section}

INDEPENDENCE & SAFETY CONSTRAINTS (MANDATORY):
- You are an independent verifier. You have NOT been given the primary auditor's chain-of-thought, severity, or confidence ratings.
- Do NOT modify, create, format, or delete any source files. Remain strictly READ-ONLY.
- Do NOT inspect `.env`, private keys, credentials, or excluded secret files.
- Never invent a source-code quotation.
- Never report a function or class without verifying its existence.
- Never use stale line numbers without snapshot verification.
- Never mark a finding CONFIRMED from a theoretical argument alone.
- Never claim tests passed unless the actual test command completed successfully.
- Never claim multiple specialist agents were used unless they were actually invoked.
- Never accept a remediation suggestion without reviewing its possible regressions.

VERIFICATION PROTOCOL FOR EACH CANDIDATE:
1. Call MCP tool `auditor_get_verification_context` with `audit_run_id="{audit_run_id}"` and `verification_run_id="{vrun_id}"`.
2. Independently inspect the actual source code in `{repo_path}` for each candidate below using `read_file`.
3. For each candidate:
   - Attempt to falsify the claim against the real implementation.
   - Verify the exact execution path, callers, and dependencies.
   - Verify the exact file path, line range (`line_start`..`line_end`), symbol, and source excerpt.
   - Independently assign `verified_severity` (`CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`) and `verified_confidence` (`CONFIRMED` | `LIKELY` | `SPECULATIVE`).
   - Review whether `unverified_remediation_proposal_to_review` would introduce regressions (`remediation_review`, `remediation_safe`).
   - Define concrete test `acceptance_criteria`.
   - Assign exactly one `verdict`:
     * `CONFIRMED` — Claim and execution path are verified in actual source code with exact evidence.
     * `PARTIALLY_CONFIRMED` — Core issue exists but scope/claim needs correction; you MUST provide a clear `corrected_claim`.
     * `REJECTED` — Claim is falsified, hallucinated, unreachable, or already mitigated.
     * `UNVERIFIABLE` — Cannot be verified from the repository snapshot (blocks finalization until resolved).

CANDIDATE CLAIMS TO VERIFY ({len(claims_block)} candidate(s)):
{json.dumps(claims_block, ensure_ascii=False, indent=2)}

REQUIRED SUBMISSION CONTRACT:
Do NOT write files into the target repository. Do NOT invoke shell commands.
To submit verdicts for ALL candidates, invoke the MCP tool `auditor_submit_verification` with:
- audit_run_id: "{audit_run_id}"
- verification_run_id: "{vrun_id}"
- verifier_conversation_id: "<YOUR_CONVERSATION_ID>"
- verifier_metadata: {{"verifier_model_id": "<YOUR_EXACT_MODEL_ID, e.g. gemini-4-argon-medium>", "invocation_mechanism": "cli"}}
- verification_results: JSON array of verification result items. Each item must include:
  candidate_finding_id (string), verdict ("CONFIRMED" | "PARTIALLY_CONFIRMED" | "REJECTED" | "UNVERIFIABLE"),
  verified_severity ("CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"),
  verified_confidence ("CONFIRMED" | "LIKELY" | "SPECULATIVE"),
  technical_rationale (string),
  source_evidence: object with file_path (string), line_start (integer), line_end (integer), symbol (string or null), excerpt (string or null),
  remediation_review (string),
  acceptance_criteria (string).
Deterministic finalization and persistence will be executed by the Auditor control plane after submission.
"""
    return prompt


def build_verification_prompt_broker(
    broker_client: BrokerClient,
    *,
    audit_run_id: str,
    verification_run_id: str | None = None,
    app_home: Path | None = None,
    package_root: Path | None = None,
    trusted_skill_name: str = "independent-audit-verifier",
) -> str:
    """Build verification prompt exclusively via Broker IPC. Zero direct SQLite calls, zero SQLite fallback."""
    if not verification_run_id:
        st = broker_client.get_verification_status(audit_run_id=audit_run_id)
        vrun_id = str(st["verification_run_id"])
    else:
        vrun_id = verification_run_id

    v_ctx = broker_client.get_verification_context(audit_run_id=audit_run_id, verification_run_id=vrun_id)
    project_ctx = v_ctx["project_context"]
    snap_meta = v_ctx["snapshot_metadata"]
    loc_by_id = {loc["candidate_finding_id"]: loc for loc in v_ctx.get("relevant_source_locations", [])}

    claims_block: list[dict[str, Any]] = []
    for c in v_ctx.get("candidate_claims", []):
        cid = c["candidate_finding_id"]
        loc = loc_by_id.get(cid, {})
        claims_block.append({
            "candidate_finding_id": cid,
            "fingerprint": c["fingerprint"],
            "title": c["title"],
            "category": c["category"],
            "technical_claim_to_falsify_or_verify": f"{c['technical_claim']} | Claimed impact: {c['claimed_impact']}",
            "affected_file": c["file_path"],
            "affected_symbol": c["symbol"],
            "line_start": c["line_start"],
            "line_end": c["line_end"],
            "file_sha256": loc.get("file_sha256"),
            "unverified_remediation_proposal_to_review": c["unverified_remediation_proposal"],
        })

    return _format_verification_prompt(
        project_key=str(project_ctx["project_key"]),
        display_name=str(project_ctx["display_name"]),
        repo_path=str(v_ctx["repository_path"]),
        audit_run_id=audit_run_id,
        vrun_id=vrun_id,
        snapshot_id=str(snap_meta["snapshot_id"]),
        base_commit_sha=str(snap_meta["base_commit_sha"]),
        claims_block=claims_block,
        package_root=package_root,
        trusted_skill_name=trusted_skill_name,
    )


def build_verification_prompt(
    db_path: Path | None = None,
    *,
    audit_run_id: str,
    verification_run_id: str | None = None,
    app_home: Path | None = None,
    package_root: Path | None = None,
    trusted_skill_name: str = "independent-audit-verifier",
    broker_client: BrokerClient | None = None,
) -> str:
    """Build a context-independent second-pass verification prompt with injected trusted protocol.

    When `broker_client` is provided, routes exclusively through Broker IPC with zero direct SQLite access.
    """
    if broker_client is not None:
        return build_verification_prompt_broker(
            broker_client,
            audit_run_id=audit_run_id,
            verification_run_id=verification_run_id,
            app_home=app_home,
            package_root=package_root,
            trusted_skill_name=trusted_skill_name,
        )

    if db_path is None:
        raise ValueError("Either db_path or broker_client must be provided to build_verification_prompt.")

    from db import connect

    with connect(db_path) as conn:
        run = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (audit_run_id,)).fetchone()
        if not run:
            raise RuntimeError(f"Audit run '{audit_run_id}' not found.")
        project_key = str(run["project_key"])
        proj = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchone()
        if not proj:
            raise RuntimeError(f"Project '{project_key}' not found.")
        if verification_run_id:
            vrun = conn.execute(
                "SELECT * FROM audit_verification_runs WHERE verification_run_id=? AND audit_run_id=?",
                (verification_run_id, audit_run_id),
            ).fetchone()
        else:
            vrun = conn.execute(
                "SELECT * FROM audit_verification_runs WHERE audit_run_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (audit_run_id,),
            ).fetchone()
        if not vrun:
            raise RuntimeError(f"Verification run not found for audit_run_id '{audit_run_id}'.")
        vrun_id = str(vrun["verification_run_id"])
        snap = conn.execute("SELECT * FROM audit_snapshots WHERE run_id=?", (audit_run_id,)).fetchone()
        candidates = _select_candidates_for_verification_run(conn, audit_run_id, vrun_id)

    claims_block: list[dict[str, Any]] = []
    for c in candidates:
        claims_block.append({
            "candidate_finding_id": c["candidate_finding_id"],
            "fingerprint": c["fingerprint"],
            "title": c["title"],
            "category": c["category"],
            "technical_claim_to_falsify_or_verify": f"{c['evidence']} | Claimed impact: {c['impact']}",
            "affected_file": c["file_path"],
            "affected_symbol": c["symbol"],
            "line_start": c["line_start"],
            "line_end": c["line_end"],
            "file_sha256": c["file_sha256"],
            "unverified_remediation_proposal_to_review": c["recommendation"],
        })

    return _format_verification_prompt(
        project_key=project_key,
        display_name=str(proj["display_name"]),
        repo_path=str(proj["repo_path"]),
        audit_run_id=audit_run_id,
        vrun_id=vrun_id,
        snapshot_id=str(snap["snapshot_id"] if snap else vrun["snapshot_id"]),
        base_commit_sha=str(snap["base_commit_sha"] if snap else vrun["base_commit_sha"]),
        claims_block=claims_block,
        package_root=package_root,
        trusted_skill_name=trusted_skill_name,
    )


def get_verification_context_broker(
    broker_client: BrokerClient,
    *,
    audit_run_id: str,
    verification_run_id: str,
) -> dict[str, Any]:
    """Return context-independent verification payload exclusively via Broker IPC. Zero direct SQLite calls."""
    return broker_client.get_verification_context(
        audit_run_id=audit_run_id,
        verification_run_id=verification_run_id,
    )


def get_verification_context(
    db_path: Path | None = None,
    *,
    audit_run_id: str,
    verification_run_id: str,
    broker_client: BrokerClient | None = None,
) -> dict[str, Any]:
    """Return context-independent verification payload for MCP `auditor_get_verification_context`.

    When `broker_client` is provided, routes exclusively through Broker IPC with zero direct SQLite access.
    """
    if broker_client is not None:
        return get_verification_context_broker(
            broker_client,
            audit_run_id=audit_run_id,
            verification_run_id=verification_run_id,
        )

    if db_path is None:
        raise ValueError("Either db_path or broker_client must be provided to get_verification_context.")

    from db import connect
    from telemetry import redact_value

    with connect(db_path) as conn:
        run = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (audit_run_id,)).fetchone()
        if not run:
            raise RuntimeError(f"Unknown audit_run_id: {audit_run_id}")
        vrun = conn.execute(
            "SELECT * FROM audit_verification_runs WHERE verification_run_id=? AND audit_run_id=?",
            (verification_run_id, audit_run_id),
        ).fetchone()
        if not vrun:
            raise RuntimeError(
                f"Unknown verification_run_id '{verification_run_id}' for audit_run_id '{audit_run_id}'."
            )
        project_key = str(run["project_key"])
        proj = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchone()
        if not proj:
            raise RuntimeError(f"Unknown project: {project_key}")
        snap = conn.execute("SELECT * FROM audit_snapshots WHERE run_id=?", (audit_run_id,)).fetchone()
        candidates = _select_candidates_for_verification_run(conn, audit_run_id, verification_run_id)

        fingerprints = [str(c["fingerprint"]) for c in candidates]
        history_rows: list[dict[str, Any]] = []
        if fingerprints:
            placeholders = ",".join("?" for _ in fingerprints)
            h_rows = conn.execute(
                f"""SELECT fh.finding_id, fh.run_id, fh.from_lifecycle, fh.to_lifecycle,
                           fh.actor, fh.reason, fh.created_at, f.fingerprint
                    FROM finding_history fh
                    JOIN findings f ON f.finding_id = fh.finding_id
                    WHERE fh.project_key=? AND f.fingerprint IN ({placeholders})
                    ORDER BY fh.history_id DESC LIMIT 50""",
                [project_key, *fingerprints],
            ).fetchall()
            history_rows = [dict(r) for r in h_rows]

    candidate_claims: list[dict[str, Any]] = []
    finding_ids: list[str] = []
    source_locations: list[dict[str, Any]] = []

    for c in candidates:
        cid = str(c["candidate_finding_id"])
        finding_ids.append(cid)
        # Note: Do NOT expose primary severity or confidence as authoritative conclusions
        candidate_claims.append({
            "candidate_finding_id": cid,
            "fingerprint": str(c["fingerprint"]),
            "title": str(c["title"]),
            "category": str(c["category"]),
            "technical_claim": str(c["evidence"]),
            "claimed_impact": str(c["impact"]),
            "file_path": c["file_path"],
            "symbol": c["symbol"],
            "line_start": c["line_start"],
            "line_end": c["line_end"],
            "unverified_remediation_proposal": str(c["recommendation"]),
            "source_origin": str(c["source_origin"]),
        })
        source_locations.append({
            "candidate_finding_id": cid,
            "file_path": c["file_path"],
            "symbol": c["symbol"],
            "line_start": c["line_start"],
            "line_end": c["line_end"],
            "file_sha256": c["file_sha256"],
            "evidence_sha256": c["evidence_sha256"],
        })

    snapshot_metadata = {
        "snapshot_id": str(snap["snapshot_id"]) if snap else str(vrun["snapshot_id"]),
        "base_commit_sha": str(snap["base_commit_sha"]) if snap else str(vrun["base_commit_sha"]),
        "working_tree_hash": str(snap["working_tree_hash"]) if snap else str(run["working_tree_hash"] or ""),
        "created_at": str(snap["created_at"]) if snap else str(vrun["created_at"]),
    }

    payload = {
        "audit_run_id": audit_run_id,
        "verification_run_id": verification_run_id,
        "project_context": {
            "project_key": project_key,
            "display_name": str(proj["display_name"]),
            "health_status": str(proj["health_status"]),
        },
        "repository_path": str(proj["repo_path"]),
        "snapshot_metadata": snapshot_metadata,
        "candidate_claims": candidate_claims,
        "finding_ids": finding_ids,
        "relevant_source_locations": source_locations,
        "allowed_audit_operations": [
            "read_file",
            "search_codebase",
            "inspect_git_diff_read_only",
            "auditor_get_verification_context",
            "auditor_submit_verification",
            "auditor_get_verification_status",
            "auditor_finalize_verified_report",
        ],
        "previous_finding_history": redact_value(history_rows),
    }
    return payload


def submit_verification_results(
    db_path: Path,
    *,
    audit_run_id: str,
    verification_run_id: str,
    verifier_conversation_id: str,
    verifier_metadata: dict[str, Any] | None = None,
    verification_results: list[dict[str, Any]],
    verifier_discovered_findings: list[dict[str, Any]] | None = None,
    jsonl_path: Path | None = None,
) -> dict[str, Any]:
    """Validate and record second-pass verification results (`auditor_submit_verification`)."""
    from db import compute_file_blob_hash, connect, record_event, validate_finding_item

    if not is_valid_conversation_id(verifier_conversation_id):
        raise ValueError(f"Invalid verifier_conversation_id: '{verifier_conversation_id}'")
    clean_conv_id = verifier_conversation_id.strip()

    if not isinstance(verification_results, list):
        raise ValueError("verification_results must be a list.")

    meta = verifier_metadata or {}
    if not isinstance(meta, dict):
        raise ValueError("verifier_metadata must be a JSON object.")

    # Check for duplicate candidate_finding_id entries in payload
    seen_ids: set[str] = set()
    for idx, res in enumerate(verification_results):
        if not isinstance(res, dict):
            raise ValueError(f"verification_results[{idx}] must be an object.")
        cid = str(res.get("candidate_finding_id") or "").strip()
        if not cid:
            raise ValueError(f"verification_results[{idx}] is missing candidate_finding_id.")
        if cid in seen_ids:
            raise ValueError(f"Duplicate verification result submitted for candidate_finding_id '{cid}'.")
        seen_ids.add(cid)

    with connect(db_path) as conn:
        run = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (audit_run_id,)).fetchone()
        if not run:
            raise RuntimeError(f"Audit run '{audit_run_id}' not found.")
        if run["status"] in ("VERIFICATION_STALE", "STALE", "FAILED", "ARCHIVED", "COMPLETED"):
            raise RuntimeError(
                f"Cannot submit verification for audit run '{audit_run_id}' in state '{run['status']}'."
            )
        primary_conv_id = str(run["agent_conversation_id"] or "").strip()
        if primary_conv_id and primary_conv_id == clean_conv_id:
            raise RuntimeError(
                "Independence violation: verifier_conversation_id must be a separate conversation from the primary audit conversation."
            )

        vrun = conn.execute(
            "SELECT * FROM audit_verification_runs WHERE verification_run_id=? AND audit_run_id=?",
            (verification_run_id, audit_run_id),
        ).fetchone()
        if not vrun:
            raise RuntimeError(
                f"Verification run '{verification_run_id}' not found for audit run '{audit_run_id}'."
            )
        if vrun["status"] in ("FINALIZED", "COMPLETED", "STALE", "ARCHIVED"):
            raise RuntimeError(
                f"Verification run '{verification_run_id}' is already in terminal/stale state '{vrun['status']}'."
            )

        existing_sub_count = int(
            conn.execute(
                "SELECT COUNT(*) FROM finding_verification_results WHERE verification_run_id=?",
                (verification_run_id,),
            ).fetchone()[0]
            or 0
        )
        vrun_keys = vrun.keys()
        prior_sub_count = int(vrun["submission_count"] or 0) if "submission_count" in vrun_keys else 0
        if prior_sub_count >= 1 or existing_sub_count > 0:
            raise RuntimeError(
                f"Verification run '{verification_run_id}' has already received a verification submission; "
                "duplicate or overwriting submissions for the same verification_run_id are forbidden."
            )
        if vrun["status"] == "FAILED":
            raise RuntimeError(
                f"Verification run '{verification_run_id}' is already in terminal/stale state '{vrun['status']}'."
            )

        recorded_v_conv = str(vrun["verifier_conversation_id"] or "").strip()
        if recorded_v_conv and recorded_v_conv != clean_conv_id:
            raise RuntimeError(
                f"Verifier conversation mismatch for '{verification_run_id}': "
                f"expected '{recorded_v_conv}', got '{clean_conv_id}'."
            )

        project_key = str(run["project_key"])
        proj = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchone()
        repo_path = Path(proj["repo_path"]) if proj and proj["repo_path"] else None

        # Handle any verifier-discovered candidate findings first (audit_snapshots remains strictly immutable)
        discovered_items = verifier_discovered_findings or []
        if discovered_items:
            prior_disc_count = int(
                conn.execute(
                    """SELECT COUNT(*) FROM candidate_findings
                       WHERE run_id=? AND source_origin='VERIFIER_DISCOVERED'
                         AND COALESCE(discovered_in_verification_run_id, '') != ?""",
                    (audit_run_id, verification_run_id),
                ).fetchone()[0]
                or 0
            )
            if verification_run_id.endswith("-DISC") or prior_disc_count > 0:
                raise ValueError(
                    "Follow-up verification runs ('-DISC') cannot submit additional verifier_discovered_findings; "
                    "recursive follow-up discovery chains are forbidden."
                )

        for d_idx, raw_disc in enumerate(discovered_items):
            disc = validate_finding_item(raw_disc, d_idx)
            if not disc.get("file_path") or disc.get("line_start") is None or disc.get("line_end") is None:
                raise ValueError(
                    f"verifier_discovered_findings[{d_idx}] is missing required evidence location (file_path, line_start, line_end)."
                )
            ok_loc, _, norm_p = validate_raw_evidence_location(
                disc["file_path"], disc["line_start"], disc["line_end"]
            )
            if not ok_loc:
                raise ValueError(f"verifier_discovered_findings[{d_idx}] has malformed location: {norm_p}")
            fp = _compute_finding_fingerprint_local(project_key, disc)
            disc_cid = disc["finding_id"]
            cand_pk = f"CAND-{audit_run_id}-{disc_cid}"
            f_sha = compute_file_blob_hash(repo_path, norm_p)
            ev_sha = compute_source_excerpt_sha_for_candidate(repo_path, disc)

            conn.execute(
                """INSERT OR IGNORE INTO candidate_findings(
                    candidate_id, candidate_finding_id, run_id, project_key,
                    snapshot_id, base_commit_sha, fingerprint, title, category,
                    severity, confidence, file_path, symbol, line_start, line_end,
                    evidence, impact, recommendation, file_sha256, evidence_sha256,
                    source_origin, discovered_by_conversation_id, discovered_in_verification_run_id, status
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'VERIFIER_DISCOVERED',?,?,'CANDIDATE')""",
                (
                    cand_pk,
                    disc_cid,
                    audit_run_id,
                    project_key,
                    vrun["snapshot_id"],
                    vrun["base_commit_sha"],
                    fp,
                    disc["title"],
                    disc["category"],
                    disc["severity"],
                    disc["confidence"],
                    norm_p,
                    disc["symbol"],
                    disc["line_start"],
                    disc["line_end"],
                    disc["evidence"],
                    disc["impact"],
                    disc["recommendation"],
                    f_sha,
                    ev_sha,
                    clean_conv_id,
                    verification_run_id,
                ),
            )

        known_candidates = {
            str(r["candidate_finding_id"]): dict(r)
            for r in conn.execute(
                "SELECT * FROM candidate_findings WHERE run_id=?",
                (audit_run_id,),
            ).fetchall()
        }

        # Validate all submitted candidate_finding_ids exist in known_candidates
        for idx, res in enumerate(verification_results):
            cid = str(res["candidate_finding_id"]).strip()
            if cid not in known_candidates:
                raise ValueError(
                    f"Unknown candidate_finding_id '{cid}' at index {idx} for audit_run_id '{audit_run_id}'."
                )
            cand_meta = known_candidates[cid]
            if (
                str(cand_meta.get("source_origin") or "") == "VERIFIER_DISCOVERED"
                and str(cand_meta.get("discovered_in_verification_run_id") or "") not in ("", verification_run_id)
                and str(cand_meta.get("discovered_by_conversation_id") or "").strip() == clean_conv_id
            ):
                raise RuntimeError(
                    f"Independence violation: verifier_conversation_id '{clean_conv_id}' discovered candidate '{cid}' "
                    "and cannot act as its own second-pass verifier."
                )
            verdict = str(res.get("verdict") or "").strip().upper()
            if verdict not in ALLOWED_VERDICTS:
                raise ValueError(f"Invalid verdict '{verdict}' for candidate '{cid}'.")
            sev = str(res.get("verified_severity") or "").strip().upper()
            if sev not in ALLOWED_SEVERITIES:
                raise ValueError(f"Invalid verified_severity '{sev}' for candidate '{cid}'.")
            conf = str(res.get("verified_confidence") or "").strip().upper()
            if conf not in ALLOWED_CONFIDENCES:
                raise ValueError(f"Invalid verified_confidence '{conf}' for candidate '{cid}'.")

            for req_str in ("technical_rationale", "remediation_review", "acceptance_criteria"):
                if not str(res.get(req_str) or "").strip():
                    raise ValueError(f"Missing or empty '{req_str}' for candidate '{cid}'.")

            corrected_claim = str(res.get("corrected_claim") or "").strip() or None
            if verdict == "PARTIALLY_CONFIRMED" and not corrected_claim:
                raise ValueError(
                    f"Candidate '{cid}' has verdict PARTIALLY_CONFIRMED and requires a non-empty 'corrected_claim'."
                )

            src_ev = res.get("source_evidence")
            if not isinstance(src_ev, dict):
                raise ValueError(f"Missing required 'source_evidence' object for candidate '{cid}'.")
            ok_ev, code_ev, norm_or_err = validate_raw_evidence_location(
                src_ev.get("file_path"),
                src_ev.get("line_start"),
                src_ev.get("line_end"),
            )
            if not ok_ev:
                raise ValueError(
                    f"Malformed source_evidence for candidate '{cid}' ({code_ev}): {norm_or_err}"
                )

            reviewed_hashes = res.get("reviewed_file_hashes") or {}
            if not isinstance(reviewed_hashes, dict):
                raise ValueError(f"reviewed_file_hashes for '{cid}' must be an object.")

            rem_safe_bool, _ = is_remediation_safe(
                cand_meta["recommendation"],
                str(res["remediation_review"]),
                res.get("remediation_safe"),
            )

            conn.execute(
                """INSERT INTO finding_verification_results(
                    candidate_finding_id, verification_run_id, audit_run_id,
                    verdict, verified_severity, verified_confidence,
                    technical_rationale, corrected_claim, source_evidence_json,
                    remediation_review, remediation_safe, acceptance_criteria,
                    evidence_validation_status, reviewed_file_hashes_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'PENDING',?)""",
                (
                    cid,
                    verification_run_id,
                    audit_run_id,
                    verdict,
                    sev,
                    conf,
                    str(res["technical_rationale"]).strip(),
                    corrected_claim,
                    json.dumps(src_ev, ensure_ascii=False, sort_keys=True),
                    str(res["remediation_review"]).strip(),
                    1 if rem_safe_bool else 0,
                    str(res["acceptance_criteria"]).strip(),
                    json.dumps(reviewed_hashes, ensure_ascii=False, sort_keys=True),
                ),
            )
            is_self_discovered_in_same_run = (
                str(cand_meta.get("source_origin") or "") == "VERIFIER_DISCOVERED"
                and (
                    str(cand_meta.get("discovered_in_verification_run_id") or "") == verification_run_id
                    or str(cand_meta.get("discovered_by_conversation_id") or "").strip() == clean_conv_id
                )
            )
            if not is_self_discovered_in_same_run:
                conn.execute(
                    "UPDATE candidate_findings SET status=?, updated_at=CURRENT_TIMESTAMP WHERE run_id=? AND candidate_finding_id=?",
                    (verdict, audit_run_id, cid),
                )

        # Update audit_verification_runs metadata (never invent model_id or agent_id; never trust caller-supplied model_id as runtime-verified)
        vrun_keys_set = set(vrun.keys())
        existing_model_source = (
            str(vrun["verifier_model_source"] or "UNVERIFIED")
            if "verifier_model_source" in vrun_keys_set
            else "UNVERIFIED"
        )
        if existing_model_source == "RUNTIME_ATTESTED" and vrun["verifier_model_id"]:
            v_model = str(vrun["verifier_model_id"]).strip()
            v_model_source = "RUNTIME_ATTESTED"
        elif meta.get("verifier_model_id"):
            v_model = str(meta["verifier_model_id"]).strip()
            v_model_source = "CALLER_CLAIMED_UNVERIFIED"
        else:
            v_model = vrun["verifier_model_id"]
            v_model_source = existing_model_source
        v_agent = str(meta["verifier_agent_id"]).strip() if meta.get("verifier_agent_id") else vrun["verifier_agent_id"]
        inv_mech = str(meta.get("invocation_mechanism") or vrun["invocation_mechanism"] or "mcp_direct").strip()
        subagents = int(meta.get("actual_subagent_invocations") or vrun["subagent_invocations"] or 0)

        conn.execute(
            """UPDATE audit_verification_runs
               SET status='RUNNING',
                   verifier_conversation_id=?,
                   verifier_model_id=?,
                   verifier_model_source=?,
                   verifier_agent_id=?,
                   invocation_mechanism=?,
                   subagent_invocations=?,
                   submission_count=COALESCE(submission_count, 0) + 1,
                   submitted_at=CURRENT_TIMESTAMP,
                   started_at=COALESCE(started_at, CURRENT_TIMESTAMP)
               WHERE verification_run_id=?""",
            (clean_conv_id, v_model, v_model_source, v_agent, inv_mech, subagents, verification_run_id),
        )
        conn.execute(
            """UPDATE verification_dispatch_queue
               SET status='RUNNING', verifier_conversation_id=?, updated_at=CURRENT_TIMESTAMP
               WHERE verification_run_id=? AND status NOT IN ('COMPLETED')""",
            (clean_conv_id, verification_run_id),
        )
        if str(run["status"]) != "READY_FOR_REVIEW":
            transition_audit_run_status(conn, audit_run_id, "VERIFICATION_RUNNING")

        submitted_ids = {
            str(r["candidate_finding_id"])
            for r in conn.execute(
                "SELECT candidate_finding_id FROM finding_verification_results WHERE verification_run_id=?",
                (verification_run_id,),
            ).fetchall()
        }
        required_candidate_ids = {
            cid
            for cid, cmeta in known_candidates.items()
            if str(cmeta.get("status") or "") != "ARCHIVED"
            and not (
                str(cmeta.get("source_origin") or "") == "VERIFIER_DISCOVERED"
                and str(cmeta.get("discovered_in_verification_run_id") or "") == verification_run_id
            )
            and not (
                cmeta.get("canonical_finding_id")
                and str(cmeta.get("status") or "") in ("CONFIRMED", "PARTIALLY_CONFIRMED", "REJECTED")
                and cid not in submitted_ids
            )
        }
        unresolved_ids = sorted(required_candidate_ids - submitted_ids)

        record_event(
            conn,
            "VERIFICATION_RESULTS_SUBMITTED",
            project_key=project_key,
            run_id=audit_run_id,
            details={
                "verification_run_id": verification_run_id,
                "verifier_conversation_id": clean_conv_id,
                "submitted_count": len(verification_results),
                "total_candidates": len(known_candidates),
                "unresolved_candidate_ids": unresolved_ids,
            },
            jsonl_path=jsonl_path,
        )
        conn.commit()

    return {
        "audit_run_id": audit_run_id,
        "verification_run_id": verification_run_id,
        "verifier_conversation_id": clean_conv_id,
        "status": "VERIFICATION_RUNNING",
        "submitted_count": len(verification_results),
        "total_candidates": len(known_candidates),
        "unresolved_candidate_ids": unresolved_ids,
        "all_candidates_resolved": len(unresolved_ids) == 0,
    }


def get_verification_status_broker(
    broker_client: BrokerClient,
    *,
    audit_run_id: str,
    verification_run_id: str | None = None,
) -> dict[str, Any]:
    """Return full verification status and counts exclusively via Broker IPC. Zero direct SQLite calls."""
    return broker_client.get_verification_status(
        audit_run_id=audit_run_id,
        verification_run_id=verification_run_id,
    )


def get_verification_status(
    db_path: Path | None = None,
    *,
    audit_run_id: str,
    verification_run_id: str | None = None,
    broker_client: BrokerClient | None = None,
) -> dict[str, Any]:
    """Return full verification status and counts (`auditor_get_verification_status`).

    When `broker_client` is provided, routes exclusively through Broker IPC with zero direct SQLite access.
    """
    if broker_client is not None:
        return get_verification_status_broker(
            broker_client,
            audit_run_id=audit_run_id,
            verification_run_id=verification_run_id,
        )

    if db_path is None:
        raise ValueError("Either db_path or broker_client must be provided to get_verification_status.")

    from db import connect

    with connect(db_path) as conn:
        run = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (audit_run_id,)).fetchone()
        if not run:
            raise RuntimeError(f"Unknown audit_run_id: {audit_run_id}")
        if verification_run_id:
            vrun = conn.execute(
                "SELECT * FROM audit_verification_runs WHERE verification_run_id=? AND audit_run_id=?",
                (verification_run_id, audit_run_id),
            ).fetchone()
        else:
            vrun = conn.execute(
                "SELECT * FROM audit_verification_runs WHERE audit_run_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (audit_run_id,),
            ).fetchone()
        if not vrun:
            raise RuntimeError(f"No verification run found for audit_run_id: {audit_run_id}")

        vrun_id = str(vrun["verification_run_id"])
        cand_rows = conn.execute(
            "SELECT candidate_finding_id, status, source_origin, canonical_finding_id FROM candidate_findings WHERE run_id=?",
            (audit_run_id,),
        ).fetchall()
        res_rows = conn.execute(
            "SELECT candidate_finding_id, verdict, evidence_validation_status FROM finding_verification_results WHERE verification_run_id=?",
            (vrun_id,),
        ).fetchall()
        q_row = conn.execute(
            "SELECT * FROM verification_dispatch_queue WHERE verification_run_id=?",
            (vrun_id,),
        ).fetchone()
        pending_vruns = conn.execute(
            """SELECT verification_run_id, status FROM audit_verification_runs
               WHERE audit_run_id=? AND status NOT IN ('FINALIZED', 'COMPLETED', 'ARCHIVED')
               ORDER BY created_at DESC, rowid DESC""",
            (audit_run_id,),
        ).fetchall()
        m_row = conn.execute(
            "SELECT * FROM audit_quality_metrics WHERE audit_run_id=?",
            (audit_run_id,),
        ).fetchone()

    candidate_count = len(cand_rows)
    verdict_counts = {
        "CONFIRMED": 0,
        "PARTIALLY_CONFIRMED": 0,
        "REJECTED": 0,
        "UNVERIFIABLE": 0,
    }
    ev_statuses: set[str] = set()
    resolved_ids: set[str] = set()

    for r in res_rows:
        resolved_ids.add(str(r["candidate_finding_id"]))
        v = str(r["verdict"])
        if v in verdict_counts:
            verdict_counts[v] += 1
        ev_statuses.add(str(r["evidence_validation_status"]))

    pending_discovered_ids = [
        str(c["candidate_finding_id"])
        for c in cand_rows
        if str(c["source_origin"] or "") == "VERIFIER_DISCOVERED"
        and str(c["status"] or "") == "CANDIDATE"
        and not c["canonical_finding_id"]
    ]
    pending_followup_vrun_id = str(pending_vruns[0]["verification_run_id"]) if pending_vruns else None
    followup_pending = bool(
        pending_discovered_ids
        or (pending_followup_vrun_id and pending_followup_vrun_id != vrun_id)
    )

    unverified_cand_count = sum(
        1
        for c in cand_rows
        if str(c["status"] or "") not in ("ARCHIVED", "REJECTED")
        and not c["canonical_finding_id"]
        and str(c["candidate_finding_id"]) not in resolved_ids
    )
    # Count unresolved candidates, not "all candidates of the run minus results of this verification run":
    # a follow-up (-DISC) run only resolves the discovered candidates.
    unresolved_count = max(
        0,
        unverified_cand_count,
        len(pending_discovered_ids),
    )
    if not res_rows and candidate_count > 0:
        overall_ev_status = "PENDING"
    elif "FABRICATED_REFERENCE" in ev_statuses:
        overall_ev_status = "FABRICATED_REFERENCE"
    elif "FAILED" in ev_statuses or "INVALID" in ev_statuses:
        overall_ev_status = "FAILED"
    elif "UNVERIFIABLE" in ev_statuses:
        overall_ev_status = "UNVERIFIABLE"
    elif "STALE" in ev_statuses or run["status"] == "VERIFICATION_STALE":
        overall_ev_status = "STALE"
    elif "PENDING" in ev_statuses or unresolved_count > 0 or followup_pending:
        overall_ev_status = "PENDING"
    else:
        overall_ev_status = "PASSED"

    dispatch_info = {
        "job_id": str(q_row["job_id"]) if q_row else None,
        "queue_status": str(q_row["status"]) if q_row else None,
        "dispatch_attempt": int(q_row["attempt_count"]) if q_row else int(vrun["dispatch_attempt"] or 0),
        "max_attempts": int(q_row["max_attempts"]) if q_row else 3,
        "lease_owner": q_row["lease_owner"] if q_row else None,
        "lease_expires_at": q_row["lease_expires_at"] if q_row else None,
        "verifier_conversation_id": vrun["verifier_conversation_id"],
        "last_error_code": (q_row["last_error_code"] if q_row and q_row["last_error_code"] else vrun["error_code"]),
        "last_error_message": (q_row["last_error_message"] if q_row and q_row["last_error_message"] else vrun["error_message"]),
    }

    return {
        "audit_run_id": audit_run_id,
        "verification_run_id": vrun_id,
        "audit_status": str(run["status"]),
        "verification_lifecycle_state": str(vrun["status"]),
        "candidate_count": candidate_count,
        "confirmed_count": verdict_counts["CONFIRMED"],
        "partially_confirmed_count": verdict_counts["PARTIALLY_CONFIRMED"],
        "rejected_count": verdict_counts["REJECTED"],
        "unverifiable_count": verdict_counts["UNVERIFIABLE"],
        "unresolved_count": unresolved_count,
        "followup_verification_pending": followup_pending,
        "pending_followup_verification_run_id": pending_followup_vrun_id,
        "pending_discovered_candidate_ids": pending_discovered_ids,
        "evidence_validation_status": overall_ev_status,
        "verification_trust": derive_verification_trust(run, vrun),
        "dispatch_info": dispatch_info,
        "quality_metrics": dict(m_row) if m_row else None,
    }


def _persist_quality_metrics(
    conn: sqlite3.Connection,
    *,
    project_key: str,
    audit_run_id: str,
    verification_run_id: str,
    verifier_model_id: str | None,
    total_primary_candidates: int,
    verifier_discovered_candidates: int,
    confirmed_findings: int,
    partially_confirmed_findings: int,
    rejected_findings: int,
    unverifiable_findings: int,
    evidence_validation_failures: int,
    fabricated_reference_detections: int,
    severity_changes: int,
    confidence_changes: int,
    remediation_proposals_rejected: int,
    dispatch_failures: int,
    verification_duration_seconds: float | None,
    actual_subagent_invocations: int,
    primary_model_id: str | None = None,
    cross_model_verified: int = 0,
    model_attestation_status: str | None = None,
) -> dict[str, Any]:
    total_evaluated = confirmed_findings + partially_confirmed_findings + rejected_findings + unverifiable_findings
    total_all = max(1, total_primary_candidates + verifier_discovered_candidates)
    non_rejected = max(1, confirmed_findings + partially_confirmed_findings)

    finding_precision = (
        round((confirmed_findings + 0.5 * partially_confirmed_findings) / total_evaluated, 4)
        if total_evaluated > 0
        else 1.0
    )
    evidence_accuracy = (
        round(max(0.0, (total_all - evidence_validation_failures) / total_all), 4)
        if (total_primary_candidates + verifier_discovered_candidates) > 0
        else 1.0
    )
    false_positive_rate = (
        round(rejected_findings / total_evaluated, 4)
        if total_evaluated > 0
        else 0.0
    )
    severity_calibration_rate = (
        round(max(0.0, (non_rejected - severity_changes) / non_rejected), 4)
        if (confirmed_findings + partially_confirmed_findings) > 0
        else 1.0
    )
    remediation_safety_rate = (
        round(max(0.0, (non_rejected - remediation_proposals_rejected) / non_rejected), 4)
        if (confirmed_findings + partially_confirmed_findings) > 0
        else 1.0
    )

    skill_rows = conn.execute("SELECT sha256 FROM skill_inventory ORDER BY scope, skill_name").fetchall()
    skill_hash = (
        hashlib.sha256("|".join(str(r["sha256"]) for r in skill_rows).encode("utf-8")).hexdigest()[:16]
        if skill_rows
        else None
    )

    conn.execute(
        """INSERT INTO audit_quality_metrics(
            project_key, audit_run_id, verification_run_id,
            primary_model_id, verifier_model_id, skill_version_hash,
            total_primary_candidates, verifier_discovered_candidates,
            confirmed_findings, partially_confirmed_findings,
            rejected_findings, unverifiable_findings,
            evidence_validation_failures, fabricated_reference_detections,
            severity_changes, confidence_changes,
            remediation_proposals_rejected, dispatch_failures,
            verification_duration_seconds, actual_subagent_invocations,
            finding_precision, evidence_accuracy, false_positive_rate,
            severity_calibration_rate, remediation_safety_rate,
            cross_model_verified, model_attestation_status
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(audit_run_id) DO UPDATE SET
            verification_run_id=excluded.verification_run_id,
            primary_model_id=excluded.primary_model_id,
            verifier_model_id=excluded.verifier_model_id,
            cross_model_verified=excluded.cross_model_verified,
            model_attestation_status=excluded.model_attestation_status,
            skill_version_hash=excluded.skill_version_hash,
            total_primary_candidates=excluded.total_primary_candidates,
            verifier_discovered_candidates=excluded.verifier_discovered_candidates,
            confirmed_findings=excluded.confirmed_findings,
            partially_confirmed_findings=excluded.partially_confirmed_findings,
            rejected_findings=excluded.rejected_findings,
            unverifiable_findings=excluded.unverifiable_findings,
            evidence_validation_failures=excluded.evidence_validation_failures,
            fabricated_reference_detections=excluded.fabricated_reference_detections,
            severity_changes=excluded.severity_changes,
            confidence_changes=excluded.confidence_changes,
            remediation_proposals_rejected=excluded.remediation_proposals_rejected,
            dispatch_failures=excluded.dispatch_failures,
            verification_duration_seconds=excluded.verification_duration_seconds,
            actual_subagent_invocations=excluded.actual_subagent_invocations,
            finding_precision=excluded.finding_precision,
            evidence_accuracy=excluded.evidence_accuracy,
            false_positive_rate=excluded.false_positive_rate,
            severity_calibration_rate=excluded.severity_calibration_rate,
            remediation_safety_rate=excluded.remediation_safety_rate,
            updated_at=CURRENT_TIMESTAMP""",
        (
            project_key,
            audit_run_id,
            verification_run_id,
            primary_model_id,
            verifier_model_id,
            skill_hash,
            total_primary_candidates,
            verifier_discovered_candidates,
            confirmed_findings,
            partially_confirmed_findings,
            rejected_findings,
            unverifiable_findings,
            evidence_validation_failures,
            fabricated_reference_detections,
            severity_changes,
            confidence_changes,
            remediation_proposals_rejected,
            dispatch_failures,
            verification_duration_seconds,
            actual_subagent_invocations,
            finding_precision,
            evidence_accuracy,
            false_positive_rate,
            severity_calibration_rate,
            remediation_safety_rate,
            int(cross_model_verified),
            model_attestation_status,
        ),
    )
    row = conn.execute("SELECT * FROM audit_quality_metrics WHERE audit_run_id=?", (audit_run_id,)).fetchone()
    return dict(row) if row else {}


def finalize_verified_report(
    db_path: Path,
    *,
    audit_run_id: str,
    verification_run_id: str,
    jsonl_path: Path | None = None,
    require_cross_model: bool = False,
) -> dict[str, Any]:
    """Enforce deterministic evidence and verification gates and promote canonical findings in one transaction."""
    from db import (
        _parse_timestamp,
        compute_evidence_hash,
        compute_file_blob_hash,
        connect,
        record_event,
    )
    from review import generate_review_report

    with connect(db_path) as conn:
        run = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (audit_run_id,)).fetchone()
        if not run:
            raise RuntimeError(f"Audit run '{audit_run_id}' not found.")
        if run["status"] in ("VERIFICATION_STALE", "STALE"):
            raise RuntimeError(f"Cannot finalize stale audit run '{audit_run_id}' (status={run['status']}).")
        if run["status"] in ("FAILED", "ARCHIVED"):
            raise RuntimeError(f"Cannot finalize failed/archived audit run '{audit_run_id}' (status={run['status']}).")

        vrun = conn.execute(
            "SELECT * FROM audit_verification_runs WHERE verification_run_id=? AND audit_run_id=?",
            (verification_run_id, audit_run_id),
        ).fetchone()
        if not vrun:
            raise RuntimeError(
                f"Verification run '{verification_run_id}' not found for audit run '{audit_run_id}'."
            )

        conv_id = str(vrun["verifier_conversation_id"] or "").strip()
        if not is_valid_conversation_id(conv_id):
            raise RuntimeError(
                "Cannot finalize verified report: valid verifier_conversation_id metadata is missing."
            )
        if run["agent_conversation_id"] and str(run["agent_conversation_id"]).strip() == conv_id:
            raise RuntimeError(
                "Cannot finalize verified report: verifier_conversation_id must differ from primary audit conversation."
            )

        project_key = str(run["project_key"])
        proj = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchone()
        if not proj:
            raise RuntimeError(f"Project '{project_key}' not found.")
        repo_path = Path(proj["repo_path"])

        # Transition to EVIDENCE_VALIDATION while running deterministic gates
        if run["status"] != "READY_FOR_REVIEW":
            transition_audit_run_status(conn, audit_run_id, "EVIDENCE_VALIDATION")
            conn.execute(
                "UPDATE audit_verification_runs SET status='EVIDENCE_VALIDATION' WHERE verification_run_id=?",
                (verification_run_id,),
            )

        candidates = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM candidate_findings WHERE run_id=? ORDER BY candidate_finding_id",
                (audit_run_id,),
            ).fetchall()
        ]
        results_by_id = {
            str(r["candidate_finding_id"]): dict(r)
            for r in conn.execute(
                "SELECT * FROM finding_verification_results WHERE verification_run_id=?",
                (verification_run_id,),
            ).fetchall()
        }
        q_row = conn.execute(
            "SELECT * FROM verification_dispatch_queue WHERE verification_run_id=?",
            (verification_run_id,),
        ).fetchone()
        dispatch_failures = max(0, int(q_row["attempt_count"] or 1) - 1) if q_row else 0

        # Gate 1: Every required candidate must have a final verification result
        unresolved = [
            str(c["candidate_finding_id"])
            for c in candidates
            if str(c["candidate_finding_id"]) not in results_by_id
            and str(c["status"]) != "ARCHIVED"
            and not (
                str(c.get("source_origin") or "") == "VERIFIER_DISCOVERED"
                and (
                    str(c.get("discovered_in_verification_run_id") or "") == verification_run_id
                    or str(c.get("discovered_by_conversation_id") or "").strip() == conv_id
                )
            )
            and not (
                c.get("canonical_finding_id")
                and str(c.get("status") or "") in ("CONFIRMED", "PARTIALLY_CONFIRMED", "REJECTED")
            )
            and str(c.get("status") or "") != "REJECTED"
        ]
        if unresolved:
            err_msg = f"Unresolved candidate findings lack verification verdicts: {unresolved}"
            transition_audit_run_status(conn, audit_run_id, "VERIFICATION_FAILED", error=err_msg)
            conn.execute(
                "UPDATE audit_verification_runs SET status='FAILED', error_code='INCOMPLETE_VERIFICATION', error_message=? WHERE verification_run_id=?",
                (err_msg, verification_run_id),
            )
            conn.commit()
            raise RuntimeError(err_msg)

        # Gate 2: UNVERIFIABLE findings must block finalization until resolved or archived
        unverifiable = [
            str(c["candidate_finding_id"])
            for c in candidates
            if str(c["status"]) != "ARCHIVED"
            and str(c["candidate_finding_id"]) in results_by_id
            and results_by_id[str(c["candidate_finding_id"])]["verdict"] == "UNVERIFIABLE"
        ]
        if unverifiable:
            err_msg = (
                f"UNVERIFIABLE findings block canonical finalization until resolved or archived: {unverifiable}"
            )
            transition_audit_run_status(conn, audit_run_id, "VERIFICATION_FAILED", error=err_msg)
            conn.execute(
                "UPDATE audit_verification_runs SET status='FAILED', error_code='UNVERIFIABLE_FINDINGS', error_message=? WHERE verification_run_id=?",
                (err_msg, verification_run_id),
            )
            conn.commit()
            raise RuntimeError(err_msg)

        # Gate 3: Snapshot consistency check (HEAD SHA and snapshot files)
        relevant_files: list[str] = []
        for c in candidates:
            if c.get("file_path"):
                relevant_files.append(str(c["file_path"]))
            res = results_by_id.get(str(c["candidate_finding_id"]))
            if res:
                ev_obj = json.loads(str(res["source_evidence_json"] or "{}"))
                if ev_obj.get("file_path"):
                    relevant_files.append(str(ev_obj["file_path"]))

        consistency = verify_snapshot_consistency(
            conn,
            repo_path=repo_path,
            run_id=audit_run_id,
            relevant_files=relevant_files,
        )
        if not consistency["consistent"]:
            stale_msg = f"Audit snapshot is stale ({consistency['code']}): {consistency['reason']}"
            transition_audit_run_status(conn, audit_run_id, "VERIFICATION_STALE", error=stale_msg)
            conn.execute(
                "UPDATE audit_verification_runs SET status='STALE', error_code=?, error_message=? WHERE verification_run_id=?",
                (consistency["code"], stale_msg, verification_run_id),
            )
            conn.execute(
                "UPDATE candidate_findings SET status='STALE', updated_at=CURRENT_TIMESTAMP WHERE run_id=?",
                (audit_run_id,),
            )
            record_event(
                conn,
                "VERIFICATION_MARKED_STALE",
                project_key=project_key,
                run_id=audit_run_id,
                level="WARNING",
                details={"verification_run_id": verification_run_id, **consistency},
                jsonl_path=jsonl_path,
            )
            conn.commit()
            raise RuntimeError(stale_msg)

        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id=?", (audit_run_id,)).fetchone()
        snap_keys = snap_row.keys() if snap_row else ()
        snapshot_info = {
            "snapshot_id": str(snap_row["snapshot_id"]),
            "base_commit_sha": str(snap_row["base_commit_sha"]),
            "working_tree_hash": str(snap_row["working_tree_hash"]),
            "file_hashes": json.loads(str(snap_row["file_hashes_json"] or "{}")),
            "snapshot_complete": (
                bool(int(snap_row["snapshot_complete"]))
                if ("snapshot_complete" in snap_keys and snap_row["snapshot_complete"] is not None)
                else True
            ),
            "incomplete_reason": snap_row["incomplete_reason"] if "incomplete_reason" in snap_keys else None,
        }

        # Gate 4: Deterministic Evidence Verification Gate & Remediation Safety Gate
        primary_candidates_count = sum(1 for c in candidates if c["source_origin"] == "PRIMARY")
        discovered_candidates_count = sum(1 for c in candidates if c["source_origin"] == "VERIFIER_DISCOVERED")
        confirmed_count = 0
        partial_count = 0
        rejected_count = 0
        unverifiable_count = 0
        evidence_failures = 0
        fabricated_detections = 0
        severity_changes = 0
        confidence_changes = 0
        remediation_rejections = 0
        remediation_safety_by_cid: dict[str, tuple[bool, str]] = {}

        gate_failure_error: tuple[str, str, bool] | None = None  # (code, message, is_stale)
        # K3: a confirmed finding whose verifier evidence fails the gate (e.g. a quote that is not in the code) is
        # rejected on its own; the rest of the report survives but the run is marked as an evidence anomaly.
        evidence_rejected: dict[str, dict[str, str]] = {}

        for c in candidates:
            cid = str(c["candidate_finding_id"])
            if str(c["status"]) == "ARCHIVED" or cid not in results_by_id:
                continue
            res = results_by_id[cid]
            verdict = str(res["verdict"])
            ev_obj = json.loads(str(res["source_evidence_json"] or "{}"))
            rev_hashes = json.loads(str(res["reviewed_file_hashes_json"] or "{}"))

            if verdict == "CONFIRMED":
                confirmed_count += 1
            elif verdict == "PARTIALLY_CONFIRMED":
                partial_count += 1
            elif verdict == "REJECTED":
                rejected_count += 1
            elif verdict == "UNVERIFIABLE":
                unverifiable_count += 1

            if verdict in ("CONFIRMED", "PARTIALLY_CONFIRMED"):
                if str(res["verified_severity"]) != str(c["severity"]):
                    severity_changes += 1
                if str(res["verified_confidence"]) != str(c["confidence"]):
                    confidence_changes += 1

            # Check primary candidate for fabricated references even if rejected
            primary_ev_check = validate_single_finding_evidence(
                repo_path=repo_path,
                snapshot_info=snapshot_info,
                candidate=c,
                source_evidence={
                    "file_path": c.get("file_path"),
                    "line_start": c.get("line_start"),
                    "line_end": c.get("line_end"),
                    "symbol": c.get("symbol"),
                },
                _allow_candidate_excerpt_fallback=True,
            )
            ev_check = validate_single_finding_evidence(
                repo_path=repo_path,
                snapshot_info=snapshot_info,
                candidate=c,
                source_evidence=ev_obj,
                reviewed_file_hashes=rev_hashes,
            )

            if primary_ev_check.get("fabricated_reference") or ev_check.get("fabricated_reference"):
                fabricated_detections += 1

            rem_ok, rem_reason = is_remediation_safe(
                str(c["recommendation"]),
                str(res["remediation_review"]),
                bool(res["remediation_safe"]),
            )
            remediation_safety_by_cid[cid] = (rem_ok, rem_reason)
            if not rem_ok:
                remediation_rejections += 1

            if verdict in ("CONFIRMED", "PARTIALLY_CONFIRMED"):
                if not ev_check["passed"]:
                    evidence_failures += 1
                    conn.execute(
                        """UPDATE finding_verification_results
                           SET evidence_validation_status=?, evidence_validation_details_json=?
                           WHERE verification_run_id=? AND candidate_finding_id=?""",
                        (
                            ev_check["status"],
                            json.dumps(ev_check, ensure_ascii=False, sort_keys=True),
                            verification_run_id,
                            cid,
                        ),
                    )
                    if bool(ev_check.get("stale", False)):
                        # the repository changed under the audit: a run-level condition, not one bad finding
                        if gate_failure_error is None:
                            gate_failure_error = (
                                str(ev_check["code"]),
                                f"Deterministic evidence gate failed for '{cid}' ({ev_check['code']}): {ev_check['reason']}",
                                True,
                            )
                    else:
                        if verdict == "CONFIRMED":
                            confirmed_count -= 1
                        else:
                            partial_count -= 1
                        rejected_count += 1
                        if str(res["verified_severity"]) != str(c["severity"]):
                            severity_changes -= 1
                        if str(res["verified_confidence"]) != str(c["confidence"]):
                            confidence_changes -= 1
                        evidence_rejected[cid] = {
                            "code": str(ev_check["code"]),
                            "reason": str(ev_check.get("reason") or "")[:500],
                            "title": str(c.get("title") or ""),
                            "file_path": str(c.get("file_path") or ""),
                        }
                else:
                    conn.execute(
                        """UPDATE finding_verification_results
                           SET evidence_validation_status='PASSED', evidence_validation_details_json=?
                           WHERE verification_run_id=? AND candidate_finding_id=?""",
                        (
                            json.dumps(ev_check, ensure_ascii=False, sort_keys=True),
                            verification_run_id,
                            cid,
                        ),
                    )

            else:
                # REJECTED finding: record evidence status without blocking finalization
                rec_status = "FABRICATED_REFERENCE" if primary_ev_check.get("fabricated_reference") else "PASSED"
                if rec_status == "FABRICATED_REFERENCE":
                    evidence_failures += 1
                conn.execute(
                    """UPDATE finding_verification_results
                       SET evidence_validation_status=?, evidence_validation_details_json=?
                       WHERE verification_run_id=? AND candidate_finding_id=?""",
                    (
                        rec_status,
                        json.dumps(primary_ev_check, ensure_ascii=False, sort_keys=True),
                        verification_run_id,
                        cid,
                    ),
                )

        start_dt = _parse_timestamp(vrun["started_at"]) or _parse_timestamp(vrun["created_at"])
        duration_sec = (
            round(max(0.0, (datetime.now(timezone.utc) - start_dt).total_seconds()), 3)
            if start_dt
            else 0.0
        )

        # Cross-model independence check
        run_keys = set(run.keys()) if hasattr(run, "keys") else set()
        vrun_keys = set(vrun.keys()) if hasattr(vrun, "keys") else set()
        primary_model = (
            str(run["primary_model"]).strip()
            if ("primary_model" in run_keys and run["primary_model"])
            else ""
        )
        verifier_model = (
            str(vrun["verifier_model_id"]).strip()
            if ("verifier_model_id" in vrun_keys and vrun["verifier_model_id"])
            else ""
        )
        verifier_attest = (
            str(vrun["verifier_attestation_status"]).strip()
            if ("verifier_attestation_status" in vrun_keys and vrun["verifier_attestation_status"])
            else ""
        )

        cross_ok, cross_msg = verify_cross_model_independence(
            primary_model, verifier_model, verifier_attest, db_path=db_path
        )

        # Check if any confirmed or partially confirmed finding is CRITICAL
        has_confirmed_critical = False
        for c in candidates:
            cid = str(c["candidate_finding_id"])
            if cid in results_by_id and cid not in evidence_rejected:
                res = results_by_id[cid]
                if res["verdict"] in ("CONFIRMED", "PARTIALLY_CONFIRMED"):
                    if str(res["verified_severity"]).upper() == "CRITICAL" or str(c["severity"]).upper() == "CRITICAL":
                        has_confirmed_critical = True
                        break

        if has_confirmed_critical and not cross_ok:
            err_msg = (
                f"Cannot finalize verified report: Confirmed CRITICAL findings require independent cross-model verification. "
                f"Primary model: '{primary_model or 'UNSPECIFIED'}', Verifier model: '{verifier_model or 'UNSPECIFIED'}', "
                f"Verifier attestation: '{verifier_attest or 'UNATTESTED'}'. Reason: {cross_msg}"
            )
            if require_cross_model:
                transition_audit_run_status(conn, audit_run_id, "VERIFICATION_FAILED", error=err_msg)
                conn.execute(
                    "UPDATE audit_verification_runs SET status='FAILED', error_code='CROSS_MODEL_INDEPENDENCE_REQUIRED', error_message=? WHERE verification_run_id=?",
                    (err_msg, verification_run_id),
                )
                record_event(
                    conn,
                    "CROSS_MODEL_INDEPENDENCE_FAILED",
                    project_key=project_key,
                    run_id=audit_run_id,
                    level="ERROR",
                    details={
                        "verification_run_id": verification_run_id,
                        "primary_model": primary_model,
                        "verifier_model": verifier_model,
                        "attestation_status": verifier_attest,
                        "error_message": err_msg,
                    },
                    jsonl_path=jsonl_path,
                )
                conn.commit()
                raise RuntimeError(err_msg)
            else:
                record_event(
                    conn,
                    "CROSS_MODEL_INDEPENDENCE_UNVERIFIED",
                    project_key=project_key,
                    run_id=audit_run_id,
                    level="WARNING",
                    details={
                        "verification_run_id": verification_run_id,
                        "primary_model": primary_model,
                        "verifier_model": verifier_model,
                        "attestation_status": verifier_attest,
                        "reason": cross_msg,
                    },
                    jsonl_path=jsonl_path,
                )

        metrics = _persist_quality_metrics(
            conn,
            project_key=project_key,
            audit_run_id=audit_run_id,
            verification_run_id=verification_run_id,
            verifier_model_id=vrun["verifier_model_id"],
            total_primary_candidates=primary_candidates_count,
            verifier_discovered_candidates=discovered_candidates_count,
            confirmed_findings=confirmed_count,
            partially_confirmed_findings=partial_count,
            rejected_findings=rejected_count,
            unverifiable_findings=unverifiable_count,
            evidence_validation_failures=evidence_failures,
            fabricated_reference_detections=fabricated_detections,
            severity_changes=severity_changes,
            confidence_changes=confidence_changes,
            remediation_proposals_rejected=remediation_rejections,
            dispatch_failures=dispatch_failures,
            verification_duration_seconds=duration_sec,
            actual_subagent_invocations=int(vrun["subagent_invocations"] or 0),
            primary_model_id=primary_model or None,
            cross_model_verified=1 if cross_ok else 0,
            model_attestation_status=verifier_attest or None,
        )

        if gate_failure_error is not None:
            err_code, err_msg, is_stale = gate_failure_error
            target_audit_state = "VERIFICATION_STALE" if is_stale else "VERIFICATION_FAILED"
            target_vrun_state = "STALE" if is_stale else "FAILED"
            transition_audit_run_status(conn, audit_run_id, target_audit_state, error=err_msg)
            conn.execute(
                "UPDATE audit_verification_runs SET status=?, error_code=?, error_message=?, completed_at=CURRENT_TIMESTAMP WHERE verification_run_id=?",
                (target_vrun_state, err_code, err_msg, verification_run_id),
            )
            # do not leave the queue job looking alive for a run that has failed
            conn.execute(
                """UPDATE verification_dispatch_queue
                   SET status='FAILED', last_error_code=?, last_error_message=?, lease_owner=NULL, lease_token=NULL,
                       lease_expires_at=NULL, updated_at=CURRENT_TIMESTAMP
                   WHERE verification_run_id=? AND status IN ('RUNNING', 'CLAIMED', 'DISPATCHING')""",
                (err_code, err_msg[:500], verification_run_id),
            )
            record_event(
                conn,
                "EVIDENCE_GATE_FAILED",
                project_key=project_key,
                run_id=audit_run_id,
                level="ERROR",
                details={
                    "verification_run_id": verification_run_id,
                    "error_code": err_code,
                    "error_message": err_msg,
                },
                jsonl_path=jsonl_path,
            )
            conn.commit()
            raise RuntimeError(err_msg)

        if evidence_rejected:
            prev_row = conn.execute("SELECT evidence_anomaly_json FROM audit_runs WHERE run_id=?", (audit_run_id,)).fetchone()
            try:
                merged = json.loads(prev_row[0]) if prev_row and prev_row[0] else {}
                merged = merged if isinstance(merged, dict) else {}
            except (TypeError, ValueError):
                merged = {}
            merged.update(evidence_rejected)
            conn.execute(
                "UPDATE audit_runs SET evidence_anomaly_json=? WHERE run_id=?",
                (json.dumps(merged, ensure_ascii=False, sort_keys=True), audit_run_id),
            )
            record_event(
                conn,
                "EVIDENCE_ANOMALY_FINDINGS_REJECTED",
                project_key=project_key,
                run_id=audit_run_id,
                level="WARNING",
                details={"verification_run_id": verification_run_id, "rejected": evidence_rejected},
                jsonl_path=jsonl_path,
            )

        # Gate 5: All checks passed -> Promote canonical findings in one atomic transaction!
        promotion_stats = {
            "total_received": len(candidates),
            "unique_in_run": len(candidates),
            "inserted_open": 0,
            "updated_open": 0,
            "suppressed_dismissed": 0,
            "reopened_dismissed": 0,
            "reopened_regression": 0,
            "preserved_deferred": 0,
            "confirmed_count": confirmed_count,
            "partially_confirmed_count": partial_count,
            "rejected_count": rejected_count,
        }
        canonical_ids: list[str] = []
        pending_discovered_candidate_ids: list[str] = []

        for c in candidates:
            cid = str(c["candidate_finding_id"])
            if str(c["status"]) == "ARCHIVED":
                continue
            is_self_discovered = (
                str(c.get("source_origin") or "") == "VERIFIER_DISCOVERED"
                and (
                    str(c.get("discovered_in_verification_run_id") or "") == verification_run_id
                    or str(c.get("discovered_by_conversation_id") or "").strip() == conv_id
                )
            )
            if is_self_discovered:
                # HIGH-03: Verifier-discovered findings cannot be self-confirmed in the same verification conversation.
                conn.execute(
                    """UPDATE candidate_findings
                       SET status='CANDIDATE', canonical_finding_id=NULL, updated_at=CURRENT_TIMESTAMP
                       WHERE candidate_id=?""",
                    (c["candidate_id"],),
                )
                pending_discovered_candidate_ids.append(cid)
                continue

            if cid not in results_by_id:
                if c.get("canonical_finding_id"):
                    canonical_ids.append(str(c["canonical_finding_id"]))
                continue

            res = results_by_id[cid]
            verdict = str(res["verdict"])
            fp = str(c["fingerprint"])
            ev_obj = json.loads(str(res["source_evidence_json"] or "{}"))

            if cid in evidence_rejected:
                # Not promoted; an earlier canonical finding with the same fingerprint keeps its state untouched.
                conn.execute(
                    "UPDATE candidate_findings SET status='REJECTED', updated_at=CURRENT_TIMESTAMP WHERE candidate_id=?",
                    (c["candidate_id"],),
                )
                continue

            existing = conn.execute(
                "SELECT * FROM findings WHERE project_key=? AND fingerprint=?",
                (project_key, fp),
            ).fetchone()

            if verdict == "REJECTED":
                conn.execute(
                    "UPDATE candidate_findings SET status='REJECTED', updated_at=CURRENT_TIMESTAMP WHERE candidate_id=?",
                    (c["candidate_id"],),
                )
                if existing is not None:
                    prev_lc = str(existing["lifecycle"])
                    conn.execute(
                        """UPDATE findings
                           SET verification_status='REJECTED',
                               execution_eligible=0,
                               lifecycle='REJECTED',
                               verification_run_id=?,
                               verified_by_run_id=?,
                               verifier_conversation_id=?,
                               verified_at=CURRENT_TIMESTAMP,
                               updated_at=CURRENT_TIMESTAMP
                           WHERE finding_id=?""",
                        (verification_run_id, verification_run_id, conv_id, existing["finding_id"]),
                    )
                    conn.execute(
                        """INSERT INTO finding_history(
                            finding_id, project_key, run_id, from_lifecycle, to_lifecycle,
                            actor, reason, evidence_hash, file_blob_hash
                        ) VALUES(?, ?, ?, ?, 'REJECTED', 'verifier', 'REJECTED_BY_SECOND_PASS_VERIFIER', ?, ?)""",
                        (
                            existing["finding_id"],
                            project_key,
                            audit_run_id,
                            prev_lc,
                            existing["evidence_hash"],
                            existing["file_blob_hash"],
                        ),
                    )
                continue

            # CONFIRMED or PARTIALLY_CONFIRMED -> promote to canonical findings table
            is_confirmed = verdict == "CONFIRMED"
            v_status = "VERIFIED" if is_confirmed else "PARTIALLY_VERIFIED"
            # Remediation safety decouples execution eligibility from finding validity:
            # Confirmed findings are ALWAYS promoted and reviewable, but execution_eligible is False if unsafe
            cid_rem_ok, _ = remediation_safety_by_cid.get(cid, (True, ""))
            eff_rem_safe = bool(int(res.get("remediation_safe") or 0) == 1) and cid_rem_ok
            rem_safe_int = 1 if eff_rem_safe else 0
            exec_eligible = 1 if (is_confirmed and rem_safe_int == 1) else 0

            # Without independent cross-model verification (same model line, unknown or unattested models) a
            # finding stays APPLY-eligible, but only through a human terminal authorization: model_independent=0
            # makes the auto-approval policy refuse it unless the user explicitly allows single-model findings.
            model_independent = 1 if cross_ok else 0

            eff_file_path = normalize_path_str(ev_obj.get("file_path") or c.get("file_path")) or None
            eff_symbol = str(ev_obj.get("symbol") or c.get("symbol") or "").strip() or None
            eff_line_start = int(ev_obj.get("line_start") or c["line_start"])
            eff_line_end = int(ev_obj.get("line_end") or c["line_end"])
            eff_evidence = (
                f"{c['evidence']} [Corrected Scope: {res['corrected_claim']}]"
                if (not is_confirmed and res.get("corrected_claim"))
                else str(c["evidence"])
            )
            eff_item = {
                "file_path": eff_file_path,
                "symbol": eff_symbol,
                "line_start": eff_line_start,
                "line_end": eff_line_end,
                "evidence": str(c["evidence"]),
            }
            ev_hash = compute_evidence_hash(eff_item)
            blob_hash = compute_file_blob_hash(repo_path, eff_file_path)

            if existing is None:
                collision = conn.execute(
                    "SELECT finding_id FROM findings WHERE finding_id=?",
                    (cid,),
                ).fetchone()
                finding_id = _compute_canonical_finding_id(project_key, fp) if collision else cid
                conn.execute(
                    """INSERT INTO findings(
                        finding_id, project_key, run_id, fingerprint, title, category,
                        severity, confidence, file_path, symbol, line_start, line_end,
                        evidence, impact, recommendation, evidence_hash, file_blob_hash,
                        first_seen_run_id, last_seen_run_id, lifecycle,
                        verification_status, execution_eligible, remediation_safe,
                        verification_run_id, verified_by_run_id,
                        verified_at, verifier_conversation_id, evidence_validation_status,
                        snapshot_id, base_commit_sha, acceptance_criteria,
                        remediation_review, technical_rationale
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'OPEN',?,?,?,?,?,CURRENT_TIMESTAMP,?,'PASSED',?,?,?,?,?)""",
                    (
                        finding_id,
                        project_key,
                        audit_run_id,
                        fp,
                        c["title"],
                        c["category"],
                        res["verified_severity"],
                        res["verified_confidence"],
                        eff_file_path,
                        eff_symbol,
                        eff_line_start,
                        eff_line_end,
                        eff_evidence,
                        c["impact"],
                        c["recommendation"],
                        ev_hash,
                        blob_hash,
                        audit_run_id,
                        audit_run_id,
                        v_status,
                        exec_eligible,
                        rem_safe_int,
                        verification_run_id,
                        verification_run_id,
                        conv_id,
                        snapshot_info["snapshot_id"],
                        snapshot_info["base_commit_sha"],
                        res["acceptance_criteria"],
                        res["remediation_review"],
                        res["technical_rationale"],
                    ),
                )
                conn.execute(
                    """INSERT INTO finding_history(
                        finding_id, project_key, run_id, from_lifecycle, to_lifecycle,
                        actor, reason, evidence_hash, file_blob_hash
                    ) VALUES(?, ?, ?, NULL, 'OPEN', 'auditor', 'INITIAL_DISCOVERY', ?, ?)""",
                    (finding_id, project_key, audit_run_id, ev_hash, blob_hash),
                )
                promotion_stats["inserted_open"] += 1
            else:
                finding_id = str(existing["finding_id"])
                prev_lifecycle = str(existing["lifecycle"])
                prev_ev_hash = existing["evidence_hash"]
                prev_blob_hash = existing["file_blob_hash"]

                new_lifecycle = prev_lifecycle
                reason = "SEEN_IN_SUBSEQUENT_RUN"

                if prev_lifecycle == "DISMISSED":
                    blob_changed = (
                        prev_blob_hash is not None
                        and blob_hash is not None
                        and prev_blob_hash != blob_hash
                    )
                    evidence_changed = prev_ev_hash is not None and prev_ev_hash != ev_hash
                    if blob_changed or evidence_changed:
                        new_lifecycle = "OPEN"
                        reason = "DISMISSED_REOPENED_MATERIAL_CHANGE"
                        promotion_stats["reopened_dismissed"] += 1
                    else:
                        new_lifecycle = "DISMISSED"
                        reason = "DISMISSED_DUPLICATE_SUPPRESSED"
                        exec_eligible = 0
                        promotion_stats["suppressed_dismissed"] += 1
                elif prev_lifecycle == "RESOLVED":
                    new_lifecycle = "OPEN"
                    reason = "REGRESSION_REOPENED"
                    promotion_stats["reopened_regression"] += 1
                elif prev_lifecycle == "DEFERRED":
                    new_lifecycle = "DEFERRED"
                    reason = "DEFERRED_PRESERVED"
                    promotion_stats["preserved_deferred"] += 1
                elif prev_lifecycle in ("SKIPPED", "STALE", "OPEN", "REJECTED", "ARCHIVED"):
                    new_lifecycle = "OPEN"
                    reason = "ACTIVE_FINDING_UPDATED"
                    promotion_stats["updated_open"] += 1

                conn.execute(
                    """UPDATE findings SET
                        run_id=?, title=?, category=?, severity=?, confidence=?,
                        file_path=?, symbol=?, line_start=?, line_end=?,
                        evidence=?, impact=?, recommendation=?,
                        evidence_hash=?, file_blob_hash=?,
                        last_seen_run_id=?, lifecycle=?,
                        verification_status=?, execution_eligible=?, remediation_safe=?,
                        verification_run_id=?, verified_by_run_id=?, verified_at=CURRENT_TIMESTAMP,
                        verifier_conversation_id=?, evidence_validation_status='PASSED',
                        snapshot_id=?, base_commit_sha=?,
                        acceptance_criteria=?, remediation_review=?, technical_rationale=?,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE finding_id=?""",
                    (
                        audit_run_id,
                        c["title"],
                        c["category"],
                        res["verified_severity"],
                        res["verified_confidence"],
                        eff_file_path,
                        eff_symbol,
                        eff_line_start,
                        eff_line_end,
                        eff_evidence,
                        c["impact"],
                        c["recommendation"],
                        ev_hash,
                        blob_hash,
                        audit_run_id,
                        new_lifecycle,
                        v_status,
                        exec_eligible,
                        rem_safe_int,
                        verification_run_id,
                        verification_run_id,
                        conv_id,
                        snapshot_info["snapshot_id"],
                        snapshot_info["base_commit_sha"],
                        res["acceptance_criteria"],
                        res["remediation_review"],
                        res["technical_rationale"],
                        finding_id,
                    ),
                )
                conn.execute(
                    """INSERT INTO finding_history(
                        finding_id, project_key, run_id, from_lifecycle, to_lifecycle,
                        actor, reason, evidence_hash, file_blob_hash
                    ) VALUES(?, ?, ?, ?, ?, 'auditor', ?, ?, ?)""",
                    (
                        finding_id,
                        project_key,
                        audit_run_id,
                        prev_lifecycle,
                        new_lifecycle,
                        reason,
                        ev_hash,
                        blob_hash,
                    ),
                )

            conn.execute(
                "UPDATE candidate_findings SET status=?, canonical_finding_id=?, updated_at=CURRENT_TIMESTAMP WHERE candidate_id=?",
                (verdict, finding_id, c["candidate_id"]),
            )
            conn.execute("UPDATE findings SET model_independent=? WHERE finding_id=?", (model_independent, finding_id))
            canonical_ids.append(finding_id)

        if not verification_run_id.endswith("-DISC"):
            # Deterministic, model-free check: a GitHub repository without CI gets one canonical finding.
            from ci_check import upsert_ci_finding

            ci_fid = upsert_ci_finding(
                conn,
                project_key=project_key,
                audit_run_id=audit_run_id,
                verification_run_id=verification_run_id,
                repo_path=repo_path,
                snapshot_id=snapshot_info["snapshot_id"],
                base_commit_sha=snapshot_info["base_commit_sha"],
            )
            if ci_fid and ci_fid not in canonical_ids:
                canonical_ids.append(ci_fid)

        followup_verification_run_id: str | None = None
        if pending_discovered_candidate_ids and not verification_run_id.endswith("-DISC"):
            disc_vrun_id = f"VRUN-{audit_run_id}-DISC"
            disc_job_id = f"VJOB-{audit_run_id}-DISC"
            existing_disc_vrun = conn.execute(
                "SELECT verification_run_id FROM audit_verification_runs WHERE verification_run_id=?",
                (disc_vrun_id,),
            ).fetchone()
            if not existing_disc_vrun:
                conn.execute(
                    """INSERT INTO audit_verification_runs(
                        verification_run_id, audit_run_id, project_key,
                        snapshot_id, base_commit_sha, idempotency_key, status, dispatch_attempt
                    ) VALUES(?, ?, ?, ?, ?, ?, 'PENDING', 0)""",
                    (
                        disc_vrun_id,
                        audit_run_id,
                        project_key,
                        snapshot_info["snapshot_id"],
                        snapshot_info["base_commit_sha"], f"idem-disc-{audit_run_id}-{verification_run_id}",
                    ),
                )
                conn.execute(
                    """INSERT INTO verification_dispatch_queue(
                        job_id, audit_run_id, verification_run_id, project_key,
                        snapshot_id, idempotency_key, status, attempt_count, max_attempts
                    ) VALUES(?, ?, ?, ?, ?, ?, 'QUEUED', 0, 3)""",
                    (
                        disc_job_id,
                        audit_run_id,
                        disc_vrun_id,
                        project_key,
                        snapshot_info["snapshot_id"],
                        f"idem-q-disc-{audit_run_id}-{verification_run_id}",
                    ),
                )
            followup_verification_run_id = disc_vrun_id

        conn.execute(
            """UPDATE audit_verification_runs
               SET status='FINALIZED', completed_at=CURRENT_TIMESTAMP, error_code=NULL, error_message=NULL
               WHERE verification_run_id=?""",
            (verification_run_id,),
        )
        conn.execute(
            """UPDATE verification_dispatch_queue
               SET status='COMPLETED', updated_at=CURRENT_TIMESTAMP, last_error_code=NULL, last_error_message=NULL
               WHERE verification_run_id=?""",
            (verification_run_id,),
        )
        other_pending_vruns = conn.execute(
            """SELECT verification_run_id, status FROM audit_verification_runs
               WHERE audit_run_id=? AND verification_run_id != ?
                 AND status NOT IN ('FINALIZED', 'COMPLETED', 'ARCHIVED')""",
            (audit_run_id, verification_run_id),
        ).fetchall()
        if (pending_discovered_candidate_ids or followup_verification_run_id or other_pending_vruns) and str(
            run["status"]
        ) == "READY_FOR_REVIEW":
            final_audit_status = "READY_FOR_REVIEW"
        elif pending_discovered_candidate_ids or followup_verification_run_id or other_pending_vruns:
            transition_audit_run_status(
                conn,
                audit_run_id,
                "VERIFICATION_PENDING",
                error=None,
                finished=False,
            )
            final_audit_status = "VERIFICATION_PENDING"
        else:
            transition_audit_run_status(conn, audit_run_id, "READY_FOR_REVIEW", finished=True)
            final_audit_status = "READY_FOR_REVIEW"
            open_for_review = conn.execute(
                """SELECT COUNT(*) FROM findings
                   WHERE project_key=? AND (run_id=? OR last_seen_run_id=?) AND lifecycle='OPEN'""",
                (project_key, audit_run_id, audit_run_id),
            ).fetchone()[0]
            if int(open_for_review) == 0:
                # Nothing to decide (clean code, or only rejected / suppressed findings): do not hold the lock.
                transition_audit_run_status(
                    conn, audit_run_id, "COMPLETED", reason="NOTHING_TO_REVIEW", finished=True, jsonl_path=jsonl_path
                )
                conn.execute("UPDATE audit_runs SET completed_by_review=1 WHERE run_id=?", (audit_run_id,))
                final_audit_status = "COMPLETED"

        record_event(
            conn,
            "VERIFIED_REPORT_FINALIZED",
            project_key=project_key,
            run_id=audit_run_id,
            details={
                "verification_run_id": verification_run_id,
                "verifier_conversation_id": conv_id,
                "audit_status": final_audit_status,
                "stats": promotion_stats,
                "canonical_finding_ids": canonical_ids,
                "pending_discovered_candidate_ids": pending_discovered_candidate_ids,
                "followup_verification_run_id": followup_verification_run_id,
            },
            jsonl_path=jsonl_path,
        )
        conn.commit()

    report_path_str = run["report_path"]
    review_md_path: Path | None = None
    if report_path_str:
        r_dir = Path(report_path_str)
        review_md_path = (r_dir / "review-report.md") if r_dir.is_dir() else r_dir
        generate_review_report(
            db_path,
            project_key=project_key,
            run_id=audit_run_id,
            output_path=review_md_path,
        )

    return {
        "project_key": project_key,
        "audit_run_id": audit_run_id,
        "verification_run_id": verification_run_id,
        "status": final_audit_status,
        "verifier_conversation_id": conv_id,
        "canonical_finding_ids": canonical_ids,
        "pending_discovered_candidate_ids": pending_discovered_candidate_ids,
        "followup_verification_run_id": followup_verification_run_id,
        "stats": promotion_stats,
        "quality_metrics": metrics,
        "review_report_path": str(review_md_path) if review_md_path else None,
    }


def recover_stale_verification_leases(
    db_path: Path,
    *,
    project_key: str | None = None,
    now: datetime | None = None,
    jsonl_path: Path | None = None,
) -> dict[str, Any]:
    """Recover expired verification queue leases and promote ready retryable jobs atomically.

    - A job that crashed in `CLAIMED` (before `agentapi` invocation) is returned to `QUEUED`
      if within `max_attempts`, or marked `FAILED` if retries are exhausted.
    - A job that crashed in `DISPATCHING` (while `agentapi new-conversation` was in flight)
      is marked `DISPATCH_UNCERTAIN` (and the audit run `VERIFICATION_UNCERTAIN`) so it
      never blindly spawns duplicate verifier conversations.
    """
    from db import _parse_timestamp, connect, record_event

    curr_now = now or datetime.now(timezone.utc)
    requeued_jobs: list[str] = []
    uncertain_jobs: list[str] = []
    failed_jobs: list[str] = []
    recovery_errors: list[dict[str, str]] = []

    conn = connect(db_path)
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        sql = "SELECT * FROM verification_dispatch_queue WHERE status IN ('CLAIMED', 'DISPATCHING', 'RETRYABLE_FAILURE')"
        params: list[Any] = []
        if project_key:
            sql += " AND project_key=?"
            params.append(project_key)
        rows = conn.execute(sql, params).fetchall()

        for idx, row in enumerate(rows):
            job_id = str(row["job_id"])
            vrun_id = str(row["verification_run_id"])
            arun_id = str(row["audit_run_id"])
            pkey = str(row["project_key"])
            st = str(row["status"])
            attempts = int(row["attempt_count"] or 0)
            max_att = int(row["max_attempts"] or 3)
            row_keys = row.keys()
            l_tok = str(row["lease_token"] or "") if "lease_token" in row_keys else ""

            sp_name = f"sp_lease_rec_{idx}"
            conn.execute(f"SAVEPOINT {sp_name}")
            try:
                if st == "RETRYABLE_FAILURE":
                    next_dt = _parse_timestamp(row["next_attempt_at"])
                    if attempts < max_att and (next_dt is None or curr_now >= next_dt):
                        upd = conn.execute(
                            """UPDATE verification_dispatch_queue
                               SET status='QUEUED', lease_owner=NULL, lease_token=NULL,
                                   claimed_at=NULL, lease_expires_at=NULL, updated_at=CURRENT_TIMESTAMP
                               WHERE job_id=? AND status='RETRYABLE_FAILURE'""",
                            (job_id,),
                        )
                        if upd.rowcount == 1:
                            requeued_jobs.append(job_id)
                    elif attempts >= max_att:
                        upd = conn.execute(
                            "UPDATE verification_dispatch_queue SET status='FAILED', lease_owner=NULL, lease_token=NULL, updated_at=CURRENT_TIMESTAMP WHERE job_id=? AND status='RETRYABLE_FAILURE'",
                            (job_id,),
                        )
                        if upd.rowcount == 1:
                            conn.execute(
                                "UPDATE audit_verification_runs SET status='FAILED', error_code='MAX_RETRIES_EXCEEDED', completed_at=CURRENT_TIMESTAMP WHERE verification_run_id=?",
                                (vrun_id,),
                            )
                            transition_audit_run_status(conn, arun_id, "VERIFICATION_FAILED", error="Verification dispatch retries exhausted.")
                            failed_jobs.append(job_id)
                    conn.execute(f"RELEASE SAVEPOINT {sp_name}")
                    continue

                lease_dt = _parse_timestamp(row["lease_expires_at"])
                if lease_dt is not None and curr_now < lease_dt:
                    conn.execute(f"RELEASE SAVEPOINT {sp_name}")
                    continue

                if st == "CLAIMED":
                    if attempts < max_att:
                        upd = conn.execute(
                            """UPDATE verification_dispatch_queue
                               SET status='QUEUED', lease_owner=NULL, lease_token=NULL,
                                   claimed_at=NULL, lease_expires_at=NULL,
                                   last_error_code='STALE_LEASE_RECOVERED',
                                   last_error_message='Worker lease expired in CLAIMED state prior to agentapi dispatch.',
                                   updated_at=CURRENT_TIMESTAMP
                               WHERE job_id=? AND status='CLAIMED' AND COALESCE(lease_token, '')=?""",
                            (job_id, l_tok),
                        )
                        if upd.rowcount == 1:
                            requeued_jobs.append(job_id)
                            record_event(
                                conn,
                                "VERIFICATION_LEASE_REQUEUED",
                                project_key=pkey,
                                run_id=arun_id,
                                level="WARNING",
                                details={"job_id": job_id, "attempt_count": attempts},
                                jsonl_path=jsonl_path,
                            )
                    else:
                        upd = conn.execute(
                            """UPDATE verification_dispatch_queue
                               SET status='FAILED', lease_owner=NULL, lease_token=NULL,
                                   last_error_code='MAX_RETRIES_EXCEEDED',
                                   last_error_message='Stale CLAIMED lease exceeded max_attempts.',
                                   updated_at=CURRENT_TIMESTAMP
                               WHERE job_id=? AND status='CLAIMED' AND COALESCE(lease_token, '')=?""",
                            (job_id, l_tok),
                        )
                        if upd.rowcount == 1:
                            conn.execute(
                                "UPDATE audit_verification_runs SET status='FAILED', error_code='MAX_RETRIES_EXCEEDED', completed_at=CURRENT_TIMESTAMP WHERE verification_run_id=?",
                                (vrun_id,),
                            )
                            transition_audit_run_status(conn, arun_id, "VERIFICATION_FAILED", error="Verification dispatch max attempts exceeded.")
                            failed_jobs.append(job_id)
                elif st == "DISPATCHING":
                    msg = (
                        "Worker lease expired while in DISPATCHING state; agentapi new-conversation may have succeeded "
                        "without durable recording. Marked DISPATCH_UNCERTAIN to prevent duplicate conversations."
                    )
                    upd = conn.execute(
                        """UPDATE verification_dispatch_queue
                           SET status='DISPATCH_UNCERTAIN',
                               lease_owner=NULL,
                               lease_token=NULL,
                               last_error_code='CRASH_DURING_DISPATCH',
                               last_error_message=?,
                               updated_at=CURRENT_TIMESTAMP
                           WHERE job_id=? AND status='DISPATCHING' AND COALESCE(lease_token, '')=?""",
                        (msg, job_id, l_tok),
                    )
                    if upd.rowcount == 1:
                        conn.execute(
                            """UPDATE audit_verification_runs
                               SET status='UNCERTAIN', error_code='CRASH_DURING_DISPATCH', error_message=?
                               WHERE verification_run_id=?""",
                            (msg, vrun_id),
                        )
                        transition_audit_run_status(conn, arun_id, "VERIFICATION_UNCERTAIN", error=msg)
                        uncertain_jobs.append(job_id)
                        record_event(
                            conn,
                            "VERIFICATION_DISPATCH_UNCERTAIN",
                            project_key=pkey,
                            run_id=arun_id,
                            level="ERROR",
                            details={"job_id": job_id, "verification_run_id": vrun_id, "reason": msg},
                            jsonl_path=jsonl_path,
                        )
                conn.execute(f"RELEASE SAVEPOINT {sp_name}")
            except Exception as job_exc:
                conn.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
                conn.execute(f"RELEASE SAVEPOINT {sp_name}")
                recovery_errors.append(
                    {
                        "job_id": job_id,
                        "verification_run_id": vrun_id,
                        "audit_run_id": arun_id,
                        "error": str(job_exc),
                    }
                )
                record_event(
                    conn,
                    "VERIFICATION_LEASE_RECOVERY_SKIPPED_ERROR",
                    project_key=pkey,
                    run_id=arun_id,
                    level="ERROR",
                    details={"job_id": job_id, "verification_run_id": vrun_id, "error": str(job_exc)},
                    jsonl_path=jsonl_path,
                )

        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()

    return {
        "requeued_jobs": requeued_jobs,
        "uncertain_jobs": uncertain_jobs,
        "failed_jobs": failed_jobs,
        "recovery_errors": recovery_errors,
    }


def claim_next_verification_job(
    db_path: Path,
    *,
    worker_id: str,
    project_key: str | None = None,
    lease_seconds: int = 120,
    now: datetime | None = None,
    jsonl_path: Path | None = None,
) -> dict[str, Any] | None:
    """Atomically claim one QUEUED verification job with a bounded lease and unique fencing token."""
    from db import connect

    curr_now = now or datetime.now(timezone.utc)
    recover_stale_verification_leases(
        db_path,
        project_key=project_key,
        now=curr_now,
        jsonl_path=jsonl_path,
    )

    claimed_iso = curr_now.isoformat()
    expires_iso = (curr_now + timedelta(seconds=max(10, int(lease_seconds)))).isoformat()
    lease_token = f"lease-{uuid.uuid4().hex}"

    conn = connect(db_path)
    try:
        conn.isolation_level = None
        conn.execute("BEGIN IMMEDIATE")
        sql = """
            SELECT * FROM verification_dispatch_queue
            WHERE status='QUEUED' AND attempt_count < max_attempts
        """
        params: list[Any] = []
        if project_key:
            sql += " AND project_key=?"
            params.append(project_key)
        sql += " ORDER BY created_at ASC, job_id ASC LIMIT 1"

        row = conn.execute(sql, params).fetchone()
        if not row:
            conn.execute("COMMIT")
            return None

        job_id = str(row["job_id"])
        next_attempt = int(row["attempt_count"] or 0) + 1
        updated = conn.execute(
            """UPDATE verification_dispatch_queue
               SET status='CLAIMED',
                   lease_owner=?,
                   lease_token=?,
                   claimed_at=?,
                   lease_expires_at=?,
                   attempt_count=?,
                   updated_at=CURRENT_TIMESTAMP
               WHERE job_id=? AND status='QUEUED'""",
            (worker_id, lease_token, claimed_iso, expires_iso, next_attempt, job_id),
        )
        if updated.rowcount != 1:
            conn.execute("ROLLBACK")
            return None

        claimed_row = conn.execute(
            "SELECT * FROM verification_dispatch_queue WHERE job_id=?",
            (job_id,),
        ).fetchone()
        conn.execute("COMMIT")
        return dict(claimed_row) if claimed_row else None
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


def ensure_audit_dir_git_excluded(repo_path: Path) -> None:
    """Keep the auditor's in-repo folder out of `git add -A` via the repository's LOCAL exclude file
    (.git/info/exclude; nothing tracked changes)."""
    try:
        res = subprocess.run(["git", "-C", str(repo_path), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                             capture_output=True, text=True, timeout=20)
        common = (res.stdout or "").strip()
        if res.returncode != 0 or not common:
            return
        exclude = Path(common) / "info" / "exclude"
        existing = exclude.read_text(encoding="utf-8", errors="replace") if exclude.is_file() else ""
        if any(line.strip() in ("/.antigravity-audit/", ".antigravity-audit/", "/.antigravity-audit", ".antigravity-audit")
               for line in existing.splitlines()):
            return
        exclude.parent.mkdir(parents=True, exist_ok=True)
        sep = "" if (not existing or existing.endswith("\n")) else "\n"
        with exclude.open("a", encoding="utf-8") as fh:
            fh.write(f"{sep}# Antigravity Auditor working files\n/.antigravity-audit/\n")
    except (OSError, subprocess.SubprocessError):
        pass


# Provider quota refusals without a retry hint wait this long before the job may be dispatched again.
PROVIDER_QUOTA_DEFAULT_WAIT_SECONDS = 3600


class VerificationWorker:
    """Read-only persistent verification worker Sidecar controller.

    Polls the durable verification queue, claims one job at a time, resolves the
    project's Antigravity Project ID, dispatches a fresh conversation via AgentApiAdapter,
    and records the result with strict lease and uncertainty guards.
    Never modifies source code and never executes remediation.
    """

    def __init__(
        self,
        db_path: Path,
        *,
        app_home: Path | None = None,
        project_key: str | None = None,
        adapter: Any | None = None,
        worker_id: str | None = None,
        # Must outlive one synchronous verification dispatch (900 s adapter timeout); there is no heartbeat
        # during the agy call, so a shorter lease would let recovery reclaim a job that is still running.
        lease_seconds: int = 1200,
        retry_backoff_seconds: int = 30,
        persist_hook: Any | None = None,
        pre_dispatch_hook: Any | None = None,
        jsonl_path: Path | None = None,
    ) -> None:
        self.db_path = db_path
        self.app_home = (app_home or db_path.parent.parent).resolve()
        self.project_key = project_key
        from agy_adapter import AntigravityCliAdapter
        self.adapter = adapter or AntigravityCliAdapter()
        self.worker_id = worker_id or f"verifier-worker-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.lease_seconds = max(10, int(lease_seconds))
        self.retry_backoff_seconds = max(1, int(retry_backoff_seconds))
        self._persist_hook = persist_hook
        self._pre_dispatch_hook = pre_dispatch_hook
        self.jsonl_path = jsonl_path or (self.app_home / "logs" / "audit-events.jsonl")
        self._stop_requested = False

    def request_stop(self, *_args: Any) -> None:
        self._stop_requested = True

    def _verify_active_lease(
        self,
        conn: sqlite3.Connection,
        *,
        job_id: str,
        lease_token: str,
        expected_status: str,
        check_expiry: bool = True,
        now: datetime | None = None,
    ) -> bool:
        from db import _parse_timestamp

        q = conn.execute(
            "SELECT status, lease_owner, lease_token, lease_expires_at FROM verification_dispatch_queue WHERE job_id=?",
            (job_id,),
        ).fetchone()
        if not q:
            return False
        if str(q["status"]) != expected_status:
            return False
        if str(q["lease_owner"] or "") != self.worker_id:
            return False
        if str(q["lease_token"] or "") != lease_token:
            return False
        if check_expiry:
            curr = now or datetime.now(timezone.utc)
            exp_dt = _parse_timestamp(q["lease_expires_at"])
            if exp_dt is not None and curr >= exp_dt:
                return False
        return True

    def _verification_schema_path(self) -> Path:
        from structured_delivery import VERIFICATION_RESULT_SCHEMA, write_agent_schema

        schema_dir = self.app_home / "logs" / "schemas"
        schema_dir.mkdir(parents=True, exist_ok=True)
        return write_agent_schema(schema_dir, "verification-verdicts", VERIFICATION_RESULT_SCHEMA)

    def _submit_structured_verdicts(
        self,
        *,
        job_id: str,
        project_key: str,
        audit_run_id: str,
        verification_run_id: str,
        dispatch_res: Any,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Submit structured verdicts through the same handler as auditor_submit_verification. Never raises:
        a rejected submission marks the job and run failed explicitly instead of leaving them RUNNING."""
        from db import connect, record_event

        if payload is None:
            return {"structured_submission": "NOT_APPLICABLE"}
        try:
            submitted = submit_verification_results(
                self.db_path,
                audit_run_id=audit_run_id,
                verification_run_id=verification_run_id,
                verifier_conversation_id=str(dispatch_res.conversation_id),
                verifier_metadata={"verifier_model_id": dispatch_res.model_id, "invocation_mechanism": "cli"},
                verification_results=payload["verification_results"],
                verifier_discovered_findings=payload.get("verifier_discovered_findings") or None,
                jsonl_path=self.jsonl_path,
            )
            return {"structured_submission": "SUBMITTED", "submission": submitted}
        except Exception as exc:  # noqa: BLE001 - surfaced as an explicit failure state
            message = f"Structured verdict submission rejected: {exc}"[:500]
            with connect(self.db_path) as conn:
                conn.execute(
                    """UPDATE verification_dispatch_queue SET status='FAILED', last_error_code='STRUCTURED_SUBMIT_REJECTED',
                           last_error_message=?, updated_at=CURRENT_TIMESTAMP WHERE job_id=? AND status='RUNNING'""",
                    (message, job_id),
                )
                conn.execute(
                    """UPDATE audit_verification_runs SET status='FAILED', error_code='STRUCTURED_SUBMIT_REJECTED',
                           error_message=? WHERE verification_run_id=?""",
                    (message, verification_run_id),
                )
                try:
                    transition_audit_run_status(conn, audit_run_id, "VERIFICATION_FAILED", error=message)
                except Exception:  # noqa: BLE001 - keep the explicit job/vrun failure even if the run moved on
                    pass
                record_event(conn, "VERIFICATION_STRUCTURED_SUBMIT_REJECTED", project_key=project_key,
                             run_id=audit_run_id, level="ERROR",
                             details={"job_id": job_id, "verification_run_id": verification_run_id, "error": message},
                             jsonl_path=self.jsonl_path)
                conn.commit()
            return {"structured_submission": "REJECTED", "error": message}

    def process_one_job(self, *, now: datetime | None = None) -> dict[str, Any] | None:
        """Claim and process at most one verification queue job with strict lease fencing."""
        from db import connect, record_event

        curr_now = now or datetime.now(timezone.utc)
        job = claim_next_verification_job(
            self.db_path,
            worker_id=self.worker_id,
            project_key=self.project_key,
            lease_seconds=self.lease_seconds,
            now=curr_now,
            jsonl_path=self.jsonl_path,
        )
        if job is None:
            return None
        try:
            return self._process_claimed_job(job, curr_now=curr_now, now=now)
        except Exception as exc:  # noqa: BLE001 - the claimed job must not stay leased after a crash
            return self._release_job_after_exception(job, exc, curr_now=curr_now)

    def _release_job_after_exception(
        self, job: dict[str, Any], exc: Exception, *, curr_now: datetime
    ) -> dict[str, Any]:
        """Unexpected exception while processing a claimed job: release the lease (fenced by lease token) as
        RETRYABLE_FAILURE, or FAILED when no attempts remain, and return the audit run to a consistent state."""
        from db import connect

        job_id = str(job["job_id"])
        vrun_id = str(job["verification_run_id"])
        arun_id = str(job["audit_run_id"])
        attempt = int(job["attempt_count"])
        max_attempts = int(job["max_attempts"])
        lease_token = str(job.get("lease_token") or "")
        message = f"{type(exc).__name__}: {exc}"[:500]
        retryable = attempt < max_attempts
        next_at = (curr_now + timedelta(seconds=self.retry_backoff_seconds * max(1, attempt))).isoformat()
        with connect(self.db_path) as conn:
            q = conn.execute(
                "SELECT status FROM verification_dispatch_queue WHERE job_id=? AND COALESCE(lease_token, '')=?",
                (job_id, lease_token),
            ).fetchone()
            q_status = str(q["status"]) if q else ""
            run = conn.execute("SELECT status FROM audit_runs WHERE run_id=?", (arun_id,)).fetchone()
            run_status = str(run["status"]) if run else ""
            if q_status == "DISPATCHING":
                # The backend may already have created a verifier conversation: never retry blindly (duplicate
                # conversation); same handling as a crash during dispatch.
                new_status, vrun_status, audit_target = "DISPATCH_UNCERTAIN", "UNCERTAIN", "VERIFICATION_UNCERTAIN"
            elif retryable:
                new_status, vrun_status, audit_target = "RETRYABLE_FAILURE", "PENDING", "VERIFICATION_PENDING"
            else:
                new_status, vrun_status, audit_target = "FAILED", "FAILED", "VERIFICATION_FAILED"
            upd = conn.execute(
                """UPDATE verification_dispatch_queue
                   SET status=?, lease_owner=NULL, lease_token=NULL, lease_expires_at=NULL,
                       next_attempt_at=?, last_error_code='WORKER_EXCEPTION', last_error_message=?,
                       updated_at=CURRENT_TIMESTAMP
                   WHERE job_id=? AND status IN ('CLAIMED', 'DISPATCHING') AND COALESCE(lease_token, '')=?""",
                (new_status, next_at, message, job_id, lease_token),
            )
            if upd.rowcount == 1:
                conn.execute(
                    "UPDATE audit_verification_runs SET status=?, error_code='WORKER_EXCEPTION', error_message=? WHERE verification_run_id=?",
                    (vrun_status, message, vrun_id),
                )
                if run_status in ("VERIFICATION_PENDING", "VERIFICATION_DISPATCHING") and run_status != audit_target:
                    transition_audit_run_status(conn, arun_id, audit_target, error=message)
            conn.commit()
        return {
            "job_id": job_id,
            "audit_run_id": arun_id,
            "verification_run_id": vrun_id,
            "status": new_status,
            "error_code": "WORKER_EXCEPTION",
            "error_message": message,
        }

    def _process_claimed_job(
        self, job: dict[str, Any], *, curr_now: datetime, now: datetime | None
    ) -> dict[str, Any] | None:
        from db import connect, record_event

        job_id = str(job["job_id"])
        vrun_id = str(job["verification_run_id"])
        arun_id = str(job["audit_run_id"])
        pkey = str(job["project_key"])
        attempt = int(job["attempt_count"])
        max_attempts = int(job["max_attempts"])
        lease_token = str(job.get("lease_token") or "")

        if self._pre_dispatch_hook is not None:
            self._pre_dispatch_hook(job)

        with connect(self.db_path) as conn:
            proj = conn.execute("SELECT * FROM projects WHERE project_key=?", (pkey,)).fetchone()
            run = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (arun_id,)).fetchone()

        if not proj or not run:
            with connect(self.db_path) as conn:
                conn.execute(
                    """UPDATE verification_dispatch_queue
                       SET status='FAILED', last_error_code='MISSING_PROJECT_OR_RUN', updated_at=CURRENT_TIMESTAMP
                       WHERE job_id=? AND status='CLAIMED' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                    (job_id, self.worker_id, lease_token),
                )
                conn.commit()
            return {"job_id": job_id, "status": "FAILED", "error_code": "MISSING_PROJECT_OR_RUN"}

        ag_project_id = str(proj["antigravity_project_id"] or "").strip()
        repo_path = Path(proj["repo_path"])

        # Safety Check 1: Validate registered Project ID (never reuse or hardcode a global Project ID)
        if not ag_project_id or ag_project_id.upper() in ("PENDING", "UNKNOWN"):
            msg = (
                f"Project '{pkey}' has missing or PENDING Antigravity Project ID ('{ag_project_id}'). "
                "Automatic verification dispatch is blocked until a valid Project ID is configured."
            )
            prompt_text = build_verification_prompt(
                self.db_path,
                audit_run_id=arun_id,
                verification_run_id=vrun_id,
                app_home=self.app_home,
            )
            prompt_file = self._write_manual_prompt_file(repo_path, arun_id, prompt_text)
            with connect(self.db_path) as conn:
                if not self._verify_active_lease(conn, job_id=job_id, lease_token=lease_token, expected_status="CLAIMED", now=now):
                    return {"job_id": job_id, "audit_run_id": arun_id, "verification_run_id": vrun_id, "status": "LEASE_LOST", "error_code": "STALE_WORKER_FENCED"}
                upd = conn.execute(
                    """UPDATE verification_dispatch_queue
                       SET status='BLOCKED_CONFIGURATION',
                           last_error_code='MISSING_PROJECT_ID',
                           last_error_message=?,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE job_id=? AND status='CLAIMED' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                    (msg, job_id, self.worker_id, lease_token),
                )
                if upd.rowcount != 1:
                    return {"job_id": job_id, "audit_run_id": arun_id, "verification_run_id": vrun_id, "status": "LEASE_LOST", "error_code": "STALE_WORKER_FENCED"}
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='BLOCKED',
                           dispatch_attempt=?,
                           error_code='MISSING_PROJECT_ID',
                           error_message=?
                       WHERE verification_run_id=?""",
                    (attempt, msg, vrun_id),
                )
                transition_audit_run_status(conn, arun_id, "VERIFICATION_BLOCKED", error=msg)
                record_event(
                    conn,
                    "VERIFICATION_BLOCKED_CONFIGURATION",
                    project_key=pkey,
                    run_id=arun_id,
                    level="WARNING",
                    details={
                        "job_id": job_id,
                        "verification_run_id": vrun_id,
                        "error_code": "MISSING_PROJECT_ID",
                        "manual_prompt_path": str(prompt_file),
                    },
                    jsonl_path=self.jsonl_path,
                )
                conn.commit()
            return {
                "job_id": job_id,
                "audit_run_id": arun_id,
                "verification_run_id": vrun_id,
                "status": "BLOCKED_CONFIGURATION",
                "error_code": "MISSING_PROJECT_ID",
                "manual_prompt_path": str(prompt_file),
            }

        prompt_text = build_verification_prompt(
            self.db_path,
            audit_run_id=arun_id,
            verification_run_id=vrun_id,
            app_home=self.app_home,
        )
        prompt_file = self._write_manual_prompt_file(repo_path, arun_id, prompt_text)
        # The manual prompt file keeps MCP submission (for an interactive Antigravity session); the headless
        # dispatch cannot use MCP, so it returns verdicts as structured JSON (structured_delivery.py).
        # Only headless adapters (agy print mode) need structured delivery; interactive adapters (agentapi)
        # open a normal Antigravity conversation where the verifier can use MCP tools.
        structured = bool(getattr(self.adapter, "SUPPORTS_STRUCTURED_DELIVERY", False))
        if structured:
            from structured_delivery import adapt_verification_prompt_for_structured_delivery

            prompt_text = adapt_verification_prompt_for_structured_delivery(prompt_text, arun_id, vrun_id)

        # Safety Check 2: Check adapter availability before entering DISPATCHING
        if self.adapter.discover_executable() is None:
            err_code = "AGENTAPI_UNAVAILABLE" if isinstance(self.adapter, AgentApiAdapter) else "CLI_UNAVAILABLE"
            msg = (
                f"{err_code.lower()} executable is unavailable in current environment. "
                f"Verification job retained; use manual verification prompt at: {prompt_file}"
            )
            with connect(self.db_path) as conn:
                if not self._verify_active_lease(conn, job_id=job_id, lease_token=lease_token, expected_status="CLAIMED", now=now):
                    return {"job_id": job_id, "audit_run_id": arun_id, "verification_run_id": vrun_id, "status": "LEASE_LOST", "error_code": "STALE_WORKER_FENCED"}
                upd = conn.execute(
                    """UPDATE verification_dispatch_queue
                       SET status='BLOCKED_CONFIGURATION',
                           last_error_code=?,
                           last_error_message=?,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE job_id=? AND status='CLAIMED' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                    (err_code, msg, job_id, self.worker_id, lease_token),
                )
                if upd.rowcount != 1:
                    return {"job_id": job_id, "audit_run_id": arun_id, "verification_run_id": vrun_id, "status": "LEASE_LOST", "error_code": "STALE_WORKER_FENCED"}
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='BLOCKED',
                           dispatch_attempt=?,
                           error_code=?,
                           error_message=?
                       WHERE verification_run_id=?""",
                    (attempt, err_code, msg, vrun_id),
                )
                transition_audit_run_status(conn, arun_id, "VERIFICATION_BLOCKED", error=msg)
                record_event(
                    conn,
                    "VERIFICATION_ADAPTER_UNAVAILABLE",
                    project_key=pkey,
                    run_id=arun_id,
                    level="WARNING",
                    details={
                        "job_id": job_id,
                        "verification_run_id": vrun_id,
                        "error_code": err_code,
                        "manual_prompt_path": str(prompt_file),
                    },
                    jsonl_path=self.jsonl_path,
                )
                conn.commit()
            return {
                "job_id": job_id,
                "audit_run_id": arun_id,
                "verification_run_id": vrun_id,
                "status": "BLOCKED_CONFIGURATION",
                "error_code": err_code,
                "manual_prompt_path": str(prompt_file),
                "manual_prompt": prompt_text,
            }

        # Step 2.5: Evaluate candidate finding and deterministic model routing
        with connect(self.db_path) as conn:
            candidates = _select_candidates_for_verification_run(conn, arun_id, vrun_id)
            snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id=?", (arun_id,)).fetchone()

        # Find highest severity candidate to route
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        top_cand = None
        top_rank = -1
        for c in candidates:
            r = sev_rank.get(str(c["severity"] or "").upper(), 0)
            if r > top_rank:
                top_rank = r
                top_cand = c

        top_cand = top_cand or (candidates[0] if candidates else None)
        cand_sev = str(top_cand["severity"] or "MEDIUM").upper() if top_cand else "MEDIUM"
        cand_cat = str(top_cand["category"] or "GENERAL").upper() if top_cand else "GENERAL"
        cand_fingerprint = str(top_cand["fingerprint"]) if top_cand else None

        # Check deterministic evidence gate on top candidate
        evidence_gate_status = "UNCHECKED"
        if top_cand and snap_row:
            snap_keys = set(snap_row.keys()) if hasattr(snap_row, "keys") else set()
            snapshot_info = {
                "snapshot_id": str(snap_row["snapshot_id"]),
                "base_commit_sha": str(snap_row["base_commit_sha"]),
                "working_tree_hash": str(snap_row["working_tree_hash"]),
                "file_hashes": json.loads(str(snap_row["file_hashes_json"] or "{}")),
                "snapshot_complete": (
                    bool(int(snap_row["snapshot_complete"]))
                    if ("snapshot_complete" in snap_keys and snap_row["snapshot_complete"] is not None)
                    else True
                ),
                "incomplete_reason": snap_row["incomplete_reason"] if "incomplete_reason" in snap_keys else None,
            }
            ev_test = validate_single_finding_evidence(
                repo_path=repo_path,
                snapshot_info=snapshot_info,
                candidate=dict(top_cand),
                source_evidence={
                    "file_path": top_cand["file_path"],
                    "line_start": top_cand["line_start"],
                    "line_end": top_cand["line_end"],
                    "symbol": top_cand["symbol"],
                },
                _allow_candidate_excerpt_fallback=True,
            )
            evidence_gate_status = "PASSED" if ev_test["passed"] else "FAILED"

        from model_policy import ExecutionIntent, ModelRoutingRequest, TaskType, route_model
        from model_budget import ModelBudgetTracker, build_minimized_evidence_package

        primary_model = (str(run["primary_model"] or "").strip() if "primary_model" in run.keys() else "") or None

        task_type = (
            TaskType.CRITICAL_VERIFICATION
            if cand_sev in ("CRITICAL", "HIGH")
            else TaskType.ROUTINE_VERIFICATION
        )
        req = ModelRoutingRequest(
            task_type=task_type,
            severity=cand_sev,
            finding_category=cand_cat,
            evidence_gate_status=evidence_gate_status,
            execution_intent=ExecutionIntent.REQUIRED_CRITICAL_VERIFICATION,
            audit_run_id=arun_id,
            finding_fingerprint=cand_fingerprint,
            primary_model=primary_model,
        )
        decision = route_model(req, db_path=self.db_path)

        # Check if routing is blocked (e.g. unvalidated evidence blocks critical verification)
        if decision.is_blocked:
            block_code = decision.routing_status.value
            block_msg = decision.blocked_reason or decision.decision_reason
            with connect(self.db_path) as conn:
                if not self._verify_active_lease(conn, job_id=job_id, lease_token=lease_token, expected_status="CLAIMED", now=now):
                    return {"job_id": job_id, "audit_run_id": arun_id, "verification_run_id": vrun_id, "status": "LEASE_LOST", "error_code": "STALE_WORKER_FENCED"}
                upd = conn.execute(
                    """UPDATE verification_dispatch_queue
                       SET status='BLOCKED_CONFIGURATION',
                           last_error_code=?,
                           last_error_message=?,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE job_id=? AND status='CLAIMED' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                    (block_code, block_msg, job_id, self.worker_id, lease_token),
                )
                if upd.rowcount != 1:
                    return {"job_id": job_id, "audit_run_id": arun_id, "verification_run_id": vrun_id, "status": "LEASE_LOST", "error_code": "STALE_WORKER_FENCED"}
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='BLOCKED',
                           dispatch_attempt=?,
                           error_code=?,
                           error_message=?
                       WHERE verification_run_id=?""",
                    (attempt, block_code, block_msg, vrun_id),
                )
                transition_audit_run_status(conn, arun_id, "VERIFICATION_BLOCKED", error=block_msg)
                record_event(
                    conn,
                    "VERIFICATION_ROUTING_BLOCKED",
                    project_key=pkey,
                    run_id=arun_id,
                    level="WARNING",
                    details={
                        "job_id": job_id,
                        "verification_run_id": vrun_id,
                        "routing_status": block_code,
                        "error_message": block_msg,
                    },
                    jsonl_path=self.jsonl_path,
                )
                conn.commit()
            return {
                "job_id": job_id,
                "audit_run_id": arun_id,
                "verification_run_id": vrun_id,
                "status": "BLOCKED",
                "error_code": block_code,
                "error_message": block_msg,
            }

        if decision.is_argon and top_cand:
            min_pkg = build_minimized_evidence_package(
                finding=dict(top_cand),
                evidence_gate_status=evidence_gate_status,
            )
            prompt_text = prompt_text + "\n\n" + min_pkg.to_prompt_text()

        # Step 3: Atomic lease check + durable transition to DISPATCHING before invoking adapter
        conn = connect(self.db_path)
        conn.isolation_level = None
        try:
            conn.execute("BEGIN IMMEDIATE")
            if not self._verify_active_lease(
                conn,
                job_id=job_id,
                lease_token=lease_token,
                expected_status="CLAIMED",
                check_expiry=True,
                now=now,
            ):
                conn.execute("ROLLBACK")
                return {
                    "job_id": job_id,
                    "audit_run_id": arun_id,
                    "verification_run_id": vrun_id,
                    "status": "LEASE_LOST",
                    "error_code": "STALE_WORKER_FENCED",
                    "error_message": "Worker lease expired or was reassigned before dispatch; aborting agentapi call.",
                }
            upd = conn.execute(
                """UPDATE verification_dispatch_queue
                   SET status='DISPATCHING', updated_at=CURRENT_TIMESTAMP
                   WHERE job_id=? AND status='CLAIMED' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                (job_id, self.worker_id, lease_token),
            )
            if upd.rowcount != 1:
                conn.execute("ROLLBACK")
                return {
                    "job_id": job_id,
                    "audit_run_id": arun_id,
                    "verification_run_id": vrun_id,
                    "status": "LEASE_LOST",
                    "error_code": "STALE_WORKER_FENCED",
                }
            conn.execute(
                """UPDATE audit_verification_runs
                   SET status='DISPATCHING', dispatch_attempt=?, started_at=COALESCE(started_at, CURRENT_TIMESTAMP)
                   WHERE verification_run_id=?""",
                (attempt, vrun_id),
            )
            if str(run["status"]) != "READY_FOR_REVIEW":
                transition_audit_run_status(conn, arun_id, "VERIFICATION_DISPATCHING")
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

        # Step 4: Invoke adapter with routed model and context minimization
        tracker = ModelBudgetTracker(db_path=self.db_path)
        structured_kwargs: dict[str, Any] = (
            {"isolated": True, "json_schema_path": self._verification_schema_path()} if structured else {}
        )
        dispatch_res = self.adapter.start_new_conversation(
            prompt_text,
            cwd=repo_path if repo_path.is_dir() else self.app_home,
            project_id=ag_project_id,
            task_type=req.task_type,
            model_id=decision.selected_model.value if decision.selected_model else None,
            severity=cand_sev,
            finding_category=cand_cat,
            evidence_gate_status=evidence_gate_status,
            execution_intent=ExecutionIntent.REQUIRED_CRITICAL_VERIFICATION,
            audit_run_id=arun_id,
            verification_run_id=vrun_id,
            finding_fingerprint=cand_fingerprint,
            primary_model=primary_model,
            budget_tracker=tracker,
            db_path=self.db_path,
            **structured_kwargs,
        )

        # Step 4b: Structured delivery - validate the verdict payload BEFORE the job becomes RUNNING, so an
        # unusable answer takes the normal retryable-failure path instead of stranding the run.
        structured_payload: dict[str, Any] | None = None
        if structured and dispatch_res.ok and dispatch_res.conversation_id:
            from dataclasses import replace as _dc_replace

            from structured_delivery import (
                VERIFICATION_RESULT_SCHEMA,
                StructuredDeliveryError,
                agent_result_payload,
                parse_structured_result,
            )

            try:
                structured_payload = parse_structured_result(agent_result_payload(dispatch_res), VERIFICATION_RESULT_SCHEMA)
            except StructuredDeliveryError as exc:
                dispatch_res = _dc_replace(
                    dispatch_res, ok=False, status="STRUCTURED_OUTPUT_INVALID",
                    error_code="STRUCTURED_OUTPUT_INVALID", error_message=str(exc)[:500],
                )

        # Step 5: Persist dispatch outcome with lease fencing and uncertainty guard on persistence failure
        if dispatch_res.ok and dispatch_res.conversation_id:
            try:
                if self._persist_hook is not None:
                    self._persist_hook(job_id, dispatch_res)
                conn = connect(self.db_path)
                conn.isolation_level = None
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    upd = conn.execute(
                        """UPDATE verification_dispatch_queue
                           SET status='RUNNING',
                               verifier_conversation_id=?,
                               last_error_code=NULL,
                               last_error_message=NULL,
                               updated_at=CURRENT_TIMESTAMP
                           WHERE job_id=? AND status='DISPATCHING' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                        (dispatch_res.conversation_id, job_id, self.worker_id, lease_token),
                    )
                    if upd.rowcount != 1:
                        conn.execute("ROLLBACK")
                        return {
                            "job_id": job_id,
                            "audit_run_id": arun_id,
                            "verification_run_id": vrun_id,
                            "status": "LEASE_LOST",
                            "error_code": "STALE_WORKER_FENCED",
                        }
                    attest_status = getattr(dispatch_res, "attestation_status", "MODEL_ATTESTATION_INCOMPLETE")
                    m_source = "RUNTIME_ATTESTED" if attest_status == "RUNTIME_ATTESTED" else "CLI_STREAM"
                    conn.execute(
                        """UPDATE audit_verification_runs
                           SET status='RUNNING',
                               verifier_conversation_id=?,
                               verifier_model_id=?,
                               verifier_model_source=?,
                               verifier_attestation_status=?,
                               verifier_agent_id=?,
                               invocation_mechanism=?,
                               error_code=NULL,
                               error_message=NULL
                           WHERE verification_run_id=?""",
                        (
                            dispatch_res.conversation_id,
                            dispatch_res.model_id,
                            m_source,
                            attest_status,
                            dispatch_res.agent_id,
                            dispatch_res.invocation_mechanism,
                            vrun_id,
                        ),
                    )
                    if str(run["status"]) != "READY_FOR_REVIEW":
                        transition_audit_run_status(conn, arun_id, "VERIFICATION_RUNNING")
                    record_event(
                        conn,
                        "VERIFICATION_CONVERSATION_DISPATCHED",
                        project_key=pkey,
                        run_id=arun_id,
                        details={
                            "job_id": job_id,
                            "verification_run_id": vrun_id,
                            "verifier_conversation_id": dispatch_res.conversation_id,
                            "verifier_model_id": dispatch_res.model_id,
                            "verifier_agent_id": dispatch_res.agent_id,
                            "attempt": attempt,
                        },
                        jsonl_path=self.jsonl_path,
                    )
                    conn.execute("COMMIT")
                finally:
                    conn.close()
                # The conversation id is durably recorded (RUNNING) at this point: a failure while submitting the
                # verdicts must not be reported as a conversation-id persistence failure below.
                try:
                    submission = self._submit_structured_verdicts(
                        job_id=job_id, project_key=pkey, audit_run_id=arun_id, verification_run_id=vrun_id,
                        dispatch_res=dispatch_res, payload=structured_payload,
                    )
                except Exception as submit_exc:  # noqa: BLE001 - reported; the run stays RUNNING for manual review
                    submission = {
                        "structured_submission": "ERROR",
                        "structured_error": f"{type(submit_exc).__name__}: {submit_exc}"[:500],
                    }
                return {
                    "job_id": job_id,
                    "audit_run_id": arun_id,
                    "verification_run_id": vrun_id,
                    "status": "RUNNING",
                    "verifier_conversation_id": dispatch_res.conversation_id,
                    "verifier_model_id": dispatch_res.model_id,
                    "verifier_agent_id": dispatch_res.agent_id,
                    **submission,
                }
            except Exception as persist_exc:
                err_msg = (
                    f"Verifier conversation was created by agentapi, but persisting conversation ID failed: {persist_exc}. "
                    "Marked DISPATCH_UNCERTAIN to prevent duplicate conversations."
                )
                with connect(self.db_path) as conn:
                    upd = conn.execute(
                        """UPDATE verification_dispatch_queue
                           SET status='DISPATCH_UNCERTAIN',
                               last_error_code='CONVERSATION_ID_PERSISTENCE_FAILED',
                               last_error_message=?,
                               updated_at=CURRENT_TIMESTAMP
                           WHERE job_id=? AND status='DISPATCHING' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                        (err_msg, job_id, self.worker_id, lease_token),
                    )
                    if upd.rowcount == 1:
                        conn.execute(
                            """UPDATE audit_verification_runs
                               SET status='UNCERTAIN',
                                   error_code='CONVERSATION_ID_PERSISTENCE_FAILED',
                                   error_message=?
                               WHERE verification_run_id=?""",
                            (err_msg, vrun_id),
                        )
                        if str(run["status"]) != "READY_FOR_REVIEW":
                            transition_audit_run_status(conn, arun_id, "VERIFICATION_UNCERTAIN", error=err_msg)
                        record_event(
                            conn,
                            "VERIFICATION_DISPATCH_UNCERTAIN",
                            project_key=pkey,
                            run_id=arun_id,
                            level="ERROR",
                            details={
                                "job_id": job_id,
                                "verification_run_id": vrun_id,
                                "error_code": "CONVERSATION_ID_PERSISTENCE_FAILED",
                                "error_message": err_msg,
                            },
                            jsonl_path=self.jsonl_path,
                        )
                        conn.commit()
                return {
                    "job_id": job_id,
                    "audit_run_id": arun_id,
                    "verification_run_id": vrun_id,
                    "status": "DISPATCH_UNCERTAIN",
                    "error_code": "CONVERSATION_ID_PERSISTENCE_FAILED",
                    "error_message": err_msg,
                }

        if dispatch_res.status == "PROVIDER_QUOTA_EXHAUSTED":
            # The provider refused (quota / rate limit). Park the job until the quota is likely back WITHOUT
            # spending one of its attempts; the next worker / weekly run picks it up after next_attempt_at.
            wait_s = int(dispatch_res.retry_after_seconds or PROVIDER_QUOTA_DEFAULT_WAIT_SECONDS)
            wait_s = max(60, min(wait_s, 7 * 86400))
            next_at = (curr_now + timedelta(seconds=wait_s)).isoformat()
            with connect(self.db_path) as conn:
                upd = conn.execute(
                    """UPDATE verification_dispatch_queue
                       SET status='RETRYABLE_FAILURE',
                           attempt_count=MAX(0, attempt_count - 1),
                           lease_owner=NULL,
                           lease_token=NULL,
                           lease_expires_at=NULL,
                           next_attempt_at=?,
                           last_error_code='PROVIDER_QUOTA_EXHAUSTED',
                           last_error_message=?,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE job_id=? AND status='DISPATCHING' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                    (next_at, dispatch_res.error_message, job_id, self.worker_id, lease_token),
                )
                if upd.rowcount != 1:
                    return {"job_id": job_id, "audit_run_id": arun_id, "verification_run_id": vrun_id, "status": "LEASE_LOST", "error_code": "STALE_WORKER_FENCED"}
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='PENDING', error_code='PROVIDER_QUOTA_EXHAUSTED', error_message=?
                       WHERE verification_run_id=?""",
                    (dispatch_res.error_message, vrun_id),
                )
                if str(run["status"]) != "READY_FOR_REVIEW":
                    transition_audit_run_status(
                        conn, arun_id, "VERIFICATION_PENDING", error=dispatch_res.error_message
                    )
                record_event(
                    conn,
                    "VERIFICATION_WAITING_PROVIDER_QUOTA",
                    project_key=pkey,
                    run_id=arun_id,
                    level="WARNING",
                    details={"job_id": job_id, "verification_run_id": vrun_id, "retry_at": next_at,
                             "model": dispatch_res.requested_model, "error_message": dispatch_res.error_message},
                    jsonl_path=self.jsonl_path,
                )
                conn.commit()
            return {
                "job_id": job_id,
                "audit_run_id": arun_id,
                "verification_run_id": vrun_id,
                "status": "WAITING_PROVIDER_QUOTA",
                "retry_at": next_at,
                "error_code": "PROVIDER_QUOTA_EXHAUSTED",
                "error_message": dispatch_res.error_message,
            }

        if dispatch_res.status in ("ARGON_QUOTA_EXHAUSTED", "BLOCKED_BUDGET"):
            with connect(self.db_path) as conn:
                upd = conn.execute(
                    """UPDATE verification_dispatch_queue
                       SET status='BLOCKED_CONFIGURATION',
                           last_error_code=?,
                           last_error_message=?,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE job_id=? AND status='DISPATCHING' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                    (dispatch_res.error_code, dispatch_res.error_message, job_id, self.worker_id, lease_token),
                )
                if upd.rowcount != 1:
                    return {"job_id": job_id, "audit_run_id": arun_id, "verification_run_id": vrun_id, "status": "LEASE_LOST", "error_code": "STALE_WORKER_FENCED"}
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='BLOCKED',
                           error_code=?,
                           error_message=?
                       WHERE verification_run_id=?""",
                    (dispatch_res.error_code, dispatch_res.error_message, vrun_id),
                )
                if str(run["status"]) != "READY_FOR_REVIEW":
                    transition_audit_run_status(
                        conn, arun_id, "VERIFICATION_BLOCKED", error=dispatch_res.error_message
                    )
                record_event(
                    conn,
                    "VERIFICATION_BLOCKED_BUDGET",
                    project_key=pkey,
                    run_id=arun_id,
                    level="WARNING",
                    details={
                        "job_id": job_id,
                        "verification_run_id": vrun_id,
                        "error_code": dispatch_res.error_code,
                        "error_message": dispatch_res.error_message,
                    },
                    jsonl_path=self.jsonl_path,
                )
                conn.commit()
            return {
                "job_id": job_id,
                "audit_run_id": arun_id,
                "verification_run_id": vrun_id,
                "status": "BLOCKED",
                "error_code": dispatch_res.error_code,
                "error_message": dispatch_res.error_message,
            }

        if dispatch_res.status == "DISPATCH_UNCERTAIN":
            with connect(self.db_path) as conn:
                upd = conn.execute(
                    """UPDATE verification_dispatch_queue
                       SET status='DISPATCH_UNCERTAIN',
                           last_error_code=?,
                           last_error_message=?,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE job_id=? AND status='DISPATCHING' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                    (dispatch_res.error_code, dispatch_res.error_message, job_id, self.worker_id, lease_token),
                )
                if upd.rowcount != 1:
                    return {"job_id": job_id, "audit_run_id": arun_id, "verification_run_id": vrun_id, "status": "LEASE_LOST", "error_code": "STALE_WORKER_FENCED"}
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='UNCERTAIN',
                           error_code=?,
                           error_message=?
                       WHERE verification_run_id=?""",
                    (dispatch_res.error_code, dispatch_res.error_message, vrun_id),
                )
                if str(run["status"]) != "READY_FOR_REVIEW":
                    transition_audit_run_status(
                        conn, arun_id, "VERIFICATION_UNCERTAIN", error=dispatch_res.error_message
                    )
                record_event(
                    conn,
                    "VERIFICATION_DISPATCH_UNCERTAIN",
                    project_key=pkey,
                    run_id=arun_id,
                    level="ERROR",
                    details={
                        "job_id": job_id,
                        "verification_run_id": vrun_id,
                        "error_code": dispatch_res.error_code,
                        "error_message": dispatch_res.error_message,
                    },
                    jsonl_path=self.jsonl_path,
                )
                conn.commit()
            return {
                "job_id": job_id,
                "audit_run_id": arun_id,
                "verification_run_id": vrun_id,
                "status": "DISPATCH_UNCERTAIN",
                "error_code": dispatch_res.error_code,
                "error_message": dispatch_res.error_message,
            }

        # Deterministic failure (e.g. non-zero exit before creating conversation) -> retryable if attempts remain
        if attempt < max_attempts:
            next_at = (curr_now + timedelta(seconds=self.retry_backoff_seconds * attempt)).isoformat()
            with connect(self.db_path) as conn:
                upd = conn.execute(
                    """UPDATE verification_dispatch_queue
                       SET status='RETRYABLE_FAILURE',
                           lease_owner=NULL,
                           lease_token=NULL,
                           lease_expires_at=NULL,
                           next_attempt_at=?,
                           last_error_code=?,
                           last_error_message=?,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE job_id=? AND status='DISPATCHING' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                    (next_at, dispatch_res.error_code, dispatch_res.error_message, job_id, self.worker_id, lease_token),
                )
                if upd.rowcount != 1:
                    return {"job_id": job_id, "audit_run_id": arun_id, "verification_run_id": vrun_id, "status": "LEASE_LOST", "error_code": "STALE_WORKER_FENCED"}
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='PENDING',
                           error_code=?,
                           error_message=?
                       WHERE verification_run_id=?""",
                    (dispatch_res.error_code, dispatch_res.error_message, vrun_id),
                )
                if str(run["status"]) != "READY_FOR_REVIEW":
                    transition_audit_run_status(
                        conn, arun_id, "VERIFICATION_PENDING", error=dispatch_res.error_message
                    )
                conn.commit()
            return {
                "job_id": job_id,
                "audit_run_id": arun_id,
                "verification_run_id": vrun_id,
                "status": "RETRYABLE_FAILURE",
                "attempt": attempt,
                "max_attempts": max_attempts,
                "error_code": dispatch_res.error_code,
                "error_message": dispatch_res.error_message,
            }

        with connect(self.db_path) as conn:
            upd = conn.execute(
                """UPDATE verification_dispatch_queue
                   SET status='FAILED',
                       lease_owner=NULL,
                       lease_token=NULL,
                       last_error_code=?,
                       last_error_message=?,
                       updated_at=CURRENT_TIMESTAMP
                   WHERE job_id=? AND status='DISPATCHING' AND lease_owner=? AND COALESCE(lease_token, '')=?""",
                (dispatch_res.error_code, dispatch_res.error_message, job_id, self.worker_id, lease_token),
            )
            if upd.rowcount != 1:
                return {"job_id": job_id, "audit_run_id": arun_id, "verification_run_id": vrun_id, "status": "LEASE_LOST", "error_code": "STALE_WORKER_FENCED"}
            conn.execute(
                """UPDATE audit_verification_runs
                   SET status='FAILED',
                       error_code=?,
                       error_message=?,
                       completed_at=CURRENT_TIMESTAMP
                   WHERE verification_run_id=?""",
                (dispatch_res.error_code, dispatch_res.error_message, vrun_id),
            )
            if str(run["status"]) != "READY_FOR_REVIEW":
                transition_audit_run_status(
                    conn, arun_id, "VERIFICATION_FAILED", error=dispatch_res.error_message
                )
            conn.commit()
        return {
            "job_id": job_id,
            "audit_run_id": arun_id,
            "verification_run_id": vrun_id,
            "status": "FAILED",
            "attempt": attempt,
            "max_attempts": max_attempts,
            "error_code": dispatch_res.error_code,
            "error_message": dispatch_res.error_message,
        }

    def run_loop(
        self,
        *,
        once: bool = False,
        poll_interval_seconds: float = 5.0,
        max_iterations: int | None = None,
    ) -> list[dict[str, Any]]:
        """Run the persistent verifier worker loop with clean signal shutdown."""
        try:
            signal.signal(signal.SIGINT, self.request_stop)
            signal.signal(signal.SIGTERM, self.request_stop)
        except (ValueError, OSError):
            pass

        processed: list[dict[str, Any]] = []
        iterations = 0
        while not self._stop_requested:
            iterations += 1
            res = self.process_one_job()
            if res is not None:
                processed.append(res)
            if once:
                break
            if max_iterations is not None and iterations >= max_iterations:
                break
            if res is None and not self._stop_requested:
                time.sleep(max(0.05, float(poll_interval_seconds)))
        return processed

    def _write_manual_prompt_file(self, repo_path: Path, audit_run_id: str, prompt_text: str) -> Path:
        from runtime_discovery.redaction import redact_report_text

        base = repo_path if repo_path.is_dir() else self.app_home
        if base == repo_path:
            ensure_audit_dir_git_excluded(repo_path)
        target = base / ".antigravity-audit" / "reports" / audit_run_id / "manual-verification-prompt.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(redact_report_text(prompt_text), encoding="utf-8")
        return target


def recover_verification_job(
    db_path: Path,
    *,
    project_key: str,
    audit_run_id: str,
    action: str,
    verifier_conversation_id: str | None = None,
    candidate_finding_id: str | None = None,
    now: datetime | None = None,
    jsonl_path: Path | None = None,
) -> dict[str, Any]:
    """Deterministically recover blocked, uncertain, failed, or unverifiable verification states.

    Supported actions:
    - `attach-conversation`: Attach a known verifier conversation ID to a `DISPATCH_UNCERTAIN` or `BLOCKED_CONFIGURATION` job and move to `RUNNING`.
    - `requeue`: Explicitly reset a `BLOCKED_CONFIGURATION`, `DISPATCH_UNCERTAIN`, `RETRYABLE_FAILURE`, or `FAILED` job (or expired lease) to `QUEUED` for fresh dispatch while preserving prior attempt and conversation history.
    - `archive-unverifiable`: Explicitly archive an `UNVERIFIABLE` candidate finding under recovery policy so remaining verified findings can finalize.
    - `archive-run`: Archive the entire audit run when superseded or abandoned.
    """
    from db import _parse_timestamp, connect, record_event

    curr_now = now or datetime.now(timezone.utc)
    conn = connect(db_path)
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        run = conn.execute(
            "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
            (audit_run_id, project_key),
        ).fetchone()
        if not run:
            raise RuntimeError(f"Audit run '{audit_run_id}' not found for project '{project_key}'.")
        vrun = conn.execute(
            "SELECT * FROM audit_verification_runs WHERE audit_run_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (audit_run_id,),
        ).fetchone()
        if not vrun:
            raise RuntimeError(f"No verification run exists for audit run '{audit_run_id}'.")
        vrun_id = str(vrun["verification_run_id"])
        q_row = conn.execute(
            "SELECT * FROM verification_dispatch_queue WHERE verification_run_id=?",
            (vrun_id,),
        ).fetchone()

        if action == "attach-conversation":
            if not is_valid_conversation_id(verifier_conversation_id):
                raise ValueError("Valid --conversation-id is required for action 'attach-conversation'.")
            cid = str(verifier_conversation_id).strip()
            if run["agent_conversation_id"] and str(run["agent_conversation_id"]).strip() == cid:
                raise RuntimeError("verifier_conversation_id cannot match primary audit conversation.")
            if q_row is not None and str(q_row["status"]) in ("CLAIMED", "DISPATCHING"):
                lease_dt = _parse_timestamp(q_row["lease_expires_at"])
                if lease_dt is None or curr_now < lease_dt:
                    raise RuntimeError(
                        f"Cannot attach conversation while job '{q_row['job_id']}' holds an active non-expired "
                        f"{q_row['status']} lease owned by '{q_row['lease_owner']}'."
                    )
            conn.execute(
                """UPDATE verification_dispatch_queue
                   SET status='RUNNING', verifier_conversation_id=?,
                       lease_owner=NULL, lease_token=NULL,
                       last_error_code=NULL, last_error_message=NULL, updated_at=CURRENT_TIMESTAMP
                   WHERE verification_run_id=?""",
                (cid, vrun_id),
            )
            conn.execute(
                """UPDATE audit_verification_runs
                   SET status='RUNNING', verifier_conversation_id=?,
                       error_code=NULL, error_message=NULL, started_at=COALESCE(started_at, CURRENT_TIMESTAMP)
                   WHERE verification_run_id=?""",
                (cid, vrun_id),
            )
            transition_audit_run_status(conn, audit_run_id, "VERIFICATION_RUNNING", error="")
            record_event(
                conn,
                "VERIFICATION_JOB_RECOVERED_ATTACHED",
                project_key=project_key,
                run_id=audit_run_id,
                details={"verification_run_id": vrun_id, "verifier_conversation_id": cid},
                jsonl_path=jsonl_path,
            )
            conn.execute("COMMIT")
            return {
                "audit_run_id": audit_run_id,
                "verification_run_id": vrun_id,
                "action": action,
                "status": "VERIFICATION_RUNNING",
                "verifier_conversation_id": cid,
            }

        if action == "requeue":
            if q_row is not None:
                q_status = str(q_row["status"])
                if q_status in ("CLAIMED", "DISPATCHING"):
                    lease_dt = _parse_timestamp(q_row["lease_expires_at"])
                    if lease_dt is None or curr_now < lease_dt:
                        raise RuntimeError(
                            f"Cannot manually requeue job '{q_row['job_id']}': worker '{q_row['lease_owner']}' "
                            f"holds an active non-expired {q_status} lease until {q_row['lease_expires_at']}."
                        )
                elif q_status not in ("BLOCKED_CONFIGURATION", "DISPATCH_UNCERTAIN", "RETRYABLE_FAILURE", "FAILED"):
                    if str(vrun["status"]) not in ("FAILED", "BLOCKED", "UNCERTAIN", "STALE"):
                        raise RuntimeError(
                            f"Cannot manually requeue job '{q_row['job_id']}' in queue state '{q_status}' "
                            f"(verification run state '{vrun['status']}')."
                        )

            transition_audit_run_status(conn, audit_run_id, "RECOVERABLE")
            transition_audit_run_status(conn, audit_run_id, "VERIFICATION_PENDING", error="")
            existing_sub_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM finding_verification_results WHERE verification_run_id=?",
                    (vrun_id,),
                ).fetchone()[0]
                or 0
            )
            vrun_keys = vrun.keys()
            prior_sub_count = int(vrun["submission_count"] or 0) if "submission_count" in vrun_keys else 0
            prior_attempts = int(q_row["attempt_count"] or 0) if q_row else int(vrun["dispatch_attempt"] or 0)
            prior_conv = str(vrun["verifier_conversation_id"] or (q_row["verifier_conversation_id"] if q_row else "") or "").strip()

            if prior_sub_count >= 1 or existing_sub_count > 0 or prior_attempts > 0 or bool(prior_conv):
                conn.execute(
                    "UPDATE audit_verification_runs SET status='ARCHIVED', completed_at=CURRENT_TIMESTAMP WHERE verification_run_id=?",
                    (vrun_id,),
                )
                conn.execute(
                    """UPDATE verification_dispatch_queue
                       SET status='FAILED', lease_owner=NULL, lease_token=NULL,
                           last_error_code='SUPERSEDED_BY_REQUEUE', updated_at=CURRENT_TIMESTAMP
                       WHERE verification_run_id=?""",
                    (vrun_id,),
                )
                conn.execute(
                    """UPDATE candidate_findings
                       SET status='CANDIDATE', updated_at=CURRENT_TIMESTAMP
                       WHERE run_id=? AND status != 'ARCHIVED' AND canonical_finding_id IS NULL""",
                    (audit_run_id,),
                )
                suffix = uuid.uuid4().hex[:6]
                disc_suffix = "-DISC" if vrun_id.endswith("-DISC") else ""
                new_vrun_id = f"VRUN-{audit_run_id}-R{suffix}{disc_suffix}"
                new_job_id = f"VJOB-{audit_run_id}-R{suffix}{disc_suffix}"
                next_max_attempts = max(int(q_row["max_attempts"] or 3) if q_row else 3, prior_attempts + 1)
                conn.execute(
                    """INSERT INTO audit_verification_runs(
                        verification_run_id, audit_run_id, project_key,
                        snapshot_id, base_commit_sha, idempotency_key, status, dispatch_attempt
                    ) VALUES(?, ?, ?, ?, ?, ?, 'PENDING', ?)""",
                    (
                        new_vrun_id,
                        audit_run_id,
                        project_key,
                        vrun["snapshot_id"],
                        vrun["base_commit_sha"],
                        f"idem-requeue-{audit_run_id}-{suffix}",
                        prior_attempts,
                    ),
                )
                conn.execute(
                    """INSERT INTO verification_dispatch_queue(
                        job_id, audit_run_id, verification_run_id, project_key,
                        snapshot_id, idempotency_key, status, attempt_count, max_attempts
                    ) VALUES(?, ?, ?, ?, ?, ?, 'QUEUED', ?, ?)""",
                    (
                        new_job_id,
                        audit_run_id,
                        new_vrun_id,
                        project_key,
                        vrun["snapshot_id"],
                        f"idem-q-requeue-{audit_run_id}-{suffix}",
                        prior_attempts,
                        next_max_attempts,
                    ),
                )
                superseded_vrun_id = vrun_id
                vrun_id = new_vrun_id
                job_id_out: str | None = new_job_id
            else:
                superseded_vrun_id = None
                conn.execute(
                    """UPDATE verification_dispatch_queue
                       SET status='QUEUED',
                           lease_owner=NULL,
                           lease_token=NULL,
                           claimed_at=NULL,
                           lease_expires_at=NULL,
                           next_attempt_at=NULL,
                           last_error_code=NULL,
                           last_error_message=NULL,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE verification_run_id=?""",
                    (vrun_id,),
                )
                conn.execute(
                    """UPDATE audit_verification_runs
                       SET status='PENDING', error_code=NULL, error_message=NULL
                       WHERE verification_run_id=?""",
                    (vrun_id,),
                )
                job_id_out = str(q_row["job_id"]) if q_row else None
            record_event(
                conn,
                "VERIFICATION_JOB_REQUEUED",
                project_key=project_key,
                run_id=audit_run_id,
                details={
                    "verification_run_id": vrun_id,
                    "superseded_verification_run_id": superseded_vrun_id,
                    "prior_attempts": prior_attempts,
                    "prior_conversation_id": prior_conv or None,
                    "job_id": job_id_out,
                },
                jsonl_path=jsonl_path,
            )
            conn.execute("COMMIT")
            return {
                "audit_run_id": audit_run_id,
                "verification_run_id": vrun_id,
                "superseded_verification_run_id": superseded_vrun_id,
                "preserved_attempt_count": prior_attempts,
                "preserved_verifier_conversation_id": prior_conv or None,
                "job_id": job_id_out,
                "action": action,
                "status": "VERIFICATION_PENDING",
                "queue_status": "QUEUED",
            }

        if action == "archive-unverifiable":
            if not candidate_finding_id:
                raise ValueError("--candidate-id is required for action 'archive-unverifiable'.")
            cand = conn.execute(
                "SELECT * FROM candidate_findings WHERE run_id=? AND candidate_finding_id=?",
                (audit_run_id, candidate_finding_id),
            ).fetchone()
            if not cand:
                raise RuntimeError(f"Candidate finding '{candidate_finding_id}' not found in run '{audit_run_id}'.")
            conn.execute(
                "UPDATE candidate_findings SET status='ARCHIVED', updated_at=CURRENT_TIMESTAMP WHERE candidate_id=?",
                (cand["candidate_id"],),
            )
            if run["status"] == "VERIFICATION_FAILED":
                transition_audit_run_status(conn, audit_run_id, "VERIFICATION_RUNNING", error="")
                conn.execute(
                    "UPDATE audit_verification_runs SET status='RUNNING', error_code=NULL, error_message=NULL WHERE verification_run_id=?",
                    (vrun_id,),
                )
            record_event(
                conn,
                "UNVERIFIABLE_CANDIDATE_ARCHIVED",
                project_key=project_key,
                run_id=audit_run_id,
                details={"candidate_finding_id": candidate_finding_id, "verification_run_id": vrun_id},
                jsonl_path=jsonl_path,
            )
            conn.execute("COMMIT")
            return {
                "audit_run_id": audit_run_id,
                "verification_run_id": vrun_id,
                "action": action,
                "archived_candidate_finding_id": candidate_finding_id,
            }

        if action == "archive-run":
            transition_audit_run_status(conn, audit_run_id, "ARCHIVED", finished=True)
            conn.execute(
                "UPDATE audit_verification_runs SET status='ARCHIVED', completed_at=CURRENT_TIMESTAMP WHERE verification_run_id=?",
                (vrun_id,),
            )
            conn.execute(
                "UPDATE verification_dispatch_queue SET status='FAILED', last_error_code='RUN_ARCHIVED', updated_at=CURRENT_TIMESTAMP WHERE verification_run_id=?",
                (vrun_id,),
            )
            conn.execute("COMMIT")
            return {
                "audit_run_id": audit_run_id,
                "verification_run_id": vrun_id,
                "action": action,
                "status": "ARCHIVED",
            }
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()

    raise ValueError(f"Unsupported recovery action: '{action}'")


def build_verifier_sidecar_spec(
    *,
    project_key: str,
    display_name: str,
    python_exe: str,
    cli_path: Path,
) -> dict[str, Any]:
    """Construct the documented Sidecar `command` process spec with `restart_policy: always`."""
    return {
        "description": f"Read-only second-pass verification worker for {display_name}",
        "command": python_exe,
        "args": [str(cli_path.resolve()), "verifier-worker", "--project", project_key],
        "restart_policy": "always",
        "display_name": f"{display_name} Audit Verifier",
    }


def configure_verifier_sidecar(
    db_path: Path,
    *,
    project_key: str,
    sidecar_root: Path,
    config_path: Path,
    cli_path: Path,
    python_exe: str | None = None,
    enable: bool = False,
    register_in_config: bool = False,
) -> dict[str, Any]:
    """Generate or toggle the per-project verifier worker Sidecar safely.

    Never hardcodes a global Project ID. Uses the project's registered `antigravity_project_id`.
    Activation remains disabled unless `enable=True` is explicitly requested.
    """
    from cli import ensure_json_object, write_json_atomic
    from db import connect

    with connect(db_path) as conn:
        proj = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchone()
        if not proj:
            raise RuntimeError(f"Project '{project_key}' not found.")

    ag_project_id = str(proj["antigravity_project_id"] or "").strip()
    if enable and (not ag_project_id or ag_project_id.upper() in ("PENDING", "UNKNOWN")):
        raise RuntimeError(
            f"Cannot enable verifier Sidecar for '{project_key}': Antigravity Project ID is '{ag_project_id or 'MISSING'}'."
        )

    sidecar_id = f"{project_key}-verifier"
    sidecar_dir = sidecar_root / sidecar_id
    sidecar_file = sidecar_dir / "sidecar.json"
    py = python_exe or sys.executable
    spec = build_verifier_sidecar_spec(
        project_key=project_key,
        display_name=str(proj["display_name"]),
        python_exe=py,
        cli_path=cli_path,
    )

    if sidecar_file.exists():
        existing = json.loads(sidecar_file.read_text(encoding="utf-8-sig"))
        if existing != spec:
            write_json_atomic(sidecar_file, spec)
    else:
        write_json_atomic(sidecar_file, spec)

    config_updated = False
    if enable or register_in_config or config_path.exists():
        cfg = ensure_json_object(config_path)
        sidecars = cfg.get("sidecars")
        if enable or register_in_config or (isinstance(sidecars, dict) and sidecar_id in sidecars):
            if not isinstance(sidecars, dict):
                sidecars = {}
                cfg["sidecars"] = sidecars
            if ag_project_id and ag_project_id.upper() not in ("PENDING", "UNKNOWN"):
                sidecars[sidecar_id] = {
                    "enabled": bool(enable),
                    "projectId": ag_project_id,
                }
                write_json_atomic(config_path, cfg)
                config_updated = True

    return {
        "project_key": project_key,
        "sidecar_id": sidecar_id,
        "sidecar_file": str(sidecar_file),
        "antigravity_project_id": ag_project_id,
        "enabled": bool(enable),
        "config_updated": config_updated,
    }


def generate_all_verifier_sidecars(
    db_path: Path,
    *,
    sidecar_root: Path,
    config_path: Path,
    cli_path: Path,
    python_exe: str | None = None,
    enable: bool = False,
    register_in_config: bool = False,
) -> dict[str, Any]:
    """Generate verifier Sidecars for all registered projects using real `projects` schema columns.

    Projects with missing or PENDING `antigravity_project_id` are skipped with explicit warnings.
    By default `enable=False` and `register_in_config=False` so existing `config.json` is never modified unless opted in.
    """
    from db import connect

    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT project_key, display_name, antigravity_project_id FROM projects ORDER BY project_key"
        ).fetchall()

    generated: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for row in rows:
        pkey = str(row["project_key"])
        ag_pid = str(row["antigravity_project_id"] or "").strip()
        if not ag_pid or ag_pid.upper() in ("PENDING", "UNKNOWN"):
            skipped.append({
                "project_key": pkey,
                "antigravity_project_id": ag_pid or None,
                "reason": (
                    f"Project '{pkey}' has missing or PENDING antigravity_project_id ('{ag_pid or 'MISSING'}'); "
                    "skipping verifier Sidecar generation."
                ),
            })
            continue
        res = configure_verifier_sidecar(
            db_path,
            project_key=pkey,
            sidecar_root=sidecar_root,
            config_path=config_path,
            cli_path=cli_path,
            python_exe=python_exe,
            enable=enable,
            register_in_config=register_in_config,
        )
        generated.append(res)

    return {
        "generated_count": len(generated),
        "skipped_count": len(skipped),
        "generated": generated,
        "skipped": skipped,
    }


def get_verifier_worker_status_broker(
    broker_client: BrokerClient,
    *,
    project_key: str | None = None,
    sidecar_root: Path | None = None,
    config_path: Path | None = None,
) -> dict[str, Any]:
    """Inspect verification worker queue status exclusively via Broker IPC. Zero direct SQLite calls."""
    s_root = sidecar_root or (Path.home() / ".gemini" / "config" / "sidecars")
    c_path = config_path or (Path.home() / ".gemini" / "config" / "config.json")
    cfg_sidecars: dict[str, Any] = {}
    if c_path.is_file():
        try:
            raw_cfg = json.loads(c_path.read_text(encoding="utf-8-sig"))
            if isinstance(raw_cfg, dict) and isinstance(raw_cfg.get("sidecars"), dict):
                cfg_sidecars = raw_cfg["sidecars"]
        except (OSError, json.JSONDecodeError):
            pass

    raw = broker_client.get_verifier_worker_status(project_key=project_key)
    p_rows = raw.get("projects", [])
    q_rows = raw.get("jobs", [])

    projects_info: list[dict[str, Any]] = []
    for p in p_rows:
        pkey = str(p["project_key"])
        sid = f"{pkey}-verifier"
        s_file = s_root / sid / "sidecar.json"
        cfg_entry = cfg_sidecars.get(sid) if isinstance(cfg_sidecars, dict) else None
        projects_info.append({
            "project_key": pkey,
            "antigravity_project_id": p.get("antigravity_project_id"),
            "sidecar_id": sid,
            "sidecar_file_exists": s_file.is_file(),
            "sidecar_enabled": bool(cfg_entry.get("enabled")) if isinstance(cfg_entry, dict) else False,
            "configured_project_id": cfg_entry.get("projectId") if isinstance(cfg_entry, dict) else None,
        })

    counts_by_status: dict[str, int] = {st: 0 for st in ALLOWED_QUEUE_STATUSES}
    for q in q_rows:
        st = str(q.get("status", ""))
        counts_by_status[st] = counts_by_status.get(st, 0) + 1

    return {
        "projects": projects_info,
        "queue_counts": counts_by_status,
        "jobs": q_rows,
    }


def get_verifier_worker_status(
    db_path: Path | None = None,
    *,
    project_key: str | None = None,
    sidecar_root: Path | None = None,
    config_path: Path | None = None,
    broker_client: BrokerClient | None = None,
) -> dict[str, Any]:
    """Inspect verification worker queue status and per-project Sidecar enablement.

    When `broker_client` is provided, routes exclusively through Broker IPC with zero direct SQLite access.
    """
    if broker_client is not None:
        return get_verifier_worker_status_broker(
            broker_client,
            project_key=project_key,
            sidecar_root=sidecar_root,
            config_path=config_path,
        )

    if db_path is None:
        raise ValueError("Either db_path or broker_client must be provided to get_verifier_worker_status.")

    from db import connect

    s_root = sidecar_root or (Path.home() / ".gemini" / "config" / "sidecars")
    c_path = config_path or (Path.home() / ".gemini" / "config" / "config.json")
    cfg_sidecars: dict[str, Any] = {}
    if c_path.is_file():
        try:
            raw = json.loads(c_path.read_text(encoding="utf-8-sig"))
            if isinstance(raw, dict) and isinstance(raw.get("sidecars"), dict):
                cfg_sidecars = raw["sidecars"]
        except (OSError, json.JSONDecodeError):
            pass

    with connect(db_path) as conn:
        if project_key:
            p_rows = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchall()
            q_rows = conn.execute(
                "SELECT * FROM verification_dispatch_queue WHERE project_key=? ORDER BY created_at DESC, rowid DESC LIMIT 50",
                (project_key,),
            ).fetchall()
        else:
            p_rows = conn.execute("SELECT * FROM projects ORDER BY project_key").fetchall()
            q_rows = conn.execute(
                "SELECT * FROM verification_dispatch_queue ORDER BY created_at DESC, rowid DESC LIMIT 50"
            ).fetchall()

    projects_info: list[dict[str, Any]] = []
    for p in p_rows:
        pkey = str(p["project_key"])
        sid = f"{pkey}-verifier"
        s_file = s_root / sid / "sidecar.json"
        cfg_entry = cfg_sidecars.get(sid) if isinstance(cfg_sidecars, dict) else None
        projects_info.append({
            "project_key": pkey,
            "antigravity_project_id": p["antigravity_project_id"],
            "sidecar_id": sid,
            "sidecar_file_exists": s_file.is_file(),
            "sidecar_enabled": bool(cfg_entry.get("enabled")) if isinstance(cfg_entry, dict) else False,
            "configured_project_id": cfg_entry.get("projectId") if isinstance(cfg_entry, dict) else None,
        })

    counts_by_status: dict[str, int] = {st: 0 for st in ALLOWED_QUEUE_STATUSES}
    for q in q_rows:
        st = str(q["status"])
        counts_by_status[st] = counts_by_status.get(st, 0) + 1

    return {
        "projects": projects_info,
        "queue_counts": counts_by_status,
        "jobs": [dict(q) for q in q_rows],
    }


def get_quality_report_broker(
    broker_client: BrokerClient,
    *,
    project_key: str | None = None,
    audit_run_id: str | None = None,
) -> dict[str, Any]:
    """Return Phase 8 audit quality metrics exclusively via Broker IPC. Zero direct SQLite calls."""
    return broker_client.get_quality_report(
        project_key=project_key,
        audit_run_id=audit_run_id,
    )


def get_quality_report(
    db_path: Path | None = None,
    *,
    project_key: str | None = None,
    audit_run_id: str | None = None,
    broker_client: BrokerClient | None = None,
) -> dict[str, Any]:
    """Return Phase 8 audit quality metrics and historical comparisons.

    When `broker_client` is provided, routes exclusively through Broker IPC with zero direct SQLite access.
    """
    if broker_client is not None:
        return get_quality_report_broker(
            broker_client,
            project_key=project_key,
            audit_run_id=audit_run_id,
        )

    if db_path is None:
        raise ValueError("Either db_path or broker_client must be provided to get_quality_report.")

    from db import connect

    with connect(db_path) as conn:
        sql = "SELECT * FROM audit_quality_metrics WHERE 1=1"
        params: list[Any] = []
        if project_key:
            sql += " AND project_key=?"
            params.append(project_key)
        if audit_run_id:
            sql += " AND audit_run_id=?"
            params.append(audit_run_id)
        sql += " ORDER BY metric_id DESC LIMIT 100"
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]

    if not rows:
        return {
            "run_count": 0,
            "summary": {
                "total_primary_candidates": 0,
                "confirmed_findings": 0,
                "partially_confirmed_findings": 0,
                "rejected_findings": 0,
                "unverifiable_findings": 0,
                "evidence_validation_failures": 0,
                "fabricated_reference_detections": 0,
                "severity_changes": 0,
                "confidence_changes": 0,
                "remediation_proposals_rejected": 0,
                "dispatch_failures": 0,
                "actual_subagent_invocations": 0,
                "avg_finding_precision": None,
                "avg_evidence_accuracy": None,
                "avg_false_positive_rate": None,
                "avg_severity_calibration_rate": None,
                "avg_remediation_safety_rate": None,
            },
            "history": [],
        }

    n = len(rows)
    summary = {
        "total_primary_candidates": sum(int(r["total_primary_candidates"]) for r in rows),
        "verifier_discovered_candidates": sum(int(r["verifier_discovered_candidates"]) for r in rows),
        "confirmed_findings": sum(int(r["confirmed_findings"]) for r in rows),
        "partially_confirmed_findings": sum(int(r["partially_confirmed_findings"]) for r in rows),
        "rejected_findings": sum(int(r["rejected_findings"]) for r in rows),
        "unverifiable_findings": sum(int(r["unverifiable_findings"]) for r in rows),
        "evidence_validation_failures": sum(int(r["evidence_validation_failures"]) for r in rows),
        "fabricated_reference_detections": sum(int(r["fabricated_reference_detections"]) for r in rows),
        "severity_changes": sum(int(r["severity_changes"]) for r in rows),
        "confidence_changes": sum(int(r["confidence_changes"]) for r in rows),
        "remediation_proposals_rejected": sum(int(r["remediation_proposals_rejected"]) for r in rows),
        "dispatch_failures": sum(int(r["dispatch_failures"]) for r in rows),
        "actual_subagent_invocations": sum(int(r["actual_subagent_invocations"]) for r in rows),
        "avg_finding_precision": round(sum(float(r["finding_precision"] or 0.0) for r in rows) / n, 4),
        "avg_evidence_accuracy": round(sum(float(r["evidence_accuracy"] or 0.0) for r in rows) / n, 4),
        "avg_false_positive_rate": round(sum(float(r["false_positive_rate"] or 0.0) for r in rows) / n, 4),
        "avg_severity_calibration_rate": round(sum(float(r["severity_calibration_rate"] or 0.0) for r in rows) / n, 4),
        "avg_remediation_safety_rate": round(sum(float(r["remediation_safety_rate"] or 0.0) for r in rows) / n, 4),
    }
    return {
        "run_count": n,
        "summary": summary,
        "history": rows,
    }

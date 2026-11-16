"""Checkpoint security, validation, and content-addressed restoration module.

Enforces strict relative path traversal defense, case-collision detection,
reparse point/symlink defenses, content-addressed SHA-256 verification, and
safe staged restoration without partial-restore corruptions.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path, PurePosixPath
from typing import Any

from broker.constants import (
    ERR_CHECKPOINT_INTEGRITY,
    ERR_CHECKPOINT_QUARANTINED,
    ERR_SCOPE_VIOLATION,
)
from broker.exceptions import BrokerSecurityError

_RESERVED_WINDOWS_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
}


def is_link_or_reparse_point(path: Path) -> bool:
    """Check if a path is a symlink, junction, or reparse point."""
    if path.is_symlink():
        return True
    if hasattr(path, "is_junction") and path.is_junction():
        return True
    try:
        stat_res = os.lstat(path)
        if getattr(stat_res, "st_file_attributes", 0) & 0x0400:  # FILE_ATTRIBUTE_REPARSE_POINT
            return True
    except OSError:
        pass
    return False


def validate_safe_relative_path(rel_path: str | Path) -> str:
    """Validate that a path is strictly relative and safe from directory traversal.

    Rejects:
    - Absolute paths (POSIX / or Windows C:\\)
    - UNC and Windows device paths (\\\\.\\, //?/)
    - Parent directory traversal components (..)
    - Empty or whitespace-only paths
    - NUL bytes
    - Reserved Windows device names (CON, NUL, AUX, etc.)
    """
    path_str = str(rel_path).strip().replace("\\", "/")
    if not path_str:
        raise BrokerSecurityError("Path cannot be empty.", code=ERR_CHECKPOINT_INTEGRITY)
    if "\0" in path_str:
        raise BrokerSecurityError("Path cannot contain NUL bytes.", code=ERR_CHECKPOINT_INTEGRITY)
    if path_str.startswith("/") or path_str.startswith("//"):
        raise BrokerSecurityError(f"Absolute or UNC paths are prohibited: '{path_str}'", code=ERR_CHECKPOINT_INTEGRITY)
    if len(path_str) >= 2 and path_str[1] == ":":
        raise BrokerSecurityError(f"Windows drive letters are prohibited: '{path_str}'", code=ERR_CHECKPOINT_INTEGRITY)
    if path_str.startswith("\\\\") or path_str.startswith("//"):
        raise BrokerSecurityError(f"Device paths are prohibited: '{path_str}'", code=ERR_CHECKPOINT_INTEGRITY)

    posix = PurePosixPath(path_str)
    for part in posix.parts:
        lower_part = part.lower().split(".")[0]
        if part == "..":
            raise BrokerSecurityError(f"Directory traversal component '..' prohibited: '{path_str}'", code=ERR_CHECKPOINT_INTEGRITY)
        if part == ".":
            continue
        if lower_part in _RESERVED_WINDOWS_NAMES:
            raise BrokerSecurityError(f"Reserved Windows device name prohibited: '{part}' in '{path_str}'", code=ERR_CHECKPOINT_INTEGRITY)

    return posix.as_posix()


def validate_checkpoint_manifest(manifest: dict[str, Any]) -> tuple[bool, str]:
    """Validate structure, schema, paths, and case-collision resistance of a checkpoint manifest."""
    required_keys = {"checkpoint_id", "exec_id", "finding_id", "created_at", "files"}
    missing = required_keys - set(manifest.keys())
    if missing:
        return False, f"Manifest missing required keys: {missing}"

    files = manifest.get("files")
    if not isinstance(files, dict):
        return False, "Manifest 'files' field must be a dictionary of relative paths to SHA-256 hashes"

    seen_lower: set[str] = set()
    for rel_path, expected_hash in files.items():
        try:
            norm_rel = validate_safe_relative_path(rel_path)
        except BrokerSecurityError as exc:
            return False, f"Path security violation: {exc}"

        lower = norm_rel.lower()
        if lower in seen_lower:
            return False, f"Case collision detected in manifest for path '{norm_rel}'"
        seen_lower.add(lower)

        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            return False, f"Invalid SHA-256 hash for path '{norm_rel}'"

    return True, "Manifest valid"


def validate_checkpoint_content_integrity(manifest_path: Path) -> tuple[bool, str, dict[str, Any]]:
    """Validate all files in checkpoint against manifest hashes before touching any worktree file."""
    if not manifest_path.is_file():
        return False, f"Manifest file '{manifest_path}' does not exist.", {}

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Failed to parse checkpoint manifest JSON: {exc}", {}

    valid_manifest, msg = validate_checkpoint_manifest(manifest)
    if not valid_manifest:
        return False, msg, {}

    files_dir = manifest_path.parent / "files"
    if not files_dir.is_dir():
        return False, f"Checkpoint files directory '{files_dir}' does not exist.", {}

    expected_files: dict[str, str] = manifest["files"]
    total_bytes = 0
    actual_file_count = 0

    for rel_posix, expected_hash in expected_files.items():
        file_path = files_dir / rel_posix
        if not _contained_without_links(files_dir, rel_posix):
            return False, f"Checkpoint path escapes the checkpoint or crosses a link: '{rel_posix}'", {}
        if not file_path.is_file():
            return False, f"Checkpoint file missing: '{rel_posix}'", {}
        if is_link_or_reparse_point(file_path):
            return False, f"Checkpoint file cannot be a symlink or reparse point: '{rel_posix}'", {}

        try:
            content = file_path.read_bytes()
        except OSError as exc:
            return False, f"Failed to read checkpoint file '{rel_posix}': {exc}", {}

        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != expected_hash:
            return False, f"Content-addressed hash mismatch for '{rel_posix}': expected {expected_hash}, got {actual_hash}", {}

        total_bytes += len(content)
        actual_file_count += 1

    metrics = {
        "checkpoint_id": manifest["checkpoint_id"],
        "file_count": actual_file_count,
        "total_bytes": total_bytes,
        "manifest_path": str(manifest_path),
    }
    return True, "Checkpoint content integrity verified", metrics


def _contained_without_links(root: Path, rel_posix: str, *, allow_leaf_link: bool = False) -> bool:
    """True if ``root/rel_posix`` stays inside ``root`` and no existing component below ``root`` (directory
    or file) is a symlink/junction -- a linked intermediate directory would redirect reads/writes outside."""
    root_abs = Path(os.path.abspath(str(root)))
    target = Path(os.path.abspath(str(root_abs / rel_posix)))
    try:
        rel_parts = target.relative_to(root_abs).parts
    except ValueError:
        return False
    cur = root_abs
    for i, part in enumerate(rel_parts):
        cur = cur / part
        is_leaf = i == len(rel_parts) - 1
        if os.path.lexists(cur) and is_link_or_reparse_point(cur):
            if is_leaf and allow_leaf_link:
                return True  # the caller replaces the link itself (unlink, then write a regular file)
            return False
    try:
        return target.resolve().is_relative_to(root_abs.resolve())
    except OSError:
        return False


def safe_restore_checkpoint(
    worktree_path: Path,
    manifest_path: Path,
    *,
    status: str = "ACTIVE",
    scope_limit: list[str] | None = None,
) -> dict[str, Any]:
    """Safely restore isolated worktree to pre-finding checkpoint state.

    Enforces:
    - Pre-restoration content-addressed validation of ALL files.
    - Zero write operations if any file fails validation (no partial restore).
    - Quarantine rejection (quarantined checkpoints cannot be restored).
    - Scope limit enforcement if configured.
    """
    worktree_path = Path(worktree_path)
    manifest_path = Path(manifest_path)
    # Detect if arguments were passed in reverse order (manifest_path, worktree_path)
    if not manifest_path.exists() and worktree_path.exists() and (worktree_path.is_file() or str(worktree_path).endswith(".json")):
        worktree_path, manifest_path = manifest_path, worktree_path

    if status == "QUARANTINED":
        raise BrokerSecurityError(
            f"Cannot restore checkpoint '{manifest_path.parent.name}': status is QUARANTINED.",
            code=ERR_CHECKPOINT_QUARANTINED,
        )

    is_valid, err_msg, metrics = validate_checkpoint_content_integrity(manifest_path)
    if not is_valid:
        raise BrokerSecurityError(
            f"Checkpoint restoration rejected due to integrity violation: {err_msg}",
            code=ERR_CHECKPOINT_INTEGRITY,
        )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files_dir = manifest_path.parent / "files"
    expected_files: dict[str, str] = manifest["files"]

    if scope_limit is not None:
        norm_scope = {validate_safe_relative_path(s).lower() for s in scope_limit}
        for rel_posix in expected_files:
            if rel_posix.lower() not in norm_scope:
                raise BrokerSecurityError(
                    f"Checkpoint file '{rel_posix}' exceeds authorized scope limit.",
                    code=ERR_SCOPE_VIOLATION,
                )

    # Pre-read all file bytes in memory before touching worktree
    staged_payload: dict[str, bytes] = {}
    for rel_posix in expected_files:
        src = files_dir / rel_posix
        staged_payload[rel_posix] = src.read_bytes()

    # Discover current worktree files to remove files created during failed step
    current_worktree_files: list[str] = []
    linked_dirs: list[Path] = []
    for root_str, dirs, files in os.walk(worktree_path):
        if ".git" in dirs:
            dirs.remove(".git")
        root_path = Path(root_str)
        # Directory symlinks/junctions created during the failed step are never part of a checkpoint
        # (checkpoints hold regular files only): do not descend into them, remove them below.
        for d in list(dirs):
            if is_link_or_reparse_point(root_path / d):
                dirs.remove(d)
                linked_dirs.append(root_path / d)
        for f in files:
            if f == ".git":
                continue
            full = root_path / f
            try:
                rel = full.relative_to(worktree_path).as_posix()
                if rel != ".git" and not rel.startswith(".git/"):
                    current_worktree_files.append(rel)
            except ValueError:
                pass

    # Remove files that are not in the checkpoint manifest
    removed_count = 0
    for rel_posix in set(current_worktree_files) - set(expected_files.keys()):
        if rel_posix == ".git" or rel_posix.startswith(".git/"):
            continue
        target = worktree_path / rel_posix
        if os.path.lexists(target) and _contained_without_links(worktree_path, rel_posix, allow_leaf_link=True):
            try:
                target.unlink()  # a leaf symlink is removed itself, never its target
                removed_count += 1
            except OSError:
                pass
    for link_dir in linked_dirs:
        try:
            if link_dir.is_symlink():
                link_dir.unlink()
            else:
                os.rmdir(link_dir)  # junction: removes the link, not the target directory's contents
            removed_count += 1
        except OSError as exc:
            raise BrokerSecurityError(
                f"Cannot remove linked directory '{link_dir}' created in the worktree: {exc}",
                code=ERR_CHECKPOINT_INTEGRITY,
            ) from exc

    # Links created by the failed step are gone now; every destination must stay inside the worktree
    # without crossing a remaining symlink/junction directory.
    for rel_posix in expected_files:
        if not _contained_without_links(worktree_path, rel_posix, allow_leaf_link=True):
            raise BrokerSecurityError(
                f"Checkpoint restore target escapes the worktree or crosses a link: '{rel_posix}'",
                code=ERR_CHECKPOINT_INTEGRITY,
            )

    # Write staged bytes to worktree
    restored_count = 0
    for rel_posix, raw_bytes in staged_payload.items():
        dst = worktree_path / rel_posix
        if dst.is_dir() and not is_link_or_reparse_point(dst):
            shutil.rmtree(dst)  # the failed step replaced a checkpointed file with a directory
        if is_link_or_reparse_point(dst):
            try:
                dst.unlink()
            except OSError as exc:
                # Writing through a surviving link would modify a file outside the worktree.
                raise BrokerSecurityError(
                    f"Cannot replace link '{rel_posix}' during checkpoint restore: {exc}",
                    code=ERR_CHECKPOINT_INTEGRITY,
                ) from exc
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(raw_bytes)
        restored_count += 1

    return {
        "restored": True,
        "checkpoint_id": manifest["checkpoint_id"],
        "files_restored": restored_count,
        "restored_files_count": restored_count,
        "files_removed": removed_count,
        "total_bytes": metrics["total_bytes"],
    }

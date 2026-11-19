"""Pytest configuration for Windows Python 3.15 symlink cleanup compatibility."""
from pathlib import Path

try:
    import _pytest.pathlib

    _ORIG_CLEANUP = _pytest.pathlib.cleanup_dead_symlinks

    def _safe_cleanup(root: Path) -> None:
        try:
            _ORIG_CLEANUP(root)
        except PermissionError:
            pass

    _pytest.pathlib.cleanup_dead_symlinks = _safe_cleanup
except Exception:
    pass


# Windows Hello / TCB, TPM-CNG key custody and Session-0 Windows-service tests (B4-A / B4-B) are disabled:
# those subsystems are not wired into the live stdio path, and the tests create real CNG/TPM keys,
# NTFS ACLs under C:\ProgramData or need Administrator rights. Opt back in explicitly with
# AUDITOR_RUN_B4_TESTS=1 on a machine prepared for them.
import os as _os
import tempfile as _tempfile

# Tests must never append to a real installation's logs/audit-events.jsonl (code paths that do not pass an
# explicit jsonl_path fall back to <ANTIGRAVITY_AUDITOR_HOME>/logs). Always use a throw-away home.
_os.environ["ANTIGRAVITY_AUDITOR_HOME"] = _tempfile.mkdtemp(prefix="auditor-test-home-")
_os.environ.setdefault("ANTIGRAVITY_AUDITOR_SKIP_CATALOG_SYNC", "1")  # never run the real `agy models`
_os.environ.setdefault("ANTIGRAVITY_AUDITOR_PRIMARY_PASSES", "1")  # legacy single-pass tests; multi-pass has its own

collect_ignore_glob = [] if _os.environ.get("AUDITOR_RUN_B4_TESTS") == "1" else ["test_b4*.py"]

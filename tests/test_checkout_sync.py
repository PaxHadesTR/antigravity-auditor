"""Before an audit (delivery modes pull_request / auto_merge) the clean default-branch checkout is fast-forwarded to
origin and merged audit-fix branches are deleted; nothing is touched while work is in progress or local work exists."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from checkout_sync import commits_behind_origin, sync_checkout  # noqa: E402
from db import connect, initialize  # noqa: E402
from test_auto_delivery import _insert  # noqa: E402

FIX = "audit-fix/r1-abc"


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True).stdout.strip()


def _ident(repo: Path) -> None:
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")


@pytest.fixture()
def env(tmp_path: Path) -> dict[str, Any]:
    remote = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
    repo = tmp_path / "repo"
    subprocess.run(["git", "clone", "-q", str(remote), str(repo)], check=True, capture_output=True)
    _ident(repo)
    _git(repo, "switch", "-q", "-c", "main")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    _git(repo, "push", "-q", "-u", "origin", "main")
    # The fix branch is pushed and merged on "GitHub" (another clone), the local checkout stays behind.
    _git(repo, "switch", "-q", "-c", FIX)
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "audit(F1): fix")
    _git(repo, "push", "-q", "origin", FIX)
    _git(repo, "switch", "-q", "main")
    other = tmp_path / "github"
    subprocess.run(["git", "clone", "-q", str(remote), str(other)], check=True, capture_output=True)
    _ident(other)
    _git(other, "merge", "--no-ff", "-q", "-m", "Merge pull request #1", f"origin/{FIX}")
    _git(other, "push", "-q", "origin", "main")
    _git(repo, "remote", "set-head", "origin", "main")

    db = tmp_path / "database" / "auditor.db"
    initialize(db)
    with connect(db) as conn:
        conn.execute("INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id, delivery_mode) "
                     "VALUES('p', 'P', ?, 'ag', 'pull_request')", (str(repo),))
        _insert(conn, "audit_runs", {"run_id": "R1", "project_key": "p", "status": "COMPLETED"})
        _insert(conn, "execution_approvals", {"approval_id": "A1", "project_key": "p", "run_id": "R1",
                                              "status": "CONSUMED", "expires_at": "2999-01-01T00:00:00+00:00"})
        _insert(conn, "execution_runs", {"exec_id": "E1", "project_key": "p", "run_id": "R1", "approval_id": "A1",
                                         "status": "COMPLETED", "review_branch": FIX})
        conn.commit()
    return {"db": db, "repo": repo, "remote": remote}


def _remote_main(env: dict[str, Any]) -> str:
    return _git(env["remote"], "rev-parse", "refs/heads/main")


def test_clean_checkout_is_pulled_and_merged_fix_branch_deleted(env: dict[str, Any]) -> None:
    assert commits_behind_origin(env["repo"]) == 2  # the fix commit and the merge commit
    out = sync_checkout(env["db"], "p", manual=False)
    assert out["status"] == "PULLED" and out["behind"] == 2, out
    assert _git(env["repo"], "rev-parse", "HEAD") == _remote_main(env)
    assert out["deleted_local"] == [FIX] and out["deleted_remote"] == [FIX]
    assert not _git(env["repo"], "branch", "--list", FIX) and not _git(env["remote"], "branch", "--list", FIX)
    with connect(env["db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='CHECKOUT_SYNC'").fetchone()[0] == 1


@pytest.mark.parametrize("setup, reason", [
    (lambda r: (r / "a.py").write_text("x = 9\n", encoding="utf-8"), "uncommitted changes"),
    (lambda r: _git(r, "switch", "-q", "-c", "feature"), "is on 'feature'"),
    (lambda r: (_git(r, "commit", "-q", "--allow-empty", "-m", "local")), "local commit"),
])
def test_local_work_is_never_touched(env: dict[str, Any], setup: Any, reason: str) -> None:
    setup(env["repo"])
    head = _git(env["repo"], "rev-parse", "HEAD")
    out = sync_checkout(env["db"], "p", manual=False)
    assert out["status"] == "BEHIND_NOT_UPDATED" and reason in out["reason"], out
    assert _git(env["repo"], "rev-parse", "HEAD") == head


def test_unmerged_or_foreign_branches_are_kept(env: dict[str, Any]) -> None:
    _git(env["repo"], "switch", "-q", "-c", "audit-fix/unmerged")
    _git(env["repo"], "commit", "-q", "--allow-empty", "-m", "wip")
    _git(env["repo"], "switch", "-q", "main")
    _git(env["repo"], "branch", "audit-fix/not-ours", "main")  # merged, but not created by the auditor
    with connect(env["db"]) as conn:
        _insert(conn, "execution_runs", {"exec_id": "E2", "project_key": "p", "run_id": "R1", "approval_id": "A1",
                                         "status": "COMPLETED", "review_branch": "audit-fix/unmerged"})
        conn.commit()
    out = sync_checkout(env["db"], "p", manual=False)
    assert out["deleted_local"] == [FIX]
    assert _git(env["repo"], "branch", "--list", "audit-fix/unmerged") and _git(env["repo"], "branch", "--list",
                                                                                  "audit-fix/not-ours")


@pytest.mark.parametrize("status, manual, skipped", [
    ("VERIFICATION_PENDING", True, True),
    ("READY_FOR_REVIEW", False, True),
    ("READY_FOR_REVIEW", True, False),  # a manual audit replaces the waiting report: current code is wanted
])
def test_busy_project_is_left_alone(env: dict[str, Any], status: str, manual: bool, skipped: bool) -> None:
    with connect(env["db"]) as conn:
        conn.execute("UPDATE audit_runs SET status=? WHERE run_id='R1'", (status,))
        conn.commit()
    head = _git(env["repo"], "rev-parse", "HEAD")
    out = sync_checkout(env["db"], "p", manual=manual)
    assert (out["status"] == "SKIPPED") is skipped, out
    assert (_git(env["repo"], "rev-parse", "HEAD") == head) is skipped


def test_local_delivery_mode_is_not_synced(env: dict[str, Any]) -> None:
    with connect(env["db"]) as conn:
        conn.execute("UPDATE projects SET delivery_mode='local'")
        conn.commit()
    assert sync_checkout(env["db"], "p", manual=True)["status"] == "SKIPPED"
    assert commits_behind_origin(env["repo"]) == 2


@pytest.mark.parametrize("mode, expected", [("pull_request", "STARTED"), ("local", "NO_CHANGES")])
def test_chat_audit_is_not_skipped_while_github_is_ahead(env: dict[str, Any], tmp_path: Path, mode: str,
                                                        expected: str) -> None:
    import os

    from mcp_server import AuditorMCPDispatcher
    from verification import compute_clean_working_tree_hash

    head = _git(env["repo"], "rev-parse", "HEAD")
    with connect(env["db"]) as conn:
        conn.execute("UPDATE projects SET delivery_mode=?", (mode,))
        conn.execute("UPDATE audit_runs SET base_commit=?, working_tree_hash=? WHERE run_id='R1'",
                     (head, compute_clean_working_tree_hash(env["repo"])))
        conn.commit()
    d = AuditorMCPDispatcher(db_path=env["db"], app_home=tmp_path)
    d.audit_spawn = lambda command, *, env, log_path: os.getpid()
    res = d.call_tool("auditor_audit_now", {"project_key": "p"})
    assert res["status"] == expected, res

"""auto_merge delivery (push, PR, CI, merge, local sync) with a real local bare remote and a fake `gh`;
plus the private pytest --basetemp of the control plane's test run."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import auto_delivery  # noqa: E402
from ci_check import _with_private_pytest_basetemp, run_project_tests  # noqa: E402
from db import connect, initialize  # noqa: E402
from project_settings import get_settings, set_settings  # noqa: E402

BRANCH = "audit-fix/r1-abc"


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True).stdout.strip()


def _ident(repo: Path) -> None:
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")


def _insert(conn: Any, table: str, row: dict[str, Any]) -> None:
    info = {r[1]: r for r in conn.execute(f"PRAGMA table_info({table})")}
    for name, col in info.items():
        if col[3] and col[4] is None and name not in row and not col[5]:
            row[name] = "x"
    row = {k: v for k, v in row.items() if k in info}
    conn.execute(f"INSERT INTO {table}({','.join(row)}) VALUES({','.join('?' for _ in row)})", tuple(row.values()))


class FakeGh:
    def __init__(self, remote: Path, tmp: Path) -> None:
        self.remote, self.tmp = remote, tmp
        self.calls: list[list[str]] = []
        self.checks: list[list[dict[str, str]]] = [[{"name": "test", "bucket": "pass", "state": "SUCCESS"}]]
        self.head: str | None = None
        self.mergeable = "MERGEABLE"
        self.prs: list[dict[str, Any]] = []
        self.base = "main"
        self.checks_error: str | None = None

    def __call__(self, cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
        if cmd[0] != "gh":
            return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
        self.calls.append(cmd)
        sub = cmd[1:3]

        def ok(out: Any) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess(cmd, 0, out if isinstance(out, str) else json.dumps(out), "")

        if sub == ["repo", "view"]:
            return ok({"nameWithOwner": "me/proj", "defaultBranchRef": {"name": "main"}})
        if sub == ["pr", "list"]:
            return ok(self.prs)
        if sub == ["pr", "create"]:
            self.prs = [{"number": 7, "url": "https://github.com/me/proj/pull/7", "isCrossRepository": False}]
            return ok("https://github.com/me/proj/pull/7\n")
        if sub == ["pr", "checks"] and self.checks_error:
            return subprocess.CompletedProcess(cmd, 1, "", self.checks_error)
        if sub == ["pr", "checks"]:
            return ok(self.checks.pop(0) if len(self.checks) > 1 else self.checks[0])
        if sub == ["pr", "view"]:
            head = self.head or _git(self.remote, "rev-parse", f"refs/heads/{BRANCH}")
            return ok({"state": "OPEN", "mergeable": self.mergeable, "headRefOid": head, "baseRefName": self.base,
                       "isCrossRepository": False})
        if sub == ["pr", "merge"]:
            work = self.tmp / "merge-clone"
            subprocess.run(["git", "clone", "-q", str(self.remote), str(work)], check=True, capture_output=True)
            _ident(work)
            _git(work, "merge", "--no-ff", "-q", "-m", "Merge pull request #7", f"origin/{BRANCH}")
            _git(work, "push", "-q", "origin", "main")
            return ok("")
        raise AssertionError(f"unexpected gh call {cmd}")

    def called(self, *sub: str) -> bool:
        return any(c[1:1 + len(sub)] == list(sub) for c in self.calls)


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
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
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "switch", "-q", "-c", BRANCH)
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "audit(F1): fix")
    sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "switch", "-q", "main")

    db = tmp_path / "database" / "auditor.db"
    initialize(db)
    with connect(db) as conn:
        conn.execute("INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id) "
                     "VALUES('p', 'P', ?, 'ag')", (str(repo),))
        _insert(conn, "audit_runs", {"run_id": "R1", "project_key": "p", "status": "COMPLETED", "base_commit": base})
        _insert(conn, "execution_approvals", {"approval_id": "A1", "project_key": "p", "run_id": "R1",
                                              "status": "CONSUMED", "expires_at": "2999-01-01T00:00:00+00:00"})
        _insert(conn, "execution_runs", {
            "exec_id": "E1", "project_key": "p", "run_id": "R1", "approval_id": "A1", "status": "COMPLETED",
            "base_commit": base, "review_branch": BRANCH, "review_commit": sha,
            "tests_json": json.dumps({"status": "PASSED"}),
            "delivery_json": json.dumps({"status": "QUEUED", "project_key": "p", "run_id": "R1", "exec_id": "E1",
                                         "merge_blockers": []}),
        })
        conn.commit()
    gh = FakeGh(remote, tmp_path)
    monkeypatch.setattr(auto_delivery, "RUN", gh)
    now = [0.0]

    def sleep(sec: float) -> None:
        now[0] += sec

    return {"db": db, "repo": repo, "remote": remote, "sha": sha, "gh": gh,
            "run": lambda: auto_delivery.run_delivery(db, "E1", sleep=sleep, clock=lambda: now[0])}


def _stored(env: dict[str, Any]) -> dict[str, Any]:
    with connect(env["db"]) as conn:
        return json.loads(conn.execute("SELECT delivery_json FROM execution_runs WHERE exec_id='E1'").fetchone()[0])


def _set_blockers(env: dict[str, Any], blockers: list[str]) -> None:
    state = _stored(env)
    state["merge_blockers"] = blockers
    with connect(env["db"]) as conn:
        conn.execute("UPDATE execution_runs SET delivery_json=? WHERE exec_id='E1'", (json.dumps(state),))
        conn.commit()


def test_all_gates_pass_merges_syncs_and_cleans_up(env: dict[str, Any]) -> None:
    res = env["run"]()
    assert res["status"] == "MERGED", res
    assert res["pr_number"] == 7 and res["local_sync"] == {"pulled": True, "branch_deleted": True}
    remote_main = _git(env["remote"], "rev-parse", "refs/heads/main")
    assert subprocess.run(["git", "-C", str(env["remote"]), "merge-base", "--is-ancestor", env["sha"], remote_main]).returncode == 0
    assert not _git(env["remote"], "branch", "--list", BRANCH)  # remote branch deleted
    assert _git(env["repo"], "rev-parse", "HEAD") == remote_main  # local main fast-forwarded
    assert not _git(env["repo"], "branch", "--list", BRANCH)
    merge = next(c for c in env["gh"].calls if c[1:3] == ["pr", "merge"])
    assert "--merge" in merge and env["sha"] in merge  # merge commit, pinned to the verified head
    assert _stored(env)["status"] == "MERGED"
    with connect(env["db"]) as conn:
        events = [r[0] for r in conn.execute("SELECT event_type FROM audit_events ORDER BY event_id")]
    assert "DELIVERY_PR_OPENED" in events and events[-1] == "DELIVERY_MERGED"


def test_blocker_opens_pr_but_never_merges(env: dict[str, Any]) -> None:
    _set_blockers(env, ["the fix changes CI/GitHub configuration (.github/workflows/ci.yml); merge it yourself"])
    res = env["run"]()
    assert res["status"] == "PR_OPEN" and ".github" in res["reason"]
    assert env["gh"].called("pr", "create") and not env["gh"].called("pr", "merge")
    assert not env["gh"].called("pr", "checks")
    assert _git(env["repo"], "branch", "--list", BRANCH)  # local branch kept


def test_failed_ci_keeps_the_pr_open(env: dict[str, Any]) -> None:
    env["gh"].checks = [[{"name": "test", "bucket": "pending"}], [{"name": "test", "bucket": "fail"}]]
    res = env["run"]()
    assert res["status"] == "PR_OPEN" and "CI failed: test" in res["reason"]
    assert not env["gh"].called("pr", "merge")


def test_waits_for_pending_ci(env: dict[str, Any]) -> None:
    env["gh"].checks = [[], [{"name": "test", "bucket": "pending"}], [{"name": "test", "bucket": "pass"}]]
    assert env["run"]()["status"] == "MERGED"


def test_no_ci_reported_keeps_the_pr_open(env: dict[str, Any]) -> None:
    env["gh"].checks = [[]]
    res = env["run"]()
    assert res["status"] == "PR_OPEN" and "no CI check" in res["reason"]


def test_only_skipped_checks_do_not_count(env: dict[str, Any]) -> None:
    env["gh"].checks = [[{"name": "test", "bucket": "skipping"}]]
    assert env["run"]()["status"] == "PR_OPEN"


def test_pushed_head_mismatch_is_not_merged(env: dict[str, Any]) -> None:
    env["gh"].head = "f" * 40
    res = env["run"]()
    assert res["status"] == "PR_OPEN" and "not the reviewed commit" in res["reason"]


def test_conflicting_pr_is_not_merged(env: dict[str, Any]) -> None:
    env["gh"].mergeable = "CONFLICTING"
    assert env["run"]()["status"] == "PR_OPEN"


def test_moved_local_branch_is_not_pushed(env: dict[str, Any]) -> None:
    _git(env["repo"], "branch", "-f", BRANCH, "main")
    res = env["run"]()
    assert res["status"] == "FAILED" and "changed since the fix" in res["reason"]
    assert not _git(env["remote"], "branch", "--list", BRANCH)


def test_dirty_checkout_is_not_touched(env: dict[str, Any]) -> None:
    (env["repo"] / "a.py").write_text("local work\n", encoding="utf-8")
    before = _git(env["repo"], "rev-parse", "HEAD")
    res = env["run"]()
    assert res["status"] == "MERGED"
    assert res["local_sync"]["pulled"] is False and "uncommitted" in res["local_sync"]["reason"]
    assert _git(env["repo"], "rev-parse", "HEAD") == before
    assert (env["repo"] / "a.py").read_text(encoding="utf-8") == "local work\n"


def test_other_checked_out_branch_is_not_switched(env: dict[str, Any]) -> None:
    _git(env["repo"], "switch", "-q", "-c", "feature")
    res = env["run"]()
    assert res["status"] == "MERGED" and res["local_sync"]["pulled"] is False
    assert _git(env["repo"], "symbolic-ref", "--short", "HEAD") == "feature"


def test_delivery_runs_only_once(env: dict[str, Any]) -> None:
    env["run"]()
    with pytest.raises(RuntimeError, match="not queued"):
        env["run"]()


def test_merge_blockers() -> None:
    good = {"tests": {"status": "PASSED"}, "files_changed": ["src/a.py"]}
    assert auto_delivery.merge_blockers(good, "COMPLETED") == []
    assert auto_delivery.merge_blockers(good, "PARTIAL")
    assert auto_delivery.merge_blockers({**good, "tests": {"status": "FAILED"}}, "COMPLETED")
    assert auto_delivery.merge_blockers({**good, "tests": {"status": "NOT_CONFIGURED"}}, "COMPLETED")
    assert auto_delivery.merge_blockers({**good, "warning": "x"}, "COMPLETED")
    assert auto_delivery.merge_blockers({**good, "policy_violations": ["y"]}, "COMPLETED")
    assert auto_delivery.merge_blockers({**good, "files_changed": [".github/workflows/ci.yml"]}, "COMPLETED")
    assert auto_delivery.merge_blockers({**good, "files_changed": [".GitHub\\dependabot.yml"]}, "COMPLETED")


def test_queue_delivery_spawns_the_background_step(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
                                                   tmp_path: Path) -> None:
    spawned: list[list[str]] = []
    monkeypatch.setattr(auto_delivery, "SPAWN", lambda cmd, *, env, log_path: spawned.append(cmd) or 4242)
    review = {"branch": BRANCH, "commit": env["sha"], "tests": {"status": "FAILED"}, "files_changed": ["a.py"]}
    state = auto_delivery.queue_delivery(env["db"], tmp_path, project_key="p", run_id="R1", exec_id="E1",
                                         review=review, final_status="COMPLETED")
    assert state["status"] == "QUEUED" and state["pid"] == 4242 and state["merge_blockers"]
    assert spawned[0][-3:] == ["deliver", "--exec", "E1"]
    assert _stored(env)["status"] == "QUEUED"


def test_get_status_shows_the_latest_delivery(env: dict[str, Any], tmp_path: Path) -> None:
    from mcp_server import AuditorMCPDispatcher

    env["run"]()
    d = AuditorMCPDispatcher(db_path=env["db"], app_home=tmp_path)
    proj = d.call_tool("auditor_get_status", {"project_key": "p"})["projects"][0]
    assert proj["latest_delivery"]["status"] == "MERGED" and proj["delivery_mode"] == "local"


def test_delivery_mode_setting(env: dict[str, Any]) -> None:
    with connect(env["db"]) as conn:
        assert get_settings(conn, "p")["delivery_mode"] == "local"
        assert set_settings(conn, "p", delivery_mode="auto_merge")["delivery_mode"] == "auto_merge"
        with pytest.raises(ValueError):
            set_settings(conn, "p", delivery_mode="yolo")
        conn.execute("UPDATE projects SET delivery_mode='weird' WHERE project_key='p'")
        assert get_settings(conn, "p")["delivery_mode"] == "local"  # unknown value: no merge


# --- private pytest --basetemp -----------------------------------------------------------------------------------


def test_pytest_gets_a_private_basetemp() -> None:
    cmd, tmp = _with_private_pytest_basetemp([sys.executable, "-m", "pytest", "-q"])
    try:
        assert tmp and cmd[-1] == f"--basetemp={tmp}"
    finally:
        Path(tmp).rmdir()
    assert _with_private_pytest_basetemp(["pytest", "--basetemp=x"]) == (["pytest", "--basetemp=x"], None)
    assert _with_private_pytest_basetemp(["npm", "test"]) == (["npm", "test"], None)


def test_test_run_uses_and_removes_its_basetemp(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    (proj / "tests").mkdir(parents=True)
    (proj / "tests" / "test_x.py").write_text(
        "def test_tmp(tmp_path):\n    (tmp_path / 'f').write_text('1')\n    print('BT', tmp_path)\n", encoding="utf-8")
    res = run_project_tests(proj, [sys.executable, "-m", "pytest", "-q", "-s", "-p", "no:cacheprovider"],
                            source="detected")
    assert res["status"] == "PASSED", res["output_tail"]
    assert res["command"][-1] == "no:cacheprovider"  # the reported command is the configured one
    line = next(ln for ln in res["output_tail"].splitlines() if "BT " in ln)
    assert "auditor-pytest-" in line
    assert not Path(line.split("BT ", 1)[1].strip()).exists()


# --- review fixes ----------------------------------------------------------------------------------------------


def test_green_must_be_confirmed_by_a_second_poll(env: dict[str, Any]) -> None:
    # first poll: only a fast check is green; the slower workflow registers later and fails
    env["gh"].checks = [[{"name": "lint", "bucket": "pass"}],
                        [{"name": "lint", "bucket": "pass"}, {"name": "test", "bucket": "fail"}]]
    res = env["run"]()
    assert res["status"] == "PR_OPEN" and "test" in res["reason"]


def test_wrong_base_is_not_merged(env: dict[str, Any]) -> None:
    env["gh"].base = "staging"
    res = env["run"]()
    assert res["status"] == "PR_OPEN" and "does not target" in res["reason"]
    assert not env["gh"].called("pr", "merge")


def test_repeated_gh_errors_stop_waiting(env: dict[str, Any]) -> None:
    env["gh"].checks_error = "HTTP 401: Bad credentials ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    res = env["run"]()
    assert res["status"] == "PR_OPEN" and "could not read the PR checks" in res["reason"]
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in json.dumps(_stored(env))


def test_second_claim_loses(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    real_connect = auto_delivery.connect
    calls = {"n": 0}

    def racing_connect(path: Any) -> Any:  # another process claims it between our read and our update
        calls["n"] += 1
        if calls["n"] == 2:
            with real_connect(path) as conn:
                conn.execute("UPDATE execution_runs SET delivery_json=? WHERE exec_id='E1'",
                             (json.dumps({"status": "RUNNING"}),))
                conn.commit()
        return real_connect(path)

    monkeypatch.setattr(auto_delivery, "connect", racing_connect)
    with pytest.raises(RuntimeError, match="claimed by another process"):
        env["run"]()
    assert not env["gh"].calls


def test_dead_delivery_process_is_shown_as_interrupted() -> None:
    import os

    state = {"status": "RUNNING", "pid": 999999999, "process_start": 1}
    assert auto_delivery.describe(state)["status"] == "INTERRUPTED"
    alive = {"status": "RUNNING", "pid": os.getpid()}
    assert auto_delivery.describe(alive)["status"] == "RUNNING"
    assert "pid" not in auto_delivery.describe(alive)


# --- delivery_mode=pull_request: push + described PR + CI result, never a merge -----------------------------------


def _set_mode(env: dict[str, Any], mode: str) -> None:
    state = _stored(env)
    state["mode"] = mode
    with connect(env["db"]) as conn:
        conn.execute("UPDATE execution_runs SET delivery_json=? WHERE exec_id='E1'", (json.dumps(state),))
        conn.commit()


def _pr_create(env: dict[str, Any]) -> list[str]:
    return next(c for c in env["gh"].calls if c[1:3] == ["pr", "create"])


def test_pull_request_mode_opens_a_described_pr_reports_ci_and_never_merges(env: dict[str, Any]) -> None:
    with connect(env["db"]) as conn:
        _insert(conn, "findings", {"finding_id": "OPEN-1", "project_key": "p", "run_id": "R1", "last_seen_run_id": "R1",
                                   "first_seen_run_id": "R1", "lifecycle": "OPEN", "severity": "HIGH",
                                   "title": "Race in refresh", "verification_status": "VERIFIED",
                                   "remediation_safe": 0, "fingerprint": "fp-open-1", "confidence": "LIKELY",
                                   "category": "CONCURRENCY"})
        conn.commit()
    _set_mode(env, "pull_request")
    res = env["run"]()
    assert res["status"] == "PR_OPEN" and res["ci"] == "PASSED", res
    assert "merging is your decision" in res["reason"] and res["pr_number"] == 7
    assert env["gh"].called("pr", "checks") and not env["gh"].called("pr", "merge")
    assert _git(env["remote"], "branch", "--list", BRANCH) and _git(env["repo"], "branch", "--list", BRANCH)
    cmd = _pr_create(env)
    title, body = cmd[cmd.index("--title") + 1], cmd[cmd.index("--body") + 1]
    assert title == "Auditor fixes for R1 (1 commits)"
    assert "### Fixed\n- audit(F1): fix" in body and "Merge: **yours**" in body and "**PASSED**" in body
    assert "`OPEN-1` (HIGH): Race in refresh - the verifier rejected the proposed fix as unsafe" in body
    with connect(env["db"]) as conn:
        last = conn.execute("SELECT event_type, details FROM audit_events ORDER BY event_id DESC LIMIT 1").fetchone()
    assert last[0] == "DELIVERY_PR_OPEN_FOR_USER"


def test_pull_request_mode_reports_failed_ci(env: dict[str, Any]) -> None:
    _set_mode(env, "pull_request")
    env["gh"].checks = [[{"name": "test", "bucket": "fail", "state": "FAILURE"}]]
    res = env["run"]()
    assert res["status"] == "PR_OPEN" and res["ci"] == "CI failed: test" and "CI: CI failed: test" in res["reason"]
    assert not env["gh"].called("pr", "merge")


def test_pull_request_mode_setting_and_queue(env: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
                                            tmp_path: Path) -> None:
    with connect(env["db"]) as conn:
        assert set_settings(conn, "p", delivery_mode="pull_request")["delivery_mode"] == "pull_request"
    monkeypatch.setattr(auto_delivery, "SPAWN", lambda cmd, *, env, log_path: 4242)
    review = {"branch": BRANCH, "commit": env["sha"], "tests": {"status": "PASSED"}, "files_changed": ["a.py"]}
    state = auto_delivery.queue_delivery(env["db"], tmp_path, project_key="p", run_id="R1", exec_id="E1",
                                         review=review, final_status="COMPLETED", mode="pull_request")
    assert state["mode"] == "pull_request" and _stored(env)["mode"] == "pull_request"
    with pytest.raises(ValueError):
        auto_delivery.queue_delivery(env["db"], tmp_path, project_key="p", run_id="R1", exec_id="E1",
                                     review=review, final_status="COMPLETED", mode="yolo")


def test_executor_withdraws_manual_push_and_merge_commands_when_delivering() -> None:
    import inspect

    import executor

    src = inspect.getsource(executor)
    assert 'delivery_mode in ("pull_request", "auto_merge")' in src
    assert 'startswith(("git push", "git merge", "git branch -D"))' in src

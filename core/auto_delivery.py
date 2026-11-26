"""Optional automatic delivery of a verified fix: push, PR, GitHub CI, merge, local sync.

``delivery_mode=pull_request`` stops after the PR is open and GitHub CI has reported (the merge stays the user's);
``delivery_mode=auto_merge`` goes on to merge when every gate passes.

The control plane does this with fixed rules; the agent never merges. After ``finalize`` delivered the local
review branch, ``queue_delivery`` records which merge gates already failed and starts ``cli.py deliver`` in the
background (waiting for CI takes minutes). ``run_delivery`` then:

1. pushes the review branch and opens a PR (always, so the user can see it),
2. merges only when every gate passes: the control plane's own test run PASSED, no warning or policy violation,
   nothing under ``.github/`` changed (a PR must not define its own check), every GitHub check of the PR passed,
   GitHub reports it mergeable and its head is exactly the reviewed commit,
3. merges with a merge commit (one commit per finding stays visible; one ``git revert -m 1`` undoes it), deletes
   the remote branch, fast-forwards the user's checkout only when it is clean and on the default branch, and
   deletes the local review branch.

When a gate fails the PR simply stays open for the user (``PR_OPEN``); nothing is forced. The outcome is stored in
``execution_runs.delivery_json`` and recorded as ``DELIVERY_*`` events.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from db import connect, record_event
from runtime_discovery.redaction import redact_report_text

QUEUED = "QUEUED"
RUNNING = "RUNNING"
MERGED = "MERGED"
PR_OPEN = "PR_OPEN"  # pushed and PR opened; the user merges (a gate failed)
FAILED = "FAILED"
TERMINAL = (MERGED, PR_OPEN, FAILED)
PULL_REQUEST_MODE = "pull_request"
AUTO_MERGE_MODE = "auto_merge"

CI_POLL_SECONDS = 20
CI_APPEAR_TIMEOUT_SECONDS = 300  # no check reported by then: the repository has no CI for this PR
CI_TIMEOUT_SECONDS = 1800
CI_CONFIRM_POLLS = 2  # all-green must be seen twice in a row: a slower workflow may register its check late
CI_MAX_GH_ERRORS = 3
PROTECTED_PREFIXES = (".github/",)

# Test seams: the gh/git runner and the background spawner.
Runner = Callable[[list[str], Path], subprocess.CompletedProcess]


def _default_runner(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=180, stdin=subprocess.DEVNULL)


RUN: Runner = _default_runner
SPAWN: Callable[..., int] | None = None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def merge_blockers(review: dict[str, Any], final_status: str) -> list[str]:
    """Gates known at finalize time. Empty list: the PR may be merged once GitHub CI passes."""
    reasons: list[str] = []
    if final_status != "COMPLETED":
        reasons.append(f"execution ended {final_status}, not COMPLETED")
    tests = review.get("tests") or {}
    if tests.get("status") != "PASSED":
        reasons.append(f"the auditor's own test run did not pass ({tests.get('status') or 'not run'})")
    if review.get("warning"):
        reasons.append("the delivery has a warning: " + str(review["warning"])[:300])
    if review.get("policy_violations"):
        reasons.append("auto-approval policy violations")
    touched = [f for f in review.get("files_changed") or [] if f.replace("\\", "/").lower().startswith(PROTECTED_PREFIXES)]
    if touched:
        reasons.append("the fix changes CI/GitHub configuration (" + ", ".join(touched[:5]) + "); merge it yourself")
    return reasons


def _save(db_path: Path, exec_id: str, state: dict[str, Any]) -> None:
    with connect(db_path) as conn:
        conn.execute("UPDATE execution_runs SET delivery_json=? WHERE exec_id=?",
                     (json.dumps(state, ensure_ascii=False), exec_id))
        conn.commit()


def _event(db_path: Path, event: str, state: dict[str, Any], *, level: str = "INFO",
           jsonl_path: Path | None = None) -> None:
    with connect(db_path) as conn:
        record_event(conn, event, project_key=state.get("project_key"), run_id=state.get("run_id"), level=level,
                     details={k: v for k, v in state.items() if k not in ("steps",)}, jsonl_path=jsonl_path)
        conn.commit()


def queue_delivery(
    db_path: Path,
    app_home: Path,
    *,
    project_key: str,
    run_id: str,
    exec_id: str,
    review: dict[str, Any],
    final_status: str,
    jsonl_path: Path | None = None,
    mode: str = AUTO_MERGE_MODE,
) -> dict[str, Any]:
    """Record the finalize-time gates and start the background delivery. Never raises (the fix is delivered
    locally either way); the returned dict goes into ``review['delivery']``."""
    if mode not in (PULL_REQUEST_MODE, AUTO_MERGE_MODE):
        raise ValueError(f"Unknown delivery mode '{mode}'.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = app_home / "logs" / "delivery" / f"{project_key}-{stamp}.log"
    state: dict[str, Any] = {
        "status": QUEUED,
        "mode": mode,
        "project_key": project_key,
        "run_id": run_id,
        "exec_id": exec_id,
        "branch": review.get("branch"),
        "commit": review.get("commit"),
        "merge_blockers": merge_blockers(review, final_status),
        "queued_at": _now(),
        "log_path": str(log_path),
    }
    try:
        _save(db_path, exec_id, state)
        env = os.environ.copy()
        env["ANTIGRAVITY_AUDITOR_HOME"] = str(app_home)
        env["ANTIGRAVITY_AUDITOR_DB"] = str(db_path)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        command = [sys.executable, str(Path(__file__).resolve().parent / "cli.py"), "deliver", "--exec", exec_id]
        if SPAWN is not None:
            spawn = SPAWN
        else:
            from audit_launcher import _spawn as spawn
        from audit_launcher import _process_start

        state["pid"] = spawn(command, env=env, log_path=log_path)
        state["process_start"] = _process_start(int(state["pid"]))
        _save(db_path, exec_id, state)
        _event(db_path, "DELIVERY_QUEUED", state, jsonl_path=jsonl_path)
    except Exception as exc:  # noqa: BLE001 - the local branch is already delivered
        state.update(status=FAILED, error=f"could not start the delivery: {type(exc).__name__}: {exc}")
        try:
            _save(db_path, exec_id, state)
        except Exception:  # noqa: BLE001
            pass
    return state


class _Stop(Exception):
    """End the delivery with a status (PR_OPEN with a reason, or FAILED)."""

    def __init__(self, status: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _ok(cmd: list[str], cwd: Path, what: str, *, status: str = FAILED) -> str:
    res = RUN(cmd, cwd)
    if res.returncode != 0:
        raise _Stop(status, f"{what} failed: {_clean(res.stderr or res.stdout)[:400]}")
    return (res.stdout or "").strip()


def _clean(text: str | None) -> str:
    """git/gh output may echo a remote URL with credentials or a token: scrub it before storing it anywhere."""
    return redact_report_text((text or "").strip())


def _pr_number(url_or_text: str) -> int | None:
    m = re.search(r"/pull/(\d+)", url_or_text)
    return int(m.group(1)) if m else None


def _wait_for_ci(repo_path: Path, repo: str, number: int, *, sleep: Callable[[float], None],
                 clock: Callable[[], float]) -> list[dict[str, Any]]:
    start = clock()
    green_seen = 0
    errors = 0
    while True:
        res = RUN(["gh", "pr", "checks", str(number), "--repo", repo, "--json", "name,bucket,state"], repo_path)
        try:
            checks = json.loads(res.stdout) if (res.stdout or "").strip().startswith("[") else None
        except ValueError:
            checks = None
        elapsed = clock() - start
        if checks is None:
            # gh exits non-zero without JSON both for "no checks yet" and for real errors (auth, network)
            msg = _clean(res.stderr or res.stdout)
            if "no checks" not in msg.lower():
                errors += 1
                if errors >= CI_MAX_GH_ERRORS:
                    raise _Stop(PR_OPEN, f"could not read the PR checks: {msg[:300]}")
            checks = []
        else:
            errors = 0
        if not checks:
            green_seen = 0
            if elapsed >= CI_APPEAR_TIMEOUT_SECONDS:
                raise _Stop(PR_OPEN, "no CI check was reported for the PR; merge it yourself after a review")
        else:
            failed = [c.get("name") for c in checks if c.get("bucket") in ("fail", "cancel")]
            if failed:
                raise _Stop(PR_OPEN, "CI failed: " + ", ".join(str(n) for n in failed))
            if all(c.get("bucket") in ("pass", "skipping") for c in checks):
                if not any(c.get("bucket") == "pass" for c in checks):
                    raise _Stop(PR_OPEN, "every CI check was skipped")
                green_seen += 1
                if green_seen >= CI_CONFIRM_POLLS:
                    return checks
            else:
                green_seen = 0
        if elapsed >= CI_TIMEOUT_SECONDS:
            raise _Stop(PR_OPEN, f"CI did not finish within {CI_TIMEOUT_SECONDS // 60} minutes")
        sleep(CI_POLL_SECONDS)


def run_delivery(
    db_path: Path,
    exec_id: str,
    *,
    jsonl_path: Path | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT e.*, p.repo_path FROM execution_runs e JOIN projects p ON p.project_key=e.project_key "
            "WHERE e.exec_id=?", (exec_id,)).fetchone()
    if row is None:
        raise RuntimeError(f"Execution '{exec_id}' not found.")
    state = json.loads(row["delivery_json"] or "{}")
    if state.get("status") != QUEUED:
        raise RuntimeError(f"Delivery of '{exec_id}' is not queued (status={state.get('status')}); not running it again.")
    state.update(status=RUNNING, started_at=_now(), steps=[])
    with connect(db_path) as conn:  # claim it atomically: a second `deliver` for the same execution loses
        claimed = conn.execute(
            "UPDATE execution_runs SET delivery_json=? WHERE exec_id=? AND delivery_json=?",
            (json.dumps(state, ensure_ascii=False), exec_id, row["delivery_json"])).rowcount
        conn.commit()
    if claimed != 1:
        raise RuntimeError(f"Delivery of '{exec_id}' was claimed by another process; not running it again.")
    repo_path = Path(str(row["repo_path"]))
    branch, sha = str(row["review_branch"] or ""), str(row["review_commit"] or "")
    try:
        if not branch or not sha:
            raise _Stop(FAILED, "the execution has no review branch")
        head = RUN(["git", "rev-parse", "--verify", "-q", f"refs/heads/{branch}"], repo_path).stdout.strip()
        if head != sha:
            raise _Stop(FAILED, f"the local review branch changed since the fix ({head[:12] or 'deleted'}); "
                                "not pushing it")
        info = json.loads(_ok(["gh", "repo", "view", "--json", "nameWithOwner,defaultBranchRef"], repo_path,
                              "reading the GitHub repository (is gh installed and logged in?)"))
        repo, default = info["nameWithOwner"], info["defaultBranchRef"]["name"]
        state.update(repository=repo, base=default)
        state["pr_details"] = _pr_details(db_path, row, repo_path, sha)

        _ok(["git", "push", "origin", f"refs/heads/{branch}:refs/heads/{branch}"], repo_path, "git push")
        state["steps"].append("pushed")
        existing = RUN(["gh", "pr", "list", "--repo", repo, "--head", branch, "--base", default, "--state", "open",
                        "--json", "number,url,isCrossRepository"], repo_path)
        prs = json.loads(existing.stdout) if existing.returncode == 0 and existing.stdout.strip().startswith("[") else []
        prs = [pr for pr in prs if not pr.get("isCrossRepository")]
        if prs:
            number, url = int(prs[0]["number"]), prs[0]["url"]
        else:
            url = _ok(["gh", "pr", "create", "--repo", repo, "--base", default, "--head", branch,
                       "--title", _pr_title(row, state), "--body", _pr_body(row, state)], repo_path, "gh pr create")
            number = _pr_number(url) or 0
            if not number:
                raise _Stop(FAILED, f"could not read the PR number from: {url[:200]}")
        state.update(pr_number=number, pr_url=url.strip().splitlines()[-1])
        state["steps"].append("pr_opened")
        _save(db_path, exec_id, state)
        _event(db_path, "DELIVERY_PR_OPENED", state, jsonl_path=jsonl_path)

        if state.get("mode") == PULL_REQUEST_MODE:
            # Report what GitHub CI says, then leave the merge to the user (never merged in this mode).
            try:
                _check_pr(repo_path, repo, number, sha, default, sleep=sleep, require_mergeable=False)
                state["checks"] = _wait_for_ci(repo_path, repo, number, sleep=sleep, clock=clock)
                state["ci"] = "PASSED"
                state["steps"].append("ci_passed")
            except _Stop as ci:
                state["ci"] = ci.reason
            notes = [f"CI: {state['ci']}", "delivery mode pull_request: merging is your decision"]
            if state.get("merge_blockers"):
                notes.append("review first: " + "; ".join(state["merge_blockers"]))
            raise _Stop(PR_OPEN, "; ".join(notes))

        if state.get("merge_blockers"):
            raise _Stop(PR_OPEN, "; ".join(state["merge_blockers"]))
        _check_pr(repo_path, repo, number, sha, default, sleep=sleep, require_mergeable=False)
        state["checks"] = _wait_for_ci(repo_path, repo, number, sleep=sleep, clock=clock)
        state["steps"].append("ci_passed")
        # Again after CI: still the verified commit (so its checks are the ones that passed), right base, mergeable.
        _check_pr(repo_path, repo, number, sha, default, sleep=sleep, require_mergeable=True)
        _ok(["gh", "pr", "merge", str(number), "--repo", repo, "--merge", "--match-head-commit", sha], repo_path,
            "gh pr merge", status=PR_OPEN)
        state["steps"].append("merged")
        state["status"] = MERGED
        state["merged_at"] = _now()
        _save(db_path, exec_id, state)

        if RUN(["git", "push", "origin", "--delete", branch], repo_path).returncode == 0:
            state["steps"].append("remote_branch_deleted")
        with connect(db_path) as conn:
            auditing = conn.execute(
                "SELECT run_id FROM audit_runs WHERE project_key=? AND status IN ('PREFLIGHT','PRIMARY_AUDIT_RUNNING',"
                "'DISPATCHED','ANALYZING','VERIFICATION_PENDING','VERIFICATION_DISPATCHING','VERIFICATION_RUNNING',"
                "'EVIDENCE_VALIDATION')", (row["project_key"],)).fetchone()
        state["local_sync"] = _sync_local(repo_path, default, branch, sha, pull=auditing is None)
    except _Stop as stop:
        state["status"] = stop.status
        state["reason"] = stop.reason
    except BaseException as exc:  # noqa: BLE001 - the delivery must end with a recorded status
        state["status"] = FAILED
        state["reason"] = _clean(f"{type(exc).__name__}: {exc}")[:500]
        if not isinstance(exc, Exception):  # interrupted: record it, then let it propagate
            state["finished_at"] = _now()
            _save(db_path, exec_id, state)
            raise
    state["finished_at"] = _now()
    _save(db_path, exec_id, state)
    event = {MERGED: "DELIVERY_MERGED", PR_OPEN: "DELIVERY_PR_OPEN_FOR_USER"}.get(state["status"], "DELIVERY_FAILED")
    as_planned = state["status"] == MERGED or (state["status"] == PR_OPEN and state.get("mode") == PULL_REQUEST_MODE
                                               and state.get("ci") == "PASSED")
    _event(db_path, event, state, level="INFO" if as_planned else "WARNING", jsonl_path=jsonl_path)
    return state


def _check_pr(repo_path: Path, repo: str, number: int, sha: str, default: str, *,
              sleep: Callable[[float], None], require_mergeable: bool) -> None:
    view: dict[str, Any] = {}
    for _ in range(6):  # GitHub computes mergeability lazily
        view = json.loads(_ok(["gh", "pr", "view", str(number), "--repo", repo, "--json",
                               "state,mergeable,headRefOid,baseRefName,isCrossRepository"], repo_path, "gh pr view"))
        if not require_mergeable or view.get("mergeable") != "UNKNOWN":
            break
        sleep(5)
    if view.get("state") != "OPEN":
        raise _Stop(PR_OPEN, f"the PR is {view.get('state')}")
    if view.get("baseRefName") != default or view.get("isCrossRepository"):
        raise _Stop(PR_OPEN, f"the PR does not target '{default}' of this repository")
    if view.get("headRefOid") != sha:
        raise _Stop(PR_OPEN, "the PR head is not the reviewed commit (someone pushed to it)")
    if require_mergeable and view.get("mergeable") != "MERGEABLE":
        raise _Stop(PR_OPEN, f"GitHub reports the PR as {view.get('mergeable')}")


def describe(state: dict[str, Any]) -> dict[str, Any]:
    """State for display. A QUEUED/RUNNING delivery whose process is gone is shown as INTERRUPTED (read-only:
    nothing is written; the stored state stays as evidence)."""
    out = {k: v for k, v in state.items() if k not in ("pid", "process_start", "checks")}
    if state.get("status") in (QUEUED, RUNNING) and state.get("pid"):
        from audit_launcher import _process_start

        alive = _process_start(int(state["pid"]))
        if alive is None or (state.get("process_start") and alive != state["process_start"]):
            out["status"] = "INTERRUPTED"
            out["reason"] = ("the delivery process ended without a result; check log_path, then push and merge "
                             "the branch yourself")
    return out


def _sync_local(repo_path: Path, default: str, branch: str, sha: str, *, pull: bool = True) -> dict[str, Any]:
    """Fast-forward the user's checkout only when it is clean and on the default branch; never touch their work."""
    out: dict[str, Any] = {"pulled": False, "branch_deleted": False}
    if RUN(["git", "fetch", "origin", default], repo_path).returncode != 0:
        out["reason"] = "git fetch failed"
        return out
    current = RUN(["git", "symbolic-ref", "-q", "--short", "HEAD"], repo_path).stdout.strip()
    dirty = RUN(["git", "status", "--porcelain", "--untracked-files=no"], repo_path).stdout.strip()
    if not pull:
        out["reason"] = "an audit of this project is running on your checkout; pull it yourself afterwards"
    elif current != default:
        out["reason"] = f"your checkout is on '{current or 'a detached HEAD'}', not '{default}'; pull it yourself"
    elif dirty:
        out["reason"] = "your checkout has uncommitted changes; pull it yourself"
    else:
        ff = RUN(["git", "merge", "--ff-only", f"origin/{default}"], repo_path)
        out["pulled"] = ff.returncode == 0
        if not out["pulled"]:
            out["reason"] = "fast-forward was not possible (local commits?); pull it yourself: " + \
                _clean(ff.stderr or ff.stdout)[:200]
    merged = RUN(["git", "merge-base", "--is-ancestor", sha, f"origin/{default}"], repo_path).returncode == 0
    still = RUN(["git", "rev-parse", "--verify", "-q", f"refs/heads/{branch}"], repo_path).stdout.strip() == sha
    if merged and still and RUN(["git", "branch", "-D", branch], repo_path).returncode == 0:
        out["branch_deleted"] = True
    return out


def _pr_details(db_path: Path, row: Any, repo_path: Path, sha: str) -> dict[str, Any]:
    """What the PR text lists: the fix commits (one per finding) and the run's findings that were not fixed."""
    commits: list[str] = []
    base = str(row["base_commit"] or "") if "base_commit" in row.keys() else ""
    if base:
        res = RUN(["git", "log", "--reverse", "--format=%s", f"{base}..{sha}"], repo_path)
        if res.returncode == 0:
            commits = [ln.strip() for ln in (res.stdout or "").splitlines() if ln.strip()][:200]
    open_findings: list[dict[str, Any]] = []
    try:
        with connect(db_path) as conn:
            for f in conn.execute(
                """SELECT finding_id, severity, title, verification_status, remediation_safe FROM findings
                   WHERE last_seen_run_id=? AND lifecycle='OPEN' ORDER BY
                   CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3
                   ELSE 4 END, finding_id""", (row["run_id"],)).fetchall():
                why = ("the verifier rejected the proposed fix as unsafe" if not f["remediation_safe"]
                       else "only partially verified" if f["verification_status"] == "PARTIALLY_VERIFIED"
                       else "not approved for this fix")
                open_findings.append({"id": f["finding_id"], "severity": f["severity"],
                                      "title": str(f["title"] or "")[:160], "why": why})
    except Exception:  # noqa: BLE001 - the PR text is informative only
        pass
    return {"commits": commits, "open_findings": open_findings[:50]}


def _pr_title(row: Any, state: dict[str, Any]) -> str:
    n = len((state.get("pr_details") or {}).get("commits") or [])
    return f"Auditor fixes for {row['run_id']}" + (f" ({n} commits)" if n else "")


def _pr_body(row: Any, state: dict[str, Any]) -> str:
    try:
        tests = json.loads(row["tests_json"] or "{}")
    except ValueError:
        tests = {}
    blockers = state.get("merge_blockers") or []
    details = state.get("pr_details") or {}
    summary = ""
    for line in reversed(str(tests.get("output_tail") or "").splitlines()):
        if " passed" in line or " failed" in line:
            summary = line.strip(" =")
            break
    lines = [
        f"Verified fixes from audit run `{row['run_id']}` (execution `{row['exec_id']}`), one commit per finding.",
        "",
        f"Auditor test run on this branch: **{tests.get('status', 'not run')}**" + (f" ({summary})." if summary else "."),
    ]
    if details.get("commits"):
        lines += ["", "### Fixed", *[f"- {c}" for c in details["commits"]]]
    if details.get("open_findings"):
        lines += ["", "### Not fixed (still open in the audit report)",
                  *[f"- `{f['id']}` ({f['severity']}): {f['title']} - {f['why']}" for f in details["open_findings"]]]
    lines.append("")
    if state.get("mode") == PULL_REQUEST_MODE:
        lines.append("Merge: **yours** (delivery mode `pull_request`). The auditor never merges this PR.")
        if blockers:
            lines.append("Review first: " + "; ".join(blockers) + ".")
    else:
        lines.append("Automatic merge: **on** - merged by the auditor once every CI check passes."
                     if not blockers else "Automatic merge: **off** for this PR - " + "; ".join(blockers) + ".")
    return "\n".join(lines)

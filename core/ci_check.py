"""Deterministic CI checks: a "no CI" finding and the control plane's own test run after a fix.

* ``ci_missing`` / ``upsert_ci_finding``: a repository hosted on GitHub with a recognisable project (Python or
  Node) but no CI configuration gets one canonical finding (``CI-MISSING-001``). It is a fact the control plane
  checks itself, so no model is involved and it needs no second-pass verification; APPLY lets the agent add a
  workflow under ``.github/workflows/`` (and tests) in the isolated worktree like any other fix.
* ``detect_test_command`` / ``run_project_tests``: after a fix the control plane runs the project's tests itself
  in the worktree instead of trusting the agent's ``integration_test_passed``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from runtime_discovery.redaction import redact_report_text

CI_FINDING_ID = "CI-MISSING-001"
CI_FINGERPRINT = "ci-missing-github-actions"
CI_CATEGORY = "CI"
CI_VERIFIER = "control-plane:ci-check"
WORKFLOWS_DIR = ".github/workflows/"

_OTHER_CI_FILES = (
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
    "bitbucket-pipelines.yml",
    ".travis.yml",
)
DEFAULT_TEST_TIMEOUT_SECONDS = 600
_OUTPUT_TAIL_CHARS = 4000


def is_ci_finding(finding: dict[str, Any] | Any) -> bool:
    try:
        return str(finding["fingerprint"] or "") == CI_FINGERPRINT
    except (KeyError, IndexError, TypeError):
        return False


def has_ci_config(repo_path: Path) -> bool:
    wf = repo_path / ".github" / "workflows"
    if wf.is_dir() and any(p.suffix.lower() in (".yml", ".yaml") and p.is_file() for p in wf.iterdir()):
        return True
    return any((repo_path / rel).is_file() for rel in _OTHER_CI_FILES)


def _is_github_repo(repo_path: Path) -> bool:
    try:
        res = subprocess.run(["git", "-C", str(repo_path), "remote", "-v"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "github.com" in (res.stdout or "").lower()


def _has_python_tests(repo_path: Path) -> bool:
    for name in ("pytest.ini", "conftest.py", "tox.ini"):
        if (repo_path / name).is_file():
            return True
    for d in ("tests", "test"):
        td = repo_path / d
        if td.is_dir() and any(td.rglob("test_*.py")):
            return True
    try:
        if "[tool.pytest" in (repo_path / "pyproject.toml").read_text(encoding="utf-8", errors="replace"):
            return True
    except OSError:
        pass
    return any(repo_path.glob("test_*.py"))


def detect_stack(repo_path: Path) -> dict[str, Any] | None:
    """The project's ecosystem as far as a CI template and a local test command need it."""
    if any((repo_path / n).is_file() for n in ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt")):
        reqs = [n for n in ("requirements.txt", "requirements-dev.txt") if (repo_path / n).is_file()]
        return {"stack": "python", "requirements": reqs, "has_tests": _has_python_tests(repo_path),
                "has_pyproject": (repo_path / "pyproject.toml").is_file()}
    pkg = repo_path / "package.json"
    if pkg.is_file():
        try:
            scripts = json.loads(pkg.read_text(encoding="utf-8")).get("scripts") or {}
        except (OSError, ValueError, AttributeError):
            scripts = {}
        test = str(scripts.get("test") or "")
        return {"stack": "node", "has_tests": bool(test) and "no test specified" not in test,
                "lockfile": (repo_path / "package-lock.json").is_file()}
    return None


def _template(stack: dict[str, Any]) -> str:
    if stack["stack"] == "python":
        install = "\n".join(f"      - run: pip install -r {r}" for r in stack["requirements"]) or (
            "      - run: pip install -e ." if stack.get("has_pyproject") else "      - run: python -m pip --version")
        check = ("      - run: python -m pytest -q" if stack["has_tests"]
                 else "      - run: python -m compileall -q .   # no tests yet: at least everything must compile")
        return (
            "name: CI\non:\n  push:\n  pull_request:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n      - uses: actions/setup-python@v5\n"
            "        with:\n          python-version: \"3.12\"\n"
            f"{install}\n{check}\n"
        )
    install = "      - run: npm ci" if stack.get("lockfile") else "      - run: npm install"
    check = "      - run: npm test" if stack["has_tests"] else "      - run: npm run build --if-present"
    return (
        "name: CI\non:\n  push:\n  pull_request:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4\n"
        "        with:\n          node-version: 20\n"
        f"{install}\n{check}\n"
    )


def ci_missing(repo_path: Path) -> dict[str, Any] | None:
    """Finding fields when the repository should have CI but has none, else None."""
    if not repo_path.is_dir() or has_ci_config(repo_path) or not _is_github_repo(repo_path):
        return None
    stack = detect_stack(repo_path)
    if stack is None:
        return None
    tests_note = (
        "The repository has tests; the workflow should run them."
        if stack["has_tests"]
        else "The repository has no automated tests yet; add a small smoke test (e.g. importing the main modules "
             "or running the CLI with --help) under tests/ so the workflow checks that the program starts."
    )
    return {
        "title": "Repository has no CI workflow: changes are merged without an automated check",
        "category": CI_CATEGORY,
        "severity": "MEDIUM",
        "confidence": "CONFIRMED",
        "file_path": WORKFLOWS_DIR + "ci.yml",
        "evidence": (
            "No CI configuration in the repository: .github/workflows/ has no .yml/.yaml file and none of "
            + ", ".join(_OTHER_CI_FILES) + " exists. The remote is on GitHub."
        ),
        "impact": (
            "Pull requests (including the auditor's own fix branches) are merged without anyone checking that the "
            "program still installs, starts and passes its tests."
        ),
        "recommendation": (
            f"Add a GitHub Actions workflow under {WORKFLOWS_DIR} (e.g. ci.yml) that installs the dependencies and "
            f"runs the checks on push and pull_request. {tests_note} Starting point ({stack['stack']}):\n\n"
            + _template(stack)
        ),
        "acceptance_criteria": (
            f"1. A workflow file exists under {WORKFLOWS_DIR} and runs on push and pull_request. "
            "2. It installs the project's dependencies and runs its tests (or a smoke test). "
            "3. The same test command passes locally in the worktree."
        ),
        "technical_rationale": "Deterministic control-plane check of the repository tree; no model involved.",
        "remediation_review": (
            f"Only files under {WORKFLOWS_DIR} and test files may change for this finding. Do not put secrets in "
            "the workflow; use GitHub repository secrets if the tests need any."
        ),
        "stack": stack,
    }


def upsert_ci_finding(
    conn: Any,
    *,
    project_key: str,
    audit_run_id: str,
    verification_run_id: str,
    repo_path: Path,
    snapshot_id: str | None,
    base_commit_sha: str | None,
) -> str | None:
    """Create/refresh the CI finding of a run (or resolve an open one once CI exists). Returns its id when OPEN."""
    existing = conn.execute(
        "SELECT * FROM findings WHERE project_key=? AND fingerprint=?", (project_key, CI_FINGERPRINT)
    ).fetchone()
    info = ci_missing(repo_path)

    def history(fid: str, prev: str | None, new: str, reason: str) -> None:
        conn.execute(
            """INSERT INTO finding_history(finding_id, project_key, run_id, from_lifecycle, to_lifecycle, actor, reason)
               VALUES(?, ?, ?, ?, ?, 'control-plane', ?)""",
            (fid, project_key, audit_run_id, prev, new, reason),
        )

    if info is None:
        if existing is not None and str(existing["lifecycle"]) == "OPEN":
            conn.execute("UPDATE findings SET lifecycle='RESOLVED', updated_at=CURRENT_TIMESTAMP WHERE finding_id=?",
                         (existing["finding_id"],))
            history(str(existing["finding_id"]), "OPEN", "RESOLVED",
                    "CI_CONFIGURATION_PRESENT" if has_ci_config(repo_path) else "CI_CHECK_NO_LONGER_APPLICABLE")
        return None

    values = (
        info["title"], info["category"], info["severity"], info["confidence"], info["file_path"],
        info["evidence"], info["impact"], info["recommendation"],
        info["acceptance_criteria"], info["remediation_review"], info["technical_rationale"],
    )
    if existing is None:
        fid = CI_FINDING_ID
        if conn.execute("SELECT 1 FROM findings WHERE finding_id=?", (fid,)).fetchone():
            fid = f"{CI_FINDING_ID}-{project_key}"[:96]
        conn.execute(
            """INSERT INTO findings(
                   finding_id, project_key, run_id, fingerprint,
                   title, category, severity, confidence, file_path, evidence, impact, recommendation,
                   acceptance_criteria, remediation_review, technical_rationale,
                   symbol, line_start, line_end, evidence_hash, file_blob_hash,
                   first_seen_run_id, last_seen_run_id, lifecycle,
                   verification_status, execution_eligible, remediation_safe,
                   verification_run_id, verified_by_run_id, verified_at, verifier_conversation_id,
                   evidence_validation_status, snapshot_id, base_commit_sha, model_independent
               ) VALUES(?,?,?,?, ?,?,?,?,?,?,?,?, ?,?,?, NULL,NULL,NULL,NULL,NULL, ?,?,'OPEN',
                        'VERIFIED',1,1, ?,?,CURRENT_TIMESTAMP,?, 'PASSED',?,?,1)""",
            (fid, project_key, audit_run_id, CI_FINGERPRINT, *values,
             audit_run_id, audit_run_id, verification_run_id, verification_run_id, CI_VERIFIER,
             snapshot_id, base_commit_sha),
        )
        history(fid, None, "OPEN", "CI_CONFIGURATION_MISSING")
        return fid

    fid = str(existing["finding_id"])
    prev = str(existing["lifecycle"])
    # A dismissed or deferred CI finding stays that way (the user decided); a resolved one that is missing again
    # is a regression.
    new = prev if prev in ("DISMISSED", "DEFERRED") else "OPEN"
    conn.execute(
        """UPDATE findings SET run_id=?, title=?, category=?, severity=?, confidence=?, file_path=?, evidence=?,
               impact=?, recommendation=?, acceptance_criteria=?, remediation_review=?, technical_rationale=?,
               last_seen_run_id=?, lifecycle=?, verification_status='VERIFIED', execution_eligible=?,
               remediation_safe=1, verification_run_id=?, verified_by_run_id=?, verified_at=CURRENT_TIMESTAMP,
               verifier_conversation_id=?, evidence_validation_status='PASSED', snapshot_id=?, base_commit_sha=?,
               model_independent=1, updated_at=CURRENT_TIMESTAMP
           WHERE finding_id=?""",
        (audit_run_id, *values, audit_run_id, new, 1 if new == "OPEN" else 0,
         verification_run_id, verification_run_id, CI_VERIFIER, snapshot_id, base_commit_sha, fid),
    )
    if prev != new:
        history(fid, prev, new, "CI_CONFIGURATION_MISSING_AGAIN" if prev == "RESOLVED" else "CI_CONFIGURATION_MISSING")
    return fid if new == "OPEN" else None


# --- the control plane's own test run ---------------------------------------------------------------------------


def _python_for(repo_path: Path) -> str:
    """The project's virtualenv interpreter when there is one (dependencies live there), else this interpreter."""
    for venv in (".venv", "venv", "env"):
        for rel in ("Scripts/python.exe", "bin/python"):
            cand = repo_path / venv / rel
            if cand.is_file():
                return str(cand)
    return sys.executable


def detect_test_command(
    repo_path: Path, configured: str | None = None, *, venv_root: Path | None = None
) -> tuple[list[str] | None, str]:
    """(command, source). ``configured`` is the project's stored test_command (a JSON list); ``venv_root`` is
    where a (git-ignored) virtualenv lives when ``repo_path`` is a worktree."""
    if configured:
        try:
            cmd = json.loads(configured)
            if isinstance(cmd, list) and cmd and all(isinstance(x, str) and x for x in cmd):
                return cmd, "configured"
        except ValueError:
            pass
        return None, "invalid-configuration"
    stack = detect_stack(repo_path)
    if stack is None:
        return None, "not-detected"
    if stack["stack"] == "python":
        py = _python_for(venv_root or repo_path)
        if stack["has_tests"]:
            return [py, "-m", "pytest", "-q", "-p", "no:cacheprovider"], "detected"
        return [py, "-m", "compileall", "-q", "."], "detected-smoke"
    npm = shutil.which("npm") or shutil.which("npm.cmd")
    if npm and stack["has_tests"]:
        return [npm, "test"], "detected"
    return None, "not-detected"


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, timeout=30)
        else:  # pragma: no cover - non-Windows: the test command runs in its own session
            import signal

            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def run_project_tests(
    worktree_path: Path,
    command: list[str] | None,
    *,
    source: str,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Run the project's test command in the isolated worktree. Never raises; the result describes what happened."""
    timeout = int(timeout_seconds or DEFAULT_TEST_TIMEOUT_SECONDS)
    if not command:
        return {
            "status": "NOT_CONFIGURED",
            "source": source,
            "hint": "Set one with: python core/cli.py project-settings set --project <key> --test-command \"...\"",
        }
    env = os.environ.copy()
    for key in list(env):
        if key.upper().startswith(("PROD_", "LIVE_DB_")):
            env.pop(key, None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    run_command, basetemp = _with_private_pytest_basetemp(command)
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            run_command, cwd=str(worktree_path), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
            stdin=subprocess.DEVNULL, **({} if os.name == "nt" else {"start_new_session": True}),
        )
    except OSError as exc:
        if basetemp:
            shutil.rmtree(basetemp, ignore_errors=True)
        return {"status": "ERROR", "source": source, "command": command, "error": f"{type(exc).__name__}: {exc}"}
    try:
        return _collect(proc, command, source=source, timeout=timeout, started=started)
    finally:
        if basetemp:
            shutil.rmtree(basetemp, ignore_errors=True)


def _is_pytest(command: list[str]) -> bool:
    if Path(command[0]).stem.lower() in ("pytest", "py.test"):
        return True
    return any(a == "-m" and i + 1 < len(command) and command[i + 1] == "pytest" for i, a in enumerate(command))


def _with_private_pytest_basetemp(command: list[str]) -> tuple[list[str], str | None]:
    """pytest keeps its temp dirs under a shared per-user folder and prunes old ones at exit; one stale entry
    there the user cannot delete (e.g. a dangling 'pytest-current' link) makes every run exit 1 although all
    tests passed. The control plane's run gets its own fresh --basetemp (unless the command already sets one)."""
    if not _is_pytest(command) or any(a == "--basetemp" or a.startswith("--basetemp=") for a in command):
        return command, None
    import tempfile

    basetemp = tempfile.mkdtemp(prefix="auditor-pytest-")
    return [*command, f"--basetemp={basetemp}"], basetemp


def _collect(
    proc: subprocess.Popen, command: list[str], *, source: str, timeout: int, started: float
) -> dict[str, Any]:
    try:
        out, _ = proc.communicate(timeout=timeout)
        status = "PASSED" if proc.returncode == 0 else "FAILED"
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            out, _ = proc.communicate(timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            out = b""  # a grandchild still holds the pipe; give up on the output, not on the result
        status = "TIMEOUT"
    text = (out or b"").decode("utf-8", errors="replace")
    return {
        "status": status,
        "source": source,
        "command": command,
        "exit_code": proc.returncode,
        "duration_seconds": round(time.monotonic() - started, 1),
        "timeout_seconds": timeout,
        "output_tail": redact_report_text(text[-_OUTPUT_TAIL_CHARS:]),
    }

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from db import (
    authorize_execution,
    connect,
    ingest_findings,
    initialize,
    save_decisions,
)
from executor import execute_approved_findings
from recovery import (
    check_disk_space,
    compute_repo_fingerprint,
    detect_moved_repositories,
    detect_project_id_for_path,
)
from verification import finalize_verified_report, submit_verification_results


def _create_isolated_git_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(repo_dir), "init"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "test@example.com"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "Auditor Test"], check=True, capture_output=True)

    (repo_dir / "calculator.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\n\ndef divide(a: float, b: float) -> float:\n    return a / b\n",
        encoding="utf-8",
    )
    (repo_dir / "formatter.py").write_text(
        "def greet(name: str) -> str:\n    return f'Hello, {name}'\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "initial commit"], check=True, capture_output=True)
    head = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return head


def _setup_project_with_findings(
    tmp_path: Path,
    repo_dir: Path,
    head_commit: str,
    findings_list: list[dict[str, Any]],
) -> tuple[Path, str]:
    db_path = tmp_path / "database" / "auditor.db"
    initialize(db_path)
    fp = compute_repo_fingerprint(repo_dir)
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects(
                project_key, display_name, repo_path, antigravity_project_id,
                repo_fingerprint, min_free_mb
            ) VALUES('calc', 'Calculator Repo', ?, 'proj-calc-1', ?, 1)""",
            (str(repo_dir), fp),
        )
        conn.execute(
            """INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash)
               VALUES('RUN-EXEC-1', 'calc', 'DISPATCHED', ?, 'tree-clean')""",
            (head_commit,),
        )
        conn.commit()

    stats = ingest_findings(
        db_path,
        project_key="calc",
        run_id="RUN-EXEC-1",
        findings=findings_list,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]
    v_results = []
    for f in findings_list:
        file_lines = (repo_dir / f["file_path"]).read_text(encoding="utf-8").splitlines()
        slice_text = "\n".join(file_lines[int(f["line_start"]) - 1 : int(f["line_end"])]).strip()
        excerpt = f["evidence"] if f["evidence"] in slice_text else slice_text
        v_results.append(
            {
                "candidate_finding_id": f["finding_id"],
                "verdict": "CONFIRMED",
                "verified_severity": f["severity"],
                "verified_confidence": f["confidence"],
                "technical_rationale": "Independently verified against repository snapshot.",
                "source_evidence": {
                    "file_path": f["file_path"],
                    "line_start": f["line_start"],
                    "line_end": f["line_end"],
                    "symbol": f["symbol"],
                    "evidence_excerpt": excerpt,
                },
                "remediation_review": "Proposed remediation is safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Unit and adversarial tests pass in isolated worktree.",
            }
        )
    submit_verification_results(
        db_path,
        audit_run_id="RUN-EXEC-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-exec-001",
        verification_results=v_results,
    )
    finalize_verified_report(
        db_path,
        audit_run_id="RUN-EXEC-1",
        verification_run_id=vrun_id,
    )
    decisions = [{"finding_id": f["finding_id"], "decision": "APPLY"} for f in findings_list]
    save_decisions(db_path, project_key="calc", run_id="RUN-EXEC-1", decisions=decisions)
    auth = authorize_execution(
        db_path,
        project_key="calc",
        run_id="RUN-EXEC-1",
        confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
    )
    return db_path, auth["approval_token"]


def test_isolated_worktree_excludes_secrets_repairs_within_bound_and_rolls_back_failed_finding(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "sample_repo"
    head_commit = _create_isolated_git_repo(repo_dir)

    # Create untracked secret files and node_modules in main repo -> must NEVER be copied to worktree
    (repo_dir / ".env").write_text("SECRET_KEY=never_copy_me\n", encoding="utf-8")
    (repo_dir / "private.pem").write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
    (repo_dir / "local.db").write_bytes(b"sqlite3-dummy")
    (repo_dir / "node_modules" / "pkg").mkdir(parents=True)
    (repo_dir / "node_modules" / "pkg" / "index.js").write_text("module.exports = 1;", encoding="utf-8")

    findings = [
        {
            "finding_id": "F-CALC-1",
            "fingerprint": "fp-calc-zero-div",
            "title": "ZeroDivisionError in divide",
            "category": "V3",
            "severity": "CRITICAL",
            "confidence": "CONFIRMED",
            "file_path": "calculator.py",
            "symbol": "divide",
            "line_start": 4,
            "line_end": 5,
            "evidence": "return a / b",
            "impact": "Unhandled ZeroDivisionError crash",
            "recommendation": "Raise ValueError when b == 0",
        },
        {
            "finding_id": "F-FMT-2",
            "fingerprint": "fp-fmt-strip",
            "title": "Unstripped name in greet",
            "category": "V7",
            "severity": "HIGH",
            "confidence": "LIKELY",
            "file_path": "formatter.py",
            "symbol": "greet",
            "line_start": 1,
            "line_end": 2,
            "evidence": "return f'Hello, {name}'",
            "impact": "Formatting glitch",
            "recommendation": "Strip name before formatting",
        },
    ]

    db_path, token = _setup_project_with_findings(tmp_path, repo_dir, head_commit, findings)

    # Remediation callback:
    # - F-CALC-1 fails on attempt 0 (doesn't guard b==0), succeeds on repair attempt 1!
    # - F-FMT-2 adds a forbidden raw `print()` on all attempts (0, 1, 2) -> fails red-team check and gets rolled back after 2 repair attempts!
    def remediation_fn(wt_path: Path, finding: dict[str, Any], attempt: int) -> None:
        if finding["finding_id"] == "F-CALC-1":
            if attempt == 0:
                # Incomplete fix on attempt 0 (adversarial test will fail)
                (wt_path / "calculator.py").write_text(
                    "import logging\nlogger = logging.getLogger(__name__)\n\ndef divide(a: float, b: float) -> float:\n    logger.info('dividing')\n    return a / b\n",
                    encoding="utf-8",
                )
            else:
                # Valid fix on repair attempt 1
                (wt_path / "calculator.py").write_text(
                    "import logging\nlogger = logging.getLogger(__name__)\n\ndef divide(a: float, b: float) -> float:\n    if b == 0:\n        raise ValueError('divisor cannot be zero')\n    return a / b\n",
                    encoding="utf-8",
                )
        elif finding["finding_id"] == "F-FMT-2":
            # Adds raw print() on every attempt -> red-team verifier must reject all 3 tries (attempt 0 + 2 repairs)
            (wt_path / "formatter.py").write_text(
                "def greet(name: str) -> str:\n    print('DEBUG GREET')\n    return f'Hello, {name.strip()}'\n",
                encoding="utf-8",
            )

    def happy_test_fn(wt_path: Path, finding: dict[str, Any], attempt: int) -> tuple[bool, str]:
        if finding["finding_id"] == "F-CALC-1":
            ns: dict[str, Any] = {}
            exec((wt_path / "calculator.py").read_text(encoding="utf-8"), ns)
            ok = ns["divide"](10, 2) == 5.0
            return ok, "happy path 10/2 == 5.0"
        return True, "happy path ok"

    def adversarial_test_fn(wt_path: Path, finding: dict[str, Any], attempt: int) -> tuple[bool, str]:
        if finding["finding_id"] == "F-CALC-1":
            ns: dict[str, Any] = {}
            exec((wt_path / "calculator.py").read_text(encoding="utf-8"), ns)
            try:
                ns["divide"](10, 0)
                return False, "Expected ValueError on divide by zero"
            except ValueError:
                return True, "Raised ValueError on divide by zero"
            except ZeroDivisionError:
                return False, "Unhandled ZeroDivisionError"
        return True, "adversarial ok"

    result = execute_approved_findings(
        db_path,
        project_key="calc",
        approval_token=token,
        remediation_fn=remediation_fn,
        happy_test_fn=happy_test_fn,
        adversarial_test_fn=adversarial_test_fn,
        integration_test_fn=lambda wt: (True, "Integration suite green"),
        worktrees_root=tmp_path / "worktrees",
        checkpoints_root=tmp_path / "checkpoints",
        quarantine_root=tmp_path / "quarantine",
        min_free_mb=1,
    )

    assert result["status"] == "PARTIAL"
    assert result["verified_finding_ids"] == ["F-CALC-1"]
    assert result["rolled_back_finding_ids"] == ["F-FMT-2"]

    wt_path = Path(result["worktree_path"])
    # Verify secrets and node_modules were NOT copied into isolated worktree
    assert not (wt_path / ".env").exists()
    assert not (wt_path / "private.pem").exists()
    assert not (wt_path / "local.db").exists()
    assert not (wt_path / "node_modules").exists()

    # Verify F-CALC-1's verified change IS present in worktree, while F-FMT-2 was rolled back to checkpoint!
    assert "divisor cannot be zero" in (wt_path / "calculator.py").read_text(encoding="utf-8")
    assert "print(" not in (wt_path / "formatter.py").read_text(encoding="utf-8")

    # Verify original repository was NOT modified and NO git commit was made anywhere
    assert "divisor cannot be zero" not in (repo_dir / "calculator.py").read_text(encoding="utf-8")
    wt_head = subprocess.run(
        ["git", "-C", str(wt_path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert wt_head == head_commit

    with connect(db_path) as conn:
        f1_exec = conn.execute(
            "SELECT status, repair_attempts FROM finding_executions WHERE finding_id='F-CALC-1'"
        ).fetchone()
        f2_exec = conn.execute(
            "SELECT status, repair_attempts, error FROM finding_executions WHERE finding_id='F-FMT-2'"
        ).fetchone()
        f1_lc = conn.execute("SELECT lifecycle FROM findings WHERE finding_id='F-CALC-1'").fetchone()
        f2_lc = conn.execute("SELECT lifecycle FROM findings WHERE finding_id='F-FMT-2'").fetchone()

    assert f1_exec["status"] == "VERIFIED"
    assert int(f1_exec["repair_attempts"]) == 1
    assert f1_lc["lifecycle"] == "RESOLVED"

    assert f2_exec["status"] == "ROLLED_BACK"
    assert int(f2_exec["repair_attempts"]) == 2
    assert "raw print()" in str(f2_exec["error"])
    assert f2_lc["lifecycle"] == "OPEN"


def test_uncommitted_changes_pause_finding_for_reconciliation(tmp_path: Path) -> None:
    repo_dir = tmp_path / "dirty_repo"
    head_commit = _create_isolated_git_repo(repo_dir)

    findings = [
        {
            "finding_id": "F-DIRTY-1",
            "fingerprint": "fp-dirty-calc",
            "title": "Check calc guard",
            "category": "V3",
            "severity": "HIGH",
            "confidence": "CONFIRMED",
            "file_path": "calculator.py",
            "symbol": "divide",
            "line_start": 4,
            "line_end": 5,
            "evidence": "return a / b",
            "impact": "Division error",
            "recommendation": "Guard zero",
        },
        {
            "finding_id": "F-DIRTY-2",
            "fingerprint": "fp-dirty-fmt",
            "title": "Check dirty working tree pause",
            "category": "V7",
            "severity": "MEDIUM",
            "confidence": "CONFIRMED",
            "file_path": "formatter.py",
            "symbol": "greet",
            "line_start": 1,
            "line_end": 2,
            "evidence": "def greet(name: str) -> str:",
            "impact": "Formatting",
            "recommendation": "Strip name",
        },
    ]
    db_path, token = _setup_project_with_findings(tmp_path, repo_dir, head_commit, findings)

    def remediate_and_dirty_next_file(wt_path: Path, finding: dict[str, Any], attempt: int) -> None:
        if finding["finding_id"] == "F-DIRTY-1":
            (wt_path / "calculator.py").write_text(
                "import logging\nlogger = logging.getLogger(__name__)\n\n"
                "def divide(a: float, b: float) -> float:\n"
                "    if b == 0:\n        raise ValueError('zero')\n    return a / b\n",
                encoding="utf-8",
            )
            # Introduce uncommitted modification to formatter.py in main repo mid-execution
            (repo_dir / "formatter.py").write_text("# uncommitted work in progress\n", encoding="utf-8")

    result = execute_approved_findings(
        db_path,
        project_key="calc",
        approval_token=token,
        remediation_fn=remediate_and_dirty_next_file,
        happy_test_fn=lambda wt, f, a: (True, "ok"),
        adversarial_test_fn=lambda wt, f, a: (True, "ok"),
        worktrees_root=tmp_path / "worktrees",
        checkpoints_root=tmp_path / "checkpoints",
        min_free_mb=1,
    )
    assert result["verified_finding_ids"] == ["F-DIRTY-1"]
    assert result["skipped_reconciliation_ids"] == ["F-DIRTY-2"]


def test_failed_integration_test_quarantines_worktree(tmp_path: Path) -> None:
    repo_dir = tmp_path / "quarantine_repo"
    head_commit = _create_isolated_git_repo(repo_dir)

    findings = [
        {
            "finding_id": "F-Q-1",
            "fingerprint": "fp-q-1",
            "title": "Fix greet",
            "category": "V7",
            "severity": "MEDIUM",
            "confidence": "CONFIRMED",
            "file_path": "formatter.py",
            "symbol": "greet",
            "line_start": 1,
            "line_end": 2,
            "evidence": "def greet(name: str) -> str:",
            "impact": "minor",
            "recommendation": "strip",
        }
    ]
    db_path, token = _setup_project_with_findings(tmp_path, repo_dir, head_commit, findings)

    def fix_greet(wt_path: Path, finding: dict[str, Any], attempt: int) -> None:
        (wt_path / "formatter.py").write_text(
            "def greet(name: str) -> str:\n    return f'Hello, {name.strip()}'\n",
            encoding="utf-8",
        )

    result = execute_approved_findings(
        db_path,
        project_key="calc",
        approval_token=token,
        remediation_fn=fix_greet,
        happy_test_fn=lambda wt, f, a: (True, "ok"),
        adversarial_test_fn=lambda wt, f, a: (True, "ok"),
        integration_test_fn=lambda wt: (False, "End-to-end contract regression detected"),
        worktrees_root=tmp_path / "worktrees",
        checkpoints_root=tmp_path / "checkpoints",
        quarantine_root=tmp_path / "quarantine",
        min_free_mb=1,
    )
    assert result["status"] == "QUARANTINED"
    assert "quarantine" in result
    assert Path(result["quarantine"]["preserved_diff_path"]).is_file()

    with connect(db_path) as conn:
        f_row = conn.execute("SELECT lifecycle FROM findings WHERE finding_id='F-Q-1'").fetchone()
        assert f_row["lifecycle"] == "OPEN"
        q_row = conn.execute("SELECT * FROM quarantined_worktrees").fetchone()
        assert q_row is not None
        assert q_row["status"] == "QUARANTINED"


def test_moved_repo_detection_project_discovery_and_disk_guard(tmp_path: Path) -> None:
    repo_dir = tmp_path / "movable_repo"
    head_commit = _create_isolated_git_repo(repo_dir)
    db_path = tmp_path / "database" / "auditor.db"
    findings: list[dict[str, Any]] = [
        {
            "finding_id": "F-M-1",
            "fingerprint": "fp-m-1",
            "title": "Sample",
            "category": "V1",
            "severity": "LOW",
            "confidence": "LIKELY",
            "file_path": "calculator.py",
            "symbol": "divide",
            "line_start": 4,
            "line_end": 5,
            "evidence": "return a / b",
            "impact": "i",
            "recommendation": "r",
        }
    ]
    db_path, _ = _setup_project_with_findings(tmp_path, repo_dir, head_commit, findings)

    # Create mock ~/.gemini/config/projects/*.json
    projects_cfg = tmp_path / "projects_config"
    projects_cfg.mkdir()
    relocated_dir = tmp_path / "relocated_repo"
    repo_dir.rename(relocated_dir)

    (projects_cfg / "proj-calc-1.json").write_text(
        json.dumps({
            "id": "proj-calc-1",
            "name": "Calculator Relocated",
            "projectResources": {
                "resources": [
                    {"folderUri": relocated_dir.as_uri()}
                ]
            },
        }),
        encoding="utf-8",
    )

    assert detect_project_id_for_path(relocated_dir, config_root=projects_cfg) == "proj-calc-1"

    moved = detect_moved_repositories(db_path, project_key="calc", config_root=projects_cfg)
    assert len(moved) == 1
    assert moved[0]["health_status"] == "MOVED_OR_MISSING"
    assert str(relocated_dir.resolve()) in moved[0]["relocated_candidates"]

    with pytest.raises(RuntimeError, match="Disk space guard triggered"):
        check_disk_space(tmp_path, min_free_mb=999_999_999)

"""Deterministic regression tests for Finding Quality & Verification Governance.

Covers 26 discrete scenarios:
 1. Primary prompt contains the complete valid JSON finding example.
 2. Primary prompt contains all registered schema fields and enum values.
 3. Primary prompt explicitly forbids probe / placeholder calls.
 4. Primary prompt explicitly instructs single consolidated submission.
 5. Server-side validation rejects title: "dummy".
 6. Server-side validation rejects evidence: "test".
 7. Server-side validation rejects impact: "TODO".
 8. Server-side validation rejects recommendation: "n/a".
 9. Server-side validation rejects whitespace/case-padded placeholders ("  DUMMY  ").
10. Server-side validation rejects repeated filler ("aaaa...").
11. Server-side validation accepts valid technical descriptions.
12. Atomic rejection: invalid item in batch prevents writing findings.json.
13. Atomic rejection: invalid item does not insert any row into candidate_findings.
14. Atomic rejection: invalid item does not set idempotency lock.
15. Corrected submission succeeds after a rejected placeholder attempt.
16. Duplicate valid submission with identical payload is idempotent.
17. Confirmed finding with remediation_safe = False passes finalization.
18. Confirmed finding with remediation_safe = False transitions run to READY_FOR_REVIEW.
19. Confirmed finding with remediation_safe = False sets execution_eligible = False.
20. Confirmed finding with remediation_safe = True sets execution_eligible = True.
21. save_decisions accepts non-APPLY decisions (DISMISS / DEFER) for unsafe remediation finding.
22. save_decisions rejects APPLY for finding with execution_eligible = False.
23. authorize_execution rejects run containing finding with execution_eligible = False if APPLY was attempted.
24. review-report.md renders unsafe remediation warning and critique.
25. Evidence gate still rejects missing containment findings.
26. Refuted candidates are marked REJECTED without promotion and cannot be authorized.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

# Ensure core is in sys.path
_core_dir = str(Path(__file__).resolve().parents[1] / "core")
if _core_dir not in sys.path:
    sys.path.insert(0, _core_dir)

# The Windows symlink-cleanup workaround lives in tests/conftest.py.

import pytest

from cli import build_primary_audit_prompt
from db import (
    ALLOWED_CONFIDENCES,
    ALLOWED_SEVERITIES,
    authorize_execution,
    connect,
    ingest_findings,
    initialize,
    save_decisions,
    validate_finding_item,
    validate_non_placeholder_text,
)
from mcp_server import AuditorMCPDispatcher
from review import generate_review_report, list_project_findings
from verification import (
    finalize_verified_report,
    submit_verification_results,
)


def _init_git_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(repo_dir), "init"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "test@example.com"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "Auditor Governance Test"], check=True, capture_output=True)

    (repo_dir / "src").mkdir(parents=True, exist_ok=True)
    (repo_dir / "src" / "payment.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n\n"
        "def charge_card(user_id: str, amount: float) -> dict:\n"
        "    if amount == 0:\n"
        "        return {'status': 'noop'}\n"
        "    balance_delta = -amount\n"
        "    return {'user_id': user_id, 'delta': balance_delta}\n\n"
        "def format_receipt(order_id: str) -> str:\n"
        "    return f'Receipt: {order_id.strip()}'\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "initial commit"], check=True, capture_output=True)
    return subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _seed_project_and_run(
    tmp_path: Path,
    *,
    project_key: str = "gov",
    project_id: str = "gov-test-uuid-001",
    run_id: str = "RUN-GOV-001",
) -> tuple[Path, Path, str]:
    db_path = tmp_path / "database" / "auditor.db"
    repo_dir = tmp_path / f"repo_{project_key}"
    head_sha = _init_git_repo(repo_dir)
    initialize(db_path)
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id, min_free_mb)
               VALUES(?, 'Governance Test Project', ?, ?, 1)""",
            (project_key, str(repo_dir), project_id),
        )
        conn.execute(
            """INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash, agent_conversation_id)
               VALUES(?, ?, 'PRIMARY_AUDIT_RUNNING', ?, 'clean', 'conv-primary-gov-001')""",
            (run_id, project_key, head_sha),
        )
        conn.commit()
    return db_path, repo_dir, head_sha


def _valid_candidate_finding(finding_id: str = "SEC-TEST-001") -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "fingerprint": f"fp-{finding_id.lower()}",
        "title": "Unsafe Balance Calculation in charge_card",
        "category": "INJECTION",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "file_path": "src/payment.py",
        "symbol": "charge_card",
        "line_start": 4,
        "line_end": 8,
        "evidence": "balance_delta = -amount",
        "impact": "Negative amount allows unauthorized credit refund to user balance.",
        "recommendation": "Validate that amount > 0 before processing transaction: if amount <= 0: raise ValueError('Invalid amount')",
    }


# ==============================================================================
# SECTION 1: PRIMARY PROMPT CONTRACT (Tests 1 - 4)
# ==============================================================================

def test_01_primary_prompt_contains_valid_json_example(tmp_path: Path) -> None:
    """1. Primary prompt contains the complete valid JSON finding example."""
    repo = tmp_path / "dummy_repo"
    repo.mkdir()
    meta = {
        "head_commit": "abc1234",
        "branch": "main",
        "is_clean": True,
        "staged_summary": "",
        "unstaged_summary": "",
        "untracked_summary": "",
        "manifest": {"entries": [], "complete": True, "total_files": 0},
    }
    prompt = build_primary_audit_prompt(
        project={"project_key": "test-gov", "display_name": "Test Gov"},
        repo=repo,
        run_id="RUN-PROMPT-1",
        commit="abc1234",
        tree_hash="HASH-1",
        skill_rows=[],
        repo_metadata=meta,
    )
    assert "COMPLETE VALID FINDING EXAMPLE:" in prompt
    assert '"finding_id": "SEC-SQLI-001"' in prompt
    assert '"fingerprint": "sqli-user-store-authenticate"' in prompt
    assert '"title": "SQL Injection in User Authentication Query"' in prompt
    assert '"category": "INJECTION"' in prompt
    assert '"severity": "CRITICAL"' in prompt
    assert '"confidence": "CONFIRMED"' in prompt
    assert '"file_path": "src/user_store.py"' in prompt
    assert '"symbol": "authenticate_user"' in prompt
    assert '"line_start": 42' in prompt
    assert '"line_end": 45' in prompt


def test_02_primary_prompt_contains_all_registered_schema_fields_and_enums(tmp_path: Path) -> None:
    """2. Primary prompt contains all registered schema fields and enum values."""
    repo = tmp_path / "dummy_repo"
    repo.mkdir()
    meta = {
        "head_commit": "abc1234",
        "branch": "main",
        "is_clean": True,
        "staged_summary": "",
        "unstaged_summary": "",
        "untracked_summary": "",
        "manifest": {"entries": [], "complete": True, "total_files": 0},
    }
    prompt = build_primary_audit_prompt(
        project={"project_key": "test-gov", "display_name": "Test Gov"},
        repo=repo,
        run_id="RUN-PROMPT-2",
        commit="abc1234",
        tree_hash="HASH-2",
        skill_rows=[],
        repo_metadata=meta,
    )
    # Check all registered schema fields
    for field in [
        "finding_id",
        "fingerprint",
        "title",
        "category",
        "severity",
        "confidence",
        "file_path",
        "symbol",
        "line_start",
        "line_end",
        "evidence",
        "impact",
        "recommendation",
    ]:
        assert f"- {field}:" in prompt

    # Check registered severities and confidences
    for sev in ALLOWED_SEVERITIES:
        assert sev in prompt
    for conf in ALLOWED_CONFIDENCES:
        assert conf in prompt


def test_03_primary_prompt_explicitly_forbids_probe_placeholder_calls(tmp_path: Path) -> None:
    """3. Primary prompt explicitly forbids probe / placeholder calls."""
    repo = tmp_path / "dummy_repo"
    repo.mkdir()
    meta = {
        "head_commit": "abc1234",
        "branch": "main",
        "is_clean": True,
        "staged_summary": "",
        "unstaged_summary": "",
        "untracked_summary": "",
        "manifest": {"entries": [], "complete": True, "total_files": 0},
    }
    prompt = build_primary_audit_prompt(
        project={"project_key": "test-gov", "display_name": "Test Gov"},
        repo=repo,
        run_id="RUN-PROMPT-3",
        commit="abc1234",
        tree_hash="HASH-3",
        skill_rows=[],
        repo_metadata=meta,
    )
    assert "NOT A PROBE OR DISCOVERY TOOL:" in prompt
    assert "NO PLACEHOLDER PAYLOADS:" in prompt
    assert "dummy" in prompt
    assert "placeholder" in prompt


def test_04_primary_prompt_explicitly_instructs_single_consolidated_submission(tmp_path: Path) -> None:
    """4. Primary prompt explicitly instructs single consolidated submission."""
    repo = tmp_path / "dummy_repo"
    repo.mkdir()
    meta = {
        "head_commit": "abc1234",
        "branch": "main",
        "is_clean": True,
        "staged_summary": "",
        "unstaged_summary": "",
        "untracked_summary": "",
        "manifest": {"entries": [], "complete": True, "total_files": 0},
    }
    prompt = build_primary_audit_prompt(
        project={"project_key": "test-gov", "display_name": "Test Gov"},
        repo=repo,
        run_id="RUN-PROMPT-4",
        commit="abc1234",
        tree_hash="HASH-4",
        skill_rows=[],
        repo_metadata=meta,
    )
    assert "INSPECT ALL RELEVANT FILES BEFORE PUBLISHING:" in prompt
    assert "SINGLE CONSOLIDATED PUBLICATION:" in prompt
    assert "NO PARTIAL OR INCREMENTAL REPLACEMENTS:" in prompt


# ==============================================================================
# SECTION 2: SERVER-SIDE PLACEHOLDER VALIDATION (Tests 5 - 11)
# ==============================================================================

def test_05_server_side_validation_rejects_title_dummy() -> None:
    """5. Server-side validation rejects title: 'dummy'."""
    item = _valid_candidate_finding()
    item["title"] = "dummy"
    with pytest.raises(RuntimeError, match="invalid placeholder value.*title.*dummy"):
        validate_finding_item(item, 0)


def test_06_server_side_validation_rejects_evidence_test() -> None:
    """6. Server-side validation rejects evidence: 'test'."""
    item = _valid_candidate_finding()
    item["evidence"] = "test"
    with pytest.raises(RuntimeError, match="invalid placeholder value.*evidence.*test"):
        validate_finding_item(item, 0)


def test_07_server_side_validation_rejects_impact_todo() -> None:
    """7. Server-side validation rejects impact: 'TODO'."""
    item = _valid_candidate_finding()
    item["impact"] = "TODO"
    with pytest.raises(RuntimeError, match="invalid placeholder value.*impact.*TODO"):
        validate_finding_item(item, 0)


def test_08_server_side_validation_rejects_recommendation_na() -> None:
    """8. Server-side validation rejects recommendation: 'n/a'."""
    item = _valid_candidate_finding()
    item["recommendation"] = "n/a"
    with pytest.raises(RuntimeError, match="invalid placeholder value.*recommendation.*n/a"):
        validate_finding_item(item, 0)


def test_09_server_side_validation_rejects_whitespace_case_padded_placeholders() -> None:
    """9. Server-side validation rejects whitespace/case-padded placeholders ('  DUMMY  ')."""
    item = _valid_candidate_finding()
    item["title"] = "   DUMMY   "
    with pytest.raises(RuntimeError, match="invalid placeholder value.*title.*DUMMY"):
        validate_finding_item(item, 0)

    item["title"] = "\n\t  TODO: TBD  \n"
    with pytest.raises(RuntimeError, match="placeholder words.*title"):
        validate_finding_item(item, 0)


def test_10_server_side_validation_rejects_repeated_filler() -> None:
    """10. Server-side validation rejects repeated filler ('aaaa...')."""
    item = _valid_candidate_finding()
    item["evidence"] = "aaaa..."
    with pytest.raises(RuntimeError, match="repeated filler content.*evidence.*aaaa..."):
        validate_finding_item(item, 0)

    item["evidence"] = "xxxxxx"
    with pytest.raises(RuntimeError, match="repeated filler content.*evidence.*xxxxxx"):
        validate_finding_item(item, 0)

    item["evidence"] = "..."
    with pytest.raises(RuntimeError, match="lacks meaningful alphanumeric content.*evidence"):
        validate_finding_item(item, 0)


def test_11_server_side_validation_accepts_valid_technical_descriptions() -> None:
    """11. Server-side validation accepts valid technical descriptions."""
    item = _valid_candidate_finding()
    validated = validate_finding_item(item, 0)
    assert validated["title"] == item["title"]
    assert validated["evidence"] == item["evidence"]
    assert validated["impact"] == item["impact"]
    assert validated["recommendation"] == item["recommendation"]
    assert validated["severity"] == "CRITICAL"
    assert validated["confidence"] == "CONFIRMED"


# ==============================================================================
# SECTION 3: ATOMIC REJECTION & IDEMPOTENCY (Tests 12 - 16)
# ==============================================================================

def test_12_atomic_rejection_prevents_writing_findings_json(tmp_path: Path) -> None:
    """12. Atomic rejection: invalid item in batch prevents writing findings.json."""
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-ATOM-1")
    report_dir = tmp_path / "reports" / "RUN-ATOM-1"
    findings_file = report_dir / "findings.json"

    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)
    batch = [
        _valid_candidate_finding("SEC-GOOD-001"),
        {**_valid_candidate_finding("SEC-BAD-002"), "title": "dummy"},
    ]

    with pytest.raises(RuntimeError, match="invalid placeholder value.*title.*dummy"):
        dispatcher.call_tool("auditor_publish_report", {
            "project_key": "gov",
            "run_id": "RUN-ATOM-1",
            "findings": batch,
        })

    assert not findings_file.exists(), "findings.json must not be written if batch validation fails!"


def test_13_atomic_rejection_does_not_insert_candidate_findings(tmp_path: Path) -> None:
    """13. Atomic rejection: invalid item does not insert any row into candidate_findings."""
    db_path, _, _ = _seed_project_and_run(tmp_path, run_id="RUN-ATOM-2")
    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)
    batch = [
        _valid_candidate_finding("SEC-GOOD-001"),
        {**_valid_candidate_finding("SEC-BAD-002"), "evidence": "test"},
    ]

    with pytest.raises(RuntimeError, match="invalid placeholder value.*evidence.*test"):
        dispatcher.call_tool("auditor_publish_report", {
            "project_key": "gov",
            "run_id": "RUN-ATOM-2",
            "findings": batch,
        })

    with connect(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM candidate_findings WHERE run_id='RUN-ATOM-2'").fetchone()[0]
        assert count == 0, "No candidate findings should be inserted on failed atomic batch!"


def test_14_atomic_rejection_does_not_set_idempotency_lock(tmp_path: Path) -> None:
    """14. Atomic rejection: invalid item does not set idempotency lock."""
    db_path, _, _ = _seed_project_and_run(tmp_path, run_id="RUN-ATOM-3")
    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)
    batch = [{**_valid_candidate_finding("SEC-BAD-001"), "impact": "TODO"}]

    with pytest.raises(RuntimeError, match="invalid placeholder value.*impact.*TODO"):
        dispatcher.call_tool("auditor_publish_report", {
            "project_key": "gov",
            "run_id": "RUN-ATOM-3",
            "findings": batch,
        })

    with connect(db_path) as conn:
        vrun_count = conn.execute(
            "SELECT COUNT(*) FROM audit_verification_runs WHERE audit_run_id='RUN-ATOM-3'"
        ).fetchone()[0]
        assert vrun_count == 0, "Idempotency lock (audit_verification_runs) must not be set on rejected submission!"


def test_15_corrected_submission_succeeds_after_rejected_placeholder_attempt(tmp_path: Path) -> None:
    """15. Corrected submission succeeds after a rejected placeholder attempt."""
    db_path, _, _ = _seed_project_and_run(tmp_path, run_id="RUN-ATOM-4")
    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)
    bad_batch = [{**_valid_candidate_finding("SEC-001"), "title": "dummy"}]

    # First attempt fails with placeholder error
    with pytest.raises(RuntimeError, match="invalid placeholder value"):
        dispatcher.call_tool("auditor_publish_report", {
            "project_key": "gov",
            "run_id": "RUN-ATOM-4",
            "findings": bad_batch,
        })

    # Second corrected attempt with the same run_id must succeed cleanly!
    good_batch = [_valid_candidate_finding("SEC-001")]
    res = dispatcher.call_tool("auditor_publish_report", {
        "project_key": "gov",
        "run_id": "RUN-ATOM-4",
        "findings": good_batch,
    })
    assert res["status"] == "VERIFICATION_PENDING"
    assert res["stats"]["candidate_count"] == 1

    report_dir = tmp_path / "reports" / "RUN-ATOM-4"
    assert (report_dir / "findings.json").exists()


def test_16_duplicate_valid_submission_is_idempotent(tmp_path: Path) -> None:
    """16. Duplicate valid submission with identical payload is idempotent."""
    db_path, _, _ = _seed_project_and_run(tmp_path, run_id="RUN-IDEMP-1")
    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)
    batch = [_valid_candidate_finding("SEC-001")]

    res1 = dispatcher.call_tool("auditor_publish_report", {
        "project_key": "gov",
        "run_id": "RUN-IDEMP-1",
        "findings": batch,
    })
    assert res1["status"] == "VERIFICATION_PENDING"

    res2 = dispatcher.call_tool("auditor_publish_report", {
        "project_key": "gov",
        "run_id": "RUN-IDEMP-1",
        "findings": batch,
    })
    assert res2["stats"]["idempotent_replay"] is True


# ==============================================================================
# SECTION 4: REMEDIATION SAFETY & EXECUTION ELIGIBILITY (Tests 17 - 24)
# ==============================================================================

def test_17_confirmed_finding_with_unsafe_remediation_passes_finalization(tmp_path: Path) -> None:
    """17. Confirmed finding with remediation_safe = False passes finalization."""
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-REM-1")
    candidates = [_valid_candidate_finding("F-UNSAFE-1")]

    stats = ingest_findings(
        db_path,
        project_key="gov",
        run_id="RUN-REM-1",
        findings=candidates,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-REM-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-unsafe-001",
        verification_results=[
            {
                "candidate_finding_id": "F-UNSAFE-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Verified balance calculation vulnerability.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 8,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Dangerous: proposed fix removes caller transaction isolation and introduces rollback regression.",
                "remediation_safe": False,
                "acceptance_criteria": "Verify caller isolation maintained.",
            }
        ],
    )

    # Must complete finalization without raising RuntimeError
    fin = finalize_verified_report(db_path, audit_run_id="RUN-REM-1", verification_run_id=vrun_id)
    assert fin is not None


def test_18_confirmed_finding_with_unsafe_remediation_transitions_to_ready_for_review(tmp_path: Path) -> None:
    """18. Confirmed finding with remediation_safe = False transitions run to READY_FOR_REVIEW."""
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-REM-2")
    candidates = [_valid_candidate_finding("F-UNSAFE-2")]

    stats = ingest_findings(
        db_path,
        project_key="gov",
        run_id="RUN-REM-2",
        findings=candidates,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-REM-2",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-unsafe-002",
        verification_results=[
            {
                "candidate_finding_id": "F-UNSAFE-2",
                "verdict": "CONFIRMED",
                "verified_severity": "HIGH",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Verified balance flaw.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 8,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Unsafe remediation proposal.",
                "remediation_safe": False,
                "acceptance_criteria": "None.",
            }
        ],
    )

    finalize_verified_report(db_path, audit_run_id="RUN-REM-2", verification_run_id=vrun_id)

    with connect(db_path) as conn:
        run_row = conn.execute("SELECT status FROM audit_runs WHERE run_id='RUN-REM-2'").fetchone()
        assert run_row["status"] == "READY_FOR_REVIEW"


def test_19_confirmed_finding_with_unsafe_remediation_sets_execution_eligible_false(tmp_path: Path) -> None:
    """19. Confirmed finding with remediation_safe = False sets execution_eligible = False."""
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-REM-3")
    candidates = [_valid_candidate_finding("F-UNSAFE-3")]

    stats = ingest_findings(
        db_path,
        project_key="gov",
        run_id="RUN-REM-3",
        findings=candidates,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-REM-3",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-unsafe-003",
        verification_results=[
            {
                "candidate_finding_id": "F-UNSAFE-3",
                "verdict": "CONFIRMED",
                "verified_severity": "HIGH",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed defect.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 8,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Unsafe remediation.",
                "remediation_safe": False,
                "acceptance_criteria": "None.",
            }
        ],
    )

    finalize_verified_report(db_path, audit_run_id="RUN-REM-3", verification_run_id=vrun_id)

    findings = list_project_findings(db_path, project_key="gov", run_id="RUN-REM-3")
    assert len(findings) == 1
    f = findings[0]
    assert f["verification_status"] == "VERIFIED"
    assert f["execution_eligible"] is False
    assert f["remediation_safe"] is False


def test_20_confirmed_finding_with_safe_remediation_sets_execution_eligible_true(tmp_path: Path) -> None:
    """20. Confirmed finding with remediation_safe = True sets execution_eligible = True."""
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-REM-4")
    candidates = [_valid_candidate_finding("F-SAFE-4")]

    stats = ingest_findings(
        db_path,
        project_key="gov",
        run_id="RUN-REM-4",
        findings=candidates,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-REM-4",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-safe-004",
        verification_results=[
            {
                "candidate_finding_id": "F-SAFE-4",
                "verdict": "CONFIRMED",
                "verified_severity": "HIGH",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed defect.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 8,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Remediation proposal is safe and adds appropriate input check.",
                "remediation_safe": True,
                "acceptance_criteria": "Verify negative amount raises ValueError.",
            }
        ],
    )

    finalize_verified_report(db_path, audit_run_id="RUN-REM-4", verification_run_id=vrun_id)

    findings = list_project_findings(db_path, project_key="gov", run_id="RUN-REM-4")
    assert len(findings) == 1
    f = findings[0]
    assert f["verification_status"] == "VERIFIED"
    assert f["execution_eligible"] is True
    assert f["remediation_safe"] is True


def test_21_save_decisions_accepts_non_apply_decisions_for_unsafe_remediation(tmp_path: Path) -> None:
    """21. save_decisions accepts non-APPLY decisions (DISMISS / DEFER) for unsafe remediation finding."""
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-DEC-1")
    candidates = [_valid_candidate_finding("F-DEC-1")]

    stats = ingest_findings(
        db_path,
        project_key="gov",
        run_id="RUN-DEC-1",
        findings=candidates,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-DEC-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-dec-001",
        verification_results=[
            {
                "candidate_finding_id": "F-DEC-1",
                "verdict": "CONFIRMED",
                "verified_severity": "HIGH",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed flaw.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 8,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Dangerous fix.",
                "remediation_safe": False,
                "acceptance_criteria": "None.",
            }
        ],
    )
    finalize_verified_report(db_path, audit_run_id="RUN-DEC-1", verification_run_id=vrun_id)

    # DISMISS decision must succeed
    res_dismiss = save_decisions(
        db_path,
        project_key="gov",
        run_id="RUN-DEC-1",
        decisions=[{"finding_id": "F-DEC-1", "decision": "DISMISS", "note": "False positive in this environment"}],
    )
    assert res_dismiss["counts"]["DISMISS"] == 1

    # DEFER decision must succeed
    res_defer = save_decisions(
        db_path,
        project_key="gov",
        run_id="RUN-DEC-1",
        decisions=[{"finding_id": "F-DEC-1", "decision": "DEFER", "note": "Plan manual refactor in next sprint"}],
    )
    assert res_defer["counts"]["DEFER"] == 1


def test_22_save_decisions_rejects_apply_for_execution_ineligible_finding(tmp_path: Path) -> None:
    """22. save_decisions rejects APPLY for finding with execution_eligible = False."""
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-DEC-2")
    candidates = [_valid_candidate_finding("F-DEC-2")]

    stats = ingest_findings(
        db_path,
        project_key="gov",
        run_id="RUN-DEC-2",
        findings=candidates,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-DEC-2",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-dec-002",
        verification_results=[
            {
                "candidate_finding_id": "F-DEC-2",
                "verdict": "CONFIRMED",
                "verified_severity": "HIGH",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed flaw.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 8,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Remediation introduces regression.",
                "remediation_safe": False,
                "acceptance_criteria": "None.",
            }
        ],
    )
    finalize_verified_report(db_path, audit_run_id="RUN-DEC-2", verification_run_id=vrun_id)

    with pytest.raises(RuntimeError, match="Cannot APPLY finding.*remediation_safe=0.*unsafe remediation"):
        save_decisions(
            db_path,
            project_key="gov",
            run_id="RUN-DEC-2",
            decisions=[{"finding_id": "F-DEC-2", "decision": "APPLY"}],
        )


def test_23_authorize_execution_rejects_run_if_execution_ineligible(tmp_path: Path) -> None:
    """23. authorize_execution rejects run containing finding with execution_eligible = False if APPLY was somehow attempted."""
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-AUTH-1")
    candidates = [_valid_candidate_finding("F-AUTH-1")]

    stats = ingest_findings(
        db_path,
        project_key="gov",
        run_id="RUN-AUTH-1",
        findings=candidates,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-AUTH-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-auth-001",
        verification_results=[
            {
                "candidate_finding_id": "F-AUTH-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed critical flaw.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 8,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Dangerous fix.",
                "remediation_safe": False,
                "acceptance_criteria": "None.",
            }
        ],
    )
    finalize_verified_report(db_path, audit_run_id="RUN-AUTH-1", verification_run_id=vrun_id)

    # Force insert an APPLY decision directly to verify authorize_execution gate defense-in-depth
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO decisions(finding_id, run_id, decision, actor, superseded) VALUES('F-AUTH-1', 'RUN-AUTH-1', 'APPLY', 'test', 0)"
        )
        conn.commit()

    with pytest.raises(RuntimeError, match="Finding 'F-AUTH-1' is not eligible for execution.*remediation_safe=0"):
        authorize_execution(
            db_path,
            project_key="gov",
            run_id="RUN-AUTH-1",
            confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
        )


def test_24_review_report_renders_unsafe_remediation_warning_and_critique(tmp_path: Path) -> None:
    """24. review-report.md renders unsafe remediation warning and critique."""
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-REP-1")
    candidates = [_valid_candidate_finding("F-REP-1")]

    stats = ingest_findings(
        db_path,
        project_key="gov",
        run_id="RUN-REP-1",
        findings=candidates,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    verifier_critique = "Critique: The proposed patch deletes the authentication guard entirely."
    submit_verification_results(
        db_path,
        audit_run_id="RUN-REP-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-rep-001",
        verification_results=[
            {
                "candidate_finding_id": "F-REP-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed flaw exists on line 6.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 8,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": verifier_critique,
                "remediation_safe": False,
                "acceptance_criteria": "Verify guard remains intact.",
            }
        ],
    )
    finalize_verified_report(db_path, audit_run_id="RUN-REP-1", verification_run_id=vrun_id)

    report_md = generate_review_report(
        db_path,
        project_key="gov",
        run_id="RUN-REP-1",
        output_path=tmp_path / "review-report.md",
    )

    assert "F-REP-1" in report_md
    assert "**Verification Status:** `VERIFIED`" in report_md
    assert "**Execution Eligible:** `NO`" in report_md
    assert "> [!WARNING]" in report_md
    assert "**Remediation Proposal Rejected as Unsafe:**" in report_md
    assert verifier_critique in report_md


# ==============================================================================
# SECTION 5: EVIDENCE GATE INTEGRITY (Tests 25 - 26)
# ==============================================================================

def test_25_evidence_gate_still_rejects_missing_containment_findings(tmp_path: Path) -> None:
    """25. Evidence gate still rejects missing containment findings."""
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-EV-1")
    candidates = [_valid_candidate_finding("F-EV-1")]

    stats = ingest_findings(
        db_path,
        project_key="gov",
        run_id="RUN-EV-1",
        findings=candidates,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    # Point to invalid line range not present in source code (e.g. line 9000-9050)
    submit_verification_results(
        db_path,
        audit_run_id="RUN-EV-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-ev-001",
        verification_results=[
            {
                "candidate_finding_id": "F-EV-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Claim with non-existent line range.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 9000,
                    "line_end": 9050,
                    "symbol": "charge_card",
                    "evidence_excerpt": "non_existent_code_snippet()",
                },
                "remediation_review": "Safe fix.",
                "remediation_safe": True,
                "acceptance_criteria": "None.",
            }
        ],
    )

    # K3: the finding failing the evidence gate is rejected on its own (never promoted); the run records the anomaly.
    finalize_verified_report(db_path, audit_run_id="RUN-EV-1", verification_run_id=vrun_id)

    with connect(db_path) as conn:
        run_row = conn.execute("SELECT status, evidence_anomaly_json FROM audit_runs WHERE run_id='RUN-EV-1'").fetchone()
        assert run_row["status"] == "COMPLETED" and run_row["evidence_anomaly_json"]
        assert conn.execute("SELECT COUNT(*) FROM findings WHERE last_seen_run_id='RUN-EV-1'").fetchone()[0] == 0


def test_26_evidence_gate_marks_refuted_candidates_as_rejected_without_promotion(tmp_path: Path) -> None:
    """26. Refuted candidates are marked REJECTED without promotion and cannot be authorized."""
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-EV-2")
    candidates = [_valid_candidate_finding("F-REFUTED-1")]

    stats = ingest_findings(
        db_path,
        project_key="gov",
        run_id="RUN-EV-2",
        findings=candidates,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-EV-2",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-ev-002",
        verification_results=[
            {
                "candidate_finding_id": "F-REFUTED-1",
                "verdict": "REJECTED",
                "verified_severity": "LOW",
                "verified_confidence": "SPECULATIVE",
                "technical_rationale": "Falsified: code already handles edge case correctly.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 8,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "No remediation required.",
                "remediation_safe": True,
                "acceptance_criteria": "None.",
            }
        ],
    )

    finalize_verified_report(db_path, audit_run_id="RUN-EV-2", verification_run_id=vrun_id)

    with connect(db_path) as conn:
        # Candidate status must be REJECTED
        cand = conn.execute("SELECT status, canonical_finding_id FROM candidate_findings WHERE candidate_finding_id='F-REFUTED-1'").fetchone()
        assert cand["status"] == "REJECTED"
        assert cand["canonical_finding_id"] is None

        # Findings table must NOT have an active OPEN canonical finding for this candidate
        canon = conn.execute("SELECT * FROM findings WHERE finding_id='F-REFUTED-1'").fetchone()
        assert canon is None

    # Attempting to save APPLY decision for the rejected finding must fail
    with pytest.raises(RuntimeError, match="must pass second-pass verification and canonical report finalization"):
        save_decisions(
            db_path,
            project_key="gov",
            run_id="RUN-EV-2",
            decisions=[{"finding_id": "F-REFUTED-1", "decision": "APPLY"}],
        )

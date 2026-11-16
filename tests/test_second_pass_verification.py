from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import _pytest.pathlib
import pytest

_ORIG_CLEANUP_DEAD_SYMLINKS = _pytest.pathlib.cleanup_dead_symlinks


def _safe_cleanup_dead_symlinks(root: Path) -> None:
    try:
        _ORIG_CLEANUP_DEAD_SYMLINKS(root)
    except PermissionError:
        pass


_pytest.pathlib.cleanup_dead_symlinks = _safe_cleanup_dead_symlinks

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from agentapi import AgentApiAdapter, is_valid_conversation_id
from db import (
    authorize_execution,
    backup_database,
    connect,
    ingest_findings,
    initialize,
    save_decisions,
    verify_backup_restore,
)
from mcp_server import AuditorMCPDispatcher
from review import list_project_findings
from skills import inventory
from verification import (
    VerificationWorker,
    build_verification_prompt,
    configure_verifier_sidecar,
    finalize_verified_report,
    get_quality_report,
    get_verification_context,
    get_verification_status,
    get_verifier_worker_status,
    recover_stale_verification_leases,
    recover_verification_job,
    submit_verification_results,
    validate_single_finding_evidence,
)


def _init_git_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(repo_dir), "init"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "test@example.com"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "Auditor Verifier Test"], check=True, capture_output=True)

    (repo_dir / "src").mkdir(parents=True, exist_ok=True)
    (repo_dir / "src" / "payment.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n\n"
        "def charge_card(user_id: str, amount: float) -> dict:\n"
        "    if amount == 0:\n"
        "        return {'status': 'noop'}\n"
        "    # Missing negative amount check allows unintended credit refund\n"
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
    project_key: str = "pay",
    project_id: str = "00000000-0000-4000-8000-000000000001",
    run_id: str = "RUN-2PASS-1",
) -> tuple[Path, Path, str]:
    db_path = tmp_path / "database" / "auditor.db"
    repo_dir = tmp_path / f"repo_{project_key}"
    head_sha = _init_git_repo(repo_dir)
    initialize(db_path)
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id, min_free_mb)
               VALUES(?, 'Payment Service', ?, ?, 1)""",
            (project_key, str(repo_dir), project_id),
        )
        conn.execute(
            """INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash, agent_conversation_id)
               VALUES(?, ?, 'PRIMARY_AUDIT_RUNNING', ?, 'clean', 'conv-primary-auditor-001')""",
            (run_id, project_key, head_sha),
        )
        conn.commit()
    return db_path, repo_dir, head_sha


def _sample_candidate_findings() -> list[dict[str, Any]]:
    return [
        {
            "finding_id": "F-PAY-1",
            "fingerprint": "fp-pay-negative-amount",
            "title": "Negative amount bypasses check in charge_card",
            "category": "V3",
            "severity": "CRITICAL",
            "confidence": "CONFIRMED",
            "file_path": "src/payment.py",
            "symbol": "charge_card",
            "line_start": 4,
            "line_end": 9,
            "evidence": "balance_delta = -amount",
            "impact": "Attacker can credit account by passing negative amount",
            "recommendation": "Raise ValueError when amount <= 0",
        },
        {
            "finding_id": "F-PAY-2",
            "fingerprint": "fp-pay-receipt-strip",
            "title": "Order ID not stripped in format_receipt",
            "category": "V7",
            "severity": "LOW",
            "confidence": "SPECULATIVE",
            "file_path": "src/payment.py",
            "symbol": "format_receipt",
            "line_start": 11,
            "line_end": 12,
            "evidence": "return f'Receipt: {order_id.strip()}'",
            "impact": "Minor formatting difference",
            "recommendation": "Strip order_id before formatting",
        },
    ]


def test_01_primary_report_produces_candidate_findings_only_and_single_verification_job(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path)
    candidates = _sample_candidate_findings()

    # Include a duplicate finding in the primary submission to test in-run deduplication
    stats1 = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-2PASS-1",
        findings=[candidates[0], dict(candidates[0]), candidates[1]],
        report_dir=tmp_path / "reports" / "RUN-2PASS-1",
        repo_path=repo_dir,
    )
    assert stats1["status"] == "VERIFICATION_PENDING"
    assert stats1["total_received"] == 3
    assert stats1["unique_in_run"] == 2
    assert stats1["candidate_count"] == 2
    assert stats1["inserted_open"] == 0

    with connect(db_path) as conn:
        run_row = conn.execute("SELECT status FROM audit_runs WHERE run_id='RUN-2PASS-1'").fetchone()
        assert run_row["status"] == "VERIFICATION_PENDING"
        canonical_count = conn.execute("SELECT COUNT(*) FROM findings WHERE run_id='RUN-2PASS-1'").fetchone()[0]
        assert canonical_count == 0
        cand_rows = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-2PASS-1'").fetchall()
        assert len(cand_rows) == 2
        assert all(r["status"] == "CANDIDATE" for r in cand_rows)
        q_rows = conn.execute("SELECT * FROM verification_dispatch_queue WHERE audit_run_id='RUN-2PASS-1'").fetchall()
        assert len(q_rows) == 1
        assert q_rows[0]["status"] == "QUEUED"

    # Duplicate report submission for the same run_id must be idempotent and NOT create a second job
    stats2 = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-2PASS-1",
        findings=candidates,
        report_dir=tmp_path / "reports" / "RUN-2PASS-1",
        repo_path=repo_dir,
    )
    assert stats2["idempotent_replay"] is True
    assert stats2["verification_run_id"] == stats1["verification_run_id"]
    assert stats2["verification_job_id"] == stats1["verification_job_id"]

    with connect(db_path) as conn:
        q_count = conn.execute("SELECT COUNT(*) FROM verification_dispatch_queue WHERE audit_run_id='RUN-2PASS-1'").fetchone()[0]
        v_count = conn.execute("SELECT COUNT(*) FROM audit_verification_runs WHERE audit_run_id='RUN-2PASS-1'").fetchone()[0]
    assert q_count == 1
    assert v_count == 1


def test_02_zero_findings_primary_report_still_requires_second_pass_verification(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-ZERO")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-ZERO",
        findings=[],
        report_dir=tmp_path / "reports" / "RUN-ZERO",
        repo_path=repo_dir,
    )
    assert stats["status"] == "VERIFICATION_PENDING"
    assert stats["candidate_count"] == 0

    vrun_id = stats["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id="RUN-ZERO",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-zero-001",
        verification_results=[],
    )
    fin = finalize_verified_report(
        db_path,
        audit_run_id="RUN-ZERO",
        verification_run_id=vrun_id,
    )
    # Second pass still ran; with nothing to review the run is completed and does not hold the project lock.
    assert fin["status"] == "COMPLETED"
    assert fin["canonical_finding_ids"] == []


def test_03_agentapi_adapter_mock_executable_timeout_and_invalid_output(
    tmp_path: Path,
) -> None:
    captured_cmds: list[list[str]] = []

    def success_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured_cmds.append(list(cmd))
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout='{"conversationId": "conv-independent-987654321"}\n',
            stderr="",
        )

    fake_exe = tmp_path / "agentapi.exe"
    fake_exe.write_text("mock", encoding="utf-8")

    adapter = AgentApiAdapter(executable_override=str(fake_exe), runner=success_runner)
    res_ok = adapter.start_new_conversation("Verify audit run RUN-2PASS-1", project_id="00000000-0000-4000-8000-000000000001")
    assert res_ok.ok is True
    assert res_ok.conversation_id == "conv-independent-987654321"
    assert res_ok.dispatch_uncertain is False
    assert captured_cmds[0] == [str(fake_exe.resolve()), "new-conversation", "Verify audit run RUN-2PASS-1"]

    # Missing executable
    missing_adapter = AgentApiAdapter(
        executable_override=str(tmp_path / "does_not_exist.exe"),
        env={"PATH": ""},
    )
    res_missing = missing_adapter.start_new_conversation("prompt", project_id="00000000-0000-4000-8000-000000000001")
    assert res_missing.ok is False
    assert res_missing.error_code == "AGENTAPI_UNAVAILABLE"
    assert res_missing.dispatch_uncertain is False

    # Timeout -> must mark dispatch_uncertain=True
    def timeout_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get('timeout', 30), output="partial", stderr="timeout")

    timeout_adapter = AgentApiAdapter(executable_override=str(fake_exe), runner=timeout_runner)
    res_timeout = timeout_adapter.start_new_conversation("prompt", project_id="00000000-0000-4000-8000-000000000001")
    assert res_timeout.ok is False
    assert res_timeout.error_code == "AGENTAPI_TIMEOUT"
    assert res_timeout.dispatch_uncertain is True

    # Zero exit code but no conversation ID in output -> must NOT claim success and must mark dispatch_uncertain=True
    def invalid_output_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="OK started\n", stderr="")

    invalid_adapter = AgentApiAdapter(executable_override=str(fake_exe), runner=invalid_output_runner)
    res_invalid = invalid_adapter.start_new_conversation("prompt", project_id="00000000-0000-4000-8000-000000000001")
    assert res_invalid.ok is False
    assert res_invalid.conversation_id is None
    assert res_invalid.error_code == "AGENTAPI_INVALID_OUTPUT"
    assert res_invalid.dispatch_uncertain is True
    assert not is_valid_conversation_id("PENDING")


def test_04_verification_worker_missing_project_id_and_missing_agentapi_manual_fallback(
    tmp_path: Path,
) -> None:
    # Case A: Missing/PENDING Project ID blocks automatic dispatch
    db_pending, repo_pending, _ = _seed_project_and_run(
        tmp_path / "pending_env",
        project_key="pendproj",
        project_id="PENDING",
        run_id="RUN-PEND-1",
    )
    ingest_findings(
        db_pending,
        project_key="pendproj",
        run_id="RUN-PEND-1",
        findings=_sample_candidate_findings(),
        report_dir=tmp_path / "pending_env" / "reports",
        repo_path=repo_pending,
    )
    fake_exe = tmp_path / "agentapi.exe"
    fake_exe.write_text("mock", encoding="utf-8")
    adapter_never_called = AgentApiAdapter(
        executable_override=str(fake_exe),
        runner=lambda *a, **kw: pytest.fail("agentapi must NOT be called when Project ID is PENDING"),
    )
    worker_pending = VerificationWorker(db_path=db_pending, adapter=adapter_never_called, app_home=tmp_path)
    out_pending = worker_pending.process_one_job()
    assert out_pending["status"] == "BLOCKED_CONFIGURATION"
    assert out_pending["error_code"] == "MISSING_PROJECT_ID"

    # Case B: Valid Project ID, but agentapi executable is missing -> retains job with manual prompt
    db_no_exe, repo_no_exe, _ = _seed_project_and_run(
        tmp_path / "no_exe_env",
        project_key="manualproj",
        project_id="00000000-0000-4000-8000-000000000001",
        run_id="RUN-MAN-1",
    )
    ingest_findings(
        db_no_exe,
        project_key="manualproj",
        run_id="RUN-MAN-1",
        findings=_sample_candidate_findings(),
        report_dir=tmp_path / "no_exe_env" / "reports",
        repo_path=repo_no_exe,
    )
    missing_adapter = AgentApiAdapter(executable_override=str(tmp_path / "missing_agentapi.exe"), env={"PATH": ""})
    worker_no_exe = VerificationWorker(db_path=db_no_exe, adapter=missing_adapter, app_home=tmp_path)
    out_no_exe = worker_no_exe.process_one_job()
    assert out_no_exe["status"] == "BLOCKED_CONFIGURATION"
    assert out_no_exe["error_code"] == "AGENTAPI_UNAVAILABLE"
    assert Path(out_no_exe["manual_prompt_path"]).is_file()

    prompt_text = build_verification_prompt(db_no_exe, audit_run_id="RUN-MAN-1", app_home=tmp_path)
    assert "independent-audit-verifier" in prompt_text
    assert "Never invent a source-code quotation." in prompt_text
    assert "F-PAY-1" in prompt_text
    # Ensure primary severity/confidence are NOT given as authoritative fields in candidate claims JSON
    assert '"severity": "CRITICAL"' not in prompt_text


def test_05_worker_crash_stale_lease_recovery_and_dispatch_uncertain_protection(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-RECOVERY-1")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-RECOVERY-1",
        findings=_sample_candidate_findings(),
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    # Simulate worker crash while job is CLAIMED
    with connect(db_path) as conn:
        conn.execute(
            """UPDATE verification_dispatch_queue
               SET status='CLAIMED', lease_owner='crashed-worker-1', lease_expires_at='2000-01-01T00:00:00+00:00', attempt_count=1
               WHERE verification_run_id=?""",
            (vrun_id,),
        )
        conn.commit()

    recovered = recover_stale_verification_leases(db_path)
    assert stats["verification_job_id"] in recovered["requeued_jobs"]

    # Now simulate agentapi timeout -> job becomes DISPATCH_UNCERTAIN and worker will NOT create duplicate conversations
    fake_exe = tmp_path / "agentapi.exe"
    fake_exe.write_text("mock", encoding="utf-8")
    call_counter = {"count": 0}

    def timeout_once_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        call_counter["count"] += 1
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get('timeout', 30))

    worker_timeout = VerificationWorker(
        db_path=db_path,
        adapter=AgentApiAdapter(executable_override=str(fake_exe), runner=timeout_once_runner),
        app_home=tmp_path,
    )
    res_uncertain = worker_timeout.process_one_job()
    assert res_uncertain["status"] == "DISPATCH_UNCERTAIN"
    assert call_counter["count"] == 1

    # Running worker again MUST NOT claim or dispatch a DISPATCH_UNCERTAIN job
    res_idle = worker_timeout.process_one_job()
    assert res_idle is None
    assert call_counter["count"] == 1

    # Operator explicitly recovers the uncertain job by recording the conversation ID
    rec_res = recover_verification_job(
        db_path,
        project_key="pay",
        audit_run_id="RUN-RECOVERY-1",
        action="attach-conversation",
        verifier_conversation_id="conv-recovered-from-sidecar-999",
    )
    assert rec_res["status"] == "VERIFICATION_RUNNING"
    assert rec_res["verifier_conversation_id"] == "conv-recovered-from-sidecar-999"


def test_06_every_candidate_requires_verdict_and_unknown_or_conflicting_ids_rejected(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-VERDICT-1")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-VERDICT-1",
        findings=_sample_candidate_findings(),
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    # 1. Unknown finding ID must be rejected
    with pytest.raises(ValueError, match="Unknown candidate_finding_id"):
        submit_verification_results(
            db_path,
            audit_run_id="RUN-VERDICT-1",
            verification_run_id=vrun_id,
            verifier_conversation_id="conv-verifier-verdict-1",
            verification_results=[
                {
                    "candidate_finding_id": "F-NON-EXISTENT",
                    "verdict": "CONFIRMED",
                    "verified_severity": "HIGH",
                    "verified_confidence": "CONFIRMED",
                    "technical_rationale": "x",
                    "source_evidence": {"file_path": "src/payment.py", "line_start": 4, "line_end": 9},
                    "remediation_review": "ok",
                    "acceptance_criteria": "ok",
                }
            ],
        )

    # 2. Duplicate conflicting results in same submission must be rejected
    with pytest.raises(ValueError, match="Duplicate verification result"):
        submit_verification_results(
            db_path,
            audit_run_id="RUN-VERDICT-1",
            verification_run_id=vrun_id,
            verifier_conversation_id="conv-verifier-verdict-1",
            verification_results=[
                {
                    "candidate_finding_id": "F-PAY-1",
                    "verdict": "CONFIRMED",
                    "verified_severity": "CRITICAL",
                    "verified_confidence": "CONFIRMED",
                    "technical_rationale": "r1",
                    "source_evidence": {"file_path": "src/payment.py", "line_start": 4, "line_end": 9},
                    "remediation_review": "ok",
                    "acceptance_criteria": "ok",
                },
                {
                    "candidate_finding_id": "F-PAY-1",
                    "verdict": "REJECTED",
                    "verified_severity": "LOW",
                    "verified_confidence": "SPECULATIVE",
                    "technical_rationale": "r2",
                    "source_evidence": {"file_path": "src/payment.py", "line_start": 4, "line_end": 9},
                    "remediation_review": "ok",
                    "acceptance_criteria": "ok",
                },
            ],
        )

    # 3. Partial submission (only F-PAY-1, missing F-PAY-2) -> finalization must fail
    sub_partial = submit_verification_results(
        db_path,
        audit_run_id="RUN-VERDICT-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-verdict-1",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Verified negative amount bug.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe check.",
                "remediation_safe": True,
                "acceptance_criteria": "Negative amount raises ValueError.",
            }
        ],
    )
    assert sub_partial["unresolved_candidate_ids"] == ["F-PAY-2"]

    with pytest.raises(RuntimeError, match="Unresolved candidate findings"):
        finalize_verified_report(db_path, audit_run_id="RUN-VERDICT-1", verification_run_id=vrun_id)

    # 4. Second submission to the same verification_run_id must be rejected unless requeued
    with pytest.raises(RuntimeError, match="already received a verification submission"):
        submit_verification_results(
            db_path,
            audit_run_id="RUN-VERDICT-1",
            verification_run_id=vrun_id,
            verifier_conversation_id="conv-verifier-verdict-1",
            verification_results=[],
        )

    requeued = recover_verification_job(
        db_path,
        project_key="pay",
        audit_run_id="RUN-VERDICT-1",
        action="requeue",
    )
    vrun_id_2 = requeued["verification_run_id"]
    assert vrun_id_2 != vrun_id

    # Submitting UNVERIFIABLE for F-PAY-2 on the requeued verification run must block canonical finalization
    submit_verification_results(
        db_path,
        audit_run_id="RUN-VERDICT-1",
        verification_run_id=vrun_id_2,
        verifier_conversation_id="conv-verifier-verdict-2",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Verified negative amount bug.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe check.",
                "remediation_safe": True,
                "acceptance_criteria": "Negative amount raises ValueError.",
            },
            {
                "candidate_finding_id": "F-PAY-2",
                "verdict": "UNVERIFIABLE",
                "verified_severity": "LOW",
                "verified_confidence": "SPECULATIVE",
                "technical_rationale": "External caller contract unavailable.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 11,
                    "line_end": 12,
                    "symbol": "format_receipt",
                },
                "remediation_review": "N/A",
                "acceptance_criteria": "N/A",
            },
        ],
    )
    with pytest.raises(RuntimeError, match="UNVERIFIABLE findings block canonical finalization"):
        finalize_verified_report(db_path, audit_run_id="RUN-VERDICT-1", verification_run_id=vrun_id_2)


def test_07_deterministic_evidence_gate_10_checks_and_secret_file_prohibition(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, head_sha = _seed_project_and_run(tmp_path, run_id="RUN-EVID-1")
    (repo_dir / ".env").write_text("SECRET_TOKEN=topsecret\n", encoding="utf-8")

    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-EVID-1",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-EVID-1'").fetchone()
        cand_row = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-EVID-1'").fetchone()

    snapshot_info = {
        "snapshot_id": snap_row["snapshot_id"],
        "base_commit_sha": snap_row["base_commit_sha"],
        "working_tree_hash": snap_row["working_tree_hash"],
        "file_hashes": json.loads(snap_row["file_hashes_json"]),
    }
    candidate = dict(cand_row)

    # Check 1: Absolute path forbidden
    c1 = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=candidate,
        source_evidence={"file_path": str(repo_dir / "src" / "payment.py"), "line_start": 4, "line_end": 9},
    )
    assert c1["passed"] is False
    assert c1["code"] == "ABSOLUTE_PATH_FORBIDDEN"

    # Check 2: Path traversal forbidden
    c2 = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=candidate,
        source_evidence={"file_path": "../outside.py", "line_start": 1, "line_end": 2},
    )
    assert c2["passed"] is False
    assert c2["code"] == "PATH_TRAVERSAL_FORBIDDEN"

    # Check 3: Secret file (.env) forbidden as evidence
    c3 = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=candidate,
        source_evidence={"file_path": ".env", "line_start": 1, "line_end": 1},
    )
    assert c3["passed"] is False
    assert c3["code"] == "FORBIDDEN_SECRET_PATH"

    # Check 4: Missing file detected as fabricated reference
    c4 = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=candidate,
        source_evidence={"file_path": "src/fabricated.py", "line_start": 1, "line_end": 5},
    )
    assert c4["passed"] is False
    assert c4["code"] == "FILE_NOT_FOUND"
    assert c4["fabricated_reference"] is True

    # Check 5: Out-of-bounds line range detected as fabricated reference
    c5 = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=candidate,
        source_evidence={"file_path": "src/payment.py", "line_start": 500, "line_end": 510},
    )
    assert c5["passed"] is False
    assert c5["code"] == "LINE_RANGE_OUT_OF_BOUNDS"
    assert c5["fabricated_reference"] is True

    # Check 6: Fabricated excerpt mismatch
    c6 = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=candidate,
        source_evidence={
            "file_path": "src/payment.py",
            "line_start": 4,
            "line_end": 9,
            "symbol": "charge_card",
            "evidence_excerpt": "invented_call_that_does_not_exist()",
        },
    )
    assert c6["passed"] is False
    assert c6["code"] == "FABRICATED_CODE_EXCERPT"
    assert c6["fabricated_reference"] is True

    # Check 7: Non-existent symbol detected as fabricated reference
    c7 = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=candidate,
        source_evidence={
            "file_path": "src/payment.py",
            "line_start": 4,
            "line_end": 9,
            "symbol": "non_existent_function_xyz",
            "evidence_excerpt": "balance_delta = -amount",
        },
    )
    assert c7["passed"] is False
    assert c7["code"] == "SYMBOL_NOT_FOUND_IN_FILE"
    assert c7["fabricated_reference"] is True

    # Check 8: Valid evidence passes all 10 checks
    c8 = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=candidate,
        source_evidence={
            "file_path": "src/payment.py",
            "line_start": 4,
            "line_end": 9,
            "symbol": "charge_card",
            "evidence_excerpt": "balance_delta = -amount",
        },
    )
    assert c8["passed"] is True
    assert c8["status"] == "PASSED"
    assert c8["metadata"]["base_commit_sha"] == head_sha


def test_08_changed_source_file_or_commit_marks_verification_stale(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-STALE-1")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-STALE-1",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-STALE-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-stale-1",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed negative amount issue.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe fix.",
                "remediation_safe": True,
                "acceptance_criteria": "Test negative amount.",
            }
        ],
    )

    # Modify src/payment.py BEFORE finalization -> must mark run VERIFICATION_STALE and reject finalization
    (repo_dir / "src" / "payment.py").write_text("# modified after primary snapshot\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Audit snapshot is stale"):
        finalize_verified_report(db_path, audit_run_id="RUN-STALE-1", verification_run_id=vrun_id)

    vstatus = get_verification_status(db_path, audit_run_id="RUN-STALE-1", verification_run_id=vrun_id)
    assert vstatus["audit_status"] == "VERIFICATION_STALE"
    assert vstatus["verification_lifecycle_state"] == "STALE"


def test_09_rejected_partially_confirmed_unverified_and_legacy_findings_cannot_execute(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-ELIG-1")
    candidates = _sample_candidate_findings()
    candidates.append(
        {
            "finding_id": "F-PAY-3",
            "fingerprint": "fp-pay-partial",
            "title": "Broad claim about charge_card logging and zero handling",
            "category": "V5",
            "severity": "HIGH",
            "confidence": "LIKELY",
            "file_path": "src/payment.py",
            "symbol": "charge_card",
            "line_start": 4,
            "line_end": 9,
            "evidence": "if amount == 0:",
            "impact": "No audit log on zero charge",
            "recommendation": "Log zero-amount noops at debug level",
        }
    )

    # Insert a pre-existing LEGACY_UNVERIFIED finding directly
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO findings(
                finding_id, project_key, run_id, fingerprint, title, category,
                severity, confidence, file_path, symbol, line_start, line_end,
                evidence, impact, recommendation, lifecycle, verification_status, execution_eligible
            ) VALUES(
                'F-LEGACY-0', 'pay', 'RUN-ELIG-1', 'fp-legacy-0', 'Legacy finding', 'V1',
                'HIGH', 'CONFIRMED', 'src/payment.py', 'charge_card', 4, 9,
                'legacy', 'legacy', 'legacy', 'OPEN', 'LEGACY_UNVERIFIED', 0
            )"""
        )
        conn.commit()

    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-ELIG-1",
        findings=candidates,
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    # Attempting to APPLY before verification completes must fail
    with pytest.raises(RuntimeError, match="must pass second-pass verification"):
        save_decisions(
            db_path,
            project_key="pay",
            run_id="RUN-ELIG-1",
            decisions=[{"finding_id": "F-PAY-1", "decision": "APPLY"}],
        )

    # Verifier confirms F-PAY-1, rejects F-PAY-2 (already calls .strip()!), and partially confirms F-PAY-3
    submit_verification_results(
        db_path,
        audit_run_id="RUN-ELIG-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-elig-001",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed negative amount credits balance.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe guard.",
                "remediation_safe": True,
                "acceptance_criteria": "Raise ValueError on amount < 0.",
            },
            {
                "candidate_finding_id": "F-PAY-2",
                "verdict": "REJECTED",
                "verified_severity": "LOW",
                "verified_confidence": "SPECULATIVE",
                "technical_rationale": "Falsified: format_receipt already calls order_id.strip() on line 12.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 11,
                    "line_end": 12,
                    "symbol": "format_receipt",
                    "evidence_excerpt": "order_id.strip()",
                },
                "remediation_review": "No change needed.",
                "remediation_safe": True,
                "acceptance_criteria": "None.",
            },
            {
                "candidate_finding_id": "F-PAY-3",
                "verdict": "PARTIALLY_CONFIRMED",
                "verified_severity": "LOW",
                "verified_confidence": "LIKELY",
                "technical_rationale": "Zero handling returns noop safely, only debug logging is absent.",
                "corrected_claim": "Only debug logging is missing on zero-amount noop return.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "if amount == 0:",
                },
                "remediation_review": "Optional logging only.",
                "remediation_safe": True,
                "acceptance_criteria": "Verify noop return unchanged.",
            },
        ],
    )

    fin = finalize_verified_report(db_path, audit_run_id="RUN-ELIG-1", verification_run_id=vrun_id)
    assert fin["status"] == "READY_FOR_REVIEW"

    listed = list_project_findings(db_path, project_key="pay", include_candidates=True)
    v_statuses = [f["verification_status"] for f in listed]
    assert v_statuses.count("VERIFIED") == 1
    assert v_statuses.count("PARTIALLY_VERIFIED") == 1
    assert v_statuses.count("LEGACY_UNVERIFIED") == 1
    assert v_statuses.count("REJECTED") == 1

    # 1. Rejected finding F-PAY-2 cannot be applied
    with pytest.raises(RuntimeError, match="REJECTED"):
        save_decisions(
            db_path,
            project_key="pay",
            run_id="RUN-ELIG-1",
            decisions=[{"finding_id": "F-PAY-2", "decision": "APPLY"}],
        )

    # 2. Partially confirmed finding F-PAY-3 cannot be applied
    with pytest.raises(RuntimeError, match="PARTIALLY_VERIFIED"):
        save_decisions(
            db_path,
            project_key="pay",
            run_id="RUN-ELIG-1",
            decisions=[{"finding_id": "F-PAY-3", "decision": "APPLY"}],
        )

    # 3. Legacy unverified finding F-LEGACY-0 cannot be applied
    with pytest.raises(RuntimeError, match="LEGACY_UNVERIFIED"):
        save_decisions(
            db_path,
            project_key="pay",
            run_id="RUN-ELIG-1",
            decisions=[{"finding_id": "F-LEGACY-0", "decision": "APPLY"}],
        )

    # 4. Confirmed & evidence-validated finding F-PAY-1 CAN be applied and authorized!
    save_decisions(
        db_path,
        project_key="pay",
        run_id="RUN-ELIG-1",
        decisions=[
            {"finding_id": "F-PAY-1", "decision": "APPLY"},
            {"finding_id": "F-PAY-3", "decision": "DEFER"},
        ],
    )
    auth = authorize_execution(
        db_path,
        project_key="pay",
        run_id="RUN-ELIG-1",
        confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
    )
    assert auth["approved_finding_ids"] == ["F-PAY-1"]

    # 5. If source file changes AFTER READY_FOR_REVIEW, re-authorizing execution must reject stale snapshot
    (repo_dir / "src" / "payment.py").write_text("# changed after review\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="stale"):
        authorize_execution(
            db_path,
            project_key="pay",
            run_id="RUN-ELIG-1",
            confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
        )


def test_10_dangerous_remediation_proposal_blocked_by_safety_gate(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-DANGER-1")
    bad_candidate = _sample_candidate_findings()[0]
    bad_candidate["recommendation"] = "Run git reset --hard and print(user_id) to debug"

    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-DANGER-1",
        findings=[bad_candidate],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-DANGER-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-danger-1",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Bug exists.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "UNSAFE_REMEDIATION: proposed fix uses forbidden git reset --hard and raw print().",
                "remediation_safe": False,
                "acceptance_criteria": "Do not use destructive commands.",
            }
        ],
    )

    fin = finalize_verified_report(db_path, audit_run_id="RUN-DANGER-1", verification_run_id=vrun_id)
    assert fin["status"] == "READY_FOR_REVIEW"

    # Confirmed finding is promoted with execution_eligible=False due to unsafe remediation
    findings = list_project_findings(db_path, project_key="pay", run_id="RUN-DANGER-1")
    assert len(findings) == 1
    assert findings[0]["verification_status"] == "VERIFIED"
    assert findings[0]["execution_eligible"] is False
    assert findings[0]["remediation_safe"] is False

    # Attempting to APPLY must fail
    with pytest.raises(RuntimeError, match="remediation_safe=0"):
        save_decisions(
            db_path,
            project_key="pay",
            run_id="RUN-DANGER-1",
            decisions=[{"finding_id": "F-PAY-1", "decision": "APPLY"}],
        )

    q_rep = get_quality_report(db_path, project_key="pay")
    assert q_rep["summary"]["remediation_proposals_rejected"] >= 1


def test_11_sqlite_v2_to_v3_migration_and_backup_restore_compatibility(
    tmp_path: Path,
) -> None:
    db_v2 = tmp_path / "legacy_v2.db"
    v2_sql = """
    CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO schema_migrations(version, name) VALUES (1, '001_initial_control_plane');
    INSERT INTO schema_migrations(version, name) VALUES (2, '002_lifecycle_execution_and_recovery');

    CREATE TABLE projects (
        project_key TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        repo_path TEXT NOT NULL UNIQUE,
        antigravity_project_id TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        schedule_cron TEXT NOT NULL DEFAULT '0 4 * * 1',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        repo_fingerprint TEXT,
        last_known_commit TEXT,
        health_status TEXT NOT NULL DEFAULT 'HEALTHY',
        stale_timeout_seconds INTEGER NOT NULL DEFAULT 3600,
        max_run_retries INTEGER NOT NULL DEFAULT 2,
        min_free_mb INTEGER NOT NULL DEFAULT 512
    );

    CREATE TABLE audit_runs (
        run_id TEXT PRIMARY KEY,
        project_key TEXT NOT NULL REFERENCES projects(project_key) ON DELETE CASCADE,
        trigger_source TEXT NOT NULL DEFAULT 'scheduled',
        status TEXT NOT NULL CHECK(status IN (
            'PREFLIGHT','DISPATCHED','INGESTED','PENDING_APPROVAL','APPROVED',
            'EXECUTING','COMPLETED','PARTIAL','ROLLED_BACK','QUARANTINED',
            'FAILED','STALE','RECOVERED','SKIPPED'
        )),
        base_commit TEXT,
        working_tree_hash TEXT,
        started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        finished_at TEXT,
        heartbeat_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        retry_count INTEGER NOT NULL DEFAULT 0,
        agent_conversation_id TEXT,
        report_path TEXT,
        summary_json TEXT,
        error TEXT
    );

    CREATE TABLE findings (
        finding_id TEXT PRIMARY KEY,
        project_key TEXT NOT NULL REFERENCES projects(project_key) ON DELETE CASCADE,
        run_id TEXT NOT NULL REFERENCES audit_runs(run_id) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
        confidence TEXT NOT NULL DEFAULT 'LIKELY' CHECK(confidence IN ('CONFIRMED','LIKELY','SPECULATIVE')),
        file_path TEXT,
        symbol TEXT,
        line_start INTEGER,
        line_end INTEGER,
        evidence TEXT NOT NULL,
        impact TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        evidence_hash TEXT,
        file_blob_hash TEXT,
        first_seen_run_id TEXT,
        last_seen_run_id TEXT,
        lifecycle TEXT NOT NULL DEFAULT 'OPEN' CHECK(lifecycle IN ('OPEN','APPROVED','DEFERRED','DISMISSED','RESOLVED','SUPPRESSED')),
        dismissed_reason TEXT,
        dismissed_evidence_hash TEXT,
        dismissed_file_blob_hash TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(project_key, fingerprint)
    );
    """
    with sqlite3.connect(db_v2) as raw_conn:
        raw_conn.executescript(v2_sql)
        raw_conn.execute(
            "INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id) VALUES('v2proj', 'V2 Project', 'C:/tmp/v2proj', 'proj-v2')"
        )
        raw_conn.execute(
            "INSERT INTO audit_runs(run_id, project_key, status) VALUES('RUN-V2-OLD', 'v2proj', 'PENDING_APPROVAL')"
        )
        raw_conn.execute(
            """INSERT INTO findings(
                finding_id, project_key, run_id, fingerprint, title, category,
                severity, confidence, evidence, impact, recommendation, lifecycle
            ) VALUES(
                'F-V2-OLD', 'v2proj', 'RUN-V2-OLD', 'fp-v2-old', 'Old finding', 'V2',
                'HIGH', 'LIKELY', 'ev', 'imp', 'rec', 'OPEN'
            )"""
        )
        raw_conn.commit()

    # Run initialize() to migrate v2 -> v3
    initialize(db_v2)

    with connect(db_v2) as conn:
        versions = {int(r[0]) for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
        assert {1, 2, 3}.issubset(versions)
        old_finding = conn.execute("SELECT * FROM findings WHERE finding_id='F-V2-OLD'").fetchone()
        assert old_finding is not None
        assert old_finding["verification_status"] == "LEGACY_UNVERIFIED"
        assert int(old_finding["execution_eligible"]) == 0

        # Ensure upgraded CHECK constraint on audit_runs allows new v3 states
        conn.execute("UPDATE audit_runs SET status='READY_FOR_REVIEW' WHERE run_id='RUN-V2-OLD'")
        conn.execute("UPDATE audit_runs SET status='COMPLETED' WHERE run_id='RUN-V2-OLD'")
        conn.execute(
            "INSERT INTO audit_runs(run_id, project_key, status) VALUES('RUN-V3-NEW', 'v2proj', 'VERIFICATION_PENDING')"
        )
        conn.commit()

    backup_file = backup_database(db_v2, backup_dir=tmp_path / "backups")
    restored_file = tmp_path / "restored" / "v2_migrated_restored.db"
    verify_res = verify_backup_restore(backup_file, restore_target=restored_file)
    assert verify_res["verified"] is True


def test_12_quality_metrics_skill_preservation_and_sidecar_isolation(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-METRICS-1")
    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)

    pub = dispatcher.call_tool(
        "auditor_publish_report",
        {
            "project_key": "pay",
            "run_id": "RUN-METRICS-1",
            "findings": _sample_candidate_findings(),
        },
    )
    vrun_id = pub["verification_run_id"]

    ctx = get_verification_context(db_path, audit_run_id="RUN-METRICS-1", verification_run_id=vrun_id)
    assert ctx["finding_ids"] == ["F-PAY-1", "F-PAY-2"]
    assert "auditor_submit_verification" in ctx["allowed_audit_operations"]

    dispatcher.call_tool(
        "auditor_submit_verification",
        {
            "audit_run_id": "RUN-METRICS-1",
            "verification_run_id": vrun_id,
            "verifier_conversation_id": "conv-verifier-metrics-001",
            "verifier_metadata": {
                "invocation_mechanism": "agentapi_sidecar",
                "actual_subagent_invocations": 0,
            },
            "verification_results": [
                {
                    "candidate_finding_id": "F-PAY-1",
                    "verdict": "CONFIRMED",
                    "verified_severity": "HIGH",  # recalibrated from CRITICAL -> severity_changes = 1
                    "verified_confidence": "CONFIRMED",
                    "technical_rationale": "Confirmed negative amount bug, recalibrated to HIGH.",
                    "source_evidence": {
                        "file_path": "src/payment.py",
                        "line_start": 4,
                        "line_end": 9,
                        "symbol": "charge_card",
                        "evidence_excerpt": "balance_delta = -amount",
                    },
                    "remediation_review": "Safe guard.",
                    "remediation_safe": True,
                    "acceptance_criteria": "Raise ValueError when amount <= 0.",
                },
                {
                    "candidate_finding_id": "F-PAY-2",
                    "verdict": "REJECTED",
                    "verified_severity": "LOW",
                    "verified_confidence": "SPECULATIVE",
                    "technical_rationale": "Already calls strip().",
                    "source_evidence": {
                        "file_path": "src/payment.py",
                        "line_start": 11,
                        "line_end": 12,
                        "symbol": "format_receipt",
                        "evidence_excerpt": "order_id.strip()",
                    },
                    "remediation_review": "Not needed.",
                    "remediation_safe": True,
                    "acceptance_criteria": "None.",
                },
            ],
        },
    )
    dispatcher.call_tool(
        "auditor_finalize_verified_report",
        {"audit_run_id": "RUN-METRICS-1", "verification_run_id": vrun_id},
    )

    status_out = dispatcher.call_tool("auditor_get_status", {"project_key": "pay"})
    assert status_out["quality_metrics"]["run_count"] == 1
    assert status_out["quality_metrics"]["summary"]["confirmed_findings"] == 1
    assert status_out["quality_metrics"]["summary"]["rejected_findings"] == 1
    assert status_out["quality_metrics"]["summary"]["severity_changes"] == 1
    # Model identity was not supplied -> must remain None (never invented)
    assert status_out["quality_metrics"]["history"][0]["verifier_model_id"] is None

    # Test Sidecar configuration in isolated tmp_path (never touching live ~/.gemini/config)
    sidecar_root = tmp_path / "sidecars"
    config_file = tmp_path / "config.json"
    sc_disabled = configure_verifier_sidecar(
        db_path,
        project_key="pay",
        sidecar_root=sidecar_root,
        config_path=config_file,
        cli_path=tmp_path / "core" / "cli.py",
        enable=False,
        register_in_config=False,
    )
    assert sc_disabled["enabled"] is False
    assert Path(sc_disabled["sidecar_file"]).is_file()
    assert not config_file.exists()

    sc_enabled = configure_verifier_sidecar(
        db_path,
        project_key="pay",
        sidecar_root=sidecar_root,
        config_path=config_file,
        cli_path=tmp_path / "core" / "cli.py",
        enable=True,
        register_in_config=True,
    )
    assert sc_enabled["enabled"] is True
    cfg_json = json.loads(config_file.read_text(encoding="utf-8"))
    assert cfg_json["sidecars"]["pay-verifier"] == {
        "enabled": True,
        "projectId": "00000000-0000-4000-8000-000000000001",
    }

    sc_off = configure_verifier_sidecar(
        db_path,
        project_key="pay",
        sidecar_root=sidecar_root,
        config_path=config_file,
        cli_path=tmp_path / "core" / "cli.py",
        enable=False,
        register_in_config=True,
    )
    assert sc_off["enabled"] is False

    w_status = get_verifier_worker_status(
        db_path,
        project_key="pay",
        sidecar_root=sidecar_root,
        config_path=config_file,
    )
    assert w_status["projects"][0]["sidecar_file_exists"] is True
    assert w_status["projects"][0]["sidecar_enabled"] is False

    # Verify bundled skills in worktree (including independent-audit-verifier and OmniApex skills)
    worktree_root = Path(__file__).resolve().parents[1]
    verifier_skill = worktree_root / "global-skills" / "independent-audit-verifier" / "SKILL.md"
    orchestrator_skill = worktree_root / "global-skills" / "project-auditor-orchestrator" / "SKILL.md"
    red_team_skill = worktree_root / "integrations" / "omniapex" / ".agents" / "skills" / "adversarial-red-team" / "SKILL.md"

    assert verifier_skill.is_file()
    assert orchestrator_skill.is_file()
    assert red_team_skill.is_file()

    verifier_text = verifier_skill.read_text(encoding="utf-8")
    mandatory_phrases = [
        "Never invent a source-code quotation.",
        "Never report a function or class without verifying its existence.",
        "Never use stale line numbers without snapshot verification.",
        "Never mark a finding CONFIRMED from a theoretical argument alone.",
        "Never claim tests passed unless the actual test command completed successfully.",
        "Never claim multiple specialist agents were used unless they were actually invoked.",
        "Never accept a remediation suggestion without reviewing its possible regressions.",
    ]
    for phrase in mandatory_phrases:
        assert phrase in verifier_text

    discovered = inventory(package_root=worktree_root)
    skill_names = {s['name'] for s in discovered}
    assert {
        "independent-audit-verifier",
        "project-auditor-orchestrator",
        "adversarial-red-team",
        "prompt-co-architect",
        "release-and-handoff",
    }.issubset(skill_names)



def test_13_commit_sha_change_during_verification_marks_stale(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-COMMIT-STALE")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-COMMIT-STALE",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id="RUN-COMMIT-STALE",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-commit-stale",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Tests pass.",
            }
        ],
    )

    # Create a new commit in the repository during verification
    (repo_dir / "README.md").write_text("# New commit\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_dir), "add", "README.md"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "advance HEAD"], check=True, capture_output=True)

    with pytest.raises(RuntimeError, match="STALE_COMMIT_SHA"):
        finalize_verified_report(db_path, audit_run_id="RUN-COMMIT-STALE", verification_run_id=vrun_id)

    vstatus = get_verification_status(db_path, audit_run_id="RUN-COMMIT-STALE", verification_run_id=vrun_id)
    assert vstatus["audit_status"] == "VERIFICATION_STALE"


def test_14_verifier_confirms_false_positive_with_fabricated_evidence_blocked_by_python_gate(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-FALSE-POS")
    false_claim = _sample_candidate_findings()[0]
    false_claim["finding_id"] = "F-HALLUCINATED"
    false_claim["evidence"] = "os.system(user_id)"

    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-FALSE-POS",
        findings=[false_claim],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    # Verifier rubber-stamps the hallucinated finding with a fabricated quote
    submit_verification_results(
        db_path,
        audit_run_id="RUN-FALSE-POS",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-rubber-stamp",
        verification_results=[
            {
                "candidate_finding_id": "F-HALLUCINATED",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed command injection.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "os.system(user_id)",
                },
                "remediation_review": "Remove os.system.",
                "remediation_safe": True,
                "acceptance_criteria": "No command injection.",
            }
        ],
    )

    # K3 (2026-11-16): the fabricated finding is rejected on its own instead of failing the whole run; the run is
    # marked as an evidence anomaly. With nothing else to review it is completed.
    fin = finalize_verified_report(db_path, audit_run_id="RUN-FALSE-POS", verification_run_id=vrun_id)
    assert fin["canonical_finding_ids"] == [] and fin["status"] == "COMPLETED"

    vstatus = get_verification_status(db_path, audit_run_id="RUN-FALSE-POS", verification_run_id=vrun_id)
    assert vstatus["evidence_validation_status"] == "FABRICATED_REFERENCE"
    assert vstatus["quality_metrics"]["fabricated_reference_detections"] >= 1
    with connect(db_path) as conn:
        anomaly = conn.execute("SELECT evidence_anomaly_json FROM audit_runs WHERE run_id='RUN-FALSE-POS'").fetchone()[0]
        assert "FABRICATED_CODE_EXCERPT" in anomaly
        assert conn.execute("SELECT COUNT(*) FROM findings WHERE last_seen_run_id='RUN-FALSE-POS'").fetchone()[0] == 0


def test_15_persistence_failure_after_agentapi_success_marks_dispatch_uncertain(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-PERSIST-FAIL")
    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-PERSIST-FAIL",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    fake_exe = tmp_path / "agentapi.exe"
    fake_exe.write_text("mock", encoding="utf-8")

    adapter = AgentApiAdapter(
        executable_override=str(fake_exe),
        runner=lambda cmd, **kw: subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout='{"conversation_id": "conv-created-ok-111"}', stderr=""
        ),
    )

    def failing_persist_hook(_job_id: str, _res: Any) -> None:
        raise sqlite3.OperationalError("simulated disk I/O error during conversation ID persistence")

    worker = VerificationWorker(
        db_path=db_path,
        adapter=adapter,
        app_home=tmp_path,
        persist_hook=failing_persist_hook,
    )
    out = worker.process_one_job()
    assert out is not None
    assert out["status"] == "DISPATCH_UNCERTAIN"
    assert out["error_code"] == "CONVERSATION_ID_PERSISTENCE_FAILED"


def test_16_crash_during_dispatching_lease_expiry_marks_dispatch_uncertain(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRASH-DISP")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRASH-DISP",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        conn.execute(
            """UPDATE verification_dispatch_queue
               SET status='DISPATCHING', lease_owner='worker-dead', lease_expires_at='2000-01-01T00:00:00+00:00'
               WHERE job_id=?""",
            (stats["verification_job_id"],),
        )
        conn.commit()

    rec = recover_stale_verification_leases(db_path)
    assert stats["verification_job_id"] in rec["uncertain_jobs"]


def test_17_verifier_discovered_finding_undergoes_same_evidence_and_finalization_gates(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-DISC-1")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-DISC-1",
        findings=[],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-DISC-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-disc-001",
        verification_results=[
            {
                "candidate_finding_id": "F-DISC-NEW-1",
                "verdict": "CONFIRMED",
                "verified_severity": "HIGH",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Discovered during independent code walkthrough.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe validation guard.",
                "remediation_safe": True,
                "acceptance_criteria": "Negative amount raises ValueError.",
            }
        ],
        verifier_discovered_findings=[
            {
                "finding_id": "F-DISC-NEW-1",
                "fingerprint": "fp-disc-new-1",
                "title": "Verifier discovered negative amount issue",
                "category": "V3",
                "severity": "HIGH",
                "confidence": "CONFIRMED",
                "file_path": "src/payment.py",
                "symbol": "charge_card",
                "line_start": 4,
                "line_end": 9,
                "evidence": "balance_delta = -amount",
                "impact": "Unintended balance credit",
                "recommendation": "Validate amount > 0",
            }
        ],
    )
    fin = finalize_verified_report(db_path, audit_run_id="RUN-DISC-1", verification_run_id=vrun_id)
    # CRIT-01: Parent audit run must remain VERIFICATION_PENDING while follow-up verification is unresolved
    assert fin["status"] == "VERIFICATION_PENDING"
    # HIGH-03: Verifier-discovered findings cannot be self-confirmed in the discovering conversation
    assert "F-DISC-NEW-1" not in fin["canonical_finding_ids"]
    assert fin["pending_discovered_candidate_ids"] == ["F-DISC-NEW-1"]
    assert fin["followup_verification_run_id"] is not None

    # Second independent verifier conversation confirms F-DISC-NEW-1 -> now it becomes canonical and READY_FOR_REVIEW
    submit_verification_results(
        db_path,
        audit_run_id="RUN-DISC-1",
        verification_run_id=fin["followup_verification_run_id"],
        verifier_conversation_id="conv-verifier-disc-002",
        verification_results=[
            {
                "candidate_finding_id": "F-DISC-NEW-1",
                "verdict": "CONFIRMED",
                "verified_severity": "HIGH",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Independently verified by second verifier conversation.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe validation guard.",
                "remediation_safe": True,
                "acceptance_criteria": "Negative amount raises ValueError.",
            }
        ],
    )
    fin2 = finalize_verified_report(
        db_path,
        audit_run_id="RUN-DISC-1",
        verification_run_id=fin["followup_verification_run_id"],
    )
    assert fin2["status"] == "READY_FOR_REVIEW"
    assert "F-DISC-NEW-1" in fin2["canonical_finding_ids"]


def test_18_unverifiable_candidate_recovery_via_explicit_archive_policy(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-UNVER-ARCH")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-UNVER-ARCH",
        findings=_sample_candidate_findings(),
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id="RUN-UNVER-ARCH",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-unver-001",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Verified.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test negative amount.",
            },
            {
                "candidate_finding_id": "F-PAY-2",
                "verdict": "UNVERIFIABLE",
                "verified_severity": "LOW",
                "verified_confidence": "SPECULATIVE",
                "technical_rationale": "Cannot verify external caller.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 11,
                    "line_end": 12,
                    "symbol": "format_receipt",
                },
                "remediation_review": "N/A",
                "acceptance_criteria": "N/A",
            },
        ],
    )
    with pytest.raises(RuntimeError, match="UNVERIFIABLE"):
        finalize_verified_report(db_path, audit_run_id="RUN-UNVER-ARCH", verification_run_id=vrun_id)

    # Explicitly archive F-PAY-2 under recovery policy, then finalize F-PAY-1
    recover_verification_job(
        db_path,
        project_key="pay",
        audit_run_id="RUN-UNVER-ARCH",
        action="archive-unverifiable",
        candidate_finding_id="F-PAY-2",
    )
    fin = finalize_verified_report(db_path, audit_run_id="RUN-UNVER-ARCH", verification_run_id=vrun_id)
    assert fin["status"] == "READY_FOR_REVIEW"
    assert fin["canonical_finding_ids"] == ["F-PAY-1"]


def test_19_cli_verification_commands_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import cli

    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CLI-1")
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "APP_HOME", tmp_path)
    monkeypatch.setattr(cli, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(cli, "SIDECAR_ROOT", tmp_path / "sidecars")
    monkeypatch.setattr(cli, "JSONL_PATH", tmp_path / "logs" / "events.jsonl")

    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CLI-1",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    prompt_out = tmp_path / "manual-prompt.md"
    monkeypatch.setattr(
        sys,
        "argv",
        ["cli.py", "generate-verification-prompt", "--project", "pay", "--run-id", "RUN-CLI-1", "--verification-run-id", vrun_id, "--output", str(prompt_out)],
    )
    cli.main()
    assert prompt_out.is_file()

    verdicts_file = tmp_path / "verdicts.json"
    verdicts_file.write_text(
        json.dumps(
            {
                "verification_results": [
                    {
                        "candidate_finding_id": "F-PAY-1",
                        "verdict": "CONFIRMED",
                        "verified_severity": "CRITICAL",
                        "verified_confidence": "CONFIRMED",
                        "technical_rationale": "Verified via CLI.",
                        "source_evidence": {
                            "file_path": "src/payment.py",
                            "line_start": 4,
                            "line_end": 9,
                            "symbol": "charge_card",
                            "evidence_excerpt": "balance_delta = -amount",
                        },
                        "remediation_review": "Safe.",
                        "remediation_safe": True,
                        "acceptance_criteria": "Pass tests.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cli.py",
            "submit-verification",
            "--project",
            "pay",
            "--run-id",
            "RUN-CLI-1",
            "--verification-run-id",
            vrun_id,
            "--conversation-id",
            "conv-cli-verifier-001",
            "--file",
            str(verdicts_file),
        ],
    )
    cli.main()

    monkeypatch.setattr(
        sys,
        "argv",
        ["cli.py", "finalize-verified-report", "--project", "pay", "--run-id", "RUN-CLI-1", "--verification-run-id", vrun_id],
    )
    cli.main()

    monkeypatch.setattr(
        sys,
        "argv",
        ["cli.py", "quality-report", "--project", "pay", "--run-id", "RUN-CLI-1"],
    )
    cli.main()
    captured = capsys.readouterr().out
    assert "READY_FOR_REVIEW" in captured


def test_20_state_machine_rejects_invalid_transitions_and_same_conversation_id(
    tmp_path: Path,
) -> None:
    from verification import transition_audit_run_status

    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-SM-1")
    with connect(db_path) as conn:
        # Primary audit cannot jump directly to READY_FOR_REVIEW
        with pytest.raises(RuntimeError, match="Illegal audit state transition"):
            transition_audit_run_status(conn, "RUN-SM-1", "READY_FOR_REVIEW")

    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-SM-1",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    # Submitting verification with the same conversation ID as the primary auditor must be rejected
    with pytest.raises(RuntimeError, match="Independence violation"):
        submit_verification_results(
            db_path,
            audit_run_id="RUN-SM-1",
            verification_run_id=stats["verification_run_id"],
            verifier_conversation_id="conv-primary-auditor-001",
            verification_results=[],
        )


def _prepare_verified_run_with_token(
    tmp_path: Path,
    *,
    run_id: str = "RUN-SEC-1",
) -> tuple[Path, Path, str, str]:
    db_path, repo_dir, head_sha = _seed_project_and_run(tmp_path, run_id=run_id)
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id=run_id,
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports" / run_id,
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id=run_id,
        verification_run_id=vrun_id,
        verifier_conversation_id=f"conv-verifier-{run_id.lower()}",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed negative amount bug.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe validation check.",
                "remediation_safe": True,
                "acceptance_criteria": "Raise ValueError when amount <= 0.",
            }
        ],
    )
    finalize_verified_report(db_path, audit_run_id=run_id, verification_run_id=vrun_id)
    save_decisions(
        db_path,
        project_key="pay",
        run_id=run_id,
        decisions=[{"finding_id": "F-PAY-1", "decision": "APPLY"}],
    )
    auth = authorize_execution(
        db_path,
        project_key="pay",
        run_id=run_id,
        confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
    )
    return db_path, repo_dir, head_sha, str(auth["approval_token"])


def test_21_high_01_stale_approval_token_after_file_edit_rejected_without_consuming_or_worktree(
    tmp_path: Path,
) -> None:
    from executor import start_isolated_execution

    db_path, repo_dir, _, token = _prepare_verified_run_with_token(tmp_path, run_id="RUN-H01-FILE")
    wt_root = tmp_path / "worktrees"

    # Modify tracked source file AFTER authorize_execution and BEFORE start_isolated_execution
    (repo_dir / "src" / "payment.py").write_text("# modified after token issued\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="stale repository snapshot"):
        start_isolated_execution(
            db_path,
            project_key="pay",
            approval_token=token,
            worktrees_root=wt_root,
            min_free_mb=1,
        )

    with connect(db_path) as conn:
        run_st = conn.execute("SELECT status FROM audit_runs WHERE run_id='RUN-H01-FILE'").fetchone()["status"]
        vrun_st = conn.execute("SELECT status FROM audit_verification_runs WHERE audit_run_id='RUN-H01-FILE'").fetchone()["status"]
        app_st = conn.execute("SELECT status FROM execution_approvals WHERE approval_token=?", (token,)).fetchone()["status"]
        exec_cnt = conn.execute("SELECT COUNT(*) FROM execution_runs WHERE run_id='RUN-H01-FILE'").fetchone()[0]

    assert run_st == "VERIFICATION_STALE"
    assert vrun_st == "STALE"
    # Token must NOT be marked CONSUMED on stale rejection
    assert app_st == "AUTHORIZED"
    assert exec_cnt == 0
    assert not wt_root.exists() or list(wt_root.rglob("*")) == []


def test_22_high_01_new_commit_invalidates_approval_token_and_mcp_step_execution(
    tmp_path: Path,
) -> None:
    from executor import start_isolated_execution, update_finding_execution_step

    db_path, repo_dir, _, token = _prepare_verified_run_with_token(tmp_path, run_id="RUN-H01-COMMIT")
    wt_root = tmp_path / "worktrees"

    # Create a new commit in repo_dir AFTER authorize_execution
    (repo_dir / "src" / "payment.py").write_text("# new commit after approval\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "post-approval commit"], check=True, capture_output=True)

    with pytest.raises(RuntimeError, match="stale repository snapshot"):
        start_isolated_execution(
            db_path,
            project_key="pay",
            approval_token=token,
            worktrees_root=wt_root,
            min_free_mb=1,
        )

    # Also verify MCP step-by-step execution (`update_finding_execution_step`) blocks if repo drifts after start
    env2 = tmp_path / "mcp_step_env"
    db2, repo2, _, token2 = _prepare_verified_run_with_token(env2, run_id="RUN-H01-MCPSTEP")
    started = start_isolated_execution(
        db2,
        project_key="pay",
        approval_token=token2,
        worktrees_root=env2 / "worktrees",
        min_free_mb=1,
    )
    # Now commit a change to repo2 before calling update_finding_execution_step(action="begin")
    (repo2 / "src" / "payment.py").write_text("# drift before MCP step begin\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo2), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo2), "commit", "-m", "drift"], check=True, capture_output=True)

    with pytest.raises(RuntimeError, match="stale repository snapshot"):
        update_finding_execution_step(
            db2,
            project_key="pay",
            exec_id=started["exec_id"],
            finding_id="F-PAY-1",
            action="begin",
            checkpoints_root=env2 / "checkpoints",
        )


def test_23_med_01_new_untracked_source_file_invalidates_snapshot_and_execution(
    tmp_path: Path,
) -> None:
    from executor import start_isolated_execution

    db_path, repo_dir, _, token = _prepare_verified_run_with_token(tmp_path, run_id="RUN-M01-UNTRACKED")
    wt_root = tmp_path / "worktrees"

    # Add a new untracked Python source file after snapshot/authorization
    (repo_dir / "src" / "rogue_untracked.py").write_text("x = 1\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="STALE_UNTRACKED_FILE_ADDED|New or untracked file"):
        start_isolated_execution(
            db_path,
            project_key="pay",
            approval_token=token,
            worktrees_root=wt_root,
            min_free_mb=1,
        )

    with connect(db_path) as conn:
        run_st = conn.execute("SELECT status FROM audit_runs WHERE run_id='RUN-M01-UNTRACKED'").fetchone()["status"]
        app_st = conn.execute("SELECT status FROM execution_approvals WHERE approval_token=?", (token,)).fetchone()["status"]
    assert run_st == "VERIFICATION_STALE"
    assert app_st == "AUTHORIZED"


def test_24_high_02_cross_run_apply_decision_leakage_blocked(
    tmp_path: Path,
) -> None:
    # Run 1: F-PAY-1 is verified and receives APPLY
    db_path, repo_dir, head_sha, _ = _prepare_verified_run_with_token(tmp_path, run_id="RUN-ISO-1")

    # Run 2: New audit run on the same project has a DIFFERENT verified finding (F-PAY-2), while F-PAY-1 was NOT verified in Run 2
    with connect(db_path) as conn:
        conn.execute("UPDATE audit_runs SET status='COMPLETED' WHERE run_id='RUN-ISO-1'")
        conn.execute(
            """INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash, agent_conversation_id)
               VALUES('RUN-ISO-2', 'pay', 'PRIMARY_AUDIT_RUNNING', ?, 'clean', 'conv-primary-iso-2')""",
            (head_sha,),
        )
        conn.commit()

    stats2 = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-ISO-2",
        findings=[_sample_candidate_findings()[1]],  # Only F-PAY-2 in Run 2
        report_dir=tmp_path / "reports" / "RUN-ISO-2",
        repo_path=repo_dir,
    )
    vrun2 = stats2["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id="RUN-ISO-2",
        verification_run_id=vrun2,
        verifier_conversation_id="conv-verifier-iso-2",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-2",
                "verdict": "REJECTED",
                "verified_severity": "LOW",
                "verified_confidence": "SPECULATIVE",
                "technical_rationale": "Already calls strip().",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 11,
                    "line_end": 12,
                    "symbol": "format_receipt",
                    "evidence_excerpt": "order_id.strip()",
                },
                "remediation_review": "No fix needed.",
                "remediation_safe": True,
                "acceptance_criteria": "None.",
            }
        ],
    )
    finalize_verified_report(db_path, audit_run_id="RUN-ISO-2", verification_run_id=vrun2)

    # Run 2 has NO APPLY decisions of its own; Run 1's APPLY decision on F-PAY-1 MUST NOT leak into Run 2!
    # Run 2 has nothing left to review, so it is COMPLETED: authorization is refused either way.
    with pytest.raises(RuntimeError, match="cannot leak across runs|No OPEN, second-pass VERIFIED|status 'COMPLETED'"):
        authorize_execution(
            db_path,
            project_key="pay",
            run_id="RUN-ISO-2",
            confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
        )


def test_25_low_01_save_decisions_rejects_defer_dismiss_on_unverified_or_foreign_run(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, head_sha, _ = _prepare_verified_run_with_token(tmp_path, run_id="RUN-L01-1")

    with connect(db_path) as conn:
        conn.execute("UPDATE audit_runs SET status='COMPLETED' WHERE run_id='RUN-L01-1'")
        conn.execute(
            """INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash, agent_conversation_id)
               VALUES('RUN-L01-PENDING', 'pay', 'PRIMARY_AUDIT_RUNNING', ?, 'clean', 'conv-primary-l01-2')""",
            (head_sha,),
        )
        conn.commit()

    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-L01-PENDING",
        findings=[_sample_candidate_findings()[1]],
        report_dir=tmp_path / "reports" / "RUN-L01-PENDING",
        repo_path=repo_dir,
    )

    # Attempting DEFER or DISMISS while RUN-L01-PENDING is still in VERIFICATION_PENDING must be rejected!
    for dec_type in ("DEFER", "DISMISS", "SKIP"):
        with pytest.raises(RuntimeError, match="VERIFICATION_PENDING"):
            save_decisions(
                db_path,
                project_key="pay",
                run_id="RUN-L01-PENDING",
                decisions=[{"finding_id": "F-PAY-1", "decision": dec_type}],
            )


def test_26_high_03_verifier_discovered_finding_cannot_self_confirm_or_execute(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-H03-1")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-H03-1",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports" / "RUN-H03-1",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-H03-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-h03-A",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed primary candidate.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe guard.",
                "remediation_safe": True,
                "acceptance_criteria": "Raise ValueError.",
            },
            {
                "candidate_finding_id": "F-DISC-SELF",
                "verdict": "CONFIRMED",
                "verified_severity": "HIGH",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Verifier attempts to self-confirm its own discovered finding.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 11,
                    "line_end": 12,
                    "symbol": "format_receipt",
                    "evidence_excerpt": "order_id.strip()",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test.",
            },
        ],
        verifier_discovered_findings=[
            {
                "finding_id": "F-DISC-SELF",
                "fingerprint": "fp-disc-self",
                "title": "Verifier-discovered receipt issue",
                "category": "V7",
                "severity": "HIGH",
                "confidence": "CONFIRMED",
                "file_path": "src/payment.py",
                "symbol": "format_receipt",
                "line_start": 11,
                "line_end": 12,
                "evidence": "return f'Receipt: {order_id.strip()}'",
                "impact": "Receipt formatting",
                "recommendation": "Validate order_id",
            }
        ],
    )

    fin = finalize_verified_report(db_path, audit_run_id="RUN-H03-1", verification_run_id=vrun_id)
    assert fin["canonical_finding_ids"] == ["F-PAY-1"]
    assert fin["pending_discovered_candidate_ids"] == ["F-DISC-SELF"]
    followup_vrun_id = fin["followup_verification_run_id"]
    assert followup_vrun_id == "VRUN-RUN-H03-1-DISC"

    # F-DISC-SELF is visible in list_project_findings as a CANDIDATE with execution_eligible=False
    listed = {f["finding_id"]: f for f in list_project_findings(db_path, project_key="pay", run_id="RUN-H03-1")}
    assert listed["F-DISC-SELF"]["verification_status"] == "CANDIDATE"
    assert listed["F-DISC-SELF"]["execution_eligible"] is False
    assert listed["F-DISC-SELF"]["source_origin"] == "VERIFIER_DISCOVERED"

    # Trying to APPLY F-DISC-SELF before independent verification must be rejected
    with pytest.raises(RuntimeError, match="must pass second-pass verification|not a verified canonical finding"):
        save_decisions(
            db_path,
            project_key="pay",
            run_id="RUN-H03-1",
            decisions=[{"finding_id": "F-DISC-SELF", "decision": "APPLY"}],
        )

    # Same verifier conversation (conv-verifier-h03-A) trying to verify F-DISC-SELF in follow-up run must be rejected!
    with pytest.raises(RuntimeError, match="Independence violation"):
        submit_verification_results(
            db_path,
            audit_run_id="RUN-H03-1",
            verification_run_id=followup_vrun_id,
            verifier_conversation_id="conv-verifier-h03-A",
            verification_results=[
                {
                    "candidate_finding_id": "F-DISC-SELF",
                    "verdict": "CONFIRMED",
                    "verified_severity": "HIGH",
                    "verified_confidence": "CONFIRMED",
                    "technical_rationale": "Self-confirm attempt.",
                    "source_evidence": {
                        "file_path": "src/payment.py",
                        "line_start": 11,
                        "line_end": 12,
                        "symbol": "format_receipt",
                        "evidence_excerpt": "order_id.strip()",
                    },
                    "remediation_review": "Safe.",
                    "remediation_safe": True,
                    "acceptance_criteria": "Test.",
                }
            ],
        )


def test_27_med_04_duplicate_or_conflicting_verifier_submission_rejected_and_snapshot_immutable(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-M04-1")
    (repo_dir / "src" / "extra.py").write_text("def extra_fn():\n    return 42\n", encoding="utf-8")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-M04-1",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports" / "RUN-M04-1",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]

    with connect(db_path) as conn:
        snap_before = conn.execute("SELECT file_hashes_json FROM audit_snapshots WHERE run_id='RUN-M04-1'").fetchone()["file_hashes_json"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-M04-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-verifier-m04-first",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "First valid submission.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test.",
            }
        ],
        verifier_discovered_findings=[
            {
                "finding_id": "F-DISC-EXTRA",
                "fingerprint": "fp-disc-extra",
                "title": "Extra finding",
                "category": "V1",
                "severity": "LOW",
                "confidence": "LIKELY",
                "file_path": "src/extra.py",
                "symbol": "extra_fn",
                "line_start": 1,
                "line_end": 2,
                "evidence": "return 42",
                "impact": "None",
                "recommendation": "None",
            }
        ],
    )

    # Audit snapshot must remain strictly immutable even after verifier_discovered_findings
    with connect(db_path) as conn:
        snap_after = conn.execute("SELECT file_hashes_json FROM audit_snapshots WHERE run_id='RUN-M04-1'").fetchone()["file_hashes_json"]
    assert snap_after == snap_before

    # Second submission from a different (or same) verifier_conversation_id for the same verification_run_id must be rejected
    with pytest.raises(RuntimeError, match="already received a verification submission"):
        submit_verification_results(
            db_path,
            audit_run_id="RUN-M04-1",
            verification_run_id=vrun_id,
            verifier_conversation_id="conv-verifier-m04-second-conflicting",
            verification_results=[
                {
                    "candidate_finding_id": "F-PAY-1",
                    "verdict": "REJECTED",
                    "verified_severity": "LOW",
                    "verified_confidence": "SPECULATIVE",
                    "technical_rationale": "Attempted overwrite to REJECTED.",
                    "source_evidence": {
                        "file_path": "src/payment.py",
                        "line_start": 4,
                        "line_end": 9,
                        "symbol": "charge_card",
                        "evidence_excerpt": "balance_delta = -amount",
                    },
                    "remediation_review": "N/A",
                    "acceptance_criteria": "N/A",
                }
            ],
        )


def test_28_high_04_sqlite_migration_mid_failure_rolls_back_completely(
    tmp_path: Path,
) -> None:
    db_v2 = tmp_path / "atomic_v2.db"
    v2_sql = """
    CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO schema_migrations(version, name) VALUES (1, '001_initial_control_plane');
    INSERT INTO schema_migrations(version, name) VALUES (2, '002_lifecycle_execution_and_recovery');

    CREATE TABLE projects (
        project_key TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        repo_path TEXT NOT NULL UNIQUE,
        antigravity_project_id TEXT
    );
    INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id)
    VALUES ('atomicproj', 'Atomic Project', '/tmp/atomic', '00000000-0000-4000-8000-000000000001');

    CREATE TABLE audit_runs (
        run_id TEXT PRIMARY KEY,
        project_key TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'DISPATCHED'
            CHECK (status IN ('DISPATCHED','ANALYZING','PENDING_APPROVAL','READY_FOR_REVIEW','COMPLETED','PARTIAL','FAILED','STALE')),
        started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO audit_runs(run_id, project_key, status) VALUES ('RUN-V2-ATOMIC', 'atomicproj', 'READY_FOR_REVIEW');

    CREATE TABLE findings (
        finding_id TEXT PRIMARY KEY,
        project_key TEXT NOT NULL,
        run_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL DEFAULT 'LIKELY',
        file_path TEXT,
        symbol TEXT,
        line_start INTEGER,
        line_end INTEGER,
        evidence TEXT NOT NULL,
        impact TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        lifecycle TEXT NOT NULL DEFAULT 'OPEN'
            CHECK (lifecycle IN ('OPEN','DEFERRED','DISMISSED','RESOLVED','SKIPPED','STALE')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(project_key, fingerprint)
    );
    INSERT INTO findings(
        finding_id, project_key, run_id, fingerprint, title, category,
        severity, confidence, file_path, symbol, line_start, line_end,
        evidence, impact, recommendation, lifecycle
    ) VALUES (
        'F-V2-ATOMIC', 'atomicproj', 'RUN-V2-ATOMIC', 'fp-v2-atomic', 'V2 Finding', 'V1',
        'HIGH', 'CONFIRMED', 'src/a.py', 'fn', 1, 2, 'ev', 'imp', 'rec', 'OPEN'
    );
    """
    raw_conn = sqlite3.connect(str(db_v2))
    raw_conn.executescript(v2_sql)
    raw_conn.close()

    def inject_fault(conn: sqlite3.Connection, stage: str) -> None:
        if stage == "before_commit":
            raise RuntimeError("Simulated mid-migration power loss / SQL error")

    with pytest.raises(RuntimeError, match="Simulated mid-migration power loss"):
        initialize(db_v2, _migration_fault_hook=inject_fault)

    # Verify database rolled back completely to v2!
    check_conn = sqlite3.connect(str(db_v2))
    versions = [r[0] for r in check_conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()]
    tables = {r[0] for r in check_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    f_cols = {r[1] for r in check_conn.execute("PRAGMA table_info(findings)").fetchall()}
    f_count = check_conn.execute("SELECT COUNT(*) FROM findings WHERE finding_id='F-V2-ATOMIC'").fetchone()[0]
    check_conn.close()

    assert versions == [1, 2]
    assert "candidate_findings" not in tables
    assert "audit_verification_runs" not in tables
    assert "verification_status" not in f_cols
    assert f_count == 1

    # Now re-run initialize without fault -> must succeed cleanly and upgrade to v3!
    initialize(db_v2)
    with connect(db_v2) as conn:
        versions_after = [r["version"] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()]
        f_row = conn.execute("SELECT verification_status, execution_eligible FROM findings WHERE finding_id='F-V2-ATOMIC'").fetchone()
    assert {1, 2, 3}.issubset(set(versions_after))
    assert f_row["verification_status"] == "LEGACY_UNVERIFIED"
    assert int(f_row["execution_eligible"]) == 0


def test_29_med_03_evidence_excerpt_outside_line_range_rejected(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-M03-RANGE")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-M03-RANGE",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-M03-RANGE'").fetchone()
        cand_row = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-M03-RANGE'").fetchone()

    snapshot_info = {
        "snapshot_id": snap_row["snapshot_id"],
        "base_commit_sha": snap_row["base_commit_sha"],
        "working_tree_hash": snap_row["working_tree_hash"],
        "file_hashes": json.loads(snap_row["file_hashes_json"]),
    }
    # 'order_id.strip()' exists on line 12 of src/payment.py, NOT in lines 4..9!
    res = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=dict(cand_row),
        source_evidence={
            "file_path": "src/payment.py",
            "line_start": 4,
            "line_end": 9,
            "symbol": "charge_card",
            "evidence_excerpt": "order_id.strip()",
        },
    )
    assert res["passed"] is False
    assert res["code"] == "FABRICATED_CODE_EXCERPT"


def test_30_med_03_empty_evidence_excerpt_rejected(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-M03-EMPTY")
    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-M03-EMPTY",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-M03-EMPTY'").fetchone()
        cand_row = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-M03-EMPTY'").fetchone()

    snapshot_info = {
        "snapshot_id": snap_row["snapshot_id"],
        "base_commit_sha": snap_row["base_commit_sha"],
        "working_tree_hash": snap_row["working_tree_hash"],
        "file_hashes": json.loads(snap_row["file_hashes_json"]),
    }
    for empty_ev in (
        {"file_path": "src/payment.py", "line_start": 4, "line_end": 9, "symbol": "charge_card", "evidence_excerpt": ""},
        {"file_path": "src/payment.py", "line_start": 4, "line_end": 9, "symbol": "charge_card", "evidence_excerpt": "   "},
        {"file_path": "src/payment.py", "line_start": 4, "line_end": 9, "symbol": "charge_card"},
    ):
        res = validate_single_finding_evidence(
            repo_path=repo_dir,
            snapshot_info=snapshot_info,
            candidate=dict(cand_row),
            source_evidence=empty_ev,
        )
        assert res["passed"] is False
        assert res["code"] == "MISSING_EVIDENCE_EXCERPT"


def test_31_med_03_symbol_only_in_comment_or_outside_range_rejected(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-M03-SYM")
    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-M03-SYM",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-M03-SYM'").fetchone()
        cand_row = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-M03-SYM'").fetchone()

    snapshot_info = {
        "snapshot_id": snap_row["snapshot_id"],
        "base_commit_sha": snap_row["base_commit_sha"],
        "working_tree_hash": snap_row["working_tree_hash"],
        "file_hashes": json.loads(snap_row["file_hashes_json"]),
    }

    # 1. 'refund' appears ONLY inside a comment on line 6 ("# Missing negative amount check allows unintended credit refund")
    res_comment = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=dict(cand_row),
        source_evidence={
            "file_path": "src/payment.py",
            "line_start": 4,
            "line_end": 9,
            "symbol": "refund",
            "evidence_excerpt": "balance_delta = -amount",
        },
    )
    assert res_comment["passed"] is False
    assert res_comment["code"] == "SYMBOL_NOT_FOUND_IN_FILE"

    # 2. 'format_receipt' is a real function on lines 11..12, outside lines 4..9
    res_outside = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=dict(cand_row),
        source_evidence={
            "file_path": "src/payment.py",
            "line_start": 4,
            "line_end": 9,
            "symbol": "format_receipt",
            "evidence_excerpt": "balance_delta = -amount",
        },
    )
    assert res_outside["passed"] is False
    assert res_outside["code"] == "SYMBOL_OUTSIDE_LINE_RANGE"


def test_32_med_02_prohibitive_remediation_warning_not_false_positive() -> None:
    from verification import is_remediation_safe

    safe1, _ = is_remediation_safe(
        "Do not use git reset --hard; instead use a bounded revert commit.",
        "Verified safe rollback strategy.",
        True,
    )
    safe2, _ = is_remediation_safe(
        "Remove chmod 777 and enforce 0600 permissions on key files.",
        "Permissions tightened safely.",
        True,
    )
    safe3, _ = is_remediation_safe(
        "Asla DROP TABLE kullanma; migration içinde tabloyu koru.",
        "Safe migration advice.",
        True,
    )
    assert safe1 is True
    assert safe2 is True
    assert safe3 is True


def test_33_med_02_actual_dangerous_remediation_command_rejected() -> None:
    from verification import is_remediation_safe

    unsafe1, reason1 = is_remediation_safe(
        "Run git reset --hard on the repository to clear state.",
        "Looks ok.",
        True,
    )
    unsafe2, reason2 = is_remediation_safe(
        "Do not log warnings; execute chmod 777 on the config directory.",
        "Looks ok.",
        True,
    )
    assert unsafe1 is False
    assert "git reset --hard" in reason1
    assert unsafe2 is False
    assert "chmod 777" in reason2


def test_34_med_05_expired_worker_lease_fenced_before_and_after_dispatch(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-M05-RACE")
    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-M05-RACE",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )

    fake_exe = tmp_path / "agentapi.exe"
    fake_exe.write_text("mock", encoding="utf-8")
    dispatch_calls: list[str] = []

    def counting_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        dispatch_calls.append(f"call-{len(dispatch_calls) + 1}")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=f'{{"conversationId": "conv-worker-{len(dispatch_calls)}"}}\n',
            stderr="",
        )

    adapter = AgentApiAdapter(executable_override=str(fake_exe), runner=counting_runner)
    worker_b = VerificationWorker(
        db_path=db_path,
        adapter=adapter,
        app_home=tmp_path,
        worker_id="worker-B",
    )

    # When worker_a claims the job, simulate worker_a stalling until its lease expires and worker_b claims and dispatches it!
    def simulate_lease_expiry_and_worker_b_takeover(claimed_job: dict[str, Any]) -> None:
        with connect(db_path) as conn:
            conn.execute(
                "UPDATE verification_dispatch_queue SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE job_id=?",
                (claimed_job["job_id"],),
            )
            conn.commit()
        res_b = worker_b.process_one_job()
        assert res_b is not None
        assert res_b["status"] == "RUNNING"
        assert res_b["verifier_conversation_id"] == "conv-worker-1"

    worker_a = VerificationWorker(
        db_path=db_path,
        adapter=adapter,
        app_home=tmp_path,
        worker_id="worker-A",
        pre_dispatch_hook=simulate_lease_expiry_and_worker_b_takeover,
    )
    res_a = worker_a.process_one_job()
    assert res_a is not None
    assert res_a["status"] == "LEASE_LOST"
    assert res_a["error_code"] == "STALE_WORKER_FENCED"
    # Worker A must NOT have invoked agentapi a second time!
    assert len(dispatch_calls) == 1

    with connect(db_path) as conn:
        q_row = conn.execute("SELECT status, verifier_conversation_id, lease_owner FROM verification_dispatch_queue WHERE audit_run_id='RUN-M05-RACE'").fetchone()
    assert q_row["status"] == "RUNNING"
    assert q_row["verifier_conversation_id"] == "conv-worker-1"
    assert q_row["lease_owner"] == "worker-B"


def test_35_ins_01_generate_verifier_sidecars_uses_real_schema_and_preserves_config(
    tmp_path: Path,
) -> None:
    from verification import generate_all_verifier_sidecars

    db_path, _, _ = _seed_project_and_run(tmp_path, project_key="pay", run_id="RUN-INS01")
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id)
               VALUES('pend', 'Pending Project', ?, 'PENDING')""",
            (str(tmp_path / "repo_pend"),),
        )
        conn.commit()

    sidecar_root = tmp_path / "sidecars"
    config_path = tmp_path / "config.json"
    original_cfg = {
        "sidecars": {
            "existing-primary-sidecar": {"enabled": True, "projectId": "00000000-0000-4000-8000-000000000001"}
        },
        "customSetting": "preserve-me",
    }
    config_path.write_text(json.dumps(original_cfg, indent=2), encoding="utf-8")

    res = generate_all_verifier_sidecars(
        db_path,
        sidecar_root=sidecar_root,
        config_path=config_path,
        cli_path=tmp_path / "core" / "cli.py",
        enable=False,
        register_in_config=False,
    )
    assert res["generated_count"] == 1
    assert res["skipped_count"] == 1
    assert res["generated"][0]["project_key"] == "pay"
    assert res["skipped"][0]["project_key"] == "pend"
    assert (sidecar_root / "pay-verifier" / "sidecar.json").is_file()
    assert not (sidecar_root / "pend-verifier" / "sidecar.json").exists()

    # Existing config.json must remain completely untouched when enable=False, register_in_config=False
    after_cfg = json.loads(config_path.read_text(encoding="utf-8"))
    assert after_cfg == original_cfg


def test_36_ins_03_global_skill_install_preserves_customized_skills(
    tmp_path: Path,
) -> None:
    from skills import install_global_skills_safely

    bundle_dir = tmp_path / "bundle_skills"
    target_dir = tmp_path / "global_skills"
    backup_dir = tmp_path / "skill_backups"

    # Create two bundle skills: independent-audit-verifier and project-auditor-orchestrator
    (bundle_dir / "independent-audit-verifier").mkdir(parents=True)
    (bundle_dir / "independent-audit-verifier" / "SKILL.md").write_text(
        "---\nname: independent-audit-verifier\ndescription: verifier\n---\nBundle Verifier Content\n",
        encoding="utf-8",
    )
    (bundle_dir / "project-auditor-orchestrator").mkdir(parents=True)
    (bundle_dir / "project-auditor-orchestrator" / "SKILL.md").write_text(
        "---\nname: project-auditor-orchestrator\ndescription: orchestrator\n---\nBundle Orchestrator Content\n",
        encoding="utf-8",
    )

    # Target already has a user-customized project-auditor-orchestrator AND an unrelated custom skill
    (target_dir / "project-auditor-orchestrator").mkdir(parents=True)
    custom_orchestrator_text = "---\nname: project-auditor-orchestrator\ndescription: custom\n---\nUSER CUSTOMIZED CONTENT DO NOT OVERWRITE\n"
    (target_dir / "project-auditor-orchestrator" / "SKILL.md").write_text(custom_orchestrator_text, encoding="utf-8")

    (target_dir / "my-unrelated-skill").mkdir(parents=True)
    (target_dir / "my-unrelated-skill" / "SKILL.md").write_text("Unrelated skill\n", encoding="utf-8")

    res = install_global_skills_safely([bundle_dir], target_dir, backup_root=backup_dir)
    assert res["installed"] == ["independent-audit-verifier"]
    assert len(res["preserved_custom"]) == 1
    assert res["preserved_custom"][0]["skill_name"] == "project-auditor-orchestrator"
    assert "my-unrelated-skill" in res["preserved_other"]

    # Verify customized skill was NOT overwritten!
    assert (target_dir / "project-auditor-orchestrator" / "SKILL.md").read_text(encoding="utf-8") == custom_orchestrator_text
    # Verify new skill was installed
    assert "Bundle Verifier Content" in (target_dir / "independent-audit-verifier" / "SKILL.md").read_text(encoding="utf-8")
    # Verify backup of customized skill was created
    assert (backup_dir / "project-auditor-orchestrator" / "SKILL.md").read_text(encoding="utf-8") == custom_orchestrator_text


def test_37_ins_02_installer_pre_migration_online_backup_and_abort_on_failure(
    tmp_path: Path,
) -> None:
    # Verify that installer script uses SQLite Online Backup API + PRAGMA integrity_check and aborts on failure
    installer_path = Path(__file__).resolve().parents[1] / "Install-AntigravityAuditor.ps1"
    installer_text = installer_path.read_text(encoding="utf-8")
    assert "src_conn.backup(dst_conn)" in installer_text
    assert "PRAGMA integrity_check" in installer_text
    assert "Aborting installation before schema migration" in installer_text
    assert "install-global-skills" in installer_text
    assert "generate-verifier-sidecars" in installer_text

    # Also test that backup_database fails closed when source DB is invalid/corrupted before migration
    corrupt_db = tmp_path / "corrupt.db"
    corrupt_db.write_bytes(b"not a valid sqlite database header")
    with pytest.raises(Exception):
        backup_database(corrupt_db, backup_dir=tmp_path / "backups")


# =====================================================================
# THIRD REMEDIATION PASS — 29 MANDATORY REGRESSION TESTS (SECTION 12)
# =====================================================================


def test_38_crit01_followup_keeps_parent_run_verification_pending_until_disc_finalized(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT01-1")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT01-1",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id="RUN-CRIT01-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-crit01-v1",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Verified primary candidate.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe guard.",
                "remediation_safe": True,
                "acceptance_criteria": "Raise ValueError.",
            }
        ],
        verifier_discovered_findings=[
            {
                "finding_id": "F-CRIT01-DISC-1",
                "fingerprint": "fp-crit01-disc-1",
                "title": "Verifier discovered receipt formatting issue",
                "category": "V7",
                "severity": "MEDIUM",
                "confidence": "CONFIRMED",
                "file_path": "src/payment.py",
                "symbol": "format_receipt",
                "line_start": 11,
                "line_end": 12,
                "evidence": "order_id.strip()",
                "impact": "Receipt formatting",
                "recommendation": "Validate order_id",
            }
        ],
    )
    fin = finalize_verified_report(db_path, audit_run_id="RUN-CRIT01-1", verification_run_id=vrun_id)
    assert fin["status"] == "VERIFICATION_PENDING"
    assert fin["followup_verification_run_id"] == "VRUN-RUN-CRIT01-1-DISC"

    # Unqualified status query must reflect the pending follow-up run, NOT claim ready_for_review!
    st = get_verification_status(db_path, audit_run_id="RUN-CRIT01-1")
    assert st["audit_status"] == "VERIFICATION_PENDING"
    assert st["followup_verification_pending"] is True
    assert st["pending_followup_verification_run_id"] == "VRUN-RUN-CRIT01-1-DISC"
    assert st["verification_run_id"] == "VRUN-RUN-CRIT01-1-DISC"

    # Attempting to save decisions or authorize execution while follow-up is pending must be rejected!
    with pytest.raises(RuntimeError, match="VERIFICATION_PENDING"):
        save_decisions(
            db_path,
            project_key="pay",
            run_id="RUN-CRIT01-1",
            decisions=[{"finding_id": "F-PAY-1", "decision": "APPLY"}],
        )
    with pytest.raises(RuntimeError, match="VERIFICATION_PENDING"):
        authorize_execution(
            db_path,
            project_key="pay",
            run_id="RUN-CRIT01-1",
            confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
        )


def test_39_crit01_build_verification_prompt_includes_verifier_discovered_candidates_for_followup(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT01-PROMPT")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT01-PROMPT",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id="RUN-CRIT01-PROMPT",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-crit01-p1",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed primary.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test.",
            }
        ],
        verifier_discovered_findings=[
            {
                "finding_id": "F-DISC-PROMPT-99",
                "fingerprint": "fp-disc-prompt-99",
                "title": "Verifier discovered order_id check",
                "category": "V7",
                "severity": "HIGH",
                "confidence": "CONFIRMED",
                "file_path": "src/payment.py",
                "symbol": "format_receipt",
                "line_start": 11,
                "line_end": 12,
                "evidence": "order_id.strip()",
                "impact": "Order ID validation",
                "recommendation": "Check empty order_id",
            }
        ],
    )
    fin = finalize_verified_report(db_path, audit_run_id="RUN-CRIT01-PROMPT", verification_run_id=vrun_id)
    disc_vrun_id = fin["followup_verification_run_id"]

    prompt_text = build_verification_prompt(
        db_path,
        audit_run_id="RUN-CRIT01-PROMPT",
        verification_run_id=disc_vrun_id,
        app_home=tmp_path,
    )
    assert "F-DISC-PROMPT-99" in prompt_text
    assert "F-PAY-1" not in prompt_text

    ctx = get_verification_context(
        db_path,
        audit_run_id="RUN-CRIT01-PROMPT",
        verification_run_id=disc_vrun_id,
    )
    cand_ids = [c["candidate_finding_id"] for c in ctx["candidate_claims"]]
    assert cand_ids == ["F-DISC-PROMPT-99"]


def test_40_crit01_end_to_end_independent_followup_verification_reaches_ready_for_review_and_blocks_recursive_discovery(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT01-E2E")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT01-E2E",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id="RUN-CRIT01-E2E",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-crit01-e2e-1",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed primary.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test.",
            }
        ],
        verifier_discovered_findings=[
            {
                "finding_id": "F-DISC-E2E-1",
                "fingerprint": "fp-disc-e2e-1",
                "title": "Verifier discovered receipt issue",
                "category": "V7",
                "severity": "HIGH",
                "confidence": "CONFIRMED",
                "file_path": "src/payment.py",
                "symbol": "format_receipt",
                "line_start": 11,
                "line_end": 12,
                "evidence": "order_id.strip()",
                "impact": "Receipt formatting",
                "recommendation": "Validate order_id",
            }
        ],
    )
    fin1 = finalize_verified_report(db_path, audit_run_id="RUN-CRIT01-E2E", verification_run_id=vrun_id)
    disc_vrun = fin1["followup_verification_run_id"]
    assert fin1["status"] == "VERIFICATION_PENDING"

    # Follow-up verification run must reject recursive verifier_discovered_findings!
    with pytest.raises((ValueError, RuntimeError), match="recursive|verifier_discovered_findings"):
        submit_verification_results(
            db_path,
            audit_run_id="RUN-CRIT01-E2E",
            verification_run_id=disc_vrun,
            verifier_conversation_id="conv-crit01-e2e-2",
            verification_results=[
                {
                    "candidate_finding_id": "F-DISC-E2E-1",
                    "verdict": "CONFIRMED",
                    "verified_severity": "HIGH",
                    "verified_confidence": "CONFIRMED",
                    "technical_rationale": "Confirmed.",
                    "source_evidence": {
                        "file_path": "src/payment.py",
                        "line_start": 11,
                        "line_end": 12,
                        "symbol": "format_receipt",
                        "evidence_excerpt": "order_id.strip()",
                    },
                    "remediation_review": "Safe.",
                    "remediation_safe": True,
                    "acceptance_criteria": "Test.",
                }
            ],
            verifier_discovered_findings=[
                {
                    "finding_id": "F-DISC-RECURSIVE",
                    "fingerprint": "fp-disc-rec",
                    "title": "Recursive",
                    "category": "V1",
                    "severity": "LOW",
                    "confidence": "LIKELY",
                    "file_path": "src/payment.py",
                    "symbol": "format_receipt",
                    "line_start": 11,
                    "line_end": 12,
                    "evidence": "order_id.strip()",
                    "impact": "None",
                    "recommendation": "None",
                }
            ],
        )

    # Valid independent follow-up submission without recursive discoveries succeeds and reaches READY_FOR_REVIEW
    submit_verification_results(
        db_path,
        audit_run_id="RUN-CRIT01-E2E",
        verification_run_id=disc_vrun,
        verifier_conversation_id="conv-crit01-e2e-2",
        verification_results=[
            {
                "candidate_finding_id": "F-DISC-E2E-1",
                "verdict": "CONFIRMED",
                "verified_severity": "HIGH",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed by second independent verifier.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 11,
                    "line_end": 12,
                    "symbol": "format_receipt",
                    "evidence_excerpt": "order_id.strip()",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test.",
            }
        ],
    )
    fin2 = finalize_verified_report(db_path, audit_run_id="RUN-CRIT01-E2E", verification_run_id=disc_vrun)
    assert fin2["status"] == "READY_FOR_REVIEW"
    assert "F-DISC-E2E-1" in fin2["canonical_finding_ids"]

    st = get_verification_status(db_path, audit_run_id="RUN-CRIT01-E2E")
    assert st["audit_status"] == "READY_FOR_REVIEW"
    assert st["followup_verification_pending"] is False


def test_41_crit01_expired_followup_lease_and_failure_recover_cleanly_without_illegal_transition(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT01-LEASE")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT01-LEASE",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id="RUN-CRIT01-LEASE",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-crit01-lease-1",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test.",
            }
        ],
        verifier_discovered_findings=[
            {
                "finding_id": "F-DISC-LEASE-1",
                "fingerprint": "fp-disc-lease-1",
                "title": "Discovered issue",
                "category": "V7",
                "severity": "MEDIUM",
                "confidence": "CONFIRMED",
                "file_path": "src/payment.py",
                "symbol": "format_receipt",
                "line_start": 11,
                "line_end": 12,
                "evidence": "order_id.strip()",
                "impact": "Impact",
                "recommendation": "Rec",
            }
        ],
    )
    fin = finalize_verified_report(db_path, audit_run_id="RUN-CRIT01-LEASE", verification_run_id=vrun_id)
    assert fin["status"] == "VERIFICATION_PENDING"
    disc_job_id = "VJOB-RUN-CRIT01-LEASE-DISC"

    # Simulate expired CLAIMED lease with max_attempts exhausted on the follow-up job
    with connect(db_path) as conn:
        conn.execute(
            """UPDATE verification_dispatch_queue
               SET status='CLAIMED', attempt_count=3, max_attempts=3,
                   lease_owner='dead-worker', lease_expires_at='2000-01-01T00:00:00+00:00'
               WHERE job_id=?""",
            (disc_job_id,),
        )
        conn.commit()

    rec = recover_stale_verification_leases(db_path)
    assert disc_job_id in rec["failed_jobs"]
    assert rec["recovery_errors"] == []

    with connect(db_path) as conn:
        run_st = conn.execute("SELECT status FROM audit_runs WHERE run_id='RUN-CRIT01-LEASE'").fetchone()["status"]
    assert run_st == "VERIFICATION_FAILED"


def test_42_crit01_stale_lease_recovery_isolates_per_job_failure_with_savepoint(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-SAVEPOINT-GOOD")
    stats_good = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-SAVEPOINT-GOOD",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports" / "good",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id)
               VALUES('pay2', 'Payment 2', ?, '00000000-0000-4000-8000-000000000001')""",
            (str(tmp_path / "repo_pay2"),),
        )
        conn.execute(
            """INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash, agent_conversation_id)
               VALUES('RUN-SAVEPOINT-BAD', 'pay2', 'PRIMARY_AUDIT_RUNNING', 'abc', 'clean', 'conv-bad-1')"""
        )
        conn.commit()
    stats_bad = ingest_findings(
        db_path,
        project_key="pay2",
        run_id="RUN-SAVEPOINT-BAD",
        findings=[_sample_candidate_findings()[1]],
        report_dir=tmp_path / "reports" / "bad",
        repo_path=repo_dir,
    )

    with connect(db_path) as conn:
        # Force RUN-SAVEPOINT-BAD into COMPLETED (terminal state from which transition to VERIFICATION_UNCERTAIN will raise)
        conn.execute("UPDATE audit_runs SET status='COMPLETED' WHERE run_id='RUN-SAVEPOINT-BAD'")
        conn.execute(
            """UPDATE verification_dispatch_queue
               SET status='DISPATCHING', lease_owner='w1', lease_expires_at='2000-01-01T00:00:00+00:00'
               WHERE job_id IN (?, ?)""",
            (stats_bad["verification_job_id"], stats_good["verification_job_id"]),
        )
        conn.commit()

    rec = recover_stale_verification_leases(db_path)
    # Bad job recovery fails and is recorded in recovery_errors, while good job succeeds!
    assert len(rec["recovery_errors"]) == 1
    assert rec["recovery_errors"][0]["job_id"] == stats_bad["verification_job_id"]
    assert stats_good["verification_job_id"] in rec["uncertain_jobs"]


def test_43_crit01_deterministic_rowid_tie_breaker_selects_latest_verification_run_with_identical_timestamps(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-TIE-1")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-TIE-1",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id="RUN-TIE-1",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-tie-1",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test.",
            }
        ],
        verifier_discovered_findings=[
            {
                "finding_id": "F-DISC-TIE",
                "fingerprint": "fp-disc-tie",
                "title": "Tie break finding",
                "category": "V7",
                "severity": "LOW",
                "confidence": "CONFIRMED",
                "file_path": "src/payment.py",
                "symbol": "format_receipt",
                "line_start": 11,
                "line_end": 12,
                "evidence": "order_id.strip()",
                "impact": "Impact",
                "recommendation": "Rec",
            }
        ],
    )
    fin = finalize_verified_report(db_path, audit_run_id="RUN-TIE-1", verification_run_id=vrun_id)
    disc_vrun = fin["followup_verification_run_id"]

    # Force identical second-resolution created_at timestamps on both verification runs
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE audit_verification_runs SET created_at='2026-11-03 12:00:00' WHERE audit_run_id='RUN-TIE-1'"
        )
        conn.commit()

    st = get_verification_status(db_path, audit_run_id="RUN-TIE-1")
    assert st["verification_run_id"] == disc_vrun


def test_44_crit02_v2_to_v3_migration_preserves_all_five_columns_and_distinct_non_null_values(
    tmp_path: Path,
) -> None:
    db_v2 = tmp_path / "v2_preserve_all.db"
    v2_sql = """
    CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO schema_migrations(version, name) VALUES (1, '001_initial');
    INSERT INTO schema_migrations(version, name) VALUES (2, '002_v2');

    CREATE TABLE projects (
        project_key TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        repo_path TEXT NOT NULL UNIQUE,
        antigravity_project_id TEXT,
        repo_fingerprint TEXT,
        last_known_commit TEXT,
        health_status TEXT NOT NULL DEFAULT 'HEALTHY',
        stale_timeout_seconds INTEGER NOT NULL DEFAULT 3600,
        max_retries INTEGER NOT NULL DEFAULT 2,
        max_run_retries INTEGER NOT NULL DEFAULT 4,
        min_free_mb INTEGER NOT NULL DEFAULT 500,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id, last_known_commit, max_run_retries)
    VALUES ('legproj', 'Legacy Project', '/tmp/legproj', '00000000-0000-4000-8000-000000000001', 'deadbeefcafe1234', 5);

    CREATE TABLE audit_runs (
        run_id TEXT PRIMARY KEY,
        project_key TEXT NOT NULL REFERENCES projects(project_key),
        status TEXT NOT NULL DEFAULT 'DISPATCHED'
            CHECK (status IN ('DISPATCHED','ANALYZING','PENDING_APPROVAL','READY_FOR_REVIEW','COMPLETED','PARTIAL','FAILED','STALE')),
        trigger_source TEXT NOT NULL DEFAULT 'scheduled',
        base_commit TEXT,
        working_tree_hash TEXT,
        retry_count INTEGER NOT NULL DEFAULT 0,
        max_retries INTEGER NOT NULL DEFAULT 2,
        heartbeat_at TEXT,
        superseded_by TEXT,
        started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        finished_at TEXT,
        agent_conversation_id TEXT,
        report_path TEXT,
        summary_json TEXT,
        error TEXT
    );
    INSERT INTO audit_runs(run_id, project_key, status, trigger_source, base_commit, summary_json)
    VALUES ('RUN-LEG-V2', 'legproj', 'READY_FOR_REVIEW', 'manual-cli-trigger-v2', 'deadbeefcafe1234', '{"v2_total": 7, "notes": "preserve-me"}');

    CREATE TABLE findings (
        finding_id TEXT PRIMARY KEY,
        project_key TEXT NOT NULL REFERENCES projects(project_key),
        run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
        first_seen_run_id TEXT,
        last_seen_run_id TEXT,
        fingerprint TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL DEFAULT 'LIKELY',
        file_path TEXT,
        symbol TEXT,
        line_start INTEGER,
        line_end INTEGER,
        evidence TEXT NOT NULL,
        evidence_hash TEXT,
        file_blob_hash TEXT,
        impact TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        lifecycle TEXT NOT NULL DEFAULT 'OPEN'
            CHECK (lifecycle IN ('OPEN','DEFERRED','DISMISSED','RESOLVED','SKIPPED','STALE')),
        dismissed_reason TEXT,
        dismissed_evidence_hash TEXT,
        dismissed_file_blob_hash TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(project_key, fingerprint)
    );
    INSERT INTO findings(
        finding_id, project_key, run_id, first_seen_run_id, last_seen_run_id,
        fingerprint, title, category, severity, confidence,
        file_path, symbol, line_start, line_end, evidence, evidence_hash, file_blob_hash,
        impact, recommendation, lifecycle,
        dismissed_reason, dismissed_evidence_hash, dismissed_file_blob_hash
    ) VALUES (
        'F-LEG-DISMISSED', 'legproj', 'RUN-LEG-V2', 'RUN-LEG-V2', 'RUN-LEG-V2',
        'fp-leg-dismissed-1', 'Dismissed Legacy Finding', 'V2', 'MEDIUM', 'LIKELY',
        'src/legacy.py', 'legacy_fn', 10, 20, 'x = 1', 'evhash-111', 'blobhash-222',
        'Minor impact', 'No action', 'DISMISSED',
        'False positive confirmed by architecture review', 'dismissed-ev-sha256-aaa', 'dismissed-blob-sha256-bbb'
    );
    """
    raw = sqlite3.connect(str(db_v2))
    raw.executescript(v2_sql)
    raw.close()

    initialize(db_v2)

    with connect(db_v2) as conn:
        proj = conn.execute("SELECT * FROM projects WHERE project_key='legproj'").fetchone()
        run = conn.execute("SELECT * FROM audit_runs WHERE run_id='RUN-LEG-V2'").fetchone()
        finding = conn.execute("SELECT * FROM findings WHERE finding_id='F-LEG-DISMISSED'").fetchone()

    assert proj["last_known_commit"] == "deadbeefcafe1234"
    assert int(proj["max_run_retries"]) == 5
    assert run["trigger_source"] == "manual-cli-trigger-v2"
    assert run["summary_json"] == '{"v2_total": 7, "notes": "preserve-me"}'
    assert finding["dismissed_reason"] == "False positive confirmed by architecture review"
    assert finding["dismissed_evidence_hash"] == "dismissed-ev-sha256-aaa"
    assert finding["dismissed_file_blob_hash"] == "dismissed-blob-sha256-bbb"
    assert finding["lifecycle"] == "DISMISSED"
    assert finding["verification_status"] == "LEGACY_UNVERIFIED"
    assert int(finding["execution_eligible"]) == 0


def test_45_crit02_table_rebuild_aborts_cleanly_on_unmapped_extra_column(
    tmp_path: Path,
) -> None:
    db_extra = tmp_path / "v2_extra_col.db"
    raw = sqlite3.connect(str(db_extra))
    raw.executescript(
        """
        CREATE TABLE projects (
            project_key TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            repo_path TEXT NOT NULL UNIQUE
        );
        CREATE TABLE audit_runs (
            run_id TEXT PRIMARY KEY,
            project_key TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'DISPATCHED'
                CHECK (status IN ('DISPATCHED','ANALYZING','READY_FOR_REVIEW')),
            unexpected_custom_run_col TEXT DEFAULT 'must-not-drop'
        );
        INSERT INTO projects VALUES ('p1', 'P1', '/tmp/p1');
        INSERT INTO audit_runs(run_id, project_key, status, unexpected_custom_run_col)
        VALUES ('R1', 'p1', 'READY_FOR_REVIEW', 'precious-custom-data');
        """
    )
    raw.close()

    with pytest.raises(RuntimeError, match="Refusing to rebuild table.*unexpected_custom_run_col"):
        initialize(db_extra)

    # Confirm the column and data were NOT dropped
    chk = sqlite3.connect(str(db_extra))
    val = chk.execute("SELECT unexpected_custom_run_col FROM audit_runs WHERE run_id='R1'").fetchone()[0]
    chk.close()
    assert val == "precious-custom-data"


def test_46_crit02_foreign_key_check_runs_and_catches_violation_before_commit(
    tmp_path: Path,
) -> None:
    db_fk = tmp_path / "v2_fk_broken.db"
    raw = sqlite3.connect(str(db_fk))
    raw.execute("PRAGMA foreign_keys=OFF")
    raw.executescript(
        """
        CREATE TABLE projects (
            project_key TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            repo_path TEXT NOT NULL UNIQUE
        );
        CREATE TABLE audit_runs (
            run_id TEXT PRIMARY KEY,
            project_key TEXT NOT NULL REFERENCES projects(project_key),
            status TEXT NOT NULL DEFAULT 'DISPATCHED'
                CHECK (status IN ('DISPATCHED','READY_FOR_REVIEW'))
        );
        -- Orphan audit_run referencing non-existent project_key 'ghost-project'
        INSERT INTO audit_runs(run_id, project_key, status) VALUES ('R-ORPHAN', 'ghost-project', 'READY_FOR_REVIEW');
        """
    )
    raw.close()

    with pytest.raises(RuntimeError, match="foreign_key_check violations"):
        initialize(db_fk)


def test_47_new04_sql_statement_splitter_handles_strings_comments_and_triggers(
    tmp_path: Path,
) -> None:
    from db import _split_sql_statements

    complex_sql = """
    -- Leading comment with semicolon; must not split incorrectly
    CREATE TABLE items (
        id INTEGER PRIMARY KEY,
        label TEXT NOT NULL DEFAULT 'default;label;with;semicolons',
        /* block comment with ; inside */
        notes TEXT DEFAULT "double;quoted;semi"
    );
    CREATE TABLE item_log (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id INTEGER NOT NULL,
        msg TEXT NOT NULL
    );
    CREATE TRIGGER tr_items_insert AFTER INSERT ON items
    BEGIN
        INSERT INTO item_log(item_id, msg) VALUES (NEW.id, 'created;item');
        UPDATE item_log SET msg = msg || ';confirmed' WHERE item_id = NEW.id;
    END;
    INSERT INTO items(id, label) VALUES (1, 'hello;world');
    """
    stmts = _split_sql_statements(complex_sql)
    assert len(stmts) == 4

    test_db = tmp_path / "splitter_test.db"
    conn = sqlite3.connect(str(test_db))
    for st in stmts:
        conn.execute(st)
    conn.commit()
    row = conn.execute("SELECT item_id, msg FROM item_log").fetchone()
    conn.close()
    assert row == (1, "created;item;confirmed")


def test_48_crit02_failed_migration_leaves_original_v2_db_intact_and_retryable(
    tmp_path: Path,
) -> None:
    db_v2 = tmp_path / "v2_retryable.db"
    raw = sqlite3.connect(str(db_v2))
    raw.executescript(
        """
        CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT DEFAULT CURRENT_TIMESTAMP);
        INSERT INTO schema_migrations(version, name) VALUES (1, '001'), (2, '002');
        CREATE TABLE projects (project_key TEXT PRIMARY KEY, display_name TEXT NOT NULL, repo_path TEXT NOT NULL UNIQUE, antigravity_project_id TEXT);
        INSERT INTO projects VALUES ('p1', 'Proj 1', '/tmp/p1', '00000000-0000-4000-8000-000000000001');
        CREATE TABLE audit_runs (
            run_id TEXT PRIMARY KEY,
            project_key TEXT NOT NULL REFERENCES projects(project_key),
            status TEXT NOT NULL DEFAULT 'READY_FOR_REVIEW' CHECK (status IN ('DISPATCHED','READY_FOR_REVIEW')),
            trigger_source TEXT NOT NULL DEFAULT 'scheduled',
            summary_json TEXT
        );
        INSERT INTO audit_runs VALUES ('R1', 'p1', 'READY_FOR_REVIEW', 'ci-webhook', '{"ok":true}');
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY,
            project_key TEXT NOT NULL REFERENCES projects(project_key),
            run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
            fingerprint TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'CONFIRMED',
            evidence TEXT NOT NULL,
            impact TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            lifecycle TEXT NOT NULL DEFAULT 'DISMISSED' CHECK (lifecycle IN ('OPEN','DISMISSED')),
            dismissed_reason TEXT,
            dismissed_evidence_hash TEXT,
            dismissed_file_blob_hash TEXT
        );
        INSERT INTO findings VALUES ('F1', 'p1', 'R1', 'fp1', 'T1', 'V1', 'LOW', 'CONFIRMED', 'ev', 'imp', 'rec', 'DISMISSED', 'reason-1', 'eh-1', 'bh-1');
        """
    )
    raw.close()

    with pytest.raises(RuntimeError, match="Fault after table rebuild"):
        initialize(
            db_v2,
            _migration_fault_hook=lambda _c, stage: (_ for _ in ()).throw(RuntimeError("Fault after table rebuild"))
            if stage == "before_commit"
            else None,
        )

    # Verify original v2 DB is intact
    chk = sqlite3.connect(str(db_v2))
    r_row = chk.execute("SELECT trigger_source, summary_json FROM audit_runs WHERE run_id='R1'").fetchone()
    f_row = chk.execute("SELECT dismissed_reason, dismissed_evidence_hash, dismissed_file_blob_hash FROM findings WHERE finding_id='F1'").fetchone()
    chk.close()
    assert r_row == ("ci-webhook", '{"ok":true}')
    assert f_row == ("reason-1", "eh-1", "bh-1")

    # Retry succeeds and preserves all data
    initialize(db_v2)
    with connect(db_v2) as conn:
        f_after = conn.execute("SELECT dismissed_reason, verification_status FROM findings WHERE finding_id='F1'").fetchone()
    assert f_after["dismissed_reason"] == "reason-1"
    assert f_after["verification_status"] == "LEGACY_UNVERIFIED"


def test_49_crit03_missing_or_empty_excerpt_with_valid_sha256_is_rejected(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT03-SHA")
    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT03-SHA",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-CRIT03-SHA'").fetchone()
        cand_row = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-CRIT03-SHA'").fetchone()

    snapshot_info = {
        "snapshot_id": snap_row["snapshot_id"],
        "base_commit_sha": snap_row["base_commit_sha"],
        "working_tree_hash": snap_row["working_tree_hash"],
        "file_hashes": json.loads(snap_row["file_hashes_json"]),
    }
    file_lines = (repo_dir / "src" / "payment.py").read_text(encoding="utf-8").splitlines()
    slice_text = "\n".join(file_lines[3:9])
    valid_slice_sha = hashlib.sha256(slice_text.strip().encode("utf-8")).hexdigest()

    for payload in (
        {"file_path": "src/payment.py", "line_start": 4, "line_end": 9, "symbol": "charge_card", "excerpt_sha256": valid_slice_sha},
        {"file_path": "src/payment.py", "line_start": 4, "line_end": 9, "symbol": "charge_card", "evidence_excerpt": "", "evidence_sha256": valid_slice_sha},
    ):
        res = validate_single_finding_evidence(
            repo_path=repo_dir,
            snapshot_info=snapshot_info,
            candidate=dict(cand_row),
            source_evidence=payload,
        )
        assert res["passed"] is False
        assert res["status"] == "INVALID"
        assert res["code"] == "MISSING_EVIDENCE_EXCERPT"


def test_50_crit03_caller_supplied_allow_candidate_excerpt_fallback_is_ignored(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT03-FALLBACK")
    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT03-FALLBACK",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-CRIT03-FALLBACK'").fetchone()
        cand_row = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-CRIT03-FALLBACK'").fetchone()

    snapshot_info = {
        "snapshot_id": snap_row["snapshot_id"],
        "base_commit_sha": snap_row["base_commit_sha"],
        "working_tree_hash": snap_row["working_tree_hash"],
        "file_hashes": json.loads(snap_row["file_hashes_json"]),
    }
    res = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snapshot_info,
        candidate=dict(cand_row),
        source_evidence={
            "file_path": "src/payment.py",
            "line_start": 4,
            "line_end": 9,
            "symbol": "charge_card",
            "_allow_candidate_excerpt_fallback": True,
        },
    )
    assert res["passed"] is False
    assert res["status"] == "INVALID"
    assert res["code"] == "MISSING_EVIDENCE_EXCERPT"


def test_51_crit03_js_url_with_double_slash_before_symbol_on_same_line_passes(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT03-JSURL")
    js_file = repo_dir / "src" / "client.js"
    js_file.write_text(
        'const url = "https://api.example.com/v1/pay"; function sendPayment(amount) { return fetch(url); }\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "add client.js"], check=True, capture_output=True)

    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT03-JSURL",
        findings=[
            {
                "finding_id": "F-JS-URL",
                "fingerprint": "fp-js-url",
                "title": "JS URL before symbol",
                "category": "V1",
                "severity": "MEDIUM",
                "confidence": "CONFIRMED",
                "file_path": "src/client.js",
                "symbol": "sendPayment",
                "line_start": 1,
                "line_end": 1,
                "evidence": "function sendPayment(amount)",
                "impact": "Impact",
                "recommendation": "Rec",
            }
        ],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-CRIT03-JSURL'").fetchone()
        cand_row = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-CRIT03-JSURL'").fetchone()

    res = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info={
            "snapshot_id": snap_row["snapshot_id"],
            "base_commit_sha": snap_row["base_commit_sha"],
            "working_tree_hash": snap_row["working_tree_hash"],
            "file_hashes": json.loads(snap_row["file_hashes_json"]),
        },
        candidate=dict(cand_row),
        source_evidence={
            "file_path": "src/client.js",
            "line_start": 1,
            "line_end": 1,
            "symbol": "sendPayment",
            "evidence_excerpt": "function sendPayment(amount)",
        },
    )
    assert res["passed"] is True
    assert res["status"] == "PASSED"


def test_52_crit03_symbol_only_in_multiline_comment_or_string_literal_is_rejected(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT03-TS")
    ts_file = repo_dir / "src" / "service.ts"
    ts_file.write_text(
        "/*\n"
        " * multiline comment mentioning ghostSymbolInBlockComment()\n"
        " */\n"
        'export function realHandler(): string {\n'
        '    const msg = "string literal mentioning ghostSymbolInString()";\n'
        "    return msg;\n"
        "}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "add service.ts"], check=True, capture_output=True)

    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT03-TS",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-CRIT03-TS'").fetchone()
        cand_row = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-CRIT03-TS'").fetchone()

    snap_info = {
        "snapshot_id": snap_row["snapshot_id"],
        "base_commit_sha": snap_row["base_commit_sha"],
        "working_tree_hash": snap_row["working_tree_hash"],
        "file_hashes": json.loads(snap_row["file_hashes_json"]),
    }

    for fake_sym in ("ghostSymbolInBlockComment", "ghostSymbolInString"):
        res = validate_single_finding_evidence(
            repo_path=repo_dir,
            snapshot_info=snap_info,
            candidate=dict(cand_row),
            source_evidence={
                "file_path": "src/service.ts",
                "line_start": 1,
                "line_end": 7,
                "symbol": fake_sym,
                "evidence_excerpt": "export function realHandler(): string {",
            },
        )
        assert res["passed"] is False
        assert res["status"] in ("INVALID", "FABRICATED_REFERENCE")
        assert res["code"] == "SYMBOL_NOT_FOUND_IN_FILE"


def test_53_crit03_python_syntax_error_returns_unverifiable_without_regex_fallback(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT03-PYSYN")
    broken_py = repo_dir / "src" / "broken.py"
    broken_py.write_text("def broken_symbol(a, b):\n    if a == :\n        return b\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "add broken.py"], check=True, capture_output=True)

    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT03-PYSYN",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-CRIT03-PYSYN'").fetchone()
        cand_row = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-CRIT03-PYSYN'").fetchone()

    res = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info={
            "snapshot_id": snap_row["snapshot_id"],
            "base_commit_sha": snap_row["base_commit_sha"],
            "working_tree_hash": snap_row["working_tree_hash"],
            "file_hashes": json.loads(snap_row["file_hashes_json"]),
        },
        candidate=dict(cand_row),
        source_evidence={
            "file_path": "src/broken.py",
            "line_start": 1,
            "line_end": 3,
            "symbol": "broken_symbol",
            "evidence_excerpt": "def broken_symbol(a, b):",
        },
    )
    assert res["passed"] is False
    assert res["status"] == "UNVERIFIABLE"
    assert res["code"] == "UNVERIFIABLE_PYTHON_SYNTAX"


def test_54_crit03_unsupported_language_extension_returns_unverifiable(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT03-UNSUP")
    (repo_dir / "src" / "query.sql").write_text("SELECT * FROM accounts WHERE id = 1;\n", encoding="utf-8")
    (repo_dir / "src" / "index.php").write_text("<?php function runQuery() { return 1; } ?>\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "add sql and php"], check=True, capture_output=True)

    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT03-UNSUP",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-CRIT03-UNSUP'").fetchone()
        cand_row = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-CRIT03-UNSUP'").fetchone()

    snap_info = {
        "snapshot_id": snap_row["snapshot_id"],
        "base_commit_sha": snap_row["base_commit_sha"],
        "working_tree_hash": snap_row["working_tree_hash"],
        "file_hashes": json.loads(snap_row["file_hashes_json"]),
    }

    for rel_path, excerpt, sym in (
        ("src/query.sql", "SELECT * FROM accounts", "accounts"),
        ("src/index.php", "function runQuery()", "runQuery"),
    ):
        res = validate_single_finding_evidence(
            repo_path=repo_dir,
            snapshot_info=snap_info,
            candidate=dict(cand_row),
            source_evidence={
                "file_path": rel_path,
                "line_start": 1,
                "line_end": 1,
                "symbol": sym,
                "evidence_excerpt": excerpt,
            },
        )
        assert res["passed"] is False
        assert res["status"] == "UNVERIFIABLE"
        assert res["code"] == "UNVERIFIABLE_SYMBOL_UNSUPPORTED_LANGUAGE"


def test_55_crit04_partial_audit_run_can_authorize_and_execute_remaining_finding(
    tmp_path: Path,
) -> None:
    from executor import finalize_isolated_execution, start_isolated_execution, update_finding_execution_step

    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT04-PARTIAL")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT04-PARTIAL",
        findings=_sample_candidate_findings(),
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id="RUN-CRIT04-PARTIAL",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-crit04-partial-1",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed F-PAY-1.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test.",
            },
            {
                "candidate_finding_id": "F-PAY-2",
                "verdict": "CONFIRMED",
                "verified_severity": "LOW",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed F-PAY-2.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 11,
                    "line_end": 12,
                    "symbol": "format_receipt",
                    "evidence_excerpt": "order_id.strip()",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test.",
            },
        ],
    )
    finalize_verified_report(db_path, audit_run_id="RUN-CRIT04-PARTIAL", verification_run_id=vrun_id)
    save_decisions(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT04-PARTIAL",
        decisions=[
            {"finding_id": "F-PAY-1", "decision": "APPLY"},
            {"finding_id": "F-PAY-2", "decision": "APPLY"},
        ],
    )
    auth1 = authorize_execution(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT04-PARTIAL",
        confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
    )
    s1 = start_isolated_execution(
        db_path,
        project_key="pay",
        approval_token=auth1["approval_token"],
        worktrees_root=tmp_path / "worktrees",
        min_free_mb=1,
    )
    wt1 = Path(s1["worktree_path"])
    update_finding_execution_step(
        db_path,
        project_key="pay",
        exec_id=s1["exec_id"],
        finding_id="F-PAY-1",
        action="begin",
        checkpoints_root=tmp_path / "checkpoints",
    )
    (wt1 / "src" / "payment.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\n\n"
        "def charge_card(user_id: str, amount: float) -> dict:\n"
        "    if amount <= 0:\n        raise ValueError('invalid')\n"
        "    balance_delta = -amount\n"
        "    logger.info('Charging %s amount %s', user_id, amount)\n"
        "    return {'user_id': user_id, 'delta': balance_delta}\n\n"
        "def format_receipt(order_id: str) -> str:\n"
        "    return f'Receipt: {order_id.strip()}'\n",
        encoding="utf-8",
    )
    update_finding_execution_step(
        db_path,
        project_key="pay",
        exec_id=s1["exec_id"],
        finding_id="F-PAY-1",
        action="verify",
        happy_test_passed=True,
        adversarial_test_passed=True,
        red_team_passed=True,
        checkpoints_root=tmp_path / "checkpoints",
    )
    # Roll back F-PAY-2 so the run finishes as PARTIAL
    update_finding_execution_step(
        db_path,
        project_key="pay",
        exec_id=s1["exec_id"],
        finding_id="F-PAY-2",
        action="rollback",
        checkpoints_root=tmp_path / "checkpoints",
    )
    fin_exec1 = finalize_isolated_execution(
        db_path,
        project_key="pay",
        exec_id=s1["exec_id"],
        integration_test_passed=True,
    )
    assert fin_exec1["status"] == "PARTIAL"

    # Now re-authorize and execute the remaining OPEN finding (F-PAY-2) from the PARTIAL audit run!
    auth2 = authorize_execution(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT04-PARTIAL",
        confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
    )
    assert auth2["approved_finding_ids"] == ["F-PAY-2"]

    s2 = start_isolated_execution(
        db_path,
        project_key="pay",
        approval_token=auth2["approval_token"],
        worktrees_root=tmp_path / "worktrees",
        min_free_mb=1,
    )
    wt2 = Path(s2["worktree_path"])
    update_finding_execution_step(
        db_path,
        project_key="pay",
        exec_id=s2["exec_id"],
        finding_id="F-PAY-2",
        action="begin",
        checkpoints_root=tmp_path / "checkpoints",
    )
    (wt2 / "src" / "payment.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\n\n"
        "def charge_card(user_id: str, amount: float) -> dict:\n"
        "    balance_delta = -amount\n"
        "    logger.info('Charging %s amount %s', user_id, amount)\n"
        "    return {'user_id': user_id, 'delta': balance_delta}\n\n"
        "def format_receipt(order_id: str) -> str:\n"
        "    cleaned = order_id.strip()\n"
        "    return f'Receipt: {cleaned}'\n",
        encoding="utf-8",
    )
    update_finding_execution_step(
        db_path,
        project_key="pay",
        exec_id=s2["exec_id"],
        finding_id="F-PAY-2",
        action="verify",
        happy_test_passed=True,
        adversarial_test_passed=True,
        red_team_passed=True,
        checkpoints_root=tmp_path / "checkpoints",
    )
    fin_exec2 = finalize_isolated_execution(
        db_path,
        project_key="pay",
        exec_id=s2["exec_id"],
        integration_test_passed=True,
    )
    assert fin_exec2["status"] == "COMPLETED"


def test_56_crit04_post_worktree_db_failure_cleans_up_worktree_and_leaves_token_unconsumed(
    tmp_path: Path,
) -> None:
    from executor import start_isolated_execution

    db_path, _, _, token = _prepare_verified_run_with_token(tmp_path, run_id="RUN-CRIT04-COMP")
    wt_root = tmp_path / "worktrees"
    created_paths: list[Path] = []

    def fail_after_worktree_add(wt_path: Path) -> None:
        assert wt_path.is_dir()
        created_paths.append(wt_path)
        raise sqlite3.OperationalError("simulated database failure after git worktree add")

    with pytest.raises(sqlite3.OperationalError, match="simulated database failure"):
        start_isolated_execution(
            db_path,
            project_key="pay",
            approval_token=token,
            worktrees_root=wt_root,
            min_free_mb=1,
            _post_worktree_fault_hook=fail_after_worktree_add,
        )

    assert len(created_paths) == 1
    # Worktree directory must have been cleaned up and compensated!
    assert not created_paths[0].exists()

    with connect(db_path) as conn:
        app_st = conn.execute("SELECT status FROM execution_approvals WHERE approval_token=?", (token,)).fetchone()["status"]
        exec_cnt = conn.execute("SELECT COUNT(*) FROM execution_runs WHERE run_id='RUN-CRIT04-COMP'").fetchone()[0]
        op_row = conn.execute("SELECT status FROM execution_worktree_ops WHERE run_id='RUN-CRIT04-COMP'").fetchone()

    assert app_st == "AUTHORIZED"
    assert exec_cnt == 0
    assert op_row is not None
    assert op_row["status"] == "COMPENSATED"

    # Retry with the same unconsumed token now succeeds cleanly!
    started = start_isolated_execution(
        db_path,
        project_key="pay",
        approval_token=token,
        worktrees_root=wt_root,
        min_free_mb=1,
    )
    assert Path(started["worktree_path"]).is_dir()


def test_57_crit04_snapshot_head_and_finding_state_revalidated_at_start_step_and_finalize(
    tmp_path: Path,
) -> None:
    from executor import finalize_isolated_execution, start_isolated_execution, update_finding_execution_step

    db_path, repo_dir, _, token = _prepare_verified_run_with_token(tmp_path, run_id="RUN-CRIT04-REVAL")
    started = start_isolated_execution(
        db_path,
        project_key="pay",
        approval_token=token,
        worktrees_root=tmp_path / "worktrees",
        min_free_mb=1,
    )
    exec_id = started["exec_id"]
    wt_path = Path(started["worktree_path"])

    update_finding_execution_step(
        db_path,
        project_key="pay",
        exec_id=exec_id,
        finding_id="F-PAY-1",
        action="begin",
        checkpoints_root=tmp_path / "checkpoints",
    )
    (wt_path / "src" / "payment.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\n\n"
        "def charge_card(user_id: str, amount: float) -> dict:\n"
        "    if amount <= 0:\n        raise ValueError('bad')\n"
        "    balance_delta = -amount\n"
        "    logger.info('Charging %s amount %s', user_id, amount)\n"
        "    return {'user_id': user_id, 'delta': balance_delta}\n\n"
        "def format_receipt(order_id: str) -> str:\n"
        "    return f'Receipt: {order_id.strip()}'\n",
        encoding="utf-8",
    )
    update_finding_execution_step(
        db_path,
        project_key="pay",
        exec_id=exec_id,
        finding_id="F-PAY-1",
        action="verify",
        happy_test_passed=True,
        adversarial_test_passed=True,
        red_team_passed=True,
        checkpoints_root=tmp_path / "checkpoints",
    )

    # Modify main repo file BEFORE finalize_isolated_execution -> must block finalization!
    (repo_dir / "src" / "payment.py").write_text("# modified before finalize\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="stale repository snapshot"):
        finalize_isolated_execution(
            db_path,
            project_key="pay",
            exec_id=exec_id,
            integration_test_passed=True,
        )


def test_58_crit04_post_approval_tampering_with_remediation_safe_verification_or_conversation_blocked(
    tmp_path: Path,
) -> None:
    from executor import start_isolated_execution, update_finding_execution_step

    db_path, _, _, token = _prepare_verified_run_with_token(tmp_path, run_id="RUN-CRIT04-TAMPER")

    # 1. Tamper with remediation_safe=0 after token issuance -> start_isolated_execution must reject!
    with connect(db_path) as conn:
        conn.execute("UPDATE findings SET remediation_safe=0 WHERE finding_id='F-PAY-1'")
        conn.commit()
    with pytest.raises(RuntimeError, match="remediation_safe=0"):
        start_isolated_execution(
            db_path,
            project_key="pay",
            approval_token=token,
            worktrees_root=tmp_path / "worktrees",
            min_free_mb=1,
        )

    # Restore remediation_safe=1, start execution, then tamper with verifier_conversation_id to match primary!
    with connect(db_path) as conn:
        conn.execute("UPDATE findings SET remediation_safe=1 WHERE finding_id='F-PAY-1'")
        conn.commit()
    started = start_isolated_execution(
        db_path,
        project_key="pay",
        approval_token=token,
        worktrees_root=tmp_path / "worktrees",
        min_free_mb=1,
    )
    with connect(db_path) as conn:
        conn.execute(
            "UPDATE findings SET verifier_conversation_id='conv-primary-auditor-001' WHERE finding_id='F-PAY-1'"
        )
        conn.commit()

    with pytest.raises(RuntimeError, match="Independence violation"):
        update_finding_execution_step(
            db_path,
            project_key="pay",
            exec_id=started["exec_id"],
            finding_id="F-PAY-1",
            action="begin",
            checkpoints_root=tmp_path / "checkpoints",
        )


def test_59_crit04_stale_snapshot_before_execution_blocks_without_consuming_token(
    tmp_path: Path,
) -> None:
    from executor import execute_approved_findings

    db_path, repo_dir, _, token = _prepare_verified_run_with_token(tmp_path, run_id="RUN-CRIT04-STALE-EXEC")
    (repo_dir / "src" / "payment.py").write_text("# dirty before execute_approved_findings\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="stale repository snapshot"):
        execute_approved_findings(
            db_path,
            project_key="pay",
            approval_token=token,
            worktrees_root=tmp_path / "worktrees",
            checkpoints_root=tmp_path / "checkpoints",
            min_free_mb=1,
        )

    with connect(db_path) as conn:
        app_st = conn.execute("SELECT status FROM execution_approvals WHERE approval_token=?", (token,)).fetchone()["status"]
    assert app_st == "AUTHORIZED"


def test_60_new01_manual_requeue_or_attach_rejected_during_active_worker_lease(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-NEW01-ACTIVE")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-NEW01-ACTIVE",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    future_iso = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    with connect(db_path) as conn:
        conn.execute(
            """UPDATE verification_dispatch_queue
               SET status='CLAIMED', lease_owner='worker-live', lease_expires_at=?
               WHERE job_id=?""",
            (future_iso, stats["verification_job_id"]),
        )
        conn.commit()

    for act in ("requeue", "attach-conversation"):
        with pytest.raises(RuntimeError, match="holds an active non-expired"):
            recover_verification_job(
                db_path,
                project_key="pay",
                audit_run_id="RUN-NEW01-ACTIVE",
                action=act,
                verifier_conversation_id="conv-manual-attach-1",
            )


def test_61_new01_manual_requeue_after_failure_preserves_prior_attempts_and_conversation_audit_trail(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-NEW01-HIST")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-NEW01-HIST",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    old_vrun_id = stats["verification_run_id"]
    old_job_id = stats["verification_job_id"]

    with connect(db_path) as conn:
        conn.execute(
            """UPDATE verification_dispatch_queue
               SET status='DISPATCH_UNCERTAIN', attempt_count=2, verifier_conversation_id='conv-old-attempt-2',
                   lease_owner=NULL, lease_expires_at=NULL
               WHERE job_id=?""",
            (old_job_id,),
        )
        conn.execute(
            """UPDATE audit_verification_runs
               SET status='UNCERTAIN', dispatch_attempt=2, verifier_conversation_id='conv-old-attempt-2'
               WHERE verification_run_id=?""",
            (old_vrun_id,),
        )
        conn.execute(
            "UPDATE audit_runs SET status='VERIFICATION_UNCERTAIN' WHERE run_id='RUN-NEW01-HIST'"
        )
        conn.commit()

    res = recover_verification_job(
        db_path,
        project_key="pay",
        audit_run_id="RUN-NEW01-HIST",
        action="requeue",
    )
    assert res["superseded_verification_run_id"] == old_vrun_id
    assert res["preserved_attempt_count"] == 2
    assert res["preserved_verifier_conversation_id"] == "conv-old-attempt-2"
    new_vrun_id = res["verification_run_id"]
    new_job_id = res["job_id"]
    assert new_vrun_id != old_vrun_id

    with connect(db_path) as conn:
        old_vrun = conn.execute(
            "SELECT status, verifier_conversation_id, dispatch_attempt FROM audit_verification_runs WHERE verification_run_id=?",
            (old_vrun_id,),
        ).fetchone()
        new_vrun = conn.execute(
            "SELECT status, dispatch_attempt FROM audit_verification_runs WHERE verification_run_id=?",
            (new_vrun_id,),
        ).fetchone()
        new_job = conn.execute(
            "SELECT status, attempt_count, max_attempts FROM verification_dispatch_queue WHERE job_id=?",
            (new_job_id,),
        ).fetchone()

    assert old_vrun["status"] == "ARCHIVED"
    assert old_vrun["verifier_conversation_id"] == "conv-old-attempt-2"
    assert int(old_vrun["dispatch_attempt"]) == 2
    assert new_vrun["status"] == "PENDING"
    assert int(new_vrun["dispatch_attempt"]) == 2
    assert new_job["status"] == "QUEUED"
    assert int(new_job["attempt_count"]) == 2
    assert int(new_job["max_attempts"]) >= 3


def test_62_new03_caller_supplied_verifier_model_id_never_produces_cross_model_verified(
    tmp_path: Path,
) -> None:
    from review import generate_review_report
    from verification import derive_verification_trust

    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-NEW03-MODEL")
    stats = ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-NEW03-MODEL",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    vrun_id = stats["verification_run_id"]
    submit_verification_results(
        db_path,
        audit_run_id="RUN-NEW03-MODEL",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-new03-verifier",
        verifier_metadata={"verifier_model_id": "claude-3-7-sonnet-claimed-by-caller"},
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test.",
            }
        ],
    )
    finalize_verified_report(db_path, audit_run_id="RUN-NEW03-MODEL", verification_run_id=vrun_id)

    with connect(db_path) as conn:
        run_row = conn.execute("SELECT * FROM audit_runs WHERE run_id='RUN-NEW03-MODEL'").fetchone()
        vrun_row = conn.execute("SELECT * FROM audit_verification_runs WHERE verification_run_id=?", (vrun_id,)).fetchone()

    assert vrun_row["verifier_model_source"] == "CALLER_CLAIMED_UNVERIFIED"
    trust = derive_verification_trust(run_row, vrun_row)
    assert trust["conversation_independence_verified"] is True
    assert trust["model_independence_verified"] is False
    assert trust["model_independence_status"] == "MODEL_INDEPENDENCE_UNVERIFIED"
    assert "MODEL_INDEPENDENCE_UNVERIFIED" in trust["verification_trust_mode"]
    assert "CROSS_MODEL_VERIFIED" not in trust["verification_trust_mode"]

    report_md = generate_review_report(db_path, project_key="pay", run_id="RUN-NEW03-MODEL")
    assert "CROSS_MODEL_VERIFIED" not in report_md
    assert "MODEL_INDEPENDENCE_UNVERIFIED" in report_md


def test_63_crit05_large_file_over_10mb_stream_hashed_and_post_snapshot_edit_detected(
    tmp_path: Path,
) -> None:
    from verification import compute_clean_working_tree_hash, verify_snapshot_consistency

    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT05-LARGE")
    large_file = repo_dir / "src" / "large_module.py"
    # Create a > 10.5 MB source file
    payload = ("# padding line 0123456789abcdef\n" * 350_000) + "def large_target() -> int:\n    return 1\n"
    assert len(payload.encode("utf-8")) > 10 * 1024 * 1024
    large_file.write_text(payload, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "add >10MB file"], check=True, capture_output=True)
    new_head = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    with connect(db_path) as conn:
        conn.execute("UPDATE audit_runs SET base_commit=? WHERE run_id='RUN-CRIT05-LARGE'", (new_head,))
        conn.commit()

    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT05-LARGE",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-CRIT05-LARGE'").fetchone()
        hashes = json.loads(snap_row["file_hashes_json"])
        assert "src/large_module.py" in hashes
        assert int(snap_row["snapshot_complete"]) == 1
        assert verify_snapshot_consistency(conn, repo_path=repo_dir, run_id="RUN-CRIT05-LARGE")["consistent"] is True

    wt_hash_before = compute_clean_working_tree_hash(repo_dir)
    # Modify the very end of the >10MB file
    large_file.write_text(payload + "# tail edit\n", encoding="utf-8")
    wt_hash_after = compute_clean_working_tree_hash(repo_dir)
    assert wt_hash_after != wt_hash_before

    with connect(db_path) as conn:
        consistency = verify_snapshot_consistency(conn, repo_path=repo_dir, run_id="RUN-CRIT05-LARGE")
    assert consistency["consistent"] is False
    assert consistency["code"] == "STALE_FILE_MODIFIED"


def test_64_crit05_unreadable_or_mid_hash_modified_file_marks_snapshot_incomplete_and_blocks_finalization_and_execution(
    tmp_path: Path,
) -> None:
    import verification

    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT05-UNREAD")
    target_abs = str((repo_dir / "src" / "payment.py").resolve())

    verification._SNAPSHOT_UNREADABLE_PATHS_FOR_TEST.add(target_abs)
    try:
        stats = ingest_findings(
            db_path,
            project_key="pay",
            run_id="RUN-CRIT05-UNREAD",
            findings=[_sample_candidate_findings()[0]],
            report_dir=tmp_path / "reports",
            repo_path=repo_dir,
        )
    finally:
        verification._SNAPSHOT_UNREADABLE_PATHS_FOR_TEST.discard(target_abs)

    vrun_id = stats["verification_run_id"]
    with connect(db_path) as conn:
        snap = conn.execute("SELECT snapshot_complete, incomplete_reason FROM audit_snapshots WHERE run_id='RUN-CRIT05-UNREAD'").fetchone()
        assert int(snap["snapshot_complete"]) == 0
        assert "src/payment.py" in str(snap["incomplete_reason"])

    submit_verification_results(
        db_path,
        audit_run_id="RUN-CRIT05-UNREAD",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-crit05-unread",
        verification_results=[
            {
                "candidate_finding_id": "F-PAY-1",
                "verdict": "CONFIRMED",
                "verified_severity": "CRITICAL",
                "verified_confidence": "CONFIRMED",
                "technical_rationale": "Confirmed.",
                "source_evidence": {
                    "file_path": "src/payment.py",
                    "line_start": 4,
                    "line_end": 9,
                    "symbol": "charge_card",
                    "evidence_excerpt": "balance_delta = -amount",
                },
                "remediation_review": "Safe.",
                "remediation_safe": True,
                "acceptance_criteria": "Test.",
            }
        ],
    )
    with pytest.raises(RuntimeError, match="incomplete|stale"):
        finalize_verified_report(db_path, audit_run_id="RUN-CRIT05-UNREAD", verification_run_id=vrun_id)


def test_65_crit05_windows_case_variant_path_validated_consistently(
    tmp_path: Path,
) -> None:
    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-CRIT05-CASE")
    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-CRIT05-CASE",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    with connect(db_path) as conn:
        snap_row = conn.execute("SELECT * FROM audit_snapshots WHERE run_id='RUN-CRIT05-CASE'").fetchone()
        cand_row = conn.execute("SELECT * FROM candidate_findings WHERE run_id='RUN-CRIT05-CASE'").fetchone()

    # 1. Case-variant path 'SRC/Payment.py' resolves to canonical 'src/payment.py' and validates consistently
    res_ok = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info={
            "snapshot_id": snap_row["snapshot_id"],
            "base_commit_sha": snap_row["base_commit_sha"],
            "working_tree_hash": snap_row["working_tree_hash"],
            "file_hashes": json.loads(snap_row["file_hashes_json"]),
        },
        candidate=dict(cand_row),
        source_evidence={
            "file_path": "SRC/Payment.py",
            "line_start": 4,
            "line_end": 9,
            "symbol": "charge_card",
            "evidence_excerpt": "balance_delta = -amount",
        },
    )
    assert res_ok["passed"] is True
    assert res_ok["status"] == "PASSED"
    assert res_ok["code"] == "OK"

    # 2. Ambiguous colliding case keys in snapshot file_hashes fail closed
    colliding_hashes = dict(json.loads(snap_row["file_hashes_json"]))
    colliding_hashes["SRC/Payment.py"] = "0000"
    res_collision = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info={
            "snapshot_id": snap_row["snapshot_id"],
            "base_commit_sha": snap_row["base_commit_sha"],
            "working_tree_hash": snap_row["working_tree_hash"],
            "file_hashes": colliding_hashes,
        },
        candidate=dict(cand_row),
        source_evidence={
            "file_path": "src/payment.py",
            "line_start": 4,
            "line_end": 9,
            "symbol": "charge_card",
            "evidence_excerpt": "balance_delta = -amount",
        },
    )
    assert res_collision["passed"] is False
    assert res_collision["code"] == "AMBIGUOUS_CASE_COLLISION"


def test_66_new02_installer_failure_rolls_back_core_integrations_skills_and_db_in_isolated_temp_dirs(
    tmp_path: Path,
) -> None:
    installer_script = Path(__file__).resolve().parents[1] / "Install-AntigravityAuditor.ps1"
    install_root = tmp_path / "isolated_install"
    gemini_home = tmp_path / "isolated_gemini"

    # Seed pre-existing core, integrations, global-skills, target config/skills, and a v2 database
    (install_root / "core").mkdir(parents=True)
    (install_root / "core" / "marker.txt").write_text("OLD_CORE_V2", encoding="utf-8")
    (install_root / "integrations").mkdir(parents=True)
    (install_root / "integrations" / "marker.txt").write_text("OLD_INTEGRATIONS_V2", encoding="utf-8")
    (install_root / "global-skills").mkdir(parents=True)
    (install_root / "global-skills" / "marker.txt").write_text("OLD_GLOBAL_SKILLS_V2", encoding="utf-8")

    target_skills = gemini_home / "config" / "skills"
    (target_skills / "custom-skill").mkdir(parents=True)
    (target_skills / "custom-skill" / "SKILL.md").write_text("CUSTOM_SKILL_V2", encoding="utf-8")

    db_dir = install_root / "database"
    db_dir.mkdir(parents=True)
    db_file = db_dir / "auditor.db"
    raw = sqlite3.connect(str(db_file))
    raw.executescript(
        """
        CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL);
        INSERT INTO schema_migrations VALUES (1, '001'), (2, '002');
        CREATE TABLE projects (project_key TEXT PRIMARY KEY, display_name TEXT NOT NULL, repo_path TEXT NOT NULL UNIQUE);
        INSERT INTO projects VALUES ('p_install', 'Install Test', '/tmp/p_install');
        """
    )
    raw.close()

    # Case A: Failure during register-mcp (AFTER skills install and DB migration init have already run!)
    proc = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(installer_script),
            "-InstallRootOverride",
            str(install_root),
            "-HomeGeminiOverride",
            str(gemini_home),
            "-SimulateFailureStep",
            "register-mcp",
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert proc.returncode != 0
    combined_out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    assert "INSTALLER ROLLBACK COMPLETED" in combined_out

    # Verify core, integrations, global-skills, target config/skills, and v2 DB were all restored!
    assert (install_root / "core" / "marker.txt").read_text(encoding="utf-8") == "OLD_CORE_V2"
    assert not (install_root / "core" / "cli.py").exists()
    assert (install_root / "integrations" / "marker.txt").read_text(encoding="utf-8") == "OLD_INTEGRATIONS_V2"
    assert (install_root / "global-skills" / "marker.txt").read_text(encoding="utf-8") == "OLD_GLOBAL_SKILLS_V2"
    assert (target_skills / "custom-skill" / "SKILL.md").read_text(encoding="utf-8") == "CUSTOM_SKILL_V2"
    assert not (target_skills / "independent-audit-verifier").exists()

    chk = sqlite3.connect(str(db_file))
    versions = [r[0] for r in chk.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()]
    chk.close()
    assert versions == [1, 2]


def test_67_powershell_herestring_lexer_and_evidence_validation(
    tmp_path: Path,
) -> None:
    from core.verification import (
        _strip_comments_and_strings_per_line,
        UnverifiableEvidenceError,
        validate_single_finding_evidence,
    )

    # 1. Single-quoted multiline here-string with embedded single quotes
    ps_single = (
        "$text = @'\n"
        "This is 'single quoted' and ''escaped''\n"
        "and another 'line' with quotes\n"
        "'@\n"
        "function TargetFunc1 {\n"
        "    return 42\n"
        "}\n"
    )
    lines_single = _strip_comments_and_strings_per_line(ps_single, ".ps1")
    assert len(lines_single) == len(ps_single.split("\n"))
    assert "TargetFunc1" in lines_single[4]
    assert "single quoted" not in "".join(lines_single[:4])

    # 2. Double-quoted multiline here-string with embedded double quotes
    ps_double = (
        '$text = @"\n'
        'This is "double quoted" and ""escaped""\n'
        'and another "line" with quotes\n'
        '"@\n'
        "function TargetFunc2 {\n"
        "    return 43\n"
        "}\n"
    )
    lines_double = _strip_comments_and_strings_per_line(ps_double, ".ps1")
    assert len(lines_double) == len(ps_double.split("\n"))
    assert "TargetFunc2" in lines_double[4]
    assert "double quoted" not in "".join(lines_double[:4])

    # 3. Fake function name inside here-string must not contribute code symbols
    ps_fake = (
        "$code = @'\n"
        "function FakeFunctionInsideHereString {\n"
        '    Write-Host "Fake"\n'
        "}\n"
        "'@\n"
    )
    lines_fake = _strip_comments_and_strings_per_line(ps_fake, ".ps1")
    assert "FakeFunctionInsideHereString" not in "".join(lines_fake)

    # 4. Real function after closing marker (both subsequent line and same line)
    # 4a. Subsequent line
    ps_subsequent = (
        "$code = @'\n"
        "some here-string payload\n"
        "'@\n"
        "function RealFunctionAfterTerminator {\n"
        "    return 100\n"
        "}\n"
    )
    lines_subsequent = _strip_comments_and_strings_per_line(ps_subsequent, ".ps1")
    assert "RealFunctionAfterTerminator" in lines_subsequent[3]

    # 4b. Same line after closing marker
    ps_sameline = (
        "$code = @'\n"
        "some here-string payload\n"
        "'@; function RealFunctionOnSameLineAsClosing { return 200 }\n"
    )
    lines_sameline = _strip_comments_and_strings_per_line(ps_sameline, ".ps1")
    assert "RealFunctionOnSameLineAsClosing" in lines_sameline[2]

    # 5. Comment inside here-string
    ps_comment = (
        "$text = @'\n"
        "# This looks like a line comment\n"
        "<# This looks like a block comment #>\n"
        "'@\n"
        "function RealFuncWithCommentInHereString { return 300 }\n"
    )
    lines_comment = _strip_comments_and_strings_per_line(ps_comment, ".ps1")
    assert "RealFuncWithCommentInHereString" in lines_comment[4]

    # 6. Ordinary PowerShell string containing @'
    ps_ordinary = (
        '$s1 = "This is a normal double quoted string containing @\' here"\n'
        "$s2 = 'This is a normal single quoted string containing @' + ' more text'\n"
        "function NormalFunctionAfterOrdinaryStrings {\n"
        "    Write-Host $s1\n"
        "}\n"
    )
    lines_ordinary = _strip_comments_and_strings_per_line(ps_ordinary, ".ps1")
    assert "NormalFunctionAfterOrdinaryStrings" in lines_ordinary[2]

    # 7. Here-string with URL containing // and code after terminator
    ps_url = (
        "$docs = @'\n"
        "Visit https://example.com/api/v1//users for details.\n"
        "See also http://foo.bar//baz//qux\n"
        "'@; function Get-UserData {\n"
        "    return 400\n"
        "}\n"
    )
    lines_url = _strip_comments_and_strings_per_line(ps_url, ".ps1")
    assert "Get-UserData" in lines_url[3]

    # 8. Unclosed here-string fails conservatively with UNVERIFIABLE_EVIDENCE
    ps_unclosed = (
        "$docs = @'\n"
        "unclosed content without terminator\n"
    )
    with pytest.raises(UnverifiableEvidenceError) as exc_info:
        _strip_comments_and_strings_per_line(ps_unclosed, ".ps1")
    assert exc_info.value.code == "UNVERIFIABLE_EVIDENCE"

    # 9. Whitespace before here-string terminator fails conservatively with UNVERIFIABLE_EVIDENCE
    ps_indented = (
        "$docs = @'\n"
        "content\n"
        "   '@\n"
    )
    with pytest.raises(UnverifiableEvidenceError) as exc_indented:
        _strip_comments_and_strings_per_line(ps_indented, ".ps1")
    assert exc_indented.value.code == "UNVERIFIABLE_EVIDENCE"

    # 10. End-to-end evidence gate integration with validate_single_finding_evidence
    repo_dir = tmp_path / "ps_repo"
    repo_dir.mkdir(parents=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True, capture_output=True)

    ps_file = repo_dir / "service.ps1"
    ps_file.write_text(
        "$banner = @'\n"
        "function FakeInternalHelper {\n"
        '    Write-Host "Fake"\n'
        "}\n"
        "'@\n"
        "function RealExportedService {\n"
        '    Write-Output "Real Service Active"\n'
        "}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial PowerShell service"], cwd=repo_dir, check=True, capture_output=True)
    head_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True).stdout.strip()

    file_bytes = ps_file.read_bytes()
    file_sha = hashlib.sha256(file_bytes).hexdigest()
    snap_info = {
        "snapshot_id": "SNAP-PS-1",
        "base_commit_sha": head_sha,
        "file_hashes": {"service.ps1": file_sha},
    }

    # Finding referencing fake function inside here-string must fail symbol gate
    cand_fake = {
        "candidate_id": "CAND-PS-FAKE",
        "file_path": "service.ps1",
        "line_start": 2,
        "line_end": 4,
        "symbol": "FakeInternalHelper",
    }
    res_fake = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snap_info,
        candidate=cand_fake,
        source_evidence={
            "file_path": "service.ps1",
            "line_start": 2,
            "line_end": 4,
            "symbol": "FakeInternalHelper",
            "evidence_excerpt": 'Write-Host "Fake"',
        },
    )
    assert res_fake["passed"] is False
    assert res_fake["code"] == "SYMBOL_NOT_FOUND_IN_FILE"
    assert res_fake["fabricated_reference"] is True

    # Finding referencing real function after terminator must pass
    cand_real = {
        "candidate_id": "CAND-PS-REAL",
        "file_path": "service.ps1",
        "line_start": 6,
        "line_end": 8,
        "symbol": "RealExportedService",
    }
    res_real = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snap_info,
        candidate=cand_real,
        source_evidence={
            "file_path": "service.ps1",
            "line_start": 6,
            "line_end": 8,
            "symbol": "RealExportedService",
            "evidence_excerpt": 'Write-Output "Real Service Active"',
        },
    )
    assert res_real["passed"] is True
    assert res_real["status"] == "PASSED"

    # Finding in file with unclosed here-string must return UNVERIFIABLE_EVIDENCE
    broken_file = repo_dir / "broken.ps1"
    broken_file.write_text(
        "$malformed = @'\n"
        "function BrokenFunc {\n"
        "    return 1\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Add broken ps1"], cwd=repo_dir, check=True, capture_output=True)
    broken_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True).stdout.strip()
    broken_sha = hashlib.sha256(broken_file.read_bytes()).hexdigest()

    snap_broken = {
        "snapshot_id": "SNAP-PS-BROKEN",
        "base_commit_sha": broken_head,
        "file_hashes": {"broken.ps1": broken_sha},
    }
    cand_broken = {
        "candidate_id": "CAND-PS-UNVER",
        "file_path": "broken.ps1",
        "line_start": 2,
        "line_end": 3,
        "symbol": "BrokenFunc",
    }
    res_broken = validate_single_finding_evidence(
        repo_path=repo_dir,
        snapshot_info=snap_broken,
        candidate=cand_broken,
        source_evidence={
            "file_path": "broken.ps1",
            "line_start": 2,
            "line_end": 3,
            "symbol": "BrokenFunc",
            "evidence_excerpt": "return 1",
        },
    )
    assert res_broken["passed"] is False
    assert res_broken["status"] == "UNVERIFIABLE"
    assert res_broken["code"] == "UNVERIFIABLE_EVIDENCE"


def test_68_installer_process_preflight_isolated_test_harness() -> None:
    harness_path = Path(__file__).resolve().parent / "test_installer_preflight.ps1"
    assert harness_path.exists(), f"Harness script missing at {harness_path}"

    proc = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness_path),
        ],
        capture_output=True,
        text=True,
        timeout=240,
    )
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    assert proc.returncode == 0, f"Installer preflight harness failed:\n{combined}"
    assert "All 18 installer preflight and SQLite lock tests passed cleanly!" in combined
    assert "Test1_NoActiveProcess: PASSED" in combined
    assert "Test2_ActiveWorkerAborts: PASSED" in combined
    assert "Test3_ActiveMcpAborts: PASSED" in combined
    assert "Test4_ZeroModificationsOnAbort: PASSED" in combined
    assert "Test5_UnrelatedPythonNoFalsePositive: PASSED" in combined
    assert "Test6_UnrelatedMcpServerNoFalsePositive: PASSED" in combined
    assert "Test7_UnrelatedMcpServeNoFalsePositive: PASSED" in combined
    assert "Test8_DbLockSafeAbort: PASSED" in combined
    assert "Test9_WalLockSafeAbort: PASSED" in combined
    assert "Test10_ShmLockSafeAbort: PASSED" in combined
    assert "Test11_NoLockProceedsCleanly: PASSED" in combined
    assert "Test12_CaseA_UnrelatedMcpServerFile: PASSED" in combined
    assert "Test13_CaseB_UnrelatedCliMcpServe: PASSED" in combined
    assert "Test14_GenuineAuditorMcpDetected: PASSED" in combined
    assert "Test15_GenuineAuditorCliMcpServeDetected: PASSED" in combined
    assert "Test16_OtherInstallRootOverrideRespected: PASSED" in combined
    assert "Test17_PrefixCollisionNotMatched: PASSED" in combined



def test_agentapi_requires_an_explicit_project_id(tmp_path: Path) -> None:
    """No hard-coded default Project ID: an omitted id is refused instead of using some other project."""
    fake_exe = tmp_path / "agentapi.exe"
    fake_exe.write_text("mock", encoding="utf-8")
    calls: list[Any] = []
    adapter = AgentApiAdapter(executable_override=str(fake_exe), runner=lambda cmd, **kw: calls.append(cmd))
    res = adapter.start_new_conversation("prompt", cwd=tmp_path)
    assert not res.ok and res.error_code == "MISSING_PROJECT_ID" and calls == []

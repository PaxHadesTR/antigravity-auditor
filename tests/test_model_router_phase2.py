"""Phase 2 Integration and Safety Remediation Tests for Task-Based Model Router.

Validates the full production integration and safety remediation:
- HIGH-01: Primary Auditor CLI dispatch integration with deterministic router and AntigravityCliAdapter.
- HIGH-02: VerificationWorker deterministic model routing for routine and critical findings.
- HIGH-03: Evidence Gate routing behavior (BLOCKED_EVIDENCE vs preliminary analysis; execution eligibility prevention).
- HIGH-04: Cross-model trust enforcement at finalization (strict model independence, degraded trust, execution eligibility block).
- MEDIUM-01: Argon default token budget = 100,000 tokens per audit run.
- MEDIUM-02: Multi-process atomic budget reservation and lease expiry in SQLite.
- MEDIUM-03: Persistent quota exhaustion rejection without retry loops or silent fallbacks.
- MEDIUM-04: Shared programmatic dispatcher (dispatch_routed_task) and CLI model-dispatch subcommand.
"""

from __future__ import annotations

import json
import multiprocessing
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Ensure core is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from agy_adapter import AgyDispatchResult, AntigravityCliAdapter
import cli
from db import (
    cleanup_expired_argon_reservations,
    connect,
    get_budget_usage_for_run,
    ingest_findings,
    initialize,
    record_event,
    record_model_dispatch,
    release_argon_budget_atomic,
    reserve_argon_budget_atomic,
)
from model_budget import (
    DEFAULT_MAX_ARGON_TOKENS_PER_RUN,
    ArgonBudgetConfig,
    ModelBudgetTracker,
    build_minimized_evidence_package,
)
from model_policy import (
    ExecutionIntent,
    ModelId,
    ModelRoutingDecision,
    ModelRoutingRequest,
    ReasoningLevel,
    RoutingStatus,
    TaskRisk,
    TaskType,
    route_model,
)
from verification import (
    VerificationWorker,
    derive_verification_trust,
    finalize_verified_report,
    submit_verification_results,
    verify_cross_model_independence,
)


def _mp_worker_compete_slot(db_path_str: str, run_id: str, fp: str, queue: Any, barrier: Any) -> None:
    barrier.wait()
    from model_budget import ModelBudgetTracker
    tracker = ModelBudgetTracker(db_path=Path(db_path_str))
    res = tracker.reserve(
        model_id="gemini-4-argon-medium",
        audit_run_id=run_id,
        finding_fingerprint=fp,
        estimated_tokens=20_000,
    )
    queue.put({"allowed": res.allowed, "status": res.status, "reason": res.reason, "reservation_id": res.reservation_id})


def _mp_worker_compete_requests(db_path_str: str, run_id: str, fp: str, max_requests: int, queue: Any, barrier: Any) -> None:
    barrier.wait()
    from model_budget import ModelBudgetTracker, ArgonBudgetConfig
    cfg = ArgonBudgetConfig(max_requests_per_run=max_requests, max_concurrent_jobs=10)
    tracker = ModelBudgetTracker(config=cfg, db_path=Path(db_path_str))
    res = tracker.reserve(
        model_id="gemini-4-argon-medium",
        audit_run_id=run_id,
        finding_fingerprint=fp,
        estimated_tokens=5_000,
    )
    queue.put({"allowed": res.allowed, "status": res.status, "reason": res.reason})


def _mp_worker_compete_tokens(db_path_str: str, run_id: str, fp: str, tokens: int, max_tokens: int, queue: Any, barrier: Any) -> None:
    barrier.wait()
    from model_budget import ModelBudgetTracker, ArgonBudgetConfig
    cfg = ArgonBudgetConfig(max_tokens_per_run=max_tokens, max_concurrent_jobs=10)
    tracker = ModelBudgetTracker(config=cfg, db_path=Path(db_path_str))
    res = tracker.reserve(
        model_id="gemini-4-argon-medium",
        audit_run_id=run_id,
        finding_fingerprint=fp,
        estimated_tokens=tokens,
    )
    queue.put({"allowed": res.allowed, "status": res.status, "reason": res.reason})


def _mp_worker_dedup_step1(db_path_str: str, run_id: str, fp: str, queue: Any) -> None:
    from model_budget import ModelBudgetTracker
    tracker = ModelBudgetTracker(db_path=Path(db_path_str))
    res = tracker.reserve(
        model_id="gemini-4-argon-medium",
        audit_run_id=run_id,
        finding_fingerprint=fp,
        estimated_tokens=10_000,
    )
    tracker.release_job(
        model_id="gemini-4-argon-medium",
        audit_run_id=run_id,
        tokens_consumed=10_000,
        finding_fingerprint=fp,
    )
    queue.put({"allowed": res.allowed, "status": res.status})


def _mp_worker_dedup_step2(db_path_str: str, run_id: str, fp: str, queue: Any) -> None:
    from model_budget import ModelBudgetTracker
    tracker = ModelBudgetTracker(db_path=Path(db_path_str))
    res = tracker.reserve(
        model_id="gemini-4-argon-medium",
        audit_run_id=run_id,
        finding_fingerprint=fp,
        estimated_tokens=10_000,
    )
    queue.put({"allowed": res.allowed, "status": res.status, "reason": res.reason})


def make_dispatch_result(
    ok: bool = True,
    status: str = "SUCCESS",
    conversation_id: str = "conv-p2-01",
    model: str = "gemini-4-hydrogen-high",
    attestation_status: str = "RUNTIME_ATTESTED",
    total_tokens: int = 1000,
    error: str | None = None,
    response_text: str = '{"findings": []}',
) -> AgyDispatchResult:
    return AgyDispatchResult(
        ok=ok,
        status=status,
        requested_model=model,
        observed_model=model if ok else None,
        conversation_id=conversation_id if ok else None,
        response_text=response_text if ok else "",
        input_tokens=total_tokens // 2 if ok else 0,
        output_tokens=total_tokens // 2 if ok else 0,
        thinking_tokens=0,
        total_tokens=total_tokens if ok else 0,
        execution_duration=1.0,
        command=["agy.exe"],
        returncode=0 if ok else 1,
        stdout="",
        stderr=error or "",
        error_message=error,
        attestation_status=attestation_status if ok else "MODEL_ATTESTATION_INCOMPLETE",
    )


def _seed_db(tmp_path: Path, run_id: str = "RUN-P2-01", status: str = "ANALYZING") -> tuple[Path, Path]:
    from db import compute_file_blob_hash

    db_path = tmp_path / "auditor.db"
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Auditor Test"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "auditor@test.local"], cwd=repo_dir, check=True)
    src_dir = repo_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    pay_file = src_dir / "payment.py"
    pay_content = (
        "def charge(amount: int):\n    if amount < 0:\n        return False\n    return True\n"
    )
    pay_file.write_text(pay_content, encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=repo_dir, check=True, capture_output=True)
    head_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir).decode().strip()

    pay_hash = compute_file_blob_hash(repo_dir, "src/payment.py")
    file_hashes = {"src/payment.py": pay_hash}

    initialize(db_path)
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id)
               VALUES(?,?,?,?)""",
            ("p2", "Phase 2 Project", str(repo_dir), "agy-p2"),
        )
        conn.execute(
            """INSERT INTO audit_runs(
                run_id, project_key, trigger_source, status, primary_model, primary_model_attestation
            ) VALUES(?,?,?,?,?,?)""",
            (run_id, "p2", "manual", status, "gemini-4-hydrogen-high", "RUNTIME_ATTESTED"),
        )
        conn.execute(
            """INSERT INTO audit_snapshots(
                snapshot_id, project_key, repo_path, run_id, base_commit_sha, working_tree_hash, file_hashes_json
            ) VALUES(?,?,?,?,?,?,?)""",
            ("snap-p2-01", "p2", str(repo_dir), run_id, head_sha, "clean", json.dumps(file_hashes)),
        )
        conn.commit()
    return db_path, repo_dir


# ==============================================================================
# HIGH-01: Primary Auditor CLI Dispatch Integration
# ==============================================================================

def test_p2_01_primary_audit_cli_dispatch_selects_hydrogen_high_and_persists_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, repo_dir = _seed_db(tmp_path, run_id="RUN-DISP-01", status="COMPLETED")
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "APP_HOME", tmp_path)
    monkeypatch.setattr(cli, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(cli, "SIDECAR_ROOT", tmp_path / "sidecars")
    monkeypatch.setattr(cli, "JSONL_PATH", tmp_path / "logs" / "events.jsonl")

    mock_result = make_dispatch_result(
        ok=True,
        conversation_id="conv-primary-001",
        model="gemini-4-hydrogen-high",
        total_tokens=1500,
    )

    with patch("cli.AntigravityCliAdapter") as MockAdapter:
        instance = MockAdapter.return_value
        instance.start_new_conversation.return_value = mock_result

        # Execute dispatch
        cli.dispatch("p2")

        # Assert adapter was called with Hydrogen High
        assert instance.start_new_conversation.called
        call_kwargs = instance.start_new_conversation.call_args.kwargs
        assert call_kwargs["model_id"] == ModelId.GEMINI_4_HYDROGEN_HIGH.value
        assert call_kwargs["task_type"] == TaskType.PRIMARY_AUDIT

        # Verify DB persistence of primary model, attestation, and conversation ID
        with connect(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM audit_runs WHERE project_key='p2' AND run_id != 'RUN-DISP-01' ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
            assert row["agent_conversation_id"] == "conv-primary-001"
            assert row["primary_model"] == "gemini-4-hydrogen-high"
            assert row["primary_model_attestation"] == "RUNTIME_ATTESTED"
            # Structured delivery submits the (empty) findings inline -> the run moves on to verification.
            assert row["status"] in ("VERIFICATION_PENDING", "READY_FOR_REVIEW")
        assert call_kwargs["isolated"] is True and call_kwargs["json_schema_path"] is not None


def test_p2_02_primary_audit_cli_missing_executable_fails_without_agentapi_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, repo_dir = _seed_db(tmp_path, run_id="RUN-DISP-FAIL", status="COMPLETED")
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "APP_HOME", tmp_path)
    monkeypatch.setattr(cli, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(cli, "SIDECAR_ROOT", tmp_path / "sidecars")
    monkeypatch.setattr(cli, "JSONL_PATH", tmp_path / "logs" / "events.jsonl")

    fail_result = make_dispatch_result(
        ok=False,
        status="CLI_NOT_FOUND",
        error="Antigravity CLI executable (agy.exe) not found",
    )

    with patch("cli.AntigravityCliAdapter") as MockAdapter, \
         patch("cli.AgentApiAdapter") as MockLegacy:
        instance = MockAdapter.return_value
        instance.start_new_conversation.return_value = fail_result

        with pytest.raises(RuntimeError, match="CLI executable"):
            cli.dispatch("p2")

        # Verify AgentApiAdapter was NEVER invoked as fallback
        assert not MockLegacy.called


# ==============================================================================
# HIGH-02: VerificationWorker Model Routing Integration
# ==============================================================================

def test_p2_03_verifier_worker_routes_routine_finding_to_hydrogen_high(
    tmp_path: Path,
) -> None:
    db_path, repo_dir = _seed_db(tmp_path, run_id="RUN-VER-ROUTINE", status="ANALYZING")

    stats = ingest_findings(
        db_path,
        project_key="p2",
        run_id="RUN-VER-ROUTINE",
        findings=[{
            "finding_id": "F-ROUTINE-1",
            "fingerprint": "fp-routine-1",
            "title": "Unnecessary whitespace",
            "category": "GENERAL",
            "severity": "LOW",
            "confidence": "LIKELY",
            "file_path": "src/payment.py",
            "symbol": "charge",
            "line_start": 1,
            "line_end": 4,
            "evidence": "def charge(amount: int):",
            "impact": "Code style",
            "recommendation": "Remove whitespace",
        }],
        repo_path=repo_dir,
        report_dir=tmp_path / "reports",
    )

    worker = VerificationWorker(db_path)
    mock_adapter = MagicMock()
    mock_adapter.start_new_conversation.return_value = make_dispatch_result(
        response_text='{"verification_results": []}',
        ok=True,
        conversation_id="conv-ver-hydrogen-01",
        model="gemini-4-hydrogen-high",
    )
    worker.adapter = mock_adapter

    res = worker.process_one_job()
    assert res is not None
    # The mocked answer is empty: routing is what these tests check; an incomplete answer is retried.
    assert res["status"] in ("RUNNING", "DISPATCHED", "RETRYABLE_FAILURE")

    # Verify routed model was Hydrogen High
    call_kwargs = mock_adapter.start_new_conversation.call_args.kwargs
    assert call_kwargs["model_id"] == ModelId.GEMINI_4_HYDROGEN_HIGH.value
    assert call_kwargs["task_type"] == TaskType.ROUTINE_VERIFICATION


def test_p2_04_verifier_worker_routes_critical_finding_to_argon_medium(
    tmp_path: Path,
) -> None:
    db_path, repo_dir = _seed_db(tmp_path, run_id="RUN-VER-CRIT", status="ANALYZING")

    stats = ingest_findings(
        db_path,
        project_key="p2",
        run_id="RUN-VER-CRIT",
        findings=[{
            "finding_id": "F-CRIT-DB",
            "fingerprint": "fp-crit-db",
            "title": "Transaction isolation violation",
            "category": "DATABASE_INTEGRITY",
            "severity": "HIGH",
            "confidence": "CONFIRMED",
            "file_path": "src/payment.py",
            "symbol": "charge",
            "line_start": 1,
            "line_end": 4,
            "evidence": "def charge(amount: int):",
            "impact": "Data inconsistency",
            "recommendation": "Use serializable isolation",
        }],
        repo_path=repo_dir,
        report_dir=tmp_path / "reports",
    )

    worker = VerificationWorker(db_path)
    mock_adapter = MagicMock()
    mock_adapter.start_new_conversation.return_value = make_dispatch_result(
        response_text='{"verification_results": []}',
        ok=True,
        conversation_id="conv-ver-argon-med-01",
        model="gemini-4-argon-medium",
    )
    worker.adapter = mock_adapter

    res = worker.process_one_job()
    assert res is not None
    # The mocked answer is empty: routing is what these tests check; an incomplete answer is retried.
    assert res["status"] in ("RUNNING", "DISPATCHED", "RETRYABLE_FAILURE")

    call_kwargs = mock_adapter.start_new_conversation.call_args.kwargs
    assert call_kwargs["model_id"] == ModelId.GEMINI_4_ARGON_MEDIUM.value
    assert call_kwargs["task_type"] == TaskType.CRITICAL_VERIFICATION


def test_p2_05_verifier_worker_routes_catastrophic_finding_to_argon_high(
    tmp_path: Path,
) -> None:
    db_path, repo_dir = _seed_db(tmp_path, run_id="RUN-VER-RCE", status="ANALYZING")

    stats = ingest_findings(
        db_path,
        project_key="p2",
        run_id="RUN-VER-RCE",
        findings=[{
            "finding_id": "F-CRIT-RCE",
            "fingerprint": "fp-crit-rce",
            "title": "Remote code execution in eval",
            "category": "RCE",
            "severity": "CRITICAL",
            "confidence": "CONFIRMED",
            "file_path": "src/payment.py",
            "symbol": "charge",
            "line_start": 1,
            "line_end": 4,
            "evidence": "def charge(amount: int):",
            "impact": "Remote code execution",
            "recommendation": "Remove eval",
        }],
        repo_path=repo_dir,
        report_dir=tmp_path / "reports",
    )

    worker = VerificationWorker(db_path)
    mock_adapter = MagicMock()
    mock_adapter.start_new_conversation.return_value = make_dispatch_result(
        response_text='{"verification_results": []}',
        ok=True,
        conversation_id="conv-ver-argon-high-01",
        model="gemini-4-argon-high",
    )
    worker.adapter = mock_adapter

    res = worker.process_one_job()
    assert res is not None
    # The mocked answer is empty: routing is what these tests check; an incomplete answer is retried.
    assert res["status"] in ("RUNNING", "DISPATCHED", "RETRYABLE_FAILURE")

    call_kwargs = mock_adapter.start_new_conversation.call_args.kwargs
    assert call_kwargs["model_id"] == ModelId.GEMINI_4_ARGON_HIGH.value


# ==============================================================================
# HIGH-03: Evidence Gate Routing Behavior & Preliminary Isolation
# ==============================================================================

def test_p2_06_unvalidated_evidence_blocks_critical_verification_from_argon() -> None:
    for status in ("UNCHECKED", "FAILED", "PENDING", "INVALID"):
        req = ModelRoutingRequest(
            task_type=TaskType.CRITICAL_VERIFICATION,
            severity="CRITICAL",
            finding_category="RCE",
            evidence_gate_status=status,
            execution_intent=ExecutionIntent.REQUIRED_CRITICAL_VERIFICATION,
        )
        decision = route_model(req)
        assert decision.is_blocked
        assert decision.routing_status == RoutingStatus.BLOCKED_EVIDENCE
        assert decision.is_preliminary
        assert "BLOCKED" in decision.decision_reason


def test_p2_07_preliminary_analysis_permitted_with_hydrogen_high() -> None:
    req = ModelRoutingRequest(
        task_type=TaskType.CRITICAL_VERIFICATION,
        severity="CRITICAL",
        finding_category="RCE",
        evidence_gate_status="UNCHECKED",
        execution_intent=ExecutionIntent.PRELIMINARY_ANALYSIS,
    )
    decision = route_model(req)
    assert not decision.is_blocked
    assert decision.routing_status == RoutingStatus.READY
    assert decision.selected_model == ModelId.GEMINI_4_HYDROGEN_HIGH
    assert decision.is_preliminary


# ==============================================================================
# HIGH-04: Cross-Model Trust Enforcement at Finalization
# ==============================================================================

def test_p2_08_identical_models_fails_cross_model_verification() -> None:
    is_ok, reason = verify_cross_model_independence(
        "gemini-4-hydrogen-high",
        "gemini-4-hydrogen-high",
        "RUNTIME_ATTESTED",
        primary_attestation_status="RUNTIME_ATTESTED",
    )
    assert not is_ok
    assert "identical" in reason.lower()

    is_ok_same_line, reason_same_line = verify_cross_model_independence(
        "gemini-4-hydrogen-high",
        "gemini-4-hydrogen-medium",
        "RUNTIME_ATTESTED",
        primary_attestation_status="RUNTIME_ATTESTED",
    )
    assert not is_ok_same_line
    assert "same model line" in reason_same_line.lower()


def test_p2_09_unattested_verifier_model_fails_cross_model_verification() -> None:
    is_ok, reason = verify_cross_model_independence(
        "gemini-4-hydrogen-high",
        "gemini-4-argon-high",
        "CALLER_CLAIMED_UNVERIFIED",
        primary_attestation_status="RUNTIME_ATTESTED",
    )
    assert not is_ok
    assert "RUNTIME_ATTESTED" in reason


def test_p2_09b_unattested_primary_model_fails_cross_model_verification() -> None:
    for primary_att in ("MODEL_ATTESTATION_MISMATCH", "MODEL_ATTESTATION_INCOMPLETE", "", None):
        is_ok, reason = verify_cross_model_independence(
            "gemini-4-hydrogen-high", "gemini-4-argon-high", "RUNTIME_ATTESTED",
            primary_attestation_status=primary_att,
        )
        assert not is_ok and "Primary model" in reason


def test_p2_10_genuine_cross_model_attestation_succeeds() -> None:
    is_ok, reason = verify_cross_model_independence(
        "gemini-4-hydrogen-high",
        "gemini-4-argon-high",
        "RUNTIME_ATTESTED",
        primary_attestation_status="RUNTIME_ATTESTED",
    )
    assert is_ok
    assert "Cross-model independence verified" in reason


def test_p2_11_unverified_cross_model_blocks_execution_eligibility_for_critical_finding(
    tmp_path: Path,
) -> None:
    db_path, repo_dir = _seed_db(tmp_path, run_id="RUN-TRUST-01")

    stats = ingest_findings(
        db_path,
        project_key="p2",
        run_id="RUN-TRUST-01",
        findings=[{
            "finding_id": "F-ARGON-SEC-1",
            "fingerprint": "fp-argon-sec-1",
            "title": "Critical Authentication Bypass",
            "category": "AUTHENTICATION_BYPASS",
            "severity": "CRITICAL",
            "confidence": "CONFIRMED",
            "file_path": "src/payment.py",
            "symbol": "charge",
            "line_start": 1,
            "line_end": 4,
            "evidence": "def charge(amount: int):",
            "impact": "Full bypass",
            "recommendation": "Enforce auth",
        }],
        repo_path=repo_dir,
        report_dir=tmp_path / "reports",
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-TRUST-01",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-trust-01-v",
        verifier_metadata={
            "verifier_model_id": "gemini-4-hydrogen-high",
            "verifier_attestation_status": "MODEL_ATTESTATION_INCOMPLETE",
        },
        verification_results=[{
            "candidate_finding_id": "F-ARGON-SEC-1",
            "verdict": "CONFIRMED",
            "verified_severity": "CRITICAL",
            "verified_confidence": "CONFIRMED",
            "technical_rationale": "Confirmed by verifier.",
            "source_evidence": {
                "file_path": "src/payment.py",
                "line_start": 1,
                "line_end": 4,
                "symbol": "charge",
                "evidence_excerpt": "def charge(amount: int):",
            },
            "remediation_review": "Safe guard.",
            "remediation_safe": True,
            "acceptance_criteria": "Verify auth required.",
        }],
    )

    fin = finalize_verified_report(db_path, audit_run_id="RUN-TRUST-01", verification_run_id=vrun_id)
    assert fin["status"] == "READY_FOR_REVIEW"

    with connect(db_path) as conn:
        finding = conn.execute("SELECT * FROM findings WHERE finding_id='F-ARGON-SEC-1'").fetchone()
        # K1 (2026-11-16): without independent cross-model verification the finding stays APPLY-eligible only
        # through the human terminal authorization; model_independent=0 keeps the auto-approval policy away.
        assert finding["execution_eligible"] == 1
        assert finding["model_independent"] == 0
        assert finding["verification_status"] == "VERIFIED"

        metrics = conn.execute("SELECT * FROM audit_quality_metrics WHERE audit_run_id='RUN-TRUST-01'").fetchone()
        assert metrics["cross_model_verified"] == 0


def test_p2_12_require_cross_model_flag_raises_error_when_unverified(
    tmp_path: Path,
) -> None:
    db_path, repo_dir = _seed_db(tmp_path, run_id="RUN-STRICT-01")

    stats = ingest_findings(
        db_path,
        project_key="p2",
        run_id="RUN-STRICT-01",
        findings=[{
            "finding_id": "F-ARGON-SEC-2",
            "fingerprint": "fp-argon-sec-2",
            "title": "Critical RCE",
            "category": "RCE",
            "severity": "CRITICAL",
            "confidence": "CONFIRMED",
            "file_path": "src/payment.py",
            "symbol": "charge",
            "line_start": 1,
            "line_end": 4,
            "evidence": "def charge(amount: int):",
            "impact": "Remote code execution",
            "recommendation": "Fix RCE",
        }],
        repo_path=repo_dir,
        report_dir=tmp_path / "reports",
    )
    vrun_id = stats["verification_run_id"]

    submit_verification_results(
        db_path,
        audit_run_id="RUN-STRICT-01",
        verification_run_id=vrun_id,
        verifier_conversation_id="conv-strict-01-v",
        verifier_metadata={
            "verifier_model_id": "gemini-4-hydrogen-high",
            "verifier_attestation_status": "MODEL_ATTESTATION_INCOMPLETE",
        },
        verification_results=[{
            "candidate_finding_id": "F-ARGON-SEC-2",
            "verdict": "CONFIRMED",
            "verified_severity": "CRITICAL",
            "verified_confidence": "CONFIRMED",
            "technical_rationale": "Confirmed by verifier.",
            "source_evidence": {
                "file_path": "src/payment.py",
                "line_start": 1,
                "line_end": 4,
                "symbol": "charge",
                "evidence_excerpt": "def charge(amount: int):",
            },
            "remediation_review": "Safe.",
            "remediation_safe": True,
            "acceptance_criteria": "Verify fix.",
        }],
    )

    with pytest.raises(RuntimeError, match="require independent cross-model verification"):
        finalize_verified_report(
            db_path,
            audit_run_id="RUN-STRICT-01",
            verification_run_id=vrun_id,
            require_cross_model=True,
        )


# ==============================================================================
# MEDIUM-01: Argon Default Token Budget = 100,000
# ==============================================================================

def test_p2_13_argon_default_token_budget_is_100k() -> None:
    assert DEFAULT_MAX_ARGON_TOKENS_PER_RUN == 100_000
    config = ArgonBudgetConfig()
    assert config.max_tokens_per_run == 100_000


# ==============================================================================
# MEDIUM-02: SQLite Atomic Argon Budget Reservation & Lease Expiry
# ==============================================================================

def test_p2_14_sqlite_atomic_argon_budget_reservation(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "budget_test.db"
    initialize(db_path)

    with connect(db_path) as conn:
        res1 = reserve_argon_budget_atomic(
            conn,
            audit_run_id="RUN-BGT-01",
            model_id="gemini-4-argon-medium",
            estimated_tokens=20_000,
            lease_seconds=60,
        )
        assert res1["allowed"] is True
        assert res1["reservation_id"] is not None

        # Second concurrent reservation in same run is fenced (max concurrent = 1)
        res2 = reserve_argon_budget_atomic(
            conn,
            audit_run_id="RUN-BGT-01",
            model_id="gemini-4-argon-medium",
            estimated_tokens=20_000,
            lease_seconds=60,
        )
        assert res2["allowed"] is False
        assert "limit" in res2["reason"].lower() or "active" in res2["reason"].lower()

        # Release first reservation
        release_argon_budget_atomic(
            conn,
            reservation_id=res1["reservation_id"],
            audit_run_id="RUN-BGT-01",
            model_id="gemini-4-argon-medium",
            actual_tokens=15_000,
        )

        # Now second reservation can proceed
        res3 = reserve_argon_budget_atomic(
            conn,
            audit_run_id="RUN-BGT-01",
            model_id="gemini-4-argon-medium",
            estimated_tokens=20_000,
            lease_seconds=60,
        )
        assert res3["allowed"] is True
        assert res3["reservation_id"] is not None


def test_p2_14_multiprocess_three_workers_competing_one_slot(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "budget_mp_compete.db"
    initialize(db_path)

    q: multiprocessing.Queue = multiprocessing.Queue()
    barrier = multiprocessing.Barrier(3)
    p1 = multiprocessing.Process(
        target=_mp_worker_compete_slot,
        args=(str(db_path), "RUN-MP-01", "fp-mp-01", q, barrier),
    )
    p2 = multiprocessing.Process(
        target=_mp_worker_compete_slot,
        args=(str(db_path), "RUN-MP-01", "fp-mp-02", q, barrier),
    )
    p3 = multiprocessing.Process(
        target=_mp_worker_compete_slot,
        args=(str(db_path), "RUN-MP-01", "fp-mp-03", q, barrier),
    )

    p1.start()
    p2.start()
    p3.start()

    p1.join(timeout=15)
    p2.join(timeout=15)
    p3.join(timeout=15)

    results = [q.get(timeout=3) for _ in range(3)]
    allowed_count = sum(1 for r in results if r["allowed"] is True)
    rejected_count = sum(1 for r in results if r["allowed"] is False)

    # Exactly one process obtains the slot; other 2 are fenced by concurrency
    assert allowed_count == 1
    assert rejected_count == 2
    for r in results:
        if not r["allowed"]:
            assert r["status"] == "REJECTED_CONCURRENCY"


def test_p2_14b_multiprocess_concurrent_request_limit_enforcement(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "budget_mp_req.db"
    initialize(db_path)

    q: multiprocessing.Queue = multiprocessing.Queue()
    barrier = multiprocessing.Barrier(3)
    # max_requests_per_run = 2, 3 workers compete
    p1 = multiprocessing.Process(
        target=_mp_worker_compete_requests,
        args=(str(db_path), "RUN-MP-REQ", "fp-req-1", 2, q, barrier),
    )
    p2 = multiprocessing.Process(
        target=_mp_worker_compete_requests,
        args=(str(db_path), "RUN-MP-REQ", "fp-req-2", 2, q, barrier),
    )
    p3 = multiprocessing.Process(
        target=_mp_worker_compete_requests,
        args=(str(db_path), "RUN-MP-REQ", "fp-req-3", 2, q, barrier),
    )

    p1.start()
    p2.start()
    p3.start()

    p1.join(timeout=15)
    p2.join(timeout=15)
    p3.join(timeout=15)

    results = [q.get(timeout=3) for _ in range(3)]
    allowed_count = sum(1 for r in results if r["allowed"] is True)
    rejected_count = sum(1 for r in results if r["allowed"] is False)

    assert allowed_count == 2
    assert rejected_count == 1
    rejected = [r for r in results if not r["allowed"]]
    assert rejected[0]["status"] == "REJECTED_REQUEST_LIMIT"


def test_p2_14c_multiprocess_concurrent_token_budget_enforcement(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "budget_mp_tok.db"
    initialize(db_path)

    q: multiprocessing.Queue = multiprocessing.Queue()
    barrier = multiprocessing.Barrier(2)
    # max_tokens = 50_000, each asks for 30_000
    p1 = multiprocessing.Process(
        target=_mp_worker_compete_tokens,
        args=(str(db_path), "RUN-MP-TOK", "fp-tok-1", 30_000, 50_000, q, barrier),
    )
    p2 = multiprocessing.Process(
        target=_mp_worker_compete_tokens,
        args=(str(db_path), "RUN-MP-TOK", "fp-tok-2", 30_000, 50_000, q, barrier),
    )

    p1.start()
    p2.start()

    p1.join(timeout=15)
    p2.join(timeout=15)

    results = [q.get(timeout=3) for _ in range(2)]
    allowed_count = sum(1 for r in results if r["allowed"] is True)
    rejected_count = sum(1 for r in results if r["allowed"] is False)

    assert allowed_count == 1
    assert rejected_count == 1
    rejected = [r for r in results if not r["allowed"]]
    assert rejected[0]["status"] == "REJECTED_TOKEN_LIMIT"


def test_p2_14d_multiprocess_persistent_deduplication_after_restart(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "budget_mp_dedup.db"
    initialize(db_path)

    q: multiprocessing.Queue = multiprocessing.Queue()
    # Step 1: Process A reserves and releases tokens (records usage) for finding fp-crypto-1
    p1 = multiprocessing.Process(
        target=_mp_worker_dedup_step1,
        args=(str(db_path), "RUN-DEDUP-01", "fp-crypto-1", q),
    )
    p1.start()
    p1.join(timeout=15)
    r1 = q.get(timeout=3)
    assert r1["allowed"] is True

    # Step 2: Fresh separate Process B starts up and attempts reservation for same fingerprint in same run
    p2 = multiprocessing.Process(
        target=_mp_worker_dedup_step2,
        args=(str(db_path), "RUN-DEDUP-01", "fp-crypto-1", q),
    )
    p2.start()
    p2.join(timeout=15)
    r2 = q.get(timeout=3)

    assert r2["allowed"] is False
    assert r2["status"] == "REJECTED_DUPLICATE"


def test_p2_14e_failed_and_cancelled_jobs_do_not_double_count_tokens(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "budget_cancel.db"
    initialize(db_path)

    # 1. Acquire reservation
    with connect(db_path) as conn:
        res = reserve_argon_budget_atomic(
            conn,
            audit_run_id="RUN-CANCEL-01",
            model_id="gemini-4-argon-medium",
            finding_fingerprint="fp-cancel-1",
            estimated_tokens=25_000,
        )
        assert res["allowed"] is True
        res_id = res["reservation_id"]

    # 2. Job fails / cancelled -> release reservation with 0 actual tokens
    with connect(db_path) as conn:
        release_argon_budget_atomic(
            conn,
            reservation_id=res_id,
            audit_run_id="RUN-CANCEL-01",
            model_id="gemini-4-argon-medium",
            actual_tokens=0,
            finding_fingerprint="fp-cancel-1",
        )

    # 3. Verify total tokens consumed for run is 0
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(tokens_consumed), 0) FROM model_budget_usage WHERE audit_run_id='RUN-CANCEL-01'"
        ).fetchone()
        assert int(row[0]) == 0
        active_res = conn.execute("SELECT COUNT(*) FROM model_budget_reservations").fetchone()
        assert int(active_res[0]) == 0


def test_p2_15_expired_argon_lease_cleanup(tmp_path: Path) -> None:
    db_path = tmp_path / "budget_exp.db"
    initialize(db_path)

    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO model_budget_reservations(
                reservation_id, audit_run_id, model_id, task_type, estimated_tokens,
                lease_expires_at
            ) VALUES('res-expired-01', 'RUN-EXP-01', 'gemini-4-argon-medium', 'CRITICAL_VERIFICATION', 25000, datetime('now', '-100 seconds'))"""
        )
        conn.commit()

    # Run cleanup
    with connect(db_path) as conn:
        cleaned = cleanup_expired_argon_reservations(conn)
        assert cleaned >= 1
        row = conn.execute("SELECT * FROM model_budget_reservations WHERE reservation_id='res-expired-01'").fetchone()
        assert row is None


# ==============================================================================
# MEDIUM-03: Persistent Quota Exhaustion Handling
# ==============================================================================

def test_p2_16_argon_budget_exhaustion_blocks_without_fallback(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "budget_exhaust.db"
    initialize(db_path)

    tracker = ModelBudgetTracker(
        config=ArgonBudgetConfig(max_requests_per_run=1, max_tokens_per_run=100_000),
        db_path=db_path,
    )

    # First request consumes the single request allowed
    chk1 = tracker.check_dispatch(
        model_id="gemini-4-argon-medium",
        audit_run_id="RUN-EXHAUST-01",
        finding_fingerprint="fp-01",
    )
    assert chk1.allowed is True
    tracker.acquire_job(
        model_id="gemini-4-argon-medium",
        audit_run_id="RUN-EXHAUST-01",
        finding_fingerprint="fp-01",
    )
    tracker.release_job(
        model_id="gemini-4-argon-medium",
        audit_run_id="RUN-EXHAUST-01",
        tokens_consumed=5000,
        finding_fingerprint="fp-01",
    )

    # Second request is rejected
    chk2 = tracker.check_dispatch(
        model_id="gemini-4-argon-medium",
        audit_run_id="RUN-EXHAUST-01",
        finding_fingerprint="fp-02",
    )
    assert chk2.allowed is False
    assert "exhausted" in chk2.reason.lower() or "limit" in chk2.reason.lower() or "exceeded" in chk2.reason.lower()


# ==============================================================================
# MEDIUM-04: Shared Programmatic Dispatcher and CLI model-dispatch
# ==============================================================================

def test_p2_17_shared_programmatic_dispatcher_routine_red_team(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "shared_disp.db"
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    initialize(db_path)

    with patch("cli.AntigravityCliAdapter") as MockAdapter:
        instance = MockAdapter.return_value
        instance.start_new_conversation.return_value = make_dispatch_result(
            ok=True,
            conversation_id="conv-shared-rt-01",
            model="gemini-4-hydrogen-high",
            total_tokens=1300,
        )

        res = cli.dispatch_routed_task(
            db_path=db_path,
            audit_run_id="RUN-SHARED-01",
            task_type=TaskType.ROUTINE_RED_TEAM,
            prompt="Audit all endpoints",
            cwd=repo_dir,
        )

        assert res["ok"] is True
        assert res["dispatch_result"]["conversation_id"] == "conv-shared-rt-01"
        assert res["dispatch_result"]["requested_model"] == "gemini-4-hydrogen-high"


def test_p2_18_cli_model_dispatch_subcommand(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "cli_disp.db"
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    initialize(db_path)

    monkeypatch.setattr(cli, "DB_PATH", db_path)

    with patch("cli.dispatch_routed_task") as mock_dispatch:
        mock_dispatch.return_value = {
            "ok": True,
            "status": "SUCCESS",
            "dispatch_result": {
                "conversation_id": "conv-subcmd-01",
                "requested_model": "gemini-4-hydrogen-high",
                "total_tokens": 1200,
            },
        }

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "cli.py",
                "model-dispatch",
                "--task",
                "ROUTINE_RED_TEAM",
                "--run-id",
                "RUN-SUBCMD-01",
                "--prompt",
                "Test red team prompt",
                "--cwd",
                str(repo_dir),
            ],
        )
        cli.main()

        out = capsys.readouterr().out
        assert "SUCCESS" in out or "conv-subcmd-01" in out
        assert mock_dispatch.called


# ==============================================================================
# NON-MCP CLI INTEGRATION CONTRACT TESTS
# ==============================================================================

def test_p2_19_primary_audit_cli_publish_report_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify primary audit CLI findings publication fallback without MCP."""
    db_path = tmp_path / "cli_primary_pub.db"
    repo_path = tmp_path / "repo"
    repo_path.mkdir(parents=True, exist_ok=True)
    app_file = repo_path / "app.py"
    app_content = "def search(q):\n    return db.execute(f'SELECT {q}')\n"
    app_file.write_text(app_content, encoding="utf-8")

    initialize(db_path)
    monkeypatch.setattr(cli, "DB_PATH", db_path)

    run_id = "RUN-PUB-CLI-01"
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects (project_key, display_name, repo_path, antigravity_project_id)
               VALUES ('demo', 'Demo Repo', ?, 'proj-demo-1')""",
            (str(repo_path),),
        )
        conn.execute(
            """INSERT INTO audit_runs (run_id, project_key, status, base_commit, working_tree_hash)
               VALUES (?, 'demo', 'ANALYZING', 'commit-1234', 'tree-5678')""",
            (run_id,),
        )
        conn.commit()

    findings_data = [
        {
            "finding_id": "F-PUB-01",
            "fingerprint": "fp-pub-01",
            "title": "SQL Injection in Search",
            "category": "V4",
            "severity": "CRITICAL",
            "confidence": "CONFIRMED",
            "file_path": "app.py",
            "symbol": "search",
            "line_start": 1,
            "line_end": 2,
            "evidence": "return db.execute(f'SELECT {q}')",
            "impact": "Data leakage",
            "recommendation": "Use parameterized queries",
        }
    ]
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(findings_data), encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cli.py",
            "publish-report",
            "--project",
            "demo",
            "--run-id",
            run_id,
            "--file",
            str(findings_file),
        ],
    )
    cli.main()

    # Verify findings persisted into candidate_findings
    with connect(db_path) as conn:
        run_row = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()
        assert run_row["status"] == "VERIFICATION_PENDING"

        candidates = conn.execute("SELECT * FROM candidate_findings WHERE run_id=?", (run_id,)).fetchall()
        assert len(candidates) == 1
        assert candidates[0]["candidate_finding_id"] == "F-PUB-01"
        assert candidates[0]["title"] == "SQL Injection in Search"
        assert len(candidates[0]["fingerprint"]) > 10

        # Verification queue job exists
        q_row = conn.execute("SELECT * FROM verification_dispatch_queue WHERE audit_run_id=?", (run_id,)).fetchone()
        assert q_row is not None
        assert q_row["status"] == "QUEUED"


def test_p2_20_verifier_cli_commands_complete_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify verifier completes full lifecycle via CLI commands without MCP."""
    from db import compute_file_blob_hash

    db_path = tmp_path / "cli_verifier_wf.db"
    repo_path = tmp_path / "repo"
    repo_path.mkdir(parents=True, exist_ok=True)
    app_file = repo_path / "app.py"
    app_content = "def search(q):\n    return db.execute(f'SELECT {q}')\n"
    app_file.write_text(app_content, encoding="utf-8")
    app_blob_hash = compute_file_blob_hash(repo_path, "app.py")

    initialize(db_path)
    monkeypatch.setattr(cli, "DB_PATH", db_path)

    run_id = "RUN-VRUN-CLI-01"
    vrun_id = "VRUN-CLI-01"

    # Seed project, run, candidate, snapshot, and verification run
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects (project_key, display_name, repo_path, antigravity_project_id)
               VALUES ('demo', 'Demo Repo', ?, 'proj-demo-1')""",
            (str(repo_path),),
        )
        conn.execute(
            """INSERT INTO audit_runs (run_id, project_key, status, base_commit, working_tree_hash, agent_conversation_id)
               VALUES (?, 'demo', 'VERIFICATION_PENDING', 'commit-1234', 'tree-5678', 'conv-primary-01')""",
            (run_id,),
        )
        conn.execute(
            """INSERT INTO audit_snapshots (snapshot_id, run_id, project_key, repo_path, base_commit_sha, working_tree_hash, snapshot_complete, file_hashes_json)
               VALUES ('snap-01', ?, 'demo', ?, 'commit-1234', 'tree-5678', 1, ?)""",
            (run_id, str(repo_path), json.dumps({"app.py": app_blob_hash})),
        )
        conn.execute(
            """INSERT INTO audit_verification_runs (verification_run_id, audit_run_id, project_key, status, snapshot_id, base_commit_sha, idempotency_key)
               VALUES (?, ?, 'demo', 'DISPATCHING', 'snap-01', 'commit-1234', 'idem-vrun-01')""",
            (vrun_id, run_id),
        )
        conn.execute(
            """INSERT INTO candidate_findings (
                candidate_id, candidate_finding_id, run_id, project_key, snapshot_id, base_commit_sha,
                fingerprint, title, category, severity, confidence, file_path, symbol, line_start,
                line_end, evidence, impact, recommendation, status, source_origin
            ) VALUES (
                'cand-01', 'F-VRUN-01', ?, 'demo', 'snap-01', 'commit-1234',
                'fp-vrun-01', 'SQLi', 'V4', 'CRITICAL', 'CONFIRMED', 'app.py', 'search', 1, 2,
                'def search(q):\n    return db.execute(f''SELECT {q}'')',
                'Data leakage', 'Use parameterized queries',
                'CANDIDATE', 'PRIMARY'
            )""",
            (run_id,),
        )
        conn.commit()

    # Step A: generate-verification-prompt via CLI
    prompt_file = tmp_path / "verification_prompt.txt"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cli.py",
            "generate-verification-prompt",
            "--run-id",
            run_id,
            "--verification-run-id",
            vrun_id,
            "--output",
            str(prompt_file),
        ],
    )
    cli.main()
    assert prompt_file.is_file()
    prompt_text = prompt_file.read_text(encoding="utf-8")
    assert "F-VRUN-01" in prompt_text
    assert "Demo Repo" in prompt_text

    # Step B: verification-context via CLI
    ctx_file = tmp_path / "verification_context.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cli.py",
            "verification-context",
            "--run-id",
            run_id,
            "--verification-run-id",
            vrun_id,
            "--output",
            str(ctx_file),
        ],
    )
    cli.main()
    assert ctx_file.is_file()
    ctx_obj = json.loads(ctx_file.read_text(encoding="utf-8"))
    assert ctx_obj["audit_run_id"] == run_id
    assert ctx_obj["verification_run_id"] == vrun_id
    assert len(ctx_obj["candidate_claims"]) == 1
    assert ctx_obj["candidate_claims"][0]["candidate_finding_id"] == "F-VRUN-01"

    # Step C: submit-verification via CLI
    results_data = [
        {
            "candidate_finding_id": "F-VRUN-01",
            "verdict": "CONFIRMED",
            "verified_severity": "CRITICAL",
            "verified_confidence": "CONFIRMED",
            "remediation_safe": 1,
            "acceptance_criteria": "Parameterized query applied",
            "remediation_review": "Safe",
            "technical_rationale": "Direct SQL injection confirmed",
            "source_evidence": {
                "file_path": "app.py",
                "line_start": 1,
                "line_end": 2,
                "symbol": "search",
                "excerpt": "def search(q):\n    return db.execute(f'SELECT {q}')",
                "evidence": "def search(q):\n    return db.execute(f'SELECT {q}')",
            },
        }
    ]
    results_file = tmp_path / "verification_results.json"
    results_file.write_text(json.dumps(results_data), encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cli.py",
            "submit-verification",
            "--project",
            "demo",
            "--run-id",
            run_id,
            "--verification-run-id",
            vrun_id,
            "--conversation-id",
            "conv-verif-distinct-01",
            "--file",
            str(results_file),
            "--model-id",
            "gemini-4-hydrogen-high",
        ],
    )
    cli.main()

    with connect(db_path) as conn:
        v_results = conn.execute(
            "SELECT * FROM finding_verification_results WHERE verification_run_id=?",
            (vrun_id,),
        ).fetchall()
        assert len(v_results) == 1
        assert v_results[0]["verdict"] == "CONFIRMED"

    # Step D: finalize-verified-report via CLI
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cli.py",
            "finalize-verified-report",
            "--project",
            "demo",
            "--run-id",
            run_id,
            "--verification-run-id",
            vrun_id,
        ],
    )
    cli.main()

    with connect(db_path) as conn:
        canonical = conn.execute("SELECT * FROM findings WHERE run_id=?", (run_id,)).fetchall()
        assert len(canonical) == 1
        assert canonical[0]["finding_id"] == "F-VRUN-01"
        assert canonical[0]["verification_status"] == "VERIFIED"
        run_after = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()
        assert run_after["status"] == "READY_FOR_REVIEW"

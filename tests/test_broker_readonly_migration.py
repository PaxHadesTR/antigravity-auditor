"""Comprehensive Test Suite for NEXT-21C-B1 Read-Only Consumer Migration.

Validates the typed Broker RPC read methods, target consumer migration (mcp_server,
review, verification), strict schema validation, AST zero-connect verification,
fail-closed error handling, and exact parity with legacy SQLite implementations.
"""

from __future__ import annotations

import ast
import json
import os
import sqlite3
import sys
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from broker.audit_logger import BrokerAuditLogger
from broker.client import BrokerClient
from broker.constants import (
    ALLOWED_SORT_COLUMNS,
    ALLOWED_SORT_DIRECTIONS,
    DEFAULT_QUERY_LIMIT,
    ERR_ACCESS_DENIED,
    ERR_DATABASE_ERROR,
    ERR_METHOD_NOT_IMPLEMENTED,
    ERR_NOT_IMPLEMENTED,
    ERR_PRODUCTION_DB_ACCESS_PROHIBITED,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    MAX_QUERY_LIMIT,
    METHOD_GET_CONTEXT,
    METHOD_GET_QUALITY_REPORT,
    METHOD_GET_REVIEW_CONTEXT,
    METHOD_GET_STATUS,
    METHOD_GET_VERIFICATION_CONTEXT,
    METHOD_GET_VERIFICATION_STATUS,
    METHOD_GET_VERIFIER_WORKER_STATUS,
    METHOD_LIST_FINDINGS,
    PROTOCOL_VERSION,
    TEST_PIPE_PREFIX,
)
from broker.db_adapter import BrokerDatabaseAdapter
from broker.dispatcher import BrokerDispatcher
from broker.exceptions import (
    BrokerAuthError,
    BrokerDatabaseError,
    BrokerError,
    BrokerSchemaError,
    BrokerTimeoutError,
    BrokerUnavailableError,
    MethodNotImplementedError,
    ProductionDatabaseAccessProhibitedError,
)
from broker.protocol import (
    JsonRpcRequest,
    decode_frame_header,
    encode_frame,
    make_error_response,
    parse_request_bytes,
)
from broker.security import ClientIdentity, is_windows
from broker.service_host import BrokerServiceConfig, BrokerServiceHost
from broker.transport import MemoryPipeTransport, WindowsNamedPipeServer
from db import connect, initialize
from mcp_server import AuditorMCPDispatcher
from review import (
    generate_review_report,
    generate_review_report_broker,
    list_project_findings,
    list_project_findings_broker,
)
from verification import (
    build_verification_prompt,
    build_verification_prompt_broker,
    get_quality_report,
    get_quality_report_broker,
    get_verification_context,
    get_verification_context_broker,
    get_verification_status,
    get_verification_status_broker,
    get_verifier_worker_status,
    get_verifier_worker_status_broker,
)


@pytest.fixture
def populated_auditor_env(tmp_path: Path) -> dict[str, Any]:
    """Provide a fully populated isolated test database and broker fixture."""
    db_file = tmp_path / "test_auditor_populated.db"
    repo_dir = tmp_path / "repo_alpha"
    (repo_dir / "src").mkdir(parents=True, exist_ok=True)
    (repo_dir / "src" / "main.py").write_text("print('hello')", encoding="utf-8")

    initialize(db_file)
    with connect(db_file) as conn:
        # 1. Project
        conn.execute(
            """INSERT INTO projects (project_key, display_name, repo_path, antigravity_project_id, health_status)
               VALUES (?, ?, ?, ?, ?)""",
            ("alpha", "Alpha Project", str(repo_dir), "proj-alpha-001", "HEALTHY"),
        )

        # 2. Audit Run
        conn.execute(
            """INSERT INTO audit_runs (run_id, project_key, status, base_commit, working_tree_hash, started_at, finished_at)
               VALUES (?, ?, ?, ?, ?, datetime('now', '-1 hour'), datetime('now', '-30 minutes'))""",
            ("RUN-B1-001", "alpha", "READY_FOR_REVIEW", "commit-aaa-111", "tree-bbb-222"),
        )

        # 3. Canonical Findings
        conn.execute(
            """INSERT INTO findings (
                   finding_id, project_key, run_id, fingerprint, title, category,
                   severity, confidence, file_path, symbol, line_start, line_end,
                   evidence, impact, recommendation, evidence_hash, file_blob_hash,
                   first_seen_run_id, last_seen_run_id, lifecycle, verification_status,
                   execution_eligible, remediation_safe, created_at, updated_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            (
                "SAB-F001", "alpha", "RUN-B1-001", "fp-sab-001", "SQL Injection Vulnerability", "SECURITY",
                "CRITICAL", "CONFIRMED", "src/main.py", "query_db", 10, 15,
                "Unparameterized raw string formatting in SQL query", "Remote code execution or data exfiltration",
                "Use parameterized SQL query placeholders", "ev-hash-1", "blob-hash-1",
                "RUN-B1-001", "RUN-B1-001", "OPEN", "VERIFIED",
                1, 1,
            ),
        )
        conn.execute(
            """INSERT INTO findings (
                   finding_id, project_key, run_id, fingerprint, title, category,
                   severity, confidence, file_path, symbol, line_start, line_end,
                   evidence, impact, recommendation, evidence_hash, file_blob_hash,
                   first_seen_run_id, last_seen_run_id, lifecycle, verification_status,
                   execution_eligible, remediation_safe, created_at, updated_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            (
                "SAB-F002", "alpha", "RUN-B1-001", "fp-sab-002", "Hardcoded API Secret", "SECURITY",
                "HIGH", "LIKELY", "src/config.py", "SECRET_KEY", 5, 5,
                "Secret token committed in source code", "Credential compromise",
                "Load secret from environment variable", "ev-hash-2", "blob-hash-2",
                "RUN-B1-001", "RUN-B1-001", "OPEN", "VERIFIED",
                0, 1,
            ),
        )
        conn.execute(
            """INSERT INTO findings (
                   finding_id, project_key, run_id, fingerprint, title, category,
                   severity, confidence, file_path, symbol, line_start, line_end,
                   evidence, impact, recommendation, evidence_hash, file_blob_hash,
                   first_seen_run_id, last_seen_run_id, lifecycle, verification_status,
                   execution_eligible, remediation_safe, created_at, updated_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))""",
            (
                "SAB-F003", "alpha", "RUN-B1-001", "fp-sab-003", "Missing docstring", "STYLE",
                "LOW", "SPECULATIVE", "src/util.py", "helper", 1, 1,
                "No docstring", "Maintainability impact",
                "Add docstring", "ev-hash-3", "blob-hash-3",
                "RUN-B1-001", "RUN-B1-001", "DISMISSED", "VERIFIED",
                0, 1,
            ),
        )

        # 4. Decisions
        conn.execute(
            """INSERT INTO decisions (finding_id, run_id, decision, note, actor, superseded)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("SAB-F001", "RUN-B1-001", "APPLY", "Approved for isolated repair", "auditor-lead", 0),
        )

        # 5. Candidate Findings
        conn.execute(
            """INSERT INTO candidate_findings (
                   candidate_finding_id, project_key, run_id, fingerprint, title, category,
                   severity, confidence, file_path, symbol, line_start, line_end,
                   evidence, impact, recommendation, evidence_sha256, file_sha256,
                   source_origin, status, snapshot_id, base_commit_sha
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "CAND-001", "alpha", "RUN-B1-001", "fp-cand-001", "Candidate Buffer Overflow", "SECURITY",
                "HIGH", "CONFIRMED", "src/buffer.c", "copy_buf", 20, 25,
                "strcpy without bounds check", "Memory corruption", "Use strncpy", "c-ev-1", "c-file-1",
                "PRIMARY", "CONFIRMED", "SNAP-001", "commit-aaa-111",
            ),
        )
        conn.execute(
            """INSERT INTO candidate_findings (
                   candidate_finding_id, project_key, run_id, fingerprint, title, category,
                   severity, confidence, file_path, symbol, line_start, line_end,
                   evidence, impact, recommendation, evidence_sha256, file_sha256,
                   source_origin, status, snapshot_id, base_commit_sha
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "CAND-002", "alpha", "RUN-B1-001", "fp-cand-002", "Hallucinated Race Condition", "CONCURRENCY",
                "MEDIUM", "SPECULATIVE", "src/thread.py", "run_worker", 40, 50,
                "Claimed race condition", "Theoretical deadlock", "Add lock", "c-ev-2", "c-file-2",
                "PRIMARY", "REJECTED", "SNAP-001", "commit-aaa-111",
            ),
        )

        # 6. Verification Run & Results
        conn.execute(
            """INSERT INTO audit_verification_runs (
                   verification_run_id, audit_run_id, project_key, status, verifier_conversation_id,
                   snapshot_id, base_commit_sha, idempotency_key, created_at, completed_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-25 minutes'), datetime('now', '-20 minutes'))""",
            ("VRUN-B1-001", "RUN-B1-001", "alpha", "FINALIZED", "conv-verifier-1234", "SNAP-001", "commit-aaa-111", "idem-vrun-001"),
        )
        conn.execute(
            """INSERT INTO finding_verification_results (
                   audit_run_id, verification_run_id, candidate_finding_id, verdict,
                   verified_severity, verified_confidence, technical_rationale,
                   source_evidence_json, remediation_review, acceptance_criteria,
                   evidence_validation_status, remediation_safe
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "RUN-B1-001", "VRUN-B1-001", "CAND-001", "CONFIRMED", "HIGH", "CONFIRMED",
                "Verified in buffer.c", "{}", "Safe fix", "Unit tests pass", "PASSED", 1,
            ),
        )
        conn.execute(
            """INSERT INTO finding_verification_results (
                   audit_run_id, verification_run_id, candidate_finding_id, verdict,
                   verified_severity, verified_confidence, technical_rationale,
                   source_evidence_json, remediation_review, acceptance_criteria,
                   evidence_validation_status, remediation_safe
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "RUN-B1-001", "VRUN-B1-001", "CAND-002", "REJECTED", "MEDIUM", "SPECULATIVE",
                "Falsified by mutex on line 38", "{}", "Unsafe proposal", "Regression test", "PASSED", 0,
            ),
        )

        # 7. Snapshot
        conn.execute(
            """INSERT INTO audit_snapshots (
                   snapshot_id, run_id, project_key, repo_path, base_commit_sha, working_tree_hash, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
            ("SNAP-001", "RUN-B1-001", "alpha", str(repo_dir), "commit-aaa-111", "tree-bbb-222"),
        )

        # 8. Execution Approval
        conn.execute(
            """INSERT INTO execution_approvals (
                   approval_id, project_key, run_id, approval_token, approved_finding_ids,
                   base_commit, working_tree_hash, status, authorized_by, expires_at, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+1 hour'), datetime('now'))""",
            (
                "APPR-001", "alpha", "RUN-B1-001", "tok-appr-001", '["SAB-F001"]',
                "commit-aaa-111", "tree-bbb-222", "AUTHORIZED", "lead-engineer",
            ),
        )

        # 9. Verification Dispatch Queue
        conn.execute(
            """INSERT INTO verification_dispatch_queue (
                   job_id, verification_run_id, project_key, audit_run_id, snapshot_id,
                   status, idempotency_key, attempt_count, max_attempts, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            ("JOB-001", "VRUN-B1-001", "alpha", "RUN-B1-001", "SNAP-001", "COMPLETED", "idem-job-001", 1, 3),
        )

        # 10. Audit Quality Metrics
        conn.execute(
            """INSERT INTO audit_quality_metrics (
                   audit_run_id, project_key, total_primary_candidates, verifier_discovered_candidates,
                   confirmed_findings, partially_confirmed_findings, rejected_findings, unverifiable_findings,
                   evidence_validation_failures, fabricated_reference_detections, severity_changes,
                   confidence_changes, remediation_proposals_rejected, dispatch_failures,
                   actual_subagent_invocations, finding_precision, evidence_accuracy, false_positive_rate,
                   severity_calibration_rate, remediation_safety_rate, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (
                "RUN-B1-001", "alpha", 2, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
                0.5, 1.0, 0.5, 1.0, 1.0,
            ),
        )

        # 11. Audit Events
        conn.execute(
            """INSERT INTO audit_events (project_key, run_id, event_type, details, created_at)
               VALUES (?, ?, ?, ?, datetime('now'))""",
            ("alpha", "RUN-B1-001", "TEST_EVENT", '{"msg": "test event"}'),
        )
        conn.commit()

    # Configure Broker Components
    log_file = tmp_path / "broker_test_audit.log"
    logger = BrokerAuditLogger(log_file=log_file)
    adapter = BrokerDatabaseAdapter(db_path=db_file)
    dispatcher = BrokerDispatcher(db_adapter=adapter, audit_logger=logger)
    transport = MemoryPipeTransport(dispatcher=dispatcher)
    client = BrokerClient(transport=transport)

    return {
        "db_path": db_file,
        "repo_dir": repo_dir,
        "client": client,
        "dispatcher": dispatcher,
        "adapter": adapter,
        "transport": transport,
        "tmp_path": tmp_path,
    }


# ==============================================================================
# Group 1: Typed Read RPC Success Scenarios (8 methods)
# ==============================================================================


def test_rpc_get_context_success(populated_auditor_env: dict[str, Any]) -> None:
    """Verify broker.get_context retrieves project context, latest run, and counts."""
    client: BrokerClient = populated_auditor_env["client"]
    res = client.get_context("alpha")
    assert isinstance(res, dict)
    assert res["project"]["project_key"] == "alpha"
    assert res["project"]["display_name"] == "Alpha Project"
    assert res["latest_run"]["run_id"] == "RUN-B1-001"
    assert "finding_counts" in res
    assert res["finding_counts"].get("OPEN") == 2
    assert res["finding_counts"].get("DISMISSED") == 1
    assert isinstance(res["recent_history"], list)


def test_rpc_list_findings_success(populated_auditor_env: dict[str, Any]) -> None:
    """Verify broker.list_findings retrieves canonical and candidate findings."""
    client: BrokerClient = populated_auditor_env["client"]
    findings = client.list_findings("alpha", include_candidates=True, include_dismissed=True)
    assert isinstance(findings, list)
    finding_ids = [f["finding_id"] for f in findings]
    assert "SAB-F001" in finding_ids
    assert "SAB-F002" in finding_ids
    assert "SAB-F003" in finding_ids
    assert "CAND-001" in finding_ids

    # Check active decision attachment
    sab1 = next(f for f in findings if f["finding_id"] == "SAB-F001")
    assert sab1["active_decision"] == "APPLY"
    assert sab1["decision_note"] == "Approved for isolated repair"


def test_rpc_get_review_context_success(populated_auditor_env: dict[str, Any]) -> None:
    """Verify broker.get_review_context retrieves review prerequisites."""
    client: BrokerClient = populated_auditor_env["client"]
    ctx = client.get_review_context("alpha", "RUN-B1-001")
    assert ctx["project"]["project_key"] == "alpha"
    assert ctx["audit_run"]["run_id"] == "RUN-B1-001"
    assert ctx["verification_run"]["verification_run_id"] == "VRUN-B1-001"
    assert ctx["active_approval"]["approval_id"] == "APPR-001"
    assert ctx["active_approval"]["status"] == "AUTHORIZED"


def test_rpc_get_verification_context_success(populated_auditor_env: dict[str, Any]) -> None:
    """Verify broker.get_verification_context retrieves context-independent claims."""
    client: BrokerClient = populated_auditor_env["client"]
    v_ctx = client.get_verification_context("RUN-B1-001", "VRUN-B1-001")
    assert v_ctx["audit_run_id"] == "RUN-B1-001"
    assert v_ctx["verification_run_id"] == "VRUN-B1-001"
    assert v_ctx["project_context"]["project_key"] == "alpha"
    assert "candidate_claims" in v_ctx
    assert "snapshot_metadata" in v_ctx
    assert v_ctx["snapshot_metadata"]["snapshot_id"] == "SNAP-001"


def test_rpc_get_verification_status_success(populated_auditor_env: dict[str, Any]) -> None:
    """Verify broker.get_verification_status retrieves verification lifecycle metrics."""
    client: BrokerClient = populated_auditor_env["client"]
    v_st = client.get_verification_status("RUN-B1-001", "VRUN-B1-001")
    assert v_st["audit_run_id"] == "RUN-B1-001"
    assert v_st["verification_run_id"] == "VRUN-B1-001"
    assert v_st["confirmed_count"] == 1
    assert v_st["rejected_count"] == 1
    assert "verification_trust" in v_st
    assert "dispatch_info" in v_st


def test_rpc_get_status_success(populated_auditor_env: dict[str, Any]) -> None:
    """Verify broker.get_status retrieves project status and recent events."""
    client: BrokerClient = populated_auditor_env["client"]
    # With project key
    st_proj = client.get_status("alpha")
    assert len(st_proj["projects"]) == 1
    assert st_proj["projects"][0]["project_key"] == "alpha"
    assert len(st_proj["recent_events"]) >= 1

    # Without project key (all projects)
    st_all = client.get_status(None)
    assert len(st_all["projects"]) >= 1


def test_rpc_get_verifier_worker_status_success(populated_auditor_env: dict[str, Any]) -> None:
    """Verify broker.get_verifier_worker_status retrieves queue jobs."""
    client: BrokerClient = populated_auditor_env["client"]
    w_st = client.get_verifier_worker_status("alpha")
    assert len(w_st["projects"]) == 1
    assert len(w_st["jobs"]) >= 1
    assert w_st["jobs"][0]["job_id"] == "JOB-001"


def test_rpc_get_quality_report_success(populated_auditor_env: dict[str, Any]) -> None:
    """Verify broker.get_quality_report retrieves metrics and computed summary."""
    client: BrokerClient = populated_auditor_env["client"]
    qr = client.get_quality_report("alpha", "RUN-B1-001")
    assert qr["run_count"] == 1
    assert qr["summary"]["confirmed_findings"] == 1
    assert qr["summary"]["rejected_findings"] == 1
    assert len(qr["history"]) == 1


# ==============================================================================
# Group 2: Security Boundaries & Rejection Scenarios (8 tests)
# ==============================================================================


def test_rejection_low_integrity_worker(populated_auditor_env: dict[str, Any]) -> None:
    """Verify that clients with Low Integrity Level are strictly rejected."""
    dispatcher: BrokerDispatcher = populated_auditor_env["dispatcher"]
    req = JsonRpcRequest(id="low-sec-1", method=METHOD_GET_CONTEXT, params={"project_key": "alpha"})
    low_client = ClientIdentity(
        pid=9999,
        sid="S-1-16-4096",
        integrity_level="LOW",
        is_low_integrity=True,
        verified_by_os=True,
    )

    resp = dispatcher.dispatch(req, low_client)
    assert resp.error is not None
    assert resp.error["code"] == ERR_ACCESS_DENIED
    assert "Low-Integrity" in resp.error["message"]


def test_rejection_client_supplied_db_path(populated_auditor_env: dict[str, Any]) -> None:
    """Verify client-supplied database paths are immediately rejected."""
    client: BrokerClient = populated_auditor_env["client"]
    with pytest.raises(BrokerSchemaError) as exc_info:
        client.invoke(METHOD_GET_CONTEXT, {"project_key": "alpha", "db_path": "C:\\evil.db"})
    assert "Client-selected database paths are strictly prohibited" in str(exc_info.value)


def test_rejection_arbitrary_sql_injection(populated_auditor_env: dict[str, Any]) -> None:
    """Verify arbitrary SQL methods and query injections are strictly denied."""
    client: BrokerClient = populated_auditor_env["client"]
    with pytest.raises(BrokerAuthError) as exc_info:
        client.invoke("broker.execute_sql", {"sql": "DROP TABLE projects;"})
    assert "Arbitrary SQL execution over IPC is strictly prohibited" in str(exc_info.value)


def test_rejection_unimplemented_governance_methods(populated_auditor_env: dict[str, Any]) -> None:
    """Verify that state-mutating governance methods remain gated with NOT_IMPLEMENTED (-32000)."""
    client: BrokerClient = populated_auditor_env["client"]
    mutating_methods = [
        "broker.approve_execution",
        "broker.authorize_execution",
        "broker.start_execution",
        "broker.ingest_findings",
        "broker.save_decisions",
        "broker.submit_verification",
        "broker.finalize_verification",
        "broker.finalize_verified_report",
    ]
    for method in mutating_methods:
        with pytest.raises(MethodNotImplementedError) as exc_info:
            client.invoke(method, {"dummy": "value"})
        assert exc_info.value.code == ERR_NOT_IMPLEMENTED


def test_rejection_invalid_params_schema(populated_auditor_env: dict[str, Any]) -> None:
    """Verify parameter schema errors for missing or ill-typed arguments."""
    client: BrokerClient = populated_auditor_env["client"]

    # Missing required project_key
    with pytest.raises(BrokerSchemaError) as exc_info:
        client.invoke(METHOD_GET_CONTEXT, {})
    assert "Parameter 'project_key' is required" in str(exc_info.value)

    # Empty project_key
    with pytest.raises(BrokerSchemaError) as exc_info:
        client.invoke(METHOD_GET_CONTEXT, {"project_key": "   "})
    assert "Parameter 'project_key' is required" in str(exc_info.value)

    # Limit exceeds maximum query limit
    with pytest.raises(BrokerSchemaError) as exc_info:
        client.invoke(METHOD_LIST_FINDINGS, {"project_key": "alpha", "limit": 99999})
    assert "Parameter 'limit' must be an integer between 1 and 1000" in str(exc_info.value)

    # Negative offset
    with pytest.raises(BrokerSchemaError) as exc_info:
        client.invoke(METHOD_LIST_FINDINGS, {"project_key": "alpha", "offset": -5})
    assert "Parameter 'offset' must be a non-negative integer" in str(exc_info.value)


def test_rejection_invalid_order_by_column(populated_auditor_env: dict[str, Any]) -> None:
    """Verify SQL injection attempt via order_by column is rejected by allowlist."""
    client: BrokerClient = populated_auditor_env["client"]
    with pytest.raises(BrokerSchemaError) as exc_info:
        client.invoke(METHOD_LIST_FINDINGS, {"project_key": "alpha", "order_by": "password; DROP TABLE findings;"})
    assert "Parameter 'order_by' must be one of" in str(exc_info.value)


def test_rejection_unknown_rpc_method(populated_auditor_env: dict[str, Any]) -> None:
    """Verify non-existent methods return JSONRPC_METHOD_NOT_FOUND (-32601)."""
    client: BrokerClient = populated_auditor_env["client"]
    with pytest.raises(MethodNotImplementedError) as exc_info:
        client.invoke("broker.undefined_rpc_call", {})
    assert exc_info.value.code == JSONRPC_METHOD_NOT_FOUND


def test_rejection_production_database_path() -> None:
    """Verify that pointing broker database adapter at production database is strictly prohibited."""
    with pytest.raises(ProductionDatabaseAccessProhibitedError):
        BrokerDatabaseAdapter(db_path=Path("C:\\Users\\test\\AppData\\Local\\AntigravityAuditor\\auditor.db"))

    with pytest.raises(ProductionDatabaseAccessProhibitedError):
        BrokerDatabaseAdapter(db_path=Path("C:\\ProgramData\\AntigravityAuditor\\auditor.db"))


# ==============================================================================
# Group 3: Target Consumer Migration & Exact Parity (6 tests)
# ==============================================================================


def test_review_list_project_findings_parity(populated_auditor_env: dict[str, Any]) -> None:
    """Verify exact parity between legacy direct SQLite list_project_findings and broker-mediated list."""
    db_path: Path = populated_auditor_env["db_path"]
    client: BrokerClient = populated_auditor_env["client"]

    legacy = list_project_findings(
        db_path,
        project_key="alpha",
        include_dismissed=True,
        include_candidates=True,
    )
    broker_res = list_project_findings(
        broker_client=client,
        project_key="alpha",
        include_dismissed=True,
        include_candidates=True,
    )

    assert len(legacy) == len(broker_res)
    for leg_item, brk_item in zip(legacy, broker_res):
        assert leg_item["finding_id"] == brk_item["finding_id"]
        assert leg_item["severity"] == brk_item["severity"]
        assert leg_item["confidence"] == brk_item["confidence"]
        assert leg_item["lifecycle"] == brk_item["lifecycle"]
        assert leg_item["active_decision"] == brk_item["active_decision"]
        assert leg_item["execution_eligible"] == brk_item["execution_eligible"]


def test_review_generate_review_report_parity(populated_auditor_env: dict[str, Any]) -> None:
    """Verify exact markdown parity between legacy direct generate_review_report and broker report."""
    db_path: Path = populated_auditor_env["db_path"]
    client: BrokerClient = populated_auditor_env["client"]

    legacy_md = generate_review_report(db_path, project_key="alpha", run_id="RUN-B1-001")
    broker_md = generate_review_report(broker_client=client, project_key="alpha", run_id="RUN-B1-001")

    assert legacy_md == broker_md
    assert "Antigravity Audit Review Report" in broker_md
    assert "SAB-F001" in broker_md
    assert "SQL Injection Vulnerability" in broker_md


def test_verification_context_parity(populated_auditor_env: dict[str, Any]) -> None:
    """Verify parity of get_verification_context between direct DB and Broker IPC."""
    db_path: Path = populated_auditor_env["db_path"]
    client: BrokerClient = populated_auditor_env["client"]

    legacy_ctx = get_verification_context(db_path, audit_run_id="RUN-B1-001", verification_run_id="VRUN-B1-001")
    broker_ctx = get_verification_context(broker_client=client, audit_run_id="RUN-B1-001", verification_run_id="VRUN-B1-001")

    assert legacy_ctx["audit_run_id"] == broker_ctx["audit_run_id"]
    assert legacy_ctx["verification_run_id"] == broker_ctx["verification_run_id"]
    assert legacy_ctx["snapshot_metadata"] == broker_ctx["snapshot_metadata"]
    assert len(legacy_ctx["candidate_claims"]) == len(broker_ctx["candidate_claims"])


def test_verification_status_parity(populated_auditor_env: dict[str, Any]) -> None:
    """Verify parity of get_verification_status between direct DB and Broker IPC."""
    db_path: Path = populated_auditor_env["db_path"]
    client: BrokerClient = populated_auditor_env["client"]

    legacy_st = get_verification_status(db_path, audit_run_id="RUN-B1-001", verification_run_id="VRUN-B1-001")
    broker_st = get_verification_status(broker_client=client, audit_run_id="RUN-B1-001", verification_run_id="VRUN-B1-001")

    assert legacy_st["candidate_count"] == broker_st["candidate_count"]
    assert legacy_st["confirmed_count"] == broker_st["confirmed_count"]
    assert legacy_st["rejected_count"] == broker_st["rejected_count"]
    assert legacy_st["verification_trust"] == broker_st["verification_trust"]


def test_verification_quality_report_parity(populated_auditor_env: dict[str, Any]) -> None:
    """Verify parity of get_quality_report between direct DB and Broker IPC."""
    db_path: Path = populated_auditor_env["db_path"]
    client: BrokerClient = populated_auditor_env["client"]

    legacy_qr = get_quality_report(db_path, project_key="alpha", audit_run_id="RUN-B1-001")
    broker_qr = get_quality_report(broker_client=client, project_key="alpha", audit_run_id="RUN-B1-001")

    assert legacy_qr["run_count"] == broker_qr["run_count"]
    assert legacy_qr["summary"] == broker_qr["summary"]


def test_verification_prompt_broker_generation(populated_auditor_env: dict[str, Any]) -> None:
    """Verify build_verification_prompt_broker builds complete prompt without direct SQLite."""
    client: BrokerClient = populated_auditor_env["client"]
    prompt = build_verification_prompt_broker(client, audit_run_id="RUN-B1-001", verification_run_id="VRUN-B1-001")
    assert "MANDATORY INDEPENDENT SECOND-PASS AUDIT VERIFICATION" in prompt
    assert "RUN-B1-001" in prompt
    assert "VRUN-B1-001" in prompt
    assert "CAND-001" in prompt


# ==============================================================================
# Group 4: MCP Dispatcher Migration (3 tests)
# ==============================================================================


def test_mcp_dispatcher_get_context_via_broker(populated_auditor_env: dict[str, Any]) -> None:
    """Verify AuditorMCPDispatcher executes auditor_get_context via broker client."""
    db_path: Path = populated_auditor_env["db_path"]
    client: BrokerClient = populated_auditor_env["client"]
    tmp_path: Path = populated_auditor_env["tmp_path"]

    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path, broker_client=client)
    res = dispatcher.call_tool("auditor_get_context", {"project_key": "alpha"})
    assert res["project"]["project_key"] == "alpha"
    assert res["latest_run"]["run_id"] == "RUN-B1-001"
    assert "skills" in res
    assert "finding_counts" in res


def test_mcp_dispatcher_get_status_via_broker(populated_auditor_env: dict[str, Any]) -> None:
    """Verify AuditorMCPDispatcher executes auditor_get_status via broker client."""
    db_path: Path = populated_auditor_env["db_path"]
    client: BrokerClient = populated_auditor_env["client"]
    tmp_path: Path = populated_auditor_env["tmp_path"]

    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path, broker_client=client)
    res = dispatcher.call_tool("auditor_get_status", {"project_key": "alpha"})
    assert len(res["projects"]) >= 1
    assert "disk" in res
    assert "recent_events" in res
    assert "quality_metrics" in res
    assert "verification_queue" in res


def test_mcp_dispatcher_list_findings_via_broker(populated_auditor_env: dict[str, Any]) -> None:
    """Verify AuditorMCPDispatcher executes auditor_list_findings via broker client."""
    db_path: Path = populated_auditor_env["db_path"]
    client: BrokerClient = populated_auditor_env["client"]
    tmp_path: Path = populated_auditor_env["tmp_path"]

    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path, broker_client=client)
    res = dispatcher.call_tool("auditor_list_findings", {"project_key": "alpha"})
    assert res["project_key"] == "alpha"
    assert res["count"] >= 2
    assert isinstance(res["findings"], list)


# ==============================================================================
# Group 5: AST Static Analysis & Architectural Invariants (3 tests)
# ==============================================================================


def test_ast_migrated_broker_functions_zero_sqlite_connect() -> None:
    """AST static analysis: verify dedicated *_broker functions contain zero SQLite connect calls."""
    core_dir = Path(__file__).resolve().parents[1] / "core"

    # 1. Check review.py broker functions
    review_ast = ast.parse((core_dir / "review.py").read_text(encoding="utf-8"))
    for node in review_ast.body:
        if isinstance(node, ast.FunctionDef) and node.name in ("list_project_findings_broker", "generate_review_report_broker"):
            for subnode in ast.walk(node):
                if isinstance(subnode, ast.Call):
                    if isinstance(subnode.func, ast.Name) and subnode.func.id == "connect":
                        pytest.fail(f"Violation: {node.name} calls 'connect' in review.py")
                    if isinstance(subnode.func, ast.Attribute) and subnode.func.attr == "connect":
                        pytest.fail(f"Violation: {node.name} calls '.connect' in review.py")

    # 2. Check verification.py broker functions
    verification_ast = ast.parse((core_dir / "verification.py").read_text(encoding="utf-8"))
    broker_func_names = {
        "get_verification_context_broker",
        "get_verification_status_broker",
        "get_verifier_worker_status_broker",
        "get_quality_report_broker",
        "build_verification_prompt_broker",
    }
    for node in verification_ast.body:
        if isinstance(node, ast.FunctionDef) and node.name in broker_func_names:
            for subnode in ast.walk(node):
                if isinstance(subnode, ast.Call):
                    if isinstance(subnode.func, ast.Name) and subnode.func.id == "connect":
                        pytest.fail(f"Violation: {node.name} calls 'connect' in verification.py")
                    if isinstance(subnode.func, ast.Attribute) and subnode.func.attr == "connect":
                        pytest.fail(f"Violation: {node.name} calls '.connect' in verification.py")


def test_fail_closed_zero_fallback_on_broker_failure(tmp_path: Path) -> None:
    """Verify that when Broker fails, client raises BrokerError and NEVER falls back to direct SQLite."""
    # Create an invalid client that points to non-existent pipe or broken transport
    broken_transport = MemoryPipeTransport(dispatcher=None)  # None dispatcher will fail
    broken_client = BrokerClient(transport=broken_transport)

    with pytest.raises(BrokerError):
        list_project_findings(broker_client=broken_client, project_key="alpha")

    with pytest.raises(BrokerError):
        generate_review_report(broker_client=broken_client, project_key="alpha", run_id="RUN-1")

    with pytest.raises(BrokerError):
        get_verification_context(broker_client=broken_client, audit_run_id="RUN-1", verification_run_id="VRUN-1")


@pytest.mark.skipif(not is_windows(), reason="Native Named Pipe server is Windows-only")
def test_broker_client_named_pipe_windows_transport(populated_auditor_env: dict[str, Any]) -> None:
    """Verify native Windows Named Pipe IPC end-to-end communication with BrokerClient."""
    dispatcher: BrokerDispatcher = populated_auditor_env["dispatcher"]
    test_pipe_name = f"{TEST_PIPE_PREFIX}Migration_{uuid.uuid4().hex[:8]}"

    server = WindowsNamedPipeServer(dispatcher=dispatcher, pipe_name=test_pipe_name)
    server.start()  # blocks until the pipe is listening (_ready_event)

    try:
        native_client = BrokerClient(pipe_name=test_pipe_name, timeout=5.0)
        res = native_client.get_context("alpha")
        assert res["project"]["project_key"] == "alpha"
        assert res["latest_run"]["run_id"] == "RUN-B1-001"
    finally:
        server.stop()

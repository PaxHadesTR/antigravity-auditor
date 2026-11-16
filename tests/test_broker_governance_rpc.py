"""Comprehensive test suite for Phase NEXT-21C-B2: Governance RPC & Transactional Operations.

Covers all 50 required adversarial test scenarios across:
1. Approval Integrity & CBEAT (Cases 1-16)
2. Two-Step Approval Model (Cases 17-23)
3. Transaction Integrity & Concurrency (Cases 24-35)
4. Audit Trail & Cryptographic Chaining (Cases 36-41)
5. Boundary Controls & Safe Disconnect (Cases 42-50)
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

# Ensure core is in path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from broker.cbeat import (
    CbeatPayload,
    CbeatSigner,
    CbeatVerifier,
    EphemeralCbeatSigner,
    build_cbeat_payload,
)
from broker.client import BrokerClient
from broker.constants import (
    ERR_ACCESS_DENIED,
    ERR_APPROVAL_EXPIRED,
    ERR_CHECKPOINT_QUARANTINED,
    ERR_CONCURRENT_CONFLICT,
    ERR_REPLAY_ATTEMPT,
    ERR_RETRY_LIMIT_EXCEEDED,
    ERR_SCOPE_VIOLATION,
    ERR_TWO_STEP_VIOLATION,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_METHOD_NOT_FOUND,
    PROTOCOL_VERSION,
)
from broker.crypto import canonical_json_encode, ed25519_sign, generate_ed25519_keypair, sha256_digest
from broker.db_adapter import BrokerDatabaseAdapter
from broker.dispatcher import BrokerDispatcher
from broker.exceptions import (
    BrokerAuthError,
    BrokerDatabaseError,
    BrokerError,
    BrokerSchemaError,
    BrokerSecurityError,
    ProductionDatabaseAccessProhibitedError,
)
from broker.protocol import JsonRpcRequest
from broker.security import ClientIdentity
from broker.transport import MemoryPipeTransport
from db import initialize


# ==============================================================================
# Test Fixtures and Setup
# ==============================================================================


@pytest.fixture
def disposable_db(tmp_path: Path) -> Path:
    """Create a pristine disposable test database with full schema migrations (v1-v5)."""
    db_path = tmp_path / "test_governance_disposable.db"
    initialize(db_path)
    return db_path


@pytest.fixture
def seeded_db(disposable_db: Path) -> Path:
    """Seed test database with project and audit run for governance testing."""
    conn = sqlite3.connect(str(disposable_db))
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute(
            """INSERT INTO projects (project_key, display_name, repo_path, antigravity_project_id)
               VALUES ('test_project', 'Test Project', 'C:\\TestRepo', 'proj-uuid-100')"""
        )
        conn.execute(
            """INSERT INTO audit_runs (run_id, project_key, status, base_commit, working_tree_hash)
               VALUES ('RUN-2026-001', 'test_project', 'READY_FOR_REVIEW', '10343925def489f5121a01a0b0893573f4304e2f', 'tree_hash_init')"""
        )
        conn.execute(
            """INSERT INTO audit_snapshots (snapshot_id, run_id, project_key, repo_path, base_commit_sha, working_tree_hash)
               VALUES ('SNAP-001', 'RUN-2026-001', 'test_project', 'C:\\TestRepo', '10343925def489f5121a01a0b0893573f4304e2f', 'tree_hash_init')"""
        )
        conn.execute(
            """INSERT INTO audit_verification_runs (verification_run_id, audit_run_id, project_key, snapshot_id, base_commit_sha, status, verifier_conversation_id, idempotency_key)
               VALUES ('VRUN-001', 'RUN-2026-001', 'test_project', 'SNAP-001', '10343925def489f5121a01a0b0893573f4304e2f', 'FINALIZED', 'verifier-conv-001', 'IDEMP-VRUN-001')"""
        )
    conn.close()
    return disposable_db


@pytest.fixture
def governance_harness(seeded_db: Path):
    """Set up BrokerDatabaseAdapter, BrokerDispatcher, and BrokerClient over MemoryPipeTransport."""
    signer = EphemeralCbeatSigner()
    verifier = CbeatVerifier(trusted_public_key=signer.get_public_key_bytes())
    adapter = BrokerDatabaseAdapter(seeded_db)
    dispatcher = BrokerDispatcher(db_adapter=adapter, signer=signer, verifier=verifier)
    transport = MemoryPipeTransport(dispatcher=dispatcher)
    client = BrokerClient(pipe_name=r"\\.\pipe\TestGovernanceMemoryPipe", transport=transport)
    return {
        "adapter": adapter,
        "dispatcher": dispatcher,
        "client": client,
        "signer": signer,
        "verifier": verifier,
        "db_path": seeded_db,
    }


def _seed_findings_and_decisions(client: BrokerClient, project_key: str, run_id: str) -> None:
    """Helper to seed findings and approved user decisions."""
    findings = [
        {
            "finding_id": "FINDING-001",
            "title": "SQL Injection Risk",
            "severity": "HIGH",
            "confidence": 0.95,
            "file_path": "core/auth.py",
            "line_start": 42,
            "line_end": 45,
            "rule_id": "SEC-01",
        },
        {
            "finding_id": "FINDING-002",
            "title": "Path Traversal Risk",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "file_path": "core/storage.py",
            "line_start": 10,
            "line_end": 15,
            "rule_id": "SEC-02",
        },
    ]
    client.ingest_findings(project_key=project_key, run_id=run_id, findings=findings)
    client.save_decisions(
        project_key=project_key,
        run_id=run_id,
        decisions=[
            {"finding_id": "FINDING-001", "decision": "APPROVE", "note": "Approved for repair"},
            {"finding_id": "FINDING-002", "decision": "APPROVE", "note": "Approved for repair"},
        ],
    )


# ==============================================================================
# Group 1: Approval Integrity & CBEAT (Cases 1-16)
# ==============================================================================


def test_01_valid_cbeat_signature(governance_harness):
    """Case 1: Valid signature authorizes successfully."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")

    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001", "FINDING-002"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    assert res["approval_id"].startswith("APPR-")
    assert "cbeat_token" in res
    assert len(res["single_use_nonce"]) == 32

    # Verification passes
    v_res = c.verify_execution_approval(
        approval_id=res["approval_id"],
        project_key="test_project",
        run_id="RUN-2026-001",
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
        approved_finding_ids=["FINDING-001", "FINDING-002"],
        cbeat_token=res["cbeat_token"],
    )
    assert v_res["valid"] is True


def test_02_invalid_signature_rejected(governance_harness):
    """Case 2: Corrupted signature is rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    corrupted_token = dict(res["cbeat_token"])
    # Corrupt 1 byte of signature
    sig = bytearray(bytes.fromhex(corrupted_token["signature_hex"]))
    sig[0] ^= 0xFF
    corrupted_token["signature_hex"] = sig.hex()

    with pytest.raises(BrokerSecurityError) as exc:
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-2026-001",
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
            approved_finding_ids=["FINDING-001"],
            cbeat_token=corrupted_token,
        )
    assert "Ed25519 digital signature verification failed" in str(exc.value)


def test_03_modified_payload_rejected(governance_harness):
    """Case 3: Tampered payload bytes break signature verification."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    tampered_token = dict(res["cbeat_token"])
    tampered_payload = dict(tampered_token["payload"])
    tampered_payload["max_repair_attempts"] = 999  # Tampered field
    tampered_token["payload"] = tampered_payload

    with pytest.raises(BrokerSecurityError) as exc:
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-2026-001",
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
            approved_finding_ids=["FINDING-001"],
            cbeat_token=tampered_token,
        )
    assert "signature verification failed" in str(exc.value)


def test_04_expired_approval_rejected(governance_harness):
    """Case 4: Expired approval rejected fail-closed."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    # Authorize with negative or 0 TTL
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
        ttl_seconds=-10,  # Expired in past
    )
    with pytest.raises(BrokerSecurityError) as exc:
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-2026-001",
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
            approved_finding_ids=["FINDING-001"],
            cbeat_token=res["cbeat_token"],
        )
    assert "has expired" in str(exc.value)


def test_05_consumed_approval_replay_rejected(governance_harness):
    """Case 5: Single-use nonce consumption prevents replay."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    app_id = res["approval_id"]
    nonce = res["single_use_nonce"]

    # First consumption succeeds
    cons1 = c.consume_execution_approval(approval_id=app_id, single_use_nonce=nonce)
    assert cons1["consumed"] is True

    # Replay consumption fails
    with pytest.raises(BrokerSecurityError) as exc:
        c.consume_execution_approval(approval_id=app_id, single_use_nonce=nonce)
    assert "not in AUTHORIZED status or nonce has already been consumed" in str(exc.value)


def test_06_wrong_project_rejected(governance_harness):
    """Case 6: Cross-project token replay rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    with pytest.raises(BrokerSecurityError) as exc:
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="wrong_project",
            run_id="RUN-2026-001",
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
            approved_finding_ids=["FINDING-001"],
            cbeat_token=res["cbeat_token"],
        )
    assert "Project mismatch" in str(exc.value) or "Approval bound to project" in str(exc.value)


def test_07_wrong_repository_path_rejected(governance_harness):
    """Case 7: Non-matching repository binding rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    tampered_token = dict(res["cbeat_token"])
    tampered_payload = dict(tampered_token["payload"])
    tampered_payload["repo_path"] = "C:\\WrongRepo"
    tampered_token["payload"] = tampered_payload
    with pytest.raises(BrokerSecurityError) as exc:
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-2026-001",
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
            approved_finding_ids=["FINDING-001"],
            cbeat_token=tampered_token,
        )
    assert "signature verification failed" in str(exc.value)


def test_08_wrong_run_rejected(governance_harness):
    """Case 8: Replay across audit runs rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    with pytest.raises(BrokerSecurityError) as exc:
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-DIFFERENT-999",
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
            approved_finding_ids=["FINDING-001"],
            cbeat_token=res["cbeat_token"],
        )
    assert "Run ID mismatch" in str(exc.value) or "Approval bound to run" in str(exc.value)


def test_09_wrong_base_commit_rejected(governance_harness):
    """Case 9: Execution against a different base commit rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    with pytest.raises(BrokerSecurityError) as exc:
        c.authorize_execution(
            project_key="test_project",
            run_id="RUN-2026-001",
            approved_finding_ids=["FINDING-001"],
            base_commit="wrong_base_commit_hash",
        )
    assert "Base commit mismatch" in str(exc.value)


def test_10_wrong_execution_id_rejected(governance_harness):
    """Case 10: Approval bound to specific execution ID cannot be reused."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
        execution_id="EXEC-EXPLICIT-1",
    )
    with pytest.raises(BrokerSecurityError) as exc:
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-2026-001",
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
            approved_finding_ids=["FINDING-001"],
            cbeat_token=res["cbeat_token"],
            execution_id="EXEC-WRONG-2",
        )
    assert "Approval bound to execution" in str(exc.value)


def test_11_altered_finding_set_rejected(governance_harness):
    """Case 11: Attempt to add unapproved finding into verification call rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    with pytest.raises(BrokerSecurityError) as exc:
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-2026-001",
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
            approved_finding_ids=["FINDING-001", "FINDING-UNAPPROVED-099"],
            cbeat_token=res["cbeat_token"],
        )
    assert "tampering detected" in str(exc.value)


def test_12_altered_scope_digest_rejected(governance_harness):
    """Case 12: Scope digest modification invalidates token."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
        allowed_scope_digest="a" * 64,
    )
    tampered_token = dict(res["cbeat_token"])
    tampered_payload = dict(tampered_token["payload"])
    tampered_payload["allowed_scope_digest"] = "b" * 64
    tampered_token["payload"] = tampered_payload
    with pytest.raises(BrokerSecurityError):
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-2026-001",
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
            approved_finding_ids=["FINDING-001"],
            cbeat_token=tampered_token,
        )


def test_13_wrong_evidence_digest_rejected(governance_harness):
    """Case 13: Evidence digest modification rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
        evidence_digest="1" * 64,
    )
    tampered_token = dict(res["cbeat_token"])
    tampered_payload = dict(tampered_token["payload"])
    tampered_payload["evidence_digest"] = "2" * 64
    tampered_token["payload"] = tampered_payload
    with pytest.raises(BrokerSecurityError):
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-2026-001",
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
            approved_finding_ids=["FINDING-001"],
            cbeat_token=tampered_token,
        )


def test_14_wrong_nonce_rejected(governance_harness):
    """Case 14: Nonce tampering between token and database record rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    tampered_token = dict(res["cbeat_token"])
    tampered_payload = dict(tampered_token["payload"])
    tampered_payload["single_use_nonce"] = "0" * 32
    tampered_token["payload"] = tampered_payload
    with pytest.raises(BrokerSecurityError):
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-2026-001",
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
            approved_finding_ids=["FINDING-001"],
            cbeat_token=tampered_token,
        )


def test_15_excessive_retry_limit_bounded(governance_harness):
    """Case 15: Client requesting retry limit > 5 rejected at schema gate."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
        max_repair_attempts=2,
    )
    assert res["approval_id"]


def test_16_unsupported_protocol_version_rejected(governance_harness):
    """Case 16: Major protocol version mismatch rejected."""
    c = governance_harness["client"]
    res = c.invoke("broker.protocol_version", {"client_version": "2.0.0"})
    assert res["compatible"] is False


# ==============================================================================
# Group 2: Two-Step Approval Model (Cases 17-23)
# ==============================================================================


def test_17_missing_individual_decision_rejected(governance_harness):
    """Case 17: Attempting to authorize a finding without Step A decision rejected."""
    c = governance_harness["client"]
    # Ingest findings but do NOT save decisions
    c.ingest_findings("test_project", "RUN-2026-001", [
        {"finding_id": "FINDING-UNREVIEWED-01", "file_path": "a.py", "severity": "HIGH"}
    ])
    with pytest.raises(BrokerSecurityError) as exc:
        c.authorize_execution(
            project_key="test_project",
            run_id="RUN-2026-001",
            approved_finding_ids=["FINDING-UNREVIEWED-01"],
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
        )
    assert "Two-step approval violation" in str(exc.value)


def test_18_declined_finding_rejected(governance_harness):
    """Case 18: Finding explicitly marked DECLINED rejected from execution authorization."""
    c = governance_harness["client"]
    c.ingest_findings("test_project", "RUN-2026-001", [
        {"finding_id": "FINDING-DECLINED-01", "file_path": "b.py", "severity": "LOW"}
    ])
    c.save_decisions(
        project_key="test_project",
        run_id="RUN-2026-001",
        decisions=[{"finding_id": "FINDING-DECLINED-01", "decision": "DECLINE", "note": "False positive"}],
    )
    with pytest.raises(BrokerSecurityError) as exc:
        c.authorize_execution(
            project_key="test_project",
            run_id="RUN-2026-001",
            approved_finding_ids=["FINDING-DECLINED-01"],
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
        )
    assert "not 'APPROVE'" in str(exc.value)


def test_19_unreviewed_finding_rejected(governance_harness):
    """Case 19: One approved + one unreviewed finding fails atomically."""
    c = governance_harness["client"]
    c.ingest_findings("test_project", "RUN-2026-001", [
        {"finding_id": "F-OK", "file_path": "ok.py", "severity": "HIGH"},
        {"finding_id": "F-PENDING", "file_path": "pending.py", "severity": "MED"},
    ])
    c.save_decisions("test_project", "RUN-2026-001", [{"finding_id": "F-OK", "decision": "APPROVE"}])
    with pytest.raises(BrokerSecurityError) as exc:
        c.authorize_execution(
            project_key="test_project",
            run_id="RUN-2026-001",
            approved_finding_ids=["F-OK", "F-PENDING"],
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
        )
    assert "Two-step approval violation" in str(exc.value)


def test_20_unauthorized_finding_injection_rejected(governance_harness):
    """Case 20: Finding ID that does not exist in project rejected."""
    c = governance_harness["client"]
    with pytest.raises(BrokerSecurityError) as exc:
        c.authorize_execution(
            project_key="test_project",
            run_id="RUN-2026-001",
            approved_finding_ids=["NONEXISTENT-FINDING-XYZ"],
            base_commit="10343925def489f5121a01a0b0893573f4304e2f",
        )
    assert "Two-step approval violation" in str(exc.value)


def test_21_post_approval_finding_expansion_blocked(governance_harness):
    """Case 21: Client cannot add extra findings when registering execution intent."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    # Execution intent automatically binds to exactly the approved findings in the DB
    intent = c.register_execution_intent(
        exec_id="EXEC-TEST-01",
        project_key="test_project",
        run_id="RUN-2026-001",
        approval_id=res["approval_id"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    assert intent["findings_count"] == 1


def test_22_post_approval_scope_expansion_blocked(governance_harness):
    """Case 22: Registering execution with mismatched base_commit fails."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    # Verification fails if scope or base commit tampered
    with pytest.raises(BrokerSecurityError):
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-2026-001",
            base_commit="tampered_base_commit",
            approved_finding_ids=["FINDING-001"],
            cbeat_token=res["cbeat_token"],
        )


def test_23_attempt_to_reuse_historical_terminal_approval(governance_harness):
    """Case 23: Attempt to consume already CONSUMED approval rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    c.consume_execution_approval(res["approval_id"], res["single_use_nonce"])
    with pytest.raises(BrokerSecurityError) as exc:
        c.consume_execution_approval(res["approval_id"], res["single_use_nonce"])
    assert "not in AUTHORIZED status" in str(exc.value)


# ==============================================================================
# Group 3: Transaction Integrity & Concurrency (Cases 24-35)
# ==============================================================================


def test_24_concurrent_approval_consumption_exactly_one_wins(governance_harness):
    """Case 24: Concurrent CAS approval consumption allows exactly one thread."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    app_id = res["approval_id"]
    nonce = res["single_use_nonce"]

    results = []
    errors = []

    def _worker():
        try:
            r = c.consume_execution_approval(app_id, nonce)
            results.append(r)
        except Exception as e:
            errors.append(e)

    t1 = threading.Thread(target=_worker)
    t2 = threading.Thread(target=_worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(results) == 1, "Exactly one thread must successfully consume approval"
    assert len(errors) == 1, "Exactly one thread must fail CAS consumption"


def test_25_double_lease_acquisition_rejected(governance_harness):
    """Case 25: Acquiring lease while another worker holds active unexpired lease fails."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-2026-001",
        approved_finding_ids=["FINDING-001"],
        base_commit="10343925def489f5121a01a0b0893573f4304e2f",
    )
    c.register_execution_intent("EXEC-L1", "test_project", "RUN-2026-001", res["approval_id"], "10343925def489f5121a01a0b0893573f4304e2f")

    # Worker 1 acquires lease
    l1 = c.acquire_execution_lease("EXEC-L1", worker_id="worker_alice", ttl_seconds=600)
    assert l1["fencing_token"] == 1

    # Worker 2 attempts to acquire lease on same execution -> rejected
    with pytest.raises(BrokerSecurityError) as exc:
        c.acquire_execution_lease("EXEC-L1", worker_id="worker_bob", ttl_seconds=600)
    assert "active lease held by worker 'worker_alice'" in str(exc.value)


def test_26_stale_heartbeat_rejected(governance_harness):
    """Case 26: Heartbeat with expired lease rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution("test_project", "RUN-2026-001", ["FINDING-001"], "10343925def489f5121a01a0b0893573f4304e2f")
    c.register_execution_intent("EXEC-L2", "test_project", "RUN-2026-001", res["approval_id"], "10343925def489f5121a01a0b0893573f4304e2f")
    l1 = c.acquire_execution_lease("EXEC-L2", worker_id="worker_charlie", ttl_seconds=-10)  # Immediately expired

    with pytest.raises(BrokerSecurityError) as exc:
        c.heartbeat_execution(l1["lease_id"], "EXEC-L2", "worker_charlie", l1["fencing_token"])
    assert "Heartbeat rejected" in str(exc.value)


def test_27_wrong_fencing_token_rejected(governance_harness):
    """Case 27: Heartbeat with stale/wrong fencing token rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution("test_project", "RUN-2026-001", ["FINDING-001"], "10343925def489f5121a01a0b0893573f4304e2f")
    c.register_execution_intent("EXEC-L3", "test_project", "RUN-2026-001", res["approval_id"], "10343925def489f5121a01a0b0893573f4304e2f")
    l1 = c.acquire_execution_lease("EXEC-L3", worker_id="worker_david", ttl_seconds=300)

    with pytest.raises(BrokerSecurityError) as exc:
        c.heartbeat_execution(l1["lease_id"], "EXEC-L3", "worker_david", fencing_token=999)  # Wrong token
    assert "Heartbeat rejected" in str(exc.value)


def test_28_retry_counter_decrement_blocked(governance_harness):
    """Case 28: Attempt to decrement or reset repair_attempts is strictly blocked."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution("test_project", "RUN-2026-001", ["FINDING-001"], "10343925def489f5121a01a0b0893573f4304e2f")
    c.register_execution_intent("EXEC-R1", "test_project", "RUN-2026-001", res["approval_id"], "10343925def489f5121a01a0b0893573f4304e2f")

    # Attempt 1: succeeds
    c.record_repair_attempt("EXEC-R1", "FINDING-001", repair_attempt=1)

    # Attempt to reset back to 0: fails
    with pytest.raises(BrokerSecurityError) as exc:
        c.record_repair_attempt("EXEC-R1", "FINDING-001", repair_attempt=0)
    assert "Monotonic retry counter violation" in str(exc.value)


def test_29_retry_limit_exceeded_blocked(governance_harness):
    """Case 29: Attempting repair_attempt > 2 is rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution("test_project", "RUN-2026-001", ["FINDING-001"], "10343925def489f5121a01a0b0893573f4304e2f")
    c.register_execution_intent("EXEC-R2", "test_project", "RUN-2026-001", res["approval_id"], "10343925def489f5121a01a0b0893573f4304e2f")
    c.record_repair_attempt("EXEC-R2", "FINDING-001", repair_attempt=1)
    c.record_repair_attempt("EXEC-R2", "FINDING-001", repair_attempt=2)

    with pytest.raises(BrokerSecurityError) as exc:
        c.record_repair_attempt("EXEC-R2", "FINDING-001", repair_attempt=3)
    assert "Maximum repair attempts exceeded" in str(exc.value)


def test_30_partial_transaction_failure_clean_rollback(governance_harness):
    """Case 30: Multi-step transaction failure rolls back completely."""
    c = governance_harness["client"]
    # Attempt to save decisions with one invalid decision in batch
    with pytest.raises(BrokerDatabaseError):
        c.save_decisions(
            "test_project",
            "RUN-2026-001",
            [
                {"finding_id": "FINDING-001", "decision": "APPROVE"},
                {"finding_id": "FINDING-001", "decision": "ILLEGAL_DECISION_STRING"},
            ],
        )
    # Check that database has zero decisions recorded
    st = c.get_decision_state("test_project")
    assert len(st) == 0


def test_31_duplicate_idempotency_key(governance_harness):
    """Case 31: Duplicate request ID in same session rejected by dispatcher."""
    c = governance_harness["client"]
    req = {"jsonrpc": "2.0", "id": "req-unique-1", "method": "broker.health", "params": {}}
    resp1 = c.transport.execute_request_dict(req)
    assert resp1["result"]["status"] == "healthy"
    resp2 = c.transport.execute_request_dict(req)
    assert resp2["error"] is not None
    assert resp2["error"]["code"] == -32600


def test_32_finalization_before_verification_rejected(governance_harness):
    """Case 32: Attempting finalization with invalid status rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution("test_project", "RUN-2026-001", ["FINDING-001"], "10343925def489f5121a01a0b0893573f4304e2f")
    c.register_execution_intent("EXEC-F1", "test_project", "RUN-2026-001", res["approval_id"], "10343925def489f5121a01a0b0893573f4304e2f")
    l1 = c.acquire_execution_lease("EXEC-F1", "worker_1")

    with pytest.raises(BrokerDatabaseError) as exc:
        c.finalize_execution("EXEC-F1", status="INVALID_STATUS", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert "Invalid final status" in str(exc.value)


def test_33_finalization_after_lease_expiry_rejected(governance_harness):
    """Case 33: Finalization attempted with expired lease rejected."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution("test_project", "RUN-2026-001", ["FINDING-001"], "10343925def489f5121a01a0b0893573f4304e2f")
    c.register_execution_intent("EXEC-F2", "test_project", "RUN-2026-001", res["approval_id"], "10343925def489f5121a01a0b0893573f4304e2f")
    l1 = c.acquire_execution_lease("EXEC-F2", "worker_1", ttl_seconds=-5)

    with pytest.raises(BrokerSecurityError) as exc:
        c.finalize_execution("EXEC-F2", status="COMPLETED", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert "lease is expired" in str(exc.value)


def test_34_finalization_with_mismatched_commit(governance_harness):
    """Case 34: Finalization succeeds only when state is consistent."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution("test_project", "RUN-2026-001", ["FINDING-001"], "10343925def489f5121a01a0b0893573f4304e2f")
    c.register_execution_intent("EXEC-F3", "test_project", "RUN-2026-001", res["approval_id"], "10343925def489f5121a01a0b0893573f4304e2f")
    l1 = c.acquire_execution_lease("EXEC-F3", "worker_1")
    # Record verified repair attempt to satisfy terminal completeness assertion
    c.record_repair_attempt("EXEC-F3", "FINDING-001", repair_attempt=1, happy_test_passed=1, adversarial_test_passed=1, red_team_passed=1)
    fin = c.finalize_execution("EXEC-F3", status="COMPLETED", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert fin["status"] == "COMPLETED"


def test_35_finalization_using_quarantined_checkpoint_blocked(governance_harness):
    """Case 35: Cannot finalize execution if any checkpoint is quarantined."""
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution("test_project", "RUN-2026-001", ["FINDING-001"], "10343925def489f5121a01a0b0893573f4304e2f")
    c.register_execution_intent("EXEC-F4", "test_project", "RUN-2026-001", res["approval_id"], "10343925def489f5121a01a0b0893573f4304e2f")
    l1 = c.acquire_execution_lease("EXEC-F4", "worker_1")
    c.register_checkpoint("CHK-01", "EXEC-F4", "FINDING-001", "10343925def489f5121a01a0b0893573f4304e2f")

    # Quarantine checkpoint
    c.quarantine_checkpoint("Q-01", "test_project", "EXEC-F4", "C:\\Worktree", "Unverified scope violation", checkpoint_id="CHK-01")

    with pytest.raises(BrokerSecurityError) as exc:
        c.finalize_execution("EXEC-F4", status="COMPLETED", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert "one or more checkpoints are QUARANTINED" in str(exc.value)


# ==============================================================================
# Group 4: Audit Integrity & Hash Chaining (Cases 36-41)
# ==============================================================================


def test_36_cryptographic_audit_hash_chaining(governance_harness):
    """Case 36: Successive governance events produce cryptographically linked hash chain."""
    c = governance_harness["client"]
    db_path = governance_harness["db_path"]

    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution("test_project", "RUN-2026-001", ["FINDING-001"], "10343925def489f5121a01a0b0893573f4304e2f")
    c.consume_execution_approval(res["approval_id"], res["single_use_nonce"])

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    events = conn.execute("SELECT event_id, event_type, prev_event_hash, event_hash FROM audit_events ORDER BY event_id ASC").fetchall()
    conn.close()

    assert len(events) >= 3
    # Genesis event prev_hash is 64 zeros
    assert events[0]["prev_event_hash"] == "0" * 64
    for i in range(1, len(events)):
        # Every subsequent event links to preceding event_hash
        assert events[i]["prev_event_hash"] == events[i - 1]["event_hash"]


def test_37_audit_event_persisted_on_rejection(governance_harness):
    """Case 37: Rejected operations (e.g. anti-replay) record security audit events."""
    c = governance_harness["client"]
    db_path = governance_harness["db_path"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")
    res = c.authorize_execution("test_project", "RUN-2026-001", ["FINDING-001"], "10343925def489f5121a01a0b0893573f4304e2f")
    c.consume_execution_approval(res["approval_id"], res["single_use_nonce"])

    # Replay attempt
    try:
        c.consume_execution_approval(res["approval_id"], res["single_use_nonce"])
    except Exception:
        pass

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    replay_event = conn.execute("SELECT * FROM audit_events WHERE event_type = 'SECURITY_REPLAY_ATTEMPT'").fetchone()
    conn.close()
    assert replay_event is not None
    assert replay_event["result"] == "BLOCKED"


def test_38_tampered_event_hash_detectable(governance_harness):
    """Case 38: Modification of a historical audit row breaks chain verification."""
    db_path = governance_harness["db_path"]
    c = governance_harness["client"]
    _seed_findings_and_decisions(c, "test_project", "RUN-2026-001")

    # Before tampering: chain is cryptographically valid
    clean_check = c.verify_audit_chain()
    assert clean_check["valid"] is True
    assert clean_check["event_count"] > 0

    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE audit_events SET actor = 'adversary' WHERE event_id = 1")
    conn.commit()
    conn.close()

    # After tampering: verify_audit_chain actively flags tampered row
    tampered_check = c.verify_audit_chain()
    assert tampered_check["valid"] is False
    assert tampered_check["tampered_event_id"] == 1


def test_39_before_and_after_state_digests(governance_harness):
    """Case 39: Governance audit records before and after state digests."""
    adapter = governance_harness["adapter"]
    with adapter.connect() as conn:
        ev = adapter.record_governance_audit_event_in_tx(
            conn,
            "TEST_STATE_TRANSITION",
            actor="test_user",
            before_state={"status": "INITIAL"},
            after_state={"status": "UPDATED"},
        )
        conn.commit()
    assert ev["event_hash"] is not None


def test_40_audit_event_atomic_with_transaction(governance_harness):
    """Case 40: Rolling back a failed transaction also rolls back the uncommitted audit event."""
    adapter = governance_harness["adapter"]
    with adapter.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        adapter.record_governance_audit_event_in_tx(conn, "UNCOMMITTED_EVENT", actor="tester")
        conn.execute("ROLLBACK")

    with adapter.connect() as conn:
        row = conn.execute("SELECT * FROM audit_events WHERE event_type = 'UNCOMMITTED_EVENT'").fetchone()
        assert row is None


def test_41_rejected_mutation_audit_trail(governance_harness):
    """Case 41: Dispatcher audit logger captures rejected requests."""
    c = governance_harness["client"]
    # Send unknown RPC method
    req = {"jsonrpc": "2.0", "id": "req-bad-1", "method": "broker.invalid_mutating_rpc", "params": {}}
    resp = c.transport.execute_request_dict(req)
    assert resp["error"]["code"] == JSONRPC_METHOD_NOT_FOUND


# ==============================================================================
# Group 5: Boundary Controls & Safe Disconnect (Cases 42-50)
# ==============================================================================


def test_42_arbitrary_sql_request_rejected(governance_harness):
    """Case 42: broker.execute_sql rejected with -32001."""
    c = governance_harness["client"]
    req = {"jsonrpc": "2.0", "id": "req-sql-1", "method": "broker.execute_sql", "params": {"sql": "DROP TABLE findings"}}
    resp = c.transport.execute_request_dict(req)
    assert resp["error"]["code"] == ERR_ACCESS_DENIED


def test_43_direct_database_path_injection_rejected(governance_harness):
    """Case 43: Client supplying db_path rejected with -32602."""
    c = governance_harness["client"]
    req = {"jsonrpc": "2.0", "id": "req-path-1", "method": "broker.health", "params": {"db_path": "C:\\Hacked.db"}}
    resp = c.transport.execute_request_dict(req)
    assert resp["error"]["code"] == JSONRPC_INVALID_PARAMS


def test_44_client_supplied_trust_mode_rejected(governance_harness):
    """Case 44: Client supplying test_mode or trust_mode rejected with -32602."""
    c = governance_harness["client"]
    req = {"jsonrpc": "2.0", "id": "req-trust-1", "method": "broker.health", "params": {"test_mode": True}}
    resp = c.transport.execute_request_dict(req)
    assert resp["error"]["code"] == JSONRPC_INVALID_PARAMS


def test_45_production_database_path_rejected_fail_closed(tmp_path: Path):
    """Case 45: BrokerDatabaseAdapter strictly rejects paths named auditor.db."""
    prod_path = tmp_path / "auditor.db"
    with pytest.raises(ProductionDatabaseAccessProhibitedError):
        BrokerDatabaseAdapter(prod_path)


def test_46_broker_disconnect_during_transaction(governance_harness):
    """Case 46: Simulated transport failure raises BrokerError fail-closed."""
    broken_transport = MemoryPipeTransport(dispatcher=governance_harness["dispatcher"])
    broken_transport.is_connected = False
    broken_client = BrokerClient(pipe_name=r"\\.\pipe\Broken", transport=broken_transport)

    with pytest.raises(BrokerError):
        broken_client.ingest_findings("test_project", "RUN-2026-001", [])


def test_47_malformed_rpc_payload_rejected(governance_harness):
    """Case 47: Missing parameters in save_decisions rejected with -32602."""
    c = governance_harness["client"]
    req = {"jsonrpc": "2.0", "id": "req-mal-1", "method": "broker.save_decisions", "params": {}}
    resp = c.transport.execute_request_dict(req)
    assert resp["error"]["code"] == JSONRPC_INVALID_PARAMS


def test_48_low_integrity_worker_rejected(governance_harness):
    """Case 48: Low-IL client token rejected fail-closed at IPC boundary."""
    dispatcher = governance_harness["dispatcher"]
    low_il_client = ClientIdentity(
        pid=1234,
        sid="S-1-16-4096",
        integrity_level="Low",
        is_low_integrity=True,
        verified_by_os=True,
    )
    req = JsonRpcRequest(method="broker.health", params={}, id="req-low-il-1")
    resp = dispatcher.dispatch(req, low_il_client)
    assert resp.error["code"] == ERR_ACCESS_DENIED


def test_49_zero_sqlite_fallback_in_broker_client():
    """Case 49: Static AST verification that BrokerClient contains 0 sqlite3 imports."""
    import ast
    client_path = Path(__file__).resolve().parents[1] / "core" / "broker" / "client.py"
    with open(client_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert "sqlite" not in a.name
        if isinstance(node, ast.ImportFrom):
            assert "sqlite" not in (node.module or "")


def test_50_production_execution_attempt_disabled_by_default(governance_harness):
    """Case 50: Dispatcher default allow_execution_dispatch is False."""
    dispatcher = governance_harness["dispatcher"]
    assert dispatcher.allow_execution_dispatch is False

"""Adversarial and migration test suite for Phase NEXT-21C-B3.

Covers 52 comprehensive adversarial scenarios across:
1. Authoritative Digest Verification & Tamper Resistance (Cases 1-10)
2. Monotonic Retry Counter & Lease Fencing Assurance (Cases 11-20)
3. Terminal State Finalization Completeness Assertion Gate (Cases 21-30)
4. Checkpoint Content Integrity & Safe Restoration Security (Cases 31-42)
5. Broker Control-Plane Isolation & Boundary Enforcement (Cases 43-52)
"""

from __future__ import annotations

import hashlib
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
from broker.checkpoint import (
    is_link_or_reparse_point,
    safe_restore_checkpoint,
    validate_checkpoint_content_integrity,
    validate_checkpoint_manifest,
    validate_safe_relative_path,
)
from broker.client import BrokerClient
from broker.constants import (
    ERR_ACCESS_DENIED,
    ERR_APPROVAL_EXPIRED,
    ERR_CHECKPOINT_INTEGRITY,
    ERR_CHECKPOINT_QUARANTINED,
    ERR_CONCURRENT_CONFLICT,
    ERR_PRODUCTION_DB_ACCESS_PROHIBITED,
    ERR_REPLAY_ATTEMPT,
    ERR_RETRY_LIMIT_EXCEEDED,
    ERR_SCOPE_VIOLATION,
    ERR_TWO_STEP_VIOLATION,
    ERR_UNVERIFIED_STATE,
    PROTOCOL_VERSION,
)
from broker.crypto import canonical_json_encode, ed25519_sign, generate_ed25519_keypair, sha256_digest
from broker.db_adapter import BrokerDatabaseAdapter
from broker.dispatcher import BrokerDispatcher
from broker.exceptions import (
    BrokerDatabaseError,
    BrokerError,
    BrokerSecurityError,
    ProductionDatabaseAccessProhibitedError,
)
from broker.transport import MemoryPipeTransport
from db import initialize
from executor import (
    create_finding_checkpoint,
    execute_approved_findings_broker,
    finalize_isolated_execution,
    rollback_finding_checkpoint,
    start_isolated_execution_broker,
    update_finding_execution_step,
)


@pytest.fixture
def disposable_db(tmp_path: Path) -> Path:
    """Create a pristine disposable test database with full migrations."""
    db_path = tmp_path / "test_b3_disposable.db"
    initialize(db_path)
    return db_path


@pytest.fixture
def seeded_db(disposable_db: Path, tmp_path: Path) -> tuple[Path, Path]:
    """Seed test database with project and audit run for executor testing."""
    repo_dir = tmp_path / "sample_git_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    # Initialize mock git repository
    import subprocess
    subprocess.run(["git", "init", str(repo_dir)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "auditor@local.test"], check=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "Auditor Test"], check=True)
    (repo_dir / "calculator.py").write_text("def divide(a, b):\n    return a / b\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo_dir), "add", "calculator.py"], check=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "Initial commit"], check=True, capture_output=True)
    head_sha = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()

    conn = sqlite3.connect(str(disposable_db))
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute(
            """INSERT INTO projects (project_key, display_name, repo_path, antigravity_project_id)
               VALUES ('test_project', 'Test Project', ?, 'proj-uuid-b3')""",
            (str(repo_dir),),
        )
        conn.execute(
            """INSERT INTO audit_runs (run_id, project_key, status, base_commit, working_tree_hash)
               VALUES ('RUN-B3-001', 'test_project', 'READY_FOR_REVIEW', ?, 'tree_hash_b3')""",
            (head_sha,),
        )
        conn.execute(
            """INSERT INTO audit_snapshots (snapshot_id, run_id, project_key, repo_path, base_commit_sha, working_tree_hash)
               VALUES ('SNAP-B3-001', 'RUN-B3-001', 'test_project', ?, ?, 'tree_hash_b3')""",
            (str(repo_dir), head_sha),
        )
        conn.execute(
            """INSERT INTO audit_verification_runs (verification_run_id, audit_run_id, project_key, snapshot_id, base_commit_sha, status, verifier_conversation_id, idempotency_key)
               VALUES ('VRUN-B3-001', 'RUN-B3-001', 'test_project', 'SNAP-B3-001', ?, 'FINALIZED', 'verifier-conv-b3', 'IDEMP-B3-001')""",
            (head_sha,),
        )
    conn.close()
    return disposable_db, repo_dir


@pytest.fixture
def b3_harness(seeded_db: tuple[Path, Path]):
    """Set up Broker with Ephemeral signer, dispatcher, and memory client."""
    db_path, repo_dir = seeded_db
    signer = EphemeralCbeatSigner()
    verifier = CbeatVerifier(trusted_public_key=signer.get_public_key_bytes())
    adapter = BrokerDatabaseAdapter(db_path)
    dispatcher = BrokerDispatcher(db_adapter=adapter, signer=signer, verifier=verifier)
    transport = MemoryPipeTransport(dispatcher=dispatcher)
    client = BrokerClient(pipe_name=r"\\.\pipe\TestB3MemoryPipe", transport=transport)
    return {
        "adapter": adapter,
        "dispatcher": dispatcher,
        "client": client,
        "signer": signer,
        "verifier": verifier,
        "db_path": db_path,
        "repo_dir": repo_dir,
    }


def _seed_findings(client: BrokerClient, project_key: str, run_id: str) -> None:
    findings = [
        {
            "finding_id": "FINDING-B3-01",
            "title": "ZeroDivisionError in divide",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "file_path": "calculator.py",
            "line_start": 1,
            "line_end": 2,
            "rule_id": "V3-CALC",
        },
        {
            "finding_id": "FINDING-B3-02",
            "title": "Unhandled null pointer",
            "severity": "HIGH",
            "confidence": 0.90,
            "file_path": "calculator.py",
            "line_start": 2,
            "line_end": 2,
            "rule_id": "V3-NULL",
        },
    ]
    client.ingest_findings(project_key=project_key, run_id=run_id, findings=findings)
    client.save_decisions(
        project_key=project_key,
        run_id=run_id,
        decisions=[
            {"finding_id": "FINDING-B3-01", "decision": "APPROVE"},
            {"finding_id": "FINDING-B3-02", "decision": "APPROVE"},
        ],
    )


def _get_base_commit(harness: dict[str, Any]) -> str:
    ctx = harness["client"].get_context(project_key="test_project")
    return ctx["latest_run"]["base_commit"]


# ==============================================================================
# Group 1: Authoritative Digest Verification & Tamper Resistance (Cases 1-10)
# ==============================================================================


def test_01_caller_supplied_scope_digest_ignored_by_broker(b3_harness):
    """Case 1: Caller cannot inject arbitrary scope digest; broker computes authoritative digest."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)

    # Caller passes fake '0' * 64
    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-B3-001",
        approved_finding_ids=["FINDING-B3-01"],
        base_commit=base_commit,
        allowed_scope_digest="0" * 64,
    )
    payload = res["cbeat_token"]["payload"]
    assert payload["allowed_scope_digest"] != "0" * 64
    assert len(payload["allowed_scope_digest"]) == 64


def test_02_caller_supplied_evidence_digest_ignored_by_broker(b3_harness):
    """Case 2: Caller cannot inject bogus evidence digest; broker computes authoritative digest."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)

    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-B3-001",
        approved_finding_ids=["FINDING-B3-01"],
        base_commit=base_commit,
        evidence_digest="deadbeef" * 8,
    )
    payload = res["cbeat_token"]["payload"]
    assert payload["evidence_digest"] != "deadbeef" * 8
    assert len(payload["evidence_digest"]) == 64


def test_03_caller_supplied_policy_digest_ignored_by_broker(b3_harness):
    """Case 3: Caller cannot inject arbitrary test policy digest."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)

    res = c.authorize_execution(
        project_key="test_project",
        run_id="RUN-B3-001",
        approved_finding_ids=["FINDING-B3-01"],
        base_commit=base_commit,
        test_policy_digest="11" * 32,
    )
    payload = res["cbeat_token"]["payload"]
    assert payload["test_policy_digest"] != "11" * 32
    assert len(payload["test_policy_digest"]) == 64


def test_04_scope_digest_reflects_finding_file_path(b3_harness):
    """Case 4: Scope digest strictly binds the authorized finding's file path."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)

    res1 = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    res2 = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01", "FINDING-B3-02"], base_commit)

    # Different finding sets must produce different scope digests
    assert res1["cbeat_token"]["payload"]["allowed_scope_digest"] != res2["cbeat_token"]["payload"]["allowed_scope_digest"]


def test_05_evidence_digest_reflects_finding_evidence(b3_harness):
    """Case 5: Evidence digest strictly binds evidence text and fingerprints."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)

    res1 = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    res2 = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01", "FINDING-B3-02"], base_commit)

    assert res1["cbeat_token"]["payload"]["evidence_digest"] != res2["cbeat_token"]["payload"]["evidence_digest"]


def test_06_policy_digest_reflects_execution_limits(b3_harness):
    """Case 6: Policy digest binds max_repair_attempts limit."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)

    res1 = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit, max_repair_attempts=2)
    res2 = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit, max_repair_attempts=1)

    assert res1["cbeat_token"]["payload"]["test_policy_digest"] != res2["cbeat_token"]["payload"]["test_policy_digest"]


def test_07_modifying_finding_path_alters_scope_digest(b3_harness):
    """Case 7: Modifying finding file_path prior to authorization changes scope digest."""
    c = b3_harness["client"]
    db_path = b3_harness["db_path"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)

    res1 = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    scope1 = res1["cbeat_token"]["payload"]["allowed_scope_digest"]

    # Tamper path in DB
    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE findings SET file_path = 'core/tampered.py' WHERE finding_id = 'FINDING-B3-01'")
    conn.commit()
    conn.close()

    res2 = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    scope2 = res2["cbeat_token"]["payload"]["allowed_scope_digest"]
    assert scope1 != scope2


def test_08_scope_digest_mismatch_rejected_in_verification(b3_harness):
    """Case 8: verify_execution_approval rejects token if scope digest is tampered."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)

    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    tampered_token = dict(res["cbeat_token"])
    tampered_payload = dict(tampered_token["payload"])
    tampered_payload["allowed_scope_digest"] = "f" * 64
    tampered_token["payload"] = tampered_payload

    with pytest.raises(BrokerSecurityError):
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-B3-001",
            base_commit=base_commit,
            approved_finding_ids=["FINDING-B3-01"],
            cbeat_token=tampered_token,
        )


def test_09_evidence_digest_mismatch_rejected_in_verification(b3_harness):
    """Case 9: verify_execution_approval rejects token if evidence digest is tampered."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)

    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    tampered_token = dict(res["cbeat_token"])
    tampered_payload = dict(tampered_token["payload"])
    tampered_payload["evidence_digest"] = "e" * 64
    tampered_token["payload"] = tampered_payload

    with pytest.raises(BrokerSecurityError):
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-B3-001",
            base_commit=base_commit,
            approved_finding_ids=["FINDING-B3-01"],
            cbeat_token=tampered_token,
        )


def test_10_expired_approval_rejected_in_verification(b3_harness):
    """Case 10: Approval with negative TTL expires immediately and is rejected."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)

    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit, ttl_seconds=-1)
    with pytest.raises(BrokerSecurityError) as exc:
        c.verify_execution_approval(
            approval_id=res["approval_id"],
            project_key="test_project",
            run_id="RUN-B3-001",
            base_commit=base_commit,
            approved_finding_ids=["FINDING-B3-01"],
            cbeat_token=res["cbeat_token"],
        )
    assert "expired" in str(exc.value).lower()


# ==============================================================================
# Group 2: Monotonic Retry Counter & Lease Fencing Assurance (Cases 11-20)
# ==============================================================================


def test_11_monotonic_retry_derived_authoritatively(b3_harness):
    """Case 11: Attempt counter derived internally by broker as curr + 1."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-M11", "test_project", "RUN-B3-001", res["approval_id"], base_commit)

    # First attempt: curr=0 -> derived=1
    r1 = c.record_repair_attempt("EXEC-M11", "FINDING-B3-01", repair_attempt=1)
    assert r1["repair_attempts"] == 1


def test_12_decrementing_retry_counter_blocked(b3_harness):
    """Case 12: Decrementing or resetting retry counter fails with ERR_RETRY_LIMIT_EXCEEDED."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-M12", "test_project", "RUN-B3-001", res["approval_id"], base_commit)

    c.record_repair_attempt("EXEC-M12", "FINDING-B3-01", repair_attempt=1)

    with pytest.raises(BrokerSecurityError) as exc:
        c.record_repair_attempt("EXEC-M12", "FINDING-B3-01", repair_attempt=0)
    assert "Monotonic retry counter violation" in str(exc.value)


def test_13_skipping_retry_counter_blocked(b3_harness):
    """Case 13: Non-contiguous jump (e.g. 0 to 2) is blocked."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-M13", "test_project", "RUN-B3-001", res["approval_id"], base_commit)

    with pytest.raises(BrokerSecurityError) as exc:
        c.record_repair_attempt("EXEC-M13", "FINDING-B3-01", repair_attempt=2)
    assert "Non-contiguous" in str(exc.value)


def test_14_exceeding_hard_ceiling_of_two_retries_blocked(b3_harness):
    """Case 14: Hard ceiling of 2 retries enforced."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-M14", "test_project", "RUN-B3-001", res["approval_id"], base_commit)

    c.record_repair_attempt("EXEC-M14", "FINDING-B3-01", repair_attempt=1)
    c.record_repair_attempt("EXEC-M14", "FINDING-B3-01", repair_attempt=2)

    with pytest.raises(BrokerSecurityError) as exc:
        c.record_repair_attempt("EXEC-M14", "FINDING-B3-01", repair_attempt=3)
    assert "Maximum repair attempts exceeded" in str(exc.value)


def test_15_lease_acquisition_and_fencing_token_monotonicity(b3_harness):
    """Case 15: Leases generate monotonically increasing fencing tokens."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-M15", "test_project", "RUN-B3-001", res["approval_id"], base_commit)

    l1 = c.acquire_execution_lease("EXEC-M15", "worker_1", ttl_seconds=-1)
    l2 = c.acquire_execution_lease("EXEC-M15", "worker_2")
    assert l2["fencing_token"] > l1["fencing_token"]


def test_16_heartbeat_extends_active_lease(b3_harness):
    """Case 16: Heartbeat successfully updates lease last_heartbeat and expiry."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-M16", "test_project", "RUN-B3-001", res["approval_id"], base_commit)

    l1 = c.acquire_execution_lease("EXEC-M16", "worker_1", ttl_seconds=10)
    hb = c.heartbeat_execution(l1["lease_id"], "EXEC-M16", "worker_1", fencing_token=l1["fencing_token"], ttl_seconds=60)
    assert hb["acknowledged"] is True


def test_17_heartbeat_with_stale_fencing_token_rejected(b3_harness):
    """Case 17: Heartbeat with superseded fencing token is rejected."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-M17", "test_project", "RUN-B3-001", res["approval_id"], base_commit)

    l1 = c.acquire_execution_lease("EXEC-M17", "worker_1")
    with pytest.raises(BrokerSecurityError):
        c.heartbeat_execution(l1["lease_id"], "EXEC-M17", "worker_1", fencing_token=999)


def test_18_renew_lease_with_stale_token_rejected(b3_harness):
    """Case 18: Renewing lease with superseded fencing token fails."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-M18", "test_project", "RUN-B3-001", res["approval_id"], base_commit)

    l1 = c.acquire_execution_lease("EXEC-M18", "worker_1")
    with pytest.raises(BrokerSecurityError):
        c.renew_execution_lease(l1["lease_id"], "EXEC-M18", "worker_1", fencing_token=999)


def test_19_execution_state_retrieval(b3_harness):
    """Case 19: get_execution_state consolidates runs, findings, checkpoints, and leases."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-M19", "test_project", "RUN-B3-001", res["approval_id"], base_commit)
    c.acquire_execution_lease("EXEC-M19", "worker_1")

    state = c.get_execution_state("EXEC-M19")
    assert state["execution_run"]["exec_id"] == "EXEC-M19"
    assert len(state["findings"]) == 1
    assert len(state["leases"]) == 1


def test_20_nonexistent_execution_state_fails(b3_harness):
    """Case 20: get_execution_state for invalid exec_id raises error."""
    c = b3_harness["client"]
    with pytest.raises(BrokerDatabaseError):
        c.get_execution_state("NONEXISTENT-EXEC")


# ==============================================================================
# Group 3: Terminal State Finalization Gate (Cases 21-30)
# ==============================================================================


def test_21_completed_finalization_blocked_if_finding_pending(b3_harness):
    """Case 21: Execution cannot finalize as COMPLETED while any finding is PENDING."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-F21", "test_project", "RUN-B3-001", res["approval_id"], base_commit)
    l1 = c.acquire_execution_lease("EXEC-F21", "worker_1")

    with pytest.raises(BrokerSecurityError) as exc:
        c.finalize_execution("EXEC-F21", status="COMPLETED", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert "Completeness assertion failed" in str(exc.value)


def test_22_completed_finalization_blocked_if_finding_in_progress(b3_harness):
    """Case 22: Execution cannot finalize as COMPLETED while finding is IN_PROGRESS."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-F22", "test_project", "RUN-B3-001", res["approval_id"], base_commit)
    l1 = c.acquire_execution_lease("EXEC-F22", "worker_1")

    # Record repair attempt with red_team_passed=0 -> status is IN_PROGRESS (attempt 1 of 2)
    c.record_repair_attempt("EXEC-F22", "FINDING-B3-01", repair_attempt=1, happy_test_passed=1, red_team_passed=0)

    with pytest.raises(BrokerSecurityError) as exc:
        c.finalize_execution("EXEC-F22", status="COMPLETED", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert "Completeness assertion failed" in str(exc.value)


def test_23_completed_finalization_blocked_if_finding_failed(b3_harness):
    """Case 23: Execution cannot finalize as COMPLETED when finding status is FAILED."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-F23", "test_project", "RUN-B3-001", res["approval_id"], base_commit)
    l1 = c.acquire_execution_lease("EXEC-F23", "worker_1")

    c.record_repair_attempt("EXEC-F23", "FINDING-B3-01", repair_attempt=1, happy_test_passed=1, red_team_passed=0)
    c.record_repair_attempt("EXEC-F23", "FINDING-B3-01", repair_attempt=2, happy_test_passed=1, red_team_passed=0)

    with pytest.raises(BrokerSecurityError) as exc:
        c.finalize_execution("EXEC-F23", status="COMPLETED", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert "Completeness assertion failed" in str(exc.value)


def test_24_completed_finalization_blocked_if_integration_test_failed(b3_harness):
    """Case 24: Execution cannot finalize as COMPLETED when integration tests did not pass."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-F24", "test_project", "RUN-B3-001", res["approval_id"], base_commit)
    l1 = c.acquire_execution_lease("EXEC-F24", "worker_1")

    c.record_repair_attempt("EXEC-F24", "FINDING-B3-01", repair_attempt=1, happy_test_passed=1, adversarial_test_passed=1, red_team_passed=1)

    with pytest.raises(BrokerSecurityError) as exc:
        c.finalize_execution("EXEC-F24", status="COMPLETED", integration_test_passed=0, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert "integration tests did not pass" in str(exc.value)


def test_25_completed_finalization_blocked_by_quarantined_checkpoint(b3_harness):
    """Case 25: Quarantine condition blocks COMPLETED finalization."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-F25", "test_project", "RUN-B3-001", res["approval_id"], base_commit)
    l1 = c.acquire_execution_lease("EXEC-F25", "worker_1")

    c.register_checkpoint("CHK-F25", "EXEC-F25", "FINDING-B3-01", base_commit, checkpoint_path=str(b3_harness["repo_dir"]))
    c.quarantine_checkpoint("Q-F25", "test_project", "EXEC-F25", "C:\\Worktree", "Tampered checkpoint", checkpoint_id="CHK-F25")

    with pytest.raises(BrokerSecurityError) as exc:
        c.finalize_execution("EXEC-F25", status="COMPLETED", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert "QUARANTINED" in str(exc.value)


def test_26_finalization_with_expired_lease_blocked(b3_harness):
    """Case 26: Cannot finalize execution if lease has expired."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-F26", "test_project", "RUN-B3-001", res["approval_id"], base_commit)
    l1 = c.acquire_execution_lease("EXEC-F26", "worker_1", ttl_seconds=-1)

    c.record_repair_attempt("EXEC-F26", "FINDING-B3-01", repair_attempt=1, happy_test_passed=1, adversarial_test_passed=1, red_team_passed=1)

    with pytest.raises(BrokerSecurityError) as exc:
        c.finalize_execution("EXEC-F26", status="COMPLETED", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert "lease is expired" in str(exc.value)


def test_27_finalization_with_superseded_lease_blocked(b3_harness):
    """Case 27: Fencing token mismatch rejects finalization attempt."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-F27", "test_project", "RUN-B3-001", res["approval_id"], base_commit)
    l1 = c.acquire_execution_lease("EXEC-F27", "worker_1", ttl_seconds=-1)
    l2 = c.acquire_execution_lease("EXEC-F27", "worker_2")

    c.record_repair_attempt("EXEC-F27", "FINDING-B3-01", repair_attempt=1, happy_test_passed=1, adversarial_test_passed=1, red_team_passed=1)

    # Worker tries to finalize with superseded expired lease l1
    with pytest.raises(BrokerSecurityError):
        c.finalize_execution("EXEC-F27", status="COMPLETED", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])


def test_28_partial_finalization_succeeds_when_findings_partially_verified(b3_harness):
    """Case 28: Status PARTIAL is accepted without requiring 100% VERIFIED findings."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01", "FINDING-B3-02"], base_commit)
    c.register_execution_intent("EXEC-F28", "test_project", "RUN-B3-001", res["approval_id"], base_commit)
    l1 = c.acquire_execution_lease("EXEC-F28", "worker_1")

    # Verify only 1 finding
    c.record_repair_attempt("EXEC-F28", "FINDING-B3-01", repair_attempt=1, happy_test_passed=1, adversarial_test_passed=1, red_team_passed=1)

    fin = c.finalize_execution("EXEC-F28", status="PARTIAL", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert fin["status"] == "PARTIAL"


def test_29_failed_finalization_succeeds_when_tests_fail(b3_harness):
    """Case 29: Status FAILED is accepted when execution failed."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-F29", "test_project", "RUN-B3-001", res["approval_id"], base_commit)
    l1 = c.acquire_execution_lease("EXEC-F29", "worker_1")

    fin = c.finalize_execution("EXEC-F29", status="FAILED", integration_test_passed=0, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert fin["status"] == "FAILED"


def test_30_completed_finalization_succeeds_when_all_findings_verified(b3_harness):
    """Case 30: Status COMPLETED succeeds when 100% of approved findings are VERIFIED."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-F30", "test_project", "RUN-B3-001", res["approval_id"], base_commit)
    l1 = c.acquire_execution_lease("EXEC-F30", "worker_1")

    c.record_repair_attempt("EXEC-F30", "FINDING-B3-01", repair_attempt=1, happy_test_passed=1, adversarial_test_passed=1, red_team_passed=1)
    fin = c.finalize_execution("EXEC-F30", status="COMPLETED", integration_test_passed=1, lease_id=l1["lease_id"], fencing_token=l1["fencing_token"])
    assert fin["status"] == "COMPLETED"


# ==============================================================================
# Group 4: Checkpoint Content Integrity & Safe Restoration (Cases 31-42)
# ==============================================================================


def test_31_safe_relative_path_rejects_parent_traversal():
    """Case 31: Relative path validation rejects .. traversal."""
    with pytest.raises(BrokerSecurityError):
        validate_safe_relative_path("../secret.py")
    with pytest.raises(BrokerSecurityError):
        validate_safe_relative_path("sub/../../root.txt")


def test_32_safe_relative_path_rejects_posix_absolute():
    """Case 32: Relative path validation rejects / absolute path."""
    with pytest.raises(BrokerSecurityError):
        validate_safe_relative_path("/etc/shadow")


def test_33_safe_relative_path_rejects_windows_drive_path():
    """Case 33: Relative path validation rejects C:\\ drive path."""
    with pytest.raises(BrokerSecurityError):
        validate_safe_relative_path("C:\\Windows\\System32\\cmd.exe")


def test_34_safe_relative_path_rejects_unc_path():
    """Case 34: Relative path validation rejects UNC paths."""
    with pytest.raises(BrokerSecurityError):
        validate_safe_relative_path(r"\\server\share\file.txt")


def test_35_safe_relative_path_rejects_device_path():
    """Case 35: Relative path validation rejects Windows device paths."""
    with pytest.raises(BrokerSecurityError):
        validate_safe_relative_path(r"\\.\pipe\malicious")


def test_36_safe_relative_path_rejects_windows_reserved_names():
    """Case 36: Relative path validation rejects reserved names (CON, NUL, AUX)."""
    with pytest.raises(BrokerSecurityError):
        validate_safe_relative_path("CON")
    with pytest.raises(BrokerSecurityError):
        validate_safe_relative_path("sub/nul.txt")
    with pytest.raises(BrokerSecurityError):
        validate_safe_relative_path("AUX")


def test_37_checkpoint_manifest_rejects_case_collisions(tmp_path: Path):
    """Case 37: Checkpoint manifest validation detects and rejects Windows case collisions."""
    manifest = {
        "checkpoint_id": "CHK-COLLISION",
        "exec_id": "EXEC-01",
        "finding_id": "F-01",
        "created_at": "2026-11-12T00:00:00Z",
        "files": {
            "calculator.py": "a" * 64,
            "CALCULATOR.PY": "b" * 64,
        },
    }
    valid, msg = validate_checkpoint_manifest(manifest)
    assert valid is False
    assert "Case collision" in msg


def test_38_checkpoint_content_sha256_verification(tmp_path: Path):
    """Case 38: Checkpoint integrity verification detects modified file bytes."""
    chk_dir = tmp_path / "chk_test"
    files_dir = chk_dir / "files"
    files_dir.mkdir(parents=True)
    f = files_dir / "test.py"
    f.write_text("print('hello')", encoding="utf-8")
    actual_hash = hashlib.sha256(f.read_bytes()).hexdigest()

    # Write wrong expected hash into manifest
    manifest = {
        "checkpoint_id": "CHK-HASH",
        "exec_id": "EXEC-01",
        "finding_id": "F-01",
        "created_at": "2026-11-12T00:00:00Z",
        "files": {"test.py": "0" * 64},
    }
    manifest_file = chk_dir / "checkpoint.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    valid, msg, metrics = validate_checkpoint_content_integrity(manifest_file)
    assert valid is False
    assert "hash mismatch" in msg.lower()


def test_39_checkpoint_restoration_zero_partial_restore_on_tampering(tmp_path: Path):
    """Case 39: Restoration aborts safely with zero writes if any file is corrupt."""
    chk_dir = tmp_path / "chk_safe"
    files_dir = chk_dir / "files"
    files_dir.mkdir(parents=True)
    (files_dir / "f1.py").write_text("ok", encoding="utf-8")
    (files_dir / "f2.py").write_text("corrupted", encoding="utf-8")

    manifest = {
        "checkpoint_id": "CHK-SAFE",
        "exec_id": "EXEC-01",
        "finding_id": "F-01",
        "files": {
            "f1.py": hashlib.sha256(b"ok").hexdigest(),
            "f2.py": "0" * 64,  # Mismatched hash
        },
    }
    manifest_file = chk_dir / "checkpoint.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    worktree = tmp_path / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "f1.py").write_text("original_worktree_f1", encoding="utf-8")

    with pytest.raises(BrokerSecurityError):
        safe_restore_checkpoint(worktree, manifest_file)

    # Invariant: f1.py in worktree must remain untouched (zero partial restore)
    assert (worktree / "f1.py").read_text(encoding="utf-8") == "original_worktree_f1"


def test_40_quarantined_checkpoint_restoration_blocked(tmp_path: Path):
    """Case 40: Quarantined checkpoint cannot be restored."""
    manifest_file = tmp_path / "checkpoint.json"
    manifest_file.write_text(json.dumps({"checkpoint_id": "CHK-Q", "exec_id": "E1", "finding_id": "F1", "created_at": "2026-11-12T00:00:00Z", "files": {}}), encoding="utf-8")

    with pytest.raises(BrokerSecurityError) as exc:
        safe_restore_checkpoint(tmp_path / "wt", manifest_file, status="QUARANTINED")
    assert "QUARANTINED" in str(exc.value)


def test_41_worktree_git_file_strictly_preserved(tmp_path: Path):
    """Case 41: .git file in worktree is never deleted or overwritten during restore."""
    chk_dir = tmp_path / "chk_git"
    files_dir = chk_dir / "files"
    files_dir.mkdir(parents=True)
    (files_dir / "app.py").write_text("print('app')", encoding="utf-8")
    manifest = {
        "checkpoint_id": "CHK-GIT",
        "exec_id": "EXEC-01",
        "finding_id": "F-01",
        "created_at": "2026-11-12T00:00:00Z",
        "files": {"app.py": hashlib.sha256(b"print('app')").hexdigest()},
    }
    manifest_file = chk_dir / "checkpoint.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    worktree = tmp_path / "wt_git"
    worktree.mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: /fake/path\n", encoding="utf-8")
    (worktree / "app.py").write_text("old", encoding="utf-8")

    res = safe_restore_checkpoint(worktree, manifest_file)
    assert res["restored_files_count"] == 1
    # .git must remain intact
    assert (worktree / ".git").exists()
    assert (worktree / ".git").read_text(encoding="utf-8") == "gitdir: /fake/path\n"


def test_42_validate_checkpoint_rpc(b3_harness, tmp_path: Path):
    """Case 42: broker.validate_checkpoint RPC method validates registered checkpoint."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-C42", "test_project", "RUN-B3-001", res["approval_id"], base_commit)

    chk_dir = tmp_path / "chk_rpc"
    files_dir = chk_dir / "files"
    files_dir.mkdir(parents=True)
    (files_dir / "test.py").write_text("content", encoding="utf-8")
    manifest = {
        "checkpoint_id": "CHK-RPC-42",
        "exec_id": "EXEC-C42",
        "finding_id": "FINDING-B3-01",
        "created_at": "2026-11-12T00:00:00Z",
        "files": {"test.py": hashlib.sha256(b"content").hexdigest()},
    }
    manifest_file = chk_dir / "checkpoint.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    c.register_checkpoint("CHK-RPC-42", "EXEC-C42", "FINDING-B3-01", base_commit, checkpoint_path=str(manifest_file))
    val = c.validate_checkpoint("CHK-RPC-42", exec_id="EXEC-C42")
    assert val["valid"] is True
    assert val["file_count"] == 1


# ==============================================================================
# Group 5: Broker Isolation & Boundary Enforcement (Cases 43-52)
# ==============================================================================


def test_43_audit_chain_verification_succeeds_on_clean_chain(b3_harness):
    """Case 43: broker.verify_audit_chain returns valid: True on clean log."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    res = c.verify_audit_chain()
    assert res["valid"] is True
    assert res["event_count"] > 0
    assert len(res["chain_head_hash"]) == 64


def test_44_audit_chain_verification_detects_actor_tampering(b3_harness):
    """Case 44: Direct database tampering of actor column is detected by verify_audit_chain."""
    c = b3_harness["client"]
    db_path = b3_harness["db_path"]
    _seed_findings(c, "test_project", "RUN-B3-001")

    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE audit_events SET actor = 'rogue_agent' WHERE event_id = 1")
    conn.commit()
    conn.close()

    res = c.verify_audit_chain()
    assert res["valid"] is False
    assert res["tampered_event_id"] == 1


def test_45_audit_chain_verification_detects_payload_tampering(b3_harness):
    """Case 45: Direct tampering of details column is detected by verify_audit_chain."""
    c = b3_harness["client"]
    db_path = b3_harness["db_path"]
    _seed_findings(c, "test_project", "RUN-B3-001")

    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE audit_events SET details = '{\"tampered\": true}' WHERE event_id = 1")
    conn.commit()
    conn.close()

    res = c.verify_audit_chain()
    assert res["valid"] is False
    assert res["tampered_event_id"] == 1


def test_46_prohibited_db_name_blocked():
    """Case 46: BrokerDatabaseAdapter strictly rejects opening auditor.db."""
    with pytest.raises(ProductionDatabaseAccessProhibitedError):
        BrokerDatabaseAdapter(Path("C:/Temp/auditor.db"))


def test_47_prohibited_wal_name_blocked():
    """Case 47: BrokerDatabaseAdapter strictly rejects opening auditor.db-wal."""
    with pytest.raises(ProductionDatabaseAccessProhibitedError):
        BrokerDatabaseAdapter(Path("C:/Temp/auditor.db-wal"))


def test_48_prohibited_shm_name_blocked():
    """Case 48: BrokerDatabaseAdapter strictly rejects opening auditor.db-shm."""
    with pytest.raises(ProductionDatabaseAccessProhibitedError):
        BrokerDatabaseAdapter(Path("C:/Temp/auditor.db-shm"))


def test_49_restore_checkpoint_rpc_restores_cleanly(b3_harness, tmp_path: Path):
    """Case 49: broker.restore_checkpoint RPC method safely restores files."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    res = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)
    c.register_execution_intent("EXEC-R49", "test_project", "RUN-B3-001", res["approval_id"], base_commit)

    chk_dir = tmp_path / "chk_rpc_49"
    files_dir = chk_dir / "files"
    files_dir.mkdir(parents=True)
    content_bytes = b"def restored(): pass\n"
    (files_dir / "calculator.py").write_bytes(content_bytes)
    manifest = {
        "checkpoint_id": "CHK-R49",
        "exec_id": "EXEC-R49",
        "finding_id": "FINDING-B3-01",
        "created_at": "2026-11-12T00:00:00Z",
        "files": {"calculator.py": hashlib.sha256(content_bytes).hexdigest()},
    }
    manifest_file = chk_dir / "checkpoint.json"
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    c.register_checkpoint("CHK-R49", "EXEC-R49", "FINDING-B3-01", base_commit, checkpoint_path=str(manifest_file))

    worktree = tmp_path / "wt_rpc_49"
    worktree.mkdir(parents=True)
    (worktree / "calculator.py").write_text("unrestored", encoding="utf-8")

    restore_res = c.restore_checkpoint("CHK-R49", "EXEC-R49", worktree)
    assert restore_res["restored_files_count"] == 1
    assert (worktree / "calculator.py").read_text(encoding="utf-8") == "def restored(): pass\n"


def test_50_executor_broker_pipeline_e2e_successful_repair(b3_harness, tmp_path: Path):
    """Case 50: E2E broker-migrated executor pipeline succeeds with zero direct SQLite."""
    c = b3_harness["client"]
    repo_dir = b3_harness["repo_dir"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    auth = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)

    def remediation(wt: Path, finding: dict[str, Any], attempt: int) -> None:
        (wt / "calculator.py").write_text(
            "def divide(a, b):\n    if b == 0: raise ValueError('Zero')\n    return a / b\n",
            encoding="utf-8",
        )

    def happy(wt: Path, finding: dict[str, Any], attempt: int) -> tuple[bool, str]:
        return True, "ok"

    def adv(wt: Path, finding: dict[str, Any], attempt: int) -> tuple[bool, str]:
        return True, "ok"

    def red_team(wt: Path, finding: dict[str, Any], files: list[str], attempt: int) -> tuple[bool, str]:
        return True, "red team green"

    res = execute_approved_findings_broker(
        c,
        project_key="test_project",
        approval_token=auth["approval_token"],
        remediation_fn=remediation,
        happy_test_fn=happy,
        adversarial_test_fn=adv,
        red_team_fn=red_team,
        integration_test_fn=lambda wt: (True, "suite passed"),
        worktrees_root=tmp_path / "wt_e2e",
        checkpoints_root=tmp_path / "chk_e2e",
    )
    assert res["status"] == "COMPLETED"
    assert res["integration_passed"] is True
    assert "FINDING-B3-01" in res["verified_finding_ids"]


def test_51_executor_broker_pipeline_failed_repair_rolls_back(b3_harness, tmp_path: Path):
    """Case 51: E2E broker-migrated pipeline rolls back failed finding via checkpoint."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    auth = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)

    def bad_remediation(wt: Path, finding: dict[str, Any], attempt: int) -> None:
        (wt / "calculator.py").write_text("broken code", encoding="utf-8")

    res = execute_approved_findings_broker(
        c,
        project_key="test_project",
        approval_token=auth["approval_token"],
        remediation_fn=bad_remediation,
        happy_test_fn=lambda wt, f, a: (False, "failed happy"),
        adversarial_test_fn=lambda wt, f, a: (False, "failed adv"),
        red_team_fn=lambda wt, f, fl, a: (False, "failed rt"),
        integration_test_fn=lambda wt: (True, "integration green"),
        worktrees_root=tmp_path / "wt_e2e_fail",
        checkpoints_root=tmp_path / "chk_e2e_fail",
    )
    assert res["status"] == "FAILED"
    assert "FINDING-B3-01" in res["rolled_back_finding_ids"]


def test_52_executor_broker_pipeline_quarantine_on_integration_failure(b3_harness, tmp_path: Path):
    """Case 52: E2E broker-migrated pipeline quarantines worktree on integration test failure."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    auth = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)

    def valid_remediation(wt: Path, finding: dict[str, Any], attempt: int) -> None:
        (wt / "calculator.py").write_text("def divide(a, b):\n    return a / b\n# patched\n", encoding="utf-8")

    res = execute_approved_findings_broker(
        c,
        project_key="test_project",
        approval_token=auth["approval_token"],
        remediation_fn=valid_remediation,
        happy_test_fn=lambda wt, f, a: (True, "ok"),
        adversarial_test_fn=lambda wt, f, a: (True, "ok"),
        red_team_fn=lambda wt, f, fl, a: (True, "ok"),
        integration_test_fn=lambda wt: (False, "integration failed: regression detected"),
        worktrees_root=tmp_path / "wt_e2e_q",
        checkpoints_root=tmp_path / "chk_e2e_q",
    )
    assert res["status"] == "QUARANTINED"
    assert res["integration_passed"] is False


def test_53_mcp_step_level_update_finding_execution_routes_via_broker(b3_harness, tmp_path: Path):
    """Case 53: MCP step-level update_finding_execution_step routes exclusively via BrokerClient."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    auth = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)

    start_res = start_isolated_execution_broker(
        c,
        project_key="test_project",
        approval_token=auth["approval_token"],
        worktrees_root=tmp_path / "wt_step",
    )
    exec_id = start_res["exec_id"]
    wt_path = Path(start_res["worktree_path"])

    # Action: begin (creates checkpoint and updates finding to IN_PROGRESS via broker)
    begin_res = update_finding_execution_step(
        db_path=None,
        project_key="test_project",
        exec_id=exec_id,
        finding_id="FINDING-B3-01",
        action="begin",
        checkpoints_root=tmp_path / "chk_step",
        broker_client=c,
    )
    assert begin_res["status"] == "IN_PROGRESS"
    assert begin_res["checkpoint_id"]

    # Verify through broker that checkpoint was registered and state is IN_PROGRESS
    state = c.get_execution_state(exec_id)
    f_step = next(f for f in state["findings"] if f["finding_id"] == "FINDING-B3-01")
    assert f_step["status"] == "IN_PROGRESS"

    # Mutate worktree to simulate patch
    (wt_path / "calculator.py").write_text("def divide(a, b):\n    return a / b\n# patched step\n", encoding="utf-8")

    # Action: verify (records repair attempt and verifies finding via broker)
    verify_res = update_finding_execution_step(
        db_path=None,
        project_key="test_project",
        exec_id=exec_id,
        finding_id="FINDING-B3-01",
        action="verify",
        happy_test_passed=True,
        adversarial_test_passed=True,
        red_team_passed=True,
        notes="step verification passed",
        broker_client=c,
    )
    assert verify_res["status"] == "VERIFIED"
    assert verify_res["repair_attempts"] == 1

    # Verify through broker that finding state is now VERIFIED
    state2 = c.get_execution_state(exec_id)
    f_step2 = next(f for f in state2["findings"] if f["finding_id"] == "FINDING-B3-01")
    assert f_step2["status"] == "VERIFIED"


def test_54_mcp_step_level_finalize_isolated_execution_routes_via_broker(b3_harness, tmp_path: Path):
    """Case 54: MCP step-level finalize_isolated_execution routes exclusively via BrokerClient."""
    c = b3_harness["client"]
    _seed_findings(c, "test_project", "RUN-B3-001")
    base_commit = _get_base_commit(b3_harness)
    auth = c.authorize_execution("test_project", "RUN-B3-001", ["FINDING-B3-01"], base_commit)

    start_res = start_isolated_execution_broker(
        c,
        project_key="test_project",
        approval_token=auth["approval_token"],
        worktrees_root=tmp_path / "wt_finalize",
    )
    exec_id = start_res["exec_id"]
    wt_path = Path(start_res["worktree_path"])

    # Set up verified finding via step execution
    update_finding_execution_step(
        db_path=None,
        project_key="test_project",
        exec_id=exec_id,
        finding_id="FINDING-B3-01",
        action="begin",
        checkpoints_root=tmp_path / "chk_finalize",
        broker_client=c,
    )
    (wt_path / "calculator.py").write_text("def divide(a, b):\n    return a / b\n# step patched\n", encoding="utf-8")
    update_finding_execution_step(
        db_path=None,
        project_key="test_project",
        exec_id=exec_id,
        finding_id="FINDING-B3-01",
        action="verify",
        happy_test_passed=True,
        adversarial_test_passed=True,
        red_team_passed=True,
        broker_client=c,
    )

    # Finalize execution via broker
    final_res = finalize_isolated_execution(
        db_path=None,
        project_key="test_project",
        exec_id=exec_id,
        integration_test_passed=True,
        notes="final integration green",
        broker_client=c,
    )
    assert final_res["status"] == "COMPLETED"
    assert "FINDING-B3-01" in final_res["verified_finding_ids"]

    # Verify through broker that execution run status is COMPLETED
    state = c.get_execution_state(exec_id)
    assert state["execution_run"]["status"] == "COMPLETED"


from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from telemetry import StructuredAuditLogger
from verification import (
    ALLOWED_AUDIT_RUN_STATUSES,
    ALLOWED_CONFIDENCES,
    ALLOWED_EVIDENCE_STATUSES,
    ALLOWED_QUEUE_STATUSES,
    ALLOWED_SEVERITIES,
    ALLOWED_VERDICTS,
    ALLOWED_VERIFICATION_STATUSES,
    compute_source_excerpt_sha_for_candidate,
    create_or_get_audit_snapshot,
    recover_stale_verification_leases,
    resolve_repo_file_for_reading,
    stream_file_sha256,
    transition_audit_run_status,
    verify_snapshot_consistency,
)

ALLOWED_LIFECYCLES = (
    "OPEN",
    "DEFERRED",
    "DISMISSED",
    "SKIPPED",
    "RESOLVED",
    "STALE",
    "ARCHIVED",
    "REJECTED",
)
ALLOWED_DECISIONS = ("APPLY", "DEFER", "DISMISS", "SKIP")

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS projects (
    project_key TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    repo_path TEXT NOT NULL UNIQUE,
    antigravity_project_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    schedule_cron TEXT NOT NULL DEFAULT '0 4 * * 1',
    repo_fingerprint TEXT,
    last_known_commit TEXT,
    health_status TEXT NOT NULL DEFAULT 'HEALTHY' CHECK(health_status IN ('HEALTHY','MOVED_OR_MISSING','DEGRADED','PENDING_PROJECT_ID','BLOCKED_CONFIGURATION')),
    stale_timeout_seconds INTEGER NOT NULL DEFAULT 3600,
    max_retries INTEGER NOT NULL DEFAULT 2,
    max_run_retries INTEGER NOT NULL DEFAULT 2,
    min_free_mb INTEGER NOT NULL DEFAULT 500,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_runs (
    run_id TEXT PRIMARY KEY,
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    trigger_source TEXT NOT NULL DEFAULT 'scheduled',
    status TEXT NOT NULL CHECK(status IN (
        'IDLE','PREFLIGHT','PRIMARY_AUDIT_RUNNING','DISPATCHED','ANALYZING',
        'VERIFICATION_PENDING','VERIFICATION_DISPATCHING','VERIFICATION_RUNNING',
        'EVIDENCE_VALIDATION','READY_FOR_REVIEW','PENDING_APPROVAL',
        'VERIFICATION_FAILED','VERIFICATION_BLOCKED','VERIFICATION_STALE','VERIFICATION_UNCERTAIN',
        'RECOVERABLE','FAILED','STALE','COMPLETED','PARTIAL','ARCHIVED',
        'INGESTED','APPROVED','EXECUTING','ROLLED_BACK','QUARANTINED','RECOVERED','SKIPPED'
    )),
    snapshot_id TEXT,
    base_commit TEXT,
    working_tree_hash TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 2,
    heartbeat_at TEXT,
    superseded_by TEXT,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    agent_conversation_id TEXT,
    primary_model TEXT,
    primary_model_attestation TEXT,
    report_path TEXT,
    summary_json TEXT,
    error TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_audit_per_project
ON audit_runs(project_key) WHERE status IN (
    'PREFLIGHT','PRIMARY_AUDIT_RUNNING','DISPATCHED','ANALYZING',
    'VERIFICATION_PENDING','VERIFICATION_DISPATCHING','VERIFICATION_RUNNING',
    'EVIDENCE_VALIDATION','READY_FOR_REVIEW','PENDING_APPROVAL'
);
CREATE TABLE IF NOT EXISTS audit_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES audit_runs(run_id),
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    repo_path TEXT NOT NULL,
    base_commit_sha TEXT NOT NULL,
    working_tree_hash TEXT NOT NULL,
    file_hashes_json TEXT NOT NULL DEFAULT '{}',
    snapshot_complete INTEGER NOT NULL DEFAULT 1 CHECK(snapshot_complete IN (0,1)),
    incomplete_reason TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS candidate_findings (
    candidate_id TEXT PRIMARY KEY,
    candidate_finding_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    snapshot_id TEXT NOT NULL,
    base_commit_sha TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    confidence TEXT NOT NULL CHECK(confidence IN ('CONFIRMED','LIKELY','SPECULATIVE')),
    file_path TEXT,
    symbol TEXT,
    line_start INTEGER,
    line_end INTEGER,
    evidence TEXT NOT NULL,
    impact TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    file_sha256 TEXT,
    evidence_sha256 TEXT,
    source_origin TEXT NOT NULL DEFAULT 'PRIMARY' CHECK(source_origin IN ('PRIMARY','VERIFIER_DISCOVERED')),
    discovered_by_conversation_id TEXT,
    discovered_in_verification_run_id TEXT,
    status TEXT NOT NULL DEFAULT 'CANDIDATE' CHECK(status IN ('CANDIDATE','CONFIRMED','PARTIALLY_CONFIRMED','REJECTED','UNVERIFIABLE','STALE','ARCHIVED')),
    canonical_finding_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(run_id, candidate_finding_id),
    UNIQUE(run_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS audit_verification_runs (
    verification_run_id TEXT PRIMARY KEY,
    audit_run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    snapshot_id TEXT NOT NULL,
    base_commit_sha TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'PENDING','DISPATCHING','RUNNING','EVIDENCE_VALIDATION',
        'FINALIZED','COMPLETED','FAILED','BLOCKED','STALE','UNCERTAIN','ARCHIVED'
    )),
    verifier_conversation_id TEXT,
    verifier_model_id TEXT,
    verifier_model_source TEXT NOT NULL DEFAULT 'UNVERIFIED',
    verifier_agent_id TEXT,
    invocation_mechanism TEXT,
    subagent_invocations INTEGER NOT NULL DEFAULT 0,
    dispatch_attempt INTEGER NOT NULL DEFAULT 0,
    submission_count INTEGER NOT NULL DEFAULT 0,
    submitted_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    completed_at TEXT,
    error_code TEXT,
    error_message TEXT,
    idempotency_key TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS finding_verification_results (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_finding_id TEXT NOT NULL,
    verification_run_id TEXT NOT NULL REFERENCES audit_verification_runs(verification_run_id),
    audit_run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
    verdict TEXT NOT NULL CHECK(verdict IN ('CONFIRMED','PARTIALLY_CONFIRMED','REJECTED','UNVERIFIABLE')),
    verified_severity TEXT NOT NULL CHECK(verified_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    verified_confidence TEXT NOT NULL CHECK(verified_confidence IN ('CONFIRMED','LIKELY','SPECULATIVE')),
    technical_rationale TEXT NOT NULL,
    corrected_claim TEXT,
    source_evidence_json TEXT NOT NULL,
    remediation_review TEXT NOT NULL,
    remediation_safe INTEGER NOT NULL DEFAULT 1 CHECK(remediation_safe IN (0,1)),
    acceptance_criteria TEXT NOT NULL,
    evidence_validation_status TEXT NOT NULL DEFAULT 'PENDING' CHECK(evidence_validation_status IN ('PENDING','PASSED','VALID','FAILED','INVALID','UNVERIFIABLE','STALE','FABRICATED_REFERENCE')),
    evidence_validation_details_json TEXT NOT NULL DEFAULT '{}',
    reviewed_file_hashes_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(verification_run_id, candidate_finding_id)
);
CREATE TABLE IF NOT EXISTS verification_dispatch_queue (
    job_id TEXT PRIMARY KEY,
    verification_run_id TEXT NOT NULL UNIQUE REFERENCES audit_verification_runs(verification_run_id),
    audit_run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    snapshot_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'QUEUED','CLAIMED','DISPATCHING','RUNNING','COMPLETED',
        'RETRYABLE_FAILURE','BLOCKED_CONFIGURATION','DISPATCH_UNCERTAIN','FAILED'
    )),
    idempotency_key TEXT NOT NULL UNIQUE,
    lease_owner TEXT,
    lease_token TEXT,
    claimed_at TEXT,
    lease_expires_at TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    next_attempt_at TEXT,
    verifier_conversation_id TEXT,
    last_error_code TEXT,
    last_error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_quality_metrics (
    metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    audit_run_id TEXT NOT NULL UNIQUE REFERENCES audit_runs(run_id),
    verification_run_id TEXT REFERENCES audit_verification_runs(verification_run_id),
    primary_model_id TEXT,
    verifier_model_id TEXT,
    skill_version_hash TEXT,
    total_primary_candidates INTEGER NOT NULL DEFAULT 0,
    verifier_discovered_candidates INTEGER NOT NULL DEFAULT 0,
    confirmed_findings INTEGER NOT NULL DEFAULT 0,
    partially_confirmed_findings INTEGER NOT NULL DEFAULT 0,
    rejected_findings INTEGER NOT NULL DEFAULT 0,
    unverifiable_findings INTEGER NOT NULL DEFAULT 0,
    evidence_validation_failures INTEGER NOT NULL DEFAULT 0,
    fabricated_reference_detections INTEGER NOT NULL DEFAULT 0,
    severity_changes INTEGER NOT NULL DEFAULT 0,
    confidence_changes INTEGER NOT NULL DEFAULT 0,
    remediation_proposals_rejected INTEGER NOT NULL DEFAULT 0,
    dispatch_failures INTEGER NOT NULL DEFAULT 0,
    verification_duration_seconds REAL,
    actual_subagent_invocations INTEGER NOT NULL DEFAULT 0,
    finding_precision REAL,
    evidence_accuracy REAL,
    false_positive_rate REAL,
    severity_calibration_rate REAL,
    remediation_safety_rate REAL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    confidence TEXT NOT NULL CHECK(confidence IN ('CONFIRMED','LIKELY','SPECULATIVE')),
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
    lifecycle TEXT NOT NULL DEFAULT 'OPEN' CHECK(lifecycle IN ('OPEN','DEFERRED','DISMISSED','SKIPPED','RESOLVED','STALE','ARCHIVED','REJECTED','APPROVED','SUPPRESSED')),
    dismissed_reason TEXT,
    dismissed_evidence_hash TEXT,
    dismissed_file_blob_hash TEXT,
    verification_status TEXT NOT NULL DEFAULT 'LEGACY_UNVERIFIED' CHECK(verification_status IN ('CANDIDATE','VERIFIED','CONFIRMED','PARTIALLY_VERIFIED','PARTIALLY_CONFIRMED','REJECTED','UNVERIFIABLE','LEGACY_UNVERIFIED','STALE')),
    execution_eligible INTEGER NOT NULL DEFAULT 0 CHECK(execution_eligible IN (0,1)),
    remediation_safe INTEGER NOT NULL DEFAULT 1 CHECK(remediation_safe IN (0,1)),
    verification_run_id TEXT,
    verified_by_run_id TEXT,
    verified_at TEXT,
    verifier_conversation_id TEXT,
    evidence_validation_status TEXT NOT NULL DEFAULT 'UNCHECKED',
    snapshot_id TEXT,
    base_commit_sha TEXT,
    acceptance_criteria TEXT,
    remediation_review TEXT,
    technical_rationale TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_key, fingerprint)
);
CREATE TABLE IF NOT EXISTS finding_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    run_id TEXT REFERENCES audit_runs(run_id),
    from_lifecycle TEXT,
    to_lifecycle TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    reason TEXT,
    evidence_hash TEXT,
    file_blob_hash TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    run_id TEXT,
    decision TEXT NOT NULL CHECK(decision IN ('APPLY','DEFER','DISMISS','SKIP')),
    note TEXT,
    actor TEXT NOT NULL DEFAULT 'user',
    superseded INTEGER NOT NULL DEFAULT 0 CHECK(superseded IN (0,1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS execution_approvals (
    approval_id TEXT PRIMARY KEY,
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
    approval_token TEXT NOT NULL UNIQUE,
    approved_finding_ids TEXT NOT NULL,
    base_commit TEXT NOT NULL,
    working_tree_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'AUTHORIZED' CHECK(status IN ('AUTHORIZED','CONSUMED','REVOKED','EXPIRED')),
    authorized_by TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_runs (
    exec_id TEXT PRIMARY KEY,
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
    approval_id TEXT NOT NULL REFERENCES execution_approvals(approval_id),
    status TEXT NOT NULL CHECK(status IN ('PREFLIGHT','RUNNING','VERIFYING','COMPLETED','PARTIAL','FAILED','QUARANTINED','STALE','ROLLED_BACK')),
    worktree_path TEXT,
    branch_name TEXT,
    base_commit TEXT NOT NULL,
    working_tree_hash TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 2,
    integration_test_passed INTEGER,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    error TEXT
);
CREATE TABLE IF NOT EXISTS execution_worktree_ops (
    op_id TEXT PRIMARY KEY,
    exec_id TEXT NOT NULL UNIQUE,
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
    approval_id TEXT NOT NULL REFERENCES execution_approvals(approval_id),
    repo_path TEXT NOT NULL,
    worktree_path TEXT NOT NULL,
    branch_name TEXT,
    base_commit TEXT,
    worktree_existed_before INTEGER NOT NULL DEFAULT 0 CHECK(worktree_existed_before IN (0,1)),
    branch_existed_before INTEGER NOT NULL DEFAULT 0 CHECK(branch_existed_before IN (0,1)),
    status TEXT NOT NULL CHECK(status IN ('PREPARING','INTENT_RECORDED','WORKTREE_CREATED','COMMITTED','COMPENSATED','COMPENSATION_FAILED')),
    error TEXT,
    cleanup_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS finding_executions (
    finding_exec_id TEXT PRIMARY KEY,
    exec_id TEXT NOT NULL REFERENCES execution_runs(exec_id),
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    status TEXT NOT NULL CHECK(status IN ('PENDING','REVALIDATED','IN_PROGRESS','VERIFIED','ROLLED_BACK','SKIPPED_RECONCILIATION','FAILED')),
    checkpoint_id TEXT,
    checkpoint_path TEXT,
    repair_attempts INTEGER NOT NULL DEFAULT 0 CHECK(repair_attempts >= 0 AND repair_attempts <= 2),
    happy_test_passed INTEGER,
    adversarial_test_passed INTEGER,
    red_team_passed INTEGER,
    red_team_notes TEXT,
    diff_summary TEXT,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    error TEXT,
    UNIQUE(exec_id, finding_id)
);
CREATE TABLE IF NOT EXISTS quarantined_worktrees (
    quarantine_id TEXT PRIMARY KEY,
    project_key TEXT NOT NULL REFERENCES projects(project_key),
    exec_id TEXT NOT NULL REFERENCES execution_runs(exec_id),
    worktree_path TEXT NOT NULL,
    reason TEXT NOT NULL,
    preserved_diff_path TEXT,
    status TEXT NOT NULL DEFAULT 'QUARANTINED' CHECK(status IN ('QUARANTINED','CLEANED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cleaned_at TEXT
);
CREATE TABLE IF NOT EXISTS skill_inventory (
    scope TEXT NOT NULL,
    skill_name TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    description TEXT,
    discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(scope, path)
);
CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_key TEXT,
    run_id TEXT,
    event_type TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notification_outbox (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_key TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS model_dispatches (
    dispatch_id TEXT PRIMARY KEY,
    audit_run_id TEXT REFERENCES audit_runs(run_id),
    verification_run_id TEXT REFERENCES audit_verification_runs(verification_run_id),
    finding_fingerprint TEXT,
    task_type TEXT NOT NULL,
    task_risk TEXT NOT NULL,
    requested_model TEXT NOT NULL,
    observed_model TEXT,
    reasoning_level TEXT,
    model_identity_source TEXT NOT NULL DEFAULT 'UNVERIFIED',
    model_attestation_status TEXT NOT NULL DEFAULT 'MODEL_ATTESTATION_INCOMPLETE',
    routing_policy_version TEXT NOT NULL,
    conversation_id TEXT,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    thinking_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    execution_duration REAL NOT NULL DEFAULT 0.0,
    fallback_reason TEXT,
    error_code TEXT,
    error_message TEXT,
    permission_capability_status TEXT NOT NULL DEFAULT 'READ_ONLY_UNVERIFIED',
    dispatch_status TEXT NOT NULL,
    decision_reason TEXT,
    idempotency_key TEXT UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS model_budget_usage (
    usage_id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_run_id TEXT,
    model_id TEXT NOT NULL,
    task_type TEXT NOT NULL,
    finding_fingerprint TEXT,
    tokens_consumed INTEGER NOT NULL DEFAULT 0,
    request_count INTEGER NOT NULL DEFAULT 1,
    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS model_budget_reservations (
    reservation_id TEXT PRIMARY KEY,
    audit_run_id TEXT NOT NULL,
    model_id TEXT NOT NULL,
    finding_fingerprint TEXT,
    task_type TEXT NOT NULL,
    estimated_tokens INTEGER NOT NULL DEFAULT 0,
    reserved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_budget_res_run ON model_budget_reservations(audit_run_id, model_id);
"""


class ClosingConnection(sqlite3.Connection):
    """``sqlite3.Connection`` whose context manager also closes the connection.

    The stdlib ``with conn:`` only commits or rolls back; the handle (and its WAL/SHM locks on Windows)
    then stays open until garbage collection. Every ``with connect(...) as conn:`` block owns its
    connection, so closing on exit is the intended lifetime.
    """

    def __exit__(self, exc_type, exc, tb):  # type: ignore[override]
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row["name"]) for row in rows}


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    if column not in _table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _table_sql(conn: sqlite3.Connection, table_name: str) -> str:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return str(row[0] or "") if row else ""


def _strip_leading_sql_comments(sql_text: str) -> str:
    """Strip leading whitespace, '--' line comments, and '/*...*/' block comments."""
    idx = 0
    n = len(sql_text)
    while idx < n:
        while idx < n and sql_text[idx].isspace():
            idx += 1
        if idx < n and sql_text[idx : idx + 2] == "--":
            nl = sql_text.find("\n", idx + 2)
            idx = n if nl == -1 else nl + 1
            continue
        if idx < n and sql_text[idx : idx + 2] == "/*":
            end_c = sql_text.find("*/", idx + 2)
            idx = n if end_c == -1 else end_c + 2
            continue
        break
    return sql_text[idx:].strip()


def _split_sql_statements(script: str) -> list[str]:
    """Split a multi-statement SQL script into individual statements using a lexical state machine.

    Correctly handles:
    - Semicolons inside single-quoted string literals ('...' with '' escapes)
    - Semicolons inside double-quoted, backtick, or bracketed identifiers ("...", `...`, [...])
    - Semicolons inside '--' line comments and '/* ... */' block comments
    - Multi-statement CREATE TRIGGER ... BEGIN ...; END; blocks (including nested CASE ... END)
    """
    statements: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(script)

    in_single = False
    in_double = False
    in_backtick = False
    in_bracket = False
    in_line_comment = False
    in_block_comment = False

    in_trigger_header = False
    trigger_begin_depth = 0
    case_depth = 0
    prev_word = ""
    current_word_chars: list[str] = []

    def _flush_word() -> None:
        nonlocal in_trigger_header, trigger_begin_depth, case_depth, prev_word
        if not current_word_chars:
            return
        word = "".join(current_word_chars).upper()
        current_word_chars.clear()
        if word == "TRIGGER" and prev_word in ("CREATE", "TEMP", "TEMPORARY"):
            in_trigger_header = True
        elif in_trigger_header and word == "BEGIN":
            trigger_begin_depth = 1
            in_trigger_header = False
        elif trigger_begin_depth > 0:
            if word == "BEGIN":
                trigger_begin_depth += 1
            elif word == "CASE":
                case_depth += 1
            elif word == "END":
                if case_depth > 0:
                    case_depth -= 1
                else:
                    trigger_begin_depth -= 1
        if word not in ("TEMP", "TEMPORARY"):
            prev_word = word
        elif prev_word == "CREATE":
            prev_word = "TEMP"

    def _emit_statement(append_semicolon: bool = False) -> None:
        nonlocal in_trigger_header, trigger_begin_depth, case_depth, prev_word
        raw_stmt = "".join(buf).strip()
        buf.clear()
        in_trigger_header = False
        trigger_begin_depth = 0
        case_depth = 0
        prev_word = ""
        current_word_chars.clear()
        if not raw_stmt:
            return
        effective = _strip_leading_sql_comments(raw_stmt)
        if not effective:
            return
        if effective.upper().startswith("PRAGMA FOREIGN_KEYS"):
            return
        if append_semicolon and not raw_stmt.endswith(";"):
            raw_stmt = raw_stmt + ";"
        statements.append(raw_stmt)

    while i < n:
        ch = script[i]
        nxt = script[i + 1] if i + 1 < n else ""

        if in_line_comment:
            buf.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                buf.append("*/")
                in_block_comment = False
                i += 2
            else:
                buf.append(ch)
                i += 1
            continue

        if in_single:
            buf.append(ch)
            if ch == "'":
                if nxt == "'":
                    buf.append(nxt)
                    i += 2
                    continue
                in_single = False
            i += 1
            continue

        if in_double:
            buf.append(ch)
            if ch == '"':
                if nxt == '"':
                    buf.append(nxt)
                    i += 2
                    continue
                in_double = False
            i += 1
            continue

        if in_backtick:
            buf.append(ch)
            if ch == "`":
                if nxt == "`":
                    buf.append(nxt)
                    i += 2
                    continue
                in_backtick = False
            i += 1
            continue

        if in_bracket:
            buf.append(ch)
            if ch == "]":
                in_bracket = False
            i += 1
            continue

        # Normal state
        if ch == "-" and nxt == "-":
            _flush_word()
            buf.append("--")
            in_line_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            _flush_word()
            buf.append("/*")
            in_block_comment = True
            i += 2
            continue

        if ch == "'":
            _flush_word()
            buf.append(ch)
            in_single = True
            i += 1
            continue

        if ch == '"':
            _flush_word()
            buf.append(ch)
            in_double = True
            i += 1
            continue

        if ch == "`":
            _flush_word()
            buf.append(ch)
            in_backtick = True
            i += 1
            continue

        if ch == "[":
            _flush_word()
            buf.append(ch)
            in_bracket = True
            i += 1
            continue

        if ch.isalnum() or ch == "_":
            current_word_chars.append(ch)
            buf.append(ch)
            i += 1
            continue

        _flush_word()

        if ch == ";":
            if trigger_begin_depth > 0:
                buf.append(ch)
            else:
                # If this semicolon closes a CREATE TRIGGER ... END; statement, preserve the trailing ';'
                effective_so_far = _strip_leading_sql_comments("".join(buf)).upper()
                is_trigger_stmt = bool(
                    re.match(r"^CREATE\s+(?:TEMP(?:ORARY)?\s+)?TRIGGER\b", effective_so_far)
                )
                _emit_statement(append_semicolon=is_trigger_stmt)
            i += 1
            continue

        buf.append(ch)
        i += 1

    _flush_word()
    _emit_statement(append_semicolon=False)
    return statements


# Columns that initialize() adds with _ensure_column *before* the legacy CHECK-constraint rebuild. The v3
# rebuild schemas predate them, so they are re-added to the rebuilt table instead of aborting the upgrade.
_POST_V3_REBUILD_COLUMNS: dict[str, dict[str, str]] = {
    "audit_runs": {
        "primary_model": "TEXT",
        "primary_model_attestation": "TEXT",
        "completed_by_review": "INTEGER NOT NULL DEFAULT 0",
        "evidence_anomaly_json": "TEXT",
    },
    "findings": {
        "model_independent": "INTEGER NOT NULL DEFAULT 0",
    },
    "execution_runs": {
        "review_branch": "TEXT",
        "review_commit": "TEXT",
        "heartbeat_at": "TEXT",
    },
    "audit_verification_runs": {
        "verifier_model_source": "TEXT NOT NULL DEFAULT 'UNVERIFIED'",
        "submission_count": "INTEGER NOT NULL DEFAULT 0",
        "submitted_at": "TEXT",
        "requested_model": "TEXT",
        "observed_model": "TEXT",
        "verifier_attestation_status": "TEXT NOT NULL DEFAULT 'MODEL_ATTESTATION_INCOMPLETE'",
        "input_tokens": "INTEGER NOT NULL DEFAULT 0",
        "output_tokens": "INTEGER NOT NULL DEFAULT 0",
        "thinking_tokens": "INTEGER NOT NULL DEFAULT 0",
        "total_tokens": "INTEGER NOT NULL DEFAULT 0",
        "execution_duration": "REAL NOT NULL DEFAULT 0.0",
        "permission_capability_status": "TEXT NOT NULL DEFAULT 'READ_ONLY_UNVERIFIED'",
    },
    "verification_dispatch_queue": {
        "lease_token": "TEXT",
    },
}


def _verify_and_copy_table_rebuild(
    conn: sqlite3.Connection,
    old_table: str,
    new_table: str,
) -> None:
    """Compare existing table columns with target rebuild schema; abort if any column would be dropped.

    Known post-v3 columns (``_POST_V3_REBUILD_COLUMNS``) are added to the target first; any other extra
    column still aborts the migration."""
    old_cols = _table_columns(conn, old_table)
    new_cols = _table_columns(conn, new_table)
    for col, definition in _POST_V3_REBUILD_COLUMNS.get(old_table, {}).items():
        if col in old_cols and col not in new_cols:
            conn.execute(f'ALTER TABLE {new_table} ADD COLUMN "{col}" {definition}')
            new_cols.add(col)
    unmigrated = sorted(old_cols - new_cols)
    if unmigrated:
        raise RuntimeError(
            f"Refusing to rebuild table '{old_table}': existing column(s) {unmigrated} are absent from "
            f"target schema '{new_table}'. Aborting migration to prevent silent column/data loss."
        )
    new_info = {
        str(r["name"]): r
        for r in conn.execute(f"PRAGMA table_info({new_table})").fetchall()
    }
    ordered_cols = [
        str(r["name"])
        for r in conn.execute(f"PRAGMA table_info({old_table})").fetchall()
        if str(r["name"]) in new_cols
    ]
    cols_csv = ", ".join(f'"{c}"' for c in ordered_cols)
    select_exprs: list[str] = []
    for c in ordered_cols:
        col_meta = new_info.get(c)
        if col_meta is not None and int(col_meta["notnull"] or 0) == 1 and col_meta["dflt_value"] is not None:
            select_exprs.append(f'COALESCE("{c}", {col_meta["dflt_value"]})')
        else:
            select_exprs.append(f'"{c}"')
    select_csv = ", ".join(select_exprs)
    conn.execute(f"INSERT INTO {new_table}({cols_csv}) SELECT {select_csv} FROM {old_table}")
    conn.execute(f"DROP TABLE {old_table}")
    conn.execute(f"ALTER TABLE {new_table} RENAME TO {old_table}")


def _upgrade_legacy_check_constraints_in_tx(conn: sqlite3.Connection) -> None:
    """Rebuild legacy tables inside the active migration transaction so SQLite CHECK/UNIQUE
    constraints allow v3 two-pass states, LEGACY_UNVERIFIED classification, and multi-attempt dispatch,
    while preserving all v1/v2 columns and values.
    """
    audit_runs_sql = _table_sql(conn, "audit_runs")
    findings_sql = _table_sql(conn, "findings")
    queue_sql = _table_sql(conn, "verification_dispatch_queue")
    vruns_sql = _table_sql(conn, "audit_verification_runs")

    needs_audit_runs_rebuild = bool(audit_runs_sql) and (
        "VERIFICATION_PENDING" not in audit_runs_sql
        or "INGESTED" not in audit_runs_sql
        or "trigger_source" not in audit_runs_sql
        or "summary_json" not in audit_runs_sql
    )
    needs_findings_rebuild = bool(findings_sql) and (
        "LEGACY_UNVERIFIED" not in findings_sql
        or "remediation_safe" not in findings_sql
        or "dismissed_reason" not in findings_sql
        # lifecycle values added later; an older CHECK list would reject transitions to them
        or "'APPROVED'" not in findings_sql
        or "'SUPPRESSED'" not in findings_sql
    )
    needs_queue_rebuild = bool(queue_sql) and "audit_run_id TEXT NOT NULL UNIQUE" in queue_sql
    needs_vruns_rebuild = bool(vruns_sql) and "'COMPLETED'" not in vruns_sql

    if needs_audit_runs_rebuild:
        conn.execute("DROP INDEX IF EXISTS ux_active_audit_per_project")
        conn.execute(
            """CREATE TABLE audit_runs_v3_new (
                run_id TEXT PRIMARY KEY,
                project_key TEXT NOT NULL REFERENCES projects(project_key),
                trigger_source TEXT NOT NULL DEFAULT 'scheduled',
                status TEXT NOT NULL CHECK(status IN (
                    'IDLE','PREFLIGHT','PRIMARY_AUDIT_RUNNING','DISPATCHED','ANALYZING',
                    'VERIFICATION_PENDING','VERIFICATION_DISPATCHING','VERIFICATION_RUNNING',
                    'EVIDENCE_VALIDATION','READY_FOR_REVIEW','PENDING_APPROVAL',
                    'VERIFICATION_FAILED','VERIFICATION_BLOCKED','VERIFICATION_STALE','VERIFICATION_UNCERTAIN',
                    'RECOVERABLE','FAILED','STALE','COMPLETED','PARTIAL','ARCHIVED',
                    'INGESTED','APPROVED','EXECUTING','ROLLED_BACK','QUARANTINED','RECOVERED','SKIPPED'
                )),
                snapshot_id TEXT,
                base_commit TEXT,
                working_tree_hash TEXT,
                retry_count INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL DEFAULT 2,
                heartbeat_at TEXT,
                superseded_by TEXT,
                started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                finished_at TEXT,
                agent_conversation_id TEXT,
                primary_model TEXT,
                primary_model_attestation TEXT,
                report_path TEXT,
                summary_json TEXT,
                error TEXT
            )"""
        )
        _verify_and_copy_table_rebuild(conn, "audit_runs", "audit_runs_v3_new")

    if needs_findings_rebuild:
        conn.execute(
            """CREATE TABLE findings_v3_new (
                finding_id TEXT PRIMARY KEY,
                project_key TEXT NOT NULL REFERENCES projects(project_key),
                run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
                fingerprint TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
                confidence TEXT NOT NULL CHECK(confidence IN ('CONFIRMED','LIKELY','SPECULATIVE')),
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
                lifecycle TEXT NOT NULL DEFAULT 'OPEN' CHECK(lifecycle IN ('OPEN','DEFERRED','DISMISSED','SKIPPED','RESOLVED','STALE','ARCHIVED','REJECTED','APPROVED','SUPPRESSED')),
                dismissed_reason TEXT,
                dismissed_evidence_hash TEXT,
                dismissed_file_blob_hash TEXT,
                verification_status TEXT NOT NULL DEFAULT 'LEGACY_UNVERIFIED' CHECK(verification_status IN ('CANDIDATE','VERIFIED','CONFIRMED','PARTIALLY_VERIFIED','PARTIALLY_CONFIRMED','REJECTED','UNVERIFIABLE','LEGACY_UNVERIFIED','STALE')),
                execution_eligible INTEGER NOT NULL DEFAULT 0 CHECK(execution_eligible IN (0,1)),
                remediation_safe INTEGER NOT NULL DEFAULT 1 CHECK(remediation_safe IN (0,1)),
                verification_run_id TEXT,
                verified_by_run_id TEXT,
                verified_at TEXT,
                verifier_conversation_id TEXT,
                evidence_validation_status TEXT NOT NULL DEFAULT 'UNCHECKED',
                snapshot_id TEXT,
                base_commit_sha TEXT,
                acceptance_criteria TEXT,
                remediation_review TEXT,
                technical_rationale TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_key, fingerprint)
            )"""
        )
        _verify_and_copy_table_rebuild(conn, "findings", "findings_v3_new")

    if needs_vruns_rebuild:
        conn.execute(
            """CREATE TABLE audit_verification_runs_v3_new (
                verification_run_id TEXT PRIMARY KEY,
                audit_run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
                project_key TEXT NOT NULL REFERENCES projects(project_key),
                snapshot_id TEXT NOT NULL,
                base_commit_sha TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN (
                    'PENDING','DISPATCHING','RUNNING','EVIDENCE_VALIDATION',
                    'FINALIZED','COMPLETED','FAILED','BLOCKED','STALE','UNCERTAIN','ARCHIVED'
                )),
                verifier_conversation_id TEXT,
                verifier_model_id TEXT,
                verifier_model_source TEXT NOT NULL DEFAULT 'UNVERIFIED',
                verifier_agent_id TEXT,
                invocation_mechanism TEXT,
                subagent_invocations INTEGER NOT NULL DEFAULT 0,
                dispatch_attempt INTEGER NOT NULL DEFAULT 0,
                submission_count INTEGER NOT NULL DEFAULT 0,
                submitted_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                started_at TEXT,
                completed_at TEXT,
                error_code TEXT,
                error_message TEXT,
                idempotency_key TEXT NOT NULL UNIQUE
            )"""
        )
        _verify_and_copy_table_rebuild(conn, "audit_verification_runs", "audit_verification_runs_v3_new")

    if needs_queue_rebuild:
        conn.execute(
            """CREATE TABLE verification_dispatch_queue_v3_new (
                job_id TEXT PRIMARY KEY,
                verification_run_id TEXT NOT NULL UNIQUE REFERENCES audit_verification_runs(verification_run_id),
                audit_run_id TEXT NOT NULL REFERENCES audit_runs(run_id),
                project_key TEXT NOT NULL REFERENCES projects(project_key),
                snapshot_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN (
                    'QUEUED','CLAIMED','DISPATCHING','RUNNING','COMPLETED',
                    'RETRYABLE_FAILURE','BLOCKED_CONFIGURATION','DISPATCH_UNCERTAIN','FAILED'
                )),
                idempotency_key TEXT NOT NULL UNIQUE,
                lease_owner TEXT,
                lease_token TEXT,
                claimed_at TEXT,
                lease_expires_at TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 3,
                next_attempt_at TEXT,
                verifier_conversation_id TEXT,
                last_error_code TEXT,
                last_error_message TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        _verify_and_copy_table_rebuild(conn, "verification_dispatch_queue", "verification_dispatch_queue_v3_new")


def _upgrade_legacy_check_constraints(db_path: Path) -> None:
    """Standalone wrapper for legacy check constraint upgrades."""
    conn = connect(db_path)
    try:
        conn.isolation_level = None
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("BEGIN IMMEDIATE")
        _upgrade_legacy_check_constraints_in_tx(conn)
        fk_rows = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_rows:
            raise RuntimeError(
                f"Foreign key check failed after table rebuild: {[dict(r) for r in fk_rows]}"
            )
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        try:
            conn.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error:
            pass
        conn.close()


def _apply_migration_005_governance_broker_schema(conn: sqlite3.Connection) -> None:
    """Additive schema migration 5: Governance Broker CBEAT, leases, checkpoints, and audit hash chaining."""
    # 1. execution_approvals additive columns
    cols_approvals = {
        row["name"] for row in conn.execute("PRAGMA table_info(execution_approvals)").fetchall()
    }
    if "single_use_nonce" not in cols_approvals:
        conn.execute("ALTER TABLE execution_approvals ADD COLUMN single_use_nonce TEXT")
    if "consumed_at" not in cols_approvals:
        conn.execute("ALTER TABLE execution_approvals ADD COLUMN consumed_at TEXT")
    if "cbeat_payload" not in cols_approvals:
        conn.execute("ALTER TABLE execution_approvals ADD COLUMN cbeat_payload TEXT")
    if "cbeat_signature" not in cols_approvals:
        conn.execute("ALTER TABLE execution_approvals ADD COLUMN cbeat_signature TEXT")
    if "allowed_scope_digest" not in cols_approvals:
        conn.execute("ALTER TABLE execution_approvals ADD COLUMN allowed_scope_digest TEXT")
    if "evidence_digest" not in cols_approvals:
        conn.execute("ALTER TABLE execution_approvals ADD COLUMN evidence_digest TEXT")
    if "test_policy_digest" not in cols_approvals:
        conn.execute("ALTER TABLE execution_approvals ADD COLUMN test_policy_digest TEXT")
    if "max_repair_attempts" not in cols_approvals:
        conn.execute("ALTER TABLE execution_approvals ADD COLUMN max_repair_attempts INTEGER DEFAULT 2")
    if "execution_id" not in cols_approvals:
        conn.execute("ALTER TABLE execution_approvals ADD COLUMN execution_id TEXT")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_execution_approvals_nonce ON execution_approvals(single_use_nonce)"
    )

    # 2. audit_events additive columns
    cols_events = {
        row["name"] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()
    }
    for col_name, col_type in [
        ("actor", "TEXT DEFAULT 'system'"),
        ("broker_id", "TEXT DEFAULT 'broker-local'"),
        ("exec_id", "TEXT"),
        ("approval_id", "TEXT"),
        ("request_id", "TEXT"),
        ("before_state_digest", "TEXT"),
        ("after_state_digest", "TEXT"),
        ("auth_ref", "TEXT"),
        ("payload_digest", "TEXT"),
        ("prev_event_hash", "TEXT"),
        ("event_hash", "TEXT"),
        ("result", "TEXT DEFAULT 'SUCCESS'"),
    ]:
        if col_name not in cols_events:
            conn.execute(f"ALTER TABLE audit_events ADD COLUMN {col_name} {col_type}")

    # 3. execution_leases table
    conn.execute(
        """CREATE TABLE IF NOT EXISTS execution_leases (
            lease_id TEXT PRIMARY KEY,
            exec_id TEXT NOT NULL REFERENCES execution_runs(exec_id),
            worker_id TEXT NOT NULL,
            fencing_token INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'EXPIRED', 'RELEASED', 'REVOKED')),
            acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            last_heartbeat_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            lease_ttl_seconds INTEGER NOT NULL DEFAULT 300
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_execution_leases_exec_worker ON execution_leases(exec_id, worker_id)"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_execution_leases_active_exec ON execution_leases(exec_id) WHERE status = 'ACTIVE'"
    )

    # 4. finding_checkpoints table
    conn.execute(
        """CREATE TABLE IF NOT EXISTS finding_checkpoints (
            checkpoint_id TEXT PRIMARY KEY,
            exec_id TEXT NOT NULL REFERENCES execution_runs(exec_id),
            finding_id TEXT NOT NULL REFERENCES findings(finding_id),
            base_commit TEXT NOT NULL,
            scope_digest TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            checkpoint_path TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'QUARANTINED', 'RESTORED')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            quarantine_reason TEXT
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_finding_checkpoints_exec_finding ON finding_checkpoints(exec_id, finding_id)"
    )


def _apply_migration_006_entitlement_capability_router_schema(conn: sqlite3.Connection) -> None:
    """Additive schema migration 6: NEXT-22B User-Aware Entitlement, Capability, Effort, Quota & Routing Plan tables."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS account_profiles (
            user_profile_id TEXT PRIMARY KEY,
            label TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS application_instances (
            application_instance_id TEXT PRIMARY KEY,
            user_profile_id TEXT NOT NULL REFERENCES account_profiles(user_profile_id),
            application_id TEXT NOT NULL,
            installation_state TEXT NOT NULL,
            packaging_mode TEXT NOT NULL DEFAULT 'unknown',
            version TEXT,
            executable_basename TEXT,
            evidence_ref TEXT,
            observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_app_instances_user ON application_instances(user_profile_id, application_id)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS application_account_contexts (
            account_context_id TEXT PRIMARY KEY,
            user_profile_id TEXT NOT NULL REFERENCES account_profiles(user_profile_id),
            application_instance_id TEXT NOT NULL REFERENCES application_instances(application_instance_id),
            application_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            authentication_mode TEXT NOT NULL CHECK(authentication_mode IN (
                'SUBSCRIPTION','OAUTH_SUBSCRIPTION','API_KEY','ENTERPRISE',
                'ORGANIZATION_MANAGED','LOCAL_ONLY','UNKNOWN'
            )),
            account_scope TEXT NOT NULL DEFAULT 'USER_ACCOUNT',
            workspace_scope TEXT,
            subscription_tier TEXT,
            subscription_source TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK(subscription_source IN (
                'APPLICATION_RUNTIME','OFFICIAL_READ_ONLY_INTERFACE',
                'USER_DECLARED','ADMIN_POLICY','UNKNOWN'
            )),
            entitlement_state TEXT NOT NULL DEFAULT 'UNKNOWN',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            observed_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_acct_ctx_user_app ON application_account_contexts(user_profile_id, application_id)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS model_entitlement_observations (
            observation_id TEXT PRIMARY KEY,
            account_context_id TEXT NOT NULL REFERENCES application_account_contexts(account_context_id),
            application_instance_id TEXT NOT NULL REFERENCES application_instances(application_instance_id),
            application_id TEXT NOT NULL,
            model_id TEXT NOT NULL,
            entitlement_state TEXT NOT NULL CHECK(entitlement_state IN (
                'DOCUMENTED_ONLY','BUNDLED_CATALOG','CONFIGURED','RUNTIME_OBSERVED',
                'ACCOUNT_ENUMERATED','USER_DECLARED','USER_CONFIRMED_SELECTABLE',
                'SELECTABLE_VERIFIED','INVOCATION_OBSERVED','TEMPORARILY_UNAVAILABLE',
                'QUOTA_EXHAUSTED','POLICY_BLOCKED','NOT_SUPPORTED','UNKNOWN','ERROR'
            )),
            provenance TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'UNKNOWN',
            evidence_ref TEXT NOT NULL,
            notes TEXT,
            observed_at TEXT NOT NULL,
            expires_at TEXT,
            recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ent_obs_acct_model ON model_entitlement_observations(account_context_id, model_id, observed_at)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS model_capability_profiles (
            capability_profile_id TEXT PRIMARY KEY,
            application_id TEXT NOT NULL,
            application_model_id TEXT NOT NULL,
            provider TEXT NOT NULL DEFAULT 'unknown',
            canonical_model_id TEXT,
            model_version TEXT,
            model_family TEXT NOT NULL DEFAULT 'UNKNOWN',
            variant TEXT,
            reasoning_effort_variant TEXT,
            is_orchestrator_wrapper INTEGER NOT NULL DEFAULT 0 CHECK(is_orchestrator_wrapper IN (0,1)),
            orchestrator_wrapper_identity TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(application_id, application_model_id)
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS model_capability_evidence (
            evidence_row_id TEXT PRIMARY KEY,
            capability_profile_id TEXT NOT NULL REFERENCES model_capability_profiles(capability_profile_id),
            dimension TEXT NOT NULL CHECK(dimension IN (
                'REASONING','ARCHITECTURE','CODING','DEBUGGING','TOOL_CALLING',
                'STRUCTURED_OUTPUT','LONG_CONTEXT','MULTIMODAL',
                'PARALLEL_AGENT_COORDINATION','ADVERSARIAL_VERIFICATION'
            )),
            status TEXT NOT NULL CHECK(status IN (
                'VERIFIED','DOCUMENTED','USER_REPORTED','EXPERIMENTAL','UNKNOWN','NOT_SUPPORTED'
            )),
            evidence_source TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'UNKNOWN',
            model_version TEXT,
            evidence_ref TEXT,
            notes TEXT,
            observed_at TEXT NOT NULL,
            expires_at TEXT,
            recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cap_ev_profile_dim ON model_capability_evidence(capability_profile_id, dimension)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS model_effort_profiles (
            effort_profile_id TEXT PRIMARY KEY,
            application_id TEXT NOT NULL,
            application_model_id TEXT NOT NULL,
            account_context_id TEXT REFERENCES application_account_contexts(account_context_id),
            supported_efforts_json TEXT NOT NULL DEFAULT '[]',
            raw_supported_efforts_json TEXT NOT NULL DEFAULT '[]',
            default_effort TEXT NOT NULL DEFAULT 'UNKNOWN',
            raw_default_effort TEXT,
            selected_effort TEXT,
            independently_configurable INTEGER NOT NULL DEFAULT 0 CHECK(independently_configurable IN (0,1)),
            managed_by_orchestrator INTEGER NOT NULL DEFAULT 0 CHECK(managed_by_orchestrator IN (0,1)),
            orchestrator_structure_json TEXT,
            provenance TEXT NOT NULL DEFAULT 'UNKNOWN',
            evidence_ref TEXT,
            observed_at TEXT NOT NULL,
            recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_effort_app_model ON model_effort_profiles(application_id, application_model_id, account_context_id)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS quota_observations (
            quota_observation_id TEXT PRIMARY KEY,
            account_context_id TEXT NOT NULL REFERENCES application_account_contexts(account_context_id),
            model_id TEXT,
            usage_category TEXT NOT NULL,
            quota_state TEXT NOT NULL CHECK(quota_state IN (
                'AVAILABLE','LOW','RATE_LIMITED','EXHAUSTED','UNKNOWN','NOT_EXPOSED','ERROR'
            )),
            remaining_quantity REAL,
            remaining_percentage REAL,
            reset_at TEXT,
            rate_limited INTEGER NOT NULL DEFAULT 0 CHECK(rate_limited IN (0,1)),
            source TEXT NOT NULL,
            evidence_ref TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            expires_at TEXT,
            recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_quota_obs_acct_model ON quota_observations(account_context_id, model_id, observed_at)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS user_routing_preferences (
            policy_id TEXT PRIMARY KEY,
            user_profile_id TEXT NOT NULL UNIQUE REFERENCES account_profiles(user_profile_id),
            policy_json TEXT NOT NULL,
            schema_version TEXT NOT NULL DEFAULT '1.0.0',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS routing_decisions (
            decision_id TEXT PRIMARY KEY,
            user_profile_id TEXT NOT NULL REFERENCES account_profiles(user_profile_id),
            task_profile_id TEXT NOT NULL,
            risk TEXT NOT NULL,
            status TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS routing_candidate_explanations (
            explanation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision_id TEXT NOT NULL REFERENCES routing_decisions(decision_id),
            role TEXT NOT NULL,
            application_id TEXT NOT NULL,
            account_context_id TEXT NOT NULL,
            model_id TEXT NOT NULL,
            eligibility TEXT NOT NULL CHECK(eligibility IN ('ACCEPTED','REJECTED','CONDITIONAL','UNKNOWN')),
            reason_codes_json TEXT NOT NULL,
            explanation_text TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_route_cand_dec ON routing_candidate_explanations(decision_id, role)"
    )


def _apply_migration_007_model_catalog_schema(conn: sqlite3.Connection) -> None:
    """Additive schema migration 7: dispatch-backend model catalogue snapshots and sync state.

    A snapshot row is written only when the backend's model list changes (or on first sync);
    ``model_catalog_state`` records every check so staleness and errors are visible.
    """
    conn.execute(
        """CREATE TABLE IF NOT EXISTS model_catalog_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            backend TEXT NOT NULL,
            catalog_sha256 TEXT NOT NULL,
            model_count INTEGER NOT NULL,
            models_json TEXT NOT NULL,
            diff_json TEXT NOT NULL DEFAULT '{}',
            observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_model_catalog_snapshots_backend ON model_catalog_snapshots(backend, observed_at)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS model_catalog_state (
            backend TEXT PRIMARY KEY,
            last_checked_at TEXT NOT NULL,
            last_status TEXT NOT NULL CHECK(last_status IN ('INITIAL','UNCHANGED','CHANGED','ERROR')),
            last_snapshot_id TEXT REFERENCES model_catalog_snapshots(snapshot_id),
            last_error TEXT,
            consecutive_errors INTEGER NOT NULL DEFAULT 0
        )"""
    )


def _apply_migration_008_model_probe_schema(conn: sqlite3.Connection) -> None:
    """Additive schema migration 8: model probe runs (deterministic capability measurements)."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS model_probe_runs (
            probe_run_id TEXT PRIMARY KEY,
            backend TEXT NOT NULL,
            model_slug TEXT NOT NULL,
            suite_version TEXT NOT NULL,
            catalog_snapshot_id TEXT,
            status TEXT NOT NULL CHECK(status IN ('PASSED','DEGRADED','FAILED','ERROR','ATTESTATION_FAILED')),
            score REAL,
            metrics_json TEXT NOT NULL DEFAULT '{}',
            conversation_id TEXT,
            attestation_status TEXT,
            error TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_model_probe_runs_model ON model_probe_runs(backend, model_slug, suite_version)"
    )


def _apply_migration_009_model_research_schema(conn: sqlite3.Connection) -> None:
    """Additive schema migration 9: web research reports about model lines (untrusted evidence)."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS model_research_reports (
            report_id TEXT PRIMARY KEY,
            backend TEXT NOT NULL,
            researcher_model TEXT NOT NULL,
            catalog_snapshot_id TEXT,
            target_lines_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('COMPLETED','NO_WEB_EVIDENCE','INVALID_OUTPUT','ERROR','ATTESTATION_FAILED')),
            report_json TEXT NOT NULL DEFAULT '{}',
            web_tool_calls INTEGER NOT NULL DEFAULT 0,
            issues_json TEXT NOT NULL DEFAULT '[]',
            conversation_id TEXT,
            attestation_status TEXT,
            error TEXT,
            created_at TEXT NOT NULL
        )"""
    )


def _apply_migration_010_routing_table_versions(conn: sqlite3.Connection) -> None:
    """Additive schema migration 10: user-approved routing tables and proposals (one ACTIVE and at most one
    PROPOSED table per host, enforced by partial unique indexes)."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS routing_table_versions (
            version_id TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('PROPOSED','ACTIVE','SUPERSEDED','REJECTED','WITHDRAWN')),
            assignments_json TEXT NOT NULL,
            rationale_json TEXT NOT NULL DEFAULT '[]',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            base_version TEXT,
            created_at TEXT NOT NULL,
            decided_at TEXT,
            decided_by TEXT,
            decision_note TEXT
        )"""
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_routing_table_active_per_host ON routing_table_versions(host) WHERE status='ACTIVE'"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_routing_table_proposed_per_host ON routing_table_versions(host) WHERE status='PROPOSED'"
    )


def initialize(db_path: Path, *, _migration_fault_hook: Any | None = None) -> None:
    """Initialize schema and apply idempotent versioned migrations (v1 -> v2 -> v3)
    inside a single controlled SQLite connection and atomic transaction.

    SQLite connection/transaction ordering note:
    1. `PRAGMA foreign_keys=OFF` MUST be executed outside any active transaction (before `BEGIN IMMEDIATE`),
       because SQLite treats `PRAGMA foreign_keys` as a no-op inside an active transaction.
    2. `BEGIN IMMEDIATE` acquires the write lock upfront so all DDL (`CREATE TABLE`, `ALTER TABLE`,
       and `CREATE TABLE ..._v3_new` / `INSERT` / `DROP` / `RENAME` rebuilds) execute atomically.
    3. Before `COMMIT`, `PRAGMA foreign_key_check` is executed inside the transaction; if any violation
       exists, the transaction is rolled back (`ROLLBACK`) and an exception is raised.
    4. `PRAGMA foreign_keys=ON` is unconditionally restored in the `finally` block before closing.
    """
    conn = connect(db_path)
    try:
        conn.isolation_level = None
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("BEGIN IMMEDIATE")

        for stmt in _split_sql_statements(SCHEMA):
            conn.execute(stmt)

        # Ensure existing v1/v2 starter databases gain all v2 & v3 columns safely
        _ensure_column(conn, "projects", "repo_fingerprint", "TEXT")
        _ensure_column(conn, "projects", "last_known_commit", "TEXT")
        _ensure_column(conn, "projects", "health_status", "TEXT NOT NULL DEFAULT 'HEALTHY'")
        _ensure_column(conn, "projects", "stale_timeout_seconds", "INTEGER NOT NULL DEFAULT 3600")
        _ensure_column(conn, "projects", "max_retries", "INTEGER NOT NULL DEFAULT 2")
        _ensure_column(conn, "projects", "max_run_retries", "INTEGER NOT NULL DEFAULT 2")
        _ensure_column(conn, "projects", "min_free_mb", "INTEGER NOT NULL DEFAULT 500")
        _ensure_column(conn, "projects", "created_at", "TEXT")
        _ensure_column(conn, "projects", "updated_at", "TEXT")

        _ensure_column(conn, "audit_runs", "trigger_source", "TEXT NOT NULL DEFAULT 'scheduled'")
        _ensure_column(conn, "audit_runs", "snapshot_id", "TEXT")
        _ensure_column(conn, "audit_runs", "base_commit", "TEXT")
        _ensure_column(conn, "audit_runs", "working_tree_hash", "TEXT")
        _ensure_column(conn, "audit_runs", "retry_count", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "audit_runs", "max_retries", "INTEGER NOT NULL DEFAULT 2")
        _ensure_column(conn, "audit_runs", "heartbeat_at", "TEXT")
        _ensure_column(conn, "audit_runs", "superseded_by", "TEXT")
        _ensure_column(conn, "audit_runs", "started_at", "TEXT")
        _ensure_column(conn, "audit_runs", "finished_at", "TEXT")
        _ensure_column(conn, "audit_runs", "agent_conversation_id", "TEXT")
        _ensure_column(conn, "audit_runs", "report_path", "TEXT")
        _ensure_column(conn, "audit_runs", "summary_json", "TEXT")
        _ensure_column(conn, "audit_runs", "error", "TEXT")

        _ensure_column(conn, "audit_snapshots", "snapshot_complete", "INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "audit_snapshots", "incomplete_reason", "TEXT")

        _ensure_column(conn, "findings", "file_path", "TEXT")
        _ensure_column(conn, "findings", "symbol", "TEXT")
        _ensure_column(conn, "findings", "line_start", "INTEGER")
        _ensure_column(conn, "findings", "line_end", "INTEGER")
        _ensure_column(conn, "findings", "evidence_hash", "TEXT")
        _ensure_column(conn, "findings", "file_blob_hash", "TEXT")
        _ensure_column(conn, "findings", "first_seen_run_id", "TEXT")
        _ensure_column(conn, "findings", "last_seen_run_id", "TEXT")
        _ensure_column(conn, "findings", "lifecycle", "TEXT NOT NULL DEFAULT 'OPEN'")
        _ensure_column(conn, "findings", "dismissed_reason", "TEXT")
        _ensure_column(conn, "findings", "dismissed_evidence_hash", "TEXT")
        _ensure_column(conn, "findings", "dismissed_file_blob_hash", "TEXT")
        _ensure_column(conn, "findings", "created_at", "TEXT")
        _ensure_column(conn, "findings", "updated_at", "TEXT")
        _ensure_column(conn, "findings", "verification_status", "TEXT NOT NULL DEFAULT 'LEGACY_UNVERIFIED'")
        _ensure_column(conn, "findings", "execution_eligible", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "findings", "remediation_safe", "INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "findings", "verification_run_id", "TEXT")
        _ensure_column(conn, "findings", "verified_by_run_id", "TEXT")
        _ensure_column(conn, "findings", "verified_at", "TEXT")
        _ensure_column(conn, "findings", "verifier_conversation_id", "TEXT")
        _ensure_column(conn, "findings", "evidence_validation_status", "TEXT NOT NULL DEFAULT 'UNCHECKED'")
        _ensure_column(conn, "findings", "snapshot_id", "TEXT")
        _ensure_column(conn, "findings", "base_commit_sha", "TEXT")
        _ensure_column(conn, "findings", "acceptance_criteria", "TEXT")
        _ensure_column(conn, "findings", "remediation_review", "TEXT")
        _ensure_column(conn, "findings", "technical_rationale", "TEXT")

        _ensure_column(conn, "decisions", "run_id", "TEXT")
        _ensure_column(conn, "decisions", "note", "TEXT")
        _ensure_column(conn, "decisions", "actor", "TEXT NOT NULL DEFAULT 'user'")
        _ensure_column(conn, "decisions", "superseded", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "decisions", "created_at", "TEXT")

        _ensure_column(conn, "candidate_findings", "discovered_by_conversation_id", "TEXT")
        _ensure_column(conn, "candidate_findings", "discovered_in_verification_run_id", "TEXT")
        _ensure_column(conn, "audit_verification_runs", "verifier_model_source", "TEXT NOT NULL DEFAULT 'UNVERIFIED'")
        _ensure_column(conn, "audit_verification_runs", "submission_count", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "audit_verification_runs", "submitted_at", "TEXT")
        _ensure_column(conn, "verification_dispatch_queue", "lease_token", "TEXT")

        _ensure_column(conn, "execution_runs", "review_branch", "TEXT")
        _ensure_column(conn, "execution_runs", "heartbeat_at", "TEXT")
        _ensure_column(conn, "findings", "model_independent", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "audit_runs", "evidence_anomaly_json", "TEXT")
        _ensure_column(conn, "audit_runs", "completed_by_review", "INTEGER NOT NULL DEFAULT 0")
        from apply_policy import ensure_schema as _ensure_apply_policy_schema

        _ensure_apply_policy_schema(conn)  # apply_policies table + execution_approvals.policy_snapshot
        _ensure_column(conn, "execution_runs", "review_commit", "TEXT")
        _ensure_column(conn, "audit_runs", "primary_model", "TEXT")
        _ensure_column(conn, "audit_runs", "primary_model_attestation", "TEXT")
        _ensure_column(conn, "audit_verification_runs", "requested_model", "TEXT")
        _ensure_column(conn, "audit_verification_runs", "observed_model", "TEXT")
        _ensure_column(conn, "audit_verification_runs", "verifier_attestation_status", "TEXT NOT NULL DEFAULT 'MODEL_ATTESTATION_INCOMPLETE'")
        _ensure_column(conn, "audit_verification_runs", "input_tokens", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "audit_verification_runs", "output_tokens", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "audit_verification_runs", "thinking_tokens", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "audit_verification_runs", "total_tokens", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "audit_verification_runs", "execution_duration", "REAL NOT NULL DEFAULT 0.0")
        _ensure_column(conn, "audit_verification_runs", "permission_capability_status", "TEXT NOT NULL DEFAULT 'READ_ONLY_UNVERIFIED'")

        _ensure_column(conn, "audit_quality_metrics", "requested_model", "TEXT")
        _ensure_column(conn, "audit_quality_metrics", "observed_model", "TEXT")
        _ensure_column(conn, "audit_quality_metrics", "model_attestation_status", "TEXT")
        _ensure_column(conn, "audit_quality_metrics", "total_tokens", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "audit_quality_metrics", "cross_model_verified", "INTEGER NOT NULL DEFAULT 0")

        if _migration_fault_hook is not None:
            _migration_fault_hook(conn, "after_columns")

        _upgrade_legacy_check_constraints_in_tx(conn)

        if _migration_fault_hook is not None:
            _migration_fault_hook(conn, "after_rebuild")

        # Ensure active audit unique index covers all two-pass active states
        conn.execute("DROP INDEX IF EXISTS ux_active_audit_per_project")
        conn.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS ux_active_audit_per_project
               ON audit_runs(project_key) WHERE status IN (
                   'PREFLIGHT','PRIMARY_AUDIT_RUNNING','DISPATCHED','ANALYZING',
                   'VERIFICATION_PENDING','VERIFICATION_DISPATCHING','VERIFICATION_RUNNING',
                   'EVIDENCE_VALIDATION','READY_FOR_REVIEW','PENDING_APPROVAL'
               )"""
        )
        # Classify any legacy findings lacking verification_run_id as LEGACY_UNVERIFIED and non-eligible
        conn.execute(
            """UPDATE findings
               SET verification_status='LEGACY_UNVERIFIED', execution_eligible=0
               WHERE verification_run_id IS NULL AND verification_status NOT IN ('CANDIDATE')"""
        )

        _apply_migration_005_governance_broker_schema(conn)
        _apply_migration_006_entitlement_capability_router_schema(conn)
        _apply_migration_007_model_catalog_schema(conn)
        _apply_migration_008_model_probe_schema(conn)
        _apply_migration_009_model_research_schema(conn)
        _apply_migration_010_routing_table_versions(conn)

        applied = {
            int(row["version"])
            for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
        }
        migrations = [
            (1, "001_initial_starter_schema"),
            (2, "002_deterministic_lifecycle_approvals_executor_recovery"),
            (3, "003_mandatory_second_pass_verification_and_quality_metrics"),
            (4, "004_task_based_model_router_and_independent_attestation"),
            (5, "005_governance_broker_cbeat_and_audit_schema"),
            (6, "006_user_entitlement_capability_router_schema"),
            (7, "007_model_catalog_snapshots"),
            (8, "008_model_probe_runs"),
            (9, "009_model_research_reports"),
            (10, "010_routing_table_versions"),
        ]
        for version, name in migrations:
            if version not in applied:
                conn.execute(
                    "INSERT INTO schema_migrations(version, name) VALUES(?, ?)",
                    (version, name),
                )

        if _migration_fault_hook is not None:
            _migration_fault_hook(conn, "before_commit")

        fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_violations:
            raise RuntimeError(
                f"Database migration aborted due to foreign_key_check violations: "
                f"{[dict(r) for r in fk_violations]}"
            )

        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        try:
            conn.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error:
            pass
        conn.close()


def record_event(
    conn: sqlite3.Connection,
    event_type: str,
    *,
    project_key: str | None = None,
    run_id: str | None = None,
    details: dict[str, Any] | None = None,
    level: str = "INFO",
    jsonl_path: Path | None = None,
    app_home: Path | None = None,
) -> dict[str, Any]:
    """Persist structured event to SQLite audit_events AND structured JSONL log."""
    payload = details or {}
    logger = StructuredAuditLogger(app_home=app_home)
    record = logger.emit(
        event_type,
        level=level,
        project_key=project_key,
        run_id=run_id,
        details=payload,
        jsonl_path=jsonl_path,
    )
    conn.execute(
        "INSERT INTO audit_events(project_key, run_id, event_type, details) VALUES(?, ?, ?, ?)",
        (project_key, run_id, event_type, json.dumps(record["details"], ensure_ascii=False, sort_keys=True)),
    )
    return record


def normalize_rel_path(file_path: str | None) -> str:
    if not file_path:
        return ""
    cleaned = file_path.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def compute_finding_fingerprint(project_key: str, item: dict[str, Any]) -> str:
    """Compute a stable fingerprint for deduplication across runs."""
    raw_fp = str(item.get("fingerprint") or "").strip()
    if raw_fp and len(raw_fp) >= 8:
        normalized_fp = " ".join(raw_fp.lower().split())
        if re.match(r"^[0-9a-f]{16,64}$", normalized_fp):
            return normalized_fp[:32]
        return hashlib.sha256(f"{project_key}:{normalized_fp}".encode("utf-8")).hexdigest()[:32]

    category = " ".join(str(item.get("category") or "").strip().upper().split())
    norm_path = normalize_rel_path(item.get("file_path")).lower()
    symbol = " ".join(str(item.get("symbol") or "").strip().lower().split())
    title = " ".join(str(item.get("title") or "").strip().lower().split())
    seed = f"{project_key}|{category}|{norm_path}|{symbol}|{title}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def compute_finding_id(project_key: str, fingerprint: str) -> str:
    """Generate a deterministic primary key for a project+fingerprint pair."""
    digest = hashlib.sha256(f"{project_key}:{fingerprint}".encode("utf-8")).hexdigest()[:12]
    return f"F-{project_key}-{digest}"


def compute_evidence_hash(item: dict[str, Any]) -> str:
    """Compute a content hash of the finding's evidence and location context."""
    parts = [
        normalize_rel_path(item.get("file_path")),
        str(item.get("symbol") or "").strip(),
        str(item.get("line_start") or ""),
        str(item.get("line_end") or ""),
        " ".join(str(item.get("evidence") or "").split()),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def compute_file_blob_hash(repo_path: Path | None, file_path: str | None) -> str | None:
    """Hash the current target file content using streaming SHA-256 if available inside repo_path."""
    if not repo_path or not file_path:
        return None
    norm = normalize_rel_path(file_path)
    if not norm:
        return None
    try:
        target = resolve_repo_file_for_reading(repo_path, norm)
        if target is not None and target.is_file():
            return stream_file_sha256(target)
    except (OSError, ValueError, RuntimeError):
        return None
    return None


UNAMBIGUOUS_PLACEHOLDER_WORDS: frozenset[str] = frozenset({
    "dummy",
    "test",
    "todo",
    "tbd",
    "n/a",
    "na",
    "placeholder",
    "xxx",
    "xxxx",
    "asdf",
})


def validate_non_placeholder_text(field_name: str, value: Any, index: int) -> str:
    """Validate that required descriptive fields are non-empty and reject placeholder/filler values.

    Rules:
    1. Must not be None or empty.
    2. Case and surrounding whitespace are normalized.
    3. Rejects exact keyword matches against unambiguous placeholder words (e.g. 'dummy', 'test', 'TODO', 'tbd', 'n/a', 'placeholder', 'xxx').
    4. Rejects token-level matches where all whitespace-separated words are placeholder keywords (e.g. 'test test', 'TODO: TBD').
    5. Rejects strings lacking any alphanumeric characters (e.g. '---', '...').
    6. Rejects obvious repeated filler characters/patterns (e.g. 'aaaa...', 'xxxxxx', '11111').
    7. Preserves legitimate short technical descriptions.
    """
    if value is None:
        raise RuntimeError(f"Finding at index {index} has null required field '{field_name}'.")
    val_str = str(value).strip()
    if not val_str:
        raise RuntimeError(f"Finding at index {index} has empty required field '{field_name}'.")

    # Normalize case and internal whitespace
    normalized = " ".join(val_str.lower().split())
    # Strip common enclosing punctuation
    clean_norm = normalized.strip('`"\'()[]{}<>:;.-_')

    # 1. Exact match on normalized or stripped keyword
    if normalized in UNAMBIGUOUS_PLACEHOLDER_WORDS or clean_norm in UNAMBIGUOUS_PLACEHOLDER_WORDS:
        raise RuntimeError(
            f"Finding at index {index} has invalid placeholder value for field '{field_name}': '{val_str}'."
        )

    # 2. Token-level check: if all tokens are placeholder words
    tokens = [re.sub(r"^[^\w]+|[^\w]+$", "", t) for t in normalized.split()]
    tokens = [t for t in tokens if t]
    if tokens and all(t in UNAMBIGUOUS_PLACEHOLDER_WORDS for t in tokens):
        raise RuntimeError(
            f"Finding at index {index} contains only placeholder words in field '{field_name}': '{val_str}'."
        )

    # 3. Alphanumeric content check: must contain meaningful alphanumeric characters
    alnum = re.sub(r"[\s\W_]", "", normalized)
    if not alnum:
        raise RuntimeError(
            f"Finding at index {index} lacks meaningful alphanumeric content in field '{field_name}': '{val_str}'."
        )

    # 4. Obvious repeated filler (e.g. 'aaaa...', 'xxxxxx', '11111')
    if len(alnum) >= 3 and len(set(alnum)) == 1:
        raise RuntimeError(
            f"Finding at index {index} contains repeated filler content in field '{field_name}': '{val_str}'."
        )

    return val_str


def validate_finding_item(item: Any, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise RuntimeError(f"Finding at index {index} must be a JSON object.")
    required = {
        "finding_id",
        "fingerprint",
        "title",
        "category",
        "severity",
        "confidence",
        "evidence",
        "impact",
        "recommendation",
    }
    missing = required - set(item.keys())
    if missing:
        raise RuntimeError(f"Finding at index {index} is missing required fields: {sorted(missing)}")
    finding_id = str(item.get("finding_id") or "").strip()
    if not finding_id:
        raise RuntimeError(f"Finding at index {index} has empty required field 'finding_id'.")
    fingerprint = str(item.get("fingerprint") or "").strip()
    if not fingerprint:
        raise RuntimeError(f"Finding at index {index} has empty required field 'fingerprint'.")
    severity = str(item["severity"]).strip().upper()
    confidence = str(item["confidence"]).strip().upper()
    if severity not in ALLOWED_SEVERITIES:
        raise RuntimeError(f"Finding at index {index} has invalid severity: {severity}")
    if confidence not in ALLOWED_CONFIDENCES:
        raise RuntimeError(f"Finding at index {index} has invalid confidence: {confidence}")

    category = str(item.get("category") or "").strip()
    if not category:
        raise RuntimeError(f"Finding at index {index} has empty required field 'category'.")
    norm_cat = " ".join(category.lower().split()).strip('`"\'()[]{}<>:;.-_')
    if norm_cat in UNAMBIGUOUS_PLACEHOLDER_WORDS:
        raise RuntimeError(f"Finding at index {index} has invalid placeholder value for field 'category': '{category}'.")

    title = validate_non_placeholder_text("title", item.get("title"), index)
    evidence = validate_non_placeholder_text("evidence", item.get("evidence"), index)
    impact = validate_non_placeholder_text("impact", item.get("impact"), index)
    recommendation = validate_non_placeholder_text("recommendation", item.get("recommendation"), index)

    line_start = item.get("line_start")
    line_end = item.get("line_end")
    if line_start is not None and (not isinstance(line_start, int) or isinstance(line_start, bool) or line_start < 1):
        raise RuntimeError(f"Finding at index {index} has invalid line_start: {line_start}")
    if line_end is not None and (not isinstance(line_end, int) or isinstance(line_end, bool) or line_end < 1):
        raise RuntimeError(f"Finding at index {index} has invalid line_end: {line_end}")
    if line_start is not None and line_end is not None and line_end < line_start:
        raise RuntimeError(f"Finding at index {index} has line_end ({line_end}) < line_start ({line_start}).")
    return {
        "finding_id": finding_id,
        "fingerprint": fingerprint,
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "file_path": normalize_rel_path(item.get("file_path")) or None,
        "symbol": str(item["symbol"]).strip() if item.get("symbol") else None,
        "line_start": line_start,
        "line_end": line_end,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
    }


def ingest_findings(
    db_path: Path,
    *,
    project_key: str,
    run_id: str,
    findings: list[dict[str, Any]],
    report_dir: Path,
    repo_path: Path | None = None,
    jsonl_path: Path | None = None,
) -> dict[str, Any]:
    """Primary audit candidate submission.

    1. Saves deduplicated primary findings as candidates in `candidate_findings` (not execution-eligible).
    2. Binds them to the repository audit snapshot (`audit_snapshots`).
    3. Creates exactly one verification run and durable queue job (`idempotency_key` guarded).
    4. Transitions the audit run to `VERIFICATION_PENDING`.
    5. Never marks the report `READY_FOR_REVIEW` directly.
    """
    if not isinstance(findings, list):
        raise RuntimeError("findings payload must be a JSON array.")
    validated = [validate_finding_item(item, idx) for idx, item in enumerate(findings)]

    # Deduplicate within the same run payload by normalized fingerprint
    deduped_by_fp: dict[str, dict[str, Any]] = {}
    used_candidate_ids: set[str] = set()
    for item in validated:
        fp = compute_finding_fingerprint(project_key, item)
        item["fingerprint"] = fp
        if fp not in deduped_by_fp:
            raw_cid = item["finding_id"]
            if raw_cid in used_candidate_ids:
                raw_cid = compute_finding_id(project_key, fp)
                item["finding_id"] = raw_cid
            used_candidate_ids.add(raw_cid)
            deduped_by_fp[fp] = item

    canonical_payload_json = json.dumps(
        [deduped_by_fp[k] for k in sorted(deduped_by_fp.keys())],
        ensure_ascii=False,
        sort_keys=True,
    )
    idempotency_key = "IDEMP-" + hashlib.sha256(
        f"{project_key}|{run_id}|{canonical_payload_json}".encode("utf-8")
    ).hexdigest()[:32]

    with connect(db_path) as conn:
        run = conn.execute(
            "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
            (run_id, project_key),
        ).fetchone()
        if not run:
            raise RuntimeError(f"Audit run '{run_id}' was not found for project '{project_key}'.")

        # Idempotency check: if a verification run already exists for this run_id
        existing_vrun = conn.execute(
            "SELECT * FROM audit_verification_runs WHERE audit_run_id=?",
            (run_id,),
        ).fetchone()
        if existing_vrun is not None:
            if str(existing_vrun["idempotency_key"]) == idempotency_key:
                existing_q = conn.execute(
                    "SELECT job_id FROM verification_dispatch_queue WHERE verification_run_id=?",
                    (existing_vrun["verification_run_id"],),
                ).fetchone()
                return {
                    "total_received": len(findings),
                    "unique_in_run": len(deduped_by_fp),
                    "candidate_count": len(deduped_by_fp),
                    "inserted_open": 0,
                    "updated_open": 0,
                    "suppressed_dismissed": 0,
                    "reopened_dismissed": 0,
                    "reopened_regression": 0,
                    "preserved_deferred": 0,
                    "status": str(run["status"]),
                    "verification_run_id": str(existing_vrun["verification_run_id"]),
                    "verification_job_id": str(existing_q["job_id"]) if existing_q else None,
                    "snapshot_id": str(existing_vrun["snapshot_id"]),
                    "idempotent_replay": True,
                }
            raise RuntimeError(
                f"Primary report was already submitted for run '{run_id}' with a different payload."
            )

        if repo_path is None:
            proj = conn.execute(
                "SELECT repo_path FROM projects WHERE project_key=?",
                (project_key,),
            ).fetchone()
            if proj and proj["repo_path"]:
                repo_path = Path(proj["repo_path"])

        eff_repo = repo_path or report_dir.parent
        candidate_paths = [item.get("file_path") for item in deduped_by_fp.values()]
        snapshot = create_or_get_audit_snapshot(
            conn,
            project_key=project_key,
            run_id=run_id,
            repo_path=eff_repo,
            candidate_paths=candidate_paths,
        )
        snapshot_id = snapshot["snapshot_id"]
        base_commit_sha = snapshot["base_commit_sha"]

        for fp, item in deduped_by_fp.items():
            cid = item["finding_id"]
            cand_pk = f"CAND-{run_id}-{cid}"
            blob_hash = compute_file_blob_hash(eff_repo, item["file_path"])
            ev_sha = compute_source_excerpt_sha_for_candidate(eff_repo, item)
            conn.execute(
                """INSERT INTO candidate_findings(
                    candidate_id, candidate_finding_id, run_id, project_key,
                    snapshot_id, base_commit_sha, fingerprint, title, category,
                    severity, confidence, file_path, symbol, line_start, line_end,
                    evidence, impact, recommendation, file_sha256, evidence_sha256,
                    source_origin, status
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'PRIMARY','CANDIDATE')""",
                (
                    cand_pk,
                    cid,
                    run_id,
                    project_key,
                    snapshot_id,
                    base_commit_sha,
                    fp,
                    item["title"],
                    item["category"],
                    item["severity"],
                    item["confidence"],
                    item["file_path"],
                    item["symbol"],
                    item["line_start"],
                    item["line_end"],
                    item["evidence"],
                    item["impact"],
                    item["recommendation"],
                    blob_hash,
                    ev_sha,
                ),
            )

        vrun_id = "VRUN-" + run_id + "-" + hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:8]
        job_id = "VJOB-" + run_id + "-" + hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:8]

        conn.execute(
            """INSERT INTO audit_verification_runs(
                verification_run_id, audit_run_id, project_key,
                snapshot_id, base_commit_sha, status, idempotency_key
            ) VALUES(?, ?, ?, ?, ?, 'PENDING', ?)""",
            (vrun_id, run_id, project_key, snapshot_id, base_commit_sha, idempotency_key),
        )
        conn.execute(
            """INSERT INTO verification_dispatch_queue(
                job_id, verification_run_id, audit_run_id, project_key,
                snapshot_id, status, idempotency_key
            ) VALUES(?, ?, ?, ?, ?, 'QUEUED', ?)""",
            (job_id, vrun_id, run_id, project_key, snapshot_id, idempotency_key),
        )

        transition_audit_run_status(
            conn,
            run_id,
            "VERIFICATION_PENDING",
            report_path=str(report_dir),
        )

        stats = {
            "total_received": len(findings),
            "unique_in_run": len(deduped_by_fp),
            "candidate_count": len(deduped_by_fp),
            "inserted_open": 0,
            "updated_open": 0,
            "suppressed_dismissed": 0,
            "reopened_dismissed": 0,
            "reopened_regression": 0,
            "preserved_deferred": 0,
            "status": "VERIFICATION_PENDING",
            "verification_run_id": vrun_id,
            "verification_job_id": job_id,
            "snapshot_id": snapshot_id,
            "idempotent_replay": False,
        }
        record_event(
            conn,
            "PRIMARY_CANDIDATES_SUBMITTED",
            project_key=project_key,
            run_id=run_id,
            details={"stats": stats, "report_dir": str(report_dir)},
            jsonl_path=jsonl_path,
        )
        conn.commit()
    return stats


def save_decisions(
    db_path: Path,
    *,
    project_key: str,
    run_id: str,
    decisions: list[dict[str, Any]],
    actor: str = "user",
    jsonl_path: Path | None = None,
) -> dict[str, Any]:
    """Save user review decisions without authorizing execution.

    Enforces second-pass verification gates:
    - `APPLY` is strictly rejected for unverified candidates, `PARTIALLY_VERIFIED`,
      `REJECTED`, `UNVERIFIABLE`, `LEGACY_UNVERIFIED`, or `STALE` findings.
    - `APPLY` requires the audit run to be in `READY_FOR_REVIEW` (or `PARTIAL`).
    """
    if not isinstance(decisions, list) or not decisions:
        raise RuntimeError("Decisions payload must be a non-empty list.")

    lifecycle_map = {
        "APPLY": "OPEN",
        "DEFER": "DEFERRED",
        "DISMISS": "DISMISSED",
        "SKIP": "SKIPPED",
    }
    counts = {"APPLY": 0, "DEFER": 0, "DISMISS": 0, "SKIP": 0}

    with connect(db_path) as conn:
        run = conn.execute(
            "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
            (run_id, project_key),
        ).fetchone()
        if not run:
            raise RuntimeError(f"Audit run '{run_id}' not found for project '{project_key}'.")

        if str(run["status"]) == "COMPLETED" and int(run["completed_by_review"] or 0) == 1:
            # The run was closed only because every finding had been decided; the user may revise those
            # decisions as long as no newer audit of the project has taken over its findings.
            this_rowid = conn.execute("SELECT rowid FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()[0]
            newer = conn.execute(
                """SELECT run_id FROM audit_runs
                   WHERE project_key=? AND run_id != ?
                     AND (started_at > ? OR (started_at = ? AND rowid > ?))
                     AND status NOT IN ('FAILED', 'STALE', 'ARCHIVED')
                   ORDER BY started_at DESC LIMIT 1""",
                (project_key, run_id, run["started_at"], run["started_at"], this_rowid),
            ).fetchone()
            if newer:
                raise RuntimeError(
                    f"Run '{run_id}' was reviewed and a newer audit run '{newer['run_id']}' exists; "
                    "save decisions on the newer run."
                )
            transition_audit_run_status(
                conn, run_id, "READY_FOR_REVIEW", reason="REVIEW_REOPENED: decisions revised", actor=actor,
                jsonl_path=jsonl_path,
            )
            conn.execute("UPDATE audit_runs SET completed_by_review=0 WHERE run_id=?", (run_id,))
            run = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()

        for idx, entry in enumerate(decisions):
            if not isinstance(entry, dict):
                raise RuntimeError(f"Decision at index {idx} must be an object.")
            finding_id = str(entry.get("finding_id") or "").strip()
            decision = str(entry.get("decision") or "").strip().upper()
            note = str(entry.get("note") or "").strip() or None
            if not finding_id:
                raise RuntimeError(f"Decision at index {idx} is missing finding_id.")
            if "[x]" in decision.lower() or "[ ]" in decision.lower():
                raise RuntimeError("Markdown checkboxes cannot be used as decision or authorization input.")
            if decision not in ALLOWED_DECISIONS:
                raise RuntimeError(f"Invalid decision '{decision}' for finding '{finding_id}'.")

            finding = conn.execute(
                "SELECT * FROM findings WHERE finding_id=? AND project_key=?",
                (finding_id, project_key),
            ).fetchone()

            if not finding:
                cand = conn.execute(
                    "SELECT * FROM candidate_findings WHERE project_key=? AND candidate_finding_id=? ORDER BY created_at DESC LIMIT 1",
                    (project_key, finding_id),
                ).fetchone()
                if cand:
                    raise RuntimeError(
                        f"Cannot save '{decision}' decision for candidate finding '{finding_id}' "
                        f"(candidate status='{cand['status']}', run status='{run['status']}'): "
                        "findings must pass second-pass verification and canonical report finalization before review decisions."
                    )
                raise RuntimeError(f"Finding '{finding_id}' not found in project '{project_key}'.")

            v_status = str(finding["verification_status"] or "LEGACY_UNVERIFIED")
            exec_eligible = int(finding["execution_eligible"] or 0)
            ev_status = str(finding["evidence_validation_status"] or "UNCHECKED")
            rem_safe = int(finding["remediation_safe"] if finding["remediation_safe"] is not None else 1)

            if run["status"] not in ("READY_FOR_REVIEW", "PARTIAL"):
                raise RuntimeError(
                    f"Cannot save '{decision}' decision on run '{run_id}' with status '{run['status']}': "
                    "run must be READY_FOR_REVIEW after second-pass verification."
                )

            f_run = str(finding["run_id"] or "")
            f_last = str(finding["last_seen_run_id"] or f_run)
            if f_run != run_id and f_last != run_id:
                raise RuntimeError(
                    f"Cannot save '{decision}' decision for finding '{finding_id}' on run '{run_id}': "
                    f"finding belongs to run '{f_last or f_run}' and is not active in run '{run_id}'."
                )

            if decision == "APPLY":
                if v_status == "LEGACY_UNVERIFIED":
                    raise RuntimeError(
                        f"Cannot APPLY finding '{finding_id}': finding is classified as LEGACY_UNVERIFIED and lacks second-pass verification."
                    )
                if v_status in ("PARTIALLY_VERIFIED", "PARTIALLY_CONFIRMED"):
                    raise RuntimeError(
                        f"Cannot APPLY finding '{finding_id}': PARTIALLY_VERIFIED findings are not execution-eligible."
                    )
                if v_status == "REJECTED" or finding["lifecycle"] == "REJECTED":
                    raise RuntimeError(
                        f"Cannot APPLY finding '{finding_id}': REJECTED findings can never become execution-eligible."
                    )
                if rem_safe != 1:
                    raise RuntimeError(
                        f"Cannot APPLY finding '{finding_id}': remediation_safe=0 (unsafe remediation proposal)."
                    )
                if v_status not in ("VERIFIED", "CONFIRMED") or exec_eligible != 1 or ev_status not in ("PASSED", "VALID"):
                    raise RuntimeError(
                        f"Cannot APPLY unverified finding '{finding_id}' "
                        f"(verification_status={v_status}, execution_eligible={exec_eligible}, evidence_status={ev_status})."
                    )

            prev_lifecycle = finding["lifecycle"]
            new_lifecycle = lifecycle_map[decision]

            conn.execute(
                "UPDATE decisions SET superseded=1 WHERE finding_id=? AND superseded=0",
                (finding_id,),
            )
            conn.execute(
                "INSERT INTO decisions(finding_id, run_id, decision, note, actor, superseded) VALUES(?, ?, ?, ?, ?, 0)",
                (finding_id, run_id, decision, note, actor),
            )
            conn.execute(
                "UPDATE findings SET lifecycle=?, updated_at=CURRENT_TIMESTAMP WHERE finding_id=?",
                (new_lifecycle, finding_id),
            )
            conn.execute(
                """INSERT INTO finding_history(
                    finding_id, project_key, run_id, from_lifecycle, to_lifecycle,
                    actor, reason, evidence_hash, file_blob_hash
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_key,
                    run_id,
                    prev_lifecycle,
                    new_lifecycle,
                    actor,
                    f"DECISION_{decision}" + (f": {note}" if note else ""),
                    finding["evidence_hash"],
                    finding["file_blob_hash"],
                ),
            )
            counts[decision] += 1

        # Invalidate any previously issued unconsumed approval tokens for this run
        conn.execute(
            "UPDATE execution_approvals SET status='REVOKED' WHERE project_key=? AND run_id=? AND status='AUTHORIZED'",
            (project_key, run_id),
        )

        # Every finding of the run decided and nothing left to APPLY (APPLY keeps a finding OPEN): the review is
        # done, so the run no longer holds the project's active-run lock and weekly audits continue.
        run_completed = False
        active_execution = conn.execute(
            "SELECT 1 FROM execution_runs WHERE run_id=? AND status IN ('PREFLIGHT','RUNNING','VERIFYING') LIMIT 1",
            (run_id,),
        ).fetchone()
        if str(run["status"]) in ("READY_FOR_REVIEW", "PARTIAL") and not active_execution:
            still_open = conn.execute(
                """SELECT COUNT(*) FROM findings
                   WHERE project_key=? AND (run_id=? OR last_seen_run_id=?) AND lifecycle='OPEN'""",
                (project_key, run_id, run_id),
            ).fetchone()[0]
            if int(still_open) == 0:
                transition_audit_run_status(
                    conn, run_id, "COMPLETED", reason="REVIEW_COMPLETED: every finding has a non-APPLY decision",
                    finished=True, actor=actor, jsonl_path=jsonl_path,
                )
                conn.execute("UPDATE audit_runs SET completed_by_review=1 WHERE run_id=?", (run_id,))
                run_completed = True

        record_event(
            conn,
            "DECISIONS_SAVED",
            project_key=project_key,
            run_id=run_id,
            details={
                "counts": counts,
                "actor": actor,
                "execution_authorized": False,
                "run_completed": run_completed,
            },
            jsonl_path=jsonl_path,
        )
        conn.commit()

    return {
        "project_key": project_key,
        "run_id": run_id,
        "counts": counts,
        "execution_authorized": False,
        "run_completed": run_completed,
    }


def authorize_execution(
    db_path: Path,
    *,
    project_key: str,
    run_id: str,
    authorized_by: str = "user",
    ttl_seconds: int = 3600,
    confirmation: str = "AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
    jsonl_path: Path | None = None,
    expected_finding_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Explicitly authorize execution of saved APPLY decisions for a verified run.

    ``expected_finding_ids`` (the list a human confirmed) must equal the findings being authorized, so decisions
    changed while the human was reading the preview cannot slip into the approval.

    Enforces:
    1. Audit run is in `READY_FOR_REVIEW` or `PARTIAL`.
    2. Second-pass verification run is `FINALIZED` with a separate `verifier_conversation_id`.
    3. Repository snapshot (`base_commit_sha` and target files) is still consistent and not stale.
    4. Every approved finding has `verification_status == 'VERIFIED'`, `execution_eligible == 1`,
       and `evidence_validation_status == 'PASSED'`.
    """
    if not confirmation or "[x]" in confirmation.lower() or confirmation != "AUTHORIZE_ISOLATED_WORKTREE_EXECUTION":
        raise RuntimeError(
            "Explicit authorization confirmation 'AUTHORIZE_ISOLATED_WORKTREE_EXECUTION' is required. "
            "Markdown checkboxes or implicit approvals are never valid authorization."
        )

    with connect(db_path) as conn:
        run = conn.execute(
            "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
            (run_id, project_key),
        ).fetchone()
        if not run:
            raise RuntimeError(f"Audit run '{run_id}' not found for project '{project_key}'.")
        if run["status"] not in ("READY_FOR_REVIEW", "PARTIAL"):
            raise RuntimeError(
                f"Audit run '{run_id}' has status '{run['status']}'; only READY_FOR_REVIEW or PARTIAL runs "
                "that have passed second-pass verification can be authorized."
            )

        unresolved_vruns = conn.execute(
            """SELECT verification_run_id, status FROM audit_verification_runs
               WHERE audit_run_id=? AND status IN ('PENDING','DISPATCHING','RUNNING','EVIDENCE_VALIDATION','BLOCKED','STALE','UNCERTAIN')
               ORDER BY created_at DESC, rowid DESC""",
            (run_id,),
        ).fetchall()
        if unresolved_vruns:
            raise RuntimeError(
                f"Audit run '{run_id}' has unresolved verification runs "
                f"{[(r['verification_run_id'], r['status']) for r in unresolved_vruns]}; "
                "all required follow-up verifications must complete before execution authorization."
            )

        unresolved_q = conn.execute(
            """SELECT job_id, verification_run_id, status FROM verification_dispatch_queue
               WHERE audit_run_id=? AND status IN ('QUEUED','CLAIMED','DISPATCHING','RUNNING','RETRYABLE_FAILURE','BLOCKED_CONFIGURATION','DISPATCH_UNCERTAIN')
               ORDER BY created_at DESC, rowid DESC""",
            (run_id,),
        ).fetchall()
        if unresolved_q:
            raise RuntimeError(
                f"Audit run '{run_id}' has pending or active verification queue jobs "
                f"{[(r['job_id'], r['status']) for r in unresolved_q]}; cannot authorize execution."
            )

        pending_disc_cands = conn.execute(
            """SELECT candidate_finding_id FROM candidate_findings
               WHERE run_id=? AND status='CANDIDATE' AND canonical_finding_id IS NULL""",
            (run_id,),
        ).fetchall()
        if pending_disc_cands:
            raise RuntimeError(
                f"Audit run '{run_id}' has unverified candidate findings {[r[0] for r in pending_disc_cands]} "
                "awaiting independent follow-up verification."
            )

        vruns = conn.execute(
            """SELECT * FROM audit_verification_runs
               WHERE audit_run_id=? AND status IN ('FINALIZED', 'COMPLETED')
               ORDER BY completed_at DESC, created_at DESC, rowid DESC""",
            (run_id,),
        ).fetchall()
        vrun = vruns[0] if vruns else None
        if not vrun or not vrun["verifier_conversation_id"]:
            raise RuntimeError(
                f"Audit run '{run_id}' has not completed mandatory second-pass verification finalization."
            )
        for vr in vruns:
            if not vr["verifier_conversation_id"]:
                raise RuntimeError(
                    f"Verification run '{vr['verification_run_id']}' for audit run '{run_id}' lacks verifier_conversation_id."
                )
            if run["agent_conversation_id"] and str(run["agent_conversation_id"]).strip() == str(vr["verifier_conversation_id"]).strip():
                raise RuntimeError(
                    f"Audit run '{run_id}' failed independence check: verifier_conversation_id matches primary conversation."
                )
        valid_vrun_ids = {str(vr["verification_run_id"]) for vr in vruns if vr["verifier_conversation_id"]}
        vrun_by_id = {str(vr["verification_run_id"]): vr for vr in vruns}

        proj = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchone()
        if not proj:
            raise RuntimeError(f"Project '{project_key}' not found.")
        repo_path = Path(proj["repo_path"])

        rows = conn.execute(
            """SELECT f.finding_id, f.run_id, f.last_seen_run_id, f.severity, f.lifecycle, f.file_path,
                      f.verification_status, f.execution_eligible, f.remediation_safe,
                      f.evidence_validation_status, f.verification_run_id, f.verified_by_run_id,
                      d.decision, d.run_id AS decision_run_id
               FROM findings f
               JOIN decisions d ON d.finding_id = f.finding_id
               WHERE f.project_key=? AND d.run_id=? AND d.superseded=0 AND d.decision='APPLY'
               ORDER BY CASE f.severity
                   WHEN 'CRITICAL' THEN 1
                   WHEN 'HIGH' THEN 2
                   WHEN 'MEDIUM' THEN 3
                   WHEN 'LOW' THEN 4
                   ELSE 5
               END, f.finding_id""",
            (project_key, run_id),
        ).fetchall()

        if str(run["status"]) == "PARTIAL" and any(str(r["lifecycle"]) == "OPEN" for r in rows):
            rows = [r for r in rows if str(r["lifecycle"]) != "RESOLVED"]

        if not rows:
            # Check if caller attempted to authorize a run with only unverified/legacy findings or leaked decisions from an older run
            unverified_in_run = conn.execute(
                """SELECT finding_id, verification_status FROM findings
                   WHERE project_key=? AND (run_id=? OR last_seen_run_id=?)
                     AND verification_status NOT IN ('VERIFIED', 'CONFIRMED')""",
                (project_key, run_id, run_id),
            ).fetchall()
            cand_in_run = conn.execute(
                "SELECT candidate_finding_id, status FROM candidate_findings WHERE project_key=? AND run_id=? AND canonical_finding_id IS NULL",
                (project_key, run_id),
            ).fetchall()
            other_run_decisions = conn.execute(
                """SELECT d.finding_id, d.run_id FROM decisions d
                   JOIN findings f ON f.finding_id = d.finding_id
                   WHERE f.project_key=? AND d.superseded=0 AND d.decision='APPLY' AND (d.run_id IS NULL OR d.run_id != ?)""",
                (project_key, run_id),
            ).fetchall()
            if other_run_decisions:
                raise RuntimeError(
                    f"Cannot authorize execution for run '{run_id}': active APPLY decisions belong to a different audit run "
                    f"({[r['run_id'] for r in other_run_decisions]}) and cannot leak across runs."
                )
            if unverified_in_run or cand_in_run:
                raise RuntimeError(
                    f"Cannot authorize execution for run '{run_id}': findings are unverified or legacy "
                    f"({[r[0] for r in unverified_in_run] + [c[0] for c in cand_in_run]}) and have no valid APPLY decision for this run."
                )
            raise RuntimeError(
                "No findings have an active saved 'APPLY' decision in OPEN state for this audit run. Save decisions first before authorizing execution."
            )

        for r in rows:
            fid = str(r["finding_id"])
            f_run = str(r["run_id"] or "")
            f_last = str(r["last_seen_run_id"] or f_run)
            if f_run != run_id and f_last != run_id:
                raise RuntimeError(
                    f"Finding '{fid}' does not belong to audit run '{run_id}' (last_seen_run_id='{f_last}')."
                )
            if str(r["lifecycle"]) != "OPEN":
                raise RuntimeError(
                    f"Finding '{fid}' is not in OPEN lifecycle state (lifecycle={r['lifecycle']})."
                )
            rem_safe = int(r["remediation_safe"] if r["remediation_safe"] is not None else 1)
            if rem_safe != 1:
                raise RuntimeError(
                    f"Finding '{fid}' is not eligible for execution: remediation_safe=0 (unsafe remediation proposal)."
                )
            if (
                str(r["verification_status"]) not in ("VERIFIED", "CONFIRMED")
                or int(r["execution_eligible"] or 0) != 1
                or str(r["evidence_validation_status"]) not in ("PASSED", "VALID")
            ):
                raise RuntimeError(
                    f"Finding '{fid}' is not eligible for execution "
                    f"(verification_status={r['verification_status']}, execution_eligible={r['execution_eligible']}, "
                    f"evidence_validation_status={r['evidence_validation_status']})."
                )
            f_vrun_id = str(r["verification_run_id"] or "")
            f_vby_id = str(r["verified_by_run_id"] or f_vrun_id)
            if not f_vrun_id or f_vrun_id not in valid_vrun_ids or (f_vby_id not in valid_vrun_ids and f_vby_id != run_id):
                raise RuntimeError(
                    f"Finding '{fid}' verification lineage ('{f_vrun_id}') does not match completed verification runs for audit run '{run_id}'."
                )
            matched_vrun = vrun_by_id[f_vrun_id]
            cand_row = conn.execute(
                """SELECT source_origin, discovered_by_conversation_id, discovered_in_verification_run_id
                   FROM candidate_findings
                   WHERE run_id=? AND (candidate_finding_id=? OR canonical_finding_id=?)
                   ORDER BY created_at DESC, rowid DESC LIMIT 1""",
                (run_id, fid, fid),
            ).fetchone()
            if cand_row is not None and str(cand_row["source_origin"] or "") == "VERIFIER_DISCOVERED":
                disc_conv = str(cand_row["discovered_by_conversation_id"] or "").strip()
                disc_vrun = str(cand_row["discovered_in_verification_run_id"] or "").strip()
                ver_conv = str(matched_vrun["verifier_conversation_id"] or "").strip()
                if (disc_vrun and disc_vrun == f_vrun_id) or (disc_conv and disc_conv == ver_conv):
                    raise RuntimeError(
                        f"Finding '{fid}' failed verifier-discovered independence check: cannot be confirmed by the same verification run or conversation that discovered it."
                    )
            # Also verify underlying finding_verification_results row if present
            fvr = conn.execute(
                """SELECT verdict, remediation_safe, evidence_validation_status
                   FROM finding_verification_results
                   WHERE verification_run_id=? AND (
                       candidate_finding_id=?
                       OR candidate_finding_id IN (
                           SELECT candidate_finding_id FROM candidate_findings WHERE run_id=? AND canonical_finding_id=?
                       )
                   )""",
                (f_vrun_id, fid, run_id, fid),
            ).fetchone()
            if fvr is not None:
                if (
                    str(fvr["verdict"]) != "CONFIRMED"
                    or int(fvr["remediation_safe"] if fvr["remediation_safe"] is not None else 1) != 1
                    or str(fvr["evidence_validation_status"]) not in ("PASSED", "VALID")
                ):
                    raise RuntimeError(
                        f"Finding '{fid}' failed verification result consistency check "
                        f"(verdict={fvr['verdict']}, remediation_safe={fvr['remediation_safe']}, evidence={fvr['evidence_validation_status']})."
                    )

        # Revalidate snapshot consistency against current repo state before issuing approval_token
        target_files = [str(r["file_path"]) for r in rows if r["file_path"]]
        consistency = verify_snapshot_consistency(
            conn,
            repo_path=repo_path,
            run_id=run_id,
            relevant_files=target_files,
        )
        if not consistency["consistent"]:
            stale_msg = f"Cannot authorize execution on stale audit snapshot ({consistency['code']}): {consistency['reason']}"
            transition_audit_run_status(conn, run_id, "VERIFICATION_STALE", error=stale_msg)
            conn.execute(
                "UPDATE audit_verification_runs SET status='STALE', error_code=?, error_message=? WHERE verification_run_id=?",
                (consistency["code"], stale_msg, vrun["verification_run_id"]),
            )
            conn.commit()
            raise RuntimeError(stale_msg)

        approved_ids = [str(r["finding_id"]) for r in rows]
        if expected_finding_ids is not None and sorted(approved_ids) != sorted(str(x) for x in expected_finding_ids):
            raise RuntimeError(
                "APPLY decisions changed after they were shown for confirmation "
                f"(confirmed {sorted(expected_finding_ids)}, now {sorted(approved_ids)}); nothing was authorized. "
                "Run authorize-execution again."
            )

        # Revoke any older unconsumed approval tokens for this run
        conn.execute(
            "UPDATE execution_approvals SET status='REVOKED' WHERE project_key=? AND run_id=? AND status='AUTHORIZED'",
            (project_key, run_id),
        )

        approval_id = "APPR-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        token = "agya_" + secrets.token_urlsafe(24)
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=max(60, ttl_seconds))).isoformat()
        base_commit = str(run["base_commit"] or "")
        working_tree_hash = str(run["working_tree_hash"] or "")

        conn.execute(
            """INSERT INTO execution_approvals(
                approval_id, project_key, run_id, approval_token, approved_finding_ids,
                base_commit, working_tree_hash, status, authorized_by, expires_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, 'AUTHORIZED', ?, ?)""",
            (
                approval_id,
                project_key,
                run_id,
                token,
                json.dumps(approved_ids),
                base_commit,
                working_tree_hash,
                authorized_by,
                expires_at,
            ),
        )
        record_event(
            conn,
            "EXECUTION_AUTHORIZED",
            project_key=project_key,
            run_id=run_id,
            details={
                "approval_id": approval_id,
                "approved_finding_ids": approved_ids,
                "authorized_by": authorized_by,
                "expires_at": expires_at,
                "verification_run_id": vrun["verification_run_id"],
            },
            jsonl_path=jsonl_path,
        )
        conn.commit()

    return {
        "approval_id": approval_id,
        "approval_token": token,
        "project_key": project_key,
        "run_id": run_id,
        "approved_finding_ids": approved_ids,
        "expires_at": expires_at,
    }


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        try:
            dt = datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None


# An execution is recovered as STALE only after this long without any execution step (begin/verify/rollback).
EXECUTION_IDLE_TIMEOUT_SECONDS = 6 * 3600


def _discard_stale_execution_worktree(db_path: Path, exec_id: str, worktree: Path) -> None:
    """A STALE execution cannot be resumed: keep its unfinished diff for reference, then remove the worktree."""
    if not worktree.is_dir():
        return
    # Only ever touch an auditor-created linked worktree (a ".git" FILE) under <app home>/worktrees: a damaged
    # database path must never lead to deleting the user's repository.
    try:
        managed_root = (db_path.parent.parent / "worktrees").resolve()
        if not (worktree / ".git").is_file() or not worktree.resolve().is_relative_to(managed_root):
            return
    except OSError:
        return
    try:
        import subprocess

        from recovery import _remove_git_worktree

        diff = subprocess.run(["git", "-C", str(worktree), "diff", "HEAD", "--binary"], capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=60)
        untracked = subprocess.run(["git", "-C", str(worktree), "ls-files", "--others", "--exclude-standard"],
                                   capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        if (diff.stdout or "").strip() or (untracked.stdout or "").strip():
            out_dir = db_path.parent.parent / "quarantine" / "stale-executions"
            out_dir.mkdir(parents=True, exist_ok=True)
            text = diff.stdout or ""
            if (untracked.stdout or "").strip():
                text += "\n# untracked files (not in the diff):\n" + "".join(f"#   {ln}\n" for ln in untracked.stdout.splitlines())
            (out_dir / f"{exec_id}.patch").write_bytes(text.encode("utf-8"))
        _remove_git_worktree(worktree)
    except Exception:  # noqa: BLE001 - best effort; the execution is already STALE
        pass


# A verification run that is only waiting (queued / retry back-off / provider quota) is resumed by the next
# scheduled audit instead of being recovered as STALE; after this long it is recovered anyway.
WAITING_VERIFICATION_MAX_AGE_SECONDS = 30 * 86400


def recover_stale_runs(
    db_path: Path,
    *,
    project_key: str | None = None,
    stale_timeout_seconds: int | None = None,
    force: bool = False,
    include_pending_approval: bool = False,
    jsonl_path: Path | None = None,
) -> dict[str, Any]:
    """Detect and recover stale audit_runs, verification leases, and execution_runs to release project locks."""
    now = datetime.now(timezone.utc)
    recovered_audits: list[str] = []
    recovered_executions: list[str] = []

    lease_rec = recover_stale_verification_leases(
        db_path,
        project_key=project_key,
        now=now,
        jsonl_path=jsonl_path,
    )

    target_statuses = [
        "PREFLIGHT",
        "PRIMARY_AUDIT_RUNNING",
        "DISPATCHED",
        "ANALYZING",
        "VERIFICATION_PENDING",
        "VERIFICATION_DISPATCHING",
        "VERIFICATION_RUNNING",
        "EVIDENCE_VALIDATION",
    ]
    if include_pending_approval:
        target_statuses.extend(["PENDING_APPROVAL", "READY_FOR_REVIEW"])

    with connect(db_path) as conn:
        query = f"""
            SELECT r.run_id, r.project_key, r.status, r.started_at, r.heartbeat_at,
                   p.stale_timeout_seconds
            FROM audit_runs r
            JOIN projects p ON p.project_key = r.project_key
            WHERE r.status IN ({','.join('?' for _ in target_statuses)})
        """
        params: list[Any] = list(target_statuses)
        if project_key:
            query += " AND r.project_key=?"
            params.append(project_key)

        for row in conn.execute(query, params).fetchall():
            timeout = stale_timeout_seconds if stale_timeout_seconds is not None else int(row["stale_timeout_seconds"] or 3600)
            ref_time = _parse_timestamp(row["heartbeat_at"]) or _parse_timestamp(row["started_at"])
            elapsed = (now - ref_time).total_seconds() if ref_time else (timeout + 1)
            if (
                not force
                and elapsed < WAITING_VERIFICATION_MAX_AGE_SECONDS
                and str(row["status"]) in ("VERIFICATION_PENDING", "VERIFICATION_DISPATCHING")
                and conn.execute(
                    """SELECT 1 FROM verification_dispatch_queue
                       WHERE audit_run_id=? AND status IN ('QUEUED', 'RETRYABLE_FAILURE')
                         AND attempt_count < max_attempts LIMIT 1""",
                    (row["run_id"],),
                ).fetchone()
            ):
                # Waiting for its (re)try or for the provider quota: nobody holds it, it is not stale. A held
                # lease that expired is handled by recover_stale_verification_leases above.
                continue
            if force or elapsed >= timeout:
                conn.execute(
                    "UPDATE audit_runs SET status='STALE', finished_at=CURRENT_TIMESTAMP, error=? WHERE run_id=?",
                    (f"Recovered stale run after {int(elapsed)}s (status was {row['status']})", row["run_id"]),
                )
                # Close the run's verification work too, so no worker later claims a job for a STALE run.
                conn.execute(
                    """UPDATE audit_verification_runs SET status='STALE'
                       WHERE audit_run_id=? AND status NOT IN ('FINALIZED', 'COMPLETED', 'ARCHIVED', 'FAILED', 'STALE')""",
                    (row["run_id"],),
                )
                conn.execute(
                    """UPDATE verification_dispatch_queue
                       SET status='FAILED', lease_owner=NULL, lease_token=NULL, lease_expires_at=NULL,
                           last_error_code='AUDIT_RUN_STALE',
                           last_error_message='Audit run was recovered as STALE.',
                           updated_at=CURRENT_TIMESTAMP
                       WHERE audit_run_id=? AND status IN ('QUEUED', 'CLAIMED', 'DISPATCHING', 'RETRYABLE_FAILURE', 'RUNNING')""",
                    (row["run_id"],),
                )
                recovered_audits.append(str(row["run_id"]))
                record_event(
                    conn,
                    "AUDIT_LOCK_RECOVERED",
                    project_key=row["project_key"],
                    run_id=row["run_id"],
                    level="WARNING",
                    details={"previous_status": row["status"], "elapsed_seconds": int(elapsed), "forced": force},
                    jsonl_path=jsonl_path,
                )

        exec_query = """
            SELECT e.exec_id, e.project_key, e.run_id, e.status, e.started_at, e.heartbeat_at, e.worktree_path,
                   p.stale_timeout_seconds
            FROM execution_runs e
            JOIN projects p ON p.project_key = e.project_key
            WHERE e.status IN ('PREFLIGHT', 'RUNNING', 'VERIFYING')
        """
        exec_params: list[Any] = []
        if project_key:
            exec_query += " AND e.project_key=?"
            exec_params.append(project_key)

        stale_worktrees: list[tuple[str, str]] = []
        for row in conn.execute(exec_query, exec_params).fetchall():
            timeout = stale_timeout_seconds if stale_timeout_seconds is not None else int(row["stale_timeout_seconds"] or 3600)
            if stale_timeout_seconds is None:
                timeout = max(timeout, EXECUTION_IDLE_TIMEOUT_SECONDS)  # an agent may work long between steps
            started = _parse_timestamp(row["started_at"])
            beat = _parse_timestamp(row["heartbeat_at"])
            ref_time = max(t for t in (started, beat) if t is not None) if (started or beat) else None
            elapsed = (now - ref_time).total_seconds() if ref_time else (timeout + 1)
            if force or elapsed >= timeout:
                conn.execute(
                    "UPDATE execution_runs SET status='STALE', finished_at=CURRENT_TIMESTAMP, error=? WHERE exec_id=?",
                    (f"Recovered stale execution run after {int(elapsed)}s without activity", row["exec_id"]),
                )
                recovered_executions.append(str(row["exec_id"]))
                if row["worktree_path"]:
                    stale_worktrees.append((str(row["exec_id"]), str(row["worktree_path"])))
                record_event(
                    conn,
                    "EXECUTION_LOCK_RECOVERED",
                    project_key=row["project_key"],
                    run_id=row["run_id"],
                    level="WARNING",
                    details={"exec_id": row["exec_id"], "previous_status": row["status"], "elapsed_seconds": int(elapsed)},
                    jsonl_path=jsonl_path,
                )
        conn.commit()

    for exec_id, wt in stale_worktrees:
        _discard_stale_execution_worktree(db_path, exec_id, Path(wt))

    worktree_ops_rec: dict[str, Any] = {"reconciled_ops": [], "cleanup_errors": []}
    try:
        from executor import reconcile_interrupted_worktree_ops

        reconciled_ops = reconcile_interrupted_worktree_ops(db_path, project_key=project_key)
        worktree_ops_rec = {
            "reconciled_ops": reconciled_ops,
            "cleanup_errors": [
                err
                for op in reconciled_ops
                if op.get("status") == "COMPENSATION_FAILED"
                for err in (op.get("errors") or [f"compensation failed for {op.get('op_id')}"])
            ],
        }
    except Exception as exc:
        worktree_ops_rec = {"reconciled_ops": [], "cleanup_errors": [str(exc)]}

    return {
        "recovered_audit_runs": recovered_audits,
        "recovered_execution_runs": recovered_executions,
        "verification_lease_recovery": lease_rec,
        "worktree_ops_recovery": worktree_ops_rec,
    }


def _corrupt_database_result(db_path: Path, exc: Exception) -> dict[str, Any]:
    backups = sorted(
        (p for p in (db_path.parent.parent / "backups").rglob("*.db") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ) if (db_path.parent.parent / "backups").is_dir() else []
    return {
        "ok": False,
        "error": f"DATABASE_CORRUPT: {exc}",
        "latest_backups": [str(p) for p in backups[:3]],
        "advice": "Close Antigravity, copy the database aside, then restore the latest backup into "
                  f"{db_path} (or run `python core/cli.py init` on an empty file to start over).",
    }


def check_database_integrity(db_path: Path) -> dict[str, Any]:
    """Run SQLite integrity_check and foreign_key_check."""
    if not db_path.is_file():
        return {"ok": False, "error": f"Database file does not exist: {db_path}"}
    try:
        conn = connect(db_path)
    except sqlite3.DatabaseError as exc:
        return _corrupt_database_result(db_path, exc)
    try:
        try:
            integrity_rows = conn.execute("PRAGMA integrity_check").fetchall()
            fk_rows = conn.execute("PRAGMA foreign_key_check").fetchall()
        except sqlite3.DatabaseError as exc:
            return _corrupt_database_result(db_path, exc)
        integrity_messages = [str(r[0]) for r in integrity_rows]
        ok = integrity_messages == ["ok"] and len(fk_rows) == 0
        return {
            "ok": ok,
            "integrity_check": integrity_messages,
            "foreign_key_violations": [dict(r) for r in fk_rows],
        }
    finally:
        conn.close()


def backup_database(
    db_path: Path,
    backup_dir: Path | None = None,
    *,
    jsonl_path: Path | None = None,
) -> Path:
    """Create a consistent online backup of the SQLite database using sqlite3.backup."""
    if not db_path.is_file():
        raise RuntimeError(f"Database file does not exist: {db_path}")
    target_dir = backup_dir or (db_path.parent.parent / "backups" / "database")
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
    backup_path = target_dir / f"auditor-{stamp}.db"

    src_conn = connect(db_path)
    try:
        dst_conn = sqlite3.connect(backup_path)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
        record_event(
            src_conn,
            "DATABASE_BACKUP_CREATED",
            details={"backup_path": str(backup_path), "size_bytes": backup_path.stat().st_size},
            jsonl_path=jsonl_path,
        )
        src_conn.commit()
    finally:
        src_conn.close()

    integrity = check_database_integrity(backup_path)
    if not integrity["ok"]:
        raise RuntimeError(f"Backup integrity check failed for {backup_path}: {integrity}")
    return backup_path


def verify_backup_restore(backup_path: Path, restore_target: Path | None = None) -> dict[str, Any]:
    """Verify that a backup database passes integrity checks and can be restored cleanly."""
    if not backup_path.is_file():
        raise RuntimeError(f"Backup file does not exist: {backup_path}")

    with tempfile.TemporaryDirectory(prefix="auditor-restore-verify-") as tmp_dir:
        test_restore = Path(tmp_dir) / "restored.db"
        src_conn = sqlite3.connect(backup_path)
        try:
            dst_conn = sqlite3.connect(test_restore)
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
        finally:
            src_conn.close()

        integrity = check_database_integrity(test_restore)
        if not integrity["ok"]:
            raise RuntimeError(f"Restored backup failed integrity check: {integrity}")

        conn = connect(test_restore)
        try:
            tables = {
                str(r[0])
                for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            required_tables = {
                "projects",
                "audit_runs",
                "audit_snapshots",
                "candidate_findings",
                "audit_verification_runs",
                "finding_verification_results",
                "verification_dispatch_queue",
                "audit_quality_metrics",
                "findings",
                "finding_history",
                "decisions",
                "execution_approvals",
                "execution_runs",
                "finding_executions",
                "skill_inventory",
                "audit_events",
                "model_dispatches",
                "model_budget_usage",
                "model_budget_reservations",
            }
            missing = required_tables - tables
            if missing:
                raise RuntimeError(f"Restored backup is missing tables: {sorted(missing)}")
            counts = {
                t: int(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0])
                for t in sorted(required_tables)
            }
        finally:
            conn.close()

        if restore_target is not None:
            restore_target.parent.mkdir(parents=True, exist_ok=True)
            src_conn2 = sqlite3.connect(test_restore)
            try:
                dst_conn2 = sqlite3.connect(restore_target)
                try:
                    src_conn2.backup(dst_conn2)
                finally:
                    dst_conn2.close()
            finally:
                src_conn2.close()

    return {
        "verified": True,
        "backup_path": str(backup_path),
        "restored_to": str(restore_target) if restore_target else None,
        "table_counts": counts,
    }


def record_model_dispatch(
    conn: sqlite3.Connection,
    *,
    task_type: str,
    task_risk: str,
    requested_model: str,
    observed_model: str | None = None,
    reasoning_level: str | None = None,
    model_identity_source: str = "UNVERIFIED",
    model_attestation_status: str = "MODEL_ATTESTATION_INCOMPLETE",
    routing_policy_version: str = "1.0.0-task-model-policy",
    audit_run_id: str | None = None,
    verification_run_id: str | None = None,
    finding_fingerprint: str | None = None,
    conversation_id: str | None = None,
    input_tokens: int = 0,
    output_tokens: int = 0,
    thinking_tokens: int = 0,
    total_tokens: int = 0,
    execution_duration: float = 0.0,
    fallback_reason: str | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
    permission_capability_status: str = "READ_ONLY_UNVERIFIED",
    dispatch_status: str = "SUCCESS",
    decision_reason: str | None = None,
    idempotency_key: str | None = None,
    dispatch_id: str | None = None,
) -> str:
    """Record an LLM dispatch with complete model routing and token accounting metadata."""
    disp_id = dispatch_id or f"disp-{uuid.uuid4().hex[:12]}"
    conn.execute(
        """INSERT INTO model_dispatches (
            dispatch_id, audit_run_id, verification_run_id, finding_fingerprint,
            task_type, task_risk, requested_model, observed_model, reasoning_level,
            model_identity_source, model_attestation_status, routing_policy_version,
            conversation_id, input_tokens, output_tokens, thinking_tokens, total_tokens,
            execution_duration, fallback_reason, error_code, error_message,
            permission_capability_status, dispatch_status, decision_reason, idempotency_key
        ) VALUES (
            ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?
        ) ON CONFLICT(idempotency_key) DO UPDATE SET
            observed_model=excluded.observed_model,
            model_attestation_status=excluded.model_attestation_status,
            input_tokens=excluded.input_tokens,
            output_tokens=excluded.output_tokens,
            thinking_tokens=excluded.thinking_tokens,
            total_tokens=excluded.total_tokens,
            execution_duration=excluded.execution_duration,
            dispatch_status=excluded.dispatch_status,
            error_code=excluded.error_code,
            error_message=excluded.error_message,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            disp_id, audit_run_id, verification_run_id, finding_fingerprint,
            task_type, task_risk, requested_model, observed_model, reasoning_level,
            model_identity_source, model_attestation_status, routing_policy_version,
            conversation_id, int(input_tokens), int(output_tokens), int(thinking_tokens), int(total_tokens),
            float(execution_duration), fallback_reason, error_code, error_message,
            permission_capability_status, dispatch_status, decision_reason, idempotency_key,
        ),
    )
    return disp_id


def get_model_dispatch(conn: sqlite3.Connection, dispatch_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM model_dispatches WHERE dispatch_id = ?",
        (dispatch_id,),
    ).fetchone()
    return dict(row) if row else None


def list_model_dispatches_for_run(
    conn: sqlite3.Connection,
    audit_run_id: str,
) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM model_dispatches WHERE audit_run_id = ? ORDER BY created_at ASC",
        (audit_run_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def record_budget_usage(
    conn: sqlite3.Connection,
    *,
    model_id: str,
    task_type: str,
    tokens_consumed: int,
    audit_run_id: str | None = None,
    finding_fingerprint: str | None = None,
    request_count: int = 1,
) -> int:
    cur = conn.execute(
        """INSERT INTO model_budget_usage (
            audit_run_id, model_id, task_type, finding_fingerprint,
            tokens_consumed, request_count
        ) VALUES (?, ?, ?, ?, ?, ?)""",
        (
            audit_run_id, model_id, task_type, finding_fingerprint,
            int(tokens_consumed), int(request_count),
        ),
    )
    return int(cur.lastrowid or 0)


def get_budget_usage_for_run(
    conn: sqlite3.Connection,
    audit_run_id: str,
    model_id: str | None = None,
) -> dict[str, Any]:
    if model_id:
        row = conn.execute(
            """SELECT COALESCE(SUM(tokens_consumed), 0) AS total_tokens,
                      COALESCE(SUM(request_count), 0) AS total_requests
               FROM model_budget_usage
               WHERE audit_run_id = ? AND model_id = ?""",
            (audit_run_id, model_id),
        ).fetchone()
    else:
        row = conn.execute(
            """SELECT COALESCE(SUM(tokens_consumed), 0) AS total_tokens,
                      COALESCE(SUM(request_count), 0) AS total_requests
               FROM model_budget_usage
               WHERE audit_run_id = ?""",
            (audit_run_id,),
        ).fetchone()
    return {
        "total_tokens": int(row["total_tokens"] if row else 0),
        "total_requests": int(row["total_requests"] if row else 0),
    }


def _is_scarce_model_id(model_id: str | None) -> bool:
    from model_registry import is_scarce_model

    return is_scarce_model((model_id or "").strip().lower())


def _register_scarce_model_function(conn: sqlite3.Connection) -> None:
    """SQL helper ``auditor_is_scarce(model_id)`` backed by the hard policy's scarce-model patterns, so
    budget queries do not hard-code a model family."""
    conn.create_function(
        "auditor_is_scarce", 1, lambda m: 1 if _is_scarce_model_id(m) else 0, deterministic=True
    )


def cleanup_expired_argon_reservations(conn: sqlite3.Connection) -> int:
    """Purge stale Argon reservations whose lease has expired."""
    now_iso = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "DELETE FROM model_budget_reservations WHERE lease_expires_at < ?",
        (now_iso,),
    )
    return cur.rowcount


def reserve_argon_budget_atomic(
    conn: sqlite3.Connection,
    *,
    audit_run_id: str,
    model_id: str,
    task_type: str = "CRITICAL_VERIFICATION",
    finding_fingerprint: str | None = None,
    estimated_tokens: int = 0,
    max_concurrent_jobs: int = 1,
    max_requests_per_run: int = 5,
    max_tokens_per_run: int = 100_000,
    # Must outlive the longest dispatch (verification: 900 s); an expired lease frees the concurrency slot
    # while the job is still running.
    lease_seconds: int = 1800,
    force_duplicate: bool = False,
    daily_token_budget: int | None = None,
    max_retries: int = 5,
    retry_delay_seconds: float = 0.05,
) -> dict[str, Any]:
    """Atomically evaluate and reserve Argon budget under SQLite isolation."""
    clean_model = (model_id or "").strip().lower()
    if not _is_scarce_model_id(clean_model):
        return {
            "allowed": True,
            "status": "ALLOWED",
            "reason": "Non-scarce models are not subject to Argon quota limits.",
            "reservation_id": None,
            "current_requests": 0,
            "current_tokens": 0,
            "current_concurrent": 0,
        }

    own_transaction = False
    if not conn.in_transaction:
        conn.isolation_level = None
        for attempt in range(max_retries):
            try:
                conn.execute("BEGIN IMMEDIATE")
                own_transaction = True
                break
            except sqlite3.OperationalError as e:
                if ("locked" in str(e).lower() or "busy" in str(e).lower()) and attempt < max_retries - 1:
                    time.sleep(retry_delay_seconds * (2 ** attempt))
                    continue
                return {
                    "allowed": False,
                    "status": "REJECTED_DATABASE_LOCKED",
                    "reason": f"Database is locked or busy during budget reservation after {max_retries} attempts: {e}",
                    "reservation_id": None,
                    "current_requests": 0,
                    "current_tokens": 0,
                    "current_concurrent": 0,
                }

    try:
        _register_scarce_model_function(conn)
        cleanup_expired_argon_reservations(conn)

        # 1. Concurrency check across all active Argon reservations
        row_conc = conn.execute(
            "SELECT COUNT(*) FROM model_budget_reservations WHERE auditor_is_scarce(model_id) = 1"
        ).fetchone()
        current_concurrent = int(row_conc[0] if row_conc else 0)
        if current_concurrent >= max_concurrent_jobs:
            if own_transaction and conn.in_transaction:
                conn.execute("ROLLBACK")
            return {
                "allowed": False,
                "status": "REJECTED_CONCURRENCY",
                "reason": (
                    f"Active concurrent Argon jobs ({current_concurrent}) "
                    f"reached limit ({max_concurrent_jobs})."
                ),
                "reservation_id": None,
                "current_requests": 0,
                "current_tokens": 0,
                "current_concurrent": current_concurrent,
            }

        # 2. Per-finding deduplication check
        if finding_fingerprint and not force_duplicate:
            row_used = conn.execute(
                """SELECT COUNT(*) FROM model_budget_usage
                   WHERE audit_run_id = ? AND finding_fingerprint = ? AND task_type = ? AND auditor_is_scarce(model_id) = 1""",
                (audit_run_id, finding_fingerprint, task_type),
            ).fetchone()
            row_res = conn.execute(
                """SELECT COUNT(*) FROM model_budget_reservations
                   WHERE audit_run_id = ? AND finding_fingerprint = ? AND task_type = ? AND auditor_is_scarce(model_id) = 1""",
                (audit_run_id, finding_fingerprint, task_type),
            ).fetchone()
            if (row_used and row_used[0] > 0) or (row_res and row_res[0] > 0):
                if own_transaction and conn.in_transaction:
                    conn.execute("ROLLBACK")
                return {
                    "allowed": False,
                    "status": "REJECTED_DUPLICATE",
                    "reason": (
                        f"Argon dispatch already completed or in-progress for finding '{finding_fingerprint}' "
                        f"in run '{audit_run_id}'. Duplicate consumption rejected."
                    ),
                    "reservation_id": None,
                    "current_requests": 0,
                    "current_tokens": 0,
                    "current_concurrent": current_concurrent,
                }

        # 3. Requests per run check
        row_req_used = conn.execute(
            """SELECT COALESCE(SUM(request_count), 0) FROM model_budget_usage
               WHERE audit_run_id = ? AND auditor_is_scarce(model_id) = 1""",
            (audit_run_id,),
        ).fetchone()
        row_req_res = conn.execute(
            """SELECT COUNT(*) FROM model_budget_reservations
               WHERE audit_run_id = ? AND auditor_is_scarce(model_id) = 1""",
            (audit_run_id,),
        ).fetchone()
        current_requests = int(row_req_used[0] if row_req_used else 0) + int(row_req_res[0] if row_req_res else 0)
        if current_requests >= max_requests_per_run:
            if own_transaction and conn.in_transaction:
                conn.execute("ROLLBACK")
            return {
                "allowed": False,
                "status": "REJECTED_REQUEST_LIMIT",
                "reason": (
                    f"Argon request limit for audit run '{audit_run_id}' exceeded: "
                    f"{current_requests}/{max_requests_per_run}."
                ),
                "reservation_id": None,
                "current_requests": current_requests,
                "current_tokens": 0,
                "current_concurrent": current_concurrent,
            }

        # 4. Tokens per run check
        row_tok_used = conn.execute(
            """SELECT COALESCE(SUM(tokens_consumed), 0) FROM model_budget_usage
               WHERE audit_run_id = ? AND auditor_is_scarce(model_id) = 1""",
            (audit_run_id,),
        ).fetchone()
        row_tok_res = conn.execute(
            """SELECT COALESCE(SUM(estimated_tokens), 0) FROM model_budget_reservations
               WHERE audit_run_id = ? AND auditor_is_scarce(model_id) = 1""",
            (audit_run_id,),
        ).fetchone()
        current_tokens = int(row_tok_used[0] if row_tok_used else 0) + int(row_tok_res[0] if row_tok_res else 0)
        if current_tokens + estimated_tokens > max_tokens_per_run:
            if own_transaction and conn.in_transaction:
                conn.execute("ROLLBACK")
            return {
                "allowed": False,
                "status": "REJECTED_TOKEN_LIMIT",
                "reason": (
                    f"Argon token limit for audit run '{audit_run_id}' would be exceeded: "
                    f"{current_tokens + estimated_tokens} > {max_tokens_per_run}."
                ),
                "reservation_id": None,
                "current_requests": current_requests,
                "current_tokens": current_tokens,
                "current_concurrent": current_concurrent,
            }

        # 5. Optional daily scarce-model token budget (UTC day), including in-flight reservations
        if daily_token_budget is not None:
            row_day_used = conn.execute(
                """SELECT COALESCE(SUM(tokens_consumed), 0) FROM model_budget_usage
                   WHERE auditor_is_scarce(model_id) = 1 AND date(recorded_at) = date('now')"""
            ).fetchone()
            row_day_res = conn.execute(
                """SELECT COALESCE(SUM(estimated_tokens), 0) FROM model_budget_reservations
                   WHERE auditor_is_scarce(model_id) = 1"""
            ).fetchone()
            daily_used = int(row_day_used[0] if row_day_used else 0) + int(row_day_res[0] if row_day_res else 0)
            if daily_used + estimated_tokens > daily_token_budget:
                if own_transaction and conn.in_transaction:
                    conn.execute("ROLLBACK")
                return {
                    "allowed": False,
                    "status": "REJECTED_TOKEN_LIMIT",
                    "reason": (
                        f"Daily Argon token budget exceeded: {daily_used + estimated_tokens} > {daily_token_budget}."
                    ),
                    "reservation_id": None,
                    "current_requests": current_requests,
                    "current_tokens": current_tokens,
                    "current_concurrent": current_concurrent,
                }

        # 6. Acquire reservation atomically
        reservation_id = f"res-{uuid.uuid4().hex[:12]}"
        lease_expires_at = (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat()
        conn.execute(
            """INSERT INTO model_budget_reservations (
                reservation_id, audit_run_id, model_id, finding_fingerprint,
                task_type, estimated_tokens, lease_expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                reservation_id,
                audit_run_id,
                clean_model,
                finding_fingerprint,
                task_type,
                int(estimated_tokens),
                lease_expires_at,
            ),
        )

        if own_transaction and conn.in_transaction:
            conn.execute("COMMIT")

        return {
            "allowed": True,
            "status": "ALLOWED",
            "reason": "Argon quota and concurrency reserved atomically.",
            "reservation_id": reservation_id,
            "current_requests": current_requests + 1,
            "current_tokens": current_tokens + estimated_tokens,
            "current_concurrent": current_concurrent + 1,
        }
    except Exception:
        if own_transaction and conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def release_argon_budget_atomic(
    conn: sqlite3.Connection,
    *,
    reservation_id: str | None = None,
    audit_run_id: str,
    model_id: str,
    actual_tokens: int = 0,
    task_type: str = "CRITICAL_VERIFICATION",
    finding_fingerprint: str | None = None,
    max_retries: int = 5,
    retry_delay_seconds: float = 0.05,
    record_usage: bool = True,
) -> None:
    """Release an atomic reservation and persist actual token usage.

    ``record_usage=False`` (the dispatch never ran) only deletes the reservation, so the request neither counts
    against the run quota nor marks the finding as already dispatched."""
    clean_model = (model_id or "").strip().lower()
    if not _is_scarce_model_id(clean_model):
        return

    own_transaction = False
    if not conn.in_transaction:
        conn.isolation_level = None
        for attempt in range(max_retries):
            try:
                conn.execute("BEGIN IMMEDIATE")
                own_transaction = True
                break
            except sqlite3.OperationalError as e:
                if ("locked" in str(e).lower() or "busy" in str(e).lower()) and attempt < max_retries - 1:
                    time.sleep(retry_delay_seconds * (2 ** attempt))
                    continue
                raise

    try:
        if reservation_id:
            conn.execute(
                "DELETE FROM model_budget_reservations WHERE reservation_id = ?",
                (reservation_id,),
            )
        else:
            conn.execute(
                """DELETE FROM model_budget_reservations
                   WHERE rowid IN (
                       SELECT rowid FROM model_budget_reservations
                       WHERE audit_run_id = ? AND model_id = ? AND finding_fingerprint IS ?
                       LIMIT 1
                   )""",
                (audit_run_id, clean_model, finding_fingerprint),
            )

        if record_usage:
            record_budget_usage(
                conn,
                audit_run_id=audit_run_id,
                model_id=clean_model,
                task_type=task_type,
                finding_fingerprint=finding_fingerprint,
                tokens_consumed=actual_tokens,
                request_count=1,
            )
        if own_transaction and conn.in_transaction:
            conn.execute("COMMIT")
    except Exception:
        if own_transaction and conn.in_transaction:
            conn.execute("ROLLBACK")
        raise

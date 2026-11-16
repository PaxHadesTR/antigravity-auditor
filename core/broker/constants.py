"""Constants for Antigravity Auditor Control-Plane Broker."""

from __future__ import annotations

import os
from pathlib import Path

PROTOCOL_VERSION = "1.0.0"
DEFAULT_PIPE_NAME = r"\\.\pipe\AntigravityAuditorBroker"
TEST_PIPE_PREFIX = r"\\.\pipe\AntigravityAuditorTest_"

# NEXT-21C-B4-A Dedicated Windows Test Service Identity (never production)
PRODUCTION_SERVICE_NAME = "AntigravityAuditorBroker"
B4A_TEST_SERVICE_NAME = "AntigravityAuditorBrokerB4ATest"
B4A_TEST_SERVICE_DISPLAY_NAME = "Antigravity Auditor Broker B4-A Test Service"
B4A_TEST_SERVICE_ACCOUNT = r"NT SERVICE\AntigravityAuditorBrokerB4ATest"
B4A_TEST_SERVICE_SID = "S-1-5-80-4260804884-1167523909-1471761090-466244648-2302600592"
B4A_TEST_PIPE_NAME = r"\\.\pipe\AntigravityAuditorBroker.B4A.Test"

# NEXT-21C-B4-B Isolated Non-Production Service Governance Identity Prefix (never production or B4-A)
B4B_TEST_SERVICE_PREFIX = "AntigravityAuditorBrokerB4BTest_"
B4B_TEST_SERVICE_DISPLAY_PREFIX = "Antigravity Auditor Broker B4-B Test Service"
B4B_TEST_PIPE_PREFIX = r"\\.\pipe\AntigravityAuditorBroker.B4B.Test_"
B4B_TEST_KEY_PREFIX = "AntigravityB4BTest_"

SERVICE_MODE_STANDARD = "STANDARD"
SERVICE_MODE_B4A_QUALIFICATION = "B4A_QUALIFICATION_ONLY"
SERVICE_MODE_B4B_GOVERNANCE_TEST = "B4B_SERVICE_GOVERNANCE_TEST"

# Allowed RPC methods in B4-A qualification-only service mode
B4A_QUALIFICATION_ALLOWED_METHODS = frozenset({
    "broker.health",
    "broker.capabilities",
    "broker.protocol_version",
    "broker.test_ping_db",
})

# Win32 SCM SERVICE_SID_TYPE Constants
SERVICE_CONFIG_SERVICE_SID_INFO = 5
SERVICE_SID_TYPE_NONE = 0x00000000
SERVICE_SID_TYPE_UNRESTRICTED = 0x00000001
SERVICE_SID_TYPE_RESTRICTED = 0x00000003

# Frame and buffer constraints
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB maximum payload
BUFFER_SIZE = 65536             # 64 KB I/O buffer
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_CONCURRENT_CLIENTS = 16

# Standard and Custom JSON-RPC 2.0 Error Codes
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603

# Broker Domain Error Codes
ERR_NOT_IMPLEMENTED = -32000
ERR_METHOD_NOT_IMPLEMENTED = -32000
ERR_ACCESS_DENIED = -32001
ERR_DATABASE_ERROR = -32002
ERR_BROKER_UNAVAILABLE = -32003
ERR_REQUEST_TIMEOUT = -32004
ERR_SCHEMA_VALIDATION = -32005
ERR_PRODUCTION_DB_BLOCKED = -32006
ERR_PRODUCTION_DB_ACCESS_PROHIBITED = -32006
ERR_REPLAY_ATTEMPT = -32010
ERR_APPROVAL_EXPIRED = -32011
ERR_TWO_STEP_VIOLATION = -32012
ERR_CONCURRENT_CONFLICT = -32013
ERR_RETRY_LIMIT_EXCEEDED = -32014
ERR_SCOPE_VIOLATION = -32015
ERR_EXECUTION_DISABLED = -32016
ERR_CHECKPOINT_QUARANTINED = -32017
ERR_UNVERIFIED_STATE = -32018
ERR_CHECKPOINT_INTEGRITY = -32019
ERR_CNG_ERROR = -32020
ERR_TPM_UNAVAILABLE = -32021
ERR_CONFIRMATION_REQUIRED = -32022
ERR_CONFIRMATION_FAILED = -32023
ERR_ALGORITHM_DOWNGRADE = -32024

# Security Descriptor Definition (SDDL) for Windows Named Pipe:
# D: DACL
# (A;;GRGW;;;WD) -> Allow Generic Read / Generic Write to Everyone (local only)
# (A;;GA;;;BA)   -> Allow Generic All to Built-in Administrators
# (A;;GA;;;SY)   -> Allow Generic All to SYSTEM
# Note: PIPE_REJECT_REMOTE_CLIENTS flag ensures remote SMB clients are rejected at kernel level.
DEFAULT_PIPE_SDDL = "D:(A;;GRGW;;;WD)(A;;GA;;;BA)(A;;GA;;;SY)"

# Prohibited database paths (must never be opened by broker or tests during NEXT-21C-A / B1 / B2)
PROHIBITED_DB_NAMES = {"auditor.db", "auditor.db-wal", "auditor.db-shm"}
PROHIBITED_DIRECTORIES = [
    Path(os.path.expandvars(r"%LOCALAPPDATA%\AntigravityAuditor")),
    Path(os.path.expandvars(r"%PROGRAMDATA%\AntigravityAuditor")),
    Path(r"C:\ProgramData\AntigravityAuditor"),
]

# Broker Operation Categories (NEXT-21C-B1 & B2)
OP_READ_PROJECT = "READ_PROJECT"
OP_READ_FINDING = "READ_FINDING"
OP_READ_REVIEW = "READ_REVIEW"
OP_READ_VERIFICATION = "READ_VERIFICATION"
OP_READ_AUDIT = "READ_AUDIT"
OP_MUTATE_FINDINGS = "MUTATE_FINDINGS"
OP_MUTATE_DECISIONS = "MUTATE_DECISIONS"
OP_MUTATE_APPROVALS = "MUTATE_APPROVALS"
OP_MUTATE_EXECUTION = "MUTATE_EXECUTION"
OP_MUTATE_CHECKPOINTS = "MUTATE_CHECKPOINTS"
OP_MUTATE_VERIFICATION = "MUTATE_VERIFICATION"

# Read RPC Method Names (NEXT-21C-B1)
METHOD_GET_CONTEXT = "broker.get_context"
METHOD_LIST_FINDINGS = "broker.list_findings"
METHOD_GET_REVIEW_CONTEXT = "broker.get_review_context"
METHOD_GET_VERIFICATION_CONTEXT = "broker.get_verification_context"
METHOD_GET_VERIFICATION_STATUS = "broker.get_verification_status"
METHOD_GET_STATUS = "broker.get_status"
METHOD_GET_VERIFIER_WORKER_STATUS = "broker.get_verifier_worker_status"
METHOD_GET_QUALITY_REPORT = "broker.get_quality_report"

# Governance State-Mutating RPC Method Names (NEXT-21C-B2)
METHOD_INGEST_FINDINGS = "broker.ingest_findings"
METHOD_SAVE_DECISIONS = "broker.save_decisions"
METHOD_GET_DECISION_STATE = "broker.get_decision_state"
METHOD_AUTHORIZE_EXECUTION = "broker.authorize_execution"
METHOD_VERIFY_EXECUTION_APPROVAL = "broker.verify_execution_approval"
METHOD_CONSUME_EXECUTION_APPROVAL = "broker.consume_execution_approval"
METHOD_REGISTER_EXECUTION_INTENT = "broker.register_execution_intent"
METHOD_ACQUIRE_EXECUTION_LEASE = "broker.acquire_execution_lease"
METHOD_HEARTBEAT_EXECUTION = "broker.heartbeat_execution"
METHOD_RENEW_EXECUTION_LEASE = "broker.renew_execution_lease"
METHOD_UPDATE_EXECUTION_STATE = "broker.update_execution_state"
METHOD_REGISTER_CHECKPOINT = "broker.register_checkpoint"
METHOD_RECORD_REPAIR_ATTEMPT = "broker.record_repair_attempt"
METHOD_QUARANTINE_CHECKPOINT = "broker.quarantine_checkpoint"
METHOD_FINALIZE_EXECUTION = "broker.finalize_execution"
METHOD_SUBMIT_VERIFICATION = "broker.submit_verification"
METHOD_FINALIZE_VERIFIED_REPORT = "broker.finalize_verified_report"
METHOD_CLAIM_VERIFICATION_JOB = "broker.claim_verification_job"
METHOD_RECOVER_VERIFICATION_LEASE = "broker.recover_verification_lease"
METHOD_VERIFY_AUDIT_CHAIN = "broker.verify_audit_chain"
METHOD_VALIDATE_CHECKPOINT = "broker.validate_checkpoint"
METHOD_RESTORE_CHECKPOINT = "broker.restore_checkpoint"
METHOD_GET_EXECUTION_STATE = "broker.get_execution_state"

# Trusted Confirmation & Key Custody RPC Method Names (NEXT-21C-B4-B)
METHOD_REQUEST_CONFIRMATION_CHALLENGE = "broker.request_confirmation_challenge"
METHOD_GET_CONFIRMATION_CHALLENGE_STATUS = "broker.get_confirmation_challenge_status"
METHOD_KEY_STATUS = "broker.key_status"

# Query constraints and allowlists
DEFAULT_QUERY_LIMIT = 500
MAX_QUERY_LIMIT = 1000
ALLOWED_SORT_COLUMNS = {
    "finding_id",
    "severity",
    "confidence",
    "created_at",
    "updated_at",
    "lifecycle",
    "verification_status",
}
ALLOWED_SORT_DIRECTIONS = {"asc", "desc", "ASC", "DESC"}


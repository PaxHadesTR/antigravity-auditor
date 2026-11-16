"""Central Authorization Dispatcher and RPC Method Handlers."""

from __future__ import annotations

from collections import OrderedDict

import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Callable

from broker.audit_logger import BrokerAuditLogger
from broker.cbeat import CBEAT_ALG_ED25519, CbeatSigner, CbeatVerifier, EphemeralCbeatSigner
from broker.cng import CngCbeatSigner
from broker.constants import (
    ALLOWED_SORT_COLUMNS,
    ALLOWED_SORT_DIRECTIONS,
    B4A_QUALIFICATION_ALLOWED_METHODS,
    DEFAULT_QUERY_LIMIT,
    ERR_ACCESS_DENIED,
    ERR_EXECUTION_DISABLED,
    ERR_NOT_IMPLEMENTED,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_METHOD_NOT_FOUND,
    MAX_QUERY_LIMIT,
    METHOD_ACQUIRE_EXECUTION_LEASE,
    METHOD_AUTHORIZE_EXECUTION,
    METHOD_CLAIM_VERIFICATION_JOB,
    METHOD_CONSUME_EXECUTION_APPROVAL,
    METHOD_FINALIZE_EXECUTION,
    METHOD_FINALIZE_VERIFIED_REPORT,
    METHOD_GET_CONFIRMATION_CHALLENGE_STATUS,
    METHOD_GET_CONTEXT,
    METHOD_GET_EXECUTION_STATE,
    METHOD_GET_DECISION_STATE,
    METHOD_GET_QUALITY_REPORT,
    METHOD_GET_REVIEW_CONTEXT,
    METHOD_GET_STATUS,
    METHOD_GET_VERIFICATION_CONTEXT,
    METHOD_GET_VERIFICATION_STATUS,
    METHOD_GET_VERIFIER_WORKER_STATUS,
    METHOD_HEARTBEAT_EXECUTION,
    METHOD_INGEST_FINDINGS,
    METHOD_KEY_STATUS,
    METHOD_LIST_FINDINGS,
    METHOD_QUARANTINE_CHECKPOINT,
    METHOD_RECORD_REPAIR_ATTEMPT,
    METHOD_RECOVER_VERIFICATION_LEASE,
    METHOD_REGISTER_CHECKPOINT,
    METHOD_RESTORE_CHECKPOINT,
    METHOD_REGISTER_EXECUTION_INTENT,
    METHOD_RENEW_EXECUTION_LEASE,
    METHOD_REQUEST_CONFIRMATION_CHALLENGE,
    METHOD_SAVE_DECISIONS,
    METHOD_SUBMIT_VERIFICATION,
    METHOD_UPDATE_EXECUTION_STATE,
    METHOD_VALIDATE_CHECKPOINT,
    METHOD_VERIFY_AUDIT_CHAIN,
    METHOD_VERIFY_EXECUTION_APPROVAL,
    PROTOCOL_VERSION,
    SERVICE_MODE_B4A_QUALIFICATION,
    SERVICE_MODE_B4B_GOVERNANCE_TEST,
    SERVICE_MODE_STANDARD,
)
from broker.tcb import FORBIDDEN_TCB_OVERRIDE_PARAMS, TcbVerifier
from broker.db_adapter import BrokerDatabaseAdapter
from broker.exceptions import (
    BrokerAuthError,
    BrokerError,
    BrokerSchemaError,
    BrokerSecurityError,
    MethodNotImplementedError,
)
from broker.protocol import (
    JsonRpcRequest,
    JsonRpcResponse,
    make_error_response,
    make_success_response,
)
from broker.security import ClientIdentity


class BrokerDispatcher:
    """Central authorization dispatcher for JSON-RPC 2.0 requests.

    Enforces:
    1. Client identity checks (rejects Low-IL worker execution).
    2. Request schema and parameter validation (rejects client-supplied DB paths).
    3. Rejection of arbitrary SQL execution.
    4. Safe execution of initial RPC contract (health, capabilities, protocol_version).
    5. Dispatches typed read-only (B1) and state-mutating governance (B2) RPC operations.
    """

    def __init__(
        self,
        db_adapter: BrokerDatabaseAdapter | None = None,
        audit_logger: BrokerAuditLogger | None = None,
        signer: CbeatSigner | None = None,
        verifier: CbeatVerifier | None = None,
        allow_execution_dispatch: bool = False,
        *,
        enable_governance_mutation: bool | None = None,
        qualification_only: bool = False,
        allowed_client_sids: set[str] | frozenset[str] | None = None,
        service_identity: str | None = None,
        service_mode: str | None = None,
        tcb_verifier: TcbVerifier | None = None,
        require_tcb: bool = False,
        require_cng: bool = False,
    ) -> None:
        self.db_adapter = db_adapter
        self.audit_logger = audit_logger or BrokerAuditLogger()
        self.has_crypto = (signer is not None or verifier is not None or isinstance(signer, CngCbeatSigner))
        self.signer = signer or EphemeralCbeatSigner()
        self.qualification_only = bool(qualification_only)
        self.require_cng = False if self.qualification_only else bool(require_cng)
        self.tcb_verifier = tcb_verifier
        self.require_tcb = False if self.qualification_only else bool(
            require_tcb or (tcb_verifier is not None and tcb_verifier.policy.require_tcb)
        )
        if self.require_cng and not isinstance(self.signer, CngCbeatSigner):
            raise BrokerSecurityError(
                "require_cng=True requires a persisted CngCbeatSigner (EphemeralCbeatSigner forbidden).",
                code=ERR_ACCESS_DENIED,
            )

        self._custom_verifier = verifier is not None
        if verifier is not None:
            self.verifier = verifier
        elif isinstance(self.signer, CngCbeatSigner):
            self.verifier = CbeatVerifier(
                trusted_public_keys=self.signer.trusted_public_keys,
                require_cng=self.require_cng,
            )
        else:
            self.verifier = CbeatVerifier(trusted_public_key=self.signer.get_public_key_bytes())

        self.allow_execution_dispatch = False if self.qualification_only else allow_execution_dispatch
        self.allowed_client_sids = frozenset(allowed_client_sids) if allowed_client_sids is not None else None
        self.service_identity = service_identity or "AntigravityAuditorBroker"
        self.start_time = datetime.now(timezone.utc)
        # Replay protection per client (pid + SID), bounded so a long-running broker does not grow forever.
        self._processed_request_ids: "OrderedDict[tuple[Any, ...], None]" = OrderedDict()
        self._max_tracked_request_ids = 10_000

        if self.qualification_only:
            self.enable_governance_mutation = False
            self.service_mode = SERVICE_MODE_B4A_QUALIFICATION
            self.phase = "NEXT-21C-B4-A"
        elif service_mode == SERVICE_MODE_B4B_GOVERNANCE_TEST:
            self.enable_governance_mutation = True if enable_governance_mutation is None else bool(enable_governance_mutation)
            self.service_mode = SERVICE_MODE_B4B_GOVERNANCE_TEST
            self.phase = "NEXT-21C-B4-B"
        else:
            if enable_governance_mutation is None:
                self.enable_governance_mutation = self.has_crypto
            else:
                self.enable_governance_mutation = enable_governance_mutation
            self.service_mode = SERVICE_MODE_STANDARD
            self.phase = "NEXT-21C-B2" if self.enable_governance_mutation else "NEXT-21C-B1"

        if not self.enable_governance_mutation:
            self._unimplemented_governance_methods = {
                "broker.approve_execution",
                "broker.authorize_execution",
                "broker.start_execution",
                "broker.ingest_findings",
                "broker.save_decisions",
                "broker.submit_verification",
                "broker.finalize_verification",
                "broker.finalize_verified_report",
                "broker.update_execution_step",
                "broker.finalize_execution",
                "broker.rollback_checkpoint",
                "broker.quarantine_worktree",
                "broker.claim_verification_job",
                "broker.recover_verification_lease",
                METHOD_REQUEST_CONFIRMATION_CHALLENGE,
            }
        else:
            self._unimplemented_governance_methods = set()

        self._gated_methods = {
            "broker.approve_execution",
            "broker.authorize_execution",
            "broker.start_execution",
            "broker.consume_execution_approval",
            "broker.acquire_execution_lease",
            "broker.finalize_execution",
        }

        # Method Routing Table
        self._handlers: dict[str, Callable[[JsonRpcRequest, ClientIdentity], Any]] = {
            "broker.health": self._handle_health,
            "broker.capabilities": self._handle_capabilities,
            "broker.protocol_version": self._handle_protocol_version,
            "broker.test_ping_db": self._handle_test_ping_db,
            # NEXT-21C-B1 Read-Only Consumer Migration Methods
            METHOD_GET_CONTEXT: self._handle_get_context,
            METHOD_LIST_FINDINGS: self._handle_list_findings,
            METHOD_GET_REVIEW_CONTEXT: self._handle_get_review_context,
            METHOD_GET_VERIFICATION_CONTEXT: self._handle_get_verification_context,
            METHOD_GET_VERIFICATION_STATUS: self._handle_get_verification_status,
            METHOD_GET_STATUS: self._handle_get_status,
            METHOD_GET_VERIFIER_WORKER_STATUS: self._handle_get_verifier_worker_status,
            METHOD_GET_QUALITY_REPORT: self._handle_get_quality_report,
            # NEXT-21C-B2 Governance State-Mutating RPC Methods
            METHOD_INGEST_FINDINGS: self._handle_ingest_findings,
            METHOD_SAVE_DECISIONS: self._handle_save_decisions,
            METHOD_GET_DECISION_STATE: self._handle_get_decision_state,
            METHOD_AUTHORIZE_EXECUTION: self._handle_authorize_execution,
            METHOD_VERIFY_EXECUTION_APPROVAL: self._handle_verify_execution_approval,
            METHOD_CONSUME_EXECUTION_APPROVAL: self._handle_consume_execution_approval,
            METHOD_REGISTER_EXECUTION_INTENT: self._handle_register_execution_intent,
            METHOD_ACQUIRE_EXECUTION_LEASE: self._handle_acquire_execution_lease,
            METHOD_HEARTBEAT_EXECUTION: self._handle_heartbeat_execution,
            METHOD_RENEW_EXECUTION_LEASE: self._handle_renew_execution_lease,
            METHOD_UPDATE_EXECUTION_STATE: self._handle_update_execution_state,
            METHOD_REGISTER_CHECKPOINT: self._handle_register_checkpoint,
            METHOD_RECORD_REPAIR_ATTEMPT: self._handle_record_repair_attempt,
            METHOD_QUARANTINE_CHECKPOINT: self._handle_quarantine_checkpoint,
            METHOD_FINALIZE_EXECUTION: self._handle_finalize_execution,
            METHOD_SUBMIT_VERIFICATION: self._handle_submit_verification,
            METHOD_FINALIZE_VERIFIED_REPORT: self._handle_finalize_verified_report,
            METHOD_CLAIM_VERIFICATION_JOB: self._handle_claim_verification_job,
            METHOD_RECOVER_VERIFICATION_LEASE: self._handle_recover_verification_lease,
            METHOD_VERIFY_AUDIT_CHAIN: self._handle_verify_audit_chain,
            METHOD_VALIDATE_CHECKPOINT: self._handle_validate_checkpoint,
            METHOD_RESTORE_CHECKPOINT: self._handle_restore_checkpoint,
            METHOD_GET_EXECUTION_STATE: self._handle_get_execution_state,
            # NEXT-21C-B4-B CNG/TPM Custody & Trusted Confirmation Boundary Methods
            METHOD_REQUEST_CONFIRMATION_CHALLENGE: self._handle_request_confirmation_challenge,
            METHOD_GET_CONFIRMATION_CHALLENGE_STATUS: self._handle_get_confirmation_challenge_status,
            METHOD_KEY_STATUS: self._handle_key_status,
            # Aliases for historical / API compatibility
            "broker.approve_execution": self._handle_authorize_execution,
            "broker.start_execution": self._handle_register_execution_intent,
            "broker.update_execution_step": self._handle_record_repair_attempt,
            "broker.finalize_verification": self._handle_finalize_verified_report,
            "broker.quarantine_worktree": self._handle_quarantine_checkpoint,
        }

    def dispatch(self, request: JsonRpcRequest, client: ClientIdentity) -> JsonRpcResponse:
        """Authorize and dispatch a validated JSON-RPC request."""
        t0 = time.perf_counter()

        # 1. Low Integrity Level Rejection (Workers cannot access Broker)
        if client.is_low_integrity or str(getattr(client, "integrity_level", "") or "").upper() in ("LOW", "UNTRUSTED", "UNKNOWN"):
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="REJECTED",
                latency_ms=latency,
                error_code=ERR_ACCESS_DENIED,
                error_message="Low-Integrity worker processes are denied access to control-plane broker.",
            )
            return make_error_response(
                request.id,
                ERR_ACCESS_DENIED,
                "Access denied: Low-Integrity processes cannot access control-plane broker.",
                {"client_pid": client.pid, "integrity": client.integrity_level},
            )

        # 1b. Client SID allowlist enforcement (if configured)
        if self.allowed_client_sids and client.sid not in self.allowed_client_sids:
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="REJECTED",
                latency_ms=latency,
                error_code=ERR_ACCESS_DENIED,
                error_message="Client SID is not authorized for this broker instance.",
            )
            return make_error_response(
                request.id,
                ERR_ACCESS_DENIED,
                "Access denied: Client SID is not authorized.",
                {"client_pid": client.pid, "client_sid": client.sid},
            )

        # 1c. Reject client-supplied mode, allowlist, CNG fallback, or TCB bypass override attempts
        _forbidden_override_keys = (
            "service_mode",
            "mode",
            "qualification_only",
            "allowed_methods",
            "require_tcb",
            "require_cng",
            "require_tpm",
            "cng_fallback",
            "signer_mode",
            *tuple(FORBIDDEN_TCB_OVERRIDE_PARAMS),
        )
        if any(k in request.params for k in _forbidden_override_keys):
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="REJECTED",
                latency_ms=latency,
                error_code=ERR_ACCESS_DENIED,
                error_message="Client cannot override broker service mode, TCB policy, CNG policy, or capability allowlist.",
            )
            return make_error_response(
                request.id,
                ERR_ACCESS_DENIED,
                "Access denied: Client-supplied service mode, CNG, or TCB overrides are prohibited.",
            )

        # 1d. B4-A qualification-only method restriction (fail-closed)
        if self.qualification_only and request.method not in B4A_QUALIFICATION_ALLOWED_METHODS:
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="REJECTED",
                latency_ms=latency,
                error_code=ERR_ACCESS_DENIED,
                error_message=f"Method '{request.method}' is blocked in B4-A qualification mode.",
            )
            return make_error_response(
                request.id,
                ERR_ACCESS_DENIED,
                f"Method '{request.method}' is blocked in B4-A qualification mode.",
                {"service_mode": self.service_mode, "method": request.method},
            )

        # 2. Check for duplicate request IDs within connection session
        replay_key = (getattr(client, "pid", None), getattr(client, "sid", None), request.id)
        if replay_key in self._processed_request_ids:
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="REJECTED",
                latency_ms=latency,
                error_code=-32600,
                error_message="Duplicate request ID detected.",
            )
            return make_error_response(request.id, -32600, f"Duplicate request ID '{request.id}' in session.")

        self._processed_request_ids[replay_key] = None
        while len(self._processed_request_ids) > self._max_tracked_request_ids:
            self._processed_request_ids.popitem(last=False)

        # 3. Reject prohibited parameters (client-selected DB path)
        if "db_path" in request.params or "database_path" in request.params or "path" in request.params:
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="REJECTED",
                latency_ms=latency,
                error_code=-32602,
                error_message="Client-selected database paths are strictly prohibited.",
            )
            return make_error_response(request.id, -32602, "Client-selected database paths are strictly prohibited.")

        # 3b. Reject client-supplied trust mode or execution mode tampering
        if any(k in request.params for k in ("test_mode", "production_mode", "allow_execution", "trust_mode")):
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="REJECTED",
                latency_ms=latency,
                error_code=JSONRPC_INVALID_PARAMS,
                error_message="Client-supplied trust_mode or execution mode parameter is strictly prohibited.",
            )
            return make_error_response(
                request.id,
                JSONRPC_INVALID_PARAMS,
                "Client-supplied trust_mode or execution mode parameter is strictly prohibited.",
            )

        # 4. Reject arbitrary SQL execution methods
        if request.method in ("broker.execute_sql", "broker.query_sql", "execute_sql"):
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="REJECTED",
                latency_ms=latency,
                error_code=ERR_ACCESS_DENIED,
                error_message="Arbitrary SQL execution over IPC is strictly prohibited.",
            )
            return make_error_response(request.id, ERR_ACCESS_DENIED, "Arbitrary SQL execution over IPC is strictly prohibited.")

        # 5. Check for unimplemented governance methods
        if request.method in self._unimplemented_governance_methods:
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="REJECTED",
                latency_ms=latency,
                error_code=ERR_NOT_IMPLEMENTED,
                error_message=f"Method '{request.method}' not implemented in phase NEXT-21C-A.",
            )
            return make_error_response(
                request.id,
                ERR_NOT_IMPLEMENTED,
                f"State-mutating governance method '{request.method}' is not implemented in phase NEXT-21C-A (reserved for Subphase NEXT-21C-B).",
                {"method": request.method, "phase": "NEXT-21C-A"},
            )

        # 6. Lookup Handler
        handler = self._handlers.get(request.method)
        if handler is None:
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="REJECTED",
                latency_ms=latency,
                error_code=JSONRPC_METHOD_NOT_FOUND,
                error_message=f"Method '{request.method}' not found.",
            )
            return make_error_response(request.id, JSONRPC_METHOD_NOT_FOUND, f"Method '{request.method}' not found.")

        # 7. Execute Handler
        try:
            result = handler(request, client)
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="ACCEPTED",
                latency_ms=latency,
            )
            return make_success_response(request.id, result)
        except BrokerError as b_err:
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="ERROR",
                latency_ms=latency,
                error_code=b_err.code,
                error_message=b_err.message,
            )
            return make_error_response(request.id, b_err.code, b_err.message, b_err.data)
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000.0
            self.audit_logger.log_request(
                request_id=request.id,
                method=request.method,
                client_pid=client.pid,
                integrity_level=client.integrity_level,
                status="ERROR",
                latency_ms=latency,
                error_code=-32603,
                error_message=str(exc),
            )
            return make_error_response(request.id, -32603, f"Internal broker error: {exc}")

    # =========================================================================
    # Initial Safe RPC Handlers
    # =========================================================================

    def _handle_health(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.health implementation."""
        now = datetime.now(timezone.utc)
        uptime = (now - self.start_time).total_seconds()
        is_cng = isinstance(self.signer, CngCbeatSigner)
        return {
            "status": "healthy",
            "service": self.service_identity or "AntigravityAuditorBroker",
            "service_identity": self.service_identity,
            "service_mode": self.service_mode,
            "qualification_only": self.qualification_only,
            "cng_enabled": is_cng,
            "require_cng": self.require_cng,
            "tpm_backed": bool(is_cng and self.signer.metadata.tpm_backed),
            "require_tcb": self.require_tcb,
            "tcb_configured": self.tcb_verifier is not None,
            "allow_execution_dispatch": self.allow_execution_dispatch,
            "version": PROTOCOL_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "pid": os.getpid(),
            "uptime_seconds": round(uptime, 2),
            "client_pid": client.pid,
            "client_sid": client.sid,
            "client_integrity": client.integrity_level,
            "impersonation_level": client.impersonation_level,
            "impersonation_reverted": client.impersonation_reverted,
            "token_handle_closed": client.token_handle_closed,
            "database_connected": self.db_adapter is not None,
            "memory_usage_mb": 12.5,
            "db_status": {"accessible": self.db_adapter is not None},
        }

    def _handle_capabilities(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.capabilities implementation."""
        gated = set(self._gated_methods)
        if self._unimplemented_governance_methods:
            gated.update(self._unimplemented_governance_methods)
        if self.qualification_only:
            supported = sorted(
                m for m in self._handlers.keys() if m in B4A_QUALIFICATION_ALLOWED_METHODS
            )
            blocked_by_qualification = sorted(
                (set(self._handlers.keys()) | gated) - B4A_QUALIFICATION_ALLOWED_METHODS
            )
        else:
            supported = sorted(list(self._handlers.keys()))
            blocked_by_qualification = []
        is_cng = isinstance(self.signer, CngCbeatSigner)
        return {
            "protocol_version": PROTOCOL_VERSION,
            "service_identity": self.service_identity,
            "service_mode": self.service_mode,
            "qualification_only": self.qualification_only,
            "cng_enabled": is_cng,
            "require_cng": self.require_cng,
            "tpm_backed": bool(is_cng and self.signer.metadata.tpm_backed),
            "require_tcb": self.require_tcb,
            "tcb_configured": self.tcb_verifier is not None,
            "allow_execution_dispatch": self.allow_execution_dispatch,
            "supported_methods": supported,
            "blocked_by_qualification": blocked_by_qualification,
            "unimplemented_governance_methods": sorted(list(self._unimplemented_governance_methods)),
            "gated_methods": sorted(list(gated)),
            "transport": "Windows Named Pipe (Local Only)",
            "database_access_mode": "BROKER_OWNED_EXCLUSIVE",
            "phase": self.phase,
        }

    def _handle_protocol_version(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.protocol_version implementation."""
        client_version = request.params.get("client_version")
        compatible = True
        if client_version and client_version != PROTOCOL_VERSION:
            compatible = client_version.split(".")[0] == PROTOCOL_VERSION.split(".")[0]

        return {
            "version": PROTOCOL_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "compatible": compatible,
            "server_version": PROTOCOL_VERSION,
        }

    def _handle_test_ping_db(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.test_ping_db implementation (Read-Only demonstration method on configured test DB)."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)

        ping_result = self.db_adapter.ping()
        tables = self.db_adapter.get_table_names()
        return {
            "ping": "pong",
            "db_status": ping_result,
            "table_count": len(tables),
            "tables": tables,
            "read_only": True,
            "schema_version": 1,
        }

    # =========================================================================
    # NEXT-21C-B1 Read-Only Handlers
    # =========================================================================

    def _handle_get_context(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.get_context handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str) or not project_key.strip():
            raise BrokerSchemaError("Parameter 'project_key' is required and must be a non-empty string.")
        history_limit = request.params.get("history_limit", 50)
        if not isinstance(history_limit, int) or history_limit < 1 or history_limit > 500:
            raise BrokerSchemaError("Parameter 'history_limit' must be an integer between 1 and 500.")
        return self.db_adapter.get_context(project_key=project_key.strip(), history_limit=history_limit)

    def _handle_list_findings(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.list_findings handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str) or not project_key.strip():
            raise BrokerSchemaError("Parameter 'project_key' is required and must be a non-empty string.")
        run_id = request.params.get("run_id")
        if run_id is not None and not isinstance(run_id, str):
            raise BrokerSchemaError("Parameter 'run_id' must be a string or null.")
        lifecycle = request.params.get("lifecycle")
        if lifecycle is not None and not isinstance(lifecycle, str):
            raise BrokerSchemaError("Parameter 'lifecycle' must be a string or null.")
        severity = request.params.get("severity")
        if severity is not None and not isinstance(severity, str):
            raise BrokerSchemaError("Parameter 'severity' must be a string or null.")
        confidence = request.params.get("confidence")
        if confidence is not None and not isinstance(confidence, str):
            raise BrokerSchemaError("Parameter 'confidence' must be a string or null.")
        verification_status = request.params.get("verification_status")
        if verification_status is not None and not isinstance(verification_status, str):
            raise BrokerSchemaError("Parameter 'verification_status' must be a string or null.")
        include_dismissed = bool(request.params.get("include_dismissed", False))
        include_candidates = bool(request.params.get("include_candidates", True))
        limit = request.params.get("limit", 500)
        if not isinstance(limit, int) or limit < 1 or limit > MAX_QUERY_LIMIT:
            raise BrokerSchemaError(f"Parameter 'limit' must be an integer between 1 and {MAX_QUERY_LIMIT}.")
        offset = request.params.get("offset", 0)
        if not isinstance(offset, int) or offset < 0:
            raise BrokerSchemaError("Parameter 'offset' must be a non-negative integer.")

        order_by = request.params.get("order_by")
        if order_by is not None:
            if not isinstance(order_by, str) or order_by.lower() not in ALLOWED_SORT_COLUMNS:
                raise BrokerSchemaError(f"Parameter 'order_by' must be one of: {sorted(ALLOWED_SORT_COLUMNS)}")
        order_dir = request.params.get("order_dir")
        if order_dir is not None:
            if not isinstance(order_dir, str) or order_dir.lower() not in {"asc", "desc"}:
                raise BrokerSchemaError("Parameter 'order_dir' must be 'asc' or 'desc'.")

        findings = self.db_adapter.list_findings(
            project_key=project_key.strip(),
            run_id=run_id.strip() if run_id else None,
            lifecycle=lifecycle.strip() if lifecycle else None,
            severity=severity.strip() if severity else None,
            confidence=confidence.strip() if confidence else None,
            verification_status=verification_status.strip() if verification_status else None,
            include_dismissed=include_dismissed,
            include_candidates=include_candidates,
            limit=limit,
            offset=offset,
        )
        return {
            "project_key": project_key.strip(),
            "count": len(findings),
            "findings": findings,
        }

    def _handle_get_review_context(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.get_review_context handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str) or not project_key.strip():
            raise BrokerSchemaError("Parameter 'project_key' is required and must be a non-empty string.")
        run_id = request.params.get("run_id")
        if not run_id or not isinstance(run_id, str) or not run_id.strip():
            raise BrokerSchemaError("Parameter 'run_id' is required and must be a non-empty string.")
        return self.db_adapter.get_review_context(project_key=project_key.strip(), run_id=run_id.strip())

    def _handle_get_verification_context(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.get_verification_context handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        audit_run_id = request.params.get("audit_run_id")
        if not audit_run_id or not isinstance(audit_run_id, str) or not audit_run_id.strip():
            raise BrokerSchemaError("Parameter 'audit_run_id' is required and must be a non-empty string.")
        verification_run_id = request.params.get("verification_run_id")
        if not verification_run_id or not isinstance(verification_run_id, str) or not verification_run_id.strip():
            raise BrokerSchemaError("Parameter 'verification_run_id' is required and must be a non-empty string.")
        return self.db_adapter.get_verification_context(
            audit_run_id=audit_run_id.strip(),
            verification_run_id=verification_run_id.strip(),
        )

    def _handle_get_verification_status(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.get_verification_status handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        audit_run_id = request.params.get("audit_run_id")
        if not audit_run_id or not isinstance(audit_run_id, str) or not audit_run_id.strip():
            raise BrokerSchemaError("Parameter 'audit_run_id' is required and must be a non-empty string.")
        verification_run_id = request.params.get("verification_run_id")
        if verification_run_id is not None and not isinstance(verification_run_id, str):
            raise BrokerSchemaError("Parameter 'verification_run_id' must be a string or null.")
        return self.db_adapter.get_verification_status(
            audit_run_id=audit_run_id.strip(),
            verification_run_id=verification_run_id.strip() if verification_run_id else None,
        )

    def _handle_get_status(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.get_status handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        project_key = request.params.get("project_key")
        if project_key is not None and not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a string or null.")
        events_limit = request.params.get("events_limit", 20)
        events_offset = request.params.get("events_offset", 0)
        if (
            not isinstance(events_limit, int) or isinstance(events_limit, bool) or not 1 <= events_limit <= 50
            or not isinstance(events_offset, int) or isinstance(events_offset, bool) or events_offset < 0
        ):
            raise BrokerSchemaError("Parameters 'events_limit' (1-50) and 'events_offset' (>= 0) must be integers.")
        return self.db_adapter.get_status(
            project_key=project_key.strip() if project_key else None,
            events_limit=events_limit,
            events_offset=events_offset,
        )

    def _handle_get_verifier_worker_status(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.get_verifier_worker_status handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        project_key = request.params.get("project_key")
        if project_key is not None and not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a string or null.")
        return self.db_adapter.get_verifier_worker_status(project_key=project_key.strip() if project_key else None)

    def _handle_get_quality_report(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.get_quality_report handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        project_key = request.params.get("project_key")
        if project_key is not None and not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a string or null.")
        audit_run_id = request.params.get("audit_run_id")
        if audit_run_id is not None and not isinstance(audit_run_id, str):
            raise BrokerSchemaError("Parameter 'audit_run_id' must be a string or null.")
        return self.db_adapter.get_quality_report(
            project_key=project_key.strip() if project_key else None,
            audit_run_id=audit_run_id.strip() if audit_run_id else None,
        )

    # =========================================================================
    # Governance State-Mutating RPC Handlers (NEXT-21C-B2)
    # =========================================================================

    def _handle_ingest_findings(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.ingest_findings handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str) or len(project_key) > 128:
            raise BrokerSchemaError("Parameter 'project_key' must be a non-empty string <= 128 chars.")
        run_id = request.params.get("run_id")
        if not run_id or not isinstance(run_id, str) or len(run_id) > 128:
            raise BrokerSchemaError("Parameter 'run_id' must be a non-empty string <= 128 chars.")
        findings = request.params.get("findings")
        if not isinstance(findings, list) or len(findings) == 0 or len(findings) > 1000:
            raise BrokerSchemaError("Parameter 'findings' must be a non-empty array with at most 1000 items.")
        return self.db_adapter.ingest_findings_tx(
            project_key=project_key.strip(),
            run_id=run_id.strip(),
            findings=findings,
            actor=str(client.pid),
        )

    def _handle_save_decisions(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.save_decisions handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a non-empty string.")
        run_id = request.params.get("run_id")
        if not run_id or not isinstance(run_id, str):
            raise BrokerSchemaError("Parameter 'run_id' must be a non-empty string.")
        decisions = request.params.get("decisions")
        if not isinstance(decisions, list) or len(decisions) == 0 or len(decisions) > 500:
            raise BrokerSchemaError("Parameter 'decisions' must be a non-empty list <= 500 items.")
        actor = request.params.get("actor", f"user-{client.pid}")
        return self.db_adapter.save_decisions_tx(
            project_key=project_key.strip(),
            run_id=run_id.strip(),
            decisions=decisions,
            actor=str(actor),
        )

    def _handle_get_decision_state(self, request: JsonRpcRequest, client: ClientIdentity) -> list[dict[str, Any]]:
        """broker.get_decision_state handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a non-empty string.")
        run_id = request.params.get("run_id")
        if run_id is not None and not isinstance(run_id, str):
            raise BrokerSchemaError("Parameter 'run_id' must be a string or null.")
        return self.db_adapter.get_decision_state(
            project_key=project_key.strip(),
            run_id=run_id.strip() if run_id else None,
        )

    def _active_verifier(self) -> CbeatVerifier:
        if not self._custom_verifier and isinstance(self.signer, CngCbeatSigner):
            return CbeatVerifier(
                trusted_public_keys=self.signer.trusted_public_keys,
                require_cng=self.require_cng,
            )
        return self.verifier

    def _handle_authorize_execution(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.authorize_execution handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        if self.require_cng and not isinstance(self.signer, CngCbeatSigner):
            raise BrokerSecurityError(
                "CNG persisted key custody is required for execution authorization.",
                code=ERR_ACCESS_DENIED,
            )
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a non-empty string.")
        run_id = request.params.get("run_id")
        if not run_id or not isinstance(run_id, str):
            raise BrokerSchemaError("Parameter 'run_id' must be a non-empty string.")
        approved_finding_ids = request.params.get("approved_finding_ids")
        if not isinstance(approved_finding_ids, list) or len(approved_finding_ids) == 0:
            raise BrokerSchemaError("Parameter 'approved_finding_ids' must be a non-empty list of string IDs.")
        base_commit = request.params.get("base_commit")
        if not base_commit or not isinstance(base_commit, str):
            raise BrokerSchemaError("Parameter 'base_commit' must be a non-empty string.")
        working_tree_hash = request.params.get("working_tree_hash", "default_hash")
        execution_id = request.params.get("execution_id", "")
        allowed_scope_digest = request.params.get("allowed_scope_digest", "0" * 64)
        evidence_digest = request.params.get("evidence_digest", "0" * 64)
        test_policy_digest = request.params.get("test_policy_digest", "0" * 64)
        max_repair_attempts = int(request.params.get("max_repair_attempts", 2))
        ttl_seconds = int(request.params.get("ttl_seconds", 3600))
        authorized_by = str(request.params.get("authorized_by", f"user-{client.pid}"))
        tcb_confirmation = request.params.get("tcb_confirmation")
        if tcb_confirmation is not None and not isinstance(tcb_confirmation, dict):
            raise BrokerSchemaError("Parameter 'tcb_confirmation' must be an object or null.")

        return self.db_adapter.authorize_execution_tx(
            project_key=project_key.strip(),
            run_id=run_id.strip(),
            approved_finding_ids=approved_finding_ids,
            base_commit=base_commit.strip(),
            working_tree_hash=str(working_tree_hash).strip(),
            execution_id=str(execution_id).strip(),
            allowed_scope_digest=str(allowed_scope_digest).strip(),
            evidence_digest=str(evidence_digest).strip(),
            test_policy_digest=str(test_policy_digest).strip(),
            signer=self.signer,
            max_repair_attempts=max_repair_attempts,
            ttl_seconds=ttl_seconds,
            authorized_by=authorized_by,
            tcb_verifier=self.tcb_verifier,
            tcb_confirmation=tcb_confirmation,
            require_tcb=self.require_tcb,
            client_sid=client.sid,
        )

    def _handle_verify_execution_approval(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.verify_execution_approval handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        approval_id = request.params.get("approval_id")
        if not approval_id or not isinstance(approval_id, str):
            raise BrokerSchemaError("Parameter 'approval_id' must be a non-empty string.")
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a non-empty string.")
        run_id = request.params.get("run_id")
        if not run_id or not isinstance(run_id, str):
            raise BrokerSchemaError("Parameter 'run_id' must be a non-empty string.")
        base_commit = request.params.get("base_commit")
        if not base_commit or not isinstance(base_commit, str):
            raise BrokerSchemaError("Parameter 'base_commit' must be a non-empty string.")
        execution_id = request.params.get("execution_id", "")
        approved_finding_ids = request.params.get("approved_finding_ids")
        if not isinstance(approved_finding_ids, list):
            raise BrokerSchemaError("Parameter 'approved_finding_ids' must be a list of string IDs.")
        cbeat_token = request.params.get("cbeat_token")
        if not isinstance(cbeat_token, dict):
            raise BrokerSchemaError("Parameter 'cbeat_token' must be an object.")

        return self.db_adapter.verify_execution_approval(
            approval_id=approval_id.strip(),
            project_key=project_key.strip(),
            run_id=run_id.strip(),
            base_commit=base_commit.strip(),
            execution_id=str(execution_id).strip(),
            approved_finding_ids=approved_finding_ids,
            cbeat_token_data=cbeat_token,
            verifier=self._active_verifier(),
        )

    def _handle_consume_execution_approval(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.consume_execution_approval handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        approval_id = request.params.get("approval_id")
        if not approval_id or not isinstance(approval_id, str):
            raise BrokerSchemaError("Parameter 'approval_id' must be a non-empty string.")
        single_use_nonce = request.params.get("single_use_nonce")
        if not single_use_nonce or not isinstance(single_use_nonce, str):
            raise BrokerSchemaError("Parameter 'single_use_nonce' must be a non-empty string.")

        return self.db_adapter.consume_execution_approval_tx(
            approval_id=approval_id.strip(),
            single_use_nonce=single_use_nonce.strip(),
            actor=str(client.pid),
        )

    def _handle_register_execution_intent(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.register_execution_intent handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        exec_id = request.params.get("exec_id")
        if not exec_id or not isinstance(exec_id, str):
            raise BrokerSchemaError("Parameter 'exec_id' must be a non-empty string.")
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a non-empty string.")
        run_id = request.params.get("run_id")
        if not run_id or not isinstance(run_id, str):
            raise BrokerSchemaError("Parameter 'run_id' must be a non-empty string.")
        approval_id = request.params.get("approval_id")
        if not approval_id or not isinstance(approval_id, str):
            raise BrokerSchemaError("Parameter 'approval_id' must be a non-empty string.")
        base_commit = request.params.get("base_commit")
        if not base_commit or not isinstance(base_commit, str):
            raise BrokerSchemaError("Parameter 'base_commit' must be a non-empty string.")
        working_tree_hash = request.params.get("working_tree_hash", "default_hash")
        worktree_path = request.params.get("worktree_path")
        branch_name = request.params.get("branch_name")
        max_retries = int(request.params.get("max_retries", 2))

        return self.db_adapter.register_execution_intent_tx(
            exec_id=exec_id.strip(),
            project_key=project_key.strip(),
            run_id=run_id.strip(),
            approval_id=approval_id.strip(),
            base_commit=base_commit.strip(),
            working_tree_hash=str(working_tree_hash).strip(),
            worktree_path=str(worktree_path).strip() if worktree_path else None,
            branch_name=str(branch_name).strip() if branch_name else None,
            max_retries=max_retries,
        )

    def _handle_acquire_execution_lease(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.acquire_execution_lease handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        exec_id = request.params.get("exec_id")
        if not exec_id or not isinstance(exec_id, str):
            raise BrokerSchemaError("Parameter 'exec_id' must be a non-empty string.")
        worker_id = request.params.get("worker_id")
        if not worker_id or not isinstance(worker_id, str):
            raise BrokerSchemaError("Parameter 'worker_id' must be a non-empty string.")
        ttl_seconds = int(request.params.get("ttl_seconds", 300))

        return self.db_adapter.acquire_execution_lease_tx(
            exec_id=exec_id.strip(),
            worker_id=worker_id.strip(),
            ttl_seconds=ttl_seconds,
        )

    def _handle_heartbeat_execution(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.heartbeat_execution handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        lease_id = request.params.get("lease_id")
        if not lease_id or not isinstance(lease_id, str):
            raise BrokerSchemaError("Parameter 'lease_id' must be a non-empty string.")
        exec_id = request.params.get("exec_id")
        if not exec_id or not isinstance(exec_id, str):
            raise BrokerSchemaError("Parameter 'exec_id' must be a non-empty string.")
        worker_id = request.params.get("worker_id")
        if not worker_id or not isinstance(worker_id, str):
            raise BrokerSchemaError("Parameter 'worker_id' must be a non-empty string.")
        fencing_token = request.params.get("fencing_token")
        if fencing_token is None or not isinstance(fencing_token, int):
            raise BrokerSchemaError("Parameter 'fencing_token' must be an integer.")
        ttl_seconds = int(request.params.get("ttl_seconds", 300))

        return self.db_adapter.heartbeat_execution_tx(
            lease_id=lease_id.strip(),
            exec_id=exec_id.strip(),
            worker_id=worker_id.strip(),
            fencing_token=fencing_token,
            ttl_seconds=ttl_seconds,
        )

    def _handle_renew_execution_lease(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.renew_execution_lease handler."""
        return self._handle_heartbeat_execution(request, client)

    def _handle_update_execution_state(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.update_execution_state handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        exec_id = request.params.get("exec_id")
        if not exec_id or not isinstance(exec_id, str):
            raise BrokerSchemaError("Parameter 'exec_id' must be a non-empty string.")
        new_status = request.params.get("new_status")
        if not new_status or not isinstance(new_status, str):
            raise BrokerSchemaError("Parameter 'new_status' must be a non-empty string.")
        lease_id = request.params.get("lease_id")
        if not lease_id or not isinstance(lease_id, str):
            raise BrokerSchemaError("Parameter 'lease_id' must be a non-empty string.")
        fencing_token = request.params.get("fencing_token")
        if fencing_token is None or not isinstance(fencing_token, int):
            raise BrokerSchemaError("Parameter 'fencing_token' must be an integer.")

        return self.db_adapter.update_execution_state_tx(
            exec_id=exec_id.strip(),
            new_status=new_status.strip(),
            lease_id=lease_id.strip(),
            fencing_token=fencing_token,
        )

    def _handle_register_checkpoint(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.register_checkpoint handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        checkpoint_id = request.params.get("checkpoint_id")
        if not checkpoint_id or not isinstance(checkpoint_id, str):
            raise BrokerSchemaError("Parameter 'checkpoint_id' must be a non-empty string.")
        exec_id = request.params.get("exec_id")
        if not exec_id or not isinstance(exec_id, str):
            raise BrokerSchemaError("Parameter 'exec_id' must be a non-empty string.")
        finding_id = request.params.get("finding_id")
        if not finding_id or not isinstance(finding_id, str):
            raise BrokerSchemaError("Parameter 'finding_id' must be a non-empty string.")
        base_commit = request.params.get("base_commit")
        if not base_commit or not isinstance(base_commit, str):
            raise BrokerSchemaError("Parameter 'base_commit' must be a non-empty string.")
        scope_digest = str(request.params.get("scope_digest", "0" * 64)).strip()
        manifest_hash = str(request.params.get("manifest_hash", "0" * 64)).strip()
        checkpoint_path = str(request.params.get("checkpoint_path", "")).strip()

        return self.db_adapter.register_checkpoint_tx(
            checkpoint_id=checkpoint_id.strip(),
            exec_id=exec_id.strip(),
            finding_id=finding_id.strip(),
            base_commit=base_commit.strip(),
            scope_digest=scope_digest,
            manifest_hash=manifest_hash,
            checkpoint_path=checkpoint_path,
        )

    def _handle_record_repair_attempt(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.record_repair_attempt handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        exec_id = request.params.get("exec_id")
        if not exec_id or not isinstance(exec_id, str):
            raise BrokerSchemaError("Parameter 'exec_id' must be a non-empty string.")
        finding_id = request.params.get("finding_id")
        if not finding_id or not isinstance(finding_id, str):
            raise BrokerSchemaError("Parameter 'finding_id' must be a non-empty string.")
        repair_attempt = request.params.get("repair_attempt")
        if repair_attempt is None or not isinstance(repair_attempt, int):
            raise BrokerSchemaError("Parameter 'repair_attempt' must be an integer.")

        happy_test = request.params.get("happy_test_passed")
        adv_test = request.params.get("adversarial_test_passed")
        red_team = request.params.get("red_team_passed")
        notes = request.params.get("red_team_notes")
        diff = request.params.get("diff_summary")
        err = request.params.get("error")

        return self.db_adapter.record_repair_attempt_tx(
            exec_id=exec_id.strip(),
            finding_id=finding_id.strip(),
            repair_attempt=repair_attempt,
            happy_test_passed=int(happy_test) if happy_test is not None else None,
            adversarial_test_passed=int(adv_test) if adv_test is not None else None,
            red_team_passed=int(red_team) if red_team is not None else None,
            red_team_notes=str(notes) if notes is not None else None,
            diff_summary=str(diff) if diff is not None else None,
            error=str(err) if err is not None else None,
        )

    def _handle_quarantine_checkpoint(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.quarantine_checkpoint handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        quarantine_id = request.params.get("quarantine_id")
        if not quarantine_id or not isinstance(quarantine_id, str):
            raise BrokerSchemaError("Parameter 'quarantine_id' must be a non-empty string.")
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a non-empty string.")
        exec_id = request.params.get("exec_id")
        if not exec_id or not isinstance(exec_id, str):
            raise BrokerSchemaError("Parameter 'exec_id' must be a non-empty string.")
        worktree_path = str(request.params.get("worktree_path", "")).strip()
        reason = str(request.params.get("reason", "Security policy violation")).strip()
        checkpoint_id = request.params.get("checkpoint_id")
        preserved_diff_path = request.params.get("preserved_diff_path")

        return self.db_adapter.quarantine_checkpoint_tx(
            quarantine_id=quarantine_id.strip(),
            project_key=project_key.strip(),
            exec_id=exec_id.strip(),
            worktree_path=worktree_path,
            reason=reason,
            checkpoint_id=str(checkpoint_id).strip() if checkpoint_id else None,
            preserved_diff_path=str(preserved_diff_path).strip() if preserved_diff_path else None,
        )

    def _handle_finalize_execution(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.finalize_execution handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        exec_id = request.params.get("exec_id")
        if not exec_id or not isinstance(exec_id, str):
            raise BrokerSchemaError("Parameter 'exec_id' must be a non-empty string.")
        status = request.params.get("status")
        if not status or not isinstance(status, str):
            raise BrokerSchemaError("Parameter 'status' must be a non-empty string.")
        integration_test_passed = int(request.params.get("integration_test_passed", 0))
        lease_id = request.params.get("lease_id")
        if not lease_id or not isinstance(lease_id, str):
            raise BrokerSchemaError("Parameter 'lease_id' must be a non-empty string.")
        fencing_token = request.params.get("fencing_token")
        if fencing_token is None or not isinstance(fencing_token, int):
            raise BrokerSchemaError("Parameter 'fencing_token' must be an integer.")

        return self.db_adapter.finalize_execution_tx(
            exec_id=exec_id.strip(),
            status=status.strip(),
            integration_test_passed=integration_test_passed,
            lease_id=lease_id.strip(),
            fencing_token=fencing_token,
        )

    def _handle_submit_verification(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.submit_verification handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        verification_run_id = request.params.get("verification_run_id")
        if not verification_run_id or not isinstance(verification_run_id, str):
            raise BrokerSchemaError("Parameter 'verification_run_id' must be a non-empty string.")
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a non-empty string.")
        run_id = request.params.get("run_id")
        if not run_id or not isinstance(run_id, str):
            raise BrokerSchemaError("Parameter 'run_id' must be a non-empty string.")
        results = request.params.get("results")
        if not isinstance(results, list):
            raise BrokerSchemaError("Parameter 'results' must be a list of verification result objects.")
        quality_metrics = request.params.get("quality_metrics")
        verifier_conv_id = str(request.params.get("verifier_conversation_id", f"verifier-{client.pid}"))

        return self.db_adapter.submit_verification_tx(
            verification_run_id=verification_run_id.strip(),
            project_key=project_key.strip(),
            run_id=run_id.strip(),
            results=results,
            quality_metrics=quality_metrics if isinstance(quality_metrics, dict) else None,
            verifier_conversation_id=verifier_conv_id,
        )

    def _handle_finalize_verified_report(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.finalize_verified_report handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        verification_run_id = request.params.get("verification_run_id")
        if not verification_run_id or not isinstance(verification_run_id, str):
            raise BrokerSchemaError("Parameter 'verification_run_id' must be a non-empty string.")
        project_key = request.params.get("project_key")
        if not project_key or not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a non-empty string.")
        run_id = request.params.get("run_id")
        if not run_id or not isinstance(run_id, str):
            raise BrokerSchemaError("Parameter 'run_id' must be a non-empty string.")
        verifier_conv_id = str(request.params.get("verifier_conversation_id", f"verifier-{client.pid}"))

        return self.db_adapter.finalize_verified_report_tx(
            verification_run_id=verification_run_id.strip(),
            project_key=project_key.strip(),
            run_id=run_id.strip(),
            verifier_conversation_id=verifier_conv_id,
        )

    def _handle_claim_verification_job(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any] | None:
        """broker.claim_verification_job handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        worker_id = request.params.get("worker_id", f"worker-{client.pid}")
        ttl_seconds = int(request.params.get("ttl_seconds", 300))
        return self.db_adapter.claim_verification_job_tx(
            worker_id=str(worker_id).strip(),
            ttl_seconds=ttl_seconds,
        )

    def _handle_recover_verification_lease(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.recover_verification_lease handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        project_key = request.params.get("project_key")
        return self.db_adapter.recover_verification_lease_tx(
            project_key=project_key.strip() if project_key else None,
        )


    def _handle_verify_audit_chain(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.verify_audit_chain handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        return self.db_adapter.verify_audit_chain_tx()

    def _handle_validate_checkpoint(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.validate_checkpoint handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        params = request.params or {}
        checkpoint_id = params.get("checkpoint_id")
        if not checkpoint_id or not isinstance(checkpoint_id, str):
            raise BrokerSchemaError("Parameter 'checkpoint_id' must be a non-empty string.")
        exec_id = params.get("exec_id")
        return self.db_adapter.validate_checkpoint_tx(
            checkpoint_id=checkpoint_id.strip(),
            exec_id=str(exec_id).strip() if exec_id else None,
        )

    def _handle_restore_checkpoint(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.restore_checkpoint handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        params = request.params or {}
        checkpoint_id = params.get("checkpoint_id")
        exec_id = params.get("exec_id")
        worktree_path = params.get("worktree_path")
        if not checkpoint_id or not isinstance(checkpoint_id, str):
            raise BrokerSchemaError("Parameter 'checkpoint_id' must be a non-empty string.")
        if not exec_id or not isinstance(exec_id, str):
            raise BrokerSchemaError("Parameter 'exec_id' must be a non-empty string.")
        if not worktree_path or not isinstance(worktree_path, str):
            raise BrokerSchemaError("Parameter 'worktree_path' must be a non-empty string.")
        return self.db_adapter.restore_checkpoint_tx(
            checkpoint_id=checkpoint_id.strip(),
            exec_id=exec_id.strip(),
            worktree_path=worktree_path.strip(),
        )

    def _handle_get_execution_state(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.get_execution_state handler."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        params = request.params or {}
        exec_id = params.get("exec_id")
        if not exec_id or not isinstance(exec_id, str):
            raise BrokerSchemaError("Parameter 'exec_id' must be a non-empty string.")
        return self.db_adapter.get_execution_state_tx(exec_id=exec_id.strip())

    def _handle_request_confirmation_challenge(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.request_confirmation_challenge handler (B4B-TCB)."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        params = request.params or {}
        project_key = params.get("project_key")
        run_id = params.get("run_id")
        approved_finding_ids = params.get("approved_finding_ids")
        base_commit = params.get("base_commit")
        if not project_key or not isinstance(project_key, str):
            raise BrokerSchemaError("Parameter 'project_key' must be a non-empty string.")
        if not run_id or not isinstance(run_id, str):
            raise BrokerSchemaError("Parameter 'run_id' must be a non-empty string.")
        if not isinstance(approved_finding_ids, list) or not approved_finding_ids:
            raise BrokerSchemaError("Parameter 'approved_finding_ids' must be a non-empty list.")
        if not base_commit or not isinstance(base_commit, str):
            raise BrokerSchemaError("Parameter 'base_commit' must be a non-empty string.")

        return self.db_adapter.create_tcb_challenge_tx(
            project_key=project_key.strip(),
            run_id=run_id.strip(),
            approved_finding_ids=[str(f) for f in approved_finding_ids],
            base_commit=base_commit.strip(),
            working_tree_hash=str(params.get("working_tree_hash", "default_hash")).strip(),
            execution_id=str(params.get("execution_id", "")).strip(),
            max_repair_attempts=int(params.get("max_repair_attempts", 2)),
            ttl_seconds=int(params.get("ttl_seconds", 120)),
            requested_by=str(params.get("requested_by") or f"user-{client.pid}"),
            client_sid=client.sid,
        )

    def _handle_get_confirmation_challenge_status(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.get_confirmation_challenge_status handler (B4B-TCB)."""
        if self.db_adapter is None:
            raise BrokerError("Broker is configured without a database adapter.", code=-32002)
        params = request.params or {}
        challenge_id = params.get("challenge_id")
        if not challenge_id or not isinstance(challenge_id, str):
            raise BrokerSchemaError("Parameter 'challenge_id' must be a non-empty string.")
        return self.db_adapter.get_tcb_challenge_status(challenge_id=challenge_id.strip())

    def _handle_key_status(self, request: JsonRpcRequest, client: ClientIdentity) -> dict[str, Any]:
        """broker.key_status handler: expose non-secret key custody and TCB policy metadata."""
        if isinstance(self.signer, CngCbeatSigner):
            meta = self.signer.metadata.to_dict()
            key_info: dict[str, Any] = {
                "custody_type": "WINDOWS_CNG",
                **meta,
                "active_history_key_ids": sorted(self.signer.trusted_public_keys.keys()),
            }
        else:
            key_info = {
                "custody_type": "EPHEMERAL_MEMORY",
                "algorithm": CBEAT_ALG_ED25519,
                "tpm_backed": False,
                "public_key_hex": self.signer.get_public_key_hex(),
            }
        return {
            "service_mode": self.service_mode,
            "require_cng": self.require_cng,
            "require_tcb": self.require_tcb,
            "key": key_info,
            "tcb": self.tcb_verifier.get_status_summary() if self.tcb_verifier is not None else None,
        }

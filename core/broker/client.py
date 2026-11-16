"""Broker Client for MCP and auditor components communicating over Named Pipe IPC."""

from __future__ import annotations

import ctypes
import json
import os
import uuid
from typing import Any

from broker.constants import (
    DEFAULT_PIPE_NAME,
    DEFAULT_TIMEOUT_SECONDS,
    ERR_ACCESS_DENIED,
    ERR_ALGORITHM_DOWNGRADE,
    ERR_CNG_ERROR,
    ERR_CONFIRMATION_FAILED,
    ERR_CONFIRMATION_REQUIRED,
    ERR_DATABASE_ERROR,
    ERR_METHOD_NOT_IMPLEMENTED,
    ERR_PRODUCTION_DB_ACCESS_PROHIBITED,
    ERR_TPM_UNAVAILABLE,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    MAX_MESSAGE_SIZE,
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
)
from broker.exceptions import (
    BrokerAuthError,
    BrokerCngError,
    BrokerConfirmationError,
    BrokerConfirmationRequiredError,
    BrokerDatabaseError,
    BrokerError,
    BrokerSchemaError,
    BrokerSecurityError,
    BrokerTpmUnavailableError,
    BrokerTimeoutError,
    BrokerUnavailableError,
    MethodNotImplementedError,
    ProductionDatabaseAccessProhibitedError,
)
from broker.protocol import (
    decode_frame_header,
    encode_frame,
)
from broker.security import get_win32_kernel32, is_windows, read_exact_pipe, write_all_pipe
from broker.transport import MemoryPipeTransport


class BrokerClient:
    """IPC client connecting to the Antigravity Auditor Broker.

    CRITICAL SECURITY MANDATE:
    This client communicates EXCLUSIVELY via IPC (Named Pipe or in-memory transport fixture).
    It contains ZERO database connection logic and NEVER falls back to direct SQLite access.
    """

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    INVALID_HANDLE_VALUES = (None, 0, -1, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF)

    # Win32 Error Codes
    ERROR_FILE_NOT_FOUND = 2
    ERROR_ACCESS_DENIED = 5
    ERROR_PIPE_BUSY = 231
    ERROR_BROKEN_PIPE = 109

    def __init__(
        self,
        pipe_name: str = DEFAULT_PIPE_NAME,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        transport: MemoryPipeTransport | None = None,
    ) -> None:
        self.pipe_name = pipe_name
        self.timeout = timeout
        self.transport = transport
        self._pipe_handle: int | None = None

    def close(self) -> None:
        """Close any open client handles or resources."""
        pass

    def invoke(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Send a JSON-RPC request to the broker and return the unwrapped result.

        Raises appropriate BrokerError subclasses on failure.
        """
        req_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params if params is not None else {},
            "protocol_version": PROTOCOL_VERSION,
        }

        raw_json = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        frame_bytes = encode_frame(raw_json)

        resp_frame: bytes
        if self.transport is not None:
            resp_frame = self.transport.execute_raw_frame(frame_bytes)
        else:
            resp_frame = self._transceive_win32_pipe(frame_bytes)

        return self._parse_and_validate_response(resp_frame, expected_id=req_id)

    def _transceive_win32_pipe(self, frame_bytes: bytes) -> bytes:
        """Connect to Windows Named Pipe, send frame, read response frame, and close."""
        if not is_windows():
            raise BrokerUnavailableError("Native Named Pipe client is only supported on Windows.")

        kernel32 = get_win32_kernel32()

        # Wait for pipe if busy (timeout in milliseconds)
        timeout_ms = int(self.timeout * 1000)
        start_time = kernel32.GetTickCount64()

        while True:
            h_pipe = kernel32.CreateFileW(
                self.pipe_name,
                self.GENERIC_READ | self.GENERIC_WRITE,
                0,
                None,
                self.OPEN_EXISTING,
                0,
                None,
            )

            if h_pipe not in self.INVALID_HANDLE_VALUES:
                break

            last_err = ctypes.get_last_error()
            elapsed = kernel32.GetTickCount64() - start_time
            remaining_ms = timeout_ms - elapsed

            if remaining_ms <= 0:
                if last_err == self.ERROR_FILE_NOT_FOUND:
                    raise BrokerUnavailableError(f"Broker Named Pipe not found at {self.pipe_name}. Service may not be running.")
                elif last_err == self.ERROR_ACCESS_DENIED:
                    raise BrokerAuthError(f"Access denied connecting to Named Pipe {self.pipe_name} (Win32 Error 5).")
                elif last_err == self.ERROR_PIPE_BUSY:
                    raise BrokerTimeoutError(f"Timed out waiting for available pipe instance on {self.pipe_name}")
                else:
                    raise BrokerUnavailableError(f"Failed to connect to Named Pipe {self.pipe_name} (Win32 Error {last_err}).")

            if last_err == self.ERROR_FILE_NOT_FOUND:
                import time
                time.sleep(0.05)
                continue
            elif last_err == self.ERROR_PIPE_BUSY:
                wait_time = min(int(remaining_ms), 500)
                if not kernel32.WaitNamedPipeW(self.pipe_name, wait_time):
                    raise BrokerTimeoutError(f"WaitNamedPipeW timed out on {self.pipe_name}")
            elif last_err == self.ERROR_ACCESS_DENIED:
                raise BrokerAuthError(f"Access denied connecting to Named Pipe {self.pipe_name} (Win32 Error 5).")
            else:
                raise BrokerUnavailableError(f"Failed to connect to Named Pipe {self.pipe_name} (Win32 Error {last_err}).")

        try:
            # 1. Send request frame
            if not write_all_pipe(kernel32, h_pipe, frame_bytes):
                raise BrokerError(f"Failed to write request to pipe. LastError: {ctypes.get_last_error()}")

            # 2. Read 4-byte response header
            header_bytes = read_exact_pipe(kernel32, h_pipe, 4)
            if header_bytes is None or len(header_bytes) != 4:
                raise BrokerError("Failed to read frame header from pipe or pipe closed prematurely.")

            payload_len = decode_frame_header(header_bytes)
            if payload_len > MAX_MESSAGE_SIZE:
                raise BrokerSchemaError(f"Response payload {payload_len} exceeds maximum size {MAX_MESSAGE_SIZE}")

            # 3. Read payload
            payload_bytes = read_exact_pipe(kernel32, h_pipe, payload_len)
            if payload_bytes is None or len(payload_bytes) != payload_len:
                raise BrokerError("Incomplete payload read from pipe.")

            return header_bytes + payload_bytes
        finally:
            kernel32.CloseHandle(h_pipe)

    def _parse_and_validate_response(self, frame_bytes: bytes, expected_id: str) -> Any:
        """Decode frame, parse JSON-RPC response, and map errors to typed exceptions."""
        if len(frame_bytes) < 4:
            raise BrokerSchemaError("Response frame shorter than 4-byte header.")

        payload_len = decode_frame_header(frame_bytes[:4])
        payload_data = frame_bytes[4 : 4 + payload_len]

        if len(payload_data) != payload_len:
            raise BrokerSchemaError(f"Payload length mismatch: expected {payload_len}, got {len(payload_data)}")

        try:
            data = json.loads(payload_data.decode("utf-8"))
        except Exception as exc:
            raise BrokerSchemaError(f"Malformed JSON in broker response: {exc}") from exc

        if not isinstance(data, dict):
            raise BrokerSchemaError("Broker response is not a valid JSON object.")

        if data.get("jsonrpc") != "2.0":
            raise BrokerSchemaError("Broker response missing 'jsonrpc': '2.0'.")

        resp_id = data.get("id")
        if resp_id is not None and resp_id != expected_id:
            raise BrokerSchemaError(f"Response ID mismatch: expected {expected_id}, got {resp_id}")

        if "error" in data:
            err = data["error"]
            if not isinstance(err, dict):
                raise BrokerSchemaError("Invalid error object in JSON-RPC response.")
            err_code = err.get("code", -32000)
            err_msg = err.get("message", "Unknown broker error")

            if err_code == ERR_TPM_UNAVAILABLE:
                raise BrokerTpmUnavailableError(err_msg, code=err_code, data=err.get("data"))
            elif err_code == ERR_CNG_ERROR:
                raise BrokerCngError(err_msg, code=err_code, data=err.get("data"))
            elif err_code == ERR_CONFIRMATION_REQUIRED:
                raise BrokerConfirmationRequiredError(err_msg, code=err_code, data=err.get("data"))
            elif err_code == ERR_CONFIRMATION_FAILED:
                raise BrokerConfirmationError(err_msg, code=err_code, data=err.get("data"))
            elif err_code in (
                ERR_ACCESS_DENIED,
                ERR_ALGORITHM_DOWNGRADE,
                -32001,
                -32004,
                -32010,  # ERR_REPLAY_ATTEMPT
                -32011,  # ERR_APPROVAL_EXPIRED
                -32012,  # ERR_TWO_STEP_VIOLATION
                -32013,  # ERR_CONCURRENT_CONFLICT
                -32014,  # ERR_RETRY_LIMIT_EXCEEDED
                -32015,  # ERR_SCOPE_VIOLATION
                -32016,  # ERR_EXECUTION_DISABLED
                -32017,  # ERR_CHECKPOINT_QUARANTINED
                -32018,  # ERR_UNVERIFIED_STATE
            ):
                raise BrokerSecurityError(err_msg, code=err_code, data=err.get("data"))
            elif err_code == ERR_PRODUCTION_DB_ACCESS_PROHIBITED:
                raise ProductionDatabaseAccessProhibitedError(err_msg, code=err_code, data=err.get("data"))
            elif err_code == ERR_DATABASE_ERROR:
                raise BrokerDatabaseError(err_msg, code=err_code, data=err.get("data"))
            elif err_code in (JSONRPC_INVALID_PARAMS, JSONRPC_INVALID_REQUEST):
                raise BrokerSchemaError(err_msg, code=err_code, data=err.get("data"))
            elif err_code in (ERR_METHOD_NOT_IMPLEMENTED, JSONRPC_METHOD_NOT_FOUND):
                raise MethodNotImplementedError(err_msg, code=err_code, data=err.get("data"))
            else:
                raise BrokerError(err_msg, code=err_code, data=err.get("data"))

        if "result" not in data:
            raise BrokerSchemaError("Broker response missing both 'result' and 'error'.")

        return data["result"]

    # Typed Helper Methods
    def health(self) -> dict[str, Any]:
        """Query broker health and system status."""
        return self.invoke("broker.health")

    def capabilities(self) -> dict[str, Any]:
        """Query broker supported capabilities and methods."""
        return self.invoke("broker.capabilities")

    def protocol_version(self) -> str:
        """Query broker protocol version."""
        res = self.invoke("broker.protocol_version")
        return res.get("version", "") if isinstance(res, dict) else str(res)

    def test_ping_db(self) -> dict[str, Any]:
        """Test broker database connectivity in an isolated test environment."""
        return self.invoke("broker.test_ping_db")

    # =========================================================================
    # NEXT-21C-B1 Typed Read Methods
    # =========================================================================

    def get_context(self, project_key: str, history_limit: int = 50) -> dict[str, Any]:
        """Query project context, latest run, finding counts, and recent history over Broker IPC."""
        return self.invoke(METHOD_GET_CONTEXT, {
            "project_key": project_key,
            "history_limit": history_limit,
        })

    def list_findings(
        self,
        project_key: str,
        *,
        run_id: str | None = None,
        lifecycle: str | None = None,
        severity: str | None = None,
        confidence: str | None = None,
        verification_status: str | None = None,
        include_dismissed: bool = False,
        include_candidates: bool = True,
        limit: int = 500,
        offset: int = 0,
        order_by: str | None = None,
        order_dir: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query canonical and candidate findings matching filters over Broker IPC."""
        params: dict[str, Any] = {
            "project_key": project_key,
            "include_dismissed": include_dismissed,
            "include_candidates": include_candidates,
            "limit": limit,
            "offset": offset,
        }
        if run_id is not None:
            params["run_id"] = run_id
        if lifecycle is not None:
            params["lifecycle"] = lifecycle
        if severity is not None:
            params["severity"] = severity
        if confidence is not None:
            params["confidence"] = confidence
        if verification_status is not None:
            params["verification_status"] = verification_status
        if order_by is not None:
            params["order_by"] = order_by
        if order_dir is not None:
            params["order_dir"] = order_dir

        res = self.invoke(METHOD_LIST_FINDINGS, params)
        if isinstance(res, dict) and "findings" in res:
            return res["findings"]
        return res if isinstance(res, list) else []

    def get_review_context(self, project_key: str, run_id: str) -> dict[str, Any]:
        """Query review report context (project, run, verification run, active approval) over Broker IPC."""
        return self.invoke(METHOD_GET_REVIEW_CONTEXT, {
            "project_key": project_key,
            "run_id": run_id,
        })

    def get_verification_context(self, audit_run_id: str, verification_run_id: str) -> dict[str, Any]:
        """Query context-independent verification payload over Broker IPC."""
        return self.invoke(METHOD_GET_VERIFICATION_CONTEXT, {
            "audit_run_id": audit_run_id,
            "verification_run_id": verification_run_id,
        })

    def get_verification_status(self, audit_run_id: str, verification_run_id: str | None = None) -> dict[str, Any]:
        """Query verification run status and counts over Broker IPC."""
        params: dict[str, Any] = {"audit_run_id": audit_run_id}
        if verification_run_id is not None:
            params["verification_run_id"] = verification_run_id
        return self.invoke(METHOD_GET_VERIFICATION_STATUS, params)

    def get_status(
        self, project_key: str | None = None, *, events_limit: int = 20, events_offset: int = 0
    ) -> dict[str, Any]:
        """Query project status and recent events (paged) over Broker IPC."""
        params: dict[str, Any] = {"events_limit": int(events_limit), "events_offset": int(events_offset)}
        if project_key is not None:
            params["project_key"] = project_key
        return self.invoke(METHOD_GET_STATUS, params)

    def get_verifier_worker_status(self, project_key: str | None = None) -> dict[str, Any]:
        """Query project and verification queue status over Broker IPC."""
        params: dict[str, Any] = {}
        if project_key is not None:
            params["project_key"] = project_key
        return self.invoke(METHOD_GET_VERIFIER_WORKER_STATUS, params)

    def get_quality_report(
        self,
        project_key: str | None = None,
        audit_run_id: str | None = None,
    ) -> dict[str, Any]:
        """Query audit quality metrics and summary over Broker IPC."""
        params: dict[str, Any] = {}
        if project_key is not None:
            params["project_key"] = project_key
        if audit_run_id is not None:
            params["audit_run_id"] = audit_run_id
        return self.invoke(METHOD_GET_QUALITY_REPORT, params)

    # =========================================================================
    # Governance State-Mutating RPC Methods (NEXT-21C-B2)
    # =========================================================================

    def ingest_findings(self, project_key: str, run_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Atomically ingest findings into broker database over Broker IPC."""
        return self.invoke(METHOD_INGEST_FINDINGS, {
            "project_key": project_key,
            "run_id": run_id,
            "findings": findings,
        })

    def save_decisions(
        self,
        project_key: str,
        run_id: str,
        decisions: list[dict[str, Any]],
        actor: str | None = None,
    ) -> dict[str, Any]:
        """Record user decisions for candidate findings (Step A) over Broker IPC."""
        params: dict[str, Any] = {
            "project_key": project_key,
            "run_id": run_id,
            "decisions": decisions,
        }
        if actor is not None:
            params["actor"] = actor
        return self.invoke(METHOD_SAVE_DECISIONS, params)

    def get_decision_state(self, project_key: str, run_id: str | None = None) -> list[dict[str, Any]]:
        """Query active finding decisions over Broker IPC."""
        params: dict[str, Any] = {"project_key": project_key}
        if run_id is not None:
            params["run_id"] = run_id
        return self.invoke(METHOD_GET_DECISION_STATE, params)

    def authorize_execution(
        self,
        project_key: str,
        run_id: str,
        approved_finding_ids: list[str],
        base_commit: str,
        working_tree_hash: str = "default_hash",
        execution_id: str | None = None,
        allowed_scope_digest: str = "0" * 64,
        evidence_digest: str = "0" * 64,
        test_policy_digest: str = "0" * 64,
        max_repair_attempts: int = 2,
        ttl_seconds: int = 3600,
        authorized_by: str | None = None,
        tcb_confirmation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Step B: Issue cryptographically bound CBEAT approval over Broker IPC."""
        params: dict[str, Any] = {
            "project_key": project_key,
            "run_id": run_id,
            "approved_finding_ids": approved_finding_ids,
            "base_commit": base_commit,
            "working_tree_hash": working_tree_hash,
            "allowed_scope_digest": allowed_scope_digest,
            "evidence_digest": evidence_digest,
            "test_policy_digest": test_policy_digest,
            "max_repair_attempts": max_repair_attempts,
            "ttl_seconds": ttl_seconds,
        }
        if execution_id is not None:
            params["execution_id"] = execution_id
        if authorized_by is not None:
            params["authorized_by"] = authorized_by
        if tcb_confirmation is not None:
            params["tcb_confirmation"] = tcb_confirmation
        return self.invoke(METHOD_AUTHORIZE_EXECUTION, params)

    def request_confirmation_challenge(
        self,
        project_key: str,
        run_id: str,
        approved_finding_ids: list[str],
        base_commit: str,
        *,
        working_tree_hash: str = "default_hash",
        execution_id: str = "",
        max_repair_attempts: int = 2,
        ttl_seconds: int = 120,
        requested_by: str | None = None,
    ) -> dict[str, Any]:
        """Request a single-use Trusted Confirmation challenge bound to DB transaction digests."""
        params: dict[str, Any] = {
            "project_key": project_key,
            "run_id": run_id,
            "approved_finding_ids": approved_finding_ids,
            "base_commit": base_commit,
            "working_tree_hash": working_tree_hash,
            "execution_id": execution_id,
            "max_repair_attempts": max_repair_attempts,
            "ttl_seconds": ttl_seconds,
        }
        if requested_by is not None:
            params["requested_by"] = requested_by
        return self.invoke(METHOD_REQUEST_CONFIRMATION_CHALLENGE, params)

    def get_confirmation_challenge_status(self, challenge_id: str) -> dict[str, Any]:
        """Query persisted TCB challenge status over Broker IPC."""
        return self.invoke(METHOD_GET_CONFIRMATION_CHALLENGE_STATUS, {"challenge_id": challenge_id})

    def key_status(self) -> dict[str, Any]:
        """Query non-secret CNG/TPM key custody and TCB policy metadata over Broker IPC."""
        return self.invoke(METHOD_KEY_STATUS)

    def verify_execution_approval(
        self,
        approval_id: str,
        project_key: str,
        run_id: str,
        base_commit: str,
        approved_finding_ids: list[str],
        cbeat_token: dict[str, Any],
        execution_id: str = "",
    ) -> dict[str, Any]:
        """Verify CBEAT token signature and authoritative DB bindings over Broker IPC."""
        return self.invoke(METHOD_VERIFY_EXECUTION_APPROVAL, {
            "approval_id": approval_id,
            "project_key": project_key,
            "run_id": run_id,
            "base_commit": base_commit,
            "approved_finding_ids": approved_finding_ids,
            "cbeat_token": cbeat_token,
            "execution_id": execution_id,
        })

    def consume_execution_approval(self, approval_id: str, single_use_nonce: str) -> dict[str, Any]:
        """Atomically consume single-use approval token over Broker IPC."""
        return self.invoke(METHOD_CONSUME_EXECUTION_APPROVAL, {
            "approval_id": approval_id,
            "single_use_nonce": single_use_nonce,
        })

    def register_execution_intent(
        self,
        exec_id: str,
        project_key: str,
        run_id: str,
        approval_id: str,
        base_commit: str,
        working_tree_hash: str = "default_hash",
        worktree_path: str | None = None,
        branch_name: str | None = None,
        max_retries: int = 2,
    ) -> dict[str, Any]:
        """Register execution run intent bound to approval over Broker IPC."""
        params: dict[str, Any] = {
            "exec_id": exec_id,
            "project_key": project_key,
            "run_id": run_id,
            "approval_id": approval_id,
            "base_commit": base_commit,
            "working_tree_hash": working_tree_hash,
            "max_retries": max_retries,
        }
        if worktree_path is not None:
            params["worktree_path"] = worktree_path
        if branch_name is not None:
            params["branch_name"] = branch_name
        return self.invoke(METHOD_REGISTER_EXECUTION_INTENT, params)

    def acquire_execution_lease(
        self,
        exec_id: str,
        worker_id: str,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        """Acquire atomic worker lease with monotonic fencing token over Broker IPC."""
        return self.invoke(METHOD_ACQUIRE_EXECUTION_LEASE, {
            "exec_id": exec_id,
            "worker_id": worker_id,
            "ttl_seconds": ttl_seconds,
        })

    def heartbeat_execution(
        self,
        lease_id: str,
        exec_id: str,
        worker_id: str,
        fencing_token: int,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        """Renew heartbeat on active execution lease over Broker IPC."""
        return self.invoke(METHOD_HEARTBEAT_EXECUTION, {
            "lease_id": lease_id,
            "exec_id": exec_id,
            "worker_id": worker_id,
            "fencing_token": fencing_token,
            "ttl_seconds": ttl_seconds,
        })

    def renew_execution_lease(
        self,
        lease_id: str,
        exec_id: str,
        worker_id: str,
        fencing_token: int,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        """Renew execution lease over Broker IPC."""
        return self.invoke(METHOD_RENEW_EXECUTION_LEASE, {
            "lease_id": lease_id,
            "exec_id": exec_id,
            "worker_id": worker_id,
            "fencing_token": fencing_token,
            "ttl_seconds": ttl_seconds,
        })

    def update_execution_state(
        self,
        exec_id: str,
        new_status: str,
        lease_id: str,
        fencing_token: int,
    ) -> dict[str, Any]:
        """Update execution run status under active lease guard over Broker IPC."""
        return self.invoke(METHOD_UPDATE_EXECUTION_STATE, {
            "exec_id": exec_id,
            "new_status": new_status,
            "lease_id": lease_id,
            "fencing_token": fencing_token,
        })

    def register_checkpoint(
        self,
        checkpoint_id: str,
        exec_id: str,
        finding_id: str,
        base_commit: str,
        scope_digest: str = "0" * 64,
        manifest_hash: str = "0" * 64,
        checkpoint_path: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Register checkpoint metadata bound to execution and finding over Broker IPC."""
        return self.invoke(METHOD_REGISTER_CHECKPOINT, {
            "checkpoint_id": checkpoint_id,
            "exec_id": exec_id,
            "finding_id": finding_id,
            "base_commit": base_commit,
            "scope_digest": scope_digest,
            "manifest_hash": manifest_hash,
            "checkpoint_path": checkpoint_path,
        })

    def record_repair_attempt(
        self,
        exec_id: str,
        finding_id: str,
        repair_attempt: int,
        happy_test_passed: int | None = None,
        adversarial_test_passed: int | None = None,
        red_team_passed: int | None = None,
        red_team_notes: str | None = None,
        diff_summary: str | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Record repair attempt enforcing monotonic increase and retry limits over Broker IPC."""
        params: dict[str, Any] = {
            "exec_id": exec_id,
            "finding_id": finding_id,
            "repair_attempt": repair_attempt,
        }
        if happy_test_passed is not None:
            params["happy_test_passed"] = happy_test_passed
        if adversarial_test_passed is not None:
            params["adversarial_test_passed"] = adversarial_test_passed
        if red_team_passed is not None:
            params["red_team_passed"] = red_team_passed
        if red_team_notes is not None:
            params["red_team_notes"] = red_team_notes
        if diff_summary is not None:
            params["diff_summary"] = diff_summary
        if error is not None:
            params["error"] = error
        return self.invoke(METHOD_RECORD_REPAIR_ATTEMPT, params)

    def quarantine_checkpoint(
        self,
        quarantine_id: str,
        project_key: str,
        exec_id: str,
        worktree_path: str,
        reason: str,
        checkpoint_id: str | None = None,
        preserved_diff_path: str | None = None,
    ) -> dict[str, Any]:
        """Record quarantine of worktree/checkpoint over Broker IPC."""
        params: dict[str, Any] = {
            "quarantine_id": quarantine_id,
            "project_key": project_key,
            "exec_id": exec_id,
            "worktree_path": worktree_path,
            "reason": reason,
        }
        if checkpoint_id is not None:
            params["checkpoint_id"] = checkpoint_id
        if preserved_diff_path is not None:
            params["preserved_diff_path"] = preserved_diff_path
        return self.invoke(METHOD_QUARANTINE_CHECKPOINT, params)

    def finalize_execution(
        self,
        exec_id: str,
        status: str,
        integration_test_passed: int,
        lease_id: str,
        fencing_token: int,
    ) -> dict[str, Any]:
        """Finalize execution and release active lease over Broker IPC."""
        return self.invoke(METHOD_FINALIZE_EXECUTION, {
            "exec_id": exec_id,
            "status": status,
            "integration_test_passed": integration_test_passed,
            "lease_id": lease_id,
            "fencing_token": fencing_token,
        })

    def submit_verification(
        self,
        verification_run_id: str,
        project_key: str,
        run_id: str,
        results: list[dict[str, Any]],
        quality_metrics: dict[str, Any] | None = None,
        verifier_conversation_id: str | None = None,
    ) -> dict[str, Any]:
        """Submit verification results and metrics over Broker IPC."""
        params: dict[str, Any] = {
            "verification_run_id": verification_run_id,
            "project_key": project_key,
            "run_id": run_id,
            "results": results,
        }
        if quality_metrics is not None:
            params["quality_metrics"] = quality_metrics
        if verifier_conversation_id is not None:
            params["verifier_conversation_id"] = verifier_conversation_id
        return self.invoke(METHOD_SUBMIT_VERIFICATION, params)

    def finalize_verified_report(
        self,
        verification_run_id: str,
        project_key: str,
        run_id: str,
        verifier_conversation_id: str | None = None,
    ) -> dict[str, Any]:
        """Finalize verified report and transition run to READY_FOR_REVIEW over Broker IPC."""
        params: dict[str, Any] = {
            "verification_run_id": verification_run_id,
            "project_key": project_key,
            "run_id": run_id,
        }
        if verifier_conversation_id is not None:
            params["verifier_conversation_id"] = verifier_conversation_id
        return self.invoke(METHOD_FINALIZE_VERIFIED_REPORT, params)

    def claim_verification_job(self, worker_id: str, ttl_seconds: int = 300) -> dict[str, Any] | None:
        """Claim next pending verification job over Broker IPC."""
        return self.invoke(METHOD_CLAIM_VERIFICATION_JOB, {
            "worker_id": worker_id,
            "ttl_seconds": ttl_seconds,
        })

    def recover_verification_lease(self, project_key: str | None = None) -> dict[str, Any]:
        """Recover expired verification leases over Broker IPC."""
        params: dict[str, Any] = {}
        if project_key is not None:
            params["project_key"] = project_key
        return self.invoke(METHOD_RECOVER_VERIFICATION_LEASE, params)


    def verify_audit_chain(self) -> dict[str, Any]:
        """Verify SHA-256 hash chain of governance audit log over Broker IPC."""
        return self.invoke(METHOD_VERIFY_AUDIT_CHAIN)

    def validate_checkpoint(self, checkpoint_id: str, exec_id: str | None = None) -> dict[str, Any]:
        """Validate content-addressed checkpoint integrity over Broker IPC."""
        params: dict[str, Any] = {"checkpoint_id": checkpoint_id}
        if exec_id is not None:
            params["exec_id"] = exec_id
        return self.invoke(METHOD_VALIDATE_CHECKPOINT, params)

    def restore_checkpoint(self, checkpoint_id: str, exec_id: str, worktree_path: str | Path) -> dict[str, Any]:
        """Restore worktree from checkpoint over Broker IPC."""
        return self.invoke(
            METHOD_RESTORE_CHECKPOINT,
            {
                "checkpoint_id": checkpoint_id,
                "exec_id": exec_id,
                "worktree_path": str(worktree_path),
            },
        )

    def get_execution_state(self, exec_id: str) -> dict[str, Any]:
        """Retrieve consolidated execution run state over Broker IPC."""
        return self.invoke(METHOD_GET_EXECUTION_STATE, {"exec_id": exec_id})

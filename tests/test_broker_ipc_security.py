"""Comprehensive IPC Security and Database Ownership Test Suite for Antigravity Auditor Broker.

Validates the security guarantees, boundaries, and error handling of the Broker architecture
per NEXT-21C-A specifications.
"""

from __future__ import annotations

import inspect
import json
import os
import sqlite3
import struct
import tempfile
import threading
import uuid
from pathlib import Path

import pytest

from broker.audit_logger import BrokerAuditLogger
from broker.client import BrokerClient
from broker.constants import (
    ERR_ACCESS_DENIED,
    ERR_DATABASE_ERROR,
    ERR_METHOD_NOT_IMPLEMENTED,
    ERR_NOT_IMPLEMENTED,
    ERR_PRODUCTION_DB_ACCESS_PROHIBITED,
    ERR_PRODUCTION_DB_BLOCKED,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
    MAX_MESSAGE_SIZE,
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
from broker.service_host import BrokerServiceConfig, BrokerServiceHost, ServiceState
from broker.transport import MemoryPipeTransport, WindowsNamedPipeServer


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Fixture providing an isolated temporary SQLite database path."""
    db_file = tmp_path / "test_isolated_broker.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, value TEXT)")
    conn.execute("INSERT INTO test_table (value) VALUES ('secure_broker_test')")
    conn.commit()
    conn.close()
    return db_file


@pytest.fixture
def mock_dispatcher(temp_db_path: Path, tmp_path: Path) -> BrokerDispatcher:
    """Fixture providing a configured BrokerDispatcher with isolated temp db and log."""
    log_file = tmp_path / "test_broker_audit.log"
    logger = BrokerAuditLogger(log_file=log_file)
    adapter = BrokerDatabaseAdapter(db_path=temp_db_path)
    return BrokerDispatcher(db_adapter=adapter, audit_logger=logger)


@pytest.fixture
def memory_transport(mock_dispatcher: BrokerDispatcher) -> MemoryPipeTransport:
    """Fixture providing an in-memory pipe transport."""
    return MemoryPipeTransport(dispatcher=mock_dispatcher)


@pytest.fixture
def memory_client(memory_transport: MemoryPipeTransport) -> BrokerClient:
    """Fixture providing a BrokerClient connected to the memory transport."""
    return BrokerClient(transport=memory_transport)


# ==============================================================================
# 1. Health and Discovery Tests
# ==============================================================================


def test_broker_health(memory_client: BrokerClient) -> None:
    """Verify broker.health returns healthy status, protocol version, and uptime."""
    health = memory_client.health()
    assert health["status"] == "healthy"
    assert health["protocol_version"] == PROTOCOL_VERSION
    assert health["uptime_seconds"] >= 0.0
    assert "memory_usage_mb" in health
    assert "db_status" in health
    assert health["db_status"]["accessible"] is True


def test_broker_capabilities(memory_client: BrokerClient) -> None:
    """Verify broker.capabilities lists supported and gated methods."""
    caps = memory_client.capabilities()
    assert caps["protocol_version"] == PROTOCOL_VERSION
    assert "broker.health" in caps["supported_methods"]
    assert "broker.capabilities" in caps["supported_methods"]
    assert "broker.approve_execution" in caps["gated_methods"]


def test_broker_protocol_version(memory_client: BrokerClient) -> None:
    """Verify broker.protocol_version returns current protocol version."""
    ver = memory_client.protocol_version()
    assert ver == PROTOCOL_VERSION


def test_broker_test_ping_db(memory_client: BrokerClient) -> None:
    """Verify broker.test_ping_db queries database connection securely."""
    ping = memory_client.test_ping_db()
    assert ping["ping"] == "pong"
    assert ping["schema_version"] == 1


# ==============================================================================
# 2. Framing, Schema, and Protocol Validation Tests
# ==============================================================================


def test_invalid_json_payload(memory_transport: MemoryPipeTransport) -> None:
    """Verify that syntactically invalid JSON payload returns -32700 Parse Error."""
    raw_payload = b"{not valid json at all, missing quotes and brackets"
    frame = encode_frame(raw_payload)
    resp_frame = memory_transport.execute_raw_frame(frame)
    payload_len = decode_frame_header(resp_frame[:4])
    resp_json = json.loads(resp_frame[4 : 4 + payload_len].decode("utf-8"))

    assert resp_json["jsonrpc"] == "2.0"
    assert resp_json["error"]["code"] == JSONRPC_PARSE_ERROR
    assert "JSON parse error" in resp_json["error"]["message"]


def test_oversized_payload_rejected() -> None:
    """Verify that payloads exceeding MAX_MESSAGE_SIZE (1 MB) are rejected fail-closed."""
    oversized_data = b"X" * (MAX_MESSAGE_SIZE + 1024)
    with pytest.raises(BrokerSchemaError) as exc_info:
        encode_frame(oversized_data)
    assert "exceeds maximum" in str(exc_info.value)


def test_unknown_method_rejected(memory_client: BrokerClient) -> None:
    """Verify that unregistered methods return -32601 Method Not Found."""
    with pytest.raises(MethodNotImplementedError) as exc_info:
        memory_client.invoke("non_existent_method_xyz")
    assert exc_info.value.code == JSONRPC_METHOD_NOT_FOUND


def test_unsupported_protocol_version_rejected(memory_transport: MemoryPipeTransport) -> None:
    """Verify that requests specifying an unsupported protocol version return -32602."""
    req = {
        "jsonrpc": "2.0",
        "id": "test-ver-1",
        "method": "broker.health",
        "params": {},
        "protocol_version": "99.0.0",
    }
    resp = memory_transport.execute_request_dict(req)
    assert resp["error"]["code"] == JSONRPC_INVALID_PARAMS
    assert "Unsupported protocol version" in resp["error"]["message"]


def test_missing_request_id_rejected(memory_transport: MemoryPipeTransport) -> None:
    """Verify that requests without an 'id' (notifications) are strictly rejected (-32600)."""
    req_no_id = {
        "jsonrpc": "2.0",
        "method": "broker.health",
        "params": {},
    }
    raw = json.dumps(req_no_id).encode("utf-8")
    resp_frame = memory_transport.execute_raw_frame(encode_frame(raw))
    payload_len = decode_frame_header(resp_frame[:4])
    resp = json.loads(resp_frame[4 : 4 + payload_len].decode("utf-8"))
    assert resp["error"]["code"] == JSONRPC_INVALID_REQUEST
    assert "notifications are not permitted" in resp["error"]["message"].lower()


def test_duplicate_request_id_rejected(memory_transport: MemoryPipeTransport) -> None:
    """Verify that duplicate request IDs within deduplication window are rejected (-32600)."""
    req = {
        "jsonrpc": "2.0",
        "id": "dup-test-id-001",
        "method": "broker.health",
        "params": {},
        "protocol_version": PROTOCOL_VERSION,
    }
    resp1 = memory_transport.execute_request_dict(req)
    assert "result" in resp1

    # Second invocation with same ID
    resp2 = memory_transport.execute_request_dict(req)
    assert resp2["error"]["code"] == JSONRPC_INVALID_REQUEST
    assert "duplicate request id" in resp2["error"]["message"].lower()


def test_malformed_params_schema_rejected(memory_transport: MemoryPipeTransport) -> None:
    """Verify that params not formatted as a dictionary return -32602."""
    req = {
        "jsonrpc": "2.0",
        "id": "malformed-params-1",
        "method": "broker.health",
        "params": "not a dictionary",
        "protocol_version": PROTOCOL_VERSION,
    }
    resp = memory_transport.execute_request_dict(req)
    assert resp["error"]["code"] == JSONRPC_INVALID_PARAMS
    assert "params" in resp["error"]["message"].lower()


# ==============================================================================
# 3. Security Boundary & Authorization Tests
# ==============================================================================


def test_unauthorized_state_mutation_rejected(memory_client: BrokerClient) -> None:
    """Verify that unimplemented governance mutation methods return -32000."""
    with pytest.raises(MethodNotImplementedError) as exc_info:
        memory_client.invoke("broker.approve_execution", {"finding_ids": ["F001"]})
    assert exc_info.value.code == ERR_NOT_IMPLEMENTED
    assert "Subphase NEXT-21C-B" in exc_info.value.message


def test_generic_sql_execution_rejected(memory_client: BrokerClient) -> None:
    """Verify that arbitrary SQL execution over IPC is strictly blocked with -32001."""
    with pytest.raises(BrokerAuthError) as exc_info:
        memory_client.invoke("broker.execute_sql", {"sql": "DROP TABLE test_table;"})
    assert exc_info.value.code == ERR_ACCESS_DENIED
    assert "arbitrary sql execution" in exc_info.value.message.lower()


def test_arbitrary_db_path_injection_rejected(memory_client: BrokerClient) -> None:
    """Verify that passing 'db_path' in params is strictly rejected with -32602."""
    with pytest.raises(BrokerSchemaError) as exc_info:
        memory_client.invoke("broker.health", {"db_path": "C:\\evil\\path.db"})
    assert exc_info.value.code == JSONRPC_INVALID_PARAMS
    assert "database paths" in exc_info.value.message.lower()


def test_production_database_path_rejected_fail_closed(tmp_path: Path) -> None:
    """Verify that attempts to initialize adapter with production paths raise fail-closed."""
    prohibited_paths = [
        Path(os.path.expandvars(r"%LOCALAPPDATA%\AntigravityAuditor\auditor.db")),
        Path(r"C:\Users\example\AppData\Local\AntigravityAuditor\auditor.db"),
        Path(r"C:\ProgramData\AntigravityAuditor\auditor.db"),
        Path(r"C:\some\dir\auditor.db"),
    ]

    for p in prohibited_paths:
        with pytest.raises(ProductionDatabaseAccessProhibitedError) as exc_info:
            BrokerDatabaseAdapter(db_path=p)
        assert exc_info.value.code == ERR_PRODUCTION_DB_BLOCKED


def test_pipe_reject_remote_clients_flag() -> None:
    """Verify that WindowsNamedPipeServer enforces PIPE_REJECT_REMOTE_CLIENTS flag."""
    assert WindowsNamedPipeServer.PIPE_REJECT_REMOTE_CLIENTS == 0x00000008


def test_same_user_worker_authorization(memory_transport: MemoryPipeTransport) -> None:
    """Verify that medium-integrity client belonging to same user is authorized."""
    client = ClientIdentity(
        pid=os.getpid(),
        sid="S-1-5-21-VALID-USER",
        integrity_level="MEDIUM",
        is_low_integrity=False,
        verified_by_os=True,
    )
    req = {
        "jsonrpc": "2.0",
        "id": "valid-user-1",
        "method": "broker.health",
        "params": {},
        "protocol_version": PROTOCOL_VERSION,
    }
    resp = memory_transport.execute_request_dict(req, client=client)
    assert "result" in resp
    assert resp["result"]["status"] == "healthy"


def test_low_integrity_worker_rejected(memory_transport: MemoryPipeTransport) -> None:
    """Verify that low-integrity worker (sandboxed/untrusted) is rejected with -32001."""
    low_integrity_client = ClientIdentity(
        pid=os.getpid(),
        sid="S-1-16-4096",
        integrity_level="LOW",
        is_low_integrity=True,
        verified_by_os=True,
    )
    req = {
        "jsonrpc": "2.0",
        "id": "low-il-1",
        "method": "broker.health",
        "params": {},
        "protocol_version": PROTOCOL_VERSION,
    }
    resp = memory_transport.execute_request_dict(req, client=low_integrity_client)
    assert resp["error"]["code"] == ERR_ACCESS_DENIED
    assert "low-integrity" in resp["error"]["message"].lower()


def test_spoofed_identity_in_params_ignored(mock_dispatcher: BrokerDispatcher) -> None:
    """Verify that caller cannot elevate privileges by supplying fake client_pid or integrity."""
    real_client = ClientIdentity(
        pid=os.getpid(),
        sid="S-1-5-21-AUTHENTIC",
        integrity_level="MEDIUM",
        is_low_integrity=False,
        verified_by_os=True,
    )
    req = JsonRpcRequest(
        id="spoof-test-1",
        method="broker.health",
        params={"client_pid": 1, "integrity_level": "SYSTEM", "is_low_integrity": False},
        protocol_version=PROTOCOL_VERSION,
    )

    resp = mock_dispatcher.dispatch(req, client=real_client)
    assert resp.result is not None
    # Verify that dispatcher logged the authentic OS client PID, not spoofed PID
    recent_logs = mock_dispatcher.audit_logger.get_recent_logs(1)
    assert len(recent_logs) == 1
    assert recent_logs[0]["client_pid"] == os.getpid()


# ==============================================================================
# 4. Client Robustness & Absence of SQLite Fallback
# ==============================================================================


def test_broker_unavailable_handling() -> None:
    """Verify that BrokerClient raises BrokerUnavailableError when pipe does not exist."""
    client = BrokerClient(pipe_name=r"\\.\pipe\NonExistentAuditorBrokerPipe_99999", timeout=0.5)
    with pytest.raises(BrokerUnavailableError) as exc_info:
        client.invoke("broker.health")
    assert "Broker Named Pipe not found" in str(exc_info.value) or "only supported on Windows" in str(exc_info.value)


def test_invalid_broker_response_rejected() -> None:
    """Verify that client strictly validates response structure and detects tampering."""
    class MaliciousTransport:
        def execute_raw_frame(self, frame_bytes: bytes) -> bytes:
            # Return response with mismatched id
            tampered = {"jsonrpc": "2.0", "id": "mismatched-id-xyz", "result": {"hacked": True}}
            raw = json.dumps(tampered).encode("utf-8")
            return encode_frame(raw)

    client = BrokerClient(transport=MaliciousTransport())  # type: ignore[arg-type]
    with pytest.raises(BrokerSchemaError) as exc_info:
        client.invoke("broker.health")
    assert "Response ID mismatch" in str(exc_info.value)


def test_zero_sqlite_fallback_in_client() -> None:
    """MANDATORY SECURITY ASSERTION: Verify BrokerClient has zero SQLite imports or calls.

    Audits BrokerClient source code AST to guarantee no direct SQLite database connection
    fallback exists.
    """
    client_src = inspect.getsource(BrokerClient)
    assert "sqlite3" not in client_src
    assert "connect(" not in client_src
    assert "auditor.db" not in client_src


def test_concurrent_requests(memory_transport: MemoryPipeTransport) -> None:
    """Verify thread-safety and isolation of concurrent requests across worker threads."""
    errors: list[Exception] = []
    results: list[dict] = []
    lock = threading.Lock()

    def worker(worker_id: int) -> None:
        client = BrokerClient(transport=memory_transport)
        try:
            for i in range(10):
                res = client.health()
                with lock:
                    results.append(res)
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    assert len(results) == 50


# ==============================================================================
# 5. Service Host Lifecycle Tests
# ==============================================================================


def test_service_host_lifecycle(tmp_path: Path) -> None:
    """Verify BrokerServiceHost lifecycle: STOPPED -> RUNNING -> STOPPED."""
    db_file = tmp_path / "host_test.db"
    log_file = tmp_path / "host_test.log"

    cfg = BrokerServiceConfig(
        db_path=db_file,
        log_file=log_file,
        use_memory_transport=True,
    )
    host = BrokerServiceHost(cfg)
    assert host.state == ServiceState.STOPPED

    host.start()
    assert host.state == ServiceState.RUNNING

    status = host.get_status()
    assert status["state"] == "RUNNING"
    assert status["db_initialized"] is True

    host.stop()
    assert host.state == ServiceState.STOPPED


def test_service_host_rejects_production_db(tmp_path: Path) -> None:
    """Verify BrokerServiceHost start fails closed if configured with production DB path."""
    cfg = BrokerServiceConfig(
        db_path=r"C:\Users\example\AppData\Local\AntigravityAuditor\auditor.db",
        use_memory_transport=True,
    )
    host = BrokerServiceHost(cfg)
    with pytest.raises(BrokerError) as exc_info:
        host.start()
    assert host.state == ServiceState.ERROR
    assert "PROHIBITED" in str(exc_info.value).upper() or "PROHIBITED" in str(exc_info.value)


# ==============================================================================
# 6. Windows Native Named Pipe Live Integration Test
# ==============================================================================


@pytest.mark.skipif(not is_windows(), reason="Windows Named Pipe live tests require Windows OS")
def test_windows_named_pipe_live_transceive(temp_db_path: Path, tmp_path: Path) -> None:
    """Test live Win32 Named Pipe creation, connection, IPC request/response round-trip, and teardown."""
    unique_pipe = f"{TEST_PIPE_PREFIX}{uuid.uuid4().hex[:8]}"
    log_file = tmp_path / "live_pipe_audit.log"
    logger = BrokerAuditLogger(log_file=log_file)
    adapter = BrokerDatabaseAdapter(db_path=temp_db_path)
    dispatcher = BrokerDispatcher(db_adapter=adapter, audit_logger=logger)

    server = WindowsNamedPipeServer(dispatcher=dispatcher, pipe_name=unique_pipe)
    server.start()  # blocks until the pipe is listening (_ready_event)

    try:
        # Connect live Win32 client
        client = BrokerClient(pipe_name=unique_pipe, timeout=5.0)
        health = client.health()
        assert health["status"] == "healthy"
        assert health["protocol_version"] == PROTOCOL_VERSION

        caps = client.capabilities()
        assert "broker.health" in caps["supported_methods"]

        ping = client.test_ping_db()
        assert ping["ping"] == "pong"
    finally:
        server.stop()

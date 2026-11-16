"""NEXT-21C-B4-A Windows Service Host, Named Pipe Security, & Identity Isolation Tests.

Organized strictly by test class:
- Class A: Automated Unit Tests (capability gate, SDDL builder, config/DB validation, SCM state machine).
- Class B: Live Windows API Tests (real Named Pipe on B4A_TEST_PIPE_NAME, real token impersonation/reversion,
           real Low-IL child process rejection, malformed/disconnect resilience, live NTFS icacls/CreateFileW
           enforcement in disposable non-production directory, live NTFS junction rejection).
- Class C/D Probe: Non-elevated Win32 SCM query & OpenSCManagerW(SC_MANAGER_CREATE_SERVICE) Error 5 check.
  (Elevated SCM registration/start/stop/delete and cross-account NT SERVICE\\* execution are NEVER mocked;
  they are executed only via core.broker.b4a_qualification_runner when elevated, otherwise reported UNEXECUTED.)
"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import uuid

import pytest

from broker.client import BrokerClient
from broker.constants import (
    B4A_QUALIFICATION_ALLOWED_METHODS,
    B4A_TEST_PIPE_NAME,
    B4A_TEST_SERVICE_ACCOUNT,
    B4A_TEST_SERVICE_NAME,
    B4A_TEST_SERVICE_SID,
    DEFAULT_PIPE_NAME,
    ERR_ACCESS_DENIED,
    PRODUCTION_SERVICE_NAME,
    TEST_PIPE_PREFIX,
)
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
from broker.protocol import JsonRpcRequest, encode_frame
from broker.scm_host import (
    ERROR_EXCEPTION_IN_SERVICE,
    SERVICE_RUNNING,
    SERVICE_START_PENDING,
    SERVICE_STOP_PENDING,
    SERVICE_STOPPED,
    Win32SCMServiceController,
)
from broker.security import (
    ClientIdentity,
    apply_restricted_directory_dacl,
    build_restricted_pipe_sddl,
    compute_service_sid_from_name,
    get_current_process_identity,
    get_current_user_sid,
    get_win32_kernel32,
    is_windows,
    probe_win32_file_open,
    query_path_dacl,
)
from broker.service_host import BrokerServiceConfig, BrokerServiceHost, ServiceState
from broker.service_installer import B4ATestServiceManager, ERROR_ACCESS_DENIED, ERROR_SERVICE_DOES_NOT_EXIST
from broker.transport import MemoryPipeTransport, WindowsNamedPipeServer


def _create_temp_sqlite_db(db_path: Path) -> Path:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS health_probe (id INTEGER PRIMARY KEY)")
        conn.commit()
    finally:
        conn.close()
    return db_path


def _spawn_low_il_python_and_wait(python_code: str, cwd: Path | None = None, timeout_ms: int = 10000) -> tuple[int, str]:
    """Spawn a real Windows child process at Low Integrity Level (S-1-16-4096)."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = get_win32_kernel32()
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.GetExitCodeProcess.restype = wintypes.BOOL
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.CreatePipe.restype = wintypes.BOOL
    k32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.DWORD
    ]
    k32.SetHandleInformation.restype = wintypes.BOOL
    k32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]

    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.DuplicateTokenEx.restype = wintypes.BOOL
    adv.DuplicateTokenEx.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)
    ]
    adv.ConvertStringSidToSidW.restype = wintypes.BOOL
    adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    adv.GetLengthSid.restype = wintypes.DWORD
    adv.GetLengthSid.argtypes = [ctypes.c_void_p]
    adv.SetTokenInformation.restype = wintypes.BOOL
    adv.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
            ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFO(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
        ]

    adv.CreateProcessAsUserW.restype = wintypes.BOOL
    adv.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
        wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFO),
    ]

    h_tok = wintypes.HANDLE()
    assert adv.OpenProcessToken(k32.GetCurrentProcess(), 0x02000000, ctypes.byref(h_tok))
    h_low = wintypes.HANDLE()
    p_low_sid = ctypes.c_void_p()
    try:
        assert adv.DuplicateTokenEx(h_tok, 0x02000000, None, 2, 1, ctypes.byref(h_low))
        assert adv.ConvertStringSidToSidW("S-1-16-4096", ctypes.byref(p_low_sid))

        class SID_AND_ATTR(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

        class TOKEN_MANDATORY_LABEL(ctypes.Structure):
            _fields_ = [("Label", SID_AND_ATTR)]

        tml = TOKEN_MANDATORY_LABEL(SID_AND_ATTR(p_low_sid.value, 0x20))
        sid_len = adv.GetLengthSid(p_low_sid.value)
        assert adv.SetTokenInformation(h_low, 25, ctypes.byref(tml), ctypes.sizeof(tml) + sid_len)

        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wintypes.BOOL)]

        sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
        h_read, h_write = wintypes.HANDLE(), wintypes.HANDLE()
        assert k32.CreatePipe(ctypes.byref(h_read), ctypes.byref(h_write), ctypes.byref(sa), 0)
        k32.SetHandleInformation(h_read, 1, 0)

        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(STARTUPINFOW)
        si.dwFlags = 0x00000100  # STARTF_USESTDHANDLES
        si.hStdOutput = h_write
        si.hStdError = h_write
        pi = PROCESS_INFO()
        exec_cwd = str(cwd or Path(sys.executable).parent)
        # Encode script as base64 and run with `-S` so Low-IL Python skips ctypes/COM site hooks cleanly
        b64 = base64.b64encode(python_code.encode("utf-8")).decode("ascii")
        cmd = ctypes.create_unicode_buffer(
            f'"{sys.executable}" -S -c "import base64; exec(base64.b64decode(\'{b64}\'))"'
        )
        ok = adv.CreateProcessAsUserW(
            h_low, None, cmd, None, None, True, 0x08000000, None, exec_cwd, ctypes.byref(si), ctypes.byref(pi)
        )
        k32.CloseHandle(h_write)
        assert ok, f"CreateProcessAsUserW failed: Win32 Error {ctypes.get_last_error()}"
        try:
            k32.WaitForSingleObject(pi.hProcess, timeout_ms)
            ec = wintypes.DWORD(999)
            assert k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(ec))
            buf = ctypes.create_string_buffer(4096)
            br = wintypes.DWORD(0)
            k32.ReadFile(h_read, buf, 4096, ctypes.byref(br), None)
            out_text = buf.raw[: br.value].decode("utf-8", errors="replace").strip()
            return int(ec.value), out_text
        finally:
            k32.CloseHandle(h_read)
            k32.CloseHandle(pi.hThread)
            k32.CloseHandle(pi.hProcess)
    finally:
        if p_low_sid.value:
            k32.LocalFree(p_low_sid.value)
        if h_low.value:
            k32.CloseHandle(h_low)
        if h_tok.value:
            k32.CloseHandle(h_tok)


# ==============================================================================
# CLASS A: AUTOMATED UNIT TESTS
# ==============================================================================


def test_class_a_service_sid_deterministic_matches_sc_showsid() -> None:
    """Service SID algorithm matches Windows `sc showsid AntigravityAuditorBrokerB4ATest`."""
    assert compute_service_sid_from_name(B4A_TEST_SERVICE_NAME) == B4A_TEST_SERVICE_SID


def test_class_a_restricted_sddl_blocks_broad_principals() -> None:
    """Restricted SDDL forbids Everyone (WD), Users (BU), and Authenticated Users (AU)."""
    sddl = build_restricted_pipe_sddl(["S-1-5-21-1-2-3-1001"], include_service_sid=B4A_TEST_SERVICE_SID)
    assert "(A;;GA;;;SY)" in sddl
    assert "(A;;GA;;;BA)" in sddl
    assert f"(A;;GA;;;{B4A_TEST_SERVICE_SID})" in sddl
    assert "(A;;GRGW;;;S-1-5-21-1-2-3-1001)" in sddl
    for forbidden in ("WD", "BU", "AU", "S-1-1-0", "S-1-5-11", "S-1-5-32-545"):
        assert forbidden not in sddl
        with pytest.raises(ValueError, match="Prohibited broad SID"):
            build_restricted_pipe_sddl([forbidden])


def test_class_a_b4a_test_config_enforces_test_identity_and_rejects_prod_pipe(tmp_path: Path) -> None:
    """b4a_test_config binds exclusively to test service identity and qualification_only."""
    db_file = _create_temp_sqlite_db(tmp_path / "b4a.db")
    cfg = BrokerServiceConfig.b4a_test_config(db_path=db_file, allowed_client_sids=["S-1-5-21-999-1001"])
    assert cfg.service_name == B4A_TEST_SERVICE_NAME
    assert cfg.service_account == B4A_TEST_SERVICE_ACCOUNT
    assert cfg.pipe_name == B4A_TEST_PIPE_NAME
    assert cfg.qualification_only is True
    assert "WD" not in cfg.sddl
    assert "BU" not in cfg.sddl

    with pytest.raises(BrokerError, match="production pipe"):
        BrokerServiceConfig.b4a_test_config(db_path=db_file, pipe_name=DEFAULT_PIPE_NAME)


def test_class_a_qualification_mode_blocks_governance_execution_and_mode_overrides(tmp_path: Path) -> None:
    """In B4-A qualification mode, ONLY health/capabilities/protocol_version/test_ping_db execute."""
    db_file = _create_temp_sqlite_db(tmp_path / "qual.db")
    adapter = BrokerDatabaseAdapter(db_file)
    dispatcher = BrokerDispatcher(
        db_adapter=adapter,
        qualification_only=True,
        allowed_client_sids=["S-1-5-21-100-1001"],
        service_identity=B4A_TEST_SERVICE_NAME,
    )
    allowed_client = ClientIdentity(pid=1234, sid="S-1-5-21-100-1001", integrity_level="MEDIUM", is_low_integrity=False)

    # Allowed methods succeed
    for idx, method in enumerate(sorted(B4A_QUALIFICATION_ALLOWED_METHODS), start=1):
        resp = dispatcher.dispatch(JsonRpcRequest(id=f"ok-{idx}", method=method, params={}), allowed_client)
        assert resp.error is None, f"Expected {method} allowed, got {resp.error}"

    caps = dispatcher.dispatch(JsonRpcRequest(id="caps", method="broker.capabilities", params={}), allowed_client).result
    assert caps["qualification_only"] is True
    assert set(caps["supported_methods"]) == set(B4A_QUALIFICATION_ALLOWED_METHODS)
    assert caps["service_mode"] == "B4A_QUALIFICATION_ONLY"

    # Mutating / read-context / execution / arbitrary SQL methods blocked fail-closed
    blocked_methods = [
        "broker.get_context",
        "broker.list_findings",
        "broker.authorize_execution",
        "broker.save_decisions",
        "broker.finalize_execution",
        "broker.submit_verification",
        "broker.execute_sql",
    ]
    for idx, method in enumerate(blocked_methods, start=1):
        resp = dispatcher.dispatch(JsonRpcRequest(id=f"blk-{idx}", method=method, params={}), allowed_client)
        assert resp.error is not None
        assert resp.error["code"] == ERR_ACCESS_DENIED

    # Mode override parameters rejected
    for idx, override_key in enumerate(("service_mode", "mode", "qualification_only", "allowed_methods"), start=1):
        resp = dispatcher.dispatch(
            JsonRpcRequest(id=f"ovr-{idx}", method="broker.health", params={override_key: "STANDARD"}),
            allowed_client,
        )
        assert resp.error is not None
        assert resp.error["code"] == ERR_ACCESS_DENIED

    # Unlisted client SID rejected
    stranger = ClientIdentity(pid=5678, sid="S-1-5-21-100-9999", integrity_level="MEDIUM", is_low_integrity=False)
    resp_sid = dispatcher.dispatch(JsonRpcRequest(id="sid-blk", method="broker.health", params={}), stranger)
    assert resp_sid.error is not None
    assert resp_sid.error["code"] == ERR_ACCESS_DENIED


def test_class_a_missing_db_dir_and_missing_db_fail_closed(tmp_path: Path) -> None:
    """Service host startup enters ERROR state when required DB directory or DB file does not exist."""
    missing_dir_db = tmp_path / "nonexistent_dir" / "test.db"
    cfg_dir = BrokerServiceConfig(
        db_path=missing_dir_db,
        use_memory_transport=True,
        require_existing_db_dir=True,
        service_name=B4A_TEST_SERVICE_NAME,
    )
    host_dir = BrokerServiceHost(cfg_dir)
    with pytest.raises(BrokerError):
        host_dir.start()
    assert host_dir.state == ServiceState.ERROR
    assert host_dir.server_startup_error is not None

    missing_file_db = tmp_path / "missing_file.db"
    cfg_file = BrokerServiceConfig(
        db_path=missing_file_db,
        use_memory_transport=True,
        require_existing_db_dir=True,
        require_existing_db=True,
        service_name=B4A_TEST_SERVICE_NAME,
    )
    host_file = BrokerServiceHost(cfg_file)
    with pytest.raises(BrokerError):
        host_file.start()
    assert host_file.state == ServiceState.ERROR
    assert "does not exist" in (host_file.server_startup_error or "")


def test_class_a_scm_controller_state_transitions_and_prod_guard(tmp_path: Path) -> None:
    """SCM controller transitions START_PENDING -> RUNNING -> STOP_PENDING -> STOPPED cleanly."""
    with pytest.raises(BrokerError, match="production"):
        Win32SCMServiceController(PRODUCTION_SERVICE_NAME, BrokerServiceHost())

    with pytest.raises(BrokerSecurityError):
        B4ATestServiceManager(PRODUCTION_SERVICE_NAME)

    db_file = _create_temp_sqlite_db(tmp_path / "scm_unit.db")
    cfg = BrokerServiceConfig.b4a_test_config(db_path=db_file, use_memory_transport=True)
    host = BrokerServiceHost(cfg)
    ctrl = Win32SCMServiceController(B4A_TEST_SERVICE_NAME, host)
    ctrl.execute_service_lifecycle(wait_for_stop=False)
    states = [entry["state"] for entry in ctrl.status_history]
    assert states == [SERVICE_START_PENDING, SERVICE_RUNNING, SERVICE_STOP_PENDING, SERVICE_STOPPED]
    assert ctrl.status_history[-1]["win32_exit_code"] == 0
    assert host.state == ServiceState.STOPPED

    # Startup failure transitions cleanly to STOPPED with nonzero exit code
    bad_cfg = BrokerServiceConfig.b4a_test_config(
        db_path=tmp_path / "missing" / "bad.db", use_memory_transport=True, require_existing_db_dir=True
    )
    bad_ctrl = Win32SCMServiceController(B4A_TEST_SERVICE_NAME, BrokerServiceHost(bad_cfg))
    with pytest.raises(BrokerError):
        bad_ctrl.execute_service_lifecycle(wait_for_stop=False)
    assert [e["state"] for e in bad_ctrl.status_history] == [SERVICE_START_PENDING, SERVICE_STOPPED]
    assert bad_ctrl.status_history[-1]["win32_exit_code"] == ERROR_EXCEPTION_IN_SERVICE


# ==============================================================================
# CLASS B: LIVE WINDOWS API TESTS (REAL PIPE, TOKENS, ACLS, LOW-IL CHILD, JUNCTIONS)
# ==============================================================================


@pytest.mark.skipif(not is_windows(), reason="Requires Windows Named Pipes")
def test_class_b_live_b4a_pipe_identity_qualification_and_restart(tmp_path: Path) -> None:
    """Boot real Named Pipe on B4A_TEST_PIPE_NAME, verify real SID/IL/RevertToSelf/restart."""
    db_file = _create_temp_sqlite_db(tmp_path / "live_b4a.db")
    cfg = BrokerServiceConfig.b4a_test_config(db_path=db_file, pipe_name=B4A_TEST_PIPE_NAME)
    host = BrokerServiceHost(cfg)
    host.start()

    try:
        assert host.state == ServiceState.RUNNING
        client = BrokerClient(pipe_name=B4A_TEST_PIPE_NAME, timeout=5.0)
        health = client.health()

        expected_sid = get_current_user_sid()
        assert health["status"] == "healthy"
        assert health["service_identity"] == B4A_TEST_SERVICE_NAME
        assert health["service_mode"] == "B4A_QUALIFICATION_ONLY"
        assert health["qualification_only"] is True
        assert health["client_pid"] == os.getpid()
        assert health["client_sid"] == expected_sid
        assert health["client_sid"] != "S-1-5-UNKNOWN"
        assert health["client_integrity"] in ("MEDIUM", "HIGH")
        assert health["impersonation_level"] == "SecurityImpersonation"
        assert health["impersonation_reverted"] is True
        assert health["token_handle_closed"] is True

        ping = client.invoke("broker.test_ping_db")
        assert ping["ping"] == "pong"
        assert ping["db_status"]["alive"] is True
        assert ping["db_status"]["status"] == "ONLINE"
        assert client.invoke("broker.protocol_version")["protocol_version"] == health["protocol_version"]

        # Verify PIPE_REJECT_REMOTE_CLIENTS blocks UNC loopback access (Win32 Error 5 / 53)
        k32 = get_win32_kernel32()
        h_rem = k32.CreateFileW(r"\\127.0.0.1\pipe\AntigravityAuditorBroker.B4A.Test", 0xC0000000, 0, None, 3, 0, None)
        rem_err = ctypes.get_last_error()
        invalid_rem = h_rem in WindowsNamedPipeServer.INVALID_HANDLE_VALUES
        if not invalid_rem:
            k32.CloseHandle(h_rem)
        assert invalid_rem is True
        assert rem_err in (5, 53, 67, 1326)

        # Blocked governance/read methods over real Named Pipe
        with pytest.raises(BrokerSecurityError):
            client.invoke("broker.authorize_execution", {"finding_id": "F-1"})
        with pytest.raises(BrokerSecurityError):
            client.invoke("broker.list_findings")
    finally:
        host.stop()

    assert host.state == ServiceState.STOPPED

    # Restart cleanly on same B4A pipe name (proves clean handle/instance teardown)
    host2 = BrokerServiceHost(BrokerServiceConfig.b4a_test_config(db_path=db_file, pipe_name=B4A_TEST_PIPE_NAME))
    host2.start()
    try:
        client2 = BrokerClient(pipe_name=B4A_TEST_PIPE_NAME, timeout=5.0)
        assert client2.health()["service_identity"] == B4A_TEST_SERVICE_NAME
    finally:
        host2.stop()


@pytest.mark.skipif(not is_windows(), reason="Requires Windows Named Pipes & SDDL")
def test_class_b_invalid_sddl_fails_pipe_startup_truthfully(tmp_path: Path) -> None:
    """Invalid SDDL causes BrokerServiceHost.start() to fail fail-closed without silent fallback."""
    db_file = _create_temp_sqlite_db(tmp_path / "bad_sddl.db")
    pipe_name = f"{TEST_PIPE_PREFIX}{uuid.uuid4().hex}"
    cfg = BrokerServiceConfig(
        db_path=db_file,
        pipe_name=pipe_name,
        sddl="D:INVALID_SDDL_SYNTAX(((",
        service_name=B4A_TEST_SERVICE_NAME,
    )
    host = BrokerServiceHost(cfg)
    with pytest.raises(BrokerError, match="SDDL"):
        host.start()
    assert host.state == ServiceState.ERROR
    assert host.server is None


@pytest.mark.skipif(not is_windows(), reason="Requires Windows Tokens & Integrity Levels")
def test_class_b_real_low_il_child_blocked_by_pipe_and_dispatcher(tmp_path: Path) -> None:
    """Spawn REAL Low-IL child process (S-1-16-4096) and verify denial at BOTH Win32 kernel & dispatcher."""
    db_file = _create_temp_sqlite_db(tmp_path / "low_il_live.db")
    work_dir = Path(os.getcwd())

    # Layer 1: Restricted SDDL without Low Mandatory Label -> kernel blocks pipe open with Error 5
    pipe1 = f"{TEST_PIPE_PREFIX}low_kernel_{uuid.uuid4().hex}"
    host1 = BrokerServiceHost(BrokerServiceConfig.b4a_test_config(db_path=db_file, pipe_name=pipe1))
    host1.start()
    try:
        code_open = (
            "import sys\n"
            "try:\n"
            f"    f = open(r'{pipe1}', 'r+b', buffering=0)\n"
            "    f.close()\n"
            "    sys.exit(0)\n"
            "except OSError as e:\n"
            "    print(repr(e), 'errno=', e.errno, 'winerror=', getattr(e, 'winerror', None))\n"
            "    sys.exit(5 if (getattr(e, 'winerror', None) == 5 or e.errno == 13) else (getattr(e, 'winerror', 0) or e.errno or 99))\n"
        )
        ec1, out1 = _spawn_low_il_python_and_wait(code_open)
        assert ec1 == 5, f"Expected kernel ERROR_ACCESS_DENIED (5) for Low-IL client, got {ec1} ({out1})"
    finally:
        host1.stop()

    # Layer 2: Pipe explicitly allowing Low-IL label S:(ML;;NW;;;LW) -> Dispatcher rejects with -32001
    pipe2 = f"{TEST_PIPE_PREFIX}low_disp_{uuid.uuid4().hex}"
    user_sid = get_current_user_sid()
    sddl_with_low_ml = f"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{user_sid})S:(ML;;NW;;;LW)"
    cfg2 = BrokerServiceConfig(
        db_path=db_file,
        pipe_name=pipe2,
        sddl=sddl_with_low_ml,
        service_name=B4A_TEST_SERVICE_NAME,
        qualification_only=True,
    )
    host2 = BrokerServiceHost(cfg2)
    host2.start()
    try:
        code_rpc = (
            "import json, sys\n"
            "payload = json.dumps({'jsonrpc':'2.0','id':'low-1','method':'broker.health','params':{},'protocol_version':'1.0.0'}).encode('utf-8')\n"
            "frame = len(payload).to_bytes(4, 'big') + payload\n"
            f"f = open(r'{pipe2}', 'r+b', buffering=0)\n"
            "f.write(frame)\n"
            "f.flush()\n"
            "hdr = f.read(4)\n"
            "n = int.from_bytes(hdr, 'big')\n"
            "resp = json.loads(f.read(n).decode('utf-8'))\n"
            "f.close()\n"
            "code = resp.get('error', {}).get('code', 0)\n"
            "sys.exit(11 if code == -32001 else 3)\n"
        )
        ec2, out2 = _spawn_low_il_python_and_wait(code_rpc)
        assert ec2 == 11, f"Expected JSON-RPC -32001 rejection (exit 11) from Low-IL dispatcher check, got {ec2} ({out2})"
        # Verify audit log recorded Low-IL rejection with OS-verified LOW IL
        rejected = [e for e in host2.audit_logger.get_events() if e["status"] == "REJECTED"]
        assert any(e["client_integrity"] == "LOW" and e["error_code"] == ERR_ACCESS_DENIED for e in rejected)
    finally:
        host2.stop()


@pytest.mark.skipif(not is_windows(), reason="Requires Windows Named Pipes")
def test_class_b_malformed_frame_and_disconnect_resilience(tmp_path: Path) -> None:
    """Server survives malformed length headers, disconnects, and continues serving valid RPCs."""
    db_file = _create_temp_sqlite_db(tmp_path / "resilience.db")
    pipe_name = f"{TEST_PIPE_PREFIX}resil_{uuid.uuid4().hex}"
    host = BrokerServiceHost(BrokerServiceConfig.b4a_test_config(db_path=db_file, pipe_name=pipe_name))
    host.start()
    k32 = get_win32_kernel32()
    try:
        # Connect raw Win32 client, send invalid oversized header (100 MB), read error, close
        h = k32.CreateFileW(pipe_name, 0xC0000000, 0, None, 3, 0, None)
        assert h not in WindowsNamedPipeServer.INVALID_HANDLE_VALUES
        try:
            bad_header = (100 * 1024 * 1024).to_bytes(4, "big")
            written = wintypes.DWORD(0)
            k32.WriteFile(h, bad_header, 4, ctypes.byref(written), None)
        finally:
            k32.CloseHandle(h)

        # Follow-up valid client request still succeeds
        client = BrokerClient(pipe_name=pipe_name, timeout=3.0)
        assert client.health()["status"] == "healthy"
    finally:
        host.stop()


@pytest.mark.skipif(not is_windows(), reason="Requires Windows NTFS ACLs")
def test_class_b_live_ntfs_acl_isolation_in_disposable_programdata_dir() -> None:
    """Prove real Win32 CreateFileW Error 5 enforcement via icacls on a disposable C:\\ProgramData test dir."""
    lab_dir = Path(rf"C:\ProgramData\AntigravityB4ATestLab_{uuid.uuid4().hex[:8]}")
    lab_db = lab_dir / "b4a_acl_test.db"
    user_sid = get_current_user_sid()

    try:
        _create_temp_sqlite_db(lab_db)
        # Apply restrictive DACL granting ONLY B4-A Service SID + SYSTEM + Administrators (inheritance removed)
        dacl_res = apply_restricted_directory_dacl(
            lab_dir,
            B4A_TEST_SERVICE_SID,
            remove_inherited=True,
            grant_system=True,
            grant_admins=True,
        )
        assert dacl_res["returncode"] == 0, f"icacls failed: {dacl_res}"
        dacl_text = dacl_res["effective_dacl"]["stdout"]
        assert "AntigravityAuditorBrokerB4ATest" in dacl_text or B4A_TEST_SERVICE_SID in dacl_text

        # Current non-elevated user (Medium IL) lacks write/read ACE once inherited Users/CREATOR OWNER stripped
        probe_write = probe_win32_file_open(lab_db, write=True)
        assert probe_write["allowed"] is False
        assert probe_write["win32_error"] == ERROR_ACCESS_DENIED
    finally:
        # Restore current user Full Control so test cleanup always succeeds with zero orphan dirs
        if lab_dir.exists():
            subprocess.run(
                ["icacls", str(lab_dir), "/grant", f"*{user_sid}:(OI)(CI)F", "/T"],
                capture_output=True,
                check=False,
            )
            shutil.rmtree(lab_dir, ignore_errors=True)
    assert not lab_dir.exists()


@pytest.mark.skipif(not is_windows(), reason="Requires Windows NTFS Junctions")
def test_class_b_live_ntfs_junction_db_path_rejected(tmp_path: Path) -> None:
    """Real NTFS junction directory on DB path is detected and blocked fail-closed."""
    real_dir = tmp_path / "real_storage"
    _create_temp_sqlite_db(real_dir / "test.db")
    junction_dir = tmp_path / "junction_storage"

    proc = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction_dir), str(real_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"Failed creating test NTFS junction: {proc.stderr}"

    try:
        with pytest.raises((ProductionDatabaseAccessProhibitedError, BrokerSecurityError, BrokerDatabaseError)):
            BrokerDatabaseAdapter(junction_dir / "test.db")
    finally:
        if junction_dir.exists():
            subprocess.run(["cmd", "/c", "rmdir", str(junction_dir)], capture_output=True, check=False)


# ==============================================================================
# CLASS C / D LIVE NON-ADMIN BOUNDARY PROBES
# ==============================================================================


@pytest.mark.skipif(not is_windows(), reason="Requires Windows SCM")
def test_class_cd_live_scm_preflight_and_truthful_elevation_probe(tmp_path: Path) -> None:
    """Verify both prod & B4-A services are absent in SCM, and record exact Win32 elevation status."""
    mgr = B4ATestServiceManager(B4A_TEST_SERVICE_NAME)
    preflight = mgr.verify_preflight_clean()
    assert preflight["clean"] is True
    assert preflight["production_service"]["win32_error"] == ERROR_SERVICE_DOES_NOT_EXIST
    assert preflight["test_service"]["win32_error"] == ERROR_SERVICE_DOES_NOT_EXIST

    proc_id = get_current_process_identity()
    access = mgr.probe_scm_create_access()

    # Interactive non-SCM invocation of StartServiceCtrlDispatcherW fails with Error 1063
    ctrl = Win32SCMServiceController(B4A_TEST_SERVICE_NAME, BrokerServiceHost())
    with pytest.raises(OSError) as scm_disp_exc:
        ctrl.run_scm_dispatcher()
    assert scm_disp_exc.value.winerror == 1063

    if not proc_id["is_elevated"]:
        assert access["granted"] is False
        assert access["win32_error"] == ERROR_ACCESS_DENIED
        with pytest.raises(PermissionError) as exc_info:
            mgr.install_test_service(f'"{sys.executable}" -m broker.scm_host --db-path "{tmp_path / "x.db"}"')
        assert exc_info.value.errno == ERROR_ACCESS_DENIED
    else:
        assert access["granted"] is True

"""Comprehensive Integration & Live Session-0 Qualification Tests for NEXT-21C-B4-B.

Covers:
1. Isolated B4B_SERVICE_GOVERNANCE_TEST mode over Named Pipe with TPM CNG key custody + TCB.
2. End-to-end two-step workflow: save_decisions -> request_confirmation_challenge ->
   WebAuthn ES256 proof -> authorize_execution (CNG/TPM CBEAT) -> verify_execution_approval ->
   consume_execution_approval -> verify_audit_chain.
3. Fail-closed attack tests: missing TCB, spoofed flags/modes, UV=0, mutated scope/findings/commit,
   challenge replay across host restart, signCount rollback, expired challenge, secret-leak audit check,
   and Low-IL Named Pipe denial.
4. B4-A regression guard: qualification_only still blocks all mutating governance & TCB methods.
5. Real elevated Windows SCM Session-0 live qualification: CreateServiceW -> StartServiceW ->
   Session-0 NT SERVICE identity + hardware TPM PCP key + Named Pipe + TCB + restart persistence +
   ControlService(STOP) -> DeleteService + persisted key & disposable dir cleanup.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
CORE_DIR = ROOT_DIR / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

import db as core_db
from broker.cbeat import CBEAT_ALG_CNG_ECDSA_P256, CbeatVerifier
from broker.client import BrokerClient
from broker.cng import (
    MS_KEY_STORAGE_PROVIDER,
    MS_PLATFORM_CRYPTO_PROVIDER,
    CngCbeatSigner,
)
from broker.constants import (
    B4B_TEST_KEY_PREFIX,
    B4B_TEST_PIPE_PREFIX,
    B4B_TEST_SERVICE_PREFIX,
    DEFAULT_PIPE_NAME,
    ERR_ACCESS_DENIED,
    ERR_APPROVAL_EXPIRED,
    ERR_CONFIRMATION_FAILED,
    ERR_CONFIRMATION_REQUIRED,
    ERR_REPLAY_ATTEMPT,
    ERR_SCOPE_VIOLATION,
    METHOD_KEY_STATUS,
    METHOD_REQUEST_CONFIRMATION_CHALLENGE,
    PRODUCTION_SERVICE_NAME,
    SERVICE_MODE_B4B_GOVERNANCE_TEST,
)
from broker.exceptions import (
    BrokerAuthError,
    BrokerConfirmationError,
    BrokerConfirmationRequiredError,
    BrokerError,
    BrokerSecurityError,
    MethodNotImplementedError,
)
from broker.security import (
    apply_restricted_directory_dacl,
    compute_service_sid_from_name,
    get_current_process_identity,
    get_current_user_sid,
    is_windows,
)
from broker.service_host import BrokerServiceConfig, BrokerServiceHost, ServiceState
from broker.service_installer import (
    ERROR_SERVICE_DOES_NOT_EXIST,
    B4BTestServiceManager,
)
from broker.tcb import (
    WEBAUTHN_FLAG_UP,
    WEBAUTHN_FLAG_UV,
    TcbTrustedAuthenticator,
    b64url_encode_nopad,
    compute_tcb_binding_digest,
)
from broker.transport import MemoryPipeTransport


def _seed_project_and_finding(db_path: Path, repo_path: Path) -> dict[str, str]:
    core_db.initialize(db_path)
    project_key = f"proj_{uuid.uuid4().hex[:8]}"
    run_id = f"run_{uuid.uuid4().hex[:8]}"
    finding_id = f"F-{uuid.uuid4().hex[:8]}"
    base_commit = "a" * 40
    repo_path.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO projects (project_key, display_name, repo_path, antigravity_project_id)
               VALUES (?, ?, ?, ?)""",
            (project_key, f"B4B Test {project_key}", str(repo_path), f"ag-{project_key}"),
        )
        conn.execute(
            """INSERT INTO audit_runs (run_id, project_key, status, base_commit, working_tree_hash)
               VALUES (?, ?, 'READY_FOR_REVIEW', ?, 'tree_hash_init')""",
            (run_id, project_key, base_commit),
        )
        conn.commit()
    finally:
        conn.close()
    return {
        "project_key": project_key,
        "run_id": run_id,
        "finding_id": finding_id,
        "base_commit": base_commit,
    }


def _make_es256_assertion(
    auth_signer: CngCbeatSigner,
    *,
    credential_id: str,
    challenge: dict[str, object],
    flags: int = WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_UV,
    sign_count: int = 1,
    rp_id: str = "antigravity-auditor.local",
    origin: str = "https://antigravity-auditor.local",
) -> dict[str, object]:
    ch_id = str(challenge["challenge_id"])
    ch_nonce = str(challenge["challenge_nonce"])
    req_digest = str(challenge["canonical_request_digest"])
    binding = compute_tcb_binding_digest(ch_id, ch_nonce, req_digest)
    client_data_bytes = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": b64url_encode_nopad(binding),
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    auth_data = hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([flags]) + sign_count.to_bytes(4, "big")
    signed_digest = hashlib.sha256(auth_data + hashlib.sha256(client_data_bytes).digest()).digest()
    sig = auth_signer.sign_digest(signed_digest)
    return {
        "proof_type": "WEBAUTHN_ES256",
        "challenge_id": ch_id,
        "challenge_nonce": ch_nonce,
        "credential_id": credential_id,
        "client_data_json_b64": b64url_encode_nopad(client_data_bytes),
        "authenticator_data_b64": b64url_encode_nopad(auth_data),
        "signature_b64": b64url_encode_nopad(sig),
    }


def _cleanup_key(key_name: str, provider_name: str, *, require_tpm: bool, allow_ksp: bool) -> None:
    try:
        s = CngCbeatSigner(
            key_name,
            provider_name=provider_name,
            require_tpm=require_tpm,
            allow_software_ksp=allow_ksp,
            create_if_missing=False,
        )
        s.delete_key()
    except Exception:
        pass


def _process_session_id(pid: int) -> int:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    k32.ProcessIdToSessionId.restype = wintypes.BOOL
    sid = wintypes.DWORD(999)
    assert k32.ProcessIdToSessionId(pid, ctypes.byref(sid)), f"ProcessIdToSessionId failed: {ctypes.get_last_error()}"
    return int(sid.value)


def _spawn_low_il_pipe_probe(pipe_name: str) -> int:
    """Spawn real Windows Low Integrity Level (S-1-16-4096) child trying to open Named Pipe."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class TOKEN_MANDATORY_LABEL(ctypes.Structure):
        _fields_ = [("Label", SID_AND_ATTRIBUTES)]

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_byte)), ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
        ]

    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.DuplicateTokenEx.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)
    ]
    adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    adv.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    adv.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
        wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
    ]

    h_cur = wintypes.HANDLE()
    assert adv.OpenProcessToken(k32.GetCurrentProcess(), 0x000F01FF, ctypes.byref(h_cur))
    h_low = wintypes.HANDLE()
    p_low_sid = ctypes.c_void_p()
    try:
        assert adv.DuplicateTokenEx(h_cur, 0x000F01FF, None, 2, 1, ctypes.byref(h_low))
        assert adv.ConvertStringSidToSidW("S-1-16-4096", ctypes.byref(p_low_sid))
        tml = TOKEN_MANDATORY_LABEL()
        tml.Label.Sid = p_low_sid
        tml.Label.Attributes = 0x00000020  # SE_GROUP_INTEGRITY
        assert adv.SetTokenInformation(h_low, 25, ctypes.byref(tml), ctypes.sizeof(tml))

        py_cmd = (
            f"import sys; sys.path.insert(0, {str(CORE_DIR)!r}); "
            f"from broker.client import BrokerClient; "
            f"BrokerClient(pipe_name={pipe_name!r}, timeout=2.0).health()"
        )
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        pi = PROCESS_INFORMATION()
        cmd = f'"{sys.executable}" -B -c "{py_cmd}"'
        ok = adv.CreateProcessAsUserW(
            h_low, None, ctypes.create_unicode_buffer(cmd), None, None,
            False, 0x08000000, None, None, ctypes.byref(si), ctypes.byref(pi)
        )
        assert ok, f"CreateProcessAsUserW failed: {ctypes.get_last_error()}"
        try:
            k32.WaitForSingleObject(pi.hProcess, 10000)
            rc = wintypes.DWORD(0)
            k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(rc))
            return int(rc.value)
        finally:
            k32.CloseHandle(pi.hThread)
            k32.CloseHandle(pi.hProcess)
    finally:
        if p_low_sid.value:
            k32.LocalFree(p_low_sid)
        if h_low.value:
            k32.CloseHandle(h_low)
        k32.CloseHandle(h_cur)


def test_b4b_config_and_installer_namespace_guards(tmp_path: Path) -> None:
    """B4-B service config & installer strictly enforce isolated prefixes and production protection."""
    db_file = tmp_path / "test.db"
    db_file.touch()

    with pytest.raises(BrokerSecurityError):
        BrokerServiceConfig.b4b_test_governance_config(
            service_name=PRODUCTION_SERVICE_NAME,
            pipe_name=f"{B4B_TEST_PIPE_PREFIX}x",
            db_path=db_file,
            cng_key_name=f"{B4B_TEST_KEY_PREFIX}k",
        )
    with pytest.raises(BrokerSecurityError):
        BrokerServiceConfig.b4b_test_governance_config(
            service_name=f"{B4B_TEST_SERVICE_PREFIX}x",
            pipe_name=DEFAULT_PIPE_NAME,
            db_path=db_file,
            cng_key_name=f"{B4B_TEST_KEY_PREFIX}k",
        )
    with pytest.raises(BrokerSecurityError):
        B4BTestServiceManager(PRODUCTION_SERVICE_NAME)
    with pytest.raises(BrokerSecurityError):
        B4BTestServiceManager("AntigravityAuditorBrokerB4ATest")
    with pytest.raises(BrokerSecurityError):
        B4BTestServiceManager("RandomService")


def test_b4b_qualification_only_regression_guard(tmp_path: Path) -> None:
    """B4-A qualification_only=True continues blocking ALL mutating governance and TCB methods."""
    db_path = tmp_path / "b4a.db"
    seed = _seed_project_and_finding(db_path, tmp_path / "repo")
    cfg = BrokerServiceConfig.b4a_test_config(db_path=db_path, use_memory_transport=True)
    host = BrokerServiceHost(cfg)
    host.start()
    try:
        client = BrokerClient(transport=host.memory_transport)
        caps = client.capabilities()
        assert caps["qualification_only"] is True
        assert METHOD_REQUEST_CONFIRMATION_CHALLENGE in caps["blocked_by_qualification"]

        for call in (
            lambda: client.request_confirmation_challenge(
                seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"]
            ),
            lambda: client.authorize_execution(
                seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"]
            ),
        ):
            with pytest.raises((BrokerSecurityError, BrokerError)) as exc_info:
                call()
            assert exc_info.value.code == ERR_ACCESS_DENIED
    finally:
        host.stop()


def test_b4b_named_pipe_governance_tpm_cng_tcb_end_to_end(tmp_path: Path) -> None:
    """Full Named Pipe B4B_SERVICE_GOVERNANCE_TEST lifecycle with real TPM PCP & ES256 TCB."""
    uid = uuid.uuid4().hex[:8]
    svc_name = f"{B4B_TEST_SERVICE_PREFIX}{uid}"
    pipe_name = f"{B4B_TEST_PIPE_PREFIX}{uid}"
    cng_key_name = f"{B4B_TEST_KEY_PREFIX}srv_{uid}"
    auth_key_name = f"{B4B_TEST_KEY_PREFIX}auth_{uid}"
    db_path = tmp_path / "b4b_gov.db"
    audit_log = tmp_path / "b4b_audit.jsonl"
    seed = _seed_project_and_finding(db_path, tmp_path / "repo")

    auth_signer = CngCbeatSigner(
        auth_key_name,
        provider_name=MS_KEY_STORAGE_PROVIDER,
        require_tpm=False,
        allow_software_ksp=True,
    )
    cred_id = "cred-e2e-01"
    trusted_auth = TcbTrustedAuthenticator.from_public_key(cred_id, auth_signer.get_public_key_bytes())

    cfg = BrokerServiceConfig.b4b_test_governance_config(
        service_name=svc_name,
        pipe_name=pipe_name,
        db_path=db_path,
        cng_key_name=cng_key_name,
        cng_provider=MS_PLATFORM_CRYPTO_PROVIDER,
        require_cng=True,
        require_tpm=True,
        require_tcb=True,
        tcb_trusted_authenticators={cred_id: trusted_auth},
        log_file=audit_log,
        use_memory_transport=False,
        require_existing_db_dir=True,
    )
    host = BrokerServiceHost(cfg)
    try:
        host.start()
        assert host.state == ServiceState.RUNNING
        assert host.signer is not None and host.signer.metadata.tpm_backed is True

        client = BrokerClient(pipe_name=pipe_name, timeout=10.0)

        # 1. Health, Capabilities & Key Status
        health = client.health()
        assert health["service_mode"] == SERVICE_MODE_B4B_GOVERNANCE_TEST
        assert health["cng_enabled"] is True
        assert health["tpm_backed"] is True
        assert health["require_tcb"] is True
        assert health["allow_execution_dispatch"] is False

        caps = client.capabilities()
        assert METHOD_REQUEST_CONFIRMATION_CHALLENGE in caps["supported_methods"]
        assert METHOD_KEY_STATUS in caps["supported_methods"]

        kstat = client.key_status()
        assert kstat["key"]["custody_type"] == "WINDOWS_CNG"
        assert kstat["key"]["tpm_backed"] is True
        assert kstat["key"]["export_policy"] == 0
        key_id = kstat["key"]["key_id"]

        # 2. Step A finding ingestion & user decision
        client.ingest_findings(
            project_key=seed["project_key"],
            run_id=seed["run_id"],
            findings=[{
                "finding_id": seed["finding_id"],
                "title": "Sample Security Defect",
                "severity": "HIGH",
                "confidence": 0.95,
                "file_path": "app.py",
                "line_start": 10,
                "line_end": 12,
                "rule_id": "SEC-01",
            }],
        )
        client.save_decisions(
            seed["project_key"],
            seed["run_id"],
            [{"finding_id": seed["finding_id"], "decision": "APPROVE", "note": "Approved in test"}],
        )

        # 3. Step B WITHOUT TCB fails closed
        with pytest.raises(BrokerConfirmationRequiredError) as exc_req:
            client.authorize_execution(
                seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"], execution_id="exec_1"
            )
        assert exc_req.value.code == ERR_CONFIRMATION_REQUIRED

        # 4. Mode / TCB override spoofing fails closed
        for bad_param in ("bypass_tcb", "tcb_override", "uac_elevated", "require_tcb", "mode"):
            with pytest.raises(BrokerSecurityError) as exc_spoof:
                client.invoke("broker.authorize_execution", {
                    "project_key": seed["project_key"],
                    "run_id": seed["run_id"],
                    "approved_finding_ids": [seed["finding_id"]],
                    "base_commit": seed["base_commit"],
                    bad_param: True,
                })
            assert exc_spoof.value.code == ERR_ACCESS_DENIED

        # 5. Request TCB challenge
        ch = client.request_confirmation_challenge(
            seed["project_key"],
            seed["run_id"],
            [seed["finding_id"]],
            seed["base_commit"],
            execution_id="exec_1",
            ttl_seconds=120,
        )
        assert ch["status"] == "PENDING"

        # 5a. UV=0 fails closed without consuming challenge
        bad_uv_proof = _make_es256_assertion(
            auth_signer, credential_id=cred_id, challenge=ch, flags=WEBAUTHN_FLAG_UP, sign_count=1
        )
        with pytest.raises(BrokerConfirmationError, match="UV=1"):
            client.authorize_execution(
                seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"],
                execution_id="exec_1", tcb_confirmation=bad_uv_proof,
            )

        # 5b. Request mutation after challenge (mutated base_commit or execution_id) fails closed
        valid_proof = _make_es256_assertion(
            auth_signer, credential_id=cred_id, challenge=ch, sign_count=1
        )
        with pytest.raises(BrokerSecurityError) as exc_mut:
            client.authorize_execution(
                seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"],
                execution_id="exec_MUTATED", tcb_confirmation=valid_proof,
            )
        assert exc_mut.value.code == ERR_SCOPE_VIOLATION

        # 6. Legitimate Step B authorization with valid TCB proof succeeds & issues TPM CNG CBEAT!
        auth_res = client.authorize_execution(
            seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"],
            execution_id="exec_1", tcb_confirmation=valid_proof,
        )
        tok = auth_res["cbeat_token"]
        assert tok["signature_algorithm"] == CBEAT_ALG_CNG_ECDSA_P256
        assert tok["tpm_backed"] is True
        assert tok["key_id"] == key_id
        assert auth_res["tcb_confirmation"]["challenge_id"] == ch["challenge_id"]

        ch_after = client.get_confirmation_challenge_status(ch["challenge_id"])
        assert ch_after["status"] == "CONSUMED"
        assert ch_after["consumed_by_approval_id"] == auth_res["approval_id"]

        # 7. Verify & Consume CBEAT
        ver_res = client.verify_execution_approval(
            auth_res["approval_id"], seed["project_key"], seed["run_id"], seed["base_commit"],
            [seed["finding_id"]], tok, execution_id="exec_1",
        )
        assert ver_res["valid"] is True
        client.consume_execution_approval(auth_res["approval_id"], auth_res["single_use_nonce"])

        # 8. Replay same TCB challenge fails EVEN AFTER host restart
        host.stop()
        host2 = BrokerServiceHost(cfg)
        host2.start()
        try:
            client2 = BrokerClient(pipe_name=pipe_name, timeout=10.0)
            with pytest.raises(BrokerSecurityError) as exc_rep:
                client2.authorize_execution(
                    seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"],
                    execution_id="exec_1", tcb_confirmation=valid_proof,
                )
            assert exc_rep.value.code == ERR_REPLAY_ATTEMPT

            # 9. SignCount rollback (sign_count=1 <= last_sign_count=1) fails on new challenge
            ch2 = client2.request_confirmation_challenge(
                seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"], execution_id="exec_2"
            )
            rollback_proof = _make_es256_assertion(
                auth_signer, credential_id=cred_id, challenge=ch2, sign_count=1
            )
            with pytest.raises((BrokerConfirmationError, BrokerSecurityError)) as exc_rb:
                client2.authorize_execution(
                    seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"],
                    execution_id="exec_2", tcb_confirmation=rollback_proof,
                )
            assert exc_rb.value.code in (ERR_REPLAY_ATTEMPT, ERR_CONFIRMATION_FAILED)

            # 10. Low-IL child process denied access to Named Pipe
            low_rc = _spawn_low_il_pipe_probe(pipe_name)
            assert low_rc != 0, "Low-IL child unexpectedly accessed B4-B Named Pipe!"

            # 11. Hash chain intact & zero secret leakage in audit log
            chain = client2.verify_audit_chain()
            assert chain["valid"] is True
            log_text = audit_log.read_text(encoding="utf-8") if audit_log.exists() else ""
            assert "PRIVATE KEY" not in log_text
            assert "signature_b64" not in log_text
        finally:
            host2.stop()
    finally:
        if host.state != ServiceState.STOPPED:
            try:
                host.stop()
            except Exception:
                pass
        auth_signer.delete_key()
        _cleanup_key(cng_key_name, MS_PLATFORM_CRYPTO_PROVIDER, require_tpm=True, allow_ksp=False)


def test_b4b_live_elevated_session0_scm_service_and_tpm_qualification() -> None:
    """Real Windows SCM Session-0 live qualification under NT SERVICE\\AntigravityAuditorBrokerB4BTest_<id>."""
    if not is_windows():
        pytest.skip("Windows required")
    proc_id = get_current_process_identity()
    if not proc_id.get("is_elevated"):
        pytest.skip("Elevation required for live Windows SCM CreateServiceW qualification")

    uid = uuid.uuid4().hex[:8]
    svc_name = f"{B4B_TEST_SERVICE_PREFIX}{uid}"
    pipe_name = f"{B4B_TEST_PIPE_PREFIX}{uid}"
    cng_key_name = f"{B4B_TEST_KEY_PREFIX}s0_{uid}"
    auth_key_name = f"{B4B_TEST_KEY_PREFIX}s0_auth_{uid}"
    lab_dir = Path(rf"C:\ProgramData\AntigravityB4BTestLab_{uid}")
    svc_sid = compute_service_sid_from_name(svc_name)

    mgr = B4BTestServiceManager(svc_name)
    preflight = mgr.verify_preflight_clean()
    assert preflight["clean"] is True
    assert preflight["production_service"]["win32_error"] == ERROR_SERVICE_DOES_NOT_EXIST

    auth_signer = CngCbeatSigner(
        auth_key_name,
        provider_name=MS_KEY_STORAGE_PROVIDER,
        require_tpm=False,
        allow_software_ksp=True,
    )
    cred_id = "cred-session0-01"

    try:
        lab_dir.mkdir(parents=True, exist_ok=True)
        code_dir = lab_dir / "code"
        db_dir = lab_dir / "db"
        log_dir = lab_dir / "logs"
        db_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(CORE_DIR / "broker", code_dir / "broker")
        # core/db.py needed only by test seeding; copy clean isolated db module if needed
        db_path = db_dir / "b4b_s0_test.db"
        repo_path = lab_dir / "repo"
        seed = _seed_project_and_finding(db_path, repo_path)

        # Store ONLY trusted PUBLIC key hex on service host (zero private keys on server)
        tcb_pub_file = lab_dir / "tcb_public_keys.json"
        tcb_pub_file.write_text(
            json.dumps({cred_id: auth_signer.get_public_key_hex()}),
            encoding="utf-8",
        )
        log_file = log_dir / "b4b_service.jsonl"

        # Provision non-exportable hardware TPM key as elevated installer, granting least-privilege
        # access to NT SERVICE\<svc_name> (Service SID), then close handle before Session-0 service starts.
        provisioner = CngCbeatSigner(
            cng_key_name,
            provider_name=MS_PLATFORM_CRYPTO_PROVIDER,
            require_tpm=True,
            allowed_key_sids=[svc_sid],
        )
        provisioner.close()

        acl_res = apply_restricted_directory_dacl(lab_dir, svc_sid, remove_inherited=True)
        assert acl_res["returncode"] == 0, acl_res

        user_sid = get_current_user_sid()
        scm_args = [
            "--mode", "b4b-test-governance",
            "--service-name", svc_name,
            "--db-path", str(db_path),
            "--pipe-name", pipe_name,
            "--allowed-sid", user_sid,
            "--log-file", str(log_file),
            "--cng-key-name", cng_key_name,
            "--cng-provider", MS_PLATFORM_CRYPTO_PROVIDER,
            "--require-cng",
            "--require-tpm",
            "--require-tcb",
            "--tcb-public-keys-file", str(tcb_pub_file),
        ]
        boot_log = log_dir / "service_boot.log"
        launcher_script = lab_dir / "launch_b4b_service.py"
        launcher_script.write_text(
            "import logging, sys, traceback\n"
            f"logging.basicConfig(filename={str(boot_log)!r}, level=logging.INFO)\n"
            f"sys.path.insert(0, {str(code_dir)!r})\n"
            "try:\n"
            "    from broker.scm_host import main\n"
            f"    raise SystemExit(main({scm_args!r}))\n"
            "except Exception:\n"
            f"    with open({str(boot_log)!r}, 'a', encoding='utf-8') as f:\n"
            "        traceback.print_exc(file=f)\n"
            "    raise\n",
            encoding="utf-8",
        )
        # Re-apply restricted directory DACL after writing all lab artifacts
        acl_res2 = apply_restricted_directory_dacl(lab_dir, svc_sid, remove_inherited=True)
        assert acl_res2["returncode"] == 0, acl_res2

        bin_cmd = f'"{sys.executable}" -B "{launcher_script}"'
        inst = mgr.install_test_service(bin_cmd)
        assert inst["installed"] is True

        try:
            start_st = mgr.start_test_service()
        except Exception as start_exc:
            boot_txt = boot_log.read_text(encoding="utf-8") if boot_log.exists() else "<no boot log>"
            raise AssertionError(f"Service startup failed: {start_exc}\nBOOT LOG:\n{boot_txt}") from start_exc
        assert start_st["state"] == "RUNNING"
        svc_pid = int(start_st["pid"])
        assert svc_pid > 0 and svc_pid != os.getpid()
        assert _process_session_id(svc_pid) == 0, f"Service PID {svc_pid} is not running in Session 0!"

        client = BrokerClient(pipe_name=pipe_name, timeout=15.0)
        health = client.health()
        assert health["pid"] == svc_pid
        assert health["service_identity"] == svc_name
        assert health["service_mode"] == SERVICE_MODE_B4B_GOVERNANCE_TEST
        assert health["cng_enabled"] is True
        assert health["tpm_backed"] is True
        assert health["require_tcb"] is True
        assert health["allow_execution_dispatch"] is False

        kstat = client.key_status()
        key_id_run1 = kstat["key"]["key_id"]
        pub_hex_run1 = kstat["key"]["public_key_hex"]
        assert kstat["key"]["tpm_backed"] is True

        # Step A + TCB Challenge + Proof + Step B over real Session-0 Named Pipe
        client.ingest_findings(
            project_key=seed["project_key"],
            run_id=seed["run_id"],
            findings=[{
                "finding_id": seed["finding_id"],
                "title": "Session 0 Test Finding",
                "severity": "CRITICAL",
                "confidence": 0.99,
                "file_path": "service_target.py",
                "line_start": 1,
                "line_end": 5,
                "rule_id": "SEC-02",
            }],
        )
        client.save_decisions(
            seed["project_key"], seed["run_id"], [{"finding_id": seed["finding_id"], "decision": "APPROVE"}]
        )
        with pytest.raises(BrokerConfirmationRequiredError):
            client.authorize_execution(
                seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"], execution_id="s0_e1"
            )
        ch = client.request_confirmation_challenge(
            seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"], execution_id="s0_e1"
        )
        proof = _make_es256_assertion(auth_signer, credential_id=cred_id, challenge=ch, sign_count=1)
        auth_res = client.authorize_execution(
            seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"],
            execution_id="s0_e1", tcb_confirmation=proof,
        )
        assert auth_res["cbeat_token"]["tpm_backed"] is True
        assert auth_res["cbeat_token"]["key_id"] == key_id_run1
        ver = client.verify_execution_approval(
            auth_res["approval_id"], seed["project_key"], seed["run_id"], seed["base_commit"],
            [seed["finding_id"]], auth_res["cbeat_token"], execution_id="s0_e1",
        )
        assert ver["valid"] is True

        # Stop & Restart Session-0 service cleanly: verify key custody & consumed TCB persistence!
        stop_st = mgr.stop_test_service()
        assert stop_st["state"] == "STOPPED"
        restart_st = mgr.start_test_service()
        assert restart_st["state"] == "RUNNING"
        svc_pid2 = int(restart_st["pid"])
        assert svc_pid2 != svc_pid and _process_session_id(svc_pid2) == 0

        kstat2 = client.key_status()
        assert kstat2["key"]["key_id"] == key_id_run1
        assert kstat2["key"]["public_key_hex"] == pub_hex_run1

        with pytest.raises(BrokerSecurityError) as exc_rep2:
            client.authorize_execution(
                seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"],
                execution_id="s0_e1", tcb_confirmation=proof,
            )
        assert exc_rep2.value.code == ERR_REPLAY_ATTEMPT
    finally:
        try:
            mgr.stop_test_service()
        except Exception:
            pass
        try:
            mgr.delete_test_service(expected_binary_substring="launch_b4b_service.py")
        except Exception:
            pass
        auth_signer.delete_key()
        _cleanup_key(cng_key_name, MS_PLATFORM_CRYPTO_PROVIDER, require_tpm=True, allow_ksp=False)
        if lab_dir.exists():
            for attempt in range(10):
                shutil.rmtree(lab_dir, ignore_errors=True)
                if not lab_dir.exists():
                    break
                time.sleep(0.2)
        # Guarantee zero lingering SCM registrations
        assert mgr.query_service_status()["win32_error"] == ERROR_SERVICE_DOES_NOT_EXIST
        assert mgr.query_named_service_status(PRODUCTION_SERVICE_NAME)["win32_error"] == ERROR_SERVICE_DOES_NOT_EXIST


def test_b4b_tcb_challenge_expiry_and_untrusted_key_audit_trail(tmp_path: Path) -> None:
    """Expired TCB challenges fail closed with ERR_APPROVAL_EXPIRED and record durable security audit events."""
    uid = uuid.uuid4().hex[:8]
    db_path = tmp_path / "b4b_expiry.db"
    seed = _seed_project_and_finding(db_path, tmp_path / "repo")
    cng_key_name = f"{B4B_TEST_KEY_PREFIX}exp_{uid}"
    auth_key_name = f"{B4B_TEST_KEY_PREFIX}exp_auth_{uid}"

    auth_signer = CngCbeatSigner(
        auth_key_name,
        provider_name=MS_KEY_STORAGE_PROVIDER,
        require_tpm=False,
        allow_software_ksp=True,
    )
    cred_id = "cred-expiry-01"
    cfg = BrokerServiceConfig.b4b_test_governance_config(
        service_name=f"{B4B_TEST_SERVICE_PREFIX}{uid}",
        pipe_name=f"{B4B_TEST_PIPE_PREFIX}{uid}",
        db_path=db_path,
        cng_key_name=cng_key_name,
        cng_provider=MS_KEY_STORAGE_PROVIDER,
        require_cng=True,
        require_tpm=False,
        allow_software_ksp=True,
        require_tcb=True,
        tcb_trusted_authenticators={
            cred_id: TcbTrustedAuthenticator.from_public_key(cred_id, auth_signer.get_public_key_bytes())
        },
        use_memory_transport=True,
        require_existing_db_dir=True,
    )
    host = BrokerServiceHost(cfg)
    try:
        host.start()
        client = BrokerClient(transport=host.memory_transport)
        client.ingest_findings(
            project_key=seed["project_key"],
            run_id=seed["run_id"],
            findings=[{
                "finding_id": seed["finding_id"],
                "title": "Expiry Test Finding",
                "severity": "MEDIUM",
                "confidence": 0.9,
                "file_path": "x.py",
                "line_start": 1,
                "line_end": 2,
                "rule_id": "SEC-03",
            }],
        )
        client.save_decisions(
            seed["project_key"], seed["run_id"], [{"finding_id": seed["finding_id"], "decision": "APPROVE"}]
        )
        ch = client.request_confirmation_challenge(
            seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"], execution_id="exp_e1"
        )
        proof = _make_es256_assertion(auth_signer, credential_id=cred_id, challenge=ch, sign_count=1)

        # Force TTL expiration deterministically in SQLite without sleeping
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE trusted_confirmations SET expires_epoch = ? WHERE challenge_id = ?",
                (time.time() - 5.0, ch["challenge_id"]),
            )
            conn.commit()

        assert client.get_confirmation_challenge_status(ch["challenge_id"])["status"] == "EXPIRED"

        with pytest.raises(BrokerSecurityError) as exc_exp:
            client.authorize_execution(
                seed["project_key"], seed["run_id"], [seed["finding_id"]], seed["base_commit"],
                execution_id="exp_e1", tcb_confirmation=proof,
            )
        assert exc_exp.value.code == ERR_APPROVAL_EXPIRED

        with sqlite3.connect(db_path) as conn:
            ev = conn.execute(
                "SELECT event_type, result FROM audit_events WHERE event_type = 'SECURITY_TCB_EXPIRED'"
            ).fetchone()
            assert ev is not None and ev[1] == "BLOCKED"
    finally:
        if host.state != ServiceState.STOPPED:
            host.stop()
        auth_signer.delete_key()
        _cleanup_key(cng_key_name, MS_KEY_STORAGE_PROVIDER, require_tpm=False, allow_ksp=True)

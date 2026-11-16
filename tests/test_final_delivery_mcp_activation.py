"""Final Delivery end-to-end verification tests for Antigravity live MCP activation."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CORE_DIR = REPO_ROOT / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from application_adapters.contracts import ProcessObservation, SignatureStatus
from application_adapters.stdio_entry import (
    ANTIGRAVITY_STDIO_APPLY_SCOPES,
    ANTIGRAVITY_STDIO_READONLY_AUDIT_SCOPES,
    ObservedProcessNode,
    _canonical_antigravity_executables,
    build_local_stdio_gateway_host,
    resolve_local_stdio_caller,
)
from broker.security import ClientIdentity
from db import connect, initialize
from mcp_gateway.contracts import AuthMethod
from mcp_server import AuditorMCPDispatcher
from verification import compute_excerpt_sha256


def _send_content_length(proc: subprocess.Popen[bytes], payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    frame = f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw
    assert proc.stdin is not None
    proc.stdin.write(frame)
    proc.stdin.flush()


def _read_content_length(proc: subprocess.Popen[bytes]) -> dict[str, Any]:
    assert proc.stdout is not None
    headers: dict[str, str] = {}
    while True:
        line = proc.stdout.readline()
        if not line:
            raise EOFError("Unexpected EOF while reading Content-Length headers")
        if line in (b"\r\n", b"\n"):
            break
        decoded = line.decode("ascii", errors="replace").strip()
        if ":" in decoded:
            k, v = decoded.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    length = int(headers["content-length"])
    body = proc.stdout.read(length)
    assert len(body) == length
    return json.loads(body.decode("utf-8"))


def _setup_controlled_git_project(tmp_path: Path) -> tuple[Path, Path, str]:
    db_path = tmp_path / "database" / "auditor.db"
    repo_path = tmp_path / "ctrl_repo"
    (repo_path / "src").mkdir(parents=True, exist_ok=True)
    app_py = repo_path / "src" / "service.py"
    app_lines = [
        "def authenticate_token(expected: str, provided: str) -> bool:",
        "    # Real test defect: direct string compare without hmac.compare_digest",
        "    return expected == provided",
    ]
    app_py.write_text("\n".join(app_lines) + "\n", encoding="utf-8")

    subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "audit-test@local.invalid"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Audit Test"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial controlled project"], cwd=repo_path, check=True, capture_output=True)
    base_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo_path, check=True, capture_output=True, text=True
    ).stdout.strip()

    initialize(db_path)
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id)
               VALUES('ctrl-test-proj', 'Controlled Test Repo', ?, 'proj-ctrl-1')""",
            (str(repo_path),),
        )
        conn.execute(
            """INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash, agent_conversation_id)
               VALUES('RUN-CTRL-1', 'ctrl-test-proj', 'DISPATCHED', ?, 'treehash-ctrl', 'primary-conv-1')""",
            (base_commit,),
        )
        conn.commit()
    return db_path, repo_path, base_commit


def test_01_live_subprocess_unknown_caller_enforces_core_read_and_protocol_resilience(tmp_path: Path) -> None:
    db_path, _, _ = _setup_controlled_git_project(tmp_path)
    env = os.environ.copy()
    env["ANTIGRAVITY_AUDITOR_HOME"] = str(tmp_path)
    env["ANTIGRAVITY_AUDITOR_DB"] = str(db_path)
    env["PYTHONIOENCODING"] = "utf-8"

    # Spawn real mcp_server.py from pytest (non-Antigravity parent) + send spoofed clientInfo.
    proc = subprocess.Popen(
        [sys.executable, str(CORE_DIR / "mcp_server.py")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        _send_content_length(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "clientInfo": {"name": "antigravity", "version": "2.32.1"},
                },
            },
        )
        init_resp = _read_content_length(proc)
        assert init_resp["result"]["protocolVersion"] == "2025-11-25"

        # Notification must not emit a frame.
        _send_content_length(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        _send_content_length(proc, {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 999}})

        _send_content_length(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        list_resp = _read_content_length(proc)
        visible_names = {t["name"] for t in list_resp["result"]["tools"]}
        assert visible_names == {"auditor_get_status", "auditor_gateway_capabilities"}

        # CORE_READ works cleanly.
        _send_content_length(
            proc,
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "auditor_gateway_capabilities", "arguments": {}}},
        )
        cap_resp = _read_content_length(proc)
        assert cap_resp["result"]["isError"] is False
        cap = cap_resp["result"]["structuredContent"]
        assert cap["application_id"] == "UNKNOWN"
        assert cap["verified_application_identity"] is False
        assert cap["execution_authorized"] is False
        assert cap["authorization_scopes"] == ["core:read"]

        _send_content_length(
            proc,
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "auditor_get_status", "arguments": {}}},
        )
        status_resp = _read_content_length(proc)
        assert status_resp["result"]["isError"] is False
        assert len(status_resp["result"]["structuredContent"]["projects"]) == 1
        assert status_resp["result"]["structuredContent"]["projects"][0]["project_key"] == "ctrl-test-proj"

        # PROJECT_READ must remain blocked despite spoofed clientInfo.
        _send_content_length(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "auditor_get_context", "arguments": {"project_key": "ctrl-test-proj"}},
            },
        )
        denied_resp = _read_content_length(proc)
        assert denied_resp["result"]["isError"] is True
        assert denied_resp["result"]["structuredContent"]["error_code"] == "UNKNOWN_IDENTITY_READONLY_ONLY"

        # Unknown method + invalid request + valid ping recovery.
        _send_content_length(proc, {"jsonrpc": "2.0", "id": 6, "method": "nonexistent/method", "params": {}})
        err_resp = _read_content_length(proc)
        assert err_resp["error"]["code"] == -32601

        _send_content_length(proc, {"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {}})
        ping_resp = _read_content_length(proc)
        assert ping_resp["result"] == {}

        assert proc.stdin is not None
        proc.stdin.close()
        stderr_bytes = proc.stderr.read() if proc.stderr is not None else b""
        rc = proc.wait(timeout=10)
        assert rc == 0
        assert b"Adapter stdio host started" in stderr_bytes
    finally:
        if proc.poll() is None:
            proc.kill()


def test_02_subprocess_spoofed_cli_hint_cannot_bypass_unknown_clamping(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["ANTIGRAVITY_AUDITOR_APPLY"] = "0"  # APPLY switched off -> execution tools disabled in the boundary log
    env["ANTIGRAVITY_AUDITOR_HOME"] = str(tmp_path)
    env["ANTIGRAVITY_AUDITOR_DB"] = str(tmp_path / "database" / "auditor.db")

    # Module invocation must work cleanly without extra PYTHONPATH, and hint must be ignored.
    proc = subprocess.run(
        [sys.executable, "-m", "core.application_adapters.stdio_entry", "--application-hint", "antigravity", "--check-boundary"],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert proc.returncode == 0
    assert proc.stdout == ""
    assert "verified_app=False" in proc.stderr
    assert "resolved_app=UNKNOWN" in proc.stderr
    assert "allow_execution_tools=False" in proc.stderr

    # Explicit disabled-named-pipe mode stays fail-closed (-32001).
    proc_pipe = subprocess.Popen(
        [sys.executable, "-m", "core.application_adapters.stdio_entry", "--transport", "disabled-named-pipe"],
        cwd=str(REPO_ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        assert proc_pipe.stdin is not None and proc_pipe.stdout is not None
        proc_pipe.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
        proc_pipe.stdin.flush()
        proc_pipe.stdin.close()
        out, _ = proc_pipe.communicate(timeout=10)
        assert proc_pipe.returncode == 0
        msg = json.loads(out.decode("utf-8").splitlines()[0])
        assert msg["error"]["code"] == -32001
        assert "PRODUCTION_BROKER_NAMED_PIPE_DISABLED" in msg["error"]["message"]
    finally:
        if proc_pipe.poll() is None:
            proc_pipe.kill()


def test_03_ancestor_chain_verification_distinguishes_antigravity_from_shells(tmp_path: Path) -> None:
    fake_agy = tmp_path / "Programs" / "antigravity" / "Antigravity.exe"
    fake_ls = tmp_path / "Programs" / "antigravity" / "resources" / "bin" / "language_server.exe"
    fake_pwsh = tmp_path / "WindowsPowerShell" / "powershell.exe"
    for p in (fake_agy, fake_ls, fake_pwsh):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"MZ")

    canon = ({os.path.realpath(str(fake_agy)).casefold()}, {os.path.realpath(str(fake_ls)).casefold()})
    sid = "S-1-5-21-2714397700-3332615980-1796267308-1001"
    os_ident = ClientIdentity(
        pid=3000,
        sid=sid,
        integrity_level="MEDIUM",
        is_low_integrity=False,
        is_appcontainer=False,
        is_elevated=False,
        verified_by_os=True,
    )
    proc_obs = ProcessObservation(
        pid=3000,
        process_creation_time_100ns=1000,
        process_creation_time_iso="2026-11-14T00:00:00Z",
        user_sid_hash="hash",
        user_sid_observed=True,
        session_id=1,
        integrity_level="MEDIUM",
        executable_path=sys.executable,
        executable_sha256="a" * 64,
        signature_status=SignatureStatus.UNSIGNED,
        parent_pid=2000,
        parent_image_path=str(fake_ls),
        parent_creation_time_100ns=500,
        verified_by_os=True,
        proves_application_identity=False,
    )

    # Valid Antigravity.exe -> language_server.exe -> python.exe chain
    valid_nodes = {
        2000: ObservedProcessNode(2000, 1000, 500, str(fake_ls), sid, 1, "MEDIUM"),
        1000: ObservedProcessNode(1000, 100, 100, str(fake_agy), sid, 1, "MEDIUM"),
    }
    caller_ok, _ = resolve_local_stdio_caller(
        _test_os_identity=os_ident,
        _test_process_obs=proc_obs,
        _test_process_reader=valid_nodes.get,
        _test_canonical_executables=canon,
    )
    assert caller_ok.verified_application_identity is True
    assert caller_ok.application_id == "antigravity"
    assert caller_ok.authentication_method == AuthMethod.LOCAL_OS_PROCESS
    # Audit lifecycle + APPLY (decide / run); never governance:authorize (human-only, terminal).
    assert caller_ok.authorization_scopes == ANTIGRAVITY_STDIO_READONLY_AUDIT_SCOPES | ANTIGRAVITY_STDIO_APPLY_SCOPES
    assert "governance:authorize" not in caller_ok.authorization_scopes

    # Shell parent (powershell.exe spawned by Antigravity) must FAIL closed to UNKNOWN / CORE_READ.
    shell_obs = ProcessObservation(**{**proc_obs.__dict__, "parent_image_path": str(fake_pwsh)})
    shell_nodes = {
        2000: ObservedProcessNode(2000, 1000, 500, str(fake_pwsh), sid, 1, "MEDIUM"),
        1000: ObservedProcessNode(1000, 100, 100, str(fake_agy), sid, 1, "MEDIUM"),
    }
    caller_shell, _ = resolve_local_stdio_caller(
        application_hint="antigravity",
        _test_os_identity=os_ident,
        _test_process_obs=shell_obs,
        _test_process_reader=shell_nodes.get,
        _test_canonical_executables=canon,
    )
    assert caller_shell.verified_application_identity is False
    assert caller_shell.application_id == "UNKNOWN"
    assert caller_shell.authorization_scopes == frozenset({"core:read"})

    # Different OS SID on Antigravity parent must also FAIL closed to UNKNOWN.
    other_sid_nodes = {
        2000: ObservedProcessNode(2000, 1000, 500, str(fake_ls), "S-1-5-21-999999-1002", 1, "MEDIUM"),
        1000: ObservedProcessNode(1000, 100, 100, str(fake_agy), "S-1-5-21-999999-1002", 1, "MEDIUM"),
    }
    caller_diff_sid, _ = resolve_local_stdio_caller(
        _test_os_identity=os_ident,
        _test_process_obs=proc_obs,
        _test_process_reader=other_sid_nodes.get,
        _test_canonical_executables=canon,
    )
    assert caller_diff_sid.verified_application_identity is False
    assert caller_diff_sid.application_id == "UNKNOWN"


def test_04_end_to_end_controlled_project_audit_and_restart_via_antigravity_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTIGRAVITY_AUDITOR_APPLY", "0")  # read-only delivery mode: APPLY tools withheld
    db_path, repo_path, base_commit = _setup_controlled_git_project(tmp_path)
    fake_agy = tmp_path / "Programs" / "antigravity" / "Antigravity.exe"
    fake_agy.parent.mkdir(parents=True, exist_ok=True)
    fake_agy.write_bytes(b"MZ")
    canon = ({os.path.realpath(str(fake_agy)).casefold()}, set())
    sid = "S-1-5-21-2714397700-3332615980-1796267308-1001"
    os_ident = ClientIdentity(
        pid=4000,
        sid=sid,
        integrity_level="MEDIUM",
        is_low_integrity=False,
        is_appcontainer=False,
        is_elevated=False,
        verified_by_os=True,
    )
    proc_obs = ProcessObservation(
        pid=4000,
        process_creation_time_100ns=2000,
        process_creation_time_iso="2026-11-14T00:00:00Z",
        user_sid_hash="hash",
        user_sid_observed=True,
        session_id=1,
        integrity_level="MEDIUM",
        executable_path=sys.executable,
        executable_sha256="b" * 64,
        signature_status=SignatureStatus.UNSIGNED,
        parent_pid=1000,
        parent_image_path=str(fake_agy),
        parent_creation_time_100ns=100,
        verified_by_os=True,
        proves_application_identity=False,
    )
    nodes = {1000: ObservedProcessNode(1000, 100, 100, str(fake_agy), sid, 1, "MEDIUM")}

    def _run_session(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
        in_buf = io.BytesIO(b"".join(json.dumps(m).encode("utf-8") + b"\n" for m in messages))
        out_buf = io.BytesIO()
        err_buf = io.StringIO()
        dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)
        host = build_local_stdio_gateway_host(
            dispatcher=dispatcher,
            app_home=tmp_path,
            db_path=db_path,
            stderr_stream=err_buf,
            allow_execution_tools=False,
            _test_os_identity=os_ident,
            _test_process_obs=proc_obs,
            _test_process_reader=nodes.get,
            _test_canonical_executables=canon,
        )
        rc = host.serve_streams(in_buf, out_buf)
        assert rc == 0
        lines = [json.loads(line) for line in out_buf.getvalue().decode("utf-8").splitlines() if line.strip()]
        return lines, err_buf.getvalue()

    target_file = repo_path / "src" / "service.py"
    target_bytes = target_file.read_bytes()
    file_sha = hashlib.sha256(target_bytes).hexdigest()
    excerpt = "    return expected == provided"
    excerpt_sha = compute_excerpt_sha256(excerpt)

    # Session 1: Initialize, list tools, inspect context, publish primary finding, check error recovery.
    res1, err1 = _run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "auditor_get_context", "arguments": {"project_key": "ctrl-test-proj"}}},
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "auditor_publish_report",
                    "arguments": {
                        "project_key": "ctrl-test-proj",
                        "run_id": "RUN-CTRL-1",
                        "findings": [
                            {
                                "finding_id": "F-CTRL-1",
                                "fingerprint": "fp-ctrl-timing-compare",
                                "title": "Non-constant-time token comparison",
                                "category": "security",
                                "severity": "HIGH",
                                "confidence": "CONFIRMED",
                                "file_path": "src/service.py",
                                "symbol": "authenticate_token",
                                "line_start": 1,
                                "line_end": 3,
                                "evidence": "Uses == string equality on secret tokens",
                                "impact": "Timing side-channel disclosure",
                                "recommendation": "Use hmac.compare_digest(expected, provided)",
                            }
                        ],
                    },
                },
            },
            # Missing project returns clean MCP tool error and keeps server alive
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "auditor_get_context", "arguments": {"project_key": "missing-proj"}}},
            # Mutating APPLY/EXECUTION tools remain withheld/blocked
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "auditor_start_execution", "arguments": {"project_key": "ctrl-test-proj", "approval_token": "tok-1234567890"}}},
            {"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {}},
        ]
    )
    assert "verified_app=True" in err1 and "resolved_app=antigravity" in err1
    listed = {t["name"] for t in res1[1]["result"]["tools"]}
    assert {
        "auditor_get_status",
        "auditor_gateway_capabilities",
        "auditor_get_context",
        "auditor_list_findings",
        "auditor_get_verification_context",
        "auditor_get_verification_status",
        "auditor_publish_report",
        "auditor_submit_verification",
        "auditor_finalize_verified_report",
    }.issubset(listed)
    for blocked_name in (
        "auditor_save_decisions",
        "auditor_authorize_execution",
        "auditor_start_execution",
        "auditor_update_finding_execution",
        "auditor_finalize_execution",
    ):
        assert blocked_name not in listed

    assert res1[2]["result"]["isError"] is False
    ctx_out = res1[2]["result"]["structuredContent"]
    assert ctx_out["project"]["project_key"] == "ctrl-test-proj"  # Must NOT be redacted!
    assert res1[3]["result"]["isError"] is False, res1[3]
    pub_out = res1[3]["result"]["structuredContent"]
    assert pub_out["project_key"] == "ctrl-test-proj"
    assert pub_out["status"] == "VERIFICATION_PENDING"
    vrun_id = pub_out["verification_run_id"]
    snap_id = pub_out["snapshot_id"]

    assert res1[4]["result"]["isError"] is True
    assert res1[5]["result"]["isError"] is True
    assert res1[5]["result"]["structuredContent"]["error_code"] in ("MISSING_SCOPE", "EXECUTION_DISABLED_FOR_CALLER")
    assert res1[6]["result"] == {}

    # Session 2 (simulated disconnect/restart on same DB): second-pass verification + finalize + findings retrieval.
    res2, _ = _run_session(
        [
            {"jsonrpc": "2.0", "id": 10, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "auditor_get_verification_context",
                    "arguments": {"audit_run_id": "RUN-CTRL-1", "verification_run_id": vrun_id},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "auditor_submit_verification",
                    "arguments": {
                        "audit_run_id": "RUN-CTRL-1",
                        "verification_run_id": vrun_id,
                        "verifier_conversation_id": "verifier-conv-independent-1",
                        "verifier_metadata": {
                            "verifier_model_id": "gemini-4-argon-high",
                            "invocation_mechanism": "mcp_direct",
                        },
                        "verification_results": [
                            {
                                "candidate_finding_id": "F-CTRL-1",
                                "verdict": "CONFIRMED",
                                "verified_severity": "HIGH",
                                "verified_confidence": "CONFIRMED",
                                "technical_rationale": "Confirmed line 3 uses non-constant-time == on tokens.",
                                "source_evidence": {
                                    "file_path": "src/service.py",
                                    "line_start": 3,
                                    "line_end": 3,
                                    "symbol": "authenticate_token",
                                    "excerpt": excerpt,
                                    "excerpt_sha256": excerpt_sha,
                                    "file_sha256": file_sha,
                                    "snapshot_id": snap_id,
                                    "base_commit_sha": base_commit,
                                },
                                "remediation_review": "Replace with hmac.compare_digest",
                                "remediation_safe": True,
                                "acceptance_criteria": "Use constant-time comparison",
                                "reviewed_file_hashes": {"src/service.py": file_sha},
                            }
                        ],
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": "auditor_get_verification_status",
                    "arguments": {"audit_run_id": "RUN-CTRL-1", "verification_run_id": vrun_id},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 14,
                "method": "tools/call",
                "params": {
                    "name": "auditor_finalize_verified_report",
                    "arguments": {"audit_run_id": "RUN-CTRL-1", "verification_run_id": vrun_id},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 15,
                "method": "tools/call",
                "params": {
                    "name": "auditor_list_findings",
                    "arguments": {"project_key": "ctrl-test-proj", "run_id": "RUN-CTRL-1"},
                },
            },
        ]
    )
    assert res2[1]["result"]["isError"] is False, res2[1]
    vctx = res2[1]["result"]["structuredContent"]
    assert vctx["audit_run_id"] == "RUN-CTRL-1"
    assert len(vctx["candidate_claims"]) == 1

    assert res2[2]["result"]["isError"] is False, res2[2]
    sub_out = res2[2]["result"]["structuredContent"]
    assert sub_out["all_candidates_resolved"] is True

    assert res2[3]["result"]["isError"] is False, res2[3]
    vstat = res2[3]["result"]["structuredContent"]
    assert vstat["confirmed_count"] == 1

    assert res2[4]["result"]["isError"] is False, res2[4]
    fin_out = res2[4]["result"]["structuredContent"]
    assert fin_out["status"] == "READY_FOR_REVIEW"
    assert fin_out["project_key"] == "ctrl-test-proj"
    report_path = Path(fin_out["review_report_path"])
    assert report_path.exists()
    assert "Non-constant-time token comparison" in report_path.read_text(encoding="utf-8")

    findings_out = res2[5]["result"]["structuredContent"]
    assert findings_out["project_key"] == "ctrl-test-proj"
    assert findings_out["count"] == 1


def test_05_env_redirection_junction_and_toctou_spoofing_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. LOCALAPPDATA / USERPROFILE env vars pointing to attacker dir MUST NEVER redirect canonical executables.
    spoof_local = tmp_path / "spoof_local"
    spoof_agy = spoof_local / "Programs" / "antigravity" / "Antigravity.exe"
    spoof_agy.parent.mkdir(parents=True, exist_ok=True)
    spoof_agy.write_bytes(b"MZ")
    monkeypatch.setenv("LOCALAPPDATA", str(spoof_local))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "spoof_profile"))
    direct_exes, ls_exes = _canonical_antigravity_executables()
    assert os.path.realpath(str(spoof_agy)).casefold() not in direct_exes
    assert os.path.realpath(str(spoof_agy)).casefold() not in ls_exes

    # 2. Reparse points / Windows NTFS junctions inside a root must be rejected.
    target_dir = tmp_path / "real_target"
    target_dir.mkdir()
    (target_dir / "Antigravity.exe").write_bytes(b"MZ")
    j_local = tmp_path / "junc_local"
    (j_local / "Programs").mkdir(parents=True)
    j_path = j_local / "Programs" / "antigravity"
    if sys.platform == "win32":
        mk = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(j_path), str(target_dir)],
            capture_output=True,
            text=True,
        )
        if mk.returncode == 0:
            j_direct, _ = _canonical_antigravity_executables(local_app_data=j_local)
            assert j_direct == set()

    # 3. Parent creation_time mismatch (PID reuse), missing session_id, or UNKNOWN integrity MUST fail closed.
    real_dir = tmp_path / "clean_local" / "Programs" / "antigravity"
    real_dir.mkdir(parents=True, exist_ok=True)
    real_agy = real_dir / "Antigravity.exe"
    real_agy.write_bytes(b"MZ")
    canon = _canonical_antigravity_executables(local_app_data=tmp_path / "clean_local")
    assert os.path.abspath(str(real_agy)).casefold() in canon[0]

    sid = "S-1-5-21-2714397700-3332615980-1796267308-1001"
    os_ident = ClientIdentity(
        pid=5000,
        sid=sid,
        integrity_level="MEDIUM",
        is_low_integrity=False,
        is_appcontainer=False,
        is_elevated=False,
        verified_by_os=True,
    )
    proc_obs = ProcessObservation(
        pid=5000,
        process_creation_time_100ns=2000,
        process_creation_time_iso="2026-11-14T00:00:00Z",
        user_sid_hash="hash",
        user_sid_observed=True,
        session_id=1,
        integrity_level="MEDIUM",
        executable_path=sys.executable,
        executable_sha256="c" * 64,
        signature_status=SignatureStatus.UNSIGNED,
        parent_pid=1000,
        parent_image_path=str(real_agy),
        parent_creation_time_100ns=500,
        verified_by_os=True,
        proves_application_identity=False,
    )

    for bad_node in (
        ObservedProcessNode(1000, 100, 501, str(real_agy), sid, 1, "MEDIUM"),  # mismatched parent_creation_time_100ns
        ObservedProcessNode(1000, 100, 500, str(real_agy), sid, None, "MEDIUM"),  # missing session_id
        ObservedProcessNode(1000, 100, 500, str(real_agy), sid, 1, "UNKNOWN"),  # untrusted integrity
    ):
        caller_bad, _ = resolve_local_stdio_caller(
            _test_os_identity=os_ident,
            _test_process_obs=proc_obs,
            _test_process_reader={1000: bad_node}.get,
            _test_canonical_executables=canon,
        )
        assert caller_bad.verified_application_identity is False
        assert caller_bad.application_id == "UNKNOWN"
        assert caller_bad.authorization_scopes == frozenset({"core:read"})


def test_05_apply_mode_exposes_execution_tools_but_never_authorization(tmp_path: Path) -> None:
    """APPLY without Windows Hello: verified Antigravity may record decisions and drive an execution, but
    authorizing it is human-only (terminal) -- the authorize tool is never listed or callable over MCP."""
    db_path, _repo_path, _base = _setup_controlled_git_project(tmp_path)
    fake_agy = tmp_path / "Programs" / "antigravity" / "Antigravity.exe"
    fake_agy.parent.mkdir(parents=True, exist_ok=True)
    fake_agy.write_bytes(b"MZ")
    canon = ({os.path.realpath(str(fake_agy)).casefold()}, set())
    sid = "S-1-5-21-2714397700-3332615980-1796267308-1001"
    os_ident = ClientIdentity(
        pid=4000, sid=sid, integrity_level="MEDIUM", is_low_integrity=False,
        is_appcontainer=False, is_elevated=False, verified_by_os=True,
    )
    proc_obs = ProcessObservation(
        pid=4000, process_creation_time_100ns=2000, process_creation_time_iso="2026-11-14T00:00:00Z",
        user_sid_hash="hash", user_sid_observed=True, session_id=1, integrity_level="MEDIUM",
        executable_path=sys.executable, executable_sha256="b" * 64, signature_status=SignatureStatus.UNSIGNED,
        parent_pid=1000, parent_image_path=str(fake_agy), parent_creation_time_100ns=100,
        verified_by_os=True, proves_application_identity=False,
    )
    nodes = {1000: ObservedProcessNode(1000, 100, 100, str(fake_agy), sid, 1, "MEDIUM")}
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "auditor_authorize_execution", "arguments": {"project_key": "ctrl-test-proj", "run_id": "R", "confirmation": "AUTHORIZE_ISOLATED_WORKTREE_EXECUTION"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "auditor_start_execution", "arguments": {"project_key": "ctrl-test-proj", "approval_id": "APPR-UNKNOWN"}}},
    ]
    in_buf = io.BytesIO(b"".join(json.dumps(m).encode("utf-8") + b"\n" for m in messages))
    out_buf = io.BytesIO()
    host = build_local_stdio_gateway_host(
        dispatcher=AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path),
        app_home=tmp_path,
        db_path=db_path,
        stderr_stream=io.StringIO(),
        allow_execution_tools=True,
        _test_os_identity=os_ident,
        _test_process_obs=proc_obs,
        _test_process_reader=nodes.get,
        _test_canonical_executables=canon,
    )
    assert host.serve_streams(in_buf, out_buf) == 0
    res = [json.loads(line) for line in out_buf.getvalue().decode("utf-8").splitlines() if line.strip()]
    listed = {t["name"] for t in res[1]["result"]["tools"]}
    assert {"auditor_save_decisions", "auditor_start_execution", "auditor_update_finding_execution", "auditor_finalize_execution"} <= listed
    assert "auditor_authorize_execution" not in listed
    assert res[2]["result"]["isError"] is True
    assert res[2]["result"]["structuredContent"]["error_code"] == "MISSING_SCOPE"
    assert res[3]["result"]["isError"] is True  # unknown approval: nothing starts without a human authorization

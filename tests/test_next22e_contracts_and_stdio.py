"""NEXT-22E non-SDK contract, carry-forward privacy, and subprocess stdio framing tests.

Runs in BOTH standard runtime (zero `mcp` dependency) and the isolated qualification venv.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from application_adapters import (
    ApplicationAdapterRegistry,
    CANONICAL_APPLICATION_LABELS,
)
from application_adapters.contracts import ApplicationAdapterProfile
from entitlement_router.privacy import sanitize_for_output
import mcp_gateway.sdk_v2_compat as sdk_compat

HARNESS_SCRIPT = Path(__file__).resolve().parent / "next22e_stdio_harness.py"


def _send_content_length(proc: subprocess.Popen[bytes], payload_bytes: bytes) -> None:
    assert proc.stdin is not None
    header = f"Content-Length: {len(payload_bytes)}\r\n\r\n".encode("ascii")
    proc.stdin.write(header + payload_bytes)
    proc.stdin.flush()


def _read_content_length(proc: subprocess.Popen[bytes]) -> dict:
    assert proc.stdout is not None
    headers: dict[str, str] = {}
    while True:
        line = proc.stdout.readline()
        if not line:
            raise EOFError("Subprocess stdout closed while reading Content-Length headers")
        if line in (b"\r\n", b"\n"):
            break
        decoded = line.decode("ascii", errors="replace").strip()
        if ":" in decoded:
            k, v = decoded.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    length = int(headers["content-length"])
    body = proc.stdout.read(length)
    return json.loads(body.decode("utf-8"))


def test_part2_canonical_application_label_preserves_safe_product_names_without_weakening_pii() -> None:
    registry = ApplicationAdapterRegistry()
    profiles = {p.application_id: p for p in registry.list_profiles()}
    for app_id, prof in profiles.items():
        d = prof.to_dict()
        # Global PII rule remains strict: display_name stays redacted
        assert d["display_name"] == "<REDACTED>"
        # Safe canonical application label is preserved without exposing user PII
        assert d["application_label"] == CANONICAL_APPLICATION_LABELS[app_id]

    # Arbitrary caller-supplied display string MUST remain redacted in BOTH fields
    spoof_user = ApplicationAdapterProfile(
        application_id="antigravity",
        application_family="google",
        display_name="Alice Johnson <alice@example.com>",
    )
    spoof_dict = spoof_user.to_dict()
    assert spoof_dict["display_name"] == "<REDACTED>"
    assert spoof_dict["application_label"] == "<REDACTED>"

    # Global privacy module remains strict for display_name anywhere else
    assert sanitize_for_output({"display_name": "John Doe"})["display_name"] == "<REDACTED>"


def test_sdk_v2_compat_safety_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    status = sdk_compat.get_sdk_v2_status()
    assert status["remote_mcp_disabled"] is True
    assert status["production_entrypoint_replaced"] is False
    assert status["compatibility_decision"] == "SUITABLE_AS_OPTIONAL_COMPATIBILITY_BRIDGE"

    # Simulated absence of SDK v2 must fail closed cleanly with SDKv2UnavailableError
    monkeypatch.setattr(sdk_compat, "SDK_V2_AVAILABLE", False)
    with pytest.raises(sdk_compat.SDKv2UnavailableError):
        sdk_compat._require_sdk_v2()


def test_next22d_legacy_subprocess_stdio_framing_unicode_errors_and_purity(tmp_path: Path) -> None:
    """Real cross-process stdio framing, malformed input recovery, Unicode, oversized frame, and stderr purity."""
    db_path = tmp_path / "next22e_framing.db"
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    # 1. Newline-delimited JSON-RPC + malformed JSON + Unicode + escaped newlines + empty params + unknown method
    proc = subprocess.Popen(
        [
            sys.executable,
            str(HARNESS_SCRIPT),
            "--mode",
            "legacy-adapter",
            "--db-path",
            str(db_path),
            "--caller",
            "verified_full",
            "--emit-warning",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None

    reqs = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}).encode("utf-8") + b"\n",
        b"{not valid json\n",
        json.dumps({"jsonrpc": "2.0", "id": "u-1", "method": "tools/call", "params": {"name": "auditor_list_projects", "arguments": {"unused": "Türkçe\\n日本語\\u2713"}}}).encode("utf-8") + b"\n",
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}).encode("utf-8") + b"\n",
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "nonexistent/method", "params": {}}).encode("utf-8") + b"\n",
        json.dumps({"jsonrpc": 1, "id": 4, "method": "ping"}).encode("utf-8") + b"\n",
    ]
    for r in reqs:
        proc.stdin.write(r)
    proc.stdin.flush()
    proc.stdin.close()

    stdout_raw, stderr_raw = proc.communicate(timeout=15)
    assert proc.returncode == 0
    lines = [ln for ln in stdout_raw.decode("utf-8").splitlines() if ln.strip()]
    parsed = [json.loads(ln) for ln in lines]
    assert len(parsed) == 6
    assert parsed[0]["result"]["protocolVersion"] == "2025-11-25"
    assert parsed[1]["error"]["code"] == -32700
    assert parsed[2]["id"] == "u-1"
    assert parsed[3]["result"] == {}
    assert parsed[4]["error"]["code"] == -32601
    assert parsed[5]["error"]["code"] == -32600

    stderr_text = stderr_raw.decode("utf-8", errors="replace")
    assert "warning" in stderr_text.lower()
    assert "warning" not in stdout_raw.decode("utf-8", errors="replace").lower()

    # 2. Content-Length framing: normal frame + oversized Content-Length + clean recovery + partial EOF
    proc2 = subprocess.Popen(
        [
            sys.executable,
            str(HARNESS_SCRIPT),
            "--mode",
            "legacy-adapter",
            "--db-path",
            str(db_path),
            "--caller",
            "unknown",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert proc2.stdin is not None and proc2.stdout is not None
    _send_content_length(
        proc2,
        json.dumps({"jsonrpc": "2.0", "id": 10, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}).encode("utf-8"),
    )
    r10 = _read_content_length(proc2)
    assert r10["result"]["protocolVersion"] == "2024-11-05"

    # Send invalid negative Content-Length then valid ping -> stream stays synchronized!
    proc2.stdin.write(b"Content-Length: -5\r\n\r\n")
    proc2.stdin.flush()
    r_bad = _read_content_length(proc2)
    assert r_bad["error"]["code"] == -32600

    _send_content_length(
        proc2,
        json.dumps({"jsonrpc": "2.0", "id": 11, "method": "ping", "params": {}}).encode("utf-8"),
    )
    r11 = _read_content_length(proc2)
    assert r11["id"] == 11 and r11["result"] == {}

    # Oversized > 1 MiB header check
    proc2.stdin.write(b"Content-Length: 9999999\r\n\r\n")
    proc2.stdin.flush()
    r_over = _read_content_length(proc2)
    assert r_over["error"]["code"] == -32600
    assert "Invalid or oversized Content-Length" in r_over["error"]["message"]

    # Unexpected partial frame before EOF exits cleanly without hanging
    proc2.stdin.write(b"Content-Length: 100\r\n\r\n{\"partial\":")
    proc2.stdin.close()
    rc = proc2.wait(timeout=10)
    assert rc == 0

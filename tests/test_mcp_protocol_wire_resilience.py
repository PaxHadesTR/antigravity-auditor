"""NEXT-22E Official MCP Python SDK v2.3.0 Protocol Wire & Resilience Qualification Suite.

Executes real cross-process Windows stdio (and disposable 127.0.0.1 loopback HTTP) wire
verification against BOTH:
1. NEXT-22D legacy `CommonStdioAdapterHost` subprocess (`InMemoryBrokerTransport`).
2. Dual-era `GatewaySDKv2Bridge` (`core/mcp_gateway/sdk_v2_compat.py`) over `mcp==2.3.0`.

Strictly qualification-only; NEVER opens production SQLite, production Named Pipes, or real apps.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

import pytest

TESTS_DIR = Path(__file__).resolve().parent
CORE_DIR = TESTS_DIR.parent / "core"
for _p in (str(CORE_DIR), str(TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from mcp_gateway.sdk_v2_compat import (
    GatewaySDKv2Bridge,
    REMOTE_MCP_DISABLED,
    SDK_V2_AVAILABLE,
    SDK_V2_VERSION,
)

pytestmark = pytest.mark.skipif(
    not SDK_V2_AVAILABLE,
    reason="Official MCP Python SDK v2.3.0 not installed in normal runtime; run inside isolated NEXT-22E qualification venv.",
)

if SDK_V2_AVAILABLE:
    import anyio
    import mcp_types as types
    from mcp import Client, Implementation, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.client.subscriptions import SubscriptionLost, ToolsListChanged
    from mcp.shared.exceptions import MCPError
    from mcp.shared.message import SessionMessage
    import uvicorn

    from mcp_gateway import (
        AdaptiveMCPGateway,
        AuthMethod,
        AuthenticatedCallerContext,
        ProtocolContext,
        UNIVERSAL_MINIMUM_READ_SCOPES,
    )
    from next22e_stdio_harness import build_caller, build_disposable_gateway

HARNESS_SCRIPT = Path(__file__).resolve().parent / "next22e_stdio_harness.py"
EXPECTED_VENV_MARKER = "AntigravityAuditor_NEXT22E_VENV"


def _stdio_params(
    *,
    mode: str,
    db_path: Path,
    caller: str = "verified_full",
    extra_args: list[str] | None = None,
) -> Any:
    args = [
        str(HARNESS_SCRIPT),
        "--mode",
        mode,
        "--db-path",
        str(db_path),
        "--caller",
        caller,
    ]
    if extra_args:
        args.extend(extra_args)
    return StdioServerParameters(
        command=sys.executable,
        args=args,
        env={"PYTHONIOENCODING": "utf-8"},
    )


def _wire_session_req(req_id: int | str, method: str, params: dict[str, Any] | None = None) -> Any:
    msg = types.JSONRPCRequest(jsonrpc="2.0", id=req_id, method=method, params=params)
    return SessionMessage(message=msg)


def _wire_session_notify(method: str, params: dict[str, Any] | None = None) -> Any:
    msg = types.JSONRPCNotification(jsonrpc="2.0", method=method, params=params)
    return SessionMessage(message=msg)


def _collect_server_messages(read_stream: Any, expected_ids: set[int | str], timeout_s: float = 10.0) -> Any:
    async def _inner() -> tuple[dict[int | str, dict[str, Any]], list[dict[str, Any]]]:
        responses: dict[int | str, dict[str, Any]] = {}
        notifications: list[dict[str, Any]] = []
        with anyio.fail_after(timeout_s):
            async for item in read_stream:
                if isinstance(item, Exception):
                    raise item
                raw = item.message.model_dump(by_alias=True, mode="json", exclude_none=True)
                if "id" in raw and raw["id"] is not None:
                    responses[raw["id"]] = raw
                    if expected_ids.issubset(responses.keys()):
                        break
                else:
                    notifications.append(raw)
        return responses, notifications

    return _inner()


# ---------------------------------------------------------------------------
# A. LEGACY PROTOCOL WIRE TESTS (ALL 4 REVISIONS OVER REAL SUBPROCESS STDIO)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("proto_ver", ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
def test_a01_legacy_all_four_revisions_real_subprocess_wire(tmp_path: Path, proto_ver: str) -> None:
    """Prove initialize, capabilities, tools/list, tools/call, error codes, and structuredOutput compatibility across all 4 legacy revisions."""
    db_path = tmp_path / f"legacy_{proto_ver}.db"

    async def _run() -> None:
        params = _stdio_params(mode="sdk-bridge", db_path=db_path, caller="verified_full")
        with open(tmp_path / f"err_{proto_ver}.log", "w", encoding="utf-8") as errlog:
            async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
                await write_stream.send(
                    _wire_session_req(
                        1,
                        "initialize",
                        {
                            "protocolVersion": proto_ver,
                            "capabilities": {},
                            "clientInfo": {"name": "next22e-wire-probe", "version": "1.0"},
                        },
                    )
                )
                await write_stream.send(_wire_session_notify("notifications/initialized"))
                await write_stream.send(_wire_session_req(2, "tools/list"))
                await write_stream.send(
                    _wire_session_req(
                        3,
                        "tools/call",
                        {"name": "auditor_gateway_capabilities", "arguments": {}},
                    )
                )
                await write_stream.send(
                    _wire_session_req(
                        4,
                        "tools/call",
                        {"name": "nonexistent_tool", "arguments": {}},
                    )
                )
                # Unsupported legacy notification/method test
                await write_stream.send(_wire_session_req(5, "subscriptions/listen", {"notifications": {"toolsListChanged": True}}))

                resps, notifs = await _collect_server_messages(read_stream, {1, 2, 3, 4, 5})
                assert notifs == []
                assert resps[1]["result"]["protocolVersion"] == proto_ver
                assert resps[1]["result"]["capabilities"]["tools"]["listChanged"] is True

                tools = resps[2]["result"]["tools"]
                assert len(tools) >= 10
                # 2024-11-05 & 2025-03-26 omit outputSchema & structuredContent; >= 2025-06-18 include both
                expect_structured = proto_ver in ("2025-06-18", "2025-11-25")
                first_tool = next(t for t in tools if t["name"] == "auditor_gateway_capabilities")
                assert ("outputSchema" in first_tool) is expect_structured

                cap_res = resps[3]["result"]
                assert cap_res["isError"] is False
                assert ("structuredContent" in cap_res) is expect_structured
                body = json.loads(cap_res["content"][0]["text"])
                assert body["protocol_version"] == proto_ver
                assert body["execution_authorized"] is False

                unknown_tool_res = resps[4]["result"]
                assert unknown_tool_res["isError"] is True
                assert "TOOL_NOT_FOUND" in unknown_tool_res["content"][0]["text"]

                # Modern method rejected on legacy handshake connection
                assert "error" in resps[5]

    anyio.run(_run)


def test_a02_legacy_unsupported_version_and_legacy_notifications_inproc() -> None:
    """Legacy version fallback + legacy notifications/tools/list_changed capability gating."""
    with tempfile.TemporaryDirectory() as td:
        gw = build_disposable_gateway(Path(td) / "a02.db")
        bridge = GatewaySDKv2Bridge(gateway=gw, caller_context=build_caller("verified_full"))
        server = bridge.build_lowlevel_server()

        received_notifs: list[str] = []

        async def _msg_handler(msg: Any) -> None:
            if isinstance(msg, types.ServerNotification):
                received_notifs.append(type(msg.root).__name__)

        async def _run() -> None:
            import warnings

            # 1. SDK Client(mode="legacy") negotiates 2025-11-25 cleanly with no errors
            async with Client(server, mode="legacy", message_handler=_msg_handler) as client:
                assert client.protocol_version == "2025-11-25"
                listed = await client.list_tools()
                assert len(listed.tools) >= 10
                with pytest.warns(UserWarning):
                    await client.send_ping()

            # 2. Propose unsupported old version "1999-01-01" directly over in-memory transport -> negotiates conservative fallback 2025-11-25
            from mcp.client._memory import InMemoryTransport

            async with InMemoryTransport(server) as (rs, ws):
                await ws.send(
                    _wire_session_req(
                        1,
                        "initialize",
                        {
                            "protocolVersion": "1999-01-01",
                            "capabilities": {},
                            "clientInfo": {"name": "legacy-old", "version": "0.1"},
                        },
                    )
                )
                resps, _ = await _collect_server_messages(rs, {1})
                assert resps[1]["result"]["protocolVersion"] == "2025-11-25"

            # Verify NotificationManager never sends legacy notification without capability
            from mcp_gateway.contracts import ClientCompatibilityProfile, CompatibilityState, ProtocolEra

            no_notif_prof = ClientCompatibilityProfile(
                application_id="antigravity",
                protocol_version="2025-11-25",
                protocol_era=ProtocolEra.LEGACY,
                notification_state=CompatibilityState.NOT_SUPPORTED,
                tool_list_refresh_state=CompatibilityState.NOT_SUPPORTED,
            )
            assert gw.notifications.emit_tools_changed(
                principal_id="qual-full",
                profile=no_notif_prof,
                catalog_version="v1",
                reason="test",
            ) is None
            with_notif_prof = ClientCompatibilityProfile(
                application_id="antigravity",
                protocol_version="2025-11-25",
                protocol_era=ProtocolEra.LEGACY,
                notification_state=CompatibilityState.USER_REPORTED,
                tool_list_refresh_state=CompatibilityState.USER_REPORTED,
            )
            emitted = gw.notifications.emit_tools_changed(
                principal_id="qual-full",
                profile=with_notif_prof,
                catalog_version="v1",
                reason="test",
            )
            assert emitted is not None and emitted["method"] == "notifications/tools/list_changed"

        anyio.run(_run)


# ---------------------------------------------------------------------------
# B. MODERN 2026-07-28 WIRE TESTS (DISCOVER, SUBSCRIPTIONS, MULTI-ROUND-TRIP)
# ---------------------------------------------------------------------------


def test_b01_modern_2026_07_28_discover_stateless_and_calls_over_subprocess_stdio(tmp_path: Path) -> None:
    """Real subprocess stdio Client(mode='auto') and Client(mode='2026-07-28') verify 2026-07-28 wire."""
    db_path = tmp_path / "b01_modern.db"

    async def _run() -> None:
        # 1. Auto mode -> sends server/discover, adopts 2026-07-28 directly (zero initialize!)
        async with Client(_stdio_params(mode="sdk-bridge", db_path=db_path), mode="auto") as client:
            assert client.protocol_version == "2026-07-28"
            assert client.session.discover_result is not None
            assert "2026-07-28" in client.session.discover_result.supported_versions
            assert client.session.initialize_result is None

            listed = await client.list_tools()
            assert len(listed.tools) >= 10
            res = await client.call_tool("auditor_gateway_capabilities", {})
            assert res.is_error is False
            assert res.structured_content is not None
            assert res.structured_content["protocol_era"] == "MODERN"
            assert res.structured_content["protocol_version"] == "2026-07-28"
            assert res.structured_content["execution_authorized"] is False

        # 2. Pinned 2026-07-28 mode -> no server/discover probe, direct per-request envelope calls work
        async with Client(_stdio_params(mode="sdk-bridge", db_path=db_path), mode="2026-07-28") as pinned:
            assert pinned.protocol_version == "2026-07-28"
            res2 = await pinned.call_tool("auditor_get_status", {})
            assert res2.is_error is False
            assert res2.structured_content is not None

    anyio.run(_run)


def test_b02_modern_subscriptions_listen_filtering_dedupe_authz_and_disconnect() -> None:
    """Test SEP-2575 subscriptions/listen opt-in filter, dedupe, ordering, authz gate, and SubscriptionLost."""
    with tempfile.TemporaryDirectory() as td:
        gw = build_disposable_gateway(Path(td) / "b02.db")
        bridge = GatewaySDKv2Bridge(gateway=gw, caller_context=build_caller("verified_full"))
        server = bridge.build_lowlevel_server()

        async def _run() -> None:
            # 1. Opt in ONLY to tools_list_changed (NOT prompts/resources)
            async with Client(server, mode="auto") as client:
                assert client.protocol_version == "2026-07-28"
                seen: list[Any] = []

                async with client.listen(tools_list_changed=True, prompts_list_changed=False) as sub:
                    assert sub.honored.tools_list_changed is True
                    assert sub.honored.prompts_list_changed is None

                    # Publish: unrequested PromptsListChanged + unauthorized account resource update + authorized ToolsListChanged (x2 duplicate)
                    from mcp.server.subscriptions import PromptsListChanged

                    await bridge._subscription_bus.publish(PromptsListChanged())
                    denied_pub = await bridge.publish_resource_updated_if_authorized(
                        uri="auditor://accounts/acct-other-tenant/summary",
                        required_account_context_id="acct-other-tenant",
                    )
                    assert denied_pub is False

                    assert await bridge.publish_tools_changed_if_authorized(reason="qual_update_1") is True
                    assert await bridge.publish_tools_changed_if_authorized(reason="qual_update_dup") is True

                    with anyio.fail_after(3):
                        ev = await anext(sub)
                        seen.append(ev)

                assert seen == [ToolsListChanged()]

            # 2. Unknown/unauthenticated caller MUST be rejected from subscriptions/listen!
            unauth_bridge = GatewaySDKv2Bridge(gateway=gw, caller_context=build_caller("unknown"))
            async with Client(unauth_bridge.build_lowlevel_server(), mode="auto") as unauth_client:
                with pytest.raises(MCPError) as exc_info:
                    async with unauth_client.listen(tools_list_changed=True):
                        pass
                assert "UNAUTHORIZED_SUBSCRIPTION" in exc_info.value.message

            # 3. Stale policy generation caller MUST be rejected from publishing & listening!
            gw.authz.min_active_policy_generation = 5
            stale_bridge = GatewaySDKv2Bridge(gateway=gw, caller_context=build_caller("stale_policy"))
            assert await stale_bridge.publish_tools_changed_if_authorized() is False
            async with Client(stale_bridge.build_lowlevel_server(), mode="auto") as stale_client:
                with pytest.raises(MCPError) as stale_exc:
                    async with stale_client.listen(tools_list_changed=True):
                        pass
                assert "STALE_POLICY_GENERATION" in stale_exc.value.message

            # 4. Abrupt subprocess disconnect mid-listen raises SubscriptionLost, and fresh client reconnects cleanly
            gw.authz.min_active_policy_generation = 0
            crash_db = Path(td) / "b02_crash_sub.db"
            saw_subscription_lost = False
            with suppress(Exception):
                async with Client(
                    _stdio_params(mode="sdk-bridge", db_path=crash_db, extra_args=["--crash-after-calls", "1"]),
                    mode="auto",
                ) as sub_proc_client:
                    with suppress(Exception):
                        async with sub_proc_client.listen(tools_list_changed=True) as sub_disc:
                            async def _trigger_crash() -> None:
                                await anyio.sleep(0.05)
                                with suppress(Exception):
                                    await sub_proc_client.call_tool("auditor_gateway_capabilities", {})

                            async with anyio.create_task_group() as tg:
                                tg.start_soon(_trigger_crash)
                                try:
                                    await anext(sub_disc)
                                except SubscriptionLost:
                                    saw_subscription_lost = True
            assert saw_subscription_lost is True

            # Fresh reconnect over new subprocess recovers listen cleanly
            async with Client(
                _stdio_params(mode="sdk-bridge", db_path=crash_db),
                mode="auto",
            ) as rec_client:
                async with rec_client.listen(tools_list_changed=True) as sub_reconn:
                    assert sub_reconn.honored.tools_list_changed is True

        anyio.run(_run)


def test_b03_modern_multi_round_trip_and_unsupported_version_rejection(tmp_path: Path) -> None:
    """Verify 2026-07-28 multi-round-trip InputRequiredResult over real subprocess stdio + -32022 rejection."""
    db_path = tmp_path / "b03_mrt.db"
    elicit_calls: list[str] = []

    async def _elicitation_handler(_ctx: Any, params: Any) -> Any:
        elicit_calls.append(params.message)
        return types.ElicitResult(action="accept", content={"detail": "summary"})

    async def _run() -> None:
        # 1. Multi-round-trip over real subprocess stdio in 2026-07-28
        async with Client(
            _stdio_params(mode="sdk-bridge", db_path=db_path, extra_args=["--enable-multi-round-trip"]),
            mode="auto",
            elicitation_callback=_elicitation_handler,
        ) as client:
            assert client.protocol_version == "2026-07-28"
            res = await client.call_tool("auditor_gateway_capabilities", {})
            assert res.is_error is False
            assert len(elicit_calls) == 1
            assert res.structured_content is not None
            assert res.structured_content["execution_authorized"] is False

        # 2. Unsupported future version header "-32022" & initialize-after-modern "-32022" on subprocess stdio
        async with stdio_client(_stdio_params(mode="sdk-bridge", db_path=db_path)) as (rs, ws):
            await ws.send(
                _wire_session_req(
                    1,
                    "tools/list",
                    {
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2099-01-01",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        }
                    },
                )
            )
            await ws.send(
                _wire_session_req(
                    2,
                    "server/discover",
                    {
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        }
                    },
                )
            )
            await ws.send(
                _wire_session_req(
                    3,
                    "initialize",
                    {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "late", "version": "1"}},
                )
            )
            resps, _ = await _collect_server_messages(rs, {1, 2, 3})
            assert resps[1]["error"]["code"] == types.UNSUPPORTED_PROTOCOL_VERSION  # -32022
            assert "supported" in resps[1]["error"]["data"]
            assert "result" in resps[2]
            assert resps[3]["error"]["code"] == types.UNSUPPORTED_PROTOCOL_VERSION  # -32022

    anyio.run(_run)


# ---------------------------------------------------------------------------
# C. CROSS-PROCESS INTEROP (NEXT-22D LEGACY HOST + SDK BRIDGE + CRASH/RESTART)
# ---------------------------------------------------------------------------


def test_c01_sdk_client_against_next22d_legacy_host_and_crash_recovery(tmp_path: Path) -> None:
    """SDK v2.3.0 Client(mode='auto' & 'legacy') interops with NEXT-22D CommonStdioAdapterHost; child crash & restart recovers."""
    db_path = tmp_path / "c01_interop.db"

    async def _run() -> None:
        # 1. SDK Client(mode='auto') -> NEXT-22D CommonStdioAdapterHost falls back from server/discover to 2025-11-25!
        async with Client(
            _stdio_params(mode="legacy-adapter", db_path=db_path, caller="verified_full"),
            mode="auto",
        ) as client:
            assert client.protocol_version == "2025-11-25"
            assert client.session.initialize_result is not None
            tools = await client.list_tools()
            assert any(t.name == "auditor_gateway_capabilities" for t in tools.tools)
            res = await client.call_tool("auditor_gateway_capabilities", {})
            assert res.is_error is False
            data = json.loads(res.content[0].text)
            assert data["execution_authorized"] is False

        # 2. Unexpected child crash mid-session followed by clean restart on fresh client
        with pytest.raises(Exception):
            async with Client(
                _stdio_params(
                    mode="sdk-bridge",
                    db_path=db_path,
                    extra_args=["--crash-after-calls", "1"],
                ),
                mode="auto",
            ) as crashing_client:
                await crashing_client.call_tool("auditor_gateway_capabilities", {})

        # Fresh restart succeeds cleanly with zero stale state
        async with Client(_stdio_params(mode="sdk-bridge", db_path=db_path), mode="auto") as recovered:
            res = await recovered.call_tool("auditor_gateway_capabilities", {})
            assert res.is_error is False

    anyio.run(_run)


# ---------------------------------------------------------------------------
# D. AUTHORIZATION & SECURITY ENFORCEMENT ON EVERY CALL (BOTH ERAS)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("connect_mode", ["legacy", "auto"])
def test_d01_authorization_enforced_per_call_across_both_eras_no_tools_list_trust(
    tmp_path: Path, connect_mode: str
) -> None:
    """Prove tools/list NEVER authorizes tools/call: test revoked-after-list, unknown identity, stale policy, hidden tool, spoofed meta, secrets."""
    db_path = tmp_path / f"d01_{connect_mode}.db"

    async def _run() -> None:
        # 1. Tool listed in tools/list, then scope revoked BEFORE direct tools/call!
        async with Client(
            _stdio_params(mode="sdk-bridge", db_path=db_path, caller="revoke_after_list"),
            mode=connect_mode,
        ) as rev_client:
            listed = await rev_client.list_tools()
            names = {t.name for t in listed.tools}
            assert "auditor_routing_inspect_profile" in names
            call_res = await rev_client.call_tool(
                "auditor_routing_inspect_profile",
                {"user_profile_id": "usr-qual"},
            )
            assert call_res.is_error is True
            assert "MISSING_SCOPE" in call_res.content[0].text

        # 2. Direct call WITHOUT calling tools/list first:
        #    2a. Unauthenticated caller ("unknown") fails closed on ALL tools including hidden execution tools!
        async with Client(
            _stdio_params(mode="sdk-bridge", db_path=db_path, caller="unknown"),
            mode=connect_mode,
            client_info=Implementation(name="claude-desktop-admin", version="99.0"),
        ) as unauth_client:
            for hidden_or_priv, priv_args in (
                ("auditor_routing_inspect_profile", {"user_profile_id": "usr-qual"}),
                ("auditor_authorize_execution", {"project_key": "proj-qual", "approved_finding_ids": ["f1"]}),
                ("auditor_gateway_capabilities", {}),
            ):
                r = await unauth_client.call_tool(hidden_or_priv, priv_args)
                assert r.is_error is True
                assert "UNAUTHORIZED_CALLER" in r.content[0].text or "TOOL_NOT_FOUND" in r.content[0].text or "SCHEMA_VALIDATION_FAILED" in r.content[0].text

        #    2b. Authenticated but unverified application identity clamped to CORE_READ; cannot call routing/project tools
        async with Client(
            _stdio_params(mode="sdk-bridge", db_path=db_path, caller="auth_unknown_app"),
            mode=connect_mode,
            client_info=Implementation(name="claude-desktop-admin", version="99.0"),
        ) as unk_client:
            routing_call = await unk_client.call_tool(
                "auditor_routing_inspect_profile",
                {"user_profile_id": "usr-qual"},
            )
            assert routing_call.is_error is True
            assert "UNKNOWN_IDENTITY_READONLY_ONLY" in routing_call.content[0].text

            # Malformed arguments rejected strictly without echoing secret
            bad_args = await unk_client.call_tool(
                "auditor_gateway_capabilities",
                {"_unexpected_spoof_field": "sk-secret1234567890abcdef"},
            )
            assert bad_args.is_error is True
            assert "SCHEMA_VALIDATION_FAILED" in bad_args.content[0].text
            assert "sk-secret1234567890abcdef" not in bad_args.content[0].text

            # Public read-only capability query succeeds even without tools/list and stays non-executing
            ok_read = await unk_client.call_tool("auditor_gateway_capabilities", {})
            assert ok_read.is_error is False
            payload = json.loads(ok_read.content[0].text)
            assert payload["application_id"] == "UNKNOWN"
            assert payload["verified_application_identity"] is False
            assert payload["execution_authorized"] is False

        # 3. Stale policy generation blocked on every call
        async with Client(
            _stdio_params(mode="sdk-bridge", db_path=db_path, caller="stale_policy"),
            mode=connect_mode,
        ) as stale_client:
            res = await stale_client.call_tool("auditor_get_status", {})
            assert res.is_error is True
            assert "UNAUTHORIZED_CALLER" in res.content[0].text

    anyio.run(_run)


# ---------------------------------------------------------------------------
# E. RESILIENCE: STDOUT/STDERR PURITY, CANCELLATION, TIMEOUT, LOOPBACK HTTP
# ---------------------------------------------------------------------------


def test_e01_stdout_purity_under_stray_print_and_prompt_cancellation_with_no_orphans(tmp_path: Path) -> None:
    """Stray print() inside handler cannot corrupt MCP stdio stream; cancelling mid-call aborts before privileged execution."""
    db_path = tmp_path / "e01_resilience.db"
    marker = tmp_path / "privileged_marker.txt"

    async def _run() -> None:
        # 1. Stray stdout noise + Python warning inside subprocess: SDK fd diversion redirects stray print to stderr!
        err_path = tmp_path / "e01_stderr.log"
        with open(err_path, "w", encoding="utf-8") as errlog:
            transport = stdio_client(
                _stdio_params(
                    mode="sdk-bridge",
                    db_path=db_path,
                    extra_args=[
                        "--stray-stdout-noise",
                        "STRAY_PRINT_MUST_NOT_CORRUPT_WIRE",
                        "--emit-warning",
                    ],
                ),
                errlog=errlog,
            )
            async with Client(transport, mode="auto") as client:
                r1 = await client.call_tool("auditor_gateway_capabilities", {})
                r2 = await client.call_tool("auditor_get_status", {})
                assert r1.is_error is False and r2.is_error is False
        err_text = err_path.read_text(encoding="utf-8", errors="replace")
        assert "STRAY_PRINT_MUST_NOT_CORRUPT_WIRE" in err_text
        assert "warning" in err_text.lower()

        # 2. Request cancellation stops slow handler BEFORE writing privileged marker file
        async with Client(
            _stdio_params(
                mode="sdk-bridge",
                db_path=db_path,
                extra_args=["--delay-before-work", "3.0", "--marker-file", str(marker)],
            ),
            mode="auto",
        ) as slow_client:
            listed = await slow_client.list_tools()
            assert len(listed.tools) >= 10
            with anyio.move_on_after(0.25) as scope:
                await slow_client.call_tool("auditor_gateway_capabilities", {})
            assert scope.cancelled_caught is True

        # Give child process a brief moment on exit; marker file must NEVER be created!
        await anyio.sleep(0.15)
        assert not marker.exists()

        # 3. Legacy notifications/cancelled wire frame cancels slow in-flight call on subprocess stdio
        legacy_marker = tmp_path / "legacy_cancelled_marker.txt"
        async with stdio_client(
            _stdio_params(
                mode="sdk-bridge",
                db_path=db_path,
                extra_args=["--delay-before-work", "3.0", "--marker-file", str(legacy_marker)],
            )
        ) as (rs, ws):
            await ws.send(
                _wire_session_req(
                    1,
                    "initialize",
                    {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "cancel-legacy", "version": "1.0"},
                    },
                )
            )
            await ws.send(_wire_session_notify("notifications/initialized"))
            resps_init, _ = await _collect_server_messages(rs, {1})
            assert resps_init[1]["result"]["protocolVersion"] == "2025-11-25"

            await ws.send(
                _wire_session_req(
                    99,
                    "tools/call",
                    {"name": "auditor_gateway_capabilities", "arguments": {}},
                )
            )
            await anyio.sleep(0.15)
            await ws.send(
                _wire_session_notify(
                    "notifications/cancelled",
                    {"requestId": 99, "reason": "next22e_legacy_cancel_test"},
                )
            )
            await anyio.sleep(0.25)
        assert not legacy_marker.exists()

    anyio.run(_run)


def test_e02_disposable_loopback_streamable_http_study_and_clean_shutdown(tmp_path: Path) -> None:
    """Part 8 Study: 127.0.0.1 ephemeral port stateless Streamable HTTP check; REMOTE_MCP_DISABLED remains True."""
    assert REMOTE_MCP_DISABLED is True
    gw = build_disposable_gateway(tmp_path / "e02_http.db")
    bridge = GatewaySDKv2Bridge(gateway=gw, caller_context=build_caller("verified_full"))
    asgi_app = bridge.build_loopback_asgi_app(stateless_http=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    config = uvicorn.Config(asgi_app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    try:
        deadline = time.monotonic() + 10.0
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        assert server.started is True

        async def _check_http() -> None:
            url = f"http://127.0.0.1:{port}/mcp"
            async with Client(url, mode="2026-07-28") as client:
                assert client.protocol_version == "2026-07-28"
                tools = await client.list_tools()
                assert len(tools.tools) >= 10
                res = await client.call_tool("auditor_gateway_capabilities", {})
                assert res.is_error is False
                assert res.structured_content is not None
                assert res.structured_content["execution_authorized"] is False

        anyio.run(_check_http)
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)

    # Verify socket listener is genuinely gone after shutdown
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as verify_sock:
        err = verify_sock.connect_ex(("127.0.0.1", port))
        assert err != 0

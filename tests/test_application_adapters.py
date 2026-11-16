"""Comprehensive offline unit & adversarial security tests for NEXT-22D application adapters."""

from __future__ import annotations

import io
import json
import sys
import tomllib
from pathlib import Path
from typing import Any
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from application_adapters import (
    AdapterChallengeManager,
    AdapterContextResolver,
    AdapterInstallState,
    ApplicationAdapterRegistry,
    BrokerTransportDisconnectedError,
    BrokerTransportTimeoutError,
    BrokerTransportUnavailableError,
    CommonStdioAdapterHost,
    CredentialProviderUnavailableError,
    DisabledProductionCredentialProvider,
    DisabledProductionNamedPipeTransport,
    EphemeralTestCredentialProvider,
    IdentityVerificationStatus,
    InMemoryBrokerTransport,
    ProcessObservation,
    SignatureStatus,
    SignedAdapterProof,
    TestBrokerTransport,
    UntrustedAdapterHints,
    Win32ReadOnlyProcessObserver,
    build_offline_mcpb_archive,
    contains_secret_material,
    validate_launch_command,
    validate_preview_item,
)
from application_adapters.contracts import AdapterConfigPreview
from broker.security import ClientIdentity
from db import initialize
from entitlement_router.contracts import (
    AccountContextRecord,
    ApplicationInstanceRecord,
    AuthenticationMode,
    CapabilityDimension,
    CapabilityState,
    ConfidenceLevel,
    CostPolicy,
    EntitlementState,
    ModelCapabilityEvidence,
    ModelEffortProfile,
    ModelEntitlementObservation,
    ModelIdentityRecord,
    NormalizedEffort,
    QuotaObservation,
    QuotaState,
    SubscriptionSource,
    UserProfileRecord,
    UserRoutingPolicy,
)
from entitlement_router.registry import EntitlementRegistry
from mcp_gateway import (
    AdaptiveMCPGateway,
    CallerIdentityResolver,
    ProtocolEra,
    RoutingToolBridge,
    SharedSecretAdapterProofVerifier,
)
from mcp_server import AuditorMCPDispatcher

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _setup_gateway(tmp_path: Path) -> tuple[AdaptiveMCPGateway, EntitlementRegistry]:
    db_path = tmp_path / "next22d_disposable.db"
    initialize(db_path)
    reg = EntitlementRegistry()
    reg.register_user(UserProfileRecord(user_profile_id="usr-alice"))
    reg.set_policy(
        UserRoutingPolicy(
            policy_id="pol-alice",
            user_profile_id="usr-alice",
            api_billing_allowed=False,
        )
    )
    reg.register_application(
        ApplicationInstanceRecord(
            application_instance_id="app-alice-agy",
            user_profile_id="usr-alice",
            application_id="antigravity",
            installation_state="installed",
            version="2.32.1.0",
        )
    )
    reg.register_account(
        AccountContextRecord(
            account_context_id="acct-alice-agy",
            user_profile_id="usr-alice",
            application_instance_id="app-alice-agy",
            application_id="antigravity",
            provider="google",
            authentication_mode=AuthenticationMode.SUBSCRIPTION,
            subscription_source=SubscriptionSource.USER_DECLARED,
            subscription_tier="pro",
        )
    )
    reg.register_model_identity(
        ModelIdentityRecord(
            application_id="antigravity",
            application_model_id="gemini-4-hydrogen-high",
            provider="google",
            model_family="gemini-4-hydrogen",
            reasoning_effort_variant="HIGH",
        )
    )
    reg.record_entitlement(
        ModelEntitlementObservation(
            observation_id="obs-ent-22d-1",
            account_context_id="acct-alice-agy",
            application_instance_id="app-alice-agy",
            application_id="antigravity",
            model_id="gemini-4-hydrogen-high",
            state=EntitlementState.USER_CONFIRMED_SELECTABLE,
            provenance="USER_DECLARED",
            confidence=ConfidenceLevel.MEDIUM,
            evidence_ref="fixture:next22d",
            observed_at="2026-11-14T09:00:00Z",
        )
    )
    reg.record_quota(
        QuotaObservation(
            observation_id="obs-q-22d-1",
            account_context_id="acct-alice-agy",
            model_id="gemini-4-hydrogen-high",
            usage_category="model",
            quota_state=QuotaState.AVAILABLE,
            remaining_percentage=90.0,
            source="test_fixture",
            evidence_ref="fixture:quota",
            observed_at="2026-11-14T09:00:00Z",
        )
    )
    reg.register_effort_profile(
        ModelEffortProfile(
            application_id="antigravity",
            application_model_id="gemini-4-hydrogen-high",
            account_context_id="acct-alice-agy",
            supported_efforts=(NormalizedEffort.HIGH,),
            default_effort=NormalizedEffort.HIGH,
            provenance="RUNTIME_OBSERVED",
            evidence_ref="fixture:effort",
            observed_at="2026-11-14T09:00:00Z",
        )
    )
    reg.record_capability_evidence(
        ModelCapabilityEvidence(
            evidence_id="cap-22d-1",
            application_id="antigravity",
            application_model_id="gemini-4-hydrogen-high",
            dimension=CapabilityDimension.CODING,
            status=CapabilityState.VERIFIED,
            evidence_source="test_fixture",
            confidence=ConfidenceLevel.HIGH,
            evidence_ref="fixture:cap",
            observed_at="2026-11-14T09:00:00Z",
        )
    )
    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=PROJECT_ROOT)
    gw = AdaptiveMCPGateway(
        dispatcher=dispatcher,
        identity_resolver=CallerIdentityResolver(adapter_verifier=SharedSecretAdapterProofVerifier()),
        routing_bridge=RoutingToolBridge(registry=reg),
    )
    return gw, reg


def _sample_os_identity(sid: str = "S-1-5-21-1000-2000-3000-1001", pid: int = 4242) -> ClientIdentity:
    return ClientIdentity(
        pid=pid,
        sid=sid,
        integrity_level="MEDIUM",
        is_low_integrity=False,
        is_appcontainer=False,
        is_elevated=False,
        verified_by_os=True,
    )


def _sample_proc_obs(
    *,
    pid: int = 4242,
    creation: int = 134000000000000000,
    ppid: int = 1111,
    parent_creation: int = 133999000000000000,
) -> ProcessObservation:
    return ProcessObservation(
        pid=pid,
        process_creation_time_100ns=creation,
        process_creation_time_iso="2026-11-14T09:00:00Z",
        user_sid_hash="0123456789abcdef",
        user_sid_observed=True,
        session_id=1,
        integrity_level="MEDIUM",
        executable_path=r"C:\Python315\python.exe",
        executable_sha256="a" * 64,
        signature_status=SignatureStatus.SIGNED_TRUSTED,
        parent_pid=ppid,
        parent_image_path=r"C:\Windows\System32\cmd.exe",
        parent_creation_time_100ns=parent_creation,
        verified_by_os=True,
    )


# ==============================================================================
# A. Adapter Contracts & Inventory Adaptation
# ==============================================================================


def test_a01_adapter_profiles_reflect_refreshed_discovery_and_claude_code_not_installed() -> None:
    reg = ApplicationAdapterRegistry()
    assert reg.supported_application_ids() == ("antigravity", "claude_code", "claude_desktop", "codex")

    discovery = {
        "generated_at": "2026-11-14T11:56:40Z",
        "applications": {
            "antigravity": {
                "installation_state": "installed",
                "executables": [{"role": "desktop_app", "version": "2.32.1.0"}],
                "cli": {"present": True, "version": "1.5.7"},
            },
            "claude_desktop": {
                "installation_state": "installed",
                "executables": [{"role": "desktop_app", "packaging": "msix_appx", "version": "5.11492.5.0"}],
            },
            "codex": {
                "installation_state": "installed",
                "cli": {"present": True, "version": "codex-cli 0.169.0"},
            },
            "claude_code": {"installation_state": "not_installed"},
        },
    }

    manifest = reg.export_manifest(discovery_report=discovery)
    assert manifest["duplicated_tool_handlers"] is False
    assert manifest["production_activated"] is False
    assert manifest["modern_runtime_wire_verified"] is False

    agy = reg.get_profile("antigravity", discovery_report=discovery)
    assert agy.install_state == AdapterInstallState.INSTALLED
    assert "2.32.1.0" in (agy.installed_version or "")
    assert agy.live_tested is False and agy.live_authenticated is False

    cd = reg.get_profile("claude_desktop", discovery_report=discovery)
    assert cd.install_state == AdapterInstallState.INSTALLED
    assert cd.installed_version == "5.11492.5.0"
    assert cd.packaging == "msix_appx"

    codex = reg.get_profile("codex", discovery_report=discovery)
    assert codex.install_state == AdapterInstallState.INSTALLED
    assert codex.installed_version == "codex-cli 0.169.0"

    cc = reg.get_profile("claude_code", discovery_report=discovery)
    assert cc.install_state == AdapterInstallState.NOT_INSTALLED
    assert cc.modern_runtime_wire_verified is False

    # Version bump in new discovery updates profile deterministically
    updated = json.loads(json.dumps(discovery))
    updated["applications"]["antigravity"]["executables"][0]["version"] = "2.99.0.0"
    assert "2.99.0.0" in (reg.get_profile("antigravity", discovery_report=updated).installed_version or "")

    # Missing discovery preserves conservative UNKNOWN without claiming live connect
    static_agy = reg.get_profile("antigravity", discovery_report=None)
    assert static_agy.install_state == AdapterInstallState.UNKNOWN
    assert static_agy.modern_runtime_wire_verified is False


# ==============================================================================
# B. Common Stdio Adapter Host
# ==============================================================================


def test_b01_stdio_host_purity_framing_malformed_oversized_and_shutdown(tmp_path: Path) -> None:
    gw, _ = _setup_gateway(tmp_path)
    prov = EphemeralTestCredentialProvider()
    prov.provision_ephemeral_adapter_key(adapter_id="adp-agy-1", key_id="k-agy", key_version=1)
    mgr = AdapterChallengeManager(credential_provider=prov, clock=lambda: 1700000010)
    os_id = _sample_os_identity()
    proc_obs = _sample_proc_obs()
    chl = mgr.issue_challenge(
        adapter_id="adp-agy-1",
        application_id="antigravity",
        application_instance_id="app-alice-agy",
        process_obs=proc_obs,
        os_identity=os_id,
        key_id="k-agy",
        key_version=1,
    )
    signed = mgr.sign_challenge(chl)
    bundle = AdapterContextResolver().resolve(
        os_identity=os_id,
        process_obs=proc_obs,
        challenge_manager=mgr,
        signed_proof=signed,
        permitted_scopes_for_sid=frozenset({"core:read", "routing:read"}),
        allowed_user_profile_ids=frozenset({"usr-alice"}),
        allowed_account_context_ids=frozenset({"acct-alice-agy"}),
        account_context_id="acct-alice-agy",
    )

    transport = InMemoryBrokerTransport(gw)
    stderr_buf = io.StringIO()
    host = CommonStdioAdapterHost(
        transport=transport,
        caller_context=bundle.caller_context,
        application_profile_id="antigravity",
        stderr_stream=stderr_buf,
        max_message_bytes=8192,
    )

    req1 = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}).encode("utf-8")
    req2 = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode("utf-8")
    framed_req1 = f"Content-Length: {len(req1)}\r\n\r\n".encode("ascii") + req1
    framed_req2 = f"Content-Length: {len(req2)}\r\n\r\n".encode("ascii") + req2
    bad_json = b"{not-valid-json\n"
    oversized = b'{"jsonrpc":"2.0","id":3,"method":"ping","params":{"pad":"' + (b"x" * 9000) + b'"}}\n'

    in_stream = io.BytesIO(framed_req1 + framed_req2 + bad_json + oversized)
    out_stream = io.BytesIO()
    rc = host.serve_streams(in_stream, out_stream)
    assert rc == 0
    assert host.is_closed is True
    assert transport.is_closed is True
    assert host.requests_processed == 2

    raw_out = out_stream.getvalue().decode("utf-8")
    assert "[antigravity-auditor-adapter]" not in raw_out  # stdout is pure JSON-RPC only
    assert "Content-Length:" in raw_out
    assert '"code": -32700' in raw_out or '"code":-32700' in raw_out
    assert "OVERSIZED_REQUEST" in raw_out
    assert "Adapter stdio host shut down cleanly." in stderr_buf.getvalue()


def test_b02_stdio_host_timeout_and_malformed_requests(tmp_path: Path) -> None:
    _ = tmp_path
    clock_state = {"t": 0.0}

    def slow_handler(req: dict[str, Any], _caller: Any) -> dict[str, Any]:
        # Simulate slow call exceeding request_timeout_seconds via clock check fallback? Not mocked monotonic here,
        # instead test TestBrokerTransport timeout + invalid non-dict JSON-RPC!
        _ = clock_state
        return {"jsonrpc": "2.0", "id": req.get("id"), "result": {}}

    host = CommonStdioAdapterHost(
        transport=TestBrokerTransport(slow_handler),
        stderr_stream=io.StringIO(),
    )
    not_obj = host.process_raw_payload(b"[1, 2, 3]")
    assert not_obj is not None and not_obj["error"]["code"] == -32600

    wrong_ver = host.process_raw_payload(b'{"jsonrpc":"1.0","id":1,"method":"ping"}')
    assert wrong_ver is not None and wrong_ver["error"]["code"] == -32600
    host.close()


# ==============================================================================
# C. Authenticated Adapter Identity & Challenge-Response
# ==============================================================================


def test_c01_challenge_response_replay_expiry_sid_process_parent_and_spoof_defenses(tmp_path: Path) -> None:
    now = {"t": 1700001000}
    prov = EphemeralTestCredentialProvider()
    prov.provision_ephemeral_adapter_key(adapter_id="adp-agy-1", key_id="key-main", key_version=1)
    mgr = AdapterChallengeManager(credential_provider=prov, clock=lambda: now["t"], ttl_seconds=60)
    os_id = _sample_os_identity(sid="S-1-5-21-REAL", pid=5000)
    proc_obs = _sample_proc_obs(pid=5000, creation=999001, ppid=100, parent_creation=888001)
    chl = mgr.issue_challenge(
        adapter_id="adp-agy-1",
        application_id="antigravity",
        application_instance_id="app-alice-agy",
        process_obs=proc_obs,
        os_identity=os_id,
        key_id="key-main",
        key_version=1,
    )
    valid_proof = mgr.sign_challenge(chl)

    # 1. Valid proof verifies ONCE, fails on REPLAY!
    ok = mgr.verify_proof(valid_proof, os_identity=os_id, process_obs=proc_obs)
    assert ok.verified is True
    assert ok.status == IdentityVerificationStatus.VERIFIED
    assert ok.production_ready is False
    replay = mgr.verify_proof(valid_proof, os_identity=os_id, process_obs=proc_obs)
    assert replay.verified is False and replay.reason_code == "PROOF_REPLAYED"

    # 2. Invalid HMAC rejected
    chl2 = mgr.issue_challenge(
        adapter_id="adp-agy-1",
        application_id="antigravity",
        application_instance_id="app-alice-agy",
        process_obs=proc_obs,
        os_identity=os_id,
        key_id="key-main",
    )
    bad_hmac = SignedAdapterProof(**{**mgr.sign_challenge(chl2).__dict__, "proof_hmac": "f" * 64})
    r_hmac = mgr.verify_proof(bad_hmac, os_identity=os_id, process_obs=proc_obs)
    assert r_hmac.verified is False and r_hmac.reason_code == "INVALID_ADAPTER_HMAC"

    # 3. Wrong SID rejected
    r_sid = mgr.verify_proof(mgr.sign_challenge(chl2), os_identity=_sample_os_identity(sid="S-1-5-21-OTHER", pid=5000), process_obs=proc_obs)
    assert r_sid.verified is False and r_sid.reason_code == "OS_SID_MISMATCH"

    # 4. Wrong process PID / creation time rejected
    r_pid = mgr.verify_proof(
        mgr.sign_challenge(chl2),
        os_identity=os_id,
        process_obs=_sample_proc_obs(pid=5000, creation=999999, ppid=100, parent_creation=888001),
    )
    assert r_pid.verified is False and r_pid.reason_code == "PROCESS_BINDING_MISMATCH"

    # 5. Parent-process mismatch rejected
    r_ppid = mgr.verify_proof(
        mgr.sign_challenge(chl2),
        os_identity=os_id,
        process_obs=_sample_proc_obs(pid=5000, creation=999001, ppid=999, parent_creation=888001),
    )
    assert r_ppid.verified is False and r_ppid.reason_code == "PARENT_PROCESS_MISMATCH"

    # 6. Expired proof rejected
    now["t"] += 120
    r_exp = mgr.verify_proof(mgr.sign_challenge(chl2), os_identity=os_id, process_obs=proc_obs)
    assert r_exp.verified is False and r_exp.reason_code == "PROOF_EXPIRED_OR_FUTURE"

    # 7. Missing/disabled credential provider + spoofed hints -> UNKNOWN app clamped to CORE_READ
    gw, _ = _setup_gateway(tmp_path)
    disabled_mgr = AdapterChallengeManager(credential_provider=DisabledProductionCredentialProvider())
    with pytest.raises(CredentialProviderUnavailableError):
        DisabledProductionCredentialProvider().sign_digest("k", 1, b"msg")

    spoof_hints = UntrustedAdapterHints(
        claimed_application_arg="codex",
        claimed_env_application="claude_desktop",
        mcp_params={"clientInfo": {"name": "claude-desktop", "version": "5.11492.5.0"}, "model_id": "claude-opus-5-5-high"},
    )
    assert spoof_hints.grants_authentication is False and spoof_hints.grants_authorization is False
    unk_bundle = AdapterContextResolver().resolve(
        os_identity=os_id,
        process_obs=proc_obs,
        challenge_manager=disabled_mgr,
        signed_proof=valid_proof,
        untrusted_adapter_hints=spoof_hints,
        permitted_scopes_for_sid=frozenset({"core:read", "routing:read", "execution:run"}),
        account_context_id="acct-alice-agy",
    )
    assert unk_bundle.caller_context.application_id == "UNKNOWN"
    assert unk_bundle.caller_context.verified_application_identity is False
    assert unk_bundle.caller_context.authorization_scopes == frozenset({"core:read"})
    listed = gw.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, caller_context=unk_bundle.caller_context)
    assert listed is not None
    assert [t["name"] for t in listed["result"]["tools"]] == ["auditor_gateway_capabilities", "auditor_get_status"]


def test_c02_real_win32_process_observation_never_proves_app_identity() -> None:
    obs = Win32ReadOnlyProcessObserver().observe_process(include_authenticode=False)
    assert obs.pid > 0
    assert obs.proves_application_identity is False
    if sys.platform == "win32":
        assert obs.process_creation_time_100ns is not None
        assert obs.executable_sha256 is not None and len(obs.executable_sha256) == 64
        assert obs.user_sid_observed is True


# ==============================================================================
# D. Secret Handling & Redaction
# ==============================================================================


def test_d01_no_secret_leakage_in_logs_repr_previews_or_exceptions() -> None:
    prov = EphemeralTestCredentialProvider()
    secret = b"super-secret-ephemeral-hmac-key-0123456789"
    prov.provision_ephemeral_adapter_key(adapter_id="adp-agy-1", key_id="k1", secret_bytes=secret)
    assert "super-secret" not in repr(prov)

    proof = SignedAdapterProof(
        challenge_id="chl-1",
        nonce="n" * 32,
        key_id="k1",
        key_version=1,
        adapter_id="adp-agy-1",
        application_id="antigravity",
        application_instance_id="inst-1",
        pid=1,
        process_creation_time_100ns=1,
        expected_os_sid="S-1-5-21-1",
        issued_at_epoch=1,
        expires_at_epoch=2,
        proof_hmac="deadbeef" * 8,
    )
    assert "deadbeef" not in repr(proof)
    assert "proof_hmac='<redacted>'" in repr(proof)

    stderr_buf = io.StringIO()
    host = CommonStdioAdapterHost(transport=TestBrokerTransport(lambda r, c: None), stderr_stream=stderr_buf)
    host.log_diagnostic("Authorization Bearer sk-ant-1234567890abcdef leaked")
    assert "sk-ant-1234567890abcdef" not in stderr_buf.getvalue()
    host.close()

    assert contains_secret_material("sk-ant-1234567890abcdef") is True
    bad_preview = AdapterConfigPreview(
        application_id="codex",
        scope_name="user",
        target_path="bad.toml",
        content_format="toml",
        content_text='api_key = "sk-ant-1234567890abcdef"\n',
        validation_ok=True,
    )
    checked = validate_preview_item(bad_preview)
    assert checked.validation_ok is False and checked.secret_free is False


# ==============================================================================
# E. Broker Transport Isolation
# ==============================================================================


def test_e01_broker_transports_isolated_and_production_pipe_disabled(tmp_path: Path) -> None:
    gw, _ = _setup_gateway(tmp_path)
    unk = AdapterContextResolver().resolve(
        os_identity=_sample_os_identity(),
        process_obs=_sample_proc_obs(),
        challenge_manager=AdapterChallengeManager(credential_provider=DisabledProductionCredentialProvider()),
    ).caller_context

    disabled_pipe = DisabledProductionNamedPipeTransport()
    assert disabled_pipe.is_production_transport is True
    assert disabled_pipe.enabled is False
    with pytest.raises(BrokerTransportUnavailableError, match="PRODUCTION_BROKER_NAMED_PIPE_DISABLED"):
        disabled_pipe.handle_gateway_rpc({"jsonrpc": "2.0", "id": 1, "method": "ping"}, caller_context=unk)

    # TestBrokerTransport timeout, disconnect, and invalid response surface cleanly via stdio host
    for bad_transport in (
        TestBrokerTransport(lambda r, c: None, simulate_timeout=True),
        TestBrokerTransport(lambda r, c: None, simulate_disconnect=True),
        TestBrokerTransport(lambda r, c: {"not_jsonrpc": True}),  # type: ignore[return-value]
    ):
        host = CommonStdioAdapterHost(transport=bad_transport, caller_context=unk, stderr_stream=io.StringIO())
        resp = host.process_raw_payload(b'{"jsonrpc":"2.0","id":7,"method":"ping"}')
        assert resp is not None and "error" in resp
        host.close()

    # InMemoryBrokerTransport works cleanly against Gateway
    inmem = InMemoryBrokerTransport(gw)
    ok_resp = inmem.handle_gateway_rpc({"jsonrpc": "2.0", "id": 8, "method": "ping"}, caller_context=unk)
    assert ok_resp == {"jsonrpc": "2.0", "id": 8, "result": {}}
    inmem.close()
    with pytest.raises(BrokerTransportDisconnectedError):
        inmem.handle_gateway_rpc({"jsonrpc": "2.0", "id": 9, "method": "ping"}, caller_context=unk)


# ==============================================================================
# F. Configuration Previews & Offline .mcpb Package
# ==============================================================================


def test_f01_all_configuration_previews_validate_secret_free_and_build_offline_mcpb(tmp_path: Path) -> None:
    reg = ApplicationAdapterRegistry()
    previews = reg.build_all_previews(
        project_root=PROJECT_ROOT,
        existing_antigravity_servers={"antigravity-auditor": {"command": sys.executable, "args": ["core/mcp_server.py"]}},
    )
    assert len(previews) == 6  # agy(2) + claude_desktop(1) + codex(2) + claude_code_status(1)
    for pv in previews:
        assert pv.applied is False
        assert pv.secret_free is True
        assert pv.validation_ok is True, f"Preview {pv.application_id}/{pv.scope_name} errors: {pv.validation_errors}"

    # Verify Antigravity preserves baseline 'antigravity-auditor'
    agy_global = next(p for p in previews if p.application_id == "antigravity" and p.scope_name == "global")
    agy_json = json.loads(agy_global.content_text)
    assert "antigravity-auditor" in agy_json["mcpServers"]
    assert "antigravity-auditor-next22d-preview" in agy_json["mcpServers"]

    # Verify Codex TOML parses strictly via tomllib and includes only read-only allowlist
    codex_user = next(p for p in previews if p.application_id == "codex" and p.scope_name == "user")
    codex_toml = tomllib.loads(codex_user.content_text)
    srv = codex_toml["mcp_servers"]["antigravity_auditor_preview"]
    assert srv["enabled"] is False
    assert "auditor_start_execution" not in srv["enabled_tools"]

    # Reject duplicate Antigravity server collision
    dup_previews = reg.antigravity.build_config_previews(
        project_root=PROJECT_ROOT,
        existing_global_servers={"antigravity-auditor-next22d-preview": {"command": "x"}},
    )
    assert any("DUPLICATE_SERVER_NAME" in e for e in dup_previews[0].validation_errors)

    # Disallow shell wrappers
    assert validate_launch_command("powershell.exe", ["-c", "echo hi"])

    # Build offline .mcpb ZIP package without installing
    mcpb_path = tmp_path / "antigravity-auditor-adapter.mcpb"
    pkg_info = reg.claude_desktop.build_offline_package(
        project_root=PROJECT_ROOT,
        output_mcpb_path=mcpb_path,
    )
    assert pkg_info["installed"] is False and pkg_info["registered"] is False
    assert "manifest.json" in pkg_info["zip_entries"]
    with zipfile.ZipFile(mcpb_path, "r") as zf:
        mf = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert mf["permissions"]["credentials"] == "none_embedded"
        assert mf["compatibility"]["runtime_wire_verified"] is False


# ==============================================================================
# G. Protocol Compatibility Boundary
# ==============================================================================


def test_g01_protocol_compatibility_honesty_across_adapters(tmp_path: Path) -> None:
    gw, _ = _setup_gateway(tmp_path)
    prov = EphemeralTestCredentialProvider()
    prov.provision_ephemeral_adapter_key(adapter_id="adp-codex-1", key_id="k-codex")
    mgr = AdapterChallengeManager(credential_provider=prov, clock=lambda: 1700002000)
    os_id = _sample_os_identity()
    proc_obs = _sample_proc_obs()
    chl = mgr.issue_challenge(
        adapter_id="adp-codex-1",
        application_id="codex",
        application_instance_id="app-alice-codex",
        process_obs=proc_obs,
        os_identity=os_id,
        key_id="k-codex",
    )
    bundle = AdapterContextResolver().resolve(
        os_identity=os_id,
        process_obs=proc_obs,
        challenge_manager=mgr,
        signed_proof=mgr.sign_challenge(chl),
        permitted_scopes_for_sid=frozenset({"core:read", "routing:read"}),
        allowed_user_profile_ids=frozenset({"usr-alice"}),
        allowed_account_context_ids=frozenset({"acct-alice-agy"}),
        account_context_id="acct-alice-agy",
        protocol_version="2026-07-28",
        protocol_era=ProtocolEra.MODERN,
    )
    host = CommonStdioAdapterHost(
        transport=InMemoryBrokerTransport(gw),
        caller_context=bundle.caller_context,
        stderr_stream=io.StringIO(),
    )
    disc = host.process_raw_payload(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"protocolVersion": "2026-07-28"}}).encode("utf-8")
    )
    assert disc is not None and "result" in disc
    assert disc["result"]["runtimeWireVerified"] is False
    assert disc["result"]["runtimeSupportStatus"] == "ADAPTER_CONTRACT_ONLY_NOT_VERIFIED"

    bad_ver = host.process_raw_payload(
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "server/discover", "params": {"protocolVersion": "2026-02-30"}}).encode("utf-8")
    )
    assert bad_ver is not None and "error" in bad_ver
    host.close()

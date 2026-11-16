"""Stdio entrypoint for NEXT-22D common application adapter host with live local Gateway routing."""

from __future__ import annotations

import argparse
from collections.abc import Callable
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import sys
from typing import Any

_CORE_DIR = str(Path(__file__).resolve().parents[1])
if _CORE_DIR not in sys.path:
    sys.path.insert(0, _CORE_DIR)

from application_adapters.adapter_context import AdapterContextResolver, UntrustedAdapterHints
from application_adapters.adapter_runtime import (
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    CommonStdioAdapterHost,
)
from application_adapters.broker_transport import (
    BrokerTransport,
    DisabledProductionNamedPipeTransport,
    InMemoryBrokerTransport,
)
from application_adapters.contracts import ProcessObservation
from application_adapters.credential_provider import (
    DisabledProductionCredentialProvider,
    EphemeralTestCredentialProvider,
)
from application_adapters.identity_proof import AdapterChallengeManager
from application_adapters.process_observation import (
    Win32ReadOnlyProcessObserver,
    _query_process_times_and_ppid,
    _query_session_and_sid,
)
from broker.security import (
    ClientIdentity,
    _win32_advapi32,
    _win32_kernel32,
    get_current_process_identity,
    is_windows,
)
from mcp_gateway.authorization_resolver import AuthorizationResolver
from mcp_gateway.contracts import UNIVERSAL_MINIMUM_READ_SCOPES, AuthMethod
from mcp_gateway.gateway import AdaptiveMCPGateway
from mcp_server import AuditorMCPDispatcher
from runtime_discovery.windows_detection import has_reparse_point_in_ancestors, is_reparse_point

# ARCH-01: these scopes are an audit *lifecycle* set, not read-only: audit:publish, verification:submit and
# governance:finalize write to auditor.db and the audited repository's .antigravity-audit/ folder.
ANTIGRAVITY_STDIO_AUDIT_LIFECYCLE_SCOPES: frozenset[str] = frozenset(
    {
        "core:read",
        "project:read",
        "evidence:read",
        "audit:publish",
        "verification:submit",
        "governance:finalize",
        "models:read",
    }
)
# Deprecated alias kept for existing imports.
ANTIGRAVITY_STDIO_READONLY_AUDIT_SCOPES = ANTIGRAVITY_STDIO_AUDIT_LIFECYCLE_SCOPES

# APPLY (fix in an isolated worktree, delivered as a local review branch): the agent may record decisions and
# drive an execution that a human authorized in a terminal. `governance:authorize` is deliberately never
# granted over MCP -- authorization is human-only (`cli.py authorize-execution`, interactive terminal).
ANTIGRAVITY_STDIO_APPLY_SCOPES: frozenset[str] = frozenset({"governance:decide", "execution:run"})


def apply_enabled() -> bool:
    """APPLY over MCP is on unless ANTIGRAVITY_AUDITOR_APPLY=0 (nothing runs without a terminal authorization)."""
    return os.environ.get("ANTIGRAVITY_AUDITOR_APPLY", "1").strip().lower() not in ("0", "false", "off", "no")


@dataclass(frozen=True)
class ObservedProcessNode:
    """Kernel-observed ancestor process node (read-only OS facts only)."""

    pid: int
    parent_pid: int | None
    creation_time_100ns: int | None
    executable_path: str | None
    user_sid: str | None
    session_id: int | None
    integrity_level: str


ProcessChainReader = Callable[[int], ObservedProcessNode | None]


def _default_process_node_reader(pid: int) -> ObservedProcessNode | None:
    if pid <= 0:
        return None
    creation_100ns, exe_path, ppid = _query_process_times_and_ppid(pid)
    session_id, user_sid, integrity = _query_session_and_sid(pid)
    if creation_100ns is None and exe_path is None and ppid is None:
        return None
    return ObservedProcessNode(
        pid=int(pid),
        parent_pid=ppid,
        creation_time_100ns=creation_100ns,
        executable_path=exe_path,
        user_sid=user_sid,
        session_id=session_id,
        integrity_level=integrity,
    )


def _resolve_os_token_local_app_data() -> Path | None:
    """Resolve LocalAppData directly from the Win32 process token (never env vars)."""
    if not is_windows():
        return None
    k32 = _win32_kernel32()
    adv = _win32_advapi32()
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    userenv.GetUserProfileDirectoryW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    userenv.GetUserProfileDirectoryW.restype = wintypes.BOOL
    htok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008, ctypes.byref(htok)):
        return None
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(1024)
        if not userenv.GetUserProfileDirectoryW(htok, buf, ctypes.byref(size)):
            return None
        profile_dir = Path(buf.value)
    finally:
        k32.CloseHandle(htok)

    local_app_data = profile_dir / "AppData" / "Local"
    if not local_app_data.is_dir() or has_reparse_point_in_ancestors(local_app_data):
        return None
    return local_app_data


def _safe_canonical_exe_path(exe_path: Path, *, root: Path | None = None) -> str | None:
    """Return casefolded real path ONLY if file exists without reparse/symlink redirection."""
    if not exe_path.exists() or not exe_path.is_file():
        return None
    if has_reparse_point_in_ancestors(exe_path, stop_at=root):
        return None
    abs_norm = os.path.abspath(str(exe_path)).casefold()
    real_norm = os.path.realpath(str(exe_path)).casefold()
    if real_norm != abs_norm:
        return None
    if root is not None:
        root_norm = os.path.abspath(str(root)).rstrip("\\/").casefold() + os.sep
        if not real_norm.startswith(root_norm):
            return None
    return real_norm


def _canonical_antigravity_executables(local_app_data: Path | None = None) -> tuple[set[str], set[str]]:
    """Return (direct_host_exes, language_server_exes) under token-verified LocalAppData."""
    base = local_app_data if local_app_data is not None else _resolve_os_token_local_app_data()
    if base is None or is_reparse_point(base) or has_reparse_point_in_ancestors(base):
        return set(), set()
    roots_direct = [
        base / "Programs" / "antigravity" / "Antigravity.exe",
        base / "agy" / "bin" / "agy.EXE",
    ]
    roots_ls = [
        base / "Programs" / "antigravity" / "resources" / "bin" / "language_server.exe",
    ]
    direct_set = {
        norm
        for p in roots_direct
        if (norm := _safe_canonical_exe_path(p, root=base)) is not None
    }
    ls_set = {
        norm
        for p in roots_ls
        if (norm := _safe_canonical_exe_path(p, root=base)) is not None
    }
    return direct_set, ls_set


def _verify_antigravity_os_ancestor_chain(
    *,
    process_obs: ProcessObservation,
    os_identity: ClientIdentity | None,
    process_reader: ProcessChainReader = _default_process_node_reader,
    canonical_executables: tuple[set[str], set[str]] | None = None,
) -> tuple[bool, str]:
    """Verify kernel-observed direct Antigravity parent chain under matching OS SID.

    Rejects shells (cmd.exe/powershell.exe/pytest) and reparse points, and binds exact
    parent_creation_time_100ns and OS session ID fail-closed.
    """
    if os_identity is None or not os_identity.verified_by_os or not os_identity.sid:
        return False, "OS_IDENTITY_MISSING"
    if os_identity.is_low_integrity or os_identity.integrity_level.upper() in ("LOW", "UNTRUSTED", "UNKNOWN"):
        return False, "UNTRUSTED_INTEGRITY_REJECTED"
    if (
        process_obs.process_creation_time_100ns is None
        or not process_obs.parent_pid
        or process_obs.parent_creation_time_100ns is None
    ):
        return False, "PARENT_PROCESS_METADATA_MISSING"

    direct_exes, ls_exes = (
        canonical_executables if canonical_executables is not None else _canonical_antigravity_executables()
    )
    if not direct_exes:
        return False, "ANTIGRAVITY_INSTALL_NOT_FOUND"

    current_sid = os_identity.sid
    cur_session_id = process_obs.session_id
    if cur_session_id is None:
        return False, "CURRENT_SESSION_MISSING"
    child_ct = int(process_obs.process_creation_time_100ns)

    hop1 = process_reader(int(process_obs.parent_pid))
    if hop1 is None or not hop1.executable_path:
        return False, "PARENT_PROCESS_UNOBSERVABLE"
    if hop1.creation_time_100ns is None or int(hop1.creation_time_100ns) != int(process_obs.parent_creation_time_100ns):
        return False, "PARENT_CREATION_TIME_MISMATCH"

    def _valid_node(node: ObservedProcessNode, expected_child_ct: int) -> tuple[bool, str]:
        if not node.user_sid or node.user_sid != current_sid:
            return False, "ANCESTOR_SID_MISMATCH"
        if node.session_id is None or node.session_id != cur_session_id:
            return False, "ANCESTOR_SESSION_MISMATCH"
        if node.integrity_level.upper() in ("LOW", "UNTRUSTED", "UNKNOWN"):
            return False, "ANCESTOR_UNTRUSTED_INTEGRITY"
        if node.creation_time_100ns is None or int(node.creation_time_100ns) > expected_child_ct:
            return False, "ANCESTOR_CREATION_TIME_INVALID"
        return True, "OK"

    ok1, reason1 = _valid_node(hop1, child_ct)
    if not ok1:
        return False, reason1

    hop1_path = _safe_canonical_exe_path(Path(hop1.executable_path))
    if hop1_path is None:
        return False, "PARENT_EXE_UNSAFE_OR_MISSING"
    if hop1_path in direct_exes:
        return True, "ANTIGRAVITY_DIRECT_PARENT_VERIFIED"

    if hop1_path in ls_exes:
        if not hop1.parent_pid or hop1.creation_time_100ns is None:
            return False, "LANGUAGE_SERVER_GRANDPARENT_MISSING"
        hop2 = process_reader(int(hop1.parent_pid))
        if hop2 is None or not hop2.executable_path:
            return False, "LANGUAGE_SERVER_GRANDPARENT_UNOBSERVABLE"
        ok2, reason2 = _valid_node(hop2, int(hop1.creation_time_100ns))
        if not ok2:
            return False, reason2
        hop2_path = _safe_canonical_exe_path(Path(hop2.executable_path))
        if hop2_path is None:
            return False, "GRANDPARENT_EXE_UNSAFE_OR_MISSING"
        if hop2_path in direct_exes:
            return True, "ANTIGRAVITY_LANGUAGE_SERVER_CHAIN_VERIFIED"
        return False, "LANGUAGE_SERVER_GRANDPARENT_NOT_ANTIGRAVITY"

    return False, "PARENT_NOT_ANTIGRAVITY_HOST"


def _resolve_current_os_identity() -> tuple[ClientIdentity | None, dict[str, Any]]:
    raw = get_current_process_identity()
    user_sid = raw.get("user_sid")
    il = str(raw.get("integrity_level") or "UNKNOWN")
    is_low = bool(raw.get("is_low_integrity", False)) or il.upper() in ("LOW", "UNTRUSTED", "UNKNOWN")
    if not user_sid or is_low or raw.get("error"):
        return None, raw
    ident = ClientIdentity(
        pid=int(raw.get("pid") or os.getpid()),
        sid=str(user_sid),
        integrity_level=il,
        is_low_integrity=is_low,
        is_appcontainer=bool(raw.get("is_appcontainer", False)),
        is_elevated=bool(raw.get("is_elevated", False)),
        verified_by_os=True,
    )
    return ident, raw


def resolve_local_stdio_caller(
    *,
    application_hint: str | None = None,
    protocol_version: str = "2025-11-25",
    _test_os_identity: ClientIdentity | None = None,
    _test_process_obs: ProcessObservation | None = None,
    _test_process_reader: ProcessChainReader | None = None,
    _test_canonical_executables: tuple[set[str], set[str]] | None = None,
):
    """Resolve authenticated local stdio caller from kernel OS evidence only.

    Untrusted inputs (clientInfo, --application-hint, env vars, model names) are recorded
    only as ignored telemetry and NEVER grant application identity or scopes.
    """
    os_identity = _test_os_identity
    if os_identity is None:
        os_identity, _ = _resolve_current_os_identity()

    proc_obs = _test_process_obs or Win32ReadOnlyProcessObserver().observe_process(include_authenticode=False)

    verified_chain, chain_reason = _verify_antigravity_os_ancestor_chain(
        process_obs=proc_obs,
        os_identity=os_identity,
        process_reader=_test_process_reader or _default_process_node_reader,
        canonical_executables=_test_canonical_executables,
    )

    signed_proof = None
    permitted_scopes: frozenset[str] = UNIVERSAL_MINIMUM_READ_SCOPES
    if verified_chain and os_identity is not None:
        cred_provider = EphemeralTestCredentialProvider()
        key_id = "local-stdio-antigravity"
        cred_provider.provision_ephemeral_adapter_key(
            adapter_id="antigravity-stdio-adapter",
            key_id=key_id,
            key_version=1,
            secret_bytes=secrets.token_bytes(32),
        )
        challenge_mgr = AdapterChallengeManager(credential_provider=cred_provider)
        challenge = challenge_mgr.issue_challenge(
            adapter_id="antigravity-stdio-adapter",
            application_id="antigravity",
            application_instance_id=f"stdio-{proc_obs.pid}-{proc_obs.process_creation_time_100ns}",
            process_obs=proc_obs,
            os_identity=os_identity,
            key_id=key_id,
            key_version=1,
        )
        signed_proof = challenge_mgr.sign_challenge(challenge)
        permitted_scopes = ANTIGRAVITY_STDIO_AUDIT_LIFECYCLE_SCOPES | (
            ANTIGRAVITY_STDIO_APPLY_SCOPES if apply_enabled() else frozenset()
        )
    else:
        challenge_mgr = AdapterChallengeManager(credential_provider=DisabledProductionCredentialProvider())

    bundle = AdapterContextResolver().resolve(
        os_identity=os_identity,
        process_obs=proc_obs,
        challenge_manager=challenge_mgr,
        signed_proof=signed_proof,
        untrusted_adapter_hints=UntrustedAdapterHints(claimed_application_arg=application_hint),
        permitted_scopes_for_sid=permitted_scopes,
        protocol_version=protocol_version,
    )
    caller = bundle.caller_context
    diag = list(caller.diagnostic_reasons)
    if f"OS_CHAIN:{chain_reason}" not in diag:
        diag.append(f"OS_CHAIN:{chain_reason}")
    caller = type(caller)(
        principal_id=caller.principal_id,
        application_id=caller.application_id,
        application_instance_id=caller.application_instance_id,
        adapter_id=caller.adapter_id,
        account_context_id=caller.account_context_id,
        workspace_context_id=caller.workspace_context_id,
        authentication_method=AuthMethod.LOCAL_OS_PROCESS if verified_chain else caller.authentication_method,
        authorization_scopes=caller.authorization_scopes,
        allowed_user_profile_ids=caller.allowed_user_profile_ids,
        allowed_account_context_ids=caller.allowed_account_context_ids,
        operating_system_identity=caller.operating_system_identity,
        verified_application_identity=caller.verified_application_identity,
        protocol_context=caller.protocol_context,
        context_evidence_refs=caller.context_evidence_refs,
        policy_generation=caller.policy_generation,
        entitlement_generation=caller.entitlement_generation,
        diagnostic_reasons=tuple(diag),
    )
    return caller, bundle


def build_local_stdio_gateway_host(
    *,
    dispatcher: AuditorMCPDispatcher | None = None,
    app_home: Path | None = None,
    db_path: Path | None = None,
    application_hint: str | None = None,
    protocol_version: str = "2025-11-25",
    transport_mode: str = "gateway",
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    stderr_stream: Any = None,
    allow_execution_tools: bool = False,
    _test_os_identity: ClientIdentity | None = None,
    _test_process_obs: ProcessObservation | None = None,
    _test_process_reader: ProcessChainReader | None = None,
    _test_canonical_executables: tuple[set[str], set[str]] | None = None,
) -> CommonStdioAdapterHost:
    """Build the fail-closed stdio adapter host backed by AdaptiveMCPGateway."""
    if transport_mode == "disabled-named-pipe":
        transport: BrokerTransport = DisabledProductionNamedPipeTransport()
        # Preserve explicit fail-closed disabled boundary when named pipe mode is requested.
        caller_ctx = AdapterContextResolver().resolve(
            os_identity=None,
            process_obs=_test_process_obs or Win32ReadOnlyProcessObserver().observe_process(include_authenticode=False),
            challenge_manager=AdapterChallengeManager(credential_provider=DisabledProductionCredentialProvider()),
            untrusted_adapter_hints=UntrustedAdapterHints(claimed_application_arg=application_hint),
            protocol_version=protocol_version,
        ).caller_context
        return CommonStdioAdapterHost(
            transport=transport,
            caller_context=caller_ctx,
            application_profile_id=application_hint,
            stderr_stream=stderr_stream,
            request_timeout_seconds=request_timeout_seconds,
        )

    resolved_home = (
        app_home or Path(os.environ.get("ANTIGRAVITY_AUDITOR_HOME", str(Path(__file__).resolve().parents[2])))
    ).resolve()
    resolved_db = (
        db_path or Path(os.environ.get("ANTIGRAVITY_AUDITOR_DB", str(resolved_home / "database" / "auditor.db")))
    ).resolve()
    if dispatcher is None:
        from model_registry import configure_routing_store

        configure_routing_store(resolved_db)
    eff_dispatcher = dispatcher or AuditorMCPDispatcher(db_path=resolved_db, app_home=resolved_home)

    # Read-only delivery mode keeps execution mutation tools disabled fail-closed unless explicitly unlocked.
    gateway = AdaptiveMCPGateway(
        dispatcher=eff_dispatcher,
        authorization_resolver=AuthorizationResolver(allow_execution_tools=bool(allow_execution_tools)),
    )
    caller_ctx, _ = resolve_local_stdio_caller(
        application_hint=application_hint,
        protocol_version=protocol_version,
        _test_os_identity=_test_os_identity,
        _test_process_obs=_test_process_obs,
        _test_process_reader=_test_process_reader,
        _test_canonical_executables=_test_canonical_executables,
    )
    return CommonStdioAdapterHost(
        transport=InMemoryBrokerTransport(gateway, timeout_seconds=request_timeout_seconds),
        caller_context=caller_ctx,
        application_profile_id=application_hint,
        stderr_stream=stderr_stream,
        request_timeout_seconds=request_timeout_seconds,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="antigravity-auditor-adapter",
        description="Common stdio adapter host backed by AdaptiveMCPGateway (read-only daily audit mode).",
    )
    parser.add_argument("--application-hint", default=None, help="Untrusted application family hint (never trusted for auth).")
    parser.add_argument("--protocol-version", default="2025-11-25", help="Legacy MCP protocol version hint.")
    parser.add_argument(
        "--transport",
        choices=("gateway", "disabled-named-pipe"),
        default="gateway",
        help="Stdio transport backend ('gateway' for local stdio AdaptiveMCPGateway, 'disabled-named-pipe' for B4-C boundary check).",
    )
    parser.add_argument("--check-boundary", action="store_true", help="Print fail-closed boundary status to stderr and exit.")
    args = parser.parse_args(argv)

    host = build_local_stdio_gateway_host(
        application_hint=args.application_hint,
        protocol_version=args.protocol_version,
        transport_mode=args.transport,
    )
    if args.check_boundary:
        host.log_diagnostic(
            f"Boundary check ok: transport={host.transport.transport_kind} "
            f"production_pipe_enabled=False allow_execution_tools={apply_enabled()} "
            f"verified_app={host.caller_context.verified_application_identity} "
            f"resolved_app={host.caller_context.application_id}"
        )
        host.close()
        return 0
    return host.serve_streams(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())

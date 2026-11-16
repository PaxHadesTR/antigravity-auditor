"""Read-only discovery adapter for OpenAI Codex CLI, Desktop/Daemon, and IDE integration."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from runtime_discovery.adapters.base import AdapterContext, BaseDiscoveryAdapter
from runtime_discovery.cli_detection import ALLOWED_CLI_BASENAMES
from runtime_discovery.contracts import (
    AvailabilityState,
    CapabilityEntry,
    CapabilityStatus,
    DiscoveryStatus,
    EvidenceClass,
    InstallationState,
    NormalizedEffortRecord,
    NormalizedModelRecord,
    ObservationState,
    PackagingMode,
    TransportType,
    make_empty_application_profile,
)
from runtime_discovery.evidence import utc_now_iso
from runtime_discovery.mcp_parsers import (
    build_mcp_section,
    parse_codex_mcp_list_json,
    parse_codex_toml_mcp_config,
)
from runtime_discovery.normalizers import parse_codex_bundled_models
from runtime_discovery.redaction import sanitize_exception
from runtime_discovery.windows_detection import is_reparse_point, safe_list_dir_names


class CodexAdapter(BaseDiscoveryAdapter):
    """Discovers Codex CLI, bundled daemon/desktop, IDE extensions, bundled catalog, and MCP metadata."""

    application_id = "codex"
    application_family = "openai"

    def discover(self, ctx: AdapterContext) -> dict[str, Any]:
        profile = make_empty_application_profile(self.application_id, self.application_family)
        observed_at = utc_now_iso()
        errors: list[dict[str, str]] = []
        limitations: list[str] = [
            "Bundled model catalog (`codex debug models --bundled`) does NOT prove account-level model availability.",
            "Account-enumerated models are not queried (no App Server launch or API call permitted in NEXT-22A).",
            "Active session model and effort are not exposed through a non-mutating interface.",
            "Live MCP server connections are not probed in NEXT-22A.",
        ]

        # 1. Process, Desktop/AppX, and bounded IDE extension checks
        procs = ctx.host_inspector.list_processes(("codex",))
        running_by_path: dict[str, list[int]] = {}
        process_cli_candidates: list[Path] = []
        for p in procs:
            if p.executable_path:
                running_by_path.setdefault(p.executable_path.lower(), []).append(p.pid)
                cand = Path(p.executable_path)
                if cand.name.lower() in ALLOWED_CLI_BASENAMES["codex"]:
                    process_cli_candidates.append(cand)

        appx_pkgs = ctx.host_inspector.find_appx_packages(("codex", "openai"))

        # Check bounded IDE extensions directories (non-recursive)
        ide_extensions: list[dict[str, str]] = []
        for ide_name, ext_root, root_bound in (
            ("vscode", ctx.user_home / ".vscode" / "extensions", ctx.user_home),
            ("antigravity", ctx.user_home / ".antigravity" / "extensions", ctx.user_home),
        ):
            names, ext_err = safe_list_dir_names(ext_root, root=root_bound)
            if ext_err is None:
                for entry_name in names:
                    low = entry_name.lower()
                    if any(tok in low for tok in ("codex", "openai", "chatgpt")):
                        ide_extensions.append({"ide": ide_name, "extension_dir": entry_name})

        # 2. Resolve Codex CLI executable
        cli_candidates = (
            ctx.local_appdata / "Programs" / "OpenAI" / "Codex" / "bin" / "codex.exe",
            ctx.appdata / "npm" / "codex.cmd",
            *process_cli_candidates,
        )
        codex_exe = ctx.cli_runner.resolve_executable("codex", cli_candidates)
        cli_present = codex_exe is not None
        cli_version: str | None = None
        cli_caps: list[str] = []
        help_observed = False

        executables: list[dict[str, Any]] = []
        seen_exe_lower: set[str] = set()
        models: list[NormalizedModelRecord] = []
        efforts: list[NormalizedEffortRecord] = []
        supported_transports: list[str] | None = None
        supported_transports_ev = EvidenceClass.UNKNOWN
        oauth_support: bool | None = None
        oauth_ev = EvidenceClass.UNKNOWN
        cli_mcp_servers = []

        # Record any running Codex executable paths observed from process list
        for p in procs:
            if p.executable_path:
                norm = p.executable_path.lower()
                if norm in seen_exe_lower:
                    continue
                p_path = Path(p.executable_path)
                if not is_reparse_point(p_path):
                    seen_exe_lower.add(norm)
                    ver = ctx.host_inspector.get_file_version(p_path)
                    pids = running_by_path.get(norm, [])
                    role = (
                        "app_server_daemon"
                        if "app-server-daemon" in norm
                        else ("sandbox_helper" if "sandbox" in p_path.name.lower() else "cli_or_desktop")
                    )
                    ev_id = ctx.ledger.add(
                        application_id=self.application_id,
                        stage="executable_detection",
                        evidence_class=EvidenceClass.PROCESS_OBSERVED,
                        source_type="executable",
                        source_ref=str(p_path),
                        observed_at=observed_at,
                        notes=f"role={role}, file_version={ver}, running_pids={len(pids)}",
                    )
                    executables.append(
                        {
                            "path": str(p_path),
                            "basename": p_path.name,
                            "role": role,
                            "version": ver,
                            "running": True,
                            "pids": sorted(pids),
                            "evidence_class": EvidenceClass.PROCESS_OBSERVED.value,
                            "evidence_id": ev_id,
                        }
                    )

        if codex_exe is not None:
            norm_cli = str(codex_exe).lower()
            ver_res = ctx.cli_runner.run(
                "codex", codex_exe, ("--version",), timeout_seconds=ctx.timeout_seconds
            )
            cli_ver_ev = ctx.ledger.add(
                application_id=self.application_id,
                stage="cli_version",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if ver_res.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(codex_exe),
                observed_at=observed_at,
                exit_code=ver_res.exit_code,
                command_basename=codex_exe.name,
                command_args=("--version",),
            )
            if ver_res.ok and ver_res.stdout.strip():
                cli_version = ver_res.stdout.strip().splitlines()[0].strip()

            if norm_cli not in seen_exe_lower:
                seen_exe_lower.add(norm_cli)
                pids = running_by_path.get(norm_cli, [])
                executables.append(
                    {
                        "path": str(codex_exe),
                        "basename": codex_exe.name,
                        "role": "cli",
                        "version": cli_version or ctx.host_inspector.get_file_version(codex_exe),
                        "running": len(pids) > 0,
                        "pids": sorted(pids),
                        "evidence_class": EvidenceClass.RUNTIME_OBSERVED.value,
                        "evidence_id": cli_ver_ev,
                    }
                )

            # Inspect `codex --help`
            help_res = ctx.cli_runner.run(
                "codex", codex_exe, ("--help",), timeout_seconds=ctx.timeout_seconds
            )
            ctx.ledger.add(
                application_id=self.application_id,
                stage="cli_help",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if help_res.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(codex_exe),
                observed_at=observed_at,
                exit_code=help_res.exit_code,
                command_basename=codex_exe.name,
                command_args=("--help",),
            )
            if help_res.ok:
                help_observed = True
                for subcmd in ("mcp", "debug", "app-server", "features", "sandbox", "login"):
                    if re.search(rf"\b{re.escape(subcmd)}\b", help_res.stdout):
                        cli_caps.append(subcmd)

            # Inspect `codex debug models --help` then `--bundled` ONLY (never refresh!)
            dbg_help = ctx.cli_runner.run(
                "codex", codex_exe, ("debug", "models", "--help"), timeout_seconds=ctx.timeout_seconds
            )
            ctx.ledger.add(
                application_id=self.application_id,
                stage="bundled_model_catalog_help",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if dbg_help.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(codex_exe),
                observed_at=observed_at,
                exit_code=dbg_help.exit_code,
                command_basename=codex_exe.name,
                command_args=("debug", "models", "--help"),
            )
            if dbg_help.ok and "--bundled" in dbg_help.stdout:
                bundled_res = ctx.cli_runner.run(
                    "codex", codex_exe, ("debug", "models", "--bundled"), timeout_seconds=ctx.timeout_seconds
                )
                bundled_ev = ctx.ledger.add(
                    application_id=self.application_id,
                    stage="bundled_model_catalog",
                    evidence_class=EvidenceClass.BUNDLED_CATALOG if bundled_res.ok else EvidenceClass.ERROR,
                    source_type="cli",
                    source_ref=str(codex_exe),
                    observed_at=observed_at,
                    exit_code=bundled_res.exit_code,
                    command_basename=codex_exe.name,
                    command_args=("debug", "models", "--bundled"),
                )
                if bundled_res.ok:
                    try:
                        b_models, b_efforts = parse_codex_bundled_models(
                            bundled_res.stdout,
                            observed_at=observed_at,
                            evidence_id=bundled_ev,
                        )
                        models.extend(b_models)
                        efforts.extend(b_efforts)
                    except Exception as exc:
                        errors.append(
                            {
                                "code": "CODEX_BUNDLED_MODELS_PARSE_ERROR",
                                "stage": "bundled_model_catalog",
                                "message": sanitize_exception(exc),
                            }
                        )
                else:
                    errors.append(
                        {
                            "code": bundled_res.error_code or "CODEX_BUNDLED_MODELS_FAILED",
                            "stage": "bundled_model_catalog",
                            "message": bundled_res.error_message or "codex debug models --bundled failed",
                        }
                    )

            # Inspect `codex mcp add --help` for transports & OAuth support
            mcp_add_help = ctx.cli_runner.run(
                "codex", codex_exe, ("mcp", "add", "--help"), timeout_seconds=ctx.timeout_seconds
            )
            ctx.ledger.add(
                application_id=self.application_id,
                stage="mcp_cli_add_help",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if mcp_add_help.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(codex_exe),
                observed_at=observed_at,
                exit_code=mcp_add_help.exit_code,
                command_basename=codex_exe.name,
                command_args=("mcp", "add", "--help"),
            )
            if mcp_add_help.ok:
                low_add = mcp_add_help.stdout.lower()
                t_list: list[str] = []
                if "stdio" in low_add:
                    t_list.append(TransportType.STDIO.value)
                if "streamable http" in low_add or "--url" in low_add:
                    t_list.append(TransportType.STREAMABLE_HTTP.value)
                if t_list:
                    supported_transports = t_list
                    supported_transports_ev = EvidenceClass.DOCUMENTED_CAPABILITY
                if "--oauth-client-id" in low_add or "oauth" in low_add:
                    oauth_support = True
                    oauth_ev = EvidenceClass.DOCUMENTED_CAPABILITY

            # Verify `codex mcp list --help` confirms safe local config listing before running `--json`
            mcp_list_help = ctx.cli_runner.run(
                "codex", codex_exe, ("mcp", "list", "--help"), timeout_seconds=ctx.timeout_seconds
            )
            ctx.ledger.add(
                application_id=self.application_id,
                stage="mcp_cli_list_help",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if mcp_list_help.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(codex_exe),
                observed_at=observed_at,
                exit_code=mcp_list_help.exit_code,
                command_basename=codex_exe.name,
                command_args=("mcp", "list", "--help"),
            )
            if (
                mcp_list_help.ok
                and "--json" in mcp_list_help.stdout
                and "configured servers" in mcp_list_help.stdout.lower()
            ):
                mcp_list_res = ctx.cli_runner.run(
                    "codex", codex_exe, ("mcp", "list", "--json"), timeout_seconds=ctx.timeout_seconds
                )
                list_ev = ctx.ledger.add(
                    application_id=self.application_id,
                    stage="mcp_list_json",
                    evidence_class=EvidenceClass.CONFIGURED if mcp_list_res.ok else EvidenceClass.ERROR,
                    source_type="cli",
                    source_ref=str(codex_exe),
                    observed_at=observed_at,
                    exit_code=mcp_list_res.exit_code,
                    command_basename=codex_exe.name,
                    command_args=("mcp", "list", "--json"),
                )
                if mcp_list_res.ok:
                    try:
                        parsed_list = parse_codex_mcp_list_json(mcp_list_res.stdout)
                        for srv in parsed_list:
                            cli_mcp_servers.append(type(srv)(**{**srv.__dict__, "evidence_id": list_ev}))
                    except Exception as exc:
                        errors.append(
                            {
                                "code": "CODEX_MCP_LIST_PARSE_ERROR",
                                "stage": "mcp_list_json",
                                "message": sanitize_exception(exc),
                            }
                        )

        # 3. Inspect sanitized config.toml (user + optional project) - NEVER read auth.json or sqlite!
        toml_servers = []
        config_sources: list[dict[str, Any]] = []
        toml_candidates: list[tuple[Path, Path, str]] = [
            (ctx.user_home / ".codex" / "config.toml", ctx.user_home, "user"),
        ]
        if ctx.project_path is not None:
            toml_candidates.append(
                (ctx.project_path / ".codex" / "config.toml", ctx.project_path, "project")
            )

        for cfg_path, root_bound, scope in toml_candidates:
            parsed = parse_codex_toml_mcp_config(cfg_path, root=root_bound, scope=scope)
            config_sources.append(parsed["source"])
            if parsed["error"]:
                errors.append(
                    {
                        "code": f"CODEX_CONFIG_{parsed['error']}",
                        "stage": "mcp_config",
                        "message": f"Failed to parse {cfg_path.name} ({parsed['error']})",
                    }
                )
            elif parsed["source"]["exists"]:
                ev_id = ctx.ledger.add(
                    application_id=self.application_id,
                    stage="toml_config",
                    evidence_class=EvidenceClass.CONFIGURED,
                    source_type="config_file",
                    source_ref=str(cfg_path),
                    observed_at=observed_at,
                    sanitized_projection={
                        "servers": [s.to_dict() for s in parsed["servers"]],
                        "model_config": parsed["model_config"],
                    },
                )
                for srv in parsed["servers"]:
                    toml_servers.append(type(srv)(**{**srv.__dict__, "evidence_id": ev_id}))

                m_cfg = parsed["model_config"]
                cfg_model = m_cfg.get("model")
                cfg_effort = m_cfg.get("model_reasoning_effort")
                if cfg_model:
                    models.append(
                        NormalizedModelRecord(
                            provider="openai",
                            application_id="codex",
                            model_id=cfg_model,
                            display_name=cfg_model,
                            availability_state=AvailabilityState.CONFIGURED,
                            evidence_class=EvidenceClass.CONFIGURED,
                            catalog_source="codex_config_toml",
                            reasoning_efforts=(cfg_effort,) if cfg_effort else (),
                            default_effort=cfg_effort,
                            capabilities={},
                            active_session_state=ObservationState.NOT_EXPOSED,
                            observed_at=observed_at,
                            evidence_id=ev_id,
                            scope=scope,
                        )
                    )
                if cfg_effort:
                    efforts.append(
                        NormalizedEffortRecord(
                            application_id="codex",
                            effort=cfg_effort,
                            model_id=cfg_model,
                            scope=scope,
                            source="codex_config_toml",
                            evidence_class=EvidenceClass.CONFIGURED,
                            is_default=True,
                            supported_efforts=(cfg_effort,),
                            evidence_id=ev_id,
                        )
                    )

        # Merge servers cleanly without duplicating same (name, scope) while preserving source distinction
        all_servers = toml_servers + cli_mcp_servers

        installed = cli_present or bool(executables) or bool(appx_pkgs) or bool(ide_extensions)
        if not installed:
            profile["installation_state"] = InstallationState.NOT_INSTALLED.value
            profile["packaging_mode"] = PackagingMode.NOT_INSTALLED.value
            profile["discovery_status"] = DiscoveryStatus.NOT_INSTALLED.value
        else:
            profile["installation_state"] = InstallationState.INSTALLED.value
            if appx_pkgs:
                profile["packaging_mode"] = PackagingMode.MSIX_APPX.value
            elif any("app-server-daemon" in str(e.get("path", "")).lower() for e in executables):
                profile["packaging_mode"] = PackagingMode.BUNDLED_DAEMON.value
            elif cli_present:
                profile["packaging_mode"] = PackagingMode.CLI_ONLY.value
            else:
                profile["packaging_mode"] = PackagingMode.IDE_EXTENSION.value
            profile["discovery_status"] = DiscoveryStatus.PARTIAL.value

        best_ver = cli_version or (appx_pkgs[0].version if appx_pkgs else None)
        if not best_ver and executables:
            best_ver = executables[0].get("version")

        profile["version"] = {
            "value": best_ver,
            "source": "cli_version" if cli_version else ("executable_metadata" if best_ver else "unknown"),
            "confidence": "high" if best_ver else "unknown",
            "evidence_class": (
                EvidenceClass.RUNTIME_OBSERVED.value
                if cli_version
                else (EvidenceClass.PROCESS_OBSERVED.value if best_ver else EvidenceClass.UNKNOWN.value)
            ),
        }
        profile["executables"] = executables
        profile["cli"] = {
            "present": cli_present,
            "version": cli_version,
            "path": str(codex_exe) if codex_exe else None,
            "capabilities": sorted(set(cli_caps)),
            "evidence_class": (
                EvidenceClass.RUNTIME_OBSERVED.value if cli_present else EvidenceClass.NOT_INSTALLED.value
            ),
            "help_observed": help_observed,
        }
        profile["models"] = [
            m.to_dict() for m in sorted(models, key=lambda x: (x.availability_state.value, x.model_id))
        ]
        profile["reasoning_efforts"] = [
            e.to_dict() for e in sorted(efforts, key=lambda x: (x.scope, x.model_id or "", x.effort))
        ]
        profile["mcp"] = build_mcp_section(
            servers=all_servers,
            config_sources=config_sources,
            supported_transports=supported_transports,
            supported_transports_evidence=supported_transports_ev,
            oauth_support=oauth_support,
            oauth_evidence=oauth_ev,
            extra_notes={
                "client_capability_declarations": CapabilityEntry(
                    value=None,
                    status=CapabilityStatus.NOT_EXPOSED,
                    evidence_class=EvidenceClass.NOT_EXPOSED,
                    notes="Not exposed without live MCP handshake.",
                )
            },
        )
        profile["mcp"]["features"]["ide_extensions"] = ide_extensions
        profile["errors"] = errors
        profile["limitations"] = limitations
        return profile

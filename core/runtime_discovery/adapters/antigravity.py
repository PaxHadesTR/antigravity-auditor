"""Read-only discovery adapter for Google Antigravity App and Antigravity CLI (`agy`)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from runtime_discovery.adapters.base import AdapterContext, BaseDiscoveryAdapter
from runtime_discovery.contracts import (
    CapabilityEntry,
    CapabilityStatus,
    DiscoveryStatus,
    EvidenceClass,
    InstallationState,
    PackagingMode,
    TransportType,
    make_empty_application_profile,
)
from runtime_discovery.evidence import utc_now_iso
from runtime_discovery.mcp_parsers import build_mcp_section, parse_json_mcp_config
from runtime_discovery.normalizers import parse_agy_help_efforts, parse_agy_models_output
from runtime_discovery.windows_detection import is_reparse_point


class AntigravityAdapter(BaseDiscoveryAdapter):
    """Discovers Antigravity App, `agy` CLI, models, orchestrators, and MCP metadata."""

    application_id = "antigravity"
    application_family = "google"

    def discover(self, ctx: AdapterContext) -> dict[str, Any]:
        profile = make_empty_application_profile(self.application_id, self.application_family)
        observed_at = utc_now_iso()
        errors: list[dict[str, str]] = []
        limitations: list[str] = [
            "Active Antigravity App conversation model is not exposed without reading conversation databases (prohibited in NEXT-22A).",
            "Live MCP server connections are not probed in NEXT-22A.",
        ]

        # 1. Process and executable detection (App + CLI)
        procs = ctx.host_inspector.list_processes(("antigravity", "agy"))
        running_by_path: dict[str, list[int]] = {}
        for p in procs:
            if p.executable_path:
                norm = p.executable_path.lower()
                running_by_path.setdefault(norm, []).append(p.pid)

        app_candidates = [
            ctx.local_appdata / "Programs" / "Antigravity" / "Antigravity.exe",
            ctx.local_appdata / "Programs" / "antigravity" / "Antigravity.exe",
            ctx.program_files / "Antigravity" / "Antigravity.exe",
        ]
        # Add any running Antigravity.exe path observed via process metadata
        for p in procs:
            if p.executable_path and p.name.lower() == "antigravity.exe":
                cand = Path(p.executable_path)
                if cand not in app_candidates:
                    app_candidates.append(cand)

        executables: list[dict[str, Any]] = []
        seen_exe_lower: set[str] = set()
        app_version: str | None = None
        app_present = False

        for cand in app_candidates:
            try:
                if str(cand).lower() in seen_exe_lower:
                    continue
                if cand.is_file() and not is_reparse_point(cand):
                    seen_exe_lower.add(str(cand).lower())
                    app_present = True
                    ver = ctx.host_inspector.get_file_version(cand)
                    if ver and not app_version:
                        app_version = ver
                    pids = running_by_path.get(str(cand).lower(), [])
                    ev_id = ctx.ledger.add(
                        application_id=self.application_id,
                        stage="executable_detection",
                        evidence_class=EvidenceClass.PROCESS_OBSERVED,
                        source_type="executable",
                        source_ref=str(cand),
                        observed_at=observed_at,
                        notes=f"file_version={ver}, running_pids={len(pids)}",
                    )
                    executables.append(
                        {
                            "path": str(cand),
                            "basename": cand.name,
                            "role": "desktop_app",
                            "version": ver,
                            "running": len(pids) > 0,
                            "pids": sorted(pids),
                            "evidence_class": EvidenceClass.PROCESS_OBSERVED.value,
                            "evidence_id": ev_id,
                        }
                    )
            except OSError:
                continue

        # Check Uninstall registry for version/install metadata
        uninstall = ctx.host_inspector.find_uninstall_entries(("antigravity",))
        if not app_version:
            for entry in uninstall:
                if entry.display_version:
                    app_version = entry.display_version
                    break

        # 2. Antigravity CLI (`agy`) detection
        cli_candidates = (
            ctx.local_appdata / "agy" / "bin" / "agy.EXE",
            ctx.local_appdata / "agy" / "bin" / "agy.exe",
        )
        agy_exe = ctx.cli_runner.resolve_executable("antigravity", cli_candidates)
        cli_present = agy_exe is not None
        cli_version: str | None = None
        cli_caps: list[str] = []
        help_observed = False

        models = []
        efforts = []
        orchestrators: list[dict[str, Any]] = []
        supported_transports: list[str] | None = None
        supported_transports_ev = EvidenceClass.UNKNOWN

        if agy_exe is not None:
            cli_ver_from_file = ctx.host_inspector.get_file_version(agy_exe)
            ver_res = ctx.cli_runner.run(
                "antigravity", agy_exe, ("--version",), timeout_seconds=ctx.timeout_seconds
            )
            cli_ver_ev = ctx.ledger.add(
                application_id=self.application_id,
                stage="cli_version",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if ver_res.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(agy_exe),
                observed_at=observed_at,
                exit_code=ver_res.exit_code,
                command_basename=agy_exe.name,
                command_args=("--version",),
            )
            ver_text = ver_res.stdout.strip() or ver_res.stderr.strip()
            if ver_res.ok and ver_text:
                cli_version = ver_text.splitlines()[0].strip()
            else:
                cli_version = cli_ver_from_file

            cli_pids = running_by_path.get(str(agy_exe).lower(), [])
            executables.append(
                {
                    "path": str(agy_exe),
                    "basename": agy_exe.name,
                    "role": "cli",
                    "version": cli_version,
                    "running": len(cli_pids) > 0,
                    "pids": sorted(cli_pids),
                    "evidence_class": EvidenceClass.RUNTIME_OBSERVED.value,
                    "evidence_id": cli_ver_ev,
                }
            )

            # Inspect `agy --help` (Go flag binaries emit help text to stderr)
            help_res = ctx.cli_runner.run(
                "antigravity", agy_exe, ("--help",), timeout_seconds=ctx.timeout_seconds
            )
            help_ev = ctx.ledger.add(
                application_id=self.application_id,
                stage="cli_help",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if help_res.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(agy_exe),
                observed_at=observed_at,
                exit_code=help_res.exit_code,
                command_basename=agy_exe.name,
                command_args=("--help",),
            )
            help_text = "\n".join(part for part in (help_res.stdout, help_res.stderr) if part)
            if help_res.ok and help_text:
                help_observed = True
                for subcmd in ("acp", "agent", "agents", "mcp", "models", "plugin", "remote-control"):
                    if re.search(rf"^\s+{re.escape(subcmd)}\b", help_text, re.MULTILINE):
                        cli_caps.append(subcmd)
                efforts.extend(parse_agy_help_efforts(help_text, evidence_id=help_ev))

            # Inspect `agy models`
            models_res = ctx.cli_runner.run(
                "antigravity", agy_exe, ("models",), timeout_seconds=ctx.timeout_seconds
            )
            models_ev = ctx.ledger.add(
                application_id=self.application_id,
                stage="model_catalog",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if models_res.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(agy_exe),
                observed_at=observed_at,
                exit_code=models_res.exit_code,
                command_basename=agy_exe.name,
                command_args=("models",),
            )
            if models_res.ok:
                parsed_models, parsed_efforts, parsed_orchs = parse_agy_models_output(
                    models_res.stdout,
                    observed_at=observed_at,
                    evidence_id=models_ev,
                )
                models.extend(parsed_models)
                efforts.extend(parsed_efforts)
                orchestrators.extend(parsed_orchs)
            else:
                errors.append(
                    {
                        "code": models_res.error_code or "AGY_MODELS_FAILED",
                        "stage": "model_catalog",
                        "message": models_res.error_message or "agy models command failed",
                    }
                )

            # Inspect `agy mcp add --help` for documented transports
            mcp_help_res = ctx.cli_runner.run(
                "antigravity", agy_exe, ("mcp", "add", "--help"), timeout_seconds=ctx.timeout_seconds
            )
            ctx.ledger.add(
                application_id=self.application_id,
                stage="mcp_cli_help",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if mcp_help_res.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(agy_exe),
                observed_at=observed_at,
                exit_code=mcp_help_res.exit_code,
                command_basename=agy_exe.name,
                command_args=("mcp", "add", "--help"),
            )
            mcp_help_text = "\n".join(
                part for part in (mcp_help_res.stdout, mcp_help_res.stderr) if part
            )
            if mcp_help_res.ok and mcp_help_text:
                low_mcp = mcp_help_text.lower()
                detected_transports: list[str] = []
                if "stdio" in low_mcp:
                    detected_transports.append(TransportType.STDIO.value)
                if "'http'" in low_mcp or "http/https" in low_mcp:
                    detected_transports.append(TransportType.HTTP.value)
                if detected_transports:
                    supported_transports = detected_transports
                    supported_transports_ev = EvidenceClass.DOCUMENTED_CAPABILITY

        # 3. Sanitized MCP config discovery (never read ~/.gemini/AGENTS.md or secrets)
        servers = []
        config_sources: list[dict[str, Any]] = []
        user_mcp_path = ctx.user_home / ".gemini" / "config" / "mcp_config.json"
        user_cfg = parse_json_mcp_config(
            user_mcp_path,
            root=ctx.user_home,
            scope="user",
            default_url_transport=TransportType.HTTP,
        )
        config_sources.append(user_cfg["source"])
        if user_cfg["error"]:
            errors.append(
                {
                    "code": f"MCP_CONFIG_{user_cfg['error']}",
                    "stage": "mcp_config",
                    "message": f"Failed to parse user MCP config ({user_cfg['error']})",
                }
            )
        else:
            ev_id = ctx.ledger.add(
                application_id=self.application_id,
                stage="mcp_config",
                evidence_class=EvidenceClass.CONFIGURED if user_cfg["source"]["exists"] else EvidenceClass.UNKNOWN,
                source_type="config_file",
                source_ref=str(user_mcp_path),
                observed_at=observed_at,
                sanitized_projection=[s.to_dict() for s in user_cfg["servers"]],
            )
            for srv in user_cfg["servers"]:
                servers.append(
                    type(srv)(**{**srv.__dict__, "evidence_id": ev_id})
                )

        if ctx.project_path is not None:
            proj_mcp_path = ctx.project_path / ".agents" / "mcp_config.json"
            proj_cfg = parse_json_mcp_config(
                proj_mcp_path,
                root=ctx.project_path,
                scope="project",
                default_url_transport=TransportType.HTTP,
            )
            config_sources.append(proj_cfg["source"])
            if proj_cfg["error"]:
                errors.append(
                    {
                        "code": f"MCP_PROJECT_CONFIG_{proj_cfg['error']}",
                        "stage": "mcp_config",
                        "message": f"Failed to parse project MCP config ({proj_cfg['error']})",
                    }
                )
            elif proj_cfg["source"]["exists"]:
                ev_id = ctx.ledger.add(
                    application_id=self.application_id,
                    stage="mcp_project_config",
                    evidence_class=EvidenceClass.CONFIGURED,
                    source_type="config_file",
                    source_ref=str(proj_mcp_path),
                    observed_at=observed_at,
                    sanitized_projection=[s.to_dict() for s in proj_cfg["servers"]],
                )
                for srv in proj_cfg["servers"]:
                    servers.append(type(srv)(**{**srv.__dict__, "evidence_id": ev_id}))

        installed = app_present or cli_present
        if not installed:
            profile["installation_state"] = InstallationState.NOT_INSTALLED.value
            profile["packaging_mode"] = PackagingMode.NOT_INSTALLED.value
            profile["discovery_status"] = DiscoveryStatus.NOT_INSTALLED.value
        else:
            profile["installation_state"] = InstallationState.INSTALLED.value
            profile["packaging_mode"] = (
                PackagingMode.CONVENTIONAL.value if app_present else PackagingMode.CLI_ONLY.value
            )
            profile["discovery_status"] = DiscoveryStatus.PARTIAL.value

        best_ver = app_version or cli_version
        ver_source = "executable_metadata" if app_version else ("cli_version" if cli_version else "unknown")
        ver_ev = (
            EvidenceClass.PROCESS_OBSERVED
            if app_version
            else (EvidenceClass.RUNTIME_OBSERVED if cli_version else EvidenceClass.UNKNOWN)
        )
        profile["version"] = {
            "value": best_ver,
            "source": ver_source,
            "confidence": "high" if best_ver else "unknown",
            "evidence_class": ver_ev.value,
        }
        profile["executables"] = executables
        profile["cli"] = {
            "present": cli_present,
            "version": cli_version,
            "path": str(agy_exe) if agy_exe else None,
            "capabilities": sorted(set(cli_caps)),
            "evidence_class": (
                EvidenceClass.RUNTIME_OBSERVED.value if cli_present else EvidenceClass.NOT_INSTALLED.value
            ),
            "help_observed": help_observed,
        }
        profile["models"] = [m.to_dict() for m in models]
        profile["reasoning_efforts"] = [e.to_dict() for e in efforts]
        profile["orchestrators"] = orchestrators
        profile["mcp"] = build_mcp_section(
            servers=servers,
            config_sources=config_sources,
            supported_transports=supported_transports,
            supported_transports_evidence=supported_transports_ev,
            extra_notes={
                "client_capability_declarations": CapabilityEntry(
                    value=None,
                    status=CapabilityStatus.NOT_EXPOSED,
                    evidence_class=EvidenceClass.NOT_EXPOSED,
                    notes="Not exposed without live MCP initialize handshake.",
                )
            },
        )
        profile["errors"] = errors
        profile["limitations"] = limitations
        return profile

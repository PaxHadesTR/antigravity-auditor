"""Read-only discovery adapter for Anthropic Claude Code CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from runtime_discovery.adapters.base import AdapterContext, BaseDiscoveryAdapter
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
from runtime_discovery.mcp_parsers import build_mcp_section, parse_json_mcp_config
from runtime_discovery.normalizers import infer_provider_from_model_id
from runtime_discovery.windows_detection import is_reparse_point, safe_read_text


def _parse_claude_settings_model_metadata(
    path: Path,
    *,
    root: Path | None,
    scope: str,
    observed_at: str,
    evidence_id: str,
) -> tuple[list[NormalizedModelRecord], list[NormalizedEffortRecord], dict[str, Any]]:
    """Extract ONLY allowlisted model/effort settings from Claude Code settings.json."""
    text, err = safe_read_text(path, root=root)
    meta = {
        "path": str(path),
        "scope": scope,
        "exists": err not in ("NOT_FOUND",),
        "status": "parsed" if err is None else err.lower(),
    }
    if err is not None or text is None:
        return [], [], meta

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        meta["status"] = "invalid_json"
        return [], [], meta

    if not isinstance(data, dict):
        meta["status"] = "invalid_structure"
        return [], [], meta

    models: list[NormalizedModelRecord] = []
    efforts: list[NormalizedEffortRecord] = []

    configured_model = data.get("model")
    configured_effort = data.get("effortLevel")
    eff_str = (
        configured_effort.strip().lower()
        if isinstance(configured_effort, str) and configured_effort.strip()
        else None
    )

    if isinstance(configured_model, str) and configured_model.strip():
        mid = configured_model.strip()
        models.append(
            NormalizedModelRecord(
                provider=infer_provider_from_model_id(mid)
                if infer_provider_from_model_id(mid) != "unknown"
                else "anthropic",
                application_id="claude_code",
                model_id=mid,
                display_name=mid,
                availability_state=AvailabilityState.CONFIGURED,
                evidence_class=EvidenceClass.CONFIGURED,
                catalog_source="claude_settings",
                reasoning_efforts=(eff_str,) if eff_str else (),
                default_effort=eff_str,
                capabilities={},
                active_session_state=ObservationState.NOT_EXPOSED,
                observed_at=observed_at,
                evidence_id=evidence_id,
                scope=scope,
            )
        )

    if eff_str:
        efforts.append(
            NormalizedEffortRecord(
                application_id="claude_code",
                effort=eff_str,
                model_id=configured_model.strip() if isinstance(configured_model, str) and configured_model.strip() else None,
                scope=scope,
                source="claude_settings",
                evidence_class=EvidenceClass.CONFIGURED,
                is_default=True,
                supported_efforts=(eff_str,),
                evidence_id=evidence_id,
            )
        )

    avail = data.get("availableModels")
    if isinstance(avail, list):
        for item in avail:
            if isinstance(item, str) and item.strip():
                mid = item.strip()
                models.append(
                    NormalizedModelRecord(
                        provider="anthropic",
                        application_id="claude_code",
                        model_id=mid,
                        display_name=mid,
                        availability_state=AvailabilityState.CONFIGURED,
                        evidence_class=EvidenceClass.CONFIGURED,
                        catalog_source="claude_settings_available_models",
                        reasoning_efforts=(),
                        default_effort=None,
                        capabilities={},
                        active_session_state=ObservationState.NOT_EXPOSED,
                        observed_at=observed_at,
                        evidence_id=evidence_id,
                        scope=scope,
                    )
                )

    return models, efforts, meta


class ClaudeCodeAdapter(BaseDiscoveryAdapter):
    """Discovers Claude Code CLI, sanitized MCP config, and model/effort configuration."""

    application_id = "claude_code"
    application_family = "anthropic"

    def discover(self, ctx: AdapterContext) -> dict[str, Any]:
        profile = make_empty_application_profile(self.application_id, self.application_family)
        observed_at = utc_now_iso()
        errors: list[dict[str, str]] = []
        limitations: list[str] = [
            "Active Claude Code session model and effort are not exposed through a non-mutating local interface.",
            "Live MCP server connections are not probed in NEXT-22A.",
        ]

        # 1. Resolve Claude Code CLI executable
        cli_candidates = (
            ctx.user_home / ".local" / "bin" / "claude.exe",
            ctx.user_home / ".claude" / "local" / "claude.exe",
            ctx.local_appdata / "Programs" / "claude" / "claude.exe",
            ctx.appdata / "npm" / "claude.cmd",
        )
        claude_exe = ctx.cli_runner.resolve_executable("claude_code", cli_candidates)
        cli_present = claude_exe is not None
        cli_version: str | None = None
        cli_caps: list[str] = []
        help_observed = False
        executables: list[dict[str, Any]] = []
        supported_transports: list[str] | None = None
        supported_transports_ev = EvidenceClass.UNKNOWN

        if claude_exe is not None:
            ver_res = ctx.cli_runner.run(
                "claude_code", claude_exe, ("--version",), timeout_seconds=ctx.timeout_seconds
            )
            ctx.ledger.add(
                application_id=self.application_id,
                stage="cli_version",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if ver_res.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(claude_exe),
                observed_at=observed_at,
                exit_code=ver_res.exit_code,
                command_basename=claude_exe.name,
                command_args=("--version",),
            )
            if ver_res.ok and ver_res.stdout.strip():
                cli_version = ver_res.stdout.strip().splitlines()[0].strip()

            help_res = ctx.cli_runner.run(
                "claude_code", claude_exe, ("--help",), timeout_seconds=ctx.timeout_seconds
            )
            ctx.ledger.add(
                application_id=self.application_id,
                stage="cli_help",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if help_res.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(claude_exe),
                observed_at=observed_at,
                exit_code=help_res.exit_code,
                command_basename=claude_exe.name,
                command_args=("--help",),
            )
            if help_res.ok:
                help_observed = True
                if "mcp" in help_res.stdout.lower():
                    cli_caps.append("mcp")

            mcp_help_res = ctx.cli_runner.run(
                "claude_code", claude_exe, ("mcp", "--help"), timeout_seconds=ctx.timeout_seconds
            )
            ctx.ledger.add(
                application_id=self.application_id,
                stage="mcp_cli_help",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED if mcp_help_res.ok else EvidenceClass.ERROR,
                source_type="cli",
                source_ref=str(claude_exe),
                observed_at=observed_at,
                exit_code=mcp_help_res.exit_code,
                command_basename=claude_exe.name,
                command_args=("mcp", "--help"),
            )
            if mcp_help_res.ok:
                transports: list[str] = []
                low = mcp_help_res.stdout.lower()
                if "stdio" in low:
                    transports.append(TransportType.STDIO.value)
                if "http" in low:
                    transports.append(TransportType.HTTP.value)
                if "sse" in low:
                    transports.append(TransportType.SSE.value)
                if transports:
                    supported_transports = transports
                    supported_transports_ev = EvidenceClass.DOCUMENTED_CAPABILITY

            executables.append(
                {
                    "path": str(claude_exe),
                    "basename": claude_exe.name,
                    "role": "cli",
                    "version": cli_version,
                    "running": False,
                    "pids": [],
                    "evidence_class": EvidenceClass.RUNTIME_OBSERVED.value,
                }
            )
        else:
            limitations.append("Claude Code CLI executable was not found on PATH or standard install paths.")

        # 2. Sanitized MCP configuration discovery (~/.claude.json + project .mcp.json)
        servers = []
        config_sources: list[dict[str, Any]] = []

        user_claude_json = ctx.user_home / ".claude.json"
        if not is_reparse_point(user_claude_json):
            parsed_user = parse_json_mcp_config(
                user_claude_json,
                root=ctx.user_home,
                scope="user",
                default_url_transport=TransportType.HTTP,
                project_filter_path=ctx.project_path,
            )
            config_sources.append(parsed_user["source"])
            if parsed_user["error"]:
                errors.append(
                    {
                        "code": f"CLAUDE_JSON_{parsed_user['error']}",
                        "stage": "mcp_config",
                        "message": f"Failed to parse ~/.claude.json ({parsed_user['error']})",
                    }
                )
            elif parsed_user["source"]["exists"]:
                ev_id = ctx.ledger.add(
                    application_id=self.application_id,
                    stage="mcp_config",
                    evidence_class=EvidenceClass.CONFIGURED,
                    source_type="config_file",
                    source_ref=str(user_claude_json),
                    observed_at=observed_at,
                    sanitized_projection=[s.to_dict() for s in parsed_user["servers"]],
                )
                for srv in parsed_user["servers"]:
                    servers.append(type(srv)(**{**srv.__dict__, "evidence_id": ev_id}))

        if ctx.project_path is not None:
            proj_mcp = ctx.project_path / ".mcp.json"
            parsed_proj = parse_json_mcp_config(
                proj_mcp,
                root=ctx.project_path,
                scope="project",
                default_url_transport=TransportType.HTTP,
            )
            config_sources.append(parsed_proj["source"])
            if parsed_proj["error"]:
                errors.append(
                    {
                        "code": f"CLAUDE_PROJECT_MCP_{parsed_proj['error']}",
                        "stage": "mcp_config",
                        "message": f"Failed to parse project .mcp.json ({parsed_proj['error']})",
                    }
                )
            elif parsed_proj["source"]["exists"]:
                ev_id = ctx.ledger.add(
                    application_id=self.application_id,
                    stage="mcp_project_config",
                    evidence_class=EvidenceClass.CONFIGURED,
                    source_type="config_file",
                    source_ref=str(proj_mcp),
                    observed_at=observed_at,
                    sanitized_projection=[s.to_dict() for s in parsed_proj["servers"]],
                )
                for srv in parsed_proj["servers"]:
                    servers.append(type(srv)(**{**srv.__dict__, "evidence_id": ev_id}))

        # 3. Allowlisted model/effort metadata from ~/.claude/settings.json & project settings
        models: list[NormalizedModelRecord] = []
        efforts: list[NormalizedEffortRecord] = []
        settings_candidates: list[tuple[Path, Path, str]] = [
            (ctx.user_home / ".claude" / "settings.json", ctx.user_home, "user"),
        ]
        if ctx.project_path is not None:
            settings_candidates.extend(
                [
                    (ctx.project_path / ".claude" / "settings.json", ctx.project_path, "project"),
                    (ctx.project_path / ".claude" / "settings.local.json", ctx.project_path, "local"),
                ]
            )

        for cfg_path, root_bound, scope in settings_candidates:
            ev_id = ctx.ledger.add(
                application_id=self.application_id,
                stage="settings_metadata",
                evidence_class=EvidenceClass.CONFIGURED if cfg_path.exists() else EvidenceClass.UNKNOWN,
                source_type="config_file",
                source_ref=str(cfg_path),
                observed_at=observed_at,
            )
            m_list, e_list, meta = _parse_claude_settings_model_metadata(
                cfg_path,
                root=root_bound,
                scope=scope,
                observed_at=observed_at,
                evidence_id=ev_id,
            )
            config_sources.append(meta)
            models.extend(m_list)
            efforts.extend(e_list)

        if not cli_present:
            profile["installation_state"] = InstallationState.NOT_INSTALLED.value
            profile["packaging_mode"] = PackagingMode.NOT_INSTALLED.value
            profile["discovery_status"] = DiscoveryStatus.NOT_INSTALLED.value
            if any(cs.get("exists") for cs in config_sources):
                limitations.append(
                    "Claude Code CLI executable is not installed, though sanitized local/user configuration metadata was observed."
                )
        else:
            profile["installation_state"] = InstallationState.INSTALLED.value
            profile["packaging_mode"] = PackagingMode.CLI_ONLY.value
            profile["discovery_status"] = DiscoveryStatus.PARTIAL.value

        profile["version"] = {
            "value": cli_version,
            "source": "cli_version" if cli_version else "unknown",
            "confidence": "high" if cli_version else "unknown",
            "evidence_class": (
                EvidenceClass.RUNTIME_OBSERVED.value if cli_version else EvidenceClass.NOT_INSTALLED.value
            ),
        }
        profile["executables"] = executables
        profile["cli"] = {
            "present": cli_present,
            "version": cli_version,
            "path": str(claude_exe) if claude_exe else None,
            "capabilities": sorted(set(cli_caps)),
            "evidence_class": (
                EvidenceClass.RUNTIME_OBSERVED.value if cli_present else EvidenceClass.NOT_INSTALLED.value
            ),
            "help_observed": help_observed,
        }
        profile["models"] = [m.to_dict() for m in sorted(models, key=lambda x: (x.scope or "", x.model_id))]
        profile["reasoning_efforts"] = [
            e.to_dict() for e in sorted(efforts, key=lambda x: (x.scope, x.effort))
        ]
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
                    notes="Not exposed without live MCP handshake.",
                )
            },
        )
        profile["errors"] = errors
        profile["limitations"] = limitations
        return profile

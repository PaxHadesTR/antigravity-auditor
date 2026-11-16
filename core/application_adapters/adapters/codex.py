"""OpenAI Codex (CLI / ChatGPT Desktop / IDE shared config) adapter profile & TOML previews."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from application_adapters.configuration_preview import validate_launch_command, validate_preview_item
from application_adapters.contracts import (
    AdapterConfigPreview,
    AdapterInstallState,
    ApplicationAdapterProfile,
)

READONLY_ALLOWLIST_TOOLS: tuple[str, ...] = (
    "auditor_gateway_capabilities",
    "auditor_get_status",
    "auditor_get_context",
    "auditor_list_findings",
    "auditor_get_verification_status",
    "auditor_routing_inspect_profile",
    "auditor_routing_list_accounts",
    "auditor_routing_inspect_models",
    "auditor_routing_plan",
    "auditor_routing_explain_decision",
)


def _toml_str(value: str) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _parse_install_state(raw: dict[str, Any] | None) -> tuple[AdapterInstallState, str | None, str | None]:
    if not isinstance(raw, dict):
        return AdapterInstallState.UNKNOWN, None, None
    st = str(raw.get("installation_state") or "").lower()
    if st == "installed":
        cli = raw.get("cli") if isinstance(raw.get("cli"), dict) else {}
        ver = str(cli["version"]) if cli.get("version") else None
        return AdapterInstallState.INSTALLED, ver, "runtime_discovery_refresh"
    if st == "not_installed":
        return AdapterInstallState.NOT_INSTALLED, None, "runtime_discovery_refresh"
    return AdapterInstallState.UNKNOWN, None, None


class CodexApplicationAdapter:
    """Adapter profile + validated user/project config.toml previews for OpenAI Codex."""

    application_id = "codex"
    application_family = "openai"

    def build_profile(self, *, discovery_report: dict[str, Any] | None = None) -> ApplicationAdapterProfile:
        apps = (discovery_report or {}).get("applications") if isinstance(discovery_report, dict) else None
        raw = apps.get(self.application_id) if isinstance(apps, dict) else None
        install_state, version, src = _parse_install_state(raw)
        observed_at = (discovery_report or {}).get("generated_at") if isinstance(discovery_report, dict) else None
        return ApplicationAdapterProfile(
            application_id=self.application_id,
            application_family=self.application_family,
            display_name="OpenAI Codex (CLI / Desktop / IDE)",
            install_state=install_state,
            installed_version=version,
            packaging="cli+app_server_daemon",
            config_scopes={
                "user": r"%USERPROFILE%\.codex\config.toml",
                "trusted_project": r"<workspace>\.codex\config.toml",
            },
            preferred_legacy_protocol_version="2025-11-25",
            modern_runtime_wire_verified=False,
            modern_runtime_support_status="ADAPTER_CONTRACT_ONLY_NOT_VERIFIED",
            default_compatibility_hints={
                "protocolVersion": "2025-11-25",
                "clientInfo": {"name": "codex-preview-hint", "version": version or "UNKNOWN"},
                "capabilities": {},
            },
            process_match_hints=("codex.exe", "codex.EXE"),
            discovery_evidence_source=src or "static_adapter_profile",
            observed_at=str(observed_at) if observed_at else None,
            live_tested=False,
            live_authenticated=False,
            limitations=(
                "Codex CLI, ChatGPT Desktop, and IDE integrations share config.toml behavior; process identity cannot be distinguished solely via shared config.",
                "Authentication-mode separation (subscription vs API key) remains enforced by NEXT-22B/NEXT-22C router policies.",
                "codex mcp add/remove/login/logout and codex app-server are never invoked in NEXT-22D.",
            ),
        )

    def _render_toml(
        self,
        *,
        scope_label: str,
        project_root: Path,
        python_exe: str,
        entrypoint: str,
    ) -> str:
        args_list = ", ".join(_toml_str(x) for x in (entrypoint, "--application-hint", self.application_id))
        tools_list = ",\n  ".join(_toml_str(t) for t in READONLY_ALLOWLIST_TOOLS)
        return (
            f"# NEXT-22D UNAPPLIED PREVIEW ONLY ({scope_label})\n"
            "# Production MCP activation is DISABLED; do not deploy before B4-A1/B4-B & NEXT-22E.\n"
            "# CLI, Desktop, and IDE share config.toml; shared config NEVER proves caller identity.\n\n"
            'approval_policy_proposal = "on-request"\n\n'
            "[mcp_servers.antigravity_auditor_preview]\n"
            f"command = {_toml_str(python_exe)}\n"
            f"args = [{args_list}]\n"
            "startup_timeout_sec = 10\n"
            "tool_timeout_sec = 15\n"
            "enabled = false\n"
            "enabled_tools = [\n"
            f"  {tools_list},\n"
            "]\n\n"
            "[mcp_servers.antigravity_auditor_preview.env]\n"
            f"ANTIGRAVITY_AUDITOR_HOME = {_toml_str(str(project_root.resolve()))}\n"
        )

    def build_config_previews(
        self,
        *,
        project_root: Path,
        python_executable: str | None = None,
    ) -> list[AdapterConfigPreview]:
        py = python_executable or sys.executable
        entrypoint = str((project_root / "core" / "application_adapters" / "stdio_entry.py").resolve())
        cmd_errors = validate_launch_command(py, [entrypoint, "--application-hint", self.application_id])

        scopes = (
            ("user", r"%USERPROFILE%\.codex\config.toml"),
            ("trusted_project", r"<workspace>\.codex\config.toml"),
        )
        out: list[AdapterConfigPreview] = []
        for scope_name, target_path in scopes:
            toml_text = self._render_toml(
                scope_label=scope_name,
                project_root=project_root,
                python_exe=py,
                entrypoint=entrypoint,
            )
            preview = AdapterConfigPreview(
                application_id=self.application_id,
                scope_name=scope_name,
                target_path=target_path,
                content_format="toml",
                content_text=toml_text,
                validation_ok=False,
                validation_errors=tuple(cmd_errors),
                manual_install_steps=(
                    f"1. Wait until NEXT-22E live qualification and B4-A1/B4-B Broker readiness before editing {target_path}.",
                    f"2. Back up {target_path}, then manually append [mcp_servers.antigravity_auditor_preview] (set enabled = true only when authorized).",
                    "3. Do NOT run 'codex mcp add' during offline NEXT-22D qualification.",
                ),
                rollback_steps=(
                    f"1. Remove [mcp_servers.antigravity_auditor_preview] and [mcp_servers.antigravity_auditor_preview.env] from {target_path}.",
                ),
                warnings=(
                    "PREVIEW_ONLY_NOT_APPLIED: No Codex user or project config.toml was modified.",
                    "Shared Codex config across CLI/Desktop/IDE cannot establish per-process application identity.",
                ),
            )
            out.append(validate_preview_item(preview))
        return out

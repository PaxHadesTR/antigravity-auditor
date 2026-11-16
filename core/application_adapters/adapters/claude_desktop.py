"""Anthropic Claude Desktop adapter profile, Desktop Extension (.mcpb) manifest & preview."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

from application_adapters.configuration_preview import (
    build_offline_mcpb_archive,
    validate_launch_command,
    validate_preview_item,
)
from application_adapters.contracts import (
    ADAPTER_PACKAGE_VERSION,
    AdapterConfigPreview,
    AdapterInstallState,
    ApplicationAdapterProfile,
)


def _parse_install_state(raw: dict[str, Any] | None) -> tuple[AdapterInstallState, str | None, str, str | None]:
    if not isinstance(raw, dict):
        return AdapterInstallState.UNKNOWN, None, "msix_appx", None
    st = str(raw.get("installation_state") or "").lower()
    if st == "installed":
        ver = None
        pkg = "msix_appx"
        for exe in raw.get("executables") or []:
            if isinstance(exe, dict):
                if exe.get("version"):
                    ver = str(exe["version"])
                if exe.get("packaging"):
                    pkg = str(exe["packaging"])
                break
        return AdapterInstallState.INSTALLED, ver, pkg, "runtime_discovery_refresh"
    if st == "not_installed":
        return AdapterInstallState.NOT_INSTALLED, None, "none", "runtime_discovery_refresh"
    return AdapterInstallState.UNKNOWN, None, "msix_appx", None


class ClaudeDesktopApplicationAdapter:
    """Adapter profile + Desktop Extension (.mcpb) manifest & offline package builder."""

    application_id = "claude_desktop"
    application_family = "anthropic"

    def build_profile(self, *, discovery_report: dict[str, Any] | None = None) -> ApplicationAdapterProfile:
        apps = (discovery_report or {}).get("applications") if isinstance(discovery_report, dict) else None
        raw = apps.get(self.application_id) if isinstance(apps, dict) else None
        install_state, version, pkg, src = _parse_install_state(raw)
        observed_at = (discovery_report or {}).get("generated_at") if isinstance(discovery_report, dict) else None
        return ApplicationAdapterProfile(
            application_id=self.application_id,
            application_family=self.application_family,
            display_name="Anthropic Claude Desktop",
            install_state=install_state,
            installed_version=version,
            packaging=pkg,
            config_scopes={
                "dxt_extension": "antigravity-auditor-adapter.mcpb (manifest.json, unapplied offline package)",
                "desktop_config_reference": r"%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\claude_desktop_config.json (PROTECTED / UNTOUCHED)",
            },
            preferred_legacy_protocol_version="2025-11-25",
            modern_runtime_wire_verified=False,
            modern_runtime_support_status="ADAPTER_CONTRACT_ONLY_NOT_VERIFIED",
            default_compatibility_hints={
                "protocolVersion": "2025-11-25",
                "clientInfo": {"name": "claude-desktop-preview-hint", "version": version or "UNKNOWN"},
                "capabilities": {},
            },
            process_match_hints=("claude.exe",),
            discovery_evidence_source=src or "static_adapter_profile",
            observed_at=str(observed_at) if observed_at else None,
            live_tested=False,
            live_authenticated=False,
            limitations=(
                "MSIX/AppX user-data root and authentication tokens are strictly protected and never accessed.",
                "Remote Claude Connectors are NOT_EXPOSED in local discovery.",
                "Desktop Extension (.mcpb) package is offline-validated only and NEVER installed or registered in NEXT-22D.",
            ),
        )

    def build_dxt_manifest_dict(
        self,
        *,
        project_root: Path,
        python_executable: str | None = None,
    ) -> tuple[dict[str, Any], list[str]]:
        py = python_executable or sys.executable
        entrypoint = str((project_root / "core" / "application_adapters" / "stdio_entry.py").resolve())
        args = [entrypoint, "--application-hint", self.application_id]
        cmd_errors = validate_launch_command(py, args)

        manifest = {
            "dxt_version": "0.2",
            "name": "antigravity-auditor-adapter",
            "display_name": "Antigravity Auditor Adaptive MCP Adapter",
            "version": "0.1.0",
            "description": (
                "Offline Desktop Extension contract forwarding read-only audit & routing queries "
                "through the NEXT-22C Adaptive MCP Gateway (NEXT-22D preview only; production disabled)."
            ),
            "author": {"name": "Antigravity Auditor"},
            "server": {
                "type": "stdio",
                "entry_point": entrypoint,
                "mcp_config": {
                    "command": py,
                    "args": args,
                    "env": {
                        "ANTIGRAVITY_AUDITOR_HOME": str(project_root.resolve()),
                    },
                },
            },
            "permissions": {
                "filesystem": "none_direct_adapter_uses_broker_ipc",
                "network": "denied",
                "subprocess": "denied",
                "credentials": "none_embedded",
            },
            "user_config": {
                "protocol_version_hint": {
                    "type": "string",
                    "title": "Preferred MCP Protocol Revision Hint",
                    "description": "Informational MCP revision hint (2025-11-25 recommended for legacy stdio).",
                    "default": "2025-11-25",
                    "required": False,
                },
                "workspace_root": {
                    "type": "directory",
                    "title": "Target Audit Workspace (Read-Only Scope)",
                    "description": "Optional workspace hint; authorization remains governed by Windows Broker policy.",
                    "required": False,
                },
            },
            "compatibility": {
                "platforms": ["win32"],
                "adapter_package_version": ADAPTER_PACKAGE_VERSION,
                "runtime_wire_verified": False,
                "production_activated": False,
            },
        }
        return manifest, cmd_errors

    def build_config_previews(
        self,
        *,
        project_root: Path,
        python_executable: str | None = None,
    ) -> list[AdapterConfigPreview]:
        manifest, cmd_errors = self.build_dxt_manifest_dict(
            project_root=project_root,
            python_executable=python_executable,
        )
        preview = AdapterConfigPreview(
            application_id=self.application_id,
            scope_name="dxt_extension_manifest",
            target_path="antigravity-auditor-adapter.mcpb!manifest.json",
            content_format="dxt_manifest",
            content_text=json.dumps(manifest, indent=2) + "\n",
            validation_ok=False,
            validation_errors=tuple(cmd_errors),
            manual_install_steps=(
                "1. Do NOT install during NEXT-22D; wait for B4-A1/B4-B Broker and NEXT-22E wire qualification.",
                "2. In a later qualified release, double-click or import antigravity-auditor-adapter.mcpb via Claude Desktop Extensions UI.",
                "3. Never embed API keys, cookies, or HMAC secrets into manifest.json or user_config.",
            ),
            rollback_steps=(
                "1. In Claude Desktop -> Settings -> Extensions, disable and uninstall 'antigravity-auditor-adapter'.",
                "2. Remove the local .mcpb artifact if desired.",
            ),
            warnings=(
                "PREVIEW_AND_OFFLINE_PACKAGE_ONLY: Not installed or registered in Claude Desktop MSIX data root.",
                "Manifest contains zero credentials and grants zero execution authority.",
            ),
        )
        return [validate_preview_item(preview)]

    def build_offline_package(
        self,
        *,
        project_root: Path,
        output_mcpb_path: Path,
        python_executable: str | None = None,
    ) -> dict[str, Any]:
        manifest, cmd_errors = self.build_dxt_manifest_dict(
            project_root=project_root,
            python_executable=python_executable,
        )
        if cmd_errors:
            raise ValueError(f"Unsafe Desktop Extension launch command: {cmd_errors}")
        readme = (
            "Antigravity Auditor NEXT-22D Offline Desktop Extension (.mcpb)\n"
            "NOT INSTALLED / NOT PRODUCTION ACTIVATED.\n"
            "Zero secrets embedded.\n"
        )
        return build_offline_mcpb_archive(
            manifest_json_text=json.dumps(manifest, indent=2),
            output_mcpb_path=output_mcpb_path,
            readme_text=readme,
        )

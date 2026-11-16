"""Google Antigravity application adapter profile & secret-free MCP config previews."""

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

PREVIEW_SERVER_NAME = "antigravity-auditor-next22d-preview"
EXISTING_BASELINE_SERVER_NAME = "antigravity-auditor"


def _parse_install_state(raw: dict[str, Any] | None) -> tuple[AdapterInstallState, str | None, str | None]:
    if not isinstance(raw, dict):
        return AdapterInstallState.UNKNOWN, None, None
    st = str(raw.get("installation_state") or "").lower()
    if st == "installed":
        ver = None
        for exe in raw.get("executables") or []:
            if isinstance(exe, dict) and exe.get("role") == "desktop_app" and exe.get("version"):
                ver = str(exe["version"])
                break
        cli = raw.get("cli") if isinstance(raw.get("cli"), dict) else {}
        if ver and cli.get("version"):
            ver = f"{ver} (agy CLI {cli['version']})"
        elif cli.get("version"):
            ver = f"agy CLI {cli['version']}"
        return AdapterInstallState.INSTALLED, ver, "runtime_discovery_refresh"
    if st == "not_installed":
        return AdapterInstallState.NOT_INSTALLED, None, "runtime_discovery_refresh"
    return AdapterInstallState.UNKNOWN, None, None


class AntigravityApplicationAdapter:
    """Adapter profile + non-destructive global/workspace previews for Google Antigravity."""

    application_id = "antigravity"
    application_family = "google"

    def build_profile(self, *, discovery_report: dict[str, Any] | None = None) -> ApplicationAdapterProfile:
        apps = (discovery_report or {}).get("applications") if isinstance(discovery_report, dict) else None
        raw = apps.get(self.application_id) if isinstance(apps, dict) else None
        install_state, version, src = _parse_install_state(raw)
        observed_at = (discovery_report or {}).get("generated_at") if isinstance(discovery_report, dict) else None
        return ApplicationAdapterProfile(
            application_id=self.application_id,
            application_family=self.application_family,
            display_name="Google Antigravity",
            install_state=install_state,
            installed_version=version,
            packaging="desktop_app+cli",
            config_scopes={
                "global": r"%USERPROFILE%\.gemini\config\mcp_config.json",
                "workspace": r"<workspace>\.agents\mcp_config.json",
            },
            preferred_legacy_protocol_version="2025-11-25",
            modern_runtime_wire_verified=False,
            modern_runtime_support_status="ADAPTER_CONTRACT_ONLY_NOT_VERIFIED",
            default_compatibility_hints={
                "protocolVersion": "2025-11-25",
                "clientInfo": {"name": "antigravity-preview-hint", "version": version or "UNKNOWN"},
                "capabilities": {"tools": {"listChanged": False}},
            },
            process_match_hints=("Antigravity.exe", "agy.EXE"),
            discovery_evidence_source=src or "static_adapter_profile",
            observed_at=str(observed_at) if observed_at else None,
            live_tested=False,
            live_authenticated=False,
            limitations=(
                "Configuration previews only; ~/.gemini/config/mcp_config.json and <workspace>/.agents/mcp_config.json are never modified in NEXT-22D.",
                "Existing baseline server entry 'antigravity-auditor' is preserved untouched.",
                "Live Antigravity MCP wire session and OS/HMAC production identity verification are not activated in NEXT-22D.",
            ),
        )

    def build_config_previews(
        self,
        *,
        project_root: Path,
        python_executable: str | None = None,
        existing_global_servers: dict[str, Any] | None = None,
    ) -> list[AdapterConfigPreview]:
        py = python_executable or sys.executable
        entrypoint = str((project_root / "core" / "application_adapters" / "stdio_entry.py").resolve())
        args = [entrypoint, "--application-hint", self.application_id]
        cmd_errors = validate_launch_command(py, args)

        proposed_entry = {
            "command": py,
            "args": args,
            "env": {
                "ANTIGRAVITY_AUDITOR_HOME": str(project_root.resolve()),
            },
            "disabled": False,
        }

        existing = dict(existing_global_servers or {})
        merged_global = dict(existing)
        if PREVIEW_SERVER_NAME in existing:
            cmd_errors.append(f"DUPLICATE_SERVER_NAME:{PREVIEW_SERVER_NAME}")
        merged_global[PREVIEW_SERVER_NAME] = proposed_entry

        global_doc = {
            "_preview_metadata": {
                "applied": False,
                "phase": "NEXT-22D",
                "preserves_existing_server": EXISTING_BASELINE_SERVER_NAME,
            },
            "mcpServers": merged_global,
        }
        ws_doc = {
            "_preview_metadata": {
                "applied": False,
                "phase": "NEXT-22D",
                "scope": "workspace",
            },
            "mcpServers": {
                PREVIEW_SERVER_NAME: proposed_entry,
            },
        }

        previews = [
            AdapterConfigPreview(
                application_id=self.application_id,
                scope_name="global",
                target_path=r"%USERPROFILE%\.gemini\config\mcp_config.json",
                content_format="json",
                content_text=json.dumps(global_doc, indent=2) + "\n",
                validation_ok=False,
                validation_errors=tuple(cmd_errors),
                manual_install_steps=(
                    "1. Review and verify B4-A1/B4-B Windows Broker and NEXT-22E live protocol qualification first (not active in NEXT-22D).",
                    "2. Back up %USERPROFILE%\\.gemini\\config\\mcp_config.json while preserving existing 'antigravity-auditor'.",
                    f"3. Manually merge only the '{PREVIEW_SERVER_NAME}' object under 'mcpServers' (omit '_preview_metadata').",
                ),
                rollback_steps=(
                    f"1. Remove '{PREVIEW_SERVER_NAME}' from 'mcpServers' in %USERPROFILE%\\.gemini\\config\\mcp_config.json.",
                    "2. Restore original backup if needed; keep 'antigravity-auditor' unchanged.",
                ),
                warnings=(
                    "PREVIEW_ONLY_NOT_APPLIED: Does not activate production MCP or modify Antigravity config.",
                    f"Existing '{EXISTING_BASELINE_SERVER_NAME}' entry is never overwritten by this preview.",
                ),
            ),
            AdapterConfigPreview(
                application_id=self.application_id,
                scope_name="workspace",
                target_path=r"<workspace>\.agents\mcp_config.json",
                content_format="json",
                content_text=json.dumps(ws_doc, indent=2) + "\n",
                validation_ok=False,
                validation_errors=tuple(cmd_errors),
                manual_install_steps=(
                    "1. After NEXT-22E qualification, manually add only the 'mcpServers' block to <workspace>\\.agents\\mcp_config.json (omit '_preview_metadata').",
                ),
                rollback_steps=(
                    f"1. Remove '{PREVIEW_SERVER_NAME}' from <workspace>\\.agents\\mcp_config.json.",
                ),
                warnings=("PREVIEW_ONLY_NOT_APPLIED: Workspace config file was not written.",),
            ),
        ]
        return [validate_preview_item(p) for p in previews]

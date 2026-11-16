"""Central registry for NEXT-22D application-specific adapter profiles & previews."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from application_adapters.adapters.antigravity import AntigravityApplicationAdapter
from application_adapters.adapters.claude_code import ClaudeCodeApplicationAdapter
from application_adapters.adapters.claude_desktop import ClaudeDesktopApplicationAdapter
from application_adapters.adapters.codex import CodexApplicationAdapter
from application_adapters.contracts import (
    ADAPTER_PACKAGE_VERSION,
    AdapterConfigPreview,
    ApplicationAdapterProfile,
)


class ApplicationAdapterRegistry:
    """Authoritative in-code registry mapping target apps to shared Gateway adapter profiles."""

    def __init__(self) -> None:
        self._antigravity = AntigravityApplicationAdapter()
        self._claude_desktop = ClaudeDesktopApplicationAdapter()
        self._codex = CodexApplicationAdapter()
        self._claude_code = ClaudeCodeApplicationAdapter()
        self._adapters = {
            self._antigravity.application_id: self._antigravity,
            self._claude_code.application_id: self._claude_code,
            self._claude_desktop.application_id: self._claude_desktop,
            self._codex.application_id: self._codex,
        }

    @property
    def antigravity(self) -> AntigravityApplicationAdapter:
        return self._antigravity

    @property
    def claude_desktop(self) -> ClaudeDesktopApplicationAdapter:
        return self._claude_desktop

    @property
    def codex(self) -> CodexApplicationAdapter:
        return self._codex

    @property
    def claude_code(self) -> ClaudeCodeApplicationAdapter:
        return self._claude_code

    def supported_application_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters.keys()))

    def get_profile(
        self,
        application_id: str,
        *,
        discovery_report: dict[str, Any] | None = None,
    ) -> ApplicationAdapterProfile:
        adapter = self._adapters.get(application_id)
        if adapter is None:
            raise KeyError(f"Unknown application adapter ID: '{application_id}'")
        return adapter.build_profile(discovery_report=discovery_report)

    def list_profiles(
        self,
        *,
        discovery_report: dict[str, Any] | None = None,
    ) -> list[ApplicationAdapterProfile]:
        return [
            self.get_profile(app_id, discovery_report=discovery_report)
            for app_id in self.supported_application_ids()
        ]

    def build_all_previews(
        self,
        *,
        project_root: Path,
        python_executable: str | None = None,
        discovery_report: dict[str, Any] | None = None,
        existing_antigravity_servers: dict[str, Any] | None = None,
    ) -> list[AdapterConfigPreview]:
        previews: list[AdapterConfigPreview] = []
        previews.extend(
            self._antigravity.build_config_previews(
                project_root=project_root,
                python_executable=python_executable,
                existing_global_servers=existing_antigravity_servers,
            )
        )
        previews.extend(
            self._claude_desktop.build_config_previews(
                project_root=project_root,
                python_executable=python_executable,
            )
        )
        previews.extend(
            self._codex.build_config_previews(
                project_root=project_root,
                python_executable=python_executable,
            )
        )
        previews.append(self._claude_code.build_status_report(discovery_report=discovery_report))
        return previews

    def export_manifest(self, *, discovery_report: dict[str, Any] | None = None) -> dict[str, Any]:
        profiles = self.list_profiles(discovery_report=discovery_report)
        return {
            "schema_version": "next-22d-adapter-manifest-v1",
            "adapter_package_version": ADAPTER_PACKAGE_VERSION,
            "shared_host": "core.application_adapters.adapter_runtime.CommonStdioAdapterHost",
            "authoritative_gateway": "core.mcp_gateway.gateway.AdaptiveMCPGateway",
            "duplicated_tool_handlers": False,
            "production_activated": False,
            "modern_runtime_wire_verified": False,
            "applications": [p.to_dict() for p in profiles],
        }

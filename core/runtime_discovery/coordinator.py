"""Coordinator for read-only multi-application runtime discovery (NEXT-22A)."""

from __future__ import annotations

import json
import os
import platform
import uuid
from pathlib import Path
from typing import Any, Sequence

from runtime_discovery.adapters.antigravity import AntigravityAdapter
from runtime_discovery.adapters.base import AdapterContext, BaseDiscoveryAdapter
from runtime_discovery.adapters.claude_code import ClaudeCodeAdapter
from runtime_discovery.adapters.claude_desktop import ClaudeDesktopAdapter
from runtime_discovery.adapters.codex import CodexAdapter
from runtime_discovery.cli_detection import CliRunner, DEFAULT_CLI_TIMEOUT_SECONDS, DefaultCliRunner
from runtime_discovery.contracts import (
    DiscoveryStatus,
    EvidenceClass,
    InstallationState,
    SCHEMA_ID,
    SCHEMA_VERSION,
    make_empty_application_profile,
)
from runtime_discovery.evidence import EvidenceLedger, utc_now_iso
from runtime_discovery.redaction import redact_mapping_for_audit, sanitize_exception
from runtime_discovery.windows_detection import DefaultWindowsHostInspector, WindowsHostInspector


def load_runtime_discovery_schema() -> dict[str, Any]:
    """Load the canonical versioned JSON Schema bundled with core/runtime_discovery."""
    schema_path = Path(__file__).resolve().parent / "schemas" / "runtime_discovery.schema.json"
    return json.loads(schema_path.read_text(encoding="utf-8"))


def default_adapters() -> tuple[BaseDiscoveryAdapter, ...]:
    """Return the default deterministic set of application discovery adapters."""
    return (
        AntigravityAdapter(),
        ClaudeCodeAdapter(),
        ClaudeDesktopAdapter(),
        CodexAdapter(),
    )


class RuntimeDiscoveryCoordinator:
    """Executes isolated, read-only application discovery adapters and builds sanitized reports."""

    def __init__(
        self,
        *,
        adapters: Sequence[BaseDiscoveryAdapter] | None = None,
        host_inspector: WindowsHostInspector | None = None,
        cli_runner: CliRunner | None = None,
        user_home: Path | None = None,
        local_appdata: Path | None = None,
        appdata: Path | None = None,
        program_files: Path | None = None,
        timeout_seconds: float = DEFAULT_CLI_TIMEOUT_SECONDS,
    ) -> None:
        self._adapters = tuple(
            sorted(adapters or default_adapters(), key=lambda a: a.application_id)
        )
        self._host_inspector = host_inspector or DefaultWindowsHostInspector()
        self._cli_runner = cli_runner or DefaultCliRunner()
        self._user_home = user_home or Path.home()
        self._local_appdata = local_appdata or Path(
            os.environ.get("LOCALAPPDATA", str(self._user_home / "AppData" / "Local"))
        )
        self._appdata = appdata or Path(
            os.environ.get("APPDATA", str(self._user_home / "AppData" / "Roaming"))
        )
        self._program_files = program_files or Path(
            os.environ.get("ProgramFiles", r"C:\Program Files")
        )
        self._timeout_seconds = timeout_seconds

    def discover(
        self,
        *,
        project_path: Path | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        """Run all adapters with per-adapter error isolation and return a deterministic report."""
        effective_run_id = run_id or f"next22a-{uuid.uuid4().hex[:12]}"
        ledger = EvidenceLedger(run_id=effective_run_id)
        ctx = AdapterContext(
            user_home=self._user_home,
            local_appdata=self._local_appdata,
            appdata=self._appdata,
            program_files=self._program_files,
            project_path=project_path.resolve() if project_path else None,
            host_inspector=self._host_inspector,
            cli_runner=self._cli_runner,
            ledger=ledger,
            timeout_seconds=self._timeout_seconds,
        )

        applications: dict[str, dict[str, Any]] = {}
        for adapter in self._adapters:
            try:
                profile = adapter.discover(ctx)
            except Exception as exc:
                profile = make_empty_application_profile(
                    adapter.application_id, adapter.application_family
                )
                profile["installation_state"] = InstallationState.ERROR.value
                profile["discovery_status"] = DiscoveryStatus.ERROR.value
                profile["errors"] = [
                    {
                        "code": "ADAPTER_UNHANDLED_ERROR",
                        "stage": "adapter",
                        "message": sanitize_exception(exc),
                    }
                ]
                ledger.add(
                    application_id=adapter.application_id,
                    stage="adapter",
                    evidence_class=EvidenceClass.ERROR,
                    source_type="adapter",
                    source_ref=type(adapter).__name__,
                    notes=sanitize_exception(exc),
                )
            applications[adapter.application_id] = redact_mapping_for_audit(profile)

        ordered_apps = {k: applications[k] for k in sorted(applications.keys())}
        installed_count = sum(
            1
            for p in ordered_apps.values()
            if p.get("installation_state") == InstallationState.INSTALLED.value
        )
        not_installed_count = sum(
            1
            for p in ordered_apps.values()
            if p.get("installation_state") == InstallationState.NOT_INSTALLED.value
        )
        error_count = sum(
            1
            for p in ordered_apps.values()
            if p.get("discovery_status") == DiscoveryStatus.ERROR.value
            or len(p.get("errors", [])) > 0
        )
        models_total = sum(len(p.get("models", [])) for p in ordered_apps.values())
        mcp_servers_total = sum(
            len(p.get("mcp", {}).get("servers", [])) for p in ordered_apps.values()
        )

        return {
            "schema_version": SCHEMA_VERSION,
            "schema_id": SCHEMA_ID,
            "run_id": effective_run_id,
            "generated_at": utc_now_iso(),
            "host": {
                "os": platform.system(),
                "os_release": platform.release(),
                "os_version": platform.version(),
                "architecture": platform.machine(),
                "python_version": platform.python_version(),
            },
            "read_only_guarantees": {
                "no_production_db_access": True,
                "no_configured_mcp_launch": True,
                "no_network_calls": True,
                "no_config_mutations": True,
                "secret_redaction_applied": True,
            },
            "applications": ordered_apps,
            "summary": {
                "applications_total": len(ordered_apps),
                "installed_count": installed_count,
                "not_installed_count": not_installed_count,
                "error_count": error_count,
                "models_total": models_total,
                "mcp_servers_total": mcp_servers_total,
            },
            "evidence_manifest": ledger.to_manifest(),
        }


def extract_model_catalog_inventory(report: dict[str, Any]) -> dict[str, Any]:
    """Project normalized model records grouped by application and availability state."""
    models: list[dict[str, Any]] = []
    by_state: dict[str, int] = {}
    for app_id in sorted(report.get("applications", {}).keys()):
        app = report["applications"][app_id]
        for model in app.get("models", []):
            models.append(model)
            st = str(model.get("availability_state", "unknown"))
            by_state[st] = by_state.get(st, 0) + 1
    return {
        "schema_version": report.get("schema_version"),
        "run_id": report.get("run_id"),
        "generated_at": report.get("generated_at"),
        "counts_by_availability_state": dict(sorted(by_state.items())),
        "models": models,
    }


def extract_reasoning_effort_inventory(report: dict[str, Any]) -> dict[str, Any]:
    """Project reasoning effort metadata across discovered applications."""
    efforts: list[dict[str, Any]] = []
    for app_id in sorted(report.get("applications", {}).keys()):
        efforts.extend(report["applications"][app_id].get("reasoning_efforts", []))
    return {
        "schema_version": report.get("schema_version"),
        "run_id": report.get("run_id"),
        "generated_at": report.get("generated_at"),
        "effort_count": len(efforts),
        "efforts": efforts,
    }


def extract_mcp_configuration_inventory(report: dict[str, Any]) -> dict[str, Any]:
    """Project sanitized MCP configuration sources and servers."""
    apps_mcp: dict[str, Any] = {}
    for app_id in sorted(report.get("applications", {}).keys()):
        mcp = report["applications"][app_id].get("mcp", {})
        apps_mcp[app_id] = {
            "configured": mcp.get("configured", False),
            "transports": mcp.get("transports", []),
            "config_sources": mcp.get("config_sources", []),
            "servers": mcp.get("servers", []),
        }
    return {
        "schema_version": report.get("schema_version"),
        "run_id": report.get("run_id"),
        "generated_at": report.get("generated_at"),
        "applications": apps_mcp,
    }


def extract_protocol_capability_matrix(report: dict[str, Any]) -> dict[str, Any]:
    """Project the 17-dimension MCP capability matrix per application."""
    matrix: dict[str, Any] = {}
    for app_id in sorted(report.get("applications", {}).keys()):
        mcp = report["applications"][app_id].get("mcp", {})
        matrix[app_id] = mcp.get("capabilities", {})
    return {
        "schema_version": report.get("schema_version"),
        "run_id": report.get("run_id"),
        "generated_at": report.get("generated_at"),
        "matrix": matrix,
    }


def render_application_inventory_markdown(report: dict[str, Any]) -> str:
    """Render a concise sanitized Markdown inventory table from a discovery report."""
    lines = [
        "# Runtime Discovery Application Inventory",
        "",
        f"- **Run ID**: `{report.get('run_id')}`",
        f"- **Generated At**: `{report.get('generated_at')}`",
        f"- **Schema Version**: `{report.get('schema_version')}`",
        f"- **Host**: `{report.get('host', {}).get('os')} {report.get('host', {}).get('os_release')} ({report.get('host', {}).get('architecture')})`",
        "",
        "| Application | Family | State | Packaging | Version | CLI | Models | MCP Servers | Status |",
        "| --- | --- | --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for app_id in sorted(report.get("applications", {}).keys()):
        app = report["applications"][app_id]
        ver = app.get("version", {}).get("value") or "UNKNOWN"
        cli_flag = "yes" if app.get("cli", {}).get("present") else "no"
        m_count = len(app.get("models", []))
        s_count = len(app.get("mcp", {}).get("servers", []))
        lines.append(
            f"| `{app_id}` | `{app.get('application_family')}` | `{app.get('installation_state')}` | "
            f"`{app.get('packaging_mode')}` | `{ver}` | `{cli_flag}` | {m_count} | {s_count} | `{app.get('discovery_status')}` |"
        )
    lines.append("")
    return "\n".join(lines)

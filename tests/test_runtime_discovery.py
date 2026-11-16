"""Deterministic tests for NEXT-22A Read-Only Multi-Application Runtime Discovery."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import cli
from runtime_discovery import (
    AvailabilityState,
    CapabilityStatus,
    DiscoveryStatus,
    EvidenceClass,
    InstallationState,
    MCP_CAPABILITY_DIMENSIONS,
    ObservationState,
    PackagingMode,
    RuntimeDiscoveryCoordinator,
    SCHEMA_VERSION,
    TransportType,
    extract_mcp_configuration_inventory,
    extract_model_catalog_inventory,
    extract_protocol_capability_matrix,
    extract_reasoning_effort_inventory,
    load_runtime_discovery_schema,
    render_application_inventory_markdown,
)
from runtime_discovery.adapters.base import AdapterContext, BaseDiscoveryAdapter
from runtime_discovery.cli_detection import CliCommandResult, validate_cli_invocation
from runtime_discovery.redaction import (
    canonical_sanitized_sha256,
    extract_safe_hostname,
    redact_text,
    safe_command_basename,
    sanitize_exception,
)
from runtime_discovery.windows_detection import (
    AppxPackageInfo,
    RunningProcessInfo,
    UninstallEntry,
    is_reparse_point,
    safe_list_dir_names,
    safe_read_text,
)


class FakeHostInspector:
    """Deterministic read-only host inspector stub."""

    def __init__(
        self,
        *,
        file_versions: dict[str, str] | None = None,
        processes: list[RunningProcessInfo] | None = None,
        appx_packages: list[AppxPackageInfo] | None = None,
        uninstall_entries: list[UninstallEntry] | None = None,
    ) -> None:
        self.file_versions = {k.lower(): v for k, v in (file_versions or {}).items()}
        self.processes = processes or []
        self.appx_packages = appx_packages or []
        self.uninstall_entries = uninstall_entries or []

    def get_file_version(self, path: Path) -> str | None:
        return self.file_versions.get(str(path).lower())

    def list_processes(self, name_filters: tuple[str, ...] | None = None) -> list[RunningProcessInfo]:
        if not name_filters:
            return list(self.processes)
        low = tuple(f.lower() for f in name_filters)
        return [p for p in self.processes if any(t in p.name.lower() for t in low)]

    def find_appx_packages(self, name_tokens: tuple[str, ...]) -> list[AppxPackageInfo]:
        low = tuple(t.lower() for t in name_tokens)
        return [
            p
            for p in self.appx_packages
            if any(t in p.package_full_name.lower() or t in p.name.lower() for t in low)
        ]

    def find_uninstall_entries(self, name_tokens: tuple[str, ...]) -> list[UninstallEntry]:
        low = tuple(t.lower() for t in name_tokens)
        return [e for e in self.uninstall_entries if any(t in e.display_name.lower() for t in low)]


class FakeCliRunner:
    """Deterministic allowlisted CLI runner stub that verifies every invocation."""

    def __init__(
        self,
        executables: dict[str, Path] | None = None,
        responses: dict[tuple[str, tuple[str, ...]], CliCommandResult] | None = None,
    ) -> None:
        self.executables = executables or {}
        self.responses = responses or {}
        self.invocations: list[tuple[str, str, tuple[str, ...]]] = []

    def resolve_executable(self, app_id: str, candidates: tuple[Path, ...] = ()) -> Path | None:
        return self.executables.get(app_id)

    def run(
        self,
        app_id: str,
        executable: Path,
        args: tuple[str, ...],
        *,
        timeout_seconds: float = 8.0,
    ) -> CliCommandResult:
        validate_cli_invocation(app_id, executable, args)
        self.invocations.append((app_id, str(executable), tuple(args)))
        res = self.responses.get((app_id, tuple(args)))
        if res is not None:
            return res
        return CliCommandResult(
            ok=False,
            executable_path=str(executable),
            executable_basename=executable.name,
            args=tuple(args),
            exit_code=1,
            stdout="",
            stderr="",
            error_code="UNMOCKED_CMD",
            error_message="No mocked response",
        )


def _create_dummy_file(path: Path, content: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _build_full_fixture_env(tmp_path: Path) -> tuple[dict[str, Path], FakeHostInspector, FakeCliRunner]:
    home = tmp_path / "home"
    localapp = tmp_path / "localapp"
    appdata = tmp_path / "appdata"
    progfiles = tmp_path / "progfiles"
    project = tmp_path / "project"
    for d in (home, localapp, appdata, progfiles, project):
        d.mkdir(parents=True, exist_ok=True)

    # Antigravity executables + config
    agy_app = _create_dummy_file(localapp / "Programs" / "Antigravity" / "Antigravity.exe", "pe")
    agy_cli = _create_dummy_file(localapp / "agy" / "bin" / "agy.EXE", "pe")
    _create_dummy_file(
        home / ".gemini" / "config" / "mcp_config.json",
        json.dumps(
            {
                "mcpServers": {
                    "auditor-stdio": {
                        "command": r"C:\Python315\python.exe",
                        "args": ["mcp_serve.py", "--api-key", "sk-ant-supersecret1234567890"],
                        "env": {"AUDITOR_SECRET_TOKEN": "tok-supersecret-999999"},
                    },
                    "remote-http": {
                        "type": "streamable_http",
                        "serverUrl": "https://user:pass@mcp.example.com:8443/v1/mcp?token=secret123",
                        "headers": {"Authorization": "Bearer secret-bearer-token-value"},
                    },
                }
            }
        ),
    )
    _create_dummy_file(
        project / ".agents" / "mcp_config.json",
        json.dumps(
            {
                "mcpServers": {
                    "legacy-sse": {
                        "type": "sse",
                        "url": "https://sse.internal.local/events",
                    }
                }
            }
        ),
    )

    # Claude Desktop MSIX + redirected user-data
    msix_root = progfiles / "WindowsApps" / "Claude_5.11492.2.0_x64__pzs8sxrjxfjjc"
    claude_desktop_exe = _create_dummy_file(msix_root / "app" / "claude.exe", "pe")
    claude_msix_roaming = (
        localapp / "Packages" / "Claude_pzs8sxrjxfjjc" / "LocalCache" / "Roaming" / "Claude"
    )
    _create_dummy_file(
        claude_msix_roaming / "claude_desktop_config.json",
        json.dumps(
            {
                "mcpServers": {
                    "local-fs": {
                        "command": "/usr/local/bin/npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "pw=hunter2"],
                        "env": {"FS_PASSWD": "hunter2-secret-value"},
                    }
                }
            }
        ),
    )
    (claude_msix_roaming / "Claude Extensions" / "sample-ext").mkdir(parents=True, exist_ok=True)

    # Claude Code CLI + ~/.claude.json + settings.json
    claude_cli = _create_dummy_file(home / ".local" / "bin" / "claude.exe", "pe")
    _create_dummy_file(
        home / ".claude.json",
        json.dumps(
            {
                "oauthAccount": {
                    "emailAddress": "secret@example.com",
                    "accessToken": "sk-ant-oauth-secret-1234567890",
                },
                "mcpServers": {
                    "mcacp": {
                        "type": "http",
                        "url": "https://gateway.anthropic.example/mcp",
                        "headers": {"X-Api-Key": "sk-ant-secret-header-value"},
                    }
                },
                "projects": {
                    str(project): {
                        "mcpServers": {
                            "proj-tool": {
                                "command": "node",
                                "args": ["server.js", "--secret=abc"],
                            }
                        }
                    }
                },
            }
        ),
    )
    _create_dummy_file(
        home / ".claude" / "settings.json",
        json.dumps(
            {
                "model": "claude-sonnet-5-5",
                "effortLevel": "high",
                "env": {"ANTHROPIC_API_KEY": "sk-ant-never-leak-this-key"},
            }
        ),
    )

    # Codex CLI + daemon + config.toml
    codex_cli = _create_dummy_file(localapp / "Programs" / "OpenAI" / "Codex" / "bin" / "codex.exe", "pe")
    _create_dummy_file(
        home / ".codex" / "config.toml",
        (
            'model = "gpt-6-astra"\n'
            'model_reasoning_effort = "medium"\n'
            "\n"
            "[mcp_servers.docs]\n"
            'url = "https://developers.openai.com/mcp"\n'
            'bearer_token_env_var = "OPENAI_DOCS_TOKEN"\n'
            "\n"
            "[mcp_servers.custom_unknown]\n"
            'type = "custom_future_transport"\n'
        ),
    )
    # Plant a sensitive auth.json that must NEVER be read
    _create_dummy_file(
        home / ".codex" / "auth.json",
        json.dumps({"OPENAI_API_KEY": "sk-proj-DO-NOT-READ-THIS-SECRET-9999"}),
    )

    inspector = FakeHostInspector(
        file_versions={
            str(agy_app): "2.31.2.0",
            str(agy_cli): "1.5.7.0",
            str(claude_desktop_exe): "5.11492.2.0",
            str(codex_cli): "0.169.0.0",
        },
        processes=[
            RunningProcessInfo(pid=101, name="Antigravity.exe", executable_path=str(agy_app)),
            RunningProcessInfo(pid=202, name="claude.exe", executable_path=str(claude_desktop_exe)),
            RunningProcessInfo(pid=303, name="codex.exe", executable_path=str(codex_cli)),
        ],
        appx_packages=[
            AppxPackageInfo(
                name="Claude",
                package_full_name="Claude_5.11492.2.0_x64__pzs8sxrjxfjjc",
                package_family_name="Claude_pzs8sxrjxfjjc",
                version="5.11492.2.0",
                install_location=str(msix_root),
            )
        ],
    )

    bundled_codex_json = json.dumps(
        {
            "models": [
                {
                    "slug": "gpt-6-astra",
                    "display_name": "GPT-6-Astra",
                    "default_reasoning_level": "low",
                    "supported_reasoning_levels": [
                        {"effort": "low", "description": "Fast"},
                        {"effort": "medium", "description": "Balanced"},
                        {"effort": "high", "description": "Deep"},
                    ],
                    "context_window": 400000,
                    "visibility": "list",
                    "supported_in_api": True,
                }
            ]
        }
    )

    runner = FakeCliRunner(
        executables={
            "antigravity": agy_cli,
            "claude_code": claude_cli,
            "codex": codex_cli,
        },
        responses={
            ("antigravity", ("--version",)): CliCommandResult(
                ok=True, executable_path=str(agy_cli), executable_basename="agy.EXE",
                args=("--version",), exit_code=0, stdout="1.5.7\n", stderr="",
            ),
            ("antigravity", ("--help",)): CliCommandResult(
                ok=True, executable_path=str(agy_cli), executable_basename="agy.EXE",
                args=("--help",), exit_code=0,
                stdout="",
                stderr="  --effort  Reasoning effort (low|medium|high|xhigh|max)\n  mcp  Manage MCP\n  models  List models\n",
            ),
            ("antigravity", ("models",)): CliCommandResult(
                ok=True, executable_path=str(agy_cli), executable_basename="agy.EXE",
                args=("models",), exit_code=0,
                stdout=(
                    "gemini-4-hydrogen-high\tGemini 4 Hydrogen (High)\n"
                    "gemini-4-argon-high\tGemini 4 Argon (High)\n"
                    "gemini-pro-orchestrator-g1-pro\tOrchestrator (Argon)\n"
                ),
                stderr="",
            ),
            ("antigravity", ("mcp", "add", "--help")): CliCommandResult(
                ok=True, executable_path=str(agy_cli), executable_basename="agy.EXE",
                args=("mcp", "add", "--help"), exit_code=0,
                stdout="", stderr="Server type: 'stdio' or 'http'\n",
            ),
            ("claude_code", ("--version",)): CliCommandResult(
                ok=True, executable_path=str(claude_cli), executable_basename="claude.exe",
                args=("--version",), exit_code=0, stdout="2.1.0 (Claude Code)\n", stderr="",
            ),
            ("claude_code", ("--help",)): CliCommandResult(
                ok=True, executable_path=str(claude_cli), executable_basename="claude.exe",
                args=("--help",), exit_code=0, stdout="Commands:\n  mcp  Configure MCP servers\n", stderr="",
            ),
            ("claude_code", ("mcp", "--help")): CliCommandResult(
                ok=True, executable_path=str(claude_cli), executable_basename="claude.exe",
                args=("mcp", "--help"), exit_code=0, stdout="Supports stdio, http, and sse transports.\n", stderr="",
            ),
            ("codex", ("--version",)): CliCommandResult(
                ok=True, executable_path=str(codex_cli), executable_basename="codex.exe",
                args=("--version",), exit_code=0, stdout="codex-cli 0.169.0\n", stderr="",
            ),
            ("codex", ("--help",)): CliCommandResult(
                ok=True, executable_path=str(codex_cli), executable_basename="codex.exe",
                args=("--help",), exit_code=0, stdout="Commands:\n  mcp\n  debug\n  app-server\n", stderr="",
            ),
            ("codex", ("debug", "models", "--help")): CliCommandResult(
                ok=True, executable_path=str(codex_cli), executable_basename="codex.exe",
                args=("debug", "models", "--help"), exit_code=0, stdout="Options:\n  --bundled\n", stderr="",
            ),
            ("codex", ("debug", "models", "--bundled")): CliCommandResult(
                ok=True, executable_path=str(codex_cli), executable_basename="codex.exe",
                args=("debug", "models", "--bundled"), exit_code=0, stdout=bundled_codex_json, stderr="",
            ),
            ("codex", ("mcp", "add", "--help")): CliCommandResult(
                ok=True, executable_path=str(codex_cli), executable_basename="codex.exe",
                args=("mcp", "add", "--help"), exit_code=0,
                stdout="streamable HTTP\n--url\n--oauth-client-id\nstdio\n", stderr="",
            ),
            ("codex", ("mcp", "list", "--help")): CliCommandResult(
                ok=True, executable_path=str(codex_cli), executable_basename="codex.exe",
                args=("mcp", "list", "--help"), exit_code=0,
                stdout="Options:\n  --json  Output the configured servers as JSON\n", stderr="",
            ),
            ("codex", ("mcp", "list", "--json")): CliCommandResult(
                ok=True, executable_path=str(codex_cli), executable_basename="codex.exe",
                args=("mcp", "list", "--json"), exit_code=0,
                stdout=json.dumps(
                    [
                        {
                            "name": "docs",
                            "enabled": True,
                            "transport": {
                                "type": "streamable_http",
                                "url": "https://developers.openai.com/mcp",
                                "bearer_token_env_var": "OPENAI_DOCS_TOKEN",
                            },
                        }
                    ]
                ),
                stderr="",
            ),
        },
    )

    roots = {
        "home": home,
        "localapp": localapp,
        "appdata": appdata,
        "progfiles": progfiles,
        "project": project,
    }
    return roots, inspector, runner


# ---------------------------------------------------------------------------
# A. Schema and Contract Tests
# ---------------------------------------------------------------------------


def test_a_schema_contract_and_all_four_adapters(tmp_path: Path) -> None:
    roots, inspector, runner = _build_full_fixture_env(tmp_path)
    coord = RuntimeDiscoveryCoordinator(
        host_inspector=inspector,
        cli_runner=runner,
        user_home=roots["home"],
        local_appdata=roots["localapp"],
        appdata=roots["appdata"],
        program_files=roots["progfiles"],
    )
    report = coord.discover(project_path=roots["project"], run_id="test-run-a")
    schema = load_runtime_discovery_schema()

    assert report["schema_version"] == SCHEMA_VERSION
    assert report["schema_id"] == schema["$id"]
    for req_key in schema["required"]:
        assert req_key in report
    assert list(report["applications"].keys()) == [
        "antigravity",
        "claude_code",
        "claude_desktop",
        "codex",
    ]

    for app_id, profile in report["applications"].items():
        assert profile["installation_state"] == InstallationState.INSTALLED.value
        assert profile["active_session"]["observation_state"] == ObservationState.NOT_EXPOSED.value
        assert profile["active_session"]["model_id"] is None
        caps = profile["mcp"]["capabilities"]
        assert set(caps.keys()) == set(MCP_CAPABILITY_DIMENSIONS)
        assert caps["transports_observed_connected"]["status"] == CapabilityStatus.NOT_PROBED.value
        assert caps["transports_observed_connected"]["value"] == []

    # Check inventories and markdown projection
    m_inv = extract_model_catalog_inventory(report)
    e_inv = extract_reasoning_effort_inventory(report)
    mcp_inv = extract_mcp_configuration_inventory(report)
    mat = extract_protocol_capability_matrix(report)
    md = render_application_inventory_markdown(report)
    assert m_inv["models"]
    assert e_inv["effort_count"] > 0
    assert mcp_inv["applications"]["claude_desktop"]["configured"] is True
    assert set(mat["matrix"].keys()) == {"antigravity", "claude_code", "claude_desktop", "codex"}
    assert "| `antigravity` |" in md


def test_a_missing_applications_and_empty_mcp_configs(tmp_path: Path) -> None:
    coord = RuntimeDiscoveryCoordinator(
        host_inspector=FakeHostInspector(),
        cli_runner=FakeCliRunner(),
        user_home=tmp_path / "empty_home",
        local_appdata=tmp_path / "empty_local",
        appdata=tmp_path / "empty_roaming",
        program_files=tmp_path / "empty_pf",
    )
    report = coord.discover(run_id="test-missing")
    assert report["summary"]["installed_count"] == 0
    assert report["summary"]["not_installed_count"] == 4
    for app in report["applications"].values():
        assert app["installation_state"] == InstallationState.NOT_INSTALLED.value
        assert app["discovery_status"] == DiscoveryStatus.NOT_INSTALLED.value
        assert app["cli"]["present"] is False
        assert app["mcp"]["configured"] is False
        assert app["mcp"]["servers"] == []
        # Never claim NOT_SUPPORTED when merely unknown/unobserved
        for cap in app["mcp"]["capabilities"].values():
            assert cap["status"] != CapabilityStatus.NOT_SUPPORTED.value


# ---------------------------------------------------------------------------
# B. Model Catalog, Effort Extraction & Orchestrator Identity Tests
# ---------------------------------------------------------------------------


def test_b_model_catalog_provenance_and_orchestrator_parsing(tmp_path: Path) -> None:
    roots, inspector, runner = _build_full_fixture_env(tmp_path)
    coord = RuntimeDiscoveryCoordinator(
        host_inspector=inspector,
        cli_runner=runner,
        user_home=roots["home"],
        local_appdata=roots["localapp"],
        appdata=roots["appdata"],
        program_files=roots["progfiles"],
    )
    report = coord.discover(project_path=roots["project"], run_id="test-models")

    agy = report["applications"]["antigravity"]
    assert agy["cli"]["capabilities"] == ["mcp", "models"]
    assert agy["mcp"]["capabilities"]["transports_supported"]["value"] == ["http", "stdio"]
    assert agy["mcp"]["capabilities"]["transports_supported"]["status"] == CapabilityStatus.SUPPORTED.value
    help_efforts = [e["effort"] for e in agy["reasoning_efforts"] if e["source"] == "agy_help"]
    assert help_efforts == ["low", "medium", "high", "xhigh", "max"]
    agy_models = {m["model_id"]: m for m in agy["models"]}
    assert agy_models["gemini-4-hydrogen-high"]["availability_state"] == AvailabilityState.RUNTIME_OBSERVED.value
    assert agy_models["gemini-4-hydrogen-high"]["reasoning_efforts"] == ["high"]
    assert agy_models["gemini-4-hydrogen-high"]["active_session_state"] == ObservationState.NOT_EXPOSED.value

    assert len(agy["orchestrators"]) == 1
    orch = agy["orchestrators"][0]
    assert orch["orchestrator_id"] == "gemini-pro-orchestrator-g1-pro"
    assert orch["display_label"] == "Orchestrator (Argon)"
    assert orch["exposed_model_identity"] == "Argon"
    assert orch["routing_observable"] is False

    # Codex bundled catalog MUST NOT be misclassified as account availability
    codex = report["applications"]["codex"]
    bundled = [m for m in codex["models"] if m["catalog_source"] == "codex_debug_models_bundled"]
    configured = [m for m in codex["models"] if m["catalog_source"] == "codex_config_toml"]
    assert len(bundled) == 1
    assert bundled[0]["availability_state"] == AvailabilityState.BUNDLED_CATALOG.value
    assert bundled[0]["evidence_class"] == EvidenceClass.BUNDLED_CATALOG.value
    assert bundled[0]["reasoning_efforts"] == ["low", "medium", "high"]
    assert len(configured) == 1
    assert configured[0]["availability_state"] == AvailabilityState.CONFIGURED.value
    assert codex["active_session"]["model_id"] is None
    assert codex["active_session"]["observation_state"] == ObservationState.NOT_EXPOSED.value

    # Claude Code configured model is CONFIGURED, not active session
    cc = report["applications"]["claude_code"]
    assert len(cc["models"]) == 1
    assert cc["models"][0]["availability_state"] == AvailabilityState.CONFIGURED.value
    assert cc["active_session"]["model_id"] is None


# ---------------------------------------------------------------------------
# C. MCP Configuration, Transports, MSIX Redirection & Invalid Config Isolation
# ---------------------------------------------------------------------------


def test_c_mcp_transports_msix_and_invalid_config_isolation(tmp_path: Path) -> None:
    roots, inspector, runner = _build_full_fixture_env(tmp_path)
    # Break Codex TOML intentionally to ensure error isolation and invalid file handling
    (roots["home"] / ".codex" / "config.toml").write_text("invalid = [toml", encoding="utf-8")

    coord = RuntimeDiscoveryCoordinator(
        host_inspector=inspector,
        cli_runner=runner,
        user_home=roots["home"],
        local_appdata=roots["localapp"],
        appdata=roots["appdata"],
        program_files=roots["progfiles"],
    )
    report = coord.discover(project_path=roots["project"], run_id="test-mcp")

    # Antigravity transports: stdio, streamable_http, sse
    agy_servers = {s["name"]: s for s in report["applications"]["antigravity"]["mcp"]["servers"]}
    assert agy_servers["auditor-stdio"]["transport"] == TransportType.STDIO.value
    assert agy_servers["auditor-stdio"]["command_basename"] == "python.exe"
    assert agy_servers["remote-http"]["transport"] == TransportType.STREAMABLE_HTTP.value
    assert agy_servers["remote-http"]["endpoint_hostname"] == "mcp.example.com"
    assert agy_servers["legacy-sse"]["transport"] == TransportType.SSE.value
    assert agy_servers["legacy-sse"]["scope"] == "project"

    # Claude Desktop MSIX redirection & remote connectors not_exposed
    cd = report["applications"]["claude_desktop"]
    assert cd["packaging_mode"] == PackagingMode.MSIX_APPX.value
    assert cd["remote_connectors"]["observation_state"] == ObservationState.NOT_EXPOSED.value
    assert cd["mcp"]["servers"][0]["name"] == "local-fs"
    assert cd["mcp"]["servers"][0]["scope"] == "user_msix"
    assert cd["mcp"]["features"]["desktop_extension_names"] == ["sample-ext"]

    # Codex invalid TOML produced structured error without breaking other adapters or codex mcp list --json
    codex = report["applications"]["codex"]
    assert any(e["code"] == "CODEX_CONFIG_INVALID_TOML" for e in codex["errors"])
    assert any(s["name"] == "docs" for s in codex["mcp"]["servers"])


def test_c_adapter_exception_isolation(tmp_path: Path) -> None:
    class ExplodingAdapter(BaseDiscoveryAdapter):
        application_id = "claude_desktop"
        application_family = "anthropic"

        def discover(self, ctx: AdapterContext) -> dict[str, Any]:
            raise RuntimeError("boom with bearer Bearer secret-tok-12345")

    roots, inspector, runner = _build_full_fixture_env(tmp_path)
    from runtime_discovery.adapters import AntigravityAdapter, ClaudeCodeAdapter, CodexAdapter

    coord = RuntimeDiscoveryCoordinator(
        adapters=[AntigravityAdapter(), ExplodingAdapter(), ClaudeCodeAdapter(), CodexAdapter()],
        host_inspector=inspector,
        cli_runner=runner,
        user_home=roots["home"],
        local_appdata=roots["localapp"],
        appdata=roots["appdata"],
        program_files=roots["progfiles"],
    )
    report = coord.discover(run_id="test-isolation")
    assert report["applications"]["claude_desktop"]["discovery_status"] == DiscoveryStatus.ERROR.value
    assert "secret-tok-12345" not in json.dumps(report)
    assert report["applications"]["antigravity"]["installation_state"] == InstallationState.INSTALLED.value
    assert report["applications"]["codex"]["installation_state"] == InstallationState.INSTALLED.value


# ---------------------------------------------------------------------------
# D. Secret Redaction Tests
# ---------------------------------------------------------------------------


def test_d_secret_redaction_guarantees(tmp_path: Path) -> None:
    roots, inspector, runner = _build_full_fixture_env(tmp_path)
    coord = RuntimeDiscoveryCoordinator(
        host_inspector=inspector,
        cli_runner=runner,
        user_home=roots["home"],
        local_appdata=roots["localapp"],
        appdata=roots["appdata"],
        program_files=roots["progfiles"],
    )
    report = coord.discover(project_path=roots["project"], run_id="test-redact")
    serialized = json.dumps(report)

    forbidden_secrets = [
        "sk-ant-supersecret1234567890",
        "tok-supersecret-999999",
        "secret-bearer-token-value",
        "user:pass@",
        "token=secret123",
        "hunter2-secret-value",
        "hunter2",
        "sk-ant-oauth-secret-1234567890",
        "sk-ant-secret-header-value",
        "sk-ant-never-leak-this-key",
        "sk-proj-DO-NOT-READ-THIS-SECRET-9999",
        "secret@example.com",
    ]
    for secret in forbidden_secrets:
        assert secret not in serialized, f"Secret leaked into discovery output: {secret}"

    # Verify helper redaction edge cases directly
    assert extract_safe_hostname("https://alice:s3cr3t@api.example.com:8443/mcp?code=oauth123") == "api.example.com"
    assert safe_command_basename(r'"C:\Program Files\Node\node.exe" --api-key=sk-123') == "node.exe"
    scrubbed_exc = sanitize_exception(ValueError("Cookie: session=abc123def; Authorization: Bearer mytok123456"))
    assert "abc123def" not in scrubbed_exc
    assert "mytok123456" not in scrubbed_exc
    assert "ghp_" not in redact_text("ghp_123456789012345678901234")
    # Hash only canonical sanitized projection, never raw config
    assert len(canonical_sanitized_sha256({"ok": True})) == 64


# ---------------------------------------------------------------------------
# E. Security & Read-Only Boundary Tests
# ---------------------------------------------------------------------------


def test_e_security_boundaries_no_exec_no_network_no_reparse_no_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots, inspector, runner = _build_full_fixture_env(tmp_path)

    # 1. Fail if any socket connection is attempted
    def _deny_connect(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Network access prohibited in NEXT-22A")

    monkeypatch.setattr(socket.socket, "connect", _deny_connect)

    # 2. Fail if subprocess.run is called directly by discovery (FakeCliRunner is used, and validate rejects non-allowlisted)
    def _deny_subprocess(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Configured MCP commands must never be executed")

    monkeypatch.setattr(subprocess, "run", _deny_subprocess)

    # 3. Verify validate_cli_invocation rejects MCP server commands & mutating subcommands
    with pytest.raises(ValueError):
        validate_cli_invocation("antigravity", Path(r"C:\Python315\python.exe"), ("--version",))
    with pytest.raises(ValueError):
        validate_cli_invocation("claude_code", Path("claude.exe"), ("mcp", "add", "evil"))
    with pytest.raises(ValueError):
        validate_cli_invocation("codex", Path("codex.exe"), ("debug", "models"))  # non-bundled refresh blocked

    # 4. Capture config mtimes and os.environ snapshot before discovery
    cfg_files = [
        roots["home"] / ".gemini" / "config" / "mcp_config.json",
        roots["home"] / ".claude.json",
        roots["home"] / ".codex" / "config.toml",
    ]
    before_mtimes = {p: p.stat().st_mtime_ns for p in cfg_files}
    env_before = dict(os.environ)

    coord = RuntimeDiscoveryCoordinator(
        host_inspector=inspector,
        cli_runner=runner,
        user_home=roots["home"],
        local_appdata=roots["localapp"],
        appdata=roots["appdata"],
        program_files=roots["progfiles"],
    )
    report = coord.discover(project_path=roots["project"], run_id="test-sec")
    assert report["read_only_guarantees"]["no_production_db_access"] is True
    assert {p: p.stat().st_mtime_ns for p in cfg_files} == before_mtimes
    assert dict(os.environ) == env_before

    # 5. Verify reparse point / symlink traversal is blocked
    secret_outside = _create_dummy_file(tmp_path / "outside_secret.json", '{"mcpServers":{"x":{"command":"evil"}}}')
    symlink_cfg = roots["home"] / ".gemini" / "config" / "linked_mcp.json"
    try:
        os.symlink(secret_outside, symlink_cfg)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation requires Developer Mode / elevation on this host")
    assert is_reparse_point(symlink_cfg) is True
    content, err = safe_read_text(symlink_cfg, root=roots["home"])
    assert content is None and err == "REPARSE_POINT_BLOCKED"
    names, dir_err = safe_list_dir_names(symlink_cfg, root=roots["home"])
    assert names == [] and dir_err == "REPARSE_POINT_BLOCKED"


# ---------------------------------------------------------------------------
# F. CLI & Regression Tests (No DB initialization on `auditor runtime discover`)
# ---------------------------------------------------------------------------


def test_f_cli_runtime_discover_never_touches_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    missing_db = tmp_path / "never_created" / "auditor.db"
    out_file = tmp_path / "evidence" / "discovery.json"
    monkeypatch.setattr(cli, "DB_PATH", missing_db)

    # Use isolated empty coordinator via monkeypatching RuntimeDiscoveryCoordinator defaults
    monkeypatch.setattr(
        cli,
        "RuntimeDiscoveryCoordinator",
        lambda timeout_seconds=8.0: RuntimeDiscoveryCoordinator(
            host_inspector=FakeHostInspector(),
            cli_runner=FakeCliRunner(),
            user_home=tmp_path / "h",
            local_appdata=tmp_path / "l",
            appdata=tmp_path / "r",
            program_files=tmp_path / "p",
            timeout_seconds=timeout_seconds,
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["cli.py", "runtime", "discover", "--json", "--output", str(out_file), "--run-id", "cli-test-1"],
    )
    cli.main()

    assert not missing_db.exists(), "runtime discover must never create or open SQLite DB"
    assert out_file.is_file()
    parsed = json.loads(out_file.read_text(encoding="utf-8"))
    assert parsed["run_id"] == "cli-test-1"
    captured = capsys.readouterr()
    assert json.loads(captured.out)["run_id"] == "cli-test-1"


def test_g_codex_mcp_list_skipped_if_help_unconfirmed_and_generic_orchestrator(tmp_path: Path) -> None:
    from runtime_discovery.normalizers import parse_agy_models_output

    models, efforts, orchs = parse_agy_models_output(
        "custom-orch\tOrchestrator\nunknown-model\tUnknown Model\n",
        observed_at="2026-11-13T12:00:00Z",
        evidence_id="ev-1",
    )
    assert len(models) == 2
    assert models[1].reasoning_efforts == ()
    assert len(orchs) == 1
    assert orchs[0]["exposed_model_identity"] is None
    assert orchs[0]["routing_observable"] is False

    roots, inspector, runner = _build_full_fixture_env(tmp_path)
    # Override codex mcp list --help to NOT confirm safe local config listing
    codex_cli = roots["localapp"] / "Programs" / "OpenAI" / "Codex" / "bin" / "codex.exe"
    runner.responses[("codex", ("mcp", "list", "--help"))] = CliCommandResult(
        ok=True,
        executable_path=str(codex_cli),
        executable_basename="codex.exe",
        args=("mcp", "list", "--help"),
        exit_code=0,
        stdout="Lists MCP servers",
        stderr="",
    )
    coord = RuntimeDiscoveryCoordinator(
        host_inspector=inspector,
        cli_runner=runner,
        user_home=roots["home"],
        local_appdata=roots["localapp"],
        appdata=roots["appdata"],
        program_files=roots["progfiles"],
    )
    coord.discover(run_id="test-codex-help-guard")
    assert ("codex", str(codex_cli), ("mcp", "list", "--json")) not in runner.invocations

    # Also verify ledger records include guard help invocations
    rep_full = coord.discover(run_id="test-codex-ledger")
    stages = {
        (r["application_id"], r["stage"])
        for r in rep_full["evidence_manifest"]["records"]
    }
    assert ("codex", "bundled_model_catalog_help") in stages
    assert ("codex", "mcp_cli_list_help") in stages


"""Read-only discovery adapter for Anthropic Claude Desktop (Windows MSIX & conventional)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from runtime_discovery.adapters.base import AdapterContext, BaseDiscoveryAdapter
from runtime_discovery.contracts import (
    CapabilityEntry,
    CapabilityStatus,
    DiscoveryStatus,
    EvidenceClass,
    InstallationState,
    ObservationState,
    PackagingMode,
    TransportType,
    make_empty_application_profile,
)
from runtime_discovery.evidence import utc_now_iso
from runtime_discovery.mcp_parsers import build_mcp_section, parse_json_mcp_config
from runtime_discovery.windows_detection import is_reparse_point, safe_list_dir_names


class ClaudeDesktopAdapter(BaseDiscoveryAdapter):
    """Discovers Claude Desktop executable, MSIX redirection, local MCP config, and extensions."""

    application_id = "claude_desktop"
    application_family = "anthropic"

    def discover(self, ctx: AdapterContext) -> dict[str, Any]:
        profile = make_empty_application_profile(self.application_id, self.application_family)
        observed_at = utc_now_iso()
        errors: list[dict[str, str]] = []
        limitations: list[str] = [
            "Remote Claude Connectors are account-managed in the Desktop UI and are not exposed in local configuration.",
            "Claude Desktop active session model and effort are not exposed through a local read-only interface.",
            "Live MCP server connections are not probed in NEXT-22A.",
        ]

        # 1. Check MSIX/AppX packages first (read-only package metadata)
        appx_pkgs = ctx.host_inspector.find_appx_packages(("claude",))
        procs = ctx.host_inspector.list_processes(("claude",))
        running_by_path: dict[str, list[int]] = {}
        for p in procs:
            if p.executable_path:
                running_by_path.setdefault(p.executable_path.lower(), []).append(p.pid)

        executables: list[dict[str, Any]] = []
        seen_exe_lower: set[str] = set()
        packaging_mode = PackagingMode.NOT_INSTALLED
        version_val: str | None = None
        version_source = "unknown"
        version_ev = EvidenceClass.UNKNOWN
        user_data_roots: list[tuple[Path, Path, str]] = []  # (config_dir, boundary_root, scope)

        if appx_pkgs:
            pkg = appx_pkgs[0]
            packaging_mode = PackagingMode.MSIX_APPX
            if pkg.version:
                version_val = pkg.version
                version_source = "appx_package_metadata"
                version_ev = EvidenceClass.RUNTIME_OBSERVED

            ctx.ledger.add(
                application_id=self.application_id,
                stage="appx_package_detection",
                evidence_class=EvidenceClass.RUNTIME_OBSERVED,
                source_type="appx_metadata",
                source_ref=pkg.package_full_name,
                observed_at=observed_at,
                notes=f"family={pkg.package_family_name}, version={pkg.version}",
            )

            # MSIX executable candidates
            msix_exe_candidates: list[Path] = []
            if pkg.install_location:
                inst = Path(pkg.install_location)
                msix_exe_candidates.extend([inst / "app" / "claude.exe", inst / "claude.exe"])
            for p in procs:
                if p.executable_path and "windowsapps" in p.executable_path.lower() and p.name.lower() == "claude.exe":
                    msix_exe_candidates.append(Path(p.executable_path))

            for cand in msix_exe_candidates:
                try:
                    if str(cand).lower() in seen_exe_lower:
                        continue
                    if cand.is_file() and not is_reparse_point(cand):
                        seen_exe_lower.add(str(cand).lower())
                        ver = ctx.host_inspector.get_file_version(cand)
                        if ver and not version_val:
                            version_val = ver
                            version_source = "executable_metadata"
                            version_ev = EvidenceClass.PROCESS_OBSERVED
                        pids = running_by_path.get(str(cand).lower(), [])
                        ev_id = ctx.ledger.add(
                            application_id=self.application_id,
                            stage="executable_detection",
                            evidence_class=EvidenceClass.PROCESS_OBSERVED,
                            source_type="executable",
                            source_ref=str(cand),
                            observed_at=observed_at,
                        )
                        executables.append(
                            {
                                "path": str(cand),
                                "basename": cand.name,
                                "role": "desktop_app",
                                "packaging": "msix_appx",
                                "version": ver or pkg.version,
                                "running": len(pids) > 0,
                                "pids": sorted(pids),
                                "evidence_class": EvidenceClass.PROCESS_OBSERVED.value,
                                "evidence_id": ev_id,
                            }
                        )
                except OSError:
                    continue

            # Verified MSIX AppData redirection path
            msix_roaming = (
                ctx.local_appdata
                / "Packages"
                / pkg.package_family_name
                / "LocalCache"
                / "Roaming"
                / "Claude"
            )
            user_data_roots.append((msix_roaming, ctx.local_appdata, "user_msix"))

        # Conventional installation candidates (also checked carefully)
        conv_candidates = [
            ctx.local_appdata / "AnthropicClaude" / "claude.exe",
            ctx.local_appdata / "Programs" / "Claude" / "Claude.exe",
            ctx.program_files / "Claude" / "Claude.exe",
        ]
        for cand in conv_candidates:
            try:
                if str(cand).lower() in seen_exe_lower:
                    continue
                if cand.is_file() and not is_reparse_point(cand):
                    seen_exe_lower.add(str(cand).lower())
                    if packaging_mode == PackagingMode.NOT_INSTALLED:
                        packaging_mode = PackagingMode.CONVENTIONAL
                    ver = ctx.host_inspector.get_file_version(cand)
                    if ver and not version_val:
                        version_val = ver
                        version_source = "executable_metadata"
                        version_ev = EvidenceClass.PROCESS_OBSERVED
                    pids = running_by_path.get(str(cand).lower(), [])
                    ev_id = ctx.ledger.add(
                        application_id=self.application_id,
                        stage="executable_detection",
                        evidence_class=EvidenceClass.PROCESS_OBSERVED,
                        source_type="executable",
                        source_ref=str(cand),
                        observed_at=observed_at,
                    )
                    executables.append(
                        {
                            "path": str(cand),
                            "basename": cand.name,
                            "role": "desktop_app",
                            "packaging": "conventional",
                            "version": ver,
                            "running": len(pids) > 0,
                            "pids": sorted(pids),
                            "evidence_class": EvidenceClass.PROCESS_OBSERVED.value,
                            "evidence_id": ev_id,
                        }
                    )
            except OSError:
                continue

        if packaging_mode == PackagingMode.CONVENTIONAL or not appx_pkgs:
            user_data_roots.append((ctx.appdata / "Claude", ctx.appdata, "user"))
        elif appx_pkgs:
            # Check conventional path ONLY as secondary observation, never assuming it is active
            conv_dir = ctx.appdata / "Claude"
            if conv_dir.exists() and not is_reparse_point(conv_dir):
                user_data_roots.append((conv_dir, ctx.appdata, "user_conventional_secondary"))

        installed = bool(appx_pkgs or executables)
        if not installed:
            profile["installation_state"] = InstallationState.NOT_INSTALLED.value
            profile["packaging_mode"] = PackagingMode.NOT_INSTALLED.value
            profile["discovery_status"] = DiscoveryStatus.NOT_INSTALLED.value
            profile["limitations"] = limitations
            return profile

        # 2. Inspect local MCP config & Desktop Extensions metadata safely
        servers = []
        config_sources: list[dict[str, Any]] = []
        desktop_extensions: list[str] = []

        for data_dir, root_bound, scope in user_data_roots:
            cfg_path = data_dir / "claude_desktop_config.json"
            parsed = parse_json_mcp_config(
                cfg_path,
                root=root_bound,
                scope=scope,
                default_url_transport=TransportType.HTTP,
            )
            config_sources.append(parsed["source"])
            if parsed["error"]:
                errors.append(
                    {
                        "code": f"CLAUDE_DESKTOP_MCP_{parsed['error']}",
                        "stage": "mcp_config",
                        "message": f"Failed to parse {cfg_path.name} ({parsed['error']})",
                    }
                )
            elif parsed["source"]["exists"]:
                ev_id = ctx.ledger.add(
                    application_id=self.application_id,
                    stage="mcp_config",
                    evidence_class=EvidenceClass.CONFIGURED,
                    source_type="config_file",
                    source_ref=str(cfg_path),
                    observed_at=observed_at,
                    sanitized_projection=[s.to_dict() for s in parsed["servers"]],
                )
                for srv in parsed["servers"]:
                    servers.append(type(srv)(**{**srv.__dict__, "evidence_id": ev_id}))

            # Bounded non-recursive check for Desktop Extensions folder names only
            ext_dir = data_dir / "Claude Extensions"
            ext_names, ext_err = safe_list_dir_names(ext_dir, root=root_bound)
            if ext_err is None and ext_names:
                desktop_extensions.extend(ext_names)

        profile["installation_state"] = InstallationState.INSTALLED.value
        profile["packaging_mode"] = packaging_mode.value
        profile["version"] = {
            "value": version_val,
            "source": version_source,
            "confidence": "high" if version_val else "unknown",
            "evidence_class": version_ev.value,
        }
        profile["executables"] = executables
        profile["cli"] = {
            "present": False,
            "version": None,
            "path": None,
            "capabilities": [],
            "evidence_class": EvidenceClass.NOT_EXPOSED.value,
            "help_observed": False,
        }
        profile["mcp"] = build_mcp_section(
            servers=servers,
            config_sources=config_sources,
            supported_transports=[TransportType.STDIO.value],
            supported_transports_evidence=EvidenceClass.DOCUMENTED_CAPABILITY,
            extra_notes={
                "client_capability_declarations": CapabilityEntry(
                    value=None,
                    status=CapabilityStatus.NOT_EXPOSED,
                    evidence_class=EvidenceClass.NOT_EXPOSED,
                    notes="Not exposed without live MCP handshake.",
                )
            },
        )
        profile["mcp"]["features"]["desktop_extensions_count"] = len(sorted(set(desktop_extensions)))
        profile["mcp"]["features"]["desktop_extension_names"] = sorted(set(desktop_extensions))
        profile["remote_connectors"] = {
            "observation_state": ObservationState.NOT_EXPOSED.value,
            "evidence_class": EvidenceClass.NOT_EXPOSED.value,
            "connectors": [],
        }
        profile["discovery_status"] = DiscoveryStatus.PARTIAL.value
        profile["errors"] = errors
        profile["limitations"] = limitations
        return profile

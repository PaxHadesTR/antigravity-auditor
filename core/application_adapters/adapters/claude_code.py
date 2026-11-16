"""Anthropic Claude Code contract adapter (strictly NOT_INSTALLED unless fresh discovery proves otherwise)."""

from __future__ import annotations

import json
from typing import Any

from application_adapters.configuration_preview import validate_preview_item
from application_adapters.contracts import (
    AdapterConfigPreview,
    AdapterInstallState,
    ApplicationAdapterProfile,
)


def _parse_install_state(raw: dict[str, Any] | None) -> tuple[AdapterInstallState, str | None, str]:
    if not isinstance(raw, dict):
        return AdapterInstallState.NOT_INSTALLED, None, "static_not_installed_default"
    st = str(raw.get("installation_state") or "").lower()
    if st == "installed":
        cli = raw.get("cli") if isinstance(raw.get("cli"), dict) else {}
        ver = str(cli["version"]) if cli.get("version") else None
        return AdapterInstallState.INSTALLED, ver, "runtime_discovery_refresh"
    return AdapterInstallState.NOT_INSTALLED, None, "runtime_discovery_refresh"


class ClaudeCodeApplicationAdapter:
    """Provider-neutral future contract ONLY; never installs, downloads, or invokes Claude Code."""

    application_id = "claude_code"
    application_family = "anthropic"

    def build_profile(self, *, discovery_report: dict[str, Any] | None = None) -> ApplicationAdapterProfile:
        apps = (discovery_report or {}).get("applications") if isinstance(discovery_report, dict) else None
        raw = apps.get(self.application_id) if isinstance(apps, dict) else None
        install_state, version, src = _parse_install_state(raw)
        observed_at = (discovery_report or {}).get("generated_at") if isinstance(discovery_report, dict) else None
        return ApplicationAdapterProfile(
            application_id=self.application_id,
            application_family=self.application_family,
            display_name="Anthropic Claude Code CLI",
            install_state=install_state,
            installed_version=version,
            packaging="not_installed" if install_state == AdapterInstallState.NOT_INSTALLED else "cli",
            config_scopes={},
            preferred_legacy_protocol_version="UNKNOWN",
            modern_runtime_wire_verified=False,
            modern_runtime_support_status="ADAPTER_CONTRACT_ONLY_NOT_VERIFIED",
            default_compatibility_hints={},
            process_match_hints=(),
            discovery_evidence_source=src,
            observed_at=str(observed_at) if observed_at else None,
            live_tested=False,
            live_authenticated=False,
            limitations=(
                "NOT_INSTALLED: Claude Code executable was not found in refreshed NEXT-22D discovery.",
                "Sanitized user MCP metadata alone never proves Claude Code CLI installation.",
                "Do not download, install, invoke, or emit runtime compatibility claims for Claude Code.",
            ),
        )

    def build_status_report(self, *, discovery_report: dict[str, Any] | None = None) -> AdapterConfigPreview:
        """Return a status-only JSON contract report (NOT an installable configuration)."""
        profile = self.build_profile(discovery_report=discovery_report)
        payload = {
            "application_id": self.application_id,
            "install_state": profile.install_state.value,
            "installed": profile.install_state == AdapterInstallState.INSTALLED,
            "runtime_compatibility_verified": False,
            "credentials_or_profiles_generated": False,
            "future_integration_prerequisites": [
                "Verify authentic Claude Code CLI installation via read-only discovery.",
                "Provision OS-SID + challenge-bound adapter identity proof via qualified Broker boundary (B4-A1/B4-B).",
                "Perform controlled protocol compatibility qualification before enabling MCP registration.",
            ],
        }
        return validate_preview_item(
            AdapterConfigPreview(
                application_id=self.application_id,
                scope_name="not_installed_status_only",
                target_path="NONE_NOT_INSTALLED",
                content_format="json",
                content_text=json.dumps(payload, indent=2) + "\n",
                validation_ok=False,
                manual_install_steps=(
                    "1. Claude Code is NOT_INSTALLED; do not install automatically.",
                ),
                rollback_steps=("1. No configuration or package created.",),
                warnings=(
                    "NOT_INSTALLED: Future contract only; no runnable config preview generated.",
                ),
            )
        )

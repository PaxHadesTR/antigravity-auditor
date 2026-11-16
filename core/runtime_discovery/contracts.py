"""Versioned schema contracts and canonical enums for NEXT-22A Runtime Discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.0.0"
SCHEMA_ID = "https://antigravity-auditor.local/schemas/runtime-discovery/1.0.0"


class EvidenceClass(str, Enum):
    """Provenance classification for every discovered runtime claim."""

    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
    PROCESS_OBSERVED = "PROCESS_OBSERVED"
    CONFIGURED = "CONFIGURED"
    ACCOUNT_ENUMERATED = "ACCOUNT_ENUMERATED"
    BUNDLED_CATALOG = "BUNDLED_CATALOG"
    DOCUMENTED_CAPABILITY = "DOCUMENTED_CAPABILITY"
    USER_REPORTED = "USER_REPORTED"
    UNKNOWN = "UNKNOWN"
    NOT_INSTALLED = "NOT_INSTALLED"
    NOT_EXPOSED = "NOT_EXPOSED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    ERROR = "ERROR"


class InstallationState(str, Enum):
    """Application installation state."""

    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    PARTIAL = "partial"
    UNKNOWN = "unknown"
    ERROR = "error"


class PackagingMode(str, Enum):
    """Windows installation / packaging mode."""

    CONVENTIONAL = "conventional"
    MSIX_APPX = "msix_appx"
    CLI_ONLY = "cli_only"
    BUNDLED_DAEMON = "bundled_daemon"
    IDE_EXTENSION = "ide_extension"
    UNKNOWN = "unknown"
    NOT_INSTALLED = "not_installed"


class DiscoveryStatus(str, Enum):
    """Overall discovery completion status for an adapter."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    NOT_INSTALLED = "not_installed"
    ERROR = "error"


class TransportType(str, Enum):
    """Normalized MCP transport classifications."""

    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable_http"
    SSE = "sse"
    HTTP = "http"
    UNKNOWN = "unknown"


class ObservationState(str, Enum):
    """Observation status for session or runtime-only metadata."""

    OBSERVED = "observed"
    NOT_EXPOSED = "not_exposed"
    UNKNOWN = "unknown"
    NOT_PROBED = "not_probed"
    UNAVAILABLE = "unavailable"


class AvailabilityState(str, Enum):
    """Model availability classification separating catalogs from account access."""

    RUNTIME_OBSERVED = "runtime_observed"
    ACCOUNT_ENUMERATED = "account_enumerated"
    BUNDLED_CATALOG = "bundled_catalog"
    CONFIGURED = "configured"
    USER_REPORTED = "user_reported"
    DOCUMENTED_ONLY = "documented_only"
    UNKNOWN = "unknown"


class CapabilityStatus(str, Enum):
    """Distinguishes support, configuration, live connection, and probing."""

    SUPPORTED = "SUPPORTED"
    CONFIGURED = "CONFIGURED"
    CONNECTED = "CONNECTED"
    PROBED = "PROBED"
    UNKNOWN = "UNKNOWN"
    NOT_PROBED = "NOT_PROBED"
    NOT_EXPOSED = "NOT_EXPOSED"
    NOT_SUPPORTED = "NOT_SUPPORTED"


MCP_CAPABILITY_DIMENSIONS: tuple[str, ...] = (
    "protocol_versions_observed",
    "protocol_versions_supported_documented",
    "transports_supported",
    "transports_configured",
    "transports_observed_connected",
    "client_capability_declarations",
    "tool_discovery_behavior",
    "dynamic_tool_list_update_support",
    "tool_search_deferred_tool_support",
    "progress_notification_support",
    "server_task_support",
    "elicitation_support",
    "roots_support",
    "oauth_remote_auth_support",
    "tool_output_limits",
    "timeout_behavior",
    "reconnection_behavior",
)


@dataclass(frozen=True)
class CapabilityEntry:
    """Single capability dimension record with provenance and status."""

    value: Any
    status: CapabilityStatus
    evidence_class: EvidenceClass
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "status": self.status.value,
            "evidence_class": self.evidence_class.value,
            "notes": self.notes,
        }


def default_mcp_capabilities() -> dict[str, dict[str, Any]]:
    """Build baseline 17-dimension MCP capability map with safe UNKNOWN/NOT_PROBED defaults."""
    caps: dict[str, dict[str, Any]] = {}
    for dim in MCP_CAPABILITY_DIMENSIONS:
        if dim == "transports_observed_connected":
            entry = CapabilityEntry(
                value=[],
                status=CapabilityStatus.NOT_PROBED,
                evidence_class=EvidenceClass.NOT_EXPOSED,
                notes="Live MCP server connection probing is prohibited in NEXT-22A.",
            )
        elif dim in ("protocol_versions_observed", "transports_configured"):
            entry = CapabilityEntry(
                value=[],
                status=CapabilityStatus.UNKNOWN,
                evidence_class=EvidenceClass.UNKNOWN,
            )
        else:
            entry = CapabilityEntry(
                value=None,
                status=CapabilityStatus.UNKNOWN,
                evidence_class=EvidenceClass.UNKNOWN,
            )
        caps[dim] = entry.to_dict()
    return caps


@dataclass(frozen=True)
class NormalizedModelRecord:
    """Provider-neutral model inventory entry (Part 8)."""

    provider: str
    application_id: str
    model_id: str
    display_name: str
    availability_state: AvailabilityState
    evidence_class: EvidenceClass
    catalog_source: str
    reasoning_efforts: tuple[str, ...] = ()
    default_effort: str | None = None
    capabilities: dict[str, Any] = field(default_factory=dict)
    active_session_state: ObservationState = ObservationState.NOT_EXPOSED
    observed_at: str = ""
    evidence_id: str = ""
    scope: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "application_id": self.application_id,
            "model_id": self.model_id,
            "display_name": self.display_name,
            "availability_state": self.availability_state.value,
            "evidence_class": self.evidence_class.value,
            "catalog_source": self.catalog_source,
            "reasoning_efforts": list(self.reasoning_efforts),
            "default_effort": self.default_effort,
            "capabilities": dict(sorted(self.capabilities.items())),
            "active_session_state": self.active_session_state.value,
            "observed_at": self.observed_at,
            "evidence_id": self.evidence_id,
            "scope": self.scope,
        }


@dataclass(frozen=True)
class NormalizedEffortRecord:
    """Normalized reasoning effort entry with scope and provenance."""

    application_id: str
    effort: str
    model_id: str | None
    scope: str
    source: str
    evidence_class: EvidenceClass
    is_default: bool = False
    supported_efforts: tuple[str, ...] = ()
    evidence_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "application_id": self.application_id,
            "effort": self.effort,
            "model_id": self.model_id,
            "scope": self.scope,
            "source": self.source,
            "evidence_class": self.evidence_class.value,
            "is_default": self.is_default,
            "supported_efforts": list(self.supported_efforts),
            "evidence_id": self.evidence_id,
        }


@dataclass(frozen=True)
class SanitizedMcpServerRecord:
    """Secret-free projection of a configured MCP server."""

    name: str
    transport: TransportType
    has_command: bool
    command_basename: str | None
    has_url: bool
    endpoint_hostname: str | None
    env_var_names: tuple[str, ...]
    header_names: tuple[str, ...]
    auth_configured: bool
    scope: str
    enabled: bool | None
    source_path: str
    connection_status: CapabilityStatus = CapabilityStatus.CONFIGURED
    evidence_class: EvidenceClass = EvidenceClass.CONFIGURED
    evidence_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "transport": self.transport.value,
            "has_command": self.has_command,
            "command_basename": self.command_basename,
            "has_url": self.has_url,
            "endpoint_hostname": self.endpoint_hostname,
            "env_var_names": sorted(set(self.env_var_names)),
            "header_names": sorted(set(self.header_names)),
            "auth_configured": self.auth_configured,
            "scope": self.scope,
            "enabled": self.enabled,
            "source_path": self.source_path,
            "connection_status": self.connection_status.value,
            "evidence_class": self.evidence_class.value,
            "evidence_id": self.evidence_id,
        }


def make_empty_application_profile(
    application_id: str,
    application_family: str,
) -> dict[str, Any]:
    """Create a schema-compliant baseline profile for an application."""
    return {
        "schema_version": SCHEMA_VERSION,
        "application_id": application_id,
        "application_family": application_family,
        "installation_state": InstallationState.NOT_INSTALLED.value,
        "packaging_mode": PackagingMode.NOT_INSTALLED.value,
        "version": {
            "value": None,
            "source": "unknown",
            "confidence": "unknown",
            "evidence_class": EvidenceClass.UNKNOWN.value,
        },
        "executables": [],
        "cli": {
            "present": False,
            "version": None,
            "path": None,
            "capabilities": [],
            "evidence_class": EvidenceClass.NOT_INSTALLED.value,
            "help_observed": False,
        },
        "models": [],
        "reasoning_efforts": [],
        "orchestrators": [],
        "mcp": {
            "configured": False,
            "transports": [],
            "protocol_versions": [],
            "features": {},
            "capabilities": default_mcp_capabilities(),
            "servers": [],
            "config_sources": [],
        },
        "active_session": {
            "model_id": None,
            "effort": None,
            "observation_state": ObservationState.NOT_EXPOSED.value,
            "evidence_class": EvidenceClass.NOT_EXPOSED.value,
        },
        "remote_connectors": {
            "observation_state": ObservationState.NOT_EXPOSED.value,
            "evidence_class": EvidenceClass.NOT_EXPOSED.value,
            "connectors": [],
        },
        "discovery_status": DiscoveryStatus.NOT_INSTALLED.value,
        "errors": [],
        "limitations": [],
    }

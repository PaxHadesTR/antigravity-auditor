"""NEXT-22A Read-Only Multi-Application Runtime Discovery Foundation."""

from runtime_discovery.contracts import (
    AvailabilityState,
    CapabilityEntry,
    CapabilityStatus,
    DiscoveryStatus,
    EvidenceClass,
    InstallationState,
    MCP_CAPABILITY_DIMENSIONS,
    ObservationState,
    PackagingMode,
    SCHEMA_ID,
    SCHEMA_VERSION,
    TransportType,
)
from runtime_discovery.coordinator import (
    RuntimeDiscoveryCoordinator,
    extract_mcp_configuration_inventory,
    extract_model_catalog_inventory,
    extract_protocol_capability_matrix,
    extract_reasoning_effort_inventory,
    load_runtime_discovery_schema,
    render_application_inventory_markdown,
)

__all__ = [
    "AvailabilityState",
    "CapabilityEntry",
    "CapabilityStatus",
    "DiscoveryStatus",
    "EvidenceClass",
    "InstallationState",
    "MCP_CAPABILITY_DIMENSIONS",
    "ObservationState",
    "PackagingMode",
    "RuntimeDiscoveryCoordinator",
    "SCHEMA_ID",
    "SCHEMA_VERSION",
    "TransportType",
    "extract_mcp_configuration_inventory",
    "extract_model_catalog_inventory",
    "extract_protocol_capability_matrix",
    "extract_reasoning_effort_inventory",
    "load_runtime_discovery_schema",
    "render_application_inventory_markdown",
]

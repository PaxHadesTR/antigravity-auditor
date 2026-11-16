"""NEXT-22C Adaptive MCP Gateway & Client-Aware Tool Catalog."""

from mcp_gateway.authenticated_context import (
    AdapterIdentityProof,
    AdapterProofVerifier,
    AuthenticatedCallerContext,
    CallerIdentityResolver,
    ProtocolContext,
    SharedSecretAdapterProofVerifier,
)
from mcp_gateway.authorization_resolver import (
    AuthorizationDecision,
    AuthorizationResolver,
)
from mcp_gateway.catalog_cache import CatalogCache, build_scoped_cache_key
from mcp_gateway.catalog_registry import CanonicalCatalogRegistry
from mcp_gateway.client_profile_resolver import (
    ClientProfileResolver,
    classify_protocol_era,
)
from mcp_gateway.compatibility import (
    FeatureCompatibility,
    evaluate_feature_compatibility,
    tool_meets_minimum_features,
)
from mcp_gateway.contracts import (
    CATALOG_VERSION,
    GATEWAY_VERSION,
    LEGACY_SUPPORTED_PROTOCOL_VERSIONS,
    MODERN_CONTRACT_PROTOCOL_VERSIONS,
    UNIVERSAL_MINIMUM_READ_SCOPES,
    AuthMethod,
    CanonicalToolManifest,
    ClientCompatibilityProfile,
    CompatibilityState,
    GatewayErrorCode,
    GatewayResultEnvelope,
    PermissionClass,
    ProtocolEra,
    ResultSizePolicy,
    RiskClass,
    ToolGroup,
    parse_strict_protocol_date,
)
from mcp_gateway.gateway import AdaptiveMCPGateway
from mcp_gateway.notifications import NotificationManager, SubscriptionRecord
from mcp_gateway.output_adapter import OutputAdapter
from mcp_gateway.protocol_adapter import (
    LegacyProtocolAdapter,
    ModernProtocolAdapter,
    ProtocolNegotiationOutcome,
    paginate_items,
    render_tool_entry,
)
from mcp_gateway.routing_tools import RoutingToolBridge
from mcp_gateway.sdk_v2_compat import (
    REMOTE_MCP_DISABLED,
    SDK_V2_AVAILABLE,
    SDK_V2_VERSION,
    GatewaySDKv2Bridge,
    SDKv2UnavailableError,
    get_sdk_v2_status,
)
from mcp_gateway.tool_manifest import (
    GATEWAY_READONLY_TOOL_DEFINITIONS,
    build_default_canonical_manifests,
)
from mcp_gateway.untrusted_hints import UntrustedClientHints

__all__ = [
    "AdaptiveMCPGateway",
    "AdapterIdentityProof",
    "AdapterProofVerifier",
    "AuthMethod",
    "AuthenticatedCallerContext",
    "AuthorizationDecision",
    "AuthorizationResolver",
    "CATALOG_VERSION",
    "CallerIdentityResolver",
    "CanonicalCatalogRegistry",
    "CanonicalToolManifest",
    "CatalogCache",
    "ClientCompatibilityProfile",
    "ClientProfileResolver",
    "CompatibilityState",
    "FeatureCompatibility",
    "GATEWAY_READONLY_TOOL_DEFINITIONS",
    "GATEWAY_VERSION",
    "GatewayErrorCode",
    "GatewayResultEnvelope",
    "GatewaySDKv2Bridge",
    "LEGACY_SUPPORTED_PROTOCOL_VERSIONS",
    "LegacyProtocolAdapter",
    "MODERN_CONTRACT_PROTOCOL_VERSIONS",
    "ModernProtocolAdapter",
    "NotificationManager",
    "OutputAdapter",
    "PermissionClass",
    "ProtocolContext",
    "ProtocolEra",
    "ProtocolNegotiationOutcome",
    "REMOTE_MCP_DISABLED",
    "ResultSizePolicy",
    "RiskClass",
    "RoutingToolBridge",
    "SDK_V2_AVAILABLE",
    "SDK_V2_VERSION",
    "SDKv2UnavailableError",
    "SharedSecretAdapterProofVerifier",
    "SubscriptionRecord",
    "ToolGroup",
    "UNIVERSAL_MINIMUM_READ_SCOPES",
    "UntrustedClientHints",
    "build_default_canonical_manifests",
    "build_scoped_cache_key",
    "classify_protocol_era",
    "evaluate_feature_compatibility",
    "get_sdk_v2_status",
    "paginate_items",
    "render_tool_entry",
    "tool_meets_minimum_features",
]

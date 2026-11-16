"""Canonical provider-neutral contracts and types for NEXT-22C Adaptive MCP Gateway."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any

from entitlement_router.privacy import sanitize_for_output, validate_opaque_id

GATEWAY_VERSION = "2026.11.14-next22c.1"
CATALOG_VERSION = "2026.11.14-next22c.1"

LEGACY_SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
)
MODERN_CONTRACT_PROTOCOL_VERSIONS: tuple[str, ...] = ("2026-07-28",)
MODERN_MIN_PROTOCOL_DATE: date = date(2026, 7, 28)
LEGACY_STRUCTURED_OUTPUT_MIN_DATE: date = date(2025, 6, 18)
_STRICT_PROTOCOL_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_strict_protocol_date(protocol_version: Any) -> date | None:
    """Parse an exact YYYY-MM-DD MCP protocol revision date; return None if malformed/invalid."""
    if not isinstance(protocol_version, str):
        return None
    candidate = protocol_version.strip()
    if not _STRICT_PROTOCOL_DATE_RE.fullmatch(candidate):
        return None
    year_s, month_s, day_s = candidate.split("-")
    try:
        return date(int(year_s), int(month_s), int(day_s))
    except ValueError:
        return None

UNIVERSAL_MINIMUM_READ_SCOPES: frozenset[str] = frozenset({"core:read"})


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_sha256(obj: Any) -> str:
    """Compute a deterministic SHA-256 hex digest over JSON-canonical data."""
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ProtocolEra(str, Enum):
    LEGACY = "LEGACY"
    MODERN = "MODERN"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class CompatibilityState(str, Enum):
    VERIFIED = "VERIFIED"
    DOCUMENTED = "DOCUMENTED"
    CONFIGURED = "CONFIGURED"
    USER_REPORTED = "USER_REPORTED"
    UNKNOWN = "UNKNOWN"
    NOT_EXPOSED = "NOT_EXPOSED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    ERROR = "ERROR"


class ToolGroup(str, Enum):
    CORE_READ = "CORE_READ"
    PROJECT_READ = "PROJECT_READ"
    EVIDENCE_READ = "EVIDENCE_READ"
    ROUTING_READ = "ROUTING_READ"
    PLANNING = "PLANNING"
    GOVERNANCE = "GOVERNANCE"
    EXECUTION = "EXECUTION"


TOOL_GROUP_ORDER: dict[ToolGroup, int] = {
    ToolGroup.CORE_READ: 10,
    ToolGroup.PROJECT_READ: 20,
    ToolGroup.EVIDENCE_READ: 30,
    ToolGroup.ROUTING_READ: 40,
    ToolGroup.PLANNING: 50,
    ToolGroup.GOVERNANCE: 60,
    ToolGroup.EXECUTION: 70,
}


class PermissionClass(str, Enum):
    PUBLIC_SAFE_READ = "PUBLIC_SAFE_READ"
    SCOPED_READ = "SCOPED_READ"
    ROUTING_READ = "ROUTING_READ"
    PLANNING_READONLY = "PLANNING_READONLY"
    GOVERNANCE_DECISION = "GOVERNANCE_DECISION"
    GOVERNANCE_APPROVAL = "GOVERNANCE_APPROVAL"
    EXECUTION_CONTROL = "EXECUTION_CONTROL"


class RiskClass(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuthMethod(str, Enum):
    LOCAL_WIN32_NAMED_PIPE = "LOCAL_WIN32_NAMED_PIPE"
    LOCAL_OS_PROCESS = "LOCAL_OS_PROCESS"
    LOCAL_TEST_PRINCIPAL = "LOCAL_TEST_PRINCIPAL"
    REMOTE_OAUTH_BEARER = "REMOTE_OAUTH_BEARER"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    UNKNOWN = "UNKNOWN"


class GatewayErrorCode(str, Enum):
    UNAUTHORIZED_CALLER = "UNAUTHORIZED_CALLER"
    LOW_INTEGRITY_REJECTED = "LOW_INTEGRITY_REJECTED"
    SID_MISMATCH = "SID_MISMATCH"
    MISSING_SCOPE = "MISSING_SCOPE"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"
    CROSS_PRINCIPAL_DENIED = "CROSS_PRINCIPAL_DENIED"
    CROSS_ACCOUNT_DENIED = "CROSS_ACCOUNT_DENIED"
    UNKNOWN_IDENTITY_READONLY_ONLY = "UNKNOWN_IDENTITY_READONLY_ONLY"
    GOVERNANCE_APPROVAL_REQUIRED = "GOVERNANCE_APPROVAL_REQUIRED"
    EXECUTION_LEASE_REQUIRED = "EXECUTION_LEASE_REQUIRED"
    EXECUTION_DISABLED_FOR_CALLER = "EXECUTION_DISABLED_FOR_CALLER"
    UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"
    PROTOCOL_ERA_MISMATCH = "PROTOCOL_ERA_MISMATCH"
    REMOTE_HTTP_DISABLED = "REMOTE_HTTP_DISABLED"
    SECRET_OR_PII_REJECTED = "SECRET_OR_PII_REJECTED"
    INTERNAL_HANDLER_ERROR = "INTERNAL_HANDLER_ERROR"


@dataclass(frozen=True)
class ResultSizePolicy:
    max_items: int = 50
    max_text_chars: int = 4096
    supports_pagination: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_items": self.max_items,
            "max_text_chars": self.max_text_chars,
            "supports_pagination": self.supports_pagination,
        }


@dataclass(frozen=True)
class CanonicalToolManifest:
    """Single canonical definition for a provider-neutral Gateway tool."""

    tool_id: str
    tool_name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    tool_group: ToolGroup
    permission_class: PermissionClass
    required_authorization_scopes: tuple[str, ...]
    minimum_client_features: tuple[str, ...]
    result_size_policy: ResultSizePolicy
    risk_class: RiskClass
    implementation_handler: str
    availability_state: CompatibilityState = CompatibilityState.VERIFIED
    catalog_version: str = CATALOG_VERSION
    schema_version: str = "1.0.0"
    requires_governance_approval: bool = False
    requires_lease: bool = False
    execution_mutating: bool = False
    compatibility_aliases: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_opaque_id(self.tool_id, field_name="tool_id")
        validate_opaque_id(self.tool_name, field_name="tool_name")

    @property
    def schema_sha256(self) -> str:
        return canonical_sha256(
            {
                "tool_name": self.tool_name,
                "schema_version": self.schema_version,
                "input_schema": self.input_schema,
                "output_schema": self.output_schema,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "tool_name": self.tool_name,
            "title": self.title,
            "description": self.description,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "tool_group": self.tool_group.value,
            "permission_class": self.permission_class.value,
            "required_authorization_scopes": list(self.required_authorization_scopes),
            "minimum_client_features": list(self.minimum_client_features),
            "result_size_policy": self.result_size_policy.to_dict(),
            "risk_class": self.risk_class.value,
            "implementation_handler": self.implementation_handler,
            "availability_state": self.availability_state.value,
            "catalog_version": self.catalog_version,
            "schema_version": self.schema_version,
            "schema_sha256": self.schema_sha256,
            "requires_governance_approval": self.requires_governance_approval,
            "requires_lease": self.requires_lease,
            "execution_mutating": self.execution_mutating,
            "compatibility_aliases": list(self.compatibility_aliases),
        }


@dataclass(frozen=True)
class ClientCompatibilityProfile:
    """Client technical compatibility profile (strictly distinct from entitlement and authorization)."""

    application_id: str = "UNKNOWN"
    application_version: str | None = None
    adapter_version: str | None = None
    transport: str = "unknown"
    protocol_era: ProtocolEra = ProtocolEra.LEGACY
    protocol_version: str = "2024-11-05"
    client_capabilities: dict[str, Any] = field(default_factory=dict)
    structured_output_state: CompatibilityState = CompatibilityState.UNKNOWN
    tool_list_refresh_state: CompatibilityState = CompatibilityState.UNKNOWN
    notification_state: CompatibilityState = CompatibilityState.UNKNOWN
    subscription_state: CompatibilityState = CompatibilityState.UNKNOWN
    pagination_state: CompatibilityState = CompatibilityState.UNKNOWN
    progress_state: CompatibilityState = CompatibilityState.UNKNOWN
    task_support_state: CompatibilityState = CompatibilityState.UNKNOWN
    elicitation_state: CompatibilityState = CompatibilityState.UNKNOWN
    output_constraints: dict[str, Any] = field(
        default_factory=lambda: {"max_items": 50, "max_text_chars": 4096, "prefer_concise_text": False}
    )
    evidence_source: str = "default_conservative"
    observation_timestamp: str = field(default_factory=utc_now_iso)
    live_verified: bool = False

    @property
    def compatibility_fingerprint(self) -> str:
        return canonical_sha256(
            {
                "application_id": self.application_id,
                "transport": self.transport,
                "protocol_era": self.protocol_era.value,
                "protocol_version": self.protocol_version,
                "structured_output_state": self.structured_output_state.value,
                "tool_list_refresh_state": self.tool_list_refresh_state.value,
                "notification_state": self.notification_state.value,
                "subscription_state": self.subscription_state.value,
                "pagination_state": self.pagination_state.value,
                "output_constraints": self.output_constraints,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "application_id": self.application_id,
                "application_version": self.application_version,
                "adapter_version": self.adapter_version,
                "transport": self.transport,
                "protocol_era": self.protocol_era.value,
                "protocol_version": self.protocol_version,
                "client_capabilities": self.client_capabilities,
                "structured_output_state": self.structured_output_state.value,
                "tool_list_refresh_state": self.tool_list_refresh_state.value,
                "notification_state": self.notification_state.value,
                "subscription_state": self.subscription_state.value,
                "pagination_state": self.pagination_state.value,
                "progress_state": self.progress_state.value,
                "task_support_state": self.task_support_state.value,
                "elicitation_state": self.elicitation_state.value,
                "output_constraints": self.output_constraints,
                "evidence_source": self.evidence_source,
                "observation_timestamp": self.observation_timestamp,
                "live_verified": self.live_verified,
                "compatibility_fingerprint": self.compatibility_fingerprint,
            }
        )


@dataclass(frozen=True)
class GatewayResultEnvelope:
    """Canonical internal tool result before compatibility rendering."""

    tool_name: str
    ok: bool
    summary: str
    data: dict[str, Any]
    truncated: bool = False
    total_count: int | None = None
    next_cursor: str | None = None
    evidence_refs: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    schema_version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "tool_name": self.tool_name,
                "ok": self.ok,
                "summary": self.summary,
                "data": self.data,
                "truncated": self.truncated,
                "total_count": self.total_count,
                "next_cursor": self.next_cursor,
                "evidence_refs": list(self.evidence_refs),
                "warnings": list(self.warnings),
                "schema_version": self.schema_version,
            }
        )

"""Versioned contracts, enums, and dataclasses for NEXT-22B User-Aware Entitlement Registry & Capability Router."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from entitlement_router.privacy import sanitize_for_output, validate_opaque_id

SCHEMA_VERSION = "1.0.0"



def strict_bool(data: Mapping[str, Any], key: str, default: bool) -> bool:
    """Boolean field from untrusted JSON: only true/false are accepted (bool("false") would be True)."""
    value = data.get(key, default)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"'{key}' must be a boolean (true/false), got {type(value).__name__}.")
    return value

def utc_now_iso() -> str:
    """Return deterministic ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso_datetime(value: str | None) -> datetime | None:
    """Parse ISO-8601 timestamp string into timezone-aware UTC datetime."""
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_expired(expires_at: str | None, *, as_of: datetime | None = None) -> bool:
    """Return True when an optional expiration timestamp is at or before as_of."""
    exp_dt = parse_iso_datetime(expires_at)
    if exp_dt is None:
        return False
    ref = as_of or datetime.now(timezone.utc)
    return exp_dt <= ref


class AuthenticationMode(str, Enum):
    """Authentication and billing modes (never interchangeable)."""

    SUBSCRIPTION = "SUBSCRIPTION"
    OAUTH_SUBSCRIPTION = "OAUTH_SUBSCRIPTION"
    API_KEY = "API_KEY"
    ENTERPRISE = "ENTERPRISE"
    ORGANIZATION_MANAGED = "ORGANIZATION_MANAGED"
    LOCAL_ONLY = "LOCAL_ONLY"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, value: str | None) -> AuthenticationMode:
        if not value:
            return cls.UNKNOWN
        norm = str(value).strip().upper()
        try:
            return cls[norm]
        except KeyError:
            return cls.UNKNOWN


class SubscriptionSource(str, Enum):
    """Explicit provenance for subscription tier metadata."""

    APPLICATION_RUNTIME = "APPLICATION_RUNTIME"
    OFFICIAL_READ_ONLY_INTERFACE = "OFFICIAL_READ_ONLY_INTERFACE"
    USER_DECLARED = "USER_DECLARED"
    ADMIN_POLICY = "ADMIN_POLICY"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, value: str | None) -> SubscriptionSource:
        if not value:
            return cls.UNKNOWN
        norm = str(value).strip().upper()
        try:
            return cls[norm]
        except KeyError:
            return cls.UNKNOWN


class AccountScope(str, Enum):
    """Scope of an application account context."""

    USER_ACCOUNT = "USER_ACCOUNT"
    WORKSPACE = "WORKSPACE"
    ORGANIZATION = "ORGANIZATION"
    LOCAL_MACHINE = "LOCAL_MACHINE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, value: str | None) -> AccountScope:
        if not value:
            return cls.UNKNOWN
        norm = str(value).strip().upper()
        try:
            return cls[norm]
        except KeyError:
            return cls.UNKNOWN


class EntitlementState(str, Enum):
    """Per-account model entitlement states separating catalogs from verified access."""

    DOCUMENTED_ONLY = "DOCUMENTED_ONLY"
    BUNDLED_CATALOG = "BUNDLED_CATALOG"
    CONFIGURED = "CONFIGURED"
    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
    ACCOUNT_ENUMERATED = "ACCOUNT_ENUMERATED"
    USER_DECLARED = "USER_DECLARED"
    USER_CONFIRMED_SELECTABLE = "USER_CONFIRMED_SELECTABLE"
    SELECTABLE_VERIFIED = "SELECTABLE_VERIFIED"
    INVOCATION_OBSERVED = "INVOCATION_OBSERVED"
    TEMPORARILY_UNAVAILABLE = "TEMPORARILY_UNAVAILABLE"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"

    @classmethod
    def parse(cls, value: str | None) -> EntitlementState:
        if not value:
            return cls.UNKNOWN
        norm = str(value).strip().upper()
        try:
            return cls[norm]
        except KeyError:
            return cls.UNKNOWN


VERIFIED_ENTITLEMENT_STATES: frozenset[EntitlementState] = frozenset(
    {
        EntitlementState.ACCOUNT_ENUMERATED,
        EntitlementState.USER_CONFIRMED_SELECTABLE,
        EntitlementState.SELECTABLE_VERIFIED,
        EntitlementState.INVOCATION_OBSERVED,
    }
)

CONDITIONAL_ENTITLEMENT_STATES: frozenset[EntitlementState] = frozenset(
    {
        EntitlementState.RUNTIME_OBSERVED,
        EntitlementState.USER_DECLARED,
        EntitlementState.CONFIGURED,
    }
)

DISALLOWED_ENTITLEMENT_STATES: frozenset[EntitlementState] = frozenset(
    {
        EntitlementState.DOCUMENTED_ONLY,
        EntitlementState.BUNDLED_CATALOG,
        EntitlementState.TEMPORARILY_UNAVAILABLE,
        EntitlementState.QUOTA_EXHAUSTED,
        EntitlementState.POLICY_BLOCKED,
        EntitlementState.NOT_SUPPORTED,
        EntitlementState.ERROR,
    }
)


class ConfidenceLevel(str, Enum):
    """Confidence classification for observations and evidence."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNVERIFIED = "UNVERIFIED"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, value: str | None) -> ConfidenceLevel:
        if not value:
            return cls.UNKNOWN
        norm = str(value).strip().upper()
        try:
            return cls[norm]
        except KeyError:
            return cls.UNKNOWN


class QuotaState(str, Enum):
    """Usage and quota availability states (strictly independent of subscription tier)."""

    AVAILABLE = "AVAILABLE"
    LOW = "LOW"
    RATE_LIMITED = "RATE_LIMITED"
    EXHAUSTED = "EXHAUSTED"
    UNKNOWN = "UNKNOWN"
    NOT_EXPOSED = "NOT_EXPOSED"
    ERROR = "ERROR"

    @classmethod
    def parse(cls, value: str | None) -> QuotaState:
        if not value:
            return cls.UNKNOWN
        norm = str(value).strip().upper()
        try:
            return cls[norm]
        except KeyError:
            return cls.UNKNOWN


class CapabilityDimension(str, Enum):
    """Standardized model capability dimensions."""

    REASONING = "REASONING"
    ARCHITECTURE = "ARCHITECTURE"
    CODING = "CODING"
    DEBUGGING = "DEBUGGING"
    TOOL_CALLING = "TOOL_CALLING"
    STRUCTURED_OUTPUT = "STRUCTURED_OUTPUT"
    LONG_CONTEXT = "LONG_CONTEXT"
    MULTIMODAL = "MULTIMODAL"
    PARALLEL_AGENT_COORDINATION = "PARALLEL_AGENT_COORDINATION"
    ADVERSARIAL_VERIFICATION = "ADVERSARIAL_VERIFICATION"

    @classmethod
    def parse(cls, value: str | None) -> CapabilityDimension:
        norm = str(value or "").strip().upper()
        return cls[norm]


class CapabilityState(str, Enum):
    """Evidence-backed capability status."""

    VERIFIED = "VERIFIED"
    DOCUMENTED = "DOCUMENTED"
    USER_REPORTED = "USER_REPORTED"
    EXPERIMENTAL = "EXPERIMENTAL"
    UNKNOWN = "UNKNOWN"
    NOT_SUPPORTED = "NOT_SUPPORTED"

    @classmethod
    def parse(cls, value: str | None) -> CapabilityState:
        if not value:
            return cls.UNKNOWN
        norm = str(value).strip().upper()
        try:
            return cls[norm]
        except KeyError:
            return cls.UNKNOWN


class NormalizedEffort(str, Enum):
    """Normalized reasoning effort levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    XHIGH = "XHIGH"
    FIXED_INTERNAL = "FIXED_INTERNAL"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, value: str | None) -> NormalizedEffort:
        if not value:
            return cls.UNKNOWN
        norm = str(value).strip().upper()
        if norm in ("MAX", "ULTRA"):
            # Preserve exact raw value in raw_effort fields; normalize high-plus tiers to XHIGH only when explicit
            return cls.XHIGH
        try:
            return cls[norm]
        except KeyError:
            return cls.UNKNOWN


class CostPolicy(str, Enum):
    """Billing and cost control policy."""

    DENY_UNSPECIFIED_COST = "DENY_UNSPECIFIED_COST"
    FREE_OR_SUBSCRIPTION_ONLY = "FREE_OR_SUBSCRIPTION_ONLY"
    ALLOW_BOUNDED_API_COST = "ALLOW_BOUNDED_API_COST"
    ALLOW_UNBOUNDED_API_COST = "ALLOW_UNBOUNDED_API_COST"

    @classmethod
    def parse(cls, value: str | None) -> CostPolicy:
        if not value:
            return cls.DENY_UNSPECIFIED_COST
        norm = str(value).strip().upper()
        try:
            return cls[norm]
        except KeyError:
            return cls.DENY_UNSPECIFIED_COST


class VerifierIndependenceLevel(str, Enum):
    """Required independence dimension for critical verification."""

    DIFFERENT_SESSION = "DIFFERENT_SESSION"
    DIFFERENT_MODEL = "DIFFERENT_MODEL"
    DIFFERENT_MODEL_FAMILY = "DIFFERENT_MODEL_FAMILY"
    DIFFERENT_PROVIDER = "DIFFERENT_PROVIDER"

    @classmethod
    def parse(cls, value: str | None) -> VerifierIndependenceLevel:
        if not value:
            return cls.DIFFERENT_MODEL_FAMILY
        norm = str(value).strip().upper()
        try:
            return cls[norm]
        except KeyError:
            return cls.DIFFERENT_MODEL_FAMILY


class TaskRole(str, Enum):
    """Orchestration task roles."""

    CHIEF_ORCHESTRATOR = "CHIEF_ORCHESTRATOR"
    ARCHITECT = "ARCHITECT"
    IMPLEMENTATION_WORKER = "IMPLEMENTATION_WORKER"
    FAST_WORKER = "FAST_WORKER"
    TEST_ENGINEER = "TEST_ENGINEER"
    INDEPENDENT_VERIFIER = "INDEPENDENT_VERIFIER"
    RECOVERY_ANALYST = "RECOVERY_ANALYST"

    @classmethod
    def parse(cls, value: str | None) -> TaskRole:
        norm = str(value or "").strip().upper()
        return cls[norm]


class RouterTaskRisk(str, Enum):
    """Task risk tiers governing routing strictness."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def parse(cls, value: str | None) -> RouterTaskRisk:
        norm = str(value or "").strip().upper()
        return cls[norm]


class CandidateEligibility(str, Enum):
    """Per-candidate eligibility outcome."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    CONDITIONAL = "CONDITIONAL"
    UNKNOWN = "UNKNOWN"


class RoutePlanStatus(str, Enum):
    """Overall route plan outcomes."""

    READY_FOR_USER_REVIEW = "READY_FOR_USER_REVIEW"
    PROPOSED = "PROPOSED"
    PROPOSED_CONDITIONAL = "PROPOSED_CONDITIONAL"
    BLOCKED_ENTITLEMENT = "BLOCKED_ENTITLEMENT"
    BLOCKED_BILLING_POLICY = "BLOCKED_BILLING_POLICY"
    BLOCKED_CAPABILITY = "BLOCKED_CAPABILITY"
    BLOCKED_INDEPENDENT_VERIFIER = "BLOCKED_INDEPENDENT_VERIFIER"
    BLOCKED_NO_RUNTIME = "BLOCKED_NO_RUNTIME"
    INVALID_TASK_PROFILE = "INVALID_TASK_PROFILE"


@dataclass(frozen=True)
class UserProfileRecord:
    """Opaque local user profile (contains no PII)."""

    user_profile_id: str
    label: str | None = None
    created_at: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        validate_opaque_id(self.user_profile_id, field_name="user_profile_id")

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "user_profile_id": self.user_profile_id,
                "label": self.label,
                "created_at": self.created_at,
            }
        )


@dataclass(frozen=True)
class ApplicationInstanceRecord:
    """Discovered or declared application installation instance."""

    application_instance_id: str
    user_profile_id: str
    application_id: str
    installation_state: str  # installed | not_installed | partial | unknown | error
    packaging_mode: str = "unknown"
    version: str | None = None
    executable_basename: str | None = None
    observed_at: str = field(default_factory=utc_now_iso)
    evidence_ref: str | None = None

    def __post_init__(self) -> None:
        validate_opaque_id(self.application_instance_id, field_name="application_instance_id")
        validate_opaque_id(self.user_profile_id, field_name="user_profile_id")

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "application_instance_id": self.application_instance_id,
                "user_profile_id": self.user_profile_id,
                "application_id": self.application_id,
                "installation_state": self.installation_state,
                "packaging_mode": self.packaging_mode,
                "version": self.version,
                "executable_basename": self.executable_basename,
                "observed_at": self.observed_at,
                "evidence_ref": self.evidence_ref,
            }
        )


@dataclass(frozen=True)
class AccountContextRecord:
    """Isolated per-application account context (never merged across apps or PII)."""

    account_context_id: str
    user_profile_id: str
    application_instance_id: str
    application_id: str
    provider: str
    authentication_mode: AuthenticationMode = AuthenticationMode.UNKNOWN
    account_scope: AccountScope = AccountScope.USER_ACCOUNT
    workspace_scope: str | None = None
    subscription_tier: str | None = None
    subscription_source: SubscriptionSource = SubscriptionSource.UNKNOWN
    entitlement_state: EntitlementState = EntitlementState.UNKNOWN
    workspace_allowed_models: tuple[str, ...] = ()
    workspace_blocked_models: tuple[str, ...] = ()
    observed_at: str | None = None

    def __post_init__(self) -> None:
        validate_opaque_id(self.account_context_id, field_name="account_context_id")
        validate_opaque_id(self.user_profile_id, field_name="user_profile_id")
        validate_opaque_id(self.application_instance_id, field_name="application_instance_id")
        if self.workspace_scope is not None:
            validate_opaque_id(self.workspace_scope, field_name="workspace_scope")

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "account_context_id": self.account_context_id,
                "user_profile_id": self.user_profile_id,
                "application_instance_id": self.application_instance_id,
                "application_id": self.application_id,
                "provider": self.provider,
                "authentication_mode": self.authentication_mode.value,
                "account_scope": self.account_scope.value,
                "workspace_scope": self.workspace_scope,
                "subscription_tier": self.subscription_tier,
                "subscription_source": self.subscription_source.value,
                "entitlement_state": self.entitlement_state.value,
                "workspace_allowed_models": list(self.workspace_allowed_models),
                "workspace_blocked_models": list(self.workspace_blocked_models),
                "observed_at": self.observed_at,
            }
        )


@dataclass(frozen=True)
class ModelEntitlementObservation:
    """Append-only historical entitlement observation for a model in an account context."""

    observation_id: str
    account_context_id: str
    application_instance_id: str
    application_id: str
    model_id: str
    state: EntitlementState
    provenance: str
    confidence: ConfidenceLevel
    observed_at: str
    evidence_ref: str
    expires_at: str | None = None
    notes: str | None = None

    def __post_init__(self) -> None:
        validate_opaque_id(self.observation_id, field_name="observation_id")
        validate_opaque_id(self.account_context_id, field_name="account_context_id")
        validate_opaque_id(self.application_instance_id, field_name="application_instance_id")

    def is_stale(self, *, as_of: datetime | None = None) -> bool:
        return is_expired(self.expires_at, as_of=as_of)

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "observation_id": self.observation_id,
                "account_context_id": self.account_context_id,
                "application_instance_id": self.application_instance_id,
                "application_id": self.application_id,
                "model_id": self.model_id,
                "state": self.state.value,
                "provenance": self.provenance,
                "confidence": self.confidence.value,
                "observed_at": self.observed_at,
                "expires_at": self.expires_at,
                "evidence_ref": self.evidence_ref,
                "notes": self.notes,
            }
        )


@dataclass(frozen=True)
class QuotaObservation:
    """Append-only quota and rate-limit observation for an account/model."""

    observation_id: str
    account_context_id: str
    model_id: str | None
    usage_category: str
    quota_state: QuotaState
    observed_at: str
    source: str
    evidence_ref: str
    remaining_quantity: float | None = None
    remaining_percentage: float | None = None
    reset_at: str | None = None
    rate_limited: bool = False
    expires_at: str | None = None

    def __post_init__(self) -> None:
        validate_opaque_id(self.observation_id, field_name="observation_id")
        validate_opaque_id(self.account_context_id, field_name="account_context_id")

    def is_stale(self, *, as_of: datetime | None = None) -> bool:
        return is_expired(self.expires_at, as_of=as_of)

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "observation_id": self.observation_id,
                "account_context_id": self.account_context_id,
                "model_id": self.model_id,
                "usage_category": self.usage_category,
                "quota_state": self.quota_state.value,
                "remaining_quantity": self.remaining_quantity,
                "remaining_percentage": self.remaining_percentage,
                "reset_at": self.reset_at,
                "rate_limited": self.rate_limited,
                "observed_at": self.observed_at,
                "expires_at": self.expires_at,
                "source": self.source,
                "evidence_ref": self.evidence_ref,
            }
        )


@dataclass(frozen=True)
class ModelIdentityRecord:
    """Tracks exact runtime model identity and family relationships without assuming cross-app equivalence."""

    application_id: str
    application_model_id: str
    provider: str = "unknown"
    canonical_model_id: str | None = None
    model_version: str | None = None
    model_family: str = "UNKNOWN"
    variant: str | None = None
    reasoning_effort_variant: str | None = None
    is_orchestrator_wrapper: bool = False
    orchestrator_wrapper_identity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "application_id": self.application_id,
                "application_model_id": self.application_model_id,
                "provider": self.provider,
                "canonical_model_id": self.canonical_model_id,
                "model_version": self.model_version,
                "model_family": self.model_family,
                "variant": self.variant,
                "reasoning_effort_variant": self.reasoning_effort_variant,
                "is_orchestrator_wrapper": self.is_orchestrator_wrapper,
                "orchestrator_wrapper_identity": self.orchestrator_wrapper_identity,
            }
        )


@dataclass(frozen=True)
class ModelCapabilityEvidence:
    """Single evidence-backed capability observation for a model dimension."""

    evidence_id: str
    application_id: str
    application_model_id: str
    dimension: CapabilityDimension
    status: CapabilityState
    evidence_source: str
    confidence: ConfidenceLevel
    observed_at: str
    model_version: str | None = None
    evidence_ref: str | None = None
    notes: str | None = None
    expires_at: str | None = None

    def is_stale(self, *, as_of: datetime | None = None) -> bool:
        return is_expired(self.expires_at, as_of=as_of)

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "evidence_id": self.evidence_id,
                "application_id": self.application_id,
                "application_model_id": self.application_model_id,
                "dimension": self.dimension.value,
                "status": self.status.value,
                "evidence_source": self.evidence_source,
                "confidence": self.confidence.value,
                "observed_at": self.observed_at,
                "expires_at": self.expires_at,
                "model_version": self.model_version,
                "evidence_ref": self.evidence_ref,
                "notes": self.notes,
            }
        )


@dataclass(frozen=True)
class ModelEffortProfile:
    """Application- and model-specific reasoning effort profile."""

    application_id: str
    application_model_id: str
    account_context_id: str | None = None
    supported_efforts: tuple[NormalizedEffort, ...] = ()
    raw_supported_efforts: tuple[str, ...] = ()
    default_effort: NormalizedEffort = NormalizedEffort.UNKNOWN
    raw_default_effort: str | None = None
    selected_effort: NormalizedEffort | None = None
    independently_configurable: bool = False
    managed_by_orchestrator: bool = False
    orchestrator_structure: dict[str, Any] | None = None
    provenance: str = "UNKNOWN"
    observed_at: str = field(default_factory=utc_now_iso)
    evidence_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "application_id": self.application_id,
                "application_model_id": self.application_model_id,
                "account_context_id": self.account_context_id,
                "supported_efforts": [e.value for e in self.supported_efforts],
                "raw_supported_efforts": list(self.raw_supported_efforts),
                "default_effort": self.default_effort.value,
                "raw_default_effort": self.raw_default_effort,
                "selected_effort": self.selected_effort.value if self.selected_effort else None,
                "independently_configurable": self.independently_configurable,
                "managed_by_orchestrator": self.managed_by_orchestrator,
                "orchestrator_structure": self.orchestrator_structure,
                "provenance": self.provenance,
                "observed_at": self.observed_at,
                "evidence_ref": self.evidence_ref,
            }
        )


@dataclass(frozen=True)
class UserRoutingPolicy:
    """User-specific routing preferences with conservative safe defaults."""

    policy_id: str
    user_profile_id: str
    preferred_applications: tuple[str, ...] = ()
    allowed_providers: tuple[str, ...] = ()
    blocked_providers: tuple[str, ...] = ()
    allowed_models: tuple[str, ...] = ()
    blocked_models: tuple[str, ...] = ()
    preferred_models: tuple[str, ...] = ()
    subscription_only: bool = True
    api_billing_allowed: bool = False
    max_cost_policy: CostPolicy = CostPolicy.DENY_UNSPECIFIED_COST
    preferred_effort: NormalizedEffort = NormalizedEffort.HIGH
    allow_automatic_fallback: bool = False
    require_independent_verifier: bool = True
    require_cross_provider_verifier: bool = False
    minimum_verifier_independence: VerifierIndependenceLevel = VerifierIndependenceLevel.DIFFERENT_MODEL_FAMILY

    def __post_init__(self) -> None:
        validate_opaque_id(self.policy_id, field_name="policy_id")
        validate_opaque_id(self.user_profile_id, field_name="user_profile_id")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserRoutingPolicy:
        return cls(
            policy_id=str(data.get("policy_id") or "pol-default"),
            user_profile_id=str(data["user_profile_id"]),
            preferred_applications=tuple(str(x).strip() for x in (data.get("preferred_applications") or []) if str(x).strip()),
            allowed_providers=tuple(str(x).strip().lower() for x in (data.get("allowed_providers") or []) if str(x).strip()),
            blocked_providers=tuple(str(x).strip().lower() for x in (data.get("blocked_providers") or []) if str(x).strip()),
            allowed_models=tuple(str(x).strip() for x in (data.get("allowed_models") or []) if str(x).strip()),
            blocked_models=tuple(str(x).strip() for x in (data.get("blocked_models") or []) if str(x).strip()),
            preferred_models=tuple(str(x).strip() for x in (data.get("preferred_models") or []) if str(x).strip()),
            subscription_only=strict_bool(data, "subscription_only", True),
            api_billing_allowed=strict_bool(data, "api_billing_allowed", False),
            max_cost_policy=CostPolicy.parse(data.get("max_cost_policy")),
            preferred_effort=NormalizedEffort.parse(data.get("preferred_effort") or "HIGH"),
            allow_automatic_fallback=strict_bool(data, "allow_automatic_fallback", False),
            require_independent_verifier=strict_bool(data, "require_independent_verifier", True),
            require_cross_provider_verifier=strict_bool(data, "require_cross_provider_verifier", False),
            minimum_verifier_independence=VerifierIndependenceLevel.parse(
                data.get("minimum_verifier_independence")
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "policy_id": self.policy_id,
                "user_profile_id": self.user_profile_id,
                "preferred_applications": list(self.preferred_applications),
                "allowed_providers": list(self.allowed_providers),
                "blocked_providers": list(self.blocked_providers),
                "allowed_models": list(self.allowed_models),
                "blocked_models": list(self.blocked_models),
                "preferred_models": list(self.preferred_models),
                "subscription_only": self.subscription_only,
                "api_billing_allowed": self.api_billing_allowed,
                "max_cost_policy": self.max_cost_policy.value.lower(),
                "preferred_effort": self.preferred_effort.value.lower(),
                "allow_automatic_fallback": self.allow_automatic_fallback,
                "require_independent_verifier": self.require_independent_verifier,
                "require_cross_provider_verifier": self.require_cross_provider_verifier,
                "minimum_verifier_independence": self.minimum_verifier_independence.value.lower(),
            }
        )


@dataclass(frozen=True)
class TaskProfile:
    """Structured task profile driving deterministic capability-based routing."""

    task_profile_id: str
    risk: RouterTaskRisk
    roles: tuple[TaskRole, ...]
    required_capabilities: dict[TaskRole, tuple[CapabilityDimension, ...]] = field(default_factory=dict)
    required_efforts: dict[TaskRole, NormalizedEffort] = field(default_factory=dict)
    description: str = ""
    require_independent_verifier: bool | None = None
    allowed_applications: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TaskProfile:
        if not isinstance(data, dict):
            raise ValueError("Task profile must be a JSON object.")
        tpid = str(data.get("task_profile_id") or "").strip()
        if not tpid:
            raise ValueError("Task profile requires non-empty 'task_profile_id'.")
        validate_opaque_id(tpid, field_name="task_profile_id")

        raw_risk = data.get("risk")
        if not raw_risk:
            raise ValueError("Task profile requires 'risk' (LOW, MEDIUM, HIGH, CRITICAL).")
        try:
            risk = RouterTaskRisk.parse(str(raw_risk))
        except KeyError as exc:
            raise ValueError(f"Unsupported task risk: {raw_risk}") from exc

        raw_roles = data.get("roles")
        if not isinstance(raw_roles, list) or not raw_roles:
            raise ValueError("Task profile requires non-empty 'roles' list.")
        roles_list: list[TaskRole] = []
        for r in raw_roles:
            try:
                roles_list.append(TaskRole.parse(str(r)))
            except KeyError as exc:
                raise ValueError(f"Unsupported task role: {r}") from exc

        req_caps: dict[TaskRole, tuple[CapabilityDimension, ...]] = {}
        raw_caps = data.get("required_capabilities") or {}
        if not isinstance(raw_caps, dict):
            raise ValueError("'required_capabilities' must be an object mapping role -> capability list.")
        for rk, dims in raw_caps.items():
            role_obj = TaskRole.parse(str(rk))
            if not isinstance(dims, list):
                raise ValueError(f"Capabilities for role '{rk}' must be a list.")
            req_caps[role_obj] = tuple(CapabilityDimension.parse(str(d)) for d in dims)

        req_effs: dict[TaskRole, NormalizedEffort] = {}
        raw_effs = data.get("required_efforts") or {}
        if not isinstance(raw_effs, dict):
            raise ValueError("'required_efforts' must be an object mapping role -> effort.")
        for rk, eff in raw_effs.items():
            req_effs[TaskRole.parse(str(rk))] = NormalizedEffort.parse(str(eff))

        return cls(
            task_profile_id=tpid,
            risk=risk,
            roles=tuple(dict.fromkeys(roles_list)),
            required_capabilities=req_caps,
            required_efforts=req_effs,
            description=str(data.get("description") or ""),
            require_independent_verifier=(
                strict_bool(data, "require_independent_verifier", True)
                if "require_independent_verifier" in data and data["require_independent_verifier"] is not None
                else None
            ),
            allowed_applications=tuple(str(x).strip() for x in (data.get("allowed_applications") or []) if str(x).strip()),
        )

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "task_profile_id": self.task_profile_id,
                "risk": self.risk.value,
                "roles": [r.value for r in self.roles],
                "required_capabilities": {
                    k.value: [d.value for d in v] for k, v in self.required_capabilities.items()
                },
                "required_efforts": {k.value: v.value for k, v in self.required_efforts.items()},
                "description": self.description,
                "require_independent_verifier": self.require_independent_verifier,
                "allowed_applications": list(self.allowed_applications),
            }
        )


@dataclass(frozen=True)
class CandidateEvaluation:
    """Explicit inclusion/exclusion explanation for one candidate in one role."""

    role: TaskRole
    application_id: str
    application_instance_id: str
    account_context_id: str
    provider: str
    model_id: str
    eligibility: CandidateEligibility
    reason_codes: tuple[str, ...]
    explanation: str
    entitlement_state: str
    quota_state: str
    authentication_mode: str
    selected_effort: str | None = None
    score: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "role": self.role.value,
                "application_id": self.application_id,
                "application_instance_id": self.application_instance_id,
                "account_context_id": self.account_context_id,
                "provider": self.provider,
                "model_id": self.model_id,
                "eligibility": self.eligibility.value,
                "reason_codes": list(self.reason_codes),
                "explanation": self.explanation,
                "entitlement_state": self.entitlement_state,
                "quota_state": self.quota_state,
                "authentication_mode": self.authentication_mode,
                "selected_effort": self.selected_effort,
            }
        )


@dataclass(frozen=True)
class RoleAssignment:
    """Selected or blocked assignment for a single task role."""

    role: TaskRole
    application: str | None
    application_instance_id: str | None
    account_context_id: str | None
    provider: str | None
    model_id: str | None
    effort: str | None
    eligibility: str  # ACCEPTED | CONDITIONAL | BLOCKED | UNKNOWN
    entitlement_state: str
    quota_state: str
    reason: str
    independence_checks: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "application": self.application,
                "application_instance_id": self.application_instance_id,
                "account_context_id": self.account_context_id,
                "provider": self.provider,
                "model_id": self.model_id,
                "effort": self.effort,
                "eligibility": self.eligibility,
                "entitlement_state": self.entitlement_state,
                "quota_state": self.quota_state,
                "reason": self.reason,
                "independence_checks": self.independence_checks,
            }
        )


@dataclass(frozen=True)
class RoutePlan:
    """Explainable, planning-only routing decision (grants zero execution authority)."""

    decision_id: str
    user_profile_id: str
    task_profile_id: str
    risk: str
    status: RoutePlanStatus
    roles: dict[str, RoleAssignment]
    billing: dict[str, Any]
    quota: dict[str, Any]
    excluded_candidates: tuple[CandidateEvaluation, ...]
    candidate_evaluations: tuple[CandidateEvaluation, ...]
    fallback_candidates: dict[str, list[dict[str, Any]]]
    required_confirmations: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    verification_independence: dict[str, Any]
    created_at: str = field(default_factory=utc_now_iso)
    execution_authorized: bool = False  # Always False in NEXT-22B

    def to_dict(self) -> dict[str, Any]:
        return sanitize_for_output(
            {
                "schema_version": SCHEMA_VERSION,
                "decision_id": self.decision_id,
                "user_profile_id": self.user_profile_id,
                "task_profile_id": self.task_profile_id,
                "risk": self.risk,
                "status": self.status.value,
                "execution_authorized": False,
                "roles": {k.lower(): v.to_dict() for k, v in self.roles.items()},
                "billing": self.billing,
                "quota": self.quota,
                "excluded_candidates": [c.to_dict() for c in self.excluded_candidates],
                "candidate_evaluations": [c.to_dict() for c in self.candidate_evaluations],
                "fallback_candidates": self.fallback_candidates,
                "required_confirmations": list(self.required_confirmations),
                "evidence_refs": list(self.evidence_refs),
                "verification_independence": self.verification_independence,
                "created_at": self.created_at,
            }
        )

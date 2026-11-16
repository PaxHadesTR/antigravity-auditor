"""NEXT-22D Application-Specific MCP Adapters & Identity Binding Foundation."""

from pathlib import Path
import sys

_CORE_DIR = str(Path(__file__).resolve().parents[1])
if _CORE_DIR not in sys.path:
    sys.path.insert(0, _CORE_DIR)

from application_adapters.adapter_context import (
    AdapterContextResolver,
    AdapterResolutionBundle,
    UntrustedAdapterHints,
)
from application_adapters.adapter_registry import ApplicationAdapterRegistry
from application_adapters.adapter_runtime import (
    DEFAULT_MAX_MESSAGE_BYTES,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    CommonStdioAdapterHost,
)
from application_adapters.adapters import (
    AntigravityApplicationAdapter,
    ClaudeCodeApplicationAdapter,
    ClaudeDesktopApplicationAdapter,
    CodexApplicationAdapter,
)
from application_adapters.broker_transport import (
    BrokerTransport,
    BrokerTransportDisconnectedError,
    BrokerTransportError,
    BrokerTransportTimeoutError,
    BrokerTransportUnavailableError,
    DisabledProductionNamedPipeTransport,
    InMemoryBrokerTransport,
    TestBrokerTransport,
)
from application_adapters.configuration_preview import (
    build_offline_mcpb_archive,
    validate_launch_command,
    validate_preview_item,
)
from application_adapters.contracts import (
    ADAPTER_PACKAGE_VERSION,
    CANONICAL_APPLICATION_LABELS,
    AdapterChallenge,
    AdapterConfigPreview,
    AdapterInstallState,
    AdapterProofVerificationResult,
    ApplicationAdapterProfile,
    IdentityVerificationStatus,
    ProcessObservation,
    SignatureStatus,
    SignedAdapterProof,
    contains_secret_material,
)
from application_adapters.credential_provider import (
    AdapterCredentialProvider,
    CredentialProviderUnavailableError,
    DisabledProductionCredentialProvider,
    EphemeralTestCredentialProvider,
)
from application_adapters.identity_proof import (
    AdapterChallengeManager,
    ChallengeBoundAdapterProofVerifier,
    ChallengeReplayCache,
    build_canonical_proof_message,
)
from application_adapters.process_observation import (
    ProcessObserver,
    Win32ReadOnlyProcessObserver,
    compute_safe_file_sha256,
)

__all__ = [
    "ADAPTER_PACKAGE_VERSION",
    "AdapterChallenge",
    "AdapterChallengeManager",
    "AdapterConfigPreview",
    "AdapterContextResolver",
    "AdapterCredentialProvider",
    "AdapterInstallState",
    "AdapterProofVerificationResult",
    "AdapterResolutionBundle",
    "AntigravityApplicationAdapter",
    "ApplicationAdapterProfile",
    "ApplicationAdapterRegistry",
    "BrokerTransport",
    "BrokerTransportDisconnectedError",
    "BrokerTransportError",
    "BrokerTransportTimeoutError",
    "BrokerTransportUnavailableError",
    "CANONICAL_APPLICATION_LABELS",
    "ChallengeBoundAdapterProofVerifier",
    "ChallengeReplayCache",
    "ClaudeCodeApplicationAdapter",
    "ClaudeDesktopApplicationAdapter",
    "CodexApplicationAdapter",
    "CommonStdioAdapterHost",
    "CredentialProviderUnavailableError",
    "DEFAULT_MAX_MESSAGE_BYTES",
    "DEFAULT_REQUEST_TIMEOUT_SECONDS",
    "DisabledProductionCredentialProvider",
    "DisabledProductionNamedPipeTransport",
    "EphemeralTestCredentialProvider",
    "IdentityVerificationStatus",
    "InMemoryBrokerTransport",
    "ProcessObservation",
    "ProcessObserver",
    "SignatureStatus",
    "SignedAdapterProof",
    "TestBrokerTransport",
    "UntrustedAdapterHints",
    "Win32ReadOnlyProcessObserver",
    "build_canonical_proof_message",
    "build_offline_mcpb_archive",
    "compute_safe_file_sha256",
    "contains_secret_material",
    "validate_launch_command",
    "validate_preview_item",
]

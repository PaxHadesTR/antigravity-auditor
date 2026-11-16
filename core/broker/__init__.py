"""Antigravity Auditor Broker IPC and Database Ownership Package.

NEXT-21C-A Foundation Package:
Provides secure Windows Named Pipe IPC, JSON-RPC 2.0 framing, client token/integrity
verification, and centralized isolated database management.
"""

from broker.audit_logger import BrokerAuditLogger
from broker.client import BrokerClient
from broker.cng import CngCbeatSigner, CngKeyMetadata, probe_cng_provider, probe_tpm_device
from broker.constants import (
    B4B_TEST_KEY_PREFIX,
    B4B_TEST_PIPE_PREFIX,
    B4B_TEST_SERVICE_PREFIX,
    DEFAULT_MAX_CONCURRENT_CLIENTS,
    DEFAULT_PIPE_NAME,
    DEFAULT_PIPE_SDDL,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_MESSAGE_SIZE,
    PROTOCOL_VERSION,
    SERVICE_MODE_B4A_QUALIFICATION,
    SERVICE_MODE_B4B_GOVERNANCE_TEST,
    SERVICE_MODE_STANDARD,
)
from broker.db_adapter import BrokerDatabaseAdapter
from broker.dispatcher import BrokerDispatcher
from broker.exceptions import (
    BrokerAuthError,
    BrokerCngError,
    BrokerConfirmationError,
    BrokerConfirmationRequiredError,
    BrokerDatabaseError,
    BrokerError,
    BrokerSchemaError,
    BrokerSecurityError,
    BrokerTimeoutError,
    BrokerTpmUnavailableError,
    BrokerUnavailableError,
    MethodNotImplementedError,
    ProductionDatabaseAccessProhibitedError,
)
from broker.protocol import (
    JsonRpcRequest,
    JsonRpcResponse,
    decode_frame_header,
    encode_frame,
    parse_request_bytes,
)
from broker.security import (
    ClientIdentity,
    create_pipe_security_descriptor,
    inspect_pipe_client_identity,
    is_windows,
)
from broker.service_host import (
    BrokerServiceConfig,
    BrokerServiceHost,
    ServiceState,
)
from broker.tcb import TcbPolicy, TcbTrustedAuthenticator, TcbVerifier
from broker.transport import (
    BasePipeServer,
    MemoryPipeTransport,
    WindowsNamedPipeServer,
)

__all__ = [
    "B4B_TEST_KEY_PREFIX",
    "B4B_TEST_PIPE_PREFIX",
    "B4B_TEST_SERVICE_PREFIX",
    "BasePipeServer",
    "BrokerAuditLogger",
    "BrokerClient",
    "BrokerCngError",
    "BrokerConfirmationError",
    "BrokerConfirmationRequiredError",
    "BrokerDatabaseAdapter",
    "BrokerDispatcher",
    "BrokerError",
    "BrokerAuthError",
    "BrokerSchemaError",
    "BrokerSecurityError",
    "BrokerDatabaseError",
    "BrokerServiceConfig",
    "BrokerServiceHost",
    "BrokerTimeoutError",
    "BrokerTpmUnavailableError",
    "BrokerUnavailableError",
    "ClientIdentity",
    "CngCbeatSigner",
    "CngKeyMetadata",
    "DEFAULT_MAX_CONCURRENT_CLIENTS",
    "DEFAULT_PIPE_NAME",
    "DEFAULT_PIPE_SDDL",
    "DEFAULT_TIMEOUT_SECONDS",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "MAX_MESSAGE_SIZE",
    "MemoryPipeTransport",
    "MethodNotImplementedError",
    "PROTOCOL_VERSION",
    "ProductionDatabaseAccessProhibitedError",
    "SERVICE_MODE_B4A_QUALIFICATION",
    "SERVICE_MODE_B4B_GOVERNANCE_TEST",
    "SERVICE_MODE_STANDARD",
    "ServiceState",
    "TcbPolicy",
    "TcbTrustedAuthenticator",
    "TcbVerifier",
    "WindowsNamedPipeServer",
    "create_pipe_security_descriptor",
    "decode_frame_header",
    "encode_frame",
    "inspect_pipe_client_identity",
    "is_windows",
    "parse_request_bytes",
    "probe_cng_provider",
    "probe_tpm_device",
]

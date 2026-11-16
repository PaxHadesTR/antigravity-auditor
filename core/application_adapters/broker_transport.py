"""Isolated BrokerTransport abstraction with disabled production Named Pipe guard."""

from __future__ import annotations

from typing import Any, Callable, Protocol

from broker.constants import DEFAULT_PIPE_NAME, DEFAULT_TIMEOUT_SECONDS
from mcp_gateway.authenticated_context import AuthenticatedCallerContext
from mcp_gateway.gateway import AdaptiveMCPGateway


class BrokerTransportError(RuntimeError):
    """Base error for adapter-to-broker transport failures (zero DB fallback)."""


class BrokerTransportTimeoutError(BrokerTransportError):
    """Raised when a broker transport call exceeds its bounded timeout."""


class BrokerTransportDisconnectedError(BrokerTransportError):
    """Raised when the broker transport disconnects or refuses connections."""


class BrokerTransportUnavailableError(PermissionError):
    """Raised when a disabled or unavailable production transport is invoked."""


class BrokerTransport(Protocol):
    """Transport contract between CommonStdioAdapterHost and AdaptiveMCPGateway/Broker."""

    @property
    def transport_kind(self) -> str: ...

    @property
    def is_production_transport(self) -> bool: ...

    @property
    def is_closed(self) -> bool: ...

    def handle_gateway_rpc(
        self,
        request: dict[str, Any],
        *,
        caller_context: AuthenticatedCallerContext,
    ) -> dict[str, Any] | None: ...

    def close(self) -> None: ...


class InMemoryBrokerTransport:
    """Deterministic in-memory transport directly invoking NEXT-22C AdaptiveMCPGateway."""

    def __init__(self, gateway: AdaptiveMCPGateway, *, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self._gateway = gateway
        self.timeout_seconds = float(timeout_seconds)
        self._closed = False

    @property
    def transport_kind(self) -> str:
        return "in_memory_gateway"

    @property
    def is_production_transport(self) -> bool:
        return False

    @property
    def is_closed(self) -> bool:
        return self._closed

    def handle_gateway_rpc(
        self,
        request: dict[str, Any],
        *,
        caller_context: AuthenticatedCallerContext,
    ) -> dict[str, Any] | None:
        if self._closed:
            raise BrokerTransportDisconnectedError("InMemoryBrokerTransport is closed.")
        return self._gateway.handle_jsonrpc_message(request, caller_context=caller_context)

    def close(self) -> None:
        self._closed = True


class TestBrokerTransport:
    """Configurable test/fault-injection transport (timeouts, disconnects, invalid responses)."""

    __test__ = False

    def __init__(
        self,
        handler: Callable[[dict[str, Any], AuthenticatedCallerContext], dict[str, Any] | None],
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        simulate_timeout: bool = False,
        simulate_disconnect: bool = False,
    ) -> None:
        self._handler = handler
        self.timeout_seconds = float(timeout_seconds)
        self.simulate_timeout = simulate_timeout
        self.simulate_disconnect = simulate_disconnect
        self._closed = False
        self.requests_seen: int = 0

    @property
    def transport_kind(self) -> str:
        return "test_fault_injectable"

    @property
    def is_production_transport(self) -> bool:
        return False

    @property
    def is_closed(self) -> bool:
        return self._closed

    def handle_gateway_rpc(
        self,
        request: dict[str, Any],
        *,
        caller_context: AuthenticatedCallerContext,
    ) -> dict[str, Any] | None:
        if self._closed or self.simulate_disconnect:
            raise BrokerTransportDisconnectedError(
                "TEST_TRANSPORT_DISCONNECTED: Broker IPC disconnected (no direct DB fallback permitted)."
            )
        if self.simulate_timeout:
            raise BrokerTransportTimeoutError(
                f"TEST_TRANSPORT_TIMEOUT: Broker RPC timed out after {self.timeout_seconds:.2f}s (no DB fallback)."
            )
        self.requests_seen += 1
        resp = self._handler(request, caller_context)
        if resp is not None and (not isinstance(resp, dict) or resp.get("jsonrpc") != "2.0"):
            raise BrokerTransportError("INVALID_BROKER_RESPONSE: Expected JSON-RPC 2.0 response object or None.")
        return resp

    def close(self) -> None:
        self._closed = True


class DisabledProductionNamedPipeTransport:
    """Explicitly disabled production Named Pipe contract (Part 8).

    B4-A1/B4-B qualification is incomplete, so production Win32 Named Pipe access MUST NOT
    be opened or queried by adapters in NEXT-22D, and direct SQLite fallback is forbidden.
    """

    def __init__(self, pipe_name: str = DEFAULT_PIPE_NAME) -> None:
        self.pipe_name = pipe_name
        self.enabled = False
        self._closed = False

    @property
    def transport_kind(self) -> str:
        return "disabled_production_named_pipe"

    @property
    def is_production_transport(self) -> bool:
        return True

    @property
    def is_closed(self) -> bool:
        return self._closed

    def handle_gateway_rpc(
        self,
        request: dict[str, Any],
        *,
        caller_context: AuthenticatedCallerContext,
    ) -> dict[str, Any] | None:
        _ = (request, caller_context)
        raise BrokerTransportUnavailableError(
            f"PRODUCTION_BROKER_NAMED_PIPE_DISABLED: Production Named Pipe '{self.pipe_name}' "
            "is disabled in NEXT-22D; direct SQLite fallback is strictly forbidden."
        )

    def close(self) -> None:
        self._closed = True

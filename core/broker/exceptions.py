"""Exceptions for Antigravity Auditor Control-Plane Broker."""

from __future__ import annotations

from typing import Any


class BrokerError(Exception):
    """Base exception for all Broker operations."""

    def __init__(self, message: str, code: int = -32603, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.data = data or {}


class BrokerAuthError(BrokerError):
    """Raised when client authentication, integrity level, or method authorization fails."""

    def __init__(self, message: str, code: int = -32001, data: dict[str, Any] | None = None) -> None:
        super().__init__(message, code=code, data=data)


class BrokerSecurityError(BrokerAuthError):
    """Raised when a governance invariant, anti-replay, or authorization check fails."""

    def __init__(self, message: str, code: int = -32001, data: dict[str, Any] | None = None) -> None:
        super().__init__(message, code=code, data=data)


class BrokerSchemaError(BrokerError):
    """Raised when request or response fails JSON-RPC 2.0 schema validation."""

    def __init__(self, message: str, code: int = -32602, data: dict[str, Any] | None = None) -> None:
        super().__init__(message, code=code, data=data)


class BrokerDatabaseError(BrokerError):
    """Raised when a broker-managed database operation encounters an error."""

    def __init__(self, message: str, code: int = -32002, data: dict[str, Any] | None = None) -> None:
        super().__init__(message, code=code, data=data)


class ProductionDatabaseAccessProhibitedError(BrokerDatabaseError):
    """Raised when an attempt is made to point the broker at a production database during non-production mode."""

    def __init__(
        self,
        message: str,
        code: int = -32006,
        data: dict[str, Any] | None = None,
        path: str | None = None,
    ) -> None:
        err_data = data or {}
        if path and "path" not in err_data:
            err_data["path"] = str(path)
        super().__init__(message, code=code, data=err_data)


class BrokerTimeoutError(BrokerError):
    """Raised when request processing or IPC transfer times out."""

    def __init__(self, message: str = "Request timed out", code: int = -32004, data: dict[str, Any] | None = None) -> None:
        super().__init__(message, code=code, data=data)


class BrokerUnavailableError(BrokerError):
    """Raised when the broker pipe is unavailable or refused connection."""

    def __init__(
        self,
        message: str = "Broker service is unavailable",
        code: int = -32003,
        data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code=code, data=data)


class MethodNotImplementedError(BrokerError):
    """Raised when a state-mutating governance method or unknown method is called."""

    def __init__(
        self,
        message: str = "Method not implemented",
        code: int = -32000,
        data: dict[str, Any] | None = None,
        method_name: str | None = None,
    ) -> None:
        err_data = data or {}
        if method_name and "method" not in err_data:
            err_data["method"] = method_name
        super().__init__(message, code=code, data=err_data)


class BrokerCngError(BrokerError):
    """Raised when a Windows CNG / NCrypt operation or policy check fails."""

    def __init__(self, message: str, code: int = -32020, data: dict[str, Any] | None = None) -> None:
        super().__init__(message, code=code, data=data)


class BrokerTpmUnavailableError(BrokerCngError):
    """Raised when TPM / Platform Crypto Provider is required but unavailable (fail closed)."""

    def __init__(
        self,
        message: str = "TPM_UNAVAILABLE: Platform Crypto Provider is unavailable or not hardware-backed.",
        code: int = -32021,
        data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code=code, data=data)


class BrokerConfirmationRequiredError(BrokerSecurityError):
    """Raised when Trusted Confirmation is required but missing for Step B authorization."""

    def __init__(self, message: str, code: int = -32022, data: dict[str, Any] | None = None) -> None:
        super().__init__(message, code=code, data=data)


class BrokerConfirmationError(BrokerSecurityError):
    """Raised when Trusted Confirmation proof verification, binding, or consumption fails."""

    def __init__(self, message: str, code: int = -32023, data: dict[str, Any] | None = None) -> None:
        super().__init__(message, code=code, data=data)

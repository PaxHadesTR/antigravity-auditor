"""Windows Service Host Abstraction for Antigravity Auditor Broker.

Architectural Purpose:
Encapsulates the lifecycle, configuration, and security boundary of the Broker process
as designed for execution under a dedicated virtual service account (NT SERVICE\\AntigravityAuditorBroker).

GOVERNANCE CONTRACT:
This module provides the service host runtime abstraction and state machine.
In subphase NEXT-21C-A, live registration/installation into the Windows Service Control Manager
(SCM) via `sc create` or registry modification is strictly PROHIBITED.
"""

from __future__ import annotations

import enum
import logging
import os
import threading
from pathlib import Path
from typing import Any

from broker.audit_logger import BrokerAuditLogger
from broker.cbeat import CbeatVerifier
from broker.cng import (
    MS_PLATFORM_CRYPTO_PROVIDER,
    CngCbeatSigner,
    build_key_dacl_sddl,
    probe_cng_provider,
    probe_tpm_device,
    validate_test_key_name,
)
from broker.constants import (
    B4A_TEST_PIPE_NAME,
    B4A_TEST_SERVICE_ACCOUNT,
    B4A_TEST_SERVICE_DISPLAY_NAME,
    B4A_TEST_SERVICE_NAME,
    B4A_TEST_SERVICE_SID,
    B4B_TEST_PIPE_PREFIX,
    B4B_TEST_SERVICE_DISPLAY_PREFIX,
    B4B_TEST_SERVICE_PREFIX,
    DEFAULT_MAX_CONCURRENT_CLIENTS,
    DEFAULT_PIPE_NAME,
    DEFAULT_PIPE_SDDL,
    PRODUCTION_SERVICE_NAME,
    SERVICE_MODE_B4A_QUALIFICATION,
    SERVICE_MODE_B4B_GOVERNANCE_TEST,
    SERVICE_MODE_STANDARD,
)
from broker.db_adapter import BrokerDatabaseAdapter
from broker.dispatcher import BrokerDispatcher
from broker.exceptions import BrokerError, BrokerSecurityError, ProductionDatabaseAccessProhibitedError
from broker.security import (
    build_restricted_pipe_sddl,
    compute_service_sid_from_name,
    get_current_user_sid,
    is_windows,
)
from broker.tcb import TcbPolicy, TcbTrustedAuthenticator, TcbVerifier
from broker.transport import BasePipeServer, MemoryPipeTransport, WindowsNamedPipeServer

logger = logging.getLogger(__name__)


class ServiceState(enum.Enum):
    """Lifecycle states of the Broker Service Host."""

    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    ERROR = "ERROR"


class BrokerServiceConfig:
    """Configuration container for Broker Service Host."""

    SERVICE_NAME = PRODUCTION_SERVICE_NAME
    SERVICE_DISPLAY_NAME = "Antigravity Auditor Broker Service"
    SERVICE_ACCOUNT = rf"NT SERVICE\{PRODUCTION_SERVICE_NAME}"

    def __init__(
        self,
        db_path: str | Path | None = None,
        pipe_name: str = DEFAULT_PIPE_NAME,
        sddl: str = DEFAULT_PIPE_SDDL,
        max_clients: int = DEFAULT_MAX_CONCURRENT_CLIENTS,
        log_file: str | Path | None = None,
        use_memory_transport: bool = False,
        *,
        service_name: str = SERVICE_NAME,
        service_display_name: str = SERVICE_DISPLAY_NAME,
        service_account: str = SERVICE_ACCOUNT,
        qualification_only: bool = False,
        allowed_client_sids: list[str] | set[str] | frozenset[str] | None = None,
        require_existing_db_dir: bool = False,
        require_existing_db: bool = False,
        service_mode: str = SERVICE_MODE_STANDARD,
        cng_key_name: str | None = None,
        cng_provider: str | None = None,
        cng_key_sddl: str | None = None,
        require_cng: bool = False,
        require_tpm: bool = False,
        allow_software_ksp: bool = False,
        require_tcb: bool = False,
        tcb_verifier: TcbVerifier | None = None,
        tcb_trusted_authenticators: dict[str, TcbTrustedAuthenticator] | None = None,
        allow_execution_dispatch: bool = False,
    ) -> None:
        self.db_path = db_path
        self.pipe_name = pipe_name
        self.sddl = sddl
        self.max_clients = max_clients
        self.log_file = log_file
        self.use_memory_transport = use_memory_transport
        self.service_name = service_name
        self.service_display_name = service_display_name
        self.service_account = service_account
        self.qualification_only = qualification_only
        self.allowed_client_sids = (
            frozenset(allowed_client_sids) if allowed_client_sids is not None else None
        )
        self.require_existing_db_dir = require_existing_db_dir
        self.require_existing_db = require_existing_db
        self.service_mode = (
            SERVICE_MODE_B4A_QUALIFICATION if qualification_only else service_mode
        )
        self.cng_key_name = cng_key_name
        self.cng_provider = cng_provider
        self.cng_key_sddl = cng_key_sddl
        self.require_cng = False if qualification_only else bool(require_cng)
        self.require_tpm = False if qualification_only else bool(require_tpm)
        self.allow_software_ksp = bool(allow_software_ksp)
        self.require_tcb = False if qualification_only else bool(require_tcb)
        self.tcb_verifier = tcb_verifier
        self.tcb_trusted_authenticators = dict(tcb_trusted_authenticators or {})
        self.allow_execution_dispatch = False if qualification_only else bool(allow_execution_dispatch)

    @classmethod
    def b4a_test_config(
        cls,
        *,
        db_path: str | Path,
        allowed_client_sids: list[str] | set[str] | frozenset[str] | None = None,
        pipe_name: str = B4A_TEST_PIPE_NAME,
        log_file: str | Path | None = None,
        max_clients: int = DEFAULT_MAX_CONCURRENT_CLIENTS,
        use_memory_transport: bool = False,
        require_existing_db_dir: bool = True,
        require_existing_db: bool = False,
        include_current_user: bool = True,
    ) -> "BrokerServiceConfig":
        """Build a hardened B4-A qualification-only test service configuration.

        Never targets the production service identity, production pipe, or permissive SDDL.
        """
        if pipe_name == DEFAULT_PIPE_NAME:
            raise BrokerError("B4-A test config cannot bind to production pipe name.")

        if allowed_client_sids is not None:
            effective_sids = [s for s in allowed_client_sids if s]
        elif include_current_user:
            effective_sids = [get_current_user_sid()]
        else:
            effective_sids = []

        restricted_sddl = build_restricted_pipe_sddl(
            allowed_sids=effective_sids,
            include_service_sid=B4A_TEST_SERVICE_SID,
        )
        return cls(
            db_path=db_path,
            pipe_name=pipe_name,
            sddl=restricted_sddl,
            max_clients=max_clients,
            log_file=log_file,
            use_memory_transport=use_memory_transport,
            service_name=B4A_TEST_SERVICE_NAME,
            service_display_name=B4A_TEST_SERVICE_DISPLAY_NAME,
            service_account=B4A_TEST_SERVICE_ACCOUNT,
            qualification_only=True,
            allowed_client_sids=effective_sids if allowed_client_sids is not None else None,
            require_existing_db_dir=require_existing_db_dir,
            require_existing_db=require_existing_db,
        )

    @classmethod
    def b4b_test_governance_config(
        cls,
        *,
        service_name: str,
        pipe_name: str,
        db_path: str | Path,
        cng_key_name: str,
        cng_provider: str | None = None,
        require_cng: bool = True,
        require_tpm: bool = False,
        allow_software_ksp: bool = False,
        require_tcb: bool = True,
        tcb_verifier: TcbVerifier | None = None,
        tcb_trusted_authenticators: dict[str, TcbTrustedAuthenticator] | None = None,
        allowed_client_sids: list[str] | set[str] | frozenset[str] | None = None,
        log_file: str | Path | None = None,
        max_clients: int = DEFAULT_MAX_CONCURRENT_CLIENTS,
        use_memory_transport: bool = False,
        require_existing_db_dir: bool = True,
        require_existing_db: bool = False,
        include_current_user: bool = True,
    ) -> "BrokerServiceConfig":
        """Build an isolated B4-B non-production Governance Test service configuration."""
        if (
            not service_name.startswith(B4B_TEST_SERVICE_PREFIX)
            or len(service_name) <= len(B4B_TEST_SERVICE_PREFIX)
            or service_name == PRODUCTION_SERVICE_NAME
        ):
            raise BrokerSecurityError(
                f"B4-B test governance service_name must have a non-empty suffix after '{B4B_TEST_SERVICE_PREFIX}', got '{service_name}'."
            )
        if (
            not pipe_name.startswith(B4B_TEST_PIPE_PREFIX)
            or len(pipe_name) <= len(B4B_TEST_PIPE_PREFIX)
            or pipe_name == DEFAULT_PIPE_NAME
        ):
            raise BrokerSecurityError(
                f"B4-B test governance pipe_name must have a non-empty suffix after '{B4B_TEST_PIPE_PREFIX}', got '{pipe_name}'."
            )
        validated_key = validate_test_key_name(cng_key_name)

        if allowed_client_sids is not None:
            effective_sids = [s for s in allowed_client_sids if s]
        elif include_current_user:
            effective_sids = [get_current_user_sid()]
        else:
            effective_sids = []

        # Include virtual service SID so Service Host and admins/allowed operators are covered
        service_sid_str: str | None = compute_service_sid_from_name(service_name) if is_windows() else None
        key_sddl = build_key_dacl_sddl([service_sid_str]) if service_sid_str else build_key_dacl_sddl(None)

        restricted_sddl = build_restricted_pipe_sddl(
            allowed_sids=effective_sids,
            include_service_sid=service_sid_str,
        )
        return cls(
            db_path=db_path,
            pipe_name=pipe_name,
            sddl=restricted_sddl,
            max_clients=max_clients,
            log_file=log_file,
            use_memory_transport=use_memory_transport,
            service_name=service_name,
            service_display_name=f"{B4B_TEST_SERVICE_DISPLAY_PREFIX} ({service_name})",
            service_account=rf"NT SERVICE\{service_name}",
            qualification_only=False,
            allowed_client_sids=effective_sids if allowed_client_sids is not None else None,
            require_existing_db_dir=require_existing_db_dir,
            require_existing_db=require_existing_db,
            service_mode=SERVICE_MODE_B4B_GOVERNANCE_TEST,
            cng_key_name=validated_key,
            cng_provider=cng_provider or (MS_PLATFORM_CRYPTO_PROVIDER if require_tpm else None),
            cng_key_sddl=key_sddl,
            require_cng=require_cng,
            require_tpm=require_tpm,
            allow_software_ksp=allow_software_ksp,
            require_tcb=require_tcb,
            tcb_verifier=tcb_verifier,
            tcb_trusted_authenticators=tcb_trusted_authenticators,
            allow_execution_dispatch=False,
        )


class BrokerServiceHost:
    """Service host runtime managing the broker's lifecycle, database adapter, and IPC transport."""

    def __init__(self, config: BrokerServiceConfig | None = None) -> None:
        self.config = config or BrokerServiceConfig()
        self._state = ServiceState.STOPPED
        self._lock = threading.Lock()
        self.server_startup_error: str | None = None

        # Components (initialized in start)
        self.audit_logger: BrokerAuditLogger | None = None
        self.db_adapter: BrokerDatabaseAdapter | None = None
        self.signer: CngCbeatSigner | None = None
        self.cbeat_verifier: CbeatVerifier | None = None
        self.tcb_verifier: TcbVerifier | None = None
        self.dispatcher: BrokerDispatcher | None = None
        self.server: BasePipeServer | None = None
        self.memory_transport: MemoryPipeTransport | None = None

    @property
    def state(self) -> ServiceState:
        return self._state

    def _validate_config(self) -> None:
        """Fail closed if B4-A/B4-B non-production hosts collide with production names."""
        if self.config.qualification_only:
            if self.config.service_name == PRODUCTION_SERVICE_NAME:
                raise BrokerError("Qualification host cannot use production service name.")
            if self.config.pipe_name == DEFAULT_PIPE_NAME:
                raise BrokerError("Qualification host cannot bind production pipe name.")
        if self.config.service_mode == SERVICE_MODE_B4B_GOVERNANCE_TEST:
            if not self.config.service_name.startswith(B4B_TEST_SERVICE_PREFIX) or self.config.service_name == PRODUCTION_SERVICE_NAME:
                raise BrokerSecurityError("B4-B Governance host must use isolated B4B_TEST_SERVICE_PREFIX.")
            if not self.config.pipe_name.startswith(B4B_TEST_PIPE_PREFIX) or self.config.pipe_name == DEFAULT_PIPE_NAME:
                raise BrokerSecurityError("B4-B Governance host must use isolated B4B_TEST_PIPE_PREFIX.")
            if self.config.allow_execution_dispatch:
                raise BrokerSecurityError("allow_execution_dispatch must remain False in NEXT-21C-B4-B Option A.")

    def start(self) -> None:
        """Initialize components in strict dependency order and start listening for IPC."""
        with self._lock:
            if self._state != ServiceState.STOPPED:
                raise BrokerError(f"Cannot start service host in state {self._state.value}")

            self._state = ServiceState.STARTING
            self.server_startup_error = None

        try:
            # 1. Validate configuration
            self._validate_config()

            # 2. Initialize Audit Logger
            self.audit_logger = BrokerAuditLogger(log_file=self.config.log_file)

            # 3. Initialize Database Adapter and verify ping() before exposing IPC pipe
            self.db_adapter = BrokerDatabaseAdapter(
                db_path=self.config.db_path,
                require_existing_dir=self.config.require_existing_db_dir,
                require_existing_db=self.config.require_existing_db,
            )
            if not self.db_adapter.ping():
                raise BrokerError("Database health ping failed during service startup.")

            # 4. Initialize CNG/TPM key custody and TCB verifier when configured
            signer = None
            cbeat_verifier = None
            if not self.config.qualification_only and (self.config.cng_key_name or self.config.require_cng):
                if not self.config.cng_key_name:
                    raise BrokerSecurityError("require_cng=True requires an explicit cng_key_name.")
                signer = CngCbeatSigner(
                    self.config.cng_key_name,
                    provider_name=self.config.cng_provider,
                    require_tpm=self.config.require_tpm,
                    allow_software_ksp=self.config.allow_software_ksp,
                    key_sddl=self.config.cng_key_sddl,
                )
                self.signer = signer
                cbeat_verifier = CbeatVerifier(
                    trusted_public_keys=signer.trusted_public_keys,
                    require_cng=self.config.require_cng,
                )
                self.cbeat_verifier = cbeat_verifier

            tcb_verifier = self.config.tcb_verifier
            if tcb_verifier is None and (self.config.require_tcb or self.config.tcb_trusted_authenticators):
                tcb_verifier = TcbVerifier(
                    policy=TcbPolicy(require_tcb=self.config.require_tcb),
                    trusted_authenticators=self.config.tcb_trusted_authenticators,
                )
            self.tcb_verifier = tcb_verifier

            # 5. Initialize Dispatcher
            self.dispatcher = BrokerDispatcher(
                db_adapter=self.db_adapter,
                audit_logger=self.audit_logger,
                signer=signer,
                verifier=cbeat_verifier,
                allow_execution_dispatch=self.config.allow_execution_dispatch,
                qualification_only=self.config.qualification_only,
                allowed_client_sids=self.config.allowed_client_sids,
                service_identity=self.config.service_name,
                service_mode=self.config.service_mode,
                tcb_verifier=tcb_verifier,
                require_tcb=self.config.require_tcb,
                require_cng=self.config.require_cng,
            )

            # 6. Initialize Transport Server and confirm listening before RUNNING
            if self.config.use_memory_transport or not is_windows():
                self.memory_transport = MemoryPipeTransport(dispatcher=self.dispatcher)
            else:
                self.server = WindowsNamedPipeServer(
                    dispatcher=self.dispatcher,
                    pipe_name=self.config.pipe_name,
                    sddl=self.config.sddl,
                    max_instances=self.config.max_clients,
                )
                self.server.start()
                if not self.server.is_alive():
                    raise BrokerError("Named Pipe server did not enter listening state.")

            with self._lock:
                self._state = ServiceState.RUNNING

            logger.info("BrokerServiceHost started successfully in state %s", self._state.value)
        except Exception as exc:
            self.server_startup_error = str(exc)
            with self._lock:
                self._state = ServiceState.ERROR
            self._cleanup_resources()
            raise BrokerError(f"Failed to start BrokerServiceHost: {exc}") from exc

    def _cleanup_resources(self) -> None:
        """Internal helper to clean up server, signer, and DB adapter handles."""
        if self.server is not None:
            try:
                self.server.stop()
            except Exception:
                pass
            self.server = None

        if self.signer is not None:
            try:
                self.signer.close()
            except Exception:
                pass
            self.signer = None

        if self.db_adapter is not None:
            try:
                self.db_adapter.close()
            except Exception:
                pass
            self.db_adapter = None

    def stop(self) -> None:
        """Signal transport server to stop, close database connections, and flush logs."""
        with self._lock:
            if self._state == ServiceState.STOPPED:
                return
            prev_state = self._state
            self._state = ServiceState.STOPPING

        try:
            self._cleanup_resources()

            with self._lock:
                self._state = ServiceState.STOPPED

            logger.info("BrokerServiceHost stopped cleanly (was %s).", prev_state.value)
        except Exception as exc:
            with self._lock:
                self._state = ServiceState.ERROR
            logger.error("Error during BrokerServiceHost shutdown: %s", exc)
            raise

    def get_status(self) -> dict[str, Any]:
        """Return diagnostic dictionary of the service host state."""
        return {
            "state": self._state.value,
            "service_name": self.config.service_name,
            "service_account": self.config.service_account,
            "qualification_only": self.config.qualification_only,
            "pipe_name": self.config.pipe_name,
            "use_memory_transport": self.config.use_memory_transport,
            "db_initialized": self.db_adapter is not None,
            "server_alive": self.server.is_alive() if self.server else False,
            "server_startup_error": self.server_startup_error,
        }

"""Native Windows Service Control Manager (SCM) Host Dispatcher for Antigravity Auditor Broker.

Implements the native Win32 ServiceMain / HandlerEx / SetServiceStatus contract using
ctypes and advapi32.dll (avoiding external pywin32 dependencies).
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import logging
from pathlib import Path
import threading
from typing import Any

from broker.constants import (
    B4A_TEST_PIPE_NAME,
    B4A_TEST_SERVICE_NAME,
    B4B_TEST_PIPE_PREFIX,
    B4B_TEST_SERVICE_PREFIX,
    PRODUCTION_SERVICE_NAME,
)
from broker.exceptions import BrokerError
from broker.security import is_windows
from broker.service_host import BrokerServiceConfig, BrokerServiceHost
from broker.tcb import TcbTrustedAuthenticator

logger = logging.getLogger(__name__)

# Win32 Service Constants
SERVICE_WIN32_OWN_PROCESS = 0x00000010

SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004

SERVICE_ACCEPT_STOP = 0x00000001
SERVICE_ACCEPT_SHUTDOWN = 0x00000004

SERVICE_CONTROL_STOP = 0x00000001
SERVICE_CONTROL_INTERROGATE = 0x00000004
SERVICE_CONTROL_SHUTDOWN = 0x00000005

NO_ERROR = 0
ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_EXCEPTION_IN_SERVICE = 1064
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063

_STATE_NAMES = {
    SERVICE_STOPPED: "SERVICE_STOPPED",
    SERVICE_START_PENDING: "SERVICE_START_PENDING",
    SERVICE_STOP_PENDING: "SERVICE_STOP_PENDING",
    SERVICE_RUNNING: "SERVICE_RUNNING",
}


class SERVICE_STATUS(ctypes.Structure):
    """Win32 SERVICE_STATUS structure."""

    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


LPSERVICE_MAIN_FUNCTIONW = ctypes.WINFUNCTYPE(
    None,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.LPWSTR),
)
LPHANDLER_FUNCTION_EX = ctypes.WINFUNCTYPE(
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
)


class SERVICE_TABLE_ENTRYW(ctypes.Structure):
    """Win32 SERVICE_TABLE_ENTRYW structure."""

    _fields_ = [
        ("lpServiceName", wintypes.LPWSTR),
        ("lpServiceProc", ctypes.c_void_p),
    ]


def _scm_advapi32() -> ctypes.WinDLL:
    """Return advapi32 WinDLL configured with explicit 64-bit SCM host prototypes."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
    adv.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRYW)]
    adv.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    adv.RegisterServiceCtrlHandlerExW.argtypes = [
        wintypes.LPCWSTR,
        LPHANDLER_FUNCTION_EX,
        ctypes.c_void_p,
    ]
    adv.SetServiceStatus.restype = wintypes.BOOL
    adv.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(SERVICE_STATUS)]
    return adv


class Win32SCMServiceController:
    """Bridges Win32 SCM control events to a BrokerServiceHost lifecycle."""

    def __init__(self, service_name: str, host: BrokerServiceHost) -> None:
        if not service_name or service_name == PRODUCTION_SERVICE_NAME:
            raise BrokerError(
                f"SCM host controller refuses non-B4A or production service name: {service_name!r}"
            )
        self.service_name = service_name
        self.host = host
        self._stop_event = threading.Event()
        self._status_handle: int | None = None
        self._advapi32: ctypes.WinDLL | None = None
        self._lock = threading.Lock()
        self.status_history: list[dict[str, Any]] = []
        self._handler_cb: Any = None
        self._service_main_cb: Any = None
        self.last_error: str | None = None

    def report_status(
        self,
        current_state: int,
        *,
        controls_accepted: int = 0,
        win32_exit_code: int = 0,
        service_specific_exit_code: int = 0,
        check_point: int = 0,
        wait_hint: int = 0,
    ) -> bool:
        """Record status transition and call SetServiceStatus when attached to SCM."""
        with self._lock:
            entry = {
                "state": current_state,
                "state_name": _STATE_NAMES.get(current_state, f"UNKNOWN_{current_state}"),
                "controls_accepted": controls_accepted,
                "win32_exit_code": win32_exit_code,
                "service_specific_exit_code": service_specific_exit_code,
                "check_point": check_point,
                "wait_hint": wait_hint,
            }
            self.status_history.append(entry)

            if self._status_handle and self._advapi32 is not None:
                status = SERVICE_STATUS(
                    dwServiceType=SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState=current_state,
                    dwControlsAccepted=controls_accepted,
                    dwWin32ExitCode=win32_exit_code,
                    dwServiceSpecificExitCode=service_specific_exit_code,
                    dwCheckPoint=check_point,
                    dwWaitHint=wait_hint,
                )
                return bool(self._advapi32.SetServiceStatus(self._status_handle, ctypes.byref(status)))
            return True

    def handle_control(
        self,
        dw_control: int,
        dw_event_type: int = 0,
        lp_event_data: Any = None,
        lp_context: Any = None,
    ) -> int:
        """Process SCM control code (STOP / SHUTDOWN / INTERROGATE)."""
        if dw_control in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN):
            self.report_status(
                SERVICE_STOP_PENDING,
                controls_accepted=0,
                check_point=1,
                wait_hint=5000,
            )
            self._stop_event.set()
            return NO_ERROR
        if dw_control == SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR
        return ERROR_CALL_NOT_IMPLEMENTED

    def request_stop(self) -> None:
        """Programmatically request service stop (used by tests or local shutdown)."""
        self.handle_control(SERVICE_CONTROL_STOP)

    def execute_service_lifecycle(self, *, wait_for_stop: bool = True) -> None:
        """Run the deterministic SCM START_PENDING -> RUNNING -> STOP_PENDING -> STOPPED sequence."""
        self.report_status(SERVICE_START_PENDING, controls_accepted=0, check_point=1, wait_hint=10000)

        try:
            self.host.start()
        except Exception as exc:
            self.last_error = str(exc)
            self.report_status(
                SERVICE_STOPPED,
                controls_accepted=0,
                win32_exit_code=ERROR_EXCEPTION_IN_SERVICE,
                service_specific_exit_code=1,
                check_point=0,
                wait_hint=0,
            )
            raise

        self.report_status(
            SERVICE_RUNNING,
            controls_accepted=SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            win32_exit_code=0,
            check_point=0,
            wait_hint=0,
        )

        if wait_for_stop:
            self._stop_event.wait()

        # Ensure STOP_PENDING is reported even if shutdown triggered programmatically
        if not any(item["state"] == SERVICE_STOP_PENDING for item in self.status_history):
            self.report_status(SERVICE_STOP_PENDING, controls_accepted=0, check_point=1, wait_hint=5000)

        stop_exit_code = 0
        try:
            self.host.stop()
        except Exception as exc:
            self.last_error = str(exc)
            stop_exit_code = ERROR_EXCEPTION_IN_SERVICE
        finally:
            self.report_status(
                SERVICE_STOPPED,
                controls_accepted=0,
                win32_exit_code=stop_exit_code,
                check_point=0,
                wait_hint=0,
            )

    def _service_main(self, argc: int, argv: Any) -> None:
        """Win32 ServiceMain callback executed inside SCM dispatcher thread."""
        advapi32 = self._advapi32 or _scm_advapi32()
        self._advapi32 = advapi32

        self._handler_cb = LPHANDLER_FUNCTION_EX(self.handle_control)
        h_status = advapi32.RegisterServiceCtrlHandlerExW(
            self.service_name,
            self._handler_cb,
            None,
        )
        if not h_status:
            err = ctypes.get_last_error()
            self.last_error = f"RegisterServiceCtrlHandlerExW failed (Win32 Error {err})"
            return

        self._status_handle = h_status
        try:
            self.execute_service_lifecycle(wait_for_stop=True)
        except Exception as exc:
            logger.exception("Unhandled error in Win32 ServiceMain: %s", exc)

    def run_scm_dispatcher(self) -> None:
        """Connect process to Windows Service Control Manager via StartServiceCtrlDispatcherW."""
        if not is_windows():
            raise RuntimeError("Win32 SCM dispatcher is only supported on Windows.")

        advapi32 = _scm_advapi32()
        self._advapi32 = advapi32
        self._service_main_cb = LPSERVICE_MAIN_FUNCTIONW(self._service_main)
        proc_ptr = ctypes.cast(self._service_main_cb, ctypes.c_void_p).value

        table = (SERVICE_TABLE_ENTRYW * 2)()
        table[0].lpServiceName = self.service_name
        table[0].lpServiceProc = proc_ptr
        table[1].lpServiceName = None
        table[1].lpServiceProc = None

        ok = advapi32.StartServiceCtrlDispatcherW(table)
        if not ok:
            err = ctypes.get_last_error()
            raise ctypes.WinError(err)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint invoked by Windows SCM for isolated B4-A or B4-B test services."""
    parser = argparse.ArgumentParser(description="Antigravity Auditor Test SCM Service Host")
    parser.add_argument(
        "--mode",
        choices=("b4a-qualification", "b4b-test-governance"),
        default="b4a-qualification",
    )
    parser.add_argument("--service-name", default=B4A_TEST_SERVICE_NAME)
    parser.add_argument("--db-path", required=True)
    parser.add_argument("--pipe-name", default=B4A_TEST_PIPE_NAME)
    parser.add_argument("--allowed-sid", action="append", dest="allowed_sids", default=None)
    parser.add_argument("--log-file", default=None)
    parser.add_argument("--cng-key-name", default=None)
    parser.add_argument("--cng-provider", default=None)
    parser.add_argument("--require-cng", action="store_true", default=False)
    parser.add_argument("--require-tpm", action="store_true", default=False)
    parser.add_argument("--allow-software-ksp", action="store_true", default=False)
    parser.add_argument("--require-tcb", action="store_true", default=False)
    parser.add_argument("--tcb-public-keys-file", default=None)
    args = parser.parse_args(argv)

    if args.service_name == PRODUCTION_SERVICE_NAME:
        raise BrokerError(f"Refusing to run SCM host for production service '{PRODUCTION_SERVICE_NAME}'.")

    if args.mode == "b4a-qualification":
        if args.service_name != B4A_TEST_SERVICE_NAME:
            raise BrokerError(
                f"Refusing to run SCM host for non-B4A service '{args.service_name}'. "
                f"Only '{B4A_TEST_SERVICE_NAME}' is authorized."
            )

        config = BrokerServiceConfig.b4a_test_config(
            db_path=Path(args.db_path),
            allowed_client_sids=args.allowed_sids,
            pipe_name=args.pipe_name,
            log_file=Path(args.log_file) if args.log_file else None,
            require_existing_db_dir=True,
            require_existing_db=False,
        )
    else:
        if not args.service_name.startswith(B4B_TEST_SERVICE_PREFIX) or len(args.service_name) <= len(B4B_TEST_SERVICE_PREFIX):
            raise BrokerError(
                f"B4-B governance SCM host requires service_name with non-empty suffix after '{B4B_TEST_SERVICE_PREFIX}', "
                f"got '{args.service_name}'."
            )
        if not args.pipe_name.startswith(B4B_TEST_PIPE_PREFIX) or len(args.pipe_name) <= len(B4B_TEST_PIPE_PREFIX):
            raise BrokerError(
                f"B4-B governance SCM host requires pipe_name with non-empty suffix after '{B4B_TEST_PIPE_PREFIX}', "
                f"got '{args.pipe_name}'."
            )
        if not args.cng_key_name:
            raise BrokerError("B4-B governance SCM host requires --cng-key-name.")

        trusted_auths: dict[str, TcbTrustedAuthenticator] = {}
        if args.tcb_public_keys_file:
            raw_map = json.loads(Path(args.tcb_public_keys_file).read_text(encoding="utf-8"))
            if isinstance(raw_map, dict):
                for cred_id, pk_hex in raw_map.items():
                    trusted_auths[str(cred_id)] = TcbTrustedAuthenticator.from_public_key(
                        credential_id=str(cred_id),
                        public_key_bytes=bytes.fromhex(str(pk_hex)),
                    )

        config = BrokerServiceConfig.b4b_test_governance_config(
            service_name=args.service_name,
            pipe_name=args.pipe_name,
            db_path=Path(args.db_path),
            cng_key_name=args.cng_key_name,
            cng_provider=args.cng_provider,
            require_cng=bool(args.require_cng or True),
            require_tpm=bool(args.require_tpm),
            allow_software_ksp=bool(args.allow_software_ksp),
            require_tcb=bool(args.require_tcb),
            tcb_trusted_authenticators=trusted_auths,
            allowed_client_sids=args.allowed_sids,
            log_file=Path(args.log_file) if args.log_file else None,
            require_existing_db_dir=True,
            require_existing_db=False,
        )

    host = BrokerServiceHost(config=config)
    controller = Win32SCMServiceController(service_name=args.service_name, host=host)
    controller.run_scm_dispatcher()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

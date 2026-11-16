"""Dedicated Test-Only Windows Service Installer & Guarded Cleanup for NEXT-21C-B4-A.

Strictly bound to `AntigravityAuditorBrokerB4ATest`. Never registers, queries for mutation,
starts, stops, or deletes the production `AntigravityAuditorBroker` service.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import time
from typing import Any

from broker.constants import (
    B4A_TEST_SERVICE_ACCOUNT,
    B4A_TEST_SERVICE_DISPLAY_NAME,
    B4A_TEST_SERVICE_NAME,
    B4A_TEST_SERVICE_SID,
    B4B_TEST_SERVICE_DISPLAY_PREFIX,
    B4B_TEST_SERVICE_PREFIX,
    PRODUCTION_SERVICE_NAME,
    SERVICE_CONFIG_SERVICE_SID_INFO,
    SERVICE_SID_TYPE_NONE,
    SERVICE_SID_TYPE_RESTRICTED,
    SERVICE_SID_TYPE_UNRESTRICTED,
)
from broker.exceptions import BrokerError, BrokerSecurityError
from broker.security import compute_service_sid_from_name, is_windows

# SCM Access Masks
SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_CREATE_SERVICE = 0x0002
SC_MANAGER_ENUMERATE_SERVICE = 0x0004

SERVICE_QUERY_CONFIG = 0x0001
SERVICE_CHANGE_CONFIG = 0x0002
SERVICE_QUERY_STATUS = 0x0004
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
DELETE = 0x00010000
SERVICE_ALL_ACCESS = 0xF01FF

# Service Creation Flags
SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_DEMAND_START = 0x00000003
SERVICE_ERROR_NORMAL = 0x00000001

# Control & Status Constants
SERVICE_CONTROL_STOP = 0x00000001
SC_STATUS_PROCESS_INFO = 0

SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004

# Common Win32 Error Codes
ERROR_ACCESS_DENIED = 5
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_NOT_ACTIVE = 1062
ERROR_SERVICE_EXISTS = 1073

_SERVICE_STATE_NAMES = {
    SERVICE_STOPPED: "STOPPED",
    SERVICE_START_PENDING: "START_PENDING",
    SERVICE_STOP_PENDING: "STOP_PENDING",
    SERVICE_RUNNING: "RUNNING",
}


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    """Win32 SERVICE_STATUS_PROCESS structure."""

    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    ]


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


class QUERY_SERVICE_CONFIGW(ctypes.Structure):
    """Win32 QUERY_SERVICE_CONFIGW structure."""

    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwStartType", wintypes.DWORD),
        ("dwErrorControl", wintypes.DWORD),
        ("lpBinaryPathName", wintypes.LPWSTR),
        ("lpLoadOrderGroup", wintypes.LPWSTR),
        ("dwTagId", wintypes.DWORD),
        ("lpDependencies", wintypes.LPWSTR),
        ("lpServiceStartName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
    ]


class SERVICE_SID_INFO(ctypes.Structure):
    """Win32 SERVICE_SID_INFO structure for ChangeServiceConfig2W."""

    _fields_ = [("dwServiceSidType", wintypes.DWORD)]


def _scm_installer_advapi32() -> ctypes.WinDLL:
    """Return advapi32 WinDLL with explicit 64-bit SC_HANDLE prototypes."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.OpenSCManagerW.restype = wintypes.HANDLE
    adv.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]

    adv.OpenServiceW.restype = wintypes.HANDLE
    adv.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]

    adv.CreateServiceW.restype = wintypes.HANDLE
    adv.CreateServiceW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
    ]

    adv.ChangeServiceConfig2W.restype = wintypes.BOOL
    adv.ChangeServiceConfig2W.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]

    adv.QueryServiceStatusEx.restype = wintypes.BOOL
    adv.QueryServiceStatusEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]

    adv.QueryServiceConfigW.restype = wintypes.BOOL
    adv.QueryServiceConfigW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]

    adv.StartServiceW.restype = wintypes.BOOL
    adv.StartServiceW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]

    adv.ControlService.restype = wintypes.BOOL
    adv.ControlService.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(SERVICE_STATUS)]

    adv.DeleteService.restype = wintypes.BOOL
    adv.DeleteService.argtypes = [wintypes.HANDLE]

    adv.CloseServiceHandle.restype = wintypes.BOOL
    adv.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    return adv


class B4ATestServiceManager:
    """Manages lifecycle of ONLY the disposable B4-A test service in Windows SCM."""

    def __init__(self, service_name: str = B4A_TEST_SERVICE_NAME, *, _allow_b4b: bool = False) -> None:
        if service_name == PRODUCTION_SERVICE_NAME:
            raise BrokerSecurityError(
                f"Refused service target '{service_name}'. "
                "Test installer never manages the production service."
            )
        if not _allow_b4b and service_name != B4A_TEST_SERVICE_NAME:
            raise BrokerSecurityError(
                f"Refused service target '{service_name}'. "
                f"B4-A installer only manages '{B4A_TEST_SERVICE_NAME}'."
            )
        self.service_name = service_name
        self.display_name = (
            B4A_TEST_SERVICE_DISPLAY_NAME
            if service_name == B4A_TEST_SERVICE_NAME
            else f"{B4B_TEST_SERVICE_DISPLAY_PREFIX} ({service_name})"
        )
        self.expected_account = rf"NT SERVICE\{service_name}"
        self.expected_sid = compute_service_sid_from_name(service_name)

    @staticmethod
    def query_named_service_status(target_service: str) -> dict[str, Any]:
        """Read-only status check for *target_service* using SC_MANAGER_CONNECT."""
        if not is_windows():
            return {"supported": False, "service_name": target_service}

        adv = _scm_installer_advapi32()
        h_scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if not h_scm:
            err = ctypes.get_last_error()
            return {
                "service_name": target_service,
                "exists": None,
                "win32_error": int(err),
                "stage": "OpenSCManagerW(SC_MANAGER_CONNECT)",
            }

        try:
            h_svc = adv.OpenServiceW(h_scm, target_service, SERVICE_QUERY_STATUS)
            if not h_svc:
                err = ctypes.get_last_error()
                return {
                    "service_name": target_service,
                    "exists": False if err == ERROR_SERVICE_DOES_NOT_EXIST else None,
                    "win32_error": int(err),
                    "stage": "OpenServiceW(SERVICE_QUERY_STATUS)",
                }
            try:
                ssp = SERVICE_STATUS_PROCESS()
                needed = wintypes.DWORD(0)
                ok = adv.QueryServiceStatusEx(
                    h_svc,
                    SC_STATUS_PROCESS_INFO,
                    ctypes.byref(ssp),
                    ctypes.sizeof(ssp),
                    ctypes.byref(needed),
                )
                if not ok:
                    err = ctypes.get_last_error()
                    return {
                        "service_name": target_service,
                        "exists": True,
                        "win32_error": int(err),
                        "stage": "QueryServiceStatusEx",
                    }
                return {
                    "service_name": target_service,
                    "exists": True,
                    "win32_error": 0,
                    "state_code": int(ssp.dwCurrentState),
                    "state": _SERVICE_STATE_NAMES.get(int(ssp.dwCurrentState), f"UNKNOWN_{ssp.dwCurrentState}"),
                    "pid": int(ssp.dwProcessId),
                    "win32_exit_code": int(ssp.dwWin32ExitCode),
                }
            finally:
                adv.CloseServiceHandle(h_svc)
        finally:
            adv.CloseServiceHandle(h_scm)

    def query_service_status(self) -> dict[str, Any]:
        """Query the B4-A test service status without altering SCM state."""
        return self.query_named_service_status(self.service_name)

    def query_service_config(self) -> dict[str, Any]:
        """Query installed configuration for B4-A test service."""
        if not is_windows():
            return {"supported": False, "service_name": self.service_name}

        adv = _scm_installer_advapi32()
        h_scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if not h_scm:
            err = ctypes.get_last_error()
            return {"service_name": self.service_name, "exists": None, "win32_error": int(err)}

        try:
            h_svc = adv.OpenServiceW(h_scm, self.service_name, SERVICE_QUERY_CONFIG)
            if not h_svc:
                err = ctypes.get_last_error()
                return {
                    "service_name": self.service_name,
                    "exists": False if err == ERROR_SERVICE_DOES_NOT_EXIST else None,
                    "win32_error": int(err),
                }
            try:
                needed = wintypes.DWORD(0)
                adv.QueryServiceConfigW(h_svc, None, 0, ctypes.byref(needed))
                err = ctypes.get_last_error()
                if err != ERROR_INSUFFICIENT_BUFFER or needed.value == 0:
                    return {"service_name": self.service_name, "exists": True, "win32_error": int(err)}
                buf = ctypes.create_string_buffer(needed.value)
                ok = adv.QueryServiceConfigW(h_svc, buf, needed.value, ctypes.byref(needed))
                if not ok:
                    return {
                        "service_name": self.service_name,
                        "exists": True,
                        "win32_error": int(ctypes.get_last_error()),
                    }
                cfg = QUERY_SERVICE_CONFIGW.from_buffer(buf)
                return {
                    "service_name": self.service_name,
                    "exists": True,
                    "win32_error": 0,
                    "service_type": int(cfg.dwServiceType),
                    "start_type": int(cfg.dwStartType),
                    "binary_path_name": cfg.lpBinaryPathName,
                    "service_start_name": cfg.lpServiceStartName,
                    "display_name": cfg.lpDisplayName,
                }
            finally:
                adv.CloseServiceHandle(h_svc)
        finally:
            adv.CloseServiceHandle(h_scm)

    @staticmethod
    def probe_scm_create_access() -> dict[str, Any]:
        """Probe whether current token can open SCM with SC_MANAGER_CREATE_SERVICE (non-mutating)."""
        if not is_windows():
            return {"supported": False, "granted": False}
        adv = _scm_installer_advapi32()
        h_scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CREATE_SERVICE)
        if not h_scm:
            err = ctypes.get_last_error()
            return {
                "granted": False,
                "win32_error": int(err),
                "error_name": "ERROR_ACCESS_DENIED" if err == ERROR_ACCESS_DENIED else f"WIN32_{err}",
            }
        adv.CloseServiceHandle(h_scm)
        return {"granted": True, "win32_error": 0, "error_name": "NO_ERROR"}

    def verify_preflight_clean(self) -> dict[str, Any]:
        """Ensure neither production nor B4-A test service already exists before install."""
        prod = self.query_named_service_status(PRODUCTION_SERVICE_NAME)
        test = self.query_service_status()
        clean = (prod.get("exists") is False) and (test.get("exists") is False)
        return {
            "clean": clean,
            "production_service": prod,
            "test_service": test,
            "expected_test_service_sid": B4A_TEST_SERVICE_SID,
            "computed_test_service_sid": self.expected_sid,
        }

    def install_test_service(
        self,
        binary_command: str,
        *,
        sid_type: int = SERVICE_SID_TYPE_UNRESTRICTED,
    ) -> dict[str, Any]:
        """Register disposable B4-A test service under NT SERVICE\\AntigravityAuditorBrokerB4ATest."""
        if not is_windows():
            raise RuntimeError("Windows SCM service installation requires Windows.")
        if not binary_command or not binary_command.strip():
            raise ValueError("binary_command cannot be empty.")
        if sid_type not in (SERVICE_SID_TYPE_NONE, SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_SID_TYPE_RESTRICTED):
            raise ValueError(f"Unsupported SERVICE_SID_TYPE value: {sid_type}")

        preflight = self.verify_preflight_clean()
        if preflight["test_service"].get("exists"):
            raise BrokerError(f"Refusing install: '{self.service_name}' already exists in SCM.")

        adv = _scm_installer_advapi32()
        h_scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CREATE_SERVICE)
        if not h_scm:
            err = ctypes.get_last_error()
            raise PermissionError(err, f"OpenSCManagerW(SC_MANAGER_CREATE_SERVICE) failed with Win32 Error {err}")

        try:
            h_svc = adv.CreateServiceW(
                h_scm,
                self.service_name,
                self.display_name,
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                binary_command,
                None,
                None,
                None,
                self.expected_account,
                None,
            )
            if not h_svc:
                err = ctypes.get_last_error()
                raise OSError(err, f"CreateServiceW failed with Win32 Error {err}")

            try:
                sid_info = SERVICE_SID_INFO(dwServiceSidType=sid_type)
                ok_sid = adv.ChangeServiceConfig2W(
                    h_svc,
                    SERVICE_CONFIG_SERVICE_SID_INFO,
                    ctypes.byref(sid_info),
                )
                if not ok_sid:
                    err = ctypes.get_last_error()
                    raise OSError(err, f"ChangeServiceConfig2W(SERVICE_CONFIG_SERVICE_SID_INFO) failed: {err}")
            finally:
                adv.CloseServiceHandle(h_svc)
        finally:
            adv.CloseServiceHandle(h_scm)

        return {
            "installed": True,
            "service_name": self.service_name,
            "service_account": self.expected_account,
            "service_sid": self.expected_sid,
            "sid_type": sid_type,
        }

    def start_test_service(self, *, timeout_seconds: float = 15.0) -> dict[str, Any]:
        """Start the registered B4-A test service via StartServiceW and wait for RUNNING."""
        if not is_windows():
            raise RuntimeError("Windows SCM requires Windows.")
        adv = _scm_installer_advapi32()
        h_scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if not h_scm:
            err = ctypes.get_last_error()
            raise PermissionError(err, f"OpenSCManagerW failed with Win32 Error {err}")
        try:
            h_svc = adv.OpenServiceW(h_scm, self.service_name, SERVICE_START | SERVICE_QUERY_STATUS)
            if not h_svc:
                err = ctypes.get_last_error()
                raise OSError(err, f"OpenServiceW failed with Win32 Error {err}")
            try:
                if not adv.StartServiceW(h_svc, 0, None):
                    err = ctypes.get_last_error()
                    raise OSError(err, f"StartServiceW failed with Win32 Error {err}")
            finally:
                adv.CloseServiceHandle(h_svc)
        finally:
            adv.CloseServiceHandle(h_scm)

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            st = self.query_service_status()
            if st.get("state_code") == SERVICE_RUNNING:
                return st
            if st.get("state_code") == SERVICE_STOPPED:
                raise BrokerError(f"Test service stopped unexpectedly during startup: {st}")
            time.sleep(0.2)
        raise TimeoutError(f"Timed out waiting for '{self.service_name}' to enter SERVICE_RUNNING.")

    def stop_test_service(self, *, timeout_seconds: float = 15.0) -> dict[str, Any]:
        """Stop the B4-A test service cleanly via ControlService(SERVICE_CONTROL_STOP)."""
        if not is_windows():
            raise RuntimeError("Windows SCM requires Windows.")
        adv = _scm_installer_advapi32()
        h_scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if not h_scm:
            err = ctypes.get_last_error()
            raise PermissionError(err, f"OpenSCManagerW failed with Win32 Error {err}")
        try:
            h_svc = adv.OpenServiceW(h_scm, self.service_name, SERVICE_STOP | SERVICE_QUERY_STATUS)
            if not h_svc:
                err = ctypes.get_last_error()
                raise OSError(err, f"OpenServiceW failed with Win32 Error {err}")
            try:
                svc_status = SERVICE_STATUS()
                if not adv.ControlService(h_svc, SERVICE_CONTROL_STOP, ctypes.byref(svc_status)):
                    err = ctypes.get_last_error()
                    if err != ERROR_SERVICE_NOT_ACTIVE:
                        raise OSError(err, f"ControlService(STOP) failed with Win32 Error {err}")
            finally:
                adv.CloseServiceHandle(h_svc)
        finally:
            adv.CloseServiceHandle(h_scm)

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            st = self.query_service_status()
            if st.get("state_code") == SERVICE_STOPPED:
                return st
            time.sleep(0.2)
        raise TimeoutError(f"Timed out waiting for '{self.service_name}' to enter SERVICE_STOPPED.")

    def delete_test_service(self, *, expected_binary_substring: str | None = None) -> dict[str, Any]:
        """Verify config identity matches B4-A test service before invoking DeleteService."""
        if not is_windows():
            raise RuntimeError("Windows SCM requires Windows.")

        cfg = self.query_service_config()
        if cfg.get("exists") is False:
            return {"deleted": False, "already_absent": True, "service_name": self.service_name}
        if not cfg.get("exists"):
            raise OSError(
                int(cfg.get("win32_error", 0)),
                f"Cannot verify service config before deletion: {cfg}",
            )

        acct = (cfg.get("service_start_name") or "").strip().lower()
        if acct != self.expected_account.lower():
            raise BrokerSecurityError(
                f"Config mismatch guard blocked DeleteService: account={cfg.get('service_start_name')!r}, "
                f"expected={self.expected_account!r}"
            )
        if expected_binary_substring:
            bpath = cfg.get("binary_path_name") or ""
            if expected_binary_substring.lower() not in bpath.lower():
                raise BrokerSecurityError(
                    f"Config mismatch guard blocked DeleteService: binary={bpath!r} "
                    f"missing {expected_binary_substring!r}"
                )

        # Ensure stopped before deletion if running
        st = self.query_service_status()
        if st.get("state_code") in (SERVICE_RUNNING, SERVICE_START_PENDING):
            self.stop_test_service()

        adv = _scm_installer_advapi32()
        h_scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if not h_scm:
            err = ctypes.get_last_error()
            raise PermissionError(err, f"OpenSCManagerW failed with Win32 Error {err}")
        try:
            h_svc = adv.OpenServiceW(h_scm, self.service_name, DELETE)
            if not h_svc:
                err = ctypes.get_last_error()
                raise OSError(err, f"OpenServiceW(DELETE) failed with Win32 Error {err}")
            try:
                if not adv.DeleteService(h_svc):
                    err = ctypes.get_last_error()
                    raise OSError(err, f"DeleteService failed with Win32 Error {err}")
            finally:
                adv.CloseServiceHandle(h_svc)
        finally:
            adv.CloseServiceHandle(h_scm)

        return {"deleted": True, "service_name": self.service_name}


class B4BTestServiceManager(B4ATestServiceManager):
    """Manages unique per-run disposable B4-B governance test services in Windows SCM.

    Enforces `B4B_TEST_SERVICE_PREFIX` (`AntigravityAuditorBrokerB4BTest_<id>`), preventing any
    collision with both `AntigravityAuditorBroker` (production) and `AntigravityAuditorBrokerB4ATest` (B4-A).
    """

    def __init__(self, service_name: str) -> None:
        if (
            not service_name
            or service_name == PRODUCTION_SERVICE_NAME
            or service_name == B4A_TEST_SERVICE_NAME
            or not service_name.startswith(B4B_TEST_SERVICE_PREFIX)
            or len(service_name) <= len(B4B_TEST_SERVICE_PREFIX)
        ):
            raise BrokerSecurityError(
                f"Refused service target '{service_name}'. "
                f"B4-B test installer requires prefix '{B4B_TEST_SERVICE_PREFIX}'."
            )
        super().__init__(service_name=service_name, _allow_b4b=True)

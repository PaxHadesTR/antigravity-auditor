"""Read-only Windows OS process & executable evidence observer for adapter telemetry."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import sys
from typing import Any, Protocol

from broker.security import (
    ClientIdentity,
    _query_token_integrity_level,
    _query_token_user_sid,
    _win32_advapi32,
    is_windows,
)
from runtime_discovery.windows_detection import (
    PROCESS_QUERY_LIMITED_INFORMATION,
    TH32CS_SNAPPROCESS,
    is_reparse_point,
    list_win32_processes,
)

from application_adapters.contracts import ProcessObservation, SignatureStatus

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_MAX_EXE_HASH_BYTES = 256 * 1024 * 1024  # 256 MiB bound


def filetime_100ns_to_iso(ticks_100ns: int | None) -> str | None:
    """Convert a Win32 FILETIME 64-bit 100ns integer to UTC ISO-8601."""
    if not ticks_100ns or ticks_100ns <= 0:
        return None
    dt = _FILETIME_EPOCH + timedelta(microseconds=ticks_100ns // 10)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_sid(sid: str | None) -> str | None:
    if not sid:
        return None
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()[:16]


def compute_safe_file_sha256(path: Path) -> tuple[str | None, str | None]:
    """Compute SHA-256 of a local regular file while refusing reparse points."""
    try:
        if is_reparse_point(path):
            return None, "REPARSE_POINT_BLOCKED"
        if not path.is_file():
            return None, "FILE_NOT_FOUND"
        size = os.lstat(path).st_size
        if size > _MAX_EXE_HASH_BYTES:
            return None, "FILE_TOO_LARGE_FOR_HASH"
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            while chunk := fh.read(65536):
                digest.update(chunk)
        return digest.hexdigest(), None
    except OSError as exc:
        return None, f"HASH_IO_ERROR:{exc.__class__.__name__}"


def _win32_verify_embedded_signature_offline(exe_path: Path) -> tuple[SignatureStatus, int | None]:
    """Perform strictly offline Authenticode check using WinVerifyTrust (WTD_REVOKE_NONE)."""
    if not is_windows():
        return SignatureStatus.UNAVAILABLE, None
    try:
        if is_reparse_point(exe_path) or not exe_path.is_file():
            return SignatureStatus.UNKNOWN, None

        class _GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        class _WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p),
            ]

        class _WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p),
            ]

        # WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
        action_guid = _GUID(
            0x00AAC56B,
            0xCD44,
            0x11D0,
            (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
        )
        file_info = _WINTRUST_FILE_INFO(
            cbStruct=ctypes.sizeof(_WINTRUST_FILE_INFO),
            pcwszFilePath=str(exe_path),
            hFile=None,
            pgKnownSubject=None,
        )
        # WTD_UI_NONE=2, WTD_REVOKE_NONE=0, WTD_CHOICE_FILE=1, WTD_STATEACTION_VERIFY=1, WTD_STATEACTION_CLOSE=2
        wtd = _WINTRUST_DATA(
            cbStruct=ctypes.sizeof(_WINTRUST_DATA),
            pPolicyCallbackData=None,
            pSIPClientData=None,
            dwUIChoice=2,
            fdwRevocationChecks=0,
            dwUnionChoice=1,
            pFile=ctypes.pointer(file_info),
            dwStateAction=1,
            hWVTStateData=None,
            pwszURLReference=None,
            dwProvFlags=0x00001000,  # WTD_CACHE_ONLY_URL_RETRIEVAL (offline)
            dwUIContext=0,
            pSignatureSettings=None,
        )

        wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
        wintrust.WinVerifyTrust.restype = ctypes.c_long
        wintrust.WinVerifyTrust.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(_GUID),
            ctypes.POINTER(_WINTRUST_DATA),
        ]
        try:
            rc = int(wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd)))
        finally:
            wtd.dwStateAction = 2  # WTD_STATEACTION_CLOSE
            wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd))

        if rc == 0:
            return SignatureStatus.SIGNED_TRUSTED, 0
        if rc in (-2146762496, 0x800B0100 - 0x100000000):  # TRUST_E_NOSIGNATURE
            return SignatureStatus.UNSIGNED, rc
        return SignatureStatus.INVALID_SIGNATURE, rc
    except Exception:
        return SignatureStatus.UNKNOWN, None


def _query_process_times_and_ppid(pid: int) -> tuple[int | None, str | None, int | None]:
    """Return (creation_time_100ns, executable_path, parent_pid) using read-only Win32 APIs."""
    if not is_windows():
        return None, None, None

    class _FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class _ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    k32 = ctypes.windll.kernel32
    creation_100ns: int | None = None
    exe_path: str | None = None
    ppid: int | None = None

    hproc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if hproc:
        try:
            ct, et, kt, ut = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
            if k32.GetProcessTimes(hproc, ctypes.byref(ct), ctypes.byref(et), ctypes.byref(kt), ctypes.byref(ut)):
                creation_100ns = (int(ct.dwHighDateTime) << 32) | int(ct.dwLowDateTime)
            buf_len = wintypes.DWORD(1024)
            buf = ctypes.create_unicode_buffer(1024)
            if k32.QueryFullProcessImageNameW(hproc, 0, buf, ctypes.byref(buf_len)):
                exe_path = buf.value
        finally:
            k32.CloseHandle(hproc)

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap not in (-1, 0, wintypes.HANDLE(-1).value):
        try:
            entry = _ProcessEntry32W()
            entry.dwSize = ctypes.sizeof(_ProcessEntry32W)
            ok = k32.Process32FirstW(snap, ctypes.byref(entry))
            while ok:
                if int(entry.th32ProcessID) == int(pid):
                    ppid = int(entry.th32ParentProcessID)
                    break
                ok = k32.Process32NextW(snap, ctypes.byref(entry))
        finally:
            k32.CloseHandle(snap)

    return creation_100ns, exe_path, ppid


def _query_session_and_sid(pid: int) -> tuple[int | None, str | None, str]:
    """Return (session_id, user_sid_str, integrity_level) read-only for *pid*."""
    if not is_windows():
        return None, None, "UNKNOWN"

    k32 = ctypes.windll.kernel32
    adv = _win32_advapi32()
    sess = wintypes.DWORD(0)
    session_id = int(sess.value) if k32.ProcessIdToSessionId(int(pid), ctypes.byref(sess)) else None

    user_sid: str | None = None
    integrity = "UNKNOWN"
    hproc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not hproc:
        return session_id, None, integrity
    try:
        htok = wintypes.HANDLE()
        if not adv.OpenProcessToken(hproc, 0x0008, ctypes.byref(htok)):  # TOKEN_QUERY
            return session_id, None, integrity
        try:
            sid_val = _query_token_user_sid(htok)
            if sid_val and sid_val != "S-1-5-UNKNOWN":
                user_sid = sid_val
            integrity, _ = _query_token_integrity_level(htok)
        finally:
            k32.CloseHandle(htok)
    finally:
        k32.CloseHandle(hproc)

    return session_id, user_sid, integrity


class ProcessObserver(Protocol):
    """Injectable read-only process observation contract."""

    def observe_process(
        self,
        pid: int | None = None,
        *,
        os_identity: ClientIdentity | None = None,
        include_authenticode: bool = True,
    ) -> ProcessObservation: ...

    def list_candidate_host_processes(self, exe_tokens: tuple[str, ...]) -> list[dict[str, Any]]: ...


class Win32ReadOnlyProcessObserver:
    """Inspects current or specified Windows process strictly read-only without trusting basenames."""

    def observe_process(
        self,
        pid: int | None = None,
        *,
        os_identity: ClientIdentity | None = None,
        include_authenticode: bool = True,
    ) -> ProcessObservation:
        target_pid = int(pid) if pid is not None else os.getpid()
        errors: list[str] = []
        if not is_windows():
            return ProcessObservation(
                pid=target_pid,
                verified_by_os=bool(os_identity.verified_by_os) if os_identity else False,
                proves_application_identity=False,
                observation_errors=("NON_WINDOWS_HOST",),
            )

        creation_100ns, exe_path, ppid = _query_process_times_and_ppid(target_pid)
        session_id, token_sid, token_il = _query_session_and_sid(target_pid)
        effective_sid = token_sid or (os_identity.sid if os_identity and os_identity.verified_by_os else None)
        effective_il = token_il if token_il != "UNKNOWN" else (os_identity.integrity_level if os_identity else "UNKNOWN")

        exe_hash: str | None = None
        sig_status = SignatureStatus.UNKNOWN
        sig_code: int | None = None
        if exe_path:
            p_exe = Path(exe_path)
            exe_hash, hash_err = compute_safe_file_sha256(p_exe)
            if hash_err:
                errors.append(hash_err)
            if include_authenticode:
                sig_status, sig_code = _win32_verify_embedded_signature_offline(p_exe)
        else:
            errors.append("EXECUTABLE_PATH_UNAVAILABLE")

        parent_creation: int | None = None
        parent_path: str | None = None
        if ppid:
            parent_creation, parent_path, _ = _query_process_times_and_ppid(ppid)

        verified_os = bool(
            (os_identity and os_identity.verified_by_os)
            or (token_sid is not None and creation_100ns is not None)
        )

        return ProcessObservation(
            pid=target_pid,
            process_creation_time_100ns=creation_100ns,
            process_creation_time_iso=filetime_100ns_to_iso(creation_100ns),
            user_sid_hash=hash_sid(effective_sid),
            user_sid_observed=effective_sid is not None,
            session_id=session_id,
            integrity_level=effective_il,
            executable_path=exe_path,
            executable_sha256=exe_hash,
            signature_status=sig_status,
            signature_error_code=sig_code,
            parent_pid=ppid,
            parent_image_path=parent_path,
            parent_creation_time_100ns=parent_creation,
            verified_by_os=verified_os,
            proves_application_identity=False,
            observation_errors=tuple(errors),
        )

    def list_candidate_host_processes(self, exe_tokens: tuple[str, ...]) -> list[dict[str, Any]]:
        """Return bounded read-only candidate process summaries (never proof of trust)."""
        procs = list_win32_processes(name_filters=exe_tokens)
        return [
            {
                "pid": p.pid,
                "name": p.name,
                "executable_path": p.executable_path,
                "proves_application_identity": False,
            }
            for p in procs[:25]
        ]

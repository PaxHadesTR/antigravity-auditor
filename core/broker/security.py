"""Windows Security Descriptors, Client Token Inspection, and Identity Models."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
from typing import Any

from broker.constants import DEFAULT_PIPE_SDDL, ERR_ACCESS_DENIED
from broker.exceptions import BrokerSecurityError

# Win32 Constants
SECURITY_DESCRIPTOR_REVISION = 1
TOKEN_QUERY = 0x0008

# TOKEN_INFORMATION_CLASS values
TokenUser = 1
TokenGroups = 2
TokenImpersonationLevel = 9
TokenRestrictedSids = 11
TokenElevation = 20
TokenIntegrityLevel = 25
TokenAppContainerNumber = 29

# Integrity Level RIDs
SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000
SECURITY_MANDATORY_LOW_RID = 0x00001000       # 4096
SECURITY_MANDATORY_MEDIUM_RID = 0x00002000    # 8192
SECURITY_MANDATORY_HIGH_RID = 0x00003000      # 12288
SECURITY_MANDATORY_SYSTEM_RID = 0x00004000    # 16384

# Impersonation level names
_IMPERSONATION_LEVEL_NAMES = {
    0: "SecurityAnonymous",
    1: "SecurityIdentification",
    2: "SecurityImpersonation",
    3: "SecurityDelegation",
}

# Broad SIDs forbidden in restricted B4-A SDDLs
_BROAD_PROHIBITED_SIDS = frozenset({
    "WD",
    "AU",
    "BU",
    "S-1-1-0",
    "S-1-5-11",
    "S-1-5-32-545",
})


@dataclass
class ClientIdentity:
    """Represents verified OS-level client process identity."""

    pid: int
    sid: str
    integrity_level: str  # "LOW", "MEDIUM", "HIGH", "SYSTEM", "UNKNOWN"
    is_low_integrity: bool
    is_appcontainer: bool = False
    is_elevated: bool = False
    verified_by_os: bool = False
    impersonation_level: str = "UNKNOWN"
    impersonation_reverted: bool = False
    token_handle_closed: bool = False


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD),
    ]


def is_windows() -> bool:
    """Check if running natively on Windows."""
    return platform.system().lower() == "windows"


def _win32_kernel32() -> ctypes.WinDLL:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetCurrentThread.restype = wintypes.HANDLE
    k32.GetCurrentThread.argtypes = []
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.GetCurrentProcess.argtypes = []
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.LocalFree.restype = wintypes.HLOCAL
    k32.LocalFree.argtypes = [wintypes.HLOCAL]
    k32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    k32.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    k32.CreateNamedPipeW.restype = wintypes.HANDLE
    k32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    k32.ConnectNamedPipe.restype = wintypes.BOOL
    k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.DisconnectNamedPipe.restype = wintypes.BOOL
    k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    k32.ReadFile.restype = wintypes.BOOL
    k32.ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    k32.WriteFile.restype = wintypes.BOOL
    k32.WriteFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    k32.WaitNamedPipeW.restype = wintypes.BOOL
    k32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    k32.GetTickCount64.restype = ctypes.c_uint64
    k32.GetTickCount64.argtypes = []
    k32.GetCurrentThreadId.restype = wintypes.DWORD
    k32.GetCurrentThreadId.argtypes = []
    k32.OpenThread.restype = wintypes.HANDLE
    k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CancelSynchronousIo.restype = wintypes.BOOL
    k32.CancelSynchronousIo.argtypes = [wintypes.HANDLE]
    return k32


get_win32_kernel32 = _win32_kernel32


def read_exact_pipe(kernel32: ctypes.WinDLL, h_pipe: int, length: int) -> bytes | None:
    """Read an exact byte count from a Win32 pipe handle."""
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        buf = ctypes.create_string_buffer(remaining)
        bytes_read = wintypes.DWORD(0)
        ok = kernel32.ReadFile(h_pipe, buf, remaining, ctypes.byref(bytes_read), None)
        if not ok or bytes_read.value == 0:
            return None
        chunks.append(buf.raw[: bytes_read.value])
        remaining -= bytes_read.value
    return b"".join(chunks)


def write_all_pipe(kernel32: ctypes.WinDLL, h_pipe: int, data: bytes) -> bool:
    """Write all bytes in *data* to a Win32 pipe handle."""
    total = 0
    view = memoryview(data)
    while total < len(data):
        chunk = bytes(view[total:])
        written = wintypes.DWORD(0)
        ok = kernel32.WriteFile(h_pipe, chunk, len(chunk), ctypes.byref(written), None)
        if not ok or written.value == 0:
            return False
        total += written.value
    return True


def _win32_advapi32() -> ctypes.WinDLL:
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    adv.ConvertSidToStringSidW.restype = wintypes.BOOL
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    adv.ImpersonateNamedPipeClient.restype = wintypes.BOOL
    adv.ImpersonateNamedPipeClient.argtypes = [wintypes.HANDLE]
    adv.RevertToSelf.restype = wintypes.BOOL
    adv.RevertToSelf.argtypes = []
    adv.OpenThreadToken.restype = wintypes.BOOL
    adv.OpenThreadToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.BOOL,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    adv.GetTokenInformation.restype = wintypes.BOOL
    adv.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    adv.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    adv.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    adv.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    adv.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    adv.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    adv.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    adv.SetNamedSecurityInfoW.restype = wintypes.DWORD
    adv.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    return adv


def create_pipe_security_descriptor(sddl: str = DEFAULT_PIPE_SDDL) -> ctypes.c_void_p | None:
    """Create a native Windows SECURITY_DESCRIPTOR from an SDDL string."""
    if not is_windows():
        return None

    advapi32 = _win32_advapi32()
    p_sd = ctypes.c_void_p()
    res = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SECURITY_DESCRIPTOR_REVISION,
        ctypes.byref(p_sd),
        None,
    )
    if not res or not p_sd.value:
        return None
    return p_sd


def free_pipe_security_descriptor(p_sd: ctypes.c_void_p | None) -> None:
    """Free a SECURITY_DESCRIPTOR allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW."""
    if p_sd and p_sd.value and is_windows():
        _win32_kernel32().LocalFree(p_sd.value)


_SDDL_SID_RE = re.compile(r"^S-1-\d+(?:-\d+)+$", re.IGNORECASE)
_SDDL_SAFE_ALIASES = frozenset({"SY", "BA", "LS", "NS", "OW", "CO"})


def validate_sddl_sid(sid: str) -> str:
    """A SID that is safe to interpolate into SDDL: a numeric ``S-1-...`` string or a small allowlist of
    two-letter aliases. Anything else (e.g. ``S-1-5-18)(A;;GA;;;WD``) could inject extra ACEs."""
    value = (sid or "").strip()
    if _SDDL_SID_RE.match(value) or value.upper() in _SDDL_SAFE_ALIASES:
        return value
    raise ValueError(f"Invalid SID for SDDL: {sid!r}")


def build_restricted_pipe_sddl(
    allowed_sids: list[str] | None = None,
    *,
    include_service_sid: str | None = None,
) -> str:
    """Construct a restrictive Named Pipe SDDL without Everyone (WD), Users (BU), or AU.

    Always grants Generic All to SYSTEM (SY) and Built-in Administrators (BA), plus
    Generic Read/Write only to explicitly enumerated SIDs.
    """
    aces = [
        "(A;;GA;;;SY)",
        "(A;;GA;;;BA)",
    ]
    if include_service_sid:
        service_clean = validate_sddl_sid(include_service_sid)  # strip + syntax check before the broad-SID check
        if service_clean.upper() in _BROAD_PROHIBITED_SIDS:
            raise ValueError(f"Prohibited broad SID in restricted pipe SDDL: {service_clean}")
        aces.append(f"(A;;GA;;;{service_clean})")

    for sid in allowed_sids or []:
        sid_clean = sid.strip()
        if not sid_clean:
            continue
        if sid_clean.upper() in _BROAD_PROHIBITED_SIDS:
            raise ValueError(f"Prohibited broad SID in restricted pipe SDDL: {sid_clean}")
        aces.append(f"(A;;GRGW;;;{validate_sddl_sid(sid_clean)})")

    return "D:" + "".join(aces)


def compute_service_sid_from_name(service_name: str) -> str:
    """Compute the deterministic Windows Virtual Service SID (S-1-5-80-...) from service name.

    Matches Microsoft SCM algorithm: SHA-1 over uppercase UTF-16LE service name bytes,
    interpreted as five little-endian 32-bit unsigned subauthorities under S-1-5-80.
    """
    digest = hashlib.sha1(service_name.upper().encode("utf-16-le")).digest()
    sub_auths = struct.unpack("<5I", digest)
    return "S-1-5-80-" + "-".join(str(x) for x in sub_auths)


def _sid_ptr_to_string(sid_ptr: int) -> str:
    """Convert a native Win32 PSID to string using ConvertSidToStringSidW + LocalFree."""
    advapi32 = _win32_advapi32()
    kernel32 = _win32_kernel32()
    str_ptr = wintypes.LPWSTR()
    if advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid_ptr), ctypes.byref(str_ptr)) and str_ptr.value:
        try:
            return str(str_ptr.value)
        finally:
            kernel32.LocalFree(ctypes.cast(str_ptr, wintypes.HLOCAL))
    return "S-1-5-UNKNOWN"


def _query_token_user_sid(h_token: wintypes.HANDLE) -> str:
    """Query TokenUser SID string from an open token handle."""
    advapi32 = _win32_advapi32()
    ret_len = wintypes.DWORD(0)
    advapi32.GetTokenInformation(h_token, TokenUser, None, 0, ctypes.byref(ret_len))
    if ret_len.value == 0:
        return "S-1-5-UNKNOWN"
    buf = ctypes.create_string_buffer(ret_len.value)
    if not advapi32.GetTokenInformation(h_token, TokenUser, buf, ret_len.value, ctypes.byref(ret_len)):
        return "S-1-5-UNKNOWN"
    user_struct = _SID_AND_ATTRIBUTES.from_buffer(buf)
    if not user_struct.Sid:
        return "S-1-5-UNKNOWN"
    return _sid_ptr_to_string(user_struct.Sid)


def _query_token_sid_list(h_token: wintypes.HANDLE, info_class: int) -> list[str]:
    """Query TokenGroups or TokenRestrictedSids SID list from an open token handle."""
    advapi32 = _win32_advapi32()
    ret_len = wintypes.DWORD(0)
    advapi32.GetTokenInformation(h_token, info_class, None, 0, ctypes.byref(ret_len))
    if ret_len.value == 0:
        return []
    buf = ctypes.create_string_buffer(ret_len.value)
    if not advapi32.GetTokenInformation(h_token, info_class, buf, ret_len.value, ctypes.byref(ret_len)):
        return []
    group_count = ctypes.c_ulong.from_buffer(buf, 0).value
    # Offset of SID_AND_ATTRIBUTES array after GroupCount (aligned to pointer size on 64-bit)
    header_size = ctypes.sizeof(ctypes.c_void_p)
    entry_size = ctypes.sizeof(_SID_AND_ATTRIBUTES)
    sids: list[str] = []
    for idx in range(group_count):
        offset = header_size + idx * entry_size
        if offset + entry_size > ret_len.value:
            break
        entry = _SID_AND_ATTRIBUTES.from_buffer(buf, offset)
        if entry.Sid:
            sids.append(_sid_ptr_to_string(entry.Sid))
    return sids


def _query_token_impersonation_level(h_token: wintypes.HANDLE) -> str:
    """Query TokenImpersonationLevel on an impersonation token."""
    advapi32 = _win32_advapi32()
    imp_level = wintypes.DWORD(0)
    ret_len = wintypes.DWORD(0)
    ok = advapi32.GetTokenInformation(
        h_token,
        TokenImpersonationLevel,
        ctypes.byref(imp_level),
        ctypes.sizeof(imp_level),
        ctypes.byref(ret_len),
    )
    if not ok:
        return "PRIMARY_OR_UNKNOWN"
    return _IMPERSONATION_LEVEL_NAMES.get(int(imp_level.value), f"UNKNOWN_{imp_level.value}")


def get_current_user_sid() -> str:
    """Return the current process token user SID string (or mock SID off Windows)."""
    if not is_windows():
        return "S-1-5-21-NON-WINDOWS"
    kernel32 = _win32_kernel32()
    advapi32 = _win32_advapi32()
    h_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(h_token)):
        return "S-1-5-UNKNOWN"
    try:
        return _query_token_user_sid(h_token)
    finally:
        kernel32.CloseHandle(h_token)


def get_current_process_identity() -> dict[str, Any]:
    """Inspect the running process's Windows identity, groups, restricted SIDs, and IL."""
    if not is_windows():
        return {
            "platform": platform.system(),
            "pid": os.getpid(),
            "user_sid": "S-1-5-21-NON-WINDOWS",
            "integrity_level": "MEDIUM",
            "is_elevated": False,
            "groups": [],
            "restricted_sids": [],
            "is_write_restricted_token": False,
        }

    kernel32 = _win32_kernel32()
    advapi32 = _win32_advapi32()
    h_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(h_token)):
        err = ctypes.get_last_error()
        return {"pid": os.getpid(), "error": f"OpenProcessToken failed with WinError {err}"}

    try:
        user_sid = _query_token_user_sid(h_token)
        il_str, is_low = _query_token_integrity_level(h_token)
        is_elevated = _query_token_elevation(h_token)
        is_appcontainer = _query_token_appcontainer(h_token)
        groups = _query_token_sid_list(h_token, TokenGroups)
        restricted_sids = _query_token_sid_list(h_token, TokenRestrictedSids)
        return {
            "pid": os.getpid(),
            "user_sid": user_sid,
            "integrity_level": il_str,
            "is_low_integrity": is_low,
            "is_elevated": is_elevated,
            "is_appcontainer": is_appcontainer,
            "groups": groups,
            "restricted_sids": restricted_sids,
            "is_write_restricted_token": len(restricted_sids) > 0,
            "has_service_sid_prefix": any(s.startswith("S-1-5-80-") for s in ([user_sid] + groups + restricted_sids)),
        }
    finally:
        kernel32.CloseHandle(h_token)


def inspect_pipe_client_identity(pipe_handle: int | ctypes.c_void_p) -> ClientIdentity:
    """Inspect the connected client process and token through the pipe handle.

    Always reverts impersonation and closes thread token handles in finally blocks.
    """
    if not is_windows() or not pipe_handle:
        return ClientIdentity(
            pid=os.getpid(),
            sid="S-1-5-21-MOCK-CLIENT",
            integrity_level="MEDIUM",
            is_low_integrity=False,
            verified_by_os=False,
            impersonation_level="MOCK",
            impersonation_reverted=True,
            token_handle_closed=True,
        )

    kernel32 = _win32_kernel32()
    advapi32 = _win32_advapi32()

    # Handle value coercion
    h_val = pipe_handle.value if isinstance(pipe_handle, ctypes.c_void_p) else int(pipe_handle)
    h_pipe_arg = wintypes.HANDLE(h_val)

    # 1. Obtain Client PID directly from kernel
    client_pid = wintypes.ULONG(0)
    res_pid = kernel32.GetNamedPipeClientProcessId(h_pipe_arg, ctypes.byref(client_pid))
    pid = int(client_pid.value) if res_pid else 0

    # 2. Impersonate client to inspect thread/client token
    sid_str = "S-1-5-UNKNOWN"
    il_str = "UNKNOWN"
    imp_level_str = "UNKNOWN"
    is_low = False
    is_appcontainer = False
    is_elevated = False
    verified = False
    reverted = False
    token_closed = True  # Stays True if no token was opened

    res_imp = advapi32.ImpersonateNamedPipeClient(h_pipe_arg)
    if res_imp:
        try:
            h_token = wintypes.HANDLE()
            curr_thread = kernel32.GetCurrentThread()
            res_tok = advapi32.OpenThreadToken(curr_thread, TOKEN_QUERY, True, ctypes.byref(h_token))
            if res_tok and h_token.value:
                token_closed = False
                try:
                    verified = True
                    sid_str = _query_token_user_sid(h_token)
                    il_str, is_low = _query_token_integrity_level(h_token)
                    imp_level_str = _query_token_impersonation_level(h_token)
                    is_appcontainer = _query_token_appcontainer(h_token)
                    is_elevated = _query_token_elevation(h_token)
                finally:
                    if kernel32.CloseHandle(h_token):
                        token_closed = True
        finally:
            if advapi32.RevertToSelf():
                reverted = True
        if not reverted:
            # Never continue on the client's impersonation token.
            raise BrokerSecurityError(
                "RevertToSelf failed after ImpersonateNamedPipeClient; refusing to continue.",
                code=ERR_ACCESS_DENIED,
            )

    return ClientIdentity(
        pid=pid,
        sid=sid_str,
        integrity_level=il_str,
        is_low_integrity=is_low,
        is_appcontainer=is_appcontainer,
        is_elevated=is_elevated,
        verified_by_os=verified,
        impersonation_level=imp_level_str,
        impersonation_reverted=reverted,
        token_handle_closed=token_closed,
    )


def _query_token_integrity_level(h_token: wintypes.HANDLE) -> tuple[str, bool]:
    """Query TokenIntegrityLevel from token handle."""
    advapi32 = _win32_advapi32()

    return_len = wintypes.DWORD(0)
    advapi32.GetTokenInformation(h_token, TokenIntegrityLevel, None, 0, ctypes.byref(return_len))
    if return_len.value == 0:
        return "UNKNOWN", True

    buf = ctypes.create_string_buffer(return_len.value)
    res = advapi32.GetTokenInformation(h_token, TokenIntegrityLevel, buf, return_len.value, ctypes.byref(return_len))
    if not res:
        return "UNKNOWN", True

    sid_ptr = ctypes.c_void_p.from_buffer(buf).value
    # An integrity level that cannot be read is treated as untrusted (fail closed): is_low_integrity=True.
    if not sid_ptr:
        return "UNKNOWN", True

    count_ptr = advapi32.GetSidSubAuthorityCount(ctypes.c_void_p(sid_ptr))
    if not count_ptr:
        return "UNKNOWN", True
    sub_count = count_ptr.contents.value
    if sub_count == 0:
        return "UNKNOWN", True

    rid_ptr = advapi32.GetSidSubAuthority(ctypes.c_void_p(sid_ptr), sub_count - 1)
    if not rid_ptr:
        return "UNKNOWN", True
    rid = rid_ptr.contents.value

    if rid < SECURITY_MANDATORY_LOW_RID:
        return "UNTRUSTED", True
    elif rid < SECURITY_MANDATORY_MEDIUM_RID:
        return "LOW", True
    elif rid < SECURITY_MANDATORY_HIGH_RID:
        return "MEDIUM", False
    elif rid < SECURITY_MANDATORY_SYSTEM_RID:
        return "HIGH", False
    else:
        return "SYSTEM", False


def _query_token_appcontainer(h_token: wintypes.HANDLE) -> bool:
    """Check if token is an AppContainer."""
    advapi32 = _win32_advapi32()
    app_cont = wintypes.DWORD(0)
    return_len = wintypes.DWORD(0)
    res = advapi32.GetTokenInformation(
        h_token,
        TokenAppContainerNumber,
        ctypes.byref(app_cont),
        ctypes.sizeof(app_cont),
        ctypes.byref(return_len),
    )
    return bool(res and app_cont.value != 0)


def _query_token_elevation(h_token: wintypes.HANDLE) -> bool:
    """Check if token is elevated."""
    advapi32 = _win32_advapi32()
    elevated = wintypes.DWORD(0)
    return_len = wintypes.DWORD(0)
    res = advapi32.GetTokenInformation(
        h_token,
        TokenElevation,
        ctypes.byref(elevated),
        ctypes.sizeof(elevated),
        ctypes.byref(return_len),
    )
    return bool(res and elevated.value != 0)


def query_path_dacl(path: Path) -> dict[str, Any]:
    """Query actual Windows NTFS DACL string via icacls for a given path."""
    if not is_windows():
        return {"path": str(path), "supported": False}
    proc = subprocess.run(
        ["icacls", str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return {
        "path": str(path),
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def apply_restricted_directory_dacl(
    directory: Path,
    service_sid: str,
    *,
    remove_inherited: bool = True,
    grant_system: bool = True,
    grant_admins: bool = True,
    deny_sids: list[str] | None = None,
) -> dict[str, Any]:
    """Apply restrictive NTFS DACL to a dedicated B4-A test directory via Win32 SetNamedSecurityInfoW.

    Uses binary-SID SDDL conversion + SetNamedSecurityInfoW so virtual service SIDs (S-1-5-80-...)
    can be written directly to the directory DACL even before SCM service registration.
    Refuses to modify any production or user-profile root directory fail-closed.
    """
    resolved = directory.resolve()
    local_app_data = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    # Whole subtrees that must never be re-ACLed.
    forbidden_subtrees = [
        (Path(local_app_data) / "AntigravityAuditor").resolve(),
        Path(r"C:\ProgramData\AntigravityAuditor").resolve(),
        Path(os.environ.get("WINDIR") or r"C:\Windows").resolve(),
    ]
    # Roots that must not be re-ACLed themselves (test directories below them are allowed).
    forbidden_roots = [
        Path(os.environ.get("USERPROFILE") or Path.home()).resolve(),
        Path(r"C:\ProgramData").resolve(),
        Path(resolved.anchor).resolve(),
    ]
    for fp in forbidden_subtrees:
        if resolved == fp or fp in resolved.parents:
            raise PermissionError(f"Refusing to modify ACL on prohibited path or subtree: {resolved}")
    if resolved in forbidden_roots:
        raise PermissionError(f"Refusing to modify ACL on protected root directory: {resolved}")
    service_sid = validate_sddl_sid(service_sid)
    if service_sid.upper() in _BROAD_PROHIBITED_SIDS:
        raise ValueError(f"Prohibited broad SID in restricted directory DACL: {service_sid}")
    deny_sids = [validate_sddl_sid(d) for d in (deny_sids or [])]

    aces = [f"(A;OICI;FA;;;{service_sid})"]
    if grant_system:
        aces.append("(A;OICI;FA;;;SY)")
    if grant_admins:
        aces.append("(A;OICI;FA;;;BA)")
    for dsid in deny_sids or []:
        aces.insert(0, f"(D;OICI;FA;;;{dsid})")
    sddl = "D:" + ("P" if remove_inherited else "") + "".join(aces)

    advapi32 = _win32_advapi32()
    p_sd = create_pipe_security_descriptor(sddl)
    if not p_sd:
        err = ctypes.get_last_error()
        return {
            "path": str(resolved),
            "sddl": sddl,
            "returncode": int(err or 1),
            "stderr": f"ConvertStringSecurityDescriptorToSecurityDescriptorW failed: Win32 {err}",
            "effective_dacl": query_path_dacl(resolved),
        }

    try:
        dacl_present = wintypes.BOOL(0)
        dacl_defaulted = wintypes.BOOL(0)
        p_dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            p_sd, ctypes.byref(dacl_present), ctypes.byref(p_dacl), ctypes.byref(dacl_defaulted)
        ) or not dacl_present.value:
            err = ctypes.get_last_error()
            return {
                "path": str(resolved),
                "sddl": sddl,
                "returncode": int(err or 1),
                "stderr": f"GetSecurityDescriptorDacl failed: Win32 {err}",
                "effective_dacl": query_path_dacl(resolved),
            }

        SE_FILE_OBJECT = 1
        DACL_SECURITY_INFORMATION = 0x00000004
        PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
        UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
        sec_info = DACL_SECURITY_INFORMATION | (
            PROTECTED_DACL_SECURITY_INFORMATION if remove_inherited else UNPROTECTED_DACL_SECURITY_INFORMATION
        )
        win_err = advapi32.SetNamedSecurityInfoW(
            str(resolved),
            SE_FILE_OBJECT,
            sec_info,
            None,
            None,
            p_dacl,
            None,
        )
    finally:
        free_pipe_security_descriptor(p_sd)

    return {
        "path": str(resolved),
        "sddl": sddl,
        "returncode": int(win_err),
        "stderr": "" if win_err == 0 else f"SetNamedSecurityInfoW failed: Win32 {win_err}",
        "effective_dacl": query_path_dacl(resolved),
    }


def probe_win32_file_open(path: Path, write: bool = False) -> dict[str, Any]:
    """Perform an actual Win32 CreateFileW open attempt to measure real NTFS ACL enforcement."""
    if not is_windows():
        return {"supported": False}
    kernel32 = _win32_kernel32()
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ_WRITE = 0x00000003
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080

    access = GENERIC_READ | (GENERIC_WRITE if write else 0)
    h = kernel32.CreateFileW(
        str(path),
        access,
        FILE_SHARE_READ_WRITE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    err = ctypes.get_last_error()
    invalid = h in (None, 0, -1, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF)
    if not invalid:
        kernel32.CloseHandle(wintypes.HANDLE(h))
        return {"path": str(path), "allowed": True, "win32_error": 0, "mode": "READ_WRITE" if write else "READ"}
    return {"path": str(path), "allowed": False, "win32_error": int(err), "mode": "READ_WRITE" if write else "READ"}

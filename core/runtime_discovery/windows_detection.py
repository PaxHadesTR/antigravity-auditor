"""Read-only Windows application, MSIX/AppX, file version, and process detection."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002

_APPX_FULLNAME_RE = re.compile(
    r"^(?P<name>[^_]+)_(?P<version>\d+\.\d+\.\d+\.\d+)_(?P<arch>[^_]+)_(?P<resource>[^_]*)_(?P<publisher>[0-9a-zA-Z]+)$"
)


@dataclass(frozen=True)
class AppxPackageInfo:
    name: str
    package_full_name: str
    package_family_name: str
    version: str | None
    install_location: str | None


@dataclass(frozen=True)
class UninstallEntry:
    display_name: str
    display_version: str | None
    install_location: str | None
    publisher: str | None
    hive: str


@dataclass(frozen=True)
class RunningProcessInfo:
    pid: int
    name: str
    executable_path: str | None


def is_reparse_point(path: Path) -> bool:
    """Return True if path itself is a symlink, junction, or Windows reparse point."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def has_reparse_point_in_ancestors(path: Path, *, stop_at: Path | None = None) -> bool:
    """Check ``path`` and its parents for reparse points.

    If ``path`` lies inside ``stop_at``, the walk stops at (and includes) ``stop_at``; otherwise -- or for a
    sibling that merely shares a name prefix such as ``AppData2`` -- every ancestor up to the drive root is
    checked (fail safe)."""
    cur = Path(os.path.abspath(str(path)))
    norm_stop: str | None = None
    if stop_at is not None:
        candidate = os.path.normcase(os.path.abspath(str(stop_at)))
        try:
            inside = os.path.commonpath([os.path.normcase(str(cur)), candidate]) == candidate
        except ValueError:  # different drives
            inside = False
        norm_stop = candidate if inside else None
    while True:
        if is_reparse_point(cur):
            return True
        if norm_stop is not None and os.path.normcase(str(cur)) == norm_stop:
            return False
        parent = cur.parent
        if parent == cur:
            return False
        cur = parent


def safe_read_text(
    path: Path,
    *,
    root: Path | None = None,
    max_bytes: int = 2 * 1024 * 1024,
) -> tuple[str | None, str | None]:
    """Safely read a bounded UTF-8 file without traversing symlinks or junctions."""
    try:
        if has_reparse_point_in_ancestors(path, stop_at=root):
            return None, "REPARSE_POINT_BLOCKED"
        if not path.exists():
            return None, "NOT_FOUND"
        if not path.is_file():
            return None, "NOT_A_FILE"
        size = os.lstat(path).st_size
        if size > max_bytes:
            return None, "FILE_TOO_LARGE"
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(max_bytes), None
    except PermissionError:
        return None, "PERMISSION_DENIED"
    except OSError:
        return None, "IO_ERROR"


def safe_list_dir_names(
    dir_path: Path,
    *,
    root: Path | None = None,
    max_entries: int = 256,
) -> tuple[list[str], str | None]:
    """List immediate directory entry names without recursion or reparse-point traversal."""
    try:
        if has_reparse_point_in_ancestors(dir_path, stop_at=root):
            return [], "REPARSE_POINT_BLOCKED"
        if not dir_path.exists() or not dir_path.is_dir():
            return [], "NOT_FOUND"
        entries: list[str] = []
        with os.scandir(dir_path) as it:
            for idx, entry in enumerate(it):
                if idx >= max_entries:
                    break
                entries.append(entry.name)
        return sorted(entries), None
    except PermissionError:
        return [], "PERMISSION_DENIED"
    except OSError:
        return [], "IO_ERROR"


def parse_appx_full_name(full_name: str) -> tuple[str, str | None, str]:
    """Parse PackageFullName into (name, version, package_family_name)."""
    m = _APPX_FULLNAME_RE.match(full_name)
    if not m:
        parts = full_name.split("_")
        name = parts[0]
        family = f"{name}_{parts[-1]}" if len(parts) >= 2 else full_name
        version = parts[1] if len(parts) >= 2 and re.match(r"^\d+\.\d+", parts[1]) else None
        return name, version, family
    name = m.group("name")
    version = m.group("version")
    publisher = m.group("publisher")
    return name, version, f"{name}_{publisher}"


def get_win32_file_version(exe_path: Path) -> str | None:
    """Read PE FileVersion via Win32 GetFileVersionInfoW (read-only)."""
    if sys.platform != "win32":
        return None
    try:
        if is_reparse_point(exe_path) or not exe_path.is_file():
            return None
        ver = ctypes.windll.version
        path_str = str(exe_path)
        size = ver.GetFileVersionInfoSizeW(path_str, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path_str, 0, size, buf):
            return None
        val_ptr = ctypes.c_void_p()
        val_len = wintypes.UINT()
        if not ver.VerQueryValueW(buf, "\\", ctypes.byref(val_ptr), ctypes.byref(val_len)):
            return None

        class _VSFixedFileInfo(ctypes.Structure):
            _fields_ = [
                ("dwSignature", wintypes.DWORD),
                ("dwStrucVersion", wintypes.DWORD),
                ("dwFileVersionMS", wintypes.DWORD),
                ("dwFileVersionLS", wintypes.DWORD),
                ("dwProductVersionMS", wintypes.DWORD),
                ("dwProductVersionLS", wintypes.DWORD),
                ("dwFileFlagsMask", wintypes.DWORD),
                ("dwFileFlags", wintypes.DWORD),
                ("dwFileOS", wintypes.DWORD),
                ("dwFileType", wintypes.DWORD),
                ("dwFileSubtype", wintypes.DWORD),
                ("dwFileDateMS", wintypes.DWORD),
                ("dwFileDateLS", wintypes.DWORD),
            ]

        ffi = ctypes.cast(val_ptr, ctypes.POINTER(_VSFixedFileInfo)).contents
        return (
            f"{ffi.dwFileVersionMS >> 16}."
            f"{ffi.dwFileVersionMS & 0xFFFF}."
            f"{ffi.dwFileVersionLS >> 16}."
            f"{ffi.dwFileVersionLS & 0xFFFF}"
        )
    except Exception:
        return None


def list_win32_processes(name_filters: tuple[str, ...] | None = None) -> list[RunningProcessInfo]:
    """List running processes using read-only Toolhelp32 + QueryFullProcessImageNameW."""
    if sys.platform != "win32":
        return []

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

    kernel32 = ctypes.windll.kernel32
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot in (-1, 0, wintypes.HANDLE(-1).value):
        return []

    results: list[RunningProcessInfo] = []
    normalized_filters = tuple(f.lower() for f in name_filters) if name_filters else None
    try:
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(_ProcessEntry32W)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            proc_name = str(entry.szExeFile)
            low_name = proc_name.lower()
            if normalized_filters is None or any(f in low_name for f in normalized_filters):
                pid = int(entry.th32ProcessID)
                exe_path: str | None = None
                hproc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if hproc:
                    try:
                        buf_len = wintypes.DWORD(1024)
                        buf = ctypes.create_unicode_buffer(1024)
                        if kernel32.QueryFullProcessImageNameW(hproc, 0, buf, ctypes.byref(buf_len)):
                            exe_path = buf.value
                    finally:
                        kernel32.CloseHandle(hproc)
                results.append(
                    RunningProcessInfo(pid=pid, name=proc_name, executable_path=exe_path)
                )
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    results.sort(key=lambda p: (p.name.lower(), p.pid))
    return results


def query_winreg_appx_packages(name_tokens: tuple[str, ...]) -> list[AppxPackageInfo]:
    """Read-only lookup of MSIX/AppX packages from HKCU AppModel Repository."""
    if sys.platform != "win32":
        return []
    import winreg

    subpath = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
    packages: list[AppxPackageInfo] = []
    tokens = tuple(t.lower() for t in name_tokens)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subpath, 0, winreg.KEY_READ) as key:
            idx = 0
            while True:
                try:
                    full_name = winreg.EnumKey(key, idx)
                    idx += 1
                except OSError:
                    break
                if not any(tok in full_name.lower() for tok in tokens):
                    continue
                install_loc: str | None = None
                try:
                    with winreg.OpenKey(key, full_name, 0, winreg.KEY_READ) as sub:
                        val, _ = winreg.QueryValueEx(sub, "PackageRootFolder")
                        if isinstance(val, str) and val.strip():
                            install_loc = val.strip()
                except OSError:
                    install_loc = None
                name, version, family = parse_appx_full_name(full_name)
                packages.append(
                    AppxPackageInfo(
                        name=name,
                        package_full_name=full_name,
                        package_family_name=family,
                        version=version,
                        install_location=install_loc,
                    )
                )
    except OSError:
        return []
    packages.sort(key=lambda p: p.package_full_name)
    return packages


def query_winreg_uninstall(name_tokens: tuple[str, ...]) -> list[UninstallEntry]:
    """Read-only lookup of Uninstall registry keys (HKCU + HKLM, KEY_READ only)."""
    if sys.platform != "win32":
        return []
    import winreg

    tokens = tuple(t.lower() for t in name_tokens)
    uninstall_sub = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    entries: list[UninstallEntry] = []
    for hive_name, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
        try:
            with winreg.OpenKey(hive, uninstall_sub, 0, winreg.KEY_READ) as root_key:
                idx = 0
                while True:
                    try:
                        sub_name = winreg.EnumKey(root_key, idx)
                        idx += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(root_key, sub_name, 0, winreg.KEY_READ) as item:
                            disp, _ = winreg.QueryValueEx(item, "DisplayName")
                            if not isinstance(disp, str) or not any(tok in disp.lower() for tok in tokens):
                                continue
                            ver = _read_reg_str(item, "DisplayVersion")
                            loc = _read_reg_str(item, "InstallLocation")
                            pub = _read_reg_str(item, "Publisher")
                            entries.append(
                                UninstallEntry(
                                    display_name=disp.strip(),
                                    display_version=ver,
                                    install_location=loc,
                                    publisher=pub,
                                    hive=hive_name,
                                )
                            )
                    except OSError:
                        continue
        except OSError:
            continue
    entries.sort(key=lambda e: (e.display_name.lower(), e.hive))
    return entries


def _read_reg_str(key: object, value_name: str) -> str | None:
    import winreg

    try:
        val, _ = winreg.QueryValueEx(key, value_name)
        if isinstance(val, str) and val.strip():
            return val.strip()
    except OSError:
        return None
    return None


class WindowsHostInspector(Protocol):
    """Injectable read-only host inspector for deterministic testing."""

    def get_file_version(self, path: Path) -> str | None: ...
    def list_processes(self, name_filters: tuple[str, ...] | None = None) -> list[RunningProcessInfo]: ...
    def find_appx_packages(self, name_tokens: tuple[str, ...]) -> list[AppxPackageInfo]: ...
    def find_uninstall_entries(self, name_tokens: tuple[str, ...]) -> list[UninstallEntry]: ...


class DefaultWindowsHostInspector:
    """Production read-only Windows inspector using Win32 APIs and KEY_READ registry."""

    def get_file_version(self, path: Path) -> str | None:
        return get_win32_file_version(path)

    def list_processes(self, name_filters: tuple[str, ...] | None = None) -> list[RunningProcessInfo]:
        return list_win32_processes(name_filters=name_filters)

    def find_appx_packages(self, name_tokens: tuple[str, ...]) -> list[AppxPackageInfo]:
        return query_winreg_appx_packages(name_tokens)

    def find_uninstall_entries(self, name_tokens: tuple[str, ...]) -> list[UninstallEntry]:
        return query_winreg_uninstall(name_tokens)

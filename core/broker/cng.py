"""Windows CNG / TPM 2.0 Cryptographic Key Custody for NEXT-21C-B4-B.

Provides hardware-backed and OS KSP non-exportable persisted signing keys via
native `ncrypt.dll` and verification via native `bcrypt.dll` without third-party
dependencies or private-key exposure to Python process memory.

Security Invariants:
- Zero private key material ever extracted or held in Python memory.
- Export Policy is pinned to 0 (`NCRYPT_ALLOW_EXPORT_NONE`) before NCryptFinalizeKey.
- `tpm_backed=True` is ONLY asserted when the OS provider's `Impl Type` reports
  `NCRYPT_IMPL_HARDWARE_FLAG` (`0x1`) without `NCRYPT_IMPL_SOFTWARE_FLAG` (`0x2`).
- Zero silent fallback from TPM (`MS_PLATFORM_CRYPTO_PROVIDER`) to Software KSP
  or pure-Python EphemeralCbeatSigner when TPM/CNG is required.
- Strict test-only persisted key namespace isolation (`AntigravityB4BTest_*`).
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import threading
from typing import Any

from broker.cbeat import (
    CBEAT_ALG_CNG_ECDSA_P256,
    CBEAT_CNG_DOMAIN_SEP,
    CbeatPayload,
    CbeatSigner,
    CbeatToken,
)
from broker.constants import (
    B4B_TEST_KEY_PREFIX,
    ERR_CNG_ERROR,
    ERR_TPM_UNAVAILABLE,
)
from broker.exceptions import (
    BrokerCngError,
    BrokerSchemaError,
    BrokerSecurityError,
    BrokerTpmUnavailableError,
)
from broker.security import is_windows

MS_KEY_STORAGE_PROVIDER = "Microsoft Software Key Storage Provider"
MS_PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider"

NCRYPT_ECDSA_P256_ALGORITHM = "ECDSA_P256"
BCRYPT_ECDSA_P256_ALGORITHM = "ECDSA_P256"
BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB"
BCRYPT_ECCPRIVATE_BLOB = "ECCPRIVATEBLOB"
PKCS8_PRIVATE_KEY_BLOB = "PKCS8_PRIVATEKEY"

# NCrypt Flags & Property Names
NCRYPT_MACHINE_KEY_FLAG = 0x00000020
NCRYPT_SILENT_FLAG = 0x00000040
NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080
NCRYPT_PERSIST_FLAG = 0x80000000

NCRYPT_EXPORT_POLICY_PROPERTY = "Export Policy"
NCRYPT_KEY_USAGE_PROPERTY = "Key Usage"
NCRYPT_IMPL_TYPE_PROPERTY = "Impl Type"
NCRYPT_SECURITY_DESCR_PROPERTY = "Security Descr"

NCRYPT_ALLOW_EXPORT_NONE = 0x00000000
NCRYPT_ALLOW_SIGNING_FLAG = 0x00000002

# NCrypt Impl Type Bits
NCRYPT_IMPL_HARDWARE_FLAG = 0x00000001
NCRYPT_IMPL_SOFTWARE_FLAG = 0x00000002
NCRYPT_IMPL_REMOVABLE_FLAG = 0x00000008
NCRYPT_IMPL_HARDWARE_RNG_FLAG = 0x00000010

# Win32 Security Descriptor Flags
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000

# Supported B4-B CNG algorithms
SUPPORTED_CNG_ALGORITHMS = frozenset({NCRYPT_ECDSA_P256_ALGORITHM})
PRODUCTION_KEY_NAMES = frozenset({
    "AntigravityAuditorCbeatProd",
    "AntigravityAuditorProdKey",
    "AntigravityAuditorRoot",
    "AntigravityAuditorSigningKey",
})

# Common Windows SECURITY_STATUS / HRESULT codes
NTE_BAD_KEYSET = 0x80090016
NTE_EXISTS = 0x8009000F
NTE_PERM = 0x80090010
NTE_NOT_SUPPORTED = 0x80090029
NTE_BAD_TYPE = 0x8009000A


class _NCryptProviderName(ctypes.Structure):
    _fields_ = [("pszName", wintypes.LPWSTR), ("pszComment", wintypes.LPWSTR)]


class _NCryptAlgName(ctypes.Structure):
    _fields_ = [
        ("pszName", wintypes.LPWSTR),
        ("dwClass", wintypes.DWORD),
        ("dwAlgOperations", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
    ]


class _TbsDeviceInfo(ctypes.Structure):
    _fields_ = [
        ("structVersion", wintypes.DWORD),
        ("tpmVersion", wintypes.DWORD),
        ("tpmInterfaceType", wintypes.DWORD),
        ("tpmImpRevision", wintypes.DWORD),
    ]


def _win32_ncrypt() -> ctypes.WinDLL:
    nc = ctypes.WinDLL("ncrypt")
    nc.NCryptEnumStorageProviders.argtypes = [
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.POINTER(_NCryptProviderName)),
        wintypes.DWORD,
    ]
    nc.NCryptEnumStorageProviders.restype = ctypes.c_long

    nc.NCryptOpenStorageProvider.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    nc.NCryptOpenStorageProvider.restype = ctypes.c_long

    nc.NCryptEnumAlgorithms.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.POINTER(_NCryptAlgName)),
        wintypes.DWORD,
    ]
    nc.NCryptEnumAlgorithms.restype = ctypes.c_long

    nc.NCryptCreatePersistedKey.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    nc.NCryptCreatePersistedKey.restype = ctypes.c_long

    nc.NCryptOpenKey.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    nc.NCryptOpenKey.restype = ctypes.c_long

    nc.NCryptSetProperty.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    nc.NCryptSetProperty.restype = ctypes.c_long

    nc.NCryptGetProperty.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
    ]
    nc.NCryptGetProperty.restype = ctypes.c_long

    nc.NCryptFinalizeKey.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    nc.NCryptFinalizeKey.restype = ctypes.c_long

    nc.NCryptSignHash.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
    ]
    nc.NCryptSignHash.restype = ctypes.c_long

    nc.NCryptExportKey.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
    ]
    nc.NCryptExportKey.restype = ctypes.c_long

    nc.NCryptDeleteKey.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    nc.NCryptDeleteKey.restype = ctypes.c_long

    nc.NCryptFreeObject.argtypes = [ctypes.c_void_p]
    nc.NCryptFreeObject.restype = ctypes.c_long

    nc.NCryptFreeBuffer.argtypes = [ctypes.c_void_p]
    nc.NCryptFreeBuffer.restype = ctypes.c_long
    return nc


def _win32_bcrypt() -> ctypes.WinDLL:
    bc = ctypes.WinDLL("bcrypt")
    bc.BCryptOpenAlgorithmProvider.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    bc.BCryptOpenAlgorithmProvider.restype = ctypes.c_long

    bc.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    bc.BCryptCloseAlgorithmProvider.restype = ctypes.c_long

    bc.BCryptImportKeyPair.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    bc.BCryptImportKeyPair.restype = ctypes.c_long

    bc.BCryptVerifySignature.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    bc.BCryptVerifySignature.restype = ctypes.c_long

    bc.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
    bc.BCryptDestroyKey.restype = ctypes.c_long
    return bc


def _status_u32(status: int) -> int:
    return status & 0xFFFFFFFF


def _status_hex(status: int) -> str:
    return hex(_status_u32(status))


def validate_test_key_name(key_name: str) -> str:
    """Enforce isolated B4-B test key namespace; never allow production or user key tampering."""
    if not key_name or not isinstance(key_name, str):
        raise BrokerSchemaError("CNG key_name must be a non-empty string.")
    cleaned = key_name.strip()
    lower = cleaned.lower()
    if cleaned in PRODUCTION_KEY_NAMES or "prod" in lower and not cleaned.startswith(B4B_TEST_KEY_PREFIX):
        raise BrokerSecurityError(
            f"Refused production or non-test CNG key name '{cleaned}'. "
            f"B4-B requires prefix '{B4B_TEST_KEY_PREFIX}'."
        )
    if not cleaned.startswith(B4B_TEST_KEY_PREFIX) or len(cleaned) <= len(B4B_TEST_KEY_PREFIX):
        raise BrokerSecurityError(
            f"CNG key_name '{cleaned}' must start with isolated test prefix '{B4B_TEST_KEY_PREFIX}'."
        )
    if len(cleaned) > 128 or not all(c.isalnum() or c in "_-" for c in cleaned):
        raise BrokerSchemaError(
            f"CNG key_name '{cleaned}' contains invalid characters or exceeds 128 characters."
        )
    return cleaned


def validate_cng_algorithm(algorithm: str) -> str:
    """Validate that algorithm is supported by B4-B CNG/TPM custody."""
    if algorithm not in SUPPORTED_CNG_ALGORITHMS:
        raise BrokerCngError(
            f"Unsupported CNG algorithm '{algorithm}'. Allowed: {sorted(SUPPORTED_CNG_ALGORITHMS)}.",
            code=ERR_CNG_ERROR,
        )
    return algorithm


def build_key_dacl_sddl(allowed_sids: list[str] | tuple[str, ...] | None = None) -> str:
    """Build restricted SDDL DACL for persisted CNG key ACL isolation."""
    aces = ["(A;;GA;;;SY)", "(A;;GA;;;BA)"]
    for sid in allowed_sids or ():
        s = (sid or "").strip()
        if s:
            if s.upper() in {"WD", "BU", "AU", "S-1-1-0", "S-1-5-11", "S-1-5-32-545"}:
                raise BrokerSecurityError(f"Broad SID '{s}' is forbidden in CNG key DACL.")
            from broker.security import validate_sddl_sid

            try:
                s = validate_sddl_sid(s)
            except ValueError as exc:
                raise BrokerSecurityError(str(exc)) from exc
            aces.append(f"(A;;GA;;;{s})")
    return "D:P" + "".join(aces)


def _apply_key_sddl_descriptor(nc: ctypes.WinDLL, h_key: ctypes.c_void_p, sddl: str, *, persist: bool = False) -> None:
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    k32.LocalFree.restype = ctypes.c_void_p

    p_sd = ctypes.c_void_p()
    sd_size = wintypes.ULONG(0)
    ok = adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        ctypes.c_wchar_p(sddl),
        1,  # SDDL_REVISION_1
        ctypes.byref(p_sd),
        ctypes.byref(sd_size),
    )
    if not ok or not p_sd.value:
        raise BrokerCngError(
            f"Failed to compile CNG key SDDL '{sddl}' (Win32 Error {ctypes.get_last_error()}).",
            code=ERR_CNG_ERROR,
        )
    try:
        flags = DACL_SECURITY_INFORMATION
        if persist:
            flags |= NCRYPT_PERSIST_FLAG
        st = nc.NCryptSetProperty(
            h_key,
            ctypes.c_wchar_p(NCRYPT_SECURITY_DESCR_PROPERTY),
            p_sd,
            sd_size.value,
            flags,
        )
        if st != 0:
            raise BrokerCngError(
                f"NCryptSetProperty(Security Descr) failed with status {_status_hex(st)}.",
                code=ERR_CNG_ERROR,
                data={"status": _status_hex(st), "sddl": sddl},
            )
    finally:
        k32.LocalFree(p_sd)


def probe_tpm_device() -> dict[str, Any]:
    """Query native Windows TBS (`tbs.dll`) for TPM device presence and version."""
    if not is_windows():
        return {"supported": False, "tpm_present": False}
    try:
        tbs = ctypes.WinDLL("tbs.dll")
        tbs.Tbsi_GetDeviceInfo.argtypes = [wintypes.DWORD, ctypes.c_void_p]
        tbs.Tbsi_GetDeviceInfo.restype = ctypes.c_uint32
        info = _TbsDeviceInfo()
        rc = tbs.Tbsi_GetDeviceInfo(ctypes.sizeof(info), ctypes.byref(info))
        return {
            "supported": True,
            "tbs_rc": hex(rc),
            "tpm_present": rc == 0,
            "tpm_version": int(info.tpmVersion) if rc == 0 else None,
            "tpm_interface_type": int(info.tpmInterfaceType) if rc == 0 else None,
        }
    except Exception as exc:
        return {"supported": False, "tpm_present": False, "error": str(exc)}


def probe_cng_provider(provider_name: str) -> dict[str, Any]:
    """Open *provider_name* read-only and query OS-reported `Impl Type` hardware backing."""
    if not is_windows():
        return {"supported": False, "available": False, "tpm_backed": False}
    nc = _win32_ncrypt()
    h_prov = ctypes.c_void_p()
    st = nc.NCryptOpenStorageProvider(ctypes.byref(h_prov), ctypes.c_wchar_p(provider_name), 0)
    if st != 0 or not h_prov.value:
        return {
            "provider_name": provider_name,
            "available": False,
            "open_status": _status_hex(st),
            "tpm_backed": False,
            "impl_type": None,
        }
    try:
        impl = wintypes.DWORD(0)
        cb = wintypes.DWORD(0)
        st_prop = nc.NCryptGetProperty(
            h_prov,
            ctypes.c_wchar_p(NCRYPT_IMPL_TYPE_PROPERTY),
            ctypes.byref(impl),
            ctypes.sizeof(impl),
            ctypes.byref(cb),
            0,
        )
        impl_val = int(impl.value) if st_prop == 0 else 0
        # Hardware-backed ONLY if HARDWARE flag is set and SOFTWARE flag is absent
        hw = bool(impl_val & NCRYPT_IMPL_HARDWARE_FLAG) and not bool(impl_val & NCRYPT_IMPL_SOFTWARE_FLAG)
        return {
            "provider_name": provider_name,
            "available": True,
            "open_status": "0x0",
            "impl_type": impl_val,
            "impl_type_hex": hex(impl_val),
            "tpm_backed": hw,
        }
    finally:
        nc.NCryptFreeObject(h_prov)


def verify_cng_ecdsa_p256_signature(public_key_blob: bytes, digest: bytes, signature: bytes) -> bool:
    """Verify IEEE P1363 ECDSA_P256 signature (`r || s`, 64 bytes) via Windows `bcrypt.dll`."""
    if not is_windows():
        raise BrokerCngError("BCrypt ECDSA_P256 verification requires Windows.", code=ERR_CNG_ERROR)
    if len(public_key_blob) != 72 or public_key_blob[:4] != b"ECS1":
        return False
    if len(signature) != 64 or len(digest) != 32:
        return False

    bc = _win32_bcrypt()
    h_alg = ctypes.c_void_p()
    h_key = ctypes.c_void_p()
    st_alg = bc.BCryptOpenAlgorithmProvider(
        ctypes.byref(h_alg), ctypes.c_wchar_p(BCRYPT_ECDSA_P256_ALGORITHM), None, 0
    )
    if st_alg != 0 or not h_alg.value:
        raise BrokerCngError(
            f"BCryptOpenAlgorithmProvider(ECDSA_P256) failed: {_status_hex(st_alg)}",
            code=ERR_CNG_ERROR,
        )
    try:
        pub_buf = (ctypes.c_ubyte * len(public_key_blob)).from_buffer_copy(public_key_blob)
        st_imp = bc.BCryptImportKeyPair(
            h_alg, None, ctypes.c_wchar_p(BCRYPT_ECCPUBLIC_BLOB),
            ctypes.byref(h_key), pub_buf, len(public_key_blob), 0,
        )
        if st_imp != 0 or not h_key.value:
            return False
        try:
            dig_buf = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
            sig_buf = (ctypes.c_ubyte * len(signature)).from_buffer_copy(signature)
            st_ver = bc.BCryptVerifySignature(
                h_key, None, dig_buf, len(digest), sig_buf, len(signature), 0
            )
            return st_ver == 0
        finally:
            bc.BCryptDestroyKey(h_key)
    finally:
        bc.BCryptCloseAlgorithmProvider(h_alg, 0)


@dataclass(frozen=True)
class CngKeyMetadata:
    """Non-secret metadata describing a persisted CNG/TPM signing key."""

    key_name: str
    key_id: str
    provider_name: str
    algorithm: str
    tpm_backed: bool
    impl_type_hex: str
    machine_key: bool
    export_policy: int
    key_usage: int
    version: int
    public_key_hex: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_name": self.key_name,
            "key_id": self.key_id,
            "provider_name": self.provider_name,
            "algorithm": self.algorithm,
            "tpm_backed": self.tpm_backed,
            "impl_type_hex": self.impl_type_hex,
            "machine_key": self.machine_key,
            "export_policy": self.export_policy,
            "key_usage": self.key_usage,
            "version": self.version,
            "public_key_hex": self.public_key_hex,
        }


class CngCbeatSigner(CbeatSigner):
    """Windows CNG / TPM 2.0 persisted non-exportable ECDSA_P256 CBEAT signer.

    Never reads private key material into Python process memory.
    Fails closed when TPM is required (`require_tpm=True`) and unavailable.
    """

    def __init__(
        self,
        key_name: str,
        *,
        provider_name: str | None = None,
        require_tpm: bool = True,
        allow_software_ksp: bool = False,
        machine_key: bool = True,
        algorithm: str = NCRYPT_ECDSA_P256_ALGORITHM,
        exportable: bool = False,
        create_if_missing: bool = True,
        overwrite: bool = False,
        key_sddl: str | None = None,
        allowed_key_sids: list[str] | tuple[str, ...] | None = None,
        version: int = 1,
        _ncrypt_loader: Any = None,
    ) -> None:
        if exportable:
            raise BrokerSecurityError(
                "Invalid key property: exportable=True is strictly forbidden for CNG CBEAT custody."
            )
        validate_cng_algorithm(algorithm)
        validated_name = validate_test_key_name(key_name)

        if provider_name is None:
            provider_name = MS_PLATFORM_CRYPTO_PROVIDER if require_tpm else MS_KEY_STORAGE_PROVIDER

        if require_tpm and provider_name != MS_PLATFORM_CRYPTO_PROVIDER:
            raise BrokerTpmUnavailableError(
                f"TPM_UNAVAILABLE: require_tpm=True cannot use non-TPM provider '{provider_name}'."
            )
        if provider_name == MS_KEY_STORAGE_PROVIDER and not allow_software_ksp:
            raise BrokerSecurityError(
                "Software KSP requires explicit allow_software_ksp=True for test-only qualification; "
                "silent fallback is prohibited."
            )
        if not is_windows() and _ncrypt_loader is None:
            raise BrokerCngError("Windows CNG key custody requires Windows.", code=ERR_CNG_ERROR)

        if key_sddl is None and allowed_key_sids is not None:
            key_sddl = build_key_dacl_sddl(allowed_key_sids)

        self._nc = _ncrypt_loader() if _ncrypt_loader is not None else _win32_ncrypt()
        self._lock = threading.RLock()
        self._provider_name = provider_name
        self._base_key_name = validated_name
        self._key_name = validated_name
        self._require_tpm = bool(require_tpm)
        self._allow_software_ksp = bool(allow_software_ksp)
        self._machine_key = bool(machine_key)
        self._algorithm = algorithm
        self._key_sddl = key_sddl
        self._version = int(version)
        self._closed = False

        self._h_prov = ctypes.c_void_p()
        self._h_key = ctypes.c_void_p()
        self._public_key_bytes = b""
        self._tpm_backed = False
        self._impl_type = 0
        self._key_history: dict[str, bytes] = {}

        try:
            self._open_provider_and_verify_backing()
            self._open_or_create_key(create_if_missing=create_if_missing, overwrite=overwrite)
            self._key_history[self.key_id] = self._public_key_bytes
        except Exception:
            self.close()
            raise

    def _open_provider_and_verify_backing(self) -> None:
        st = self._nc.NCryptOpenStorageProvider(
            ctypes.byref(self._h_prov), ctypes.c_wchar_p(self._provider_name), 0
        )
        if st != 0 or not self._h_prov.value:
            err_cls = BrokerTpmUnavailableError if self._require_tpm else BrokerCngError
            code = ERR_TPM_UNAVAILABLE if self._require_tpm else ERR_CNG_ERROR
            raise err_cls(
                f"{'TPM_UNAVAILABLE' if self._require_tpm else 'CNG_PROVIDER_UNAVAILABLE'}: "
                f"NCryptOpenStorageProvider('{self._provider_name}') failed with {_status_hex(st)}.",
                code=code,
                data={"provider": self._provider_name, "status": _status_hex(st)},
            )

        impl = wintypes.DWORD(0)
        cb = wintypes.DWORD(0)
        st_prop = self._nc.NCryptGetProperty(
            self._h_prov,
            ctypes.c_wchar_p(NCRYPT_IMPL_TYPE_PROPERTY),
            ctypes.byref(impl),
            ctypes.sizeof(impl),
            ctypes.byref(cb),
            0,
        )
        if st_prop != 0:
            if self._require_tpm:
                raise BrokerTpmUnavailableError(
                    f"TPM_UNAVAILABLE: Unable to verify Impl Type for '{self._provider_name}' ({_status_hex(st_prop)})."
                )
            self._impl_type = 0
            self._tpm_backed = False
        else:
            self._impl_type = int(impl.value)
            self._tpm_backed = bool(self._impl_type & NCRYPT_IMPL_HARDWARE_FLAG) and not bool(
                self._impl_type & NCRYPT_IMPL_SOFTWARE_FLAG
            )

        if self._require_tpm and not self._tpm_backed:
            raise BrokerTpmUnavailableError(
                f"TPM_UNAVAILABLE: Provider '{self._provider_name}' Impl Type {hex(self._impl_type)} "
                "does not prove hardware TPM backing."
            )
        if not self._tpm_backed and not self._allow_software_ksp:
            raise BrokerTpmUnavailableError(
                f"TPM_UNAVAILABLE: Non-hardware provider '{self._provider_name}' (Impl Type {hex(self._impl_type)}) "
                "requires explicit allow_software_ksp=True."
            )

    def _open_or_create_key(self, *, create_if_missing: bool, overwrite: bool) -> None:
        base_flags = NCRYPT_SILENT_FLAG | (NCRYPT_MACHINE_KEY_FLAG if self._machine_key else 0)
        if not overwrite:
            h_existing = ctypes.c_void_p()
            st_open = self._nc.NCryptOpenKey(
                self._h_prov,
                ctypes.byref(h_existing),
                ctypes.c_wchar_p(self._key_name),
                0,
                base_flags,
            )
            if st_open == 0 and h_existing.value:
                self._h_key = h_existing
                self._verify_opened_key_properties()
                self._public_key_bytes = self._export_public_key_blob()
                return
            if not create_if_missing:
                raise BrokerCngError(
                    f"Persisted CNG key '{self._key_name}' not found (status {_status_hex(st_open)}).",
                    code=ERR_CNG_ERROR,
                    data={"key_name": self._key_name, "status": _status_hex(st_open)},
                )

        create_flags = (NCRYPT_MACHINE_KEY_FLAG if self._machine_key else 0) | (
            NCRYPT_OVERWRITE_KEY_FLAG if overwrite else 0
        )
        h_new = ctypes.c_void_p()
        st_cr = self._nc.NCryptCreatePersistedKey(
            self._h_prov,
            ctypes.byref(h_new),
            ctypes.c_wchar_p(self._algorithm),
            ctypes.c_wchar_p(self._key_name),
            0,
            create_flags,
        )
        if st_cr != 0 or not h_new.value:
            raise BrokerCngError(
                f"NCryptCreatePersistedKey('{self._key_name}', '{self._algorithm}') failed: {_status_hex(st_cr)}.",
                code=ERR_CNG_ERROR,
                data={"key_name": self._key_name, "provider": self._provider_name, "status": _status_hex(st_cr)},
            )
        self._h_key = h_new

        # Enforce non-exportability BEFORE finalize
        exp_policy = wintypes.DWORD(NCRYPT_ALLOW_EXPORT_NONE)
        st_exp = self._nc.NCryptSetProperty(
            self._h_key,
            ctypes.c_wchar_p(NCRYPT_EXPORT_POLICY_PROPERTY),
            ctypes.byref(exp_policy),
            ctypes.sizeof(exp_policy),
            0,
        )
        if st_exp != 0:
            raise BrokerCngError(
                f"NCryptSetProperty(Export Policy=0) failed: {_status_hex(st_exp)}.",
                code=ERR_CNG_ERROR,
            )

        # Restrict usage to signing only
        usage = wintypes.DWORD(NCRYPT_ALLOW_SIGNING_FLAG)
        st_use = self._nc.NCryptSetProperty(
            self._h_key,
            ctypes.c_wchar_p(NCRYPT_KEY_USAGE_PROPERTY),
            ctypes.byref(usage),
            ctypes.sizeof(usage),
            0,
        )
        if st_use != 0:
            raise BrokerCngError(
                f"NCryptSetProperty(Key Usage=SIGNING) failed: {_status_hex(st_use)}.",
                code=ERR_CNG_ERROR,
            )

        if self._key_sddl:
            _apply_key_sddl_descriptor(self._nc, self._h_key, self._key_sddl, persist=False)

        st_fin = self._nc.NCryptFinalizeKey(self._h_key, 0)
        if st_fin != 0:
            raise BrokerCngError(
                f"NCryptFinalizeKey('{self._key_name}') failed: {_status_hex(st_fin)}.",
                code=ERR_CNG_ERROR,
                data={"status": _status_hex(st_fin)},
            )
        self._public_key_bytes = self._export_public_key_blob()

    def _verify_opened_key_properties(self) -> None:
        exp = wintypes.DWORD(0)
        cb = wintypes.DWORD(0)
        st = self._nc.NCryptGetProperty(
            self._h_key,
            ctypes.c_wchar_p(NCRYPT_EXPORT_POLICY_PROPERTY),
            ctypes.byref(exp),
            ctypes.sizeof(exp),
            ctypes.byref(cb),
            0,
        )
        if st == 0 and exp.value != NCRYPT_ALLOW_EXPORT_NONE:
            raise BrokerSecurityError(
                f"Opened CNG key '{self._key_name}' has forbidden Export Policy={hex(exp.value)}."
            )

    def _export_public_key_blob(self) -> bytes:
        pcb = wintypes.DWORD(0)
        st1 = self._nc.NCryptExportKey(
            self._h_key, None, ctypes.c_wchar_p(BCRYPT_ECCPUBLIC_BLOB),
            None, None, 0, ctypes.byref(pcb), 0,
        )
        if st1 != 0 or pcb.value == 0:
            raise BrokerCngError(
                f"NCryptExportKey(ECCPUBLICBLOB size query) failed: {_status_hex(st1)}.",
                code=ERR_CNG_ERROR,
            )
        buf = (ctypes.c_ubyte * pcb.value)()
        st2 = self._nc.NCryptExportKey(
            self._h_key, None, ctypes.c_wchar_p(BCRYPT_ECCPUBLIC_BLOB),
            None, buf, pcb.value, ctypes.byref(pcb), 0,
        )
        if st2 != 0:
            raise BrokerCngError(
                f"NCryptExportKey(ECCPUBLICBLOB) failed: {_status_hex(st2)}.",
                code=ERR_CNG_ERROR,
            )
        return bytes(buf[: pcb.value])

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self._public_key_bytes).hexdigest()[:16]

    @property
    def metadata(self) -> CngKeyMetadata:
        return CngKeyMetadata(
            key_name=self._key_name,
            key_id=self.key_id,
            provider_name=self._provider_name,
            algorithm=CBEAT_ALG_CNG_ECDSA_P256,
            tpm_backed=self._tpm_backed,
            impl_type_hex=hex(self._impl_type),
            machine_key=self._machine_key,
            export_policy=NCRYPT_ALLOW_EXPORT_NONE,
            key_usage=NCRYPT_ALLOW_SIGNING_FLAG,
            version=self._version,
            public_key_hex=self._public_key_bytes.hex(),
        )

    @property
    def trusted_public_keys(self) -> dict[str, bytes]:
        return dict(self._key_history)

    def get_public_key_bytes(self) -> bytes:
        if self._closed:
            raise BrokerCngError("CNG signer has been closed.", code=ERR_CNG_ERROR)
        return self._public_key_bytes

    def probe_private_key_export_denied(self) -> dict[str, Any]:
        """Negatively verify that private key export fails fail-closed in OS provider."""
        with self._lock:
            if self._closed or not self._h_key.value:
                raise BrokerCngError("CNG key handle is closed.", code=ERR_CNG_ERROR)
            results: dict[str, Any] = {}
            for blob_type in (BCRYPT_ECCPRIVATE_BLOB, PKCS8_PRIVATE_KEY_BLOB):
                pcb = wintypes.DWORD(0)
                st = self._nc.NCryptExportKey(
                    self._h_key, None, ctypes.c_wchar_p(blob_type),
                    None, None, 0, ctypes.byref(pcb), 0,
                )
                results[blob_type] = {
                    "denied": st != 0,
                    "status": _status_hex(st),
                }
            all_denied = all(v["denied"] for v in results.values())
            return {"all_private_exports_denied": all_denied, "probes": results}

    def sign_digest(self, digest: bytes) -> bytes:
        """Sign a 32-byte SHA-256 digest inside the CNG/TPM provider."""
        if len(digest) != 32:
            raise BrokerSchemaError("CNG ECDSA_P256 signing requires a 32-byte SHA-256 digest.")
        with self._lock:
            if self._closed or not self._h_key.value:
                raise BrokerCngError("CNG signer handle is closed.", code=ERR_CNG_ERROR)
            dig_buf = (ctypes.c_ubyte * 32).from_buffer_copy(digest)
            sig_len = wintypes.DWORD(0)
            st1 = self._nc.NCryptSignHash(
                self._h_key, None, dig_buf, 32, None, 0, ctypes.byref(sig_len), NCRYPT_SILENT_FLAG
            )
            if st1 != 0 or sig_len.value == 0:
                raise BrokerCngError(
                    f"NCryptSignHash(size query) failed: {_status_hex(st1)}.",
                    code=ERR_CNG_ERROR,
                    data={"status": _status_hex(st1)},
                )
            sig_buf = (ctypes.c_ubyte * sig_len.value)()
            st2 = self._nc.NCryptSignHash(
                self._h_key, None, dig_buf, 32, sig_buf, sig_len.value, ctypes.byref(sig_len), NCRYPT_SILENT_FLAG
            )
            if st2 != 0:
                raise BrokerCngError(
                    f"NCryptSignHash failed: {_status_hex(st2)}.",
                    code=ERR_CNG_ERROR,
                    data={"status": _status_hex(st2)},
                )
            return bytes(sig_buf[: sig_len.value])

    def sign_payload(self, payload: CbeatPayload) -> CbeatToken:
        """Sign canonical CBEAT payload with domain separation using CNG/TPM key."""
        digest = hashlib.sha256(CBEAT_CNG_DOMAIN_SEP + payload.canonical_bytes()).digest()
        sig = self.sign_digest(digest)
        return CbeatToken(
            payload=payload,
            signature_hex=sig.hex(),
            public_key_hex=self._public_key_bytes.hex(),
            signature_algorithm=CBEAT_ALG_CNG_ECDSA_P256,
            key_id=self.key_id,
            tpm_backed=self._tpm_backed,
        )

    def rotate_key(self, *, delete_previous: bool = False) -> dict[str, Any]:
        """Rotate to a new persisted CNG key version while retaining public-key history."""
        with self._lock:
            if self._closed:
                raise BrokerCngError("Cannot rotate a closed CNG signer.", code=ERR_CNG_ERROR)
            old_key_name = self._key_name
            old_key_id = self.key_id
            old_h_key = self._h_key
            new_version = self._version + 1
            base_root = self._base_key_name
            new_key_name = validate_test_key_name(f"{base_root}_v{new_version}")

            self._h_key = ctypes.c_void_p()
            self._key_name = new_key_name
            self._version = new_version
            try:
                self._open_or_create_key(create_if_missing=True, overwrite=True)
                self._key_history[self.key_id] = self._public_key_bytes
            except Exception:
                # Roll back handle state if rotation fails
                self._key_name = old_key_name
                self._version = new_version - 1
                if self._h_key.value:
                    self._nc.NCryptFreeObject(self._h_key)
                self._h_key = old_h_key
                raise

            if old_h_key.value:
                if delete_previous:
                    self._nc.NCryptDeleteKey(old_h_key, 0)
                else:
                    self._nc.NCryptFreeObject(old_h_key)

            return {
                "rotated": True,
                "previous_key_name": old_key_name,
                "previous_key_id": old_key_id,
                "new_key_name": self._key_name,
                "new_key_id": self.key_id,
                "version": self._version,
                "tpm_backed": self._tpm_backed,
            }

    def delete_key(self) -> dict[str, Any]:
        """Permanently delete the active persisted test CNG key and free handles."""
        with self._lock:
            name = self._key_name
            deleted = False
            status_hex = "0x0"
            if self._h_key.value:
                st = self._nc.NCryptDeleteKey(self._h_key, 0)
                status_hex = _status_hex(st)
                if st == 0:
                    deleted = True
                    self._h_key = ctypes.c_void_p()
                else:
                    self._nc.NCryptFreeObject(self._h_key)
                    self._h_key = ctypes.c_void_p()
                    raise BrokerCngError(
                        f"NCryptDeleteKey('{name}') failed: {status_hex}.",
                        code=ERR_CNG_ERROR,
                    )
            self.close()
            return {"deleted": deleted, "key_name": name, "status": status_hex}

    def close(self) -> None:
        """Deterministically free CNG key and provider handles."""
        with self._lock:
            self._closed = True
            if self._h_key.value:
                try:
                    self._nc.NCryptFreeObject(self._h_key)
                finally:
                    self._h_key = ctypes.c_void_p()
            if self._h_prov.value:
                try:
                    self._nc.NCryptFreeObject(self._h_prov)
                finally:
                    self._h_prov = ctypes.c_void_p()

    def __enter__(self) -> "CngCbeatSigner":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

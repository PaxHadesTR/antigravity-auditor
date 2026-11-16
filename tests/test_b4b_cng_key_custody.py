"""Comprehensive tests for NEXT-21C-B4-B CNG / TPM 2.0 Key Custody (B4B-CNG).

Validates real Windows `ncrypt.dll` / `bcrypt.dll` / `tbs.dll` behavior with zero mocked
crypto and deterministic persisted-key cleanup:
1. Key creation (hardware TPM PCP and explicit test Software KSP).
2. Persistence across reopening and independent subprocess restart.
3. Signing + BCryptVerifySignature verification.
4. Negative private key export proofs (ECCPRIVATEBLOB & PKCS8_PRIVATEKEY).
5. Key ACL isolation via NCRYPT_SECURITY_DESCR_PROPERTY & restricted-process denial.
6. Unavailable provider fail-closed behavior.
7. require_tpm=True fail-closed behavior (zero silent fallback).
8. Unsupported algorithm rejection.
9. Invalid exportable=True property rejection.
10. NCryptDeleteKey deletion & create_if_missing=False fail-closed.
11. Reinitialization after deletion creates distinct fresh key.
12. Key rotation retaining historical public keys in CbeatVerifier & delete_previous cleanup.
13. CbeatToken / CbeatVerifier wire compatibility & algorithm downgrade rejection.
14. Concurrent signing threads & deterministic handle closure.
15. Production key namespace isolation.
16. Live TPM & CNG provider hardware probes.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from broker.cbeat import (
    CBEAT_ALG_CNG_ECDSA_P256,
    CBEAT_ALG_ED25519,
    CBEAT_CNG_DOMAIN_SEP,
    CbeatVerifier,
    EphemeralCbeatSigner,
    build_cbeat_payload,
)
from broker.cng import (
    MS_KEY_STORAGE_PROVIDER,
    MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_ALLOW_EXPORT_NONE,
    NCRYPT_ALLOW_SIGNING_FLAG,
    NCRYPT_MACHINE_KEY_FLAG,
    PRODUCTION_KEY_NAMES,
    CngCbeatSigner,
    build_key_dacl_sddl,
    probe_cng_provider,
    probe_tpm_device,
    validate_cng_algorithm,
    validate_test_key_name,
    verify_cng_ecdsa_p256_signature,
)
from broker.constants import B4B_TEST_KEY_PREFIX
from broker.exceptions import (
    BrokerCngError,
    BrokerSchemaError,
    BrokerSecurityError,
    BrokerTpmUnavailableError,
)


def _unique_test_key(tag: str) -> str:
    return f"{B4B_TEST_KEY_PREFIX}{tag}_{uuid.uuid4().hex[:10]}"


def _cleanup_signer_key(key_name: str, provider_name: str, *, allow_software_ksp: bool, require_tpm: bool) -> None:
    try:
        signer = CngCbeatSigner(
            key_name,
            provider_name=provider_name,
            require_tpm=require_tpm,
            allow_software_ksp=allow_software_ksp,
            create_if_missing=False,
        )
        signer.delete_key()
    except Exception:
        pass


def _make_sample_payload() -> object:
    return build_cbeat_payload(
        approval_id=f"appr_{uuid.uuid4().hex[:12]}",
        project_key="proj_b4b_test",
        repo_path=r"C:\Temp\DisposRepo",
        run_id="run_b4b_001",
        base_commit="a" * 40,
        execution_id=f"exec_{uuid.uuid4().hex[:12]}",
        approved_finding_ids=["F-001", "F-002"],
        evidence_digest="b" * 64,
        allowed_scope_digest="c" * 64,
        test_policy_digest="d" * 64,
        max_repair_attempts=2,
        ttl_seconds=600,
    )


def _current_user_sid() -> str:
    """Resolve current Windows user SID string cleanly without shell tools."""
    import ctypes.wintypes as wt

    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h_tok = ctypes.c_void_p()
    TOKEN_QUERY = 0x0008
    TokenUser = 1
    assert adv.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(h_tok))
    try:
        needed = wt.DWORD(0)
        adv.GetTokenInformation(h_tok, TokenUser, None, 0, ctypes.byref(needed))
        buf = (ctypes.c_ubyte * needed.value)()
        assert adv.GetTokenInformation(h_tok, TokenUser, buf, needed.value, ctypes.byref(needed))
        psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        pstr = wt.LPWSTR()
        assert adv.ConvertSidToStringSidW(psid, ctypes.byref(pstr))
        try:
            return str(pstr.value)
        finally:
            k32.LocalFree(pstr)
    finally:
        k32.CloseHandle(h_tok)


def test_b4b_live_tpm_and_cng_provider_probes() -> None:
    """16. Live TPM & CNG provider hardware probes return accurate OS status."""
    tpm = probe_tpm_device()
    assert tpm["supported"] is True
    assert tpm["tpm_present"] is True
    assert tpm["tpm_version"] == 2

    pcp = probe_cng_provider(MS_PLATFORM_CRYPTO_PROVIDER)
    assert pcp["available"] is True
    assert pcp["tpm_backed"] is True
    assert pcp["impl_type"] == 0x1

    ksp = probe_cng_provider(MS_KEY_STORAGE_PROVIDER)
    assert ksp["available"] is True
    assert ksp["tpm_backed"] is False


@pytest.mark.parametrize(
    "provider,require_tpm,allow_ksp",
    [
        (MS_PLATFORM_CRYPTO_PROVIDER, True, False),
        (MS_KEY_STORAGE_PROVIDER, False, True),
    ],
)
def test_b4b_cng_key_lifecycle_persist_sign_export_denial_and_delete(
    provider: str, require_tpm: bool, allow_ksp: bool
) -> None:
    """Tests 1, 2, 3, 4, 10, 11 across both TPM PCP and explicit test Software KSP."""
    key_name = _unique_test_key("lifecycle")
    try:
        # 1. Creation & non-exportable metadata
        with CngCbeatSigner(
            key_name,
            provider_name=provider,
            require_tpm=require_tpm,
            allow_software_ksp=allow_ksp,
            create_if_missing=True,
        ) as signer1:
            meta = signer1.metadata
            assert meta.key_name == key_name
            assert meta.provider_name == provider
            assert meta.tpm_backed is require_tpm
            assert meta.export_policy == NCRYPT_ALLOW_EXPORT_NONE
            assert meta.key_usage == NCRYPT_ALLOW_SIGNING_FLAG
            pub1 = signer1.get_public_key_bytes()
            assert len(pub1) == 72 and pub1[:4] == b"ECS1"

            # 4. Private key export denial (ECCPRIVATEBLOB & PKCS8_PRIVATEKEY)
            export_probe = signer1.probe_private_key_export_denied()
            assert export_probe["all_private_exports_denied"] is True
            assert export_probe["probes"]["ECCPRIVATEBLOB"]["denied"] is True
            assert export_probe["probes"]["PKCS8_PRIVATEKEY"]["denied"] is True

            # 3. Sign & BCryptVerifySignature
            payload = _make_sample_payload()
            token = signer1.sign_payload(payload)
            assert token.signature_algorithm == CBEAT_ALG_CNG_ECDSA_P256
            assert token.tpm_backed is require_tpm
            assert token.key_id == signer1.key_id

            verifier = CbeatVerifier(
                trusted_public_keys=signer1.trusted_public_keys,
                require_cng=True,
            )
            ok, msg, decoded = verifier.verify_signature(token.to_dict())
            assert ok is True, msg
            assert decoded is not None
            assert decoded.execution_id == payload.execution_id

        # 2a. Persistence across same-process reopen
        with CngCbeatSigner(
            key_name,
            provider_name=provider,
            require_tpm=require_tpm,
            allow_software_ksp=allow_ksp,
            create_if_missing=False,
        ) as signer2:
            assert signer2.get_public_key_bytes() == pub1
            assert signer2.key_id == hashlib.sha256(pub1).hexdigest()[:16]

        # 2b. Persistence across fresh subprocess restart + real cross-process verify
        core_dir = str(Path(__file__).resolve().parents[1] / "core")
        script = (
            "import json, sys; "
            f"sys.path.insert(0, {core_dir!r}); "
            "from broker.cng import CngCbeatSigner; "
            f"s = CngCbeatSigner({key_name!r}, provider_name={provider!r}, "
            f"require_tpm={require_tpm!r}, allow_software_ksp={allow_ksp!r}, create_if_missing=False); "
            "d = b'A' * 32; "
            "sig = s.sign_digest(d); "
            "pub = s.get_public_key_bytes(); "
            "s.close(); "
            "print(json.dumps({'pub': pub.hex(), 'sig': sig.hex()}))"
        )
        proc = subprocess.run(
            [sys.executable, "-B", "-c", script],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        out = json.loads(proc.stdout.strip())
        assert bytes.fromhex(out["pub"]) == pub1
        assert verify_cng_ecdsa_p256_signature(pub1, b"A" * 32, bytes.fromhex(out["sig"])) is True

        # 10. Deletion + create_if_missing=False fails closed
        with CngCbeatSigner(
            key_name,
            provider_name=provider,
            require_tpm=require_tpm,
            allow_software_ksp=allow_ksp,
            create_if_missing=False,
        ) as signer3:
            del_res = signer3.delete_key()
            assert del_res["deleted"] is True

        with pytest.raises(BrokerCngError, match="not found"):
            CngCbeatSigner(
                key_name,
                provider_name=provider,
                require_tpm=require_tpm,
                allow_software_ksp=allow_ksp,
                create_if_missing=False,
            )

        # 11. Reinitialization after deletion creates a brand new distinct keypair
        with CngCbeatSigner(
            key_name,
            provider_name=provider,
            require_tpm=require_tpm,
            allow_software_ksp=allow_ksp,
            create_if_missing=True,
        ) as signer4:
            pub4 = signer4.get_public_key_bytes()
            assert pub4 != pub1
            assert signer4.delete_key()["deleted"] is True
    finally:
        _cleanup_signer_key(key_name, provider, allow_software_ksp=allow_ksp, require_tpm=require_tpm)


def test_b4b_cng_acl_isolation_and_restricted_access() -> None:
    """5. NCRYPT_SECURITY_DESCR_PROPERTY ACL isolation denies unauthorized callers."""
    key_name = _unique_test_key("acl")
    # SDDL strictly limiting key access to SYSTEM + Builtin Administrators (excluding current user standard non-elevated/restricted token)
    sddl_admins_only = build_key_dacl_sddl(None)
    assert "(A;;GA;;;SY)(A;;GA;;;BA)" in sddl_admins_only
    assert "WD" not in sddl_admins_only and "BU" not in sddl_admins_only

    # Broad SIDs must be rejected upfront
    for broad in ("WD", "BU", "AU", "S-1-1-0", "S-1-5-11", "S-1-5-32-545"):
        with pytest.raises(BrokerSecurityError, match="forbidden"):
            build_key_dacl_sddl([broad])

    # Software KSP natively supports persisted NCRYPT_SECURITY_DESCR_PROPERTY ACL enforcement
    try:
        with CngCbeatSigner(
            key_name,
            provider_name=MS_KEY_STORAGE_PROVIDER,
            require_tpm=False,
            allow_software_ksp=True,
            key_sddl=sddl_admins_only,
        ) as signer:
            assert signer.metadata.export_policy == 0

            # Impersonate a restricted token (BUILTIN\Administrators disabled + privileges dropped)
            # to prove real Windows OS ACL enforcement denies opening the SYSTEM/BA-only key.
            denied, err_msg = _open_key_under_restricted_impersonation(
                key_name, MS_KEY_STORAGE_PROVIDER, require_tpm=False, allow_software_ksp=True
            )
            assert denied is True, f"Restricted non-admin token unexpectedly accessed SYSTEM/BA-only CNG key! ({err_msg})"
    finally:
        _cleanup_signer_key(key_name, MS_KEY_STORAGE_PROVIDER, allow_software_ksp=True, require_tpm=False)

    # Also verify Platform Crypto Provider key ACL behavior empirically
    pcp_key = _unique_test_key("pcp_acl")
    try:
        with CngCbeatSigner(
            pcp_key,
            provider_name=MS_PLATFORM_CRYPTO_PROVIDER,
            require_tpm=True,
            key_sddl=sddl_admins_only,
        ) as pcp_signer:
            assert pcp_signer.metadata.tpm_backed is True
            denied_pcp, err_pcp = _open_key_under_restricted_impersonation(
                pcp_key, MS_PLATFORM_CRYPTO_PROVIDER, require_tpm=True, allow_software_ksp=False
            )
            assert denied_pcp is True, f"Restricted non-admin token unexpectedly accessed SYSTEM/BA-only PCP key! ({err_pcp})"
    finally:
        _cleanup_signer_key(pcp_key, MS_PLATFORM_CRYPTO_PROVIDER, allow_software_ksp=False, require_tpm=True)


def _open_key_under_restricted_impersonation(
    key_name: str, provider_name: str, *, require_tpm: bool, allow_software_ksp: bool
) -> tuple[bool, str]:
    """Impersonate a CreateRestrictedToken thread (BA deny-only, privileges dropped) and attempt key open."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    DISABLE_MAX_PRIVILEGE = 0x1
    TOKEN_DUPLICATE = 0x0002
    TOKEN_IMPERSONATE = 0x0004
    TOKEN_QUERY = 0x0008
    SecurityImpersonation = 2

    k32.GetCurrentProcess.argtypes = []
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    k32.LocalFree.restype = ctypes.c_void_p

    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    adv.ConvertStringSidToSidW.restype = wintypes.BOOL
    adv.CreateRestrictedToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(SID_AND_ATTRIBUTES),
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    adv.CreateRestrictedToken.restype = wintypes.BOOL
    adv.DuplicateToken.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
    adv.DuplicateToken.restype = wintypes.BOOL
    adv.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
    adv.ImpersonateLoggedOnUser.restype = wintypes.BOOL
    adv.RevertToSelf.argtypes = []
    adv.RevertToSelf.restype = wintypes.BOOL

    h_cur = wintypes.HANDLE()
    assert adv.OpenProcessToken(
        k32.GetCurrentProcess(),
        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
        ctypes.byref(h_cur),
    ), f"OpenProcessToken failed: {ctypes.get_last_error()}"

    p_ba_sid = ctypes.c_void_p()
    assert adv.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(p_ba_sid))

    h_rest = wintypes.HANDLE()
    h_imp = wintypes.HANDLE()
    try:
        sids_to_disable = (SID_AND_ATTRIBUTES * 1)()
        sids_to_disable[0].Sid = p_ba_sid
        sids_to_disable[0].Attributes = 0
        ok = adv.CreateRestrictedToken(
            h_cur, DISABLE_MAX_PRIVILEGE, 1, sids_to_disable, 0, None, 0, None, ctypes.byref(h_rest)
        )
        assert ok, f"CreateRestrictedToken failed: {ctypes.get_last_error()}"
        ok_dup = adv.DuplicateToken(h_rest, SecurityImpersonation, ctypes.byref(h_imp))
        assert ok_dup, f"DuplicateToken failed: {ctypes.get_last_error()}"

        assert adv.ImpersonateLoggedOnUser(h_imp), f"ImpersonateLoggedOnUser failed: {ctypes.get_last_error()}"
        try:
            try:
                with CngCbeatSigner(
                    key_name,
                    provider_name=provider_name,
                    require_tpm=require_tpm,
                    allow_software_ksp=allow_software_ksp,
                    create_if_missing=False,
                ):
                    return False, "unexpectedly opened"
            except Exception as exc:
                return True, str(exc)
        finally:
            adv.RevertToSelf()
    finally:
        if h_imp.value:
            k32.CloseHandle(h_imp)
        if h_rest.value:
            k32.CloseHandle(h_rest)
        if p_ba_sid.value:
            k32.LocalFree(p_ba_sid)
        k32.CloseHandle(h_cur)


def test_b4b_cng_provider_unavailable_and_require_tpm_fail_closed() -> None:
    """6 & 7. Unavailable provider and require_tpm=True fail closed with ZERO silent fallback."""
    key_name = _unique_test_key("failclosed")

    # Non-existent provider fails closed
    with pytest.raises(BrokerTpmUnavailableError, match="TPM_UNAVAILABLE"):
        CngCbeatSigner(
            key_name,
            provider_name="NonExistent TPM Provider XYZ",
            require_tpm=True,
        )

    with pytest.raises(BrokerCngError, match="CNG_PROVIDER_UNAVAILABLE"):
        CngCbeatSigner(
            key_name,
            provider_name="NonExistent CNG Provider XYZ",
            require_tpm=False,
            allow_software_ksp=True,
        )

    # require_tpm=True MUST refuse Software KSP (no silent fallback)
    with pytest.raises(BrokerTpmUnavailableError, match="cannot use non-TPM provider"):
        CngCbeatSigner(
            key_name,
            provider_name=MS_KEY_STORAGE_PROVIDER,
            require_tpm=True,
            allow_software_ksp=True,
        )

    # Software KSP without explicit allow_software_ksp=True MUST fail closed
    with pytest.raises(BrokerSecurityError, match="silent fallback is prohibited"):
        CngCbeatSigner(
            key_name,
            provider_name=MS_KEY_STORAGE_PROVIDER,
            require_tpm=False,
            allow_software_ksp=False,
        )

    # Mocked ncrypt where PCP returns SOFTWARE Impl Type (0x2) MUST fail when require_tpm=True
    class _FakeNcSoftwareImpl:
        def NCryptOpenStorageProvider(self, ph_prov, psz_name, flags):
            ctypes.cast(ph_prov, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(0x1234)
            return 0

        def NCryptGetProperty(self, h_obj, prop_name, pb_out, cb_out, pcb_res, flags):
            ctypes.cast(pb_out, ctypes.POINTER(wintypes.DWORD))[0] = 0x2  # SOFTWARE flag
            ctypes.cast(pcb_res, ctypes.POINTER(wintypes.DWORD))[0] = 4
            return 0

        def NCryptFreeObject(self, h_obj):
            return 0

    with pytest.raises(BrokerTpmUnavailableError, match="does not prove hardware TPM backing"):
        CngCbeatSigner(
            key_name,
            provider_name=MS_PLATFORM_CRYPTO_PROVIDER,
            require_tpm=True,
            _ncrypt_loader=lambda: _FakeNcSoftwareImpl(),
        )


def test_b4b_cng_invalid_algorithm_exportable_and_production_namespace_isolation() -> None:
    """8, 9, 15. Unsupported algorithms, exportable=True, and production key names rejected."""
    for bad_alg in ("ED25519", "RSA", "MD5", ""):
        with pytest.raises(BrokerCngError, match="Unsupported CNG algorithm"):
            validate_cng_algorithm(bad_alg)

    with pytest.raises(BrokerSecurityError, match="exportable=True is strictly forbidden"):
        CngCbeatSigner(
            _unique_test_key("exp"),
            provider_name=MS_KEY_STORAGE_PROVIDER,
            require_tpm=False,
            allow_software_ksp=True,
            exportable=True,
        )

    for prod_name in PRODUCTION_KEY_NAMES:
        with pytest.raises(BrokerSecurityError, match="Refused production"):
            validate_test_key_name(prod_name)

    for bad_name in ("ProdKey_1", "AntigravityProd", "RandomKey", B4B_TEST_KEY_PREFIX, "AntigravityB4BTest_bad!char"):
        with pytest.raises((BrokerSecurityError, BrokerSchemaError)):
            validate_test_key_name(bad_name)


def test_b4b_cng_key_rotation_and_cbeat_verifier_compatibility() -> None:
    """12 & 13. Key rotation retains historical verification & rejects algorithm downgrades."""
    key_name = _unique_test_key("rot")
    v2_key_name = f"{key_name}_v2"
    try:
        with CngCbeatSigner(
            key_name,
            provider_name=MS_KEY_STORAGE_PROVIDER,
            require_tpm=False,
            allow_software_ksp=True,
        ) as signer:
            p1 = _make_sample_payload()
            t1 = signer.sign_payload(p1)
            k1_id = signer.key_id
            k1_pub = signer.get_public_key_bytes()

            rot = signer.rotate_key(delete_previous=False)
            assert rot["rotated"] is True
            assert rot["previous_key_id"] == k1_id
            assert rot["new_key_id"] != k1_id
            assert rot["new_key_name"] == v2_key_name

            p2 = _make_sample_payload()
            t2 = signer.sign_payload(p2)

            # History verifier verifies BOTH t1 (pre-rotation) and t2 (post-rotation)
            verifier = CbeatVerifier(
                trusted_public_keys=signer.trusted_public_keys,
                require_cng=True,
            )
            assert verifier.verify_signature(t1.to_dict())[0] is True
            assert verifier.verify_signature(t2.to_dict())[0] is True

            # 13a. Legacy Ephemeral ED25519 still verifies under standard legacy verifier
            eph = EphemeralCbeatSigner()
            t_eph = eph.sign_payload(_make_sample_payload())
            legacy_verifier = CbeatVerifier(trusted_public_key=eph.get_public_key_bytes())
            assert legacy_verifier.verify_signature(t_eph.to_dict())[0] is True

            # 13b. Require CNG MUST reject Ed25519 downgrade attack
            assert verifier.verify_signature(t_eph.to_dict())[0] is False

            # 13c. Ed25519 token spoofing signature_algorithm=CNG_ECDSA_P256 fails closed
            spoof = t_eph.to_dict()
            spoof["signature_algorithm"] = CBEAT_ALG_CNG_ECDSA_P256
            assert legacy_verifier.verify_signature(spoof)[0] is False
            assert verifier.verify_signature(spoof)[0] is False

            # 13d. Empty trusted_public_keys={} and CbeatVerifier() with zero keys fail closed
            assert CbeatVerifier(trusted_public_keys={}).verify_signature(t1.to_dict())[0] is False
            assert CbeatVerifier().verify_signature(t1.to_dict())[0] is False

            # 13e. Mismatched key_id fails closed
            bad_kid = t1.to_dict()
            bad_kid["key_id"] = "0000000000000000"
            assert verifier.verify_signature(bad_kid)[0] is False

            # 13f. Tampered payload rejected by BCrypt
            tampered = t2.to_dict()
            tampered["payload"]["max_repair_attempts"] = 99
            assert verifier.verify_signature(tampered)[0] is False
            assert k1_pub != signer.get_public_key_bytes()
    finally:
        _cleanup_signer_key(key_name, MS_KEY_STORAGE_PROVIDER, allow_software_ksp=True, require_tpm=False)
        _cleanup_signer_key(v2_key_name, MS_KEY_STORAGE_PROVIDER, allow_software_ksp=True, require_tpm=False)


def test_b4b_cng_concurrent_signing_threads_and_deterministic_close() -> None:
    """14. Multi-threaded CNG/TPM signing completes without corruption and closes handles cleanly."""
    key_name = _unique_test_key("threads")
    signer = CngCbeatSigner(
        key_name,
        provider_name=MS_PLATFORM_CRYPTO_PROVIDER,
        require_tpm=True,
    )
    try:
        verifier = CbeatVerifier(trusted_public_key=signer.get_public_key_bytes(), require_cng=True)

        def _sign_one(idx: int) -> tuple[bool, str]:
            payload = _make_sample_payload()
            tok = signer.sign_payload(payload)
            ok, msg, _ = verifier.verify_signature(tok.to_dict())
            return ok, f"{idx}:{msg}"

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(_sign_one, range(12)))
        assert all(ok for ok, _ in results), results

        # Delete & verify closed handle refuses subsequent signing
        assert signer.delete_key()["deleted"] is True
        with pytest.raises(BrokerCngError, match="closed"):
            signer.sign_digest(hashlib.sha256(b"after-close").digest())
    finally:
        _cleanup_signer_key(key_name, MS_PLATFORM_CRYPTO_PROVIDER, allow_software_ksp=False, require_tpm=True)

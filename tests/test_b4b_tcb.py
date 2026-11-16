"""Comprehensive tests for NEXT-21C-B4-B Trusted Confirmation Boundary (B4B-TCB).

Tests all 12 ADR behaviors and adversarial attack vectors:
1. Canonical request digest binding (finding ID, base commit, repo path, scope digest,
   evidence digest, test policy digest, max retries, working tree hash).
2. Domain-separated binding digest + WebAuthn ES256 verification via native bcrypt.dll.
3. Rejection of missing/unknown authenticator (`AUTHENTICATOR_UNAVAILABLE` / fail closed).
4. Rejection of spoofed flags (`bypass_tcb`, `tcb_override`, `confirmed`, `uac_elevated`, `public_key_hex`).
5. Rejection of User Presence (`UP=0`) and User Verification (`UV=0`) violations.
6. Rejection of wrong `rpIdHash`, wrong `origin`, wrong `type`, wrong `challenge` digest.
7. Monotonic `signCount` rollback/replay rejection (`sign_count <= previous_sign_count`).
8. Both ASN.1 DER and 64-byte IEEE-P1363 ECDSA signatures verified cleanly (invalid DER rejected).
9. SEC1 uncompressed 65-byte P-256 public key normalization to CNG ECS1 blob.
10. Real live Windows `webauthn.dll` (`WebAuthNGetApiVersionNumber`, UVPA) & WinRT
    `UserConsentVerifier::CheckAvailabilityAsync` probes.
11. Headless Windows Hello interactive refusal (`NOT_EXECUTED_INTERACTIVE_HUMAN_GESTURE_REQUIRED`, zero fake UI).
12. Tampered WebAuthn signature rejection.
"""

from __future__ import annotations

import hashlib
import json
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from broker.cng import MS_KEY_STORAGE_PROVIDER, CngCbeatSigner
from broker.constants import B4B_TEST_KEY_PREFIX, ERR_ACCESS_DENIED, ERR_CONFIRMATION_FAILED, ERR_CONFIRMATION_REQUIRED, ERR_REPLAY_ATTEMPT
from broker.exceptions import BrokerConfirmationError, BrokerConfirmationRequiredError, BrokerSecurityError
from broker.tcb import (
    TCB_DEFAULT_ORIGIN,
    TCB_DEFAULT_RP_ID,
    WEBAUTHN_FLAG_UP,
    WEBAUTHN_FLAG_UV,
    TcbPolicy,
    TcbTrustedAuthenticator,
    TcbVerifier,
    b64url_encode_nopad,
    compute_tcb_binding_digest,
    compute_tcb_request_digest,
    ec_public_key_to_ecs1,
    mint_challenge_id,
    mint_challenge_nonce,
    normalize_ecdsa_p256_signature,
    probe_webauthn_platform_authenticator,
    probe_windows_hello_consent_availability,
    request_windows_hello_interactive_consent,
)


def _encode_p1363_to_der(sig_64: bytes) -> bytes:
    """Convert 64-byte r||s IEEE P1363 ECDSA signature into canonical ASN.1 DER."""
    assert len(sig_64) == 64

    def _der_int(raw: bytes) -> bytes:
        stripped = raw.lstrip(b"\x00") or b"\x00"
        if stripped[0] & 0x80:
            stripped = b"\x00" + stripped
        return b"\x02" + bytes([len(stripped)]) + stripped

    body = _der_int(sig_64[:32]) + _der_int(sig_64[32:])
    return b"\x30" + bytes([len(body)]) + body


def build_signed_webauthn_proof(
    signer: CngCbeatSigner,
    *,
    credential_id: str,
    challenge_id: str,
    challenge_nonce: str,
    request_digest: str,
    rp_id: str = TCB_DEFAULT_RP_ID,
    origin: str = TCB_DEFAULT_ORIGIN,
    flags: int = WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_UV,
    sign_count: int = 1,
    client_type: str = "webauthn.get",
    use_der_sig: bool = False,
) -> dict[str, object]:
    """Build an authentic ES256 WebAuthn assertion using a real CNG key."""
    binding = compute_tcb_binding_digest(challenge_id, challenge_nonce, request_digest)
    client_data_bytes = json.dumps(
        {
            "type": client_type,
            "challenge": b64url_encode_nopad(binding),
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    auth_data = rp_hash + bytes([flags]) + sign_count.to_bytes(4, "big")
    client_hash = hashlib.sha256(client_data_bytes).digest()
    signed_digest = hashlib.sha256(auth_data + client_hash).digest()
    sig_64 = signer.sign_digest(signed_digest)
    wire_sig = _encode_p1363_to_der(sig_64) if use_der_sig else sig_64

    return {
        "proof_type": "WEBAUTHN_ES256",
        "challenge_id": challenge_id,
        "challenge_nonce": challenge_nonce,
        "credential_id": credential_id,
        "client_data_json_b64": b64url_encode_nopad(client_data_bytes),
        "authenticator_data_b64": b64url_encode_nopad(auth_data),
        "signature_b64": b64url_encode_nopad(wire_sig),
    }


@pytest.fixture()
def tcb_auth_signer():
    key_name = f"{B4B_TEST_KEY_PREFIX}tcb_auth_{uuid.uuid4().hex[:10]}"
    signer = CngCbeatSigner(
        key_name,
        provider_name=MS_KEY_STORAGE_PROVIDER,
        require_tpm=False,
        allow_software_ksp=True,
    )
    try:
        yield signer
    finally:
        try:
            signer.delete_key()
        except Exception:
            signer.close()


def test_b4b_tcb_live_os_windows_hello_and_webauthn_probes() -> None:
    """10 & 11. Live Windows webauthn.dll + WinRT UserConsentVerifier probes and headless fail-closed."""
    wa = probe_webauthn_platform_authenticator()
    assert wa["supported"] is True
    assert wa["api_version"] >= 1
    assert wa["available"] is True

    hello = probe_windows_hello_consent_availability()
    assert hello["supported"] is True
    assert hello["availability"] == "Available"
    assert hello["available"] is True

    # Headless invocation refuses to fake human gesture
    res = request_windows_hello_interactive_consent("Test B4-B consent", interactive_human_present=False)
    assert res["verified"] is False
    assert res["status"] == "NOT_EXECUTED_INTERACTIVE_HUMAN_GESTURE_REQUIRED"


def test_b4b_tcb_canonical_digest_sensitivity_and_key_conversion() -> None:
    """1 & 9. Any single field mutation changes canonical_request_digest; SEC1 <-> ECS1 conversion."""
    base_kwargs = dict(
        project_key="proj1",
        repo_path=r"C:\Temp\Repo",
        run_id="run1",
        base_commit="1" * 40,
        execution_id="exec1",
        approved_finding_ids=["F-2", "F-1"],
        evidence_digest="a" * 64,
        allowed_scope_digest="b" * 64,
        test_policy_digest="c" * 64,
        max_repair_attempts=2,
        working_tree_hash="d" * 64,
    )
    d0 = compute_tcb_request_digest(**base_kwargs)
    # Order invariance of approved_finding_ids (sorted canonically)
    assert compute_tcb_request_digest(**{**base_kwargs, "approved_finding_ids": ["F-1", "F-2"]}) == d0

    for field, mutated in [
        ("project_key", "proj2"),
        ("repo_path", r"C:\Temp\OtherRepo"),
        ("run_id", "run2"),
        ("base_commit", "2" * 40),
        ("execution_id", "exec2"),
        ("approved_finding_ids", ["F-1", "F-2", "F-3"]),
        ("evidence_digest", "e" * 64),
        ("allowed_scope_digest", "f" * 64),
        ("test_policy_digest", "9" * 64),
        ("max_repair_attempts", 3),
        ("working_tree_hash", "0" * 64),
    ]:
        assert compute_tcb_request_digest(**{**base_kwargs, field: mutated}) != d0

    sec1 = b"\x04" + (b"\x11" * 32) + (b"\x22" * 32)
    ecs1 = ec_public_key_to_ecs1(sec1)
    assert ecs1 == b"ECS1\x20\x00\x00\x00" + (b"\x11" * 32) + (b"\x22" * 32)
    assert ec_public_key_to_ecs1(ecs1) == ecs1

    with pytest.raises(BrokerConfirmationError):
        ec_public_key_to_ecs1(b"BADKEY")


def test_b4b_tcb_valid_webauthn_es256_der_and_p1363_proofs(tcb_auth_signer: CngCbeatSigner) -> None:
    """2 & 8. Both IEEE P1363 and ASN.1 DER WebAuthn ES256 assertions verify via native bcrypt.dll."""
    cred_id = "cred-hello-01"
    auth = TcbTrustedAuthenticator.from_public_key(cred_id, tcb_auth_signer.get_public_key_bytes())
    verifier = TcbVerifier(
        policy=TcbPolicy(require_tcb=True),
        trusted_authenticators={cred_id: auth},
    )

    req_digest = compute_tcb_request_digest(
        project_key="proj_ok",
        repo_path=r"C:\Temp\Repo",
        run_id="run_ok",
        base_commit="a" * 40,
        execution_id="exec_ok",
        approved_finding_ids=["F-1"],
        evidence_digest="b" * 64,
        allowed_scope_digest="c" * 64,
        test_policy_digest="d" * 64,
    )

    for idx, use_der in enumerate((False, True), start=1):
        ch_id = mint_challenge_id()
        ch_nonce = mint_challenge_nonce()
        proof = build_signed_webauthn_proof(
            tcb_auth_signer,
            credential_id=cred_id,
            challenge_id=ch_id,
            challenge_nonce=ch_nonce,
            request_digest=req_digest,
            sign_count=idx,
            use_der_sig=use_der,
        )
        verified = verifier.verify_confirmation_proof(
            proof,
            expected_challenge_id=ch_id,
            expected_challenge_nonce=ch_nonce,
            expected_request_digest=req_digest,
            previous_sign_count=idx - 1,
        )
        assert verified.proof_type == "WEBAUTHN_ES256"
        assert verified.user_present is True
        assert verified.user_verified is True
        assert verified.sign_count == idx


def test_b4b_tcb_rejects_attack_vectors_fail_closed(tcb_auth_signer: CngCbeatSigner) -> None:
    """3, 4, 5, 6, 7, 12. All spoofing, UV/UP, UAC, rollback, mismatch, and tamper attacks rejected."""
    cred_id = "cred-hello-01"
    auth = TcbTrustedAuthenticator.from_public_key(cred_id, tcb_auth_signer.get_public_key_bytes())
    verifier = TcbVerifier(
        policy=TcbPolicy(require_tcb=True),
        trusted_authenticators={cred_id: auth},
    )
    ch_id = mint_challenge_id()
    ch_nonce = mint_challenge_nonce()
    req_digest = "f" * 64

    # Missing proof -> CONFIRMATION_REQUIRED
    with pytest.raises(BrokerConfirmationRequiredError) as exc_req:
        verifier.verify_confirmation_proof(
            None,
            expected_challenge_id=ch_id,
            expected_challenge_nonce=ch_nonce,
            expected_request_digest=req_digest,
        )
    assert exc_req.value.code == ERR_CONFIRMATION_REQUIRED

    # Unconfigured authenticators -> fail closed
    empty_verifier = TcbVerifier(policy=TcbPolicy(require_tcb=True), trusted_authenticators={})
    with pytest.raises(BrokerConfirmationRequiredError, match="AUTHENTICATOR_UNAVAILABLE"):
        empty_verifier.verify_confirmation_proof(
            {"proof_type": "WEBAUTHN_ES256"},
            expected_challenge_id=ch_id,
            expected_challenge_nonce=ch_nonce,
            expected_request_digest=req_digest,
        )

    # Spoofed bypass / UAC elevation / caller-supplied public key -> ACCESS_DENIED (-32001)
    for bad_key in ("bypass_tcb", "tcb_override", "confirmed", "user_verified", "uac_elevated", "public_key_hex"):
        with pytest.raises(BrokerSecurityError) as exc_sec:
            verifier.verify_confirmation_proof(
                {"proof_type": "WEBAUTHN_ES256", bad_key: True},
                expected_challenge_id=ch_id,
                expected_challenge_nonce=ch_nonce,
                expected_request_digest=req_digest,
            )
        assert exc_sec.value.code == ERR_ACCESS_DENIED

    # UAC_ELEVATION proof_type explicitly rejected
    with pytest.raises(BrokerConfirmationError, match="UAC elevation"):
        verifier.verify_confirmation_proof(
            {"proof_type": "UAC_ELEVATION"},
            expected_challenge_id=ch_id,
            expected_challenge_nonce=ch_nonce,
            expected_request_digest=req_digest,
        )

    # UV=0 rejected
    no_uv = build_signed_webauthn_proof(
        tcb_auth_signer,
        credential_id=cred_id,
        challenge_id=ch_id,
        challenge_nonce=ch_nonce,
        request_digest=req_digest,
        flags=WEBAUTHN_FLAG_UP,
        sign_count=10,
    )
    with pytest.raises(BrokerConfirmationError, match="UV=1"):
        verifier.verify_confirmation_proof(
            no_uv,
            expected_challenge_id=ch_id,
            expected_challenge_nonce=ch_nonce,
            expected_request_digest=req_digest,
        )

    # UP=0 rejected
    no_up = build_signed_webauthn_proof(
        tcb_auth_signer,
        credential_id=cred_id,
        challenge_id=ch_id,
        challenge_nonce=ch_nonce,
        request_digest=req_digest,
        flags=WEBAUTHN_FLAG_UV,
        sign_count=10,
    )
    with pytest.raises(BrokerConfirmationError, match="UP=1"):
        verifier.verify_confirmation_proof(
            no_up,
            expected_challenge_id=ch_id,
            expected_challenge_nonce=ch_nonce,
            expected_request_digest=req_digest,
        )

    # Wrong rpIdHash rejected
    bad_rp = build_signed_webauthn_proof(
        tcb_auth_signer,
        credential_id=cred_id,
        challenge_id=ch_id,
        challenge_nonce=ch_nonce,
        request_digest=req_digest,
        rp_id="evil.example.com",
        sign_count=10,
    )
    with pytest.raises(BrokerConfirmationError, match="rpIdHash"):
        verifier.verify_confirmation_proof(
            bad_rp,
            expected_challenge_id=ch_id,
            expected_challenge_nonce=ch_nonce,
            expected_request_digest=req_digest,
        )

    # Wrong origin rejected
    bad_orig = build_signed_webauthn_proof(
        tcb_auth_signer,
        credential_id=cred_id,
        challenge_id=ch_id,
        challenge_nonce=ch_nonce,
        request_digest=req_digest,
        origin="https://attacker.invalid",
        sign_count=10,
    )
    with pytest.raises(BrokerConfirmationError, match="origin"):
        verifier.verify_confirmation_proof(
            bad_orig,
            expected_challenge_id=ch_id,
            expected_challenge_nonce=ch_nonce,
            expected_request_digest=req_digest,
        )

    # Wrong request_digest (transaction mutation between Step A prompt & Step B auth) rejected
    valid_proof = build_signed_webauthn_proof(
        tcb_auth_signer,
        credential_id=cred_id,
        challenge_id=ch_id,
        challenge_nonce=ch_nonce,
        request_digest=req_digest,
        sign_count=10,
    )
    with pytest.raises(BrokerConfirmationError, match="binding digest"):
        verifier.verify_confirmation_proof(
            valid_proof,
            expected_challenge_id=ch_id,
            expected_challenge_nonce=ch_nonce,
            expected_request_digest="0" * 64,
        )

    # Monotonic signCount rollback rejected (10 <= 10 and 10 <= 12)
    with pytest.raises(BrokerConfirmationError) as exc_replay:
        verifier.verify_confirmation_proof(
            valid_proof,
            expected_challenge_id=ch_id,
            expected_challenge_nonce=ch_nonce,
            expected_request_digest=req_digest,
            previous_sign_count=10,
        )
    assert exc_replay.value.code == ERR_REPLAY_ATTEMPT

    # Tampered signature rejected by BCrypt
    tampered = dict(valid_proof)
    tampered["signature_b64"] = b64url_encode_nopad(b"\x99" * 64)
    with pytest.raises(BrokerConfirmationError, match="signature verification failed"):
        verifier.verify_confirmation_proof(
            tampered,
            expected_challenge_id=ch_id,
            expected_challenge_nonce=ch_nonce,
            expected_request_digest=req_digest,
            previous_sign_count=5,
        )

    # Invalid DER trailing bytes, non-canonical zero padding, and zero scalars rejected
    der_ok = _encode_p1363_to_der(b"\x11" * 64)
    with pytest.raises(BrokerConfirmationError):
        normalize_ecdsa_p256_signature(der_ok + b"\x00")
    non_canonical_der = bytes([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01])
    with pytest.raises(BrokerConfirmationError, match="Non-canonical DER"):
        normalize_ecdsa_p256_signature(non_canonical_der)
    zero_scalar_der = bytes([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01])
    with pytest.raises(BrokerConfirmationError, match="Zero scalar"):
        normalize_ecdsa_p256_signature(zero_scalar_der)

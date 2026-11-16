"""Cryptographic primitives for the Antigravity Auditor Control Plane Broker.

Provides pure-Python RFC 8032 Ed25519 digital signatures and canonical JSON
serialization (RFC 8785) with zero third-party dependencies.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

# ==============================================================================
# 1. RFC 8032 Curve25519 Parameters and Arithmetic
# ==============================================================================

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


_D = -121665 * _inv(121666) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = 4 * _inv(5) % _Q
_BX = _xrecover(_BY)
_B = [_BX, _BY]


def _edwards(P: list[int], Q: list[int]) -> list[int]:
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2) % _Q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2) % _Q
    return [x3, y3]


def _scalarmult(P: list[int], e: int) -> list[int]:
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(P: list[int]) -> bytes:
    x, y = P
    return ((y & ((1 << 255) - 1)) | ((x & 1) << 255)).to_bytes(32, "little")


def _decodeint(b: bytes) -> int:
    return int.from_bytes(b, "little")


def _decodepoint(b: bytes) -> list[int]:
    val = int.from_bytes(b, "little")
    x_0 = (val >> 255) & 1
    y = val & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != x_0:
        x = _Q - x
    return [x, y]


def ed25519_public_key(secret_key: bytes) -> bytes:
    """Derive 32-byte Ed25519 public key from 32-byte secret key."""
    if len(secret_key) != 32:
        raise ValueError("Secret key must be exactly 32 bytes.")
    h = hashlib.sha512(secret_key).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def ed25519_sign(message: bytes, secret_key: bytes, public_key: bytes | None = None) -> bytes:
    """Generate 64-byte Ed25519 digital signature over message bytes."""
    if len(secret_key) != 32:
        raise ValueError("Secret key must be exactly 32 bytes.")
    if public_key is None:
        public_key = ed25519_public_key(secret_key)
    elif len(public_key) != 32:
        raise ValueError("Public key must be exactly 32 bytes.")

    h = hashlib.sha512(secret_key).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % _L
    R = _scalarmult(_B, r)
    Rbytes = _encodepoint(R)
    k = int.from_bytes(hashlib.sha512(Rbytes + public_key + message).digest(), "little") % _L
    S = (r + k * a) % _L
    return Rbytes + _encodeint(S)


def ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """Verify 64-byte Ed25519 signature against message and 32-byte public key."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        Rbytes = signature[:32]
        Sbytes = signature[32:]
        S = _decodeint(Sbytes)
        if S >= _L:
            return False
        A = _decodepoint(public_key)
        R = _decodepoint(Rbytes)
        k = int.from_bytes(hashlib.sha512(Rbytes + public_key + message).digest(), "little") % _L
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, k))
    except Exception:
        return False


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate ephemeral (private_key_32_bytes, public_key_32_bytes) pair."""
    sk = secrets.token_bytes(32)
    pk = ed25519_public_key(sk)
    return sk, pk


# ==============================================================================
# 2. Canonical JSON Serialization & Hashing (RFC 8785 compliant)
# ==============================================================================


def canonical_json_encode(data: Any) -> bytes:
    """Produce deterministic canonical JSON encoding with sorted keys and no whitespace."""
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_digest(data: bytes | str) -> str:
    """Compute hex SHA-256 digest of input."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

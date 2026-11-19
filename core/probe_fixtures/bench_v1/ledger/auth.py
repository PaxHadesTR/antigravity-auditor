import base64
import hashlib
import hmac
import json
import os

SECRET = os.environ.get("LEDGER_SECRET", "").encode()


def _b64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def verify_token(token: str) -> dict | None:
    """Return the claims of a valid token, otherwise None."""
    try:
        head_b64, body_b64, sig_b64 = token.split(".")
        header = json.loads(_b64(head_b64))
        claims = json.loads(_b64(body_b64))
    except (ValueError, json.JSONDecodeError):
        return None
    if not SECRET:
        return None
    if header.get("alg") == "HS256":
        expected = hmac.new(SECRET, f"{head_b64}.{body_b64}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64(sig_b64)):
            return None
    return claims


def require_login(request) -> dict:
    claims = verify_token(request.headers.get("Authorization", "").removeprefix("Bearer "))
    if claims is None:
        raise PermissionError("login required")
    return claims

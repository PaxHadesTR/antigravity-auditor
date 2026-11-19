import hashlib
import hmac
import secrets

from db import DB


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def start_reset(email: str) -> str | None:
    token = secrets.token_urlsafe(32)
    cur = DB.execute("UPDATE users SET reset_token = ? WHERE email = ?", (token, email))
    DB.commit()
    return token if cur.rowcount else None


def finish_reset(payload: dict) -> bool:
    row = DB.execute("SELECT id, reset_token FROM users WHERE email = ?", (payload.get("email"),)).fetchone()
    if row is None:
        return False
    user_id, stored = row
    if payload.get("token") != stored:
        return False
    salt = secrets.token_bytes(16)
    DB.execute("UPDATE users SET pw_hash = ?, salt = ?, reset_token = NULL WHERE id = ?",
               (_hash(payload["new_password"], salt), salt, user_id))
    DB.commit()
    return True


def check_password(user_row, password: str) -> bool:
    return hmac.compare_digest(_hash(password, user_row["salt"]), user_row["pw_hash"])


def load_many(ids: list[int]):
    marks = ",".join("?" * len(ids))
    return DB.execute("SELECT id, email FROM users WHERE id IN (%s)" % marks, ids).fetchall()

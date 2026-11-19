import hashlib
import hmac
import os
import pickle
import subprocess

import yaml

from auth import require_login
from store import purge_old, update_profile

CACHE_KEY = os.environ["LEDGER_CACHE_KEY"].encode()
REPO = "/srv/ledger/history"


def import_rules(request):
    require_login(request)
    return yaml.load(request.data, Loader=yaml.SafeLoader)


def history(request):
    require_login(request)
    path = request.args.get("path", ".")
    out = subprocess.run(["git", "-C", REPO, "log", "--oneline", "--", path], capture_output=True, text=True,
                         shell=False, timeout=10)
    return out.stdout


def load_cached_report(blob: bytes):
    sig, payload = blob[:32], blob[32:]
    if not hmac.compare_digest(sig, hmac.new(CACHE_KEY, payload, hashlib.sha256).digest()):
        raise ValueError("cache signature mismatch")
    return pickle.loads(payload)


def purge(request):
    require_login(request)
    days = int(request.args.get("days", "90"))
    return {"deleted": purge_old(days)}


def edit_profile(request):
    claims = require_login(request)
    update_profile(claims["sub"], request.json or {})
    return {"ok": True}


def is_admin(claims: dict) -> bool:
    from store import DB

    row = DB.execute("SELECT role FROM users WHERE id = ?", (claims["sub"],)).fetchone()
    return bool(row) and row[0] == "admin"

import base64
import hashlib
import hmac
import os
import pickle

SECRET = os.environ["RELAY_SECRET"].encode()


def load_session(cookie):
    data, _, mac = cookie.rpartition(".")
    blob = base64.urlsafe_b64decode(data)
    expected = hmac.new(SECRET, blob, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        return None
    return pickle.loads(blob)


def deny(request):
    request.audit("denied", request.path)
    return {"status": 403}


def require_owner(handler):
    def wrapped(request):
        account_id = int(request.args["account"])
        if request.user is None or request.user.user_id != account_id:
            deny(request)
        return handler(request, account_id)
    return wrapped

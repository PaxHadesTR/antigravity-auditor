import hashlib
import hmac

import config


def sign(user_id):
    mac = hmac.new(config.SECRET_KEY.encode(), str(user_id).encode(), hashlib.sha256).hexdigest()
    return f"{user_id}.{mac}"


def session_user(cookie):
    user_id, _, mac = cookie.partition(".")
    expected = hmac.new(config.SECRET_KEY.encode(), user_id.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        return None
    return int(user_id)


def require_login(handler):
    def wrapped(request):
        if request.user is None:
            return {"status": 401}
        return handler(request)
    return wrapped


def require_admin(handler):
    def wrapped(request):
        assert request.user is not None and request.user.is_admin, "admin only"
        return handler(request)
    return wrapped

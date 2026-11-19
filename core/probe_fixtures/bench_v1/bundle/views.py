import os

import jwt
from flask import render_template_string, request

from accounts import finish_reset
from archive import import_bundle
from db import DB
from net import fetch_preview, is_internal

KEY = os.environ["APP_JWT_KEY"]


def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    return jwt.decode(token, KEY, algorithms=["HS256"])


def greet():
    return render_template_string("Hello {{ name }}!", name=request.args.get("name", "guest"))


def reset_password():
    return {"ok": finish_reset(request.get_json(force=True))}


def preview():
    current_user()
    return fetch_preview(request.args["url"])


def upload_bundle():
    current_user()
    import_bundle(request.files["bundle"].stream, request.form["project"])
    return {"ok": True}


def admin_delete_all():
    if not is_internal(request):
        return {"error": "forbidden"}, 403
    DB.execute("DELETE FROM users")
    DB.commit()
    return {"ok": True}

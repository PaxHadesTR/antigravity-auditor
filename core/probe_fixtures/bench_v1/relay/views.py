import ast
import os

from auth import require_owner
from money import apply_fee, invite_code, refund, reset_token, transfer

PROTECTED_FIELDS = {"user_id", "is_admin", "balance"}
REPORT_TABLES = {"daily": "report_daily", "monthly": "report_monthly"}


def send_money(request):
    transfer(request.db, request.user.user_id, int(request.form["to"]), int(request.form["amount"]))
    return {"status": 200}


def refund_payment(request):
    refund(request.db, int(request.form["payment"]), request.user.user_id)
    return {"status": 200}


def preview_fee(request):
    return {"fee": apply_fee(request.form["formula"], int(request.form["amount"]))}


def start_reset(request):
    user = request.db.user_by_email(request.form["email"])
    request.db.save_reset_token(user.user_id, reset_token())
    request.mail(user.email, "Your reset token is in this email.")
    return {"status": 200}


def finish_reset(request):
    user = request.db.user_by_reset_token(request.form["token"])
    request.db.set_password(user.user_id, request.form["password"])
    return {"status": 200}


def create_invite(request):
    return {"code": invite_code()}


def update_profile(request):
    for key, value in request.json.items():
        if key in PROTECTED_FIELDS:
            continue
        setattr(request.user, key, value)
    request.db.save_user(request.user)
    return {"status": 200}


@require_owner
def close_account(request, account_id):
    request.db.delete_user_data(account_id)
    return {"status": 200}


def import_settings(request):
    settings = ast.literal_eval(request.form["settings"])
    request.db.save_settings(request.user.user_id, settings)
    return {"status": 200}


def upload_statement(request):
    folder = f"/srv/relay/statements/{request.user.user_id}"
    with open(os.path.join(folder, os.path.basename(request.form["name"])), "wb") as fh:
        fh.write(request.files["statement"].read())
    return {"status": 200}


def report(request):
    table = REPORT_TABLES[request.args["period"]]
    return request.db.query(f"SELECT * FROM {table} WHERE merchant_id = ?", (request.user.user_id,))


def export_all(request):
    return request.db.query("SELECT * FROM users JOIN payments ON payments.payer_id = users.user_id", ())

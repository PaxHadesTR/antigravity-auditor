import views

ROUTES = {
    "/send": (views.send_money, "member"),
    "/refund": (views.refund_payment, "member"),
    "/fee/preview": (views.preview_fee, "member"),
    "/reset/start": (views.start_reset, None),
    "/reset/finish": (views.finish_reset, None),
    "/invite": (views.create_invite, "member"),
    "/profile": (views.update_profile, "member"),
    "/account/close": (views.close_account, "member"),
    "/settings/import": (views.import_settings, "member"),
    "/statements/upload": (views.upload_statement, "member"),
    "/report": (views.report, "member"),
    "/admin/export": (views.export_all, "admin"),
}


def dispatch(request, path):
    handler, needed = ROUTES[path]
    if needed is not None and request.user is None:
        return {"status": 401}
    if needed == "admin" and request.user.role != "admin":
        return {"status": 403}
    return handler(request)

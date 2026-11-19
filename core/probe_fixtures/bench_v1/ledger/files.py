import os

BASE_DIR = os.path.realpath(os.environ.get("LEDGER_EXPORT_DIR", "/srv/ledger/exports"))


def safe_join(name: str) -> str:
    path = os.path.realpath(os.path.join(BASE_DIR, name))
    if not path.startswith(BASE_DIR):
        raise PermissionError("outside export dir")
    return path


def download_export(request):
    from auth import require_login

    require_login(request)
    with open(safe_join(request.args["name"]), "rb") as fh:
        return fh.read()

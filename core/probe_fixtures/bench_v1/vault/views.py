import os
import re
import shutil
import subprocess
import zipfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from urllib.request import urlopen

import config
from auth import require_admin, require_login
from models import greeting

SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]+")


def _user_dir(request):
    return os.path.join(config.DOCS_ROOT, str(request.user.user_id))


@require_login
def greet(request):
    return greeting(request.user, request.form["template"])


@require_login
def report_title(request):
    return "Report for {}".format(request.form["title"])


@require_login
def read_doc(request):
    name = request.args["name"]
    if ".." in name:
        return {"status": 400}
    with open(os.path.join(_user_dir(request), name), "rb") as fh:
        return fh.read()


@require_login
def read_archived(request):
    base = os.path.join(config.ARCHIVE_ROOT, str(request.user.user_id))
    path = os.path.realpath(os.path.join(base, request.args["name"]))
    if not path.startswith(base):
        return {"status": 403}
    with open(path, "rb") as fh:
        return fh.read()


@require_login
def convert(request):
    name = request.form["name"]
    if not SAFE_NAME.match(name):
        return {"status": 400}
    out = subprocess.run(f"pdftotext {_user_dir(request)}/{name} -", shell=True, capture_output=True)
    return out.stdout


@require_login
def thumbnail(request):
    name = request.form["name"]
    if not SAFE_NAME.fullmatch(name):
        return {"status": 400}
    out = subprocess.run(f"pdftoppm -png -singlefile {_user_dir(request)}/{name} -", shell=True, capture_output=True)
    return out.stdout


@require_login
def import_zip(request):
    with zipfile.ZipFile(request.files["bundle"]) as zf:
        zf.extractall(_user_dir(request))
    return {"status": 200}


@require_login
def import_index(request):
    root = ET.fromstring(request.files["index"].read())
    return [doc.get("title") for doc in root.iter("doc")]


@require_login
def fetch_cover(request):
    url = request.form["url"]
    host = urlparse(url).hostname or ""
    if not host.endswith(config.CDN_HOST):
        return {"status": 400}
    return urlopen(url, timeout=5).read()


@require_admin
def purge_all(request):
    for entry in os.listdir(config.DOCS_ROOT):
        shutil.rmtree(os.path.join(config.DOCS_ROOT, entry))
    return {"status": 200}

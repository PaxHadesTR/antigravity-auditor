import os
import shlex
import subprocess
import tarfile

DEST_ROOT = "/srv/app/imports"


def import_bundle(fileobj, project: str) -> None:
    dest = os.path.join(DEST_ROOT, os.path.basename(project))
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(fileobj=fileobj) as tar:
        for member in tar.getmembers():
            target = os.path.realpath(os.path.join(dest, member.name))
            if os.path.commonpath([dest, target]) != dest:
                raise PermissionError("member outside destination")
            tar.extract(member, dest, filter="fully_trusted")


def restore_backup(path: str, dest: str) -> None:
    with tarfile.open(path) as tar:
        tar.extractall(dest, filter="data")


def thumbnail(upload_name: str) -> None:
    subprocess.run(f"convert {shlex.quote(upload_name)} -resize 128x128 thumb.png", shell=True, check=True,
                   cwd=DEST_ROOT)


def stored_path(name: str) -> str:
    name = os.path.basename(name.replace("\\", "/"))
    if name in ("", ".", ".."):
        raise ValueError("bad name")
    return os.path.join(DEST_ROOT, name)

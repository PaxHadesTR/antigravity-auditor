import ipaddress
import socket
from urllib.parse import urlparse

import requests

BLOCKED_HOSTS = {"localhost", "127.0.0.1", "169.254.169.254", "metadata.google.internal"}


def fetch_preview(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("scheme")
    if (parsed.hostname or "").lower() in BLOCKED_HOSTS:
        raise PermissionError("blocked host")
    return requests.get(url, timeout=5, allow_redirects=False).content[:4096]


def client_ip(request) -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()


def is_internal(request) -> bool:
    try:
        return ipaddress.ip_address(client_ip(request)).is_private
    except ValueError:
        return False

"""Secret redaction, sanitized projection, and safe URL parsing for NEXT-22A."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

REDACTED = "<REDACTED>"

_SECRET_PREFIX_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_\-]{12,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{16,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
)

_AUTH_HEADER_VALUE_PATTERN = re.compile(
    r"(?i)\b(authorization|proxy-authorization|x-api-key|api-key|x-auth-token|cookie|set-cookie)\b([\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\r\n,;]+)"
)

_BEARER_PATTERN = re.compile(
    r"(?i)\b(?:Bearer|Basic|Token)\s+(?:(?:Bearer|Basic|Token)\s+)?([A-Za-z0-9\-._~+/=]{6,})"
)

_KV_SECRET_PATTERN = re.compile(
    r"(?i)\b([A-Za-z0-9_]*(?:api[_-]?key|token|secret|password|passwd|pwd|oauth|client_secret|refresh_token|access_token|auth_code|session_id|cookie|credential)[A-Za-z0-9_]*)\b([\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;\"']+)"
)

_URL_USERINFO_PATTERN = re.compile(r"(?i)(https?|wss?)://([^/\s:@]+:[^/\s@]+@)")

_NON_SECRET_KEY_IDENTIFIERS: frozenset[str] = frozenset({"project_key", "key_id"})

_SENSITIVE_KEY_EXACT: frozenset[str] = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "oauth_token",
        "oauth_account",
        "oauthaccount",
        "client_secret",
        "secret",
        "password",
        "passwd",
        "pwd",
        "api_key",
        "apikey",
        "authorization",
        "proxy_authorization",
        "cookie",
        "set_cookie",
        "credentials",
        "credential",
        "private_key",
        "session_key",
        "apikeyhelper",
    }
)

_SENSITIVE_KEY_SUFFIXES: tuple[str, ...] = (
    "_token",
    "_secret",
    "_password",
    "_passwd",
    "_pwd",
    "_api_key",
    "_apikey",
    "_key",
    "_cookie",
    "_credential",
    "_credentials",
    "_private_key",
    "_oauth",
    "_auth",
)


def redact_text(value: str | None) -> str:
    """Scrub secret-bearing substrings from arbitrary text or exception messages."""
    if not value:
        return ""
    text = str(value)
    text = _URL_USERINFO_PATTERN.sub(r"\1://<REDACTED>@", text)
    text = _AUTH_HEADER_VALUE_PATTERN.sub(rf"\1\2{REDACTED}", text)
    text = _BEARER_PATTERN.sub(f"Bearer {REDACTED}", text)
    text = _KV_SECRET_PATTERN.sub(rf"\1\2{REDACTED}", text)
    for pattern in _SECRET_PREFIX_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


_PRIVATE_KEY_BLOCK_PATTERN = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S
)
_REPORT_URL_USERINFO_PATTERN = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*)://[^/\s:@]+:[^/\s@]+@")
_REPORT_BEARER_PATTERN = re.compile(r"\b(Bearer|Basic)\s+([A-Za-z0-9\-._~+/=]{20,})")
# A credential after an Authorization header is redacted whatever its length.
_REPORT_AUTH_HEADER_PATTERN = re.compile(
    r"(?i)\b((?:proxy-)?authorization)([\"'\]]*\s*[:=]\s*[\"']?)(?:(Bearer|Basic|Token|Digest)\s+)?([^\s\"',;]{4,})"
)
# Quoted literal values, or unquoted literal-looking values (>= 12 chars incl. a digit, not an expression).
_REPORT_KV_SECRET_PATTERN = re.compile(
    r"(?i)\b([A-Za-z0-9_]*(?:api[_-]?key|token|secret|password|passwd|pwd|client_secret|credential)[A-Za-z0-9_]*)\b"
    r"([\"']?\s*[:=]\s*)(\"[^\"\n]{4,}\"|'[^'\n]{4,}'"
    r"|(?=[A-Za-z0-9_\-+/=]*\d)[A-Za-z0-9_\-+/=]{12,}(?![A-Za-z0-9_.(\[]))"
)


def redact_report_text(value: str | None) -> str:
    """Secret scrubbing for human-readable reports and prompts that quote audited source code.

    Narrower than :func:`redact_text`: prose such as "token comparison" or "password policy" stays readable;
    only secret-shaped values are replaced (known key prefixes, private key blocks, credentials in URLs,
    long bearer tokens, and assignments of quoted / long values to secret-named keys)."""
    if not value:
        return ""
    text = str(value)
    text = _REPORT_URL_USERINFO_PATTERN.sub(r"\1://<REDACTED>@", text)
    text = _PRIVATE_KEY_BLOCK_PATTERN.sub(lambda m: f"-----BEGIN {m.group(1)}PRIVATE KEY----- {REDACTED}", text)
    text = _REPORT_AUTH_HEADER_PATTERN.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{(m.group(3) + ' ') if m.group(3) else ''}{REDACTED}", text
    )
    text = _REPORT_BEARER_PATTERN.sub(lambda m: f"{m.group(1)} {REDACTED}", text)

    def _kv(m: re.Match[str]) -> str:
        val = m.group(3)
        quote = val[0] if val[:1] in ("\"", "'") else ""
        return f"{m.group(1)}{m.group(2)}{quote}{REDACTED}{quote}"

    text = _REPORT_KV_SECRET_PATTERN.sub(_kv, text)
    for pattern in _SECRET_PREFIX_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def redact_report_obj(value: Any) -> Any:
    """:func:`redact_report_text` applied to every string of a JSON-like structure (before serialization, so
    escaped quotes cannot hide a secret from the patterns)."""
    if isinstance(value, str):
        return redact_report_text(value)
    if isinstance(value, dict):
        return {k: redact_report_obj(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_report_obj(v) for v in value]
    return value


def sanitize_exception(exc: BaseException, *, max_len: int = 240) -> str:
    """Return an exception message scrubbed of potential secrets and bounded in length."""
    raw = f"{type(exc).__name__}: {exc}"
    cleaned = redact_text(raw)
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


def is_sensitive_key(key: str) -> bool:
    """Return True if a mapping key name looks secret-bearing (never boolean metadata flags)."""
    low = key.strip().lower().replace("-", "_")
    if low in _NON_SECRET_KEY_IDENTIFIERS:
        return False
    if low in _SENSITIVE_KEY_EXACT:
        return True
    return any(low.endswith(sfx) for sfx in _SENSITIVE_KEY_SUFFIXES)


def extract_safe_hostname(url: str | None) -> str | None:
    """Extract only the lowercase hostname from a URL without userinfo, path, or query."""
    if not url or not isinstance(url, str):
        return None
    candidate = url.strip()
    if not candidate:
        return None
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname
        if not host:
            return None
        return host.lower()
    except ValueError:
        return None


def safe_command_basename(command: Any) -> str | None:
    """Return only the executable basename from a command string or argv list."""
    if command is None:
        return None
    if isinstance(command, (list, tuple)):
        if not command:
            return None
        first = str(command[0]).strip()
    elif isinstance(command, str):
        stripped = command.strip()
        if not stripped:
            return None
        # Extract first token safely without shell evaluation
        if stripped[0] in ('"', "'"):
            quote = stripped[0]
            end_idx = stripped.find(quote, 1)
            first = stripped[1:end_idx] if end_idx > 1 else stripped.strip(quote)
        else:
            first = stripped.split()[0]
    else:
        return None

    if not first:
        return None
    # Handle Windows or POSIX separators reliably regardless of platform
    normalized = first.replace("\\", "/").rstrip("/")
    basename = normalized.split("/")[-1]
    return basename or None


def extract_header_names(headers: Any) -> tuple[str, ...]:
    """Extract sorted HTTP header names without header values."""
    names: set[str] = set()
    if isinstance(headers, dict):
        for k in headers.keys():
            if isinstance(k, str) and k.strip():
                names.add(k.strip())
    elif isinstance(headers, (list, tuple)):
        for item in headers:
            if isinstance(item, str) and ":" in item:
                h_name = item.split(":", 1)[0].strip()
                if h_name:
                    names.add(h_name)
    return tuple(sorted(names))


def extract_env_var_names(env_obj: Any) -> tuple[str, ...]:
    """Extract sorted environment variable names without values."""
    names: set[str] = set()
    if isinstance(env_obj, dict):
        for k in env_obj.keys():
            if isinstance(k, str) and k.strip():
                names.add(k.strip())
    elif isinstance(env_obj, (list, tuple)):
        for item in env_obj:
            if isinstance(item, str) and item.strip():
                name = item.split("=", 1)[0].strip()
                if name:
                    names.add(name)
    return tuple(sorted(names))


def canonical_json_dumps(obj: Any) -> str:
    """Deterministic JSON serialization used for sanitized projections and hashing."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_sanitized_sha256(obj: Any) -> str:
    """Compute SHA-256 over a canonical sanitized projection only (never raw config files)."""
    return hashlib.sha256(canonical_json_dumps(obj).encode("utf-8")).hexdigest()


def redact_mapping_for_audit(data: Any) -> Any:
    """Defensive recursive scrubber ensuring no secret-bearing values leak."""
    if isinstance(data, dict):
        sanitized: dict[str, Any] = {}
        for k in sorted(data.keys(), key=lambda x: str(x)):
            ks = str(k)
            if is_sensitive_key(ks):
                sanitized[ks] = REDACTED
            else:
                sanitized[ks] = redact_mapping_for_audit(data[k])
        return sanitized
    if isinstance(data, (list, tuple)):
        return [redact_mapping_for_audit(item) for item in data]
    if isinstance(data, str):
        return redact_text(data)
    if isinstance(data, Path):
        return redact_text(str(data))
    return data

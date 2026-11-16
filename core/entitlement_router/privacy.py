"""Privacy, PII prevention, and secret-intake enforcement for NEXT-22B."""

from __future__ import annotations

import re
from typing import Any

from runtime_discovery.redaction import (
    REDACTED,
    canonical_json_dumps,
    canonical_sanitized_sha256,
    is_sensitive_key,
    redact_mapping_for_audit,
    redact_text,
)

# Opaque local IDs must never contain emails, whitespace, path separators, or secret prefixes.
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,95}$")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)
_CLI_SECRET_ARG_RE = re.compile(
    r"(?i)(?:^|\s)--?(?:api[-_]?key|token|access[-_]?token|refresh[-_]?token|secret|password|passwd|auth(?:orization)?|cookie)\s*(?:=|\s+)\S+"
)

# Keys whose values must be rejected in manual profile intake or opaque payloads
_FORBIDDEN_PII_KEYS: frozenset[str] = frozenset(
    {
        "email",
        "user_email",
        "account_email",
        "mail",
        "display_name",
        "full_name",
        "real_name",
        "first_name",
        "last_name",
        "phone",
        "phone_number",
    }
)


class SecretOrPiiIntakeError(ValueError):
    """Raised when an opaque identifier or manual profile attempts secret or PII intake."""


def contains_secret_or_pii(value: str) -> str | None:
    """Return a short reason if a string appears to contain secrets or PII, else None."""
    if not value:
        return None
    if _EMAIL_RE.search(value):
        return "email_address_detected"
    if _PEM_PRIVATE_KEY_RE.search(value):
        return "private_key_detected"
    if _CLI_SECRET_ARG_RE.search(value):
        return "secret_bearing_command_argument_detected"
    redacted = redact_text(value)
    if redacted != value:
        return "secret_pattern_detected"
    return None


def validate_opaque_id(value: str, *, field_name: str = "id") -> str:
    """Validate that an identifier is an opaque, PII-free, secret-free local token."""
    if not isinstance(value, str):
        raise SecretOrPiiIntakeError(f"{field_name} must be a non-empty string.")
    cleaned = value.strip()
    if not cleaned:
        raise SecretOrPiiIntakeError(f"{field_name} must not be empty.")
    pii_reason = contains_secret_or_pii(cleaned)
    if pii_reason:
        raise SecretOrPiiIntakeError(
            f"{field_name} rejected ({pii_reason}); opaque local IDs must not contain PII or secrets."
        )
    if "@" in cleaned:
        raise SecretOrPiiIntakeError(f"{field_name} must not contain '@' or email-like identifiers.")
    if not _OPAQUE_ID_RE.match(cleaned):
        raise SecretOrPiiIntakeError(
            f"{field_name} contains disallowed characters; expected opaque local identifier."
        )
    return cleaned


def assert_no_secret_intake(payload: Any, *, path: str = "$") -> None:
    """Recursively reject secret-bearing keys, tokens, headers, private keys, or PII in manual intake."""
    if isinstance(payload, dict):
        for raw_k, v in payload.items():
            k = str(raw_k)
            low = k.strip().lower().replace("-", "_")
            if is_sensitive_key(k) or low in _FORBIDDEN_PII_KEYS:
                # Allow explicit boolean flags like api_billing_allowed; reject any string/secret payload
                if v is not None and not isinstance(v, bool):
                    raise SecretOrPiiIntakeError(
                        f"Forbidden secret or PII field '{path}.{k}' in intake payload."
                    )
                if low in _FORBIDDEN_PII_KEYS:
                    raise SecretOrPiiIntakeError(
                        f"Forbidden PII field '{path}.{k}' in intake payload."
                    )
            assert_no_secret_intake(v, path=f"{path}.{k}")
    elif isinstance(payload, (list, tuple)):
        for idx, item in enumerate(payload):
            assert_no_secret_intake(item, path=f"{path}[{idx}]")
    elif isinstance(payload, str):
        reason = contains_secret_or_pii(payload)
        if reason:
            raise SecretOrPiiIntakeError(
                f"Secret or PII pattern ({reason}) rejected at '{path}'."
            )


def sanitize_for_output(data: Any) -> Any:
    """Defensive recursive redaction + email scrubbing for any serialized output or explanation."""
    scrubbed = redact_mapping_for_audit(data)
    return _scrub_emails_recursive(scrubbed)


def _scrub_emails_recursive(data: Any) -> Any:
    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for k, v in data.items():
            low = str(k).strip().lower().replace("-", "_")
            if low in _FORBIDDEN_PII_KEYS:
                out[k] = REDACTED
            else:
                out[k] = _scrub_emails_recursive(v)
        return out
    if isinstance(data, list):
        return [_scrub_emails_recursive(item) for item in data]
    if isinstance(data, str):
        return _EMAIL_RE.sub(REDACTED, data)
    return data


__all__ = [
    "REDACTED",
    "SecretOrPiiIntakeError",
    "assert_no_secret_intake",
    "canonical_json_dumps",
    "canonical_sanitized_sha256",
    "contains_secret_or_pii",
    "sanitize_for_output",
    "validate_opaque_id",
]

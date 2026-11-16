from __future__ import annotations

import json
import logging
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key|cookie|credential|client[_-]?secret)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_PATTERNS = [
    re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"(AIza[0-9A-Za-z_-]{20,})"),
    re.compile(r"(sk-[A-Za-z0-9]{16,})"),
    re.compile(r"(ghp_[A-Za-z0-9]{20,})"),
]


def redact_value(value: Any) -> Any:
    """Recursively redact secrets, tokens, and credentials from structured payloads."""
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for k, v in value.items():
            key_str = str(k)
            is_token_count = key_str.lower().endswith("tokens") and isinstance(v, (int, float)) and not isinstance(v, bool)
            if is_token_count:
                # Model token *counts* (input_tokens, total_tokens, ...) are metrics, not credentials.
                sanitized[key_str] = v
            elif SENSITIVE_KEY_PATTERN.search(key_str) and key_str not in ("approval_token",):
                sanitized[key_str] = "[REDACTED]"
            elif key_str == "approval_token" and isinstance(v, str) and len(v) > 8:
                sanitized[key_str] = f"{v[:6]}...[REDACTED]"
            else:
                sanitized[key_str] = redact_value(v)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        result = value
        for pattern in SENSITIVE_VALUE_PATTERNS:
            if pattern.groups >= 1 and "Bearer" in pattern.pattern:
                result = pattern.sub(r"\1[REDACTED]", result)
            else:
                result = pattern.sub("[REDACTED]", result)
        return result
    return value


class StructuredAuditLogger:
    """Structured JSONL event logger and console formatter with secret redaction."""

    def __init__(self, app_home: Path | None = None) -> None:
        self.app_home = app_home or Path(
            os.environ.get("ANTIGRAVITY_AUDITOR_HOME", str(Path(__file__).resolve().parents[1]))
        )
        self.log_dir = self.app_home / "logs"
        self.jsonl_path = self.log_dir / "audit-events.jsonl"
        self._logger = logging.getLogger("antigravity_auditor")
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)
            self._logger.propagate = False

    def emit(
        self,
        event_type: str,
        *,
        level: str = "INFO",
        project_key: str | None = None,
        run_id: str | None = None,
        correlation_id: str | None = None,
        duration_ms: float | None = None,
        details: dict[str, Any] | None = None,
        jsonl_path: Path | None = None,
    ) -> dict[str, Any]:
        target_path = jsonl_path or self.jsonl_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.upper(),
            "event_type": event_type,
            "project_key": project_key,
            "run_id": run_id,
            "correlation_id": correlation_id or uuid.uuid4().hex[:12],
            "duration_ms": round(duration_ms, 2) if duration_ms is not None else None,
            "details": redact_value(details or {}),
        }
        serialized = json.dumps(record, ensure_ascii=False, sort_keys=True)
        with target_path.open("a", encoding="utf-8") as handle:
            handle.write(serialized + "\n")
        return record

    def console(self, message: str, *, error: bool = False) -> None:
        stream = sys.stderr if error else sys.stdout
        stream.write(redact_value(message) + "\n")
        stream.flush()

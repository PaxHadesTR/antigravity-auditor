"""Audit request logging interface for Broker control-plane."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class BrokerAuditLogger:
    """Thread-safe audit request logger recording all IPC requests and security decisions."""

    def __init__(self, log_path: Path | str | None = None, log_file: Path | str | None = None) -> None:
        target = log_path if log_path is not None else log_file
        self.log_path = Path(target) if target is not None else None
        self._lock = threading.Lock()
        self._events: list[dict[str, Any]] = []

    def log_request(
        self,
        *,
        request_id: str | int,
        method: str,
        client_pid: int,
        integrity_level: str,
        status: str,  # "ACCEPTED", "REJECTED", "ERROR"
        latency_ms: float = 0.0,
        error_code: int | None = None,
        error_message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record an audit event for an IPC request."""
        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "method": method,
            "client_pid": client_pid,
            "client_integrity": integrity_level,
            "status": status,
            "latency_ms": round(latency_ms, 2),
            "error_code": error_code,
            "error_message": error_message,
            "details": details or {},
        }

        with self._lock:
            self._events.append(record)
            if self.log_path is not None:
                try:
                    self.log_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(self.log_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(record, ensure_ascii=False) + "\n")
                except OSError:
                    pass

        return record

    def get_events(self) -> list[dict[str, Any]]:
        """Return memory-recorded audit events."""
        with self._lock:
            return list(self._events)

    def get_recent_logs(self, n: int = 10) -> list[dict[str, Any]]:
        """Return the n most recent audit events."""
        with self._lock:
            return list(self._events[-n:])

    def clear(self) -> None:
        """Clear memory-recorded events."""
        with self._lock:
            self._events.clear()

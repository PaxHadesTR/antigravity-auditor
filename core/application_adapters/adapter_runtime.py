"""Common stdio adapter host bridging client stdio JSON-RPC to NEXT-22C Gateway."""

from __future__ import annotations

import contextlib
import json
import sys
import time
from typing import Any, BinaryIO, TextIO

from entitlement_router.privacy import redact_text
from mcp_gateway.authenticated_context import AuthenticatedCallerContext
from mcp_gateway.contracts import UNIVERSAL_MINIMUM_READ_SCOPES, AuthMethod

from application_adapters.broker_transport import (
    BrokerTransport,
    BrokerTransportError,
    BrokerTransportUnavailableError,
)
from application_adapters.contracts import contains_secret_material

DEFAULT_MAX_MESSAGE_BYTES = 1024 * 1024  # 1 MiB strict bound
DEFAULT_REQUEST_TIMEOUT_SECONDS = 15.0


def _fail_closed_unknown_caller() -> AuthenticatedCallerContext:
    return AuthenticatedCallerContext(
        principal_id="unauthenticated-adapter-host",
        application_id="UNKNOWN",
        authentication_method=AuthMethod.UNAUTHENTICATED,
        authorization_scopes=frozenset(),
        verified_application_identity=False,
        operating_system_identity={"verified_by_os": False},
        diagnostic_reasons=("UNAUTHENTICATED_ADAPTER_FALLBACK",),
    )


class CommonStdioAdapterHost:
    """Single shared stdio JSON-RPC host used across all application adapter profiles.

    Security invariants:
    - JSON-RPC goes ONLY to stdout; diagnostics go ONLY to stderr (redacted).
    - Never trusts clientInfo, CLI application hints, or env vars for identity/authz.
    - Never opens SQLite directly, executes shell commands, or connects to production pipes.
    - Enforces bounded input frame sizes and deterministic clean shutdown.
    """

    def __init__(
        self,
        *,
        transport: BrokerTransport,
        caller_context: AuthenticatedCallerContext | None = None,
        application_profile_id: str | None = None,
        stderr_stream: TextIO | None = None,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self.transport = transport
        self.caller_context = caller_context if caller_context is not None else _fail_closed_unknown_caller()
        self.claimed_profile_hint = application_profile_id  # Telemetry only, never trusted for authz
        self._stderr = stderr_stream if stderr_stream is not None else sys.stderr
        self.max_message_bytes = max(4096, int(max_message_bytes))
        self.request_timeout_seconds = max(0.5, float(request_timeout_seconds))
        self._closed = False
        self.requests_processed = 0

    @property
    def is_closed(self) -> bool:
        return self._closed

    def log_diagnostic(self, message: str) -> None:
        safe = redact_text(str(message))
        if contains_secret_material(safe):
            safe = "[REDACTED_DIAGNOSTIC_WITH_SECRET_PATTERN]"
        self._stderr.write(f"[antigravity-auditor-adapter] {safe}\n")
        self._stderr.flush()

    def process_raw_payload(self, raw_body: bytes) -> dict[str, Any] | None:
        if len(raw_body) > self.max_message_bytes:
            self.log_diagnostic(f"Rejected oversized JSON-RPC payload ({len(raw_body)} bytes).")
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": f"OVERSIZED_REQUEST: payload exceeded {self.max_message_bytes} bytes.",
                },
            }

        try:
            msg = json.loads(raw_body.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.log_diagnostic(f"Malformed JSON-RPC input: {exc}")
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error: invalid JSON payload."},
            }

        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return {
                "jsonrpc": "2.0",
                "id": msg.get("id") if isinstance(msg, dict) else None,
                "error": {"code": -32600, "message": "Invalid Request: expected JSON-RPC 2.0 request object with string method."},
            }

        start = time.monotonic()
        try:
            with contextlib.redirect_stdout(self._stderr):
                resp = self.transport.handle_gateway_rpc(
                    msg,
                    caller_context=self.caller_context,
                )
        except (BrokerTransportError, BrokerTransportUnavailableError) as exc:
            err_text = redact_text(str(exc))
            self.log_diagnostic(f"Transport failure: {err_text}")
            return {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "error": {"code": -32001, "message": err_text},
            }
        except Exception as exc:
            err_text = redact_text(str(exc))
            self.log_diagnostic(f"Adapter host failure: {err_text}")
            return {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "error": {"code": -32603, "message": "Internal adapter error (see redacted stderr diagnostics)."},
            }

        elapsed = time.monotonic() - start
        if elapsed > self.request_timeout_seconds:
            # ARCH-06: the budget is measured after the synchronous call has already
            # finished, so any side effects (e.g. auditor_publish_report DB writes) are
            # already committed. Replacing the real response with a timeout error would
            # make the client believe the call failed and retry it (duplicate publish).
            # Keep the budget as a diagnostic only and return the actual result.
            self.log_diagnostic(
                f"Slow request: method={msg.get('method')!r} took {elapsed:.3f}s "
                f"(budget {self.request_timeout_seconds:.3f}s); returning the completed response."
            )
        self.requests_processed += 1
        return resp

    def serve_streams(self, in_stream: BinaryIO, out_stream: BinaryIO) -> int:
        """Read JSON-RPC messages (Content-Length or newline-delimited) until EOF and close cleanly."""
        self.log_diagnostic(
            f"Adapter stdio host started (claimed_hint={self.claimed_profile_hint or 'none'}, "
            f"verified_app={self.caller_context.verified_application_identity}, "
            f"resolved_app={self.caller_context.application_id}, "
            f"transport={self.transport.transport_kind})."
        )
        try:
            while not self._closed:
                first_line = in_stream.readline(self.max_message_bytes + 64)
                if not first_line:
                    break
                if len(first_line) > self.max_message_bytes:
                    # Discard the rest of the oversized line so it is not parsed as a new message.
                    tail = first_line
                    while tail and not tail.endswith(b"\n"):
                        tail = in_stream.readline(self.max_message_bytes)
                    err = self.process_raw_payload(first_line)
                    if err is not None:
                        self._write_frame(out_stream, err, content_length=False)
                    continue
                stripped = first_line.strip()
                if not stripped:
                    continue

                use_content_length = stripped.lower().startswith(b"content-length:")
                if use_content_length:
                    headers: dict[str, str] = {}
                    header_line = first_line
                    header_count = 0
                    while header_line.strip() and header_count < 16:
                        header_count += 1
                        decoded = header_line.decode("ascii", errors="replace").strip()
                        if ":" in decoded:
                            k, v = decoded.split(":", 1)
                            headers[k.strip().lower()] = v.strip()
                        header_line = in_stream.readline(4096)
                        if not header_line:
                            break
                    try:
                        length = int(headers.get("content-length", "0"))
                    except ValueError:
                        length = -1
                    if length <= 0 or length > self.max_message_bytes:
                        if length > self.max_message_bytes * 2:
                            # Draining that much is not worth it and the stream would desynchronise: fail closed.
                            self._closed = True
                        elif length > 0:
                            in_stream.read(length)
                        err_resp = {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {
                                "code": -32600,
                                "message": f"Invalid or oversized Content-Length ({length}).",
                            },
                        }
                        self._write_frame(out_stream, err_resp, content_length=True)
                        continue
                    raw_body = in_stream.read(length)
                    if len(raw_body) < length:
                        break
                else:
                    raw_body = stripped

                resp = self.process_raw_payload(raw_body)
                if resp is not None:
                    self._write_frame(out_stream, resp, content_length=use_content_length)
            return 0
        finally:
            self.close()

    def _write_frame(self, out_stream: BinaryIO, resp: dict[str, Any], *, content_length: bool) -> None:
        payload = json.dumps(resp, ensure_ascii=False).encode("utf-8")
        if content_length:
            header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
            out_stream.write(header + payload)
        else:
            out_stream.write(payload + b"\n")
        out_stream.flush()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.transport.close()
            self.log_diagnostic("Adapter stdio host shut down cleanly.")

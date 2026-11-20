"""Antigravity Auditor — Local Antigravity CLI (agy.exe) Adapter.

Robust wrapper around the verified local `agy.exe`:
- Resolves executable dynamically without hardcoded usernames.
- Invokes subprocess using argument arrays with shell=False strictly.
- Dispatches only models approved by model_registry (host hard policy + active routing table;
  Antigravity: Gemini only, Flash retired); accepts agy:-qualified refs.
- Strictly rejects Claude, GPT, and arbitrary model strings for the antigravity host.
- Parses stream-json events (init, step_update, result, usage).
- Enforces read-only boundaries (--mode plan) and keeps Repair Worker writable dispatch disabled.
- Never silently falls back to another model or tier, and never silently falls back to AgentAPI.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from model_attestation import AttestationStatus, attest_conversation_model
from model_policy import (
    ExecutionIntent,
    ModelId,
    ModelRoutingRequest,
    ReasoningLevel,
    RoutingStatus,
    TaskRisk,
    TaskType,
    route_model,
)
from model_registry import (
    ModelRefError,
    approved_model_slugs,
    hard_policy_violation,
    is_scarce_model,
    model_slug,
)


# Session settings for isolated helper dispatches (model probes, web research): never call MCP tools
# (the agy CLI has the auditor's own MCP server configured, and web content is untrusted) and never
# run shell commands. Headless agy already auto-denies both; the explicit deny keeps that true even if
# a user later adds allow rules to their agy settings.
ISOLATED_SESSION_SETTINGS = '{"permissions": {"deny": ["mcp(*)", "command(*)"]}}'


from model_registry import RoutingTier as _RoutingTierForRank  # noqa: E402

_TIER_RANK = {
    _RoutingTierForRank.ENTRY: 0,
    _RoutingTierForRank.STANDARD: 1,
    _RoutingTierForRank.CRITICAL: 2,
    _RoutingTierForRank.CATASTROPHIC: 3,
}


def _tier_of_model(model_slug_value: str, db_path: Path | None) -> "RoutingTier | None":
    """Lowest routing tier of the active table served by ``model_slug_value`` (None if not in the table)."""
    from model_registry import get_active_routing_table, model_slug

    try:
        table = get_active_routing_table(db_path=db_path)
    except Exception:  # noqa: BLE001 - a broken table blocks dispatch elsewhere (route_model)
        return None
    tiers = [t for t, m in table.assignments.items() if model_slug(m) == model_slug_value]
    return min(tiers, key=lambda t: _TIER_RANK[t]) if tiers else None

def _normalize_dispatch_model(model_id: str | None) -> str:
    """Bare slug for ``agy --model`` (accepts ``agy:``-qualified refs); '' when malformed."""
    try:
        return model_slug(model_id or "")
    except ModelRefError:
        return ""


def _unapproved_model_reason(model_id: str | None, db_path: Path | None = None) -> str:
    violation = hard_policy_violation(model_id)
    if violation:
        return violation
    try:
        approved = approved_model_slugs(db_path=db_path)
    except Exception as exc:  # routing table unavailable/invalid
        return f"Active routing table unavailable: {exc}"
    return f"Model '{model_id}' is not assigned in the active routing table (approved: {approved})."


UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

AUTH_FAILURE_PATTERNS = [
    re.compile(r"authentication\s+failed", re.IGNORECASE),
    re.compile(r"not\s+logged\s+in", re.IGNORECASE),
    re.compile(r"login\s+required", re.IGNORECASE),
    re.compile(r"sign-?in\s+required", re.IGNORECASE),
    re.compile(r"invalid\s+credentials", re.IGNORECASE),
]

STRUCTURED_AUTH_ERROR_CODES = frozenset({
    "AUTH_ERROR",
    "AUTHENTICATION_FAILED",
    "UNAUTHENTICATED",
    "NOT_LOGGED_IN",
    "SIGN_IN_REQUIRED",
    "LOGIN_REQUIRED",
})


def check_authentication_failure(
    stderr: str,
    parsed: StreamJsonParseResult,
) -> bool:
    """Detect authentic CLI authentication errors without inspecting assistant text or tool results.

    Invariants:
    1. Inspects explicit CLI stderr diagnostics against known auth failure patterns.
    2. Inspects structured CLI error events (event_type == 'error' or result error fields) in stream-json.
    3. NEVER inspects assistant text deltas, final response text, or MCP tool outputs.
    """
    # 1. Explicit CLI stderr diagnostics
    if stderr:
        for ptn in AUTH_FAILURE_PATTERNS:
            if ptn.search(stderr):
                return True

    # 2. Structured CLI error events in stream-json (only explicit error fields, never response or tool content)
    for ev in parsed.events:
        if not isinstance(ev, dict):
            continue
        ev_type = ev.get("event") or ev.get("type")

        # Top-level error event: {"event": "error", "error": ...}
        if ev_type == "error":
            code = str(ev.get("error_code") or ev.get("code") or "").strip().upper()
            if code in STRUCTURED_AUTH_ERROR_CODES:
                return True
            err_val = ev.get("error") or ev.get("message")
            if isinstance(err_val, dict):
                sub_code = str(err_val.get("code") or err_val.get("error_code") or "").strip().upper()
                if sub_code in STRUCTURED_AUTH_ERROR_CODES:
                    return True
                sub_msg = str(err_val.get("message") or "")
                if any(ptn.search(sub_msg) for ptn in AUTH_FAILURE_PATTERNS):
                    return True
            elif isinstance(err_val, str) and any(ptn.search(err_val) for ptn in AUTH_FAILURE_PATTERNS):
                return True

        # Result event with error payload: {"event": "result", "result": {"status": "ERROR", ...}}
        elif ev_type == "result":
            res_obj = ev.get("result")
            if isinstance(res_obj, dict):
                res_status = str(res_obj.get("status") or "").strip().upper()
                if res_status in STRUCTURED_AUTH_ERROR_CODES:
                    return True
                res_code = str(res_obj.get("error_code") or res_obj.get("code") or "").strip().upper()
                if res_code in STRUCTURED_AUTH_ERROR_CODES:
                    return True
                res_err = res_obj.get("error") or res_obj.get("error_message")
                if isinstance(res_err, dict):
                    sub_code = str(res_err.get("code") or "").strip().upper()
                    if sub_code in STRUCTURED_AUTH_ERROR_CODES:
                        return True
                    sub_msg = str(res_err.get("message") or "")
                    if any(ptn.search(sub_msg) for ptn in AUTH_FAILURE_PATTERNS):
                        return True
                elif isinstance(res_err, str) and any(ptn.search(res_err) for ptn in AUTH_FAILURE_PATTERNS):
                    return True

    return False


# Provider-side quota / rate limits (the Google account ran out for the model). Matched only on CLI stderr and
# structured error fields of a FAILED dispatch, never on assistant text or tool output.
QUOTA_FAILURE_PATTERNS = [
    re.compile(r"resource[_\s-]?exhausted", re.IGNORECASE),
    re.compile(r"quota[^\n]{0,60}?(exceed|exhaust|reached|limit|ran\s+out|resets?)", re.IGNORECASE),
    re.compile(r"(exceed|exhaust|reached|out\s+of)[^\n]{0,40}?quota", re.IGNORECASE),
    re.compile(r"rate[\s_-]?limit(ed)?[^\n]{0,40}?(exceed|reached|hit)|\brate[\s_-]?limited\b", re.IGNORECASE),
    re.compile(r"too\s+many\s+requests", re.IGNORECASE),
    re.compile(r"\b(status|code|http|error)[\s:=]*429\b|\b429\s+too\s+many", re.IGNORECASE),
    re.compile(r"usage\s+limit\s+(reached|exceeded)", re.IGNORECASE),
]

STRUCTURED_QUOTA_ERROR_CODES = frozenset({
    "RESOURCE_EXHAUSTED",
    "QUOTA_EXCEEDED",
    "QUOTA_EXHAUSTED",
    "RATE_LIMITED",
    "RATE_LIMIT_EXCEEDED",
    "TOO_MANY_REQUESTS",
    "USAGE_LIMIT_REACHED",
    "429",
})

_RETRY_AFTER_PATTERNS = [
    (re.compile(r"retry[\s_-]?after[\s:=\"']*(\d{1,6})\s*(s|sec|secs|seconds)?\b", re.IGNORECASE), 1),
    (re.compile(r"(?:retry|try\s+again|resets?)\s+in\s+(\d{1,4})\s*(h|hr|hrs|hours?)\b", re.IGNORECASE), 3600),
    (re.compile(r"(?:retry|try\s+again|resets?)\s+in\s+(\d{1,5})\s*(m|min|mins|minutes?)\b", re.IGNORECASE), 60),
    (re.compile(r"(?:retry|try\s+again|resets?)\s+in\s+(\d{1,6})\s*(s|sec|secs|seconds?)\b", re.IGNORECASE), 1),
]


def _structured_error_fields(parsed: StreamJsonParseResult) -> list[tuple[str, str]]:
    """(code, message) pairs from explicit error events / result error payloads only."""
    out: list[tuple[str, str]] = []
    for ev in parsed.events:
        if not isinstance(ev, dict):
            continue
        ev_type = ev.get("event") or ev.get("type")
        if ev_type == "error":
            err = ev.get("error") or ev.get("message")
            code = str(ev.get("error_code") or ev.get("code") or "")
            if isinstance(err, dict):
                out.append((str(err.get("code") or err.get("error_code") or err.get("status") or code),
                            str(err.get("message") or "")))
            else:
                out.append((code, str(err or "")))
        elif ev_type == "result" and isinstance(ev.get("result"), dict):
            res = ev["result"]
            err = res.get("error") or res.get("error_message")
            code = str(res.get("error_code") or res.get("code") or "")
            if isinstance(err, dict):
                out.append((str(err.get("code") or err.get("status") or code), str(err.get("message") or "")))
            elif err or code:
                out.append((code, str(err or "")))
    return out


def check_quota_exhausted(stderr: str, parsed: StreamJsonParseResult) -> tuple[bool, int | None]:
    """Did a failed dispatch fail because the provider quota / rate limit ran out? Returns (hit, retry_after_s)."""
    texts: list[str] = [stderr or ""]
    hit = bool(stderr) and any(p.search(stderr) for p in QUOTA_FAILURE_PATTERNS)
    for code, msg in _structured_error_fields(parsed):
        texts.append(msg)
        if code.strip().upper() in STRUCTURED_QUOTA_ERROR_CODES or any(p.search(msg) for p in QUOTA_FAILURE_PATTERNS):
            hit = True
    if not hit:
        return False, None
    for text in texts:
        for rx, unit in _RETRY_AFTER_PATTERNS:
            m = rx.search(text)
            if m:
                return True, max(1, min(int(m.group(1)) * unit, 7 * 86400))
    return True, None


class PermissionCapabilityStatus:
    """Explicit permission verification statuses."""

    READ_ONLY_VERIFIED = "READ_ONLY_VERIFIED"
    READ_ONLY_UNVERIFIED = "READ_ONLY_UNVERIFIED"
    WRITE_VERIFIED = "WRITE_VERIFIED"
    PERMISSION_TEST_FAILED = "PERMISSION_TEST_FAILED"


@dataclass(frozen=True)
class StreamJsonParseResult:
    """Parsed output from CLI stream-json execution."""

    conversation_id: str | None
    reported_model: str | None
    status: str
    response_text: str
    input_tokens: int
    output_tokens: int
    thinking_tokens: int
    total_tokens: int
    duration_seconds: float
    denied_actions: list[dict[str, Any]]
    events: list[dict[str, Any]]
    malformed_lines_count: int
    missing_result: bool


@dataclass(frozen=True)
class AgyDispatchResult:
    """Standardized outcome of an Antigravity CLI dispatch."""

    ok: bool
    status: str  # SUCCESS | FAILED | CLI_UNAVAILABLE | INVALID_MODEL | CLI_TIMEOUT | CLI_CANCELLED | CLI_AUTHENTICATION_FAILED | PERMISSION_TEST_FAILED | REPAIR_WORKER_DISABLED | ARGON_QUOTA_EXHAUSTED
    requested_model: str
    observed_model: str | None
    conversation_id: str | None
    response_text: str
    input_tokens: int
    output_tokens: int
    thinking_tokens: int
    total_tokens: int
    execution_duration: float
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    error_code: str | None = None
    error_message: str | None = None
    permission_capability_status: str = PermissionCapabilityStatus.READ_ONLY_UNVERIFIED
    events: list[dict[str, Any]] = field(default_factory=list)
    attestation_status: str = "MODEL_ATTESTATION_INCOMPLETE"
    invocation_mechanism: str = "antigravity_cli"
    agent_id: str | None = None
    retry_after_seconds: int | None = None

    @property
    def model_id(self) -> str | None:
        return self.observed_model or self.requested_model

    @property
    def dispatch_uncertain(self) -> bool:
        return self.status == "DISPATCH_UNCERTAIN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "requested_model": self.requested_model,
            "observed_model": self.observed_model,
            "conversation_id": self.conversation_id,
            "response_text": self.response_text,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "thinking_tokens": self.thinking_tokens,
            "total_tokens": self.total_tokens,
            "execution_duration": self.execution_duration,
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "retry_after_seconds": self.retry_after_seconds,
            "permission_capability_status": self.permission_capability_status,
            "events_count": len(self.events),
            "attestation_status": self.attestation_status,
            "invocation_mechanism": self.invocation_mechanism,
            "agent_id": self.agent_id,
        }


def _token_count(value: Any) -> int:
    """Non-negative int from an untrusted usage field (malformed values count as 0)."""
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _usage_counts(usage: dict[str, Any]) -> tuple[int, int, int, int]:
    inp = _token_count(usage.get("input_tokens"))
    out = _token_count(usage.get("output_tokens"))
    think = _token_count(usage.get("thinking_tokens"))
    total = _token_count(usage.get("total_tokens")) or (inp + out + think)
    return inp, out, think, total


def parse_stream_json(raw_stdout: str) -> StreamJsonParseResult:
    """Parse Antigravity CLI stream-json NDJSON lines robustly.

    Extracts init, step_update, and result events, handling malformed lines,
    missing results, partial outputs, and token deduplication.
    """
    conversation_id: str | None = None
    reported_model: str | None = None
    status = "UNKNOWN"
    response_parts: list[str] = []
    input_tokens = 0
    output_tokens = 0
    thinking_tokens = 0
    total_tokens = 0
    duration_seconds = 0.0
    denied_actions: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    malformed_count = 0
    saw_result = False

    if not raw_stdout:
        return StreamJsonParseResult(
            conversation_id=None,
            reported_model=None,
            status="EMPTY_OUTPUT",
            response_text="",
            input_tokens=0,
            output_tokens=0,
            thinking_tokens=0,
            total_tokens=0,
            duration_seconds=0.0,
            denied_actions=[],
            events=[],
            malformed_lines_count=0,
            missing_result=True,
        )

    for line in raw_stdout.splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        try:
            data = json.loads(trimmed)
        except json.JSONDecodeError:
            malformed_count += 1
            continue

        if not isinstance(data, dict):
            malformed_count += 1
            continue

        events.append(data)
        event_type = data.get("event") or data.get("type")

        # 1. Init event
        if event_type == "init":
            cid = data.get("conversation_id")
            if cid and isinstance(cid, str):
                conversation_id = cid.strip()
            init_obj = data.get("init")
            if isinstance(init_obj, dict):
                model = init_obj.get("model")
                if model and isinstance(model, str):
                    reported_model = model.strip()

        # 2. Step update event
        elif event_type == "step_update":
            step_obj = data.get("step_update")
            if isinstance(step_obj, dict):
                cid = step_obj.get("conversation_id")
                if cid and not conversation_id and isinstance(cid, str):
                    conversation_id = cid.strip()
                delta = step_obj.get("text_delta")
                if delta and isinstance(delta, str):
                    response_parts.append(delta)
                # Keep latest usage from step updates as fallback
                usage = step_obj.get("usage")
                if isinstance(usage, dict) and not saw_result:
                    input_tokens, output_tokens, thinking_tokens, total_tokens = _usage_counts(usage)

        # 3. Result event (authoritative)
        elif event_type == "result":
            saw_result = True
            res_obj = data.get("result")
            if isinstance(res_obj, dict):
                cid = res_obj.get("conversation_id")
                if cid and isinstance(cid, str):
                    conversation_id = cid.strip()
                res_status = res_obj.get("status")
                if res_status and isinstance(res_status, str):
                    status = res_status.strip()
                resp = res_obj.get("response")
                if resp is not None:
                    response_parts = [str(resp)]
                dur = res_obj.get("duration_seconds")
                if dur is not None:
                    try:
                        duration_seconds = float(dur)
                    except (ValueError, TypeError):
                        pass
                usage = res_obj.get("usage")
                if isinstance(usage, dict):
                    input_tokens, output_tokens, thinking_tokens, total_tokens = _usage_counts(usage)
                denied = res_obj.get("denied_actions")
                if isinstance(denied, list):
                    denied_actions.extend(d for d in denied if isinstance(d, dict))

    final_response = "".join(response_parts)
    if not saw_result and status == "UNKNOWN":
        status = "INCOMPLETE"

    return StreamJsonParseResult(
        conversation_id=conversation_id,
        reported_model=reported_model,
        status=status,
        response_text=final_response,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        thinking_tokens=thinking_tokens,
        total_tokens=total_tokens,
        duration_seconds=duration_seconds,
        denied_actions=denied_actions,
        events=events,
        malformed_lines_count=malformed_count,
        missing_result=not saw_result,
    )


PRIMARY_AUDIT_TIMEOUT_SECONDS: int = 300
# Second-pass verification re-inspects every candidate independently; a real 12-candidate run timed out
# twice at the 120 s adapter default (2026-11-15).
VERIFICATION_TIMEOUT_SECONDS: int = 1800  # multi-pass audits hand over ~3x more candidates
_VERIFICATION_TASKS = {"ROUTINE_VERIFICATION", "CRITICAL_VERIFICATION"}


# Windows caps a process command line at 32,767 characters (CreateProcess fails with [WinError 206]). A prompt
# that would push the command line past this margin (e.g. a verification with dozens of candidates) is sent on
# stdin as one stream-json user message instead of as the `-p` argument; output and flags are unchanged.
MAX_COMMAND_LINE_CHARS = 30000


def stdin_prompt_message(prompt: str) -> str:
    """The NDJSON line `agy --input-format stream-json` reads for one user turn."""
    return json.dumps({"event": "user", "message": {"role": "user", "content": prompt}}, ensure_ascii=False) + "\n"


class AntigravityCliAdapter:
    """Testable adapter around `agy.exe`."""

    def __init__(
        self,
        *,
        executable_override: str | None = None,
        env: dict[str, str] | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        timeout_seconds: int = 120,
    ) -> None:
        self.executable_override = executable_override
        self._env = dict(env) if env is not None else None
        self._runner = runner or subprocess.run
        self.timeout_seconds = max(1, int(timeout_seconds))

    def _effective_env(self) -> dict[str, str]:
        if self._env is not None:
            return dict(self._env)
        return os.environ.copy()

    def discover_executable(self) -> Path | None:
        """Resolve `agy.exe` dynamically without hardcoding usernames or modifying PATH."""
        env = self._effective_env()

        # 1. Explicit override: caller requested this specific binary
        if self.executable_override:
            cand = Path(self.executable_override).expanduser()
            if cand.is_file():
                return cand.resolve()
            found_override = shutil.which(self.executable_override, path=env.get("PATH"))
            if found_override:
                return Path(found_override).resolve()
            return None

        # 2. Environment variable ANTIGRAVITY_CLI_EXE
        env_explicit = env.get("ANTIGRAVITY_CLI_EXE", "").strip()
        if env_explicit:
            cand = Path(env_explicit).expanduser()
            if cand.is_file():
                return cand.resolve()
            found_env = shutil.which(env_explicit, path=env.get("PATH"))
            if found_env:
                return Path(found_env).resolve()
            return None

        # 3. LOCALAPPDATA / agy / bin / agy.exe
        local_app_data = env.get("LOCALAPPDATA", "").strip()
        if local_app_data:
            default_cand = Path(local_app_data) / "agy" / "bin" / "agy.exe"
            if default_cand.is_file():
                return default_cand.resolve()

        # 4. System PATH fallback
        found_in_path = shutil.which("agy", path=env.get("PATH"))
        if found_in_path:
            return Path(found_in_path).resolve()

        return None

    # Headless print mode cannot use MCP tools, so results come back as schema-constrained JSON.
    SUPPORTS_STRUCTURED_DELIVERY = True

    def build_command(
        self,
        *,
        prompt: str,
        model_id: str,
        mode: str = "plan",
        probe: bool = False,
        json_schema_path: str | Path | None = None,
        db_path: Path | None = None,
        isolated: bool = False,
    ) -> list[str]:
        """Construct argument array. Always shell=False, no string interpolation.

        ``probe=True`` is the model-probe path: the model only has to pass host hard policy (it may
        not yet be in the routing table), and plan mode is mandatory.
        """
        if not prompt or not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Prompt must be a non-empty string.")

        clean_model = _normalize_dispatch_model(model_id)
        if probe:
            if mode != "plan":
                raise ValueError("Probe dispatch is restricted to --mode plan.")
            violation = hard_policy_violation(model_id) if clean_model else f"Malformed model '{model_id}'."
            if violation:
                raise ValueError(f"Model '{model_id}' may not be probed: {violation}")
        elif not clean_model or not ModelId.is_approved(model_id, db_path=db_path):
            raise ValueError(f"Model '{model_id}' is not approved: {_unapproved_model_reason(model_id, db_path)}")

        exe = self.discover_executable()
        if exe is None:
            # If executable_override was set, use its path string in error message
            raise FileNotFoundError(
                "Antigravity CLI executable (agy.exe) not found in LOCALAPPDATA or PATH."
            )

        cmd = [
            str(exe),
            "-p",
            prompt,
            "--model",
            clean_model,
            "--mode",
            mode,
            "--output-format",
            "stream-json",
        ]
        if probe or isolated:
            cmd.extend(["--settings", ISOLATED_SESSION_SETTINGS])
        if json_schema_path is not None:
            cmd.extend(["--json-schema", str(json_schema_path)])
        if len(subprocess.list2cmdline(cmd)) > MAX_COMMAND_LINE_CHARS:
            # The prompt goes to stdin (see dispatch); `-p=` keeps print mode with an empty argument.
            cmd[1:3] = ["-p=", "--input-format", "stream-json"]
        return cmd

    @staticmethod
    def prompt_on_stdin(cmd: Sequence[str]) -> bool:
        return len(cmd) > 1 and cmd[1] == "-p="

    def dispatch(
        self,
        *,
        prompt: str,
        model_id: str,
        cwd: Path | str,
        mode: str = "plan",
        timeout_seconds: int | None = None,
        allow_write: bool = False,
        probe: bool = False,
        json_schema_path: str | Path | None = None,
        db_path: Path | None = None,
        isolated: bool = False,
    ) -> AgyDispatchResult:
        """Execute a prompt via `agy.exe` and capture stream-json events.

        Safety boundaries:
        - Repair Worker writable dispatch remains hard-disabled unless independently verified.
        - Claude, GPT, and unapproved models rejected upfront.
        - Plan mode (--mode plan) enforced for read-only audit/verifier tasks.
        """
        # Hard fail if caller attempts writable dispatch without verification
        if allow_write:
            return AgyDispatchResult(
                ok=False,
                status="REPAIR_WORKER_DISABLED",
                requested_model=model_id,
                observed_model=None,
                conversation_id=None,
                response_text="",
                input_tokens=0,
                output_tokens=0,
                thinking_tokens=0,
                total_tokens=0,
                execution_duration=0.0,
                command=[],
                returncode=None,
                stdout="",
                stderr="",
                error_code="REPAIR_WORKER_WRITABLE_DISPATCH_DISABLED",
                error_message=(
                    "Repair Worker writable execution is disabled. "
                    "Operating-system-level NTFS write fences have not been independently verified."
                ),
                permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
            )

        clean_model = _normalize_dispatch_model(model_id)
        probe_rejected = probe and (
            mode != "plan" or not clean_model or hard_policy_violation(model_id) is not None
        )
        if probe_rejected or (not probe and (not clean_model or not ModelId.is_approved(model_id, db_path=db_path))):
            return AgyDispatchResult(
                ok=False,
                status="INVALID_MODEL",
                requested_model=model_id,
                observed_model=None,
                conversation_id=None,
                response_text="",
                input_tokens=0,
                output_tokens=0,
                thinking_tokens=0,
                total_tokens=0,
                execution_duration=0.0,
                command=[],
                returncode=None,
                stdout="",
                stderr="",
                error_code="UNAPPROVED_MODEL",
                error_message=f"Model '{model_id}' is prohibited. Only verified Gemini models allowed.",
                permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
            )

        try:
            cmd = self.build_command(
                prompt=prompt, model_id=clean_model, mode=mode, probe=probe, json_schema_path=json_schema_path,
                db_path=db_path, isolated=isolated,
            )
        except FileNotFoundError as exc:
            return AgyDispatchResult(
                ok=False,
                status="CLI_UNAVAILABLE",
                requested_model=clean_model,
                observed_model=None,
                conversation_id=None,
                response_text="",
                input_tokens=0,
                output_tokens=0,
                thinking_tokens=0,
                total_tokens=0,
                execution_duration=0.0,
                command=[],
                returncode=None,
                stdout="",
                stderr="",
                error_code="CLI_UNAVAILABLE",
                error_message=str(exc),
                permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
            )
        except ValueError as exc:
            return AgyDispatchResult(
                ok=False,
                status="INVALID_MODEL",
                requested_model=clean_model,
                observed_model=None,
                conversation_id=None,
                response_text="",
                input_tokens=0,
                output_tokens=0,
                thinking_tokens=0,
                total_tokens=0,
                execution_duration=0.0,
                command=[],
                returncode=None,
                stdout="",
                stderr="",
                error_code="INVALID_PROMPT_OR_MODEL",
                error_message=str(exc),
                permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
            )

        working_dir = Path(cwd).resolve()
        effective_timeout = max(1, int(timeout_seconds or self.timeout_seconds))
        start_t = time.monotonic()

        stdin_kwargs: dict[str, Any] = {}
        if self.prompt_on_stdin(cmd):
            stdin_kwargs = {"input": stdin_prompt_message(prompt), "encoding": "utf-8"}
        try:
            proc = self._runner(
                cmd,
                cwd=str(working_dir),
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                env=self._effective_env(),
                **stdin_kwargs,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - start_t
            out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
            err = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
            parsed = parse_stream_json(out)
            return AgyDispatchResult(
                ok=False,
                status="CLI_TIMEOUT",
                requested_model=clean_model,
                observed_model=parsed.reported_model,
                conversation_id=parsed.conversation_id,
                response_text=parsed.response_text,
                input_tokens=parsed.input_tokens,
                output_tokens=parsed.output_tokens,
                thinking_tokens=parsed.thinking_tokens,
                total_tokens=parsed.total_tokens,
                execution_duration=elapsed,
                command=cmd,
                returncode=None,
                stdout=out,
                stderr=err,
                error_code="TIMEOUT",
                error_message=f"Process timed out after {effective_timeout}s",
                permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
                events=parsed.events,
            )
        except KeyboardInterrupt:
            elapsed = time.monotonic() - start_t
            return AgyDispatchResult(
                ok=False,
                status="CLI_CANCELLED",
                requested_model=clean_model,
                observed_model=None,
                conversation_id=None,
                response_text="",
                input_tokens=0,
                output_tokens=0,
                thinking_tokens=0,
                total_tokens=0,
                execution_duration=elapsed,
                command=cmd,
                returncode=None,
                stdout="",
                stderr="",
                error_code="CANCELLED",
                error_message="Execution cancelled by user",
                permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
            )
        except Exception as exc:
            elapsed = time.monotonic() - start_t
            return AgyDispatchResult(
                ok=False,
                status="CLI_EXECUTION_FAILED",
                requested_model=clean_model,
                observed_model=None,
                conversation_id=None,
                response_text="",
                input_tokens=0,
                output_tokens=0,
                thinking_tokens=0,
                total_tokens=0,
                execution_duration=elapsed,
                command=cmd,
                returncode=None,
                stdout="",
                stderr=str(exc),
                error_code="SUBPROCESS_ERROR",
                error_message=str(exc),
                permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
            )

        elapsed = time.monotonic() - start_t
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        parsed = parse_stream_json(stdout)

        # Check authentication failure (explicit stderr diagnostics or structured error events only)
        if check_authentication_failure(stderr, parsed):
            return AgyDispatchResult(
                    ok=False,
                    status="CLI_AUTHENTICATION_FAILED",
                    requested_model=clean_model,
                    observed_model=parsed.reported_model,
                    conversation_id=parsed.conversation_id,
                    response_text=parsed.response_text,
                    input_tokens=parsed.input_tokens,
                    output_tokens=parsed.output_tokens,
                    thinking_tokens=parsed.thinking_tokens,
                    total_tokens=parsed.total_tokens,
                    execution_duration=elapsed,
                    command=cmd,
                    returncode=proc.returncode,
                    stdout=stdout,
                    stderr=stderr,
                    error_code="AUTHENTICATION_FAILED",
                    error_message="Antigravity CLI authentication failed.",
                    permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
                    events=parsed.events,
                )

        # Provider quota / rate limit: a distinct, non-retryable-now outcome (retrying in seconds only burns attempts)
        if proc.returncode != 0 or parsed.missing_result or parsed.status in ("FAILED", "ERROR", "INCOMPLETE"):
            quota_hit, retry_after = check_quota_exhausted(stderr, parsed)
            if quota_hit:
                return AgyDispatchResult(
                    ok=False,
                    status="PROVIDER_QUOTA_EXHAUSTED",
                    requested_model=clean_model,
                    observed_model=parsed.reported_model,
                    conversation_id=parsed.conversation_id,
                    response_text="",
                    input_tokens=parsed.input_tokens,
                    output_tokens=parsed.output_tokens,
                    thinking_tokens=parsed.thinking_tokens,
                    total_tokens=parsed.total_tokens,
                    execution_duration=elapsed,
                    command=cmd,
                    returncode=proc.returncode,
                    stdout=stdout,
                    stderr=stderr,
                    error_code="PROVIDER_QUOTA_EXHAUSTED",
                    error_message=(
                        f"Model '{clean_model}' quota or rate limit is exhausted on the provider side"
                        + (f" (retry after ~{retry_after}s)" if retry_after else "")
                        + f": {stderr.strip()[:200]}"
                    ),
                    permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
                    events=parsed.events,
                    retry_after_seconds=retry_after,
                )

        # Nonzero exit code
        if proc.returncode != 0:
            return AgyDispatchResult(
                ok=False,
                status="CLI_EXECUTION_FAILED",
                requested_model=clean_model,
                observed_model=parsed.reported_model,
                conversation_id=parsed.conversation_id,
                response_text=parsed.response_text,
                input_tokens=parsed.input_tokens,
                output_tokens=parsed.output_tokens,
                thinking_tokens=parsed.thinking_tokens,
                total_tokens=parsed.total_tokens,
                execution_duration=elapsed,
                command=cmd,
                returncode=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                error_code="NONZERO_EXIT",
                error_message=f"Process exited with non-zero code {proc.returncode}: {stderr[:200]}",
                permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
                events=parsed.events,
            )

        # Missing result event or error in stream JSON
        if parsed.missing_result or parsed.status in ("FAILED", "ERROR", "INCOMPLETE"):
            return AgyDispatchResult(
                ok=False,
                status="CLI_EXECUTION_FAILED",
                requested_model=clean_model,
                observed_model=parsed.reported_model,
                conversation_id=parsed.conversation_id,
                response_text=parsed.response_text,
                input_tokens=parsed.input_tokens,
                output_tokens=parsed.output_tokens,
                thinking_tokens=parsed.thinking_tokens,
                total_tokens=parsed.total_tokens,
                execution_duration=elapsed,
                command=cmd,
                returncode=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                error_code="INCOMPLETE_STREAM",
                error_message="CLI exited 0 but final result event was missing or failed.",
                permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
                events=parsed.events,
            )

        return AgyDispatchResult(
            ok=True,
            status="SUCCESS",
            requested_model=clean_model,
            observed_model=parsed.reported_model,
            conversation_id=parsed.conversation_id,
            response_text=parsed.response_text,
            input_tokens=parsed.input_tokens,
            output_tokens=parsed.output_tokens,
            thinking_tokens=parsed.thinking_tokens,
            total_tokens=parsed.total_tokens,
            execution_duration=elapsed,
            command=cmd,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            error_code=None,
            error_message=None,
            permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
            events=parsed.events,
        )

    def start_new_conversation(
        self,
        prompt: str,
        *,
        cwd: Path | str | None = None,
        project_id: str | None = None,
        model_id: str | None = None,
        task_type: TaskType | str = TaskType.ROUTINE_VERIFICATION,
        severity: str = "MEDIUM",
        finding_category: str | None = None,
        evidence_gate_status: str = "UNCHECKED",
        execution_intent: ExecutionIntent | str = ExecutionIntent.ROUTINE_VERIFICATION,
        audit_run_id: str | None = None,
        verification_run_id: str | None = None,
        finding_fingerprint: str | None = None,
        explicit_operator_escalation: bool = False,
        operator_escalation_reason: str | None = None,
        primary_model: str | None = None,
        allow_budget_duplicate: bool = False,
        budget_tracker: Any | None = None,
        conversations_dir: Path | str | None = None,
        db_path: Path | None = None,
        timeout_seconds: int | None = None,
        isolated: bool = False,
        json_schema_path: str | Path | None = None,
    ) -> AgyDispatchResult:
        """Deterministic model routing, budget checking, dispatch, and attestation.

        ``isolated=True`` (structured delivery) denies MCP tools and shell commands for the session;
        ``json_schema_path`` constrains the final answer. Routing-table approval is unchanged.
        """
        # str() of a (str, Enum) member is "TaskType.X" on Python 3.11+; persist and key budgets by the value.
        task_name = task_type.value if isinstance(task_type, TaskType) else str(task_type)
        req = ModelRoutingRequest(
            task_type=task_type,
            severity=severity,
            finding_category=finding_category,
            evidence_gate_status=evidence_gate_status,
            execution_intent=execution_intent,
            audit_run_id=audit_run_id,
            finding_fingerprint=finding_fingerprint,
            explicit_operator_escalation=explicit_operator_escalation,
            operator_escalation_reason=operator_escalation_reason,
            primary_model=primary_model,
        )
        decision = route_model(req, db_path=db_path)
        if model_id is not None:
            # An explicit model may pick a model, but never bypass the routing gates: a blocked task stays
            # blocked (evidence gate, disabled repair worker, unavailable table) and a scarce model is only
            # allowed where the routed tier is scarce as well.
            clean_model = _normalize_dispatch_model(model_id) or model_id.strip().lower()
            decision_reason = "Explicit caller model override."
            is_argon = is_scarce_model(clean_model)
            t_risk = decision.task_risk.value
            # Validate before any budget reservation so a rejected override can neither consume
            # scarce quota nor occupy the per-finding dispatch key.
            is_blocked = not ModelId.is_approved(model_id, db_path=db_path)
            blocked_status = "INVALID_MODEL" if is_blocked else None
            blocked_reason = _unapproved_model_reason(model_id, db_path) if is_blocked else None
            if not is_blocked and decision.is_blocked:
                is_blocked = True
                blocked_status = decision.routing_status.value
                blocked_reason = decision.blocked_reason or decision.decision_reason
            elif not is_blocked:
                explicit_tier = _tier_of_model(clean_model, db_path)
                routed_tier = decision.routing_tier
                exceeds = (is_argon and not decision.is_argon) or (
                    explicit_tier is not None
                    and routed_tier is not None
                    and _TIER_RANK[explicit_tier] > _TIER_RANK[routed_tier]
                )
                if exceeds:
                    is_blocked = True
                    blocked_status = "EXPLICIT_MODEL_EXCEEDS_TIER"
                    blocked_reason = (
                        f"Explicit model {clean_model} belongs to a higher routing tier than task {task_name} "
                        f"({routed_tier.value if routed_tier else 'unknown'}); explicit models cannot escalate the tier."
                    )
        else:
            clean_model = decision.selected_model.value if decision.selected_model else "NONE"
            decision_reason = decision.decision_reason
            is_argon = decision.is_argon
            t_risk = decision.task_risk.value
            is_blocked = decision.is_blocked
            blocked_status = decision.routing_status.value
            blocked_reason = decision.blocked_reason or decision.decision_reason

        # Blocked routing decisions (e.g. BLOCKED_EVIDENCE, REPAIR_WORKER_DISABLED)
        if is_blocked:
            res = AgyDispatchResult(
                ok=False,
                status=blocked_status or "BLOCKED",
                requested_model=clean_model,
                observed_model=None,
                conversation_id=None,
                response_text="",
                input_tokens=0,
                output_tokens=0,
                thinking_tokens=0,
                total_tokens=0,
                execution_duration=0.0,
                command=[],
                returncode=None,
                stdout="",
                stderr="",
                error_code=blocked_status,
                error_message=blocked_reason,
                permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
                attestation_status="MODEL_ATTESTATION_INCOMPLETE",
            )
            if db_path is not None:
                try:
                    from db import connect, record_model_dispatch

                    with connect(db_path) as conn:
                        record_model_dispatch(
                            conn,
                            task_type=task_name,
                            task_risk=t_risk,
                            requested_model=clean_model,
                            observed_model=None,
                            model_identity_source="ROUTING_BLOCKED",
                            model_attestation_status="MODEL_ATTESTATION_INCOMPLETE",
                            audit_run_id=audit_run_id,
                            verification_run_id=verification_run_id,
                            finding_fingerprint=finding_fingerprint,
                            error_code=blocked_status,
                            error_message=blocked_reason,
                            permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
                            dispatch_status=blocked_status or "BLOCKED",
                            decision_reason=decision_reason,
                        )
                        conn.commit()
                except Exception:
                    pass
            return res

        # Budget check for Argon models
        if is_argon and budget_tracker is not None:
            if db_path is not None and getattr(budget_tracker, "db_path", None) is None:
                budget_tracker.db_path = db_path

            check = budget_tracker.check_dispatch(
                model_id=clean_model,
                audit_run_id=audit_run_id or "default",
                finding_fingerprint=finding_fingerprint,
                task_type=task_name,
                force_duplicate=allow_budget_duplicate,
            )
            if not check.allowed:
                blocked_status = (
                    "BLOCKED_BUDGET"
                    if check.status in ("REJECTED_REQUEST_LIMIT", "REJECTED_TOKEN_LIMIT", "REJECTED_CONCURRENCY")
                    else "REJECTED_DUPLICATE"
                )
                res = AgyDispatchResult(
                    ok=False,
                    status=blocked_status,
                    requested_model=clean_model,
                    observed_model=None,
                    conversation_id=None,
                    response_text="",
                    input_tokens=0,
                    output_tokens=0,
                    thinking_tokens=0,
                    total_tokens=0,
                    execution_duration=0.0,
                    command=[],
                    returncode=None,
                    stdout="",
                    stderr="",
                    error_code=check.status,
                    error_message=check.reason,
                    permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
                    attestation_status="MODEL_ATTESTATION_INCOMPLETE",
                )
                if db_path is not None:
                    try:
                        from db import connect, record_model_dispatch

                        with connect(db_path) as conn:
                            record_model_dispatch(
                                conn,
                                task_type=task_name,
                                task_risk=t_risk,
                                requested_model=clean_model,
                                observed_model=None,
                                model_identity_source="BUDGET_REJECTED",
                                model_attestation_status="MODEL_ATTESTATION_INCOMPLETE",
                                audit_run_id=audit_run_id,
                                verification_run_id=verification_run_id,
                                finding_fingerprint=finding_fingerprint,
                                error_code=check.status,
                                error_message=check.reason,
                                permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
                                dispatch_status=blocked_status,
                                decision_reason=check.reason,
                            )
                            conn.commit()
                    except Exception:
                        pass
                return res

            reservation_id = getattr(check, "reservation_id", None)
            acquired = budget_tracker.acquire_job(
                model_id=clean_model,
                audit_run_id=audit_run_id or "default",
                finding_fingerprint=finding_fingerprint,
                task_type=task_name,
            )
            if acquired is False:
                return AgyDispatchResult(
                    ok=False,
                    status="BLOCKED_BUDGET",
                    requested_model=clean_model,
                    observed_model=None,
                    conversation_id=None,
                    response_text="",
                    input_tokens=0,
                    output_tokens=0,
                    thinking_tokens=0,
                    total_tokens=0,
                    execution_duration=0.0,
                    command=[],
                    returncode=None,
                    stdout="",
                    stderr="",
                    error_code="REJECTED_CONCURRENCY",
                    error_message="Scarce-model concurrency limit reached before dispatch.",
                    permission_capability_status=PermissionCapabilityStatus.READ_ONLY_UNVERIFIED,
                    attestation_status="MODEL_ATTESTATION_INCOMPLETE",
                )
        else:
            reservation_id = None

        # Resolve task-specific timeout: primary audit 300 s, second-pass verification 900 s, others keep the
        # default adapter timeout.
        effective_timeout = timeout_seconds
        if effective_timeout is None:
            if task_name == "PRIMARY_AUDIT":
                effective_timeout = PRIMARY_AUDIT_TIMEOUT_SECONDS
            elif task_name in _VERIFICATION_TASKS:
                effective_timeout = VERIFICATION_TIMEOUT_SECONDS
            else:
                effective_timeout = self.timeout_seconds

        # Dispatch via agy.exe. The scarce-model reservation is released even if dispatch raises.
        tokens_consumed = 0
        dispatch_completed = False
        try:
            dispatch_res = self.dispatch(
                prompt=prompt,
                model_id=clean_model,
                cwd=cwd or Path.cwd(),
                mode="plan",
                timeout_seconds=effective_timeout,
                db_path=db_path,
                isolated=isolated,
                json_schema_path=json_schema_path,
            )
            tokens_consumed = dispatch_res.total_tokens
            # dispatch() reports spawn/validation failures as results instead of raising; those never reached
            # the model and must not consume the scarce quota or the per-finding dedup key either.
            # A provider quota refusal did not run the model either: no scarce-budget usage is recorded.
            never_ran = dispatch_res.status in ("CLI_UNAVAILABLE", "INVALID_MODEL", "PROVIDER_QUOTA_EXHAUSTED") or (
                dispatch_res.status == "CLI_EXECUTION_FAILED"
                and dispatch_res.returncode is None
                and not dispatch_res.conversation_id
            )
            dispatch_completed = not never_ran
        finally:
            if is_argon and budget_tracker is not None:
                budget_tracker.release_job(
                    model_id=clean_model,
                    audit_run_id=audit_run_id or "default",
                    tokens_consumed=tokens_consumed,
                    finding_fingerprint=finding_fingerprint,
                    task_type=task_name,
                    reservation_id=reservation_id,
                    completed=dispatch_completed,
                )

        # Runtime attestation
        attestation_status = "MODEL_ATTESTATION_INCOMPLETE"
        observed_model = dispatch_res.observed_model
        if dispatch_res.conversation_id:
            from model_catalog import known_model_lines

            attest_res = attest_conversation_model(
                dispatch_res.conversation_id,
                clean_model,
                conversations_dir=conversations_dir,
                known_model_lines=known_model_lines(db_path),
            )
            attestation_status = attest_res.status
            if attest_res.observed_model:
                observed_model = attest_res.observed_model

        final_res = AgyDispatchResult(
            ok=dispatch_res.ok,
            status=dispatch_res.status,
            requested_model=clean_model,
            observed_model=observed_model,
            conversation_id=dispatch_res.conversation_id,
            response_text=dispatch_res.response_text,
            input_tokens=dispatch_res.input_tokens,
            output_tokens=dispatch_res.output_tokens,
            thinking_tokens=dispatch_res.thinking_tokens,
            total_tokens=dispatch_res.total_tokens,
            execution_duration=dispatch_res.execution_duration,
            command=dispatch_res.command,
            returncode=dispatch_res.returncode,
            stdout=dispatch_res.stdout,
            stderr=dispatch_res.stderr,
            error_code=dispatch_res.error_code,
            error_message=dispatch_res.error_message,
            permission_capability_status=dispatch_res.permission_capability_status,
            events=dispatch_res.events,
            attestation_status=attestation_status,
            retry_after_seconds=dispatch_res.retry_after_seconds,
        )

        # Record in SQLite database if db_path provided
        if db_path is not None:
            try:
                from db import connect, record_budget_usage, record_model_dispatch

                with connect(db_path) as conn:
                    record_model_dispatch(
                        conn,
                        task_type=task_name,
                        task_risk=t_risk,
                        requested_model=clean_model,
                        observed_model=observed_model,
                        model_identity_source="SQLITE_METADATA" if attestation_status == "RUNTIME_ATTESTED" else "CLI_STREAM",
                        model_attestation_status=attestation_status,
                        audit_run_id=audit_run_id,
                        verification_run_id=verification_run_id,
                        finding_fingerprint=finding_fingerprint,
                        conversation_id=dispatch_res.conversation_id,
                        input_tokens=dispatch_res.input_tokens,
                        output_tokens=dispatch_res.output_tokens,
                        thinking_tokens=dispatch_res.thinking_tokens,
                        total_tokens=dispatch_res.total_tokens,
                        execution_duration=dispatch_res.execution_duration,
                        error_code=dispatch_res.error_code,
                        error_message=dispatch_res.error_message,
                        permission_capability_status=dispatch_res.permission_capability_status,
                        dispatch_status=dispatch_res.status,
                        decision_reason=decision_reason,
                    )
                    if not is_argon and dispatch_res.total_tokens > 0:
                        record_budget_usage(
                            conn,
                            model_id=clean_model,
                            task_type=task_name,
                            tokens_consumed=dispatch_res.total_tokens,
                            audit_run_id=audit_run_id,
                            finding_fingerprint=finding_fingerprint,
                            request_count=1,
                        )
                    conn.commit()
            except Exception:
                pass

        return final_res

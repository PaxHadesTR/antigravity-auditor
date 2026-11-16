from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

CONVERSATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{4,128}$")
FORBIDDEN_CONVERSATION_LITERALS = {
    "error",
    "failed",
    "failure",
    "null",
    "none",
    "undefined",
    "unknown",
    "pending",
    "true",
    "false",
}
KV_CONVERSATION_PATTERN = re.compile(
    r"(?:conversation[_-]?id|conversationId)\s*[:=]\s*[\"']?([A-Za-z0-9_.:-]{4,128})[\"']?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class AgentApiDispatchResult:
    ok: bool
    status: str  # DISPATCHED | UNAVAILABLE | FAILED | DISPATCH_UNCERTAIN
    conversation_id: str | None
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    error_code: str | None = None
    error_message: str | None = None
    model_id: str | None = None
    agent_id: str | None = None
    invocation_mechanism: str = "agentapi_sidecar"

    @property
    def dispatch_uncertain(self) -> bool:
        return self.status == "DISPATCH_UNCERTAIN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "conversation_id": self.conversation_id,
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "model_id": self.model_id,
            "agent_id": self.agent_id,
            "invocation_mechanism": self.invocation_mechanism,
        }


def is_valid_conversation_id(value: str | None) -> bool:
    if not value or not isinstance(value, str):
        return False
    cleaned = value.strip()
    if not cleaned or cleaned.lower() in FORBIDDEN_CONVERSATION_LITERALS:
        return False
    return bool(CONVERSATION_ID_PATTERN.match(cleaned))


class AgentApiAdapter:
    """Testable adapter for Antigravity Sidecar `agentapi new-conversation` dispatch."""

    def __init__(
        self,
        *,
        env: dict[str, str] | None = None,
        executable_override: str | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        timeout_seconds: int = 60,
    ) -> None:
        base_env = dict(env) if env is not None else None
        if executable_override is not None:
            base_env = dict(base_env) if base_env is not None else os.environ.copy()
            base_env["ANTIGRAVITY_AGENTAPI_EXE"] = str(executable_override)
        self._env = base_env
        self._runner = runner or subprocess.run
        self.timeout_seconds = max(1, int(timeout_seconds))

    def _effective_env(self) -> dict[str, str]:
        if self._env is not None:
            return dict(self._env)
        return os.environ.copy()

    def discover_executable(self) -> Path | None:
        """Discover the agentapi executable from ANTIGRAVITY_AGENTAPI_EXE or PATH."""
        env = self._effective_env()
        explicit = env.get("ANTIGRAVITY_AGENTAPI_EXE", "").strip()
        if explicit:
            candidate = Path(explicit).expanduser()
            if candidate.is_file():
                return candidate.resolve()
            found_explicit = shutil.which(explicit, path=env.get("PATH"))
            if found_explicit:
                return Path(found_explicit).resolve()
            return None

        found_path = shutil.which("agentapi", path=env.get("PATH"))
        if found_path:
            return Path(found_path).resolve()
        return None

    def build_command(self, prompt: str) -> list[str]:
        """Construct an argument array for `agentapi new-conversation <prompt>`.

        Never uses shell string concatenation.
        """
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Verification prompt must be a non-empty string.")
        exe = self.discover_executable()
        if exe is None:
            raise FileNotFoundError(
                "agentapi executable was not found in ANTIGRAVITY_AGENTAPI_EXE or PATH."
            )
        if exe.suffix.lower() == ".py":
            return [sys.executable, str(exe), "new-conversation", prompt]
        if exe.stem.lower() in ("antigravity", "agy"):
            return [str(exe), "agentapi", "new-conversation", prompt]
        return [str(exe), "new-conversation", prompt]

    @staticmethod
    def parse_output(stdout: str | None) -> tuple[str | None, str | None, str | None]:
        """Parse and validate conversation_id (and optional runtime-confirmed model/agent IDs)."""
        if not stdout:
            return None, None, None
        raw = stdout.strip()
        if not raw:
            return None, None, None

        # 1. Try JSON object parsing (either full output or last JSON line)
        candidates_to_parse = [raw]
        non_empty_lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if non_empty_lines and non_empty_lines[-1] != raw:
            candidates_to_parse.append(non_empty_lines[-1])

        for text_candidate in candidates_to_parse:
            if text_candidate.startswith("{") and text_candidate.endswith("}"):
                try:
                    data = json.loads(text_candidate)
                except json.JSONDecodeError:
                    data = None
                if isinstance(data, dict):
                    cid_raw = (
                        data.get("conversation_id")
                        or data.get("conversationId")
                        or data.get("id")
                    )
                    cid = str(cid_raw).strip() if cid_raw is not None else None
                    model_raw = data.get("model_id") or data.get("modelId")
                    agent_raw = data.get("agent_id") or data.get("agentId")
                    model_id = str(model_raw).strip() if model_raw else None
                    agent_id = str(agent_raw).strip() if agent_raw else None
                    if is_valid_conversation_id(cid):
                        return cid, model_id, agent_id
                    return None, None, None

        # 2. Try key=value or key: value pattern
        match = KV_CONVERSATION_PATTERN.search(raw)
        if match:
            cid = match.group(1).strip()
            if is_valid_conversation_id(cid):
                return cid, None, None

        # 3. Try single-line token matching conversation ID pattern
        if len(non_empty_lines) == 1:
            token = non_empty_lines[0].strip()
            if is_valid_conversation_id(token):
                return token, None, None

        return None, None, None

    def start_new_conversation(
        self,
        prompt: str,
        *,
        cwd: Path | None = None,
        project_id: str | None = None,
        timeout_seconds: int | None = None,
        **_kwargs: Any,
    ) -> AgentApiDispatchResult:
        """Start a fresh Antigravity conversation inside the configured Project ID.

        There is deliberately no default Project ID: a missing or PENDING id is refused
        (MISSING_PROJECT_ID) instead of silently using some other project.
        """
        clean_project_id = (project_id or "").strip()
        if not clean_project_id or clean_project_id.upper() in ("PENDING", "UNKNOWN"):
            return AgentApiDispatchResult(
                ok=False,
                status="FAILED",
                conversation_id=None,
                command=[],
                returncode=None,
                stdout="",
                stderr="",
                error_code="MISSING_PROJECT_ID",
                error_message="Project ID is missing or PENDING; refusing to dispatch conversation.",
            )

        try:
            cmd = self.build_command(prompt)
        except FileNotFoundError as exc:
            return AgentApiDispatchResult(
                ok=False,
                status="UNAVAILABLE",
                conversation_id=None,
                command=[],
                returncode=None,
                stdout="",
                stderr="",
                error_code="AGENTAPI_UNAVAILABLE",
                error_message=str(exc),
            )
        except ValueError as exc:
            return AgentApiDispatchResult(
                ok=False,
                status="FAILED",
                conversation_id=None,
                command=[],
                returncode=None,
                stdout="",
                stderr="",
                error_code="INVALID_PROMPT",
                error_message=str(exc),
            )

        run_env = self._effective_env()
        run_env["ANTIGRAVITY_PROJECT_ID"] = clean_project_id
        effective_timeout = max(1, int(timeout_seconds or self.timeout_seconds))

        try:
            proc = self._runner(
                cmd,
                cwd=str(cwd or Path.cwd()),
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                env=run_env,
            )
        except subprocess.TimeoutExpired as exc:
            out_str = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err_str = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return AgentApiDispatchResult(
                ok=False,
                status="DISPATCH_UNCERTAIN",
                conversation_id=None,
                command=cmd,
                returncode=None,
                stdout=out_str,
                stderr=err_str,
                error_code="AGENTAPI_TIMEOUT",
                error_message=(
                    f"agentapi new-conversation timed out after {effective_timeout}s; "
                    "conversation creation outcome is uncertain."
                ),
            )
        except FileNotFoundError as exc:
            return AgentApiDispatchResult(
                ok=False,
                status="UNAVAILABLE",
                conversation_id=None,
                command=cmd,
                returncode=None,
                stdout="",
                stderr="",
                error_code="AGENTAPI_UNAVAILABLE",
                error_message=str(exc),
            )
        except OSError as exc:
            return AgentApiDispatchResult(
                ok=False,
                status="FAILED",
                conversation_id=None,
                command=cmd,
                returncode=None,
                stdout="",
                stderr="",
                error_code="AGENTAPI_PROCESS_ERROR",
                error_message=str(exc),
            )

        stdout_text = (proc.stdout or "").strip()
        stderr_text = (proc.stderr or "").strip()

        if proc.returncode != 0:
            return AgentApiDispatchResult(
                ok=False,
                status="FAILED",
                conversation_id=None,
                command=cmd,
                returncode=proc.returncode,
                stdout=stdout_text,
                stderr=stderr_text,
                error_code="AGENTAPI_NONZERO_EXIT",
                error_message=stderr_text or stdout_text or f"agentapi exited with code {proc.returncode}",
            )

        cid, model_id, agent_id = self.parse_output(stdout_text)
        if not cid:
            return AgentApiDispatchResult(
                ok=False,
                status="DISPATCH_UNCERTAIN",
                conversation_id=None,
                command=cmd,
                returncode=proc.returncode,
                stdout=stdout_text,
                stderr=stderr_text,
                error_code="AGENTAPI_INVALID_OUTPUT",
                error_message=(
                    "agentapi exited with code 0 but did not return a valid conversation ID; "
                    "marking dispatch uncertain to prevent duplicate conversations."
                ),
            )

        return AgentApiDispatchResult(
            ok=True,
            status="DISPATCHED",
            conversation_id=cid,
            command=cmd,
            returncode=proc.returncode,
            stdout=stdout_text,
            stderr=stderr_text,
            error_code=None,
            error_message=None,
            model_id=model_id,
            agent_id=agent_id,
            invocation_mechanism="agentapi_sidecar",
        )

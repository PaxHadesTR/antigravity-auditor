"""Bounded, strictly allowlisted read-only CLI executable resolver and runner."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from runtime_discovery.redaction import redact_text, sanitize_exception
from runtime_discovery.windows_detection import is_reparse_point

DEFAULT_CLI_TIMEOUT_SECONDS = 8.0

ALLOWED_CLI_COMMANDS: dict[str, frozenset[tuple[str, ...]]] = {
    "antigravity": frozenset(
        {
            ("--version",),
            ("--help",),
            ("models",),
            ("mcp", "--help"),
            ("mcp", "list", "--help"),
            ("mcp", "add", "--help"),
        }
    ),
    "claude_code": frozenset(
        {
            ("--version",),
            ("--help",),
            ("mcp", "--help"),
            ("mcp", "list", "--help"),
        }
    ),
    "codex": frozenset(
        {
            ("--version",),
            ("--help",),
            ("debug", "models", "--help"),
            ("debug", "models", "--bundled"),
            ("mcp", "--help"),
            ("mcp", "list", "--help"),
            ("mcp", "add", "--help"),
            ("mcp", "list", "--json"),
        }
    ),
}

ALLOWED_CLI_BASENAMES: dict[str, frozenset[str]] = {
    "antigravity": frozenset({"agy", "agy.exe"}),
    "claude_code": frozenset({"claude", "claude.exe", "claude.cmd"}),
    "codex": frozenset({"codex", "codex.exe", "codex.cmd"}),
}


@dataclass(frozen=True)
class CliCommandResult:
    """Sanitized result of an allowlisted read-only CLI invocation."""

    ok: bool
    executable_path: str
    executable_basename: str
    args: tuple[str, ...]
    exit_code: int | None
    stdout: str
    stderr: str
    error_code: str | None = None
    error_message: str | None = None


class CliRunner(Protocol):
    """Injectable allowlisted CLI runner protocol."""

    def resolve_executable(self, app_id: str, candidates: tuple[Path, ...] = ()) -> Path | None: ...
    def run(
        self,
        app_id: str,
        executable: Path,
        args: tuple[str, ...],
        *,
        timeout_seconds: float = DEFAULT_CLI_TIMEOUT_SECONDS,
    ) -> CliCommandResult: ...


def validate_cli_invocation(app_id: str, executable: Path, args: tuple[str, ...]) -> None:
    """Enforce strict executable basename and read-only subcommand allowlists."""
    allowed_names = ALLOWED_CLI_BASENAMES.get(app_id)
    if allowed_names is None:
        raise ValueError(f"Unsupported CLI application id: {app_id}")
    basename = executable.name.lower()
    if basename not in allowed_names:
        raise ValueError(
            f"Disallowed CLI executable '{executable.name}' for '{app_id}'."
        )
    allowed_args = ALLOWED_CLI_COMMANDS.get(app_id, frozenset())
    if tuple(args) not in allowed_args:
        raise ValueError(
            f"Disallowed CLI arguments {args!r} for '{app_id}'. Read-only allowlist enforced."
        )
    if is_reparse_point(executable):
        raise ValueError(f"Refusing to execute reparse point CLI path: {executable}")


class DefaultCliRunner:
    """Subprocess-based allowlisted CLI runner with bounded timeout and shell=False."""

    def resolve_executable(self, app_id: str, candidates: tuple[Path, ...] = ()) -> Path | None:
        allowed_names = ALLOWED_CLI_BASENAMES.get(app_id, frozenset())
        # 1. Check PATH via shutil.which for allowlisted names
        for name in sorted(allowed_names):
            found = shutil.which(name)
            if found:
                cand = Path(found)
                if cand.is_file() and not is_reparse_point(cand):
                    return cand

        # 2. Check explicit bounded candidate paths
        for cand in candidates:
            try:
                if (
                    cand.name.lower() in allowed_names
                    and cand.is_file()
                    and not is_reparse_point(cand)
                ):
                    return cand
            except OSError:
                continue
        return None

    def run(
        self,
        app_id: str,
        executable: Path,
        args: tuple[str, ...],
        *,
        timeout_seconds: float = DEFAULT_CLI_TIMEOUT_SECONDS,
    ) -> CliCommandResult:
        validate_cli_invocation(app_id, executable, args)
        bounded_timeout = max(0.5, min(float(timeout_seconds), 20.0))
        try:
            proc = subprocess.run(
                [str(executable), *args],
                capture_output=True,
                text=True,
                timeout=bounded_timeout,
                shell=False,
                encoding="utf-8",
                errors="replace",
                env=os.environ.copy(),
            )
            return CliCommandResult(
                ok=(proc.returncode == 0),
                executable_path=str(executable),
                executable_basename=executable.name,
                args=tuple(args),
                exit_code=proc.returncode,
                stdout=proc.stdout or "",
                stderr=redact_text(proc.stderr or ""),
                error_code=None if proc.returncode == 0 else "NON_ZERO_EXIT",
                error_message=None if proc.returncode == 0 else f"Exit code {proc.returncode}",
            )
        except subprocess.TimeoutExpired:
            return CliCommandResult(
                ok=False,
                executable_path=str(executable),
                executable_basename=executable.name,
                args=tuple(args),
                exit_code=None,
                stdout="",
                stderr="",
                error_code="CLI_TIMEOUT",
                error_message=f"CLI command timed out after {bounded_timeout:.1f}s",
            )
        except OSError as exc:
            return CliCommandResult(
                ok=False,
                executable_path=str(executable),
                executable_basename=executable.name,
                args=tuple(args),
                exit_code=None,
                stdout="",
                stderr="",
                error_code="CLI_OS_ERROR",
                error_message=sanitize_exception(exc),
            )

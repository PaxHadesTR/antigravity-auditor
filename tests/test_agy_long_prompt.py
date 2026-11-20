"""A prompt too long for the Windows command line (32,767 characters, [WinError 206]) goes to agy's stdin as one
stream-json user message; short prompts keep the `-p <prompt>` argument."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from agy_adapter import MAX_COMMAND_LINE_CHARS, AntigravityCliAdapter, stdin_prompt_message

MODEL = "gemini-4-hydrogen-high"
# A verification prompt with many candidates: JSON quotes (escaped on the command line) and non-ASCII text.
LONG_PROMPT = "CANDIDATE CLAIMS:\n" + json.dumps(
    [{"title": f"Bulgu {i}: \"yarış\" koşulu ÇĞŞ", "evidence": "x" * 1800} for i in range(40)], ensure_ascii=False
)


def _adapter(tmp_path: Path, runner: Any = None) -> AntigravityCliAdapter:
    exe = tmp_path / "agy.exe"
    exe.write_text("fake")
    return AntigravityCliAdapter(executable_override=str(exe), runner=runner)


def test_short_prompt_stays_on_the_command_line(tmp_path: Path) -> None:
    cmd = _adapter(tmp_path).build_command(prompt="Audit findings", model_id=MODEL)
    assert cmd[1:3] == ["-p", "Audit findings"]
    assert "--input-format" not in cmd
    assert not AntigravityCliAdapter.prompt_on_stdin(cmd)


def test_long_prompt_moves_to_stdin_and_keeps_every_flag(tmp_path: Path) -> None:
    schema = tmp_path / "schema.json"
    cmd = _adapter(tmp_path).build_command(
        prompt=LONG_PROMPT, model_id=MODEL, json_schema_path=schema, isolated=True,
    )
    assert len(LONG_PROMPT) > 40000
    assert cmd[1:4] == ["-p=", "--input-format", "stream-json"]
    assert LONG_PROMPT not in cmd
    assert len(subprocess.list2cmdline(cmd)) < MAX_COMMAND_LINE_CHARS
    for flag, value in (("--model", MODEL), ("--mode", "plan"), ("--output-format", "stream-json"),
                        ("--json-schema", str(schema))):
        assert cmd[cmd.index(flag) + 1] == value
    assert "--settings" in cmd
    assert AntigravityCliAdapter.prompt_on_stdin(cmd)


def test_dispatch_writes_the_long_prompt_to_stdin_as_utf8_stream_json(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"], seen["kwargs"] = cmd, kwargs
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

    res = _adapter(tmp_path, runner).dispatch(prompt=LONG_PROMPT, model_id=MODEL, cwd=tmp_path)
    assert res.error_code != "SUBPROCESS_ERROR"
    kwargs = seen["kwargs"]
    assert kwargs["encoding"] == "utf-8"
    line = kwargs["input"]
    assert line.endswith("\n") and line.count("\n") == 1  # one NDJSON message
    assert json.loads(line) == {"event": "user", "message": {"role": "user", "content": LONG_PROMPT}}
    assert line == stdin_prompt_message(LONG_PROMPT)
    assert "shell" not in kwargs


def test_dispatch_of_a_short_prompt_sends_nothing_on_stdin(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

    _adapter(tmp_path, runner).dispatch(prompt="Audit", model_id=MODEL, cwd=tmp_path)
    assert "input" not in seen["kwargs"]

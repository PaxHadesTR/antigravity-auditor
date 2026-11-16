"""Phase 2 of dynamic model routing: deterministic model probes (no real model calls here)."""

from __future__ import annotations

import json
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import model_catalog as cat  # noqa: E402
import model_probes as mp  # noqa: E402
from agy_adapter import AgyDispatchResult, AntigravityCliAdapter  # noqa: E402
from db import initialize  # noqa: E402
from test_model_registry import _blob  # noqa: E402

LISTING = "\n".join([
    "gemini-4-argon-medium\tGemini 4 Argon (Medium)",
    "gemini-4-argon-high\tGemini 4 Argon (High)",
    "gemini-4-hydrogen-high\tGemini 4 Hydrogen (High)",
    "gemini-4-hydrogen-medium\tGemini 4 Hydrogen (Medium)",
    "gemini-4-hydrogen-xhigh\tGemini 4 Hydrogen (XHigh)",
    "gemini-3.8-flash-high\tGemini 3.8 Flash (High)",
    "claude-opus-5-5-high\tClaude Opus 5.5 (High)",
]) + "\n"


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    path = tmp_path / "home" / "database" / "auditor.db"
    initialize(path)
    cat.sync_catalog(path, listing=LISTING)
    return path


def _perfect_answer() -> dict[str, Any]:
    files, truth = mp.load_suite()
    return {"findings": [
        {"file_path": d["file_path"], "line_start": d["line"], "line_end": d["line"], "symbol": d["symbol"],
         "title": d["title"], "severity": "HIGH", "evidence_excerpt": files[d["file_path"]][d["line"] - 1].strip()}
        for d in truth["defects"]
    ]}


def _result(text: str, *, ok: bool = True, conversation_id: str | None = None, status: str = "SUCCESS") -> AgyDispatchResult:
    return AgyDispatchResult(
        ok=ok, status=status, requested_model="m", observed_model=None, conversation_id=conversation_id,
        response_text=text, input_tokens=100, output_tokens=50, thinking_tokens=0, total_tokens=150,
        execution_duration=1.0, command=[], returncode=0 if ok else 1, stdout="", stderr="",
    )


class FakeAdapter:
    def __init__(self, text: str, conversation_id: str | None, ok: bool = True) -> None:
        self.text, self.conversation_id, self.ok = text, conversation_id, ok
        self.calls: list[dict[str, Any]] = []

    def dispatch(self, **kw: Any) -> AgyDispatchResult:
        schema = Path(kw["json_schema_path"])
        assert schema.is_file() and json.loads(schema.read_text(encoding="utf-8")) == mp.FINDINGS_SCHEMA
        self.calls.append(kw)
        return _result(self.text, ok=self.ok, conversation_id=self.conversation_id,
                       status="SUCCESS" if self.ok else "CLI_TIMEOUT")


def _conversation(directory: Path, backend: str, display: str) -> str:
    conv = str(uuid.uuid4())
    conn = sqlite3.connect(directory / f"{conv}.db")
    conn.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB, size INTEGER)")
    blob = _blob(conv, backend, display)
    conn.execute("INSERT INTO gen_metadata VALUES (0, ?, ?)", (blob, len(blob)))
    conn.commit()
    conn.close()
    return conv


# --- fixture integrity ------------------------------------------------------------------------------

def test_ground_truth_matches_fixture_and_is_hidden_from_the_model() -> None:
    files, truth = mp.load_suite()
    assert {n: len(v) for n, v in files.items()} == truth["files"]
    for d in truth["defects"]:
        assert d["anchor"] in files[d["file_path"]][d["line"] - 1], d["id"]
    assert not (mp.FIXTURE_ROOT / mp.SUITE_VERSION / f"{mp.SUITE_VERSION}.truth.json").exists()
    prompt = mp.build_probe_prompt(files)
    lowered = prompt.lower()
    for leak in ("planted", "intentional", "ground truth", "truth.json", "probe"):
        assert leak not in lowered, leak
    assert "=== FILE: orders.py ===" in prompt and "11|     end = start + page_size - 1" in prompt
    assert len(mp.suite_sha256()) == 64


# --- scoring ----------------------------------------------------------------------------------------

def test_perfect_answer_scores_one() -> None:
    files, truth = mp.load_suite()
    m = mp.score_findings(_perfect_answer(), files, truth)
    assert m["recall"] == 1.0 and m["precision"] == 1.0 and m["fabricated_count"] == 0 and m["score"] == 1.0
    assert mp.classify(m, "RUNTIME_ATTESTED") == "PASSED"


@pytest.mark.parametrize("mutate", [
    lambda f: f.update(file_path="billing.py"),                       # file does not exist
    lambda f: f.update(line_start=500, line_end=501),                 # out of range
    lambda f: f.update(evidence_excerpt="os.system(user_input)"),     # quote not in source
    lambda f: f.update(evidence_excerpt=f["evidence_excerpt"] + " and more invented code"),  # padded quote
])
def test_fabricated_references_are_detected(mutate: Any) -> None:
    files, truth = mp.load_suite()
    answer = _perfect_answer()
    mutate(answer["findings"][0])
    m = mp.score_findings(answer, files, truth)
    assert m["fabricated_count"] == 1 and "D1" not in m["matched_defects"]
    assert mp.classify(m, "RUNTIME_ATTESTED") == "DEGRADED"


def test_decoy_reports_are_false_positives() -> None:
    files, truth = mp.load_suite()
    answer = _perfect_answer()
    line = next(i for i, l in enumerate(files["orders.py"], 1) if "subprocess.run(" in l)
    answer["findings"].append({"file_path": "orders.py", "line_start": line, "line_end": line, "symbol": "export_report",
                               "title": "Command injection", "evidence_excerpt": files["orders.py"][line - 1].strip()})
    m = mp.score_findings(answer, files, truth)
    assert m["false_positive_count"] == 1 and m["fabricated_count"] == 0 and m["precision"] < 1.0


@pytest.mark.parametrize("payload", [None, {}, {"findings": "x"}, {"findings": [{"file_path": "a"}]}])
def test_schema_violations_score_zero(payload: Any) -> None:
    files, truth = mp.load_suite()
    m = mp.score_findings(payload, files, truth)
    assert m["schema_valid"] is False and m["score"] == 0.0
    assert mp.classify(m, "RUNTIME_ATTESTED") == "FAILED"


def test_attestation_failure_overrides_quality() -> None:
    files, truth = mp.load_suite()
    m = mp.score_findings(_perfect_answer(), files, truth)
    assert mp.classify(m, "MODEL_ATTESTATION_MISMATCH") == "ATTESTATION_FAILED"


def test_extract_json_handles_fences_and_prose() -> None:
    assert mp.extract_json_object('```json\n{"findings": []}\n```') == {"findings": []}
    assert mp.extract_json_object('Here you go: {"findings": []} thanks') == {"findings": []}
    assert mp.extract_json_object("no json") is None


# --- execution path ---------------------------------------------------------------------------------

def test_run_probe_end_to_end_with_attestation(db: Path, tmp_path: Path) -> None:
    conv_dir = tmp_path / "conversations"
    conv_dir.mkdir()
    conv = _conversation(conv_dir, "gemini-4-hydrogen", "Gemini 4 Hydrogen (XHigh)")
    adapter = FakeAdapter(json.dumps(_perfect_answer()), conv)
    res = mp.run_probe(db, "gemini-4-hydrogen-xhigh", adapter=adapter, conversations_dir=conv_dir)
    assert res["status"] == "PASSED" and res["attestation_status"] == "RUNTIME_ATTESTED"
    call = adapter.calls[0]
    assert call["probe"] is True and call["mode"] == "plan" and call["model_id"] == "gemini-4-hydrogen-xhigh"
    assert not Path(call["cwd"]).exists()  # temporary directory cleaned up
    summary = mp.probe_summary(db, "gemini-4-hydrogen-xhigh")
    assert summary["status"] == "PASSED" and summary["suite_sha256"] == mp.suite_sha256()


def test_run_probe_records_wrong_model_as_attestation_failure(db: Path, tmp_path: Path) -> None:
    conv_dir = tmp_path / "conversations"
    conv_dir.mkdir()
    conv = _conversation(conv_dir, "gemini-4-hydrogen", "Gemini 4 Hydrogen (Medium)")
    res = mp.run_probe(db, "gemini-4-hydrogen-xhigh", adapter=FakeAdapter(json.dumps(_perfect_answer()), conv),
                       conversations_dir=conv_dir)
    assert res["status"] == "ATTESTATION_FAILED"


def test_run_probe_records_dispatch_errors(db: Path) -> None:
    res = mp.run_probe(db, "gemini-4-hydrogen-high", adapter=FakeAdapter("", None, ok=False))
    assert res["status"] == "ERROR" and "CLI_TIMEOUT" in res["error"]


def test_run_probe_refuses_policy_denied_models(db: Path) -> None:
    adapter = FakeAdapter("{}", None)
    for model in ("gemini-3.8-flash-high", "claude-opus-5-5-high", "gemini-pro-orchestrator-g1-pro"):
        with pytest.raises(ValueError):
            mp.run_probe(db, model, adapter=adapter)
    assert adapter.calls == []


def test_candidate_selection_reasons(db: Path, tmp_path: Path) -> None:
    sel = mp.probe_candidates(db, models=["gemini-4-hydrogen-high", "gemini-4-argon-high", "gemini-3.8-flash-high", "gemini-9-nope-high"])
    reasons = {s["model"]: s["reason"] for s in sel["skipped"]}
    assert sel["candidates"] == ["gemini-4-hydrogen-high"]
    assert reasons == {"gemini-4-argon-high": "SCARCE_REQUIRES_OPT_IN", "gemini-3.8-flash-high": "POLICY_DENIED",
                       "gemini-9-nope-high": "NOT_IN_CATALOGUE"}
    assert "gemini-4-argon-high" in mp.probe_candidates(db, include_scarce=True)["candidates"]
    mp.run_probe(db, "gemini-4-hydrogen-high", adapter=FakeAdapter("", None, ok=False))
    again = {s["model"]: s["reason"] for s in mp.probe_candidates(db)["skipped"]}
    assert again["gemini-4-hydrogen-high"] == "ALREADY_PROBED"


def test_probe_models_respects_max(db: Path) -> None:
    out = mp.probe_models(db, max_probes=1, adapter=FakeAdapter("", None, ok=False))
    assert len(out["results"]) == 1
    assert any(s["reason"] == "MAX_PROBES_REACHED" for s in out["skipped"])


def test_overview_includes_probe_summary(db: Path) -> None:
    mp.run_probe(db, "gemini-4-hydrogen-high", adapter=FakeAdapter("", None, ok=False))
    models = {m["slug"]: m for m in cat.catalog_overview(db)["catalog"]["models"]}
    assert models["gemini-4-hydrogen-high"]["probe"]["status"] == "ERROR"
    assert models["gemini-3.8-flash-high"]["probe"] is None


# --- adapter probe gate -----------------------------------------------------------------------------

def test_probe_gate_is_hard_policy_and_plan_only(tmp_path: Path) -> None:
    exe = tmp_path / "agy.exe"
    exe.write_bytes(b"")
    adapter = AntigravityCliAdapter(executable_override=str(exe))
    schema = tmp_path / "s.json"
    cmd = adapter.build_command(prompt="p", model_id="gemini-4-hydrogen-xhigh", probe=True, json_schema_path=schema)
    assert cmd[cmd.index("--json-schema") + 1] == str(schema) and cmd[cmd.index("--mode") + 1] == "plan"
    with pytest.raises(ValueError, match="routing table"):
        adapter.build_command(prompt="p", model_id="gemini-4-hydrogen-xhigh")  # not a probe -> table applies
    for model in ("gemini-3.8-flash-high", "claude-opus-5-5-high"):
        with pytest.raises(ValueError, match="may not be probed"):
            adapter.build_command(prompt="p", model_id=model, probe=True)
    with pytest.raises(ValueError, match="plan"):
        adapter.build_command(prompt="p", model_id="gemini-4-hydrogen-xhigh", mode="accept-edits", probe=True)
    res = adapter.dispatch(prompt="p", model_id="claude-opus-5-5-high", cwd=tmp_path, probe=True)
    assert res.status == "INVALID_MODEL"
    res = adapter.dispatch(prompt="p", model_id="gemini-4-hydrogen-xhigh", cwd=tmp_path, mode="auto", probe=True)
    assert res.status == "INVALID_MODEL"


def test_probe_sessions_deny_mcp_and_commands(tmp_path: Path) -> None:
    from agy_adapter import ISOLATED_SESSION_SETTINGS

    exe = tmp_path / "agy.exe"
    exe.write_bytes(b"")
    adapter = AntigravityCliAdapter(executable_override=str(exe))
    cmd = adapter.build_command(prompt="p", model_id="gemini-4-hydrogen-high", probe=True)
    settings = json.loads(cmd[cmd.index("--settings") + 1])
    assert settings == json.loads(ISOLATED_SESSION_SETTINGS)
    assert {"mcp(*)", "command(*)"} <= set(settings["permissions"]["deny"])
    # Regular (routing-table) dispatches keep their existing behaviour.
    assert "--settings" not in adapter.build_command(prompt="p", model_id="gemini-4-hydrogen-high")


# --- regressions from the independent Argon review of Phase 2 ----------------------------------

def _function_lines(files: dict[str, list[str]], name: str) -> list[tuple[str, int, str]]:
    out = []
    for i, line in enumerate(files[name], 1):
        if line.startswith("def "):
            out.append((name, i, line.split("(")[0][4:]))
    return out


def test_symbol_only_answers_with_trivial_quotes_do_not_score() -> None:
    files, truth = mp.load_suite()
    answer = {"findings": [
        {"file_path": d["file_path"], "line_start": 1, "line_end": 1, "symbol": d["symbol"], "title": d["title"],
         "evidence_excerpt": files[d["file_path"]][0].strip()}
        for d in truth["defects"]
    ]}
    m = mp.score_findings(answer, files, truth)
    assert m["recall"] == 0.0 and mp.classify(m, "RUNTIME_ATTESTED") == "FAILED"


def test_whole_file_ranges_are_fabricated() -> None:
    files, truth = mp.load_suite()
    d = truth["defects"][0]
    answer = {"findings": [{"file_path": d["file_path"], "line_start": 1, "line_end": len(files[d["file_path"]]),
                            "symbol": d["symbol"], "title": "x", "evidence_excerpt": files[d["file_path"]][d["line"] - 1]}]}
    assert mp.score_findings(answer, files, truth)["fabricated_count"] == 1


def test_tiny_fragment_quotes_are_fabricated_but_short_whole_lines_are_not() -> None:
    files, truth = mp.load_suite()
    d7 = next(d for d in truth["defects"] if d["id"] == "D7")
    base = {"file_path": d7["file_path"], "line_start": d7["line"], "line_end": d7["line"], "symbol": d7["symbol"], "title": "x"}
    assert not mp.is_fabricated({**base, "evidence_excerpt": "return True"}, files)
    assert mp.is_fabricated({**base, "evidence_excerpt": "True"}, files)
    assert mp.is_fabricated({**base, "evidence_excerpt": "="}, files)


def test_duplicates_do_not_inflate_precision() -> None:
    files, truth = mp.load_suite()
    one = _perfect_answer()["findings"][0]
    m = mp.score_findings({"findings": [one] * 10}, files, truth)
    assert m["duplicate_count"] == 9 and m["precision"] == 0.1 and mp.classify(m, "RUNTIME_ATTESTED") == "FAILED"


def test_reporting_every_function_does_not_pass() -> None:
    files, truth = mp.load_suite()
    findings = []
    for name in ("inventory.py", "orders.py"):
        for fname, line, sym in _function_lines(files, name):
            defect = next((d for d in truth["defects"] if d["symbol"] == sym), None)
            ln = defect["line"] if defect else line
            findings.append({"file_path": fname, "line_start": ln, "line_end": ln, "symbol": sym, "title": "issue",
                             "evidence_excerpt": files[fname][ln - 1].strip()})
    m = mp.score_findings({"findings": findings}, files, truth)
    assert m["recall"] == 1.0 and m["precision"] < mp.PASS_PRECISION
    assert mp.classify(m, "RUNTIME_ATTESTED") != "PASSED"


@pytest.mark.parametrize("path", ["../../inventory.py", "/inventory.py", r"\inventory.py", "C:/x/inventory.py", "sub/../inventory.py"])
def test_path_tricks_are_fabricated(path: str) -> None:
    files, _ = mp.load_suite()
    finding = {**_perfect_answer()["findings"][0], "file_path": path}
    assert mp.is_fabricated(finding, files)
    assert not mp.is_fabricated({**finding, "file_path": "./inventory.py"}, files)


def test_backend_prefix_is_not_stripped_before_policy(db: Path) -> None:
    adapter = FakeAdapter("{}", None)
    with pytest.raises(ValueError, match="may not be probed"):
        mp.run_probe(db, "vibe:gemini-4-hydrogen-high", adapter=adapter)
    sel = mp.probe_candidates(db, models=["vibe:gemini-4-hydrogen-high"])
    assert sel["candidates"] == [] and sel["skipped"][0]["reason"] == "POLICY_DENIED"
    assert adapter.calls == []


def test_bool_line_numbers_and_missing_titles_are_schema_violations() -> None:
    files, truth = mp.load_suite()
    good = _perfect_answer()["findings"][0]
    for bad in ({**good, "line_start": True, "line_end": True}, {**good, "title": ""}, {**good, "severity": "BAD"}):
        assert mp.score_findings({"findings": [bad]}, files, truth)["schema_valid"] is False


class SequenceAdapter(FakeAdapter):
    def __init__(self, texts: list[str], conversation_id: str | None) -> None:
        super().__init__(texts[0], conversation_id)
        self.texts = list(texts)

    def dispatch(self, **kw: Any) -> AgyDispatchResult:
        self.text = self.texts[min(len(self.calls), len(self.texts) - 1)]
        return super().dispatch(**kw)


def test_dispatch_errors_are_retried_once(db: Path) -> None:
    adapter = FakeAdapter("", None, ok=False)
    res = mp.run_probe(db, "gemini-4-hydrogen-high", adapter=adapter)
    assert res["status"] == "ERROR" and len(adapter.calls) == 2 and len(res["metrics"]["attempts"]) == 2


def test_unparsable_answer_is_retried_and_can_pass(db: Path, tmp_path: Path) -> None:
    conv_dir = tmp_path / "conversations"
    conv_dir.mkdir()
    conv = _conversation(conv_dir, "gemini-4-hydrogen", "Gemini 4 Hydrogen (XHigh)")
    adapter = SequenceAdapter(["I created implementation_plan.md", json.dumps(_perfect_answer())], conv)
    res = mp.run_probe(db, "gemini-4-hydrogen-xhigh", adapter=adapter, conversations_dir=conv_dir)
    assert res["status"] == "PASSED" and [a["schema_valid"] for a in res["metrics"]["attempts"]] == [False, True]


def test_quality_failures_are_not_retried(db: Path, tmp_path: Path) -> None:
    conv_dir = tmp_path / "conversations"
    conv_dir.mkdir()
    conv = _conversation(conv_dir, "gemini-4-hydrogen", "Gemini 4 Hydrogen (XHigh)")
    answer = _perfect_answer()
    for f in answer["findings"]:
        f["evidence_excerpt"] = "invented code that is not in the file"
    adapter = SequenceAdapter([json.dumps(answer), json.dumps(_perfect_answer())], conv)
    res = mp.run_probe(db, "gemini-4-hydrogen-xhigh", adapter=adapter, conversations_dir=conv_dir)
    assert res["status"] == "FAILED" and len(adapter.calls) == 1


@pytest.mark.parametrize("text", [
    '{"findings": []}{"findings": []}',
    '{"findings": []}\nI found these issues above.',
    'Sure:\n```json\n{"findings": []}\n```\nDone.',
    '{"note": "x"} {"findings": []}',
])
def test_extract_first_object_tolerates_trailing_content(text: str) -> None:
    obj = mp.extract_json_object(text)
    assert isinstance(obj, dict)


def test_extract_returns_none_without_an_object() -> None:
    assert mp.extract_json_object("[1, 2] no object") is None
    assert mp.extract_json_object('{"broken": ') is None

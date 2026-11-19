"""Multi-pass primary audit (lenses) and the Windows weekly scheduled task. No real agy / schtasks is run."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cli  # noqa: E402
import primary_lenses  # noqa: E402
import weekly_scheduler as ws  # noqa: E402
from db import connect  # noqa: E402
from test_model_router_phase2 import _seed_db, make_dispatch_result  # noqa: E402
from test_structured_delivery import FINDING  # noqa: E402


def _cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path, _ = _seed_db(tmp_path, run_id="RUN-OLD", status="COMPLETED")
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "APP_HOME", tmp_path)
    monkeypatch.setattr(cli, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(cli, "SIDECAR_ROOT", tmp_path / "sidecars")
    monkeypatch.setattr(cli, "JSONL_PATH", tmp_path / "logs" / "events.jsonl")
    monkeypatch.setenv("ANTIGRAVITY_AUDITOR_PRIMARY_PASSES", "3")
    return db_path


def _result(findings: list[dict[str, Any]], conv: str) -> Any:
    return make_dispatch_result(conversation_id=conv, response_text=json.dumps({"findings": findings}))


def _events(db_path: Path, kind: str) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        return [json.loads(r[0] or "{}") for r in conn.execute(
            "SELECT details FROM audit_events WHERE event_type=? ORDER BY event_id", (kind,))]


def test_three_lenses_run_and_merge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = _cli_env(tmp_path, monkeypatch)
    other = {**FINDING, "finding_id": "F-SD-1", "fingerprint": "fp-other", "title": "Charge has no audit log",
             "category": "RESILIENCE", "line_start": 2, "line_end": 3}
    prompts: list[str] = []

    def fake(prompt: str, **kw: Any) -> Any:
        prompts.append(prompt)
        assert kw["timeout_seconds"] == primary_lenses.PRIMARY_LENS_TIMEOUT_SECONDS
        if "PASS 1/3" in prompt:
            return _result([FINDING], "conv-1")
        if "PASS 2/3" in prompt:
            return _result([FINDING, other], "conv-2")  # FINDING again: merged; `other` collides by id
        return make_dispatch_result(ok=False, status="TIMEOUT", error="timed out")

    with patch("cli.AntigravityCliAdapter") as adapter:
        adapter.return_value.start_new_conversation.side_effect = fake
        out = cli.dispatch("p2")
    assert len(prompts) == 3 and all("MULTI-PASS AUDIT" in p for p in prompts)
    assert out["candidate_count"] == 2
    assert [e["lens"] for e in _events(db_path, "PRIMARY_PASS_FINISHED")] == ["security-data", "reliability"]
    failed = _events(db_path, "PRIMARY_PASS_FAILED")
    assert failed and failed[0]["errors"][0].startswith("logic-contracts:")
    with connect(db_path) as conn:
        ids = sorted(r[0] for r in conn.execute(
            "SELECT candidate_finding_id FROM candidate_findings WHERE run_id=?", (out["run_id"],)))
    assert ids == ["F-SD-1", "reliability-F-SD-1"]


def test_all_lenses_on_quota_park_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _cli_env(tmp_path, monkeypatch)
    quota = make_dispatch_result(ok=False, status="PROVIDER_QUOTA_EXHAUSTED", error="quota")
    with patch("cli.AntigravityCliAdapter") as adapter:
        adapter.return_value.start_new_conversation.return_value = quota
        with pytest.raises(cli.ProviderQuotaExhausted):
            cli.dispatch("p2")


def test_all_lenses_failing_fails_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _cli_env(tmp_path, monkeypatch)
    with patch("cli.AntigravityCliAdapter") as adapter:
        adapter.return_value.start_new_conversation.side_effect = RuntimeError("agy crashed")
        with pytest.raises(RuntimeError, match="agy crashed"):
            cli.dispatch("p2")


def test_single_pass_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTIGRAVITY_AUDITOR_PRIMARY_PASSES", "1")
    assert primary_lenses.active_lenses() == []
    monkeypatch.setenv("ANTIGRAVITY_AUDITOR_PRIMARY_PASSES", "x")
    assert len(primary_lenses.active_lenses()) == 3


def test_merge_keeps_the_higher_severity() -> None:
    low = {**FINDING, "fingerprint": "fingerprint-a", "severity": "LOW"}
    high = {**FINDING, "finding_id": "X", "fingerprint": "fingerprint-b", "severity": "HIGH"}  # same place+category
    merged = primary_lenses.merge_lens_findings([("l1", [low]), ("l2", [high])])
    assert len(merged) == 1 and merged[0]["severity"] == "HIGH" and merged[0]["finding_id"] == "F-SD-1"
    elsewhere = {**FINDING, "fingerprint": "fingerprint-c", "line_start": 40, "line_end": 41}
    assert len(primary_lenses.merge_lens_findings([("l1", [low]), ("l2", [elsewhere])])) == 2


# --- Windows weekly task ----------------------------------------------------------------------------------------


class FakePs:
    def __init__(self) -> None:
        self.scripts: list[str] = []
        self.stdout = ""

    def __call__(self, cmd: list[str]) -> subprocess.CompletedProcess:
        self.scripts.append(cmd[-1])
        return subprocess.CompletedProcess(cmd, 0, self.stdout, "")


def test_install_registers_the_task_and_writes_the_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ps = FakePs()
    monkeypatch.setattr(ws, "RUN", ps)
    ws.install(tmp_path, tmp_path / "core" / "cli.py", day="mon", time="4:05")
    script = ps.scripts[0]
    assert "Register-ScheduledTask" in script and "-StartWhenAvailable" in script and "IgnoreNew" in script
    assert "Monday" in script and "'04:05'" in script and "weekly" in script
    assert ws.uses_windows_task(tmp_path)
    with pytest.raises(ValueError):
        ws.install(tmp_path, tmp_path / "cli.py", day="XYZ")
    with pytest.raises(ValueError):
        ws.install(tmp_path, tmp_path / "cli.py", time="25:00")


def test_status_parses_task_info(monkeypatch: pytest.MonkeyPatch) -> None:
    ps = FakePs()
    ps.stdout = json.dumps({"state": "Ready", "last_run": "", "last_result": 267011, "next_run": "11/23/2026 4:00"})
    monkeypatch.setattr(ws, "RUN", ps)
    st = ws.status()
    assert st["installed"] and st["state"] == "Ready"
    ps.stdout = ""
    assert ws.status() == {"installed": False}


def test_legacy_sidecars_are_backed_up_and_removed(tmp_path: Path) -> None:
    root = tmp_path / "sidecars"
    for sid in ("p-audit", "auditor-models-sync", "someone-else"):
        (root / sid).mkdir(parents=True)
        (root / sid / "sidecar.json").write_text("{}", encoding="utf-8")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"sidecars": {"p-audit": {}, "auditor-models-sync": {}, "someone-else": {}},
                               "other": 1}), encoding="utf-8")
    res = ws.remove_legacy_sidecars(tmp_path, root, cfg, ["p"])
    assert not (root / "p-audit").exists() and not (root / "auditor-models-sync").exists()
    assert (root / "someone-else").exists()
    left = json.loads(cfg.read_text(encoding="utf-8"))
    assert left == {"sidecars": {"someone-else": {}}, "other": 1}
    assert (Path(res["backup"]) / "config.json").is_file() and (Path(res["backup"]) / "p-audit" / "sidecar.json").is_file()


def test_weekly_runs_model_sync_then_every_enabled_project(tmp_path: Path) -> None:
    db_path, _ = _seed_db(tmp_path, run_id="RUN-W", status="COMPLETED")
    with connect(db_path) as conn:
        conn.execute("INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id, enabled) "
                     "VALUES('off', 'Off', ?, 'x', 0)", (str(tmp_path),))
        conn.commit()
    calls: list[list[str]] = []

    def runner(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess:
        calls.append(cmd[2:])
        kw["stdout"].write("step output\n")
        return subprocess.CompletedProcess(cmd, 0 if "models" in cmd else 2)

    out = ws.run_weekly(tmp_path, db_path, tmp_path / "cli.py", runner=runner)
    assert calls == [["models", "sync", "--probe", "--propose"], ["scheduled-audit", "--project", "p2"]]
    assert [s["exit_code"] for s in out["steps"]] == [0, 2]
    assert "step output" in Path(out["log_path"]).read_text(encoding="utf-8")
    with connect(db_path) as conn:
        details = json.loads(conn.execute(
            "SELECT details FROM audit_events WHERE event_type='WEEKLY_RUN_FINISHED'").fetchone()[0])
    assert details["steps"][1] == {"step": "audit:p2", "exit_code": 2}


def test_empty_conversation_id_is_retried_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _cli_env(tmp_path, monkeypatch)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    calls: dict[str, int] = {}

    def fake(prompt: str, **kw: Any) -> Any:
        key = prompt.split("MULTI-PASS AUDIT - PASS ", 1)[1][:3]
        calls[key] = calls.get(key, 0) + 1
        if calls[key] == 1:
            return make_dispatch_result(ok=False, status="ERROR",
                                        error="failed to start conversation: backend returned an empty conversation id")
        return _result([], f"conv-{key}")

    with patch("cli.AntigravityCliAdapter") as adapter:
        adapter.return_value.start_new_conversation.side_effect = fake
        out = cli.dispatch("p2")
    assert out["candidate_count"] == 0 and calls == {"1/3": 2, "2/3": 2, "3/3": 2}


def test_merge_normalizes_fingerprints_and_bounds_ids() -> None:
    a = {**FINDING, "fingerprint": "Charge-Negative-Amount", "severity": "LOW"}
    b = {**FINDING, "finding_id": "Y", "fingerprint": "  charge-negative-amount ", "severity": "HIGH",
         "line_start": 90, "line_end": 91}
    merged = primary_lenses.merge_lens_findings([("l1", [a]), ("l2", [b])])
    assert len(merged) == 1 and merged[0]["severity"] == "HIGH"
    long_id = "X" * 128
    c = {**FINDING, "finding_id": long_id, "fingerprint": "fp-c-long", "line_start": 50, "line_end": 51}
    d = {**FINDING, "finding_id": long_id, "fingerprint": "fp-d-long", "line_start": 70, "line_end": 71}
    e = {**FINDING, "finding_id": long_id, "fingerprint": "fp-e-long", "line_start": 80, "line_end": 81}
    ids = [m["finding_id"] for m in primary_lenses.merge_lens_findings([("logic-contracts", [c, d, e])])]
    assert len(set(ids)) == 3 and all(len(i) <= 128 for i in ids)


def test_schedule_install_command_removes_the_sidecars(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path, _ = _seed_db(tmp_path, run_id="RUN-S", status="COMPLETED")
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "APP_HOME", tmp_path)
    monkeypatch.setattr(cli, "SIDECAR_ROOT", tmp_path / "sidecars")
    monkeypatch.setattr(cli, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(ws, "RUN", FakePs())
    (tmp_path / "sidecars" / "p2-audit").mkdir(parents=True)
    (tmp_path / "sidecars" / "p2-audit" / "sidecar.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["cli.py", "schedule", "install"])
    cli.main()
    assert not (tmp_path / "sidecars" / "p2-audit").exists() and ws.uses_windows_task(tmp_path)

"""Tier measurements, the measured routing engine, quota-aware planning and chat notices."""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

CORE = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE))

import model_benchmarks as mb  # noqa: E402
import model_catalog as cat  # noqa: E402
import model_notices as mn  # noqa: E402
import model_probes as mp  # noqa: E402
import model_routing_proposals as rp  # noqa: E402
from db import connect, initialize  # noqa: E402
from model_registry import RoutingTier, get_active_routing_table  # noqa: E402

MODELS = ["gemini-4-hydrogen-medium", "gemini-4-hydrogen-high", "gemini-4-neon-medium", "gemini-4-neon-high",
          "gemini-4-argon-high"]
TABLE = {"ENTRY": "agy:gemini-4-hydrogen-medium", "STANDARD": "agy:gemini-4-hydrogen-high",
         "CRITICAL": "agy:gemini-4-neon-medium", "CATASTROPHIC": "agy:gemini-4-argon-high"}


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    path = tmp_path / "home" / "database" / "auditor.db"
    initialize(path)
    cat.sync_catalog(path, listing="".join(f"{m}\t{m}\n" for m in MODELS))
    for m in MODELS:
        _probe(path, m)
    with connect(path) as conn:
        conn.execute("""INSERT INTO routing_table_versions(version_id, host, status, assignments_json, created_at,
                        decided_at, decided_by) VALUES('RT-cur', 'antigravity', 'ACTIVE', ?, 't', 't', 'tester')""",
                     (json.dumps(TABLE),))
        conn.commit()
    return path


def _probe(db: Path, slug: str) -> None:
    metrics = {"suite_sha256": mp.suite_sha256(), "latency_seconds": 20.0, "total_tokens": 1000, "score": 1.0}
    mp._store(db, {
        "probe_run_id": f"PROBE-{slug}-{uuid.uuid4().hex[:8]}", "backend": "agy", "model_slug": slug,
        "suite_version": mp.SUITE_VERSION, "catalog_snapshot_id": None, "status": "PASSED", "score": 1.0,
        "metrics_json": json.dumps(metrics), "conversation_id": None, "attestation_status": "RUNTIME_ATTESTED",
        "error": None, "started_at": "t", "finished_at": "t",
    })


def _measure(db: Path, slug: str, find: float, verify: float, tokens: int, *, finished: str | None = None,
             skip: tuple[str, ...] = ()) -> None:
    bench = mb.load_bench()
    finished = finished or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    for repo, kind in mb.bench_suites(bench):
        suite = f"{kind}:{repo}"
        if suite in skip:
            continue
        mb._store(db, {"run_id": f"B-{uuid.uuid4().hex}", "backend": "agy", "model_slug": slug,
                       "bench_version": mb.BENCH_VERSION, "bench_sha256": mb.suite_fingerprint(bench, repo, kind),
                       "suite": suite, "rep": 1, "status": "OK", "score": find if kind == "find" else verify,
                       "metrics_json": json.dumps({"missed_real": 0 if verify == 1.0 else 1}),
                       "total_tokens": tokens, "latency_seconds": 100.0, "conversation_id": None,
                       "error": None, "started_at": finished, "finished_at": finished})


def _measure_all(db: Path, standard_high_tokens: int = 22000) -> None:
    _measure(db, "gemini-4-hydrogen-medium", 0.95, 0.90, 18000)
    _measure(db, "gemini-4-hydrogen-high", 0.97, 0.90, standard_high_tokens)
    _measure(db, "gemini-4-neon-medium", 0.97, 0.95, 20000)
    _measure(db, "gemini-4-neon-high", 0.98, 1.00, 28000)
    _measure(db, "gemini-4-argon-high", 0.96, 0.958, 31000)


# --- suites and scoring -------------------------------------------------------------------------------

def _perfect_find(repo: dict) -> dict:
    out = []
    for d in repo["defects"]:
        loc = d["locations"][0]
        lo, hi = loc["lines"]
        lines = repo["files"][loc["file"]]
        line = next(i for i in range(lo, hi + 1) if lines[i - 1].strip())
        out.append({"file_path": loc["file"], "line_start": line, "line_end": line, "symbol": loc["symbol"],
                    "title": d["id"], "severity": "CRITICAL", "evidence_excerpt": lines[line - 1].strip()})
    return {"findings": out}


def _perfect_verify(repo: dict) -> dict:
    first = next(iter(repo["files"]))
    return {"results": [{"id": cid, "verdict": c["verdict"], "file": (c.get("evidence") or [[first]])[0][0],
                         "line": (c.get("evidence") or [[None, 1]])[0][1], "reason": "r"}
                        for cid, c in repo["claims"].items()]}


def test_bench_suites_are_consistent() -> None:
    bench = mb.load_bench()
    assert mb.bench_suites(bench) == [("ledger", "find"), ("bundle", "find"), ("vault", "verify"), ("relay", "verify")]
    for name, kind in mb.bench_suites(bench):
        repo = bench["repos"][name]
        if kind == "find":
            assert len(repo["defects"]) == 4 and len(repo["decoys"]) == 6, name
            for d in repo["defects"]:
                for loc in d["locations"]:
                    assert loc["file"] in repo["files"] and loc["lines"][1] <= len(repo["files"][loc["file"]]), (name, d)
            assert mb.score_find(_perfect_find(repo), repo)["score"] == 1.0
        else:
            claims = repo["claims"]
            real = [c for c in claims.values() if c["verdict"] == "CONFIRMED"]
            assert len(claims) == 12 and 4 <= len(real) <= 8, name
            for c in real:
                for f, lo, hi in c["evidence"]:
                    assert f in repo["files"] and 1 <= lo <= hi <= len(repo["files"][f]), (name, c)
                    assert all(repo["files"][f][i - 1].strip() for i in (lo, hi)), (name, c)  # no blank edges
            assert mb.score_verify(_perfect_verify(repo), repo)["score"] == 1.0
    fps = {mb.suite_fingerprint(bench, r, k) for r, k in mb.bench_suites(bench)}
    assert len(fps) == 4 and len(mb.bench_sha256()) == 64


def test_find_scoring_penalises_decoys_fabrication_and_misses() -> None:
    repo = mb.load_bench()["repos"]["ledger"]
    perfect = _perfect_find(repo)
    decoy_line = repo["files"]["views.py"][17].strip()  # yaml.load(... SafeLoader) on line 18
    with_decoy = {"findings": perfect["findings"] + [{"file_path": "views.py", "line_start": 18, "line_end": 18,
                  "symbol": "import_rules", "title": "yaml", "evidence_excerpt": decoy_line}]}
    s = mb.score_find(with_decoy, repo)
    assert s["decoy_hits"] == ["LD1"] and s["score"] < 1.0
    fabricated = {"findings": perfect["findings"][:3] + [{"file_path": "auth.py", "line_start": 1, "line_end": 1,
                  "symbol": "x", "title": "t", "evidence_excerpt": "this line does not exist"}]}
    s = mb.score_find(fabricated, repo)
    assert s["fabricated"] == 1 and s["missed"] == ["L4"]
    assert mb.score_find(None, repo)["score"] == 0.0


def test_verify_scoring_counts_missed_real_and_false_confirms() -> None:
    repo = mb.load_bench()["repos"]["relay"]
    answer = _perfect_verify(repo)
    for r in answer["results"]:
        if r["id"] == "C3":
            r["verdict"] = "REFUTED"   # real defect refuted (eval "sandbox" trusted)
        if r["id"] == "C2":
            r["verdict"] = "CONFIRMED"  # safe code confirmed
    s = mb.score_verify(answer, repo)
    assert s["missed_real"] == 1 and s["false_confirm"] == 1 and s["score"] < 1.0


@pytest.fixture()
def attested(monkeypatch):
    monkeypatch.setattr(mb, "ATTEST", lambda *_a: "RUNTIME_ATTESTED")


def test_measure_model_runs_every_suite_and_aggregates(db: Path, attested) -> None:
    bench = mb.load_bench()
    calls = []

    class Fake:
        def dispatch(self, *, prompt, model_id, **_kw):
            name, kind = next((r, k) for r, k in mb.bench_suites(bench)
                              if mb.build_prompt(bench["repos"][r], k) == prompt)
            repo = bench["repos"][name]
            calls.append((model_id, kind))
            answer = _perfect_find(repo) if kind == "find" else _perfect_verify(repo)
            return SimpleNamespace(ok=True, status="OK", events=[], response_text=json.dumps(answer), total_tokens=1234,
                                   conversation_id=None, error_message=None)

    runs = mb.measure_model(db, "gemini-4-neon-high", reps=2, adapter=Fake())
    assert len(runs) == 8 and all(r["status"] == "OK" for r in runs)
    m = mb.measurements(db)["gemini-4-neon-high"]
    assert m["complete"] and m["find_accuracy"] == 1.0 and m["verify_accuracy"] == 1.0
    assert m["tokens_per_call"] == 1234.0


def test_gate_is_one_find_and_one_verify_suite(db: Path) -> None:
    _measure(db, "gemini-4-neon-high", 1.0, 1.0, 1000, skip=("verify:relay",))
    assert mb.measurements(db)["gemini-4-neon-high"]["complete"] is True  # relay is not a gate suite
    _measure(db, "gemini-4-neon-medium", 1.0, 1.0, 1000, skip=("verify:vault",))
    m = mb.measurements(db)["gemini-4-neon-medium"]
    assert m["complete"] is False and m["missing_suites"] == ["verify:vault"]


def test_plan_never_remeasures_a_gated_model(db: Path) -> None:
    old = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    for slug in MODELS:
        _measure(db, slug, 1.0, 1.0, 1000, finished=old)
    plan = mb.measurement_plan(db, quota={"Gemini Models": 80.0, "Gemini 4 Argon": 90.0}, max_models=10)
    assert plan["todo"] == []


# --- planning -----------------------------------------------------------------------------------------

def test_plan_measures_table_models_first_and_respects_quota(db: Path) -> None:
    plan = mb.measurement_plan(db, quota={"Gemini Models": 80.0, "Gemini 4 Argon": 90.0}, max_models=3)
    first = [t["model"] for t in plan["todo"]]
    assert set(first) <= {model.split(":")[1] for model in TABLE.values()}  # table models first
    assert len(first) == 3
    low = mb.measurement_plan(db, quota={"Gemini Models": 20.0, "Gemini 4 Argon": 90.0})
    assert not low["todo"] and all(d["reason"] == "QUOTA_LOW" for d in low["deferred"])
    argon_low = mb.measurement_plan(db, quota={"Gemini Models": 80.0, "Gemini 4 Argon": 30.0}, max_models=10)
    assert {"model": "gemini-4-argon-high", "reason": "SCARCE_QUOTA_LOW", "remaining": 30.0} in argon_low["deferred"]
    unknown = mb.measurement_plan(db, quota=None, max_models=10)
    assert len(unknown["todo"]) == 1 and any(d["reason"] == "QUOTA_UNKNOWN" for d in unknown["deferred"])










def test_weekly_runs_measurements() -> None:
    import weekly_scheduler as ws

    src = Path(ws.__file__).read_text(encoding="utf-8")
    assert '"--measure"' in src and '"--evidence"' in src


def test_repeatedly_failing_model_waits_and_partial_runs_only_missing_suites(db: Path) -> None:
    _measure(db, "gemini-4-neon-high", 1.0, 1.0, 1000, skip=("verify:vault",))
    plan = mb.measurement_plan(db, quota={"Gemini Models": 80.0, "Gemini 4 Argon": 90.0}, max_models=10)
    item = next(t for t in plan["todo"] if t["model"] == "gemini-4-neon-high")
    assert item["suites"] == ["verify:vault"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    for _ in range(mb.MAX_RECENT_FAILURES):
        mb._store(db, {"run_id": f"B-{uuid.uuid4().hex}", "backend": "agy", "model_slug": "gemini-4-neon-high",
                       "bench_version": mb.BENCH_VERSION, "suite": "verify:vault",
                       "bench_sha256": mb.suite_fingerprint(mb.load_bench(), "vault", "verify"),
                       "rep": 1, "status": "ERROR", "score": None, "metrics_json": "{}", "total_tokens": 0,
                       "latency_seconds": 1.0, "conversation_id": None, "error": "x", "started_at": now,
                       "finished_at": now})
    plan = mb.measurement_plan(db, quota={"Gemini Models": 80.0, "Gemini 4 Argon": 90.0}, max_models=10)
    assert {"model": "gemini-4-neon-high", "reason": "REPEATED_FAILURES"} in plan["deferred"]


def test_find_credit_needs_the_defect_function() -> None:
    repo = mb.load_bench()["repos"]["ledger"]
    line = repo["files"]["store.py"][19].strip()  # inside decoy fee(), two lines from purge_old
    near = {"findings": [{"file_path": "store.py", "line_start": 20, "line_end": 21, "symbol": "fee", "title": "eval",
                          "severity": "CRITICAL", "evidence_excerpt": line}]}
    s = mb.score_find(near, repo)
    assert s["matched"] == [] and s["decoy_hits"] == ["LD6"]


def test_verify_requires_every_candidate_once_with_real_citations() -> None:
    repo = mb.load_bench()["repos"]["vault"]
    assert mb.score_verify({"results": []}, repo)["schema_valid"] is False
    dup = _perfect_verify(repo)
    dup["results"][1]["id"] = dup["results"][0]["id"]
    assert mb.score_verify(dup, repo)["schema_valid"] is False
    fake = _perfect_verify(repo)
    fake["results"][0]["line"] = 99999  # C1 (real defect) cited at a line that does not exist
    s = mb.score_verify(fake, repo)
    assert s["schema_valid"] and "C1" in s["bad_citation"] and s["missed_real"] == 1
    readme = _perfect_verify(repo)
    readme["results"][1].update(file="README.md", line=1)  # README facts may justify a REFUTED (C2)
    assert mb.score_verify(readme, repo)["score"] == 1.0


def test_unattested_runs_do_not_count(db: Path) -> None:
    bench = mb.load_bench()

    class Fake:
        def dispatch(self, *, prompt, **_kw):
            return SimpleNamespace(ok=True, status="OK", events=[], response_text="{}", total_tokens=1,
                                   conversation_id=None, error_message=None)

    out = mb.run_suite(db, "gemini-4-neon-high", "ledger", "find", adapter=Fake(), bench=bench)
    assert out["status"] == "ATTESTATION_FAILED"
    assert "gemini-4-neon-high" not in mb.measurements(db) or not mb.measurements(db)["gemini-4-neon-high"]["complete"]


def test_latest_runs_replace_older_ones(db: Path) -> None:
    old = (datetime.now(timezone.utc) - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    _measure(db, "gemini-4-neon-high", 0.5, 0.5, 1000, finished=old)
    _measure(db, "gemini-4-neon-high", 0.5, 0.5, 1000, finished=old)
    _measure(db, "gemini-4-neon-high", 1.0, 1.0, 2000)
    _measure(db, "gemini-4-neon-high", 1.0, 1.0, 2000)
    m = mb.measurements(db)["gemini-4-neon-high"]
    assert m["find_accuracy"] == 1.0 and m["tokens_per_call"] == 2000.0 and m["measured_at"] > old


def test_scarce_model_needs_its_own_quota_group(db: Path) -> None:
    plan = mb.measurement_plan(db, quota={"Gemini Models": 80.0}, max_models=10)
    assert {"model": "gemini-4-argon-high", "reason": "QUOTA_UNKNOWN"} in plan["deferred"]



def test_unmeasured_non_table_models_prefer_high_then_medium(db: Path) -> None:
    for slug in ("gemini-4-hydrogen-medium", "gemini-4-hydrogen-high", "gemini-4-neon-medium", "gemini-4-argon-high"):
        _measure(db, slug, 0.9, 0.9, 1000)
    cat.sync_catalog(db, listing="".join(f"{m}\t{m}\n" for m in MODELS + ["gemini-4-neon-low", "gemini-4-neon-xhigh"]))
    for m in ("gemini-4-neon-low", "gemini-4-neon-xhigh"):
        _probe(db, m)
    plan = mb.measurement_plan(db, quota={"Gemini Models": 80.0, "Gemini 4 Argon": 90.0}, max_models=10)
    assert [t["model"] for t in plan["todo"]] == ["gemini-4-neon-high", "gemini-4-neon-xhigh", "gemini-4-neon-low"]


def test_cli_setup_and_measure_share_one_lock(tmp_path: Path) -> None:
    import os
    import subprocess

    home = tmp_path / "home"
    (home / "locks").mkdir(parents=True)
    initialize(home / "database" / "auditor.db")
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        import audit_launcher as al

        (al._lock_path(home, "_models")).write_text(json.dumps({"pid": holder.pid,
                                                                 "process_start": al._process_start(holder.pid)}))
        env = {**os.environ, "ANTIGRAVITY_AUDITOR_HOME": str(home),
               "ANTIGRAVITY_AUDITOR_DB": str(home / "database" / "auditor.db")}
        out = subprocess.run([sys.executable, str(CORE / "cli.py"), "models", "setup"], capture_output=True, text=True,
                             env=env, timeout=120, stdin=subprocess.DEVNULL)
        assert out.returncode == 0 and '"BUSY"' in out.stdout
    finally:
        holder.kill()



def test_changed_suite_only_invalidates_its_own_runs(db: Path, monkeypatch) -> None:
    _measure(db, "gemini-4-neon-high", 1.0, 1.0, 1000)
    assert mb.measurements(db)["gemini-4-neon-high"]["complete"]
    real = mb.suite_fingerprint
    monkeypatch.setattr(mb, "suite_fingerprint",
                        lambda bench, r, k: "changed" if (r, k) == ("vault", "verify") else real(bench, r, k))
    m = mb.measurements(db)["gemini-4-neon-high"]
    assert not m["complete"] and m["missing_suites"] == ["verify:vault"] and m["find_accuracy"] == 1.0


def test_run_suite_rejects_a_kind_the_repository_is_not_for(db: Path) -> None:
    with pytest.raises(mb.BenchmarkError):
        mb.run_suite(db, "gemini-4-neon-high", "vault", "find", adapter=object())

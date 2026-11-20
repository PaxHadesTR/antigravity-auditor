"""Published benchmark evidence (verified on its pages) and the evidence routing engine."""

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
import model_evidence as me  # noqa: E402
import model_notices as mn  # noqa: E402
import model_probes as mp  # noqa: E402
import model_routing_proposals as rp  # noqa: E402
from db import connect, initialize  # noqa: E402
from model_registry import RoutingTier, get_active_routing_table  # noqa: E402

MODELS = ["gemini-4-hydrogen-medium", "gemini-4-hydrogen-high", "gemini-4-neon-medium", "gemini-4-neon-high",
          "gemini-4-argon-high"]
TABLE = {"ENTRY": "agy:gemini-4-hydrogen-medium", "STANDARD": "agy:gemini-4-hydrogen-high",
         "CRITICAL": "agy:gemini-4-neon-medium", "CATASTROPHIC": "agy:gemini-4-argon-high"}
TARGETS = {"gemini-4-hydrogen": ["gemini-4-hydrogen-medium", "gemini-4-hydrogen-high"],
           "gemini-4-neon": ["gemini-4-neon-medium", "gemini-4-neon-high"],
           "gemini-4-argon": ["gemini-4-argon-high"]}
LINES = sorted(TARGETS)
INDEX = {"gemini-4-neon-high": 60, "gemini-4-neon-medium": 55, "gemini-4-hydrogen-high": 51,
         "gemini-4-hydrogen-medium": 41, "gemini-4-argon-high": 50}
TOKENS = {"gemini-4-hydrogen-medium": 18000, "gemini-4-hydrogen-high": 22000, "gemini-4-neon-medium": 20000,
          "gemini-4-neon-high": 28000, "gemini-4-argon-high": 15000}


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    path = tmp_path / "home" / "database" / "auditor.db"
    initialize(path)
    cat.sync_catalog(path, listing="".join(f"{m}\t{m}\n" for m in MODELS))
    for m in MODELS:
        metrics = {"suite_sha256": mp.suite_sha256(), "latency_seconds": 20.0, "total_tokens": 1000, "score": 1.0}
        mp._store(path, {"probe_run_id": f"PROBE-{m}-{uuid.uuid4().hex[:8]}", "backend": "agy", "model_slug": m,
                         "suite_version": mp.SUITE_VERSION, "catalog_snapshot_id": None, "status": "PASSED",
                         "score": 1.0, "metrics_json": json.dumps(metrics), "conversation_id": None,
                         "attestation_status": "RUNTIME_ATTESTED", "error": None, "started_at": "t", "finished_at": "t"})
    with connect(path) as conn:
        conn.execute("""INSERT INTO routing_table_versions(version_id, host, status, assignments_json, created_at,
                        decided_at, decided_by) VALUES('RT-cur', 'antigravity', 'ACTIVE', ?, 't', 't', 'tester')""",
                     (json.dumps(TABLE),))
        conn.commit()
    return path


def _gate(db: Path, slug: str, *, tokens: int, find: float = 1.0, verify: float = 1.0) -> None:
    bench = mb.load_bench()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    for suite in mb.GATE_SUITES:
        kind, repo = suite.split(":")
        mb._store(db, {"run_id": f"B-{uuid.uuid4().hex}", "backend": "agy", "model_slug": slug,
                       "bench_version": mb.BENCH_VERSION, "bench_sha256": mb.suite_fingerprint(bench, repo, kind),
                       "suite": suite, "rep": 1, "status": "OK", "score": find if kind == "find" else verify,
                       "metrics_json": "{}", "total_tokens": tokens, "latency_seconds": 50.0,
                       "conversation_id": None, "error": None, "started_at": now, "finished_at": now})


def _evidence(db: Path, index: dict[str, float], security: dict[tuple[str, str], float] | None = None, *,
              created: str | None = None, report_id: str | None = None) -> None:
    scores = []
    for slug, value in index.items():
        line, effort = slug.rsplit("-", 1)
        scores.append({"model_line": line, "effort": effort, "benchmark": "aa_index", "value": float(value),
                       "source_url": f"https://artificialanalysis.ai/models/{line}", "host": "artificialanalysis.ai",
                       "reported_by": "independent"})
    for (line, bench), value in (security or {}).items():
        scores.append({"model_line": line, "effort": "unspecified", "benchmark": bench, "value": float(value),
                       "source_url": "https://sec-bench.github.io/", "host": "sec-bench.github.io",
                       "reported_by": "independent"})
    created = created or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    me._store(db, {"report_id": report_id or f"EVIDENCE-{uuid.uuid4().hex[:8]}", "backend": "agy",
                   "researcher_model": "gemini-4-hydrogen-high", "catalog_snapshot_id": None,
                   "target_lines_json": json.dumps(TARGETS), "status": "COMPLETED", "scores_json": json.dumps(scores),
                   "rejected_json": "[]", "web_tool_calls": 4, "issues_json": "[]", "conversation_id": None,
                   "attestation_status": "RUNTIME_ATTESTED", "error": None, "created_at": created})


def _all(db: Path, index: dict[str, float] | None = None, tokens: dict[str, int] | None = None,
         security: dict[tuple[str, str], float] | None = None) -> None:
    for slug, t in (tokens or TOKENS).items():
        _gate(db, slug, tokens=t)
    _evidence(db, index or INDEX, security if security is not None else
              {("gemini-4-neon", "sec_bench_pro"): 90.5, ("gemini-4-argon", "sec_bench_pro"): 83.4})


# --- verification of published numbers ------------------------------------------------------------------

def test_benchmark_names_are_canonicalised() -> None:
    assert me.benchmark_key("Artificial Analysis Intelligence Index") == "aa_index"
    assert me.benchmark_key("CWE-bench v2 (Pass@1)") == "cwe_bench_v2"
    assert me.benchmark_key("CWE-bench v2 (Pass@4)") is None
    assert me.benchmark_key("SEC-bench Pro") == "sec_bench_pro"
    assert me.benchmark_key("Some Other Leaderboard") is None


AA_PAGE = ("Gemini 4 Hydrogen scores 54 (xhigh), 51 (high), 41 (medium), and 27 (low) on the Artificial Analysis "
           "Intelligence Index. It is 1 point ahead of Gemini 4 Carbon (high), which scores 53.")
BOARD = "CWE-bench v2 leaderboard | Rank, Model, Pass@1, Pass@4 | 2, Gemini 4 Neon, Antigravity, 70.7%, 76.4% 3, Gemini 4 Hydrogen, Antigravity, 68.1%, 78.0%"


@pytest.mark.parametrize("line,effort,bench,value,host,expected", [
    ("gemini-4-hydrogen", "high", "aa_index", 51, "artificialanalysis.ai", None),
    ("gemini-4-hydrogen", "xhigh", "aa_index", 54, "artificialanalysis.ai", None),
    ("gemini-4-hydrogen", "high", "aa_index", 54, "artificialanalysis.ai", "EFFORT_NOT_NEAREST"),
    ("gemini-4-hydrogen", "high", "aa_index", 53, "artificialanalysis.ai", "MODEL_NOT_NEAREST"),  # Carbon's number
    ("gemini-4-hydrogen", "high", "aa_index", 99, "artificialanalysis.ai", "VALUE_NOT_ON_PAGE"),
])
def test_verify_score_on_an_index_page(line, effort, bench, value, host, expected) -> None:
    assert me.verify_score(AA_PAGE, line=line, effort=effort, bench=bench, value=value, host=host,
                           lines=LINES) == expected


def test_verify_score_on_a_leaderboard_row() -> None:
    kw = {"effort": None, "bench": "cwe_bench_v2", "host": "cwe-bench.com", "lines": LINES}
    assert me.verify_score(BOARD, line="gemini-4-neon", value=70.7, **kw) is None
    assert me.verify_score(BOARD, line="gemini-4-hydrogen", value=68.1, **kw) is None
    assert me.verify_score(BOARD, line="gemini-4-hydrogen", value=70.7, **kw) == "MODEL_NOT_NEAREST"
    # on a vendor page the benchmark must be named next to the value
    blog = "Neon reaches 70.7% on CWE-bench v2 and 90.5% on SEC-bench Pro."
    assert me.verify_score(blog, line="gemini-4-neon", value=70.7, effort=None, bench="cwe_bench_v2",
                           host="blog.google", lines=LINES) is None
    assert me.verify_score(blog, line="gemini-4-neon", value=90.5, effort=None, bench="cwe_bench_v2",
                           host="blog.google", lines=LINES) == "BENCHMARK_NOT_NEAREST"


def test_sanitize_and_verify_keeps_only_verified_numbers() -> None:
    pages = {"https://artificialanalysis.ai/models/gemini-4-hydrogen": AA_PAGE, "https://cwe-bench.com/": BOARD}
    fetched = []

    def fetch(url: str) -> str | None:
        fetched.append(url)
        return pages.get(url)

    def item(**kw):
        return {"model_line": "gemini-4-hydrogen", "effort": "high", "benchmark": "Artificial Analysis Intelligence Index",
                "value": 51, "source_url": "https://artificialanalysis.ai/models/gemini-4-hydrogen", **kw}

    payload = {"scores": [
        item(),
        item(effort="medium", value=41),
        item(effort="xhigh", value=54),  # not offered on this account
        item(model_line="gemini-9-unknown"),
        item(benchmark="Made-up Bench"),
        item(value=140),
        item(source_url="https://random-blog.example/hydrogen"),  # not a trusted host for this benchmark
        item(source_url="https://vertexaisearch.cloud.google.com/grounding-api-redirect/abc"),
        item(value=27),  # wrong effort for this value
        {"model_line": "gemini-4-neon", "effort": "unspecified", "benchmark": "CWE-bench v2", "value": 70.7,
         "source_url": "https://cwe-bench.com/"},
        item(),  # duplicate
    ]}
    accepted, rejected, issues = me.sanitize_and_verify(payload, TARGETS, fetch=fetch)
    got = {(a["model_line"], a["effort"], a["benchmark"], a["value"]) for a in accepted}
    assert got == {("gemini-4-hydrogen", "high", "aa_index", 51.0), ("gemini-4-hydrogen", "medium", "aa_index", 41.0),
                   ("gemini-4-neon", "unspecified", "cwe_bench_v2", 70.7)}
    # the untrusted and redirect citations of the true 51 are confirmed on the canonical page instead
    assert {r["reason"] for r in rejected} == {"EFFORT_NOT_OFFERED", "UNREQUESTED_MODEL_LINE", "UNKNOWN_BENCHMARK",
                                               "VALUE_OUT_OF_RANGE", "EFFORT_NOT_NEAREST"}
    assert "Duplicate scores were merged." in issues
    assert len(fetched) == len(set(fetched))  # each page fetched once
    assert all("random-blog" not in u for u in fetched)  # untrusted hosts are never fetched


def test_fetch_refuses_non_public_and_non_https_urls() -> None:
    for url in ("http://artificialanalysis.ai/", "https://localhost/x", "https://127.0.0.1/", "https://10.0.0.1/",
                "https://user@artificialanalysis.ai/"):
        assert me._fetch(url) is None


def test_page_text_drops_scripts_and_tags() -> None:
    raw = "<html><script>var x = 99;</script><p>Neon &amp; Hydrogen <b>61</b></p></html>"
    assert me.page_text(raw) == "Neon & Hydrogen 61"


def test_current_evidence_prefers_newest_and_expires_old(db: Path) -> None:
    old = (datetime.now(timezone.utc) - timedelta(days=me.EVIDENCE_MAX_AGE_DAYS + 5)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    _evidence(db, {"gemini-4-argon-high": 49}, created=old)
    assert "gemini-4-argon-high" not in me.current_evidence(db)["index"]
    _evidence(db, {"gemini-4-neon-high": 58}, created="2026-11-01T00:00:00.000000Z")
    _evidence(db, {"gemini-4-neon-high": 60})
    ev = me.current_evidence(db)
    assert me.index_for(ev, "gemini-4-neon-high") == 60.0 and me.index_for(ev, "agy:gemini-4-neon-high") == 60.0
    assert me.index_for(ev, "gemini-4-neon-medium") is None


def test_security_points_compare_only_shared_benchmarks() -> None:
    ev = {"security": {"gemini-4-neon": {"sec_bench_pro": 90.5, "cwe_bench_v2": 70.7},
                       "gemini-4-argon": {"sec_bench_pro": 83.4, "cwe_bench_v2": 65.0},
                       "gemini-4-hydrogen": {"cwe_bench_v2": 68.1}}}
    assert me.security_points(ev, set(LINES)) == {"gemini-4-neon": 1.0, "gemini-4-hydrogen": 0.5, "gemini-4-argon": 0.0}
    # a line that shares no benchmark with the others has no proven result
    ev["security"]["gemini-4-hydrogen"] = {"realvuln": 50.0}
    assert me.security_points(ev, set(LINES))["gemini-4-hydrogen"] == -1.0
    # only the given lines are compared (a weak line that cannot serve critical tiers does not add wins)
    assert me.security_points(ev, {"gemini-4-neon", "gemini-4-argon"}) == {"gemini-4-neon": 1.0, "gemini-4-argon": 0.0}


def test_evidence_is_due_weekly_and_for_new_lines(db: Path) -> None:
    assert me.evidence_due(db) is True
    _evidence(db, INDEX)
    assert me.evidence_due(db) is False
    assert me.evidence_due(db, now=datetime.now(timezone.utc) + timedelta(days=7)) is True
    cat.sync_catalog(db, listing="".join(f"{m}\t{m}\n" for m in MODELS + ["gemini-4-carbon-high"]))
    assert me.evidence_due(db) is True


def test_run_evidence_stores_only_verified_scores(db: Path, monkeypatch) -> None:
    monkeypatch.setattr(me, "ATTEST", lambda *_a: "RUNTIME_ATTESTED")
    monkeypatch.setattr(me, "FETCH", lambda url: AA_PAGE if "artificialanalysis" in url else None)
    payload = {"scores": [
        {"model_line": "gemini-4-hydrogen", "effort": "high", "benchmark": "Artificial Analysis Intelligence Index",
         "value": 51, "source_url": "https://artificialanalysis.ai/models/gemini-4-hydrogen"},
        {"model_line": "gemini-4-hydrogen", "effort": "medium", "benchmark": "Artificial Analysis Intelligence Index",
         "value": 45, "source_url": "https://artificialanalysis.ai/models/gemini-4-hydrogen"}]}

    class Fake:
        def dispatch(self, **_kw):
            return SimpleNamespace(ok=True, status="OK", response_text=json.dumps(payload), total_tokens=1234,
                                   conversation_id="c1", error_message=None,
                                   events=[{"step_update": {"tool_name": "search_web", "state": "DONE"}}])

    out = me.run_evidence(db, adapter=Fake())
    assert out["status"] == "COMPLETED" and out["accepted"] == 1 and out["rejected_reasons"] == ["VALUE_NOT_ON_PAGE"]
    assert me.index_for(me.current_evidence(db), "gemini-4-hydrogen-high") == 51.0
    assert me.index_for(me.current_evidence(db), "gemini-4-hydrogen-medium") is None


def test_run_without_web_tool_calls_is_not_used(db: Path, monkeypatch) -> None:
    monkeypatch.setattr(me, "ATTEST", lambda *_a: "RUNTIME_ATTESTED")
    monkeypatch.setattr(me, "FETCH", lambda url: AA_PAGE)

    class Fake:
        def dispatch(self, **_kw):
            return SimpleNamespace(ok=True, status="OK", response_text=json.dumps({"scores": [
                {"model_line": "gemini-4-hydrogen", "effort": "high", "benchmark": "Intelligence Index", "value": 51,
                 "source_url": "https://artificialanalysis.ai/models/gemini-4-hydrogen"}]}),
                total_tokens=1, conversation_id="c1", error_message=None, events=[])

    assert me.run_evidence(db, adapter=Fake())["status"] == "NO_WEB_EVIDENCE"
    assert me.current_evidence(db)["index"] == {}


# --- evidence engine ----------------------------------------------------------------------------------

def test_engine_picks_strongest_then_cheapest_and_keeps_lines_apart(db: Path) -> None:
    _all(db)
    r = rp.build_proposal(db)
    assert r["evidence"]["engine"] == "evidence" and r["status"] == "PROPOSAL"
    # CATASTROPHIC/CRITICAL: highest index (Neon High 60; Neon Medium 55 is outside CRITICAL's 2 points);
    # STANDARD must leave the Neon line: Hydrogen High (51) - Argon High (50) is cheaper in tokens but scarce (x4);
    # ENTRY: cheapest within 10 points of the best (Neon Medium 55, 20k tokens).
    assert r["assignments"] == {"ENTRY": "agy:gemini-4-neon-medium", "STANDARD": "agy:gemini-4-hydrogen-high",
                                "CRITICAL": "agy:gemini-4-neon-high", "CATASTROPHIC": "agy:gemini-4-neon-high"}


def test_engine_keeps_the_table_within_margin(db: Path) -> None:
    _all(db)
    with connect(db) as conn:
        conn.execute("UPDATE routing_table_versions SET assignments_json=? WHERE version_id='RT-cur'", (json.dumps({
            "ENTRY": "agy:gemini-4-neon-medium", "STANDARD": "agy:gemini-4-hydrogen-high",
            "CRITICAL": "agy:gemini-4-neon-high", "CATASTROPHIC": "agy:gemini-4-neon-high"}),))
        conn.commit()
    _gate(db, "gemini-4-hydrogen-medium", tokens=17500)  # slightly cheaper ENTRY candidate is no reason to change
    assert rp.build_proposal(db)["status"] == "NO_CHANGE"


def test_engine_waits_until_every_working_incumbent_has_evidence(db: Path) -> None:
    _all(db, index={k: v for k, v in INDEX.items() if k != "gemini-4-argon-high"})
    assert rp.build_evidence_proposal(db) is None
    assert rp.build_proposal(db).get("evidence", {}).get("engine") != "evidence"
    assert rp.evidence_candidates(db)["missing"] == {"gemini-4-argon-high": "NO_PUBLISHED_INDEX"}


def test_gate_floor_keeps_a_model_off_the_critical_tiers(db: Path) -> None:
    _all(db)
    _gate(db, "gemini-4-neon-high", tokens=28000, verify=0.5)
    _gate(db, "gemini-4-neon-high", tokens=28000, verify=0.5)  # newest runs count
    r = rp.build_proposal(db)
    assert "gemini-4-neon-high" not in (r["assignments"]["CRITICAL"], r["assignments"]["CATASTROPHIC"])


def test_security_results_break_ties_on_the_critical_tiers(db: Path) -> None:
    index = {**INDEX, "gemini-4-argon-high": 60}
    _all(db, index=index, security={("gemini-4-neon", "sec_bench_pro"): 83.4, ("gemini-4-argon", "sec_bench_pro"): 90.5})
    r = rp.build_proposal(db)
    assert r["assignments"]["CATASTROPHIC"] == "agy:gemini-4-argon-high"
    _evidence(db, {}, {("gemini-4-neon", "sec_bench_pro"): 95.0})  # newer result: Neon now ahead
    assert rp.build_proposal(db)["assignments"]["CATASTROPHIC"] == "agy:gemini-4-neon-high"


def test_evidence_proposal_is_auto_approved_and_noticed(db: Path) -> None:
    _all(db)
    prop = rp.create_proposal(db)
    assert rp.auto_approve_blockers(db, prop) == []
    auto = rp.maybe_auto_approve(db, prop)
    assert auto["status"] == "APPROVED"
    assert get_active_routing_table(db_path=db).model_for(RoutingTier.CATASTROPHIC) == "agy:gemini-4-neon-high"
    assert mn.notices_from_sync(db, {"proposal": prop, "auto_approval": auto}) == ["TABLE_CHANGED"]


@pytest.mark.parametrize("field,value,message", [
    ("evidence_verified", False, "not verified"),
    ("gate_ok", False, "gate floor"),
    ("probe_run_id", None, "PASSED probe"),
    ("incumbent_index", 70.0, "clearly weaker"),
])
def test_auto_approval_gates(db: Path, field: str, value, message: str, monkeypatch) -> None:
    _all(db)
    prop = rp.create_proposal(db)
    real = rp.build_evidence_proposal

    def fresh_with(*a, **kw):  # the gates read the freshly derived rationale
        out = real(*a, **kw)
        next(r for r in out["rationale"] if r["changed"] and r["tier"] == "CATASTROPHIC")[field] = value
        return out

    monkeypatch.setattr(rp, "build_evidence_proposal", fresh_with)
    assert any(message in b for b in rp.auto_approve_blockers(db, prop))


def test_tampering_with_the_stored_rationale_changes_nothing(db: Path) -> None:
    _all(db)
    prop = rp.create_proposal(db)
    for r in prop["rationale"]:
        r.update(evidence_verified=True, gate_ok=True, index=99.0)
    assert rp.auto_approve_blockers(db, prop) == []  # same verdict as the untampered proposal
    _gate(db, "gemini-4-neon-high", tokens=28000, verify=0.5)  # the gate result really changes
    assert any("changed since the proposal" in b for b in rp.auto_approve_blockers(db, prop))


def test_auto_approve_can_still_be_turned_off(db: Path) -> None:
    _all(db)
    rp.set_auto_approve(db, False, decided_by="alice")
    prop = rp.create_proposal(db)
    auto = rp.maybe_auto_approve(db, prop)
    assert auto == {"status": "OFF"}
    assert mn.notices_from_sync(db, {"proposal": prop, "auto_approval": auto}) == ["PROPOSAL_WAITING"]
    assert get_active_routing_table(db_path=db).version == "RT-cur"


# --- hardening (review findings 2026-11-20) -----------------------------------------------------------------

def test_a_later_column_of_the_row_is_not_accepted() -> None:
    kw = {"effort": None, "bench": "cwe_bench_v2", "host": "cwe-bench.com", "lines": LINES}
    assert me.verify_score(BOARD, line="gemini-4-neon", value=76.4, **kw) == "NOT_FIRST_VALUE_OF_ROW"  # pass@4
    v1_page = "CWE-bench v1 results | 2, Gemini 4 Neon, 61.0%"
    assert me.verify_score(v1_page, line="gemini-4-neon", value=61.0, **kw) == "BENCHMARK_NOT_NEAREST"


def test_rounded_or_inflated_values_do_not_match() -> None:
    page = "Gemini 4 Neon scores 60 (high) on the Artificial Analysis Intelligence Index"
    kw = {"line": "gemini-4-neon", "effort": "high", "bench": "aa_index", "host": "artificialanalysis.ai", "lines": LINES}
    assert me.verify_score(page, value=60.0, **kw) is None
    assert me.verify_score(page, value=60.04, **kw) == "VALUE_NOT_ON_PAGE"


def test_table_cells_keep_their_own_effort() -> None:
    raw = ("<p>Artificial Analysis Intelligence Index</p><table><tr><td>Gemini 4 Neon</td><td>48 (low)</td>"
           "<td>55 (medium)</td><td>60 (high)</td></tr></table>")
    text = me.page_text(raw)
    kw = {"line": "gemini-4-neon", "bench": "aa_index", "host": "artificialanalysis.ai", "lines": LINES}
    assert me.verify_score(text, value=55, effort="medium", **kw) is None
    assert me.verify_score(text, value=55, effort="low", **kw) == "EFFORT_NOT_NEAREST"
    assert me.verify_score(text, value=60, effort="medium", **kw) == "EFFORT_NOT_NEAREST"


def test_unclosed_script_is_dropped() -> None:
    assert me.page_text("<p>Neon 61</p><script>var leaked = {score: 99, model: 'neon'") == "Neon 61"


def test_benchmark_names_are_not_model_names_and_other_lines_compete() -> None:
    lines = ["gemini-4-neon", "gemini-4-pro"]
    blog = "Neon achieves state-of-the-art performance on SEC-bench Pro (90.5%), while costing less."
    assert me.verify_score(blog, line="gemini-4-neon", effort=None, bench="sec_bench_pro", value=90.5,
                           host="blog.google", lines=lines) is None
    board = "SEC-bench Pro | 1, Gemini 4 Neon, 55.0% | 2, Gemini 3.5 Flash, 72.0%"
    assert me.verify_score(board, line="gemini-4-neon", effort=None, bench="sec_bench_pro", value=72.0,
                           host="sec-bench.github.io", lines=["gemini-4-neon"],
                           other_lines=["gemini-3.5-flash"]) == "MODEL_NOT_NEAREST"
    words = me.model_words(["gemini-3-pro", "gemini-4-pro"])
    assert words["gemini-3-pro"].search("Gemini 3 Pro") and not words["gemini-3-pro"].search("Gemini 4 Pro")


def test_user_content_google_hosts_are_not_trusted() -> None:
    payload = {"scores": [{"model_line": "gemini-4-argon", "effort": "high", "benchmark": "Intelligence Index",
                           "value": 99, "source_url": url} for url in (
        "https://support.google.com/gemini/thread/123", "https://gemini.google.com/share/abc")]}
    forged = "Gemini 4 Argon (high) scores 99 on the Artificial Analysis Intelligence Index"
    accepted, rejected, _ = me.sanitize_and_verify(
        payload, TARGETS, fetch=lambda url: forged if "google.com" in url else None)
    assert accepted == [] and {r["reason"] for r in rejected} == {"SOURCE_NOT_TRUSTED_FOR_BENCHMARK"}


def test_conflicting_values_use_the_lower_one_and_security_has_no_effort() -> None:
    pages = {"https://sec-bench.github.io/a": "SEC-bench Pro | 1, Gemini 4 Neon, 90.5%",
             "https://sec-bench.github.io/b": "SEC-bench Pro | 1, Gemini 4 Neon, 80.0%"}
    payload = {"scores": [{"model_line": "gemini-4-neon", "effort": e, "benchmark": "SEC-bench Pro", "value": v,
                           "source_url": u} for e, v, u in (("high", 90.5, "https://sec-bench.github.io/a"),
                                                            ("unspecified", 80.0, "https://sec-bench.github.io/b"))]}
    accepted, _, issues = me.sanitize_and_verify(payload, TARGETS, fetch=pages.get)
    assert [(a["effort"], a["value"]) for a in accepted] == [("unspecified", 80.0)]
    assert "Conflicting verified values were found; the lower one is used." in issues


def test_malformed_values_never_crash() -> None:
    payload = {"scores": [{"model_line": "gemini-4-neon", "effort": "high", "benchmark": "Intelligence Index",
                           "value": 10 ** 400, "source_url": "https://artificialanalysis.ai/x"},
                          {"model_line": "gemini-4-neon", "effort": "high", "benchmark": "Intelligence Index",
                           "value": float("nan"), "source_url": "https://artificialanalysis.ai/x"}, "junk", None]}
    accepted, rejected, _ = me.sanitize_and_verify(payload, TARGETS, fetch=lambda url: "x")
    assert accepted == [] and [r["reason"] for r in rejected] == ["VALUE_NOT_A_NUMBER", "VALUE_NOT_A_NUMBER"]


def test_fetch_budget_is_limited(monkeypatch) -> None:
    monkeypatch.setattr(me, "MAX_FETCHES", 2)
    payload = {"scores": [{"model_line": "gemini-4-neon", "effort": "high", "benchmark": "Intelligence Index",
                           "value": 60, "source_url": f"https://artificialanalysis.ai/p{i}"} for i in range(5)]}
    fetched = []
    _, rejected, _ = me.sanitize_and_verify(payload, TARGETS, fetch=lambda url: fetched.append(url) or None)
    assert len(fetched) == 2 and [r["reason"] for r in rejected].count("FETCH_BUDGET_EXHAUSTED") == 4


def test_a_run_without_verified_numbers_does_not_count_as_done(db: Path, monkeypatch) -> None:
    monkeypatch.setattr(me, "ATTEST", lambda *_a: "RUNTIME_ATTESTED")
    monkeypatch.setattr(me, "FETCH", lambda url: None)

    class Fake:
        def dispatch(self, **_kw):
            return SimpleNamespace(ok=True, status="OK", response_text=json.dumps({"scores": [
                {"model_line": "gemini-4-neon", "effort": "high", "benchmark": "Intelligence Index", "value": 60,
                 "source_url": "https://artificialanalysis.ai/models/gemini-4-neon"}]}), total_tokens=1,
                conversation_id="c1", error_message=None,
                events=[{"step_update": {"tool_name": "search_web", "state": "DONE"}}])

    assert me.run_evidence(db, adapter=Fake())["status"] == "NO_VERIFIED_SCORES"
    assert me.evidence_due(db) is True


def test_a_new_effort_of_a_known_line_makes_evidence_due(db: Path) -> None:
    _evidence(db, INDEX)
    assert me.evidence_due(db) is False
    cat.sync_catalog(db, listing="".join(f"{m}\t{m}\n" for m in MODELS + ["gemini-4-neon-xhigh"]))
    assert me.evidence_due(db) is True


def test_standard_cannot_be_weakened_by_moving_critical_to_another_line(db: Path) -> None:
    """Review case: CRITICAL on a third line must not shrink STANDARD's comparison pool."""
    index = {"gemini-4-neon-high": 60, "gemini-4-neon-medium": 40, "gemini-4-hydrogen-high": 58,
             "gemini-4-hydrogen-medium": 57, "gemini-4-argon-high": 30}
    tokens = {"gemini-4-neon-high": 30000, "gemini-4-neon-medium": 30000, "gemini-4-hydrogen-high": 30000,
              "gemini-4-hydrogen-medium": 30000, "gemini-4-argon-high": 1000}
    _all(db, index=index, tokens=tokens, security={})
    r = rp.build_proposal(db)
    assert r["assignments"]["STANDARD"].startswith("agy:gemini-4-hydrogen")
    std = next(x for x in r["rationale"] if x["tier"] == "STANDARD")
    assert std["best_index"] == 58


def test_an_unprobed_offered_incumbent_is_not_evicted(db: Path) -> None:
    _all(db)
    with connect(db) as conn:  # Argon (CATASTROPHIC incumbent) was never probed, e.g. its quota was low
        conn.execute("DELETE FROM model_probe_runs WHERE model_slug='gemini-4-argon-high'")
        conn.commit()
    assert rp.build_evidence_proposal(db) is None


def test_a_model_without_token_counts_is_not_free(db: Path) -> None:
    _all(db)
    with connect(db) as conn:
        conn.execute("UPDATE model_benchmark_runs SET total_tokens=NULL WHERE model_slug='gemini-4-hydrogen-medium'")
        conn.commit()
    cand = rp.evidence_candidates(db)["candidates"]
    assert cand["gemini-4-hydrogen-medium"]["cost"] == max(c["cost"] for c in cand.values() if not c["scarce"])


def test_auto_approval_rechecks_the_database(db: Path) -> None:
    _all(db)
    prop = rp.create_proposal(db)
    _evidence(db, {"gemini-4-neon-high": 20})  # newer evidence: the stored proposal is no longer the choice
    assert any("changed since the proposal" in b for b in rp.auto_approve_blockers(db, prop))


def test_evidence_show_does_not_take_the_models_lock(tmp_path: Path) -> None:
    import os
    import subprocess

    home = tmp_path / "home"
    (home / "locks").mkdir(parents=True)
    initialize(home / "database" / "auditor.db")
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        import audit_launcher as al

        al._lock_path(home, "_models").write_text(json.dumps({"pid": holder.pid,
                                                               "process_start": al._process_start(holder.pid)}))
        env = {**os.environ, "ANTIGRAVITY_AUDITOR_HOME": str(home),
               "ANTIGRAVITY_AUDITOR_DB": str(home / "database" / "auditor.db")}
        out = subprocess.run([sys.executable, str(CORE / "cli.py"), "models", "evidence", "--show"],
                             capture_output=True, text=True, env=env, timeout=120, stdin=subprocess.DEVNULL)
        assert out.returncode == 0 and '"BUSY"' not in out.stdout and '"index"' in out.stdout
    finally:
        holder.kill()


# --- second review round ----------------------------------------------------------------------------------

def test_standard_reference_does_not_depend_on_the_chosen_combination(db: Path) -> None:
    """Two lines tie for CATASTROPHIC; only one of them may serve STANDARD (the other fails FIND). The table must
    put the tied line that cannot serve STANDARD on the critical tiers and keep STANDARD strong."""
    index = {"gemini-4-neon-high": 60, "gemini-4-neon-medium": 20, "gemini-4-argon-high": 60,
             "gemini-4-hydrogen-high": 30, "gemini-4-hydrogen-medium": 25}
    tokens = {"gemini-4-neon-high": 30000, "gemini-4-neon-medium": 30000, "gemini-4-argon-high": 5000,
              "gemini-4-hydrogen-high": 1000, "gemini-4-hydrogen-medium": 1000}
    _all(db, index=index, tokens=tokens, security={})
    _gate(db, "gemini-4-argon-high", tokens=5000, find=0.5)  # Argon fails the FIND floor
    r = rp.build_proposal(db)
    assert r["assignments"]["STANDARD"] == "agy:gemini-4-neon-high"
    assert r["assignments"]["CATASTROPHIC"] == "agy:gemini-4-argon-high"


def test_effortless_slug_and_neighbouring_cells() -> None:
    assert me.verify_score("Artificial Analysis Intelligence Index | Gemini 4 Neon | 61", line="gemini-4-neon",
                           effort="unspecified", bench="aa_index", value=61, host="artificialanalysis.ai",
                           lines=LINES) is None
    cells = me.page_text("<p>Artificial Analysis Intelligence Index</p><table><tr><td>Gemini 4 Neon (high)</td>"
                         "<td>60</td></tr></table>")
    assert me.verify_score(cells, line="gemini-4-neon", effort="high", bench="aa_index", value=60,
                           host="artificialanalysis.ai", lines=LINES) is None
    vendor = me.page_text("<h2>Gemini 4 Neon</h2><table><tr><td>SEC-bench Pro</td><td>90.5%</td></tr></table>")
    assert me.verify_score(vendor, line="gemini-4-neon", effort=None, bench="sec_bench_pro", value=90.5,
                           host="blog.google", lines=LINES) is None


def test_numbers_are_whole_tokens() -> None:
    page = "Artificial Analysis Intelligence Index | Gemini 4 Neon (high, 64k context)"
    assert me.verify_score(page, line="gemini-4-neon", effort="high", bench="aa_index", value=64,
                           host="artificialanalysis.ai", lines=LINES) == "VALUE_NOT_ON_PAGE"
    row = "CWE-bench v2 | 2 | Gemini 4 Neon (2026-11) | 70.7% | 76.4%"
    assert me.verify_score(row, line="gemini-4-neon", effort=None, bench="cwe_bench_v2", value=70.7,
                           host="cwe-bench.com", lines=LINES) is None


def test_generic_and_unoffered_model_names() -> None:
    page = "SEC-bench Pro | 1 | GPT-5 Pro | 82.0% | 2 | Gemini 4 Pro | 70.0%"
    kw = {"effort": None, "bench": "sec_bench_pro", "host": "sec-bench.github.io", "lines": ["gemini-4-pro"]}
    assert me.verify_score(page, line="gemini-4-pro", value=82.0, **kw) == "MODEL_NOT_NEAREST"
    assert me.verify_score(page, line="gemini-4-pro", value=70.0, **kw) is None
    board = "SEC-bench Pro | 1, Gemini 4 Neon, 55.0% | 2, Gemini 4 Argon, 72.0%"  # Argon not on this account
    assert me.verify_score(board, line="gemini-4-neon", effort=None, bench="sec_bench_pro", value=72.0,
                           host="sec-bench.github.io", lines=["gemini-4-neon"]) == "MODEL_NOT_NEAREST"


def test_leaderboard_site_must_name_the_benchmark() -> None:
    other = "Blog | Gemini 4 Neon reaches 95% on SWE-bench"
    assert me.verify_score(other, line="gemini-4-neon", effort=None, bench="realvuln", value=95,
                           host="kolega.dev", lines=LINES) == "BENCHMARK_NOT_NEAREST"


def test_a_transient_probe_error_does_not_evict_the_incumbent(db: Path) -> None:
    _all(db)
    with connect(db) as conn:
        conn.execute("UPDATE model_probe_runs SET status='ERROR' WHERE model_slug='gemini-4-argon-high'")
        conn.commit()
    assert rp.build_evidence_proposal(db) is None


def test_a_number_the_cited_page_cannot_confirm_is_checked_on_the_canonical_page() -> None:
    pages = {"https://artificialanalysis.ai/models/gemini-4-hydrogen": AA_PAGE}
    payload = {"scores": [{"model_line": "gemini-4-hydrogen", "effort": "high", "value": 51,
                           "benchmark": "Artificial Analysis Intelligence Index",
                           "source_url": "https://artificialanalysis.ai/leaderboards/models?x=1"},
                          {"model_line": "gemini-4-hydrogen", "effort": "medium", "value": 45,  # not published
                           "benchmark": "Artificial Analysis Intelligence Index",
                           "source_url": "https://artificialanalysis.ai/leaderboards/models?x=1"}]}
    accepted, rejected, _ = me.sanitize_and_verify(payload, TARGETS, fetch=pages.get)
    assert [(a["effort"], a["value"], a["source_url"]) for a in accepted] == [
        ("high", 51.0, "https://artificialanalysis.ai/models/gemini-4-hydrogen")]
    assert rejected[0]["reason"] == "SOURCE_NOT_FETCHABLE"

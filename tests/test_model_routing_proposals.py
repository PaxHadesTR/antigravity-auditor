"""Phase 4 of dynamic model routing: DB-backed active table, evidence-based proposals, human approval."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

CORE = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE))

import model_catalog as cat  # noqa: E402
import model_probes as mp  # noqa: E402
import model_routing_proposals as rp  # noqa: E402
from db import connect, initialize  # noqa: E402
from mcp_server import TOOL_DEFINITIONS  # noqa: E402
from model_policy import ModelRoutingRequest, route_model  # noqa: E402
from model_registry import RoutingTableError, get_active_routing_table, is_approved_model  # noqa: E402

FULL = {
    "gemini-4-argon-medium": "Gemini 4 Argon (Medium)",
    "gemini-4-argon-high": "Gemini 4 Argon (High)",
    "gemini-4-hydrogen-medium": "Gemini 4 Hydrogen (Medium)",
    "gemini-4-hydrogen-high": "Gemini 4 Hydrogen (High)",
    "gemini-4-hydrogen-xhigh": "Gemini 4 Hydrogen (XHigh)",
    "gemini-4-hydrogen-low": "Gemini 4 Hydrogen (Low)",
    "gemini-3.8-flash-high": "Gemini 3.8 Flash (High)",
}


def _listing(without: tuple[str, ...] = ()) -> str:
    return "".join(f"{s}\t{d}\n" for s, d in FULL.items() if s not in without)


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    path = tmp_path / "home" / "database" / "auditor.db"
    initialize(path)
    cat.sync_catalog(path, listing=_listing())
    return path


def _probe(db: Path, slug: str, status: str = "PASSED", latency: float = 20.0, sha: str | None = None) -> None:
    metrics = {"suite_sha256": sha or mp.suite_sha256(), "latency_seconds": latency, "total_tokens": 1000, "score": 1.0}
    mp._store(db, {
        "probe_run_id": f"PROBE-{slug}-{uuid.uuid4().hex[:8]}", "backend": "agy", "model_slug": slug,
        "suite_version": mp.SUITE_VERSION, "catalog_snapshot_id": None, "status": status, "score": 1.0,
        "metrics_json": json.dumps(metrics), "conversation_id": None, "attestation_status": "RUNTIME_ATTESTED",
        "error": None, "started_at": "t", "finished_at": "t",
    })


def _research(db: Path, line_tiers: dict[str, str], status: str = "COMPLETED") -> None:
    report = {"lines": [{"model_line": l, "tier_suggestion": t, "capability_rank": None, "self_assessed": False}
                        for l, t in line_tiers.items()], "rank_tier_consistency": "UNDETERMINED"}
    with connect(db) as conn:
        conn.execute(
            """INSERT INTO model_research_reports(report_id, backend, researcher_model, target_lines_json, status,
                   report_json, web_tool_calls, created_at) VALUES(?, 'agy', 'gemini-4-hydrogen-high', '{}', ?, ?, 5, 't')""",
            (f"R-{uuid.uuid4().hex[:8]}", status, json.dumps(report)),
        )
        conn.commit()


def _active_row(db: Path, assignments: dict[str, str], version: str = "RT-test") -> None:
    with connect(db) as conn:
        conn.execute(
            """INSERT INTO routing_table_versions(version_id, host, status, assignments_json, created_at, decided_at, decided_by)
               VALUES(?, 'antigravity', 'ACTIVE', ?, 't', 't', 'tester')""",
            (version, json.dumps(assignments)),
        )
        conn.commit()


SEED = {"ENTRY": "agy:gemini-4-hydrogen-medium", "STANDARD": "agy:gemini-4-hydrogen-high",
        "CRITICAL": "agy:gemini-4-argon-medium", "CATASTROPHIC": "agy:gemini-4-argon-high"}


# --- store ------------------------------------------------------------------------------------------

def test_migration_010_enforces_single_active_and_proposed(db: Path) -> None:
    _active_row(db, SEED, "RT-1")
    with pytest.raises(sqlite3.IntegrityError):
        _active_row(db, SEED, "RT-2")


def test_seed_applies_without_approved_table(db: Path) -> None:
    t = get_active_routing_table(db_path=db)
    assert t.source == "SEED" and t.version == "seed-2026-11-15"


def test_approved_table_drives_routing_and_dispatch_approval(db: Path) -> None:
    _active_row(db, {**SEED, "STANDARD": "agy:gemini-4-hydrogen-xhigh"})
    t = get_active_routing_table(db_path=db)
    assert t.source == "APPROVED" and t.approved_by == "tester"
    assert route_model(ModelRoutingRequest(task_type="PRIMARY_AUDIT"), db_path=db).selected_model == "gemini-4-hydrogen-xhigh"
    assert is_approved_model("gemini-4-hydrogen-xhigh", db_path=db)
    assert not is_approved_model("gemini-4-hydrogen-high", db_path=db)


def test_invalid_approved_table_fails_closed_without_seed_fallback(db: Path) -> None:
    _active_row(db, {**SEED, "STANDARD": "agy:gemini-3.8-flash-high"})
    with pytest.raises(RoutingTableError):
        get_active_routing_table(db_path=db)
    d = route_model(ModelRoutingRequest(task_type="PRIMARY_AUDIT"), db_path=db)
    assert d.is_blocked and d.selected_model is None
    assert not is_approved_model("gemini-4-hydrogen-high", db_path=db)


def test_malformed_approved_row_fails_closed(db: Path) -> None:
    with connect(db) as conn:
        conn.execute("INSERT INTO routing_table_versions(version_id, host, status, assignments_json, created_at) "
                     "VALUES('RT-bad', 'antigravity', 'ACTIVE', '{\"NOPE\": 1}', 't')")
        conn.commit()
    with pytest.raises(RoutingTableError):
        get_active_routing_table(db_path=db)


# --- proposals --------------------------------------------------------------------------------------

def test_no_catalogue_means_no_evidence(tmp_path: Path) -> None:
    path = tmp_path / "x" / "auditor.db"
    initialize(path)
    assert rp.build_proposal(path)["status"] == "NO_EVIDENCE"


def test_consistent_evidence_changes_nothing(db: Path) -> None:
    for s in ("gemini-4-hydrogen-medium", "gemini-4-hydrogen-high"):
        _probe(db, s)
    _research(db, {"gemini-4-hydrogen": "STANDARD", "gemini-4-argon": "CRITICAL"})
    assert rp.create_proposal(db)["status"] == "NO_CHANGE"
    assert rp.pending_proposal(db) is None


def test_missing_incumbent_is_replaced_by_eligible_model(db: Path) -> None:
    _probe(db, "gemini-4-hydrogen-medium", latency=10)
    _probe(db, "gemini-4-hydrogen-xhigh", latency=50)
    _research(db, {"gemini-4-hydrogen": "STANDARD", "gemini-4-argon": "CRITICAL"})
    cat.sync_catalog(db, listing=_listing(without=("gemini-4-hydrogen-high",)))
    r = rp.create_proposal(db)
    assert r["status"] == "PROPOSAL" and r["assignments"]["STANDARD"] == "agy:gemini-4-hydrogen-medium"
    changed = [x for x in r["rationale"] if x["changed"]]
    assert [c["tier"] for c in changed] == ["STANDARD"] and "Incumbent unavailable" in changed[0]["reason"]


def test_unprobed_or_failed_models_are_not_eligible(db: Path) -> None:
    _probe(db, "gemini-4-hydrogen-medium", status="DEGRADED")
    _probe(db, "gemini-4-hydrogen-xhigh", sha="0" * 64)  # stale suite
    _research(db, {"gemini-4-hydrogen": "STANDARD"})
    cat.sync_catalog(db, listing=_listing(without=("gemini-4-hydrogen-high",)))
    r = rp.build_proposal(db)
    assert r["status"] == "UNRESOLVED" and "STANDARD" in [x["tier"] for x in r["rationale"] if x["to"] is None]


def test_research_reassignment_needs_an_eligible_candidate(db: Path) -> None:
    _research(db, {"gemini-4-hydrogen": "ENTRY", "gemini-4-argon": "STANDARD"})
    assert rp.build_proposal(db)["status"] == "NO_CHANGE"  # nothing probed -> nothing eligible
    _probe(db, "gemini-4-argon-high")
    r = rp.build_proposal(db)
    # Argon for STANDARD would put CRITICAL/CATASTROPHIC on the same line as STANDARD -> invalid table.
    assert r["status"] == "UNRESOLVED" and "different model line" in r["detail"]


def test_non_completed_research_is_ignored(db: Path) -> None:
    _probe(db, "gemini-4-argon-high")
    _research(db, {"gemini-4-hydrogen": "ENTRY", "gemini-4-argon": "STANDARD"}, status="NO_WEB_EVIDENCE")
    assert rp.build_proposal(db)["status"] == "NO_CHANGE"


def test_new_proposal_withdraws_older_pending(db: Path) -> None:
    _probe(db, "gemini-4-hydrogen-medium")
    _research(db, {"gemini-4-hydrogen": "STANDARD"})
    cat.sync_catalog(db, listing=_listing(without=("gemini-4-hydrogen-high",)))
    first = rp.create_proposal(db)["version_id"]
    second = rp.create_proposal(db)["version_id"]
    statuses = {h["version_id"]: h["status"] for h in rp.table_history(db)}
    assert statuses[first] == "WITHDRAWN" and statuses[second] == "PROPOSED"


# --- decisions --------------------------------------------------------------------------------------

def _make_proposal(db: Path) -> str:
    _probe(db, "gemini-4-hydrogen-medium")
    _research(db, {"gemini-4-hydrogen": "STANDARD"})
    cat.sync_catalog(db, listing=_listing(without=("gemini-4-hydrogen-high",)))
    return rp.create_proposal(db)["version_id"]


def test_approval_activates_supersedes_and_audits(db: Path) -> None:
    _active_row(db, SEED, "RT-old")
    cat.sync_catalog(db, listing=_listing())
    vid = _make_proposal(db)
    out = rp.approve_proposal(db, vid, decided_by="alice")
    assert out["previous_active"] == "RT-old"
    statuses = {h["version_id"]: h["status"] for h in rp.table_history(db)}
    assert statuses[vid] == "ACTIVE" and statuses["RT-old"] == "SUPERSEDED"
    assert get_active_routing_table(db_path=db).version == vid
    conn = sqlite3.connect(db)
    try:
        events = [r[0] for r in conn.execute("SELECT event_type FROM audit_events")]
    finally:
        conn.close()
    assert "ROUTING_TABLE_APPROVED" in events
    with pytest.raises(rp.ProposalError, match="not PROPOSED"):
        rp.approve_proposal(db, vid, decided_by="alice")


def test_approval_revalidates_against_current_catalogue(db: Path) -> None:
    vid = _make_proposal(db)
    cat.sync_catalog(db, listing=_listing(without=("gemini-4-hydrogen-high", "gemini-4-hydrogen-medium")))
    with pytest.raises(rp.ProposalError, match="no longer offered"):
        rp.approve_proposal(db, vid, decided_by="alice")
    assert rp.pending_proposal(db)["version_id"] == vid  # unchanged
    assert get_active_routing_table(db_path=db).source == "SEED"


def test_reject_and_revert(db: Path) -> None:
    vid = _make_proposal(db)
    assert rp.reject_proposal(db, vid, decided_by="alice")["status"] == "REJECTED"
    assert rp.pending_proposal(db) is None
    assert rp.revert_to_seed(db, decided_by="alice")["status"] == "ALREADY_SEED"
    vid2 = _make_proposal(db)
    rp.approve_proposal(db, vid2, decided_by="alice")
    assert rp.revert_to_seed(db, decided_by="alice")["status"] == "SEED"
    assert get_active_routing_table(db_path=db).source == "SEED"


def test_overview_shows_pending_proposal_and_no_mcp_approval_tool(db: Path) -> None:
    vid = _make_proposal(db)
    view = cat.catalog_overview(db)
    assert view["proposal"]["version_id"] == vid and view["proposal"]["changes"][0]["tier"] == "STANDARD"
    names = {t["name"] for t in TOOL_DEFINITIONS}
    assert not any("approve" in n or "proposal" in n or "routing_table" in n for n in names)


def test_cli_approval_refuses_non_interactive_use(db: Path) -> None:
    vid = _make_proposal(db)
    env = {**os.environ, "ANTIGRAVITY_AUDITOR_HOME": str(db.parent.parent), "ANTIGRAVITY_AUDITOR_DB": str(db)}
    proc = subprocess.run(
        [sys.executable, str(CORE / "cli.py"), "models", "proposal", "approve", vid],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=120,
    )
    assert proc.returncode == 3 and "interactive terminal" in proc.stdout + proc.stderr
    assert rp.pending_proposal(db)["version_id"] == vid
    assert get_active_routing_table(db_path=db).source == "SEED"


# --- regressions from the independent Argon review of Phase 4 ----------------------------------

def test_adapter_approval_uses_the_callers_store(db: Path, tmp_path: Path) -> None:
    from agy_adapter import AntigravityCliAdapter

    _active_row(db, {**SEED, "STANDARD": "agy:gemini-4-hydrogen-xhigh"})
    exe = tmp_path / "agy.exe"
    exe.write_bytes(b"")
    adapter = AntigravityCliAdapter(
        executable_override=str(exe),
        runner=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "boom"),
    )
    assert adapter.dispatch(prompt="p", model_id="gemini-4-hydrogen-xhigh", cwd=tmp_path, db_path=db).status != "INVALID_MODEL"
    assert adapter.dispatch(prompt="p", model_id="gemini-4-hydrogen-high", cwd=tmp_path, db_path=db).status == "INVALID_MODEL"
    blocked = adapter.start_new_conversation("p", model_id="gemini-4-hydrogen-high", db_path=db)
    assert blocked.status == "INVALID_MODEL"


def test_approval_rechecks_probes_at_decision_time(db: Path) -> None:
    # Only hydrogen-xhigh (not in the active table) is probed, so it replaces the missing STANDARD model.
    _probe(db, "gemini-4-hydrogen-xhigh")
    _research(db, {"gemini-4-hydrogen": "STANDARD"})
    cat.sync_catalog(db, listing=_listing(without=("gemini-4-hydrogen-high",)))
    vid = rp.create_proposal(db)["version_id"]
    assert rp.pending_proposal(db)["assignments"]["STANDARD"] == "agy:gemini-4-hydrogen-xhigh"
    _probe(db, "gemini-4-hydrogen-xhigh", status="FAILED")  # newer, failing probe
    with pytest.raises(rp.ProposalError, match="PASSED probe"):
        rp.approve_proposal(db, vid, decided_by="alice")
    _probe(db, "gemini-4-hydrogen-xhigh", sha="1" * 64)  # passed, but on a different suite
    with pytest.raises(rp.ProposalError, match="PASSED probe"):
        rp.approve_proposal(db, vid, decided_by="alice")
    _probe(db, "gemini-4-hydrogen-xhigh")
    assert rp.approve_proposal(db, vid, decided_by="alice")["status"] == "ACTIVE"


def test_new_table_does_not_invalidate_in_flight_independence(db: Path) -> None:
    from verification import verify_cross_model_independence

    _active_row(db, {**SEED, "STANDARD": "agy:gemini-4-hydrogen-xhigh"})
    ok, _ = verify_cross_model_independence("gemini-4-hydrogen-high", "gemini-4-argon-medium", "RUNTIME_ATTESTED", db_path=db)
    assert ok  # hydrogen-high was approved (seed) when the audit ran
    ok, reason = verify_cross_model_independence("gemini-4-hydrogen-low", "gemini-4-argon-medium", "RUNTIME_ATTESTED", db_path=db)
    assert not ok and "not an approved model" in reason
    ok, _ = verify_cross_model_independence("gemini-3.8-flash-high", "gemini-4-argon-medium", "RUNTIME_ATTESTED", db_path=db)
    assert not ok


@pytest.mark.parametrize("payload", ["[]", "null", "42", '"x"'])
def test_non_object_assignments_fail_closed(db: Path, payload: str) -> None:
    with connect(db) as conn:
        conn.execute("INSERT INTO routing_table_versions(version_id, host, status, assignments_json, created_at) "
                     "VALUES('RT-bad', 'antigravity', 'ACTIVE', ?, 't')", (payload,))
        conn.commit()
    with pytest.raises(RoutingTableError):
        get_active_routing_table(db_path=db)
    assert route_model(ModelRoutingRequest(task_type="PRIMARY_AUDIT"), db_path=db).is_blocked


def test_corrupt_store_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "auditor.db"
    bad.write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(RoutingTableError):
        get_active_routing_table(db_path=bad)


@pytest.mark.parametrize("who", ["", "   ", None])
def test_blank_decider_is_rejected(db: Path, who: Any) -> None:
    vid = _make_proposal(db)
    with pytest.raises(rp.ProposalError):
        rp.reject_proposal(db, vid, decided_by=who)
    with pytest.raises(rp.ProposalError):
        rp.revert_to_seed(db, decided_by=who)
    with pytest.raises(rp.ProposalError):
        rp.approve_proposal(db, vid, decided_by=who)

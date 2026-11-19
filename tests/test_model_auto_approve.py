"""Opt-in automatic activation of routing-table proposals (PASSED probe + research support) and restore."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[1] / "core"
sys.path.insert(0, str(CORE))

import model_catalog as cat  # noqa: E402
import model_probes as mp  # noqa: E402
import model_routing_proposals as rp  # noqa: E402
from db import connect, initialize  # noqa: E402
from model_registry import get_active_routing_table  # noqa: E402

FULL = {
    "gemini-4-argon-medium": "Gemini 4 Argon (Medium)",
    "gemini-4-argon-high": "Gemini 4 Argon (High)",
    "gemini-4-hydrogen-medium": "Gemini 4 Hydrogen (Medium)",
    "gemini-4-hydrogen-high": "Gemini 4 Hydrogen (High)",
    "gemini-4-hydrogen-low": "Gemini 4 Hydrogen (Low)",
}
SEED = {"ENTRY": "agy:gemini-4-hydrogen-medium", "STANDARD": "agy:gemini-4-hydrogen-high",
        "CRITICAL": "agy:gemini-4-argon-medium", "CATASTROPHIC": "agy:gemini-4-argon-high"}


def _listing(without: tuple[str, ...] = ()) -> str:
    return "".join(f"{s}\t{d}\n" for s, d in FULL.items() if s not in without)


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    path = tmp_path / "home" / "database" / "auditor.db"
    initialize(path)
    cat.sync_catalog(path, listing=_listing())
    with connect(path) as conn:
        conn.execute(
            """INSERT INTO routing_table_versions(version_id, host, status, assignments_json, created_at, decided_at, decided_by)
               VALUES('RT-old', 'antigravity', 'ACTIVE', ?, 't', 't', 'tester')""", (json.dumps(SEED),))
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


def _research(db: Path, *, confidence: str = "HIGH", official: int = 2, self_assessed: bool = False,
              consistency: str = "CONSISTENT", tier: str = "STANDARD") -> None:
    report = {"lines": [{"model_line": "gemini-4-hydrogen", "tier_suggestion": tier, "capability_rank": None,
                         "confidence": confidence, "official_source_count": official, "self_assessed": self_assessed}],
              "rank_tier_consistency": consistency}
    with connect(db) as conn:
        conn.execute(
            """INSERT INTO model_research_reports(report_id, backend, researcher_model, target_lines_json, status,
                   report_json, web_tool_calls, created_at) VALUES(?, 'agy', 'gemini-4-argon-medium', '{}', 'COMPLETED', ?, 5, 't')""",
            (f"R-{uuid.uuid4().hex[:8]}", json.dumps(report)),
        )
        conn.commit()


def _proposal(db: Path, **research) -> dict:
    """STANDARD's incumbent (hydrogen-high) disappears; research places the hydrogen line in STANDARD."""
    _probe(db, "gemini-4-hydrogen-medium")
    _research(db, **research)
    cat.sync_catalog(db, listing=_listing(without=("gemini-4-hydrogen-high",)))
    out = rp.create_proposal(db)
    assert out["status"] == "PROPOSAL"
    return out


def _events(db: Path) -> list[str]:
    conn = sqlite3.connect(db)
    try:
        return [r[0] for r in conn.execute("SELECT event_type FROM audit_events ORDER BY rowid")]
    finally:
        conn.close()


def test_turned_off_leaves_proposal_for_user(db: Path) -> None:
    assert rp.auto_approve_enabled(db) is True  # on by default since 2026-11-19 (user decision)
    rp.set_auto_approve(db, False, decided_by="alice")
    prop = _proposal(db)
    assert rp.auto_approve_enabled(db) is False
    assert rp.maybe_auto_approve(db, prop) == {"status": "OFF"}
    assert rp.pending_proposal(db)["version_id"] == prop["version_id"]
    assert get_active_routing_table(db_path=db).version == "RT-old"


def test_enabled_and_all_gates_pass_activates(db: Path) -> None:
    rp.set_auto_approve(db, True, decided_by="alice")
    prop = _proposal(db)
    out = rp.maybe_auto_approve(db, prop)
    assert out["status"] == "APPROVED" and out["previous_active"] == "RT-old"
    active = get_active_routing_table(db_path=db)
    assert active.version == prop["version_id"] and active.approved_by == rp.AUTO_APPROVER
    assert "MODEL_AUTO_APPROVE_ENABLED" in _events(db) and "ROUTING_TABLE_APPROVED" in _events(db)
    summary = rp.auto_approval_summary(db)
    assert summary["enabled"] is True
    last = summary["last_auto_approval"]
    assert last["still_active"] and last["changes"][0]["tier"] == "STANDARD"
    assert last["undo_command"] == "python core/cli.py models restore RT-old"


@pytest.mark.parametrize("research, reason", [
    ({"confidence": "LOW"}, "confidence"),
    ({"official": 0}, "official source"),
    ({"self_assessed": True}, "its own model line"),
    ({"consistency": "INCONSISTENT"}, "contradicts itself"),
])
def test_weak_evidence_leaves_proposal_for_user(db: Path, research: dict, reason: str) -> None:
    rp.set_auto_approve(db, True, decided_by="alice")
    prop = _proposal(db, **research)
    out = rp.maybe_auto_approve(db, prop)
    assert out["status"] == "LEFT_FOR_USER" and any(reason in r for r in out["reasons"])
    assert rp.pending_proposal(db)["version_id"] == prop["version_id"]
    assert get_active_routing_table(db_path=db).version == "RT-old"
    assert "ROUTING_TABLE_AUTO_APPROVE_SKIPPED" in _events(db)


def test_change_without_research_tier_support_is_left_for_user(db: Path) -> None:
    rp.set_auto_approve(db, True, decided_by="alice")
    _probe(db, "gemini-4-hydrogen-medium")
    _research(db, tier="ENTRY")  # research does not place the hydrogen line in STANDARD
    cat.sync_catalog(db, listing=_listing(without=("gemini-4-hydrogen-high",)))
    prop = rp.create_proposal(db)
    assert prop["status"] == "PROPOSAL"  # same-line replacement of a vanished incumbent
    out = rp.maybe_auto_approve(db, prop)
    assert out["status"] == "LEFT_FOR_USER" and any("does not place" in r for r in out["reasons"])


def test_revalidation_failure_is_reported_not_raised(db: Path) -> None:
    rp.set_auto_approve(db, True, decided_by="alice")
    prop = _proposal(db)
    cat.sync_catalog(db, listing=_listing(without=("gemini-4-hydrogen-high", "gemini-4-hydrogen-medium")))
    out = rp.maybe_auto_approve(db, prop)
    assert out["status"] == "LEFT_FOR_USER" and any("no longer offered" in r for r in out["reasons"])


def test_corrupt_or_missing_setting_means_off(db: Path) -> None:
    path = db.parent.parent / "config" / rp.AUTO_APPROVE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    for content in ("not json", "[]", '{"enabled": "yes"}'):
        path.write_text(content, encoding="utf-8")
        assert rp.auto_approve_enabled(db) is False
    rp.set_auto_approve(db, False, decided_by="alice")
    assert rp.auto_approve_enabled(db) is False and "MODEL_AUTO_APPROVE_DISABLED" in _events(db)


def test_restore_undoes_an_automatic_approval(db: Path) -> None:
    rp.set_auto_approve(db, True, decided_by="alice")
    prop = _proposal(db)
    rp.maybe_auto_approve(db, prop)
    cat.sync_catalog(db, listing=_listing())  # the old STANDARD model is offered again
    out = rp.restore_version(db, "RT-old", decided_by="alice")
    active = get_active_routing_table(db_path=db)
    assert active.version == out["version_id"] and out["previous_active"] == prop["version_id"]
    assert {t.value: m for t, m in active.assignments.items()} == SEED
    assert "ROUTING_TABLE_RESTORED" in _events(db)
    assert rp.auto_approval_summary(db)["last_auto_approval"]["still_active"] is False


def test_restore_rejects_non_superseded_and_unavailable_tables(db: Path) -> None:
    with pytest.raises(rp.ProposalError, match="only a SUPERSEDED"):
        rp.restore_version(db, "RT-old", decided_by="alice")
    prop = _proposal(db)
    rp.approve_proposal(db, prop["version_id"], decided_by="alice")
    with pytest.raises(rp.ProposalError, match="no longer offered"):  # hydrogen-high is still missing
        rp.restore_version(db, "RT-old", decided_by="alice")
    assert get_active_routing_table(db_path=db).version == prop["version_id"]


def test_cli_toggle_needs_a_terminal_but_status_does_not(db: Path) -> None:
    env = {**os.environ, "ANTIGRAVITY_AUDITOR_HOME": str(db.parent.parent), "ANTIGRAVITY_AUDITOR_DB": str(db)}

    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(CORE / "cli.py"), "models", *args], stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, env=env, timeout=120)

    on = run("auto-approve", "on")
    assert on.returncode == 3 and "interactive terminal" in on.stdout + on.stderr
    assert not (db.parent.parent / "config" / rp.AUTO_APPROVE_FILE).exists()  # nothing written
    status = run("auto-approve", "status")
    assert status.returncode == 0 and json.loads(status.stdout)["enabled"] is True
    restore = run("restore", "RT-old")
    assert restore.returncode == 3


# --- manual proposals (e.g. after a benchmark) ------------------------------------------------------

def test_manual_proposal_changes_only_requested_tiers_and_needs_approval(db: Path) -> None:
    _probe(db, "gemini-4-argon-medium")
    out = rp.create_manual_proposal(db, {"catastrophic": "agy:gemini-4-argon-medium"}, note="bench: medium enough")
    assert out["changes"] == [{"tier": "CATASTROPHIC", "from": "agy:gemini-4-argon-high", "to": "agy:gemini-4-argon-medium"}]
    assert rp.pending_proposal(db)["version_id"] == out["version_id"]
    assert get_active_routing_table(db_path=db).version == "RT-old"  # not active until approved
    rp.set_auto_approve(db, True, decided_by="alice")
    stored = {"status": "PROPOSAL", "version_id": out["version_id"], "evidence": {"research_report_id": None},
              "rationale": [{"tier": "CATASTROPHIC", "to": "agy:gemini-4-argon-medium", "changed": True}]}
    assert rp.auto_approve_blockers(db, stored)  # automatic approval never applies without research support
    rp.approve_proposal(db, out["version_id"], decided_by="alice")
    assert get_active_routing_table(db_path=db).model_for(rp.RoutingTier.CATASTROPHIC) == "agy:gemini-4-argon-medium"


@pytest.mark.parametrize("changes, match", [
    ({"CATASTROPHIC": "agy:gemini-4-argon-low"}, "not eligible"),          # not offered
    ({"CATASTROPHIC": "agy:gemini-4-hydrogen-low"}, "not eligible"),       # offered, no probe
    ({"BOGUS": "agy:gemini-4-argon-medium"}, "Unknown tier"),
    ({"CATASTROPHIC": "agy:gemini-4-argon-high"}, "equals the active table"),
])
def test_manual_proposal_rejects_bad_input(db: Path, changes: dict, match: str) -> None:
    _probe(db, "gemini-4-argon-high")
    with pytest.raises(rp.ProposalError, match=match):
        rp.create_manual_proposal(db, changes, note="x")
    assert rp.pending_proposal(db) is None


def test_manual_proposal_keeps_critical_tiers_off_the_standard_line(db: Path) -> None:
    _probe(db, "gemini-4-hydrogen-high")
    with pytest.raises(rp.ProposalError, match="different model line"):
        rp.create_manual_proposal(db, {"CATASTROPHIC": "agy:gemini-4-hydrogen-high"}, note="x")
    with pytest.raises(rp.ProposalError, match="note"):
        rp.create_manual_proposal(db, {"CATASTROPHIC": "agy:gemini-4-argon-medium"}, note="  ")

"""Antigravity Auditor — evidence-based routing-table proposals with human approval (Phase 4).

Inputs (all read-only): the persisted backend catalogue, probe results (eligibility gate), the latest
COMPLETED web-research report (untrusted, used only for its per-line *tier suggestion*; capability ranks
are never used), the active routing table and host hard policy.

The engine is deliberately conservative. A tier's model changes only when

1. the incumbent is no longer dispatchable (missing from the catalogue or denied by policy) — it is
   replaced by an eligible model, preferring the research-suggested line for the tier, then the
   incumbent's own line; or
2. research suggests the incumbent's line for a *different* tier and an eligible model whose line is
   suggested for this tier exists.

Eligible = in the catalogue, allowed by hard policy and with a PASSED probe on the current suite. Ties are
broken by the tier's effort preference, then probe latency and tokens. Every proposal is validated with
``model_registry.validate_routing_table`` (including the different-line rule for critical tiers).

Proposals are stored as PROPOSED rows; a human activates one (``cli.py models proposal approve`` requires an
interactive terminal and a typed confirmation). Optionally, and only after the user turned it on in an
interactive terminal (``cli.py models auto-approve on``), a proposal whose every change passes the gates in
``auto_approve_blockers`` (PASSED probe + research support) is activated automatically; ``models restore``
undoes it. Approval re-validates against the current
catalogue and policy, supersedes the previous ACTIVE table atomically and is recorded in audit_events.
There is no MCP tool that approves, and nothing here ever dispatches a model.
"""

from __future__ import annotations

import json
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

from db import connect, record_event
from model_catalog import _read_one, latest_snapshot
from model_probes import latest_probe, suite_sha256
from model_registry import (
    BACKEND_AGY,
    SEED_ROUTING_TABLES,
    RoutingTable,
    RoutingTableError,
    RoutingTier,
    current_host_app,
    get_active_routing_table,
    hard_policy_violation,
    model_effort,
    model_line,
    model_slug,
    qualify_model,
    table_from_row,
    validate_routing_table,
)
from model_research import latest_research

PROPOSAL_ENGINE_VERSION = "1.0.0-conservative"

TIER_EFFORT_PREFERENCE: dict[RoutingTier, tuple[str, ...]] = {
    RoutingTier.ENTRY: ("medium", "low", "high"),
    RoutingTier.STANDARD: ("high", "medium", "xhigh"),
    RoutingTier.CRITICAL: ("medium", "high", "xhigh"),
    RoutingTier.CATASTROPHIC: ("high", "xhigh", "max", "ultra", "medium"),
}


class ProposalError(RuntimeError):
    """A proposal cannot be created, approved or rejected."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- evidence -----------------------------------------------------------------------------------------

def collect_evidence(db_path: Path, host_app: str | None = None) -> dict[str, Any]:
    host = host_app or current_host_app()
    snap = latest_snapshot(db_path, BACKEND_AGY)
    offered = [m["slug"] for m in json.loads(snap["models_json"])] if snap else []
    current_sha = suite_sha256()
    models: dict[str, dict[str, Any]] = {}
    for slug in offered:
        violation = hard_policy_violation(slug, host)
        probe = latest_probe(db_path, slug)
        metrics = json.loads(probe["metrics_json"] or "{}") if probe else {}
        eligible = (
            violation is None
            and probe is not None
            and probe["status"] == "PASSED"
            and metrics.get("suite_sha256") == current_sha
        )
        models[slug] = {
            "slug": slug,
            "line": model_line(slug),
            "effort": model_effort(slug),
            "policy_ok": violation is None,
            "probe_status": probe["status"] if probe else None,
            "probe_run_id": probe["probe_run_id"] if probe else None,
            "latency_seconds": metrics.get("latency_seconds"),
            "total_tokens": metrics.get("total_tokens"),
            "eligible": eligible,
        }
    research = latest_research(db_path)
    line_tiers: dict[str, str] = {}
    self_assessed: set[str] = set()
    if research and research["status"] == "COMPLETED":
        for line in research["report"].get("lines", []):
            if line.get("tier_suggestion") in RoutingTier.__members__:
                line_tiers[line["model_line"]] = line["tier_suggestion"]
            if line.get("self_assessed"):
                self_assessed.add(line["model_line"])
    return {
        "host": host,
        "catalog_snapshot_id": snap["snapshot_id"] if snap else None,
        "catalog_available": snap is not None,
        "models": models,
        "research_report_id": research["report_id"] if research and research["status"] == "COMPLETED" else None,
        "line_tiers": line_tiers,
        "self_assessed_lines": sorted(self_assessed),
        "suite_sha256": current_sha,
    }


def _rank_key(model: dict[str, Any], tier: RoutingTier) -> tuple[Any, ...]:
    prefs = TIER_EFFORT_PREFERENCE[tier]
    effort_rank = prefs.index(model["effort"]) if model["effort"] in prefs else len(prefs)
    return (
        effort_rank,
        model["latency_seconds"] if model["latency_seconds"] is not None else float("inf"),
        model["total_tokens"] if model["total_tokens"] is not None else float("inf"),
        model["slug"],
    )


def _best(candidates: list[dict[str, Any]], tier: RoutingTier) -> dict[str, Any] | None:
    return min(candidates, key=lambda m: _rank_key(m, tier)) if candidates else None


# --- proposal construction ----------------------------------------------------------------------------

def build_proposal(db_path: Path, host_app: str | None = None) -> dict[str, Any]:
    """Compute (but do not store) a proposal. Status: NO_CHANGE, PROPOSAL, UNRESOLVED or NO_EVIDENCE."""
    ev = collect_evidence(db_path, host_app)
    host = ev["host"]
    if not ev["catalog_available"]:
        return {"status": "NO_EVIDENCE", "host": host, "detail": "No catalogue snapshot; run `cli.py models sync`."}
    try:
        active = get_active_routing_table(host, db_path)
        base_note = None
    except RoutingTableError as exc:
        seed = SEED_ROUTING_TABLES.get(host)
        if seed is None:
            return {"status": "UNRESOLVED", "host": host, "detail": str(exc)}
        active, base_note = seed, f"Active table invalid ({exc}); proposing from the seed."

    models = ev["models"]
    eligible = [m for m in models.values() if m["eligible"]]
    line_tiers = ev["line_tiers"]
    assignments: dict[RoutingTier, str] = {}
    rationale: list[dict[str, Any]] = []

    for tier in RoutingTier:
        incumbent = model_slug(active.model_for(tier))
        inc = models.get(incumbent)
        inc_ok = inc is not None and inc["policy_ok"]
        suggested = [m for m in eligible if line_tiers.get(m["line"]) == tier.value]
        choice, reason = incumbent, "Incumbent kept."
        if not inc_ok:
            same_line = [m for m in eligible if m["line"] == model_line(incumbent)]
            best = _best(suggested, tier) or _best(same_line, tier)
            if best is None:
                choice, reason = None, ("Incumbent is no longer offered or allowed and no eligible replacement "
                                        "(PASSED probe) exists for this tier.")
            else:
                choice = best["slug"]
                reason = ("Incumbent unavailable; replaced by "
                          + ("the research-suggested line for this tier" if best in suggested else "the incumbent's own line")
                          + " (PASSED probe).")
        elif line_tiers.get(model_line(incumbent)) not in (None, tier.value) and suggested:
            best = _best(suggested, tier)
            choice = best["slug"]
            reason = (f"Research suggests the incumbent's line for {line_tiers[model_line(incumbent)]} and "
                      f"{best['line']} for {tier.value}; replacement has a PASSED probe.")
        rationale.append({
            "tier": tier.value,
            "from": qualify_model(incumbent),
            "to": qualify_model(choice) if choice else None,
            "changed": choice != incumbent,
            "reason": reason,
            "probe_run_id": models.get(choice, {}).get("probe_run_id") if choice else None,
            "research_tier_for_line": line_tiers.get(model_line(choice)) if choice else None,
            "research_self_assessed": bool(choice) and model_line(choice) in ev["self_assessed_lines"],
        })
        if choice:
            assignments[tier] = qualify_model(choice)

    evidence = {
        "catalog_snapshot_id": ev["catalog_snapshot_id"],
        "research_report_id": ev["research_report_id"],
        "suite_sha256": ev["suite_sha256"],
        "engine_version": PROPOSAL_ENGINE_VERSION,
        "base_version": active.version,
        "base_note": base_note,
    }
    if len(assignments) < len(RoutingTier):
        return {"status": "UNRESOLVED", "host": host, "rationale": rationale, "evidence": evidence,
                "detail": "At least one tier has no dispatchable model; probe more models or wait for the catalogue."}

    proposed = RoutingTable(host=host, version="proposal", source="PROPOSED", assignments=MappingProxyType(assignments))
    try:
        validate_routing_table(proposed)
    except RoutingTableError as exc:
        return {"status": "UNRESOLVED", "host": host, "rationale": rationale, "evidence": evidence, "detail": str(exc)}

    changed = any(r["changed"] for r in rationale) or base_note is not None
    return {
        "status": "PROPOSAL" if changed else "NO_CHANGE",
        "host": host,
        "assignments": {t.value: m for t, m in assignments.items()},
        "rationale": rationale,
        "evidence": evidence,
    }


def create_proposal(db_path: Path, host_app: str | None = None) -> dict[str, Any]:
    """Store a PROPOSED table if the evidence warrants a change; withdraws any older pending proposal."""
    result = build_proposal(db_path, host_app)
    if result["status"] != "PROPOSAL":
        return result
    version_id = f"RT-{result['host']}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    now = _utc_now()
    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "UPDATE routing_table_versions SET status='WITHDRAWN', decided_at=?, decision_note=? "
                "WHERE host=? AND status='PROPOSED'",
                (now, f"Superseded by newer proposal {version_id}.", result["host"]),
            )
            conn.execute(
                """INSERT INTO routing_table_versions(version_id, host, status, assignments_json, rationale_json,
                       evidence_json, base_version, created_at)
                   VALUES(?, ?, 'PROPOSED', ?, ?, ?, ?, ?)""",
                (version_id, result["host"], json.dumps(result["assignments"]), json.dumps(result["rationale"]),
                 json.dumps(result["evidence"]), result["evidence"]["base_version"], now),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return {**result, "version_id": version_id}


# --- decisions ----------------------------------------------------------------------------------------

def _app_home(db_path: Path) -> Path:
    """Install root for JSONL audit logs (database lives in <home>/database/auditor.db)."""
    return Path(db_path).resolve().parent.parent


def _get_version(conn: Any, version_id: str) -> Any:
    row = conn.execute("SELECT * FROM routing_table_versions WHERE version_id=?", (version_id,)).fetchone()
    if row is None:
        raise ProposalError(f"Unknown routing-table version '{version_id}'.")
    return row


def _check_dispatchable_now(conn: Any, table: RoutingTable, current_active: RoutingTable | None) -> None:
    """Re-validate at approval time, inside the approval transaction: hard policy + table rules, every model
    still offered by the latest catalogue, and every model that is not already in the active table backed
    by a PASSED probe on the current suite."""
    validate_routing_table(table)
    snap = conn.execute(
        "SELECT models_json FROM model_catalog_snapshots WHERE backend=? ORDER BY rowid DESC LIMIT 1", (BACKEND_AGY,)
    ).fetchone()
    if snap is None:
        raise ProposalError("No catalogue snapshot; cannot verify the proposal's models are offered.")
    offered = {m["slug"] for m in json.loads(snap["models_json"])}
    missing = sorted(model_slug(m) for m in table.assignments.values() if model_slug(m) not in offered)
    if missing:
        raise ProposalError(f"Models no longer offered by the backend: {missing}")
    incumbents = current_active.approved_models() if current_active else frozenset()
    current_sha = suite_sha256()
    for ref in sorted(set(table.assignments.values())):
        if qualify_model(ref) in incumbents:
            continue
        slug = model_slug(ref)
        row = conn.execute(
            "SELECT status, metrics_json FROM model_probe_runs WHERE backend=? AND model_slug=? ORDER BY rowid DESC LIMIT 1",
            (BACKEND_AGY, slug),
        ).fetchone()
        metrics = json.loads(row["metrics_json"] or "{}") if row else {}
        if row is None or row["status"] != "PASSED" or metrics.get("suite_sha256") != current_sha:
            raise ProposalError(f"Model '{slug}' no longer has a PASSED probe on the current suite.")


def _require_decider(decided_by: str | None) -> str:
    if not decided_by or not str(decided_by).strip():
        raise ProposalError("decided_by is required.")
    return str(decided_by).strip()[:128]


def approve_proposal(db_path: Path, version_id: str, *, decided_by: str, note: str | None = None) -> dict[str, Any]:
    """Activate a PROPOSED table after re-validating it against current policy and catalogue."""
    decided_by = _require_decider(decided_by)
    now = _utc_now()
    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = _get_version(conn, version_id)
            if row["status"] != "PROPOSED":
                raise ProposalError(f"Version {version_id} is {row['status']}, not PROPOSED.")
            active_row = conn.execute(
                "SELECT * FROM routing_table_versions WHERE host=? AND status='ACTIVE'", (row["host"],)
            ).fetchone()
            try:
                table = table_from_row({**dict(row), "status": "ACTIVE", "decided_by": decided_by, "decided_at": now})
                current_active = table_from_row(active_row) if active_row else SEED_ROUTING_TABLES.get(row["host"])
                _check_dispatchable_now(conn, table, current_active)
            except RoutingTableError as exc:
                raise ProposalError(str(exc)) from exc
            previous = conn.execute(
                "SELECT version_id FROM routing_table_versions WHERE host=? AND status='ACTIVE'", (row["host"],)
            ).fetchone()
            conn.execute(
                "UPDATE routing_table_versions SET status='SUPERSEDED', decision_note=? WHERE host=? AND status='ACTIVE'",
                (f"Superseded by {version_id}.", row["host"]),
            )
            conn.execute(
                "UPDATE routing_table_versions SET status='ACTIVE', decided_at=?, decided_by=?, decision_note=? WHERE version_id=?",
                (now, decided_by.strip()[:128], (note or "")[:500], version_id),
            )
            record_event(conn, app_home=_app_home(db_path), event_type="ROUTING_TABLE_APPROVED", details={
                "version_id": version_id, "host": row["host"], "decided_by": decided_by.strip()[:128],
                "previous_active": previous["version_id"] if previous else "SEED",
                "assignments": json.loads(row["assignments_json"]),
            })
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return {"version_id": version_id, "status": "ACTIVE", "previous_active": previous["version_id"] if previous else "SEED"}


def reject_proposal(db_path: Path, version_id: str, *, decided_by: str, note: str | None = None) -> dict[str, Any]:
    decided_by = _require_decider(decided_by)
    now = _utc_now()
    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = _get_version(conn, version_id)
            if row["status"] != "PROPOSED":
                raise ProposalError(f"Version {version_id} is {row['status']}, not PROPOSED.")
            conn.execute(
                "UPDATE routing_table_versions SET status='REJECTED', decided_at=?, decided_by=?, decision_note=? WHERE version_id=?",
                (now, decided_by.strip()[:128], (note or "")[:500], version_id),
            )
            record_event(conn, app_home=_app_home(db_path), event_type="ROUTING_TABLE_PROPOSAL_REJECTED", details={"version_id": version_id, "decided_by": decided_by.strip()[:128]})
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return {"version_id": version_id, "status": "REJECTED"}


def revert_to_seed(db_path: Path, *, decided_by: str, host_app: str | None = None) -> dict[str, Any]:
    """Deactivate the approved table so the validated seed applies again."""
    decided_by = _require_decider(decided_by)
    host = host_app or current_host_app()
    if host not in SEED_ROUTING_TABLES:
        raise ProposalError(f"No seed table for host '{host}'.")
    now = _utc_now()
    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT version_id FROM routing_table_versions WHERE host=? AND status='ACTIVE'", (host,)).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return {"status": "ALREADY_SEED", "host": host}
            conn.execute(
                "UPDATE routing_table_versions SET status='SUPERSEDED', decided_at=?, decision_note=? WHERE version_id=?",
                (now, f"Reverted to seed by {decided_by.strip()[:128]}.", row["version_id"]),
            )
            record_event(conn, app_home=_app_home(db_path), event_type="ROUTING_TABLE_REVERTED_TO_SEED", details={"previous_active": row["version_id"], "decided_by": decided_by.strip()[:128]})
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return {"status": "SEED", "host": host, "previous_active": row["version_id"]}


# --- opt-in automatic approval ------------------------------------------------------------------------
#
# Off by default. The user turns it on in an interactive terminal (`cli.py models auto-approve on`). When on,
# a proposal stored by `models sync --propose` / `models propose` is activated without a typed confirmation
# only if every changed tier passes all gates in ``auto_approve_blockers`` (PASSED probe on the current
# suite, research places the new model's line in exactly that tier with at least MEDIUM confidence and an
# official source, no self-assessment, a consistent research report, a valid active base table). Anything
# else stays PROPOSED for the user. ``restore_version`` undoes an approval in one interactive command.

AUTO_APPROVE_FILE = "model_auto_approve.json"
AUTO_APPROVER = "auto:probe+research"
AUTO_APPROVE_MIN_CONFIDENCE = ("MEDIUM", "HIGH")


def _auto_approve_path(db_path: Path) -> Path:
    return _app_home(db_path) / "config" / AUTO_APPROVE_FILE


def auto_approve_enabled(db_path: Path | None) -> bool:
    if db_path is None:
        return False
    try:
        data = json.loads(_auto_approve_path(Path(db_path)).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("enabled") is True


def set_auto_approve(db_path: Path, enabled: bool, *, decided_by: str) -> dict[str, Any]:
    """Turn automatic approval on or off (the CLI calls this only after an interactive confirmation)."""
    decided_by = _require_decider(decided_by)
    path = _auto_approve_path(Path(db_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {"enabled": bool(enabled), "updated_at": _utc_now(), "updated_by": decided_by}
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(path)
    with closing(connect(db_path)) as conn:
        record_event(conn, app_home=_app_home(db_path),
                     event_type="MODEL_AUTO_APPROVE_ENABLED" if enabled else "MODEL_AUTO_APPROVE_DISABLED",
                     details={"decided_by": decided_by})
        conn.commit()
    return state


def _research_report(db_path: Path, report_id: str | None) -> dict[str, Any] | None:
    if not report_id:
        return None
    row = _read_one(db_path, "SELECT status, report_json FROM model_research_reports WHERE report_id=?", (report_id,))
    if not row or row["status"] != "COMPLETED":
        return None
    try:
        report = json.loads(row["report_json"] or "{}")
    except ValueError:
        return None
    return report if isinstance(report, dict) else None


def auto_approve_blockers(db_path: Path, proposal: dict[str, Any]) -> list[str]:
    """Reasons a stored proposal must wait for the user. Empty means every gate passed."""
    if proposal.get("status") != "PROPOSAL" or not proposal.get("version_id"):
        return ["No stored proposal."]
    blockers: list[str] = []
    evidence = proposal.get("evidence") or {}
    if evidence.get("base_note"):
        blockers.append("The active table was invalid; a proposal built from the seed needs the user.")
    report = _research_report(db_path, evidence.get("research_report_id"))
    if report is None:
        return blockers + ["No COMPLETED research report backs this proposal."]
    if report.get("rank_tier_consistency") == "INCONSISTENT":
        blockers.append("The research report contradicts itself (rank vs tier).")
    lines = {str(item.get("model_line")): item for item in report.get("lines") or [] if isinstance(item, dict)}
    changed = [r for r in proposal.get("rationale") or [] if r.get("changed")]
    if not changed:
        blockers.append("The proposal changes no tier.")
    for r in changed:
        tier, target = r.get("tier"), r.get("to")
        if not target:
            blockers.append(f"{tier}: no model.")
            continue
        line = model_line(model_slug(target))
        info = lines.get(line) or {}
        if not r.get("probe_run_id"):
            blockers.append(f"{tier}: {target} has no PASSED probe.")
        if r.get("research_tier_for_line") != tier or info.get("tier_suggestion") != tier:
            blockers.append(f"{tier}: research does not place {line} in {tier}.")
        if r.get("research_self_assessed") or info.get("self_assessed"):
            blockers.append(f"{tier}: {line} was assessed by its own model line.")
        if info.get("confidence") not in AUTO_APPROVE_MIN_CONFIDENCE:
            blockers.append(f"{tier}: research confidence for {line} is {info.get('confidence') or 'missing'}.")
        if not info.get("official_source_count"):
            blockers.append(f"{tier}: research for {line} cites no official source.")
    return blockers


def maybe_auto_approve(db_path: Path, proposal: dict[str, Any]) -> dict[str, Any] | None:
    """Activate a freshly stored proposal when automatic approval is on and every gate passes. Never raises
    for a gate or re-validation failure: the proposal then simply stays PROPOSED for the user."""
    if proposal.get("status") != "PROPOSAL" or not proposal.get("version_id"):
        return None
    if not auto_approve_enabled(db_path):
        return {"status": "OFF"}
    version_id = proposal["version_id"]
    blockers = auto_approve_blockers(db_path, proposal)
    if not blockers:
        try:
            out = approve_proposal(db_path, version_id, decided_by=AUTO_APPROVER,
                                   note="Automatic approval: PASSED probes and research support every change.")
        except ProposalError as exc:
            blockers = [str(exc)]
        else:
            return {**out, "status": "APPROVED"}
    with closing(connect(db_path)) as conn:
        record_event(conn, app_home=_app_home(db_path), event_type="ROUTING_TABLE_AUTO_APPROVE_SKIPPED",
                     details={"version_id": version_id, "reasons": blockers[:10]})
        conn.commit()
    return {"status": "LEFT_FOR_USER", "version_id": version_id, "reasons": blockers}


def restore_version(db_path: Path, version_id: str, *, decided_by: str) -> dict[str, Any]:
    """Make an earlier (SUPERSEDED) table active again as a new version, e.g. to undo an automatic approval.
    Its models were approved before, so no new probe is required; catalogue and hard policy are re-checked."""
    decided_by = _require_decider(decided_by)
    now = _utc_now()
    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = _get_version(conn, version_id)
            if row["status"] != "SUPERSEDED":
                raise ProposalError(f"Version {version_id} is {row['status']}; only a SUPERSEDED table can be restored.")
            host = row["host"]
            new_id = f"RT-{host}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
            try:
                table = table_from_row({**dict(row), "version_id": new_id, "status": "ACTIVE",
                                        "decided_by": decided_by, "decided_at": now})
                _check_dispatchable_now(conn, table, table)
            except RoutingTableError as exc:
                raise ProposalError(str(exc)) from exc
            previous = conn.execute(
                "SELECT version_id FROM routing_table_versions WHERE host=? AND status='ACTIVE'", (host,)
            ).fetchone()
            conn.execute(
                "UPDATE routing_table_versions SET status='WITHDRAWN', decided_at=?, decision_note=? "
                "WHERE host=? AND status='PROPOSED'", (now, f"Withdrawn: {version_id} restored.", host),
            )
            conn.execute(
                "UPDATE routing_table_versions SET status='SUPERSEDED', decision_note=? WHERE host=? AND status='ACTIVE'",
                (f"Superseded by {new_id} (restore of {version_id}).", host),
            )
            conn.execute(
                """INSERT INTO routing_table_versions(version_id, host, status, assignments_json, rationale_json,
                       evidence_json, base_version, created_at, decided_at, decided_by, decision_note)
                   VALUES(?, ?, 'ACTIVE', ?, ?, '{}', ?, ?, ?, ?, ?)""",
                (new_id, host, row["assignments_json"], json.dumps([{"restored_from": version_id}]),
                 previous["version_id"] if previous else None, now, now, decided_by, f"Restore of {version_id}."),
            )
            record_event(conn, app_home=_app_home(db_path), event_type="ROUTING_TABLE_RESTORED", details={
                "version_id": new_id, "restored_from": version_id, "host": host, "decided_by": decided_by,
                "previous_active": previous["version_id"] if previous else "SEED",
            })
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return {"version_id": new_id, "status": "ACTIVE", "restored_from": version_id,
            "previous_active": previous["version_id"] if previous else "SEED"}


def auto_approval_summary(db_path: Path | None, host_app: str | None = None) -> dict[str, Any]:
    """Read-only: whether automatic approval is on, and the most recent automatic approval with how to undo it."""
    host = host_app or current_host_app()
    row = _read_one(db_path, "SELECT version_id, status, rationale_json, base_version, decided_at "
                    "FROM routing_table_versions WHERE host=? AND decided_by=? ORDER BY rowid DESC LIMIT 1",
                    (host, AUTO_APPROVER))
    last = None
    if row:
        try:
            rationale = json.loads(row["rationale_json"] or "[]")
        except ValueError:
            rationale = []
        base = row["base_version"]
        restorable = bool(base) and _read_one(
            db_path, "SELECT 1 AS ok FROM routing_table_versions WHERE version_id=?", (base,)) is not None
        last = {
            "version_id": row["version_id"],
            "still_active": row["status"] == "ACTIVE",
            "decided_at": row["decided_at"],
            "changes": [{k: r.get(k) for k in ("tier", "from", "to")} for r in rationale if r.get("changed")],
            "undo_command": (f"python core/cli.py models restore {base}" if restorable
                             else "python core/cli.py models revert-to-seed"),
        }
    return {"enabled": auto_approve_enabled(db_path), "last_auto_approval": last}


# --- read-only views ----------------------------------------------------------------------------------

def pending_proposal(db_path: Path | None, host_app: str | None = None) -> dict[str, Any] | None:
    host = host_app or current_host_app()
    row = _read_one(db_path, "SELECT * FROM routing_table_versions WHERE host=? AND status='PROPOSED' ORDER BY rowid DESC LIMIT 1", (host,))
    if not row:
        return None
    rationale = json.loads(row["rationale_json"] or "[]")
    return {
        "version_id": row["version_id"],
        "created_at": row["created_at"],
        "base_version": row["base_version"],
        "assignments": json.loads(row["assignments_json"]),
        "changes": [{k: r.get(k) for k in ("tier", "from", "to")} for r in rationale if r.get("changed")],
        "approval": "Human: `python core/cli.py models proposal approve <version_id>` in an interactive terminal.",
    }


def table_history(db_path: Path | None, host_app: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    host = host_app or current_host_app()
    path = Path(db_path) if db_path else None
    if path is None or not path.is_file():
        return []
    import sqlite3

    try:
        with closing(sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True, timeout=30)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT version_id, status, assignments_json, created_at, decided_at, decided_by, decision_note "
                "FROM routing_table_versions WHERE host=? ORDER BY rowid DESC LIMIT ?",
                (host, limit),
            ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [{**dict(r), "assignments": json.loads(r["assignments_json"])} for r in rows]

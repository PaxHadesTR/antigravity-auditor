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


# --- measured engine (tier measurements decide; research is only the fallback) -------------------------

MEASURED_ENGINE_VERSION = "2.0.0-measured"
TIER_KIND = {RoutingTier.ENTRY: "find", RoutingTier.STANDARD: "find",
             RoutingTier.CRITICAL: "verify", RoutingTier.CATASTROPHIC: "verify"}
# Accuracy a model may lose against the best measured model of the tier and still count as "as good".
TIER_TOLERANCE = {RoutingTier.ENTRY: 0.10, RoutingTier.STANDARD: 0.05,
                  RoutingTier.CRITICAL: 0.03, RoutingTier.CATASTROPHIC: 0.0}
# Relative call volume per tier (multi-pass primary audits dominate), used to weigh tokens per call.
TIER_TOKEN_WEIGHT = {RoutingTier.ENTRY: 1.0, RoutingTier.STANDARD: 4.0,
                     RoutingTier.CRITICAL: 1.0, RoutingTier.CATASTROPHIC: 0.5}
TIER_PRIORITY = (RoutingTier.CATASTROPHIC, RoutingTier.CRITICAL, RoutingTier.STANDARD, RoutingTier.ENTRY)
KEEP_INCUMBENT_MARGIN = 0.10  # keep the active table unless the best table saves more than 10 % weighted tokens
# Absolute floor for automatic activation: below it a measured change waits for the user, however it ranks.
AUTO_MIN_ACCURACY = {RoutingTier.ENTRY: 0.60, RoutingTier.STANDARD: 0.75,
                     RoutingTier.CRITICAL: 0.85, RoutingTier.CATASTROPHIC: 0.90}


def _accuracy(meas: dict[str, Any], tier: RoutingTier) -> float:
    value = meas.get(f"{TIER_KIND[tier]}_accuracy")
    return float(value) if value is not None else 0.0


_RESEARCH_TIER_RANK = {"ENTRY": 1, "STANDARD": 2, "CRITICAL": 3, "CATASTROPHIC": 4}
_EFFORT_RANK = {"low": 1, "medium": 2, "high": 3, "xhigh": 4, "max": 5, "ultra": 6}


def _capability_prior(slug: str, line_tiers: dict[str, str], *, with_effort: bool) -> tuple[int, int]:
    """Tie-break for the critical tiers when the measurements cannot separate models (a saturated benchmark): the
    tier research places the model line in, then (CATASTROPHIC only) the effort level. Never outranks accuracy,
    and comes before tokens: for critical verification, equal measured accuracy is no reason to pick the cheapest."""
    line_rank = _RESEARCH_TIER_RANK.get(line_tiers.get(model_line(slug), ""), 0)
    return (line_rank, _EFFORT_RANK.get(model_effort(slug) or "", 0) if with_effort else 0)


def _table_key(combo: dict[RoutingTier, str], meas: dict[str, dict[str, Any]],
               best: dict[RoutingTier, float], line_tiers: dict[str, str] | None = None) -> tuple[Any, ...]:
    out_of_band = tuple(_accuracy(meas[combo[t]], t) < best[t] - TIER_TOLERANCE[t] - 1e-9 for t in TIER_PRIORITY)
    lost = tuple(round(best[t] - _accuracy(meas[combo[t]], t), 4) if oob else 0.0
                 for t, oob in zip(TIER_PRIORITY, out_of_band))
    lt = line_tiers or {}
    cat = _capability_prior(combo[RoutingTier.CATASTROPHIC], lt, with_effort=True)
    crit = _capability_prior(combo[RoutingTier.CRITICAL], lt, with_effort=False)
    prior = (-cat[0], -cat[1], -crit[0])
    tokens = sum(TIER_TOKEN_WEIGHT[t] * float(meas[combo[t]].get("tokens_per_call") or 0) for t in RoutingTier)
    latency = sum(TIER_TOKEN_WEIGHT[t] * float(meas[combo[t]].get("latency_per_call") or 0) for t in RoutingTier)
    return (out_of_band, lost, prior, round(tokens, 1), round(latency, 1), tuple(combo[t] for t in TIER_PRIORITY))


def _valid_combo(combo: dict[RoutingTier, str]) -> bool:
    from model_registry import same_model_line

    std = combo[RoutingTier.STANDARD]
    return not any(same_model_line(combo[t], std) for t in (RoutingTier.CRITICAL, RoutingTier.CATASTROPHIC))


def build_measured_proposal(db_path: Path, host_app: str | None = None) -> dict[str, Any] | None:
    """Choose the table from tier measurements. Returns None when the measurements are not sufficient yet (an
    incumbent that is still offered has no complete measurement, or no valid table can be formed)."""
    import itertools

    from model_benchmarks import bench_sha256, measurements

    ev = collect_evidence(db_path, host_app)
    host = ev["host"]
    if not ev["catalog_available"]:
        return None
    try:
        active = get_active_routing_table(host, db_path)
    except RoutingTableError:
        return None
    all_meas = measurements(db_path)
    meas = {slug: m for slug, m in all_meas.items()
            if m["complete"] and ev["models"].get(slug, {}).get("eligible")}
    if not meas:
        return None
    incumbents = {t: model_slug(active.model_for(t)) for t in RoutingTier}
    for slug in set(incumbents.values()):
        if ev["models"].get(slug, {}).get("eligible") and slug not in meas:
            return None  # an incumbent that still works must be measured before it can be compared
    best = {t: max(_accuracy(m, t) for m in meas.values()) for t in RoutingTier}
    slugs = sorted(meas)
    best_combo, best_key = None, None
    for picks in itertools.product(slugs, repeat=len(RoutingTier)):
        combo = dict(zip(RoutingTier, picks))
        if not _valid_combo(combo):
            continue
        key = _table_key(combo, meas, best, ev["line_tiers"])
        if best_key is None or key < best_key:
            best_combo, best_key = combo, key
    if best_combo is None:
        return None
    reason_kept = None
    if all(s in meas for s in incumbents.values()) and _valid_combo(incumbents):
        inc_key = _table_key(incumbents, meas, best, ev["line_tiers"])
        if inc_key[:3] == best_key[:3] and inc_key[3] <= best_key[3] * (1 + KEEP_INCUMBENT_MARGIN):
            best_combo, reason_kept = incumbents, "Active table is within the measurement margin of the best table."
    sha = bench_sha256()
    rationale = []
    for tier in RoutingTier:
        before, after = incumbents[tier], best_combo[tier]
        m = meas[after]
        changed = before != after
        rationale.append({
            "tier": tier.value, "from": qualify_model(before), "to": qualify_model(after), "changed": changed,
            "reason": (f"Measured {TIER_KIND[tier]} accuracy {_accuracy(m, tier):.3f} (best {best[tier]:.3f}), "
                       f"{int(m.get('tokens_per_call') or 0)} tokens/call"
                       + (f"; ties broken by the research tier of the line ({ev['line_tiers'].get(model_line(after), 'none')})"
                          if tier in (RoutingTier.CRITICAL, RoutingTier.CATASTROPHIC) else "")
                       if changed else (reason_kept or "Incumbent kept.")),
            "probe_run_id": ev["models"].get(after, {}).get("probe_run_id"),
            "measured": True, "bench_sha256": sha,
            "accuracy": _accuracy(m, tier), "best_accuracy": best[tier],
            "tokens_per_call": m.get("tokens_per_call"),
            "incumbent_accuracy": _accuracy(all_meas[before], tier) if all_meas.get(before, {}).get("complete") else None,
            "incumbent_tokens_per_call": (all_meas[before].get("tokens_per_call")
                                          if all_meas.get(before, {}).get("complete") else None),
            "research_tier_for_line": None, "research_self_assessed": False,
        })
    assignments = {t: qualify_model(best_combo[t]) for t in RoutingTier}
    table = RoutingTable(host=host, version="proposal", source="PROPOSED", assignments=MappingProxyType(assignments))
    try:
        validate_routing_table(table)
    except RoutingTableError:
        return None
    changed = any(r["changed"] for r in rationale)
    return {
        "status": "PROPOSAL" if changed else "NO_CHANGE",
        "host": host,
        "assignments": {t.value: m for t, m in assignments.items()},
        "rationale": rationale,
        "evidence": {
            "engine": "measured", "engine_version": MEASURED_ENGINE_VERSION, "bench_sha256": sha,
            "catalog_snapshot_id": ev["catalog_snapshot_id"], "suite_sha256": ev["suite_sha256"],
            "research_report_id": ev["research_report_id"], "base_version": active.version, "base_note": None,
            "measurements": {s: {k: meas[s].get(k) for k in ("find_accuracy", "verify_accuracy", "tokens_per_call",
                                                            "latency_per_call", "measured_at")} for s in slugs},
        },
    }


# --- proposal construction ----------------------------------------------------------------------------

def build_proposal(db_path: Path, host_app: str | None = None) -> dict[str, Any]:
    """Compute (but do not store) a proposal. Status: NO_CHANGE, PROPOSAL, UNRESOLVED or NO_EVIDENCE.
    Tier measurements decide when they are sufficient; otherwise the conservative research-based engine runs."""
    measured = build_measured_proposal(db_path, host_app)
    if measured is not None:
        return measured
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


def create_manual_proposal(db_path: Path, changes: dict[str, str], *, note: str,
                           host_app: str | None = None) -> dict[str, Any]:
    """Store a PROPOSED table that changes the given tiers of the active table (e.g. after a benchmark). Every new
    model must be offered, allowed and have a PASSED probe on the current suite; the table must validate.
    Activation still needs ``models proposal approve`` (automatic approval never applies to manual proposals)."""
    note = str(note or "").strip()[:500]
    if not note:
        raise ProposalError("A manual proposal needs a note (the evidence for the change).")
    if not changes:
        raise ProposalError("No tier changes given.")
    ev = collect_evidence(db_path, host_app)
    host = ev["host"]
    try:
        active = get_active_routing_table(host, db_path)
    except RoutingTableError as exc:
        raise ProposalError(f"Active table is invalid ({exc}); fix or revert it first.") from exc
    assignments = dict(active.assignments)
    rationale: list[dict[str, Any]] = []
    for tier_name, ref in changes.items():
        try:
            tier = RoutingTier[str(tier_name).strip().upper()]
        except KeyError as exc:
            raise ProposalError(f"Unknown tier '{tier_name}'.") from exc
        slug = model_slug(qualify_model(str(ref).strip()))
        info = ev["models"].get(slug)
        if info is None or not info["eligible"]:
            raise ProposalError(f"{slug} is not eligible (not offered, not allowed, or no PASSED probe on the "
                                "current suite).")
        assignments[tier] = qualify_model(slug)
    for tier in RoutingTier:
        before, after = active.model_for(tier), assignments[tier]
        rationale.append({
            "tier": tier.value, "from": qualify_model(before), "to": qualify_model(after),
            "changed": model_slug(before) != model_slug(after),
            "reason": f"Manual proposal: {note}" if model_slug(before) != model_slug(after) else "Incumbent kept.",
            "probe_run_id": ev["models"].get(model_slug(after), {}).get("probe_run_id"),
            "research_tier_for_line": None, "research_self_assessed": False,
        })
    if not any(r["changed"] for r in rationale):
        raise ProposalError("The requested table equals the active table.")
    table = RoutingTable(host=host, version="proposal", source="PROPOSED", assignments=MappingProxyType(assignments))
    try:
        validate_routing_table(table)
    except RoutingTableError as exc:
        raise ProposalError(str(exc)) from exc
    version_id = f"RT-{host}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    now = _utc_now()
    evidence = {"manual": True, "note": note, "catalog_snapshot_id": ev["catalog_snapshot_id"],
                "suite_sha256": ev["suite_sha256"], "engine_version": PROPOSAL_ENGINE_VERSION,
                "base_version": active.version, "base_note": None}
    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "UPDATE routing_table_versions SET status='WITHDRAWN', decided_at=?, decision_note=? "
                "WHERE host=? AND status='PROPOSED'",
                (now, f"Superseded by manual proposal {version_id}.", host),
            )
            conn.execute(
                """INSERT INTO routing_table_versions(version_id, host, status, assignments_json, rationale_json,
                       evidence_json, base_version, created_at)
                   VALUES(?, ?, 'PROPOSED', ?, ?, ?, ?, ?)""",
                (version_id, host, json.dumps({t.value: m for t, m in assignments.items()}), json.dumps(rationale),
                 json.dumps(evidence), active.version, now),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return {"status": "PROPOSAL", "version_id": version_id, "host": host,
            "assignments": {t.value: m for t, m in assignments.items()},
            "changes": [{k: r[k] for k in ("tier", "from", "to")} for r in rationale if r["changed"]]}


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
    """On by default (the user decided the table should follow the measurements by itself); an explicit
    ``models auto-approve off`` turns it off. An unreadable setting file counts as off (fail closed)."""
    if db_path is None:
        return False
    path = _auto_approve_path(Path(db_path))
    if not path.exists():
        return True
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
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
    if evidence.get("engine") == "measured":
        from model_benchmarks import bench_sha256

        changed = [r for r in proposal.get("rationale") or [] if r.get("changed")]
        if not changed:
            blockers.append("The proposal changes no tier.")
        sha = bench_sha256()
        for r in changed:
            if not r.get("measured") or r.get("bench_sha256") != sha or evidence.get("bench_sha256") != sha:
                blockers.append(f"{r.get('tier')}: no measurement on the current benchmark.")
            if not r.get("probe_run_id"):
                blockers.append(f"{r.get('tier')}: {r.get('to')} has no PASSED probe.")
            if r.get("tier") not in RoutingTier.__members__ or r.get("accuracy") is None:
                blockers.append(f"{r.get('tier')}: no measured accuracy.")
                continue
            tier = RoutingTier[r["tier"]]
            tol, acc = TIER_TOLERANCE[tier], float(r["accuracy"])
            inc, best = r.get("incumbent_accuracy"), r.get("best_accuracy")
            if acc < AUTO_MIN_ACCURACY[tier]:
                blockers.append(f"{tier.value}: measured accuracy {acc:.2f} is below the automatic floor "
                                f"{AUTO_MIN_ACCURACY[tier]:.2f}.")
            if best is not None and acc < float(best) - tol - 1e-9:
                blockers.append(f"{tier.value}: the new model is not among the most accurate measured models.")
            if inc is not None and acc < float(inc) - tol - 1e-9:
                blockers.append(f"{tier.value}: the new model measured clearly less accurate than the current one.")
        return blockers
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

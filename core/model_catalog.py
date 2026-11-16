"""Antigravity Auditor — dispatch-backend model catalogue (Phase 1 of dynamic model routing).

* ``sync_catalog`` runs the backend's model listing (``agy models``), normalises it, compares it with
  the last persisted snapshot and records a new snapshot only when the list changed. Every check
  updates ``model_catalog_state`` (INITIAL / UNCHANGED / CHANGED / ERROR).
* ``routing_table_health`` reports whether every tier model of the active routing table is still
  offered by the backend and allowed by hard policy (HEALTHY / STALE / UNKNOWN / INVALID).
* ``catalog_overview`` is the read-only view used by ``cli.py models overview`` and the
  ``auditor_models_overview`` MCP tool. It never runs a backend CLI and never writes.

The catalogue is evidence for later phases (probe triggering, research, routing proposals). It never
widens what may be dispatched: dispatchability stays with ``model_registry`` hard policy + the
active routing table.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import subprocess
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from db import connect
from model_registry import (
    BACKEND_AGY,
    ModelRefError,
    RoutingTableError,
    RoutingTier,
    agy_executable,
    current_host_app,
    discover_dispatch_backends,
    get_active_routing_table,
    hard_policy_violation,
    model_effort,
    model_family,
    model_line,
    model_slug,
    qualify_model,
)

CATALOG_VERSION = "1.0.0-model-catalog"
DEFAULT_TIMEOUT_SECONDS = 90
MAX_CATALOG_ENTRIES = 500

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


@dataclass(frozen=True)
class CatalogEntry:
    slug: str
    display_name: str

    def to_dict(self) -> dict[str, str]:
        return {"slug": self.slug, "display_name": self.display_name}


class CatalogError(RuntimeError):
    """Backend listing failed or produced unusable output."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# A listing row is exactly "<lowercase slug>\t<display name>"; the slug must look like a model id
# (letters/digits/dots, hyphen-separated, at least one hyphen) of a known model family.
_LISTING_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9.]*(?:-[a-z0-9.]+)+$")


def parse_agy_models_listing(stdout: str) -> list[CatalogEntry]:
    """Parse ``agy models`` output (``<slug>\\t<display name>`` per line).

    Strict: rows without a tab, without a display name, with a non-lowercase / prefixed slug or an
    unknown model family are ignored, so banners such as "No models available" can never become
    catalogue entries. Output is sorted and de-duplicated so the catalogue hash is deterministic.
    """
    entries: dict[str, CatalogEntry] = {}
    for raw in (stdout or "").splitlines():
        if "\t" not in raw:
            continue
        slug_part, _, display = raw.strip().partition("\t")
        slug_part = slug_part.strip()
        display = " ".join(display.split())[:120]
        if not display or not _LISTING_SLUG_RE.match(slug_part):
            continue
        try:
            slug = model_slug(slug_part)
        except ModelRefError:
            continue
        if model_family(slug) == "unknown":
            continue
        entries[slug] = CatalogEntry(slug=slug, display_name=display)
        if len(entries) >= MAX_CATALOG_ENTRIES:
            break
    return [entries[k] for k in sorted(entries)]


def catalog_sha256(entries: Iterable[CatalogEntry]) -> str:
    canonical = "\n".join(f"{e.slug}\t{e.display_name}" for e in sorted(entries, key=lambda e: e.slug))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def diff_catalogs(old: Iterable[CatalogEntry], new: Iterable[CatalogEntry]) -> dict[str, Any]:
    old_map = {e.slug: e.display_name for e in old}
    new_map = {e.slug: e.display_name for e in new}
    return {
        "added": sorted(set(new_map) - set(old_map)),
        "removed": sorted(set(old_map) - set(new_map)),
        "renamed": [
            {"slug": s, "old": old_map[s], "new": new_map[s]}
            for s in sorted(set(old_map) & set(new_map))
            if old_map[s] != new_map[s]
        ],
    }


def run_agy_models(
    *,
    executable: str | Path | None = None,
    runner: Runner | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    if not isinstance(timeout_seconds, int) or not (1 <= timeout_seconds <= 600):
        raise CatalogError(f"Invalid timeout {timeout_seconds!r}; expected 1-600 seconds.")
    exe = Path(executable) if executable else agy_executable()
    if exe is None:
        raise CatalogError("agy executable not found.")
    run = runner or subprocess.run
    try:
        proc = run(
            [str(exe), "models"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CatalogError(f"`agy models` timed out after {timeout_seconds}s.") from exc
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise CatalogError(f"`agy models` could not be run: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] or [""]
        raise CatalogError(f"`agy models` exited with {proc.returncode}: {detail[0][:200]}")
    return proc.stdout or ""


def _load_entries(models_json: str) -> list[CatalogEntry]:
    return [CatalogEntry(slug=m["slug"], display_name=m.get("display_name", "")) for m in json.loads(models_json)]


def _read_one(db_path: Path | None, sql: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
    """Read-only single-row query. Never creates files; tolerates pre-007 databases."""
    if db_path is None or not Path(db_path).is_file():
        return None
    uri = f"file:{Path(db_path).resolve().as_posix()}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=30)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            row = conn.execute(sql, params).fetchone()
    except sqlite3.OperationalError:
        return None
    return dict(row) if row else None


_LATEST_SNAPSHOT_SQL = "SELECT * FROM model_catalog_snapshots WHERE backend=? ORDER BY rowid DESC LIMIT 1"


def latest_snapshot(db_path: Path | None, backend: str = BACKEND_AGY) -> dict[str, Any] | None:
    return _read_one(db_path, _LATEST_SNAPSHOT_SQL, (backend,))


def catalog_state(db_path: Path | None, backend: str = BACKEND_AGY) -> dict[str, Any] | None:
    return _read_one(db_path, "SELECT * FROM model_catalog_state WHERE backend=?", (backend,))


def known_model_lines(db_path: Path | None, backend: str = BACKEND_AGY) -> frozenset[str] | None:
    """Model lines of the latest catalogue snapshot (for attestation disambiguation), or None."""
    try:
        snap = latest_snapshot(db_path, backend)
    except Exception:
        return None
    if not snap:
        return None
    lines: set[str] = set()
    for entry in _load_entries(snap["models_json"]):
        try:
            lines.add(model_line(entry.slug))
        except ModelRefError:
            continue
    return frozenset(lines)


def sync_catalog(
    db_path: Path,
    *,
    backend: str = BACKEND_AGY,
    runner: Runner | None = None,
    executable: str | Path | None = None,
    listing: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Refresh the catalogue for ``backend``; returns a JSON-serialisable result.

    ``listing`` injects raw listing output (tests / offline imports) instead of running the CLI.
    """
    if backend != BACKEND_AGY:
        raise CatalogError(f"Catalogue sync is not implemented for backend '{backend}'.")
    error: str | None = None
    entries: list[CatalogEntry] = []
    try:
        raw = listing if listing is not None else run_agy_models(
            executable=executable, runner=runner, timeout_seconds=timeout_seconds
        )
        entries = parse_agy_models_listing(raw)
        if not entries:
            raise CatalogError("Backend listing contained no models.")
    except CatalogError as exc:
        error = str(exc)

    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        # Timestamp taken under the write lock, so concurrent syncs serialise in timestamp order.
        now = _utc_now()
        try:
            prev_state = conn.execute("SELECT * FROM model_catalog_state WHERE backend=?", (backend,)).fetchone()
            if error is not None:
                errors = (int(prev_state["consecutive_errors"]) if prev_state else 0) + 1
                conn.execute(
                    """INSERT INTO model_catalog_state(backend, last_checked_at, last_status, last_snapshot_id, last_error, consecutive_errors)
                       VALUES(?, ?, 'ERROR', ?, ?, ?)
                       ON CONFLICT(backend) DO UPDATE SET last_checked_at=excluded.last_checked_at,
                           last_status='ERROR', last_error=excluded.last_error,
                           consecutive_errors=excluded.consecutive_errors""",
                    (backend, now, prev_state["last_snapshot_id"] if prev_state else None, error, errors),
                )
                conn.execute("COMMIT")
                return {"backend": backend, "status": "ERROR", "error": error, "checked_at": now,
                        "consecutive_errors": errors, "snapshot_id": prev_state["last_snapshot_id"] if prev_state else None}

            sha = catalog_sha256(entries)
            prev = conn.execute(_LATEST_SNAPSHOT_SQL, (backend,)).fetchone()
            if prev is None:
                status, diff = "INITIAL", diff_catalogs([], entries)
            elif prev["catalog_sha256"] == sha:
                status, diff = "UNCHANGED", {"added": [], "removed": [], "renamed": []}
            else:
                status, diff = "CHANGED", diff_catalogs(_load_entries(prev["models_json"]), entries)

            snapshot_id = prev["snapshot_id"] if prev is not None else None
            if status in ("INITIAL", "CHANGED"):
                stamp = now.replace(":", "").replace("-", "").replace(".", "")
                snapshot_id = f"CAT-{backend}-{stamp}-{sha[:12]}-{uuid.uuid4().hex[:8]}"
                conn.execute(
                    """INSERT INTO model_catalog_snapshots(snapshot_id, backend, catalog_sha256, model_count, models_json, diff_json, observed_at)
                       VALUES(?, ?, ?, ?, ?, ?, ?)""",
                    (snapshot_id, backend, sha, len(entries),
                     json.dumps([e.to_dict() for e in entries], ensure_ascii=False),
                     json.dumps(diff, ensure_ascii=False), now),
                )
            conn.execute(
                """INSERT INTO model_catalog_state(backend, last_checked_at, last_status, last_snapshot_id, last_error, consecutive_errors)
                   VALUES(?, ?, ?, ?, NULL, 0)
                   ON CONFLICT(backend) DO UPDATE SET last_checked_at=excluded.last_checked_at,
                       last_status=excluded.last_status, last_snapshot_id=excluded.last_snapshot_id,
                       last_error=NULL, consecutive_errors=0""",
                (backend, now, status, snapshot_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    return {"backend": backend, "status": status, "checked_at": now, "snapshot_id": snapshot_id,
            "catalog_sha256": sha, "model_count": len(entries), "diff": diff}


def routing_table_health(db_path: Path, host_app: str | None = None) -> dict[str, Any]:
    host = host_app or current_host_app()
    try:
        table = get_active_routing_table(host, db_path)
    except RoutingTableError as exc:
        return {"status": "INVALID", "host": host, "detail": str(exc), "tiers": []}
    snap = latest_snapshot(db_path, BACKEND_AGY)
    offered = {e.slug for e in _load_entries(snap["models_json"])} if snap else None
    tiers = []
    missing = []
    for tier in RoutingTier:
        ref = table.model_for(tier)
        slug = model_slug(ref)
        in_catalog = (slug in offered) if offered is not None else None
        if in_catalog is False:
            missing.append(slug)
        tiers.append({
            "tier": tier.value,
            "model": qualify_model(ref),
            "in_catalog": in_catalog,
            "policy_violation": hard_policy_violation(ref, host),
        })
    if offered is None:
        status = "UNKNOWN"
    elif missing:
        status = "STALE"
    else:
        status = "HEALTHY"
    return {"status": status, "host": host, "table_version": table.version, "missing_models": missing, "tiers": tiers}


def catalog_overview(db_path: Path, *, host_app: str | None = None, include_models: bool = True) -> dict[str, Any]:
    """Read-only overview (no backend CLI execution, no writes)."""
    host = host_app or current_host_app()
    try:
        table_dict: dict[str, Any] = get_active_routing_table(host, db_path).to_dict()
        table_by_slug = {model_slug(m): t for t, m in table_dict["assignments"].items()}
    except RoutingTableError as exc:
        table_dict, table_by_slug = {"error": "ROUTING_TABLE_UNAVAILABLE", "detail": str(exc)}, {}

    snap = latest_snapshot(db_path, BACKEND_AGY)
    state = catalog_state(db_path, BACKEND_AGY)
    catalog: dict[str, Any] = {
        "backend": BACKEND_AGY,
        "snapshot_id": snap["snapshot_id"] if snap else None,
        "catalog_sha256": snap["catalog_sha256"] if snap else None,
        "observed_at": snap["observed_at"] if snap else None,
        "model_count": snap["model_count"] if snap else 0,
        "last_checked_at": state["last_checked_at"] if state else None,
        "last_status": state["last_status"] if state else "NEVER_SYNCED",
        "last_error": state["last_error"] if state else None,
        "consecutive_errors": state["consecutive_errors"] if state else 0,
        "last_change": json.loads(snap["diff_json"]) if snap else None,
    }
    if include_models and snap:
        from model_probes import probe_summary

        models = []
        for e in _load_entries(snap["models_json"]):
            violation = hard_policy_violation(e.slug, host)
            models.append({
                "slug": e.slug,
                # Not "display_name": the gateway's PII scrubber redacts that key.
                "display_model_name": e.display_name,
                "family": model_family(e.slug),
                "effort": model_effort(e.slug),
                "dispatch_allowed_by_policy": violation is None,
                "tier": table_by_slug.get(e.slug),
                "probe": probe_summary(db_path, e.slug) if violation is None else None,
            })
        catalog["models"] = models
    from model_research import latest_research

    research = latest_research(db_path)
    research_summary = None
    if research:
        research_summary = {
            "report_id": research["report_id"],
            "status": research["status"],
            "created_at": research["created_at"],
            "researcher_model": research["researcher_model"],
            "web_tool_calls": research["web_tool_calls"],
            "trust": research["trust"],
            "rank_tier_consistency": research["report"].get("rank_tier_consistency"),
            "issues": research["issues"][:10],
            "lines": [
                {k: line.get(k) for k in ("model_line", "capability_rank", "tier_suggestion", "confidence",
                                           "cost_class", "latency_class", "official_source_count", "self_assessed")}
                for line in research["report"].get("lines", [])
            ],
        }
    from model_routing_proposals import pending_proposal

    return {
        "catalog_version": CATALOG_VERSION,
        "host": host,
        "proposal": pending_proposal(db_path, host),
        "research": research_summary,
        "routing_table": table_dict,
        "table_health": routing_table_health(db_path, host),
        "catalog": catalog,
        "dispatch_backends": [
            {"backend": b.backend, "available": b.available, "detail": b.detail}
            for b in discover_dispatch_backends()
        ],
    }

"""Antigravity Auditor — host/backend-aware model registry and routing table.

This module is the single source of truth for *which* concrete model may be dispatched.
``model_policy.route_model`` decides the *routing tier* of a task (deterministic, evidence-gated);
this module maps tiers to models through an approved routing table and enforces hard rules
that no routing table, research result or approval can override.

Design (kept deliberately open for later phases):

* **Host application** — the client the auditor is installed for / the MCP is attached to
  (``antigravity`` today; ``claude_code``, ``claude_desktop``, ``codex`` later).
* **Dispatch backend** — the CLI that actually runs a model (``agy`` today; ``vibe`` later).
* Model references are backend-qualified (``agy:gemini-4-hydrogen-high``). A bare slug is read
  as an ``agy`` model for backward compatibility.
* Hard policy is keyed by ``(host, backend)``. A pair without an entry is denied (fail closed),
  so adding a new client or backend is an explicit, reviewable code change.
* The active routing table is resolved per host. Phase 0 ships a validated seed table; later
  phases load the user-approved table from SQLite through :func:`get_active_routing_table`.
* :func:`discover_dispatch_backends` is the extension point for "which model CLIs can this
  machine run" (agy now; vibe and others later).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

REGISTRY_VERSION = "3.0.0-dynamic-registry"

# --- hosts & backends -------------------------------------------------------------------------

HOST_ANTIGRAVITY = "antigravity"
HOST_CLAUDE_CODE = "claude_code"
HOST_CLAUDE_DESKTOP = "claude_desktop"
HOST_CODEX = "codex"
KNOWN_HOSTS = (HOST_ANTIGRAVITY, HOST_CLAUDE_CODE, HOST_CLAUDE_DESKTOP, HOST_CODEX)

BACKEND_AGY = "agy"
BACKEND_VIBE = "vibe"
KNOWN_BACKENDS = (BACKEND_AGY, BACKEND_VIBE)
DEFAULT_BACKEND = BACKEND_AGY

HOST_APP_ENV = "ANTIGRAVITY_AUDITOR_HOST_APP"


def current_host_app() -> str:
    """Host application whose policy governs dispatches from this installation.

    Unknown values are returned as-is so they match no policy/table and fail closed.
    """
    value = (os.environ.get(HOST_APP_ENV) or "").strip().lower()
    return value or HOST_ANTIGRAVITY


# --- model identifiers ------------------------------------------------------------------------

_EFFORTS = ("low", "medium", "high", "xhigh", "max", "ultra")
_EFFORT_SUFFIX_RE = re.compile(r"-(" + "|".join(_EFFORTS) + r")$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]{1,95}$")
_DISPLAY_RE = re.compile(r"^(?P<base>[A-Za-z0-9][A-Za-z0-9 ._\-]{0,80}?)\s*\((?P<effort>" + "|".join(_EFFORTS) + r")\)$", re.IGNORECASE)

_FAMILY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("gemini-", "gemini"),
    ("claude-", "claude"),
    ("gpt-", "gpt"),
    ("deepseek-", "deepseek"),
    ("glm-", "glm"),
    ("mistral-", "mistral"),
    ("devstral-", "mistral"),
)


class ModelRefError(ValueError):
    """Raised for malformed model references."""


def split_model_ref(model_ref: str | None) -> tuple[str, str]:
    """Return ``(backend, slug)`` for ``"agy:gemini-x"`` or a bare ``"gemini-x"`` (backend agy)."""
    raw = (model_ref or "").strip().lower()
    if not raw:
        raise ModelRefError("Empty model reference.")
    backend, sep, slug = raw.partition(":")
    if not sep:
        backend, slug = DEFAULT_BACKEND, raw
    if backend not in KNOWN_BACKENDS:
        raise ModelRefError(f"Unknown dispatch backend '{backend}'.")
    if not _SLUG_RE.match(slug):
        raise ModelRefError(f"Malformed model slug '{slug}'.")
    return backend, slug


def qualify_model(model_ref: str) -> str:
    backend, slug = split_model_ref(model_ref)
    return f"{backend}:{slug}"


def model_slug(model_ref: str) -> str:
    """Bare slug suitable for the backend CLI's ``--model`` flag."""
    return split_model_ref(model_ref)[1]


def model_effort(model_ref: str) -> str | None:
    m = _EFFORT_SUFFIX_RE.search(model_slug(model_ref))
    return m.group(1) if m else None


def model_line(model_ref: str) -> str:
    """Model line without the effort suffix (``gemini-4-hydrogen-high`` -> ``gemini-4-hydrogen``).

    Different efforts of one line are the same underlying model and never count as
    independent verifiers.
    """
    return _EFFORT_SUFFIX_RE.sub("", model_slug(model_ref))


def model_family(model_ref: str) -> str:
    slug = model_slug(model_ref)
    for prefix, family in _FAMILY_PREFIXES:
        if slug.startswith(prefix):
            return family
    return "unknown"


def same_model_line(a: str | None, b: str | None) -> bool:
    """True if ``a`` and ``b`` are the same model line.

    Conservative: if either side cannot be normalised (empty, display string that does not parse,
    malformed ref) the answer is True, so callers checking *independence* fail closed.
    """
    slug_a = canonical_model_slug(a)
    slug_b = canonical_model_slug(b)
    if not slug_a or not slug_b:
        return True
    return model_line(slug_a) == model_line(slug_b)


def canonical_model_slug(name: str | None) -> str | None:
    """Normalise a slug (``gemini-4-argon-high``), qualified ref or display name
    (``Gemini 4 Argon (High)``) to a bare slug. Returns ``None`` when it cannot be done
    deterministically."""
    text = (name or "").strip()
    if not text:
        return None
    try:
        return model_slug(text)
    except ModelRefError:
        pass
    m = _DISPLAY_RE.match(text)
    if not m:
        return None
    base = re.sub(r"\s+", "-", m.group("base").strip().lower())
    candidate = f"{base}-{m.group('effort').lower()}"
    return candidate if _SLUG_RE.match(candidate) else None


def resolve_observed_model(
    backend_model_id: str | None,
    display_model_name: str | None,
    known_model_lines: "frozenset[str] | set[str] | None" = None,
) -> str | None:
    """Resolve the effort-qualified slug a backend actually ran.

    ``agy`` records an un-suffixed internal id (``gemini-4-hydrogen``, ``gemini-4-argon-trial``,
    ``gemini-3.8-flash-n``) and an effort-qualified display name (``Gemini 4 Hydrogen (Medium)``).
    The display name decides the slug; the internal id must start with that slug's model line,
    otherwise the record is inconsistent and nothing is attested.

    Fails closed (``None``) when either field is missing, when the display name does not carry
    an effort, or when the internal id is not on the display name's model line or names a
    different effort. With ``known_model_lines`` (from the persisted backend catalogue) the
    internal id must not belong to a longer sibling line (e.g. ``<line>-lite``).
    """
    backend_raw = (backend_model_id or "").strip().lower()
    display_raw = (display_model_name or "").strip()
    if not backend_raw or not display_raw:
        return None
    display_slug = canonical_model_slug(display_raw)
    if not display_slug or model_effort(display_slug) is None:
        return None
    line = model_line(display_slug)
    # Token boundary: "gemini-4-argon" matches "gemini-4-argon" and "gemini-4-argon-trial" but not
    # "gemini-4-argonx".
    if not (backend_raw == line or backend_raw.startswith(line + "-")):
        return None
    # Sibling-line disambiguation against the catalogue: an internal id that matches a longer known
    # line (e.g. "gemini-4-hydrogen-lite") belongs to that line, not to the display name's line.
    for other in known_model_lines or ():
        if len(other) > len(line) and other.startswith(line + "-") and (
            backend_raw == other or backend_raw.startswith(other + "-")
        ):
            return None
    backend_effort = _EFFORT_SUFFIX_RE.search(backend_raw)
    if backend_effort and backend_effort.group(1) != model_effort(display_slug):
        return None
    return display_slug


# --- hard policy --------------------------------------------------------------------------------

@dataclass(frozen=True)
class BackendPolicy:
    """Rules for one (host, backend) pair that no routing table or approval can override."""

    host: str
    backend: str
    allowed_families: frozenset[str]
    denied_line_patterns: tuple[str, ...] = ()
    scarce_line_patterns: tuple[str, ...] = ()
    notes: str = ""

    def violation(self, model_ref: str) -> str | None:
        backend, slug = split_model_ref(model_ref)
        if backend != self.backend:
            return f"Model '{model_ref}' is not a {self.backend} model."
        family = model_family(slug)
        if family not in self.allowed_families:
            return (
                f"Model family '{family}' is not allowed for host '{self.host}' on backend "
                f"'{self.backend}' (allowed: {sorted(self.allowed_families)})."
            )
        line = model_line(slug)
        for pattern in self.denied_line_patterns:
            if re.search(pattern, slug) or re.search(pattern, line):
                return f"Model '{slug}' is denied by policy rule '{pattern}' for host '{self.host}'."
        return None

    def is_scarce(self, model_ref: str) -> bool:
        line = model_line(model_ref)
        return any(re.search(p, line) for p in self.scarce_line_patterns)


# Pairs absent from this map are denied. Add entries for claude_code / codex / vibe only as an
# explicit policy decision.
HARD_POLICIES: Mapping[tuple[str, str], BackendPolicy] = MappingProxyType({
    (HOST_ANTIGRAVITY, BACKEND_AGY): BackendPolicy(
        host=HOST_ANTIGRAVITY,
        backend=BACKEND_AGY,
        allowed_families=frozenset({"gemini"}),
        denied_line_patterns=(r"flash", r"orchestrator"),
        scarce_line_patterns=(r"^gemini-4-argon",),
        notes="User decision 2026-11-15: Antigravity dispatches Gemini models only; Gemini 3.8 Flash retired.",
    ),
})


def backend_policy(host_app: str | None, backend: str) -> BackendPolicy | None:
    return HARD_POLICIES.get(((host_app or current_host_app()), backend))


def hard_policy_violation(model_ref: str | None, host_app: str | None = None) -> str | None:
    """Reason the model may never be dispatched for ``host_app``, or ``None`` if allowed."""
    host = host_app or current_host_app()
    try:
        backend, _ = split_model_ref(model_ref)
    except ModelRefError as exc:
        return str(exc)
    policy = backend_policy(host, backend)
    if policy is None:
        return f"No dispatch policy for host '{host}' and backend '{backend}' (fail closed)."
    return policy.violation(model_ref or "")


def is_scarce_model(model_ref: str | None, host_app: str | None = None) -> bool:
    """Scarce models (e.g. Argon) are subject to atomic budget reservations.

    Conservative: anything mentioning "argon" is scarce even without a matching policy or when the
    reference does not parse, so budgeting can only widen, never silently disappear.
    """
    if "argon" in (model_ref or "").lower():
        return True
    try:
        backend, _ = split_model_ref(model_ref)
    except ModelRefError:
        return False
    policy = backend_policy(host_app, backend)
    return bool(policy and policy.is_scarce(model_ref or ""))


# --- routing tiers & table ----------------------------------------------------------------------

class RoutingTier(str, Enum):
    """Abstract capability tiers that ``model_policy.route_model`` assigns to tasks."""

    ENTRY = "ENTRY"                # lightweight, well-specified tasks
    STANDARD = "STANDARD"          # default for audits, exploration, routine verification
    CRITICAL = "CRITICAL"          # evidence-gated critical verification / decisions
    CATASTROPHIC = "CATASTROPHIC"  # evidence-gated catastrophic security / data-loss cases


class RoutingTableError(ValueError):
    """Raised when a routing table violates hard policy or independence invariants."""


@dataclass(frozen=True)
class RoutingTable:
    host: str
    version: str
    source: str  # SEED | APPROVED
    assignments: Mapping[RoutingTier, str] = field(default_factory=dict)
    approved_by: str | None = None
    approved_at: str | None = None

    def model_for(self, tier: RoutingTier) -> str:
        return self.assignments[tier]

    def approved_models(self) -> frozenset[str]:
        return frozenset(qualify_model(m) for m in self.assignments.values())

    def tier_of(self, model_ref: str) -> RoutingTier | None:
        q = qualify_model(model_ref)
        for tier, assigned in self.assignments.items():
            if qualify_model(assigned) == q:
                return tier
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "version": self.version,
            "source": self.source,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "assignments": {t.value: qualify_model(m) for t, m in self.assignments.items()},
        }


def validate_routing_table(table: RoutingTable) -> None:
    """Every tier assigned, every model allowed by hard policy, and critical tiers on a different
    model line than STANDARD (critical verification of a STANDARD-tier primary audit must be able
    to satisfy cross-model independence)."""
    missing = [t.value for t in RoutingTier if t not in table.assignments]
    if missing:
        raise RoutingTableError(f"Routing table {table.version} misses tiers: {missing}")
    for tier, model in table.assignments.items():
        reason = hard_policy_violation(model, table.host)
        if reason:
            raise RoutingTableError(f"Routing table {table.version} tier {tier.value}: {reason}")
    standard = table.assignments[RoutingTier.STANDARD]
    for tier in (RoutingTier.CRITICAL, RoutingTier.CATASTROPHIC):
        if same_model_line(table.assignments[tier], standard):
            raise RoutingTableError(
                f"Routing table {table.version}: {tier.value} model must be a different model line "
                f"than STANDARD ({standard}) to allow independent critical verification."
            )


SEED_ROUTING_TABLES: Mapping[str, RoutingTable] = MappingProxyType({
    HOST_ANTIGRAVITY: RoutingTable(
        host=HOST_ANTIGRAVITY,
        version="seed-2026-11-15",
        source="SEED",
        assignments=MappingProxyType({
            RoutingTier.ENTRY: "agy:gemini-4-hydrogen-medium",
            RoutingTier.STANDARD: "agy:gemini-4-hydrogen-high",
            RoutingTier.CRITICAL: "agy:gemini-4-argon-medium",
            RoutingTier.CATASTROPHIC: "agy:gemini-4-argon-high",
        }),
    ),
})


# --- routing-table store (user-approved tables persisted in SQLite, migration 010) -------------------

_configured_store: Path | None = None


def configure_routing_store(db_path: Path | str | None) -> None:
    """Pin the SQLite database that holds approved routing tables for this process (CLI / MCP main)."""
    global _configured_store
    _configured_store = Path(db_path).resolve() if db_path else None


def routing_store_path() -> Path:
    """Same resolution as cli.py / mcp_server.main: ANTIGRAVITY_AUDITOR_DB, else
    <ANTIGRAVITY_AUDITOR_HOME or install root>/database/auditor.db."""
    if _configured_store is not None:
        return _configured_store
    env_db = os.environ.get("ANTIGRAVITY_AUDITOR_DB")
    if env_db:
        return Path(env_db).resolve()
    home = Path(os.environ.get("ANTIGRAVITY_AUDITOR_HOME", str(Path(__file__).resolve().parents[1]))).resolve()
    return home / "database" / "auditor.db"


def table_from_row(row: "sqlite3.Row | dict[str, object]") -> RoutingTable:
    """Build a RoutingTable from a routing_table_versions row; malformed rows raise RoutingTableError."""
    try:
        raw = json.loads(str(row["assignments_json"]))
        if not isinstance(raw, dict):
            raise ValueError("assignments_json must be a JSON object")
        assignments = {RoutingTier[str(k)]: qualify_model(str(v)) for k, v in raw.items()}
    except (KeyError, ValueError, TypeError, AttributeError, ModelRefError) as exc:
        raise RoutingTableError(f"Stored routing table {row['version_id']} is malformed: {exc}") from exc
    return RoutingTable(
        host=str(row["host"]),
        version=str(row["version_id"]),
        source="APPROVED" if row["status"] == "ACTIVE" else str(row["status"]),
        assignments=MappingProxyType(assignments),
        approved_by=row["decided_by"] if row["status"] == "ACTIVE" else None,
        approved_at=row["decided_at"] if row["status"] == "ACTIVE" else None,
    )


def load_approved_table(host: str, db_path: Path | None = None) -> RoutingTable | None:
    """The ACTIVE user-approved table for ``host``, or None if the store has none (or does not exist yet).

    Read errors other than "table missing" fail closed (RoutingTableError) rather than silently
    reverting to the seed.
    """
    path = Path(db_path) if db_path else routing_store_path()
    if not path.is_file():
        return None
    try:
        with closing(sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True, timeout=30)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            row = conn.execute(
                "SELECT * FROM routing_table_versions WHERE host=? AND status='ACTIVE' ORDER BY rowid DESC LIMIT 1",
                (host,),
            ).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return None
        raise RoutingTableError(f"Routing-table store unreadable: {exc}") from exc
    except sqlite3.DatabaseError as exc:  # corrupt / not a database: fail closed, never fall back
        raise RoutingTableError(f"Routing-table store unreadable: {exc}") from exc
    return table_from_row(row) if row else None


def get_active_routing_table(host_app: str | None = None, db_path: Path | None = None) -> RoutingTable:
    """Active, validated routing table for ``host_app``.

    The latest user-approved (ACTIVE) table from the routing-table store if one exists, otherwise the
    seed. An approved table that no longer validates (e.g. hard policy changed) raises — it never
    silently falls back to the seed.
    """
    host = host_app or current_host_app()
    table = load_approved_table(host, db_path) or SEED_ROUTING_TABLES.get(host)
    if table is None:
        raise RoutingTableError(f"No routing table configured for host '{host}'.")
    validate_routing_table(table)
    return table


def is_approved_model(model_ref: str | None, host_app: str | None = None, db_path: Path | None = None) -> bool:
    """Dispatchable = allowed by hard policy AND assigned in the active routing table."""
    if hard_policy_violation(model_ref, host_app) is not None:
        return False
    try:
        return qualify_model(model_ref or "") in get_active_routing_table(host_app, db_path).approved_models()
    except (ModelRefError, RoutingTableError):
        return False


def was_ever_approved_model(model_ref: str | None, host_app: str | None = None, db_path: Path | None = None) -> bool:
    """Allowed by hard policy AND assigned in the seed, the active table or any previously ACTIVE
    (now SUPERSEDED) approved table. Used to judge work that already ran (e.g. cross-model independence
    of an in-flight audit) so approving a new table does not retroactively invalidate it."""
    host = host_app or current_host_app()
    if hard_policy_violation(model_ref, host) is not None:
        return False
    try:
        q = qualify_model(model_ref or "")
    except ModelRefError:
        return False
    seed = SEED_ROUTING_TABLES.get(host)
    if seed is not None and q in seed.approved_models():
        return True
    if is_approved_model(model_ref, host, db_path):
        return True
    path = Path(db_path) if db_path else routing_store_path()
    if not path.is_file():
        return False
    try:
        with closing(sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True, timeout=30)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM routing_table_versions WHERE host=? AND status IN ('ACTIVE','SUPERSEDED') AND decided_at IS NOT NULL",
                (host,),
            ).fetchall()
    except sqlite3.DatabaseError:
        return False
    for row in rows:
        try:
            if q in table_from_row({**dict(row), "status": "ACTIVE"}).approved_models():
                return True
        except RoutingTableError:
            continue
    return False


def approved_model_slugs(host_app: str | None = None, db_path: Path | None = None) -> list[str]:
    return sorted(model_slug(m) for m in get_active_routing_table(host_app, db_path).approved_models())


# --- backend discovery (extension point) ----------------------------------------------------------

@dataclass(frozen=True)
class DispatchBackendInfo:
    backend: str
    executable: str | None
    available: bool
    detail: str


def agy_executable() -> Path | None:
    """Locate agy (ANTIGRAVITY_CLI_EXE, %LOCALAPPDATA%\agy\bin\agy.exe, PATH)."""
    return _agy_executable()


def _agy_executable() -> Path | None:
    override = os.environ.get("ANTIGRAVITY_CLI_EXE")
    candidates = [Path(override)] if override else []
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.append(Path(local) / "agy" / "bin" / "agy.exe")
    which = shutil.which("agy")
    if which:
        candidates.append(Path(which))
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def discover_dispatch_backends() -> list[DispatchBackendInfo]:
    """Model CLIs this machine can dispatch to. Only ``agy`` is implemented; other backends are
    reported as not implemented so callers can see the extension point without using them."""
    agy = _agy_executable()
    infos = [
        DispatchBackendInfo(
            backend=BACKEND_AGY,
            executable=str(agy) if agy else None,
            available=agy is not None,
            detail="Antigravity CLI" if agy else "agy executable not found",
        )
    ]
    infos.append(DispatchBackendInfo(
        backend=BACKEND_VIBE, executable=None, available=False,
        detail="NOT_IMPLEMENTED: vibe dispatch is planned for a later phase.",
    ))
    return infos

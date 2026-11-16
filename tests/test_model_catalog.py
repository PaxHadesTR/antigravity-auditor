"""Phase 1 of dynamic model routing: backend model catalogue, change detection, table health,
catalogue-aware attestation and the read-only ``auditor_models_overview`` MCP tool."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import model_catalog as cat  # noqa: E402
from db import initialize  # noqa: E402
from mcp_gateway.tool_manifest import build_default_canonical_manifests  # noqa: E402
from mcp_server import AuditorMCPDispatcher, TOOL_DEFINITIONS, validate_strict_schema  # noqa: E402
from model_attestation import AttestationStatus, attest_conversation_model  # noqa: E402
from model_registry import resolve_observed_model  # noqa: E402

LISTING = """Fetching available models...
gemini-4-argon-medium\tGemini 4 Argon (Medium)
gemini-4-argon-high\tGemini 4 Argon (High)
gemini-4-hydrogen-high\tGemini 4 Hydrogen (High)
gemini-4-hydrogen-medium\tGemini 4 Hydrogen (Medium)
gemini-3.8-flash-high\tGemini 3.8 Flash (High)
claude-opus-5-5-high\tClaude Opus 5.5 (High)
gemini-pro-orchestrator-g1-pro\tOrchestrator (Argon)
not a valid slug!!\tJunk
"""


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    path = tmp_path / "home" / "database" / "auditor.db"
    initialize(path)
    return path


def _rows(db: Path, table: str) -> int:
    conn = sqlite3.connect(db)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def test_migration_007_creates_catalog_tables(db: Path) -> None:
    conn = sqlite3.connect(db)
    try:
        versions = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()
    assert 7 in versions
    assert {"model_catalog_snapshots", "model_catalog_state"} <= tables


def test_parse_listing_is_strict_sorted_and_deduplicated() -> None:
    entries = cat.parse_agy_models_listing(LISTING + "gemini-4-argon-high\tGemini 4 Argon (High)\n")
    slugs = [e.slug for e in entries]
    assert slugs == sorted(slugs) and len(slugs) == len(set(slugs)) == 7
    assert "not" not in slugs and all(" " not in s for s in slugs)
    assert dict((e.slug, e.display_name) for e in entries)["gemini-4-hydrogen-high"] == "Gemini 4 Hydrogen (High)"


def test_sync_initial_unchanged_changed(db: Path) -> None:
    first = cat.sync_catalog(db, listing=LISTING)
    assert first["status"] == "INITIAL" and first["model_count"] == 7
    again = cat.sync_catalog(db, listing=LISTING)
    assert again["status"] == "UNCHANGED" and again["snapshot_id"] == first["snapshot_id"]
    assert _rows(db, "model_catalog_snapshots") == 1

    changed_listing = LISTING.replace("gemini-4-argon-high\tGemini 4 Argon (High)\n", "") + "gemini-4-hydrogen-xhigh\tGemini 4 Hydrogen (XHigh)\n"
    changed = cat.sync_catalog(db, listing=changed_listing)
    assert changed["status"] == "CHANGED" and changed["snapshot_id"] != first["snapshot_id"]
    assert changed["diff"]["added"] == ["gemini-4-hydrogen-xhigh"]
    assert changed["diff"]["removed"] == ["gemini-4-argon-high"]
    assert _rows(db, "model_catalog_snapshots") == 2


def test_removed_table_model_makes_table_stale(db: Path) -> None:
    assert cat.routing_table_health(db)["status"] == "UNKNOWN"
    cat.sync_catalog(db, listing=LISTING)
    assert cat.routing_table_health(db)["status"] == "HEALTHY"
    cat.sync_catalog(db, listing=LISTING.replace("gemini-4-argon-high\tGemini 4 Argon (High)\n", ""))
    health = cat.routing_table_health(db)
    assert health["status"] == "STALE" and health["missing_models"] == ["gemini-4-argon-high"]


def test_sync_errors_are_recorded_without_losing_last_snapshot(db: Path) -> None:
    ok = cat.sync_catalog(db, listing=LISTING)

    def failing_runner(*_a: Any, **_k: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="Error: sign-in required")

    err = cat.sync_catalog(db, runner=failing_runner, executable=__file__)
    assert err["status"] == "ERROR" and "sign-in required" in err["error"]
    err2 = cat.sync_catalog(db, listing="Fetching available models...\n")
    assert err2["status"] == "ERROR" and err2["consecutive_errors"] == 2
    state = cat.catalog_state(db)
    assert state["last_snapshot_id"] == ok["snapshot_id"] and state["consecutive_errors"] == 2
    assert cat.sync_catalog(db, listing=LISTING)["status"] == "UNCHANGED"
    assert cat.catalog_state(db)["consecutive_errors"] == 0


def test_runner_is_invoked_without_shell(db: Path) -> None:
    seen: dict[str, Any] = {}

    def runner(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"], seen["kw"] = cmd, kw
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=LISTING, stderr="")

    assert cat.sync_catalog(db, runner=runner, executable=__file__)["status"] == "INITIAL"
    assert seen["cmd"][1:] == ["models"] and seen["kw"]["shell"] is False


def test_overview_marks_policy_and_tiers_and_never_runs_cli(db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cat.sync_catalog(db, listing=LISTING)
    monkeypatch.setattr(cat, "run_agy_models", lambda **_k: pytest.fail("overview must not run the backend CLI"))
    before = _rows(db, "model_catalog_snapshots")
    view = cat.catalog_overview(db)
    models = {m["slug"]: m for m in view["catalog"]["models"]}
    assert models["gemini-4-hydrogen-high"]["tier"] == "STANDARD"
    assert models["gemini-4-hydrogen-high"]["dispatch_allowed_by_policy"] is True
    for denied in ("gemini-3.8-flash-high", "claude-opus-5-5-high", "gemini-pro-orchestrator-g1-pro"):
        assert models[denied]["dispatch_allowed_by_policy"] is False and models[denied]["tier"] is None
    assert view["table_health"]["status"] == "HEALTHY"
    assert _rows(db, "model_catalog_snapshots") == before


def test_catalogue_lines_disambiguate_sibling_lines(db: Path, tmp_path: Path) -> None:
    cat.sync_catalog(db, listing=LISTING + "gemini-4-hydrogen-lite-high\tGemini 4 Hydrogen Lite (High)\n")
    lines = cat.known_model_lines(db)
    assert {"gemini-4-hydrogen", "gemini-4-hydrogen-lite", "gemini-4-argon"} <= lines
    assert resolve_observed_model("gemini-4-hydrogen-lite", "Gemini 4 Hydrogen (High)") == "gemini-4-hydrogen-high"
    assert resolve_observed_model("gemini-4-hydrogen-lite", "Gemini 4 Hydrogen (High)", lines) is None

    # End to end through attestation.
    from test_model_registry import _blob  # reuse protobuf fixture

    conv = str(uuid.uuid4())
    conn = sqlite3.connect(tmp_path / f"{conv}.db")
    conn.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB, size INTEGER)")
    blob = _blob(conv, "gemini-4-hydrogen-lite", "Gemini 4 Hydrogen (High)")
    conn.execute("INSERT INTO gen_metadata VALUES (0, ?, ?)", (blob, len(blob)))
    conn.commit()
    conn.close()
    res = attest_conversation_model(conv, "gemini-4-hydrogen-high", conversations_dir=tmp_path, known_model_lines=lines)
    assert not res.is_attested and res.status == AttestationStatus.MODEL_ATTESTATION_MISMATCH


def test_known_model_lines_tolerates_missing_catalog(tmp_path: Path) -> None:
    assert cat.known_model_lines(None) is None
    assert cat.known_model_lines(tmp_path / "missing" / "auditor.db") is None


def test_models_overview_tool_contract(db: Path) -> None:
    cat.sync_catalog(db, listing=LISTING)
    d = AuditorMCPDispatcher(db_path=db, app_home=db.parent.parent)
    out = d.call_tool("auditor_models_overview", {"include_models": False})
    spec = next(t for t in TOOL_DEFINITIONS if t["name"] == "auditor_models_overview")
    validate_strict_schema(out, spec["outputSchema"], "output")
    assert "models" not in out["catalog"] and out["catalog"]["model_count"] == 7
    with pytest.raises(ValueError):
        d.call_tool("auditor_models_overview", {"refresh": True})


def test_models_overview_requires_models_read_scope() -> None:
    manifest = {m.tool_name: m for m in build_default_canonical_manifests()}["auditor_models_overview"]
    assert manifest.required_authorization_scopes == ("models:read",)
    assert manifest.tool_group.value == "PROJECT_READ"  # UNKNOWN callers are limited to CORE_READ
    assert manifest.execution_mutating is False
    from application_adapters.stdio_entry import ANTIGRAVITY_STDIO_READONLY_AUDIT_SCOPES

    assert "models:read" in ANTIGRAVITY_STDIO_READONLY_AUDIT_SCOPES


# --- regressions from the independent Argon review of Phase 1 ---------------------------------

def test_banner_lines_never_become_models(db: Path) -> None:
    banners = "No models available\nAvailable models:\nDone\nPlease sign in to continue\nAGY:Gemini-X\tShouty\n"
    assert cat.parse_agy_models_listing(banners) == []
    ok = cat.sync_catalog(db, listing=LISTING)
    res = cat.sync_catalog(db, listing=banners)
    assert res["status"] == "ERROR" and cat.latest_snapshot(db)["snapshot_id"] == ok["snapshot_id"]


def test_rapid_a_b_a_changes_do_not_collide(db: Path) -> None:
    other = LISTING + "gemini-4-hydrogen-xhigh\tGemini 4 Hydrogen (XHigh)\n"
    a1 = cat.sync_catalog(db, listing=LISTING)
    b = cat.sync_catalog(db, listing=other)
    a2 = cat.sync_catalog(db, listing=LISTING)
    assert [a1["status"], b["status"], a2["status"]] == ["INITIAL", "CHANGED", "CHANGED"]
    assert len({a1["snapshot_id"], b["snapshot_id"], a2["snapshot_id"]}) == 3
    assert cat.latest_snapshot(db)["snapshot_id"] == a2["snapshot_id"] == cat.catalog_state(db)["last_snapshot_id"]


def test_overview_model_names_survive_gateway_redaction(db: Path) -> None:
    from entitlement_router.privacy import sanitize_for_output

    cat.sync_catalog(db, listing=LISTING)
    scrubbed = sanitize_for_output(cat.catalog_overview(db))
    names = {m["slug"]: m["display_model_name"] for m in scrubbed["catalog"]["models"]}
    assert names["gemini-4-hydrogen-high"] == "Gemini 4 Hydrogen (High)"


def test_read_helpers_never_create_files_and_tolerate_old_schema(tmp_path: Path) -> None:
    missing = tmp_path / "missing" / "auditor.db"
    assert cat.known_model_lines(missing) is None and cat.latest_snapshot(missing) is None
    assert not missing.parent.exists()
    old = tmp_path / "v6.db"
    conn = sqlite3.connect(old)
    conn.execute("CREATE TABLE projects (project_key TEXT)")
    conn.commit()
    conn.close()
    assert cat.latest_snapshot(old) is None and cat.catalog_state(old) is None
    assert cat.routing_table_health(old)["status"] == "UNKNOWN"
    assert cat.catalog_overview(old)["catalog"]["last_status"] == "NEVER_SYNCED"


def test_invalid_timeout_is_recorded_as_error(db: Path) -> None:
    res = cat.sync_catalog(db, executable=__file__, timeout_seconds=-1)
    assert res["status"] == "ERROR" and "Invalid timeout" in res["error"]


def test_runner_decodes_utf8(db: Path) -> None:
    seen: dict[str, Any] = {}

    def runner(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kw)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=LISTING, stderr="")

    cat.sync_catalog(db, runner=runner, executable=__file__)
    assert seen["encoding"] == "utf-8" and seen["errors"] == "replace"

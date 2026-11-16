"""Dynamic model registry (Phase 0): hard policy, routing table, tiered routing, dynamic attestation.

Security-relevant invariants covered here:
* Antigravity dispatches Gemini models only; Flash, orchestrator and non-Gemini families are
  denied regardless of any routing table.
* Unknown (host, backend) pairs fail closed — new clients/backends need an explicit policy entry.
* A routing table that violates hard policy is rejected; a tier whose model is disallowed
  blocks the dispatch instead of silently falling back.
* Attestation resolves the effort-qualified model from agy's display name and refuses
  records whose internal id belongs to a different model line.
* Two efforts of one model line never count as independent verifiers.
"""

from __future__ import annotations

import sqlite3
import sys
import uuid
from pathlib import Path
from types import MappingProxyType

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import model_policy  # noqa: E402
import model_registry as reg  # noqa: E402
from agy_adapter import AntigravityCliAdapter  # noqa: E402
from model_attestation import (  # noqa: E402
    AttestationStatus,
    CrossModelStatus,
    attest_conversation_model,
    parse_gen_metadata_blob,
    verify_cross_model_independence,
)
from model_policy import ModelId, ModelRoutingRequest, RoutingStatus, route_model  # noqa: E402
from model_registry import RoutingTable, RoutingTableError, RoutingTier  # noqa: E402
from verification import verify_cross_model_independence as verification_independence  # noqa: E402


# --- helpers ---------------------------------------------------------------------------------

def _varint(val: int) -> bytes:
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        out.append(b | 0x80 if val else b)
        if not val:
            return bytes(out)


def _field(num: int, payload: bytes) -> bytes:
    return _varint((num << 3) | 2) + _varint(len(payload)) + payload


def _blob(conversation_id: str, backend_model_id: str, display: str) -> bytes:
    kv = _field(20, _field(1, b"cascade_id") + _field(2, conversation_id.encode()))
    sub = _field(19, backend_model_id.encode()) + kv + _field(21, display.encode())
    return _field(1, sub)


def _conversation(tmp_path: Path, backend_model_id: str, display: str) -> tuple[str, Path]:
    conv_id = str(uuid.uuid4())
    db = tmp_path / f"{conv_id}.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB, size INTEGER)")
    blob = _blob(conv_id, backend_model_id, display)
    conn.execute("INSERT INTO gen_metadata VALUES (0, ?, ?)", (blob, len(blob)))
    conn.commit()
    conn.close()
    return conv_id, tmp_path


def _table(**overrides: str) -> RoutingTable:
    base = dict(reg.SEED_ROUTING_TABLES[reg.HOST_ANTIGRAVITY].assignments)
    for tier_name, model in overrides.items():
        base[RoutingTier[tier_name]] = model
    return RoutingTable(host=reg.HOST_ANTIGRAVITY, version="test", source="TEST", assignments=MappingProxyType(base))


# --- hard policy ---------------------------------------------------------------------------------

@pytest.mark.parametrize("model", [
    "gemini-3.8-flash-high", "gemini-3.8-flash-medium", "gemini-3.8-flash-low",
    "agy:gemini-3.8-flash-high", "gemini-pro-orchestrator-g1-pro",
    "claude-opus-5-5-high", "claude-sonnet-5-5-medium", "gpt-oss-120b-medium", "mystery-model-1",
])
def test_antigravity_hard_policy_denies_flash_orchestrator_and_non_gemini(model: str) -> None:
    assert reg.hard_policy_violation(model, reg.HOST_ANTIGRAVITY) is not None
    assert not ModelId.is_approved(model)


@pytest.mark.parametrize("model", ["gemini-4-hydrogen-low", "gemini-4-hydrogen-xhigh", "gemini-4-argon-low", "agy:gemini-4-argon-high"])
def test_antigravity_hard_policy_allows_gemini_4(model: str) -> None:
    assert reg.hard_policy_violation(model, reg.HOST_ANTIGRAVITY) is None


def test_unknown_host_or_backend_fails_closed() -> None:
    assert "fail closed" in reg.hard_policy_violation("vibe:deepseek-v4-flash", reg.HOST_ANTIGRAVITY)
    for host in (reg.HOST_CLAUDE_CODE, reg.HOST_CLAUDE_DESKTOP, reg.HOST_CODEX):
        assert "fail closed" in reg.hard_policy_violation("gemini-4-hydrogen-high", host)
    with pytest.raises(reg.ModelRefError):
        reg.split_model_ref("ollama:llama")


def test_approved_means_policy_allowed_and_in_active_table() -> None:
    for model in ModelId:
        assert ModelId.is_approved(model.value)
        assert ModelId.is_approved(f"agy:{model.value}")
    # Allowed by hard policy but not assigned in the active table -> not dispatchable.
    assert reg.hard_policy_violation("gemini-4-hydrogen-xhigh") is None
    assert not ModelId.is_approved("gemini-4-hydrogen-xhigh")
    assert reg.approved_model_slugs() == sorted(m.value for m in ModelId)


def test_scarce_models_are_the_argon_line() -> None:
    assert reg.is_scarce_model("gemini-4-argon-medium") and reg.is_scarce_model("agy:gemini-4-argon-high")
    assert not reg.is_scarce_model("gemini-4-hydrogen-high")


# --- routing table validation ------------------------------------------------------------------

def test_seed_table_is_valid_and_matches_user_decision() -> None:
    table = reg.get_active_routing_table(reg.HOST_ANTIGRAVITY)
    assert table.to_dict()["assignments"] == {
        "ENTRY": "agy:gemini-4-hydrogen-medium",
        "STANDARD": "agy:gemini-4-hydrogen-high",
        "CRITICAL": "agy:gemini-4-argon-medium",
        "CATASTROPHIC": "agy:gemini-4-argon-high",
    }


@pytest.mark.parametrize("overrides, message", [
    ({"STANDARD": "gemini-3.8-flash-high"}, "flash"),
    ({"ENTRY": "claude-sonnet-5-5-low"}, "not allowed"),
    ({"CRITICAL": "gemini-4-hydrogen-xhigh"}, "different model line"),
    ({"CATASTROPHIC": "agy:gemini-4-hydrogen-medium"}, "different model line"),
])
def test_invalid_routing_tables_are_rejected(overrides: dict[str, str], message: str) -> None:
    with pytest.raises(RoutingTableError, match=message):
        reg.validate_routing_table(_table(**overrides))


def test_table_missing_a_tier_is_rejected() -> None:
    assignments = dict(reg.SEED_ROUTING_TABLES[reg.HOST_ANTIGRAVITY].assignments)
    assignments.pop(RoutingTier.ENTRY)
    with pytest.raises(RoutingTableError, match="misses tiers"):
        reg.validate_routing_table(RoutingTable(host=reg.HOST_ANTIGRAVITY, version="t", source="T", assignments=assignments))


# --- tiered routing -----------------------------------------------------------------------------

def test_tiers_resolve_through_table() -> None:
    d = route_model(ModelRoutingRequest(task_type="PRIMARY_AUDIT"))
    assert d.selected_model == ModelId.GEMINI_4_HYDROGEN_HIGH and d.routing_tier is RoutingTier.STANDARD
    assert d.routing_table_version == "seed-2026-11-15" and d.backend == "agy" and not d.is_argon
    d = route_model(ModelRoutingRequest(task_type="FINDING_CLASSIFICATION"))
    assert d.selected_model == ModelId.GEMINI_4_HYDROGEN_MEDIUM and d.routing_tier is RoutingTier.ENTRY
    d = route_model(ModelRoutingRequest(task_type="CRITICAL_VERIFICATION", severity="HIGH",
                                        finding_category="DATABASE_INTEGRITY", evidence_gate_status="PASSED"))
    assert d.selected_model == ModelId.GEMINI_4_ARGON_MEDIUM and d.is_argon and d.is_cross_model_required
    d = route_model(ModelRoutingRequest(task_type="CRITICAL_VERIFICATION", severity="CRITICAL",
                                        finding_category="RCE", evidence_gate_status="PASSED"))
    assert d.selected_model == ModelId.GEMINI_4_ARGON_HIGH and d.routing_tier is RoutingTier.CATASTROPHIC


def test_custom_table_changes_models_without_code_changes() -> None:
    table = _table(STANDARD="gemini-4-hydrogen-xhigh", CRITICAL="gemini-4-argon-high")
    reg.validate_routing_table(table)
    d = route_model(ModelRoutingRequest(task_type="PRIMARY_AUDIT"), routing_table=table)
    assert d.selected_model.value == "gemini-4-hydrogen-xhigh" and d.reasoning_level.value == "xhigh"


def test_disallowed_tier_model_blocks_without_fallback() -> None:
    table = _table(STANDARD="gemini-3.8-flash-high")  # deliberately not validated
    d = route_model(ModelRoutingRequest(task_type="PRIMARY_AUDIT"), routing_table=table)
    assert d.is_blocked and d.selected_model is None
    assert d.routing_status is RoutingStatus.BLOCKED_MODEL_UNAVAILABLE
    assert "MODEL_POLICY_VIOLATION" in d.blocked_reason


def test_missing_routing_table_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> RoutingTable:
        raise RoutingTableError("no table")

    monkeypatch.setattr(model_policy, "get_active_routing_table", boom)
    d = route_model(ModelRoutingRequest(task_type="PRIMARY_AUDIT"))
    assert d.is_blocked and d.selected_model is None and "ROUTING_TABLE_UNAVAILABLE" in d.blocked_reason


# --- identifiers & attestation ------------------------------------------------------------------

@pytest.mark.parametrize("name, slug", [
    ("Gemini 4 Hydrogen (Medium)", "gemini-4-hydrogen-medium"),
    ("Gemini 4 Argon (High)", "gemini-4-argon-high"),
    ("gemini 3.8 flash (low)", "gemini-3.8-flash-low"),
    ("agy:gemini-4-hydrogen-high", "gemini-4-hydrogen-high"),
    ("Orchestrator (Argon)", None),
    ("", None),
])
def test_canonical_model_slug(name: str, slug: str | None) -> None:
    assert reg.canonical_model_slug(name) == slug


def test_resolve_observed_model_uses_display_and_checks_line() -> None:
    assert reg.resolve_observed_model("gemini-4-hydrogen", "Gemini 4 Hydrogen (Medium)") == "gemini-4-hydrogen-medium"
    assert reg.resolve_observed_model("gemini-4-argon-trial", "Gemini 4 Argon (High)") == "gemini-4-argon-high"
    assert reg.resolve_observed_model("gemini-4-hydrogen", "Gemini 4 Argon (High)") is None  # inconsistent record
    assert reg.resolve_observed_model("gemini-4-hydrogen", None) is None  # effort unknown
    assert reg.resolve_observed_model("gemini-4-argonx", "Gemini 4 Argon (High)") is None  # token boundary


def test_flash_medium_is_no_longer_attested_as_flash_high() -> None:
    """Regression: the old static map read the shared internal id first and attested every
    Flash record (internal id gemini-3.8-flash-n) as Flash High."""
    rec = parse_gen_metadata_blob(_blob(str(uuid.uuid4()), "gemini-3.8-flash-n", "Gemini 3.8 Flash (Medium)"))
    assert rec.canonical_model_id == "gemini-3.8-flash-medium"


def test_attestation_matches_real_agy_record_shapes(tmp_path: Path) -> None:
    conv, d = _conversation(tmp_path, "gemini-4-hydrogen", "Gemini 4 Hydrogen (High)")
    ok = attest_conversation_model(conv, "gemini-4-hydrogen-high", conversations_dir=d)
    assert ok.status == AttestationStatus.RUNTIME_ATTESTED and ok.observed_model == "gemini-4-hydrogen-high"
    effort = attest_conversation_model(conv, "gemini-4-hydrogen-medium", conversations_dir=d)
    assert effort.status == AttestationStatus.MODEL_ATTESTATION_MISMATCH
    conv2, d2 = _conversation(tmp_path, "gemini-4-argon-trial", "Gemini 4 Argon (Medium)")
    assert attest_conversation_model(conv2, "agy:gemini-4-argon-medium", conversations_dir=d2).is_attested


def test_attestation_rejects_inconsistent_record(tmp_path: Path) -> None:
    conv, d = _conversation(tmp_path, "gemini-4-hydrogen", "Gemini 4 Argon (High)")
    res = attest_conversation_model(conv, "gemini-4-argon-high", conversations_dir=d)
    assert not res.is_attested and res.status == AttestationStatus.MODEL_ATTESTATION_MISMATCH


def test_same_line_efforts_are_not_independent(tmp_path: Path) -> None:
    c1, d = _conversation(tmp_path, "gemini-4-hydrogen", "Gemini 4 Hydrogen (High)")
    c2, _ = _conversation(tmp_path, "gemini-4-hydrogen", "Gemini 4 Hydrogen (Medium)")
    c3, _ = _conversation(tmp_path, "gemini-4-argon-trial", "Gemini 4 Argon (Medium)")
    hi = attest_conversation_model(c1, "gemini-4-hydrogen-high", conversations_dir=d)
    med = attest_conversation_model(c2, "gemini-4-hydrogen-medium", conversations_dir=d)
    argon = attest_conversation_model(c3, "gemini-4-argon-medium", conversations_dir=d)
    assert verify_cross_model_independence(hi, med).status == CrossModelStatus.MODEL_INDEPENDENCE_UNVERIFIED
    assert verify_cross_model_independence(hi, argon).status == CrossModelStatus.CROSS_MODEL_VERIFIED

    ok, reason = verification_independence("gemini-4-hydrogen-high", "gemini-4-hydrogen-medium", "RUNTIME_ATTESTED")
    assert not ok and "same model line" in reason
    ok, _ = verification_independence("gemini-4-hydrogen-high", "gemini-4-argon-medium", "RUNTIME_ATTESTED")
    assert ok
    ok, reason = verification_independence("gemini-3.8-flash-high", "gemini-4-argon-medium", "RUNTIME_ATTESTED")
    assert not ok and "not an approved model" in reason


# --- adapter ---------------------------------------------------------------------------------------

def test_adapter_rejects_disallowed_models_and_accepts_qualified_refs(tmp_path: Path) -> None:
    exe = tmp_path / "agy.exe"
    exe.write_bytes(b"")
    adapter = AntigravityCliAdapter(executable_override=str(exe))
    cmd = adapter.build_command(prompt="hi", model_id="agy:gemini-4-hydrogen-high")
    assert cmd[cmd.index("--model") + 1] == "gemini-4-hydrogen-high"
    with pytest.raises(ValueError, match="flash"):
        adapter.build_command(prompt="hi", model_id="gemini-3.8-flash-high")
    with pytest.raises(ValueError, match="not allowed"):
        adapter.build_command(prompt="hi", model_id="claude-opus-5-5-high")
    with pytest.raises(ValueError, match="routing table"):
        adapter.build_command(prompt="hi", model_id="gemini-4-hydrogen-xhigh")


def test_backend_discovery_reports_extension_point() -> None:
    backends = {b.backend: b for b in reg.discover_dispatch_backends()}
    assert set(backends) == {"agy", "vibe"}
    assert backends["vibe"].available is False and "NOT_IMPLEMENTED" in backends["vibe"].detail


# --- regressions from the independent Argon review (2026-11-15) ---------------------------------

@pytest.mark.parametrize("backend, display", [
    (None, "Gemini 4 Argon (High)"),                     # missing internal id
    ("gemini-4-argon-trial", None),                      # missing display name
    ("gemini-4-hydrogen", "Gemini 4 Hydrogen"),          # display without effort
    ("gemini-4-argon-high", "Gemini 4 Hydrogen"),        # unparsable display must not fall back to internal id
    ("gemini-4-hydrogen", "gemini-4-hydrogen"),          # effort-less slug as display
    ("gemini-4-hydrogen-low", "Gemini 4 Hydrogen (High)"),  # internal effort contradicts display
])
def test_resolve_observed_model_fails_closed(backend: str | None, display: str | None) -> None:
    assert reg.resolve_observed_model(backend, display) is None


def test_attestation_refuses_record_of_another_conversation(tmp_path: Path) -> None:
    conv_id = str(uuid.uuid4())
    db = tmp_path / f"{conv_id}.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB, size INTEGER)")
    blob = _blob(str(uuid.uuid4()), "gemini-4-hydrogen", "Gemini 4 Hydrogen (High)")
    conn.execute("INSERT INTO gen_metadata VALUES (0, ?, ?)", (blob, len(blob)))
    conn.commit()
    conn.close()
    res = attest_conversation_model(conv_id, "gemini-4-hydrogen-high", conversations_dir=tmp_path)
    assert not res.is_attested and res.status == AttestationStatus.MODEL_ATTESTATION_INCOMPLETE


def test_same_model_line_is_conservative() -> None:
    assert reg.same_model_line("Gemini 4 Hydrogen (High)", "gemini-4-hydrogen-medium")
    assert reg.same_model_line("", "gemini-4-argon-medium")
    assert reg.same_model_line(None, None)
    assert reg.same_model_line("gemini-4-hydrogen-ultra", "gemini-4-hydrogen-high")
    assert not reg.same_model_line("gemini-4-hydrogen-high", "gemini-4-argon-high")


def test_independence_fails_closed_on_unnormalisable_observed_model(tmp_path: Path) -> None:
    conv, d = _conversation(tmp_path, "gemini-4-argon-trial", "Gemini 4 Argon (Medium)")
    argon = attest_conversation_model(conv, "gemini-4-argon-medium", conversations_dir=d)
    blank = argon.__class__(**{**argon.to_dict(), "observed_model": ""})
    assert verify_cross_model_independence(blank, argon).status == CrossModelStatus.MODEL_INDEPENDENCE_UNVERIFIED


def test_scarce_budget_cannot_be_bypassed(monkeypatch: pytest.MonkeyPatch) -> None:
    for ref in ("gemini-4-argon-high", "Gemini 4 Argon (High)", "vibe:gemini-4-argon-high", "gemini-5-argon-high"):
        assert reg.is_scarce_model(ref), ref
    monkeypatch.setenv(reg.HOST_APP_ENV, reg.HOST_CLAUDE_CODE)
    assert reg.is_scarce_model("gemini-4-argon-high")


def test_unknown_host_env_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(reg.HOST_APP_ENV, "totally-unknown-host")
    assert reg.current_host_app() == "totally-unknown-host"
    assert "fail closed" in reg.hard_policy_violation("gemini-4-hydrogen-high")
    assert not ModelId.is_approved("gemini-4-hydrogen-high")
    d = route_model(ModelRoutingRequest(task_type="PRIMARY_AUDIT"))
    assert d.is_blocked and d.selected_model is None


@pytest.mark.parametrize("bad", ["ollama:llama", ""])
def test_malformed_table_entry_blocks_instead_of_raising(bad: str) -> None:
    d = route_model(ModelRoutingRequest(task_type="PRIMARY_AUDIT"), routing_table=_table(STANDARD=bad))
    assert d.is_blocked and d.selected_model is None and d.routing_status is RoutingStatus.BLOCKED_MODEL_UNAVAILABLE


def test_rejected_override_does_not_touch_scarce_budget(tmp_path: Path) -> None:
    class RecordingBudget:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def __getattr__(self, name: str):  # any budget API call is recorded
            def _rec(*_a: object, **_k: object) -> None:
                self.calls.append(name)
                raise AssertionError(f"budget.{name} must not be called for a rejected override")
            return _rec

    exe = tmp_path / "agy.exe"
    exe.write_bytes(b"")
    budget = RecordingBudget()
    res = AntigravityCliAdapter(executable_override=str(exe)).start_new_conversation(
        "prompt", model_id="gemini-4-argon-low", audit_run_id="RUN-1",
        finding_fingerprint="fp", budget_tracker=budget,
    )
    assert not res.ok and res.status == "INVALID_MODEL" and budget.calls == []

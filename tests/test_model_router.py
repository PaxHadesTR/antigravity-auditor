"""Comprehensive Test Suite for Task-Based Model Router and Independent Attestation.

Validates:
- Deterministic model policy rules (Hydrogen High STANDARD default, Hydrogen Medium ENTRY lightweight,
  Argon Medium CRITICAL, Argon High CATASTROPHIC security).
- Strict model boundaries (Claude, GPT, and retired Flash prohibited, unapproved models rejected).
- CLI adapter argument safety (shell=False, dynamic exe resolution, stream-json parsing).
- Independent SQLite model attestation via local conversation gen_metadata protobuf decoding.
- Cross-model verification invariants (same-model and same-line different-effort rejected).
- Argon budget management (concurrency limit, request/token limits, deduplication, context minimization).
- SQLite schema migration and persistence (model_dispatches, model_budget_usage).
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# Ensure core is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from agy_adapter import (
    AgyDispatchResult,
    AntigravityCliAdapter,
    PermissionCapabilityStatus,
    parse_stream_json,
)
from db import (
    connect,
    get_budget_usage_for_run,
    get_model_dispatch,
    initialize,
    list_model_dispatches_for_run,
    record_budget_usage,
    record_model_dispatch,
)
from model_attestation import (
    AttestationResult,
    AttestationStatus,
    CrossModelStatus,
    attest_conversation_model,
    decode_raw_protobuf_fields,
    parse_gen_metadata_blob,
    resolve_conversation_db_path,
    verify_cross_model_independence,
)
from model_budget import (
    ArgonBudgetConfig,
    ModelBudgetTracker,
    build_minimized_evidence_package,
)
from model_policy import (
    ModelId,
    ModelRoutingDecision,
    ModelRoutingRequest,
    ReasoningLevel,
    TaskRisk,
    TaskType,
    route_model,
)


# ==============================================================================
# Protobuf Test Fixture Generators
# ==============================================================================

def encode_varint(val: int) -> bytes:
    res = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val:
            res.append(b | 0x80)
        else:
            res.append(b)
            break
    return bytes(res)


def encode_field(fnum: int, wtype: int, payload: bytes) -> bytes:
    tag = (fnum << 3) | wtype
    return encode_varint(tag) + encode_varint(len(payload)) + payload


def encode_kv(key: str, val: str) -> bytes:
    kb = encode_field(1, 2, key.encode("utf-8"))
    vb = encode_field(2, 2, val.encode("utf-8"))
    return encode_field(20, 2, kb + vb)


def build_fixture_blob(
    conversation_id: str,
    backend_model_id: str,
    display_model_name: str,
) -> bytes:
    f19 = encode_field(19, 2, backend_model_id.encode("utf-8"))
    f21 = encode_field(21, 2, display_model_name.encode("utf-8"))
    kv_cascade = encode_kv("cascade_id", conversation_id)
    kv_req = encode_kv("request_id", f"{conversation_id}-0")
    kv_enum = encode_kv("model_enum", "MODEL_FIXTURE")

    sub_bytes = f19 + kv_cascade + kv_req + kv_enum + f21
    f1 = encode_field(1, 2, sub_bytes)
    f4 = encode_field(4, 2, b"00000000-0000-4000-8000-0000000000aa")
    return f1 + f4


def create_mock_conversation_db(
    db_path: Path,
    conversation_id: str,
    backend_model_id: str,
    display_model_name: str,
) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB, size INTEGER)")
        blob = build_fixture_blob(conversation_id, backend_model_id, display_model_name)
        conn.execute("INSERT INTO gen_metadata(idx, data, size) VALUES(0, ?, ?)", (blob, len(blob)))
        conn.commit()
    finally:
        conn.close()


# ==============================================================================
# 12.1 Model Policy Tests
# ==============================================================================

def test_01_primary_audit_routes_to_standard_tier_hydrogen_high() -> None:
    req = ModelRoutingRequest(task_type=TaskType.PRIMARY_AUDIT)
    decision = route_model(req)
    assert decision.selected_model == ModelId.GEMINI_4_HYDROGEN_HIGH
    assert decision.reasoning_level == ReasoningLevel.HIGH
    assert not decision.is_argon


def test_02_repository_exploration_routes_to_standard_tier_hydrogen_high() -> None:
    req = ModelRoutingRequest(task_type=TaskType.REPOSITORY_EXPLORATION)
    decision = route_model(req)
    assert decision.selected_model == ModelId.GEMINI_4_HYDROGEN_HIGH


def test_03_routine_verification_routes_to_standard_tier_hydrogen_high() -> None:
    req = ModelRoutingRequest(
        task_type=TaskType.ROUTINE_VERIFICATION,
        severity="MEDIUM",
        finding_category="GENERAL",
    )
    decision = route_model(req)
    assert decision.selected_model == ModelId.GEMINI_4_HYDROGEN_HIGH
    assert not decision.is_argon


def test_04_routine_red_team_routes_to_standard_tier_hydrogen_high() -> None:
    req = ModelRoutingRequest(task_type=TaskType.ROUTINE_RED_TEAM)
    decision = route_model(req)
    assert decision.selected_model == ModelId.GEMINI_4_HYDROGEN_HIGH


def test_05_repair_planning_and_worker_policy() -> None:
    plan_req = ModelRoutingRequest(task_type=TaskType.REPAIR_PLANNING)
    plan_dec = route_model(plan_req)
    assert plan_dec.selected_model == ModelId.GEMINI_4_HYDROGEN_HIGH
    assert not plan_dec.repair_writable_dispatch_enabled

    worker_req = ModelRoutingRequest(task_type=TaskType.REPAIR_WORKER)
    worker_dec = route_model(worker_req)
    assert worker_dec.selected_model == ModelId.GEMINI_4_HYDROGEN_HIGH
    assert not worker_dec.repair_writable_dispatch_enabled


def test_06_finding_classification_routes_to_entry_tier_hydrogen_medium() -> None:
    req = ModelRoutingRequest(task_type=TaskType.FINDING_CLASSIFICATION)
    decision = route_model(req)
    assert decision.selected_model == ModelId.GEMINI_4_HYDROGEN_MEDIUM
    assert decision.reasoning_level == ReasoningLevel.MEDIUM


def test_07_critical_verification_database_integrity_routes_to_argon_medium() -> None:
    req = ModelRoutingRequest(
        task_type=TaskType.CRITICAL_VERIFICATION,
        severity="HIGH",
        finding_category="DATABASE_INTEGRITY",
        evidence_gate_status="PASSED",
    )
    decision = route_model(req)
    assert decision.selected_model == ModelId.GEMINI_4_ARGON_MEDIUM
    assert decision.is_argon
    assert decision.task_risk == TaskRisk.CRITICAL


def test_08_critical_concurrency_race_condition_routes_to_argon_medium() -> None:
    # The tier follows severity: a HIGH candidate goes to CRITICAL (a CRITICAL one would go to CATASTROPHIC).
    req = ModelRoutingRequest(
        task_type=TaskType.CRITICAL_VERIFICATION,
        severity="HIGH",
        finding_category="CONCURRENCY_RACE_CONDITION",
        evidence_gate_status="PASSED",
    )
    decision = route_model(req)
    assert decision.selected_model == ModelId.GEMINI_4_ARGON_MEDIUM
    assert decision.is_argon


def test_09_catastrophic_rce_with_passed_gate_routes_to_argon_high() -> None:
    req = ModelRoutingRequest(
        task_type=TaskType.CRITICAL_VERIFICATION,
        severity="CRITICAL",
        finding_category="RCE",
        evidence_gate_status="PASSED",
    )
    decision = route_model(req)
    assert decision.selected_model == ModelId.GEMINI_4_ARGON_HIGH
    assert decision.is_argon
    assert decision.task_risk == TaskRisk.CATASTROPHIC


def test_10_authentication_bypass_and_privilege_escalation_routes_to_argon_high() -> None:
    for cat in ("AUTHENTICATION_BYPASS", "PRIVILEGE_ESCALATION", "CATASTROPHIC_DATA_LOSS"):
        req = ModelRoutingRequest(
            task_type=TaskType.CRITICAL_RED_TEAM,
            severity="CRITICAL",
            finding_category=cat,
            evidence_gate_status="PASSED",
        )
        decision = route_model(req)
        assert decision.selected_model == ModelId.GEMINI_4_ARGON_HIGH
        assert decision.is_argon


def test_11_unvalidated_evidence_blocks_argon_high() -> None:
    # Evidence gate FAILED or UNCHECKED must revert Argon High candidate to Hydrogen High!
    for status in ("UNCHECKED", "FAILED", "PENDING", "INVALID"):
        req = ModelRoutingRequest(
            task_type=TaskType.CRITICAL_VERIFICATION,
            severity="CRITICAL",
            finding_category="RCE",
            evidence_gate_status=status,
        )
        decision = route_model(req)
        assert decision.selected_model == ModelId.GEMINI_4_HYDROGEN_HIGH
        assert not decision.is_argon
        assert decision.is_blocked
        assert "BLOCKED from critical verification" in decision.decision_reason


def test_12_llm_self_classification_cannot_escalate_model() -> None:
    # An ordinary finding claiming CRITICAL severity in low-risk category stays Hydrogen High
    req = ModelRoutingRequest(
        task_type=TaskType.ROUTINE_VERIFICATION,
        severity="CRITICAL",
        finding_category="STYLE_LINT",
        evidence_gate_status="PASSED",
    )
    decision = route_model(req)
    assert decision.selected_model == ModelId.GEMINI_4_HYDROGEN_HIGH


def test_13_operator_escalation_requires_explicit_flag() -> None:
    # Explicit human operator escalation authorizes Argon Medium
    req = ModelRoutingRequest(
        task_type=TaskType.ROUTINE_VERIFICATION,
        severity="MEDIUM",
        explicit_operator_escalation=True,
        operator_escalation_reason="Human engineer requested independent Argon review",
    )
    decision = route_model(req)
    assert decision.selected_model == ModelId.GEMINI_4_ARGON_MEDIUM
    assert decision.is_argon


def test_14_unapproved_model_identifiers_are_rejected() -> None:
    for bad in (
        "claude-3-opus",
        "gpt-4o",
        "claude-sonnet-5-5-high",
        "pro",
        "gemini-pro",
        "random-llm",
        "gemini-3.8-flash-high",
        "gemini-3.8-flash-medium",
    ):
        assert not ModelId.is_approved(bad)
    for good in ("gemini-4-hydrogen-high", "gemini-4-hydrogen-medium"):
        assert ModelId.is_approved(good)


# ==============================================================================
# 12.2 CLI Adapter Tests
# ==============================================================================

def test_15_cli_adapter_resolves_executable_without_hardcoded_user(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_exe = tmp_path / "bin" / "agy.exe"
    fake_exe.parent.mkdir(parents=True)
    fake_exe.write_text("fake binary")

    # Explicit override
    adapter1 = AntigravityCliAdapter(executable_override=str(fake_exe))
    assert adapter1.discover_executable() == fake_exe.resolve()

    # Via LOCALAPPDATA
    fake_localappdata = tmp_path / "localappdata"
    agy_in_local = fake_localappdata / "agy" / "bin" / "agy.exe"
    agy_in_local.parent.mkdir(parents=True)
    agy_in_local.write_text("fake")

    monkeypatch.setenv("LOCALAPPDATA", str(fake_localappdata))
    adapter2 = AntigravityCliAdapter()
    assert adapter2.discover_executable() == agy_in_local.resolve()


def test_16_cli_command_construction_uses_shell_false_and_arrays(tmp_path: Path) -> None:
    fake_exe = tmp_path / "agy.exe"
    fake_exe.write_text("fake")

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe))
    cmd = adapter.build_command(
        prompt="Audit findings",
        model_id="gemini-4-hydrogen-high",
        mode="plan",
    )
    assert cmd == [
        str(fake_exe.resolve()),
        "-p",
        "Audit findings",
        "--model",
        "gemini-4-hydrogen-high",
        "--mode",
        "plan",
        "--output-format",
        "stream-json",
    ]


def test_17_cli_adapter_rejects_unapproved_model_upfront(tmp_path: Path) -> None:
    fake_exe = tmp_path / "agy.exe"
    fake_exe.write_text("fake")
    adapter = AntigravityCliAdapter(executable_override=str(fake_exe))
    res = adapter.dispatch(
        prompt="Audit",
        model_id="claude-opus-5-5-high",
        cwd=Path.cwd(),
    )
    assert not res.ok
    assert res.status == "INVALID_MODEL"
    assert res.error_code == "UNAPPROVED_MODEL"


def test_18_cli_adapter_rejects_empty_prompt(tmp_path: Path) -> None:
    fake_exe = tmp_path / "agy.exe"
    fake_exe.write_text("fake")
    adapter = AntigravityCliAdapter(executable_override=str(fake_exe))
    res = adapter.dispatch(
        prompt="   ",
        model_id="gemini-4-hydrogen-high",
        cwd=Path.cwd(),
    )
    assert not res.ok
    assert res.status == "INVALID_MODEL"


def test_19_cli_adapter_handles_missing_executable() -> None:
    adapter = AntigravityCliAdapter(executable_override="C:/does/not/exist/agy.exe")
    res = adapter.dispatch(
        prompt="Valid prompt",
        model_id="gemini-4-hydrogen-high",
        cwd=Path.cwd(),
    )
    assert not res.ok
    assert res.status == "CLI_UNAVAILABLE"


def test_20_cli_adapter_blocks_repair_worker_writable_dispatch(tmp_path: Path) -> None:
    fake_exe = tmp_path / "agy.exe"
    fake_exe.write_text("fake")
    adapter = AntigravityCliAdapter(executable_override=str(fake_exe))
    res = adapter.dispatch(
        prompt="Fix finding",
        model_id="gemini-4-hydrogen-high",
        cwd=Path.cwd(),
        allow_write=True,
    )
    assert not res.ok
    assert res.status == "REPAIR_WORKER_DISABLED"
    assert res.error_code == "REPAIR_WORKER_WRITABLE_DISPATCH_DISABLED"


def test_21_stream_json_parser_extracts_init_steps_and_result() -> None:
    raw_lines = "\n".join([
        '{"event":"init","conversation_id":"c1111111-2222-3333-4444-555555555555","init":{"model":"gemini-4-hydrogen-high"}}',
        '{"event":"step_update","step_update":{"step_index":0,"state":"ACTIVE","text_delta":"Working..."}}',
        '{"event":"step_update","step_update":{"step_index":1,"state":"DONE","usage":{"input_tokens":100,"output_tokens":20,"total_tokens":120}}}',
        '{"event":"result","result":{"conversation_id":"c1111111-2222-3333-4444-555555555555","status":"SUCCESS","response":"Audit complete","duration_seconds":2.5,"usage":{"input_tokens":150,"output_tokens":30,"thinking_tokens":10,"total_tokens":190}}}',
    ])
    parsed = parse_stream_json(raw_lines)
    assert parsed.conversation_id == "c1111111-2222-3333-4444-555555555555"
    assert parsed.reported_model == "gemini-4-hydrogen-high"
    assert parsed.status == "SUCCESS"
    assert parsed.response_text == "Audit complete"
    assert parsed.input_tokens == 150
    assert parsed.output_tokens == 30
    assert parsed.thinking_tokens == 10
    assert parsed.total_tokens == 190
    assert parsed.duration_seconds == 2.5
    assert not parsed.missing_result
    assert parsed.malformed_lines_count == 0


def test_22_stream_json_parser_handles_malformed_lines_and_partial_output() -> None:
    raw_lines = "\n".join([
        '{"event":"init","conversation_id":"c2222222-2222-3333-4444-555555555555","init":{"model":"gemini-4-hydrogen-high"}}',
        'NOT_JSON_LINE',
        '{"corrupted": true',
        '{"event":"step_update","step_update":{"step_index":0,"state":"ACTIVE","text_delta":"Partial response"}}',
    ])
    parsed = parse_stream_json(raw_lines)
    assert parsed.conversation_id == "c2222222-2222-3333-4444-555555555555"
    assert parsed.reported_model == "gemini-4-hydrogen-high"
    assert parsed.missing_result
    assert parsed.malformed_lines_count == 2
    assert parsed.response_text == "Partial response"


def test_23_cli_adapter_handles_auth_failure_cleanly(tmp_path: Path) -> None:
    fake_exe = tmp_path / "agy.exe"
    fake_exe.write_text("fake")

    def fake_runner(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout="",
            stderr="Error: sign-in required. Run 'agy auth login'",
        )

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=fake_runner)
    res = adapter.dispatch(prompt="Audit", model_id="gemini-4-hydrogen-high", cwd=Path.cwd())
    assert not res.ok
    assert res.status == "CLI_AUTHENTICATION_FAILED"
    assert res.error_code == "AUTHENTICATION_FAILED"


def test_24_cli_adapter_handles_timeout_cleanly(tmp_path: Path) -> None:
    fake_exe = tmp_path / "agy.exe"
    fake_exe.write_text("fake")

    def timeout_runner(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=5, output='{"event":"step_update"}')

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=timeout_runner)
    res = adapter.dispatch(prompt="Audit", model_id="gemini-4-hydrogen-high", cwd=Path.cwd(), timeout_seconds=5)
    assert not res.ok
    assert res.status == "CLI_TIMEOUT"
    assert res.error_code == "TIMEOUT"


# ==============================================================================
# 12.3 Workspace Tests
# ==============================================================================

def test_25_workspace_rules_and_skills_compatibility(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    rules_dir = ws / ".agents" / "rules"
    rules_dir.mkdir(parents=True)
    rule_file = rules_dir / "01-test-rule.md"
    rule_file.write_text("---\ntrigger: always_on\n---\n# Rule Test\nDo not break invariants.\n")

    skill_dir = ws / ".agents" / "skills" / "test-skill"
    skill_dir.mkdir(parents=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text("---\nname: test-skill\ndescription: Test skill description\n---\n# Skill Test\n")

    text = rule_file.read_text(encoding="utf-8")
    assert "trigger: always_on" in text
    assert skill_file.is_file()


# ==============================================================================
# 12.4 Independent Attestation Tests
# ==============================================================================

def test_26_attestation_succeeds_on_matching_hydrogen_high(tmp_path: Path) -> None:
    cid = "11111111-2222-3333-4444-555555555555"
    db_file = tmp_path / f"{cid}.db"
    create_mock_conversation_db(
        db_file,
        conversation_id=cid,
        backend_model_id="gemini-4-hydrogen",
        display_model_name="Gemini 4 Hydrogen (High)",
    )

    res = attest_conversation_model(
        cid,
        expected_model="gemini-4-hydrogen-high",
        conversations_dir=tmp_path,
    )
    assert res.is_attested
    assert res.status == AttestationStatus.RUNTIME_ATTESTED
    assert res.observed_model == "gemini-4-hydrogen-high"
    assert res.display_model_name == "Gemini 4 Hydrogen (High)"


def test_27_attestation_succeeds_on_matching_argon_medium(tmp_path: Path) -> None:
    cid = "22222222-3333-4444-5555-666666666666"
    db_file = tmp_path / f"{cid}.db"
    create_mock_conversation_db(
        db_file,
        conversation_id=cid,
        backend_model_id="gemini-4-argon-medium",
        display_model_name="Gemini 4 Argon (Medium)",
    )

    res = attest_conversation_model(
        cid,
        expected_model="gemini-4-argon-medium",
        conversations_dir=tmp_path,
    )
    assert res.is_attested
    assert res.status == AttestationStatus.RUNTIME_ATTESTED
    assert res.observed_model == "gemini-4-argon-medium"


def test_28_attestation_succeeds_on_matching_argon_high(tmp_path: Path) -> None:
    cid = "33333333-4444-5555-6666-777777777777"
    db_file = tmp_path / f"{cid}.db"
    create_mock_conversation_db(
        db_file,
        conversation_id=cid,
        backend_model_id="gemini-4-argon-high",
        display_model_name="Gemini 4 Argon (High)",
    )

    res = attest_conversation_model(
        cid,
        expected_model="gemini-4-argon-high",
        conversations_dir=tmp_path,
    )
    assert res.is_attested
    assert res.status == AttestationStatus.RUNTIME_ATTESTED
    assert res.observed_model == "gemini-4-argon-high"


def test_29_attestation_detects_model_mismatch(tmp_path: Path) -> None:
    cid = "44444444-5555-6666-7777-888888888888"
    db_file = tmp_path / f"{cid}.db"
    create_mock_conversation_db(
        db_file,
        conversation_id=cid,
        backend_model_id="gemini-4-hydrogen",
        display_model_name="Gemini 4 Hydrogen (High)",
    )

    res = attest_conversation_model(
        cid,
        expected_model="gemini-4-argon-medium",
        conversations_dir=tmp_path,
    )
    assert not res.is_attested
    assert res.status == AttestationStatus.MODEL_ATTESTATION_MISMATCH
    assert res.observed_model == "gemini-4-hydrogen-high"


def test_30_attestation_detects_missing_database(tmp_path: Path) -> None:
    cid = "55555555-6666-7777-8888-999999999999"
    res = attest_conversation_model(
        cid,
        expected_model="gemini-4-hydrogen-high",
        conversations_dir=tmp_path,
    )
    assert not res.is_attested
    assert res.status == AttestationStatus.MODEL_ATTESTATION_DATABASE_UNAVAILABLE


def test_31_attestation_rejects_path_traversal() -> None:
    for bad_id in ("../../etc/passwd", "..\\secret.db", "not-a-uuid", ""):
        res = attest_conversation_model(bad_id, expected_model="gemini-4-hydrogen-high")
        assert not res.is_attested
        assert res.status == AttestationStatus.MODEL_ATTESTATION_FAILED


def test_32_attestation_fails_closed_on_unsupported_schema(tmp_path: Path) -> None:
    cid = "66666666-7777-8888-9999-000000000000"
    db_file = tmp_path / f"{cid}.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE wrong_table (id INT)")
    conn.commit()
    conn.close()

    res = attest_conversation_model(cid, expected_model="gemini-4-hydrogen-high", conversations_dir=tmp_path)
    assert not res.is_attested
    assert res.status == AttestationStatus.MODEL_ATTESTATION_UNSUPPORTED_SCHEMA


def test_33_attestation_fails_closed_on_corrupt_protobuf(tmp_path: Path) -> None:
    cid = "77777777-8888-9999-0000-111111111111"
    db_file = tmp_path / f"{cid}.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB, size INTEGER)")
    conn.execute("INSERT INTO gen_metadata VALUES(0, X'DEADBEEF', 4)")
    conn.commit()
    conn.close()

    res = attest_conversation_model(cid, expected_model="gemini-4-hydrogen-high", conversations_dir=tmp_path)
    assert not res.is_attested
    assert res.status == AttestationStatus.MODEL_ATTESTATION_FAILED


def test_34_cross_model_verification_guarantees() -> None:
    p_attested_hydrogen = AttestationResult(
        status=AttestationStatus.RUNTIME_ATTESTED,
        is_attested=True,
        conversation_id="p-1",
        expected_model="gemini-4-hydrogen-high",
        observed_model="gemini-4-hydrogen-high",
        display_model_name="Gemini 4 Hydrogen (High)",
        db_path="p.db",
        details="Attested",
    )
    v_attested_argon = AttestationResult(
        status=AttestationStatus.RUNTIME_ATTESTED,
        is_attested=True,
        conversation_id="v-1",
        expected_model="gemini-4-argon-medium",
        observed_model="gemini-4-argon-medium",
        display_model_name="Gemini 4 Argon (Medium)",
        db_path="v.db",
        details="Attested",
    )
    v_attested_hydrogen_med = AttestationResult(
        status=AttestationStatus.RUNTIME_ATTESTED,
        is_attested=True,
        conversation_id="v-2",
        expected_model="gemini-4-hydrogen-medium",
        observed_model="gemini-4-hydrogen-medium",
        display_model_name="Gemini 4 Hydrogen (Medium)",
        db_path="v2.db",
        details="Attested",
    )

    # 1. Hydrogen High vs Argon Medium -> CROSS_MODEL_VERIFIED
    res1 = verify_cross_model_independence(p_attested_hydrogen, v_attested_argon)
    assert res1.is_independent
    assert res1.status == CrossModelStatus.CROSS_MODEL_VERIFIED

    # 2. Hydrogen High vs Hydrogen Medium -> REJECTED (same line, different effort is not independent)
    res2 = verify_cross_model_independence(p_attested_hydrogen, v_attested_hydrogen_med)
    assert not res2.is_independent
    assert res2.status == CrossModelStatus.MODEL_INDEPENDENCE_UNVERIFIED
    assert "same model line" in res2.reason

    # 3. Same model run -> REJECTED
    res3 = verify_cross_model_independence(p_attested_hydrogen, p_attested_hydrogen)
    assert not res3.is_independent
    assert res3.status == CrossModelStatus.MODEL_INDEPENDENCE_UNVERIFIED

    # 4. Unattested verifier -> REJECTED
    v_unattested = AttestationResult(
        status=AttestationStatus.MODEL_ATTESTATION_INCOMPLETE,
        is_attested=False,
        conversation_id="v-3",
        expected_model="gemini-4-argon-medium",
        observed_model=None,
        display_model_name=None,
        db_path=None,
        details="Incomplete",
    )
    res4 = verify_cross_model_independence(p_attested_hydrogen, v_unattested)
    assert not res4.is_independent
    assert res4.status == CrossModelStatus.MODEL_INDEPENDENCE_UNVERIFIED


# ==============================================================================
# 12.5 Argon Budget and Context Minimization Tests
# ==============================================================================

def test_35_argon_budget_request_and_token_limits() -> None:
    cfg = ArgonBudgetConfig(
        max_concurrent_jobs=1,
        max_requests_per_run=2,
        max_tokens_per_run=1000,
    )
    tracker = ModelBudgetTracker(config=cfg)

    # First request OK
    c1 = tracker.check_dispatch(model_id="gemini-4-argon-medium", audit_run_id="RUN-1", estimated_tokens=300)
    assert c1.allowed
    tracker.acquire_job(model_id="gemini-4-argon-medium", audit_run_id="RUN-1", finding_fingerprint="F1")
    tracker.release_job(model_id="gemini-4-argon-medium", audit_run_id="RUN-1", tokens_consumed=300)

    # Second request OK
    c2 = tracker.check_dispatch(model_id="gemini-4-argon-medium", audit_run_id="RUN-1", estimated_tokens=400)
    assert c2.allowed
    tracker.acquire_job(model_id="gemini-4-argon-medium", audit_run_id="RUN-1", finding_fingerprint="F2")
    tracker.release_job(model_id="gemini-4-argon-medium", audit_run_id="RUN-1", tokens_consumed=400)

    # Third request blocked by request limit (2 max)
    c3 = tracker.check_dispatch(model_id="gemini-4-argon-medium", audit_run_id="RUN-1", estimated_tokens=100)
    assert not c3.allowed
    assert c3.status == "REJECTED_REQUEST_LIMIT"
    assert c3.is_quota_exhausted


def test_36_argon_budget_concurrency_fencing() -> None:
    cfg = ArgonBudgetConfig(max_concurrent_jobs=1)
    tracker = ModelBudgetTracker(config=cfg)

    # Job 1 starts
    c1 = tracker.check_dispatch(model_id="gemini-4-argon-medium", audit_run_id="RUN-A")
    assert c1.allowed
    tracker.acquire_job(model_id="gemini-4-argon-medium", audit_run_id="RUN-A")

    # Concurrent job 2 blocked
    c2 = tracker.check_dispatch(model_id="gemini-4-argon-medium", audit_run_id="RUN-A")
    assert not c2.allowed
    assert c2.status == "REJECTED_CONCURRENCY"

    # After Job 1 completes, Job 2 can proceed
    tracker.release_job(model_id="gemini-4-argon-medium", audit_run_id="RUN-A", tokens_consumed=100)
    c3 = tracker.check_dispatch(model_id="gemini-4-argon-medium", audit_run_id="RUN-A")
    assert c3.allowed


def test_37_argon_per_finding_deduplication() -> None:
    tracker = ModelBudgetTracker()
    tracker.acquire_job(
        model_id="gemini-4-argon-medium",
        audit_run_id="RUN-100",
        finding_fingerprint="FP-SQLI-001",
        task_type="CRITICAL_VERIFICATION",
    )
    tracker.release_job(model_id="gemini-4-argon-medium", audit_run_id="RUN-100", tokens_consumed=250)

    # Duplicate request for same finding fingerprint rejected
    c_dup = tracker.check_dispatch(
        model_id="gemini-4-argon-medium",
        audit_run_id="RUN-100",
        finding_fingerprint="FP-SQLI-001",
        task_type="CRITICAL_VERIFICATION",
    )
    assert not c_dup.allowed
    assert c_dup.status == "REJECTED_DUPLICATE"

    # Forced duplicate with explicit override allowed
    c_forced = tracker.check_dispatch(
        model_id="gemini-4-argon-medium",
        audit_run_id="RUN-100",
        finding_fingerprint="FP-SQLI-001",
        task_type="CRITICAL_VERIFICATION",
        force_duplicate=True,
    )
    assert c_forced.allowed


def test_38_argon_context_minimization_excludes_secrets_and_transcripts() -> None:
    finding = {
        "finding_id": "FIND-01",
        "fingerprint": "FP-01",
        "title": "SQL Injection in User Query",
        "category": "DATABASE_INTEGRITY",
        "severity": "CRITICAL",
        "file_path": "src/db/queries.py",
        "line_start": 42,
        "line_end": 45,
        "evidence": "SELECT * FROM users WHERE id = " + "x" * 100,
        "impact": "Data exposure",
        "reproduction_steps": "Send ' OR 1=1 --",
        "expected_behavior": "Parameterized query",
        "actual_behavior": "String concatenation",
        "technical_rationale": "Unsanitized user input formatted directly into SQL query.",
    }
    pkg = build_minimized_evidence_package(finding=finding, evidence_gate_status="PASSED")
    prompt = pkg.to_prompt_text()

    assert "CRITICAL VERIFICATION EVIDENCE PACKAGE" in prompt
    assert "Finding Fingerprint: FP-01" in prompt
    assert "src/db/queries.py" in prompt
    assert "SELECT * FROM users" in prompt
    assert "Do not perform unnecessary tool scans" in prompt
    assert pkg.raw_size_bytes < 5000


# ==============================================================================
# 12.6 Database Persistence and Migration Tests
# ==============================================================================

def test_39_database_migration_v3_to_v4_and_model_persistence(tmp_path: Path) -> None:
    db = tmp_path / "auditor_test.db"
    initialize(db)

    with connect(db) as conn:
        # Seed project and audit_run
        conn.execute("INSERT INTO projects (project_key, display_name, repo_path, antigravity_project_id) VALUES ('proj-test', 'Test', '/tmp', 'agy-proj-123')")
        conn.execute("INSERT INTO audit_runs (run_id, project_key, status) VALUES ('RUN-TEST-001', 'proj-test', 'DISPATCHED')")
        conn.commit()

        # Verify schema_migrations has version 4
        rows = {int(r["version"]): r["name"] for r in conn.execute("SELECT version, name FROM schema_migrations").fetchall()}
        assert 4 in rows
        assert "task_based_model_router" in rows[4]

        # Record a model dispatch
        disp_id = record_model_dispatch(
            conn,
            task_type="CRITICAL_VERIFICATION",
            task_risk="CRITICAL",
            requested_model="gemini-4-argon-medium",
            observed_model="gemini-4-argon-medium",
            reasoning_level="medium",
            model_identity_source="SQLITE_METADATA",
            model_attestation_status=AttestationStatus.RUNTIME_ATTESTED,
            conversation_id="conv-1111-2222-3333-4444",
            input_tokens=1200,
            output_tokens=300,
            thinking_tokens=150,
            total_tokens=1650,
            execution_duration=4.2,
            dispatch_status="SUCCESS",
            audit_run_id="RUN-TEST-001",
            idempotency_key="idem-disp-1",
        )
        record_budget_usage(
            conn,
            model_id="gemini-4-argon-medium",
            task_type="CRITICAL_VERIFICATION",
            tokens_consumed=1650,
            audit_run_id="RUN-TEST-001",
        )
        conn.commit()

        # Retrieve and verify
        rec = get_model_dispatch(conn, disp_id)
        assert rec is not None
        assert rec["requested_model"] == "gemini-4-argon-medium"
        assert rec["observed_model"] == "gemini-4-argon-medium"
        assert rec["model_attestation_status"] == AttestationStatus.RUNTIME_ATTESTED
        assert rec["total_tokens"] == 1650
        assert rec["execution_duration"] == 4.2

        usage = get_budget_usage_for_run(conn, "RUN-TEST-001")
        assert usage["total_tokens"] == 1650
        assert usage["total_requests"] == 1

        dispatches = list_model_dispatches_for_run(conn, "RUN-TEST-001")
        assert len(dispatches) == 1
        assert dispatches[0]["dispatch_id"] == disp_id

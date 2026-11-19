"""Regression tests for the full-project review fixes (2026-11-15)."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agy_adapter import AntigravityCliAdapter  # noqa: E402
from db import connect, initialize, recover_stale_runs, reserve_argon_budget_atomic  # noqa: E402
from model_attestation import AttestationStatus, attest_conversation_model  # noqa: E402
from model_budget import ArgonBudgetConfig, ModelBudgetTracker  # noqa: E402
from model_policy import ExecutionIntent, ModelRoutingRequest, RoutingStatus, TaskType, route_model  # noqa: E402
from runtime_discovery.redaction import redact_text  # noqa: E402
from test_model_router import build_fixture_blob  # noqa: E402

ARGON = "gemini-4-argon-medium"
HYDROGEN = "gemini-4-hydrogen-high"


# --- secret redaction -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"password": "my-super-secret-pass"}',
        '{"api_key": "custom_secret_12345"}',
        '{"authorization": "Basic_custom_token_12345"}',
        "{'client_secret': 'abc123def456'}",
    ],
)
def test_json_quoted_secrets_are_redacted(text: str) -> None:
    out = redact_text(text)
    assert "<REDACTED>" in out
    assert "secret-pass" not in out and "12345" not in out and "abc123" not in out


def test_non_secret_keys_are_untouched() -> None:
    assert redact_text('{"project_key": "demo"}') == '{"project_key": "demo"}'


# --- model routing / dispatch -----------------------------------------------------------------------------


def _adapter_with_fake_dispatch(calls: list, *, raise_exc: Exception | None = None) -> AntigravityCliAdapter:
    adapter = AntigravityCliAdapter(executable_override="agy-not-used")

    def fake_dispatch(**kwargs):
        calls.append(kwargs)
        if raise_exc is not None:
            raise raise_exc
        raise AssertionError("dispatch must not be reached in this test")

    adapter.dispatch = fake_dispatch  # type: ignore[method-assign]
    return adapter


def test_explicit_model_cannot_bypass_disabled_repair_worker() -> None:
    calls: list = []
    res = _adapter_with_fake_dispatch(calls).start_new_conversation(
        "x", task_type=TaskType.REPAIR_WORKER, model_id=HYDROGEN
    )
    assert not res.ok and calls == []


def test_explicit_model_cannot_bypass_evidence_gate() -> None:
    calls: list = []
    res = _adapter_with_fake_dispatch(calls).start_new_conversation(
        "x",
        task_type=TaskType.CRITICAL_VERIFICATION,
        severity="CRITICAL",
        finding_category="DATABASE_INTEGRITY",
        evidence_gate_status="FAILED",
        execution_intent=ExecutionIntent.REQUIRED_CRITICAL_VERIFICATION,
        model_id=ARGON,
    )
    assert not res.ok and res.status == RoutingStatus.BLOCKED_EVIDENCE.value and calls == []


def test_explicit_scarce_model_cannot_escalate_a_standard_task() -> None:
    calls: list = []
    res = _adapter_with_fake_dispatch(calls).start_new_conversation(
        "x", task_type=TaskType.PRIMARY_AUDIT, model_id=ARGON
    )
    assert not res.ok and res.status == "EXPLICIT_MODEL_EXCEEDS_TIER" and calls == []


def test_budget_is_released_when_dispatch_raises() -> None:
    calls: list = []
    tracker = ModelBudgetTracker(ArgonBudgetConfig(max_concurrent_jobs=1))
    adapter = _adapter_with_fake_dispatch(calls, raise_exc=OSError("boom"))
    with pytest.raises(OSError):
        adapter.start_new_conversation(
            "x",
            task_type=TaskType.CRITICAL_VERIFICATION,
            severity="CRITICAL",
            finding_category="DATABASE_INTEGRITY",
            evidence_gate_status="PASSED",
            execution_intent=ExecutionIntent.REQUIRED_CRITICAL_VERIFICATION,
            audit_run_id="RUN-1",
            finding_fingerprint="fp-1",
            budget_tracker=tracker,
            model_id=ARGON,
        )
    assert len(calls) == 1
    assert tracker.get_run_usage("RUN-1")["active_jobs"] == 0


def test_task_type_is_persisted_by_value(tmp_path: Path) -> None:
    db_path = tmp_path / "auditor.db"
    initialize(db_path)
    calls: list = []
    _adapter_with_fake_dispatch(calls).start_new_conversation(
        "x", task_type=TaskType.REPAIR_WORKER, db_path=db_path
    )
    with connect(db_path) as conn:
        task_types = [r[0] for r in conn.execute("SELECT task_type FROM model_dispatches").fetchall()]
    assert task_types == ["REPAIR_WORKER"]


def test_catastrophic_tier_requires_a_critical_task() -> None:
    req = ModelRoutingRequest(
        task_type=TaskType.REPORT_GENERATION,
        severity="CRITICAL",
        finding_category="RCE",
        evidence_gate_status="PASSED",
    )
    decision = route_model(req)
    assert not decision.is_argon and not decision.is_blocked


def test_daily_budget_is_enforced_on_the_sqlite_path(tmp_path: Path) -> None:
    db_path = tmp_path / "auditor.db"
    initialize(db_path)
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO model_budget_usage(audit_run_id, model_id, task_type, tokens_consumed) VALUES(?,?,?,?)",
            ("RUN-OLD", ARGON, "CRITICAL_VERIFICATION", 900),
        )
        conn.commit()
    conn = connect(db_path)
    conn.isolation_level = None
    try:
        res = reserve_argon_budget_atomic(
            conn, audit_run_id="RUN-2", model_id=ARGON, estimated_tokens=200, daily_token_budget=1000
        )
    finally:
        conn.close()
    assert res["allowed"] is False and res["status"] == "REJECTED_TOKEN_LIMIT"


# --- attestation ------------------------------------------------------------------------------------------


def test_attestation_rejects_a_conversation_that_switched_models(tmp_path: Path) -> None:
    cid = "11111111-2222-4333-8444-555555555555"
    conv_db = tmp_path / f"{cid}.db"
    conn = sqlite3.connect(conv_db)
    try:
        conn.execute("CREATE TABLE gen_metadata (idx INTEGER PRIMARY KEY, data BLOB, size INTEGER)")
        for idx, (backend, display) in enumerate(
            [("gemini-4-hydrogen", "Gemini 4 Hydrogen (High)"), ("gemini-4-argon", "Gemini 4 Argon (Medium)")]
        ):
            blob = build_fixture_blob(cid, backend, display)
            conn.execute("INSERT INTO gen_metadata(idx, data, size) VALUES(?, ?, ?)", (idx, blob, len(blob)))
        conn.commit()
    finally:
        conn.close()
    res = attest_conversation_model(f" {cid}\n", ARGON, conversations_dir=tmp_path)
    assert res.status == AttestationStatus.MODEL_ATTESTATION_MISMATCH
    assert not res.is_attested


# --- state machine / executor -----------------------------------------------------------------------------


def test_recover_stale_runs_reconciles_worktree_ops(tmp_path: Path) -> None:
    db_path = tmp_path / "auditor.db"
    initialize(db_path)
    res = recover_stale_runs(db_path)
    # Previously a TypeError (unexpected keyword 'jsonl_path') was swallowed into cleanup_errors.
    assert res["worktree_ops_recovery"] == {"reconciled_ops": [], "cleanup_errors": []}


@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        ("tests/test_x.py", True),
        ("pkg/test_mod.py", True),
        ("pkg/mod_test.py", True),
        ("conftest.py", True),
        ("core/attestation.py", False),
        ("core/latest.py", False),
        ("contest/app.py", False),
    ],
)
def test_test_file_detection(rel: str, expected: bool) -> None:
    from executor import _is_test_path

    assert _is_test_path(rel) is expected


def test_connect_closes_the_connection_on_context_exit(tmp_path: Path) -> None:
    with connect(tmp_path / "x.db") as conn:
        conn.execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")


# --- windows / broker helpers -----------------------------------------------------------------------------


def test_reparse_walk_ignores_stop_at_for_paths_outside_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import runtime_discovery.windows_detection as wd

    visited: list[str] = []
    monkeypatch.setattr(wd, "is_reparse_point", lambda p: visited.append(str(p)) or False)
    stop = tmp_path / "AppData"
    sibling = tmp_path / "AppData2" / "file.txt"
    assert wd.has_reparse_point_in_ancestors(sibling, stop_at=stop) is False
    assert str(tmp_path) in visited  # walked past the prefix-sharing sibling up to the root

    visited.clear()
    inside = stop / "a" / "b.txt"
    wd.has_reparse_point_in_ancestors(inside, stop_at=stop)
    assert visited[-1] == str(stop)  # stops at stop_at inside it


def test_sddl_sid_injection_is_rejected() -> None:
    from broker.security import build_restricted_pipe_sddl

    with pytest.raises(ValueError):
        build_restricted_pipe_sddl(["S-1-5-18)(A;;GA;;;WD"])
    assert "S-1-5-21-1-2-3-1001" in build_restricted_pipe_sddl(["S-1-5-21-1-2-3-1001"])


def test_checkpoint_rejects_linked_intermediate_directory(tmp_path: Path) -> None:
    from broker.checkpoint import _contained_without_links

    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "sub"
    res = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True, text=True)
    if res.returncode != 0:
        pytest.skip(f"cannot create a junction here: {res.stderr or res.stdout}")
    assert _contained_without_links(root, "sub/file.txt") is False
    assert _contained_without_links(root, "plain/file.txt") is True


def test_manual_profile_rejects_string_booleans() -> None:
    from entitlement_router.registry import EntitlementRegistry
    from entitlement_router.manual_profile import load_manual_profile_dict

    payload = {
        "schema_version": "1.0.0",
        "user_profile_id": "usr-bool",
        "accounts": [],
        "api_billing_permission": "false",
    }
    with pytest.raises(ValueError, match="boolean"):
        load_manual_profile_dict(EntitlementRegistry(), payload)


# --- models schedule (catalogue sync Sidecar) -------------------------------------------------------------


def test_models_schedule_creates_and_removes_the_sidecar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    import cli

    db_path = tmp_path / "auditor.db"
    initialize(db_path)
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id) VALUES(?,?,?,?)",
            ("demo", "Demo", str(tmp_path), "00000000-0000-4000-8000-000000000001"),
        )
        conn.execute(
            "INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id) VALUES(?,?,?,?)",
            ("pending", "Pending", str(tmp_path / "other"), "PENDING"),
        )
        conn.commit()
    cfg = tmp_path / "config.json"
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "CONFIG_PATH", cfg)
    monkeypatch.setattr(cli, "SIDECAR_ROOT", tmp_path / "sidecars")

    with pytest.raises(RuntimeError, match="Project ID"):
        cli.schedule_models_sync(project_key="pending")

    res = cli.schedule_models_sync(project_key="demo")
    assert res["status"] == "SCHEDULED"
    sidecar = json.loads((tmp_path / "sidecars" / "auditor-models-sync" / "sidecar.json").read_text(encoding="utf-8"))
    assert sidecar["builtin"] == "schedule" and sidecar["args"][0] == "30 3 * * 1"
    assert sidecar["args"][-3:] == ["sync", "--probe", "--propose"]
    assert json.loads(cfg.read_text(encoding="utf-8"))["sidecars"]["auditor-models-sync"]["enabled"] is True
    assert cli.schedule_models_sync(project_key="demo")["status"] == "UNCHANGED"

    assert cli.schedule_models_sync(project_key="", remove=True)["status"] == "REMOVED"
    assert not (tmp_path / "sidecars" / "auditor-models-sync" / "sidecar.json").exists()
    assert "auditor-models-sync" not in json.loads(cfg.read_text(encoding="utf-8"))["sidecars"]


# --- second review round ----------------------------------------------------------------------------------


def test_failed_dispatch_does_not_consume_scarce_quota_or_dedup_key() -> None:
    calls: list = []
    tracker = ModelBudgetTracker(ArgonBudgetConfig(max_concurrent_jobs=1))
    adapter = _adapter_with_fake_dispatch(calls, raise_exc=OSError("boom"))
    kwargs = dict(
        task_type=TaskType.CRITICAL_VERIFICATION,
        severity="CRITICAL",
        finding_category="DATABASE_INTEGRITY",
        evidence_gate_status="PASSED",
        execution_intent=ExecutionIntent.REQUIRED_CRITICAL_VERIFICATION,
        audit_run_id="RUN-Q",
        finding_fingerprint="fp-q",
        budget_tracker=tracker,
        model_id=ARGON,
    )
    with pytest.raises(OSError):
        adapter.start_new_conversation("x", **kwargs)
    assert tracker.get_run_usage("RUN-Q")["requests"] == 0
    # a retry is not rejected as a duplicate
    with pytest.raises(OSError):
        adapter.start_new_conversation("x", **kwargs)
    assert len(calls) == 2


def test_explicit_model_cannot_escalate_entry_to_standard() -> None:
    calls: list = []
    res = _adapter_with_fake_dispatch(calls).start_new_conversation(
        "x", task_type=TaskType.FINDING_CLASSIFICATION, model_id=HYDROGEN
    )
    assert not res.ok and res.status == "EXPLICIT_MODEL_EXCEEDS_TIER" and calls == []


def test_worker_releases_its_lease_when_processing_raises(tmp_path: Path) -> None:
    from test_second_pass_verification import _sample_candidate_findings, _seed_project_and_run
    from db import ingest_findings
    from verification import VerificationWorker

    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-EXC")
    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-EXC",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )

    def boom(_job):
        raise ValueError("unexpected")

    worker = VerificationWorker(db_path=db_path, app_home=tmp_path, worker_id="w", pre_dispatch_hook=boom)
    res = worker.process_one_job()
    assert res["status"] == "RETRYABLE_FAILURE" and res["error_code"] == "WORKER_EXCEPTION"
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT status, lease_owner, lease_token FROM verification_dispatch_queue WHERE audit_run_id='RUN-EXC'"
        ).fetchone()
    assert row["status"] == "RETRYABLE_FAILURE" and row["lease_owner"] is None and row["lease_token"] is None


@pytest.mark.parametrize(
    ("ext", "src"),
    [
        (".sh", "echo 'C:\'\n"),
        (".js", "const re = /'/;\n"),
        (".cs", 'var p = @"C:\\";\n'),
        (".rs", 'let s = r#"a "b" c"#;\n'),
        (".yaml", "key: it's fine\n"),
        (".toml", "a = 'C:\'\n"),
    ],
)
def test_lexer_accepts_valid_language_constructs(ext: str, src: str) -> None:
    from verification import _strip_comments_and_strings_per_line

    _strip_comments_and_strings_per_line(src, ext)  # must not raise UnverifiableEvidenceError


@pytest.mark.parametrize(
    ("path", "src", "sym", "line", "expected"),
    [
        ("x.go", "func (s *Server) Handle() {\n  x := 1\n}\n", "Handle", 2, True),
        ("A.java", "class A {\n  public void handle(int a) {\n    int x = 1;\n  }\n}\n", "handle", 3, True),
        ("a.ts", "const handle = async (a: number) => {\n  const x = 1;\n};\n", "handle", 2, True),
        ("a.js", "function other() {\n  handle();\n  let y = 2;\n}\n", "handle", 3, False),
    ],
)
def test_symbol_definitions_across_languages(path: str, src: str, sym: str, line: int, expected: bool) -> None:
    from verification import _verify_symbol_in_range

    ok, _code, _msg = _verify_symbol_in_range(
        file_text=src, lines=src.split("\n"), norm_path=path, sym_clean=sym, line_start=line, line_end=line
    )
    assert ok is expected


def test_telemetry_keeps_token_counts_but_redacts_secrets() -> None:
    from telemetry import redact_value

    out = redact_value({"total_tokens": 12, "input_tokens": 3, "lease_token": "lease-x", "api_key": "k"})
    assert out["total_tokens"] == 12 and out["input_tokens"] == 3
    assert out["lease_token"] == "[REDACTED]" and out["api_key"] == "[REDACTED]"


def test_commitless_repository_has_no_placeholder_fingerprint(tmp_path: Path) -> None:
    from recovery import compute_repo_fingerprint

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    assert compute_repo_fingerprint(tmp_path) == ""


def test_policy_booleans_must_be_real_booleans() -> None:
    from entitlement_router.contracts import strict_bool

    assert strict_bool({"x": False}, "x", True) is False
    assert strict_bool({}, "x", True) is True
    with pytest.raises(ValueError):
        strict_bool({"x": "false"}, "x", False)


def test_broad_sid_with_whitespace_is_still_rejected() -> None:
    from broker.security import build_restricted_pipe_sddl

    with pytest.raises(ValueError):
        build_restricted_pipe_sddl([], include_service_sid=" S-1-1-0 ")


def test_stale_run_recovery_closes_its_verification_queue(tmp_path: Path) -> None:
    from test_second_pass_verification import _sample_candidate_findings, _seed_project_and_run
    from db import ingest_findings

    db_path, repo_dir, _ = _seed_project_and_run(tmp_path, run_id="RUN-STALE")
    ingest_findings(
        db_path,
        project_key="pay",
        run_id="RUN-STALE",
        findings=[_sample_candidate_findings()[0]],
        report_dir=tmp_path / "reports",
        repo_path=repo_dir,
    )
    res = recover_stale_runs(db_path, force=True)
    assert "RUN-STALE" in res["recovered_audit_runs"]
    with connect(db_path) as conn:
        q = conn.execute("SELECT status, last_error_code FROM verification_dispatch_queue WHERE audit_run_id='RUN-STALE'").fetchone()
    assert q["status"] == "FAILED" and q["last_error_code"] == "AUDIT_RUN_STALE"


# --- third review round -----------------------------------------------------------------------------------


def test_wire_schema_lists_null_in_nullable_enums() -> None:
    from mcp_gateway.protocol_adapter import to_wire_json_schema

    out = to_wire_json_schema({"type": "object", "properties": {"s": {"type": "string", "enum": ["A"], "nullable": True}}})
    assert out["properties"]["s"]["type"] == ["string", "null"]
    assert out["properties"]["s"]["enum"] == ["A", None]


def test_dispatch_that_never_launched_is_not_counted() -> None:
    from dataclasses import replace

    from test_model_router_phase2 import make_dispatch_result

    not_launched = replace(
        make_dispatch_result(ok=False, status="CLI_UNAVAILABLE", conversation_id="", total_tokens=0),
        returncode=None,
        conversation_id=None,
    )
    tracker = ModelBudgetTracker(ArgonBudgetConfig(max_concurrent_jobs=1))
    adapter = AntigravityCliAdapter(executable_override="agy-not-used")
    adapter.dispatch = lambda **kw: not_launched  # type: ignore[method-assign]
    kwargs = dict(
        task_type=TaskType.CRITICAL_VERIFICATION,
        severity="CRITICAL",
        finding_category="DATABASE_INTEGRITY",
        evidence_gate_status="PASSED",
        execution_intent=ExecutionIntent.REQUIRED_CRITICAL_VERIFICATION,
        audit_run_id="RUN-NL",
        finding_fingerprint="fp-nl",
        budget_tracker=tracker,
        model_id=ARGON,
    )
    first = adapter.start_new_conversation("x", **kwargs)
    second = adapter.start_new_conversation("x", **kwargs)
    assert first.status == "CLI_UNAVAILABLE" and second.status == "CLI_UNAVAILABLE"  # not REJECTED_DUPLICATE
    assert tracker.get_run_usage("RUN-NL")["requests"] == 0


@pytest.mark.parametrize(
    ("ext", "src", "must_contain"),
    [
        (".yaml", "steps:\n  - run: |\n      'tis a note\n      echo done\n", "echo done"),
        (".yaml", 'run: echo "label: \'unclosed"\n', "run: echo"),
        (".toml", 'msg = """a \\""" b = """\nc = 1\n', "c = 1"),
        (".js", "const x = i++ / targetSym / 2;\n", "targetSym"),
    ],
)
def test_lexer_third_round_cases(ext: str, src: str, must_contain: str) -> None:
    from verification import _strip_comments_and_strings_per_line

    assert must_contain in "\n".join(_strip_comments_and_strings_per_line(src, ext))


def test_restore_removes_a_linked_directory_before_containment_check(tmp_path: Path) -> None:
    import hashlib
    import json as _json

    from broker.checkpoint import safe_restore_checkpoint

    wt = tmp_path / "wt"
    outside = tmp_path / "outside"
    chk = tmp_path / "chk"
    (wt / "sub").mkdir(parents=True)
    outside.mkdir()
    (chk / "files" / "sub").mkdir(parents=True)
    content = b"original\n"
    (chk / "files" / "sub" / "file.txt").write_bytes(content)
    manifest = {
        "checkpoint_id": "CHK-1",
        "exec_id": "EXEC-1",
        "finding_id": "F-1",
        "created_at": "2026-11-15T00:00:00Z",
        "files": {"sub/file.txt": hashlib.sha256(content).hexdigest()},
    }
    (chk / "manifest.json").write_text(_json.dumps(manifest), encoding="utf-8")
    # failed step replaced sub/ with a junction to a directory outside the worktree
    (wt / "sub").rmdir()
    res = subprocess.run(["cmd", "/c", "mklink", "/J", str(wt / "sub"), str(outside)], capture_output=True, text=True)
    if res.returncode != 0:
        pytest.skip("cannot create a junction here")
    out = safe_restore_checkpoint(wt, chk / "manifest.json")
    assert out["restored"] is True
    assert (wt / "sub" / "file.txt").read_bytes() == content
    assert not (outside / "file.txt").exists()


# --- fourth review round ----------------------------------------------------------------------------------


def test_yaml_comment_is_not_a_block_scalar_header() -> None:
    from verification import _strip_comments_and_strings_per_line

    out = "\n".join(_strip_comments_and_strings_per_line('# example: |\n  run: "secret" # comment\n', ".yaml"))
    assert "secret" not in out and "comment" not in out


def test_wire_schema_keeps_a_property_named_nullable() -> None:
    from mcp_gateway.protocol_adapter import to_wire_json_schema

    out = to_wire_json_schema({"type": "object", "properties": {"nullable": {"type": "boolean"}}})
    assert out["properties"]["nullable"] == {"type": "boolean"}


def test_status_paging_parameters_are_validated(tmp_path: Path) -> None:
    from mcp_server import AuditorMCPDispatcher

    db_path = tmp_path / "auditor.db"
    initialize(db_path)
    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)
    ok = dispatcher._handle_auditor_get_status({"events_limit": None, "events_offset": None})
    assert ok["recent_events_next_offset"] is None
    with pytest.raises(ValueError):
        dispatcher._handle_auditor_get_status({"events_limit": 0})


# --- APPLY without Windows Hello: human-only terminal authorization -----------------------------------------


def _authorize_cli(monkeypatch: pytest.MonkeyPatch, *, tty: bool, typed: str) -> list[dict]:
    import builtins

    import cli

    calls: list[dict] = []
    monkeypatch.setattr(cli, "_apply_preview", lambda project, run: [{"finding_id": "F-1", "severity": "HIGH"}])
    monkeypatch.setattr(
        cli,
        "authorize_execution",
        lambda db, **kw: calls.append(kw) or {"approval_id": "APPR-1", "approval_token": "agya_secret", "approved_finding_ids": ["F-1"]},
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: tty, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: tty, raising=False)
    monkeypatch.setattr(builtins, "input", lambda prompt="": typed)
    monkeypatch.setattr(sys, "argv", ["cli.py", "authorize-execution", "--project", "p", "--run-id", "R"])
    cli.main()
    return calls


def test_authorize_execution_refuses_non_interactive_use(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SystemExit) as exc:
        _authorize_cli(monkeypatch, tty=False, typed="APPLY R 1")
    assert exc.value.code == 3


@pytest.mark.parametrize("typed", ["", "n", "no", "APPLY R 1", "yess"])
def test_authorize_execution_requires_an_explicit_yes(monkeypatch: pytest.MonkeyPatch, typed: str) -> None:
    with pytest.raises(SystemExit):
        _authorize_cli(monkeypatch, tty=True, typed=typed)


@pytest.mark.parametrize("typed", ["y", "Y", "yes", "e", "evet"])
def test_authorize_execution_accepts_yes(monkeypatch: pytest.MonkeyPatch, typed: str) -> None:
    assert len(_authorize_cli(monkeypatch, tty=True, typed=typed)) == 1


def test_authorize_execution_in_a_terminal_hides_the_token(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    calls = _authorize_cli(monkeypatch, tty=True, typed="y")
    assert len(calls) == 1 and calls[0]["confirmation"] == "AUTHORIZE_ISOLATED_WORKTREE_EXECUTION"
    assert calls[0]["ttl_seconds"] == 86400
    out = capsys.readouterr().out
    assert "APPR-1" in out and "agya_secret" not in out and "start the approved fix for p" in out


# --- APPLY delivery: local review branch ------------------------------------------------------------------


def _repo_with_worktree_change(tmp_path: Path) -> tuple[Path, Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    g = lambda *a, cwd=repo: subprocess.run(["git", "-C", str(cwd), *a], check=True, capture_output=True, text=True)
    g("init", "-q")
    g("config", "user.name", "Test User")
    g("config", "user.email", "test@example.invalid")
    (repo / "mod.py").write_text("def val():\n    return 1\n", encoding="utf-8")
    g("add", ".")
    g("commit", "-q", "-m", "init")
    base = g("rev-parse", "HEAD").stdout.strip()
    wt = tmp_path / "wt"
    g("worktree", "add", "-q", "--detach", str(wt), base)
    (wt / "mod.py").write_text("def val() -> int:\n    return 1\n", encoding="utf-8")
    return repo, wt, base


def test_review_branch_is_undone_when_the_commit_fails(tmp_path: Path) -> None:
    from executor import deliver_review_branch

    repo, wt, base = _repo_with_worktree_change(tmp_path)
    hooks = repo / ".git" / "hooks"
    (hooks / "pre-commit").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Committing the review branch failed"):
        deliver_review_branch(
            repo_path=repo, worktree_path=wt, run_id="RUN-1", exec_id="EXEC-1-abcdef01",
            base_commit=base, finding_ids=["F-1"], reports_root=tmp_path / "reports",
        )
    branches = subprocess.run(["git", "-C", str(repo), "branch", "--list", "audit-fix/*"], capture_output=True, text=True).stdout
    assert branches.strip() == ""  # no stale branch blocks a retry
    assert "-> int" in (wt / "mod.py").read_text(encoding="utf-8")  # the fix is still in the worktree
    (hooks / "pre-commit").unlink()
    res = deliver_review_branch(
        repo_path=repo, worktree_path=wt, run_id="RUN-1", exec_id="EXEC-1-abcdef01",
        base_commit=base, finding_ids=["F-1"], reports_root=tmp_path / "reports",
    )
    assert res["branch"] == "audit-fix/run-1-abcdef01" and res["files_changed"] == ["mod.py"]


def test_review_branch_ignores_signing_config_and_unsafe_run_ids(tmp_path: Path) -> None:
    from executor import deliver_review_branch

    repo, wt, base = _repo_with_worktree_change(tmp_path)
    subprocess.run(["git", "-C", str(repo), "config", "commit.gpgsign", "true"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "gpg.program", "nonexistent-gpg"], check=True)
    res = deliver_review_branch(
        repo_path=repo, worktree_path=wt, run_id="../..//run..x", exec_id="EXEC-2-0badc0de",
        base_commit=base, finding_ids=["F-1"], reports_root=tmp_path / "reports",
    )
    assert ".." not in res["branch"] and res["branch"].startswith("audit-fix/")
    assert Path(res["patch_path"]).resolve().is_relative_to((tmp_path / "reports").resolve())
    status = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, text=True).stdout
    assert status.strip() == ""  # the user's working tree is untouched


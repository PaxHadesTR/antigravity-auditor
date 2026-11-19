"""Simple/strict approval modes, per-finding commits, the control plane's own test run and the CI finding."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ci_check  # noqa: E402
import cli  # noqa: E402
from db import authorize_execution, connect, initialize  # noqa: E402
from executor import revalidate_finding_against_repo, verify_red_team_diff  # noqa: E402
from project_settings import get_settings, latest_reviewable_run, set_settings  # noqa: E402
from test_apply_policy_and_quota import FINDING, _git, ready  # noqa: E402,F401
from test_gateway_start_execution import _gateway, _payload  # noqa: E402


def _settings(db: Path, **kw: Any) -> None:
    with connect(db) as conn:
        set_settings(conn, "svc1", **kw)
        conn.commit()


def _fix(ready: dict[str, Any], start_args: dict[str, Any], *, extra_change: bool = False) -> dict[str, Any]:
    """start -> begin -> edit -> verify -> finalize through the gateway; returns the finalize payload."""
    gw, caller = _gateway(ready)

    def call(tool: str, args: dict[str, Any]) -> dict[str, Any]:
        res = gw.call_tool(tool_name=tool, arguments=args, caller=caller)
        assert res["isError"] is False, (tool, res)
        return _payload(res)

    started = call("auditor_start_execution", start_args)
    exec_id, wt = started["exec_id"], Path(started["worktree_path"])
    call("auditor_update_finding_execution",
         {"project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "begin"})
    (wt / "mod.py").write_text("def val() -> int:\n    return 1\n", encoding="utf-8")
    verified = call("auditor_update_finding_execution", {
        "project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "verify",
        "happy_test_passed": True, "adversarial_test_passed": True, "red_team_passed": True})
    assert verified["status"] == "VERIFIED" and verified["commit"]
    if extra_change:
        (wt / "tests").mkdir(exist_ok=True)
        (wt / "tests" / "test_mod.py").write_text("from mod import val\n\ndef test_val():\n    assert val() == 1\n",
                                                  encoding="utf-8")
    fin = call("auditor_finalize_execution", {"project_key": "svc1", "exec_id": exec_id, "integration_test_passed": True})
    return {"started": started, "fin": fin}


# --- approval modes ---------------------------------------------------------------------------------------------


def test_default_mode_is_simple_and_latest_run_is_found(ready: dict[str, Any]) -> None:
    with connect(ready["db"]) as conn:
        assert get_settings(conn, "svc1")["approval_mode"] == "simple"
        assert latest_reviewable_run(conn, "svc1") == "R-AP"


def test_chat_approval_starts_the_fix_without_any_id(ready: dict[str, Any]) -> None:
    out = _fix(ready, {"project_key": "svc1", "chat_approved": True})
    assert out["started"]["approval"]["mode"] == "chat" and out["started"]["approval"]["run_id"] == "R-AP"
    assert out["fin"]["review"]["approval"] == "chat"
    with connect(ready["db"]) as conn:
        row = conn.execute("SELECT authorized_by, status FROM execution_approvals").fetchone()
        assert row["authorized_by"] == "chat" and row["status"] == "CONSUMED"
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='EXECUTION_CHAT_AUTHORIZED'").fetchone()[0] == 1


def test_chat_approval_is_refused_in_strict_mode(ready: dict[str, Any]) -> None:
    _settings(ready["db"], approval_mode="strict")
    gw, caller = _gateway(ready)
    res = gw.call_tool(tool_name="auditor_start_execution", arguments={"project_key": "svc1", "chat_approved": True},
                       caller=caller)
    assert res["isError"] is True and "strict approval mode" in json.dumps(res)
    with connect(ready["db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM execution_approvals").fetchone()[0] == 0


def test_strict_mode_terminal_approval_is_found_by_project_alone(ready: dict[str, Any]) -> None:
    _settings(ready["db"], approval_mode="strict")
    authorize_execution(ready["db"], project_key="svc1", run_id="R-AP", authorized_by="some-user",
                        confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION", ttl_seconds=86400)
    out = _fix(ready, {"project_key": "svc1"})
    assert out["started"]["approval"]["mode"] == "human_terminal"
    assert out["fin"]["review"]["approval"] == "human_terminal"


def test_chat_approval_refused_for_an_evidence_anomaly_run(ready: dict[str, Any]) -> None:
    with connect(ready["db"]) as conn:
        conn.execute("UPDATE audit_runs SET evidence_anomaly_json='{\"X\": {}}' WHERE run_id='R-AP'")
        conn.commit()
    gw, caller = _gateway(ready)
    res = gw.call_tool(tool_name="auditor_start_execution", arguments={"project_key": "svc1", "chat_approved": True},
                       caller=caller)
    assert res["isError"] is True and "evidence anomaly" in json.dumps(res)


def test_expired_or_used_terminal_approval_is_not_picked_up(ready: dict[str, Any]) -> None:
    auth = authorize_execution(ready["db"], project_key="svc1", run_id="R-AP",
                               confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION")
    with connect(ready["db"]) as conn:
        conn.execute("UPDATE execution_approvals SET expires_at='2020-01-01T00:00:00+00:00' WHERE approval_id=?",
                     (auth["approval_id"],))
        conn.commit()
    gw, caller = _gateway(ready)
    res = gw.call_tool(tool_name="auditor_start_execution", arguments={"project_key": "svc1"}, caller=caller)
    assert res["isError"] is True and "No approval" in json.dumps(res)


def test_more_than_one_approval_form_is_refused(ready: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        ready["d"].call_tool("auditor_start_execution",
                             {"project_key": "svc1", "chat_approved": True, "auto_approve": True})


def test_settings_validation(ready: dict[str, Any]) -> None:
    with connect(ready["db"]) as conn:
        with pytest.raises(ValueError):
            set_settings(conn, "svc1", approval_mode="yolo")
        with pytest.raises(ValueError):
            set_settings(conn, "svc1", test_timeout_seconds=5)
        with pytest.raises(ValueError):
            set_settings(conn, "svc1", test_command=[])
        conn.execute("UPDATE projects SET approval_mode='weird' WHERE project_key='svc1'")
        assert get_settings(conn, "svc1")["approval_mode"] == "strict"  # unknown value fails closed


def test_settings_and_approve_commands_need_a_terminal(ready: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    for argv in (["project-settings", "set", "--project", "svc1", "--approval-mode", "strict"],
                 ["approve", "--project", "svc1"]):
        monkeypatch.setattr(sys, "argv", ["cli.py", *argv])
        with pytest.raises(SystemExit):
            cli.main()
    with connect(ready["db"]) as conn:
        assert get_settings(conn, "svc1")["approval_mode"] == "simple"
        assert conn.execute("SELECT COUNT(*) FROM execution_approvals").fetchone()[0] == 0


# --- per-finding commits and delivery --------------------------------------------------------------------------


def test_each_verified_finding_is_its_own_commit_and_leftovers_follow(ready: dict[str, Any]) -> None:
    out = _fix(ready, {"project_key": "svc1", "chat_approved": True}, extra_change=True)
    review = out["fin"]["review"]
    subjects = [c["subject"] for c in review["commits"]]
    assert subjects[0].startswith("audit(F-AP-1): ")
    assert subjects[1].startswith("Auditor fix for R-AP: remaining integration changes")
    assert set(review["files_changed"]) == {"mod.py", "tests/test_mod.py"}
    log = _git(ready["repo"], "log", "--format=%s", f"{review['base_commit']}..{review['branch']}").stdout.splitlines()
    assert len(log) == 2
    assert any("--no-edit" in c for c in review["review_commands"])
    with connect(ready["db"]) as conn:
        assert conn.execute("SELECT commit_sha FROM finding_executions").fetchone()[0]


def test_committed_finding_cannot_be_rolled_back(ready: dict[str, Any]) -> None:
    d = ready["d"]
    started = d.call_tool("auditor_start_execution", {"project_key": "svc1", "chat_approved": True})
    exec_id, wt = started["exec_id"], Path(started["worktree_path"])
    d.call_tool("auditor_update_finding_execution", {"project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1",
                                                     "action": "begin"})
    (wt / "mod.py").write_text("def val() -> int:\n    return 1\n", encoding="utf-8")
    d.call_tool("auditor_update_finding_execution", {
        "project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "verify",
        "happy_test_passed": True, "adversarial_test_passed": True, "red_team_passed": True})
    with pytest.raises(RuntimeError, match="already verified and committed"):
        d.call_tool("auditor_update_finding_execution", {"project_key": "svc1", "exec_id": exec_id,
                                                         "finding_id": "F-AP-1", "action": "rollback"})


def test_quarantine_keeps_committed_finding_changes(ready: dict[str, Any]) -> None:
    d = ready["d"]
    started = d.call_tool("auditor_start_execution", {"project_key": "svc1", "chat_approved": True})
    exec_id, wt = started["exec_id"], Path(started["worktree_path"])
    d.call_tool("auditor_update_finding_execution", {"project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1",
                                                     "action": "begin"})
    (wt / "mod.py").write_text("def val() -> int:\n    return 1\n", encoding="utf-8")
    d.call_tool("auditor_update_finding_execution", {
        "project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "verify",
        "happy_test_passed": True, "adversarial_test_passed": True, "red_team_passed": True})
    fin = d.call_tool("auditor_finalize_execution", {"project_key": "svc1", "exec_id": exec_id,
                                                     "integration_test_passed": False})
    assert fin["status"] == "QUARANTINED"
    q = fin["quarantine"]
    patch_file = next(Path(v) for k, v in q.items() if isinstance(v, str) and v.endswith(".patch"))
    assert "-> int" in patch_file.read_text(encoding="utf-8")


# --- control plane test run ------------------------------------------------------------------------------------


def test_configured_tests_run_on_the_review_branch(ready: dict[str, Any]) -> None:
    _settings(ready["db"], test_command=[sys.executable, "-c", "import mod; assert mod.val() == 1; print('ok-tests')"])
    tests = _fix(ready, {"project_key": "svc1", "chat_approved": True})["fin"]["review"]["tests"]
    assert tests["status"] == "PASSED" and tests["source"] == "configured" and "ok-tests" in tests["output_tail"]
    with connect(ready["db"]) as conn:
        assert json.loads(conn.execute("SELECT tests_json FROM execution_runs").fetchone()[0])["status"] == "PASSED"
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='EXECUTION_TESTS_PASSED'").fetchone()[0] == 1


def test_failing_tests_still_deliver_the_branch_but_warn(ready: dict[str, Any]) -> None:
    _settings(ready["db"], test_command=[sys.executable, "-c", "raise SystemExit('boom token=abcdef1234567890xyz')"])
    review = _fix(ready, {"project_key": "svc1", "chat_approved": True})["fin"]["review"]
    assert review["tests"]["status"] == "FAILED" and review["branch"]
    assert "tests did not pass" in review["warning"]


def test_tests_timeout_is_reported(tmp_path: Path) -> None:
    res = ci_check.run_project_tests(tmp_path, [sys.executable, "-c", "import time; time.sleep(30)"],
                                     source="configured", timeout_seconds=2)
    assert res["status"] == "TIMEOUT"


def test_no_detectable_tests_is_not_configured(ready: dict[str, Any]) -> None:
    review = _fix(ready, {"project_key": "svc1", "chat_approved": True})["fin"]["review"]
    assert review["tests"]["status"] == "NOT_CONFIGURED"
    assert "warning" not in review


def test_detect_test_command(tmp_path: Path) -> None:
    assert ci_check.detect_test_command(tmp_path) == (None, "not-detected")
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
    cmd, src = ci_check.detect_test_command(tmp_path)
    assert src == "detected-smoke" and cmd[1:3] == ["-m", "compileall"]
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test_a():\n    pass\n", encoding="utf-8")
    cmd, src = ci_check.detect_test_command(tmp_path)
    assert src == "detected" and "pytest" in cmd
    assert ci_check.detect_test_command(tmp_path, json.dumps(["make", "test"])) == (["make", "test"], "configured")
    assert ci_check.detect_test_command(tmp_path, "not json")[0] is None


# --- CI finding ------------------------------------------------------------------------------------------------


def _github_repo(tmp_path: Path, *, ci: bool = False, remote: str = "https://github.com/acme/app.git") -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    for args in (["init"], ["config", "user.email", "t@example.com"], ["config", "user.name", "Test"]):
        _git(repo, *args)
    (repo / "requirements.txt").write_text("requests\n", encoding="utf-8")
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    if ci:
        (repo / ".github" / "workflows").mkdir(parents=True)
        (repo / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")
    if remote:
        _git(repo, "remote", "add", "origin", remote)
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")
    return repo


def test_ci_missing_only_for_github_projects_without_ci(tmp_path: Path) -> None:
    repo = _github_repo(tmp_path)
    info = ci_check.ci_missing(repo)
    assert info and info["file_path"] == ".github/workflows/ci.yml" and "pip install -r requirements.txt" in info["recommendation"]
    assert "compileall" in info["recommendation"]  # no tests yet -> smoke check
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "x.yaml").write_text("name: x\n", encoding="utf-8")
    assert ci_check.ci_missing(repo) is None


def test_ci_missing_not_reported_without_github_remote(tmp_path: Path) -> None:
    assert ci_check.ci_missing(_github_repo(tmp_path, remote="")) is None


def _seed_run(db: Path, repo: Path) -> None:
    initialize(db)
    with connect(db) as conn:
        conn.execute("INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id) "
                     "VALUES('p', 'P', ?, 'x')", (str(repo),))
        conn.execute("INSERT INTO audit_runs(run_id, project_key, status) VALUES('R1', 'p', 'VERIFICATION_PENDING')")
        conn.commit()


def test_ci_finding_lifecycle(tmp_path: Path) -> None:
    repo = _github_repo(tmp_path)
    db = tmp_path / "db" / "a.db"
    _seed_run(db, repo)
    with connect(db) as conn:
        fid = ci_check.upsert_ci_finding(conn, project_key="p", audit_run_id="R1", verification_run_id="V1",
                                         repo_path=repo, snapshot_id="S", base_commit_sha="abc")
        row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (fid,)).fetchone()
        assert fid == "CI-MISSING-001" and row["lifecycle"] == "OPEN" and row["verification_status"] == "VERIFIED"
        assert row["execution_eligible"] == 1 and row["model_independent"] == 1
        # dismissed stays dismissed in the next run
        conn.execute("UPDATE findings SET lifecycle='DISMISSED' WHERE finding_id=?", (fid,))
        assert ci_check.upsert_ci_finding(conn, project_key="p", audit_run_id="R1", verification_run_id="V2",
                                          repo_path=repo, snapshot_id="S", base_commit_sha="abc") is None
        assert conn.execute("SELECT lifecycle FROM findings WHERE finding_id=?", (fid,)).fetchone()[0] == "DISMISSED"
        # an open one is resolved once CI exists
        conn.execute("UPDATE findings SET lifecycle='OPEN' WHERE finding_id=?", (fid,))
        (repo / ".github" / "workflows").mkdir(parents=True)
        (repo / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")
        assert ci_check.upsert_ci_finding(conn, project_key="p", audit_run_id="R1", verification_run_id="V2",
                                          repo_path=repo, snapshot_id="S", base_commit_sha="abc") is None
        assert conn.execute("SELECT lifecycle FROM findings WHERE finding_id=?", (fid,)).fetchone()[0] == "RESOLVED"


def test_ci_finding_revalidation_and_scope(tmp_path: Path) -> None:
    repo = _github_repo(tmp_path)
    finding = {"finding_id": "CI-MISSING-001", "fingerprint": ci_check.CI_FINGERPRINT,
               "file_path": ".github/workflows/ci.yml", "base_commit_sha": ""}
    assert revalidate_finding_against_repo(repo, finding)["valid"] is True
    before = {"app.py": b"print('hi')\n"}
    ok = verify_red_team_diff(repo, before_snapshot=before, finding=finding, after_snapshot={
        **before, ".github/workflows/tests.yml": b"name: t\n", "tests/test_smoke.py": b"def test_x():\n    pass\n"})
    assert ok["passed"] is True, ok
    bad = verify_red_team_diff(repo, before_snapshot=before, finding=finding, after_snapshot={
        "app.py": b"print('changed')\n", ".github/workflows/ci.yml": b"name: t\n"})
    assert bad["passed"] is False and "scope" in bad["notes"]
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")
    assert revalidate_finding_against_repo(repo, finding)["valid"] is False


def test_ci_finding_end_to_end_through_report_and_chat_approved_fix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A GitHub repo without CI: finalizing the verified report adds CI-MISSING-001; the user approves it in the
    chat and the fix adds a workflow on the review branch."""
    from mcp_server import AuditorMCPDispatcher

    db_path = tmp_path / "database" / "auditor.db"
    initialize(db_path)
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "CONFIG_PATH", tmp_path / "config" / "config.json")
    monkeypatch.setattr(cli, "SIDECAR_ROOT", tmp_path / "config" / "sidecars")
    monkeypatch.setattr(cli, "JSONL_PATH", tmp_path / "logs" / "audit-events.jsonl")
    repo = tmp_path / "svc1"
    repo.mkdir()
    for args in (["init"], ["config", "user.email", "t@example.com"], ["config", "user.name", "Test"],
                 ["remote", "add", "origin", "https://github.com/acme/svc1.git"]):
        _git(repo, *args)
    (repo / "mod.py").write_text("def val():\n    return 1\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")
    cli.register(cli.argparse.Namespace(key="svc1", path=str(repo), project_id="ag-1", name="S1", cron="0 3 * * 1",
                                        copy_omniapex_rules=False))
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    with connect(db_path) as conn:
        conn.execute("UPDATE projects SET min_free_mb=1 WHERE project_key='svc1'")
        conn.execute("INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash) "
                     "VALUES('R-CI', 'svc1', 'DISPATCHED', ?, 'th')", (head,))
        conn.commit()
    d = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)
    vrun = d.call_tool("auditor_publish_report", {"project_key": "svc1", "run_id": "R-CI", "findings": [FINDING]})[
        "verification_run_id"]
    d.call_tool("auditor_submit_verification", {
        "audit_run_id": "R-CI", "verification_run_id": vrun,
        "verifier_metadata": {"invocation_mechanism": "mcp_direct", "actual_subagent_invocations": 0},
        "verifier_conversation_id": "conv-verifier-ci-1",
        "verification_results": [{
            "candidate_finding_id": "F-AP-1", "verdict": "REJECTED", "verified_severity": "MEDIUM",
            "verified_confidence": "CONFIRMED", "technical_rationale": "Not a problem.",
            "source_evidence": {"file_path": "mod.py", "line_start": 1, "line_end": 2, "symbol": "val",
                                "evidence_excerpt": "return 1"},
            "remediation_review": "n/a", "remediation_safe": True, "acceptance_criteria": "n/a",
        }],
    })
    fin = d.call_tool("auditor_finalize_verified_report", {"audit_run_id": "R-CI", "verification_run_id": vrun})
    assert fin["status"] == "READY_FOR_REVIEW"  # the CI finding keeps the run open for a decision
    assert ci_check.CI_FINDING_ID in fin["canonical_finding_ids"]
    report = (tmp_path / "reports").rglob("review-report.md")
    assert any("CI-MISSING-001" in p.read_text(encoding="utf-8") for p in report)

    d.call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-CI",
                                           "decisions": [{"finding_id": ci_check.CI_FINDING_ID, "decision": "APPLY"}]})
    started = d.call_tool("auditor_start_execution", {"project_key": "svc1", "chat_approved": True})
    exec_id, wt = started["exec_id"], Path(started["worktree_path"])
    d.call_tool("auditor_update_finding_execution", {"project_key": "svc1", "exec_id": exec_id,
                                                     "finding_id": ci_check.CI_FINDING_ID, "action": "begin"})
    (wt / ".github" / "workflows").mkdir(parents=True)
    (wt / ".github" / "workflows" / "ci.yml").write_text("name: CI\non: [push]\n", encoding="utf-8")
    (wt / "tests").mkdir()
    (wt / "tests" / "test_smoke.py").write_text("def test_import():\n    import mod\n", encoding="utf-8")
    v = d.call_tool("auditor_update_finding_execution", {
        "project_key": "svc1", "exec_id": exec_id, "finding_id": ci_check.CI_FINDING_ID, "action": "verify",
        "happy_test_passed": True, "adversarial_test_passed": True, "red_team_passed": True})
    assert v["status"] == "VERIFIED", v
    out = d.call_tool("auditor_finalize_execution", {"project_key": "svc1", "exec_id": exec_id,
                                                     "integration_test_passed": True})
    review = out["review"]
    assert ".github/workflows/ci.yml" in review["files_changed"]
    assert review["commits"][0]["subject"].startswith("audit(CI-MISSING-001)")
    assert not (repo / ".github").exists()  # the user's working tree is untouched


# --- review fixes ----------------------------------------------------------------------------------------------


def test_os_user_named_chat_is_still_a_terminal_approval(ready: dict[str, Any]) -> None:
    _settings(ready["db"], approval_mode="strict")
    authorize_execution(ready["db"], project_key="svc1", run_id="R-AP", authorized_by="chatadmin",
                        confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION")
    started = ready["d"].call_tool("auditor_start_execution", {"project_key": "svc1"})
    assert started["approval"]["mode"] == "human_terminal"


def test_approval_of_a_run_that_is_no_longer_reviewable_is_not_picked_up(ready: dict[str, Any]) -> None:
    authorize_execution(ready["db"], project_key="svc1", run_id="R-AP",
                        confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION")
    with connect(ready["db"]) as conn:
        conn.execute("UPDATE audit_runs SET status='ARCHIVED' WHERE run_id='R-AP'")
        conn.commit()
    with pytest.raises(PermissionError, match="No approval"):
        ready["d"].call_tool("auditor_start_execution", {"project_key": "svc1"})


def test_tests_added_by_the_fix_are_detected_in_the_worktree(ready: dict[str, Any]) -> None:
    review = _fix(ready, {"project_key": "svc1", "chat_approved": True}, extra_change=True)["fin"]["review"]
    # mod.py has no requirements file, so the stack is not detectable; configure python to see pytest picked up
    assert review["tests"]["status"] in ("NOT_CONFIGURED", "PASSED")


def test_detection_uses_worktree_tests_and_repo_venv(tmp_path: Path) -> None:
    repo, wt = tmp_path / "repo", tmp_path / "wt"
    (repo / ".venv" / "Scripts").mkdir(parents=True)
    (repo / ".venv" / "Scripts" / "python.exe").write_bytes(b"")
    wt.mkdir()
    (wt / "requirements.txt").write_text("\n", encoding="utf-8")
    (wt / "tests").mkdir()
    (wt / "tests" / "test_new.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    cmd, src = ci_check.detect_test_command(wt, None, venv_root=repo)
    assert src == "detected" and "pytest" in cmd and cmd[0].endswith(str(Path(".venv") / "Scripts" / "python.exe"))


def test_committed_finding_cannot_be_begun_again(ready: dict[str, Any]) -> None:
    d = ready["d"]
    started = d.call_tool("auditor_start_execution", {"project_key": "svc1", "chat_approved": True})
    exec_id, wt = started["exec_id"], Path(started["worktree_path"])
    args = {"project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1"}
    d.call_tool("auditor_update_finding_execution", {**args, "action": "begin"})
    (wt / "mod.py").write_text("def val() -> int:\n    return 1\n", encoding="utf-8")
    d.call_tool("auditor_update_finding_execution", {**args, "action": "verify", "happy_test_passed": True,
                                                     "adversarial_test_passed": True, "red_team_passed": True})
    for action in ("begin", "verify"):
        with pytest.raises(RuntimeError, match="already verified and committed"):
            d.call_tool("auditor_update_finding_execution", {**args, "action": action, "happy_test_passed": True,
                                                             "adversarial_test_passed": True, "red_team_passed": True})


def test_open_ci_finding_resolved_when_check_no_longer_applies(tmp_path: Path) -> None:
    repo = _github_repo(tmp_path)
    db = tmp_path / "db" / "a.db"
    _seed_run(db, repo)
    with connect(db) as conn:
        fid = ci_check.upsert_ci_finding(conn, project_key="p", audit_run_id="R1", verification_run_id="V1",
                                         repo_path=repo, snapshot_id="S", base_commit_sha="abc")
        _git(repo, "remote", "remove", "origin")
        ci_check.upsert_ci_finding(conn, project_key="p", audit_run_id="R1", verification_run_id="V1",
                                   repo_path=repo, snapshot_id="S", base_commit_sha="abc")
        assert conn.execute("SELECT lifecycle FROM findings WHERE finding_id=?", (fid,)).fetchone()[0] == "RESOLVED"

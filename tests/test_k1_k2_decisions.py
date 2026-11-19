"""User decisions 2026-11-16.

K1: findings verified without an independent second model are APPLY-eligible through the human terminal
    authorization only; the auto-approval policy refuses them unless allow_single_model_verification is set.
K2: the weekly audit does not run while the previous report waits for the user, nor when the code has not changed
    since the last finished audit; `audit-now` runs on request and replaces a report nobody acted on.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import apply_policy as ap  # noqa: E402
import cli  # noqa: E402
from db import authorize_execution, connect  # noqa: E402
from test_apply_policy_and_quota import _git, ready  # noqa: E402,F401  (fixture)


def _policy(db: Path, **over: Any) -> None:
    with connect(db) as conn:
        ap.set_policy(conn, "svc1", {**ap.DEFAULT_POLICY, "enabled": True, **over}, updated_by="test")
        conn.commit()


def _auto(ready: dict[str, Any]) -> dict[str, Any]:
    return ready["d"].call_tool("auditor_start_execution", {"project_key": "svc1", "run_id": "R-AP", "auto_approve": True})


# --- K1 ----------------------------------------------------------------------------------------------------------------


def test_single_model_finding_is_apply_eligible_but_not_auto_approvable(ready: dict[str, Any]) -> None:
    with connect(ready["db"]) as conn:
        row = conn.execute("SELECT execution_eligible, model_independent FROM findings WHERE finding_id='F-AP-1'").fetchone()
    assert tuple(row) == (1, 0)
    _policy(ready["db"])
    with pytest.raises(PermissionError, match="independent second model"):
        _auto(ready)
    # the human terminal path still works
    auth = authorize_execution(ready["db"], project_key="svc1", run_id="R-AP",
                               confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION")
    assert auth["approved_finding_ids"] == ["F-AP-1"]


def test_policy_can_explicitly_allow_single_model_findings(ready: dict[str, Any]) -> None:
    _policy(ready["db"], allow_single_model_verification=True)
    assert _auto(ready)["approval"]["mode"] == "auto_policy"


def test_cross_model_finding_is_auto_approvable_by_default_policy_limits(ready: dict[str, Any]) -> None:
    with connect(ready["db"]) as conn:
        conn.execute("UPDATE findings SET model_independent=1 WHERE finding_id='F-AP-1'")
        conn.commit()
    _policy(ready["db"])
    assert _auto(ready)["approval"]["mode"] == "auto_policy"


def test_weekly_same_model_finding_is_now_apply_eligible(tmp_path: Path) -> None:
    from verification import finalize_verified_report  # noqa: F401  (import check only)
    import inspect

    import verification

    src = inspect.getsource(verification)
    assert "model_independent = 1 if cross_ok else 0" in src
    assert "elif has_explicit_models and not cross_ok:\n                exec_eligible = 0" not in src


# --- K2 ----------------------------------------------------------------------------------------------------------------


def _use_db(monkeypatch: pytest.MonkeyPatch, ready: dict[str, Any]) -> None:
    monkeypatch.setattr(cli, "DB_PATH", ready["db"])
    monkeypatch.setattr(cli, "JSONL_PATH", ready["db"].parent.parent / "logs" / "events.jsonl")


def test_weekly_skips_while_the_report_waits_for_the_user(ready: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    _use_db(monkeypatch, ready)
    monkeypatch.setattr(cli, "dispatch", lambda project_key, **_kw: pytest.fail("must not spend tokens"))
    out = cli.scheduled_audit("svc1")
    assert out["result"] == "SKIPPED_AWAITING_REVIEW" and out["run_id"] == "R-AP" and "audit-now" in out["hint"]


def _fake_agy(monkeypatch: pytest.MonkeyPatch, tmp: Path, *, quota: bool = False) -> None:
    from dataclasses import replace

    from agy_adapter import AntigravityCliAdapter
    from test_model_router_phase2 import make_dispatch_result

    exe = tmp / "fake_agy.exe"
    exe.write_text("", encoding="utf-8")
    res = make_dispatch_result(ok=True, response_text='{"findings": []}', conversation_id="conv-manual-0001")
    if quota:
        res = replace(make_dispatch_result(ok=False, status="PROVIDER_QUOTA_EXHAUSTED", error="RESOURCE_EXHAUSTED"),
                      error_code="PROVIDER_QUOTA_EXHAUSTED", retry_after_seconds=600)
    monkeypatch.setattr(AntigravityCliAdapter, "discover_executable", lambda self: exe)
    monkeypatch.setattr(AntigravityCliAdapter, "start_new_conversation", lambda self, prompt, **kw: res)

    class _NoWorker:
        def process_one_job(self) -> None:
            return None

    monkeypatch.setattr(cli, "VerificationWorker", lambda *a, **k: _NoWorker())
    monkeypatch.setattr(cli, "_seconds_until_retry", lambda run_id: None)


def _r_ap(db: Path) -> Any:
    with connect(db) as conn:
        run = conn.execute("SELECT status, error FROM audit_runs WHERE run_id='R-AP'").fetchone()
        live_apply = conn.execute("SELECT COUNT(*) FROM decisions WHERE run_id='R-AP' AND decision='APPLY' "
                                  "AND superseded=0").fetchone()[0]
    return run["status"], run["error"], live_apply


def test_manual_audit_replaces_a_report_nobody_acted_on(ready: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
                                                        tmp_path: Path) -> None:
    _use_db(monkeypatch, ready)
    _fake_agy(monkeypatch, tmp_path)
    out = cli.scheduled_audit("svc1", manual=True)
    assert out["primary"]["status"] == "VERIFICATION_PENDING"  # the new audit ran
    assert _r_ap(ready["db"]) == ("ARCHIVED", "SUPERSEDED_BY_MANUAL_AUDIT", 0)


def test_failed_manual_audit_gives_the_old_report_back(ready: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
                                                       tmp_path: Path) -> None:
    _use_db(monkeypatch, ready)
    _fake_agy(monkeypatch, tmp_path, quota=True)
    out = cli.scheduled_audit("svc1", manual=True)
    assert out["result"] == "PRIMARY_WAITING_PROVIDER_QUOTA"
    assert _r_ap(ready["db"]) == ("READY_FOR_REVIEW", None, 1)  # report and its APPLY decision restored


def test_manual_audit_does_not_replace_a_run_with_a_pending_fix(ready: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
                                                                tmp_path: Path) -> None:
    _use_db(monkeypatch, ready)
    _fake_agy(monkeypatch, tmp_path)
    authorize_execution(ready["db"], project_key="svc1", run_id="R-AP", confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION")
    out = cli.scheduled_audit("svc1", manual=True)
    assert out["result"] == "PRIMARY_FAILED" and "pending fix approval" in out["primary"]["error"]
    assert _r_ap(ready["db"])[0] == "READY_FOR_REVIEW"


def test_an_expired_approval_does_not_block_a_manual_audit(ready: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
                                                            tmp_path: Path) -> None:
    _use_db(monkeypatch, ready)
    _fake_agy(monkeypatch, tmp_path)
    authorize_execution(ready["db"], project_key="svc1", run_id="R-AP", confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION")
    with connect(ready["db"]) as conn:
        conn.execute("UPDATE execution_approvals SET expires_at='2000-01-01T00:00:00+00:00'")
        conn.commit()
    cli.scheduled_audit("svc1", manual=True)
    assert _r_ap(ready["db"])[0] == "ARCHIVED"
    with connect(ready["db"]) as conn:
        assert conn.execute("SELECT status FROM execution_approvals").fetchone()[0] == "EXPIRED"


def test_a_manually_archived_run_is_no_baseline_for_the_no_change_skip(ready: dict[str, Any],
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    _use_db(monkeypatch, ready)
    with connect(ready["db"]) as conn:
        conn.execute("UPDATE audit_runs SET status='ARCHIVED', working_tree_hash=? WHERE run_id='R-AP'",
                     (cli.working_tree_hash(ready["repo"]),))
        conn.commit()
    assert cli._weekly_gate("svc1", manual=False) is None


def test_weekly_skips_unchanged_code_but_runs_after_a_change(ready: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    _use_db(monkeypatch, ready)
    ready["d"].call_tool("auditor_save_decisions", {"project_key": "svc1", "run_id": "R-AP",
                                                    "decisions": [{"finding_id": "F-AP-1", "decision": "DISMISS"}]})
    with connect(ready["db"]) as conn:  # the finished run audited exactly the current tree
        conn.execute("UPDATE audit_runs SET working_tree_hash=? WHERE run_id='R-AP'",
                     (cli.working_tree_hash(ready["repo"]),))
        conn.commit()
    called: list[str] = []
    monkeypatch.setattr(cli, "dispatch", lambda project_key, **_kw: called.append(project_key) or None)
    assert cli.scheduled_audit("svc1")["result"] == "SKIPPED_NO_CHANGES" and called == []
    # manual audit ignores the no-change skip
    cli.scheduled_audit("svc1", manual=True)
    assert called == ["svc1"]
    (ready["repo"] / "mod.py").write_text("def val():\n    return 2\n", encoding="utf-8")
    _git(ready["repo"], "commit", "-qam", "change")
    cli.scheduled_audit("svc1")
    assert called == ["svc1", "svc1"]


def test_skips_exit_zero_for_the_sidecar(ready: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    _use_db(monkeypatch, ready)
    monkeypatch.setattr(sys, "argv", ["cli.py", "scheduled-audit", "--project", "svc1"])
    cli.main()  # SKIPPED_AWAITING_REVIEW -> no SystemExit(2)


# --- K3 ----------------------------------------------------------------------------------------------------------------


def _two_finding_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, run_id: str, fabricate: bool,
                     repo: Path | None = None, discovered: list | None = None) -> tuple[Any, Path, Path]:
    from db import initialize
    from mcp_server import AuditorMCPDispatcher

    db = tmp_path / "database" / "auditor.db"
    if repo is None:
        initialize(db)
        for name, val in (("DB_PATH", db), ("CONFIG_PATH", tmp_path / "config" / "c.json"),
                          ("SIDECAR_ROOT", tmp_path / "config" / "sc"), ("JSONL_PATH", tmp_path / "e.jsonl")):
            monkeypatch.setattr(cli, name, val)
        repo = tmp_path / "svc"
        repo.mkdir()
        for args in (["init", "-q"], ["config", "user.email", "t@example.com"], ["config", "user.name", "T"]):
            _git(repo, *args)
        (repo / "mod.py").write_text("def a():\n    return 1\n\n\ndef b():\n    return 2\n", encoding="utf-8")
        _git(repo, "add", ".")
        _git(repo, "commit", "-qm", "init")
        cli.register(cli.argparse.Namespace(key="svc", path=str(repo), project_id="ag-1", name="S", cron="0 3 * * 1",
                                            copy_omniapex_rules=False))
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    with connect(db) as conn:
        conn.execute("UPDATE projects SET min_free_mb=1")
        conn.execute("INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash) "
                     "VALUES(?, 'svc', 'DISPATCHED', ?, 'th')", (run_id, head))
        conn.commit()
    d = AuditorMCPDispatcher(db_path=db, app_home=tmp_path)

    def f(fid: str, sym: str, line: int, ev: str) -> dict:
        return {"finding_id": fid, "fingerprint": f"fp-{fid}", "title": f"t {fid}", "category": "V7",
                "severity": "MEDIUM", "confidence": "CONFIRMED", "file_path": "mod.py", "symbol": sym,
                "line_start": line, "line_end": line + 1, "evidence": ev, "impact": "i", "recommendation": "r"}

    def v(fid: str, sym: str, line: int, ev: str) -> dict:
        return {"candidate_finding_id": fid, "verdict": "CONFIRMED", "verified_severity": "MEDIUM",
                "verified_confidence": "CONFIRMED", "technical_rationale": "Checked the function body directly.",
                "source_evidence": {"file_path": "mod.py", "line_start": line, "line_end": line + 1, "symbol": sym,
                                    "evidence_excerpt": ev},
                "remediation_review": "Safe.", "remediation_safe": True, "acceptance_criteria": "Typed return."}

    pub = d.call_tool("auditor_publish_report", {"project_key": "svc", "run_id": run_id, "findings": [
        f("F-A", "a", 1, "return 1"), f("F-B", "b", 5, "return 2")]})
    vrun = pub["verification_run_id"]
    b_excerpt = "return 2 if flag else 3" if fabricate else "return 2"
    d.call_tool("auditor_submit_verification", {
        "audit_run_id": run_id, "verification_run_id": vrun,
        "verifier_metadata": {"invocation_mechanism": "mcp_direct", "actual_subagent_invocations": 0},
        "verifier_conversation_id": f"conv-verifier-{run_id}",
        "verification_results": [v("F-A", "a", 1, "return 1"), v("F-B", "b", 5, b_excerpt)],
        **({"verifier_discovered_findings": discovered} if discovered else {})})
    fin = d.call_tool("auditor_finalize_verified_report", {"audit_run_id": run_id, "verification_run_id": vrun})
    return fin, db, repo


def test_one_fabricated_excerpt_rejects_only_that_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fin, db, _ = _two_finding_run(tmp_path, monkeypatch, "R-K3", fabricate=True)
    assert fin["status"] == "READY_FOR_REVIEW" and fin["canonical_finding_ids"] == ["F-A"]
    with connect(db) as conn:
        cand = dict(conn.execute("SELECT candidate_finding_id, status FROM candidate_findings").fetchall())
        anomaly = conn.execute("SELECT evidence_anomaly_json FROM audit_runs WHERE run_id='R-K3'").fetchone()[0]
        queue = conn.execute("SELECT status FROM verification_dispatch_queue").fetchone()[0]
        ap.set_policy(conn, "svc", {**ap.DEFAULT_POLICY, "enabled": True, "allow_single_model_verification": True},
                      updated_by="t")
        conn.commit()
        ev = ap.evaluate(conn, "svc", "R-K3")
    assert cand == {"F-A": "CONFIRMED", "F-B": "REJECTED"} and "F-B" in anomaly and queue == "COMPLETED"
    report = next(tmp_path.rglob("review-report.md")).read_text(encoding="utf-8")
    assert "## Evidence Anomaly" in report and "F-B" in report
    assert any("evidence anomaly" in r for r in ev["reasons"])


def test_a_fabricated_recheck_does_not_damage_last_weeks_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fin1, db, repo = _two_finding_run(tmp_path, monkeypatch, "R-W1", fabricate=False)
    assert sorted(fin1["canonical_finding_ids"]) == ["F-A", "F-B"]
    with connect(db) as conn:  # week 1 reviewed (DEFER) so the next run may start
        conn.execute("UPDATE audit_runs SET status='COMPLETED' WHERE run_id='R-W1'")
        before = dict(conn.execute("SELECT * FROM findings WHERE finding_id='F-B'").fetchone())
        conn.commit()
    _two_finding_run(tmp_path, monkeypatch, "R-W2", fabricate=True, repo=repo)
    with connect(db) as conn:
        after = dict(conn.execute("SELECT * FROM findings WHERE finding_id='F-B'").fetchone())
    for col in ("lifecycle", "verification_status", "execution_eligible", "last_seen_run_id"):
        assert after[col] == before[col], col


def test_followup_round_completes_after_an_evidence_rejection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from verification import finalize_verified_report, submit_verification_results

    disc = {"finding_id": "F-DISC", "fingerprint": "fp-disc", "title": "b lacks a type", "category": "V7",
            "severity": "LOW", "confidence": "CONFIRMED", "file_path": "mod.py", "symbol": "b", "line_start": 5,
            "line_end": 6, "evidence": "return 2", "impact": "i", "recommendation": "r"}
    fin, db, _ = _two_finding_run(tmp_path, monkeypatch, "R-DISC", fabricate=True, discovered=[disc])
    assert fin["status"] == "VERIFICATION_PENDING" and fin["followup_verification_run_id"]
    with connect(db) as conn:  # first round: F-A confirmed, F-B counted as rejected (metrics are per round)
        assert tuple(conn.execute("SELECT confirmed_findings, rejected_findings FROM audit_quality_metrics "
                                  "WHERE audit_run_id='R-DISC'").fetchone()) == (1, 1)
    submit_verification_results(db, audit_run_id="R-DISC", verification_run_id=fin["followup_verification_run_id"],
                                verifier_conversation_id="conv-verifier-followup-2", verification_results=[{
                                    "candidate_finding_id": "F-DISC", "verdict": "CONFIRMED", "verified_severity": "LOW",
                                    "verified_confidence": "CONFIRMED", "technical_rationale": "Checked b directly.",
                                    "source_evidence": {"file_path": "mod.py", "line_start": 5, "line_end": 6,
                                                        "symbol": "b", "evidence_excerpt": "return 2"},
                                    "remediation_review": "Safe.", "remediation_safe": True,
                                    "acceptance_criteria": "Typed."}])
    fin2 = finalize_verified_report(db, audit_run_id="R-DISC", verification_run_id=fin["followup_verification_run_id"])
    assert fin2["status"] == "READY_FOR_REVIEW" and "F-DISC" in fin2["canonical_finding_ids"]
    with connect(db) as conn:
        anomaly = conn.execute("SELECT evidence_anomaly_json FROM audit_runs WHERE run_id='R-DISC'").fetchone()[0]
    assert "F-B" in anomaly  # kept across rounds

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from db import (
    authorize_execution,
    backup_database,
    check_database_integrity,
    connect,
    ingest_findings,
    initialize,
    record_event,
    recover_stale_runs,
    save_decisions,
    verify_backup_restore,
)
from verification import finalize_verified_report, submit_verification_results


def _seed_project_and_run(db_path: Path, repo_path: Path, run_id: str = "RUN-001") -> None:
    initialize(db_path)
    with connect(db_path) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO projects(
                project_key, display_name, repo_path, antigravity_project_id
            ) VALUES('demo', 'Demo Project', ?, 'proj-uuid-1')""",
            (str(repo_path),),
        )
        conn.execute(
            """INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash)
               VALUES(?, 'demo', 'DISPATCHED', 'abc1234', 'treehash1')""",
            (run_id,),
        )
        conn.commit()


def _verify_and_finalize(
    db_path: Path,
    run_id: str,
    verification_run_id: str,
    findings: list[dict[str, Any]],
    *,
    conv_id: str = "conv-verifier-db-test-001",
    excerpt_override: str | None = None,
) -> dict[str, Any]:
    results = []
    for f in findings:
        results.append(
            {
                "candidate_finding_id": f["finding_id"],
                "verdict": "CONFIRMED",
                "verified_severity": f["severity"],
                "verified_confidence": f["confidence"],
                "technical_rationale": "Independently verified against actual repository source.",
                "source_evidence": {
                    "file_path": f["file_path"],
                    "line_start": f["line_start"],
                    "line_end": f["line_end"],
                    "symbol": f["symbol"],
                    "evidence_excerpt": excerpt_override if excerpt_override is not None else f["evidence"],
                },
                "remediation_review": "Safe remediation proposal with no regressions.",
                "remediation_safe": True,
                "acceptance_criteria": "Verify happy and adversarial unit tests pass.",
            }
        )
    submit_verification_results(
        db_path,
        audit_run_id=run_id,
        verification_run_id=verification_run_id,
        verifier_conversation_id=conv_id,
        verification_results=results,
    )
    return finalize_verified_report(
        db_path,
        audit_run_id=run_id,
        verification_run_id=verification_run_id,
    )


def test_initialize_creates_expected_tables(tmp_path: Path) -> None:
    db = tmp_path / "auditor.db"
    initialize(db)
    with connect(db) as conn:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    expected = {
        "schema_migrations",
        "projects",
        "audit_runs",
        "audit_snapshots",
        "candidate_findings",
        "audit_verification_runs",
        "finding_verification_results",
        "verification_dispatch_queue",
        "audit_quality_metrics",
        "findings",
        "finding_history",
        "decisions",
        "execution_approvals",
        "execution_runs",
        "finding_executions",
        "quarantined_worktrees",
        "skill_inventory",
        "audit_events",
        "notification_outbox",
    }
    assert expected.issubset(names)


def test_v1_to_v2_schema_migration_preserves_data(tmp_path: Path) -> None:
    db = tmp_path / "legacy_v1.db"
    v1_sql = """
    CREATE TABLE projects (
        project_key TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        repo_path TEXT NOT NULL UNIQUE,
        antigravity_project_id TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        schedule_cron TEXT NOT NULL DEFAULT '0 4 * * 1',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE audit_runs (
        run_id TEXT PRIMARY KEY,
        project_key TEXT NOT NULL REFERENCES projects(project_key),
        status TEXT NOT NULL,
        base_commit TEXT,
        working_tree_hash TEXT,
        started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        finished_at TEXT,
        agent_conversation_id TEXT,
        report_path TEXT,
        error TEXT
    );
    CREATE TABLE findings (
        finding_id TEXT PRIMARY KEY,
        project_key TEXT NOT NULL,
        run_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        file_path TEXT,
        symbol TEXT,
        line_start INTEGER,
        line_end INTEGER,
        evidence TEXT NOT NULL,
        impact TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        lifecycle TEXT NOT NULL DEFAULT 'OPEN',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(project_key, fingerprint)
    );
    CREATE TABLE decisions (
        decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id TEXT NOT NULL,
        decision TEXT NOT NULL,
        note TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """
    with sqlite3.connect(db) as raw_conn:
        raw_conn.executescript(v1_sql)
        raw_conn.execute(
            "INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id) VALUES('legacy', 'Legacy', 'C:/tmp/legacy', 'id-1')"
        )
        raw_conn.commit()

    initialize(db)
    with connect(db) as conn:
        proj = conn.execute("SELECT * FROM projects WHERE project_key='legacy'").fetchone()
        assert proj is not None
        assert proj["health_status"] == "HEALTHY"
        assert int(proj["stale_timeout_seconds"]) == 3600
        versions = {int(r[0]) for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
        assert {1, 2, 3}.issubset(versions)


def test_finding_deduplication_dismissal_suppression_and_material_change_reopen(tmp_path: Path) -> None:
    db = tmp_path / "auditor.db"
    repo = tmp_path / "repo"
    repo.mkdir()
    target_file = repo / "service.py"
    target_file.write_text("def compute(x):\n    return x + 1\n", encoding="utf-8")

    _seed_project_and_run(db, repo, "RUN-1")
    sample_finding = {
        "finding_id": "F-001",
        "fingerprint": "fp-service-compute-overflow",
        "title": "Unbounded integer operation",
        "category": "V3",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "file_path": "service.py",
        "symbol": "compute",
        "line_start": 1,
        "line_end": 2,
        "evidence": "return x + 1",
        "impact": "Downstream overflow",
        "recommendation": "Validate bounds on x",
    }

    # Ingest duplicate items in same run -> deduplicated to 1 candidate finding in VERIFICATION_PENDING
    stats1 = ingest_findings(
        db,
        project_key="demo",
        run_id="RUN-1",
        findings=[sample_finding, dict(sample_finding)],
        report_dir=tmp_path / "reports" / "RUN-1",
        repo_path=repo,
    )
    assert stats1["total_received"] == 2
    assert stats1["unique_in_run"] == 1
    assert stats1["status"] == "VERIFICATION_PENDING"
    assert stats1["inserted_open"] == 0

    fin1 = _verify_and_finalize(
        db,
        "RUN-1",
        stats1["verification_run_id"],
        [sample_finding],
        conv_id="conv-verifier-run-1",
    )
    assert fin1["status"] == "READY_FOR_REVIEW"
    assert fin1["stats"]["inserted_open"] == 1

    # User dismisses finding F-001
    save_res = save_decisions(
        db,
        project_key="demo",
        run_id="RUN-1",
        decisions=[{"finding_id": "F-001", "decision": "DISMISS", "note": "False positive for bounded caller"}],
    )
    assert save_res["counts"]["DISMISS"] == 1
    assert save_res["execution_authorized"] is False

    # Complete/close RUN-1 so RUN-2 can be created
    with connect(db) as conn:
        conn.execute("UPDATE audit_runs SET status='COMPLETED' WHERE run_id='RUN-1'")
        conn.execute(
            "INSERT INTO audit_runs(run_id, project_key, status) VALUES('RUN-2', 'demo', 'DISPATCHED')"
        )
        conn.commit()

    # Run 2 reports same finding with NO code or evidence change -> remains DISMISSED (suppressed)
    stats2 = ingest_findings(
        db,
        project_key="demo",
        run_id="RUN-2",
        findings=[sample_finding],
        report_dir=tmp_path / "reports" / "RUN-2",
        repo_path=repo,
    )
    fin2 = _verify_and_finalize(
        db,
        "RUN-2",
        stats2["verification_run_id"],
        [sample_finding],
        conv_id="conv-verifier-run-2",
    )
    assert fin2["stats"]["suppressed_dismissed"] == 1
    assert fin2["stats"]["reopened_dismissed"] == 0
    with connect(db) as conn:
        f_row = conn.execute("SELECT lifecycle FROM findings WHERE finding_id='F-001'").fetchone()
        assert f_row["lifecycle"] == "DISMISSED"

    # Now materially change service.py and run RUN-3 -> dismissed finding must reopen!
    target_file.write_text("def compute(x):\n    return (x * 999999) / 0\n", encoding="utf-8")
    with connect(db) as conn:
        conn.execute("UPDATE audit_runs SET status='COMPLETED' WHERE run_id='RUN-2'")
        conn.execute(
            "INSERT INTO audit_runs(run_id, project_key, status) VALUES('RUN-3', 'demo', 'DISPATCHED')"
        )
        conn.commit()

    stats3 = ingest_findings(
        db,
        project_key="demo",
        run_id="RUN-3",
        findings=[sample_finding],
        report_dir=tmp_path / "reports" / "RUN-3",
        repo_path=repo,
    )
    fin3 = _verify_and_finalize(
        db,
        "RUN-3",
        stats3["verification_run_id"],
        [sample_finding],
        conv_id="conv-verifier-run-3",
        excerpt_override="return (x * 999999) / 0",
    )
    assert fin3["stats"]["reopened_dismissed"] == 1
    with connect(db) as conn:
        f_row = conn.execute("SELECT lifecycle FROM findings WHERE finding_id='F-001'").fetchone()
        assert f_row["lifecycle"] == "OPEN"
        history = conn.execute(
            "SELECT reason, to_lifecycle FROM finding_history WHERE finding_id='F-001' ORDER BY history_id"
        ).fetchall()
        reasons = [r["reason"] for r in history]
        assert "INITIAL_DISCOVERY" in reasons
        assert "DISMISSED_DUPLICATE_SUPPRESSED" in reasons
        assert "DISMISSED_REOPENED_MATERIAL_CHANGE" in reasons


def test_decision_save_and_execution_authorization_separation(tmp_path: Path) -> None:
    db = tmp_path / "auditor.db"
    repo = tmp_path / "repo"
    repo.mkdir()
    auth_lines = [f"# header line {i}" for i in range(1, 10)] + [
        "def login(token):",
        "    # No token check",
        "    return {'authenticated': True}",
        "    # line 13",
        "    # line 14",
        "    # line 15",
    ]
    (repo / "auth.py").write_text("\n".join(auth_lines) + "\n", encoding="utf-8")
    _seed_project_and_run(db, repo, "RUN-AUTH")

    finding_item = {
        "finding_id": "F-10",
        "fingerprint": "fp-10-auth",
        "title": "Missing auth check",
        "category": "V4",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "file_path": "auth.py",
        "symbol": "login",
        "line_start": 10,
        "line_end": 15,
        "evidence": "No token check",
        "impact": "Account takeover",
        "recommendation": "Verify token signature",
    }
    stats = ingest_findings(
        db,
        project_key="demo",
        run_id="RUN-AUTH",
        findings=[finding_item],
        report_dir=tmp_path / "reports",
        repo_path=repo,
    )

    # Complete second-pass verification so RUN-AUTH enters READY_FOR_REVIEW
    _verify_and_finalize(db, "RUN-AUTH", stats["verification_run_id"], [finding_item])

    # Attempting to authorize before saving APPLY decision must fail
    with pytest.raises(RuntimeError, match="Save decisions first"):
        authorize_execution(db, project_key="demo", run_id="RUN-AUTH")

    # Attempting to pass markdown checkbox in decision or confirmation must fail
    with pytest.raises(RuntimeError, match="Markdown checkboxes"):
        save_decisions(
            db,
            project_key="demo",
            run_id="RUN-AUTH",
            decisions=[{"finding_id": "F-10", "decision": "[x] APPLY"}],
        )

    save_decisions(
        db,
        project_key="demo",
        run_id="RUN-AUTH",
        decisions=[{"finding_id": "F-10", "decision": "APPLY", "note": "Fix immediately"}],
    )

    with pytest.raises(RuntimeError, match="Explicit authorization confirmation"):
        authorize_execution(
            db,
            project_key="demo",
            run_id="RUN-AUTH",
            confirmation="- [x] AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
        )

    auth = authorize_execution(
        db,
        project_key="demo",
        run_id="RUN-AUTH",
        confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
    )
    assert auth["approval_token"].startswith("agya_")
    assert auth["approved_finding_ids"] == ["F-10"]

    # Changing decision to DEFER must revoke the unconsumed approval token
    save_decisions(
        db,
        project_key="demo",
        run_id="RUN-AUTH",
        decisions=[{"finding_id": "F-10", "decision": "DEFER"}],
    )
    with connect(db) as conn:
        row = conn.execute(
            "SELECT status FROM execution_approvals WHERE approval_id=?",
            (auth["approval_id"],),
        ).fetchone()
        assert row["status"] == "REVOKED"


def test_lock_recovery_backup_restore_and_jsonl_redaction(tmp_path: Path) -> None:
    db = tmp_path / "auditor.db"
    jsonl = tmp_path / "logs" / "audit-events.jsonl"
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_project_and_run(db, repo, "RUN-STUCK")

    # Recover stuck run and verify partial unique index allows a new run
    rec = recover_stale_runs(db, project_key="demo", force=True, jsonl_path=jsonl)
    assert "RUN-STUCK" in rec["recovered_audit_runs"]

    with connect(db) as conn:
        conn.execute(
            "INSERT INTO audit_runs(run_id, project_key, status) VALUES('RUN-NEW', 'demo', 'PREFLIGHT')"
        )
        record_event(
            conn,
            "SECRET_REDACTION_TEST",
            project_key="demo",
            run_id="RUN-NEW",
            details={
                "api_key": "super-secret-value",
                "header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "safe_field": "visible",
            },
            jsonl_path=jsonl,
        )
        conn.commit()

    jsonl_text = jsonl.read_text(encoding="utf-8")
    assert "super-secret-value" not in jsonl_text
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in jsonl_text
    assert "[REDACTED]" in jsonl_text
    assert "visible" in jsonl_text

    backup_file = backup_database(db, backup_dir=tmp_path / "backups", jsonl_path=jsonl)
    restored_file = tmp_path / "restored" / "auditor_restored.db"
    verify = verify_backup_restore(backup_file, restore_target=restored_file)
    assert verify["verified"] is True
    assert restored_file.is_file()
    assert check_database_integrity(restored_file)["ok"] is True

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import cli
from db import connect, initialize
from mcp_server import AuditorMCPDispatcher
from skills import _frontmatter, inventory_rules


def test_skills_multiline_frontmatter_and_scoped_sync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sample_md = """---
name: sample-multiline-skill
description: >-
  First line of description
  second line of description.
---
# Body
"""
    name, desc = _frontmatter(sample_md)
    assert name == "sample-multiline-skill"
    assert desc == "First line of description second line of description."

    db_path = tmp_path / "auditor.db"
    initialize(db_path)
    monkeypatch.setattr(cli, "DB_PATH", db_path)

    repo_a = tmp_path / "repo_a"
    (repo_a / ".agents" / "skills" / "skill-a").mkdir(parents=True)
    (repo_a / ".agents" / "skills" / "skill-a" / "SKILL.md").write_text(
        "---\nname: skill-a\ndescription: Skill A\n---\n", encoding="utf-8"
    )
    (repo_a / ".agents" / "rules").mkdir(parents=True)
    (repo_a / ".agents" / "rules" / "01-backend.md").write_text("# Rule 1\n", encoding="utf-8")

    repo_b = tmp_path / "repo_b"
    (repo_b / ".agents" / "skills" / "skill-b").mkdir(parents=True)
    (repo_b / ".agents" / "skills" / "skill-b" / "SKILL.md").write_text(
        "---\nname: skill-b\ndescription: Skill B\n---\n", encoding="utf-8"
    )

    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id) VALUES('proja', 'A', ?, 'id-a')",
            (str(repo_a),),
        )
        conn.execute(
            "INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id) VALUES('projb', 'B', ?, 'id-b')",
            (str(repo_b),),
        )
        conn.commit()

    cli.sync_inventory("proja")
    cli.sync_inventory("projb")

    with connect(db_path) as conn:
        scopes = {
            r["scope"]
            for r in conn.execute("SELECT DISTINCT scope FROM skill_inventory").fetchall()
        }
    assert "workspace:proja" in scopes
    assert "workspace:projb" in scopes

    rules = inventory_rules(repo_a)
    assert any(r["name"] == "01-backend.md" for r in rules)


def test_multi_project_registration_and_mcp_step_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "database" / "auditor.db"
    cfg_path = tmp_path / "config" / "config.json"
    sidecars_dir = tmp_path / "config" / "sidecars"
    initialize(db_path)

    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr(cli, "CONFIG_PATH", cfg_path)
    monkeypatch.setattr(cli, "SIDECAR_ROOT", sidecars_dir)
    monkeypatch.setattr(cli, "JSONL_PATH", tmp_path / "logs" / "audit-events.jsonl")

    # Create two isolated test Git repositories
    for name in ("svc1", "svc2"):
        r = tmp_path / name
        r.mkdir()
        subprocess.run(["git", "-C", str(r), "init"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(r), "config", "user.email", "t@example.com"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(r), "config", "user.name", "Test"], check=True, capture_output=True)
        (r / "mod.py").write_text("def val():\n    return 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(r), "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(r), "commit", "-m", "init"], check=True, capture_output=True)

    ns1 = cli.argparse.Namespace(
        key="svc1",
        path=str(tmp_path / "svc1"),
        project_id="ag-proj-1",
        name="Service 1",
        cron="0 3 * * 1",
        copy_omniapex_rules=True,
    )
    ns2 = cli.argparse.Namespace(
        key="svc2",
        path=str(tmp_path / "svc2"),
        project_id="ag-proj-2",
        name="Service 2",
        cron="30 5 * * 4",
        copy_omniapex_rules=False,
    )
    cli.register(ns1)
    cli.register(ns2)

    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert cfg["sidecars"]["svc1-audit"] == {"enabled": True, "projectId": "ag-proj-1"}
    assert cfg["sidecars"]["svc2-audit"] == {"enabled": True, "projectId": "ag-proj-2"}
    assert (sidecars_dir / "svc1-audit" / "sidecar.json").is_file()
    assert (sidecars_dir / "svc2-audit" / "sidecar.json").is_file()

    # Drive step-by-step execution via MCP dispatcher for svc1
    head_svc1 = subprocess.run(
        ["git", "-C", str(tmp_path / "svc1"), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    with connect(db_path) as conn:
        conn.execute("UPDATE projects SET min_free_mb=1 WHERE project_key='svc1'")
        conn.execute(
            "INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash) VALUES('R-STEP-1', 'svc1', 'DISPATCHED', ?, 'th1')",
            (head_svc1,),
        )
        conn.commit()

    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)
    pub = dispatcher.call_tool(
        "auditor_publish_report",
        {
            "project_key": "svc1",
            "run_id": "R-STEP-1",
            "findings": [
                {
                    "finding_id": "F-STEP-1",
                    "fingerprint": "fp-step-1",
                    "title": "Return explicit int",
                    "category": "V7",
                    "severity": "MEDIUM",
                    "confidence": "CONFIRMED",
                    "file_path": "mod.py",
                    "symbol": "val",
                    "line_start": 1,
                    "line_end": 2,
                    "evidence": "return 1",
                    "impact": "type clarity",
                    "recommendation": "add return annotation",
                }
            ],
        },
    )
    assert pub["status"] == "VERIFICATION_PENDING"
    vrun_id = pub["verification_run_id"]

    dispatcher.call_tool(
        "auditor_submit_verification",
        {
            "audit_run_id": "R-STEP-1",
            "verification_run_id": vrun_id,
            "verifier_metadata": {"invocation_mechanism": "mcp_direct", "actual_subagent_invocations": 0},
                "verifier_conversation_id": "conv-verifier-step-001",
            "verification_results": [
                {
                    "candidate_finding_id": "F-STEP-1",
                    "verdict": "CONFIRMED",
                    "verified_severity": "MEDIUM",
                    "verified_confidence": "CONFIRMED",
                    "technical_rationale": "Confirmed missing return type annotation on val().",
                    "source_evidence": {
                        "file_path": "mod.py",
                        "line_start": 1,
                        "line_end": 2,
                        "symbol": "val",
                        "evidence_excerpt": "return 1",
                    },
                    "remediation_review": "Adding -> int annotation is safe.",
                    "remediation_safe": True,
                    "acceptance_criteria": "Function val() returns 1 with int annotation.",
                }
            ],
        },
    )
    fin = dispatcher.call_tool(
        "auditor_finalize_verified_report",
        {
            "audit_run_id": "R-STEP-1",
            "verification_run_id": vrun_id,
        },
    )
    assert fin["status"] == "READY_FOR_REVIEW"

    dispatcher.call_tool(
        "auditor_save_decisions",
        {
            "project_key": "svc1",
            "run_id": "R-STEP-1",
            "decisions": [{"finding_id": "F-STEP-1", "decision": "APPLY"}],
        },
    )
    # Authorization is human-only over MCP; the Python API stands in for the terminal command here.
    with pytest.raises(PermissionError, match="human-only"):
        dispatcher.call_tool(
            "auditor_authorize_execution",
            {"project_key": "svc1", "run_id": "R-STEP-1", "confirmation": "AUTHORIZE_ISOLATED_WORKTREE_EXECUTION"},
        )
    from db import authorize_execution

    # Decisions that differ from what the human confirmed are refused (no approval is created).
    with pytest.raises(RuntimeError, match="changed after they were shown"):
        authorize_execution(
            cli.DB_PATH, project_key="svc1", run_id="R-STEP-1",
            confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION", expected_finding_ids=["F-OTHER"],
        )
    auth = authorize_execution(
        cli.DB_PATH, project_key="svc1", run_id="R-STEP-1", confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION"
    )
    started = dispatcher.call_tool(
        "auditor_start_execution",
        {"project_key": "svc1", "approval_id": auth["approval_id"]},
    )
    exec_id = started["exec_id"]
    wt = Path(started["worktree_path"])

    begun = dispatcher.call_tool(
        "auditor_update_finding_execution",
        {
            "project_key": "svc1",
            "exec_id": exec_id,
            "finding_id": "F-STEP-1",
            "action": "begin",
        },
    )
    assert begun["status"] == "IN_PROGRESS"

    (wt / "mod.py").write_text("def val() -> int:\n    return 1\n", encoding="utf-8")

    verified = dispatcher.call_tool(
        "auditor_update_finding_execution",
        {
            "project_key": "svc1",
            "exec_id": exec_id,
            "finding_id": "F-STEP-1",
            "action": "verify",
            "happy_test_passed": True,
            "adversarial_test_passed": True,
            "red_team_passed": True,
            "notes": "Verified clean change",
        },
    )
    assert verified["status"] == "VERIFIED"

    finalized = dispatcher.call_tool(
        "auditor_finalize_execution",
        {
            "project_key": "svc1",
            "exec_id": exec_id,
            "integration_test_passed": True,
            "notes": "All tests green",
        },
    )
    assert finalized["status"] == "COMPLETED"
    assert finalized["verified_finding_ids"] == ["F-STEP-1"]
    # The fix is delivered as a local review branch; the user's working tree is untouched.
    review = finalized["review"]
    with connect(cli.DB_PATH) as conn:
        repo = Path(conn.execute("SELECT repo_path FROM projects WHERE project_key='svc1'").fetchone()["repo_path"])
    assert review["branch"].startswith("audit-fix/") and review["merged"] is False and review["pushed"] is False
    assert review["files_changed"] == ["mod.py"]
    assert not wt.exists()
    assert Path(review["patch_path"]).is_file()
    git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)
    assert git("rev-parse", "--verify", f"refs/heads/{review['branch']}").returncode == 0
    assert git("status", "--porcelain", "--untracked-files=no").stdout.strip() == ""  # user working tree untouched
    assert "-> int" not in (repo / "mod.py").read_text(encoding="utf-8")
    assert "-> int" in git("show", f"{review['branch']}:mod.py").stdout

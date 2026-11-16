"""Targeted regression tests for Primary Auditor Plan Mode Compatibility & Skill Context Injection.

Proves:
1. Prompt construction does not require run_command, git status, or shell execution.
2. Precomputed repository metadata is correctly included from deterministic Python control plane.
3. Supported read-only file inspection (read_file) remains available and instructed.
4. Structured candidate findings can reach the ingestion layer via inline JSON without in-repo files.
5. MCP auditor_publish_report writes reports outside monitored repositories, leaving them 100% clean.
6. Dispatch succeeds with mocked adapter without requiring shell or write operations.
7. Security restrictions (mode=plan, strict git allowlist, disabled repair writes) remain intact.
8. Required skill content is injected into the Primary prompt.
9. Missing or invalid skill fails closed.
10. Skill path traversal is rejected.
11. External absolute skill paths are not exposed through model-facing context.
12. Primary prompt does not ask the model to read external skill files.
13. Primary prompt still requires actual source-code inspection.
14. Primary report publication contract remains intact.
15. Existing MCP tool schemas remain backward compatible.
16. Existing plan-mode and write restrictions remain enforced.
17. Context size is bounded.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

# Add core to sys.path
_core_dir = str(Path(__file__).resolve().parents[1] / "core")
if _core_dir not in sys.path:
    sys.path.insert(0, _core_dir)

# Fix Windows pytest symlink cleanup PermissionError on Python 3.15
try:
    import _pytest.pathlib

    _ORIG_CLEANUP = _pytest.pathlib.cleanup_dead_symlinks

    def _safe_cleanup(root: Path) -> None:
        try:
            _ORIG_CLEANUP(root)
        except PermissionError:
            pass

    _pytest.pathlib.cleanup_dead_symlinks = _safe_cleanup
except Exception:
    pass

import pytest

from agy_adapter import AgyDispatchResult, AntigravityCliAdapter, PRIMARY_AUDIT_TIMEOUT_SECONDS
from cli import (
    MAX_MANIFEST_BYTES,
    MAX_MANIFEST_ENTRIES,
    SAFE_READONLY_GIT_COMMANDS,
    build_primary_audit_prompt,
    dispatch,
    format_repo_file_manifest_section,
    generate_repo_file_manifest,
    get_precomputed_repo_metadata,
    publish_report,
    safe_git_query,
)
from model_policy import TaskType
from db import connect, initialize
from mcp_server import TOOL_DEFINITIONS, AuditorMCPDispatcher
from skills import (
    MAX_TRUSTED_SKILL_SIZE,
    format_trusted_skill_section,
    load_trusted_skill_content,
    resolve_trusted_skill_path,
    sanitize_skill_inventory_for_model,
)


@pytest.fixture
def temp_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "target_repo"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "auditor@test.local"],
        cwd=str(repo),
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Auditor Test"],
        cwd=str(repo),
        check=True,
        capture_output=True,
    )
    readme = repo / "README.md"
    readme.write_text("# Test Repo\nInitial content\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(repo), check=True, capture_output=True)
    return repo


@pytest.fixture
def isolated_auditor_env(tmp_path: Path, temp_git_repo: Path):
    app_home = tmp_path / "auditor_home"
    app_home.mkdir(parents=True)
    db_path = app_home / "database" / "auditor.db"
    db_path.parent.mkdir(parents=True)
    initialize(db_path)

    project_key = "test-project"
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects (
                project_key, display_name, repo_path, antigravity_project_id,
                min_free_mb, max_retries, enabled
            ) VALUES (?, ?, ?, ?, 10, 2, 1)""",
            (project_key, "Test Project", str(temp_git_repo), "AG-TEST-001"),
        )
        conn.commit()

    return {
        "app_home": app_home,
        "db_path": db_path,
        "project_key": project_key,
        "repo": temp_git_repo,
    }


def test_01_prompt_construction_no_shell_commands_and_read_only(temp_git_repo: Path) -> None:
    """Prompt construction must not instruct run_command, git status, or shell commands."""
    meta = get_precomputed_repo_metadata(temp_git_repo)
    project_dict = {
        "project_key": "test-repo",
        "display_name": "Test Repository",
    }
    prompt = build_primary_audit_prompt(
        project=project_dict,
        repo=temp_git_repo,
        run_id="RUN-TEST-001",
        commit=meta["head_commit"],
        tree_hash="HASH-123",
        skill_rows=[],
        repo_metadata=meta,
    )

    # Must NOT ask model to run shell or terminal commands
    assert "run_command" not in prompt
    assert "git status" not in prompt
    assert "git diff" not in prompt
    assert "publish-report --project" not in prompt

    # Must specify plan mode, read_file tool, and auditor_publish_report
    assert "PLAN MODE READ-ONLY" in prompt
    assert "read_file" in prompt
    assert "auditor_publish_report" in prompt
    assert "PRECOMPUTED REPOSITORY STATE" in prompt
    assert "WORKING_TREE_STATUS: CLEAN" in prompt
    assert "Do NOT write files into the target repository" in prompt


def test_02_precomputed_repo_metadata_correctly_extracted(temp_git_repo: Path) -> None:
    """Deterministic Python control plane precomputes git metadata safely."""
    meta = get_precomputed_repo_metadata(temp_git_repo)
    assert len(meta["head_commit"]) == 40
    assert meta["branch"] in ("main", "master")
    assert meta["is_clean"] is True
    assert meta["staged_summary"] == "(none)"
    assert meta["unstaged_summary"] == "(none)"

    # Create an untracked file and verify is_clean becomes False
    new_file = temp_git_repo / "unsafe_code.py"
    new_file.write_text("x = 1\n", encoding="utf-8")

    meta_dirty = get_precomputed_repo_metadata(temp_git_repo)
    assert meta_dirty["is_clean"] is False
    assert "unsafe_code.py" in meta_dirty["untracked_summary"]


def test_03_safe_git_query_enforces_allowlist(temp_git_repo: Path) -> None:
    """Only allowlisted read-only git queries are permitted; arbitrary commands raise ValueError."""
    # Allowlisted commands succeed
    head = safe_git_query(temp_git_repo, "rev-parse", "HEAD")
    assert len(head) == 40

    status = safe_git_query(temp_git_repo, "status", "--porcelain")
    assert isinstance(status, str)

    # Disallowed commands must raise ValueError immediately
    with pytest.raises(ValueError, match="Disallowed git command"):
        safe_git_query(temp_git_repo, "commit", "-m", "Exploit")

    with pytest.raises(ValueError, match="Disallowed git command"):
        safe_git_query(temp_git_repo, "push", "origin", "main")

    with pytest.raises(ValueError, match="Disallowed git command"):
        safe_git_query(temp_git_repo, "checkout", "HEAD~1")

    # Invalid directory must raise ValueError
    with pytest.raises(ValueError, match="not a valid directory"):
        safe_git_query(temp_git_repo / "nonexistent", "rev-parse", "HEAD")


def test_04_publish_report_cli_with_inline_findings_json(
    isolated_auditor_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLI publish-report with --findings-json ingests findings without requiring in-repo files."""
    db_path = isolated_auditor_env["db_path"]
    app_home = isolated_auditor_env["app_home"]
    pkey = isolated_auditor_env["project_key"]
    repo = isolated_auditor_env["repo"]

    # Target file in repo
    vulnerable_file = repo / "db_helper.py"
    vulnerable_file.write_text(
        'def query(sql):\n    cursor.execute("SELECT * FROM users WHERE id = " + sql)\n', encoding="utf-8"
    )

    run_id = "RUN-CLI-INLINE-001"
    meta = get_precomputed_repo_metadata(repo)
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO audit_runs (
                run_id, project_key, status, base_commit, working_tree_hash, retry_count, max_retries
            ) VALUES (?, ?, 'PRIMARY_AUDIT_RUNNING', ?, 'HASH-001', 0, 2)""",
            (run_id, pkey, meta["head_commit"]),
        )
        conn.commit()

    sample_finding = {
        "finding_id": "FIND-SQLI-001",
        "fingerprint": "FP-SQLI-001",
        "title": "SQL Injection in db_helper",
        "category": "V4-Security",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "file_path": "db_helper.py",
        "symbol": "query",
        "line_start": 2,
        "line_end": 2,
        "evidence": 'cursor.execute("SELECT * FROM users WHERE id = " + sql)',
        "impact": "Arbitrary SQL execution",
        "recommendation": "Use parameterized queries",
    }
    findings_json = json.dumps([sample_finding])

    monkeypatch.setattr("cli.DB_PATH", db_path)
    monkeypatch.setattr("cli.APP_HOME", app_home)
    monkeypatch.setattr("cli.JSONL_PATH", app_home / "logs" / "audit-events.jsonl")

    args = argparse.Namespace(
        project=pkey,
        run_id=run_id,
        file=None,
        findings_json=findings_json,
    )
    publish_report(args)

    with connect(db_path) as conn:
        run = conn.execute("SELECT status FROM audit_runs WHERE run_id=?", (run_id,)).fetchone()
        assert run["status"] == "VERIFICATION_PENDING"

        candidates = conn.execute("SELECT * FROM candidate_findings WHERE run_id=?", (run_id,)).fetchall()
        assert len(candidates) == 1
        assert candidates[0]["title"] == "SQL Injection in db_helper"
        assert candidates[0]["severity"] == "CRITICAL"

    # Monitored repo MUST NOT contain .antigravity-audit
    assert not (repo / ".antigravity-audit").exists()

    # Reports must be persisted under APP_HOME/reports/run_id
    reports_dir = app_home / "reports" / run_id
    assert (reports_dir / "findings.json").exists()
    assert (reports_dir / "review-report.md").exists()


def test_05_mcp_auditor_publish_report_leaves_repo_clean(isolated_auditor_env: dict[str, Any]) -> None:
    """MCP tool auditor_publish_report with inline findings writes to app_home and leaves repo clean."""
    db_path = isolated_auditor_env["db_path"]
    app_home = isolated_auditor_env["app_home"]
    pkey = isolated_auditor_env["project_key"]
    repo = isolated_auditor_env["repo"]

    meta = get_precomputed_repo_metadata(repo)
    run_id = "RUN-MCP-001"
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO audit_runs (
                run_id, project_key, status, base_commit, working_tree_hash, retry_count, max_retries
            ) VALUES (?, ?, 'PRIMARY_AUDIT_RUNNING', ?, 'HASH-002', 0, 2)""",
            (run_id, pkey, meta["head_commit"]),
        )
        conn.commit()

    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=app_home)
    sample_finding = {
        "finding_id": "FIND-MCP-001",
        "fingerprint": "FP-MCP-001",
        "title": "Unsafe path concatenation",
        "category": "V4-Security",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "file_path": "README.md",
        "symbol": None,
        "line_start": 1,
        "line_end": 1,
        "evidence": "# Test Repo",
        "impact": "Path traversal",
        "recommendation": "Use resolve() with strict boundary checks",
    }

    res = dispatcher.call_tool(
        "auditor_publish_report",
        {
            "project_key": pkey,
            "run_id": run_id,
            "findings": [sample_finding],
        },
    )

    assert res["status"] == "VERIFICATION_PENDING"
    assert res["stats"]["unique_in_run"] == 1

    # Verify repo directory is completely clean and unmodified
    assert not (repo / ".antigravity-audit").exists()

    # Verify report is written to app_home/reports/run_id
    report_file = app_home / "reports" / run_id / "findings.json"
    assert report_file.exists()
    assert (app_home / "reports" / run_id / "review-report.md").exists()


def test_06_dispatch_completes_with_mocked_adapter(
    isolated_auditor_env: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Primary audit dispatch executes smoothly without shell commands using mocked AntigravityCliAdapter."""
    db_path = isolated_auditor_env["db_path"]
    app_home = isolated_auditor_env["app_home"]
    pkey = isolated_auditor_env["project_key"]
    repo = isolated_auditor_env["repo"]

    monkeypatch.setattr("cli.DB_PATH", db_path)
    monkeypatch.setattr("cli.APP_HOME", app_home)
    monkeypatch.setattr("cli.JSONL_PATH", app_home / "logs" / "audit-events.jsonl")

    fake_conversation_id = "conv-mock-12345"
    mock_dispatch_result = AgyDispatchResult(
        ok=True,
        status="SUCCESS",
        requested_model="gemini-4-hydrogen-high",
        observed_model="gemini-4-hydrogen-high",
        conversation_id=fake_conversation_id,
        response_text='{"findings": []}',  # structured delivery (headless agy cannot use MCP)
        input_tokens=100,
        output_tokens=50,
        thinking_tokens=10,
        total_tokens=160,
        execution_duration=1.5,
        command=["agy.exe"],
        returncode=0,
        stdout="",
        stderr="",
        attestation_status="RUNTIME_ATTESTED",
    )

    captured_prompt: list[str] = []

    captured_kwargs: list[dict] = []

    def fake_start_new_conversation(self, prompt, **kwargs):
        captured_prompt.append(prompt)
        captured_kwargs.append(kwargs)
        return mock_dispatch_result

    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    with patch.object(AntigravityCliAdapter, "discover_executable", return_value=fake_exe):
        with patch.object(AntigravityCliAdapter, "start_new_conversation", fake_start_new_conversation):
            dispatch(pkey)

    # Verify prompt captured
    assert len(captured_prompt) == 1
    p = captured_prompt[0]
    assert "PLAN MODE READ-ONLY" in p
    # Structured delivery: no MCP submission instructions, JSON result contract instead.
    assert "invoke the MCP tool `auditor_publish_report`" not in p
    assert "MCP DATA EXCHANGE" not in p
    assert "RESULT CONTRACT (STRUCTURED OUTPUT - NO MCP TOOLS)" in p
    assert "PRECEDENCE:" in p
    assert captured_kwargs[0]["isolated"] is True and captured_kwargs[0]["json_schema_path"] is not None

    # Verify run updated in SQLite
    with connect(db_path) as conn:
        run = conn.execute("SELECT * FROM audit_runs WHERE project_key=?", (pkey,)).fetchone()
        assert run is not None
        assert run["agent_conversation_id"] == fake_conversation_id
        assert run["primary_model"] == "gemini-4-hydrogen-high"
        assert run["primary_model_attestation"] == "RUNTIME_ATTESTED"


def test_07_existing_security_restrictions_preserved(tmp_path: Path) -> None:
    """Strict security invariants remain untouched."""
    fake_exe = tmp_path / "agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe))
    cmd = adapter.build_command(
        prompt="Audit test",
        model_id="gemini-4-hydrogen-high",
    )
    # Must enforce --mode plan
    assert "--mode" in cmd
    idx = cmd.index("--mode")
    assert cmd[idx + 1] == "plan"

    # Safe readonly commands must not include mutating commands
    for disallowed in [
        ("commit",),
        ("push",),
        ("checkout",),
        ("reset",),
        ("rebase",),
        ("clean",),
    ]:
        assert disallowed not in SAFE_READONLY_GIT_COMMANDS


# ==============================================================================
# PHASE 5 TARGETED REGRESSION TESTS: SKILL CONTEXT INJECTION & WORKSPACE BOUNDARY
# ==============================================================================


def test_08_required_skill_content_injected_into_primary_prompt(temp_git_repo: Path) -> None:
    """Requirement 1: Required skill content is injected directly into the Primary prompt."""
    meta = get_precomputed_repo_metadata(temp_git_repo)
    project_dict = {
        "project_key": "test-repo",
        "display_name": "Test Repository",
    }
    prompt = build_primary_audit_prompt(
        project=project_dict,
        repo=temp_git_repo,
        run_id="RUN-INJECT-001",
        commit=meta["head_commit"],
        tree_hash="HASH-INJECT-001",
        skill_rows=[],
        repo_metadata=meta,
    )

    # Injected delimited block must be present
    assert "=== BEGIN TRUSTED AUDIT PROTOCOL INSTRUCTIONS (project-auditor-orchestrator) ===" in prompt
    assert "=== END TRUSTED AUDIT PROTOCOL INSTRUCTIONS (project-auditor-orchestrator) ===" in prompt

    # Verify actual SKILL.md content is contained inside
    assert "Project Auditor Orchestrator" in prompt
    assert "Two-pass audit lifecycle & role separation" in prompt
    assert "Scheduled audit mode" in prompt
    assert "Primary Auditor Role (`adversarial-red-team`)" in prompt


def test_09_missing_or_invalid_skill_fails_closed(tmp_path: Path, temp_git_repo: Path) -> None:
    """Requirement 2: Missing or invalid skill fails closed."""
    # Nonexistent skill raises FileNotFoundError
    with pytest.raises(FileNotFoundError, match="not found within trusted application roots"):
        resolve_trusted_skill_path("nonexistent-skill-xyz")

    with pytest.raises(FileNotFoundError, match="not found within trusted application roots"):
        load_trusted_skill_content("nonexistent-skill-xyz")

    meta = get_precomputed_repo_metadata(temp_git_repo)
    project_dict = {"project_key": "test-repo", "display_name": "Test Repository"}

    with pytest.raises(FileNotFoundError, match="not found within trusted application roots"):
        build_primary_audit_prompt(
            project=project_dict,
            repo=temp_git_repo,
            run_id="RUN-FAIL-001",
            commit=meta["head_commit"],
            tree_hash="HASH-001",
            skill_rows=[],
            repo_metadata=meta,
            trusted_skill_name="nonexistent-skill-xyz",
        )

    # Empty skill file fails closed with RuntimeError
    fake_root = tmp_path / "fake_app_root"
    fake_skill_dir = fake_root / "global-skills" / "empty-skill"
    fake_skill_dir.mkdir(parents=True)
    (fake_skill_dir / "SKILL.md").write_text("   \n\n  ", encoding="utf-8")

    with pytest.raises(RuntimeError, match="is empty"):
        load_trusted_skill_content("empty-skill", package_root=fake_root)


def test_10_skill_path_traversal_is_rejected() -> None:
    """Requirement 3: Skill path traversal is strictly rejected."""
    traversal_payloads = [
        "../etc/passwd",
        "../../skills",
        "skill/subpath",
        r"skill\subpath",
        "skill;rm",
        "skill name with spaces",
        "skill*wildcard",
        "skill?question",
        "",
        "a" * 65,  # Exceeds max identifier length
    ]
    for bad_name in traversal_payloads:
        with pytest.raises(ValueError, match="Invalid or unsafe skill name"):
            resolve_trusted_skill_path(bad_name)

        with pytest.raises(ValueError, match="Invalid or unsafe skill name"):
            load_trusted_skill_content(bad_name)


def test_11_external_skill_paths_not_exposed_in_model_context(isolated_auditor_env: dict[str, Any]) -> None:
    """Requirement 4: External absolute skill paths are not exposed through model-facing context."""
    db_path = isolated_auditor_env["db_path"]
    app_home = isolated_auditor_env["app_home"]
    pkey = isolated_auditor_env["project_key"]

    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=app_home)
    context = dispatcher.call_tool("auditor_get_context", {"project_key": pkey})

    assert "skills" in context
    skills = context["skills"]
    assert isinstance(skills, list)
    assert len(skills) > 0

    # Ensure no skill item exposes a filesystem path or content hash to the model
    for item in skills:
        assert "path" not in item, f"External filesystem path leaked in MCP context: {item}"
        assert "sha256" not in item, f"File hash leaked in MCP context: {item}"
        assert set(item.keys()) == {"name", "scope", "description"}

        # Values must not contain path strings
        for val in item.values():
            assert "global-skills" not in val
            assert ":\\" not in val  # Windows drive path
            assert not val.startswith("/")  # Unix absolute path

    # Directly verify sanitize_skill_inventory_for_model
    raw_inventory = [
        {
            "name": "project-auditor-orchestrator",
            "scope": "bundle-global",
            "path": r"C:\sensitive\auditor\global-skills\project-auditor-orchestrator\SKILL.md",
            "sha256": "abc123",
            "description": "Orchestrates audits.",
        },
        {
            "name": "unrelated-global-skill",
            "scope": "global",
            "path": r"C:\Users\example\.gemini\config\skills\unrelated\SKILL.md",
            "sha256": "def456",
            "description": "Unrelated skill.",
        },
    ]
    sanitized = sanitize_skill_inventory_for_model(raw_inventory)
    assert len(sanitized) == 1
    assert sanitized[0]["name"] == "project-auditor-orchestrator"
    assert "path" not in sanitized[0]
    assert "sha256" not in sanitized[0]


def test_12_primary_prompt_does_not_ask_model_to_read_external_skill_files(temp_git_repo: Path) -> None:
    """Requirement 5: Primary prompt does not ask the model to read external skill files."""
    meta = get_precomputed_repo_metadata(temp_git_repo)
    project_dict = {"project_key": "test-repo", "display_name": "Test Repository"}
    prompt = build_primary_audit_prompt(
        project=project_dict,
        repo=temp_git_repo,
        run_id="RUN-EXT-001",
        commit=meta["head_commit"],
        tree_hash="HASH-EXT-001",
        skill_rows=[],
        repo_metadata=meta,
    )

    # Must NOT instruct reading external SKILL.md
    assert "Read and apply relevant SKILL.md files" not in prompt

    # Must explicitly instruct boundary rules forbidding reading external Auditor directories
    assert "Do NOT attempt to read external skill files or files in the Auditor installation directory" in prompt
    assert "Do NOT call read_file or any tool on the Auditor installation directory or external paths" in prompt


def test_13_primary_prompt_still_requires_actual_source_code_inspection(temp_git_repo: Path) -> None:
    """Requirement 6: Primary prompt still requires actual source-code inspection."""
    meta = get_precomputed_repo_metadata(temp_git_repo)
    project_dict = {"project_key": "test-repo", "display_name": "Test Repository"}
    prompt = build_primary_audit_prompt(
        project=project_dict,
        repo=temp_git_repo,
        run_id="RUN-INSP-001",
        commit=meta["head_commit"],
        tree_hash="HASH-INSP-001",
        skill_rows=[],
        repo_metadata=meta,
    )

    # Must mandate inspecting source code within the monitored repository using read_file
    assert f"Inspect source files ONLY within the monitored repository path `{temp_git_repo}`" in prompt
    assert "Use supported read-only file inspection tools (`read_file`)" in prompt
    assert "Continue inspecting files until comprehensive coverage of the codebase is achieved" in prompt
    assert "Apply the OmniApex V1-V7 rubric" in prompt
    assert "Every candidate finding must include exact, verifiable evidence" in prompt


def test_14_primary_report_publication_contract_remains_intact(isolated_auditor_env: dict[str, Any]) -> None:
    """Requirement 7: Primary report publication contract remains intact."""
    meta = get_precomputed_repo_metadata(isolated_auditor_env["repo"])
    project_dict = {"project_key": "test-repo", "display_name": "Test Repository"}
    prompt = build_primary_audit_prompt(
        project=project_dict,
        repo=isolated_auditor_env["repo"],
        run_id="RUN-PUB-001",
        commit=meta["head_commit"],
        tree_hash="HASH-PUB-001",
        skill_rows=[],
        repo_metadata=meta,
    )

    # Finding submission contract must be present with auditor_publish_report and schema
    assert "FINDING SUBMISSION CONTRACT:" in prompt
    assert "auditor_publish_report" in prompt
    assert "finding_id (stable string), fingerprint (stable string), title, category, severity, confidence" in prompt
    assert "file_path (relative string), symbol (string or null), line_start (integer), line_end (integer)" in prompt
    assert "evidence, impact, recommendation" in prompt


def test_15_existing_mcp_tool_schemas_backward_compatible() -> None:
    """Requirement 8: Existing MCP tool schemas remain backward compatible."""
    tools_by_name = {t["name"]: t for t in TOOL_DEFINITIONS}

    assert "auditor_get_context" in tools_by_name
    get_ctx = tools_by_name["auditor_get_context"]
    assert get_ctx["inputSchema"]["required"] == ["project_key"]
    assert get_ctx["outputSchema"]["required"] == [
        "project",
        "latest_run",
        "skills",
        "finding_counts",
        "recent_history",
    ]
    assert get_ctx["outputSchema"]["properties"]["skills"]["type"] == "array"

    assert "auditor_publish_report" in tools_by_name
    pub_rep = tools_by_name["auditor_publish_report"]
    assert set(pub_rep["inputSchema"]["required"]) == {"project_key", "run_id"}
    assert "findings" in pub_rep["inputSchema"]["properties"]

    assert "auditor_get_verification_context" in tools_by_name
    assert "auditor_submit_verification" in tools_by_name


def test_16_existing_plan_mode_and_write_restrictions_remain_enforced(temp_git_repo: Path, tmp_path: Path) -> None:
    """Requirement 9: Existing plan-mode and write restrictions remain enforced."""
    meta = get_precomputed_repo_metadata(temp_git_repo)
    project_dict = {"project_key": "test-repo", "display_name": "Test Repository"}
    prompt = build_primary_audit_prompt(
        project=project_dict,
        repo=temp_git_repo,
        run_id="RUN-PLAN-001",
        commit=meta["head_commit"],
        tree_hash="HASH-PLAN-001",
        skill_rows=[],
        repo_metadata=meta,
    )

    # Plan mode constraints in prompt
    assert "PLAN MODE READ-ONLY" in prompt
    assert "Do NOT attempt to run shell or terminal commands" in prompt
    assert "Do NOT edit, create, delete, format, or auto-fix source files" in prompt
    assert "Do NOT write files into the target repository" in prompt

    # Cli adapter enforces --mode plan
    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")
    adapter = AntigravityCliAdapter(executable_override=str(fake_exe))
    cmd = adapter.build_command(prompt="Test audit", model_id="gemini-4-hydrogen-high")
    assert "--mode" in cmd
    assert cmd[cmd.index("--mode") + 1] == "plan"


def test_17_context_size_is_bounded(tmp_path: Path) -> None:
    """Requirement 10: Context size is bounded and limits are enforced."""
    # Size limit enforced on loading
    fake_root = tmp_path / "oversized_root"
    fake_skill_dir = fake_root / "global-skills" / "big-skill"
    fake_skill_dir.mkdir(parents=True)
    oversized_content = "x" * 2000
    (fake_skill_dir / "SKILL.md").write_text(oversized_content, encoding="utf-8")

    # If max_size=1000, must fail closed
    with pytest.raises(RuntimeError, match="exceeds limit"):
        load_trusted_skill_content("big-skill", package_root=fake_root, max_size=1000)

    # Actual bundle skill must be well within MAX_TRUSTED_SKILL_SIZE
    content = load_trusted_skill_content("project-auditor-orchestrator")
    content_bytes = len(content.encode("utf-8"))
    assert content_bytes < MAX_TRUSTED_SKILL_SIZE
    assert content_bytes > 500  # Non-trivial size


# ==============================================================================
# PHASE 5 TARGETED REGRESSION TESTS: DETERMINISTIC FILE DISCOVERY & TASK TIMEOUT
# ==============================================================================


def test_18_clean_committed_repo_produces_complete_manifest(temp_git_repo: Path) -> None:
    """Requirement 1: Clean committed repositories produce a complete file manifest."""
    src_dir = temp_git_repo / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")
    docs_dir = temp_git_repo / "docs"
    docs_dir.mkdir(parents=True)
    (docs_dir / "index.md").write_text("# Documentation\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=str(temp_git_repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Add source and docs"], cwd=str(temp_git_repo), check=True, capture_output=True)

    meta = get_precomputed_repo_metadata(temp_git_repo)
    assert meta["is_clean"] is True

    manifest = generate_repo_file_manifest(temp_git_repo)
    assert manifest["is_truncated"] is False
    assert manifest["coverage_status"] == "COMPLETE"
    assert manifest["total_discovered"] == 3
    assert manifest["included_count"] == 3
    assert manifest["excluded_sensitive_count"] == 0
    assert manifest["unsupported_binary_count"] == 0

    rel_paths = {e["relative_path"] for e in manifest["entries"]}
    assert rel_paths == {"README.md", "src/app.py", "docs/index.md"}

    # Verify each entry contains relative_path, file_size_bytes, file_type
    for e in manifest["entries"]:
        assert "relative_path" in e
        assert "file_size_bytes" in e
        assert "file_type" in e
        assert isinstance(e["file_size_bytes"], int)
        assert e["file_size_bytes"] > 0


def test_19_both_synthetic_source_files_present_in_manifest(tmp_path: Path) -> None:
    """Requirement 2: Both synthetic source files appear in the manifest even with clean tree."""
    repo = tmp_path / "synthetic_fixture"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "auditor@test.local"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Auditor Test"], cwd=str(repo), check=True, capture_output=True)

    src_dir = repo / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "user_store.py").write_text("class UserStore:\n    pass\n", encoding="utf-8")
    (src_dir / "file_vault.py").write_text("class FileVault:\n    pass\n", encoding="utf-8")
    (repo / "README.md").write_text("# Synthetic Fixture\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(repo), check=True, capture_output=True)

    meta = get_precomputed_repo_metadata(repo)
    assert meta["is_clean"] is True

    manifest = meta["manifest"]
    assert manifest["coverage_status"] == "COMPLETE"
    assert manifest["is_truncated"] is False

    rel_paths = [e["relative_path"] for e in manifest["entries"]]
    assert "src/user_store.py" in rel_paths
    assert "src/file_vault.py" in rel_paths

    user_store_entry = next(e for e in manifest["entries"] if e["relative_path"] == "src/user_store.py")
    assert user_store_entry["file_type"] == ".py"
    assert user_store_entry["file_size_bytes"] > 0

    file_vault_entry = next(e for e in manifest["entries"] if e["relative_path"] == "src/file_vault.py")
    assert file_vault_entry["file_type"] == ".py"
    assert file_vault_entry["file_size_bytes"] > 0


def test_20_non_ignored_untracked_included_and_ignored_untracked_excluded(temp_git_repo: Path) -> None:
    """Requirements 3 & 4: Non-ignored untracked files included, ignored untracked files excluded."""
    # Create .gitignore
    (temp_git_repo / ".gitignore").write_text("*.ignored\nignored_folder/\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=str(temp_git_repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Add gitignore"], cwd=str(temp_git_repo), check=True, capture_output=True)

    # Non-ignored untracked file
    (temp_git_repo / "untracked_script.py").write_text("x = 42\n", encoding="utf-8")

    # Ignored untracked files
    (temp_git_repo / "temp.ignored").write_text("ignored\n", encoding="utf-8")
    ignored_dir = temp_git_repo / "ignored_folder"
    ignored_dir.mkdir(parents=True)
    (ignored_dir / "cache.dat").write_text("cache\n", encoding="utf-8")

    manifest = generate_repo_file_manifest(temp_git_repo)
    rel_paths = {e["relative_path"] for e in manifest["entries"]}

    assert "untracked_script.py" in rel_paths
    assert "temp.ignored" not in rel_paths
    assert "ignored_folder/cache.dat" not in rel_paths


def test_21_git_internals_and_symlinks_excluded(temp_git_repo: Path) -> None:
    """Requirements 5 & 6: .git internals and symlinks escaping root are excluded."""
    manifest = generate_repo_file_manifest(temp_git_repo)
    rel_paths = {e["relative_path"] for e in manifest["entries"]}

    for p in rel_paths:
        assert not p.startswith(".git")
        assert ".git" not in Path(p).parts

    # Try creating symlink if OS permissions allow
    try:
        symlink_path = temp_git_repo / "symlink_to_readme.md"
        symlink_path.symlink_to(temp_git_repo / "README.md")
        subprocess.run(["git", "add", "symlink_to_readme.md"], cwd=str(temp_git_repo), check=True, capture_output=True)
        manifest_sym = generate_repo_file_manifest(temp_git_repo)
        sym_paths = {e["relative_path"] for e in manifest_sym["entries"]}
        assert "symlink_to_readme.md" not in sym_paths
    except (OSError, NotImplementedError, subprocess.CalledProcessError):
        pass


def test_22_sensitive_file_paths_not_exposed(temp_git_repo: Path) -> None:
    """Requirement 7: Sensitive and credential files are excluded and paths not exposed."""
    sensitive_files = [
        ".env",
        ".env.local",
        ".env.production",
        "id_rsa",
        "credentials.json",
        "service-account.json",
        "database.sqlite3",
        "server.key",
        "cert.pem",
    ]
    for sf in sensitive_files:
        (temp_git_repo / sf).write_text("SECRET_DATA=123\n", encoding="utf-8")

    # Allowed template should be kept
    (temp_git_repo / ".env.example").write_text("HOST=localhost\n", encoding="utf-8")

    subprocess.run(["git", "add", "-f", "."], cwd=str(temp_git_repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Add files with secrets"], cwd=str(temp_git_repo), check=True, capture_output=True)

    manifest = generate_repo_file_manifest(temp_git_repo)
    entries = manifest["entries"]
    entry_paths = {e["relative_path"] for e in entries}

    for sf in sensitive_files:
        assert sf not in entry_paths, f"Sensitive file exposed in entries: {sf}"

    assert manifest["excluded_sensitive_count"] >= len(sensitive_files)
    assert ".env.example" in entry_paths

    formatted = format_repo_file_manifest_section(manifest)
    for sf in sensitive_files:
        assert f"relative_path: {sf} |" not in formatted


def test_23_manifest_limits_enforced_and_truncation_explicit(temp_git_repo: Path) -> None:
    """Requirements 8 & 9: Manifest entry and byte limits are enforced, truncation is explicit."""
    # Test entry limit: create 510 files
    files_dir = temp_git_repo / "many_files"
    files_dir.mkdir(parents=True)
    for i in range(510):
        (files_dir / f"f_{i:04d}.txt").write_text(f"content {i}\n", encoding="utf-8")

    subprocess.run(["git", "add", "many_files"], cwd=str(temp_git_repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Add 510 files"], cwd=str(temp_git_repo), check=True, capture_output=True)

    manifest = generate_repo_file_manifest(temp_git_repo)
    assert manifest["is_truncated"] is True
    assert manifest["included_count"] <= MAX_MANIFEST_ENTRIES
    assert len(manifest["entries"]) <= MAX_MANIFEST_ENTRIES
    assert manifest["total_discovered"] >= 510
    assert manifest["coverage_status"] == "INCOMPLETE (MANIFEST TRUNCATED)"

    formatted = format_repo_file_manifest_section(manifest)
    assert "TRUNCATION_STATUS: TRUNCATED" in formatted
    assert "REPOSITORY_COVERAGE: INCOMPLETE (MANIFEST TRUNCATED)" in formatted
    assert "Repository inspection coverage is INCOMPLETE" in formatted
    assert len(formatted.encode("utf-8")) <= MAX_MANIFEST_BYTES


def test_24_manifest_injected_into_primary_prompt(temp_git_repo: Path) -> None:
    """Requirement 10: Precomputed manifest is injected into Primary prompt."""
    meta = get_precomputed_repo_metadata(temp_git_repo)
    project_dict = {"project_key": "test-repo", "display_name": "Test Repository"}
    prompt = build_primary_audit_prompt(
        project=project_dict,
        repo=temp_git_repo,
        run_id="RUN-MAN-001",
        commit=meta["head_commit"],
        tree_hash="HASH-MAN-001",
        skill_rows=[],
        repo_metadata=meta,
    )

    assert "=== PRECOMPUTED REPOSITORY FILE MANIFEST ===" in prompt
    assert "=== END PRECOMPUTED REPOSITORY FILE MANIFEST ===" in prompt
    assert "TOTAL_DISCOVERED_FILES:" in prompt
    assert "INCLUDED_FILES:" in prompt
    assert "TRUNCATION_STATUS: NOT TRUNCATED" in prompt
    assert "REPOSITORY_COVERAGE: COMPLETE" in prompt
    assert "README.md" in prompt


def test_25_primary_prompt_manifest_instructions_and_prohibitions(temp_git_repo: Path) -> None:
    """Requirements 11, 12, 13, 14: Prompt prohibits shell, Git, subagent discovery, and mandates read_file."""
    meta = get_precomputed_repo_metadata(temp_git_repo)
    project_dict = {"project_key": "test-repo", "display_name": "Test Repository"}
    prompt = build_primary_audit_prompt(
        project=project_dict,
        repo=temp_git_repo,
        run_id="RUN-INST-001",
        commit=meta["head_commit"],
        tree_hash="HASH-INST-001",
        skill_rows=[],
        repo_metadata=meta,
    )

    # 1. Directory enumeration is unnecessary
    assert "Directory enumeration is unnecessary" in prompt

    # 2. Shell and terminal commands forbidden
    assert "Shell and terminal commands are forbidden" in prompt

    # 3. Git commands forbidden
    assert "Git commands are forbidden" in prompt

    # 4. Subagent delegation forbidden
    assert "Subagent delegation for repository discovery is forbidden" in prompt

    # 5. Inspect source files listed in manifest
    assert "Inspect source files listed in the manifest" in prompt

    # 6. Exact relative paths with read_file
    assert "The model must use exact relative paths with supported read-only `read_file`" in prompt

    # 7. Do not inspect sensitive files
    assert "Do not inspect excluded sensitive files" in prompt

    # 8. Report incomplete coverage if truncated
    assert "If the manifest is truncated, report incomplete coverage" in prompt


def test_26_task_specific_timeout_primary_300s_and_others_unchanged(tmp_path: Path) -> None:
    """Requirements 15 & 16: Primary timeout is exactly 300s, other tasks retain existing timeout (120s)."""
    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    captured_timeouts: list[int | None] = []

    def spy_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured_timeouts.append(kwargs.get("timeout"))
        return subprocess.CompletedProcess(cmd, returncode=0, stdout='{"event":"result","data":{"status":"SUCCESS"}}\n', stderr="")

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner)

    # Base adapter timeout remains unchanged (120s)
    assert adapter.timeout_seconds == 120
    assert PRIMARY_AUDIT_TIMEOUT_SECONDS == 300

    # 1. PRIMARY_AUDIT without explicit timeout -> gets exactly 300s
    adapter.start_new_conversation(
        "Audit repo",
        task_type=TaskType.PRIMARY_AUDIT,
        cwd=tmp_path,
    )
    assert captured_timeouts[-1] == 300

    # 2. ROUTINE_VERIFICATION without explicit timeout -> verification timeout (900s)
    adapter.start_new_conversation(
        "Verify finding",
        task_type=TaskType.ROUTINE_VERIFICATION,
        cwd=tmp_path,
    )
    assert captured_timeouts[-1] == 900

    # 3. CRITICAL_VERIFICATION without explicit timeout -> verification timeout (900s)
    adapter.start_new_conversation(
        "Verify critical finding",
        task_type=TaskType.CRITICAL_VERIFICATION,
        cwd=tmp_path,
    )
    assert captured_timeouts[-1] == 900

    # 4. Direct dispatch without task_type -> gets default 120s
    adapter.dispatch(
        prompt="Direct prompt",
        model_id="gemini-4-hydrogen-high",
        cwd=tmp_path,
    )
    assert captured_timeouts[-1] == 120

    # 5. Explicit caller override takes precedence
    adapter.start_new_conversation(
        "Audit with custom timeout",
        task_type=TaskType.PRIMARY_AUDIT,
        cwd=tmp_path,
        timeout_seconds=450,
    )
    assert captured_timeouts[-1] == 450



def test_27_assistant_output_containing_unauthorized_does_not_fail_auth(tmp_path: Path) -> None:
    """Requirement 1: Assistant output containing 'unauthorized' does not cause authentication failure."""
    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    stdout_stream = (
        '{"event":"init","conversation_id":"cid-auth-01","init":{"model":"gemini-4-hydrogen-high"}}\n'
        '{"event":"step_update","step_update":{"conversation_id":"cid-auth-01","text_delta":"Identified an unauthorized access vulnerability in file_vault.py allowing path traversal."}}\n'
        '{"event":"result","result":{"status":"SUCCESS","response":"Identified an unauthorized access vulnerability in file_vault.py allowing path traversal."}}\n'
    )

    def spy_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=stdout_stream, stderr="")

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner)
    res = adapter.dispatch(prompt="Audit repo", model_id="gemini-4-hydrogen-high", cwd=tmp_path)

    assert res.ok is True
    assert res.status == "SUCCESS"
    assert "unauthorized access vulnerability" in res.response_text
    assert res.error_code is None


def test_28_assistant_output_containing_credential_harvesting_does_not_fail_auth(tmp_path: Path) -> None:
    """Requirement 2: Assistant output containing 'credential harvesting' does not cause authentication failure."""
    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    stdout_stream = (
        '{"event":"init","conversation_id":"cid-auth-02","init":{"model":"gemini-4-hydrogen-high"}}\n'
        '{"event":"step_update","step_update":{"conversation_id":"cid-auth-02","text_delta":"The code is vulnerable to credential harvesting and invalid credentials storage."}}\n'
        '{"event":"result","result":{"status":"SUCCESS","response":"The code is vulnerable to credential harvesting and invalid credentials storage."}}\n'
    )

    def spy_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=stdout_stream, stderr="")

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner)
    res = adapter.dispatch(prompt="Audit credentials", model_id="gemini-4-hydrogen-high", cwd=tmp_path)

    assert res.ok is True
    assert res.status == "SUCCESS"
    assert "credential harvesting" in res.response_text


def test_29_assistant_output_discussing_http_401_does_not_fail_auth(tmp_path: Path) -> None:
    """Requirement 3: Assistant output discussing HTTP 401 does not cause authentication failure."""
    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    stdout_stream = (
        '{"event":"init","conversation_id":"cid-auth-03","init":{"model":"gemini-4-hydrogen-high"}}\n'
        '{"event":"step_update","step_update":{"conversation_id":"cid-auth-03","text_delta":"Endpoints should return HTTP 401 Unauthorized when auth tokens are omitted."}}\n'
        '{"event":"result","result":{"status":"SUCCESS","response":"Endpoints should return HTTP 401 Unauthorized when auth tokens are omitted."}}\n'
    )

    def spy_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=stdout_stream, stderr="")

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner)
    res = adapter.dispatch(prompt="Audit HTTP headers", model_id="gemini-4-hydrogen-high", cwd=tmp_path)

    assert res.ok is True
    assert res.status == "SUCCESS"
    assert "HTTP 401 Unauthorized" in res.response_text


def test_30_mcp_tool_output_containing_unauthorized_does_not_fail_auth(tmp_path: Path) -> None:
    """Requirement 4: MCP tool output containing 'unauthorized' does not cause authentication failure."""
    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    stdout_stream = (
        '{"event":"init","conversation_id":"cid-auth-04","init":{"model":"gemini-4-hydrogen-high"}}\n'
        '{"event":"tool_call","tool_call":{"name":"auditor_publish_report","arguments":{"findings":[{"title":"Unauthorized arbitrary file read"}]}}}\n'
        '{"event":"tool_result","tool_result":{"published":true,"summary":"Published finding: Unauthorized arbitrary file read"}}\n'
        '{"event":"result","result":{"status":"SUCCESS","response":"Report published."}}\n'
    )

    def spy_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=stdout_stream, stderr="")

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner)
    res = adapter.dispatch(prompt="Publish report", model_id="gemini-4-hydrogen-high", cwd=tmp_path)

    assert res.ok is True
    assert res.status == "SUCCESS"
    assert res.error_code is None


def test_31_real_explicit_cli_authentication_error_is_detected(tmp_path: Path) -> None:
    """Requirement 5: A real explicit CLI authentication error on stderr is detected."""
    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    def spy_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            cmd,
            returncode=1,
            stdout="",
            stderr="Error: Authentication failed: sign-in required. Please run 'agy auth login'.",
        )

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner)
    res = adapter.dispatch(prompt="Check auth", model_id="gemini-4-hydrogen-high", cwd=tmp_path)

    assert res.ok is False
    assert res.status == "CLI_AUTHENTICATION_FAILED"
    assert res.error_code == "AUTHENTICATION_FAILED"
    assert "authentication failed" in (res.error_message or "").lower()


def test_32_real_structured_authentication_error_event_is_detected(tmp_path: Path) -> None:
    """Requirement 6: A real structured authentication error event is detected if supported by the actual protocol."""
    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    stdout_stream = (
        '{"event":"init","conversation_id":"cid-auth-06","init":{"model":"gemini-4-hydrogen-high"}}\n'
        '{"event":"error","error":{"code":"AUTHENTICATION_FAILED","message":"User sign-in required"}}\n'
        '{"event":"result","result":{"status":"FAILED","error_code":"AUTHENTICATION_FAILED"}}\n'
    )

    def spy_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, returncode=1, stdout=stdout_stream, stderr="")

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner)
    res = adapter.dispatch(prompt="Run auth test", model_id="gemini-4-hydrogen-high", cwd=tmp_path)

    assert res.ok is False
    assert res.status == "CLI_AUTHENTICATION_FAILED"
    assert res.error_code == "AUTHENTICATION_FAILED"


def test_33_unrelated_cli_error_is_not_mislabeled_as_authentication_failure(tmp_path: Path) -> None:
    """Requirement 7: An unrelated CLI error is not mislabeled as an authentication failure."""
    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    def spy_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            cmd,
            returncode=1,
            stdout="",
            stderr="Error: Could not bind port 8080 or parse configuration schema.",
        )

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner)
    res = adapter.dispatch(prompt="Run broken config", model_id="gemini-4-hydrogen-high", cwd=tmp_path)

    assert res.ok is False
    assert res.status == "CLI_EXECUTION_FAILED"
    assert res.status != "CLI_AUTHENTICATION_FAILED"
    assert res.error_code == "NONZERO_EXIT"


def test_34_process_timeouts_produce_correct_timeout_status(tmp_path: Path) -> None:
    """Requirement 8: Process timeouts still produce the correct timeout status."""
    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    def spy_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=300)

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner)
    res = adapter.dispatch(prompt="Long running query", model_id="gemini-4-hydrogen-high", cwd=tmp_path)

    assert res.ok is False
    assert res.status == "CLI_TIMEOUT"
    assert res.error_code == "TIMEOUT"
    assert "Process timed out" in (res.error_message or "")


def test_35_process_exit_codes_and_ordinary_error_handling_remain_correct(tmp_path: Path) -> None:
    """Requirement 9: Process exit codes and ordinary error handling remain correct."""
    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    # Non-zero exit code
    def spy_runner_fail(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, returncode=42, stdout="", stderr="Custom failure reason")

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner_fail)
    res = adapter.dispatch(prompt="Exit 42", model_id="gemini-4-hydrogen-high", cwd=tmp_path)

    assert res.ok is False
    assert res.returncode == 42
    assert res.status == "CLI_EXECUTION_FAILED"
    assert res.error_code == "NONZERO_EXIT"
    assert "42" in (res.error_message or "")

    # Zero exit code but missing result event (incomplete stream)
    def spy_runner_incomplete(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            cmd,
            returncode=0,
            stdout='{"event":"init","conversation_id":"cid-inc","init":{"model":"gemini-4-hydrogen-high"}}\n',
            stderr="",
        )

    adapter2 = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner_incomplete)
    res2 = adapter2.dispatch(prompt="Incomplete stream", model_id="gemini-4-hydrogen-high", cwd=tmp_path)

    assert res2.ok is False
    assert res2.status == "CLI_EXECUTION_FAILED"
    assert res2.error_code == "INCOMPLETE_STREAM"



def test_36_model_attestation_remains_mandatory_and_unchanged(tmp_path: Path) -> None:
    """Requirement 10: Model attestation remains mandatory and unchanged."""
    from model_attestation import AttestationStatus, attest_conversation_model

    fake_exe = tmp_path / "fake_agy.exe"
    fake_exe.write_text("", encoding="utf-8")

    cid = "11111111-2222-3333-4444-555555555555"
    stdout_stream = (
        f'{{"event":"init","conversation_id":"{cid}","init":{{"model":"gemini-4-hydrogen-high"}}}}\n'
        '{"event":"result","result":{"status":"SUCCESS","response":"Audit complete"}}\n'
    )

    def spy_runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=stdout_stream, stderr="")

    adapter = AntigravityCliAdapter(executable_override=str(fake_exe), runner=spy_runner)

    # 1. When conversation DB is not present, attestation status is DATABASE_UNAVAILABLE and cannot be bypassed
    res = adapter.start_new_conversation(
        prompt="Audit repo",
        model_id="gemini-4-hydrogen-high",
        cwd=tmp_path,
        conversations_dir=tmp_path,
    )
    assert res.attestation_status == AttestationStatus.MODEL_ATTESTATION_DATABASE_UNAVAILABLE
    assert res.conversation_id == cid

    # 2. Attestation direct check confirms not attested
    attest_direct = attest_conversation_model(
        conversation_id=cid,
        expected_model="gemini-4-hydrogen-high",
        conversations_dir=tmp_path,
    )
    assert attest_direct.status == AttestationStatus.MODEL_ATTESTATION_DATABASE_UNAVAILABLE
    assert not attest_direct.is_attested

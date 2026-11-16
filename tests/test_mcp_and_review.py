from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from db import connect, initialize
from mcp_server import (
    AuditorMCPDispatcher,
    MCPStdioServer,
    register_mcp_server_config,
)
from review import assert_not_markdown_checkbox, generate_review_report


def _setup_mcp_env(tmp_path: Path) -> tuple[Path, AuditorMCPDispatcher, MCPStdioServer]:
    db_path = tmp_path / "database" / "auditor.db"
    repo_path = tmp_path / "repo"
    (repo_path / "src").mkdir(parents=True, exist_ok=True)
    ledger_lines = [f"# line {i}" for i in range(1, 42)] + [
        "async def transfer_funds(account_id, amount):",
        "    # Unlocked read-modify-write across await boundary",
    ] + [f"    # body line {i}" for i in range(44, 58)] + ["    return account_id"]
    (repo_path / "src" / "ledger.py").write_text("\n".join(ledger_lines) + "\n", encoding="utf-8")

    client_lines = [f"# line {i}" for i in range(1, 10)] + [
        "def fetch(url):",
        "    # Timeout is 30s",
        "    return url",
    ]
    (repo_path / "src" / "client.py").write_text("\n".join(client_lines) + "\n", encoding="utf-8")

    initialize(db_path)
    with connect(db_path) as conn:
        conn.execute(
            """INSERT INTO projects(project_key, display_name, repo_path, antigravity_project_id)
               VALUES('alpha', 'Alpha Repo', ?, 'proj-alpha-1')""",
            (str(repo_path),),
        )
        conn.execute(
            """INSERT INTO audit_runs(run_id, project_key, status, base_commit, working_tree_hash)
               VALUES('RUN-MCP-1', 'alpha', 'DISPATCHED', '1111aaaa', '2222bbbb')"""
        )
        conn.commit()
    dispatcher = AuditorMCPDispatcher(db_path=db_path, app_home=tmp_path)
    server = MCPStdioServer(dispatcher)
    return db_path, dispatcher, server


def test_mcp_strict_schema_rejects_extra_fields_and_arbitrary_sql(tmp_path: Path) -> None:
    _, dispatcher, _ = _setup_mcp_env(tmp_path)

    # Extra property must be rejected
    with pytest.raises(ValueError, match="unexpected additional properties"):
        dispatcher.call_tool(
            "auditor_get_context",
            {"project_key": "alpha", "unknown_field": "nope"},
        )

    # Arbitrary SQL field must be rejected
    with pytest.raises(ValueError, match="arbitrary SQL fields are strictly forbidden"):
        dispatcher.call_tool(
            "auditor_get_context",
            {"project_key": "alpha", "sql": "DROP TABLE projects;"},
        )

    # Unsafe identifier with SQL injection syntax must be rejected
    with pytest.raises(ValueError, match="unsafe identifier format"):
        dispatcher.call_tool(
            "auditor_get_context",
            {"project_key": "alpha'; DROP TABLE projects;--"},
        )


def test_mcp_jsonrpc_end_to_end_and_review_report(tmp_path: Path) -> None:
    db_path, _, server = _setup_mcp_env(tmp_path)

    init_resp = server.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init_resp is not None
    assert init_resp["result"]["serverInfo"]["name"] == "antigravity-auditor"

    tools_resp = server.handle_jsonrpc_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert tools_resp is not None
    tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
    assert {
        "auditor_get_context",
        "auditor_publish_report",
        "auditor_get_verification_context",
        "auditor_submit_verification",
        "auditor_get_verification_status",
        "auditor_finalize_verified_report",
        "auditor_list_findings",
        "auditor_save_decisions",
        "auditor_authorize_execution",
        "auditor_start_execution",
        "auditor_update_finding_execution",
        "auditor_finalize_execution",
        "auditor_get_status",
    }.issubset(tool_names)

    # Publish primary candidate report via MCP tool call -> returns VERIFICATION_PENDING
    pub_resp = server.handle_jsonrpc_message({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "auditor_publish_report",
            "arguments": {
                "project_key": "alpha",
                "run_id": "RUN-MCP-1",
                "findings": [
                    {
                        "finding_id": "F-MCP-1",
                        "fingerprint": "fp-mcp-critical-race",
                        "title": "Async race condition in balance transfer",
                        "category": "V1",
                        "severity": "CRITICAL",
                        "confidence": "CONFIRMED",
                        "file_path": "src/ledger.py",
                        "symbol": "transfer_funds",
                        "line_start": 42,
                        "line_end": 58,
                        "evidence": "Unlocked read-modify-write across await boundary",
                        "impact": "Double-spend under concurrent requests",
                        "recommendation": "Use atomic row-level update with WHERE balance >= amount",
                    },
                    {
                        "finding_id": "F-MCP-2",
                        "fingerprint": "fp-mcp-low-speculative",
                        "title": "Potential timeout tune",
                        "category": "V5",
                        "severity": "LOW",
                        "confidence": "SPECULATIVE",
                        "file_path": "src/client.py",
                        "symbol": "fetch",
                        "line_start": 10,
                        "line_end": 12,
                        "evidence": "Timeout is 30s",
                        "impact": "Slow fallback",
                        "recommendation": "Consider 10s timeout",
                    },
                ],
            },
        },
    })
    assert pub_resp is not None
    assert pub_resp["result"]["isError"] is False
    pub_data = pub_resp["result"]["structuredContent"]
    assert pub_data["status"] == "VERIFICATION_PENDING"
    vrun_id = pub_data["verification_run_id"]
    report_path = Path(pub_data["review_report_path"])
    assert report_path.is_file()

    # Submit second-pass verification verdicts and finalize canonical report via MCP
    sub_resp = server.handle_jsonrpc_message({
        "jsonrpc": "2.0",
        "id": 31,
        "method": "tools/call",
        "params": {
            "name": "auditor_submit_verification",
            "arguments": {
                "audit_run_id": "RUN-MCP-1",
                "verification_run_id": vrun_id,
                "verifier_metadata": {"invocation_mechanism": "mcp_direct", "actual_subagent_invocations": 0},
                "verifier_conversation_id": "conv-verifier-mcp-001",
                "verification_results": [
                    {
                        "candidate_finding_id": "F-MCP-1",
                        "verdict": "CONFIRMED",
                        "verified_severity": "CRITICAL",
                        "verified_confidence": "CONFIRMED",
                        "technical_rationale": "Verified unlocked read-modify-write across await boundary.",
                        "source_evidence": {
                            "file_path": "src/ledger.py",
                            "line_start": 42,
                            "line_end": 58,
                            "symbol": "transfer_funds",
                            "evidence_excerpt": "Unlocked read-modify-write across await boundary",
                        },
                        "remediation_review": "Atomic WHERE balance >= amount update is safe.",
                        "remediation_safe": True,
                        "acceptance_criteria": "Concurrent balance transfer test passes.",
                    },
                    {
                        "candidate_finding_id": "F-MCP-2",
                        "verdict": "CONFIRMED",
                        "verified_severity": "LOW",
                        "verified_confidence": "SPECULATIVE",
                        "technical_rationale": "Confirmed 30s timeout setting in fetch.",
                        "source_evidence": {
                            "file_path": "src/client.py",
                            "line_start": 10,
                            "line_end": 12,
                            "symbol": "fetch",
                            "evidence_excerpt": "Timeout is 30s",
                        },
                        "remediation_review": "Timeout adjustment is safe.",
                        "remediation_safe": True,
                        "acceptance_criteria": "Client timeout test passes.",
                    },
                ],
            },
        },
    })
    assert sub_resp is not None
    assert sub_resp["result"]["isError"] is False

    fin_resp = server.handle_jsonrpc_message({
        "jsonrpc": "2.0",
        "id": 32,
        "method": "tools/call",
        "params": {
            "name": "auditor_finalize_verified_report",
            "arguments": {
                "audit_run_id": "RUN-MCP-1",
                "verification_run_id": vrun_id,
            },
        },
    })
    assert fin_resp is not None
    assert fin_resp["result"]["isError"] is False
    assert fin_resp["result"]["structuredContent"]["status"] == "READY_FOR_REVIEW"

    report_text = generate_review_report(db_path, project_key="alpha", run_id="RUN-MCP-1")
    assert "Severity vs. Confidence Matrix" in report_text
    assert "`src/ledger.py:L42-L58` (`transfer_funds`)" in report_text or "src/ledger.py:L42-L58 (`transfer_funds`)" in report_text
    assert "No Checkbox Authorization" in report_text

    # Save decisions via MCP
    save_resp = server.handle_jsonrpc_message({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "auditor_save_decisions",
            "arguments": {
                "project_key": "alpha",
                "run_id": "RUN-MCP-1",
                "decisions": [
                    {"finding_id": "F-MCP-1", "decision": "APPLY", "note": "Approve race fix"},
                    {"finding_id": "F-MCP-2", "decision": "DISMISS", "note": "Acceptable timeout"},
                ],
            },
        },
    })
    assert save_resp is not None
    assert save_resp["result"]["isError"] is False
    assert save_resp["result"]["structuredContent"]["execution_authorized"] is False

    # Authorization is human-only: the MCP tool refuses (use `cli.py authorize-execution` in a terminal)
    auth_resp = server.handle_jsonrpc_message({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "auditor_authorize_execution",
            "arguments": {
                "project_key": "alpha",
                "run_id": "RUN-MCP-1",
                "confirmation": "AUTHORIZE_ISOLATED_WORKTREE_EXECUTION",
            },
        },
    })
    assert auth_resp is not None
    assert auth_resp["result"]["isError"] is True
    assert "human-only" in json.dumps(auth_resp["result"])


def test_register_mcp_server_preserves_existing_and_handles_empty_file(tmp_path: Path) -> None:
    mcp_cfg = tmp_path / "mcp_config.json"
    # 0-byte empty file case (matching real ~/.gemini/config/mcp_config.json initial state)
    mcp_cfg.write_text("", encoding="utf-8")

    res1 = register_mcp_server_config(mcp_cfg, app_home=tmp_path, python_exe="python")
    assert res1["server_name"] == "antigravity-auditor"

    # Add another MCP server and re-run registration -> must preserve existing server
    loaded = json.loads(mcp_cfg.read_text(encoding="utf-8"))
    loaded["mcpServers"]["existing-custom-server"] = {"url": "https://example.com/mcp"}
    mcp_cfg.write_text(json.dumps(loaded), encoding="utf-8")

    res2 = register_mcp_server_config(mcp_cfg, app_home=tmp_path, python_exe="python")
    assert "existing-custom-server" in res2["preserved_servers"]
    final_data = json.loads(mcp_cfg.read_text(encoding="utf-8"))
    assert "existing-custom-server" in final_data["mcpServers"]
    assert "antigravity-auditor" in final_data["mcpServers"]

    with pytest.raises(RuntimeError, match="Markdown checkboxes"):
        assert_not_markdown_checkbox("- [x] Approve F-MCP-1")

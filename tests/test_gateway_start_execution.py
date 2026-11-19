"""auditor_start_execution through the MCP gateway, the way Antigravity calls it.

Regression: the gateway's presence check accepted only `approval_token`, but the terminal approval
(`cli.py authorize-execution`) hands out only an `approval_id` and the policy path sends
`auto_approve=true` + `run_id`; both were refused with MISSING_APPROVAL_TOKEN before reaching the handler.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import authorize_execution, connect  # noqa: E402
from entitlement_router.registry import EntitlementRegistry  # noqa: E402
from mcp_gateway import (  # noqa: E402
    AdaptiveMCPGateway,
    AuthorizationResolver,
    CallerIdentityResolver,
    SharedSecretAdapterProofVerifier,
)
from mcp_gateway.routing_tools import RoutingToolBridge  # noqa: E402
from test_apply_policy_and_quota import _set_policy, ready  # noqa: E402,F401
from test_mcp_gateway import _make_verified_caller  # noqa: E402

APPLY_SCOPES = frozenset({"core:read", "project:read", "governance:decide", "execution:run"})


def _gateway(ready: dict[str, Any], *, allow_execution_tools: bool = True):
    verifier = SharedSecretAdapterProofVerifier()
    verifier.register_adapter_key("adp-agy-1", b"super-secret-adapter-key-agy")
    caller = _make_verified_caller(CallerIdentityResolver(adapter_verifier=verifier), verifier, scopes=APPLY_SCOPES)
    gw = AdaptiveMCPGateway(
        dispatcher=ready["d"],
        routing_bridge=RoutingToolBridge(registry=EntitlementRegistry()),
        authorization_resolver=AuthorizationResolver(allow_execution_tools=allow_execution_tools),
    )
    return gw, caller


def _payload(res: dict[str, Any]) -> dict[str, Any]:
    if res.get("structuredContent"):
        return res["structuredContent"]
    return json.loads(res["content"][0]["text"])


def test_terminal_approval_id_starts_execution_through_gateway(ready: dict[str, Any]) -> None:
    gw, caller = _gateway(ready)
    auth = authorize_execution(ready["db"], project_key="svc1", run_id="R-AP",
                               confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION")
    res = gw.call_tool(tool_name="auditor_start_execution",
                       arguments={"project_key": "svc1", "approval_id": auth["approval_id"]}, caller=caller)
    assert res["isError"] is False, res
    out = _payload(res)
    assert out["approval"] == {"mode": "human_terminal"}
    assert Path(out["worktree_path"]).is_dir()
    assert out["approved_finding_ids"] == ["F-AP-1"]


def test_auto_approve_with_run_id_starts_execution_through_gateway(ready: dict[str, Any]) -> None:
    _set_policy(ready["db"])
    gw, caller = _gateway(ready)
    res = gw.call_tool(tool_name="auditor_start_execution",
                       arguments={"project_key": "svc1", "run_id": "R-AP", "auto_approve": True}, caller=caller)
    assert res["isError"] is False, res
    assert _payload(res)["approval"]["mode"] == "auto_policy"


def test_full_terminal_approved_fix_runs_end_to_end_through_gateway(ready: dict[str, Any]) -> None:
    """start -> begin -> verify -> finalize, every call through the gateway, ending in a local review branch."""
    gw, caller = _gateway(ready)
    auth = authorize_execution(ready["db"], project_key="svc1", run_id="R-AP",
                               confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION")

    def call(tool: str, args: dict[str, Any]) -> dict[str, Any]:
        res = gw.call_tool(tool_name=tool, arguments=args, caller=caller)
        assert res["isError"] is False, (tool, res)
        return _payload(res)

    started = call("auditor_start_execution", {"project_key": "svc1", "approval_id": auth["approval_id"]})
    exec_id, wt = started["exec_id"], Path(started["worktree_path"])
    call("auditor_update_finding_execution",
         {"project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "begin"})
    (wt / "mod.py").write_text("def val() -> int:\n    return 1\n", encoding="utf-8")
    call("auditor_update_finding_execution", {
        "project_key": "svc1", "exec_id": exec_id, "finding_id": "F-AP-1", "action": "verify",
        "happy_test_passed": True, "adversarial_test_passed": True, "red_team_passed": True})
    fin = call("auditor_finalize_execution", {"project_key": "svc1", "exec_id": exec_id, "integration_test_passed": True})
    review = fin["review"]
    assert review["approval"] == "human_terminal"
    assert review["branch"].startswith("audit-fix/") and review["merged"] is False and review["pushed"] is False
    assert "mod.py" in review["files_changed"]
    assert "-> int" not in (ready["repo"] / "mod.py").read_text(encoding="utf-8")  # user's working tree untouched


def test_auto_approve_refusal_reasons_reach_the_caller(ready: dict[str, Any]) -> None:
    gw, caller = _gateway(ready)  # no policy -> disabled
    res = gw.call_tool(tool_name="auditor_start_execution",
                       arguments={"project_key": "svc1", "run_id": "R-AP", "auto_approve": True}, caller=caller)
    assert res["isError"] is True
    text = json.dumps(res)
    assert "MISSING_APPROVAL" not in text
    assert "disabled" in text


@pytest.mark.parametrize("args, expected", [
    ({"project_key": "svc1"}, "chat_approved=true"),  # simple mode: tells the agent to ask in the chat
    ({"project_key": "svc1", "run_id": "R-AP", "auto_approve": False}, "chat_approved=true"),
    ({"project_key": "svc1", "auto_approve": True}, "disabled"),  # latest run, but no policy
])
def test_start_execution_without_an_approval_is_refused_with_the_way_forward(
    ready: dict[str, Any], args: dict, expected: str
) -> None:
    gw, caller = _gateway(ready)
    res = gw.call_tool(tool_name="auditor_start_execution", arguments=args, caller=caller)
    assert res["isError"] is True
    text = json.dumps(res)
    assert "GOVERNANCE_APPROVAL_REQUIRED" in text and expected in text
    with connect(ready["db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM execution_runs").fetchone()[0] == 0


def test_unknown_approval_id_passes_gateway_but_is_refused_by_handler(ready: dict[str, Any]) -> None:
    gw, caller = _gateway(ready)
    res = gw.call_tool(tool_name="auditor_start_execution",
                       arguments={"project_key": "svc1", "approval_id": "APPR-doesnotexist"}, caller=caller)
    assert res["isError"] is True
    text = json.dumps(res)
    assert "GOVERNANCE_APPROVAL_REQUIRED" not in text
    assert "not found" in text


def test_execution_tools_stay_withheld_when_apply_is_disabled(ready: dict[str, Any]) -> None:
    gw, caller = _gateway(ready, allow_execution_tools=False)
    auth = authorize_execution(ready["db"], project_key="svc1", run_id="R-AP",
                               confirmation="AUTHORIZE_ISOLATED_WORKTREE_EXECUTION")
    res = gw.call_tool(tool_name="auditor_start_execution",
                       arguments={"project_key": "svc1", "approval_id": auth["approval_id"]}, caller=caller)
    assert res["isError"] is True

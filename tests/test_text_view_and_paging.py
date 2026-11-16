"""Text-view condensation (ARCH-09 follow-up) and auditor_list_findings paging.

Before: any MCP result whose pretty JSON exceeded the tool's text limit collapsed to
``{"tool": ..., "truncated": true}`` in ``content``, so content-only clients such as
Antigravity saw no data for auditor_get_status / auditor_get_context /
auditor_list_findings on a real project.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

import mcp_server  # noqa: E402
from db import initialize  # noqa: E402
from mcp_gateway.output_adapter import _render_concise_text  # noqa: E402
from mcp_gateway.tool_manifest import build_default_canonical_manifests  # noqa: E402
from mcp_server import AuditorMCPDispatcher, validate_strict_schema  # noqa: E402

TOOLS = {t.tool_name: t for t in build_default_canonical_manifests()}
HASH = "a" * 64


def _finding(i: int) -> dict[str, Any]:
    return {
        "finding_id": f"F{i:03d}",
        "title": f"Finding number {i}",
        "severity": "HIGH",
        "file_path": f"src/module_{i}.py",
        "line_start": 10,
        "line_end": 20,
        "lifecycle": "OPEN",
        "technical_rationale": "x" * 900,
        "evidence_hash": HASH,
        "empty_field": None,
    }


def test_small_payload_is_unchanged_pretty_json() -> None:
    tool = TOOLS["auditor_list_findings"]
    data = {"project_key": "p", "count": 1, "findings": [{"finding_id": "F1", "title": "t"}]}
    text = _render_concise_text(tool, data, truncated=False)
    assert json.loads(text) == data
    assert "\n" in text  # pretty-printed, as before


def test_oversize_payload_is_condensed_not_collapsed() -> None:
    tool = TOOLS["auditor_list_findings"]
    limit = tool.result_size_policy.max_text_chars
    data = {"project_key": "p", "count": 50, "next_offset": 50, "execution_authorized": False,
            "findings": [_finding(i) for i in range(50)]}

    text = _render_concise_text(tool, data, truncated=False)
    view = json.loads(text)

    assert len(text) <= limit
    assert view["truncated"] is True and view["text_view"]["complete"] is False
    # Identity fields of the leading findings are visible, in order.
    shown = view["findings"]
    assert len(shown) >= 2
    assert [f["finding_id"] for f in shown] == [f"F{i:03d}" for i in range(len(shown))]
    assert shown[0]["file_path"] == "src/module_0.py" and shown[0]["severity"] == "HIGH"
    # Exactly what was omitted is reported.
    assert len(shown) + view["text_view"]["omitted_items"]["findings"] == 50
    assert {"technical_rationale", "evidence_hash"} <= set(view["text_view"]["omitted_fields"])
    # Preserved keys are never altered.
    assert view["next_offset"] == 50 and view["execution_authorized"] is False


def test_moderate_overflow_only_caps_strings_and_keeps_all_items() -> None:
    tool = TOOLS["auditor_get_status"]
    data = {"projects": [{"project_key": "p", "health_status": "HEALTHY"}],
            "recent_events": [{"event_id": i, "event_type": "E", "details": "z" * 600} for i in range(10)]}
    view = json.loads(_render_concise_text(tool, data, truncated=False))
    assert len(view["recent_events"]) == 10
    assert "omitted_items" not in view["text_view"]
    assert view["text_view"]["strings_capped_at"] in (512, 256, 160, 96)


def test_structured_truncation_is_flagged_in_text_view() -> None:
    tool = TOOLS["auditor_get_status"]
    view = json.loads(_render_concise_text(tool, {"projects": []}, truncated=True))
    assert view["text_view"]["structured_content_truncated"] is True


def test_unfittable_payload_falls_back_to_summary() -> None:
    tool = TOOLS["auditor_get_status"]
    data = {f"k{i}": i for i in range(2000)}
    data["status"] = "OK"
    view = json.loads(_render_concise_text(tool, data, truncated=False))
    assert view == {"tool": "auditor_get_status", "truncated": True, "status": "OK"}


@pytest.fixture()
def paged_dispatcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AuditorMCPDispatcher:
    home = tmp_path / "home"
    db_path = home / "database" / "auditor.db"
    initialize(db_path)
    rows = [{"finding_id": f"F{i}"} for i in range(7)]

    def fake_list(_db: Any, **kw: Any) -> list[dict[str, Any]]:
        # Mimic the direct-SQLite path, which ignores limit/offset.
        assert kw["offset"] == 0
        return list(rows)

    monkeypatch.setattr(mcp_server, "list_project_findings", fake_list)
    return AuditorMCPDispatcher(db_path=db_path, app_home=home)


def _ids(result: dict[str, Any]) -> list[str]:
    return [f["finding_id"] for f in result["findings"]]


def test_list_findings_paging(paged_dispatcher: AuditorMCPDispatcher) -> None:
    out_schema = next(t for t in mcp_server.TOOL_DEFINITIONS if t["name"] == "auditor_list_findings")["outputSchema"]

    first = paged_dispatcher.call_tool("auditor_list_findings", {"project_key": "p", "limit": 3})
    assert _ids(first) == ["F0", "F1", "F2"] and first["count"] == 3 and first["next_offset"] == 3
    middle = paged_dispatcher.call_tool("auditor_list_findings", {"project_key": "p", "limit": 3, "offset": 3})
    assert _ids(middle) == ["F3", "F4", "F5"] and middle["next_offset"] == 6
    last = paged_dispatcher.call_tool("auditor_list_findings", {"project_key": "p", "limit": 3, "offset": 6})
    assert _ids(last) == ["F6"] and last["next_offset"] is None
    default = paged_dispatcher.call_tool("auditor_list_findings", {"project_key": "p"})
    assert default["count"] == 7 and default["offset"] == 0 and default["next_offset"] is None
    exact = paged_dispatcher.call_tool("auditor_list_findings", {"project_key": "p", "limit": 7})
    assert exact["next_offset"] is None
    for result in (first, middle, last, default):
        validate_strict_schema(result, out_schema, "output")


def test_list_findings_paging_with_offset_honouring_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The broker path applies limit/offset itself; paging must not double-apply the offset."""
    home = tmp_path / "home"
    db_path = home / "database" / "auditor.db"
    initialize(db_path)
    rows = [{"finding_id": f"F{i}"} for i in range(7)]
    monkeypatch.setattr(
        mcp_server, "list_project_findings",
        lambda _db, **kw: rows[kw["offset"] : kw["offset"] + kw["limit"]],
    )
    d = AuditorMCPDispatcher(db_path=db_path, app_home=home)
    page = d.call_tool("auditor_list_findings", {"project_key": "p", "limit": 2, "offset": 4})
    assert _ids(page) == ["F4", "F5"] and page["next_offset"] == 6


@pytest.mark.parametrize("bad", [{"limit": 0}, {"limit": 51}, {"offset": -1}])
def test_list_findings_rejects_bad_paging_args(paged_dispatcher: AuditorMCPDispatcher, bad: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        paged_dispatcher.call_tool("auditor_list_findings", {"project_key": "p", **bad})

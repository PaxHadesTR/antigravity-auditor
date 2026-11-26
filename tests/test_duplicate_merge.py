"""The primary audit's passes can report one defect as two candidates (other id, category or symbol). The verifier
sees the overlapping pairs and marks a duplicate with ``duplicate_of``; finalization folds it into the target's
finding. Unusable pointers and duplicates that carry a user decision are ignored: nothing is lost."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import compute_finding_fingerprint, connect  # noqa: E402
from review import list_project_findings  # noqa: E402
from structured_delivery import VERIFICATION_RESULT_SCHEMA, parse_structured_result  # noqa: E402
from test_auto_delivery import _insert  # noqa: E402
from test_verification_stuck_states import F1, F2, RUN, _one, _seed, _verdict, _worker  # noqa: E402
from verification import overlapping_candidate_pairs  # noqa: E402

# Another pass reported the same defect under another category and symbol.
F2_DUP = {**F2, "category": "LOGIC", "symbol": "charge"}


def _rows(db_path: Path, sql: str, *args: Any) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def _run(db_path: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    worker = _worker(db_path, {"verification_results": results})
    res = worker.process_one_job()
    assert res["finalize"]["status"] == "READY_FOR_REVIEW", res
    return {"result": res, "prompt": worker.adapter.start_new_conversation.call_args.args[0]}


def test_overlapping_pairs_are_listed_for_the_verifier(tmp_path: Path) -> None:
    claims = [
        {"candidate_finding_id": "A", "affected_file": "src/a.py", "line_start": 10, "line_end": 20},
        {"candidate_finding_id": "B", "affected_file": "./src/a.py", "line_start": 20, "line_end": 30},
        {"candidate_finding_id": "C", "affected_file": "src/a.py", "line_start": 31, "line_end": 40},
        {"candidate_finding_id": "D", "affected_file": "src/b.py", "line_start": 10, "line_end": 20},
    ]
    assert overlapping_candidate_pairs(claims) == [("A", "B")]

    db_path = _seed(tmp_path, [F1, F2_DUP])
    prompt = _run(db_path, [_verdict("F-ST-1"), _verdict("F-ST-2")])["prompt"]
    assert "DUPLICATE CANDIDATES" in prompt and "F-ST-1 <-> F-ST-2" in prompt
    assert "duplicate_of (string or null" in prompt  # the structured contract names the field


def test_duplicate_is_merged_into_its_target(tmp_path: Path) -> None:
    db_path = _seed(tmp_path, [F1, F2_DUP])
    out = _run(db_path, [_verdict("F-ST-1", verified_severity="MEDIUM"),
                         _verdict("F-ST-2", verified_severity="HIGH", duplicate_of="F-ST-1")])["result"]
    rows = _rows(db_path, "SELECT finding_id, severity, technical_rationale FROM findings")
    assert len(rows) == 1, rows
    fid, severity, rationale = rows[0]
    assert severity == "HIGH"  # the higher verified severity is kept
    assert "[Merged duplicate F-ST-2: Zero amount is accepted]" in rationale
    assert _one(db_path, "SELECT canonical_finding_id, status FROM candidate_findings WHERE candidate_finding_id="
                         "'F-ST-2'") == (fid, "CONFIRMED")
    assert _one(db_path, "SELECT reason FROM finding_history WHERE finding_id=? ORDER BY history_id DESC LIMIT 1",
                fid)[0] == "DUPLICATE_MERGED:F-ST-2"
    assert out["finalize"]["stats"]["merged_duplicates"] == 1
    listed = list_project_findings(db_path, project_key="p2", run_id=RUN)
    assert [f["finding_id"] for f in listed] == [fid]  # the report shows one finding, not the candidate too
    event = json.loads(_one(db_path, "SELECT details FROM audit_events WHERE event_type='DUPLICATE_FINDINGS_MERGED'")[0])
    assert event["merged"] == [{"candidate_finding_id": "F-ST-2", "merged_into": fid, "target": "F-ST-1"}]


@pytest.mark.parametrize("results, reason", [
    ([_verdict("F-ST-1", "REJECTED"), _verdict("F-ST-2", duplicate_of="F-ST-1")], "not a confirmed candidate"),
    ([_verdict("F-ST-1", duplicate_of="F-ST-2"), _verdict("F-ST-2", duplicate_of="F-ST-1")], "itself marked"),
    ([_verdict("F-ST-1"), _verdict("F-ST-2", duplicate_of="F-NOPE")], "not a confirmed candidate"),
])
def test_unusable_pointers_are_ignored(tmp_path: Path, results: list[dict[str, Any]], reason: str) -> None:
    db_path = _seed(tmp_path, [F1, F2_DUP])
    _run(db_path, results)
    confirmed = [r["candidate_finding_id"] for r in results if r["verdict"] != "REJECTED"]
    assert _one(db_path, "SELECT COUNT(*) FROM findings WHERE lifecycle='OPEN'")[0] == len(confirmed)
    event = json.loads(_one(db_path, "SELECT details FROM audit_events WHERE event_type='DUPLICATE_FINDINGS_MERGED'")[0])
    assert event["merged"] == [] and all(reason in i["reason"] for i in event["ignored"]), event


def test_empty_pointer_is_no_merge_and_passes_the_schema(tmp_path: Path) -> None:
    payload = {"verification_results": [_verdict("F-ST-1", duplicate_of=None), _verdict("F-ST-2", duplicate_of="")]}
    parse_structured_result(json.dumps(payload), VERIFICATION_RESULT_SCHEMA)
    db_path = _seed(tmp_path, [F1, F2_DUP])
    _run(db_path, payload["verification_results"])
    assert _one(db_path, "SELECT COUNT(*) FROM findings")[0] == 2
    assert _one(db_path, "SELECT COUNT(*) FROM audit_events WHERE event_type='DUPLICATE_FINDINGS_MERGED'")[0] == 0


def _earlier_finding(db_path: Path, item: dict[str, Any], lifecycle: str) -> str:
    fid = "F-EARLIER"
    with connect(db_path) as conn:
        _insert(conn, "audit_runs", {"run_id": "RUN-OLD", "project_key": "p2", "status": "COMPLETED"})
        _insert(conn, "findings", {
            "finding_id": fid, "project_key": "p2", "run_id": "RUN-OLD",
            "fingerprint": compute_finding_fingerprint("p2", item), "title": item["title"],
            "category": item["category"], "severity": "MEDIUM", "confidence": "LIKELY", "lifecycle": lifecycle,
            "first_seen_run_id": "RUN-OLD", "last_seen_run_id": "RUN-OLD", "execution_eligible": 1,
        })
        conn.commit()
    return fid


def test_open_earlier_finding_of_the_duplicate_is_archived(tmp_path: Path) -> None:
    db_path = _seed(tmp_path, [F1, F2_DUP])
    earlier = _earlier_finding(db_path, F2_DUP, "OPEN")
    _run(db_path, [_verdict("F-ST-1"), _verdict("F-ST-2", duplicate_of="F-ST-1")])
    assert _one(db_path, "SELECT lifecycle, execution_eligible FROM findings WHERE finding_id=?", earlier) == (
        "ARCHIVED", 0)
    reason = _one(db_path, "SELECT reason FROM finding_history WHERE finding_id=? ORDER BY history_id DESC LIMIT 1",
                  earlier)[0]
    assert reason.startswith("MERGED_AS_DUPLICATE_OF:")
    assert _one(db_path, "SELECT COUNT(*) FROM findings WHERE lifecycle='OPEN'")[0] == 1
    assert earlier not in [f["finding_id"] for f in list_project_findings(db_path, project_key="p2", run_id=RUN)]


def test_user_decision_on_the_duplicate_blocks_the_merge(tmp_path: Path) -> None:
    db_path = _seed(tmp_path, [F1, F2_DUP])
    earlier = _earlier_finding(db_path, F2_DUP, "DEFERRED")
    _run(db_path, [_verdict("F-ST-1"), _verdict("F-ST-2", duplicate_of="F-ST-1")])
    assert _one(db_path, "SELECT lifecycle FROM findings WHERE finding_id=?", earlier)[0] == "DEFERRED"
    event = json.loads(_one(db_path, "SELECT details FROM audit_events WHERE event_type='DUPLICATE_FINDINGS_MERGED'")[0])
    assert event["merged"] == [] and "DEFERRED" in event["ignored"][0]["reason"]


@pytest.mark.parametrize("lifecycle", ["DEFERRED", "DISMISSED", "SKIPPED"])
def test_user_decision_on_the_target_blocks_the_merge(tmp_path: Path, lifecycle: str) -> None:
    # Otherwise the duplicate's open finding would be archived into a finding the user set aside.
    db_path = _seed(tmp_path, [F1, F2_DUP])
    _earlier_finding(db_path, F1, lifecycle)
    _run(db_path, [_verdict("F-ST-1"), _verdict("F-ST-2", duplicate_of="F-ST-1")])
    event = json.loads(_one(db_path, "SELECT details FROM audit_events WHERE event_type='DUPLICATE_FINDINGS_MERGED'")[0])
    assert event["merged"] == [] and "target" in event["ignored"][0]["reason"], event
    assert _one(db_path, "SELECT lifecycle FROM findings WHERE title=?", F2_DUP["title"])[0] == "OPEN"


def test_confirmed_duplicate_is_not_folded_into_a_partially_confirmed_target(tmp_path: Path) -> None:
    db_path = _seed(tmp_path, [F1, F2_DUP])
    _run(db_path, [_verdict("F-ST-1", "PARTIALLY_CONFIRMED", corrected_claim="Only negative amounts."),
                   _verdict("F-ST-2", duplicate_of="F-ST-1")])
    assert _one(db_path, "SELECT COUNT(*) FROM findings")[0] == 2
    assert _one(db_path, "SELECT execution_eligible FROM findings WHERE title=?", F2_DUP["title"])[0] == 1

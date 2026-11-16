from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from db import ALLOWED_CONFIDENCES, ALLOWED_SEVERITIES, connect

if TYPE_CHECKING:
    from broker.client import BrokerClient

MARKDOWN_CHECKBOX_PATTERN = re.compile(r"(^\s*[-*+]\s*\[[xX ]\]|\[[xX]\])", re.MULTILINE)


def assert_not_markdown_checkbox(value: str, context: str = "input") -> None:
    """Explicitly reject Markdown checkboxes as decision or execution authorization."""
    if MARKDOWN_CHECKBOX_PATTERN.search(value or ""):
        raise RuntimeError(
            f"Rejected {context}: Markdown checkboxes ('[x]' / '[ ]') are never valid decision or execution authorization. "
            "Use structured JSON decisions via 'save-decisions' / 'auditor_save_decisions' followed by explicit 'authorize-execution'."
        )


def list_project_findings_broker(
    broker_client: BrokerClient,
    *,
    project_key: str,
    run_id: str | None = None,
    lifecycle: str | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    verification_status: str | None = None,
    include_dismissed: bool = False,
    include_candidates: bool = True,
    limit: int = 500,
    offset: int = 0,
    order_by: str | None = None,
    order_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Query findings exclusively via Broker IPC. Zero direct SQLite calls, zero SQLite fallback."""
    return broker_client.list_findings(
        project_key=project_key,
        run_id=run_id,
        lifecycle=lifecycle,
        severity=severity,
        confidence=confidence,
        verification_status=verification_status,
        include_dismissed=include_dismissed,
        include_candidates=include_candidates,
        limit=limit,
        offset=offset,
        order_by=order_by,
        order_dir=order_dir,
    )


def list_project_findings(
    db_path: Path | None = None,
    *,
    project_key: str,
    run_id: str | None = None,
    lifecycle: str | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    verification_status: str | None = None,
    include_dismissed: bool = False,
    include_candidates: bool = True,
    limit: int = 500,
    offset: int = 0,
    broker_client: BrokerClient | None = None,
) -> list[dict[str, Any]]:
    """Query canonical findings and candidate findings, distinguishing verification status and execution eligibility.

    When `broker_client` is provided, routes exclusively through Broker IPC with zero direct SQLite access.
    """
    if broker_client is not None:
        return list_project_findings_broker(
            broker_client,
            project_key=project_key,
            run_id=run_id,
            lifecycle=lifecycle,
            severity=severity,
            confidence=confidence,
            verification_status=verification_status,
            include_dismissed=include_dismissed,
            include_candidates=include_candidates,
            limit=limit,
            offset=offset,
        )

    if db_path is None:
        raise ValueError("Either db_path or broker_client must be provided to list_project_findings.")

    with connect(db_path) as conn:
        sql = """
            SELECT
                f.finding_id, f.project_key, f.run_id, f.fingerprint, f.title, f.category,
                f.severity, f.confidence, f.file_path, f.symbol, f.line_start, f.line_end,
                f.evidence, f.impact, f.recommendation, f.evidence_hash, f.file_blob_hash,
                f.first_seen_run_id, f.last_seen_run_id, f.lifecycle,
                f.verification_status, f.execution_eligible, f.remediation_safe, f.verification_run_id,
                f.verified_at, f.verifier_conversation_id, f.evidence_validation_status,
                f.snapshot_id, f.base_commit_sha, f.acceptance_criteria,
                f.remediation_review, f.technical_rationale,
                f.created_at, f.updated_at,
                (
                    SELECT d.decision FROM decisions d
                    WHERE d.finding_id = f.finding_id AND d.superseded = 0
                    ORDER BY d.decision_id DESC LIMIT 1
                ) AS active_decision,
                (
                    SELECT d.note FROM decisions d
                    WHERE d.finding_id = f.finding_id AND d.superseded = 0
                    ORDER BY d.decision_id DESC LIMIT 1
                ) AS decision_note
            FROM findings f
            WHERE f.project_key = ?
        """
        params: list[Any] = [project_key]
        if run_id:
            sql += " AND (f.run_id = ? OR f.last_seen_run_id = ?)"
            params.extend([run_id, run_id])
        if lifecycle:
            sql += " AND f.lifecycle = ?"
            params.append(lifecycle.upper())
        elif not include_dismissed:
            sql += " AND f.lifecycle != 'DISMISSED'"
        if severity:
            sql += " AND f.severity = ?"
            params.append(severity.upper())
        if confidence:
            sql += " AND f.confidence = ?"
            params.append(confidence.upper())
        if verification_status:
            sql += " AND f.verification_status = ?"
            params.append(verification_status.upper())

        sql += """
            ORDER BY
                CASE f.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                CASE f.confidence
                    WHEN 'CONFIRMED' THEN 1
                    WHEN 'LIKELY' THEN 2
                    ELSE 3
                END,
                f.finding_id
        """
        canonical_rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        for r in canonical_rows:
            r["execution_eligible"] = bool(r.get("execution_eligible"))
            r["remediation_safe"] = bool(r.get("remediation_safe", 1))
            r["source_origin"] = "CANONICAL"

        # Include unpromoted candidate/rejected/unverifiable findings when requested
        candidate_items: list[dict[str, Any]] = []
        if include_candidates:
            cand_sql = """
                SELECT c.*,
                       r.verdict, r.verified_severity, r.verified_confidence,
                       r.technical_rationale, r.corrected_claim, r.remediation_review, r.remediation_safe,
                       r.acceptance_criteria, r.evidence_validation_status,
                       r.verification_run_id AS res_verification_run_id,
                       vr.verifier_conversation_id
                FROM candidate_findings c
                LEFT JOIN finding_verification_results r
                  ON r.result_id = (SELECT r2.result_id FROM finding_verification_results r2 WHERE r2.audit_run_id = c.run_id AND r2.candidate_finding_id = c.candidate_finding_id ORDER BY r2.result_id DESC LIMIT 1)
                LEFT JOIN audit_verification_runs vr
                  ON vr.verification_run_id = r.verification_run_id
                WHERE c.project_key = ? AND c.canonical_finding_id IS NULL
            """
            cand_params: list[Any] = [project_key]
            if run_id:
                cand_sql += " AND c.run_id = ?"
                cand_params.append(run_id)
            cand_rows = conn.execute(cand_sql, cand_params).fetchall()

            for cr in cand_rows:
                raw_st = str(cr["status"] or "CANDIDATE")
                if raw_st == "CONFIRMED":
                    mapped_v_status = "CANDIDATE"
                elif raw_st == "PARTIALLY_CONFIRMED":
                    mapped_v_status = "PARTIALLY_VERIFIED"
                elif raw_st in ("REJECTED", "UNVERIFIABLE", "STALE", "CANDIDATE"):
                    mapped_v_status = raw_st
                else:
                    mapped_v_status = "CANDIDATE"

                mapped_lc = "REJECTED" if mapped_v_status == "REJECTED" else ("STALE" if mapped_v_status == "STALE" else "OPEN")
                eff_sev = str(cr["verified_severity"] or cr["severity"])
                eff_conf = str(cr["verified_confidence"] or cr["confidence"])

                if lifecycle and mapped_lc != lifecycle.upper():
                    continue
                if severity and eff_sev != severity.upper():
                    continue
                if confidence and eff_conf != confidence.upper():
                    continue
                if verification_status and mapped_v_status != verification_status.upper():
                    continue

                candidate_items.append({
                    "finding_id": str(cr["candidate_finding_id"]),
                    "project_key": str(cr["project_key"]),
                    "run_id": str(cr["run_id"]),
                    "fingerprint": str(cr["fingerprint"]),
                    "title": str(cr["title"]),
                    "category": str(cr["category"]),
                    "severity": eff_sev,
                    "confidence": eff_conf,
                    "file_path": cr["file_path"],
                    "symbol": cr["symbol"],
                    "line_start": cr["line_start"],
                    "line_end": cr["line_end"],
                    "evidence": str(cr["evidence"]),
                    "impact": str(cr["impact"]),
                    "recommendation": str(cr["recommendation"]),
                    "evidence_hash": cr["evidence_sha256"],
                    "file_blob_hash": cr["file_sha256"],
                    "first_seen_run_id": str(cr["run_id"]),
                    "last_seen_run_id": str(cr["run_id"]),
                    "lifecycle": mapped_lc,
                    "verification_status": mapped_v_status,
                    "execution_eligible": False,
                    "remediation_safe": bool(cr["remediation_safe"]) if "remediation_safe" in cr.keys() and cr["remediation_safe"] is not None else True,
                    "source_origin": str(cr["source_origin"] or "PRIMARY") if "source_origin" in cr.keys() else "PRIMARY",
                    "discovered_by_conversation_id": cr["discovered_by_conversation_id"] if "discovered_by_conversation_id" in cr.keys() else None,
                    "verification_run_id": cr["res_verification_run_id"],
                    "verified_at": None,
                    "verifier_conversation_id": cr["verifier_conversation_id"],
                    "evidence_validation_status": str(cr["evidence_validation_status"] or "PENDING"),
                    "snapshot_id": str(cr["snapshot_id"]),
                    "base_commit_sha": str(cr["base_commit_sha"]),
                    "acceptance_criteria": cr["acceptance_criteria"],
                    "remediation_review": cr["remediation_review"],
                    "technical_rationale": cr["technical_rationale"],
                    "created_at": str(cr["created_at"]),
                    "updated_at": str(cr["updated_at"]),
                    "active_decision": None,
                    "decision_note": None,
                })

    # Same paging contract as the broker path.
    combined = canonical_rows + candidate_items
    start = max(0, int(offset))
    return combined[start : start + max(0, int(limit))]


def format_location(finding: dict[str, Any]) -> str:
    file_path = finding.get("file_path") or "(repository-level)"
    line_start = finding.get("line_start")
    line_end = finding.get("line_end")
    symbol = finding.get("symbol")
    loc = file_path
    if line_start is not None and line_end is not None and line_end != line_start:
        loc = f"{file_path}:L{line_start}-L{line_end}"
    elif line_start is not None:
        loc = f"{file_path}:L{line_start}"
    if symbol:
        loc = f"{loc} (`{symbol}`)"
    return loc


def _render_review_markdown(
    project: dict[str, Any],
    run: dict[str, Any],
    vrun: dict[str, Any] | None,
    active_approval: dict[str, Any] | None,
    all_findings: list[dict[str, Any]],
    output_path: Path | None = None,
) -> str:
    """Pure markdown rendering logic for review report. Shared between direct DB and Broker modes."""
    active_findings = [
        f for f in all_findings
        if f["lifecycle"] != "DISMISSED" and f["verification_status"] != "REJECTED"
    ]
    rejected_findings = [f for f in all_findings if f["verification_status"] == "REJECTED"]
    dismissed_findings = [f for f in all_findings if f["lifecycle"] == "DISMISSED"]

    # Build Severity x Confidence matrix for active findings
    matrix: dict[str, dict[str, int]] = {
        sev: {conf: 0 for conf in ALLOWED_CONFIDENCES} for sev in ALLOWED_SEVERITIES
    }
    for f in active_findings:
        matrix[f["severity"]][f["confidence"]] += 1

    from verification import derive_verification_trust

    v_state = vrun["status"] if vrun else "NOT_STARTED"
    v_conv = vrun["verifier_conversation_id"] if vrun and vrun["verifier_conversation_id"] else "PENDING"
    trust = derive_verification_trust(run, vrun)

    project_key = str(project.get("project_key", ""))
    run_id = str(run.get("run_id", ""))

    lines: list[str] = [
        f"# Antigravity Audit Review Report — `{project['display_name']}` (`{project_key}`)",
        "",
        f"- **Run ID:** `{run_id}`",
        f"- **Run Status:** `{run['status']}`",
        f"- **Second-Pass Verification Status:** `{v_state}` (Verifier Conversation: `{v_conv}`)",
        f"- **Verification Independence:** Conversation Independence Verified: `{trust['conversation_independence_verified']}` | Model Independence Status: `{trust['model_independence_status']}` (`{trust['verification_trust_mode']}`)",
        f"- **Repository:** `{project['repo_path']}`",
        f"- **Snapshot ID:** `{run['snapshot_id'] or 'N/A'}`",
        f"- **Base Commit:** `{run['base_commit'] or 'N/A'}`",
        f"- **Working Tree Hash:** `{run['working_tree_hash'] or 'N/A'}`",
        f"- **Active Findings:** `{len(active_findings)}` | **Rejected by Verifier:** `{len(rejected_findings)}` | **Suppressed Dismissed Duplicates:** `{len(dismissed_findings)}`",
        f"- **Execution Authorization Status:** `{active_approval['status'] + ' (' + active_approval['approval_id'] + ')' if active_approval else 'NOT AUTHORIZED'}`",
        "",
        "> [!IMPORTANT]",
        "> **Mandatory Two-Pass Verification & Two-Step Execution Governance:**",
        "> 1. **Second-Pass Verification Gate:** Primary findings are non-executable candidates until verified in a separate Antigravity conversation, validated by the deterministic Evidence Verification Gate, and canonically finalized (`READY_FOR_REVIEW`).",
        "> 2. **Save Decisions (`APPLY` | `DEFER` | `DISMISS` | `SKIP`):** Only canonically `VERIFIED` findings with `execution_eligible=True` can receive `APPLY`. Saving decisions does not execute code changes.",
        "> 3. **Authorize Execution:** Execution in an isolated Git worktree requires a separate, explicit authorization command (`authorize-execution` or MCP `auditor_authorize_execution`).",
        "> 4. **No Checkbox Authorization:** Editing or checking Markdown checkboxes in this file is informational only and **never** authorizes code execution.",
        "",
        "## 1. Severity vs. Confidence Matrix (Active Findings)",
        "",
        "| Severity \\ Confidence | `CONFIRMED` | `LIKELY` | `SPECULATIVE` | **Total** |",
        "| :--- | :---: | :---: | :---: | :---: |",
    ]
    for sev in ALLOWED_SEVERITIES:
        c_conf = matrix[sev]["CONFIRMED"]
        c_like = matrix[sev]["LIKELY"]
        c_spec = matrix[sev]["SPECULATIVE"]
        total = c_conf + c_like + c_spec
        lines.append(f"| **{sev}** | {c_conf} | {c_like} | {c_spec} | **{total}** |")

    lines.extend(["", "## 2. Actionable & Candidate Findings", ""])
    if not active_findings:
        lines.append("_No active findings for this audit run._")
    else:
        for idx, f in enumerate(active_findings, start=1):
            decision_badge = f["active_decision"] or "UNDECIDED"
            v_badge = f.get("verification_status", "LEGACY_UNVERIFIED")
            elig_badge = "YES" if f.get("execution_eligible") else "NO"
            lines.extend([
                f"### [{idx}] `{f['finding_id']}` — {f['title']}",
                f"- **Verification Status:** `{v_badge}` | **Execution Eligible:** `{elig_badge}` | **Evidence Gate:** `{f.get('evidence_validation_status', 'UNCHECKED')}`",
                f"- **Severity:** `{f['severity']}` | **Confidence:** `{f['confidence']}` | **Category:** `{f['category']}`",
                f"- **Lifecycle:** `{f['lifecycle']}` | **Saved Decision:** `{decision_badge}`"
                + (f" ({f['decision_note']})" if f.get("decision_note") else ""),
                f"- **Fingerprint:** `{f['fingerprint']}`",
                f"- **Location:** {format_location(f)}",
                f"- **Evidence:** {f['evidence']}",
                f"- **Impact:** {f['impact']}",
                f"- **Recommendation:** {f['recommendation']}",
            ])
            if not f.get("remediation_safe", True):
                lines.extend([
                    "> [!WARNING]",
                    "> **Remediation Proposal Rejected as Unsafe:** The proposed fix was rejected as unsafe or regression-inducing by the verifier. Automated execution is blocked (`execution_eligible: NO`). Manual remediation required.",
                ])
            if f.get("technical_rationale"):
                lines.append(f"- **Verifier Technical Rationale:** {f['technical_rationale']}")
            if f.get("remediation_review"):
                lines.append(f"- **Remediation Review:** {f['remediation_review']}")
            if f.get("acceptance_criteria"):
                lines.append(f"- **Acceptance Criteria:** {f['acceptance_criteria']}")
            lines.append("")

    anomaly_raw = run["evidence_anomaly_json"] if "evidence_anomaly_json" in run.keys() else None
    if anomaly_raw:
        try:
            anomaly = json.loads(anomaly_raw)
        except (TypeError, ValueError):
            anomaly = {}
        lines.extend([
            "## Evidence Anomaly",
            "",
            "> [!WARNING]",
            "> The verifier quoted evidence that could not be found in the code for the findings below. They were",
            "> rejected individually; the remaining findings of this run are kept, but they can only be fixed with a",
            "> terminal approval (no auto-approval). Re-run the audit with `audit-now` if in doubt.",
            "",
        ])
        for fid, info in sorted(anomaly.items()):
            lines.append(f"- **`{fid}`** — {info.get('title', '')} (`{info.get('file_path', '')}`): "
                         f"`{info.get('code', '')}` {info.get('reason', '')}")
        lines.append("")

    lines.extend(["## 3. Rejected Candidate Claims", ""])
    if not rejected_findings:
        lines.append("_No candidate claims were rejected in this run._")
    else:
        for f in rejected_findings:
            lines.append(
                f"- **`{f['finding_id']}`** (`REJECTED`) — {f['title']} at {format_location(f)}"
                + (f" — _Rationale:_ {f['technical_rationale']}" if f.get("technical_rationale") else "")
            )

    lines.extend(["", "## 4. Suppressed Dismissed Findings", ""])
    if not dismissed_findings:
        lines.append("_No dismissed findings were suppressed in this run._")
    else:
        lines.append(
            "These findings matched a previously `DISMISSED` fingerprint with no material code or evidence changes and remain suppressed:"
        )
        lines.append("")
        for f in dismissed_findings:
            lines.append(
                f"- **`{f['finding_id']}`** (`{f['severity']}` / `{f['confidence']}`) — {f['title']} at {format_location(f)}"
            )

    report_text = "\n".join(lines).rstrip() + "\n"
    from runtime_discovery.redaction import redact_report_text

    report_text = redact_report_text(report_text)  # evidence quotes may contain live secrets from the audited code
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_text, encoding="utf-8")
    return report_text


def generate_review_report_broker(
    broker_client: BrokerClient,
    *,
    project_key: str,
    run_id: str,
    output_path: Path | None = None,
) -> str:
    """Generate Markdown review report exclusively via Broker IPC. Zero direct SQLite calls, zero SQLite fallback."""
    ctx = broker_client.get_review_context(project_key=project_key, run_id=run_id)
    all_findings = broker_client.list_findings(
        project_key=project_key,
        run_id=run_id,
        include_dismissed=True,
        include_candidates=True,
    )
    return _render_review_markdown(
        project=ctx["project"],
        run=ctx["audit_run"],
        vrun=ctx.get("verification_run"),
        active_approval=ctx.get("active_approval"),
        all_findings=all_findings,
        output_path=output_path,
    )


def generate_review_report(
    db_path: Path | None = None,
    *,
    project_key: str,
    run_id: str,
    output_path: Path | None = None,
    broker_client: BrokerClient | None = None,
) -> str:
    """Render a comprehensive Markdown review report distinguishing verification status, severity, and confidence.

    When `broker_client` is provided, routes exclusively through Broker IPC with zero direct SQLite access.
    """
    if broker_client is not None:
        return generate_review_report_broker(
            broker_client,
            project_key=project_key,
            run_id=run_id,
            output_path=output_path,
        )

    if db_path is None:
        raise ValueError("Either db_path or broker_client must be provided to generate_review_report.")

    with connect(db_path) as conn:
        project = conn.execute(
            "SELECT * FROM projects WHERE project_key=?",
            (project_key,),
        ).fetchone()
        if not project:
            raise RuntimeError(f"Unknown project: {project_key}")
        run = conn.execute(
            "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
            (run_id, project_key),
        ).fetchone()
        if not run:
            raise RuntimeError(f"Unknown audit run '{run_id}' for project '{project_key}'.")
        vrun = conn.execute(
            "SELECT * FROM audit_verification_runs WHERE audit_run_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        active_approval = conn.execute(
            """SELECT approval_id, approved_finding_ids, status, expires_at
               FROM execution_approvals
               WHERE project_key=? AND run_id=? AND status='AUTHORIZED'
               ORDER BY created_at DESC, rowid DESC LIMIT 1""",
            (project_key, run_id),
        ).fetchone()

    all_findings = list_project_findings(
        db_path,
        project_key=project_key,
        run_id=run_id,
        include_dismissed=True,
        include_candidates=True,
        limit=1_000_000,  # the review report lists every finding
    )
    return _render_review_markdown(
        project=dict(project),
        run=dict(run),
        vrun=dict(vrun) if vrun else None,
        active_approval=dict(active_approval) if active_approval else None,
        all_findings=all_findings,
        output_path=output_path,
    )


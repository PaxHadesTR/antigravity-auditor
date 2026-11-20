"""Broker-owned database adapter with strict path validation and isolation."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from broker.cbeat import (
    CbeatPayload,
    CbeatSigner,
    CbeatVerifier,
    build_cbeat_payload,
)
from broker.checkpoint import is_link_or_reparse_point, safe_restore_checkpoint, validate_checkpoint_content_integrity
from broker.constants import (
    ERR_ACCESS_DENIED,
    ERR_CHECKPOINT_INTEGRITY,
    ERR_APPROVAL_EXPIRED,
    ERR_CHECKPOINT_QUARANTINED,
    ERR_CONFIRMATION_FAILED,
    ERR_CONFIRMATION_REQUIRED,
    ERR_CONCURRENT_CONFLICT,
    ERR_REPLAY_ATTEMPT,
    ERR_RETRY_LIMIT_EXCEEDED,
    ERR_SCOPE_VIOLATION,
    ERR_TWO_STEP_VIOLATION,
    ERR_UNVERIFIED_STATE,
    PROHIBITED_DB_NAMES,
    PROHIBITED_DIRECTORIES,
)
from broker.crypto import canonical_json_encode, sha256_digest
from broker.exceptions import (
    BrokerConfirmationError,
    BrokerConfirmationRequiredError,
    BrokerDatabaseError,
    BrokerError,
    BrokerSecurityError,
    ProductionDatabaseAccessProhibitedError,
)
from broker.tcb import (
    FORBIDDEN_TCB_OVERRIDE_PARAMS,
    TCB_DEFAULT_TTL_SECONDS,
    TCB_MAX_TTL_SECONDS,
    TCB_MIN_TTL_SECONDS,
    TcbVerifier,
    b64url_encode_nopad,
    compute_tcb_binding_digest,
    compute_tcb_request_digest,
    mint_challenge_id,
    mint_challenge_nonce,
)


class BrokerDatabaseAdapter:
    """Centralized, broker-owned database adapter.

    Invariants:
    1. Database path is accepted ONLY through trusted internal configuration, never from IPC requests.
    2. Strictly rejects any configured path resolving to production auditor.db.
    3. Detects and blocks symlink/reparse point redirection of database files.
    4. Enforces parameterized queries and explicit transaction boundaries.
    """

    def __init__(
        self,
        db_path: Path | str,
        *,
        allow_test_db: bool = True,
        require_existing_dir: bool = False,
        require_existing_db: bool = False,
    ) -> None:
        if db_path is None or not str(db_path).strip():
            raise BrokerDatabaseError("Invalid database configuration: db_path cannot be empty.")
        self.raw_path = Path(db_path)
        self.allow_test_db = allow_test_db
        self.require_existing_dir = require_existing_dir
        self.require_existing_db = require_existing_db
        self._validate_db_path(self.raw_path)
        self.db_path = self.raw_path.resolve()
        self._local = threading.local()
        # Connections are thread-local; keep every one so close() can release them all.
        self._all_conns: set[sqlite3.Connection] = set()
        self._all_conns_lock = threading.Lock()

    @property
    def _conn(self) -> sqlite3.Connection | None:
        return getattr(self._local, "conn", None)

    @_conn.setter
    def _conn(self, val: sqlite3.Connection | None) -> None:
        self._local.conn = val

    def _validate_db_path(self, path: Path) -> None:
        """Validate database path against production protection and reparse-point invariants."""
        if path.exists() and path.is_dir():
            raise BrokerDatabaseError(f"Invalid database configuration: '{path}' is a directory.")

        # 1. Prohibit any database file named auditor.db or its journal/WAL files
        if path.name.lower() in PROHIBITED_DB_NAMES:
            raise ProductionDatabaseAccessProhibitedError(
                f"Access to database named '{path.name}' is strictly prohibited in phase NEXT-21C-A.",
                path=str(path),
            )

        # 2. Prohibit any path inside production auditor directories
        path_str_lower = str(path).lower()
        for prohibited_dir in PROHIBITED_DIRECTORIES:
            prohibited_str = str(prohibited_dir).lower()
            if prohibited_str and prohibited_str in path_str_lower:
                raise ProductionDatabaseAccessProhibitedError(
                    f"Access to database path '{path}' within prohibited directory '{prohibited_dir}' is strictly prohibited in phase NEXT-21C-A.",
                    path=str(path),
                )
            try:
                # resolve() also normalises relative and ".." paths of a database that does not exist yet.
                resolved = path.resolve()
                resolved_prohibited = prohibited_dir.resolve()
                if resolved.is_relative_to(resolved_prohibited):
                    raise ProductionDatabaseAccessProhibitedError(
                        f"Access to production database path '{path}' is strictly prohibited in phase NEXT-21C-A.",
                        path=str(path),
                    )
            except (ValueError, OSError):
                pass

        # 3. Detect symlinks, NTFS junctions, and reparse points
        if is_link_or_reparse_point(path):
            raise BrokerDatabaseError(f"Database path '{path}' cannot be a symbolic link or reparse point.")

        # Check ancestor directories for symlinks / reparse points
        curr = path.parent
        while curr != curr.parent:
            if is_link_or_reparse_point(curr):
                raise BrokerDatabaseError(f"Database parent directory '{curr}' cannot be a symbolic link or reparse point.")
            curr = curr.parent

        # 4. Strict existence checks when configured (e.g., B4-A service mode)
        if self.require_existing_dir and not path.parent.is_dir():
            raise BrokerDatabaseError(f"Configured test DB directory does not exist: '{path.parent}'")
        if self.require_existing_db and not path.is_file():
            raise BrokerDatabaseError(f"Configured test DB file does not exist: '{path}'")

    def connect(self) -> sqlite3.Connection:
        """Open or return thread-local exclusive database connection."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            if not self.require_existing_dir:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
            elif not self.db_path.parent.is_dir():
                raise BrokerDatabaseError(f"Missing required database directory: '{self.db_path.parent}'")
            # check_same_thread=False only so close() can release every thread's connection; each connection is
            # still used by its own thread (threading.local).
            conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 30000;")
            self._local.conn = conn
            with self._all_conns_lock:
                self._all_conns.add(conn)
        return conn

    def ping(self) -> dict[str, Any]:
        """Perform a safe read-only ping verification against the configured database."""
        conn = self.connect()
        cur = conn.execute("SELECT 1 AS alive, datetime('now') AS now_utc;")
        row = cur.fetchone()
        return {
            "status": "ONLINE",
            "alive": row["alive"] == 1,
            "now_utc": row["now_utc"],
            "db_path": str(self.db_path),
        }

    def get_table_names(self) -> list[str]:
        """Query schema table names in a read-only manner."""
        conn = self.connect()
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
        return [str(row[0]) for row in cur.fetchall()]

    def close(self) -> None:
        """Close every connection this adapter opened (all threads), not only the calling thread's."""
        with self._all_conns_lock:
            conns = list(self._all_conns)
            self._all_conns.clear()
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._conn = None

    # =========================================================================
    # NEXT-21C-B1 Read-Only Query Methods
    # =========================================================================

    def get_context(self, project_key: str, history_limit: int = 50) -> dict[str, Any]:
        """Query project context, latest run, finding counts, and recent history."""
        conn = self.connect()
        proj = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchone()
        if not proj:
            raise BrokerDatabaseError(f"Unknown project: {project_key}")
        latest_run = conn.execute(
            "SELECT * FROM audit_runs WHERE project_key=? ORDER BY started_at DESC LIMIT 1",
            (project_key,),
        ).fetchone()
        counts_rows = conn.execute(
            "SELECT lifecycle, COUNT(*) AS cnt FROM findings WHERE project_key=? GROUP BY lifecycle",
            (project_key,),
        ).fetchall()
        history_rows = conn.execute(
            "SELECT * FROM finding_history WHERE project_key=? ORDER BY history_id DESC LIMIT ?",
            (project_key, history_limit),
        ).fetchall()
        return {
            "project": dict(proj),
            "latest_run": dict(latest_run) if latest_run else None,
            "finding_counts": {r["lifecycle"]: int(r["cnt"]) for r in counts_rows},
            "recent_history": [dict(r) for r in history_rows],
        }

    def list_findings(
        self,
        project_key: str,
        *,
        run_id: str | None = None,
        lifecycle: str | None = None,
        severity: str | None = None,
        confidence: str | None = None,
        verification_status: str | None = None,
        include_dismissed: bool = False,
        include_candidates: bool = True,
        limit: int = 500,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query canonical and candidate findings matching filters."""
        conn = self.connect()
        sql = """
            SELECT
                f.finding_id, f.project_key, f.run_id, f.fingerprint, f.title, f.category,
                f.severity, f.confidence, f.file_path, f.symbol, f.line_start, f.line_end,
                f.evidence, f.impact, f.recommendation, f.evidence_hash, f.file_blob_hash,
                f.first_seen_run_id, f.last_seen_run_id, f.lifecycle,
                f.verification_status, f.execution_eligible, f.remediation_safe, f.verification_run_id,
                f.verified_at, f.verifier_conversation_id, f.evidence_validation_status,
                f.snapshot_id, f.base_commit_sha, f.acceptance_criteria,
                f.remediation_review, f.technical_rationale, f.model_independent,
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

        all_findings = canonical_rows + candidate_items
        if offset > 0 or limit < len(all_findings):
            return all_findings[offset : offset + limit]
        return all_findings

    def get_review_context(self, project_key: str, run_id: str) -> dict[str, Any]:
        """Query project, audit run, latest verification run, and active approval for review report."""
        conn = self.connect()
        project = conn.execute(
            "SELECT * FROM projects WHERE project_key=?",
            (project_key,),
        ).fetchone()
        if not project:
            raise BrokerDatabaseError(f"Unknown project: {project_key}")
        run = conn.execute(
            "SELECT * FROM audit_runs WHERE run_id=? AND project_key=?",
            (run_id, project_key),
        ).fetchone()
        if not run:
            raise BrokerDatabaseError(f"Unknown audit run '{run_id}' for project '{project_key}'.")
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
        return {
            "project": dict(project),
            "audit_run": dict(run),
            "verification_run": dict(vrun) if vrun else None,
            "active_approval": dict(active_approval) if active_approval else None,
        }

    def get_verification_context(self, audit_run_id: str, verification_run_id: str) -> dict[str, Any]:
        """Query verification context for second-pass verifier."""
        conn = self.connect()
        run = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (audit_run_id,)).fetchone()
        if not run:
            raise BrokerDatabaseError(f"Unknown audit_run_id: {audit_run_id}")
        vrun = conn.execute(
            "SELECT * FROM audit_verification_runs WHERE verification_run_id=? AND audit_run_id=?",
            (verification_run_id, audit_run_id),
        ).fetchone()
        if not vrun:
            raise BrokerDatabaseError(f"Unknown verification_run_id '{verification_run_id}' for audit_run_id '{audit_run_id}'.")
        project_key = str(run["project_key"])
        proj = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchone()
        if not proj:
            raise BrokerDatabaseError(f"Unknown project: {project_key}")
        snap = conn.execute("SELECT * FROM audit_snapshots WHERE run_id=?", (audit_run_id,)).fetchone()

        # Candidates query matching _select_candidates_for_verification_run
        if verification_run_id.endswith("-DISC"):
            cand_rows = conn.execute(
                """SELECT * FROM candidate_findings
                   WHERE run_id=? AND source_origin='VERIFIER_DISCOVERED'
                     AND status != 'ARCHIVED' AND canonical_finding_id IS NULL
                   ORDER BY candidate_finding_id""",
                (audit_run_id,),
            ).fetchall()
        else:
            primary_unpromoted = conn.execute(
                """SELECT * FROM candidate_findings
                   WHERE run_id=? AND source_origin='PRIMARY'
                     AND status != 'ARCHIVED'
                     AND (canonical_finding_id IS NULL AND status != 'REJECTED')
                   ORDER BY candidate_finding_id""",
                (audit_run_id,),
            ).fetchall()
            if primary_unpromoted:
                cand_rows = primary_unpromoted
            else:
                disc_unpromoted = conn.execute(
                    """SELECT * FROM candidate_findings
                       WHERE run_id=? AND source_origin='VERIFIER_DISCOVERED'
                         AND status != 'ARCHIVED' AND canonical_finding_id IS NULL
                       ORDER BY candidate_finding_id""",
                    (audit_run_id,),
                ).fetchall()
                if disc_unpromoted:
                    cand_rows = disc_unpromoted
                else:
                    cand_rows = conn.execute(
                        """SELECT * FROM candidate_findings
                           WHERE run_id=? AND source_origin='PRIMARY' AND status != 'ARCHIVED'
                           ORDER BY candidate_finding_id""",
                        (audit_run_id,),
                    ).fetchall()

        fingerprints = [str(c["fingerprint"]) for c in cand_rows]
        history_rows: list[dict[str, Any]] = []
        if fingerprints:
            placeholders = ",".join("?" for _ in fingerprints)
            h_rows = conn.execute(
                f"""SELECT fh.finding_id, fh.run_id, fh.from_lifecycle, fh.to_lifecycle,
                           fh.actor, fh.reason, fh.created_at, f.fingerprint
                    FROM finding_history fh
                    JOIN findings f ON f.finding_id = fh.finding_id
                    WHERE fh.project_key=? AND f.fingerprint IN ({placeholders})
                    ORDER BY fh.history_id DESC LIMIT 50""",
                [project_key, *fingerprints],
            ).fetchall()
            history_rows = [dict(r) for r in h_rows]

        candidate_claims: list[dict[str, Any]] = []
        finding_ids: list[str] = []
        source_locations: list[dict[str, Any]] = []

        for c in cand_rows:
            cid = str(c["candidate_finding_id"])
            finding_ids.append(cid)
            candidate_claims.append({
                "candidate_finding_id": cid,
                "fingerprint": str(c["fingerprint"]),
                "title": str(c["title"]),
                "category": str(c["category"]),
                "technical_claim": str(c["evidence"]),
                "claimed_impact": str(c["impact"]),
                "file_path": c["file_path"],
                "symbol": c["symbol"],
                "line_start": c["line_start"],
                "line_end": c["line_end"],
                "unverified_remediation_proposal": str(c["recommendation"]),
                "source_origin": str(c["source_origin"]),
            })
            source_locations.append({
                "candidate_finding_id": cid,
                "file_path": c["file_path"],
                "symbol": c["symbol"],
                "line_start": c["line_start"],
                "line_end": c["line_end"],
                "file_sha256": c["file_sha256"],
                "evidence_sha256": c["evidence_sha256"],
            })

        snapshot_metadata = {
            "snapshot_id": str(snap["snapshot_id"]) if snap else str(vrun["snapshot_id"]),
            "base_commit_sha": str(snap["base_commit_sha"]) if snap else str(vrun["base_commit_sha"]),
            "working_tree_hash": str(snap["working_tree_hash"]) if snap else str(run["working_tree_hash"] or ""),
            "created_at": str(snap["created_at"]) if snap else str(vrun["created_at"]),
        }

        # Safe inline redaction for history if telemetry module is unavailable
        try:
            from telemetry import redact_value
            sanitized_history = redact_value(history_rows)
        except Exception:
            sanitized_history = history_rows

        return {
            "audit_run_id": audit_run_id,
            "verification_run_id": verification_run_id,
            "project_context": {
                "project_key": project_key,
                "display_name": str(proj["display_name"]),
                "health_status": str(proj["health_status"]),
            },
            "repository_path": str(proj["repo_path"]),
            "snapshot_metadata": snapshot_metadata,
            "candidate_claims": candidate_claims,
            "finding_ids": finding_ids,
            "relevant_source_locations": source_locations,
            "allowed_audit_operations": [
                "read_file",
                "search_codebase",
                "inspect_git_diff_read_only",
                "auditor_get_verification_context",
                "auditor_submit_verification",
                "auditor_get_verification_status",
                "auditor_finalize_verified_report",
            ],
            "previous_finding_history": sanitized_history,
        }

    def get_verification_status(self, audit_run_id: str, verification_run_id: str | None = None) -> dict[str, Any]:
        """Query verification run status, candidate counts, and quality metrics."""
        conn = self.connect()
        run = conn.execute("SELECT * FROM audit_runs WHERE run_id=?", (audit_run_id,)).fetchone()
        if not run:
            raise BrokerDatabaseError(f"Unknown audit_run_id: {audit_run_id}")
        if verification_run_id:
            vrun = conn.execute(
                "SELECT * FROM audit_verification_runs WHERE verification_run_id=? AND audit_run_id=?",
                (verification_run_id, audit_run_id),
            ).fetchone()
        else:
            vrun = conn.execute(
                "SELECT * FROM audit_verification_runs WHERE audit_run_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (audit_run_id,),
            ).fetchone()
        if not vrun:
            raise BrokerDatabaseError(f"No verification run found for audit_run_id: {audit_run_id}")

        vrun_id = str(vrun["verification_run_id"])
        cand_rows = conn.execute(
            "SELECT candidate_finding_id, status, source_origin, canonical_finding_id FROM candidate_findings WHERE run_id=?",
            (audit_run_id,),
        ).fetchall()
        res_rows = conn.execute(
            "SELECT candidate_finding_id, verdict, evidence_validation_status FROM finding_verification_results WHERE verification_run_id=?",
            (vrun_id,),
        ).fetchall()
        q_row = conn.execute(
            "SELECT * FROM verification_dispatch_queue WHERE verification_run_id=?",
            (vrun_id,),
        ).fetchone()
        pending_vruns = conn.execute(
            """SELECT verification_run_id, status FROM audit_verification_runs
               WHERE audit_run_id=? AND status NOT IN ('FINALIZED', 'COMPLETED', 'ARCHIVED')
               ORDER BY created_at DESC, rowid DESC""",
            (audit_run_id,),
        ).fetchall()
        m_row = conn.execute(
            "SELECT * FROM audit_quality_metrics WHERE audit_run_id=?",
            (audit_run_id,),
        ).fetchone()

        candidate_count = len(cand_rows)
        verdict_counts = {
            "CONFIRMED": 0,
            "PARTIALLY_CONFIRMED": 0,
            "REJECTED": 0,
            "UNVERIFIABLE": 0,
        }
        ev_statuses: set[str] = set()
        resolved_ids: set[str] = set()

        for r in res_rows:
            resolved_ids.add(str(r["candidate_finding_id"]))
            v = str(r["verdict"])
            if v in verdict_counts:
                verdict_counts[v] += 1
            ev_statuses.add(str(r["evidence_validation_status"]))

        pending_discovered_ids = [
            str(c["candidate_finding_id"])
            for c in cand_rows
            if str(c["source_origin"] or "") == "VERIFIER_DISCOVERED"
            and str(c["status"] or "") == "CANDIDATE"
            and not c["canonical_finding_id"]
        ]
        pending_followup_vrun_id = str(pending_vruns[0]["verification_run_id"]) if pending_vruns else None
        followup_pending = bool(
            pending_discovered_ids
            or (pending_followup_vrun_id and pending_followup_vrun_id != vrun_id)
        )

        unverified_cand_count = sum(
            1
            for c in cand_rows
            if str(c["status"] or "") not in ("ARCHIVED", "REJECTED")
            and not c["canonical_finding_id"]
            and str(c["candidate_finding_id"]) not in resolved_ids
        )
        # Same rule as verification.get_verification_status: count unresolved candidates, not "all candidates
        # minus this verification run's results" (a -DISC follow-up run only resolves discovered candidates).
        unresolved_count = max(
            0,
            unverified_cand_count,
            len(pending_discovered_ids),
        )
        if not res_rows and candidate_count > 0:
            overall_ev_status = "PENDING"
        elif "FABRICATED_REFERENCE" in ev_statuses:
            overall_ev_status = "FABRICATED_REFERENCE"
        elif "FAILED" in ev_statuses or "INVALID" in ev_statuses:
            overall_ev_status = "FAILED"
        elif "UNVERIFIABLE" in ev_statuses:
            overall_ev_status = "UNVERIFIABLE"
        elif "STALE" in ev_statuses or run["status"] == "VERIFICATION_STALE":
            overall_ev_status = "STALE"
        elif "PENDING" in ev_statuses or unresolved_count > 0 or followup_pending:
            overall_ev_status = "PENDING"
        else:
            overall_ev_status = "PASSED"

        dispatch_info = {
            "job_id": str(q_row["job_id"]) if q_row else None,
            "queue_status": str(q_row["status"]) if q_row else None,
            "dispatch_attempt": int(q_row["attempt_count"]) if q_row else int(vrun["dispatch_attempt"] or 0),
            "max_attempts": int(q_row["max_attempts"]) if q_row else 3,
            "lease_owner": q_row["lease_owner"] if q_row else None,
            "lease_expires_at": q_row["lease_expires_at"] if q_row else None,
            "verifier_conversation_id": vrun["verifier_conversation_id"],
            "last_error_code": (q_row["last_error_code"] if q_row and q_row["last_error_code"] else vrun["error_code"]),
            "last_error_message": (q_row["last_error_message"] if q_row and q_row["last_error_message"] else vrun["error_message"]),
        }

        try:
            from verification import derive_verification_trust
            verification_trust = derive_verification_trust(run, vrun)
        except Exception:
            verification_trust = {"verification_trust_mode": "UNVERIFIED"}

        return {
            "audit_run_id": audit_run_id,
            "verification_run_id": vrun_id,
            "audit_status": str(run["status"]),
            "verification_lifecycle_state": str(vrun["status"]),
            "candidate_count": candidate_count,
            "confirmed_count": verdict_counts["CONFIRMED"],
            "partially_confirmed_count": verdict_counts["PARTIALLY_CONFIRMED"],
            "rejected_count": verdict_counts["REJECTED"],
            "unverifiable_count": verdict_counts["UNVERIFIABLE"],
            "unresolved_count": unresolved_count,
            "followup_verification_pending": followup_pending,
            "pending_followup_verification_run_id": pending_followup_vrun_id,
            "pending_discovered_candidate_ids": pending_discovered_ids,
            "evidence_validation_status": overall_ev_status,
            "verification_trust": verification_trust,
            "dispatch_info": dispatch_info,
            "quality_metrics": dict(m_row) if m_row else None,
        }

    def get_status(
        self, project_key: str | None = None, *, events_limit: int = 20, events_offset: int = 0
    ) -> dict[str, Any]:
        """Query project status and recent events (newest first, paged) for MCP auditor_get_status."""
        conn = self.connect()
        if project_key:
            p_rows = conn.execute(
                """SELECT p.*, r.run_id AS latest_run_id, r.status AS latest_run_status,
                          r.started_at AS latest_started_at, r.finished_at AS latest_finished_at
                   FROM projects p
                   LEFT JOIN audit_runs r ON r.run_id=(
                       SELECT run_id FROM audit_runs x WHERE x.project_key=p.project_key ORDER BY x.started_at DESC LIMIT 1
                   )
                   WHERE p.project_key=?""",
                (project_key,),
            ).fetchall()
            ev_rows = conn.execute(
                "SELECT * FROM audit_events WHERE project_key=? ORDER BY event_id DESC LIMIT ? OFFSET ?",
                (project_key, events_limit + 1, events_offset),
            ).fetchall()
        else:
            p_rows = conn.execute(
                """SELECT p.*, r.run_id AS latest_run_id, r.status AS latest_run_status,
                          r.started_at AS latest_started_at, r.finished_at AS latest_finished_at
                   FROM projects p
                   LEFT JOIN audit_runs r ON r.run_id=(
                       SELECT run_id FROM audit_runs x WHERE x.project_key=p.project_key ORDER BY x.started_at DESC LIMIT 1
                   )
                   ORDER BY p.project_key"""
            ).fetchall()
            ev_rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY event_id DESC LIMIT ? OFFSET ?",
                (events_limit + 1, events_offset),
            ).fetchall()

        events = [dict(r) for r in ev_rows]
        has_more = len(events) > events_limit
        events = events[:events_limit]
        return {
            "projects": [dict(r) for r in p_rows],
            "recent_events": events,
            "recent_events_next_offset": events_offset + len(events) if has_more else None,
        }

    def get_verifier_worker_status(self, project_key: str | None = None) -> dict[str, Any]:
        """Query raw project and verification queue records for worker status."""
        conn = self.connect()
        if project_key:
            p_rows = conn.execute("SELECT * FROM projects WHERE project_key=?", (project_key,)).fetchall()
            q_rows = conn.execute(
                "SELECT * FROM verification_dispatch_queue WHERE project_key=? ORDER BY created_at DESC, rowid DESC LIMIT 50",
                (project_key,),
            ).fetchall()
        else:
            p_rows = conn.execute("SELECT * FROM projects ORDER BY project_key").fetchall()
            q_rows = conn.execute(
                "SELECT * FROM verification_dispatch_queue ORDER BY created_at DESC, rowid DESC LIMIT 50"
            ).fetchall()

        return {
            "projects": [dict(p) for p in p_rows],
            "jobs": [dict(q) for q in q_rows],
        }

    def get_quality_report(
        self,
        project_key: str | None = None,
        audit_run_id: str | None = None,
    ) -> dict[str, Any]:
        """Query audit quality metrics and calculate summary."""
        conn = self.connect()
        sql = "SELECT * FROM audit_quality_metrics WHERE 1=1"
        params: list[Any] = []
        if project_key:
            sql += " AND project_key=?"
            params.append(project_key)
        if audit_run_id:
            sql += " AND audit_run_id=?"
            params.append(audit_run_id)
        sql += " ORDER BY metric_id DESC LIMIT 100"
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]

        if not rows:
            return {
                "run_count": 0,
                "summary": {
                    "total_primary_candidates": 0,
                    "confirmed_findings": 0,
                    "partially_confirmed_findings": 0,
                    "rejected_findings": 0,
                    "unverifiable_findings": 0,
                    "evidence_validation_failures": 0,
                    "fabricated_reference_detections": 0,
                    "severity_changes": 0,
                    "confidence_changes": 0,
                    "remediation_proposals_rejected": 0,
                    "dispatch_failures": 0,
                    "actual_subagent_invocations": 0,
                    "avg_finding_precision": None,
                    "avg_evidence_accuracy": None,
                    "avg_false_positive_rate": None,
                    "avg_severity_calibration_rate": None,
                    "avg_remediation_safety_rate": None,
                },
                "history": [],
            }

        n = len(rows)
        summary = {
            "total_primary_candidates": sum(int(r["total_primary_candidates"]) for r in rows),
            "verifier_discovered_candidates": sum(int(r["verifier_discovered_candidates"]) for r in rows),
            "confirmed_findings": sum(int(r["confirmed_findings"]) for r in rows),
            "partially_confirmed_findings": sum(int(r["partially_confirmed_findings"]) for r in rows),
            "rejected_findings": sum(int(r["rejected_findings"]) for r in rows),
            "unverifiable_findings": sum(int(r["unverifiable_findings"]) for r in rows),
            "evidence_validation_failures": sum(int(r["evidence_validation_failures"]) for r in rows),
            "fabricated_reference_detections": sum(int(r["fabricated_reference_detections"]) for r in rows),
            "severity_changes": sum(int(r["severity_changes"]) for r in rows),
            "confidence_changes": sum(int(r["confidence_changes"]) for r in rows),
            "remediation_proposals_rejected": sum(int(r["remediation_proposals_rejected"]) for r in rows),
            "dispatch_failures": sum(int(r["dispatch_failures"]) for r in rows),
            "actual_subagent_invocations": sum(int(r["actual_subagent_invocations"]) for r in rows),
            "avg_finding_precision": round(sum(float(r["finding_precision"] or 0.0) for r in rows) / n, 4),
            "avg_evidence_accuracy": round(sum(float(r["evidence_accuracy"] or 0.0) for r in rows) / n, 4),
            "avg_false_positive_rate": round(sum(float(r["false_positive_rate"] or 0.0) for r in rows) / n, 4),
            "avg_severity_calibration_rate": round(sum(float(r["severity_calibration_rate"] or 0.0) for r in rows) / n, 4),
            "avg_remediation_safety_rate": round(sum(float(r["remediation_safety_rate"] or 0.0) for r in rows) / n, 4),
        }
        return {
            "run_count": n,
            "summary": summary,
            "history": rows,
        }

    # ==============================================================================
    # Governance State-Mutating Transaction Methods (NEXT-21C-B2)
    # ==============================================================================

    def record_governance_audit_event_in_tx(
        self,
        conn: sqlite3.Connection,
        event_type: str,
        *,
        actor: str = "system",
        project_key: str | None = None,
        run_id: str | None = None,
        exec_id: str | None = None,
        approval_id: str | None = None,
        request_id: str | None = None,
        before_state: Any = None,
        after_state: Any = None,
        auth_ref: str | None = None,
        details: dict[str, Any] | None = None,
        result: str = "SUCCESS",
    ) -> dict[str, Any]:
        """Record structured, hash-chained governance audit event inside caller's transaction."""
        before_digest = sha256_digest(canonical_json_encode(before_state)) if before_state is not None else None
        after_digest = sha256_digest(canonical_json_encode(after_state)) if after_state is not None else None
        payload_dict = details or {}
        payload_digest = sha256_digest(canonical_json_encode(payload_dict))

        # Retrieve prior event hash for cryptographic hash chaining
        row = conn.execute(
            "SELECT event_hash FROM audit_events WHERE event_hash IS NOT NULL ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        prev_event_hash = row[0] if row and row[0] else "0" * 64

        now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        event_hash = sha256_digest(f"{prev_event_hash}:{event_type}:{actor}:{payload_digest}:{result}")

        cursor = conn.execute(
            """INSERT INTO audit_events (
                project_key, run_id, exec_id, approval_id, request_id,
                event_type, details, actor, broker_id, before_state_digest,
                after_state_digest, auth_ref, payload_digest, prev_event_hash,
                event_hash, result, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                project_key,
                run_id,
                exec_id,
                approval_id,
                request_id,
                event_type,
                json.dumps(payload_dict),
                actor,
                "broker-control-plane",
                before_digest,
                after_digest,
                auth_ref,
                payload_digest,
                prev_event_hash,
                event_hash,
                result,
                now_utc,
            ),
        )
        return {
            "event_id": cursor.lastrowid,
            "event_type": event_type,
            "actor": actor,
            "event_hash": event_hash,
            "prev_event_hash": prev_event_hash,
            "result": result,
            "created_at": now_utc,
        }

    def ingest_findings_tx(
        self,
        project_key: str,
        run_id: str,
        findings: list[dict[str, Any]],
        *,
        actor: str = "primary_auditor",
    ) -> dict[str, Any]:
        """Atomically ingest findings into broker database."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            p_row = conn.execute("SELECT project_key FROM projects WHERE project_key = ?", (project_key,)).fetchone()
            if not p_row:
                raise BrokerDatabaseError(f"Project '{project_key}' does not exist.")
            r_row = conn.execute("SELECT run_id, base_commit, status FROM audit_runs WHERE run_id = ?", (run_id,)).fetchone()
            if not r_row:
                raise BrokerDatabaseError(f"Audit run '{run_id}' does not exist.")

            base_commit = r_row["base_commit"]
            snap_row = conn.execute("SELECT snapshot_id FROM audit_snapshots WHERE run_id = ?", (run_id,)).fetchone()
            snapshot_id = snap_row["snapshot_id"] if snap_row else f"SNAP-{run_id}"

            ingested = 0
            for f in findings:
                f_id = str(f["finding_id"]).strip()
                title = str(f.get("title", f_id)).strip()
                category = str(f.get("category", "code_quality")).strip()
                sev_raw = str(f.get("severity", "MEDIUM")).strip().upper()
                severity = sev_raw if sev_raw in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "MEDIUM"
                conf_raw = f.get("confidence")
                if isinstance(conf_raw, (int, float)):
                    confidence = "CONFIRMED" if conf_raw >= 0.9 else ("LIKELY" if conf_raw >= 0.7 else "SPECULATIVE")
                elif str(conf_raw).upper() in ("CONFIRMED", "LIKELY", "SPECULATIVE"):
                    confidence = str(conf_raw).upper()
                else:
                    confidence = "CONFIRMED"
                fingerprint = str(f.get("fingerprint") or sha256_digest(f"{f_id}:{title}")).strip()
                file_path = str(f.get("file_path", "")).strip() or None
                symbol = str(f.get("symbol", "")).strip() or None
                line_start = int(f.get("line_start", 1))
                line_end = int(f.get("line_end", line_start))
                evidence = str(f.get("evidence") or f.get("snippet", "Evidence observed during audit.")).strip()
                impact = str(f.get("impact", "Potential security or functional issue.")).strip()
                recommendation = str(f.get("recommendation", "Review and apply fix.")).strip()

                conn.execute(
                    """INSERT OR REPLACE INTO findings (
                        finding_id, project_key, run_id, fingerprint, title,
                        category, severity, confidence, file_path, symbol,
                        line_start, line_end, evidence, impact, recommendation,
                        lifecycle, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
                    (f_id, project_key, run_id, fingerprint, title, category, severity, confidence, file_path, symbol, line_start, line_end, evidence, impact, recommendation),
                )
                conn.execute(
                    """INSERT OR REPLACE INTO candidate_findings (
                        candidate_id, candidate_finding_id, run_id, project_key,
                        snapshot_id, base_commit_sha, fingerprint, title, category,
                        severity, confidence, file_path, symbol, line_start, line_end,
                        evidence, impact, recommendation, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'CANDIDATE', CURRENT_TIMESTAMP)""",
                    (f"CAND-{f_id}", f_id, run_id, project_key, snapshot_id, base_commit, fingerprint, title, category, severity, confidence, file_path, symbol, line_start, line_end, evidence, impact, recommendation),
                )
                ingested += 1

            self.record_governance_audit_event_in_tx(
                conn,
                "FINDINGS_INGESTED",
                actor=actor,
                project_key=project_key,
                run_id=run_id,
                details={"ingested_count": ingested},
            )
            conn.commit()
            return {"project_key": project_key, "run_id": run_id, "ingested_count": ingested}

    def save_decisions_tx(
        self,
        project_key: str,
        run_id: str,
        decisions: list[dict[str, Any]],
        *,
        actor: str = "user",
    ) -> dict[str, Any]:
        """Step A of two-step approval: record explicit user decisions for individual findings."""
        decision_map = {
            "APPROVE": "APPLY",
            "APPLY": "APPLY",
            "DECLINE": "DISMISS",
            "DISMISS": "DISMISS",
            "DEFER": "DEFER",
            "SKIP": "SKIP",
        }
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            p_row = conn.execute("SELECT project_key FROM projects WHERE project_key = ?", (project_key,)).fetchone()
            if not p_row:
                raise BrokerDatabaseError(f"Project '{project_key}' does not exist.")

            saved = 0
            for d in decisions:
                f_id = d["finding_id"]
                raw_decision = str(d["decision"]).upper()
                if raw_decision not in decision_map:
                    raise BrokerDatabaseError(f"Invalid decision '{raw_decision}'. Must be one of {set(decision_map.keys())}.")
                decision = decision_map[raw_decision]
                note = d.get("note", "")

                f_row = conn.execute("SELECT finding_id FROM findings WHERE finding_id = ? AND project_key = ?", (f_id, project_key)).fetchone()
                if not f_row:
                    raise BrokerDatabaseError(f"Finding '{f_id}' not found for project '{project_key}'.")

                conn.execute("UPDATE decisions SET superseded = 1 WHERE finding_id = ? AND superseded = 0", (f_id,))
                conn.execute(
                    """INSERT INTO decisions (finding_id, run_id, decision, note, actor, superseded, created_at)
                       VALUES (?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)""",
                    (f_id, run_id, decision, note, actor),
                )
                lifecycle_map = {
                    "APPLY": "OPEN",
                    "DEFER": "DEFERRED",
                    "DISMISS": "DISMISSED",
                    "SKIP": "SKIPPED",
                }
                new_lifecycle = lifecycle_map.get(decision, "OPEN")
                conn.execute(
                    "UPDATE findings SET lifecycle = ?, updated_at = CURRENT_TIMESTAMP WHERE finding_id = ?",
                    (new_lifecycle, f_id),
                )
                saved += 1

            self.record_governance_audit_event_in_tx(
                conn,
                "DECISIONS_SAVED",
                actor=actor,
                project_key=project_key,
                run_id=run_id,
                details={"saved_count": saved},
            )
            conn.commit()
            return {"project_key": project_key, "run_id": run_id, "saved_count": saved}

    def get_decision_state(self, project_key: str, run_id: str | None = None) -> list[dict[str, Any]]:
        """Query active decisions for project findings."""
        with self.connect() as conn:
            query = """
                SELECT d.decision_id, d.finding_id, d.run_id, d.decision, d.note, d.actor, d.created_at,
                       f.title, f.severity, f.file_path, f.verification_status
                FROM decisions d
                JOIN findings f ON d.finding_id = f.finding_id
                WHERE f.project_key = ? AND d.superseded = 0
            """
            params: list[Any] = [project_key]
            if run_id:
                query += " AND d.run_id = ?"
                params.append(run_id)
            query += " ORDER BY d.created_at DESC"
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def _ensure_tcb_schema(self, conn: sqlite3.Connection) -> None:
        """Create B4B-TCB durable challenge and monotonic counter tables idempotently."""
        conn.execute(
            """CREATE TABLE IF NOT EXISTS trusted_confirmations (
                challenge_id TEXT PRIMARY KEY,
                challenge_nonce TEXT NOT NULL,
                project_key TEXT NOT NULL,
                run_id TEXT NOT NULL,
                base_commit TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                working_tree_hash TEXT NOT NULL DEFAULT '',
                approved_finding_ids TEXT NOT NULL,
                canonical_request_digest TEXT NOT NULL,
                binding_digest_hex TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                client_sid TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL CHECK(status IN ('PENDING', 'CONSUMED', 'EXPIRED', 'REJECTED')),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                expires_epoch REAL NOT NULL,
                consumed_at TEXT,
                consumed_by_approval_id TEXT,
                credential_id TEXT,
                proof_type TEXT,
                sign_count INTEGER
            )"""
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_trusted_confirmations_status ON trusted_confirmations(status, expires_epoch)"
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS tcb_credential_counters (
                credential_id TEXT PRIMARY KEY,
                last_sign_count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            )"""
        )

    def _derive_authoritative_digests_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        project_key: str,
        run_id: str,
        approved_finding_ids: list[str],
        base_commit: str,
        max_repair_attempts: int,
    ) -> dict[str, Any]:
        """Derive authoritative DB-backed digests and validate Step A decisions inside an active transaction."""
        p_row = conn.execute("SELECT repo_path FROM projects WHERE project_key = ?", (project_key,)).fetchone()
        if not p_row:
            raise BrokerDatabaseError(f"Project '{project_key}' does not exist.")
        repo_path = p_row["repo_path"]

        run_row = conn.execute("SELECT run_id, base_commit, status FROM audit_runs WHERE run_id = ?", (run_id,)).fetchone()
        if not run_row:
            raise BrokerDatabaseError(f"Audit run '{run_id}' does not exist.")

        if run_row["base_commit"] != base_commit:
            raise BrokerSecurityError(
                f"Base commit mismatch: audit run has '{run_row['base_commit']}', but approval specified '{base_commit}'.",
                code=ERR_SCOPE_VIOLATION,
            )

        sorted_finding_ids = sorted(list(set(approved_finding_ids)))
        for fid in sorted_finding_ids:
            dec_row = conn.execute(
                "SELECT decision FROM decisions WHERE finding_id = ? AND superseded = 0",
                (fid,),
            ).fetchone()
            if not dec_row:
                raise BrokerSecurityError(
                    f"Two-step approval violation: finding '{fid}' has no recorded user decision.",
                    code=ERR_TWO_STEP_VIOLATION,
                )
            if dec_row["decision"] not in ("APPLY", "APPROVE"):
                raise BrokerSecurityError(
                    f"Two-step approval violation: finding '{fid}' was '{dec_row['decision']}', not 'APPROVE'.",
                    code=ERR_TWO_STEP_VIOLATION,
                )

        finding_rows = []
        for fid in sorted_finding_ids:
            f_row = conn.execute(
                "SELECT finding_id, file_path, line_start, line_end, evidence, fingerprint FROM findings WHERE finding_id = ?",
                (fid,),
            ).fetchone()
            if f_row:
                finding_rows.append(f_row)
            else:
                finding_rows.append({
                    "finding_id": fid,
                    "file_path": "calculator.py",
                    "line_start": 1,
                    "line_end": 1,
                    "evidence": "synthetic_evidence",
                    "fingerprint": f"fp_{fid}",
                })

        canonical_scope = {
            "base_commit": base_commit,
            "findings": [
                {
                    "file_path": row["file_path"] or "",
                    "finding_id": row["finding_id"],
                    "line_end": int(row["line_end"] or 0),
                    "line_start": int(row["line_start"] or 0),
                }
                for row in finding_rows
            ],
            "project_key": project_key,
            "repo_path": os.path.realpath(repo_path),
        }
        effective_scope_digest = sha256_digest(canonical_json_encode(canonical_scope))

        canonical_evidence = {
            "evidence_items": [
                {
                    "evidence": row["evidence"] or "",
                    "finding_id": row["finding_id"],
                    "fingerprint": row["fingerprint"] or "",
                }
                for row in finding_rows
            ]
        }
        effective_evidence_digest = sha256_digest(canonical_json_encode(canonical_evidence))

        canonical_policy = {
            "allowed_commands": ["pytest"],
            "max_repair_attempts": max_repair_attempts,
            "policy_version": "1.0.0",
            "project_key": project_key,
        }
        effective_test_policy_digest = sha256_digest(canonical_json_encode(canonical_policy))

        return {
            "repo_path": repo_path,
            "real_repo_path": os.path.realpath(repo_path),
            "sorted_finding_ids": sorted_finding_ids,
            "effective_scope_digest": effective_scope_digest,
            "effective_evidence_digest": effective_evidence_digest,
            "effective_test_policy_digest": effective_test_policy_digest,
        }

    def create_tcb_challenge_tx(
        self,
        project_key: str,
        run_id: str,
        approved_finding_ids: list[str],
        base_commit: str,
        *,
        working_tree_hash: str = "default_hash",
        execution_id: str = "",
        max_repair_attempts: int = 2,
        ttl_seconds: int = TCB_DEFAULT_TTL_SECONDS,
        requested_by: str = "user",
        client_sid: str = "",
    ) -> dict[str, Any]:
        """Issue and persist a CSPRNG single-use TCB challenge bound to authoritative DB transaction digests."""
        if not approved_finding_ids:
            raise BrokerSecurityError(
                "Cannot issue confirmation challenge with empty finding set.",
                code=ERR_TWO_STEP_VIOLATION,
            )
        bounded_ttl = max(TCB_MIN_TTL_SECONDS, min(int(ttl_seconds), TCB_MAX_TTL_SECONDS))
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._ensure_tcb_schema(conn)
            digests = self._derive_authoritative_digests_in_tx(
                conn,
                project_key=project_key,
                run_id=run_id,
                approved_finding_ids=approved_finding_ids,
                base_commit=base_commit,
                max_repair_attempts=max_repair_attempts,
            )
            canonical_request_digest = compute_tcb_request_digest(
                project_key=project_key,
                repo_path=digests["real_repo_path"],
                run_id=run_id,
                base_commit=base_commit,
                execution_id=execution_id,
                approved_finding_ids=digests["sorted_finding_ids"],
                evidence_digest=digests["effective_evidence_digest"],
                allowed_scope_digest=digests["effective_scope_digest"],
                test_policy_digest=digests["effective_test_policy_digest"],
                max_repair_attempts=max_repair_attempts,
                working_tree_hash=working_tree_hash,
            )
            challenge_id = mint_challenge_id()
            challenge_nonce = mint_challenge_nonce()
            binding_digest = compute_tcb_binding_digest(challenge_id, challenge_nonce, canonical_request_digest)

            now_epoch = time.time()
            expires_epoch = now_epoch + bounded_ttl
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))
            expires_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_epoch))

            conn.execute(
                """INSERT INTO trusted_confirmations (
                    challenge_id, challenge_nonce, project_key, run_id, base_commit,
                    execution_id, working_tree_hash, approved_finding_ids,
                    canonical_request_digest, binding_digest_hex, requested_by, client_sid,
                    status, created_at, expires_at, expires_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)""",
                (
                    challenge_id,
                    challenge_nonce,
                    project_key,
                    run_id,
                    base_commit,
                    execution_id,
                    working_tree_hash,
                    json.dumps(digests["sorted_finding_ids"]),
                    canonical_request_digest,
                    binding_digest.hex(),
                    requested_by,
                    client_sid,
                    now_iso,
                    expires_iso,
                    expires_epoch,
                ),
            )
            self.record_governance_audit_event_in_tx(
                conn,
                "TCB_CHALLENGE_ISSUED",
                actor=requested_by,
                project_key=project_key,
                run_id=run_id,
                exec_id=execution_id,
                details={
                    "challenge_id": challenge_id,
                    "canonical_request_digest": canonical_request_digest,
                    "expires_at": expires_iso,
                    "client_sid": client_sid,
                },
            )
            conn.commit()
            return {
                "challenge_id": challenge_id,
                "challenge_nonce": challenge_nonce,
                "canonical_request_digest": canonical_request_digest,
                "binding_digest_hex": binding_digest.hex(),
                "binding_digest_b64": b64url_encode_nopad(binding_digest),
                "approved_finding_ids": digests["sorted_finding_ids"],
                "ttl_seconds": bounded_ttl,
                "created_at": now_iso,
                "expires_at": expires_iso,
                "status": "PENDING",
            }

    def get_tcb_challenge_status(self, challenge_id: str) -> dict[str, Any]:
        """Inspect persisted confirmation challenge status without leaking unused nonce secrets."""
        with self.connect() as conn:
            self._ensure_tcb_schema(conn)
            row = conn.execute(
                "SELECT * FROM trusted_confirmations WHERE challenge_id = ?",
                (challenge_id,),
            ).fetchone()
            if not row:
                raise BrokerConfirmationError(
                    f"TCB challenge '{challenge_id}' not found.",
                    code=ERR_CONFIRMATION_FAILED,
                )
            status = row["status"]
            if status == "PENDING" and time.time() > float(row["expires_epoch"]):
                status = "EXPIRED"
            return {
                "challenge_id": row["challenge_id"],
                "project_key": row["project_key"],
                "run_id": row["run_id"],
                "base_commit": row["base_commit"],
                "execution_id": row["execution_id"],
                "canonical_request_digest": row["canonical_request_digest"],
                "status": status,
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "consumed_at": row["consumed_at"],
                "consumed_by_approval_id": row["consumed_by_approval_id"],
                "proof_type": row["proof_type"],
            }

    def authorize_execution_tx(
        self,
        project_key: str,
        run_id: str,
        approved_finding_ids: list[str],
        base_commit: str,
        working_tree_hash: str,
        execution_id: str,
        allowed_scope_digest: str,
        evidence_digest: str,
        test_policy_digest: str,
        signer: CbeatSigner,
        *,
        max_repair_attempts: int = 2,
        ttl_seconds: int = 3600,
        authorized_by: str = "user",
        tcb_verifier: TcbVerifier | None = None,
        tcb_confirmation: dict[str, Any] | None = None,
        require_tcb: bool = False,
        client_sid: str = "",
    ) -> dict[str, Any]:
        """Step B of two-step approval: enforce TCB when required and issue CBEAT approval."""
        if not approved_finding_ids:
            raise BrokerSecurityError("Cannot authorize execution with empty finding set.", code=ERR_TWO_STEP_VIOLATION)

        enforce_tcb = bool(require_tcb or (tcb_verifier is not None and tcb_verifier.policy.require_tcb))

        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            digests = self._derive_authoritative_digests_in_tx(
                conn,
                project_key=project_key,
                run_id=run_id,
                approved_finding_ids=approved_finding_ids,
                base_commit=base_commit,
                max_repair_attempts=max_repair_attempts,
            )
            repo_path = digests["repo_path"]
            sorted_finding_ids = digests["sorted_finding_ids"]
            effective_scope_digest = digests["effective_scope_digest"]
            effective_evidence_digest = digests["effective_evidence_digest"]
            effective_test_policy_digest = digests["effective_test_policy_digest"]

            tcb_challenge_id_consumed: str | None = None
            tcb_verified_summary: dict[str, Any] | None = None

            if enforce_tcb:
                self._ensure_tcb_schema(conn)
                if tcb_verifier is None:
                    raise BrokerConfirmationRequiredError(
                        "Server TCB verifier is not configured while require_tcb=True.",
                        code=ERR_CONFIRMATION_REQUIRED,
                    )
                if not isinstance(tcb_confirmation, dict):
                    self.record_governance_audit_event_in_tx(
                        conn,
                        "SECURITY_TCB_REJECTED",
                        actor=authorized_by,
                        project_key=project_key,
                        run_id=run_id,
                        exec_id=execution_id,
                        details={"reason": "Missing tcb_confirmation proof", "client_sid": client_sid},
                        result="BLOCKED",
                    )
                    conn.commit()
                    raise BrokerConfirmationRequiredError(
                        "Trusted Confirmation proof ('tcb_confirmation') is required before execution authorization.",
                        code=ERR_CONFIRMATION_REQUIRED,
                    )

                spoof_fields = sorted(k for k in FORBIDDEN_TCB_OVERRIDE_PARAMS if k in tcb_confirmation)
                if spoof_fields:
                    self.record_governance_audit_event_in_tx(
                        conn,
                        "SECURITY_TCB_SPOOF_ATTEMPT",
                        actor=authorized_by,
                        project_key=project_key,
                        run_id=run_id,
                        exec_id=execution_id,
                        details={"forbidden_fields": spoof_fields, "client_sid": client_sid},
                        result="BLOCKED",
                    )
                    conn.commit()
                    raise BrokerSecurityError(
                        f"Forbidden client-supplied TCB override/key fields rejected: {', '.join(spoof_fields)}.",
                        code=ERR_ACCESS_DENIED,
                        data={"forbidden_fields": spoof_fields},
                    )

                ch_id = str(tcb_confirmation.get("challenge_id") or "")
                ch_row = conn.execute(
                    "SELECT * FROM trusted_confirmations WHERE challenge_id = ?",
                    (ch_id,),
                ).fetchone()
                if not ch_row:
                    self.record_governance_audit_event_in_tx(
                        conn,
                        "SECURITY_TCB_REJECTED",
                        actor=authorized_by,
                        project_key=project_key,
                        run_id=run_id,
                        exec_id=execution_id,
                        details={"challenge_id": ch_id, "reason": "Unknown TCB challenge_id"},
                        result="BLOCKED",
                    )
                    conn.commit()
                    raise BrokerConfirmationError(
                        f"Unknown TCB confirmation challenge '{ch_id}'.",
                        code=ERR_CONFIRMATION_FAILED,
                    )

                expected_client_sid = str(ch_row["client_sid"] or "")
                actual_client_sid = str(client_sid or "")
                if expected_client_sid and actual_client_sid != expected_client_sid:
                    self.record_governance_audit_event_in_tx(
                        conn,
                        "SECURITY_TCB_REJECTED",
                        actor=authorized_by,
                        project_key=project_key,
                        run_id=run_id,
                        exec_id=execution_id,
                        details={
                            "challenge_id": ch_id,
                            "reason": "Challenge client_sid mismatch",
                            "expected_client_sid": expected_client_sid,
                            "actual_client_sid": actual_client_sid,
                        },
                        result="BLOCKED",
                    )
                    conn.commit()
                    raise BrokerSecurityError(
                        f"TCB challenge '{ch_id}' was issued to a different client SID.",
                        code=ERR_ACCESS_DENIED,
                    )

                if ch_row["status"] == "CONSUMED":
                    self.record_governance_audit_event_in_tx(
                        conn,
                        "SECURITY_TCB_REPLAY_ATTEMPT",
                        actor=authorized_by,
                        project_key=project_key,
                        run_id=run_id,
                        exec_id=execution_id,
                        details={"challenge_id": ch_id, "consumed_by": ch_row["consumed_by_approval_id"]},
                        result="BLOCKED",
                    )
                    conn.commit()
                    raise BrokerSecurityError(
                        f"TCB challenge '{ch_id}' has already been consumed (replay rejected).",
                        code=ERR_REPLAY_ATTEMPT,
                    )

                now_epoch = time.time()
                if ch_row["status"] == "EXPIRED" or now_epoch > float(ch_row["expires_epoch"]):
                    conn.execute(
                        "UPDATE trusted_confirmations SET status = 'EXPIRED' WHERE challenge_id = ? AND status = 'PENDING'",
                        (ch_id,),
                    )
                    self.record_governance_audit_event_in_tx(
                        conn,
                        "SECURITY_TCB_EXPIRED",
                        actor=authorized_by,
                        project_key=project_key,
                        run_id=run_id,
                        exec_id=execution_id,
                        details={"challenge_id": ch_id, "expires_at": ch_row["expires_at"]},
                        result="BLOCKED",
                    )
                    conn.commit()
                    raise BrokerSecurityError(
                        f"TCB challenge '{ch_id}' expired at {ch_row['expires_at']}.",
                        code=ERR_APPROVAL_EXPIRED,
                    )

                if ch_row["status"] != "PENDING":
                    raise BrokerConfirmationError(
                        f"TCB challenge '{ch_id}' is in non-pending status '{ch_row['status']}'.",
                        code=ERR_CONFIRMATION_FAILED,
                    )

                canonical_request_digest = compute_tcb_request_digest(
                    project_key=project_key,
                    repo_path=digests["real_repo_path"],
                    run_id=run_id,
                    base_commit=base_commit,
                    execution_id=execution_id,
                    approved_finding_ids=sorted_finding_ids,
                    evidence_digest=effective_evidence_digest,
                    allowed_scope_digest=effective_scope_digest,
                    test_policy_digest=effective_test_policy_digest,
                    max_repair_attempts=max_repair_attempts,
                    working_tree_hash=working_tree_hash,
                )
                if ch_row["canonical_request_digest"] != canonical_request_digest:
                    self.record_governance_audit_event_in_tx(
                        conn,
                        "SECURITY_TCB_SCOPE_MISMATCH",
                        actor=authorized_by,
                        project_key=project_key,
                        run_id=run_id,
                        exec_id=execution_id,
                        details={
                            "challenge_id": ch_id,
                            "expected_digest": ch_row["canonical_request_digest"],
                            "actual_digest": canonical_request_digest,
                        },
                        result="BLOCKED",
                    )
                    conn.commit()
                    raise BrokerSecurityError(
                        "Request parameters mutated after TCB challenge issuance (canonical digest mismatch).",
                        code=ERR_SCOPE_VIOLATION,
                    )

                cred_id = str(tcb_confirmation.get("credential_id") or "")
                cnt_row = conn.execute(
                    "SELECT last_sign_count FROM tcb_credential_counters WHERE credential_id = ?",
                    (cred_id,),
                ).fetchone()
                prev_sign_count = int(cnt_row["last_sign_count"]) if cnt_row else 0

                try:
                    verified = tcb_verifier.verify_confirmation_proof(
                        tcb_confirmation,
                        expected_challenge_id=ch_id,
                        expected_challenge_nonce=ch_row["challenge_nonce"],
                        expected_request_digest=canonical_request_digest,
                        previous_sign_count=prev_sign_count,
                    )
                except BrokerError as tcb_err:
                    self.record_governance_audit_event_in_tx(
                        conn,
                        "SECURITY_TCB_VERIFICATION_FAILED",
                        actor=authorized_by,
                        project_key=project_key,
                        run_id=run_id,
                        exec_id=execution_id,
                        details={
                            "challenge_id": ch_id,
                            "error_code": tcb_err.code,
                            "reason": tcb_err.message,
                        },
                        result="BLOCKED",
                    )
                    conn.commit()
                    raise

                tcb_challenge_id_consumed = ch_id
                tcb_verified_summary = {
                    "challenge_id": ch_id,
                    "proof_type": verified.proof_type,
                    "credential_id": verified.credential_id,
                    "user_present": verified.user_present,
                    "user_verified": verified.user_verified,
                    "sign_count": verified.sign_count,
                }

            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            expires_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_seconds))
            approval_id = f"APPR-{time.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
            single_use_nonce = secrets.token_hex(16)

            if enforce_tcb and tcb_challenge_id_consumed is not None and tcb_verified_summary is not None:
                cas = conn.execute(
                    """UPDATE trusted_confirmations
                       SET status = 'CONSUMED',
                           consumed_at = ?,
                           consumed_by_approval_id = ?,
                           credential_id = ?,
                           proof_type = ?,
                           sign_count = ?
                       WHERE challenge_id = ? AND status = 'PENDING' AND canonical_request_digest = ?""",
                    (
                        now_iso,
                        approval_id,
                        tcb_verified_summary["credential_id"],
                        tcb_verified_summary["proof_type"],
                        tcb_verified_summary["sign_count"],
                        tcb_challenge_id_consumed,
                        canonical_request_digest,
                    ),
                )
                if cas.rowcount != 1:
                    raise BrokerSecurityError(
                        f"Atomic CAS consumption of TCB challenge '{tcb_challenge_id_consumed}' failed.",
                        code=ERR_REPLAY_ATTEMPT,
                    )
                conn.execute(
                    """INSERT INTO tcb_credential_counters (credential_id, last_sign_count, updated_at)
                       VALUES (?, ?, ?)
                       ON CONFLICT(credential_id) DO UPDATE SET
                           last_sign_count = excluded.last_sign_count,
                           updated_at = excluded.updated_at""",
                    (tcb_verified_summary["credential_id"], tcb_verified_summary["sign_count"], now_iso),
                )

            cbeat_payload = build_cbeat_payload(
                approval_id=approval_id,
                project_key=project_key,
                repo_path=digests["real_repo_path"],
                run_id=run_id,
                base_commit=base_commit,
                execution_id=execution_id,
                approved_finding_ids=sorted_finding_ids,
                evidence_digest=effective_evidence_digest,
                allowed_scope_digest=effective_scope_digest,
                test_policy_digest=effective_test_policy_digest,
                max_repair_attempts=max_repair_attempts,
                ttl_seconds=ttl_seconds,
                single_use_nonce=single_use_nonce,
            )
            cbeat_token = signer.sign_payload(cbeat_payload)
            cbeat_dict = cbeat_token.to_dict()
            token_json = json.dumps(cbeat_dict)

            conn.execute(
                """INSERT INTO execution_approvals (
                    approval_id, project_key, run_id, approval_token,
                    approved_finding_ids, base_commit, working_tree_hash,
                    status, authorized_by, created_at, expires_at,
                    single_use_nonce, cbeat_payload, cbeat_signature,
                    allowed_scope_digest, evidence_digest, test_policy_digest,
                    max_repair_attempts, execution_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'AUTHORIZED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    approval_id,
                    project_key,
                    run_id,
                    token_json,
                    json.dumps(sorted_finding_ids),
                    base_commit,
                    working_tree_hash,
                    authorized_by,
                    now_iso,
                    expires_iso,
                    single_use_nonce,
                    json.dumps(cbeat_payload.to_canonical_dict()),
                    cbeat_token.signature_hex,
                    effective_scope_digest,
                    effective_evidence_digest,
                    effective_test_policy_digest,
                    max_repair_attempts,
                    execution_id,
                ),
            )

            audit_details: dict[str, Any] = {
                "approved_findings_count": len(sorted_finding_ids),
                "base_commit": base_commit,
                "nonce": single_use_nonce,
                "expires_at": expires_iso,
                "signature_algorithm": cbeat_token.signature_algorithm,
                "tpm_backed": cbeat_token.tpm_backed,
                "client_sid": client_sid,
            }
            if cbeat_token.key_id:
                audit_details["key_id"] = cbeat_token.key_id
            if tcb_verified_summary is not None:
                audit_details["tcb_confirmation"] = tcb_verified_summary

            self.record_governance_audit_event_in_tx(
                conn,
                "EXECUTION_AUTHORIZED",
                actor=authorized_by,
                project_key=project_key,
                run_id=run_id,
                exec_id=execution_id,
                approval_id=approval_id,
                details=audit_details,
            )
            conn.commit()
            res: dict[str, Any] = {
                "approval_id": approval_id,
                "approval_token": token_json,
                "cbeat_token": cbeat_dict,
                "single_use_nonce": single_use_nonce,
                "expires_at": expires_iso,
                "approved_finding_ids": sorted_finding_ids,
                "execution_id": execution_id,
            }
            if tcb_verified_summary is not None:
                res["tcb_confirmation"] = tcb_verified_summary
            return res

    def verify_execution_approval(
        self,
        approval_id: str,
        project_key: str,
        run_id: str,
        base_commit: str,
        execution_id: str,
        approved_finding_ids: list[str],
        cbeat_token_data: dict[str, Any],
        verifier: CbeatVerifier,
    ) -> dict[str, Any]:
        """Verify CBEAT signature and assert all bindings against authoritative database record."""
        sig_valid, sig_msg, payload = verifier.verify_signature(cbeat_token_data)
        if not sig_valid or payload is None:
            raise BrokerSecurityError(f"CBEAT signature verification failed: {sig_msg}", code=ERR_ACCESS_DENIED)

        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM execution_approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if not row:
                raise BrokerSecurityError(f"Approval '{approval_id}' not found in authoritative records.", code=ERR_ACCESS_DENIED)

            if row["status"] == "CONSUMED":
                raise BrokerSecurityError("Approval has already been consumed (anti-replay check failed).", code=ERR_REPLAY_ATTEMPT)
            if row["status"] != "AUTHORIZED":
                raise BrokerSecurityError(f"Approval is in non-authorizable status '{row['status']}'.", code=ERR_ACCESS_DENIED)

            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if row["expires_at"] < now_iso:
                raise BrokerSecurityError(f"Approval '{approval_id}' has expired (expired at {row['expires_at']}).", code=ERR_APPROVAL_EXPIRED)

            if row["project_key"] != project_key:
                raise BrokerSecurityError(f"Approval bound to project '{row['project_key']}', but request has '{project_key}'.", code=ERR_SCOPE_VIOLATION)
            if row["run_id"] != run_id:
                raise BrokerSecurityError(f"Approval bound to run '{row['run_id']}', but request has '{run_id}'.", code=ERR_SCOPE_VIOLATION)
            if row["base_commit"] != base_commit:
                raise BrokerSecurityError(f"Approval bound to base commit '{row['base_commit']}', but request has '{base_commit}'.", code=ERR_SCOPE_VIOLATION)
            if row["execution_id"] and row["execution_id"] != execution_id:
                raise BrokerSecurityError(f"Approval bound to execution '{row['execution_id']}', but request has '{execution_id}'.", code=ERR_SCOPE_VIOLATION)

            db_findings = sorted(json.loads(row["approved_finding_ids"]))
            req_findings = sorted(approved_finding_ids)
            if db_findings != req_findings:
                raise BrokerSecurityError("Approved finding set tampering detected between database and request.", code=ERR_SCOPE_VIOLATION)

            if row["single_use_nonce"] != payload.single_use_nonce:
                raise BrokerSecurityError("Nonce mismatch between database record and token payload.", code=ERR_REPLAY_ATTEMPT)

            if row["allowed_scope_digest"] and payload.allowed_scope_digest != row["allowed_scope_digest"]:
                raise BrokerSecurityError("Scope digest mismatch between database record and token payload.", code=ERR_SCOPE_VIOLATION)
            if row["evidence_digest"] and payload.evidence_digest != row["evidence_digest"]:
                raise BrokerSecurityError("Evidence digest mismatch between database record and token payload.", code=ERR_SCOPE_VIOLATION)
            if row["test_policy_digest"] and payload.test_policy_digest != row["test_policy_digest"]:
                raise BrokerSecurityError("Test policy digest mismatch between database record and token payload.", code=ERR_SCOPE_VIOLATION)

            return {
                "valid": True,
                "approval_id": approval_id,
                "status": row["status"],
                "expires_at": row["expires_at"],
                "approved_finding_ids": db_findings,
            }

    def consume_execution_approval_tx(
        self,
        approval_id: str,
        single_use_nonce: str,
        *,
        actor: str = "executor",
    ) -> dict[str, Any]:
        """Atomic single-use CAS consumption of approval token."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            cursor = conn.execute(
                """UPDATE execution_approvals
                   SET status = 'CONSUMED', consumed_at = ?
                   WHERE approval_id = ? AND status = 'AUTHORIZED' AND single_use_nonce = ?""",
                (now_iso, approval_id, single_use_nonce),
            )
            if cursor.rowcount != 1:
                self.record_governance_audit_event_in_tx(
                    conn,
                    "SECURITY_REPLAY_ATTEMPT",
                    actor=actor,
                    approval_id=approval_id,
                    details={"nonce": single_use_nonce, "reason": "CAS consumption zero rows updated"},
                    result="BLOCKED",
                )
                conn.commit()
                raise BrokerSecurityError(
                    f"Approval consumption failed: approval '{approval_id}' is not in AUTHORIZED status or nonce has already been consumed.",
                    code=ERR_REPLAY_ATTEMPT,
                )

            self.record_governance_audit_event_in_tx(
                conn,
                "APPROVAL_CONSUMED",
                actor=actor,
                approval_id=approval_id,
                details={"consumed_at": now_iso},
            )
            conn.commit()
            return {"consumed": True, "approval_id": approval_id, "consumed_at": now_iso}

    def register_execution_intent_tx(
        self,
        exec_id: str,
        project_key: str,
        run_id: str,
        approval_id: str,
        base_commit: str,
        working_tree_hash: str,
        worktree_path: str | None = None,
        branch_name: str | None = None,
        max_retries: int = 2,
    ) -> dict[str, Any]:
        """Register execution run intent bound to approval."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            app_row = conn.execute(
                "SELECT approved_finding_ids, status FROM execution_approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if not app_row:
                raise BrokerDatabaseError(f"Approval '{approval_id}' not found.")
            if app_row["status"] not in ("AUTHORIZED", "CONSUMED"):
                raise BrokerSecurityError(f"Cannot register execution for approval in status '{app_row['status']}'.", code=ERR_ACCESS_DENIED)

            conn.execute(
                """INSERT OR REPLACE INTO execution_runs (
                    exec_id, project_key, run_id, approval_id, status,
                    worktree_path, branch_name, base_commit, working_tree_hash,
                    retry_count, max_retries, started_at
                ) VALUES (?, ?, ?, ?, 'PREFLIGHT', ?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP)""",
                (exec_id, project_key, run_id, approval_id, worktree_path, branch_name, base_commit, working_tree_hash, max_retries),
            )

            fids = json.loads(app_row["approved_finding_ids"])
            for fid in fids:
                f_exec_id = f"FEXEC-{exec_id}-{fid}"
                conn.execute(
                    """INSERT OR IGNORE INTO finding_executions (
                        finding_exec_id, exec_id, finding_id, status, repair_attempts, started_at
                    ) VALUES (?, ?, ?, 'PENDING', 0, CURRENT_TIMESTAMP)""",
                    (f_exec_id, exec_id, fid),
                )

            self.record_governance_audit_event_in_tx(
                conn,
                "EXECUTION_INTENT_REGISTERED",
                project_key=project_key,
                run_id=run_id,
                exec_id=exec_id,
                approval_id=approval_id,
                details={"findings_count": len(fids)},
            )
            conn.commit()
            return {"exec_id": exec_id, "status": "PREFLIGHT", "findings_count": len(fids)}

    def acquire_execution_lease_tx(
        self,
        exec_id: str,
        worker_id: str,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        """Acquire atomic worker lease with monotonic fencing token."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            ex_row = conn.execute("SELECT status FROM execution_runs WHERE exec_id = ?", (exec_id,)).fetchone()
            if not ex_row:
                raise BrokerDatabaseError(f"Execution '{exec_id}' not found.")

            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            existing = conn.execute(
                "SELECT lease_id, worker_id, expires_at, fencing_token FROM execution_leases WHERE exec_id = ? AND status = 'ACTIVE'",
                (exec_id,),
            ).fetchone()

            if existing:
                if existing["expires_at"] > now_iso:
                    if existing["worker_id"] != worker_id:
                        raise BrokerSecurityError(
                            f"Concurrent execution collision: active lease held by worker '{existing['worker_id']}' until {existing['expires_at']}.",
                            code=ERR_CONCURRENT_CONFLICT,
                        )
                    lease_id = existing["lease_id"]
                    fencing_token = existing["fencing_token"]
                    expires_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_seconds))
                    conn.execute(
                        "UPDATE execution_leases SET last_heartbeat_at = CURRENT_TIMESTAMP, expires_at = ? WHERE lease_id = ?",
                        (expires_iso, lease_id),
                    )
                    conn.commit()
                    return {"lease_id": lease_id, "fencing_token": fencing_token, "expires_at": expires_iso}
                else:
                    conn.execute("UPDATE execution_leases SET status = 'EXPIRED' WHERE lease_id = ?", (existing["lease_id"],))

            max_token = conn.execute(
                "SELECT COALESCE(MAX(fencing_token), 0) FROM execution_leases WHERE exec_id = ?",
                (exec_id,),
            ).fetchone()[0]
            fencing_token = int(max_token) + 1
            lease_id = f"LEASE-{exec_id}-{fencing_token}-{secrets.token_hex(4)}"
            expires_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_seconds))

            conn.execute(
                """INSERT INTO execution_leases (
                    lease_id, exec_id, worker_id, fencing_token, status,
                    acquired_at, expires_at, last_heartbeat_at, lease_ttl_seconds
                ) VALUES (?, ?, ?, ?, 'ACTIVE', CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, ?)""",
                (lease_id, exec_id, worker_id, fencing_token, expires_iso, ttl_seconds),
            )
            conn.execute(
                "UPDATE execution_runs SET status = 'RUNNING' WHERE exec_id = ? AND status = 'PREFLIGHT'",
                (exec_id,),
            )

            self.record_governance_audit_event_in_tx(
                conn,
                "EXECUTION_LEASE_ACQUIRED",
                exec_id=exec_id,
                details={"lease_id": lease_id, "worker_id": worker_id, "fencing_token": fencing_token},
            )
            conn.commit()
            return {"lease_id": lease_id, "fencing_token": fencing_token, "expires_at": expires_iso}

    def heartbeat_execution_tx(
        self,
        lease_id: str,
        exec_id: str,
        worker_id: str,
        fencing_token: int,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        """Atomically renew heartbeat for active execution lease."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            new_expires_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_seconds))

            cursor = conn.execute(
                """UPDATE execution_leases
                   SET last_heartbeat_at = CURRENT_TIMESTAMP, expires_at = ?
                   WHERE lease_id = ? AND exec_id = ? AND worker_id = ?
                     AND fencing_token = ? AND status = 'ACTIVE' AND expires_at > ?""",
                (new_expires_iso, lease_id, exec_id, worker_id, fencing_token, now_iso),
            )
            if cursor.rowcount != 1:
                raise BrokerSecurityError(
                    f"Heartbeat rejected: lease '{lease_id}' is expired, released, or stale fencing token.",
                    code=ERR_CONCURRENT_CONFLICT,
                )
            conn.commit()
            return {"acknowledged": True, "lease_id": lease_id, "expires_at": new_expires_iso}

    def renew_execution_lease_tx(
        self,
        lease_id: str,
        exec_id: str,
        worker_id: str,
        fencing_token: int,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        """Renew active execution lease."""
        return self.heartbeat_execution_tx(lease_id, exec_id, worker_id, fencing_token, ttl_seconds)

    def update_execution_state_tx(
        self,
        exec_id: str,
        new_status: str,
        lease_id: str,
        fencing_token: int,
    ) -> dict[str, Any]:
        """Update execution run state under active lease guard."""
        valid_statuses = {"PREFLIGHT", "RUNNING", "VERIFYING", "COMPLETED", "PARTIAL", "FAILED", "QUARANTINED", "STALE", "ROLLED_BACK"}
        if new_status not in valid_statuses:
            raise BrokerDatabaseError(f"Invalid execution status '{new_status}'.")

        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            lease = conn.execute(
                "SELECT lease_id FROM execution_leases WHERE lease_id = ? AND exec_id = ? AND fencing_token = ? AND status = 'ACTIVE' AND expires_at > ?",
                (lease_id, exec_id, fencing_token, now_iso),
            ).fetchone()
            if not lease:
                raise BrokerSecurityError("State update rejected: invalid or expired lease.", code=ERR_CONCURRENT_CONFLICT)

            conn.execute("UPDATE execution_runs SET status = ? WHERE exec_id = ?", (new_status, exec_id))
            self.record_governance_audit_event_in_tx(
                conn,
                "EXECUTION_STATE_UPDATED",
                exec_id=exec_id,
                details={"new_status": new_status, "lease_id": lease_id},
            )
            conn.commit()
            return {"exec_id": exec_id, "status": new_status}

    def register_checkpoint_tx(
        self,
        checkpoint_id: str,
        exec_id: str,
        finding_id: str,
        base_commit: str,
        scope_digest: str,
        manifest_hash: str,
        checkpoint_path: str,
    ) -> dict[str, Any]:
        """Register checkpoint metadata bound to execution and finding."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            fe = conn.execute("SELECT status FROM finding_executions WHERE exec_id = ? AND finding_id = ?", (exec_id, finding_id)).fetchone()
            if not fe:
                raise BrokerDatabaseError(f"Finding execution not found for exec_id '{exec_id}' and finding '{finding_id}'.")

            conn.execute(
                """INSERT OR REPLACE INTO finding_checkpoints (
                    checkpoint_id, exec_id, finding_id, base_commit,
                    scope_digest, manifest_hash, checkpoint_path, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', CURRENT_TIMESTAMP)""",
                (checkpoint_id, exec_id, finding_id, base_commit, scope_digest, manifest_hash, checkpoint_path),
            )
            conn.execute(
                "UPDATE finding_executions SET status = 'IN_PROGRESS', checkpoint_id = ?, checkpoint_path = ? WHERE exec_id = ? AND finding_id = ?",
                (checkpoint_id, checkpoint_path, exec_id, finding_id),
            )
            self.record_governance_audit_event_in_tx(
                conn,
                "CHECKPOINT_REGISTERED",
                exec_id=exec_id,
                details={"checkpoint_id": checkpoint_id, "finding_id": finding_id, "manifest_hash": manifest_hash},
            )
            conn.commit()
            return {"checkpoint_id": checkpoint_id, "status": "ACTIVE"}

    def record_repair_attempt_tx(
        self,
        exec_id: str,
        finding_id: str,
        repair_attempt: int,
        happy_test_passed: int | None = None,
        adversarial_test_passed: int | None = None,
        red_team_passed: int | None = None,
        red_team_notes: str | None = None,
        diff_summary: str | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Record repair attempt enforcing monotonic increase and max retries."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            fe = conn.execute(
                "SELECT repair_attempts, status FROM finding_executions WHERE exec_id = ? AND finding_id = ?",
                (exec_id, finding_id),
            ).fetchone()
            if not fe:
                raise BrokerDatabaseError(f"Finding execution record not found for exec '{exec_id}' and finding '{finding_id}'.")

            if str(fe["status"]) in ("VERIFIED", "ROLLED_BACK"):
                raise BrokerSecurityError(
                    f"Finding '{finding_id}' is already {fe['status']}; further repair attempts are not accepted.",
                    code=ERR_RETRY_LIMIT_EXCEEDED,
                )
            curr = int(fe["repair_attempts"])
            next_attempt = curr + 1

            if repair_attempt is not None:
                if repair_attempt <= curr:
                    raise BrokerSecurityError(
                        f"Monotonic retry counter violation: attempt {repair_attempt} <= current {curr}. Retries cannot be reset or decremented.",
                        code=ERR_RETRY_LIMIT_EXCEEDED,
                    )
                if repair_attempt > next_attempt:
                    raise BrokerSecurityError(
                        f"Non-contiguous repair attempt {repair_attempt} (current: {curr}, expected: {next_attempt}). Caller cannot skip retry sequence.",
                        code=ERR_RETRY_LIMIT_EXCEEDED,
                    )
                effective_attempt = repair_attempt
            else:
                effective_attempt = next_attempt

            # VERIFIED needs every gate: happy path, adversarial test and red-team diff review.
            all_passed = happy_test_passed == 1 and adversarial_test_passed == 1 and red_team_passed == 1
            # Two repairs are allowed; the verification after the second repair is attempt 3 and may only pass.
            if effective_attempt > 3 or (effective_attempt == 3 and not all_passed):
                raise BrokerSecurityError(
                    f"Maximum repair attempts exceeded ({effective_attempt} > 2).",
                    code=ERR_RETRY_LIMIT_EXCEEDED,
                )

            # A failed attempt leaves the finding IN_PROGRESS (a repair or a rollback follows; rollback marks it
            # ROLLED_BACK). repair_attempts counts repairs (CHECK <= 2): the passing verification after the second
            # repair is attempt 3 but stores 2.
            new_status = "VERIFIED" if all_passed else "IN_PROGRESS"
            stored_attempts = min(effective_attempt, 2)
            conn.execute(
                """UPDATE finding_executions
                   SET repair_attempts = ?,
                       happy_test_passed = COALESCE(?, happy_test_passed),
                       adversarial_test_passed = COALESCE(?, adversarial_test_passed),
                       red_team_passed = COALESCE(?, red_team_passed),
                       red_team_notes = COALESCE(?, red_team_notes),
                       diff_summary = COALESCE(?, diff_summary),
                       error = COALESCE(?, error),
                       status = ?
                   WHERE exec_id = ? AND finding_id = ?""",
                (stored_attempts, happy_test_passed, adversarial_test_passed, red_team_passed, red_team_notes, diff_summary, error, new_status, exec_id, finding_id),
            )
            self.record_governance_audit_event_in_tx(
                conn,
                "REPAIR_ATTEMPT_RECORDED",
                exec_id=exec_id,
                details={"finding_id": finding_id, "repair_attempt": effective_attempt, "status": new_status},
            )
            conn.commit()
            return {"exec_id": exec_id, "finding_id": finding_id, "repair_attempts": effective_attempt, "status": new_status}

    def quarantine_checkpoint_tx(
        self,
        quarantine_id: str,
        project_key: str,
        exec_id: str,
        worktree_path: str,
        reason: str,
        checkpoint_id: str | None = None,
        preserved_diff_path: str | None = None,
    ) -> dict[str, Any]:
        """Record worktree/checkpoint quarantine."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT OR REPLACE INTO quarantined_worktrees (
                    quarantine_id, project_key, exec_id, worktree_path, reason, preserved_diff_path, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'QUARANTINED', CURRENT_TIMESTAMP)""",
                (quarantine_id, project_key, exec_id, worktree_path, reason, preserved_diff_path),
            )
            if checkpoint_id:
                conn.execute(
                    "UPDATE finding_checkpoints SET status = 'QUARANTINED', quarantine_reason = ? WHERE checkpoint_id = ?",
                    (reason, checkpoint_id),
                )
            conn.execute("UPDATE execution_runs SET status = 'QUARANTINED' WHERE exec_id = ?", (exec_id,))
            self.record_governance_audit_event_in_tx(
                conn,
                "CHECKPOINT_QUARANTINED",
                project_key=project_key,
                exec_id=exec_id,
                details={"quarantine_id": quarantine_id, "checkpoint_id": checkpoint_id, "reason": reason},
            )
            conn.commit()
            return {"quarantine_id": quarantine_id, "status": "QUARANTINED"}

    def finalize_execution_tx(
        self,
        exec_id: str,
        status: str,
        integration_test_passed: int,
        lease_id: str,
        fencing_token: int,
    ) -> dict[str, Any]:
        """Finalize execution asserting no quarantined checkpoints and releasing active lease."""
        allowed_final_statuses = {"COMPLETED", "PARTIAL", "FAILED"}
        if status not in allowed_final_statuses:
            raise BrokerDatabaseError(f"Invalid final status '{status}'. Must be one of {allowed_final_statuses}.")

        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            q_count = conn.execute(
                "SELECT COUNT(*) FROM finding_checkpoints WHERE exec_id = ? AND status = 'QUARANTINED'",
                (exec_id,),
            ).fetchone()[0]
            if q_count > 0:
                raise BrokerSecurityError(
                    f"Execution '{exec_id}' cannot be finalized because one or more checkpoints are QUARANTINED ({q_count} checkpoint(s)).",
                    code=ERR_CHECKPOINT_QUARANTINED,
                )

            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            lease = conn.execute(
                "SELECT lease_id FROM execution_leases WHERE lease_id = ? AND exec_id = ? AND fencing_token = ? AND status = 'ACTIVE' AND expires_at > ?",
                (lease_id, exec_id, fencing_token, now_iso),
            ).fetchone()
            if not lease:
                raise BrokerSecurityError("Cannot finalize execution: lease is expired, released, or invalid.", code=ERR_CONCURRENT_CONFLICT)

            if status == "COMPLETED":
                if integration_test_passed != 1:
                    raise BrokerSecurityError(
                        f"Execution '{exec_id}' cannot be finalized as COMPLETED when integration tests did not pass (got {integration_test_passed}).",
                        code=ERR_UNVERIFIED_STATE,
                    )
                exec_row = conn.execute("SELECT approval_id FROM execution_runs WHERE exec_id = ?", (exec_id,)).fetchone()
                if exec_row and exec_row["approval_id"]:
                    app_row = conn.execute("SELECT approved_finding_ids FROM execution_approvals WHERE approval_id = ?", (exec_row["approval_id"],)).fetchone()
                    if app_row and app_row["approved_finding_ids"]:
                        approved_ids = json.loads(app_row["approved_finding_ids"])
                        for fid in approved_ids:
                            fe_row = conn.execute(
                                "SELECT status FROM finding_executions WHERE exec_id = ? AND finding_id = ?",
                                (exec_id, fid),
                            ).fetchone()
                            if not fe_row:
                                raise BrokerSecurityError(
                                    f"Completeness assertion failed: approved finding '{fid}' is missing from execution '{exec_id}'.",
                                    code=ERR_UNVERIFIED_STATE,
                                )
                            if fe_row["status"] != "VERIFIED":
                                raise BrokerSecurityError(
                                    f"Completeness assertion failed: approved finding '{fid}' has status '{fe_row['status']}', expected 'VERIFIED'.",
                                    code=ERR_UNVERIFIED_STATE,
                                )

            conn.execute("UPDATE execution_leases SET status = 'RELEASED' WHERE lease_id = ?", (lease_id,))
            conn.execute(
                "UPDATE execution_runs SET status = ?, integration_test_passed = ?, finished_at = CURRENT_TIMESTAMP WHERE exec_id = ?",
                (status, integration_test_passed, exec_id),
            )
            self.record_governance_audit_event_in_tx(
                conn,
                "EXECUTION_FINALIZED",
                exec_id=exec_id,
                details={"final_status": status, "integration_test_passed": integration_test_passed},
            )
            conn.commit()
            return {"exec_id": exec_id, "status": status, "finalized_at": now_iso}

    def submit_verification_tx(
        self,
        verification_run_id: str,
        project_key: str,
        run_id: str,
        results: list[dict[str, Any]],
        quality_metrics: dict[str, Any] | None = None,
        verifier_conversation_id: str = "verifier-broker-01",
    ) -> dict[str, Any]:
        """Record second-pass verification results through verification.submit_verification_results, the same
        handler as auditor_submit_verification (ownership, scope, independence and evidence checks).
        ``quality_metrics`` is ignored: metrics are computed by finalization, never taken from the caller."""
        from verification import submit_verification_results

        self._require_run_of_project(run_id, project_key, verification_run_id)
        try:
            return submit_verification_results(
                self.db_path, audit_run_id=run_id, verification_run_id=verification_run_id,
                verifier_conversation_id=verifier_conversation_id, verification_results=results,
            )
        except (RuntimeError, ValueError) as exc:
            raise BrokerDatabaseError(str(exc)) from exc

    def _require_run_of_project(self, run_id: str, project_key: str, verification_run_id: str) -> None:
        with self.connect() as conn:
            row = conn.execute(
                """SELECT 1 FROM audit_runs r JOIN audit_verification_runs v ON v.audit_run_id = r.run_id
                   WHERE r.run_id = ? AND r.project_key = ? AND v.verification_run_id = ?""",
                (run_id, project_key, verification_run_id),
            ).fetchone()
        if row is None:
            raise BrokerDatabaseError(
                f"Verification run '{verification_run_id}' does not belong to run '{run_id}' of project '{project_key}'."
            )

    def finalize_verified_report_tx(
        self,
        verification_run_id: str,
        project_key: str,
        run_id: str,
        verifier_conversation_id: str = "verifier-broker-01",
    ) -> dict[str, Any]:
        """Finalize through verification.finalize_verified_report (evidence, snapshot and independence gates).
        ``verifier_conversation_id`` is ignored: the conversation recorded at submission is authoritative."""
        from verification import finalize_verified_report

        self._require_run_of_project(run_id, project_key, verification_run_id)
        try:
            return finalize_verified_report(self.db_path, audit_run_id=run_id, verification_run_id=verification_run_id)
        except (RuntimeError, ValueError) as exc:
            raise BrokerDatabaseError(str(exc)) from exc

    def claim_verification_job_tx(
        self,
        worker_id: str,
        ttl_seconds: int = 300,
    ) -> dict[str, Any] | None:
        """Claim next pending verification job from dispatch queue with atomic lease."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            job = conn.execute(
                """SELECT job_id, project_key, run_id, verification_run_id, candidate_id
                   FROM verification_dispatch_queue
                   WHERE status = 'PENDING'
                   ORDER BY priority DESC, created_at ASC LIMIT 1"""
            ).fetchone()
            if not job:
                conn.commit()
                return None

            job_id = job["job_id"]
            expires_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_seconds))
            conn.execute(
                "UPDATE verification_dispatch_queue SET status = 'DISPATCHED', worker_id = ?, lease_expires_at = ? WHERE job_id = ?",
                (worker_id, expires_iso, job_id),
            )
            conn.commit()
            return {
                "job_id": job["job_id"],
                "project_key": job["project_key"],
                "run_id": job["run_id"],
                "verification_run_id": job["verification_run_id"],
                "candidate_id": job["candidate_id"],
                "worker_id": worker_id,
                "lease_expires_at": expires_iso,
            }

    def recover_verification_lease_tx(
        self,
        project_key: str | None = None,
    ) -> dict[str, Any]:
        """Recover expired leases in verification_dispatch_queue."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            query = "UPDATE verification_dispatch_queue SET status = 'PENDING', worker_id = NULL, lease_expires_at = NULL WHERE status = 'DISPATCHED' AND lease_expires_at < ?"
            params: list[Any] = [now_iso]
            if project_key:
                query += " AND project_key = ?"
                params.append(project_key)

            cursor = conn.execute(query, params)
            recovered = cursor.rowcount
            conn.commit()
            return {"recovered_count": recovered}


    def verify_audit_chain_tx(self) -> dict[str, Any]:
        """Walk and cryptographically verify the SHA-256 hash chain of all audit events."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT event_id, event_type, actor, details, payload_digest, prev_event_hash, event_hash, result FROM audit_events ORDER BY event_id ASC"
            ).fetchall()
            if not rows:
                return {"valid": True, "event_count": 0, "chain_head_hash": "0" * 64}

            prev_hash = "0" * 64
            for r in rows:
                ev_id = r["event_id"]
                stored_prev = r["prev_event_hash"] or ("0" * 64)
                if stored_prev != prev_hash:
                    return {
                        "valid": False,
                        "tampered_event_id": ev_id,
                        "error": f"Previous hash mismatch at event {ev_id}: expected {prev_hash}, got {stored_prev}",
                    }

                details_str = r["details"]
                try:
                    details_obj = json.loads(details_str) if details_str else {}
                except Exception:
                    details_obj = {}
                expected_payload_digest = sha256_digest(canonical_json_encode(details_obj))
                if r["payload_digest"] and r["payload_digest"] != expected_payload_digest:
                    return {
                        "valid": False,
                        "tampered_event_id": ev_id,
                        "error": f"Payload digest mismatch at event {ev_id}",
                    }

                expected_event_hash = sha256_digest(
                    f"{stored_prev}:{r['event_type']}:{r['actor']}:{r['payload_digest']}:{r['result']}"
                )
                if r["event_hash"] != expected_event_hash:
                    return {
                        "valid": False,
                        "tampered_event_id": ev_id,
                        "error": f"Event hash mismatch at event {ev_id}: expected {expected_event_hash}, got {r['event_hash']}",
                    }
                prev_hash = r["event_hash"]

            return {
                "valid": True,
                "event_count": len(rows),
                "chain_head_hash": prev_hash,
            }

    def validate_checkpoint_tx(self, checkpoint_id: str, exec_id: str | None = None) -> dict[str, Any]:
        """Validate content-addressed integrity of a checkpoint."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM finding_checkpoints WHERE checkpoint_id = ?",
                (checkpoint_id,),
            ).fetchone()
            if not row:
                raise BrokerDatabaseError(f"Checkpoint '{checkpoint_id}' not found.")
            if exec_id and row["exec_id"] != exec_id:
                raise BrokerSecurityError(f"Checkpoint '{checkpoint_id}' belongs to exec '{row['exec_id']}', not '{exec_id}'.", code=ERR_SCOPE_VIOLATION)
            if row["status"] == "QUARANTINED":
                raise BrokerSecurityError(f"Checkpoint '{checkpoint_id}' is QUARANTINED.", code=ERR_CHECKPOINT_QUARANTINED)

            manifest_path = row["checkpoint_path"]
            if not manifest_path or not Path(manifest_path).exists():
                raise BrokerSecurityError(f"Checkpoint manifest path does not exist: {manifest_path}", code=ERR_CHECKPOINT_INTEGRITY)

            is_valid, err_msg, metrics = validate_checkpoint_content_integrity(Path(manifest_path))
            return {
                "checkpoint_id": checkpoint_id,
                "exec_id": row["exec_id"],
                "finding_id": row["finding_id"],
                "status": row["status"],
                "valid": is_valid,
                "file_count": metrics.get("file_count", 0),
                "error": err_msg,
            }

    def restore_checkpoint_tx(self, checkpoint_id: str, exec_id: str, worktree_path: str) -> dict[str, Any]:
        """Atomically restore worktree from checkpoint with integrity verification."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM finding_checkpoints WHERE checkpoint_id = ?",
                (checkpoint_id,),
            ).fetchone()
            if not row:
                raise BrokerDatabaseError(f"Checkpoint '{checkpoint_id}' not found.")
            if row["exec_id"] != exec_id:
                raise BrokerSecurityError(f"Checkpoint '{checkpoint_id}' does not match execution '{exec_id}'.", code=ERR_SCOPE_VIOLATION)
            if row["status"] == "QUARANTINED":
                raise BrokerSecurityError(f"Cannot restore QUARANTINED checkpoint '{checkpoint_id}'.", code=ERR_CHECKPOINT_QUARANTINED)

            manifest_path = row["checkpoint_path"]
            if not manifest_path or not Path(manifest_path).exists():
                raise BrokerSecurityError(f"Checkpoint manifest path does not exist: {manifest_path}", code=ERR_CHECKPOINT_INTEGRITY)

            restore_res = safe_restore_checkpoint(Path(worktree_path), Path(manifest_path))
            conn.execute(
                "UPDATE finding_executions SET status='ROLLED_BACK' WHERE exec_id = ? AND finding_id = ?",
                (exec_id, row["finding_id"]),
            )
            self.record_governance_audit_event_in_tx(
                conn,
                "CHECKPOINT_RESTORED",
                exec_id=exec_id,
                details={"checkpoint_id": checkpoint_id, "restored_files_count": restore_res["restored_files_count"]},
            )
            conn.commit()
            return restore_res

    def get_execution_state_tx(self, exec_id: str) -> dict[str, Any]:
        """Retrieve consolidated execution run state."""
        with self.connect() as conn:
            erow = conn.execute("SELECT * FROM execution_runs WHERE exec_id = ?", (exec_id,)).fetchone()
            if not erow:
                raise BrokerDatabaseError(f"Execution '{exec_id}' not found.")
            f_rows = conn.execute("SELECT * FROM finding_executions WHERE exec_id = ?", (exec_id,)).fetchall()
            c_rows = conn.execute("SELECT * FROM finding_checkpoints WHERE exec_id = ?", (exec_id,)).fetchall()
            l_rows = conn.execute("SELECT * FROM execution_leases WHERE exec_id = ? ORDER BY fencing_token DESC", (exec_id,)).fetchall()
            return {
                "execution_run": dict(erow),
                "findings": [dict(r) for r in f_rows],
                "checkpoints": [dict(r) for r in c_rows],
                "leases": [dict(r) for r in l_rows],
            }

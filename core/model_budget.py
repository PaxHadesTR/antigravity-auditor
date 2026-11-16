"""Antigravity Auditor — Argon Quota and Context Management.

Guards limited Gemini 4 Argon quota via:
- Strict concurrency limits (default 1 concurrent Argon job).
- Per-audit-run request and token limits (default 5 requests, 100,000 tokens).
- Optional daily token budget limits.
- Context minimization: packages only necessary excerpts, lines, symbols, and findings;
  never sends full repository or full conversation transcripts.
- Per-finding request deduplication: identical finding fingerprint and task type cannot
  silently consume duplicate Argon quota without explicit operator authorization.
- Persistent token and request accounting across multiple OS processes via SQLite atomic transactions.
- Reconciles and expires stale reservations across crashes.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


# Operator-defined local safety limits (distinct from provider account quotas)
DEFAULT_MAX_CONCURRENT_ARGON_JOBS = 1
DEFAULT_MAX_ARGON_REQUESTS_PER_RUN = 5
DEFAULT_MAX_ARGON_TOKENS_PER_RUN = 100_000
DEFAULT_MAX_ARGON_CONTEXT_BYTES = 64_000


@dataclass
class ArgonBudgetConfig:
    """Configurable quotas for Argon models."""

    max_concurrent_jobs: int = DEFAULT_MAX_CONCURRENT_ARGON_JOBS
    max_requests_per_run: int = DEFAULT_MAX_ARGON_REQUESTS_PER_RUN
    max_tokens_per_run: int = DEFAULT_MAX_ARGON_TOKENS_PER_RUN
    daily_token_budget: int | None = None
    max_context_bytes: int = DEFAULT_MAX_ARGON_CONTEXT_BYTES


@dataclass(frozen=True)
class BudgetCheckResult:
    """Outcome of pre-dispatch budget evaluation."""

    allowed: bool
    status: str  # ALLOWED | REJECTED_CONCURRENCY | REJECTED_REQUEST_LIMIT | REJECTED_TOKEN_LIMIT | REJECTED_DUPLICATE
    reason: str
    current_requests: int = 0
    current_tokens: int = 0
    current_concurrent: int = 0
    reservation_id: str | None = None

    @property
    def is_quota_exhausted(self) -> bool:
        return self.status in (
            "REJECTED_REQUEST_LIMIT",
            "REJECTED_TOKEN_LIMIT",
            "REJECTED_CONCURRENCY",
        )


@dataclass(frozen=True)
class MinimizedEvidencePackage:
    """Strictly minimized context for Argon verification."""

    finding_fingerprint: str
    title: str
    category: str
    severity: str
    file_path: str | None
    line_range: tuple[int | None, int | None]
    symbol: str | None
    source_excerpt: str
    reproduction_steps: str
    expected_behavior: str
    actual_behavior: str
    primary_reasoning: str
    evidence_gate_outcome: str
    raw_size_bytes: int
    content_hash: str

    def to_prompt_text(self) -> str:
        lines = [
            f"# CRITICAL VERIFICATION EVIDENCE PACKAGE",
            f"Finding Fingerprint: {self.finding_fingerprint}",
            f"Title: {self.title}",
            f"Category: {self.category}",
            f"Severity: {self.severity}",
            f"Target File: {self.file_path or 'N/A'}",
            f"Line Range: {self.line_range[0] or 0}-{self.line_range[1] or 0}",
            f"Symbol: {self.symbol or 'N/A'}",
            f"Evidence Gate Outcome: {self.evidence_gate_outcome}",
            "",
            "## Source Excerpt",
            "```",
            self.source_excerpt.strip(),
            "```",
            "",
            "## Primary Auditor Finding & Reasoning",
            self.primary_reasoning.strip(),
            "",
            "## Reproduction Steps",
            self.reproduction_steps.strip(),
            "",
            "## Expected vs Actual Behavior",
            f"Expected: {self.expected_behavior.strip()}",
            f"Actual: {self.actual_behavior.strip()}",
            "",
            "Instructions for Verifier:",
            "Assess this finding independently based on the verified evidence excerpt.",
            "Do not perform unnecessary tool scans or full repository reads.",
        ]
        return "\n".join(lines)


def build_minimized_evidence_package(
    *,
    finding: Mapping[str, Any],
    evidence_gate_status: str = "PASSED",
    max_bytes: int = DEFAULT_MAX_ARGON_CONTEXT_BYTES,
) -> MinimizedEvidencePackage:
    """Build a strictly minimized context package for Argon dispatch.

    Never includes secrets, full repositories, or prior conversation transcripts.
    """
    fingerprint = str(finding.get("fingerprint") or finding.get("finding_id") or "unknown")
    title = str(finding.get("title") or "Untitled finding")
    category = str(finding.get("category") or "GENERAL")
    severity = str(finding.get("severity") or "HIGH")
    file_path = str(finding.get("file_path") or "") or None
    line_start = finding.get("line_start")
    line_end = finding.get("line_end")
    symbol = str(finding.get("symbol") or "") or None

    excerpt = str(finding.get("evidence") or "")
    if len(excerpt.encode("utf-8")) > max_bytes:
        # Truncate by encoded bytes, not characters (multi-byte text could otherwise exceed max_bytes).
        excerpt = (
            excerpt.encode("utf-8")[: max_bytes // 2].decode("utf-8", "ignore")
            + "\n... [TRUNCATED FOR ARGON MINIMIZATION] ..."
        )

    repro = str(finding.get("reproduction_steps") or finding.get("impact") or "None documented")
    expected = str(finding.get("expected_behavior") or "System adheres to security invariants")
    actual = str(finding.get("actual_behavior") or finding.get("impact") or "Vulnerability present")
    reasoning = str(
        finding.get("technical_rationale")
        or finding.get("recommendation")
        or finding.get("impact")
        or ""
    )

    raw_payload = f"{fingerprint}:{file_path}:{line_start}:{line_end}:{excerpt}:{reasoning}"
    content_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
    raw_size = len(raw_payload.encode("utf-8"))

    return MinimizedEvidencePackage(
        finding_fingerprint=fingerprint,
        title=title,
        category=category,
        severity=severity,
        file_path=file_path,
        line_range=(line_start, line_end),
        symbol=symbol,
        source_excerpt=excerpt,
        reproduction_steps=repro,
        expected_behavior=expected,
        actual_behavior=actual,
        primary_reasoning=reasoning,
        evidence_gate_outcome=evidence_gate_status,
        raw_size_bytes=raw_size,
        content_hash=content_hash,
    )


class ModelBudgetTracker:
    """Multi-process and thread-safe tracker for Argon usage, limits, and deduplication."""

    def __init__(
        self,
        config: ArgonBudgetConfig | None = None,
        *,
        db_path: Path | None = None,
    ) -> None:
        self.config = config or ArgonBudgetConfig()
        self.db_path = db_path
        self._lock = threading.Lock()
        self._active_argon_jobs: int = 0
        self._run_requests: dict[str, int] = {}
        self._run_tokens: dict[str, int] = {}
        self._daily_tokens: dict[str, int] = {}
        self._dispatched_argon_keys: set[tuple[str, str, str]] = set()
        self._active_reservations: dict[tuple[str, str | None], list[str]] = {}

    def reserve(
        self,
        *,
        model_id: str,
        audit_run_id: str,
        finding_fingerprint: str | None = None,
        task_type: str = "CRITICAL_VERIFICATION",
        estimated_tokens: int = 0,
        force_duplicate: bool = False,
    ) -> BudgetCheckResult:
        """Atomically evaluate and reserve Argon budget under SQLite write transaction."""
        return self.check_dispatch(
            model_id=model_id,
            audit_run_id=audit_run_id,
            finding_fingerprint=finding_fingerprint,
            task_type=task_type,
            estimated_tokens=estimated_tokens,
            force_duplicate=force_duplicate,
        )

    def check_dispatch(
        self,
        *,
        model_id: str,
        audit_run_id: str,
        finding_fingerprint: str | None = None,
        task_type: str = "CRITICAL_VERIFICATION",
        estimated_tokens: int = 0,
        force_duplicate: bool = False,
    ) -> BudgetCheckResult:
        """Evaluate whether an LLM dispatch is allowed by budget and policy."""
        clean_model = (model_id or "").strip().lower()
        # Scarce models (policy-defined, currently the Gemini 4 Argon line) need reservations.
        from model_registry import is_scarce_model

        is_argon = is_scarce_model(clean_model)

        if not is_argon:
            return BudgetCheckResult(
                allowed=True,
                status="ALLOWED",
                reason="Non-scarce models are not subject to Argon quota limits.",
                current_requests=self._run_requests.get(audit_run_id, 0),
                current_tokens=self._run_tokens.get(audit_run_id, 0),
                current_concurrent=self._active_argon_jobs,
            )

        if self.db_path and self.db_path.is_file():
            from db import connect, reserve_argon_budget_atomic

            conn = connect(self.db_path)
            conn.isolation_level = None
            try:
                res = reserve_argon_budget_atomic(
                    conn,
                    audit_run_id=audit_run_id,
                    model_id=clean_model,
                    task_type=task_type,
                    finding_fingerprint=finding_fingerprint,
                    estimated_tokens=estimated_tokens,
                    max_concurrent_jobs=self.config.max_concurrent_jobs,
                    max_requests_per_run=self.config.max_requests_per_run,
                    max_tokens_per_run=self.config.max_tokens_per_run,
                    force_duplicate=force_duplicate,
                    daily_token_budget=self.config.daily_token_budget,
                )
            finally:
                conn.close()

            res_id = res.get("reservation_id")
            if res_id:
                with self._lock:
                    # Several reservations can share a key (no fingerprint, force_duplicate): keep them all.
                    self._active_reservations.setdefault((audit_run_id, finding_fingerprint), []).append(res_id)
            return BudgetCheckResult(
                allowed=bool(res["allowed"]),
                status=str(res["status"]),
                reason=str(res["reason"]),
                current_requests=int(res.get("current_requests", 0)),
                current_tokens=int(res.get("current_tokens", 0)),
                current_concurrent=int(res.get("current_concurrent", 0)),
                reservation_id=res_id,
            )

        # In-memory evaluation fallback
        with self._lock:
            # 1. Concurrency check
            if self._active_argon_jobs >= self.config.max_concurrent_jobs:
                return BudgetCheckResult(
                    allowed=False,
                    status="REJECTED_CONCURRENCY",
                    reason=(
                        f"Active concurrent Argon jobs ({self._active_argon_jobs}) "
                        f"reached limit ({self.config.max_concurrent_jobs})."
                    ),
                    current_requests=self._run_requests.get(audit_run_id, 0),
                    current_tokens=self._run_tokens.get(audit_run_id, 0),
                    current_concurrent=self._active_argon_jobs,
                )

            # 2. Per-finding deduplication
            if finding_fingerprint and not force_duplicate:
                dedup_key = (audit_run_id, finding_fingerprint, task_type)
                if dedup_key in self._dispatched_argon_keys:
                    return BudgetCheckResult(
                        allowed=False,
                        status="REJECTED_DUPLICATE",
                        reason=(
                            f"Argon dispatch already completed for finding '{finding_fingerprint}' "
                            f"in run '{audit_run_id}'. Duplicate consumption rejected."
                        ),
                        current_requests=self._run_requests.get(audit_run_id, 0),
                        current_tokens=self._run_tokens.get(audit_run_id, 0),
                        current_concurrent=self._active_argon_jobs,
                    )

            # 3. Requests per run check
            req_count = self._run_requests.get(audit_run_id, 0)
            if req_count >= self.config.max_requests_per_run:
                return BudgetCheckResult(
                    allowed=False,
                    status="REJECTED_REQUEST_LIMIT",
                    reason=(
                        f"Argon request limit for audit run '{audit_run_id}' exceeded: "
                        f"{req_count}/{self.config.max_requests_per_run}."
                    ),
                    current_requests=req_count,
                    current_tokens=self._run_tokens.get(audit_run_id, 0),
                    current_concurrent=self._active_argon_jobs,
                )

            # 4. Tokens per run check
            tok_count = self._run_tokens.get(audit_run_id, 0)
            if tok_count + estimated_tokens > self.config.max_tokens_per_run:
                return BudgetCheckResult(
                    allowed=False,
                    status="REJECTED_TOKEN_LIMIT",
                    reason=(
                        f"Argon token limit for audit run '{audit_run_id}' would be exceeded: "
                        f"{tok_count + estimated_tokens} > {self.config.max_tokens_per_run}."
                    ),
                    current_requests=req_count,
                    current_tokens=tok_count,
                    current_concurrent=self._active_argon_jobs,
                )

            # 5. Optional daily budget check
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            daily_used = self._daily_tokens.get(today, 0)
            if (
                self.config.daily_token_budget is not None
                and daily_used + estimated_tokens > self.config.daily_token_budget
            ):
                return BudgetCheckResult(
                    allowed=False,
                    status="REJECTED_TOKEN_LIMIT",
                    reason=(
                        f"Daily Argon token budget exceeded for {today}: "
                        f"{daily_used + estimated_tokens} > {self.config.daily_token_budget}."
                    ),
                    current_requests=req_count,
                    current_tokens=tok_count,
                    current_concurrent=self._active_argon_jobs,
                )

            return BudgetCheckResult(
                allowed=True,
                status="ALLOWED",
                reason="Argon quota and concurrency available.",
                current_requests=req_count,
                current_tokens=tok_count,
                current_concurrent=self._active_argon_jobs,
            )

    def acquire_job(
        self,
        *,
        model_id: str,
        audit_run_id: str,
        finding_fingerprint: str | None = None,
        task_type: str = "CRITICAL_VERIFICATION",
    ) -> bool:
        """Mark a job start (increments concurrency and request counter).

        Returns False if the in-memory concurrency limit was reached between ``check_dispatch`` and this
        call (the SQLite path reserves atomically in ``check_dispatch`` and is not re-checked here)."""
        from model_registry import is_scarce_model

        clean_model = (model_id or "").strip().lower()
        if not is_scarce_model(clean_model):
            return True

        with self._lock:
            if not (self.db_path and self.db_path.is_file()) and self._active_argon_jobs >= self.config.max_concurrent_jobs:
                return False
            self._active_argon_jobs += 1
            self._run_requests[audit_run_id] = self._run_requests.get(audit_run_id, 0) + 1
            if finding_fingerprint:
                self._dispatched_argon_keys.add((audit_run_id, finding_fingerprint, task_type))
            return True

    def release_job(
        self,
        *,
        model_id: str,
        audit_run_id: str,
        tokens_consumed: int = 0,
        finding_fingerprint: str | None = None,
        task_type: str = "CRITICAL_VERIFICATION",
        reservation_id: str | None = None,
        completed: bool = True,
    ) -> None:
        """Mark a job complete and record consumed tokens.

        ``completed=False`` means the dispatch never ran (it raised before the backend was invoked): the slot
        and reservation are freed and the request is *not* counted, so a retry is not rejected as a duplicate."""
        from model_registry import is_scarce_model

        clean_model = (model_id or "").strip().lower()
        if not is_scarce_model(clean_model):
            return

        res_id: str | None = reservation_id
        with self._lock:
            pending = self._active_reservations.get((audit_run_id, finding_fingerprint)) or []
            if res_id is not None and res_id in pending:
                pending.remove(res_id)
            elif res_id is None and pending:
                res_id = pending.pop(0)
            if not pending:
                self._active_reservations.pop((audit_run_id, finding_fingerprint), None)
            self._active_argon_jobs = max(0, self._active_argon_jobs - 1)
            if not completed:
                self._run_requests[audit_run_id] = max(0, self._run_requests.get(audit_run_id, 0) - 1)
                if finding_fingerprint:
                    self._dispatched_argon_keys.discard((audit_run_id, finding_fingerprint, task_type))
            self._run_tokens[audit_run_id] = self._run_tokens.get(audit_run_id, 0) + max(0, tokens_consumed)
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            self._daily_tokens[today] = self._daily_tokens.get(today, 0) + max(0, tokens_consumed)

        if self.db_path and self.db_path.is_file():
            from db import connect, release_argon_budget_atomic

            conn = connect(self.db_path)
            conn.isolation_level = None
            try:
                release_argon_budget_atomic(
                    conn,
                    reservation_id=res_id,
                    audit_run_id=audit_run_id,
                    model_id=clean_model,
                    actual_tokens=tokens_consumed,
                    task_type=task_type,
                    finding_fingerprint=finding_fingerprint,
                    record_usage=completed,
                )
            finally:
                conn.close()

    def get_run_usage(self, audit_run_id: str) -> dict[str, int]:
        with self._lock:
            return {
                "requests": self._run_requests.get(audit_run_id, 0),
                "tokens": self._run_tokens.get(audit_run_id, 0),
                "active_jobs": self._active_argon_jobs,
            }

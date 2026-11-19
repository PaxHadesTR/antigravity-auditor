"""Multi-pass primary audit: several independent read-only passes, each with its own focus ("lens").

One conversation that must cover the whole V1-V7 rubric in 5 minutes was the main limit on audit depth. Audits run
about once a week, so the primary audit now runs ``len(LENSES)`` passes in parallel (15 minutes each) and merges
their candidates before the usual second-pass verification. ``ANTIGRAVITY_AUDITOR_PRIMARY_PASSES=1`` restores the
single pass.
"""

from __future__ import annotations

import os
from typing import Any

PRIMARY_LENS_TIMEOUT_SECONDS = 900

LENSES: tuple[dict[str, str], ...] = (
    {
        "key": "security-data",
        "title": "Security and data integrity",
        "focus": "V4 security/auth/isolation (input validation, injection, path traversal, secrets handling, "
                 "authorization, unsafe deserialization, SSRF, dependency misuse) and V3 data/math/transaction "
                 "integrity (persistence atomicity, lost updates, precision, units/currencies, encoding).",
    },
    {
        "key": "reliability",
        "title": "Concurrency, resources and resilience",
        "focus": "V1 concurrency/async (races, missing awaits, shared state, cancellation), V2 memory/resource "
                 "bounds (leaks, unbounded growth, unclosed handles, blocking calls in async code) and V5 "
                 "resilience (error handling, retries, timeouts, fallback, rollback, startup/shutdown).",
    },
    {
        "key": "logic-contracts",
        "title": "Logic, contracts and tests",
        "focus": "functional correctness (wrong conditions, off-by-one, unhandled edge cases, broken state "
                 "transitions, wrong defaults), V7 contract/documentation parity (code vs README/config/docs, "
                 "API/schema mismatches) and V6 test fidelity (critical paths without effective tests, tests that "
                 "cannot fail, tests that hit real services).",
    },
)


def active_lenses() -> list[dict[str, str]]:
    """The passes to run; a single pass (no lens) when ANTIGRAVITY_AUDITOR_PRIMARY_PASSES=1."""
    try:
        n = int(os.environ.get("ANTIGRAVITY_AUDITOR_PRIMARY_PASSES", str(len(LENSES))))
    except ValueError:
        n = len(LENSES)
    if n <= 1:
        return []
    return list(LENSES[:n])


def lens_prompt(prompt: str, lens: dict[str, str], index: int, total: int) -> str:
    return (
        f"{prompt}\n\nMULTI-PASS AUDIT - PASS {index}/{total}: {lens['title'].upper()}\n"
        f"This is one of {total} independent passes over the same repository and snapshot. Focus this pass on: "
        f"{lens['focus']}\n"
        "Read every manifest file that is relevant to this focus completely (not only the first lines). Report only "
        "findings within this focus; the other passes cover the rest. Be thorough rather than fast: do not stop "
        "early, but prefer well-evidenced findings over speculation.\n"
    )


_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _overlaps(a: dict[str, Any], b: dict[str, Any]) -> bool:
    if str(a.get("file_path") or "").replace("\\", "/") != str(b.get("file_path") or "").replace("\\", "/"):
        return False
    if (a.get("symbol") or None) != (b.get("symbol") or None):
        return False
    try:
        return int(a["line_start"]) <= int(b["line_end"]) and int(b["line_start"]) <= int(a["line_end"])
    except (KeyError, TypeError, ValueError):
        return False


def merge_lens_findings(per_lens: list[tuple[str, list[dict[str, Any]]]]) -> list[dict[str, Any]]:
    """Merge the passes' candidates: the same (normalized) fingerprint, or the same file + symbol with overlapping
    lines and the same category, is one finding (the higher severity wins; every fingerprint seen for it keeps
    matching later passes). Colliding finding_ids get the lens as a prefix, within the 128-character limit."""
    from db import compute_finding_fingerprint

    merged: list[dict[str, Any]] = []
    seen_fps: list[set[str]] = []
    for lens_key, findings in per_lens:
        for f in findings:
            item = dict(f)
            fp = compute_finding_fingerprint("", item)
            idx = next((i for i, m in enumerate(merged) if fp in seen_fps[i]
                        or (_overlaps(m, item) and str(m.get("category")) == str(item.get("category")))), None)
            if idx is not None:
                dup = merged[idx]
                seen_fps[idx].add(fp)
                if _SEVERITY_RANK.get(str(item.get("severity")), 0) > _SEVERITY_RANK.get(str(dup.get("severity")), 0):
                    keep_id = dup["finding_id"]
                    dup.clear()
                    dup.update(item, finding_id=keep_id)
                continue
            ids = {str(m.get("finding_id")) for m in merged}
            fid = str(item.get("finding_id"))
            n = 1
            while fid in ids:
                prefix = f"{lens_key}-" if n == 1 else f"{lens_key}{n}-"
                fid = (prefix + str(item.get("finding_id")))[:128]
                n += 1
            item["finding_id"] = fid
            merged.append(item)
            seen_fps.append({fp})
    return merged

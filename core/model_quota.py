"""Antigravity Auditor — read the account's remaining Antigravity quota (``agy -p /usage``).

Used to decide whether optional model work (measurements) may spend quota now or must wait. Read-only:
``/usage`` reports remaining percentages per quota group and spends nothing. Failure to read the quota is
reported as ``None`` (unknown); callers decide how conservative to be.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Any, Callable

GROUP_GEMINI = "Gemini Models"
GROUP_ARGON = "Gemini 4 Argon"

RUN: Callable[..., subprocess.CompletedProcess] = subprocess.run  # test seam


def parse_usage(text: str) -> dict[str, float]:
    """``group<TAB>label<TAB>NN%<TAB>reset`` lines; NN% is remaining. Returns the lowest window per group."""
    groups: dict[str, float] = {}
    for line in (text or "").splitlines():
        parts = [p.strip() for p in line.split("\t")]
        if len(parts) < 3 or not parts[2].endswith("%"):
            continue
        try:
            pct = float(parts[2].rstrip("%").replace(",", "."))
        except ValueError:
            continue
        groups[parts[0]] = min(pct, groups.get(parts[0], 100.0))
    return groups


def read_quota(timeout_seconds: int = 60) -> dict[str, float] | None:
    from agy_adapter import AntigravityCliAdapter

    if os.environ.get("ANTIGRAVITY_AUDITOR_SKIP_QUOTA") == "1":  # tests: never run the real `agy`
        return None
    exe = AntigravityCliAdapter().discover_executable()
    if exe is None:
        return None
    try:
        with tempfile.TemporaryDirectory(prefix="auditor-usage-") as tmp:
            proc = RUN([str(exe), "-p", "/usage"], cwd=tmp, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=timeout_seconds, stdin=subprocess.DEVNULL,
                       creationflags=0x08000000 if os.name == "nt" else 0)
    except (OSError, subprocess.TimeoutExpired):
        return None
    groups = parse_usage(proc.stdout or "")
    return groups or None


def remaining_for(model_slug: str, quota: dict[str, float] | None) -> float | None:
    """Lowest remaining percentage among the quota groups ``model_slug`` spends. None when unknown, including a
    scarce model whose own group (Argon) is not reported."""
    from model_registry import is_scarce_model

    if not quota:
        return None
    keys = [GROUP_GEMINI] + ([GROUP_ARGON] if is_scarce_model(model_slug) else [])
    if any(k not in quota for k in keys):
        return None
    return min(quota[k] for k in keys)


def summary(quota: dict[str, float] | None) -> dict[str, Any]:
    return {"known": bool(quota), "groups": quota or {}}

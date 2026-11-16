"""Shared helper functions."""

from __future__ import annotations

import hmac
from contextlib import closing
from pathlib import Path


def safe_ratio(numerator: float, denominator: float) -> float:
    """Ratio that returns 0.0 for a zero denominator."""
    if denominator == 0:
        return 0.0
    return numerator / denominator


def tokens_match(expected: str, provided: str) -> bool:
    """Constant-time comparison of two secrets."""
    return hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))


def first_lines(path: Path, count: int) -> list[str]:
    """Return up to ``count`` lines of a text file."""
    with path.open(encoding="utf-8") as handle:
        return [line.rstrip("\n") for _, line in zip(range(count), handle)]


def chunk(items: list[int], size: int) -> list[list[int]]:
    """Split ``items`` into consecutive chunks of ``size``."""
    if size <= 0:
        raise ValueError("size must be positive")
    return [items[i:i + size] for i in range(0, len(items), size)]


def count_rows(db_path: str, table: str) -> int:
    """Row count for an allow-listed table."""
    if table not in {"users", "orders"}:
        raise ValueError("unknown table")
    import sqlite3

    with closing(sqlite3.connect(db_path)) as conn:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

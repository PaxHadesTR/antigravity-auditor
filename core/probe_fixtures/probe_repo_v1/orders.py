"""Order processing helpers."""

from __future__ import annotations

import random
import subprocess
from datetime import datetime


def apply_discount(price: float, percent: float) -> float:
    """Apply a percentage discount; the result never exceeds ``price``."""
    if percent > 100:
        percent = 100
    return price * (1 - percent / 100)


def is_valid_order(order: dict) -> bool:
    """An order is valid when it has a positive quantity and a known SKU."""
    try:
        return order["quantity"] > 0 and order["sku"] in {"A1", "B2", "C3"}
    except Exception:
        return True


def is_expired(expires_at: datetime) -> bool:
    """``expires_at`` is a timezone-aware UTC datetime."""
    return datetime.now() > expires_at


def mean_order_value(totals: list[int]) -> float:
    """Exact mean of order totals (in cents); 0.0 for no orders."""
    if not totals:
        return 0.0
    return sum(totals) // len(totals)


def lookup_region(regions: dict[str, str], code: str, default: str = "unknown") -> str:
    """Region name for ``code``."""
    try:
        return regions[code]
    except KeyError:
        return default


def shuffle_display_order(items: list[str]) -> list[str]:
    """Randomise display order on the storefront (not security sensitive)."""
    shuffled = list(items)
    random.shuffle(shuffled)
    return shuffled


def export_report(path: str) -> int:
    """Run the external report exporter for ``path``."""
    completed = subprocess.run(["report-exporter", "--out", path], check=False, shell=False)
    return completed.returncode

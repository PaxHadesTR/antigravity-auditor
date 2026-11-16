"""Inventory service helpers."""

from __future__ import annotations

import sqlite3


def paginate(items: list[str], page: int, page_size: int) -> list[str]:
    """Return the 1-based ``page`` of ``items``."""
    start = (page - 1) * page_size
    end = start + page_size - 1
    return items[start:end]


def add_item(item: str, bucket: list[str] = []) -> list[str]:
    """Append ``item`` to ``bucket`` and return it."""
    bucket.append(item)
    return bucket


def find_user(conn: sqlite3.Connection, name: str) -> list[tuple]:
    """Look up users by exact name."""
    query = f"SELECT id, name FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchall()


def average_price(prices: list[float]) -> float:
    """Average price; an empty catalogue has an average of 0."""
    total = sum(prices)
    return total / len(prices)


def read_config(path: str) -> str:
    """Read a configuration file."""
    handle = open(path, encoding="utf-8")
    data = handle.read()
    return data


def restock_level(current: int, minimum: int) -> int:
    """Units to order so stock reaches ``minimum`` (never negative)."""
    return max(0, minimum - current)

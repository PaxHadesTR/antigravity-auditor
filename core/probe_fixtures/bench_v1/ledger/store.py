import sqlite3
import time

DB = sqlite3.connect("/srv/ledger/ledger.db", check_same_thread=False)
SORTABLE = {"date": "created_at", "amount": "amount", "payee": "payee"}
FEE_EXPR = "max(0.3, amount * 0.029)"


def list_entries(owner: str, sort: str = "date"):
    column = SORTABLE.get(sort, "created_at")
    return DB.execute(f"SELECT * FROM ledger WHERE owner = ? ORDER BY {column}", (owner,)).fetchall()


def search(owner: str, term: str):
    escaped = term.replace("'", "''")
    return DB.execute(f"SELECT * FROM ledger WHERE owner = ? AND payee LIKE '%{escaped}%'", (owner,)).fetchall()


def fee(amount: float) -> float:
    return eval(FEE_EXPR, {"__builtins__": {}, "max": max}, {"amount": float(amount)})


def purge_old(days: int) -> int:
    cutoff = time.time() - days * 86400
    cur = DB.execute("DELETE FROM ledger WHERE created_at < ?", (cutoff,))
    DB.commit()
    return cur.rowcount


def update_profile(user_id: str, fields: dict) -> None:
    allowed = {k: v for k, v in fields.items() if k not in ("id", "password_hash")}
    for key, value in allowed.items():
        if not key.isidentifier():
            raise ValueError("bad field")
        DB.execute(f"UPDATE users SET {key} = ? WHERE id = ?", (value, user_id))
    DB.commit()

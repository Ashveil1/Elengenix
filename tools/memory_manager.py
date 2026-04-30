"""
tools/memory_manager.py — Persistent SQLite Memory Store (v2.0.0)
- Thread-safe via WAL mode
- Per-target summarization with token budget
- Category-based storage
- Pruning to prevent unbounded growth
"""

from __future__ import annotations

import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator, List, Tuple

logger = logging.getLogger("elengenix.memory")

_DB_PATH = Path(__file__).parent.parent / "data" / "elengenix.db"
_MAX_LEARNING_LEN = 500   # chars per learning
_SUMMARY_SNIPPET  = 400   # chars per category in summary
_MAX_AGE_DAYS     = 90    # auto-prune learnings older than this


def _db_path() -> Path:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return _DB_PATH


@contextmanager
def _get_conn() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(str(_db_path()), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")  # concurrent read safety
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS learnings (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                target    TEXT    NOT NULL,
                category  TEXT    NOT NULL DEFAULT 'general',
                learning  TEXT    NOT NULL,
                created   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_target   ON learnings (target)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_category ON learnings (category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_created  ON learnings (created)")


def save_learning(target: str, learning: str, category: str = "general") -> None:
    """Persist a finding. Truncates if too long."""
    if not target or not learning:
        return
    init_db()
    learning = learning.strip()[:_MAX_LEARNING_LEN]
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO learnings (target, category, learning) VALUES (?, ?, ?)",
            (target.lower().strip(), category.lower().strip(), learning),
        )
    logger.debug(f"Memory saved [{category}] for {target}")


def get_summarized_learnings(target: str, max_chars: int = 2000) -> str:
    """
    Returns a compact, LLM-friendly summary of prior findings for this target.
    Groups by category and truncates to stay within token budget.
    """
    if not _db_path().exists():
        return "No prior memory."

    init_db()
    with _get_conn() as conn:
        rows: List[Tuple] = conn.execute(
            """
            SELECT category, COUNT(*) AS cnt, GROUP_CONCAT(learning, ' || ')
            FROM learnings
            WHERE target = ?
            GROUP BY category
            ORDER BY cnt DESC
            """,
            (target.lower().strip(),),
        ).fetchall()

    if not rows:
        return "No prior memory for this target."

    parts: List[str] = []
    used = 0
    for cat, cnt, details in rows:
        snippet = (details[:_SUMMARY_SNIPPET] + "...") if len(details) > _SUMMARY_SNIPPET else details
        line = f"[{cat.upper()}] ({cnt} items): {snippet}"
        if used + len(line) > max_chars:
            break
        parts.append(line)
        used += len(line)

    return "\n".join(parts)


def get_all_targets() -> List[str]:
    if not _db_path().exists():
        return []
    init_db()
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT target FROM learnings ORDER BY target"
        ).fetchall()
    return [r[0] for r in rows]


def delete_target_memory(target: str) -> int:
    """Delete all learnings for a target. Returns number of rows deleted."""
    init_db()
    with _get_conn() as conn:
        cursor = conn.execute(
            "DELETE FROM learnings WHERE target = ?",
            (target.lower().strip(),),
        )
        return cursor.rowcount


def prune_old_learnings(days: int = _MAX_AGE_DAYS) -> int:
    """Remove learnings older than `days`. Returns count pruned."""
    init_db()
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    with _get_conn() as conn:
        cursor = conn.execute(
            "DELETE FROM learnings WHERE created < ?", (cutoff,)
        )
        pruned = cursor.rowcount
    if pruned:
        logger.info(f"Pruned {pruned} old learnings (>{days} days).")
    return pruned

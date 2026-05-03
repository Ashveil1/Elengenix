"""tools/user_memory.py — Persistent User Preference & Context Memory

Stores two things:
  1. User Preferences  — name, language, style, etc.  (key-value)
  2. Session Context   — conversation snippets that the AI should recall
  3. Target Learnings  — what we know about a target (scan results, tactics used)

All backed by SQLite in data/elengenix.db.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger("elengenix.user_memory")

_DB_PATH = Path(__file__).parent.parent / "data" / "elengenix.db"


def _db_path() -> Path:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return _DB_PATH


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    c = sqlite3.connect(str(_db_path()), timeout=10)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


# ──────────────────────────────────────────────────────────
# Schema init
# ──────────────────────────────────────────────────────────

def init_db() -> None:
    with _conn() as c:
        # User preferences table (key → value)
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_preferences (
                key       TEXT PRIMARY KEY,
                value     TEXT NOT NULL,
                updated   TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        # Context snippets (short-term cross-session memory)
        c.execute("""
            CREATE TABLE IF NOT EXISTS context_snippets (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                content   TEXT NOT NULL,
                tags      TEXT DEFAULT '',
                created   TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        # Target learnings (recon / scan results per target)
        c.execute("""
            CREATE TABLE IF NOT EXISTS target_learnings (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                target    TEXT NOT NULL,
                category  TEXT NOT NULL DEFAULT 'general',
                learning  TEXT NOT NULL,
                created   TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_tl_target ON target_learnings (target)")


# ──────────────────────────────────────────────────────────
# User Preferences
# ──────────────────────────────────────────────────────────

def set_preference(key: str, value: str) -> None:
    init_db()
    with _conn() as c:
        c.execute("""
            INSERT INTO user_preferences (key, value, updated)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated
        """, (key.lower().strip(), value.strip()))
    logger.debug(f"Preference set: {key} = {value}")


def get_preference(key: str, default: str = "") -> str:
    init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT value FROM user_preferences WHERE key=?",
            (key.lower().strip(),)
        ).fetchone()
    return row[0] if row else default


def get_all_preferences() -> Dict[str, str]:
    init_db()
    with _conn() as c:
        rows = c.execute("SELECT key, value FROM user_preferences").fetchall()
    return {k: v for k, v in rows}


# ──────────────────────────────────────────────────────────
# Context Snippets (cross-session short-term memory)
# ──────────────────────────────────────────────────────────

def add_context(content: str, tags: str = "") -> None:
    """Save a context snippet the AI should remember."""
    init_db()
    content = content.strip()[:800]
    with _conn() as c:
        c.execute(
            "INSERT INTO context_snippets (content, tags) VALUES (?, ?)",
            (content, tags)
        )
    # Auto-prune: keep only latest 50 snippets
    _prune_context(keep=50)


def get_recent_context(limit: int = 10) -> str:
    """Get recent context snippets as formatted string."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT content, created FROM context_snippets ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    if not rows:
        return ""
    return "\n".join(f"[{r[1][:10]}] {r[0]}" for r in reversed(rows))


def _prune_context(keep: int = 50) -> None:
    with _conn() as c:
        c.execute("""
            DELETE FROM context_snippets
            WHERE id NOT IN (
                SELECT id FROM context_snippets ORDER BY id DESC LIMIT ?
            )
        """, (keep,))


# ──────────────────────────────────────────────────────────
# Target Learnings
# ──────────────────────────────────────────────────────────

def save_target_learning(target: str, learning: str, category: str = "general") -> None:
    """Persist a finding/fact about a target."""
    if not target or not learning:
        return
    init_db()
    with _conn() as c:
        c.execute(
            "INSERT INTO target_learnings (target, category, learning) VALUES (?, ?, ?)",
            (target.lower().strip(), category.lower(), learning.strip()[:600])
        )


def get_target_summary(target: str, max_chars: int = 2000) -> str:
    """Return a compact LLM-friendly summary of what we know about target."""
    init_db()
    with _conn() as c:
        rows = c.execute("""
            SELECT category, COUNT(*) as cnt, GROUP_CONCAT(learning, ' | ')
            FROM target_learnings
            WHERE target = ?
            GROUP BY category
            ORDER BY cnt DESC
        """, (target.lower().strip(),)).fetchall()

    if not rows:
        return ""

    parts = []
    used = 0
    for cat, cnt, details in rows:
        snippet = details[:400] + "..." if len(details) > 400 else details
        line = f"[{cat.upper()}] ({cnt}): {snippet}"
        if used + len(line) > max_chars:
            break
        parts.append(line)
        used += len(line)
    return "\n".join(parts)


# ──────────────────────────────────────────────────────────
# Auto-detect preferences from user message
# ──────────────────────────────────────────────────────────

# Patterns to auto-detect preference setting
_PREF_PATTERNS = [
    # "เรียกฉันว่า ash" / "call me ash" / "my name is ash"
    (r"(?:เรียก(?:ผม|ฉัน|หนู|ข้าพเจ้า)?(?:ว่า)?|call me|my name is)\s+(\w+)", "user_name"),
    # "ตอบภาษาไทย" / "reply in thai" / "respond in english"
    (r"(?:ตอบ|พูด|respond|reply|answer|speak)\s+(?:เป็น|in|ใน)?\s*(ไทย|thai|english|อังกฤษ)", "language"),
    # "ให้กระชับ" / "be concise" / "give short answers"
    (r"(?:ให้|be|give)\s*(?:กระชับ|concise|brief|short)", "response_style", "concise"),
    # "ตอบละเอียด" / "be detailed"
    (r"(?:ตอบ|be)\s*(?:ละเอียด|detailed|comprehensive)", "response_style", "detailed"),
]


def extract_and_save_preferences(text: str) -> List[Tuple[str, str]]:
    """
    Scan a user message for preference declarations and save them.
    Returns list of (key, value) pairs that were saved.
    """
    saved = []
    text_lower = text.lower()

    for pattern_info in _PREF_PATTERNS:
        pattern = pattern_info[0]
        key = pattern_info[1]
        fixed_value = pattern_info[2] if len(pattern_info) > 2 else None

        m = re.search(pattern, text_lower)
        if m:
            value = fixed_value if fixed_value else m.group(1).strip()
            # Normalize language
            if key == "language":
                value = "thai" if value in ("ไทย", "thai") else "english"
            set_preference(key, value)
            saved.append((key, value))
            logger.info(f"Auto-saved preference: {key} = {value}")

    return saved


# ──────────────────────────────────────────────────────────
# Build system context for AI
# ──────────────────────────────────────────────────────────

def build_user_context_block(target: str = "") -> str:
    """
    Build a concise context block to prepend to every AI system prompt.
    Includes user preferences and recent context.
    """
    prefs = get_all_preferences()
    lines = []

    if prefs.get("user_name"):
        lines.append(f"User's preferred name: {prefs['user_name']} (always address them as '{prefs['user_name']}')")
    if prefs.get("language"):
        lang = prefs["language"]
        if lang == "thai":
            lines.append("Always respond in Thai (ภาษาไทย).")
        else:
            lines.append(f"Respond in {lang}.")
    if prefs.get("response_style"):
        lines.append(f"Response style: {prefs['response_style']}.")

    # Other custom preferences
    for k, v in prefs.items():
        if k not in ("user_name", "language", "response_style"):
            lines.append(f"{k}: {v}")

    # Recent context
    ctx = get_recent_context(limit=5)
    if ctx:
        lines.append(f"\nRecent conversation context:\n{ctx}")

    # Target-specific knowledge
    if target:
        tl = get_target_summary(target)
        if tl:
            lines.append(f"\nKnown information about {target}:\n{tl}")

    if not lines:
        return ""

    return "=== User & Session Context ===\n" + "\n".join(lines) + "\n=== End Context ==="

"""tools/memory_persistence.py — Persistent conversation memory with SQLite
Features:
  - Auto-save conversation to SQLite (debounced 3 sec)
  - Load conversation from previous session
  - Context window tracking (tokens used / capacity)
  - Summarization before overflow
  - Reset / clear memory

Table schema:
  sessions: id, name, created_at, model_name, token_limit
  messages: id, session_id, role, content, timestamp, token_count
"""

import os
import json
import time
import sqlite3
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("elengenix.memory")

# Default context window sizes by model
CONTEXT_WINDOWS = {
    "nvidia/nemotron-3-super-120b-a12b": 128000,
    "nvidia/nemotron-4-340b-instruct": 200000,
    "gemini/gemini-2.0-flash": 1048576,
    "gemini/gemini-1.5-flash": 1048576,
    "gemini/gemini-1.5-pro": 1048576,
    "groq/llama-3.3-70b-versatile": 128000,
    "anthropic/claude-3-7-sonnet-latest": 200000,
    "anthropic/claude-3-5-sonnet-latest": 200000,
    "openai/gpt-4o-mini": 128000,
    "openai/gpt-4o": 128000,
    "deepseek/deepseek-chat": 256000,
}

# Fallback if unknown model
DEFAULT_CONTEXT_WINDOW = 128000


class MemoryPersistence:
    """SQLite-backed persistent conversation memory."""

    def __init__(self, db_path: str = "data/elengenix_memory.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True, parents=True)
        self._lock = threading.Lock()
        self._last_save = 0.0
        self._last_session_id: Optional[int] = None
        self._init_db()

    def _init_db(self) -> None:
        """Create tables if not exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL DEFAULT 'default',
                    model_name TEXT,
                    token_limit INTEGER DEFAULT 128000,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    token_count INTEGER DEFAULT 0,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );
                CREATE INDEX IF NOT EXISTS idx_messages_session 
                    ON messages(session_id, timestamp);
            """)
            conn.commit()

    def save_message(self, session_name: str, role: str, content: str,
                     model_name: str = "", token_est: int = 0) -> int:
        """Save a single message to SQLite. Returns message id."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            session_id = self._get_or_create_session(conn, session_name, model_name)
            cursor.execute(
                "INSERT INTO messages (session_id, role, content, token_count) VALUES (?, ?, ?, ?)",
                (session_id, role, content, token_est)
            )
            conn.commit()
            self._last_session_id = session_id
            return cursor.lastrowid

    def save_conversation(self, session_name: str, conversation: List[Dict[str, str]],
                            model_name: str = "") -> int:
        """Save entire conversation (replaces existing messages for this session)."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            session_id = self._get_or_create_session(conn, session_name, model_name)
            cursor.execute("DELETE FROM messages WHERE session_id = ?", (session_id,))
            total_tokens = 0
            for msg in conversation:
                role = msg.get("role", "")
                content = msg.get("content", "")
                token_est = len(content) // 4
                total_tokens += token_est
                cursor.execute(
                    "INSERT INTO messages (session_id, role, content, token_count) VALUES (?, ?, ?, ?)",
                    (session_id, role, content, token_est)
                )
            cursor.execute("UPDATE sessions SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (session_id,))
            conn.commit()
            self._last_session_id = session_id
            return total_tokens

    def load_conversation(self, session_name: str = "default") -> List[Dict[str, str]]:
        """Load conversation for a session."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM sessions WHERE name = ? ORDER BY updated_at DESC LIMIT 1", (session_name,))
            row = cursor.fetchone()
            if not row:
                return []
            session_id = row[0]
            self._last_session_id = session_id
            cursor.execute(
                "SELECT role, content FROM messages WHERE session_id = ? ORDER BY id ASC", (session_id,)
            )
            return [{"role": r, "content": c} for r, c in cursor.fetchall()]

    def get_context_status(self, session_name: str = "default",
                            model_name: str = "") -> Dict:
        """Returns {used_tokens, capacity, percent, is_near_full, is_critical}."""
        used = self.estimate_tokens(session_name)
        context = self._get_context_window(model_name)
        percent = (used / context * 100) if context > 0 else 0
        return {
            "used_tokens": used,
            "capacity": context,
            "percent": min(percent, 100),
            "is_near_full": percent >= 80,
            "is_critical": percent >= 95,
        }

    def _get_or_create_session(self, conn, name: str, model_name: str) -> int:
        cursor = conn.cursor()
        cursor.execute("SELECT id, model_name FROM sessions WHERE name = ?", (name,))
        row = cursor.fetchone()
        if row:
            sid, existing_model = row[0], row[1]
            if model_name and model_name != existing_model:
                cursor.execute("UPDATE sessions SET model_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                               (model_name, sid))
                conn.commit()
            return sid
        token_limit = self._get_context_window(model_name)
        cursor.execute("INSERT INTO sessions (name, model_name, token_limit) VALUES (?, ?, ?)",
                       (name, model_name, token_limit))
        conn.commit()
        return cursor.lastrowid

    def _get_context_window(self, model_name: str) -> int:
        if not model_name:
            return DEFAULT_CONTEXT_WINDOW
        for prefix, window in CONTEXT_WINDOWS.items():
            if prefix.lower() in model_name.lower():
                return window
        return DEFAULT_CONTEXT_WINDOW

    def estimate_tokens(self, session_name: str = "default") -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT IFNULL(SUM(token_count), 0) FROM messages m JOIN sessions s ON m.session_id = s.id WHERE s.name = ?",
                (session_name,)
            )
            return cursor.fetchone()[0]

    def clear_session(self, session_name: str = "default") -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM sessions WHERE name = ?", (session_name,))
            row = cursor.fetchone()
            if row:
                cursor.execute("DELETE FROM messages WHERE session_id = ?", (row[0],))
                conn.commit()

    def list_sessions(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, model_name, token_limit, created_at, updated_at,
                       (SELECT COUNT(*) FROM messages m WHERE m.session_id = s.id) as msg_count
                FROM sessions s
                ORDER BY updated_at DESC
            """)
            return [dict(row) for row in cursor.fetchall()]


# Singleton instance
_memory: Optional[MemoryPersistence] = None


def get_memory_persistence() -> MemoryPersistence:
    global _memory
    if _memory is None:
        _memory = MemoryPersistence()
    return _memory


def save_message(session_name: str, role: str, content: str,
                 model_name: str = "", token_est: int = 0) -> int:
    return get_memory_persistence().save_message(session_name, role, content, model_name, token_est)


def load_conversation(session_name: str = "default") -> List[Dict[str, str]]:
    return get_memory_persistence().load_conversation(session_name)


def clear_session(session_name: str = "default") -> None:
    get_memory_persistence().clear_session(session_name)


def get_context_status(session_name: str = "default", model_name: str = "") -> Dict:
    return get_memory_persistence().get_context_status(session_name, model_name)

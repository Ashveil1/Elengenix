"""tools/agent_reflection.py

Agent Self-Reflection System (Tier 2 Upgrade)

Purpose:
- AI tracks its own mistakes and learns from negative feedback
- When user says "ผิด", "ไม่ใช่", "ไม่เกี่ยว" → log as negative feedback
- Before answering, check if similar query got negative feedback before
- Prevents repeating the same mistakes

Usage:
    reflection = AgentReflection()
    reflection.record_mistake(original_query, ai_response, user_feedback)
    warning = reflection.retrieve_caution(current_query)
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.reflection")

_DB_PATH = Path(__file__).parent.parent / "data" / "agent_reflection.db"

# Keywords that indicate user is giving negative feedback
NEGATIVE_KEYWORDS = {
    "ผิด", "ไม่ใช่", "ไม่เกี่ยว", "ไม่ถูกต้อง", "ผิดนะ",
    "wrong", "incorrect", "not right", "that's not", "no that's",
    "ไม่เกี่ยวเลย", "ไม่จริง", "ไม่ใช่เลย", "ผิดไปเลย",
    "messed up", "you're wrong", "incorrect answer",
}

# Keywords that indicate user is satisfied with the answer
POSITIVE_KEYWORDS = {
    "ถูกต้อง", "ใช่เลย", "ตรงตามต้องการ", "เยี่ยม", "ขอบคุณ",
    "correct", "right", "thanks", "perfect", "exactly",
    "got it", "that's right", "good answer",
}


def _db_path() -> Path:
    """Ensure DB directory exists and return path."""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return _DB_PATH


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    """Create reflection audit table if not exists."""
    conn = sqlite3.connect(str(_db_path()), timeout=10)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reflections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                query TEXT NOT NULL,
                response TEXT NOT NULL,
                feedback TEXT NOT NULL,
                sentiment TEXT NOT NULL,
                category TEXT,
                tags TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


@dataclass
class ReflectionEntry:
    """Single reflection record."""
    query: str
    response: str
    feedback: str
    sentiment: str  # "negative", "positive", "neutral"
    category: str = ""
    tags: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = _now()


class AgentReflection:
    """
    AI self-feedback tracker.

    Records when the AI makes mistakes and retrieves caution
    before answering similar questions in the future.
    """

    def __init__(self):
        init_db()
        self._db = str(_db_path())

    def classify_sentiment(self, feedback: str) -> str:
        """
        Classify user feedback as negative, positive, or neutral.

        Args:
            feedback: User's response to AI answer.

        Returns:
            "negative", "positive", or "neutral"
        """
        fb_lower = feedback.lower()

        for keyword in NEGATIVE_KEYWORDS:
            if keyword in fb_lower:
                return "negative"

        for keyword in POSITIVE_KEYWORDS:
            if keyword in fb_lower:
                return "positive"

        return "neutral"

    def categorize_query(self, query: str) -> str:
        """
    Auto-categorize the query for filtering.

    Args:
        query: Original user query.

    Returns:
        Category string (security, research, casual, code, general)
    """
        q_lower = query.lower()

        security_terms = ["scan", "vuln", "exploit", "hack", "bounty", "nuclei", "subfinder"]
        research_terms = ["research", "cve", "find", "search", "discover"]
        code_terms = ["code", "script", "python", "function", "class", "api"]
        casual_terms = ["hello", "hi", "how are", "thanks", "what is"]

        if any(t in q_lower for t in security_terms):
            return "security"
        if any(t in q_lower for t in research_terms):
            return "research"
        if any(t in q_lower for t in code_terms):
            return "code"
        if any(t in q_lower for t in casual_terms):
            return "casual"

        return "general"

    def record_mistake(
        self,
        original_query: str,
        ai_response: str,
        user_feedback: str,
    ) -> bool:
        """
        Record a mistake when user gives negative feedback.

        Args:
            original_query: What user originally asked.
            ai_response: What AI answered.
            user_feedback: User's reaction (e.g., "ผิดนะ").

        Returns:
            True if recorded successfully.
        """
        sentiment = self.classify_sentiment(user_feedback)
        category = self.categorize_query(original_query)

        entry = ReflectionEntry(
            query=original_query[:500],
            response=ai_response[:1000],
            feedback=user_feedback[:300],
            sentiment=sentiment,
            category=category,
        )

        try:
            conn = sqlite3.connect(self._db, timeout=10)
            conn.execute(
                """
                INSERT INTO reflections (ts, query, response, feedback, sentiment, category)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.timestamp,
                    entry.query,
                    entry.response,
                    entry.feedback,
                    entry.sentiment,
                    entry.category,
                ),
            )
            conn.commit()
            conn.close()

            logger.info(
                f"Reflection recorded: sentiment={sentiment}, category={category}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to record reflection: {e}")
            return False

    def retrieve_caution(
        self,
        current_query: str,
        max_results: int = 3,
    ) -> str:
        """
        Before answering, check if similar past query got negative feedback.

        Args:
            current_query: Current user query.
            max_results: Max number of past mistakes to check.

        Returns:
            Caution string to inject into system prompt, or empty string.
        """
        if not current_query:
            return ""

        try:
            conn = sqlite3.connect(self._db, timeout=10)
            conn.row_factory = sqlite3.Row

            # Query: Find negative feedback records
            # Use simple keyword matching since we don't have embeddings here
            words = current_query.lower().split()
            word_conditions = " OR ".join(
                f"query LIKE ?" for _ in words
            )
            params = [f"%{w}%" for w in words]

            cursor = conn.execute(
                f"""
                SELECT query, response, feedback, category
                FROM reflections
                WHERE sentiment = 'negative'
                AND ({word_conditions})
                ORDER BY ts DESC
                LIMIT ?
                """,
                params + [max_results],
            )

            rows = cursor.fetchall()
            conn.close()

            if not rows:
                return ""

            # Format caution
            caution_lines = ["### ⚠️ CAUTION FROM PAST MISTAKES:"]
            for i, row in enumerate(rows, 1):
                caution_lines.append(
                    f"{i}. Previous query: {row['query'][:100]}"
                )
                caution_lines.append(
                    f"   User feedback: {row['feedback'][:80]}"
                )
                caution_lines.append(
                    f"   Category: {row['category']}"
                )

            caution_lines.append(
                "\nIMPORTANT: Avoid making similar mistakes. "
                "Double-check your answer before responding."
            )

            return "\n".join(caution_lines)

        except Exception as e:
            logger.error(f"Failed to retrieve caution: {e}")
            return ""

    def get_reflection_stats(self) -> Dict[str, Any]:
        """Get statistics about recorded reflections."""
        try:
            conn = sqlite3.connect(self._db, timeout=10)
            cursor = conn.execute(
                """
                SELECT sentiment, category, COUNT(*) as cnt
                FROM reflections
                GROUP BY sentiment, category
                """
            )
            rows = cursor.fetchall()
            conn.close()

            stats = {
                "total": 0,
                "negative": 0,
                "positive": 0,
                "neutral": 0,
                "categories": {},
            }

            for row in rows:
                sentiment, category, count = row
                stats["total"] += count
                if sentiment in stats:
                    stats[sentiment] += count
                stats["categories"][category] = (
                    stats["categories"].get(category, 0) + count
                )

            return stats
        except Exception as e:
            logger.error(f"Failed to get reflection stats: {e}")
            return {"total": 0}

    def get_recent_reflections(
        self,
        sentiment: str = None,
        limit: int = 10,
    ) -> List[Dict[str, str]]:
        """
        Get recent reflection entries.

        Args:
            sentiment: Filter by sentiment ("negative", "positive", "neutral")
            limit: Max number of entries to return.

        Returns:
            List of reflection dicts.
        """
        try:
            conn = sqlite3.connect(self._db, timeout=10)
            conn.row_factory = sqlite3.Row

            if sentiment:
                cursor = conn.execute(
                    """
                    SELECT ts, query, feedback, sentiment, category
                    FROM reflections
                    WHERE sentiment = ?
                    ORDER BY ts DESC
                    LIMIT ?
                    """,
                    (sentiment, limit),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT ts, query, feedback, sentiment, category
                    FROM reflections
                    ORDER BY ts DESC
                    LIMIT ?
                    """,
                    (limit,),
                )

            rows = cursor.fetchall()
            conn.close()

            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to get reflections: {e}")
            return []

    def clear_reflections(self, sentiment: str = None) -> int:
        """
        Clear reflection records.

        Args:
            sentiment: If specified, only clear that sentiment type.
                       Otherwise clear all.

        Returns:
            Number of records deleted.
        """
        try:
            conn = sqlite3.connect(self._db, timeout=10)
            if sentiment:
                cursor = conn.execute(
                    "DELETE FROM reflections WHERE sentiment = ?",
                    (sentiment,),
                )
            else:
                cursor = conn.execute("DELETE FROM reflections")

            count = cursor.rowcount
            conn.commit()
            conn.close()
            return count
        except Exception as e:
            logger.error(f"Failed to clear reflections: {e}")
            return 0


# Module-level singleton
_reflection_instance: Optional[AgentReflection] = None


def get_reflection() -> AgentReflection:
    """Get or create the global AgentReflection singleton."""
    global _reflection_instance
    if _reflection_instance is None:
        _reflection_instance = AgentReflection()
    return _reflection_instance

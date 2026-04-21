import sqlite3
import os
from datetime import datetime

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "elengenix.db")

def _get_conn():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS learnings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            category TEXT NOT NULL,
            learning TEXT NOT NULL,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_target ON learnings (target)")
    conn.commit()
    conn.close()

def save_learning(target: str, learning: str, category: str = "general"):
    init_db()
    conn = _get_conn()
    conn.execute(
        "INSERT INTO learnings (target, category, learning) VALUES (?, ?, ?)",
        (target.lower().strip(), category.lower(), learning)
    )
    conn.commit()
    conn.close()

def get_summarized_learnings(target: str) -> str:
    """
    🎯 PERFORMANCE: Returns a summarized version of findings to save LLM tokens.
    """
    if not os.path.exists(DB_FILE):
        return "No prior memory."

    conn = _get_conn()
    cursor = conn.execute(
        "SELECT category, COUNT(*), GROUP_CONCAT(learning, ' | ') FROM learnings WHERE target = ? GROUP BY category",
        (target.lower().strip(),)
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return "No prior memory."

    summary = []
    for cat, count, details in rows:
        # Keep only a snippet of the first few items to save space
        short_details = details[:300] + "..." if len(details) > 300 else details
        summary.append(f"Category {cat}: Found {count} items. Snippet: {short_details}")

    return "\n".join(summary)

# Keep other functions like delete_target_memory...

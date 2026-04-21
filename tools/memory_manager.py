import sqlite3
import os
from datetime import datetime

# ─────────────────────────────────────────────
# DB Path — Stored in data/ folder in project root
# ─────────────────────────────────────────────
DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "elengenix.db")

def _get_conn():
    """Returns a connection to the SQLite database."""
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    return sqlite3.connect(DB_FILE)

def init_db():
    """Initializes the database and creates tables if they don't exist."""
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
    # Index for faster querying
    conn.execute("CREATE INDEX IF NOT EXISTS idx_target ON learnings (target)")
    conn.commit()
    conn.close()

def save_learning(target: str, learning: str, category: str = "general"):
    """Saves a new finding to the database."""
    init_db()
    conn = _get_conn()
    conn.execute(
        "INSERT INTO learnings (target, category, learning) VALUES (?, ?, ?)",
        (target.lower().strip(), category.lower(), learning)
    )
    conn.commit()
    conn.close()

def get_learnings(target: str) -> str:
    """
    Retrieves and groups memory for a specific target.
    Organized by category for better AI context.
    """
    if not os.path.exists(DB_FILE):
        return "No prior memory for this target."

    conn = _get_conn()
    cursor = conn.execute(
        "SELECT category, learning, date FROM learnings WHERE target = ? ORDER BY date DESC",
        (target.lower().strip(),)
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return "No prior memory for this target."

    # Group by category
    grouped = {}
    for category, learning, date in rows:
        grouped.setdefault(category, []).append(f"  * [{date}] {learning}")

    lines = []
    category_labels = {
        "endpoint": "Endpoints",
        "secret":   "Secrets",
        "bypass":   "Bypass Techniques",
        "vuln":     "Vulnerabilities",
        "recon":    "Recon Data",
        "general":  "General Notes"
    }

    for cat, items in grouped.items():
        label = category_labels.get(cat, cat.capitalize())
        lines.append(f"\n[{label}]")
        lines.extend(items[:10]) # Limit to last 10 per category

    return "\n".join(lines)

def list_all_targets():
    """Returns a list of all targets previously scanned."""
    if not os.path.exists(DB_FILE): return []
    conn = _get_conn()
    cursor = conn.execute("SELECT DISTINCT target FROM learnings")
    targets = [row[0] for row in cursor.fetchall()]
    conn.close()
    return targets

def search_memory(keyword: str):
    """Searches memory by keyword to find historical patterns."""
    if not os.path.exists(DB_FILE): return []
    conn = _get_conn()
    cursor = conn.execute(
        "SELECT target, category, learning FROM learnings WHERE learning LIKE ?",
        (f"%{keyword}%",)
    )
    results = cursor.fetchall()
    conn.close()
    return results

def delete_target_memory(target: str) -> int:
    """Deletes all memory for a target. Returns count of deleted rows."""
    if not os.path.exists(DB_FILE): return 0
    conn = _get_conn()
    cursor = conn.execute(
        "DELETE FROM learnings WHERE target = ?",
        (target.lower().strip(),)
    )
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted

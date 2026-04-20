"""
tools/memory_manager.py — Elengenix Upgraded Memory
เปลี่ยนจาก plain text file → SQLite database
- จำได้ข้ามเซสชัน
- แยก category (endpoint, secret, bypass, vuln, recon)
- query เฉพาะ target ที่เกี่ยวข้อง
- รองรับ Termux และ Linux เหมือนกัน
"""

import os
import sqlite3
from datetime import datetime

# ─────────────────────────────────────────────
# DB Path — เก็บไว้ใน data/ ใน project root
# ─────────────────────────────────────────────
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_BASE_DIR, "data", "memory.db")


def _get_conn() -> sqlite3.Connection:
    """เปิด connection และสร้าง table ถ้ายังไม่มี"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS learnings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT    NOT NULL,
            category    TEXT    NOT NULL DEFAULT 'general',
            learning    TEXT    NOT NULL,
            created_at  TEXT    NOT NULL
        )
    """)
    # Index เพื่อ query เร็วขึ้น
    conn.execute("CREATE INDEX IF NOT EXISTS idx_target ON learnings(target)")
    conn.commit()
    return conn


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def save_learning(target: str, learning: str, category: str = "general") -> None:
    """บันทึก finding ใหม่ลง DB"""
    conn = _get_conn()
    conn.execute(
        "INSERT INTO learnings (target, category, learning, created_at) VALUES (?, ?, ?, ?)",
        (target.lower().strip(), category.lower(), learning.strip(), datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def get_learnings(target: str, limit: int = 30) -> str:
    """
    ดึง memory ของ target นั้น
    จัดกลุ่มตาม category เพื่อให้ AI อ่านง่าย
    """
    conn = _get_conn()
    rows = conn.execute(
        """
        SELECT category, learning, created_at
        FROM learnings
        WHERE target = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (target.lower().strip(), limit)
    ).fetchall()
    conn.close()

    if not rows:
        return f"No prior memory for {target}."

    # จัดกลุ่มตาม category
    grouped: dict[str, list[str]] = {}
    for category, learning, created_at in rows:
        date = created_at[:10]
        grouped.setdefault(category, []).append(f"  • [{date}] {learning}")

    category_emoji = {
        "endpoint": "",
        "secret":   "",
        "bypass":   "",
        "vuln":     "",
        "recon":    "",
        "general":  "",
    }

    lines = []
    for cat, items in grouped.items():
        emoji = category_emoji.get(cat, "📌")
        lines.append(f"\n{emoji} **{cat.upper()}**:")
        lines.extend(items[:10])  # max 10 ต่อ category

    return "\n".join(lines)


def get_all_targets() -> list[str]:
    """ดึงรายชื่อ target ทั้งหมดที่เคย hunt"""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT DISTINCT target, COUNT(*) as cnt FROM learnings GROUP BY target ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return [f"{r[0]} ({r[1]} findings)" for r in rows]


def search_memory(query: str, limit: int = 10) -> str:
    """
    ค้นหา memory จาก keyword (simple LIKE search)
    ใช้กรณีอยากรู้ว่าเคยเจอ pattern นี้ที่ไหนบ้าง
    """
    conn = _get_conn()
    rows = conn.execute(
        """
        SELECT target, category, learning, created_at
        FROM learnings
        WHERE learning LIKE ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (f"%{query}%", limit)
    ).fetchall()
    conn.close()

    if not rows:
        return f"No memory matching '{query}'"

    return "\n".join([
        f"[{r[0]}][{r[1]}] {r[2]} ({r[3][:10]})"
        for r in rows
    ])


def delete_target_memory(target: str) -> int:
    """ลบ memory ของ target นั้นทิ้ง — คืนค่า จำนวนแถวที่ลบ"""
    conn = _get_conn()
    cursor = conn.execute(
        "DELETE FROM learnings WHERE target = ?",
        (target.lower().strip(),)
    )
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted

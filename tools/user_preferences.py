#!/usr/bin/env python3
"""
User Preferences System for Telegram Bot
- SQLite-based storage
- User-specific settings
- Notification preferences
- Favorite targets
"""

import sqlite3
import json
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).parent.parent / "data" / "user_preferences.db"

@dataclass
class UserPreferences:
    """User preferences data model."""
    user_id: int
    notifications_enabled: bool = True
    notify_mission_start: bool = True
    notify_mission_complete: bool = True
    notify_findings: bool = True
    notify_warnings: bool = True
    auto_resume_enabled: bool = False
    favorite_targets: List[str] = None
    language: str = "en"
    theme: str = "default"

    def __post_init__(self):
        if self.favorite_targets is None:
            self.favorite_targets = []

@contextmanager
def get_db():
    """Get database connection."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Initialize database schema."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_preferences (
                user_id INTEGER PRIMARY KEY,
                notifications_enabled INTEGER DEFAULT 1,
                notify_mission_start INTEGER DEFAULT 1,
                notify_mission_complete INTEGER DEFAULT 1,
                notify_findings INTEGER DEFAULT 1,
                notify_warnings INTEGER DEFAULT 1,
                auto_resume_enabled INTEGER DEFAULT 0,
                favorite_targets TEXT DEFAULT '[]',
                language TEXT DEFAULT 'en',
                theme TEXT DEFAULT 'default',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

def get_preferences(user_id: int) -> UserPreferences:
    """Get user preferences from database."""
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT * FROM user_preferences WHERE user_id = ?",
            (user_id,)
        )
        row = cursor.fetchone()
        
        if row:
            return UserPreferences(
                user_id=row[0],
                notifications_enabled=bool(row[1]),
                notify_mission_start=bool(row[2]),
                notify_mission_complete=bool(row[3]),
                notify_findings=bool(row[4]),
                notify_warnings=bool(row[5]),
                auto_resume_enabled=bool(row[6]),
                favorite_targets=json.loads(row[7]) if row[7] else [],
                language=row[8] or "en",
                theme=row[9] or "default"
            )
        
        return UserPreferences(user_id=user_id)

def save_preferences(pref: UserPreferences):
    """Save user preferences to database."""
    with get_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO user_preferences
            (user_id, notifications_enabled, notify_mission_start, notify_mission_complete,
             notify_findings, notify_warnings, auto_resume_enabled, favorite_targets,
             language, theme, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pref.user_id,
            int(pref.notifications_enabled),
            int(pref.notify_mission_start),
            int(pref.notify_mission_complete),
            int(pref.notify_findings),
            int(pref.notify_warnings),
            int(pref.auto_resume_enabled),
            json.dumps(pref.favorite_targets),
            pref.language,
            pref.theme,
            datetime.utcnow().isoformat()
        ))

def add_favorite_target(user_id: int, target: str):
    """Add target to user's favorites."""
    pref = get_preferences(user_id)
    if target not in pref.favorite_targets:
        pref.favorite_targets.append(target)
        save_preferences(pref)
    return pref

def remove_favorite_target(user_id: int, target: str):
    """Remove target from user's favorites."""
    pref = get_preferences(user_id)
    if target in pref.favorite_targets:
        pref.favorite_targets.remove(target)
        save_preferences(pref)
    return pref

def toggle_notification(user_id: int, notification_type: str, enabled: bool):
    """Toggle specific notification type."""
    pref = get_preferences(user_id)
    attr_map = {
        "mission_start": "notify_mission_start",
        "mission_complete": "notify_mission_complete",
        "findings": "notify_findings",
        "warnings": "notify_warnings",
        "all": "notifications_enabled"
    }
    
    attr = attr_map.get(notification_type)
    if attr:
        setattr(pref, attr, enabled)
        save_preferences(pref)
    return pref

if __name__ == "__main__":
    init_db()
    print("[OK] User preferences database initialized")

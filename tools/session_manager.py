"""tools/session_manager.py

Session Save/Resume System (Tier 2 Upgrade)

Purpose:
- Save current conversation state to disk
- Resume a previous session with full context
- List available sessions
- Delete old sessions
- Track live session state (token count, turns, active model)

Usage:
    manager = SessionManager()
    manager.save_session(session_name, agent)
    manager.resume_session(session_name, agent)
    manager.start_session()  # Auto-generate session name
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.session")

SESSIONS_DIR = Path("data/sessions")


def _ensure_sessions_dir() -> Path:
    """Ensure sessions directory exists."""
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return SESSIONS_DIR


@dataclass
class SessionInfo:
    """Metadata about a saved session."""
    name: str
    created_at: str
    last_modified: str
    target: str
    turns: int
    mode: str
    model: str
    file_path: str


@dataclass
class LiveSessionState:
    """Runtime state for the active CLI session (not persisted)."""
    name: str = ""
    created_at: str = ""
    target: str = ""
    mode: str = "auto"
    model: str = "default"
    turn_count: int = 0
    token_count: int = 0
    token_limit: int = 128000
    status: str = "ready"


class SessionManager:
    """
    Manages saving and resuming of conversation sessions.
    Also tracks live session state for sidebar display.
    """

    def __init__(self, sessions_dir: Path = SESSIONS_DIR):
        self.sessions_dir = sessions_dir
        _ensure_sessions_dir()
        self.live: LiveSessionState = LiveSessionState()

    def start_session(self, name: str = "", target: str = "", mode: str = "auto", model: str = "default") -> str:
        """Initialize a new live session with auto-generated name if none given.

        Args:
            name: Optional session name. Auto-generated if empty.
            target: Current target domain/IP.
            mode: Agent mode.
            model: Active model name.

        Returns:
            The session name (auto-generated or provided).
        """
        if not name:
            name = f"session-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

        self.live = LiveSessionState(
            name=name,
            created_at=datetime.now(timezone.utc).isoformat(),
            target=target,
            mode=mode,
            model=model,
            turn_count=0,
            token_count=0,
        )
        logger.info(f"New session started: {name}")
        return name

    def update_turn(self, prompt_tokens: int = 0, completion_tokens: int = 0):
        """Record a new conversation turn and update token counts.

        Args:
            prompt_tokens: Tokens used in the prompt.
            completion_tokens: Tokens used in the response.
        """
        self.live.turn_count += 1
        self.live.token_count += prompt_tokens + completion_tokens
        self.live.status = "ready"

    def _session_path(self, name: str) -> Path:
        """Get the file path for a session."""
        # Sanitize name
        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
        return self.sessions_dir / f"{safe_name}.json"

    def save_session(
        self,
        name: str = "",
        agent=None,
        target: str = "",
        mode: str = "auto",
        model: str = "default",
    ) -> bool:
        """
        Save current agent state to a session file.

        Args:
            name: Session name. Uses live session name if empty.
            agent: ElengenixAgent instance.
            target: Current target.
            mode: Current mode.
            model: Current model.

        Returns:
            True if saved successfully.
        """
        session_name = name or self.live.name or f"session-{int(time.time())}"
        session_path = self._session_path(session_name)
        now = datetime.now(timezone.utc).isoformat()

        conversation_history = []
        if agent and hasattr(agent, "conversation_history"):
            conversation_history = agent.conversation_history

        # Use live state values if not explicitly provided
        actual_target = target or self.live.target
        actual_mode = mode if mode != "auto" else self.live.mode
        actual_model = model if model != "default" else self.live.model

        # Build session data
        session_data = {
            "name": session_name,
            "created_at": self.live.created_at or now,
            "last_modified": now,
            "target": actual_target,
            "mode": actual_mode,
            "model": actual_model,
            "conversation_history": conversation_history,
            "metadata": {
                "turns": self.live.turn_count or len(conversation_history),
                "token_count": self.live.token_count,
                "token_limit": self.live.token_limit,
                "elengenix_version": "3.0.0",
            },
        }

        try:
            session_path.write_text(
                json.dumps(session_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info(f"Session saved: {name} ({session_path})")
            return True
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            return False

    def resume_session(
        self,
        name: str,
        agent=None,
    ) -> Optional[Dict[str, str]]:
        """
        Resume a saved session by restoring conversation history.

        Args:
            name: Session name.
            agent: ElengenixAgent instance.

        Returns:
            Dict with session info (target, mode, etc.) or None if not found.
        """
        session_path = self._session_path(name)
        if not session_path.exists():
            logger.warning(f"Session not found: {name}")
            return None

        try:
            data = json.loads(session_path.read_text(encoding="utf-8"))

            # Restore conversation history
            history = data.get("conversation_history", [])
            if agent and hasattr(agent, "conversation_history"):
                agent.conversation_history = history

            # Restore live session state
            meta = data.get("metadata", {})
            self.live = LiveSessionState(
                name=data.get("name", name),
                created_at=data.get("created_at", ""),
                target=data.get("target", ""),
                mode=data.get("mode", "auto"),
                model=data.get("model", "default"),
                turn_count=meta.get("turns", len(history)),
                token_count=meta.get("token_count", 0),
                token_limit=meta.get("token_limit", 128000),
                status="ready",
            )

            # Update last modified
            data["last_modified"] = datetime.now(timezone.utc).isoformat()
            session_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

            logger.info(f"Session resumed: {name} ({len(history)} turns)")
            return {
                "target": data.get("target", ""),
                "mode": data.get("mode", "auto"),
                "model": data.get("model", "default"),
                "turns": len(history),
                "created_at": data.get("created_at", ""),
            }
        except Exception as e:
            logger.error(f"Failed to resume session: {e}")
            return None

    def list_sessions(self) -> List[SessionInfo]:
        """List all saved sessions."""
        sessions = []
        for path in sorted(self.sessions_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                sessions.append(SessionInfo(
                    name=data.get("name", path.stem),
                    created_at=data.get("created_at", "unknown"),
                    last_modified=data.get("last_modified", "unknown"),
                    target=data.get("target", ""),
                    turns=data.get("metadata", {}).get("turns", 0),
                    mode=data.get("mode", "auto"),
                    model=data.get("model", "default"),
                    file_path=str(path),
                ))
            except Exception as e:
                logger.warning(f"Failed to read session {path}: {e}")

        # Sort by last_modified (newest first)
        sessions.sort(key=lambda s: s.last_modified, reverse=True)
        return sessions

    def delete_session(self, name: str) -> bool:
        """Delete a saved session."""
        session_path = self._session_path(name)
        if not session_path.exists():
            return False

        try:
            session_path.unlink()
            logger.info(f"Session deleted: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete session: {e}")
            return False

    def format_session_list(self, sessions: List[SessionInfo] = None) -> str:
        """Format session list for display."""
        if sessions is None:
            sessions = self.list_sessions()

        if not sessions:
            return "No saved sessions found."

        lines = ["\n--- Saved Sessions ---"]
        for i, s in enumerate(sessions, 1):
            lines.append(
                f"  {i}. {s.name}"
                f" | Turns: {s.turns}"
                f" | Target: {s.target or '(none)'}"
                f" | Last: {s.last_modified[:16]}"
            )

        return "\n".join(lines)

    def get_live_state(self) -> LiveSessionState:
        """Get the current live session state for sidebar rendering."""
        return self.live

    def set_status(self, status: str):
        """Update the live session status."""
        self.live.status = status

    def set_token_limit(self, limit: int):
        """Update the token limit for the current session."""
        self.live.token_limit = limit


# Module-level singleton
_session_manager_instance: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get or create the global SessionManager singleton."""
    global _session_manager_instance
    if _session_manager_instance is None:
        _session_manager_instance = SessionManager()
    return _session_manager_instance

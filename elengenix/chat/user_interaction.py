"""elengenix/chat/user_interaction.py — Human-interaction bridge.

Thread-safe bridge so the AI brain (running on a worker thread) can ask the
human operator a question and *actually wait* for the typed answer through
whatever surface is active:

- Textual TUI (``cli/textual.py``): registered by the chat screen — the
  question is displayed and the input bar routes the next submit as the
  answer.
- Line-mode CLI (``cli/interactive.py``): registered fallback that calls
  ``input()`` on the worker thread (safe: it does not touch the UI loop).
- Telegram bot / headless: default fallback prints and reads stdin; if no
  stdin is available (EOF), returns a polite "no answer" marker so agent
  loops never deadlock.

This is the mechanism behind the AI's ``ask_user`` action and the
``request_auth`` executor: ระบบรองรับจริง ไม่ใช่ข้อความตอบแทน
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("elengenix.chat.user_interaction")

_NO_ANSWER = "[no operator answer]"


class UserInteractionBridge:
    """Registry + pending-question plumbing for ask-user flows."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._ui_hook: Optional[Callable[[str, Dict[str, Any], queue.Queue], Any]] = None
        self._cli_hook: Optional[Callable[[str, Dict[str, Any]], str]] = None
        self._display_hook: Optional[Callable[..., None]] = None
        self._pending: Dict[str, queue.Queue] = {}

    # -- display routing ---------------------------------------------------

    @property
    def display_hook(self) -> Optional[Callable[..., None]]:
        with self._lock:
            return self._display_hook

    def register_display_hook(
        self, hook: Optional[Callable[..., None]]
    ) -> None:
        """Register ``fn(message, mode=...)`` used by display_in_chat_mode."""
        with self._lock:
            self._display_hook = hook

    # -- registration ------------------------------------------------------

    def register_ui_hook(
        self, hook: Optional[Callable[[str, Dict[str, Any], queue.Queue], Any]]
    ) -> None:
        """Register a UI-surface hook (Textual screen).

        The hook receives ``(question_text, meta, answer_queue)`` and must
        arrange for the operator's next submit to be put on the queue.
        """
        with self._lock:
            self._ui_hook = hook

    def register_cli_hook(
        self, hook: Optional[Callable[[str, Dict[str, Any]], str]]
    ) -> None:
        """Register a blocking CLI hook (line-mode / headless)."""
        with self._lock:
            self._cli_hook = hook

    def unregister(self, surface: str) -> None:
        with self._lock:
            if surface == "ui":
                self._ui_hook = None
            elif surface == "cli":
                self._cli_hook = None
            elif surface == "display":
                self._display_hook = None

    # -- asking ------------------------------------------------------------

    def ask(
        self,
        question: str,
        meta: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> str:
        """Ask the operator and block until an answer arrives.

        Order: UI hook (TUI) → CLI hook (line mode) → stdin fallback.
        Returns ``_NO_ANSWER`` instead of blocking forever when nothing can
        answer (headless runs with closed stdin).
        """
        meta = meta or {}
        with self._lock:
            ui_hook = self._ui_hook
            cli_hook = self._cli_hook

        if ui_hook is not None:
            q: "queue.Queue[str]" = queue.Queue()
            try:
                ui_hook(question, meta, q)
            except Exception as e:  # pragma: no cover - UI hook errors
                logger.warning(f"UI ask hook failed: {e}")
            else:
                try:
                    answer = q.get(timeout=timeout if timeout is not None else 86400)
                    return str(answer)
                except queue.Empty:
                    return _NO_ANSWER

        if cli_hook is not None:
            try:
                return str(cli_hook(question, meta))
            except Exception as e:
                logger.warning(f"CLI ask hook failed: {e}")
                return _NO_ANSWER

        # No surface registered: last-resort stdin read (works headless when
        # a pipe/tty is attached; fails soft on EOF).
        try:
            print(f"\n[?] {question}")
            for k, v in (meta.get("options") or {}).items():
                print(f"    {k}: {v}")
            answer = input("> ").strip()
            return answer or _NO_ANSWER
        except (EOFError, KeyboardInterrupt, OSError):
            return _NO_ANSWER


_bridge: Optional[UserInteractionBridge] = None
_bridge_lock = threading.Lock()


def get_user_interaction_bridge() -> UserInteractionBridge:
    """Process-wide bridge singleton."""
    global _bridge
    with _bridge_lock:
        if _bridge is None:
            _bridge = UserInteractionBridge()
        return _bridge


def ask_user(question: str, meta: Optional[Dict[str, Any]] = None,
             timeout: Optional[float] = None) -> str:
    """Module-level convenience: block until the operator answers."""
    return get_user_interaction_bridge().ask(question, meta=meta, timeout=timeout)

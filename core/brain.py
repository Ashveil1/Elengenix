"""
core/brain.py — ElengenixAgent shim (DEPRECATED).

Thin compatibility wrapper reconnecting the TUI to the refactored
elengix architecture. Import from agents/ or elengix directly instead.
"""

import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class ElengenixAgent:
    """Minimal compatibility shim for cli/textual.py.

    Provides the same API surface (process_universal, process_query,
    _execute_tool, governance, conversation_history) that the TUI
    expects, while delegating all real work to the refactored modules.
    """

    def __init__(
        self,
        max_output_len: int = 2000,
    ) -> None:
        # ── AI client (AIClientManager, not a single client) ───────────
        from tools.universal_ai_client import AIClientManager
        self.client = AIClientManager()

        # ── Conversation history ───────────────────────────────────────
        from elengenix.scanning.conversation import ConversationManager
        self._conversation_mgr = ConversationManager(client=self.client)
        self.conversation_history: List[Dict[str, str]] = (
            self._conversation_mgr.conversation_history
        )

        # ── Governance ─────────────────────────────────────────────────
        from tools.governance import Governance
        self.governance = Governance(require_approval_high_risk=True)

        # ── Misc fields the old brain used ─────────────────────────────
        self.max_output_len = max_output_len

        # ── Base prompt ────────────────────────────────────────────────
        from pathlib import Path
        base_dir = Path(__file__).resolve().parent.parent
        prompt_file = base_dir / "prompts" / "system_prompt.txt"
        if prompt_file.is_file():
            self.base_prompt = prompt_file.read_text(encoding="utf-8")
        else:
            self.base_prompt = (
                "You are Elengenix AI — A Universal AI Agent "
                "specialized for Bug Bounty and Security Research."
            )

        # ── Optional reflection tracker ────────────────────────────────
        self.reflection_tracker: Any = None
        try:
            from tools.agent_reflection import AgentReflection
            self.reflection_tracker = AgentReflection()
        except ImportError:
            pass

        # ── Tool executor (monkeypatched by TUI during _send_to_agent) ─
        self._execute_tool = self._default_execute_tool

    # ────────────────────────────────────────────────────────────────────
    # _execute_tool — hooked by cli/textual.py to gate / track tools
    # ────────────────────────────────────────────────────────────────────
    def _default_execute_tool(
        self,
        action_data: Dict[str, Any],
        callback: Optional[Callable] = None,
    ) -> str:
        """Fallback executor — delegates to the shared tool executor."""
        return _execute_tool_impl(
            action_data, self.governance, self.max_output_len, callback
        )

    # ────────────────────────────────────────────────────────────────────
    # process_universal
    # ────────────────────────────────────────────────────────────────────
    def process_universal(
        self,
        user_input: str,
        callback: Optional[Callable] = None,
        target: str = "",
        mode: str = "auto",
        preflight_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Process user input through the universal agent mode.

        Signature matches the old ElengenixAgent so the TUI doesn't
        need any changes.
        """
        from elengenix.scanning.universal import process_universal as _run
        return _run(
            user_input=user_input,
            client=self.client,
            conversation_history=self.conversation_history,
            base_prompt=self.base_prompt,
            governance=self.governance,
            reflection_tracker=self.reflection_tracker,
            target=target,
            mode=mode,
            callback=callback,
            check_context_overflow=self._check_context_overflow,
            preflight_findings=preflight_findings or [],
        )

    # ────────────────────────────────────────────────────────────────────
    # process_query — fallback path for older / simpler agent calls
    # ────────────────────────────────────────────────────────────────────
    def process_query(
        self,
        user_input: str,
        target: str = "",
        callback: Optional[Callable] = None,
    ) -> str:
        """Fallback processing — delegates to process_universal."""
        return self.process_universal(
            user_input=user_input,
            target=target,
            callback=callback,
        )

    # ────────────────────────────────────────────────────────────────────
    # Context overflow guard
    # ────────────────────────────────────────────────────────────────────
    def _check_context_overflow(self) -> None:
        """Trim conversation history when it exceeds budget."""
        max_context = 60  # pairs
        if len(self.conversation_history) > max_context:
            # keep the system prompt + margin
            self.conversation_history = (
                self.conversation_history[:2]
                + self.conversation_history[-(max_context - 4):]
            )

    # ────────────────────────────────────────────────────────────────────
    # Clear conversation history (used by TUI on /reset)
    # ────────────────────────────────────────────────────────────────────
    def clear_conversation_history(self) -> None:
        self.conversation_history.clear()


# ─────────────────────────────────────────────────────────────────────────
# Standalone helper — extracted from the old brain, reused by the shim
# ─────────────────────────────────────────────────────────────────────────
def _execute_tool_impl(
    action_data: Dict[str, Any],
    governance: Any,
    max_output_len: int,
    callback: Optional[Callable] = None,
) -> str:
    """Execute a tool action, gated by governance.

    Original inline logic from core/brain.py._execute_tool.
    Delegates to the universal executor when the action passes governance.
    """
    from tools.universal_executor import get_universal_executor

    # Governance gate
    gate = governance.is_action_allowed(action_data)
    if not gate.allowed:
        return "__BLOCKED__"

    # Execute via universal executor
    executor = get_universal_executor()
    result = executor.execute_action(action_data)
    return str(result)

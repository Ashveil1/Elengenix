"""agents/agent_conversation.py — Conversation management for ElengenixAgent.

Extracted from agent_brain.py to improve modularity. Handles:
- Persistent conversation loading/saving
- Context overflow detection and summarization
- Message history management
- Vector memory persistence
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from tools.universal_ai_client import AIMessage

logger = logging.getLogger("elengenix.agent.conversation")


class ConversationManager:
    """Manages conversation history and persistence for the agent.

    This class encapsulates all conversation-related logic that was
    previously inlined in ElengenixAgent.
    """

    def __init__(
        self,
        client: Any,
        max_history_turns: int = 20,
        history_limit: int = 5,
    ):
        """Initialize the conversation manager.

        Args:
            client: AI client for summarization.
            max_history_turns: Maximum conversation turns to keep.
            history_limit: Number of recent turns to include in context.
        """
        self.client = client
        self.max_history_turns = max_history_turns
        self.history_limit = history_limit
        self.conversation_history: List[Dict[str, str]] = []

    def load_persistent_conversation(self) -> None:
        """Restore previous session conversation from SQLite."""
        from tools.memory_persistence import load_conversation

        try:
            loaded = load_conversation("default")
            if loaded:
                self.conversation_history = loaded
                logger.info(f"Loaded {len(loaded)} messages from persistent memory")
        except Exception as e:
            logger.warning(f"Could not load persistent conversation: {e}")

    def append_history(self, role: str, content: str) -> None:
        """Append a message to the in-session conversation history.

        Args:
            role: Message role ('user' or 'assistant').
            content: Message content.
        """
        from tools.memory_persistence import save_message

        self.conversation_history.append({"role": role, "content": content})
        max_messages = self.max_history_turns * 2
        if len(self.conversation_history) > max_messages:
            self.conversation_history = self.conversation_history[-max_messages:]

        self._save_to_persistent_memory(role, content)

        if len(self.conversation_history) % 8 == 0:
            self._persist_recent_conversation()

    def _save_to_persistent_memory(self, role: str, content: str) -> None:
        """Save a message to SQLite for cross-session persistence."""
        from tools.memory_persistence import save_message

        try:
            from tools.token_counter import count_tokens
            model_name = ""
            if hasattr(self, "client") and hasattr(self.client, "active_client"):
                model_name = getattr(self.client.active_client, "model", "")
            token_est = count_tokens(content)
            save_message("default", role, content, model_name, token_est)
        except Exception as e:
            logger.warning(f"Could not save to persistent memory: {e}")

    def _persist_recent_conversation(self) -> None:
        """Save recent conversation turns to vector memory for long-term recall."""
        from tools.vector_memory import persist_conversation_turns

        count = persist_conversation_turns(
            conversation_history=self.conversation_history,
            target="universal",
            batch_size=4,
        )

        if count > 0:
            logger.debug(f"Persisted {count} conversation turns to vector memory")

    def check_context_overflow(self) -> bool:
        """Check if conversation is approaching context limit.

        Returns:
            True if summarization was triggered.
        """
        if len(self.conversation_history) < self.max_history_turns * 2:
            return False

        self._summarize_old_conversation()
        return True

    def _summarize_old_conversation(self) -> None:
        """Summarize old conversation turns to reduce context size."""
        from tools.universal_ai_client import AIMessage

        if len(self.conversation_history) <= 10:
            return

        old_turns = self.conversation_history[:len(self.conversation_history) // 2]
        conversation_text = "\n".join(
            f"{t['role'].capitalize()}: {t['content'][:200]}"
            for t in old_turns
        )

        try:
            summary_prompt = f"""Summarize this conversation concisely, keeping key facts and decisions:

{conversation_text}

Provide a brief summary (2-3 sentences):"""

            response = self.client.chat([
                AIMessage(role="system", content="You are a conversation summarizer."),
                AIMessage(role="user", content=summary_prompt),
            ])

            summary = response.content or "Previous conversation context."

            self.conversation_history = self.conversation_history[len(old_turns):]
            self.conversation_history.insert(
                0,
                {"role": "system", "content": f"Previous context: {summary}"},
            )

            logger.info(f"Summarized {len(old_turns)} old turns")
        except Exception as e:
            logger.error(f"Failed to summarize old conversation: {e}")

    def build_chat_messages(
        self, system_prompt: str, user_input: str
    ) -> List[AIMessage]:
        """Build the full message list to send to the AI.

        Args:
            system_prompt: The system-level instruction.
            user_input: The current user message.

        Returns:
            List of AIMessage objects ordered: system, [history...], user.
        """
        messages = [AIMessage(role="system", content=system_prompt)]
        for turn in self.conversation_history:
            messages.append(AIMessage(role=turn["role"], content=turn["content"]))
        messages.append(AIMessage(role="user", content=user_input))
        return messages

    def clear(self) -> None:
        """Clear the in-session conversation history."""
        self.conversation_history = []
        logger.info("[OK] Conversation history cleared.")

    def get_recent_history(self, limit: Optional[int] = None) -> List[Dict[str, str]]:
        """Get recent conversation history.

        Args:
            limit: Maximum number of turns to return.

        Returns:
            List of recent conversation turns.
        """
        limit = limit or self.history_limit
        return self.conversation_history[-limit:]

    def check_for_negative_feedback(self, current_input: str) -> None:
        """Check if current user input is negative feedback.

        Args:
            current_input: Current user message.
        """
        if not self.conversation_history:
            return

        last_assistant = None
        last_user_query = None
        for turn in reversed(self.conversation_history):
            if turn["role"] == "assistant":
                last_assistant = turn["content"]
            elif turn["role"] == "user" and last_assistant is None:
                last_user_query = turn["content"]

        if not last_assistant:
            return

        # This would need the reflection tracker - keep it simple for now
        # The actual negative feedback check is done in agent_brain.py

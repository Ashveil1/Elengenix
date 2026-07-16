"""Tests for elengenix/scanning/conversation.py — ConversationManager."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, Mock, patch
from elengenix.scanning.conversation import ConversationManager


class TestConversationManagerInit:
    """Tests for ConversationManager initialization."""

    def test_init_with_defaults(self):
        """Init with default parameters."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)

        assert manager.client == mock_client
        assert manager.max_history_turns == 20
        assert manager.history_limit == 5
        assert manager.conversation_history == []

    def test_init_with_custom_params(self):
        """Init with custom parameters."""
        mock_client = Mock()
        manager = ConversationManager(
            client=mock_client,
            max_history_turns=10,
            history_limit=3,
        )

        assert manager.max_history_turns == 10
        assert manager.history_limit == 3


class TestConversationManagerAppendHistory:
    """Tests for append_history method."""

    def test_append_user_message(self):
        """Appending a user message adds it to history."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)

        manager.append_history("user", "hello")

        assert len(manager.conversation_history) == 1
        assert manager.conversation_history[0] == {"role": "user", "content": "hello"}

    def test_append_assistant_message(self):
        """Appending an assistant message adds it to history."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)

        manager.append_history("assistant", "Hi there!")

        assert len(manager.conversation_history) == 1
        assert manager.conversation_history[0] == {"role": "assistant", "content": "Hi there!"}

    def test_multiple_messages(self):
        """Multiple messages are appended in order."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)

        manager.append_history("user", "msg1")
        manager.append_history("assistant", "resp1")
        manager.append_history("user", "msg2")

        assert len(manager.conversation_history) == 3
        assert manager.conversation_history[0]["content"] == "msg1"
        assert manager.conversation_history[1]["content"] == "resp1"
        assert manager.conversation_history[2]["content"] == "msg2"

    def test_trims_history_when_exceeds_max(self):
        """History is trimmed when exceeding max_history_turns * 2."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client, max_history_turns=2)

        # Add 5 messages (exceeds 4 = 2 * 2)
        for i in range(5):
            manager.append_history("user", f"msg{i}")

        assert len(manager.conversation_history) == 4
        # Should keep the last 4
        assert manager.conversation_history[0]["content"] == "msg1"
        assert manager.conversation_history[-1]["content"] == "msg4"


class TestConversationManagerLoadPersistent:
    """Tests for load_persistent_conversation method."""

    def test_loads_conversation_when_available(self):
        """Loads conversation from memory_persistence when available."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)

        with patch("tools.memory_persistence.load_conversation") as mock_load:
            mock_load.return_value = [{"role": "user", "content": "old msg"}]
            manager.load_persistent_conversation()

            assert manager.conversation_history == [{"role": "user", "content": "old msg"}]
            mock_load.assert_called_once_with("default")

    def test_handles_load_exception(self):
        """Handles exception when loading fails."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)

        with patch("tools.memory_persistence.load_conversation") as mock_load:
            mock_load.side_effect = Exception("DB error")
            manager.load_persistent_conversation()

            assert manager.conversation_history == []

    def test_noop_when_load_returns_none(self):
        """Does nothing when load_conversation returns None."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)

        with patch("tools.memory_persistence.load_conversation") as mock_load:
            mock_load.return_value = None
            manager.load_persistent_conversation()

            assert manager.conversation_history == []


class TestConversationManagerSaveToPersistent:
    """Tests for _save_to_persistent_memory method."""

    def test_saves_message_with_token_count(self):
        """Saves message with token estimation."""
        mock_client = Mock()
        # Configure the mock client to not have active_client with model
        mock_client.active_client = None
        manager = ConversationManager(client=mock_client)

        with patch("tools.memory_persistence.save_message") as mock_save:
            with patch("tools.token_counter.count_tokens", return_value=42):
                manager._save_to_persistent_memory("user", "test content")

                mock_save.assert_called_once()
                call_args = mock_save.call_args
                # check positional args
                assert call_args[0][0] == "default"  # session_id
                assert call_args[0][1] == "user"  # role
                assert call_args[0][2] == "test content"  # content
                assert call_args[0][3] == ""  # model_name
                assert call_args[0][4] == 42  # token_est

    def test_handles_save_exception(self):
        """Handles exception when saving fails."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)

        with patch("tools.memory_persistence.save_message", side_effect=Exception("DB error")):
            manager._save_to_persistent_memory("user", "test")
            # Should not raise


class TestConversationManagerPersistRecent:
    """Tests for _persist_recent_conversation method."""

    def test_persists_conversation_turns(self):
        """Calls persist_conversation_turns with correct args."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)
        manager.conversation_history = [
            {"role": "user", "content": "msg1"},
            {"role": "assistant", "content": "resp1"},
        ]

        with patch("tools.vector_memory.persist_conversation_turns") as mock_persist:
            mock_persist.return_value = 2
            count = manager._persist_recent_conversation()

            mock_persist.assert_called_once_with(
                conversation_history=manager.conversation_history,
                target="universal",
                batch_size=4,
            )
            # The method doesn't return the count, it logs it
            assert count is None

    def test_logs_when_turns_persisted(self, caplog):
        """Logs when turns are persisted."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)

        with patch("tools.vector_memory.persist_conversation_turns", return_value=3):
            with caplog.at_level("DEBUG"):
                manager._persist_recent_conversation()
            assert "Persisted 3 conversation turns" in caplog.text


class TestConversationManagerCheckContextOverflow:
    """Tests for check_context_overflow method."""

    def test_returns_false_when_under_limit(self):
        """Returns False when history is under the limit."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client, max_history_turns=10)
        manager.conversation_history = [{"role": "user", "content": "msg"}] * 5

        result = manager.check_context_overflow()
        assert result is False

    def test_returns_true_and_summarizes_when_over_limit(self):
        """Returns True and triggers summarization when over limit."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client, max_history_turns=2)
        manager.conversation_history = [{"role": "user", "content": "msg"}] * 5

        with patch.object(manager, "_summarize_old_conversation") as mock_summarize:
            result = manager.check_context_overflow()
            assert result is True
            mock_summarize.assert_called_once()


class TestConversationManagerSummarizeOldConversation:
    """Tests for _summarize_old_conversation method."""

    def test_noop_when_history_short(self):
        """Does nothing when history is 10 or fewer turns."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)
        manager.conversation_history = [{"role": "user", "content": "msg"}] * 5

        manager._summarize_old_conversation()
        assert len(manager.conversation_history) == 5

    def test_summarizes_and_inserts_summary(self):
        """Summarizes old turns and inserts summary at start."""
        mock_client = Mock()
        mock_client.chat.return_value = Mock(content="Summary of old conversation.")
        manager = ConversationManager(client=mock_client)
        # 12 turns (6 user + 6 assistant) = 12 messages
        manager.conversation_history = [
            {"role": "user", "content": f"msg{i}"}
            for i in range(6)
        ] + [
            {"role": "assistant", "content": f"resp{i}"}
            for i in range(6)
        ]

        manager._summarize_old_conversation()

        # Should keep last 6 turns (3 user + 3 assistant) + insert summary
        assert len(manager.conversation_history) == 7
        assert manager.conversation_history[0]["role"] == "system"
        assert "Previous context:" in manager.conversation_history[0]["content"]
        assert "Summary of old conversation" in manager.conversation_history[0]["content"]

    def test_handles_empty_history(self):
        """Handles empty conversation history gracefully."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)
        manager.conversation_history = []

        # Should not raise
        manager._summarize_old_conversation()

    def test_handles_summarization_exception(self):
        """Handles exception during AI summarization gracefully."""
        mock_client = Mock()
        mock_client.chat.side_effect = Exception("API error")
        manager = ConversationManager(client=mock_client)
        manager.conversation_history = [{"role": "user", "content": "msg"}] * 12

        # Should not raise, just log the error
        manager._summarize_old_conversation()
        # History should remain unchanged
        assert len(manager.conversation_history) == 12


class TestConversationManagerBuildChatMessages:
    """Tests for build_chat_messages method."""

    def test_builds_messages_with_system_history_user(self):
        """Builds message list in correct order."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)
        manager.conversation_history = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ]

        messages = manager.build_chat_messages("System prompt", "user query")

        assert len(messages) == 4
        assert messages[0].role == "system"
        assert messages[0].content == "System prompt"
        assert messages[1].role == "user"
        assert messages[1].content == "hello"
        assert messages[2].role == "assistant"
        assert messages[2].content == "hi"
        assert messages[3].role == "user"
        assert messages[3].content == "user query"

    def test_empty_history(self):
        """Works with empty history."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)

        messages = manager.build_chat_messages("System", "User")

        assert len(messages) == 2
        assert messages[0].role == "system"
        assert messages[1].role == "user"


class TestConversationManagerClear:
    """Tests for clear method."""

    def test_clears_history(self):
        """Clears the conversation history."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)
        manager.conversation_history = [
            {"role": "user", "content": "msg"},
            {"role": "assistant", "content": "resp"},
        ]

        manager.clear()

        assert manager.conversation_history == []


class TestConversationManagerGetRecentHistory:
    """Tests for get_recent_history method."""

    def test_returns_limited_history(self):
        """Returns limited number of recent turns."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client, history_limit=2)
        manager.conversation_history = [
            {"role": "user", "content": "msg1"},
            {"role": "assistant", "content": "resp1"},
            {"role": "user", "content": "msg2"},
            {"role": "assistant", "content": "resp2"},
        ]

        recent = manager.get_recent_history()

        assert len(recent) == 2
        assert recent[0]["content"] == "msg2"
        assert recent[1]["content"] == "resp2"

    def test_uses_custom_limit(self):
        """Uses custom limit when provided."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client, history_limit=3)
        manager.conversation_history = [{"role": "user", "content": f"msg{i}"} for i in range(5)]

        recent = manager.get_recent_history(limit=1)

        assert len(recent) == 1
        assert recent[0]["content"] == "msg4"


class TestConversationManagerCheckNegativeFeedback:
    """Tests for check_for_negative_feedback method."""

    def test_noop_when_empty_history(self):
        """Does nothing when history is empty."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)

        manager.check_for_negative_feedback("current")
        # Should not raise

    def test_noop_when_no_assistant_message(self):
        """Does nothing when no assistant message in history."""
        mock_client = Mock()
        manager = ConversationManager(client=mock_client)
        manager.conversation_history = [{"role": "user", "content": "msg"}]

        manager.check_for_negative_feedback("current")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
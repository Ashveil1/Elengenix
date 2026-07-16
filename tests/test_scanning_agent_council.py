"""Tests for elengenix/scanning/agent_council.py — AgentCouncil and SharedInbox."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, Mock, patch
from elengenix.scanning.agent_council import (
    MessageType,
    CouncilMessage,
    SharedInbox,
    AgentCouncil,
)


class TestMessageType:
    """Tests for MessageType enum."""

    def test_all_message_types(self):
        """All expected message types should exist."""
        assert MessageType.PLAN == "plan"
        assert MessageType.TASK == "task"
        assert MessageType.RESULT == "result"
        assert MessageType.FINDING == "finding"
        assert MessageType.REVIEW_REQUEST == "review_req"
        assert MessageType.VERDICT == "verdict"
        assert MessageType.DELIBERATE == "deliberate"
        assert MessageType.VOTE == "vote"
        assert MessageType.STATUS == "status"
        assert MessageType.COMPLETE == "complete"


class TestCouncilMessage:
    """Tests for CouncilMessage dataclass."""

    def test_default_values(self):
        """Test default field values."""
        msg = CouncilMessage(
            msg_type=MessageType.PLAN,
            sender="strategist",
            recipient="council",
        )
        assert msg.msg_type == MessageType.PLAN
        assert msg.sender == "strategist"
        assert msg.recipient == "council"
        assert msg.payload == {}
        assert msg.msg_id != ""
        assert msg.timestamp > 0

    def test_custom_payload(self):
        """Test with custom payload."""
        msg = CouncilMessage(
            msg_type=MessageType.TASK,
            sender="council",
            recipient="specialist",
            payload={"task": "scan", "target": "example.com"},
        )
        assert msg.payload == {"task": "scan", "target": "example.com"}

    def test_msg_id_generation(self):
        """Test msg_id is generated with correct format."""
        msg = CouncilMessage(
            msg_type=MessageType.PLAN,
            sender="strategist",
            recipient="council",
        )
        # Format is: sender:msg_type:timestamp (uses enum repr, not value)
        assert msg.msg_id.startswith("strategist:MessageType.PLAN:")

    def test_to_dict(self):
        """Test serialization to dict."""
        msg = CouncilMessage(
            msg_type=MessageType.TASK,
            sender="council",
            recipient="specialist",
            payload={"task": "scan"},
            msg_id="test-id-123",
        )
        d = msg.to_dict()
        assert d["id"] == "test-id-123"
        assert d["type"] == "task"
        assert d["from"] == "council"
        assert d["to"] == "specialist"
        assert d["payload"] == {"task": "scan"}
        assert "ts" in d


class TestSharedInbox:
    """Tests for SharedInbox thread-safe message queue."""

    def test_init_creates_queue(self):
        """Initializes with empty queue and history."""
        inbox = SharedInbox()
        assert inbox.pending_count == 0
        assert inbox.history(10) == []

    def test_post_adds_message(self):
        """post() adds message to queue and history."""
        inbox = SharedInbox()
        msg = CouncilMessage(
            msg_type=MessageType.TASK,
            sender="council",
            recipient="specialist",
        )
        inbox.post(msg)
        assert inbox.pending_count == 1
        assert len(inbox.history(10)) == 1
        assert inbox.history(10)[0].msg_id == msg.msg_id

    def test_get_returns_message(self):
        """get() returns next message."""
        inbox = SharedInbox()
        msg = CouncilMessage(
            msg_type=MessageType.TASK,
            sender="council",
            recipient="specialist",
        )
        inbox.post(msg)
        retrieved = inbox.get(timeout=0.1)
        assert retrieved is not None
        assert retrieved.msg_id == msg.msg_id

    def test_get_returns_none_on_timeout(self):
        """get() returns None when queue is empty."""
        inbox = SharedInbox()
        result = inbox.get(timeout=0.01)
        assert result is None

    def test_drain_returns_multiple_messages(self):
        """drain() returns up to limit messages."""
        inbox = SharedInbox()
        for i in range(5):
            msg = CouncilMessage(
                msg_type=MessageType.TASK,
                sender="council",
                recipient="specialist",
                payload={"index": i},
            )
            inbox.post(msg)

        drained = inbox.drain(limit=3)
        assert len(drained) == 3
        assert inbox.pending_count == 2

    def test_drain_limits_results(self):
        """drain() respects limit parameter."""
        inbox = SharedInbox()
        for i in range(10):
            msg = CouncilMessage(
                msg_type=MessageType.TASK,
                sender="council",
                recipient="specialist",
            )
            inbox.post(msg)

        drained = inbox.drain(limit=3)
        assert len(drained) == 3

    def test_history_returns_recent(self):
        """history() returns recent messages."""
        inbox = SharedInbox()
        for i in range(5):
            msg = CouncilMessage(
                msg_type=MessageType.TASK,
                sender="council",
                recipient="specialist",
                payload={"index": i},
            )
            inbox.post(msg)

        hist = inbox.history(last_n=3)
        assert len(hist) == 3
        assert hist[0].payload.get("index") == 2  # third message (0-indexed)

    def test_history_text_formatting(self):
        """history_text() returns formatted string."""
        inbox = SharedInbox()
        msg = CouncilMessage(
            msg_type=MessageType.TASK,
            sender="council",
            recipient="specialist",
            payload={"task": "scan"},
        )
        inbox.post(msg)

        text = inbox.history_text(last_n=1)
        assert "[task]" in text
        assert "council → specialist" in text
        assert "scan" in text

    def test_history_text_empty(self):
        """history_text() returns message when empty."""
        inbox = SharedInbox()
        text = inbox.history_text()
        assert "(no messages yet)" in text

    def test_post_drops_when_full(self):
        """post() drops message when queue is full."""
        inbox = SharedInbox(maxsize=1)
        msg1 = CouncilMessage(msg_type=MessageType.TASK, sender="a", recipient="b")
        msg2 = CouncilMessage(msg_type=MessageType.TASK, sender="c", recipient="d")
        inbox.post(msg1)
        inbox.post(msg2)  # Should be dropped
        assert inbox.pending_count == 1
        assert inbox.history(10)[0].sender == "a"


class TestAgentCouncilInit:
    """Tests for AgentCouncil initialization."""

    def test_init_sets_attributes(self):
        """__init__ sets all provided attributes."""
        mock_strategist = Mock()
        mock_specialist = Mock()
        mock_critic = Mock()
        mock_callback = Mock()

        council = AgentCouncil(
            strategist=mock_strategist,
            specialist=mock_specialist,
            critic=mock_critic,
            target="example.com",
            max_rounds=10,
            risk_threshold="high",
            callback=mock_callback,
        )

        assert council.strategist == mock_strategist
        assert council.specialist == mock_specialist
        assert council.critic == mock_critic
        assert council.target == "example.com"
        assert council.max_rounds == 10
        assert council.risk_threshold == "high"
        assert council.callback == mock_callback

    def test_default_risk_levels(self):
        """RISK_LEVELS should have correct values."""
        assert AgentCouncil.RISK_LEVELS == {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def test_init_initializes_collections(self):
        """__init__ initializes empty collections."""
        mock_strategist = Mock()
        mock_specialist = Mock()
        mock_critic = Mock()

        council = AgentCouncil(
            strategist=mock_strategist,
            specialist=mock_specialist,
            critic=mock_critic,
        )

        assert isinstance(council.inbox, SharedInbox)
        assert council.all_findings == []
        assert council.validated_findings == []
        assert council.false_positives == []
        assert council.action_log == []
        assert council.start_time == 0.0
        assert council.token_usage == {
            "strategist": 0,
            "specialist": 0,
            "critic": 0,
        }


class TestAgentCouncilRequiresDeliberation:
    """Tests for _requires_deliberation method."""

    def test_returns_false_for_low_risk_with_critical_threshold(self):
        """Low risk should not require deliberation with critical threshold."""
        council = AgentCouncil(strategist=Mock(), specialist=Mock(), critic=Mock(), risk_threshold="critical")
        assert council._requires_deliberation("low") is False
        assert council._requires_deliberation("medium") is False
        assert council._requires_deliberation("high") is False
        assert council._requires_deliberation("critical") is True

    def test_returns_true_for_high_risk_with_high_threshold(self):
        """High risk should require deliberation with high threshold."""
        council = AgentCouncil(strategist=Mock(), specialist=Mock(), critic=Mock(), risk_threshold="high")
        assert council._requires_deliberation("low") is False
        assert council._requires_deliberation("medium") is False
        assert council._requires_deliberation("high") is True
        assert council._requires_deliberation("critical") is True

    def test_case_insensitive(self):
        """Risk comparison should be case-insensitive."""
        council = AgentCouncil(strategist=Mock(), specialist=Mock(), critic=Mock(), risk_threshold="high")
        assert council._requires_deliberation("HIGH") is True
        assert council._requires_deliberation("High") is True
        assert council._requires_deliberation("high") is True


class TestAgentCouncilDeliberate:
    """Tests for _deliberate method."""

    def test_returns_true_when_both_approve(self):
        """Should return True when both AI agents approve."""
        mock_strategist = Mock()
        mock_strategist.vote.return_value = "approve"
        mock_critic = Mock()
        mock_critic.vote.return_value = "approve"

        council = AgentCouncil(strategist=mock_strategist, specialist=Mock(), critic=mock_critic)
        task = {"description": "test task", "risk": "high"}
        council.validated_findings = []

        with patch("elengenix.scanning.agent_council.logger") as mock_logger:
            result = council._deliberate(task)

        assert result is True
        assert mock_logger.info.called

    def test_returns_false_when_both_deny(self):
        """Should return False when both AI agents deny."""
        mock_strategist = Mock()
        mock_strategist.vote.return_value = "deny"
        mock_critic = Mock()
        mock_critic.vote.return_value = "deny"

        council = AgentCouncil(strategist=mock_strategist, specialist=Mock(), critic=mock_critic)
        task = {"description": "test task", "risk": "high"}
        council.validated_findings = []

        result = council._deliberate(task)
        assert result is False

    def test_returns_false_on_tie(self):
        """Should return False on tie (conservative default)."""
        mock_strategist = Mock()
        mock_strategist.vote.return_value = "approve"
        mock_critic = Mock()
        mock_critic.vote.return_value = "deny"

        council = AgentCouncil(strategist=mock_strategist, specialist=Mock(), critic=mock_critic)
        task = {"description": "test task", "risk": "high"}
        council.validated_findings = []

        result = council._deliberate(task)
        assert result is False

    def test_handles_strategist_exception(self):
        """Should default to approve on strategist exception."""
        mock_strategist = Mock()
        mock_strategist.vote.side_effect = Exception("AI error")
        mock_critic = Mock()
        mock_critic.vote.return_value = "approve"

        council = AgentCouncil(strategist=mock_strategist, specialist=Mock(), critic=mock_critic)
        task = {"description": "test task", "risk": "high"}
        council.validated_findings = []

        result = council._deliberate(task)
        assert result is True  # both approve -> majority

    def test_handles_critic_exception(self):
        """Should default to approve on critic exception."""
        mock_strategist = Mock()
        mock_strategist.vote.return_value = "approve"
        mock_critic = Mock()
        mock_critic.vote.side_effect = Exception("AI error")

        council = AgentCouncil(strategist=mock_strategist, specialist=Mock(), critic=mock_critic)
        task = {"description": "test task", "risk": "high"}
        council.validated_findings = []

        result = council._deliberate(task)
        assert result is True  # both approve -> majority


class TestAgentCouncilRun:
    """Tests for run method (partial - mocking dependencies)."""

    def test_returns_default_plan_when_strategist_empty(self):
        """Should use default plan when strategist returns empty."""
        mock_strategist = Mock()
        mock_strategist.plan.return_value = []
        mock_strategist.model_label = "Strategist"
        mock_strategist.total_tokens_used = 0
        mock_specialist = Mock()
        mock_specialist.model_label = "Specialist"
        mock_specialist.total_tokens_used = 0
        # Mock execute_task to return an object with findings=[]
        mock_specialist.execute_task.return_value = Mock(findings=[])
        mock_critic = Mock()
        mock_critic.model_label = "Critic"
        mock_critic.total_tokens_used = 0

        council = AgentCouncil(
            strategist=mock_strategist,
            specialist=mock_specialist,
            critic=mock_critic,
            target="example.com",
        )

        with patch.object(council, "_emit") as mock_emit:
            result = council.run("scan example.com")

        assert "No confirmed vulnerabilities found" in result or "Total raw findings" in result
        mock_strategist.plan.assert_called_once()

    def test_emits_start_messages(self):
        """Should emit startup messages with agent labels."""
        mock_strategist = Mock()
        mock_strategist.plan.return_value = [
            {"description": "recon", "phase": "recon", "status": "pending"}
        ]
        mock_strategist.model_label = "Strategist-AI"
        mock_strategist.total_tokens_used = 0
        mock_specialist = Mock()
        mock_specialist.model_label = "Specialist-AI"
        mock_specialist.total_tokens_used = 0
        # execute_task needs to return an object with findings=[]
        mock_specialist.execute_task.return_value = Mock(findings=[])
        mock_critic = Mock()
        mock_critic.model_label = "Critic-AI"
        mock_critic.total_tokens_used = 0

        council = AgentCouncil(
            strategist=mock_strategist,
            specialist=mock_specialist,
            critic=mock_critic,
            target="test.com",
        )
        # Ensure token_usage has proper integer values
        council.token_usage = {"strategist": 0, "specialist": 0, "critic": 0}

        with patch.object(council, "_emit") as mock_emit:
            council.run("scan test.com")

        emit_calls = [str(c) for c in mock_emit.call_args_list]
        assert any("TeamAegis v2 starting" in c for c in emit_calls)
        assert any("Strategist-AI" in c for c in emit_calls)
        assert any("Specialist-AI" in c for c in emit_calls)
        assert any("Critic-AI" in c for c in emit_calls)


class TestAgentCouncilEmit:
    """Tests for _emit method."""

    def test_logs_and_calls_callback(self):
        """Should log and call callback."""
        council = AgentCouncil(strategist=Mock(), specialist=Mock(), critic=Mock())
        mock_callback = Mock()
        council.callback = mock_callback

        with patch("elengenix.scanning.agent_council.logger") as mock_logger:
            with patch("elengenix.scanning.agent_council.console") as mock_console:
                council._emit("Test message")
                mock_logger.info.assert_called_once_with("Test message")
                mock_console.print.assert_called_once()
                mock_callback.assert_called_once_with("Test message")

    def test_handles_callback_exception(self):
        """Should not raise when callback fails."""
        council = AgentCouncil(strategist=Mock(), specialist=Mock(), critic=Mock())
        council.callback = Mock(side_effect=Exception("callback error"))

        with patch("elengenix.scanning.agent_council.logger"):
            with patch("elengenix.scanning.agent_council.console"):
                council._emit("Test")  # Should not raise


class TestAgentCouncilBuildReport:
    """Tests for _build_report method."""

    def test_builds_report_with_findings(self):
        """Should build markdown report with findings."""
        mock_strategist = Mock()
        mock_strategist.model_label = "Strategist"
        mock_specialist = Mock()
        mock_specialist.model_label = "Specialist"
        mock_critic = Mock()
        mock_critic.model_label = "Critic"

        council = AgentCouncil(
            strategist=mock_strategist,
            specialist=mock_specialist,
            critic=mock_critic,
            target="example.com",
        )
        council.validated_findings = [
            {
                "severity": "high",
                "title": "SQL Injection",
                "target": "example.com/login",
                "url": "http://example.com/login",
                "_phase": "scanning",
                "_task": "sql scan",
                "_cvss": 7.5,
                "_confidence": "high",
                "description": "SQL injection in login form",
                "_critic_notes": "Fix with parameterized queries",
            }
        ]
        council.action_log = ["Step 1", "Step 2"]
        council.token_usage = {"strategist": 100, "specialist": 200, "critic": 50}

        report = council._build_report("Test objective", 120.5)

        assert "# TeamAegis Report — example.com" in report
        assert "Objective**: Test objective" in report
        assert "Duration**: 120s" in report
        assert "SQL Injection" in report
        assert "7.5" in report
        assert "Total Tokens" in report
        assert "Action Log" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
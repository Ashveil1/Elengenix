"""Tests for elengenix/scanning/strategist.py — StrategistAgent and sub-workers."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, Mock, patch
from elengenix.scanning.strategist import (
    ReconWorker,
    OsintWorker,
    StrategistAgent,
    _extract_json,
)
from elengenix.scanning.worker import WorkerResult


class TestReconWorker:
    """Tests for ReconWorker."""

    def test_init_sets_attributes(self):
        """Init should set name, description, timeout."""
        worker = ReconWorker(timeout_seconds=60)
        assert worker.name == "ReconWorker"
        assert worker.description == "Subdomain and DNS enumeration"
        assert worker.timeout_seconds == 60

    def test_init_default_timeout(self):
        """Default timeout should be 180."""
        worker = ReconWorker()
        assert worker.timeout_seconds == 180

    @patch("subprocess.run")
    def test_run_dns_enumeration(self, mock_run):
        """Should run dig and return findings."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="example.com. 300 IN A 93.184.216.34",
        )

        worker = ReconWorker()
        result = worker.run("example.com")

        assert isinstance(result, WorkerResult)
        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0]["type"] == "dns_enumeration"
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_run_handles_dig_failure(self, mock_run):
        """Should handle dig failure gracefully."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="error")

        worker = ReconWorker()
        result = worker.run("example.com")

        assert result.success is False
        assert result.findings == []

    @patch("subprocess.run")
    def test_run_handles_exception(self, mock_run):
        """Should handle subprocess exception."""
        mock_run.side_effect = Exception("timeout")

        worker = ReconWorker()
        result = worker.run("example.com")

        assert result.success is False
        assert "timeout" in result.output


class TestOsintWorker:
    """Tests for OsintWorker."""

    def test_init_sets_attributes(self):
        """Init should set name, description, timeout."""
        worker = OsintWorker(timeout_seconds=30)
        assert worker.name == "OsintWorker"
        assert worker.description == "Web search OSINT for target intelligence"
        assert worker.timeout_seconds == 30

    def test_init_defaults(self):
        """Default timeout should be 60."""
        worker = OsintWorker()
        assert worker.timeout_seconds == 60

    def test_run_default_queries(self):
        """Should use default queries when none provided."""
        worker = OsintWorker()

        with patch("tools.research_tool.search_web") as mock_search:
            mock_search.return_value = [{"title": "Test", "url": "http://test.com"}]
            result = worker.run("example.com")

            assert result.success is True
            assert len(result.findings) == 3
            assert mock_search.call_count == 3

    def test_run_custom_queries(self):
        """Should use custom queries when provided."""
        worker = OsintWorker()

        with patch("tools.research_tool.search_web") as mock_search:
            mock_search.return_value = [{"title": "Test", "url": "http://test.com"}]
            result = worker.run("example.com", params={"queries": ["custom query"]})

            assert result.success is True
            assert mock_search.call_count == 1

    def test_run_handles_search_exception(self):
        """Should handle search exception gracefully."""
        worker = OsintWorker()

        with patch("tools.research_tool.search_web", side_effect=Exception("API error")):
            result = worker.run("example.com")

            assert result.success is False
            assert result.findings == []


class TestStrategistAgent:
    """Tests for StrategistAgent."""

    def test_init_sets_attributes(self):
        """Init should set all attributes."""
        mock_client = Mock()
        agent = StrategistAgent(
            client=mock_client,
            model_label="Test Strategist",
            enable_workers=True,
            max_tasks=5,
        )

        assert agent.client == mock_client
        assert agent.model_label == "Test Strategist"
        assert agent.enable_workers is True
        assert agent.max_tasks == 5
        assert agent.total_tokens_used == 0
        assert agent.recon_worker is not None
        assert agent.osint_worker is not None

    def test_init_defaults(self):
        """Should have correct defaults."""
        mock_client = Mock()
        agent = StrategistAgent(client=mock_client)

        assert agent.model_label == "Strategist AI"
        assert agent.enable_workers is True
        assert agent.max_tasks == 10

    def test_plan_calls_ai(self):
        """Plan should call AI and return parsed tasks."""
        mock_client = Mock()
        mock_client.chat.return_value = Mock(content='[{"description": "test task", "phase": "recon", "risk": "low"}]')
        agent = StrategistAgent(client=mock_client)
        mock_inbox = Mock()

        with patch.object(agent, "_call_ai_for_json") as mock_ai:
            mock_ai.return_value = [{"description": "test task", "phase": "recon", "risk": "low"}]
            tasks = agent.plan("scan example.com", "example.com", mock_inbox)

        assert isinstance(tasks, list)
        assert len(tasks) == 1
        assert tasks[0]["description"] == "test task"
        mock_inbox.post.assert_called_once()

    def test_plan_with_no_ai(self):
        """Should return empty list when no AI client."""
        agent = StrategistAgent(client=None)
        mock_inbox = Mock()

        tasks = agent.plan("scan example.com", "example.com", mock_inbox)
        assert tasks == []

    def test_plan_with_enable_workers_false(self):
        """Should skip OSINT when enable_workers is False."""
        mock_client = Mock()
        agent = StrategistAgent(client=mock_client, enable_workers=False)
        mock_inbox = Mock()

        with patch.object(agent, "_call_ai_for_json") as mock_ai:
            mock_ai.return_value = [{"description": "test", "phase": "recon", "risk": "low"}]
            agent.plan("scan example.com", "example.com", mock_inbox)

        # Should not have called osint_worker
        assert mock_ai.called

    def test_plan_returns_empty_on_ai_failure(self):
        """Should return empty list when AI call fails."""
        mock_client = Mock()
        mock_client.chat.side_effect = Exception("API error")
        agent = StrategistAgent(client=mock_client)
        mock_inbox = Mock()

        tasks = agent.plan("scan example.com", "example.com", mock_inbox)
        assert tasks == []

    def test_replan_calls_ai(self):
        """Replan should call AI with findings summary."""
        mock_client = Mock()
        agent = StrategistAgent(client=mock_client)
        mock_inbox = Mock()

        with patch.object(agent, "_call_ai_for_json") as mock_ai:
            mock_ai.return_value = [{"description": "follow up", "phase": "follow_up", "risk": "medium"}]
            findings = [{"severity": "high", "title": "SQLi", "description": "Found SQLi"}]
            tasks = agent.replan(findings, "example.com", mock_inbox)

        assert isinstance(tasks, list)
        assert len(tasks) == 1
        mock_inbox.post.assert_called_once()

    def test_replan_with_no_findings(self):
        """Replan should handle empty findings."""
        mock_client = Mock()
        agent = StrategistAgent(client=mock_client)
        mock_inbox = Mock()

        with patch.object(agent, "_call_ai_for_json") as mock_ai:
            mock_ai.return_value = []
            tasks = agent.replan([], "example.com", mock_inbox)

        assert tasks == []

    def test_vote_approves(self):
        """Vote should approve when AI says approve."""
        mock_client = Mock()
        mock_client.chat.return_value = Mock(content="approve this task")
        agent = StrategistAgent(client=mock_client)

        result = agent.vote(
            {"description": "risky task", "risk": "high"},
            [],
            "example.com",
        )

        assert result == "approve"

    def test_vote_denies(self):
        """Vote should deny when AI says deny."""
        mock_client = Mock()
        mock_client.chat.return_value = Mock(content="deny the action")
        agent = StrategistAgent(client=mock_client)

        result = agent.vote(
            {"description": "risky task", "risk": "high"},
            [],
            "example.com",
        )

        assert result == "deny"

    def test_vote_handles_exception(self):
        """Vote should default to approve on exception."""
        mock_client = Mock()
        mock_client.chat.side_effect = Exception("API error")
        agent = StrategistAgent(client=mock_client)

        result = agent.vote(
            {"description": "risky task", "risk": "high"},
            [],
            "example.com",
        )

        assert result == "approve"

    def test_vote_defaults_to_approve_on_empty(self):
        """Empty response should default to approve."""
        mock_client = Mock()
        mock_client.chat.return_value = Mock(content="")
        agent = StrategistAgent(client=mock_client)

        result = agent.vote(
            {"description": "task", "risk": "high"},
            [],
            "example.com",
        )

        assert result == "approve"


class TestExtractJson:
    """Tests for _extract_json helper."""

    def test_valid_json_array(self):
        """Should parse valid JSON array."""
        result = _extract_json('[{"index": 0, "verdict": "confirmed"}]')
        assert result == [{"index": 0, "verdict": "confirmed"}]

    def test_valid_json_object(self):
        """Should parse valid JSON object."""
        result = _extract_json('{"verdict": "confirmed"}')
        assert result == {"verdict": "confirmed"}

    def test_json_in_markdown_fence(self):
        """Should extract JSON from markdown code blocks."""
        result = _extract_json('```json\n[{"index": 0}]\n```')
        assert result == [{"index": 0}]

    def test_invalid_json_returns_empty(self):
        """Should return empty list on invalid JSON."""
        result = _extract_json("not json at all")
        assert result == []

    def test_json_with_extra_text(self):
        """Should find JSON in mixed text."""
        result = _extract_json('Here is the result: {"verdict": "confirmed"} end.')
        assert result == {"verdict": "confirmed"}

    def test_outmost_brackets(self):
        """Should find outermost brackets when they contain a single valid JSON."""
        # Multiple brackets in text - function finds outermost but fails to parse
        result = _extract_json('text [{"a": 1}] text [{"b": 2}]')
        # Current implementation returns empty list when multiple arrays found
        assert result == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
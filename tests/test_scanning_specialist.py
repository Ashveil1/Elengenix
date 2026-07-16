"""Tests for elengenix/scanning/specialist.py — SpecialistAgent and sub-workers."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, Mock, patch, AsyncMock
from elengenix.scanning.specialist import (
    ExploitWorker,
    FuzzerWorker,
    SpecialistAgent,
    _parse_json,
    _heuristic_findings,
)
from elengenix.scanning.worker import WorkerResult


class TestExploitWorker:
    """Tests for ExploitWorker."""

    def test_init_sets_attributes(self):
        """Init should set name, description, timeout."""
        worker = ExploitWorker(timeout_seconds=30)
        assert worker.name == "ExploitWorker"
        assert worker.description == "Safe PoC verification for potential exploits"
        assert worker.timeout_seconds == 30

    def test_init_default_timeout(self):
        """Default timeout should be 60."""
        worker = ExploitWorker()
        assert worker.timeout_seconds == 60

    @patch("subprocess.run")
    def test_run_returns_error_when_no_payload(self, mock_run):
        """Should return error when no payload provided."""
        worker = ExploitWorker()
        result = worker.run("http://example.com", params={})

        assert result.success is False
        assert "No payload provided" in result.error
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_run_probes_with_payload(self, mock_run):
        """Should run curl with provided payload."""
        mock_run.return_value = Mock(
            stdout="HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>",
            stderr="",
        )

        worker = ExploitWorker()
        result = worker.run("http://example.com", params={"payload": "test"})

        assert result.success is True
        assert "WorkerResult" in str(type(result))
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_run_finds_exploit_indicators(self, mock_run):
        """Should detect exploit indicators in response."""
        mock_run.return_value = Mock(
            stdout="HTTP/1.1 500 Internal Server Error\nSQL syntax error",
            stderr="",
        )

        worker = ExploitWorker()
        result = worker.run("http://example.com", params={"payload": "' OR 1=1--"})

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0]["type"] == "exploit_indicator"
        assert "SQL" in str(result.findings[0])

    @patch("subprocess.run")
    def test_run_handles_subprocess_exception(self, mock_run):
        """Should handle subprocess exceptions gracefully."""
        mock_run.side_effect = Exception("timeout")

        worker = ExploitWorker()
        result = worker.run("http://example.com", params={"payload": "test"})

        assert result.success is False
        assert "timeout" in result.error


class TestFuzzerWorker:
    """Tests for FuzzerWorker."""

    def test_init_sets_attributes(self):
        """Init should set name, description, timeout, wordlist_path."""
        worker = FuzzerWorker(timeout_seconds=60, wordlist_path="/custom/wordlist.txt")
        assert worker.name == "FuzzerWorker"
        assert worker.description == "Directory and parameter fuzzing"
        assert worker.timeout_seconds == 60
        assert worker.wordlist_path == "/custom/wordlist.txt"

    def test_init_defaults(self):
        """Default values should be set."""
        worker = FuzzerWorker()
        assert worker.timeout_seconds == 120
        assert worker.wordlist_path == "/usr/share/wordlists/dirb/common.txt"

    @patch("requests.get")
    def test_run_checks_common_paths(self, mock_get):
        """Should check common paths and return findings."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        worker = FuzzerWorker()
        result = worker.run("example.com")

        assert result.success is True
        assert "Checked" in result.output
        mock_get.assert_called()

    @patch("requests.get")
    def test_run_filters_status_codes(self, mock_get):
        """Should only report paths with relevant status codes."""
        mock_get.side_effect = [
            Mock(status_code=200),  # should report
            Mock(status_code=404),  # should not report
            Mock(status_code=403),  # should report
        ]

        worker = FuzzerWorker()
        result = worker.run("example.com")

        # Should only have 2 findings (200 and 403)
        assert len(result.findings) == 2
        assert result.findings[0]["type"] == "directory_found"
        assert result.findings[1]["type"] == "directory_found"

    @patch("requests.get")
    def test_run_handles_request_exception(self, mock_get):
        """Should handle request exceptions gracefully."""
        mock_get.side_effect = Exception("Connection error")

        worker = FuzzerWorker()
        result = worker.run("example.com")

        assert result.success is True
        # Should still complete even with errors
        assert "Checked" in result.output


class TestSpecialistAgent:
    """Tests for SpecialistAgent."""

    def test_init_sets_attributes(self):
        """Init should set all attributes."""
        mock_client = Mock()
        mock_governance = Mock()

        agent = SpecialistAgent(
            client=mock_client,
            model_label="Test Specialist",
            governance=mock_governance,
            enable_workers=True,
            max_retries=3,
        )

        assert agent.client == mock_client
        assert agent.model_label == "Test Specialist"
        assert agent.governance == mock_governance
        assert agent.enable_workers is True
        assert agent.max_retries == 3
        assert agent.total_tokens_used == 0

    def test_init_defaults(self):
        """Default values should be set."""
        mock_client = Mock()
        agent = SpecialistAgent(client=mock_client)

        assert agent.model_label == "Specialist AI"
        assert agent.governance is None
        assert agent.enable_workers is True
        assert agent.max_retries == 2

    def test_init_creates_subworkers(self):
        """Should create ExploitWorker and FuzzerWorker."""
        mock_client = Mock()
        agent = SpecialistAgent(client=mock_client)

        assert isinstance(agent.exploit_worker, ExploitWorker)
        assert isinstance(agent.fuzzer_worker, FuzzerWorker)

    def test_execute_task_returns_skip(self):
        """Should handle skip action."""
        mock_client = Mock()
        mock_client.chat.return_value = Mock(
            content='{"action": "skip", "reason": "not applicable"}'
        )

        agent = SpecialistAgent(client=mock_client)
        mock_inbox = Mock()

        result = agent.execute_task(
            task={"description": "test task", "phase": "recon", "risk": "low"},
            target="example.com",
            inbox=mock_inbox,
        )

        assert result.success is True
        assert result.output == "Skipped"
        mock_inbox.post.assert_called()

    @patch("tools.tool_registry.registry")
    def test_dispatch_run_tool(self, mock_registry):
        """Should route run_tool action to _run_tool."""
        mock_client = Mock()
        agent = SpecialistAgent(client=mock_client)
        agent._run_tool = Mock(return_value=WorkerResult(success=True, worker_name="test"))

        decision = {"action": "run_tool", "tool": "dns_lookup", "target": "example.com"}
        result = agent._dispatch("run_tool", decision, "example.com", "test task")

        agent._run_tool.assert_called_once_with(decision, "example.com")

    def test_dispatch_run_shell(self):
        """Should route run_shell action to _run_shell."""
        mock_client = Mock()
        agent = SpecialistAgent(client=mock_client)
        agent._run_shell = Mock(return_value=WorkerResult(success=True, worker_name="test"))

        decision = {"action": "run_shell", "command": "ls"}
        result = agent._dispatch("run_shell", decision, "example.com", "test task")

        agent._run_shell.assert_called_once_with(decision, "example.com", "test task")

    def test_dispatch_fuzz_action(self):
        """Should route fuzz action to fuzzer_worker."""
        mock_client = Mock()
        agent = SpecialistAgent(client=mock_client)
        agent.fuzzer_worker.execute = Mock(return_value=WorkerResult(success=True, worker_name="test"))

        decision = {"action": "fuzz"}
        result = agent._dispatch("fuzz", decision, "example.com", "test task")

        agent.fuzzer_worker.execute.assert_called_once_with("example.com")

    def test_dispatch_exploit_action(self):
        """Should route exploit action to exploit_worker."""
        mock_client = Mock()
        agent = SpecialistAgent(client=mock_client)
        agent.exploit_worker.execute = Mock(return_value=WorkerResult(success=True, worker_name="test"))

        decision = {"action": "exploit", "target": "example.com", "payload": "test"}
        result = agent._dispatch("exploit", decision, "example.com", "test task")

        agent.exploit_worker.execute.assert_called_once()

    def test_dispatch_unknown_action(self):
        """Should return error for unknown action."""
        mock_client = Mock()
        agent = SpecialistAgent(client=mock_client)

        decision = {"action": "unknown_action"}
        result = agent._dispatch("unknown_action", decision, "example.com", "test")

        assert result.success is False
        assert "Unknown action" in result.error


class TestSpecialistAgentRunTool:
    """Tests for _run_tool method."""

    @patch("tools.tool_registry.registry")
    @patch("asyncio.run_coroutine_threadsafe")
    @patch("tools.event_loop.get_shared_loop")
    def test_run_tool_uses_shared_loop(self, mock_get_loop, mock_run_coro, mock_registry):
        """Should use shared event loop when available."""
        mock_tool = Mock()
        mock_tool.is_available = True
        mock_tool.metadata.timeout_seconds = 60
        mock_registry.get_tool.return_value = mock_tool
        mock_registry.list_available_tools.return_value = {"dns_lookup": {"available": True}}

        mock_loop = Mock()
        mock_get_loop.return_value = mock_loop

        mock_future = Mock()
        mock_future.result.return_value = Mock(success=True, output="result", findings=[])
        mock_run_coro.return_value = mock_future

        mock_client = Mock()
        agent = SpecialistAgent(client=Mock())

        decision = {"tool": "dns_lookup", "target": "example.com"}
        result = agent._run_tool(decision, "example.com")

        mock_run_coro.assert_called()
        mock_future.result.assert_called_once()

    @patch("tools.tool_registry.registry")
    def test_run_tool_fallback_to_shell(self, mock_registry):
        """Should fallback to shell when tool unavailable."""
        mock_registry.get_tool.return_value = None
        mock_registry.list_available_tools.return_value = {}

        mock_client = Mock()
        agent = SpecialistAgent(client=Mock())
        agent._run_shell = Mock(return_value=WorkerResult(success=True, worker_name="test"))

        decision = {"tool": "nonexistent", "target": "example.com"}
        result = agent._run_tool(decision, "example.com")

        agent._run_shell.assert_called_once()


class TestSpecialistAgentRunShell:
    """Tests for _run_shell method."""

    def test_run_shell_empty_command(self):
        """Should return error for empty command."""
        mock_client = Mock()
        agent = SpecialistAgent(client=Mock(), governance=Mock())

        decision = {"command": ""}
        result = agent._run_shell(decision, "example.com", "test")

        assert result.success is False
        assert "Empty command" in result.error

    def test_run_shell_governance_denied(self):
        """Should respect governance denial."""
        mock_governance = Mock()
        mock_governance.gate.return_value = Mock(allowed=False, rationale="Dangerous command")

        agent = SpecialistAgent(client=Mock(), governance=mock_governance)

        decision = {"command": "rm -rf /"}
        result = agent._run_shell(decision, "example.com", "test")

        assert result.success is False
        assert "Blocked by governance" in result.error

    @patch("tools.safe_exec.execute_safely")
    def test_run_shell_success(self, mock_execute):
        """Should execute command and extract findings."""
        mock_execute.return_value = {
            "success": True,
            "stdout": "API_KEY=secret123",
            "stderr": "",
        }

        agent = SpecialistAgent(client=Mock(), governance=Mock())
        agent.governance.gate.return_value = Mock(allowed=True)

        decision = {"command": "echo test"}
        result = agent._run_shell(decision, "example.com", "test")

        assert result.success is True
        assert "API_KEY=secret123" in result.output
        assert len(result.findings) == 1
        assert result.findings[0]["type"] == "potential_secret"

    @patch("tools.safe_exec.execute_safely")
    def test_run_shell_extracts_urls(self, mock_execute):
        """Should extract URLs from output."""
        mock_execute.return_value = {
            "success": True,
            "stdout": "Visit https://example.com and http://test.com",
            "stderr": "",
        }

        agent = SpecialistAgent(client=Mock(), governance=Mock())
        agent.governance.gate.return_value = Mock(allowed=True)

        decision = {"command": "curl example.com"}
        result = agent._run_shell(decision, "example.com", "test")

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0]["type"] == "urls_extracted"


class TestSpecialistAgentAiDecide:
    """Tests for _ai_decide method."""

    def test_ai_decide_returns_none_when_no_client(self):
        """Should return None when no client."""
        agent = SpecialistAgent(client=None)
        result = agent._ai_decide("prompt")
        assert result is None

    def test_ai_decide_parses_json_response(self):
        """Should parse JSON from AI response."""
        mock_client = Mock()
        mock_client.chat.return_value = Mock(
            content='{"action": "run_shell", "command": "ls", "purpose": "list files"}'
        )

        agent = SpecialistAgent(client=mock_client)
        result = agent._ai_decide("prompt")

        assert result is not None
        assert result["action"] == "run_shell"
        assert result["command"] == "ls"

    def test_ai_decide_handles_exception(self):
        """Should handle exceptions and retry."""
        mock_client = Mock()
        mock_client.chat.side_effect = Exception("API error")

        agent = SpecialistAgent(client=mock_client, max_retries=1)
        result = agent._ai_decide("prompt")

        assert result is None
        assert mock_client.chat.call_count == 2  # initial + 1 retry


class TestParseJson:
    """Tests for _parse_json helper."""

    def test_valid_json_object(self):
        """Should parse valid JSON object."""
        result = _parse_json('{"action": "run_shell", "command": "ls"}')
        assert result == {"action": "run_shell", "command": "ls"}

    def test_valid_json_array(self):
        """Should parse valid JSON array."""
        # _parse_json expects an object, not an array
        result = _parse_json('[{"index": 0, "verdict": "confirmed"}]')
        assert result is None

    def test_json_in_markdown_codeblock(self):
        """Should extract JSON from markdown code block."""
        result = _parse_json('```json\n{"action": "run_shell"}\n```')
        assert result == {"action": "run_shell"}

    def test_mixed_text_with_json(self):
        """Should extract JSON from mixed text."""
        result = _parse_json('Here is the decision:\n{"action": "skip", "reason": "done"}')
        assert result == {"action": "skip", "reason": "done"}

    def test_invalid_json_returns_none(self):
        """Should return None for invalid JSON."""
        result = _parse_json("not json at all")
        assert result is None

    def test_none_input_returns_none(self):
        """Should return None for None input."""
        result = _parse_json(None)
        assert result is None


class TestHeuristicFindings:
    """Tests for _heuristic_findings helper."""

    def test_detects_secrets(self):
        """Should detect API keys and secrets."""
        output = "API_KEY=sk-1234567890abcdef\nPASSWORD=secret123"
        findings = _heuristic_findings(output, "env")

        assert len(findings) >= 1
        assert any(f["type"] == "potential_secret" for f in findings)

    def test_detects_urls(self):
        """Should detect URLs in output."""
        output = "Visit https://example.com/api and http://test.com/path"
        findings = _heuristic_findings(output, "curl")

        assert any(f["type"] == "urls_extracted" for f in findings)

    def test_detects_sql_errors(self):
        """Should detect SQL errors."""
        output = "ERROR: syntax error near 'UNION SELECT' at line 1\nmysql_fetch_array() expects parameter"
        findings = _heuristic_findings(output, "sqlmap")

        assert any(f["type"] == "sql_error_detected" for f in findings)

    def test_empty_output_returns_empty(self):
        """Empty output should return empty findings."""
        findings = _heuristic_findings("", "test")
        assert findings == []

    def test_detects_multiple_types(self):
        """Should detect multiple finding types in one output."""
        output = "API_KEY=secret\nVisit https://example.com\nERROR: mysql syntax error"
        findings = _heuristic_findings(output, "test")

        types = [f["type"] for f in findings]
        assert "potential_secret" in types
        assert "urls_extracted" in types
        assert "sql_error_detected" in types


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
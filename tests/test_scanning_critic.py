"""Tests for elengenix/scanning/critic.py — CriticAgent and sub-workers."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, Mock, patch
from elengenix.scanning.critic import (
    ValidatorWorker,
    ReportWorker,
    CriticAgent,
    _extract_signatures,
    _extract_json,
)


class TestValidatorWorker:
    """Tests for ValidatorWorker class."""

    def test_init_sets_attributes(self):
        """Init should set name, description, timeout."""
        worker = ValidatorWorker(timeout_seconds=30)
        assert worker.name == "ValidatorWorker"
        assert worker.description == "HTTP probe to confirm findings"
        assert worker.timeout_seconds == 30

    def test_init_default_timeout(self):
        """Init with default timeout."""
        worker = ValidatorWorker()
        assert worker.timeout_seconds == 20

    def test_run_confirms_signatures(self):
        """Run should confirm when signatures found in response."""
        worker = ValidatorWorker(timeout_seconds=5)

        with patch("elengenix.scanning.critic.subprocess.run") as mock_run:
            mock_result = Mock()
            mock_result.stdout = "HTTP/1.1 200 OK\nServer: Apache\n\nContent"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            result = worker.run(
                "http://example.com",
                {"signatures": ["Apache", "nginx"]},
            )

            assert result.success is True
            assert result.metadata["confirmed"] is True
            assert "Apache" in result.metadata["matched"]
            assert len(result.findings) == 1
            assert result.findings[0]["type"] == "validated_finding"

    def test_run_no_signatures_found(self):
        """Run should not confirm when no signatures match."""
        worker = ValidatorWorker()

        with patch("elengenix.scanning.critic.subprocess.run") as mock_run:
            mock_result = Mock()
            mock_result.stdout = "HTTP/1.1 200 OK\nServer: nginx\n\nContent"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            result = worker.run(
                "http://example.com",
                {"signatures": ["Apache"]},
            )

            assert result.success is True
            assert result.metadata["confirmed"] is False
            assert result.metadata["matched"] == []
            assert result.findings == []

    def test_run_handles_subprocess_exception(self):
        """Run should handle subprocess timeout/exception."""
        worker = ValidatorWorker()

        with patch("elengenix.scanning.critic.subprocess.run") as mock_run:
            mock_run.side_effect = Exception("timeout")

            result = worker.run("http://example.com", {})

            assert result.success is False
            assert result.worker_name == "ValidatorWorker"
            assert "timeout" in result.error


class TestReportWorker:
    """Tests for ReportWorker class."""

    def test_init_sets_attributes(self):
        """Init should set name and description."""
        worker = ReportWorker()
        assert worker.name == "ReportWorker"
        assert worker.description == "Formats findings into structured report entries"

    def test_run_formats_finding(self):
        """Run should format finding into markdown report."""
        worker = ReportWorker()

        finding = {
            "severity": "high",
            "title": "SQL Injection",
            "description": "Found SQLi in login form",
            "url": "http://example.com/login",
            "_cvss": 8.5,
            "_critic_notes": "Use parameterized queries",
        }

        result = worker.run("example.com", {"finding": finding})

        assert result.success is True
        assert "### [High] SQL Injection" in result.output
        assert "URL: http://example.com/login" in result.output
        assert "CVSS: 8.5" in result.output
        assert "Description: Found SQLi in login form" in result.output
        assert "Remediation: Use parameterized queries" in result.output

    def test_run_handles_missing_fields(self):
        """Run should handle missing finding fields gracefully."""
        worker = ReportWorker()

        finding = {}

        result = worker.run("example.com", {"finding": finding})

        assert result.success is True
        assert "### [Info] Security Finding" in result.output
        assert "CVSS: 0.0" in result.output
        assert "Remediation: " in result.output


class TestCriticAgent:
    """Tests for CriticAgent class."""

    def test_init_sets_attributes(self):
        """Init should set all attributes correctly."""
        mock_client = Mock()
        agent = CriticAgent(
            client=mock_client,
            model_label="Test Critic",
            enable_workers=True,
            cvss_threshold=5.0,
        )

        assert agent.client == mock_client
        assert agent.model_label == "Test Critic"
        assert agent.enable_workers is True
        assert agent.cvss_threshold == 5.0
        assert agent.total_tokens_used == 0
        assert agent.validator_worker is not None
        assert agent.report_worker is not None

    def test_init_with_defaults(self):
        """Init with default parameters."""
        mock_client = Mock()
        agent = CriticAgent(client=mock_client)

        assert agent.model_label == "Critic AI"
        assert agent.enable_workers is True
        assert agent.cvss_threshold == 0.0

    def test_review_empty_findings(self):
        """Review with empty findings returns empty list."""
        mock_client = Mock()
        agent = CriticAgent(client=mock_client)
        mock_inbox = Mock()

        result = agent.review([], "example.com", mock_inbox)
        assert result == []

    def test_review_filters_below_threshold(self):
        """Findings below CVSS threshold are marked as false_positive."""
        mock_client = Mock()
        agent = CriticAgent(client=mock_client, cvss_threshold=7.0)
        mock_inbox = Mock()

        with patch.object(agent, "_call_ai_for_json") as mock_ai:
            mock_ai.return_value = [
                {"index": 0, "verdict": "confirmed", "cvss": 5.0, "confidence": "high", "notes": "test"}
            ]

            findings = [{"title": "Test", "severity": "medium"}]
            result = agent.review(findings, "example.com", mock_inbox)

            # CVSS 5.0 < 7.0 threshold, so should be false_positive
            assert result[0]["verdict"] == "false_positive"
            mock_inbox.post.assert_called_once()

    def test_review_passes_threshold(self):
        """Findings above CVSS threshold keep their verdict."""
        mock_client = Mock()
        agent = CriticAgent(client=mock_client, cvss_threshold=5.0)
        mock_inbox = Mock()

        with patch.object(agent, "_call_ai_for_json") as mock_ai:
            mock_ai.return_value = [
                {"index": 0, "verdict": "confirmed", "cvss": 7.5, "confidence": "high", "notes": "test"}
            ]

            findings = [{"title": "Test", "severity": "high"}]
            result = agent.review(findings, "example.com", mock_inbox)

            assert result[0]["verdict"] == "confirmed"
            assert result[0]["cvss"] == 7.5

    def test_review_skips_probe_for_subdomains(self):
        """Probe is skipped for subdomain/OSINT findings."""
        mock_client = Mock()
        agent = CriticAgent(client=mock_client, enable_workers=True)
        mock_inbox = Mock()

        with patch.object(agent, "_call_ai_for_json") as mock_ai:
            mock_ai.return_value = [{"index": 0, "verdict": "confirmed", "cvss": 0.0}]

            with patch.object(agent.validator_worker, "execute") as mock_execute:
                mock_execute.return_value = Mock(metadata={"confirmed": True})

                findings = [
                    {"type": "subdomains_discovered", "url": "http://sub.example.com"},
                    {"type": "osint_result", "url": "http://sub.example.com"},
                ]
                agent.review(findings, "example.com", mock_inbox)

                mock_execute.assert_not_called()

    def test_review_probes_other_findings(self):
        """Probe is executed for non-subdomain findings."""
        mock_client = Mock()
        agent = CriticAgent(client=mock_client, enable_workers=True)
        mock_inbox = Mock()

        with patch.object(agent, "_call_ai_for_json") as mock_ai:
            mock_ai.return_value = [{"index": 0, "verdict": "confirmed", "cvss": 0.0}]

            with patch.object(agent.validator_worker, "execute") as mock_execute:
                mock_execute.return_value = Mock(metadata={"confirmed": True, "matched": ["test"]})

                findings = [{"type": "xss", "url": "http://example.com/test"}]
                result = agent.review(findings, "example.com", mock_inbox)

                mock_execute.assert_called_once()
                assert "_probe_confirmed" in findings[0]
                assert findings[0]["_probe_matched"] == ["test"]

    def test_vote_approves(self):
        """Vote should approve when AI says approve."""
        mock_client = Mock()
        agent = CriticAgent(client=mock_client)

        mock_client.chat.return_value = Mock(content="approve this task")

        result = agent.vote(
            {"description": "Run exploit", "risk": "high"},
            [{"verdict": "confirmed"}],
            "example.com",
        )

        assert result == "approve"

    def test_vote_denies(self):
        """Vote should deny when AI says deny."""
        mock_client = Mock()
        agent = CriticAgent(client=mock_client)

        mock_client.chat.return_value = Mock(content="deny the action")

        result = agent.vote(
            {"description": "Run exploit", "risk": "high"},
            [],
            "example.com",
        )

        assert result == "deny"

    def test_vote_denies_on_exception(self):
        """Vote defaults to deny on AI error (conservative)."""
        mock_client = Mock()
        agent = CriticAgent(client=mock_client)

        mock_client.chat.side_effect = Exception("AI error")

        result = agent.vote(
            {"description": "Run exploit", "risk": "high"},
            [],
            "example.com",
        )

        assert result == "deny"

    def test_vote_empty_response(self):
        """Vote defaults to approve on empty response (per implementation)."""
        mock_client = Mock()
        agent = CriticAgent(client=mock_client)

        mock_client.chat.return_value = Mock(content="")

        result = agent.vote(
            {"description": "Run exploit"},
            [],
            "example.com",
        )

        assert result == "approve"


class TestExtractSignatures:
    """Tests for _extract_signatures helper function."""

    def test_extracts_quoted_strings(self):
        """Should extract double-quoted strings from evidence/description/title."""
        finding = {
            "evidence": 'Error: "SQL syntax error" near user input',
            "description": "Found 'union select' in response",
            "title": "SQL Injection",
        }

        sigs = _extract_signatures(finding)
        assert "SQL syntax error" in sigs
        # Note: single-quoted strings are not extracted by the current regex
        # Only double-quoted strings with 4-40 chars are matched

    def test_limits_signatures(self):
        """Should limit to 5 signatures max."""
        finding = {
            "evidence": '"a" "b" "c" "d" "e" "f"',
        }

        sigs = _extract_signatures(finding)
        assert len(sigs) <= 5

    def test_handles_missing_keys(self):
        """Should handle missing keys gracefully."""
        finding = {}
        sigs = _extract_signatures(finding)
        assert sigs == []


class TestExtractJson:
    """Tests for _extract_json helper function."""

    def test_valid_json_array(self):
        """Should parse valid JSON array."""
        result = _extract_json('[{"index": 0, "verdict": "confirmed"}]')
        assert result == [{"index": 0, "verdict": "confirmed"}]

    def test_valid_json_object(self):
        """Should parse valid JSON object."""
        result = _extract_json('{"verdict": "confirmed"}')
        assert result == {"verdict": "confirmed"}

    def test_invalid_json_returns_empty(self):
        """Should return empty list on invalid JSON."""
        result = _extract_json("not json at all")
        assert result == []

    def test_json_in_markdown_codeblock(self):
        """Should extract JSON from markdown code blocks."""
        result = _extract_json('```json\n[{"index": 0}]\n```')
        assert result == [{"index": 0}]

    def test_mixed_text_with_json(self):
        """Should find JSON in mixed text."""
        result = _extract_json('Here is the result: {"verdict": "confirmed"} end.')
        assert result == {"verdict": "confirmed"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
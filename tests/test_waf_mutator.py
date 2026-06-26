"""tests/test_waf_mutator.py — Tests for the Dynamic WAF Bypass Payload Mutator."""

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tools.dynamic_waf_mutator import DynamicWAFMutator, DynamicWAFMutatorTool
from tools.tool_registry import ToolCategory, ToolResult


class TestDynamicWAFMutator:
    """Test the core DynamicWAFMutator AI loop and heuristic checks."""

    @pytest.fixture
    def mutator(self):
        return DynamicWAFMutator(base_url="http://test.target.com")

    def test_is_blocked_status_codes(self, mutator):
        """Test that common WAF status codes trigger blocked validation."""
        assert mutator._is_blocked(403, "Forbidden") is True
        assert mutator._is_blocked(406, "Not Acceptable") is True
        assert mutator._is_blocked(200, "Normal Response") is False

    def test_is_blocked_body_heuristics(self, mutator):
        """Test that common WAF block patterns in HTTP bodies trigger block validation."""
        assert mutator._is_blocked(200, "blocked by WAF under incident id 123") is True
        assert mutator._is_blocked(200, "Access Denied via Cloudflare") is True
        assert mutator._is_blocked(200, "Welcome to the site") is False

    def test_build_evasion_prompt_structure(self, mutator):
        """Test prompt building returns valid list of AIMessages with high context."""
        messages = mutator._build_evasion_prompt(
            failed_payload="<script>alert(1)</script>",
            vuln_type="Cross-Site Scripting",
            waf_name="cloudflare",
            status_code=403,
            headers='{"Server": "cloudflare"}',
            body_snippet="Access Denied",
            attempt=1,
        )
        assert len(messages) == 2
        assert messages[0].role == "system"
        assert messages[1].role == "user"
        assert "Cross-Site Scripting" in messages[1].content
        assert "cloudflare" in messages[1].content

    def test_run_mutation_loop_success_on_first_try(self, mutator):
        """Test that mutation loop exits immediately if the first request bypasses WAF."""
        # Mock _send_probe to return successful 200 OK
        mutator.evasion_engine._send_probe = MagicMock(
            return_value=(200, "Success Response", {"Server": "nginx"})
        )

        result = asyncio.run(
            mutator.run_mutation_loop(
                target_path="/login", base_payload="test_payload", vuln_type="SQLi", max_attempts=3
            )
        )
        assert result["success"] is True
        assert result["bypass_payload"] == "test_payload"
        assert result["attempts"] == 1

    def test_run_mutation_loop_llm_bypass_sequence(self, mutator):
        """Test that the loop queries the LLM and successfully bypasses WAF using the mutated payload."""
        # 1st probe fails with 403, 2nd probe succeeds with 200
        mutator.evasion_engine._send_probe = MagicMock(
            side_effect=[
                (403, "Access Denied", {"Server": "cloudflare"}),
                (200, "Payload Executed", {"Server": "cloudflare"}),
            ]
        )

        # Mock AI Client Manager to return a bypass candidate
        mock_response = MagicMock()
        mock_response.content = (
            '{"mutated_payload": "svg/onload=alert(1)", "reasoning": "Using SVG bypass"}'
        )

        mutator.ai_manager.chat = MagicMock(return_value=mock_response)

        result = asyncio.run(
            mutator.run_mutation_loop(
                target_path="/search",
                base_payload="<script>alert(1)</script>",
                vuln_type="XSS",
                max_attempts=3,
            )
        )
        assert result["success"] is True
        assert result["bypass_payload"] == "svg/onload=alert(1)"
        assert result["attempts"] == 2


class TestDynamicWAFMutatorTool:
    """Test the registration and execute wrapper of the WAF Evasion Mutator tool."""

    def test_tool_registration(self):
        """Test tool is registered in the global registry under correct metadata."""
        from tools.tool_registry import registry

        tool = registry.get_tool("dynamic_waf_mutator")
        assert tool is not None
        assert tool.metadata.category == ToolCategory.EXPLOITATION
        assert tool.is_available is True

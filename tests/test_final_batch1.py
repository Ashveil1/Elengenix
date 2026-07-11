"""tests/test_final_batch1.py

Comprehensive tests for:
  - agents/hybrid_agent.py
  - tools/multi_agent.py
  - tools/targeted_attacks.py
  - tools/hunt_engine.py

All network is mocked. No emoji anywhere.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ---------------------------------------------------------------------------
# fixtures / shared mocks
# ---------------------------------------------------------------------------


def _make_mock_client():
    client = MagicMock()
    client.provider = "openai"
    client.model = "gpt-4"
    client.chat = MagicMock(return_value=MagicMock(content='{"action": "none"}'))
    client.simple_chat = MagicMock(return_value="OK")
    return client


def _make_endpoint(url: str = "http://example.com/login", method: str = "POST", **kw):
    from tools.endpoint_discovery import Endpoint

    return Endpoint(url=url, method=method, **kw)


# ════════════════════════════════════════════════════════════════════════════
# SECTION 1: agents/hybrid_agent.py
# ════════════════════════════════════════════════════════════════════════════


class TestExtractJson:
    """Tests for the module-level _extract_json helper."""

    def test_extracts_json_object_direct(self):
        from agents.hybrid_agent import _extract_json

        text = '{"action": "run_command", "command": "echo hi"}'
        result = _extract_json(text)
        assert result["action"] == "run_command"
        assert result["command"] == "echo hi"

    def test_extracts_json_array_direct(self):
        from agents.hybrid_agent import _extract_json

        text = '[{"id": 1}, {"id": 2}]'
        result = _extract_json(text)
        assert isinstance(result, list)
        assert len(result) == 2

    def test_extracts_json_from_markdown_fence(self):
        from agents.hybrid_agent import _extract_json

        text = 'Some preamble\n```json\n{"key": "val"}\n```\nTrailing text'
        result = _extract_json(text)
        assert result["key"] == "val"

    def test_extracts_json_from_fence_without_language_tag(self):
        from agents.hybrid_agent import _extract_json

        text = '```\n{"x": 1}\n```'
        result = _extract_json(text)
        assert result["x"] == 1

    def test_extracts_from_embedded_curly_braces(self):
        from agents.hybrid_agent import _extract_json

        text = 'Here is the result: {"action": "done"} and more text'
        result = _extract_json(text)
        assert result["action"] == "done"

    def test_extracts_from_embedded_square_brackets(self):
        from agents.hybrid_agent import _extract_json

        text = 'Items: [{"name": "a"}, {"name": "b"}] end'
        result = _extract_json(text)
        assert isinstance(result, list)
        assert result[0]["name"] == "a"

    def test_raises_valueerror_for_no_json(self):
        from agents.hybrid_agent import _extract_json
        import pytest

        with pytest.raises(ValueError, match="No valid JSON"):
            _extract_json("No JSON here at all")

    def test_json_decode_error_inner_recoverable(self):
        from agents.hybrid_agent import _extract_json

        # Broken outer parse, but inner slice between first { and last } is valid
        text = 'junk {"valid": true} junk'
        result = _extract_json(text)
        assert result["valid"] is True


class TestHybridAgentInit:
    """Tests for HybridAgent.__init__."""

    def test_basic_init_defaults(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None, target="example.com")
        assert agent.target == "example.com"
        assert agent.max_steps == 50
        assert agent.enable_analysis is True
        assert agent.enable_memory is True
        assert agent.loop_threshold == 4
        assert agent._use_council is False

    def test_council_mode_detected(self):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        agent = HybridAgent(client=client, strategist_client=client)
        assert agent._use_council is True

    def test_council_not_used_when_no_separate_clients(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=_make_mock_client())
        assert agent._use_council is False

    def test_custom_params(self):
        from agents.hybrid_agent import HybridAgent

        cb = MagicMock()
        agent = HybridAgent(
            client=None,
            target="t",
            max_steps=10,
            strategist_interval=2,
            enable_analysis=False,
            enable_memory=False,
            loop_threshold=3,
            callback=cb,
            risk_threshold="high",
        )
        assert agent.max_steps == 10
        assert agent.strategist_interval == 2
        assert agent.enable_analysis is False
        assert agent.enable_memory is False
        assert agent.loop_threshold == 3
        assert agent.callback is cb
        assert agent._risk_threshold == "high"


class TestExtractFindings:
    """Tests for HybridAgent._extract_findings (static method)."""

    def test_empty_output(self):
        from agents.hybrid_agent import HybridAgent

        assert HybridAgent._extract_findings("", "ls") == []

    def test_empty_whitespace(self):
        from agents.hybrid_agent import HybridAgent

        assert HybridAgent._extract_findings("   \n  ", "echo hi") == []

    def test_nuclei_json_finding(self):
        from agents.hybrid_agent import HybridAgent

        nuclei_out = json.dumps(
            {
                "template-id": "cve-2021-44228",
                "info": {"name": "Log4Shell", "severity": "critical"},
                "matched-at": "http://target.com/api",
                "host": "target.com",
            }
        )
        findings = HybridAgent._extract_findings(nuclei_out, "nuclei")
        assert len(findings) == 1
        assert findings[0]["type"] == "vulnerability"
        assert findings[0]["severity"] == "critical"
        assert "Log4Shell" in findings[0]["title"]

    def test_httpx_probe_json(self):
        from agents.hybrid_agent import HybridAgent

        probe_out = json.dumps(
            {
                "url": "http://target.com",
                "webserver": "nginx",
                "tech": ["Python", "Django"],
                "status-code": 200,
                "title": "Home",
            }
        )
        findings = HybridAgent._extract_findings(probe_out, "httpx")
        assert len(findings) == 1
        assert findings[0]["type"] == "http_probe"

    def test_generic_finding_json(self):
        from agents.hybrid_agent import HybridAgent

        out = json.dumps({"vuln": "SQLi", "severity": "high", "url": "http://x.com"})
        findings = HybridAgent._extract_findings(out, "some_tool")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_dig_subdomains(self):
        from agents.hybrid_agent import HybridAgent

        dig_out = "api.example.com\nmail.example.com\nwww.example.com"
        findings = HybridAgent._extract_findings(dig_out, "dig example.com")
        assert len(findings) == 1
        assert findings[0]["type"] == "subdomains_discovered"
        assert "3" in findings[0]["title"]

    def test_extracted_urls(self):
        from agents.hybrid_agent import HybridAgent

        out = "Found: http://a.com/path http://b.com/other"
        findings = HybridAgent._extract_findings(out, "grep -r http")
        assert any(f.get("type") == "extracted_url" for f in findings)

    def test_potential_secrets(self):
        from agents.hybrid_agent import HybridAgent

        out = "API_KEY=sk_test_12345\nPASSWORD=hunter2"
        findings = HybridAgent._extract_findings(out, "env | grep pass")
        assert any(f.get("type") == "potential_secret" for f in findings)

    def test_jsonl_multi_lines(self):
        from agents.hybrid_agent import HybridAgent

        lines = [
            json.dumps(
                {
                    "template-id": "xss-1",
                    "info": {"name": "XSS", "severity": "high"},
                    "host": "a.com",
                }
            ),
            json.dumps(
                {
                    "template-id": "sqli-1",
                    "info": {"name": "SQLi", "severity": "critical"},
                    "host": "a.com",
                }
            ),
        ]
        findings = HybridAgent._extract_findings("\n".join(lines), "nuclei")
        assert len(findings) == 2


class TestIsDeadlocked:
    """Tests for HybridAgent._is_deadlocked."""

    def test_not_deadlocked_under_threshold(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None, loop_threshold=4)
        agent.action_history = [
            {"action": "run_command", "command": "ls"},
            {"action": "run_command", "command": "ls"},
        ]
        assert agent._is_deadlocked() is False

    def test_not_deadlocked_different_actions(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None, loop_threshold=4)
        agent.action_history = [
            {"action": "run_command", "command": "ls"},
            {"action": "run_command", "command": "pwd"},
            {"action": "run_tool", "tool": "nuclei"},
            {"action": "run_command", "command": "ls"},
        ]
        assert agent._is_deadlocked() is False

    def test_deadlocked_same_action(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None, loop_threshold=3)
        agent.action_history = [
            {"action": "run_command", "command": "echo hi"},
            {"action": "run_command", "command": "echo hi"},
            {"action": "run_command", "command": "echo hi"},
        ]
        assert agent._is_deadlocked() is True

    def test_deadlocked_run_tool(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None, loop_threshold=2)
        agent.action_history = [
            {"action": "run_tool", "tool": "nuclei"},
            {"action": "run_tool", "tool": "nuclei"},
        ]
        assert agent._is_deadlocked() is True


class TestShouldRunAnalysis:
    """Tests for HybridAgent._should_run_analysis."""

    def test_empty_string(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None)
        assert agent._should_run_analysis("") is False

    def test_simple_commands_skipped(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None)
        for cmd in ["ls -la", "cat file.txt", "echo hello", "pwd", "whoami", "date", "wc -l"]:
            assert agent._should_run_analysis(cmd) is False, f"Expected skip for: {cmd}"

    def test_complex_commands_run(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None)
        for cmd in [
            "nuclei -u http://x.com",
            "sqlmap --url http://x.com/login",
            "python3 exploit.py",
            "curl -X POST http://x.com/api",
        ]:
            assert agent._should_run_analysis(cmd) is True, f"Expected run for: {cmd}"


class TestAgentRef:
    """Tests for HybridAgent._agent_ref."""

    def test_agent_ref_has_governance(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None, governance=MagicMock())
        ref = agent._agent_ref()
        assert ref.governance is agent.governance

    def test_agent_ref_fallback_attrs(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None)
        ref = agent._agent_ref()
        assert hasattr(ref, "payload_mutator")
        assert hasattr(ref, "active_fuzzer")
        assert hasattr(ref, "bola_tester")
        assert hasattr(ref, "waf_detector")
        assert hasattr(ref, "logic_analyzer")


class TestFinalizeMission:
    """Tests for HybridAgent._finalize_mission."""

    def test_finalize_empty_findings(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None, target="test.com")
        agent.start_time = __import__("time").time() - 10
        agent.objective = "Find vulns"
        agent.action_history = [{"action": "run_command", "command": "echo"}]
        report = agent._finalize_mission()
        assert "Find vulns" in report
        assert "No structured findings" in report
        assert "Hybrid Mission Report" in report

    def test_finalize_with_findings(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=None, target="test.com")
        agent.start_time = __import__("time").time()
        agent.objective = "Security scan"
        agent.all_findings = [
            {"type": "xss", "severity": "high", "url": "http://x.com", "_tool": "nuclei"},
            {"type": "info_leak", "severity": "info", "_tool": "httpx"},
        ]
        agent.action_history = [{"action": "run_tool", "tool": "nuclei", "purpose": "scan"}]
        report = agent._finalize_mission()
        assert "Security scan" in report
        assert "CVSS-Scored Findings" in report
        assert "Action Log" in report


# ════════════════════════════════════════════════════════════════════════════
# SECTION 2: tools/multi_agent.py
# ════════════════════════════════════════════════════════════════════════════


class TestDataclasses:
    """Tests for TeamMessage, TaskAssignment, Finding dataclasses."""

    def test_team_message_defaults(self):
        from tools.multi_agent import TeamMessage

        msg = TeamMessage(
            round=1, agent_id=0, agent_role="Strategist", model_name="gpt-4", content="hello"
        )
        assert msg.round == 1
        assert msg.msg_type == "discussion"
        assert msg.timestamp > 0

    def test_task_assignment_defaults(self):
        from tools.multi_agent import TaskAssignment

        ta = TaskAssignment(
            agent_id=0, action_type="shell", params={"cmd": "ls"}, description="list"
        )
        assert ta.success is False
        assert ta.completed is False
        assert ta.result is None

    def test_finding_defaults(self):
        from tools.multi_agent import Finding

        f = Finding(source_agent="Recon", description="SQLi found")
        assert f.severity == "info"
        assert f.evidence == ""
        assert f.confirmed_by == []


class TestTeamAegisInit:
    """Tests for TeamAegis.__init__."""

    def test_init_with_two_clients(self):
        from tools.multi_agent import TeamAegis

        c1 = _make_mock_client()
        c2 = _make_mock_client()
        ta = TeamAegis(clients=[c1, c2], target="example.com")
        assert ta.team_size == 2
        assert ta.target == "example.com"
        assert len(ta.roles) == 2

    def test_init_with_three_clients(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client() for _ in range(3)]
        ta = TeamAegis(clients=clients, target="t.com")
        assert ta.team_size == 3

    def test_init_truncates_to_three(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client() for _ in range(5)]
        ta = TeamAegis(clients=clients, target="t.com")
        assert ta.team_size == 3

    def test_init_rejects_single_client(self):
        from tools.multi_agent import TeamAegis
        import pytest

        with pytest.raises(ValueError, match="at least 2"):
            TeamAegis(clients=[_make_mock_client()], target="t")

    def test_init_empty_clients(self):
        from tools.multi_agent import TeamAegis
        import pytest

        with pytest.raises(ValueError, match="at least 2"):
            TeamAegis(clients=[], target="t")

    def test_default_roles_assigned(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client() for _ in range(3)]
        ta = TeamAegis(clients=clients, target="t.com")
        role_names = [r["name"] for r in ta.roles]
        assert "Strategist" in role_names
        assert "Recon Lead" in role_names
        assert "Exploit Analyst" in role_names

    def test_parallel_mode_default(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client() for _ in range(2)]
        ta = TeamAegis(clients=clients, target="t.com")
        assert ta.parallel_mode is True

    def test_max_rounds(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client() for _ in range(2)]
        ta = TeamAegis(clients=clients, target="t.com", max_rounds=5)
        assert ta.max_rounds == 5


class TestParseAgentResponse:
    """Tests for TeamAegis._parse_agent_response."""

    def _make_ta(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client() for _ in range(2)]
        return TeamAegis(clients=clients, target="t.com")

    def test_empty_string(self):
        ta = self._make_ta()
        result = ta._parse_agent_response("")
        assert result["discussion"] == "(No response)"
        assert result["action"]["type"] == "none"

    def test_json_fence(self):
        ta = self._make_ta()
        text = '```json\n{"discussion": "test", "action": {"type": "none"}}\n```'
        result = ta._parse_agent_response(text)
        assert result["discussion"] == "test"

    def test_raw_json(self):
        ta = self._make_ta()
        text = '{"discussion": "hello", "action": {"type": "run_tool"}}'
        result = ta._parse_agent_response(text)
        assert result["discussion"] == "hello"
        assert result["action"]["type"] == "run_tool"

    def test_plain_text_fallback(self):
        ta = self._make_ta()
        text = "Just some plain text from the agent"
        result = ta._parse_agent_response(text)
        assert result["action"]["type"] == "none"
        assert "Just some plain text" in result["discussion"]

    def test_json_with_findings(self):
        ta = self._make_ta()
        text = json.dumps(
            {
                "discussion": "Found something",
                "action": {"type": "none"},
                "findings": [{"description": "XSS", "severity": "high", "evidence": "<script>"}],
            }
        )
        result = ta._parse_agent_response(text)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "high"


class TestFormatMethods:
    """Tests for _format_* methods."""

    def _make_ta(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client() for _ in range(2)]
        return TeamAegis(clients=clients, target="t.com")

    def test_format_discussion_history_empty(self):
        ta = self._make_ta()
        result = ta._format_discussion_history()
        assert "No previous discussion" in result

    def test_format_discussion_history_with_messages(self):
        from tools.multi_agent import TeamMessage

        ta = self._make_ta()
        ta.discussion.append(
            TeamMessage(
                round=1,
                agent_id=0,
                agent_role="Strategist",
                model_name="gpt-4",
                content="Let's scan",
                msg_type="discussion",
            )
        )
        result = ta._format_discussion_history()
        assert "Strategist" in result
        assert "Let's scan" in result

    def test_format_discussion_history_task_result_tag(self):
        from tools.multi_agent import TeamMessage

        ta = self._make_ta()
        ta.discussion.append(
            TeamMessage(
                round=1,
                agent_id=1,
                agent_role="Recon Lead",
                model_name="gpt-4",
                content="Result data",
                msg_type="task_result",
            )
        )
        result = ta._format_discussion_history()
        assert "TOOL RESULT" in result

    def test_format_findings_empty(self):
        ta = self._make_ta()
        result = ta._format_findings()
        assert "No confirmed findings" in result

    def test_format_findings_with_items(self):
        from tools.multi_agent import Finding

        ta = self._make_ta()
        ta.findings.append(
            Finding(
                source_agent="Recon",
                description="SQL injection",
                severity="high",
                evidence="payload sent",
                confirmed_by=["Exploit Analyst"],
            )
        )
        result = ta._format_findings()
        assert "SQL injection" in result
        assert "HIGH" in result
        assert "Exploit Analyst" in result

    def test_format_team_roster(self):
        ta = self._make_ta()
        result = ta._format_team_roster()
        assert "openai" in result
        assert "gpt-4" in result

    def test_format_prior_memories_empty(self):
        ta = self._make_ta()
        result = ta._format_prior_memories()
        assert "No prior memories" in result


class TestShareIntel:
    """Tests for TeamAegis._share_intel."""

    def test_share_intel_adds_entry(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client() for _ in range(2)]
        ta = TeamAegis(clients=clients, target="t.com")
        ta._share_intel(0, "Found open port 8080")
        assert len(ta.shared_intel) == 1
        assert "Strategist" in ta.shared_intel[0]
        assert "open port 8080" in ta.shared_intel[0]

    def test_share_intel_deduplicates(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client() for _ in range(2)]
        ta = TeamAegis(clients=clients, target="t.com")
        ta._share_intel(0, "Same insight")
        ta._share_intel(0, "Same insight")
        assert len(ta.shared_intel) == 1

    def test_share_intel_out_of_range_agent(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client() for _ in range(2)]
        ta = TeamAegis(clients=clients, target="t.com")
        ta._share_intel(99, "insight from unknown")
        assert len(ta.shared_intel) == 1
        assert "Agent99" in ta.shared_intel[0]


class TestGenerateFinalReport:
    """Tests for TeamAegis._generate_final_report."""

    def test_report_empty(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client() for _ in range(2)]
        ta = TeamAegis(clients=clients, target="t.com")
        ta.round = 3
        report = ta._generate_final_report()
        assert "TEAM AEGIS" in report
        assert "t.com" in report
        assert "No confirmed vulnerabilities" in report

    def test_report_with_findings(self):
        from tools.multi_agent import Finding, TeamAegis

        clients = [_make_mock_client() for _ in range(2)]
        ta = TeamAegis(clients=clients, target="t.com")
        ta.round = 2
        ta.findings.append(
            Finding(
                source_agent="Recon Lead",
                description="XSS in search",
                severity="high",
                evidence="payload reflected",
            )
        )
        report = ta._generate_final_report()
        assert "XSS in search" in report
        assert "[HIGH]" in report
        assert "Recon Lead" in report

    def test_report_with_tasks(self):
        from tools.multi_agent import TaskAssignment, TeamAegis

        clients = [_make_mock_client() for _ in range(2)]
        ta = TeamAegis(clients=clients, target="t.com")
        ta.round = 1
        ta.tasks.append(
            TaskAssignment(
                agent_id=0,
                action_type="shell",
                params={},
                description="run nuclei",
                success=True,
                completed=True,
            )
        )
        report = ta._generate_final_report()
        assert "ACTIONS EXECUTED: 1" in report
        assert "[OK]" in report


# ════════════════════════════════════════════════════════════════════════════
# SECTION 3: tools/targeted_attacks.py
# ════════════════════════════════════════════════════════════════════════════


class TestConfirmedFinding:
    """Tests for ConfirmedFinding dataclass."""

    def test_defaults(self):
        from tools.targeted_attacks import ConfirmedFinding

        cf = ConfirmedFinding(
            title="Test",
            severity="High",
            category="xss",
            endpoint_url="http://x.com",
            method="GET",
            evidence="reflected",
        )
        assert cf.payload == ""
        assert cf.response_snippet == ""
        assert cf.status_code == 0
        assert cf.confidence == 1.0
        assert cf.detector == ""


class TestPayloadConstants:
    """Tests that payload constants are properly defined."""

    def test_sqli_payloads_nonempty(self):
        from tools.targeted_attacks import SQLI_PAYLOADS

        assert len(SQLI_PAYLOADS) > 0
        for payload, kind in SQLI_PAYLOADS:
            assert isinstance(payload, str)
            assert isinstance(kind, str)

    def test_xss_payloads_nonempty(self):
        from tools.targeted_attacks import XSS_PAYLOADS

        assert len(XSS_PAYLOADS) > 0
        assert all(isinstance(p, str) for p in XSS_PAYLOADS)

    def test_ssti_payloads_nonempty(self):
        from tools.targeted_attacks import SSTI_PAYLOADS

        assert len(SSTI_PAYLOADS) > 0
        for payload, indicator in SSTI_PAYLOADS:
            assert isinstance(payload, str)
            assert isinstance(indicator, str)


class _MockResponse:
    """Lightweight mock for aiohttp response objects."""

    def __init__(self, status: int = 200, text: str = "", headers: dict = None):
        self.status = status
        self._text = text
        self.headers = headers or {"content-type": "text/html"}

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


class _MockSession:
    """Mock aiohttp.ClientSession that routes by URL/method."""

    def __init__(self, responses: dict = None):
        self._responses = responses or {}

    def _get_response(self, method, url, **kw):
        key = (method, url)
        if key in self._responses:
            r = self._responses[key]
            return r if isinstance(r, _MockResponse) else _MockResponse(*r)
        return _MockResponse(200, "default")

    def post(self, url, **kw):
        return self._get_response("POST", url, **kw)

    def get(self, url, **kw):
        return self._get_response("GET", url, **kw)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass


class TestTestSqlInjection:
    """Tests for test_sql_injection with mocked aiohttp."""

    def test_skips_non_login_get_endpoint(self):
        from tools.targeted_attacks import test_sql_injection
        import asyncio

        ep = _make_endpoint(url="http://x.com/api/data", method="GET")
        session = _MockSession()
        result = asyncio.run(test_sql_injection(session, ep))
        assert result == []

    def test_skips_non_login_post_endpoint(self):
        from tools.targeted_attacks import test_sql_injection
        import asyncio

        ep = _make_endpoint(url="http://x.com/api/data", method="POST")
        session = _MockSession()
        result = asyncio.run(test_sql_injection(session, ep))
        assert result == []

    def test_baseline_failure_returns_empty(self):
        from tools.targeted_attacks import test_sql_injection
        import asyncio

        ep = _make_endpoint(url="http://x.com/login", method="POST")
        session = _MockSession({("POST", "http://x.com/login"): Exception("conn refused")})
        result = asyncio.run(test_sql_injection(session, ep))
        assert result == []

    def test_status_change_detected(self):
        from tools.targeted_attacks import test_sql_injection
        import asyncio

        ep = _make_endpoint(url="http://x.com/login", method="POST")
        session = _MockSession(
            {
                ("POST", "http://x.com/login"): _MockResponse(200, "Invalid credentials"),
            }
        )
        # All payloads return 200 except one returns 500 (status change)
        responses = {
            ("POST", "http://x.com/login"): _MockResponse(500, "SQL error"),
        }
        # Patch the session to return different responses per call
        call_count = [0]
        original_session = session

        class CountingSession:
            def __init__(self):
                self._call = 0

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            def post(self, url, **kw):
                self._call += 1
                if self._call == 1:
                    return _MockResponse(200, "Invalid credentials")
                return _MockResponse(500, "SQL syntax error near 'OR'")

        result = asyncio.run(test_sql_injection(CountingSession(), ep))
        assert len(result) >= 1
        assert result[0].category == "sql_injection"
        assert result[0].severity == "Critical"

    def test_auth_bypass_detected(self):
        from tools.targeted_attacks import test_sql_injection
        import asyncio

        ep = _make_endpoint(url="http://x.com/auth/login", method="POST")

        class BypassSession:
            def __init__(self):
                self._call = 0

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            def post(self, url, **kw):
                self._call += 1
                if self._call == 1:
                    return _MockResponse(200, "Login failed")
                return _MockResponse(200, "OK welcome admin")

        result = asyncio.run(test_sql_injection(BypassSession(), ep))
        assert len(result) == 1
        assert (
            "auth bypass" in result[0].title.lower() or "sql injection" in result[0].title.lower()
        )


class TestTestXSS:
    """Tests for test_xss with mocked aiohttp."""

    def test_skips_post_method(self):
        from tools.targeted_attacks import test_xss
        import asyncio

        ep = _make_endpoint(url="http://x.com/search", method="POST")
        session = _MockSession()
        result = asyncio.run(test_xss(session, ep))
        assert result == []

    def test_reflected_xss_detected(self):
        from tools.targeted_attacks import test_xss
        import asyncio

        ep = _make_endpoint(url="http://x.com/search?q=test", method="GET")
        payload = "<script>alert(1)</script>"

        class XssSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            def get(self, url, **kw):
                return _MockResponse(200, f"Results for {payload}", {"content-type": "text/html"})

        result = asyncio.run(test_xss(XssSession(), ep))
        assert len(result) == 1
        assert result[0].category == "xss_reflected"
        assert result[0].severity == "High"

    def test_no_reflection_no_finding(self):
        from tools.targeted_attacks import test_xss
        import asyncio

        ep = _make_endpoint(url="http://x.com/search", method="GET")
        session = _MockSession(
            {
                ("GET", "http://x.com/search?q=<script>alert(1)</script>"): _MockResponse(
                    200, "Safe output", {"content-type": "text/html"}
                )
            }
        )
        result = asyncio.run(test_xss(session, ep))
        assert result == []


class TestTestSSTI:
    """Tests for test_ssti with mocked aiohttp."""

    def test_skips_post(self):
        from tools.targeted_attacks import test_ssti
        import asyncio

        ep = _make_endpoint(url="http://x.com/render", method="POST")
        session = _MockSession()
        result = asyncio.run(test_ssti(session, ep))
        assert result == []

    def test_ssti_detected(self):
        from tools.targeted_attacks import test_ssti
        import asyncio

        ep = _make_endpoint(url="http://x.com/render", method="GET")

        class SstiSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            def get(self, url, **kw):
                if "7*7" in url:
                    return _MockResponse(200, "Result: 49")
                return _MockResponse(200, "Hello")

        result = asyncio.run(test_ssti(SstiSession(), ep))
        assert len(result) == 1
        assert result[0].category == "ssti"


class TestTestIDOR:
    """Tests for test_idor with mocked aiohttp."""

    def test_no_digit_ending_returns_empty(self):
        from tools.targeted_attacks import test_idor
        import asyncio

        ep = _make_endpoint(url="http://x.com/api/users", method="GET")
        session = _MockSession()
        result = asyncio.run(test_idor(session, ep))
        assert result == []

    def test_idor_detected(self):
        from tools.targeted_attacks import test_idor
        import asyncio

        ep = _make_endpoint(url="http://x.com/api/user/5", method="GET")

        class IdoorSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            def get(self, url, **kw):
                if url.endswith("/1"):
                    return _MockResponse(200, '{"id": 1, "username": "alice", "name": "Alice"}')
                return _MockResponse(404, "not found")

        result = asyncio.run(test_idor(IdoorSession(), ep))
        assert len(result) == 1
        assert result[0].category == "idor"


class TestTestMassAssignment:
    """Tests for test_mass_assignment with mocked aiohttp."""

    def test_skips_non_register_endpoints(self):
        from tools.targeted_attacks import test_mass_assignment
        import asyncio

        ep = _make_endpoint(url="http://x.com/api/orders", method="POST")
        session = _MockSession()
        result = asyncio.run(test_mass_assignment(session, ep))
        assert result == []

    def test_skips_get_method(self):
        from tools.targeted_attacks import test_mass_assignment
        import asyncio

        ep = _make_endpoint(url="http://x.com/register", method="GET")
        session = _MockSession()
        result = asyncio.run(test_mass_assignment(session, ep))
        assert result == []

    def test_mass_assignment_detected(self):
        from tools.targeted_attacks import test_mass_assignment
        import asyncio

        ep = _make_endpoint(url="http://x.com/register", method="POST")

        class MASession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            def post(self, url, **kw):
                return _MockResponse(200, '{"role": "admin", "balance": 99999}')

        result = asyncio.run(test_mass_assignment(MASession(), ep))
        assert len(result) == 1
        assert result[0].category == "mass_assignment"


class TestTestJwtAlgNone:
    """Tests for test_jwt_alg_none with mocked aiohttp."""

    def test_skips_irrelevant_endpoints(self):
        from tools.targeted_attacks import test_jwt_alg_none
        import asyncio

        ep = _make_endpoint(url="http://x.com/api/search", method="GET")
        session = _MockSession()
        result = asyncio.run(test_jwt_alg_none(session, ep))
        assert result == []

    def test_jwt_none_accepted(self):
        from tools.targeted_attacks import test_jwt_alg_none
        import asyncio

        ep = _make_endpoint(url="http://x.com/jwt/verify", method="POST")

        class JWTSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            def post(self, url, **kw):
                return _MockResponse(200, '{"valid": true, "payload": {"user": "admin"}}')

        result = asyncio.run(test_jwt_alg_none(JWTSession(), ep))
        assert len(result) == 1
        assert result[0].category == "jwt_confusion"


class TestTestProtoPollution:
    """Tests for test_proto_pollution with mocked aiohttp."""

    def test_skips_non_post(self):
        from tools.targeted_attacks import test_proto_pollution
        import asyncio

        ep = _make_endpoint(url="http://x.com/merge", method="GET")
        session = _MockSession()
        result = asyncio.run(test_proto_pollution(session, ep))
        assert result == []

    def test_pollution_detected(self):
        from tools.targeted_attacks import test_proto_pollution
        import asyncio

        ep = _make_endpoint(url="http://x.com/merge", method="POST")

        class PollSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            def post(self, url, **kw):
                return _MockResponse(200, "__proto__ accepted, polluted value")

        result = asyncio.run(test_proto_pollution(PollSession(), ep))
        assert len(result) == 1
        assert result[0].category == "prototype_pollution"


class TestTestPathTraversal:
    """Tests for test_path_traversal with mocked aiohttp."""

    def test_skips_non_get(self):
        from tools.targeted_attacks import test_path_traversal
        import asyncio

        ep = _make_endpoint(url="http://x.com/download", method="POST")
        session = _MockSession()
        result = asyncio.run(test_path_traversal(session, ep))
        assert result == []

    def test_traversal_detected(self):
        from tools.targeted_attacks import test_path_traversal
        import asyncio

        ep = _make_endpoint(url="http://x.com/download", method="GET")

        class TraversalSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            def get(self, url, **kw):
                if "etc/passwd" in url or "file=../../../" in url:
                    return _MockResponse(200, "root:x:0:0:root:/root:/bin/bash")
                return _MockResponse(200, "normal file")

        result = asyncio.run(test_path_traversal(TraversalSession(), ep))
        assert len(result) == 1
        assert result[0].category == "path_traversal"


class TestTestRaceCondition:
    """Tests for test_race_condition with mocked aiohttp."""

    def test_skips_non_post(self):
        from tools.targeted_attacks import test_race_condition
        import asyncio

        ep = _make_endpoint(url="http://x.com/coupon", method="GET")
        session = _MockSession()
        result = asyncio.run(test_race_condition(session, ep))
        assert result == []

    def test_race_detected_when_many_succeed(self):
        from tools.targeted_attacks import test_race_condition
        import asyncio

        ep = _make_endpoint(url="http://x.com/redeem", method="POST")

        class RaceSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            def post(self, url, **kw):
                return _MockResponse(200, "coupon applied")

        result = asyncio.run(test_race_condition(RaceSession(), ep))
        assert len(result) == 1
        assert result[0].category == "race_condition"
        assert result[0].confidence == 0.6

    def test_no_race_when_few_succeed(self):
        from tools.targeted_attacks import test_race_condition
        import asyncio

        ep = _make_endpoint(url="http://x.com/redeem", method="POST")
        call_count = [0]

        class SlowRaceSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            def post(self, url, **kw):
                call_count[0] += 1
                if call_count[0] <= 3:
                    return _MockResponse(200, "ok")
                return _MockResponse(429, "rate limited")

        result = asyncio.run(test_race_condition(SlowRaceSession(), ep))
        assert result == []


# ════════════════════════════════════════════════════════════════════════════
# SECTION 4: tools/hunt_engine.py
# ════════════════════════════════════════════════════════════════════════════


class TestSeverityEnum:
    """Tests for Severity enum."""

    def test_all_values(self):
        from tools.hunt_engine import Severity

        assert Severity.CRITICAL.value == "Critical"
        assert Severity.HIGH.value == "High"
        assert Severity.MEDIUM.value == "Medium"
        assert Severity.LOW.value == "Low"
        assert Severity.INFO.value == "Informational"


class TestHuntFinding:
    """Tests for HuntFinding dataclass."""

    def test_defaults(self):
        from tools.hunt_engine import HuntFinding

        hf = HuntFinding(phase="recon", category="endpoint", severity="Informational", title="test")
        assert hf.details == ""
        assert hf.url == ""
        assert hf.evidence == {}
        assert hf.cvss == 0.0
        assert hf.cve_id is None

    def test_to_dict(self):
        from tools.hunt_engine import HuntFinding

        hf = HuntFinding(
            phase="smart", category="xss", severity="High", title="XSS", url="http://x.com"
        )
        d = hf.to_dict()
        assert d["phase"] == "smart"
        assert d["category"] == "xss"
        assert d["url"] == "http://x.com"


class TestHuntPhase:
    """Tests for HuntPhase dataclass."""

    def test_defaults(self):
        from tools.hunt_engine import HuntPhase

        hp = HuntPhase(name="recon", status="pending")
        assert hp.duration == 0.0
        assert hp.findings == 0
        assert hp.error == ""


class TestHuntReport:
    """Tests for HuntReport dataclass."""

    def test_by_severity(self):
        from tools.hunt_engine import HuntFinding, HuntReport

        report = HuntReport(target="t.com", started_at="2024-01-01")
        report.findings = [
            HuntFinding(phase="a", category="x", severity="High", title="h1"),
            HuntFinding(phase="a", category="y", severity="High", title="h2"),
            HuntFinding(phase="a", category="z", severity="Low", title="l1"),
        ]
        counts = report.by_severity()
        assert counts["High"] == 2
        assert counts["Low"] == 1

    def test_by_phase(self):
        from tools.hunt_engine import HuntFinding, HuntReport

        report = HuntReport(target="t.com", started_at="2024-01-01")
        report.findings = [
            HuntFinding(phase="recon", category="a", severity="Info", title="r1"),
            HuntFinding(phase="smart", category="b", severity="High", title="s1"),
            HuntFinding(phase="smart", category="c", severity="Medium", title="s2"),
        ]
        counts = report.by_phase()
        assert counts["recon"] == 1
        assert counts["smart"] == 2


class TestComputeRiskScore:
    """Tests for compute_risk_score."""

    def test_empty_findings(self):
        from tools.hunt_engine import compute_risk_score

        score, level = compute_risk_score([])
        assert score == 0.0
        assert level == "None"

    def test_informational_only(self):
        from tools.hunt_engine import HuntFinding, compute_risk_score

        findings = [
            HuntFinding(phase="recon", category="ep", severity="Informational", title="discovered"),
        ]
        score, level = compute_risk_score(findings)
        assert score == 0.0
        assert level == "None"

    def test_single_critical(self):
        from tools.hunt_engine import HuntFinding, compute_risk_score

        findings = [
            HuntFinding(
                phase="smart",
                category="sqli",
                severity="Critical",
                title="SQLi",
                url="http://x.com",
            ),
        ]
        score, level = compute_risk_score(findings)
        assert score == 25.0
        assert level == "Medium"  # 25.0 is between 20 and 40

    def test_critical_and_high(self):
        from tools.hunt_engine import HuntFinding, compute_risk_score

        findings = [
            HuntFinding(
                phase="smart",
                category="sqli",
                severity="Critical",
                title="SQLi",
                url="http://x.com",
            ),
            HuntFinding(
                phase="smart", category="xss", severity="High", title="XSS", url="http://x.com"
            ),
        ]
        score, level = compute_risk_score(findings)
        assert score == 37.0  # 25 + 12
        assert level == "Medium"

    def test_multi_phase_bonus(self):
        from tools.hunt_engine import HuntFinding, compute_risk_score

        findings = [
            HuntFinding(
                phase="smart",
                category="sqli",
                severity="Critical",
                title="SQLi",
                url="http://x.com",
            ),
            HuntFinding(
                phase="zero_day", category="rce", severity="High", title="RCE", url="http://x.com"
            ),
            HuntFinding(
                phase="logic", category="idor", severity="Medium", title="IDOR", url="http://x.com"
            ),
        ]
        score, level = compute_risk_score(findings)
        # 25 + 12 + 5 = 42 + 10 bonus = 52
        assert score == 52.0
        assert level == "High"

    def test_score_capped_at_100(self):
        from tools.hunt_engine import HuntFinding, compute_risk_score

        findings = [
            HuntFinding(
                phase="smart", category="x", severity="Critical", title=f"c{i}", url="http://x.com"
            )
            for i in range(10)
        ]
        score, level = compute_risk_score(findings)
        assert score == 100.0

    def test_candidate_excluded(self):
        from tools.hunt_engine import HuntFinding, compute_risk_score

        findings = [
            HuntFinding(
                phase="zero_day",
                category="jwt",
                severity="Critical",
                title="JWT FORGERY CANDIDATE - not tested",
                url="http://x.com",
            ),
        ]
        score, level = compute_risk_score(findings)
        assert score == 0.0

    def test_no_url_no_details_excluded(self):
        from tools.hunt_engine import HuntFinding, compute_risk_score

        findings = [
            HuntFinding(phase="smart", category="x", severity="Critical", title="vuln"),
        ]
        score, level = compute_risk_score(findings)
        assert score == 0.0

    def test_threshold_levels(self):
        from tools.hunt_engine import HuntFinding, compute_risk_score

        # 4 mediums = 20 = Medium level
        findings_20 = [
            HuntFinding(
                phase="smart", category="x", severity="Medium", title=f"m{i}", url="http://x.com"
            )
            for i in range(4)
        ]
        score, level = compute_risk_score(findings_20)
        assert score == 20.0
        assert level == "Medium"


class TestCorrelateChains:
    """Tests for correlate_chains."""

    def test_empty_findings(self):
        from tools.hunt_engine import correlate_chains

        assert correlate_chains([]) == []

    def test_informational_only_no_chains(self):
        from tools.hunt_engine import HuntFinding, correlate_chains

        findings = [
            HuntFinding(phase="recon", category="ep", severity="Informational", title="discovered"),
        ]
        assert correlate_chains(findings) == []

    def test_same_url_multi_finding_chain(self):
        from tools.hunt_engine import HuntFinding, correlate_chains

        findings = [
            HuntFinding(
                phase="smart",
                category="sqli",
                severity="Critical",
                title="SQLi on /api",
                url="http://x.com/api",
            ),
            HuntFinding(
                phase="smart",
                category="xss",
                severity="High",
                title="XSS on /api",
                url="http://x.com/api",
            ),
        ]
        chains = correlate_chains(findings)
        assert len(chains) >= 1
        assert chains[0]["chain_type"] == "same_url_multi_finding"
        assert chains[0]["combined_severity_score"] == 37  # 25 + 12

    def test_jwt_bola_chain(self):
        from tools.hunt_engine import HuntFinding, correlate_chains

        findings = [
            HuntFinding(
                phase="smart",
                category="jwt_confusion",
                severity="Critical",
                title="JWT alg=none on /verify",
                url="http://x.com/verify",
            ),
            HuntFinding(
                phase="smart",
                category="bola",
                severity="High",
                title="IDOR on /user/1",
                url="http://x.com/user/1",
            ),
        ]
        chains = correlate_chains(findings)
        jwt_bola = [c for c in chains if c["chain_type"] == "auth_bypass_then_idor"]
        assert len(jwt_bola) == 1

    def test_race_state_chain(self):
        from tools.hunt_engine import HuntFinding, correlate_chains

        findings = [
            HuntFinding(
                phase="smart",
                category="race_condition",
                severity="Medium",
                title="Race on /coupon",
                url="http://x.com/coupon",
            ),
            HuntFinding(
                phase="logic",
                category="state_machine",
                severity="High",
                title="State bypass on /pay",
                url="http://x.com/pay",
            ),
        ]
        chains = correlate_chains(findings)
        race_sm = [c for c in chains if c["chain_type"] == "race_then_state_bypass"]
        assert len(race_sm) == 1

    def test_candidate_excluded_from_chains(self):
        from tools.hunt_engine import HuntFinding, correlate_chains

        findings = [
            HuntFinding(
                phase="zero_day",
                category="jwt",
                severity="Critical",
                title="JWT FORGERY CANDIDATE",
                url="http://x.com",
            ),
            HuntFinding(
                phase="zero_day",
                category="jwt",
                severity="High",
                title="JWT FORGERY CANDIDATE",
                url="http://x.com",
            ),
        ]
        chains = correlate_chains(findings)
        assert chains == []


class TestReportToConsole:
    """Tests for report_to_console."""

    def test_basic_report(self):
        from tools.hunt_engine import HuntReport, report_to_console

        report = HuntReport(target="example.com", started_at="2024-01-01", total_duration=10.0)
        text = report_to_console(report)
        assert "ELENGENIX HUNT REPORT" in text
        assert "example.com" in text
        assert "No live vulnerabilities" in text

    def test_report_with_findings(self):
        from tools.hunt_engine import HuntFinding, HuntPhase, HuntReport, report_to_console

        report = HuntReport(
            target="test.com",
            started_at="2024-01-01",
            total_duration=5.0,
            risk_score=45.0,
            risk_level="High",
        )
        report.phases = [
            HuntPhase(name="recon", status="done", duration=1.0, findings=3),
            HuntPhase(name="smart", status="done", duration=2.5, findings=2),
        ]
        report.findings = [
            HuntFinding(
                phase="smart",
                category="sqli",
                severity="Critical",
                title="SQLi",
                url="http://test.com/api",
            ),
            HuntFinding(
                phase="smart",
                category="xss",
                severity="High",
                title="XSS",
                url="http://test.com/search",
            ),
            HuntFinding(
                phase="recon",
                category="endpoint",
                severity="Informational",
                title="Discovered /api",
            ),
        ]
        report.chains = [
            {
                "chain_type": "same_url_multi_finding",
                "findings": ["SQLi", "XSS"],
                "categories": ["sqli", "xss"],
                "combined_severity_score": 37,
                "url": "http://test.com",
            }
        ]
        text = report_to_console(report)
        assert "test.com" in text
        assert "LIVE vulnerabilities:  2" in text
        assert "SQLi" in text
        assert "VULNERABILITY CHAINS" in text
        assert "[OK]" in text

    def test_report_with_static_candidates(self):
        from tools.hunt_engine import HuntFinding, HuntReport, report_to_console

        report = HuntReport(target="x.com", started_at="2024-01-01", total_duration=1.0)
        report.findings = [
            HuntFinding(
                phase="zero_day",
                category="jwt",
                severity="Critical",
                title="JWT FORGERY CANDIDATE - not tested",
                url="http://x.com",
            ),
        ]
        text = report_to_console(report)
        assert "FORGERY CANDIDATES" in text
        assert "NOT confirmed" in text


class TestReportToDict:
    """Tests for report_to_dict."""

    def test_empty_report(self):
        from tools.hunt_engine import HuntReport, report_to_dict

        report = HuntReport(target="t.com", started_at="2024-01-01")
        d = report_to_dict(report)
        assert d["target"] == "t.com"
        assert d["findings"] == []
        assert d["phases"] == []
        assert d["chains"] == []

    def test_report_with_all_fields(self):
        from tools.hunt_engine import HuntFinding, HuntPhase, HuntReport, report_to_dict

        report = HuntReport(
            target="a.com",
            started_at="2024-01-01",
            finished_at="2024-01-02",
            total_duration=60.0,
            risk_score=75.0,
            risk_level="Critical",
            summary={"total": 1},
        )
        report.phases = [HuntPhase(name="recon", status="done", duration=5.0, findings=1)]
        report.findings = [
            HuntFinding(
                phase="recon", category="ep", severity="Informational", title="ep1", cvss=0.0
            ),
        ]
        report.chains = [{"chain_type": "test"}]
        d = report_to_dict(report)
        assert d["total_duration"] == 60.0
        assert d["risk_score"] == 75.0
        assert d["risk_level"] == "Critical"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["phase"] == "recon"
        assert d["chains"] == [{"chain_type": "test"}]
        assert d["summary"] == {"total": 1}


class TestHuntEngineInit:
    """Tests for HuntEngine.__init__ and _normalize_target."""

    def test_basic_init(self):
        from tools.hunt_engine import HuntEngine

        engine = HuntEngine(target="example.com")
        assert engine.target == "example.com"
        assert engine.skip_phases == set()
        assert engine.quiet is False

    def test_strip_http(self):
        from tools.hunt_engine import HuntEngine

        engine = HuntEngine(target="http://example.com")
        assert engine.target == "example.com"

    def test_strip_https(self):
        from tools.hunt_engine import HuntEngine

        engine = HuntEngine(target="https://example.com")
        assert engine.target == "example.com"

    def test_strip_trailing_slash(self):
        from tools.hunt_engine import HuntEngine

        engine = HuntEngine(target="example.com/")
        assert engine.target == "example.com"

    def test_skip_phases(self):
        from tools.hunt_engine import HuntEngine

        engine = HuntEngine(target="x.com", skip_phases=["recon", "smart"])
        assert "recon" in engine.skip_phases
        assert "smart" in engine.skip_phases

    def test_quiet_mode(self):
        from tools.hunt_engine import HuntEngine

        engine = HuntEngine(target="x.com", quiet=True)
        assert engine.quiet is True


# ════════════════════════════════════════════════════════════════════════════
# ADDITIONAL TESTS: hybrid_agent missing items
# ════════════════════════════════════════════════════════════════════════════


class TestRunStrategist:
    """Tests for HybridAgent._run_strategist."""

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.get_context_for_ai", return_value="")
    @patch("agents.hybrid_agent.registry")
    def test_populates_tasks_from_json_list(self, mock_registry, mock_ctx, mock_refl):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        client.chat.return_value = MagicMock(
            content='[{"description": "scan ports", "status": "pending"}]'
        )
        agent = HybridAgent(client=client, target="example.com")
        mock_registry.list_available_tools.return_value = {}
        agent.objective = "find vulns"
        agent._run_strategist()
        assert len(agent.tasks) == 1
        assert agent.tasks[0]["description"] == "scan ports"

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    def test_no_client_returns_early(self, mock_refl):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        agent.objective = "test"
        agent._run_strategist()
        assert agent.tasks == []

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.get_context_for_ai", return_value="")
    @patch("agents.hybrid_agent.registry")
    def test_handles_parse_error(self, mock_registry, mock_ctx, mock_refl):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        client.chat.return_value = MagicMock(content="not json at all")
        agent = HybridAgent(client=client, target="t")
        mock_registry.list_available_tools.return_value = {}
        agent.objective = "test"
        agent._run_strategist()
        assert agent.tasks == []

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.get_context_for_ai", return_value="")
    @patch("agents.hybrid_agent.registry")
    def test_handles_api_exception(self, mock_registry, mock_ctx, mock_refl):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        client.chat.side_effect = RuntimeError("API down")
        agent = HybridAgent(client=client, target="t")
        mock_registry.list_available_tools.return_value = {}
        agent.objective = "test"
        agent._run_strategist()
        assert agent.tasks == []

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.get_context_for_ai", return_value="past context")
    @patch("agents.hybrid_agent.registry")
    def test_includes_memory_context(self, mock_registry, mock_ctx, mock_refl):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        client.chat.return_value = MagicMock(content="[]")
        agent = HybridAgent(client=client, target="t", enable_memory=True)
        mock_registry.list_available_tools.return_value = {}
        agent.objective = "test"
        agent._run_strategist()
        mock_ctx.assert_called_once()


class TestRunSpecialistCycle:
    """Tests for HybridAgent._run_specialist_cycle."""

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.registry")
    def test_returns_true_on_empty_decision(self, mock_registry, mock_refl):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        client.chat.return_value = MagicMock(content=None)
        agent = HybridAgent(client=client, target="t")
        agent.objective = "test"
        agent.max_steps = 10
        mock_registry.list_available_tools.return_value = {}
        result = agent._run_specialist_cycle(1)
        assert result is True

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.registry")
    def test_returns_false_on_complete_mission(self, mock_registry, mock_refl):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        client.chat.return_value = MagicMock(content='{"action": "complete_mission"}')
        agent = HybridAgent(client=client, target="t")
        agent.objective = "test"
        mock_registry.list_available_tools.return_value = {}
        result = agent._run_specialist_cycle(1)
        assert result is False

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.registry")
    def test_returns_false_on_message(self, mock_registry, mock_refl):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        client.chat.return_value = MagicMock(
            content='{"action": "message", "message": "hello", "purpose": "notify"}'
        )
        agent = HybridAgent(client=client, target="t")
        agent.objective = "test"
        mock_registry.list_available_tools.return_value = {}
        result = agent._run_specialist_cycle(1)
        assert result is False

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.registry")
    def test_appends_to_action_history(self, mock_registry, mock_refl):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        client.chat.return_value = MagicMock(
            content='{"action": "run_command", "command": "ls", "purpose": "list"}'
        )
        agent = HybridAgent(client=client, target="t")
        agent.objective = "test"
        mock_registry.list_available_tools.return_value = {}
        agent._run_specialist_cycle(1)
        assert len(agent.action_history) == 1
        assert agent.action_history[0]["action"] == "run_command"

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.registry")
    def test_returns_true_on_run_tool(self, mock_registry, mock_refl):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        client.chat.return_value = MagicMock(
            content='{"action": "run_tool", "tool": "nuclei", "target": "x.com"}'
        )
        agent = HybridAgent(client=client, target="t")
        agent.objective = "test"
        mock_registry.list_available_tools.return_value = {}
        # run_tool will fail to find tool in registry, but cycle still returns True
        result = agent._run_specialist_cycle(1)
        assert result is True


class TestAiDecideAction:
    """Tests for HybridAgent._ai_decide_action."""

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.registry")
    def test_returns_parsed_json(self, mock_registry, mock_refl):
        from agents.hybrid_agent import HybridAgent

        decision = {"action": "run_command", "command": "echo hi"}
        client = _make_mock_client()
        client.chat.return_value = MagicMock(content=json.dumps(decision))
        agent = HybridAgent(client=client, target="t")
        agent.objective = "test"
        mock_registry.list_available_tools.return_value = {}
        result = agent._ai_decide_action(1)
        assert result["action"] == "run_command"

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    def test_returns_none_when_no_client(self, mock_refl):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        agent.objective = "test"
        result = agent._ai_decide_action(1)
        assert result is None

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.registry")
    def test_returns_none_on_persistent_errors(self, mock_registry, mock_refl):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        client.chat.side_effect = [ValueError("bad json"), RuntimeError("down")]
        agent = HybridAgent(client=client, target="t")
        agent.objective = "test"
        mock_registry.list_available_tools.return_value = {}
        result = agent._ai_decide_action(1)
        assert result is None

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.registry")
    def test_includes_tasks_in_context(self, mock_registry, mock_refl):
        from agents.hybrid_agent import HybridAgent

        client = _make_mock_client()
        client.chat.return_value = MagicMock(content='{"action": "none"}')
        agent = HybridAgent(client=client, target="t")
        agent.objective = "test"
        agent.tasks = [{"description": "scan", "status": "pending"}]
        mock_registry.list_available_tools.return_value = {}
        agent._ai_decide_action(1)
        call_args = client.chat.call_args
        prompt_text = call_args[0][0][0].content
        assert "scan" in prompt_text


class TestHandleMethods:
    """Tests for all _handle_* action methods."""

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.registry")
    def test_handle_run_tool_no_tool_warns(self, mock_registry, mock_refl):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=_make_mock_client(), target="t")
        agent._handle_run_tool({"action": "run_tool"}, 1)

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.registry")
    def test_handle_run_command_no_command_warns(self, mock_registry, mock_refl):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=_make_mock_client(), target="t")
        agent._handle_run_command({"action": "run_command"}, 1)

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    def test_handle_read_file_empty_path(self, mock_refl):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=_make_mock_client(), target="t")
        agent._handle_read_file({"action": "read_file"})

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    @patch("agents.hybrid_agent.remember")
    def test_handle_update_intel_saves_memory(self, mock_remember, mock_refl):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=_make_mock_client(), target="t", enable_memory=True)
        agent._handle_update_intel({"intel": {"k1": "v1", "k2": "v2"}})
        assert mock_remember.call_count == 2

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    def test_handle_update_intel_no_intel(self, mock_refl):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=_make_mock_client(), target="t")
        agent._handle_update_intel({"action": "update_intel"})

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    def test_handle_update_intel_memory_disabled(self, mock_refl):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=_make_mock_client(), target="t", enable_memory=False)
        agent._handle_update_intel({"intel": {"k": "v"}})

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    def test_handle_search_web_empty_query(self, mock_refl):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=_make_mock_client(), target="t")
        agent._handle_search_web({"action": "search_web"})

    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    def test_handle_message(self, mock_refl):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=_make_mock_client(), target="t")
        agent._handle_message({"message": "hello", "purpose": "notify"})


class TestBuildCouncil:
    """Tests for HybridAgent._build_council."""

    @patch("agents.agent_council.AgentCouncil")
    @patch("agents.critic_agent.CriticAgent")
    @patch("agents.specialist_agent.SpecialistAgent")
    @patch("agents.strategist_agent.StrategistAgent")
    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    def test_creates_all_agents(self, mock_refl, mock_strat, mock_spec, mock_critic, mock_council):
        from agents.hybrid_agent import HybridAgent

        s, sp, c = _make_mock_client(), _make_mock_client(), _make_mock_client()
        agent = HybridAgent(
            client=_make_mock_client(),
            strategist_client=s,
            specialist_client=sp,
            critic_client=c,
            target="t",
            risk_threshold="high",
        )
        agent._build_council()
        mock_strat.assert_called_once()
        mock_spec.assert_called_once()
        mock_critic.assert_called_once()
        mock_council.assert_called_once()

    @patch("agents.agent_council.AgentCouncil")
    @patch("agents.critic_agent.CriticAgent")
    @patch("agents.specialist_agent.SpecialistAgent")
    @patch("agents.strategist_agent.StrategistAgent")
    @patch("agents.hybrid_agent.get_reflection", return_value=MagicMock())
    def test_falls_back_to_client(
        self, mock_refl, mock_strat, mock_spec, mock_critic, mock_council
    ):
        from agents.hybrid_agent import HybridAgent

        fallback = _make_mock_client()
        agent = HybridAgent(
            client=fallback,
            strategist_client=None,
            specialist_client=None,
            critic_client=None,
            target="t",
        )
        agent._build_council()
        call_kwargs = mock_strat.call_args[1]
        assert call_kwargs["client"] is fallback


# ════════════════════════════════════════════════════════════════════════════
# ADDITIONAL TESTS: multi_agent missing items
# ════════════════════════════════════════════════════════════════════════════


class TestAgentRoles:
    """Tests for AGENT_ROLES constant."""

    def test_has_three_roles(self):
        from tools.multi_agent import AGENT_ROLES

        assert len(AGENT_ROLES) == 3

    def test_roles_have_required_keys(self):
        from tools.multi_agent import AGENT_ROLES

        for role in AGENT_ROLES:
            assert "name" in role
            assert "icon" in role
            assert "focus" in role
            assert "personality" in role

    def test_role_names(self):
        from tools.multi_agent import AGENT_ROLES

        names = [r["name"] for r in AGENT_ROLES]
        assert "Strategist" in names
        assert "Recon Lead" in names
        assert "Exploit Analyst" in names


class TestBuildAgentPrompt:
    """Tests for TeamAegis._build_agent_prompt."""

    def test_prompt_contains_identity(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client(), _make_mock_client()]
        team = TeamAegis(clients=clients, target="t")
        prompt = team._build_agent_prompt(0)
        assert "Strategist" in prompt
        assert "YOUR IDENTITY" in prompt

    def test_prompt_contains_target(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client(), _make_mock_client()]
        team = TeamAegis(clients=clients, target="example.com")
        prompt = team._build_agent_prompt(0)
        assert "example.com" in prompt

    def test_prompt_contains_response_format(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client(), _make_mock_client()]
        team = TeamAegis(clients=clients, target="t")
        prompt = team._build_agent_prompt(0)
        assert "RESPONSE FORMAT" in prompt
        assert "JSON" in prompt

    def test_prompt_lists_teammates(self):
        from tools.multi_agent import TeamAegis

        clients = [_make_mock_client(), _make_mock_client(), _make_mock_client()]
        team = TeamAegis(clients=clients, target="t")
        prompt = team._build_agent_prompt(0)
        assert "Recon Lead" in prompt
        assert "Exploit Analyst" in prompt


class TestPushPopTask:
    """Tests for _push_task and _pop_task."""

    def test_push_pop_priority_order(self):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=[_make_mock_client(), _make_mock_client()], target="t")
        team._push_task(5, 0, {"type": "run_tool", "description": "low pri"})
        team._push_task(1, 1, {"type": "shell", "description": "high pri"})
        task = team._pop_task()
        assert task[0] == 1  # highest priority (lowest number)

    def test_pop_empty_queue(self):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=[_make_mock_client(), _make_mock_client()], target="t")
        assert team._pop_task() is None

    def test_negative_priority_clamped(self):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=[_make_mock_client(), _make_mock_client()], target="t")
        team._push_task(-5, 0, {"type": "test"})
        task = team._pop_task()
        assert task[0] == 0  # clamped to 0

    def test_format_shared_intel_with_pending_tasks(self):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=[_make_mock_client(), _make_mock_client()], target="t")
        team._share_intel(0, "Found XSS")
        team._push_task(3, 0, {"type": "suggested", "description": "Run nuclei on target"})
        result = team._format_shared_intel()
        assert "SHARED INTELLIGENCE" in result
        assert "PENDING TASKS" in result


class TestRunSingleAgent:
    """Tests for TeamAegis._run_single_agent."""

    def test_successful_run(self):
        from tools.multi_agent import TeamAegis

        client = _make_mock_client()
        client.simple_chat.return_value = '{"discussion": "hi", "action": {"type": "none"}}'
        team = TeamAegis(clients=[client, _make_mock_client()], target="t")
        result = team._run_single_agent(0)
        assert result["success"] is True
        assert result["agent_id"] == 0

    def test_error_handling(self):
        from tools.multi_agent import TeamAegis

        client = _make_mock_client()
        client.simple_chat.side_effect = RuntimeError("API error")
        team = TeamAegis(clients=[client, _make_mock_client()], target="t")
        result = team._run_single_agent(0)
        assert result["success"] is False
        assert "API error" in result["error"]


class TestProcessAgentResult:
    """Tests for TeamAegis._process_agent_result."""

    def test_error_result_adds_discussion(self):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=[_make_mock_client(), _make_mock_client()], target="t")
        result = {"agent_id": 0, "success": False, "error": "timeout"}
        team._process_agent_result(result)
        assert len(team.discussion) == 1
        assert "ERROR" in team.discussion[0].content

    def test_success_result_adds_discussion(self):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=[_make_mock_client(), _make_mock_client()], target="t")
        result = {
            "agent_id": 0,
            "success": True,
            "action_data": {"discussion": "Found something", "action": {"type": "none"}},
            "response_text": "raw",
        }
        team._process_agent_result(result)
        assert len(team.discussion) == 1
        assert team.discussion[0].content == "Found something"

    def test_finish_action(self):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=[_make_mock_client(), _make_mock_client()], target="t")
        result = {
            "agent_id": 0,
            "success": True,
            "action_data": {"discussion": "done", "action": {"type": "finish"}},
            "response_text": "raw",
        }
        team._process_agent_result(result)
        assert len(team.discussion) == 1
        assert "done" in team.discussion[0].content

    def test_findings_added(self):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=[_make_mock_client(), _make_mock_client()], target="t")
        result = {
            "agent_id": 0,
            "success": True,
            "action_data": {
                "discussion": "found it",
                "action": {"type": "none"},
                "findings": [{"description": "XSS", "severity": "high"}],
            },
            "response_text": "raw",
        }
        team._process_agent_result(result)
        assert len(team.findings) == 1
        assert team.findings[0].severity == "high"

    def test_confirm_existing_finding(self):
        from tools.multi_agent import Finding, TeamAegis

        team = TeamAegis(clients=[_make_mock_client(), _make_mock_client()], target="t")
        team.findings.append(Finding(source_agent="R", description="SQLi", severity="high"))
        result = {
            "agent_id": 0,
            "success": True,
            "action_data": {
                "discussion": "confirmed",
                "action": {"type": "none"},
                "findings": [{"description": "SQLi", "severity": "critical", "confirmed_by": "E"}],
            },
            "response_text": "raw",
        }
        team._process_agent_result(result)
        assert len(team.findings) == 1
        assert "E" in team.findings[0].confirmed_by

    def test_suggest_task(self):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=[_make_mock_client(), _make_mock_client()], target="t")
        result = {
            "agent_id": 0,
            "success": True,
            "action_data": {
                "discussion": "suggest",
                "action": {"type": "none"},
                "suggest_task": "Run nuclei on target",
            },
            "response_text": "raw",
        }
        team._process_agent_result(result)
        assert len(team.task_queue) > 0

    def test_needs_help(self):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=[_make_mock_client(), _make_mock_client()], target="t")
        result = {
            "agent_id": 0,
            "success": True,
            "action_data": {
                "discussion": "stuck",
                "action": {"type": "none"},
                "needs_help": True,
                "help_request": "How to bypass WAF?",
            },
            "response_text": "raw",
        }
        team._process_agent_result(result)
        help_msgs = [m for m in team.discussion if "HELP NEEDED" in m.content]
        assert len(help_msgs) == 1


# ════════════════════════════════════════════════════════════════════════════
# ADDITIONAL TESTS: targeted_attacks missing items
# ════════════════════════════════════════════════════════════════════════════


class TestRunTargetedAttacks:
    """Tests for run_targeted_attacks orchestrator."""

    def test_empty_endpoints(self):
        from tools.targeted_attacks import run_targeted_attacks
        import asyncio

        with patch("tools.targeted_attacks.aiohttp") as mock_aio:
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_aio.ClientSession.return_value = mock_session
            mock_aio.ClientTimeout.return_value = MagicMock()
            result = asyncio.run(run_targeted_attacks([]))
            assert result == []

    def test_deduplicates_findings(self):
        from tools.targeted_attacks import ConfirmedFinding, run_targeted_attacks
        import asyncio

        ep = _make_endpoint(url="http://t.com/login", method="POST")
        fake_finding = ConfirmedFinding(
            title="SQLi",
            severity="Critical",
            category="sql_injection",
            endpoint_url="http://t.com/login",
            method="POST",
            evidence="e",
            payload="username='",
        )
        with patch("tools.targeted_attacks.aiohttp") as mock_aio, patch(
            "tools.targeted_attacks.test_sql_injection", new_callable=AsyncMock
        ) as mock_sqli:
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_aio.ClientSession.return_value = mock_session
            mock_aio.ClientTimeout.return_value = MagicMock()
            mock_sqli.return_value = [fake_finding]
            result = asyncio.run(run_targeted_attacks([ep, ep]))
            assert len(result) == 1


class TestRunAuthenticatedBola:
    """Tests for run_authenticated_bola."""

    def test_needs_at_least_2_sessions(self):
        from tools.targeted_attacks import run_authenticated_bola
        import asyncio

        session = _MockSession()
        ep = _make_endpoint(url="http://t.com/api/user/1", method="GET")
        auth = MagicMock()
        result = asyncio.run(run_authenticated_bola(session, [ep], [auth]))
        assert result == []

    def test_no_user_endpoints(self):
        from tools.targeted_attacks import run_authenticated_bola
        import asyncio

        session = _MockSession()
        ep = _make_endpoint(url="http://t.com/api/data", method="GET")
        auth1, auth2 = MagicMock(), MagicMock()
        result = asyncio.run(run_authenticated_bola(session, [ep], [auth1, auth2]))
        assert result == []


# ════════════════════════════════════════════════════════════════════════════
# ADDITIONAL TESTS: hunt_engine missing items
# ════════════════════════════════════════════════════════════════════════════


class TestSaveReport:
    """Tests for save_report."""

    def test_saves_json_and_txt(self):
        from tools.hunt_engine import HuntReport, save_report
        import tempfile

        report = HuntReport(
            target="test-save.example.com", started_at="2024-01-01", total_duration=1.0
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "report"
            result = save_report(report, out_dir=out_dir)
            assert (out_dir / "report.json").exists()
            assert (out_dir / "report.txt").exists()
            data = json.loads((out_dir / "report.json").read_text())
            assert data["target"] == "test-save.example.com"
            txt = (out_dir / "report.txt").read_text()
            assert "ELENGENIX HUNT REPORT" in txt

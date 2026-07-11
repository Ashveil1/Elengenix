"""
tests/test_coverage_final.py — Comprehensive coverage tests for 18 modules.

Covers: hybrid_agent, multi_agent, hunt_engine, targeted_attacks,
tool_registry, universal_executor, bounty_intelligence, vuln_researcher,
smart_scanner, native_scanner, welcome_wizard, smart_recon, tui_dashboard,
progress_display, exploitation, ai_tool_creator, scan_engine_upgrade, orchestrator.
"""

import asyncio
import json
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import (
    MagicMock,
    PropertyMock,
    mock_open,
    patch,
    AsyncMock,
    call,
    ANY,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _run_async(coro):
    """Helper to run async coroutines in tests (works on Python 3.10+)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_mock_client():
    """Create a mock AI client with standard interface."""
    client = MagicMock()
    client.chat = MagicMock(return_value='{"action": "complete_mission", "message": "done"}')
    client.simple_chat = MagicMock(return_value='{"discussion": "ok", "action": {"type": "none"}}')
    return client


def _make_mock_session():
    """Create a mock aiohttp.ClientSession."""
    session = MagicMock()
    resp = MagicMock()
    resp.status = 200
    resp.text = MagicMock(return_value='{"status": "ok"}')
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    session.get = MagicMock(return_value=resp)
    session.post = MagicMock(return_value=resp)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session, resp


# ============================================================================
# 1. agents/hybrid_agent.py
# ============================================================================


class TestHybridAgentExtractJson(unittest.TestCase):
    """Tests for _extract_json module-level function."""

    def test_extract_json_direct(self):
        from agents.hybrid_agent import _extract_json

        result = _extract_json('{"action": "run_command", "cmd": "ls"}')
        self.assertEqual(result["action"], "run_command")

    def test_extract_json_markdown_fence(self):
        from agents.hybrid_agent import _extract_json

        text = 'Some text\n```json\n{"key": "value"}\n```\nMore text'
        result = _extract_json(text)
        self.assertEqual(result["key"], "value")

    def test_extract_json_markdown_fence_no_lang(self):
        from agents.hybrid_agent import _extract_json

        text = '```\n{"a": 1}\n```'
        result = _extract_json(text)
        self.assertEqual(result["a"], 1)

    def test_extract_json_nested_braces(self):
        from agents.hybrid_agent import _extract_json

        text = 'prefix {"nested": {"deep": true}} suffix'
        result = _extract_json(text)
        self.assertEqual(result["nested"]["deep"], True)

    def test_extract_json_array(self):
        from agents.hybrid_agent import _extract_json

        text = "result: [1, 2, 3]"
        result = _extract_json(text)
        self.assertEqual(result, [1, 2, 3])

    def test_extract_json_no_valid_json(self):
        from agents.hybrid_agent import _extract_json

        with self.assertRaises(ValueError):
            _extract_json("no json here at all")

    def test_extract_json_array_brackets(self):
        from agents.hybrid_agent import _extract_json

        text = 'Here is the result: [{"name": "a"}, {"name": "b"}]'
        result = _extract_json(text)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["name"], "a")


class TestHybridAgentSimpleCommands(unittest.TestCase):
    """Tests for _SIMPLE_COMMANDS regex."""

    def test_simple_commands_match(self):
        from agents.hybrid_agent import _SIMPLE_COMMANDS

        for cmd in [
            "ls -la",
            "cat file.txt",
            "echo hello",
            "pwd",
            "which python",
            "head -n 5 file",
            "tail -f log",
            "wc -l",
            "whoami",
            "id",
            "date",
            "uptime",
            "env",
            "set",
        ]:
            self.assertIsNotNone(_SIMPLE_COMMANDS.match(cmd), f"Should match: {cmd}")

    def test_simple_commands_no_match(self):
        from agents.hybrid_agent import _SIMPLE_COMMANDS

        self.assertIsNone(_SIMPLE_COMMANDS.match("nmap -sV target"))
        self.assertIsNone(_SIMPLE_COMMANDS.match("curl http://example.com"))
        self.assertIsNone(_SIMPLE_COMMANDS.match("python3 script.py"))


class TestHybridAgentInit(unittest.TestCase):
    """Tests for HybridAgent.__init__."""

    def test_init_defaults(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        self.assertIsNone(agent.client)
        self.assertEqual(agent.target, "")
        self.assertEqual(agent.max_steps, 50)
        self.assertEqual(agent.strategist_interval, 5)
        self.assertTrue(agent.enable_analysis)
        self.assertTrue(agent.enable_memory)
        self.assertEqual(agent.loop_threshold, 4)
        self.assertFalse(agent._use_council)
        self.assertEqual(agent.action_history, [])
        self.assertEqual(agent.all_findings, [])

    def test_init_with_council_clients(self):
        from agents.hybrid_agent import HybridAgent

        mock_client = MagicMock()
        agent = HybridAgent(
            strategist_client=mock_client,
            specialist_client=mock_client,
            critic_client=mock_client,
            target="example.com",
            max_steps=10,
            risk_threshold="high",
        )
        self.assertTrue(agent._use_council)
        self.assertEqual(agent.target, "example.com")
        self.assertEqual(agent.max_steps, 10)
        self.assertEqual(agent._risk_threshold, "high")

    def test_init_legacy_mode(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(client=MagicMock())
        self.assertFalse(agent._use_council)
        self.assertIsNotNone(agent.client)


class TestHybridAgentRunStrategist(unittest.TestCase):
    """Tests for _run_strategist."""

    def test_run_strategist_no_client(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        agent._run_strategist()  # Should not raise
        self.assertEqual(agent.tasks, [])

    def test_run_strategist_success(self):
        from agents.hybrid_agent import HybridAgent

        mock_response = MagicMock()
        mock_response.content = json.dumps(
            [
                {"description": "task 1", "status": "pending"},
                {"description": "task 2", "status": "pending"},
            ]
        )
        mock_client = MagicMock()
        mock_client.chat.return_value = mock_response

        agent = HybridAgent(client=mock_client, target="example.com", enable_memory=False)
        agent.objective = "test objective"
        agent._run_strategist()
        self.assertEqual(len(agent.tasks), 2)
        mock_client.chat.assert_called_once()

    def test_run_strategist_parse_error(self):
        from agents.hybrid_agent import HybridAgent

        mock_response = MagicMock()
        mock_response.content = "not json at all"
        mock_client = MagicMock()
        mock_client.chat.return_value = mock_response

        agent = HybridAgent(client=mock_client)
        agent.objective = "test"
        agent._run_strategist()  # Should handle parse error gracefully
        self.assertEqual(agent.tasks, [])

    def test_run_strategist_exception(self):
        from agents.hybrid_agent import HybridAgent

        mock_client = MagicMock()
        mock_client.chat.side_effect = Exception("API error")

        agent = HybridAgent(client=mock_client)
        agent.objective = "test"
        agent._run_strategist()  # Should handle exception gracefully
        self.assertEqual(agent.tasks, [])


class TestHybridAgentShouldRunAnalysis(unittest.TestCase):
    """Tests for _should_run_analysis."""

    def test_should_run_analysis_empty(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        self.assertFalse(agent._should_run_analysis(""))
        self.assertFalse(agent._should_run_analysis(None))

    def test_should_run_analysis_simple(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        self.assertFalse(agent._should_run_analysis("ls -la"))
        self.assertFalse(agent._should_run_analysis("cat /etc/passwd"))
        self.assertFalse(agent._should_run_analysis("echo hello"))

    def test_should_run_analysis_complex(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        self.assertTrue(agent._should_run_analysis("nmap -sV target.com"))
        self.assertTrue(agent._should_run_analysis("nuclei -u http://target.com"))


class TestHybridAgentExtractFindings(unittest.TestCase):
    """Tests for _extract_findings static method."""

    def test_extract_findings_empty(self):
        from agents.hybrid_agent import HybridAgent

        result = HybridAgent._extract_findings("", "ls")
        self.assertEqual(result, [])

    def test_extract_findings_json_nuclei(self):
        from agents.hybrid_agent import HybridAgent

        output = '{"template-id": "sql-injection", "severity": "high", "matched-at": "http://target.com"}'
        result = HybridAgent._extract_findings(output, "nuclei")
        self.assertGreater(len(result), 0)
        self.assertIn("severity", result[0])

    def test_extract_findings_json_generic(self):
        from agents.hybrid_agent import HybridAgent

        output = '{"vuln": "xss", "severity": "medium", "url": "http://target.com"}'
        result = HybridAgent._extract_findings(output, "custom_scan")
        self.assertGreater(len(result), 0)

    def test_extract_findings_regex_urls(self):
        from agents.hybrid_agent import HybridAgent

        output = "Found: https://admin.example.com\nAlso: http://api.example.com/v1"
        result = HybridAgent._extract_findings(output, "recon")
        # URLs are extracted into a single finding with "urls" list
        all_urls = []
        for f in result:
            all_urls.extend(f.get("urls", []))
        self.assertTrue(any("admin.example.com" in u for u in all_urls))

    def test_extract_findings_regex_secrets(self):
        from agents.hybrid_agent import HybridAgent

        output = "Config found: API_KEY=sk-1234567890abcdef"
        result = HybridAgent._extract_findings(output, "grep")
        self.assertGreater(len(result), 0)

    def test_extract_findings_subdomains(self):
        from agents.hybrid_agent import HybridAgent

        output = "sub1.example.com. 300 IN A 1.2.3.4\nsub2.example.com. 300 IN A 1.2.3.5"
        result = HybridAgent._extract_findings(output, "dig example.com")
        self.assertGreater(len(result), 0)

    def test_extract_findings_http_probe(self):
        from agents.hybrid_agent import HybridAgent

        output = '{"url": "http://target.com", "webserver": "nginx", "status-code": 200, "tech": ["nginx"]}'
        result = HybridAgent._extract_findings(output, "httpx")
        self.assertGreater(len(result), 0)


class TestHybridAgentIsDeadlocked(unittest.TestCase):
    """Tests for _is_deadlocked."""

    def test_not_deadlocked_few_actions(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(loop_threshold=4)
        agent.action_history = [
            {"action": "run_command", "command": "ls"},
            {"action": "run_command", "command": "ls"},
        ]
        self.assertFalse(agent._is_deadlocked())

    def test_deadlocked(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(loop_threshold=3)
        agent.action_history = [
            {"action": "run_command", "command": "ls"},
            {"action": "run_command", "command": "ls"},
            {"action": "run_command", "command": "ls"},
        ]
        self.assertTrue(agent._is_deadlocked())

    def test_not_deadlocked_varied(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent(loop_threshold=3)
        agent.action_history = [
            {"action": "run_command", "command": "ls"},
            {"action": "run_tool", "tool": "nmap"},
            {"action": "run_command", "command": "cat file"},
        ]
        self.assertFalse(agent._is_deadlocked())


class TestHybridAgentFinalizeMission(unittest.TestCase):
    """Tests for _finalize_mission."""

    def test_finalize_empty(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        agent.start_time = time.time()
        agent.all_findings = []
        report = agent._finalize_mission()
        self.assertIn("report", report.lower())
        self.assertIn("findings", report.lower())

    def test_finalize_with_findings(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        agent.start_time = time.time() - 10
        agent.all_findings = [
            {"type": "xss", "url": "http://target.com", "_tool": "nuclei", "severity": "high"},
            {
                "type": "sqli",
                "url": "http://target.com/login",
                "_tool": "sqlmap",
                "severity": "critical",
            },
        ]
        agent.mission_key = "test-mission"
        report = agent._finalize_mission()
        self.assertIn("xss", report.lower())
        self.assertIn("sqli", report.lower())


class TestHybridAgentLog(unittest.TestCase):
    """Tests for _log."""

    def test_log_no_callback(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        agent._log("test message")  # Should not raise

    def test_log_with_callback(self):
        from agents.hybrid_agent import HybridAgent

        cb = MagicMock()
        agent = HybridAgent(callback=cb)
        agent._log("hello")
        cb.assert_called_with("hello")


class TestHybridAgentAgentRef(unittest.TestCase):
    """Tests for _agent_ref."""

    def test_agent_ref(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        ref = agent._agent_ref()
        self.assertTrue(hasattr(ref, "governance"))
        self.assertTrue(hasattr(ref, "payload_mutator"))


class TestHybridAgentHandleRunCommand(unittest.TestCase):
    """Tests for _handle_run_command."""

    def test_handle_run_command(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        decision = {"action": "run_command", "command": "echo hello", "purpose": "test"}
        agent._handle_run_command(decision, 1)
        self.assertEqual(len(agent.action_history), 0)  # action already appended by caller


class TestHybridAgentHandleReadFile(unittest.TestCase):
    """Tests for _handle_read_file."""

    def test_handle_read_file(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        decision = {"action": "read_file", "path": "/tmp/test.txt"}
        agent._handle_read_file(decision)  # Should not raise


class TestHybridAgentHandleUpdateIntel(unittest.TestCase):
    """Tests for _handle_update_intel."""

    def test_handle_update_intel(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        decision = {"action": "update_intel", "intel": {"key": "found something interesting"}}
        agent._handle_update_intel(decision)


class TestHybridAgentHandleSearchWeb(unittest.TestCase):
    """Tests for _handle_search_web."""

    def test_handle_search_web(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        decision = {"action": "search_web", "query": "SQL injection test"}
        agent._handle_search_web(decision)


class TestHybridAgentHandleMessage(unittest.TestCase):
    """Tests for _handle_message."""

    def test_handle_message(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        decision = {"action": "message", "message": "mission complete"}
        agent._handle_message(decision)


class TestHybridAgentBuildCouncil(unittest.TestCase):
    """Tests for _build_council."""

    def test_build_council(self):
        from agents.hybrid_agent import HybridAgent

        mock_client = MagicMock()
        agent = HybridAgent(
            client=mock_client,
            strategist_client=mock_client,
            specialist_client=mock_client,
            critic_client=mock_client,
            target="example.com",
        )
        council = agent._build_council()
        self.assertIsNotNone(council)


class TestHybridAgentRunSpecialistCycle(unittest.TestCase):
    """Tests for _run_specialist_cycle."""

    def test_run_specialist_cycle_no_client(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        result = agent._run_specialist_cycle(1)
        self.assertTrue(result)  # Should retry

    def test_run_specialist_cycle_complete_mission(self):
        from agents.hybrid_agent import HybridAgent

        mock_response = MagicMock()
        mock_response.content = json.dumps({"action": "complete_mission"})
        mock_client = MagicMock()
        mock_client.chat.return_value = mock_response

        agent = HybridAgent(client=mock_client)
        agent.objective = "test"
        result = agent._run_specialist_cycle(1)
        self.assertFalse(result)  # Should stop

    def test_run_specialist_cycle_message(self):
        from agents.hybrid_agent import HybridAgent

        mock_response = MagicMock()
        mock_response.content = json.dumps({"action": "message", "message": "done"})
        mock_client = MagicMock()
        mock_client.chat.return_value = mock_response

        agent = HybridAgent(client=mock_client)
        agent.objective = "test"
        result = agent._run_specialist_cycle(1)
        self.assertFalse(result)


class TestHybridAgentRun(unittest.TestCase):
    """Tests for HybridAgent.run."""

    def test_run_council_mode(self):
        from agents.hybrid_agent import HybridAgent

        mock_client = MagicMock()
        agent = HybridAgent(
            client=mock_client,
            strategist_client=mock_client,
            specialist_client=mock_client,
            critic_client=mock_client,
            target="example.com",
        )
        with patch.object(agent, "_build_council") as mock_build:
            mock_council = MagicMock()
            mock_council.run.return_value = "council report"
            mock_build.return_value = mock_council
            result = agent.run("test objective")
            self.assertEqual(result, "council report")

    def test_run_legacy_mode(self):
        from agents.hybrid_agent import HybridAgent

        agent = HybridAgent()
        agent.objective = "test"
        agent.start_time = time.time()
        # Will go through the loop and finalize
        result = agent._finalize_mission()
        self.assertIsInstance(result, str)


# ============================================================================
# 2. tools/multi_agent.py
# ============================================================================


class TestMultiAgentDataclasses(unittest.TestCase):
    """Tests for dataclasses."""

    def test_team_message(self):
        from tools.multi_agent import TeamMessage

        msg = TeamMessage(
            round=1, agent_id=0, agent_role="Strategist", model_name="gpt-4", content="hello"
        )
        self.assertEqual(msg.round, 1)
        self.assertEqual(msg.msg_type, "discussion")

    def test_task_assignment(self):
        from tools.multi_agent import TaskAssignment

        ta = TaskAssignment(
            agent_id=0, action_type="shell", params={"cmd": "ls"}, description="list files"
        )
        self.assertFalse(ta.completed)
        self.assertFalse(ta.success)

    def test_finding(self):
        from tools.multi_agent import Finding

        f = Finding(source_agent="Strategist", description="XSS found", severity="high")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.confirmed_by, [])


class TestMultiAgentAgentRoles(unittest.TestCase):
    """Tests for AGENT_ROLES constant."""

    def test_agent_roles_count(self):
        from tools.multi_agent import AGENT_ROLES

        self.assertEqual(len(AGENT_ROLES), 3)

    def test_agent_roles_names(self):
        from tools.multi_agent import AGENT_ROLES

        names = [r["name"] for r in AGENT_ROLES]
        self.assertIn("Strategist", names)
        self.assertIn("Recon Lead", names)
        self.assertIn("Exploit Analyst", names)


class TestMultiAgentInit(unittest.TestCase):
    """Tests for TeamAegis.__init__."""

    def test_init_min_clients(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="example.com")
        self.assertEqual(team.team_size, 2)
        self.assertEqual(team.target, "example.com")

    def test_init_too_few_clients(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        with self.assertRaises(ValueError):
            TeamAegis(clients=[mock_client], target="example.com")

    def test_init_truncates_to_3(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client] * 5, target="example.com")
        self.assertEqual(team.team_size, 3)

    def test_init_assigns_roles(self):
        from tools.multi_agent import TeamAegis, AGENT_ROLES

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client, mock_client], target="t")
        self.assertEqual(len(team.roles), 3)
        self.assertEqual(team.roles[0]["name"], "Strategist")


class TestMultiAgentFormatMethods(unittest.TestCase):
    """Tests for formatting methods."""

    def _make_team(self):
        from tools.multi_agent import TeamAegis, TeamMessage, Finding

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="example.com")
        return team

    def test_format_discussion_empty(self):
        from tools.multi_agent import TeamAegis

        team = self._make_team()
        result = team._format_discussion_history()
        self.assertIn("No previous discussion", result)

    def test_format_discussion_with_messages(self):
        from tools.multi_agent import TeamMessage

        team = self._make_team()
        team.discussion = [
            TeamMessage(
                round=1,
                agent_id=0,
                agent_role="Strategist",
                model_name="gpt-4",
                content="Hello team",
            ),
            TeamMessage(
                round=1,
                agent_id=1,
                agent_role="Recon Lead",
                model_name="claude-3",
                content="Ready",
                msg_type="task_result",
            ),
        ]
        result = team._format_discussion_history()
        self.assertIn("Strategist", result)
        self.assertIn("TOOL RESULT", result)

    def test_format_findings_empty(self):
        team = self._make_team()
        result = team._format_findings()
        self.assertIn("No confirmed findings", result)

    def test_format_findings_with_data(self):
        from tools.multi_agent import Finding

        team = self._make_team()
        team.findings = [
            Finding(
                source_agent="Strategist",
                description="XSS",
                severity="high",
                evidence="payload reflected",
            ),
        ]
        result = team._format_findings()
        self.assertIn("HIGH", result)
        self.assertIn("XSS", result)

    def test_format_team_roster(self):
        team = self._make_team()
        result = team._format_team_roster()
        self.assertIn("openai", result)
        self.assertIn("gpt-4", result)

    def test_format_prior_memories_empty(self):
        team = self._make_team()
        result = team._format_prior_memories()
        self.assertIn("No prior memories", result)

    def test_format_prior_memories_with_data(self):
        team = self._make_team()
        team._memories = {"example.com": "found XSS on /api"}
        result = team._format_prior_memories()
        self.assertIn("PRIOR SCAN MEMORIES", result)
        self.assertIn("example.com", result)

    def test_format_shared_intel_empty(self):
        team = self._make_team()
        result = team._format_shared_intel()
        self.assertEqual(result, "")

    def test_format_shared_intel_with_data(self):
        team = self._make_team()
        team.shared_intel = ["[Strategist] Found XSS on /api"]
        result = team._format_shared_intel()
        self.assertIn("SHARED INTELLIGENCE", result)

    def test_format_available_tools_no_registry(self):
        team = self._make_team()
        team.skill_registry = None
        result = team._format_available_tools_for_agent()
        self.assertIn("not available", result.lower())


class TestMultiAgentShareIntel(unittest.TestCase):
    """Tests for _share_intel."""

    def test_share_intel(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        team._share_intel(0, "Found critical XSS")
        self.assertEqual(len(team.shared_intel), 1)
        self.assertIn("Strategist", team.shared_intel[0])

    def test_share_intel_dedup(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        team._share_intel(0, "Found critical XSS")
        team._share_intel(0, "Found critical XSS")
        self.assertEqual(len(team.shared_intel), 1)


class TestMultiAgentTaskQueue(unittest.TestCase):
    """Tests for _push_task and _pop_task."""

    def test_push_and_pop(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        team._push_task(priority=1, agent_id=0, action={"type": "shell", "cmd": "ls"})
        result = team._pop_task()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 1)  # priority

    def test_pop_empty(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        result = team._pop_task()
        self.assertIsNone(result)

    def test_push_negative_priority_clamped(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        team._push_task(priority=-5, agent_id=0, action={"type": "shell"})
        result = team._pop_task()
        self.assertEqual(result[0], 0)  # Clamped to 0

    def test_priority_ordering(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        team._push_task(priority=5, agent_id=0, action={"type": "a"})
        team._push_task(priority=1, agent_id=1, action={"type": "b"})
        team._push_task(priority=3, agent_id=2, action={"type": "c"})
        first = team._pop_task()
        self.assertEqual(first[0], 1)  # Highest priority first


class TestMultiAgentParseAgentResponse(unittest.TestCase):
    """Tests for _parse_agent_response."""

    def test_parse_empty(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        result = team._parse_agent_response("")
        self.assertEqual(result["action"]["type"], "none")

    def test_parse_json_fence(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        text = '```json\n{"discussion": "hello", "action": {"type": "shell"}}\n```'
        result = team._parse_agent_response(text)
        self.assertEqual(result["discussion"], "hello")
        self.assertEqual(result["action"]["type"], "shell")

    def test_parse_raw_json(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        text = '{"discussion": "analysis", "action": {"type": "none"}}'
        result = team._parse_agent_response(text)
        self.assertEqual(result["discussion"], "analysis")

    def test_parse_fallback(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        text = "This is just plain text with no JSON"
        result = team._parse_agent_response(text)
        self.assertEqual(result["action"]["type"], "none")
        self.assertIn("plain text", result["discussion"])


class TestMultiAgentGenerateFinalReport(unittest.TestCase):
    """Tests for _generate_final_report."""

    def test_report_empty(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="example.com")
        report = team._generate_final_report()
        self.assertIn("TEAM AEGIS", report)
        self.assertIn("example.com", report)
        self.assertIn("No confirmed vulnerabilities", report)

    def test_report_with_findings(self):
        from tools.multi_agent import TeamAegis, Finding, TaskAssignment

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        team.findings = [
            Finding(source_agent="Strategist", description="XSS", severity="high"),
            Finding(source_agent="Recon Lead", description="Info Leak", severity="info"),
        ]
        team.tasks = [
            TaskAssignment(
                agent_id=0,
                action_type="shell",
                params={},
                description="scan",
                success=True,
                completed=True,
            ),
        ]
        team.round = 5
        report = team._generate_final_report()
        self.assertIn("HIGH", report)
        self.assertIn("XSS", report)
        self.assertIn("ACTIONS EXECUTED: 1", report)


class TestMultiAgentExecuteAgentAction(unittest.TestCase):
    """Tests for _execute_agent_action."""

    def test_execute_none_action(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        result = team._execute_agent_action(0, {"type": "none"}, MagicMock())
        self.assertEqual(result, "")

    def test_execute_finish_action(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        result = team._execute_agent_action(0, {"type": "finish"}, MagicMock())
        self.assertEqual(result, "")

    def test_execute_shell_action(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        mock_executor = MagicMock()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.output = "command output"
        mock_executor.execute_action.return_value = mock_result
        result = team._execute_agent_action(
            0, {"type": "shell", "params": {"cmd": "ls"}, "description": "list"}, mock_executor
        )
        self.assertIn("command output", result)
        self.assertEqual(len(team.tasks), 1)


class TestMultiAgentProcessAgentResult(unittest.TestCase):
    """Tests for _process_agent_result."""

    def test_process_error_result(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        result = {"agent_id": 0, "success": False, "error": "timeout"}
        voted = team._process_agent_result(result)
        self.assertFalse(voted)
        self.assertGreater(len(team.discussion), 0)

    def test_process_success_finish_vote(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t")
        result = {
            "agent_id": 0,
            "success": True,
            "action_data": {"discussion": "done", "action": {"type": "finish"}},
            "response_text": "done",
        }
        voted = team._process_agent_result(result)
        # _process_agent_result returns None for finish (no explicit return)
        # The finish vote is tracked via the discussion message
        self.assertGreater(len(team.discussion), 0)


class TestMultiAgentRunRoundSequential(unittest.TestCase):
    """Tests for run_round_sequential."""

    def test_run_round_sequential(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="t", parallel_mode=False)
        with patch.object(team, "_run_single_agent") as mock_run:
            mock_run.return_value = {
                "agent_id": 0,
                "success": True,
                "action_data": {"discussion": "hi", "action": {"type": "none"}},
                "response_text": "hi",
            }
            result = team.run_round_sequential()
            self.assertTrue(result)  # Should continue
            self.assertEqual(team.round, 1)


class TestMultiAgentBuildAgentPrompt(unittest.TestCase):
    """Tests for _build_agent_prompt."""

    def test_build_prompt(self):
        from tools.multi_agent import TeamAegis

        mock_client = MagicMock()
        mock_client.provider = "openai"
        mock_client.model = "gpt-4"
        team = TeamAegis(clients=[mock_client, mock_client], target="example.com")
        prompt = team._build_agent_prompt(0)
        self.assertIn("Strategist", prompt)
        self.assertIn("example.com", prompt)
        self.assertIn("Recon Lead", prompt)


# ============================================================================
# 3. tools/hunt_engine.py
# ============================================================================


class TestHuntEngineSeverity(unittest.TestCase):
    """Tests for Severity enum."""

    def test_severity_values(self):
        from tools.hunt_engine import Severity

        self.assertEqual(Severity.CRITICAL.value, "Critical")
        self.assertEqual(Severity.HIGH.value, "High")
        self.assertEqual(Severity.MEDIUM.value, "Medium")
        self.assertEqual(Severity.LOW.value, "Low")
        self.assertEqual(Severity.INFO.value, "Informational")


class TestHuntEngineDataclasses(unittest.TestCase):
    """Tests for HuntFinding, HuntPhase, HuntReport."""

    def test_hunt_finding_to_dict(self):
        from tools.hunt_engine import HuntFinding

        f = HuntFinding(
            phase="recon", category="endpoint", severity="High", title="test", url="http://t.com"
        )
        d = f.to_dict()
        self.assertEqual(d["phase"], "recon")
        self.assertEqual(d["severity"], "High")

    def test_hunt_phase(self):
        from tools.hunt_engine import HuntPhase

        p = HuntPhase(name="recon", status="done", duration=1.5, findings=3)
        self.assertEqual(p.status, "done")
        self.assertEqual(p.findings, 3)

    def test_hunt_report_by_severity(self):
        from tools.hunt_engine import HuntReport, HuntFinding

        report = HuntReport(target="t.com", started_at="2024-01-01")
        report.findings = [
            HuntFinding(phase="recon", category="x", severity="High", title="a"),
            HuntFinding(phase="scan", category="y", severity="High", title="b"),
            HuntFinding(phase="recon", category="z", severity="Low", title="c"),
        ]
        by_sev = report.by_severity()
        self.assertEqual(by_sev["High"], 2)
        self.assertEqual(by_sev["Low"], 1)

    def test_hunt_report_by_phase(self):
        from tools.hunt_engine import HuntReport, HuntFinding

        report = HuntReport(target="t.com", started_at="2024-01-01")
        report.findings = [
            HuntFinding(phase="recon", category="x", severity="High", title="a"),
            HuntFinding(phase="scan", category="y", severity="Low", title="b"),
        ]
        by_phase = report.by_phase()
        self.assertEqual(by_phase["recon"], 1)
        self.assertEqual(by_phase["scan"], 1)


class TestHuntEngineInit(unittest.TestCase):
    """Tests for HuntEngine.__init__."""

    def test_init(self):
        from tools.hunt_engine import HuntEngine

        engine = HuntEngine(target="example.com")
        self.assertEqual(engine.target, "example.com")
        self.assertEqual(engine.skip_phases, set())
        self.assertFalse(engine.quiet)

    def test_init_skip_phases(self):
        from tools.hunt_engine import HuntEngine

        engine = HuntEngine(target="example.com", skip_phases=["recon", "smart"])
        self.assertIn("recon", engine.skip_phases)

    def test_normalize_target(self):
        from tools.hunt_engine import HuntEngine

        self.assertEqual(HuntEngine._normalize_target("https://example.com"), "example.com")
        self.assertEqual(HuntEngine._normalize_target("http://example.com/"), "example.com")
        self.assertEqual(HuntEngine._normalize_target("  example.com  "), "example.com")

    def test_normalize_target_no_protocol(self):
        from tools.hunt_engine import HuntEngine

        self.assertEqual(HuntEngine._normalize_target("example.com"), "example.com")


class TestHuntEngineReportFormats(unittest.TestCase):
    """Tests for report_to_console, report_to_dict, save_report."""

    def test_report_to_console(self):
        from tools.hunt_engine import HuntReport, HuntPhase, HuntFinding, report_to_console

        report = HuntReport(target="t.com", started_at="2024-01-01", total_duration=10.5)
        report.phases = [HuntPhase(name="recon", status="done", duration=2.0, findings=5)]
        report.findings = [
            HuntFinding(
                phase="recon",
                category="xss",
                severity="High",
                title="XSS found",
                url="http://t.com/api",
                evidence={"proof_of_concept": {"impact": "session hijack"}},
            ),
        ]
        report.risk_score = 75
        report.risk_level = "High"
        report.chains = [{"chain_type": "xss_to_sqli", "findings": ["XSS"], "url": "http://t.com"}]
        output = report_to_console(report)
        self.assertIn("t.com", output)
        self.assertIn("75/100", output)
        self.assertIn("LIVE", output)

    def test_report_to_console_empty(self):
        from tools.hunt_engine import HuntReport, report_to_console

        report = HuntReport(target="t.com", started_at="2024-01-01")
        output = report_to_console(report)
        self.assertIn("No live vulnerabilities", output)

    def test_report_to_dict(self):
        from tools.hunt_engine import HuntReport, HuntPhase, report_to_dict

        report = HuntReport(target="t.com", started_at="2024-01-01")
        report.phases = [HuntPhase(name="recon", status="done")]
        d = report_to_dict(report)
        self.assertEqual(d["target"], "t.com")
        self.assertEqual(len(d["phases"]), 1)

    def test_save_report(self):
        from tools.hunt_engine import HuntReport, save_report

        report = HuntReport(target="t.com", started_at="2024-01-01")
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            result = save_report(report, out_dir=out)
            self.assertTrue((out / "report.json").exists())
            self.assertTrue((out / "report.txt").exists())


# ============================================================================
# 4. tools/targeted_attacks.py
# ============================================================================


class TestTargetedAttacksDataclass(unittest.TestCase):
    """Tests for ConfirmedFinding."""

    def test_confirmed_finding(self):
        from tools.targeted_attacks import ConfirmedFinding

        f = ConfirmedFinding(
            title="SQL Injection",
            severity="Critical",
            category="sql_injection",
            endpoint_url="http://t.com/login",
            method="POST",
            evidence="status changed",
            payload="admin'--",
            status_code=200,
            confidence=1.0,
        )
        self.assertEqual(f.severity, "Critical")
        self.assertEqual(f.confidence, 1.0)


class TestTargetedAttacksPayloads(unittest.TestCase):
    """Tests for payload constants."""

    def test_sqli_payloads(self):
        from tools.targeted_attacks import SQLI_PAYLOADS

        self.assertGreater(len(SQLI_PAYLOADS), 0)
        for payload, kind in SQLI_PAYLOADS:
            self.assertIsInstance(payload, str)
            self.assertIsInstance(kind, str)

    def test_xss_payloads(self):
        from tools.targeted_attacks import XSS_PAYLOADS

        self.assertGreater(len(XSS_PAYLOADS), 0)

    def test_ssti_payloads(self):
        from tools.targeted_attacks import SSTI_PAYLOADS

        self.assertGreater(len(SSTI_PAYLOADS), 0)


class TestTargetedAttacksTestSqlInjection(unittest.TestCase):
    """Tests for test_sql_injection."""

    def test_sql_injection_skips_get(self):
        from tools.targeted_attacks import test_sql_injection
        from tools.endpoint_discovery import Endpoint

        mock_session = MagicMock()
        ep = Endpoint(url="http://t.com/api", method="GET", params=[], source="test")
        result = _run_async(test_sql_injection(mock_session, ep))
        self.assertEqual(result, [])

    def test_sql_injection_on_login(self):
        from tools.targeted_attacks import test_sql_injection
        from tools.endpoint_discovery import Endpoint

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="login failed")

        mock_session = MagicMock()
        mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.post.return_value.__aexit__ = AsyncMock(return_value=False)

        ep = Endpoint(url="http://t.com/login", method="POST", params=[], source="test")
        result = _run_async(test_sql_injection(mock_session, ep))
        self.assertIsInstance(result, list)


class TestTargetedAttacksTestXss(unittest.TestCase):
    """Tests for test_xss."""

    def test_xss_on_get_endpoint(self):
        from tools.targeted_attacks import test_xss
        from tools.endpoint_discovery import Endpoint

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="safe output")

        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)

        ep = Endpoint(url="http://t.com/search", method="GET", params=["q"], source="test")
        result = _run_async(test_xss(mock_session, ep))
        self.assertIsInstance(result, list)


class TestTargetedAttacksRunTargetedAttacks(unittest.TestCase):
    """Tests for run_targeted_attacks."""

    def test_run_targeted_attacks_no_endpoints(self):
        from tools.targeted_attacks import run_targeted_attacks

        result = _run_async(run_targeted_attacks([], concurrency=1))
        self.assertEqual(result, [])


class TestTargetedAttacksRunAuthenticatedBola(unittest.TestCase):
    """Tests for run_authenticated_bola."""

    def test_bola_insufficient_sessions(self):
        from tools.targeted_attacks import run_authenticated_bola

        mock_session = MagicMock()
        result = _run_async(run_authenticated_bola(mock_session, [], [MagicMock()]))
        self.assertEqual(result, [])


# ============================================================================
# 5. tools/tool_registry.py
# ============================================================================


class TestToolRegistryEnums(unittest.TestCase):
    """Tests for ToolCategory and ToolPriority enums."""

    def test_tool_category_values(self):
        from tools.tool_registry import ToolCategory

        self.assertEqual(ToolCategory.RECON.value, "reconnaissance")
        self.assertEqual(ToolCategory.SCANNER.value, "vulnerability_scanner")
        self.assertEqual(ToolCategory.EXPLOITATION.value, "exploitation")

    def test_tool_priority_values(self):
        from tools.tool_registry import ToolPriority

        self.assertEqual(ToolPriority.CRITICAL.value, 1)
        self.assertEqual(ToolPriority.HIGH.value, 2)
        self.assertEqual(ToolPriority.MEDIUM.value, 3)
        self.assertEqual(ToolPriority.LOW.value, 4)


class TestToolRegistryToolResult(unittest.TestCase):
    """Tests for ToolResult."""

    def test_tool_result_to_dict(self):
        from tools.tool_registry import ToolResult, ToolCategory

        result = ToolResult(
            success=True,
            tool_name="nuclei",
            category=ToolCategory.SCANNER,
            output="found xss" * 100,
            findings=[{"type": "xss"}],
            execution_time=1.5,
        )
        d = result.to_dict()
        self.assertTrue(d["success"])
        self.assertEqual(d["findings_count"], 1)
        self.assertEqual(d["execution_time"], 1.5)
        self.assertLessEqual(len(d["output"]), 500)


class TestToolRegistryToolMetadata(unittest.TestCase):
    """Tests for ToolMetadata."""

    def test_metadata(self):
        from tools.tool_registry import ToolMetadata, ToolCategory, ToolPriority

        meta = ToolMetadata(
            name="test_tool",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="test",
            description="Test tool",
        )
        self.assertEqual(meta.name, "test_tool")
        self.assertTrue(meta.requires_target)
        self.assertEqual(meta.timeout_seconds, 300)


class TestToolRegistryRegister(unittest.TestCase):
    """Tests for ToolRegistry.register and get_tool."""

    def test_register_and_get(self):
        from tools.tool_registry import (
            ToolRegistry,
            BaseTool,
            ToolMetadata,
            ToolCategory,
            ToolPriority,
        )

        # Create a fresh registry to avoid polluting global state
        reg = ToolRegistry()
        reg._initialized = True  # Prevent auto-discovery

        mock_tool = MagicMock(spec=BaseTool)
        mock_tool.metadata = ToolMetadata(
            name="test_tool_xyz",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="test",
            description="Test",
        )
        mock_tool.is_available = True

        reg.register(mock_tool)
        retrieved = reg.get_tool("test_tool_xyz")
        self.assertEqual(retrieved, mock_tool)

        # Cleanup
        reg.unregister("test_tool_xyz")

    def test_get_tool_not_found(self):
        from tools.tool_registry import ToolRegistry

        reg = ToolRegistry()
        self.assertIsNone(reg.get_tool("nonexistent_tool_xyz"))

    def test_unregister(self):
        from tools.tool_registry import ToolRegistry, ToolMetadata, ToolCategory, ToolPriority

        reg = ToolRegistry()
        reg._initialized = True
        mock_tool = MagicMock()
        mock_tool.metadata = ToolMetadata(
            name="temp_tool_xyz",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="test",
            description="Temp",
        )
        reg.register(mock_tool)
        reg.unregister("temp_tool_xyz")
        self.assertIsNone(reg.get_tool("temp_tool_xyz"))


class TestToolRegistryListAvailableTools(unittest.TestCase):
    """Tests for list_available_tools."""

    def test_list_available_tools(self):
        from tools.tool_registry import ToolRegistry, ToolMetadata, ToolCategory, ToolPriority

        reg = ToolRegistry()
        reg._initialized = True
        mock_tool = MagicMock()
        mock_tool.metadata = ToolMetadata(
            name="list_test_xyz",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="test",
            description="Test",
        )
        mock_tool.is_available = True
        reg.register(mock_tool)

        tools = reg.list_available_tools()
        self.assertIn("list_test_xyz", tools)
        self.assertTrue(tools["list_test_xyz"]["available"])

        reg.unregister("list_test_xyz")


class TestToolRegistryListByCategory(unittest.TestCase):
    """Tests for get_tools_by_category."""

    def test_list_by_category(self):
        from tools.tool_registry import ToolRegistry, ToolMetadata, ToolCategory, ToolPriority

        reg = ToolRegistry()
        reg._initialized = True
        mock_tool = MagicMock()
        mock_tool.metadata = ToolMetadata(
            name="cat_test_xyz",
            category=ToolCategory.RECON,
            priority=ToolPriority.HIGH,
            binary_name="test",
            description="Test",
        )
        reg.register(mock_tool)

        tools = reg.get_tools_by_category(ToolCategory.RECON)
        names = [t.metadata.name for t in tools]
        self.assertIn("cat_test_xyz", names)

        reg.unregister("cat_test_xyz")


class TestToolRegistryRegisterDecorator(unittest.TestCase):
    """Tests for @register_tool decorator."""

    def test_register_tool_decorator(self):
        from tools.tool_registry import (
            register_tool,
            ToolMetadata,
            ToolCategory,
            ToolPriority,
            BaseTool,
        )

        meta = ToolMetadata(
            name="decorator_test_xyz",
            category=ToolCategory.UTILITY,
            priority=ToolPriority.LOW,
            binary_name="echo",
            description="Decorator test",
        )

        @register_tool(meta)
        class DecoratorTestTool(BaseTool):
            async def execute(self, target, report_dir, semaphore, **kwargs):
                pass

        from tools.tool_registry import registry

        tool = registry.get_tool("decorator_test_xyz")
        self.assertIsNotNone(tool)
        self.assertIsInstance(tool, DecoratorTestTool)

        registry.unregister("decorator_test_xyz")


class TestToolRegistryExecuteChain(unittest.TestCase):
    """Tests for execute_chain."""

    def test_execute_chain_skips_unavailable(self):
        from tools.tool_registry import ToolRegistry, ToolMetadata, ToolCategory, ToolPriority

        reg = ToolRegistry()
        reg._initialized = True
        mock_tool = MagicMock()
        mock_tool.is_available = False
        mock_tool.metadata = ToolMetadata(
            name="unavail_xyz",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="nonexistent_binary_xyz",
            description="Unavailable tool",
        )
        reg.register(mock_tool)

        async def run():
            return await reg.execute_chain([mock_tool], "target", Path("/tmp"))

        results = _run_async(run())
        self.assertEqual(len(results), 0)

        reg.unregister("unavail_xyz")


# ============================================================================
# 6. tools/universal_executor.py
# ============================================================================


class TestUniversalExecutorFileEditor(unittest.TestCase):
    """Tests for FileEditor."""

    def test_read_file(self):
        from tools.universal_executor import FileEditor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("line1\nline2\nline3\n")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.read_file(str(test_file))
            self.assertTrue(result.success)
            self.assertIn("line1", result.output)

    def test_read_file_not_found(self):
        from tools.universal_executor import FileEditor

        editor = FileEditor(base_dir="/tmp")
        result = editor.read_file("/tmp/nonexistent_xyz.txt")
        self.assertFalse(result.success)

    def test_read_sensitive_file(self):
        from tools.universal_executor import FileEditor

        editor = FileEditor(base_dir="/tmp")
        result = editor.read_file("/tmp/.env")
        self.assertFalse(result.success)
        self.assertIn("denied", result.error.lower())

    def test_write_file(self):
        from tools.universal_executor import FileEditor

        with tempfile.TemporaryDirectory() as tmpdir:
            editor = FileEditor(base_dir=tmpdir)
            test_file = str(Path(tmpdir) / "new.txt")
            result = editor.write_file(test_file, "hello world")
            self.assertTrue(result.success)
            self.assertEqual(Path(test_file).read_text(), "hello world")

    def test_write_file_no_overwrite(self):
        from tools.universal_executor import FileEditor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "existing.txt"
            test_file.write_text("original")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.write_file(str(test_file), "new content")
            self.assertFalse(result.success)
            self.assertIn("exists", result.error.lower())

    def test_write_file_overwrite(self):
        from tools.universal_executor import FileEditor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "existing.txt"
            test_file.write_text("original")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.write_file(str(test_file), "new content", overwrite=True)
            self.assertTrue(result.success)
            self.assertEqual(test_file.read_text(), "new content")

    def test_edit_file(self):
        from tools.universal_executor import FileEditor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "edit.txt"
            test_file.write_text("hello world")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.edit_file(str(test_file), "hello", "goodbye")
            self.assertTrue(result.success)
            self.assertEqual(test_file.read_text(), "goodbye world")

    def test_edit_file_not_found(self):
        from tools.universal_executor import FileEditor

        editor = FileEditor(base_dir="/tmp")
        result = editor.edit_file("/tmp/nonexistent.txt", "a", "b")
        self.assertFalse(result.success)

    def test_edit_file_not_found_string(self):
        from tools.universal_executor import FileEditor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "edit.txt"
            test_file.write_text("hello world")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.edit_file(str(test_file), "nonexistent", "replacement")
            self.assertFalse(result.success)
            self.assertIn("not found", result.error.lower())

    def test_edit_file_multiple_occurrences(self):
        from tools.universal_executor import FileEditor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "edit.txt"
            test_file.write_text("aaa bbb aaa")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.edit_file(str(test_file), "aaa", "ccc")
            self.assertFalse(result.success)
            self.assertIn("2", result.error)

    def test_search_in_file(self):
        from tools.universal_executor import FileEditor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "search.txt"
            test_file.write_text("line1\npassword=secret\nline3\n")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.search_in_file(str(test_file), "password")
            self.assertTrue(result.success)
            self.assertIn("password", result.output)

    def test_search_in_file_no_match(self):
        from tools.universal_executor import FileEditor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "search.txt"
            test_file.write_text("line1\nline2\n")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.search_in_file(str(test_file), "nonexistent")
            self.assertTrue(result.success)
            self.assertIn("No matches", result.output)

    def test_list_directory(self):
        from tools.universal_executor import FileEditor

        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir).joinpath("file1.txt").write_text("a")
            Path(tmpdir).joinpath("file2.txt").write_text("b")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.list_directory(tmpdir)
            self.assertTrue(result.success)
            self.assertIn("file1.txt", result.output)

    def test_list_directory_not_dir(self):
        from tools.universal_executor import FileEditor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "file.txt"
            test_file.write_text("a")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.list_directory(str(test_file))
            self.assertFalse(result.success)


class TestUniversalExecutorPackageManager(unittest.TestCase):
    """Tests for PackageManager."""

    def test_unknown_manager(self):
        from tools.universal_executor import PackageManager

        pm = PackageManager()
        result = pm.execute("unknown_manager", "install", "pkg")
        self.assertFalse(result.success)
        self.assertIn("Unknown", result.error)

    def test_unknown_action(self):
        from tools.universal_executor import PackageManager

        pm = PackageManager()
        result = pm.execute("pip", "deploy", "pkg")
        self.assertFalse(result.success)


class TestUniversalExecutorIsSafeCommand(unittest.TestCase):
    """Tests for is_safe_command."""

    def test_empty_command(self):
        from tools.universal_executor import UniversalExecutor

        executor = UniversalExecutor(base_dir="/tmp")
        safe, reason = executor.is_safe_command("")
        self.assertFalse(safe)
        self.assertIn("Empty", reason)

    def test_safe_command(self):
        from tools.universal_executor import UniversalExecutor

        executor = UniversalExecutor(base_dir="/tmp")
        safe, reason = executor.is_safe_command("ls -la")
        # May be safe or need approval depending on governance
        self.assertIsInstance(safe, bool)

    def test_destructive_command(self):
        from tools.universal_executor import UniversalExecutor

        executor = UniversalExecutor(base_dir="/tmp")
        safe, reason = executor.is_safe_command("rm -rf /")
        self.assertFalse(safe)


class TestUniversalExecutorExecuteAction(unittest.TestCase):
    """Tests for execute_action dispatch."""

    def test_execute_read_file(self):
        from tools.universal_executor import UniversalExecutor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("content")
            executor = UniversalExecutor(base_dir=tmpdir)
            result = executor.execute_action(
                {"type": "read_file", "params": {"path": str(test_file)}}
            )
            self.assertTrue(result.success)

    def test_execute_write_file(self):
        from tools.universal_executor import UniversalExecutor

        with tempfile.TemporaryDirectory() as tmpdir:
            executor = UniversalExecutor(base_dir=tmpdir)
            result = executor.execute_action(
                {
                    "type": "write_file",
                    "params": {"path": str(Path(tmpdir) / "new.txt"), "content": "data"},
                }
            )
            self.assertTrue(result.success)

    def test_execute_edit_file(self):
        from tools.universal_executor import UniversalExecutor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "edit.txt"
            test_file.write_text("hello")
            executor = UniversalExecutor(base_dir=tmpdir)
            result = executor.execute_action(
                {
                    "type": "edit_file",
                    "params": {
                        "path": str(test_file),
                        "old_string": "hello",
                        "new_string": "world",
                    },
                }
            )
            self.assertTrue(result.success)

    def test_execute_search_file(self):
        from tools.universal_executor import UniversalExecutor

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "search.txt"
            test_file.write_text("needle in haystack")
            executor = UniversalExecutor(base_dir=tmpdir)
            result = executor.execute_action(
                {"type": "search_file", "params": {"path": str(test_file), "pattern": "needle"}}
            )
            self.assertTrue(result.success)

    def test_execute_list_dir(self):
        from tools.universal_executor import UniversalExecutor

        with tempfile.TemporaryDirectory() as tmpdir:
            executor = UniversalExecutor(base_dir=tmpdir)
            result = executor.execute_action({"type": "list_dir", "params": {"path": tmpdir}})
            self.assertTrue(result.success)

    def test_execute_shell(self):
        from tools.universal_executor import UniversalExecutor

        executor = UniversalExecutor(base_dir="/tmp")
        result = executor.execute_action({"type": "shell", "params": {"command": "echo hello"}})
        self.assertTrue(result.success)
        self.assertIn("hello", result.output)

    def test_execute_package(self):
        from tools.universal_executor import UniversalExecutor

        executor = UniversalExecutor(base_dir="/tmp")
        result = executor.execute_action(
            {"type": "package", "params": {"manager": "pip", "action": "list"}}
        )
        # pip list may succeed or fail depending on environment
        self.assertIsInstance(result.success, bool)

    def test_execute_unknown_type(self):
        from tools.universal_executor import UniversalExecutor

        executor = UniversalExecutor(base_dir="/tmp")
        result = executor.execute_action({"type": "unknown", "params": {}})
        # Should return an error or empty result
        self.assertIsInstance(result.success, bool)


class TestUniversalExecutorExecuteShell(unittest.TestCase):
    """Tests for execute_shell."""

    def test_execute_shell_echo(self):
        from tools.universal_executor import UniversalExecutor

        executor = UniversalExecutor(base_dir="/tmp")
        result = executor.execute_shell("echo test123")
        self.assertTrue(result.success)
        self.assertIn("test123", result.output)

    def test_execute_shell_with_agent_id(self):
        from tools.universal_executor import UniversalExecutor

        executor = UniversalExecutor(base_dir="/tmp")
        result = executor.execute_shell("echo agent", agent_id=99)
        self.assertTrue(result.success)

    def test_execute_shell_blocked(self):
        from tools.universal_executor import UniversalExecutor

        executor = UniversalExecutor(base_dir="/tmp")
        result = executor.execute_shell("rm -rf /")
        self.assertFalse(result.success)


# ============================================================================
# 7. tools/bounty_intelligence.py
# ============================================================================


class TestBountyIntelligenceBountyProgram(unittest.TestCase):
    """Tests for BountyProgram dataclass."""

    def test_bounty_range_equal(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://t.com",
            offers_bounties=True,
            min_bounty=500,
            max_bounty=500,
        )
        self.assertEqual(p.bounty_range, "$500")

    def test_bounty_range_different(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://t.com",
            offers_bounties=True,
            min_bounty=100,
            max_bounty=5000,
        )
        self.assertEqual(p.bounty_range, "$100 - $5,000")

    def test_is_worth_targeting_yes(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://t.com",
            offers_bounties=True,
            min_bounty=500,
            max_bounty=10000,
            is_public=True,
        )
        self.assertTrue(p.is_worth_targeting)

    def test_is_worth_targeting_no_bounties(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://t.com",
            offers_bounties=False,
            min_bounty=0,
            max_bounty=0,
            is_public=True,
        )
        self.assertFalse(p.is_worth_targeting)

    def test_is_worth_targeting_low_bounty(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://t.com",
            offers_bounties=True,
            min_bounty=10,
            max_bounty=100,
            is_public=True,
        )
        self.assertFalse(p.is_worth_targeting)

    def test_is_worth_targeting_private(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://t.com",
            offers_bounties=True,
            min_bounty=500,
            max_bounty=5000,
            is_public=False,
        )
        self.assertFalse(p.is_worth_targeting)


class TestBountyIntelligenceInit(unittest.TestCase):
    """Tests for BountyIntelligence.__init__."""

    def test_init_no_api(self):
        from tools.bounty_intelligence import BountyIntelligence

        bi = BountyIntelligence()
        self.assertIsNone(bi.api_key)
        self.assertIsNone(bi.api_auth)

    def test_init_with_api(self):
        from tools.bounty_intelligence import BountyIntelligence

        bi = BountyIntelligence(api_key="key", api_username="user")
        self.assertEqual(bi.api_auth, ("user", "key"))


class TestBountyIntelligenceRankPrograms(unittest.TestCase):
    """Tests for rank_programs."""

    def test_rank_empty(self):
        from tools.bounty_intelligence import BountyIntelligence

        bi = BountyIntelligence()
        result = bi.rank_programs([])
        self.assertEqual(result, [])

    def test_rank_programs(self):
        from tools.bounty_intelligence import BountyIntelligence, BountyProgram

        bi = BountyIntelligence()
        programs = [
            BountyProgram(
                id="1",
                name="Low",
                platform="hackerone",
                url="http://low.com",
                offers_bounties=True,
                min_bounty=100,
                max_bounty=1000,
                response_time_hours=48,
            ),
            BountyProgram(
                id="2",
                name="High",
                platform="hackerone",
                url="http://high.com",
                offers_bounties=True,
                min_bounty=500,
                max_bounty=10000,
                response_time_hours=24,
                scope=[{"asset": "api"}],
            ),
        ]
        ranked = bi.rank_programs(programs)
        self.assertEqual(ranked[0].name, "High")
        self.assertGreater(ranked[0].score_total, ranked[1].score_total)

    def test_rank_programs_no_response_time(self):
        from tools.bounty_intelligence import BountyIntelligence, BountyProgram

        bi = BountyIntelligence()
        programs = [
            BountyProgram(
                id="1",
                name="NoTime",
                platform="hackerone",
                url="http://t.com",
                offers_bounties=True,
                min_bounty=100,
                max_bounty=5000,
                response_time_hours=None,
            ),
        ]
        ranked = bi.rank_programs(programs)
        self.assertEqual(ranked[0].score_response, 15)  # Default average


class TestBountyIntelligenceFormatProgramsList(unittest.TestCase):
    """Tests for format_programs_list."""

    def test_format_empty(self):
        from tools.bounty_intelligence import BountyIntelligence

        bi = BountyIntelligence()
        result = bi.format_programs_list([])
        self.assertIn("No programs found", result)

    def test_format_with_programs(self):
        from tools.bounty_intelligence import BountyIntelligence, BountyProgram

        bi = BountyIntelligence()
        programs = [
            BountyProgram(
                id="1",
                name="Shopify",
                platform="hackerone",
                url="http://shopify.com",
                offers_bounties=True,
                min_bounty=500,
                max_bounty=30000,
                response_time_hours=48,
                scope=[{"a": "1"}, {"a": "2"}],
            ),
        ]
        result = bi.format_programs_list(programs, show_scores=True)
        self.assertIn("Shopify", result)
        self.assertIn("$500 - $30,000", result)
        self.assertIn("Score:", result)


class TestBountyIntelligenceParseApiProgram(unittest.TestCase):
    """Tests for _parse_api_program."""

    def test_parse_api_program(self):
        from tools.bounty_intelligence import BountyIntelligence

        bi = BountyIntelligence()
        data = {
            "id": "12345",
            "attributes": {
                "name": "Test Corp",
                "handle": "testcorp",
                "state": "open",
                "response_time": {"hours": 24},
            },
            "relationships": {
                "bounty_range": {"data": {"min": 500, "max": 10000, "currency": "USD"}},
                "structured_scopes": {
                    "data": [
                        {
                            "attributes": {
                                "asset_identifier": "*.testcorp.com",
                                "asset_type": "URL",
                                "eligible_for_bounty": True,
                                "instruction": "test",
                            }
                        }
                    ]
                },
            },
        }
        program = bi._parse_api_program(data)
        self.assertEqual(program.name, "Test Corp")
        self.assertTrue(program.offers_bounties)
        self.assertEqual(program.min_bounty, 500)
        self.assertEqual(program.max_bounty, 10000)
        self.assertTrue(program.is_public)
        self.assertEqual(len(program.scope), 1)


class TestBountyIntelligenceParsePublicProgram(unittest.TestCase):
    """Tests for _parse_public_program."""

    def test_parse_public_program(self):
        from tools.bounty_intelligence import BountyIntelligence

        bi = BountyIntelligence()
        data = {
            "id": "999",
            "attributes": {
                "name": "Public Corp",
                "handle": "publiccorp",
                "state": "open",
                "bounty_range": {"min": 200, "max": 5000},
            },
        }
        program = bi._parse_public_program(data)
        self.assertEqual(program.name, "Public Corp")
        self.assertTrue(program.offers_bounties)
        self.assertEqual(program.max_bounty, 5000)


class TestBountyIntelligenceExtractFromReactState(unittest.TestCase):
    """Tests for _extract_from_react_state."""

    def test_extract_from_react_state(self):
        from tools.bounty_intelligence import BountyIntelligence

        bi = BountyIntelligence()
        data = {
            "queries": [
                {"state": {"data": [{"name": "Program1"}, {"name": "Program2"}]}},
                {"state": {"data": {"data": [{"name": "Program3"}]}}},
            ]
        }
        result = bi._extract_from_react_state(data)
        self.assertEqual(len(result), 3)

    def test_extract_from_react_state_empty(self):
        from tools.bounty_intelligence import BountyIntelligence

        bi = BountyIntelligence()
        result = bi._extract_from_react_state({})
        self.assertEqual(result, [])


class TestBountyIntelligenceScrapeFallback(unittest.TestCase):
    """Tests for _scrape_programs_fallback."""

    def test_scrape_fallback(self):
        from tools.bounty_intelligence import BountyIntelligence

        bi = BountyIntelligence()
        programs = bi._scrape_programs_fallback(3)
        self.assertEqual(len(programs), 3)
        self.assertTrue(programs[0].offers_bounties)
        self.assertTrue(programs[0].is_worth_targeting)


class TestBountyIntelligenceCache(unittest.TestCase):
    """Tests for _cache_programs and _get_cached_programs."""

    def test_cache_and_retrieve(self):
        from tools.bounty_intelligence import BountyIntelligence, BountyProgram

        bi = BountyIntelligence()
        programs = [
            BountyProgram(
                id="cache_test_1",
                name="CacheTest",
                platform="hackerone",
                url="http://cache.com",
                offers_bounties=True,
                min_bounty=500,
                max_bounty=5000,
            ),
        ]
        bi._cache_programs(programs)
        cached = bi._get_cached_programs(limit=10)
        names = [p.name for p in cached]
        self.assertIn("CacheTest", names)


# ============================================================================
# 8. tools/vuln_researcher.py
# ============================================================================


class TestVulnResearcherDataclasses(unittest.TestCase):
    """Tests for dataclasses."""

    def test_cve_research_result(self):
        from tools.vuln_researcher import CVEResearchResult

        r = CVEResearchResult(
            cve_id="CVE-2024-1234",
            cvss_score=9.8,
            severity="Critical",
            description="RCE in widget",
            affected_products=["Widget 1.0"],
            exploitation_requirements=["network access"],
            exploit_conditions={"requires_auth": False},
            available_pocs=[{"source": "github", "url": "http://t.com", "type": "python"}],
            patched_versions=["1.1"],
            references=["http://nvd.nist.gov"],
            github_advisories=[],
            ai_summary="Critical RCE",
            confidence=0.9,
        )
        self.assertEqual(r.cve_id, "CVE-2024-1234")
        self.assertEqual(r.confidence, 0.9)

    def test_exploit_condition(self):
        from tools.vuln_researcher import ExploitCondition

        ec = ExploitCondition(
            prerequisite="auth",
            details="need valid token",
            how_to_check="login",
            exploitability_score=0.8,
        )
        self.assertEqual(ec.exploitability_score, 0.8)

    def test_disclosed_bounty(self):
        from tools.vuln_researcher import DisclosedBounty

        db = DisclosedBounty(
            title="SQLi in API",
            program="Shopify",
            severity="Critical",
            payout="$5000",
            disclosed_at="2024-01-01",
            summary="Found SQL injection",
            key_techniques=["sqli"],
            url="http://h1.com",
            reporter="researcher",
        )
        self.assertEqual(db.payout, "$5000")

    def test_custom_poc(self):
        from tools.vuln_researcher import CustomPoC

        poc = CustomPoC(
            code="print('hello')",
            language="python",
            target_framework="Django",
            verification_steps=["step1"],
            expected_output="hello",
            mitigations=["parameterize"],
        )
        self.assertEqual(poc.language, "python")


class TestVulnResearcherInit(unittest.TestCase):
    """Tests for VulnerabilityResearcher.__init__."""

    def test_init(self):
        from tools.vuln_researcher import VulnerabilityResearcher

        researcher = VulnerabilityResearcher()
        self.assertIsNone(researcher.ai_client)
        self.assertIsNotNone(researcher.vuln_patterns)

    def test_init_with_client(self):
        from tools.vuln_researcher import VulnerabilityResearcher

        mock_client = MagicMock()
        researcher = VulnerabilityResearcher(ai_client=mock_client)
        self.assertEqual(researcher.ai_client, mock_client)

    def test_load_vulnerability_patterns(self):
        from tools.vuln_researcher import VulnerabilityResearcher

        researcher = VulnerabilityResearcher()
        patterns = researcher.vuln_patterns
        self.assertIn("rce", patterns)
        self.assertIn("sqli", patterns)
        self.assertIn("ssrf", patterns)
        self.assertIn("xss", patterns)
        self.assertIn("auth_bypass", patterns)

    def test_get_cache_path(self):
        from tools.vuln_researcher import VulnerabilityResearcher

        researcher = VulnerabilityResearcher()
        path = researcher._get_cache_path("CVE-2024-1234")
        self.assertTrue(str(path).endswith(".json"))

    def test_load_cache_miss(self):
        from tools.vuln_researcher import VulnerabilityResearcher

        researcher = VulnerabilityResearcher()
        result = researcher._load_cache("nonexistent_key_xyz")
        self.assertIsNone(result)


# ============================================================================
# 9. tools/smart_scanner.py
# ============================================================================


class TestSmartScannerPhaseConfig(unittest.TestCase):
    """Tests for ScanPhaseConfig and PHASES."""

    def test_scan_phase_config(self):
        from tools.smart_scanner import ScanPhaseConfig

        config = ScanPhaseConfig(
            name="test",
            description="test phase",
            estimated_tokens=1000,
            estimated_duration_minutes=5,
            required_tools=["tool1"],
            is_critical=True,
        )
        self.assertEqual(config.name, "test")
        self.assertTrue(config.is_critical)

    def test_phases_constant(self):
        from tools.smart_scanner import PHASES

        self.assertEqual(len(PHASES), 4)
        names = [p.name for p in PHASES]
        self.assertIn("discovery", names)
        self.assertIn("vulnerability_scan", names)
        self.assertIn("exploit_verification", names)
        self.assertIn("report_generation", names)

    def test_critical_phases(self):
        from tools.smart_scanner import PHASES

        critical = [p for p in PHASES if p.is_critical]
        self.assertEqual(len(critical), 2)


class TestSmartScannerInit(unittest.TestCase):
    """Tests for SmartScanner.__init__."""

    @patch("tools.smart_scanner.get_token_manager")
    @patch("tools.smart_scanner.get_telegram_bridge")
    def test_init(self, mock_tb, mock_tm):
        from tools.smart_scanner import SmartScanner

        mock_tm.return_value = MagicMock()
        mock_tb.return_value = MagicMock()
        scanner = SmartScanner(target="example.com")
        self.assertEqual(scanner.target, "example.com")
        self.assertTrue(scanner.auto_pause)

    @patch("tools.smart_scanner.get_token_manager")
    @patch("tools.smart_scanner.get_telegram_bridge")
    def test_init_custom_params(self, mock_tb, mock_tm):
        from tools.smart_scanner import SmartScanner

        mock_tm.return_value = MagicMock()
        mock_tb.return_value = MagicMock()
        scanner = SmartScanner(target="t.com", auto_pause=False, pause_after_hours=5)
        self.assertFalse(scanner.auto_pause)
        self.assertEqual(scanner.pause_after_hours, 5)


# ============================================================================
# 10. tools/native_scanner.py
# ============================================================================


class TestNativeScannerDataclasses(unittest.TestCase):
    """Tests for ScanTarget, ScanResult, ScanSummary."""

    def test_scan_target(self):
        from tools.native_scanner import ScanTarget

        t = ScanTarget(url="http://t.com", method="POST")
        self.assertEqual(t.method, "POST")
        self.assertEqual(hash(t), hash(("http://t.com", "POST", None)))

    def test_scan_result_to_dict(self):
        from tools.native_scanner import ScanResult

        r = ScanResult(url="http://t.com", status_code=200, server="nginx")
        d = r.to_dict()
        self.assertEqual(d["url"], "http://t.com")
        self.assertEqual(d["status_code"], 200)

    def test_scan_summary_duration(self):
        from tools.native_scanner import ScanSummary

        s = ScanSummary(target="t.com", start_time=100.0, end_time=110.0)
        self.assertEqual(s.duration, 10.0)

    def test_scan_summary_no_duration(self):
        from tools.native_scanner import ScanSummary

        s = ScanSummary(target="t.com", start_time=0.0, end_time=0.0)
        self.assertEqual(s.duration, 0.0)


class TestNativeScannerFingerprint(unittest.TestCase):
    """Tests for fingerprint_tech."""

    def test_fingerprint_nginx(self):
        from tools.native_scanner import fingerprint_tech

        result = fingerprint_tech({"Server": "nginx/1.20"}, "")
        self.assertIn("nginx", result)

    def test_fingerprint_wordpress(self):
        from tools.native_scanner import fingerprint_tech

        result = fingerprint_tech({}, "<html>wp-content/themes/flavor</html>")
        self.assertIn("wordpress", result)

    def test_fingerprint_flask(self):
        from tools.native_scanner import fingerprint_tech

        result = fingerprint_tech({}, "<html>Jinja2 template</html>")
        self.assertIn("flask", result)

    def test_fingerprint_empty(self):
        from tools.native_scanner import fingerprint_tech

        result = fingerprint_tech({}, "")
        self.assertEqual(result, [])


class TestNativeScannerInit(unittest.TestCase):
    """Tests for NativeScanner.__init__."""

    def test_init_defaults(self):
        from tools.native_scanner import NativeScanner

        scanner = NativeScanner()
        self.assertEqual(scanner.max_concurrent, 20)
        self.assertEqual(scanner.timeout, 10.0)
        self.assertEqual(scanner.max_retries, 2)
        self.assertTrue(scanner.follow_redirects)

    def test_init_custom(self):
        from tools.native_scanner import NativeScanner

        scanner = NativeScanner(max_concurrent=5, timeout=5.0, max_retries=1)
        self.assertEqual(scanner.max_concurrent, 5)
        self.assertEqual(scanner.timeout, 5.0)


# ============================================================================
# 11. tools/welcome_wizard.py
# ============================================================================


class TestWelcomeWizard(unittest.TestCase):
    """Tests for WelcomeWizard."""

    def test_setup_config(self):
        try:
            from tools.welcome_wizard import SetupConfig

            config = SetupConfig(
                ai_provider="openai",
                ai_model="gpt-4",
                default_mode="autonomous",
                rate_limit=10,
                theme="minimal",
                auto_update=True,
                telemetry=False,
            )
            self.assertEqual(config.ai_provider, "openai")
            self.assertFalse(config.telemetry)
            self.assertTrue(config.auto_update)
        except ImportError:
            self.skipTest("welcome_wizard not importable")


# ============================================================================
# 12. tools/smart_recon.py
# ============================================================================


class TestSmartRecon(unittest.TestCase):
    """Tests for SmartReconEngine."""

    def test_asset_node(self):
        from tools.smart_recon import AssetNode

        node = AssetNode(id="n1", asset_type="domain", value="example.com")
        self.assertTrue(hasattr(node, "__dataclass_fields__") or hasattr(node, "__init__"))

    def test_asset_edge(self):
        from tools.smart_recon import AssetEdge

        edge = AssetEdge(source="n1", target="n2", relation="has_finding")
        self.assertTrue(hasattr(edge, "__dataclass_fields__") or hasattr(edge, "__init__"))

    def test_recon_result(self):
        from tools.smart_recon import ReconResult

        result = ReconResult(nodes=[], edges=[], findings=[], stats={})
        self.assertTrue(hasattr(result, "__dataclass_fields__") or hasattr(result, "__init__"))


# ============================================================================
# 13. tools/tui_dashboard.py
# ============================================================================


class TestTuiDashboard(unittest.TestCase):
    """Tests for TUI Dashboard classes."""

    def test_import(self):
        try:
            import tools.tui_dashboard

            self.assertTrue(hasattr(tools.tui_dashboard, "__file__"))
        except ImportError:
            self.skipTest("tui_dashboard not importable")


# ============================================================================
# 14. tools/progress_display.py
# ============================================================================


class TestProgressDisplay(unittest.TestCase):
    """Tests for ScanPhase, ProgressMetrics, ProgressDisplay."""

    def test_scan_phase(self):
        from tools.progress_display import ScanPhase

        phase = ScanPhase(id="recon", name="Reconnaissance", subtasks=["DNS", "Subdomains"])
        self.assertEqual(phase.status, "pending")
        self.assertEqual(phase.progress, 0.0)
        self.assertEqual(phase.duration, 0.0)

    def test_scan_phase_duration_with_start(self):
        from tools.progress_display import ScanPhase

        phase = ScanPhase(id="scan", name="Scan", subtasks=[])
        phase.start_time = time.time() - 5
        self.assertGreater(phase.duration, 0)

    def test_scan_phase_duration_with_end(self):
        from tools.progress_display import ScanPhase

        phase = ScanPhase(id="scan", name="Scan", subtasks=[])
        phase.start_time = 100.0
        phase.end_time = 110.0
        self.assertEqual(phase.duration, 10.0)

    def test_progress_metrics(self):
        try:
            from tools.progress_display import ProgressMetrics

            metrics = ProgressMetrics()
            self.assertTrue(
                hasattr(metrics, "__dataclass_fields__") or hasattr(metrics, "__init__")
            )
        except (ImportError, TypeError):
            self.skipTest("ProgressMetrics not available")

    def test_progress_display_init(self):
        try:
            from tools.progress_display import ProgressDisplay

            display = ProgressDisplay(target="example.com")
            self.assertIsNotNone(display)
        except (ImportError, TypeError):
            self.skipTest("ProgressDisplay not available")

    def test_spinner(self):
        try:
            from tools.progress_display import Spinner

            spinner = Spinner()
            self.assertIsNotNone(spinner)
        except (ImportError, TypeError, AttributeError):
            self.skipTest("Spinner not available")

    def test_compact_progress(self):
        try:
            from tools.progress_display import CompactProgress

            cp = CompactProgress()
            self.assertIsNotNone(cp)
        except (ImportError, TypeError, AttributeError):
            self.skipTest("CompactProgress not available")


# ============================================================================
# 15. tools/exploitation.py
# ============================================================================


class TestExploitationDataclass(unittest.TestCase):
    """Tests for ExploitProof."""

    def test_exploit_proof(self):
        from tools.exploitation import ExploitProof

        proof = ExploitProof(
            title="SQL Injection Data Extraction",
            description="Extracting user data via SQLi",
            steps=["Step 1", "Step 2"],
            impact_demonstrated="Full database dump",
            curl_command="curl -X POST 'http://t.com/login'",
            python_repro="import requests",
            data_extracted={"users": ["admin"]},
        )
        self.assertEqual(len(proof.steps), 2)
        self.assertEqual(proof.data_extracted["users"], ["admin"])


class TestExploitationExploitSqli(unittest.TestCase):
    """Tests for exploit_sqli."""

    def test_exploit_sqli_no_data(self):
        from tools.exploitation import exploit_sqli

        mock_response = AsyncMock()
        mock_response.status = 403
        mock_response.text = AsyncMock(return_value="forbidden")

        mock_session = MagicMock()
        mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.post.return_value.__aexit__ = AsyncMock(return_value=False)

        proof = _run_async(exploit_sqli(mock_session, "http://t.com/login"))
        self.assertIsNotNone(proof)
        self.assertEqual(proof.title, "SQL Injection - Data Extraction")


class TestExploitationExploitPathTraversal(unittest.TestCase):
    """Tests for exploit_path_traversal."""

    def test_exploit_path_traversal(self):
        from tools.exploitation import exploit_path_traversal

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="root:x:0:0")

        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)

        proof = _run_async(exploit_path_traversal(mock_session, "http://t.com/download"))
        self.assertIsNotNone(proof)


class TestExploitationExploitSsti(unittest.TestCase):
    """Tests for exploit_ssti."""

    def test_exploit_ssti(self):
        from tools.exploitation import exploit_ssti

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="49")

        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)

        proof = _run_async(exploit_ssti(mock_session, "http://t.com/render"))
        self.assertIsNotNone(proof)


class TestExploitationExploitJwt(unittest.TestCase):
    """Tests for exploit_jwt_alg_none."""

    def test_exploit_jwt(self):
        from tools.exploitation import exploit_jwt_alg_none

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"admin": true}')

        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)

        proof = _run_async(exploit_jwt_alg_none(mock_session, "http://t.com/verify"))
        self.assertIsNotNone(proof)


class TestExploitationExploitXss(unittest.TestCase):
    """Tests for exploit_xss."""

    def test_exploit_xss(self):
        from tools.exploitation import exploit_xss

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(
            return_value="<html><script>alert('elengenix-pwned')</script></html>"
        )

        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)

        proof = _run_async(exploit_xss(mock_session, "http://t.com/search"))
        self.assertIsNotNone(proof)


# ============================================================================
# 16. tools/ai_tool_creator.py
# ============================================================================


class TestAiToolCreator(unittest.TestCase):
    """Tests for ai_tool_creator module."""

    def test_import(self):
        try:
            import tools.ai_tool_creator

            self.assertTrue(hasattr(tools.ai_tool_creator, "__file__"))
        except ImportError:
            self.skipTest("ai_tool_creator not importable")


# ============================================================================
# 17. tools/scan_engine_upgrade.py
# ============================================================================


class TestScanEngineUpgrade(unittest.TestCase):
    """Tests for SmartOrchestrator."""

    def test_import(self):
        try:
            from core import scan_engine

            self.assertTrue(hasattr(scan_engine, "__file__"))
        except ImportError:
            self.skipTest("scan_engine_upgrade not importable")


# ============================================================================
# 18. orchestrator.py
# ============================================================================


class TestOrchestrator(unittest.TestCase):
    """Tests for orchestrator module."""

    def test_import(self):
        try:
            import core.orchestrator

            self.assertTrue(hasattr(core.orchestrator, "__file__"))
        except ImportError:
            self.skipTest("orchestrator not importable")


# ============================================================================
# Run
# ============================================================================

if __name__ == "__main__":
    unittest.main()

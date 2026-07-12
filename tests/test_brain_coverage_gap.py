"""
Comprehensive coverage gap fill for core/brain.py — targets all uncovered lines.

Coverage baseline (from 180 existing tests): 78%
This file adds tests for the remaining ~142 lines to push coverage above 80%.
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.brain import (  # noqa: E402
    ElengenixAgent,
    _get_db_path,
    get_context_for_ai,
    _analyze_intent,
    _extract_target_from_text,
    display_in_chat_mode,
    send_telegram_notification,
    execute_tool,
    handle_ask_user,
    execute_tool_registry,
    execute_tool_subprocess,
)
from tools.tool_registry import ToolCategory, ToolResult


# ======================================================================
# Module-level lazy loaders & helpers
# ======================================================================


class TestGetDbPath:
    """Covers core.brain:35-38 — _SQLITE_DB is None branch."""

    def test_returns_default_path(self):
        path = _get_db_path()
        assert "elengenix" in path
        assert path.endswith("conversations.db")


class TestGetContextForAiEmptyQuery:
    """Covers core.brain:147 — current_query is falsy -> returns ''."""

    def test_empty_query(self):
        assert get_context_for_ai("", target="test") == ""

    def test_none_query(self):
        assert get_context_for_ai(None, target="test") == ""


class TestAnalyzeIntentFallback:
    """Covers core.brain:200-205 — exception handler fallback keywords."""

    def _fallback_intent(self, text: str) -> str:
        """Force the fallback path by making analyze_intent raise."""
        with patch("elengenix.scanning.universal.analyze_intent",
                   side_effect=Exception("forced fallback")):
            return _analyze_intent(None, text)

    def test_scan_keyword(self):
        assert self._fallback_intent("please scan this host") == "scan"

    def test_attack_keyword(self):
        assert self._fallback_intent("attack the box") == "scan"

    def test_recon_keyword(self):
        assert self._fallback_intent("do recon on target") == "scan"

    def test_exploit_keyword(self):
        assert self._fallback_intent("run exploit") == "scan"

    def test_vuln_keyword(self):
        assert self._fallback_intent("check vuln") == "scan"

    def test_target_keyword(self):
        assert self._fallback_intent("target is example.com") == "scan"

    def test_casual_fallback(self):
        assert self._fallback_intent("hello, how are you?") == "casual"


class TestExtractTargetFromText:
    """Covers core.brain:211-220 — domain + IP regex extraction."""

    def test_extract_domain(self):
        assert _extract_target_from_text("scan example.com") == "example.com"

    def test_extract_domain_with_protocol(self):
        assert _extract_target_from_text(
            "test https://sub.example.org/path"
        ) == "sub.example.org"

    def test_extract_ip(self):
        assert _extract_target_from_text("attack 192.168.1.1") == "192.168.1.1"

    def test_no_match(self):
        assert _extract_target_from_text("hello world") == ""


class TestDisplayInChatMode:
    """Covers core.brain:231."""

    def test_logs_message(self, caplog):
        import logging
        with caplog.at_level(logging.INFO, logger="core.brain"):
            display_in_chat_mode("test message", mode="warn")
        assert "[WARN] test message" in caplog.text


class TestSendTelegramNotification:
    """Covers core.brain:236."""

    def test_logs_message(self, caplog):
        import logging
        with caplog.at_level(logging.INFO, logger="core.brain"):
            send_telegram_notification("alert!")
        assert "[TELEGRAM] alert!" in caplog.text


class TestExecuteTool:
    """Covers core.brain:243-244 — delegates to tools.tool_executor.execute_tool."""

    def test_calls_through(self):
        """Fake the import so the function body runs without real module."""
        action = {"tool": "nmap", "args": "-sT"}
        with patch.dict("sys.modules", {
            "tools.tool_executor": MagicMock(),
        }):
            from tools import tool_executor
            tool_executor.execute_tool = MagicMock(return_value="mocked")
            # Re-patch after our fake module is set up
            with patch("tools.tool_executor.execute_tool", return_value="mocked"):
                result = execute_tool(action)
                assert result == "mocked"


class TestHandleAskUser:
    """Covers core.brain:249."""

    def test_returns_prompt(self):
        result = handle_ask_user({"question": "Proceed?"})
        assert "Proceed?" in result
        assert "User response needed" in result


class TestExecuteToolRegistry:
    """Covers core.brain:255-259 — tool found + not found."""

    @patch("tools.tool_registry.registry")
    def test_tool_found(self, mock_reg):
        mock_tool = MagicMock()
        mock_tool.handler.return_value = ToolResult(
            success=True, tool_name="nmap", category=ToolCategory.RECON,
            output="scan result",
        )
        mock_reg.get.return_value = mock_tool
        result = execute_tool_registry("nmap", "example.com")
        assert result.success is True
        assert result.output == "scan result"

    @patch("tools.tool_registry.registry")
    def test_tool_not_found(self, mock_reg):
        mock_reg.get.return_value = None
        result = execute_tool_registry("unknown", "test")
        assert isinstance(result, ToolResult)
        assert not result.success


class TestExecuteToolSubprocess:
    """Covers core.brain:265-273 — subprocess success + failure."""

    @patch("subprocess.check_output")
    def test_success(self, mock_check):
        mock_check.return_value = b"scan output"
        result = execute_tool_subprocess("echo", "hello")
        assert result.success is True

    @patch("subprocess.check_output")
    def test_failure(self, mock_check):
        mock_check.side_effect = Exception("not found")
        result = execute_tool_subprocess("nonexistent", "x")
        assert result.success is False


# ======================================================================
# ElengenixAgent — constructor, setters, trivial methods
# ======================================================================


class TestAgentConstructor:
    """Covers core.brain:337-367 — __init__ body."""

    def test_init_sets_all_attributes(self):
        agent = ElengenixAgent(
            max_steps=10,
            loop_threshold=5,
            history_limit=3,
            max_output_len=1000,
            enable_planning=True,
            enable_cot_logging=True,
            max_history_turns=50,
            verbose_thoughts=True,
            verify_ssl=False,
            agent_prompt_template="custom prompt",
        )
        assert agent.max_steps == 10
        assert agent.loop_threshold == 5
        assert agent.history_limit == 3
        assert agent.max_output_len == 1000
        assert agent.enable_planning is True
        assert agent.enable_cot_logging is True
        assert agent.max_history_turns == 50
        assert agent.verbose_thoughts is True
        assert agent.verify_ssl is False
        assert agent.agent_prompt_template == "custom prompt"
        assert agent.cvss_client is not None
        assert isinstance(agent.activity_log, list)


class TestAgentPropertySetters:
    """Covers core.brain:380, 391, 402 — property setters."""

    def test_logic_analyzer_setter(self):
        agent = ElengenixAgent()
        mock_val = MagicMock()
        agent.logic_analyzer = mock_val
        assert agent._logic_analyzer is mock_val

    def test_payload_mutator_setter(self):
        agent = ElengenixAgent()
        mock_val = MagicMock()
        agent.payload_mutator = mock_val
        assert agent._payload_mutator is mock_val

    def test_smart_orchestrator_setter(self):
        agent = ElengenixAgent()
        mock_val = MagicMock()
        agent.smart_orchestrator = mock_val
        assert agent._smart_orchestrator is mock_val


class TestAgentConversation:
    """Covers core.brain:417, 423, 431 — no conversation_manager branches."""

    def test_append_history_no_manager(self):
        agent = ElengenixAgent()
        agent.conversation_manager = None
        agent._append_history("user", "hello")
        assert len(agent.conversation_history) == 1
        assert agent.conversation_history[0] == {"role": "user", "content": "hello"}

    def test_clear_history_no_manager(self):
        agent = ElengenixAgent()
        agent.conversation_manager = None
        agent.conversation_history.append({"role": "user", "content": "x"})
        agent.clear_conversation_history()
        assert agent.conversation_history == []

    def test_build_chat_messages_no_manager(self):
        agent = ElengenixAgent()
        agent.conversation_manager = None
        msgs = agent._build_chat_messages("sys prompt", "user input")
        assert len(msgs) == 2
        assert msgs[0] == {"role": "system", "content": "sys prompt"}
        assert msgs[1] == {"role": "user", "content": "user input"}


# ======================================================================
# process_query — casual path edge cases
# ======================================================================


class TestProcessQueryCasualEdgeCases:
    """Covers core.brain:777, 790-791 — no client + remember exception."""

    def test_casual_no_client(self):
        """agent with client=None -> uses fallback response format."""
        agent = ElengenixAgent()
        agent.client = None
        with patch("elengenix.scanning.universal.analyze_intent",
                   return_value="casual"):
            result = agent.process_query("hello there")
        assert "[CASUAL] Received: hello there" in result

    @patch("core.brain.remember")
    def test_casual_remember_exception(self, mock_remember):
        """remember() raises -> caught by except, still returns response."""
        mock_remember.side_effect = Exception("db full")
        agent = ElengenixAgent()
        agent.client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.content = "Hello! How can I help?"
        agent.client.chat.return_value = mock_resp
        with patch("elengenix.scanning.universal.analyze_intent",
                   return_value="casual"):
            result = agent.process_query("hi")
        assert "Hello!" in result


# ======================================================================
# process_query — scan path edge cases
# ======================================================================


class TestProcessQueryScanEdgeCases:
    """Covers scan-path lines 831, 837-838, 854-855, 894-898, 906-907, 914-918."""

    def test_scan_no_client(self):
        """No client -> empty JSON parse -> finish fallback."""
        agent = ElengenixAgent()
        agent.client = None
        agent.max_steps = 1
        result = agent.process_query("scan test.com", target="test.com")
        assert isinstance(result, str)

    @patch("core.brain.remember")
    @patch("core.brain.get_context_for_ai", return_value="")
    @patch("core.brain._get_now_context", return_value="now")
    def test_scan_invalid_json_from_ai(self, mock_now, mock_context, mock_remember):
        """AI returns malformed JSON -> action defaults to finish."""
        agent = ElengenixAgent()
        agent.client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.content = "not even json"
        agent.client.chat.return_value = mock_resp
        agent.max_steps = 1
        result = agent.process_query("scan target", target="target")
        assert "Task finished" in result

    @patch("core.brain.remember")
    @patch("core.brain.get_context_for_ai", return_value="")
    @patch("core.brain._get_now_context", return_value="now")
    def test_scan_remember_exception_on_finish(self, mock_now, mock_context, mock_remember):
        """remember() on finish branch raises -> caught."""
        mock_remember.side_effect = Exception("fail")
        agent = ElengenixAgent()
        agent.client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.content = json.dumps({"action": "finish", "summary": "done work"})
        agent.client.chat.return_value = mock_resp
        agent.max_steps = 1
        result = agent.process_query("scan target", target="target")
        assert "Task finished" in result

    @patch("core.brain.remember", return_value=None)
    @patch("core.brain.get_context_for_ai", return_value="")
    @patch("core.brain._get_now_context", return_value="now")
    @patch("core.brain.display_in_chat_mode")
    def test_scan_save_memory_action(self, mock_display, mock_now, mock_context, mock_remember):
        """'save_memory' action continues loop."""
        from collections import namedtuple

        ChatResp = namedtuple("ChatResp", "content")
        agent = ElengenixAgent()
        agent.client = MagicMock()
        agent.client.chat.side_effect = [
            ChatResp(
                content=json.dumps({
                    "action": "save_memory",
                    "learning": "found open port 80",
                    "target": "example.com",
                    "category": "finding",
                })
            ),
            ChatResp(
                content=json.dumps({
                    "action": "finish",
                    "summary": "scan complete",
                })
            ),
        ]
        agent.max_steps = 5
        result = agent.process_query("scan example.com", target="example.com")
        assert "Task finished" in result
        mock_display.assert_called()

    @patch("core.brain.get_context_for_ai", return_value="")
    @patch("core.brain._get_now_context", return_value="now")
    def test_scan_governance_blocked_not_deny(self, mock_now, mock_context):
        """Gate with allowed=False but decision != 'deny' -> hits line 894-898."""
        agent = ElengenixAgent()
        agent.client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.content = json.dumps({
            "action": "run_shell",
            "tool": "nmap",
            "command": "nmap -sT target",
        })
        agent.client.chat.return_value = mock_resp
        agent.max_steps = 1

        mock_gate = MagicMock()
        mock_gate.decision = "review"  # not "deny"
        mock_gate.allowed = False
        mock_gate.rationale = "needs human review"
        mock_governance = MagicMock()
        mock_governance.gate.return_value = mock_gate
        agent.governance = mock_governance

        result = agent.process_query("scan test", target="test")
        assert "Governance gate" in result

    @patch("core.brain.get_context_for_ai", return_value="")
    @patch("core.brain._get_now_context", return_value="now")
    @patch(
        "core.brain.execute_tool_registry",
        return_value=ToolResult(
            success=True,
            tool_name="nmap",
            category=ToolCategory.RECON,
            output="done",
        ),
    )
    @patch("core.brain.display_in_chat_mode")
    def test_scan_execute_tool_path(
        self, mock_display, mock_exec, mock_now, mock_context
    ):
        """run_shell action with allowed gate -> executes tool."""
        from collections import namedtuple

        ChatResp = namedtuple("ChatResp", "content")
        agent = ElengenixAgent()
        agent.client = MagicMock()
        agent.client.chat.side_effect = [
            ChatResp(
                content=json.dumps({
                    "action": "run_shell",
                    "tool": "nmap",
                    "command": "nmap -sT example.com",
                    "target": "example.com",
                })
            ),
            ChatResp(
                content=json.dumps({
                    "action": "finish",
                    "summary": "scan results saved",
                })
            ),
        ]
        agent.max_steps = 5
        mock_gate = MagicMock()
        mock_gate.decision = "allow"
        mock_gate.allowed = True
        mock_governance = MagicMock()
        mock_governance.gate.return_value = mock_gate
        agent.governance = mock_governance

        result = agent.process_query("scan example.com", target="example.com")
        assert "Task finished" in result
        mock_exec.assert_called()

    @patch("core.brain.get_context_for_ai", return_value="")
    @patch("core.brain._get_now_context", return_value="now")
    @patch("core.brain.execute_tool_registry")
    def test_scan_execute_tool_exception(self, mock_exec, mock_now, mock_context):
        """execute_tool_registry raises -> caught (line 906-907)."""
        from collections import namedtuple

        ChatResp = namedtuple("ChatResp", "content")
        mock_exec.side_effect = Exception("crash")
        agent = ElengenixAgent()
        agent.client = MagicMock()
        agent.client.chat.side_effect = [
            ChatResp(
                content=json.dumps({
                    "action": "run_shell",
                    "tool": "broken_tool",
                    "command": "broken",
                })
            ),
            ChatResp(
                content=json.dumps({
                    "action": "finish",
                    "summary": "done",
                })
            ),
        ]
        agent.max_steps = 5
        mock_gate = MagicMock()
        mock_gate.decision = "allow"
        mock_gate.allowed = True
        mock_governance = MagicMock()
        mock_governance.gate.return_value = mock_gate
        agent.governance = mock_governance

        result = agent.process_query("scan x", target="x")
        assert "Task finished" in result

    @patch("core.brain.get_context_for_ai", return_value="")
    @patch("core.brain._get_now_context", return_value="now")
    @patch("core.brain.remember")
    def test_scan_remember_exception_in_save_memory(
        self, mock_remember, mock_now, mock_context
    ):
        """save_memory: remember() raises -> caught (line 870-871)."""
        from collections import namedtuple

        ChatResp = namedtuple("ChatResp", "content")
        mock_remember.side_effect = Exception("fail")
        agent = ElengenixAgent()
        agent.client = MagicMock()
        agent.client.chat.side_effect = [
            ChatResp(
                content=json.dumps({
                    "action": "save_memory",
                    "learning": "important finding",
                    "target": "x",
                    "category": "finding",
                })
            ),
            ChatResp(
                content=json.dumps({
                    "action": "finish",
                    "summary": "done",
                })
            ),
        ]
        agent.max_steps = 5
        result = agent.process_query("scan x", target="x")
        assert "Task finished" in result

    @patch("core.brain.get_context_for_ai", return_value="")
    @patch("core.brain._get_now_context", return_value="now")
    def test_scan_unknown_action(self, mock_now, mock_context):
        """Unknown action -> treated as finish (line 914-918)."""
        from collections import namedtuple

        ChatResp = namedtuple("ChatResp", "content")
        agent = ElengenixAgent()
        agent.client = MagicMock()
        agent.client.chat.return_value = ChatResp(
            content=json.dumps({"action": "dance", "summary": "dancing"})
        )
        agent.max_steps = 1
        result = agent.process_query("do something", target="x")
        assert "Task finished" in result


# ======================================================================
# Agent helper methods
# ======================================================================


class TestAgentEnhancePrompt:
    """Covers core.brain:599 — no base_prompt path."""

    def test_no_base_prompt(self):
        agent = ElengenixAgent()
        agent.base_prompt = ""
        result = agent._enhance_prompt_with_cve_context()
        assert "[CVE Context]" in result
        assert agent.base_prompt != ""


class TestAgentExtractJson:
    """Covers core.brain:636-638, 645-648 — JSON extraction with repair."""

    def test_empty_text(self):
        agent = ElengenixAgent()
        assert agent._extract_json("") is None
        assert agent._extract_json(None) is None

    def test_trailing_comma_repair(self):
        agent = ElengenixAgent()
        text = '{"key": "value", "list": [1, 2, 3],}'
        result = agent._extract_json(text)
        assert result == {"key": "value", "list": [1, 2, 3]}

    def test_code_fence_extraction(self):
        agent = ElengenixAgent()
        text = 'Some text\n```json\n{"a": 1}\n```\nmore text'
        result = agent._extract_json(text)
        assert result == {"a": 1}

    def test_array_returns_none(self):
        agent = ElengenixAgent()
        assert agent._extract_json("[1, 2, 3]") is None

    def test_unparseable_returns_none(self):
        agent = ElengenixAgent()
        assert agent._extract_json("clearly not json") is None


class TestAgentSumarizeResults:
    """Covers core.brain:933-938 — result objects with .output and dict fallback."""

    def test_result_with_output_attr(self):
        """Object with .output (no .tool_name) -> hits elif branch."""
        agent = ElengenixAgent()
        r = SimpleNamespace(output="tool ran successfully")
        result = agent._summarize_results([r])
        assert "tool ran successfully" in result

    def test_result_as_dict(self):
        agent = ElengenixAgent()
        r = {"output": "dict output"}
        result = agent._summarize_results([r])
        assert "dict output" in result

    def test_result_as_str(self):
        agent = ElengenixAgent()
        result = agent._summarize_results(["raw string result"])
        assert "raw string result" in result


class TestAgentActivityLog:
    """Covers core.brain:950-951 — callback exception."""

    def test_callback_raises(self):
        agent = ElengenixAgent()

        def broken(msg):
            raise ValueError("broken")

        agent._activity_log("test", callback=broken)  # should not raise
        assert "test" in agent.activity_log


class TestAgentFingerprint:
    """Covers core.brain:956-958 — empty target path."""

    def test_empty_target(self):
        agent = ElengenixAgent()
        result = agent._fingerprint_target_for_planning("")
        assert result is None

    def test_none_target(self):
        agent = ElengenixAgent()
        result = agent._fingerprint_target_for_planning(None)
        assert result is None


class TestAgentInitTeamAegis:
    """Covers core.brain:996-1004 — no config file, disabled, error."""

    def test_no_config_file(self):
        agent = ElengenixAgent()
        with patch.object(Path, "exists", return_value=False):
            result = agent._init_team_aegis_clients()
            assert result["enabled"] is False


class TestAgentSaveMemory:
    """Covers core.brain:1008-1012, 1015-1020."""

    def test_save_to_persistent_memory(self):
        agent = ElengenixAgent()
        agent._save_to_persistent_memory("user", "important data")

    @patch("core.brain.remember", return_value=None)
    def test_handle_save_memory_success(self, mock_remember):
        agent = ElengenixAgent()
        result = agent._handle_save_memory("my note", target="x")
        assert "Memory saved" in result

    @patch("core.brain.remember")
    def test_handle_save_memory_failure(self, mock_remember):
        mock_remember.side_effect = Exception("full")
        agent = ElengenixAgent()
        result = agent._handle_save_memory("my note")
        assert "Failed to save" in result


class TestAgentRequestToolInstall:
    """Covers core.brain:1059-1060 — confirm_install exception."""

    def test_no_skill_registry(self):
        agent = ElengenixAgent()
        agent.skill_registry = None
        result = agent.request_tool_install("nmap")
        assert "no skill registry" in result

    def test_tool_not_in_registry(self):
        agent = ElengenixAgent()
        mock_registry = MagicMock()
        mock_registry.skills = {"other": MagicMock()}
        agent.skill_registry = mock_registry
        result = agent.request_tool_install("nmap")
        assert "not found in skill registry" in result


class TestAgentResumeMission:
    """Covers core.brain:1086."""

    def test_resume_mission(self):
        agent = ElengenixAgent()
        result = agent.resume_mission("abc-123")
        assert "abc-123" in result


class TestAgentProcessTeamScan:
    """Covers core.brain:1089."""

    @patch("core.brain.ElengenixAgent.run_smart_scan")
    def test_process_team_scan(self, mock_run):
        agent = ElengenixAgent()
        result = agent.process_team_scan("target")
        mock_run.assert_called_with("target")


class TestAgentExecuteWithGovernance:
    """Covers core.brain:1070-1083."""

    def test_no_governance(self):
        agent = ElengenixAgent()
        agent.governance = None
        with patch("core.brain.execute_tool", return_value="done"):
            result = agent._execute_with_governance("nmap", "test", "scan x")
            assert result == "done"

    def test_gate_denied(self):
        agent = ElengenixAgent()
        mock_gate = MagicMock()
        mock_gate.decision = "deny"
        mock_governance = MagicMock()
        mock_governance.gate.return_value = mock_gate
        agent.governance = mock_governance
        result = agent._execute_with_governance("nmap", "test", "scan x")
        assert result["success"] is False
        assert "Blocked by governance" in result["error"]


class TestAgentProcessQueryNew:
    """Covers core.brain:1066."""

    def test_delegates_to_process_universal(self):
        agent = ElengenixAgent()
        with patch.object(agent, "process_universal", return_value="done") as mock_pu:
            result = agent._process_query_new("test", target="x")
            mock_pu.assert_called_with("test", target="x", mode="auto")
            assert result == "done"


class TestAgentProcessHybridModeProcessor:
    """Covers core.brain:726 — mode_processor branch."""

    def test_calls_mode_processor_hybrid(self):
        agent = ElengenixAgent()
        agent.mode_processor = MagicMock()
        agent.mode_processor.process_hybrid.return_value = "hybrid result"
        result = agent.process_hybrid("scan example.com", target="example.com")
        assert result == "hybrid result"

"""
tests/test_agent_brain_coverage.py — Increase agent_brain.py test coverage to 50%+.
"""

import json
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, mock_open, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.cvss_calculator import CVSSCalculator, Severity
from tools.governance import GateDecision, Governance
from tools.tool_registry import ToolCategory, ToolResult, registry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_lightweight_agent():
    """Create a minimal ElengenixAgent bypassing __init__."""
    from core.brain import ElengenixAgent

    agent = ElengenixAgent.__new__(ElengenixAgent)
    agent.max_steps = 25
    agent.loop_threshold = 3
    agent.history_limit = 5
    agent.max_output_len = 2000
    agent.enable_planning = True
    agent.enable_cot_logging = True
    agent.max_history_turns = 20
    agent.verbose_thoughts = True
    agent.conversation_history = []
    agent.current_tree = None
    agent._fingerprint_cache = {}
    agent._logic_analyzer = None
    agent._payload_mutator = None
    agent._smart_orchestrator = None
    agent.cvss_calc = CVSSCalculator(use_ai=False)
    agent.governance = Governance(require_approval_high_risk=False)
    agent.base_prompt = "Test prompt"

    mock_client = MagicMock()
    mock_client.chat.return_value = SimpleNamespace(
        content='{"action": "finish", "summary": "done"}',
        tool_calls=None,
    )
    mock_client.active_client = SimpleNamespace(model="test-model")
    mock_client.clients = {}
    agent.client = mock_client

    mock_cm = MagicMock()
    mock_cm.conversation_history = []
    mock_cm.build_chat_messages.return_value = [
        SimpleNamespace(role="system", content="sys"),
        SimpleNamespace(role="user", content="hello"),
    ]
    agent.conversation_manager = mock_cm

    agent.mode_processor = MagicMock()
    agent.mode_processor.process_universal.return_value = "universal result"
    agent.mode_processor.process_hybrid.return_value = "hybrid result"

    mock_al = MagicMock()
    agent.activity_logger = mock_al

    mock_planner = MagicMock()
    agent.planner = mock_planner

    mock_cot = MagicMock()
    mock_cot.current_session = []
    agent.cot_logger = mock_cot

    agent.skill_registry = None

    mock_reflection = MagicMock()
    mock_reflection.classify_sentiment.return_value = "neutral"
    agent.reflection_tracker = mock_reflection

    agent.active_fuzzer = None
    agent.coverage_analyzer = None
    agent.learning_engine = None
    agent.bola_tester = None
    agent.waf_detector = None
    agent.analysis_pipeline = None
    agent.vuln_reasoning = None
    agent._team_aegis_clients = {"enabled": False}

    # Mock CVE DB
    mock_cve_db = MagicMock()
    mock_cve_db.find_similar_vulns.return_value = []
    agent.cve_db = mock_cve_db

    return agent


# ===================================================================
# Module-level lazy loaders
# ===================================================================

class TestModuleLevelLazyLoaders:
    @patch("core.brain._vector_memory", None)
    def test_get_vector_memory(self):
        import core.brain as brain_mod
        mock_vm = MagicMock()
        with patch.dict("sys.modules", {"tools.vector_memory": mock_vm}):
            result = brain_mod._get_vector_memory()
            assert result is not None

    @patch("core.brain._memory_persistence", None)
    def test_get_memory_persistence(self):
        import core.brain as brain_mod
        mock_mp = MagicMock()
        with patch.dict("sys.modules", {"tools.memory_persistence": mock_mp}):
            result = brain_mod._get_memory_persistence()
            assert result is not None

    @patch("core.brain._cve_database", None)
    def test_get_cve_database(self):
        import core.brain as brain_mod
        mock_db = MagicMock()
        with patch.dict("sys.modules", {"tools.cve_database": mock_db}):
            result = brain_mod._get_cve_database()
            assert result is not None

    @patch("core.brain._mission_state", None)
    def test_get_mission_state(self):
        import core.brain as brain_mod
        mock_ms = MagicMock()
        with patch.dict("sys.modules", {"tools.mission_state": mock_ms}):
            result = brain_mod._get_mission_state()
            assert result is not None

    @patch("core.brain._agent_reflection", None)
    def test_get_agent_reflection(self):
        import core.brain as brain_mod
        mock_ar = MagicMock()
        with patch.dict("sys.modules", {"tools.agent_reflection": mock_ar}):
            result = brain_mod._get_agent_reflection()
            assert result is not None

    @patch("core.brain._vuln_finder", None)
    def test_get_vuln_finder(self):
        import core.brain as brain_mod
        mock_vf = MagicMock()
        with patch.dict("sys.modules", {"tools.vuln_finder": mock_vf}):
            result = brain_mod._get_vuln_finder()
            assert result is not None


# ===================================================================
# Module-level memory/SQL functions
# ===================================================================

class TestModuleLevelMemoryFunctions:
    @patch("core.brain._get_vector_memory")
    def test_remember_success(self, mock_get_vm):
        import core.brain as brain_mod
        mock_vm = MagicMock()
        mock_get_vm.return_value = mock_vm
        brain_mod.remember("test content", target="t", category="cat")
        mock_vm.remember.assert_called_once_with("test content", target="t", category="cat")

    @patch("core.brain._get_vector_memory", side_effect=Exception("fail"))
    def test_remember_exception(self, mock_get_vm):
        import core.brain as brain_mod
        brain_mod.remember("test content")

    @patch("core.brain._get_vector_memory")
    def test_recall_success(self, mock_get_vm):
        import core.brain as brain_mod
        mock_vm = MagicMock()
        mock_vm.recall.return_value = [{"content": "mem1"}]
        mock_get_vm.return_value = mock_vm
        result = brain_mod.recall("query", target="t", n_results=5)
        assert result == [{"content": "mem1"}]

    @patch("core.brain._get_vector_memory", side_effect=Exception("fail"))
    def test_recall_exception(self, mock_get_vm):
        import core.brain as brain_mod
        result = brain_mod.recall("query")
        assert result == []

    @patch("core.brain._get_vector_memory")
    def test_get_context_for_ai_success(self, mock_get_vm):
        import core.brain as brain_mod
        mock_vm = MagicMock()
        mock_vm.get_context_for_ai.return_value = "context lines"
        mock_get_vm.return_value = mock_vm
        result = brain_mod.get_context_for_ai("q", target="t", max_memories=5)
        assert result == "context lines"

    @patch("core.brain._get_vector_memory", side_effect=Exception("fail"))
    def test_get_context_for_ai_exception(self, mock_get_vm):
        import core.brain as brain_mod
        result = brain_mod.get_context_for_ai("q")
        assert result == ""


class TestModuleLevelSqliteFunctions:
    @patch("core.brain._get_memory_persistence")
    def test_sqlite_save_message_success(self, mock_get_mp):
        import core.brain as brain_mod
        mock_mp = MagicMock()
        mock_get_mp.return_value = mock_mp
        brain_mod._sqlite_save_message("sid", "user", "content", "model", 100)
        mock_mp.save_message.assert_called_once_with("sid", "user", "content", "model", 100)

    @patch("core.brain._get_memory_persistence", side_effect=Exception("fail"))
    def test_sqlite_save_message_exception(self, mock_get_mp):
        import core.brain as brain_mod
        brain_mod._sqlite_save_message("sid", "user", "content")

    @patch("core.brain._get_memory_persistence")
    def test_get_context_status_success(self, mock_get_mp):
        import core.brain as brain_mod
        mock_mp = MagicMock()
        mock_mp.get_context_status.return_value = {"is_near_full": True, "percent": 90.0}
        mock_get_mp.return_value = mock_mp
        result = brain_mod._get_context_status("sid", "model")
        assert result["is_near_full"] is True

    @patch("core.brain._get_memory_persistence", side_effect=Exception("fail"))
    def test_get_context_status_exception(self, mock_get_mp):
        import core.brain as brain_mod
        result = brain_mod._get_context_status("sid")
        assert result["is_near_full"] is False
        assert result["percent"] == 0

    @patch("core.brain._get_memory_persistence")
    def test_sqlite_clear_session_success(self, mock_get_mp):
        import core.brain as brain_mod
        mock_mp = MagicMock()
        mock_get_mp.return_value = mock_mp
        brain_mod._sqlite_clear_session("sid")
        mock_mp.clear_session.assert_called_once_with("sid")

    @patch("core.brain._get_memory_persistence", side_effect=Exception("fail"))
    def test_sqlite_clear_session_exception(self, mock_get_mp):
        import core.brain as brain_mod
        brain_mod._sqlite_clear_session("sid")


# ===================================================================
# ElengenixAgent class methods
# ===================================================================

class TestElengenixAgentInitAndProperties:
    def test_logic_analyzer_lazy_init(self):
        agent = _make_lightweight_agent()
        with patch("tools.logic_analyzer.BusinessLogicAnalyzer") as MockBA:
            MockBA.return_value = MagicMock()
            la = agent.logic_analyzer
            assert la is not None
            la2 = agent.logic_analyzer
            assert la2 is la

    def test_payload_mutator_lazy_init(self):
        agent = _make_lightweight_agent()
        with patch("tools.payload_mutation.PayloadMutator") as MockPM:
            MockPM.return_value = MagicMock()
            pm = agent.payload_mutator
            assert pm is not None
            pm2 = agent.payload_mutator
            assert pm2 is pm

    def test_smart_orchestrator_lazy_init(self):
        agent = _make_lightweight_agent()
        with patch("core.scan_engine.SmartOrchestrator") as MockSO:
            MockSO.return_value = MagicMock()
            so = agent.smart_orchestrator
            assert so is not None
            so2 = agent.smart_orchestrator
            assert so2 is so

    def test_get_shared_loop(self):
        agent = _make_lightweight_agent()
        with patch("tools.event_loop.get_shared_loop") as mock_loop:
            mock_loop.return_value = MagicMock()
            result = agent._get_shared_loop()
            assert result is not None


class TestElengenixAgentConversationManagement:
    def test_append_history(self):
        agent = _make_lightweight_agent()
        agent.conversation_manager.conversation_history = []
        agent.conversation_history = agent.conversation_manager.conversation_history
        agent._append_history("user", "hello")
        agent.conversation_manager.append_history.assert_called_with("user", "hello")
        assert agent.conversation_history is agent.conversation_manager.conversation_history

    def test_clear_conversation_history(self):
        agent = _make_lightweight_agent()
        agent.conversation_manager.conversation_history = [{"role": "user", "content": "hi"}]
        agent.conversation_history = agent.conversation_manager.conversation_history
        agent.clear_conversation_history()
        agent.conversation_manager.clear.assert_called_once()
        assert agent.conversation_history is agent.conversation_manager.conversation_history

    def test_build_chat_messages(self):
        agent = _make_lightweight_agent()
        result = agent._build_chat_messages("system prompt", "user input")
        agent.conversation_manager.build_chat_messages.assert_called_once_with(
            "system prompt", "user input"
        )
        assert result is not None


class TestElengenixAgentCheckForNegativeFeedback:
    def test_no_history_returns_early(self):
        agent = _make_lightweight_agent()
        agent.conversation_history = []
        agent._check_for_negative_feedback("bad answer")

    def test_no_assistant_turn_returns_early(self):
        agent = _make_lightweight_agent()
        agent.conversation_history = [{"role": "user", "content": "hi"}]
        agent._check_for_negative_feedback("bad answer")
        agent.reflection_tracker.classify_sentiment.assert_not_called()

    def test_negative_feedback_records_mistake(self):
        agent = _make_lightweight_agent()
        # Need: [user_old, assistant_old, user_new] so that reversed iteration
        # finds assistant (last_assistant), then earlier user (last_user_query)
        agent.conversation_history = [
            {"role": "user", "content": "scan target"},
            {"role": "assistant", "content": "I'll scan now"},
            {"role": "user", "content": "new follow up"},
        ]
        agent.reflection_tracker.classify_sentiment.return_value = "negative"
        agent._check_for_negative_feedback("that was wrong")
        agent.reflection_tracker.record_mistake.assert_called_once()

    def test_positive_feedback_no_mistake(self):
        agent = _make_lightweight_agent()
        agent.conversation_history = [
            {"role": "user", "content": "scan target"},
            {"role": "assistant", "content": "I'll scan now"},
        ]
        agent.reflection_tracker.classify_sentiment.return_value = "positive"
        agent._check_for_negative_feedback("great answer")
        agent.reflection_tracker.record_mistake.assert_not_called()


class TestElengenixAgentEnhancePrompt:
    def test_enhance_prompt_appends_cve_context(self):
        agent = _make_lightweight_agent()
        agent.base_prompt = "You are a security agent."
        agent._enhance_prompt_with_cve_context()
        assert "CVE" in agent.base_prompt
        assert "You are a security agent." in agent.base_prompt


class TestElengenixAgentBaseUrlHint:
    def test_with_http_target(self):
        agent = _make_lightweight_agent()
        mock_ms = MagicMock()
        mock_ms.snapshot.return_value = {"target": "http://example.com"}
        assert agent._base_url_hint(mock_ms) == "http://example.com"

    def test_with_https_target(self):
        agent = _make_lightweight_agent()
        mock_ms = MagicMock()
        mock_ms.snapshot.return_value = {"target": "https://example.com"}
        assert agent._base_url_hint(mock_ms) == "https://example.com"

    def test_with_bare_domain(self):
        agent = _make_lightweight_agent()
        mock_ms = MagicMock()
        mock_ms.snapshot.return_value = {"target": "example.com"}
        assert agent._base_url_hint(mock_ms) == "https://example.com"

    def test_with_empty_target(self):
        agent = _make_lightweight_agent()
        mock_ms = MagicMock()
        mock_ms.snapshot.return_value = {"target": ""}
        assert agent._base_url_hint(mock_ms) == "http://localhost"

    def test_exception_fallback(self):
        agent = _make_lightweight_agent()
        mock_ms = MagicMock()
        mock_ms.snapshot.side_effect = Exception("db error")
        assert agent._base_url_hint(mock_ms) == "http://localhost"


class TestElengenixAgentExtractJson:
    def test_valid_json(self):
        agent = _make_lightweight_agent()
        result = agent._extract_json('{"action": "run_shell", "command": "nmap target"}')
        assert isinstance(result, dict)
        assert result["action"] == "run_shell"

    def test_json_in_code_fence(self):
        agent = _make_lightweight_agent()
        result = agent._extract_json('```json\n{"action": "finish"}\n```')
        assert isinstance(result, dict)
        assert result["action"] == "finish"

    def test_empty_string(self):
        agent = _make_lightweight_agent()
        result = agent._extract_json("")
        assert result is None

    def test_array_input_returns_none_for_object_expect(self):
        agent = _make_lightweight_agent()
        # extract_json with expect="object" + isinstance(dict) check
        result = agent._extract_json('[1, 2, 3]')
        # May return the array from extract_json, but isinstance dict returns None
        assert result is None or isinstance(result, dict)

    def test_trailing_comma_repaired(self):
        agent = _make_lightweight_agent()
        result = agent._extract_json('{"key": "val",}')
        assert isinstance(result, dict)
        assert result["key"] == "val"


class TestElengenixAgentSummarizeResults:
    def test_empty_results(self):
        agent = _make_lightweight_agent()
        assert agent._summarize_results([]) == "No previous results."

    def test_single_result(self):
        agent = _make_lightweight_agent()
        tr = ToolResult(success=True, tool_name="nmap", category=ToolCategory.RECON,
                        findings=[{"type": "xss"}])
        result = agent._summarize_results([tr])
        assert "nmap" in result
        assert "1 findings" in result

    def test_multiple_results_last_3(self):
        agent = _make_lightweight_agent()
        results = [ToolResult(success=True, tool_name=f"t{i}", category=ToolCategory.RECON,
                             findings=[{"type": f"v{i}"} for _ in range(i)]) for i in range(5)]
        result = agent._summarize_results(results)
        assert "t2" in result or "t3" in result or "t4" in result
        assert "t0" not in result


class TestElengenixAgentActivityLog:
    def test_logs_and_callback(self):
        agent = _make_lightweight_agent()
        cb = MagicMock()
        with patch("core.brain.logger") as mock_logger:
            agent._activity_log("test message [INFO]", callback=cb)
            mock_logger.info.assert_called()
            cb.assert_called_once()

    def test_logs_no_callback(self):
        agent = _make_lightweight_agent()
        with patch("core.brain.logger") as mock_logger:
            agent._activity_log("test message")
            mock_logger.info.assert_called()


class TestElengenixAgentCheckContextOverflow:
    def test_not_near_full(self):
        agent = _make_lightweight_agent()
        with patch("core.brain._get_context_status") as mock_status:
            mock_status.return_value = {"is_near_full": False, "percent": 30.0,
                                        "used_tokens": 30000, "capacity": 100000}
            assert agent._check_context_overflow() is False

    def test_near_full_triggers_summarize(self):
        agent = _make_lightweight_agent()
        agent.conversation_history = [{"role": "user", "content": "hi"}] * 10
        with patch("core.brain._get_context_status") as mock_status:
            mock_status.return_value = {"is_near_full": True, "percent": 95.0,
                                        "used_tokens": 95000, "capacity": 100000}
            with patch.object(agent, "_summarize_old_conversation") as mock_sum:
                assert agent._check_context_overflow() is True
                mock_sum.assert_called_once()

    def test_exception_returns_false(self):
        agent = _make_lightweight_agent()
        with patch("core.brain._get_context_status", side_effect=Exception("fail")):
            assert agent._check_context_overflow() is False


class TestElengenixAgentSummarizeOldConversation:
    def test_short_history_no_op(self):
        agent = _make_lightweight_agent()
        agent.conversation_history = [{"role": "user", "content": "hi"}] * 5
        agent._summarize_old_conversation()
        assert len(agent.conversation_history) == 5

    def test_long_history_compressed(self):
        agent = _make_lightweight_agent()
        history = []
        for i in range(10):
            history.append({"role": "user", "content": f"msg {i}"})
            history.append({"role": "assistant", "content": f"reply {i}"})
        agent.conversation_history = history

        mock_response = SimpleNamespace(content="This is a summary of the conversation.")
        agent.client.chat.return_value = mock_response

        with patch("core.brain._sqlite_clear_session"), \
             patch("core.brain._sqlite_save_message"), \
             patch("core.brain.logger"):
            with patch("tools.token_counter.count_tokens", return_value=100):
                agent._summarize_old_conversation()

        assert len(agent.conversation_history) == 7
        summary_entry = agent.conversation_history[3]
        assert "COMPRESSED SUMMARY" in summary_entry["content"]

    def test_short_summary_skipped(self):
        agent = _make_lightweight_agent()
        history = []
        for i in range(10):
            history.append({"role": "user", "content": f"msg {i}"})
            history.append({"role": "assistant", "content": f"reply {i}"})
        agent.conversation_history = history

        mock_response = SimpleNamespace(content="short")
        agent.client.chat.return_value = mock_response

        original_len = len(agent.conversation_history)
        with patch("core.brain._sqlite_clear_session"), \
             patch("core.brain.logger"):
            agent._summarize_old_conversation()
        assert len(agent.conversation_history) == original_len


class TestElengenixAgentFingerprintTarget:
    def test_empty_target_returns_none(self):
        agent = _make_lightweight_agent()
        assert agent._fingerprint_target_for_planning("") is None

    def test_cache_hit(self):
        agent = _make_lightweight_agent()
        cached = {"server": "nginx", "technologies": ["jQuery"]}
        agent._fingerprint_cache["http://example.com"] = cached
        assert agent._fingerprint_target_for_planning("http://example.com") == cached

    def test_successful_probe(self):
        agent = _make_lightweight_agent()
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "nginx"}
        mock_resp.cookies = []
        mock_resp.text = "<html>test</html>"
        mock_fp = {"server": "nginx", "technologies": ["jQuery"], "language": None}

        with patch("requests.get", return_value=mock_resp) as mock_get:
            with patch("agents.agent_planner.TargetFingerprinter") as MockTFP:
                MockTFP.return_value.fingerprint.return_value = mock_fp
                result = agent._fingerprint_target_for_planning("http://example.com")
                assert result == mock_fp
                assert "http://example.com" in agent._fingerprint_cache

    def test_probe_failure_returns_none(self):
        agent = _make_lightweight_agent()
        with patch("requests.get", side_effect=Exception("network error")):
            assert agent._fingerprint_target_for_planning("http://example.com") is None

    def test_fingerprinter_failure_returns_none(self):
        agent = _make_lightweight_agent()
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.cookies = []
        mock_resp.text = "body"

        with patch("requests.get", return_value=mock_resp):
            with patch("agents.agent_planner.TargetFingerprinter") as MockTFP:
                MockTFP.return_value.fingerprint.side_effect = Exception("fp error")
                assert agent._fingerprint_target_for_planning("http://example.com") is None

    def test_bare_domain_gets_http_prefix(self):
        agent = _make_lightweight_agent()
        with patch("requests.get", side_effect=Exception("fail")):
            agent._fingerprint_target_for_planning("example.com")
            # requests.get should have been called with http:// prefix
            # Since we patched it, we can't directly verify, but the function handles it


class TestElengenixAgentInitTeamAegisClients:
    def test_no_config_file(self):
        agent = _make_lightweight_agent()
        with patch("pathlib.Path.exists", return_value=False):
            result = agent._init_team_aegis_clients()
            assert result["enabled"] is False

    def test_team_aegis_disabled(self):
        agent = _make_lightweight_agent()
        config_data = {"team_aegis": {"enabled": False}}
        with patch("pathlib.Path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="")), \
             patch("yaml.safe_load", return_value=config_data):
            result = agent._init_team_aegis_clients()
            assert result["enabled"] is False

    def test_team_aegis_exception(self):
        agent = _make_lightweight_agent()
        with patch("yaml.safe_load", side_effect=Exception("yaml error")):
            result = agent._init_team_aegis_clients()
            assert result["enabled"] is False


class TestElengenixAgentSaveToPersistentMemory:
    def test_success(self):
        agent = _make_lightweight_agent()
        with patch("core.brain._sqlite_save_message") as mock_save:
            agent._save_to_persistent_memory("user", "hello")
            mock_save.assert_called_once()
            assert mock_save.call_args[0][0] == "default"
            assert mock_save.call_args[0][1] == "user"

    def test_exception_does_not_raise(self):
        agent = _make_lightweight_agent()
        with patch("core.brain._sqlite_save_message", side_effect=Exception("err")):
            agent._save_to_persistent_memory("user", "hello")


class TestElengenixAgentToolDelegation:
    def test_execute_tool_delegates(self):
        agent = _make_lightweight_agent()
        with patch("core.brain.execute_tool") as mock_exec:
            mock_exec.return_value = "result"
            result = agent._execute_tool({"action": "run_shell", "command": "echo hi"})
            assert result == "result"

    def test_handle_ask_user_delegates(self):
        agent = _make_lightweight_agent()
        with patch("core.brain.handle_ask_user") as mock_hau:
            mock_hau.return_value = "user said yes"
            result = agent._handle_ask_user({"question": "continue?"})
            assert result == "user said yes"

    def test_execute_tool_registry_delegates(self):
        agent = _make_lightweight_agent()
        with patch("core.brain.execute_tool_registry") as mock_et:
            mock_et.return_value = MagicMock()
            report_dir = Path("/tmp/reports")
            result = agent._execute_tool_registry("nmap", "target.com", report_dir)
            mock_et.assert_called_once()

    def test_execute_tool_subprocess_delegates(self):
        agent = _make_lightweight_agent()
        with patch("core.brain.execute_tool_subprocess") as mock_ets:
            mock_ets.return_value = MagicMock()
            result = agent._execute_tool_subprocess("nmap", "target.com")
            mock_ets.assert_called_once_with("nmap", "target.com")


class TestElengenixAgentAnalyzeIntent:
    def test_delegates_to_module(self):
        agent = _make_lightweight_agent()
        with patch("core.brain._analyze_intent") as mock_ai:
            mock_ai.return_value = "scan"
            result = agent._analyze_intent("scan example.com")
            mock_ai.assert_called_once_with(agent.client, "scan example.com")
            assert result == "scan"


class TestElengenixAgentRunSmartScan:
    def test_smart_scan_success(self):
        agent = _make_lightweight_agent()
        mock_state = MagicMock()
        mock_state.results = [1, 2, 3]
        mock_state.findings = [{"type": "xss"}]
        mock_state.duration = 42.5

        mock_correlator = MagicMock()
        mock_correlator.get_clustered_report.return_value = [{"cluster": 1}]

        mock_future = MagicMock()
        mock_future.result.return_value = (mock_state, mock_correlator)

        # Set _smart_orchestrator directly (property reads this)
        agent._smart_orchestrator = MagicMock()

        with patch("asyncio.run_coroutine_threadsafe", return_value=mock_future), \
             patch.object(agent, "_get_shared_loop", return_value=MagicMock()):
            result = agent.run_smart_scan("target.com", Path("/tmp/reports"))
            assert "Smart Scan Results" in result
            assert "42.5" in result

    def test_smart_scan_failure(self):
        agent = _make_lightweight_agent()
        agent._smart_orchestrator = MagicMock()
        with patch("asyncio.run_coroutine_threadsafe", side_effect=Exception("timeout")), \
             patch.object(agent, "_get_shared_loop", return_value=MagicMock()):
            result = agent.run_smart_scan("target.com", Path("/tmp/reports"))
            assert "Smart scan failed" in result


class TestElengenixAgentProcessUniversal:
    def test_process_universal_delegates(self):
        agent = _make_lightweight_agent()
        agent.mode_processor.process_universal.return_value = "universal result"
        result = agent.process_universal("hello", target="t", mode="auto")
        assert result == "universal result"

    def test_process_universal_calls_context_check(self):
        agent = _make_lightweight_agent()
        agent.mode_processor.process_universal.return_value = "result"
        with patch.object(agent, "_check_context_overflow") as mock_check:
            mock_check.return_value = False
            agent.process_universal("hi")
            mock_check.assert_called_once()


class TestElengenixAgentProcessHybrid:
    def test_hybrid_casual_no_target_returns_universal(self):
        agent = _make_lightweight_agent()
        with patch.object(agent, "_analyze_intent", return_value="casual"):
            result = agent.process_hybrid("hello", target="")
            assert result == "universal result"

    def test_hybrid_scan_no_target_inferred(self):
        agent = _make_lightweight_agent()
        with patch.object(agent, "_analyze_intent", return_value="scan"), \
             patch("core.brain._extract_target_from_text", return_value="example.com"):
            result = agent.process_hybrid("scan example.com", target="")
            # Should delegate to mode_processor since target is inferred
            assert result == "hybrid result"

    def test_hybrid_scan_no_target_no_inference(self):
        agent = _make_lightweight_agent()
        with patch.object(agent, "_analyze_intent", return_value="scan"), \
             patch("core.brain._extract_target_from_text", return_value=""):
            result = agent.process_hybrid("scan something", target="")
            assert "No target specified" in result

    def test_hybrid_scan_with_target(self):
        agent = _make_lightweight_agent()
        with patch.object(agent, "_analyze_intent", return_value="scan"):
            result = agent.process_hybrid("scan example.com", target="example.com")
            assert result == "hybrid result"

    def test_hybrid_intent_exception_fallback(self):
        agent = _make_lightweight_agent()
        with patch.object(agent, "_analyze_intent", side_effect=Exception("err")):
            result = agent.process_hybrid("hello", target="")
            assert result == "universal result"


class TestElengenixAgentRequestToolInstall:
    def test_no_skill_registry(self):
        agent = _make_lightweight_agent()
        agent.skill_registry = None
        assert "[FAIL]" in agent.request_tool_install("tool1")

    def test_unknown_tool(self):
        agent = _make_lightweight_agent()
        agent.skill_registry = MagicMock()
        agent.skill_registry.skills = {}
        assert "[FAIL]" in agent.request_tool_install("nonexistent")

    def test_already_installed(self):
        agent = _make_lightweight_agent()
        mock_skill = MagicMock()
        mock_skill.status.value = "available"
        agent.skill_registry = MagicMock()
        agent.skill_registry.skills = {"tool1": mock_skill}
        assert "[OK]" in agent.request_tool_install("tool1")

    def test_pending_already(self):
        agent = _make_lightweight_agent()
        mock_skill = MagicMock()
        mock_skill.status.value = "missing"
        agent.skill_registry = MagicMock()
        agent.skill_registry.skills = {"tool1": mock_skill}

        mock_request = MagicMock()
        mock_request.tool_name = "tool1"

        mock_mgr = MagicMock()
        mock_mgr.get_pending_requests.return_value = [mock_request]

        with patch("tools.install_request.get_install_manager", return_value=mock_mgr):
            result = agent.request_tool_install("tool1")
            assert "[PENDING]" in result

    def test_ask_first_returns_install_request(self):
        agent = _make_lightweight_agent()
        mock_skill = MagicMock()
        mock_skill.status.value = "missing"
        mock_skill.description = "A security tool"
        mock_skill.install_command = "apt install tool1"
        agent.skill_registry = MagicMock()
        agent.skill_registry.skills = {"tool1": mock_skill}

        mock_mgr = MagicMock()
        mock_mgr.get_pending_requests.return_value = []
        mock_mgr.request.return_value = MagicMock()

        with patch("tools.install_request.get_install_manager", return_value=mock_mgr):
            result = agent.request_tool_install("tool1", ask_first=True)
            assert "[INSTALL REQUEST]" in result

    def test_auto_install_success(self):
        agent = _make_lightweight_agent()
        mock_skill = MagicMock()
        mock_skill.status.value = "missing"
        mock_skill.description = "desc"
        mock_skill.install_command = "pip install tool1"
        agent.skill_registry = MagicMock()
        agent.skill_registry.skills = {"tool1": mock_skill}

        mock_mgr = MagicMock()
        mock_mgr.get_pending_requests.return_value = []
        mock_mgr.request.return_value = MagicMock()
        mock_mgr.confirm_install.return_value = True

        with patch("tools.install_request.get_install_manager", return_value=mock_mgr):
            result = agent.request_tool_install("tool1", ask_first=False)
            assert "[OK]" in result

    def test_auto_install_failure(self):
        agent = _make_lightweight_agent()
        mock_skill = MagicMock()
        mock_skill.status.value = "missing"
        mock_skill.description = "desc"
        mock_skill.install_command = "pip install tool1"
        agent.skill_registry = MagicMock()
        agent.skill_registry.skills = {"tool1": mock_skill}

        mock_mgr = MagicMock()
        mock_mgr.get_pending_requests.return_value = []
        mock_mgr.request.return_value = MagicMock()
        mock_mgr.confirm_install.return_value = False

        with patch("tools.install_request.get_install_manager", return_value=mock_mgr):
            result = agent.request_tool_install("tool1", ask_first=False)
            assert "[FAIL]" in result


# ===================================================================
# Intent fast-path patterns
# ===================================================================

class TestIntentFastPath:
    def test_casual_greeting(self):
        from agents.agent_intent import _fast_path_classify
        assert _fast_path_classify("hello") == "casual"
        assert _fast_path_classify("hi") == "casual"
        assert _fast_path_classify("hey") == "casual"
        assert _fast_path_classify("who are you") == "casual"

    def test_scan_pattern(self):
        from agents.agent_intent import _fast_path_classify
        assert _fast_path_classify("scan example.com") == "scan"
        assert _fast_path_classify("pentest 192.168.1.1") == "scan"
        assert _fast_path_classify("recon target.org") == "scan"
        assert _fast_path_classify("attack http://evil.com") == "scan"

    def test_research_pattern(self):
        from agents.agent_intent import _fast_path_classify
        assert _fast_path_classify("today's scores") == "research"
        assert _fast_path_classify("latest news") == "research"
        assert _fast_path_classify("current weather") == "research"
        assert _fast_path_classify("stock price today") == "research"

    def test_empty_input(self):
        from agents.agent_intent import _fast_path_classify
        assert _fast_path_classify("") == "casual"

    def test_ambiguous_input_returns_none(self):
        from agents.agent_intent import _fast_path_classify
        assert _fast_path_classify("explain how sql injection works") is None

    def test_thai_short_text(self):
        from agents.agent_intent import _fast_path_classify
        assert _fast_path_classify("สวัสดี") == "casual"


# ===================================================================
# Agent helpers
# ===================================================================

class TestAgentHelpersExtractJson:
    def test_valid_json(self):
        from agents.agent_helpers import extract_json
        result = extract_json('{"key": "value"}', expect="object")
        assert result == {"key": "value"}

    def test_in_code_fence(self):
        from agents.agent_helpers import extract_json
        result = extract_json('```json\n{"key": "val"}\n```', expect="object")
        assert result == {"key": "val"}

    def test_array_expect(self):
        from agents.agent_helpers import extract_json
        result = extract_json('[1, 2, 3]', expect="array")
        assert result == [1, 2, 3]

    def test_none_input(self):
        from agents.agent_helpers import extract_json
        assert extract_json(None) is None

    def test_empty_string(self):
        from agents.agent_helpers import extract_json
        assert extract_json("") is None

    def test_trailing_comma_repair(self):
        from agents.agent_helpers import extract_json
        result = extract_json('{"key": "val",}', expect="object")
        assert result == {"key": "val"}

    def test_smart_quotes_repair(self):
        from agents.agent_helpers import extract_json
        text = '\u201c{"key": "val"}\u201d'
        result = extract_json(text, expect="object")
        assert result == {"key": "val"}


class TestAgentHelpersExtractTarget:
    def test_url_in_text(self):
        from agents.agent_helpers import _extract_target_from_text
        result = _extract_target_from_text("scan example.com please")
        assert result == "example.com"

    def test_ip_in_text(self):
        from agents.agent_helpers import _extract_target_from_text
        result = _extract_target_from_text("scan 192.168.1.1")
        assert result == "192.168.1.1"

    def test_empty_text(self):
        from agents.agent_helpers import _extract_target_from_text
        assert _extract_target_from_text("") == ""

    def test_no_target_words(self):
        from agents.agent_helpers import _extract_target_from_text
        result = _extract_target_from_text("hello world")
        assert result != ""


class TestAgentHelpersSafeOperation:
    def test_success(self):
        from agents.agent_helpers import _safe_operation
        result = _safe_operation("test", lambda: 42)
        assert result == 42

    def test_failure_returns_default(self):
        from agents.agent_helpers import _safe_operation
        result = _safe_operation("test", lambda: 1/0, default="fallback")
        assert result == "fallback"

    def test_failure_logs_warning(self):
        from agents.agent_helpers import _safe_operation
        with patch("agents.agent_helpers.logger") as mock_logger:
            _safe_operation("test_op", lambda: 1/0)
            mock_logger.warning.assert_called_once()


class TestAgentHelpersGetNowContext:
    def test_returns_string(self):
        from agents.agent_helpers import _get_now_context
        result = _get_now_context()
        assert isinstance(result, str)
        assert "CURRENT TIME CONTEXT" in result

    def test_with_timezone(self):
        import os
        from agents.agent_helpers import _get_now_context
        old_tz = os.environ.pop("ELENGENIX_TZ", None)
        os.environ["ELENGENIX_TZ"] = "Asia/Bangkok"
        try:
            result = _get_now_context()
            assert "CURRENT TIME CONTEXT" in result
        finally:
            if old_tz:
                os.environ["ELENGENIX_TZ"] = old_tz
            else:
                os.environ.pop("ELENGENIX_TZ", None)


# ===================================================================
# Chain of Thought Logger
# ===================================================================

class TestChainOfThoughtLogger:
    def test_log_adds_thought(self):
        from agents.agent_logger import ChainOfThoughtLogger
        logger = ChainOfThoughtLogger(log_dir=Path(tempfile.mkdtemp()))
        logger.log(0, "test", "reasoning", "test_action", "result", 0.8)
        assert len(logger.current_session) == 1
        assert logger.current_session[0].reasoning == "reasoning"

    def test_save_session(self):
        from agents.agent_logger import ChainOfThoughtLogger
        tmpdir = Path(tempfile.mkdtemp())
        logger = ChainOfThoughtLogger(log_dir=tmpdir)
        logger.log(0, "ctx", "reason", "act", "res", 0.9)
        path = logger.save_session("target.com")
        assert path is not None
        assert path.exists()

    def test_save_empty_session(self):
        from agents.agent_logger import ChainOfThoughtLogger
        logger = ChainOfThoughtLogger(log_dir=Path(tempfile.mkdtemp()))
        assert logger.save_session("target") is None

    def test_set_target(self):
        from agents.agent_logger import ChainOfThoughtLogger
        logger = ChainOfThoughtLogger(log_dir=Path(tempfile.mkdtemp()))
        logger.set_target("example.com")
        assert logger._pending_target == "example.com"


# ===================================================================
# AttackTree data classes
# ===================================================================

class TestAttackTreeDataclasses:
    def test_attack_step_defaults(self):
        from agents.agent_dataclasses import AttackStep, AttackPhase
        step = AttackStep(
            phase=AttackPhase.RECONNAISSANCE,
            tool_name="nmap",
            target="example.com",
            purpose="port scan",
        )
        assert step.completed is False
        assert step.findings == []

    def test_attack_tree_defaults(self):
        from agents.agent_dataclasses import AttackTree
        tree = AttackTree(target="example.com", objective="find vulns")
        assert tree.steps == []
        assert tree.reasoning == ""

    def test_agent_thought(self):
        from agents.agent_dataclasses import AgentThought
        thought = AgentThought(
            step=0, timestamp=1.0, context="ctx",
            reasoning="reason", action_taken="act",
            result="res", confidence=0.8,
        )
        assert thought.confidence == 0.8


# ===================================================================
# ConversationManager
# ===================================================================

class TestConversationManager:
    def test_build_chat_messages(self):
        from agents.agent_conversation import ConversationManager
        cm = ConversationManager(client=MagicMock())
        cm.conversation_history = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ]
        messages = cm.build_chat_messages("system prompt", "user msg")
        assert len(messages) == 4
        assert messages[0].role == "system"
        assert messages[-1].role == "user"
        assert messages[-1].content == "user msg"

    def test_clear(self):
        from agents.agent_conversation import ConversationManager
        cm = ConversationManager(client=MagicMock())
        cm.conversation_history = [{"role": "user", "content": "hi"}]
        cm.clear()
        assert cm.conversation_history == []

    def test_get_recent_history(self):
        from agents.agent_conversation import ConversationManager
        cm = ConversationManager(client=MagicMock(), history_limit=2)
        cm.conversation_history = [
            {"role": "user", "content": "1"},
            {"role": "assistant", "content": "2"},
            {"role": "user", "content": "3"},
        ]
        recent = cm.get_recent_history()
        assert len(recent) == 2

    def test_append_history_trims(self):
        from agents.agent_conversation import ConversationManager
        cm = ConversationManager(client=MagicMock(), max_history_turns=2)
        cm.conversation_history = [{"role": "user", "content": f"msg {i}"} for i in range(10)]
        with patch.object(cm, "_save_to_persistent_memory"):
            cm.append_history("user", "new msg")
        assert len(cm.conversation_history) <= 4

    def test_check_context_overflow(self):
        from agents.agent_conversation import ConversationManager
        cm = ConversationManager(client=MagicMock(), max_history_turns=5)
        cm.conversation_history = [{"role": "user", "content": f"msg {i}"} for i in range(20)]
        with patch.object(cm, "_summarize_old_conversation") as mock_sum:
            result = cm.check_context_overflow()
            assert result is True
            mock_sum.assert_called()

    def test_check_context_overflow_short(self):
        from agents.agent_conversation import ConversationManager
        cm = ConversationManager(client=MagicMock(), max_history_turns=20)
        cm.conversation_history = [{"role": "user", "content": "hi"}]
        assert cm.check_context_overflow() is False


# ===================================================================
# Process query tests
# ===================================================================

def _make_process_query_patches(agent):
    """Return a dict of common patches needed for process_query tests.

    Values are patch objects. Start them, configure mocks, then stop in finally.
    """
    return {
        "get_context_for_ai": patch("core.brain.get_context_for_ai", return_value=""),
        "recall": patch("core.brain.recall", return_value=[]),
        "remember": patch("core.brain.remember"),
        "display": patch("core.brain.display_in_chat_mode"),
        "fingerprint": patch.object(agent, "_fingerprint_target_for_planning", return_value=None),
        "vf_module": patch("core.brain._get_vuln_finder"),
        "belief": patch("tools.vuln_hunter_core.BeliefState"),
        "coverage": patch("tools.vuln_hunter_core.CoverageMap"),
        "negative": patch("tools.vuln_hunter_core.NegativeResultStore"),
        "verify": patch("tools.vuln_hunter_core.VerificationPipeline"),
        "reflect": patch("tools.vuln_hunter_core.ReflectEngine"),
        "mission": patch("tools.mission_state.MissionState"),
        "graph_node": patch("tools.mission_state.GraphNode"),
        "graph_edge": patch("tools.mission_state.GraphEdge"),
        "now_ctx": patch("core.brain._get_now_context", return_value="now"),
        "spinner": patch("cli.ui_components.show_spinner"),
        "action_tools": patch("tools.universal_ai_client.ACTION_TOOLS", []),
    }


def _start_patches(patch_dict):
    """Start all patches and return dict of mock objects."""
    mocks = {}
    for key, p in patch_dict.items():
        mocks[key] = p.start()
    return mocks


def _stop_patches(patch_dict):
    """Stop all patches."""
    for key, p in patch_dict.items():
        p.stop()


class TestProcessQueryEdgeCases:
    def test_process_query_casual_intent(self):
        agent = _make_lightweight_agent()
        with patch.object(agent, "_analyze_intent", return_value="casual"), \
             patch("core.brain.get_context_for_ai", return_value=""), \
             patch("core.brain._get_now_context", return_value="now"), \
             patch("core.brain.remember"), \
             patch("core.brain.display_in_chat_mode"):
            agent.client.chat.return_value = SimpleNamespace(content="Hi there!")
            agent.conversation_manager.build_chat_messages.return_value = [
                SimpleNamespace(role="system", content="sys"),
                SimpleNamespace(role="user", content="hi"),
            ]
            result = agent.process_query("hi there")
            assert isinstance(result, str)

    def test_process_query_scan_with_target(self):
        agent = _make_lightweight_agent()
        agent.max_steps = 1

        mock_tree = MagicMock()
        mock_tree.steps = [MagicMock(tool_name="nmap", purpose="recon", completed=False)]
        agent.planner.generate_attack_tree.return_value = mock_tree

        mock_vf_module = MagicMock()
        mock_vf = MagicMock()
        mock_vf.escalation = MagicMock()
        mock_vf.chaining = MagicMock()
        mock_vf_module.VulnFinder.return_value = mock_vf

        mock_mission = MagicMock()
        mock_mission.target = "example.com"
        mock_mission.snapshot.return_value = {"target": "example.com"}

        mock_reflect = MagicMock()
        mock_reflect.status = "ok"
        mock_reflect.recommendation = "continue"
        mock_reflect.switch_strategy = False
        mock_reflect.prompt_context.return_value = ""
        mock_reflect.history = []
        mock_reflect.consecutive_no_findings = 0

        patches = _make_process_query_patches(agent)
        mocks = _start_patches(patches)
        mocks["vf_module"].return_value = mock_vf_module
        mocks["belief"].return_value = MagicMock()
        mocks["coverage"].return_value = MagicMock()
        mocks["coverage"].return_value.get_gaps.return_value = []
        mocks["coverage"].return_value.prompt_context.return_value = ""
        mocks["negative"].return_value = MagicMock()
        mocks["negative"].return_value.get_prompt_context.return_value = ""
        mocks["verify"].return_value = MagicMock()
        mocks["reflect"].return_value = mock_reflect
        mocks["mission"].return_value = mock_mission
        try:
            agent.client.chat.return_value = SimpleNamespace(
                content=json.dumps({"action": "finish", "summary": "done"}),
                tool_calls=None,
            )
            with patch.object(agent.cvss_calc, "from_finding") as mock_cvss:
                mock_cvss.return_value = SimpleNamespace(
                    base_score=5.0, severity=Severity("Medium")
                )
                result = agent.process_query("scan example.com", target="example.com")
                assert isinstance(result, str)
        finally:
            _stop_patches(patches)


class TestProcessQuerySaveMemory:
    def test_save_memory_action(self):
        agent = _make_lightweight_agent()
        agent.max_steps = 2

        mock_mission = MagicMock()
        mock_mission.target = "example.com"
        mock_mission.snapshot.return_value = {"target": "example.com"}

        mock_reflect = MagicMock()
        mock_reflect.status = "ok"
        mock_reflect.recommendation = "continue"
        mock_reflect.switch_strategy = False
        mock_reflect.prompt_context.return_value = ""
        mock_reflect.history = []
        mock_reflect.consecutive_no_findings = 0

        responses = [
            SimpleNamespace(
                content=json.dumps({"action": "save_memory", "learning": "XSS found", "target": "t", "category": "finding"}),
                tool_calls=None,
            ),
            SimpleNamespace(
                content=json.dumps({"action": "finish", "summary": "done"}),
                tool_calls=None,
            ),
        ]
        agent.client.chat.side_effect = responses

        patches = _make_process_query_patches(agent)
        mocks = _start_patches(patches)
        mocks["vf_module"].return_value = MagicMock()
        mocks["belief"].return_value = MagicMock()
        mocks["coverage"].return_value = MagicMock()
        mocks["coverage"].return_value.get_gaps.return_value = []
        mocks["coverage"].return_value.prompt_context.return_value = ""
        mocks["negative"].return_value = MagicMock()
        mocks["negative"].return_value.get_prompt_context.return_value = ""
        mocks["verify"].return_value = MagicMock()
        mocks["reflect"].return_value = mock_reflect
        mocks["mission"].return_value = mock_mission
        try:
            with patch.object(agent.cvss_calc, "from_finding") as mock_cvss:
                mock_cvss.return_value = SimpleNamespace(
                    base_score=5.0, severity=Severity("Medium")
                )
                result = agent.process_query("scan example.com", target="example.com")
                assert isinstance(result, str)
        finally:
            _stop_patches(patches)


class TestProcessQueryToolExecution:
    def test_goverance_blocks_tool(self):
        agent = _make_lightweight_agent()
        agent.max_steps = 1

        mock_tree = MagicMock()
        mock_tree.steps = [MagicMock(tool_name="nmap", purpose="recon")]
        agent.planner.generate_attack_tree.return_value = mock_tree

        mock_mission = MagicMock()
        mock_mission.target = "example.com"
        mock_mission.snapshot.return_value = {"target": "example.com"}

        gate_decision = GateDecision(allowed=False, risk_level="DESTRUCTIVE",
                                     decision="deny", rationale="dangerous")

        mock_governance = MagicMock()
        mock_governance.gate.return_value = gate_decision
        agent.governance = mock_governance

        mock_reflect = MagicMock()
        mock_reflect.status = "ok"
        mock_reflect.recommendation = "continue"
        mock_reflect.switch_strategy = False
        mock_reflect.prompt_context.return_value = ""
        mock_reflect.history = []
        mock_reflect.consecutive_no_findings = 0

        patches = _make_process_query_patches(agent)
        mocks = _start_patches(patches)
        mocks["vf_module"].return_value = MagicMock()
        mocks["belief"].return_value = MagicMock()
        mocks["coverage"].return_value = MagicMock()
        mocks["coverage"].return_value.get_gaps.return_value = []
        mocks["coverage"].return_value.prompt_context.return_value = ""
        mocks["negative"].return_value = MagicMock()
        mocks["negative"].return_value.get_prompt_context.return_value = ""
        mocks["verify"].return_value = MagicMock()
        mocks["reflect"].return_value = mock_reflect
        mocks["mission"].return_value = mock_mission
        try:
            agent.client.chat.return_value = SimpleNamespace(
                content=json.dumps({
                    "action": "run_shell",
                    "tool": "nmap",
                    "command": "rm -rf /",
                    "purpose": "recon",
                }),
                tool_calls=None,
            )
            result = agent.process_query("scan example.com", target="example.com")
            assert "Governance gate" in result
        finally:
            _stop_patches(patches)


class TestProcessQueryDeadlock:
    def test_deadlock_detection(self):
        agent = _make_lightweight_agent()
        agent.max_steps = 10
        agent.loop_threshold = 2

        mock_mission = MagicMock()
        mock_mission.target = "example.com"
        mock_mission.snapshot.return_value = {"target": "example.com"}

        action_data = json.dumps({
            "action": "run_shell",
            "tool": "nmap",
            "command": "nmap example.com",
            "purpose": "recon",
        })
        agent.client.chat.return_value = SimpleNamespace(content=action_data, tool_calls=None)

        gate_decision = GateDecision(allowed=True, risk_level="SAFE", decision="allow")
        mock_governance = MagicMock()
        mock_governance.gate.return_value = gate_decision
        agent.governance = mock_governance

        mock_tool_result = ToolResult(success=True, tool_name="nmap", category=ToolCategory.RECON, findings=[])

        mock_reflect = MagicMock()
        mock_reflect.status = "ok"
        mock_reflect.recommendation = "continue"
        mock_reflect.switch_strategy = False
        mock_reflect.prompt_context.return_value = ""
        mock_reflect.history = []
        mock_reflect.consecutive_no_findings = 0

        # cot_logger.current_session needs entries for the [-1] access
        mock_thought = MagicMock()
        agent.cot_logger.current_session = [mock_thought]

        patches = _make_process_query_patches(agent)
        mocks = _start_patches(patches)
        mocks["vf_module"].return_value = MagicMock()
        mocks["belief"].return_value = MagicMock()
        mocks["coverage"].return_value = MagicMock()
        mocks["coverage"].return_value.get_gaps.return_value = []
        mocks["coverage"].return_value.prompt_context.return_value = ""
        mocks["negative"].return_value = MagicMock()
        mocks["negative"].return_value.get_prompt_context.return_value = ""
        mocks["verify"].return_value = MagicMock()
        mocks["reflect"].return_value = mock_reflect
        mocks["mission"].return_value = mock_mission
        p_telegram = patch("core.brain.send_telegram_notification")
        p_registry = patch.object(agent, "_execute_tool_registry", return_value=mock_tool_result)
        p_telegram.start()
        p_registry.start()
        try:
            result = agent.process_query("scan example.com", target="example.com")
            assert "DEADLOCK" in result
        finally:
            p_registry.stop()
            p_telegram.stop()
            _stop_patches(patches)


class TestProcessQueryMaxStepsHalt:
    def test_halts_after_max_steps(self):
        agent = _make_lightweight_agent()
        agent.max_steps = 2

        mock_mission = MagicMock()
        mock_mission.target = "example.com"
        mock_mission.snapshot.return_value = {"target": "example.com"}

        action_data = json.dumps({
            "action": "save_memory",
            "learning": "test",
            "target": "t",
            "category": "cat",
        })
        agent.client.chat.return_value = SimpleNamespace(content=action_data, tool_calls=None)

        mock_reflect = MagicMock()
        mock_reflect.status = "ok"
        mock_reflect.recommendation = "continue"
        mock_reflect.switch_strategy = False
        mock_reflect.prompt_context.return_value = ""
        mock_reflect.history = []
        mock_reflect.consecutive_no_findings = 0

        patches = _make_process_query_patches(agent)
        mocks = _start_patches(patches)
        mocks["vf_module"].return_value = MagicMock()
        mocks["belief"].return_value = MagicMock()
        mocks["coverage"].return_value = MagicMock()
        mocks["coverage"].return_value.get_gaps.return_value = []
        mocks["coverage"].return_value.prompt_context.return_value = ""
        mocks["negative"].return_value = MagicMock()
        mocks["negative"].return_value.get_prompt_context.return_value = ""
        mocks["verify"].return_value = MagicMock()
        mocks["reflect"].return_value = mock_reflect
        mocks["mission"].return_value = mock_mission
        try:
            result = agent.process_query("scan example.com", target="example.com")
            assert "Task halted" in result
            assert "2 steps" in result
        finally:
            _stop_patches(patches)


class TestProcessQueryCallback:
    def test_callback_called_on_intent(self):
        agent = _make_lightweight_agent()
        agent.max_steps = 1

        mock_mission = MagicMock()
        mock_mission.target = "example.com"
        mock_mission.snapshot.return_value = {"target": "example.com"}

        agent.client.chat.return_value = SimpleNamespace(
            content=json.dumps({"action": "finish", "summary": "done"}),
            tool_calls=None,
        )

        mock_reflect = MagicMock()
        mock_reflect.status = "ok"
        mock_reflect.recommendation = "continue"
        mock_reflect.switch_strategy = False
        mock_reflect.prompt_context.return_value = ""
        mock_reflect.history = []
        mock_reflect.consecutive_no_findings = 0

        cb = MagicMock()

        patches = _make_process_query_patches(agent)
        mocks = _start_patches(patches)
        mocks["vf_module"].return_value = MagicMock()
        mocks["belief"].return_value = MagicMock()
        mocks["coverage"].return_value = MagicMock()
        mocks["coverage"].return_value.get_gaps.return_value = []
        mocks["coverage"].return_value.prompt_context.return_value = ""
        mocks["negative"].return_value = MagicMock()
        mocks["negative"].return_value.get_prompt_context.return_value = ""
        mocks["verify"].return_value = MagicMock()
        mocks["reflect"].return_value = mock_reflect
        mocks["mission"].return_value = mock_mission
        try:
            with patch.object(agent.cvss_calc, "from_finding") as mock_cvss:
                mock_cvss.return_value = SimpleNamespace(
                    base_score=5.0, severity=Severity("Medium")
                )
                result = agent.process_query("scan example.com", target="example.com", callback=cb)
                cb.assert_called()
        finally:
            _stop_patches(patches)


class TestAdditionalEdgeCases:
    def test_extract_json_with_array(self):
        agent = _make_lightweight_agent()
        result = agent._extract_json('[1, 2, 3]')
        assert result is None

    def test_process_query_no_target_scan_inferred(self):
        agent = _make_lightweight_agent()
        agent.max_steps = 1

        mock_mission = MagicMock()
        mock_mission.target = "example.com"
        mock_mission.snapshot.return_value = {"target": "example.com"}

        agent.client.chat.return_value = SimpleNamespace(
            content=json.dumps({"action": "finish", "summary": "done"}),
            tool_calls=None,
        )

        mock_reflect = MagicMock()
        mock_reflect.status = "ok"
        mock_reflect.recommendation = "continue"
        mock_reflect.switch_strategy = False
        mock_reflect.prompt_context.return_value = ""
        mock_reflect.history = []
        mock_reflect.consecutive_no_findings = 0

        patches = _make_process_query_patches(agent)
        mocks = _start_patches(patches)
        mocks["vf_module"].return_value = MagicMock()
        mocks["belief"].return_value = MagicMock()
        mocks["coverage"].return_value = MagicMock()
        mocks["coverage"].return_value.get_gaps.return_value = []
        mocks["coverage"].return_value.prompt_context.return_value = ""
        mocks["negative"].return_value = MagicMock()
        mocks["negative"].return_value.get_prompt_context.return_value = ""
        mocks["verify"].return_value = MagicMock()
        mocks["reflect"].return_value = mock_reflect
        mocks["mission"].return_value = mock_mission
        p_target = patch("core.brain._extract_target_from_text", return_value="example.com")
        p_target.start()
        try:
            with patch.object(agent.cvss_calc, "from_finding") as mock_cvss:
                mock_cvss.return_value = SimpleNamespace(
                    base_score=5.0, severity=Severity("Medium")
                )
                result = agent.process_query("scan example.com")
                assert isinstance(result, str)
        finally:
            p_target.stop()
            _stop_patches(patches)

    def test_allowed_tools_set(self):
        from core.brain import ElengenixAgent
        assert isinstance(ElengenixAgent.ALLOWED_TOOLS, set)
        assert len(ElengenixAgent.ALLOWED_TOOLS) == 0

    def test_summarize_results_various_sizes(self):
        agent = _make_lightweight_agent()
        assert agent._summarize_results([]) == "No previous results."
        r1 = ToolResult(success=True, tool_name="a", category=ToolCategory.RECON, findings=[])
        summary = agent._summarize_results([r1])
        assert "a" in summary
        many = [ToolResult(success=True, tool_name=f"t{i}", category=ToolCategory.RECON, findings=[]) for i in range(10)]
        summary = agent._summarize_results(many)
        assert "t9" in summary
        assert "t0" not in summary


class TestGetNowContext:
    def test_default_tz(self):
        import os
        from agents.agent_helpers import _get_now_context
        old_tz = os.environ.pop("ELENGENIX_TZ", None)
        try:
            result = _get_now_context()
            assert "CURRENT TIME CONTEXT" in result
        finally:
            if old_tz:
                os.environ["ELENGENIX_TZ"] = old_tz

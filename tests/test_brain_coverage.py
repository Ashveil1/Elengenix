"""tests/test_brain_coverage.py — Coverage tests for core/brain.py

Focuses on uncovered lines in ElengenixAgent methods.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from tools.cvss_calculator import CVSSCalculator
from tools.governance import Governance


def _make_agent():
    """Create a lightweight agent for testing."""
    from core.brain import ElengenixAgent

    agent = ElengenixAgent.__new__(ElengenixAgent)
    agent.max_steps = 25
    agent.loop_threshold = 3
    agent.history_limit = 5
    agent.max_output_len = 2000
    agent.enable_planning = False
    agent.enable_cot_logging = False
    agent.verbose_thoughts = False
    agent.max_history_turns = 20
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
    agent.conversation_history = mock_cm.conversation_history

    mock_mp = MagicMock()
    mock_mp.process_universal.return_value = "universal result"
    mock_mp.process_hybrid.return_value = "hybrid result"
    agent.mode_processor = mock_mp

    agent.reflection_tracker = MagicMock()
    agent.reflection_tracker.classify_sentiment.return_value = "neutral"

    agent.planner = None
    agent.cot_logger = None
    agent.activity_logger = None
    agent.skill_registry = None
    agent.analysis_pipeline = None
    agent.vuln_reasoning = None
    agent.active_fuzzer = None
    agent.coverage_analyzer = None
    agent.learning_engine = None
    agent.bola_tester = None
    agent.waf_detector = None
    agent._team_aegis_clients = {"enabled": False}
    agent.agent_prompt_template = ""  # Required for process_query
    agent.verify_ssl = True  # Required for _fingerprint_target_for_planning

    return agent


# ═══════════════════════════════════════════════════════════════════════════════
# _fingerprint_target_for_planning
# ═══════════════════════════════════════════════════════════════════════════════


class TestFingerprintTarget:
    def test_empty_target_returns_none(self):
        agent = _make_agent()
        assert agent._fingerprint_target_for_planning("") is None

    def test_cache_hit(self):
        agent = _make_agent()
        cached = {"server": "nginx", "technologies": ["jQuery"]}
        agent._fingerprint_cache["http://example.com"] = cached
        assert agent._fingerprint_target_for_planning("http://example.com") == cached

    def test_successful_probe(self):
        agent = _make_agent()
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "nginx"}
        mock_resp.cookies = []
        mock_resp.text = "<html>test</html>"
        with patch("requests.get", return_value=mock_resp):
            with patch("agents.agent_planner.TargetFingerprinter") as MockFP:
                mock_fp = MagicMock()
                mock_fp.fingerprint.return_value = {"server": "nginx", "technologies": []}
                MockFP.return_value = mock_fp
                result = agent._fingerprint_target_for_planning("http://example.com")
                assert result is not None

    def test_probe_failure_returns_none(self):
        agent = _make_agent()
        with patch("requests.get", side_effect=Exception("network error")):
            result = agent._fingerprint_target_for_planning("http://example.com")
            assert result is None

    def test_fingerprinter_failure_returns_none(self):
        agent = _make_agent()
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.cookies = []
        mock_resp.text = ""
        with patch("requests.get", return_value=mock_resp):
            with patch(
                "agents.agent_planner.TargetFingerprinter", side_effect=Exception("fp error")
            ):
                result = agent._fingerprint_target_for_planning("http://example.com")
                assert result is None

    def test_bare_domain_gets_http_prefix(self):
        agent = _make_agent()
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.cookies = []
        mock_resp.text = ""
        with patch("requests.get", return_value=mock_resp):
            with patch("agents.agent_planner.TargetFingerprinter") as MockFP:
                mock_fp = MagicMock()
                mock_fp.fingerprint.return_value = {"server": None}
                MockFP.return_value = mock_fp
                agent._fingerprint_target_for_planning("example.com")


# ═══════════════════════════════════════════════════════════════════════════════
# _init_team_aegis_clients
# ═══════════════════════════════════════════════════════════════════════════════


class TestInitTeamAegis:
    def test_no_config_file(self):
        agent = _make_agent()
        with patch("pathlib.Path.exists", return_value=False):
            result = agent._init_team_aegis_clients()
            assert result["enabled"] is False

    def test_team_aegis_disabled(self):
        agent = _make_agent()
        with patch("pathlib.Path.exists", return_value=True):
            with patch("yaml.safe_load", return_value={"team_aegis": {"enabled": False}}):
                result = agent._init_team_aegis_clients()
                assert result["enabled"] is False

    def test_team_aegis_exception(self):
        agent = _make_agent()
        with patch("yaml.safe_load", side_effect=Exception("yaml error")):
            result = agent._init_team_aegis_clients()
            assert result["enabled"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# _save_to_persistent_memory
# ═══════════════════════════════════════════════════════════════════════════════


class TestSaveToPersistentMemory:
    def test_success(self):
        agent = _make_agent()
        with patch("core.brain._sqlite_save_message") as mock_save:
            agent._save_to_persistent_memory("user", "hello")
            mock_save.assert_called_once()

    def test_exception_does_not_raise(self):
        agent = _make_agent()
        with patch("core.brain._sqlite_save_message", side_effect=Exception("err")):
            agent._save_to_persistent_memory("user", "hello")


# ═══════════════════════════════════════════════════════════════════════════════
# _check_context_overflow
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckContextOverflow:
    def test_not_near_full(self):
        agent = _make_agent()
        with patch("core.brain._get_context_status") as mock_status:
            mock_status.return_value = {
                "is_near_full": False,
                "percent": 30.0,
                "used_tokens": 30000,
                "capacity": 100000,
            }
            assert agent._check_context_overflow() is False

    def test_near_full_triggers_summarize(self):
        agent = _make_agent()
        agent.conversation_history = [{"role": "user", "content": "hi"}] * 10
        with patch("core.brain._get_context_status") as mock_status:
            mock_status.return_value = {
                "is_near_full": True,
                "percent": 95.0,
                "used_tokens": 95000,
                "capacity": 100000,
            }
            with patch.object(agent, "_summarize_old_conversation") as mock_sum:
                assert agent._check_context_overflow() is True
                mock_sum.assert_called_once()

    def test_exception_returns_false(self):
        agent = _make_agent()
        with patch("core.brain._get_context_status", side_effect=Exception("fail")):
            assert agent._check_context_overflow() is False


# ═══════════════════════════════════════════════════════════════════════════════
# _summarize_old_conversation
# ═══════════════════════════════════════════════════════════════════════════════


class TestSummarizeOldConversation:
    def test_short_history_no_op(self):
        agent = _make_agent()
        agent.conversation_history = [{"role": "user", "content": "hi"}] * 5
        agent._summarize_old_conversation()
        assert len(agent.conversation_history) == 5

    def test_long_history_compressed(self):
        agent = _make_agent()
        history = []
        for i in range(10):
            history.append({"role": "user", "content": f"msg {i}"})
            history.append({"role": "assistant", "content": f"reply {i}"})
        agent.conversation_history = history

        mock_response = SimpleNamespace(content="This is a summary of the conversation.")
        agent.client.chat.return_value = mock_response

        with patch("core.brain._sqlite_clear_session"), patch(
            "core.brain._sqlite_save_message"
        ), patch("core.brain.logger"):
            with patch("tools.token_counter.count_tokens", return_value=100):
                agent._summarize_old_conversation()

        assert len(agent.conversation_history) == 7
        summary_entry = agent.conversation_history[3]
        assert "COMPRESSED SUMMARY" in summary_entry["content"]

    def test_short_summary_skipped(self):
        agent = _make_agent()
        history = []
        for i in range(10):
            history.append({"role": "user", "content": f"msg {i}"})
            history.append({"role": "assistant", "content": f"reply {i}"})
        agent.conversation_history = history

        mock_response = SimpleNamespace(content="short")
        agent.client.chat.return_value = mock_response

        original_len = len(agent.conversation_history)
        with patch("core.brain._sqlite_clear_session"), patch("core.brain.logger"):
            agent._summarize_old_conversation()
        assert len(agent.conversation_history) == original_len


# ═══════════════════════════════════════════════════════════════════════════════
# _enhance_prompt_with_cve_context
# ═══════════════════════════════════════════════════════════════════════════════


class TestEnhancePrompt:
    def test_enhances_prompt(self):
        agent = _make_agent()
        agent.base_prompt = "Base prompt"
        agent._enhance_prompt_with_cve_context()
        assert "CVE" in agent.base_prompt
        assert "Base prompt" in agent.base_prompt


# ═══════════════════════════════════════════════════════════════════════════════
# _base_url_hint
# ═══════════════════════════════════════════════════════════════════════════════


class TestBaseUrlHint:
    def test_with_http_target(self):
        agent = _make_agent()
        ms = MagicMock()
        ms.snapshot.return_value = {"target": "http://example.com"}
        assert agent._base_url_hint(ms) == "http://example.com"

    def test_with_bare_domain(self):
        agent = _make_agent()
        ms = MagicMock()
        ms.snapshot.return_value = {"target": "example.com"}
        assert agent._base_url_hint(ms) == "https://example.com"

    def test_with_empty_target(self):
        agent = _make_agent()
        ms = MagicMock()
        ms.snapshot.return_value = {"target": ""}
        assert agent._base_url_hint(ms) == "http://localhost"

    def test_exception_fallback(self):
        agent = _make_agent()
        ms = MagicMock()
        ms.snapshot.side_effect = Exception("error")
        assert agent._base_url_hint(ms) == "http://localhost"


# ═══════════════════════════════════════════════════════════════════════════════
# _extract_json
# ═══════════════════════════════════════════════════════════════════════════════


class TestExtractJson:
    def test_valid_json(self):
        agent = _make_agent()
        result = agent._extract_json('{"action": "finish"}')
        assert result == {"action": "finish"}

    def test_json_in_code_fence(self):
        agent = _make_agent()
        result = agent._extract_json('```json\n{"action": "finish"}\n```')
        assert result == {"action": "finish"}

    def test_empty_string(self):
        agent = _make_agent()
        result = agent._extract_json("")
        assert result is None

    def test_array_input_returns_none_for_object_expect(self):
        agent = _make_agent()
        result = agent._extract_json("[1, 2, 3]")
        assert result is None

    def test_trailing_comma_repaired(self):
        agent = _make_agent()
        result = agent._extract_json('{"action": "finish", "target": "example.com",}')
        assert result is not None


# ═══════════════════════════════════════════════════════════════════════════════
# _check_for_negative_feedback
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckForNegativeFeedback:
    def test_no_history_returns_early(self):
        agent = _make_agent()
        agent.conversation_history = []
        agent._check_for_negative_feedback("this is wrong")

    def test_no_assistant_turn_returns_early(self):
        agent = _make_agent()
        agent.conversation_history = [{"role": "user", "content": "hi"}]
        agent._check_for_negative_feedback("bad response")

    def test_negative_feedback_records_mistake(self):
        agent = _make_agent()
        agent.conversation_history = [
            {"role": "user", "content": "scan example.com"},
            {"role": "assistant", "content": "I found 3 vulnerabilities"},
            {"role": "user", "content": "this is wrong"},
        ]
        agent.reflection_tracker.classify_sentiment.return_value = "negative"
        agent._check_for_negative_feedback("this is completely wrong")
        agent.reflection_tracker.record_mistake.assert_called_once()

    def test_positive_feedback_no_mistake(self):
        agent = _make_agent()
        agent.conversation_history = [
            {"role": "user", "content": "scan example.com"},
            {"role": "assistant", "content": "I found 3 vulnerabilities"},
            {"role": "user", "content": "great work"},
        ]
        agent.reflection_tracker.classify_sentiment.return_value = "positive"
        agent._check_for_negative_feedback("great work")
        agent.reflection_tracker.record_mistake.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# _build_chat_messages
# ═══════════════════════════════════════════════════════════════════════════════


class TestBuildChatMessages:
    def test_build_chat_messages(self):
        agent = _make_agent()
        result = agent._build_chat_messages("system prompt", "user input")
        agent.conversation_manager.build_chat_messages.assert_called_once_with(
            "system prompt", "user input"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# clear_conversation_history
# ═══════════════════════════════════════════════════════════════════════════════


class TestClearConversationHistory:
    def test_clear(self):
        agent = _make_agent()
        agent.conversation_history = [{"role": "user", "content": "hi"}]
        agent.clear_conversation_history()
        agent.conversation_manager.clear.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# _append_history
# ═══════════════════════════════════════════════════════════════════════════════


class TestAppendHistory:
    def test_append(self):
        agent = _make_agent()
        agent._append_history("user", "hello")
        agent.conversation_manager.append_history.assert_called_once_with("user", "hello")


# ═══════════════════════════════════════════════════════════════════════════════
# process_query edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestProcessQuery:
    def test_casual_intent(self):
        agent = _make_agent()
        with patch("core.brain._analyze_intent", return_value="casual"):
            result = agent.process_query("hello", callback=None)
            assert result is not None

    def test_scan_with_target(self):
        agent = _make_agent()
        with patch("core.brain._analyze_intent", return_value="scan"):
            result = agent.process_query("scan example.com", target="example.com")
            assert result is not None

    def test_save_memory_action(self):
        agent = _make_agent()
        agent.mode_processor.process_universal.return_value = "saved"
        with patch("core.brain._analyze_intent", return_value="casual"):
            result = agent.process_query("remember this", callback=None)
            assert result is not None

    def test_governance_blocks_tool(self):
        agent = _make_agent()
        agent.governance.gate = MagicMock(
            return_value=MagicMock(decision="deny", rationale="blocked")
        )
        with patch("core.brain._analyze_intent", return_value="scan"):
            result = agent.process_query("run nmap", target="example.com")
            assert result is not None

    def test_deadlock_detection(self):
        agent = _make_agent()
        with patch("core.brain._analyze_intent", return_value="scan"):
            for _ in range(5):
                result = agent.process_query("run tool", target="example.com")
            assert result is not None


# ═══════════════════════════════════════════════════════════════════════════════
# process_universal and process_hybrid
# ═══════════════════════════════════════════════════════════════════════════════


class TestProcessModes:
    def test_process_universal(self):
        agent = _make_agent()
        result = agent.process_universal("hello", target="t", mode="auto")
        assert result is not None

    def test_process_hybrid_with_target(self):
        agent = _make_agent()
        with patch("core.brain._analyze_intent", return_value="scan"):
            result = agent.process_hybrid("scan example.com", target="example.com")
            assert result is not None

    def test_process_hybrid_no_target_no_inference(self):
        agent = _make_agent()
        with patch("core.brain._analyze_intent", return_value="scan"):
            with patch("core.brain._extract_target_from_text", return_value=""):
                result = agent.process_hybrid("scan something", target="")
                assert "No target specified" in result


# ═══════════════════════════════════════════════════════════════════════════════
# _fingerprint_target_for_planning (cache and activity_logger)
# ═══════════════════════════════════════════════════════════════════════════════


class TestFingerprintActivityLog:
    def test_activity_logger_called(self):
        agent = _make_agent()
        agent.activity_logger = MagicMock()
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "nginx"}
        mock_resp.cookies = []
        mock_resp.text = "<html></html>"
        with patch("requests.get", return_value=mock_resp):
            with patch("agents.agent_planner.TargetFingerprinter") as MockFP:
                mock_fp = MagicMock()
                mock_fp.fingerprint.return_value = {"server": "nginx", "technologies": []}
                MockFP.return_value = mock_fp
                agent._fingerprint_target_for_planning("http://test.com")
                agent.activity_logger.log_thought.assert_called_once()

    def test_activity_logger_exception(self):
        agent = _make_agent()
        agent.activity_logger = MagicMock()
        agent.activity_logger.log_thought.side_effect = Exception("log error")
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.cookies = []
        mock_resp.text = ""
        with patch("requests.get", return_value=mock_resp):
            with patch("agents.agent_planner.TargetFingerprinter") as MockFP:
                mock_fp = MagicMock()
                mock_fp.fingerprint.return_value = {"server": None}
                MockFP.return_value = mock_fp
                result = agent._fingerprint_target_for_planning("http://test.com")
                assert result is not None


# ═══════════════════════════════════════════════════════════════════════════════
# _init_team_aegis_clients with enabled config
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
# _summarize_old_conversation edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestSummarizeEdgeCases:
    def test_middle_end_leq_start(self):
        agent = _make_agent()
        agent.conversation_history = [{"role": "user", "content": "hi"}] * 7
        agent._summarize_old_conversation()
        assert len(agent.conversation_history) == 7

    def test_empty_middle_messages(self):
        agent = _make_agent()
        agent.conversation_history = [
            {"role": "user", "content": "a"},
            {"role": "assistant", "content": "b"},
            {"role": "user", "content": "c"},
            {"role": "assistant", "content": "d"},
            {"role": "user", "content": "e"},
            {"role": "assistant", "content": "f"},
            {"role": "user", "content": "g"},
        ]
        agent._summarize_old_conversation()
        assert len(agent.conversation_history) == 7

    def test_exception_in_summarize(self):
        agent = _make_agent()
        agent.conversation_history = [{"role": "user", "content": "hi"}] * 10
        agent.client.chat.side_effect = Exception("chat error")
        agent._summarize_old_conversation()
        assert len(agent.conversation_history) == 10


# ═══════════════════════════════════════════════════════════════════════════════
# process_query additional paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestProcessQueryAdditional:
    def test_max_steps_halt(self):
        agent = _make_agent()
        agent.max_steps = 1
        with patch("core.brain._analyze_intent", return_value="scan"):
            for _ in range(3):
                result = agent.process_query("run tool", target="example.com")
            assert result is not None

    def test_callback_called_on_intent(self):
        agent = _make_agent()
        callback = MagicMock()
        with patch("core.brain._analyze_intent", return_value="casual"):
            agent.process_query("hello", callback=callback)
            callback.assert_called()

    def test_no_target_scan_inferred(self):
        agent = _make_agent()
        with patch("core.brain._analyze_intent", return_value="scan"):
            with patch("core.brain._extract_target_from_text", return_value="example.com"):
                result = agent.process_query("scan example.com")
                assert result is not None

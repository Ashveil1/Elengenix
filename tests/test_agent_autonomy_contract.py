"""Anti-drift contract tests: what the AI is told it can do MUST actually work.

Locks in the autonomy overhaul:

1. No phase scripts — agent prompts must not prescribe an ordered pipeline.
2. Every action advertised in a system prompt has a real executor
   (prompt == executor), and unknown actions are reported back to the AI
   instead of silently finishing.
3. ``ask_user`` is a real, working interaction (bridge → TUI/CLI/stdin),
   not a stub string.
4. The sovereign decision-maker actually consults the LLM first.
"""

from __future__ import annotations

import asyncio
import inspect
import queue
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestNoPhaseScripts:
    """Agent-facing prompts must not prescribe an ordered phase pipeline."""

    def test_autonomous_agent_prompt_has_no_phase_script(self):
        src = (REPO_ROOT / "tools" / "autonomous_agent.py").read_text()
        assert "(Phase 1" not in src
        assert "(Phase 2" not in src
        assert "(Phase 3" not in src
        assert "(Phase 4" not in src
        # the capability menu explicitly says it is not an order of operations
        assert "NOT an order of operations" in src

    def test_autonomous_agent_system_prompt_grants_autonomy(self):
        from tools.autonomous_agent import _ai_decide_next

        src = inspect.getsource(_ai_decide_next)
        assert "FULL autonomy" in src
        assert "no phase script" in src
        assert "YOUR" in src

    def test_brain_planning_prompt_has_no_prescribed_phases(self):
        from elengenix.brain import PlanningEngine

        src = inspect.getsource(PlanningEngine._generate_strategic_plan)
        assert '"Reconnaissance"' not in src  # canned phase template removed
        assert "NO prescribed phase script" in src


class TestPromptExecutorContract:
    """Every action advertised to the AI has a real executor."""

    def test_every_advertised_action_has_an_executor(self):
        import tools.autonomous_agent as aa

        # actions advertised in the capability menu
        advertised = {
            "recon", "wayback_recon", "github_dork", "osint_research",
            "vuln_intel", "js_recon", "http_probe", "waf_detect",
            "endpoint_fuzz", "param_mine", "cors_scan", "header_audit",
            "subdomain_takeover", "request_auth", "auth_test",
            "injection_test", "bola_probe", "waf_bypass", "vuln_scan",
            "xss_hunt", "ssrf_scan", "graphql_introspect", "race_condition",
            "zap_active_scan", "create_custom_tool", "threat_model",
            "analyze", "done",
        }
        # collect the dispatch map built inside the run method
        src = (REPO_ROOT / "tools" / "autonomous_agent.py").read_text()
        # every advertised name must have an _exec_* function or special-case
        executors = {n for n in dir(aa) if n.startswith("_exec_")}
        special = {"threat_model", "create_custom_tool", "endpoint_fuzz", "done"}
        mapping = {
            "recon": "_exec_recon", "http_probe": "_exec_http_probe",
            "waf_detect": "_exec_waf_detect", "bola_probe": "_exec_bola_probe",
            "header_audit": "_exec_header_audit", "osint_research": "_exec_osint_research",
            "vuln_intel": "_exec_vuln_intel", "wayback_recon": "_exec_wayback_recon",
            "github_dork": "_exec_github_dork", "js_recon": "_exec_js_recon",
            "param_mine": "_exec_param_mine", "cors_scan": "_exec_cors_scan",
            "injection_test": "_exec_injection_test",
            "subdomain_takeover": "_exec_subdomain_takeover",
            "waf_bypass": "_exec_waf_bypass", "request_auth": "_exec_request_auth",
            "vuln_scan": "_exec_vuln_scan", "xss_hunt": "_exec_xss_hunt",
            "zap_active_scan": "_exec_zap_active_scan", "analyze": "_exec_analyze_findings",
            "ssrf_scan": "_exec_ssrf_scan_ex", "graphql_introspect": "_exec_graphql_ex",
            "race_condition": "_exec_race_condition_ex", "auth_test": "_exec_auth_test_ex",
        }
        missing = [
            a for a in advertised
            if a not in special and mapping.get(a) not in executors
        ]
        assert missing == [], f"advertised but not executable: {missing}"

    def test_chat_brain_advertises_only_supported_actions(self):
        from elengenix.chat import brain as chat_brain

        src = inspect.getsource(chat_brain)
        for action in ("run_shell", "execute_tool", "ask_user", "save_memory", "finish"):
            assert f'"{action}"' in src
        # unknown actions are corrected, not treated as finish
        assert "unsupported action" in src

    def test_unknown_chat_action_does_not_finish(self, monkeypatch):
        """An unknown action must be reported back to the AI, never silently
        end the task (the old behavior swallowed arbitrary actions)."""
        from elengenix.chat import brain as chat_brain

        agent = chat_brain.ElengenixAgent.__new__(chat_brain.ElengenixAgent)
        agent.max_steps = 3
        agent.loop_threshold = 3
        agent._step_count = 0
        agent._last_responses = []
        agent.conversation_history = []

        monkeypatch.setattr(chat_brain, "get_context_for_ai", lambda *a, **k: "")
        monkeypatch.setattr(chat_brain, "_get_now_context", lambda: "")
        monkeypatch.setattr(chat_brain, "remember", lambda *a, **k: None)
        monkeypatch.setattr(chat_brain, "display_in_chat_mode", lambda *a, **k: None)

        class _Resp:
            content = '{"action": "teleport", "somewhere": "far"}'

        class _Client:
            def chat(self, messages, **kw):
                return _Resp()

        agent.client = _Client()
        agent._build_chat_messages = lambda *a, **k: []
        agent._append_history = lambda *a, **k: None
        agent._activity_log = lambda *a, **k: None

        result = agent.process_query("scan something", target="example.com")
        # the loop must NOT claim success on an unknown action: it records
        # the correction and keeps iterating until it runs out of steps
        assert "Task finished" not in result
        assert any("unsupported action" in r for r in agent._last_responses)


class TestAskUserRealInteraction:
    """ask_user must route to a real operator answer, not a canned string."""

    def test_bridge_ui_hook_roundtrip(self):
        from elengenix.chat.user_interaction import UserInteractionBridge

        bridge = UserInteractionBridge()
        sent = {}

        def ui_hook(question, meta, answer_q):
            sent["question"] = question
            answer_q.put("skiplines")

        bridge.register_ui_hook(ui_hook)
        answer = bridge.ask("Provide auth?", meta={"options": {"1": "cookie"}})
        assert answer == "skiplines"
        assert "auth" in sent["question"]

    def test_bridge_cli_hook_roundtrip(self):
        from elengenix.chat.user_interaction import UserInteractionBridge

        bridge = UserInteractionBridge()
        bridge.register_cli_hook(lambda q, m: f"answer-to:{q}")
        assert bridge.ask("what?") == "answer-to:what?"

    def test_bridge_headless_eof_never_deadlocks(self, monkeypatch):
        from elengenix.chat.user_interaction import UserInteractionBridge

        bridge = UserInteractionBridge()

        def fake_input(prompt=""):
            raise EOFError

        monkeypatch.setattr("builtins.input", fake_input)
        answer = bridge.ask("anyone there?")
        assert answer == "[no operator answer]"

    def test_handle_ask_user_uses_bridge(self, monkeypatch):
        from elengenix.chat import brain as chat_brain

        monkeypatch.setattr(
            "elengenix.chat.user_interaction.ask_user",
            lambda q, meta=None, timeout=None: "REAL-ANSWER",
        )
        out = chat_brain.handle_ask_user({"question": "go?"})
        assert out == "REAL-ANSWER"

    def test_chat_loop_ask_user_returns_operator_answer(self, monkeypatch):
        """End-to-end: AI chooses ask_user → bridge → answer feeds back."""
        from elengenix.chat import brain as chat_brain

        agent = chat_brain.ElengenixAgent.__new__(chat_brain.ElengenixAgent)
        agent.max_steps = 5
        agent.loop_threshold = 3
        agent._step_count = 0
        agent._last_responses = []
        agent.conversation_history = []

        monkeypatch.setattr(chat_brain, "get_context_for_ai", lambda *a, **k: "")
        monkeypatch.setattr(chat_brain, "_get_now_context", lambda: "")
        monkeypatch.setattr(chat_brain, "remember", lambda *a, **k: None)
        monkeypatch.setattr(chat_brain, "display_in_chat_mode", lambda *a, **k: None)
        monkeypatch.setattr(
            chat_brain, "handle_ask_user",
            lambda q: "session=abc123",
        )

        responses = iter([
            '{"action": "ask_user", "question": "need auth for /admin"}',
            '{"action": "finish", "summary": "got auth"}',
        ])

        class _Resp:
            content = None

        class _Client:
            def chat(self, messages, **kw):
                _Resp.content = next(responses)
                return _Resp()

        agent.client = _Client()
        agent._build_chat_messages = lambda *a, **k: []
        agent._append_history = lambda *a, **k: None
        agent._activity_log = lambda *a, **k: None

        result = agent.process_query("test target", target="example.com")
        assert "got auth" in result

    def test_display_in_chat_mode_routes_to_registered_hook(self):
        import elengenix.chat.brain as chat_brain
        from elengenix.chat.user_interaction import get_user_interaction_bridge

        seen = []
        bridge = get_user_interaction_bridge()
        bridge.register_display_hook(lambda msg, mode="info": seen.append((msg, mode)))
        try:
            chat_brain.display_in_chat_mode("hello operator", "info")
        finally:
            bridge.unregister("display")
        assert seen and seen[0][0] == "hello operator"


class TestSovereignDecisionUsesLLM:
    """The decision engine must consult the LLM before falling back to
    heuristic scoring."""

    def test_llm_choice_wins(self):
        import asyncio

        from elengenix.brain import DecisionEngine

        actions = [
            {"tool": "nmap", "description": "port scan", "params": {}},
            {"tool": "curl", "description": "probe root", "params": {}},
        ]

        class _Resp:
            content = '{"chosen": 1, "reasoning": "cheaper first"}'

        class _LLM:
            def chat(self, messages, **kw):
                return _Resp()

        engine = DecisionEngine(_LLM(), reasoning=None, constitutional_engine=None, governance=None)
        ctx = type("Ctx", (), {"target": "example.com"})()
        decision = asyncio.run(engine._make_sovereign_decision(actions, ctx))
        assert decision.tool == "curl"

    def test_llm_unavailable_falls_back_to_scoring(self):
        import asyncio

        from elengenix.brain import DecisionEngine

        actions = [
            {"tool": "nmap", "description": "port scan", "params": {}},
        ]

        class _BrokenLLM:
            def chat(self, messages, **kw):
                raise RuntimeError("no llm")

        engine = DecisionEngine(_BrokenLLM(), reasoning=None, constitutional_engine=None, governance=None)
        ctx = type("Ctx", (), {"target": "example.com"})()
        decision = asyncio.run(engine._make_sovereign_decision(actions, ctx))
        # heuristic fallback still picks a valid action
        assert decision.tool == "nmap"


class TestLoopToolExecution:
    """loop._execute_action must work against the real ToolRegistry."""

    def test_unknown_tool_reports_available_tools(self):
        import asyncio

        from elengenix.loop import TrueAgenticLoop
        from elengenix.tools import ToolRegistry

        loop_obj = TrueAgenticLoop.__new__(TrueAgenticLoop)
        loop_obj.tools = ToolRegistry()
        loop_obj.mission_context = type("C", (), {"mission_id": "m", "target": "x"})()

        class _AllowGate:
            decision = "allow"
            rationale = ""

        class _Gov:
            async def gate(self, *a, **k):
                return _AllowGate()

        loop_obj.governance = _Gov()
        action = type("A", (), {"tool": "does_not_exist", "target": "x", "parameters": {}, "description": "d"})()
        result = asyncio.run(loop_obj._execute_action(action))
        assert result["success"] is False
        assert "not registered" in result["error"]

    def test_registered_tool_executes(self):
        from elengenix.loop import TrueAgenticLoop
        from elengenix.tools import ToolRegistry, ToolResult

        tool = MagicMock()
        tool.metadata.name = "fake_scanner"
        tool.execute = AsyncMock(
            return_value=ToolResult(
                success=True, tool_name="fake_scanner", category="scan", output="done"
            )
        )
        reg = ToolRegistry()
        reg.register(tool)

        loop_obj = TrueAgenticLoop.__new__(TrueAgenticLoop)
        loop_obj.tools = reg
        loop_obj.mission_context = type("C", (), {"mission_id": "m", "target": "x"})()

        class _AllowGate2:
            decision = "allow"
            rationale = ""

        class _Gov2:
            async def gate(self, *a, **k):
                return _AllowGate2()

        loop_obj.governance = _Gov2()
        action = type("A", (), {"tool": "fake_scanner", "target": "x", "parameters": {}, "description": "d"})()
        result = asyncio.run(loop_obj._execute_action(action))
        assert result["success"] is True
        assert result["output"] == "done"

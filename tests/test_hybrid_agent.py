"""tests/test_hybrid_agent.py — Unit tests for HybridAgent."""

import json
import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from agents.hybrid_agent import HybridAgent, _extract_json, _SIMPLE_COMMANDS
from tools.tool_registry import ToolResult, ToolCategory


class FakeClient:
    """Minimal mock AI client for testing."""
    def __init__(self, responses=None):
        self.responses = responses or []

    def chat(self, messages, temperature=0.5):
        if self.responses:
            return type("Resp", (), {"content": self.responses.pop(0)})()
        return type("Resp", (), {"content": '{"action": "complete_mission", "message": "done"}'})()


class FakeGovernance:
    """Always-allows governance for testing."""
    def gate(self, mission_id="", target="", action=None):
        from tools.governance import GateDecision
        return GateDecision(
            allowed=True,
            risk_level="SAFE",
            decision="allow",
            rationale="test",
        )

    def classify_risk(self, command=""):
        return {
            "risk_level": "SAFE",
            "decision": "allow",
            "rationale": "test",
        }


# ── _extract_json tests ────────────────────────────────────────────────

class TestExtractJson:
    def test_extract_json_from_markdown_fence(self):
        text = '```json\n{"action": "run_command", "command": "nmap"}\n```'
        assert _extract_json(text) == {"action": "run_command", "command": "nmap"}

    def test_extract_json_plain_object(self):
        text = '{"action": "run_tool", "tool": "nuclei"}'
        assert _extract_json(text) == {"action": "run_tool", "tool": "nuclei"}

    def test_extract_json_plain_array(self):
        text = '[{"description": "task1", "status": "pending"}]'
        assert _extract_json(text) == [{"description": "task1", "status": "pending"}]

    def test_extract_json_finds_braces_in_noisy_text(self):
        text = "Here is my response:\n\n{\"action\": \"run_command\", \"command\": \"ls\"}\n\nThat's all."
        assert _extract_json(text) == {"action": "run_command", "command": "ls"}

    def test_extract_json_raises_on_invalid(self):
        with pytest.raises(ValueError):
            _extract_json("this is not json at all")

    def test_extract_json_with_extra_whitespace(self):
        text = '  {"a": 1}  '
        assert _extract_json(text) == {"a": 1}


# ── Analysis filtering tests ───────────────────────────────────────────

class TestShouldRunAnalysis:
    def test_skip_simple_commands(self):
        agent = HybridAgent()
        for cmd in ["ls", "cat /etc/hosts", "echo hello", "pwd", "cd /tmp", "which nmap", "whoami", "ls -la"]:
            assert not agent._should_run_analysis(cmd), f"{cmd} should be skipped"

    def test_run_for_security_tools(self):
        agent = HybridAgent()
        for cmd in ["nuclei -u https://example.com", "nmap -sV target.com", "python3 exploit.py", "curl -si http://target/"]:
            assert agent._should_run_analysis(cmd), f"{cmd} should run analysis"

    def test_run_for_custom_tools(self):
        agent = HybridAgent()
        for cmd in ["sublist3r -d example.com", "ffuf -u https://example.com/FUZZ", "sqlmap -u https://example.com/"]:
            assert agent._should_run_analysis(cmd), f"{cmd} should run analysis"

    def test_empty_command_skipped(self):
        agent = HybridAgent()
        assert not agent._should_run_analysis("")
        assert not agent._should_run_analysis(None)


# ── Deadlock detection tests ──────────────────────────────────────────

class TestDeadlockDetection:
    def test_no_deadlock_with_few_actions(self):
        agent = HybridAgent(loop_threshold=4)
        agent.action_history = [
            {"action": "run_tool", "tool": "subfinder"},
            {"action": "run_tool", "tool": "httpx"},
        ]
        assert not agent._is_deadlocked()

    def test_detects_deadlock_same_action(self):
        agent = HybridAgent(loop_threshold=4)
        action = {"action": "run_command", "command": "nmap localhost"}
        for _ in range(4):
            agent.action_history.append(action)
        assert agent._is_deadlocked()

    def test_no_deadlock_different_actions(self):
        agent = HybridAgent(loop_threshold=4)
        agent.action_history = [
            {"action": "run_tool", "tool": "subfinder", "purpose": "recon"},
            {"action": "run_tool", "tool": "httpx", "purpose": "probe"},
            {"action": "run_command", "command": "nmap", "purpose": "scan"},
            {"action": "update_intel", "intel": {"key": "val"}, "purpose": "record"},
        ]
        assert not agent._is_deadlocked()

    def test_deadlock_custom_threshold(self):
        agent = HybridAgent(loop_threshold=3)
        action = {"action": "run_command", "command": "curl http://target/"}
        for _ in range(3):
            agent.action_history.append(action)
        assert agent._is_deadlocked()


# ── Finding extraction tests ───────────────────────────────────────────

class TestExtractFindings:
    def test_extract_urls_from_output(self):
        output = "Found something at https://example.com/admin and https://example.com/api"
        findings = HybridAgent._extract_findings(output, "curl -si https://example.com")
        assert len(findings) > 0
        url_finding = next((f for f in findings if f["type"] == "extracted_url"), None)
        assert url_finding is not None
        assert "https://example.com/admin" in url_finding["urls"]

    def test_extract_potential_secrets(self):
        output = "API_KEY=sk-1234567890abcdef\nSECRET=topsecretvalue\nTOKEN=ghp_testtoken"
        findings = HybridAgent._extract_findings(output, "cat config.txt")
        secret_finding = next((f for f in findings if f["type"] == "potential_secret"), None)
        assert secret_finding is not None
        assert len(secret_finding["matches"]) > 0

    def test_no_findings_for_empty_output(self):
        findings = HybridAgent._extract_findings("", "ls")
        assert findings == []

    def test_no_findings_for_clean_output(self):
        findings = HybridAgent._extract_findings("Everything looks normal\nNo issues found.", "echo check")
        assert findings == []


# ── Report generation tests ────────────────────────────────────────────

class TestReportGeneration:
    def test_finalize_mission_with_no_findings(self):
        agent = HybridAgent()
        agent.objective = "test target"
        agent.action_history = [
            {"action": "run_command", "command": "ping -c 1 target", "purpose": "check connectivity"},
        ]
        report = agent._finalize_mission()
        assert "Hybrid Mission Report" in report
        assert "test target" in report
        assert "1" in report  # 1 action

    def test_finalize_mission_with_findings(self):
        agent = HybridAgent()
        agent.objective = "scan target.com"
        agent.target = "target.com"
        agent.all_findings = [
            {"type": "open_port", "port": 80, "severity": "medium", "_tool": "nmap"},
            {"type": "xss", "url": "https://target.com/search", "severity": "high", "_tool": "dalfox"},
        ]
        report = agent._finalize_mission()
        assert "CVSS-Scored Findings" in report
        assert "open_port" in report
        assert "xss" in report

    def test_report_includes_duration(self):
        import time
        agent = HybridAgent()
        agent.start_time = time.time() - 60  # 1 minute ago
        agent.objective = "test"
        report = agent._finalize_mission()
        assert "60s" in report or "1.0m" in report

    def test_report_tracks_missing_tools(self):
        agent = HybridAgent()
        agent.objective = "test"
        agent.missing_tools = {"sublist3r", "aquatone"}
        report = agent._finalize_mission()
        assert "Tools Not Available" in report
        assert "sublist3r" in report
        assert "aquatone" in report


# ── SMOKE: HybridAgent construction ───────────────────────────────────

class TestHybridAgentConstruction:
    def test_default_construction(self):
        agent = HybridAgent()
        assert agent.max_steps == 50
        assert agent.strategist_interval == 5
        assert agent.enable_analysis is True
        assert agent.enable_memory is True
        assert agent.loop_threshold == 4
        assert agent.target == ""
        assert agent.action_history == []
        assert agent.all_findings == []

    def test_custom_construction(self):
        agent = HybridAgent(
            target="example.com",
            max_steps=30,
            strategist_interval=3,
            enable_analysis=False,
            loop_threshold=5,
        )
        assert agent.max_steps == 30
        assert agent.target == "example.com"
        assert not agent.enable_analysis
        assert agent.loop_threshold == 5

    def test_executor_created(self):
        agent = HybridAgent()
        assert agent.executor is not None
        assert hasattr(agent.executor, "execute_shell")

    def test_cvss_calculator_created(self):
        agent = HybridAgent()
        assert agent.cvss_calc is not None
        assert hasattr(agent.cvss_calc, "from_finding")


# ── SMOKE: Full cycle (mocked) ────────────────────────────────────────

class TestHybridCycle:
    def test_mocked_cycle_no_client_returns_early(self):
        agent = HybridAgent()
        result = agent.run("test objective")
        assert result is not None
        assert "Hybrid Mission Report" in result

    def test_mocked_cycle_with_client(self):
        responses = [
            # Strategist response
            json.dumps([
                {"description": "Run subfinder", "status": "pending", "phase": "recon"},
                {"description": "Scan with nuclei", "status": "pending", "phase": "scanning"},
            ]),
            # Specialist cycle 1 - complete_mission immediately
            json.dumps({
                "thought": "No tasks to execute, mission complete",
                "action": "complete_mission",
                "message": "Mission completed successfully",
            }),
        ]
        agent = HybridAgent(client=FakeClient(responses))
        result = agent.run("test scan")
        assert result is not None
        assert "Hybrid Mission Report" in result

    def test_strategist_parses_json_tasks(self):
        responses = [
            json.dumps([
                {"description": "Recon phase", "status": "pending", "phase": "recon"},
                {"description": "Scan phase", "status": "pending", "phase": "scanning"},
            ]),
            json.dumps({"action": "complete_mission", "message": "done"}),
        ]
        agent = HybridAgent(client=FakeClient(responses))
        agent.run("test")
        assert len(agent.tasks) == 2
        assert agent.tasks[0]["description"] == "Recon phase"
        assert agent.tasks[1]["phase"] == "scanning"

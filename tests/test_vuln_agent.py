"""
Tests for elengenix/agent/vuln_agent.py — Autonomous VulnAgent.
"""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from elengenix.agent.vuln_agent import (
    VulnAgent,
    Finding,
    Hypothesis,
    ScanStep,
    VulnReport,
    _tool_port_scan,
    _tool_web_recon,
    _tool_vuln_scan,
    _tool_search_cve,
    _tool_analyze_target,
    AVAILABLE_TOOLS,
)


# ---------------------------------------------------------------------------
# Mock AI client
# ---------------------------------------------------------------------------


class MockChatResponse:
    def __init__(self, content: str):
        self.content = content


class MockClient:
    def __init__(self, responses=None):
        self._responses = responses or []
        self._idx = 0
        self.call_count = 0

    def chat(self, messages):
        self.call_count += 1
        if self._idx < len(self._responses):
            resp = self._responses[self._idx]
            self._idx += 1
            return MockChatResponse(resp)
        return MockChatResponse('{"conclude": true, "summary": "done"}')


# ---------------------------------------------------------------------------
# Unit: Data types
# ---------------------------------------------------------------------------


class TestFinding:
    def test_defaults(self):
        f = Finding(title="Test", description="Desc", severity="high", target="x")
        assert f.confidence == 0.5
        assert f.remediation == ""

    def test_high_confidence(self):
        f = Finding(title="X", description="Y", severity="critical", target="t", confidence=0.95)
        assert f.confidence == 0.95


class TestHypothesis:
    def test_defaults(self):
        h = Hypothesis(description="Port 80 open", rationale="nmap scan")
        assert h.status == "pending"
        assert h.confidence == 0.3
        assert h.evidence == []


class TestScanStep:
    def test_creation(self):
        s = ScanStep(step=1, reasoning="test", tool="port_scan", arguments={"target": "x"}, result_summary="ok")
        assert s.step == 1
        assert s.tool == "port_scan"


class TestVulnReport:
    def test_to_dict(self):
        r = VulnReport(
            target="test.com",
            findings=[Finding(title="XSS", description="X", severity="high", target="test.com")],
            open_ports=[80, 443],
            services={"http": "nginx"},
        )
        d = r.to_dict()
        assert d["target"] == "test.com"
        assert len(d["findings"]) == 1
        assert d["open_ports"] == [80, 443]

    def test_empty_report(self):
        r = VulnReport(target="x")
        d = r.to_dict()
        assert d["findings"] == []
        assert d["total_steps"] == 0


# ---------------------------------------------------------------------------
# Unit: VulnAgent capabilities
# ---------------------------------------------------------------------------


class TestVulnAgentInit:
    def test_defaults(self):
        agent = VulnAgent(client=MagicMock(), target="10.0.0.1")
        assert agent.target == "10.0.0.1"
        assert agent.max_steps == 25
        assert agent.step == 0
        assert agent.findings == []
        assert agent.hypotheses == []

    def test_custom_max_steps(self):
        agent = VulnAgent(client=MagicMock(), target="x", max_steps=5)
        assert agent.max_steps == 5

    def test_with_governance(self):
        gov = MagicMock()
        agent = VulnAgent(client=MagicMock(), target="x", governance=gov)
        assert agent.governance is gov

    def test_custom_report_dir(self):
        agent = VulnAgent(client=MagicMock(), target="x", report_dir=Path("/tmp/reports"))
        assert agent.report_dir == Path("/tmp/reports")


class TestVulnAgentBuildTurnPrompt:
    def test_initial_prompt_contains_target(self):
        agent = VulnAgent(client=MagicMock(), target="example.com")
        prompt = agent._build_turn_prompt()
        assert "example.com" in prompt
        assert "TOOL_DEFS_TEXT" not in prompt  # formatted away
        assert "port_scan" in prompt
        assert "web_recon" in prompt
        assert "vuln_scan" in prompt

    def test_prompt_includes_state(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent.findings.append(Finding(title="Open port 80", description="Port 80 open", severity="info", target="x"))
        agent.hypotheses.append(Hypothesis(description="Test hypothesis", rationale="because"))
        prompt = agent._build_turn_prompt()
        assert "Open port 80" in prompt
        assert "Test hypothesis" in prompt


class TestVulnAgentFormatMethods:
    def test_format_hypotheses_empty(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        assert "No hypotheses yet" in agent._format_hypotheses()

    def test_format_hypotheses_list(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent.hypotheses.append(Hypothesis(description="Port 22 open", rationale="test"))
        result = agent._format_hypotheses()
        assert "Port 22 open" in result
        assert "pending" in result

    def test_format_findings_empty(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        assert "No findings yet" in agent._format_findings()

    def test_format_findings_list(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent.findings.append(Finding(title="XSS", description="x", severity="high", target="x", source_tool="nikto"))
        result = agent._format_findings()
        assert "XSS" in result
        assert "HIGH" in result

    def test_format_history_empty(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        assert "no steps yet" in agent._format_history()

    def test_format_history_list(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent.scan_history.append(ScanStep(step=1, reasoning="r", tool="port_scan", arguments={"target": "x"}, result_summary="done"))
        result = agent._format_history()
        assert "port_scan" in result


class TestVulnAgentExtractAction:
    def test_json_code_fence(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        content = 'Reasoning: test\n\n```json\n{"tool": "port_scan", "arguments": {"target": "x"}}\n```'
        action = agent._extract_action(content)
        assert action["tool"] == "port_scan"
        assert action["arguments"]["target"] == "x"

    def test_bare_json(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        content = 'Some text {"tool": "web_recon", "arguments": {"target": "y"}} more text'
        action = agent._extract_action(content)
        assert action["tool"] == "web_recon"

    def test_conclude_pattern(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        content = "I have enough evidence to conclude"
        action = agent._extract_action(content)
        assert action["conclude"] is True

    def test_conclude_explicit_true(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        content = 'Based on findings I conclude: true'
        action = agent._extract_action(content)
        assert action["conclude"] is True

    def test_fallback(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        content = "Just random text with no structure"
        action = agent._extract_action(content)
        assert action["conclude"] is True


# ---------------------------------------------------------------------------
# Integration: Hunt loop
# ---------------------------------------------------------------------------


class TestVulnAgentHunt:
    def test_concludes_immediately_if_ai_says_conclude(self):
        """AI says conclude right away -> no steps, immediate report."""
        client = MockClient(['{"conclude": true, "summary": "nothing to see"}'])
        agent = VulnAgent(client=client, target="test.com", max_steps=10)
        report = agent.hunt()
        assert report.total_steps == 1  # 1 reasoning step
        assert "nothing to see" in report.summary
        assert client.call_count == 1

    def test_one_tool_then_conclude(self):
        """AI runs one tool then concludes."""
        responses = [
            'Reasoning: scan port 80\n\n```json\n{"tool": "port_scan", "arguments": {"target": "test.com"}}\n```',
            '{"conclude": true, "summary": "found nothing interesting"}',
        ]
        client = MockClient(responses)
        agent = VulnAgent(client=client, target="test.com", max_steps=10)

        with patch("elengenix.agent.vuln_agent._tool_port_scan", return_value={"success": True, "output": "Port 80 open (http)"}):
            report = agent.hunt()

        assert report.total_steps == 2
        assert len(agent.scan_history) == 1
        assert agent.scan_history[0].tool == "port_scan"

    def test_max_steps_honored(self):
        """Hunt stops after max_steps even if AI keeps calling tools."""
        client = MockClient()  # always returns conclude
        # Override to always call a tool
        client._responses = [
            '{"tool": "port_scan", "arguments": {"target": "x"}}'
        ] * 5 + ['{"conclude": true, "summary": "done"}']
        client._idx = 0

        agent = VulnAgent(client=client, target="x", max_steps=3)

        with patch("elengenix.agent.vuln_agent._tool_port_scan", return_value={"success": True, "output": "ok"}):
            report = agent.hunt()

        assert report.total_steps <= 3
        assert client.call_count <= 3

    def test_governance_blocks_tool(self):
        """Governance blocks a tool, agent handles gracefully."""
        client = MockClient([
            '{"tool": "port_scan", "arguments": {"target": "evil.com"}}',
            '{"conclude": true, "summary": "all done"}',
        ])
        gov = MagicMock()
        gate_result = MagicMock()
        gate_result.decision = "deny"
        gate_result.rationale = "unauthorized target"
        gov.gate.return_value = gate_result

        agent = VulnAgent(client=client, target="evil.com", governance=gov, max_steps=5)
        report = agent.hunt()

        assert report.total_steps == 2
        # The tool was blocked, but agent continued

    def test_tool_error_handled(self):
        """Tool raises exception, agent keeps going."""
        client = MockClient([
            '{"tool": "vuln_scan", "arguments": {"target": "x"}}',
            '{"conclude": true, "summary": "done"}',
        ])
        agent = VulnAgent(client=client, target="x", max_steps=5)

        with patch("elengenix.agent.vuln_agent._tool_vuln_scan", side_effect=Exception("crash")):
            report = agent.hunt()

        assert report.total_steps == 2
        assert not agent.scan_history[0].result_summary.startswith("crash")

    def test_unknown_tool_handled(self):
        """AI calls unknown tool, agent returns error."""
        client = MockClient([
            '{"tool": "nonexistent", "arguments": {}}',
            '{"conclude": true, "summary": "done"}',
        ])
        agent = VulnAgent(client=client, target="x", max_steps=5)
        report = agent.hunt()
        assert report.total_steps == 2


# ---------------------------------------------------------------------------
# Integration: Profile & hypothesis updates
# ---------------------------------------------------------------------------


class TestVulnAgentUpdateProfile:
    def test_extracts_open_ports(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent._update_profile({"success": True, "output": "22/tcp open  ssh\n80/tcp open  http\n443/tcp open https"})
        assert 22 in agent.profile.get("open_ports", [])
        assert 80 in agent.profile.get("open_ports", [])
        assert 443 in agent.profile.get("open_ports", [])

    def test_extracts_services(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent._update_profile({"success": True, "output": "Apache 2.4.49\nOpenSSH 8.9p1"})
        svcs = agent.profile.get("services", {})
        assert "apache" in svcs
        assert svcs["apache"] == "2.4.49"
        assert "openssh" in svcs

    def test_ignores_failed_results(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent._update_profile({"success": False, "error": "timeout"})
        assert agent.profile == {}


class TestVulnAgentHypothesis:
    def test_generates_hypothesis_from_port_80(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent._maybe_generate_hypothesis({"success": True, "output": "port 80 found"})
        assert any("HTTP service" in h.description for h in agent.hypotheses)

    def test_generates_hypothesis_from_apache(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent._maybe_generate_hypothesis({"success": True, "output": "Apache 2.4.49"})
        assert any("Apache" in h.description for h in agent.hypotheses)

    def test_generates_hypothesis_from_ssh(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent._maybe_generate_hypothesis({"success": True, "output": "OpenSSH 8.9p1"})
        assert any("SSH" in h.description for h in agent.hypotheses)

    def test_no_duplicate_hypotheses(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent._maybe_generate_hypothesis({"success": True, "output": "port 80 found"})
        agent._maybe_generate_hypothesis({"success": True, "output": "port 80 open"})
        assert len(agent.hypotheses) == 1

    def test_redis_hypothesis(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent._maybe_generate_hypothesis({"success": True, "output": "port 6379 open"})
        assert any("Redis" in h.description for h in agent.hypotheses)

    def test_mongodb_hypothesis(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent._maybe_generate_hypothesis({"success": True, "output": "port 27017 found"})
        assert any("MongoDB" in h.description for h in agent.hypotheses)

    def test_no_hypothesis_for_unmatched_output(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent._maybe_generate_hypothesis({"success": True, "output": "everything is fine"})
        assert agent.hypotheses == []


# ---------------------------------------------------------------------------
# Unit: Tool functions
# ---------------------------------------------------------------------------


class TestToolPortScan:
    @patch("tools.omni_scan.run_scan", create=True)
    def test_tries_omni_scan_fallback(self, mock_run):
        mock_run.return_value = "port results"
        result = _tool_port_scan("test.com")
        assert result["success"] is True
        assert result["output"] == "port results"

    @patch("tools.omni_scan.run_scan", side_effect=ImportError("no module"), create=True)
    def test_handles_no_tools(self, mock_run):
        result = _tool_port_scan("test.com")
        assert result["success"] is False


class TestToolWebRecon:
    @patch("tools.omni_scan.run_scan", create=True)
    def test_calls_omni_scan(self, mock_run):
        mock_run.return_value = "web results"
        result = _tool_web_recon("example.com")
        assert result["success"] is True
        mock_run.assert_called_with("example.com", scan_type="web")


class TestToolSearchCve:
    @patch("tools.nvd_cve.search_cve", create=True)
    def test_calls_nvd(self, mock_search):
        mock_search.return_value = ["CVE-2021-1234"]
        result = _tool_search_cve("apache", "2.4.49")
        assert result["success"] is True
        mock_search.assert_called_with("apache 2.4.49")

    @patch("tools.nvd_cve.search_cve", side_effect=Exception("API down"), create=True)
    def test_handles_error(self, mock_search):
        result = _tool_search_cve("nginx")
        assert result["success"] is False


# ---------------------------------------------------------------------------
# Integration: Tool definitions consistency
# ---------------------------------------------------------------------------


class TestToolDefinitions:
    def test_all_tools_have_handler_names(self):
        for t in AVAILABLE_TOOLS:
            assert "handler_name" in t, f"Missing handler_name for {t['name']}"
            assert isinstance(t["handler_name"], str)

    def test_handler_names_resolve(self):
        import sys

        module = sys.modules["elengenix.agent.vuln_agent"]
        for t in AVAILABLE_TOOLS:
            handler = getattr(module, t["handler_name"], None)
            assert callable(handler), f"handler {t['handler_name']} not callable"

    def test_tools_have_required_fields(self):
        for t in AVAILABLE_TOOLS:
            assert "name" in t
            assert "description" in t
            assert "parameters" in t
            assert "properties" in t["parameters"]
            assert "required" in t["parameters"]


# ---------------------------------------------------------------------------
# Integration: VulnReport generation
# ---------------------------------------------------------------------------


class TestVulnAgentReport:
    def test_report_includes_findings(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent.findings.append(Finding(title="XSS", description="x", severity="high", target="x"))
        report = agent._generate_report()
        assert len(report.findings) == 1
        assert report.findings[0].title == "XSS"

    def test_report_includes_profile(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent.profile["open_ports"] = [22, 80, 443]
        agent.profile["services"] = {"ssh": "OpenSSH_8.0"}
        report = agent._generate_report()
        assert 80 in report.open_ports
        assert report.services["ssh"] == "OpenSSH_8.0"

    def test_report_respects_step_count(self):
        agent = VulnAgent(client=MagicMock(), target="x")
        agent.step = 7
        report = agent._generate_report()
        assert report.total_steps == 7

    def test_report_saves_to_disk(self, tmp_path):
        agent = VulnAgent(client=MagicMock(), target="test-target", report_dir=tmp_path)
        report = agent._generate_report()
        # Should have created a JSON file
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) >= 1
        assert json_files[0].stat().st_size > 0

    def test_report_to_dict_structure(self):
        report = VulnReport(
            target="x",
            scan_duration=10.5,
            total_steps=3,
            findings=[Finding(title="SQLi", description="injection", severity="critical", target="x")],
            open_ports=[3306],
            services={"mysql": "8.0"},
            recommendations=["patch mysql"],
        )
        d = report.to_dict()
        assert d["target"] == "x"
        assert d["scan_duration_seconds"] == 10.5
        assert d["total_steps"] == 3
        assert len(d["findings"]) == 1
        assert d["findings"][0]["severity"] == "critical"
        assert d["open_ports"] == [3306]
        assert d["recommendations"] == ["patch mysql"]


# ---------------------------------------------------------------------------
# Integration: Full hunt with mock orchestration
# ---------------------------------------------------------------------------


class TestVulnAgentFullHunt:
    def test_multi_tool_hunt(self):
        """Full multi-step hunt: recon → port scan → conclude."""
        responses = [
            'Reasoning: initial recon\n\n```json\n{"tool": "analyze_target", "arguments": {"target": "x"}}\n```',
            'Reasoning: scan ports\n\n```json\n{"tool": "port_scan", "arguments": {"target": "x", "ports": "common"}}\n```',
            '{"conclude": true, "summary": "found 2 open ports"}',
        ]
        client = MockClient(responses)
        agent = VulnAgent(client=client, target="x", max_steps=10)

        with (
            patch("elengenix.agent.vuln_agent._tool_analyze_target", return_value={"success": True, "output": "domain: x, IP: 1.2.3.4"}),
            patch("elengenix.agent.vuln_agent._tool_port_scan", return_value={"success": True, "output": "22/tcp open ssh\n80/tcp open http"}),
        ):
            report = agent.hunt()

        assert report.total_steps == 3
        assert len(agent.scan_history) == 2
        assert agent.scan_history[0].tool == "analyze_target"
        assert agent.scan_history[1].tool == "port_scan"
        assert "2 open ports" in report.summary
        assert client.call_count == 3

    def test_hypothesis_generated_during_hunt(self):
        """Hypotheses get created during multi-step hunt."""
        responses = [
            '{"tool": "port_scan", "arguments": {"target": "x"}}',
            '{"conclude": true, "summary": "done"}',
        ]
        client = MockClient(responses)
        agent = VulnAgent(client=client, target="x", max_steps=5)

        with patch("elengenix.agent.vuln_agent._tool_port_scan", return_value={"success": True, "output": "port 80 open http\nport 6379 open redis"}):
            report = agent.hunt()

        assert len(agent.hypotheses) >= 1
        hypotheses_desc = [h.description for h in agent.hypotheses]
        assert any("HTTP" in h for h in hypotheses_desc)
        assert any("Redis" in h for h in hypotheses_desc)

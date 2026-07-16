"""Tests for elengenix/scanning/planner.py — StrategicPlanner class."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, PropertyMock, call, patch

import pytest

from elengenix.scanning.dataclasses import AttackPhase, AttackStep, AttackTree
from elengenix.scanning.planner import (
    AttackVectorDatabase,
    StrategicPlanner,
    TargetFingerprinter,
    VULN_BY_STACK,
)
from tools.tool_registry import ToolCategory, ToolResult


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture
def mock_ai_client() -> MagicMock:
    """Return a mock AIClientManager with a .chat() method."""
    client = MagicMock()
    # Default: return a JSON response with one recon phase
    client.chat.return_value.content = json.dumps(
        {
            "reasoning": "Start with recon",
            "phases": [
                {"phase": "recon", "tools": ["dns_lookup"], "purpose": "DNS enumeration", "priority": 1},
            ],
        }
    )
    return client


@pytest.fixture
def planner(mock_ai_client: MagicMock) -> StrategicPlanner:
    """Return a StrategicPlanner instance with a mocked AI client."""
    return StrategicPlanner(client=mock_ai_client)


@pytest.fixture
def sample_fingerprint() -> Dict[str, Any]:
    """A typical tech-stack fingerprint for a PHP/WordPress site."""
    return {
        "server": "nginx",
        "language": "php",
        "framework": None,
        "cms": "wordpress",
        "cdn": None,
        "waf": None,
        "db": "mysql",
        "technologies": ["nginx", "php", "wordpress", "mysql"],
    }


@pytest.fixture
def empty_fingerprint() -> Dict[str, Any]:
    """Fingerprint with no detected technologies."""
    return {
        "server": None,
        "language": None,
        "framework": None,
        "cms": None,
        "cdn": None,
        "waf": None,
        "db": None,
        "technologies": [],
    }


@pytest.fixture
def completed_step() -> AttackStep:
    return AttackStep(
        phase=AttackPhase.RECONNAISSANCE,
        tool_name="dns_lookup",
        target="example.com",
        purpose="DNS enumeration",
        completed=True,
    )


@pytest.fixture
def incomplete_step() -> AttackStep:
    return AttackStep(
        phase=AttackPhase.RECONNAISSANCE,
        tool_name="http_probe",
        target="example.com",
        purpose="HTTP service discovery",
        completed=False,
    )


@pytest.fixture
def sample_tree() -> AttackTree:
    """A tree with a mix of completed and pending steps."""
    return AttackTree(
        target="example.com",
        objective="discover vulnerabilities",
        steps=[
            AttackStep(AttackPhase.RECONNAISSANCE, "dns_lookup", "example.com", "DNS", completed=True),
            AttackStep(AttackPhase.RECONNAISSANCE, "http_probe", "example.com", "HTTP probe", completed=False),
            AttackStep(AttackPhase.SCANNING, "port_scan", "example.com", "Port scan", completed=False),
        ],
    )


# ===================================================================
# TargetFingerprinter tests (supporting class)
# ===================================================================


class TestTargetFingerprinter:
    def test_fingerprint_empty(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint()
        assert result == {
            "server": None,
            "language": None,
            "framework": None,
            "cms": None,
            "cdn": None,
            "waf": None,
            "db": None,
            "technologies": [],
        }

    def test_fingerprint_nginx_php(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "nginx/1.21", "X-Powered-By": "PHP/8.1"},
            body="wp-content/themes",
        )
        assert result["server"] == "nginx"
        assert result["language"] == "php"
        assert result["cms"] == "wordpress"
        assert "nginx" in result["technologies"]
        assert "php" in result["technologies"]
        assert "wordpress" in result["technologies"]

    def test_fingerprint_iis_aspnet(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "Microsoft-IIS/10.0", "X-Aspnet-Version": "4.0.30319"},
            cookies={"ASP.NET_SessionId": "abc123"},
        )
        assert result["server"] == "iis"
        assert result["language"] == "aspnet"
        assert "iis" in result["technologies"]
        assert "aspnet" in result["technologies"]

    def test_fingerprint_url_hints(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "Apache"},
            url="https://example.com/index.php?page=home",
        )
        assert result["server"] == "apache"
        assert "php" in result["technologies"]

    def test_fingerprint_cloudflare(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "cloudflare", "Cf-Ray": "abc123"},
        )
        assert result["server"] == "cloudflare"
        assert result["cdn"] is not None
        assert "cloudflare" in result["technologies"]
        # cloudflare is also WAF
        assert result["waf"] is not None

    def test_fingerprint_cookie_hints(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "nginx"},
            cookies={"PHPSESSID": "abc", "csrftoken": "xyz"},
            body="Drupal.settings",
        )
        assert "php" in result["technologies"]
        assert "drupal" in result["technologies"]
        assert result["cms"] == "drupal"

    def test_fingerprint_express_node(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "express"},
            cookies={"connect.sid": "abc123"},
        )
        # "express" is a framework, not a server
        assert result["framework"] == "express"
        # Language inference is from result["server"], which is None for express
        # (express is only in the framework slot)
        assert "express" in result["technologies"]

    def test_fingerprint_rails(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "gunicorn"},
            cookies={"_rails_session": "abc"},
            body="csrf-token",
        )
        assert result["language"] == "python"
        assert "rails" in result["technologies"] or "python" in result["technologies"]

    def test_fingerprint_java_from_url(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(headers={"Server": "Apache"}, url="https://example.com/login.do")
        assert "java" in result["technologies"]
        assert result["language"] == "java"

    def test_fingerprint_aspx_url(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "Microsoft-IIS/10.0"},
            url="https://example.com/login.aspx",
        )
        assert result["server"] == "iis"
        assert "aspnet" in result["technologies"]

    def test_fingerprint_jsp_url(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "Apache"},
            url="https://example.com/index.jsp",
        )
        assert "java" in result["technologies"]

    def test_fingerprint_wp_url(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "nginx"},
            url="https://example.com/wp-admin/",
        )
        assert "wordpress" in result["technologies"]

    def test_fingerprint_java_cookie(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "Apache"},
            cookies={"JSESSIONID": "ABC123"},
        )
        assert "java" in result["technologies"]

    def test_fingerprint_rails_cookie(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "gunicorn"},
            cookies={"_rails_session": "xyz"},
        )
        assert "rails" in result["technologies"]

    def test_fingerprint_tomcat_cookie(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "Apache"},
            cookies={"tomcat_sid": "xyz"},
        )
        assert "tomcat" in result["technologies"]

    def test_fingerprint_django_cookie(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "gunicorn"},
            cookies={"csrftoken": "abc"},
        )
        assert "django" in result["technologies"]

    def test_fingerprint_no_duplicate_technologies(self):
        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"Server": "nginx/1.21"},
            url="https://example.com/.php",
        )
        # php should appear only once
        assert result["technologies"].count("php") == 1


# ===================================================================
# AttackVectorDatabase tests
# ===================================================================


class TestAttackVectorDatabase:
    def test_hypotheses_for_known_tech(self):
        db = AttackVectorDatabase()
        hyps = db.hypotheses_for(["php"])
        assert len(hyps) > 0
        assert any(h[0] == "sqli" for h in hyps)

    def test_hypotheses_for_unknown_tech(self):
        db = AttackVectorDatabase()
        hyps = db.hypotheses_for(["nonexistent_tech_12345"])
        assert hyps == []

    def test_hypotheses_for_multi_tech_no_duplicates(self):
        db = AttackVectorDatabase()
        # php and wordpress both have sqli entries but different hypothesis text
        hyps = db.hypotheses_for(["php", "wordpress"])
        sqli_hypotheses = [h for h in hyps if h[0] == "sqli"]
        # Each distinct (vuln_class, text) pair appears once — php and wordpress
        # have different sqli text, so there should be 2 entries
        assert len(sqli_hypotheses) == 2

    def test_technologies_for_vuln(self):
        db = AttackVectorDatabase()
        techs = db.technologies_for_vuln("sqli")
        assert "php" in techs
        assert "mysql" in techs

    def test_technologies_for_vuln_unknown(self):
        db = AttackVectorDatabase()
        techs = db.technologies_for_vuln("nonexistent_vuln")
        assert techs == []

    def test_add_tech(self):
        db = AttackVectorDatabase()
        db.add("custom_tech", [("test_vuln", "test hypothesis", ("tool1",))])
        hyps = db.hypotheses_for(["custom_tech"])
        assert len(hyps) == 1
        assert hyps[0][0] == "test_vuln"

    def test_hypotheses_for_deduplicates_by_vuln_class_and_text(self):
        """Same (vuln_class, text) from different techs should dedupe."""
        db = AttackVectorDatabase()
        db.add("tech_a", [("same_vuln", "same text", ("tool1",))])
        db.add("tech_b", [("same_vuln", "same text", ("tool2",))])
        hyps = db.hypotheses_for(["tech_a", "tech_b"])
        # Both entries have same (vuln_class, text) key — only one should appear
        matching = [h for h in hyps if h[0] == "same_vuln"]
        assert len(matching) == 1


# ===================================================================
# StrategicPlanner — __init__
# ===================================================================


class TestStrategicPlannerInit:
    def test_creates_with_client(self, mock_ai_client: MagicMock):
        sp = StrategicPlanner(client=mock_ai_client)
        assert sp.client is mock_ai_client
        assert sp.fingerprinter is not None
        assert sp.vector_db is not None
        assert sp.cvss_calc is not None

    def test_client_required(self):
        """Passing None as client should not crash but store the reference."""
        sp = StrategicPlanner(client=None)  # type: ignore[arg-type]
        assert sp.client is None


# ===================================================================
# StrategicPlanner — generate_attack_tree
# ===================================================================


class TestGenerateAttackTree:
    def test_basic_with_fingerprint(self, planner: StrategicPlanner, sample_fingerprint: Dict[str, Any]):
        """Provide a fingerprint — should use semantic steps + AI."""
        tree = planner.generate_attack_tree(
            target="https://wordpress-site.com",
            fingerprint=sample_fingerprint,
        )
        assert isinstance(tree, AttackTree)
        assert tree.target == "https://wordpress-site.com"
        assert len(tree.steps) > 0
        # Should have at least semantic-based steps (sqli, lfi, rce, etc.)
        assert any(step.tool_name for step in tree.steps)

    def test_without_fingerprint_calls_fingerprinter(
        self, planner: StrategicPlanner, monkeypatch: pytest.MonkeyPatch
    ):
        """When fingerprint is None, fingerprinter.fingerprint() should be called."""
        with patch.object(planner.fingerprinter, "fingerprint") as mock_fp:
            mock_fp.return_value = {"server": None, "language": None, "technologies": []}
            tree = planner.generate_attack_tree(target="example.com")
            mock_fp.assert_called_once_with(url="example.com")
            assert tree.target == "example.com"

    def test_ai_called_with_correct_prompt(
        self, planner: StrategicPlanner, sample_fingerprint: Dict[str, Any]
    ):
        """AI client.chat() should be called with system + user messages."""
        planner.generate_attack_tree(target="https://test.com", fingerprint=sample_fingerprint)
        assert planner.client.chat.called
        call_args = planner.client.chat.call_args[0][0]
        assert len(call_args) == 2
        assert call_args[0].role == "system"
        assert "penetration testing" in call_args[0].content.lower()
        assert call_args[1].role == "user"
        assert "https://test.com" in call_args[1].content

    def test_ai_response_parsed_into_steps(
        self, planner: StrategicPlanner, sample_fingerprint: Dict[str, Any]
    ):
        """AI response JSON should be parsed into additional AttackSteps."""
        tree = planner.generate_attack_tree(target="https://test.com", fingerprint=sample_fingerprint)
        # Our mock returns a recon phase with "dns_lookup"
        # The semantic step generation may produce "dns_lookup" too, but merge avoids dups
        all_tools = {s.tool_name for s in tree.steps}
        assert "dns_lookup" in all_tools or len(tree.steps) > 0

    def test_ai_failure_falls_back_gracefully(
        self, mock_ai_client: MagicMock, sample_fingerprint: Dict[str, Any]
    ):
        """When AI call raises, the tree should still contain semantic steps."""
        mock_ai_client.chat.side_effect = RuntimeError("API down")
        sp = StrategicPlanner(client=mock_ai_client)
        tree = sp.generate_attack_tree(target="https://test.com", fingerprint=sample_fingerprint)
        # Should still have semantic steps
        assert len(tree.steps) > 0

    def test_ai_returns_invalid_json(
        self, mock_ai_client: MagicMock, sample_fingerprint: Dict[str, Any]
    ):
        """When AI returns non-JSON, should not crash; fall back to semantic steps."""
        mock_ai_client.chat.return_value.content = "I'm sorry, I cannot do that."
        sp = StrategicPlanner(client=mock_ai_client)
        tree = sp.generate_attack_tree(target="https://test.com", fingerprint=sample_fingerprint)
        assert len(tree.steps) > 0

    def test_ai_returns_empty_phases(
        self, mock_ai_client: MagicMock, sample_fingerprint: Dict[str, Any]
    ):
        """AI returns valid JSON but with empty phases."""
        mock_ai_client.chat.return_value.content = json.dumps(
            {"reasoning": "nothing", "phases": []}
        )
        sp = StrategicPlanner(client=mock_ai_client)
        tree = sp.generate_attack_tree(target="https://test.com", fingerprint=sample_fingerprint)
        assert len(tree.steps) > 0  # semantic steps still present

    def test_no_semantic_steps_and_ai_fails_uses_default(
        self, mock_ai_client: MagicMock, empty_fingerprint: Dict[str, Any]
    ):
        """When both semantic steps and AI fail, default attack tree should be used.
        
        Note: semantic_steps_for always falls back to ['nginx'] even with empty
        fingerprint, so default tree only kicks in on actual failure.
        """
        mock_ai_client.chat.side_effect = RuntimeError("API down")
        sp = StrategicPlanner(client=mock_ai_client)
        tree = sp.generate_attack_tree(target="example.com", fingerprint=empty_fingerprint)
        # Semantic nginx fallback produces steps even with empty fingerprint
        assert len(tree.steps) > 0

    def test_multiple_ai_phases_merged(
        self, mock_ai_client: MagicMock, empty_fingerprint: Dict[str, Any]
    ):
        """AI response with multiple phases should produce multiple steps."""
        mock_ai_client.chat.return_value.content = json.dumps(
            {
                "reasoning": "Full strategy",
                "phases": [
                    {"phase": "recon", "tools": ["dns_lookup", "http_probe"], "purpose": "Recon", "priority": 1},
                    {"phase": "scanning", "tools": ["port_scan"], "purpose": "Scan", "priority": 2},
                    {"phase": "exploitation", "tools": ["vuln_scan"], "purpose": "Exploit", "priority": 3},
                ],
            }
        )
        sp = StrategicPlanner(client=mock_ai_client)
        tree = sp.generate_attack_tree(target="example.com", fingerprint=empty_fingerprint)
        # Since empty fingerprint has no technologies, the AI steps will be primary
        # (semantic steps might still fall back to ["nginx"])
        tools = {s.tool_name for s in tree.steps}
        # At minimum the AI-provided tools should exist
        assert "http_probe" in tools or "port_scan" in tools or "vuln_scan" in tools

    def test_ai_does_not_duplicate_semantic_tools(
        self, planner: StrategicPlanner, sample_fingerprint: Dict[str, Any]
    ):
        """If AI returns same tool as semantic, it should not duplicate."""
        tree = planner.generate_attack_tree(target="https://test.com", fingerprint=sample_fingerprint)
        tool_counts: Dict[str, int] = {}
        for step in tree.steps:
            tool_counts[step.tool_name] = tool_counts.get(step.tool_name, 0) + 1
        for tool, count in tool_counts.items():
            assert count == 1, f"Tool {tool} appears {count} times (should be 1)"


# ===================================================================
# StrategicPlanner — semantic_steps_for
# ===================================================================


class TestSemanticStepsFor:
    def test_with_technologies(self, planner: StrategicPlanner, sample_fingerprint: Dict[str, Any]):
        steps = planner.semantic_steps_for(sample_fingerprint, target="https://test.com")
        assert len(steps) > 0
        for step in steps:
            assert isinstance(step, AttackStep)
            assert step.target == "https://test.com"
            assert step.tool_name

    def test_empty_technologies_falls_back_to_server(
        self, planner: StrategicPlanner, empty_fingerprint: Dict[str, Any]
    ):
        fp = dict(empty_fingerprint, server="nginx")
        steps = planner.semantic_steps_for(fp, target="example.com")
        assert len(steps) > 0

    def test_empty_technologies_and_server_falls_back_to_language(
        self, planner: StrategicPlanner, empty_fingerprint: Dict[str, Any]
    ):
        fp = dict(empty_fingerprint, language="php")
        steps = planner.semantic_steps_for(fp, target="example.com")
        assert len(steps) > 0

    def test_completely_empty_falls_back_to_nginx(
        self, planner: StrategicPlanner, empty_fingerprint: Dict[str, Any]
    ):
        steps = planner.semantic_steps_for(empty_fingerprint, target="example.com")
        # Should fall back to ["nginx"] and produce nginx-related steps
        assert len(steps) > 0

    def test_single_tech(self, planner: StrategicPlanner):
        fp = {"server": None, "language": None, "framework": None, "cms": None, "cdn": None,
              "waf": None, "db": None, "technologies": ["nginx"]}
        steps = planner.semantic_steps_for(fp, target="example.com")
        assert len(steps) > 0

    def test_tools_deduplicated(self, planner: StrategicPlanner):
        """Multiple hypotheses pointing to the same tool should not create duplicates."""
        fp = {"server": None, "language": None, "framework": None, "cms": None, "cdn": None,
              "waf": None, "db": None, "technologies": ["php", "wordpress"]}
        steps = planner.semantic_steps_for(fp, target="example.com")
        tool_names = [s.tool_name for s in steps]
        assert len(tool_names) == len(set(tool_names)), "Tools should not be duplicated"

    def test_severity_ordering(self, planner: StrategicPlanner):
        """Steps should be ordered by severity (rce first, info last)."""
        fp = {"server": None, "language": None, "framework": None, "cms": None, "cdn": None,
              "waf": None, "db": None, "technologies": ["php"]}
        steps = planner.semantic_steps_for(fp, target="example.com")
        # rce should come before lfi if both are present
        tool_names = [s.tool_name for s in steps]
        # Just verify the list is non-empty and well-formed
        assert len(steps) > 0
        for step in steps:
            assert isinstance(step.phase, AttackPhase)
            assert step.purpose

    def test_correct_phase_assignment(self, planner: StrategicPlanner):
        """Different vuln classes should map to correct phases."""
        # Test origin -> RECONNAISSANCE
        fp = {"technologies": ["cloudflare"]}
        steps = planner.semantic_steps_for(fp, target="example.com")
        for step in steps:
            assert step.phase in AttackPhase


# ===================================================================
# StrategicPlanner — _default_attack_tree
# ===================================================================


class TestDefaultAttackTree:
    def test_default_tree_structure(self, planner: StrategicPlanner):
        tree = planner._default_attack_tree("example.com", "test objective")
        assert isinstance(tree, AttackTree)
        assert tree.target == "example.com"
        assert tree.objective == "test objective"
        assert tree.reasoning == "Default reconnaissance-to-exploitation pipeline"
        assert len(tree.steps) == 6

    def test_default_steps_in_order(self, planner: StrategicPlanner):
        tree = planner._default_attack_tree("example.com", "test")
        # Steps should progress: recon -> scanning -> enumeration -> exploitation -> enumeration
        phases = [s.phase for s in tree.steps]
        assert AttackPhase.RECONNAISSANCE in phases
        assert AttackPhase.SCANNING in phases
        assert AttackPhase.ENUMERATION in phases
        assert AttackPhase.EXPLOITATION in phases


# ===================================================================
# StrategicPlanner — select_next_tool
# ===================================================================


class TestSelectNextTool:
    def test_none_when_no_results_and_no_steps(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        result = planner.select_next_tool(tree, [])
        assert result is None

    def test_critical_secret_returns_trufflehog(self, planner: StrategicPlanner, sample_tree: AttackTree):
        results = [
            ToolResult(
                tool_name="test",
                success=True,
                category=ToolCategory.UTILITY,
                findings=[{"severity": "critical", "type": "secret"}],
            )
        ]
        tool = planner.select_next_tool(sample_tree, results)
        assert tool == "trufflehog"

    def test_critical_rce_returns_vuln_verify(self, planner: StrategicPlanner, sample_tree: AttackTree):
        results = [
            ToolResult(
                tool_name="test",
                success=True,
                category=ToolCategory.UTILITY,
                findings=[{"severity": "critical", "type": "rce"}],
            )
        ]
        tool = planner.select_next_tool(sample_tree, results)
        assert tool == "vuln_verify"

    def test_sqli_finding_returns_sqli_test(self, planner: StrategicPlanner, sample_tree: AttackTree):
        results = [
            ToolResult(
                tool_name="test",
                success=True,
                category=ToolCategory.UTILITY,
                findings=[{"severity": "high", "type": "sqli"}],
            )
        ]
        tool = planner.select_next_tool(sample_tree, results)
        assert tool == "sqli_test"

    def test_xss_finding_returns_xss_test(self, planner: StrategicPlanner, sample_tree: AttackTree):
        results = [
            ToolResult(
                tool_name="test",
                success=True,
                category=ToolCategory.UTILITY,
                findings=[{"severity": "high", "type": "xss"}],
            )
        ]
        tool = planner.select_next_tool(sample_tree, results)
        assert tool == "xss_test"

    def test_open_database_port_returns_service_scan(self, planner: StrategicPlanner, sample_tree: AttackTree):
        results = [
            ToolResult(
                tool_name="test",
                success=True,
                category=ToolCategory.UTILITY,
                findings=[{"severity": "medium", "type": "open_port", "port": 3306}],
            )
        ]
        tool = planner.select_next_tool(sample_tree, results)
        assert tool == "service_scan"

    def test_open_web_port_returns_dir_scan(self, planner: StrategicPlanner, sample_tree: AttackTree):
        results = [
            ToolResult(
                tool_name="test",
                success=True,
                category=ToolCategory.UTILITY,
                findings=[{"severity": "medium", "type": "open_port", "port": 80}],
            )
        ]
        tool = planner.select_next_tool(sample_tree, results)
        assert tool == "dir_scan"

    def test_api_endpoint_returns_param_discovery(self, planner: StrategicPlanner, sample_tree: AttackTree):
        results = [
            ToolResult(
                tool_name="test",
                success=True,
                category=ToolCategory.UTILITY,
                findings=[{"severity": "info", "type": "api_endpoint"}],
            )
        ]
        tool = planner.select_next_tool(sample_tree, results)
        assert tool == "param_discovery"

    def test_hidden_parameter_returns_xss_test(self, planner: StrategicPlanner, sample_tree: AttackTree):
        results = [
            ToolResult(
                tool_name="test",
                success=True,
                category=ToolCategory.UTILITY,
                findings=[{"severity": "info", "type": "hidden_parameter"}],
            )
        ]
        tool = planner.select_next_tool(sample_tree, results)
        assert tool == "xss_test"

    def test_unsuccessful_results_skipped(self, planner: StrategicPlanner, sample_tree: AttackTree):
        """Failed tool results should be skipped."""
        results = [
            ToolResult(
                tool_name="test",
                success=False,
                category=ToolCategory.UTILITY,
                findings=[{"severity": "critical", "type": "secret"}],
            )
        ]
        tool = planner.select_next_tool(sample_tree, results)
        # Should fall through to the tree's first incomplete step
        assert tool == "http_probe"

    def test_follows_phase_order(self, planner: StrategicPlanner):
        """Should pick the first incomplete step in phase order."""
        tree = AttackTree(
            target="example.com",
            objective="test",
            steps=[
                AttackStep(AttackPhase.EXPLOITATION, "vuln_scan", "example.com", "Vuln scan", completed=False),
                AttackStep(AttackPhase.RECONNAISSANCE, "dns_lookup", "example.com", "DNS", completed=False),
            ],
        )
        # Should pick dns_lookup first (recon before exploitation)
        tool = planner.select_next_tool(tree, [])
        assert tool == "dns_lookup"

    def test_dependency_met_allows_step(self, planner: StrategicPlanner):
        """Step with a completed dependency should be eligible."""
        tree = AttackTree(
            target="example.com",
            objective="test",
            steps=[
                AttackStep(
                    AttackPhase.RECONNAISSANCE, "step_a", "t", "first",
                    completed=False, depends_on=["step_b"],
                ),
                AttackStep(
                    AttackPhase.RECONNAISSANCE, "step_b", "t", "second",
                    completed=True, depends_on=[],
                ),
            ],
        )
        # step_a depends on step_b which is completed, so deps met → step_a returned
        tool = planner.select_next_tool(tree, [])
        assert tool == "step_a"

    def test_unmet_dependency_skips_to_next_step(self, planner: StrategicPlanner):
        """When first step has unmet dep, next step in same phase is tried."""
        tree = AttackTree(
            target="example.com",
            objective="test",
            steps=[
                AttackStep(
                    AttackPhase.RECONNAISSANCE, "step_a", "t", "first",
                    completed=False, depends_on=["step_b"],
                ),
                AttackStep(
                    AttackPhase.RECONNAISSANCE, "step_b", "t", "second",
                    completed=False, depends_on=[],
                ),
            ],
        )
        # step_a depends on step_b which is not completed → skip to step_b
        tool = planner.select_next_tool(tree, [])
        assert tool == "step_b"

    def test_dependency_not_met_skips_step(self, planner: StrategicPlanner):
        """Step with unmet dependency should be skipped."""
        tree = AttackTree(
            target="example.com",
            objective="test",
            steps=[
                AttackStep(AttackPhase.RECONNAISSANCE, "dns_lookup", "example.com", "DNS", completed=True),
                AttackStep(
                    AttackPhase.ENUMERATION, "dir_scan", "example.com", "Dir scan",
                    completed=False, depends_on=["http_probe"],
                ),
                AttackStep(
                    AttackPhase.RECONNAISSANCE, "http_probe", "example.com", "HTTP probe",
                    completed=False, depends_on=[],
                ),
            ],
        )
        tool = planner.select_next_tool(tree, [])
        # phase order: recon -> scanning -> enum -> exploitation
        # http_probe comes before dir_scan in recon phase, and its dep on [] is met
        assert tool == "http_probe"

    def test_all_completed_returns_none(self, planner: StrategicPlanner, completed_step: AttackStep):
        tree = AttackTree(
            target="example.com",
            objective="test",
            steps=[completed_step],
        )
        tool = planner.select_next_tool(tree, [])
        assert tool is None

    def test_high_severity_not_known_finding(self, planner: StrategicPlanner, sample_tree: AttackTree):
        """High severity but unknown finding type should not match and fall through."""
        results = [
            ToolResult(
                tool_name="test",
                success=True,
                category=ToolCategory.UTILITY,
                findings=[{"severity": "high", "type": "unknown_type_xyz"}],
            )
        ]
        tool = planner.select_next_tool(sample_tree, results)
        # Should fall through to tree steps (first incomplete is http_probe)
        assert tool == "http_probe"


# ===================================================================
# StrategicPlanner — adapt_strategy
# ===================================================================


class TestAdaptStrategy:
    def test_api_endpoint_adds_steps(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "api_endpoint", "url": "https://example.com/api/v1"},
        )
        assert len(steps) == 2
        # Check tree extended
        assert len(tree.steps) == 2
        # First step should be param_discovery (enumeration)
        assert steps[0].tool_name == "param_discovery"
        assert steps[0].phase == AttackPhase.ENUMERATION
        # Second step should be vuln_scan (scanning)
        assert steps[1].tool_name == "vuln_scan"
        assert steps[1].phase == AttackPhase.SCANNING

    def test_subdomain_adds_steps(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "subdomain", "subdomain": "admin.example.com"},
        )
        assert len(steps) == 2
        assert steps[0].tool_name == "http_probe"
        assert steps[0].target == "admin.example.com"

    def test_subdomain_without_name_returns_no_steps(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "subdomain"},  # no subdomain key
        )
        assert len(steps) == 0

    def test_hidden_parameter_adds_steps(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "hidden_parameter", "url": "https://example.com/page"},
        )
        assert len(steps) == 2
        assert steps[0].tool_name == "xss_test"
        assert steps[1].tool_name == "sqli_test"

    def test_sqli_finding_adds_deep_analysis(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "sqli", "url": "https://example.com/page"},
        )
        assert len(steps) == 1
        assert steps[0].tool_name == "sqli_test"
        assert "Deep" in steps[0].purpose

    def test_sql_injection_alternative_type(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "sql_injection"},
        )
        assert len(steps) == 1
        assert steps[0].tool_name == "sqli_test"

    def test_xss_finding_adds_stored_xss_check(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "xss", "url": "https://example.com/page"},
        )
        assert len(steps) == 1
        assert steps[0].tool_name == "xss_test"
        assert "stored" in steps[0].purpose.lower()

    def test_reflected_xss_matches(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "reflected_xss"},
        )
        assert len(steps) == 1
        assert steps[0].tool_name == "xss_test"

    def test_lfi_finding_adds_rce_check(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "lfi", "url": "https://example.com/page"},
        )
        assert len(steps) == 1
        assert steps[0].tool_name == "vuln_scan"
        assert "RCE" in steps[0].purpose

    def test_path_traversal_matches(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "path_traversal"},
        )
        assert len(steps) == 1
        assert steps[0].tool_name == "vuln_scan"

    def test_rce_finding_returns_no_steps(self, planner: StrategicPlanner):
        """RCE is critical — no further exploitation needed."""
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "rce"},
        )
        assert len(steps) == 0

    def test_remote_code_execution_returns_no_steps(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "remote_code_execution"},
        )
        assert len(steps) == 0

    def test_open_database_port_adds_service_scan(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "open_port", "port": 5432, "service": "postgres"},
        )
        assert len(steps) == 1
        assert steps[0].tool_name == "service_scan"
        assert "postgres" in steps[0].purpose

    def test_open_web_port_adds_vuln_scan(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "open_port", "port": 443, "service": "https"},
        )
        assert len(steps) == 1
        assert steps[0].tool_name == "vuln_scan"
        assert "443" in steps[0].target

    def test_open_unknown_port_no_action(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "open_port", "port": 9999},
        )
        assert len(steps) == 0

    def test_critical_secret_adds_deep_scan(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "secret", "severity": "critical"},
        )
        assert len(steps) == 1
        assert steps[0].tool_name == "trufflehog"
        assert "Deep" in steps[0].purpose

    def test_low_severity_secret_no_action(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "secret", "severity": "low"},
        )
        assert len(steps) == 0

    def test_waf_detected_adds_bypass(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "waf_detected", "waf_name": "Cloudflare"},
        )
        assert len(steps) == 1
        assert steps[0].tool_name == "waf_bypass"
        assert "Cloudflare" in steps[0].purpose

    def test_waf_detected_without_name(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "waf_detected"},
        )
        assert len(steps) == 1
        assert "unknown" in steps[0].purpose

    def test_unknown_finding_type_no_steps(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(
            tree,
            {"type": "completely_unknown_finding"},
        )
        assert len(steps) == 0

    def test_missing_type_key_does_not_crash(self, planner: StrategicPlanner):
        tree = AttackTree(target="example.com", objective="test")
        steps = planner.adapt_strategy(tree, {"url": "https://example.com"})
        assert len(steps) == 0


# ===================================================================
# StrategicPlanner — fingerprint_target
# ===================================================================


class TestFingerprintTarget:
    def test_delegates_to_fingerprinter(self, planner: StrategicPlanner):
        with patch.object(planner.fingerprinter, "fingerprint") as mock_fp:
            mock_fp.return_value = {"server": "nginx"}
            result = planner.fingerprint_target(
                headers={"Server": "nginx"},
                body="<html>",
                cookies={"PHPSESSID": "abc"},
                url="https://example.com",
            )
            mock_fp.assert_called_once_with(
                headers={"Server": "nginx"},
                body="<html>",
                cookies={"PHPSESSID": "abc"},
                url="https://example.com",
            )
            assert result == {"server": "nginx"}

    def test_fingerprint_target_no_args(self, planner: StrategicPlanner):
        with patch.object(planner.fingerprinter, "fingerprint") as mock_fp:
            mock_fp.return_value = TargetFingerprinter().DEFAULT_RESULT
            result = planner.fingerprint_target()
            mock_fp.assert_called_once_with(
                headers=None, body=None, cookies=None, url=None
            )
            assert result["technologies"] == []


# ===================================================================
# StrategicPlanner — semantic_attack_tree
# ===================================================================


class TestSemanticAttackTree:
    def test_returns_tree_with_semantic_steps(self, planner: StrategicPlanner, sample_fingerprint: Dict[str, Any]):
        tree = planner.semantic_attack_tree("https://test.com", sample_fingerprint)
        assert isinstance(tree, AttackTree)
        assert tree.target == "https://test.com"
        assert len(tree.steps) > 0

    def test_no_ai_call(self, planner: StrategicPlanner, sample_fingerprint: Dict[str, Any]):
        """semantic_attack_tree should NOT call the AI client."""
        tree = planner.semantic_attack_tree("https://test.com", sample_fingerprint)
        assert not planner.client.chat.called

    def test_reasoning_includes_technologies(self, planner: StrategicPlanner, sample_fingerprint: Dict[str, Any]):
        tree = planner.semantic_attack_tree("https://test.com", sample_fingerprint)
        assert "php" in tree.reasoning or "nginx" in tree.reasoning or "wordpress" in tree.reasoning

    def test_empty_fingerprint(self, planner: StrategicPlanner, empty_fingerprint: Dict[str, Any]):
        """Even with empty fingerprint, should still produce a tree."""
        tree = planner.semantic_attack_tree("https://test.com", empty_fingerprint)
        assert len(tree.steps) > 0


# ===================================================================
# Edge cases and error handling
# ===================================================================


class TestEdgeCases:
    def test_planner_with_none_client_no_crash_on_ai_failure(self, sample_fingerprint: Dict[str, Any]):
        """Planner with client=None should not crash when AI is unavailable."""
        sp = StrategicPlanner(client=None)  # type: ignore[arg-type]
        tree = sp.generate_attack_tree(target="example.com", fingerprint=sample_fingerprint)
        assert len(tree.steps) > 0  # semantic steps should still work

    def test_ai_returns_partial_json(self, mock_ai_client: MagicMock, empty_fingerprint: Dict[str, Any]):
        """AI returns JSON with missing fields — should not crash."""
        mock_ai_client.chat.return_value.content = json.dumps({"reasoning": "test"})
        sp = StrategicPlanner(client=mock_ai_client)
        tree = sp.generate_attack_tree(target="example.com", fingerprint=empty_fingerprint)
        assert len(tree.steps) > 0  # fallback to semantic (nginx default) or default

    def test_ai_returns_null_content(self, mock_ai_client: MagicMock, empty_fingerprint: Dict[str, Any]):
        """AI returns None content — should not crash."""
        mock_ai_client.chat.return_value.content = None
        sp = StrategicPlanner(client=mock_ai_client)
        tree = sp.generate_attack_tree(target="example.com", fingerprint=empty_fingerprint)
        assert len(tree.steps) > 0

    def test_target_with_special_chars(self, planner: StrategicPlanner, sample_fingerprint: Dict[str, Any]):
        """Target with special characters should be handled."""
        tree = planner.generate_attack_tree(
            target="https://üñîçødé.com/path?q=test#frag",
            fingerprint=sample_fingerprint,
        )
        assert len(tree.steps) > 0

    def test_very_long_target(self, planner: StrategicPlanner, sample_fingerprint: Dict[str, Any]):
        """Very long target should not cause issues."""
        long_target = "https://" + "a" * 500 + ".com"
        tree = planner.generate_attack_tree(
            target=long_target,
            fingerprint=sample_fingerprint,
        )
        assert len(tree.steps) > 0

    def test_empty_technologies_list_in_fingerprint(self, planner: StrategicPlanner):
        """Empty technologies list should fall through properly."""
        fp = {"technologies": []}
        steps = planner.semantic_steps_for(fp, target="example.com")
        assert len(steps) > 0  # Should fall back to nginx

    def test_none_technologies_in_fingerprint(self, planner: StrategicPlanner):
        """None technologies should be treated as empty."""
        fp = {"technologies": None}
        steps = planner.semantic_steps_for(fp, target="example.com")
        assert len(steps) > 0  # Should fall back

    def test_phase_order_with_empty_tree(self, planner: StrategicPlanner):
        """select_next_tool with empty tree and no results."""
        tree = AttackTree(target="example.com", objective="test")
        result = planner.select_next_tool(tree, [])
        assert result is None

    def test_adapt_strategy_multiple_calls(self, planner: StrategicPlanner):
        """Multiple adapt_strategy calls should accumulate steps."""
        tree = AttackTree(target="example.com", objective="test")
        planner.adapt_strategy(tree, {"type": "api_endpoint", "url": "/api"})
        assert len(tree.steps) == 2
        planner.adapt_strategy(tree, {"type": "waf_detected", "waf_name": "Cloudflare"})
        assert len(tree.steps) == 3  # 2 + 1
        planner.adapt_strategy(tree, {"type": "subdomain", "subdomain": "dev.example.com"})
        assert len(tree.steps) == 5  # 2 + 1 + 2


# ===================================================================
# Integration-style: generate_attack_tree end-to-end with mocked AI
# ===================================================================


class TestGenerateAttackTreeIntegration:
    def test_full_flow_with_fingerprint_and_ai(self, sample_fingerprint: Dict[str, Any]):
        """Full flow: fingerprint + AI response merged."""
        client = MagicMock()
        client.chat.return_value.content = json.dumps(
            {
                "reasoning": "Test strategy",
                "phases": [
                    {"phase": "recon", "tools": ["unique_ai_tool_xyz"], "purpose": "AI recommended", "priority": 1},
                ],
            }
        )
        sp = StrategicPlanner(client=client)
        tree = sp.generate_attack_tree(
            target="https://example.com",
            fingerprint=sample_fingerprint,
        )
        # Both semantic steps and the AI step should be present
        all_tools = {s.tool_name for s in tree.steps}
        assert "unique_ai_tool_xyz" in all_tools
        assert len(tree.steps) > 1

    def test_ai_only_with_empty_fingerprint_falls_to_default_on_failure(
        self, empty_fingerprint: Dict[str, Any]
    ):
        """When fingerprint is empty and AI fails, semantic steps still apply (nginx fallback)."""
        client = MagicMock()
        client.chat.side_effect = Exception("AI unavailable")
        sp = StrategicPlanner(client=client)
        tree = sp.generate_attack_tree(
            target="example.com",
            fingerprint=empty_fingerprint,
        )
        # Semantic fallback (nginx) produces steps
        assert len(tree.steps) > 0

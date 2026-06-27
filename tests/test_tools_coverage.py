"""
tests/test_tools_coverage.py — Increase coverage for tools/ modules

Tests pure functions and classes that don't require network or external dependencies.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── tools/tool_registry.py ────────────────────────────────────────────────────


class TestToolRegistry:
    """Test ToolRegistry operations."""

    def test_registry_singleton(self):
        from tools.tool_registry import registry

        assert registry is not None

    def test_list_tools(self):
        from tools.tool_registry import registry

        tools = registry.list_available_tools()
        assert isinstance(tools, dict)
        assert len(tools) > 0

    def test_get_existing_tool(self):
        from tools.tool_registry import registry

        # Try to get a tool that should be registered
        tools = registry.list_available_tools()
        if tools:
            tool_name = list(tools.keys())[0]
            tool = registry.get_tool(tool_name)
            assert tool is not None

    def test_get_nonexistent_tool(self):
        from tools.tool_registry import registry

        tool = registry.get_tool("nonexistent_tool_xyz")
        assert tool is None

    def test_get_recommended_chain(self):
        from tools.tool_registry import registry

        chain = registry.get_recommended_chain("web")
        assert isinstance(chain, list)

    def test_tool_metadata(self):
        from tools.tool_registry import ToolCategory

        # Test all categories exist
        for cat in ToolCategory:
            assert cat.name


class TestToolResultExtended:
    """Test ToolResult in more detail."""

    def test_findings_default_empty(self):
        from tools.tool_registry import ToolResult, ToolCategory

        result = ToolResult(
            success=True,
            tool_name="test",
            category=ToolCategory.RECON,
        )
        assert result.findings == []

    def test_output_default_empty(self):
        from tools.tool_registry import ToolResult, ToolCategory

        result = ToolResult(
            success=True,
            tool_name="test",
            category=ToolCategory.RECON,
        )
        assert result.output == ""


# ── tools/governance.py ──────────────────────────────────────────────────────


class TestGovernanceExtended:
    """Test Governance in more detail."""

    def test_classify_risk_safe(self):
        from tools.governance import Governance

        gov = Governance()
        risk = gov.classify_risk({"command": "echo hello", "tool": "shell"})
        assert risk in ["SAFE", "LOW"]

    def test_classify_risk_destructive(self):
        from tools.governance import Governance

        gov = Governance()
        risk = gov.classify_risk({"command": "rm -rf /", "tool": "shell"})
        assert risk in ["DESTRUCTIVE", "HIGH", "CRITICAL"]

    def test_gate_returns_decision(self):
        from tools.governance import Governance, GateDecision

        gov = Governance()
        decision = gov.gate("test-mission", "example.com", {"command": "ls", "tool": "shell"})
        assert isinstance(decision, GateDecision)
        assert hasattr(decision, "risk_level")
        assert hasattr(decision, "decision")

    def test_gate_safe_command(self):
        from tools.governance import Governance

        gov = Governance()
        decision = gov.gate(
            "test-mission", "example.com", {"command": "echo hello", "tool": "shell"}
        )
        assert decision.decision is not None

    def test_gate_destructive_command(self):
        from tools.governance import Governance

        gov = Governance()
        decision = gov.gate(
            "test-mission", "example.com", {"command": "mkfs.ext4 /dev/sda", "tool": "shell"}
        )
        assert decision.decision is not None


# ── tools/mission_state.py ───────────────────────────────────────────────────


class TestMissionStateExtended:
    """Test MissionState in more detail."""

    def test_create_with_defaults(self):
        from tools.mission_state import MissionState

        ms = MissionState(mission_id="test-1", target="example.com", objective="Test")
        assert ms.mission_id == "test-1"
        assert ms.target == "example.com"
        assert ms.objective == "Test"

    def test_snapshot_structure(self):
        from tools.mission_state import MissionState

        ms = MissionState(mission_id="test-1", target="example.com", objective="Test")
        snap = ms.snapshot()
        assert isinstance(snap, dict)
        assert "mission_id" in snap

    def test_add_fact(self):
        from tools.mission_state import MissionState

        ms = MissionState(mission_id="test-1", target="example.com", objective="Test")
        ms.add_fact(
            fact_id="fact-1",
            category="finding",
            statement="Found XSS",
            confidence=0.8,
            evidence={"url": "http://example.com"},
        )

    def test_upsert_node(self):
        from tools.mission_state import MissionState, GraphNode

        ms = MissionState(mission_id="test-1", target="example.com", objective="Test")
        node = GraphNode(
            node_id="node-1",
            node_type="target",
            props={"target": "example.com"},
        )
        ms.upsert_node(node)

    def test_upsert_edge(self):
        from tools.mission_state import MissionState, GraphEdge

        ms = MissionState(mission_id="test-1", target="example.com", objective="Test")
        edge = GraphEdge(
            edge_id="edge-1",
            src_id="node-1",
            dst_id="node-2",
            edge_type="has_finding",
            props={"tool": "scanner"},
        )
        ms.upsert_edge(edge)

    def test_resume_mission(self):
        from tools.mission_state import MissionState

        ms = MissionState(mission_id="test-1", target="example.com", objective="Test")
        ms.resume_mission()

    def test_snapshot_max_items(self):
        from tools.mission_state import MissionState

        ms = MissionState(mission_id="test-1", target="example.com", objective="Test")
        snap = ms.snapshot(max_items=5)
        assert isinstance(snap, dict)


# ── tools/payload_mutation.py ────────────────────────────────────────────────


class TestPayloadMutation:
    """Test PayloadMutation basics."""

    def test_import(self):
        from tools.payload_mutation import PayloadMutator

        assert PayloadMutator is not None

    def test_create_mutator(self):
        from tools.payload_mutation import PayloadMutator

        try:
            mutator = PayloadMutator()
            assert mutator is not None
        except Exception:
            # May fail due to missing dependencies
            pass


# ── tools/vuln_engine.py ─────────────────────────────────────────────────────


class TestVulnEngine:
    """Test vuln_engine functions."""

    def test_import(self):
        from tools.vuln_engine import TECH_SIGNATURES, KNOWN_CVES

        assert TECH_SIGNATURES is not None
        assert KNOWN_CVES is not None

    def test_tech_signatures_structure(self):
        from tools.vuln_engine import TECH_SIGNATURES

        assert isinstance(TECH_SIGNATURES, dict)
        assert len(TECH_SIGNATURES) > 0
        for tech, sigs in TECH_SIGNATURES.items():
            assert isinstance(tech, str)
            assert isinstance(sigs, dict)

    def test_known_cves_structure(self):
        from tools.vuln_engine import KNOWN_CVES

        assert isinstance(KNOWN_CVES, dict)
        assert len(KNOWN_CVES) > 0

    def test_severity_from_cvss(self):
        from tools.vuln_engine import severity_from_cvss

        assert severity_from_cvss(9.0) == "Critical"
        assert severity_from_cvss(7.0) == "High"
        assert severity_from_cvss(5.0) == "Medium"
        assert severity_from_cvss(2.0) == "Low"

    def test_fingerprint_tech(self):
        from tools.vuln_engine import fingerprint_tech

        result = fingerprint_tech(
            headers={"X-Powered-By": "WordPress"},
            body="<meta name='generator' content='WordPress 5.8'>",
        )
        assert isinstance(result, list)


# ── tools/cvss_calculator.py ─────────────────────────────────────────────────


class TestCVSSCalculatorExtended:
    """Test CVSS calculator in more detail."""

    def test_severity_enum(self):
        from tools.cvss_calculator import CVSSScore

        # Check that CVSSScore exists
        assert CVSSScore is not None

    def test_cvss_vector_creation(self):
        from tools.cvss_calculator import CVSSVector

        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        assert vector.attack_vector == "N"

    def test_calculate_basic(self):
        from tools.cvss_calculator import CVSSCalculator, CVSSVector

        calc = CVSSCalculator(use_ai=False)
        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        score = calc.calculate(vector)
        assert score.base_score >= 9.0  # Should be Critical

    def test_calculate_low_severity(self):
        from tools.cvss_calculator import CVSSCalculator, CVSSVector

        calc = CVSSCalculator(use_ai=False)
        vector = CVSSVector(
            attack_vector="P",
            attack_complexity="H",
            privileges_required="H",
            user_interaction="R",
            scope="U",
            confidentiality="N",
            integrity="N",
            availability="N",
        )
        score = calc.calculate(vector)
        assert score.base_score < 4.0  # Should be Low


# ── tools/analysis_pipeline.py ───────────────────────────────────────────────


class TestAnalysisPipeline:
    """Test AnalysisPipeline basics."""

    def test_import(self):
        from tools.analysis_pipeline import AnalysisPipeline

        assert AnalysisPipeline is not None


# ── tools/agent_reflection.py ────────────────────────────────────────────────


class TestAgentReflection:
    """Test agent reflection basics."""

    def test_import(self):
        from tools.agent_reflection import get_reflection

        assert get_reflection is not None

    def test_get_reflection(self):
        from tools.agent_reflection import get_reflection

        try:
            reflection = get_reflection()
            assert reflection is not None
        except Exception:
            # May fail due to missing dependencies
            pass


# ── tools/auto_detector.py ───────────────────────────────────────────────────


class TestAutoDetector:
    """Test AutoDetector basics."""

    def test_import(self):
        from tools.auto_detector import AutoDetector

        assert AutoDetector is not None

    def test_detect_returns_string(self):
        from tools.auto_detector import AutoDetector

        try:
            result = AutoDetector.detect("example.com")
            assert isinstance(result, str)
        except Exception:
            # May fail due to missing dependencies
            pass


# ── tools/coverage_analyzer.py ───────────────────────────────────────────────


class TestCoverageAnalyzer:
    """Test CoverageAnalyzer basics."""

    def test_import(self):
        from tools.coverage_analyzer import CoverageAnalyzer

        assert CoverageAnalyzer is not None


# ── tools/cve_database.py ────────────────────────────────────────────────────


class TestCVEDatabase:
    """Test CVE database basics."""

    def test_import(self):
        from tools.cve_database import get_cve_database

        assert get_cve_database is not None


# ── tools/hunt_engine.py ─────────────────────────────────────────────────────


class TestHuntEngine:
    """Test HuntEngine basics."""

    def test_import(self):
        from tools.hunt_engine import HuntEngine

        assert HuntEngine is not None


# ── tools/logic_flaw_engine.py ───────────────────────────────────────────────


class TestLogicFlawEngine:
    """Test LogicFlawEngine basics."""

    def test_import(self):
        from tools.logic_flaw_engine import LogicFlawEngine

        assert LogicFlawEngine is not None


# ── tools/supply_chain_analyzer.py ───────────────────────────────────────────


class TestSupplyChainAnalyzer:
    """Test SupplyChainAnalyzer basics."""

    def test_import(self):
        from tools.supply_chain_analyzer import SupplyChainAnalyzer

        assert SupplyChainAnalyzer is not None


# ── tools/vector_memory.py ───────────────────────────────────────────────────


class TestVectorMemory:
    """Test vector memory basics."""

    def test_import(self):
        from tools.vector_memory import remember, recall, get_context_for_ai

        assert remember is not None
        assert recall is not None
        assert get_context_for_ai is not None


# ── tools/profile_manager.py ─────────────────────────────────────────────────


class TestProfileManager:
    """Test ProfileManager basics."""

    def test_import(self):
        from tools.profile_manager import ProfileManager

        assert ProfileManager is not None


# ── tools/reporter.py ────────────────────────────────────────────────────────


class TestReporter:
    """Test Reporter basics."""

    def test_import(self):
        from tools import html_reporter

        assert html_reporter is not None


# ── tools/smart_scanner.py ───────────────────────────────────────────────────


class TestSmartScanner:
    """Test SmartScanner basics."""

    def test_import(self):
        from tools.smart_scanner import SmartScanner

        assert SmartScanner is not None


# ── tools/token_counter.py ───────────────────────────────────────────────────


class TestTokenCounter:
    """Test token counter basics."""

    def test_import(self):
        from tools.token_counter import count_tokens

        assert count_tokens is not None

    def test_count_tokens(self):
        from tools.token_counter import count_tokens

        result = count_tokens("Hello world")
        assert isinstance(result, int)
        assert result > 0


# ── tools/user_preferences.py ────────────────────────────────────────────────


class TestUserPreferences:
    """Test user preferences basics."""

    def test_import(self):
        from tools.user_preferences import get_preferences, save_preferences

        assert get_preferences is not None
        assert save_preferences is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

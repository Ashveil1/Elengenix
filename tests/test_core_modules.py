"""test_core_modules.py - Tests for critical modules without coverage.

Covers: cvss_calculator, governance, mission_state, vector_memory, cve_database.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ═══════════════════════════════════════════════════════════════════════════
# CVSS Calculator
# ═══════════════════════════════════════════════════════════════════════════

def test_cvss_zero_vector():
    """All-NONE vector should score 0.0."""
    from tools.cvss_calculator import CVSSCalculator, CVSSVector, Severity
    calc = CVSSCalculator(use_ai=False)
    vector = CVSSVector()
    score = calc.calculate(vector)
    assert score.base_score == 0.0
    assert score.severity == Severity.INFO


def test_cvss_critical_rce():
    """Network RCE with no auth should be Critical."""
    from tools.cvss_calculator import CVSSCalculator, CVSSVector, Severity
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
    assert score.base_score >= 9.0
    assert score.severity == Severity.CRITICAL


def test_cvss_medium_stored_xss():
    """Stored XSS should be around Medium."""
    from tools.cvss_calculator import CVSSCalculator, CVSSVector, Severity
    calc = CVSSCalculator(use_ai=False)
    vector = CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="L",
        user_interaction="R",
        scope="U",
        confidentiality="L",
        integrity="L",
        availability="N",
    )
    score = calc.calculate(vector)
    assert 4.0 <= score.base_score <= 6.0
    assert score.severity in (Severity.MEDIUM, Severity.HIGH)


def test_cvss_vector_string():
    """CVSS vector string should follow standard format."""
    from tools.cvss_calculator import CVSSVector
    vector = CVSSVector()
    vs = vector.to_vector_string()
    assert vs.startswith("CVSS:3.1/AV:")
    assert "AC:" in vs
    assert "PR:" in vs


def test_cvss_from_finding():
    """from_finding should return a valid score."""
    from tools.cvss_calculator import CVSSCalculator, Severity
    calc = CVSSCalculator(use_ai=False)
    score = calc.from_finding("sql_injection", "https://example.com", "UNION SELECT")
    assert 0.0 <= score.base_score <= 10.0
    assert isinstance(score.severity, Severity)


# ═══════════════════════════════════════════════════════════════════════════
# Governance
# ═══════════════════════════════════════════════════════════════════════════

def test_governance_safe_command():
    """Safe commands should be allowed."""
    from tools.governance import Governance
    gov = Governance(require_approval_high_risk=False)
    decision = gov.gate("test", "example.com", {"command": "nuclei -u example.com"})
    assert decision.allowed is True
    assert decision.risk_level == "SAFE"


def test_governance_destructive_rm_rf():
    """rm -rf / should be blocked."""
    from tools.governance import Governance
    gov = Governance()
    decision = gov.gate("test", "example.com", {"command": "rm -rf /"})
    assert decision.allowed is False
    assert decision.risk_level == "DESTRUCTIVE"


def test_governance_destructive_dd():
    """dd if=/dev/zero of=/dev/sda should be blocked."""
    from tools.governance import Governance
    gov = Governance()
    decision = gov.gate("test", "example.com", {"command": "dd if=/dev/zero of=/dev/sda"})
    assert decision.allowed is False
    assert decision.risk_level == "DESTRUCTIVE"


def test_governance_privileged_sudo():
    """sudo commands should need approval."""
    from tools.governance import Governance
    gov = Governance(require_approval_high_risk=True)
    decision = gov.gate("test", "example.com", {"command": "sudo apt install nmap"})
    assert decision.allowed is False
    assert decision.risk_level == "PRIVILEGED"
    assert decision.decision == "needs_approval"


def test_governance_privileged_auto_approve():
    """Auto-approve mode should allow privileged commands."""
    from tools.governance import Governance
    gov = Governance(require_approval_high_risk=True)
    gov.auto_approve_privileged = True
    decision = gov.gate("test", "example.com", {"command": "sudo apt install nmap"})
    assert decision.allowed is True
    assert decision.risk_level == "PRIVILEGED"


def test_governance_classify_risk():
    """classify_risk should return correct risk levels."""
    from tools.governance import Governance
    gov = Governance()
    assert gov.classify_risk({"command": "nuclei -u x"}) == "SAFE"
    assert gov.classify_risk({"command": "rm -rf /"}) == "DESTRUCTIVE"
    assert gov.classify_risk({"command": "sudo ls"}) == "PRIVILEGED"


# ═══════════════════════════════════════════════════════════════════════════
# Mission State
# ═══════════════════════════════════════════════════════════════════════════

def test_mission_state_create():
    """MissionState should create with correct fields."""
    from tools.mission_state import MissionState
    ms = MissionState(mission_id="test:123", target="example.com", objective="scan")
    assert ms.mission_id == "test:123"
    assert ms.target == "example.com"
    assert ms.objective == "scan"


def test_mission_state_snapshot():
    """snapshot should return a dict with expected keys."""
    from tools.mission_state import MissionState
    ms = MissionState(mission_id="test:456", target="example.com", objective="test")
    snap = ms.snapshot()
    assert "target" in snap
    assert "objective" in snap
    assert snap["target"] == "example.com"


def test_mission_state_add_fact():
    """add_fact should store a fact."""
    from tools.mission_state import MissionState
    ms = MissionState(mission_id="test:789", target="example.com", objective="test")
    ms.add_fact(
        fact_id="fact:test:0",
        category="finding",
        statement="Found SQLi at /login",
        confidence=0.9,
    )
    snap = ms.snapshot()
    assert "facts" in snap


# ═══════════════════════════════════════════════════════════════════════════
# CVE Database
# ═══════════════════════════════════════════════════════════════════════════

def test_cve_database_loads():
    """CVE database should load without errors."""
    from tools.cve_database import get_cve_database
    db = get_cve_database(auto_update=False)
    assert db is not None


def test_cve_database_find_similar():
    """find_similar_vulns should return a list."""
    from tools.cve_database import get_cve_database
    db = get_cve_database(auto_update=False)
    results = db.find_similar_vulns("sql_injection", cvss_range=(7.0, 10.0))
    assert isinstance(results, list)


# ═══════════════════════════════════════════════════════════════════════════
# Vector Memory
# ═══════════════════════════════════════════════════════════════════════════

def test_vector_memory_remember_recall():
    """remember and recall should work together."""
    from tools.vector_memory import remember, recall
    remember(
        content="Test memory entry for unit test",
        target="test_target",
        category="test",
    )
    results = recall(query="unit test", target="test_target", n_results=3)
    assert isinstance(results, list)


# ═══════════════════════════════════════════════════════════════════════════
# Tool Registry (expanded)
# ═══════════════════════════════════════════════════════════════════════════

def test_tool_registry_has_multiple_tools():
    """Registry should have discovered tools."""
    from tools.tool_registry import registry
    tools = registry.list_available_tools()
    assert len(tools) >= 5


def test_tool_registry_categories():
    """Each registered tool should have a valid category."""
    from tools.tool_registry import registry, ToolCategory
    tools = registry.list_available_tools()
    for name, info in tools.items():
        assert any(cat.value == info["category"] for cat in ToolCategory), \
            f"{name} has invalid category: {info['category']}"


def test_tool_registry_chain():
    """get_recommended_chain should return ordered tools."""
    from tools.tool_registry import registry
    chain = registry.get_recommended_chain("web")
    assert len(chain) > 0
    # Each tool should be a BaseTool instance
    from tools.tool_registry import BaseTool
    for tool in chain:
        assert isinstance(tool, BaseTool)


# ═══════════════════════════════════════════════════════════════════════════
# Tool Registry - New Wrappers
# ═══════════════════════════════════════════════════════════════════════════

def test_tool_registry_waf_detector_registered():
    """WAF detector should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("waf_detector")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_tool_registry_active_fuzzer_registered():
    """Active fuzzer should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("active_fuzzer")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_tool_registry_python_recon_registered():
    """Python recon should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("python_recon")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_tool_registry_tool_count():
    """Registry should have at least 6 tools (3 Go + 3 Python)."""
    from tools.tool_registry import registry
    tools = registry.list_available_tools()
    assert len(tools) >= 6


# ═══════════════════════════════════════════════════════════════════════════
# New Scanning Modules
# ═══════════════════════════════════════════════════════════════════════════

def test_ssrf_scanner_registered():
    """SSRF scanner should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("ssrf_scanner")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_ssti_scanner_registered():
    """SSTI scanner should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("ssti_scanner")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_xxe_scanner_registered():
    """XXE scanner should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("xxe_scanner")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_deserialization_scanner_registered():
    """Deserialization scanner should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("deserialization_scanner")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_ssrf_scanner_instantiation():
    """SSRF scanner should instantiate correctly."""
    from tools.ssrf_scanner import SSRFScanner
    scanner = SSRFScanner()
    assert scanner.timeout > 0


def test_ssti_scanner_instantiation():
    """SSTI scanner should instantiate correctly."""
    from tools.ssti_scanner import SSTIScanner
    scanner = SSTIScanner()
    assert scanner.timeout > 0


def test_xxe_scanner_instantiation():
    """XXE scanner should instantiate correctly."""
    from tools.xxe_scanner import XXEScanner
    scanner = XXEScanner()
    assert scanner.timeout > 0


def test_deserialization_scanner_instantiation():
    """Deserialization scanner should instantiate correctly."""
    from tools.deserialization_scanner import DeserializationScanner
    scanner = DeserializationScanner()
    assert scanner.timeout > 0


def test_tool_registry_scanner_count():
    """Registry should have at least 10 tools (including new scanners)."""
    from tools.tool_registry import registry
    tools = registry.list_available_tools()
    assert len(tools) >= 10


# ═══════════════════════════════════════════════════════════════════════════
# GraphQL Scanner
# ═══════════════════════════════════════════════════════════════════════════

def test_graphql_scanner_registered():
    """GraphQL scanner should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("graphql_scanner")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_graphql_scanner_instantiation():
    """GraphQL scanner should instantiate correctly."""
    from tools.graphql_scanner import GraphQLScanner
    scanner = GraphQLScanner()
    assert scanner.timeout > 0


def test_graphql_endpoints_list():
    """GraphQL endpoints list should be populated."""
    from tools.graphql_scanner import GRAPHQL_ENDPOINTS
    assert len(GRAPHQL_ENDPOINTS) > 0
    assert "/graphql" in GRAPHQL_ENDPOINTS


def test_introspection_query():
    """Introspection query should be valid GraphQL."""
    from tools.graphql_scanner import INTROSPECTION_QUERY
    assert "IntrospectionQuery" in INTROSPECTION_QUERY
    assert "__schema" in INTROSPECTION_QUERY


# ═══════════════════════════════════════════════════════════════════════════
# Race Condition Tester
# ═══════════════════════════════════════════════════════════════════════════

def test_race_condition_tester_registered():
    """Race condition tester should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("race_condition_tester")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_race_condition_tester_instantiation():
    """Race condition tester should instantiate correctly."""
    from tools.race_condition_tester import RaceConditionTester
    tester = RaceConditionTester()
    assert tester.timeout > 0
    assert tester.max_workers > 0


def test_race_condition_result_dataclass():
    """RaceConditionResult dataclass should work correctly."""
    from tools.race_condition_tester import RaceConditionResult
    result = RaceConditionResult(
        test_type="test",
        endpoint="http://test.com",
        vulnerable=True,
        evidence="test evidence",
    )
    assert result.vulnerable is True
    assert result.test_type == "test"


# ═══════════════════════════════════════════════════════════════════════════
# API Schema Diff
# ═══════════════════════════════════════════════════════════════════════════

def test_api_schema_diff_registered():
    """API schema diff should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("api_schema_diff")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_api_schema_diff_instantiation():
    """API schema diff should instantiate correctly."""
    from tools.api_schema_diff import APISchemaDiffer
    differ = APISchemaDiffer()
    assert differ is not None


def test_api_schema_diff_compare():
    """API schema diff should compare schemas correctly."""
    from tools.api_schema_diff import APISchemaDiffer
    
    schema1 = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {"summary": "Get users"},
                "post": {"summary": "Create user"},
            }
        }
    }
    
    schema2 = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "get": {"summary": "Get users"},
            },
            "/posts": {
                "get": {"summary": "Get posts"},
            }
        }
    }
    
    differ = APISchemaDiffer()
    result = differ.compare_schemas(schema1, schema2, "v1", "v2")
    
    assert result.has_changes
    assert len(result.removed_endpoints) == 1  # POST /users removed
    assert len(result.added_endpoints) == 1  # GET /posts added


# ═══════════════════════════════════════════════════════════════════════════
# Supply Chain Analyzer
# ═══════════════════════════════════════════════════════════════════════════

def test_supply_chain_analyzer_registered():
    """Supply chain analyzer should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("supply_chain_analyzer")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_supply_chain_analyzer_instantiation():
    """Supply chain analyzer should instantiate correctly."""
    from tools.supply_chain_analyzer import SupplyChainAnalyzer
    analyzer = SupplyChainAnalyzer()
    assert analyzer is not None


def test_supply_chain_analyzer_package_list():
    """Supply chain analyzer should analyze package lists correctly."""
    from tools.supply_chain_analyzer import SupplyChainAnalyzer
    
    packages = [
        {"name": "requests", "version": "2.28.0"},
        {"name": "flask", "version": "2.0.0"},
    ]
    
    analyzer = SupplyChainAnalyzer()
    result = analyzer.analyze_package_list(packages, "pypi")
    
    assert result.total_dependencies == 2
    assert len(result.dependencies) == 2


# ═══════════════════════════════════════════════════════════════════════════
# Business Logic Analyzer
# ═══════════════════════════════════════════════════════════════════════════

def test_logic_flaw_engine_registered():
    """Logic flaw engine should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("logic_flaw_engine")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_logic_flaw_engine_instantiation():
    """Logic flaw engine should instantiate correctly."""
    from tools.logic_flaw_engine import LogicFlawEngine
    engine = LogicFlawEngine()
    assert engine.timeout > 0


def test_logic_flaw_result_dataclass():
    """LogicFlawResult dataclass should work correctly."""
    from tools.logic_flaw_engine import LogicFlaw, LogicFlawResult
    
    flaw = LogicFlaw(
        flaw_type="test",
        endpoint="http://test.com",
        description="Test flaw",
    )
    
    result = LogicFlawResult(
        target="http://test.com",
        flaws=[flaw],
    )
    
    assert result.is_vulnerable
    assert len(result.flaws) == 1


# ═══════════════════════════════════════════════════════════════════════════
# CORS Checker
# ═══════════════════════════════════════════════════════════════════════════

def test_cors_checker_registered():
    """CORS checker should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("cors_checker")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_cors_checker_instantiation():
    """CORS checker should instantiate correctly."""
    from tools.cors_checker import CORSChecker
    checker = CORSChecker()
    assert checker.timeout > 0


def test_cors_result_dataclass():
    """CORSResult dataclass should work correctly."""
    from tools.cors_checker import CORSResult
    result = CORSResult(
        test_type="test",
        origin="https://evil.com",
        vulnerable=True,
    )
    assert result.vulnerable is True
    assert result.origin == "https://evil.com"


# ═══════════════════════════════════════════════════════════════════════════
# JWT Tester
# ═══════════════════════════════════════════════════════════════════════════

def test_jwt_tester_registered():
    """JWT tester should be registered in the tool registry."""
    from tools.tool_registry import registry
    tool = registry.get_tool("jwt_tester")
    assert tool is not None
    assert tool.is_available  # Pure Python, always available


def test_jwt_tester_instantiation():
    """JWT tester should instantiate correctly."""
    from tools.jwt_tester import JWTTester
    tester = JWTTester()
    assert tester.timeout > 0


def test_jwt_result_dataclass():
    """JWTResult dataclass should work correctly."""
    from tools.jwt_tester import JWTResult
    result = JWTResult(
        test_type="test",
        vulnerable=True,
        evidence="test evidence",
    )
    assert result.vulnerable is True
    assert result.test_type == "test"

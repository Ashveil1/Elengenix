"""test_untested_modules.py - Tests for modules without existing tests.

Covers: All tools/ modules that can be imported
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# List of modules to test
MODULES_TO_TEST = [
    "tools.access_control_matrix",
    "tools.agent_bola_bridge",
    "tools.agent_reflection",
    "tools.ai_config",
    "tools.ai_sandbox",
    "tools.ai_tool_creator",
    "tools.analysis_pipeline",
    "tools.api_finder",
    "tools.api_schema_diff",
    "tools.api_server",
    "tools.arjun_integration",
    "tools.auth_session",
    "tools.auth_tester",
    "tools.auto_detector",
    "tools.autonomous_agent",
    "tools.base_recon",
    "tools.base_scanner",
    "tools.bola_harness",
    "tools.bounty_intelligence",
    "tools.bounty_predictor",
    "tools.bounty_reporter",
    "tools.cloud_scanner",
    "tools.command_suggest",
    "tools.compliance_engine",
    "tools.context_compressor",
    "tools.cors_checker",
    "tools.cve_database",
    "tools.cvss_calculator",
    "tools.dashboard_server",
    "tools.deserialization_scanner",
    "tools.dork_miner",
    "tools.dynamic_waf_mutator",
    "tools.ecosystem",
    "tools.edr_evasion",
    "tools.endpoint_discovery",
    "tools.enterprise_security",
    "tools.event_loop",
    "tools.exploit_chain_builder",
    "tools.exploit_template",
    "tools.exploitation",
    "tools.finding_dedup",
    "tools.github_intel",
    "tools.governance",
    "tools.graphql_scanner",
    "tools.history_manager",
    "tools.html_reporter",
    "tools.hunt_engine",
    "tools.injection_tester",
    "tools.install_request",
    "tools.interactive_dashboard",
    "tools.js_analyzer",
    "tools.learning_engine",
    "tools.llm_reasoning",
    "tools.logic_analyzer",
    "tools.logic_flaw_engine",
    "tools.marketplace",
    "tools.memory_manager",
    "tools.memory_persistence",
    "tools.memory_profile",
    "tools.mission_state",
    "tools.ml_filter",
    "tools.mobile_api_tester",
    "tools.multi_agent",
    "tools.multimodal_agent",
    "tools.native_scanner",
    "tools.nvd_cve",
    "tools.object_id_permuter",
    "tools.omni_scan",
    "tools.overlay_menu",
    "tools.param_miner",
    "tools.payload_mutation",
    "tools.pdf_report_generator",
    "tools.perf",
    "tools.profile_manager",
    "tools.progress_display",
    "tools.protocol_analyzer",
    "tools.python_recon",
    "tools.race_condition_tester",
    "tools.report_gen",
    "tools.reporter",
    "tools.research_tool",
    "tools.safe_exec",
    "tools.sast_engine",
    "tools.session_manager",
    "tools.skill_registry",
    "tools.smart_recon",
    "tools.smart_scanner",
    "tools.soc_analyzer",
    "tools.ssrf_scanner",
    "tools.subdomain_takeover",
    "tools.supply_chain_analyzer",
    "tools.swarm_controller",
    "tools.targeted_attacks",
    "tools.telegram_bridge",
    "tools.threat_intel",
    "tools.token_counter",
    "tools.token_manager",
    "tools.tool_registry",
    "tools.truffle_integration",
    "tools.tui_dashboard",
    "tools.universal_ai_client",
    "tools.universal_executor",
    "tools.updater",
    "tools.user_memory",
    "tools.user_preferences",
    "tools.vector_memory",
    "tools.vuln_engine",
    "tools.vuln_researcher",
    "tools.vulncheck_tool",
    "tools.waf_detector",
    "tools.waf_evasion",
    "tools.waf_signatures",
    "tools.wayback_tool",
    "tools.welcome_wizard",
    "tools.wordlist_manager",
    "tools.workflow_fuzzer",
    "tools.zero_day_heuristics",
    "tools.jwt_tester",
    "tools.ssti_scanner",
    "tools.xxe_scanner",
    "tools.deserialization_scanner",
    "tools.graphql_scanner",
    "tools.race_condition_tester",
    "tools.api_schema_diff",
    "tools.supply_chain_analyzer",
    "tools.logic_flaw_engine",
    "tools.cors_checker",
]


def test_all_modules_import():
    """All tools modules should be importable."""
    errors = []
    for module in MODULES_TO_TEST:
        try:
            __import__(module)
        except Exception as e:
            errors.append(f"{module}: {e}")

    if errors:
        for err in errors:
            print(f"ERROR: {err}")
    assert len(errors) == 0, f"Failed to import {len(errors)} modules"


def test_all_critical_classes_instantiate():
    """Critical classes should be instantiable."""
    from tools.cvss_calculator import CVSSCalculator
    from tools.governance import Governance
    from tools.mission_state import MissionState
    from tools.tool_registry import registry
    from tools.vector_memory import recall, remember

    # Test instantiation
    gov = Governance()
    calc = CVSSCalculator(use_ai=False)
    ms = MissionState(mission_id="test", target="test.com", objective="test")

    # Test registry
    tools = registry.list_available_tools()
    assert len(tools) > 0

    # Test vector memory
    remember(content="test", target="test_target", category="test")
    results = recall(query="test", target="test_target", n_results=1)
    assert isinstance(results, list)


def test_all_scanners_instantiate():
    """All scanner modules should be importable."""
    from tools.api_schema_diff import APISchemaDiffer
    from tools.cors_checker import CORSChecker
    from tools.deserialization_scanner import DeserializationScanner
    from tools.graphql_scanner import GraphQLScanner
    from tools.jwt_tester import JWTTester
    from tools.logic_flaw_engine import LogicFlawEngine
    from tools.race_condition_tester import RaceConditionTester
    from tools.ssrf_scanner import SSRFScanner
    from tools.ssti_scanner import SSTIScanner
    from tools.supply_chain_analyzer import SupplyChainAnalyzer
    from tools.xxe_scanner import XXEScanner

    # Test instantiation
    scanners = [
        SSRFScanner(),
        SSTIScanner(),
        XXEScanner(),
        DeserializationScanner(),
        GraphQLScanner(),
        RaceConditionTester(),
        APISchemaDiffer(),
        SupplyChainAnalyzer(),
        LogicFlawEngine(),
        CORSChecker(),
        JWTTester(),
    ]

    for scanner in scanners:
        assert scanner is not None


def test_all_tui_modules_import():
    """All TUI modules should be importable."""
    from tui.dashboard import ThreatDashboard
    from tui.export import export_to_html, export_to_json
    from tui.findings_display import FindingsDisplay
    from tui.keyboard_shortcuts import KeyboardShortcutManager
    from tui.main_menu import render_main_menu
    from tui.scan_progress import ScanProgressWidget
    from tui.themes import THEMES
    from tui.visualizations import RiskGauge, SeverityChart
    from tui.welcome import build_welcome_renderable

    # Test instantiation
    result = build_welcome_renderable()
    assert result is not None

    gauge = RiskGauge(value=50, max_value=100, label="RISK")
    assert gauge is not None

    display = FindingsDisplay()
    assert display is not None

    manager = KeyboardShortcutManager()
    assert manager is not None

    widget = ScanProgressWidget()
    assert widget is not None


def test_all_agent_modules_import():
    """All agent modules should be importable."""
    from agents.agent_conversation import ConversationManager
    from agents.agent_dataclasses import AttackTree
    from agents.agent_executor import execute_tool
    from agents.agent_helpers import _extract_target_from_text, _safe_operation
    from agents.agent_intent import analyze_intent
    from agents.agent_logger import ChainOfThoughtLogger
    from agents.agent_modes import ModeProcessor
    from agents.agent_planner import StrategicPlanner
    from agents.critic_agent import CriticAgent
    from agents.hybrid_agent import HybridAgent
    from agents.specialist_agent import SpecialistAgent
    from agents.strategist_agent import StrategistAgent

    # Test helpers
    result = _safe_operation("test", lambda: 42)
    assert result == 42

    target = _extract_target_from_text("scan example.com")
    assert "example" in target

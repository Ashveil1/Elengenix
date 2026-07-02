"""tests/test_analysis_pipeline_imports.py — Test that key module imports work."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_cors_checker_import():
    from tools.cors_checker import CORSChecker, CORSResult, CORSScanResult
    assert CORSChecker is not None
    assert CORSResult is not None
    assert CORSScanResult is not None


def test_ssrf_scanner_import():
    from tools.ssrf_scanner import SSRFScanner, SSRFResult, SSRFScanResult
    assert SSRFScanner is not None
    assert SSRFResult is not None
    assert SSRFScanResult is not None


def test_mission_state_import():
    from tools.mission_state import MissionState
    assert MissionState is not None


def test_knowledge_graph_import():
    from tools.knowledge_graph import KnowledgeGraph, NodeType, EdgeType
    assert KnowledgeGraph is not None
    assert NodeType is not None
    assert EdgeType is not None


def test_escalation_engine_import():
    from tools.escalation_engine import EscalationEngine, EscalationPath
    assert EscalationEngine is not None
    assert EscalationPath is not None


def test_chaining_engine_import():
    from tools.chaining_engine import ChainingEngine, AttackChain
    assert ChainingEngine is not None
    assert AttackChain is not None


def test_verification_engine_import():
    from tools.verification_engine import VerificationEngine, VerificationResult
    assert VerificationEngine is not None
    assert VerificationResult is not None


def test_adaptive_planner_import():
    from tools.adaptive_planner import AdaptivePlanner, ActionType, AttackPath
    assert AdaptivePlanner is not None
    assert ActionType is not None
    assert AttackPath is not None

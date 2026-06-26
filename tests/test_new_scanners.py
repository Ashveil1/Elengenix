"""test_new_scanners.py - Tests for newly added scanning modules.

Covers: ssrf_scanner, ssti_scanner, xxe_scanner, deserialization_scanner,
        graphql_scanner, race_condition_tester, api_schema_diff, cors_checker, jwt_tester
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ═══════════════════════════════════════════════════════════════════════════
# SSRF Scanner
# ═══════════════════════════════════════════════════════════════════════════

def test_ssrf_scanner_instantiation():
    from tools.ssrf_scanner import SSRFScanner
    scanner = SSRFScanner()
    assert scanner.timeout > 0


def test_ssrf_scan_result():
    from tools.ssrf_scanner import SSRFScanResult
    result = SSRFScanResult(target="test.com")
    assert result.target == "test.com"
    assert result.is_vulnerable is False


# ═══════════════════════════════════════════════════════════════════════════
# SSTI Scanner
# ═══════════════════════════════════════════════════════════════════════════

def test_ssti_scanner_instantiation():
    from tools.ssti_scanner import SSTIScanner
    scanner = SSTIScanner()
    assert scanner.timeout > 0


def test_ssti_scan_result():
    from tools.ssti_scanner import SSTIScanResult
    result = SSTIScanResult(target="test.com")
    assert result.target == "test.com"
    assert result.is_vulnerable is False


# ═══════════════════════════════════════════════════════════════════════════
# XXE Scanner
# ═══════════════════════════════════════════════════════════════════════════

def test_xxe_scanner_instantiation():
    from tools.xxe_scanner import XXEScanner
    scanner = XXEScanner()
    assert scanner.timeout > 0


def test_xxe_scan_result():
    from tools.xxe_scanner import XXEScanResult
    result = XXEScanResult(target="test.com")
    assert result.target == "test.com"
    assert result.is_vulnerable is False


# ═══════════════════════════════════════════════════════════════════════════
# Deserialization Scanner
# ═══════════════════════════════════════════════════════════════════════════

def test_deserialization_scanner_instantiation():
    from tools.deserialization_scanner import DeserializationScanner
    scanner = DeserializationScanner()
    assert scanner.timeout > 0


def test_deserialization_scan_result():
    from tools.deserialization_scanner import DeserScanResult
    result = DeserScanResult(target="test.com")
    assert result.target == "test.com"
    assert result.is_vulnerable is False


# ═══════════════════════════════════════════════════════════════════════════
# GraphQL Scanner
# ═══════════════════════════════════════════════════════════════════════════

def test_graphql_scanner_instantiation():
    from tools.graphql_scanner import GraphQLScanner
    scanner = GraphQLScanner()
    assert scanner.timeout > 0


def test_graphql_scan_result():
    from tools.graphql_scanner import GraphQLScanResult
    result = GraphQLScanResult(target="test.com")
    assert result.target == "test.com"
    assert result.is_vulnerable is False


# ═══════════════════════════════════════════════════════════════════════════
# Race Condition Tester
# ═══════════════════════════════════════════════════════════════════════════

def test_race_condition_tester_instantiation():
    from tools.race_condition_tester import RaceConditionTester
    tester = RaceConditionTester()
    assert tester.timeout > 0


def test_race_condition_scan_result():
    from tools.race_condition_tester import RaceConditionScanResult
    result = RaceConditionScanResult(target="test.com")
    assert result.target == "test.com"
    assert result.is_vulnerable is False


# ═══════════════════════════════════════════════════════════════════════════
# API Schema Diff
# ═══════════════════════════════════════════════════════════════════════════

def test_api_schema_diff_instantiation():
    from tools.api_schema_diff import APISchemaDiffer
    differ = APISchemaDiffer()
    assert differ is not None


def test_api_schema_diff_compare():
    from tools.api_schema_diff import APISchemaDiffer
    differ = APISchemaDiffer()
    
    schema1 = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {"get": {"summary": "Get users"}},
            "/posts": {"get": {"summary": "Get posts"}},
        }
    }
    schema2 = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {"get": {"summary": "Get users"}},
            "/comments": {"get": {"summary": "Get comments"}},
        }
    }
    
    result = differ.compare_schemas(schema1, schema2, "v1", "v2")
    assert result.has_changes
    assert len(result.added_endpoints) == 1  # /comments added
    assert len(result.removed_endpoints) == 1  # /posts removed


# ═══════════════════════════════════════════════════════════════════════════
# CORS Checker
# ═══════════════════════════════════════════════════════════════════════════

def test_cors_checker_instantiation():
    from tools.cors_checker import CORSChecker
    checker = CORSChecker()
    assert checker.timeout > 0


def test_cors_scan_result():
    from tools.cors_checker import CORSScanResult
    result = CORSScanResult(target="test.com")
    assert result.target == "test.com"
    assert result.is_vulnerable is False


# ═══════════════════════════════════════════════════════════════════════════
# JWT Tester
# ═══════════════════════════════════════════════════════════════════════════

def test_jwt_tester_instantiation():
    from tools.jwt_tester import JWTTester
    tester = JWTTester()
    assert tester.timeout > 0


def test_jwt_scan_result():
    from tools.jwt_tester import JWTScanResult
    result = JWTScanResult(target="test.com")
    assert result.target == "test.com"
    assert result.is_vulnerable is False


# ═══════════════════════════════════════════════════════════════════════════
# Tool Registry Integration
# ═══════════════════════════════════════════════════════════════════════════

def test_all_new_scanners_registered():
    """All new scanners should be registered in tool registry."""
    from tools.tool_registry import registry
    new_tools = [
        "ssrf_scanner", "ssti_scanner", "xxe_scanner", "deserialization_scanner",
        "graphql_scanner", "race_condition_tester", "api_schema_diff",
        "supply_chain_analyzer", "logic_flaw_engine", "cors_checker", "jwt_tester"
    ]
    for tool_name in new_tools:
        tool = registry.get_tool(tool_name)
        assert tool is not None, f"{tool_name} not registered"
        assert tool.is_available, f"{tool_name} not available"

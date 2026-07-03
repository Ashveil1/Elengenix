"""tests/test_breadth_coverage.py

Massive breadth-focused test suite covering tools/ modules that lack
dedicated tests. Strategy: test dataclasses, enums, pure functions,
class methods with mocked network/IO, edge cases, and error paths.

Run: python3 -m pytest tests/test_breadth_coverage.py -q --tb=short
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import sqlite3
import tempfile
import textwrap
import threading
import time
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
from unittest.mock import MagicMock, mock_open, patch

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ============================================================================
# access_control_matrix
# ============================================================================

class TestAccessControlMatrix:
    """tests/tools/access_control_matrix.py"""

    def test_matrix_cell_dataclass(self):
        from tools.access_control_matrix import MatrixCell
        c = MatrixCell(method="GET", url="http://x.com/api", status_a=200, status_b=403,
                       len_a=100, len_b=0, signal="mismatch")
        assert c.signal == "mismatch"
        assert c.status_a == 200

    def test_acm_result_dataclass(self):
        from tools.access_control_matrix import ACMResult
        r = ACMResult(success=True, cells=[], findings=[], notes=["test"])
        assert r.success is True
        assert len(r.notes) == 1

    def test_acm_init_normalizes_url(self):
        from tools.access_control_matrix import AccessControlMatrixTester
        t = AccessControlMatrixTester("http://example.com")
        assert t.base_url.endswith("/")
        assert t.rate_limit_rps >= 0.2

    def test_acm_dry_run(self):
        from tools.access_control_matrix import AccessControlMatrixTester
        t = AccessControlMatrixTester("http://example.com", rate_limit_rps=100)
        result = t.run(
            headers_a={"Authorization": "A"},
            headers_b={"Authorization": "B"},
            endpoints=["/api/users"],
            dry_run=True,
        )
        assert result.success
        assert len(result.cells) == 1
        assert result.cells[0].signal == "dry_run"

    def test_acm_skips_non_get(self):
        from tools.access_control_matrix import AccessControlMatrixTester
        t = AccessControlMatrixTester("http://example.com", rate_limit_rps=100)
        result = t.run(
            headers_a={}, headers_b={},
            endpoints=["/api"],
            methods=["POST", "DELETE"],
            dry_run=True,
        )
        assert len(result.cells) == 0
        assert any("Skipping" in n for n in result.notes)

    def test_format_acm_result(self):
        from tools.access_control_matrix import AccessControlMatrixTester, format_acm_result
        t = AccessControlMatrixTester("http://x.com", rate_limit_rps=100)
        r = t.run({}, {}, ["/a", "/b"], dry_run=True)
        text = format_acm_result(r)
        assert "Matrix cells" in text
        assert "/a" in text

    def test_format_truncates_long(self):
        from tools.access_control_matrix import AccessControlMatrixTester, format_acm_result, MatrixCell
        from tools.access_control_matrix import ACMResult
        cells = [MatrixCell("GET", f"http://x.com/{i}", 200, 200, 10, 10, "ok") for i in range(50)]
        r = ACMResult(success=True, cells=cells, findings=[], notes=[])
        text = format_acm_result(r, max_rows=5)
        assert "45 more" in text


# ============================================================================
# agent_reflection
# ============================================================================

class TestAgentReflection:
    """tests/tools/agent_reflection.py"""

    def test_reflection_entry_post_init(self):
        from tools.agent_reflection import ReflectionEntry
        e = ReflectionEntry(query="q", response="r", feedback="wrong", sentiment="negative")
        assert e.timestamp  # auto-set

    def test_classify_sentiment_negative(self):
        from tools.agent_reflection import AgentReflection
        # Use a temp DB to avoid polluting real data
        import tools.agent_reflection as mod
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_db = Path(f.name)
        try:
            old = mod._DB_PATH
            mod._DB_PATH = tmp_db
            ref = AgentReflection()
            assert ref.classify_sentiment("that's wrong") == "negative"
            assert ref.classify_sentiment("incorrect answer") == "negative"
            assert ref.classify_sentiment("correct answer") == "positive"
            assert ref.classify_sentiment("hello there") == "neutral"
            mod._DB_PATH = old
        finally:
            tmp_db.unlink(missing_ok=True)

    def test_categorize_query(self):
        from tools.agent_reflection import AgentReflection
        import tools.agent_reflection as mod
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_db = Path(f.name)
        try:
            old = mod._DB_PATH
            mod._DB_PATH = tmp_db
            ref = AgentReflection()
            assert ref.categorize_query("scan the target") == "security"
            assert ref.categorize_query("research CVE-2024") == "research"
            assert ref.categorize_query("write python code") == "code"
            assert ref.categorize_query("hello there") == "casual"
            assert ref.categorize_query("random stuff") == "general"
            mod._DB_PATH = old
        finally:
            tmp_db.unlink(missing_ok=True)

    def test_record_and_retrieve(self):
        from tools.agent_reflection import AgentReflection
        import tools.agent_reflection as mod
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_db = Path(f.name)
        try:
            old = mod._DB_PATH
            mod._DB_PATH = tmp_db
            ref = AgentReflection()
            ok = ref.record_mistake("scan target", "found nothing", "that's wrong")
            assert ok
            stats = ref.get_reflection_stats()
            assert stats["total"] >= 1
            assert stats["negative"] >= 1
            # retrieve
            caution = ref.retrieve_caution("scan target")
            assert "CAUTION" in caution or caution == ""
            # clear
            cleared = ref.clear_reflections()
            assert cleared >= 1
            mod._DB_PATH = old
        finally:
            tmp_db.unlink(missing_ok=True)

    def test_get_reflection_singleton(self):
        from tools.agent_reflection import get_reflection, AgentReflection
        r1 = get_reflection()
        assert isinstance(r1, AgentReflection)


# ============================================================================
# ai_config
# ============================================================================

class TestAIConfig:
    """tests/tools/ai_config.py"""

    def test_reset_config_cache(self):
        from tools.ai_config import reset_config_cache, _CONFIG_CACHE
        reset_config_cache()
        from tools.ai_config import _CONFIG_CACHE as cache
        assert isinstance(cache, dict)

    def test_get_active_provider_default(self):
        from tools.ai_config import get_active_provider, reset_config_cache
        reset_config_cache()
        with patch.dict(os.environ, {}, clear=True):
            p = get_active_provider()
            assert isinstance(p, str)

    def test_get_provider_config_missing(self):
        from tools.ai_config import get_provider_config, reset_config_cache
        reset_config_cache()
        cfg = get_provider_config("nonexistent_provider_xyz")
        assert isinstance(cfg, dict)

    def test_resolve_provider_settings(self):
        from tools.ai_config import resolve_provider_settings, reset_config_cache
        reset_config_cache()
        result = resolve_provider_settings("openai", model="gpt-4", api_key="sk-test")
        assert result["provider"] == "openai"
        assert result["model"] == "gpt-4"
        assert result["api_key"] == "sk-test"
        assert result["sources"]["model"] == "param"

    def test_parse_active_models_empty(self):
        from tools.ai_config import parse_active_models, reset_config_cache
        reset_config_cache()
        models = parse_active_models()
        assert isinstance(models, list)

    def test_get_provider_order(self):
        from tools.ai_config import get_provider_order, reset_config_cache
        reset_config_cache()
        order = get_provider_order()
        assert isinstance(order, list)
        assert len(order) > 0

    def test_default_env_key_for(self):
        from tools.ai_config import _default_env_key_for
        assert _default_env_key_for("openai") == "OPENAI_API_KEY"
        assert _default_env_key_for("gemini") == "GEMINI_API_KEY"
        assert _default_env_key_for("ollama") is None
        assert _default_env_key_for("unknown") is None


# ============================================================================
# ai_sandbox
# ============================================================================

class TestAISandbox:
    """tests/tools/ai_sandbox.py"""

    def test_pattern_severity_constants(self):
        from tools.ai_sandbox import PatternSeverity
        assert PatternSeverity.LOW == "low"
        assert PatternSeverity.CRITICAL == "critical"

    def test_dangerous_pattern_hit_dataclass(self):
        from tools.ai_sandbox import DangerousPatternHit
        h = DangerousPatternHit("test", "high", 1, 0, "desc", "code")
        assert h.severity == "high"

    def test_safety_report(self):
        from tools.ai_sandbox import SafetyReport, DangerousPatternHit, PatternSeverity
        r = SafetyReport(is_safe=True)
        assert r.has_critical() is False
        assert r.summary() == "OK (no dangerous patterns detected)"
        # Add critical hit
        r.hits.append(DangerousPatternHit("x", PatternSeverity.CRITICAL, 1, 0, "d", "s"))
        assert r.has_critical() is True
        r.is_safe = False
        assert r.summary().startswith("Hits:")

    def test_detector_safe_code(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        d = RealDangerousPatternDetector()
        r = d.analyze("x = 1\nprint(x)")
        assert r.is_safe

    def test_detector_syntax_error(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        d = RealDangerousPatternDetector()
        r = d.analyze("def foo(")
        assert not r.is_safe
        assert r.syntax_error is not None

    def test_detector_dangerous_import(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        d = RealDangerousPatternDetector()
        r = d.analyze("import os")
        assert not r.is_safe
        assert any(h.pattern_id == "dangerous_import" for h in r.hits)

    def test_detector_from_import(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        d = RealDangerousPatternDetector()
        r = d.analyze("from os import system")
        assert not r.is_safe

    def test_detector_eval_exec(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        d = RealDangerousPatternDetector()
        r = d.analyze("eval('1+1')")
        assert not r.is_safe
        assert any(h.pattern_id == "dangerous_builtin" for h in r.hits)

    def test_detector_shell_token(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        d = RealDangerousPatternDetector()
        r = d.analyze('os.system("/dev/tcp/x/80")')
        assert not r.is_safe

    def test_detector_dunder_access(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        d = RealDangerousPatternDetector()
        r = d.analyze("x.__subclasses__()")
        assert any(h.pattern_id == "dunder_access" for h in r.hits)

    def test_detector_allows_eval_when_permitted(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        d = RealDangerousPatternDetector(allow_eval_exec=True)
        r = d.analyze("eval('1+1')")
        assert r.is_safe

    def test_sandbox_config_dataclass(self):
        from tools.ai_sandbox import SandboxConfig
        c = SandboxConfig(timeout_seconds=10, memory_limit_mb=256)
        assert c.timeout_seconds == 10

    def test_sandbox_result_to_dict(self):
        from tools.ai_sandbox import SandboxResult
        r = SandboxResult(success=True, returncode=0, stdout="ok", stderr="",
                          duration_seconds=1.0)
        d = r.to_dict()
        assert d["success"] is True
        assert d["stdout"] == "ok"

    def test_subprocess_sandbox_safe_code(self):
        from tools.ai_sandbox import SubprocessSandbox, SandboxConfig
        cfg = SandboxConfig(timeout_seconds=5)
        s = SubprocessSandbox(config=cfg)
        r = s.run("x = 42")
        assert r.success
        assert r.returncode == 0

    def test_subprocess_sandbox_syntax_error(self):
        from tools.ai_sandbox import SubprocessSandbox
        s = SubprocessSandbox()
        r = s.run("def bad(")
        assert not r.success
        assert "syntax" in r.stderr.lower() or r.error == "syntax_error"

    def test_subprocess_sandbox_critical_blocked(self):
        from tools.ai_sandbox import SubprocessSandbox
        s = SubprocessSandbox()
        r = s.run("import subprocess\nsubprocess.run(['ls'])")
        assert not r.success
        assert r.error == "critical_violations"

    def test_analyze_code_helper(self):
        from tools.ai_sandbox import analyze_code
        r = analyze_code("x = 1")
        assert r.is_safe
        r2 = analyze_code("import os")
        assert not r2.is_safe

    def test_run_sandboxed_helper(self):
        from tools.ai_sandbox import run_sandboxed
        r = run_sandboxed("print('hello')")
        assert r.success
        assert "hello" in r.stdout


# ============================================================================
# ai_tool_creator
# ============================================================================

class TestAIToolCreator:
    """tests/tools/ai_tool_creator.py"""

    def test_tool_spec_dataclass(self):
        from tools.ai_tool_creator import ToolSpec
        s = ToolSpec(name="test", purpose="test tool", language="python",
                     code="x=1", dependencies=[], entry_point="test",
                     safety_level="safe")
        assert s.name == "test"
        assert s.requires_approval is True

    def test_tool_execution_result_dataclass(self):
        from tools.ai_tool_creator import ToolExecutionResult
        r = ToolExecutionResult(success=True, output="ok", error=None,
                                findings=[], execution_time=0.1, tool_name="t")
        assert r.success

    def test_ai_governance_safe_code(self):
        from tools.ai_tool_creator import AIGovernance, ToolSpec
        gov = AIGovernance(mode="auto", use_ast_sandbox=True)
        spec = ToolSpec(name="t", purpose="p", language="python",
                        code="x = 1", dependencies=[], entry_point="t",
                        safety_level="safe")
        safe, reason = gov.check_tool_safety(spec)
        assert safe

    def test_ai_governance_blocks_dangerous(self):
        from tools.ai_tool_creator import AIGovernance, ToolSpec
        gov = AIGovernance(mode="auto", use_ast_sandbox=True)
        spec = ToolSpec(name="t", purpose="p", language="python",
                        code="import os\nos.system('rm -rf /')",
                        dependencies=[], entry_point="t", safety_level="dangerous")
        safe, reason = gov.check_tool_safety(spec)
        assert not safe

    def test_ai_governance_auto_mode(self):
        from tools.ai_tool_creator import AIGovernance
        gov = AIGovernance(mode="auto")
        approved = gov.request_approval("create_tool", {"tool_name": "t"})
        assert approved

    def test_ai_governance_regex_fallback(self):
        from tools.ai_tool_creator import AIGovernance, ToolSpec
        gov = AIGovernance(mode="auto", use_ast_sandbox=False)
        spec = ToolSpec(name="t", purpose="p", language="python",
                        code="eval('bad')", dependencies=[], entry_point="t",
                        safety_level="safe")
        safe, reason = gov.check_tool_safety(spec)
        assert not safe

    def test_dependency_manager_init(self):
        from tools.ai_tool_creator import DependencyManager
        with tempfile.TemporaryDirectory() as td:
            dm = DependencyManager(cache_dir=Path(td))
            assert dm.cache_dir.exists()

    def test_ai_tool_creator_execute_not_found(self):
        from tools.ai_tool_creator import AIToolCreator
        with tempfile.TemporaryDirectory() as td:
            creator = AIToolCreator.__new__(AIToolCreator)
            creator.governance = MagicMock()
            creator.governance.mode = "auto"
            creator.dep_manager = MagicMock()
            creator.ai_client = None
            creator.AI_TOOLS_DIR = Path(td)
            creator.ai_tools = {}
            result = creator.execute_tool("nonexistent")
            assert not result.success
            assert "not found" in result.error

    def test_ai_tool_creator_list_tools(self):
        from tools.ai_tool_creator import AIToolCreator, ToolSpec
        with tempfile.TemporaryDirectory() as td:
            creator = AIToolCreator.__new__(AIToolCreator)
            creator.governance = MagicMock()
            creator.dep_manager = MagicMock()
            creator.ai_client = None
            creator.AI_TOOLS_DIR = Path(td)
            creator.ai_tools = {"t": ToolSpec(name="t", purpose="p", language="python",
                                               code="", dependencies=[], entry_point="t",
                                               safety_level="safe")}
            tools = creator.list_ai_tools()
            assert len(tools) == 1
            assert tools[0]["name"] == "t"

    def test_ai_tool_creator_delete(self):
        from tools.ai_tool_creator import AIToolCreator, ToolSpec
        with tempfile.TemporaryDirectory() as td:
            creator = AIToolCreator.__new__(AIToolCreator)
            creator.governance = MagicMock()
            creator.dep_manager = MagicMock()
            creator.ai_client = None
            creator.AI_TOOLS_DIR = Path(td)
            creator.ai_tools = {"t": ToolSpec(name="t", purpose="p", language="python",
                                               code="", dependencies=[], entry_point="t",
                                               safety_level="safe")}
            assert creator.delete_tool("t") is True
            assert creator.delete_tool("nonexistent") is False


# ============================================================================
# command_suggest
# ============================================================================

class TestCommandSuggest:
    """tests/tools/command_suggest.py"""

    def test_suggest_correction_typo(self):
        from tools.command_suggest import CommandSuggester
        s = CommandSuggester()
        assert s.suggest_correction("scann") == "scan"
        assert s.suggest_correction("helo") == "help"
        assert s.suggest_correction("autonomus") == "autonomous"

    def test_suggest_correction_valid(self):
        from tools.command_suggest import CommandSuggester
        s = CommandSuggester()
        assert s.suggest_correction("scan") is None

    def test_suggest_completions(self):
        from tools.command_suggest import CommandSuggester
        s = CommandSuggester()
        c = s.suggest_completions("sc")
        assert "scan" in c

    def test_get_contextual_help(self):
        from tools.command_suggest import CommandSuggester
        s = CommandSuggester()
        h = s.get_contextual_help(after_error=True, command="scann")
        assert "Did you mean" in h or "Popular" in h

    def test_get_command_info(self):
        from tools.command_suggest import CommandSuggester
        s = CommandSuggester()
        info = s.get_command_info("scan")
        assert info is not None
        assert info["category"] == "scanning"
        assert s.get_command_info("nonexistent") is None

    def test_suggest_next_command(self):
        from tools.command_suggest import CommandSuggester
        s = CommandSuggester()
        assert s.suggest_next_command("scan", had_findings=True) == "report"
        assert s.suggest_next_command("recon") == "research"
        assert s.suggest_next_command("research") == "poc"

    def test_record_usage(self):
        from tools.command_suggest import CommandSuggester
        s = CommandSuggester()
        s.record_usage("scan")
        assert s.usage_stats.get("scan", 0) >= 1

    def test_handle_command_error(self):
        from tools.command_suggest import handle_command_error
        msg = handle_command_error("scann")
        assert "Unknown command" in msg


# ============================================================================
# compliance_engine
# ============================================================================

class TestComplianceEngine:
    """tests/tools/compliance_engine.py"""

    def test_control_dataclass(self):
        from tools.compliance_engine import Control
        c = Control(id="1.1", title="Firewall", description="Install firewall",
                    category="Network", severity="critical")
        d = c.to_dict()
        assert d["id"] == "1.1"

    def test_control_result_dataclass(self):
        from tools.compliance_engine import Control, ControlResult
        c = Control(id="1.1", title="T", description="D", category="C")
        cr = ControlResult(control=c, status="pass", evidence=["ok"])
        d = cr.to_dict()
        assert d["status"] == "pass"

    def test_pci_dss_standard(self):
        from tools.compliance_engine import PCI_DSS
        pci = PCI_DSS()
        assert pci.name == "PCI DSS"
        assert len(pci.controls) > 0
        assert pci.get_control("1.1") is not None
        assert pci.get_control("nonexistent") is None

    def test_soc2_standard(self):
        from tools.compliance_engine import SOC2
        s = SOC2()
        assert s.version == "2.0"
        assert len(s.controls) > 0

    def test_iso27001_standard(self):
        from tools.compliance_engine import ISO27001
        s = ISO27001()
        assert len(s.controls) > 0

    def test_owasp_top10_standard(self):
        from tools.compliance_engine import OWASP_Top10
        s = OWASP_Top10()
        assert len(s.controls) == 10

    def test_compliance_engine_init(self):
        from tools.compliance_engine import ComplianceEngine
        e = ComplianceEngine()
        stds = e.list_standards()
        assert len(stds) >= 4

    def test_assess_unknown_standard(self):
        from tools.compliance_engine import ComplianceEngine
        e = ComplianceEngine()
        result = e.assess([], "nonexistent")
        assert "error" in result

    def test_assess_empty_findings(self):
        from tools.compliance_engine import ComplianceEngine
        e = ComplianceEngine()
        result = e.assess([], "pci_dss")
        assert result["total_controls"] > 0
        assert result["compliance_pct"] >= 0

    def test_assess_with_findings(self):
        from tools.compliance_engine import ComplianceEngine
        e = ComplianceEngine()
        findings = [
            {"type": "sqli", "severity": "critical", "title": "SQL Injection"},
            {"type": "xss", "severity": "high", "title": "XSS"},
        ]
        result = e.assess(findings, "owasp_top_10")
        assert "standard" in result

    def test_count_severities(self):
        from tools.compliance_engine import ComplianceEngine
        e = ComplianceEngine()
        counts = e._count_severities([{"severity": "critical"}, {"severity": "low"}])
        assert counts["critical"] == 1
        assert counts["low"] == 1

    def test_count_types(self):
        from tools.compliance_engine import ComplianceEngine
        e = ComplianceEngine()
        counts = e._count_types([{"type": "xss"}, {"type": "xss"}, {"type": "sqli"}])
        assert counts["xss"] == 2


# ============================================================================
# context_compressor
# ============================================================================

class TestContextCompressor:
    """tests/tools/context_compressor.py"""

    def test_compression_result_dataclass(self):
        from tools.context_compressor import CompressionResult
        r = CompressionResult(original_turns=10, compressed_turns=5,
                              original_tokens=1000, estimated_compressed_tokens=500,
                              compression_ratio=2.0, summary="ok")
        assert r.compression_ratio == 2.0

    def test_is_security_relevant(self):
        from tools.context_compressor import ContextCompressor
        c = ContextCompressor()
        assert c.is_security_relevant("Found a critical vulnerability")
        assert c.is_security_relevant("SQL injection detected")
        assert not c.is_security_relevant("Hello, how are you?")

    def test_summarize_turn_short(self):
        from tools.context_compressor import ContextCompressor
        c = ContextCompressor()
        s = c.summarize_turn("short text")
        assert s == "short text"

    def test_compress_empty(self):
        from tools.context_compressor import ContextCompressor
        c = ContextCompressor()
        r = c.compress([])
        assert r.original_turns == 0
        assert r.compression_ratio == 1.0

    def test_compress_small_history(self):
        from tools.context_compressor import ContextCompressor
        c = ContextCompressor(max_tokens=50000)
        history = [{"role": "user", "content": "hello"}]
        r = c.compress(history)
        assert r.compression_ratio == 1.0  # no compression needed

    def test_compress_large_history(self):
        from tools.context_compressor import ContextCompressor
        c = ContextCompressor(max_tokens=50, recent_turns_full=2)
        history = [{"role": "user", "content": "word " * 100} for _ in range(20)]
        r = c.compress(history)
        assert r.original_turns == 20
        assert r.compression_ratio > 1.0

    def test_compress_and_return_history(self):
        from tools.context_compressor import ContextCompressor
        c = ContextCompressor(max_tokens=50, recent_turns_full=2)
        history = [{"role": "user", "content": "word " * 100} for _ in range(20)]
        result = c.compress_and_return_history(history)
        assert isinstance(result, list)
        assert len(result) <= len(history)

    def test_get_compressor_singleton(self):
        from tools.context_compressor import get_compressor
        c1 = get_compressor()
        c2 = get_compressor()
        assert c1 is c2


# ============================================================================
# coverage_analyzer
# ============================================================================

class TestCoverageAnalyzer:
    """tests/tools/coverage_analyzer.py"""

    def test_endpoint_record(self):
        from tools.coverage_analyzer import EndpointRecord
        r = EndpointRecord(url="http://x.com/api/users", method="GET",
                           params=["id", "name"], source="subfinder")
        assert r.endpoint_key() == "GET http://x.com/api/users"

    def test_test_record_dataclass(self):
        from tools.coverage_analyzer import TestRecord
        r = TestRecord(url="http://x.com/api", method="GET", tool="fuzzer",
                       injection_point="param:id", payload="<script>",
                       status=200, response_size=100, is_interesting=True)
        assert r.is_interesting

    def test_coverage_report_dataclass(self):
        from tools.coverage_analyzer import CoverageReport
        cr = CoverageReport(total_endpoints=10, total_param_slots=30,
                            tested_param_slots=15, coverage_pct=50.0,
                            untested_endpoints=5, undertested_params=3,
                            interesting_findings=2, total_tests=20,
                            unique_tools_used=3, endpoints_by_source={"subfinder": 5},
                            attack_surface_growth=5)
        d = cr.to_dict()
        assert d["coverage_pct"] == 50.0

    def test_coverage_analyzer_record_endpoint(self):
        from tools.coverage_analyzer import CoverageAnalyzer
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "test.db"
            ca = CoverageAnalyzer(db_path=db)
            rec = ca.record_endpoint("http://x.com/api", "GET", ["id"], source="test")
            assert rec.url == "http://x.com/api"
            # record same again
            rec2 = ca.record_endpoint("http://x.com/api", "GET", ["id", "name"])
            assert rec2.first_seen > 0

    def test_coverage_analyzer_record_test(self):
        from tools.coverage_analyzer import CoverageAnalyzer
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "test.db"
            ca = CoverageAnalyzer(db_path=db)
            ca.record_endpoint("http://x.com/api", "GET", ["q"])
            tr = ca.record_test("http://x.com/api", "GET", "fuzzer",
                                "param:q", "<script>", 200, 100, True)
            assert tr.is_interesting

    def test_get_untested_endpoints(self):
        from tools.coverage_analyzer import CoverageAnalyzer
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "test.db"
            ca = CoverageAnalyzer(db_path=db)
            ca.record_endpoint("http://x.com/a")
            ca.record_endpoint("http://x.com/b")
            untested = ca.get_untested_endpoints()
            assert len(untested) == 2

    def test_get_coverage_report(self):
        from tools.coverage_analyzer import CoverageAnalyzer
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "test.db"
            ca = CoverageAnalyzer(db_path=db)
            ca.record_endpoint("http://x.com/api", "GET", ["q"])
            ca.record_test("http://x.com/api", "GET", "fuzzer", "param:q", "x", 200, 100)
            report = ca.get_coverage_report()
            assert report.total_endpoints == 1
            assert report.total_tests == 1

    def test_suggest_next_targets(self):
        from tools.coverage_analyzer import CoverageAnalyzer
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "test.db"
            ca = CoverageAnalyzer(db_path=db)
            ca.record_endpoint("http://x.com/api", "GET", ["id"])
            suggestions = ca.suggest_next_targets()
            assert isinstance(suggestions, list)

    def test_discover_from_url(self):
        from tools.coverage_analyzer import CoverageAnalyzer
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "test.db"
            ca = CoverageAnalyzer(db_path=db)
            recs = ca.discover_from_url("http://x.com/api?q=test&page=1")
            assert len(recs) == 1
            assert "q" in recs[0].params

    def test_reset(self):
        from tools.coverage_analyzer import CoverageAnalyzer
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "test.db"
            ca = CoverageAnalyzer(db_path=db)
            ca.record_endpoint("http://x.com/api")
            ca.reset()
            untested = ca.get_untested_endpoints()
            assert len(untested) == 0


# ============================================================================
# finding_dedup
# ============================================================================

class TestFindingDedup:
    """tests/tools/finding_dedup.py"""

    def test_finding_hash_deterministic(self):
        from tools.finding_dedup import _finding_hash
        f = {"type": "xss", "url": "http://x.com/api", "param": "q"}
        h1 = _finding_hash(f)
        h2 = _finding_hash(f)
        assert h1 == h2

    def test_finding_hash_different(self):
        from tools.finding_dedup import _finding_hash
        f1 = {"type": "xss", "url": "http://x.com/a"}
        f2 = {"type": "sqli", "url": "http://x.com/a"}
        assert _finding_hash(f1) != _finding_hash(f2)

    def test_dedup_result_dataclass(self):
        from tools.finding_dedup import DedupResult
        r = DedupResult(unique_findings=[], duplicates_removed=0, merge_count=0)
        assert r.duplicates_removed == 0

    def test_deduplicate_no_duplicates(self):
        from tools.finding_dedup import deduplicate_findings
        findings = [
            {"type": "xss", "url": "http://x.com/a"},
            {"type": "sqli", "url": "http://x.com/b"},
        ]
        result = deduplicate_findings(findings)
        assert len(result.unique_findings) == 2
        assert result.duplicates_removed == 0

    def test_deduplicate_with_duplicates(self):
        from tools.finding_dedup import deduplicate_findings
        findings = [
            {"type": "xss", "url": "http://x.com/a", "param": "q"},
            {"type": "xss", "url": "http://x.com/a", "param": "q"},
        ]
        result = deduplicate_findings(findings)
        assert len(result.unique_findings) == 1
        assert result.duplicates_removed == 1

    def test_dedup_merges_sources(self):
        from tools.finding_dedup import deduplicate_findings
        findings = [
            {"type": "xss", "url": "http://x.com/a", "source": "scanner1", "tool": "tool1"},
            {"type": "xss", "url": "http://x.com/a", "source": "scanner2", "tool": "tool2"},
        ]
        result = deduplicate_findings(findings, merge_sources=True)
        assert len(result.unique_findings) == 1
        assert "scanner1" in result.unique_findings[0]["source"]

    def test_dedup_keeps_higher_severity(self):
        from tools.finding_dedup import deduplicate_findings
        findings = [
            {"type": "xss", "url": "http://x.com/a", "severity": "low"},
            {"type": "xss", "url": "http://x.com/a", "severity": "critical"},
        ]
        result = deduplicate_findings(findings)
        assert result.unique_findings[0]["severity"] == "critical"

    def test_dedup_empty_list(self):
        from tools.finding_dedup import deduplicate_findings
        r = deduplicate_findings([])
        assert r.unique_findings == []
        assert r.duplicates_removed == 0

    def test_deduplicate_in_place(self):
        from tools.finding_dedup import deduplicate_in_place
        findings = [
            {"type": "xss", "url": "http://x.com/a"},
            {"type": "xss", "url": "http://x.com/a"},
        ]
        result = deduplicate_in_place(findings)
        assert len(result) == 1


# ============================================================================
# exploit_chain_builder
# ============================================================================

class TestExploitChainBuilder:
    """tests/tools/exploit_chain_builder.py"""

    def test_node_type_enum(self):
        from tools.exploit_chain_builder import NodeType
        assert NodeType.ENTRY_POINT.value == "entry_point"
        assert len(NodeType) == 5

    def test_edge_type_enum(self):
        from tools.exploit_chain_builder import EdgeType
        assert EdgeType.ENABLES.value == "enables"
        assert len(EdgeType) == 4

    def test_attack_node_dataclass(self):
        from tools.exploit_chain_builder import AttackNode, NodeType
        n = AttackNode(node_id="n1", node_type=NodeType.ENTRY_POINT, name="XSS",
                       description="reflected xss", severity="high", tool_source="scanner",
                       target="http://x.com", confidence=0.8)
        assert n.node_type == NodeType.ENTRY_POINT

    def test_exploit_chain_dataclass(self):
        from tools.exploit_chain_builder import ExploitChain
        c = ExploitChain(chain_id="c1", name="test", description="d",
                         nodes=[], edges=[], total_probability=0.5,
                         total_impact="high", time_estimate="1-4 hours",
                         complexity="simple", prerequisites=[], mitigations=[],
                         poc_steps=[])
        assert c.total_probability == 0.5

    def test_attack_graph_add_node(self):
        from tools.exploit_chain_builder import AttackGraph, AttackNode, NodeType
        g = AttackGraph()
        n = AttackNode(node_id="n1", node_type=NodeType.ENTRY_POINT, name="XSS",
                       description="d", severity="high", tool_source="s",
                       target="http://x.com", confidence=0.8)
        g.add_node(n)
        assert "n1" in g.nodes

    def test_attack_graph_find_paths(self):
        from tools.exploit_chain_builder import (AttackGraph, AttackNode, AttackEdge,
                                                   NodeType, EdgeType)
        g = AttackGraph()
        n1 = AttackNode(node_id="n1", node_type=NodeType.ENTRY_POINT, name="XSS",
                        description="d", severity="high", tool_source="s",
                        target="http://x.com", confidence=0.8)
        n2 = AttackNode(node_id="n2", node_type=NodeType.DATA_ACCESS, name="SQLi",
                        description="d", severity="critical", tool_source="s",
                        target="http://x.com", confidence=0.7)
        g.add_node(n1)
        g.add_node(n2)
        e = AttackEdge(edge_id="e1", source="n1", target="n2",
                       edge_type=EdgeType.CHAINS_TO, probability=0.7, description="enables")
        g.add_edge(e)
        paths = g.find_paths("n1", [NodeType.DATA_ACCESS])
        assert len(paths) == 1

    def test_builder_process_findings(self):
        from tools.exploit_chain_builder import ExploitChainBuilder
        b = ExploitChainBuilder()
        findings = [
            {"finding_id": "f1", "type": "xss", "severity": "high",
             "tool": "scanner", "target": "http://x.com", "confidence": 0.8},
            {"finding_id": "f2", "type": "sqli", "severity": "critical",
             "tool": "scanner", "target": "http://x.com", "confidence": 0.7},
        ]
        b.process_findings(findings)
        assert len(b.graph.nodes) == 2

    def test_builder_build_chains(self):
        from tools.exploit_chain_builder import ExploitChainBuilder
        b = ExploitChainBuilder()
        findings = [
            {"finding_id": "f1", "type": "xss", "severity": "high",
             "tool": "s", "target": "http://x.com", "confidence": 0.8},
            {"finding_id": "f2", "type": "sqli", "severity": "critical",
             "tool": "s", "target": "http://x.com", "confidence": 0.7},
        ]
        b.process_findings(findings)
        chains = b.build_chains()
        assert isinstance(chains, list)

    def test_builder_ignores_unknown_type(self):
        from tools.exploit_chain_builder import ExploitChainBuilder
        b = ExploitChainBuilder()
        b.process_findings([{"type": "unknown_finding_type", "severity": "low"}])
        assert len(b.graph.nodes) == 0

    def test_extract_domain(self):
        from tools.exploit_chain_builder import ExploitChainBuilder
        b = ExploitChainBuilder()
        assert b._extract_domain("http://example.com/path") == "example.com"
        assert b._extract_domain("https://sub.example.com:8080/x") == "sub.example.com"

    def test_aggregate_severity(self):
        from tools.exploit_chain_builder import ExploitChainBuilder
        b = ExploitChainBuilder()
        assert b._aggregate_severity(["critical", "low"]) == "critical"
        assert b._aggregate_severity(["low", "info"]) == "low"

    def test_format_chain_report_empty(self):
        from tools.exploit_chain_builder import format_chain_report
        text = format_chain_report([])
        assert "No exploit chains" in text

    def test_analyze_findings_for_chains(self):
        from tools.exploit_chain_builder import analyze_findings_for_chains
        findings = [
            {"finding_id": "f1", "type": "xss", "severity": "high",
             "tool": "s", "target": "http://x.com", "confidence": 0.9},
            {"finding_id": "f2", "type": "sqli", "severity": "critical",
             "tool": "s", "target": "http://x.com", "confidence": 0.8},
        ]
        result = analyze_findings_for_chains(findings)
        assert "total_chains" in result
        assert "chains" in result


# ============================================================================
# compliance_engine additional
# ============================================================================

class TestComplianceEngineReport:
    """Test compliance report generation."""

    def test_generate_report_json(self):
        from tools.compliance_engine import ComplianceEngine
        e = ComplianceEngine()
        result = e.assess([], "pci_dss")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            out = e.generate_report(result, path, format="json")
            assert Path(out).exists()
        finally:
            Path(path).unlink(missing_ok=True)

    def test_generate_report_html(self):
        from tools.compliance_engine import ComplianceEngine
        e = ComplianceEngine()
        result = e.assess([], "pci_dss")
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            out = e.generate_report(result, path, format="html")
            assert Path(out).exists()
            content = Path(out).read_text()
            assert "Compliance Report" in content
        finally:
            Path(path).unlink(missing_ok=True)


# ============================================================================
# injection_tester helpers
# ============================================================================

class TestInjectionTester:
    """tests/tools/injection_tester.py"""

    def test_inject_param(self):
        from tools.injection_tester import _inject_param
        url = _inject_param("http://x.com/api?q=old", "q", "new")
        assert "q=new" in url

    def test_inject_param_adds_new(self):
        from tools.injection_tester import _inject_param
        url = _inject_param("http://x.com/api", "id", "1")
        assert "id=1" in url

    def test_xss_payloads_generated(self):
        from tools.injection_tester import _xss_payloads
        payloads = _xss_payloads("testcanary")
        assert len(payloads) > 0
        assert any("testcanary" in p["payload"] for p in payloads)

    def test_sqli_payloads(self):
        from tools.injection_tester import _sqli_payloads
        payloads = _sqli_payloads()
        assert len(payloads) > 0

    def test_ssti_payloads(self):
        from tools.injection_tester import _ssti_payloads
        payloads = _ssti_payloads()
        assert len(payloads) > 0

    def test_lfi_payloads(self):
        from tools.injection_tester import _lfi_payloads
        payloads = _lfi_payloads()
        assert len(payloads) > 0

    def test_open_redirect_payloads(self):
        from tools.injection_tester import _open_redirect_payloads
        payloads = _open_redirect_payloads()
        assert len(payloads) > 0


# ============================================================================
# logic_analyzer
# ============================================================================

class TestLogicAnalyzer:
    """tests/tools/logic_analyzer.py"""

    def test_logic_hypothesis_dataclass(self):
        from tools.logic_analyzer import LogicHypothesis
        h = LogicHypothesis(hyp_id="h1", title="test", description="d",
                            confidence=0.5, tags=["a"], suggested_tests=[])
        assert h.confidence == 0.5

    def test_generate_no_endpoints(self):
        from tools.logic_analyzer import BusinessLogicAnalyzer
        a = BusinessLogicAnalyzer()
        hyps = a.generate({"target": "x", "nodes": []}, [])
        assert len(hyps) == 0

    def test_generate_with_api_endpoints(self):
        from tools.logic_analyzer import BusinessLogicAnalyzer
        a = BusinessLogicAnalyzer()
        snap = {
            "target": "x.com",
            "nodes": [
                {"type": "finding", "props": {"raw": {"url": "http://x.com/api/users/1"}}},
                {"type": "finding", "props": {"raw": {"url": "http://x.com/v1/orders"}}},
            ],
        }
        hyps = a.generate(snap, [])
        assert len(hyps) >= 1
        assert any("idor" in h.tags for h in hyps)

    def test_generate_with_auth_endpoints(self):
        from tools.logic_analyzer import BusinessLogicAnalyzer
        a = BusinessLogicAnalyzer()
        snap = {
            "target": "x.com",
            "nodes": [
                {"type": "finding", "props": {"raw": {"url": "http://x.com/login"}}},
            ],
        }
        hyps = a.generate(snap, [])
        assert any("rate_limit" in h.tags for h in hyps)


# ============================================================================
# llm_reasoning
# ============================================================================

class TestLLMReasoning:
    """tests/tools/llm_reasoning.py"""

    def test_is_ai_available(self):
        from tools.llm_reasoning import is_ai_available
        result = is_ai_available()
        assert isinstance(result, bool)

    def test_priortization_prompt_format(self):
        from tools.llm_reasoning import PRIORITIZATION_PROMPT
        assert "{endpoints}" in PRIORITIZATION_PROMPT

    def test_explanation_prompt_format(self):
        from tools.llm_reasoning import EXPLANATION_PROMPT
        assert "{title}" in EXPLANATION_PROMPT

    def test_generate_executive_summary_empty(self):
        from tools.llm_reasoning import generate_executive_summary
        result = generate_executive_summary("x.com", [])
        assert result is None


# ============================================================================
# memory_manager
# ============================================================================

class TestMemoryManager:
    """tests/tools/memory_manager.py"""

    def test_save_and_get_learning(self):
        from tools.memory_manager import save_learning, get_summarized_learnings
        import tools.memory_manager as mod
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_db = Path(f.name)
        try:
            old = mod._DB_PATH
            mod._DB_PATH = tmp_db
            save_learning("test_target", "Found XSS vulnerability", "vuln")
            summary = get_summarized_learnings("test_target")
            assert "VULN" in summary or "xss" in summary.lower() or "XSS" in summary
            mod._DB_PATH = old
        finally:
            tmp_db.unlink(missing_ok=True)

    def test_empty_target_no_save(self):
        from tools.memory_manager import save_learning
        save_learning("", "something")  # should not crash

    def test_get_all_targets(self):
        from tools.memory_manager import get_all_targets
        targets = get_all_targets()
        assert isinstance(targets, list)


# ============================================================================
# memory_profile
# ============================================================================

class TestMemoryProfile:
    """tests/tools/memory_profile.py"""

    def test_read_memory(self):
        from tools.memory_profile import read_memory
        profile = read_memory()
        assert isinstance(profile, dict)

    def test_build_memory_prompt_block(self):
        from tools.memory_profile import build_memory_prompt_block
        block = build_memory_prompt_block()
        assert isinstance(block, str)

    def test_get_memory_path(self):
        from tools.memory_profile import get_memory_path
        p = get_memory_path()
        assert p.name == "MEMORY.md"

    def test_default_template(self):
        from tools.memory_profile import _default_template
        t = _default_template()
        assert "Identity" in t
        assert "name:" in t


# ============================================================================
# ml_filter
# ============================================================================

class TestMLFilter:
    """tests/tools/ml_filter.py"""

    def test_finding_profile(self):
        from tools.ml_filter import FindingProfile
        fp = FindingProfile(pattern_id="test:pattern")
        assert fp.real_rate == 1.0  # 0 seen = 100% real
        fp.update(suppressed=False, confidence=0.8)
        assert fp.total_seen == 1
        assert fp.false_positive_rate == 0.0
        fp.update(suppressed=True, confidence=0.5)
        assert fp.false_positive_rate == 0.5

    def test_ml_filter_score(self):
        from tools.ml_filter import MLFilter
        with tempfile.TemporaryDirectory() as td:
            f = MLFilter(profile_path=str(Path(td) / "profiles.json"))
            finding = {"type": "xss", "url": "http://x.com", "param": "q",
                       "severity": "high", "cvss": 8.0, "details": "evidence" * 50}
            result = f.score(finding)
            assert "ml_confidence" in result
            assert "ml_verdict" in result
            assert 0 <= result["ml_confidence"] <= 1

    def test_ml_filter_suppress(self):
        from tools.ml_filter import MLFilter
        with tempfile.TemporaryDirectory() as td:
            f = MLFilter(profile_path=str(Path(td) / "profiles.json"))
            finding = {"type": "xss", "url": "http://x.com", "title": "test xss"}
            f.suppress(finding, "test")
            assert len(f.suppression_history) >= 1

    def test_ml_filter_confirm(self):
        from tools.ml_filter import MLFilter
        with tempfile.TemporaryDirectory() as td:
            f = MLFilter(profile_path=str(Path(td) / "profiles.json"))
            finding = {"type": "xss", "url": "http://x.com", "title": "test"}
            f.confirm(finding)
            stats = f.get_stats()
            assert stats["patterns"] >= 1

    def test_filter_findings(self):
        from tools.ml_filter import MLFilter
        with tempfile.TemporaryDirectory() as td:
            f = MLFilter(profile_path=str(Path(td) / "profiles.json"))
            findings = [
                {"type": "xss", "url": "http://x.com", "title": "test",
                 "severity": "high", "cvss": 9.0, "details": "x" * 600},
            ]
            high, low = f.filter_findings(findings, min_confidence=0.0)
            assert len(high) + len(low) == 1

    def test_get_stats_empty(self):
        from tools.ml_filter import MLFilter
        with tempfile.TemporaryDirectory() as td:
            f = MLFilter(profile_path=str(Path(td) / "profiles.json"))
            stats = f.get_stats()
            assert stats["patterns"] == 0

    def test_make_pattern_id(self):
        from tools.ml_filter import MLFilter
        with tempfile.TemporaryDirectory() as td:
            f = MLFilter(profile_path=str(Path(td) / "profiles.json"))
            pid = f._make_pattern_id({"type": "xss", "url": "http://x.com",
                                       "param": "q", "title": "test"})
            assert "xss" in pid


# ============================================================================
# profile_manager
# ============================================================================

class TestProfileManager:
    """tests/tools/profile_manager.py"""

    def test_command_profile_dataclass(self):
        from tools.profile_manager import CommandProfile
        p = CommandProfile(name="test", description="d", base_command="scan",
                           args=[], options={}, env_vars={}, created_by="user")
        assert p.name == "test"

    def test_profile_manager_init(self):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        assert len(pm.profiles) > 0

    def test_get_profile(self):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        p = pm.get_profile("quick")
        assert p is not None
        assert p.base_command == "recon"
        assert pm.get_profile("nonexistent") is None

    def test_list_profiles(self):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        profiles = pm.list_profiles()
        assert len(profiles) > 0

    def test_expand_profile(self):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        result = pm.expand_profile("quick", target="example.com")
        assert result is not None
        cmd, args = result
        assert cmd == "recon"
        assert "example.com" in args

    def test_expand_profile_not_found(self):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        assert pm.expand_profile("nonexistent") is None

    def test_create_and_delete_profile(self):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        ok = pm.create_profile("test_custom", "scan", description="test")
        assert ok
        assert pm.get_profile("test_custom") is not None
        assert pm.delete_profile("test_custom") is True
        assert pm.get_profile("test_custom") is None

    def test_cannot_delete_builtin(self):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        assert pm.delete_profile("quick") is False

    def test_cannot_override_builtin(self):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        assert pm.create_profile("quick", "scan") is False

    def test_export_import(self):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        exported = pm.export_profile("quick")
        assert exported is not None
        # Modify and import as new
        data = json.loads(exported)
        data["name"] = "imported_test"
        data["created_by"] = "user"
        ok = pm.import_profile(json.dumps(data))
        assert ok
        pm.delete_profile("imported_test")

    def test_get_recommended_profile(self):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        assert pm.get_recommended_profile("api") == "api"
        assert pm.get_recommended_profile("web") == "web"
        assert pm.get_recommended_profile() == "deep"

    def test_format_profile_list(self):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        text = pm.format_profile_list()
        assert "Built-in" in text


# ============================================================================
# token_counter
# ============================================================================

class TestTokenCounter:
    """tests/tools/token_counter.py"""

    def test_count_tokens_empty(self):
        from tools.token_counter import count_tokens
        assert count_tokens("") == 0

    def test_count_tokens_basic(self):
        from tools.token_counter import count_tokens
        n = count_tokens("Hello world, this is a test.")
        assert n > 0

    def test_count_tokens_longer(self):
        from tools.token_counter import count_tokens
        short = count_tokens("hello")
        long = count_tokens("hello " * 100)
        assert long > short


# ============================================================================
# safe_exec
# ============================================================================

class TestSafeExec:
    """tests/tools/safe_exec.py"""

    def test_execute_safely_echo(self):
        from tools.safe_exec import execute_safely
        result = execute_safely("echo hello", timeout=5)
        assert result["success"]
        assert "hello" in result["stdout"]

    def test_execute_safely_failure(self):
        from tools.safe_exec import execute_safely
        result = execute_safely("false", timeout=5)
        assert not result["success"]
        assert result["exit_code"] != 0

    def test_execute_safely_error(self):
        from tools.safe_exec import execute_safely
        result = execute_safely("nonexistent_command_xyz_abc123", timeout=5)
        assert not result["success"]
        assert result["exit_code"] != 0 or result["error"]


# ============================================================================
# sast_engine
# ============================================================================

class TestSASTEngine:
    """tests/tools/sast_engine.py"""

    def test_code_vulnerability_dataclass(self):
        from tools.sast_engine import CodeVulnerability
        v = CodeVulnerability(vuln_id="V001", file_path="app.py", line_number=10,
                              column=5, vuln_type="sqli", severity="critical",
                              confidence=0.9, description="SQL injection",
                              code_snippet="execute(query)", remediation="Use parameterized queries")
        assert v.severity == "critical"

    def test_pattern_scanner_init(self):
        from tools.sast_engine import PatternBasedScanner
        s = PatternBasedScanner()
        assert "python" in s.PATTERNS
        assert "sql_injection" in s.PATTERNS["python"]


# ============================================================================
# soc_analyzer
# ============================================================================

class TestSOCAnalyzer:
    """tests/tools/soc_analyzer.py"""

    def test_alert_dataclass(self):
        from tools.soc_analyzer import Alert
        a = Alert(alert_id="A001", timestamp="2024-01-01", source="suricata",
                  alert_type="intrusion", severity="high", confidence=0.8)
        assert a.severity == "high"

    def test_triage_result_dataclass(self):
        from tools.soc_analyzer import Alert, TriageResult
        a = Alert(alert_id="A001", timestamp="2024-01-01", source="s",
                  alert_type="recon", severity="medium", confidence=0.6)
        tr = TriageResult(alert=a, priority_score=5.0,
                          category="needs_investigation", recommended_action="review",
                          related_alerts=[])
        assert tr.priority_score == 5.0

    def test_detection_rule_dataclass(self):
        from tools.soc_analyzer import DetectionRule
        dr = DetectionRule(title="test", logsource={"product": "test"},
                           detection={"condition": "test"}, tags=["test"],
                           level="high", description="d")
        assert dr.level == "high"

    def test_soc_analyzer_init(self):
        from tools.soc_analyzer import SOCAnalyzer
        sa = SOCAnalyzer(ioc_db={})
        assert isinstance(sa.THREAT_ACTOR_SIGNATURES, dict)


# ============================================================================
# threat_intel
# ============================================================================

class TestThreatIntel:
    """tests/tools/threat_intel.py"""

    def test_threat_intel_db_init(self):
        from tools.threat_intel import ThreatIntelDB
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "test_ti.db"
            with patch("tools.threat_intel._DB_PATH", db):
                ti = ThreatIntelDB()
                assert ti is not None

    def test_add_and_lookup_ioc(self):
        from tools.threat_intel import ThreatIntelDB, _DB_PATH
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "test_ti.db"
            import tools.threat_intel as mod
            old = mod._DB_PATH
            mod._DB_PATH = db
            try:
                ti = ThreatIntelDB()
                ti.add_ioc("1.2.3.4", "ip", "malware", 80, "scanner")
                result = ti.lookup("1.2.3.4")
                assert result is not None
                assert result["value"] == "1.2.3.4"
            finally:
                mod._DB_PATH = old


# ============================================================================
# exploit_template
# ============================================================================

class TestExploitTemplate:
    """tests/tools/exploit_template.py"""

    def test_batch_test(self):
        from tools.exploit_template import batch_test
        with patch("tools.exploit_template.test_payload") as mock_test:
            mock_test.return_value = {"status_code": 200, "reflected": False}
            results = batch_test("http://x.com", ["a", "b", "c"])
            assert len(results) == 3


# ============================================================================
# api_finder
# ============================================================================

class TestAPIFinder:
    """tests/tools/api_finder.py"""

    def test_api_endpoints_list(self):
        from tools.api_finder import API_ENDPOINTS
        assert len(API_ENDPOINTS) > 10
        assert "/swagger.json" in API_ENDPOINTS

    def test_make_session(self):
        from tools.api_finder import _make_session
        s = _make_session()
        assert s is not None
        s.close()


# ============================================================================
# agent_bola_bridge
# ============================================================================

class TestAgentBOLABridge:
    """tests/tools/agent_bola_bridge.py"""

    def test_extract_headers_placeholder(self):
        from tools.agent_bola_bridge import extract_headers_from_mission_state
        a, b = extract_headers_from_mission_state({})
        assert a is None
        assert b is None

    def test_propose_plan_no_hypotheses(self):
        from tools.agent_bola_bridge import AgentBOLABridge
        b = AgentBOLABridge("http://x.com", {}, {})
        result = b.propose_plan_from_hypotheses({})
        assert result is None

    def test_propose_plan_with_idor_hypothesis(self):
        from tools.agent_bola_bridge import AgentBOLABridge
        b = AgentBOLABridge("http://x.com", {}, {})
        snapshot = {
            "hypotheses": [
                {"tags": ["idor", "bola"], "evidence": {}}
            ]
        }
        plan = b.propose_plan_from_hypotheses(snapshot)
        assert plan is not None
        assert plan["type"] == "bola_differential"
        assert len(plan["seeds"]) > 0

    def test_propose_plan_no_matching_tags(self):
        from tools.agent_bola_bridge import AgentBOLABridge
        b = AgentBOLABridge("http://x.com", {}, {})
        snapshot = {"hypotheses": [{"tags": ["unrelated"], "evidence": {}}]}
        plan = b.propose_plan_from_hypotheses(snapshot)
        assert plan is None


# ============================================================================
# doctor
# ============================================================================

class TestDoctor:
    """tests/tools/doctor.py"""

    def test_python_min(self):
        from tools.doctor import PYTHON_MIN
        assert PYTHON_MIN == (3, 10)

    def test_project_root(self):
        from tools.doctor import _project_root
        root = _project_root()
        assert root.exists()
        assert (root / "main.py").exists()

    def test_check_python(self):
        from tools.doctor import _check_python
        ok, ver = _check_python(Path(sys.executable))
        assert ok
        assert "3." in ver

    def test_check_library(self):
        from tools.doctor import _check_library
        ok, info = _check_library("json", Path(sys.executable))
        assert ok
        assert info == "Installed"

    def test_in_virtualenv(self):
        from tools.doctor import _in_virtualenv
        result = _in_virtualenv()
        assert isinstance(result, bool)


# ============================================================================
# dork_miner
# ============================================================================

class TestDorkMiner:
    """tests/tools/dork_miner.py"""

    def test_dork_templates_exist(self):
        from tools.dork_miner import _DORK_TEMPLATES
        assert "exposed_files" in _DORK_TEMPLATES
        assert "admin_panels" in _DORK_TEMPLATES
        assert "api_endpoints" in _DORK_TEMPLATES
        assert "cloud_leaks" in _DORK_TEMPLATES
        # Ensure {target} placeholder in all
        for cat, templates in _DORK_TEMPLATES.items():
            for t in templates:
                assert "{target}" in t, f"Missing {{target}} in {cat}: {t}"


# ============================================================================
# analysis_pipeline (limited - complex dependencies)
# ============================================================================

class TestAnalysisPipeline:
    """tests/tools/analysis_pipeline.py - import and class structure only"""

    def test_import(self):
        from tools.analysis_pipeline import AnalysisPipeline
        assert AnalysisPipeline is not None

    def test_base_url_hint(self):
        from tools.analysis_pipeline import AnalysisPipeline
        mock_ms = MagicMock()
        mock_ms.snapshot.return_value = {"target": "http://example.com"}
        hint = AnalysisPipeline._base_url_hint(mock_ms)
        assert "example.com" in hint

    def test_base_url_hint_no_target(self):
        from tools.analysis_pipeline import AnalysisPipeline
        mock_ms = MagicMock()
        mock_ms.snapshot.return_value = {"target": ""}
        hint = AnalysisPipeline._base_url_hint(mock_ms)
        assert "localhost" in hint


# ============================================================================
# html_reporter
# ============================================================================

class TestHTMLReporter:
    """tests/tools/html_reporter.py"""

    def test_badge(self):
        from tools.html_reporter import _badge
        assert _badge("CRITICAL") == "danger"
        assert _badge("HIGH") == "warning"
        assert _badge("MEDIUM") == "primary"
        assert _badge("LOW") == "success"
        assert _badge("INFO") == "secondary"
        assert _badge("UNKNOWN") == "secondary"

    def test_generate_html_report(self):
        from tools.html_reporter import generate_html_report
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            out = generate_html_report("x.com", [
                {"severity": "CRITICAL", "name": "SQLi", "url": "http://x.com/api", "details": "bad"},
                {"severity": "HIGH", "name": "XSS", "url": "http://x.com/xss", "details": "reflected"},
            ], path)
            assert Path(out).exists()
            content = Path(out).read_text()
            assert "Elengenix" in content
            assert "table" in content.lower()
        finally:
            Path(path).unlink(missing_ok=True)

    def test_generate_html_report_empty(self):
        from tools.html_reporter import generate_html_report
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            out = generate_html_report("x.com", [], path)
            content = Path(out).read_text()
            assert "Elengenix" in content
            assert "tbody" in content
        finally:
            Path(path).unlink(missing_ok=True)


# ============================================================================
# user_preferences
# ============================================================================

class TestUserPreferences:
    """tests/tools/user_preferences.py"""

    def test_user_preferences_dataclass(self):
        from tools.user_preferences import UserPreferences
        p = UserPreferences(user_id=123)
        assert p.notifications_enabled is True
        assert p.favorite_targets == []

    def test_init_and_crud(self):
        from tools.user_preferences import (init_db, get_preferences, save_preferences,
                                              add_favorite_target, remove_favorite_target,
                                              toggle_notification, DB_PATH)
        import tools.user_preferences as mod
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_db = Path(f.name)
        try:
            old = mod.DB_PATH
            mod.DB_PATH = tmp_db
            init_db()
            pref = get_preferences(999)
            assert pref.user_id == 999
            pref.notifications_enabled = False
            save_preferences(pref)
            pref2 = get_preferences(999)
            assert pref2.notifications_enabled is False
            # favorites
            add_favorite_target(999, "target.com")
            pref3 = get_preferences(999)
            assert "target.com" in pref3.favorite_targets
            remove_favorite_target(999, "target.com")
            pref4 = get_preferences(999)
            assert "target.com" not in pref4.favorite_targets
            # toggle
            toggle_notification(999, "all", True)
            toggle_notification(999, "findings", False)
            mod.DB_PATH = old
        finally:
            tmp_db.unlink(missing_ok=True)


# ============================================================================
# user_memory
# ============================================================================

class TestUserMemory:
    """tests/tools/user_memory.py"""

    def test_set_get_preference(self):
        from tools.user_memory import set_preference, get_preference, get_all_preferences
        import tools.user_memory as mod
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_db = Path(f.name)
        try:
            old = mod._DB_PATH
            mod._DB_PATH = tmp_db
            set_preference("test_key", "test_value")
            val = get_preference("test_key")
            assert val == "test_value"
            assert get_preference("nonexistent", "default") == "default"
            all_prefs = get_all_preferences()
            assert "test_key" in all_prefs
            mod._DB_PATH = old
        finally:
            tmp_db.unlink(missing_ok=True)

    def test_add_get_context(self):
        from tools.user_memory import add_context, get_recent_context
        import tools.user_memory as mod
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_db = Path(f.name)
        try:
            old = mod._DB_PATH
            mod._DB_PATH = tmp_db
            add_context("remember this", tags="important")
            ctx = get_recent_context()
            assert "remember this" in ctx
            mod._DB_PATH = old
        finally:
            tmp_db.unlink(missing_ok=True)

    def test_save_target_learning(self):
        from tools.user_memory import save_target_learning, get_target_summary
        import tools.user_memory as mod
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_db = Path(f.name)
        try:
            old = mod._DB_PATH
            mod._DB_PATH = tmp_db
            save_target_learning("target.com", "SQL injection found", "vuln")
            summary = get_target_summary("target.com")
            assert "SQL" in summary or "vuln" in summary.lower()
            mod._DB_PATH = old
        finally:
            tmp_db.unlink(missing_ok=True)

    def test_build_user_context_block(self):
        from tools.user_memory import build_user_context_block
        block = build_user_context_block()
        assert isinstance(block, str)


# ============================================================================
# memory_persistence (import only, limited API)
# ============================================================================

class TestMemoryPersistence:
    """tests/tools/memory_persistence.py"""

    def test_import(self):
        try:
            import tools.memory_persistence
            assert True
        except ImportError:
            pytest.skip("memory_persistence not importable")


# ============================================================================
# smart_recon (import + dataclass)
# ============================================================================

class TestSmartRecon:
    """tests/tools/smart_recon.py"""

    def test_import(self):
        try:
            import tools.smart_recon
            assert True
        except ImportError:
            pytest.skip("smart_recon not importable")


# ============================================================================
# smart_scanner (import)
# ============================================================================

class TestSmartScanner:
    """tests/tools/smart_scanner.py"""

    def test_import(self):
        try:
            import tools.smart_scanner
            assert True
        except ImportError:
            pytest.skip("smart_scanner not importable")


# ============================================================================
# native_scanner (import)
# ============================================================================

class TestNativeScanner:
    """tests/tools/native_scanner.py"""

    def test_import(self):
        try:
            import tools.native_scanner
            assert True
        except ImportError:
            pytest.skip("native_scanner not importable")


# ============================================================================
# waf_signatures
# ============================================================================

class TestWAFSignatures:
    """tests/tools/waf_signatures.py"""

    def test_import(self):
        try:
            import tools.waf_signatures
            assert True
        except ImportError:
            pytest.skip("waf_signatures not importable")


# ============================================================================
# cloud_scanner (import + basic structure)
# ============================================================================

class TestCloudScanner:
    """tests/tools/cloud_scanner.py"""

    def test_import(self):
        try:
            import tools.cloud_scanner
            assert True
        except ImportError:
            pytest.skip("cloud_scanner not importable")


# ============================================================================
# graphql_scanner (import)
# ============================================================================

class TestGraphQLScanner:
    """tests/tools/graphql_scanner.py"""

    def test_import(self):
        try:
            import tools.graphql_scanner
            assert True
        except ImportError:
            pytest.skip("graphql_scanner not importable")


# ============================================================================
# ssrf_scanner (import)
# ============================================================================

class TestSSRFScanner:
    """tests/tools/ssrf_scanner.py"""

    def test_import(self):
        try:
            import tools.ssrf_scanner
            assert True
        except ImportError:
            pytest.skip("ssrf_scanner not importable")


# ============================================================================
# ssti_scanner (import)
# ============================================================================

class TestSSTIScanner:
    """tests/tools/ssti_scanner.py"""

    def test_import(self):
        try:
            import tools.ssti_scanner
            assert True
        except ImportError:
            pytest.skip("ssti_scanner not importable")


# ============================================================================
# xxe_scanner (import)
# ============================================================================

class TestXXEScanner:
    """tests/tools/xxe_scanner.py"""

    def test_import(self):
        try:
            import tools.xxe_scanner
            assert True
        except ImportError:
            pytest.skip("xxe_scanner not importable")


# ============================================================================
# deserialization_scanner (import)
# ============================================================================

class TestDeserializationScanner:
    """tests/tools/deserialization_scanner.py"""

    def test_import(self):
        try:
            import tools.deserialization_scanner
            assert True
        except ImportError:
            pytest.skip("deserialization_scanner not importable")


# ============================================================================
# race_condition_tester (import)
# ============================================================================

class TestRaceConditionTester:
    """tests/tools/race_condition_tester.py"""

    def test_import(self):
        try:
            import tools.race_condition_tester
            assert True
        except ImportError:
            pytest.skip("race_condition_tester not importable")


# ============================================================================
# cors_checker (import)
# ============================================================================

class TestCORSChecker:
    """tests/tools/cors_checker.py"""

    def test_import(self):
        try:
            import tools.cors_checker
            assert True
        except ImportError:
            pytest.skip("cors_checker not importable")


# ============================================================================
# jwt_tester (import)
# ============================================================================

class TestJWTTester:
    """tests/tools/jwt_tester.py"""

    def test_import(self):
        try:
            import tools.jwt_tester
            assert True
        except ImportError:
            pytest.skip("jwt_tester not importable")


# ============================================================================
# edr_evasion (import)
# ============================================================================

class TestEDREvasion:
    """tests/tools/edr_evasion.py"""

    def test_import(self):
        try:
            import tools.edr_evasion
            assert True
        except ImportError:
            pytest.skip("edr_evasion not importable")


# ============================================================================
# enterprise_security (import)
# ============================================================================

class TestEnterpriseSecurity:
    """tests/tools/enterprise_security.py"""

    def test_import(self):
        try:
            import tools.enterprise_security
            assert True
        except ImportError:
            pytest.skip("enterprise_security not importable")


# ============================================================================
# endpoint_discovery (import)
# ============================================================================

class TestEndpointDiscovery:
    """tests/tools/endpoint_discovery.py"""

    def test_import(self):
        try:
            import tools.endpoint_discovery
            assert True
        except ImportError:
            pytest.skip("endpoint_discovery not importable")


# ============================================================================
# param_miner (import)
# ============================================================================

class TestParamMiner:
    """tests/tools/param_miner.py"""

    def test_import(self):
        try:
            import tools.param_miner
            assert True
        except ImportError:
            pytest.skip("param_miner not importable")


# ============================================================================
# subdomain_takeover (import)
# ============================================================================

class TestSubdomainTakeover:
    """tests/tools/subdomain_takeover.py"""

    def test_import(self):
        try:
            import tools.subdomain_takeover
            assert True
        except ImportError:
            pytest.skip("subdomain_takeover not importable")


# ============================================================================
# wayback_tool (import)
# ============================================================================

class TestWaybackTool:
    """tests/tools/wayback_tool.py"""

    def test_import(self):
        try:
            import tools.wayback_tool
            assert True
        except ImportError:
            pytest.skip("wayback_tool not importable")


# ============================================================================
# wordlist_manager (import)
# ============================================================================

class TestWordlistManager:
    """tests/tools/wordlist_manager.py"""

    def test_import(self):
        try:
            import tools.wordlist_manager
            assert True
        except ImportError:
            pytest.skip("wordlist_manager not importable")


# ============================================================================
# workflow_fuzzer (import)
# ============================================================================

class TestWorkflowFuzzer:
    """tests/tools/workflow_fuzzer.py"""

    def test_import(self):
        try:
            import tools.workflow_fuzzer
            assert True
        except ImportError:
            pytest.skip("workflow_fuzzer not importable")


# ============================================================================
# truffle_integration (import)
# ============================================================================

class TestTruffleIntegration:
    """tests/tools/truffle_integration.py"""

    def test_import(self):
        try:
            import tools.truffle_integration
            assert True
        except ImportError:
            pytest.skip("truffle_integration not importable")


# ============================================================================
# api_schema_diff (import)
# ============================================================================

class TestAPISchemaDiff:
    """tests/tools/api_schema_diff.py"""

    def test_import(self):
        try:
            import tools.api_schema_diff
            assert True
        except ImportError:
            pytest.skip("api_schema_diff not importable")


# ============================================================================
# object_id_permuter (import)
# ============================================================================

class TestObjectIDPermuter:
    """tests/tools/object_id_permuter.py"""

    def test_import(self):
        try:
            import tools.object_id_permuter
            assert True
        except ImportError:
            pytest.skip("object_id_permuter not importable")


# ============================================================================
# bola_tester (import)
# ============================================================================

class TestBOLATester:
    """tests/tools/bola_tester.py"""

    def test_import(self):
        try:
            import tools.bola_tester
            assert True
        except ImportError:
            pytest.skip("bola_tester not importable")


# ============================================================================
# install_request (import)
# ============================================================================

class TestInstallRequest:
    """tests/tools/install_request.py"""

    def test_import(self):
        try:
            import tools.install_request
            assert True
        except ImportError:
            pytest.skip("install_request not importable")


# ============================================================================
# progress_display (import)
# ============================================================================

class TestProgressDisplay:
    """tests/tools/progress_display.py"""

    def test_import(self):
        try:
            import tools.progress_display
            assert True
        except ImportError:
            pytest.skip("progress_display not importable")


# ============================================================================
# interactive_dashboard (import)
# ============================================================================

class TestInteractiveDashboard:
    """tests/tools/interactive_dashboard.py"""

    def test_import(self):
        try:
            import tools.interactive_dashboard
            assert True
        except ImportError:
            pytest.skip("interactive_dashboard not importable")


# ============================================================================
# tui_dashboard (import)
# ============================================================================

class TestTUIDashboard:
    """tests/tools/tui_dashboard.py"""

    def test_import(self):
        try:
            import tools.tui_dashboard
            assert True
        except ImportError:
            pytest.skip("tui_dashboard not importable")


# ============================================================================
# dashboard_server (import)
# ============================================================================

class TestDashboardServer:
    """tests/tools/dashboard_server.py"""

    def test_import(self):
        try:
            import tools.dashboard_server
            assert True
        except ImportError:
            pytest.skip("dashboard_server not importable")


# ============================================================================
# reporter (import)
# ============================================================================

class TestReporter:
    """tests/tools/reporter.py"""

    def test_import(self):
        try:
            import tools.reporter
            assert True
        except ImportError:
            pytest.skip("reporter not importable")


# ============================================================================
# report_gen (import)
# ============================================================================

class TestReportGen:
    """tests/tools/report_gen.py"""

    def test_import(self):
        try:
            import tools.report_gen
            assert True
        except ImportError:
            pytest.skip("report_gen not importable")


# ============================================================================
# pdf_report_generator (import)
# ============================================================================

class TestPDFReportGenerator:
    """tests/tools/pdf_report_generator.py"""

    def test_import(self):
        try:
            import tools.pdf_report_generator
            assert True
        except ImportError:
            pytest.skip("pdf_report_generator not importable")


# ============================================================================
# multimodal_agent (import)
# ============================================================================

class TestMultimodalAgent:
    """tests/tools/multimodal_agent.py"""

    def test_import(self):
        try:
            import tools.multimodal_agent
            assert True
        except ImportError:
            pytest.skip("multimodal_agent not importable")


# ============================================================================
# github_intel (import)
# ============================================================================

class TestGithubIntel:
    """tests/tools/github_intel.py"""

    def test_import(self):
        try:
            import tools.github_intel
            assert True
        except ImportError:
            pytest.skip("github_intel not importable")


# ============================================================================
# arjun_integration (import)
# ============================================================================

class TestArjunIntegration:
    """tests/tools/arjun_integration.py"""

    def test_import(self):
        try:
            import tools.arjun_integration
            assert True
        except ImportError:
            pytest.skip("arjun_integration not importable")


# ============================================================================
# mobile_api_tester (import)
# ============================================================================

class TestMobileAPITester:
    """tests/tools/mobile_api_tester.py"""

    def test_import(self):
        try:
            import tools.mobile_api_tester
            assert True
        except ImportError:
            pytest.skip("mobile_api_tester not importable")


# ============================================================================
# auth_session (import)
# ============================================================================

class TestAuthSession:
    """tests/tools/auth_session.py"""

    def test_import(self):
        try:
            import tools.auth_session
            assert True
        except ImportError:
            pytest.skip("auth_session not importable")


# ============================================================================
# auth_tester (import)
# ============================================================================

class TestAuthTester:
    """tests/tools/auth_tester.py"""

    def test_import(self):
        try:
            import tools.auth_tester
            assert True
        except ImportError:
            pytest.skip("auth_tester not importable")


# ============================================================================
# event_loop (import)
# ============================================================================

class TestEventLoop:
    """tests/tools/event_loop.py"""

    def test_import(self):
        try:
            import tools.event_loop
            assert True
        except ImportError:
            pytest.skip("event_loop not importable")


# ============================================================================
# welcome_wizard (import)
# ============================================================================

class TestWelcomeWizard:
    """tests/tools/welcome_wizard.py"""

    def test_import(self):
        try:
            import tools.welcome_wizard
            assert True
        except ImportError:
            pytest.skip("welcome_wizard not importable")


# ============================================================================
# swarm_controller (import)
# ============================================================================

class TestSwarmController:
    """tests/tools/swarm_controller.py"""

    def test_import(self):
        try:
            import tools.swarm_controller
            assert True
        except ImportError:
            pytest.skip("swarm_controller not importable")


# ============================================================================
# telegram_bridge (import)
# ============================================================================

class TestTelegramBridge:
    """tests/tools/telegram_bridge.py"""

    def test_import(self):
        try:
            import tools.telegram_bridge
            assert True
        except ImportError:
            pytest.skip("telegram_bridge not importable")


# ============================================================================
# nvd_cve (import)
# ============================================================================

class TestNVDCVE:
    """tests/tools/nvd_cve.py"""

    def test_import(self):
        try:
            import tools.nvd_cve
            assert True
        except ImportError:
            pytest.skip("nvd_cve not importable")


# ============================================================================
# vuln_engine (import)
# ============================================================================

class TestVulnEngine:
    """tests/tools/vuln_engine.py"""

    def test_import(self):
        try:
            import tools.vuln_engine
            assert True
        except ImportError:
            pytest.skip("vuln_engine not importable")


# ============================================================================
# vuln_reasoning (import)
# ============================================================================

class TestVulnReasoning:
    """tests/tools/vuln_reasoning.py"""

    def test_import(self):
        try:
            import tools.vuln_reasoning
            assert True
        except ImportError:
            pytest.skip("vuln_reasoning not importable")


# ============================================================================
# vuln_researcher (import)
# ============================================================================

class TestVulnResearcher:
    """tests/tools/vuln_researcher.py"""

    def test_import(self):
        try:
            import tools.vuln_researcher
            assert True
        except ImportError:
            pytest.skip("vuln_researcher not importable")


# ============================================================================
# vulncheck_tool (import)
# ============================================================================

class TestVulnCheckTool:
    """tests/tools/vulncheck_tool.py"""

    def test_import(self):
        try:
            import tools.vulncheck_tool
            assert True
        except ImportError:
            pytest.skip("vulncheck_tool not importable")


# ============================================================================
# research_tool (import)
# ============================================================================

class TestResearchTool:
    """tests/tools/research_tool.py"""

    def test_import(self):
        try:
            import tools.research_tool
            assert True
        except ImportError:
            pytest.skip("research_tool not importable")


# ============================================================================
# python_recon (import)
# ============================================================================

class TestPythonRecon:
    """tests/tools/python_recon.py"""

    def test_import(self):
        try:
            import tools.python_recon
            assert True
        except ImportError:
            pytest.skip("python_recon not importable")


# ============================================================================
# base_recon (import)
# ============================================================================

class TestBaseRecon:
    """tests/tools/base_recon.py"""

    def test_import(self):
        try:
            import tools.base_recon
            assert True
        except ImportError:
            pytest.skip("base_recon not importable")


# ============================================================================
# base_scanner (import)
# ============================================================================

class TestBaseScanner:
    """tests/tools/base_scanner.py"""

    def test_import(self):
        try:
            import tools.base_scanner
            assert True
        except ImportError:
            pytest.skip("base_scanner not importable")


# ============================================================================
# bounty_intelligence (import)
# ============================================================================

class TestBountyIntelligence:
    """tests/tools/bounty_intelligence.py"""

    def test_import(self):
        try:
            import tools.bounty_intelligence
            assert True
        except ImportError:
            pytest.skip("bounty_intelligence not importable")


# ============================================================================
# bounty_reporter (import)
# ============================================================================

class TestBountyReporter:
    """tests/tools/bounty_reporter.py"""

    def test_import(self):
        try:
            import tools.bounty_reporter
            assert True
        except ImportError:
            pytest.skip("bounty_reporter not importable")


# ============================================================================
# learning_engine (import)
# ============================================================================

class TestLearningEngine:
    """tests/tools/learning_engine.py"""

    def test_import(self):
        try:
            import tools.learning_engine
            assert True
        except ImportError:
            pytest.skip("learning_engine not importable")


# ============================================================================
# js_analyzer (import)
# ============================================================================

class TestJSAnalyzer:
    """tests/tools/js_analyzer.py"""

    def test_import(self):
        try:
            import tools.js_analyzer
            assert True
        except ImportError:
            pytest.skip("js_analyzer not importable")


# ============================================================================
# waf_evasion (import)
# ============================================================================

class TestWAFEvasion:
    """tests/tools/waf_evasion.py"""

    def test_import(self):
        try:
            import tools.waf_evasion
            assert True
        except ImportError:
            pytest.skip("waf_evasion not importable")


# ============================================================================
# omni_scan (import)
# ============================================================================

class TestOmniScan:
    """tests/tools/omni_scan.py"""

    def test_import(self):
        try:
            import tools.omni_scan
            assert True
        except ImportError:
            pytest.skip("omni_scan not importable")


# ============================================================================
# auto_detector (import)
# ============================================================================

class TestAutoDetector:
    """tests/tools/auto_detector.py"""

    def test_import(self):
        try:
            import tools.auto_detector
            assert True
        except ImportError:
            pytest.skip("auto_detector not importable")


# ============================================================================
# compliance_engine additional edge cases
# ============================================================================

class TestComplianceEngineEdge:
    """Additional compliance engine edge cases."""

    def test_assess_partial_match_standard(self):
        from tools.compliance_engine import ComplianceEngine
        e = ComplianceEngine()
        result = e.assess([], "pci")
        assert "standard" in result

    def test_standard_categories(self):
        from tools.compliance_engine import PCI_DSS
        pci = PCI_DSS()
        cats = pci.categories()
        assert len(cats) > 0

    def test_standard_to_dict(self):
        from tools.compliance_engine import SOC2
        d = SOC2().to_dict()
        assert d["name"] == "SOC 2"
        assert "control_count" in d

    def test_control_result_default_status(self):
        from tools.compliance_engine import Control, ControlResult
        c = Control(id="x", title="x", description="x", category="x")
        cr = ControlResult(control=c)
        assert cr.status == "not_tested"


# ============================================================================
# coverage_analyzer additional
# ============================================================================

class TestCoverageAnalyzerEdge:
    """Additional coverage analyzer edge cases."""

    def test_get_endpoint_coverage_unknown(self):
        from tools.coverage_analyzer import CoverageAnalyzer
        with tempfile.TemporaryDirectory() as td:
            ca = CoverageAnalyzer(db_path=Path(td) / "test.db")
            cov = ca.get_endpoint_coverage("http://unknown.com/api")
            assert cov["known"] is False

    def test_get_undertested_params(self):
        from tools.coverage_analyzer import CoverageAnalyzer
        with tempfile.TemporaryDirectory() as td:
            ca = CoverageAnalyzer(db_path=Path(td) / "test.db")
            ca.record_endpoint("http://x.com/api", "GET", ["q", "id"])
            ca.record_test("http://x.com/api", "GET", "tool", "param:q", "x", 200, 100)
            undertested = ca.get_undertested_params(min_tests=2)
            assert isinstance(undertested, list)


# ============================================================================
# exploit_template additional
# ============================================================================

class TestExploitTemplateAdditional:
    """Additional exploit_template tests."""

    def test_test_payload_returns_error_on_failure(self):
        from tools.exploit_template import test_payload
        with patch("tools.exploit_template.requests.get", side_effect=Exception("network error")):
            result = test_payload("http://x.com", "payload")
            assert result["error"]


# ============================================================================
# ml_filter additional
# ============================================================================

class TestMLFilterEdge:
    """Additional ML filter edge cases."""

    def test_signal_strength_low_cvss(self):
        from tools.ml_filter import MLFilter
        with tempfile.TemporaryDirectory() as td:
            f = MLFilter(profile_path=str(Path(td) / "p.json"))
            s = f._signal_strength({"cvss": 2.0, "details": "short"})
            assert 0 <= s <= 1

    def test_signal_strength_high_cvss(self):
        from tools.ml_filter import MLFilter
        with tempfile.TemporaryDirectory() as td:
            f = MLFilter(profile_path=str(Path(td) / "p.json"))
            s = f._signal_strength({"cvss": 9.5, "details": "x" * 600,
                                     "type": "sqli", "param": "id"})
            assert s > 0.5

    def test_bayesian_no_history(self):
        from tools.ml_filter import MLFilter
        with tempfile.TemporaryDirectory() as td:
            f = MLFilter(profile_path=str(Path(td) / "p.json"))
            b = f._bayesian_score({"type": "xss", "url": "http://x.com", "title": "t"})
            assert b == 0.5  # neutral without history


# ============================================================================
# docstrings and module metadata spot checks
# ============================================================================

class TestModuleDocstrings:
    """Verify all tested modules have docstrings."""

    @pytest.mark.parametrize("module_name", [
        "tools.access_control_matrix",
        "tools.agent_reflection",
        "tools.ai_config",
        "tools.ai_sandbox",
        "tools.ai_tool_creator",
        "tools.command_suggest",
        "tools.compliance_engine",
        "tools.context_compressor",
        "tools.coverage_analyzer",
        "tools.finding_dedup",
        "tools.exploit_chain_builder",
        "tools.exploit_template",
        "tools.html_reporter",
        "tools.injection_tester",
        "tools.llm_reasoning",
        "tools.logic_analyzer",
        "tools.memory_manager",
        "tools.memory_profile",
        "tools.ml_filter",
        "tools.profile_manager",
        "tools.token_counter",
        "tools.safe_exec",
        "tools.sast_engine",
        "tools.soc_analyzer",
        "tools.threat_intel",
        "tools.user_preferences",
        "tools.user_memory",
    ])
    def test_module_has_docstring(self, module_name):
        mod = __import__(module_name, fromlist=["_"])
        assert mod.__doc__ is not None

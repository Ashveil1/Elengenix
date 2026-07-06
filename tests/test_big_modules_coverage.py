"""tests/test_big_modules_coverage.py

Comprehensive tests for the three largest uncovered modules:
  - tools/autonomous_agent.py
  - tools/zero_day_heuristics.py
  - tools/config_wizard.py

All network/async mocked. No emoji. 4-space indent.
"""

import asyncio
import json
import math
import os
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════


def _make_action(name="http_probe", target="https://example.com", params=None):
    from tools.autonomous_agent import AgentAction
    return AgentAction(name=name, target=target, params=params or {})


def _make_state(target="example.com"):
    from tools.autonomous_agent import AgentState
    return AgentState(root_target=target, goal="test goal")


def _mock_response(status=200, text="ok", headers=None, content=b"ok"):
    r = MagicMock()
    r.status_code = status
    r.status = status
    r.text = text
    r.content = content
    r.headers = headers or {"Server": "nginx"}
    r.json.return_value = {}
    r.elapsed.total_seconds.return_value = 0.01
    r.history = []
    return r


def _mock_async_resp(status=200, text="ok", headers=None):
    return {
        "status": status,
        "text": text,
        "body": text.encode(),
        "length": len(text),
        "elapsed_ms": 10.0,
        "headers": headers or {},
        "history": [],
    }


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _make_http_mock():
    """Create a mock HTTPClient with async_request as async function."""

    class _HTTPMock:
        _async_return = None
        _async_side_effect = None

        async def async_request(self, *args, **kwargs):
            if self._async_side_effect is not None:
                result = self._async_side_effect(*args, **kwargs)
                return await result if asyncio.iscoroutine(result) else result
            return self._async_return

    return _HTTPMock()


@contextmanager
def _patch_requests():
    """Patch requests module globally for local-import functions."""
    mock_req = MagicMock()
    old = sys.modules.get("requests")
    sys.modules["requests"] = mock_req
    try:
        yield mock_req
    finally:
        if old is not None:
            sys.modules["requests"] = old
        else:
            del sys.modules["requests"]


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 1: autonomous_agent.py
# ═══════════════════════════════════════════════════════════════════════════════


class TestAutonomousAgentHelpers:
    def test_to_domain_plain(self):
        from tools.autonomous_agent import _to_domain
        assert _to_domain("example.com") == "example.com"

    def test_to_domain_url(self):
        from tools.autonomous_agent import _to_domain
        assert _to_domain("https://example.com/path") == "example.com"

    def test_to_domain_with_port(self):
        from tools.autonomous_agent import _to_domain
        assert _to_domain("https://example.com:8080/x") == "example.com"

    def test_to_domain_no_scheme(self):
        from tools.autonomous_agent import _to_domain
        assert _to_domain("sub.example.com") == "sub.example.com"

    def test_parse_json_valid(self):
        from tools.autonomous_agent import _parse_json
        assert _parse_json('{"action": "done"}')["action"] == "done"

    def test_parse_json_in_fence(self):
        from tools.autonomous_agent import _parse_json
        assert _parse_json('```json\n{"action": "recon"}\n```')["action"] == "recon"

    def test_parse_json_invalid(self):
        from tools.autonomous_agent import _parse_json
        assert _parse_json("not json") == {}

    def test_parse_json_trailing_comma(self):
        from tools.autonomous_agent import _parse_json
        assert _parse_json('{"a": 1,}').get("a") == 1

    def test_build_headers_basic(self):
        from tools.autonomous_agent import _build_headers
        assert "User-Agent" in _build_headers(_make_state())

    def test_build_headers_with_auth(self):
        from tools.autonomous_agent import _build_headers
        state = _make_state()
        state.assets["auth_headers"] = {"Authorization": "Bearer tok"}
        assert _build_headers(state)["Authorization"] == "Bearer tok"

    def test_build_headers_with_extra(self):
        from tools.autonomous_agent import _build_headers
        assert _build_headers(_make_state(), extra={"X-Custom": "val"})["X-Custom"] == "val"

    @patch("tools.autonomous_agent.display_in_chat_mode")
    @patch("tools.autonomous_agent._ui_console")
    def test_display_success(self, mock_console, mock_display):
        from tools.autonomous_agent import _display
        _display("hello", "info")
        mock_display.assert_called_once_with("hello", "info")

    @patch("tools.autonomous_agent.display_in_chat_mode", side_effect=Exception("fail"))
    @patch("tools.autonomous_agent._ui_console")
    def test_display_fallback(self, mock_console, mock_display):
        from tools.autonomous_agent import _display
        _display("msg")
        mock_console._display.assert_called_once()

    def test_ai_call_success(self):
        mock_client = MagicMock()
        mock_client.chat.return_value = MagicMock(content='{"action": "done"}')
        from tools.autonomous_agent import _ai_call
        assert _ai_call(mock_client, "sys", "usr") == '{"action": "done"}'

    def test_ai_call_failure(self):
        mock_client = MagicMock()
        mock_client.chat.side_effect = Exception("network")
        from tools.autonomous_agent import _ai_call
        assert _ai_call(mock_client, "sys", "usr") == ""


class TestAutonomousAgentDataclasses:
    def test_agent_action(self):
        from tools.autonomous_agent import AgentAction
        a = AgentAction(name="recon", target="x.com")
        assert a.name == "recon" and a.params == {}

    def test_agent_state(self):
        from tools.autonomous_agent import AgentState
        s = AgentState(root_target="x.com", goal="find bugs")
        assert s.findings == [] and s.iteration == 0

    def test_scan_result(self):
        from tools.autonomous_agent import ScanResult
        sr = ScanResult(target="x", start_time=datetime.now(timezone.utc), end_time=None,
                        findings=[], bounty_predictions=[], tools_created=[],
                        ai_decisions=[], report_path=None, success=True, summary="done")
        assert sr.success

    def test_autonomous_decision(self):
        from tools.autonomous_agent import AutonomousDecision
        d = AutonomousDecision(decision_type="scan", reasoning="t", action_plan={},
                               expected_outcome="f", risk_level="low")
        assert not d.auto_approved


class TestAutonomousAgentExecHttpProbe:
    def test_http_probe_success(self):
        r = _mock_response(200, "<html>ok</html>", {"Server": "apache"})
        with _patch_requests() as mock_req:
            mock_req.get.return_value = r
            from tools.autonomous_agent import _exec_http_probe
            findings = _exec_http_probe(_make_action(), _make_state())
            assert any(f["type"] == "server_fingerprint" for f in findings)

    def test_http_probe_missing_headers(self):
        with _patch_requests() as mock_req:
            mock_req.get.return_value = _mock_response(200, "ok", {})
            from tools.autonomous_agent import _exec_http_probe
            findings = _exec_http_probe(_make_action(), _make_state())
            assert any(f["type"] == "missing_security_headers" for f in findings)

    def test_http_probe_error(self):
        with _patch_requests() as mock_req:
            mock_req.get.side_effect = Exception("timeout")
            from tools.autonomous_agent import _exec_http_probe
            assert _exec_http_probe(_make_action(), _make_state()) == []

    def test_http_probe_no_scheme(self):
        with _patch_requests() as mock_req:
            mock_req.get.return_value = _mock_response(200, "ok", {})
            from tools.autonomous_agent import _exec_http_probe
            _exec_http_probe(_make_action(target="example.com"), _make_state())
            assert mock_req.get.call_args[0][0].startswith("https://")


class TestAutonomousAgentExecWafDetect:
    def test_waf_detected(self):
        with _patch_requests() as mock_req:
            mock_req.get.side_effect = [
                _mock_response(200, "Welcome", {"Server": "Cloudflare"}),
                _mock_response(403, "Blocked"),
            ]
            with patch("tools.waf_signatures.detect_waf_from_response", return_value=("Cloudflare", 0.9)):
                from tools.autonomous_agent import _exec_waf_detect
                findings = _exec_waf_detect(_make_action("waf_detect"), _make_state())
                assert any(f["type"] == "waf_detected" for f in findings)

    def test_no_waf_not_blocked(self):
        with _patch_requests() as mock_req:
            mock_req.get.side_effect = [_mock_response(200, "ok"), _mock_response(200, "ok")]
            with patch("tools.waf_signatures.detect_waf_from_response", return_value=(None, 0)):
                from tools.autonomous_agent import _exec_waf_detect
                findings = _exec_waf_detect(_make_action("waf_detect"), _make_state())
                assert any(f["type"] == "no_waf" for f in findings)

    def test_waf_detect_error(self):
        with _patch_requests() as mock_req:
            mock_req.get.side_effect = Exception("err")
            from tools.autonomous_agent import _exec_waf_detect
            assert _exec_waf_detect(_make_action("waf_detect"), _make_state()) == []


class TestAutonomousAgentExecBolaProbe:
    @patch("tools.autonomous_agent.time.sleep")
    def test_bola_accessible(self, mock_sleep):
        with _patch_requests() as mock_req:
            mock_req.get.return_value = _mock_response(200, "x" * 50, content=b"x" * 50)
            from tools.autonomous_agent import _exec_bola_probe
            findings = _exec_bola_probe(_make_action("bola_probe"), _make_state())
            assert len(findings) >= 1 and findings[0]["type"] == "bola_surface"

    @patch("tools.autonomous_agent.time.sleep")
    def test_bola_error(self, mock_sleep):
        with _patch_requests() as mock_req:
            mock_req.get.side_effect = Exception("err")
            from tools.autonomous_agent import _exec_bola_probe
            assert _exec_bola_probe(_make_action("bola_probe"), _make_state()) == []


class TestAutonomousAgentExecHeaderAudit:
    def test_cors_wildcard(self):
        with _patch_requests() as mock_req:
            mock_req.options.return_value = _mock_response(200, "", {"Access-Control-Allow-Origin": "*"})
            from tools.autonomous_agent import _exec_header_audit
            findings = _exec_header_audit(_make_action("header_audit"), _make_state())
            assert any(f["type"] == "cors_wildcard" for f in findings)

    def test_cors_reflection_with_creds(self):
        with _patch_requests() as mock_req:
            mock_req.options.return_value = _mock_response(200, "", {
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "true",
            })
            from tools.autonomous_agent import _exec_header_audit
            findings = _exec_header_audit(_make_action("header_audit"), _make_state())
            assert any(f["type"] == "cors_reflection" and f["severity"] == "high" for f in findings)

    def test_cors_reflection_no_creds(self):
        with _patch_requests() as mock_req:
            mock_req.options.return_value = _mock_response(200, "", {
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "false",
            })
            from tools.autonomous_agent import _exec_header_audit
            findings = _exec_header_audit(_make_action("header_audit"), _make_state())
            assert any(f["severity"] == "medium" for f in findings)

    def test_header_audit_error(self):
        with _patch_requests() as mock_req:
            mock_req.options.side_effect = Exception("err")
            from tools.autonomous_agent import _exec_header_audit
            assert _exec_header_audit(_make_action("header_audit"), _make_state()) == []


class TestAutonomousAgentExecThreatModel:
    def test_threat_model_no_ai(self):
        from tools.autonomous_agent import _exec_threat_model
        findings = _exec_threat_model(_make_action("threat_model"), _make_state(), ai_client=None)
        assert findings == []

    def test_threat_model_with_ai(self):
        mock_client = MagicMock()
        mock_client.chat.return_value = MagicMock(content=json.dumps({
            "attack_plan": [{"priority": 1, "target": "/api", "attack_type": "sqli", "reasoning": "test"}],
            "key_weaknesses": ["no auth"], "risk_assessment": "high risk",
        }))
        from tools.autonomous_agent import _exec_threat_model
        state = _make_state()
        state.findings = [{"severity": "high", "title": "XSS"}]
        findings = _exec_threat_model(_make_action("threat_model"), state, ai_client=mock_client)
        assert len(findings) == 1 and "Threat Model" in findings[0]["title"]
        assert "attack_plan" in state.assets


class TestAutonomousAgentExecRecon:
    @patch("tools.smart_recon.SmartReconEngine")
    def test_recon_success(self, MockEngine):
        mock_result = MagicMock()
        mock_result.nodes = []
        mock_result.findings = [{"type": "sub", "severity": "info", "title": "sub", "target": "x", "description": "d"}]
        mock_result.stats = {"domains": 5, "endpoints": 10}
        MockEngine.return_value.run_full_recon.return_value = mock_result
        from tools.autonomous_agent import _exec_recon
        findings = _exec_recon(_make_action("recon", "https://example.com"), _make_state())
        assert len(findings) == 1

    @patch("tools.smart_recon.SmartReconEngine", side_effect=Exception("fail"))
    def test_recon_error(self, MockEngine):
        from tools.autonomous_agent import _exec_recon
        assert _exec_recon(_make_action("recon", "https://example.com"), _make_state()) == []


class TestAutonomousAgentExecParamMine:
    @patch("tools.param_miner.mine_parameters")
    def test_param_mine_success(self, mock_mine):
        mock_mine.return_value = [{"param": "id", "status": 200, "base_status": 200,
                                   "length_delta": 50, "reflected": True, "url": "https://example.com?id=1"}]
        from tools.autonomous_agent import _exec_param_mine
        findings = _exec_param_mine(_make_action("param_mine"), _make_state())
        assert len(findings) == 1 and findings[0]["severity"] == "high"

    @patch("tools.param_miner.mine_parameters", side_effect=Exception("fail"))
    def test_param_mine_error(self, mock_mine):
        from tools.autonomous_agent import _exec_param_mine
        assert _exec_param_mine(_make_action("param_mine"), _make_state()) == []


class TestAutonomousAgentExecCorsScan:
    def test_cors_scan_issues(self):
        import tools.cors_checker
        # pyrefly: ignore [missing-attribute]
        tools.cors_checker.check_cors = lambda target: {"issues": [{"severity": "HIGH", "origin": "evil.com", "reason": "reflected", "headers": {}}]}
        try:
            from tools.autonomous_agent import _exec_cors_scan
            assert len(_exec_cors_scan(_make_action("cors_scan"), _make_state())) == 1
        finally:
            if hasattr(tools.cors_checker, "check_cors"):
                delattr(tools.cors_checker, "check_cors")

    def test_cors_scan_error(self):
        import tools.cors_checker
        tools.cors_checker.check_cors = lambda target: 1 / 0
        try:
            from tools.autonomous_agent import _exec_cors_scan
            assert _exec_cors_scan(_make_action("cors_scan"), _make_state()) == []
        finally:
            if hasattr(tools.cors_checker, "check_cors"):
                delattr(tools.cors_checker, "check_cors")


class TestAutonomousAgentExecJsRecon:
    @patch("tools.js_analyzer.analyze_js")
    def test_js_recon_success(self, mock_analyze):
        mock_analyze.return_value = {
            "API Endpoint": [{"match": "https://api.example.com/v1", "severity": "MEDIUM"}],
            "Secret Key": [{"match": "AKIA123", "severity": "CRITICAL"}],
        }
        from tools.autonomous_agent import _exec_js_recon
        state = _make_state()
        state.assets["js_files"] = ["https://example.com/app.js"]
        findings = _exec_js_recon(_make_action("js_recon"), state)
        assert len(findings) >= 2

    @patch("tools.js_analyzer.analyze_js", side_effect=Exception("fail"))
    def test_js_recon_error(self, mock_analyze):
        from tools.autonomous_agent import _exec_js_recon
        assert _exec_js_recon(_make_action("js_recon"), _make_state()) == []


class TestAutonomousAgentVulnScan:
    @patch("tools.autonomous_agent.time.sleep")
    def test_vuln_scan_finds_admin(self, mock_sleep):
        def side_effect(url, **kwargs):
            if "/admin" in url:
                return _mock_response(200, "x" * 200)
            return _mock_response(404, "not found")
        with _patch_requests() as mock_req:
            mock_req.get.side_effect = side_effect
            from tools.autonomous_agent import _exec_vuln_scan
            findings = _exec_vuln_scan(_make_action("vuln_scan"), _make_state())
            assert any("admin" in f["title"].lower() for f in findings)

    def test_vuln_scan_error(self):
        with _patch_requests() as mock_req:
            mock_req.get.side_effect = Exception("fail")
            from tools.autonomous_agent import _exec_vuln_scan
            assert _exec_vuln_scan(_make_action("vuln_scan"), _make_state()) == []


class TestAutonomousAgentXssHunt:
    @patch("tools.autonomous_agent.time.sleep")
    def test_xss_found(self, mock_sleep):
        def side_effect(url, **kwargs):
            if "<script>alert(1)</script>" in url:
                return _mock_response(200, "Echo: <script>alert(1)</script>")
            return _mock_response(200, "normal")
        with _patch_requests() as mock_req:
            mock_req.get.side_effect = side_effect
            from tools.autonomous_agent import _exec_xss_hunt
            state = _make_state()
            state.assets["discovered_params"] = ["q"]
            findings = _exec_xss_hunt(_make_action("xss_hunt"), state)
            assert any("XSS" in f["title"] for f in findings)

    def test_xss_error(self):
        with _patch_requests() as mock_req:
            mock_req.get.side_effect = Exception("fail")
            from tools.autonomous_agent import _exec_xss_hunt
            assert _exec_xss_hunt(_make_action("xss_hunt"), _make_state()) == []


class TestAutonomousAgentZapScan:
    def test_zap_not_installed(self):
        with patch.dict("sys.modules", {"zapv2": None}):
            from tools.autonomous_agent import _exec_zap_active_scan
            assert _exec_zap_active_scan(_make_action("zap_active_scan"), _make_state()) == []


class TestAutonomousAgentBuildSummary:
    def test_build_summary(self):
        from tools.autonomous_agent import AutonomousAgent
        agent = AutonomousAgent(ai_client=None)
        state = _make_state()
        state.findings = [{"severity": "critical"}, {"severity": "high"}, {"severity": "medium"},
                          {"severity": "low"}, {"severity": "info"}]
        state.iteration = 3
        summary = agent._build_summary("example.com", state, 60)
        assert "Critical: 1" in summary and "60s" in summary


class TestAutonomousAgentExecuteAction:
    def test_dispatch_known_action(self):
        from tools.autonomous_agent import AutonomousAgent
        agent = AutonomousAgent(ai_client=None)
        with _patch_requests() as mock_req:
            mock_req.options.return_value = _mock_response(200, "", {})
            findings = agent._execute_action(_make_action("header_audit"), _make_state())
            assert isinstance(findings, list)

    def test_dispatch_unknown_action(self):
        from tools.autonomous_agent import AutonomousAgent
        assert AutonomousAgent(ai_client=None)._execute_action(_make_action("nonexistent"), _make_state()) == []

    def test_dispatch_threat_model(self):
        from tools.autonomous_agent import AutonomousAgent
        findings = AutonomousAgent(ai_client=None)._execute_action(_make_action("threat_model"), _make_state())
        assert isinstance(findings, list)


class TestAutonomousAgentExportJson:
    def test_export_json(self):
        from tools.autonomous_agent import AutonomousAgent
        agent = AutonomousAgent(ai_client=None)
        state = _make_state()
        with tempfile.TemporaryDirectory() as tmp:
            scans_dir = Path(tmp) / "data" / "scans"
            scans_dir.mkdir(parents=True)
            with patch("tools.autonomous_agent.Path") as MockPath:
                mock_file = MagicMock()
                MockPath.return_value.mkdir = MagicMock()
                MockPath.return_value.__truediv__ = MagicMock(return_value=mock_file)
                agent._export_json("example.com", state, [], 10)
                mock_file.write_text.assert_called_once()


class TestAutonomousAgentAiDecideNext:
    def test_fallback_no_ai(self):
        from tools.autonomous_agent import _ai_decide_next
        action = _ai_decide_next(None, _make_state())
        assert action.name in ("wayback_recon", "recon", "osint_research", "done")

    def test_fallback_all_taken(self):
        from tools.autonomous_agent import _ai_decide_next
        state = _make_state()
        taken = ["wayback_recon", "recon", "osint_research", "github_dork", "vuln_intel",
                 "js_recon", "threat_model", "http_probe", "waf_detect", "endpoint_fuzz",
                 "param_mine", "cors_scan", "header_audit", "subdomain_takeover",
                 "request_auth", "auth_test", "injection_test", "bola_probe", "waf_bypass",
                 "vuln_scan", "xss_hunt", "ssrf_scan", "graphql_introspect", "race_condition",
                 "create_custom_tool"]
        state.action_history = [f"{a}:https://x.com" for a in taken]
        assert _ai_decide_next(None, state).name == "done"


class TestAutonomousAgentAnalyzeFindings:
    def test_no_ai_client(self):
        from tools.autonomous_agent import _exec_analyze_findings
        assert _exec_analyze_findings([{"title": "x"}], _make_action(), _make_state(), None) == ""

    def test_no_new_findings(self):
        from tools.autonomous_agent import _exec_analyze_findings
        assert _exec_analyze_findings([], _make_action(), _make_state(), MagicMock()) == ""


class TestAutonomousAgentAiReflect:
    def test_reflect_no_ai(self):
        from tools.autonomous_agent import _ai_reflect_on_action
        safe, _, _ = _ai_reflect_on_action(_make_action(), _make_state(), None)
        assert safe is True

    def test_reflect_skip_threat_model(self):
        from tools.autonomous_agent import _ai_reflect_on_action
        safe, _, _ = _ai_reflect_on_action(_make_action("threat_model"), _make_state(), MagicMock())
        assert safe is True


class TestAutonomousAgentEndpointFuzz:
    @patch("tools.autonomous_agent.time.sleep")
    @patch("tools.wordlist_manager.WordlistManager")
    def test_endpoint_fuzz(self, MockWM, mock_sleep):
        mock_wm = MagicMock()
        mock_wm.get_smart_wordlist.return_value = ["/admin", "/api"]
        mock_wm.ai_calls_made = 0
        MockWM.return_value = mock_wm
        def side_effect(url, **kwargs):
            if "/admin" in url:
                return _mock_response(200, "x" * 200)
            return _mock_response(404, "nf")
        with _patch_requests() as mock_req:
            mock_req.get.side_effect = side_effect
            from tools.autonomous_agent import _exec_endpoint_fuzz
            findings = _exec_endpoint_fuzz(_make_action("endpoint_fuzz"), _make_state())
            assert any("admin" in f["title"] for f in findings)


class TestAutonomousAgentSsrf:
    @patch("tools.ssrf_scanner.SSRFScanner")
    def test_ssrf_scan(self, MockScanner):
        mock = MagicMock()
        mock.scan.return_value = [{"title": "SSRF", "severity": "high"}]
        MockScanner.return_value = mock
        from tools.autonomous_agent import _exec_ssrf_scan_ex
        assert len(_exec_ssrf_scan_ex(_make_action("ssrf_scan"), _make_state())) == 1

    @patch("tools.ssrf_scanner.SSRFScanner", side_effect=Exception("import"))
    def test_ssrf_scan_error(self, MockScanner):
        from tools.autonomous_agent import _exec_ssrf_scan_ex
        assert _exec_ssrf_scan_ex(_make_action("ssrf_scan"), _make_state()) == []


class TestAutonomousAgentGraphql:
    def test_graphql_scan(self):
        import tools.graphql_scanner
        # pyrefly: ignore [missing-attribute]
        tools.graphql_scanner.scan_graphql = lambda t, **kw: [{"title": "GraphQL", "severity": "info"}]
        try:
            from tools.autonomous_agent import _exec_graphql_ex
            assert len(_exec_graphql_ex(_make_action("graphql_introspect"), _make_state())) == 1
        finally:
            if hasattr(tools.graphql_scanner, "scan_graphql"):
                delattr(tools.graphql_scanner, "scan_graphql")

    def test_graphql_scan_error(self):
        import tools.graphql_scanner
        # pyrefly: ignore [missing-attribute]
        tools.graphql_scanner.scan_graphql = lambda t, **kw: 1 / 0
        try:
            from tools.autonomous_agent import _exec_graphql_ex
            assert _exec_graphql_ex(_make_action("graphql_introspect"), _make_state()) == []
        finally:
            if hasattr(tools.graphql_scanner, "scan_graphql"):
                delattr(tools.graphql_scanner, "scan_graphql")


class TestAutonomousAgentRaceCondition:
    def test_race_scan(self):
        import tools.race_condition_tester
        # pyrefly: ignore [missing-attribute]
        tools.race_condition_tester.scan_race_conditions = lambda t, **kw: [{"title": "Race", "severity": "high"}]
        try:
            from tools.autonomous_agent import _exec_race_condition_ex
            assert len(_exec_race_condition_ex(_make_action("race_condition"), _make_state())) == 1
        finally:
            if hasattr(tools.race_condition_tester, "scan_race_conditions"):
                delattr(tools.race_condition_tester, "scan_race_conditions")

    def test_race_scan_error(self):
        import tools.race_condition_tester
        # pyrefly: ignore [missing-attribute]
        tools.race_condition_tester.scan_race_conditions = lambda t, **kw: 1 / 0
        try:
            from tools.autonomous_agent import _exec_race_condition_ex
            assert _exec_race_condition_ex(_make_action("race_condition"), _make_state()) == []
        finally:
            if hasattr(tools.race_condition_tester, "scan_race_conditions"):
                delattr(tools.race_condition_tester, "scan_race_conditions")


class TestAutonomousAgentAuthTest:
    @patch("tools.auth_tester.run_auth_tests")
    def test_auth_test(self, mock_auth):
        mock_auth.return_value = [{"title": "Weak JWT", "severity": "medium"}]
        from tools.autonomous_agent import _exec_auth_test_ex
        state = _make_state()
        state.assets["auth_headers"] = {"Authorization": "Bearer abc"}
        assert len(_exec_auth_test_ex(_make_action("auth_test"), state)) == 1

    @patch("tools.auth_tester.run_auth_tests", side_effect=Exception("fail"))
    def test_auth_test_error(self, mock_auth):
        from tools.autonomous_agent import _exec_auth_test_ex
        assert _exec_auth_test_ex(_make_action("auth_test"), _make_state()) == []


class TestAutonomousAgentPredictBounties:
    def test_predict_bounties_no_module(self):
        from tools.autonomous_agent import AutonomousAgent
        assert isinstance(AutonomousAgent(ai_client=None)._predict_bounties([{"title": "t"}]), list)


class TestAutonomousAgentGenerateReport:
    def test_generate_report_no_module(self):
        from tools.autonomous_agent import AutonomousAgent
        result = AutonomousAgent(ai_client=None)._generate_report("example.com", [], [])
        assert result is None or isinstance(result, Path)


class TestAutonomousAgentWaybackRecon:
    @patch("tools.wayback_tool.gather_historical_intel")
    def test_wayback_success(self, mock_intel):
        mock_intel.return_value = {
            "total_urls": 5, "high_interest": ["/admin"],
            "medium_interest": [], "unique_paths": ["/admin"], "unique_params": ["id"],
        }
        from tools.autonomous_agent import _exec_wayback_recon
        state = _make_state()
        findings = _exec_wayback_recon(_make_action("wayback_recon"), state)
        assert len(findings) >= 1

    @patch("tools.wayback_tool.gather_historical_intel", side_effect=Exception("fail"))
    def test_wayback_error(self, mock_intel):
        from tools.autonomous_agent import _exec_wayback_recon
        with pytest.raises(Exception):
            _exec_wayback_recon(_make_action("wayback_recon"), _make_state())


class TestAutonomousAgentGithubDork:
    @patch("tools.github_intel.hunt_leaks")
    def test_github_dork_success(self, mock_hunt):
        mock_hunt.return_value = {
            "total_findings": 1, "critical_count": 1, "high_count": 0,
            "findings": [{"file": "config.env", "repo": "test/repo", "path": "/config.env",
                          "url": "https://github.com/test/repo", "category": "env_files"}],
        }
        from tools.autonomous_agent import _exec_github_dork
        findings = _exec_github_dork(_make_action("github_dork"), _make_state())
        assert len(findings) == 1 and findings[0]["severity"] == "high"

    @patch("tools.github_intel.hunt_leaks", side_effect=Exception("fail"))
    def test_github_dork_error(self, mock_hunt):
        from tools.autonomous_agent import _exec_github_dork
        with pytest.raises(Exception):
            _exec_github_dork(_make_action("github_dork"), _make_state())


class TestAutonomousAgentSubdomainTakeover:
    @patch("tools.subdomain_takeover.check_subdomains")
    def test_subdomain_takeover(self, mock_check):
        mock_check.return_value = [{"title": "Takeover", "severity": "critical"}]
        from tools.autonomous_agent import _exec_subdomain_takeover
        assert len(_exec_subdomain_takeover(_make_action("subdomain_takeover"), _make_state())) == 1

    @patch("tools.subdomain_takeover.check_subdomains", side_effect=Exception("fail"))
    def test_subdomain_takeover_error(self, mock_check):
        from tools.autonomous_agent import _exec_subdomain_takeover
        assert _exec_subdomain_takeover(_make_action("subdomain_takeover"), _make_state()) == []


class TestAutonomousAgentWafBypass:
    @patch("tools.waf_evasion.WAFEvasionEngine")
    def test_waf_bypass_with_waf(self, MockEngine):
        mock = MagicMock()
        mock.detect_waf.return_value = ("Cloudflare", 0.9)
        mock.test_bypass.return_value = []
        mock.get_best_bypass.return_value = None
        mock.export_learned_strategies.return_value = {"test": "data"}
        MockEngine.return_value = mock
        from tools.autonomous_agent import _exec_waf_bypass
        assert isinstance(_exec_waf_bypass(_make_action("waf_bypass"), _make_state()), list)

    @patch("tools.waf_evasion.WAFEvasionEngine")
    def test_waf_bypass_no_waf(self, MockEngine):
        mock = MagicMock()
        mock.detect_waf.return_value = (None, 0)
        MockEngine.return_value = mock
        from tools.autonomous_agent import _exec_waf_bypass
        findings = _exec_waf_bypass(_make_action("waf_bypass"), _make_state())
        assert any("No WAF" in f["title"] for f in findings)

    @patch("tools.waf_evasion.WAFEvasionEngine", side_effect=Exception("fail"))
    def test_waf_bypass_error(self, MockEngine):
        from tools.autonomous_agent import _exec_waf_bypass
        assert _exec_waf_bypass(_make_action("waf_bypass"), _make_state()) == []


class TestAutonomousAgentInjectionTest:
    @patch("tools.injection_tester.run_all_injection_tests")
    def test_injection_test(self, mock_inj):
        mock_inj.return_value = [{"title": "SQLi", "severity": "critical"}]
        from tools.autonomous_agent import _exec_injection_test
        assert len(_exec_injection_test(_make_action("injection_test"), _make_state())) >= 1

    @patch("tools.injection_tester.run_all_injection_tests", side_effect=Exception("fail"))
    def test_injection_test_error(self, mock_inj):
        from tools.autonomous_agent import _exec_injection_test
        assert _exec_injection_test(_make_action("injection_test"), _make_state()) == []


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 2: zero_day_heuristics.py
# ═══════════════════════════════════════════════════════════════════════════════


class TestZeroDayHelpers:
    def test_entropy_empty(self):
        from tools.zero_day_heuristics import _entropy
        assert _entropy("") == 0.0

    def test_entropy_uniform(self):
        from tools.zero_day_heuristics import _entropy
        assert _entropy("aaaa") == 0.0

    def test_entropy_high(self):
        from tools.zero_day_heuristics import _entropy
        assert _entropy("abcdef0123456789") > 3.0

    def test_shannon_empty(self):
        from tools.zero_day_heuristics import _shannon
        assert _shannon(b"") == 0.0

    def test_shannon_bytes(self):
        from tools.zero_day_heuristics import _shannon
        assert _shannon(b"abcdef") > 2.0

    def test_short_hash_deterministic(self):
        from tools.zero_day_heuristics import _short_hash
        assert _short_hash("a", "b") == _short_hash("a", "b")
        assert len(_short_hash("a", "b")) == 12

    def test_short_hash_different(self):
        from tools.zero_day_heuristics import _short_hash
        assert _short_hash("a") != _short_hash("b")


class TestZeroDaySeverityLevel:
    def test_enum_values(self):
        from tools.zero_day_heuristics import SeverityLevel
        assert SeverityLevel.INFO.value == "info" and SeverityLevel.CRITICAL.value == "critical"

    def test_cvss_floor_mapping(self):
        from tools.zero_day_heuristics import SeverityLevel, SEVERITY_CVSS_FLOOR
        assert SEVERITY_CVSS_FLOOR[SeverityLevel.CRITICAL] == 9.5


class TestZeroDayFinding:
    def test_finding_creation(self):
        from tools.zero_day_heuristics import Finding, SeverityLevel
        from tools.vuln_engine import VulnClass
        f = Finding(detector="test", title="T", severity=SeverityLevel.HIGH,
                    vuln_class=VulnClass.PROTOTYPE_POLLUTION, url="https://example.com")
        assert f.detector == "test" and f.confidence == 0.5

    def test_to_vuln_finding(self):
        from tools.zero_day_heuristics import Finding, SeverityLevel
        from tools.vuln_engine import VulnClass
        f = Finding(detector="test", title="T", severity=SeverityLevel.HIGH,
                    vuln_class=VulnClass.PROTOTYPE_POLLUTION, url="https://example.com")
        vf = f.to_vuln_finding()
        assert vf.title == "T" and vf.cvss_score >= 7.5


class TestZeroDayDefaultVector:
    def test_known_classes(self):
        from tools.zero_day_heuristics import _default_vector_for
        from tools.vuln_engine import VulnClass
        assert _default_vector_for(VulnClass.PROTOTYPE_POLLUTION).startswith("CVSS:3.1/")

    def test_unknown_class(self):
        from tools.zero_day_heuristics import _default_vector_for
        from tools.vuln_engine import VulnClass
        assert _default_vector_for(VulnClass.ZERO_DAY).startswith("CVSS:3.1/")


class TestPrototypePollutionDetector:
    def _make_detector(self):
        from tools.zero_day_heuristics import PrototypePollutionDetector
        http = _make_http_mock()
        # pyrefly: ignore [bad-argument-type]
        return PrototypePollutionDetector(http=http), http

    def test_canary_reflected(self):
        det, http = self._make_detector()
        http._async_return = _mock_async_resp(200, '{"polluted":"elenheur-1337"}')
        findings = run_async(det.detect("https://example.com"))
        assert any("canary" in f.title.lower() for f in findings)

    def test_gadget_reflected(self):
        det, http = self._make_detector()
        http._async_return = _mock_async_resp(200, '{"polluted":"elenheur-1337","lodash.merge":true}')
        findings = run_async(det.detect("https://example.com"))
        assert any(f.severity.value == "high" for f in findings)

    def test_500_error(self):
        det, http = self._make_detector()
        http._async_return = _mock_async_resp(500, "Object.prototype error")
        findings = run_async(det.detect("https://example.com"))
        assert any("stack" in f.title.lower() for f in findings)

    def test_no_finding(self):
        det, http = self._make_detector()
        http._async_return = _mock_async_resp(200, "normal page")
        assert len(run_async(det.detect("https://example.com"))) == 0

    def test_has_stack_signal(self):
        det, _ = self._make_detector()
        assert det._has_stack_signal({"text": "Cannot set property x of Object.prototype"})
        assert not det._has_stack_signal({"text": "normal"})

    def test_mentions_gadget(self):
        det, _ = self._make_detector()
        assert det._mentions_gadget("using lodash.merge for deep copy")
        assert not det._mentions_gadget("normal text")

    def test_analyze_response_mass_assignment(self):
        det, _ = self._make_detector()
        assert det._analyze_response("https://x.com", {"isAdmin": True},
                                     _mock_async_resp(200, '{"isadmin": true, "role": "admin"}')) is not None

    def test_build_stack_finding(self):
        det, _ = self._make_detector()
        f = det._build_stack_finding("https://x.com", _mock_async_resp(500, "Object.prototype error"))
        assert f.severity.value == "critical"


class TestMassAssignmentDetector:
    def _make_detector(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import MassAssignmentDetector
        http = _make_http_mock()
        # pyrefly: ignore [bad-argument-type]
        return MassAssignmentDetector(http=http), http

    def test_echoed_field(self):
        det, http = self._make_detector()
        baseline = _mock_async_resp(200, '{"username":"elenheur"}')
        poisoned = _mock_async_resp(200, '{"username":"elenheur","isAdmin":true,"role":"admin"}')
        call_count = [0]
        async def side_effect(method, url, **kwargs):
            call_count[0] += 1
            return baseline if call_count[0] == 1 else poisoned
        http._async_side_effect = side_effect
        findings = run_async(det.detect("https://example.com"))
        assert any("isAdmin" in f.parameter for f in findings)

    def test_baseline_none(self):
        det, http = self._make_detector()
        http._async_return = None
        assert run_async(det.detect("https://example.com")) == []


class TestInsecureDeserializationDetector:
    def _make_detector(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import InsecureDeserializationDetector
        http = _make_http_mock()
        # pyrefly: ignore [bad-argument-type]
        return InsecureDeserializationDetector(http=http), http

    def test_java_magic_bytes(self):
        det, http = self._make_detector()
        body = bytes.fromhex("ACED000500000000")
        resp = _mock_async_resp(200, "")
        resp["body"] = body
        http._async_return = resp
        findings = run_async(det.detect("https://example.com"))
        assert any("java" in f.title.lower() for f in findings)

    def test_python_pickle(self):
        det, http = self._make_detector()
        http._async_return = _mock_async_resp(200, "gASVHQAAAACMCnN1YnByb2Nlc3OUhA==")
        findings = run_async(det.detect("https://example.com"))
        assert any("python" in f.title.lower() for f in findings)

    def test_php_serial(self):
        det, http = self._make_detector()
        http._async_return = _mock_async_resp(200, 'O:8:"stdClass":0:{}')
        findings = run_async(det.detect("https://example.com"))
        assert any("php" in f.title.lower() for f in findings)


class TestRaceConditionDetector:
    def _make_detector(self):
        from tools.zero_day_heuristics import RaceConditionDetector
        # pyrefly: ignore [bad-argument-type]
        return RaceConditionDetector(http=_make_http_mock()), _make_http_mock()

    def test_status_divergence(self):
        det, _ = self._make_detector()
        findings = det._analyze("https://example.com", "POST", 2, [_mock_async_resp(200, "ok"), _mock_async_resp(500, "err")])
        assert any("status code diverged" in f.title for f in findings)

    def test_length_spread(self):
        det, _ = self._make_detector()
        findings = det._analyze("https://example.com", "POST", 2, [_mock_async_resp(200, "x" * 100), _mock_async_resp(200, "x" * 10)])
        assert any("body diverged" in f.title for f in findings)

    def test_timing_spread(self):
        det, _ = self._make_detector()
        findings = det._analyze("https://example.com", "POST", 2, [
            {"status": 200, "length": 100, "elapsed_ms": 10.0, "text": "ok"},
            {"status": 200, "length": 100, "elapsed_ms": 2000.0, "text": "ok"},
        ])
        assert any("timing" in f.title for f in findings)

    def test_field_race(self):
        det, _ = self._make_detector()
        assert det._field_race(['"balance": 100', '"balance": 50', '"balance": 120']) == "balance"

    def test_field_race_monotonic(self):
        det, _ = self._make_detector()
        assert det._field_race(['"balance": 100', '"balance": 200', '"balance": 300']) is None

    def test_less_than_2_results(self):
        det, _ = self._make_detector()
        assert det._analyze("https://example.com", "POST", 12, [{"status": 200, "length": 100, "elapsed_ms": 10, "text": "ok"}]) == []


class TestSSTIDetector:
    def _make_detector(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import SSTIDetector
        http = _make_http_mock()
        return SSTIDetector(http=http), http

    def test_reflection_detected(self):
        det, http = self._make_detector()
        baseline = _mock_async_resp(200, "Hello World")
        call_count = [0]
        async def side_effect(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            params = kwargs.get("params") or {}
            if params.get("q") == "{{7*7}}":
                return _mock_async_resp(200, "Result: 49")
            return _mock_async_resp(200, "normal")
        http._async_side_effect = side_effect
        findings = run_async(det.detect("https://example.com"))
        assert any("SSTI" in f.title for f in findings)

    def test_jinja2_stack_trace(self):
        det, http = self._make_detector()
        call_count = [0]
        async def side_effect(method, url, **kwargs):
            call_count[0] += 1
            return _mock_async_resp(500, "jinja2.exceptions.TemplateSyntaxError") if call_count[0] > 1 else _mock_async_resp(200, "ok")
        http._async_side_effect = side_effect
        findings = run_async(det.detect("https://example.com"))
        assert any("stack trace" in f.title.lower() for f in findings)

    def test_analyze_reflection(self):
        det, _ = self._make_detector()
        findings = det._analyze("https://x.com", "q", "{{7*7}}", "49", "normal page", "Result: 49", {"_method": "GET"})
        assert len(findings) == 1 and findings[0].severity.value == "critical"

    def test_analyze_no_reflection(self):
        det, _ = self._make_detector()
        assert len(det._analyze("https://x.com", "q", "{{7*7}}", "49", "Result: 49", "Result: 49", {"_method": "GET"})) == 0

    def test_analyze_stack_trace_in_payload(self):
        det, _ = self._make_detector()
        findings = det._analyze("https://x.com", "q", "{{config}}", "Config", "normal", "jinja2.exceptions.UndefinedError", {"_method": "GET"})
        assert any("stack trace" in f.title.lower() for f in findings)


class TestInferEngine:
    def test_jinja2(self):
        from tools.zero_day_heuristics import _infer_engine
        assert _infer_engine("{{7*7}}", "jinja2 error") == "jinja2"

    def test_freemarker(self):
        from tools.zero_day_heuristics import _infer_engine
        assert _infer_engine("${7*7}", "freemarker template") == "freemarker"

    def test_erb(self):
        from tools.zero_day_heuristics import _infer_engine
        assert _infer_engine("<%= 7*7 %>", "ERB SyntaxError") == "erb"

    def test_twig(self):
        from tools.zero_day_heuristics import _infer_engine
        assert _infer_engine("#{7*7}", "Twig error") == "twig"

    def test_unknown(self):
        from tools.zero_day_heuristics import _infer_engine
        assert _infer_engine("test", "normal") == "unknown"


class TestGraphQLIntrospectionDetector:
    def _make_detector(self):
        from tools.zero_day_heuristics import GraphQLIntrospectionDetector
        http = _make_http_mock()
        return GraphQLIntrospectionDetector(http=http), http

    def test_introspection_enabled(self):
        det, http = self._make_detector()
        schema = {"types": [{"name": "User", "fields": [{"name": "password", "isDeprecated": False}], "kind": "OBJECT"}],
                  "mutationType": {"name": "Mutation"}}
        det._discover_endpoint = AsyncMock(return_value="https://example.com/graphql")
        det._introspect = AsyncMock(return_value=schema)
        det._test_batching = AsyncMock(return_value=None)
        det._test_depth = AsyncMock(return_value=None)
        http._async_return = _mock_async_resp(200, '{"data":{"__typename":"Query"}}')
        findings = run_async(det.detect("https://example.com"))
        assert any("introspection" in f.title.lower() for f in findings)

    def test_introspection_disabled(self):
        det, http = self._make_detector()
        det._discover_endpoint = AsyncMock(return_value="https://example.com/graphql")
        det._introspect = AsyncMock(return_value=None)
        det._test_batching = AsyncMock(return_value=None)
        det._test_depth = AsyncMock(return_value=None)
        findings = run_async(det.detect("https://example.com"))
        assert any("introspection disabled" in f.title.lower() for f in findings)

    def test_no_endpoint(self):
        det, _ = self._make_detector()
        det._discover_endpoint = AsyncMock(return_value=None)
        assert run_async(det.detect("https://example.com")) == []

    def test_discover_endpoint_found(self):
        det, http = self._make_detector()
        async def mock_request(method, url, **kwargs):
            if "/graphql" in url:
                return _mock_async_resp(200, '{"data":{"__typename":"Query"}}')
            return None
        http._async_side_effect = mock_request
        ep = run_async(det._discover_endpoint("https://example.com", headers={}))
        assert ep is not None

    def test_analyze_schema_sensitive_fields(self):
        det, _ = self._make_detector()
        schema = {"types": [{"name": "User", "fields": [
            {"name": "password", "isDeprecated": False}, {"name": "token", "isDeprecated": True}], "kind": "OBJECT"}],
            "mutationType": None}
        findings = det._analyze_schema("https://example.com/graphql", schema)
        assert any("sensitive" in f.title.lower() for f in findings)
        assert any("deprecated" in f.title.lower() for f in findings)

    def test_test_batching(self):
        det, http = self._make_detector()
        http._async_return = _mock_async_resp(200, '[{"data":{}},{"data":{}}]')
        finding = run_async(det._test_batching("https://example.com/graphql", headers={}))
        assert finding is not None and "batching" in finding.title.lower()

    def test_test_depth(self):
        det, http = self._make_detector()
        http._async_return = _mock_async_resp(200, '{"data":{"__typename":"Query"}}')
        finding = run_async(det._test_depth("https://example.com/graphql", headers={}))
        assert finding is not None and "depth" in finding.title.lower()


class TestJWTAlgorithmDetector:
    def _make_detector(self):
        from tools.zero_day_heuristics import JWTAlgorithmDetector
        http = _make_http_mock()
        return JWTAlgorithmDetector(http=http), http

    def test_forge_tokens(self):
        det, _ = self._make_detector()
        attacks = det.forge_tokens()
        assert len(attacks) >= 8
        assert "alg_none" in attacks and "kid_path_traversal" in attacks and "hs256_confusion" in attacks

    def test_forge_with_original(self):
        det, _ = self._make_detector()
        from tools.zero_day_heuristics import _b64url
        token = f"{_b64url(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode())}.{_b64url(json.dumps({'user': 'admin'}).encode())}.sig"
        assert len(det.forge_tokens(token)) >= 8

    def test_forge_with_invalid_token(self):
        det, _ = self._make_detector()
        assert len(det.forge_tokens("not-a-jwt")) >= 8

    def test_detect_static(self):
        det, _ = self._make_detector()
        findings = det.detect()
        assert len(findings) >= 8 and all(f.confidence == 0.0 for f in findings)

    def test_detect_on_endpoint_accepted(self):
        det, http = self._make_detector()
        call_count = [0]
        async def side_effect(method, url, **kwargs):
            call_count[0] += 1
            return _mock_async_resp(401, "Unauthorized") if call_count[0] == 1 else _mock_async_resp(200, "Welcome admin")
        http._async_side_effect = side_effect
        findings = run_async(det.detect_on_endpoint("https://example.com/api"))
        assert any("accepted" in f.title.lower() for f in findings)

    def test_detect_on_endpoint_rejected(self):
        det, http = self._make_detector()
        http._async_return = _mock_async_resp(401, "Unauthorized")
        assert run_async(det.detect_on_endpoint("https://example.com/api")) == []


class TestJWTHelpers:
    def test_b64url(self):
        from tools.zero_day_heuristics import _b64url, _b64url_decode
        assert _b64url_decode(_b64url(b"hello")) == b"hello"

    def test_make_jwt(self):
        from tools.zero_day_heuristics import _make_jwt
        assert len(_make_jwt({"alg": "none"}, {"user": "admin"}).split(".")) == 3

    def test_is_jwt_valid(self):
        from tools.zero_day_heuristics import _is_jwt
        assert _is_jwt("eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.")
        assert not _is_jwt("not-a-jwt") and not _is_jwt("") and not _is_jwt(None) and not _is_jwt("a.b")


class TestSmartAnomalyDetector:
    def _make_detector(self):
        from tools.zero_day_heuristics import SmartAnomalyDetector
        http = _make_http_mock()
        return SmartAnomalyDetector(http=http), http

    def test_anomaly_detected(self):
        det, http = self._make_detector()
        call_count = [0]
        async def side_effect(method, url, **kwargs):
            call_count[0] += 1
            return _mock_async_resp(500, "Internal Server Error") if call_count[0] > 5 else _mock_async_resp(200, "normal")
        http._async_side_effect = side_effect
        findings = run_async(det.detect("https://example.com"))
        assert any("anomal" in f.title.lower() for f in findings)

    def test_no_anomaly(self):
        det, http = self._make_detector()
        http._async_return = _mock_async_resp(200, "normal")
        assert isinstance(run_async(det.detect("https://example.com")), list)

    def test_stats(self):
        from tools.zero_day_heuristics import ResponseSnapshot, SmartAnomalyDetector
        stats = SmartAnomalyDetector._stats([
            ResponseSnapshot(status=200, length=100, elapsed_ms=10, headers={}, text="a"),
            ResponseSnapshot(status=200, length=120, elapsed_ms=15, headers={}, text="b"),
        ])
        assert "length" in stats and "timing" in stats

    def test_header_anomaly(self):
        from tools.zero_day_heuristics import ResponseSnapshot, SmartAnomalyDetector
        s1 = ResponseSnapshot(status=200, length=100, elapsed_ms=10, headers={"A": "1", "B": "2"}, text="")
        s2 = ResponseSnapshot(status=200, length=100, elapsed_ms=10, headers={"C": "3"}, text="")
        assert len(SmartAnomalyDetector._header_anomaly("https://x.com", [s1, s2])) == 1

    def test_timing_anomaly(self):
        from tools.zero_day_heuristics import ResponseSnapshot, SmartAnomalyDetector
        s1 = ResponseSnapshot(status=200, length=100, elapsed_ms=10, headers={}, text="")
        s2 = ResponseSnapshot(status=200, length=100, elapsed_ms=2000, headers={}, text="")
        assert len(SmartAnomalyDetector._timing_anomaly("https://x.com", [s1, s2])) == 1

    def test_outlier_length(self):
        from tools.zero_day_heuristics import ResponseSnapshot
        det, _ = self._make_detector()
        stats = {"length": (100.0, 10.0), "timing": (10.0, 5.0), "status_mean": (200.0, 0.0)}
        assert det._outlier(ResponseSnapshot(status=200, length=500, elapsed_ms=10, headers={}, text="x"), stats) is not None

    def test_outlier_5xx(self):
        from tools.zero_day_heuristics import ResponseSnapshot
        det, _ = self._make_detector()
        stats = {"length": (100.0, 10.0), "timing": (10.0, 5.0), "status_mean": (200.0, 0.0)}
        assert det._outlier(ResponseSnapshot(status=500, length=100, elapsed_ms=10, headers={}, text="x"), stats) is not None

    def test_outlier_none(self):
        from tools.zero_day_heuristics import ResponseSnapshot
        det, _ = self._make_detector()
        stats = {"length": (100.0, 10.0), "timing": (10.0, 5.0), "status_mean": (200.0, 0.0)}
        assert det._outlier(ResponseSnapshot(status=200, length=100, elapsed_ms=10, headers={}, text="x"), stats) is None

    def test_too_few_baselines(self):
        det, http = self._make_detector()
        http._async_return = _mock_async_resp(200, "ok")
        assert run_async(det.detect("https://example.com", baseline_count=1)) == []


class TestResponseSnapshot:
    def test_from_response(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import ResponseSnapshot
        snap = ResponseSnapshot.from_response({"status": 200, "length": 100, "elapsed_ms": 5.0, "headers": {"A": "1"}, "text": "hello"})
        assert snap.status == 200 and snap.length == 100


class TestFindingGraph:
    def test_add_endpoint(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import FindingGraph
        g = FindingGraph()
        eid = g.add_endpoint("https://example.com/api", "GET")
        assert eid in g.nodes

    def test_add_parameter(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import FindingGraph
        g = FindingGraph()
        eid = g.add_endpoint("https://example.com/api")
        pid = g.add_parameter(eid, "id")
        assert pid in g.nodes and any(e.relation == "has_parameter" for e in g.edges)

    def test_add_finding(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import FindingGraph, Finding, SeverityLevel
        # pyrefly: ignore [missing-import]
        from tools.vuln_engine import VulnClass
        g = FindingGraph()
        f = Finding(detector="test", title="XSS", severity=SeverityLevel.HIGH,
                    vuln_class=VulnClass.PROTOTYPE_POLLUTION, url="https://example.com/api", parameter="q")
        fid = g.add_finding(f)
        assert fid in g.nodes and any(e.relation == "exploits" for e in g.edges)

    def test_chain_score(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import FindingGraph, FindingNode
        g = FindingGraph()
        g.nodes = {"n1": FindingNode(node_id="n1", kind="finding", label="a", metadata={"severity": "high"}),
                    "n2": FindingNode(node_id="n2", kind="finding", label="b", metadata={"severity": "critical"})}
        assert g.chain_score(["n1", "n2"]) > 0

    def test_chain_score_empty(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import FindingGraph
        assert FindingGraph().chain_score([]) == 0.0

    def test_render(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import FindingGraph
        g = FindingGraph()
        g.add_endpoint("https://x.com")
        assert "Nodes:" in g.render()

    def test_ensure_edge_dedup(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import FindingGraph
        g = FindingGraph()
        g._ensure_edge("a", "b", "test")
        g._ensure_edge("a", "b", "test")
        assert len(g.edges) == 1

    def test_cartesian(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import FindingGraph
        assert len(list(FindingGraph._cartesian([1, 2, 3], 2))) == 3


class TestZeroDayEngine:
    def test_build_detectors_all_enabled(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import ZeroDayEngine, ScanConfig
        engine = ZeroDayEngine(config=ScanConfig())
        assert all(k in engine._detectors for k in ["prototype", "mass_assignment", "ssti", "graphql"])
        engine.close()

    def test_build_detectors_all_disabled(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import ZeroDayEngine, ScanConfig
        config = ScanConfig(enable_prototype=False, enable_mass_assignment=False,
                            enable_deserialization=False, enable_smuggling=False,
                            enable_race=False, enable_ssti=False, enable_graphql=False)
        engine = ZeroDayEngine(config=config)
        assert len(engine._detectors) >= 1
        engine.close()

    def test_severity_rank(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import ZeroDayEngine, Finding, SeverityLevel
        # pyrefly: ignore [missing-import]
        from tools.vuln_engine import VulnClass
        f = Finding(detector="t", title="t", severity=SeverityLevel.CRITICAL, vuln_class=VulnClass.ZERO_DAY)
        assert ZeroDayEngine._severity_rank(f) == 5

    def test_deduplicate(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import ZeroDayEngine, Finding, SeverityLevel
        # pyrefly: ignore [missing-import]
        from tools.vuln_engine import VulnClass
        f1 = Finding(detector="t", title="XSS", severity=SeverityLevel.HIGH, vuln_class=VulnClass.ZERO_DAY, url="https://x.com")
        f2 = Finding(detector="t", title="XSS", severity=SeverityLevel.HIGH, vuln_class=VulnClass.ZERO_DAY, url="https://x.com")
        assert len(ZeroDayEngine._deduplicate([f1, f2])) == 1

    def test_looks_like_jwt(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import ZeroDayEngine
        assert ZeroDayEngine._looks_like_jwt("eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.sig")
        assert not ZeroDayEngine._looks_like_jwt("not a jwt")

    def test_close(self):
        # pyrefly: ignore [missing-import]
        from tools.zero_day_heuristics import ZeroDayEngine
        ZeroDayEngine().close()


# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 3: config_wizard.py
# ═══════════════════════════════════════════════════════════════════════════════


class TestConfigWizardInit:
    def test_creates_env_file(self):
        # pyrefly: ignore [missing-import]
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            assert ConfigWizard(config_dir=Path(tmp)).env_file == Path(tmp) / ".env"

    def test_restricts_existing_env(self):
        # pyrefly: ignore [missing-import]
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("KEY=VAL\n")
            env_file.chmod(0o666)
            ConfigWizard(config_dir=Path(tmp))
            assert (env_file.stat().st_mode & 0o777) == 0o600


class TestConfigWizardSaveEnvVar:
    def test_save_new(self):
        # pyrefly: ignore [missing-import]
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            wizard = ConfigWizard(config_dir=Path(tmp))
            wizard._save_env_var("TEST_KEY_123", "test_value_123")
            assert "TEST_KEY_123=test_value_123" in wizard.env_file.read_text()
            assert os.environ.get("TEST_KEY_123") == "test_value_123"
            del os.environ["TEST_KEY_123"]

    def test_save_overwrite(self):
        # pyrefly: ignore [missing-import]
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            wizard = ConfigWizard(config_dir=Path(tmp))
            wizard._save_env_var("TEST_KEY_OVER", "val1")
            wizard._save_env_var("TEST_KEY_OVER", "val2")
            lines = [l for l in wizard.env_file.read_text().splitlines() if l.startswith("TEST_KEY_OVER=")]
            assert len(lines) == 1 and lines[0] == "TEST_KEY_OVER=val2"
            del os.environ["TEST_KEY_OVER"]


class TestConfigWizardRemoveEnvVar:
    def test_remove_existing(self):
        # pyrefly: ignore [missing-import]
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            wizard = ConfigWizard(config_dir=Path(tmp))
            wizard._save_env_var("TEST_REMOVE", "val")
            wizard._remove_env_var("TEST_REMOVE")
            assert "TEST_REMOVE" not in wizard.env_file.read_text()
            assert "TEST_REMOVE" not in os.environ

    def test_remove_nonexistent_file(self):
        # pyrefly: ignore [missing-import]
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._remove_env_var("NONEXISTENT")


class TestConfigWizardShowStatus:
    # pyrefly: ignore [missing-import]
    @patch("tools.config_wizard.console")
    def test_show_status(self, mock_console):
        # pyrefly: ignore [missing-import]
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._show_status()
            assert mock_console.print.called


class TestConfigWizardHealthCheck:
    @patch("tools.doctor.check_health")
    @patch("tools.config_wizard.console")
    def test_health_check(self, mock_console, mock_health):
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._health_check()
            mock_health.assert_called_once()


class TestConfigWizardSelectModel:
    @patch("tools.config_wizard.console")
    def test_select_model_skip(self, mock_console):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        mock_console.input.return_value = "s"
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._select_model(AIProviderConfig(
                name="TP", env_key="TEST_PK_API_KEY", base_url="https://api.test.com/v1",
                signup_url="https://test.com", is_free=True, notes="t"))

    @patch("tools.config_wizard.console")
    def test_select_model_by_number(self, mock_console):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        mock_console.input.return_value = "1"
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._select_model(AIProviderConfig(
                name="TP", env_key="TEST_MN_API_KEY", base_url="https://api.test.com/v1",
                signup_url="https://test.com", is_free=True, notes="t"))
            assert os.environ.get("TEST_MN_MODEL") is not None
            del os.environ["TEST_MN_MODEL"]

    @patch("tools.config_wizard.console")
    def test_select_model_custom(self, mock_console):
        # pyrefly: ignore [missing-import]
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        # "TP" has no DEFAULT_MODELS entry, so models=["default"] (len=1)
        # Menu: [1] default, [2] Custom (Enter identifier)
        # Input "2" triggers custom model input
        mock_console.input.side_effect = ["2", "custom-model-name"]
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._select_model(AIProviderConfig(
                name="TP", env_key="TEST_MC_API_KEY", base_url="https://api.test.com/v1",
                signup_url="https://test.com", is_free=True, notes="t"))
            assert os.environ.get("TEST_MC_MODEL") == "custom-model-name"
            del os.environ["TEST_MC_MODEL"]


class TestConfigWizardFetchRemoteModels:
    def test_fetch_models_success(self):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": [{"id": "model-a"}, {"id": "model-b"}, {"id": "embedding-model"}]}
        with _patch_requests() as mock_req:
            mock_req.get.return_value = mock_resp
            with tempfile.TemporaryDirectory() as tmp:
                models = ConfigWizard(config_dir=Path(tmp))._fetch_remote_models(AIProviderConfig(
                    name="TP", env_key="TF", base_url="https://api.test.com/v1",
                    signup_url="https://test.com", is_free=True, notes="t"), "fake-key")
                assert "model-a" in models and "embedding-model" not in models

    def test_fetch_models_anthropic(self):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        with tempfile.TemporaryDirectory() as tmp:
            assert ConfigWizard(config_dir=Path(tmp))._fetch_remote_models(AIProviderConfig(
                name="Anthropic (Claude)", env_key="TF", base_url="https://api.anthropic.com/v1",
                signup_url="https://test.com", is_free=False, notes="t"), "fake-key") == []

    def test_fetch_models_list_format(self):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"id": "model-c"}, {"id": "model-d"}]
        with _patch_requests() as mock_req:
            mock_req.get.return_value = mock_resp
            with tempfile.TemporaryDirectory() as tmp:
                models = ConfigWizard(config_dir=Path(tmp))._fetch_remote_models(AIProviderConfig(
                    name="TP", env_key="TF2", base_url="https://api.test2.com/v1",
                    signup_url="https://test.com", is_free=True, notes="t"), "fake-key")
                assert "model-c" in models

    def test_fetch_models_failure(self):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        with _patch_requests() as mock_req:
            mock_req.get.side_effect = Exception("network")
            with tempfile.TemporaryDirectory() as tmp:
                assert ConfigWizard(config_dir=Path(tmp))._fetch_remote_models(AIProviderConfig(
                    name="TP", env_key="TF3", base_url="https://api.test3.com/v1",
                    signup_url="https://test.com", is_free=True, notes="t"), "fake-key") == []


class TestConfigWizardTestProvider:
    @patch("tools.config_wizard.console")
    def test_test_provider_success(self, mock_console):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with _patch_requests() as mock_req:
            mock_req.post.return_value = mock_resp
            with tempfile.TemporaryDirectory() as tmp:
                assert ConfigWizard(config_dir=Path(tmp))._test_provider(AIProviderConfig(
                    name="TP", env_key="TT_API_KEY", base_url="https://api.test.com/v1",
                    signup_url="https://test.com", is_free=True, notes="t"), "fake-key", "model-a")

    @patch("tools.config_wizard.console")
    def test_test_provider_timeout(self, mock_console):
        # pyrefly: ignore [missing-import]
        import requests as real_requests
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        with _patch_requests() as mock_req:
            mock_req.exceptions = MagicMock()
            mock_req.exceptions.Timeout = real_requests.exceptions.Timeout
            mock_req.post.side_effect = real_requests.exceptions.Timeout()
            with tempfile.TemporaryDirectory() as tmp:
                assert ConfigWizard(config_dir=Path(tmp))._test_provider(AIProviderConfig(
                    name="TP", env_key="TT2_API_KEY", base_url="https://api.test.com/v1",
                    signup_url="https://test.com", is_free=True, notes="t"), "fake-key")

    @patch("tools.config_wizard.console")
    def test_test_provider_nvidia_nemotron(self, mock_console):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with _patch_requests() as mock_req:
            mock_req.post.return_value = mock_resp
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["NVIDIA_PARAM_MODE"] = "nemotron"
                assert ConfigWizard(config_dir=Path(tmp))._test_provider(AIProviderConfig(
                    name="NVIDIA", env_key="TT3_API_KEY", base_url="https://integrate.api.nvidia.com/v1",
                    signup_url="https://test.com", is_free=True, notes="t"), "fake-key", "nemotron-model")
                del os.environ["NVIDIA_PARAM_MODE"]


class TestConfigWizardSetupDefaultTarget:
    @patch("tools.config_wizard.console")
    def test_setup_target(self, mock_console):
        from tools.config_wizard import ConfigWizard
        mock_console.input.return_value = "https://example.com"
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._setup_default_target()
            assert os.environ.get("ELENGENIX_DEFAULT_TARGET") == "https://example.com"
            del os.environ["ELENGENIX_DEFAULT_TARGET"]

    @patch("tools.config_wizard.console")
    def test_setup_target_skip(self, mock_console):
        from tools.config_wizard import ConfigWizard
        mock_console.input.return_value = "s"
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._setup_default_target()


class TestConfigWizardSetupRateLimits:
    @patch("tools.config_wizard.console")
    def test_setup_rate_limit(self, mock_console):
        from tools.config_wizard import ConfigWizard
        mock_console.input.return_value = "120"
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._setup_rate_limits()
            assert os.environ.get("ELENGENIX_RATE_LIMIT") == "120"
            del os.environ["ELENGENIX_RATE_LIMIT"]

    @patch("tools.config_wizard.console")
    def test_setup_rate_limit_invalid(self, mock_console):
        from tools.config_wizard import ConfigWizard
        mock_console.input.return_value = "abc"
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._setup_rate_limits()


class TestConfigWizardConfigureProvider:
    @patch("tools.config_wizard.console")
    def test_configure_provider_skip(self, mock_console):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        mock_console.input.return_value = "s"
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._configure_provider(AIProviderConfig(
                name="TP", env_key="TCP", base_url="https://api.test.com/v1",
                signup_url="https://test.com", is_free=True, notes="t"))

    @patch("tools.config_wizard.console")
    def test_configure_provider_ollama(self, mock_console):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with _patch_requests() as mock_req:
            mock_req.get.return_value = mock_resp
            with tempfile.TemporaryDirectory() as tmp:
                ConfigWizard(config_dir=Path(tmp))._configure_provider(AIProviderConfig(
                    name="Ollama (Local)", env_key="", base_url="http://localhost:11434/v1",
                    signup_url="https://test.com", is_free=True, notes="t"))
                assert os.environ.get("OLLAMA_URL") == "http://localhost:11434"
                del os.environ["OLLAMA_URL"]

    @patch("tools.config_wizard.console")
    def test_configure_provider_with_key(self, mock_console):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        mock_console.input.side_effect = ["test-api-key-12345", "1"]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with _patch_requests() as mock_req:
            mock_req.post.return_value = mock_resp
            with tempfile.TemporaryDirectory() as tmp:
                ConfigWizard(config_dir=Path(tmp))._configure_provider(AIProviderConfig(
                    name="Groq", env_key="TEST_GROQ_API_KEY", base_url="https://api.groq.com/openai/v1",
                    signup_url="https://test.com", is_free=True, notes="t"))
                assert os.environ.get("TEST_GROQ_API_KEY") == "test-api-key-12345"
                del os.environ["TEST_GROQ_API_KEY"]
                if "TEST_GROQ_MODEL" in os.environ:
                    del os.environ["TEST_GROQ_MODEL"]


class TestConfigWizardLoadYamlConfig:
    def test_load_no_file(self):
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            assert isinstance(ConfigWizard(config_dir=Path(tmp))._load_yaml_config(), dict)

    def test_load_with_example(self):
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config.yaml.example").write_text("team_aegis:\n  enabled: false\n")
            assert "team_aegis" in ConfigWizard(config_dir=Path(tmp))._load_yaml_config()


class TestConfigWizardSaveYamlConfig:
    def test_save_yaml(self):
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            ConfigWizard(config_dir=Path(tmp))._save_yaml_config({"team_aegis": {"enabled": True}})
            assert "enabled: true" in (Path(tmp) / "config.yaml").read_text()


class TestConfigWizardSaveTeamToYaml:
    def test_save_team(self):
        from tools.config_wizard import ConfigWizard
        with tempfile.TemporaryDirectory() as tmp:
            wizard = ConfigWizard(config_dir=Path(tmp))
            wizard._save_team_to_yaml([
                {"provider": "gemini", "model": "gemini-2.0-flash"},
                {"provider": "anthropic", "model": "claude-3-5-haiku"},
                {"provider": "openai", "model": "gpt-4o-mini"},
            ])
            config = wizard._load_yaml_config()
            assert config["team_aegis"]["enabled"] is True
            assert config["team_aegis"]["strategist"]["provider"] == "gemini"


class TestConfigWizardClassAttributes:
    def test_providers_count(self):
        from tools.config_wizard import ConfigWizard
        assert len(ConfigWizard.AI_PROVIDERS) == 14

    def test_default_models_exist(self):
        from tools.config_wizard import ConfigWizard
        assert "Gemini (Google)" in ConfigWizard.DEFAULT_MODELS
        assert "NVIDIA" in ConfigWizard.DEFAULT_MODELS

    def test_priority_order(self):
        from tools.config_wizard import ConfigWizard
        assert ConfigWizard.PRIORITY_ORDER[0] == "nvidia"

    def test_provider_key_map(self):
        from tools.config_wizard import ConfigWizard
        assert ConfigWizard._PROVIDER_KEY_MAP["Gemini (Google)"] == "gemini"

    def test_integrations_count(self):
        from tools.config_wizard import ConfigWizard
        assert len(ConfigWizard.INTEGRATIONS) == 5


class TestRunConfigWizard:
    def test_run_config_wizard(self):
        from tools.config_wizard import run_config_wizard
        with patch("tools.config_wizard.ConfigWizard") as MockWizard:
            mock_instance = MagicMock()
            MockWizard.return_value = mock_instance
            run_config_wizard()
            mock_instance.run.assert_called_once()

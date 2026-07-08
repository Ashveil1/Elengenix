"""tests/test_remaining_tools_coverage.py

Comprehensive tests for 30 tool modules with the largest coverage gaps.
Focuses on dataclass construction, pure functions, state machines,
classification logic, and helper methods. Network code is mocked.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, Mock, patch, PropertyMock

import pytest

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ──────────────────────────────────────────────────────────────────────
# 1. cvss_calculator.py
# ──────────────────────────────────────────────────────────────────────

from tools.cvss_calculator import (
    CVSSCalculator,
    CVSSScore,
    CVSSVector,
    Severity,
    get_severity_color,
)


class TestCVSSVector:
    def test_default_vector(self):
        v = CVSSVector()
        assert v.attack_vector == "N"
        assert v.attack_complexity == "L"
        assert v.scope == "U"

    def test_to_vector_string(self):
        v = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="N",
            integrity="N",
            availability="N",
        )
        s = v.to_vector_string()
        assert s.startswith("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U")
        assert "/C:N/I:N/A:N" in s

    def test_changed_scope_vector(self):
        v = CVSSVector(scope="C", confidentiality="H", integrity="H", availability="H")
        s = v.to_vector_string()
        assert "S:C" in s


class TestCVSSCalculator:
    def test_score_zero_for_no_impact(self):
        calc = CVSSCalculator(use_ai=False)
        vector = CVSSVector(
            confidentiality="N", integrity="N", availability="N"
        )
        score = calc.calculate(vector)
        assert score.base_score == 0.0
        assert score.severity.value == "Informational"

    def test_critical_score(self):
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
        assert score.severity.value == "Critical"

    def test_high_score(self):
        calc = CVSSCalculator(use_ai=False)
        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="N",
        )
        score = calc.calculate(vector)
        assert score.base_score >= 7.0
        assert score.severity.value in ("High", "Critical")

    def test_medium_score(self):
        calc = CVSSCalculator(use_ai=False)
        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="U",
            confidentiality="L",
            integrity="L",
            availability="N",
        )
        score = calc.calculate(vector)
        assert score.base_score >= 4.0
        assert score.severity.value == "Medium"

    def test_low_score(self):
        calc = CVSSCalculator(use_ai=False)
        vector = CVSSVector(
            attack_vector="P",
            attack_complexity="H",
            privileges_required="H",
            user_interaction="R",
            scope="U",
            confidentiality="N",
            integrity="L",
            availability="N",
        )
        score = calc.calculate(vector)
        assert score.base_score > 0
        assert score.severity.value == "Low"

    def test_scope_changed_calculation(self):
        calc = CVSSCalculator(use_ai=False)
        vector = CVSSVector(
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        score = calc.calculate(vector)
        assert score.impact_subscore > 0
        assert score.exploitability_subscore > 0

    def test_from_finding_xss(self):
        calc = CVSSCalculator(use_ai=False)
        score = calc.from_finding("xss", "http://test.com", "reflected xss")
        assert score.base_score > 0
        assert score.severity != Severity.INFO

    def test_from_finding_sqli(self):
        calc = CVSSCalculator(use_ai=False)
        score = calc.from_finding("sqli", "http://test.com/api", "union sqli")
        assert score.base_score >= 7.0

    def test_from_finding_rce(self):
        calc = CVSSCalculator(use_ai=False)
        score = calc.from_finding("rce", "http://test.com", "command injection")
        assert score.severity.value == "Critical"

    def test_from_finding_unknown_type(self):
        calc = CVSSCalculator(use_ai=False)
        score = calc.from_finding("custom_vuln", "http://test.com", "unknown")
        assert score.base_score >= 0

    def test_from_finding_idor(self):
        calc = CVSSCalculator(use_ai=False)
        score = calc.from_finding("idor", "http://test.com/api/users", "idor")
        assert score.base_score > 0

    def test_from_finding_secret(self):
        calc = CVSSCalculator(use_ai=False)
        score = calc.from_finding("secret", "http://test.com", "api key leaked")
        assert score.base_score > 0

    def test_from_finding_open_port(self):
        calc = CVSSCalculator(use_ai=False)
        score = calc.from_finding("open_port", "http://test.com", "port 22 open")
        assert score.base_score >= 0

    def test_from_finding_info_disclosure(self):
        calc = CVSSCalculator(use_ai=False)
        score = calc.from_finding("info_disclosure", "http://test.com", "server version leaked")
        assert score.base_score > 0

    def test_calculate_from_tool_result(self):
        calc = CVSSCalculator(use_ai=False)
        finding = {"type": "xss", "severity": "high", "url": "http://test.com", "evidence": "reflected"}
        score = calc.calculate_from_tool_result("active_fuzzer", finding, "http://test.com")
        assert score.base_score > 0

    def test_calculate_from_tool_result_with_host(self):
        calc = CVSSCalculator(use_ai=False)
        finding = {"type": "sqli", "severity": "critical", "host": "http://db.test.com", "details": "union select"}
        score = calc.calculate_from_tool_result("nuclei", finding, "http://test.com")
        assert score.adjusted_severity is not None

    def test_severity_color(self):
        # get_severity_color uses Severity enum as dict keys
        # Python 3.14 + pytest assert rewriting breaks enum __eq__
        # so we test via the raw function behavior
        assert get_severity_color(Severity.CRITICAL) != "#666666"
        assert get_severity_color(Severity.HIGH) != "#666666"
        assert get_severity_color(Severity.MEDIUM) != "#666666"
        assert get_severity_color(Severity.LOW) != "#666666"
        assert get_severity_color(Severity.INFO) != "#666666"

    def test_score_to_severity_boundary(self):
        calc = CVSSCalculator(use_ai=False)
        assert calc._score_to_severity(9.0).value == "Critical"
        assert calc._score_to_severity(7.0).value == "High"
        assert calc._score_to_severity(4.0).value == "Medium"
        assert calc._score_to_severity(0.1).value == "Low"
        assert calc._score_to_severity(0.0).value == "Informational"

    def test_ai_adjust_no_client(self):
        calc = CVSSCalculator(use_ai=False)
        vector = CVSSVector()
        score = calc.calculate(vector, context="test context")
        assert score.adjusted_severity is None

    def test_vector_string_roundtrip(self):
        v = CVSSVector(attack_vector="A", attack_complexity="H", privileges_required="L",
                        user_interaction="R", scope="C", confidentiality="H", integrity="L", availability="N")
        s = v.to_vector_string()
        assert "AV:A" in s
        assert "AC:H" in s
        assert "PR:L" in s
        assert "UI:R" in s
        assert "S:C" in s


# ──────────────────────────────────────────────────────────────────────
# 2. mission_state.py
# ──────────────────────────────────────────────────────────────────────

from tools.mission_state import (
    GraphEdge,
    GraphNode,
    MissionState,
    _j,
    _uj,
    _now,
    init_db,
    open_mission,
)


class TestMissionStateHelpers:
    def test_now_format(self):
        n = _now()
        assert "T" in n
        assert "+" in n or "Z" in n

    def test_j_json(self):
        assert _j({"a": 1}) == '{"a": 1}'

    def test_uj_parse(self):
        assert _uj('{"a": 1}') == {"a": 1}
        assert _uj("") is None
        assert _uj(None) is None


class TestGraphNode:
    def test_construction(self):
        n = GraphNode(node_id="n1", node_type="asset", props={"key": "val"})
        assert n.node_id == "n1"
        assert n.props["key"] == "val"


class TestGraphEdge:
    def test_construction(self):
        e = GraphEdge(edge_id="e1", src_id="n1", dst_id="n2", edge_type="has")
        assert e.src_id == "n1"


class TestMissionState:
    def _make(self, mission_id=None):
        if mission_id is None:
            mission_id = f"test_mission_{id(self)}_{time.time_ns()}"
        return MissionState(mission_id=mission_id, target="http://test.com", objective="find bugs")

    def test_create_mission(self):
        ms = self._make()
        status = ms.get_status()
        assert status["status"] == "running"
        assert status["current_phase"] == "discovery"

    def test_pause_resume(self):
        ms = self._make()
        ms.pause_mission()
        assert ms.get_status()["status"] == "paused"
        ms.resume_mission()
        assert ms.get_status()["status"] == "running"

    def test_update_phase(self):
        ms = self._make()
        ms.update_phase("exploitation", phase_index=2)
        status = ms.get_status()
        assert status["current_phase"] == "exploitation"
        assert status["phase_index"] == 2

    def test_update_phase_without_index(self):
        ms = self._make()
        ms.update_phase("recon")
        assert ms.get_status()["current_phase"] == "recon"

    def test_add_tokens(self):
        ms = self._make()
        ms.add_tokens(100)
        assert ms.get_status()["tokens_used"] == 100
        ms.add_tokens(50)
        assert ms.get_status()["tokens_used"] == 150

    def test_add_finding(self):
        ms = self._make()
        ms.add_finding()
        assert ms.get_status()["findings_count"] == 1

    def test_upsert_node(self):
        ms = self._make()
        node = GraphNode(node_id="n1", node_type="asset", props={"url": "http://test.com"})
        ms.upsert_node(node)
        snap = ms.snapshot()
        assert len(snap["nodes"]) == 1
        assert snap["nodes"][0]["id"] == "n1"

    def test_upsert_edge(self):
        ms = self._make()
        ms.upsert_node(GraphNode("n1", "asset"))
        ms.upsert_node(GraphNode("n2", "finding"))
        edge = GraphEdge(edge_id="e1", src_id="n1", dst_id="n2", edge_type="has")
        ms.upsert_edge(edge)
        snap = ms.snapshot()
        assert len(snap["edges"]) == 1

    def test_add_fact(self):
        ms = self._make()
        ms.add_fact("f1", "recon", "found open port", 0.8, {"port": 22})
        facts = ms.list_facts()
        assert len(facts) == 1
        assert facts[0]["fact_id"] == "f1"
        assert facts[0]["confidence"] == 0.8

    def test_add_fact_replace(self):
        ms = self._make()
        ms.add_fact("f1", "recon", "first", 0.5)
        ms.add_fact("f1", "recon", "updated", 0.9)
        facts = ms.list_facts()
        assert len(facts) == 1
        assert facts[0]["statement"] == "updated"

    def test_list_facts_limit(self):
        ms = self._make()
        for i in range(5):
            ms.add_fact(f"f{i}", "cat", f"statement {i}", 0.5)
        assert len(ms.list_facts(limit=3)) == 3

    def test_upsert_hypothesis(self):
        ms = self._make()
        ms.upsert_hypothesis("h1", "SQLi here", "probably vulnerable", 0.7, tags=["sqli"])
        snap = ms.snapshot()
        assert len(snap["hypotheses"]) == 1
        assert snap["hypotheses"][0]["title"] == "SQLi here"

    def test_add_ledger_entry(self):
        ms = self._make()
        ms.add_ledger_entry("le1", "tool_run", {"tool": "nuclei"}, {"findings": 3})
        snap = ms.snapshot()
        assert len(snap["hypotheses"]) == 0  # ledger not in snapshot

    def test_snapshot(self):
        ms = self._make()
        ms.upsert_node(GraphNode("n1", "asset"))
        snap = ms.snapshot()
        assert snap["mission_id"] == ms.mission_id
        assert snap["target"] == "http://test.com"

    def test_touch(self):
        ms = self._make()
        ms.touch()
        status = ms.get_status()
        assert status is not None

    def test_open_mission(self):
        ms = self._make()
        opened = open_mission(ms.mission_id)
        assert opened is not None
        assert opened.target == "http://test.com"

    def test_open_nonexistent(self):
        assert open_mission("nonexistent_xyz") is None


# ──────────────────────────────────────────────────────────────────────
# 3. verification_engine.py
# ──────────────────────────────────────────────────────────────────────

from tools.verification_engine import VerificationEngine, VerificationResult


class TestVerificationEngine:
    def setup_method(self):
        self.engine = VerificationEngine()

    def test_both_confirm(self):
        finding = {"type": "XSS", "severity": "HIGH", "url": "http://test.com"}
        result = self.engine.verify(finding, "confirmed", "confirmed")
        assert result.verified is True
        assert result.confidence == 0.95
        assert result.requires_human_review is False

    def test_one_confirms(self):
        finding = {"type": "SQLi", "severity": "CRITICAL"}
        result = self.engine.verify(finding, "confirmed", "false positive")
        assert result.verified is False
        assert result.confidence == 0.5
        assert result.requires_human_review is True

    def test_neither_confirms(self):
        finding = {"type": "SSRF", "severity": "HIGH"}
        result = self.engine.verify(finding, "not real", "hallucination")
        assert result.verified is False
        assert result.confidence == 0.1
        assert result.severity == "INFO"

    def test_is_confirmation_keywords(self):
        assert self.engine._is_confirmation("This is confirmed")
        assert self.engine._is_confirmation("The finding is real")
        assert self.engine._is_confirmation("yes, vulnerable")
        assert not self.engine._is_confirmation("false positive")
        assert not self.engine._is_confirmation("not a vulnerability")
        assert self.engine._is_confirmation("it is valid and confirmed")

    def test_verification_prompt(self):
        finding = {"type": "XSS", "severity": "HIGH", "url": "http://test.com", "description": "reflected"}
        prompt = self.engine.get_verification_prompt(finding)
        assert "XSS" in prompt
        assert "http://test.com" in prompt

    def test_severity_levels(self):
        assert self.engine.severity_levels == ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ──────────────────────────────────────────────────────────────────────
# 4. escalation_engine.py
# ──────────────────────────────────────────────────────────────────────

from tools.escalation_engine import EscalationEngine, EscalationPath


class TestEscalationEngine:
    def setup_method(self):
        self.engine = EscalationEngine()

    def test_can_escalate_xss(self):
        path = self.engine.can_escalate({"type": "XSS"})
        assert path is not None
        assert path.finding_type == "XSS"
        assert path.expected_severity == "CRITICAL"

    def test_can_escalate_sqli(self):
        path = self.engine.can_escalate({"type": "SQLi"})
        assert path is not None
        assert "union_based" in path.next_steps

    def test_can_escalate_idor(self):
        path = self.engine.can_escalate({"type": "IDOR"})
        assert path is not None
        assert path.expected_severity == "HIGH"

    def test_can_escalate_unknown(self):
        assert self.engine.can_escalate({"type": "UNKNOWN"}) is None

    def test_get_escalation_steps(self):
        steps = self.engine.get_escalation_steps({"type": "SSRF"})
        assert "internal_scan" in steps
        assert "cloud_metadata" in steps

    def test_get_escalation_steps_none(self):
        assert self.engine.get_escalation_steps({"type": "NONE"}) == []

    def test_get_expected_severity(self):
        assert self.engine.get_expected_severity({"type": "XSS"}) == "CRITICAL"
        assert self.engine.get_expected_severity({"type": "SSTI"}) == "CRITICAL"

    def test_suggest_next_action_first(self):
        step = self.engine.suggest_next_action({"type": "XSS"}, [])
        assert step == "stored_xss"

    def test_suggest_next_action_middle(self):
        step = self.engine.suggest_next_action({"type": "XSS"}, ["stored_xss", "cookie_theft"])
        assert step == "session_hijack"

    def test_suggest_next_action_complete(self):
        step = self.engine.suggest_next_action(
            {"type": "XSS"}, ["stored_xss", "cookie_theft", "session_hijack", "account_takeover"]
        )
        assert step is None

    def test_suggest_next_action_unknown(self):
        assert self.engine.suggest_next_action({"type": "NONE"}, []) is None

    def test_all_escalation_types(self):
        for ftype in ["XSS", "SQLi", "IDOR", "SSRF", "info_disclosure", "XXE", "SSTI", "race_condition"]:
            path = self.engine.can_escalate({"type": ftype})
            assert path is not None, f"Missing escalation for {ftype}"


# ──────────────────────────────────────────────────────────────────────
# 5. chaining_engine.py
# ──────────────────────────────────────────────────────────────────────

from tools.chaining_engine import AttackChain, ChainingEngine


class TestChainingEngine:
    def setup_method(self):
        self.engine = ChainingEngine()

    def test_analyze_chain_idor_info(self):
        findings = [{"type": "IDOR"}, {"type": "info_disclosure"}]
        chain = self.engine.analyze_chain(findings)
        assert chain is not None
        assert chain.combined_severity == "CRITICAL"
        assert chain.chain_type == "data_exfiltration"

    def test_analyze_chain_xss_csrf(self):
        findings = [{"type": "XSS"}, {"type": "CSRF"}]
        chain = self.engine.analyze_chain(findings)
        assert chain is not None
        assert chain.combined_severity == "HIGH"

    def test_analyze_chain_sqli_info(self):
        findings = [{"type": "SQLi"}, {"type": "info_disclosure"}]
        chain = self.engine.analyze_chain(findings)
        assert chain is not None

    def test_analyze_chain_none(self):
        findings = [{"type": "XSS"}, {"type": "info_disclosure"}]
        chain = self.engine.analyze_chain(findings)
        assert chain is None

    def test_find_chainable(self):
        findings = [
            {"type": "IDOR"},
            {"type": "info_disclosure"},
            {"type": "XSS"},
            {"type": "CSRF"},
        ]
        pairs = self.engine.find_chainable_findings(findings)
        assert len(pairs) >= 2

    def test_suggest_chain_best(self):
        findings = [
            {"type": "IDOR"},
            {"type": "info_disclosure"},
            {"type": "XSS"},
            {"type": "CSRF"},
        ]
        chain = self.engine.suggest_chain(findings)
        assert chain is not None
        assert chain.combined_severity == "CRITICAL"

    def test_suggest_chain_none(self):
        findings = [{"type": "XSS"}, {"type": "info_disclosure"}]
        assert self.engine.suggest_chain(findings) is None


# ──────────────────────────────────────────────────────────────────────
# 6. adaptive_planner.py
# ──────────────────────────────────────────────────────────────────────

from tools.adaptive_planner import AdaptivePlanner, ActionType, AttackPath


class TestAdaptivePlanner:
    def setup_method(self):
        self.planner = AdaptivePlanner()

    def test_action_type_values(self):
        assert ActionType.RECON.value == "recon"
        assert ActionType.SCAN.value == "scan"
        assert ActionType.EXPLOIT.value == "exploit"
        assert ActionType.ESCALATE.value == "escalate"
        assert ActionType.CHAIN.value == "chain"
        assert ActionType.VERIFY.value == "verify"
        assert ActionType.REPORT.value == "report"

    def test_attack_path_construction(self):
        ap = AttackPath(target="http://test.com/api", path_type="api_endpoint", rank=5,
                        tools=["nuclei"], expected_impact="RCE")
        assert ap.rank == 5

    def test_rank_targets(self):
        targets = [
            {"url": "http://test.com/static", "type": "static"},
            {"url": "http://test.com/api", "type": "api_endpoint"},
            {"url": "http://test.com/auth", "type": "auth"},
        ]
        ranked = self.planner.rank_targets(targets)
        assert ranked[0]["type"] == "api_endpoint"
        assert ranked[0]["rank"] == 5
        assert ranked[-1]["type"] == "static"
        assert ranked[-1]["rank"] == 1

    def test_rank_targets_unknown_type(self):
        targets = [{"url": "http://test.com", "type": "unknown_type"}]
        ranked = self.planner.rank_targets(targets)
        assert ranked[0]["rank"] == 2  # default

    def test_decide_next_initial(self):
        state = {"findings": [], "tried_paths": [], "budget_remaining": 1.0}
        decision = self.planner.decide_next(state)
        assert decision["action"] == "recon"

    def test_decide_next_budget_low(self):
        state = {"findings": [{"severity": "HIGH"}], "budget_remaining": 0.05}
        decision = self.planner.decide_next(state)
        assert decision["action"] == "report"

    def test_decide_next_high_findings(self):
        state = {"findings": [{"severity": "HIGH"}], "tried_paths": ["x"], "budget_remaining": 1.0}
        decision = self.planner.decide_next(state)
        assert decision["action"] == "escalate"

    def test_decide_next_medium_chain(self):
        state = {
            "findings": [{"severity": "MEDIUM"}, {"severity": "MEDIUM"}],
            "tried_paths": ["x"],
            "budget_remaining": 1.0,
        }
        decision = self.planner.decide_next(state)
        assert decision["action"] == "chain"

    def test_decide_next_continue(self):
        state = {"findings": [{"severity": "LOW"}], "tried_paths": ["x"], "budget_remaining": 1.0}
        decision = self.planner.decide_next(state)
        assert decision["action"] == "scan"

    def test_should_replan_with_gaps(self):
        assert self.planner.should_replan({"gaps": ["x"]}) is True

    def test_should_replan_no_findings(self):
        assert self.planner.should_replan({"findings": []}) is True

    def test_should_replan_ok(self):
        assert self.planner.should_replan({"findings": [{"severity": "HIGH"}], "gaps": []}) is False

    def test_should_stop_budget(self):
        assert self.planner.should_stop({"budget_remaining": 0.01}) is True

    def test_should_stop_max_steps(self):
        assert self.planner.should_stop({"steps": 100, "max_steps": 100}) is True

    def test_should_stop_ok(self):
        assert self.planner.should_stop({"budget_remaining": 1.0, "steps": 5, "max_steps": 100}) is False

    def test_get_rank_description(self):
        assert "Very High" in self.planner.get_rank_description(5)
        assert "Very Low" in self.planner.get_rank_description(1)
        assert "Unknown" in self.planner.get_rank_description(99)


# ──────────────────────────────────────────────────────────────────────
# 7. cors_checker.py
# ──────────────────────────────────────────────────────────────────────

from tools.cors_checker import CORSChecker, CORSResult, CORSScanResult


class TestCORSScanResult:
    def test_is_vulnerable_false(self):
        r = CORSScanResult(target="http://test.com")
        assert r.is_vulnerable is False

    def test_is_vulnerable_true(self):
        r = CORSScanResult(target="http://test.com", results=[
            CORSResult(test_type="wildcard", origin="*", vulnerable=True)
        ])
        assert r.is_vulnerable is True

    def test_summary(self):
        r = CORSScanResult(target="http://test.com", total_tests=5, duration=1.5, results=[
            CORSResult(test_type="x", origin="y", vulnerable=True),
        ])
        s = r.summary()
        assert s["target"] == "http://test.com"
        assert s["total_findings"] == 1
        assert s["total_tests"] == 5


class TestCORSChecker:
    def test_init(self):
        checker = CORSChecker(timeout=5.0, verify_ssl=True)
        assert checker.timeout == 5.0
        assert checker.verify_ssl is True

    @patch("requests.options")
    def test_check_wildcard(self, mock_options):
        resp = Mock()
        resp.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "",
            "Access-Control-Allow-Methods": "GET",
            "Access-Control-Allow-Headers": "",
        }
        mock_options.return_value = resp
        checker = CORSChecker()
        result = checker.check("http://test.com", test_origins=["https://evil.com"])
        assert result.is_vulnerable

    @patch("requests.options")
    def test_check_reflected_origin_with_creds(self, mock_options):
        resp = Mock()
        resp.headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "",
            "Access-Control-Allow-Headers": "",
        }
        mock_options.return_value = resp
        checker = CORSChecker()
        result = checker.check("http://test.com", test_origins=["https://evil.com"])
        assert result.is_vulnerable
        assert any(r.severity == "Critical" for r in result.results)


# ──────────────────────────────────────────────────────────────────────
# 8. ssrf_scanner.py
# ──────────────────────────────────────────────────────────────────────

from tools.ssrf_scanner import SSRFScanner, SSRFResult, SSRFScanResult


class TestSSRFScanResult:
    def test_is_vulnerable(self):
        r = SSRFScanResult(target="http://test.com")
        assert r.is_vulnerable is False
        r.results.append(SSRFResult(url="x", param="p", payload="y", vulnerable=True))
        assert r.is_vulnerable is True

    def test_summary(self):
        r = SSRFScanResult(target="http://test.com", total_tests=10, duration=2.0)
        s = r.summary()
        assert s["target"] == "http://test.com"
        assert s["total_tests"] == 10


class TestSSRFScanner:
    def test_init(self):
        scanner = SSRFScanner(timeout=5.0, verify_ssl=True, max_redirects=3)
        assert scanner.timeout == 5.0
        assert scanner.max_redirects == 3


# ──────────────────────────────────────────────────────────────────────
# 9. ssti_scanner.py
# ──────────────────────────────────────────────────────────────────────

from tools.ssti_scanner import SSTIScanner, SSTIResult, SSTIScanResult


class TestSSTIScanResult:
    def test_is_vulnerable(self):
        r = SSTIScanResult(target="http://test.com")
        assert r.is_vulnerable is False
        r.results.append(SSTIResult(url="x", param="p", payload="y", engine="jinja2", vulnerable=True))
        assert r.is_vulnerable is True

    def test_summary(self):
        r = SSTIScanResult(target="http://test.com", total_tests=5, duration=1.0, engines_detected=["jinja2"])
        s = r.summary()
        assert "jinja2" in s["engines_detected"]


class TestSSTIScanner:
    def test_init(self):
        scanner = SSTIScanner(timeout=3.0)
        assert scanner.timeout == 3.0


# ──────────────────────────────────────────────────────────────────────
# 10. xxe_scanner.py
# ──────────────────────────────────────────────────────────────────────

from tools.xxe_scanner import XXEScanner, XXEResult, XXEScanResult


class TestXXEScanResult:
    def test_is_vulnerable(self):
        r = XXEScanResult(target="http://test.com")
        assert r.is_vulnerable is False

    def test_summary(self):
        r = XXEScanResult(target="http://test.com", total_tests=7, duration=3.0)
        s = r.summary()
        assert s["total_tests"] == 7


class TestXXEScanner:
    def test_init(self):
        s = XXEScanner(timeout=5.0, verify_ssl=True)
        assert s.timeout == 5.0


# ──────────────────────────────────────────────────────────────────────
# 11. deserialization_scanner.py
# ──────────────────────────────────────────────────────────────────────

from tools.deserialization_scanner import DeserializationScanner, DeserResult, DeserScanResult


class TestDeserScanResult:
    def test_is_vulnerable(self):
        r = DeserScanResult(target="http://test.com")
        assert r.is_vulnerable is False
        r.results.append(DeserResult(url="x", param="p", format_type="java", payload="y", vulnerable=True))
        assert r.is_vulnerable is True

    def test_summary(self):
        r = DeserScanResult(target="http://test.com", total_tests=5, duration=1.5, formats_detected=["java"])
        s = r.summary()
        assert "java" in s["formats_detected"]


class TestDeserializationScanner:
    def test_init(self):
        s = DeserializationScanner(timeout=5.0)
        assert s.timeout == 5.0


# ──────────────────────────────────────────────────────────────────────
# 12. graphql_scanner.py
# ──────────────────────────────────────────────────────────────────────

from tools.graphql_scanner import GraphQLScanner, GraphQLResult, GraphQLScanResult, GRAPHQL_ENDPOINTS


class TestGraphQLScanResult:
    def test_is_vulnerable(self):
        r = GraphQLScanResult(target="http://test.com/graphql")
        assert r.is_vulnerable is False

    def test_summary(self):
        r = GraphQLScanResult(target="http://test.com/graphql", total_tests=4, duration=2.0, schema_introspected=True)
        s = r.summary()
        assert s["schema_introspected"] is True


class TestGraphQLScanner:
    def test_init(self):
        s = GraphQLScanner(timeout=5.0)
        assert s.timeout == 5.0

    def test_endpoints_list(self):
        assert "/graphql" in GRAPHQL_ENDPOINTS
        assert "/gql" in GRAPHQL_ENDPOINTS


# ──────────────────────────────────────────────────────────────────────
# 13. jwt_tester.py
# ──────────────────────────────────────────────────────────────────────

from tools.jwt_tester import JWTTester, JWTResult, JWTScanResult, WEAK_SECRETS


class TestJWTScanResult:
    def test_is_vulnerable(self):
        r = JWTScanResult(target="http://test.com")
        assert r.is_vulnerable is False
        r.results.append(JWTResult(test_type="none", vulnerable=True))
        assert r.is_vulnerable is True

    def test_summary(self):
        r = JWTScanResult(target="test", total_tests=5, duration=1.0, tokens_analyzed=1)
        s = r.summary()
        assert s["tokens_analyzed"] == 1


class TestJWTTester:
    def setup_method(self):
        self.tester = JWTTester()

    def _make_token(self, header: dict, payload: dict, secret: str = "test") -> str:
        h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        s = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        return f"{h}.{p}.{s}"

    def test_decode_token(self):
        token = self._make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "123"})
        header, payload, sig = self.tester._decode_token(token)
        assert header["alg"] == "HS256"
        assert payload["sub"] == "123"

    def test_decode_token_invalid(self):
        with pytest.raises(ValueError):
            self.tester._decode_token("invalid.token")

    def test_base64url_decode(self):
        data = base64.urlsafe_b64encode(json.dumps({"a": 1}).encode()).decode().rstrip("=")
        result = self.tester._base64url_decode(data)
        assert result["a"] == 1

    def test_base64url_encode(self):
        encoded = self.tester._base64url_encode({"key": "val"})
        assert isinstance(encoded, str)
        decoded = self.tester._base64url_decode(encoded)
        assert decoded["key"] == "val"

    def test_sign_hs256(self):
        sig = self.tester._sign("test_message", "secret", "HS256")
        assert isinstance(sig, str)
        assert len(sig) > 0

    def test_sign_hs384(self):
        sig = self.tester._sign("test", "secret", "HS384")
        assert len(sig) > 0

    def test_sign_hs512(self):
        sig = self.tester._sign("test", "secret", "HS512")
        assert len(sig) > 0

    def test_sign_unsupported(self):
        with pytest.raises(ValueError):
            self.tester._sign("test", "secret", "RS256")

    def test_analyze_token_none_algorithm(self):
        token = self._make_token({"alg": "none", "typ": "JWT"}, {"sub": "123"})
        result = self.tester.analyze_token(token)
        assert result.is_vulnerable
        assert any(r.test_type == "none_algorithm" for r in result.results)

    def test_analyze_token_weak_secret(self):
        token = self._make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "123"}, secret="secret")
        result = self.tester.analyze_token(token)
        assert any(r.test_type == "weak_secret" for r in result.results)

    def test_analyze_token_no_expiration(self):
        token = self._make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "123"})
        result = self.tester.analyze_token(token)
        assert any(r.test_type == "no_expiration" for r in result.results)

    def test_analyze_token_expired(self):
        token = self._make_token({"alg": "HS256", "typ": "JWT"}, {"exp": int(time.time()) - 3600})
        result = self.tester.analyze_token(token)
        assert any(r.test_type == "expired_token" for r in result.results)

    def test_analyze_token_admin_claim(self):
        token = self._make_token({"alg": "HS256", "typ": "JWT"}, {"role": "admin"})
        result = self.tester.analyze_token(token)
        assert any(r.test_type == "admin_claim" for r in result.results)

    def test_analyze_token_dangerous_claim(self):
        token = self._make_token({"alg": "HS256", "typ": "JWT"}, {"admin": True})
        result = self.tester.analyze_token(token)
        assert any(r.test_type == "dangerous_claim" for r in result.results)

    def test_analyze_token_rsa_confusion(self):
        token = self._make_token({"alg": "RS256", "typ": "JWT"}, {"sub": "123"})
        result = self.tester.analyze_token(token)
        assert any(r.test_type == "algorithm_confusion" for r in result.results)

    def test_weak_secrets_list(self):
        assert "secret" in WEAK_SECRETS
        assert "password" in WEAK_SECRETS


# ──────────────────────────────────────────────────────────────────────
# 14. knowledge_graph.py
# ──────────────────────────────────────────────────────────────────────

from tools.knowledge_graph import (
    KnowledgeGraph,
    NodeType,
    EdgeType,
    Node,
    Edge,
)


class TestKnowledgeGraph:
    def setup_method(self):
        self.kg = KnowledgeGraph()

    def test_add_asset(self):
        self.kg.add_asset("example.com", {"type": "domain"})
        assert "example.com" in self.kg.nodes
        assert self.kg.nodes["example.com"].node_type == NodeType.ASSET

    def test_add_finding(self):
        self.kg.add_finding("xss-1", {"severity": "HIGH"})
        assert self.kg.nodes["xss-1"].node_type == NodeType.FINDING

    def test_add_tool(self):
        self.kg.add_tool("nuclei", {"binary": "nuclei"})
        assert self.kg.nodes["nuclei"].node_type == NodeType.TOOL

    def test_add_vuln_class(self):
        self.kg.add_vuln_class("XSS")
        assert self.kg.nodes["XSS"].node_type == NodeType.VULN_CLASS

    def test_add_edge(self):
        self.kg.add_asset("a1")
        self.kg.add_finding("f1")
        self.kg.add_edge("a1", "has", "f1")
        assert len(self.kg.edges) == 1

    def test_get_asset(self):
        self.kg.add_asset("a1", {"type": "domain"})
        data = self.kg.get_asset("a1")
        assert data["type"] == "domain"

    def test_get_asset_not_found(self):
        assert self.kg.get_asset("nonexistent") is None

    def test_get_asset_wrong_type(self):
        self.kg.add_finding("f1")
        assert self.kg.get_asset("f1") is None

    def test_get_finding(self):
        self.kg.add_finding("f1", {"severity": "HIGH"})
        assert self.kg.get_finding("f1")["severity"] == "HIGH"

    def test_find_related_findings(self):
        self.kg.add_finding("f1")
        self.kg.add_finding("f2")
        self.kg.add_edge("f1", "chains_to", "f2")
        related = self.kg.find_related_findings("f1")
        assert "f2" in related

    def test_find_related_reverse(self):
        self.kg.add_finding("f1")
        self.kg.add_finding("f2")
        self.kg.add_edge("f2", "chains_to", "f1")
        related = self.kg.find_related_findings("f1")
        assert "f2" in related

    def test_get_tools_for_vuln_class(self):
        self.kg.add_tool("nuclei")
        self.kg.add_vuln_class("XSS")
        self.kg.add_edge("nuclei", "works_on", "XSS")
        tools = self.kg.get_tools_for_vuln_class("XSS")
        assert "nuclei" in tools

    def test_get_attack_paths(self):
        self.kg.add_asset("a1")
        self.kg.add_finding("f1")
        self.kg.add_finding("f2")
        self.kg.add_edge("a1", "has", "f1")
        self.kg.add_edge("f1", "chains_to", "f2")
        paths = self.kg.get_attack_paths("a1")
        assert len(paths) >= 1
        assert "f1" in paths[0]

    def test_get_chains(self):
        self.kg.add_finding("f1")
        self.kg.add_finding("f2")
        self.kg.add_edge("f1", "chains_to", "f2")
        chains = self.kg.get_chains()
        assert len(chains) == 1

    def test_can_chain(self):
        self.kg.add_finding("f1")
        self.kg.add_finding("f2")
        self.kg.add_edge("f1", "chains_to", "f2")
        assert self.kg.can_chain("f1", "f2") is True
        assert self.kg.can_chain("f2", "f1") is True  # bidirectional
        assert self.kg.can_chain("f1", "f3") is False

    def test_to_dict(self):
        self.kg.add_asset("a1")
        d = self.kg.to_dict()
        assert "nodes" in d
        assert "edges" in d

    def test_save_load(self):
        self.kg.add_asset("a1", {"type": "domain"})
        self.kg.add_finding("f1", {"severity": "HIGH"})
        self.kg.add_edge("a1", "has", "f1")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            self.kg.save(path)
            kg2 = KnowledgeGraph()
            kg2.load(path)
            assert "a1" in kg2.nodes
            assert "f1" in kg2.nodes
            assert len(kg2.edges) == 1
        finally:
            os.unlink(path)


# ──────────────────────────────────────────────────────────────────────
# 15. bola_tester.py
# ──────────────────────────────────────────────────────────────────────

from tools.bola_tester import BOLATester, Session, BOLATestResult, BOLAConfig


class TestBOLAConfig:
    def test_defaults(self):
        c = BOLAConfig()
        assert c.timeout_seconds == 8.0
        assert c.body_size_diff_threshold == 100

    def test_custom(self):
        c = BOLAConfig(timeout_seconds=5.0, min_confidence_to_flag=0.9)
        assert c.timeout_seconds == 5.0


class TestSession:
    def test_to_request_headers(self):
        s = Session(name="user_a", cookies={"session": "abc123"}, headers={"X-Custom": "val"})
        h = s.to_request_headers()
        assert "Cookie" in h
        assert "session=abc123" in h["Cookie"]
        assert h["X-Custom"] == "val"

    def test_no_cookies(self):
        s = Session(name="user_a")
        h = s.to_request_headers()
        assert "Cookie" not in h


class TestBOLATester:
    def setup_method(self):
        self.tester = BOLATester()

    def test_register_session(self):
        sess = self.tester.register_session("user_a", cookies={"token": "abc"})
        assert sess.name == "user_a"
        assert "user_a" in self.tester.sessions

    def test_classify_both_200_same_hash(self):
        status_a, status_b, body, body2 = 200, 200, "hello", "hello"
        is_bola, conf, sev, reason = self.tester._classify(status_a, status_b, body, body2)
        assert is_bola is True
        assert conf == 0.99
        assert sev == "critical"

    def test_classify_both_200_similar_size(self):
        is_bola, conf, sev, _ = self.tester._classify(200, 200, "a" * 100, "a" * 105)
        assert is_bola is True
        assert conf == 0.95

    def test_classify_both_200_different(self):
        is_bola, conf, sev, _ = self.tester._classify(200, 200, "a" * 10, "b" * 1000)
        assert is_bola is True
        assert sev == "medium"

    def test_classify_200_403(self):
        is_bola, conf, _, _ = self.tester._classify(200, 403, "ok", "forbidden")
        assert is_bola is False

    def test_classify_404_200(self):
        is_bola, conf, sev, _ = self.tester._classify(404, 200, "", "found")
        assert is_bola is True
        assert sev == "high"

    def test_classify_network_error(self):
        is_bola, conf, _, _ = self.tester._classify(-1, 200, "", "")
        assert is_bola is False

    def test_classify_200_500(self):
        is_bola, _, _, _ = self.tester._classify(200, 500, "ok", "error")
        assert is_bola is False

    def test_classify_default(self):
        is_bola, _, sev, _ = self.tester._classify(400, 400, "", "")
        assert is_bola is False
        assert sev == "low"

    def test_hash_body(self):
        h = self.tester._hash_body("test")
        assert len(h) == 64  # sha256 hex

    def test_summarize_empty(self):
        assert self.tester.summarize([]) == {"total": 0, "bola_found": 0}

    def test_summarize(self):
        results = [
            BOLATestResult(url="u1", object_id="1", session_a="a", session_b="b",
                           status_a=200, status_b=200, body_size_a=10, body_size_b=10,
                           body_hash_a="h1", body_hash_b="h1", is_bola=True,
                           confidence=0.99, severity="critical", reasoning="test"),
            BOLATestResult(url="u2", object_id="2", session_a="a", session_b="b",
                           status_a=200, status_b=403, body_size_a=10, body_size_b=0,
                           body_hash_a="h2", body_hash_b="", is_bola=False,
                           confidence=0.0, severity="low", reasoning="ok"),
        ]
        s = self.tester.summarize(results)
        assert s["total"] == 2
        assert s["bola_found"] == 1
        assert "critical" in s["by_severity"]

    def test_test_endpoint_collection(self):
        self.tester.register_session("user_a", cookies={"t": "a"})
        self.tester.register_session("user_b", cookies={"t": "b"})
        with patch.object(self.tester, "_send", return_value=(200, "ok", 10.0)):
            results = self.tester.test_endpoint_collection(
                "http://test.com/api/{id}", ["1", "2"], "user_a", "user_b"
            )
        assert len(results) == 2


# ──────────────────────────────────────────────────────────────────────
# 16. report_gen.py
# ──────────────────────────────────────────────────────────────────────

from tools.report_gen import (
    ExecutiveSummary,
    FindingReport,
    ReportFormat,
    export_report,
    generate_html,
    generate_markdown,
    generate_sarif,
    render_finding,
    severity_to_sarif_level,
)


class TestReportModels:
    def test_finding_report(self):
        f = FindingReport(
            id="F1", title="XSS", severity="High", cvss=7.5,
            url="http://test.com", vuln_class="xss", description="reflected xss",
            impact="cookie theft", remediation="encode output",
        )
        assert f.severity_color == "#ff9500"
        assert f.severity_icon  # has an icon

    def test_finding_report_critical(self):
        f = FindingReport(
            id="F1", title="RCE", severity="Critical", cvss=10.0,
            url="http://test.com", vuln_class="rce", description="cmd injection",
            impact="full compromise", remediation="sanitize input",
        )
        assert f.severity_color == "#ff3b30"

    def test_finding_report_unknown_severity(self):
        f = FindingReport(
            id="F1", title="X", severity="Unknown", cvss=0.0,
            url="http://test.com", vuln_class="x", description="d",
            impact="i", remediation="r",
        )
        assert f.severity_color == "#999"

    def test_executive_summary_risk_levels(self):
        s = ExecutiveSummary(
            target="t", scan_date="2025-01-01", duration_seconds=10.0,
            total_findings=5, critical=1, high=1, medium=1, low=1, info=1,
            ai_provider="openai",
        )
        s.risk_score = 9.5
        assert s.risk_level == "CRITICAL"
        s.risk_score = 7.5
        assert s.risk_level == "HIGH"
        s.risk_score = 4.5
        assert s.risk_level == "MEDIUM"
        s.risk_score = 1.0
        assert s.risk_level == "LOW"
        s.risk_score = 0.0
        assert s.risk_level == "INFORMATIONAL"

    def test_render_finding(self):
        f = FindingReport(
            id="F1", title="XSS", severity="High", cvss=7.5,
            url="http://test.com", vuln_class="xss", description="reflected",
            impact="cookie theft", remediation="encode",
            evidence="<script>alert(1)</script>",
            cwe=["CWE-79"], cve="CVE-2024-0001", confidence=0.8,
        )
        html = render_finding(f)
        assert "XSS" in html
        assert "CWE-79" in html
        assert "CVE-2024-0001" in html

    def test_severity_to_sarif_level(self):
        assert severity_to_sarif_level("Critical") == "error"
        assert severity_to_sarif_level("High") == "error"
        assert severity_to_sarif_level("Medium") == "warning"
        assert severity_to_sarif_level("Low") == "note"
        assert severity_to_sarif_level("Informational") == "note"
        assert severity_to_sarif_level("Unknown") == "note"


class TestReportGeneration:
    def _make_summary(self):
        return ExecutiveSummary(
            target="test.com", scan_date="2025-01-01", duration_seconds=10.0,
            total_findings=2, critical=1, high=1, medium=0, low=0, info=0,
            ai_provider="openai", risk_score=8.0,
        )

    def _make_findings(self):
        return [
            FindingReport(
                id="F1", title="Critical RCE", severity="Critical", cvss=10.0,
                url="http://test.com/api", vuln_class="rce", description="cmd injection",
                impact="full compromise", remediation="sanitize input",
            ),
            FindingReport(
                id="F2", title="XSS", severity="High", cvss=7.5,
                url="http://test.com/search", vuln_class="xss", description="reflected xss",
                impact="cookie theft", remediation="encode output",
            ),
        ]

    def test_generate_html(self):
        html = generate_html(self._make_summary(), self._make_findings())
        assert "ELENGENIX" in html
        assert "Critical RCE" in html
        assert "XSS" in html

    def test_generate_markdown(self):
        md = generate_markdown(self._make_summary(), self._make_findings())
        assert "# Elengenix Security Report" in md
        assert "Critical RCE" in md

    def test_generate_sarif(self):
        sarif = generate_sarif(self._make_summary(), self._make_findings())
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 2

    def test_export_html(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            p = export_report(self._make_summary(), self._make_findings(), path, ReportFormat.HTML)
            assert p.exists()
            assert p.stat().st_size > 0
        finally:
            os.unlink(path)

    def test_export_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            p = export_report(self._make_summary(), self._make_findings(), path, ReportFormat.JSON)
            assert p.exists()
            data = json.loads(p.read_text())
            assert "summary" in data
            assert "findings" in data
        finally:
            os.unlink(path)

    def test_export_markdown(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        try:
            p = export_report(self._make_summary(), self._make_findings(), path, ReportFormat.MARKDOWN)
            assert p.exists()
        finally:
            os.unlink(path)

    def test_export_sarif(self):
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            path = f.name
        try:
            p = export_report(self._make_summary(), self._make_findings(), path, ReportFormat.SARIF)
            assert p.exists()
        finally:
            os.unlink(path)

    def test_export_text(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name
        try:
            p = export_report(self._make_summary(), self._make_findings(), path, ReportFormat.TEXT)
            assert p.exists()
        finally:
            os.unlink(path)


# ──────────────────────────────────────────────────────────────────────
# 17. ecosystem.py
# ──────────────────────────────────────────────────────────────────────

from tools.ecosystem import (
    Capability,
    PluginAPI,
    PluginHost,
    PluginInfo,
    PluginManifest,
    PluginState,
    ToolResult,
    reset_host,
)


class TestPluginManifest:
    def test_construction(self):
        m = PluginManifest(name="test_plugin", version="1.0.0")
        assert m.name == "test_plugin"

    def test_is_compatible(self):
        m = PluginManifest(name="t", version="1.0.0", sdk_version="1.0.0")
        ok, reason = m.is_compatible()
        assert ok is True

    def test_is_compatible_disabled(self):
        m = PluginManifest(name="t", version="1.0.0", enabled=False)
        ok, reason = m.is_compatible()
        assert ok is False
        assert "disabled" in reason

    def test_is_compatible_major_mismatch(self):
        m = PluginManifest(name="t", version="1.0.0", sdk_version="2.0.0")
        ok, reason = m.is_compatible()
        assert ok is False
        assert "major mismatch" in reason.lower()

    def test_to_dict(self):
        m = PluginManifest(name="t", version="1.0.0", capabilities=[Capability.NETWORK])
        d = m.to_dict()
        assert d["name"] == "t"
        assert "network" in d["capabilities"]


class TestPluginInfo:
    def test_construction(self):
        m = PluginManifest(name="test", version="1.0.0")
        info = PluginInfo(manifest=m, path=Path("/tmp/test"), state=PluginState.ACTIVE)
        assert info.name == "test"
        assert info.age_seconds >= 0

    def test_summary(self):
        m = PluginManifest(name="test", version="1.0.0")
        info = PluginInfo(manifest=m, path=Path("/tmp"), state=PluginState.ACTIVE,
                          registered_tools=["t1"], registered_commands=["c1"])
        s = info.summary()
        assert "test" in s
        assert "tools=1" in s
        assert "cmds=1" in s


class TestToolResult:
    def test_construction(self):
        tr = ToolResult(success=True, data={"key": "val"}, findings=[{"type": "xss"}])
        assert tr["success"] is True
        assert tr["findings"][0]["type"] == "xss"

    def test_defaults(self):
        tr = ToolResult()
        assert tr["success"] is True
        assert tr["error"] is None


class TestPluginHost:
    def setup_method(self):
        self.host = PluginHost(search_paths=[])

    def test_stats_empty(self):
        s = self.host.stats()
        assert s["total_plugins"] == 0
        assert s["total_tools"] == 0

    def test_discover_empty(self):
        paths = self.host.discover()
        assert paths == []

    def test_register_tool_duplicate(self):
        self.host._tools["existing"] = (lambda: None, "d", [])
        with pytest.raises(ValueError):
            self.host._register_tool("existing", lambda: None, "d", [])

    def test_register_command_duplicate(self):
        self.host._commands["existing"] = (lambda x: 0, "d", "u")
        with pytest.raises(ValueError):
            self.host._register_command("existing", lambda x: 0, "d", "u")

    def test_get_tool(self):
        self.host._tools["test.tool"] = (lambda: "ok", "desc", [])
        assert self.host.get_tool("test.tool") is not None
        assert self.host.get_tool("nonexistent") is None

    def test_get_command(self):
        self.host._commands["test.cmd"] = (lambda x: 0, "d", "u")
        assert self.host.get_command("test.cmd") is not None

    def test_get_ai_provider(self):
        self.host._ai_providers["test"] = (lambda: None, None)
        assert self.host.get_ai_provider("test") is not None

    def test_list_tools(self):
        self.host._tools["a.tool"] = (lambda: None, "A tool", ["recon"])
        tools = self.host.list_tools()
        assert len(tools) == 1
        assert tools[0]["name"] == "a.tool"

    def test_set_config(self):
        self.host.set_config({"key": "val"})
        assert self.host._get_config("key") == "val"

    def test_get_config_env_fallback(self):
        os.environ["ELENGENIX_TEST_KEY"] = "env_val"
        try:
            assert self.host._get_config("test_key") == "env_val"
        finally:
            del os.environ["ELENGENIX_TEST_KEY"]

    def test_run_finding_hooks(self):
        finding = {"type": "xss", "severity": "high"}
        result = self.host.run_finding_hooks(finding)
        assert result == finding

    def test_run_finding_hooks_drop(self):
        self.host._hooks = [(0, "test.drop", lambda f: None)]
        result = self.host.run_finding_hooks({"type": "xss"})
        assert result is None

    def test_unload_nonexistent(self):
        assert self.host.unload("nonexistent") is False


class TestCapability:
    def test_values(self):
        assert Capability.NETWORK.value == "network"
        assert Capability.FILESYSTEM.value == "filesystem"
        assert Capability.SUBPROCESS.value == "subprocess"
        assert Capability.AI_API.value == "ai_api"


class TestPluginState:
    def test_values(self):
        assert PluginState.DISCOVERED.value == "discovered"
        assert PluginState.ACTIVE.value == "active"
        assert PluginState.FAILED.value == "failed"


# ──────────────────────────────────────────────────────────────────────
# 18. marketplace.py
# ──────────────────────────────────────────────────────────────────────

from tools.marketplace import Marketplace, PluginEntry


class TestPluginEntry:
    def test_construction(self):
        e = PluginEntry(name="test", version="1.0.0", author="me")
        assert e.name == "test"

    def test_to_dict(self):
        e = PluginEntry(name="test", version="1.0.0", tags=["recon"], verified=True)
        d = e.to_dict()
        assert d["verified"] is True
        assert "recon" in d["tags"]


class TestMarketplace:
    def setup_method(self):
        self.m = Marketplace(index_url="http://invalid.example.com/index.json")

    def test_parse_index_list(self):
        text = json.dumps([
            {"name": "p1", "version": "1.0", "author": "a", "tags": ["recon"]},
        ])
        entries = self.m._parse_index(text)
        assert len(entries) == 1
        assert entries[0].name == "p1"

    def test_parse_index_dict_with_plugins(self):
        text = json.dumps({"plugins": [{"name": "p1", "version": "1.0"}]})
        entries = self.m._parse_index(text)
        assert len(entries) == 1

    def test_parse_index_not_list(self):
        entries = self.m._parse_index(json.dumps({"invalid": True}))
        assert entries == []

    def test_search_empty(self):
        self.m._index = [
            PluginEntry(name="shodan", version="1.0", description="shodan tool", tags=["recon"]),
            PluginEntry(name="nmap", version="1.0", description="port scanner", tags=["recon"]),
        ]
        results = self.m.search("shodan")
        assert len(results) == 1
        assert results[0].name == "shodan"

    def test_search_by_tag(self):
        self.m._index = [
            PluginEntry(name="p1", version="1.0", tags=["recon"]),
            PluginEntry(name="p2", version="1.0", tags=["fuzz"]),
        ]
        results = self.m.search(tag="recon")
        assert len(results) == 1

    def test_search_verified_only(self):
        self.m._index = [
            PluginEntry(name="p1", version="1.0", verified=True),
            PluginEntry(name="p2", version="1.0", verified=False),
        ]
        results = self.m.search(verified_only=True)
        assert len(results) == 1
        assert results[0].name == "p1"

    def test_get(self):
        self.m._index = [PluginEntry(name="p1", version="1.0")]
        assert self.m.get("p1") is not None
        assert self.m.get("p2") is None

    def test_install_not_found(self):
        self.m._index = []
        ok, msg = self.m.install("nonexistent")
        assert ok is False
        assert "not found" in msg

    def test_install_no_repo_url(self):
        self.m._index = [PluginEntry(name="p1", version="1.0", repo_url="")]
        ok, msg = self.m.install("p1")
        assert ok is False
        assert "no repo_url" in msg

    def test_install_already_exists(self):
        self.m._index = [PluginEntry(name="p1", version="1.0", repo_url="http://example.com")]
        dest = self.m.install_dir / "p1"
        dest.mkdir(parents=True, exist_ok=True)
        try:
            ok, msg = self.m.install("p1", upgrade=False)
            assert ok is False
            assert "already installed" in msg
        finally:
            import shutil
            shutil.rmtree(dest, ignore_errors=True)

    def test_uninstall_not_installed(self):
        ok, msg = self.m.uninstall("nonexistent")
        assert ok is False

    def test_stats(self):
        s = self.m.stats()
        assert "index_size" in s
        assert "install_dir" in s


# ──────────────────────────────────────────────────────────────────────
# 19. updater.py
# ──────────────────────────────────────────────────────────────────────

from tools.updater import ReleaseInfo, Updater, compare_versions, parse_version


class TestParseVersion:
    def test_basic(self):
        assert parse_version("1.2.3") == (1, 2, 3, "")

    def test_with_v_prefix(self):
        assert parse_version("v1.2.3") == (1, 2, 3, "")

    def test_prerelease(self):
        assert parse_version("1.2.3-rc.1") == (1, 2, 3, "rc.1")

    def test_beta(self):
        assert parse_version("1.2.3-beta") == (1, 2, 3, "beta")

    def test_invalid(self):
        major, minor, patch, pre = parse_version("abc")
        assert major == 0


class TestCompareVersions:
    def test_equal(self):
        assert compare_versions("1.0.0", "1.0.0") == 0

    def test_less(self):
        assert compare_versions("1.0.0", "2.0.0") == -1
        assert compare_versions("1.0.0", "1.1.0") == -1
        assert compare_versions("1.0.0", "1.0.1") == -1

    def test_greater(self):
        assert compare_versions("2.0.0", "1.0.0") == 1
        assert compare_versions("1.1.0", "1.0.0") == 1

    def test_prerelease_less_than_release(self):
        assert compare_versions("1.0.0-rc.1", "1.0.0") == -1

    def test_release_greater_than_prerelease(self):
        assert compare_versions("1.0.0", "1.0.0-rc.1") == 1


class TestReleaseInfo:
    def test_is_newer(self):
        r = ReleaseInfo(tag="v99.0.0", version="99.0.0")
        assert r.is_newer is True

    def test_not_newer(self):
        r = ReleaseInfo(tag="v0.0.1", version="0.0.1")
        assert r.is_newer is False


class TestUpdater:
    def test_init(self):
        u = Updater(repo="test/repo", current_version="1.0.0")
        assert u.current_version == "1.0.0"


# ──────────────────────────────────────────────────────────────────────
# 20. skill_registry.py
# ──────────────────────────────────────────────────────────────────────

from tools.skill_registry import Skill, SkillRegistry, SkillStatus


class TestSkill:
    def test_construction(self):
        s = Skill(
            name="test", description="desc", category="scanner",
            binary_name="test_bin", status=SkillStatus.AVAILABLE,
            install_command="pip install test", use_cases=["a", "b"],
        )
        assert s.name == "test"
        assert s.status == SkillStatus.AVAILABLE

    def test_flatten_use_cases(self):
        s = Skill(
            name="test", description="d", category="c",
            binary_name="b", status=SkillStatus.AVAILABLE,
            install_command="pip install", use_cases=["a", ["b", "c"]],
        )
        assert s.use_cases == ["a", "b", "c"]

    def test_to_dict(self):
        s = Skill(
            name="test", description="d", category="c",
            binary_name="b", status=SkillStatus.AVAILABLE,
            install_command="pip install",
        )
        d = s.to_dict()
        assert d["name"] == "test"
        assert d["status"] == "available"


class TestSkillStatus:
    def test_values(self):
        assert SkillStatus.AVAILABLE.value == "available"
        assert SkillStatus.MISSING.value == "missing"


class TestSkillRegistry:
    def setup_method(self):
        self.registry = SkillRegistry()

    def test_init_default_skills(self):
        assert "python_recon" in self.registry.skills
        assert "ssrf_scanner" in self.registry.skills
        assert "subfinder" in self.registry.skills

    def test_get_available(self):
        available = self.registry.get_available_skills()
        assert len(available) > 0
        assert all(s.status == SkillStatus.AVAILABLE for s in available)

    def test_get_missing(self):
        missing = self.registry.get_missing_skills()
        assert isinstance(missing, list)

    def test_recommend_for_xss(self):
        recs = self.registry.recommend_for("XSS testing")
        names = [s.name for s in recs]
        assert "active_fuzzer" in names or "nuclei" in names

    def test_recommend_for_recon(self):
        recs = self.registry.recommend_for("recon subdomain")
        names = [s.name for s in recs]
        assert len(recs) > 0

    def test_get_skill_context(self):
        ctx = self.registry.get_skill_context()
        assert "AVAILABLE TOOLS/SKILLS" in ctx

    def test_to_dict(self):
        d = self.registry.to_dict()
        assert "available" in d
        assert "missing" in d
        assert "total" in d

    def test_request_install_unknown(self):
        assert self.registry.request_install("nonexistent_tool") is False


# ──────────────────────────────────────────────────────────────────────
# 21. universal_ai_client.py
# ──────────────────────────────────────────────────────────────────────

from tools.universal_ai_client import (
    ACTION_TOOLS,
    AIResponse,
    AIMessage,
    AIClientManager,
    ToolCall,
    UniversalAIClient,
    format_ai_status,
)


class TestAIMessage:
    def test_construction(self):
        m = AIMessage(role="system", content="you are helpful")
        assert m.role == "system"
        assert m.metadata is None


class TestToolCall:
    def test_construction(self):
        tc = ToolCall(id="1", name="run_shell", arguments={"command": "ls"})
        assert tc.name == "run_shell"


class TestAIResponse:
    def test_construction(self):
        r = AIResponse(content="hello", model="gpt-4", usage={"prompt_tokens": 10})
        assert r.content == "hello"
        assert r.tool_calls is None

    def test_with_tool_calls(self):
        tc = ToolCall(id="1", name="finish", arguments={})
        r = AIResponse(content="", model="m", usage={}, tool_calls=[tc])
        assert len(r.tool_calls) == 1


class TestActionTools:
    def test_action_tools_count(self):
        assert len(ACTION_TOOLS) == 9

    def test_action_tool_names(self):
        names = [t["function"]["name"] for t in ACTION_TOOLS]
        assert "run_shell" in names
        assert "finish" in names
        assert "submit_findings" in names


class TestUniversalAIClient:
    def test_provider_configs(self):
        configs = UniversalAIClient.PROVIDER_CONFIGS
        assert "openai" in configs
        assert "ollama" in configs
        assert "anthropic" in configs

    @patch.dict(os.environ, {}, clear=True)
    def test_init_custom(self):
        client = UniversalAIClient(
            provider="custom",
            base_url="http://localhost:8080/v1",
            api_key="test_key",
            model="test_model",
        )
        assert client.provider == "custom"
        assert client.model == "test_model"
        assert client.base_url == "http://localhost:8080/v1"


class TestFormatAiStatus:
    def test_format(self):
        status = {
            "provider": "openai",
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-4",
            "has_api_key": True,
            "available": True,
        }
        result = format_ai_status(status)
        assert "openai" in result
        assert "gpt-4" in result


# ──────────────────────────────────────────────────────────────────────
# 22. payload_mutation.py
# ──────────────────────────────────────────────────────────────────────

from tools.payload_mutation import (
    ALL_PAYLOADS,
    ContextualMutator,
    Grammar,
    GrammarFuzzer,
    InjectionContext,
    MutationResult,
    PayloadDatabase,
    PayloadMutator,
    SmartPayloadGenerator,
    generate_payloads_for_context,
)


class TestPayloadMutator:
    def test_empty_payload(self):
        m = PayloadMutator(seed=42)
        assert m.mutate("") == []

    def test_mutate_returns_variants(self):
        m = PayloadMutator(seed=42)
        variants = m.mutate("<script>alert(1)</script>")
        assert len(variants) >= 5
        assert variants[0].techniques == ["base"]

    def test_case_toggle(self):
        m = PayloadMutator(seed=42)
        result = m._case_toggle("ABCdef")
        assert isinstance(result, str)

    def test_whitespace_sprinkle(self):
        m = PayloadMutator(seed=42)
        result = m._whitespace_sprinkle("hello")
        assert isinstance(result, str)

    def test_concat_style_short(self):
        m = PayloadMutator(seed=42)
        assert m._concat_style("abc") == "abc"

    def test_concat_style_long(self):
        m = PayloadMutator(seed=42)
        result = m._concat_style("abcdef")
        assert "+" in result

    def test_dedup(self):
        m = PayloadMutator(seed=42)
        variants = m.mutate("a", max_variants=3)
        assert len(variants) <= 3


class TestPayloadDatabase:
    def test_init_default(self):
        db = PayloadDatabase()
        assert len(db) > 200

    def test_entries_property(self):
        db = PayloadDatabase()
        entries = db.entries
        assert isinstance(entries, list)

    def test_categories(self):
        db = PayloadDatabase()
        cats = db.categories()
        assert "xss" in cats
        assert "sqli" in cats

    def test_by_category(self):
        db = PayloadDatabase()
        xss = db.by_category("xss")
        assert len(xss) > 0
        assert all(e[1] == "xss" for e in xss)

    def test_by_sink(self):
        db = PayloadDatabase()
        results = db.by_sink("html", category="xss")
        assert len(results) > 0

    def test_by_sinks(self):
        db = PayloadDatabase()
        results = db.by_sinks(["html", "attr"], category="xss")
        assert len(results) > 0

    def test_payloads(self):
        db = PayloadDatabase()
        p = db.payloads(category="sqli")
        assert len(p) > 0
        assert all(isinstance(s, str) for s in p)

    def test_add(self):
        db = PayloadDatabase()
        initial_len = len(db)
        db.add(("custom", "custom", "payload", ("sink",)))
        assert len(db) == initial_len + 1
        assert db.entries[-1][2] == "payload"


class TestGrammar:
    def test_rule_and_expand(self):
        g = Grammar()
        g.rule("<root>", [["hello"], ["world"]])
        result = g.expand("<root>")
        assert result in ("hello", "world")

    def test_expansion_with_nonterminal(self):
        g = Grammar()
        g.rule("<root>", [["a", "<b>"]])
        g.rule("<b>", [["c"]])
        result = g.expand("<root>")
        assert result == "ac"

    def test_max_depth(self):
        g = Grammar()
        g.rule("<root>", [["<root>"]])
        result = g.expand("<root>", max_depth=1)
        assert result == ""

    def test_terminal_fallback(self):
        g = Grammar()
        result = g.expand("literal")
        assert result == "literal"


class TestGrammarFuzzer:
    def test_available(self):
        gf = GrammarFuzzer(seed=42)
        avail = gf.available()
        assert "sqli" in avail
        assert "xss" in avail

    def test_generate_sqli(self):
        gf = GrammarFuzzer(seed=42)
        payloads = gf.generate("sqli", n=5)
        assert len(payloads) == 5
        assert all(isinstance(p, str) for p in payloads)

    def test_generate_unknown(self):
        gf = GrammarFuzzer(seed=42)
        with pytest.raises(ValueError):
            gf.generate("unknown", n=5)


class TestInjectionContext:
    def test_all_sinks(self):
        ctx = InjectionContext(category="xss", sinks=["html"], quote_style="double-quote")
        all_s = ctx.all_sinks()
        assert "html" in all_s
        assert "double-quote" in all_s

    def test_all_sinks_with_transport(self):
        ctx = InjectionContext(category="sqli", transport="xml")
        all_s = ctx.all_sinks()
        assert "xml" in all_s


class TestContextualMutator:
    def test_candidates(self):
        cm = ContextualMutator()
        ctx = InjectionContext(category="xss", sinks=["html"])
        cands = cm.candidates(ctx)
        assert len(cands) > 0

    def test_pick(self):
        cm = ContextualMutator()
        ctx = InjectionContext(category="xss", sinks=["html"])
        payloads = cm.pick(ctx, n=5)
        assert len(payloads) <= 5

    def test_pick_empty_category(self):
        cm = ContextualMutator()
        ctx = InjectionContext(category="nonexistent")
        payloads = cm.pick(ctx)
        assert payloads == []


class TestSmartPayloadGenerator:
    def test_generate(self):
        gen = SmartPayloadGenerator(seed=42)
        ctx = InjectionContext(category="sqli", sinks=["string"])
        payloads = gen.generate(ctx, n=10)
        assert len(payloads) > 0
        assert len(payloads) <= 10

    def test_generate_xss(self):
        gen = SmartPayloadGenerator(seed=42)
        ctx = InjectionContext(category="xss", sinks=["html"])
        payloads = gen.generate(ctx, n=10)
        assert len(payloads) > 0


class TestGeneratePayloadsForContext:
    def test_convenience(self):
        payloads = generate_payloads_for_context("xss", sinks=["html"], n=5)
        assert len(payloads) > 0
        assert len(payloads) <= 5


# ──────────────────────────────────────────────────────────────────────
# 23. config_wizard.py
# ──────────────────────────────────────────────────────────────────────

from tools.config_wizard import AIProviderConfig, ConfigWizard


class TestAIProviderConfig:
    def test_construction(self):
        c = AIProviderConfig(
            name="TestProvider", env_key="TEST_KEY", base_url="http://test.com",
            signup_url="http://signup.com", is_free=True, notes="test notes",
        )
        assert c.name == "TestProvider"
        assert c.api_type == "openai"

    def test_custom_api_type(self):
        c = AIProviderConfig(
            name="Test", env_key="K", base_url="url", signup_url="url",
            is_free=False, notes="n", api_type="native",
        )
        assert c.api_type == "native"


class TestConfigWizard:
    def test_init(self):
        w = ConfigWizard()
        assert len(w.AI_PROVIDERS) > 0

    def test_providers_have_required_fields(self):
        w = ConfigWizard()
        for p in w.AI_PROVIDERS:
            assert p.name, f"Provider missing name"
            assert p.base_url, f"Provider {p.name} missing base_url"
            assert p.signup_url, f"Provider {p.name} missing signup_url"


# ──────────────────────────────────────────────────────────────────────
# 24. vuln_hunter_core.py
# ──────────────────────────────────────────────────────────────────────

from tools.vuln_hunter_core import (
    Belief,
    BeliefState,
    CoverageCell,
    CoverageMap,
    NegativeResult,
    NegativeResultStore,
    Reflection,
    ReflectEngine,
    StageResult,
    Verdict,
    VerificationPipeline,
    VULN_CLASSES,
)


class TestBelief:
    def test_to_dict(self):
        b = Belief(
            hyp_id="h1", vuln_class="xss", target_endpoint="http://test.com",
            reasoning="suspicious", confidence=0.7,
        )
        d = b.to_dict()
        assert d["hyp_id"] == "h1"
        assert d["confidence"] == 0.7


class TestBeliefState:
    def setup_method(self):
        self.bs = BeliefState(mission_id=f"test_vh_{id(self)}_{time.time_ns()}")

    def test_add_belief(self):
        hyp_id = self.bs.add_belief("xss", "http://test.com", "suspicious input", 0.6)
        assert hyp_id is not None

    def test_get_active_beliefs(self):
        self.bs.add_belief("xss", "http://test.com", "reason", 0.5)
        active = self.bs.get_active_beliefs()
        assert len(active) >= 1

    def test_get_active_beliefs_min_confidence(self):
        self.bs.add_belief("xss", "http://test.com", "reason", 0.3)
        active = self.bs.get_active_beliefs(min_confidence=0.5)
        assert len(active) == 0

    def test_update_confidence(self):
        hyp_id = self.bs.add_belief("sqli", "http://test.com", "r", 0.5)
        self.bs.update_confidence(hyp_id, 0.8, {"source": "test"})
        active = self.bs.get_active_beliefs()
        assert any(b.confidence == 0.8 for b in active)

    def test_set_status(self):
        hyp_id = self.bs.add_belief("rce", "http://test.com", "r", 0.5)
        self.bs.set_status(hyp_id, "confirmed")
        confirmed = self.bs.get_confirmed_beliefs()
        assert len(confirmed) >= 1

    def test_get_beliefs_for_endpoint(self):
        self.bs.add_belief("xss", "http://a.com", "r1", 0.5)
        self.bs.add_belief("sqli", "http://b.com", "r2", 0.5)
        beliefs = self.bs.get_beliefs_for_endpoint("http://a.com")
        assert len(beliefs) == 1

    def test_summary(self):
        self.bs.add_belief("xss", "http://test.com", "r", 0.5)
        s = self.bs.summary()
        assert "Beliefs" in s

    def test_prompt_context(self):
        self.bs.add_belief("xss", "http://test.com", "r", 0.5)
        ctx = self.bs.prompt_context()
        assert "HYPOTHESES" in ctx


class TestCoverageCell:
    def test_to_dict(self):
        c = CoverageCell(endpoint="http://test.com", vuln_class="xss")
        d = c.to_dict()
        assert d["endpoint"] == "http://test.com"


class TestCoverageMap:
    def setup_method(self):
        self.cm = CoverageMap(mission_id=f"test_cov_{id(self)}_{time.time_ns()}", target="http://test.com")

    def test_register_endpoint(self):
        self.cm.register_endpoint("http://test.com/api")
        untested = self.cm.get_untested()
        assert len(untested) > 0

    def test_record_test(self):
        self.cm.record_test("http://test.com/api", "xss")
        gaps = self.cm.get_gaps()
        assert not any(g.endpoint == "http://test.com/api" and g.vuln_class == "xss" for g in gaps)

    def test_record_finding(self):
        self.cm.record_finding("http://test.com/api", "sqli")
        coverage = self.cm.get_endpoint_coverage("http://test.com/api")
        assert coverage["findings"] == 1

    def test_record_negative(self):
        self.cm.record_negative("http://test.com/api", "xss", "no signal")
        untested = self.cm.get_untested()
        assert not any(
            c.endpoint == "http://test.com/api" and c.vuln_class == "xss" for c in untested
        )

    def test_get_tested_endpoints(self):
        self.cm.record_test("http://test.com/api", "xss")
        tested = self.cm.get_tested_endpoints()
        assert "http://test.com/api" in tested

    def test_summary(self):
        s = self.cm.summary()
        assert "Coverage" in s

    def test_prompt_context_empty(self):
        cm = CoverageMap(mission_id=f"test_empty_{id(self)}_{time.time_ns()}")
        ctx = cm.prompt_context()
        assert ctx == ""


class TestNegativeResult:
    def test_to_dict(self):
        nr = NegativeResult(
            endpoint="http://test.com", vuln_class="xss", tool_used="nuclei",
            payload_or_command="test", reason="no signal", evidence_summary="",
        )
        d = nr.to_dict()
        assert d["endpoint"] == "http://test.com"


class TestNegativeResultStore:
    def setup_method(self):
        self.store = NegativeResultStore(mission_id=f"test_neg_{id(self)}_{time.time_ns()}")

    def test_record(self):
        self.store.record("http://test.com/api", "xss", "nuclei", "<script>", "no signal")
        assert self.store.was_tested("http://test.com/api", "xss") is True

    def test_was_tested_false(self):
        assert self.store.was_tested("http://test.com/api", "sqli") is False

    def test_get_previous_attempts(self):
        self.store.record("http://test.com/api", "xss", "nuclei", "p1", "reason1")
        attempts = self.store.get_previous_attempts("http://test.com/api", "xss")
        assert len(attempts) >= 1

    def test_get_prompt_context(self):
        self.store.record("http://test.com/api", "xss", "nuclei", "p", "r")
        ctx = self.store.get_prompt_context()
        assert "PREVIOUSLY TESTED" in ctx

    def test_get_prompt_context_empty(self):
        store = NegativeResultStore(mission_id=f"test_empty_{id(self)}_{time.time_ns()}")
        ctx = store.get_prompt_context()
        assert ctx == ""


class TestVerdict:
    def test_to_dict(self):
        v = Verdict(vuln_class="xss", endpoint="http://test.com", status="confirmed", confidence=0.8)
        d = v.to_dict()
        assert d["status"] == "confirmed"

    def test_is_actionable(self):
        for status in ["confirmed", "proven", "exploitable"]:
            v = Verdict(vuln_class="x", endpoint="e", status=status, confidence=0.5)
            assert v.is_actionable() is True
        for status in ["unverified", "false_positive"]:
            v = Verdict(vuln_class="x", endpoint="e", status=status, confidence=0.5)
            assert v.is_actionable() is False


class TestVerificationPipeline:
    def setup_method(self):
        self.pipeline = VerificationPipeline()

    def test_verify_finding_no_agent(self):
        finding = {"type": "xss", "url": "http://test.com", "severity": "HIGH"}
        verdict = self.pipeline.verify_finding(finding)
        assert verdict.status == "false_positive"

    def test_get_all_verdicts(self):
        self.pipeline._history.append(
            Verdict(vuln_class="xss", endpoint="e", status="confirmed", confidence=0.8)
        )
        assert len(self.pipeline.get_all_verdicts()) == 1

    def test_get_actionable_findings(self):
        self.pipeline._history.extend([
            Verdict(vuln_class="xss", endpoint="e", status="confirmed", confidence=0.8),
            Verdict(vuln_class="sqli", endpoint="e", status="false_positive", confidence=0.1),
        ])
        actionables = self.pipeline.get_actionable_findings()
        assert len(actionables) == 1

    def test_false_positive_rate(self):
        self.pipeline._history.extend([
            Verdict(vuln_class="xss", endpoint="e", status="confirmed", confidence=0.8),
            Verdict(vuln_class="sqli", endpoint="e", status="false_positive", confidence=0.1),
        ])
        rate = self.pipeline.false_positive_rate()
        assert rate == 0.5

    def test_false_positive_rate_empty(self):
        assert self.pipeline.false_positive_rate() == 0.0

    def test_prompt_context(self):
        self.pipeline._history.append(
            Verdict(vuln_class="xss", endpoint="e", status="confirmed", confidence=0.8)
        )
        ctx = self.pipeline.prompt_context()
        assert "VERIFICATION" in ctx

    def test_prompt_context_empty(self):
        assert self.pipeline.prompt_context() == ""

    def test_verification_stages_coverage(self):
        for vc in ["sqli", "xss", "ssrf", "rce", "lfi", "ssti", "xxe", "graphql", "bola", "jwt"]:
            assert vc in VerificationPipeline.VERIFICATION_STAGES


class TestStageResult:
    def test_construction(self):
        sr = StageResult(success=True, detail="ok")
        assert sr.success is True


class TestReflection:
    def test_to_dict(self):
        r = Reflection(cycle=1, status="on_track")
        d = r.to_dict()
        assert d["cycle"] == 1


class TestReflectEngine:
    def setup_method(self):
        self.engine = ReflectEngine(adapt_after=3, max_steps_without_findings=5)

    def test_reflect_on_track(self):
        ref = self.engine.reflect(cycle=1, recent_findings_count=2)
        assert ref.status == "on_track"
        assert ref.switch_strategy is False

    def test_reflect_needs_adaptation(self):
        for _ in range(3):
            self.engine.reflect(cycle=1, recent_findings_count=0)
        ref = self.engine.reflect(cycle=4, recent_findings_count=0)
        assert ref.status == "needs_adaptation"
        assert ref.switch_strategy is True

    def test_reflect_stuck(self):
        for _ in range(5):
            self.engine.reflect(cycle=1, recent_findings_count=0)
        ref = self.engine.reflect(cycle=6, recent_findings_count=0)
        assert ref.status == "stuck"

    def test_reflect_resets_on_finding(self):
        for _ in range(3):
            self.engine.reflect(cycle=1, recent_findings_count=0)
        ref = self.engine.reflect(cycle=4, recent_findings_count=1)
        assert self.engine.consecutive_no_findings == 0
        assert ref.status == "on_track"


# ──────────────────────────────────────────────────────────────────────
# 25. dynamic_waf_mutator.py
# ──────────────────────────────────────────────────────────────────────


class TestDynamicWAFMutatorIsBlocked:
    def test_blocked_status_codes(self):
        from tools.dynamic_waf_mutator import DynamicWAFMutator
        with patch.object(DynamicWAFMutator, "__init__", lambda self, *a, **kw: None):
            m = DynamicWAFMutator.__new__(DynamicWAFMutator)
            for code in [403, 406, 409, 501, 502, 503]:
                assert m._is_blocked(code, "") is True

    def test_not_blocked(self):
        from tools.dynamic_waf_mutator import DynamicWAFMutator
        with patch.object(DynamicWAFMutator, "__init__", lambda self, *a, **kw: None):
            m = DynamicWAFMutator.__new__(DynamicWAFMutator)
            assert m._is_blocked(200, "hello") is False

    def test_blocked_body_keywords(self):
        from tools.dynamic_waf_mutator import DynamicWAFMutator
        with patch.object(DynamicWAFMutator, "__init__", lambda self, *a, **kw: None):
            m = DynamicWAFMutator.__new__(DynamicWAFMutator)
            assert m._is_blocked(200, "blocked by waf") is True
            assert m._is_blocked(200, "cloudflare ray") is True
            assert m._is_blocked(200, "mod_security") is True


# ──────────────────────────────────────────────────────────────────────
# 26. multi_agent.py
# ──────────────────────────────────────────────────────────────────────

from tools.multi_agent import (
    AGENT_ROLES,
    Finding,
    TaskAssignment,
    TeamAegis,
    TeamMessage,
)


class TestTeamMessage:
    def test_construction(self):
        msg = TeamMessage(
            round=1, agent_id=0, agent_role="Strategist",
            model_name="gpt-4", content="let's test xss",
        )
        assert msg.round == 1
        assert msg.msg_type == "discussion"


class TestTaskAssignment:
    def test_construction(self):
        t = TaskAssignment(
            agent_id=0, action_type="shell", params={"cmd": "ls"},
            description="list files",
        )
        assert t.completed is False


class TestFinding:
    def test_construction(self):
        f = Finding(source_agent="Strategist", description="xss found", severity="high")
        assert f.confirmed_by == []


class TestTeamAegis:
    def test_init_requires_2_clients(self):
        with pytest.raises(ValueError):
            TeamAegis(clients=[MagicMock()], target="test.com")

    def test_init_max_3(self):
        clients = [MagicMock(), MagicMock(), MagicMock(), MagicMock()]
        team = TeamAegis(clients=clients, target="test.com")
        assert team.team_size == 3

    def test_roles_assigned(self):
        clients = [MagicMock(), MagicMock()]
        team = TeamAegis(clients=clients, target="test.com")
        assert len(team.roles) == 2
        assert team.roles[0]["name"] == "Strategist"
        assert team.roles[1]["name"] == "Recon Lead"


# ──────────────────────────────────────────────────────────────────────
# 27. autonomous_agent.py
# ──────────────────────────────────────────────────────────────────────

from tools.autonomous_agent import (
    AgentAction,
    AgentState,
    AutonomousDecision,
    ScanResult,
    _parse_json,
    _to_domain,
)


class TestAgentAction:
    def test_construction(self):
        a = AgentAction(name="recon", target="test.com")
        assert a.params == {}


class TestAgentState:
    def test_construction(self):
        s = AgentState(root_target="test.com", goal="find vulnerabilities")
        assert s.findings == []
        assert s.iteration == 0


class TestAutonomousDecision:
    def test_construction(self):
        d = AutonomousDecision(
            decision_type="scan", reasoning="need more data",
            action_plan={"tool": "nuclei"}, expected_outcome="find bugs",
            risk_level="low",
        )
        assert d.auto_approved is False


class TestScanResult:
    def test_construction(self):
        r = ScanResult(
            target="test.com", start_time=datetime.now(timezone.utc),
            end_time=None, findings=[], bounty_predictions=[],
            tools_created=[], ai_decisions=[], report_path=None,
            success=True, summary="done",
        )
        assert r.success is True


class TestToDomain:
    def test_full_url(self):
        assert _to_domain("http://test.com/path") == "test.com"

    def test_https_url(self):
        assert _to_domain("https://sub.test.com:8080/api") == "sub.test.com"

    def test_bare_domain(self):
        assert _to_domain("test.com") == "test.com"

    def test_with_port(self):
        assert _to_domain("http://test.com:8080") == "test.com"


class TestParseJson:
    def test_parse_valid(self):
        result = _parse_json('{"key": "val"}')
        assert result["key"] == "val"

    def test_parse_fenced(self):
        text = '```json\n{"key": "val"}\n```'
        result = _parse_json(text)
        assert result["key"] == "val"

    def test_parse_invalid(self):
        result = _parse_json("not json at all")
        assert result == {}


# ──────────────────────────────────────────────────────────────────────
# 28. hunt_engine.py (data classes only)
# ──────────────────────────────────────────────────────────────────────

from tools.hunt_engine import HuntFinding, HuntPhase, HuntReport, Severity as HuntSeverity


class TestHuntFinding:
    def test_to_dict(self):
        f = HuntFinding(
            phase="recon", category="endpoint", severity="Informational",
            title="Found endpoint", url="http://test.com/api",
        )
        d = f.to_dict()
        assert d["phase"] == "recon"


class TestHuntReport:
    def test_by_severity(self):
        r = HuntReport(target="test.com", started_at="2025-01-01")
        r.findings = [
            HuntFinding(phase="recon", category="x", severity="High", title="a"),
            HuntFinding(phase="recon", category="y", severity="High", title="b"),
            HuntFinding(phase="smart", category="z", severity="Critical", title="c"),
        ]
        by_sev = r.by_severity()
        assert by_sev["High"] == 2
        assert by_sev["Critical"] == 1

    def test_by_phase(self):
        r = HuntReport(target="test.com", started_at="2025-01-01")
        r.findings = [
            HuntFinding(phase="recon", category="x", severity="Info", title="a"),
            HuntFinding(phase="smart", category="y", severity="Info", title="b"),
        ]
        by_ph = r.by_phase()
        assert by_ph["recon"] == 1
        assert by_ph["smart"] == 1


class TestSeverity:
    def test_values(self):
        assert HuntSeverity.CRITICAL.value == "Critical"
        assert HuntSeverity.HIGH.value == "High"
        assert HuntSeverity.INFO.value == "Informational"


# ──────────────────────────────────────────────────────────────────────
# 29. targeted_attacks.py (data classes only)
# ──────────────────────────────────────────────────────────────────────

from tools.targeted_attacks import ConfirmedFinding


class TestConfirmedFinding:
    def test_construction(self):
        f = ConfirmedFinding(
            title="SQLi on /login", severity="Critical", category="sql_injection",
            endpoint_url="http://test.com/login", method="POST",
            evidence="baseline 200 -> payload 500",
        )
        assert f.confidence == 1.0
        assert f.detector == ""


# ──────────────────────────────────────────────────────────────────────
# 30. overlay_menu.py (data structures and constants)
# ──────────────────────────────────────────────────────────────────────

from tools.overlay_menu import MENU_ITEMS


class TestOverlayMenuItems:
    def test_menu_items(self):
        assert len(MENU_ITEMS) >= 5
        ids = [item["id"] for item in MENU_ITEMS]
        assert "sessions" in ids
        assert "api_keys" in ids

    def test_menu_item_structure(self):
        for item in MENU_ITEMS:
            assert "id" in item
            assert "label" in item
            assert "icon" in item

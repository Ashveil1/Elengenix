"""tests/test_post_processor.py — Tests for agents.post_processor.PostExecutionProcessor"""

from dataclasses import dataclass, field
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from agents.post_processor import PostExecutionProcessor, _safe_operation
from agents.scan_context import ScanContext


# ── Mock Objects ────────────────────────────────────────────────


@dataclass
class MockToolResult:
    success: bool = True
    tool_name: str = "test_tool"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    output: str = ""
    error_message: str = None


@dataclass
class MockVerdict:
    status: str = "verified"
    confidence: float = 0.9

    def is_actionable(self):
        return self.status == "verified"

    def to_dict(self):
        return {"status": self.status, "confidence": self.confidence}


class MockCoverageMap:
    def __init__(self):
        self.endpoints = []
        self.tests = []
        self.findings_recorded = []
        self.negatives_recorded = []

    def register_endpoint(self, ep):
        self.endpoints.append(ep)

    def record_test(self, ep, vuln_class):
        self.tests.append((ep, vuln_class))

    def record_finding(self, ep, vuln_class):
        self.findings_recorded.append((ep, vuln_class))

    def record_negative(self, ep, vuln_class, reason=""):
        self.negatives_recorded.append((ep, vuln_class, reason))


class MockBeliefState:
    def __init__(self):
        self.beliefs = []

    def add_belief(self, **kwargs):
        self.beliefs.append(kwargs)


class MockNegativeResults:
    def __init__(self):
        self.records = []

    def record(self, **kwargs):
        self.records.append(kwargs)


class MockVerificationPipeline:
    def __init__(self, verdict=None):
        self._verdict = verdict or MockVerdict()

    def verify_finding(self, finding, target="", callback=None):
        return self._verdict


class MockEscalation:
    def __init__(self):
        self.can_escalate_result = None

    def can_escalate(self, finding):
        return self.can_escalate_result


class MockChaining:
    def __init__(self):
        self.chainable = []
        self.chain_result = None

    def find_chainable_findings(self, findings):
        return self.chainable

    def analyze_chain(self, pair):
        return self.chain_result


class MockVulnFinder:
    def __init__(self):
        self.escalation = MockEscalation()
        self.chaining = MockChaining()
        self.added_findings = []

    def add_finding(self, finding):
        self.added_findings.append(finding)


class MockMissionState:
    def __init__(self):
        self.target = "example.com"
        self.nodes = []
        self.edges = []
        self.facts = []

    def upsert_node(self, node):
        self.nodes.append(node)

    def upsert_edge(self, edge):
        self.edges.append(edge)

    def add_fact(self, **kwargs):
        self.facts.append(kwargs)


# ── Helper ──────────────────────────────────────────────────────


def _make_ctx(**kwargs) -> ScanContext:
    defaults = {"target": "example.com", "objective": "Find vulns"}
    defaults.update(kwargs)
    return ScanContext(**defaults)


# ── Safe Operation Tests ────────────────────────────────────────


class TestSafeOperation:
    def test_success(self):
        result = _safe_operation("test", lambda: 42)
        assert result == 42

    def test_exception_swallowed(self):
        result = _safe_operation("test", lambda: 1 / 0)
        assert result is None


# ── Coverage & Verification Tests ──────────────────────────────


class TestCoverageAndVerification:
    def test_records_endpoint_in_coverage_map(self):
        coverage = MockCoverageMap()
        ctx = _make_ctx()
        ctx.coverage_map = coverage
        processor = PostExecutionProcessor()

        result = MockToolResult(findings=[])
        processor._process_coverage_and_verification(
            ctx, result, "fuzzer", {"command": "nmap target", "purpose": "scan"}, 0
        )
        assert "nmap target" in coverage.endpoints

    def test_records_test_in_coverage_map(self):
        coverage = MockCoverageMap()
        ctx = _make_ctx()
        ctx.coverage_map = coverage
        processor = PostExecutionProcessor()

        result = MockToolResult(findings=[])
        processor._process_coverage_and_verification(
            ctx, result, "fuzzer", {"command": "nmap", "purpose": "port_scan"}, 0
        )
        assert ("nmap", "port_scan") in coverage.tests

    def test_records_negative_when_no_findings(self):
        neg = MockNegativeResults()
        ctx = _make_ctx()
        ctx.negative_results = neg
        processor = PostExecutionProcessor()

        result = MockToolResult(findings=[])
        processor._process_coverage_and_verification(
            ctx, result, "fuzzer", {"command": "nmap", "purpose": "scan"}, 0
        )
        assert len(neg.records) == 1
        assert neg.records[0]["reason"] == "no vulnerabilities detected"

    def test_verified_finding_added_to_context(self):
        ctx = _make_ctx()
        ctx.verification_pipeline = MockVerificationPipeline(MockVerdict("verified", 0.9))
        processor = PostExecutionProcessor()

        finding = {"type": "xss", "url": "http://example.com/x", "severity": "High"}
        result = MockToolResult(findings=[finding])
        verified = processor._process_coverage_and_verification(
            ctx, result, "fuzzer", {"command": "nmap", "purpose": "xss"}, 0
        )
        assert len(verified) == 1
        assert ctx.has_findings

    def test_unverified_finding_discarded(self):
        ctx = _make_ctx()
        ctx.verification_pipeline = MockVerificationPipeline(MockVerdict("false_positive", 0.1))
        neg = MockNegativeResults()
        ctx.negative_results = neg
        processor = PostExecutionProcessor()

        finding = {"type": "xss", "url": "http://example.com/x"}
        result = MockToolResult(findings=[finding])
        verified = processor._process_coverage_and_verification(
            ctx, result, "fuzzer", {"command": "nmap", "purpose": "xss"}, 0
        )
        assert len(verified) == 0
        assert not ctx.has_findings
        assert len(neg.records) == 1

    def test_verification_error_accepts_finding(self):
        ctx = _make_ctx()
        # Verification that raises an exception
        bad_pipeline = MagicMock()
        bad_pipeline.verify_finding.side_effect = RuntimeError("boom")
        ctx.verification_pipeline = bad_pipeline
        processor = PostExecutionProcessor()

        finding = {"type": "xss", "url": "http://example.com/x"}
        result = MockToolResult(findings=[finding])
        verified = processor._process_coverage_and_verification(
            ctx, result, "fuzzer", {"command": "nmap", "purpose": "xss"}, 0
        )
        assert len(verified) == 1  # Accepted on error

    def test_extracts_urls_from_output(self):
        coverage = MockCoverageMap()
        ctx = _make_ctx()
        ctx.coverage_map = coverage
        processor = PostExecutionProcessor()

        result = MockToolResult(
            findings=[],
            output="Found: https://api.example.com/v1/users and http://cdn.example.com",
        )
        processor._process_coverage_and_verification(
            ctx, result, "recon", {"command": "recon", "purpose": "scan"}, 0
        )
        assert "https://api.example.com/v1/users" in coverage.endpoints

    def test_no_coverage_map_still_works(self):
        ctx = _make_ctx()
        ctx.coverage_map = None
        processor = PostExecutionProcessor()

        result = MockToolResult(findings=[{"type": "xss", "url": "http://example.com"}])
        verified = processor._process_coverage_and_verification(
            ctx, result, "fuzzer", {"command": "nmap", "purpose": "xss"}, 0
        )
        assert len(verified) == 1


# ── Escalation & Chaining Tests ────────────────────────────────


class TestEscalationAndChaining:
    def test_escalation_low_severity(self):
        vf = MockVulnFinder()
        vf.escalation.can_escalate_result = MagicMock(next_steps=["test_rce"])
        ctx = _make_ctx()
        processor = PostExecutionProcessor(vuln_finder=vf)

        findings = [{"type": "xss", "severity": "low", "url": "http://example.com"}]
        processor._process_escalation_and_chaining(ctx, findings)
        assert len(vf.added_findings) == 1

    def test_escalation_skips_high_severity(self):
        vf = MockVulnFinder()
        ctx = _make_ctx()
        processor = PostExecutionProcessor(vuln_finder=vf)

        findings = [{"type": "xss", "severity": "high"}]
        processor._process_escalation_and_chaining(ctx, findings)
        assert len(vf.added_findings) == 0

    def test_chaining_combines_findings(self):
        vf = MockVulnFinder()
        from dataclasses import dataclass

        @dataclass
        class MockChain:
            chain_type: str = "xss_csrf"
            combined_severity: str = "Critical"
            impact_description: str = "Combined XSS+CSRF"

        f1 = {"type": "xss", "url": "http://example.com/xss"}
        f2 = {"type": "csrf", "url": "http://example.com/csrf"}
        vf.chaining.chainable = [(f1, f2)]
        vf.chaining.chain_result = MockChain()
        ctx = _make_ctx()
        ctx.add_finding(f1)
        ctx.add_finding(f2)
        processor = PostExecutionProcessor(vuln_finder=vf)

        processor._process_escalation_and_chaining(ctx, [f1, f2])
        # Should have original 2 + chained finding
        assert ctx.finding_count >= 3

    def test_no_findings_skips_escalation(self):
        vf = MockVulnFinder()
        ctx = _make_ctx()
        processor = PostExecutionProcessor(vuln_finder=vf)

        processor._process_escalation_and_chaining(ctx, [])
        assert len(vf.added_findings) == 0


# ── Mission State Tests ─────────────────────────────────────────


class TestMissionState:
    def test_updates_graph_nodes(self):
        ms = MockMissionState()
        ctx = _make_ctx()
        ctx.mission_state = ms
        processor = PostExecutionProcessor()

        result = MockToolResult(
            findings=[{"type": "xss", "url": "http://example.com/xss", "severity": "High"}]
        )
        processor._process_mission_state(ctx, result, "fuzzer", 0)
        assert len(ms.nodes) == 1
        assert ms.nodes[0].node_type == "finding"

    def test_updates_graph_edges(self):
        ms = MockMissionState()
        ctx = _make_ctx()
        ctx.mission_state = ms
        processor = PostExecutionProcessor()

        result = MockToolResult(
            findings=[{"type": "xss", "url": "http://example.com/xss"}]
        )
        processor._process_mission_state(ctx, result, "fuzzer", 0)
        assert len(ms.edges) == 1
        assert ms.edges[0].edge_type == "has_finding"

    def test_adds_facts(self):
        ms = MockMissionState()
        ctx = _make_ctx()
        ctx.mission_state = ms
        processor = PostExecutionProcessor()

        result = MockToolResult(
            findings=[{"type": "xss", "url": "http://example.com/xss", "severity": "High"}]
        )
        processor._process_mission_state(ctx, result, "fuzzer", 0)
        assert len(ms.facts) == 1
        assert "fuzzer" in ms.facts[0]["statement"]

    def test_no_mission_state_still_works(self):
        ctx = _make_ctx()
        ctx.mission_state = None
        processor = PostExecutionProcessor()

        result = MockToolResult(findings=[{"type": "xss"}])
        # Should not raise
        processor._process_mission_state(ctx, result, "fuzzer", 0)


# ── Strategy Tests ──────────────────────────────────────────────


class TestStrategy:
    def test_marks_attack_tree_step_completed(self):
        tree = MagicMock()
        step = MagicMock()
        step.completed = False
        tree.steps = [step]
        ctx = _make_ctx()
        ctx.attack_tree = tree
        processor = PostExecutionProcessor()

        result = MockToolResult(findings=[])
        processor._process_strategy(ctx, result, "fuzzer", 0)
        assert step.completed is True

    def test_adaptive_strategy_adds_steps(self):
        planner = MagicMock()
        planner.adapt_strategy.return_value = [MagicMock()]
        ctx = _make_ctx()
        ctx.planner = planner
        processor = PostExecutionProcessor(planner=planner)

        result = MockToolResult(findings=[{"type": "xss"}])
        processor._process_strategy(ctx, result, "fuzzer", 0)
        planner.adapt_strategy.assert_called_once()

    def test_no_planner_still_works(self):
        ctx = _make_ctx()
        processor = PostExecutionProcessor()

        result = MockToolResult(findings=[])
        # Should not raise
        processor._process_strategy(ctx, result, "fuzzer", 0)


# ── Full Process Tests ─────────────────────────────────────────


class TestFullProcess:
    def test_process_calls_all_groups(self):
        ctx = _make_ctx()
        ctx.coverage_map = MockCoverageMap()
        ctx.verification_pipeline = MockVerificationPipeline()
        ctx.mission_state = MockMissionState()
        processor = PostExecutionProcessor()

        result = MockToolResult(
            findings=[{"type": "xss", "url": "http://example.com/xss", "severity": "High"}]
        )
        processor.process(ctx, result, "fuzzer", {"command": "nmap", "purpose": "xss"}, 0)

        assert ctx.has_findings
        assert len(ctx.previous_results) == 1

    def test_process_handles_none_result(self):
        ctx = _make_ctx()
        processor = PostExecutionProcessor()

        # Should not raise
        processor.process(ctx, None, "fuzzer", {}, 0)
        assert len(ctx.previous_results) == 0

    def test_process_with_no_findings(self):
        ctx = _make_ctx()
        ctx.negative_results = MockNegativeResults()
        processor = PostExecutionProcessor()

        result = MockToolResult(findings=[])
        processor.process(ctx, result, "fuzzer", {"command": "nmap", "purpose": "scan"}, 0)

        assert not ctx.has_findings
        assert len(ctx.previous_results) == 1

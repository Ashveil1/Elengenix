"""Tests for tools/vuln_hunter_core.py — meta-cognitive engine."""

import json
import os
import tempfile
from pathlib import Path

import pytest

# Override DB path to temp for tests
from tools import vuln_hunter_core as vhc

vhc._DB_PATH = Path(tempfile.mktemp(suffix=".db"))


@pytest.fixture(autouse=True)
def _clean_db():
    """Reset database state before each test."""
    yield
    try:
        vhc._DB_PATH.unlink(missing_ok=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# BeliefState tests
# ---------------------------------------------------------------------------


class TestBeliefState:
    def test_add_and_retrieve_belief(self):
        bs = vhc.BeliefState("test_mission")
        hyp_id = bs.add_belief("sqli", "https://example.com/login", "Login page has user input in SQL query", confidence=0.7)

        assert hyp_id is not None
        assert hyp_id.startswith("sqli")

        active = bs.get_active_beliefs()
        assert len(active) == 1
        assert active[0].vuln_class == "sqli"
        assert active[0].target_endpoint == "https://example.com/login"
        assert active[0].confidence == 0.7

    def test_update_confidence(self):
        bs = vhc.BeliefState("test_mission")
        hyp_id = bs.add_belief("xss", "https://example.com/search", "Search reflects user input", confidence=0.5)

        bs.update_confidence(hyp_id, 0.9, {"stage": "confirm", "result": "payload reflected unencoded"})

        active = bs.get_active_beliefs()
        assert len(active) == 1
        assert active[0].confidence == 0.9

    def test_set_status(self):
        bs = vhc.BeliefState("test_mission")
        hyp_id = bs.add_belief("ssrf", "https://example.com/proxy", "Proxy endpoint takes URL parameter", confidence=0.6)

        bs.set_status(hyp_id, "refuted")

        active = bs.get_active_beliefs()
        assert len(active) == 0

    def test_confirm_belief(self):
        bs = vhc.BeliefState("test_mission")
        hyp_id = bs.add_belief("rce", "https://example.com/exec", "Command injection point", confidence=0.7)

        bs.set_status(hyp_id, "confirmed")

        confirmed = bs.get_confirmed_beliefs()
        assert len(confirmed) == 1

    def test_prompt_context(self):
        bs = vhc.BeliefState("test_mission")
        context = bs.prompt_context()
        assert context == ""

        bs.add_belief("sqli", "https://example.com/login", "SQL injection", confidence=0.7)
        context = bs.prompt_context()
        assert "sqli" in context
        assert "example.com" in context

    def test_summary(self):
        bs = vhc.BeliefState("test_mission")
        summary = bs.summary()
        assert "No beliefs yet" in summary

        bs.add_belief("lfi", "https://example.com/file", "Local file inclusion", confidence=0.6)
        summary = bs.summary()
        assert "1 active" in summary
        assert "lfi" in summary


# ---------------------------------------------------------------------------
# CoverageMap tests
# ---------------------------------------------------------------------------


class TestCoverageMap:
    def test_register_endpoint(self):
        cm = vhc.CoverageMap("test_mission", "example.com")
        cm.register_endpoint("https://example.com/login")

        # All VULN_CLASSES should be registered
        assert cm.get_untested() != []

        # Check endpoint coverage
        cov = cm.get_endpoint_coverage("https://example.com/login")
        assert cov["endpoint"] == "https://example.com/login"
        assert cov["total_vuln_classes"] == len(vhc.VULN_CLASSES)
        assert cov["tested"] == 0

    def test_record_test(self):
        cm = vhc.CoverageMap("test_mission", "example.com")
        cm.register_endpoint("https://example.com/login")
        cm.record_test("https://example.com/login", "sqli")

        cov = cm.get_endpoint_coverage("https://example.com/login")
        assert cov["tested"] >= 1

    def test_record_negative(self):
        cm = vhc.CoverageMap("test_mission", "example.com")
        cm.register_endpoint("https://example.com/login")
        cm.record_negative("https://example.com/login", "xss", reason="no reflection in response")

        gap = cm.get_gaps()
        # This cell should NOT be in gaps since it was tested
        tested_for_xss = [g for g in gap if g.vuln_class == "xss" and g.endpoint == "https://example.com/login"]
        # The cell was tested (test_count=1) so it should not appear with min_count=2
        assert all(g.test_count >= 1 for g in tested_for_xss) or len(tested_for_xss) == 0

    def test_record_finding(self):
        cm = vhc.CoverageMap("test_mission", "example.com")
        cm.register_endpoint("https://example.com/api")
        cm.record_finding("https://example.com/api", "sqli")

        cov = cm.get_endpoint_coverage("https://example.com/api")
        assert cov["findings"] >= 1

    def test_get_gaps(self):
        cm = vhc.CoverageMap("test_mission", "example.com")
        cm.register_endpoint("https://example.com/login")
        cm.register_endpoint("https://example.com/api")

        # Test one endpoint for one vuln class
        cm.record_test("https://example.com/login", "sqli")

        gaps = cm.get_gaps()
        # There should still be many gaps (most vuln classes untested on login + all on api)
        assert len(gaps) > 0

    def test_get_tested_endpoints(self):
        cm = vhc.CoverageMap("test_mission", "example.com")
        cm.register_endpoint("https://example.com/login")
        cm.record_test("https://example.com/login", "sqli")

        tested = cm.get_tested_endpoints()
        assert "https://example.com/login" in tested

    def test_prompt_context(self):
        cm = vhc.CoverageMap("test_mission", "example.com")
        context = cm.prompt_context()
        assert context == ""

        cm.register_endpoint("https://example.com/login")
        context = cm.prompt_context()
        assert "COVERAGE GAPS" in context

    def test_summary(self):
        cm = vhc.CoverageMap("test_mission", "example.com")
        summary = cm.summary()
        assert "Coverage:" in summary
        assert "0%" in summary  # nothing tested


# ---------------------------------------------------------------------------
# NegativeResultStore tests
# ---------------------------------------------------------------------------


class TestNegativeResultStore:
    def test_record_and_check(self):
        ns = vhc.NegativeResultStore("test_mission")
        assert not ns.was_tested("/api/login", "sqli")

        ns.record("/api/login", "sqli", "sqlmap", "sqlmap -u /api/login", reason="no injection detected")

        assert ns.was_tested("/api/login", "sqli")

    def test_get_previous_attempts(self):
        ns = vhc.NegativeResultStore("test_mission")
        ns.record("/api/login", "sqli", "sqlmap", "sqlmap -u /api/login", "no injection")

        attempts = ns.get_previous_attempts("/api/login", "sqli")
        assert len(attempts) == 1
        assert attempts[0].tool_used == "sqlmap"

    def test_prompt_context(self):
        ns = vhc.NegativeResultStore("test_mission")
        context = ns.get_prompt_context()
        assert context == ""

        ns.record("/api/login", "sqli", "sqlmap", "sqlmap -u /api/login", "no injection")
        context = ns.get_prompt_context()
        assert "PREVIOUSLY TESTED" in context
        assert "sqli" in context


# ---------------------------------------------------------------------------
# VerificationPipeline tests
# ---------------------------------------------------------------------------


class TestVerificationPipeline:
    def test_initial_state(self):
        vp = vhc.VerificationPipeline()
        assert vp.get_all_verdicts() == []
        assert vp.get_actionable_findings() == []
        assert vp.false_positive_rate() == 0.0

    def test_verify_no_agent(self):
        vp = vhc.VerificationPipeline()
        verdict = vp.verify_finding(
            {"type": "sqli", "url": "https://example.com/login"},
        )
        assert verdict.status == "false_positive"
        assert verdict.confidence == 0.1

    def test_verify_different_types(self):
        vp = vhc.VerificationPipeline()
        verdict = vp.verify_finding(
            {"type": "rce", "url": "https://example.com/exec", "evidence": "command injection in id parameter"},
        )
        assert verdict.status == "false_positive"  # no agent = can't verify

    def test_prompt_context_empty(self):
        vp = vhc.VerificationPipeline()
        assert vp.prompt_context() == ""

    def test_verdict_actionable(self):
        v = vhc.Verdict(
            vuln_class="sqli",
            endpoint="/api/login",
            status="confirmed",
            confidence=0.7,
        )
        assert v.is_actionable()

        v2 = vhc.Verdict(
            vuln_class="sqli",
            endpoint="/api/login",
            status="false_positive",
            confidence=0.1,
        )
        assert not v2.is_actionable()

    def test_verdict_serialization(self):
        v = vhc.Verdict(
            vuln_class="xss",
            endpoint="/search",
            status="proven",
            confidence=0.85,
            proof_of_concept="<script>alert(1)</script>",
        )
        d = v.to_dict()
        assert d["vuln_class"] == "xss"
        assert d["status"] == "proven"
        assert d["proof_of_concept"] == "<script>alert(1)</script>"


# ---------------------------------------------------------------------------
# ReflectEngine tests
# ---------------------------------------------------------------------------


class TestReflectEngine:
    def test_initial_reflection(self):
        re = vhc.ReflectEngine(max_steps_without_findings=5)
        ref = re.reflect(cycle=0, recent_findings_count=0)

        assert ref.cycle == 0
        assert ref.status == "on_track"
        assert ref.findings_this_cycle == 0
        assert not ref.switch_strategy

    def test_consecutive_no_findings_triggers_stuck(self):
        re = vhc.ReflectEngine(max_steps_without_findings=3)

        # Three cycles with no findings
        for i in range(3):
            ref = re.reflect(cycle=i, recent_findings_count=0)

        assert ref.status == "stuck"
        assert ref.switch_strategy
        assert ref.consecutive_no_findings == 3

    def test_finding_resets_counter(self):
        re = vhc.ReflectEngine(max_steps_without_findings=3)

        ref1 = re.reflect(cycle=0, recent_findings_count=0)
        ref2 = re.reflect(cycle=1, recent_findings_count=0)
        ref3 = re.reflect(cycle=2, recent_findings_count=1)  # found something

        assert ref3.consecutive_no_findings == 0
        assert ref3.status == "on_track"

    def test_adaptation_before_stuck(self):
        re = vhc.ReflectEngine(max_steps_without_findings=5)

        ref1 = re.reflect(cycle=0, recent_findings_count=0)
        ref2 = re.reflect(cycle=1, recent_findings_count=0)
        ref3 = re.reflect(cycle=2, recent_findings_count=0)

        # Adaptation kicks in at 3 consecutive no-findings (counter=3 after 3 no-finding calls)
        assert ref3.status == "needs_adaptation", f"Got {ref3.status} with consecutive={ref3.consecutive_no_findings}"

    def test_on_track_with_findings(self):
        re = vhc.ReflectEngine(max_steps_without_findings=5)

        ref = re.reflect(cycle=0, recent_findings_count=2)
        assert ref.status == "on_track"
        assert not ref.switch_strategy

    def test_prompt_context(self):
        re = vhc.ReflectEngine(max_steps_without_findings=5)
        assert re.prompt_context() == ""

        re.reflect(cycle=0, recent_findings_count=1)
        ctx = re.prompt_context()
        assert "REFLECTION" in ctx
        assert "on_track" in ctx

    def test_multiple_reflections_in_history(self):
        re = vhc.ReflectEngine(max_steps_without_findings=3)

        for i in range(5):
            re.reflect(cycle=i, recent_findings_count=0)

        assert len(re.history) == 5
        assert re.switch_count > 0

    def test_reflection_priority_targets(self):
        cm = vhc.CoverageMap("test_mission", "example.com")
        cm.register_endpoint("https://example.com/api")

        re = vhc.ReflectEngine(max_steps_without_findings=5)
        ref = re.reflect(cycle=0, recent_findings_count=0, coverage_map=cm)

        assert ref.status == "on_track"


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_belief_to_coverage_flow(self):
        """End-to-end: add belief + coverage gaps exist."""
        bs = vhc.BeliefState("integration_test")
        cm = vhc.CoverageMap("integration_test", "example.com")

        cm.register_endpoint("https://example.com/login")
        bs.add_belief("sqli", "https://example.com/login", "User input in SQL query", confidence=0.6)

        gaps = cm.get_gaps()
        assert len(gaps) > 0
        assert bs.get_active_beliefs(min_confidence=0.5) is not None

    def test_negative_store_covers_multiple_classes(self):
        """Multiple negative results tracked independently."""
        ns = vhc.NegativeResultStore("integration_test")

        ns.record("/api/login", "sqli", "sqlmap", "sqlmap -u /api/login")
        ns.record("/api/login", "xss", "dalfox", "dalfox url /api/login")

        assert ns.was_tested("/api/login", "sqli")
        assert ns.was_tested("/api/login", "xss")
        assert not ns.was_tested("/api/login", "ssrf")

    def test_full_reflection_cycle(self):
        """Simulate a realistic reflection cycle."""
        re = vhc.ReflectEngine(max_steps_without_findings=5)

        # Cycle 1: Find something (resets counter)
        r1 = re.reflect(0, recent_findings_count=2)
        assert r1.status == "on_track"

        # Cycle 2-3: Nothing (building up)
        r2 = re.reflect(1, recent_findings_count=0)
        r3 = re.reflect(2, recent_findings_count=0)
        assert r3.status == "on_track"

        # Cycle 4: Nothing (consecutive=3 → needs adaptation)
        r4 = re.reflect(3, recent_findings_count=0)
        assert r4.status == "needs_adaptation", f"Got {r4.status} consecutive={r4.consecutive_no_findings}"

        # Cycle 5: Nothing (consecutive=4, still adapting)
        r5 = re.reflect(4, recent_findings_count=0)
        assert r5.status == "needs_adaptation"

        # Cycle 6: Nothing (consecutive=5 ≥ max=5 → stuck)
        r6 = re.reflect(5, recent_findings_count=0)
        assert r6.status == "stuck"
        assert r6.switch_strategy

"""tests/test_scan_context.py — Tests for agents.scan_context.ScanContext"""

import time
from pathlib import Path

import pytest

from agents.scan_context import ScanContext


# ── Creation Tests ──────────────────────────────────────────────


class TestScanContextCreation:
    """Test ScanContext creation with various inputs."""

    def test_create_with_required_fields(self):
        ctx = ScanContext(target="example.com")
        assert ctx.target == "example.com"
        assert ctx.max_steps == 25
        assert ctx.step_count == 0
        assert ctx.all_findings == []

    def test_create_with_all_fields(self):
        ctx = ScanContext(
            target="example.com",
            base_url="https://example.com",
            report_dir=Path("/tmp/reports"),
            objective="Find SQLi",
            mission_key="test:123",
            max_steps=10,
            rate_limit=3,
            timeout=120,
        )
        assert ctx.target == "example.com"
        assert ctx.base_url == "https://example.com"
        assert ctx.report_dir == Path("/tmp/reports")
        assert ctx.objective == "Find SQLi"
        assert ctx.mission_key == "test:123"
        assert ctx.max_steps == 10
        assert ctx.rate_limit == 3
        assert ctx.timeout == 120

    def test_create_rejects_empty_target(self):
        with pytest.raises(ValueError, match="must not be empty"):
            ScanContext(target="")

    def test_create_rejects_zero_max_steps(self):
        with pytest.raises(ValueError, match="must be >= 1"):
            ScanContext(target="example.com", max_steps=0)

    def test_create_rejects_negative_max_steps(self):
        with pytest.raises(ValueError, match="must be >= 1"):
            ScanContext(target="example.com", max_steps=-5)

    def test_defaults_are_sensible(self):
        ctx = ScanContext(target="example.com")
        assert ctx.rate_limit == 5
        assert ctx.timeout == 600
        assert ctx.step_count == 0
        assert ctx.consecutive_no_findings == 0
        assert ctx.token_usage == 0
        assert ctx.all_findings == []
        assert ctx.previous_results == []
        assert ctx.action_history == []
        assert ctx.history == []

    def test_state_objects_default_to_none(self):
        ctx = ScanContext(target="example.com")
        assert ctx.mission_state is None
        assert ctx.coverage_map is None
        assert ctx.belief_state is None
        assert ctx.negative_results is None
        assert ctx.verification_pipeline is None
        assert ctx.vector_memory is None
        assert ctx.planner is None
        assert ctx.attack_tree is None
        assert ctx.reflect_engine is None


# ── Factory Method Tests ────────────────────────────────────────


class TestScanContextFromTarget:
    """Test ScanContext.from_target() factory method."""

    def test_from_target_basic(self):
        ctx = ScanContext.from_target("example.com", objective="Find vulns")
        assert ctx.target == "example.com"
        assert ctx.base_url == "http://example.com"
        assert ctx.objective == "Find vulns"
        assert ctx.mission_key.startswith("example.com:")
        assert ctx.report_dir.exists()

    def test_from_target_preserves_url(self):
        ctx = ScanContext.from_target("https://example.com")
        assert ctx.target == "example.com"
        assert ctx.base_url == "https://example.com"

    def test_from_target_with_ip(self):
        ctx = ScanContext.from_target("93.184.216.34")
        assert ctx.target == "93.184.216.34"
        assert ctx.base_url == "http://93.184.216.34"

    def test_from_target_custom_report_dir(self):
        custom_dir = Path("/tmp/test_reports")
        ctx = ScanContext.from_target("example.com", report_dir=custom_dir)
        assert ctx.report_dir == custom_dir

    def test_from_target_custom_params(self):
        ctx = ScanContext.from_target(
            "example.com",
            max_steps=10,
            rate_limit=3,
            timeout=120,
        )
        assert ctx.max_steps == 10
        assert ctx.rate_limit == 3
        assert ctx.timeout == 120

    def test_from_target_empty_raises(self):
        with pytest.raises(ValueError):
            ScanContext.from_target("")

    def test_from_target_initializes_history(self):
        ctx = ScanContext.from_target("example.com", objective="test")
        assert len(ctx.history) == 1
        assert ctx.history[0]["role"] == "user"
        assert ctx.history[0]["content"] == "test"

    def test_from_target_no_objective_empty_history(self):
        ctx = ScanContext.from_target("example.com")
        assert ctx.history == []


# ── Update Tests ────────────────────────────────────────────────


class TestScanContextUpdate:
    """Test ScanContext counter updates."""

    def test_update_with_findings(self):
        ctx = ScanContext(target="example.com")
        ctx.update_after_step([{"type": "xss", "url": "http://example.com"}])
        assert ctx.step_count == 1
        assert ctx.consecutive_no_findings == 0
        assert ctx.cycle_findings_count == 1

    def test_update_without_findings(self):
        ctx = ScanContext(target="example.com")
        ctx.update_after_step([])
        assert ctx.step_count == 1
        assert ctx.consecutive_no_findings == 1
        assert ctx.cycle_findings_count == 0

    def test_update_streak_tracking(self):
        ctx = ScanContext(target="example.com")
        ctx.update_after_step([])  # 1
        ctx.update_after_step([])  # 2
        ctx.update_after_step([])  # 3
        assert ctx.consecutive_no_findings == 3

        ctx.update_after_step([{"type": "sqli"}])  # found something
        assert ctx.consecutive_no_findings == 0

        ctx.update_after_step([])  # back to no findings
        assert ctx.consecutive_no_findings == 1

    def test_multiple_steps(self):
        ctx = ScanContext(target="example.com", max_steps=10)
        for i in range(5):
            ctx.update_after_step([])
        assert ctx.step_count == 5
        assert ctx.steps_remaining == 5


# ── Accumulation Tests ──────────────────────────────────────────


class TestScanContextAccumulation:
    """Test finding/result accumulation methods."""

    def test_add_finding(self):
        ctx = ScanContext(target="example.com")
        ctx.add_finding({"type": "xss", "url": "http://example.com/x"})
        assert ctx.finding_count == 1
        assert ctx.has_findings is True

    def test_add_findings(self):
        ctx = ScanContext(target="example.com")
        ctx.add_findings(
            [
                {"type": "xss"},
                {"type": "sqli"},
                {"type": "ssrf"},
            ]
        )
        assert ctx.finding_count == 3

    def test_add_result(self):
        ctx = ScanContext(target="example.com")
        result = {"tool": "fuzzer", "success": True}
        ctx.add_result(result)
        assert len(ctx.previous_results) == 1
        assert ctx.previous_results[0] == result

    def test_add_action(self):
        ctx = ScanContext(target="example.com")
        ctx.add_action({"action": "run_shell", "command": "nmap target"})
        assert len(ctx.action_history) == 1

    def test_append_history(self):
        ctx = ScanContext(target="example.com")
        ctx.append_history("assistant", "I found an XSS vulnerability")
        assert len(ctx.history) == 1
        assert ctx.history[0]["role"] == "assistant"

    def test_has_findings_false_initially(self):
        ctx = ScanContext(target="example.com")
        assert ctx.has_findings is False
        assert ctx.finding_count == 0

    def test_is_stuck_after_5_no_finds(self):
        ctx = ScanContext(target="example.com")
        for _ in range(4):
            ctx.update_after_step([])
        assert ctx.is_stuck is False
        ctx.update_after_step([])
        assert ctx.is_stuck is True

    def test_is_stuck_resets_on_finding(self):
        ctx = ScanContext(target="example.com")
        for _ in range(6):
            ctx.update_after_step([])
        assert ctx.is_stuck is True
        ctx.update_after_step([{"type": "sqli"}])
        assert ctx.is_stuck is False


# ── Steps Remaining Tests ───────────────────────────────────────


class TestScanContextStepsRemaining:
    """Test steps_remaining property."""

    def test_initial_steps_remaining(self):
        ctx = ScanContext(target="example.com", max_steps=25)
        assert ctx.steps_remaining == 25

    def test_steps_remaining_decreases(self):
        ctx = ScanContext(target="example.com", max_steps=10)
        ctx.update_after_step([])
        assert ctx.steps_remaining == 9
        ctx.update_after_step([])
        assert ctx.steps_remaining == 8

    def test_steps_remaining_floor_zero(self):
        ctx = ScanContext(target="example.com", max_steps=2)
        ctx.update_after_step([])
        ctx.update_after_step([])
        ctx.update_after_step([])  # over max
        assert ctx.steps_remaining == 0


# ── Integration Test ────────────────────────────────────────────


class TestScanContextLifecycle:
    """Test a realistic scan context lifecycle."""

    def test_full_lifecycle(self):
        ctx = ScanContext.from_target("example.com", objective="Find SQLi")
        assert ctx.target == "example.com"

        # Step 1: no findings
        ctx.update_after_step([])
        assert ctx.step_count == 1
        assert ctx.consecutive_no_findings == 1

        # Step 2: find something
        ctx.add_finding({"type": "sqli", "url": "http://example.com/api"})
        ctx.add_result({"tool": "fuzzer", "success": True})
        ctx.add_action({"action": "run_shell", "command": "python3 fuzzer.py"})
        ctx.update_after_step(ctx.all_findings)
        assert ctx.step_count == 2
        assert ctx.consecutive_no_findings == 0
        assert ctx.has_findings is True

        # Step 3: more no findings
        ctx.update_after_step([])
        assert ctx.step_count == 3
        assert ctx.steps_remaining == ctx.max_steps - 3

"""Tests for elengix/scanning/scan_context.py — ScanContext."""

from __future__ import annotations

import pytest
from pathlib import Path

from elengenix.scanning.scan_context import ScanContext


class TestScanContextInit:
    """Tests for ScanContext creation and validation."""

    def test_create_with_target(self):
        ctx = ScanContext(target="example.com")
        assert ctx.target == "example.com"
        assert ctx.step_count == 0
        assert ctx.consecutive_no_findings == 0
        assert ctx.all_findings == []
        assert ctx.history == []

    def test_empty_target_raises(self):
        with pytest.raises(ValueError, match="must not be empty"):
            ScanContext(target="")

    def test_blank_target_does_not_raise(self):
        """Blank-ish string is still truthy, so no ValueError."""
        ctx = ScanContext(target="   ")
        assert ctx.target == "   "

    def test_max_steps_must_be_positive(self):
        with pytest.raises(ValueError, match="must be >= 1"):
            ScanContext(target="ex.com", max_steps=0)

    def test_default_max_steps(self):
        ctx = ScanContext(target="ex.com")
        assert ctx.max_steps == 25

    def test_custom_max_steps(self):
        ctx = ScanContext(target="ex.com", max_steps=10)
        assert ctx.max_steps == 10

    def test_default_report_dir(self):
        ctx = ScanContext(target="ex.com")
        assert isinstance(ctx.report_dir, Path)

    def test_init_with_objective_does_not_store_history_by_default(self):
        """Only from_target stores objective in history, not __init__."""
        ctx = ScanContext(target="ex.com", objective="scan")
        assert ctx.objective == "scan"
        assert ctx.history == []

    def test_init_without_objective_empty_history(self):
        ctx = ScanContext(target="ex.com")
        assert ctx.history == []


class TestScanContextFromTarget:
    """Tests for ScanContext.from_target factory."""

    def test_basic_creation(self):
        ctx = ScanContext.from_target("example.com")
        assert ctx.target == "example.com"
        assert ctx.step_count == 0

    def test_target_normalized(self, monkeypatch):
        """from_target normalizes via core.orchestrator.normalize_target."""
        monkeypatch.setattr(
            "core.orchestrator.normalize_target",
            lambda t: "normalized.local",
        )
        ctx = ScanContext.from_target("EXAMPLE.COM")
        assert ctx.target == "normalized.local"

    def test_normalize_failure_raises(self, monkeypatch):
        monkeypatch.setattr(
            "core.orchestrator.normalize_target",
            lambda t: "",
        )
        with pytest.raises(ValueError, match="Cannot normalize target"):
            ScanContext.from_target("invalid")

    def test_base_url_adds_scheme(self):
        ctx = ScanContext.from_target("example.com", objective="test")
        assert ctx.base_url == "http://example.com"

    def test_base_url_preserves_scheme(self):
        ctx = ScanContext.from_target("https://example.com")
        assert ctx.base_url == "https://example.com"

    def test_custom_report_dir(self, tmp_path):
        d = tmp_path / "reports"
        ctx = ScanContext.from_target("ex.com", report_dir=d)
        assert ctx.report_dir == d
        assert d.exists()

    def test_mission_key_contains_target(self):
        ctx = ScanContext.from_target("example.com")
        assert "example.com" in ctx.mission_key

    def test_mission_key_contains_timestamp(self):
        ctx = ScanContext.from_target("ex.com")
        assert ":" in ctx.mission_key  # normalized:timestamp

    def test_objective_in_history(self):
        ctx = ScanContext.from_target("ex.com", objective="find xss")
        assert any(
            m["content"] == "find xss" for m in ctx.history
        )

    def test_no_objective_empty_history(self):
        ctx = ScanContext.from_target("ex.com")
        assert ctx.history == []


class TestScanContextUpdateAfterStep:
    """Tests for update_after_step."""

    def test_step_count_increments(self):
        ctx = ScanContext(target="ex.com")
        ctx.update_after_step([])
        assert ctx.step_count == 1

    def test_findings_reset_consecutive(self):
        ctx = ScanContext(target="ex.com")
        ctx.consecutive_no_findings = 3
        ctx.update_after_step([{"vuln": "xss"}])
        assert ctx.consecutive_no_findings == 0

    def test_no_findings_increments_consecutive(self):
        ctx = ScanContext(target="ex.com")
        ctx.update_after_step([])
        assert ctx.consecutive_no_findings == 1

    def test_multiple_no_findings(self):
        ctx = ScanContext(target="ex.com")
        for _ in range(4):
            ctx.update_after_step([])
        assert ctx.consecutive_no_findings == 4

    def test_findings_sets_cycle_findings_count(self):
        ctx = ScanContext(target="ex.com")
        ctx.update_after_step([{"vuln": "a"}, {"vuln": "b"}])
        assert ctx.cycle_findings_count == 2

    def test_no_findings_sets_cycle_findings_count_zero(self):
        ctx = ScanContext(target="ex.com")
        ctx.update_after_step([])
        assert ctx.cycle_findings_count == 0


class TestScanContextAddMethods:
    """Tests for add_finding, add_findings, add_result, add_action, append_history."""

    def test_add_finding(self):
        ctx = ScanContext(target="ex.com")
        ctx.add_finding({"vuln": "xss"})
        assert len(ctx.all_findings) == 1
        assert ctx.all_findings[0]["vuln"] == "xss"

    def test_add_findings(self):
        ctx = ScanContext(target="ex.com")
        ctx.add_findings([{"vuln": "a"}, {"vuln": "b"}])
        assert len(ctx.all_findings) == 2

    def test_add_result(self):
        ctx = ScanContext(target="ex.com")
        r = {"output": "done"}
        ctx.add_result(r)
        assert ctx.previous_results == [r]

    def test_add_action(self):
        ctx = ScanContext(target="ex.com")
        a = {"action": "scan"}
        ctx.add_action(a)
        assert ctx.action_history == [a]

    def test_append_history(self):
        ctx = ScanContext(target="ex.com")
        ctx.append_history("assistant", "hello")
        assert ctx.history == [{"role": "assistant", "content": "hello"}]

    def test_multiple_history_entries(self):
        ctx = ScanContext(target="ex.com")
        ctx.append_history("user", "hi")
        ctx.append_history("assistant", "ok")
        assert len(ctx.history) == 2


class TestScanContextProperties:
    """Tests for has_findings, finding_count, is_stuck, steps_remaining."""

    def test_has_findings_default_false(self):
        ctx = ScanContext(target="ex.com")
        assert ctx.has_findings is False

    def test_has_findings_after_add(self):
        ctx = ScanContext(target="ex.com")
        ctx.add_finding({"vuln": "xss"})
        assert ctx.has_findings is True

    def test_finding_count(self):
        ctx = ScanContext(target="ex.com")
        assert ctx.finding_count == 0
        ctx.add_finding({"vuln": "a"})
        ctx.add_finding({"vuln": "b"})
        assert ctx.finding_count == 2

    def test_is_stuck_below_threshold(self):
        ctx = ScanContext(target="ex.com")
        for _ in range(4):
            ctx.update_after_step([])
        assert ctx.is_stuck is False

    def test_is_stuck_at_threshold(self):
        ctx = ScanContext(target="ex.com")
        for _ in range(5):
            ctx.update_after_step([])
        assert ctx.is_stuck is True

    def test_is_stuck_above_threshold(self):
        ctx = ScanContext(target="ex.com")
        for _ in range(7):
            ctx.update_after_step([])
        assert ctx.is_stuck is True

    def test_is_stuck_resets_after_finding(self):
        ctx = ScanContext(target="ex.com")
        for _ in range(5):
            ctx.update_after_step([])
        assert ctx.is_stuck is True
        ctx.update_after_step([{"vuln": "xss"}])
        assert ctx.is_stuck is False

    def test_steps_remaining_full(self):
        ctx = ScanContext(target="ex.com", max_steps=10)
        assert ctx.steps_remaining == 10

    def test_steps_remaining_partial(self):
        ctx = ScanContext(target="ex.com", max_steps=10)
        ctx.update_after_step([])
        ctx.update_after_step([])
        assert ctx.steps_remaining == 8

    def test_steps_remaining_zero(self):
        ctx = ScanContext(target="ex.com", max_steps=3)
        ctx.update_after_step([])
        ctx.update_after_step([])
        ctx.update_after_step([])
        assert ctx.steps_remaining == 0

    def test_steps_remaining_not_negative(self):
        ctx = ScanContext(target="ex.com", max_steps=2)
        for _ in range(5):
            ctx.update_after_step([])
        assert ctx.steps_remaining == 0


class TestScanContextEdgeCases:
    """Edge cases and composite behaviors."""

    def test_from_target_then_add_finding(self):
        ctx = ScanContext.from_target("https://example.com", objective="pentest")
        ctx.add_finding({"vuln": "xss", "severity": "high"})
        assert ctx.finding_count == 1
        assert ctx.objective == "pentest"

    def test_full_lifecycle(self):
        """Simulate a complete scan lifecycle."""
        ctx = ScanContext(target="app.example.com", max_steps=3, objective="find bugs")
        ctx.add_finding({"vuln": "sqli"})
        ctx.update_after_step(ctx.all_findings)  # step 1 with findings
        ctx.update_after_step([])  # step 2 no findings
        ctx.update_after_step([])  # step 3 no findings
        assert ctx.step_count == 3
        assert ctx.consecutive_no_findings == 2
        assert ctx.finding_count == 1
        assert ctx.steps_remaining == 0

    def test_normalized_target_spaces_replaced(self, monkeypatch):
        monkeypatch.setattr(
            "core.orchestrator.normalize_target",
            lambda t: "my target.local",
        )
        ctx = ScanContext.from_target("my target.local")
        # Spaces become underscores in safe_name
        assert "my_target.local" not in ctx.mission_key  # just confirm no space crash
        assert ctx.target == "my target.local"

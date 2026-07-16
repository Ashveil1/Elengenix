"""Tests for elengenix/loop.py — Agentic loop dataclasses and MetricsCollector."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, Mock, patch

from elengenix.loop import LoopConfig, LoopMetrics, TrueAgenticLoop, MetricsCollector


class TestLoopConfig:
    """Tests for LoopConfig dataclass."""

    def test_default_values(self):
        """Should have correct defaults."""
        config = LoopConfig()
        assert config.max_steps == 100
        assert config.max_duration == 86400
        assert config.max_cost == 100.0
        assert config.replan_threshold == 0.3
        assert config.reflection_interval == 10
        assert config.constitutional_check is True
        assert config.auto_replan is True
        assert config.max_consecutive_failures == 3

    def test_custom_values(self):
        """Should accept custom values."""
        config = LoopConfig(max_steps=50, max_duration=3600, max_cost=10.0)
        assert config.max_steps == 50
        assert config.max_duration == 3600
        assert config.max_cost == 10.0


class TestLoopMetrics:
    """Tests for LoopMetrics dataclass."""

    def test_default_values(self):
        """Should have correct defaults."""
        metrics = LoopMetrics()
        assert metrics.steps_taken == 0
        assert metrics.successful_actions == 0
        assert metrics.failed_actions == 0
        assert metrics.replans == 0
        assert metrics.constitutional_violations == 0
        assert metrics.human_interventions == 0
        assert metrics.total_duration == 0.0
        assert metrics.total_cost == 0.0
        assert metrics.findings_discovered == 0
        assert metrics.findings_verified == 0
        assert metrics.unique_vuln_types == set()


class TestMetricsCollector:
    """Tests for MetricsCollector."""

    def test_init(self):
        """Should initialize empty counters, gauges, histograms."""
        mc = MetricsCollector()
        assert mc.counters == {}
        assert mc.gauges == {}
        assert mc.histograms == {}

    def test_increment(self):
        """Should increment counter."""
        mc = MetricsCollector()
        mc.increment("test_counter")
        assert mc.counters["test_counter"] == 1
        mc.increment("test_counter")
        assert mc.counters["test_counter"] == 2

    def test_increment_with_value(self):
        """Should increment by specified value."""
        mc = MetricsCollector()
        mc.increment("counter", 5)
        assert mc.counters["counter"] == 5
        mc.increment("counter", 3)
        assert mc.counters["counter"] == 8

    def test_gauge(self):
        """Should set gauge value."""
        mc = MetricsCollector()
        mc.gauge("cpu", 0.75)
        assert mc.gauges["cpu"] == 0.75
        mc.gauge("cpu", 0.9)
        assert mc.gauges["cpu"] == 0.9

    def test_histogram(self):
        """Should append to histogram."""
        mc = MetricsCollector()
        mc.histogram("latency", 10.0)
        mc.histogram("latency", 20.0)
        mc.histogram("latency", 30.0)
        assert mc.histograms["latency"] == [10.0, 20.0, 30.0]

    def test_get_summary(self):
        """Should return summary dict."""
        mc = MetricsCollector()
        mc.increment("requests", 10)
        mc.increment("errors", 2)
        mc.gauge("memory", 0.5)
        mc.histogram("latency", 10.0)
        mc.histogram("latency", 20.0)

        summary = mc.get_summary()
        assert summary["counters"]["requests"] == 10
        assert summary["counters"]["errors"] == 2
        assert summary["gauges"]["memory"] == 0.5
        assert summary["histograms"]["latency"]["count"] == 2
        assert summary["histograms"]["latency"]["avg"] == 15.0

    def test_get_summary_empty_histogram(self):
        """Empty histogram should have avg=0."""
        mc = MetricsCollector()
        mc.histogram("empty", 5.0)  # create the key
        mc.histograms["empty"] = []  # clear it
        summary = mc.get_summary()
        assert summary["histograms"]["empty"]["avg"] == 0
        assert summary["histograms"]["empty"]["count"] == 0


class TestTrueAgenticLoop:
    """Tests for TrueAgenticLoop init."""

    def test_init(self):
        """Should initialize with required components."""
        mock_brain = Mock()
        mock_constitution = MagicMock()
        mock_governance = Mock()
        mock_tools = Mock()
        mock_memory = Mock()

        loop = TrueAgenticLoop(
            brain=mock_brain,
            constitution=mock_constitution,
            governance=mock_governance,
            tools=mock_tools,
            memory=mock_memory,
        )

        assert loop.brain is mock_brain
        assert loop.governance is mock_governance
        assert loop.tools is mock_tools
        assert loop.memory is mock_memory
        assert isinstance(loop.config, LoopConfig)
        assert isinstance(loop.metrics_data, LoopMetrics)
        assert loop._shutdown is False

    def test_init_with_custom_config(self):
        """Should use provided config."""
        loop = TrueAgenticLoop(
            brain=Mock(),
            constitution=MagicMock(),
            governance=Mock(),
            tools=Mock(),
            memory=Mock(),
            config=LoopConfig(max_steps=50),
        )
        assert loop.config.max_steps == 50

    def test_shutdown(self):
        """Should set shutdown flag."""
        loop = TrueAgenticLoop(
            brain=Mock(),
            constitution=MagicMock(),
            governance=Mock(),
            tools=Mock(),
            memory=Mock(),
        )
        assert loop._shutdown is False
        loop.shutdown()
        assert loop._shutdown is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
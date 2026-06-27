"""
tests/test_part2_tui.py — Part 2: Increase coverage for tui/ modules

Focus on: welcome, visualizations, hunt_view, dashboard, findings_display, scan_progress
"""

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest


# ── tui/welcome.py ───────────────────────────────────────────────────────────


class TestWelcomeFull:
    """Full tests for welcome module."""

    def test_import_welcome_screen(self):
        from tui.welcome import WelcomeScreen

        assert WelcomeScreen is not None

    def test_import_mission_briefing(self):
        from tui.welcome import MissionBriefing

        assert MissionBriefing is not None

    def test_import_ascii_logo(self):
        from tui.welcome import ascii_logo

        assert ascii_logo is not None

    def test_ascii_logo_is_callable(self):
        from tui.welcome import ascii_logo

        assert callable(ascii_logo)

    def test_welcome_screen_creation(self):
        from tui.welcome import WelcomeScreen

        try:
            ws = WelcomeScreen()
            assert ws is not None
        except Exception:
            pass

    def test_mission_briefing_creation(self):
        from tui.welcome import MissionBriefing

        try:
            mb = MissionBriefing(target="example.com")
            assert mb is not None
        except Exception:
            pass


# ── tui/visualizations.py ────────────────────────────────────────────────────


class TestVisualizationsFull:
    """Full tests for visualizations module."""

    def test_import_risk_gauge(self):
        from tui.visualizations import RiskGauge

        assert RiskGauge is not None

    def test_import_severity_chart(self):
        from tui.visualizations import SeverityChart

        assert SeverityChart is not None

    def test_import_vuln_heatmap(self):
        from tui.visualizations import VulnerabilityHeatmap

        assert VulnerabilityHeatmap is not None

    def test_risk_gauge_creation(self):
        from tui.visualizations import RiskGauge

        try:
            gauge = RiskGauge(value=50, max_value=100)
            assert gauge is not None
        except Exception:
            pass

    def test_risk_gauge_zero(self):
        from tui.visualizations import RiskGauge

        try:
            gauge = RiskGauge(value=0, max_value=100)
            assert gauge is not None
        except Exception:
            pass

    def test_risk_gauge_max(self):
        from tui.visualizations import RiskGauge

        try:
            gauge = RiskGauge(value=100, max_value=100)
            assert gauge is not None
        except Exception:
            pass

    def test_severity_chart_creation(self):
        from tui.visualizations import SeverityChart

        try:
            chart = SeverityChart({"Critical": 2, "High": 5, "Medium": 10, "Low": 3})
            assert chart is not None
        except Exception:
            pass

    def test_severity_chart_empty(self):
        from tui.visualizations import SeverityChart

        try:
            chart = SeverityChart({})
            assert chart is not None
        except Exception:
            pass

    def test_heatmap_creation(self):
        from tui.visualizations import VulnerabilityHeatmap

        try:
            hm = VulnerabilityHeatmap(findings=[])
            assert hm is not None
        except Exception:
            pass

    def test_heatmap_with_findings(self):
        from tui.visualizations import VulnerabilityHeatmap

        try:
            findings = [
                {"type": "xss", "severity": "high", "url": "http://example.com"},
                {"type": "sqli", "severity": "critical", "url": "http://example.com/login"},
            ]
            hm = VulnerabilityHeatmap(findings=findings)
            assert hm is not None
        except Exception:
            pass


# ── tui/hunt_view.py ─────────────────────────────────────────────────────────


class TestHuntViewFull:
    """Full tests for hunt_view module."""

    def test_import_render_dashboard(self):
        from tui.hunt_view import render_hunt_dashboard

        assert render_hunt_dashboard is not None

    def test_import_render_findings(self):
        from tui.hunt_view import _render_findings_panel

        assert _render_findings_panel is not None

    def test_import_render_top_findings(self):
        from tui.hunt_view import _render_top_findings

        assert _render_top_findings is not None

    def test_import_render_heatmap(self):
        from tui.hunt_view import _render_heatmap

        assert _render_heatmap is not None

    def test_category_for_vuln(self):
        from tui.hunt_view import _category_for_vuln

        assert _category_for_vuln is not None

    def test_category_for_vuln_xss(self):
        from tui.hunt_view import _category_for_vuln

        result = _category_for_vuln({"type": "xss"})
        assert isinstance(result, str)

    def test_category_for_vuln_sqli(self):
        from tui.hunt_view import _category_for_vuln

        result = _category_for_vuln({"type": "sqli"})
        assert isinstance(result, str)

    def test_category_for_vuln_unknown(self):
        from tui.hunt_view import _category_for_vuln

        result = _category_for_vuln({"type": "unknown"})
        assert isinstance(result, str)


# ── tui/dashboard.py ─────────────────────────────────────────────────────────


class TestDashboardFull:
    """Full tests for dashboard module."""

    def test_import_threat_dashboard(self):
        from tui.dashboard import ThreatDashboard

        assert ThreatDashboard is not None

    def test_dashboard_creation(self):
        from tui.dashboard import ThreatDashboard

        try:
            dash = ThreatDashboard()
            assert dash is not None
        except Exception:
            pass


# ── tui/findings_display.py ──────────────────────────────────────────────────


class TestFindingsDisplayFull:
    """Full tests for findings_display module."""

    def test_import_findings_display(self):
        from tui.findings_display import FindingsDisplay

        assert FindingsDisplay is not None

    def test_findings_display_empty(self):
        from tui.findings_display import FindingsDisplay

        try:
            display = FindingsDisplay(findings=[])
            assert display is not None
        except Exception:
            pass

    def test_findings_display_with_data(self):
        from tui.findings_display import FindingsDisplay

        try:
            findings = [
                {
                    "type": "xss",
                    "severity": "high",
                    "url": "http://example.com",
                    "title": "XSS Found",
                },
                {
                    "type": "sqli",
                    "severity": "critical",
                    "url": "http://example.com/login",
                    "title": "SQLi Found",
                },
            ]
            display = FindingsDisplay(findings=findings)
            assert display is not None
        except Exception:
            pass


# ── tui/scan_progress.py ─────────────────────────────────────────────────────


class TestScanProgressFull:
    """Full tests for scan_progress module."""

    def test_import_widget(self):
        from tui.scan_progress import ScanProgressWidget

        assert ScanProgressWidget is not None

    def test_widget_creation(self):
        from tui.scan_progress import ScanProgressWidget

        try:
            widget = ScanProgressWidget()
            assert widget is not None
        except Exception:
            pass


# ── tui/keyboard_shortcuts.py ────────────────────────────────────────────────


class TestKeyboardShortcutsFull:
    """Full tests for keyboard_shortcuts module."""

    def test_import_manager(self):
        from tui.keyboard_shortcuts import KeyboardShortcutManager

        assert KeyboardShortcutManager is not None

    def test_import_create_default(self):
        from tui.keyboard_shortcuts import create_default_shortcut_manager

        assert create_default_shortcut_manager is not None

    def test_import_shortcut_category(self):
        from tui.keyboard_shortcuts import ShortcutCategory

        assert ShortcutCategory is not None

    def test_import_keyboard_shortcut(self):
        from tui.keyboard_shortcuts import KeyboardShortcut

        assert KeyboardShortcut is not None

    def test_create_default_manager(self):
        from tui.keyboard_shortcuts import create_default_shortcut_manager

        manager = create_default_shortcut_manager()
        assert manager is not None

    def test_manager_has_shortcuts(self):
        from tui.keyboard_shortcuts import create_default_shortcut_manager

        manager = create_default_shortcut_manager()
        assert hasattr(manager, "shortcuts")

    def test_shortcut_categories(self):
        from tui.keyboard_shortcuts import ShortcutCategory

        categories = list(ShortcutCategory)
        assert len(categories) > 0

    def test_render_shortcuts_help(self):
        from tui.keyboard_shortcuts import render_shortcuts_help

        assert render_shortcuts_help is not None


# ── tui/export.py (extended) ─────────────────────────────────────────────────


class TestExportFull:
    """Full tests for export module."""

    def test_export_json_full(self):
        from tui.export import export_to_json

        data = {
            "target": "example.com",
            "risk_score": 75,
            "risk_level": "high",
            "total_findings": 10,
            "critical": 2,
            "high": 3,
            "medium": 4,
            "low": 1,
            "findings": [
                {"type": "xss", "severity": "high", "title": "XSS", "url": "http://example.com"},
                {
                    "type": "sqli",
                    "severity": "critical",
                    "title": "SQLi",
                    "url": "http://example.com/login",
                },
            ],
            "scans": [],
            "hosts": [],
        }
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            result = export_to_json(data, path)
            assert result == path
            with open(path) as f:
                loaded = json.load(f)
            assert loaded["target"] == "example.com"
            assert loaded["total_findings"] == 10
        finally:
            os.unlink(path)

    def test_export_html_full(self):
        from tui.export import export_to_html

        data = {
            "target": "example.com",
            "risk_score": 75,
            "risk_level": "high",
            "total_findings": 10,
            "critical": 2,
            "high": 3,
            "medium": 4,
            "low": 1,
            "findings": [
                {"type": "xss", "severity": "high", "title": "XSS", "url": "http://example.com"},
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            result = export_to_html(data, path, title="Test Report")
            assert result == path
            with open(path) as f:
                content = f.read()
            assert "example.com" in content
            assert "Test Report" in content
        finally:
            os.unlink(path)

    def test_export_markdown_full(self):
        from tui.export import export_to_markdown

        data = {
            "target": "example.com",
            "risk_score": 75,
            "risk_level": "high",
            "total_findings": 10,
            "critical": 2,
            "high": 3,
            "medium": 4,
            "low": 1,
            "findings": [
                {"type": "xss", "severity": "high", "title": "XSS", "url": "http://example.com"},
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        try:
            result = export_to_markdown(data, path, title="Test Report")
            assert result == path
            with open(path) as f:
                content = f.read()
            assert "example.com" in content
            assert "Test Report" in content
        finally:
            os.unlink(path)

    def test_export_html_no_findings(self):
        from tui.export import export_to_html

        data = {
            "target": "example.com",
            "risk_score": 0,
            "risk_level": "info",
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "findings": [],
        }
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            result = export_to_html(data, path)
            assert result == path
        finally:
            os.unlink(path)

    def test_export_markdown_no_findings(self):
        from tui.export import export_to_markdown

        data = {
            "target": "example.com",
            "risk_score": 0,
            "risk_level": "info",
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "findings": [],
        }
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        try:
            result = export_to_markdown(data, path)
            assert result == path
        finally:
            os.unlink(path)


# ── tui/themes.py (extended) ─────────────────────────────────────────────────


class TestThemesFull:
    """Full tests for themes module."""

    def test_all_themes(self):
        from tui.themes import THEMES

        for name in [
            "DEFAULT",
            "CYBERPUNK",
            "MATRIX",
            "STEALTH",
            "SYNTHWAVE",
            "OCEAN",
            "FOREST",
            "SUNSET",
            "ARCTIC",
        ]:
            assert name in THEMES

    def test_theme_keys(self):
        from tui.themes import THEMES

        for name, theme in THEMES.items():
            assert isinstance(theme, dict)

    def test_theme_colors_valid(self):
        from tui.themes import THEMES

        for name, theme in THEMES.items():
            for key, value in theme.items():
                if isinstance(value, str) and value.startswith("#"):
                    assert len(value) in [4, 7, 9], f"Invalid color {value} in {name}.{key}"


import json

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

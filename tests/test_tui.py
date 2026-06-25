"""test_tui.py - Tests for integrated TUI components.

Tests what is actually used by the hunt/launch commands:
- themes (THEMES, get_theme)
- dashboard (build_static_renderable)
- visualizations (RiskGauge, SeverityChart, VulnerabilityHeatmap)
- welcome (MissionBriefing, build_welcome_renderable)
- hunt_view (render_hunt_dashboard, render_launcher_layout)
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ═══════════════════════════════════════════════════════════════════════════
# THEMES
# ═══════════════════════════════════════════════════════════════════════════

def test_themes_loaded():
    """All 5 themes must be defined."""
    from tui.themes import THEMES, get_theme
    assert "DEFAULT" in THEMES
    assert "CYBERPUNK" in THEMES
    assert "MATRIX" in THEMES
    assert "STEALTH" in THEMES
    assert "SYNTHWAVE" in THEMES
    assert len(THEMES) >= 5


def test_themes_have_required_keys():
    """Each theme must have primary, text, muted."""
    from tui.themes import THEMES
    for name, theme in THEMES.items():
        assert "primary" in theme, f"{name} missing primary"
        assert "text" in theme, f"{name} missing text"
        assert "muted" in theme, f"{name} missing muted"
        # Should be hex colors
        assert theme["primary"].startswith("#"), f"{name} primary not hex"


def test_get_theme_returns_dict():
    """get_theme must return theme dict."""
    from tui.themes import get_theme
    t = get_theme("CYBERPUNK")
    assert t["primary"] == "#ff007a"  # neon pink


# ═══════════════════════════════════════════════════════════════════════════
# VISUALIZATIONS
# ═══════════════════════════════════════════════════════════════════════════

def test_risk_gauge_renders():
    """RiskGauge must produce a Rich renderable."""
    from tui.visualizations import RiskGauge
    gauge = RiskGauge(value=50, max_value=100, label="RISK")
    rendered = gauge.render()
    assert rendered is not None


def test_severity_chart_renders():
    """SeverityChart must render."""
    from tui.visualizations import SeverityChart
    chart = SeverityChart(critical=2, high=5, medium=3, low=1, info=10)
    rendered = chart.render()
    assert rendered is not None


def test_vulnerability_heatmap_renders():
    """VulnerabilityHeatmap must render."""
    from tui.visualizations import VulnerabilityHeatmap
    heatmap = VulnerabilityHeatmap(
        endpoints=["/login", "/api/user/1", "/render"],
        vuln_types=["sql", "xss", "auth"],
    )
    rendered = heatmap.render()
    assert rendered is not None


# ═══════════════════════════════════════════════════════════════════════════
# WELCOME
# ═══════════════════════════════════════════════════════════════════════════

def test_mission_briefing_creation():
    """MissionBriefing must accept target/scan_status."""
    from tui.welcome import MissionBriefing
    m = MissionBriefing(target="example.com", scan_status="READY", ai_status="READY")
    assert m.target == "example.com"


def test_build_welcome_renderable():
    """Welcome screen must render without target."""
    from tui.welcome import build_welcome_renderable, MissionBriefing
    welcome = build_welcome_renderable(
        mission=MissionBriefing(target="test.com")
    )
    assert welcome is not None


# ═══════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════

def test_build_static_renderable_all_themes():
    """Dashboard must render in all 5 themes."""
    from tui.themes import THEMES
    from tui.dashboard import build_static_renderable
    for name in THEMES.keys():
        rendered = build_static_renderable(
            theme_name=name, risk=42, target="test.com"
        )
        assert rendered is not None, f"{name} failed to render"


# ═══════════════════════════════════════════════════════════════════════════
# HUNT VIEW (integrated dashboard)
# ═══════════════════════════════════════════════════════════════════════════

def test_render_hunt_dashboard():
    """render_hunt_dashboard must produce Layout."""
    from tui.hunt_view import render_hunt_dashboard
    layout = render_hunt_dashboard(
        target="test.com",
        findings=[],
        risk_score=0,
        risk_level="None",
        theme_name="DEFAULT",
    )
    assert layout is not None


def test_render_launcher_layout_all_themes():
    """render_launcher_layout must work for all themes."""
    from tui.themes import THEMES
    from tui.hunt_view import render_launcher_layout
    for name in THEMES.keys():
        layout = render_launcher_layout(theme_name=name, target="test.com", risk=50)
        assert layout is not None, f"{name} failed"


def test_render_banner():
    """render_banner must produce Text."""
    from tui.hunt_view import render_banner
    from tui.themes import THEMES
    for name in THEMES.keys():
        banner = render_banner(theme_name=name)
        assert banner is not None


# ═══════════════════════════════════════════════════════════════════════════
# EXPORT MODULE
# ═══════════════════════════════════════════════════════════════════════════

def test_export_to_html():
    """Export to HTML should create a valid HTML file."""
    from tui.export import export_to_html, collect_dashboard_data
    import tempfile
    import os
    
    # Create test data
    test_data = {
        "target": "test.example.com",
        "risk_score": 75,
        "risk_level": "high",
        "total_findings": 3,
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
        "info": 0,
        "findings": [
            {"title": "SQL Injection", "severity": "critical", "location": "/api/users"},
            {"title": "XSS Vulnerability", "severity": "high", "location": "/search"},
            {"title": "Open Redirect", "severity": "medium", "location": "/redirect"},
        ],
    }
    
    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
        output_path = f.name
    
    try:
        result = export_to_html(test_data, output_path)
        assert os.path.exists(result)
        content = open(result).read()
        assert "ELENGENIX" in content
        assert "test.example.com" in content
        assert "SQL Injection" in content
    finally:
        os.unlink(output_path)


def test_export_to_json():
    """Export to JSON should create a valid JSON file."""
    from tui.export import export_to_json
    import tempfile
    import os
    import json
    
    test_data = {
        "target": "test.example.com",
        "risk_score": 50,
        "findings": [],
    }
    
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        output_path = f.name
    
    try:
        result = export_to_json(test_data, output_path)
        assert os.path.exists(result)
        data = json.load(open(result))
        assert data["target"] == "test.example.com"
        assert data["risk_score"] == 50
    finally:
        os.unlink(output_path)


def test_export_to_markdown():
    """Export to Markdown should create a valid Markdown file."""
    from tui.export import export_to_markdown
    import tempfile
    import os
    
    test_data = {
        "target": "test.example.com",
        "risk_score": 60,
        "total_findings": 2,
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
        "info": 0,
        "findings": [
            {"title": "XSS", "severity": "high", "location": "/search"},
            {"title": "Info Leak", "severity": "medium", "location": "/api"},
        ],
    }
    
    with tempfile.NamedTemporaryFile(suffix='.md', delete=False) as f:
        output_path = f.name
    
    try:
        result = export_to_markdown(test_data, output_path)
        assert os.path.exists(result)
        content = open(result).read()
        assert "test.example.com" in content
        assert "XSS" in content
    finally:
        os.unlink(output_path)


def test_collect_dashboard_data():
    """collect_dashboard_data should aggregate findings correctly."""
    from tui.export import collect_dashboard_data
    
    class MockFinding:
        def __init__(self, title, severity, location=""):
            self.title = title
            self.severity = severity
            self.location = location
            self.description = ""
            self.timestamp = "2024-01-01T00:00:00"
    
    findings = [
        MockFinding("Critical Vuln", "Critical"),
        MockFinding("High Vuln", "High"),
        MockFinding("Medium Vuln", "Medium"),
        MockFinding("Low Vuln", "Low"),
    ]
    
    data = collect_dashboard_data(
        target="example.com",
        findings=findings,
        risk_score=85,
    )
    
    assert data["target"] == "example.com"
    assert data["risk_score"] == 85
    assert data["total_findings"] == 4
    assert data["critical"] == 1
    assert data["high"] == 1
    assert data["medium"] == 1
    assert data["low"] == 1


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
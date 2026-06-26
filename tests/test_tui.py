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
    """All 9 themes must be defined."""
    from tui.themes import THEMES, get_theme
    assert "DEFAULT" in THEMES
    assert "CYBERPUNK" in THEMES
    assert "MATRIX" in THEMES
    assert "STEALTH" in THEMES
    assert "SYNTHWAVE" in THEMES
    assert "OCEAN" in THEMES
    assert "FOREST" in THEMES
    assert "SUNSET" in THEMES
    assert "ARCTIC" in THEMES
    assert len(THEMES) >= 9


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


# ═══════════════════════════════════════════════════════════════════════════
# SCAN PROGRESS
# ═══════════════════════════════════════════════════════════════════════════

def test_scan_progress_widget_creation():
    """ScanProgressWidget should create correctly."""
    from tui.scan_progress import ScanProgressWidget
    widget = ScanProgressWidget()
    assert widget.scan is None


def test_scan_progress_widget_start():
    """ScanProgressWidget should start scan correctly."""
    from tui.scan_progress import ScanProgressWidget
    widget = ScanProgressWidget()
    widget.start_scan("example.com", "Full Scan")
    assert widget.scan is not None
    assert widget.scan.target == "example.com"
    assert len(widget.scan.phases) > 0


def test_scan_progress_widget_update():
    """ScanProgressWidget should update phases correctly."""
    from tui.scan_progress import ScanProgressWidget
    widget = ScanProgressWidget()
    widget.start_scan("example.com", "Full Scan")
    widget.update_phase("Recon", progress=0.5, findings=3)
    assert widget.scan.phases[0].progress == 0.5
    assert widget.scan.phases[0].findings_count == 3


def test_scan_progress_widget_render():
    """ScanProgressWidget should render correctly."""
    from tui.scan_progress import ScanProgressWidget
    widget = ScanProgressWidget()
    widget.start_scan("example.com", "Full Scan")
    widget.update_phase("Recon", progress=0.5, findings=3)
    panel = widget.render()
    assert panel is not None


def test_scan_progress_standalone():
    """render_scan_progress should work as standalone."""
    from tui.scan_progress import render_scan_progress
    panel = render_scan_progress(
        target="example.com",
        scan_type="Full Scan",
        progress=0.5,
        phases=[("Recon", 1.0, 5), ("Scanning", 0.5, 3)],
        findings_total=8,
        elapsed=30.0,
    )
    assert panel is not None


# ═══════════════════════════════════════════════════════════════════════════
# FINDINGS DISPLAY
# ═══════════════════════════════════════════════════════════════════════════

def test_findings_display_creation():
    """FindingsDisplay should create correctly."""
    from tui.findings_display import FindingsDisplay
    display = FindingsDisplay()
    assert len(display.findings) == 0


def test_findings_display_add_finding():
    """FindingsDisplay should add findings correctly."""
    from tui.findings_display import FindingsDisplay, Finding
    display = FindingsDisplay()
    finding = Finding(
        id="1",
        title="SQL Injection",
        severity="critical",
        category="sqli",
        location="/api/users",
    )
    display.add_finding(finding)
    assert len(display.findings) == 1


def test_findings_display_sort():
    """FindingsDisplay should sort correctly."""
    from tui.findings_display import FindingsDisplay, Finding
    display = FindingsDisplay()
    display.add_finding(Finding(id="1", title="Low", severity="low", category="xss", location="/"))
    display.add_finding(Finding(id="2", title="Critical", severity="critical", category="sqli", location="/"))
    display.add_finding(Finding(id="3", title="Medium", severity="medium", category="ssrf", location="/"))
    
    display.set_sort("severity")
    filtered = display.get_filtered_sorted()
    assert filtered[0].severity == "critical"
    assert filtered[-1].severity == "low"


def test_findings_display_filter():
    """FindingsDisplay should filter correctly."""
    from tui.findings_display import FindingsDisplay, Finding, FindingFilter
    display = FindingsDisplay()
    display.add_finding(Finding(id="1", title="Low", severity="low", category="xss", location="/"))
    display.add_finding(Finding(id="2", title="Critical", severity="critical", category="sqli", location="/"))
    
    display.set_filter(FindingFilter(severities=["critical"]))
    filtered = display.get_filtered_sorted()
    assert len(filtered) == 1
    assert filtered[0].severity == "critical"


def test_findings_display_render():
    """FindingsDisplay should render correctly."""
    from tui.findings_display import FindingsDisplay, Finding
    display = FindingsDisplay()
    display.add_finding(Finding(id="1", title="SQL Injection", severity="critical", category="sqli", location="/api"))
    panel = display.render()
    assert panel is not None


def test_findings_display_statistics():
    """FindingsDisplay should calculate statistics correctly."""
    from tui.findings_display import FindingsDisplay, Finding
    display = FindingsDisplay()
    display.add_finding(Finding(id="1", title="A", severity="critical", category="sqli", location="/"))
    display.add_finding(Finding(id="2", title="B", severity="high", category="xss", location="/"))
    display.add_finding(Finding(id="3", title="C", severity="low", category="info", location="/"))
    
    stats = display.get_statistics()
    assert stats["critical"] == 1
    assert stats["high"] == 1
    assert stats["low"] == 1
    assert stats["total"] == 3


def test_render_findings_table_standalone():
    """render_findings_table should work as standalone."""
    from tui.findings_display import render_findings_table, Finding
    findings = [
        Finding(id="1", title="SQL Injection", severity="critical", category="sqli", location="/api"),
        Finding(id="2", title="XSS", severity="high", category="xss", location="/search"),
    ]
    panel = render_findings_table(findings)
    assert panel is not None


def test_render_finding_detail_standalone():
    """render_finding_detail should work as standalone."""
    from tui.findings_display import render_finding_detail, Finding
    finding = Finding(
        id="1",
        title="SQL Injection",
        severity="critical",
        category="sqli",
        location="/api/users",
        description="SQL injection in user parameter",
        cvss_score=9.8,
        cve_id="CVE-2024-12345",
    )
    panel = render_finding_detail(finding)
    assert panel is not None


# ═══════════════════════════════════════════════════════════════════════════
# KEYBOARD SHORTCUTS
# ═══════════════════════════════════════════════════════════════════════════

def test_keyboard_shortcut_manager_creation():
    """KeyboardShortcutManager should create correctly."""
    from tui.keyboard_shortcuts import KeyboardShortcutManager
    manager = KeyboardShortcutManager()
    assert len(manager.shortcuts) == 0


def test_keyboard_shortcut_register():
    """KeyboardShortcutManager should register shortcuts correctly."""
    from tui.keyboard_shortcuts import KeyboardShortcutManager, ShortcutCategory
    manager = KeyboardShortcutManager()
    manager.register("Ctrl+S", "Save", "save", ShortcutCategory.ACTION)
    assert len(manager.shortcuts) == 1
    assert manager.shortcuts[0].key == "Ctrl+S"


def test_keyboard_shortcut_get_action():
    """KeyboardShortcutManager should get action correctly."""
    from tui.keyboard_shortcuts import KeyboardShortcutManager, ShortcutCategory
    manager = KeyboardShortcutManager()
    manager.register("Ctrl+S", "Save", "save", ShortcutCategory.ACTION)
    action = manager.get_action("Ctrl+S")
    assert action == "save"


def test_keyboard_shortcut_execute():
    """KeyboardShortcutManager should execute action correctly."""
    from tui.keyboard_shortcuts import KeyboardShortcutManager, ShortcutCategory
    manager = KeyboardShortcutManager()
    manager.register("Ctrl+S", "Save", "save", ShortcutCategory.ACTION)
    
    executed = []
    manager.register_handler("save", lambda: executed.append(True))
    
    result = manager.execute("Ctrl+S")
    assert result is True
    assert len(executed) == 1


def test_keyboard_shortcut_render_help():
    """KeyboardShortcutManager should render help correctly."""
    from tui.keyboard_shortcuts import KeyboardShortcutManager, ShortcutCategory
    manager = KeyboardShortcutManager()
    manager.register("Ctrl+S", "Save", "save", ShortcutCategory.ACTION)
    manager.register("F1", "Help", "help", ShortcutCategory.VIEW)
    
    panel = manager.render_help()
    assert panel is not None


def test_create_default_shortcut_manager():
    """create_default_shortcut_manager should create manager with defaults."""
    from tui.keyboard_shortcuts import create_default_shortcut_manager
    manager = create_default_shortcut_manager()
    assert len(manager.shortcuts) > 0


def test_render_shortcuts_help_standalone():
    """render_shortcuts_help should work as standalone."""
    from tui.keyboard_shortcuts import render_shortcuts_help
    panel = render_shortcuts_help()
    assert panel is not None


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
"""test_tui_components.py - Smoke tests for Elengenix TUI components.

The tests in this module are deliberately lightweight: they exercise
imports, class construction, and the pure-Python helpers (easing
functions, fuzzy match, theme math) without booting a full Textual app.
This keeps the test suite fast and free of screenshot dependencies.

Run with:
    cd /mnt/data/Elengenix && source venv/bin/activate \\
        && python3 -m pytest tests/test_tui_components.py -v
    # or
    cd /mnt/data/Elengenix && source venv/bin/activate \\
        && python3 tests/test_tui_components.py
"""

from __future__ import annotations

import math
import os
import sys
from datetime import datetime
from io import StringIO

# Ensure the project root is on sys.path.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# ---------------------------------------------------------------------------
# Imports - confirm every public module loads without error
# ---------------------------------------------------------------------------


def test_animations_import():
    """Animations module exports its public classes."""
    from tui.animations import (
        Easing,
        AnimatedCounter,
        AnimatedProgress,
        ParticleField,
        FadeTransition,
        GlitchEffect,
        WaveAnimation,
        animated_text,
    )
    assert Easing is not None
    assert AnimatedCounter is not None
    assert AnimatedProgress is not None
    assert ParticleField is not None
    assert FadeTransition is not None
    assert GlitchEffect is not None
    assert WaveAnimation is not None
    assert animated_text is not None
    print("[OK] test_animations_import")


def test_themes_import():
    """Themes module exports THEMES dict and ThemeManager."""
    from tui.themes import THEMES, ThemeManager, get_theme, lerp_color, gradient_stops
    assert isinstance(THEMES, dict)
    assert "DEFAULT" in THEMES
    assert "CYBERPUNK" in THEMES
    assert "MATRIX" in THEMES
    assert "STEALTH" in THEMES
    assert "SYNTHWAVE" in THEMES
    for name in THEMES:
        for token in ("primary", "bg_dark", "text", "gradient_1", "gradient_2"):
            assert token in THEMES[name], f"theme {name} missing {token}"
    assert ThemeManager is not None
    assert get_theme("MATRIX")["primary"].startswith("#")
    assert lerp_color("#000000", "#ffffff", 0.5) == "#808080"
    assert len(gradient_stops(["#ff0000", "#0000ff"], 5)) == 5
    print("[OK] test_themes_import")


def test_visualizations_import():
    """Visualizations module exports every chart / diagram class."""
    from tui.visualizations import (
        VulnerabilityHeatmap,
        FindingTimeline,
        ExploitChainDiagram,
        AttackSurfaceMap,
        RiskGauge,
        SeverityChart,
    )
    assert VulnerabilityHeatmap is not None
    assert FindingTimeline is not None
    assert ExploitChainDiagram is not None
    assert AttackSurfaceMap is not None
    assert RiskGauge is not None
    assert SeverityChart is not None
    print("[OK] test_visualizations_import")


def test_dashboard_import():
    """Dashboard module exports ThreatDashboard."""
    from tui.dashboard import ThreatDashboard, build_static_renderable
    assert ThreatDashboard is not None
    assert build_static_renderable is not None
    print("[OK] test_dashboard_import")


def test_welcome_import():
    """Welcome module exports WelcomeScreen + helpers."""
    from tui.welcome import (
        WelcomeScreen,
        ascii_logo,
        build_welcome_renderable,
        MissionBriefing,
        RecentActivity,
    )
    assert WelcomeScreen is not None
    assert ascii_logo is not None
    assert build_welcome_renderable is not None
    assert MissionBriefing is not None
    assert RecentActivity is not None
    print("[OK] test_welcome_import")


def test_command_palette_import():
    """Command palette module exports the modal + helpers."""
    from tui.command_palette import (
        CommandPalette,
        Command,
        DEFAULT_COMMANDS,
        fuzzy_match,
        fuzzy_score,
    )
    assert CommandPalette is not None
    assert Command is not None
    assert len(DEFAULT_COMMANDS) > 0
    assert fuzzy_match is not None
    assert fuzzy_score is not None
    print("[OK] test_command_palette_import")


def test_top_level_package_import():
    """The tui package re-exports every public symbol."""
    import tui
    expected = {
        "Easing", "AnimatedCounter", "AnimatedProgress", "ParticleField",
        "FadeTransition", "GlitchEffect", "WaveAnimation", "animated_text",
        "THEMES", "ThemeManager", "get_manager", "get_theme", "lerp_color",
        "gradient_stops", "CYBERPUNK", "MATRIX", "STEALTH", "SYNTHWAVE",
        "VulnerabilityHeatmap", "FindingTimeline", "ExploitChainDiagram",
        "AttackSurfaceMap", "RiskGauge", "SeverityChart",
        "ThreatDashboard", "build_dashboard_renderable",
        "ascii_logo", "WelcomeScreen", "build_welcome_renderable",
        "MissionBriefing", "RecentActivity",
        "Command", "CommandPalette", "DEFAULT_COMMANDS",
        "fuzzy_match", "fuzzy_score", "render_palette", "build_palette",
    }
    missing = expected - set(tui.__all__)
    assert not missing, f"Missing exports: {missing}"
    # Also confirm each name is importable from the package.
    for name in expected:
        assert hasattr(tui, name), f"tui.{name} missing"
    print("[OK] test_top_level_package_import")


# ---------------------------------------------------------------------------
# Easing functions - pure math, easy to test
# ---------------------------------------------------------------------------


def test_easing_endpoints():
    """All easings return 0 at t=0 and 1 at t=1."""
    from tui.animations import Easing
    names = Easing.names()
    assert len(names) >= 10
    for name in names:
        a = Easing.apply(name, 0.0)
        b = Easing.apply(name, 1.0)
        # Some easings (e.g. elastic) may return 0 or 1 exactly, others may
        # be close (within 1e-6) - both are acceptable.
        assert abs(a) < 1e-6, f"{name}(0) = {a}"
        assert abs(b - 1.0) < 1e-6, f"{name}(1) = {b}"
    print("[OK] test_easing_endpoints")


def test_easing_midpoint_monotonic():
    """Most easings are non-decreasing on [0, 1] (bounce/back variants excluded)."""
    from tui.animations import Easing
    # Bounce / back / elastic variants intentionally overshoot or oscillate
    # and are excluded from the monotonicity check.
    skip = {
        "ease_in_bounce",
        "ease_out_bounce",
        "ease_in_elastic",
        "ease_out_elastic",
        "ease_out_back",
        "ease_in_out_back",
    }
    samples = [i / 20.0 for i in range(21)]
    for name in Easing.names():
        if name in skip:
            continue
        values = [Easing.apply(name, t) for t in samples]
        # Allow a tiny epsilon for numerical noise.
        for a, b in zip(values, values[1:]):
            assert b >= a - 1e-6, f"{name} not monotonic: {values}"
    print("[OK] test_easing_midpoint_monotonic")


def test_easing_apply_unknown():
    """Unknown easing name falls back to linear."""
    from tui.animations import Easing
    assert Easing.apply("nonexistent", 0.4) == 0.4
    assert Easing.apply("nonexistent", 0.0) == 0.0
    assert Easing.apply("nonexistent", 1.0) == 1.0
    print("[OK] test_easing_apply_unknown")


def test_easing_lerp():
    """``Easing.lerp`` interpolates with the chosen easing."""
    from tui.animations import Easing
    assert Easing.lerp(0, 100, 0.0) == 0
    assert Easing.lerp(0, 100, 1.0) == 100
    assert 40 <= Easing.lerp(0, 100, 0.5, "ease_in_out_cubic") <= 60
    print("[OK] test_easing_lerp")


# ---------------------------------------------------------------------------
# Theme math
# ---------------------------------------------------------------------------


def test_lerp_color():
    """``lerp_color`` interpolates between two hex colours."""
    from tui.themes import lerp_color
    assert lerp_color("#000000", "#ffffff", 0.0) == "#000000"
    assert lerp_color("#000000", "#ffffff", 1.0) == "#ffffff"
    assert lerp_color("#000000", "#ffffff", 0.5) == "#808080"
    # Out-of-range values are clamped.
    assert lerp_color("#000000", "#ffffff", -1.0) == "#000000"
    assert lerp_color("#000000", "#ffffff", 2.0) == "#ffffff"
    print("[OK] test_lerp_color")


def test_gradient_stops():
    """``gradient_stops`` returns the right number of colour samples."""
    from tui.themes import gradient_stops
    stops = gradient_stops(["#ff0000", "#00ff00", "#0000ff"], 7)
    assert len(stops) == 7
    assert stops[0] == "#ff0000"
    assert stops[-1] == "#0000ff"
    # Single colour case.
    assert gradient_stops(["#aaaaaa"], 4) == ["#aaaaaa"] * 4
    # Zero steps.
    assert gradient_stops(["#ffffff"], 0) == []
    print("[OK] test_gradient_stops")


def test_theme_manager_set_and_query():
    """ThemeManager can switch themes and report colours."""
    from tui.themes import ThemeManager
    mgr = ThemeManager("DEFAULT")
    assert mgr.active == "DEFAULT"
    assert mgr.current("primary").startswith("#")
    mgr.set_theme("MATRIX")
    assert mgr.active == "MATRIX"
    # The matrix primary is green.
    assert "ff" in mgr.current("primary").lower()
    print("[OK] test_theme_manager_set_and_query")


def test_theme_manager_listen():
    """ThemeManager notifies listeners on each transition tick."""
    from tui.themes import ThemeManager
    mgr = ThemeManager("DEFAULT")
    calls = []

    def listener(m):
        calls.append(m.active)

    mgr.register_listener(listener)
    mgr.transition_to("CYBERPUNK", duration=0.05)
    # Run a few manual ticks.
    for _ in range(10):
        mgr.tick()
    assert calls, "listener was never called"
    assert calls[-1] == "CYBERPUNK"
    print("[OK] test_theme_manager_listen")


# ---------------------------------------------------------------------------
# Visualizations - render to an in-memory console
# ---------------------------------------------------------------------------


def _capture(renderable, width: int = 100) -> str:
    """Render a Rich renderable into a string for assertion."""
    from rich.console import Console
    buf = StringIO()
    console = Console(file=buf, width=width, record=False, force_terminal=True, color_system="truecolor")
    console.print(renderable)
    return buf.getvalue()


def test_risk_gauge_render():
    """RiskGauge renders without error and shows the value."""
    from tui.visualizations import RiskGauge
    gauge = RiskGauge(value=73, max_value=100, label="RISK", width=30, height=8)
    out = _capture(gauge.render())
    # The gauge should produce *some* output.
    assert len(out) > 0
    assert "RISK" in out
    # Numeric value 73 is shown.
    assert "73" in out
    print("[OK] test_risk_gauge_render")


def test_severity_chart_render():
    """SeverityChart renders all severity buckets."""
    from tui.visualizations import SeverityChart
    chart = SeverityChart(critical=2, high=5, medium=8, low=12, info=3)
    out = _capture(chart.render())
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert sev in out, f"{sev} missing from chart"
    print("[OK] test_severity_chart_render")


def test_heatmap_render():
    """VulnerabilityHeatmap renders cells with the configured endpoints."""
    from tui.visualizations import VulnerabilityHeatmap
    heat = VulnerabilityHeatmap(
        endpoints=["api.example.com", "admin.example.com"],
        vuln_types=["XSS", "IDOR", "SQLi"],
    )
    heat.set("api.example.com", "XSS", "high", 1)
    heat.set("admin.example.com", "SQLi", "critical", 2)
    out = _capture(heat.render(), width=120)
    assert "api.example.com" in out
    assert "admin.example.com" in out
    assert "XSS" in out
    print("[OK] test_heatmap_render")


def test_finding_timeline_render():
    """FindingTimeline lists findings newest-first by default."""
    from tui.visualizations import FindingTimeline
    timeline = FindingTimeline()
    timeline.add("Reflected XSS", "high", "/search?q=", description="Sample")
    timeline.add("Verbose error", "low", "/api", description="Stack trace")
    out = _capture(timeline.render())
    assert "Reflected XSS" in out
    assert "Verbose error" in out
    print("[OK] test_finding_timeline_render")


def test_exploit_chain_render():
    """ExploitChainDiagram renders every step and an objective."""
    from tui.visualizations import ExploitChainDiagram
    chain = ExploitChainDiagram(title="auth -> admin")
    chain.add("Anonymous access", severity="info", success=True)
    chain.add("IDOR on /user/:id", severity="high", success=True)
    chain.add("Privilege escalation", severity="critical", success=True)
    out = _capture(chain.render())
    assert "Anonymous access" in out
    assert "IDOR" in out
    assert "Privilege escalation" in out
    assert "OBJECTIVE" in out
    print("[OK] test_exploit_chain_render")


def test_attack_surface_render():
    """AttackSurfaceMap renders a tree of endpoints."""
    from tui.visualizations import AttackSurfaceMap
    surface = AttackSurfaceMap()
    surface.add("/api/users", "GET", "low")
    surface.add("/api/users/:id", "GET", "medium")
    surface.add("/admin/login", "POST", "high")
    out = _capture(surface.render())
    assert "/api" in out
    assert "/admin" in out
    print("[OK] test_attack_surface_render")


# ---------------------------------------------------------------------------
# Welcome
# ---------------------------------------------------------------------------


def test_ascii_logo():
    """``ascii_logo`` returns a Rich Text containing the ELENGENIX wordmark."""
    from tui.welcome import ascii_logo, LOGO_LINES
    from rich.text import Text
    logo = ascii_logo()
    assert isinstance(logo, Text)
    plain = logo.plain
    # The wordmark is ASCII art, so the individual letter shapes (slashes,
    # underscores, vertical bars) should be present, along with the expected
    # number of newline-separated lines.
    for line in LOGO_LINES:
        for ch in line:
            if not ch.isspace():
                assert ch in plain, f"missing char {ch!r} from logo"
    # Right number of lines.
    assert plain.count("\n") == len(LOGO_LINES) - 1
    print("[OK] test_ascii_logo")


def test_mission_briefing_render():
    """MissionBriefing renders target/scan/ai fields."""
    from tui.welcome import MissionBriefing
    brief = MissionBriefing(target="example.com", scan_status="RUNNING", ai_status="READY", operators=2)
    out = _capture(brief.render())
    assert "example.com" in out
    assert "RUNNING" in out
    assert "READY" in out
    print("[OK] test_mission_briefing_render")


def test_recent_activity_render():
    """RecentActivity renders appended entries."""
    from tui.welcome import RecentActivity
    act = RecentActivity()
    act.add("12:00:00", "SCAN", "Recon finished")
    act.add("12:01:30", "INFO", "5 hosts found")
    out = _capture(act.render())
    assert "Recon finished" in out
    assert "5 hosts found" in out
    print("[OK] test_recent_activity_render")


def test_build_welcome_renderable():
    """``build_welcome_renderable`` produces a Rich Group with all sections."""
    from tui.welcome import build_welcome_renderable, MissionBriefing, RecentActivity
    from rich.console import Group
    mission = MissionBriefing(target="demo.example.com", scan_status="IDLE", ai_status="READY")
    activity = RecentActivity()
    activity.add("now", "INFO", "Welcome to Elengenix")
    out = build_welcome_renderable(mission=mission, activity=activity, theme_name="MATRIX", width=100)
    assert isinstance(out, Group)
    rendered = _capture(out, width=120)
    assert "demo.example.com" in rendered
    assert "Welcome to Elengenix" in rendered
    assert "MISSION BRIEFING" in rendered
    assert "QUICK START" in rendered
    print("[OK] test_build_welcome_renderable")


# ---------------------------------------------------------------------------
# Command palette
# ---------------------------------------------------------------------------


def test_fuzzy_match():
    """``fuzzy_match`` returns scored results in descending order."""
    from tui.command_palette import fuzzy_match, fuzzy_score
    # Exact match should score highest.
    s_exact = fuzzy_score("scan", "scan")
    s_partial = fuzzy_score("scn", "scan")
    assert s_exact >= s_partial
    # Non-match returns 0 score.
    assert fuzzy_score("xyz", "scan") == 0
    # Multi-candidate lookup returns indices and is sorted.
    results = fuzzy_match("scn", ["scan", "recon", "quit", "score"])
    assert results, "no matches for 'scn'"
    indices = [i for _, i in results]
    assert 0 in indices or 3 in indices  # 'scan' or 'score' should match
    print("[OK] test_fuzzy_match")


def test_command_palette_state_render():
    """The palette renders to a Rich panel that includes results."""
    from tui.command_palette import CommandPalette, _PaletteState, DEFAULT_COMMANDS, render_palette
    state = _PaletteState(query="scan")
    panel = render_palette(DEFAULT_COMMANDS, state, width=80)
    out = _capture(panel, width=100)
    # We should see at least one of the scan-related commands.
    assert "Scan" in out or "Recon" in out
    print("[OK] test_command_palette_state_render")


def test_default_commands_have_unique_ids():
    """DEFAULT_COMMANDS has no duplicate ids."""
    from tui.command_palette import DEFAULT_COMMANDS
    ids = [c.id for c in DEFAULT_COMMANDS]
    assert len(set(ids)) == len(ids), "duplicate command ids"
    print("[OK] test_default_commands_have_unique_ids")


# ---------------------------------------------------------------------------
# Animation helpers
# ---------------------------------------------------------------------------


def test_animated_counter_static_render():
    """AnimatedCounter.render_value produces a Rich Text with the formatted value."""
    from tui.animations import AnimatedCounter
    from rich.text import Text
    text = AnimatedCounter.render_value(value=42.7, color="#ffffff", precision=1)
    assert isinstance(text, Text)
    assert "42" in text.plain
    print("[OK] test_animated_counter_static_render")


def test_glitch_effect_deterministic():
    """GlitchEffect.jitter with the same seed produces the same output."""
    from tui.animations import GlitchEffect
    a = GlitchEffect.jitter("ELENGENIX", intensity=0.5, seed=42)
    b = GlitchEffect.jitter("ELENGENIX", intensity=0.5, seed=42)
    assert a == b
    print("[OK] test_glitch_effect_deterministic")


def test_wave_animation_render():
    """WaveAnimation.render returns a Rich Text of the right length."""
    from tui.animations import WaveAnimation
    from rich.text import Text
    text = WaveAnimation.render("HELLO", t=0.5)
    assert isinstance(text, Text)
    assert len(text.plain) == len("HELLO")
    print("[OK] test_wave_animation_render")


def test_fade_transition_render():
    """FadeTransition.render is empty at t=0 and full at t=1."""
    from tui.animations import FadeTransition
    from rich.text import Text
    text0 = FadeTransition.render("HELLO", t=0.0)
    text1 = FadeTransition.render("HELLO", t=1.0)
    assert isinstance(text0, Text) and isinstance(text1, Text)
    assert text1.plain == "HELLO"
    # At t=0 the visible content is masked (length still matches input).
    assert len(text0.plain) == len("HELLO")
    print("[OK] test_fade_transition_render")


def test_particle_field_init():
    """ParticleField can be constructed and seeded for each mode."""
    from tui.animations import ParticleField
    for mode in ("matrix", "rain", "glitch", "snow", "stars", "fire", "scan", "pulse"):
        field = ParticleField(mode=mode, width=20, height=8, color="#ff2222", accent="#888888")
        field._init_particles()
        # Internal particle list must be populated.
        assert field._particles, f"no particles for mode {mode}"
    print("[OK] test_particle_field_init")


# ---------------------------------------------------------------------------
# Dashboard helpers
# ---------------------------------------------------------------------------


def test_dashboard_static_renderable():
    """build_static_renderable produces a Rich Group containing the gauge + chart."""
    from tui.dashboard import build_static_renderable
    from rich.console import Group
    out = build_static_renderable(theme_name="CYBERPUNK", risk=42, target="example.com")
    assert isinstance(out, Group)
    text = _capture(out, width=140)
    assert "ELENGENIX" in text
    assert "example.com" in text
    print("[OK] test_dashboard_static_renderable")


# ---------------------------------------------------------------------------
# Direct execution
# ---------------------------------------------------------------------------


def _run_all() -> None:
    """Run every test_* function defined in this module."""
    tests = [
        v for k, v in sorted(globals().items())
        if k.startswith("test_") and callable(v)
    ]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"[FAIL] {t.__name__}: {exc!r}")
    print()
    print(f"=== {passed} passed, {failed} failed, {passed + failed} total ===")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    _run_all()

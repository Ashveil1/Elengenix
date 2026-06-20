"""tui - Premium TUI component library for Elengenix.

Public API
----------

Animations (tui.animations):
    * :class:`Easing` - collection of easing functions
    * :class:`AnimatedCounter` - smooth numeric counter widget
    * :class:`AnimatedProgress` - eased progress bar
    * :class:`ParticleField` - matrix / glitch / snow particle effects
    * :class:`FadeTransition` - text fade in/out
    * :class:`GlitchEffect` - text glitch / scramble
    * :class:`WaveAnimation` - sine-wave text reveal
    * :func:`animated_text` - dispatch helper

Themes (tui.themes):
    * :data:`THEMES` - the catalogue (DEFAULT, CYBERPUNK, MATRIX, STEALTH, SYNTHWAVE)
    * :class:`ThemeManager` - live theme switching with smooth transitions
    * :func:`get_theme`, :func:`get_manager` - convenience helpers
    * :func:`lerp_color`, :func:`gradient_stops` - colour math

Visualizations (tui.visualizations) - all Rich renderables:
    * :class:`VulnerabilityHeatmap` - endpoint x vuln-type matrix
    * :class:`FindingTimeline` - chronological finding list
    * :class:`ExploitChainDiagram` - attack chain visualisation
    * :class:`AttackSurfaceMap` - endpoint tree
    * :class:`RiskGauge` - radial speedometer
    * :class:`SeverityChart` - bar chart of severities

Dashboard (tui.dashboard):
    * :class:`ThreatDashboard` - composite real-time dashboard widget

Welcome (tui.welcome):
    * :func:`ascii_logo` - gradient ELENGENIX wordmark
    * :class:`WelcomeScreen` - full-screen Textual welcome widget
    * :class:`MissionBriefing`, :class:`RecentActivity` - data containers
    * :func:`build_welcome_renderable` - standalone Rich renderable

Command palette (tui.command_palette):
    * :class:`CommandPalette` - VSCode-style modal palette
    * :class:`Command` - command data class
    * :func:`fuzzy_match`, :func:`fuzzy_score` - fuzzy search
"""

from __future__ import annotations

# -- Animations --------------------------------------------------------------
from .animations import (
    Easing,
    AnimatedCounter,
    AnimatedProgress,
    ParticleField,
    FadeTransition,
    GlitchEffect,
    WaveAnimation,
    animated_text,
)

# -- Themes ------------------------------------------------------------------
from .themes import (
    THEMES,
    THEME_TOKENS,
    CYBERPUNK,
    MATRIX,
    STEALTH,
    SYNTHWAVE,
    DEFAULT,
    ThemeManager,
    get_manager,
    get_theme,
    lerp_color,
    gradient_stops,
)

# -- Visualizations ----------------------------------------------------------
from .visualizations import (
    SEVERITY_ORDER,
    SEVERITY_GLYPH,
    DEFAULT_SEVERITY_COLORS,
    VulnerabilityHeatmap,
    HeatmapCell,
    FindingTimeline,
    Finding,
    ExploitChainDiagram,
    ExploitStep,
    AttackSurfaceMap,
    Endpoint,
    RiskGauge,
    SeverityChart,
    render_text_panel,
)

# -- Dashboard ---------------------------------------------------------------
from .dashboard import (
    ThreatDashboard,
    SystemStats,
    Scan,
    Host,
    Finding as DashboardFinding,
    ThreatMarker,
    build_static_renderable as build_dashboard_renderable,
    run_demo as run_dashboard_demo,
)

# -- Welcome -----------------------------------------------------------------
from .welcome import (
    LOGO_LINES,
    ascii_logo,
    MissionBriefing,
    RecentActivity,
    QUICK_START_TILES,
    render_quick_start,
    build_welcome_renderable,
    WelcomeScreen,
)

# -- Command palette ---------------------------------------------------------
from .command_palette import (
    Command,
    CommandPalette,
    DEFAULT_COMMANDS,
    fuzzy_match,
    fuzzy_score,
    render_palette,
    build_palette,
)

__all__ = [
    # animations
    "Easing",
    "AnimatedCounter",
    "AnimatedProgress",
    "ParticleField",
    "FadeTransition",
    "GlitchEffect",
    "WaveAnimation",
    "animated_text",
    # themes
    "THEMES",
    "THEME_TOKENS",
    "CYBERPUNK",
    "MATRIX",
    "STEALTH",
    "SYNTHWAVE",
    "DEFAULT",
    "ThemeManager",
    "get_manager",
    "get_theme",
    "lerp_color",
    "gradient_stops",
    # visualizations
    "SEVERITY_ORDER",
    "SEVERITY_GLYPH",
    "DEFAULT_SEVERITY_COLORS",
    "VulnerabilityHeatmap",
    "HeatmapCell",
    "FindingTimeline",
    "Finding",
    "ExploitChainDiagram",
    "ExploitStep",
    "AttackSurfaceMap",
    "Endpoint",
    "RiskGauge",
    "SeverityChart",
    "render_text_panel",
    # dashboard
    "ThreatDashboard",
    "SystemStats",
    "Scan",
    "Host",
    "DashboardFinding",
    "ThreatMarker",
    "build_dashboard_renderable",
    "run_dashboard_demo",
    # welcome
    "LOGO_LINES",
    "ascii_logo",
    "MissionBriefing",
    "RecentActivity",
    "QUICK_START_TILES",
    "render_quick_start",
    "build_welcome_renderable",
    "WelcomeScreen",
    # command palette
    "Command",
    "CommandPalette",
    "DEFAULT_COMMANDS",
    "fuzzy_match",
    "fuzzy_score",
    "render_palette",
    "build_palette",
]

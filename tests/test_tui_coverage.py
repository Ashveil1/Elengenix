"""
test_tui_coverage.py - Comprehensive tests for TUI modules and ui_components.py.

Covers:
    - ui_components.py: all print_*, banners, cards, tables, menus, sidebar, etc.
    - tui/themes.py: ThemeManager, Easing, color utilities, all 9 themes
    - tui/visualizations.py: Heatmap, Timeline, ExploitChain, AttackSurface, RiskGauge, SeverityChart
    - tui/welcome.py: ascii_logo, MissionBriefing, RecentActivity, build_welcome_renderable
    - tui/dashboard.py: dataclasses, build_static_renderable, ThreatDashboard
    - tui/main_menu.py: data constants, render_*_menu functions
"""

import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ============================================================================
# ui_components.py tests
# ============================================================================


class TestUiComponents:
    """Tests for ui_components.py module."""

    def test_colors_dict(self):
        """COLORS dict has expected keys and all values are strings."""
        from ui_components import COLORS
        assert isinstance(COLORS, dict)
        assert "primary" in COLORS
        assert "secondary" in COLORS
        assert "accent" in COLORS
        assert "success" in COLORS
        assert "error" in COLORS
        assert "warning" in COLORS
        assert "info" in COLORS
        assert "muted" in COLORS
        assert "high" in COLORS
        assert "medium" in COLORS
        assert "low" in COLORS
        assert "border" in COLORS
        assert "bg_dark" in COLORS
        assert "bg_card" in COLORS
        assert "gradient_1" in COLORS
        assert "gradient_2" in COLORS
        for k, v in COLORS.items():
            assert isinstance(v, str), f"COLORS[{k}] is not a string"

    def test_styles_dict(self):
        """STYLES dict has expected keys and Rich Style values."""
        from ui_components import STYLES
        from rich.style import Style
        assert isinstance(STYLES, dict)
        for key in ["title", "subtitle", "success", "error", "warning", "info",
                     "command", "high", "medium", "low", "accent", "heading"]:
            assert key in STYLES, f"STYLES missing key: {key}"
            assert isinstance(STYLES[key], Style), f"STYLES[{key}] is not a Style"

    def test_markers_dict(self):
        """MARKERS dict has expected keys."""
        from ui_components import MARKERS
        assert MARKERS["ok"] == "[OK]"
        assert MARKERS["fail"] == "[FAIL]"
        assert MARKERS["warn"] == "[WARN]"
        assert MARKERS["info"] == "[INFO]"
        assert MARKERS["run"] == "[RUN]"
        assert MARKERS["skip"] == "[SKIP]"
        assert MARKERS["arrow"] == "[->]"

    def test_console_singleton(self):
        """console is a Rich Console instance with force_terminal."""
        from ui_components import console
        from rich.console import Console
        assert isinstance(console, Console)

    def test_console_width(self):
        """Console width is at least 100."""
        from ui_components import console
        assert console.width >= 100

    @patch("ui_components.console")
    def test_print_success(self, mock_console):
        """print_success outputs [OK] marker."""
        from ui_components import print_success
        print_success("test passed")
        mock_console.print.assert_called_once()
        args = mock_console.print.call_args[0][0]
        assert "[OK]" in args
        assert "test passed" in args

    @patch("ui_components.console")
    def test_print_error(self, mock_console):
        """print_error outputs [FAIL] marker and strips Rich tags."""
        from ui_components import print_error
        print_error("something broke [bold]now[/bold]")
        mock_console.print.assert_called_once()
        args = mock_console.print.call_args[0][0]
        assert "[FAIL]" in args
        assert "something broke" in args

    @patch("ui_components.console")
    def test_print_warning(self, mock_console):
        """print_warning outputs [WARN] marker."""
        from ui_components import print_warning
        print_warning("caution")
        mock_console.print.assert_called_once()
        args = mock_console.print.call_args[0][0]
        assert "[WARN]" in args
        assert "caution" in args

    @patch("ui_components.console")
    def test_print_info(self, mock_console):
        """print_info outputs [INFO] marker."""
        from ui_components import print_info
        print_info("fyi")
        mock_console.print.assert_called_once()
        args = mock_console.print.call_args[0][0]
        assert "[INFO]" in args
        assert "fyi" in args

    @patch("ui_components.console")
    def test_print_command(self, mock_console):
        """print_command outputs command in highlighted style."""
        from ui_components import print_command
        print_command("nmap -sV target.com")
        mock_console.print.assert_called_once()
        args = mock_console.print.call_args[0][0]
        assert "nmap -sV target.com" in args

    @patch("ui_components.console")
    def test_print_step(self, mock_console):
        """print_step outputs step with status marker."""
        from ui_components import print_step
        print_step(1, "running step", "running")
        args = mock_console.print.call_args[0][0]
        assert "Step 1" in args
        assert "running step" in args
        assert "[RUN]" in args

    @patch("ui_components.console")
    def test_print_step_done(self, mock_console):
        """print_step with status='done' shows [OK]."""
        from ui_components import print_step
        print_step(2, "finished", "done")
        args = mock_console.print.call_args[0][0]
        assert "[OK]" in args

    @patch("ui_components.console")
    def test_print_step_failed(self, mock_console):
        """print_step with status='failed' shows [FAIL]."""
        from ui_components import print_step
        print_step(3, "broke", "failed")
        args = mock_console.print.call_args[0][0]
        assert "[FAIL]" in args

    @patch("ui_components.console")
    def test_print_step_skipped(self, mock_console):
        """print_step with status='skipped' shows [SKIP]."""
        from ui_components import print_step
        print_step(4, "skipped step", "skipped")
        args = mock_console.print.call_args[0][0]
        assert "[SKIP]" in args

    @patch("ui_components.console")
    def test_print_step_unknown_status(self, mock_console):
        """print_step with unknown status defaults to [RUN]."""
        from ui_components import print_step
        print_step(5, "weird", "mystery")
        args = mock_console.print.call_args[0][0]
        assert "[RUN]" in args

    def test_severity_badge_info(self):
        """severity_badge returns styled badge for info."""
        from ui_components import severity_badge
        badge = severity_badge("info")
        assert "INFO" in badge

    def test_severity_badge_high(self):
        """severity_badge returns styled badge for high."""
        from ui_components import severity_badge
        badge = severity_badge("high")
        assert "HIGH" in badge

    def test_severity_badge_medium(self):
        """severity_badge returns styled badge for medium."""
        from ui_components import severity_badge
        badge = severity_badge("medium")
        assert "MEDIUM" in badge

    def test_severity_badge_low(self):
        """severity_badge returns styled badge for low."""
        from ui_components import severity_badge
        badge = severity_badge("low")
        assert "LOW" in badge

    def test_severity_badge_unknown(self):
        """severity_badge returns UNKNOWN for unrecognized severity."""
        from ui_components import severity_badge
        badge = severity_badge("unknown_severity")
        assert "UNKNOWN" in badge

    def test_severity_color(self):
        """severity_color returns correct colors for all levels."""
        from ui_components import severity_color
        assert severity_color("high") == "#ffffff"
        assert severity_color("medium") == "#888888"
        assert severity_color("low") == "#81C784"
        assert severity_color("info") == "#ffffff"
        assert severity_color("UNKNOWN") == "#ffffff"

    def test_create_status_table(self):
        """create_status_table returns a Rich Table."""
        from ui_components import create_status_table
        table = create_status_table("Test Title")
        assert isinstance(table, Table)

    def test_create_tools_table(self):
        """create_tools_table builds a table from tool list."""
        from ui_components import create_tools_table
        tools = [{"name": "tool_a", "desc": "desc a"}, {"name": "tool_b", "desc": "desc b"}]
        table = create_tools_table(tools)
        assert isinstance(table, Table)

    def test_create_doctor_table(self):
        """create_doctor_table builds a table from check results."""
        from ui_components import create_doctor_table
        checks = [
            {"name": "check1", "status": "ok", "details": "pass"},
            {"name": "check2", "status": "fail", "details": "broken"},
            {"name": "check3", "status": "warn", "details": "slow"},
            {"name": "check4", "status": "info", "details": "info"},
        ]
        table = create_doctor_table(checks)
        assert isinstance(table, Table)

    def test_create_doctor_table_unknown_status(self):
        """create_doctor_table handles unknown status gracefully."""
        from ui_components import create_doctor_table
        checks = [{"name": "x", "status": "unknown", "details": ""}]
        table = create_doctor_table(checks)
        assert isinstance(table, Table)

    def test_create_finding_table(self):
        """create_finding_table builds a table from findings."""
        from ui_components import create_finding_table
        findings = [
            {"severity": "high", "title": "XSS", "location": "/api", "description": "Found XSS"},
            {"severity": "low", "title": "Info leak", "location": "/", "description": "minor"},
        ]
        table = create_finding_table(findings)
        assert isinstance(table, Table)

    def test_create_finding_table_empty(self):
        """create_finding_table handles empty list."""
        from ui_components import create_finding_table
        table = create_finding_table([])
        assert isinstance(table, Table)

    def test_create_main_menu(self):
        """create_main_menu returns flat list of tuples."""
        from ui_components import create_main_menu
        menu = create_main_menu()
        assert isinstance(menu, list)
        assert len(menu) > 0
        assert menu[-1] == ("Exit", "Quit application", "exit")

    def test_create_arsenal_menu(self):
        """create_arsenal_menu returns list of tool dicts."""
        from ui_components import create_arsenal_menu
        arsenal = create_arsenal_menu()
        assert isinstance(arsenal, list)
        assert len(arsenal) > 0
        for tool in arsenal:
            assert "name" in tool
            assert "desc" in tool
            assert "file" in tool

    def test_format_menu_item(self):
        """format_menu_item returns a styled string."""
        from ui_components import format_menu_item
        result = format_menu_item(1, "Test", "Description")
        assert "Test" in result
        assert "Description" in result

    def test_show_spinner_returns_status(self):
        """show_spinner returns a context manager."""
        from ui_components import show_spinner
        spinner = show_spinner("Testing...")
        assert spinner is not None

    def test_show_progress_bar_returns_progress(self):
        """show_progress_bar returns a Progress instance."""
        from ui_components import show_progress_bar
        from rich.progress import Progress
        bar = show_progress_bar(100, "Test")
        assert isinstance(bar, Progress)

    @patch("ui_components.console")
    def test_show_card(self, mock_console):
        """show_card prints a Panel."""
        from ui_components import show_card
        show_card("Title", "Content")
        mock_console.print.assert_called()

    @patch("ui_components.console")
    def test_show_metric_card(self, mock_console):
        """show_metric_card prints a Panel."""
        from ui_components import show_metric_card
        show_metric_card("Label", "42", unit="items", icon="#", color="#ffffff")
        mock_console.print.assert_called()

    @patch("ui_components.console")
    def test_show_metric_card_no_unit_no_icon(self, mock_console):
        """show_metric_card works without unit and icon."""
        from ui_components import show_metric_card
        show_metric_card("Label", "42")
        mock_console.print.assert_called()

    @patch("ui_components.console")
    def test_show_metric_row(self, mock_console):
        """show_metric_row prints a Panel with table."""
        from ui_components import show_metric_row
        metrics = [
            {"label": "A", "value": "1", "unit": "x"},
            {"label": "B", "value": "2"},
        ]
        show_metric_row(metrics)
        mock_console.print.assert_called()

    @patch("ui_components.console")
    def test_show_section(self, mock_console):
        """show_section prints title and optional subtitle."""
        from ui_components import show_section
        show_section("My Section", "subtitle text")
        assert mock_console.print.call_count >= 2

    @patch("ui_components.console")
    def test_show_section_no_subtitle(self, mock_console):
        """show_section prints without subtitle."""
        from ui_components import show_section
        show_section("My Section")
        assert mock_console.print.call_count >= 2

    @patch("ui_components.console")
    def test_show_subsection(self, mock_console):
        """show_subsection prints subsection."""
        from ui_components import show_subsection
        show_subsection("Sub")
        mock_console.print.assert_called()

    @patch("ui_components.console")
    def test_show_main_banner(self, mock_console):
        """show_main_banner prints ASCII art."""
        from ui_components import show_main_banner
        show_main_banner()
        assert mock_console.print.call_count > 5

    @patch("ui_components.console")
    def test_show_cli_banner_default(self, mock_console):
        """show_cli_banner with default mode."""
        from ui_components import show_cli_banner
        show_cli_banner()
        assert mock_console.print.call_count >= 3

    @patch("ui_components.console")
    def test_show_cli_banner_all_modes(self, mock_console):
        """show_cli_banner works for all known modes."""
        from ui_components import show_cli_banner
        for mode in ["universal", "bug_bounty", "auto", "agent"]:
            mock_console.reset_mock()
            show_cli_banner(mode)
            assert mock_console.print.call_count >= 3

    @patch("ui_components.console")
    def test_show_cli_banner_unknown_mode(self, mock_console):
        """show_cli_banner with unknown mode falls back to default."""
        from ui_components import show_cli_banner
        show_cli_banner("nonexistent")
        assert mock_console.print.call_count >= 3

    @patch("ui_components.console")
    def test_show_arsenal_banner(self, mock_console):
        """show_arsenal_banner prints banner."""
        from ui_components import show_arsenal_banner
        show_arsenal_banner()
        assert mock_console.print.call_count >= 3

    @patch("ui_components.console")
    def test_show_scan_summary_with_findings(self, mock_console):
        """show_scan_summary shows metrics when findings present."""
        from ui_components import show_scan_summary
        show_scan_summary({"high": 3, "medium": 5, "low": 2, "info": 1})
        assert mock_console.print.call_count >= 3

    @patch("ui_components.console")
    def test_show_scan_summary_no_findings(self, mock_console):
        """show_scan_summary shows no findings message."""
        from ui_components import show_scan_summary
        show_scan_summary({})
        assert mock_console.print.call_count >= 2

    @patch("ui_components.console")
    def test_show_memory_stats(self, mock_console):
        """show_memory_stats shows memory stats."""
        from ui_components import show_memory_stats
        show_memory_stats({
            "status": "active",
            "total_memories": 42,
            "unique_targets": 5,
            "targets": ["a.com", "b.com"],
        })
        assert mock_console.print.call_count >= 3

    @patch("ui_components.console")
    def test_show_memory_stats_no_targets(self, mock_console):
        """show_memory_stats works without targets list."""
        from ui_components import show_memory_stats
        show_memory_stats({"status": "active", "total_memories": 10, "unique_targets": 2})
        assert mock_console.print.call_count >= 2

    @patch("ui_components.console")
    def test_show_findings_summary_empty(self, mock_console):
        """show_findings_summary handles empty list."""
        from ui_components import show_findings_summary
        show_findings_summary([])
        mock_console.print.assert_called()

    @patch("ui_components.console")
    def test_show_findings_summary_with_findings(self, mock_console):
        """show_findings_summary groups by severity."""
        from ui_components import show_findings_summary
        findings = [
            {"severity": "high", "title": "XSS"},
            {"severity": "medium", "title": "CSRF"},
            {"severity": "low", "title": "Info"},
        ]
        show_findings_summary(findings)
        assert mock_console.print.call_count >= 2

    @patch("ui_components.console")
    def test_show_toast_info(self, mock_console):
        """show_toast with level info."""
        from ui_components import show_toast
        with patch("ui_components.time"):
            show_toast("hello", level="info", duration=0)
        args = mock_console.print.call_args[0][0]
        assert "[INFO]" in args

    @patch("ui_components.console")
    def test_show_toast_success(self, mock_console):
        """show_toast with level success."""
        from ui_components import show_toast
        with patch("ui_components.time"):
            show_toast("done", level="success", duration=0)
        args = mock_console.print.call_args[0][0]
        assert "[OK]" in args

    @patch("ui_components.console")
    def test_show_toast_error(self, mock_console):
        """show_toast with level error."""
        from ui_components import show_toast
        with patch("ui_components.time"):
            show_toast("err", level="error", duration=0)
        args = mock_console.print.call_args[0][0]
        assert "[FAIL]" in args

    @patch("ui_components.console")
    def test_show_toast_warning(self, mock_console):
        """show_toast with level warning."""
        from ui_components import show_toast
        with patch("ui_components.time"):
            show_toast("warn", level="warning", duration=0)
        args = mock_console.print.call_args[0][0]
        assert "[WARN]" in args

    @patch("ui_components.console")
    def test_show_toast_unknown_level(self, mock_console):
        """show_toast with unknown level uses [*]."""
        from ui_components import show_toast
        with patch("ui_components.time"):
            show_toast("misc", level="other", duration=0)
        args = mock_console.print.call_args[0][0]
        assert "[*]" in args

    @patch("ui_components.console")
    def test_show_divider(self, mock_console):
        """show_divider prints a divider line."""
        from ui_components import show_divider
        show_divider()
        mock_console.print.assert_called_once()

    @patch("ui_components.console")
    def test_show_divider_custom(self, mock_console):
        """show_divider with custom char and width."""
        from ui_components import show_divider
        show_divider(char="-", width=50)
        mock_console.print.assert_called_once()

    @patch("ui_components.console")
    def test_show_key_value(self, mock_console):
        """show_key_value prints key-value pair."""
        from ui_components import show_key_value
        show_key_value("Name", "value")
        args = mock_console.print.call_args[0][0]
        assert "Name" in args
        assert "value" in args

    @patch("ui_components.console")
    def test_show_key_value_indent(self, mock_console):
        """show_key_value with custom indent."""
        from ui_components import show_key_value
        show_key_value("K", "V", indent=4)
        args = mock_console.print.call_args[0][0]
        assert "    " in args

    @patch("ui_components.console")
    def test_show_bullet_list(self, mock_console):
        """show_bullet_list prints items."""
        from ui_components import show_bullet_list
        show_bullet_list(["a", "b", "c"])
        assert mock_console.print.call_count == 3

    @patch("ui_components.console")
    def test_show_bullet_list_custom_marker(self, mock_console):
        """show_bullet_list with custom marker."""
        from ui_components import show_bullet_list
        show_bullet_list(["item1"], marker="*", color="#ff0000")
        args = mock_console.print.call_args[0][0]
        assert "*" in args

    def test_render_sidebar_returns_panel(self):
        """render_sidebar returns a Rich Panel."""
        from ui_components import render_sidebar
        panel = render_sidebar()
        assert isinstance(panel, Panel)

    def test_render_sidebar_with_target(self):
        """render_sidebar with target set includes target in output."""
        from ui_components import render_sidebar
        panel = render_sidebar(target="example.com", mode="scan", status="thinking")
        assert isinstance(panel, Panel)

    def test_render_sidebar_high_tokens(self):
        """render_sidebar with high token usage."""
        from ui_components import render_sidebar
        panel = render_sidebar(token_count=120000, token_limit=128000)
        assert isinstance(panel, Panel)

    def test_render_sidebar_zero_token_limit(self):
        """render_sidebar with zero token limit handles division safely."""
        from ui_components import render_sidebar
        panel = render_sidebar(token_count=0, token_limit=0)
        assert isinstance(panel, Panel)

    def test_render_sidebar_idle_status(self):
        """render_sidebar with idle status."""
        from ui_components import render_sidebar
        panel = render_sidebar(status="idle")
        assert isinstance(panel, Panel)

    def test_render_sidebar_unknown_status(self):
        """render_sidebar with unknown status falls back."""
        from ui_components import render_sidebar
        panel = render_sidebar(status="mystery")
        assert isinstance(panel, Panel)

    def test_render_sidebar_with_scroll_info(self):
        """render_sidebar with scroll_info."""
        from ui_components import render_sidebar
        panel = render_sidebar(scroll_info="Page 1/5")
        assert isinstance(panel, Panel)

    @patch("ui_components.console")
    def test_show_command_execution_success(self, mock_console):
        """show_command_execution shows success panel."""
        from ui_components import show_command_execution
        show_command_execution(
            cmd="ls -la",
            result="file1.txt\nfile2.txt",
            success=True,
            purpose="list files",
            thought="need to see files",
            elapsed=0.5,
        )
        mock_console.print.assert_called()

    @patch("ui_components.console")
    def test_show_command_execution_failure(self, mock_console):
        """show_command_execution shows failure panel."""
        from ui_components import show_command_execution
        show_command_execution(
            cmd="rm /",
            result="permission denied",
            success=False,
        )
        mock_console.print.assert_called()

    @patch("ui_components.console")
    def test_show_command_execution_long_output(self, mock_console):
        """show_command_execution truncates long output."""
        from ui_components import show_command_execution
        long_output = "\n".join([f"line {i}" for i in range(30)])
        show_command_execution(cmd="cmd", result=long_output, success=True)
        mock_console.print.assert_called()

    @patch("ui_components.console")
    def test_show_command_execution_empty_cmd(self, mock_console):
        """show_command_execution handles empty command."""
        from ui_components import show_command_execution
        show_command_execution(cmd="", result="output", success=True)
        mock_console.print.assert_called()

    @patch("ui_components.console")
    def test_show_categorized_menu(self, mock_console):
        """show_categorized_menu renders the full menu."""
        from ui_components import show_categorized_menu
        show_categorized_menu()
        assert mock_console.print.call_count >= 2

    def test_menu_categories_structure(self):
        """MENU_CATEGORIES has expected structure."""
        from ui_components import MENU_CATEGORIES
        assert isinstance(MENU_CATEGORIES, list)
        for cat in MENU_CATEGORIES:
            assert "title" in cat
            assert "icon" in cat
            assert "items" in cat
            assert isinstance(cat["items"], list)
            for item in cat["items"]:
                assert len(item) == 3

    @patch("ui_components.console")
    def test_confirm_yes(self, mock_console):
        """confirm() returns True on 'y'."""
        from ui_components import confirm
        mock_console.input.return_value = "y"
        assert confirm("Proceed?") is True

    @patch("ui_components.console")
    def test_confirm_no(self, mock_console):
        """confirm() returns False on 'n'."""
        from ui_components import confirm
        mock_console.input.return_value = "n"
        assert confirm("Proceed?") is False

    @patch("ui_components.console")
    def test_confirm_default_true_empty(self, mock_console):
        """confirm() with default=True returns True on empty input."""
        from ui_components import confirm
        mock_console.input.return_value = ""
        assert confirm("Proceed?", default=True) is True

    @patch("ui_components.console")
    def test_confirm_default_false_empty(self, mock_console):
        """confirm() with default=False returns False on empty input."""
        from ui_components import confirm
        mock_console.input.return_value = ""
        assert confirm("Proceed?", default=False) is False

    @patch("ui_components.console")
    def test_confirm_yes_capital(self, mock_console):
        """confirm() accepts 'Yes'."""
        from ui_components import confirm
        mock_console.input.return_value = "Yes"
        assert confirm("Proceed?") is True

    def test_sidebar_constants(self):
        """SIDEBAR_TITLE and SIDEBAR_SUBTITLE are set."""
        from ui_components import SIDEBAR_TITLE, SIDEBAR_SUBTITLE
        assert isinstance(SIDEBAR_TITLE, str)
        assert isinstance(SIDEBAR_SUBTITLE, str)

    def test_all_exports(self):
        """__all__ contains all expected public symbols."""
        from ui_components import __all__
        assert "print_success" in __all__
        assert "print_error" in __all__
        assert "console" in __all__
        assert "COLORS" in __all__
        assert "STYLES" in __all__
        assert "MARKERS" in __all__


# ============================================================================
# tui/themes.py tests
# ============================================================================


class TestThemes:
    """Tests for tui/themes.py module."""

    def test_all_themes_exist(self):
        """All 9 themes are defined in THEMES dict."""
        from tui.themes import THEMES
        expected = ["DEFAULT", "CYBERPUNK", "MATRIX", "STEALTH", "SYNTHWAVE",
                     "OCEAN", "FOREST", "SUNSET", "ARCTIC"]
        for name in expected:
            assert name in THEMES, f"Missing theme: {name}"

    def test_theme_tokens_complete(self):
        """Every theme provides all required tokens."""
        from tui.themes import THEMES, THEME_TOKENS
        for name, theme in THEMES.items():
            for token in THEME_TOKENS:
                assert token in theme, f"Theme {name} missing token: {token}"

    def test_theme_colors_are_hex(self):
        """All theme values look like hex colors."""
        from tui.themes import THEMES
        for name, theme in THEMES.items():
            for token, value in theme.items():
                assert value.startswith("#"), f"Theme {name}.{token} not hex: {value}"

    def test_theme_values_are_strings(self):
        """All theme values are strings."""
        from tui.themes import THEMES
        for name, theme in THEMES.items():
            for token, value in theme.items():
                assert isinstance(value, str), f"Theme {name}.{token} not string"

    def test_easing_linear(self):
        """Easing.LINEAR returns linear interpolation."""
        from tui.themes import Easing
        assert Easing.apply(Easing.LINEAR, 0.0, 0.0, 100.0) == 0.0
        assert Easing.apply(Easing.LINEAR, 0.5, 0.0, 100.0) == 50.0
        assert Easing.apply(Easing.LINEAR, 1.0, 0.0, 100.0) == 100.0

    def test_easing_ease_in(self):
        """Easing.EASE_IN uses quadratic ease-in curve."""
        from tui.themes import Easing
        assert Easing.apply(Easing.EASE_IN, 0.0, 0.0, 100.0) == 0.0
        assert Easing.apply(Easing.EASE_IN, 1.0, 0.0, 100.0) == 100.0
        mid = Easing.apply(Easing.EASE_IN, 0.5, 0.0, 100.0)
        assert mid == 25.0  # 0.5^2 * 100

    def test_easing_ease_out(self):
        """Easing.EASE_OUT uses quadratic ease-out curve."""
        from tui.themes import Easing
        assert Easing.apply(Easing.EASE_OUT, 0.0, 0.0, 100.0) == 0.0
        assert Easing.apply(Easing.EASE_OUT, 1.0, 0.0, 100.0) == 100.0
        mid = Easing.apply(Easing.EASE_OUT, 0.5, 0.0, 100.0)
        assert mid == 75.0  # 1 - (1-0.5)^2 = 0.75

    def test_easing_ease_in_out_first_half(self):
        """Easing.EASE_IN_OUT first half uses ease-in curve."""
        from tui.themes import Easing
        val = Easing.apply(Easing.EASE_IN_OUT, 0.25, 0.0, 100.0)
        expected = 100.0 * (2 * 0.25 * 0.25)  # 12.5
        assert abs(val - expected) < 0.01

    def test_easing_ease_in_out_second_half(self):
        """Easing.EASE_IN_OUT second half uses ease-out curve."""
        from tui.themes import Easing
        val = Easing.apply(Easing.EASE_IN_OUT, 0.75, 0.0, 100.0)
        assert 80.0 < val < 100.0

    def test_easing_clamps_t(self):
        """Easing.apply clamps t to [0, 1]."""
        from tui.themes import Easing
        assert Easing.apply(Easing.LINEAR, -0.5, 0.0, 100.0) == 0.0
        assert Easing.apply(Easing.LINEAR, 1.5, 0.0, 100.0) == 100.0

    def test_easing_unknown_falls_back_to_linear(self):
        """Unknown easing type falls back to linear."""
        from tui.themes import Easing
        val = Easing.apply("mystery", 0.5, 0.0, 100.0)
        assert val == 50.0

    def test_lerp_color_same(self):
        """lerp_color at t=0 returns first color."""
        from tui.themes import lerp_color
        result = lerp_color("#ff0000", "#0000ff", 0.0)
        assert result == "#ff0000"

    def test_lerp_color_end(self):
        """lerp_color at t=1 returns second color."""
        from tui.themes import lerp_color
        result = lerp_color("#ff0000", "#0000ff", 1.0)
        assert result == "#0000ff"

    def test_lerp_color_mid(self):
        """lerp_color at t=0.5 returns midpoint color."""
        from tui.themes import lerp_color
        result = lerp_color("#000000", "#ffffff", 0.5)
        assert result == "#808080"

    def test_lerp_color_clamps_t(self):
        """lerp_color clamps t outside [0, 1]."""
        from tui.themes import lerp_color
        assert lerp_color("#000000", "#ffffff", -1.0) == "#000000"
        assert lerp_color("#000000", "#ffffff", 2.0) == "#ffffff"

    def test_gradient_stops_empty(self):
        """gradient_stops returns white defaults for empty list."""
        from tui.themes import gradient_stops
        result = gradient_stops([], 5)
        assert len(result) == 5
        assert all(c == "#ffffff" for c in result)

    def test_gradient_stops_single(self):
        """gradient_stops returns repeated color for single input."""
        from tui.themes import gradient_stops
        result = gradient_stops(["#ff0000"], 3)
        assert result == ["#ff0000"] * 3

    def test_gradient_stops_two_colors(self):
        """gradient_stops interpolates between two colors."""
        from tui.themes import gradient_stops
        result = gradient_stops(["#000000", "#ffffff"], 5)
        assert len(result) == 5
        assert result[0] == "#000000"
        assert result[-1] == "#ffffff"

    def test_gradient_stops_zero_steps(self):
        """gradient_stops returns empty list for zero steps."""
        from tui.themes import gradient_stops
        result = gradient_stops(["#ff0000", "#00ff00"], 0)
        assert result == []

    def test_gradient_stops_one_step(self):
        """gradient_stops returns first color for one step."""
        from tui.themes import gradient_stops
        result = gradient_stops(["#ff0000", "#00ff00"], 1)
        assert result == ["#ff0000"]

    def test_gradient_stops_three_colors(self):
        """gradient_stops works with three color stops."""
        from tui.themes import gradient_stops
        result = gradient_stops(["#ff0000", "#00ff00", "#0000ff"], 7)
        assert len(result) == 7

    def test_theme_manager_default(self):
        """ThemeManager defaults to DEFAULT theme."""
        from tui.themes import ThemeManager
        mgr = ThemeManager()
        assert mgr.active == "DEFAULT"

    def test_theme_manager_named(self):
        """ThemeManager accepts named theme."""
        from tui.themes import ThemeManager
        mgr = ThemeManager("CYBERPUNK")
        assert mgr.active == "CYBERPUNK"

    def test_theme_manager_unknown_falls_back(self):
        """ThemeManager with unknown theme falls back to DEFAULT."""
        from tui.themes import ThemeManager
        mgr = ThemeManager("NONEXISTENT")
        assert mgr.active == "DEFAULT"

    def test_theme_manager_current(self):
        """ThemeManager.current() returns a color string."""
        from tui.themes import ThemeManager
        mgr = ThemeManager("DEFAULT")
        color = mgr.current("primary")
        assert isinstance(color, str)
        assert color.startswith("#")

    def test_theme_manager_current_unknown_token(self):
        """ThemeManager.current() returns default for unknown token."""
        from tui.themes import ThemeManager
        mgr = ThemeManager()
        color = mgr.current("nonexistent_token")
        assert color == "#ffffff"

    def test_theme_manager_list_themes(self):
        """ThemeManager.list_themes() returns all theme names."""
        from tui.themes import ThemeManager
        mgr = ThemeManager()
        themes = mgr.list_themes()
        assert len(themes) == 9
        assert "DEFAULT" in themes

    def test_theme_manager_set_theme(self):
        """ThemeManager.set_theme() switches instantly."""
        from tui.themes import ThemeManager
        mgr = ThemeManager("DEFAULT")
        mgr.set_theme("MATRIX")
        assert mgr.active == "MATRIX"
        assert mgr.current("primary") != "#ff2222"

    def test_theme_manager_set_theme_unknown(self):
        """ThemeManager.set_theme() ignores unknown theme."""
        from tui.themes import ThemeManager
        mgr = ThemeManager("DEFAULT")
        mgr.set_theme("NONEXISTENT")
        assert mgr.active == "DEFAULT"

    def test_theme_manager_transition_to(self):
        """ThemeManager.transition_to() starts a transition."""
        from tui.themes import ThemeManager
        mgr = ThemeManager("DEFAULT")
        mgr.transition_to("CYBERPUNK", duration=0.1)
        assert mgr.active == "CYBERPUNK"

    def test_theme_manager_transition_to_unknown(self):
        """ThemeManager.transition_to() ignores unknown theme."""
        from tui.themes import ThemeManager
        mgr = ThemeManager("DEFAULT")
        mgr.transition_to("NONEXISTENT")
        assert mgr.active == "DEFAULT"

    def test_theme_manager_tick_returns_false_when_not_transitioning(self):
        """ThemeManager.tick() returns False when no transition."""
        from tui.themes import ThemeManager
        mgr = ThemeManager("DEFAULT")
        assert mgr.tick() is False

    def test_theme_manager_tick_completes_transition(self):
        """ThemeManager.tick() completes after duration."""
        import time
        from tui.themes import ThemeManager
        mgr = ThemeManager("DEFAULT")
        mgr.transition_to("MATRIX", duration=0.01)
        time.sleep(0.05)
        result = mgr.tick()
        assert result is False

    def test_theme_manager_register_listener(self):
        """ThemeManager.register_listener() adds callback."""
        from tui.themes import ThemeManager
        mgr = ThemeManager()
        callback = MagicMock()
        mgr.register_listener(callback)
        mgr.set_theme("MATRIX")
        callback.assert_called()

    def test_theme_manager_register_listener_exception(self):
        """ThemeManager handles listener exceptions gracefully."""
        from tui.themes import ThemeManager
        mgr = ThemeManager()
        bad_callback = MagicMock(side_effect=RuntimeError("fail"))
        mgr.register_listener(bad_callback)
        # Should not raise
        mgr.set_theme("MATRIX")

    def test_theme_manager_style(self):
        """ThemeManager.style() returns a Rich Style."""
        from tui.themes import ThemeManager
        from rich.style import Style
        mgr = ThemeManager()
        style = mgr.style("primary")
        assert isinstance(style, Style)

    def test_theme_manager_render_styled(self):
        """ThemeManager.render_styled() returns Rich Text."""
        from tui.themes import ThemeManager
        mgr = ThemeManager()
        result = mgr.render_styled("Hello", token="primary", bold=True)
        assert isinstance(result, Text)
        assert "Hello" in result.plain

    def test_theme_manager_render_styled_dim(self):
        """ThemeManager.render_styled() with dim=True."""
        from tui.themes import ThemeManager
        mgr = ThemeManager()
        result = mgr.render_styled("Dim", dim=True)
        assert isinstance(result, Text)

    def test_theme_manager_gradient_text(self):
        """ThemeManager.gradient_text() returns gradient-colored Text."""
        from tui.themes import ThemeManager
        mgr = ThemeManager("DEFAULT")
        result = mgr.gradient_text("Hello World")
        assert isinstance(result, Text)
        assert "Hello World" in result.plain

    def test_theme_manager_gradient_text_custom_tokens(self):
        """ThemeManager.gradient_text() with custom tokens."""
        from tui.themes import ThemeManager
        mgr = ThemeManager()
        result = mgr.gradient_text("AB", tokens=("primary", "secondary", "accent"))
        assert isinstance(result, Text)

    def test_theme_manager_current_colors_static(self):
        """ThemeManager.current_colors returns dict when not transitioning."""
        from tui.themes import ThemeManager
        mgr = ThemeManager("DEFAULT")
        colors = mgr.current_colors
        assert isinstance(colors, dict)
        assert "primary" in colors

    def test_get_manager_singleton(self):
        """get_manager() returns the same ThemeManager instance."""
        from tui.themes import get_manager
        mgr1 = get_manager()
        mgr2 = get_manager()
        assert mgr1 is mgr2

    def test_get_theme_valid(self):
        """get_theme() returns a copy of the named theme."""
        from tui.themes import get_theme
        theme = get_theme("CYBERPUNK")
        assert isinstance(theme, dict)
        assert "primary" in theme

    def test_get_theme_invalid(self):
        """get_theme() returns DEFAULT for unknown theme."""
        from tui.themes import get_theme
        theme = get_theme("NONEXISTENT")
        assert theme["primary"] == "#ff2222"  # DEFAULT primary

    def test_hex_to_rgb_normal(self):
        """_hex_to_rgb converts 6-char hex correctly."""
        from tui.themes import _hex_to_rgb
        assert _hex_to_rgb("#ff0000") == (255, 0, 0)
        assert _hex_to_rgb("#00ff00") == (0, 255, 0)
        assert _hex_to_rgb("#0000ff") == (0, 0, 255)

    def test_hex_to_rgb_short_form(self):
        """_hex_to_rgb handles 3-char hex."""
        from tui.themes import _hex_to_rgb
        assert _hex_to_rgb("#f00") == (255, 0, 0)

    def test_hex_to_rgb_invalid(self):
        """_hex_to_rgb returns white for invalid input."""
        from tui.themes import _hex_to_rgb
        assert _hex_to_rgb("invalid") == (255, 255, 255)

    def test_rgb_to_hex(self):
        """_rgb_to_hex converts tuple to hex string."""
        from tui.themes import _rgb_to_hex
        assert _rgb_to_hex((255, 0, 0)) == "#ff0000"
        assert _rgb_to_hex((0, 255, 0)) == "#00ff00"

    def test_rgb_to_hex_clamps(self):
        """_rgb_to_hex clamps values to 0-255."""
        from tui.themes import _rgb_to_hex
        assert _rgb_to_hex((300, -10, 128)) == "#ff0080"


# ============================================================================
# tui/visualizations.py tests
# ============================================================================


class TestVisualizations:
    """Tests for tui/visualizations.py module."""

    def test_vulnerability_heatmap_render(self):
        """VulnerabilityHeatmap renders a Panel."""
        from tui.visualizations import VulnerabilityHeatmap
        heat = VulnerabilityHeatmap(
            endpoints=["api.example.com", "admin.example.com"],
            vuln_types=["XSS", "IDOR", "SQLi"],
        )
        heat.set("api.example.com", "XSS", "high", 3)
        result = heat.render()
        assert isinstance(result, Panel)

    def test_vulnerability_heatmap_empty_endpoints(self):
        """VulnerabilityHeatmap with no endpoints returns Text."""
        from tui.visualizations import VulnerabilityHeatmap
        heat = VulnerabilityHeatmap(endpoints=[], vuln_types=["XSS"])
        result = heat.render()
        assert isinstance(result, Text)

    def test_vulnerability_heatmap_get(self):
        """VulnerabilityHeatmap.get returns cell."""
        from tui.visualizations import VulnerabilityHeatmap
        heat = VulnerabilityHeatmap(endpoints=["ep1"], vuln_types=["XSS"])
        heat.set("ep1", "XSS", "high", 5)
        cell = heat.get("ep1", "XSS")
        assert cell is not None
        assert cell.count == 5

    def test_vulnerability_heatmap_get_missing(self):
        """VulnerabilityHeatmap.get returns None for missing cell."""
        from tui.visualizations import VulnerabilityHeatmap
        heat = VulnerabilityHeatmap(endpoints=["ep1"], vuln_types=["XSS"])
        assert heat.get("ep1", "SQLi") is None

    def test_vulnerability_heatmap_custom_colors(self):
        """VulnerabilityHeatmap accepts custom severity colors."""
        from tui.visualizations import VulnerabilityHeatmap
        custom = {"high": "#ff0000", "low": "#00ff00", "medium": "#ffff00",
                  "info": "#888888", "critical": "#ff0000"}
        heat = VulnerabilityHeatmap(
            endpoints=["a"], vuln_types=["X"], severity_colors=custom
        )
        heat.set("a", "X", "high", 1)
        result = heat.render()
        assert isinstance(result, Panel)

    def test_finding_timeline_render(self):
        """FindingTimeline renders a Panel."""
        from tui.visualizations import FindingTimeline, Finding
        tl = FindingTimeline()
        tl.add("XSS found", severity="high", location="/api")
        tl.add("CSRF found", severity="medium")
        result = tl.render()
        assert isinstance(result, Panel)

    def test_finding_timeline_empty(self):
        """FindingTimeline with no findings shows empty message."""
        from tui.visualizations import FindingTimeline
        tl = FindingTimeline()
        result = tl.render()
        assert isinstance(result, Panel)

    def test_finding_timeline_newest_first(self):
        """FindingTimeline sorts newest first by default."""
        from tui.visualizations import FindingTimeline
        tl = FindingTimeline(newest_first=True)
        tl.add("First", severity="low", timestamp=datetime(2025, 1, 1))
        tl.add("Second", severity="high", timestamp=datetime(2025, 6, 1))
        result = tl.render()
        assert isinstance(result, Panel)

    def test_finding_timeline_old_first(self):
        """FindingTimeline sorts oldest first when configured."""
        from tui.visualizations import FindingTimeline
        tl = FindingTimeline(newest_first=False)
        tl.add("First", severity="low", timestamp=datetime(2025, 1, 1))
        tl.add("Second", severity="high", timestamp=datetime(2025, 6, 1))
        result = tl.render()
        assert isinstance(result, Panel)

    def test_finding_timeline_trims_max_items(self):
        """FindingTimeline trims when exceeding max_items * 2."""
        from tui.visualizations import FindingTimeline
        tl = FindingTimeline(max_items=2)
        for i in range(10):
            tl.add(f"Finding {i}")
        assert len(tl.findings) <= 4

    def test_finding_timeline_custom_colors(self):
        """FindingTimeline accepts custom severity colors."""
        from tui.visualizations import FindingTimeline
        custom = {"high": "#ff0000", "low": "#00ff00", "medium": "#ffff00",
                  "info": "#888888", "critical": "#ff0000"}
        tl = FindingTimeline(severity_colors=custom)
        tl.add("XSS", severity="high")
        result = tl.render()
        assert isinstance(result, Panel)

    def test_finding_timeline_with_description(self):
        """FindingTimeline shows descriptions when present."""
        from tui.visualizations import FindingTimeline
        tl = FindingTimeline()
        tl.add("XSS", severity="high", description="Found in search parameter")
        result = tl.render()
        assert isinstance(result, Panel)

    def test_exploit_chain_render(self):
        """ExploitChainDiagram renders a Panel."""
        from tui.visualizations import ExploitChainDiagram
        chain = ExploitChainDiagram()
        chain.add("Recon", "Gathered endpoints", severity="info", success=True)
        chain.add("Exploit", "SQL injection", severity="high", success=True)
        chain.add("Privilege Escalation", "Admin access", severity="critical", success=True)
        result = chain.render()
        assert isinstance(result, Panel)

    def test_exploit_chain_empty(self):
        """ExploitChainDiagram with no steps renders objective only."""
        from tui.visualizations import ExploitChainDiagram
        chain = ExploitChainDiagram()
        result = chain.render()
        assert isinstance(result, Panel)

    def test_exploit_chain_with_init_steps(self):
        """ExploitChainDiagram accepts steps at init."""
        from tui.visualizations import ExploitChainDiagram, ExploitStep
        steps = [ExploitStep(title="Step 1", severity="medium")]
        chain = ExploitChainDiagram(steps=steps)
        result = chain.render()
        assert isinstance(result, Panel)

    def test_exploit_chain_failed_step(self):
        """ExploitChainDiagram shows [FAIL] for failed steps."""
        from tui.visualizations import ExploitChainDiagram
        chain = ExploitChainDiagram()
        chain.add("Failed exploit", success=False, severity="critical")
        result = chain.render()
        assert isinstance(result, Panel)

    def test_attack_surface_map_render(self):
        """AttackSurfaceMap renders a Panel with Tree."""
        from tui.visualizations import AttackSurfaceMap
        surface = AttackSurfaceMap()
        surface.add("/api/users", method="GET", risk="high")
        surface.add("/api/admin", method="POST", risk="critical")
        surface.add("/login", method="GET", risk="low", notes="login page")
        result = surface.render()
        assert isinstance(result, Panel)

    def test_attack_surface_map_empty(self):
        """AttackSurfaceMap with no endpoints renders empty tree."""
        from tui.visualizations import AttackSurfaceMap
        surface = AttackSurfaceMap()
        result = surface.render()
        assert isinstance(result, Panel)

    def test_attack_surface_map_custom_colors(self):
        """AttackSurfaceMap accepts custom severity colors."""
        from tui.visualizations import AttackSurfaceMap
        custom = {"high": "#ff0000", "low": "#00ff00", "medium": "#ffff00",
                  "info": "#888888", "critical": "#ff0000"}
        surface = AttackSurfaceMap(severity_colors=custom)
        surface.add("/test", risk="high")
        result = surface.render()
        assert isinstance(result, Panel)

    def test_risk_gauge_render(self):
        """RiskGauge renders a Panel."""
        from tui.visualizations import RiskGauge
        gauge = RiskGauge(value=50, max_value=100, label="RISK")
        result = gauge.render()
        assert isinstance(result, Panel)

    def test_risk_gauge_zero(self):
        """RiskGauge at zero value."""
        from tui.visualizations import RiskGauge
        gauge = RiskGauge(value=0, max_value=100)
        result = gauge.render()
        assert isinstance(result, Panel)

    def test_risk_gauge_max(self):
        """RiskGauge at max value."""
        from tui.visualizations import RiskGauge
        gauge = RiskGauge(value=100, max_value=100)
        result = gauge.render()
        assert isinstance(result, Panel)

    def test_risk_gauge_negative_clamped(self):
        """RiskGauge clamps negative values."""
        from tui.visualizations import RiskGauge
        gauge = RiskGauge(value=-50, max_value=100)
        assert gauge.value == 0.0

    def test_risk_gauge_custom_colors(self):
        """RiskGauge accepts custom colors."""
        from tui.visualizations import RiskGauge
        gauge = RiskGauge(
            value=75, max_value=100,
            low_color="#00ff00", mid_color="#ffff00", high_color="#ff0000"
        )
        result = gauge.render()
        assert isinstance(result, Panel)

    def test_risk_gauge_unit(self):
        """RiskGauge with unit suffix."""
        from tui.visualizations import RiskGauge
        gauge = RiskGauge(value=75, max_value=100, unit="%")
        result = gauge.render()
        assert isinstance(result, Panel)

    def test_risk_gauge_arc_color(self):
        """RiskGauge._arc_color returns correct color bands."""
        from tui.visualizations import RiskGauge
        gauge = RiskGauge()
        assert gauge._arc_color(0.3) == gauge.low_color
        assert gauge._arc_color(0.6) == gauge.mid_color
        assert gauge._arc_color(0.9) == gauge.high_color

    def test_severity_chart_render(self):
        """SeverityChart renders a Panel."""
        from tui.visualizations import SeverityChart
        chart = SeverityChart(critical=1, high=3, medium=5, low=8, info=12)
        result = chart.render()
        assert isinstance(result, Panel)

    def test_severity_chart_set(self):
        """SeverityChart.set updates counts."""
        from tui.visualizations import SeverityChart
        chart = SeverityChart()
        chart.set("high", 10)
        assert chart.counts["high"] == 10

    def test_severity_chart_set_invalid(self):
        """SeverityChart.set ignores unknown severity."""
        from tui.visualizations import SeverityChart
        chart = SeverityChart()
        chart.set("unknown", 5)
        assert "unknown" not in chart.counts

    def test_severity_chart_set_negative(self):
        """SeverityChart.set clamps negative counts to 0."""
        from tui.visualizations import SeverityChart
        chart = SeverityChart()
        chart.set("high", -5)
        assert chart.counts["high"] == 0

    def test_severity_chart_custom_colors(self):
        """SeverityChart accepts custom severity colors."""
        from tui.visualizations import SeverityChart
        custom = {"critical": "#ff0000", "high": "#ff5500", "medium": "#ffb300",
                  "low": "#81c784", "info": "#888888"}
        chart = SeverityChart(high=5, severity_colors=custom)
        result = chart.render()
        assert isinstance(result, Panel)

    def test_render_text_panel(self):
        """render_text_panel wraps text in a Panel."""
        from tui.visualizations import render_text_panel
        result = render_text_panel("Hello", title="Title")
        assert isinstance(result, Panel)

    def test_render_text_panel_no_title(self):
        """render_text_panel without title."""
        from tui.visualizations import render_text_panel
        result = render_text_panel("Content", title="")
        assert isinstance(result, Panel)

    def test_render_text_panel_with_width(self):
        """render_text_panel with explicit width."""
        from tui.visualizations import render_text_panel
        result = render_text_panel("Text", width=60)
        assert isinstance(result, Panel)


# ============================================================================
# tui/welcome.py tests
# ============================================================================


class TestWelcome:
    """Tests for tui/welcome.py module."""

    def test_ascii_logo_returns_text(self):
        """ascii_logo returns Rich Text with block characters."""
        from tui.welcome import ascii_logo
        result = ascii_logo()
        assert isinstance(result, Text)
        assert len(result.plain) > 100

    def test_ascii_logo_custom_colors(self):
        """ascii_logo accepts custom colors."""
        from tui.welcome import ascii_logo
        result = ascii_logo(color_a="#ff0000", color_b="#00ff00", color_c="#0000ff")
        assert isinstance(result, Text)

    def test_ascii_logo_not_bold(self):
        """ascii_logo with bold=False."""
        from tui.welcome import ascii_logo
        result = ascii_logo(bold=False)
        assert isinstance(result, Text)

    def test_mix_color(self):
        """_mix interpolates two hex colors (int truncation gives 0x7f)."""
        from tui.welcome import _mix
        assert _mix("#000000", "#ffffff", 0.5) == "#7f7f7f"
        assert _mix("#ff0000", "#00ff00", 0.0) == "#ff0000"
        assert _mix("#ff0000", "#00ff00", 1.0) == "#00ff00"

    def test_mix_short_hex(self):
        """_mix handles 3-char hex input."""
        from tui.welcome import _mix
        result = _mix("#f00", "#00f", 0.5)
        assert result == "#7f007f"

    def test_mission_briefing_render(self):
        """MissionBriefing.render returns a Panel."""
        from tui.welcome import MissionBriefing
        mb = MissionBriefing(
            target="example.com",
            scan_status="RUNNING",
            ai_status="THINKING",
            operators=2,
            active_session="test",
        )
        result = mb.render()
        assert isinstance(result, Panel)

    def test_mission_briefing_defaults(self):
        """MissionBriefing has sensible defaults."""
        from tui.welcome import MissionBriefing
        mb = MissionBriefing()
        assert mb.target == "no target set"
        assert mb.scan_status == "IDLE"
        assert mb.ai_status == "READY"

    def test_mission_briefing_empty_target(self):
        """MissionBriefing handles empty target."""
        from tui.welcome import MissionBriefing
        mb = MissionBriefing(target="")
        result = mb.render()
        assert isinstance(result, Panel)

    def test_recent_activity_add(self):
        """RecentActivity.add appends entries."""
        from tui.welcome import RecentActivity
        ra = RecentActivity()
        ra.add("10:00:00", "SCAN", "started")
        ra.add("10:01:00", "FIND", "xss found")
        assert len(ra.items) == 2

    def test_recent_activity_render(self):
        """RecentActivity.render returns a Panel."""
        from tui.welcome import RecentActivity
        ra = RecentActivity()
        ra.add("10:00:00", "SCAN", "started")
        result = ra.render()
        assert isinstance(result, Panel)

    def test_recent_activity_empty_render(self):
        """RecentActivity.render with no items shows empty message."""
        from tui.welcome import RecentActivity
        ra = RecentActivity()
        result = ra.render()
        assert isinstance(result, Panel)

    def test_recent_activity_trims(self):
        """RecentActivity trims when exceeding max_items * 2."""
        from tui.welcome import RecentActivity
        ra = RecentActivity(max_items=3)
        for i in range(20):
            ra.add(f"{i:08d}", "TYPE", f"msg {i}")
        assert len(ra.items) <= 6

    def test_render_quick_start(self):
        """render_quick_start returns a Panel."""
        from tui.welcome import render_quick_start
        result = render_quick_start()
        assert isinstance(result, Panel)

    def test_render_quick_start_highlight(self):
        """render_quick_start with highlight_index."""
        from tui.welcome import render_quick_start
        result = render_quick_start(highlight_index=2)
        assert isinstance(result, Panel)

    def test_render_system_status(self):
        """render_system_status returns a Panel."""
        from tui.welcome import render_system_status
        result = render_system_status()
        assert isinstance(result, Panel)

    def test_get_system_status(self):
        """get_system_status returns dict with expected keys."""
        from tui.welcome import get_system_status
        status = get_system_status()
        assert isinstance(status, dict)
        assert "cpu_percent" in status
        assert "memory_percent" in status
        assert "disk_percent" in status
        assert "python_version" in status
        assert "tools_installed" in status
        assert "last_scan" in status

    def test_build_welcome_renderable(self):
        """build_welcome_renderable returns a renderable Group."""
        from tui.welcome import build_welcome_renderable
        from rich.console import Group
        result = build_welcome_renderable()
        assert isinstance(result, Group)

    def test_build_welcome_renderable_custom(self):
        """build_welcome_renderable with custom mission and activity."""
        from tui.welcome import build_welcome_renderable, MissionBriefing, RecentActivity
        mission = MissionBriefing(target="test.com")
        activity = RecentActivity()
        activity.add("10:00", "SCAN", "running")
        result = build_welcome_renderable(mission=mission, activity=activity, theme_name="CYBERPUNK")
        assert result is not None

    def test_render_status_footer(self):
        """_render_status_footer returns a Panel."""
        from tui.welcome import _render_status_footer
        result = _render_status_footer()
        assert isinstance(result, Panel)

    def test_render_status_footer_custom(self):
        """_render_status_footer with custom theme."""
        from tui.welcome import _render_status_footer
        result = _render_status_footer(theme_name="MATRIX", primary="#00ff66")
        assert isinstance(result, Panel)

    def test_logo_lines_count(self):
        """LOGO_LINES has 6 lines."""
        from tui.welcome import LOGO_LINES
        assert len(LOGO_LINES) == 6

    def test_quick_start_tiles_count(self):
        """QUICK_START_TILES has expected items."""
        from tui.welcome import QUICK_START_TILES
        assert len(QUICK_START_TILES) == 6
        for tile in QUICK_START_TILES:
            assert "key" in tile
            assert "title" in tile
            assert "desc" in tile
            assert "action" in tile

    def test_welcome_screen_importable(self):
        """WelcomeScreen class can be imported."""
        from tui.welcome import WelcomeScreen
        assert WelcomeScreen is not None

    def test_welcome_screen_instantiation(self):
        """WelcomeScreen can be instantiated."""
        from tui.welcome import WelcomeScreen, MissionBriefing, RecentActivity
        mission = MissionBriefing(target="test.com")
        activity = RecentActivity()
        ws = WelcomeScreen(mission=mission, activity=activity)
        assert ws is not None


# ============================================================================
# tui/dashboard.py tests
# ============================================================================


class TestDashboard:
    """Tests for tui/dashboard.py module."""

    def test_system_stats_defaults(self):
        """SystemStats has default values."""
        from tui.dashboard import SystemStats
        stats = SystemStats()
        assert stats.cpu == 0.0
        assert stats.memory == 0.0
        assert stats.net_in == 0.0
        assert stats.net_out == 0.0

    def test_system_stats_custom(self):
        """SystemStats accepts custom values."""
        from tui.dashboard import SystemStats
        stats = SystemStats(cpu=50.0, memory=75.0, net_in=100.0, net_out=50.0, timestamp=1.0)
        assert stats.cpu == 50.0

    def test_scan_defaults(self):
        """Scan has default values."""
        from tui.dashboard import Scan
        scan = Scan(name="test", target="example.com")
        assert scan.progress == 0.0
        assert scan.status == "running"

    def test_scan_custom(self):
        """Scan accepts custom values."""
        from tui.dashboard import Scan
        scan = Scan(name="nmap", target="10.0.0.1", progress=0.5, status="done")
        assert scan.progress == 0.5
        assert scan.status == "done"

    def test_host_defaults(self):
        """Host has default values."""
        from tui.dashboard import Host
        host = Host(ip="10.0.0.1")
        assert host.hostname == ""
        assert host.role == "unknown"
        assert host.risk == "low"

    def test_host_custom(self):
        """Host accepts custom values."""
        from tui.dashboard import Host
        host = Host(ip="10.0.0.1", hostname="web", role="webserver", risk="high")
        assert host.hostname == "web"
        assert host.risk == "high"

    def test_finding_defaults(self):
        """Finding has default values."""
        from tui.dashboard import Finding
        finding = Finding(title="XSS")
        assert finding.severity == "info"
        assert finding.location == ""
        assert finding.timestamp is not None

    def test_finding_custom(self):
        """Finding accepts custom values."""
        from tui.dashboard import Finding
        ts = datetime(2025, 1, 1)
        finding = Finding(title="SQLi", severity="critical", location="/api", timestamp=ts)
        assert finding.severity == "critical"

    def test_threat_marker_defaults(self):
        """ThreatMarker has default values."""
        from tui.dashboard import ThreatMarker
        marker = ThreatMarker(x=5, y=10)
        assert marker.severity == "info"
        assert marker.pulse == 0.0

    def test_threat_marker_custom(self):
        """ThreatMarker accepts custom values."""
        from tui.dashboard import ThreatMarker
        marker = ThreatMarker(x=1, y=2, severity="high", label="attack", pulse=0.5)
        assert marker.label == "attack"

    def test_threat_dashboard_importable(self):
        """ThreatDashboard class can be imported."""
        from tui.dashboard import ThreatDashboard
        assert ThreatDashboard is not None

    def test_threat_dashboard_instantiation(self):
        """ThreatDashboard can be instantiated."""
        from tui.dashboard import ThreatDashboard
        dash = ThreatDashboard()
        assert dash.findings == []
        assert dash.scans == []
        assert dash.hosts == []
        assert dash.markers == []

    def test_threat_dashboard_add_finding(self):
        """ThreatDashboard.add_finding adds to findings list."""
        from tui.dashboard import ThreatDashboard
        dash = ThreatDashboard()
        # Mock query_one to avoid Textual widget dependency
        with patch.object(dash, "query_one", return_value=MagicMock()):
            dash.add_finding("XSS", "high", "/api")
            assert len(dash.findings) == 1

    def test_threat_dashboard_add_finding_trims(self):
        """ThreatDashboard.add_finding trims when exceeding max * 2."""
        from tui.dashboard import ThreatDashboard
        dash = ThreatDashboard()
        with patch.object(dash, "query_one", return_value=MagicMock()):
            for i in range(200):
                dash.add_finding(f"Finding {i}")
            assert len(dash.findings) <= dash._max_findings * 2

    def test_threat_dashboard_add_threat(self):
        """ThreatDashboard.add_threat adds marker."""
        from tui.dashboard import ThreatDashboard
        dash = ThreatDashboard()
        with patch.object(dash, "query_one", return_value=MagicMock()):
            dash.add_threat(x=5, y=5, severity="high", label="test")
            assert len(dash.markers) == 1

    def test_threat_dashboard_add_threat_random(self):
        """ThreatDashboard.add_threat with random position."""
        from tui.dashboard import ThreatDashboard
        dash = ThreatDashboard()
        with patch.object(dash, "query_one", return_value=MagicMock()):
            dash.add_threat(severity="medium")
            assert len(dash.markers) == 1

    def test_threat_dashboard_add_scan(self):
        """ThreatDashboard.add_scan adds scan."""
        from tui.dashboard import ThreatDashboard
        dash = ThreatDashboard()
        with patch.object(dash, "query_one", return_value=MagicMock()):
            dash.add_scan("Recon", target="example.com", duration=120.0)
            assert len(dash.scans) == 1

    def test_threat_dashboard_add_host(self):
        """ThreatDashboard.add_host adds host."""
        from tui.dashboard import ThreatDashboard
        dash = ThreatDashboard()
        with patch.object(dash, "query_one", return_value=MagicMock()):
            dash.add_host("10.0.0.1", hostname="web", role="web", risk="medium")
            assert len(dash.hosts) == 1

    def test_threat_dashboard_update_stats(self):
        """ThreatDashboard.update_stats clamps values."""
        from tui.dashboard import ThreatDashboard
        dash = ThreatDashboard()
        with patch.object(dash, "query_one", return_value=MagicMock()):
            dash.update_stats(cpu=150.0, memory=-10.0, net_in=100, net_out=100)
            assert dash.stats.cpu == 100.0
            assert dash.stats.memory == 0.0
            assert dash.stats.net_in == 100.0

    def test_threat_dashboard_set_layout(self):
        """ThreatDashboard.set_layout changes layout."""
        from tui.dashboard import ThreatDashboard
        dash = ThreatDashboard()
        with patch.object(dash, "query_one", return_value=MagicMock()):
            dash.set_layout("compact")
            assert dash._current_layout == "compact"

    def test_threat_dashboard_set_layout_unknown(self):
        """ThreatDashboard.set_layout ignores unknown layout."""
        from tui.dashboard import ThreatDashboard
        dash = ThreatDashboard()
        with patch.object(dash, "query_one", return_value=MagicMock()):
            dash.set_layout("nonexistent")
            assert dash._current_layout == "default"

    def test_threat_dashboard_get_layout(self):
        """ThreatDashboard.get_layout returns current layout."""
        from tui.dashboard import ThreatDashboard
        dash = ThreatDashboard()
        assert dash.get_layout() == "default"

    def test_build_static_renderable(self):
        """build_static_renderable returns a Group."""
        from tui.dashboard import build_static_renderable
        from rich.console import Group
        result = build_static_renderable("DEFAULT", risk=73, target="example.com")
        assert isinstance(result, Group)

    def test_build_static_renderable_all_themes(self):
        """build_static_renderable works with all themes."""
        from tui.dashboard import build_static_renderable
        from tui.themes import THEMES
        for name in THEMES:
            result = build_static_renderable(name, risk=50, target="test")
            assert result is not None


# ============================================================================
# tui/main_menu.py tests
# ============================================================================


class TestMainMenu:
    """Tests for tui/main_menu.py module."""

    def test_menu_items_structure(self):
        """MENU_ITEMS has expected keys."""
        from tui.main_menu import MENU_ITEMS
        assert isinstance(MENU_ITEMS, dict)
        for key, item in MENU_ITEMS.items():
            assert "title" in item
            assert "description" in item
            assert "icon" in item
            assert "action" in item

    def test_menu_items_actions(self):
        """MENU_ITEMS has all expected actions."""
        from tui.main_menu import MENU_ITEMS
        expected_actions = ["scan", "recon", "tools", "reports", "memory", "settings", "help", "exit"]
        for action in expected_actions:
            assert action in MENU_ITEMS, f"Missing action: {action}"

    def test_scan_options_structure(self):
        """SCAN_OPTIONS has expected structure."""
        from tui.main_menu import SCAN_OPTIONS
        assert isinstance(SCAN_OPTIONS, list)
        assert len(SCAN_OPTIONS) >= 3
        for opt in SCAN_OPTIONS:
            assert "label" in opt
            assert "description" in opt
            assert "args" in opt

    def test_tool_categories_structure(self):
        """TOOL_CATEGORIES has expected structure."""
        from tui.main_menu import TOOL_CATEGORIES
        assert isinstance(TOOL_CATEGORIES, dict)
        for category, tools in TOOL_CATEGORIES.items():
            assert isinstance(tools, list)
            for tool in tools:
                assert "name" in tool
                assert "module" in tool
                assert "description" in tool

    def test_tool_categories_has_all(self):
        """TOOL_CATEGORIES has all expected categories."""
        from tui.main_menu import TOOL_CATEGORIES
        expected = ["Reconnaissance", "Vulnerability Scanning", "API Security",
                     "Business Logic", "Supply Chain"]
        for cat in expected:
            assert cat in TOOL_CATEGORIES, f"Missing category: {cat}"

    def test_settings_options_structure(self):
        """SETTINGS_OPTIONS has expected structure."""
        from tui.main_menu import SETTINGS_OPTIONS
        assert isinstance(SETTINGS_OPTIONS, list)
        assert len(SETTINGS_OPTIONS) >= 4
        for opt in SETTINGS_OPTIONS:
            assert "label" in opt
            assert "description" in opt

    def test_render_main_menu(self):
        """render_main_menu returns a Panel."""
        from tui.main_menu import render_main_menu
        result = render_main_menu()
        assert isinstance(result, Panel)

    def test_render_main_menu_custom_colors(self):
        """render_main_menu accepts custom colors."""
        from tui.main_menu import render_main_menu
        result = render_main_menu(primary="#00ff00", text_color="#ffffff", muted="#888888")
        assert isinstance(result, Panel)

    def test_render_scan_menu(self):
        """render_scan_menu returns a Panel."""
        from tui.main_menu import render_scan_menu
        result = render_scan_menu()
        assert isinstance(result, Panel)

    def test_render_scan_menu_custom_colors(self):
        """render_scan_menu accepts custom colors."""
        from tui.main_menu import render_scan_menu
        result = render_scan_menu(primary="#00ff00")
        assert isinstance(result, Panel)

    def test_render_tools_menu(self):
        """render_tools_menu returns a Panel."""
        from tui.main_menu import render_tools_menu
        result = render_tools_menu()
        assert isinstance(result, Panel)

    def test_render_tools_menu_custom_colors(self):
        """render_tools_menu accepts custom colors."""
        from tui.main_menu import render_tools_menu
        result = render_tools_menu(primary="#00ff00")
        assert isinstance(result, Panel)

    def test_render_settings_menu(self):
        """render_settings_menu returns a Panel."""
        from tui.main_menu import render_settings_menu
        result = render_settings_menu()
        assert isinstance(result, Panel)

    def test_render_settings_menu_custom_colors(self):
        """render_settings_menu accepts custom colors."""
        from tui.main_menu import render_settings_menu
        result = render_settings_menu(primary="#00ff00")
        assert isinstance(result, Panel)

    def test_run_main_menu_questionary_missing(self):
        """run_main_menu prints message when questionary not installed."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "questionary":
                raise ImportError("No module named 'questionary'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with patch("builtins.print") as mock_print:
                from tui.main_menu import run_main_menu
                run_main_menu()
                mock_print.assert_called_once()

    def test_run_scan_menu_questionary_missing(self):
        """run_scan_menu prints message when questionary not installed."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "questionary":
                raise ImportError("No module")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with patch("builtins.print") as mock_print:
                from tui.main_menu import run_scan_menu
                run_scan_menu()
                mock_print.assert_called()

    def test_run_tools_menu_questionary_missing(self):
        """run_tools_menu prints message when questionary not installed."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "questionary":
                raise ImportError("No module")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with patch("builtins.print") as mock_print:
                from tui.main_menu import run_tools_menu
                run_tools_menu()
                mock_print.assert_called()

    def test_run_settings_menu_questionary_missing(self):
        """run_settings_menu prints message when questionary not installed."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "questionary":
                raise ImportError("No module")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with patch("builtins.print") as mock_print:
                from tui.main_menu import run_settings_menu
                run_settings_menu()
                mock_print.assert_called()

    def test_run_memory_menu_questionary_missing(self):
        """run_memory_menu prints message when questionary not installed."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "questionary":
                raise ImportError("No module")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with patch("builtins.print") as mock_print:
                from tui.main_menu import run_memory_menu
                run_memory_menu()
                mock_print.assert_called()

    def test_run_recon_menu_questionary_missing(self):
        """run_recon_menu prints message when questionary not installed."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "questionary":
                raise ImportError("No module")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with patch("builtins.print") as mock_print:
                from tui.main_menu import run_recon_menu
                run_recon_menu()
                mock_print.assert_called()

    def test_run_reports_menu_questionary_missing(self):
        """run_reports_menu prints message when questionary not installed."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "questionary":
                raise ImportError("No module")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with patch("builtins.print") as mock_print:
                from tui.main_menu import run_reports_menu
                run_reports_menu()
                mock_print.assert_called()

    def test_run_theme_selector_questionary_missing(self):
        """run_theme_selector prints message when questionary not installed."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "questionary":
                raise ImportError("No module")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with patch("builtins.print") as mock_print:
                from tui.main_menu import run_theme_selector
                run_theme_selector()
                mock_print.assert_called()

    def test_all_exports(self):
        """__all__ contains expected symbols."""
        from tui.main_menu import __all__
        assert "MENU_ITEMS" in __all__
        assert "SCAN_OPTIONS" in __all__
        assert "TOOL_CATEGORIES" in __all__
        assert "SETTINGS_OPTIONS" in __all__
        assert "render_main_menu" in __all__
        assert "render_scan_menu" in __all__
        assert "render_tools_menu" in __all__
        assert "render_settings_menu" in __all__
        assert "run_main_menu" in __all__
        assert "run_help_menu" in __all__

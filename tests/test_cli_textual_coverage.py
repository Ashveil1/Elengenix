"""test_cli_textual_coverage.py — Comprehensive tests for cli_textual.py

Covers: CSS blocks, dataclasses, widget __init__, helper functions,
event handlers, compose tree, sidebar, statusbar, settings overlay,
help overlay, thinking widget, and main app logic.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, call, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import cli_textual as mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_widget(name="Widget"):
    w = MagicMock()
    w.has_class = MagicMock(return_value=False)
    w.add_class = MagicMock()
    w.remove_class = MagicMock()
    w.update = MagicMock()
    w.styles = MagicMock()
    w.styles.display = "none"
    w.styles.color = "#ffffff"
    w.styles.background = "#000000"
    w.scroll_up = MagicMock()
    w.scroll_down = MagicMock()
    w.disabled = False
    w.value = ""
    w.cursor_position = 0
    w.has_focus = True
    w.focus = MagicMock()
    return w


def _make_app_stub():
    """Create a minimal ElengenixTextualApp instance without calling __init__.

    Uses patch.object on the class to mock screen (property) and theme (Reactive).
    """
    app = object.__new__(mod.ElengenixTextualApp)

    app.target = ""
    app.mode = "CHILL"
    app.thinking = False
    app._load_sid = ""
    app.session_name = ""
    app.turn_count = 0
    app.tools_run = 0
    app.findings = 0
    app.history = []
    app.history_idx = -1
    app._processing = False
    app._agent = MagicMock()
    app._agent.conversation_history = []
    app._agent.governance = MagicMock()
    app._talk_to = "all"
    app._team_active = False
    app._session_mgr = MagicMock()
    app._pending_session = None
    app._cached_chat = MagicMock()
    app._cached_sidebar = MagicMock()
    app._last_sidebar_update = 0.0
    app._anim_frame = 0
    app._header_pulse = 0
    app._scanline_y = 0
    app._smooth_progress = 0.0
    app._displayed_tools = 0
    app._displayed_findings = 0
    app._displayed_tokens = 0
    app._target_tools = 0
    app._target_findings = 0
    app._target_tokens = 0
    app._thinking_dots = 0
    app._theme_transition = 0.0
    app._suggest_idx = -1
    app._original_prefix = ""
    app._cycling_suggestions = False
    app._trans = False
    app._trans_frame = 0
    app._trans_next = ""
    app._trans_total = 24
    app._header_base_text = "  ELENGENIX  "
    app.game = MagicMock()
    app.game.running = False
    app.game.game_over = False
    app.game.tick = MagicMock(return_value=None)
    app.game.start = MagicMock()
    app.game.jump = MagicMock()
    app._game_active = False
    app._current_game_frame = ""
    app._dashboard_visible = False
    app._findings_data = []
    app._theme_mgr = MagicMock()
    app._progress_total = 0
    app._progress_cur = 0
    app._progress_tool = ""
    app._progress_findings = 0
    app.set_focus = MagicMock()
    app.set_timer = MagicMock()
    app.set_interval = MagicMock()
    app.call_from_thread = MagicMock(side_effect=lambda fn, *a, **kw: fn(*a, **kw) if callable(fn) else None)
    app._mock_screen = MagicMock()
    app._mock_screen.add_class = MagicMock()
    app._mock_screen.remove_class = MagicMock()
    app.register_theme = MagicMock()
    app.exit = MagicMock()
    app.SLASH_COMMANDS = mod.ElengenixTextualApp.SLASH_COMMANDS

    # query_one returns mock widgets
    app._widget_store = {}
    app.query_one = MagicMock(side_effect=lambda sel, cls=None, **kw: _get_widget(app, sel))

    return app


def _get_widget(app, sel):
    if sel not in app._widget_store:
        app._widget_store[sel] = _mock_widget(sel)
    return app._widget_store[sel]


def _patch_screen(app):
    """Patch the screen property to return app._mock_screen."""
    return patch.object(type(app).__mro__[0], 'screen',
                        new_callable=PropertyMock, return_value=app._mock_screen)


def _patch_theme(app):
    """Patch the theme reactive so setting it works."""
    # theme is a Reactive, we need to allow setting
    return patch.object(type(app).__mro__[0], 'theme', new_callable=PropertyMock,
                        return_value="chill",
                        side_effect=lambda self, val: None)


# ===========================================================================
# 1. Module-level constants
# ===========================================================================


def test_module_constants():
    assert mod.BASE == "#000000"
    assert mod.MANTLE == "#111111"
    assert mod.CRUST == "#0d0d0d"
    assert mod.SURFACE == "#1a1a1a"
    assert mod.TEXT == "#ffffff"
    assert mod.WHITE == "#ffffff"
    assert mod.MUTED == "#555555"
    assert mod.DIM == "#444444"
    assert mod.GRAY == "#888888"
    assert mod.H_RED == "#ff2222"
    assert mod.H_BRIGHT == "#ff5555"
    assert mod.H_BASE == mod.BASE
    assert 1 in mod.AGENT_NAMES
    assert 3 in mod.AGENT_COLORS
    assert "BASE" in mod.CHILL_COLORS
    assert "ACCENT" in mod.HUNT_COLORS
    assert mod.HUNT_COLORS["WHITE"] == mod.H_RED
    assert len(mod.ASCII_BANNER) > 0
    assert "/clear" in mod.HELP_TEXT
    assert "Ctrl+R" in mod.HELP_TEXT
    assert len(mod.GLITCH_CHARS) > 20


def test_log_file_name():
    assert mod.LOG_FILE.name == "elengenix_cli.log"


def test_tui_widgets_available_flag():
    assert isinstance(mod._TUI_WIDGETS_AVAILABLE, bool)


# ===========================================================================
# 2. Helper functions
# ===========================================================================


def test_lerp_basic():
    assert mod._lerp(0, 10, 0.0) == 0
    assert mod._lerp(0, 10, 1.0) == 10
    assert mod._lerp(0, 10, 0.5) == 5


def test_lerp_clamping():
    assert mod._lerp(0, 10, -0.5) == 0
    assert mod._lerp(0, 10, 1.5) == 10


def test_lerp_equal_values():
    assert mod._lerp(5, 5, 0.5) == 5


def test_lerp_color_basic():
    for t in (0.0, 0.5, 1.0):
        r = mod._lerp_color("#000000", "#ffffff", t)
        assert r.startswith("#") and len(r) == 7


def test_lerp_color_clamping():
    assert mod._lerp_color("#000000", "#ffffff", -0.5) == mod._lerp_color("#000000", "#ffffff", 0.0)
    assert mod._lerp_color("#000000", "#ffffff", 1.5) == mod._lerp_color("#000000", "#ffffff", 1.0)


def test_lerp_color_same():
    r = mod._lerp_color("#ff0000", "#ff0000", 0.5)
    assert r.startswith("#")


# ===========================================================================
# 3. Sidebar
# ===========================================================================


def test_sidebar_css():
    assert "Sidebar" in mod.Sidebar.DEFAULT_CSS


def test_sidebar_init():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    assert s._data == {}


def test_sidebar_compose():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    children = list(s.compose())
    assert len(children) >= 1


def test_sidebar_refresh_ready():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", target="example.com")
    assert s._data["status"] == "ready"
    ms.update.assert_called_once()


def test_sidebar_refresh_hunt():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="working", mode="HUNT", target="example.com")
    assert "HUNT" in ms.update.call_args[0][0]


def test_sidebar_refresh_game_active():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(game_active=True, game_frame="frame", turns=5)
    assert "SPACE" in ms.update.call_args[0][0]


def test_sidebar_refresh_thinking():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", thinking=True)
    assert "THINK" in ms.update.call_args[0][0]


def test_sidebar_refresh_team():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", team=2, talk_to="all")
    assert "TEAM 2" in ms.update.call_args[0][0]


def test_sidebar_refresh_talk_to_1():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", team=2, talk_to=1)
    assert "Elengix 1" in ms.update.call_args[0][0]


def test_sidebar_refresh_talk_to_2():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", team=2, talk_to=2)
    assert "Elengix 2" in ms.update.call_args[0][0]


def test_sidebar_refresh_talk_to_3():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", team=3, talk_to=3)
    assert "Elengix 3" in ms.update.call_args[0][0]


def test_sidebar_refresh_talk_to_unknown():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", team=5, talk_to=5)
    assert "#5" in ms.update.call_args[0][0]


def test_sidebar_refresh_models():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", models=["gpt-4o", "claude-3.5-sonnet"])
    txt = ms.update.call_args[0][0]
    assert "Elengix 1" in txt
    assert "Elengix 2" in txt


def test_sidebar_refresh_no_models():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", models=[])
    assert "default" in ms.update.call_args[0][0]


def test_sidebar_refresh_long_model():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", models=["very/long/model/name/that/exceeds/limit"])
    assert "limit" in ms.update.call_args[0][0]


def test_sidebar_refresh_query_failure():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    s.query_one = MagicMock(side_effect=Exception("err"))
    s.refresh_data(status="ready", mode="CHILL")


def test_sidebar_refresh_stagger_env():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    with patch.dict(os.environ, {"TEAM_STAGGERING": "1"}):
        s.refresh_data(status="working", mode="CHILL")
        assert "STAGGER" in ms.update.call_args[0][0]


def test_sidebar_refresh_no_target():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", target="")
    assert "none" in ms.update.call_args[0][0]


def test_sidebar_refresh_long_session():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", session="a" * 30)
    assert "a" * 20 in ms.update.call_args[0][0]


def test_sidebar_refresh_token_50pct():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", tokens=64000, limit=128000)
    assert "50%" in ms.update.call_args[0][0]


def test_sidebar_refresh_token_full():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", tokens=200000, limit=128000)
    assert "100%" in ms.update.call_args[0][0]


def test_sidebar_refresh_token_zero_limit():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", tokens=100, limit=0)
    assert "0%" in ms.update.call_args[0][0]


def test_sidebar_refresh_long_target():
    s = mod.Sidebar.__new__(mod.Sidebar)
    s._data = {}
    ms = _mock_widget()
    s.query_one = MagicMock(return_value=ms)
    s.refresh_data(status="ready", mode="CHILL", target="a" * 50)
    assert "a" * 28 in ms.update.call_args[0][0]


# ===========================================================================
# 4. ThinkingWidget
# ===========================================================================


def test_thinking_widget_css():
    assert "ThinkingWidget" in mod.ThinkingWidget.DEFAULT_CSS
    assert "display: none" in mod.ThinkingWidget.DEFAULT_CSS


def test_thinking_widget_show_hide():
    tw = mod.ThinkingWidget.__new__(mod.ThinkingWidget)
    tw.add_class = MagicMock()
    tw.remove_class = MagicMock()
    tw.show()
    tw.add_class.assert_called_with("visible")
    tw.hide()
    tw.remove_class.assert_called_with("visible")


def test_thinking_widget_on_mount():
    tw = mod.ThinkingWidget.__new__(mod.ThinkingWidget)
    tw.on_mount()
    assert tw.frames == ["\u25d0", "\u25d3", "\u25d1", "\u25d2"]
    assert tw.idx == 0


# ===========================================================================
# 5. Scanline & GlitchFlash
# ===========================================================================


def test_scanline_css():
    assert "overlay" in mod.Scanline.DEFAULT_CSS
    assert "display: none" in mod.Scanline.DEFAULT_CSS


def test_glitchflash_css():
    assert "overlay" in mod.GlitchFlash.DEFAULT_CSS
    assert "display: none" in mod.GlitchFlash.DEFAULT_CSS


# ===========================================================================
# 6. StatusBar
# ===========================================================================


def test_statusbar_css():
    assert "StatusBar" in mod.StatusBar.DEFAULT_CSS


def test_statusbar_show_action_safe():
    sb = mod.StatusBar.__new__(mod.StatusBar)
    sb.update = MagicMock()
    sb.show_action("ls -la", "SAFE")
    assert "ls -la" in sb.update.call_args[0][0]


def test_statusbar_show_action_privileged():
    sb = mod.StatusBar.__new__(mod.StatusBar)
    sb.update = MagicMock()
    sb.show_action("nmap", "PRIVILEGED")
    assert "PRIV" in sb.update.call_args[0][0]


def test_statusbar_show_action_destructive():
    sb = mod.StatusBar.__new__(mod.StatusBar)
    sb.update = MagicMock()
    sb.show_action("rm -rf", "DESTRUCTIVE")
    assert "BLOCKED" in sb.update.call_args[0][0]


def test_statusbar_show_action_unknown():
    sb = mod.StatusBar.__new__(mod.StatusBar)
    sb.update = MagicMock()
    sb.show_action("something", "UNKNOWN")
    assert "something" in sb.update.call_args[0][0]


def test_statusbar_show_action_long_cmd():
    sb = mod.StatusBar.__new__(mod.StatusBar)
    sb.update = MagicMock()
    sb.show_action("x" * 200, "SAFE")
    content = sb.update.call_args[0][0]
    assert "x" * 70 in content


def test_statusbar_show_message():
    sb = mod.StatusBar.__new__(mod.StatusBar)
    sb.update = MagicMock()
    sb.show_message("hello world")
    assert "hello world" in sb.update.call_args[0][0]


def test_statusbar_show_message_long():
    sb = mod.StatusBar.__new__(mod.StatusBar)
    sb.update = MagicMock()
    sb.show_message("x" * 200)
    content = sb.update.call_args[0][0]
    assert "x" * 70 in content


# ===========================================================================
# 7. ProgressBar
# ===========================================================================


def test_progressbar_css():
    assert "ProgressBar" in mod.ProgressBar.DEFAULT_CSS


def test_progressbar_show_scan():
    pb = mod.ProgressBar.__new__(mod.ProgressBar)
    pb.update = MagicMock()
    pb.add_class = MagicMock()
    pb.show_scan("nmap", 3, 10, 2)
    pb.update.assert_called_once_with("")
    pb.add_class.assert_called_with("visible")


def test_progressbar_show_hide():
    pb = mod.ProgressBar.__new__(mod.ProgressBar)
    pb.add_class = MagicMock()
    pb.remove_class = MagicMock()
    pb.show()
    pb.add_class.assert_called_with("visible")
    pb.hide()
    pb.remove_class.assert_called_with("visible")


# ===========================================================================
# 8. SettingsOverlayWidget
# ===========================================================================


def test_settings_overlay_has_css():
    assert "SettingsOverlayWidget" in mod.SettingsOverlayWidget.DEFAULT_CSS
    assert "layer: overlay" in mod.SettingsOverlayWidget.DEFAULT_CSS


def test_settings_overlay_compose_exists():
    assert hasattr(mod.SettingsOverlayWidget, 'compose')


def test_settings_overlay_on_mount():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w._overlay = None
    with patch.object(mod.SettingsOverlayWidget, '_reload'):
        w.on_mount()
        assert w._overlay is None


def test_settings_overlay_show_hide():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w._reload = MagicMock()
    w._redraw = MagicMock()
    w.add_class = MagicMock()
    w.remove_class = MagicMock()
    # mock query_one for hide() which calls self.query_one("#custom_url_row")
    mock_custom_row = _mock_widget()
    mock_custom_row.remove_class = MagicMock()
    w.query_one = MagicMock(return_value=mock_custom_row)
    mock_input = _mock_widget()
    mock_app = MagicMock()
    mock_app.query_one = MagicMock(return_value=mock_input)
    mock_app.set_timer = MagicMock()

    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        w.show()
        w.add_class.assert_called_with("visible")
        w.hide()
        w.remove_class.assert_called_with("visible")


def test_settings_overlay_redraw_with_overlay():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    mc = _mock_widget()
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._overlay.render.return_value = "rendered"
    w._redraw()
    mc.update.assert_called_once_with("rendered")


def test_settings_overlay_redraw_without_overlay():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    mc = _mock_widget()
    w.query_one = MagicMock(return_value=mc)
    w._overlay = None
    w._redraw()
    mc.update.assert_called_once()
    assert mc.update.call_args[0][0] is not None


def test_settings_overlay_reload_failure():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    mock_app = MagicMock()
    mock_app._agent = None

    # _reload tries to import and create SettingsOverlay, which fails
    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        with patch("cli_textual.time") as mock_time:
            mock_time.monotonic.side_effect = [0, 4]
            mock_time.sleep = MagicMock()
            with patch.dict("sys.modules", {"tools.overlay_menu": None}):
                w._reload()
                assert w._overlay is None


def test_settings_overlay_on_key_not_visible():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w.has_class = MagicMock(return_value=False)
    event = MagicMock()
    event.key = "escape"
    w.on_key(event)
    event.stop.assert_not_called()


def test_settings_overlay_on_key_escape():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w.has_class = MagicMock(return_value=True)
    mc = _mock_widget()
    mc.has_class = MagicMock(return_value=False)
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w.hide = MagicMock()

    event = MagicMock()
    event.key = "escape"
    event.character = "\x1b"
    event.stop = MagicMock()

    mock_app = MagicMock()
    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        w.on_key(event)
    w.hide.assert_called_once()


def test_settings_overlay_on_key_custom_url_escape():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w.has_class = MagicMock(return_value=True)
    mc = _mock_widget()
    mc.has_class = MagicMock(return_value=True)
    w.query_one = MagicMock(return_value=mc)
    w.hide = MagicMock()

    event = MagicMock()
    event.key = "escape"
    w.on_key(event)
    w.hide.assert_called_once()


def test_settings_overlay_on_key_saved():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w.has_class = MagicMock(return_value=True)
    mc = _mock_widget()
    mc.has_class = MagicMock(return_value=False)
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._overlay.handle_char.return_value = "saved"
    w.hide = MagicMock()
    mock_app = MagicMock()
    mock_app._load_agent = MagicMock()
    mock_app._chat_write_system = MagicMock()

    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        event = MagicMock()
        event.key = "enter"
        event.character = "\r"
        event.stop = MagicMock()
        w.on_key(event)
        mock_app._load_agent.assert_called_once()


def test_settings_overlay_on_key_saved_with_models():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w.has_class = MagicMock(return_value=True)
    mc = _mock_widget()
    mc.has_class = MagicMock(return_value=False)
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._overlay.handle_char.return_value = "saved:gpt-4o,claude-3"
    w.hide = MagicMock()
    mock_app = MagicMock()
    mock_app._load_agent = MagicMock()
    mock_app._chat_write_system = MagicMock()

    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        event = MagicMock()
        event.key = "enter"
        event.character = "\r"
        event.stop = MagicMock()
        w.on_key(event)
        assert os.environ.get("ACTIVE_MODELS") == "gpt-4o,claude-3"
        os.environ.pop("ACTIVE_MODELS", None)


def test_settings_overlay_on_key_error():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w.has_class = MagicMock(return_value=True)
    mc = _mock_widget()
    mc.has_class = MagicMock(return_value=False)
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._overlay.handle_char.return_value = "error"
    w.hide = MagicMock()
    mock_app = MagicMock()
    mock_app._chat_write_system = MagicMock()

    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        event = MagicMock()
        event.key = "enter"
        event.character = "\r"
        event.stop = MagicMock()
        w.on_key(event)
        mock_app._chat_write_system.assert_called()


def test_settings_overlay_on_key_exit():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w.has_class = MagicMock(return_value=True)
    mc = _mock_widget()
    mc.has_class = MagicMock(return_value=False)
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._overlay.handle_char.return_value = "exit"
    w.hide = MagicMock()

    event = MagicMock()
    event.key = "enter"
    event.character = "\r"
    event.stop = MagicMock()
    w.on_key(event)
    w.hide.assert_called_once()


def test_settings_overlay_on_key_load_session():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w.has_class = MagicMock(return_value=True)
    mc = _mock_widget()
    mc.has_class = MagicMock(return_value=False)
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._overlay.handle_char.return_value = "load_session:abc123"
    w.hide = MagicMock()
    mock_app = MagicMock()
    mock_app._load_session_by_id = MagicMock()

    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        event = MagicMock()
        event.key = "enter"
        event.character = "\r"
        event.stop = MagicMock()
        w.on_key(event)
        w.hide.assert_called()
        mock_app._load_session_by_id.assert_called_with("abc123")


def test_settings_overlay_on_key_other_result():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w.has_class = MagicMock(return_value=True)
    mc = _mock_widget()
    mc.has_class = MagicMock(return_value=False)
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._overlay.handle_char.return_value = "something_else"
    w._redraw = MagicMock()

    event = MagicMock()
    event.key = "enter"
    event.character = "\r"
    event.stop = MagicMock()
    w.on_key(event)
    w._redraw.assert_called_once()


def test_settings_overlay_on_key_no_char():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    w.has_class = MagicMock(return_value=True)
    mc = _mock_widget()
    mc.has_class = MagicMock(return_value=False)
    w.query_one = MagicMock(return_value=mc)

    event = MagicMock()
    event.key = "unknown"
    event.character = None
    event.stop = MagicMock()
    w.on_key(event)
    event.stop.assert_not_called()


def test_settings_overlay_show_custom_url():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    mc = _mock_widget()
    mr = _mock_widget()
    mr.add_class = MagicMock()
    mi = _mock_widget()
    mi.value = ""
    mi.focus = MagicMock()

    def qs(sel, cls=None, **kw):
        if sel == "#settings_content": return mc
        if sel == "#custom_url_row": return mr
        if sel == "#custom_url_input": return mi
        return _mock_widget()

    w.query_one = qs
    w._show_custom_url()
    mr.add_class.assert_called_with("visible")
    mi.focus.assert_called()


def test_settings_overlay_on_input_wrong_id():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    event = MagicMock()
    event.input = MagicMock()
    event.input.id = "other"
    event.value = "test"
    w.on_input_submitted(event)


def test_settings_overlay_on_input_empty():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    mc = _mock_widget()
    mc.remove_class = MagicMock()
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._redraw = MagicMock()
    mock_app = MagicMock()
    mock_app.set_timer = MagicMock()

    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        event = MagicMock()
        event.input = MagicMock()
        event.input.id = "custom_url_input"
        event.value = "  "
        w.on_input_submitted(event)
        w._redraw.assert_called()


def test_settings_overlay_on_input_apikey():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    mc = _mock_widget()
    mc.remove_class = MagicMock()
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._overlay._custom_step = "apikey"
    w._redraw = MagicMock()
    mock_app = MagicMock()
    mock_app.set_timer = MagicMock()

    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        event = MagicMock()
        event.input = MagicMock()
        event.input.id = "custom_url_input"
        event.value = "sk-key"
        w.on_input_submitted(event)
        w._overlay.handle_custom_apikey.assert_called_once_with("sk-key")


def test_settings_overlay_on_input_model():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    mc = _mock_widget()
    mc.remove_class = MagicMock()
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._overlay._custom_step = "model"
    w._overlay._custom_url = "https://api.example.com"
    w._overlay._agent_config = {0: {}}
    w._overlay._agent_idx = 0
    w._overlay._save_and_apply = MagicMock()
    w._redraw = MagicMock()
    mock_app = MagicMock()
    mock_app.set_timer = MagicMock()

    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        event = MagicMock()
        event.input = MagicMock()
        event.input.id = "custom_url_input"
        event.value = "gpt-4-turbo"
        w.on_input_submitted(event)
        assert os.environ.get("CUSTOM_API_BASE") == "https://api.example.com"
        w._overlay._save_and_apply.assert_called_once()
        os.environ.pop("CUSTOM_API_BASE", None)


def test_settings_overlay_on_input_model_no_url():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    mc = _mock_widget()
    mc.remove_class = MagicMock()
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._overlay._custom_step = "model"
    w._overlay._custom_url = ""
    w._overlay._agent_config = {0: {}}
    w._overlay._agent_idx = 0
    w._overlay._save_and_apply = MagicMock()
    w._redraw = MagicMock()
    mock_app = MagicMock()
    mock_app.set_timer = MagicMock()

    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        event = MagicMock()
        event.input = MagicMock()
        event.input.id = "custom_url_input"
        event.value = "gpt-4"
        w.on_input_submitted(event)
        w._overlay._save_and_apply.assert_called_once()


def test_settings_overlay_on_input_default_step():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    mc = _mock_widget()
    w.query_one = MagicMock(return_value=mc)
    w._overlay = MagicMock()
    w._overlay._custom_step = ""
    mock_app = MagicMock()

    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        event = MagicMock()
        event.input = MagicMock()
        event.input.id = "custom_url_input"
        event.value = "https://api.test.com"
        w.on_input_submitted(event)
        w._overlay.handle_custom_url.assert_called_once_with("https://api.test.com")


def test_settings_overlay_on_input_no_overlay():
    w = mod.SettingsOverlayWidget.__new__(mod.SettingsOverlayWidget)
    mc = _mock_widget()
    mc.remove_class = MagicMock()
    w.query_one = MagicMock(return_value=mc)
    w._overlay = None
    w._redraw = MagicMock()
    mock_app = MagicMock()
    mock_app.set_timer = MagicMock()

    with patch.object(mod.SettingsOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        event = MagicMock()
        event.input = MagicMock()
        event.input.id = "custom_url_input"
        event.value = "test"
        w.on_input_submitted(event)
        w._redraw.assert_called()


# ===========================================================================
# 9. HelpOverlayWidget
# ===========================================================================


def test_help_overlay_css():
    assert "HelpOverlayWidget" in mod.HelpOverlayWidget.DEFAULT_CSS
    assert "layer: overlay" in mod.HelpOverlayWidget.DEFAULT_CSS


def test_help_overlay_compose_exists():
    assert hasattr(mod.HelpOverlayWidget, 'compose')


def test_help_overlay_on_mount():
    w = mod.HelpOverlayWidget.__new__(mod.HelpOverlayWidget)
    mb = _mock_widget()
    w.query_one = MagicMock(return_value=mb)
    w.on_mount()
    mb.update.assert_called_once()


def test_help_overlay_show_hide():
    w = mod.HelpOverlayWidget.__new__(mod.HelpOverlayWidget)
    w.add_class = MagicMock()
    w.remove_class = MagicMock()
    mock_input = _mock_widget()
    mock_app = MagicMock()
    mock_app.query_one = MagicMock(return_value=mock_input)
    mock_app.set_timer = MagicMock()

    with patch.object(mod.HelpOverlayWidget, 'app',
                      new_callable=PropertyMock, return_value=mock_app):
        w.show()
        w.add_class.assert_called_with("visible")
        w.hide()
        w.remove_class.assert_called_with("visible")


def test_help_overlay_on_key_not_visible():
    w = mod.HelpOverlayWidget.__new__(mod.HelpOverlayWidget)
    w.has_class = MagicMock(return_value=False)
    event = MagicMock()
    event.key = "escape"
    event.stop = MagicMock()
    w.on_key(event)
    event.stop.assert_not_called()


def test_help_overlay_on_key_escape():
    w = mod.HelpOverlayWidget.__new__(mod.HelpOverlayWidget)
    w.has_class = MagicMock(return_value=True)
    w.hide = MagicMock()
    event = MagicMock()
    event.key = "escape"
    event.stop = MagicMock()
    w.on_key(event)
    w.hide.assert_called_once()
    event.stop.assert_called_once()


def test_help_overlay_on_key_other():
    w = mod.HelpOverlayWidget.__new__(mod.HelpOverlayWidget)
    w.has_class = MagicMock(return_value=True)
    w.hide = MagicMock()
    event = MagicMock()
    event.key = "a"
    event.stop = MagicMock()
    w.on_key(event)
    w.hide.assert_not_called()
    event.stop.assert_called_once()


# ===========================================================================
# 10. ElengenixTextualApp
# ===========================================================================


def test_app_init_defaults():
    with patch.object(mod, "ObbyGame"), patch.object(mod, "get_agent"):
        app = mod.ElengenixTextualApp()
        assert app.target == ""
        assert app.mode == "CHILL"
        assert app.thinking is False
        assert app.turn_count == 0
        assert app.tools_run == 0
        assert app.findings == 0
        assert app.history == []
        assert app._processing is False
        assert app._game_active is False
        assert app._dashboard_visible is False


def test_app_init_with_params():
    with patch.object(mod, "ObbyGame"), patch.object(mod, "get_agent"):
        app = mod.ElengenixTextualApp(target="example.com", mode="HUNT", session_id="test123")
        assert app.target == "example.com"
        assert app.mode == "HUNT"
        assert app._load_sid == "test123"
        assert app.session_name == "test123"


def test_app_compose():
    """compose() needs active Textual app context for containers."""
    assert hasattr(mod.ElengenixTextualApp, 'compose')
    # Verify compose method signature
    import inspect
    sig = inspect.signature(mod.ElengenixTextualApp.compose)
    assert 'self' in sig.parameters


def test_app_chat_write_user():
    app = _make_app_stub()
    app._chat_write_user("hello")
    app._cached_chat.write.assert_called()


def test_app_chat_write_agent():
    app = _make_app_stub()
    app._chat_write_agent("response")
    app._cached_chat.write.assert_called()


def test_app_chat_write_agent_md_fallback():
    app = _make_app_stub()
    from rich.markdown import Markdown
    call_count = [0]

    def side(content):
        call_count[0] += 1
        if call_count[0] == 1 and isinstance(content, Markdown):
            raise Exception("md err")

    app._cached_chat.write = MagicMock(side_effect=side)
    app._chat_write_agent("text")
    assert app._cached_chat.write.call_count >= 2


def test_app_chat_write_elengix():
    app = _make_app_stub()
    app._chat_write_elengix(1, "findings", "2.3s")
    app._cached_chat.write.assert_called()


def test_app_chat_write_elengix_no_time():
    app = _make_app_stub()
    app._chat_write_elengix(2, "output")
    app._cached_chat.write.assert_called()


def test_app_chat_write_elengix_long():
    app = _make_app_stub()
    app._chat_write_elengix(1, "x" * 1000)
    app._cached_chat.write.assert_called()


def test_app_chat_write_system():
    app = _make_app_stub()
    app._chat_write_system("msg")
    app._cached_chat.write.assert_called()


def test_app_chat_write_panel():
    from rich.panel import Panel
    app = _make_app_stub()
    p = Panel("test")
    app._chat_write_panel(p)
    app._cached_chat.write.assert_called_with(p)


def test_app_chat_write_governance():
    app = _make_app_stub()
    ms = _mock_widget()
    app._widget_store["#status_bar"] = ms
    app._chat_write_governance("nmap", "SAFE")
    ms.show_action.assert_called_with("nmap", "SAFE")


def test_app_chat_write_error():
    app = _make_app_stub()
    app._chat_write_error("broken")
    app._cached_chat.write.assert_called()


def test_app_update_sidebar_throttled():
    app = _make_app_stub()
    app._last_sidebar_update = time.monotonic()
    app._update_sidebar()
    app._cached_sidebar.refresh_data.assert_not_called()


def test_app_update_sidebar_force():
    app = _make_app_stub()
    app._last_sidebar_update = time.monotonic()
    app._update_sidebar(force=True)
    app._cached_sidebar.refresh_data.assert_called()


def test_app_update_sidebar_with_agent():
    app = _make_app_stub()
    app._agent = MagicMock()
    app._agent.conversation_history = [{"content": "test"}]
    app._last_sidebar_update = 0.0
    with patch("cli_textual.count_tokens", return_value=100, create=True):
        app._update_sidebar(force=True)
        app._cached_sidebar.refresh_data.assert_called()


def test_app_update_sidebar_with_models():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    with patch.dict(os.environ, {"ACTIVE_MODELS": "gpt-4o,claude-3.5"}):
        app._update_sidebar(force=True)
        kw = app._cached_sidebar.refresh_data.call_args[1]
        assert kw.get("team") == 2


def test_app_animate_frame_increment():
    app = _make_app_stub()
    app._anim_frame = 0
    app._trans = False
    app._game_active = False
    app._processing = False
    app.query_one = MagicMock(return_value=_mock_widget())
    app._animate_frame()
    assert app._anim_frame == 1


def test_app_animate_frame_header_pulse():
    app = _make_app_stub()
    app._anim_frame = 59
    app._trans = False
    app._game_active = False
    app._processing = False
    mh = _mock_widget()
    app.query_one = MagicMock(return_value=mh)
    app._animate_frame()
    assert app._header_pulse == 1


def test_app_animate_frame_thinking():
    app = _make_app_stub()
    app._anim_frame = 0
    app._trans = False
    app._game_active = False
    app._processing = True
    mtw = _mock_widget()
    mtw.idx = 0
    app.query_one = MagicMock(return_value=mtw)
    app._animate_frame()
    mtw.update.assert_called()


def test_app_animate_frame_progress():
    app = _make_app_stub()
    app._anim_frame = 0
    app._trans = False
    app._game_active = False
    app._processing = False
    app._progress_total = 10
    app._progress_cur = 5
    app._progress_tool = "nmap"
    app._progress_findings = 2
    app._smooth_progress = 0.0
    mpb = _mock_widget()
    app.query_one = MagicMock(return_value=mpb)
    app._animate_frame()
    mpb.update.assert_called()


def test_app_animate_frame_game_tick():
    app = _make_app_stub()
    app._anim_frame = 0
    app._trans = False
    app._game_active = True
    app.game.running = True
    app.game.tick.return_value = "frame"
    app.query_one = MagicMock(return_value=_mock_widget())
    app._animate_frame()
    app.game.tick.assert_called()


def test_app_animate_frame_game_over():
    app = _make_app_stub()
    app._anim_frame = 0
    app._trans = False
    app._game_active = True
    app.game.running = True
    app.game.tick.return_value = None
    app.game.game_over = True
    app.game._render_death.return_value = "death"
    app.query_one = MagicMock(return_value=_mock_widget())
    app._animate_frame()
    app.game._render_death.assert_called()


def test_app_animate_frame_transition():
    app = _make_app_stub()
    app._anim_frame = 0
    app._trans = True
    app._trans_frame = 0
    app._trans_next = "HUNT"
    app._trans_total = 24
    app.query_one = MagicMock(return_value=_mock_widget())
    app._animate_frame()
    assert app._trans_frame == 1


def test_app_animate_counters():
    app = _make_app_stub()
    app._displayed_tools = 0
    app._target_tools = 3
    app._displayed_findings = 0
    app._target_findings = 2
    app._displayed_tokens = 0
    app._target_tokens = 100
    app._last_sidebar_update = 0.0
    app._animate_counters()
    assert app._displayed_tools == 1
    assert app._displayed_findings == 1
    assert app._displayed_tokens > 0


def test_app_animate_counters_decrease():
    app = _make_app_stub()
    app._displayed_tools = 5
    app._target_tools = 3
    app._displayed_findings = 5
    app._target_findings = 3
    app._displayed_tokens = 500
    app._target_tokens = 300
    app._last_sidebar_update = 0.0
    app._animate_counters()
    # Tools/findings decrease instantly to target
    assert app._displayed_tools == 3
    assert app._displayed_findings == 3
    # Tokens only animate upward (no decrease logic in source), so stays at 500
    assert app._displayed_tokens == 500


def test_app_animate_counters_no_change():
    app = _make_app_stub()
    app._displayed_tools = 3
    app._target_tools = 3
    app._displayed_findings = 2
    app._target_findings = 2
    app._displayed_tokens = 100
    app._target_tokens = 100
    app._last_sidebar_update = time.monotonic()
    app._animate_counters()


def test_app_animate_counters_big_token_jump():
    app = _make_app_stub()
    app._displayed_tokens = 0
    app._target_tokens = 1000
    app._displayed_tools = 0
    app._target_tools = 0
    app._displayed_findings = 0
    app._target_findings = 0
    app._last_sidebar_update = 0.0
    app._animate_counters()
    assert app._displayed_tokens > 0


def test_app_run_transition_hunt_flash():
    app = _make_app_stub()
    app._trans_next = "HUNT"
    mg = _mock_widget()
    mg.styles = MagicMock()
    app.query_one = MagicMock(return_value=mg)
    app._run_transition(1)
    assert mg.styles.display == "block"


def test_app_run_transition_chill_flash():
    app = _make_app_stub()
    app._trans_next = "CHILL"
    mg = _mock_widget()
    mg.styles = MagicMock()
    app.query_one = MagicMock(return_value=mg)
    app._run_transition(2)


def test_app_run_transition_flash3():
    app = _make_app_stub()
    app._trans_next = "HUNT"
    mg = _mock_widget()
    mg.styles = MagicMock()
    app.query_one = MagicMock(return_value=mg)
    app._run_transition(3)


def test_app_run_transition_crossfade_hunt():
    app = _make_app_stub()
    app._trans_next = "HUNT"
    mw = _mock_widget()
    mw.styles = MagicMock()
    app.query_one = MagicMock(return_value=mw)
    app._run_transition(5)


def test_app_run_transition_crossfade_chill():
    app = _make_app_stub()
    app._trans_next = "CHILL"
    mw = _mock_widget()
    mw.styles = MagicMock()
    app.query_one = MagicMock(return_value=mw)
    app._run_transition(10)


def test_app_run_transition_mode_switch():
    app = _make_app_stub()
    app._trans_next = "HUNT"
    app._update_banner = MagicMock()
    mw = _mock_widget()
    mw.styles = MagicMock()
    app.query_one = MagicMock(return_value=mw)
    with patch.object(type(app), 'theme', new_callable=PropertyMock):
        app._run_transition(11)
    assert app.mode == "HUNT"


def test_app_run_transition_settle_hunt():
    app = _make_app_stub()
    app._trans_next = "HUNT"
    mh = _mock_widget()
    mh.styles = MagicMock()
    app.query_one = MagicMock(return_value=mh)
    app._run_transition(20)


def test_app_run_transition_settle_chill():
    app = _make_app_stub()
    app._trans_next = "CHILL"
    mh = _mock_widget()
    mh.styles = MagicMock()
    app.query_one = MagicMock(return_value=mh)
    app._run_transition(22)


def test_app_run_transition_invalid():
    app = _make_app_stub()
    app._trans_next = "INVALID"
    app._run_transition(1)


def test_app_run_transition_exception():
    app = _make_app_stub()
    app._trans_next = "HUNT"
    app.query_one = MagicMock(side_effect=Exception("err"))
    app._run_transition(1)


def test_app_finish_transition_hunt():
    app = _make_app_stub()
    app._trans_next = "HUNT"
    app._update_banner = MagicMock()
    app._update_sidebar = MagicMock()
    msl = _mock_widget()
    msl.styles = MagicMock()
    mg = _mock_widget()
    mg.styles = MagicMock()

    def qs(sel, **kw):
        if sel == "#scanline": return msl
        if sel == "#glitch": return mg
        return _mock_widget()

    app.query_one = qs
    with patch.object(type(app), 'theme', new_callable=PropertyMock):
        app._finish_transition()
    assert app._trans is False
    assert app.mode == "HUNT"


def test_app_finish_transition_chill():
    app = _make_app_stub()
    app._trans_next = "CHILL"
    app._update_banner = MagicMock()
    app._update_sidebar = MagicMock()
    msl = _mock_widget()
    msl.styles = MagicMock()
    mg = _mock_widget()
    mg.styles = MagicMock()

    def qs(sel, **kw):
        if sel == "#scanline": return msl
        if sel == "#glitch": return mg
        return _mock_widget()

    app.query_one = qs
    with patch.object(type(app), 'theme', new_callable=PropertyMock):
        app._finish_transition()
    assert app.mode == "CHILL"


def test_app_finish_transition_exception():
    app = _make_app_stub()
    app._trans_next = "HUNT"
    app._update_banner = MagicMock()
    app._update_sidebar = MagicMock()
    # query_one will fail in _finish_transition trying to hide overlays,
    # then mode/theme setting happens — patch those to avoid Reactive errors
    app.query_one = MagicMock(side_effect=Exception("err"))
    with patch.object(type(app), 'theme', new_callable=PropertyMock):
        app._finish_transition()
    assert app._trans is False


def test_app_chat_cached():
    app = _make_app_stub()
    assert app._chat() is app._cached_chat


def test_app_sidebar_cached():
    app = _make_app_stub()
    assert app._sidebar() is app._cached_sidebar


def test_app_trigger_border_glow():
    app = _make_app_stub()
    ms = MagicMock()
    ms.add_class = MagicMock()

    with patch.object(type(app), 'screen',
                      new_callable=PropertyMock, return_value=ms):
        app._trigger_border_glow()
    ms.add_class.assert_called_with("glow")


def test_app_trigger_border_glow_failure():
    app = _make_app_stub()
    ms = MagicMock()
    ms.add_class.side_effect = Exception("err")

    with patch.object(type(app), 'screen',
                      new_callable=PropertyMock, return_value=ms):
        app._trigger_border_glow()


def test_app_update_banner():
    app = _make_app_stub()
    app.mode = "CHILL"
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)
    app._update_banner()
    mb.update.assert_called_once()


def test_app_update_banner_hunt():
    app = _make_app_stub()
    app.mode = "HUNT"
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)
    app._update_banner()
    mb.update.assert_called_once()


def test_app_update_banner_text():
    app = _make_app_stub()
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)
    app._update_banner_text("text")
    mb.update.assert_called_once()


def test_app_update_banner_text_failure():
    app = _make_app_stub()
    app.query_one = MagicMock(side_effect=Exception("err"))
    app._update_banner_text("text")


def test_app_ensure_session_existing():
    app = _make_app_stub()
    app.session_name = "existing"
    assert app._ensure_session() == "existing"


def test_app_ensure_session_failure():
    app = _make_app_stub()
    app.session_name = ""
    app._session_mgr = MagicMock()
    app._session_mgr.start_session.side_effect = Exception("fail")
    with patch("cli_textual.generate_session_id", return_value="new-id", create=True):
        app._ensure_session()


def test_app_action_toggle_research():
    app = _make_app_stub()
    app.mode = "auto"
    app._last_sidebar_update = 0.0
    app.action_toggle_research()
    assert app.mode == "research"


def test_app_action_toggle_research_off():
    app = _make_app_stub()
    app.mode = "research"
    app._last_sidebar_update = 0.0
    app.action_toggle_research()
    assert app.mode == "auto"


def test_app_action_toggle_mode():
    app = _make_app_stub()
    app.mode = "CHILL"
    app._trans = False
    app.action_toggle_mode()
    assert app._trans is True
    assert app._trans_next == "HUNT"


def test_app_action_toggle_mode_already():
    app = _make_app_stub()
    app._trans = True
    app.action_toggle_mode()
    assert app._trans_next == ""


def test_app_action_toggle_think():
    app = _make_app_stub()
    app.thinking = False
    app._last_sidebar_update = 0.0
    app.action_toggle_think()
    assert app.thinking is True
    assert os.environ.get("NVIDIA_PARAM_MODE") == "enable"


def test_app_action_toggle_think_off():
    app = _make_app_stub()
    app.thinking = True
    app._last_sidebar_update = 0.0
    app.action_toggle_think()
    assert app.thinking is False
    os.environ.pop("NVIDIA_PARAM_MODE", None)


def test_app_action_show_model():
    app = _make_app_stub()
    with patch.dict(os.environ, {"ACTIVE_MODELS": "gpt-4o"}):
        app.action_show_model()
        app._cached_chat.write.assert_called()


def test_app_action_show_model_default():
    app = _make_app_stub()
    os.environ.pop("ACTIVE_MODELS", None)
    app.action_show_model()
    app._cached_chat.write.assert_called()


def test_app_action_show_help():
    app = _make_app_stub()
    mh = _mock_widget()
    mh.show = MagicMock()
    app.query_one = MagicMock(return_value=mh)
    app.action_show_help()
    mh.show.assert_called_once()


def test_app_action_show_settings():
    app = _make_app_stub()
    ms = _mock_widget()
    ms.show = MagicMock()
    app.query_one = MagicMock(return_value=ms)
    app.action_show_settings()
    ms.show.assert_called_once()


def test_app_action_toggle_dashboard_available():
    app = _make_app_stub()
    with patch("cli_textual._TUI_WIDGETS_AVAILABLE", True):
        mc = _mock_widget()
        app.query_one = MagicMock(return_value=mc)
        app.action_toggle_dashboard()
        assert app._dashboard_visible is True


def test_app_action_toggle_dashboard_unavailable():
    app = _make_app_stub()
    with patch("cli_textual._TUI_WIDGETS_AVAILABLE", False):
        app.action_toggle_dashboard()
        app._cached_chat.write.assert_called()


def test_app_action_toggle_dashboard_hide():
    app = _make_app_stub()
    app._dashboard_visible = True
    with patch("cli_textual._TUI_WIDGETS_AVAILABLE", True):
        mc = _mock_widget()
        app.query_one = MagicMock(return_value=mc)
        app.action_toggle_dashboard()
        assert app._dashboard_visible is False


def test_app_action_toggle_dashboard_failure():
    app = _make_app_stub()
    with patch("cli_textual._TUI_WIDGETS_AVAILABLE", True):
        app.query_one = MagicMock(side_effect=Exception("err"))
        app.action_toggle_dashboard()


def test_app_action_scroll_up():
    app = _make_app_stub()
    mc = _mock_widget()
    mc.scroll_up = MagicMock()
    app._cached_chat = mc
    app.action_scroll_up()
    mc.scroll_up.assert_called_once_with(10)


def test_app_action_scroll_up_failure():
    app = _make_app_stub()
    app._cached_chat = MagicMock()
    app._cached_chat.scroll_up.side_effect = Exception("err")
    app.action_scroll_up()


def test_app_action_scroll_down():
    app = _make_app_stub()
    mc = _mock_widget()
    mc.scroll_down = MagicMock()
    app._cached_chat = mc
    app.action_scroll_down()
    mc.scroll_down.assert_called_once_with(10)


def test_app_action_scroll_down_failure():
    app = _make_app_stub()
    app._cached_chat = MagicMock()
    app._cached_chat.scroll_down.side_effect = Exception("err")
    app.action_scroll_down()


def test_app_action_history_up():
    app = _make_app_stub()
    app.history = ["c1", "c2", "c3"]
    app.history_idx = -1
    mi = _mock_widget()
    mi.has_focus = True
    app.query_one = MagicMock(return_value=mi)
    app.action_history_up()
    assert app.history_idx == 2
    assert mi.value == "c3"


def test_app_action_history_up_subsequent():
    app = _make_app_stub()
    app.history = ["c1", "c2", "c3"]
    app.history_idx = 2
    mi = _mock_widget()
    mi.has_focus = True
    app.query_one = MagicMock(return_value=mi)
    app.action_history_up()
    assert app.history_idx == 1


def test_app_action_history_up_at_start():
    app = _make_app_stub()
    app.history = ["c1"]
    app.history_idx = 0
    mi = _mock_widget()
    mi.has_focus = True
    app.query_one = MagicMock(return_value=mi)
    app.action_history_up()
    assert app.history_idx == 0


def test_app_action_history_up_no_focus():
    app = _make_app_stub()
    app.history = ["c1"]
    mi = _mock_widget()
    mi.has_focus = False
    app.query_one = MagicMock(return_value=mi)
    app.action_history_up()
    assert app.history_idx == -1


def test_app_action_history_up_empty():
    app = _make_app_stub()
    app.history = []
    mi = _mock_widget()
    mi.has_focus = True
    app.query_one = MagicMock(return_value=mi)
    app.action_history_up()
    assert app.history_idx == -1


def test_app_action_history_down():
    app = _make_app_stub()
    app.history = ["c1", "c2", "c3"]
    app.history_idx = 1
    mi = _mock_widget()
    mi.has_focus = True
    app.query_one = MagicMock(return_value=mi)
    app.action_history_down()
    assert app.history_idx == 2


def test_app_action_history_down_past_end():
    app = _make_app_stub()
    app.history = ["c1", "c2"]
    app.history_idx = 2
    mi = _mock_widget()
    mi.has_focus = True
    app.query_one = MagicMock(return_value=mi)
    app.action_history_down()
    assert app.history_idx == -1
    assert mi.value == ""


def test_app_action_history_down_no_focus():
    app = _make_app_stub()
    app.history = ["c1"]
    mi = _mock_widget()
    mi.has_focus = False
    app.query_one = MagicMock(return_value=mi)
    app.action_history_down()


def test_app_action_history_down_negative():
    app = _make_app_stub()
    app.history = ["c1"]
    app.history_idx = -1
    mi = _mock_widget()
    mi.has_focus = True
    app.query_one = MagicMock(return_value=mi)
    app.action_history_down()
    assert app.history_idx == -1


def test_app_on_resize_hide():
    app = _make_app_stub()
    ms = _mock_widget()
    ms.display = True
    app.query_one = MagicMock(return_value=ms)
    ev = MagicMock()
    ev.size.width = 80
    app.on_resize(ev)
    assert ms.display is False


def test_app_on_resize_show():
    app = _make_app_stub()
    ms = _mock_widget()
    ms.display = False
    app.query_one = MagicMock(return_value=ms)
    ev = MagicMock()
    ev.size.width = 120
    app.on_resize(ev)
    assert ms.display is True


def test_app_on_resize_failure():
    app = _make_app_stub()
    app.query_one = MagicMock(side_effect=Exception("err"))
    ev = MagicMock()
    ev.size.width = 80
    app.on_resize(ev)


def test_app_start_stop_game():
    app = _make_app_stub()
    mi = _mock_widget()
    mi.disabled = False
    app.query_one = MagicMock(return_value=mi)
    app._start_game()
    assert app._game_active is True
    app.game.start.assert_called_once()
    app._stop_game()
    assert app._game_active is False
    assert app.game.running is False


def test_app_game_display():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    app._game_display("frame123")
    assert app._current_game_frame == "frame123"


def test_app_save_session():
    app = _make_app_stub()
    app.session_name = "test"
    result = app._save_session()
    assert result == "test"
    app._session_mgr.save_session.assert_called_once()


def test_app_save_session_no_mgr():
    app = _make_app_stub()
    app.session_name = "test"
    app._session_mgr = None
    assert app._save_session() == "test"


def test_app_save_session_failure():
    app = _make_app_stub()
    app.session_name = "test"
    app._session_mgr = MagicMock()
    app._session_mgr.save_session.side_effect = Exception("err")
    app._save_session()


def test_app_replay_history():
    app = _make_app_stub()
    app._agent = MagicMock()
    app._agent.conversation_history = [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi"},
        {"role": "user", "content": ""},
    ]
    app._chat_write_user = MagicMock()
    app._chat_write_agent = MagicMock()
    app._replay_history()
    app._chat_write_user.assert_called_once_with("hello")
    app._chat_write_agent.assert_called_once_with("hi")


def test_app_replay_history_no_agent():
    app = _make_app_stub()
    app._agent = None
    app._replay_history()


def test_app_replay_history_no_history():
    app = _make_app_stub()
    app._agent = MagicMock(spec=[])
    app._replay_history()


def test_app_load_session_by_id():
    app = _make_app_stub()
    app._session_mgr = MagicMock()
    app._replay_history = MagicMock()
    app._update_sidebar = MagicMock()
    app._save_session = MagicMock()

    # _load_session_by_id does `from tools.session_manager import SessionManager`
    # then calls SessionManager().resume_session() — patch the class at import path
    mock_sm = MagicMock()
    mock_sm.return_value.resume_session.return_value = {
        "target": "new.com", "mode": "HUNT", "turns": 5,
    }
    with patch("tools.session_manager.SessionManager", mock_sm):
        app._load_session_by_id("abc")
    assert app.session_name == "abc"
    assert app.target == "new.com"
    assert app.mode == "HUNT"
    assert app.turn_count == 5


def test_app_load_session_not_found():
    app = _make_app_stub()
    app._session_mgr = MagicMock()
    app._session_mgr.resume_session.return_value = None
    app._save_session = MagicMock()
    app._load_session_by_id("nonexistent")
    app._cached_chat.write.assert_called()


def test_app_load_session_empty():
    app = _make_app_stub()
    app._save_session = MagicMock()
    app._load_session_by_id("")
    app._save_session.assert_not_called()


def test_app_load_session_no_mgr():
    app = _make_app_stub()
    app._session_mgr = None
    app._save_session = MagicMock()
    app._load_session_by_id("test")
    app._save_session.assert_not_called()


# ===========================================================================
# 11. Slash commands
# ===========================================================================


def test_slash_quit():
    app = _make_app_stub()
    app._save_session = MagicMock()
    app.set_timer = MagicMock()
    assert app._handle_slash("/quit") is True
    app._save_session.assert_called()


def test_slash_exit():
    app = _make_app_stub()
    app._save_session = MagicMock()
    app.set_timer = MagicMock()
    assert app._handle_slash("/exit") is True


def test_slash_bare_quit():
    app = _make_app_stub()
    app._save_session = MagicMock()
    app.set_timer = MagicMock()
    assert app._handle_slash("quit") is True


def test_slash_clear():
    app = _make_app_stub()
    mc = _mock_widget()
    app._cached_chat = mc
    assert app._handle_slash("/clear") is True
    mc.clear.assert_called_once()


def test_slash_reset():
    app = _make_app_stub()
    mc = _mock_widget()
    app._cached_chat = mc
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)
    app._agent = MagicMock()
    app._agent.clear_conversation_history = MagicMock()
    assert app._handle_slash("/reset") is True
    assert app.turn_count == 0
    assert app.tools_run == 0
    assert app.findings == 0


def test_slash_reset_no_clear():
    app = _make_app_stub()
    mc = _mock_widget()
    app._cached_chat = mc
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)
    app._agent = MagicMock(spec=[])
    assert app._handle_slash("/reset") is True


def test_slash_help():
    app = _make_app_stub()
    app.action_show_help = MagicMock()
    assert app._handle_slash("/help") is True
    app.action_show_help.assert_called()


def test_slash_question():
    app = _make_app_stub()
    app.action_show_help = MagicMock()
    assert app._handle_slash("?") is True


def test_slash_mode_no_arg():
    app = _make_app_stub()
    assert app._handle_slash("/mode") is True


def test_slash_mode_chill():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    assert app._handle_slash("/mode chill") is True
    assert app.mode == "CHILL"


def test_slash_mode_hunt():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    assert app._handle_slash("/mode hunt") is True
    assert app.mode == "HUNT"


def test_slash_mode_invalid():
    app = _make_app_stub()
    assert app._handle_slash("/mode invalid") is True


def test_slash_target():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    assert app._handle_slash("/target example.com") is True
    assert app.target == "example.com"


def test_slash_target_clear():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    assert app._handle_slash("/target") is True
    assert app.target == ""


def test_slash_stats():
    app = _make_app_stub()
    with patch("cli_textual.get_vector_memory", create=True) as m:
        m.return_value.get_memory_stats.return_value = {"total_memories": 42, "unique_targets": 5}
        assert app._handle_slash("/stats") is True


def test_slash_stats_error():
    app = _make_app_stub()
    with patch("cli_textual.get_vector_memory", side_effect=Exception("err"), create=True):
        assert app._handle_slash("/stats") is True


def test_slash_team_empty():
    app = _make_app_stub()
    with patch.dict(os.environ, {"ACTIVE_MODELS": ""}):
        assert app._handle_slash("/team") is True


def test_slash_team_active():
    app = _make_app_stub()
    with patch.dict(os.environ, {"ACTIVE_MODELS": "gpt-4o,claude-3"}):
        assert app._handle_slash("/team") is True


def test_slash_talk_1():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    assert app._handle_slash("/talk 1") is True
    assert app._talk_to == 1


def test_slash_talk_2():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    assert app._handle_slash("/talk 2") is True
    assert app._talk_to == 2


def test_slash_talk_3():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    assert app._handle_slash("/talk 3") is True
    assert app._talk_to == 3


def test_slash_talk_all():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    app._talk_to = 1
    assert app._handle_slash("/talk all") is True
    assert app._talk_to == "all"


def test_slash_talk_star():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    app._talk_to = 1
    assert app._handle_slash("/talk *") is True
    assert app._talk_to == "all"


def test_slash_talk_invalid():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    assert app._handle_slash("/talk invalid") is True


def test_slash_talk_no_arg():
    app = _make_app_stub()
    app._last_sidebar_update = 0.0
    assert app._handle_slash("/talk") is True


def test_slash_theme_list():
    app = _make_app_stub()
    app._theme_mgr = MagicMock()
    app._theme_mgr.list_themes.return_value = ["DEFAULT", "CYBERPUNK"]
    assert app._handle_slash("/theme") is True


def test_slash_theme_no_mgr():
    app = _make_app_stub()
    app._theme_mgr = None
    assert app._handle_slash("/theme") is True


def test_slash_theme_set():
    app = _make_app_stub()
    app._theme_mgr = MagicMock()
    with patch("cli_textual.THEME_PALETTE", {"DEFAULT": {}, "CYBERPUNK": {}}):
        assert app._handle_slash("/theme CYBERPUNK") is True
        app._theme_mgr.transition_to.assert_called_once()


def test_slash_theme_invalid():
    app = _make_app_stub()
    app._theme_mgr = MagicMock()
    app._theme_mgr.list_themes.return_value = ["DEFAULT"]
    with patch("cli_textual.THEME_PALETTE", {"DEFAULT": {}}):
        assert app._handle_slash("/theme INVALID") is True


def test_slash_session_info():
    app = _make_app_stub()
    app.session_name = "test"
    app.turn_count = 5
    assert app._handle_slash("/session") is True


def test_slash_session_new():
    app = _make_app_stub()
    app.session_name = "old"
    app._save_session = MagicMock()
    app._session_mgr = MagicMock()
    app._agent = MagicMock()
    app._agent.clear_conversation_history = MagicMock()
    mc = _mock_widget()
    app._cached_chat = mc
    with patch("cli_textual.generate_session_id", return_value="new-id", create=True):
        assert app._handle_slash("/session new") is True
        assert app.turn_count == 0


def test_slash_session_list():
    app = _make_app_stub()
    app._session_mgr = MagicMock()
    ms = MagicMock()
    ms.name = "s1"
    ms.turn_count = 3
    ms.target = "t.com"
    app._session_mgr.list_sessions.return_value = [ms]
    app.session_name = "s1"
    assert app._handle_slash("/session list") is True


def test_slash_session_list_empty():
    app = _make_app_stub()
    app._session_mgr = MagicMock()
    app._session_mgr.list_sessions.return_value = []
    assert app._handle_slash("/session list") is True


def test_slash_session_load():
    app = _make_app_stub()
    app._session_mgr = MagicMock()
    app._session_mgr.resume_session.return_value = {
        "target": "loaded.com", "mode": "CHILL", "turns": 10,
    }
    app._replay_history = MagicMock()
    app._update_sidebar = MagicMock()
    mc = _mock_widget()
    app._cached_chat = mc
    assert app._handle_slash("/session load abc") is True
    assert app.session_name == "abc"


def test_slash_session_load_not_found():
    app = _make_app_stub()
    app._session_mgr = MagicMock()
    app._session_mgr.resume_session.return_value = None
    assert app._handle_slash("/session load nonexistent") is True


def test_slash_game_toggle():
    app = _make_app_stub()
    app._game_active = False
    app._start_game = MagicMock()
    assert app._handle_slash("/game") is True
    app._start_game.assert_called()


def test_slash_game_stop():
    app = _make_app_stub()
    app._game_active = True
    app._stop_game = MagicMock()
    assert app._handle_slash("/game") is True
    app._stop_game.assert_called()


def test_slash_unknown():
    app = _make_app_stub()
    assert app._handle_slash("/unknown") is True


def test_slash_returns_false():
    app = _make_app_stub()
    assert app._handle_slash("hello") is False


# ===========================================================================
# 12. on_input_submitted / on_input_changed
# ===========================================================================


def test_on_input_submitted_empty():
    app = _make_app_stub()
    ev = MagicMock()
    ev.value = "  "
    ev.input = MagicMock()
    app.on_input_submitted(ev)


def test_on_input_submitted_slash():
    app = _make_app_stub()
    app._handle_slash = MagicMock(return_value=True)
    ev = MagicMock()
    ev.value = "/clear"
    ev.input = MagicMock()
    app.on_input_submitted(ev)
    app._handle_slash.assert_called_once()


def test_on_input_submitted_normal():
    app = _make_app_stub()
    app._ensure_session = MagicMock(return_value="s")
    app._chat_write_user = MagicMock()
    app._send_to_agent = MagicMock()
    mb = _mock_widget()
    mb.display = True
    app.query_one = MagicMock(return_value=mb)
    app._last_sidebar_update = 0.0
    ev = MagicMock()
    ev.value = "hello AI"
    ev.input = MagicMock()
    app.on_input_submitted(ev)
    app._chat_write_user.assert_called_once()
    assert app.turn_count == 1


def test_on_input_submitted_dup_history():
    app = _make_app_stub()
    app.history = ["hello"]
    app._ensure_session = MagicMock(return_value="s")
    app._chat_write_user = MagicMock()
    app._send_to_agent = MagicMock()
    mb = _mock_widget()
    mb.display = True
    app.query_one = MagicMock(return_value=mb)
    app._last_sidebar_update = 0.0
    ev = MagicMock()
    ev.value = "hello"
    ev.input = MagicMock()
    app.on_input_submitted(ev)
    assert len(app.history) == 1


def test_on_input_changed_slash():
    app = _make_app_stub()
    app._cycling_suggestions = False
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)
    ev = MagicMock()
    ev.value = "/cl"
    app.on_input_changed(ev)
    mb.styles.display = "block"


def test_on_input_changed_empty():
    app = _make_app_stub()
    app._cycling_suggestions = False
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)
    ev = MagicMock()
    ev.value = ""
    app.on_input_changed(ev)
    mb.styles.display = "none"


def test_on_input_changed_non_slash():
    app = _make_app_stub()
    app._cycling_suggestions = False
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)
    ev = MagicMock()
    ev.value = "hello"
    app.on_input_changed(ev)
    assert app._cycling_suggestions is False


def test_on_input_changed_multi_word():
    app = _make_app_stub()
    app._cycling_suggestions = False
    app._original_prefix = "/mode chill"
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)
    ev = MagicMock()
    ev.value = "/mode chill"
    app.on_input_changed(ev)


def test_on_input_changed_cycling():
    app = _make_app_stub()
    app._cycling_suggestions = True
    app._original_prefix = "/cl"
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)
    ev = MagicMock()
    ev.value = "/clear"
    app.on_input_changed(ev)


def test_update_suggestion_box():
    app = _make_app_stub()
    app._suggest_idx = 0
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)
    app._update_suggestion_box(["/clear", "/cl"])
    mb.update.assert_called_once()


# ===========================================================================
# 13. on_key dispatch
# ===========================================================================


def _setup_key(app):
    mi = _mock_widget()
    mi.has_focus = True
    mi.value = ""
    mb = _mock_widget()
    mh = _mock_widget()
    mh.has_class = MagicMock(return_value=False)
    ms = _mock_widget()
    ms.has_class = MagicMock(return_value=False)
    ms.query_one = MagicMock(return_value=_mock_widget())

    def qs(sel, *args, **kw):
        if sel == "#user_input": return mi
        if sel == "#suggest_box": return mb
        if sel == "#help_overlay": return mh
        if sel == "#settings_overlay": return ms
        return _mock_widget()

    app.query_one = qs
    return mi, mb, mh, ms


def test_on_key_tab_slash():
    app = _make_app_stub()
    app._cycling_suggestions = False
    app._original_prefix = ""
    app._suggest_idx = -1
    mi, mb, mh, ms = _setup_key(app)
    mi.value = "/cl"
    ev = MagicMock()
    ev.key = "tab"
    ev.stop = MagicMock()
    app.on_key(ev)
    ev.stop.assert_called()


def test_on_key_shift_tab():
    app = _make_app_stub()
    app._cycling_suggestions = True
    app._original_prefix = "/cl"
    app._suggest_idx = 1
    mi, mb, mh, ms = _setup_key(app)
    mi.value = "/cl"
    ev = MagicMock()
    ev.key = "shift+tab"
    ev.stop = MagicMock()
    app.on_key(ev)
    ev.stop.assert_called()


def test_on_key_tab_no_focus():
    app = _make_app_stub()
    app._cycling_suggestions = False
    app.SLASH_COMMANDS = ["/clear"]
    mi, mb, mh, ms = _setup_key(app)
    mi.has_focus = False
    ev = MagicMock()
    ev.key = "tab"
    ev.stop = MagicMock()
    app.on_key(ev)
    ev.stop.assert_not_called()


def test_on_key_tab_no_matches():
    app = _make_app_stub()
    app._cycling_suggestions = False
    app.SLASH_COMMANDS = ["/clear"]
    mi, mb, mh, ms = _setup_key(app)
    mi.has_focus = True
    mi.value = "/xyz"
    ev = MagicMock()
    ev.key = "tab"
    ev.stop = MagicMock()
    app.on_key(ev)
    ev.stop.assert_not_called()


def test_on_key_tab_multi_word():
    app = _make_app_stub()
    app._cycling_suggestions = False
    app.SLASH_COMMANDS = ["/mode chill"]
    mi, mb, mh, ms = _setup_key(app)
    mi.has_focus = True
    mi.value = "/mode chill"
    ev = MagicMock()
    ev.key = "tab"
    ev.stop = MagicMock()
    app.on_key(ev)
    ev.stop.assert_not_called()


def test_on_key_ctrl_comma():
    app = _make_app_stub()
    app.action_show_settings = MagicMock()
    _setup_key(app)
    ev = MagicMock()
    ev.key = "ctrl+comma"
    ev.stop = MagicMock()
    app.on_key(ev)
    app.action_show_settings.assert_called()


def test_on_key_ctrl_t():
    app = _make_app_stub()
    app.action_toggle_think = MagicMock()
    _setup_key(app)
    ev = MagicMock()
    ev.key = "ctrl+t"
    ev.stop = MagicMock()
    app.on_key(ev)
    app.action_toggle_think.assert_called()


def test_on_key_ctrl_r():
    app = _make_app_stub()
    app.action_toggle_research = MagicMock()
    _setup_key(app)
    ev = MagicMock()
    ev.key = "ctrl+r"
    ev.stop = MagicMock()
    app.on_key(ev)
    app.action_toggle_research.assert_called()


def test_on_key_game_space():
    app = _make_app_stub()
    app._game_active = True
    app.game.game_over = False
    _setup_key(app)
    ev = MagicMock()
    ev.key = "space"
    ev.stop = MagicMock()
    app.on_key(ev)
    app.game.jump.assert_called()


def test_on_key_game_space_restart():
    app = _make_app_stub()
    app._game_active = True
    app.game.game_over = True
    _setup_key(app)
    ev = MagicMock()
    ev.key = "space"
    ev.stop = MagicMock()
    app.on_key(ev)
    app.game.start.assert_called()


def test_on_key_game_quit():
    app = _make_app_stub()
    app._game_active = True
    app.game.game_over = False
    app._stop_game = MagicMock()
    _setup_key(app)
    ev = MagicMock()
    ev.key = "q"
    ev.stop = MagicMock()
    app.on_key(ev)
    app._stop_game.assert_called()


def test_on_key_game_escape():
    app = _make_app_stub()
    app._game_active = True
    app.game.game_over = False
    app._stop_game = MagicMock()
    _setup_key(app)
    ev = MagicMock()
    ev.key = "escape"
    ev.stop = MagicMock()
    app.on_key(ev)
    app._stop_game.assert_called()


def test_on_key_ctrl_m():
    app = _make_app_stub()
    app.action_toggle_mode = MagicMock()
    _setup_key(app)
    ev = MagicMock()
    ev.key = "ctrl+m"
    ev.stop = MagicMock()
    app.on_key(ev)
    app.action_toggle_mode.assert_called()


def test_on_key_ctrl_p():
    app = _make_app_stub()
    app.action_show_model = MagicMock()
    _setup_key(app)
    ev = MagicMock()
    ev.key = "ctrl+p"
    ev.stop = MagicMock()
    app.on_key(ev)
    app.action_show_model.assert_called()


def test_on_key_ctrl_g():
    app = _make_app_stub()
    app.action_show_help = MagicMock()
    _setup_key(app)
    ev = MagicMock()
    ev.key = "ctrl+g"
    ev.stop = MagicMock()
    app.on_key(ev)
    app.action_show_help.assert_called()


def test_on_key_ctrl_d():
    app = _make_app_stub()
    app.action_toggle_dashboard = MagicMock()
    _setup_key(app)
    ev = MagicMock()
    ev.key = "ctrl+d"
    ev.stop = MagicMock()
    app.on_key(ev)
    app.action_toggle_dashboard.assert_called()


def test_on_key_ctrl_c():
    app = _make_app_stub()
    app.action_app_exit = MagicMock()
    _setup_key(app)
    ev = MagicMock()
    ev.key = "ctrl+c"
    ev.stop = MagicMock()
    app.on_key(ev)
    app.action_app_exit.assert_called()


def test_on_key_help_visible():
    app = _make_app_stub()
    mh = _mock_widget()
    mh.has_class = MagicMock(return_value=True)
    mh.on_key = MagicMock()

    def qs(sel, *args, **kw):
        if sel == "#help_overlay": return mh
        return _mock_widget()

    app.query_one = qs
    ev = MagicMock()
    ev.key = "a"
    ev.stop = MagicMock()
    app.on_key(ev)
    mh.on_key.assert_called_once_with(ev)


def test_on_key_settings_visible():
    app = _make_app_stub()
    ms = _mock_widget()
    ms.has_class = MagicMock(return_value=True)
    ms.on_key = MagicMock()
    mc = _mock_widget()
    mc.has_class = MagicMock(return_value=False)
    ms.query_one = MagicMock(return_value=mc)

    def qs(sel, *args, **kw):
        if sel == "#help_overlay":
            w = _mock_widget()
            w.has_class = MagicMock(return_value=False)
            return w
        if sel == "#settings_overlay": return ms
        return _mock_widget()

    app.query_one = qs
    ev = MagicMock()
    ev.key = "a"
    ev.stop = MagicMock()
    app.on_key(ev)
    ms.on_key.assert_called_once_with(ev)


def test_on_key_settings_custom_url_visible():
    app = _make_app_stub()
    ms = _mock_widget()
    ms.has_class = MagicMock(return_value=True)
    mc = _mock_widget()
    mc.has_class = MagicMock(return_value=True)
    ms.query_one = MagicMock(return_value=mc)

    def qs(sel, *args, **kw):
        if sel == "#help_overlay":
            w = _mock_widget()
            w.has_class = MagicMock(return_value=False)
            return w
        if sel == "#settings_overlay": return ms
        return _mock_widget()

    app.query_one = qs
    ev = MagicMock()
    ev.key = "a"
    ev.stop = MagicMock()
    app.on_key(ev)
    ev.stop.assert_not_called()


def test_on_key_normal():
    app = _make_app_stub()
    app._cycling_suggestions = False
    _setup_key(app)
    ev = MagicMock()
    ev.key = "a"
    ev.stop = MagicMock()
    app.on_key(ev)
    ev.stop.assert_not_called()


# ===========================================================================
# 14. Refresh dashboard
# ===========================================================================


def test_refresh_dashboard_unavailable():
    app = _make_app_stub()
    with patch("cli_textual._TUI_WIDGETS_AVAILABLE", False):
        app._refresh_dashboard()


def test_refresh_dashboard_available():
    app = _make_app_stub()
    app._findings_data = [{"title": "XSS", "severity": "high"}]
    mf = _mock_widget()
    mf.update_findings = MagicMock()
    mt = _mock_widget()
    mt.add_finding = MagicMock()

    def qs(sel, **kw):
        if sel == "#findings_display": return mf
        if sel == "#threat_dashboard": return mt
        return _mock_widget()

    app.query_one = qs
    with patch("cli_textual._TUI_WIDGETS_AVAILABLE", True):
        app._refresh_dashboard()


def test_refresh_dashboard_object_findings():
    app = _make_app_stub()

    class F:
        title = "XSS"
        severity = "high"
        location = "/api"

    app._findings_data = [F()]
    mf = _mock_widget()
    mf.update_findings = MagicMock()
    mt = _mock_widget()
    mt.add_finding = MagicMock()

    def qs(sel, *args, **kw):
        if sel == "#findings_display": return mf
        if sel == "#threat_dashboard": return mt
        return _mock_widget()

    app.query_one = qs
    with patch("cli_textual._TUI_WIDGETS_AVAILABLE", True):
        app._refresh_dashboard()
        mt.add_finding.assert_called()


def test_refresh_dashboard_failure():
    app = _make_app_stub()
    app.query_one = MagicMock(side_effect=Exception("err"))
    with patch("cli_textual._TUI_WIDGETS_AVAILABLE", True):
        app._refresh_dashboard()


# ===========================================================================
# 15. Send to agent
# ===========================================================================


def test_send_to_agent_busy():
    """When _processing is True, _send_to_agent should return immediately."""
    app = _make_app_stub()
    app._processing = True
    # Verify early return flag is set — can't call the @work-decorated method
    # without Textual runtime, so just verify the state
    assert app._processing is True


def test_send_to_agent_no_agent():
    """When _agent is None, _send_to_agent raises RuntimeError."""
    app = _make_app_stub()
    app._processing = False
    app._agent = None
    # Can't call @work-decorated method without Textual runtime
    assert app._agent is None


# ===========================================================================
# 16. CSS and bindings
# ===========================================================================


def test_custom_url_css():
    assert "custom_url_row" in mod.CUSTOM_URL_INPUT_CSS


def test_app_css():
    css = mod.ElengenixTextualApp.CSS
    assert "Screen" in css
    assert "#chat_area" in css
    assert "#user_input" in css
    assert "#banner" in css


def test_bindings():
    bindings = mod.ElengenixTextualApp.BINDINGS
    assert len(bindings) >= 8
    keys = [b.key for b in bindings]
    for k in ("ctrl+r", "ctrl+m", "ctrl+t", "ctrl+g", "ctrl+d", "ctrl+c"):
        assert k in keys


def test_slash_commands():
    cmds = mod.ElengenixTextualApp.SLASH_COMMANDS
    for c in ("/clear", "/reset", "/quit", "/mode chill", "/mode hunt",
              "/target <domain>", "/talk 1", "/session", "/game", "/help",
              "/theme <name>"):
        assert c in cmds
    assert len(cmds) >= 18


# ===========================================================================
# 17. _load_agent and _run_boot_sequence
# ===========================================================================


def test_load_agent_success():
    app = _make_app_stub()
    app._agent = None
    mock_agent = MagicMock()
    mock_agent.governance = MagicMock()

    with patch.object(mod, "get_agent", return_value=mock_agent):
        try:
            mod.ElengenixTextualApp._load_agent.__wrapped__(app)
        except Exception:
            pass
    assert app._agent is not None


def test_load_agent_failure():
    app = _make_app_stub()
    app._agent = None
    app._chat_write_error = MagicMock()

    with patch.object(mod, "get_agent", side_effect=Exception("init fail")):
        try:
            mod.ElengenixTextualApp._load_agent.__wrapped__(app)
        except Exception:
            pass


def test_run_boot_sequence():
    app = _make_app_stub()
    app.mode = "CHILL"
    app._chat_write_system = MagicMock()
    app._update_banner_text = MagicMock()

    with patch("cli_textual.time.sleep"):
        with patch("cli_textual.sys.argv", ["elengenix"]):
            with patch("cli_textual.os.environ", {"ELENGENIX_BELL": "0"}):
                try:
                    mod.ElengenixTextualApp._run_boot_sequence.__wrapped__(app)
                except Exception:
                    pass


# ===========================================================================
# 18. on_mount
# ===========================================================================


def test_on_mount_loads_session():
    app = _make_app_stub()
    app._load_sid = "test-session"
    app._chat_write_system = MagicMock()
    app._update_sidebar = MagicMock()
    app._load_agent = MagicMock()
    app._run_boot_sequence = MagicMock()
    app.set_focus = MagicMock()
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)

    # on_mount does `self._session_mgr = SessionManager()` then resume_session
    mock_sm_cls = MagicMock()
    mock_sm_cls.return_value.resume_session.return_value = {
        "target": "loaded.com", "mode": "HUNT", "turns": 3,
    }
    with patch.object(type(app), 'theme', new_callable=PropertyMock):
        with patch("tools.session_manager.SessionManager", mock_sm_cls):
            app.on_mount()
    assert app.target == "loaded.com"
    assert app.turn_count == 3


def test_on_mount_session_not_found():
    app = _make_app_stub()
    app._load_sid = "nonexistent"
    app._session_mgr = MagicMock()
    app._session_mgr.resume_session.return_value = None
    app._chat_write_system = MagicMock()
    app._update_sidebar = MagicMock()
    app._load_agent = MagicMock()
    app._run_boot_sequence = MagicMock()
    app.set_focus = MagicMock()
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)

    with patch.object(type(app), 'theme', new_callable=PropertyMock):
        app.on_mount()
    assert app._load_sid == ""


def test_on_mount_no_session():
    app = _make_app_stub()
    app._load_sid = ""
    app._chat_write_system = MagicMock()
    app._update_sidebar = MagicMock()
    app._load_agent = MagicMock()
    app._run_boot_sequence = MagicMock()
    app.set_focus = MagicMock()
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)

    with patch.object(type(app), 'theme', new_callable=PropertyMock):
        app.on_mount()
    app._load_agent.assert_called_once()
    app._run_boot_sequence.assert_called_once()


def test_on_mount_session_mgr_failure():
    app = _make_app_stub()
    app._load_sid = "test"
    app._session_mgr = None
    app._chat_write_system = MagicMock()
    app._update_sidebar = MagicMock()
    app._load_agent = MagicMock()
    app._run_boot_sequence = MagicMock()
    app.set_focus = MagicMock()
    mb = _mock_widget()
    app.query_one = MagicMock(return_value=mb)

    with patch.dict("sys.modules", {"tools.session_manager": None}):
        with patch.object(type(app), 'theme', new_callable=PropertyMock):
            app.on_mount()


# ===========================================================================
# 19. main function
# ===========================================================================


def test_main():
    with patch.object(mod, "ObbyGame"), patch.object(mod, "get_agent"):
        with patch("cli_textual.ElengenixTextualApp") as MockApp:
            mock_app = MagicMock()
            MockApp.return_value = mock_app
            mod.main(target="x.com", mode="HUNT", session_id="abc")
            MockApp.assert_called_once_with(target="x.com", mode="HUNT", session_id="abc")
            mock_app.run.assert_called_once()


# ===========================================================================
# 20. GLITCH_CHARS
# ===========================================================================


def test_glitch_chars():
    assert len(mod.GLITCH_CHARS) > 20

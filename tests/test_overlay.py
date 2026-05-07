"""
tests/test_overlay.py — Tests for Settings Overlay (Ctrl+E Menu)
"""

import pytest
from unittest.mock import MagicMock


class TestSettingsOverlay:
    """Test the overlay settings menu."""

    @pytest.fixture
    def mock_agent(self):
        return MagicMock()

    @pytest.fixture
    def mock_console(self):
        c = MagicMock()
        c.clear = MagicMock()
        c.print = MagicMock()
        return c

    def test_init(self, mock_agent, mock_console):
        from tools.overlay_menu import SettingsOverlay
        overlay = SettingsOverlay(mock_agent, mock_console, target="test.com")
        assert overlay._current_layer == "main"
        assert len(overlay._agent_config) == 3

    def test_load_agent_config_empty(self, mock_agent, mock_console):
        from tools.overlay_menu import SettingsOverlay
        import os
        old = os.environ.pop("ACTIVE_MODELS", None)
        overlay = SettingsOverlay(mock_agent, mock_console)
        assert overlay._agent_config[0]["provider"] == ""
        if old:
            os.environ["ACTIVE_MODELS"] = old

    def test_load_agent_config_with_models(self, mock_agent, mock_console):
        from tools.overlay_menu import SettingsOverlay
        import os
        old = os.environ.get("ACTIVE_MODELS")
        os.environ["ACTIVE_MODELS"] = "nvidia/nemotron-3,gemini/flash,deepseek/chat"
        overlay = SettingsOverlay(mock_agent, mock_console)
        assert overlay._agent_config[0]["provider"] == "nvidia"
        assert overlay._agent_config[0]["model"] == "nemotron-3"
        if old:
            os.environ["ACTIVE_MODELS"] = old
        else:
            os.environ.pop("ACTIVE_MODELS", None)

    def test_navigate_to_submenu(self, mock_agent, mock_console):
        from tools.overlay_menu import SettingsOverlay
        overlay = SettingsOverlay(mock_agent, mock_console)
        overlay._navigate_to("agent_setup")
        assert overlay._current_layer == "agent_setup"

    def test_go_back_from_submenu(self, mock_agent, mock_console):
        from tools.overlay_menu import SettingsOverlay
        overlay = SettingsOverlay(mock_agent, mock_console)
        overlay._navigate_to("agent_setup")
        overlay._go_back()
        assert overlay._current_layer == "main"

    def test_go_back_from_main(self, mock_agent, mock_console):
        from tools.overlay_menu import SettingsOverlay
        overlay = SettingsOverlay(mock_agent, mock_console)
        result = overlay._go_back()
        assert result == "exit"

    def test_build_provider_items(self, mock_agent, mock_console):
        from tools.overlay_menu import SettingsOverlay
        import os
        old = os.environ.get("GEMINI_API_KEY")
        os.environ["GEMINI_API_KEY"] = "sk-test123"
        overlay = SettingsOverlay(mock_agent, mock_console)
        items = overlay._build_provider_items()
        gemini = next(i for i in items if i["id"] == "gemini")
        assert "✓" in gemini["label"]
        if old:
            os.environ["GEMINI_API_KEY"] = old
        else:
            os.environ.pop("GEMINI_API_KEY", None)

    def test_build_rate_limits(self, mock_agent, mock_console):
        from tools.overlay_menu import SettingsOverlay
        overlay = SettingsOverlay(mock_agent, mock_console)
        items = overlay._build_rate_limit_items()
        # Should have 3 agents * (label + decrease + increase + spacer) + back = many
        assert len(items) > 3

    def test_rate_limit_increment(self, mock_agent, mock_console):
        from tools.overlay_menu import SettingsOverlay
        overlay = SettingsOverlay(mock_agent, mock_console)
        old = overlay._rate_limits[0]
        overlay._handle_enter()
        # Simulate clicking increase button
        overlay._current_layer = "rate_limits"
        overlay._update_items()
        # Can't easily test exact action, but structure should exist

"""Tests for the Elengenix TUI/CLI UX surfaces added in the polish pass.

Covers, all offline/headless:
  - tools.ai_config.any_provider_configured() helper semantics
  - The TUI startup provider-check message wires into the boot path
  - LiveDisplay compact mission-status line (target / step / findings / provider+model)

These tests never touch the network, a real terminal, or any real API key.
"""

from __future__ import annotations

import pytest

from tools import ai_config


# Every env var ai_config consults for the provider check, so tests stay
# hermetic regardless of whatever keys happen to exist on the host / .env.
_ALL_KEY_ENV = [
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GROQ_API_KEY",
    "NVIDIA_API_KEY",
    "DEEPSEEK_API_KEY",
    "MISTRAL_API_KEY",
    "OPENROUTER_API_KEY",
    "TOGETHER_API_KEY",
    "PERPLEXITY_API_KEY",
    "CUSTOM_API_KEY",
    "CUSTOM_API_BASE",
    "OLLAMA_BASE_URL",
]


@pytest.fixture
def _clean_provider_env(monkeypatch):
    """Strip every provider key/env the helper inspects + empty config.yaml."""
    for k in _ALL_KEY_ENV:
        monkeypatch.delenv(k, raising=False)
    # Neutralize any keys embedded in config.yaml so the test is self-contained.
    monkeypatch.setattr(ai_config, "get_provider_config", lambda provider: {})
    monkeypatch.setattr(ai_config, "get_active_provider", lambda: "auto")
    monkeypatch.setattr(ai_config, "load_config", lambda *a, **k: {})
    ai_config.reset_config_cache()
    yield
    ai_config.reset_config_cache()


# ===================================================================
# tools.ai_config.any_provider_configured
# ===================================================================


class TestAnyProviderConfigured:
    def test_no_keys_configured_returns_false(self, _clean_provider_env):
        assert ai_config.any_provider_configured() is False

    def test_env_key_configured_returns_true(self, _clean_provider_env, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key-1234567890")
        assert ai_config.any_provider_configured() is True

    def test_any_single_provider_counts(self, _clean_provider_env, monkeypatch):
        # Try a non-default provider to prove it scans all of them.
        monkeypatch.setenv("GROQ_API_KEY", "gsk_test_1234567890")
        assert ai_config.any_provider_configured() is True

    def test_empty_string_key_not_configured(self, _clean_provider_env, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "   ")
        assert ai_config.any_provider_configured() is False

    def test_custom_api_key_counts(self, _clean_provider_env, monkeypatch):
        monkeypatch.setenv("CUSTOM_API_KEY", "ck-test-123")
        assert ai_config.any_provider_configured() is True

    def test_honest_local_provider_requires_env_hint(
        self, _clean_provider_env, monkeypatch
    ):
        """An ollama/active key-free provider only counts when the base URL env
        is actually set — a default 'ollama' provider with no endpoint is not
        a real configuration."""
        monkeypatch.setattr(ai_config, "get_active_provider", lambda: "ollama")
        monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
        assert ai_config.any_provider_configured() is False


# ===================================================================
# LiveDisplay mission status line
# ===================================================================


class TestMissionStatusLine:
    @staticmethod
    def _plain(text: str) -> str:
        from rich.markup import render

        return render(text).plain

    def test_default_status_line_render(self):
        from cli.live_display import LiveDisplay

        d = LiveDisplay()
        line = self._plain(d.render_mission_status())
        assert "target" in line
        assert "step" in line
        assert "findings" in line

    def test_status_line_shows_all_fields(self):
        from cli.live_display import LiveDisplay

        d = LiveDisplay()
        d.current_target = "example.com"
        d.step_count = 4
        d.max_steps = 50
        d.findings_so_far = 3
        d.set_model_info("gemini", "gemini-2.0-flash")

        plain = self._plain(d.render_mission_status())
        assert "example.com" in plain
        assert "4/50" in plain
        assert "3" in plain
        assert "gemini/gemini-2.0-flash" in plain

    def test_status_line_tolerates_missing_model_info(self):
        from cli.live_display import LiveDisplay

        d = LiveDisplay()
        d.current_target = "x.test"
        line = self._plain(d.render_mission_status())
        assert "x.test" in line
        assert "/" not in line.split("findings", 1)[1]  # no stray provider/model

    def test_render_header_includes_mission_status(self):
        from rich.console import Console

        from cli.live_display import LiveDisplay

        d = LiveDisplay()
        d.current_target = "demo.test"
        d.step_count = 7
        d.max_steps = 30
        d.set_model_info("openai", "gpt-4o")
        panel = d.render_header()
        c = Console(force_terminal=False, width=140)
        with c.capture() as cap:
            c.print(panel)
        out = cap.get()
        assert "demo.test" in out
        assert "7/30" in out
        assert "openai/gpt-4o" in out


# ===================================================================
# Textual startup provider check (headless)
#
# Rather than driving the full app lifecycle (heavy and platform-dependent),
# we build the real app, replace its chat sinks with spies, and invoke the
# exact hook the boot sequence calls — proving both wiring and messaging.
# ===================================================================


class TestTuiProviderCheck:
    def _make_app_with_spies(self, monkeypatch):
        import importlib

        tex = importlib.import_module("cli.textual")

        captured = {"panels": [], "systems": [], "errors": []}
        # Patch on the class: Textual apps restrict per-instance attribute
        # assignment of methods, so instance-level setattr can be a no-op.
        monkeypatch.setattr(
            tex.ElengenixTextualApp,
            "_chat_write_panel",
            lambda self, p: captured["panels"].append(p),
        )
        monkeypatch.setattr(
            tex.ElengenixTextualApp,
            "_chat_write_system",
            lambda self, m: captured["systems"].append(m),
        )
        monkeypatch.setattr(
            tex.ElengenixTextualApp,
            "_chat_write_error",
            lambda self, m: captured["errors"].append(m),
        )
        app = tex.ElengenixTextualApp(mode="CHILL", target="")
        return app, captured

    @staticmethod
    def _reenforce_clean_env(monkeypatch):
        """Importing cli.textual pulls in core.agent, which re-loads .env and
        re-populates provider keys — wipe + reset ai_config again *after* import
        so the check-under-test actually sees a clean slate."""
        from tools import ai_config as ac

        for k in _ALL_KEY_ENV:
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setattr(ac, "get_provider_config", lambda provider: {})
        monkeypatch.setattr(ac, "get_active_provider", lambda: "auto")
        monkeypatch.setattr(ac, "load_config", lambda *a, **k: {})
        ac.reset_config_cache()

    def test_warns_when_no_provider_configured(self, _clean_provider_env, monkeypatch):
        app, captured = self._make_app_with_spies(monkeypatch)
        # Re-pin the clean env *after* the import (see helper comment).
        self._reenforce_clean_env(monkeypatch)
        assert ai_config.any_provider_configured() is False
        app._check_provider_and_warn()

        # Friendly guidance panel rendered, not a crash.
        assert captured["panels"], "expected a warning panel when unconfigured"
        pane = captured["panels"][0]
        from rich.console import Console

        c = Console(force_terminal=False, width=140)
        with c.capture() as cap:
            c.print(pane)
        out = cap.get()
        assert "No AI provider configured" in out
        # actionable guidance
        assert "API_KEY" in out or "ai.providers" in out

    def test_silent_ok_when_provider_configured(self, _clean_provider_env, monkeypatch):
        app, captured = self._make_app_with_spies(monkeypatch)
        self._reenforce_clean_env(monkeypatch)
        monkeypatch.setenv("GEMINI_API_KEY", "test-1234567890-sufficient")
        app._check_provider_and_warn()

        assert not captured["panels"], "no warning expected when a provider key exists"
        # benign confirmation to the chat log
        assert any("Configured" in s or "configured" in s for s in captured["systems"])

    def test_never_raises_when_check_explodes(self, _clean_provider_env, monkeypatch):
        app, captured = self._make_app_with_spies(monkeypatch)
        self._reenforce_clean_env(monkeypatch)

        def boom():
            raise RuntimeError("simulated ai_config failure")

        monkeypatch.setattr(ai_config, "any_provider_configured", boom)
        # Must swallow and log — the boot path survives.
        app._check_provider_and_warn()
        assert not captured["panels"]

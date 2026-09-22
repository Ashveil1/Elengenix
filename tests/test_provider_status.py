"""Tests for honest provider status (single source of truth).

Covers tools.ai_config.provider_status():
  - clean install: nothing Ready, no phantom models
  - set/delete round-trip is reflected immediately (no stale Ready)
  - ollama counts only with an endpoint configured (both URL spellings)
  - custom counts only with base URL (+ key, or localhost base)
  - describe_provider_setup() includes custom and reports no phantom model
"""

from __future__ import annotations

import pytest

from tools import ai_config


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
    "COHERE_API_KEY",
    "HUGGINGFACE_API_KEY",
    "REPLICATE_API_TOKEN",
    "OPENCODE_API_KEY",
    "CUSTOM_API_KEY",
    "CUSTOM_API_BASE",
    "CUSTOM_MODEL",
    "OLLAMA_BASE_URL",
    "OLLAMA_URL",
    "OLLAMA_MODEL",
    "ACTIVE_AI_PROVIDER",
    "ACTIVE_MODELS",
]


@pytest.fixture
def _clean_provider_env(monkeypatch):
    for k in _ALL_KEY_ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(ai_config, "get_provider_config", lambda provider: {})
    monkeypatch.setattr(ai_config, "get_active_provider", lambda: "auto")
    monkeypatch.setattr(ai_config, "load_config", lambda *a, **k: {})
    ai_config.reset_config_cache()
    yield
    ai_config.reset_config_cache()


class TestCleanState:
    def test_nothing_ready_on_clean_install(self, _clean_provider_env):
        from elengenix.providers.catalog import PROVIDER_IDS

        for pid in list(PROVIDER_IDS) + ["custom"]:
            st = ai_config.provider_status(pid)
            assert st["key_set"] is False, pid
            assert st["model"] == "", pid

    def test_no_provider_configured_when_clean(self, _clean_provider_env):
        assert ai_config.any_provider_configured() is False

    def test_describe_reports_no_model_when_clean(self, _clean_provider_env):
        info = ai_config.describe_provider_setup()
        assert info["model"] == ""
        assert info["ok"] is False
        assert any(p["name"] == "custom" for p in info["providers"])


class TestSetDeleteRoundTrip:
    def test_key_set_then_deleted(self, _clean_provider_env, monkeypatch):
        assert ai_config.provider_status("gemini")["key_set"] is False
        monkeypatch.setenv("GEMINI_API_KEY", "test-key-1234567890")
        st = ai_config.provider_status("gemini")
        assert st["key_set"] is True
        assert st["key_source"] == "env:GEMINI_API_KEY"
        # Delete must be reflected immediately — no stale Ready.
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        assert ai_config.provider_status("gemini")["key_set"] is False
        assert ai_config.any_provider_configured() is False

    def test_model_never_phantom(self, _clean_provider_env, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-1234567890")
        st = ai_config.provider_status("openai")
        assert st["key_set"] is True
        assert st["model"] == ""  # key without model must not invent one


class TestOllama:
    def test_ollama_not_ready_without_endpoint(self, _clean_provider_env):
        assert ai_config.provider_status("ollama")["key_set"] is False

    def test_ollama_ready_with_base_url(self, _clean_provider_env, monkeypatch):
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434")
        assert ai_config.provider_status("ollama")["key_set"] is True

    def test_ollama_alt_spelling(self, _clean_provider_env, monkeypatch):
        monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")
        assert ai_config.provider_status("ollama")["key_set"] is True


class TestCustom:
    def test_custom_needs_base_url(self, _clean_provider_env, monkeypatch):
        monkeypatch.setenv("CUSTOM_API_KEY", "ck-test-123")
        assert ai_config.provider_status("custom")["key_set"] is False

    def test_custom_ready_with_base_and_key(self, _clean_provider_env, monkeypatch):
        monkeypatch.setenv("CUSTOM_API_BASE", "https://llm.example.com/v1")
        monkeypatch.setenv("CUSTOM_API_KEY", "ck-test-123")
        monkeypatch.setenv("CUSTOM_MODEL", "my-model")
        st = ai_config.provider_status("custom")
        assert st["key_set"] is True
        assert st["model"] == "my-model"

    def test_custom_localhost_needs_no_key(self, _clean_provider_env, monkeypatch):
        monkeypatch.setenv("CUSTOM_API_BASE", "http://localhost:8000/v1")
        assert ai_config.provider_status("custom")["key_set"] is True


class TestOverlaySync:
    """TUI overlay writes/reads the same .env the runtime loads."""

    def test_type_confirm_clear_round_trip(self, _clean_provider_env, monkeypatch, tmp_path):
        env_file = tmp_path / ".env"
        monkeypatch.setenv("ELENGENIX_ENV", str(env_file))
        from rich.console import Console

        from tools.overlay_menu import SettingsOverlay

        console = Console(width=80, force_terminal=False)
        ov = SettingsOverlay(None, console)
        ov._current_layer = "api_keys"
        ov._update_items()
        ov._navigate_to("key_gemini")
        assert ov._current_layer == "api_key_edit"
        for ch in "sk-test-xyz123":
            ov.handle_char(ch)
        assert ov._api_keys_dirty.get("gemini") == "sk-test-xyz123"
        ov.handle_char("\r")  # Confirm & Save persists immediately
        assert ov._current_layer == "api_keys"
        assert env_file.exists()
        assert "GEMINI_API_KEY=sk-test-xyz123" in env_file.read_text()
        assert ai_config.provider_status("gemini")["key_set"] is True

        ov._update_items()
        ov._navigate_to("key_gemini")
        idx = next(i for i, x in enumerate(ov._items) if x.get("action") == "clear_key")
        ov._selected_idx = idx
        ov._handle_enter()
        assert "GEMINI_API_KEY" not in env_file.read_text()
        assert ai_config.provider_status("gemini")["key_set"] is False

    def test_writes_go_to_resolved_env_file(self, _clean_provider_env, monkeypatch, tmp_path):
        env_file = tmp_path / ".env"
        monkeypatch.setenv("ELENGENIX_ENV", str(env_file))
        from elengenix.paths import default_env_file

        assert default_env_file() == env_file

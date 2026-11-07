"""tests/test_ai_config_provider_order.py — provider fallback ordering.

Pins the ``custom`` (user-configured OpenAI-compatible endpoint) fallback
in ``get_provider_order`` / ``AIClientManager``: it must be reachable when
configured, and it must never shadow a real provider or report available
when unconfigured.
"""

import pytest

from tools.ai_config import get_provider_order


class TestCustomProviderOrdering:
    def test_custom_is_last_in_order(self, monkeypatch):
        """A configured custom endpoint is a LAST-resort fallback, never
        ahead of a real provider (it only becomes active when nothing
        else is available)."""
        monkeypatch.setenv("CUSTOM_API_BASE", "https://example.invalid/v1")
        monkeypatch.setenv("CUSTOM_API_KEY", "k" * 32)
        order = get_provider_order()
        assert "custom" in order
        assert order[-1] == "custom"

    def test_custom_manager_active_when_configured(self, monkeypatch):
        """AIClientManager resolves a configured custom endpoint as the
        active client (this is what the verification council needs)."""
        monkeypatch.setenv("CUSTOM_API_BASE", "https://example.invalid/v1")
        monkeypatch.setenv("CUSTOM_API_KEY", "k" * 32)
        monkeypatch.setenv("CUSTOM_MODEL", "test-model")
        from tools.universal_ai_client import AIClientManager

        # No real provider keys in the test env -> custom must win.
        m = AIClientManager()
        assert m.get_active_provider() == "custom"
        assert m.active_client is not None
        assert m.active_client.model == "test-model"

    def test_custom_unavailable_when_unconfigured(self, monkeypatch):
        """No CUSTOM_* env -> the custom client is in the order but not
        available, so a real provider (or nothing) wins instead."""
        for key in ("CUSTOM_API_BASE", "CUSTOM_API_KEY", "CUSTOM_MODEL"):
            monkeypatch.delenv(key, raising=False)
        order = get_provider_order()
        assert "custom" in order
        from tools.universal_ai_client import UniversalAIClient

        client = UniversalAIClient(provider="custom")
        assert not client.is_available()

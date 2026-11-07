"""tests/test_universal_ai_client_ollama.py — Ollama endpoint/timeout hardening.

Covers the two fixes that made local Ollama actually usable by the agent:

* The OpenAI-compatible endpoint lives at ``{server}/v1/chat/completions``, but
  the ``OLLAMA_URL`` / ``OLLAMA_BASE_URL`` env convention (and most docs) points
  at the bare server root. The client must normalize, or every call 404s.
* ``ELENGENIX_AI_TIMEOUT`` overrides the per-call timeout (slow CPU inference
  needs far more than the 150s default); a malformed value keeps the default.

All tests are construction-only (no network), so they stay hermetic: the
request endpoint is irrelevant here — we only inspect the resolved client.
"""
from __future__ import annotations

import os

from tools.universal_ai_client import UniversalAIClient


def _bare_client(monkeypatch, url: str, timeout_env: str = "") -> UniversalAIClient:
    monkeypatch.delenv("ELENGENIX_AI_TIMEOUT", raising=False)
    if url:
        monkeypatch.setenv("OLLAMA_URL", url)
        monkeypatch.setenv("OLLAMA_BASE_URL", url)
    else:
        monkeypatch.delenv("OLLAMA_URL", raising=False)
        monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    if timeout_env:
        monkeypatch.setenv("ELENGENIX_AI_TIMEOUT", timeout_env)
    return UniversalAIClient(provider="ollama", model="qwen2.5:1.5b")


class TestOllamaV1Normalization:
    def test_bare_root_gets_v1(self, monkeypatch):
        c = _bare_client(monkeypatch, "http://localhost:11434")
        assert c.base_url == "http://localhost:11434/v1"

    def test_trailing_slash_root(self, monkeypatch):
        c = _bare_client(monkeypatch, "http://localhost:11434/")
        assert c.base_url == "http://localhost:11434/v1"

    def test_existing_v1_untouched(self, monkeypatch):
        c = _bare_client(monkeypatch, "http://localhost:11434/v1")
        assert c.base_url == "http://localhost:11434/v1"

    def test_existing_v1_slash_normalized(self, monkeypatch):
        # The trailing slash is dropped (harmless — the request path does its
        # own rstrip), but the /v1 segment must be preserved exactly once.
        c = _bare_client(monkeypatch, "http://host:11434/v1/")
        assert c.base_url == "http://host:11434/v1"

    def test_no_env_uses_catalog_default(self, monkeypatch):
        # Catalog default for ollama is already the /v1 root.
        c = _bare_client(monkeypatch, "")
        assert c.base_url.endswith("/v1")
        assert "11434" in c.base_url


class TestAiTimeoutOverride:
    def test_default_150(self, monkeypatch):
        c = _bare_client(monkeypatch, "http://localhost:11434")
        assert c.timeout == 150

    def test_env_override(self, monkeypatch):
        c = _bare_client(monkeypatch, "http://localhost:11434", timeout_env="1500")
        assert c.timeout == 1500

    def test_env_float_string(self, monkeypatch):
        c = _bare_client(monkeypatch, "http://localhost:11434", timeout_env="900.5")
        assert c.timeout == 900

    def test_env_malformed_keeps_default(self, monkeypatch):
        c = _bare_client(monkeypatch, "http://localhost:11434", timeout_env="not-a-number")
        assert c.timeout == 150

    def test_empty_env_keeps_default(self, monkeypatch):
        c = _bare_client(monkeypatch, "http://localhost:11434", timeout_env="")
        assert c.timeout == 150

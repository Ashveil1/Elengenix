"""
Ollama Local AI Provider Plugin — Example custom AI provider.

This plugin adds support for local Ollama models (llama3, codellama, mistral, etc.)
to Elengenix. Once installed, you can use Ollama models in `config.yaml`:

    active_provider: ollama_local
    active_models:
      - ollama_local/llama3:70b
      - ollama_local/codellama:13b

Or via env var:
    ACTIVE_MODELS=ollama_local/llama3:70b

Setup:
  1. Install Ollama: https://ollama.ai
  2. Pull a model: `ollama pull llama3`
  3. Start the server: `ollama serve` (or it auto-starts on Linux)
  4. Copy this folder to ~/.elengenix/plugins/ollama_local/
  5. Run Elengenix — the provider will be auto-discovered
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, List

PLUGIN_NAME = "ollama_local"
DEFAULT_OLLAMA_URL = "http://localhost:11434"


def register(api) -> None:
    """Register the Ollama provider with Elengenix."""
    api.logger.info("Registering Ollama local provider (URL: %s)", DEFAULT_OLLAMA_URL)

    def list_models() -> List[str]:
        """Fetch available models from the local Ollama server."""
        try:
            req = urllib.request.Request(
                f"{DEFAULT_OLLAMA_URL}/api/tags",
                headers={"User-Agent": "Elengenix-OllamaPlugin/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return [m["name"] for m in data.get("models", [])]
        except Exception as e:  # noqa: BLE001
            api.logger.warning("Failed to list Ollama models: %s", e)
            return []

    def chat(messages: List[dict], model: str = "llama3") -> str:
        """Send a chat completion request to Ollama.

        Args:
            messages: List of {"role": "user|assistant|system", "content": "..."}
            model: Model name (e.g. "llama3", "codellama:13b")

        Returns:
            The assistant's response text
        """
        try:
            payload = json.dumps(
                {
                    "model": model,
                    "messages": messages,
                    "stream": False,
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                f"{DEFAULT_OLLAMA_URL}/api/chat",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Elengenix-OllamaPlugin/1.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data.get("message", {}).get("content", "")
        except urllib.error.URLError as e:
            api.logger.error("Ollama request failed: %s", e)
            return f"[Ollama error: {e}]"
        except Exception as e:  # noqa: BLE001
            api.logger.error("Unexpected Ollama error: %s", e)
            return f"[Ollama error: {e}]"

    api.register_ai_provider(
        name=PLUGIN_NAME,
        chat_func=chat,
        list_models_func=list_models,
    )
    api.logger.info("Ollama provider registered. Use 'ollama_local/<model>' in config.")

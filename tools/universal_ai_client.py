"""tools/universal_ai_client.py

Universal AI Client - OpenAI-compatible API for any provider.

Design Principle (OpenClaw-style):
- Direct HTTP API calls (no vendor-locked libraries)
- OpenAI-compatible format (universal standard)
- Support: OpenAI, Gemini, Anthropic, Ollama, LocalAI, etc.
- Easy provider switching (just change base_url + key)

Providers with OpenAI-compatible API:
- OpenAI (native)
- Gemini (via endpoint)
- Anthropic (Claude with OpenAI adapter)
- Ollama (local models)
- LocalAI, vLLM, etc.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Generator, List, Optional
from urllib.parse import urljoin

import requests

logger = logging.getLogger("elengenix.universal_ai")


@dataclass
class AIMessage:
    """Standardized message format."""
    role: str  # system, user, assistant, tool
    content: str
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AIResponse:
    """Standardized response format."""
    content: str
    model: str
    usage: Dict[str, int]
    raw_response: Optional[Dict] = None


class UniversalAIClient:
    """
    Universal AI client using OpenAI-compatible API.
    Works with any provider that supports /v1/chat/completions
    """

    # Default configurations for popular providers
    PROVIDER_CONFIGS = {
        "openai": {
            "base_url": "https://api.openai.com/v1",
            "env_key": "OPENAI_API_KEY",
            "default_model": "gpt-4o-mini",
        },
        "gemini": {
            "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",  # Gemini OpenAI compatibility
            "env_key": "GEMINI_API_KEY",
            "default_model": "gemini-1.5-flash",
        },
        "anthropic": {
            "base_url": "https://api.anthropic.com/v1",  # Claude uses different format, needs adapter
            "env_key": "ANTHROPIC_API_KEY",
            "default_model": "claude-3-haiku-20240307",
            "custom_format": True,
        },
        "ollama": {
            "base_url": "http://localhost:11434/v1",  # Ollama OpenAI compatibility
            "env_key": None,  # No key needed for local
            "default_model": "llama3.1:8b",
        },
        "groq": {
            "base_url": "https://api.groq.com/openai/v1",
            "env_key": "GROQ_API_KEY",
            "default_model": "llama-3.1-8b-instant",
        },
        "openrouter": {
            "base_url": "https://openrouter.ai/api/v1",
            "env_key": "OPENROUTER_API_KEY",
            "default_model": "meta-llama/llama-3.1-8b-instruct",
        },
    }

    def __init__(
        self,
        provider: str = "auto",
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 60,
        max_retries: int = 3,
    ):
        """
        Initialize universal AI client.
        
        Args:
            provider: Provider name (openai, gemini, anthropic, ollama, etc.) or "auto"
            base_url: Custom API endpoint (overrides provider default)
            api_key: API key (overrides environment variable)
            model: Model name (overrides provider default)
            timeout: Request timeout in seconds
            max_retries: Number of retries on failure
        """
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Auto-detect provider if not specified
        if provider == "auto":
            provider = self._detect_provider()
        
        self.provider = provider
        config = self.PROVIDER_CONFIGS.get(provider, {})
        
        # Set base URL
        self.base_url = base_url or config.get("base_url", "")
        
        # Set API key (priority: param > env > None)
        if api_key:
            self.api_key = api_key
        elif "env_key" in config:
            self.api_key = os.getenv(config["env_key"], "")
        else:
            self.api_key = ""
        
        # Set model
        self.model = model or config.get("default_model", "gpt-4o-mini")
        
        # Check if provider needs custom format (like Anthropic)
        self.custom_format = config.get("custom_format", False)
        
        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
        })
        if self.api_key:
            self.session.headers.update({
                "Authorization": f"Bearer {self.api_key}",
            })
        
        logger.info(f"Universal AI Client initialized: {provider} @ {self.base_url}, model={self.model}")

    def _detect_provider(self) -> str:
        """Auto-detect provider from environment variables."""
        # Priority order
        if os.getenv("OPENAI_API_KEY"):
            return "openai"
        elif os.getenv("GEMINI_API_KEY"):
            return "gemini"
        elif os.getenv("ANTHROPIC_API_KEY"):
            return "anthropic"
        elif os.getenv("GROQ_API_KEY"):
            return "groq"
        elif os.getenv("OLLAMA_URL") or self._check_ollama():
            return "ollama"
        else:
            # Default to Ollama (local) if nothing else available
            logger.warning("No API key found, defaulting to Ollama (local)")
            return "ollama"

    def _check_ollama(self) -> bool:
        """Check if Ollama is running locally."""
        try:
            resp = requests.get("http://localhost:11434/api/tags", timeout=2)
            return resp.status_code == 200
        except:
            return False

    def chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
    ) -> AIResponse:
        """
        Send chat completion request.
        
        Args:
            messages: List of messages (system, user, assistant)
            temperature: Sampling temperature (0-2)
            max_tokens: Maximum tokens to generate
            stream: Whether to stream the response
        
        Returns:
            AIResponse with content and metadata
        """
        # Format messages for API
        formatted_messages = [
            {"role": m.role, "content": m.content}
            for m in messages
        ]
        
        # Build request payload (OpenAI format)
        payload = {
            "model": self.model,
            "messages": formatted_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": stream,
        }
        
        # Handle custom formats (Anthropic, etc.)
        if self.custom_format:
            return self._call_custom_api(payload, stream)
        
        # Standard OpenAI-compatible API call
        return self._call_openai_api(payload, stream)

    def _call_openai_api(self, payload: Dict, stream: bool) -> AIResponse:
        """Call OpenAI-compatible API."""
        url = urljoin(self.base_url, "chat/completions")
        
        for attempt in range(self.max_retries):
            try:
                if stream:
                    return self._stream_response(url, payload)
                
                resp = self.session.post(
                    url,
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                
                # Parse response
                choice = data["choices"][0]
                content = choice["message"]["content"]
                
                return AIResponse(
                    content=content,
                    model=data.get("model", self.model),
                    usage=data.get("usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}),
                    raw_response=data,
                )
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    logger.error("Authentication failed - check API key")
                    raise
                elif attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                raise
            except Exception as e:
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise
        
        raise RuntimeError("Max retries exceeded")

    def _call_custom_api(self, payload: Dict, stream: bool) -> AIResponse:
        """Handle custom API formats (Anthropic, etc.)."""
        if self.provider == "anthropic":
            return self._call_anthropic(payload, stream)
        
        # Add more custom handlers here
        raise NotImplementedError(f"Custom format for {self.provider} not implemented")

    def _call_anthropic(self, payload: Dict, stream: bool) -> AIResponse:
        """Call Anthropic Claude API."""
        url = "https://api.anthropic.com/v1/messages"
        
        # Convert OpenAI format to Anthropic format
        system_msg = ""
        messages = []
        for m in payload["messages"]:
            if m["role"] == "system":
                system_msg = m["content"]
            else:
                messages.append({"role": m["role"], "content": m["content"]})
        
        anthropic_payload = {
            "model": self.model,
            "max_tokens": payload["max_tokens"],
            "temperature": payload["temperature"],
            "system": system_msg,
            "messages": messages,
        }
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        
        resp = requests.post(url, json=anthropic_payload, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        
        return AIResponse(
            content=data["content"][0]["text"],
            model=data["model"],
            usage={
                "prompt_tokens": data["usage"]["input_tokens"],
                "completion_tokens": data["usage"]["output_tokens"],
                "total_tokens": data["usage"]["input_tokens"] + data["usage"]["output_tokens"],
            },
            raw_response=data,
        )

    def _stream_response(self, url: str, payload: Dict) -> Generator[str, None, None]:
        """Stream response from API."""
        payload["stream"] = True
        
        with self.session.post(url, json=payload, timeout=self.timeout, stream=True) as resp:
            resp.raise_for_status()
            
            for line in resp.iter_lines():
                if not line:
                    continue
                    
                line = line.decode("utf-8")
                if line.startswith("data: "):
                    data = line[6:]  # Remove "data: " prefix
                    if data == "[DONE]":
                        break
                    
                    try:
                        chunk = json.loads(data)
                        delta = chunk["choices"][0].get("delta", {})
                        if "content" in delta:
                            yield delta["content"]
                    except:

    def simple_chat(self, user_message: str, system_prompt: Optional[str] = None) -> str:
        """
        Simple one-shot chat (non-streaming).
        
        Args:
            user_message: User's message
            system_prompt: Optional system prompt
        
        Returns:
            AI response as string
        """
        messages = []
        if system_prompt:
            messages.append(AIMessage(role="system", content=system_prompt))
        messages.append(AIMessage(role="user", content=user_message))
        
        response = self.chat(messages)
        return response.content

    def is_available(self) -> bool:
        """Check if the client is properly configured."""
        if not self.base_url:
            return False
        if self.provider not in ["ollama"] and not self.api_key:
            return False
        return True

    def get_status(self) -> Dict[str, Any]:
        """Get client status information."""
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "has_api_key": bool(self.api_key),
            "available": self.is_available(),
        }


class AIClientManager:
    """
    Manager for multiple AI clients with fallback.
    """

    def __init__(self, preferred_order: Optional[List[str]] = None):
        """
        Initialize with preferred provider order.
        
        Args:
            preferred_order: List of provider names in preference order
        """
        self.preferred_order = preferred_order or ["gemini", "openai", "groq", "ollama"]
        self.clients: Dict[str, UniversalAIClient] = {}
        self.active_client: Optional[UniversalAIClient] = None
        
        self._init_clients()

    def _init_clients(self) -> None:
        """Initialize all available clients."""
        for provider in self.preferred_order:
            try:
                client = UniversalAIClient(provider=provider)
                if client.is_available():
                    self.clients[provider] = client
                    if not self.active_client:
                        self.active_client = client
                        logger.info(f"Active AI provider: {provider}")
            except Exception as e:
                logger.debug(f"Failed to initialize {provider}: {e}")

    def chat(self, messages: List[AIMessage], **kwargs) -> AIResponse:
        """Chat with fallback."""
        if not self.active_client:
            raise RuntimeError("No AI provider available. Check your API keys.")
        
        # Try active client first
        try:
            return self.active_client.chat(messages, **kwargs)
        except Exception as e:
            logger.warning(f"{self.active_client.provider} failed: {e}")
        
        # Fallback to other clients
        for provider, client in self.clients.items():
            if client == self.active_client:
                continue
            try:
                logger.info(f"Falling back to {provider}")
                return client.chat(messages, **kwargs)
            except Exception as e:
                logger.warning(f"{provider} failed: {e}")
                continue
        
        raise RuntimeError("All AI providers failed")

    def simple_chat(self, message: str, system_prompt: Optional[str] = None) -> str:
        """Simple chat with fallback."""
        messages = []
        if system_prompt:
            messages.append(AIMessage(role="system", content=system_prompt))
        messages.append(AIMessage(role="user", content=message))
        
        response = self.chat(messages)
        return response.content

    def get_active_provider(self) -> str:
        """Get currently active provider name."""
        return self.active_client.provider if self.active_client else "none"


def create_default_client() -> UniversalAIClient:
    """Factory function to create default client."""
    return UniversalAIClient(provider="auto")


def format_ai_status(status: Dict[str, Any]) -> str:
    """Format AI client status for display."""
    lines = [
        f"🤖 AI Provider: {status['provider']}",
        f"📍 Endpoint: {status['base_url']}",
        f"🧠 Model: {status['model']}",
        f"🔑 API Key: {'✓' if status['has_api_key'] else '✗'}",
        f"✅ Available: {'Yes' if status['available'] else 'No'}",
    ]
    return "\n".join(lines)

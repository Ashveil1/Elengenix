"""tools/universal_ai_client.py

Universal AI Client - OpenAI-compatible API for any provider.

Design Principle (OpenClaw-style):
- Direct HTTP API calls (no vendor-locked libraries)
- OpenAI-compatible format (universal standard)
- Support: OpenAI, Gemini, Anthropic, Ollama, LocalAI, etc.
- Easy provider switching (just change base_url + key)
- Async via httpx (optional); falls back to synchronous requests.

Providers with OpenAI-compatible API:
- OpenAI (native)
- Gemini (via endpoint)
- Anthropic (Claude with OpenAI adapter)
- Ollama (local models)
- LocalAI, vLLM, etc.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from elengenix.paths import find_env

# Auto-load .env so API keys are available without manual setup
try:
    from dotenv import load_dotenv

    _env = find_env()
    if _env:
        load_dotenv(_env, override=False)
except ImportError:
    pass

# Primary transport: httpx (async-capable, faster).
# Fallback: requests (synchronous, always available).
try:
    import httpx as _httpx

    HTTPX_AVAILABLE = True
except ImportError:
    _httpx = None  # type: ignore[assignment]
    HTTPX_AVAILABLE = False

import requests

logger = logging.getLogger("elengenix.universal_ai")


@dataclass
class AIMessage:
    """Standardized message format."""

    role: str  # system, user, assistant, tool
    content: str
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ToolCall:
    """A structured tool-call returned by the model via native function-calling."""

    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class AIResponse:
    """Standardized response format."""

    content: str
    model: str
    usage: Dict[str, int]
    raw_response: Optional[Dict] = None
    tool_calls: Optional[List[ToolCall]] = None


# ── Native tool-calling schema for the agent action set ───────────────────
# Mirrors the actions defined in prompts/system_prompt.txt.  When a provider
# supports native function-calling these schemas are sent in the ``tools``
# parameter so the model returns structured calls instead of free-text JSON.
ACTION_TOOLS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "Execute a shell command on the target",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to run"},
                    "purpose": {"type": "string", "description": "Why this command is being run"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ai_tool",
            "description": "Execute a custom Python tool created by the agent",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Tool name"},
                    "kwargs": {"type": "object", "description": "Arguments to pass"},
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_script",
            "description": "Write and run a custom script",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string"},
                    "runner": {"type": "string", "description": "e.g. python3, bash, go run"},
                    "purpose": {"type": "string"},
                    "code": {"type": "string", "description": "Script content"},
                },
                "required": ["filename", "code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "install_tool",
            "description": "Request installation of a security tool (requires user approval)",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "manager": {"type": "string", "description": "pip/go/apt/cargo/npm/brew"},
                    "purpose": {"type": "string"},
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ask_user",
            "description": "Ask the user a question or request input",
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {"type": "string"},
                    "input_type": {"type": "string", "enum": ["text", "confirm", "password"]},
                },
                "required": ["question"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_findings",
            "description": "Report a discovered vulnerability to the system",
            "parameters": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string"},
                                "endpoint": {"type": "string"},
                                "severity": {
                                    "type": "string",
                                    "enum": ["critical", "high", "medium", "low", "info"],
                                },
                                "description": {"type": "string"},
                                "evidence": {"type": "string"},
                            },
                            "required": ["type", "severity"],
                        },
                    },
                    "target": {"type": "string"},
                },
                "required": ["findings"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for information, CVEs, or exploits",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "save_memory",
            "description": "Save an important finding for future sessions",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "learning": {"type": "string", "description": "What was learned"},
                    "category": {"type": "string"},
                },
                "required": ["learning"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "Complete the mission with a summary",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string", "description": "Mission summary and findings"},
                },
                "required": ["summary"],
            },
        },
    },
]


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
            "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",  # OpenAI-compatible endpoint, NO /v1 suffix
            "env_key": "GEMINI_API_KEY",
            "default_model": "gemini-2.5-flash",
        },
        "anthropic": {
            "base_url": "https://api.anthropic.com/v1",  # Claude uses different format, needs adapter
            "env_key": "ANTHROPIC_API_KEY",
            "default_model": "claude-3-7-sonnet-latest",
            "custom_format": True,
        },
        "ollama": {
            "base_url": "http://localhost:11434/v1",  # Ollama OpenAI compatibility
            "env_key": None,  # No key needed for local
            "default_model": "llama3.2",
        },
        "groq": {
            "base_url": "https://api.groq.com/openai/v1",
            "env_key": "GROQ_API_KEY",
            "default_model": "llama-3.3-70b-versatile",
        },
        "openrouter": {
            "base_url": "https://openrouter.ai/api/v1",
            "env_key": "OPENROUTER_API_KEY",
            "default_model": "meta-llama/llama-3.3-70b-instruct",
        },
        "nvidia": {
            "base_url": "https://integrate.api.nvidia.com/v1",
            "env_key": "NVIDIA_API_KEY",
            "default_model": "nvidia/nemotron-3-super-120b-a12b",
        },
        "deepseek": {
            "base_url": "https://api.deepseek.com/v1",
            "env_key": "DEEPSEEK_API_KEY",
            "default_model": "deepseek-chat",
        },
        "mistral": {
            "base_url": "https://api.mistral.ai/v1",
            "env_key": "MISTRAL_API_KEY",
            "default_model": "mistral-large-latest",
        },
        "together": {
            "base_url": "https://api.together.xyz/v1",
            "env_key": "TOGETHER_API_KEY",
            "default_model": "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        },
        "perplexity": {
            "base_url": "https://api.perplexity.ai",
            "env_key": "PERPLEXITY_API_KEY",
            "default_model": "llama-3.1-sonar-large-128k-online",
        },
        "custom": {
            "base_url": "",
            "env_key": None,
            "default_model": "custom-model",
        },
    }

    def __init__(
        self,
        provider: str = "auto",
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 150,
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

        Settings resolution priority (high → low):
          1. Constructor params
          2. config.yaml providers.{name}.*  (via tools.ai_config)
          3. .env  {PROVIDER}_API_KEY, {PROVIDER}_MODEL, {PROVIDER}_BASE_URL
          4. PROVIDER_CONFIGS hardcoded defaults (this class)
        """
        # Late import to avoid circular dep
        from tools.ai_config import resolve_provider_settings

        self.timeout = timeout
        self.max_retries = max_retries

        # Auto-detect provider if not specified
        if provider == "auto":
            provider = self._detect_provider()

        self.provider = provider
        config = self.PROVIDER_CONFIGS.get(provider, {})

        # Resolve all settings via ai_config (which reads config.yaml + env)
        resolved = resolve_provider_settings(
            provider=provider,
            model=model,
            base_url=base_url,
            api_key=api_key,
        )
        # base_url: param > config.yaml > env > PROVIDER_CONFIGS hardcoded
        self.base_url = resolved["base_url"] or config.get("base_url", "")
        if provider == "custom" and not self.base_url:
            self.base_url = os.getenv("CUSTOM_API_BASE", "")
        # model: param > config.yaml > env > PROVIDER_CONFIGS default
        self.model = (
            resolved["model"]
            or os.getenv(f"{provider.upper()}_MODEL")
            or config.get("default_model", "gpt-4o-mini")
        )
        # api_key: param > config.yaml lookup > PROVIDER_CONFIGS env_key
        self.api_key = resolved["api_key"]
        if not self.api_key and provider == "custom":
            self.api_key = os.getenv("CUSTOM_API_KEY", "")
        elif not self.api_key and config.get("env_key"):
            self.api_key = os.getenv(config["env_key"], "")

        # Check if provider needs custom format (like Anthropic)
        self.custom_format = config.get("custom_format", False)

        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json",
            }
        )
        if self.api_key:
            self.session.headers.update(
                {
                    "Authorization": f"Bearer {self.api_key}",
                }
            )

        # Rate Limiting configuration
        env_rpm_key = f"RPM_{self.model.upper()}"
        self.rpm_limit = int(os.environ.get(env_rpm_key, "40"))
        self.min_delay = 60.0 / max(1, self.rpm_limit)
        self.last_request_time = 0.0

        logger.info(
            f"Universal AI Client initialized: {provider} @ {self.base_url}, "
            f"model={self.model}, api_key={'***' if self.api_key else '(missing)'}, "
            f"sources={resolved['sources']}"
        )

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
        elif os.getenv("NVIDIA_API_KEY"):
            return "nvidia"
        elif os.getenv("DEEPSEEK_API_KEY"):
            return "deepseek"
        elif os.getenv("MISTRAL_API_KEY"):
            return "mistral"
        elif os.getenv("OPENROUTER_API_KEY"):
            return "openrouter"
        elif os.getenv("TOGETHER_API_KEY"):
            return "together"
        elif os.getenv("PERPLEXITY_API_KEY"):
            return "perplexity"
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
        except Exception:
            return False

    def chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str] = None,
    ) -> AIResponse:
        """
        Send chat completion request.

        Args:
            messages: List of messages (system, user, assistant)
            temperature: Sampling temperature (0-2)
            max_tokens: Maximum tokens to generate
            stream: Whether to stream the response
            tools: Optional list of tool schemas for native function-calling
            tool_choice: Optional tool choice hint ("auto", "none", or a tool name)

        Returns:
            AIResponse with content and metadata
        """
        # Enforce Rate Limiting
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_delay:
            time.sleep(self.min_delay - elapsed)

        self.last_request_time = time.time()

        # Format messages for API
        formatted_messages = [{"role": m.role, "content": m.content} for m in messages]

        # Build request payload (OpenAI format)
        payload = {
            "model": self.model,
            "messages": formatted_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": stream,
        }

        # Native tool-calling support
        if tools:
            payload["tools"] = tools
            if tool_choice:
                payload["tool_choice"] = (
                    tool_choice
                    if tool_choice in ("auto", "none")
                    else {"type": "function", "function": {"name": tool_choice}}
                )

        # NVIDIA-specific parameters (e.g., for reasoning models)
        if self.provider == "nvidia":
            import os

            param_mode = os.getenv("NVIDIA_PARAM_MODE", "auto")
            model_lower = self.model.lower()

            if param_mode == "nemotron" or (param_mode == "auto" and "nemotron" in model_lower):
                payload["chat_template_kwargs"] = {"enable_thinking": True}
                payload["reasoning_budget"] = min(max_tokens, 16384)
            elif param_mode == "disable" or (param_mode == "auto" and "deepseek" in model_lower):
                payload["chat_template_kwargs"] = {"thinking": False}
            elif param_mode == "enable":
                payload["chat_template_kwargs"] = {"thinking": True}

        # Handle custom formats (Anthropic, etc.)
        if self.custom_format:
            return self._call_custom_api(payload, stream)

        # Standard OpenAI-compatible API call
        return self._call_openai_api(payload, stream)

    def _call_openai_api(self, payload: Dict, stream: bool) -> AIResponse:
        """Call OpenAI-compatible API."""
        url = self.base_url.rstrip("/") + "/chat/completions"

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
                content = choice["message"].get("content") or ""
                raw_tool_calls = choice["message"].get("tool_calls")

                parsed_tool_calls = None
                if raw_tool_calls:
                    parsed_tool_calls = []
                    for tc in raw_tool_calls:
                        try:
                            args = tc["function"]["arguments"]
                            if isinstance(args, str):
                                args = json.loads(args)
                        except (json.JSONDecodeError, KeyError):
                            args = {}
                        parsed_tool_calls.append(
                            ToolCall(
                                id=tc.get("id", ""),
                                name=tc["function"]["name"],
                                arguments=args,
                            )
                        )

                return AIResponse(
                    content=content,
                    model=data.get("model", self.model),
                    usage=data.get(
                        "usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
                    ),
                    raw_response=data,
                    tool_calls=parsed_tool_calls,
                )

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    logger.error("Authentication failed - check API key")
                    raise
                elif attempt < self.max_retries - 1:
                    time.sleep(2**attempt)  # Exponential backoff
                    continue
                raise
            except Exception:
                if attempt < self.max_retries - 1:
                    time.sleep(2**attempt)
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
        """Call Anthropic Claude API with retry logic, tool-calling, and prompt caching."""
        url = "https://api.anthropic.com/v1/messages"

        # Convert OpenAI format to Anthropic format
        system_msg = ""
        messages = []
        for m in payload["messages"]:
            if m["role"] == "system":
                system_msg = m["content"]
            else:
                messages.append({"role": m["role"], "content": m["content"]})

        # Build system param: use cache_control for prompt caching when system
        # prompt is large enough to benefit (>1000 chars). This saves both
        # latency and cost on multi-step missions where the same base prompt
        # is sent every step.
        if system_msg:
            if len(system_msg) > 1000:
                system_param = [
                    {
                        "type": "text",
                        "text": system_msg,
                        "cache_control": {"type": "ephemeral"},
                    }
                ]
            else:
                system_param = system_msg
        else:
            system_param = ""

        anthropic_payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": payload["max_tokens"],
            "temperature": payload["temperature"],
            "system": system_param,
            "messages": messages,
        }

        # Native tool-calling for Anthropic (tool_use)
        if payload.get("tools"):
            anthropic_payload["tools"] = []
            for tool in payload["tools"]:
                if tool.get("type") == "function":
                    anthropic_payload["tools"].append(
                        {
                            "name": tool["function"]["name"],
                            "description": tool["function"].get("description", ""),
                            "input_schema": tool["function"].get("parameters", {}),
                        }
                    )

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2024-10-22",
        }

        for attempt in range(self.max_retries):
            try:
                resp = self.session.post(
                    url, json=anthropic_payload, headers=headers, timeout=self.timeout
                )
                resp.raise_for_status()
                data = resp.json()

                # Parse Anthropic response: content blocks can be text or tool_use
                text_parts: List[str] = []
                parsed_tool_calls: List[ToolCall] = []
                for block in data.get("content", []):
                    if block.get("type") == "text":
                        text_parts.append(block.get("text", ""))
                    elif block.get("type") == "tool_use":
                        parsed_tool_calls.append(
                            ToolCall(
                                id=block.get("id", ""),
                                name=block.get("name", ""),
                                arguments=block.get("input", {}),
                            )
                        )

                return AIResponse(
                    content="\n".join(text_parts),
                    model=data["model"],
                    usage={
                        "prompt_tokens": data["usage"]["input_tokens"],
                        "completion_tokens": data["usage"]["output_tokens"],
                        "total_tokens": data["usage"]["input_tokens"]
                        + data["usage"]["output_tokens"],
                    },
                    raw_response=data,
                    tool_calls=parsed_tool_calls if parsed_tool_calls else None,
                )
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    logger.error("Authentication failed - check API key")
                    raise
                elif attempt < self.max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise
            except requests.exceptions.RequestException as e:
                logger.debug(f"API request failed (attempt {attempt+1}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise

        raise RuntimeError("Max retries exceeded")

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
                    except Exception:
                        pass

    async def chat_async(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> AIResponse:
        """Async chat completion via httpx (falls back to thread-pool executor).

        When ``httpx`` is installed the HTTP call is truly non-blocking.
        Otherwise the synchronous ``requests`` call is offloaded to a
        thread pool so the caller's event loop is not blocked.
        """
        formatted_messages = [{"role": m.role, "content": m.content} for m in messages]
        payload = {
            "model": self.model,
            "messages": formatted_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }

        if self.custom_format:
            return self._call_custom_api(payload, stream=False)

        url = self.base_url.rstrip("/") + "/chat/completions"

        # Rate-limit enforcement (same as sync path).
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_delay:
            await asyncio.sleep(self.min_delay - elapsed)
        self.last_request_time = time.time()

        if HTTPX_AVAILABLE:
            return await self._call_openai_api_async(url, payload)
        else:
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None, lambda: self._call_openai_api(payload, stream=False)
            )
            return resp

    async def _call_openai_api_async(self, url: str, payload: Dict) -> AIResponse:
        """Async HTTP POST via httpx."""
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        for attempt in range(self.max_retries):
            try:
                async with _httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    resp.raise_for_status()
                    data = resp.json()

                choice = data["choices"][0]
                return AIResponse(
                    content=choice["message"]["content"],
                    model=data.get("model", self.model),
                    usage=data.get(
                        "usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
                    ),
                    raw_response=data,
                )

            except Exception as e:
                if attempt < self.max_retries - 1:
                    wait = 2**attempt
                    logger.debug(f"httpx attempt {attempt+1} failed: {e}, retrying in {wait}s")
                    await asyncio.sleep(wait)
                    continue
                raise

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
        """Check if the client is properly configured and the endpoint is reachable.

        For local providers (ollama, local, custom with localhost) we ping the
        server first to avoid reporting a "phantom" client that points at a
        dead localhost port. For cloud providers we only check that we have
        an API key (no network call here — keep init fast).
        """
        if not self.base_url:
            return False
        if (
            self.provider == "ollama"
            or self.base_url.startswith("http://localhost")
            or self.base_url.startswith("http://127.0.0.1")
        ):
            # Local provider — must actually be reachable
            return self._ping_local()
        if not self.api_key:
            return False
        return True

    def _ping_local(self, timeout: float = 1.0) -> bool:
        """Quick TCP/HTTP ping to a local provider.

        Tries GET /v1/models first (OpenAI-compatible), falls back to a raw
        TCP connect to the host:port. Returns True if the server responds.
        Cached per-instance so we only ping once.
        """
        if hasattr(self, "_ping_ok"):
            return self._ping_ok
        from urllib.parse import urlparse

        parsed = urlparse(self.base_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        # Try HTTP GET /v1/models first (OpenAI convention)
        try:
            r = requests.get(
                self.base_url.rstrip("/") + "/models",
                timeout=timeout,
            )
            self._ping_ok = r.status_code < 500
            return self._ping_ok
        except Exception:
            pass
        # Fallback: raw TCP connect
        try:
            import socket

            with socket.create_connection((host, port), timeout=timeout):
                self._ping_ok = True
                return True
        except Exception:
            self._ping_ok = False
            return False

    def fetch_available_models(self) -> List[str]:
        """Fetch models from the provider's /v1/models endpoint."""
        try:
            # Special handling for Anthropic (don't support /models well)
            if self.provider == "anthropic":
                return [
                    self.model,
                    "claude-3-7-sonnet-latest",
                    "claude-3-5-sonnet-latest",
                    "claude-3-opus-latest",
                ]

            url = self.base_url.rstrip("/") + "/models"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                models = []

                if isinstance(data, dict) and "data" in data:
                    for item in data["data"]:
                        if isinstance(item, dict) and "id" in item:
                            models.append(item["id"])
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, str):
                            models.append(item)
                        elif isinstance(item, dict) and "id" in item:
                            models.append(item["id"])

                # Filter chat/instruct models
                chat_models = []
                exclude_keywords = [
                    "embedding",
                    "whisper",
                    "tts",
                    "dall-e",
                    "moderation",
                    "vision-preview",
                ]
                for m in models:
                    if not any(kw in m.lower() for kw in exclude_keywords):
                        chat_models.append(m)

                return sorted(chat_models) if chat_models else [self.model]
        except Exception as e:
            logger.debug(f"Failed to fetch remote models for {self.provider}: {e}")

        return [self.model]

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
            preferred_order: List of provider names in preference order.
                If None, uses ai_config.get_provider_order() (from config.yaml).
        """
        if preferred_order is not None:
            self.preferred_order = list(preferred_order)
        else:
            # Single source of truth: config.yaml > ACTIVE_AI_PROVIDER env > hardcoded
            from tools.ai_config import get_active_provider, get_provider_order

            self.preferred_order = get_provider_order()
            logger.info(
                f"Provider order from config.yaml: {self.preferred_order[:3]}... (active={get_active_provider()})"
            )

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
                        logger.info(f"Active AI provider: {provider} / {client.model}")
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

    def get_all_providers_status(self) -> List[Dict[str, Any]]:
        """Get status for all supported providers."""
        status_list = []
        # Temporarily silence logs to avoid cluttering during discovery
        original_level = logger.level
        logger.setLevel(logging.WARNING)

        for p_name in sorted(list(UniversalAIClient.PROVIDER_CONFIGS.keys())):
            try:
                temp_client = UniversalAIClient(provider=p_name)
                status = temp_client.get_status()
                # Check if it's currently the active one
                status["active"] = self.active_client and self.active_client.provider == p_name
                status_list.append(status)
            except Exception:
                continue

        logger.setLevel(original_level)
        return status_list


def create_default_client() -> UniversalAIClient:
    """Factory function to create default client."""
    return UniversalAIClient(provider="auto")


def format_ai_status(status: Dict[str, Any]) -> str:
    """Format AI client status for display."""
    lines = [
        f" AI Provider: {status['provider']}",
        f" Endpoint: {status['base_url']}",
        f" Model: {status['model']}",
        f" API Key: {'' if status['has_api_key'] else ''}",
        f" Available: {'Yes' if status['available'] else 'No'}",
    ]
    return "\n".join(lines)

"""elengenix.providers.ollama — Ollama local LLM provider adapter (Python port).

Port of PentAGI's ``backend/pkg/providers/ollama/ollama.go``. Drives a
local Ollama server via the ``ollama`` Python SDK (or direct HTTP if the
SDK is unavailable). Ollama is OpenAI-compatible at
``http://localhost:11434/v1`` but the official ``ollama`` Python SDK
exposes a richer native API (``/api/chat``, ``/api/generate``,
``/api/list``) which we prefer.

Key features ported from the Go original
-----------------------------------------
* **Default model** — config-defined (env: ``OLLAMA_SERVER_MODEL`` /
  ``OLLAMA_MODEL``). PentAGI's ``OllamaServerModel`` defaults to
  ``llama3.1`` in its ``config.go``.
* **Auth** — optional. Local Ollama does not require an API key; the
  env var ``OLLAMA_SERVER_API_KEY`` / ``OLLAMA_API_KEY`` is for Ollama
  Cloud support.
* **Tool-call ID template** — none. Ollama auto-generates tool-call IDs;
  :meth:`OllamaProvider.get_tool_call_id_template` returns the empty
  string.
* **Model auto-pull** — when ``pull_models_enabled=True`` (env:
  ``OLLAMA_SERVER_PULL_MODELS_ENABLED``), the provider calls
  ``client.pull(model)`` on startup for any configured model that is
  not already present locally. Default pull timeout: 10 minutes.
* **Model discovery** — when ``load_models_enabled=True`` (env:
  ``OLLAMA_SERVER_LOAD_MODELS_ENABLED``), the provider queries
  ``client.list()`` and exposes the available local models via
  :meth:`get_models`.
* **No pricing** — local inference is free. ``PriceInfo`` is ``None``
  for all agent slots.
* **Default options** — ``n=1``, ``max_tokens=32768`` (matches
  PentAGI's ``ollama.go`` ``BuildProviderConfig`` defaults).

The ``ollama`` SDK is imported lazily inside
:meth:`OllamaProvider._get_client` so that environments without
``ollama`` installed (e.g. when only ``openai`` is being used) can
still import this module.
"""

from __future__ import annotations

import logging
import os
from typing import Any, List, Optional
from urllib import parse as urllib_parse

from elengenix.providers.base import (
    AgentConfig,
    CallUsage,
    Choice,
    ContentResponse,
    MessageContent,
    MessagePart,
    ModelConfig,
    ModelsConfig,
    PriceInfo,
    ProviderConfig,
    ProviderOptionsType,
    ProviderType,
    StreamingCallback,
    TextPart,
    ToolCall,
    ToolCallResponse,
)

logger = logging.getLogger("elengenix.providers.ollama")

# ---------------------------------------------------------------------------
# Constants — ported from ollama.go
# ---------------------------------------------------------------------------

#: Default Ollama server URL. Overridable via ``OLLAMA_SERVER_URL`` (or
#: ``OLLAMA_HOST`` for native Ollama compatibility).
OLLAMA_DEFAULT_SERVER_URL: str = "http://localhost:11434"

#: Default fallback model when no per-agent model is configured. The
#: caller should set ``OLLAMA_SERVER_MODEL`` to the actual model they
#: want to use; this constant is a safe default for the orchestrator's
#: ``model()`` lookup.
OLLAMA_DEFAULT_MODEL: str = "llama3.1"

#: Default pull timeout — 10 minutes (matches PentAGI's
#: ``defaultPullTimeout``).
OLLAMA_DEFAULT_PULL_TIMEOUT: float = 600.0

#: Default API call timeout for /api/list and /api/show — 10 seconds
#: (matches PentAGI's ``defaultAPICallTimeout``).
OLLAMA_DEFAULT_API_CALL_TIMEOUT: float = 10.0

#: Default max_tokens — matches PentAGI's ollama.go BuildProviderConfig
#: default of 32768.
OLLAMA_DEFAULT_MAX_TOKENS: int = 32_768

#: 429 retry policy — Ollama doesn't typically rate-limit (local
#: inference), but the constants are exposed for parity with other
#: providers.
OLLAMA_MAX_429_RETRIES: int = 10
OLLAMA_429_BASE_DELAY: float = 5.0


# ---------------------------------------------------------------------------
# Default provider config — empty (caller supplies via YAML file or
# env vars). Mirrors PentAGI's DefaultProviderConfig which loads from
# configFS / cfg.OllamaServerConfig.
# ---------------------------------------------------------------------------


def _default_agent(model: str = "") -> AgentConfig:
    """Build the default Ollama :class:`AgentConfig`. Matches PentAGI's
    ollama.go ``BuildProviderConfig`` defaults: ``n=1``,
    ``max_tokens=32768``."""
    return AgentConfig(
        model=model,
        n=1,
        max_tokens=OLLAMA_DEFAULT_MAX_TOKENS,
    )


def get_default_config(model: str = "") -> ProviderConfig:
    """Return the default Ollama :class:`ProviderConfig`.

    When ``model`` is empty, all 13 agent slots are populated with the
    default agent config (which itself has an empty model — the
    caller's :attr:`OllamaProvider._default_model`-derived default
    applies). When ``model`` is supplied, all 13 slots use that model.

    Mirrors PentAGI's ollama.go ``DefaultProviderConfig`` which loads
    from the embedded ``config.yml`` (or ``cfg.OllamaServerConfig`` if
    set).
    """
    cfg = ProviderConfig()
    agent = _default_agent(model)
    cfg.simple = agent.model_copy(deep=True)
    cfg.simple_json = agent.model_copy(deep=True)
    cfg.simple_json.json_mode = True
    cfg.primary_agent = agent.model_copy(deep=True)
    cfg.assistant = agent.model_copy(deep=True)
    cfg.generator = agent.model_copy(deep=True)
    cfg.refiner = agent.model_copy(deep=True)
    cfg.adviser = agent.model_copy(deep=True)
    cfg.reflector = agent.model_copy(deep=True)
    cfg.searcher = agent.model_copy(deep=True)
    cfg.enricher = agent.model_copy(deep=True)
    cfg.coder = agent.model_copy(deep=True)
    cfg.installer = agent.model_copy(deep=True)
    cfg.pentester = agent.model_copy(deep=True)
    return cfg


# ---------------------------------------------------------------------------
# OllamaProvider
# ---------------------------------------------------------------------------


class _OllamaTooManyRequests(Exception):
    """Internal sentinel raised to trigger tenacity 429 retry."""


def _is_too_many_requests(exc: BaseException) -> bool:
    """Return ``True`` if ``exc`` represents an HTTP 429 / throttling
    error. Ollama doesn't typically rate-limit (local inference), but
    Ollama Cloud deployments may."""
    err_str = str(exc).lower()
    if "429" in err_str:
        return True
    if "rate limit" in err_str or "too many requests" in err_str:
        return True
    return False


class OllamaProvider:
    """Ollama local LLM adapter (Python port of ``ollamaProvider``).

    Construction is lazy — the ``ollama`` Python SDK is imported inside
    :meth:`_get_client` (with an HTTP fallback for environments without
    the SDK). The server URL defaults to
    :data:`OLLAMA_DEFAULT_SERVER_URL` and is overridable via
    ``OLLAMA_SERVER_URL`` (or ``OLLAMA_HOST`` for native Ollama
    compatibility).

    Ollama auto-generates tool-call IDs — there's no
    ``generate_tool_call_id`` function exposed at module scope.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        default_model: Optional[str] = None,
        provider_config: Optional[ProviderConfig] = None,
        models: Optional[List[ModelConfig]] = None,
        provider_name: str = "ollama",
        request_timeout: float = 120.0,
        pull_models_enabled: bool = False,
        load_models_enabled: bool = False,
        pull_models_timeout: float = OLLAMA_DEFAULT_PULL_TIMEOUT,
    ) -> None:
        # Resolve env vars
        self._api_key = api_key or (
            os.environ.get("OLLAMA_SERVER_API_KEY")
            or os.environ.get("OLLAMA_API_KEY")
            or ""
        )
        self._base_url = base_url or (
            os.environ.get("OLLAMA_SERVER_URL")
            or os.environ.get("OLLAMA_HOST")
            or OLLAMA_DEFAULT_SERVER_URL
        )
        # Validate URL early
        parsed = urllib_parse.urlparse(self._base_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                f"Invalid Ollama server URL: {self._base_url!r}"
            )

        self._default_model = default_model or (
            os.environ.get("OLLAMA_SERVER_MODEL")
            or os.environ.get("OLLAMA_MODEL")
            or OLLAMA_DEFAULT_MODEL
        )
        self._provider_name = provider_name
        self._provider_config: ProviderConfig = (
            provider_config if provider_config is not None
            else get_default_config(self._default_model)
        )
        self._models: List[ModelConfig] = (
            models if models is not None
            else [ModelConfig(name=self._default_model)]
        )
        self._request_timeout = request_timeout
        self._pull_models_enabled = (
            pull_models_enabled
            or os.environ.get("OLLAMA_SERVER_PULL_MODELS_ENABLED", "").lower()
            in ("1", "true", "yes")
        )
        self._load_models_enabled = (
            load_models_enabled
            or os.environ.get("OLLAMA_SERVER_LOAD_MODELS_ENABLED", "").lower()
            in ("1", "true", "yes")
        )
        self._pull_models_timeout = pull_models_timeout
        self._client: Any = None  # ollama.Client — lazy

    # ------------------------------------------------------------------
    # Lazy SDK client
    # ------------------------------------------------------------------

    def _get_client(self) -> Any:
        """Lazily instantiate the ``ollama.Client`` client. If the
        ``ollama`` package is not installed, falls back to direct HTTP
        via ``urllib``."""
        if self._client is not None:
            return self._client
        try:
            from ollama import Client  # type: ignore[import-not-found]
            kwargs: dict = {"host": self._base_url}
            if self._api_key:
                # ollama SDK accepts headers via the 'headers' kwarg
                kwargs["headers"] = {"Authorization": f"Bearer {self._api_key}"}
            self._client = Client(**kwargs)
        except ImportError:
            logger.warning(
                "OllamaProvider: 'ollama' package not installed; falling "
                "back to direct HTTP. Install via "
                "`pip install ollama>=0.1.0` for full SDK support."
            )
            self._client = _OllamaHTTPClient(
                self._base_url, self._api_key, self._request_timeout,
            )
        return self._client

    # ------------------------------------------------------------------
    # Provider Protocol implementation
    # ------------------------------------------------------------------

    def type(self) -> ProviderType:
        return ProviderType.OLLAMA

    def name(self) -> str:
        return self._provider_name

    def model(self, opt: ProviderOptionsType) -> str:
        """Return the model name configured for ``opt`` (or the default
        model if the slot is unconfigured)."""
        agent = self._provider_config.get_agent_config(opt)
        if agent is not None and agent.model:
            return agent.model
        return self._default_model

    def model_with_prefix(self, opt: ProviderOptionsType) -> str:
        """Ollama provider doesn't need prefix support (passthrough mode
        in LiteLLM). Returns the bare model name."""
        return self.model(opt)

    def get_provider_config(self) -> ProviderConfig:
        return self._provider_config

    def get_models(self) -> ModelsConfig:
        return ModelsConfig(models=list(self._models))

    def get_price_info(self, opt: ProviderOptionsType) -> Optional[PriceInfo]:
        """Ollama is free local inference — always returns ``None``."""
        return None

    def get_tool_call_id_template(self) -> str:
        """Ollama auto-generates tool-call IDs; no template."""
        return ""

    # ------------------------------------------------------------------
    # Ollama-specific startup helpers
    # ------------------------------------------------------------------

    def ensure_models_available(self) -> None:
        """Pull any configured models that are not already present
        locally. Called by the caller on startup when
        :attr:`pull_models_enabled` is True.

        Mirrors PentAGI's ``ensureModelsAvailable`` — uses a 10-minute
        default timeout per pull operation.
        """
        if not self._pull_models_enabled:
            return
        client = self._get_client()
        models_to_pull = self._get_config_models_list()
        for model_name in models_to_pull:
            try:
                exists = self._model_exists_locally(client, model_name)
                if exists:
                    continue
                logger.info("OllamaProvider: pulling model %r", model_name)
                self._pull_model(client, model_name)
            except Exception as exc:
                logger.error(
                    "OllamaProvider: failed to pull model %r: %s",
                    model_name, exc,
                )

    def _get_config_models_list(self) -> List[str]:
        """De-duplicated sorted list of model names referenced by any
        agent slot, plus the default model."""
        names: List[str] = []
        seen: set = set()
        if self._default_model and self._default_model not in seen:
            names.append(self._default_model)
            seen.add(self._default_model)
        # Walk all 13 agent slots
        for attr in (
            "simple", "simple_json", "primary_agent", "assistant",
            "generator", "refiner", "adviser", "reflector", "searcher",
            "enricher", "coder", "installer", "pentester",
        ):
            agent = getattr(self._provider_config, attr, None)
            if agent is not None and agent.model and agent.model not in seen:
                names.append(agent.model)
                seen.add(agent.model)
        return sorted(names)

    def _model_exists_locally(self, client: Any, model: str) -> bool:
        """Check if ``model`` is already pulled locally via ``client.show``."""
        try:
            show = getattr(client, "show", None)
            if show is None:
                return False
            show(model=model)
            return True
        except Exception:
            return False

    def _pull_model(self, client: Any, model: str) -> None:
        """Pull ``model`` from the Ollama registry. The ``ollama`` SDK's
        ``pull`` method is a sync iterator of progress dicts."""
        pull = getattr(client, "pull", None)
        if pull is None:
            return
        result = pull(model=model)
        if hasattr(result, "__iter__"):
            for _ in result:
                pass

    def load_available_models(self) -> ModelsConfig:
        """Query ``/api/list`` and populate :attr:`_models` with the
        available local models. Called by the caller on startup when
        :attr:`load_models_enabled` is True.
        """
        client = self._get_client()
        list_fn = getattr(client, "list", None)
        if list_fn is None:
            return self.get_models()
        try:
            response = list_fn()
            models_list = (
                getattr(response, "models", None)
                or (response.get("models") if isinstance(response, dict) else [])
                or []
            )
            out: List[ModelConfig] = []
            for m in models_list:
                name = (
                    getattr(m, "name", None)
                    or getattr(m, "model", None)
                    or (m.get("name") if isinstance(m, dict) else None)
                    or (m.get("model") if isinstance(m, dict) else None)
                    or ""
                )
                if name:
                    out.append(ModelConfig(name=name))
            self._models = out
            return self.get_models()
        except Exception as exc:
            logger.warning("OllamaProvider: failed to list models: %s", exc)
            return self.get_models()

    # ------------------------------------------------------------------
    # Request building
    # ------------------------------------------------------------------

    def _convert_chain(
        self, chain: List[MessageContent]
    ) -> List[dict]:
        """Convert a list of :class:`MessageContent` to Ollama's chat
        message format (``{role, content, tool_calls, images}``)."""
        out: List[dict] = []
        for msg in chain:
            entry: dict = {"role": msg.role}
            text_parts: List[str] = []
            tool_calls: List[dict] = []
            for part in msg.parts:
                if isinstance(part, TextPart) and part.text:
                    text_parts.append(part.text)
                elif isinstance(part, ToolCall):
                    tool_calls.append({
                        "id": part.id,
                        "type": "function",
                        "function": {
                            "name": part.name,
                            "arguments": _safe_json_loads(part.arguments),
                        },
                    })
                elif isinstance(part, ToolCallResponse):
                    entry["tool_call_id"] = part.tool_call_id
                    if part.content:
                        entry["content"] = part.content
            if tool_calls:
                entry["tool_calls"] = tool_calls
            if text_parts and "content" not in entry:
                entry["content"] = "\n".join(text_parts)
            out.append(entry)
        return out

    @staticmethod
    def _convert_tools(tools: List[dict]) -> List[dict]:
        """Convert OpenAI-shape tools to Ollama's tools format
        (OpenAI-compatible function definitions)."""
        out: List[dict] = []
        for t in tools:
            fn = t.get("function", t)
            schema = dict(
                fn.get("parameters") or {"type": "object", "properties": {}}
            )
            out.append({
                "type": "function",
                "function": {
                    "name": fn.get("name", ""),
                    "description": fn.get("description", ""),
                    "parameters": schema,
                },
            })
        return out

    def _build_request(
        self,
        model: str,
        agent: Optional[AgentConfig],
        chain: List[MessageContent],
        tools: Optional[List[dict]],
        stream: bool = False,
    ) -> dict:
        """Build the kwargs dict for ``client.chat()``."""
        messages = self._convert_chain(chain)
        kwargs: dict = {
            "model": model,
            "messages": messages,
        }
        options: dict = {}
        if agent is not None:
            if agent.temperature is not None:
                options["temperature"] = agent.temperature
            if agent.top_p is not None:
                options["top_p"] = agent.top_p
            if agent.max_tokens is not None:
                options["num_predict"] = agent.max_tokens
            elif not agent.max_tokens:
                options["num_predict"] = OLLAMA_DEFAULT_MAX_TOKENS
        if options:
            kwargs["options"] = options
        if agent is not None and agent.json_mode:
            kwargs["format"] = "json"
        if tools:
            kwargs["tools"] = self._convert_tools(tools)
        if stream:
            kwargs["stream"] = True
        return kwargs

    # ------------------------------------------------------------------
    # Call entrypoints
    # ------------------------------------------------------------------

    def call(
        self,
        opt: ProviderOptionsType,
        prompt: str,
    ) -> str:
        """Single-prompt convenience wrapper."""
        chain = [MessageContent(role="user", parts=[TextPart(text=prompt)])]
        resp = self.call_ex(opt, chain, stream_cb=None)
        if not resp.choices:
            raise RuntimeError("empty response from Ollama")
        return resp.choices[0].content

    def call_ex(
        self,
        opt: ProviderOptionsType,
        chain: List[MessageContent],
        stream_cb: Optional[StreamingCallback] = None,
    ) -> ContentResponse:
        """Multi-turn call without new tools."""
        return self._invoke(opt, chain, tools=None, stream_cb=stream_cb)

    def call_with_tools(
        self,
        opt: ProviderOptionsType,
        chain: List[MessageContent],
        tools: List[dict],
        stream_cb: Optional[StreamingCallback] = None,
    ) -> ContentResponse:
        """Multi-turn call with explicit tools."""
        return self._invoke(opt, chain, tools=tools, stream_cb=stream_cb)

    def _invoke(
        self,
        opt: ProviderOptionsType,
        chain: List[MessageContent],
        tools: Optional[List[dict]],
        stream_cb: Optional[StreamingCallback],
    ) -> ContentResponse:
        """Build the request, fire it with 429 retry, parse the response."""
        agent = self._provider_config.get_agent_config(opt)
        model = self.model(opt)
        request = self._build_request(
            model, agent, chain, tools, stream=(stream_cb is not None)
        )
        client = self._get_client()
        if stream_cb is not None:
            return self._invoke_streaming(client, request, stream_cb, opt)
        return self._invoke_sync(client, request, opt)

    def _invoke_sync(
        self, client: Any, request: dict, opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Call ``client.chat()`` with 429 retry."""
        try:
            from tenacity import (
                Retrying, retry_if_exception_type,
                stop_after_attempt, wait_fixed, wait_incrementing,
            )
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "tenacity is required for 429 retry; install with "
                "`pip install tenacity`"
            ) from exc

        retrying = Retrying(
            stop=stop_after_attempt(OLLAMA_MAX_429_RETRIES),
            wait=wait_fixed(OLLAMA_429_BASE_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_OllamaTooManyRequests),
            reraise=True,
        )
        response: Any = None
        for attempt in retrying:
            with attempt:
                try:
                    response = client.chat(**request)
                except Exception as exc:
                    if _is_too_many_requests(exc):
                        logger.warning(
                            "ollama 429 on slot %s, retrying (attempt %d/%d)",
                            opt.value,
                            attempt.retry_state.attempt_number,
                            OLLAMA_MAX_429_RETRIES,
                        )
                        raise _OllamaTooManyRequests(str(exc)) from exc
                    raise
        return self._parse_response(response, opt)

    def _invoke_streaming(
        self, client: Any, request: dict,
        stream_cb: StreamingCallback, opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Call ``client.chat()`` (stream=True) with 429 retry."""
        try:
            from tenacity import (
                Retrying, retry_if_exception_type,
                stop_after_attempt, wait_fixed, wait_incrementing,
            )
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "tenacity is required for 429 retry; install with "
                "`pip install tenacity`"
            ) from exc

        retrying = Retrying(
            stop=stop_after_attempt(OLLAMA_MAX_429_RETRIES),
            wait=wait_fixed(OLLAMA_429_BASE_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_OllamaTooManyRequests),
            reraise=True,
        )
        stream: Any = None
        for attempt in retrying:
            with attempt:
                try:
                    stream = client.chat(**{**request, "stream": True})
                except Exception as exc:
                    if _is_too_many_requests(exc):
                        logger.warning(
                            "ollama 429 (stream) on slot %s, retrying "
                            "(attempt %d/%d)",
                            opt.value,
                            attempt.retry_state.attempt_number,
                            OLLAMA_MAX_429_RETRIES,
                        )
                        raise _OllamaTooManyRequests(str(exc)) from exc
                    raise
        return self._parse_stream_response(stream, opt, stream_cb)

    def _parse_response(
        self, response: Any, opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Parse an ``ollama`` SDK ``ChatResponse`` into our
        :class:`ContentResponse`."""
        # Normalize to dict
        if hasattr(response, "model_dump"):
            raw = response.model_dump()
        elif hasattr(response, "to_dict"):
            raw = response.to_dict()
        elif isinstance(response, dict):
            raw = dict(response)
        else:
            raw = {k: v for k, v in vars(response).items() if not k.startswith("_")} if hasattr(response, "__dict__") else {}

        msg = raw.get("message") or {}
        role = msg.get("role") or "assistant"
        content = msg.get("content") or ""
        tool_calls_raw = msg.get("tool_calls") or []
        tcs: List[ToolCall] = []
        for tc in tool_calls_raw:
            tc_dict = tc if isinstance(tc, dict) else {}
            fn = tc_dict.get("function") if isinstance(tc_dict.get("function"), dict) else {}
            args = fn.get("arguments", {})
            if not isinstance(args, str):
                args = json.dumps(args) if args else "{}"
            tcs.append(ToolCall(
                id=tc_dict.get("id", "") or "",
                name=fn.get("name", ""),
                arguments=args,
                type="tool_call",
            ))

        finish_reason = (
            raw.get("done_reason") or raw.get("finish_reason") or ""
        )

        choice = Choice(
            content=content,
            tool_calls=tcs,
            stop_reason=finish_reason,
            generation_info={},
        )

        # Usage
        usage = CallUsage(
            input_tokens=int(raw.get("prompt_eval_count") or 0),
            output_tokens=int(raw.get("eval_count") or 0),
        )
        # Ollama is free — no cost update.

        return ContentResponse(choices=[choice], usage=usage)

    def _parse_stream_response(
        self, stream: Any, opt: ProviderOptionsType,
        stream_cb: StreamingCallback,
    ) -> ContentResponse:
        """Translate an Ollama streaming response."""
        text_parts: List[str] = []
        tcs: List[ToolCall] = []
        finish_reason = ""
        prompt_eval_count = 0
        eval_count = 0

        for chunk in stream or []:
            chunk_dict = (
                chunk.model_dump() if hasattr(chunk, "model_dump")
                else (chunk if isinstance(chunk, dict) else vars(chunk))
            )
            msg = chunk_dict.get("message") or {}
            delta = msg.get("content") or ""
            if delta:
                text_parts.append(delta)
                stream_cb(delta)
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
                args = fn.get("arguments", {})
                if not isinstance(args, str):
                    import json as _json
                    args = _json.dumps(args) if args else "{}"
                tcs.append(ToolCall(
                    id=tc.get("id", "") or "",
                    name=fn.get("name", ""),
                    arguments=args,
                    type="tool_call",
                ))
            if chunk_dict.get("done"):
                finish_reason = chunk_dict.get("done_reason", "") or "stop"
            if "prompt_eval_count" in chunk_dict:
                prompt_eval_count = int(chunk_dict["prompt_eval_count"] or 0)
            if "eval_count" in chunk_dict:
                eval_count = int(chunk_dict["eval_count"] or 0)

        choice = Choice(
            content="".join(text_parts),
            tool_calls=tcs,
            stop_reason=finish_reason,
            generation_info={"streamed": True},
        )
        usage = CallUsage(
            input_tokens=prompt_eval_count,
            output_tokens=eval_count,
        )
        return ContentResponse(choices=[choice], usage=usage)


# ---------------------------------------------------------------------------
# _OllamaHTTPClient — fallback HTTP client used when the 'ollama' Python
# package is not installed. Implements the same surface as
# ``ollama.Client`` (just ``chat`` / ``list`` / ``show`` / ``pull``) via
# direct ``urllib`` requests to ``<server_url>/api/<endpoint>``.
# ---------------------------------------------------------------------------


import json  # noqa: E402  -- top-level would shadow json module used in _safe


class _OllamaHTTPClient:
    """Minimal sync HTTP wrapper for the Ollama REST API. Used as a
    fallback when the ``ollama`` Python package is not installed."""

    def __init__(
        self,
        server_url: str,
        api_key: str = "",
        timeout: float = 120.0,
    ) -> None:
        self._server_url = server_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def _headers(self) -> dict:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    def chat(self, **kwargs: Any) -> dict:
        """POST /api/chat with the Ollama chat payload."""
        body = json.dumps(kwargs).encode("utf-8")
        from urllib import request as urllib_request
        req = urllib_request.Request(
            f"{self._server_url}/api/chat",
            data=body,
            headers=self._headers(),
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))

    def list(self) -> dict:
        """GET /api/list — return available local models."""
        from urllib import request as urllib_request
        req = urllib_request.Request(
            f"{self._server_url}/api/list",
            headers=self._headers(),
            method="GET",
        )
        with urllib_request.urlopen(req, timeout=10.0) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))

    def show(self, model: str) -> dict:
        """POST /api/show — return model metadata."""
        body = json.dumps({"model": model}).encode("utf-8")
        from urllib import request as urllib_request
        req = urllib_request.Request(
            f"{self._server_url}/api/show",
            data=body,
            headers=self._headers(),
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=10.0) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))

    def pull(self, model: str) -> Any:
        """POST /api/pull — return a sync iterator of progress dicts."""
        body = json.dumps({"model": model, "stream": True}).encode("utf-8")
        from urllib import request as urllib_request
        req = urllib_request.Request(
            f"{self._server_url}/api/pull",
            data=body,
            headers=self._headers(),
            method="POST",
        )
        resp = urllib_request.urlopen(req, timeout=600.0)  # noqa: S310
        # Return an iterator that reads lines from the response
        def _iter():
            for line in resp:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        continue
        return _iter()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_json_loads(s: str) -> dict:
    """Parse a JSON-encoded argument string. Returns {} on any error."""
    if not s:
        return {}
    try:
        parsed = json.loads(s)
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, TypeError):
        return {}


__all__ = [
    "OLLAMA_DEFAULT_SERVER_URL",
    "OLLAMA_DEFAULT_MODEL",
    "OLLAMA_DEFAULT_PULL_TIMEOUT",
    "OLLAMA_DEFAULT_API_CALL_TIMEOUT",
    "OLLAMA_DEFAULT_MAX_TOKENS",
    "OLLAMA_MAX_429_RETRIES",
    "OLLAMA_429_BASE_DELAY",
    "OllamaProvider",
    "get_default_config",
]

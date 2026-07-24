"""elengenix.providers._openai_compat — Shared base for OpenAI-compatible
LLM provider adapters (GLM, Kimi, Qwen, Custom/vLLM, OpenAI).

All five OpenAI-compatible providers in this package share the same
client-construction, request-building, response-parsing, and
reasoning-content-preservation logic — only their default model,
default base URL, tool-call ID template, env-var names, and per-agent
``extra_body`` semantics differ. This module factors that shared logic
into the :class:`OpenAICompatProvider` base class, so each concrete
provider module is ~150 lines of config + provider-specific helpers
instead of ~600 lines of duplicated plumbing.

Key design decisions:

* **Sync Provider Protocol** — matches
  :class:`elengenix.providers.base.Provider` (sync ``call`` /
  ``call_ex`` / ``call_with_tools``). The ``openai.OpenAI`` client (not
  ``AsyncOpenAI``) is used. Callers that need async can wrap with
  ``asyncio.to_thread``.
* **Lazy ``openai`` import** — the ``openai`` SDK is imported inside
  :meth:`_get_client`, not at module load, so that environments without
  ``openai`` installed can still import this module (and the concrete
  provider modules) for their types and helpers.
* **429 retry via tenacity** — matches PentAGI's
  ``provider.WrapGenerateContent`` retry policy: 10 attempts, 5 s base
  + 1 s linear increment per attempt.
* **Preserved Reasoning Content** — Z.AI GLM, Moonshot Kimi, Alibaba
  DashScope (Qwen3.x), and DeepSeek-R1 all return a
  ``reasoning_content`` field on assistant messages. Multi-turn
  tool-call flows require this field to be re-serialized into the
  assistant message on the next turn (otherwise the upstream API
  rejects the request or silently drops the thinking history). The
  langchaingo Go port achieves this via
  ``WithPreserveReasoningContent()``; in Python we re-attach the
  ``reasoning_content`` automatically inside :meth:`_build_request`
  when ``preserve_reasoning=True``.
* **Provider-prefix passthrough** — when ``provider_prefix`` is set
  (LiteLLM-style), :meth:`model_with_prefix` prepends ``prefix/`` to
  the model name so the LiteLLM proxy can route the request correctly.
* **Tool-call ID generation** — each concrete provider declares its
  own ``TOOL_CALL_ID_TEMPLATE`` constant; the base class's
  :func:`make_generate_tool_call_id` factory produces a
  ``generate_tool_call_id()`` function that renders the template via
  the shared :func:`elengenix.providers.base.apply_model_prefix`
  helpers (re-using the random-char primitives).
"""

from __future__ import annotations

import logging
import secrets
import string
from typing import Any, Callable, List, Optional

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
    Provider,
    ProviderConfig,
    ProviderOptionsType,
    ProviderType,
    StreamingCallback,
    TextPart,
    ToolCall,
    ToolCallResponse,
    apply_model_prefix,
)

logger = logging.getLogger("elengenix.providers._openai_compat")

__all__ = [
    "OpenAICompatProvider",
    "make_generate_tool_call_id",
    "DEFAULT_429_MAX_RETRIES",
    "DEFAULT_429_BASE_DELAY",
]


# 429 retry policy — mirrors PentAGI's MaxTooManyRequestsRetries /
# TooManyRequestsRetryDelay constants.
DEFAULT_429_MAX_RETRIES: int = 10
DEFAULT_429_BASE_DELAY: float = 5.0

_HEX_ALPHABET: str = "0123456789abcdef"
_DIGIT_ALPHABET: str = "0123456789"
_BASE62_ALPHABET: str = string.digits + string.ascii_lowercase + string.ascii_uppercase


# ---------------------------------------------------------------------------
# Tool-call ID template engine
# ---------------------------------------------------------------------------


def _validate_template(template: str) -> bool:
    """Return ``True`` if ``template`` is a syntactically-valid tool-call
    ID template. A valid template contains zero or more ``{...}``
    directives, each of which is either ``{f}`` or ``{r:N:<kind>}`` where
    ``N`` is a positive integer and ``<kind>`` is one of ``d`` / ``h`` /
    ``x`` / ``b``."""
    if not isinstance(template, str) or not template:
        return False
    i = 0
    while i < len(template):
        ch = template[i]
        if ch == "{":
            end = template.find("}", i + 1)
            if end < 0:
                return False
            inner = template[i + 1:end]
            if inner == "f":
                i = end + 1
                continue
            if not inner.startswith("r:"):
                return False
            parts = inner.split(":")
            if len(parts) != 3:
                return False
            _, n_str, kind = parts
            if not n_str.isdigit() or int(n_str) <= 0:
                return False
            if kind not in {"d", "h", "x", "b"}:
                return False
            i = end + 1
            continue
        i += 1
    return True


def _render_template(template: str, function_name: Optional[str] = None) -> str:
    """Render a single tool-call ID from ``template``.

    ``function_name`` is substituted for every ``{f}`` directive. Random
    parts are filled using ``secrets.choice`` (CSPRNG) so IDs are
    unpredictable — matching PentAGI's use of ``crypto/rand``.

    Raises ``ValueError`` if the template is syntactically invalid.
    """
    if not _validate_template(template):
        raise ValueError(f"invalid tool-call ID template: {template!r}")

    out: List[str] = []
    i = 0
    n = len(template)
    while i < n:
        ch = template[i]
        if ch == "{":
            end = template.find("}", i + 1)
            inner = template[i + 1:end]
            if inner == "f":
                out.append(function_name or "")
            else:
                _, n_str, kind = inner.split(":")
                count = int(n_str)
                if kind == "d":
                    out.append("".join(
                        secrets.choice(_DIGIT_ALPHABET) for _ in range(count)
                    ))
                elif kind in ("h", "x"):
                    out.append("".join(
                        secrets.choice(_HEX_ALPHABET) for _ in range(count)
                    ))
                elif kind == "b":
                    out.append("".join(
                        secrets.choice(_BASE62_ALPHABET) for _ in range(count)
                    ))
            i = end + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def make_generate_tool_call_id(template: str) -> Callable[[], str]:
    """Return a ``generate_tool_call_id()`` function bound to ``template``.

    The returned function takes no arguments and returns a freshly-
    rendered tool-call ID. Used by each concrete provider module to
    expose a ``generate_tool_call_id`` function matching the
    ``deepseek.generate_tool_call_id`` shape expected by the registry.
    """
    if not _validate_template(template):
        raise ValueError(f"invalid tool-call ID template: {template!r}")

    def _generate() -> str:
        return _render_template(template)

    _generate.__doc__ = (
        f"Generate a random tool-call ID matching the template "
        f"{template!r}. Uses ``secrets.choice`` (CSPRNG)."
    )
    return _generate


# ---------------------------------------------------------------------------
# OpenAICompatProvider — shared base class
# ---------------------------------------------------------------------------


class _TooManyRequests(Exception):
    """Internal sentinel raised to trigger tenacity 429 retry."""


def _is_too_many_requests(exc: BaseException) -> bool:
    """Return ``True`` if ``exc`` represents an HTTP 429 / throttling
    error. The ``openai`` Python SDK raises ``openai.RateLimitError`` on
    429s; we also check the message text as a fallback (some proxies
    return bare 429 strings)."""
    if exc.__class__.__name__ == "RateLimitError":
        return True
    err_str = str(exc).lower()
    if "status code: 429" in err_str or "statuscode: 429" in err_str:
        return True
    if "rate limit" in err_str or "too many requests" in err_str:
        return True
    return False


class OpenAICompatProvider:
    """Shared base class for all OpenAI-compatible providers.

    Concrete subclasses (``GLMProvider``, ``KimiProvider``,
    ``QwenProvider``, ``CustomProvider``, ``OpenAIProvider``) set the
    following class attributes and override the indicated methods:

    * ``PROVIDER_TYPE`` — the :class:`ProviderType` enum value.
    * ``TOOL_CALL_ID_TEMPLATE`` — the format string for
      :func:`make_generate_tool_call_id`.
    * ``DEFAULT_MODEL`` — the fallback model name.
    * ``DEFAULT_BASE_URL`` — the fallback base URL.
    * ``ENV_VAR_API_KEY`` — env var name for the API key.
    * ``ENV_VAR_BASE_URL`` — env var name for the base URL override.
    * ``ENV_VAR_PROVIDER_PREFIX`` — env var name for the LiteLLM prefix.
    * :meth:`get_default_config` (classmethod) — returns the per-provider
      default :class:`ProviderConfig` (ported from ``config.yml``).
    * :meth:`get_default_models` (classmethod) — returns the per-provider
      default ``list[ModelConfig]`` (ported from ``models.yml``).
    """

    # Class-level constants — overridden by subclasses.
    PROVIDER_TYPE: ProviderType = ProviderType.CUSTOM
    TOOL_CALL_ID_TEMPLATE: str = ""
    DEFAULT_MODEL: str = ""
    DEFAULT_BASE_URL: str = ""
    ENV_VAR_API_KEY: str = ""
    ENV_VAR_BASE_URL: str = ""
    ENV_VAR_PROVIDER_PREFIX: str = ""

    # 429 retry policy — overridable per provider.
    MAX_429_RETRIES: int = DEFAULT_429_MAX_RETRIES
    BASE_429_DELAY: float = DEFAULT_429_BASE_DELAY

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        provider_prefix: str = "",
        provider_config: Optional[ProviderConfig] = None,
        models: Optional[List[ModelConfig]] = None,
        provider_name: str = "",
        preserve_reasoning: bool = True,
        legacy_reasoning: bool = False,
        request_timeout: float = 120.0,
    ) -> None:
        # Resolve env-var-driven config (matches PentAGI's New() pattern).
        self._api_key = api_key if api_key is not None else (
            __import__("os").environ.get(self.ENV_VAR_API_KEY, "")
            if self.ENV_VAR_API_KEY else ""
        )
        # Some providers (Custom / vLLM) tolerate an empty api_key.
        if not self._api_key and self.PROVIDER_TYPE != ProviderType.CUSTOM:
            raise RuntimeError(
                f"missing {self.ENV_VAR_API_KEY} environment variable "
                f"(set it or pass api_key=... to "
                f"{self.__class__.__name__})"
            )

        self._base_url = base_url or (
            __import__("os").environ.get(self.ENV_VAR_BASE_URL, "")
            if self.ENV_VAR_BASE_URL else ""
        ) or self.DEFAULT_BASE_URL

        self._provider_prefix = provider_prefix or (
            __import__("os").environ.get(self.ENV_VAR_PROVIDER_PREFIX, "")
            if self.ENV_VAR_PROVIDER_PREFIX else ""
        )

        self._provider_name = provider_name or self.PROVIDER_TYPE.value
        self._provider_config: ProviderConfig = (
            provider_config
            if provider_config is not None
            else (self.get_default_config() if hasattr(self, "get_default_config") else ProviderConfig())
        )
        self._models: List[ModelConfig] = (
            models if models is not None
            else (self.get_default_models() if hasattr(self, "get_default_models") else [])
        )

        self._preserve_reasoning = preserve_reasoning
        self._legacy_reasoning = legacy_reasoning
        self._request_timeout = request_timeout
        self._client: Any = None  # openai.OpenAI — lazy

    # ------------------------------------------------------------------
    # Classmethods — overridden by subclasses
    # ------------------------------------------------------------------

    @classmethod
    def get_default_config(cls) -> ProviderConfig:
        """Return the default :class:`ProviderConfig` for this provider.
        Subclasses override this to return a config ported from the
        provider's ``config.yml``. The base implementation returns an
        empty :class:`ProviderConfig`."""
        return ProviderConfig()

    @classmethod
    def get_default_models(cls) -> List[ModelConfig]:
        """Return the default ``list[ModelConfig]`` for this provider.
        Subclasses override this to return a list ported from the
        provider's ``models.yml``. The base implementation returns an
        empty list."""
        return []

    # ------------------------------------------------------------------
    # Lazy SDK client
    # ------------------------------------------------------------------

    def _get_client(self) -> Any:
        """Lazily construct (and cache) the ``openai.OpenAI`` client."""
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover — depends on env
            raise RuntimeError(
                f"openai is required for the {self.PROVIDER_TYPE.value} "
                "provider; install with `pip install openai>=1.0.0`"
            ) from exc
        self._client = OpenAI(
            api_key=self._api_key,
            base_url=self._base_url,
            timeout=self._request_timeout,
        )
        return self._client

    # ------------------------------------------------------------------
    # Provider Protocol implementation
    # ------------------------------------------------------------------

    def type(self) -> ProviderType:
        return self.PROVIDER_TYPE

    def name(self) -> str:
        return self._provider_name

    def model(self, opt: ProviderOptionsType) -> str:
        """Return the model name configured for ``opt`` (or the default
        model if the slot is unconfigured)."""
        agent = self._provider_config.get_agent_config(opt)
        if agent is not None and agent.model:
            return agent.model
        return self.DEFAULT_MODEL

    def model_with_prefix(self, opt: ProviderOptionsType) -> str:
        """Return the model name with the LiteLLM prefix prepended."""
        return apply_model_prefix(self.model(opt), self._provider_prefix)

    def get_provider_config(self) -> ProviderConfig:
        return self._provider_config

    def get_models(self) -> ModelsConfig:
        return ModelsConfig(models=list(self._models))

    def get_price_info(self, opt: ProviderOptionsType) -> Optional[PriceInfo]:
        return self._provider_config.get_price_info(opt)

    def get_tool_call_id_template(self) -> str:
        return self.TOOL_CALL_ID_TEMPLATE

    def generate_tool_call_id(self) -> str:
        """Generate a random tool-call ID matching this provider's
        template. Raises ``NotImplementedError`` if the provider does
        not declare a ``TOOL_CALL_ID_TEMPLATE``."""
        if not self.TOOL_CALL_ID_TEMPLATE:
            raise NotImplementedError(
                f"{self.PROVIDER_TYPE.value} does not declare a "
                "TOOL_CALL_ID_TEMPLATE"
            )
        return _render_template(self.TOOL_CALL_ID_TEMPLATE)

    # ------------------------------------------------------------------
    # Preserved Reasoning Content helper
    # ------------------------------------------------------------------

    def preserve_reasoning_content(
        self,
        tool_call: ToolCall,
        reasoning_content: str,
    ) -> ToolCall:
        """Attach ``reasoning_content`` to a :class:`ToolCall` so that
        the next request re-serializes it on the assistant message.

        This is the Python equivalent of langchaingo's
        ``WithPreserveReasoningContent()``. Z.AI GLM, Moonshot Kimi,
        Alibaba Qwen3.x, and DeepSeek-R1 all return a
        ``reasoning_content`` field on assistant messages — multi-turn
        tool-call flows require it to be re-serialized into the
        assistant message on the next turn, otherwise the upstream API
        rejects the request or silently drops the thinking history.

        The :class:`ToolCall` model uses ``model_extra`` to carry
        provider-specific fields like ``reasoning_content`` — this
        helper sets it on a copy of the tool_call so the caller's
        original object is not mutated.
        """
        if not reasoning_content:
            return tool_call
        # Pydantic v2 model_extra is mutable via model_extra setattr.
        new_tc = tool_call.model_copy(deep=True)
        if new_tc.model_extra is None:
            # Force-create the model_extra dict by setting a key.
            new_tc.model_extra = {}
        new_tc.model_extra["reasoning_content"] = reasoning_content
        return new_tc

    # ------------------------------------------------------------------
    # Call entrypoints
    # ------------------------------------------------------------------

    def call(
        self,
        opt: ProviderOptionsType,
        prompt: str,
    ) -> str:
        """Single-prompt convenience wrapper — builds a 1-message chain
        and delegates to :meth:`call_ex`."""
        chain = [MessageContent(role="user", parts=[TextPart(text=prompt)])]
        resp = self.call_ex(opt, chain, stream_cb=None)
        if not resp.choices:
            raise RuntimeError(
                f"empty response from {self.PROVIDER_TYPE.value}"
            )
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

    # ------------------------------------------------------------------
    # Internal: request building + 429 retry
    # ------------------------------------------------------------------

    def _invoke(
        self,
        opt: ProviderOptionsType,
        chain: List[MessageContent],
        tools: Optional[List[dict]],
        stream_cb: Optional[StreamingCallback],
    ) -> ContentResponse:
        """Build the request, fire it with 429 retry, parse the
        response."""
        agent = self._provider_config.get_agent_config(opt)
        model = self.model_with_prefix(opt)
        request = self._build_request(model, agent, chain, tools)
        client = self._get_client()
        if stream_cb is not None:
            return self._invoke_streaming(client, request, stream_cb, opt)
        return self._invoke_sync(client, request, opt)

    def _invoke_sync(
        self,
        client: Any,
        request: dict,
        opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Call ``chat.completions.create`` with 429 retry."""
        try:
            from tenacity import (
                Retrying,
                retry_if_exception_type,
                stop_after_attempt,
                wait_fixed,
                wait_incrementing,
            )
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "tenacity is required for 429 retry; install with "
                "`pip install tenacity`"
            ) from exc

        retrying = Retrying(
            stop=stop_after_attempt(self.MAX_429_RETRIES),
            wait=wait_fixed(self.BASE_429_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_TooManyRequests),
            reraise=True,
        )

        response: Any = None
        for attempt in retrying:
            with attempt:
                try:
                    response = client.chat.completions.create(**request)
                except Exception as exc:
                    if _is_too_many_requests(exc):
                        logger.warning(
                            "%s 429 on slot %s, retrying (attempt %d/%d)",
                            self.PROVIDER_TYPE.value,
                            opt.value,
                            attempt.retry_state.attempt_number,
                            self.MAX_429_RETRIES,
                        )
                        raise _TooManyRequests(str(exc)) from exc
                    raise
        return self._parse_response(response, opt)

    def _invoke_streaming(
        self,
        client: Any,
        request: dict,
        stream_cb: StreamingCallback,
        opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Call ``chat.completions.create`` (stream=True) with 429
        retry. Streams text deltas to ``stream_cb`` as they arrive."""
        try:
            from tenacity import (
                Retrying,
                retry_if_exception_type,
                stop_after_attempt,
                wait_fixed,
                wait_incrementing,
            )
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "tenacity is required for 429 retry; install with "
                "`pip install tenacity`"
            ) from exc

        retrying = Retrying(
            stop=stop_after_attempt(self.MAX_429_RETRIES),
            wait=wait_fixed(self.BASE_429_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_TooManyRequests),
            reraise=True,
        )

        stream: Any = None
        for attempt in retrying:
            with attempt:
                try:
                    stream = client.chat.completions.create(
                        **{**request, "stream": True}
                    )
                except Exception as exc:
                    if _is_too_many_requests(exc):
                        logger.warning(
                            "%s 429 (stream) on slot %s, retrying "
                            "(attempt %d/%d)",
                            self.PROVIDER_TYPE.value,
                            opt.value,
                            attempt.retry_state.attempt_number,
                            self.MAX_429_RETRIES,
                        )
                        raise _TooManyRequests(str(exc)) from exc
                    raise
        return self._parse_stream_response(stream, opt, stream_cb)

    def _build_request(
        self,
        model: str,
        agent: Optional[AgentConfig],
        chain: List[MessageContent],
        tools: Optional[List[dict]],
    ) -> dict:
        """Build an OpenAI-shape chat-completion request body.

        Translates the provider-agnostic :class:`MessageContent` chain
        into the OpenAI ``messages`` / ``tools`` shape. Preserves
        ``reasoning_content`` on assistant messages (required for
        Z.AI/Moonshot/Qwen preserved-thinking multi-turn flow).
        """
        messages: List[dict] = []
        for msg in chain:
            role = msg.role
            if role == "system":
                text = _collect_text(msg.parts)
                if text:
                    messages.append({"role": "system", "content": text})
                continue

            if role == "tool":
                for part in msg.parts:
                    if isinstance(part, ToolCallResponse):
                        messages.append({
                            "role": "tool",
                            "tool_call_id": part.tool_call_id,
                            "content": part.content,
                        })
                continue

            # user / assistant
            text_parts: List[str] = []
            tool_calls: List[dict] = []
            reasoning: Optional[str] = None
            for part in msg.parts:
                if isinstance(part, TextPart):
                    if part.text:
                        text_parts.append(part.text)
                elif isinstance(part, ToolCall):
                    tc: dict = {
                        "id": part.id or self.generate_tool_call_id(),
                        "type": "function",
                        "function": {
                            "name": part.name,
                            "arguments": part.arguments,
                        },
                    }
                    # Preserve reasoning_content from ToolCall.model_extra
                    if self._preserve_reasoning and part.model_extra:
                        rc = part.model_extra.get("reasoning_content")
                        if rc and not reasoning:
                            reasoning = rc
                    tool_calls.append(tc)
                elif isinstance(part, ToolCallResponse):
                    text_parts.append(part.content)

            message: dict = {"role": role}
            if role == "assistant":
                message["content"] = "".join(text_parts) if text_parts else None
                if tool_calls:
                    message["tool_calls"] = tool_calls
                if reasoning and self._preserve_reasoning:
                    message["reasoning_content"] = reasoning
            else:
                message["content"] = "".join(text_parts)
            messages.append(message)

        request: dict = {"model": model, "messages": messages}

        if agent is not None:
            if agent.temperature is not None:
                request["temperature"] = agent.temperature
            if agent.top_p is not None:
                request["top_p"] = agent.top_p
            if agent.n is not None:
                request["n"] = agent.n
            if agent.max_tokens is not None:
                request["max_tokens"] = agent.max_tokens
            if agent.frequency_penalty is not None:
                request["frequency_penalty"] = agent.frequency_penalty
            if agent.presence_penalty is not None:
                request["presence_penalty"] = agent.presence_penalty
            if agent.json_mode:
                request["response_format"] = {"type": "json_object"}
            if agent.extra_body:
                request["extra_body"] = dict(agent.extra_body)

        if tools:
            request["tools"] = tools

        return request

    def _parse_response(
        self,
        response: Any,
        opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Translate an OpenAI-shape chat completion response."""
        choices_out: List[Choice] = []
        for raw_choice in getattr(response, "choices", []) or []:
            message = getattr(raw_choice, "message", None)
            content = (
                (getattr(message, "content", "") or "")
                if message else ""
            )
            tool_calls: List[ToolCall] = []
            reasoning: Optional[str] = None
            if message is not None:
                raw_tcs = getattr(message, "tool_calls", None) or []
                for raw_tc in raw_tcs:
                    func = getattr(raw_tc, "function", None)
                    tc = ToolCall(
                        id=getattr(raw_tc, "id", "") or "",
                        name=getattr(func, "name", "") if func else "",
                        arguments=(
                            getattr(func, "arguments", "{}") if func else "{}"
                        ),
                    )
                    # Capture reasoning_content for preserve_reasoning_content
                    reasoning = getattr(message, "reasoning_content", None)
                    if reasoning and self._preserve_reasoning:
                        tc.model_extra = {"reasoning_content": reasoning}
                    tool_calls.append(tc)

            finish = getattr(raw_choice, "finish_reason", "") or ""
            choice = Choice(
                content=content,
                tool_calls=tool_calls,
                stop_reason=finish,
                generation_info=(
                    {"reasoning_content": reasoning}
                    if reasoning and self._preserve_reasoning else {}
                ),
            )
            choices_out.append(choice)

        raw_usage = getattr(response, "usage", None)
        usage = _parse_openai_usage(raw_usage)
        usage.update_cost(self.get_price_info(opt))

        return ContentResponse(choices=choices_out, usage=usage)

    def _parse_stream_response(
        self,
        stream: Any,
        opt: ProviderOptionsType,
        stream_cb: StreamingCallback,
    ) -> ContentResponse:
        """Translate an OpenAI-shape streaming chat completion response."""
        text_parts: List[str] = []
        tool_calls_by_index: dict = {}
        finish_reason = ""
        usage_dict: dict = {}

        for chunk in stream or []:
            choices = getattr(chunk, "choices", []) or []
            for raw_choice in choices:
                delta = getattr(raw_choice, "delta", None)
                if delta is not None:
                    delta_content = getattr(delta, "content", None)
                    if delta_content:
                        text_parts.append(delta_content)
                        stream_cb(delta_content)
                    delta_tcs = getattr(delta, "tool_calls", None) or []
                    for raw_tc in delta_tcs:
                        idx = getattr(raw_tc, "index", 0)
                        slot = tool_calls_by_index.setdefault(
                            idx, {"id": "", "name": "", "arguments": ""}
                        )
                        if getattr(raw_tc, "id", None):
                            slot["id"] = raw_tc.id
                        func = getattr(raw_tc, "function", None)
                        if func is not None:
                            if getattr(func, "name", None):
                                slot["name"] += func.name
                            if getattr(func, "arguments", None):
                                slot["arguments"] += func.arguments
                if getattr(raw_choice, "finish_reason", None):
                    finish_reason = raw_choice.finish_reason

            chunk_usage = getattr(chunk, "usage", None)
            if chunk_usage is not None:
                usage_dict = {
                    "prompt_tokens": getattr(chunk_usage, "prompt_tokens", 0) or 0,
                    "completion_tokens": getattr(chunk_usage, "completion_tokens", 0) or 0,
                }

        tool_calls = [
            ToolCall(
                id=slot["id"] or self.generate_tool_call_id(),
                name=slot["name"],
                arguments=slot["arguments"] or "{}",
            )
            for _, slot in sorted(tool_calls_by_index.items())
        ]

        choice = Choice(
            content="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=finish_reason,
            generation_info={"streamed": True},
        )
        usage = CallUsage(
            input_tokens=int(usage_dict.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage_dict.get("completion_tokens", 0) or 0),
        )
        usage.update_cost(self.get_price_info(opt))
        return ContentResponse(choices=[choice], usage=usage)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _collect_text(parts: List[MessagePart]) -> str:
    """Concatenate every :class:`TextPart` in ``parts``."""
    return "".join(p.text for p in parts if isinstance(p, TextPart))


def _parse_openai_usage(raw_usage: Any) -> CallUsage:
    """Translate an OpenAI ``usage`` object into a :class:`CallUsage`."""
    if raw_usage is None:
        return CallUsage()
    return CallUsage(
        input_tokens=int(getattr(raw_usage, "prompt_tokens", 0) or 0),
        output_tokens=int(getattr(raw_usage, "completion_tokens", 0) or 0),
        cache_read_tokens=int(
            (
                getattr(getattr(raw_usage, "prompt_tokens_details", None), "cached_tokens", 0)
                if getattr(raw_usage, "prompt_tokens_details", None) is not None
                else 0
            )
            or 0
        ),
    )

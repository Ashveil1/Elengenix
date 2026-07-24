"""elengenix.providers.deepseek — DeepSeek adapter (Python port).

Port of PentAGI's ``backend/pkg/providers/deepseek/deepseek.go``. The
adapter talks to DeepSeek's OpenAI-compatible Chat Completions API at
``https://api.deepseek.com/v1`` via the official ``openai`` Python SDK
(with a custom ``base_url``), and implements the full
:class:`~elengenix.providers.base.Provider` protocol.

Key features ported from the Go original
-----------------------------------------
* **OpenAI-compatible transport** — the DeepSeek V4 API accepts the
  standard OpenAI Chat Completions request shape; the only customisation
  is ``base_url`` and the ``DEEPSEEK_API_KEY`` bearer token. The OpenAI
  SDK is imported lazily so the module loads without it installed.
* **Reasoning-content preservation** — DeepSeek's reasoning models
  (``deepseek-reasoner``, ``deepseek-v4-pro`` with thinking enabled)
  emit a separate ``reasoning_content`` field on assistant messages.
  When the chain is replayed for a multi-turn tool call, the
  ``reasoning_content`` MUST be preserved verbatim or the API rejects
  the request. The orchestrator threads this through via
  :attr:`MessagePart` ``metadata`` on :class:`ToolCall`.
* **Tool-call ID template** — ``"call_{r:2:d}_{r:24:b}"`` (2-digit
  decimal prefix + 24-char base62). DeepSeek's server generates IDs in
  this exact shape, so orchestrator-synthesised IDs are
  indistinguishable.
* **429 retry** — same ``tenacity`` policy as Bedrock: 10 attempts,
  5 s base + 1 s linear increment per attempt.
* **Per-agent config** — :func:`get_default_config` returns the
  PentAGI default agent configuration (``deepseek-v4-flash`` for
  workhorse agents, ``deepseek-v4-pro`` for reasoning-heavy slots),
  ported verbatim from ``deepseek/config.yml``.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import string
from typing import Any

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
    ReasoningConfig,
    ReasoningEffort,
    StreamingCallback,
    TextPart,
    ToolCall,
    ToolCallResponse,
    apply_model_prefix,
)

logger = logging.getLogger("elengenix.providers.deepseek")

# ---------------------------------------------------------------------------
# Constants — ported from deepseek.go
# ---------------------------------------------------------------------------

#: Default DeepSeek API base URL. Overridable via ``DEEPSEEK_SERVER_URL``
#: for self-hosted / proxy deployments.
DEEPSEEK_DEFAULT_BASE_URL: str = "https://api.deepseek.com/v1"

#: Default DeepSeek model. PentAGI's ``DeepSeekAgentModel`` constant
#: points at the same ``deepseek-v4-flash`` ID.
DEEPSEEK_DEFAULT_MODEL: str = "deepseek-v4-flash"

#: DeepSeek tool-call ID template. ``{r:2:d}`` = 2 random decimal digits,
#: ``{r:24:b}`` = 24 random base62 characters. Matches the format
#: DeepSeek's server generates so orchestrator-synthesised IDs are
#: indistinguishable.
DEEPSEEK_TOOL_CALL_ID_TEMPLATE: str = "call_{r:2:d}_{r:24:b}"

#: 429 retry policy — mirrors PentAGI's
#: ``MaxTooManyRequestsRetries`` / ``TooManyRequestsRetryDelay``.
DEEPSEEK_MAX_429_RETRIES: int = 10
DEEPSEEK_429_BASE_DELAY: float = 5.0

#: Default pricing for the V4 Flash model (USD per 1M tokens).
_FLASH_PRICE = PriceInfo(input=0.14, output=0.28, cache_read=0.0028)

#: Default pricing for the V4 Pro model (USD per 1M tokens).
_PRO_PRICE = PriceInfo(input=1.74, output=3.48, cache_read=0.0145)


# ---------------------------------------------------------------------------
# Base62 random helpers (for tool-call ID generation)
# ---------------------------------------------------------------------------

_BASE62_ALPHABET: str = string.digits + string.ascii_letters


def _random_base62(length: int) -> str:
    """Return a cryptographically-secure random base62 string of ``length``."""
    return "".join(secrets.choice(_BASE62_ALPHABET) for _ in range(length))


def _random_digits(length: int) -> str:
    """Return a cryptographically-secure random decimal-digit string."""
    return "".join(secrets.choice(string.digits) for _ in range(length))


def generate_tool_call_id() -> str:
    """Generate a DeepSeek-shaped tool-call ID.

    Format: ``call_<2 digits>_<24 base62 chars>``. The orchestrator uses
    this when it needs to synthesise a tool-call ID for a tool result
    that didn't come from a real DeepSeek response (e.g. when replaying
    a cached chain).
    """
    return f"call_{_random_digits(2)}_{_random_base62(24)}"


# ---------------------------------------------------------------------------
# Default provider config (port of deepseek/config.yml)
# ---------------------------------------------------------------------------


def _agent(
    model: str = DEEPSEEK_DEFAULT_MODEL,
    *,
    temperature: float | None = None,
    top_p: float | None = None,
    n: int | None = 1,
    max_tokens: int | None = None,
    json_mode: bool = False,
    reasoning_effort: ReasoningEffort | None = None,
    thinking_type: str = "disabled",
    price: PriceInfo | None = None,
) -> AgentConfig:
    """Build an :class:`AgentConfig` with DeepSeek defaults.

    The ``extra_body.thinking.type`` knob is set explicitly on every slot
    as a defensive measure against future DeepSeek default changes —
    PentAGI does the same thing in ``deepseek/config.yml``.
    """
    extra_body: dict[str, Any] = {"thinking": {"type": thinking_type}}
    reasoning = None
    if reasoning_effort is not None and reasoning_effort != ReasoningEffort.NONE:
        reasoning = ReasoningConfig(effort=reasoning_effort)
    return AgentConfig(
        model=model,
        temperature=temperature,
        top_p=top_p,
        n=n,
        max_tokens=max_tokens,
        json_mode=json_mode,
        reasoning=reasoning or None,  # type: ignore[arg-type]
        price=price,
        extra_body=extra_body,
    )


def get_default_config() -> ProviderConfig:
    """Return the default DeepSeek :class:`ProviderConfig`.

    Ported verbatim from ``deepseek/config.yml``. ``deepseek-v4-flash``
    is used for the workhorse agents (cheap, fast); ``deepseek-v4-pro``
    with reasoning effort=high for the planning / code-gen / pentest
    slots that benefit from deeper thinking.
    """
    cfg = ProviderConfig()
    cfg.simple = _agent(
        temperature=0.3,
        top_p=0.9,
        max_tokens=8192,
        thinking_type="disabled",
        price=_FLASH_PRICE,
    )
    cfg.simple_json = _agent(
        temperature=0.3,
        top_p=0.9,
        max_tokens=4096,
        json_mode=True,
        thinking_type="disabled",
        price=_FLASH_PRICE,
    )
    cfg.primary_agent = _agent(
        model="deepseek-v4-pro",
        max_tokens=16384,
        reasoning_effort=ReasoningEffort.HIGH,
        thinking_type="enabled",
        price=_PRO_PRICE,
    )
    cfg.assistant = _agent(
        model="deepseek-v4-pro",
        max_tokens=16384,
        reasoning_effort=ReasoningEffort.HIGH,
        thinking_type="enabled",
        price=_PRO_PRICE,
    )
    cfg.generator = _agent(
        model="deepseek-v4-pro",
        max_tokens=32768,
        reasoning_effort=ReasoningEffort.HIGH,
        thinking_type="enabled",
        price=_PRO_PRICE,
    )
    cfg.refiner = _agent(
        model="deepseek-v4-pro",
        max_tokens=32768,
        reasoning_effort=ReasoningEffort.HIGH,
        thinking_type="enabled",
        price=_PRO_PRICE,
    )
    cfg.adviser = _agent(
        model="deepseek-v4-pro",
        max_tokens=16384,
        reasoning_effort=ReasoningEffort.HIGH,
        thinking_type="enabled",
        price=_PRO_PRICE,
    )
    cfg.reflector = _agent(
        temperature=0.5,
        top_p=0.9,
        max_tokens=8192,
        thinking_type="disabled",
        price=_FLASH_PRICE,
    )
    cfg.searcher = _agent(
        temperature=0.5,
        top_p=0.9,
        max_tokens=4096,
        thinking_type="disabled",
        price=_FLASH_PRICE,
    )
    cfg.enricher = _agent(
        temperature=0.5,
        top_p=0.9,
        max_tokens=4096,
        thinking_type="disabled",
        price=_FLASH_PRICE,
    )
    cfg.coder = _agent(
        model="deepseek-v4-pro",
        max_tokens=20480,
        reasoning_effort=ReasoningEffort.HIGH,
        thinking_type="enabled",
        price=_PRO_PRICE,
    )
    cfg.installer = _agent(
        max_tokens=12288,
        reasoning_effort=ReasoningEffort.HIGH,
        thinking_type="enabled",
        price=_FLASH_PRICE,
    )
    cfg.pentester = _agent(
        model="deepseek-v4-pro",
        max_tokens=16384,
        reasoning_effort=ReasoningEffort.HIGH,
        thinking_type="enabled",
        price=_PRO_PRICE,
    )
    return cfg


# ---------------------------------------------------------------------------
# Default models catalog (port of deepseek/models.yml)
# ---------------------------------------------------------------------------


DEEPSEEK_DEFAULT_MODELS: list[ModelConfig] = [
    ModelConfig(
        name="deepseek-v4-flash",
        description=(
            "DeepSeek V4 Flash — Cost-efficient general-purpose model with "
            "hybrid thinking/non-thinking modes (default thinking, switchable "
            "via extra_body). Suitable for dialogue, code generation, and tool "
            "calling. Supports JSON output, tool calls, chat prefix completion "
            "(beta), and FIM completion (non-thinking only). 1M context, up to "
            "384K output tokens."
        ),
        thinking=True,
        price=PriceInfo(input=0.14, output=0.28, cache_read=0.0028),
    ),
    ModelConfig(
        name="deepseek-v4-pro",
        description=(
            "DeepSeek V4 Pro — Higher-tier reasoning model with hybrid "
            "thinking/non-thinking modes (default thinking, switchable via "
            "extra_body). Suitable for complex logic, mathematical reasoning, "
            "and security analysis. Supports JSON output, tool calls, chat "
            "prefix completion (beta), and FIM completion (non-thinking only). "
            "1M context, up to 384K output tokens."
        ),
        thinking=True,
        price=PriceInfo(input=1.74, output=3.48, cache_read=0.0145),
    ),
]


# ---------------------------------------------------------------------------
# DeepSeekProvider
# ---------------------------------------------------------------------------


class DeepSeekProvider:
    """DeepSeek adapter (Python port of ``deepseekProvider``).

    Construction is lazy — the ``openai`` Python SDK is imported inside
    :meth:`__init__` so importing this module never requires it to be
    installed. The API key is read from ``DEEPSEEK_API_KEY`` (or supplied
    explicitly); the base URL defaults to
    :data:`DEEPSEEK_DEFAULT_BASE_URL` and is overridable via
    ``DEEPSEEK_SERVER_URL`` for self-hosted / proxy deployments.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        provider_prefix: str = "",
        provider_config: ProviderConfig | None = None,
        models: list[ModelConfig] | None = None,
        provider_name: str = "deepseek",
    ) -> None:
        self._api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        if not self._api_key:
            raise RuntimeError(
                "missing DEEPSEEK_API_KEY environment variable "
                "(set it or pass api_key=... to DeepSeekProvider)"
            )

        self._base_url = base_url or os.environ.get(
            "DEEPSEEK_SERVER_URL", DEEPSEEK_DEFAULT_BASE_URL
        )
        self._provider_prefix = provider_prefix or os.environ.get(
            "DEEPSEEK_PROVIDER", ""
        )
        self._provider_name = provider_name
        self._provider_config: ProviderConfig = (
            provider_config if provider_config is not None else get_default_config()
        )
        self._models: list[ModelConfig] = (
            models if models is not None else list(DEEPSEEK_DEFAULT_MODELS)
        )

        # Cached tool-call ID template.
        self._tool_call_id_template: str | None = None

        # The OpenAI client is created lazily so the module can be
        # imported without the ``openai`` package installed.
        self._client: Any = None

    # ------------------------------------------------------------------
    # OpenAI client construction
    # ------------------------------------------------------------------

    def _get_client(self) -> Any:
        """Lazily construct (and cache) the OpenAI SDK client.

        Uses the official ``openai.OpenAI`` class with ``base_url`` set
        to the DeepSeek endpoint and ``api_key`` set to the bearer
        token. ``with_options(timeout=...)`` is left to the caller to
        configure via env vars if needed.
        """
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "openai is required for the DeepSeek provider; "
                "install with `pip install openai`"
            ) from exc
        self._client = OpenAI(
            api_key=self._api_key,
            base_url=self._base_url,
        )
        return self._client

    # ------------------------------------------------------------------
    # Provider protocol
    # ------------------------------------------------------------------

    def type(self) -> ProviderType:
        return ProviderType.DEEPSEEK

    def name(self) -> str:
        return self._provider_name

    def model(self, opt: ProviderOptionsType) -> str:
        """Resolve the model name for ``opt``.

        Falls back to :data:`DEEPSEEK_DEFAULT_MODEL` when the slot is
        empty — mirrors PentAGI's ``deepseekProvider.Model``.
        """
        agent = self._provider_config.get_agent_config(opt)
        if agent is not None and agent.model:
            return agent.model
        return DEEPSEEK_DEFAULT_MODEL

    def model_with_prefix(self, opt: ProviderOptionsType) -> str:
        """Return the model name with the LiteLLM proxy prefix applied.

        DeepSeek supports LiteLLM-style model namespacing via
        ``DEEPSEEK_PROVIDER``; when set, the prefix is prepended to the
        model name (e.g. ``deepseek/deepseek-v4-flash``).
        """
        return apply_model_prefix(self.model(opt), self._provider_prefix)

    def get_models(self) -> ModelsConfig:
        return ModelsConfig(models=list(self._models))

    def get_price_info(self, opt: ProviderOptionsType) -> PriceInfo | None:
        return self._provider_config.get_price_info(opt)

    def get_tool_call_id_template(self) -> str:
        """Return the cached DeepSeek tool-call ID template."""
        if self._tool_call_id_template is None:
            self._tool_call_id_template = DEEPSEEK_TOOL_CALL_ID_TEMPLATE
        return self._tool_call_id_template

    # ------------------------------------------------------------------
    # Call entrypoints
    # ------------------------------------------------------------------

    def call(
        self,
        opt: ProviderOptionsType,
        prompt: str,
    ) -> str:
        """Single-prompt convenience call — wraps :meth:`call_ex`.

        Builds a 1-message chain (user role, single text part) and
        returns the first choice's content. Mirrors PentAGI's
        ``WrapGenerateFromSinglePrompt``.
        """
        chain = [MessageContent(role="user", parts=[TextPart(text=prompt)])]
        resp = self.call_ex(opt, chain, stream_cb=None)
        if not resp.choices:
            raise RuntimeError("empty response from DeepSeek")
        return resp.choices[0].content

    def call_ex(
        self,
        opt: ProviderOptionsType,
        chain: list[MessageContent],
        stream_cb: StreamingCallback | None = None,
    ) -> ContentResponse:
        """Multi-turn call without new tools (mirrors ``CallEx``)."""
        return self._invoke_chat_completion(opt, chain, tools=None, stream_cb=stream_cb)

    def call_with_tools(
        self,
        opt: ProviderOptionsType,
        chain: list[MessageContent],
        tools: list[dict[str, Any]],
        stream_cb: StreamingCallback | None = None,
    ) -> ContentResponse:
        """Multi-turn call with explicit tools (mirrors ``CallWithTools``)."""
        return self._invoke_chat_completion(opt, chain, tools=tools, stream_cb=stream_cb)

    # ------------------------------------------------------------------
    # Chat Completions invocation + 429 retry
    # ------------------------------------------------------------------

    def _invoke_chat_completion(
        self,
        opt: ProviderOptionsType,
        chain: list[MessageContent],
        tools: list[dict[str, Any]] | None,
        stream_cb: StreamingCallback | None,
    ) -> ContentResponse:
        """Invoke DeepSeek chat completion with 429 retry.

        The 429 retry policy uses ``tenacity`` with 10 attempts, 5 s
        base + 1 s linear increment per attempt — matching PentAGI's
        ``MaxTooManyRequestsRetries`` / ``TooManyRequestsRetryDelay``
        exactly. ``tenacity`` is imported lazily so the module can be
        imported without it installed.
        """
        agent = self._provider_config.get_agent_config(opt)
        model = self.model_with_prefix(opt)
        request = self._build_chat_request(model, agent, chain, tools)

        client = self._get_client()
        if stream_cb is not None:
            return self._invoke_with_retry_streaming(client, request, stream_cb, opt)
        return self._invoke_with_retry(client, request, opt)

    def _invoke_with_retry(
        self,
        client: Any,
        request: dict[str, Any],
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
                "tenacity is required for the DeepSeek provider; "
                "install with `pip install tenacity`"
            ) from exc

        retrying = Retrying(
            stop=stop_after_attempt(DEEPSEEK_MAX_429_RETRIES),
            wait=wait_fixed(DEEPSEEK_429_BASE_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_DeepSeekTooManyRequests),
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
                            "deepseek 429 on slot %s, retrying (attempt %d/%d)",
                            opt.value,
                            attempt.retry_state.attempt_number,
                            DEEPSEEK_MAX_429_RETRIES,
                        )
                        raise _DeepSeekTooManyRequests(str(exc)) from exc
                    raise
        return self._parse_chat_response(response, opt)

    def _invoke_with_retry_streaming(
        self,
        client: Any,
        request: dict[str, Any],
        stream_cb: StreamingCallback,
        opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Call ``chat.completions.create`` (stream=True) with 429 retry."""
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
                "tenacity is required for the DeepSeek provider; "
                "install with `pip install tenacity`"
            ) from exc

        retrying = Retrying(
            stop=stop_after_attempt(DEEPSEEK_MAX_429_RETRIES),
            wait=wait_fixed(DEEPSEEK_429_BASE_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_DeepSeekTooManyRequests),
            reraise=True,
        )

        stream: Any = None
        for attempt in retrying:
            with attempt:
                try:
                    stream = client.chat.completions.create(**{**request, "stream": True})
                except Exception as exc:
                    if _is_too_many_requests(exc):
                        logger.warning(
                            "deepseek 429 (stream) on slot %s, retrying (attempt %d/%d)",
                            opt.value,
                            attempt.retry_state.attempt_number,
                            DEEPSEEK_MAX_429_RETRIES,
                        )
                        raise _DeepSeekTooManyRequests(str(exc)) from exc
                    raise
        return self._parse_chat_stream_response(stream, opt, stream_cb)

    # ------------------------------------------------------------------
    # Request / response translation
    # ------------------------------------------------------------------

    def _build_chat_request(
        self,
        model: str,
        agent: AgentConfig | None,
        chain: list[MessageContent],
        tools: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Build a DeepSeek (OpenAI-shape) chat-completion request body.

        Translates the provider-agnostic :class:`MessageContent` chain
        into the OpenAI ``messages`` / ``tools`` shape. Assistant tool
        calls and tool results are emitted in the format expected by
        DeepSeek (identical to OpenAI).

        Reasoning-content preservation: when an assistant message in the
        chain carries a ``reasoning`` field, it is forwarded as
        ``reasoning_content`` on the message so the API accepts the
        replay (DeepSeek rejects multi-turn requests that drop the
        reasoning_content of a prior thinking-mode assistant message).
        """
        messages: list[dict[str, Any]] = []
        for msg in chain:
            role = msg.role
            if role == "system":
                text = _collect_text(msg.parts)
                if text:
                    messages.append({"role": "system", "content": text})
                continue

            if role == "tool":
                # Tool results — emit one message per ToolCallResponse.
                for part in msg.parts:
                    if isinstance(part, ToolCallResponse):
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": part.tool_call_id,
                                "content": part.content,
                            }
                        )
                continue

            # user / assistant
            text_parts: list[str] = []
            tool_calls: list[dict[str, Any]] = []
            reasoning: str | None = None
            for part in msg.parts:
                if isinstance(part, TextPart):
                    if part.text:
                        text_parts.append(part.text)
                elif isinstance(part, ToolCall):
                    tc: dict[str, Any] = {
                        "id": part.id or generate_tool_call_id(),
                        "type": "function",
                        "function": {
                            "name": part.name,
                            "arguments": part.arguments,
                        },
                    }
                    # Preserve reasoning_content (if any) on the
                    # originating assistant message — DeepSeek requires
                    # this for multi-turn tool-call replays.
                    tc_reasoning = part.model_extra.get("reasoning_content") if \
                        part.model_extra else None
                    if tc_reasoning and not reasoning:
                        reasoning = tc_reasoning
                    tool_calls.append(tc)
                elif isinstance(part, ToolCallResponse):
                    # Shouldn't normally appear on assistant messages —
                    # if it does, surface as text content.
                    text_parts.append(part.content)

            message: dict[str, Any] = {"role": role}
            if role == "assistant":
                # Assistant messages with tool_calls must have
                # ``content`` set to ``None`` (or empty string) per the
                # OpenAI spec.
                message["content"] = "".join(text_parts) if text_parts else None
                if tool_calls:
                    message["tool_calls"] = tool_calls
                if reasoning:
                    message["reasoning_content"] = reasoning
            else:
                message["content"] = "".join(text_parts)
            messages.append(message)

        request: dict[str, Any] = {"model": model, "messages": messages}

        # Inference config — ported from AgentConfig.BuildOptions().
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

            # Reasoning — DeepSeek accepts the legacy
            # ``reasoning_effort`` string ("low"|"medium"|"high") rather
            # than the modern ``reasoning`` object form. PentAGI's Go
            # adapter does the same by NOT calling
            # ``WithModernReasoningFormat()``.
            reasoning_effort = (
                agent.reasoning.effort if agent.reasoning is not None else None
            )
            if reasoning_effort and reasoning_effort != ReasoningEffort.NONE:
                request["reasoning_effort"] = reasoning_effort.value

            # extra_body — forwarded verbatim (thinking.type, etc.).
            if agent.extra_body:
                request["extra_body"] = dict(agent.extra_body)

        if tools:
            request["tools"] = tools

        return request

    def _parse_chat_response(
        self,
        response: Any,
        opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Translate an OpenAI-shape chat completion response."""
        choices_out: list[Choice] = []
        usage = CallUsage()

        for raw_choice in getattr(response, "choices", []) or []:
            message = getattr(raw_choice, "message", None)
            content = getattr(message, "content", "") or "" if message else ""
            tool_calls: list[ToolCall] = []
            reasoning: str | None = None
            if message is not None:
                raw_tcs = getattr(message, "tool_calls", None) or []
                for raw_tc in raw_tcs:
                    func = getattr(raw_tc, "function", None)
                    tool_calls.append(
                        ToolCall(
                            id=getattr(raw_tc, "id", "") or "",
                            name=getattr(func, "name", "") if func else "",
                            arguments=getattr(func, "arguments", "{}") if func else "{}",
                        )
                    )
                # Preserve reasoning_content for multi-turn replays.
                reasoning = getattr(message, "reasoning_content", None)

            finish = getattr(raw_choice, "finish_reason", "") or ""
            choice = Choice(
                content=content,
                tool_calls=tool_calls,
                stop_reason=finish,
                generation_info={"reasoning_content": reasoning} if reasoning else {},
            )
            choices_out.append(choice)

        raw_usage = getattr(response, "usage", None)
        if raw_usage is not None:
            usage = CallUsage(
                input_tokens=int(getattr(raw_usage, "prompt_tokens", 0) or 0),
                output_tokens=int(getattr(raw_usage, "completion_tokens", 0) or 0),
                cache_read_tokens=int(
                    getattr(raw_usage, "prompt_tokens_details", None)
                    and getattr(raw_usage.prompt_tokens_details, "cached_tokens", 0)
                    or 0
                ),
            )
        usage.update_cost(self.get_price_info(opt))

        return ContentResponse(choices=choices_out, usage=usage)

    def _parse_chat_stream_response(
        self,
        stream: Any,
        opt: ProviderOptionsType,
        stream_cb: StreamingCallback,
    ) -> ContentResponse:
        """Translate an OpenAI-shape streaming chat completion response.

        Streams text deltas to ``stream_cb`` as they arrive; aggregates
        tool-call deltas and usage into the final
        :class:`ContentResponse`. Tool-call deltas are merged by index
        (OpenAI streams a single tool call across multiple deltas with
        the same ``index``).
        """
        text_parts: list[str] = []
        tool_calls_by_index: dict[int, dict[str, Any]] = {}
        finish_reason = ""
        usage_dict: dict[str, Any] = {}

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
                id=slot["id"] or generate_tool_call_id(),
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


class _DeepSeekTooManyRequests(Exception):
    """Internal sentinel raised to trigger tenacity 429 retry."""


def _is_too_many_requests(exc: BaseException) -> bool:
    """Return True if ``exc`` represents an HTTP 429 / throttling error.

    The ``openai`` Python SDK raises ``openai.RateLimitError`` on 429s;
    we also check the message text as a fallback (some proxies return
    bare 429 strings).
    """
    # ``openai.RateLimitError`` — check by class name to avoid importing
    # the SDK at module load.
    if exc.__class__.__name__ == "RateLimitError":
        return True
    err_str = str(exc).lower()
    if "status code: 429" in err_str or "statuscode: 429" in err_str:
        return True
    if "rate limit" in err_str or "too many requests" in err_str:
        return True
    return False


def _collect_text(parts: list[MessagePart]) -> str:
    """Concatenate every :class:`TextPart` in ``parts``."""
    return "".join(p.text for p in parts if isinstance(p, TextPart))


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------


__all__ = [
    "DEEPSEEK_DEFAULT_BASE_URL",
    "DEEPSEEK_DEFAULT_MODEL",
    "DEEPSEEK_TOOL_CALL_ID_TEMPLATE",
    "DEEPSEEK_MAX_429_RETRIES",
    "DEEPSEEK_429_BASE_DELAY",
    "DEEPSEEK_DEFAULT_MODELS",
    "DeepSeekProvider",
    "generate_tool_call_id",
    "get_default_config",
]

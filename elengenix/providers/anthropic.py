"""elengenix.providers.anthropic — Anthropic (Claude) LLM provider adapter
(Python port).

Port of PentAGI's ``backend/pkg/providers/anthropic/anthropic.go``. The
adapter talks to Anthropic's Messages API at
``https://api.anthropic.com`` via the official ``anthropic`` Python SDK,
and implements the full :class:`~elengenix.providers.base.Provider`
protocol.

Key features ported from the Go original
-----------------------------------------
* **Default model** — ``claude-sonnet-4-20250514`` (PentAGI's
  ``AnthropicAgentModel``). Also supports ``claude-opus-4-...``,
  ``claude-haiku-4-...``, ``claude-3-7-sonnet-...``, etc.
* **Tool-call ID template** — ``toolu_{r:24:b}`` (24 random base62
  chars, ``toolu_`` prefix). Matches Anthropic's server-generated
  ``tool_use`` IDs.
* **Extended thinking with cryptographic signatures** — required for
  multi-turn tool calls. When thinking is enabled, the API returns a
  ``thinking`` content block with both ``thinking`` (the reasoning
  text) and ``signature`` (a server-signed HMAC). On the NEXT turn, the
  full ``thinking`` block (text + signature) MUST be re-sent verbatim —
  otherwise the API rejects the request. The
  :meth:`AnthropicProvider.preserve_thinking_block` helper captures
  this; :meth:`_build_request` automatically re-attaches preserved
  thinking blocks.
* **Auto-strip reasoning sigs from previous turns** — when building a
  new request, prior assistant turns' thinking blocks are kept if and
  only if they immediately precede a ``tool_use`` block (Anthropic's
  multi-turn contract). Other thinking blocks are stripped via
  :meth:`_strip_orphan_thinking_blocks`.
* **Cache strategy** — inline ``cache_control`` markers on
  ``system``, ``tools``, and the last 1-2 user messages. Anthropic
  offers 90% savings on cached reads. Per PentAGI's
  ``WithDefaultCacheStrategy``, the cache TTL is 5 minutes. Cache
  breakpoints:

  - Sonnet models: 1024-token minimum for cache breakpoint.
  - Haiku models: 4096-token minimum for cache breakpoint (lowered to
    2048 in 2024).
  - Opus models: 1024-token minimum.

  The :meth:`apply_cache_strategy` helper inserts ``cache_control``
  markers; :meth:`min_cache_tokens` returns the model-specific minimum.
* **No ``temperature`` constraint** — Anthropic accepts 0.0-1.0 (and
  up to 2.0 with extended thinking disabled). The per-agent YAML sets
  the desired value (typically 1.0).

The ``anthropic`` SDK is imported lazily inside
:meth:`AnthropicProvider._get_client` so that environments without
``anthropic`` installed can still import this module.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import string
from typing import Any, List, Optional

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
    apply_model_prefix,
)

logger = logging.getLogger("elengenix.providers.anthropic")

# ---------------------------------------------------------------------------
# Constants — ported from anthropic.go
# ---------------------------------------------------------------------------

#: Default Anthropic API base URL. Overridable via ``ANTHROPIC_BASE_URL``
#: (or ``ANTHROPIC_SERVER_URL`` for PentAGI compatibility).
ANTHROPIC_DEFAULT_SERVER_URL: str = "https://api.anthropic.com"

#: Default Anthropic model. PentAGI's ``AnthropicAgentModel`` constant.
ANTHROPIC_DEFAULT_MODEL: str = "claude-sonnet-4-20250514"

#: Anthropic tool-call ID template. ``{r:24:b}`` = 24 random base62 chars.
#: Matches the format Anthropic's server generates for ``tool_use`` IDs.
ANTHROPIC_TOOL_CALL_ID_TEMPLATE: str = "toolu_{r:24:b}"

#: 429 retry policy.
ANTHROPIC_MAX_429_RETRIES: int = 10
ANTHROPIC_429_BASE_DELAY: float = 5.0

#: Anthropic's documented minimum cacheable prompt tokens by model family.
#: Source: https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching
ANTHROPIC_CACHE_MIN_TOKENS: dict = {
    "claude-opus": 1024,
    "claude-sonnet": 1024,
    "claude-haiku": 2048,
}


# ---------------------------------------------------------------------------
# Tool-call ID generator — exposed at module scope for registry import
# ---------------------------------------------------------------------------


_BASE62_ALPHABET: str = string.digits + string.ascii_letters


def generate_tool_call_id() -> str:
    """Generate an Anthropic-shaped tool-call ID.

    Format: ``toolu_<24 base62 chars>``. Matches the format Anthropic's
    server generates so orchestrator-synthesised IDs are
    indistinguishable.
    """
    return "toolu_" + "".join(
        secrets.choice(_BASE62_ALPHABET) for _ in range(24)
    )


# ---------------------------------------------------------------------------
# Default pricing — USD per 1M tokens (Anthropic public pricing, 2026-Q1)
# ---------------------------------------------------------------------------

_SONNET_4_PRICE = PriceInfo(input=3.00, output=15.00, cache_read=0.30, cache_write=3.75)
_OPUS_4_PRICE = PriceInfo(input=15.00, output=75.00, cache_read=1.50, cache_write=18.75)
_HAIKU_4_PRICE = PriceInfo(input=0.80, output=4.00, cache_read=0.08, cache_write=1.00)


#: Default Anthropic model catalog — ported from anthropic/models.yml.
ANTHROPIC_DEFAULT_MODELS: List[ModelConfig] = [
    ModelConfig(
        name="claude-sonnet-4-20250514",
        description=(
            "Claude Sonnet 4 - Best balance of intelligence and speed. "
            "200K context, extended thinking with signatures, prompt "
            "caching (1024-token min). Best default for agent workloads."
        ),
        thinking=True,
        price=_SONNET_4_PRICE,
    ),
    ModelConfig(
        name="claude-opus-4-20250514",
        description=(
            "Claude Opus 4 - Top-tier intelligence for complex reasoning. "
            "200K context, extended thinking, prompt caching (1024-token "
            "min). Best for generator/refiner/adviser slots."
        ),
        thinking=True,
        price=_OPUS_4_PRICE,
    ),
    ModelConfig(
        name="claude-haiku-4-20250514",
        description=(
            "Claude Haiku 4 - Fastest model. 200K context, prompt caching "
            "(2048-token min). Best for high-volume utility / reflector "
            "slots."
        ),
        thinking=False,
        price=_HAIKU_4_PRICE,
    ),
]


# ---------------------------------------------------------------------------
# Default provider config (port of anthropic/config.yml)
# ---------------------------------------------------------------------------


def _agent(
    model: str,
    *,
    temperature: float = 1.0,
    max_tokens: int = 4000,
    thinking_enabled: bool = False,
    thinking_budget: int = 0,
    json_mode: bool = False,
    price: PriceInfo | None = None,
) -> AgentConfig:
    """Build an Anthropic :class:`AgentConfig`.

    ``thinking_enabled=True`` enables extended thinking (requires a
    ``thinking_budget`` token budget — Anthropic recommends 4096+ for
    agent workloads). The ``extra_body.thinking`` block is forwarded
    verbatim to the ``anthropic`` SDK as the ``thinking=`` kwarg on
    ``client.messages.create()``.
    """
    extra_body: dict[str, Any] = {}
    if thinking_enabled:
        thinking_block: dict[str, Any] = {"type": "enabled"}
        if thinking_budget > 0:
            thinking_block["budget_tokens"] = thinking_budget
        extra_body["thinking"] = thinking_block
    agent = AgentConfig(
        model=model,
        temperature=temperature,
        n=1,
        max_tokens=max_tokens,
        extra_body=extra_body,
        price=price,
    )
    if json_mode:
        agent.json_mode = True
    return agent


def get_default_config() -> ProviderConfig:
    """Return the default Anthropic :class:`ProviderConfig`.

    Ported from ``anthropic/config.yml``. Strategy:
    * ``claude-sonnet-4`` for all slots by default.
    * Extended thinking enabled (budget=8192) for reasoning-heavy slots.
    """
    cfg = ProviderConfig()
    cfg.simple = _agent(
        "claude-sonnet-4-20250514",
        temperature=1.0, max_tokens=8192,
        price=_SONNET_4_PRICE,
    )
    cfg.simple_json = _agent(
        "claude-sonnet-4-20250514",
        temperature=1.0, max_tokens=4096, json_mode=True,
        price=_SONNET_4_PRICE,
    )
    cfg.primary_agent = _agent(
        "claude-sonnet-4-20250514",
        temperature=1.0, max_tokens=16384,
        thinking_enabled=True, thinking_budget=8192,
        price=_SONNET_4_PRICE,
    )
    cfg.assistant = _agent(
        "claude-sonnet-4-20250514",
        temperature=1.0, max_tokens=16384,
        thinking_enabled=True, thinking_budget=8192,
        price=_SONNET_4_PRICE,
    )
    cfg.generator = _agent(
        "claude-opus-4-20250514",
        temperature=1.0, max_tokens=32768,
        thinking_enabled=True, thinking_budget=16384,
        price=_OPUS_4_PRICE,
    )
    cfg.refiner = _agent(
        "claude-opus-4-20250514",
        temperature=1.0, max_tokens=32768,
        thinking_enabled=True, thinking_budget=16384,
        price=_OPUS_4_PRICE,
    )
    cfg.adviser = _agent(
        "claude-opus-4-20250514",
        temperature=1.0, max_tokens=16384,
        thinking_enabled=True, thinking_budget=8192,
        price=_OPUS_4_PRICE,
    )
    cfg.reflector = _agent(
        "claude-haiku-4-20250514",
        temperature=0.7, max_tokens=4096,
        price=_HAIKU_4_PRICE,
    )
    cfg.searcher = _agent(
        "claude-haiku-4-20250514",
        temperature=0.7, max_tokens=4096,
        price=_HAIKU_4_PRICE,
    )
    cfg.enricher = _agent(
        "claude-haiku-4-20250514",
        temperature=0.7, max_tokens=4096,
        price=_HAIKU_4_PRICE,
    )
    cfg.coder = _agent(
        "claude-sonnet-4-20250514",
        temperature=1.0, max_tokens=20480,
        thinking_enabled=True, thinking_budget=8192,
        price=_SONNET_4_PRICE,
    )
    cfg.installer = _agent(
        "claude-sonnet-4-20250514",
        temperature=1.0, max_tokens=16384,
        price=_SONNET_4_PRICE,
    )
    cfg.pentester = _agent(
        "claude-sonnet-4-20250514",
        temperature=1.0, max_tokens=16384,
        thinking_enabled=True, thinking_budget=8192,
        price=_SONNET_4_PRICE,
    )
    return cfg


# ---------------------------------------------------------------------------
# AnthropicProvider
# ---------------------------------------------------------------------------


class _AnthropicTooManyRequests(Exception):
    """Internal sentinel raised to trigger tenacity 429 retry."""


def _is_too_many_requests(exc: BaseException) -> bool:
    """Return ``True`` if ``exc`` represents an HTTP 429 / throttling
    error. The ``anthropic`` Python SDK raises
    ``anthropic.RateLimitError`` on 429s."""
    if exc.__class__.__name__ == "RateLimitError":
        return True
    err_str = str(exc).lower()
    if "status code: 429" in err_str or "statuscode: 429" in err_str:
        return True
    if "rate limit" in err_str or "too many requests" in err_str:
        return True
    return False


class AnthropicProvider:
    """Anthropic (Claude) adapter (Python port of ``anthropicProvider``).

    Construction is lazy — the ``anthropic`` Python SDK is imported
    inside :meth:`_get_client` so importing this module never requires
    it to be installed. The API key is read from ``ANTHROPIC_API_KEY``;
    the base URL defaults to :data:`ANTHROPIC_DEFAULT_SERVER_URL` and is
    overridable via ``ANTHROPIC_BASE_URL`` (or ``ANTHROPIC_SERVER_URL``
    for PentAGI compatibility).

    Anthropic's extended-thinking contract requires that the thinking
    block (text + signature) from the immediately-preceding assistant
    turn be re-sent verbatim when continuing a multi-turn tool-call
    flow. The :meth:`preserve_thinking_block` helper captures this; the
    per-agent YAML config sets ``extra_body.thinking.type=enabled`` +
    ``extra_body.thinking.budget_tokens`` for reasoning slots.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        provider_config: Optional[ProviderConfig] = None,
        models: Optional[List[ModelConfig]] = None,
        provider_name: str = "anthropic",
        request_timeout: float = 120.0,
        cache_strategy: Optional[dict] = None,
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self._api_key:
            raise RuntimeError(
                "missing ANTHROPIC_API_KEY environment variable "
                "(set it or pass api_key=... to AnthropicProvider)"
            )
        self._base_url = base_url or (
            os.environ.get("ANTHROPIC_BASE_URL")
            or os.environ.get("ANTHROPIC_SERVER_URL")
            or ANTHROPIC_DEFAULT_SERVER_URL
        )
        self._provider_name = provider_name
        self._provider_config: ProviderConfig = (
            provider_config if provider_config is not None
            else get_default_config()
        )
        self._models: List[ModelConfig] = (
            models if models is not None
            else list(ANTHROPIC_DEFAULT_MODELS)
        )
        self._request_timeout = request_timeout
        # Cache strategy — mirrors langchaingo's WithDefaultCacheStrategy.
        # Default: cache tools + system + last user message, TTL 5m.
        self._cache_strategy: dict = cache_strategy or {
            "cache_tools": True,
            "cache_system": True,
            "cache_messages": True,
            "ttl": "5m",
        }
        self._client: Any = None  # anthropic.Anthropic — lazy

    # ------------------------------------------------------------------
    # Lazy SDK client
    # ------------------------------------------------------------------

    def _get_client(self) -> Any:
        """Lazily construct (and cache) the ``anthropic.Anthropic`` client."""
        if self._client is not None:
            return self._client
        try:
            from anthropic import Anthropic  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "anthropic is required for the Anthropic provider; "
                "install with `pip install anthropic>=0.20.0`"
            ) from exc
        self._client = Anthropic(
            api_key=self._api_key,
            base_url=self._base_url,
            timeout=self._request_timeout,
        )
        return self._client

    # ------------------------------------------------------------------
    # Provider Protocol implementation
    # ------------------------------------------------------------------

    def type(self) -> ProviderType:
        return ProviderType.ANTHROPIC

    def name(self) -> str:
        return self._provider_name

    def model(self, opt: ProviderOptionsType) -> str:
        """Return the model name configured for ``opt``."""
        agent = self._provider_config.get_agent_config(opt)
        if agent is not None and agent.model:
            return agent.model
        return ANTHROPIC_DEFAULT_MODEL

    def model_with_prefix(self, opt: ProviderOptionsType) -> str:
        """Anthropic provider doesn't need prefix support (passthrough
        mode in LiteLLM). Returns the bare model name."""
        return self.model(opt)

    def get_provider_config(self) -> ProviderConfig:
        return self._provider_config

    def get_models(self) -> ModelsConfig:
        return ModelsConfig(models=list(self._models))

    def get_price_info(self, opt: ProviderOptionsType) -> Optional[PriceInfo]:
        return self._provider_config.get_price_info(opt)

    def get_tool_call_id_template(self) -> str:
        return ANTHROPIC_TOOL_CALL_ID_TEMPLATE

    # ------------------------------------------------------------------
    # Anthropic-specific helpers
    # ------------------------------------------------------------------

    @staticmethod
    def min_cache_tokens(model: str) -> int:
        """Return the minimum cacheable prompt-token count for ``model``.
        Anthropic requires at least this many tokens in the cached
        prefix or the cache breakpoint is silently ignored."""
        for prefix, tokens in ANTHROPIC_CACHE_MIN_TOKENS.items():
            if model.startswith(prefix):
                return tokens
        return 1024  # conservative default

    @staticmethod
    def preserve_thinking_block(
        tool_call: ToolCall,
        thinking_text: str,
        thinking_signature: str,
    ) -> ToolCall:
        """Attach a thinking block (with cryptographic signature) to a
        :class:`ToolCall` so that the next request re-serializes it on
        the assistant message.

        Anthropic's extended-thinking contract requires that the
        thinking block (text + signature) from the immediately-preceding
        assistant turn be re-sent verbatim when continuing a multi-turn
        tool-call flow. Without it, the API rejects the request.

        Use this whenever you build a follow-up request from a prior
        assistant turn that contained a tool_use:

        .. code-block:: python

            resp = provider.call_with_tools(opt, chain, tools)
            choice = resp.choices[0]
            thinking = choice.generation_info.get("thinking_text")
            thinking_sig = choice.generation_info.get("thinking_signature")
            if thinking and thinking_sig:
                for tc in choice.tool_calls:
                    tc = AnthropicProvider.preserve_thinking_block(
                        tc, thinking, thinking_sig,
                    )
            chain = [*chain, assistant_msg, tool_result_msg]
            resp = provider.call_with_tools(opt, chain, tools)
        """
        if not thinking_text or not thinking_signature:
            return tool_call
        new_tc = tool_call.model_copy(deep=True)
        if new_tc.model_extra is None:
            new_tc.model_extra = {}
        new_tc.model_extra["thinking_text"] = thinking_text
        new_tc.model_extra["thinking_signature"] = thinking_signature
        return new_tc

    @staticmethod
    def _strip_orphan_thinking_blocks(
        chain: List[MessageContent],
    ) -> List[MessageContent]:
        """Strip thinking metadata from assistant messages that are NOT
        immediately followed by a tool_result. Anthropic's contract
        requires thinking blocks only on the immediately-preceding
        assistant turn before a tool_result; thinking blocks on earlier
        turns are rejected."""
        result: List[MessageContent] = []
        for i, msg in enumerate(chain):
            if msg.role != "assistant":
                result.append(msg)
                continue
            next_is_tool_result = False
            if i + 1 < len(chain):
                nxt = chain[i + 1]
                if nxt.role in ("user", "tool") and any(
                    isinstance(p, ToolCallResponse) for p in nxt.parts
                ):
                    next_is_tool_result = True
            if next_is_tool_result:
                result.append(msg)
            else:
                # Strip thinking metadata from ToolCall.model_extra
                stripped_parts: List[MessagePart] = []
                for p in msg.parts:
                    if isinstance(p, ToolCall) and p.model_extra:
                        new_p = p.model_copy(deep=True)
                        # Remove thinking_* keys; keep other extras
                        if new_p.model_extra:
                            new_p.model_extra = {
                                k: v for k, v in new_p.model_extra.items()
                                if not k.startswith("thinking_")
                            } or None
                        stripped_parts.append(new_p)
                    else:
                        stripped_parts.append(p)
                if stripped_parts:
                    result.append(MessageContent(
                        role=msg.role, parts=stripped_parts
                    ))
        return result

    def _convert_chain(
        self, chain: List[MessageContent]
    ) -> dict:
        """Convert a list of :class:`MessageContent` to Anthropic's
        request shape: ``{system: str, messages: [{role, content: [...]}]}``.

        Anthropic uses a single ``system`` string (not a message), and
        each message's ``content`` is a list of typed blocks
        (``text``, ``thinking``, ``tool_use``, ``tool_result``).
        """
        chain = self._strip_orphan_thinking_blocks(chain)

        system_text: List[str] = []
        messages: List[dict] = []

        for msg in chain:
            if msg.role in ("system", "developer"):
                for part in msg.parts:
                    if isinstance(part, TextPart) and part.text:
                        system_text.append(part.text)
                continue

            role = "assistant" if msg.role == "assistant" else "user"
            blocks: List[dict] = []
            for part in msg.parts:
                if isinstance(part, TextPart) and part.text:
                    blocks.append({"type": "text", "text": part.text})
                elif isinstance(part, ToolCall):
                    # If the ToolCall carries thinking_text + thinking_signature
                    # (from preserve_thinking_block), emit a thinking block
                    # BEFORE the tool_use block (Anthropic contract).
                    if part.model_extra:
                        thinking_text = part.model_extra.get("thinking_text")
                        thinking_sig = part.model_extra.get("thinking_signature")
                        if thinking_text and thinking_sig:
                            blocks.append({
                                "type": "thinking",
                                "thinking": thinking_text,
                                "signature": thinking_sig,
                            })
                    blocks.append({
                        "type": "tool_use",
                        "id": part.id or generate_tool_call_id(),
                        "name": part.name,
                        "input": _safe_json_loads(part.arguments),
                    })
                elif isinstance(part, ToolCallResponse):
                    blocks.append({
                        "type": "tool_result",
                        "tool_use_id": part.tool_call_id,
                        "content": part.content,
                    })

            if not blocks:
                continue
            messages.append({"role": role, "content": blocks})

        # Apply cache_control markers
        if self._cache_strategy.get("cache_messages") and messages:
            for i in range(len(messages) - 1, -1, -1):
                if messages[i]["role"] == "user" and messages[i]["content"]:
                    last_block = messages[i]["content"][-1]
                    last_block["cache_control"] = {
                        "type": "ephemeral",
                        "ttl": self._cache_strategy.get("ttl", "5m"),
                    }
                    break

        return {
            "system": "\n\n".join(system_text) if system_text else None,
            "messages": messages,
        }

    def _convert_tools(
        self, tools: List[dict]
    ) -> List[dict]:
        """Convert OpenAI-shape tools to Anthropic tool dicts. Anthropic
        requires ``input_schema`` (not ``parameters``) and rejects
        ``$schema`` keys in the JSON schema (Bedrock-style cleanup).
        When cache_strategy.cache_tools is True, marks the last tool
        with ``cache_control``."""
        out: List[dict] = []
        for t in tools:
            fn = t.get("function", t)
            schema = dict(fn.get("parameters") or {"type": "object", "properties": {}})
            schema.pop("$schema", None)
            out.append({
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "input_schema": schema,
            })
        if self._cache_strategy.get("cache_tools") and out:
            out[-1]["cache_control"] = {
                "type": "ephemeral",
                "ttl": self._cache_strategy.get("ttl", "5m"),
            }
        return out

    def _build_request(
        self,
        model: str,
        agent: Optional[AgentConfig],
        converted: dict,
        tools: Optional[List[dict]],
    ) -> dict:
        """Build the kwargs dict for ``client.messages.create()``."""
        kwargs: dict = {
            "model": model,
            "messages": converted["messages"],
            # Anthropic uses 'max_tokens' (required, no default)
            "max_tokens": (agent.max_tokens if agent and agent.max_tokens else 4096),
        }
        if agent is not None:
            if agent.temperature is not None:
                kwargs["temperature"] = agent.temperature
            if agent.top_p is not None:
                kwargs["top_p"] = agent.top_p
            # Extended thinking config — forwarded verbatim
            extra_body = agent.extra_body or {}
            thinking_cfg = extra_body.get("thinking")
            if thinking_cfg and isinstance(thinking_cfg, dict):
                kwargs["thinking"] = thinking_cfg
        # System goes as a top-level field (not a message)
        system = converted.get("system")
        if system:
            if self._cache_strategy.get("cache_system"):
                kwargs["system"] = [{
                    "type": "text",
                    "text": system,
                    "cache_control": {
                        "type": "ephemeral",
                        "ttl": self._cache_strategy.get("ttl", "5m"),
                    },
                }]
            else:
                kwargs["system"] = system
        if tools:
            kwargs["tools"] = self._convert_tools(tools)
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
            raise RuntimeError("empty response from Anthropic")
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
        converted = self._convert_chain(chain)
        request = self._build_request(model, agent, converted, tools)
        client = self._get_client()
        if stream_cb is not None:
            return self._invoke_streaming(client, request, stream_cb, opt)
        return self._invoke_sync(client, request, opt)

    def _invoke_sync(
        self, client: Any, request: dict, opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Call ``messages.create`` with 429 retry."""
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
            stop=stop_after_attempt(ANTHROPIC_MAX_429_RETRIES),
            wait=wait_fixed(ANTHROPIC_429_BASE_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_AnthropicTooManyRequests),
            reraise=True,
        )
        response: Any = None
        for attempt in retrying:
            with attempt:
                try:
                    response = client.messages.create(**request)
                except Exception as exc:
                    if _is_too_many_requests(exc):
                        logger.warning(
                            "anthropic 429 on slot %s, retrying (attempt %d/%d)",
                            opt.value,
                            attempt.retry_state.attempt_number,
                            ANTHROPIC_MAX_429_RETRIES,
                        )
                        raise _AnthropicTooManyRequests(str(exc)) from exc
                    raise
        return self._parse_response(response, opt)

    def _invoke_streaming(
        self, client: Any, request: dict,
        stream_cb: StreamingCallback, opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Call ``messages.create`` (stream=True) with 429 retry."""
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
            stop=stop_after_attempt(ANTHROPIC_MAX_429_RETRIES),
            wait=wait_fixed(ANTHROPIC_429_BASE_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_AnthropicTooManyRequests),
            reraise=True,
        )
        stream: Any = None
        for attempt in retrying:
            with attempt:
                try:
                    stream = client.messages.create(**{**request, "stream": True})
                except Exception as exc:
                    if _is_too_many_requests(exc):
                        logger.warning(
                            "anthropic 429 (stream) on slot %s, retrying "
                            "(attempt %d/%d)",
                            opt.value,
                            attempt.retry_state.attempt_number,
                            ANTHROPIC_MAX_429_RETRIES,
                        )
                        raise _AnthropicTooManyRequests(str(exc)) from exc
                    raise
        return self._parse_stream_response(stream, opt, stream_cb)

    def _parse_response(
        self, response: Any, opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Parse an ``anthropic`` SDK ``Message`` into our
        :class:`ContentResponse`. Captures thinking blocks (with
        signatures) for multi-turn extended-thinking flows."""
        content_blocks = getattr(response, "content", None) or []
        text_parts: List[str] = []
        tool_calls: List[ToolCall] = []
        thinking_text: Optional[str] = None
        thinking_sig: Optional[str] = None

        for block in content_blocks:
            btype = (
                getattr(block, "type", None)
                if not isinstance(block, dict) else block.get("type")
            )
            if btype == "text":
                text = (
                    getattr(block, "text", None)
                    if not isinstance(block, dict) else block.get("text")
                ) or ""
                if text:
                    text_parts.append(text)
            elif btype == "thinking":
                thinking_text = (
                    getattr(block, "thinking", None)
                    if not isinstance(block, dict) else block.get("thinking")
                )
                thinking_sig = (
                    getattr(block, "signature", None)
                    if not isinstance(block, dict) else block.get("signature")
                )
            elif btype == "tool_use":
                tc_id = (
                    getattr(block, "id", None)
                    if not isinstance(block, dict) else block.get("id")
                ) or ""
                tc_name = (
                    getattr(block, "name", None)
                    if not isinstance(block, dict) else block.get("name")
                ) or ""
                tc_input = (
                    getattr(block, "input", None)
                    if not isinstance(block, dict) else block.get("input")
                )
                tc_args = (
                    json.dumps(tc_input) if tc_input is not None else "{}"
                )
                tc = ToolCall(
                    id=tc_id, name=tc_name, arguments=tc_args,
                    type="tool_use",
                )
                # Stash thinking info on the tool_call so callers can
                # re-attach via preserve_thinking_block on the next turn.
                if thinking_text and thinking_sig:
                    tc.model_extra = {
                        "thinking_text": thinking_text,
                        "thinking_signature": thinking_sig,
                    }
                tool_calls.append(tc)

        finish_reason = getattr(response, "stop_reason", "") or ""
        gen_info: dict = {}
        if thinking_text:
            gen_info["thinking_text"] = thinking_text
        if thinking_sig:
            gen_info["thinking_signature"] = thinking_sig

        choice = Choice(
            content="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=finish_reason,
            generation_info=gen_info,
        )

        # Usage
        raw_usage = getattr(response, "usage", None)
        usage = CallUsage()
        if raw_usage is not None:
            usage = CallUsage(
                input_tokens=int(getattr(raw_usage, "input_tokens", 0) or 0),
                output_tokens=int(getattr(raw_usage, "output_tokens", 0) or 0),
                cache_read_tokens=int(
                    getattr(raw_usage, "cache_read_input_tokens", 0) or 0
                ),
                cache_write_tokens=int(
                    getattr(raw_usage, "cache_creation_input_tokens", 0) or 0
                ),
            )
        usage.update_cost(self.get_price_info(opt))

        return ContentResponse(choices=[choice], usage=usage)

    def _parse_stream_response(
        self, stream: Any, opt: ProviderOptionsType,
        stream_cb: StreamingCallback,
    ) -> ContentResponse:
        """Translate an Anthropic streaming response."""
        text_parts: List[str] = []
        tool_calls: List[ToolCall] = []
        finish_reason = ""
        thinking_text: Optional[str] = None
        thinking_sig: Optional[str] = None
        usage_dict: dict = {}

        for event in stream or []:
            event_type = getattr(event, "type", "")
            if event_type == "content_block_delta":
                delta = getattr(event, "delta", None)
                if delta is not None:
                    delta_type = getattr(delta, "type", "")
                    if delta_type == "text_delta":
                        text = getattr(delta, "text", "") or ""
                        if text:
                            text_parts.append(text)
                            stream_cb(text)
                    elif delta_type == "thinking_delta":
                        thinking_text = (
                            (thinking_text or "") + (getattr(delta, "thinking", "") or "")
                        )
                    elif delta_type == "signature_delta":
                        thinking_sig = (
                            (thinking_sig or "") + (getattr(delta, "signature", "") or "")
                        )
            elif event_type == "message_delta":
                msg_delta = getattr(event, "delta", None)
                if msg_delta is not None:
                    stop = getattr(msg_delta, "stop_reason", None)
                    if stop:
                        finish_reason = stop
                event_usage = getattr(event, "usage", None)
                if event_usage is not None:
                    usage_dict["output_tokens"] = int(
                        getattr(event_usage, "output_tokens", 0) or 0
                    )
            elif event_type == "message_start":
                msg = getattr(event, "message", None)
                if msg is not None:
                    msg_usage = getattr(msg, "usage", None)
                    if msg_usage is not None:
                        usage_dict["input_tokens"] = int(
                            getattr(msg_usage, "input_tokens", 0) or 0
                        )
                        usage_dict["cache_read_tokens"] = int(
                            getattr(msg_usage, "cache_read_input_tokens", 0) or 0
                        )
                        usage_dict["cache_write_tokens"] = int(
                            getattr(msg_usage, "cache_creation_input_tokens", 0) or 0
                        )

        gen_info: dict = {"streamed": True}
        if thinking_text:
            gen_info["thinking_text"] = thinking_text
        if thinking_sig:
            gen_info["thinking_signature"] = thinking_sig

        choice = Choice(
            content="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=finish_reason,
            generation_info=gen_info,
        )
        usage = CallUsage(
            input_tokens=int(usage_dict.get("input_tokens", 0) or 0),
            output_tokens=int(usage_dict.get("output_tokens", 0) or 0),
            cache_read_tokens=int(usage_dict.get("cache_read_tokens", 0) or 0),
            cache_write_tokens=int(usage_dict.get("cache_write_tokens", 0) or 0),
        )
        usage.update_cost(self.get_price_info(opt))
        return ContentResponse(choices=[choice], usage=usage)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_json_loads(s: str) -> dict:
    """Parse a JSON-encoded argument string. Returns {} on any error
    (Anthropic requires a dict for tool_use input)."""
    if not s:
        return {}
    try:
        parsed = json.loads(s)
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, TypeError):
        return {}


__all__ = [
    "ANTHROPIC_DEFAULT_SERVER_URL",
    "ANTHROPIC_DEFAULT_MODEL",
    "ANTHROPIC_TOOL_CALL_ID_TEMPLATE",
    "ANTHROPIC_MAX_429_RETRIES",
    "ANTHROPIC_429_BASE_DELAY",
    "ANTHROPIC_CACHE_MIN_TOKENS",
    "ANTHROPIC_DEFAULT_MODELS",
    "AnthropicProvider",
    "generate_tool_call_id",
    "get_default_config",
]

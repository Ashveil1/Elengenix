"""elengenix.providers.gemini — Google Gemini LLM provider adapter (Python port).

Port of PentAGI's ``backend/pkg/providers/gemini/gemini.go``. The adapter
talks to Google's Generative Language API at
``https://generativelanguage.googleapis.com`` via the
``google-generativeai`` Python SDK, and implements the full
:class:`~elengenix.providers.base.Provider` protocol.

Key features ported from the Go original
-----------------------------------------
* **Default model** — ``gemini-2.5-flash`` (PentAGI's
  ``GeminiAgentModel``). Also supports ``gemini-2.5-pro``,
  ``gemini-2.0-flash``, ``gemini-1.5-pro``, etc.
* **Tool-call ID template** — ``{r:8:x}`` (8 random hex chars, no
  prefix). Gemini emits short 8-char hex IDs.
* **Critical thought-signature contract** — every ``FunctionCall`` in
  the current turn MUST carry a ``thought_signature`` field returned by
  the API on the preceding ``FunctionResponse`` turn. The
  :meth:`GeminiProvider.preserve_thought_signature` helper captures
  these signatures; :meth:`_convert_chain` re-attaches them on
  subsequent turns. Without this, multi-turn tool-call flows fail with
  ``INVALID_ARGUMENT: thought_signature is required``.
* **Cache strategy** — Gemini supports both explicit and implicit
  caching:

  - **Explicit cache** — pre-populate a 32K-token context cache via
    ``CachedContent`` and reference it by ID. 75% discount on cached
    input tokens.
  - **Implicit cache** — Gemini automatically caches the most-recent
    4K tokens of identical prefix. 75% discount. No setup required.

  The provider does NOT manage explicit caches (that's a separate
  concern); it relies on implicit caching by default. The
  :data:`GEMINI_IMPLICIT_CACHE_THRESHOLD_TOKENS` constant exposes the
  4K threshold for documentation / observability.

* **API key transport** — Gemini uses ``x-goog-api-key`` header (not
  Bearer). The ``google-generativeai`` SDK handles this when given
  ``api_key=``; we just pass it through.

The ``google-generativeai`` SDK is imported lazily inside
:meth:`GeminiProvider._get_client` so that environments without the
SDK installed can still import this module.
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
)

logger = logging.getLogger("elengenix.providers.gemini")

# ---------------------------------------------------------------------------
# Constants — ported from gemini.go
# ---------------------------------------------------------------------------

#: Default Gemini API base URL. Overridable via ``GEMINI_SERVER_URL``.
GEMINI_DEFAULT_SERVER_URL: str = "https://generativelanguage.googleapis.com"

#: Default Gemini model. PentAGI's ``GeminiAgentModel`` constant.
GEMINI_DEFAULT_MODEL: str = "gemini-2.5-flash"

#: Gemini tool-call ID template. ``{r:8:x}`` = 8 random lowercase hex
#: chars. Matches the format Gemini's server generates.
GEMINI_TOOL_CALL_ID_TEMPLATE: str = "{r:8:x}"

#: 429 retry policy.
GEMINI_MAX_429_RETRIES: int = 10
GEMINI_429_BASE_DELAY: float = 5.0

#: Cache thresholds — per Gemini docs (2024-Q4):
#:   explicit cache: minimum 32K tokens
#:   implicit cache: most-recent 4K tokens (automatic, no setup required)
#:   cache discount: 75% off cached input tokens
GEMINI_EXPLICIT_CACHE_MIN_TOKENS: int = 32_768
GEMINI_IMPLICIT_CACHE_THRESHOLD_TOKENS: int = 4_096
GEMINI_CACHE_DISCOUNT_FRACTION: float = 0.75


# ---------------------------------------------------------------------------
# Tool-call ID generator
# ---------------------------------------------------------------------------


_HEX_ALPHABET: str = "0123456789abcdef"


def generate_tool_call_id() -> str:
    """Generate a Gemini-shaped tool-call ID.

    Format: ``<8 lowercase hex chars>`` (no prefix). Matches the format
    Gemini's server generates so orchestrator-synthesised IDs are
    indistinguishable.
    """
    return "".join(secrets.choice(_HEX_ALPHABET) for _ in range(8))


# ---------------------------------------------------------------------------
# Default pricing — USD per 1M tokens (Google public pricing)
# ---------------------------------------------------------------------------

_GEMINI_25_FLASH_PRICE = PriceInfo(input=0.30, output=2.50, cache_read=0.075)
_GEMINI_25_PRO_PRICE = PriceInfo(input=1.25, output=10.00, cache_read=0.3125)


#: Default Gemini model catalog — ported from gemini/models.yml.
GEMINI_DEFAULT_MODELS: List[ModelConfig] = [
    ModelConfig(
        name="gemini-2.5-flash",
        description=(
            "Gemini 2.5 Flash - Cost-effective hybrid model with thinking "
            "support. 1M context. Implicit caching (4K threshold). Best "
            "default for agent workloads."
        ),
        thinking=True,
        price=_GEMINI_25_FLASH_PRICE,
    ),
    ModelConfig(
        name="gemini-2.5-pro",
        description=(
            "Gemini 2.5 Pro - Flagship model. 2M context, deeper reasoning. "
            "Best for generator/refiner/adviser slots."
        ),
        thinking=True,
        price=_GEMINI_25_PRO_PRICE,
    ),
]


# ---------------------------------------------------------------------------
# Default provider config (port of gemini/config.yml)
# ---------------------------------------------------------------------------


def _agent(
    model: str,
    *,
    temperature: float = 1.0,
    max_tokens: int = 4000,
    json_mode: bool = False,
    price: PriceInfo | None = None,
) -> AgentConfig:
    """Build a Gemini :class:`AgentConfig`.

    Gemini doesn't have explicit thinking controls (thinking is always
    enabled on hybrid models); the per-agent config focuses on
    temperature / max_tokens. ``response_mime_type`` can be set via
    ``extra_body`` to force JSON-mode.
    """
    extra_body: dict[str, Any] = {}
    if json_mode:
        extra_body["response_mime_type"] = "application/json"
    agent = AgentConfig(
        model=model,
        temperature=temperature,
        n=1,
        max_tokens=max_tokens,
        extra_body=extra_body if extra_body else None,
        price=price,
    )
    return agent


def get_default_config() -> ProviderConfig:
    """Return the default Gemini :class:`ProviderConfig`.

    Ported from ``gemini/config.yml``. Strategy:
    * ``gemini-2.5-flash`` for all slots by default (cost-effective).
    * ``gemini-2.5-pro`` for generator/refiner/adviser (deeper reasoning).
    """
    cfg = ProviderConfig()
    cfg.simple = _agent(
        "gemini-2.5-flash",
        temperature=1.0, max_tokens=8192,
        price=_GEMINI_25_FLASH_PRICE,
    )
    cfg.simple_json = _agent(
        "gemini-2.5-flash",
        temperature=1.0, max_tokens=4096, json_mode=True,
        price=_GEMINI_25_FLASH_PRICE,
    )
    cfg.primary_agent = _agent(
        "gemini-2.5-flash",
        temperature=1.0, max_tokens=16384,
        price=_GEMINI_25_FLASH_PRICE,
    )
    cfg.assistant = _agent(
        "gemini-2.5-flash",
        temperature=1.0, max_tokens=16384,
        price=_GEMINI_25_FLASH_PRICE,
    )
    cfg.generator = _agent(
        "gemini-2.5-pro",
        temperature=1.0, max_tokens=32768,
        price=_GEMINI_25_PRO_PRICE,
    )
    cfg.refiner = _agent(
        "gemini-2.5-pro",
        temperature=1.0, max_tokens=32768,
        price=_GEMINI_25_PRO_PRICE,
    )
    cfg.adviser = _agent(
        "gemini-2.5-pro",
        temperature=1.0, max_tokens=16384,
        price=_GEMINI_25_PRO_PRICE,
    )
    cfg.reflector = _agent(
        "gemini-2.5-flash",
        temperature=0.7, max_tokens=4096,
        price=_GEMINI_25_FLASH_PRICE,
    )
    cfg.searcher = _agent(
        "gemini-2.5-flash",
        temperature=0.7, max_tokens=4096,
        price=_GEMINI_25_FLASH_PRICE,
    )
    cfg.enricher = _agent(
        "gemini-2.5-flash",
        temperature=0.7, max_tokens=4096,
        price=_GEMINI_25_FLASH_PRICE,
    )
    cfg.coder = _agent(
        "gemini-2.5-flash",
        temperature=1.0, max_tokens=20480,
        price=_GEMINI_25_FLASH_PRICE,
    )
    cfg.installer = _agent(
        "gemini-2.5-flash",
        temperature=1.0, max_tokens=16384,
        price=_GEMINI_25_FLASH_PRICE,
    )
    cfg.pentester = _agent(
        "gemini-2.5-flash",
        temperature=1.0, max_tokens=16384,
        price=_GEMINI_25_FLASH_PRICE,
    )
    return cfg


# ---------------------------------------------------------------------------
# GeminiProvider
# ---------------------------------------------------------------------------


class _GeminiTooManyRequests(Exception):
    """Internal sentinel raised to trigger tenacity 429 retry."""


def _is_too_many_requests(exc: BaseException) -> bool:
    """Return ``True`` if ``exc`` represents an HTTP 429 / throttling
    error. The ``google.api_core.exceptions`` package raises
    ``ResourceExhausted`` on 429s."""
    if exc.__class__.__name__ in ("ResourceExhausted", "RateLimitError"):
        return True
    err_str = str(exc).lower()
    if "429" in err_str:
        return True
    if "rate limit" in err_str or "too many requests" in err_str:
        return True
    if "resource_exhausted" in err_str:
        return True
    return False


class GeminiProvider:
    """Google Gemini adapter (Python port of ``geminiProvider``).

    Construction is lazy — the ``google.generativeai`` SDK is imported
    inside :meth:`_get_client` so importing this module never requires
    it to be installed. The API key is read from ``GEMINI_API_KEY`` (or
    the alias ``GOOGLE_API_KEY``); the base URL defaults to
    :data:`GEMINI_DEFAULT_SERVER_URL` and is overridable via
    ``GEMINI_SERVER_URL``.

    Gemini's contract requires every ``FunctionCall`` in the current
    turn to carry a ``thought_signature`` field. The
    :meth:`preserve_thought_signature` helper captures these signatures
    from the API response's ``thought_signatures`` map; the per-agent
    YAML config doesn't need to set anything extra (thinking is always
    enabled on hybrid Gemini 2.5+ models).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        provider_config: Optional[ProviderConfig] = None,
        models: Optional[List[ModelConfig]] = None,
        provider_name: str = "gemini",
        request_timeout: float = 120.0,
        preserve_thought_signatures: bool = True,
    ) -> None:
        self._api_key = api_key or (
            os.environ.get("GEMINI_API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
            or ""
        )
        if not self._api_key:
            raise RuntimeError(
                "missing GEMINI_API_KEY (or GOOGLE_API_KEY) environment "
                "variable (set it or pass api_key=... to GeminiProvider)"
            )
        self._base_url = base_url or (
            os.environ.get("GEMINI_SERVER_URL")
            or GEMINI_DEFAULT_SERVER_URL
        )
        self._provider_name = provider_name
        self._provider_config: ProviderConfig = (
            provider_config if provider_config is not None
            else get_default_config()
        )
        self._models: List[ModelConfig] = (
            models if models is not None
            else list(GEMINI_DEFAULT_MODELS)
        )
        self._request_timeout = request_timeout
        self._preserve_thought_signatures = preserve_thought_signatures
        self._client: Any = None  # google.generativeai module — lazy

    # ------------------------------------------------------------------
    # Lazy SDK client
    # ------------------------------------------------------------------

    def _get_client(self) -> Any:
        """Lazily configure (and cache) the ``google.generativeai`` SDK.
        Returns the configured module (callers use
        ``genai.GenerativeModel(model)`` to obtain a model handle)."""
        if self._client is not None:
            return self._client
        try:
            import google.generativeai as genai  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "google-generativeai is required for the Gemini provider; "
                "install with `pip install google-generativeai>=0.3.0`"
            ) from exc
        genai.configure(
            api_key=self._api_key,
            client_options={"api_endpoint": self._base_url},
        )
        self._client = genai
        return self._client

    # ------------------------------------------------------------------
    # Provider Protocol implementation
    # ------------------------------------------------------------------

    def type(self) -> ProviderType:
        return ProviderType.GEMINI

    def name(self) -> str:
        return self._provider_name

    def model(self, opt: ProviderOptionsType) -> str:
        """Return the model name configured for ``opt``."""
        agent = self._provider_config.get_agent_config(opt)
        if agent is not None and agent.model:
            return agent.model
        return GEMINI_DEFAULT_MODEL

    def model_with_prefix(self, opt: ProviderOptionsType) -> str:
        """Gemini provider doesn't need prefix support (passthrough mode
        in LiteLLM). Returns the bare model name."""
        return self.model(opt)

    def get_provider_config(self) -> ProviderConfig:
        return self._provider_config

    def get_models(self) -> ModelsConfig:
        return ModelsConfig(models=list(self._models))

    def get_price_info(self, opt: ProviderOptionsType) -> Optional[PriceInfo]:
        return self._provider_config.get_price_info(opt)

    def get_tool_call_id_template(self) -> str:
        return GEMINI_TOOL_CALL_ID_TEMPLATE

    # ------------------------------------------------------------------
    # Gemini-specific helpers
    # ------------------------------------------------------------------

    @staticmethod
    def preserve_thought_signature(
        tool_call: ToolCall,
        thought_signature: str,
    ) -> ToolCall:
        """Attach a ``thought_signature`` to a :class:`ToolCall` so that
        the next request re-serializes it on the FunctionCall block.

        Gemini's contract requires every ``FunctionCall`` in the
        current turn to carry a ``thought_signature`` field. The
        signature is returned by the API on the preceding turn (in the
        ``FunctionCall`` block's ``thought_signature`` key). The caller
        must capture it and re-attach via this helper when building the
        next request.

        .. code-block:: python

            resp = provider.call_with_tools(opt, chain, tools)
            choice = resp.choices[0]
            sigs = choice.generation_info.get("thought_signatures", {})
            for tc in choice.tool_calls:
                sig = sigs.get(tc.id)
                if sig:
                    tc = GeminiProvider.preserve_thought_signature(tc, sig)
            chain = [*chain, assistant_msg, tool_result_msg]
            resp = provider.call_with_tools(opt, chain, tools)
        """
        if not thought_signature:
            return tool_call
        new_tc = tool_call.model_copy(deep=True)
        if new_tc.model_extra is None:
            new_tc.model_extra = {}
        new_tc.model_extra["thought_signature"] = thought_signature
        return new_tc

    def _convert_chain(
        self, chain: List[MessageContent]
    ) -> dict:
        """Convert a list of :class:`MessageContent` to Gemini's
        request shape: ``{system_instruction: str, contents: [...]}``.

        Gemini uses ``system_instruction`` (not a message role) and a
        flat ``contents`` list where each entry has ``role`` ('user' or
        'model') and ``parts`` (list of typed parts: ``text``,
        ``function_call``, ``function_response``, ``thought_signature``).
        """
        system_text: List[str] = []
        contents: List[dict] = []

        for msg in chain:
            if msg.role in ("system", "developer"):
                for part in msg.parts:
                    if isinstance(part, TextPart) and part.text:
                        system_text.append(part.text)
                continue

            role = "model" if msg.role == "assistant" else "user"
            parts: List[dict] = []
            for part in msg.parts:
                if isinstance(part, TextPart) and part.text:
                    parts.append({"text": part.text})
                elif isinstance(part, ToolCall):
                    fc: dict = {
                        "function_call": {
                            "name": part.name,
                            "args": _safe_json_loads(part.arguments),
                        }
                    }
                    # Attach thought_signature if present (required for
                    # multi-turn tool-call flows on Gemini 2.5+).
                    if (
                        self._preserve_thought_signatures
                        and part.model_extra
                    ):
                        sig = part.model_extra.get("thought_signature")
                        if sig:
                            fc["thought_signature"] = sig
                    parts.append(fc)
                elif isinstance(part, ToolCallResponse):
                    parts.append({
                        "function_response": {
                            "name": part.name or "",
                            "response": _safe_json_loads(part.content or "{}"),
                            "id": part.tool_call_id,
                        }
                    })
            if parts:
                contents.append({"role": role, "parts": parts})

        return {
            "system_instruction": (
                "\n\n".join(system_text) if system_text else None
            ),
            "contents": contents,
        }

    @staticmethod
    def _convert_tools(tools: List[dict]) -> List[dict]:
        """Convert OpenAI-shape tools to Gemini's ``tools`` format.
        Gemini wraps function declarations in a ``function_declarations``
        list inside a single ``tools`` entry."""
        func_decls: List[dict] = []
        for t in tools:
            fn = t.get("function", t)
            schema = dict(
                fn.get("parameters") or {"type": "object", "properties": {}}
            )
            # Gemini rejects $schema and additionalProperties in some
            # SDK versions; strip defensively.
            schema.pop("$schema", None)
            schema.pop("additionalProperties", None)
            func_decls.append({
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "parameters": schema,
            })
        return [{"function_declarations": func_decls}]

    def _build_request(
        self,
        model: str,
        agent: Optional[AgentConfig],
        converted: dict,
        tools: Optional[List[dict]],
        stream: bool = False,
    ) -> dict:
        """Build the kwargs dict for ``GenerativeModel.generate_content()``."""
        kwargs: dict = {
            "contents": converted["contents"],
        }
        if converted.get("system_instruction"):
            kwargs["system_instruction"] = converted["system_instruction"]
        gen_config: dict = {}
        if agent is not None:
            if agent.temperature is not None:
                gen_config["temperature"] = agent.temperature
            if agent.top_p is not None:
                gen_config["top_p"] = agent.top_p
            if agent.n is not None:
                gen_config["candidate_count"] = agent.n
            if agent.max_tokens is not None:
                gen_config["max_output_tokens"] = agent.max_tokens
            if agent.extra_body:
                for k, v in agent.extra_body.items():
                    if k not in gen_config:
                        gen_config[k] = v
        if gen_config:
            kwargs["generation_config"] = gen_config
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
            raise RuntimeError("empty response from Gemini")
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
        request = self._build_request(
            model, agent, converted, tools, stream=(stream_cb is not None)
        )
        genai = self._get_client()
        gen_model = genai.GenerativeModel(model)
        if stream_cb is not None:
            return self._invoke_streaming(gen_model, request, stream_cb, opt)
        return self._invoke_sync(gen_model, request, opt)

    def _invoke_sync(
        self, gen_model: Any, request: dict, opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Call ``generate_content`` with 429 retry."""
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
            stop=stop_after_attempt(GEMINI_MAX_429_RETRIES),
            wait=wait_fixed(GEMINI_429_BASE_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_GeminiTooManyRequests),
            reraise=True,
        )
        response: Any = None
        for attempt in retrying:
            with attempt:
                try:
                    response = gen_model.generate_content(**request)
                except Exception as exc:
                    if _is_too_many_requests(exc):
                        logger.warning(
                            "gemini 429 on slot %s, retrying (attempt %d/%d)",
                            opt.value,
                            attempt.retry_state.attempt_number,
                            GEMINI_MAX_429_RETRIES,
                        )
                        raise _GeminiTooManyRequests(str(exc)) from exc
                    raise
        return self._parse_response(response, opt)

    def _invoke_streaming(
        self, gen_model: Any, request: dict,
        stream_cb: StreamingCallback, opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Call ``generate_content`` (stream=True) with 429 retry."""
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
            stop=stop_after_attempt(GEMINI_MAX_429_RETRIES),
            wait=wait_fixed(GEMINI_429_BASE_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_GeminiTooManyRequests),
            reraise=True,
        )
        stream: Any = None
        for attempt in retrying:
            with attempt:
                try:
                    stream = gen_model.generate_content(**{**request, "stream": True})
                except Exception as exc:
                    if _is_too_many_requests(exc):
                        logger.warning(
                            "gemini 429 (stream) on slot %s, retrying "
                            "(attempt %d/%d)",
                            opt.value,
                            attempt.retry_state.attempt_number,
                            GEMINI_MAX_429_RETRIES,
                        )
                        raise _GeminiTooManyRequests(str(exc)) from exc
                    raise
        return self._parse_stream_response(stream, opt, stream_cb)

    def _parse_response(
        self, response: Any, opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Parse a ``google.generativeai`` ``GenerateContentResponse``
        into our :class:`ContentResponse`. Captures thought_signature
        fields for multi-turn tool-call flows."""
        text_parts: List[str] = []
        tool_calls: List[ToolCall] = []
        thought_sigs: dict = {}

        candidates = getattr(response, "candidates", None) or []
        finish_reason = ""
        for cand in candidates:
            content = getattr(cand, "content", None)
            cand_parts = getattr(content, "parts", None) if content else None
            cand_finish = getattr(cand, "finish_reason", None)
            if cand_finish:
                finish_reason = str(cand_finish)
            for p in cand_parts or []:
                p_dict = (
                    p.to_dict() if hasattr(p, "to_dict")
                    else (vars(p) if hasattr(p, "__dict__") else p)
                )
                if not isinstance(p_dict, dict):
                    continue
                if "text" in p_dict and p_dict["text"]:
                    text_parts.append(p_dict["text"])
                elif "function_call" in p_dict:
                    fc = p_dict["function_call"] or {}
                    name = fc.get("name", "")
                    args = fc.get("args", {})
                    args_str = json.dumps(args) if args else "{}"
                    tc = ToolCall(
                        id=fc.get("id", "") or generate_tool_call_id(),
                        name=name,
                        arguments=args_str,
                        type="function_call",
                    )
                    # Capture thought_signature if present
                    sig = p_dict.get("thought_signature")
                    if sig and self._preserve_thought_signatures:
                        thought_sigs[tc.id] = sig
                        tc.model_extra = {"thought_signature": sig}
                    tool_calls.append(tc)

        gen_info: dict = {}
        if thought_sigs:
            gen_info["thought_signatures"] = thought_sigs

        choice = Choice(
            content="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=finish_reason,
            generation_info=gen_info,
        )

        # Usage
        raw_usage = getattr(response, "usage_metadata", None)
        usage = CallUsage()
        if raw_usage is not None:
            usage = CallUsage(
                input_tokens=int(
                    getattr(raw_usage, "prompt_token_count", 0) or 0
                ),
                output_tokens=int(
                    getattr(raw_usage, "candidates_token_count", 0) or 0
                ),
                cache_read_tokens=int(
                    getattr(raw_usage, "cached_content_token_count", 0) or 0
                ),
            )
        usage.update_cost(self.get_price_info(opt))

        return ContentResponse(choices=[choice], usage=usage)

    def _parse_stream_response(
        self, stream: Any, opt: ProviderOptionsType,
        stream_cb: StreamingCallback,
    ) -> ContentResponse:
        """Translate a Gemini streaming response."""
        text_parts: List[str] = []
        tool_calls: List[ToolCall] = []
        thought_sigs: dict = {}
        finish_reason = ""
        usage_dict: dict = {}

        for chunk in stream or []:
            for cand in getattr(chunk, "candidates", []) or []:
                content = getattr(cand, "content", None)
                for p in getattr(content, "parts", []) if content else []:
                    p_dict = (
                        p.to_dict() if hasattr(p, "to_dict")
                        else (vars(p) if hasattr(p, "__dict__") else p)
                    )
                    if not isinstance(p_dict, dict):
                        continue
                    if "text" in p_dict and p_dict["text"]:
                        text_parts.append(p_dict["text"])
                        stream_cb(p_dict["text"])
                    elif "function_call" in p_dict:
                        fc = p_dict["function_call"] or {}
                        name = fc.get("name", "")
                        args = fc.get("args", {})
                        args_str = json.dumps(args) if args else "{}"
                        tc = ToolCall(
                            id=fc.get("id", "") or generate_tool_call_id(),
                            name=name, arguments=args_str,
                            type="function_call",
                        )
                        sig = p_dict.get("thought_signature")
                        if sig and self._preserve_thought_signatures:
                            thought_sigs[tc.id] = sig
                            tc.model_extra = {"thought_signature": sig}
                        tool_calls.append(tc)
                cand_finish = getattr(cand, "finish_reason", None)
                if cand_finish:
                    finish_reason = str(cand_finish)
            chunk_usage = getattr(chunk, "usage_metadata", None)
            if chunk_usage is not None:
                usage_dict = {
                    "prompt_token_count": getattr(chunk_usage, "prompt_token_count", 0) or 0,
                    "candidates_token_count": getattr(chunk_usage, "candidates_token_count", 0) or 0,
                    "cached_content_token_count": getattr(chunk_usage, "cached_content_token_count", 0) or 0,
                }

        gen_info: dict = {"streamed": True}
        if thought_sigs:
            gen_info["thought_signatures"] = thought_sigs

        choice = Choice(
            content="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=finish_reason,
            generation_info=gen_info,
        )
        usage = CallUsage(
            input_tokens=int(usage_dict.get("prompt_token_count", 0) or 0),
            output_tokens=int(usage_dict.get("candidates_token_count", 0) or 0),
            cache_read_tokens=int(
                usage_dict.get("cached_content_token_count", 0) or 0
            ),
        )
        usage.update_cost(self.get_price_info(opt))
        return ContentResponse(choices=[choice], usage=usage)


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
    "GEMINI_DEFAULT_SERVER_URL",
    "GEMINI_DEFAULT_MODEL",
    "GEMINI_TOOL_CALL_ID_TEMPLATE",
    "GEMINI_MAX_429_RETRIES",
    "GEMINI_429_BASE_DELAY",
    "GEMINI_EXPLICIT_CACHE_MIN_TOKENS",
    "GEMINI_IMPLICIT_CACHE_THRESHOLD_TOKENS",
    "GEMINI_CACHE_DISCOUNT_FRACTION",
    "GEMINI_DEFAULT_MODELS",
    "GeminiProvider",
    "generate_tool_call_id",
    "get_default_config",
]

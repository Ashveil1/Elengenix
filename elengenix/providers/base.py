"""elengenix.providers.base — LLM provider abstraction layer.

This module is the Python port of PentAGI's
``backend/pkg/providers/provider/provider.go`` and
``backend/pkg/providers/pconfig/config.go`` (Go originals by vxcontrol).
It defines the universal ``Provider`` Protocol implemented by every concrete
adapter (OpenAI, Anthropic, Gemini, Bedrock, Ollama, Custom, DeepSeek, GLM,
Kimi, Qwen), the Pydantic v2 data models that describe per-agent
configuration, and two shared helpers used by all Bedrock-family adapters:

* :func:`load_models_from_http` — fetch a model catalog from an
  OpenAI-compatible ``/models`` endpoint, optionally filtering by a
  ``prefix/`` namespace (port of ``litellm.go::LoadModelsFromHTTP``).
* :func:`clean_tool_schemas` — strip the ``$schema`` metadata field from
  JSON-Schema tool definitions; AWS Bedrock's Converse API rejects schemas
  that carry it (``ValidationException``).

Design notes
------------
* All heavy SDK imports (``boto3``, ``openai``, ``anthropic``,
  ``google.generativeai``) are performed lazily inside concrete provider
  ``__init__`` methods, so importing :mod:`elengenix.providers.base` never
  requires those packages to be installed.
* Pydantic v2 is used for every data model. ``model_config`` is set to
  ``extra="allow"`` on ``AgentConfig`` so provider-specific knobs (e.g.
  DeepSeek ``extra_body.thinking.type``) survive a round-trip.
* The :class:`Provider` Protocol mirrors the Go interface 1:1; the only
  intentional rename is ``Call`` -> ``call`` / ``CallEx`` -> ``call_ex`` /
  ``CallWithTools`` -> ``call_with_tools`` to satisfy PEP 8.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Protocol, Union, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("elengenix.providers.base")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ProviderType(str, Enum):
    """The 10 LLM provider types supported by Elengenix.

    Mirrors PentAGI's ``provider.ProviderType`` enum (``provider.go``).
    Values are lowercase short names that match the YAML config keys and the
    GraphQL ``ProviderType`` enum, so they round-trip cleanly through any
    persistence layer.
    """

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    BEDROCK = "bedrock"
    OLLAMA = "ollama"
    CUSTOM = "custom"
    DEEPSEEK = "deepseek"
    GLM = "glm"
    KIMI = "kimi"
    QWEN = "qwen"


class ProviderOptionsType(str, Enum):
    """Per-agent slot identifier (mirrors PentAGI's ``ProviderOptionsType``).

    A provider's :class:`ProviderConfig` exposes one optional
    :class:`AgentConfig` per slot; the slot name doubles as the agent role
    inside the orchestrator (``primary_agent``, ``assistant``, …).
    """

    SIMPLE = "simple"
    SIMPLE_JSON = "simple_json"
    PRIMARY_AGENT = "primary_agent"
    ASSISTANT = "assistant"
    GENERATOR = "generator"
    REFINER = "refiner"
    ADVISER = "adviser"
    REFLECTOR = "reflector"
    SEARCHER = "searcher"
    ENRICHER = "enricher"
    CODER = "coder"
    INSTALLER = "installer"
    PENTESTER = "pentester"


#: Tuple of all 13 agent slots in canonical order — ported from
#: ``pconfig.AllAgentTypes``.
ALL_AGENT_TYPES: tuple[ProviderOptionsType, ...] = (
    ProviderOptionsType.SIMPLE,
    ProviderOptionsType.SIMPLE_JSON,
    ProviderOptionsType.PRIMARY_AGENT,
    ProviderOptionsType.ASSISTANT,
    ProviderOptionsType.GENERATOR,
    ProviderOptionsType.REFINER,
    ProviderOptionsType.ADVISER,
    ProviderOptionsType.REFLECTOR,
    ProviderOptionsType.SEARCHER,
    ProviderOptionsType.ENRICHER,
    ProviderOptionsType.CODER,
    ProviderOptionsType.INSTALLER,
    ProviderOptionsType.PENTESTER,
)


class ReasoningEffort(str, Enum):
    """Reasoning-effort selector (mirrors ``llms.ReasoningEffort``).

    Used by reasoning-capable models (Claude 4.x, GPT-OSS, GLM, DeepSeek
    reasoner, …) to trade latency for thinking depth. ``NONE`` lets the
    caller pass ``max_tokens`` instead of a qualitative effort level.
    """

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Pydantic data models
# ---------------------------------------------------------------------------


class ReasoningConfig(BaseModel):
    """Reasoning configuration for an agent slot.

    Ported from ``pconfig.ReasoningConfig``. When ``effort`` is anything
    other than ``NONE``, the provider passes a qualitative effort level to
    the upstream API. When ``effort == NONE`` and ``max_tokens > 0``, the
    provider passes an explicit thinking-token budget instead (DeepSeek /
    Claude 4 extended-thinking style).
    """

    effort: ReasoningEffort = ReasoningEffort.NONE
    max_tokens: int = 0

    model_config = ConfigDict(extra="allow")


class PriceInfo(BaseModel):
    """Per-million-token pricing for a model or agent slot.

    All values are USD per 1,000,000 tokens. ``cache_read`` /
    ``cache_write`` are discounted rates applied to prompt-cache hits and
    cache-creation writes respectively (Anthropic prompt caching,
    DeepSeek context caching).
    """

    input: float = 0.0
    output: float = 0.0
    cache_read: float = 0.0
    cache_write: float = 0.0

    model_config = ConfigDict(extra="allow")


class AgentConfig(BaseModel):
    """Configuration for a single agent slot.

    Ported from ``pconfig.AgentConfig`` (``config.go``). ``extra="allow"``
    is set so provider-specific knobs (e.g. ``top_k``, ``min_p``,
    ``response_mime_type``) survive a YAML round-trip even when this model
    doesn't declare them explicitly. The ``extra_body`` dict is forwarded
    verbatim to OpenAI-compatible APIs to control features like
    ``thinking.type`` (DeepSeek / GLM / Kimi).
    """

    model: str = ""
    temperature: float | None = None
    top_p: float | None = None
    top_k: int | None = None
    min_p: float | None = None
    n: int | None = None
    max_tokens: int | None = None
    min_length: int | None = None
    max_length: int | None = None
    repetition_penalty: float | None = None
    frequency_penalty: float | None = None
    presence_penalty: float | None = None
    # Aliased to ``json`` in the wire format (YAML / JSON) so configs port
    # verbatim from PentAGI, while avoiding the Pydantic v2 ``BaseModel.json``
    # method shadow warning on the Python side.
    json_mode: bool = Field(default=False, alias="json")
    response_mime_type: str | None = None
    reasoning: ReasoningConfig | None = Field(default=None)
    price: PriceInfo | None = None
    extra_body: dict[str, Any] | None = None

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class ProviderConfig(BaseModel):
    """Per-provider configuration covering all 13 agent slots.

    Ported from ``pconfig.ProviderConfig``. Each slot is optional — when a
    slot is ``None`` the provider falls back to its built-in default agent
    config (see each adapter's ``DEFAULT_CONFIG`` constant).
    """

    simple: AgentConfig | None = None
    simple_json: AgentConfig | None = None
    primary_agent: AgentConfig | None = None
    assistant: AgentConfig | None = None
    generator: AgentConfig | None = None
    refiner: AgentConfig | None = None
    adviser: AgentConfig | None = None
    reflector: AgentConfig | None = None
    searcher: AgentConfig | None = None
    enricher: AgentConfig | None = None
    coder: AgentConfig | None = None
    installer: AgentConfig | None = None
    pentester: AgentConfig | None = None

    model_config = ConfigDict(extra="allow")

    def get_agent_config(self, opt: ProviderOptionsType) -> AgentConfig | None:
        """Return the :class:`AgentConfig` for ``opt`` or ``None``."""
        return getattr(self, opt.value, None)

    def get_price_info(self, opt: ProviderOptionsType) -> PriceInfo | None:
        """Return the :class:`PriceInfo` for ``opt`` or ``None``.

        Convenience wrapper used by every provider's ``get_price_info``
        implementation — mirrors PentAGI's
        ``ProviderConfig.GetPriceInfoForType``.
        """
        agent = self.get_agent_config(opt)
        return agent.price if agent is not None else None


class ModelConfig(BaseModel):
    """Single entry in a provider's model catalog.

    Ported from ``pconfig.ModelConfig``. ``release_date`` is stored as a
    ISO-8601 date string (YYYY-MM-DD) so the model serialises cleanly to
    YAML/JSON without dragging a ``datetime`` dependency into the schema.
    """

    name: str
    description: str | None = None
    thinking: bool | None = None
    release_date: str | None = None
    price: PriceInfo | None = None

    model_config = ConfigDict(extra="allow")


class ModelsConfig(BaseModel):
    """A provider's full model catalog.

    Ported from ``pconfig.ModelsConfig`` (which is just ``[]ModelConfig``
    in Go). Wrapped in a Pydantic model so it can be (de)serialised with
    ``model_validate_json`` / ``model_dump_json`` and embedded in API
    responses.
    """

    models: list[ModelConfig] = Field(default_factory=list)

    def __iter__(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        return iter(self.models)

    def __len__(self) -> int:
        return len(self.models)


# ---------------------------------------------------------------------------
# Message / response models — used as the wire format for Provider.call_ex
# and Provider.call_with_tools. These are deliberately minimal and
# provider-agnostic so adapters only need to translate to/from their
# native SDK shape.
# ---------------------------------------------------------------------------


class TextPart(BaseModel):
    """A plain-text content part (mirrors ``llms.TextContent``)."""

    text: str
    type: str = "text"

    model_config = ConfigDict(extra="allow")


class ToolCall(BaseModel):
    """A tool-call request emitted by the assistant.

    Mirrors ``llms.ToolCall`` / OpenAI ``chat.completions.tool_calls``.
    ``arguments`` is the raw JSON-encoded argument string (preserved
    verbatim so the tool-call fixer can repair malformed payloads).
    """

    id: str = ""
    name: str = ""
    arguments: str = "{}"
    type: str = "tool_call"

    model_config = ConfigDict(extra="allow")


class ToolCallResponse(BaseModel):
    """A tool-result message returned to the LLM.

    Mirrors ``llms.ToolCallResponse``. ``tool_call_id`` ties the response
    back to the originating :class:`ToolCall.id` (required by OpenAI and
    Bedrock Converse API).
    """

    name: str = ""
    tool_call_id: str = ""
    content: str = ""
    type: str = "tool_result"

    model_config = ConfigDict(extra="allow")


#: Union of all valid content parts for a :class:`MessageContent`.
MessagePart = Union[TextPart, ToolCall, ToolCallResponse]


class MessageContent(BaseModel):
    """A single chat message in the agent chain.

    Mirrors PentAGI's ``llms.MessageContent``. ``role`` is one of
    ``"system"``, ``"user"``, ``"assistant"``, ``"tool"``. ``parts`` is a
    heterogeneous list of :data:`MessagePart` — adapters are responsible
    for translating this to their provider-native shape (e.g. OpenAI's
    flat ``content``/``tool_calls`` split, Bedrock's ``contentBlocks``).
    """

    role: str
    parts: list[MessagePart] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class CallUsage(BaseModel):
    """Token-usage accounting for a single LLM call.

    Ported from ``pconfig.CallUsage``. ``input_tokens`` /
    ``output_tokens`` are the raw token counts; ``cache_read_tokens`` and
    ``cache_write_tokens`` track prompt-cache hits and writes. Cost fields
    are in USD and computed by :meth:`update_cost` from the agent slot's
    :class:`PriceInfo`.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    input_cost: float = 0.0
    output_cost: float = 0.0

    model_config = ConfigDict(extra="allow")

    def merge(self, other: CallUsage) -> None:
        """Merge ``other`` into ``self`` (non-zero values win).

        Mirrors ``CallUsage.Merge``: used when a multi-choice response
        aggregates usage across N completions.
        """
        for field_name in (
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
        ):
            other_val = getattr(other, field_name)
            if other_val > 0:
                setattr(self, field_name, other_val)
        if other.input_cost > 0:
            self.input_cost = other.input_cost
        if other.output_cost > 0:
            self.output_cost = other.output_cost

    def update_cost(self, price: PriceInfo | None) -> None:
        """Compute ``input_cost`` / ``output_cost`` from ``price``.

        Ported from ``CallUsage.UpdateCost``. If the provider already
        populated cost (e.g. OpenRouter passes upstream inference cost
        directly), the existing values are kept. Otherwise:

        * When the price has no cache rates, the full input token count is
          billed at ``price.input``.
        * When cache rates are present, ``cache_read_tokens`` are billed
          at ``price.cache_read``, ``cache_write_tokens`` at
          ``price.cache_write``, and the remainder at ``price.input``.
        """
        if price is None:
            return
        if self.input_cost != 0.0 or self.output_cost != 0.0:
            return  # Provider already populated cost (e.g. OpenRouter).

        if price.cache_read == 0.0 and price.cache_write == 0.0:
            self.input_cost = self.input_tokens * price.input / 1_000_000
            self.output_cost = self.output_tokens * price.output / 1_000_000
            return

        uncached = max(self.input_tokens - self.cache_read_tokens, 0)
        cache_read_cost = self.cache_read_tokens * price.cache_read / 1_000_000
        cache_write_cost = self.cache_write_tokens * price.cache_write / 1_000_000
        self.input_cost = uncached * price.input / 1_000_000 + cache_read_cost + cache_write_cost
        self.output_cost = self.output_tokens * price.output / 1_000_000

    def is_zero(self) -> bool:
        """Return ``True`` if every field is zero (mirrors ``IsZero``)."""
        return (
            self.input_tokens == 0
            and self.output_tokens == 0
            and self.cache_read_tokens == 0
            and self.cache_write_tokens == 0
            and self.input_cost == 0.0
            and self.output_cost == 0.0
        )


class Choice(BaseModel):
    """A single completion choice (mirrors ``llms.Choice``)."""

    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    stop_reason: str = ""
    generation_info: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class ContentResponse(BaseModel):
    """Structured response from ``call_ex`` / ``call_with_tools``.

    Mirrors ``llms.ContentResponse``. ``choices`` always has at least one
    entry for a successful call (adapters raise on empty responses).
    ``usage`` is the aggregated :class:`CallUsage` across all choices.
    """

    choices: list[Choice] = Field(default_factory=list)
    usage: CallUsage = Field(default_factory=CallUsage)

    model_config = ConfigDict(extra="allow")


# ---------------------------------------------------------------------------
# Streaming callback type
# ---------------------------------------------------------------------------

#: Streaming callback signature (mirrors ``streaming.Callback``). Receives
#: a single chunk of text; the adapter is responsible for closing the
#: stream (e.g. by calling with an empty string or by raising).
StreamingCallback = Callable[[str], None]


# ---------------------------------------------------------------------------
# Provider Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Provider(Protocol):
    """Universal LLM provider protocol (mirrors ``provider.Provider``).

    Every concrete adapter implements this interface. Methods are sync by
    default to match the boto3 / openai SDK shape; async wrappers can be
    layered on top by callers that need them.
    """

    def type(self) -> ProviderType:
        """Return the provider type (e.g. ``ProviderType.BEDROCK``)."""
        ...

    def name(self) -> str:
        """Return the provider instance name (e.g. ``"bedrock"``)."""
        ...

    def model(self, opt: ProviderOptionsType) -> str:
        """Return the resolved model name for ``opt``."""
        ...

    def call(
        self,
        opt: ProviderOptionsType,
        prompt: str,
    ) -> str:
        """Single-prompt convenience wrapper (mirrors ``Call``)."""
        ...

    def call_ex(
        self,
        opt: ProviderOptionsType,
        chain: list[MessageContent],
        stream_cb: StreamingCallback | None = None,
    ) -> ContentResponse:
        """Multi-turn call with no new tools offered (mirrors ``CallEx``)."""
        ...

    def call_with_tools(
        self,
        opt: ProviderOptionsType,
        chain: list[MessageContent],
        tools: list[dict[str, Any]],
        stream_cb: StreamingCallback | None = None,
    ) -> ContentResponse:
        """Multi-turn call with explicit tools (mirrors ``CallWithTools``)."""
        ...

    def get_models(self) -> ModelsConfig:
        """Return the provider's full model catalog."""
        ...

    def get_price_info(self, opt: ProviderOptionsType) -> PriceInfo | None:
        """Return the :class:`PriceInfo` for ``opt``."""
        ...

    def get_tool_call_id_template(self) -> str:
        """Return the provider's tool-call ID template (e.g. ``"call_{r:24:b}"``).

        The template uses a ``{r:N:x|d|b}`` placeholder syntax where ``r``
        means "random", ``N`` is the character count, and the suffix is
        ``x`` (hex), ``d`` (decimal), or ``b`` (base62). Used by the
        orchestrator to generate provider-correct tool-call IDs when the
        upstream API doesn't return one (e.g. Anthropic via Bedrock).
        """
        ...


# ---------------------------------------------------------------------------
# Helpers — shared across all Bedrock-family adapters
# ---------------------------------------------------------------------------


def apply_model_prefix(model_name: str, prefix: str) -> str:
    """Prepend ``prefix/`` to ``model_name`` when ``prefix`` is non-empty.

    Ported from ``litellm.go::ApplyModelPrefix``. Used by OpenAI-compatible
    providers that sit behind a LiteLLM proxy with model namespacing.
    """
    if not prefix:
        return model_name
    return f"{prefix}/{model_name}"


def remove_model_prefix(model_name: str, prefix: str) -> str:
    """Strip ``prefix/`` from ``model_name`` when present.

    Ported from ``litellm.go::RemoveModelPrefix``. Inverse of
    :func:`apply_model_prefix`.
    """
    if not prefix:
        return model_name
    if model_name.startswith(f"{prefix}/"):
        return model_name[len(prefix) + 1 :]
    return model_name


def load_models_from_http(
    base_url: str,
    api_key: str = "",
    prefix: str = "",
    timeout: float = 3.0,
) -> list[ModelConfig]:
    """Fetch a model catalog from an OpenAI-compatible ``/models`` endpoint.

    Python port of ``litellm.go::LoadModelsFromHTTP``. The endpoint is
    expected to return either the full LiteLLM shape::

        {"data": [{"id": "...", "description": "...",
                   "supported_parameters": ["tools", "reasoning", ...],
                   "pricing": {"prompt": "0.001", "completion": "0.002"},
                   "created": 1700000000}, ...]}

    or the simplified OpenAI shape::

        {"data": [{"id": "..."}, ...]}

    When ``prefix`` is set, only models whose ``id`` starts with
    ``"prefix/"`` are returned and the prefix is stripped from each
    ``name``. Models that declare ``supported_parameters`` but omit both
    ``tools`` and ``structured_outputs`` are skipped — they cannot be used
    for tool-calling agent slots.

    Uses :mod:`urllib.request` so no extra HTTP dependency is required.
    """
    models_url = base_url.rstrip("/") + "/models"

    req = urllib.request.Request(models_url, method="GET")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            if resp.status != 200:
                raise RuntimeError(
                    f"unexpected status code from {models_url}: {resp.status}"
                )
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"failed to fetch models from {models_url}: {exc}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"failed to fetch models from {models_url}: {exc}") from exc

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"failed to parse models response: {exc}") from exc

    raw_models = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(raw_models, list):
        # Fallback: some endpoints return a bare list of {"id": ...}.
        if isinstance(payload, list):
            raw_models = payload
        else:
            raise RuntimeError("models response missing 'data' array")

    return _parse_models(raw_models, prefix)


def _parse_models(raw_models: list[Any], prefix: str) -> list[ModelConfig]:
    """Parse the ``data`` array returned by ``/models`` into ModelConfigs.

    Tolerates both the full LiteLLM shape (with ``supported_parameters`` /
    ``pricing`` / ``description`` / ``created``) and the simplified OpenAI
    shape (``id`` only). Ported from ``parseFullModels`` /
    ``parseFallbackModels``.
    """
    result: list[ModelConfig] = []
    for raw in raw_models:
        if not isinstance(raw, dict):
            continue
        model_id = raw.get("id")
        if not isinstance(model_id, str) or not model_id:
            continue

        # Prefix filtering — ported from parseFullModels.
        if prefix and not model_id.startswith(f"{prefix}/"):
            continue
        name = remove_model_prefix(model_id, prefix) if prefix else model_id

        # Skip models that explicitly declare supported_parameters but
        # lack both tools and structured_outputs (LiteLLM-style catalogs).
        supported_params = raw.get("supported_parameters")
        if isinstance(supported_params, list) and supported_params:
            if "tools" not in supported_params and "structured_outputs" not in supported_params:
                continue

        cfg = ModelConfig(name=name)

        description = raw.get("description")
        if isinstance(description, str) and description:
            cfg.description = description

        created = raw.get("created")
        if isinstance(created, (int, float)) and created > 0:
            cfg.release_date = (
                datetime.fromtimestamp(int(created), tz=timezone.utc).date().isoformat()
            )

        if isinstance(supported_params, list) and supported_params:
            cfg.thinking = "reasoning" in supported_params

        pricing = raw.get("pricing")
        if isinstance(pricing, dict):
            input_price = _parse_float(pricing.get("prompt"))
            output_price = _parse_float(pricing.get("completion"))
            if input_price is not None and output_price is not None:
                # LiteLLM reports per-token prices; convert to per-million
                # when the values look like per-token (very small).
                if input_price < 0.001 and output_price < 0.001:
                    input_price *= 1_000_000
                    output_price *= 1_000_000
                cfg.price = PriceInfo(input=input_price, output=output_price)

        result.append(cfg)

    return result


def _parse_float(value: Any) -> float | None:
    """Best-effort float parser (handles str / int / float / None)."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def clean_tool_schemas(schemas: dict[str, Any]) -> dict[str, Any]:
    """Strip ``$schema`` from a tool-schemas dict (Bedrock compatibility).

    AWS Bedrock's Converse API rejects JSON-Schema definitions that carry
    the ``$schema`` metadata field with a ``ValidationException``. This
    helper recursively walks the ``schemas`` dict and removes every
    ``$schema`` key encountered, returning a new dict (the input is not
    mutated). Ported from Bedrock's ``cleanParameters`` / ``cleanToolSchemas``.

    The input is expected to be a ``{tool_name: {"function": {"parameters":
    {...}}}}``-style dict (OpenAI tool shape) OR a single tool's
    ``parameters`` dict — both are handled gracefully.
    """
    if not isinstance(schemas, dict):
        return schemas

    return _strip_schema_key(schemas)


def _strip_schema_key(node: Any) -> Any:
    """Recursively strip ``$schema`` keys from ``node``.

    Handles dicts and lists; primitive values are returned unchanged.
    """
    if isinstance(node, dict):
        cleaned: dict[str, Any] = {}
        for key, value in node.items():
            if key == "$schema":
                continue
            cleaned[key] = _strip_schema_key(value)
        return cleaned
    if isinstance(node, list):
        return [_strip_schema_key(item) for item in node]
    return node


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------


__all__ = [
    # Enums
    "ProviderType",
    "ProviderOptionsType",
    "ReasoningEffort",
    "ALL_AGENT_TYPES",
    # Data models
    "ReasoningConfig",
    "PriceInfo",
    "AgentConfig",
    "ProviderConfig",
    "ModelConfig",
    "ModelsConfig",
    "TextPart",
    "ToolCall",
    "ToolCallResponse",
    "MessagePart",
    "MessageContent",
    "CallUsage",
    "Choice",
    "ContentResponse",
    # Protocol
    "Provider",
    "StreamingCallback",
    # Helpers
    "apply_model_prefix",
    "remove_model_prefix",
    "load_models_from_http",
    "clean_tool_schemas",
]


# ``os`` is imported only so adapters can probe env vars at runtime; keep
# the import here so type-checkers don't flag it as unused when callers
# ``from elengenix.providers.base import os`` (defensive).
_ = os

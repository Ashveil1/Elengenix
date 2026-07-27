"""elengenix.providers.glm — GLM (Z.AI) LLM provider adapter (Python port).

Port of PentAGI's ``backend/pkg/providers/glm/glm.go``. The adapter talks
to Z.AI's OpenAI-compatible Chat Completions API at
``https://api.z.ai/api/paas/v4/`` via the official ``openai`` Python SDK
(with a custom ``base_url``), and implements the full
:class:`~elengenix.providers.base.Provider` protocol.

Key features ported from the Go original
-----------------------------------------
* **OpenAI-compatible transport** — the only customisation is
  ``base_url`` and the ``GLM_API_KEY`` bearer token. The OpenAI SDK is
  imported lazily so the module loads without it installed.
* **Thinking control** — every agent slot can toggle reasoning on/off
  via ``extra_body.thinking.type`` (``"enabled"`` or ``"disabled"``).
  This is set per-agent in the YAML config, not at the provider level.
* **Preserved Thinking** — Z.AI clears ``reasoning_content`` between
  turns by default, which breaks multi-turn tool-call loops. Setting
  ``extra_body.thinking.clear_thinking = false`` keeps the reasoning
  content across turns. The client additionally re-serializes
  ``reasoning_content`` back into the assistant message when sending
  the next turn (this is what PentAGI's
  ``WithPreserveReasoningContent()`` does in langchaingo; in Python it
  is implemented by
  :meth:`OpenAICompatProvider.preserve_reasoning_content`).
* **Strategy** — ``glm-5.1`` (flagship) for critical reasoning,
  ``glm-5-turbo`` for orchestration, ``glm-4.5-air`` for cheap utility.
  The fallback model is ``glm-4.7-flashx`` (PentAGI's ``GLMAgentModel``).
* **Provider prefix** — when ``GLM_PROVIDER`` is set (e.g. ``"glm"``),
  :meth:`GLMProvider.model_with_prefix` returns ``glm/<model>`` so
  LiteLLM proxy routing works transparently.
* **Tool-call ID template** — ``call_-{r:19:d}`` (19 random digits).
  GLM emits 19-digit numeric IDs prefixed with ``call_-``; this template
  matches that format so orchestrator-synthesised IDs are
  indistinguishable from server-generated ones.
* **429 retry** — 10 attempts, 5 s base + 1 s linear increment
  (mirrors PentAGI's ``MaxTooManyRequestsRetries``).
"""

from __future__ import annotations

import logging
import os
from typing import Any, List

from elengenix.providers._openai_compat import (
    OpenAICompatProvider,
    make_generate_tool_call_id,
)
from elengenix.providers.base import (
    AgentConfig,
    ModelConfig,
    PriceInfo,
    ProviderConfig,
    ProviderOptionsType,
    ProviderType,
    ReasoningEffort,
)

logger = logging.getLogger("elengenix.providers.glm")

# ---------------------------------------------------------------------------
# Constants — ported from glm.go
# ---------------------------------------------------------------------------

#: Default Z.AI OpenAI-compatible base URL. Overridable via ``GLM_SERVER_URL``.
GLM_DEFAULT_SERVER_URL: str = "https://api.z.ai/api/paas/v4/"

#: Default GLM model. PentAGI's ``GLMAgentModel`` constant points at the
#: same ``glm-4.7-flashx`` ID — a high-speed, paid, priority-GPU variant
#: of the GLM-4.7 Flash model, best price/performance for batch utility.
GLM_DEFAULT_MODEL: str = "glm-4.7-flashx"

#: GLM tool-call ID template. ``{r:19:d}`` = 19 random decimal digits.
#: Matches the format Z.AI's server generates so orchestrator-synthesised
#: IDs are indistinguishable.
GLM_TOOL_CALL_ID_TEMPLATE: str = "call_-{r:19:d}"

#: 429 retry policy — mirrors PentAGI's MaxTooManyRequestsRetries /
#: TooManyRequestsRetryDelay constants.
GLM_MAX_429_RETRIES: int = 10
GLM_429_BASE_DELAY: float = 5.0


# ---------------------------------------------------------------------------
# Tool-call ID generator — exposed at module scope for registry import
# ---------------------------------------------------------------------------


generate_tool_call_id = make_generate_tool_call_id(GLM_TOOL_CALL_ID_TEMPLATE)


# ---------------------------------------------------------------------------
# Default pricing — USD per 1M tokens (Z.AI public pricing, 2026-Q1)
# ---------------------------------------------------------------------------

_GLM_5_1_PRICE = PriceInfo(input=1.40, output=4.40, cache_read=0.26)
_GLM_5_TURBO_PRICE = PriceInfo(input=1.20, output=4.00, cache_read=0.24)
_GLM_4_5_AIR_PRICE = PriceInfo(input=0.20, output=1.10, cache_read=0.03)
_GLM_4_7_FLASHX_PRICE = PriceInfo(input=0.07, output=0.40, cache_read=0.01)


#: Default GLM model catalog — ported from glm/models.yml.
GLM_DEFAULT_MODELS: List[ModelConfig] = [
    ModelConfig(
        name="glm-5.1",
        description=(
            "GLM-5.1 - Latest flagship for long-horizon tasks (8h sustained "
            "autonomous execution), Claude Opus 4.6-aligned coding, 200K "
            "context, hybrid thinking. Best for planning, mentor, and "
            "complex agentic engineering."
        ),
        thinking=True,
        price=_GLM_5_1_PRICE,
    ),
    ModelConfig(
        name="glm-5-turbo",
        description=(
            "GLM-5-Turbo - OpenClaw-native model optimized for tool "
            "invocation, instruction following, and long-chain execution. "
            "200K context, hybrid thinking. Ideal for orchestrator and "
            "assistant roles."
        ),
        thinking=True,
        price=_GLM_5_TURBO_PRICE,
    ),
    ModelConfig(
        name="glm-4.7-flashx",
        description=(
            "GLM-4.7-FlashX - Paid high-speed variant with priority GPU "
            "access, 200K context, hybrid thinking. Best price/performance "
            "for batch utility tasks."
        ),
        thinking=True,
        price=_GLM_4_7_FLASHX_PRICE,
    ),
    ModelConfig(
        name="glm-4.5-air",
        description=(
            "GLM-4.5-Air - Cost-effective lightweight MoE 106B/12B active, "
            "128K context, auto-thinking. Best price/quality ratio for "
            "utility agents and continuous monitoring."
        ),
        thinking=True,
        price=_GLM_4_5_AIR_PRICE,
    ),
]


# ---------------------------------------------------------------------------
# Default provider config (port of glm/config.yml)
# ---------------------------------------------------------------------------


def _agent(
    model: str,
    *,
    temperature: float,
    top_p: float,
    max_tokens: int,
    thinking_enabled: bool,
    clear_thinking: bool = False,
    price: PriceInfo | None = None,
) -> AgentConfig:
    """Build a GLM :class:`AgentConfig` with the per-agent ``extra_body``
    structure that Z.AI requires for thinking control + preserved
    thinking.

    ``thinking_enabled=True`` + ``clear_thinking=False`` enables
    Preserved Thinking (Z.AI docs): on the standard API endpoint Z.AI
    defaults to clearing ``reasoning_content`` between turns, which
    hurts agent loops with tool calls. Setting ``clear_thinking=false``
    preserves ``reasoning_content`` across turns, improving reasoning
    continuity and cache hit rates.
    """
    thinking_block: dict[str, Any] = {
        "type": "enabled" if thinking_enabled else "disabled",
    }
    if thinking_enabled and clear_thinking is not None:
        thinking_block["clear_thinking"] = clear_thinking
    return AgentConfig(
        model=model,
        temperature=temperature,
        top_p=top_p,
        n=1,
        max_tokens=max_tokens,
        extra_body={
            "thinking": thinking_block,
            "tool_choice": "auto",
        },
        price=price,
    )


def get_default_config() -> ProviderConfig:
    """Return the default GLM :class:`ProviderConfig`.

    Ported verbatim from ``glm/config.yml``. Strategy:
    * ``glm-5.1`` (flagship) for critical reasoning (generator/refiner/
      adviser/coder/pentester)
    * ``glm-5-turbo`` (OpenClaw-native, agent-optimized) for orchestration
      (primary_agent/assistant/installer)
    * ``glm-4.5-air`` for cheap utility (simple/simple_json/reflector/
      searcher/enricher)

    Thinking is enabled (with ``clear_thinking=false`` for preserved
    thinking) on all reasoning-heavy slots; disabled on utility slots.
    """
    cfg = ProviderConfig()
    cfg.simple = _agent(
        "glm-4.5-air",
        temperature=0.6, top_p=0.9, max_tokens=8192,
        thinking_enabled=False,
        price=_GLM_4_5_AIR_PRICE,
    )
    cfg.simple_json = _agent(
        "glm-4.5-air",
        temperature=0.6, top_p=0.9, max_tokens=4096,
        thinking_enabled=False,
        price=_GLM_4_5_AIR_PRICE,
    )
    cfg.simple_json.json_mode = True
    cfg.primary_agent = _agent(
        "glm-5-turbo",
        temperature=1.0, top_p=0.95, max_tokens=16384,
        thinking_enabled=True, clear_thinking=False,
        price=_GLM_5_TURBO_PRICE,
    )
    cfg.assistant = _agent(
        "glm-5-turbo",
        temperature=1.0, top_p=0.95, max_tokens=16384,
        thinking_enabled=True, clear_thinking=False,
        price=_GLM_5_TURBO_PRICE,
    )
    cfg.generator = _agent(
        "glm-5.1",
        temperature=1.0, top_p=0.95, max_tokens=32768,
        thinking_enabled=True, clear_thinking=False,
        price=_GLM_5_1_PRICE,
    )
    cfg.refiner = _agent(
        "glm-5.1",
        temperature=1.0, top_p=0.95, max_tokens=32768,
        thinking_enabled=True, clear_thinking=False,
        price=_GLM_5_1_PRICE,
    )
    cfg.adviser = _agent(
        "glm-5.1",
        temperature=1.0, top_p=0.95, max_tokens=16384,
        thinking_enabled=True, clear_thinking=False,
        price=_GLM_5_1_PRICE,
    )
    cfg.reflector = _agent(
        "glm-4.5-air",
        temperature=0.6, top_p=0.9, max_tokens=8192,
        thinking_enabled=False,
        price=_GLM_4_5_AIR_PRICE,
    )
    cfg.searcher = _agent(
        "glm-4.5-air",
        temperature=0.6, top_p=0.9, max_tokens=4096,
        thinking_enabled=False,
        price=_GLM_4_5_AIR_PRICE,
    )
    cfg.enricher = _agent(
        "glm-4.5-air",
        temperature=0.6, top_p=0.9, max_tokens=4096,
        thinking_enabled=False,
        price=_GLM_4_5_AIR_PRICE,
    )
    cfg.coder = _agent(
        "glm-5.1",
        temperature=1.0, top_p=0.95, max_tokens=20480,
        thinking_enabled=True, clear_thinking=False,
        price=_GLM_5_1_PRICE,
    )
    cfg.installer = _agent(
        "glm-4.5-air",
        temperature=1.0, top_p=0.95, max_tokens=16384,
        thinking_enabled=True, clear_thinking=False,
        price=_GLM_4_5_AIR_PRICE,
    )
    cfg.pentester = _agent(
        "glm-5.1",
        temperature=1.0, top_p=0.95, max_tokens=16384,
        thinking_enabled=True, clear_thinking=False,
        price=_GLM_5_1_PRICE,
    )
    return cfg


# ---------------------------------------------------------------------------
# GLMProvider
# ---------------------------------------------------------------------------


class GLMProvider(OpenAICompatProvider):
    """GLM (Z.AI) adapter (Python port of ``glmProvider``).

    Construction is lazy — the ``openai`` Python SDK is imported inside
    :meth:`_get_client` so importing this module never requires it to be
    installed. The API key is read from ``GLM_API_KEY`` (or supplied
    explicitly); the base URL defaults to :data:`GLM_DEFAULT_SERVER_URL`
    and is overridable via ``GLM_SERVER_URL``.

    Z.AI requires ``reasoning_content`` to be re-serialized into
    assistant messages on multi-turn tool-call flows. The
    :meth:`preserve_reasoning_content` helper (inherited from
    :class:`OpenAICompatProvider`) handles this; the per-agent YAML
    config sets ``extra_body.thinking.clear_thinking=false`` server-side
    so Z.AI preserves the reasoning content across turns.
    """

    PROVIDER_TYPE: ProviderType = ProviderType.GLM
    TOOL_CALL_ID_TEMPLATE: str = GLM_TOOL_CALL_ID_TEMPLATE
    DEFAULT_MODEL: str = GLM_DEFAULT_MODEL
    DEFAULT_BASE_URL: str = GLM_DEFAULT_SERVER_URL
    ENV_VAR_API_KEY: str = "GLM_API_KEY"
    ENV_VAR_BASE_URL: str = "GLM_SERVER_URL"
    ENV_VAR_PROVIDER_PREFIX: str = "GLM_PROVIDER"

    MAX_429_RETRIES: int = GLM_MAX_429_RETRIES
    BASE_429_DELAY: float = GLM_429_BASE_DELAY

    @classmethod
    def get_default_config(cls) -> ProviderConfig:
        return get_default_config()

    @classmethod
    def get_default_models(cls) -> List[ModelConfig]:
        return list(GLM_DEFAULT_MODELS)


__all__ = [
    "GLM_DEFAULT_SERVER_URL",
    "GLM_DEFAULT_MODEL",
    "GLM_TOOL_CALL_ID_TEMPLATE",
    "GLM_MAX_429_RETRIES",
    "GLM_429_BASE_DELAY",
    "GLM_DEFAULT_MODELS",
    "GLMProvider",
    "generate_tool_call_id",
    "get_default_config",
]

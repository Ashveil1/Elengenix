"""elengenix.providers.kimi — Kimi (Moonshot) LLM provider adapter (Python port).

Port of PentAGI's ``backend/pkg/providers/kimi/kimi.go``. The adapter talks
to Moonshot's OpenAI-compatible Chat Completions API at
``https://api.moonshot.cn/v1`` via the official ``openai`` Python SDK
(with a custom ``base_url``), and implements the full
:class:`~elengenix.providers.base.Provider` protocol.

Key features ported from the Go original
-----------------------------------------
* **OpenAI-compatible transport** — the only customisation is
  ``base_url`` and the ``KIMI_API_KEY`` bearer token. The OpenAI SDK is
  imported lazily so the module loads without it installed.
* **Thinking constraints** — any deviation triggers
  ``invalid_request_error``:

  =========== ===================== ========== ======================
  mode        temperature           top_p      thinking
  =========== ===================== ========== ======================
  thinking    1.0                   0.95       keep="all" (K2.6 only)
  non-thinking 0.6                  0.95       (absent)
  =========== ===================== ========== ======================

  Always: ``presence_penalty=0``, ``frequency_penalty=0``,
  ``tool_choice ∈ {auto, none}``, ``n=1``.

* **K2.5 langchaingo bug workaround** — langchaingo's
  ``reasoning.IsReasoningModel`` matches the substring ``"2.5"`` and
  force-overrides ``temperature`` to 1.0 in ``createChatRequest``. For
  non-thinking K2.5 agents, ``extra_body.temperature: 0.6`` is
  duplicated so it merges via ``maps.Copy`` with priority over the
  override. The Python ``openai`` SDK does NOT have this bug, so the
  duplication is harmless (the ``extra_body.temperature`` simply
  overrides the top-level ``temperature`` at the server side).

* **K2.6 multi-turn requires ``thinking.keep=all``** — without it,
  Moonshot returns ``"thinking is enabled but reasoning_content is
  missing in assistant tool call message"``. The
  ``extra_body.thinking.keep`` field is set per-agent in the YAML
  config for K2.6 reasoning slots.

* **Strategy** — ``kimi-k2.5`` (cost-effective default: $0.60/$3.00
  input/output) for utility/orchestration, ``kimi-k2.6`` ($0.95/$4.00)
  for critical reasoning. All legacy ``kimi-k2-*`` models
  (turbo-preview, 0905-preview, 0711-preview, thinking, thinking-turbo)
  were deprecated by Moonshot on 2026-05-25 and must not be used.

* **Tool-call ID template** — ``{f}:{r:1:d}`` (function name + ``:`` +
  single decimal digit). Matches Kimi's server-generated format.

* **Preserved Reasoning Content** — required for multi-turn tool-call
  flows (see :meth:`OpenAICompatProvider.preserve_reasoning_content`).
"""

from __future__ import annotations

import logging
import os
from typing import Any, List, Optional

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
)

logger = logging.getLogger("elengenix.providers.kimi")

# ---------------------------------------------------------------------------
# Constants — ported from kimi.go
# ---------------------------------------------------------------------------

#: Default Moonshot OpenAI-compatible base URL. Overridable via
#: ``KIMI_SERVER_URL``.
KIMI_DEFAULT_SERVER_URL: str = "https://api.moonshot.cn/v1"

#: Default Kimi model. PentAGI's ``KimiAgentModel`` constant — kimi-k2.5
#: is chosen as cost-effective default ($0.60/$3.00 input/output vs
#: $0.95/$4.00 for k2.6). All legacy kimi-k2-* models (turbo-preview,
#: 0905-preview, 0711-preview, thinking, thinking-turbo) were deprecated
#: by Moonshot on 2026-05-25 and must not be used.
KIMI_DEFAULT_MODEL: str = "kimi-k2.5"

#: Kimi tool-call ID template. ``{f}`` = function name, ``{r:1:d}`` =
#: 1 random decimal digit. Matches the format Moonshot's server generates.
KIMI_TOOL_CALL_ID_TEMPLATE: str = "{f}:{r:1:d}"

#: 429 retry policy.
KIMI_MAX_429_RETRIES: int = 10
KIMI_429_BASE_DELAY: float = 5.0


# ---------------------------------------------------------------------------
# Tool-call ID generator
# ---------------------------------------------------------------------------


def generate_tool_call_id(function_name: str = "call") -> str:
    """Generate a Kimi-shaped tool-call ID.

    Format: ``<function_name>:<1 digit>``. The orchestrator uses this
    when it needs to synthesise a tool-call ID for a tool result that
    didn't come from a real Kimi response. Defaults to ``"call"`` as the
    function-name placeholder when none is supplied (matching
    PentAGI's behaviour).
    """
    # We can't use make_generate_tool_call_id here because the template
    # uses {f} which requires a function-name argument; the shared
    # factory produces a zero-arg callable. Render inline instead.
    from elengenix.providers._openai_compat import _render_template
    return _render_template(KIMI_TOOL_CALL_ID_TEMPLATE, function_name)


# ---------------------------------------------------------------------------
# Default pricing — USD per 1M tokens (Moonshot public pricing)
# ---------------------------------------------------------------------------

_KIMI_K25_PRICE = PriceInfo(input=0.60, output=3.00, cache_read=0.10)
_KIMI_K26_PRICE = PriceInfo(input=0.95, output=4.00, cache_read=0.16)


#: Default Kimi model catalog — ported from kimi/models.yml.
KIMI_DEFAULT_MODELS: List[ModelConfig] = [
    ModelConfig(
        name="kimi-k2.6",
        description=(
            "Kimi K2.6 - Moonshot flagship hybrid thinking model. Requires "
            "thinking.keep='all' for multi-turn tool calls (otherwise "
            "Moonshot returns 'thinking is enabled but reasoning_content "
            "is missing in assistant tool call message'). Best for "
            "critical reasoning (generator/refiner/adviser/pentester)."
        ),
        thinking=True,
        price=_KIMI_K26_PRICE,
    ),
    ModelConfig(
        name="kimi-k2.5",
        description=(
            "Kimi K2.5 - Cost-effective default ($0.60/$3.00 input/output "
            "vs $0.95/$4.00 for k2.6). Best for utility/orchestration. "
            "langchaingo's IsReasoningModel matches '2.5' and force-"
            "overrides temperature to 1.0 — non-thinking K2.5 agents "
            "duplicate temperature=0.6 into extra_body to bypass."
        ),
        thinking=True,
        price=_KIMI_K25_PRICE,
    ),
]


# ---------------------------------------------------------------------------
# Default provider config (port of kimi/config.yml)
# ---------------------------------------------------------------------------


def _agent(
    model: str,
    *,
    temperature: float,
    top_p: float = 0.95,
    max_tokens: int,
    thinking_enabled: bool,
    keep_all: bool = False,
    json_mode: bool = False,
    price: PriceInfo | None = None,
) -> AgentConfig:
    """Build a Kimi :class:`AgentConfig` with the per-agent
    ``extra_body`` structure that Moonshot requires for thinking control
    + preserved thinking.

    Per Moonshot API constraints (any deviation -> invalid_request_error):
      thinking:     temperature=1.0, top_p=0.95, n=1, thinking.keep="all" (k2.6)
      non-thinking: temperature=0.6, top_p=0.95, n=1
      always:       presence_penalty=0, frequency_penalty=0, tool_choice in {auto, none}

    WORKAROUND (langchaingo bug, drop after upstream fix): for
    kimi-k2.5 non-thinking agents we duplicate temperature=0.6 into
    extra_body. langchaingo's reasoning.IsReasoningModel matches '2.5'
    and force-overrides temperature to 1.0 in createChatRequest.
    extra_body merges with priority via maps.Copy in openaiclient.createChat,
    so it bypasses the override. Remove once langchaingo stops matching
    k2.5/k2.6 as reasoning.
    """
    thinking_block: dict[str, Any] = {
        "type": "enabled" if thinking_enabled else "disabled",
    }
    if thinking_enabled and keep_all:
        thinking_block["keep"] = "all"

    extra_body: dict[str, Any] = {
        "thinking": thinking_block,
        "tool_choice": "auto",
    }
    # langchaingo bug workaround for non-thinking K2.5 agents
    if not thinking_enabled and model.startswith("kimi-k2.5"):
        extra_body["temperature"] = temperature

    agent = AgentConfig(
        model=model,
        temperature=temperature,
        top_p=top_p,
        n=1,
        max_tokens=max_tokens,
        extra_body=extra_body,
        price=price,
    )
    if json_mode:
        agent.json_mode = True
    return agent


def get_default_config() -> ProviderConfig:
    """Return the default Kimi :class:`ProviderConfig`.

    Ported verbatim from ``kimi/config.yml``. Strategy:
    * ``kimi-k2.5`` for utility/orchestration (simple, simple_json,
      primary_agent, assistant, reflector, searcher, enricher, installer)
    * ``kimi-k2.6`` for critical reasoning (generator, refiner, adviser,
      coder, pentester) — with ``thinking.keep=all`` for multi-turn tool
      calls.
    """
    cfg = ProviderConfig()
    cfg.simple = _agent(
        "kimi-k2.5",
        temperature=0.6, max_tokens=8192,
        thinking_enabled=False,
        price=_KIMI_K25_PRICE,
    )
    cfg.simple_json = _agent(
        "kimi-k2.5",
        temperature=0.6, max_tokens=4096,
        thinking_enabled=False, json_mode=True,
        price=_KIMI_K25_PRICE,
    )
    cfg.primary_agent = _agent(
        "kimi-k2.5",
        temperature=1.0, max_tokens=16384,
        thinking_enabled=True,
        price=_KIMI_K25_PRICE,
    )
    cfg.assistant = _agent(
        "kimi-k2.5",
        temperature=1.0, max_tokens=16384,
        thinking_enabled=True,
        price=_KIMI_K25_PRICE,
    )
    cfg.generator = _agent(
        "kimi-k2.6",
        temperature=1.0, max_tokens=32768,
        thinking_enabled=True, keep_all=True,
        price=_KIMI_K26_PRICE,
    )
    cfg.refiner = _agent(
        "kimi-k2.6",
        temperature=1.0, max_tokens=32768,
        thinking_enabled=True, keep_all=True,
        price=_KIMI_K26_PRICE,
    )
    cfg.adviser = _agent(
        "kimi-k2.6",
        temperature=1.0, max_tokens=8192,
        thinking_enabled=True, keep_all=True,
        price=_KIMI_K26_PRICE,
    )
    cfg.reflector = _agent(
        "kimi-k2.5",
        temperature=0.6, max_tokens=4096,
        thinking_enabled=False,
        price=_KIMI_K25_PRICE,
    )
    cfg.searcher = _agent(
        "kimi-k2.5",
        temperature=0.6, max_tokens=4096,
        thinking_enabled=False,
        price=_KIMI_K25_PRICE,
    )
    cfg.enricher = _agent(
        "kimi-k2.5",
        temperature=0.6, max_tokens=4096,
        thinking_enabled=False,
        price=_KIMI_K25_PRICE,
    )
    cfg.coder = _agent(
        "kimi-k2.6",
        temperature=1.0, max_tokens=20480,
        thinking_enabled=True, keep_all=True,
        price=_KIMI_K26_PRICE,
    )
    cfg.installer = _agent(
        "kimi-k2.5",
        temperature=1.0, max_tokens=16384,
        thinking_enabled=True,
        price=_KIMI_K25_PRICE,
    )
    cfg.pentester = _agent(
        "kimi-k2.6",
        temperature=1.0, max_tokens=16384,
        thinking_enabled=True, keep_all=True,
        price=_KIMI_K26_PRICE,
    )
    return cfg


# ---------------------------------------------------------------------------
# KimiProvider
# ---------------------------------------------------------------------------


class KimiProvider(OpenAICompatProvider):
    """Kimi (Moonshot) adapter (Python port of ``kimiProvider``).

    Construction is lazy — the ``openai`` Python SDK is imported inside
    :meth:`_get_client`. The API key is read from ``KIMI_API_KEY`` (or
    supplied explicitly); the base URL defaults to
    :data:`KIMI_DEFAULT_SERVER_URL` and is overridable via
    ``KIMI_SERVER_URL``.

    Moonshot requires ``reasoning_content`` to be re-serialized into
    assistant messages on multi-turn tool-call flows. The
    :meth:`preserve_reasoning_content` helper (inherited from
    :class:`OpenAICompatProvider`) handles this; the per-agent YAML
    config sets ``extra_body.thinking.keep=all`` for K2.6 reasoning
    slots.
    """

    PROVIDER_TYPE: ProviderType = ProviderType.KIMI
    TOOL_CALL_ID_TEMPLATE: str = KIMI_TOOL_CALL_ID_TEMPLATE
    DEFAULT_MODEL: str = KIMI_DEFAULT_MODEL
    DEFAULT_BASE_URL: str = KIMI_DEFAULT_SERVER_URL
    ENV_VAR_API_KEY: str = "KIMI_API_KEY"
    ENV_VAR_BASE_URL: str = "KIMI_SERVER_URL"
    ENV_VAR_PROVIDER_PREFIX: str = "KIMI_PROVIDER"

    MAX_429_RETRIES: int = KIMI_MAX_429_RETRIES
    BASE_429_DELAY: float = KIMI_429_BASE_DELAY

    @classmethod
    def get_default_config(cls) -> ProviderConfig:
        return get_default_config()

    @classmethod
    def get_default_models(cls) -> List[ModelConfig]:
        return list(KIMI_DEFAULT_MODELS)

    # ------------------------------------------------------------------
    # Kimi-specific helpers
    # ------------------------------------------------------------------

    @staticmethod
    def validate_thinking_constraints(
        agent: AgentConfig,
    ) -> Optional[str]:
        """Validate the per-agent options against Kimi's hard API
        constraints. Returns an error message if the configuration would
        trigger ``invalid_request_error``, or ``None`` if valid.

        Useful for the agent-config loader to fail fast at startup
        rather than at the first LLM call.
        """
        extra_body = agent.extra_body or {}
        thinking_block = extra_body.get("thinking") or {}
        thinking_enabled = (
            isinstance(thinking_block, dict)
            and thinking_block.get("type") == "enabled"
        )
        if agent.n is not None and agent.n != 1:
            return f"Kimi requires n=1, got n={agent.n}"
        if agent.presence_penalty is not None and agent.presence_penalty != 0:
            return "Kimi requires presence_penalty=0"
        if agent.frequency_penalty is not None and agent.frequency_penalty != 0:
            return "Kimi requires frequency_penalty=0"
        tool_choice = extra_body.get("tool_choice")
        if tool_choice is not None and tool_choice not in ("auto", "none"):
            return f"Kimi requires tool_choice in {{auto, none}}, got {tool_choice!r}"

        temperature = agent.temperature if agent.temperature is not None else 1.0
        top_p = agent.top_p if agent.top_p is not None else 0.95
        model = agent.model

        if thinking_enabled:
            if temperature != 1.0:
                return (
                    f"Kimi thinking mode requires temperature=1.0, got {temperature}"
                )
            if top_p != 0.95:
                return f"Kimi thinking mode requires top_p=0.95, got {top_p}"
            if model.startswith("kimi-k2.6"):
                keep = thinking_block.get("keep") if isinstance(
                    thinking_block, dict
                ) else None
                if keep != "all":
                    return (
                        "Kimi K2.6 multi-turn requires thinking.keep='all', "
                        f"got {keep!r}"
                    )
        else:
            if temperature != 0.6:
                return (
                    "Kimi non-thinking mode requires temperature=0.6, "
                    f"got {temperature}"
                )
            if top_p != 0.95:
                return f"Kimi non-thinking mode requires top_p=0.95, got {top_p}"
        return None


__all__ = [
    "KIMI_DEFAULT_SERVER_URL",
    "KIMI_DEFAULT_MODEL",
    "KIMI_TOOL_CALL_ID_TEMPLATE",
    "KIMI_MAX_429_RETRIES",
    "KIMI_429_BASE_DELAY",
    "KIMI_DEFAULT_MODELS",
    "KimiProvider",
    "generate_tool_call_id",
    "get_default_config",
]

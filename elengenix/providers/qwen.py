"""elengenix.providers.qwen — Qwen (Alibaba Cloud DashScope) LLM provider
adapter (Python port).

Port of PentAGI's ``backend/pkg/providers/qwen/qwen.go``. The adapter
talks to Alibaba Cloud DashScope's OpenAI-compatibility endpoint at
``https://dashscope.aliyun.com/compatible-mode/v1`` via the official
``openai`` Python SDK (with a custom ``base_url``), and implements the
full :class:`~elengenix.providers.base.Provider` protocol.

Key features ported from the Go original
-----------------------------------------
* **OpenAI-compatible transport** — the only customisation is
  ``base_url`` and the ``QWEN_API_KEY`` bearer token (also accepts
  ``DASHSCOPE_API_KEY``). The OpenAI SDK is imported lazily.
* **DashScope-specific thinking control** (NOT OpenAI standard):

  - ``extra_body.enable_thinking: bool`` — utility agents MUST set this
    to ``False`` explicitly. Qwen3.5/3.6/3.7 hybrid models have thinking
    ENABLED by default; without disabling it, ``reasoning_content`` is
    returned inline as part of ``content``, corrupting short
    deterministic outputs (e.g. the docker image selector returning the
    full chain-of-thought instead of just ``vxcontrol/kali-linux``).
  - ``extra_body.preserve_thinking: true`` — keeps reasoning_content
    from previous assistant turns in subsequent requests. Supported
    ONLY by ``qwen3.7-max`` and ``qwen3.6-plus`` families. Required for
    agent loops with tool calls to preserve reasoning continuity. Works
    together with the client-side
    :meth:`OpenAICompatProvider.preserve_reasoning_content` re-serializer.

* **``qwen3-coder-*`` models are NOT hybrid thinking models** — no
  thinking control needed. The per-agent YAML config deliberately omits
  ``extra_body.enable_thinking`` for ``coder`` and ``installer`` slots
  that use ``qwen3-coder-plus`` / ``qwen3-coder-flash``.

* **Strategy**:

  - ``qwen3.7-max`` — flagship, critical reasoning (generator/refiner/adviser)
  - ``qwen3.6-plus`` — mid-tier multimodal Plus, orchestration
    (primary_agent / assistant / pentester)
  - ``qwen3.5-flash`` — cheap utility (simple / simple_json / reflector
    / searcher / enricher)
  - ``qwen3-coder-plus`` / ``qwen3-coder-flash`` — code-specialized
    (coder / installer)

* **Tool-call ID template** — ``call_{r:24:h}`` (24 random hex chars,
  ``call_`` prefix). Matches Qwen's server-generated format.

* **Default model** — ``qwen-plus`` (DashScope's generic Plus model
  alias; PentAGI's ``QwenAgentModel`` constant).
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

logger = logging.getLogger("elengenix.providers.qwen")

# ---------------------------------------------------------------------------
# Constants — ported from qwen.go
# ---------------------------------------------------------------------------

#: Default DashScope OpenAI-compatible base URL. Overridable via
#: ``QWEN_SERVER_URL``.
QWEN_DEFAULT_SERVER_URL: str = (
    "https://dashscope.aliyun.com/compatible-mode/v1"
)

#: Default Qwen model. PentAGI's ``QwenAgentModel`` constant —
#: ``qwen-plus`` is DashScope's generic Plus model alias that resolves
#: to the latest Plus-tier model.
QWEN_DEFAULT_MODEL: str = "qwen-plus"

#: Qwen tool-call ID template. ``{r:24:h}`` = 24 random lowercase hex
#: chars. Matches the format DashScope's server generates.
QWEN_TOOL_CALL_ID_TEMPLATE: str = "call_{r:24:h}"

#: 429 retry policy.
QWEN_MAX_429_RETRIES: int = 10
QWEN_429_BASE_DELAY: float = 5.0

#: Models that support ``preserve_thinking=true`` (DashScope docs). Other
#: Qwen3 models silently ignore the flag (or error on it, depending on
#: the exact model version).
QWEN_PRESERVE_THINKING_MODELS: tuple = (
    "qwen3.7-max",
    "qwen3.6-plus",
)


# ---------------------------------------------------------------------------
# Tool-call ID generator
# ---------------------------------------------------------------------------


generate_tool_call_id = make_generate_tool_call_id(QWEN_TOOL_CALL_ID_TEMPLATE)


# ---------------------------------------------------------------------------
# Default pricing — USD per 1M tokens (DashScope public pricing)
# ---------------------------------------------------------------------------

_QWEN_37_MAX_PRICE = PriceInfo(input=2.5, output=7.5, cache_read=0.5)
_QWEN_36_PLUS_PRICE = PriceInfo(input=0.5, output=3.0, cache_read=0.05)
_QWEN_35_FLASH_PRICE = PriceInfo(input=0.1, output=0.4, cache_read=0.01)
_QWEN_CODER_PLUS_PRICE = PriceInfo(input=1.0, output=5.0, cache_read=0.2)
_QWEN_CODER_FLASH_PRICE = PriceInfo(input=0.3, output=1.5, cache_read=0.06)


#: Default Qwen model catalog — ported from qwen/models.yml.
QWEN_DEFAULT_MODELS: List[ModelConfig] = [
    ModelConfig(
        name="qwen3.7-max",
        description=(
            "Qwen3.7-Max - DashScope flagship. Supports preserve_thinking=true "
            "for multi-turn reasoning continuity. Best for critical reasoning "
            "(generator/refiner/adviser)."
        ),
        thinking=True,
        price=_QWEN_37_MAX_PRICE,
    ),
    ModelConfig(
        name="qwen3.6-plus",
        description=(
            "Qwen3.6-Plus - Mid-tier multimodal Plus. Supports "
            "preserve_thinking=true. Best for orchestration "
            "(primary_agent/assistant/pentester)."
        ),
        thinking=True,
        price=_QWEN_36_PLUS_PRICE,
    ),
    ModelConfig(
        name="qwen3.5-flash",
        description=(
            "Qwen3.5-Flash - Cheap utility hybrid model. Thinking ENABLED "
            "by default — utility agents must explicitly set "
            "extra_body.enable_thinking=false to avoid reasoning_content "
            "leaking into content."
        ),
        thinking=True,
        price=_QWEN_35_FLASH_PRICE,
    ),
    ModelConfig(
        name="qwen3-coder-plus",
        description=(
            "Qwen3-Coder-Plus - Code-specialized model. NOT a hybrid "
            "thinking model — no thinking control needed (do not set "
            "extra_body.enable_thinking)."
        ),
        thinking=False,
        price=_QWEN_CODER_PLUS_PRICE,
    ),
    ModelConfig(
        name="qwen3-coder-flash",
        description=(
            "Qwen3-Coder-Flash - Cheap code-specialized model. NOT a hybrid "
            "thinking model — no thinking control needed."
        ),
        thinking=False,
        price=_QWEN_CODER_FLASH_PRICE,
    ),
]


# ---------------------------------------------------------------------------
# Default provider config (port of qwen/config.yml)
# ---------------------------------------------------------------------------


def _agent(
    model: str,
    *,
    temperature: float,
    max_tokens: int,
    enable_thinking: Optional[bool] = None,
    preserve_thinking: Optional[bool] = None,
    json_mode: bool = False,
    price: PriceInfo | None = None,
) -> AgentConfig:
    """Build a Qwen :class:`AgentConfig` with the per-agent
    ``extra_body`` structure that DashScope requires for thinking
    control + preserved thinking.

    ``enable_thinking=False`` MUST be set explicitly on utility agents
    (simple, simple_json, reflector, searcher, enricher) — Qwen3.5/3.6/3.7
    hybrid models have thinking ENABLED by default. Without disabling,
    reasoning_content leaks into content and corrupts short deterministic
    outputs (e.g. docker image selector returning chain-of-thought
    instead of just 'vxcontrol/kali-linux').

    ``preserve_thinking=True`` is supported ONLY by qwen3.7-max and
    qwen3.6-plus families — it keeps reasoning_content from previous
    assistant turns in subsequent requests. Required for agent loops
    with tool calls to preserve reasoning continuity.
    """
    extra_body: dict[str, Any] = {}
    if enable_thinking is not None:
        extra_body["enable_thinking"] = enable_thinking
    if preserve_thinking is not None:
        extra_body["preserve_thinking"] = preserve_thinking
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
    """Return the default Qwen :class:`ProviderConfig`.

    Ported verbatim from ``qwen/config.yml``. Strategy:
    * ``qwen3.5-flash`` for cheap utility (simple, simple_json, reflector,
      searcher, enricher) — with enable_thinking=False explicitly.
    * ``qwen3.6-plus`` for orchestration (primary_agent, assistant,
      pentester) — with preserve_thinking=True.
    * ``qwen3.7-max`` for critical reasoning (generator, refiner,
      adviser) — with preserve_thinking=True.
    * ``qwen3-coder-plus`` / ``qwen3-coder-flash`` for code-specialized
      (coder, installer) — NO thinking control (not hybrid models).
    """
    cfg = ProviderConfig()
    cfg.simple = _agent(
        "qwen3.5-flash",
        temperature=0.6, max_tokens=8192,
        enable_thinking=False,
        price=_QWEN_35_FLASH_PRICE,
    )
    cfg.simple_json = _agent(
        "qwen3.5-flash",
        temperature=0.6, max_tokens=4096,
        enable_thinking=False, json_mode=True,
        price=_QWEN_35_FLASH_PRICE,
    )
    cfg.primary_agent = _agent(
        "qwen3.6-plus",
        temperature=1.0, max_tokens=16384,
        enable_thinking=True, preserve_thinking=True,
        price=_QWEN_36_PLUS_PRICE,
    )
    cfg.assistant = _agent(
        "qwen3.6-plus",
        temperature=1.0, max_tokens=16384,
        enable_thinking=True, preserve_thinking=True,
        price=_QWEN_36_PLUS_PRICE,
    )
    cfg.generator = _agent(
        "qwen3.7-max",
        temperature=1.0, max_tokens=32768,
        enable_thinking=True, preserve_thinking=True,
        price=_QWEN_37_MAX_PRICE,
    )
    cfg.refiner = _agent(
        "qwen3.7-max",
        temperature=1.0, max_tokens=20480,
        enable_thinking=True, preserve_thinking=True,
        price=_QWEN_37_MAX_PRICE,
    )
    cfg.adviser = _agent(
        "qwen3.7-max",
        temperature=1.0, max_tokens=8192,
        enable_thinking=True, preserve_thinking=True,
        price=_QWEN_37_MAX_PRICE,
    )
    cfg.reflector = _agent(
        "qwen3.5-flash",
        temperature=0.7, max_tokens=4096,
        enable_thinking=False,
        price=_QWEN_35_FLASH_PRICE,
    )
    cfg.searcher = _agent(
        "qwen3.5-flash",
        temperature=0.7, max_tokens=4096,
        enable_thinking=False,
        price=_QWEN_35_FLASH_PRICE,
    )
    cfg.enricher = _agent(
        "qwen3.5-flash",
        temperature=0.7, max_tokens=4096,
        enable_thinking=False,
        price=_QWEN_35_FLASH_PRICE,
    )
    cfg.coder = _agent(
        "qwen3-coder-plus",
        temperature=1.0, max_tokens=20480,
        price=_QWEN_CODER_PLUS_PRICE,
    )
    cfg.installer = _agent(
        "qwen3-coder-flash",
        temperature=0.7, max_tokens=16384,
        price=_QWEN_CODER_FLASH_PRICE,
    )
    cfg.pentester = _agent(
        "qwen3.6-plus",
        temperature=0.8, max_tokens=16384,
        enable_thinking=True, preserve_thinking=True,
        price=_QWEN_36_PLUS_PRICE,
    )
    return cfg


# ---------------------------------------------------------------------------
# QwenProvider
# ---------------------------------------------------------------------------


class QwenProvider(OpenAICompatProvider):
    """Qwen (Alibaba DashScope) adapter (Python port of ``qwenProvider``).

    Construction is lazy — the ``openai`` Python SDK is imported inside
    :meth:`_get_client`. The API key is read from ``QWEN_API_KEY`` (or
    the alias ``DASHSCOPE_API_KEY``); the base URL defaults to
    :data:`QWEN_DEFAULT_SERVER_URL` and is overridable via
    ``QWEN_SERVER_URL``.

    DashScope requires ``reasoning_content`` to be re-serialized into
    assistant messages on multi-turn tool-call flows for qwen3.7-max and
    qwen3.6-plus models. The :meth:`preserve_reasoning_content` helper
    (inherited from :class:`OpenAICompatProvider`) handles this; the
    per-agent YAML config sets ``extra_body.preserve_thinking=true`` for
    those models.
    """

    PROVIDER_TYPE: ProviderType = ProviderType.QWEN
    TOOL_CALL_ID_TEMPLATE: str = QWEN_TOOL_CALL_ID_TEMPLATE
    DEFAULT_MODEL: str = QWEN_DEFAULT_MODEL
    DEFAULT_BASE_URL: str = QWEN_DEFAULT_SERVER_URL
    ENV_VAR_API_KEY: str = "QWEN_API_KEY"  # also accepts DASHSCOPE_API_KEY
    ENV_VAR_BASE_URL: str = "QWEN_SERVER_URL"
    ENV_VAR_PROVIDER_PREFIX: str = "QWEN_PROVIDER"

    MAX_429_RETRIES: int = QWEN_MAX_429_RETRIES
    BASE_429_DELAY: float = QWEN_429_BASE_DELAY

    def __init__(
        self,
        api_key: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        # Accept DASHSCOPE_API_KEY as an alias when QWEN_API_KEY is unset.
        if api_key is None:
            api_key = (
                os.environ.get("QWEN_API_KEY")
                or os.environ.get("DASHSCOPE_API_KEY")
                or ""
            )
        super().__init__(api_key, **kwargs)

    @classmethod
    def get_default_config(cls) -> ProviderConfig:
        return get_default_config()

    @classmethod
    def get_default_models(cls) -> List[ModelConfig]:
        return list(QWEN_DEFAULT_MODELS)

    # ------------------------------------------------------------------
    # Qwen-specific helpers
    # ------------------------------------------------------------------

    @staticmethod
    def supports_preserve_thinking(model: str) -> bool:
        """Return ``True`` if ``model`` is in the DashScope
        ``preserve_thinking``-supporting family (``qwen3.7-max`` /
        ``qwen3.6-plus``). Other Qwen3 models silently ignore the flag
        or error on it."""
        return any(
            model.startswith(p) for p in QWEN_PRESERVE_THINKING_MODELS
        )

    @staticmethod
    def is_coder_model(model: str) -> bool:
        """Return ``True`` if ``model`` is a ``qwen3-coder-*`` model.
        Coder models are NOT hybrid thinking models — they don't accept
        ``enable_thinking`` and don't return ``reasoning_content``."""
        return model.startswith("qwen3-coder-")

    @staticmethod
    def validate_thinking_config(agent: AgentConfig) -> Optional[str]:
        """Validate the per-agent ``extra_body`` against DashScope's
        documented behaviour. Returns an error message if the
        configuration is known to be rejected (or silently ignored), or
        ``None`` if valid. Useful for the agent-config loader to fail
        fast at startup."""
        extra_body = agent.extra_body or {}
        model = agent.model

        # Coder models don't accept enable_thinking
        if QwenProvider.is_coder_model(model):
            if "enable_thinking" in extra_body:
                return (
                    f"qwen3-coder-* models do not accept enable_thinking; "
                    f"model={model!r} has it set"
                )
            if "preserve_thinking" in extra_body:
                return (
                    f"qwen3-coder-* models do not accept preserve_thinking; "
                    f"model={model!r} has it set"
                )
            return None

        # preserve_thinking only supported on qwen3.7-max / qwen3.6-plus
        if (
            extra_body.get("preserve_thinking")
            and not QwenProvider.supports_preserve_thinking(model)
        ):
            return (
                f"preserve_thinking=true is only supported on "
                f"{QWEN_PRESERVE_THINKING_MODELS}; model={model!r} does "
                "not support it"
            )

        # enable_thinking=false + preserve_thinking=true is contradictory
        if (
            extra_body.get("enable_thinking") is False
            and extra_body.get("preserve_thinking") is True
        ):
            return (
                "enable_thinking=false + preserve_thinking=true is "
                "contradictory (no reasoning to preserve)"
            )

        return None


__all__ = [
    "QWEN_DEFAULT_SERVER_URL",
    "QWEN_DEFAULT_MODEL",
    "QWEN_TOOL_CALL_ID_TEMPLATE",
    "QWEN_MAX_429_RETRIES",
    "QWEN_429_BASE_DELAY",
    "QWEN_DEFAULT_MODELS",
    "QWEN_PRESERVE_THINKING_MODELS",
    "QwenProvider",
    "generate_tool_call_id",
    "get_default_config",
]

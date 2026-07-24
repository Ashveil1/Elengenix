"""elengenix.providers.openai — Standard OpenAI LLM provider adapter (Python port).

Port of PentAGI's ``backend/pkg/providers/openai/openai.go``. Drives the
official OpenAI Chat Completions API via the ``openai`` Python SDK.

Unlike the other OpenAI-compatible providers in this package, the OpenAI
provider:

* Uses no custom ``base_url`` (the SDK's default
  ``https://api.openai.com/v1`` applies). The caller MAY override via
  ``OPENAI_BASE_URL`` for Azure OpenAI / proxy deployments.
* Has no LiteLLM provider-prefix passthrough —
  :meth:`OpenAIProvider.model_with_prefix` returns the bare model name
  (matching PentAGI's ``openaiProvider.ModelWithPrefix`` which is a
  passthrough).
* Supports all OpenAI models: ``gpt-4o``, ``gpt-4-turbo``, ``gpt-4.1``,
  ``o1``, ``o3``, ``o4-mini``, etc.

Reasoning-model specifics (``o1`` / ``o3`` / ``o4`` family):

* Temperature must be ``1.0`` (the API rejects any other value).
* The ``system`` role is NOT supported — system prompts must be
  converted to the ``developer`` role. :meth:`_build_request` performs
  this rewrite automatically when
  :meth:`OpenAIProvider.is_reasoning_model` returns ``True`` for the
  configured model.
* ``max_tokens`` is interpreted as ``max_completion_tokens`` on the
  reasoning-model API. The openai SDK accepts both kwargs; we forward
  ``max_tokens`` unchanged for backwards compatibility.

Tool-call ID template: ``call_{r:24:b}`` (24 random base62 chars,
``call_`` prefix). Matches OpenAI's server-generated format.

Default model: ``o4-mini`` (PentAGI's ``OpenAIAgentModel``).
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

logger = logging.getLogger("elengenix.providers.openai")

# ---------------------------------------------------------------------------
# Constants — ported from openai.go
# ---------------------------------------------------------------------------

#: Default OpenAI base URL. Overridable via ``OPENAI_BASE_URL`` (or
#: ``OPENAI_SERVER_URL`` for PentAGI compatibility).
OPENAI_DEFAULT_SERVER_URL: str = "https://api.openai.com/v1"

#: Default OpenAI model. PentAGI's ``OpenAIAgentModel`` constant —
#: ``o4-mini`` is OpenAI's latest cost-effective reasoning model.
OPENAI_DEFAULT_MODEL: str = "o4-mini"

#: OpenAI tool-call ID template. ``{r:24:b}`` = 24 random base62 chars.
#: Matches the format OpenAI's server generates.
OPENAI_TOOL_CALL_ID_TEMPLATE: str = "call_{r:24:b}"

#: 429 retry policy.
OPENAI_MAX_429_RETRIES: int = 10
OPENAI_429_BASE_DELAY: float = 5.0

#: Model-name prefixes that trigger reasoning-model behaviour (system→
#: developer rewrite, forced temperature=1.0). Includes the latest
#: ``o5`` prefix for forward compatibility.
OPENAI_REASONING_MODEL_PREFIXES: tuple = ("o1", "o3", "o4", "o5")


# ---------------------------------------------------------------------------
# Tool-call ID generator
# ---------------------------------------------------------------------------


generate_tool_call_id = make_generate_tool_call_id(OPENAI_TOOL_CALL_ID_TEMPLATE)


# ---------------------------------------------------------------------------
# Default pricing — USD per 1M tokens (OpenAI public pricing, 2026-Q1)
# ---------------------------------------------------------------------------

_GPT_4O_PRICE = PriceInfo(input=2.50, output=10.00, cache_read=1.25)
_GPT_4O_MINI_PRICE = PriceInfo(input=0.15, output=0.60, cache_read=0.075)
_O4_MINI_PRICE = PriceInfo(input=1.10, output=4.40, cache_read=0.55)
_O3_PRICE = PriceInfo(input=2.00, output=8.00, cache_read=1.00)


#: Default OpenAI model catalog — ported from openai/models.yml.
OPENAI_DEFAULT_MODELS: List[ModelConfig] = [
    ModelConfig(
        name="o4-mini",
        description=(
            "o4-mini - OpenAI's latest cost-effective reasoning model. "
            "Requires temperature=1.0; system role must be converted to "
            "developer role. Best default for agent workloads."
        ),
        thinking=True,
        price=_O4_MINI_PRICE,
    ),
    ModelConfig(
        name="o3",
        description=(
            "o3 - OpenAI's flagship reasoning model. Same constraints as "
            "o4-mini (temperature=1.0, developer role)."
        ),
        thinking=True,
        price=_O3_PRICE,
    ),
    ModelConfig(
        name="gpt-4o",
        description=(
            "GPT-4o - Multimodal flagship. Supports system role, accepts "
            "any temperature in [0, 2]. Best for vision + tool-heavy workloads."
        ),
        thinking=False,
        price=_GPT_4O_PRICE,
    ),
    ModelConfig(
        name="gpt-4o-mini",
        description=(
            "GPT-4o-mini - Cheap utility model. Same shape as gpt-4o. "
            "Best for high-volume parsing/structured tasks."
        ),
        thinking=False,
        price=_GPT_4O_MINI_PRICE,
    ),
]


# ---------------------------------------------------------------------------
# Default provider config (port of openai/config.yml)
# ---------------------------------------------------------------------------


def _agent(
    model: str,
    *,
    temperature: float = 1.0,
    max_tokens: int = 4000,
    json_mode: bool = False,
    price: PriceInfo | None = None,
) -> AgentConfig:
    """Build an OpenAI :class:`AgentConfig`.

    For reasoning models (``o1`` / ``o3`` / ``o4`` / ``o5``), temperature
    must be 1.0 — the API rejects any other value. The
    :meth:`OpenAIProvider._build_request` method enforces this at
    request-build time as a belt-and-braces measure.
    """
    agent = AgentConfig(
        model=model,
        temperature=temperature,
        n=1,
        max_tokens=max_tokens,
        price=price,
    )
    if json_mode:
        agent.json_mode = True
    return agent


def get_default_config() -> ProviderConfig:
    """Return the default OpenAI :class:`ProviderConfig`.

    Ported from ``openai/config.yml``. Strategy:
    * ``o4-mini`` (cost-effective reasoning) for all slots by default.
    * The caller can override per-slot via the YAML config.
    """
    cfg = ProviderConfig()
    cfg.simple = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=8192,
        price=_O4_MINI_PRICE,
    )
    cfg.simple_json = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=4096, json_mode=True,
        price=_O4_MINI_PRICE,
    )
    cfg.primary_agent = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=16384,
        price=_O4_MINI_PRICE,
    )
    cfg.assistant = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=16384,
        price=_O4_MINI_PRICE,
    )
    cfg.generator = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=32768,
        price=_O4_MINI_PRICE,
    )
    cfg.refiner = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=32768,
        price=_O4_MINI_PRICE,
    )
    cfg.adviser = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=16384,
        price=_O4_MINI_PRICE,
    )
    cfg.reflector = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=4096,
        price=_O4_MINI_PRICE,
    )
    cfg.searcher = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=4096,
        price=_O4_MINI_PRICE,
    )
    cfg.enricher = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=4096,
        price=_O4_MINI_PRICE,
    )
    cfg.coder = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=20480,
        price=_O4_MINI_PRICE,
    )
    cfg.installer = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=16384,
        price=_O4_MINI_PRICE,
    )
    cfg.pentester = _agent(
        "o4-mini",
        temperature=1.0, max_tokens=16384,
        price=_O4_MINI_PRICE,
    )
    return cfg


# ---------------------------------------------------------------------------
# OpenAIProvider
# ---------------------------------------------------------------------------


class OpenAIProvider(OpenAICompatProvider):
    """Standard OpenAI adapter (Python port of ``openaiProvider``).

    Construction is lazy — the ``openai`` Python SDK is imported inside
    :meth:`_get_client`. The API key is read from ``OPENAI_API_KEY``;
    the base URL defaults to :data:`OPENAI_DEFAULT_SERVER_URL` and is
    overridable via ``OPENAI_BASE_URL`` (or ``OPENAI_SERVER_URL`` for
    PentAGI compatibility).
    """

    PROVIDER_TYPE: ProviderType = ProviderType.OPENAI
    TOOL_CALL_ID_TEMPLATE: str = OPENAI_TOOL_CALL_ID_TEMPLATE
    DEFAULT_MODEL: str = OPENAI_DEFAULT_MODEL
    DEFAULT_BASE_URL: str = OPENAI_DEFAULT_SERVER_URL
    ENV_VAR_API_KEY: str = "OPENAI_API_KEY"
    ENV_VAR_BASE_URL: str = "OPENAI_BASE_URL"  # also accepts OPENAI_SERVER_URL
    ENV_VAR_PROVIDER_PREFIX: str = ""  # OpenAI doesn't use prefix passthrough

    MAX_429_RETRIES: int = OPENAI_MAX_429_RETRIES
    BASE_429_DELAY: float = OPENAI_429_BASE_DELAY

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        # Accept OPENAI_SERVER_URL as an alias for OPENAI_BASE_URL
        # (PentAGI compatibility).
        if base_url is None:
            base_url = (
                os.environ.get("OPENAI_BASE_URL")
                or os.environ.get("OPENAI_SERVER_URL")
                or None
            )
        super().__init__(api_key, base_url=base_url, **kwargs)

    @classmethod
    def get_default_config(cls) -> ProviderConfig:
        return get_default_config()

    @classmethod
    def get_default_models(cls) -> List[ModelConfig]:
        return list(OPENAI_DEFAULT_MODELS)

    # ------------------------------------------------------------------
    # OpenAI-specific overrides
    # ------------------------------------------------------------------

    def model_with_prefix(self, opt: ProviderOptionsType) -> str:
        """OpenAI provider doesn't need prefix support (passthrough mode
        in LiteLLM). Returns the bare model name — matches PentAGI's
        ``openaiProvider.ModelWithPrefix``."""
        return self.model(opt)

    @staticmethod
    def is_reasoning_model(model: str) -> bool:
        """Return ``True`` if ``model`` is in the OpenAI reasoning-model
        family (``o1``, ``o3``, ``o4``, ``o5`` prefixes). These models:

        * Require ``temperature=1.0`` (API rejects any other value).
        * Do NOT accept the ``system`` role — system prompts must be
          converted to the ``developer`` role.
        * Use ``max_completion_tokens`` instead of ``max_tokens`` (the
          openai SDK accepts both for backwards compatibility).
        """
        return any(
            model == p or model.startswith(p + "-") or model.startswith(p + "_")
            for p in OPENAI_REASONING_MODEL_PREFIXES
        )

    def _build_request(
        self,
        model: str,
        agent: Optional[AgentConfig],
        chain: list,
        tools: Optional[List[dict]],
    ) -> dict:
        """Build the OpenAI chat-completion request. For reasoning models
        (``o1``/``o3``/``o4``), rewrites ``system`` messages to
        ``developer`` role and forces ``temperature=1.0``."""
        request = super()._build_request(model, agent, chain, tools)
        if model and self.is_reasoning_model(model):
            # Rewrite system -> developer role
            for msg in request.get("messages", []):
                if msg.get("role") == "system":
                    msg["role"] = "developer"
            # Force temperature=1.0 (API rejects other values)
            request["temperature"] = 1.0
            # Use max_completion_tokens instead of max_tokens for
            # reasoning models (the openai SDK accepts both for
            # backwards compat; we set the modern name explicitly).
            if "max_tokens" in request:
                request["max_completion_tokens"] = request.pop("max_tokens")
        return request


__all__ = [
    "OPENAI_DEFAULT_SERVER_URL",
    "OPENAI_DEFAULT_MODEL",
    "OPENAI_TOOL_CALL_ID_TEMPLATE",
    "OPENAI_MAX_429_RETRIES",
    "OPENAI_429_BASE_DELAY",
    "OPENAI_REASONING_MODEL_PREFIXES",
    "OPENAI_DEFAULT_MODELS",
    "OpenAIProvider",
    "generate_tool_call_id",
    "get_default_config",
]

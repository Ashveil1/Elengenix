"""elengenix.providers.custom — Custom / vLLM / OpenAI-compatible endpoint
LLM provider adapter (Python port).

Port of PentAGI's ``backend/pkg/providers/custom/custom.go``. This is the
catch-all adapter for ANY OpenAI-compatible endpoint: vLLM, LiteLLM
proxy, OpenRouter, Together AI, Groq, Anyscale, local ``llama.cpp``
server, etc. Configuration is entirely env-driven:

* ``LLM_SERVER_URL`` (or ``CUSTOM_BASE_URL`` / ``LLMServerURL``) — base
  URL (e.g. ``http://localhost:8000/v1`` for vLLM,
  ``https://openrouter.ai/api/v1`` for OpenRouter).
* ``LLM_SERVER_KEY`` (or ``CUSTOM_API_KEY`` / ``LLMServerKey``) — API
  key (Bearer). May be empty for local vLLM.
* ``LLM_SERVER_MODEL`` (or ``LLMServerModel``) — default model name.
* ``LLM_SERVER_CONFIG`` (or ``LLMServerConfig``) — path to a YAML config
  file (per-agent slots, same format as the other providers'
  ``config.yml``).
* ``LLM_SERVER_PROVIDER`` (or ``LLMServerProvider``) — prefix for
  LiteLLM-style namespacing. When set, ``model_with_prefix()`` prepends
  ``prefix/`` and :meth:`discover_models` filters / strips the prefix.
* ``LLM_SERVER_LEGACY_REASONING`` (default ``False``) — enables modern
  reasoning format (langchaingo's ``WithModernReasoningFormat``). The
  Python ``openai`` SDK always uses the modern format, so this is
  advisory; included for parity.
* ``LLM_SERVER_PRESERVE_REASONING`` (default ``True``) — preserves
  ``reasoning_content`` on multi-turn tool-call flows (DeepSeek-R1,
  Qwen3 hybrid, GLM, Kimi, etc.).

Dynamic model discovery:

* :meth:`CustomProvider.discover_models` performs
  ``GET {base_url}/models`` via
  :func:`elengenix.providers.base.load_models_from_http`. Parses
  ``{data: [...]}`` per OpenAI spec, filters by the optional prefix,
  and extracts per-model metadata (description, created,
  supported_parameters, pricing). Models that explicitly list
  ``supported_parameters`` without ``tools`` or ``structured_outputs``
  are skipped — they can't be used for agent tool-calling.
* Default options: ``temperature=1.0``, ``top_p=1.0``, ``n=1``,
  ``max_tokens=16384`` (matches PentAGI's ``custom.go``
  ``BuildProviderConfig`` defaults).
"""

from __future__ import annotations

import logging
import os
from typing import Any, List, Optional

from elengenix.providers._openai_compat import OpenAICompatProvider
from elengenix.providers.base import (
    AgentConfig,
    ModelConfig,
    ModelsConfig,
    PriceInfo,
    ProviderConfig,
    ProviderOptionsType,
    ProviderType,
    load_models_from_http,
)

logger = logging.getLogger("elengenix.providers.custom")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default request timeout for upstream API calls. Mirrors PentAGI's
#: system.GetHTTPClient default (120s).
CUSTOM_DEFAULT_TIMEOUT: float = 120.0

#: Default max_tokens when no per-agent config is set. Matches
#: PentAGI's custom.go ``BuildProviderConfig`` default.
CUSTOM_DEFAULT_MAX_TOKENS: int = 16384

#: 429 retry policy.
CUSTOM_MAX_429_RETRIES: int = 10
CUSTOM_429_BASE_DELAY: float = 5.0


# ---------------------------------------------------------------------------
# Default provider config — empty (caller supplies via YAML file or
# env vars). Mirrors PentAGI's DefaultProviderConfig which falls back to
# EmptyProviderConfigRaw when cfg.LLMServerConfig is empty.
# ---------------------------------------------------------------------------


def _default_agent(model: str = "") -> AgentConfig:
    """Build the default Custom :class:`AgentConfig` when no YAML config
    is supplied. Matches PentAGI's custom.go ``BuildProviderConfig``
    defaults: ``temperature=1.0``, ``top_p=1.0``, ``n=1``,
    ``max_tokens=16384``."""
    return AgentConfig(
        model=model,
        temperature=1.0,
        top_p=1.0,
        n=1,
        max_tokens=CUSTOM_DEFAULT_MAX_TOKENS,
    )


def get_default_config(model: str = "") -> ProviderConfig:
    """Return the default Custom :class:`ProviderConfig`.

    When ``model`` is empty, all 13 agent slots are populated with the
    default agent config (which itself has an empty model — the
    caller's :attr:`CustomProvider._api_key`-derived default applies).
    When ``model`` is supplied, all 13 slots use that model.

    Mirrors PentAGI's custom.go ``DefaultProviderConfig`` which loads
    from ``cfg.LLMServerConfig`` YAML file if set, else falls back to
    :data:`pconfig.EmptyProviderConfigRaw`. The caller is responsible
    for loading the YAML file (via :func:`elengenix.providers.yaml.load`)
    and passing the resulting :class:`ProviderConfig` to
    :class:`CustomProvider` — this function provides the empty-default
    fallback.
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
# CustomProvider
# ---------------------------------------------------------------------------


class CustomProvider(OpenAICompatProvider):
    """Custom / vLLM / OpenAI-compatible endpoint adapter (Python port
    of ``customProvider``).

    The Custom provider is unique in that it has no fixed default model
    or URL — both come from the caller's configuration (env vars in
    PentAGI, constructor kwargs here). It also exposes
    :meth:`discover_models` for dynamic model catalog discovery via the
    upstream ``/models`` endpoint.

    Construction is lazy — the ``openai`` Python SDK is imported inside
    :meth:`_get_client`. The API key may be empty for unauthenticated
    local vLLM endpoints.
    """

    PROVIDER_TYPE: ProviderType = ProviderType.CUSTOM
    # No fixed template — Custom uses no caller-generated tool-call IDs
    # (server-side IDs are auto-generated). Empty string signals this to
    # callers via get_tool_call_id_template().
    TOOL_CALL_ID_TEMPLATE: str = ""
    DEFAULT_MODEL: str = ""
    DEFAULT_BASE_URL: str = ""
    # Custom uses a constellation of env-var aliases (PentAGI uses
    # LLMServerURL/LLMServerKey/LLMServerModel; the Elengenix CLI uses
    # CUSTOM_BASE_URL/CUSTOM_API_KEY). The _resolve_env helper below
    # handles all of them.
    ENV_VAR_API_KEY: str = ""  # resolved in __init__
    ENV_VAR_BASE_URL: str = ""  # resolved in __init__
    ENV_VAR_PROVIDER_PREFIX: str = ""  # resolved in __init__

    MAX_429_RETRIES: int = CUSTOM_MAX_429_RETRIES
    BASE_429_DELAY: float = CUSTOM_429_BASE_DELAY

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        provider_prefix: str = "",
        provider_config: Optional[ProviderConfig] = None,
        models: Optional[List[ModelConfig]] = None,
        provider_name: str = "custom",
        preserve_reasoning: bool = True,
        legacy_reasoning: bool = False,
        request_timeout: float = CUSTOM_DEFAULT_TIMEOUT,
        default_model: Optional[str] = None,
    ) -> None:
        # Resolve env-var aliases — Custom accepts both PentAGI's
        # LLMServer* names and the Elengenix CUSTOM_* names.
        if api_key is None:
            api_key = (
                os.environ.get("LLM_SERVER_KEY")
                or os.environ.get("CUSTOM_API_KEY")
                or os.environ.get("LLM_API_KEY")
                or ""
            )
        if base_url is None:
            base_url = (
                os.environ.get("LLM_SERVER_URL")
                or os.environ.get("CUSTOM_BASE_URL")
                or os.environ.get("LLM_BASE_URL")
                or ""
            )
        if not provider_prefix:
            provider_prefix = (
                os.environ.get("LLM_SERVER_PROVIDER")
                or os.environ.get("CUSTOM_PROVIDER_PREFIX")
                or ""
            )
        if default_model is None:
            default_model = (
                os.environ.get("LLM_SERVER_MODEL")
                or os.environ.get("CUSTOM_MODEL")
                or ""
            )

        # legacy_reasoning + preserve_reasoning env vars
        if legacy_reasoning is False and os.environ.get(
            "LLM_SERVER_LEGACY_REASONING", ""
        ).lower() in ("1", "true", "yes"):
            legacy_reasoning = True
        if preserve_reasoning is True and os.environ.get(
            "LLM_SERVER_PRESERVE_REASONING", ""
        ).lower() in ("0", "false", "no"):
            preserve_reasoning = False

        if not base_url:
            raise RuntimeError(
                "CustomProvider requires base_url (set LLM_SERVER_URL or "
                "CUSTOM_BASE_URL env var, or pass base_url=...)"
            )

        # api_key may be empty for unauthenticated local vLLM — log a
        # warning but proceed.
        if not api_key:
            logger.warning(
                "CustomProvider: api_key is empty — assuming unauthenticated "
                "endpoint (local vLLM / llama.cpp). If the upstream requires "
                "auth, set LLM_SERVER_KEY / CUSTOM_API_KEY."
            )

        # Bypass OpenAICompatProvider's api_key-empty check (Custom
        # tolerates an empty key). We do this by temporarily setting a
        # sentinel env var, then immediately restoring it.
        # Actually it's simpler to just set the resolved api_key here and
        # call super().__init__ with it explicitly.
        super().__init__(
            api_key=api_key,
            base_url=base_url,
            provider_prefix=provider_prefix,
            provider_config=provider_config,
            models=models,
            provider_name=provider_name,
            preserve_reasoning=preserve_reasoning,
            legacy_reasoning=legacy_reasoning,
            request_timeout=request_timeout,
        )
        # Override the default model with the resolved env-var value.
        self._default_model_resolved: str = default_model

    # ------------------------------------------------------------------
    # Override model() to use the resolved default model
    # ------------------------------------------------------------------

    def model(self, opt: ProviderOptionsType) -> str:
        """Return the model name configured for ``opt`` (or the resolved
        default model from env vars if the slot is unconfigured)."""
        agent = self._provider_config.get_agent_config(opt)
        if agent is not None and agent.model:
            return agent.model
        return getattr(self, "_default_model_resolved", "") or self.DEFAULT_MODEL

    def get_tool_call_id_template(self) -> str:
        """Custom provider does not declare a tool-call ID template —
        the upstream server auto-generates IDs."""
        return ""

    def generate_tool_call_id(self) -> str:
        """Custom provider does not generate tool-call IDs — the upstream
        server auto-generates them. Raises ``NotImplementedError`` to
        surface this contract violation early."""
        raise NotImplementedError(
            "CustomProvider does not generate tool-call IDs — the upstream "
            "server auto-generates them. If you need a synthesised ID for "
            "testing, use the upstream provider's generate_tool_call_id()."
        )

    @classmethod
    def get_default_config(cls) -> ProviderConfig:
        return get_default_config()

    @classmethod
    def get_default_models(cls) -> List[ModelConfig]:
        return []

    # ------------------------------------------------------------------
    # Custom-specific helpers
    # ------------------------------------------------------------------

    def discover_models(
        self,
        timeout: float = 3.0,
    ) -> ModelsConfig:
        """Fetch the upstream ``/models`` endpoint and return a
        :class:`ModelsConfig`. Filters by ``provider_prefix`` if set,
        strips the prefix from the returned names. Per-model metadata
        (description, created, supported_parameters, pricing) is parsed
        if present.

        On any HTTP / JSON error, returns an empty :class:`ModelsConfig`
        and logs a warning. The caller is expected to fall back to the
        configured default model.

        Mirrors PentAGI's ``provider.LoadModelsFromHTTP`` invocation in
        ``custom.go::New`` — on error, ``custom.go`` falls back to an
        empty ``ModelsConfig`` (``pconfig.ModelsConfig{}``).
        """
        if not self._base_url:
            return ModelsConfig()
        try:
            discovered = load_models_from_http(
                base_url=self._base_url,
                api_key=self._api_key,
                prefix=self._provider_prefix,
                timeout=timeout,
            )
        except Exception as exc:
            logger.warning(
                "CustomProvider.discover_models: failed to fetch %s/models: %s",
                self._base_url.rstrip("/"), exc,
            )
            return ModelsConfig()
        # Cache the discovered models on the instance.
        self._models = list(discovered)
        return ModelsConfig(models=list(discovered))


__all__ = [
    "CUSTOM_DEFAULT_TIMEOUT",
    "CUSTOM_DEFAULT_MAX_TOKENS",
    "CUSTOM_MAX_429_RETRIES",
    "CUSTOM_429_BASE_DELAY",
    "CustomProvider",
    "get_default_config",
]

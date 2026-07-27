"""elengenix.providers.registry — Provider registry for all 10 LLM providers.

This module exposes :class:`ProviderRegistry`, the central factory used
by the Elengenix orchestrator to look up concrete
:class:`~elengenix.providers.base.Provider` instances by
:class:`~elengenix.providers.base.ProviderType`.

The registry pattern matches PentAGI's
``backend/pkg/providers/providers.go::providerController`` (factory
registration + ``NewProvider(db.Provider)`` switch), with two
differences:

1. **Lazy adapter loading** — concrete adapter modules (``bedrock``,
   ``deepseek``, …) are imported on first use, not at registry
   construction. This keeps ``import elengenix.providers`` cheap and
   means an environment without ``boto3`` installed can still use the
   OpenAI provider.
2. **Env-var availability probe** — :meth:`list_available_providers`
   inspects the standard env vars for each provider (``OPENAI_API_KEY``,
   ``ANTHROPIC_API_KEY``, ``DEEPSEEK_API_KEY``, ``AWS_ACCESS_KEY_ID``
   / ``BEDROCK_ACCESS_KEY``, …) so the CLI can show the user which
   providers are ready without attempting a network call.

Only Bedrock and DeepSeek adapters ship with full implementations in
this Phase 7-a drop; the remaining 8 providers are registered as
``NotImplementedError`` stubs that other Phase 7 subagents will fill in.
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Dict

from elengenix.providers.base import (
    Provider,
    ProviderConfig,
    ProviderType,
)

logger = logging.getLogger("elengenix.providers.registry")


# ---------------------------------------------------------------------------
# Env-var probe table — maps ProviderType -> list of env vars where at
# least one must be set for the provider to be considered "available".
# Mirrors PentAGI's per-provider ``New()`` env-var checks.
# ---------------------------------------------------------------------------


_PROVIDER_ENV_VARS: dict[ProviderType, list[tuple[str, ...]]] = {
    # Each tuple is a set of env vars of which ANY one being set is OK.
    # Multiple tuples mean ALL tuples must have at least one var set.
    ProviderType.OPENAI: [("OPENAI_API_KEY",)],
    ProviderType.ANTHROPIC: [("ANTHROPIC_API_KEY",)],
    ProviderType.GEMINI: [("GEMINI_API_KEY", "GOOGLE_API_KEY")],
    ProviderType.BEDROCK: [
        ("BEDROCK_DEFAULT_AUTH", "AWS_ACCESS_KEY_ID", "BEDROCK_ACCESS_KEY",
         "BEDROCK_BEARER_TOKEN", "AWS_PROFILE"),
    ],
    ProviderType.OLLAMA: [("OLLAMA_HOST", "OLLAMA_BASE_URL", "OLLAMA_API_KEY")],
    ProviderType.CUSTOM: [("CUSTOM_API_KEY", "CUSTOM_BASE_URL", "LLM_API_KEY")],
    ProviderType.DEEPSEEK: [("DEEPSEEK_API_KEY",)],
    ProviderType.GLM: [("GLM_API_KEY", "ZAI_API_KEY", "ZHIPUAI_API_KEY")],
    ProviderType.KIMI: [("KIMI_API_KEY", "MOONSHOT_API_KEY")],
    ProviderType.QWEN: [("QWEN_API_KEY", "DASHSCOPE_API_KEY")],
}


# ---------------------------------------------------------------------------
# ProviderRegistry
# ---------------------------------------------------------------------------


#: Type of a provider factory function: takes a ProviderConfig (or None
#: for the provider's default) and returns a Provider instance.
ProviderFactory = Callable[[ProviderConfig | None], Provider]


class ProviderRegistry:
    """Factory + lookup table for all 10 LLM providers.

    Usage::

        from elengenix.providers.registry import ProviderRegistry
        from elengenix.providers.base import ProviderType

        registry = ProviderRegistry.default()
        bedrock = registry.get_provider(ProviderType.BEDROCK)
        print(registry.list_available_providers())
    """

    def __init__(self) -> None:
        self._factories: dict[ProviderType, ProviderFactory] = {}
        self._default_configs: dict[ProviderType, ProviderConfig] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        provider_type: ProviderType,
        factory: ProviderFactory,
        default_config: ProviderConfig | None = None,
    ) -> None:
        """Register a provider ``factory`` under ``provider_type``.

        ``default_config`` is the config returned by
        :meth:`get_default_config` when no explicit config is passed to
        :meth:`get_provider`.
        """
        self._factories[provider_type] = factory
        if default_config is not None:
            self._default_configs[provider_type] = default_config
        logger.debug("registered provider %s", provider_type.value)

    def register_default_config(
        self,
        provider_type: ProviderType,
        default_config: ProviderConfig,
    ) -> None:
        """Attach (or replace) the default config for ``provider_type``."""
        self._default_configs[provider_type] = default_config

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_provider(
        self,
        provider_type: ProviderType,
        config: ProviderConfig | None = None,
    ) -> Provider:
        """Instantiate and return the provider for ``provider_type``.

        Raises ``KeyError`` if no factory is registered for the type.
        ``config`` overrides the registry's default config when supplied.
        """
        factory = self._factories.get(provider_type)
        if factory is None:
            raise KeyError(
                f"no provider factory registered for {provider_type!r}; "
                f"available: {[t.value for t in self._factories]}"
            )
        effective_config = config if config is not None else self._default_configs.get(
            provider_type
        )
        return factory(effective_config)

    def list_available_providers(self) -> list[ProviderType]:
        """Return all provider types whose env vars are satisfied.

        Probes the env vars in :data:`_PROVIDER_ENV_VARS`; a provider is
        "available" when at least one env var from each tuple in its
        entry is set. Providers without an env-var probe are always
        considered available (e.g. Ollama running locally without auth).
        """
        available: list[ProviderType] = []
        for provider_type, env_var_groups in _PROVIDER_ENV_VARS.items():
            if not env_var_groups:
                available.append(provider_type)
                continue
            if all(
                any(os.environ.get(var) for var in group)
                for group in env_var_groups
            ):
                available.append(provider_type)
        return available

    def list_registered_providers(self) -> list[ProviderType]:
        """Return all provider types with a registered factory."""
        return list(self._factories.keys())

    def get_default_config(self, provider_type: ProviderType) -> ProviderConfig:
        """Return the default :class:`ProviderConfig` for ``provider_type``.

        Raises ``KeyError`` if no default config is registered.
        """
        if provider_type not in self._default_configs:
            raise KeyError(
                f"no default config registered for {provider_type!r}"
            )
        return self._default_configs[provider_type]

    # ------------------------------------------------------------------
    # Default registry — wires up the adapters shipped in this drop.
    # ------------------------------------------------------------------

    @classmethod
    def default(cls) -> ProviderRegistry:
        """Return a registry with all shippable providers registered.

        Bedrock and DeepSeek ship with full implementations in this
        Phase 7-a drop. The remaining 8 providers (OpenAI, Anthropic,
        Gemini, Ollama, Custom, GLM, Kimi, Qwen) are registered as
        stubs that raise ``NotImplementedError`` until later Phase 7
        subagents fill them in. ``list_available_providers`` still
        reports all 10 based on env-var probing, so the CLI can show
        the user which providers are *configured*.
        """
        registry = cls()

        # Bedrock — full implementation.
        registry.register(
            ProviderType.BEDROCK,
            _bedrock_factory,
            default_config=_bedrock_default_config(),
        )

        # DeepSeek — full implementation.
        registry.register(
            ProviderType.DEEPSEEK,
            _deepseek_factory,
            default_config=_deepseek_default_config(),
        )

        # Best-effort registration of the remaining 8 providers. These
        # are implemented by parallel Phase 7 subagents in their own
        # modules (``openai.py``, ``anthropic.py``, ``gemini.py``,
        # ``ollama.py``, ``custom.py``, ``glm.py``, ``kimi.py``,
        # ``qwen.py``). Each adapter uses the shared ``_common.py``
        # abstraction layer (a sibling module to this one). We try to
        # import each factory here; on any failure we fall back to a
        # ``NotImplementedError`` stub so the registry always reports
        # the full set of 10 providers.
        for provider_type, factory_factory in (
            (ProviderType.OPENAI, _make_openai_factory),
            (ProviderType.ANTHROPIC, _make_anthropic_factory),
            (ProviderType.GEMINI, _make_gemini_factory),
            (ProviderType.OLLAMA, _make_ollama_factory),
            (ProviderType.CUSTOM, _make_custom_factory),
            (ProviderType.GLM, _make_glm_factory),
            (ProviderType.KIMI, _make_kimi_factory),
            (ProviderType.QWEN, _make_qwen_factory),
        ):
            try:
                factory, default_config = factory_factory()
                registry.register(provider_type, factory, default_config=default_config)
            except Exception as exc:  # noqa: BLE001 — best-effort only
                logger.debug(
                    "provider %s not yet available (%s); registering stub",
                    provider_type.value,
                    exc,
                )
                registry.register(provider_type, _make_stub_factory(provider_type))

        return registry


# ---------------------------------------------------------------------------
# Factory functions — imported lazily so the registry module loads
# without boto3 / openai installed.
# ---------------------------------------------------------------------------


def _bedrock_factory(config: ProviderConfig | None) -> Provider:
    """Construct a :class:`BedrockProvider` from env + optional config."""
    from elengenix.providers.bedrock import (
        BEDROCK_DEFAULT_MODEL,
        BedrockProvider,
        resolve_auth_from_env,
    )

    region = os.environ.get("BEDROCK_REGION", os.environ.get("AWS_REGION", "us-east-1"))
    server_url = os.environ.get("BEDROCK_SERVER_URL", "")
    return BedrockProvider(
        auth=resolve_auth_from_env(),
        region_name=region,
        server_url=server_url,
        provider_config=config,
        provider_name="bedrock",
    )


def _deepseek_factory(config: ProviderConfig | None) -> Provider:
    """Construct a :class:`DeepSeekProvider` from env + optional config."""
    from elengenix.providers.deepseek import DeepSeekProvider

    return DeepSeekProvider(
        api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
        base_url=os.environ.get("DEEPSEEK_SERVER_URL") or None,
        provider_prefix=os.environ.get("DEEPSEEK_PROVIDER", ""),
        provider_config=config,
        provider_name="deepseek",
    )


def _bedrock_default_config() -> ProviderConfig:
    """Return Bedrock's default :class:`ProviderConfig`."""
    from elengenix.providers.bedrock import get_default_config

    return get_default_config()


def _deepseek_default_config() -> ProviderConfig:
    """Return DeepSeek's default :class:`ProviderConfig`."""
    from elengenix.providers.deepseek import get_default_config

    return get_default_config()


def _make_stub_factory(provider_type: ProviderType) -> ProviderFactory:
    """Build a factory that raises NotImplementedError when called.

    Used for the 8 providers not yet implemented in this drop. The
    error message tells the caller which Phase 7 subagent will fill it
    in.
    """

    def _factory(_config: ProviderConfig | None) -> Provider:  # noqa: ANN202
        raise NotImplementedError(
            f"provider {provider_type.value!r} is not yet implemented; "
            "it will be added by a later Phase 7 subagent. "
            "Bedrock and DeepSeek are available now."
        )

    return _factory


# ---------------------------------------------------------------------------
# Best-effort factories for the 8 sibling-provider adapters authored by
# parallel Phase 7 subagents. Each ``_make_<provider>_factory`` returns
# a ``(factory, default_config)`` tuple on success or raises on import
# failure (caught by ``ProviderRegistry.default``).
#
# The sibling adapters live in ``elengenix/providers/<name>.py``. They
# share the ``OpenAICompatProvider`` mixin (for GLM/Kimi/Qwen/Custom/
# OpenAI) and have self-contained sync implementations for Anthropic /
# Gemini / Ollama. Each constructor takes ``api_key=None, *,
# base_url=None, provider_prefix="", provider_config=None, models=None,
# provider_name="..."`` (matching the deepseek.py adapter pattern), and
# reads env vars when args are not supplied explicitly.
# ---------------------------------------------------------------------------


def _make_openai_factory() -> tuple[ProviderFactory, ProviderConfig]:
    """Build the OpenAI factory + default config from the sibling adapter."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    from elengenix.providers.openai import OpenAIProvider, get_default_config

    default_config = get_default_config()

    def factory(_pcfg: ProviderConfig | None) -> Provider:  # noqa: ANN202
        return OpenAIProvider(api_key=api_key, provider_config=_pcfg)

    return factory, default_config


def _make_anthropic_factory() -> tuple[ProviderFactory, ProviderConfig]:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    from elengenix.providers.anthropic import (
        AnthropicProvider,
        get_default_config,
    )

    default_config = get_default_config()

    def factory(_pcfg: ProviderConfig | None) -> Provider:  # noqa: ANN202
        return AnthropicProvider(api_key=api_key, provider_config=_pcfg)

    return factory, default_config


def _make_gemini_factory() -> tuple[ProviderFactory, ProviderConfig]:
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY", "")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY/GOOGLE_API_KEY not set")
    from elengenix.providers.gemini import GeminiProvider, get_default_config

    default_config = get_default_config()

    def factory(_pcfg: ProviderConfig | None) -> Provider:  # noqa: ANN202
        return GeminiProvider(api_key=api_key, provider_config=_pcfg)

    return factory, default_config


def _make_ollama_factory() -> tuple[ProviderFactory, ProviderConfig]:
    # Ollama doesn't require an API key — local inference.
    from elengenix.providers.ollama import OllamaProvider, get_default_config

    default_config = get_default_config(
        os.environ.get("OLLAMA_SERVER_MODEL", "")
    )

    def factory(_pcfg: ProviderConfig | None) -> Provider:  # noqa: ANN202
        return OllamaProvider(provider_config=_pcfg)

    return factory, default_config


def _make_custom_factory() -> tuple[ProviderFactory, ProviderConfig]:
    base_url = (
        os.environ.get("LLM_SERVER_URL")
        or os.environ.get("CUSTOM_BASE_URL", "")
    )
    if not base_url:
        raise RuntimeError("LLM_SERVER_URL/CUSTOM_BASE_URL not set")
    from elengenix.providers.custom import CustomProvider, get_default_config

    default_config = get_default_config(
        os.environ.get("LLM_SERVER_MODEL", "")
    )

    def factory(_pcfg: ProviderConfig | None) -> Provider:  # noqa: ANN202
        return CustomProvider(provider_config=_pcfg)

    return factory, default_config


def _make_glm_factory() -> tuple[ProviderFactory, ProviderConfig]:
    api_key = (
        os.environ.get("GLM_API_KEY")
        or os.environ.get("ZAI_API_KEY")
        or os.environ.get("ZHIPUAI_API_KEY", "")
    )
    if not api_key:
        raise RuntimeError("GLM_API_KEY/ZAI_API_KEY not set")
    from elengenix.providers.glm import GLMProvider, get_default_config

    default_config = get_default_config()

    def factory(_pcfg: ProviderConfig | None) -> Provider:  # noqa: ANN202
        return GLMProvider(api_key=api_key, provider_config=_pcfg)

    return factory, default_config


def _make_kimi_factory() -> tuple[ProviderFactory, ProviderConfig]:
    api_key = (
        os.environ.get("KIMI_API_KEY")
        or os.environ.get("MOONSHOT_API_KEY", "")
    )
    if not api_key:
        raise RuntimeError("KIMI_API_KEY/MOONSHOT_API_KEY not set")
    from elengenix.providers.kimi import KimiProvider, get_default_config

    default_config = get_default_config()

    def factory(_pcfg: ProviderConfig | None) -> Provider:  # noqa: ANN202
        return KimiProvider(api_key=api_key, provider_config=_pcfg)

    return factory, default_config


def _make_qwen_factory() -> tuple[ProviderFactory, ProviderConfig]:
    api_key = (
        os.environ.get("QWEN_API_KEY")
        or os.environ.get("DASHSCOPE_API_KEY", "")
    )
    if not api_key:
        raise RuntimeError("QWEN_API_KEY/DASHSCOPE_API_KEY not set")
    from elengenix.providers.qwen import QwenProvider, get_default_config

    default_config = get_default_config()

    def factory(_pcfg: ProviderConfig | None) -> Provider:  # noqa: ANN202
        return QwenProvider(api_key=api_key, provider_config=_pcfg)

    return factory, default_config


# ---------------------------------------------------------------------------
# Module-level singleton — convenience accessor.
# ---------------------------------------------------------------------------


_DEFAULT_REGISTRY: ProviderRegistry | None = None


def get_default_registry() -> ProviderRegistry:
    """Return the process-wide default :class:`ProviderRegistry`.

    Lazily constructed on first call so import-time side effects are
    minimised. Equivalent to PentAGI's ``providerController`` singleton.
    """
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = ProviderRegistry.default()
    return _DEFAULT_REGISTRY


__all__ = [
    "ProviderFactory",
    "ProviderRegistry",
    "get_default_registry",
]

"""elengenix/providers/catalog.py — Single source of truth for AI providers.

Every AI-provider catalog in the codebase used to be hand-maintained in
five places (tools/ai_config.py, tools/universal_ai_client.py,
tools/config_wizard.py, tools/welcome_wizard.py, tools/overlay_menu.py).
They drifted: wizards offered providers the runtime could not resolve,
default models differed per file, and adding one provider meant editing
five modules.

This module is now the **only** place that defines provider metadata.
It is stdlib-only so any layer (including tools/ai_config, which is
imported at startup) can derive from it without circular imports.

Consumers derive their views with :func:`iter_specs` / :func:`spec` /
:func:`env_key_for` / :func:`priority_order` — they must not keep their
own copies of provider ids, env keys, base URLs, or default models.

Two model fields exist on purpose:

* ``default_model``  — what the runtime client uses when nothing else is
  configured (kept identical to the historical UniversalAIClient value).
* ``recommended_model`` — what wizards pre-select in menus (the richer
  curated choice).

``models`` is the curated menu list shown by ``elengenix configure``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, Optional, Tuple

__all__ = [
    "PROVIDERS",
    "PROVIDER_IDS",
    "ProviderSpec",
    "SPECIAL_IDS",
    "env_key_for",
    "get_provider_config",
    "iter_specs",
    "priority_order",
    "provider_defaults",
    "spec",
]


@dataclass(frozen=True)
class ProviderSpec:
    """Metadata for one AI provider.

    Attributes:
        id: Canonical lowercase id used by config.yaml, env resolution and
            the universal client (e.g. ``"gemini"``).
        display: Human-facing name for wizards/menus.
        env_key: Environment variable holding the API key
            (``None`` for key-free local providers).
        base_url: OpenAI-compatible (or native) endpoint.
        default_model: Runtime fallback model.
        recommended_model: Model wizards pre-select.
        models: Curated model menu (first entry is the wizard default).
        tagline: One-line description used by the first-run wizard.
        signup_url: Where to obtain an API key.
        is_free: Provider has a usable free tier.
        api_format: ``"openai"`` (chat/completions compatible) or
            ``"native"`` (provider-specific protocol).
        key_free: Needs no API key (local servers).
        priority: Lower = higher fallback priority (AIClientManager order).
    """

    id: str
    display: str
    env_key: Optional[str]
    base_url: str
    default_model: str
    recommended_model: str = ""
    models: Tuple[str, ...] = field(default=())
    tagline: str = ""
    signup_url: str = ""
    is_free: bool = False
    api_format: str = "openai"
    key_free: bool = False
    priority: int = 999


PROVIDERS: Tuple[ProviderSpec, ...] = (
    ProviderSpec(
        id="nvidia",
        display="NVIDIA",
        env_key="NVIDIA_API_KEY",
        base_url="https://integrate.api.nvidia.com/v1",
        default_model="nvidia/nemotron-3-super-120b-a12b",
        recommended_model="meta/llama3-70b-instruct",
        models=(
            "nvidia/nemotron-3-super-120b-a12b",
            "qwen/qwen2.5-coder-32b-instruct",
            "meta/llama3-70b-instruct",
            "mistralai/mixtral-8x22b-instruct-v0.1",
            "deepseek-ai/deepseek-r1",
        ),
        tagline="Fast NIM endpoints, free tier",
        signup_url="https://build.nvidia.com/explore/discover",
        is_free=True,
        priority=1,
    ),
    ProviderSpec(
        id="gemini",
        display="Gemini (Google)",
        env_key="GEMINI_API_KEY",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        default_model="gemini-2.5-flash",
        recommended_model="gemini-3.1-pro",
        models=(
            "gemini-3.1-flash-lite-preview",
            "gemini-3.1-pro",
            "gemini-3.1-flash",
            "gemini-3.0-pro",
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-1.5-pro",
            "gemini-1.5-flash",
        ),
        tagline="Free, fast, good Thai support",
        signup_url="https://aistudio.google.com/app/apikey",
        is_free=True,
        # OpenAI-compatible endpoint (no /v1 suffix) — the universal client
        # speaks chat/completions to it directly.
        api_format="openai",
        priority=2,
    ),
    ProviderSpec(
        id="openai",
        display="OpenAI",
        env_key="OPENAI_API_KEY",
        base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini",
        recommended_model="gpt-4.5-turbo",
        models=(
            "gpt-4.5-turbo",
            "gpt-4o",
            "gpt-4o-mini",
            "o2-preview",
            "o1-preview",
            "o1-mini",
        ),
        tagline="Most accurate",
        signup_url="https://platform.openai.com/api-keys",
        priority=3,
    ),
    ProviderSpec(
        id="anthropic",
        display="Anthropic",
        env_key="ANTHROPIC_API_KEY",
        base_url="https://api.anthropic.com/v1",
        default_model="claude-sonnet-4-20250514",
        recommended_model="claude-3-7-sonnet-latest",
        models=(
            "claude-3-7-sonnet-latest",
            "claude-3-5-sonnet-latest",
            "claude-3-5-haiku-latest",
            "claude-3-opus-latest",
        ),
        tagline="Best reasoning",
        signup_url="https://console.anthropic.com/settings/keys",
        api_format="native",
        priority=4,
    ),
    ProviderSpec(
        id="groq",
        display="Groq",
        env_key="GROQ_API_KEY",
        base_url="https://api.groq.com/openai/v1",
        default_model="llama-3.3-70b-versatile",
        recommended_model="llama-3.3-70b-versatile",
        models=(
            "llama-3.3-70b-versatile",
            "llama-3.1-70b-versatile",
            "llama-3.1-8b-instant",
        ),
        tagline="Very fast, free tier",
        signup_url="https://console.groq.com/keys",
        is_free=True,
        priority=5,
    ),
    ProviderSpec(
        id="deepseek",
        display="DeepSeek",
        env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com/v1",
        default_model="deepseek-chat",
        recommended_model="deepseek-chat",
        models=("deepseek-chat", "deepseek-reasoner"),
        tagline="Very affordable, strong performance",
        signup_url="https://platform.deepseek.com/api_keys",
        is_free=True,
        priority=6,
    ),
    ProviderSpec(
        id="mistral",
        display="Mistral",
        env_key="MISTRAL_API_KEY",
        base_url="https://api.mistral.ai/v1",
        default_model="mistral-large-latest",
        recommended_model="mistral-large-latest",
        models=(
            "mistral-large-latest",
            "mistral-small-latest",
            "open-mixtral-8x7b",
        ),
        tagline="Free tier, Mistral 7B/8x7B",
        signup_url="https://console.mistral.ai/api-keys",
        is_free=True,
        priority=7,
    ),
    ProviderSpec(
        id="openrouter",
        display="OpenRouter",
        env_key="OPENROUTER_API_KEY",
        base_url="https://openrouter.ai/api/v1",
        default_model="meta-llama/llama-3.3-70b-instruct",
        recommended_model="auto",
        models=(
            "meta-llama/llama-3.3-70b-instruct",
            "google/gemini-2.0-flash-exp:free",
            "auto",
        ),
        tagline="Multiple models via one API",
        signup_url="https://openrouter.ai/keys",
        is_free=True,
        priority=8,
    ),
    ProviderSpec(
        id="together",
        display="Together AI",
        env_key="TOGETHER_API_KEY",
        base_url="https://api.together.xyz/v1",
        default_model="meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        recommended_model="meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        models=(
            "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
            "mistralai/Mixtral-8x7B-Instruct-v0.1",
        ),
        tagline="Free tier, fast inference",
        signup_url="https://api.together.xyz/settings/api-keys",
        is_free=True,
        priority=9,
    ),
    ProviderSpec(
        id="perplexity",
        display="Perplexity",
        env_key="PERPLEXITY_API_KEY",
        base_url="https://api.perplexity.ai",
        default_model="llama-3.1-sonar-large-128k-online",
        recommended_model="llama-3.1-sonar-large-128k-online",
        models=(
            "llama-3.1-sonar-large-128k-online",
            "llama-3.1-sonar-small-128k-online",
        ),
        tagline="Free tier, good for research",
        signup_url="https://www.perplexity.ai/settings/api",
        is_free=True,
        priority=10,
    ),
    ProviderSpec(
        # OpenCode Zen — OpenAI-compatible gateway (https://opencode.ai/zen/v1)
        # exposing tier-1 models: Claude 5.x/4.x, GPT-5.x, Gemini 3.x, Kimi K3,
        # DeepSeek V4, Grok, Qwen3.6, GLM-5.x, MiniMax M3 — plus free tiers.
        id="opencode",
        display="OpenCode Zen",
        env_key="OPENCODE_API_KEY",
        base_url="https://opencode.ai/zen/v1",
        default_model="gpt-5.4-mini",
        recommended_model="gpt-5.4-mini",
        models=(
            "gpt-5.4-mini",
            "claude-sonnet-4-20250514",
            "gemini-2.5-flash",
        ),
        tagline="Tier-1 model gateway with free tiers",
        signup_url="https://opencode.ai/auth",
        is_free=True,
        priority=11,
    ),
    ProviderSpec(
        id="cohere",
        display="Cohere",
        env_key="COHERE_API_KEY",
        base_url="https://api.cohere.ai/v1",
        default_model="command-r-plus",
        recommended_model="command-r-plus",
        models=("command-r-plus", "command-r"),
        tagline="Free tier available, good for text generation",
        signup_url="https://dashboard.cohere.com/api-keys",
        is_free=True,
        api_format="native",
        priority=12,
    ),
    ProviderSpec(
        id="huggingface",
        display="Hugging Face",
        env_key="HUGGINGFACE_API_KEY",
        base_url="https://api-inference.huggingface.co",
        default_model="meta-llama/Llama-3.1-8B-Instruct",
        recommended_model="meta-llama/Llama-3.1-8B-Instruct",
        models=("meta-llama/Llama-3.1-8B-Instruct",),
        tagline="Free inference for many models",
        signup_url="https://huggingface.co/settings/tokens",
        is_free=True,
        api_format="native",
        priority=13,
    ),
    ProviderSpec(
        id="replicate",
        display="Replicate",
        env_key="REPLICATE_API_TOKEN",
        base_url="https://api.replicate.com/v1",
        default_model="meta/meta-llama-3-70b-instruct",
        recommended_model="meta/meta-llama-3-70b-instruct",
        models=("meta/meta-llama-3-70b-instruct",),
        tagline="Pay-as-you-go, many open-source models",
        signup_url="https://replicate.com/account/api-tokens",
        is_free=True,
        api_format="native",
        priority=14,
    ),
    ProviderSpec(
        id="ollama",
        display="Ollama (Local)",
        env_key=None,
        base_url="http://localhost:11434/v1",
        default_model="llama3.2",
        recommended_model="llama3.2",
        models=("llama3.2", "llama3.1:8b", "mistral:7b", "codellama:7b"),
        tagline="Runs AI on your machine, no API key needed",
        signup_url="https://ollama.com/download",
        is_free=True,
        key_free=True,
        priority=15,
    ),
)

#: Non-provider sentinel ids kept for backwards compatibility
#: (``custom`` = any OpenAI-compatible endpoint with a user-supplied URL).
SPECIAL_IDS: Tuple[str, ...] = ("custom",)

_BY_ID: Dict[str, ProviderSpec] = {p.id: p for p in PROVIDERS}

PROVIDER_IDS: Tuple[str, ...] = tuple(p.id for p in PROVIDERS)


def iter_specs() -> Iterator[ProviderSpec]:
    """Iterate all provider specs in catalog definition order."""
    return iter(PROVIDERS)


def spec(provider_id: str) -> Optional[ProviderSpec]:
    """Return the spec for *provider_id* (or ``None``)."""
    return _BY_ID.get(provider_id)


def env_key_for(provider_id: str) -> Optional[str]:
    """Default env var name for *provider_id*'s API key (``None`` if key-free).

    Includes the ``custom`` sentinel (``CUSTOM_API_KEY``) to stay compatible
    with the historical tools.ai_config mapping.
    """
    if provider_id == "custom":
        return "CUSTOM_API_KEY"
    found = _BY_ID.get(provider_id)
    return found.env_key if found else None


def priority_order() -> Tuple[str, ...]:
    """Provider ids sorted by fallback priority (index 0 = highest)."""
    return tuple(p.id for p in sorted(PROVIDERS, key=lambda p: p.priority))


def provider_defaults(provider_id: str) -> Optional[Dict[str, object]]:
    """Return ``{base_url, env_key, default_model}`` for *provider_id*.

    The exact shape historically consumed by ``UniversalAIClient``.
    """
    found = _BY_ID.get(provider_id)
    if not found:
        return None
    return {
        "base_url": found.base_url,
        "env_key": found.env_key,
        "default_model": found.default_model,
    }


def get_provider_config(provider_id: str) -> Dict[str, object]:
    """Return the default config dict for *provider_id* (``{}`` if unknown)."""
    return dict(provider_defaults(provider_id) or {})

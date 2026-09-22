"""elengenix.providers — LLM provider abstraction layer for Elengenix.

This package is the Python port of PentAGI's
``backend/pkg/providers/`` (Go). It defines a single
:class:`~elengenix.providers.base.Provider` Protocol implemented by 10
concrete adapters, plus the data models, helpers, and registry that
glue them together.

Providers implemented in this drop (Phases 7-a + 7-b)
---------------------------------------------------
Phase 7-a (base + bedrock + deepseek):
* :class:`elengenix.providers.bedrock.BedrockProvider` — AWS Bedrock
  Converse API adapter (3 auth modes, ``$schema`` cleanup, 429 retry,
  Claude 4.x / Nova / Cohere / DeepSeek / GPT-OSS / Qwen3 / Mistral /
  Kimi K2.5 model catalog).
* :class:`elengenix.providers.deepseek.DeepSeekProvider` — DeepSeek V4
  OpenAI-compatible adapter (``reasoning_content`` preservation,
  ``reasoning_effort`` string format, ``deepseek-v4-flash`` /
  ``deepseek-v4-pro`` model catalog).

Phase 7-b (8 remaining LLM providers):
* :class:`elengenix.providers.openai.OpenAIProvider` — Standard OpenAI
  Chat Completions API (``o4-mini`` default, reasoning-model system→
  developer role rewrite, ``call_{r:24:b}`` tool-call IDs).
* :class:`elengenix.providers.anthropic.AnthropicProvider` — Anthropic
  Messages API (``claude-sonnet-4-20250514`` default, extended thinking
  with cryptographic signatures, inline cache_control markers,
  ``toolu_{r:24:b}`` tool-call IDs).
* :class:`elengenix.providers.gemini.GeminiProvider` — Google Gemini
  (``gemini-2.5-flash`` default, ``thought_signature`` contract for
  multi-turn tool calls, implicit/explicit caching, ``{r:8:x}`` IDs).
* :class:`elengenix.providers.ollama.OllamaProvider` — Local Ollama
  (optional auth, model auto-pull, model discovery via ``/api/list``).
* :class:`elengenix.providers.custom.CustomProvider` — Any OpenAI-
  compatible endpoint (vLLM / LiteLLM proxy / OpenRouter / Together /
  Groq), with dynamic model discovery via ``/models``.
* :class:`elengenix.providers.glm.GLMProvider` — Z.AI GLM
  (``glm-4.7-flashx`` default, thinking control via
  ``extra_body.thinking.type``, preserved thinking via
  ``clear_thinking=false``, ``call_-{r:19:d}`` IDs).
* :class:`elengenix.providers.kimi.KimiProvider` — Moonshot Kimi
  (``kimi-k2.5`` default, hard thinking-mode constraints,
  ``thinking.keep=all`` for K2.6, ``{f}:{r:1:d}`` IDs).
* :class:`elengenix.providers.qwen.QwenProvider` — Alibaba DashScope
  (``qwen-plus`` default, ``enable_thinking`` / ``preserve_thinking``
  DashScope-specific controls, ``call_{r:24:h}`` IDs).

Quick start
-----------
>>> from elengenix.providers.registry import get_default_registry
>>> from elengenix.providers.base import ProviderType, ProviderOptionsType
>>> registry = get_default_registry()
>>> bedrock = registry.get_provider(ProviderType.BEDROCK)
>>> bedrock.type().value
'bedrock'
>>> bedrock.model(ProviderOptionsType.PRIMARY_AGENT)
'us.anthropic.claude-sonnet-4-5-20250929-v1:0'

Architecture
------------
* :mod:`elengenix.providers.base` — Protocol + Pydantic v2 data models
  + shared helpers (``load_models_from_http``, ``clean_tool_schemas``).
* :mod:`elengenix.providers._openai_compat` — Shared base class for
  the 5 OpenAI-compatible providers (GLM, Kimi, Qwen, Custom, OpenAI).
* :mod:`elengenix.providers.bedrock` — AWS Bedrock adapter.
* :mod:`elengenix.providers.deepseek` — DeepSeek adapter.
* :mod:`elengenix.providers.openai` — Standard OpenAI adapter.
* :mod:`elengenix.providers.anthropic` — Anthropic Claude adapter.
* :mod:`elengenix.providers.gemini` — Google Gemini adapter.
* :mod:`elengenix.providers.ollama` — Local Ollama adapter.
* :mod:`elengenix.providers.custom` — Custom / vLLM adapter.
* :mod:`elengenix.providers.glm` — Z.AI GLM adapter.
* :mod:`elengenix.providers.kimi` — Moonshot Kimi adapter.
* :mod:`elengenix.providers.qwen` — Alibaba Qwen / DashScope adapter.
* :mod:`elengenix.providers.registry` — factory + env-var availability
  probe.
"""

from __future__ import annotations

# Re-export everything from base — this is the public API surface for
# callers building their own provider adapters.


# --- Lazy submodule re-exports (PEP 562) -----------------------------------
# Importing `elengenix.providers` stays cheap: provider adapters (pydantic,
# boto3, httpx...) load only when an attribute is actually accessed.
# _LAZY_MAP: public name -> (source module, original attribute name).
import importlib as _importlib
import sys as _sys

_LAZY_MAP = {
    "ALL_AGENT_TYPES": ("elengenix.providers.base", "ALL_AGENT_TYPES"),
    "ANTHROPIC_429_BASE_DELAY": ("elengenix.providers.anthropic", "ANTHROPIC_429_BASE_DELAY"),
    "ANTHROPIC_CACHE_MIN_TOKENS": ("elengenix.providers.anthropic", "ANTHROPIC_CACHE_MIN_TOKENS"),
    "ANTHROPIC_DEFAULT_MODEL": ("elengenix.providers.anthropic", "ANTHROPIC_DEFAULT_MODEL"),
    "ANTHROPIC_DEFAULT_MODELS": ("elengenix.providers.anthropic", "ANTHROPIC_DEFAULT_MODELS"),
    "ANTHROPIC_DEFAULT_SERVER_URL": ("elengenix.providers.anthropic", "ANTHROPIC_DEFAULT_SERVER_URL"),
    "ANTHROPIC_MAX_429_RETRIES": ("elengenix.providers.anthropic", "ANTHROPIC_MAX_429_RETRIES"),
    "ANTHROPIC_TOOL_CALL_ID_TEMPLATE": ("elengenix.providers.anthropic", "ANTHROPIC_TOOL_CALL_ID_TEMPLATE"),
    "AgentConfig": ("elengenix.providers.base", "AgentConfig"),
    "AnthropicProvider": ("elengenix.providers.anthropic", "AnthropicProvider"),
    "BEDROCK_429_BASE_DELAY": ("elengenix.providers.bedrock", "BEDROCK_429_BASE_DELAY"),
    "BEDROCK_DEFAULT_MODEL": ("elengenix.providers.bedrock", "BEDROCK_DEFAULT_MODEL"),
    "BEDROCK_DEFAULT_MODELS": ("elengenix.providers.bedrock", "BEDROCK_DEFAULT_MODELS"),
    "BEDROCK_MAX_429_RETRIES": ("elengenix.providers.bedrock", "BEDROCK_MAX_429_RETRIES"),
    "BEDROCK_TOOL_CALL_ID_TEMPLATE": ("elengenix.providers.bedrock", "BEDROCK_TOOL_CALL_ID_TEMPLATE"),
    "BearerToken": ("elengenix.providers.bedrock", "BearerToken"),
    "BedrockAuth": ("elengenix.providers.bedrock", "BedrockAuth"),
    "BedrockProvider": ("elengenix.providers.bedrock", "BedrockProvider"),
    "CUSTOM_429_BASE_DELAY": ("elengenix.providers.custom", "CUSTOM_429_BASE_DELAY"),
    "CUSTOM_DEFAULT_MAX_TOKENS": ("elengenix.providers.custom", "CUSTOM_DEFAULT_MAX_TOKENS"),
    "CUSTOM_DEFAULT_TIMEOUT": ("elengenix.providers.custom", "CUSTOM_DEFAULT_TIMEOUT"),
    "CUSTOM_MAX_429_RETRIES": ("elengenix.providers.custom", "CUSTOM_MAX_429_RETRIES"),
    "CallUsage": ("elengenix.providers.base", "CallUsage"),
    "Choice": ("elengenix.providers.base", "Choice"),
    "ContentResponse": ("elengenix.providers.base", "ContentResponse"),
    "CustomProvider": ("elengenix.providers.custom", "CustomProvider"),
    "DEEPSEEK_429_BASE_DELAY": ("elengenix.providers.deepseek", "DEEPSEEK_429_BASE_DELAY"),
    "DEEPSEEK_DEFAULT_BASE_URL": ("elengenix.providers.deepseek", "DEEPSEEK_DEFAULT_BASE_URL"),
    "DEEPSEEK_DEFAULT_MODEL": ("elengenix.providers.deepseek", "DEEPSEEK_DEFAULT_MODEL"),
    "DEEPSEEK_DEFAULT_MODELS": ("elengenix.providers.deepseek", "DEEPSEEK_DEFAULT_MODELS"),
    "DEEPSEEK_MAX_429_RETRIES": ("elengenix.providers.deepseek", "DEEPSEEK_MAX_429_RETRIES"),
    "DEEPSEEK_TOOL_CALL_ID_TEMPLATE": ("elengenix.providers.deepseek", "DEEPSEEK_TOOL_CALL_ID_TEMPLATE"),
    "DeepSeekProvider": ("elengenix.providers.deepseek", "DeepSeekProvider"),
    "DefaultAuth": ("elengenix.providers.bedrock", "DefaultAuth"),
    "GEMINI_429_BASE_DELAY": ("elengenix.providers.gemini", "GEMINI_429_BASE_DELAY"),
    "GEMINI_CACHE_DISCOUNT_FRACTION": ("elengenix.providers.gemini", "GEMINI_CACHE_DISCOUNT_FRACTION"),
    "GEMINI_DEFAULT_MODEL": ("elengenix.providers.gemini", "GEMINI_DEFAULT_MODEL"),
    "GEMINI_DEFAULT_MODELS": ("elengenix.providers.gemini", "GEMINI_DEFAULT_MODELS"),
    "GEMINI_DEFAULT_SERVER_URL": ("elengenix.providers.gemini", "GEMINI_DEFAULT_SERVER_URL"),
    "GEMINI_EXPLICIT_CACHE_MIN_TOKENS": ("elengenix.providers.gemini", "GEMINI_EXPLICIT_CACHE_MIN_TOKENS"),
    "GEMINI_IMPLICIT_CACHE_THRESHOLD_TOKENS": ("elengenix.providers.gemini", "GEMINI_IMPLICIT_CACHE_THRESHOLD_TOKENS"),
    "GEMINI_MAX_429_RETRIES": ("elengenix.providers.gemini", "GEMINI_MAX_429_RETRIES"),
    "GEMINI_TOOL_CALL_ID_TEMPLATE": ("elengenix.providers.gemini", "GEMINI_TOOL_CALL_ID_TEMPLATE"),
    "GLMProvider": ("elengenix.providers.glm", "GLMProvider"),
    "GLM_429_BASE_DELAY": ("elengenix.providers.glm", "GLM_429_BASE_DELAY"),
    "GLM_DEFAULT_MODEL": ("elengenix.providers.glm", "GLM_DEFAULT_MODEL"),
    "GLM_DEFAULT_MODELS": ("elengenix.providers.glm", "GLM_DEFAULT_MODELS"),
    "GLM_DEFAULT_SERVER_URL": ("elengenix.providers.glm", "GLM_DEFAULT_SERVER_URL"),
    "GLM_MAX_429_RETRIES": ("elengenix.providers.glm", "GLM_MAX_429_RETRIES"),
    "GLM_TOOL_CALL_ID_TEMPLATE": ("elengenix.providers.glm", "GLM_TOOL_CALL_ID_TEMPLATE"),
    "GeminiProvider": ("elengenix.providers.gemini", "GeminiProvider"),
    "KIMI_429_BASE_DELAY": ("elengenix.providers.kimi", "KIMI_429_BASE_DELAY"),
    "KIMI_DEFAULT_MODEL": ("elengenix.providers.kimi", "KIMI_DEFAULT_MODEL"),
    "KIMI_DEFAULT_MODELS": ("elengenix.providers.kimi", "KIMI_DEFAULT_MODELS"),
    "KIMI_DEFAULT_SERVER_URL": ("elengenix.providers.kimi", "KIMI_DEFAULT_SERVER_URL"),
    "KIMI_MAX_429_RETRIES": ("elengenix.providers.kimi", "KIMI_MAX_429_RETRIES"),
    "KIMI_TOOL_CALL_ID_TEMPLATE": ("elengenix.providers.kimi", "KIMI_TOOL_CALL_ID_TEMPLATE"),
    "KimiProvider": ("elengenix.providers.kimi", "KimiProvider"),
    "MessageContent": ("elengenix.providers.base", "MessageContent"),
    "MessagePart": ("elengenix.providers.base", "MessagePart"),
    "ModelConfig": ("elengenix.providers.base", "ModelConfig"),
    "ModelsConfig": ("elengenix.providers.base", "ModelsConfig"),
    "OLLAMA_429_BASE_DELAY": ("elengenix.providers.ollama", "OLLAMA_429_BASE_DELAY"),
    "OLLAMA_DEFAULT_API_CALL_TIMEOUT": ("elengenix.providers.ollama", "OLLAMA_DEFAULT_API_CALL_TIMEOUT"),
    "OLLAMA_DEFAULT_MAX_TOKENS": ("elengenix.providers.ollama", "OLLAMA_DEFAULT_MAX_TOKENS"),
    "OLLAMA_DEFAULT_MODEL": ("elengenix.providers.ollama", "OLLAMA_DEFAULT_MODEL"),
    "OLLAMA_DEFAULT_PULL_TIMEOUT": ("elengenix.providers.ollama", "OLLAMA_DEFAULT_PULL_TIMEOUT"),
    "OLLAMA_DEFAULT_SERVER_URL": ("elengenix.providers.ollama", "OLLAMA_DEFAULT_SERVER_URL"),
    "OLLAMA_MAX_429_RETRIES": ("elengenix.providers.ollama", "OLLAMA_MAX_429_RETRIES"),
    "OPENAI_429_BASE_DELAY": ("elengenix.providers.openai", "OPENAI_429_BASE_DELAY"),
    "OPENAI_DEFAULT_MODEL": ("elengenix.providers.openai", "OPENAI_DEFAULT_MODEL"),
    "OPENAI_DEFAULT_MODELS": ("elengenix.providers.openai", "OPENAI_DEFAULT_MODELS"),
    "OPENAI_DEFAULT_SERVER_URL": ("elengenix.providers.openai", "OPENAI_DEFAULT_SERVER_URL"),
    "OPENAI_MAX_429_RETRIES": ("elengenix.providers.openai", "OPENAI_MAX_429_RETRIES"),
    "OPENAI_REASONING_MODEL_PREFIXES": ("elengenix.providers.openai", "OPENAI_REASONING_MODEL_PREFIXES"),
    "OPENAI_TOOL_CALL_ID_TEMPLATE": ("elengenix.providers.openai", "OPENAI_TOOL_CALL_ID_TEMPLATE"),
    "OllamaProvider": ("elengenix.providers.ollama", "OllamaProvider"),
    "OpenAIProvider": ("elengenix.providers.openai", "OpenAIProvider"),
    "PriceInfo": ("elengenix.providers.base", "PriceInfo"),
    "Provider": ("elengenix.providers.base", "Provider"),
    "ProviderConfig": ("elengenix.providers.base", "ProviderConfig"),
    "ProviderFactory": ("elengenix.providers.registry", "ProviderFactory"),
    "ProviderOptionsType": ("elengenix.providers.base", "ProviderOptionsType"),
    "ProviderRegistry": ("elengenix.providers.registry", "ProviderRegistry"),
    "ProviderType": ("elengenix.providers.base", "ProviderType"),
    "QWEN_429_BASE_DELAY": ("elengenix.providers.qwen", "QWEN_429_BASE_DELAY"),
    "QWEN_DEFAULT_MODEL": ("elengenix.providers.qwen", "QWEN_DEFAULT_MODEL"),
    "QWEN_DEFAULT_MODELS": ("elengenix.providers.qwen", "QWEN_DEFAULT_MODELS"),
    "QWEN_DEFAULT_SERVER_URL": ("elengenix.providers.qwen", "QWEN_DEFAULT_SERVER_URL"),
    "QWEN_MAX_429_RETRIES": ("elengenix.providers.qwen", "QWEN_MAX_429_RETRIES"),
    "QWEN_PRESERVE_THINKING_MODELS": ("elengenix.providers.qwen", "QWEN_PRESERVE_THINKING_MODELS"),
    "QWEN_TOOL_CALL_ID_TEMPLATE": ("elengenix.providers.qwen", "QWEN_TOOL_CALL_ID_TEMPLATE"),
    "QwenProvider": ("elengenix.providers.qwen", "QwenProvider"),
    "ReasoningConfig": ("elengenix.providers.base", "ReasoningConfig"),
    "ReasoningEffort": ("elengenix.providers.base", "ReasoningEffort"),
    "StaticCredentials": ("elengenix.providers.bedrock", "StaticCredentials"),
    "StreamingCallback": ("elengenix.providers.base", "StreamingCallback"),
    "TextPart": ("elengenix.providers.base", "TextPart"),
    "ToolCall": ("elengenix.providers.base", "ToolCall"),
    "ToolCallResponse": ("elengenix.providers.base", "ToolCallResponse"),
    "anthropic_generate_tool_call_id": ("elengenix.providers.anthropic", "generate_tool_call_id"),
    "anthropic_get_default_config": ("elengenix.providers.anthropic", "get_default_config"),
    "apply_model_prefix": ("elengenix.providers.base", "apply_model_prefix"),
    "bedrock_generate_tool_call_id": ("elengenix.providers.bedrock", "generate_tool_call_id"),
    "bedrock_get_default_config": ("elengenix.providers.bedrock", "get_default_config"),
    "bedrock_resolve_auth_from_env": ("elengenix.providers.bedrock", "resolve_auth_from_env"),
    "clean_tool_schemas": ("elengenix.providers.base", "clean_tool_schemas"),
    "custom_get_default_config": ("elengenix.providers.custom", "get_default_config"),
    "deepseek_generate_tool_call_id": ("elengenix.providers.deepseek", "generate_tool_call_id"),
    "deepseek_get_default_config": ("elengenix.providers.deepseek", "get_default_config"),
    "gemini_generate_tool_call_id": ("elengenix.providers.gemini", "generate_tool_call_id"),
    "gemini_get_default_config": ("elengenix.providers.gemini", "get_default_config"),
    "get_default_registry": ("elengenix.providers.registry", "get_default_registry"),
    "glm_generate_tool_call_id": ("elengenix.providers.glm", "generate_tool_call_id"),
    "glm_get_default_config": ("elengenix.providers.glm", "get_default_config"),
    "kimi_generate_tool_call_id": ("elengenix.providers.kimi", "generate_tool_call_id"),
    "kimi_get_default_config": ("elengenix.providers.kimi", "get_default_config"),
    "load_models_from_http": ("elengenix.providers.base", "load_models_from_http"),
    "ollama_get_default_config": ("elengenix.providers.ollama", "get_default_config"),
    "openai_generate_tool_call_id": ("elengenix.providers.openai", "generate_tool_call_id"),
    "openai_get_default_config": ("elengenix.providers.openai", "get_default_config"),
    "qwen_generate_tool_call_id": ("elengenix.providers.qwen", "generate_tool_call_id"),
    "qwen_get_default_config": ("elengenix.providers.qwen", "get_default_config"),
    "remove_model_prefix": ("elengenix.providers.base", "remove_model_prefix"),
}


def __getattr__(name):
    entry = _LAZY_MAP.get(name)
    if entry is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_path, attr = entry
    _importlib.import_module(module_path)
    value = getattr(_sys.modules[module_path], attr)
    globals()[name] = value  # cache: subsequent lookups are free
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY_MAP))


# Concrete providers — imported eagerly because they don't pull in
# boto3/openai at module load (those imports happen inside __init__).
# Phase 7-b: OpenAI-compatible + native adapters (8 providers)

__all__ = [
    # base
    "ALL_AGENT_TYPES",
    "AgentConfig",
    "CallUsage",
    "Choice",
    "ContentResponse",
    "MessageContent",
    "MessagePart",
    "ModelConfig",
    "ModelsConfig",
    "PriceInfo",
    "Provider",
    "ProviderConfig",
    "ProviderOptionsType",
    "ProviderType",
    "ReasoningConfig",
    "ReasoningEffort",
    "StreamingCallback",
    "TextPart",
    "ToolCall",
    "ToolCallResponse",
    "apply_model_prefix",
    "clean_tool_schemas",
    "load_models_from_http",
    "remove_model_prefix",
    # bedrock
    "BEDROCK_429_BASE_DELAY",
    "BEDROCK_DEFAULT_MODEL",
    "BEDROCK_DEFAULT_MODELS",
    "BEDROCK_MAX_429_RETRIES",
    "BEDROCK_TOOL_CALL_ID_TEMPLATE",
    "BedrockAuth",
    "BedrockProvider",
    "BearerToken",
    "DefaultAuth",
    "StaticCredentials",
    "bedrock_generate_tool_call_id",
    "bedrock_get_default_config",
    "bedrock_resolve_auth_from_env",
    # deepseek
    "DEEPSEEK_429_BASE_DELAY",
    "DEEPSEEK_DEFAULT_BASE_URL",
    "DEEPSEEK_DEFAULT_MODEL",
    "DEEPSEEK_DEFAULT_MODELS",
    "DEEPSEEK_MAX_429_RETRIES",
    "DEEPSEEK_TOOL_CALL_ID_TEMPLATE",
    "DeepSeekProvider",
    "deepseek_generate_tool_call_id",
    "deepseek_get_default_config",
    # openai (Phase 7-b)
    "OPENAI_429_BASE_DELAY",
    "OPENAI_DEFAULT_MODELS",
    "OPENAI_DEFAULT_MODEL",
    "OPENAI_DEFAULT_SERVER_URL",
    "OPENAI_MAX_429_RETRIES",
    "OPENAI_REASONING_MODEL_PREFIXES",
    "OPENAI_TOOL_CALL_ID_TEMPLATE",
    "OpenAIProvider",
    "openai_generate_tool_call_id",
    "openai_get_default_config",
    # anthropic (Phase 7-b)
    "ANTHROPIC_429_BASE_DELAY",
    "ANTHROPIC_CACHE_MIN_TOKENS",
    "ANTHROPIC_DEFAULT_MODELS",
    "ANTHROPIC_DEFAULT_MODEL",
    "ANTHROPIC_DEFAULT_SERVER_URL",
    "ANTHROPIC_MAX_429_RETRIES",
    "ANTHROPIC_TOOL_CALL_ID_TEMPLATE",
    "AnthropicProvider",
    "anthropic_generate_tool_call_id",
    "anthropic_get_default_config",
    # gemini (Phase 7-b)
    "GEMINI_429_BASE_DELAY",
    "GEMINI_CACHE_DISCOUNT_FRACTION",
    "GEMINI_DEFAULT_MODELS",
    "GEMINI_DEFAULT_MODEL",
    "GEMINI_DEFAULT_SERVER_URL",
    "GEMINI_EXPLICIT_CACHE_MIN_TOKENS",
    "GEMINI_IMPLICIT_CACHE_THRESHOLD_TOKENS",
    "GEMINI_MAX_429_RETRIES",
    "GEMINI_TOOL_CALL_ID_TEMPLATE",
    "GeminiProvider",
    "gemini_generate_tool_call_id",
    "gemini_get_default_config",
    # ollama (Phase 7-b)
    "OLLAMA_429_BASE_DELAY",
    "OLLAMA_DEFAULT_API_CALL_TIMEOUT",
    "OLLAMA_DEFAULT_MAX_TOKENS",
    "OLLAMA_DEFAULT_MODEL",
    "OLLAMA_DEFAULT_PULL_TIMEOUT",
    "OLLAMA_DEFAULT_SERVER_URL",
    "OLLAMA_MAX_429_RETRIES",
    "OllamaProvider",
    "ollama_get_default_config",
    # custom / vLLM (Phase 7-b)
    "CUSTOM_429_BASE_DELAY",
    "CUSTOM_DEFAULT_MAX_TOKENS",
    "CUSTOM_DEFAULT_TIMEOUT",
    "CUSTOM_MAX_429_RETRIES",
    "CustomProvider",
    "custom_get_default_config",
    # glm (Phase 7-b)
    "GLM_429_BASE_DELAY",
    "GLM_DEFAULT_MODELS",
    "GLM_DEFAULT_MODEL",
    "GLM_DEFAULT_SERVER_URL",
    "GLM_MAX_429_RETRIES",
    "GLM_TOOL_CALL_ID_TEMPLATE",
    "GLMProvider",
    "glm_generate_tool_call_id",
    "glm_get_default_config",
    # kimi (Phase 7-b)
    "KIMI_429_BASE_DELAY",
    "KIMI_DEFAULT_MODELS",
    "KIMI_DEFAULT_MODEL",
    "KIMI_DEFAULT_SERVER_URL",
    "KIMI_MAX_429_RETRIES",
    "KIMI_TOOL_CALL_ID_TEMPLATE",
    "KimiProvider",
    "kimi_generate_tool_call_id",
    "kimi_get_default_config",
    # qwen (Phase 7-b)
    "QWEN_429_BASE_DELAY",
    "QWEN_DEFAULT_MODELS",
    "QWEN_DEFAULT_MODEL",
    "QWEN_DEFAULT_SERVER_URL",
    "QWEN_MAX_429_RETRIES",
    "QWEN_PRESERVE_THINKING_MODELS",
    "QWEN_TOOL_CALL_ID_TEMPLATE",
    "QwenProvider",
    "qwen_generate_tool_call_id",
    "qwen_get_default_config",
    # registry
    "ProviderFactory",
    "ProviderRegistry",
    "get_default_registry",
]

__version__ = "0.1.0"

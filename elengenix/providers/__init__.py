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
from elengenix.providers.base import (
    ALL_AGENT_TYPES,
    AgentConfig,
    CallUsage,
    Choice,
    ContentResponse,
    MessageContent,
    MessagePart,
    ModelConfig,
    ModelsConfig,
    PriceInfo,
    Provider,
    ProviderConfig,
    ProviderOptionsType,
    ProviderType,
    ReasoningConfig,
    ReasoningEffort,
    StreamingCallback,
    TextPart,
    ToolCall,
    ToolCallResponse,
    apply_model_prefix,
    clean_tool_schemas,
    load_models_from_http,
    remove_model_prefix,
)

# Concrete providers — imported eagerly because they don't pull in
# boto3/openai at module load (those imports happen inside __init__).
from elengenix.providers.bedrock import (
    BEDROCK_429_BASE_DELAY,
    BEDROCK_DEFAULT_MODEL,
    BEDROCK_DEFAULT_MODELS,
    BEDROCK_MAX_429_RETRIES,
    BEDROCK_TOOL_CALL_ID_TEMPLATE,
    BedrockAuth,
    BedrockProvider,
    BearerToken,
    DefaultAuth,
    StaticCredentials,
    generate_tool_call_id as bedrock_generate_tool_call_id,
    get_default_config as bedrock_get_default_config,
    resolve_auth_from_env as bedrock_resolve_auth_from_env,
)
from elengenix.providers.deepseek import (
    DEEPSEEK_429_BASE_DELAY,
    DEEPSEEK_DEFAULT_BASE_URL,
    DEEPSEEK_DEFAULT_MODEL,
    DEEPSEEK_DEFAULT_MODELS,
    DEEPSEEK_MAX_429_RETRIES,
    DEEPSEEK_TOOL_CALL_ID_TEMPLATE,
    DeepSeekProvider,
    generate_tool_call_id as deepseek_generate_tool_call_id,
    get_default_config as deepseek_get_default_config,
)
# Phase 7-b: OpenAI-compatible + native adapters (8 providers)
from elengenix.providers.openai import (
    OPENAI_429_BASE_DELAY,
    OPENAI_DEFAULT_MODELS,
    OPENAI_DEFAULT_MODEL,
    OPENAI_DEFAULT_SERVER_URL,
    OPENAI_MAX_429_RETRIES,
    OPENAI_REASONING_MODEL_PREFIXES,
    OPENAI_TOOL_CALL_ID_TEMPLATE,
    OpenAIProvider,
    generate_tool_call_id as openai_generate_tool_call_id,
    get_default_config as openai_get_default_config,
)
from elengenix.providers.anthropic import (
    ANTHROPIC_429_BASE_DELAY,
    ANTHROPIC_CACHE_MIN_TOKENS,
    ANTHROPIC_DEFAULT_MODELS,
    ANTHROPIC_DEFAULT_MODEL,
    ANTHROPIC_DEFAULT_SERVER_URL,
    ANTHROPIC_MAX_429_RETRIES,
    ANTHROPIC_TOOL_CALL_ID_TEMPLATE,
    AnthropicProvider,
    generate_tool_call_id as anthropic_generate_tool_call_id,
    get_default_config as anthropic_get_default_config,
)
from elengenix.providers.gemini import (
    GEMINI_429_BASE_DELAY,
    GEMINI_CACHE_DISCOUNT_FRACTION,
    GEMINI_DEFAULT_MODELS,
    GEMINI_DEFAULT_MODEL,
    GEMINI_DEFAULT_SERVER_URL,
    GEMINI_EXPLICIT_CACHE_MIN_TOKENS,
    GEMINI_IMPLICIT_CACHE_THRESHOLD_TOKENS,
    GEMINI_MAX_429_RETRIES,
    GEMINI_TOOL_CALL_ID_TEMPLATE,
    GeminiProvider,
    generate_tool_call_id as gemini_generate_tool_call_id,
    get_default_config as gemini_get_default_config,
)
from elengenix.providers.ollama import (
    OLLAMA_429_BASE_DELAY,
    OLLAMA_DEFAULT_API_CALL_TIMEOUT,
    OLLAMA_DEFAULT_MAX_TOKENS,
    OLLAMA_DEFAULT_MODEL,
    OLLAMA_DEFAULT_PULL_TIMEOUT,
    OLLAMA_DEFAULT_SERVER_URL,
    OLLAMA_MAX_429_RETRIES,
    OllamaProvider,
    get_default_config as ollama_get_default_config,
)
from elengenix.providers.custom import (
    CUSTOM_429_BASE_DELAY,
    CUSTOM_DEFAULT_MAX_TOKENS,
    CUSTOM_DEFAULT_TIMEOUT,
    CUSTOM_MAX_429_RETRIES,
    CustomProvider,
    get_default_config as custom_get_default_config,
)
from elengenix.providers.glm import (
    GLM_429_BASE_DELAY,
    GLM_DEFAULT_MODELS,
    GLM_DEFAULT_MODEL,
    GLM_DEFAULT_SERVER_URL,
    GLM_MAX_429_RETRIES,
    GLM_TOOL_CALL_ID_TEMPLATE,
    GLMProvider,
    generate_tool_call_id as glm_generate_tool_call_id,
    get_default_config as glm_get_default_config,
)
from elengenix.providers.kimi import (
    KIMI_429_BASE_DELAY,
    KIMI_DEFAULT_MODELS,
    KIMI_DEFAULT_MODEL,
    KIMI_DEFAULT_SERVER_URL,
    KIMI_MAX_429_RETRIES,
    KIMI_TOOL_CALL_ID_TEMPLATE,
    KimiProvider,
    generate_tool_call_id as kimi_generate_tool_call_id,
    get_default_config as kimi_get_default_config,
)
from elengenix.providers.qwen import (
    QWEN_429_BASE_DELAY,
    QWEN_DEFAULT_MODELS,
    QWEN_DEFAULT_MODEL,
    QWEN_DEFAULT_SERVER_URL,
    QWEN_MAX_429_RETRIES,
    QWEN_PRESERVE_THINKING_MODELS,
    QWEN_TOOL_CALL_ID_TEMPLATE,
    QwenProvider,
    generate_tool_call_id as qwen_generate_tool_call_id,
    get_default_config as qwen_get_default_config,
)
from elengenix.providers.registry import (
    ProviderFactory,
    ProviderRegistry,
    get_default_registry,
)

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

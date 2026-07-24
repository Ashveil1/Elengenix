"""elengenix.providers.bedrock — AWS Bedrock adapter (Python port).

Port of PentAGI's ``backend/pkg/providers/bedrock/bedrock.go`` (467 lines).
The adapter talks to AWS Bedrock's Converse API via :mod:`boto3` and
implements the full :class:`~elengenix.providers.base.Provider` protocol.

Key features ported from the Go original
-----------------------------------------
* **Three auth modes** — chosen at construction time via the
  :class:`BedrockAuth` discriminated union:
    - :class:`DefaultAuth` — AWS SDK default credential chain
      (env vars, EC2 role, SSO, …).  No explicit credentials needed.
    - :class:`BearerToken` — ``Authorization: Bearer <token>`` for
      Bedrock's bearer-token auth (used by some Marketplace deployments).
    - :class:`StaticCredentials` — explicit ``access_key`` +
      ``secret_key`` (+ optional ``session_token``).
* **Converse API quirks** — when the conversation chain already contains
  ``toolUse`` / ``toolResult`` content blocks, the Converse API requires
  a non-empty ``toolConfig`` even when no new tools are being offered.
  :meth:`BedrockProvider._restore_missed_tools_from_chain` reconstructs
  minimal tool definitions from the prior tool calls so the request
  succeeds. :meth:`BedrockProvider._infer_schema_from_arguments`
  reflection-infers a JSON schema from the actual argument samples found
  in the chain.
* **``$schema`` stripping** — Bedrock rejects JSON-Schema definitions
  that carry the ``$schema`` metadata field. The shared helper
  :func:`elengenix.providers.base.clean_tool_schemas` is applied to
  every tool config before the request is sent.
* **429 retry** — :func:`tenacity.retry` with 10 attempts, 5 s base +
  1 s linear increment per attempt (matches PentAGI's
  ``MaxTooManyRequestsRetries`` / ``TooManyRequestsRetryDelay``).
* **Tool-call ID template** — ``"tooluse_{r:22:x}"`` (22-char hex).
  Bedrock auto-generates tool-use IDs in this shape; the orchestrator
  uses the template to synthesise IDs when replaying tool results.
* **Model catalog** — :data:`BEDROCK_DEFAULT_MODELS` mirrors
  ``bedrock/models.yml`` (Amazon Nova, Anthropic Claude 4.x/3.5,
  Cohere Command R+, DeepSeek v3.2, OpenAI GPT-OSS, Qwen3, Mistral
  Large 3, Moonshot Kimi K2.5).
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from typing import Any, Callable, Iterable

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
    StreamingCallback,
    TextPart,
    ToolCall,
    ToolCallResponse,
    clean_tool_schemas,
)

logger = logging.getLogger("elengenix.providers.bedrock")

# ---------------------------------------------------------------------------
# Constants — ported from bedrock.go
# ---------------------------------------------------------------------------

#: Default Bedrock model. PentAGI's ``BedrockAgentModel`` constant points
#: at the same Claude Sonnet 4.5 cross-region inference ID.
BEDROCK_DEFAULT_MODEL: str = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"

#: Bedrock tool-call ID template (22-char hex, e.g.
#: ``tooluse_0a1b2c3d4e5f6a7b8c9d0e``). Matches the format Bedrock
#: auto-generates server-side so orchestrator-synthesised IDs are
#: indistinguishable.
BEDROCK_TOOL_CALL_ID_TEMPLATE: str = "tooluse_{r:22:x}"

#: Maximum number of 429 (TooManyRequests) retries — mirrors PentAGI's
#: ``MaxTooManyRequestsRetries``.
BEDROCK_MAX_429_RETRIES: int = 10

#: Base delay (seconds) for 429 backoff — mirrors
#: ``TooManyRequestsRetryDelay``. Each retry waits ``BASE + i`` seconds
#: (linear, not exponential — matches PentAGI exactly).
BEDROCK_429_BASE_DELAY: float = 5.0


# ---------------------------------------------------------------------------
# Auth modes — discriminated by the ``mode`` field
# ---------------------------------------------------------------------------


def _bedrock_auth_discriminator(v: Any) -> str:
    """Pydantic discriminator for :class:`BedrockAuth`.

    Returns the ``mode`` field value so Pydantic v2 can route
    deserialisation to the correct auth subclass.
    """
    if isinstance(v, dict):
        return v.get("mode", "default")
    return getattr(v, "mode", "default")


class _BedrockAuthBase:
    """Common marker for Bedrock auth-mode configs.

    Concrete subclasses live below; the union :data:`BedrockAuth` is the
    public type used by :class:`BedrockProvider`.
    """


class DefaultAuth(_BedrockAuthBase):
    """Use the AWS SDK default credential chain (env / EC2 / SSO / …).

    No explicit credentials are passed to ``boto3.client``; the SDK
    resolves them from the environment. Equivalent to PentAGI's
    ``cfg.BedrockDefaultAuth == true`` branch.
    """

    mode: str = "default"


class BearerToken(_BedrockAuthBase):
    """Bedrock bearer-token auth (``Authorization: Bearer <token>``).

    Used by some Marketplace / Bedrock-Enterprise deployments. The token
    is passed to boto3 via a custom ``request_payer`` /
    ``aws_session_token`` shim; see :meth:`BedrockProvider._build_client`.
    """

    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("BearerToken requires a non-empty token")
        self.token = token
        self.mode = "bearer"


class StaticCredentials(_BedrockAuthBase):
    """Static AWS credentials (access key + secret key + session token).

    Equivalent to PentAGI's
    ``credentials.NewStaticCredentialsProvider(access, secret, session)``
    branch.
    """

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        session_token: str = "",
    ) -> None:
        if not access_key or not secret_key:
            raise ValueError("StaticCredentials requires access_key and secret_key")
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.mode = "static"


#: Union of all supported auth modes. Use :func:`resolve_auth_from_env`
#: to pick one based on environment variables (mirrors PentAGI's
#: precedence: default-auth > bearer > static).
BedrockAuth = DefaultAuth | BearerToken | StaticCredentials


def resolve_auth_from_env() -> BedrockAuth:
    """Pick a Bedrock auth mode from environment variables.

    Mirrors PentAGI's precedence in ``bedrock.go::New``:

    1. ``BEDROCK_DEFAULT_AUTH=1`` -> :class:`DefaultAuth`.
    2. ``BEDROCK_BEARER_TOKEN`` set -> :class:`BearerToken`.
    3. ``BEDROCK_ACCESS_KEY`` + ``BEDROCK_SECRET_KEY`` set ->
       :class:`StaticCredentials`.
    4. Otherwise -> :class:`DefaultAuth` (let boto3 resolve from the
       environment; fails at request time if no creds are available).
    """
    if os.environ.get("BEDROCK_DEFAULT_AUTH", "").lower() in ("1", "true", "yes"):
        return DefaultAuth()
    bearer = os.environ.get("BEDROCK_BEARER_TOKEN", "")
    if bearer:
        return BearerToken(bearer)
    access_key = os.environ.get("BEDROCK_ACCESS_KEY", "")
    secret_key = os.environ.get("BEDROCK_SECRET_KEY", "")
    if access_key and secret_key:
        return StaticCredentials(
            access_key=access_key,
            secret_key=secret_key,
            session_token=os.environ.get("BEDROCK_SESSION_TOKEN", ""),
        )
    # Fallback — let boto3 resolve from its default chain.
    return DefaultAuth()


# ---------------------------------------------------------------------------
# Default provider config (port of bedrock/config.yml)
# ---------------------------------------------------------------------------


def _agent(
    model: str = BEDROCK_DEFAULT_MODEL,
    *,
    temperature: float | None = 1.0,
    top_p: float | None = None,
    n: int | None = 1,
    max_tokens: int | None = 16384,
    reasoning_max_tokens: int = 0,
    price: PriceInfo | None = None,
    json_mode: bool = False,
    extra_body: dict[str, Any] | None = None,
) -> AgentConfig:
    """Build an :class:`AgentConfig` with sensible Bedrock defaults."""
    reasoning = None
    if reasoning_max_tokens > 0:
        from elengenix.providers.base import ReasoningConfig

        reasoning = ReasoningConfig(max_tokens=reasoning_max_tokens)
    return AgentConfig(
        model=model,
        temperature=temperature,
        top_p=top_p,
        n=n,
        max_tokens=max_tokens,
        json_mode=json_mode,
        reasoning=reasoning or None,  # type: ignore[arg-type]
        price=price,
        extra_body=extra_body,
    )


_SONNET_PRICE = PriceInfo(input=3.0, output=15.0, cache_read=0.3, cache_write=3.75)
_OPUS_PRICE = PriceInfo(input=5.0, output=25.0, cache_read=0.5, cache_write=6.25)
_HAIKU_PRICE = PriceInfo(input=1.0, output=5.0, cache_read=0.1, cache_write=1.25)
_GPT_OSS_PRICE = PriceInfo(input=0.15, output=0.6)


def get_default_config() -> ProviderConfig:
    """Return the default Bedrock :class:`ProviderConfig`.

    Ported verbatim from ``bedrock/config.yml``. Each of the 13 agent
    slots is populated with the same model / temperature / pricing
    PentAGI ships out-of-the-box.
    """
    cfg = ProviderConfig()
    cfg.simple = _agent(
        model="openai.gpt-oss-120b-1:0",
        temperature=0.5,
        top_p=0.5,
        max_tokens=6000,
        price=_GPT_OSS_PRICE,
    )
    cfg.simple_json = _agent(
        model="openai.gpt-oss-120b-1:0",
        temperature=0.5,
        top_p=0.5,
        max_tokens=4000,
        json_mode=True,
        price=_GPT_OSS_PRICE,
    )
    cfg.primary_agent = _agent(
        max_tokens=16384, reasoning_max_tokens=2048, price=_SONNET_PRICE
    )
    cfg.assistant = _agent(
        max_tokens=16384, reasoning_max_tokens=1024, price=_SONNET_PRICE
    )
    cfg.generator = _agent(
        max_tokens=16384, reasoning_max_tokens=4096, price=_SONNET_PRICE
    )
    cfg.refiner = _agent(
        max_tokens=12000, reasoning_max_tokens=2048, price=_SONNET_PRICE
    )
    cfg.adviser = _agent(
        model="us.anthropic.claude-opus-4-6-v1",
        max_tokens=16384,
        reasoning_max_tokens=4096,
        price=_OPUS_PRICE,
    )
    cfg.reflector = _agent(
        model="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        max_tokens=4096,
        reasoning_max_tokens=1024,
        price=_HAIKU_PRICE,
    )
    cfg.searcher = _agent(
        model="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        max_tokens=8192,
        reasoning_max_tokens=1024,
        price=_HAIKU_PRICE,
    )
    cfg.enricher = _agent(
        model="us.anthropic.claude-haiku-4-5-20251001-v1:0",
        max_tokens=8192,
        reasoning_max_tokens=1024,
        price=_HAIKU_PRICE,
    )
    cfg.coder = _agent(
        max_tokens=16384, reasoning_max_tokens=2048, price=_SONNET_PRICE
    )
    cfg.installer = _agent(
        max_tokens=8192, reasoning_max_tokens=1024, price=_SONNET_PRICE
    )
    cfg.pentester = _agent(
        max_tokens=16384, reasoning_max_tokens=1024, price=_SONNET_PRICE
    )
    return cfg


# ---------------------------------------------------------------------------
# Default models catalog (port of bedrock/models.yml)
# ---------------------------------------------------------------------------


def _mc(
    name: str,
    description: str,
    *,
    thinking: bool,
    release_date: str,
    price: PriceInfo,
) -> ModelConfig:
    return ModelConfig(
        name=name,
        description=description,
        thinking=thinking,
        release_date=release_date,
        price=price,
    )


BEDROCK_DEFAULT_MODELS: list[ModelConfig] = [
    # Amazon Nova series
    _mc(
        "us.amazon.nova-2-lite-v1:0",
        "Advanced multimodal model with adaptive reasoning and efficient thinking",
        thinking=False,
        release_date="2025-12-02",
        price=PriceInfo(input=0.33, output=2.75),
    ),
    _mc(
        "us.amazon.nova-premier-v1:0",
        "Most capable multimodal model for complex reasoning tasks",
        thinking=False,
        release_date="2025-04-30",
        price=PriceInfo(input=2.5, output=12.5),
    ),
    _mc(
        "us.amazon.nova-pro-v1:0",
        "Highly capable multimodal model with optimal balance of accuracy, speed, cost",
        thinking=False,
        release_date="2024-12-03",
        price=PriceInfo(input=0.8, output=3.2),
    ),
    _mc(
        "us.amazon.nova-lite-v1:0",
        "Very low-cost multimodal model optimized for rapid vulnerability scanning",
        thinking=False,
        release_date="2024-12-03",
        price=PriceInfo(input=0.06, output=0.24),
    ),
    _mc(
        "us.amazon.nova-micro-v1:0",
        "Ultra-efficient text-only model for real-time security monitoring",
        thinking=False,
        release_date="2024-12-03",
        price=PriceInfo(input=0.035, output=0.14),
    ),
    # Anthropic Claude 4.6 series
    _mc(
        "us.anthropic.claude-opus-4-6-v1",
        "World's best model for coding, enterprise agents, and professional work",
        thinking=True,
        release_date="2026-02-05",
        price=PriceInfo(input=5.0, output=25.0, cache_read=0.5, cache_write=6.25),
    ),
    _mc(
        "us.anthropic.claude-sonnet-4-6",
        "Frontier intelligence at scale built for coding, agents, and enterprise",
        thinking=True,
        release_date="2026-02-17",
        price=PriceInfo(input=3.0, output=15.0, cache_read=0.3, cache_write=3.75),
    ),
    # Anthropic Claude 4.5 series
    _mc(
        "us.anthropic.claude-opus-4-5-20251101-v1:0",
        "Next generation most intelligent model for multi-day dev projects",
        thinking=True,
        release_date="2025-11-24",
        price=PriceInfo(input=5.0, output=25.0, cache_read=0.5, cache_write=6.25),
    ),
    _mc(
        "us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "Near-frontier performance with exceptional speed and cost efficiency",
        thinking=True,
        release_date="2025-10-15",
        price=PriceInfo(input=1.0, output=5.0, cache_read=0.1, cache_write=1.25),
    ),
    _mc(
        "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "Most powerful model for real-world agents with industry-leading coding",
        thinking=True,
        release_date="2025-09-29",
        price=PriceInfo(input=3.0, output=15.0, cache_read=0.3, cache_write=3.75),
    ),
    # Anthropic Claude 4 series
    _mc(
        "us.anthropic.claude-sonnet-4-20250514-v1:0",
        "Balanced performance for coding with optimal speed and cost",
        thinking=True,
        release_date="2025-05-22",
        price=PriceInfo(input=3.0, output=15.0, cache_read=0.3, cache_write=3.75),
    ),
    # Anthropic Claude 3.5 series
    _mc(
        "us.anthropic.claude-3-5-haiku-20241022-v1:0",
        "Fastest and most cost-effective Claude 3.5 model",
        thinking=False,
        release_date="2024-11-04",
        price=PriceInfo(input=0.8, output=4.0, cache_read=0.08, cache_write=1.0),
    ),
    # Cohere Command R+
    _mc(
        "cohere.command-r-plus-v1:0",
        "Highly performant generative model with superior RAG capabilities",
        thinking=False,
        release_date="2024-04-29",
        price=PriceInfo(input=3.0, output=15.0),
    ),
    # DeepSeek v3.2
    _mc(
        "deepseek.v3.2",
        "Harmonizes high computational efficiency with superior reasoning",
        thinking=False,
        release_date="2025-12-01",
        price=PriceInfo(input=0.58, output=1.68),
    ),
    # OpenAI GPT-OSS series
    _mc(
        "openai.gpt-oss-120b-1:0",
        "Performance comparable to leading alternatives in coding and reasoning",
        thinking=True,
        release_date="2025-08-20",
        price=PriceInfo(input=0.15, output=0.6),
    ),
    _mc(
        "openai.gpt-oss-20b-1:0",
        "Efficient model with strong coding and scientific analysis capabilities",
        thinking=True,
        release_date="2025-08-20",
        price=PriceInfo(input=0.07, output=0.3),
    ),
    # Qwen3 series
    _mc(
        "qwen.qwen3-next-80b-a3b",
        "Cutting-edge MoE with ultra-long-context, flagship reasoning and coding",
        thinking=False,
        release_date="2025-09-11",
        price=PriceInfo(input=0.15, output=1.2),
    ),
    _mc(
        "qwen.qwen3-32b-v1:0",
        "Balanced dense model with strong reasoning and general-purpose performance",
        thinking=False,
        release_date="2025-04-28",
        price=PriceInfo(input=0.15, output=0.6),
    ),
    _mc(
        "qwen.qwen3-coder-30b-a3b-v1:0",
        "Strong coding and reasoning in compact MoE design",
        thinking=False,
        release_date="2025-09-18",
        price=PriceInfo(input=0.15, output=0.6),
    ),
    _mc(
        "qwen.qwen3-coder-next",
        "Open-weight language model built for coding with high capability",
        thinking=False,
        release_date="2026-02-02",
        price=PriceInfo(input=0.45, output=1.8),
    ),
    # Mistral Large 3
    _mc(
        "mistral.mistral-large-3-675b-instruct",
        "Most advanced open-weight multimodal model with granular MoE architecture",
        thinking=False,
        release_date="2025-12-02",
        price=PriceInfo(input=4.0, output=12.0),
    ),
    # Moonshot Kimi K2.5
    _mc(
        "moonshotai.kimi-k2.5",
        "Strong vision, language, and code capabilities in single multimodal architecture",
        thinking=False,
        release_date="2026-01-27",
        price=PriceInfo(input=0.6, output=3.0),
    ),
]


# ---------------------------------------------------------------------------
# Tool-call ID generator (matches Bedrock's server-side format)
# ---------------------------------------------------------------------------


def generate_tool_call_id() -> str:
    """Generate a Bedrock-shaped tool-call ID (``tooluse_<22 hex>``).

    The orchestrator calls this when it needs to synthesise a tool-call
    ID for a tool result that didn't come from a real Bedrock response
    (e.g. when replaying a cached chain).
    """
    return f"tooluse_{secrets.token_hex(11)}"  # 22 hex chars


# ---------------------------------------------------------------------------
# BedrockProvider
# ---------------------------------------------------------------------------


class BedrockProvider:
    """AWS Bedrock adapter (Python port of ``bedrockProvider``).

    Construction is lazy — :mod:`boto3` is imported inside
    :meth:`__init__` so importing this module never requires boto3 to be
    installed. Callers must supply a non-null :class:`BedrockAuth` (use
    :func:`resolve_auth_from_env` for the PentAGI default precedence).
    """

    def __init__(
        self,
        auth: BedrockAuth | None = None,
        *,
        region_name: str = "us-east-1",
        server_url: str = "",
        provider_config: ProviderConfig | None = None,
        models: list[ModelConfig] | None = None,
        provider_name: str = "bedrock",
    ) -> None:
        self._auth: BedrockAuth = auth if auth is not None else resolve_auth_from_env()
        self._region_name = region_name
        self._server_url = server_url
        self._provider_name = provider_name
        self._provider_config: ProviderConfig = (
            provider_config if provider_config is not None else get_default_config()
        )
        self._models: list[ModelConfig] = (
            models if models is not None else list(BEDROCK_DEFAULT_MODELS)
        )

        # Cached tool-call ID template — PentAGI uses ``sync.Once``;
        # Python uses a plain ``threading.Event`` for the same effect.
        self._tool_call_id_template: str | None = None
        self._tool_call_id_template_lock = threading.Lock()

        # boto3 clients are created lazily so the module can be imported
        # without boto3 installed.
        self._runtime_client: Any = None
        self._control_client: Any = None
        self._client_lock = threading.Lock()

    # ------------------------------------------------------------------
    # boto3 client construction
    # ------------------------------------------------------------------

    def _build_client_kwargs(self) -> dict[str, Any]:
        """Build kwargs for ``boto3.client('bedrock-runtime')``."""
        kwargs: dict[str, Any] = {"region_name": self._region_name}
        if self._server_url:
            # boto3 accepts endpoint_url at client() construction time.
            kwargs["endpoint_url"] = self._server_url

        if isinstance(self._auth, StaticCredentials):
            kwargs["aws_access_key_id"] = self._auth.access_key
            kwargs["aws_secret_access_key"] = self._auth.secret_key
            if self._auth.session_token:
                kwargs["aws_session_token"] = self._auth.session_token
        elif isinstance(self._auth, BearerToken):
            # Bedrock bearer-token auth is exposed via the
            # ``aws_session_token`` parameter when used together with
            # empty access/secret keys; boto3 then sends
            # ``Authorization: Bearer <token>``.
            kwargs["aws_access_key_id"] = ""
            kwargs["aws_secret_access_key"] = ""
            kwargs["aws_session_token"] = self._auth.token
        # DefaultAuth: pass nothing — boto3 resolves from env.
        return kwargs

    def _get_runtime_client(self) -> Any:
        """Lazily construct (and cache) the bedrock-runtime boto3 client."""
        if self._runtime_client is not None:
            return self._runtime_client
        with self._client_lock:
            if self._runtime_client is None:
                try:
                    import boto3  # type: ignore[import-untyped]
                except ImportError as exc:  # pragma: no cover — exercised via tests
                    raise RuntimeError(
                        "boto3 is required for the Bedrock provider; "
                        "install with `pip install boto3`"
                    ) from exc
                self._runtime_client = boto3.client(
                    "bedrock-runtime", **self._build_client_kwargs()
                )
                self._control_client = boto3.client(
                    "bedrock", **self._build_client_kwargs()
                )
        return self._runtime_client

    def _get_control_client(self) -> Any:
        """Lazily construct (and cache) the bedrock control-plane client."""
        if self._control_client is None:
            self._get_runtime_client()
        return self._control_client

    # ------------------------------------------------------------------
    # Provider protocol
    # ------------------------------------------------------------------

    def type(self) -> ProviderType:
        return ProviderType.BEDROCK

    def name(self) -> str:
        return self._provider_name

    def model(self, opt: ProviderOptionsType) -> str:
        """Resolve the model name for ``opt``.

        Falls back to :data:`BEDROCK_DEFAULT_MODEL` when the slot is empty
        — mirrors PentAGI's ``bedrockProvider.Model``.
        """
        agent = self._provider_config.get_agent_config(opt)
        if agent is not None and agent.model:
            return agent.model
        return BEDROCK_DEFAULT_MODEL

    def get_models(self) -> ModelsConfig:
        return ModelsConfig(models=list(self._models))

    def get_price_info(self, opt: ProviderOptionsType) -> PriceInfo | None:
        return self._provider_config.get_price_info(opt)

    def get_tool_call_id_template(self) -> str:
        """Return the cached Bedrock tool-call ID template.

        Uses a ``threading.Lock`` instead of Go's ``sync.Once`` but the
        semantics are identical: the template is computed exactly once
        per provider instance.
        """
        if self._tool_call_id_template is not None:
            return self._tool_call_id_template
        with self._tool_call_id_template_lock:
            if self._tool_call_id_template is None:
                self._tool_call_id_template = BEDROCK_TOOL_CALL_ID_TEMPLATE
        return self._tool_call_id_template

    # ------------------------------------------------------------------
    # Call entrypoints
    # ------------------------------------------------------------------

    def call(
        self,
        opt: ProviderOptionsType,
        prompt: str,
    ) -> str:
        """Single-prompt convenience call — wraps :meth:`call_ex`.

        Builds a 1-message chain (user role, single text part) and
        returns the first choice's content. Mirrors PentAGI's
        ``WrapGenerateFromSinglePrompt``.
        """
        chain = [MessageContent(role="user", parts=[TextPart(text=prompt)])]
        resp = self.call_ex(opt, chain, stream_cb=None)
        if not resp.choices:
            raise RuntimeError("empty response from Bedrock")
        return resp.choices[0].content

    def call_ex(
        self,
        opt: ProviderOptionsType,
        chain: list[MessageContent],
        stream_cb: StreamingCallback | None = None,
    ) -> ContentResponse:
        """Multi-turn call without new tools (mirrors ``CallEx``).

        Implements the Bedrock Converse API quirk: if the chain already
        carries ``toolUse`` / ``toolResult`` blocks, minimal tool
        definitions are reconstructed from prior tool calls so the
        request includes a non-empty ``toolConfig``.
        """
        tools = self._restore_missed_tools_from_chain(chain, [])
        tools = self._clean_tools(tools)
        return self._invoke_converse(opt, chain, tools, stream_cb)

    def call_with_tools(
        self,
        opt: ProviderOptionsType,
        chain: list[MessageContent],
        tools: list[dict[str, Any]],
        stream_cb: StreamingCallback | None = None,
    ) -> ContentResponse:
        """Multi-turn call with explicit tools (mirrors ``CallWithTools``).

        Same Converse-API quirk handling as :meth:`call_ex`: missing
        tools are reconstructed from the chain, then ``$schema`` is
        stripped from every tool's parameters.
        """
        tools = self._restore_missed_tools_from_chain(chain, tools)
        tools = self._clean_tools(tools)
        return self._invoke_converse(opt, chain, tools, stream_cb)

    # ------------------------------------------------------------------
    # Converse API invocation + 429 retry
    # ------------------------------------------------------------------

    def _invoke_converse(
        self,
        opt: ProviderOptionsType,
        chain: list[MessageContent],
        tools: list[dict[str, Any]],
        stream_cb: StreamingCallback | None,
    ) -> ContentResponse:
        """Invoke Bedrock ``converse`` (or ``converse_stream``) with retry.

        The 429 retry policy uses ``tenacity`` with 10 attempts, 5 s
        base + 1 s linear increment per attempt — matching PentAGI's
        ``MaxTooManyRequestsRetries`` / ``TooManyRequestsRetryDelay``
        exactly. ``tenacity`` is imported lazily so the module can be
        imported without it installed.
        """
        agent = self._provider_config.get_agent_config(opt)
        model_id = self.model(opt)
        request = self._build_converse_request(model_id, agent, chain, tools)

        client = self._get_runtime_client()
        if stream_cb is not None:
            return self._invoke_with_retry_streaming(client, request, stream_cb, opt)
        return self._invoke_with_retry(client, request, opt)

    def _invoke_with_retry(
        self,
        client: Any,
        request: dict[str, Any],
        opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Call ``converse`` with 429 retry (non-streaming path)."""
        try:
            from tenacity import (
                Retrying,
                retry_if_exception_type,
                stop_after_attempt,
                wait_fixed,
                wait_incrementing,
            )
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "tenacity is required for the Bedrock provider; "
                "install with `pip install tenacity`"
            ) from exc

        retrying = Retrying(
            stop=stop_after_attempt(BEDROCK_MAX_429_RETRIES),
            wait=wait_fixed(BEDROCK_429_BASE_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_BedrockTooManyRequests),
            reraise=True,
        )

        for attempt in retrying:
            with attempt:
                try:
                    response = client.converse(**request)
                except Exception as exc:
                    if _is_too_many_requests(exc):
                        logger.warning(
                            "bedrock 429 on slot %s, retrying (attempt %d/%d)",
                            opt.value,
                            attempt.retry_state.attempt_number,
                            BEDROCK_MAX_429_RETRIES,
                        )
                        raise _BedrockTooManyRequests(str(exc)) from exc
                    raise
        return self._parse_converse_response(response, opt)  # type: ignore[name-defined]

    def _invoke_with_retry_streaming(
        self,
        client: Any,
        request: dict[str, Any],
        stream_cb: StreamingCallback,
        opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Call ``converse_stream`` with 429 retry (streaming path)."""
        try:
            from tenacity import (
                Retrying,
                retry_if_exception_type,
                stop_after_attempt,
                wait_fixed,
                wait_incrementing,
            )
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "tenacity is required for the Bedrock provider; "
                "install with `pip install tenacity`"
            ) from exc

        retrying = Retrying(
            stop=stop_after_attempt(BEDROCK_MAX_429_RETRIES),
            wait=wait_fixed(BEDROCK_429_BASE_DELAY) + wait_incrementing(0, 1),
            retry=retry_if_exception_type(_BedrockTooManyRequests),
            reraise=True,
        )

        response_stream: Any = None
        for attempt in retrying:
            with attempt:
                try:
                    response_stream = client.converse_stream(**request)
                except Exception as exc:
                    if _is_too_many_requests(exc):
                        logger.warning(
                            "bedrock 429 (stream) on slot %s, retrying (attempt %d/%d)",
                            opt.value,
                            attempt.retry_state.attempt_number,
                            BEDROCK_MAX_429_RETRIES,
                        )
                        raise _BedrockTooManyRequests(str(exc)) from exc
                    raise
        return self._parse_converse_stream_response(response_stream, opt, stream_cb)

    # ------------------------------------------------------------------
    # Request / response translation
    # ------------------------------------------------------------------

    def _build_converse_request(
        self,
        model_id: str,
        agent: AgentConfig | None,
        chain: list[MessageContent],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build a Bedrock ``converse`` request body.

        Translates the provider-agnostic :class:`MessageContent` chain
        into Bedrock's ``messages`` / ``system`` / ``toolConfig`` shape.
        Tool schemas are passed through :func:`clean_tool_schemas` to
        strip ``$schema`` (Bedrock rejects it).
        """
        system_blocks: list[dict[str, Any]] = []
        converse_messages: list[dict[str, Any]] = []

        for msg in chain:
            role = msg.role
            if role == "system":
                text = _collect_text(msg.parts)
                if text:
                    system_blocks.append({"text": text})
                continue

            bedrock_role = "assistant" if role in ("assistant", "tool") else "user"
            content_blocks: list[dict[str, Any]] = []

            for part in msg.parts:
                if isinstance(part, TextPart):
                    if part.text:
                        content_blocks.append({"text": part.text})
                elif isinstance(part, ToolCall):
                    # Assistant tool call -> Bedrock ``toolUse`` block.
                    content_blocks.append(
                        {
                            "toolUse": {
                                "toolUseId": part.id or generate_tool_call_id(),
                                "name": part.name,
                                "input": _safe_json_loads(part.arguments, {}),
                            }
                        }
                    )
                elif isinstance(part, ToolCallResponse):
                    # Tool result -> Bedrock ``toolResult`` block. Bedrock
                    # requires toolResult to be in a ``user`` message.
                    if bedrock_role != "user":
                        # Flush current message, start a new user one.
                        if content_blocks:
                            converse_messages.append(
                                {"role": bedrock_role, "content": content_blocks}
                            )
                            content_blocks = []
                        bedrock_role = "user"
                    content_blocks.append(
                        {
                            "toolResult": {
                                "toolUseId": part.tool_call_id,
                                "content": [{"text": part.content}],
                            }
                        }
                    )

            if content_blocks:
                converse_messages.append({"role": bedrock_role, "content": content_blocks})

        request: dict[str, Any] = {
            "modelId": model_id,
            "messages": converse_messages,
        }
        if system_blocks:
            request["system"] = system_blocks

        # Inference config — ported from AgentConfig.BuildOptions().
        inference_config: dict[str, Any] = {}
        if agent is not None:
            if agent.max_tokens is not None:
                inference_config["maxTokens"] = agent.max_tokens
            if agent.temperature is not None:
                inference_config["temperature"] = agent.temperature
            if agent.top_p is not None:
                inference_config["topP"] = agent.top_p
            if agent.n is not None and agent.n > 1:
                # Bedrock doesn't support N>1 directly; emit a warning.
                logger.warning(
                    "Bedrock Converse API does not support n>1; ignoring n=%d",
                    agent.n,
                )
        if inference_config:
            request["inferenceConfig"] = inference_config

        # Tool config — must be present whenever the chain carries
        # toolUse/toolResult blocks (Bedrock ValidationException otherwise).
        if tools:
            cleaned = clean_tool_schemas({"tools": tools})
            request["toolConfig"] = {
                "tools": [
                    {
                        "toolSpec": {
                            "name": t.get("function", {}).get("name", t.get("name", "")),
                            "description": t.get("function", {}).get(
                                "description", t.get("description", "")
                            ),
                            "inputSchema": {
                                "json": t.get("function", {}).get(
                                    "parameters", t.get("parameters", {})
                                ),
                            },
                        }
                    }
                    for t in cleaned.get("tools", [])
                ]
            }

        return request

    def _parse_converse_response(
        self,
        response: Any,
        opt: ProviderOptionsType,
    ) -> ContentResponse:
        """Translate a Bedrock ``converse`` response into ContentResponse."""
        output = (response or {}).get("output", {})
        message = output.get("message", {})
        content_blocks = message.get("content", [])

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for block in content_blocks:
            if "text" in block:
                text_parts.append(block["text"])
            elif "toolUse" in block:
                tu = block["toolUse"]
                tool_calls.append(
                    ToolCall(
                        id=tu.get("toolUseId", ""),
                        name=tu.get("name", ""),
                        arguments=json.dumps(tu.get("input", {})),
                    )
                )

        choice = Choice(
            content="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=(response or {}).get("stopReason", ""),
            generation_info=dict(response or {}),
        )

        usage = self._extract_usage((response or {}).get("usage", {}))
        usage.update_cost(self.get_price_info(opt))

        return ContentResponse(choices=[choice], usage=usage)

    def _parse_converse_stream_response(
        self,
        response_stream: Any,
        opt: ProviderOptionsType,
        stream_cb: StreamingCallback,
    ) -> ContentResponse:
        """Translate a Bedrock ``converse_stream`` response.

        Streams text deltas to ``stream_cb`` as they arrive; aggregates
        tool-use blocks and usage into the final :class:`ContentResponse`.
        """
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        stop_reason = ""
        usage_dict: dict[str, Any] = {}

        stream = response_stream.get("stream", []) if response_stream else []
        for event in stream:
            if "contentBlockDelta" in event:
                delta = event["contentBlockDelta"].get("delta", {})
                if "text" in delta:
                    text_parts.append(delta["text"])
                    stream_cb(delta["text"])
            elif "contentBlockStart" in event:
                start = event["contentBlockStart"].get("start", {})
                if "toolUse" in start:
                    tu = start["toolUse"]
                    tool_calls.append(
                        ToolCall(
                            id=tu.get("toolUseId", ""),
                            name=tu.get("name", ""),
                            arguments="{}",
                        )
                    )
            elif "contentBlockStop" in event:
                # Bedrock streams toolUse input as a separate
                # ``toolUseInput`` delta stream in some SDK versions; the
                # final input is available on the finished block.
                pass
            elif "messageStop" in event:
                stop_reason = event["messageStop"].get("stopReason", "")
            elif "metadata" in event and "usage" in event["metadata"]:
                usage_dict = event["metadata"]["usage"]
            elif "usage" in event:
                usage_dict = event["usage"]

        choice = Choice(
            content="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            generation_info={"streamed": True},
        )
        usage = self._extract_usage(usage_dict)
        usage.update_cost(self.get_price_info(opt))
        return ContentResponse(choices=[choice], usage=usage)

    @staticmethod
    def _extract_usage(usage_dict: dict[str, Any]) -> CallUsage:
        """Translate Bedrock's usage dict into :class:`CallUsage`.

        Bedrock uses camelCase keys (``inputTokens``, ``outputTokens``,
        ``cacheReadInputTokens``, ``cacheWriteInputTokens``). We map them
        to the PentAGI-style snake_case fields.
        """
        return CallUsage(
            input_tokens=int(usage_dict.get("inputTokens", 0) or 0),
            output_tokens=int(usage_dict.get("outputTokens", 0) or 0),
            cache_read_tokens=int(usage_dict.get("cacheReadInputTokens", 0) or 0),
            cache_write_tokens=int(usage_dict.get("cacheWriteInputTokens", 0) or 0),
        )

    # ------------------------------------------------------------------
    # Tool reconstruction helpers — ported from bedrock.go
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Apply :func:`clean_tool_schemas` to each tool's parameters."""
        if not tools:
            return tools
        cleaned_list: list[dict[str, Any]] = []
        for tool in tools:
            if not isinstance(tool, dict):
                cleaned_list.append(tool)
                continue
            # Normalise to OpenAI shape {function: {parameters: {...}}}
            # so clean_tool_schemas can find the parameters block.
            function = tool.get("function")
            if isinstance(function, dict):
                params = function.get("parameters")
                if isinstance(params, dict):
                    cleaned_params = clean_tool_schemas(params)
                    new_function = dict(function)
                    new_function["parameters"] = cleaned_params
                    new_tool = dict(tool)
                    new_tool["function"] = new_function
                    cleaned_list.append(new_tool)
                    continue
            cleaned_list.append(tool)
        return cleaned_list

    @classmethod
    def _restore_missed_tools_from_chain(
        cls,
        chain: list[MessageContent],
        tools: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Reconstruct minimal tool defs from prior tool calls in ``chain``.

        Ported from ``restoreMissedToolsFromChain``. The Bedrock Converse
        API requires ``toolConfig`` to be present whenever the message
        chain contains ``toolUse`` / ``toolResult`` blocks — even when no
        new tools are being offered. We collect every distinct tool name
        from the chain and, for tools not already declared, synthesise a
        minimal definition by reflection-inferring the parameter schema
        from the actual argument samples.
        """
        declared: dict[str, dict[str, Any]] = {}
        for tool in tools:
            name = _tool_name(tool)
            if name:
                declared[name] = tool

        usage = cls._collect_tool_usage_from_chain(chain)
        if not usage:
            return list(tools)

        result: list[dict[str, Any]] = list(tools)
        for name, arg_samples in usage.items():
            if name in declared:
                continue
            schema = cls._infer_schema_from_arguments(arg_samples)
            result.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": f"Tool: {name}",
                        "parameters": schema,
                    },
                }
            )
        return result

    @staticmethod
    def _collect_tool_usage_from_chain(
        chain: list[MessageContent],
    ) -> dict[str, list[str]]:
        """Collect ``{tool_name: [arg_json, ...]}`` from the chain.

        Ported from ``collectToolUsageFromChain``. ``ToolCallResponse``
        parts don't carry arguments, but their ``name`` is recorded with
        an empty sample list so the tool gets a stub definition.
        """
        usage: dict[str, list[str]] = {}
        for msg in chain:
            for part in msg.parts:
                if isinstance(part, ToolCall):
                    if part.name:
                        usage.setdefault(part.name, []).append(part.arguments)
                elif isinstance(part, ToolCallResponse):
                    if part.name:
                        usage.setdefault(part.name, [])
        return usage

    @staticmethod
    def _infer_schema_from_arguments(
        argument_samples: list[str],
    ) -> dict[str, Any]:
        """Infer a JSON schema from actual argument samples.

        Ported from ``inferSchemaFromArguments``. Only top-level property
        types are classified (string / number / boolean / array / object /
        null) — deeper nesting is not descended into. The first sample
        wins for any given property; later samples are ignored for that
        key (matches the Go original).
        """
        schema: dict[str, Any] = {"type": "object", "properties": {}}
        if not argument_samples:
            return schema

        properties: dict[str, Any] = {}
        for arg_json in argument_samples:
            if not arg_json:
                continue
            try:
                args = json.loads(arg_json)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(args, dict):
                continue
            for key, value in args.items():
                if key in properties:
                    continue
                properties[key] = {"type": _infer_property_type(value)}

        schema["properties"] = properties
        return schema


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class _BedrockTooManyRequests(Exception):
    """Internal sentinel raised to trigger tenacity 429 retry."""


def _is_too_many_requests(exc: BaseException) -> bool:
    """Return True if ``exc`` represents an HTTP 429 / throttling error.

    Ported from ``isTooManyRequestsError``. Checks for:
    * boto3 ``ClientError`` with ``TooManyRequestsException`` /
      ``ThrottlingException`` error codes.
    * bare ``429`` / ``TooManyRequests`` / ``too many requests`` substrings
      in the error message.
    """
    err_str = str(exc).lower()

    # boto3 ClientError — check error code attribute.
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")  # type: ignore[union-attr]
    if code in ("TooManyRequestsException", "ThrottlingException"):
        return True

    if "statuscode: 429" in err_str:
        return True
    if "toomanyrequests" in err_str or "too many requests" in err_str:
        return True
    return False


def _collect_text(parts: Iterable[MessagePart]) -> str:
    """Concatenate every :class:`TextPart` in ``parts``."""
    return "".join(p.text for p in parts if isinstance(p, TextPart))


def _safe_json_loads(s: str, default: Any) -> Any:
    """``json.loads`` with a default on failure."""
    if not s:
        return default
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return default


def _tool_name(tool: dict[str, Any]) -> str:
    """Extract the tool name from an OpenAI-shape tool dict."""
    function = tool.get("function")
    if isinstance(function, dict):
        return function.get("name", "")
    return tool.get("name", "")


def _infer_property_type(value: Any) -> str:
    """Classify a Python value into a JSON-schema type string.

    Ported from ``inferPropertyType``. Only top-level types are returned
    (no nested ``items`` / ``properties``), matching the Go original's
    behaviour of leaving deeper inference to the caller.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):  # bool must come before int (bool is int subclass)
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (list, tuple)):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "object"


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------


__all__ = [
    "BEDROCK_DEFAULT_MODEL",
    "BEDROCK_TOOL_CALL_ID_TEMPLATE",
    "BEDROCK_MAX_429_RETRIES",
    "BEDROCK_429_BASE_DELAY",
    "BEDROCK_DEFAULT_MODELS",
    "BedrockAuth",
    "DefaultAuth",
    "BearerToken",
    "StaticCredentials",
    "BedrockProvider",
    "resolve_auth_from_env",
    "generate_tool_call_id",
    "get_default_config",
]

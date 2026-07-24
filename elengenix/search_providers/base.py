"""elengenix/search_providers/base.py — Common base class for all search providers.

This module ports PentAGI's ``backend/pkg/tools/search.go`` ``Tool``-style
interface to Python. Every concrete search provider (Tavily, Perplexity,
DuckDuckGo, Google, Sploitus, Traversaal, SearXNG) subclasses
:class:`SearchProvider` and implements two coroutines:

* :meth:`SearchProvider.search` — execute the query and return a Markdown
  formatted result string (optionally LLM-summarised when the result exceeds
  the 3000-character threshold).
* :meth:`SearchProvider.is_available` — return ``True`` if the provider is
  properly configured in the current environment (API key present, opt-in
  flag set, etc.).

The module also provides:

* :class:`SearchAction` — a Pydantic v2 model mirroring the JSON schema
  PentAGI injects into the LLM's tool definitions (``{"query": str,
  "max_results": int}``).
* :func:`summarize_if_needed` — a common helper that invokes an async LLM
  summarizer when the raw output exceeds 3000 characters. This is used by
  the Tavily and Perplexity providers (and is available to any provider
  that opts in).
* :class:`SearchSummarizerProtocol` — a runtime-checkable Protocol so
  concrete providers can be wired with whatever async LLM client
  Elengenix's environment supplies (``universal_ai_client``,
  ``llm_reasoning``, etc.) without a hard dependency on any specific SDK.

All HTTP I/O is performed through ``httpx.AsyncClient`` (lazy-imported per
provider module so the base module stays dependency-light for AST-level
test discovery).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field

logger = logging.getLogger("elengenix.search_providers.base")

# ---------------------------------------------------------------------------
# Constants — ported verbatim from PentAGI.
# ---------------------------------------------------------------------------

#: Character threshold above which the search provider will hand its raw
#: output to the LLM summarizer. Mirrors PentAGI's ``3000``-byte cutoff
#: applied to Tavily / Perplexity outputs before ``getSummarizePrompt`` is
#: invoked.
SUMMARIZE_THRESHOLD: int = 3000

#: Maximum number of results a single search call may return. PentAGI's
#: search tools cap at 10 across the board.
DEFAULT_MAX_RESULTS: int = 10


# ---------------------------------------------------------------------------
# Pydantic v2 schema — JSON-schema compatible with PentAGI's tool definitions.
# ---------------------------------------------------------------------------


class SearchAction(BaseModel):
    """Pydantic model for the JSON arguments every search tool accepts.

    Mirrors the JSON schema PentAGI injects into the LLM's
    ``functions`` array for each search tool:

    .. code-block:: json

       {"type": "object",
        "properties": {
            "query":       {"type": "string", "minLength": 1},
            "max_results": {"type": "integer", "minimum": 1, "maximum": 50,
                            "default": 10}
        },
        "required": ["query"]}

    The model is strict-by-default (Pydantic v2) and rejects unknown keys
    so malformed tool calls surface early rather than being silently
    dropped.
    """

    model_config = {
        "extra": "forbid",
        "str_strip_whitespace": True,
        "str_min_length": 1,
    }

    query: str = Field(
        ...,
        description="The search query string (non-empty).",
        min_length=1,
        max_length=2000,
    )
    max_results: int = Field(
        default=DEFAULT_MAX_RESULTS,
        description="Maximum number of results to return (1..50).",
        ge=1,
        le=50,
    )


# ---------------------------------------------------------------------------
# Summarizer protocol — lets callers wire any async LLM in.
# ---------------------------------------------------------------------------


@runtime_checkable
class SearchSummarizerProtocol(Protocol):
    """Minimal async LLM interface for the search-provider summarizer.

    Implementations are expected to wrap Elengenix's existing LLM clients
    (``universal_ai_client``, ``llm_reasoning``, or the
    :class:`elengenix.agents.summarizer.AsyncLLMProvider` protocol). The
    only contract is a single coroutine that takes a ``prompt`` (and
    optional ``system``) and returns the model's text completion.
    """

    async def complete_async(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
    ) -> str:
        """Return the model's completion for ``prompt``."""
        ...


# ---------------------------------------------------------------------------
# Default summarization prompt — ported from PentAGI's
# ``templates/prompts/get_summarize_prompt.tmpl``.
# ---------------------------------------------------------------------------

SUMMARIZE_SYSTEM_PROMPT: str = (
    "You are the search-result summarizer inside the Elengenix multi-agent "
    "system. You condense raw search output into a faithful, citation-aware "
    "Markdown summary that preserves:\n"
    "- All factual claims and key URLs.\n"
    "- The original citation numbering ([Source #N]).\n"
    "- The order and meaning of results.\n\n"
    "Rules:\n"
    "- Be concise but loss-less: a downstream agent reading your summary must "
    "be able to continue the task without re-reading the raw output.\n"
    "- Do NOT invent facts. If something is ambiguous, say 'unclear'.\n"
    "- Keep the Markdown structure (headings, lists, citation markers).\n"
    "- Output a single Markdown block of <= 800 words.\n"
)


def _build_summarize_prompt(query: str, raw_output: str) -> str:
    """Build the user-message prompt for the search-result summarizer.

    Ports the ``getSummarizePrompt`` template from PentAGI. The prompt
    inlines the original query and the raw output (already truncated to
    a reasonable bound by callers) and instructs the model to preserve
    citation markers like ``[Source #N]``.

    Args:
        query: The original search query.
        raw_output: The raw search provider output to be summarised.

    Returns:
        A formatted prompt string ready to send to an LLM.
    """
    return (
        f"Original search query:\n```\n{query}\n```\n\n"
        f"Raw search results (may be truncated):\n"
        f"```\n{raw_output}\n```\n\n"
        "Summarise the above search results into a faithful, "
        "citation-preserving Markdown summary. Keep all URLs and "
        "source-citation markers like [Source #N]."
    )


async def summarize_if_needed(
    *,
    query: str,
    raw_output: str,
    summarizer: Optional[SearchSummarizerProtocol],
    threshold: int = SUMMARIZE_THRESHOLD,
) -> str:
    """Return ``raw_output``, LLM-summarised if it exceeds ``threshold``.

    Mirrors PentAGI's pattern in ``tavily.go`` / ``perplexity.go``:

    * If ``len(raw_output) <= threshold``: return ``raw_output`` unchanged.
    * If a ``summarizer`` is provided: invoke it with a summarization
      prompt and return its response. If the summarizer raises, log the
      error and fall back to the truncated raw output (never propagate
      the exception — search must remain best-effort).
    * If no ``summarizer`` is provided: return the raw output truncated
      to ``threshold`` characters with a truncation marker appended.

    Args:
        query: The original search query (inlined into the prompt).
        raw_output: The raw output produced by the search provider.
        summarizer: Optional async LLM summarizer implementing
            :class:`SearchSummarizerProtocol`. ``None`` disables LLM
            summarization.
        threshold: Character threshold above which summarization kicks
            in. Defaults to :data:`SUMMARIZE_THRESHOLD`.

    Returns:
        The final result string (either summarised, truncated, or
        unchanged).
    """
    if len(raw_output) <= threshold:
        return raw_output

    if summarizer is None:
        # No summarizer wired in — hard truncate with a marker.
        truncated = raw_output[:threshold]
        return (
            f"{truncated}\n\n"
            f"⚠️ Note: Raw output truncated at {threshold} characters "
            f"(full length: {len(raw_output)})."
        )

    try:
        prompt = _build_summarize_prompt(query, raw_output)
        summarised = await summarizer.complete_async(
            prompt=prompt,
            system=SUMMARIZE_SYSTEM_PROMPT,
        )
        if summarised and summarised.strip():
            return summarised.strip()
    except Exception as exc:  # noqa: BLE001 — best-effort summarization
        logger.warning(
            "search_summarize_failed query=%r error=%r -- falling back to "
            "truncated raw output",
            query,
            exc,
        )

    # Summarizer returned empty OR raised — fall back to truncation.
    truncated = raw_output[:threshold]
    return (
        f"{truncated}\n\n"
        f"⚠️ Note: Raw output truncated at {threshold} characters "
        f"(full length: {len(raw_output)})."
    )


# ---------------------------------------------------------------------------
# SearchProvider ABC.
# ---------------------------------------------------------------------------


class SearchProvider(ABC):
    """Abstract base class for all search providers.

    Concrete subclasses must implement :meth:`search` and
    :meth:`is_available`. The base class provides:

    * A ``name`` attribute (provider short-name, lower-case, matches the
      registry key).
    * A ``summarizer`` slot — when set to a
      :class:`SearchSummarizerProtocol` implementation, providers that
      support LLM summarization (Tavily, Perplexity) will use it to
      condense large outputs.
    * A default ``__repr__`` for loggability.

    All concrete providers should be async-friendly and use
    ``httpx.AsyncClient`` for HTTP. Heavy SDK imports (``httpx``,
    ``lxml``, ``googleapiclient``) MUST be performed lazily inside the
    methods that need them so the module imports cleanly for AST-level
    test discovery in environments where the optional deps are absent.
    """

    #: Short, lower-case name of the provider — MUST be overridden by
    #: subclasses and MUST match the registry key.
    name: str = "base"

    #: Display-friendly human-readable name (used in logs / UI).
    display_name: str = "Base Search Provider"

    def __init__(
        self,
        *,
        summarizer: Optional[SearchSummarizerProtocol] = None,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        **_: Any,
    ) -> None:
        """Initialise the provider.

        Args:
            summarizer: Optional async LLM summarizer for condensing
                large outputs. Only used by providers that opt in
                (Tavily, Perplexity).
            timeout: Default HTTP timeout in seconds for the provider's
                outbound requests. May be overridden per-provider.
            proxy: Optional HTTP/HTTPS proxy URL. When provided, every
                ``httpx.AsyncClient`` created by the provider will be
                configured with this proxy.
        """
        self.summarizer: Optional[SearchSummarizerProtocol] = summarizer
        self.timeout: float = float(timeout)
        self.proxy: Optional[str] = proxy

    @abstractmethod
    async def search(
        self,
        query: str,
        max_results: int = DEFAULT_MAX_RESULTS,
    ) -> str:
        """Execute the search and return a Markdown-formatted result.

        Args:
            query: Non-empty search query string.
            max_results: Maximum number of results to return. Clamped
                per-provider to the provider-specific hard cap.

        Returns:
            Markdown-formatted search result string. When the raw output
            exceeds :data:`SUMMARIZE_THRESHOLD` and a summarizer is
            configured, the returned string is the LLM-summarised
            version.
        """
        raise NotImplementedError

    @abstractmethod
    def is_available(self) -> bool:
        """Return ``True`` if the provider is properly configured.

        Examples:
          * Tavily: ``TAVILY_API_KEY != ""``
          * DuckDuckGo: ``DUCKDUCKGO_ENABLED=true`` (default true)
          * SearXNG: ``SEARXNG_URL != ""``
        """
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover — trivial
        return (
            f"<{self.__class__.__name__} name={self.name!r} "
            f"available={self.is_available()}>"
        )

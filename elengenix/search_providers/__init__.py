"""elengenix.search_providers — PentAGI-style multi-provider search layer.

This package ports PentAGI's 7 search providers
(``backend/pkg/tools/{tavily,perplexity,duckduckgo,google,sploitus,
traversaal,searxng}.go``) to async Python clients built on
``httpx.AsyncClient``. All providers share a common :class:`SearchProvider`
ABC and accept the same ``(query, max_results)`` arguments.

Provider roster:
    * :class:`TavilySearchProvider`        — LLM-friendly web search (body-key auth).
    * :class:`PerplexitySearchProvider`    — Sonar chat-completions (bearer auth).
    * :class:`DuckDuckGoSearchProvider`    — FREE HTML scrape (no auth).
    * :class:`GoogleSearchProvider`        — Custom Search JSON API (API+CX).
    * :class:`SploitusSearchProvider`      — Exploit/PoC search (no auth).
    * :class:`TraversaalSearchProvider`    — ARES LLM-grounded search (x-api-key).
    * :class:`SearXNGSearchProvider`       — Self-hosted meta search (no auth).

Common base:
    * :class:`SearchProvider` — ABC with ``async search()`` and
      ``is_available()``.
    * :class:`SearchAction` — Pydantic v2 model for the JSON tool-args
      schema (``{"query": str, "max_results": int}``).
    * :func:`summarize_if_needed` — common LLM-summarization helper
      invoked when raw output exceeds 3000 chars (used by Tavily and
      Perplexity).

Registry:
    * :class:`SearchProviderRegistry` — constructs one of each provider,
      exposes ``get_provider(name)``, ``list_available_providers()``,
      and ``async search_all(query, max_results)`` (parallel fan-out via
      ``asyncio.gather``).

All HTTP/HTML/SDK dependencies (``httpx``, ``lxml``, ``selectolax``,
``googleapiclient``) are lazy-imported inside the methods that need
them so the package imports cleanly for AST-level test discovery even
when the optional packages are not installed.
"""

from __future__ import annotations

from elengenix.search_providers.base import (
    DEFAULT_MAX_RESULTS,
    SUMMARIZE_SYSTEM_PROMPT,
    SUMMARIZE_THRESHOLD,
    SearchAction,
    SearchProvider,
    SearchSummarizerProtocol,
    summarize_if_needed,
)
from elengenix.search_providers.duckduckgo import (
    DuckDuckGoSearchProvider,
    DUCKDUCKGO_ENDPOINT,
    DUCKDUCKGO_MAX_RESULTS,
    DUCKDUCKGO_TIMEOUT,
    DUCKDUCKGO_USER_AGENT,
)
from elengenix.search_providers.google import (
    GoogleSearchProvider,
    GOOGLE_MAX_RESULTS,
    GOOGLE_TIMEOUT,
)
from elengenix.search_providers.perplexity import (
    PERPLEXITY_DEFAULT_MODEL,
    PERPLEXITY_ENDPOINT,
    PERPLEXITY_MAX_TOKENS,
    PERPLEXITY_TIMEOUT,
    PerplexitySearchProvider,
)
from elengenix.search_providers.registry import (
    SearchProviderRegistry,
    get_default_registry,
    reset_default_registry,
)
from elengenix.search_providers.searxng import (
    SEARXNG_DEFAULT_CATEGORIES,
    SEARXNG_DEFAULT_SAFESEARCH,
    SEARXNG_MAX_RESULTS,
    SEARXNG_TIMEOUT,
    SEARXNG_USER_AGENT,
    SearXNGSearchProvider,
)
from elengenix.search_providers.sploitus import (
    SPLOITUS_DEFAULT_LIMIT,
    SPLOITUS_ENDPOINT,
    SPLOITUS_MAX_LIMIT,
    SPLOITUS_MAX_SOURCE_SIZE,
    SPLOITUS_MAX_TOTAL_SIZE,
    SPLOITUS_TIMEOUT,
    SPLOITUS_TRUNCATION_BUFFER,
    SploitusSearchProvider,
)
from elengenix.search_providers.tavily import (
    TAVILY_ENDPOINT,
    TAVILY_PER_RESULT_TRUNC,
    TAVILY_TIMEOUT,
    TavilySearchProvider,
)
from elengenix.search_providers.traversaal import (
    TRAVERSAAL_ENDPOINT,
    TRAVERSAAL_TIMEOUT,
    TraversaalSearchProvider,
)

__all__ = [
    # base
    "DEFAULT_MAX_RESULTS",
    "SUMMARIZE_SYSTEM_PROMPT",
    "SUMMARIZE_THRESHOLD",
    "SearchAction",
    "SearchProvider",
    "SearchSummarizerProtocol",
    "summarize_if_needed",
    # tavily
    "TavilySearchProvider",
    "TAVILY_ENDPOINT",
    "TAVILY_TIMEOUT",
    "TAVILY_PER_RESULT_TRUNC",
    # perplexity
    "PerplexitySearchProvider",
    "PERPLEXITY_ENDPOINT",
    "PERPLEXITY_TIMEOUT",
    "PERPLEXITY_DEFAULT_MODEL",
    "PERPLEXITY_MAX_TOKENS",
    # duckduckgo
    "DuckDuckGoSearchProvider",
    "DUCKDUCKGO_ENDPOINT",
    "DUCKDUCKGO_TIMEOUT",
    "DUCKDUCKGO_MAX_RESULTS",
    "DUCKDUCKGO_USER_AGENT",
    # google
    "GoogleSearchProvider",
    "GOOGLE_MAX_RESULTS",
    "GOOGLE_TIMEOUT",
    # sploitus
    "SploitusSearchProvider",
    "SPLOITUS_ENDPOINT",
    "SPLOITUS_TIMEOUT",
    "SPLOITUS_DEFAULT_LIMIT",
    "SPLOITUS_MAX_LIMIT",
    "SPLOITUS_MAX_SOURCE_SIZE",
    "SPLOITUS_MAX_TOTAL_SIZE",
    "SPLOITUS_TRUNCATION_BUFFER",
    # traversaal
    "TraversaalSearchProvider",
    "TRAVERSAAL_ENDPOINT",
    "TRAVERSAAL_TIMEOUT",
    # searxng
    "SearXNGSearchProvider",
    "SEARXNG_TIMEOUT",
    "SEARXNG_MAX_RESULTS",
    "SEARXNG_DEFAULT_CATEGORIES",
    "SEARXNG_DEFAULT_SAFESEARCH",
    "SEARXNG_USER_AGENT",
    # registry
    "SearchProviderRegistry",
    "get_default_registry",
    "reset_default_registry",
]

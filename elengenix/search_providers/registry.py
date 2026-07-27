"""elengenix/search_providers/registry.py — Search-provider registry.

This module ports PentAGI's ``backend/pkg/tools/registry.go`` (the
search-tool portion) to a Python registry that:

* Instantiates one of each of the 7 search providers (Tavily, Perplexity,
  DuckDuckGo, Google, Sploitus, Traversaal, SearXNG).
* Exposes ``get_provider(name)`` for single-provider lookups.
* Exposes ``list_available_providers()`` for the UI / CLI to enumerate
  which providers are configured.
* Exposes ``async search_all(query, max_results)`` which fans out to
  every available provider in parallel via ``asyncio.gather`` and
  returns a ``{provider_name: result_string}`` dict.

The registry is intentionally a thin orchestrator — provider
configuration is read from environment variables at instantiation time,
matching PentAGI's ``cfg.*`` env-var resolution pattern. Callers can
override the env-derived configuration by passing explicit kwargs to
:meth:`SearchProviderRegistry.__init__` or to the individual provider
constructors.

All providers are constructed **eagerly** (so :meth:`is_available` checks
are O(1)), but their HTTP/SDK clients are lazy-imported inside the
``search`` coroutines — meaning the registry itself imports cleanly
even when ``httpx`` / ``lxml`` / ``googleapiclient`` aren't installed.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from elengenix.search_providers.base import (
    DEFAULT_MAX_RESULTS,
    SearchProvider,
    SearchSummarizerProtocol,
)
from elengenix.search_providers.duckduckgo import DuckDuckGoSearchProvider
from elengenix.search_providers.google import GoogleSearchProvider
from elengenix.search_providers.perplexity import PerplexitySearchProvider
from elengenix.search_providers.searxng import SearXNGSearchProvider
from elengenix.search_providers.sploitus import SploitusSearchProvider
from elengenix.search_providers.tavily import TavilySearchProvider
from elengenix.search_providers.traversaal import TraversaalSearchProvider

logger = logging.getLogger("elengenix.search_providers.registry")


# ---------------------------------------------------------------------------
# Registry.
# ---------------------------------------------------------------------------


class SearchProviderRegistry:
    """Registry for all 7 search providers.

    Constructing a registry instantiates one of each provider. The
    providers read their configuration (API keys, opt-in flags, etc.)
    from environment variables at construction time — call
    :meth:`list_available_providers` afterwards to discover which are
    actually usable.

    Example::

        registry = SearchProviderRegistry()
        print(registry.list_available_providers())
        # -> ['duckduckgo', 'tavily']

        results = await registry.search_all("cve-2024-1234", max_results=5)
        # -> {'duckduckgo': '...', 'tavily': '...'}
    """

    #: Ordered tuple of (name, provider-class) pairs. Order controls the
    #: default ``list_available_providers()`` output ordering.
    _PROVIDER_SPECS: tuple[tuple[str, type[SearchProvider]], ...] = (
        ("tavily", TavilySearchProvider),
        ("perplexity", PerplexitySearchProvider),
        ("duckduckgo", DuckDuckGoSearchProvider),
        ("google", GoogleSearchProvider),
        ("sploitus", SploitusSearchProvider),
        ("traversaal", TraversaalSearchProvider),
        ("searxng", SearXNGSearchProvider),
    )

    def __init__(
        self,
        *,
        summarizer: Optional[SearchSummarizerProtocol] = None,
        proxy: Optional[str] = None,
        timeout: Optional[float] = None,
        provider_kwargs: Optional[dict[str, dict[str, Any]]] = None,
    ) -> None:
        """Initialise the registry and construct every provider.

        Args:
            summarizer: Optional async LLM summarizer forwarded to every
                provider that supports it (Tavily, Perplexity).
            proxy: Optional HTTP/HTTPS proxy URL forwarded to every
                provider's ``httpx.AsyncClient``.
            timeout: Optional default HTTP timeout (seconds) forwarded
                to every provider. ``None`` lets each provider use its
                own default.
            provider_kwargs: Optional per-provider overrides. The outer
                key is the provider name (e.g. ``"tavily"``); the
                inner dict is forwarded as ``**kwargs`` to that
                provider's constructor.
        """
        self._summarizer = summarizer
        self._proxy = proxy
        self._timeout = timeout
        self._provider_kwargs = provider_kwargs or {}

        self._providers: dict[str, SearchProvider] = {}
        for name, cls in self._PROVIDER_SPECS:
            kwargs: dict[str, Any] = {}
            if summarizer is not None:
                kwargs["summarizer"] = summarizer
            if proxy is not None:
                kwargs["proxy"] = proxy
            if timeout is not None:
                kwargs["timeout"] = timeout
            # Per-provider overrides win.
            kwargs.update(self._provider_kwargs.get(name, {}))
            try:
                self._providers[name] = cls(**kwargs)
            except Exception as exc:  # noqa: BLE001 — best-effort init
                logger.error(
                    "registry_provider_init_failed name=%s error=%r",
                    name,
                    exc,
                )

    # -- Lookups ----------------------------------------------------------

    def get_provider(self, name: str) -> Optional[SearchProvider]:
        """Return the provider registered under ``name`` (case-insensitive).

        Returns ``None`` if no such provider is registered.
        """
        return self._providers.get(name.strip().lower())

    def list_providers(self) -> list[str]:
        """Return the names of all registered providers (available or not)."""
        return [name for name, _ in self._PROVIDER_SPECS if name in self._providers]

    def list_available_providers(self) -> list[str]:
        """Return the names of all providers whose ``is_available()`` is True.

        Order matches :data:`_PROVIDER_SPECS` (Tavily, Perplexity,
        DuckDuckGo, Google, Sploitus, Traversaal, SearXNG).
        """
        return [
            name
            for name, _ in self._PROVIDER_SPECS
            if name in self._providers and self._providers[name].is_available()
        ]

    def all_providers(self) -> dict[str, SearchProvider]:
        """Return a shallow copy of the underlying ``{name: provider}`` dict."""
        return dict(self._providers)

    # -- Fan-out search ---------------------------------------------------

    async def search_all(
        self,
        query: str,
        max_results: int = DEFAULT_MAX_RESULTS,
    ) -> dict[str, str]:
        """Fan out ``query`` to every available provider in parallel.

        Mirrors PentAGI's pattern of dispatching the same query to every
        configured search engine simultaneously, then collecting results
        into a ``{provider_name: result_string}`` dict. Failures in any
        single provider do NOT propagate — the corresponding dict value
        is set to an error string and the others continue.

        Args:
            query: Non-empty search query.
            max_results: Max results per provider (providers further
                clamp this to their own hard caps).

        Returns:
            ``{provider_name: result_string}`` dict. Keys are limited to
            available providers; never includes providers that returned
            ``is_available() == False``.
        """
        names = self.list_available_providers()
        if not names:
            logger.warning("registry_search_all_no_providers query=%r", query)
            return {}

        logger.info(
            "registry_search_all query=%r providers=%s max_results=%d",
            query,
            names,
            max_results,
        )

        async def _safe_search(name: str) -> tuple[str, str]:
            provider = self._providers[name]
            try:
                result = await provider.search(query, max_results=max_results)
                return name, result
            except asyncio.CancelledError:
                # Propagate cancellation — don't swallow it.
                raise
            except Exception as exc:  # noqa: BLE001 — best-effort fan-out
                logger.error(
                    "registry_search_failed provider=%s query=%r error=%r",
                    name,
                    query,
                    exc,
                )
                return name, f"{name} search failed: {exc}"

        tasks = [asyncio.create_task(_safe_search(n)) for n in names]
        # ``return_exceptions=True`` is belt-and-suspenders — _safe_search
        # already catches everything except cancellation.
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        results: dict[str, str] = {}
        for item in gathered:
            if isinstance(item, BaseException):
                # Cancellation or other low-level error — log and skip.
                logger.error(
                    "registry_search_all_gather_exception error=%r",
                    item,
                )
                continue
            name, result = item
            results[name] = result
        return results


# ---------------------------------------------------------------------------
# Module-level convenience: a lazily-initialised default registry.
# ---------------------------------------------------------------------------

_default_registry: Optional[SearchProviderRegistry] = None


def get_default_registry() -> SearchProviderRegistry:
    """Return a process-wide default registry (singleton).

    Constructed on first call. Subsequent calls return the same
    instance. The default registry has no summarizer and no proxy
    (providers fall back to environment-variable configuration).
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = SearchProviderRegistry()
    return _default_registry


def reset_default_registry() -> None:
    """Reset the singleton default registry (mainly for tests)."""
    global _default_registry
    _default_registry = None

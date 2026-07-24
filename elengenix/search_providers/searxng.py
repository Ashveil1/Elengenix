"""elengenix/search_providers/searxng.py — SearXNG self-hosted meta-search provider.

Ports PentAGI's ``backend/pkg/tools/searxng.go`` (289 lines) to an async
Python client. SearXNG is a privacy-respecting meta-search engine
typically self-hosted; the provider relies on network isolation for
security (no API key, no auth).

Endpoint:
    ``GET {SEARXNG_URL}/search?q=...&format=json&language=...&
    categories=...&safesearch=...&time_range=...&limit=N``

Auth:
    None (relies on network isolation — SearXNG is self-hosted).

Headers:
    ``User-Agent: Elengenix/2.0`` (PentAGI uses ``PentAGI/1.0``; we bump
    the version string to match the Elengenix project).

Response:
    .. code-block:: json

       {
         "query": "...",
         "results": [
           {"title": "...", "url": "...", "content": "...",
            "author": "...", "publishedDate": "...", "engine": "..."}
         ],
         "info": {"timings": {...}, "results": N,
                  "engine": "...", "suggestions": [...]}
       }

URL normalization (preserved verbatim from PentAGI):
    If ``SEARXNG_URL`` doesn't end with ``/search``, appends ``/search``.

Defaults (preserved verbatim):
    * Categories: ``general``
    * SafeSearch: ``0`` (0=off, 1=moderate, 2=strict)
    * Timeout: 30s
    * Language: empty (let SearXNG pick)

Availability: ``SEARXNG_URL`` env var is non-empty.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional
from urllib.parse import urlencode

from elengenix.search_providers.base import (
    DEFAULT_MAX_RESULTS,
    SearchProvider,
    SearchSummarizerProtocol,
)

logger = logging.getLogger("elengenix.search_providers.searxng")

# ---------------------------------------------------------------------------
# Constants — ported verbatim from PentAGI's searxng.go.
# ---------------------------------------------------------------------------

SEARXNG_TIMEOUT: float = 30.0
SEARXNG_DEFAULT_CATEGORIES: str = "general"
SEARXNG_DEFAULT_SAFESEARCH: int = 0
SEARXNG_MAX_RESULTS: int = 50
SEARXNG_USER_AGENT: str = "Elengenix/2.0"


# ---------------------------------------------------------------------------
# SearXNG provider.
# ---------------------------------------------------------------------------


class SearXNGSearchProvider(SearchProvider):
    """SearXNG self-hosted meta-search provider.

    Calls the ``/search`` JSON endpoint of a user-supplied SearXNG
    instance. No authentication — the provider relies on the operator
    having placed the SearXNG instance on an isolated network (preserved
    verbatim from PentAGI).

    URL normalization: if ``SEARXNG_URL`` doesn't end with ``/search``,
    appends ``/search`` (preserved verbatim).

    Availability gate: ``SEARXNG_URL`` env var is non-empty.
    """

    name = "searxng"
    display_name = "SearXNG"

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        categories: str = SEARXNG_DEFAULT_CATEGORIES,
        safesearch: int = SEARXNG_DEFAULT_SAFESEARCH,
        language: str = "",
        time_range: str = "",
        summarizer: Optional[SearchSummarizerProtocol] = None,
        timeout: float = SEARXNG_TIMEOUT,
        proxy: Optional[str] = None,
        **_: Any,
    ) -> None:
        super().__init__(summarizer=summarizer, timeout=timeout, proxy=proxy)
        raw_url = (base_url or os.environ.get("SEARXNG_URL", "")).strip()
        self._base_url: str = _normalize_searxng_url(raw_url)
        self.categories: str = categories or SEARXNG_DEFAULT_CATEGORIES
        # Clamp safesearch to SearXNG's accepted range (0, 1, 2).
        try:
            ss = int(safesearch)
        except (TypeError, ValueError):
            ss = SEARXNG_DEFAULT_SAFESEARCH
        self.safesearch: int = max(0, min(ss, 2))
        self.language: str = (language or "").strip()
        self.time_range: str = (time_range or "").strip()

    # -- SearchProvider interface -----------------------------------------

    def is_available(self) -> bool:
        """True when ``SEARXNG_URL`` is non-empty (after normalization)."""
        return bool(self._base_url)

    async def search(
        self,
        query: str,
        max_results: int = DEFAULT_MAX_RESULTS,
    ) -> str:
        """Search the configured SearXNG instance and return Markdown."""
        if not self.is_available():
            return "SearXNG search unavailable: SEARXNG_URL is not set."

        import httpx  # noqa: WPS433 — lazy import is intentional

        capped = max(1, min(int(max_results), SEARXNG_MAX_RESULTS))

        # Build query parameters (port-verbatim from PentAGI).
        params: dict[str, Any] = {
            "q": query,
            "format": "json",
            "categories": self.categories,
            "safesearch": self.safesearch,
            "limit": capped,
        }
        if self.language:
            params["language"] = self.language
        if self.time_range:
            params["time_range"] = self.time_range

        url = f"{self._base_url}?{urlencode(params, doseq=True)}"
        headers = {
            "User-Agent": SEARXNG_USER_AGENT,
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
        }

        client_kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        logger.info(
            "searxng_search query=%r base=%s cats=%s safe=%d lang=%s max=%d",
            query,
            self._base_url,
            self.categories,
            self.safesearch,
            self.language or "(default)",
            capped,
        )
        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                resp = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            logger.error("searxng_http_error query=%r error=%r", query, exc)
            return f"SearXNG search failed: HTTP error: {exc}"

        status = resp.status_code
        if status != 200:
            return _format_searxng_error(status, resp.text)

        try:
            payload = resp.json()
        except ValueError as exc:
            logger.error("searxng_bad_json query=%r error=%r", query, exc)
            return f"SearXNG search failed: invalid JSON response: {exc}"

        return _render_searxng_results(query, payload, capped)


# ---------------------------------------------------------------------------
# URL normalization — ported verbatim from PentAGI's searxng.go.
# ---------------------------------------------------------------------------


def _normalize_searxng_url(raw_url: str) -> str:
    """Normalize a SearXNG base URL.

    If the URL doesn't already end with ``/search``, appends ``/search``.
    Strips trailing slashes before the append so ``http://x/`` and
    ``http://x`` both become ``http://x/search``. Empty input returns
    empty string (treated as "not configured").
    """
    if not raw_url:
        return ""
    # Strip trailing slashes.
    stripped = raw_url.rstrip("/")
    if not stripped:
        return ""
    if stripped.endswith("/search"):
        return stripped
    return f"{stripped}/search"


# ---------------------------------------------------------------------------
# Rendering — Markdown output.
# ---------------------------------------------------------------------------


def _render_searxng_results(
    query: str, payload: dict[str, Any], max_results: int
) -> str:
    """Render SearXNG results as Markdown.

    Output format:

    .. code-block:: markdown

       # SearXNG Search: <query>

       ## Results (N)

       ### 1. <title>

       **URL:** <url>  **Engine:** <engine>

       <content>
    """
    results: list[dict[str, Any]] = payload.get("results") or []
    info: dict[str, Any] = payload.get("info") or {}
    info_count = info.get("results") if isinstance(info, dict) else None

    capped = results[:max_results]
    if not capped:
        return f"# SearXNG Search: {query}\n\n_No results returned._"

    lines: list[str] = [f"# SearXNG Search: {query}\n"]
    if isinstance(info_count, int):
        lines.append(
            f"_SearXNG reports {info_count} total results; "
            f"rendering top {len(capped)}._\n"
        )
    lines.append(f"## Results ({len(capped)})\n")
    for idx, r in enumerate(capped, start=1):
        title = (r.get("title") or "(untitled)").strip()
        url = (r.get("url") or "").strip()
        content = (r.get("content") or "").strip()
        engine = (r.get("engine") or "").strip()
        author = (r.get("author") or "").strip()
        published = (r.get("publishedDate") or "").strip()

        lines.append(f"### {idx}. {title}\n")
        meta: list[str] = []
        if engine:
            meta.append(f"engine: {engine}")
        if author:
            meta.append(f"author: {author}")
        if published:
            meta.append(f"published: {published}")
        if url:
            lines.append(f"**URL:** {url}")
        if meta:
            lines.append(f"**Meta:** {' | '.join(meta)}")
        if content:
            lines.append(f"\n{content}")
        lines.append("")

    return "\n".join(lines).strip()


# ---------------------------------------------------------------------------
# HTTP error mapping.
# ---------------------------------------------------------------------------


_SEARXNG_STATUS_MAP: dict[int, str] = {
    400: "invalid request",
    401: "auth required (unexpected — check SearXNG config)",
    403: "forbidden (SearXNG ACL block?)",
    404: "endpoint not found (check SEARXNG_URL)",
    405: "wrong HTTP method (GET required)",
    429: "rate limit exceeded",
    500: "SearXNG server error (500)",
    502: "SearXNG server error (502)",
    503: "SearXNG server error (503)",
    504: "SearXNG server error (504)",
}


def _format_searxng_error(status: int, body: str) -> str:
    """Format a SearXNG HTTP error response as a user-facing string."""
    reason = _SEARXNG_STATUS_MAP.get(status, f"HTTP {status}")
    snippet = (body or "").strip()
    if snippet and len(snippet) > 500:
        snippet = snippet[:500] + " …"
    suffix = f"\nResponse: {snippet}" if snippet else ""
    return f"SearXNG search failed ({reason}).{suffix}"

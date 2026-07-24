"""elengenix/search_providers/tavily.py — Tavily search provider.

Ports PentAGI's ``backend/pkg/tools/tavily.go`` (323 lines) to an async
Python client. Tavily is an LLM-friendly search API whose notable quirk
is that the API key is passed **in the request body**, not in an
``Authorization`` header.

Endpoint:
    ``POST https://api.tavily.com/search``

Request body (port-verbatim from PentAGI):
    .. code-block:: json

       {
         "api_key": "<key>", "query": "...", "topic": "general",
         "search_depth": "advanced", "include_images": false,
         "include_answer": true, "include_raw_content": true,
         "max_results": N, "include_domains": [],
         "exclude_domains": []
       }

Response:
    .. code-block:: json

       {"answer": "...", "query": "...", "response_time": 0.42,
        "results": [{"title": "...", "url": "...", "content": "...",
                     "raw_content": "...?", "score": 0.91}]}

Post-processing (mirrors PentAGI exactly):
    * If any result has a non-empty ``raw_content`` AND a summarizer is
      configured: concatenate all raw contents together (with citation
      markers like ``[Source #N]``) and hand the bundle to the LLM
      summarizer.
    * Otherwise: each result's content is rendered as a Markdown block
      truncated to 3000 chars per result.

HTTP status mapping (preserved verbatim):
    * 400 -> invalid request
    * 401 -> wrong API key
    * 403 -> admin-only endpoint
    * 404 -> not found
    * 405 -> wrong HTTP method
    * 429 -> rate limit
    * 500/502/503/504 -> server error

Availability: ``TAVILY_API_KEY`` environment variable is non-empty.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from elengenix.search_providers.base import (
    DEFAULT_MAX_RESULTS,
    SUMMARIZE_THRESHOLD,
    SearchProvider,
    SearchSummarizerProtocol,
    summarize_if_needed,
)

logger = logging.getLogger("elengenix.search_providers.tavily")

# ---------------------------------------------------------------------------
# Constants — ported verbatim from PentAGI's tavily.go.
# ---------------------------------------------------------------------------

TAVILY_ENDPOINT: str = "https://api.tavily.com/search"
TAVILY_TIMEOUT: float = 30.0

#: Per-result character cap for raw_content when no summarizer is wired.
#: Mirrors PentAGI's ``3000``-char per-result truncation.
TAVILY_PER_RESULT_TRUNC: int = 3000


# ---------------------------------------------------------------------------
# Tavily provider.
# ---------------------------------------------------------------------------


class TavilySearchProvider(SearchProvider):
    """Tavily search provider (LLM-friendly web search API).

    Auth is unusual: the API key is sent **in the JSON request body**
    (field ``api_key``), NOT in an ``Authorization`` header. This mirrors
    PentAGI's tavily.go verbatim.

    Availability gate: ``TAVILY_API_KEY`` env var is non-empty.
    """

    name = "tavily"
    display_name = "Tavily"

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        summarizer: Optional[SearchSummarizerProtocol] = None,
        timeout: float = TAVILY_TIMEOUT,
        proxy: Optional[str] = None,
        **_: Any,
    ) -> None:
        super().__init__(summarizer=summarizer, timeout=timeout, proxy=proxy)
        # Resolve API key: explicit arg -> env var. Empty string is
        # treated as "unset" (matches Go's ``cfg.TavilyAPIKey != ""``).
        self._api_key: str = (api_key or os.environ.get("TAVILY_API_KEY", "")).strip()

    # -- SearchProvider interface -----------------------------------------

    def is_available(self) -> bool:
        """True when ``TAVILY_API_KEY`` is non-empty."""
        return bool(self._api_key)

    async def search(
        self,
        query: str,
        max_results: int = DEFAULT_MAX_RESULTS,
    ) -> str:
        """Search Tavily and return Markdown-formatted results.

        See module docstring for the full request / response shape and
        post-processing rules.
        """
        if not self.is_available():
            return "Tavily search unavailable: TAVILY_API_KEY is not set."

        # Lazy import httpx so the module imports cleanly without httpx
        # installed (matters for AST-level test discovery).
        import httpx  # noqa: WPS433 — lazy import is intentional

        capped = max(1, min(int(max_results), 50))
        body = {
            "api_key": self._api_key,
            "query": query,
            "topic": "general",
            "search_depth": "advanced",
            "include_images": False,
            "include_answer": True,
            "include_raw_content": True,
            "max_results": capped,
            "include_domains": [],
            "exclude_domains": [],
        }

        client_kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        logger.info("tavily_search query=%r max_results=%d", query, capped)
        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                resp = await client.post(TAVILY_ENDPOINT, json=body)
        except httpx.HTTPError as exc:
            logger.error("tavily_http_error query=%r error=%r", query, exc)
            return f"Tavily search failed: HTTP error: {exc}"

        status = resp.status_code
        if status != 200:
            return _format_tavily_error(status, resp.text)

        try:
            payload = resp.json()
        except ValueError as exc:
            logger.error("tavily_bad_json query=%r error=%r", query, exc)
            return f"Tavily search failed: invalid JSON response: {exc}"

        return await self._render(query, payload)

    # -- Rendering helpers ------------------------------------------------

    async def _render(self, query: str, payload: dict[str, Any]) -> str:
        """Render the Tavily JSON payload as Markdown.

        When any result carries a non-empty ``raw_content`` AND a
        summarizer is wired, the raw contents are concatenated and sent
        to the summarizer (mirrors PentAGI's ``getSummarizePrompt``).
        Otherwise each result's content is rendered with a hard
        3000-char cap per result.
        """
        answer: str = (payload.get("answer") or "").strip()
        results: list[dict[str, Any]] = payload.get("results") or []

        if not results:
            base = (
                f"# Tavily Search: {query}\n\n"
                + (f"## Answer\n\n{answer}\n\n" if answer else "")
                + "_No results returned._"
            )
            return base

        # Collect raw contents for LLM summarization when available.
        raw_bundles: list[str] = []
        any_raw = False
        for idx, r in enumerate(results, start=1):
            raw = (r.get("raw_content") or "").strip()
            if raw:
                any_raw = True
                raw_bundles.append(
                    f"[Source #{idx}]\nURL: {r.get('url', '')}\n\n{raw}"
                )

        # If we have raw contents and a summarizer, route the bundle
        # through the LLM summarizer (port of PentAGI's getSummarizePrompt
        # branch).
        if any_raw and self.summarizer is not None:
            bundle = "\n\n---\n\n".join(raw_bundles)
            if answer:
                bundle = f"Instant answer: {answer}\n\n{bundle}"
            summarised = await summarize_if_needed(
                query=query,
                raw_output=bundle,
                summarizer=self.summarizer,
                threshold=SUMMARIZE_THRESHOLD,
            )
            header = f"# Tavily Search: {query}\n"
            if answer:
                header += f"\n## Instant Answer\n\n{answer}\n"
            return f"{header}\n## Summarised Results\n\n{summarised}"

        # Sync rendering: per-result truncated content.
        lines: list[str] = [f"# Tavily Search: {query}\n"]
        if answer:
            lines.append(f"## Answer\n\n{answer}\n")
        lines.append(f"## Results ({len(results)})\n")
        for idx, r in enumerate(results, start=1):
            title = (r.get("title") or "(untitled)").strip()
            url = (r.get("url") or "").strip()
            content = (r.get("content") or "").strip()
            if len(content) > TAVILY_PER_RESULT_TRUNC:
                content = content[:TAVILY_PER_RESULT_TRUNC] + " …"
            score = r.get("score")
            score_str = ""
            if isinstance(score, (int, float)) and score:
                try:
                    score_str = f" (score: {float(score):.2f})"
                except (TypeError, ValueError):
                    score_str = ""
            lines.append(f"### {idx}. {title}{score_str}\n")
            if url:
                lines.append(f"**URL:** {url}\n")
            if content:
                lines.append(f"{content}\n")

        return "\n".join(lines).strip()


# ---------------------------------------------------------------------------
# HTTP error mapping — preserved verbatim from PentAGI.
# ---------------------------------------------------------------------------

_TAVILY_STATUS_MAP: dict[int, str] = {
    400: "invalid request (query too long or malformed)",
    401: "wrong API key",
    403: "admin-only endpoint (key lacks permission)",
    404: "endpoint not found",
    405: "wrong HTTP method (POST required)",
    429: "rate limit exceeded",
    500: "Tavily server error (500)",
    502: "Tavily server error (502)",
    503: "Tavily server error (503)",
    504: "Tavily server error (504)",
}


def _format_tavily_error(status: int, body: str) -> str:
    """Format a Tavily HTTP error response as a user-facing string."""
    reason = _TAVILY_STATUS_MAP.get(status, f"HTTP {status}")
    snippet = (body or "").strip()
    if snippet and len(snippet) > 500:
        snippet = snippet[:500] + " …"
    suffix = f"\nResponse: {snippet}" if snippet else ""
    return f"Tavily search failed ({reason}).{suffix}"

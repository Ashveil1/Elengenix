"""elengenix/search_providers/traversaal.py — Traversaal ARES search provider.

Ports PentAGI's ``backend/pkg/tools/traversaal.go`` (175 lines) to an
async Python client. Traversaal's ARES API is an LLM-grounded web search
that returns a synthesized answer plus a list of supporting URLs.

Endpoint:
    ``POST https://api-ares.traversaal.ai/live/predict``

Auth:
    ``x-api-key: <api_key>`` header.

Request body (port-verbatim from PentAGI):
    .. code-block:: json

       {"query": "<query>"}

Response:
    .. code-block:: json

       {
         "data": {
           "response_text": "<answer>",
           "web_url": ["url1", "url2", ...]
         }
       }

Output format (port-verbatim from PentAGI):
    .. code-block:: markdown

       # Answer

       <response_text>

       # Links

       1. <url>
       2. <url>

Availability: ``TRAVERSAAL_API_KEY`` env var is non-empty.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from elengenix.search_providers.base import (
    DEFAULT_MAX_RESULTS,
    SearchProvider,
    SearchSummarizerProtocol,
)

logger = logging.getLogger("elengenix.search_providers.traversaal")

# ---------------------------------------------------------------------------
# Constants — ported verbatim from PentAGI's traversaal.go.
# ---------------------------------------------------------------------------

TRAVERSAAL_ENDPOINT: str = "https://api-ares.traversaal.ai/live/predict"
TRAVERSAAL_TIMEOUT: float = 30.0


# ---------------------------------------------------------------------------
# Traversaal provider.
# ---------------------------------------------------------------------------


class TraversaalSearchProvider(SearchProvider):
    """Traversaal ARES search provider (LLM-grounded web search).

    The ARES API returns a synthesized answer string plus a list of
    supporting URLs. Unlike Tavily / Perplexity, no LLM summarization is
    applied — the provider's response is already LLM-synthesized.

    Availability gate: ``TRAVERSAAL_API_KEY`` env var is non-empty.
    """

    name = "traversaal"
    display_name = "Traversaal ARES"

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        summarizer: Optional[SearchSummarizerProtocol] = None,
        timeout: float = TRAVERSAAL_TIMEOUT,
        proxy: Optional[str] = None,
        **_: Any,
    ) -> None:
        super().__init__(summarizer=summarizer, timeout=timeout, proxy=proxy)
        self._api_key: str = (
            api_key or os.environ.get("TRAVERSAAL_API_KEY", "")
        ).strip()

    # -- SearchProvider interface -----------------------------------------

    def is_available(self) -> bool:
        """True when ``TRAVERSAAL_API_KEY`` is non-empty."""
        return bool(self._api_key)

    async def search(
        self,
        query: str,
        max_results: int = DEFAULT_MAX_RESULTS,
    ) -> str:
        """Search Traversaal ARES and return Markdown-formatted results.

        Note: ``max_results`` is accepted for interface parity but
        Traversaal's API does not support per-call result limits — the
        response always returns the full URL list. The provider renders
        up to ``max_results`` URLs in the output.
        """
        if not self.is_available():
            return (
                "Traversaal search unavailable: TRAVERSAAL_API_KEY is not set."
            )

        import httpx  # noqa: WPS433 — lazy import is intentional

        body = {"query": query}
        headers = {
            "x-api-key": self._api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        client_kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        logger.info("traversaal_search query=%r", query)
        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                resp = await client.post(
                    TRAVERSAAL_ENDPOINT, json=body, headers=headers
                )
        except httpx.HTTPError as exc:
            logger.error("traversaal_http_error query=%r error=%r", query, exc)
            return f"Traversaal search failed: HTTP error: {exc}"

        status = resp.status_code
        if status != 200:
            return _format_traversaal_error(status, resp.text)

        try:
            payload = resp.json()
        except ValueError as exc:
            logger.error("traversaal_bad_json query=%r error=%r", query, exc)
            return f"Traversaal search failed: invalid JSON response: {exc}"

        return _render_traversaal(payload, max_results)


# ---------------------------------------------------------------------------
# Rendering — Markdown output (port-verbatim from PentAGI).
# ---------------------------------------------------------------------------


def _render_traversaal(payload: dict[str, Any], max_results: int) -> str:
    """Render the Traversaal JSON payload as Markdown.

    Output format (preserved verbatim from PentAGI):

    .. code-block:: markdown

       # Answer

       <response_text>

       # Links

       1. <url>
    """
    data = payload.get("data") or {}
    response_text = (data.get("response_text") or "").strip()
    web_urls: list[Any] = data.get("web_url") or []

    parts: list[str] = ["# Answer\n"]
    if response_text:
        parts.append(response_text)
    else:
        parts.append("_(no answer returned)_")

    # ``max_results`` clamps the rendered URL count (Traversaal's API
    # itself doesn't support per-call limits).
    capped = max(1, min(int(max_results), 50))
    if web_urls:
        parts.append("\n# Links\n")
        idx = 0
        for url in web_urls[:capped]:
            url_str = (str(url) if url is not None else "").strip()
            if url_str:
                idx += 1
                parts.append(f"{idx}. {url_str}")

    return "\n".join(parts).strip()


# ---------------------------------------------------------------------------
# HTTP error mapping.
# ---------------------------------------------------------------------------


_TRAVERSAAL_STATUS_MAP: dict[int, str] = {
    400: "invalid request",
    401: "wrong API key",
    403: "forbidden (key lacks permission)",
    404: "endpoint not found",
    405: "wrong HTTP method (POST required)",
    429: "rate limit exceeded",
    500: "Traversaal server error (500)",
    502: "Traversaal server error (502)",
    503: "Traversaal server error (503)",
    504: "Traversaal server error (504)",
}


def _format_traversaal_error(status: int, body: str) -> str:
    """Format a Traversaal HTTP error response as a user-facing string."""
    reason = _TRAVERSAAL_STATUS_MAP.get(status, f"HTTP {status}")
    snippet = (body or "").strip()
    if snippet and len(snippet) > 500:
        snippet = snippet[:500] + " …"
    suffix = f"\nResponse: {snippet}" if snippet else ""
    return f"Traversaal search failed ({reason}).{suffix}"

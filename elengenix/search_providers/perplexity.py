"""elengenix/search_providers/perplexity.py — Perplexity (Sonar) search provider.

Ports PentAGI's ``backend/pkg/tools/perplexity.go`` (427 lines) to an
async Python client. Perplexity's Sonar model is OpenAI-compatible — the
provider speaks the chat-completions schema with a handful of
search-specific extra fields (``search_context_size``,
``search_domain_filter``, ``return_images``, ``return_related_questions``,
``search_recency_filter``, ``top_k``).

Endpoint:
    ``POST https://api.perplexity.ai/chat/completions``

Auth:
    ``Authorization: Bearer <api_key>`` header.

Request body (port-verbatim from PentAGI):
    .. code-block:: json

       {
         "messages": [{"role": "user", "content": "<query>"}],
         "model": "sonar", "max_tokens": 4000,
         "temperature": 0.5, "top_p": 0.9,
         "search_context_size": "low|medium|high",
         "search_domain_filter": [], "return_images": false,
         "return_related_questions": false,
         "search_recency_filter": "", "top_k": 0, "stream": false
       }

Response:
    .. code-block:: json

       {
         "id": "...", "model": "sonar", "created": 0, "object": "...",
         "choices": [{"index": 0, "finish_reason": "stop",
                       "message": {"role": "assistant", "content": "..."}}],
         "usage": {"prompt_tokens": 0, "completion_tokens": 0,
                   "total_tokens": 0},
         "citations": ["url1", "url2", ...]
       }

Output format (port-verbatim):
    .. code-block:: markdown

       # Answer

       <content>

       # Citations

       1. <url>
       2. <url>

Summarization: if the rendered output exceeds 3000 chars and a summarizer
is configured, the output is LLM-summarised; otherwise it is returned
as-is (truncation handled by :func:`summarize_if_needed`).

Timeout: 60 seconds (preserved verbatim from PentAGI).
Availability: ``PERPLEXITY_API_KEY`` env var is non-empty.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Literal, Optional

from elengenix.search_providers.base import (
    DEFAULT_MAX_RESULTS,
    SUMMARIZE_THRESHOLD,
    SearchProvider,
    SearchSummarizerProtocol,
    summarize_if_needed,
)

logger = logging.getLogger("elengenix.search_providers.perplexity")

# ---------------------------------------------------------------------------
# Constants — ported verbatim from PentAGI's perplexity.go.
# ---------------------------------------------------------------------------

PERPLEXITY_ENDPOINT: str = "https://api.perplexity.ai/chat/completions"
PERPLEXITY_TIMEOUT: float = 60.0
PERPLEXITY_DEFAULT_MODEL: str = "sonar"
PERPLEXITY_MAX_TOKENS: int = 4000
PERPLEXITY_TEMPERATURE: float = 0.5
PERPLEXITY_TOP_P: float = 0.9

#: Allowed values for ``search_context_size`` — mirrors PentAGI's enum.
ContextSize = Literal["low", "medium", "high"]


# ---------------------------------------------------------------------------
# Perplexity provider.
# ---------------------------------------------------------------------------


class PerplexitySearchProvider(SearchProvider):
    """Perplexity (Sonar) search provider.

    OpenAI-compatible chat-completions endpoint with Perplexity-specific
    search fields. The ``max_results`` parameter is forwarded to
    Perplexity as ``top_k`` when non-zero (though Perplexity ignores it
    for non-pro models — kept for API parity).

    Availability gate: ``PERPLEXITY_API_KEY`` env var is non-empty.
    """

    name = "perplexity"
    display_name = "Perplexity (Sonar)"

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        model: str = PERPLEXITY_DEFAULT_MODEL,
        search_context_size: ContextSize = "low",
        search_recency_filter: str = "",
        search_domain_filter: Optional[list[str]] = None,
        summarizer: Optional[SearchSummarizerProtocol] = None,
        timeout: float = PERPLEXITY_TIMEOUT,
        proxy: Optional[str] = None,
        **_: Any,
    ) -> None:
        super().__init__(summarizer=summarizer, timeout=timeout, proxy=proxy)
        self._api_key: str = (
            api_key or os.environ.get("PERPLEXITY_API_KEY", "")
        ).strip()
        self.model: str = model or PERPLEXITY_DEFAULT_MODEL
        self.search_context_size: ContextSize = search_context_size
        self.search_recency_filter: str = search_recency_filter
        self.search_domain_filter: list[str] = list(search_domain_filter or [])

    # -- SearchProvider interface -----------------------------------------

    def is_available(self) -> bool:
        """True when ``PERPLEXITY_API_KEY`` is non-empty."""
        return bool(self._api_key)

    async def search(
        self,
        query: str,
        max_results: int = DEFAULT_MAX_RESULTS,
    ) -> str:
        """Search Perplexity and return Markdown-formatted results."""
        if not self.is_available():
            return "Perplexity search unavailable: PERPLEXITY_API_KEY is not set."

        import httpx  # noqa: WPS433 — lazy import is intentional

        body = {
            "messages": [{"role": "user", "content": query}],
            "model": self.model,
            "max_tokens": PERPLEXITY_MAX_TOKENS,
            "temperature": PERPLEXITY_TEMPERATURE,
            "top_p": PERPLEXITY_TOP_P,
            "search_context_size": self.search_context_size,
            "search_domain_filter": self.search_domain_filter,
            "return_images": False,
            "return_related_questions": False,
            "search_recency_filter": self.search_recency_filter,
            "top_k": 0,  # PentAGI hardcodes 0 (Sonar ignores non-zero)
            "stream": False,
        }
        # Note: max_results is intentionally NOT forwarded to Perplexity's
        # ``top_k`` because the Sonar model ignores it. We accept the arg
        # only for interface parity.

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        client_kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        logger.info(
            "perplexity_search query=%r model=%s ctx=%s",
            query,
            self.model,
            self.search_context_size,
        )
        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                resp = await client.post(
                    PERPLEXITY_ENDPOINT, json=body, headers=headers
                )
        except httpx.HTTPError as exc:
            logger.error("perplexity_http_error query=%r error=%r", query, exc)
            return f"Perplexity search failed: HTTP error: {exc}"

        status = resp.status_code
        if status != 200:
            return _format_perplexity_error(status, resp.text)

        try:
            payload = resp.json()
        except ValueError as exc:
            logger.error("perplexity_bad_json query=%r error=%r", query, exc)
            return f"Perplexity search failed: invalid JSON response: {exc}"

        rendered = self._render(payload)
        return await summarize_if_needed(
            query=query,
            raw_output=rendered,
            summarizer=self.summarizer,
            threshold=SUMMARIZE_THRESHOLD,
        )

    # -- Rendering helper -------------------------------------------------

    def _render(self, payload: dict[str, Any]) -> str:
        """Render the Perplexity JSON payload as Markdown.

        Output format (verbatim from PentAGI):

        .. code-block:: markdown

           # Answer

           <content>

           # Citations

           1. <url>
        """
        choices = payload.get("choices") or []
        content = ""
        if choices and isinstance(choices, list):
            msg = (choices[0] or {}).get("message") or {}
            content = (msg.get("content") or "").strip()

        citations: list[str] = payload.get("citations") or []

        parts: list[str] = ["# Answer\n"]
        if content:
            parts.append(content)
        else:
            parts.append("_(no content returned)_")

        if citations:
            parts.append("\n# Citations\n")
            for idx, url in enumerate(citations, start=1):
                url_str = (url or "").strip()
                if url_str:
                    parts.append(f"{idx}. {url_str}")

        return "\n".join(parts).strip()


# ---------------------------------------------------------------------------
# HTTP error mapping — preserved verbatim from PentAGI.
# ---------------------------------------------------------------------------

_PERPLEXITY_STATUS_MAP: dict[int, str] = {
    400: "invalid request",
    401: "wrong API key",
    403: "forbidden (key lacks permission)",
    404: "endpoint not found",
    405: "wrong HTTP method (POST required)",
    429: "rate limit exceeded",
    500: "Perplexity server error (500)",
    502: "Perplexity server error (502)",
    503: "Perplexity server error (503)",
    504: "Perplexity server error (504)",
}


def _format_perplexity_error(status: int, body: str) -> str:
    """Format a Perplexity HTTP error response as a user-facing string."""
    reason = _PERPLEXITY_STATUS_MAP.get(status, f"HTTP {status}")
    snippet = (body or "").strip()
    if snippet and len(snippet) > 500:
        snippet = snippet[:500] + " …"
    suffix = f"\nResponse: {snippet}" if snippet else ""
    return f"Perplexity search failed ({reason}).{suffix}"

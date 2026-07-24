"""elengenix/search_providers/google.py — Google Custom Search provider.

Ports PentAGI's ``backend/pkg/tools/google.go`` (180 lines) to an async
Python client. Uses Google's official ``google-api-python-client`` SDK
to call the Custom Search JSON API (``cse.list``).

SDK:
    ``google-api-python-client`` (``from googleapiclient.discovery import build``).

Auth:
    API key (``developerKey=...``) + Custom Search Engine ID (CX key).
    NOT OAuth.

Call chain (port-verbatim from PentAGI):
    .. code-block:: python

       svc = build("customsearch", "v1", developerKey=api_key)
       cse = svc.cse()
       req = cse.list(cx=cx_key, q=query, lr=lr_key, num=num_results)
       resp = req.execute()

Response (Google Custom Search):
    .. code-block:: json

       {
         "search": {"...": "..."},
         "items": [
           {"title": "...", "link": "...", "snippet": "...", "...": "..."}
         ]
       }

Output format (port-verbatim from PentAGI):
    .. code-block:: markdown

       # 1. <title>

       ## URL
       <link>

       ## Snippet

       <snippet>

       # 2. <title>
       ...

Max results: 10 (Google's hard cap for ``num=``).
Availability: ``GOOGLE_API_KEY != ""`` AND ``GOOGLE_CX_KEY != ""``.

Implementation note: the ``googleapiclient`` SDK is **synchronous**.
To stay async-friendly, the blocking ``req.execute()`` call is wrapped
in :func:`asyncio.to_thread` so it never blocks the event loop.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Optional

from elengenix.search_providers.base import (
    DEFAULT_MAX_RESULTS,
    SearchProvider,
    SearchSummarizerProtocol,
)

logger = logging.getLogger("elengenix.search_providers.google")

# ---------------------------------------------------------------------------
# Constants — ported verbatim from PentAGI's google.go.
# ---------------------------------------------------------------------------

GOOGLE_CSE_API_VERSION: str = "v1"
GOOGLE_MAX_RESULTS: int = 10  # Google's hard cap for ``num=``.
GOOGLE_TIMEOUT: float = 30.0


# ---------------------------------------------------------------------------
# Google Custom Search provider.
# ---------------------------------------------------------------------------


class GoogleSearchProvider(SearchProvider):
    """Google Custom Search provider.

    Uses Google's official ``google-api-python-client`` SDK with API-key
    authentication (NOT OAuth). The blocking ``req.execute()`` call is
    wrapped in :func:`asyncio.to_thread` so the event loop is never
    blocked.

    Availability gate: ``GOOGLE_API_KEY`` AND ``GOOGLE_CX_KEY`` are both
    non-empty.
    """

    name = "google"
    display_name = "Google Custom Search"

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        cx_key: Optional[str] = None,
        lr_key: str = "",
        summarizer: Optional[SearchSummarizerProtocol] = None,
        timeout: float = GOOGLE_TIMEOUT,
        proxy: Optional[str] = None,
        **_: Any,
    ) -> None:
        super().__init__(summarizer=summarizer, timeout=timeout, proxy=proxy)
        self._api_key: str = (
            api_key or os.environ.get("GOOGLE_API_KEY", "")
        ).strip()
        self._cx_key: str = (
            cx_key or os.environ.get("GOOGLE_CX_KEY", "")
        ).strip()
        # ``lr`` is the language-restrict parameter, e.g. ``lang_en``.
        # PentAGI passes it through verbatim — empty string = no filter.
        self.lr_key: str = (lr_key or "").strip()

    # -- SearchProvider interface -----------------------------------------

    def is_available(self) -> bool:
        """True when both ``GOOGLE_API_KEY`` and ``GOOGLE_CX_KEY`` are set."""
        return bool(self._api_key) and bool(self._cx_key)

    async def search(
        self,
        query: str,
        max_results: int = DEFAULT_MAX_RESULTS,
    ) -> str:
        """Search Google Custom Search and return Markdown results."""
        if not self.is_available():
            missing = []
            if not self._api_key:
                missing.append("GOOGLE_API_KEY")
            if not self._cx_key:
                missing.append("GOOGLE_CX_KEY")
            return (
                f"Google search unavailable: missing env var(s): "
                f"{', '.join(missing)}."
            )

        capped = max(1, min(int(max_results), GOOGLE_MAX_RESULTS))

        logger.info(
            "google_search query=%r cx=%s lr=%s num=%d",
            query,
            self._cx_key[:8] + "…",
            self.lr_key or "(none)",
            capped,
        )

        try:
            payload = await asyncio.to_thread(
                self._execute_sync, query, capped
            )
        except Exception as exc:  # noqa: BLE001 — surface any SDK error
            logger.error("google_search_failed query=%r error=%r", query, exc)
            return f"Google search failed: {exc}"

        items = (payload or {}).get("items") or []
        if not items:
            return f"# Google Custom Search: {query}\n\n_No results returned._"

        return _render_google_results(query, items[:capped])

    # -- Sync SDK call (run in thread) ------------------------------------

    def _execute_sync(self, query: str, num: int) -> dict[str, Any]:
        """Execute the synchronous Google API call.

        Runs inside :func:`asyncio.to_thread` from
        :meth:`search` so the event loop is never blocked. The
        ``googleapiclient`` SDK is imported lazily here so this module
        imports cleanly in environments where the SDK is not installed
        (matters for AST-level test discovery).
        """
        # Lazy import — the google-api-python-client package is optional.
        from googleapiclient.discovery import build  # noqa: WPS433

        svc = build(
            "customsearch",
            GOOGLE_CSE_API_VERSION,
            developerKey=self._api_key,
            # ``cache_discovery=False`` avoids a noisy warning when
            # ``google-api-core`` isn't installed.
            cache_discovery=False,
            static_discovery=False,
        )
        cse = svc.cse()
        # Build the list() request — call chain mirrors PentAGI verbatim.
        kwargs: dict[str, Any] = {
            "cx": self._cx_key,
            "q": query,
            "num": num,
        }
        if self.lr_key:
            kwargs["lr"] = self.lr_key
        req = cse.list(**kwargs)
        return req.execute()


# ---------------------------------------------------------------------------
# Rendering — Markdown output (port-verbatim from PentAGI).
# ---------------------------------------------------------------------------


def _render_google_results(query: str, items: list[dict[str, Any]]) -> str:
    """Render Google Custom Search items as Markdown.

    Output format (preserved verbatim from PentAGI):

    .. code-block:: markdown

       # 1. <title>

       ## URL
       <link>

       ## Snippet

       <snippet>
    """
    lines: list[str] = [f"# Google Custom Search: {query}\n"]
    for idx, item in enumerate(items, start=1):
        title = (item.get("title") or "(untitled)").strip()
        link = (item.get("link") or "").strip()
        snippet = (item.get("snippet") or "").strip()
        lines.append(f"# {idx}. {title}\n")
        lines.append("## URL")
        lines.append(link or "_(none)_")
        lines.append("\n## Snippet\n")
        lines.append(snippet or "_(no snippet)_")
        lines.append("")
    return "\n".join(lines).strip()

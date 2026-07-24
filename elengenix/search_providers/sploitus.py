"""elengenix/search_providers/sploitus.py — Sploitus exploit-search provider.

Ports PentAGI's ``backend/pkg/tools/sploitus.go`` (388 lines) to an
async Python client. Sploitus is an exploit/PoC search engine that
requires **no API key** but is aggressively rate-limited and
Cloudflare-protected.

Endpoint:
    ``POST https://sploitus.com/search``

Request body (port-verbatim from PentAGI):
    .. code-block:: json

       {"query": "...", "type": "exploits|tools", "sort": "default",
        "title": false, "offset": 0}

Anti-Cloudflare headers (preserved verbatim — spoofed Chrome 145):
    * ``User-Agent``: Chrome 145 macOS.
    * ``Origin: https://sploitus.com``
    * ``Referer: https://sploitus.com/?query=...`` (URL-encoded)
    * ``sec-ch-ua``, ``sec-ch-ua-platform: "macOS"``
    * ``sec-fetch-dest/mode/site``
    * ``DNT: 1``

Response:
    .. code-block:: json

       {
         "exploits": [
           {"id": "...", "title": "...", "type": "...", "href": "...",
            "download": "...?", "score": 7.5?, "published": "...?",
            "source": "...?", "language": "...?"}
         ],
         "exploits_total": N
       }

Field semantics:
    * ``score`` — CVSS score (exploits only).
    * ``source`` — source code / PoC (exploits only; can be very large).
    * ``download`` — direct download URL (tools only).

Rate-limit handling (preserved verbatim):
    HTTP 499 OR 422 -> "rate limit exceeded, try again later"
    (Sploitus uses non-standard codes — PentAGI's quirk is preserved).

Hard size limits (preserved verbatim from PentAGI's sploitus.go):
    * ``maxSourceSize = 50 KB`` per source field
    * ``maxTotalResultSize = 80 KB`` total output
    * ``truncationMsgBuffer = 500 bytes`` reserved for truncation notice

Default limit: 10. Max limit: 25. Timeout: 30s.
Availability: ``SPLOITUS_ENABLED=true`` (default true).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Literal, Optional
from urllib.parse import quote_plus

from elengenix.search_providers.base import (
    DEFAULT_MAX_RESULTS,
    SearchProvider,
    SearchSummarizerProtocol,
)

logger = logging.getLogger("elengenix.search_providers.sploitus")

# ---------------------------------------------------------------------------
# Constants — ported verbatim from PentAGI's sploitus.go.
# ---------------------------------------------------------------------------

SPLOITUS_ENDPOINT: str = "https://sploitus.com/search"
SPLOITUS_TIMEOUT: float = 30.0
SPLOITUS_DEFAULT_LIMIT: int = 10
SPLOITUS_MAX_LIMIT: int = 25

#: Per-source field character cap (50 KB).
SPLOITUS_MAX_SOURCE_SIZE: int = 50 * 1024

#: Total-output character cap (80 KB).
SPLOITUS_MAX_TOTAL_SIZE: int = 80 * 1024

#: Truncation-notice buffer (500 bytes).
SPLOITUS_TRUNCATION_BUFFER: int = 500

#: Spoofed Chrome 145 user-agent on macOS.
SPLOITUS_USER_AGENT: str = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)

#: ``sec-ch-ua`` header value for Chrome 145.
SPLOITUS_SEC_CH_UA: str = (
    '"Chromium";v="145", "Not?A_Brand";v="24", '
    '"Google Chrome";v="145"'
)

SploitusType = Literal["exploits", "tools"]
SploitusSort = Literal["default", "published", "popularity", "score"]


# ---------------------------------------------------------------------------
# Sploitus provider.
# ---------------------------------------------------------------------------


class SploitusSearchProvider(SearchProvider):
    """Sploitus exploit-search provider (NO API key, anti-Cloudflare).

    Implements the hard size limits (50 KB per source, 80 KB total,
    500-byte truncation buffer) and the non-standard HTTP 499/422
    rate-limit mapping preserved verbatim from PentAGI's
    ``sploitus.go``.

    Availability gate: ``SPLOITUS_ENABLED`` env var is ``true`` or
    ``1`` (default: enabled).
    """

    name = "sploitus"
    display_name = "Sploitus"

    def __init__(
        self,
        *,
        enabled: Optional[bool] = None,
        search_type: SploitusType = "exploits",
        sort: SploitusSort = "default",
        title_only: bool = False,
        offset: int = 0,
        summarizer: Optional[SearchSummarizerProtocol] = None,
        timeout: float = SPLOITUS_TIMEOUT,
        proxy: Optional[str] = None,
        **_: Any,
    ) -> None:
        super().__init__(summarizer=summarizer, timeout=timeout, proxy=proxy)
        if enabled is None:
            env_val = os.environ.get("SPLOITUS_ENABLED", "true").strip().lower()
            self._enabled = env_val in ("1", "true", "yes", "on")
        else:
            self._enabled = bool(enabled)
        # Clamp ``search_type`` to the allowed literal set.
        self.search_type: SploitusType = (
            search_type if search_type in ("exploits", "tools") else "exploits"
        )
        self.sort: SploitusSort = (
            sort if sort in ("default", "published", "popularity", "score")
            else "default"
        )
        self.title_only: bool = bool(title_only)
        self.offset: int = max(0, int(offset))

    # -- SearchProvider interface -----------------------------------------

    def is_available(self) -> bool:
        """True when ``SPLOITUS_ENABLED`` is truthy (default true)."""
        return self._enabled

    async def search(
        self,
        query: str,
        max_results: int = DEFAULT_MAX_RESULTS,
    ) -> str:
        """Search Sploitus and return Markdown-formatted exploit results."""
        if not self.is_available():
            return "Sploitus search unavailable: SPLOITUS_ENABLED is false."

        import httpx  # noqa: WPS433 — lazy import is intentional

        capped = max(1, min(int(max_results), SPLOITUS_MAX_LIMIT))

        body = {
            "query": query,
            "type": self.search_type,
            "sort": self.sort,
            "title": self.title_only,
            "offset": self.offset,
        }

        # Anti-Cloudflare headers — preserved verbatim from PentAGI.
        encoded_q = quote_plus(query)
        headers = {
            "User-Agent": SPLOITUS_USER_AGENT,
            "Origin": "https://sploitus.com",
            "Referer": f"https://sploitus.com/?query={encoded_q}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": SPLOITUS_SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "DNT": "1",
        }

        client_kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        logger.info(
            "sploitus_search query=%r type=%s sort=%s max=%d",
            query,
            self.search_type,
            self.sort,
            capped,
        )
        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                resp = await client.post(
                    SPLOITUS_ENDPOINT, json=body, headers=headers
                )
        except httpx.HTTPError as exc:
            logger.error("sploitus_http_error query=%r error=%r", query, exc)
            return f"Sploitus search failed: HTTP error: {exc}"

        status = resp.status_code
        # Non-standard rate-limit mapping (Sploitus uses 499 + 422).
        if status in (499, 422):
            return (
                "Sploitus search failed: rate limit exceeded, try again later."
            )
        if status != 200:
            return _format_sploitus_error(status, resp.text)

        try:
            payload = resp.json()
        except ValueError as exc:
            logger.error("sploitus_bad_json query=%r error=%r", query, exc)
            return f"Sploitus search failed: invalid JSON response: {exc}"

        return _render_sploitus_results(query, payload, capped)


# ---------------------------------------------------------------------------
# Rendering — Markdown output with hard size limits (50KB/80KB/500B).
# ---------------------------------------------------------------------------


def _render_sploitus_results(
    query: str, payload: dict[str, Any], max_results: int
) -> str:
    """Render Sploitus exploit results as Markdown.

    Enforces the three size limits (ported verbatim from PentAGI):

    * ``SPLOITUS_MAX_SOURCE_SIZE`` (50 KB) — each exploit's ``source``
      field is truncated to this length.
    * ``SPLOITUS_MAX_TOTAL_SIZE`` (80 KB) — total output is capped; once
      reached, the loop breaks with a truncation notice.
    * ``SPLOITUS_TRUNCATION_BUFFER`` (500 bytes) — buffer reserved for
      the truncation notice so the total never exceeds 80 KB.
    """
    exploits: list[dict[str, Any]] = payload.get("exploits") or []
    total_count: int = int(payload.get("exploits_total") or 0)

    # The output budget is reduced by the truncation buffer so the
    # truncation notice itself never pushes us past the cap.
    output_budget = SPLOITUS_MAX_TOTAL_SIZE - SPLOITUS_TRUNCATION_BUFFER

    lines: list[str] = [
        f"# Sploitus Search: {query}\n",
        f"**Type:** exploits  **Total found:** {total_count}\n",
    ]
    current_size = sum(len(s) for s in lines)
    rendered_count = 0
    truncated = False

    for idx, item in enumerate(exploits, start=1):
        if rendered_count >= max_results:
            break

        rendered = _render_one_sploitus(idx, item)
        # Enforce the total-output budget.
        if current_size + len(rendered) > output_budget:
            truncated = True
            break

        lines.append(rendered)
        current_size += len(rendered)
        rendered_count += 1

    if truncated:
        notice = (
            f"\n⚠️ Note: Results truncated after {rendered_count} items "
            f"due to {SPLOITUS_MAX_TOTAL_SIZE} bytes size limit."
        )
        lines.append(notice)

    return "\n".join(lines).strip()


def _render_one_sploitus(idx: int, item: dict[str, Any]) -> str:
    """Render a single Sploitus exploit entry as Markdown.

    The ``source`` field (exploit source code / PoC) is hard-capped at
    ``SPLOITUS_MAX_SOURCE_SIZE`` bytes (50 KB) — ported verbatim.
    """
    title = (item.get("title") or "(untitled)").strip()
    href = (item.get("href") or "").strip()
    etype = (item.get("type") or "").strip()
    download = (item.get("download") or "").strip()
    score = item.get("score")
    published = (item.get("published") or "").strip()
    source = (item.get("source") or "").strip()
    language = (item.get("language") or "").strip()

    parts: list[str] = [f"## {idx}. {title}"]
    meta: list[str] = []
    if etype:
        meta.append(f"**Type:** {etype}")
    if isinstance(score, (int, float)) and score:
        meta.append(f"**CVSS:** {float(score):.1f}")
    if published:
        meta.append(f"**Published:** {published}")
    if language:
        meta.append(f"**Language:** {language}")
    if meta:
        parts.append(" | ".join(meta))

    if href:
        parts.append(f"**URL:** {href}")
    if download:
        parts.append(f"**Download:** {download}")

    # Enforce per-source 50 KB cap.
    if source:
        if len(source) > SPLOITUS_MAX_SOURCE_SIZE:
            source = (
                source[:SPLOITUS_MAX_SOURCE_SIZE]
                + f"\n\n⚠️ Source truncated at {SPLOITUS_MAX_SOURCE_SIZE} bytes."
            )
        parts.append(f"```\n{source}\n```")

    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# HTTP error mapping.
# ---------------------------------------------------------------------------


_SPLOITUS_STATUS_MAP: dict[int, str] = {
    400: "invalid request",
    401: "auth required (unexpected for Sploitus)",
    403: "forbidden (Cloudflare block?)",
    404: "endpoint not found",
    405: "wrong HTTP method (POST required)",
    429: "rate limit exceeded",
    500: "Sploitus server error (500)",
    502: "Sploitus server error (502)",
    503: "Sploitus server error (503)",
    504: "Sploitus server error (504)",
}


def _format_sploitus_error(status: int, body: str) -> str:
    """Format a Sploitus HTTP error response as a user-facing string."""
    reason = _SPLOITUS_STATUS_MAP.get(status, f"HTTP {status}")
    snippet = (body or "").strip()
    if snippet and len(snippet) > 500:
        snippet = snippet[:500] + " …"
    suffix = f"\nResponse: {snippet}" if snippet else ""
    return f"Sploitus search failed ({reason}).{suffix}"

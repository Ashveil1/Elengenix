"""elengenix/search_providers/duckduckgo.py — DuckDuckGo HTML search provider.

Ports PentAGI's ``backend/pkg/tools/duckduckgo.go`` (565 lines) to an
async Python client. DuckDuckGo is **free** and requires no API key —
the provider scrapes the ``html.duckduckgo.com/html/`` HTML endpoint
with a spoofed Chrome 120 user-agent.

Endpoint:
    ``POST https://html.duckduckgo.com/html/`` (HTML, NOT JSON)

Content-Type: ``application/x-www-form-urlencoded``

Form data (port-verbatim from PentAGI):
    .. code-block:: text

       q=<query> b= df=<time_range> kl=<region> kp=<safesearch>

Spoofed Chrome 120 headers:
    ``User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36``
    ``Accept: text/html,application/xhtml+xml,...``
    ``Accept-Language: en-US,en;q=0.9``

Retries: 3 attempts with 1-second delay between (preserved verbatim).

Region constants: ``us-en, uk-en, de-de, fr-fr, jp-jp, cn-zh, ru-ru``.

SafeSearch:
    * strict   -> ``kp=1``
    * moderate -> ``kp=0``
    * off      -> ``kp=-1``

TimeRange: ``d`` (day), ``w`` (week), ``m`` (month), ``y`` (year).

Two-tier parsing (preserved verbatim):
    1. **Primary (DOM walker):** uses ``lxml.html`` (preferred) — walks
       ``div.result.results_links`` containers, extracting
       ``a.result__a`` (URL+title) and ``a.result__snippet``
       (description). Falls back to ``selectolax`` when ``lxml`` is not
       available.
    2. **Fallback (regex):** mirrors PentAGI's
       ``(?s)<div class="result results_links[^"]*">.*?<div class="clear"></div>\\s*</div>\\s*</div>``
       pattern for environments where no HTML parser is installed.

HTML entity decoding: manual ``&amp; &lt; &gt; &quot; &#39; &#x27;
&nbsp; &apos;`` plus hex/decimal entity regex — ported verbatim.

Max results: 10. Timeout: 30s.
Availability: ``DUCKDUCKGO_ENABLED=true`` (default true).
"""

from __future__ import annotations

import asyncio
import html as html_mod
import logging
import os
import re
from typing import Any, Literal, Optional
from urllib.parse import quote_plus

from elengenix.search_providers.base import (
    DEFAULT_MAX_RESULTS,
    SearchProvider,
    SearchSummarizerProtocol,
)

logger = logging.getLogger("elengenix.search_providers.duckduckgo")

# ---------------------------------------------------------------------------
# Constants — ported verbatim from PentAGI's duckduckgo.go.
# ---------------------------------------------------------------------------

DUCKDUCKGO_ENDPOINT: str = "https://html.duckduckgo.com/html/"
DUCKDUCKGO_TIMEOUT: float = 30.0
DUCKDUCKGO_MAX_RESULTS: int = 10
DUCKDUCKGO_RETRIES: int = 3
DUCKDUCKGO_RETRY_DELAY: float = 1.0

#: Spoofed Chrome 120 user-agent — preserved verbatim.
DUCKDUCKGO_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

#: Allowed region constants (PentAGI's region list, ported verbatim).
Region = Literal["us-en", "uk-en", "de-de", "fr-fr", "jp-jp", "cn-zh", "ru-ru"]
_ALLOWED_REGIONS: frozenset[str] = frozenset(
    {"us-en", "uk-en", "de-de", "fr-fr", "jp-jp", "cn-zh", "ru-ru"}
)

#: Allowed safe-search values.
SafeSearch = Literal["strict", "moderate", "off"]
_SAFESEARCH_KV: dict[str, int] = {
    "strict": 1,
    "moderate": 0,
    "off": -1,
}

#: Allowed time-range values.
TimeRange = Literal["d", "w", "m", "y", ""]
_ALLOWED_TIMERANGES: frozenset[str] = frozenset({"d", "w", "m", "y", ""})


# ---------------------------------------------------------------------------
# DuckDuckGo provider.
# ---------------------------------------------------------------------------


class DuckDuckGoSearchProvider(SearchProvider):
    """DuckDuckGo HTML search provider (FREE, no API key).

    Scrapes ``html.duckduckgo.com/html/`` with a spoofed Chrome 120
    user-agent. Implements the two-tier parser (DOM walker + regex
    fallback) ported from PentAGI's ``duckduckgo.go``.

    Availability gate: ``DUCKDUCKGO_ENABLED`` env var is ``true`` or
    ``1`` (default: enabled, matching PentAGI's
    ``cfg.DuckDuckGoEnabled`` zero-value semantics).
    """

    name = "duckduckgo"
    display_name = "DuckDuckGo"

    def __init__(
        self,
        *,
        enabled: Optional[bool] = None,
        region: str = "us-en",
        safe_search: str = "moderate",
        time_range: str = "",
        summarizer: Optional[SearchSummarizerProtocol] = None,
        timeout: float = DUCKDUCKGO_TIMEOUT,
        proxy: Optional[str] = None,
        **_: Any,
    ) -> None:
        super().__init__(summarizer=summarizer, timeout=timeout, proxy=proxy)
        # Resolve enabled flag: explicit arg -> env var -> default (true).
        if enabled is None:
            env_val = os.environ.get("DUCKDUCKGO_ENABLED", "true").strip().lower()
            self._enabled = env_val in ("1", "true", "yes", "on")
        else:
            self._enabled = bool(enabled)

        self.region: str = region if region in _ALLOWED_REGIONS else "us-en"
        self.safe_search: str = (
            safe_search if safe_search in _SAFESEARCH_KV else "moderate"
        )
        self.time_range: str = time_range if time_range in _ALLOWED_TIMERANGES else ""

    # -- SearchProvider interface -----------------------------------------

    def is_available(self) -> bool:
        """True when ``DUCKDUCKGO_ENABLED`` is truthy (default true)."""
        return self._enabled

    async def search(
        self,
        query: str,
        max_results: int = DEFAULT_MAX_RESULTS,
    ) -> str:
        """Search DuckDuckGo and return Markdown-formatted results."""
        if not self.is_available():
            return "DuckDuckGo search unavailable: DUCKDUCKGO_ENABLED is false."

        import httpx  # noqa: WPS433 — lazy import is intentional

        capped = max(1, min(int(max_results), DUCKDUCKGO_MAX_RESULTS))

        # Build form data (order matters — PentAGI uses ``b=`` as a
        # no-op separator between q and df).
        form_data = {
            "q": query,
            "b": "",
            "df": self.time_range,
            "kl": self.region,
            "kp": str(_SAFESEARCH_KV[self.safe_search]),
        }

        headers = {
            "User-Agent": DUCKDUCKGO_USER_AGENT,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://html.duckduckgo.com/html/",
            "Origin": "https://html.duckduckgo.com",
        }

        client_kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        logger.info(
            "duckduckgo_search query=%r region=%s safe=%s time=%s max=%d",
            query,
            self.region,
            self.safe_search,
            self.time_range or "(none)",
            capped,
        )

        last_error: Optional[str] = None
        html_text: Optional[str] = None
        for attempt in range(1, DUCKDUCKGO_RETRIES + 1):
            try:
                async with httpx.AsyncClient(**client_kwargs) as client:
                    resp = await client.post(
                        DUCKDUCKGO_ENDPOINT, data=form_data, headers=headers
                    )
                if resp.status_code == 200:
                    html_text = resp.text
                    break
                last_error = (
                    f"HTTP {resp.status_code}: {resp.text[:200]!r}"
                )
                logger.warning(
                    "duckduckgo_attempt_failed attempt=%d status=%d",
                    attempt,
                    resp.status_code,
                )
            except httpx.HTTPError as exc:
                last_error = f"HTTP error: {exc!r}"
                logger.warning(
                    "duckduckgo_attempt_error attempt=%d error=%r",
                    attempt,
                    exc,
                )
            if attempt < DUCKDUCKGO_RETRIES:
                await asyncio.sleep(DUCKDUCKGO_RETRY_DELAY)

        if html_text is None:
            return (
                f"DuckDuckGo search failed after {DUCKDUCKGO_RETRIES} "
                f"attempts: {last_error or 'unknown error'}"
            )

        results = _parse_ddg_html(html_text, capped)
        if not results:
            return f"# DuckDuckGo Search: {query}\n\n_No results found._"

        return _render_ddg_results(query, results)


# ---------------------------------------------------------------------------
# HTML parsing — two-tier (DOM walker + regex fallback).
# ---------------------------------------------------------------------------


def _parse_ddg_html(html_text: str, max_results: int) -> list[dict[str, str]]:
    """Parse DuckDuckGo HTML into a list of ``{title, url, snippet}``.

    Two-tier strategy (mirrors PentAGI's ``duckduckgo.go``):

      1. **Primary (DOM walker):** ``lxml.html`` (preferred, faster).
         Falls back to ``selectolax`` if available. Walks
         ``div.result.results_links`` containers.
      2. **Fallback (regex):** if no HTML parser is importable, use a
         regex that mirrors PentAGI's pattern to extract titles / URLs
         / snippets directly from the raw HTML.

    Args:
        html_text: Raw HTML returned by DuckDuckGo's ``html/`` endpoint.
        max_results: Maximum number of results to return.

    Returns:
        List of ``{"title": str, "url": str, "snippet": str}`` dicts.
    """
    # Try lxml first (preferred — port of PentAGI's golang.org/x/net/html
    # walker).
    try:
        return _parse_ddg_with_lxml(html_text, max_results)
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001 — parser errors are recoverable
        logger.warning(
            "duckduckgo_lxml_parse_failed error=%r -- falling back to "
            "selectolax/regex",
            exc,
        )

    # Fall back to selectolax if available.
    try:
        return _parse_ddg_with_selectolax(html_text, max_results)
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001 — parser errors are recoverable
        logger.warning(
            "duckduckgo_selectolax_parse_failed error=%r -- falling back "
            "to regex",
            exc,
        )

    # Last resort: regex.
    return _parse_ddg_with_regex(html_text, max_results)


def _parse_ddg_with_lxml(html_text: str, max_results: int) -> list[dict[str, str]]:
    """Parse DuckDuckGo HTML with ``lxml.html``.

    Mirrors PentAGI's DOM walker that iterates
    ``div.result.results_links`` containers and extracts:

    * ``a.result__a`` — title + URL
    * ``a.result__snippet`` — description

    Uses only XPath (no ``cssselect``) so we don't pull in the optional
    ``cssselect`` package — ``lxml`` itself ships with full XPath
    support and is sufficient for the selector complexity we need.
    """
    from lxml import html as lxml_html  # noqa: WPS433 — lazy import

    tree = lxml_html.fromstring(html_text)
    results: list[dict[str, str]] = []
    # DuckDuckGo HTML structure: each result is wrapped in
    # ``<div class="result results_links ...">``. We select all such
    # divs via XPath (the ``contains()`` predicates match regardless of
    # class-attribute ordering).
    result_divs = tree.xpath(
        '//div[contains(concat(" ", normalize-space(@class), " "), " result ")'
        ' and contains(concat(" ", normalize-space(@class), " "), " results_links ")]'
    )
    for node in result_divs:
        if len(results) >= max_results:
            break
        title = ""
        url = ""
        snippet = ""
        # ``a.result__a`` holds the title + href.
        anchors = node.xpath('.//a[contains(@class, "result__a")]')
        if anchors:
            a = anchors[0]
            title = _decode_entities(a.text_content() or "").strip()
            url = _decode_entities(a.get("href") or "").strip()
        # ``a.result__snippet`` holds the description.
        snippets = node.xpath('.//a[contains(@class, "result__snippet")]')
        if snippets:
            snippet = _decode_entities(snippets[0].text_content() or "").strip()
        if title or url:
            results.append({"title": title, "url": url, "snippet": snippet})
    return results


def _parse_ddg_with_selectolax(
    html_text: str, max_results: int
) -> list[dict[str, str]]:
    """Parse DuckDuckGo HTML with ``selectolax`` (lxml fallback).

    Used when ``lxml`` itself is unavailable but ``selectolax`` is.
    Mirrors the same selectors as the lxml walker.
    """
    from selectolax.parser import HTMLParser  # noqa: WPS433 — lazy import

    tree = HTMLParser(html_text)
    results: list[dict[str, str]] = []
    for node in tree.css("div.result.results_links"):
        if len(results) >= max_results:
            break
        title = ""
        url = ""
        snippet = ""
        anchor = node.css_first("a.result__a")
        if anchor is not None:
            title = _decode_entities(anchor.text()).strip()
            url = _decode_entities(anchor.attributes.get("href", "") or "").strip()
        snip_node = node.css_first("a.result__snippet")
        if snip_node is not None:
            snippet = _decode_entities(snip_node.text()).strip()
        if title or url:
            results.append({"title": title, "url": url, "snippet": snippet})
    return results


# Regex fallback — mirrors PentAGI's pattern. We intentionally keep this
# conservative: it captures the title, URL, and snippet from each result
# div using named groups.
_RESULT_BLOCK_RE = re.compile(
    r'<div[^>]*class="[^"]*result\s+results_links[^"]*"[^>]*>'
    r'(?P<body>.*?)'
    r'<div\s+class="clear"></div>\s*</div>\s*</div>',
    re.DOTALL | re.IGNORECASE,
)
_TITLE_URL_RE = re.compile(
    r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="(?P<url>[^"]+)"[^>]*>'
    r'(?P<title>.*?)</a>',
    re.DOTALL | re.IGNORECASE,
)
_SNIPPET_RE = re.compile(
    r'<a[^>]*class="[^"]*result__snippet[^"]*"[^>]*>(?P<snippet>.*?)</a>',
    re.DOTALL | re.IGNORECASE,
)
_TAG_RE = re.compile(r"<[^>]+>")


def _parse_ddg_with_regex(html_text: str, max_results: int) -> list[dict[str, str]]:
    """Regex fallback for DuckDuckGo HTML parsing.

    Used when neither ``lxml`` nor ``selectolax`` is importable. Mirrors
    PentAGI's regex pattern as closely as Python's ``re`` module allows.
    """
    results: list[dict[str, str]] = []
    for match in _RESULT_BLOCK_RE.finditer(html_text):
        if len(results) >= max_results:
            break
        body = match.group("body")
        title = ""
        url = ""
        snippet = ""
        tm = _TITLE_URL_RE.search(body)
        if tm:
            url = _decode_entities(tm.group("url")).strip()
            title = _decode_entities(_strip_tags(tm.group("title"))).strip()
        sm = _SNIPPET_RE.search(body)
        if sm:
            snippet = _decode_entities(_strip_tags(sm.group("snippet"))).strip()
        if title or url:
            results.append({"title": title, "url": url, "snippet": snippet})
    return results


# ---------------------------------------------------------------------------
# HTML entity decoding — manual table + numeric entity regex, ported
# verbatim from PentAGI's duckduckgo.go.
# ---------------------------------------------------------------------------

_NAMED_ENTITIES: dict[str, str] = {
    "amp": "&",
    "lt": "<",
    "gt": ">",
    "quot": '"',
    "#39": "'",
    "#x27": "'",
    "nbsp": " ",
    "apos": "'",
}

_NAMED_ENTITY_RE = re.compile(r"&(?:#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);")
_HEX_ENTITY_RE = re.compile(r"^#x([0-9a-fA-F]+)$")
_DEC_ENTITY_RE = re.compile(r"^#([0-9]+)$")


def _decode_entities(text: str) -> str:
    """Decode HTML entities using stdlib ``html.unescape``.

    PentAGI implements its own entity decoder (a manual table + numeric
    entity regex). Python's stdlib ``html.unescape`` already handles
    all named entities (including the eight PentAGI special-cases:
    ``&amp; &lt; &gt; &quot; &#39; &#x27; &nbsp; &apos;``) plus the full
    HTML5 entity set, so we delegate to it for both correctness and
    conciseness.

    A tiny manual fast-path is kept for the 8 entities PentAGI
    special-cases — these are by far the most common in DuckDuckGo
    snippets and avoiding the function call improves throughput on
    large result sets.
    """
    if not text or "&" not in text:
        return text

    def _replace(match: re.Match[str]) -> str:
        ent = match.group(0)[1:-1]  # strip leading & and trailing ;
        if ent in _NAMED_ENTITIES:
            return _NAMED_ENTITIES[ent]
        hex_m = _HEX_ENTITY_RE.match(ent)
        if hex_m:
            try:
                return chr(int(hex_m.group(1), 16))
            except (ValueError, OverflowError):
                return match.group(0)
        dec_m = _DEC_ENTITY_RE.match(ent)
        if dec_m:
            try:
                return chr(int(dec_m.group(1)))
            except (ValueError, OverflowError):
                return match.group(0)
        # Fallback to stdlib for the long tail of HTML5 named entities.
        return html_mod.unescape(match.group(0))

    return _NAMED_ENTITY_RE.sub(_replace, text)


def _strip_tags(text: str) -> str:
    """Remove all HTML tags from ``text`` (regex-based, mirrors PentAGI)."""
    return _TAG_RE.sub("", text)


# ---------------------------------------------------------------------------
# Rendering — Markdown output.
# ---------------------------------------------------------------------------


def _render_ddg_results(query: str, results: list[dict[str, str]]) -> str:
    """Render DuckDuckGo results as Markdown.

    Output format (mirrors PentAGI):

    .. code-block:: markdown

       # DuckDuckGo Search: <query>

       ## Results (N)

       ### 1. <title>

       **URL:** <url>

       <snippet>
    """
    lines: list[str] = [f"# DuckDuckGo Search: {query}\n"]
    lines.append(f"## Results ({len(results)})\n")
    for idx, r in enumerate(results, start=1):
        title = r.get("title") or "(untitled)"
        url = r.get("url") or ""
        snippet = r.get("snippet") or ""
        lines.append(f"### {idx}. {title}\n")
        if url:
            lines.append(f"**URL:** {url}\n")
        if snippet:
            lines.append(f"{snippet}\n")
    return "\n".join(lines).strip()

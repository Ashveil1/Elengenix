"""
tools/research_tool.py — OSINT Web Research Tool
- DuckDuckGo search as primary free backend (real snippets, no API key)
- Tavily API as preferred backend when TAVILY_API_KEY is set
- trafilatura for clean text extraction from URLs
- Respects robots.txt intent (no aggressive crawling)
- Returns structured result dicts
"""

import logging
import os
import random
import time
from typing import Dict, List

import requests

try:
    import trafilatura

    _HAS_TRAFILATURA = True
except ImportError:
    _HAS_TRAFILATURA = False

try:
    from googlesearch import search

    _HAS_GOOGLESEARCH = True
except ImportError:
    _HAS_GOOGLESEARCH = False

logger = logging.getLogger("elengenix.research")

_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

_TIMEOUT = 15
_MAX_TEXT = 4000  # chars returned to LLM


def _headers() -> Dict[str, str]:
    """Return randomised browser-like HTTP headers."""
    return {
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
        "Connection": "keep-alive",
    }


def _search_tavily(query: str, num_results: int, api_key: str) -> List[Dict]:
    """
    Search using Tavily API (returns rich, structured snippets).

    Args:
        query: Search query string.
        num_results: Max results to return.
        api_key: Tavily API key.

    Returns:
        List of dicts with url, title, content.
    """
    try:
        logger.info(f"Searching Tavily for: {query}")
        resp = requests.post(
            "https://api.tavily.com/search",
            json={
                "api_key": api_key,
                "query": query,
                "search_depth": "smart",
                "max_results": num_results,
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        results = []
        for r in data.get("results", []):
            results.append(
                {
                    "url": r.get("url", ""),
                    "title": r.get("title", ""),
                    "content": r.get("content") or r.get("snippet", ""),
                }
            )
        return results
    except Exception as e:
        logger.error(f"Tavily search error: {e}")
        return []


def _search_duckduckgo(query: str, num_results: int) -> List[Dict]:
    """
    Search using DuckDuckGo (free, no API key, returns real snippets).

    This is the primary free backend. It returns title + body snippet for
    each result so the AI does not need to fabricate content.

    Args:
        query: Search query string.
        num_results: Max results to return.

    Returns:
        List of dicts with url, title, content.
    """
    try:
        from duckduckgo_search import DDGS as _DDGS

        _HAS_DDG = True
    except ImportError:
        try:
            from ddgs import DDGS as _DDGS  # type: ignore[no-redef]
            _HAS_DDG = True
        except ImportError:
            _HAS_DDG = False

    if not _HAS_DDG:
        logger.warning("[WARN] DuckDuckGo not installed. Run: pip install ddgs")
        return []

    try:
        logger.info(f"Searching DuckDuckGo for: {query}")
        results = []
        with _DDGS() as ddgs:  # type: ignore[possibly-undefined]
            for r in ddgs.text(query, max_results=num_results):
                results.append(
                    {
                        "url": r.get("href") or r.get("hre", ""),
                        "title": r.get("title", "Web Result"),
                        "content": r.get("body", ""),
                    }
                )
        return results
    except Exception as e:
        logger.error(f"DuckDuckGo search error: {e}")
        return []


def _search_google_fallback(query: str, num_results: int) -> List[Dict]:
    """
    Last-resort Google scraping fallback.

    Returns URL list only — content will be empty and may require
    extract_and_summarize() to be useful.

    Args:
        query: Search query string.
        num_results: Max results to return.

    Returns:
        List of dicts with url, title (generic), empty content.
    """
    if not _HAS_GOOGLESEARCH:
        return []
    try:
        logger.info(f"Searching Google (scrape fallback) for: {query}")
        urls: List[str] = []
        try:
            urls = list(search(query, num_results=num_results))
        except TypeError:
            try:
                urls = list(search(query, num_results=num_results, stop=num_results))
            except TypeError:
                try:
                    urls = list(search(query, num=num_results, stop=num_results))
                except TypeError:
                    urls = list(search(query))[:num_results]
        return [{"url": u, "title": "Web Result", "content": ""} for u in urls]
    except Exception as e:
        logger.error(f"Google search error: {e}")
        return []


def search_web(query: str, num_results: int = 5) -> List[Dict]:
    """
    Search the web for real-time information.

    Priority order:
      1. Tavily API  — richest snippets, requires TAVILY_API_KEY env var
      2. DuckDuckGo  — real snippets, free, no key needed  (primary fallback)
      3. Google scrape — URLs only, last resort

    Args:
        query: The search query.
        num_results: Number of results to return.

    Returns:
        List of dicts: [{url, title, content}]
    """
    tavily_key = os.getenv("TAVILY_API_KEY")

    # 1. Tavily (preferred when API key is available)
    if tavily_key:
        results = _search_tavily(query, num_results, tavily_key)
        if results:
            return results
        logger.warning("[WARN] Tavily failed, falling back to DuckDuckGo")

    # 2. DuckDuckGo (primary free backend — returns real snippets)
    results = _search_duckduckgo(query, num_results)
    if results:
        return results

    # 3. Google scrape (last resort — content may be empty)
    logger.warning("[WARN] DuckDuckGo failed, falling back to Google scrape")
    return _search_google_fallback(query, num_results)


def extract_and_summarize(url: str, max_chars: int = _MAX_TEXT) -> Dict:
    """
    Fetch and extract readable text from a URL using trafilatura.

    Args:
        url: The URL to fetch.
        max_chars: Maximum characters to return.

    Returns:
        Dict with url, title, text, chars, error keys.
    """
    try:
        r = requests.get(url, headers=_headers(), timeout=_TIMEOUT, verify=False)
        r.raise_for_status()

        if not _HAS_TRAFILATURA:
            return {
                "url": url,
                "text": "trafilatura not installed; cannot extract content",
                "chars": 0,
                "error": "missing trafilatura",
            }
        text = trafilatura.extract(
            r.text,
            include_tables=False,
            include_links=False,
            no_fallback=False,
        )
        if not text:
            text = "No readable content extracted."

        return {
            "url": url,
            "text": text[:max_chars],
            "chars": len(text),
            "error": "",
        }
    except Exception as e:
        logger.error(f"Extract error ({url}): {e}")
        return {"url": url, "text": "", "chars": 0, "error": str(e)}


def research_target(
    target: str,
    num_results: int = 5,
    summarize: bool = True,
) -> List[Dict]:
    """
    Search for OSINT about a target and optionally extract page text.

    Args:
        target: Domain or organisation name to research.
        num_results: Results per query.
        summarize: Whether to extract full page text from each URL.

    Returns:
        List of extracted content dicts.
    """
    queries = [
        f"site:{target} inurl:admin OR inurl:config OR inurl:api",
        f'"{target}" vulnerability OR CVE OR exploit',
        f'"{target}" tech stack framework',
    ]

    results: List[Dict] = []
    seen: set = set()

    for q in queries:
        search_results = search_web(q, num_results=num_results)
        for res in search_results:
            url = res["url"]
            if url in seen:
                continue
            seen.add(url)

            if summarize:
                if res.get("content") and len(res["content"]) > 500:
                    results.append(
                        {
                            "url": url,
                            "text": res["content"][:_MAX_TEXT],
                            "chars": len(res["content"]),
                            "error": "",
                        }
                    )
                else:
                    data = extract_and_summarize(url)
                    results.append(data)
            else:
                results.append({"url": url, "text": "", "chars": 0, "error": ""})

            time.sleep(0.3)  # polite delay

    return results

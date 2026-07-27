"""elengenix/docker/browser.py — Thin async HTTP client to the vxcontrol/scraper service.

Port of PentAGI's ``backend/pkg/tools/browser.go`` (521 lines). The
scraper is a self-hosted headless-Chrome sidecar (image
``vxcontrol/scraper:latest``) that exposes four endpoints: ``/markdown``,
``/html``, ``/links`` (JSON), and ``/screenshot`` (PNG). URL routing
chooses between a private scraper URL (for LAN/loopback targets) and a
public scraper URL based on host IP classification + a local-zones
suffix list. ``httpx.AsyncClient(verify=False, timeout=65.0)`` replaces
Go's ``http.Client{Timeout: 65s, TLSClientConfig: InsecureSkipVerify}``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable
from urllib.parse import urlencode, urlparse, urlunparse, ParseResult

logger = logging.getLogger("elengenix.docker.browser")

# ── Minimum content-size thresholds (port of browser.go §24-28) ─────────
MIN_MD_CONTENT_SIZE = 50
MIN_HTML_CONTENT_SIZE = 300
MIN_IMG_CONTENT_SIZE = 2048

# ── Binary-URL guard: known non-HTML extensions (verbatim from browser.go) ─
NON_HTML_EXTENSIONS: tuple[str, ...] = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav",
    ".exe", ".bin", ".dll", ".so", ".dmg", ".apk",
)

# ── Local zones (verbatim from browser.go §56-68) ───────────────────────
LOCAL_ZONES: tuple[str, ...] = (
    ".localdomain",
    ".local",
    ".lan",
    ".htb",
    ".dev",
    ".test",
    ".corp",
    ".example",
    ".invalid",
    ".internal",
    ".home.arpa",
)

# ── HTTP client config (verbatim from browser.go §491-497) ──────────────
SCRAPER_HTTP_TIMEOUT = 65.0  # seconds


@runtime_checkable
class ScreenshotProviderProtocol(Protocol):
    """Optional screenshot-recording sink (port of Go ScreenshotProvider)."""

    async def put_screenshot(
        self, screenshot_path: str, url: str,
        task_id: Optional[int] = None, subtask_id: Optional[int] = None,
    ) -> Any: ...


class _NullScreenshotProvider:
    async def put_screenshot(self, *args: Any, **kw: Any) -> None:
        return None


@dataclass
class BrowserResult:
    """Outcome of a browser action: content + optional screenshot path."""

    content: str
    screenshot: Optional[str] = None


def is_binary_url(raw_url: str) -> bool:
    """Return True iff the URL path ends in a known non-HTML extension.

    Port of Go ``isBinaryURL`` — strips the query string before suffix
    matching and case-normalises the URL.
    """
    lower = raw_url.lower()
    if (idx := lower.find("?")) != -1:
        lower = lower[:idx]
    return lower.endswith(NON_HTML_EXTENSIONS)


def _is_private_ip(host: str) -> bool:
    """Return True for private/loopback IPv4/IPv6 literals."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def _resolve_host_ips(host: str) -> list[str]:
    """Best-effort DNS resolution of ``host`` to a list of IP strings.

    Failures (NXDOMAIN, timeout, etc.) return an empty list — the caller
    falls back to local-zone heuristic matching.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, socket.herror, OSError):
        return []
    return [info[4][0] for info in infos if info[4]]


class DockerBrowser:
    """Async client for the external ``vxcontrol/scraper`` sidecar service.

    Mirrors the PentAGI ``browser`` struct (browser.go §70-78). Three
    public actions (``markdown``, ``html``, ``links``) each fetch
    content + capture a screenshot in parallel. A binary-URL guard
    rejects known non-HTML resources with a hint to use the terminal
    tool's ``curl``/``wget`` instead.
    """

    def __init__(
        self,
        *,
        flow_id: int | str,
        data_dir: str,
        scraper_private_url: str = "",
        scraper_public_url: str = "",
        screenshot_provider: Optional[ScreenshotProviderProtocol] = None,
        task_id: Optional[int] = None,
        subtask_id: Optional[int] = None,
    ) -> None:
        self.flow_id = flow_id
        self.data_dir = data_dir
        self.sc_prv_url = scraper_private_url.rstrip("/")
        self.sc_pub_url = scraper_public_url.rstrip("/")
        self.scp: ScreenshotProviderProtocol = screenshot_provider or _NullScreenshotProvider()
        self.task_id = task_id
        self.subtask_id = subtask_id

    # ── Availability ────────────────────────────────────────────────────
    def is_available(self) -> bool:
        """Mirror Go ``IsAvailable`` — true if either scraper URL is set."""
        return bool(self.sc_prv_url) or bool(self.sc_pub_url)

    # ── URL routing (port of browser.go §285-340) ───────────────────────
    def resolve_url(self, target_url: str) -> ParseResult:
        """Choose the scraper base URL (private vs public) for ``target_url``.

        Decision tree (verbatim port):
          1. Parse the URL; extract host (without port).
          2. If host is an IP literal → check ``is_private`` / ``is_loopback``.
          3. Else DNS-resolve → if any resolved IP is private/loopback → private.
          4. Else if host contains ``localhost`` or has no ``.`` → private.
          5. Else if host ends with any ``LOCAL_ZONES`` suffix → private.
          6. Else public.

        Private scraper URL falls back to public if unset (and vice versa).
        """
        try:
            u = urlparse(target_url)
        except Exception as exc:
            raise ValueError(f"failed to parse url: {exc}") from exc

        host = u.hostname or ""

        is_private = False
        if _is_private_ip(host):
            is_private = True
        else:
            resolved = _resolve_host_ips(host)
            if any(_is_private_ip(ip) for ip in resolved):
                is_private = True
            else:
                lower_host = host.lower()
                if "localhost" in lower_host or "." not in lower_host:
                    is_private = True
                else:
                    is_private = lower_host.endswith(LOCAL_ZONES)

        if is_private:
            scraper_url = self.sc_prv_url or self.sc_pub_url
        else:
            scraper_url = self.sc_pub_url or self.sc_prv_url

        if not scraper_url:
            raise ValueError("no scraper URL configured")

        return urlparse(scraper_url)

    # ── Screenshot persistence (port of browser.go §342-360) ────────────
    def _screenshot_path(self) -> str:
        """Compute the on-disk path for a new screenshot.

        ``{data_dir}/screenshots/flow-{flow_id}/screenshot-{unix_ts}.png``
        — matches the PentAGI layout exactly. The directory is created
        lazily on first write.
        """
        flow_dir = os.path.join(self.data_dir, "screenshots", f"flow-{self.flow_id}")
        os.makedirs(flow_dir, exist_ok=True)
        return os.path.join(flow_dir, f"screenshot-{int(time.time())}.png")

    async def _save_screenshot(self, content: bytes) -> str:
        """Write the screenshot PNG and record it via ``scp.put_screenshot``."""
        if len(content) < MIN_IMG_CONTENT_SIZE:
            raise RuntimeError(
                f"image size is less than minimum: {MIN_IMG_CONTENT_SIZE} bytes"
            )
        path = self._screenshot_path()
        try:
            await asyncio.to_thread(self._write_file, path, content, 0o644)
        except OSError as exc:
            raise RuntimeError(f"screenshot write operation failed: {exc}") from exc
        try:
            await self.scp.put_screenshot(path, "", self.task_id, self.subtask_id)
        except Exception as exc:  # noqa: BLE001 — recording is best-effort
            logger.warning("screenshot recording failed: %s", exc)
        return path

    @staticmethod
    def _write_file(path: str, content: bytes, mode: int = 0o644) -> None:
        with open(path, "wb") as f:
            f.write(content)
            os.chmod(path, mode)

    # ── Scraper HTTP call (port of browser.go §491-516) ─────────────────
    async def _call_scraper(self, scraper_url: ParseResult, path: str,
                            extra_query: dict[str, str]) -> bytes:
        """Issue a single GET to ``{scraper_url}{path}?{query}`` and return bytes.

        Uses ``httpx.AsyncClient(verify=False, timeout=65.0)`` (the scraper
        self-signs its TLS cert). Only GET is supported (matches Go).
        """
        try:
            import httpx  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover — runtime guard
            raise RuntimeError(
                "httpx is required for DockerBrowser — install with `pip install httpx`"
            ) from exc

        query = dict(scraper_url.query)  # type: ignore[arg-type]
        query.update(extra_query)
        full = urlunparse((
            scraper_url.scheme, scraper_url.netloc, path, "",
            urlencode(query), "",
        ))

        async with httpx.AsyncClient(verify=False, timeout=SCRAPER_HTTP_TIMEOUT) as client:
            try:
                resp = await client.get(full)
            except Exception as exc:
                raise RuntimeError(
                    f"failed to fetch data by scraper '{full}': {exc}"
                ) from exc

        if resp.status_code != 200:
            raise RuntimeError(
                f"unexpected resp code for scraper '{full}': {resp.status_code}"
            )

        content = resp.content
        if not content:
            raise RuntimeError(f"empty response body for scraper '{full}'")
        return content

    # ── Public actions (markdown / html / links) ────────────────────────
    async def _action(
        self, target_url: str, action_path: str, *,
        min_size: int, kind: str, binary_ok: bool = True,
    ) -> BrowserResult:
        """Common dispatch for markdown/html/links actions.

        Concurrent content + screenshot fetch (port of browser.go §171-283
        — Go uses two goroutines + ``sync.WaitGroup``; Python uses
        ``asyncio.gather``). Screenshot failure is non-fatal.
        """
        if not binary_ok and is_binary_url(target_url):
            raise RuntimeError(
                f"the URL appears to point to a binary/non-HTML resource "
                f"(e.g. PDF, image, archive) that cannot be rendered as {kind}. "
                f"Use the terminal tool with curl/wget to download it instead"
            )

        scraper_url = self.resolve_url(target_url)

        content_task = asyncio.create_task(
            self._call_scraper(scraper_url, action_path, {"url": target_url})
        )
        # Screenshot is always captured in parallel (browser.go §468-489).
        screenshot_task = asyncio.create_task(
            self._call_scraper(scraper_url, "/screenshot",
                               {"url": target_url, "fullPage": "true"})
        )

        content_bytes = await content_task
        try:
            screenshot_bytes = await screenshot_task
        except Exception as exc:  # noqa: BLE001 — screenshot failure is non-fatal
            logger.warning("failed to capture screenshot, continuing without it: %s", exc)
            screenshot_bytes = b""

        if action_path == "/links":
            content = self._format_links(target_url, content_bytes)
        else:
            text = content_bytes.decode("utf-8", errors="replace")
            if len(content_bytes) < min_size:
                content = (
                    f"[WARNING: page returned very little {kind} content "
                    f"({len(content_bytes)} bytes), it may be a redirect, "
                    f"error page, or near-empty]\n\n{text}"
                )
            else:
                content = text

        screenshot_path: Optional[str] = None
        if screenshot_bytes:
            try:
                screenshot_path = await self._save_screenshot(screenshot_bytes)
            except Exception as exc:  # noqa: BLE001 — non-fatal
                logger.warning("screenshot save failed: %s", exc)

        return BrowserResult(content=content, screenshot=screenshot_path)

    @staticmethod
    def _format_links(target_url: str, content_bytes: bytes) -> str:
        """Parse the ``/links`` JSON response and format as a markdown list.

        Port of browser.go §442-465. Response shape:
        ``[{"Title": "...", "Link": "..."}, ...]``.
        """
        try:
            links = json.loads(content_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"failed to unmarshal links: {exc}") from exc

        if not isinstance(links, list):
            raise RuntimeError(
                f"unexpected links payload shape: {type(links).__name__}"
            )

        buffer: list[str] = [f"Links list from URL '{target_url}'"]
        for entry in links:
            if not isinstance(entry, dict):
                continue
            link = (entry.get("Link") or "").strip()
            if not link:
                continue
            title = (entry.get("Title") or "").strip() or "UNTITLED"
            buffer.append(f"[{title}]({link})")
        return "\n".join(buffer)

    async def markdown(self, url: str) -> BrowserResult:
        """Fetch ``/markdown?url=…`` — content smaller than 50 bytes is flagged."""
        return await self._action(
            url, "/markdown", min_size=MIN_MD_CONTENT_SIZE,
            kind="markdown", binary_ok=False,
        )

    async def html(self, url: str) -> BrowserResult:
        """Fetch ``/html?url=…`` — content smaller than 300 bytes is flagged."""
        return await self._action(
            url, "/html", min_size=MIN_HTML_CONTENT_SIZE,
            kind="HTML", binary_ok=False,
        )

    async def links(self, url: str) -> BrowserResult:
        """Fetch ``/links?url=…`` (returns JSON, formatted as a markdown list)."""
        return await self._action(
            url, "/links", min_size=0, kind="links", binary_ok=True,
        )

    # ── Single entry-point dispatcher (port of browser.go §129-169) ─────
    async def handle(self, action: str, url: str) -> BrowserResult:
        """Dispatch ``action`` ∈ {``markdown``, ``html``, ``links``}."""
        if not self.is_available():
            raise RuntimeError("browser is not available")
        if action == "markdown":
            return await self.markdown(url)
        if action == "html":
            return await self.html(url)
        if action == "links":
            return await self.links(url)
        raise ValueError(f"unknown browser action: {action}")


__all__ = [
    "MIN_MD_CONTENT_SIZE",
    "MIN_HTML_CONTENT_SIZE",
    "MIN_IMG_CONTENT_SIZE",
    "NON_HTML_EXTENSIONS",
    "LOCAL_ZONES",
    "SCRAPER_HTTP_TIMEOUT",
    "BrowserResult",
    "DockerBrowser",
    "ScreenshotProviderProtocol",
    "is_binary_url",
]

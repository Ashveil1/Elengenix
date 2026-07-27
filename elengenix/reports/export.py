"""elengenix.reports.export — Multi-format async report export.

Public surface (matches the brutal test contract):
  * ``SUPPORTED_FORMATS`` — tuple of canonical format names.
  * ``_slugify_title(title)`` — filesystem-safe slug (no ``/`` or ``\\``,
    capped at 150 chars).
  * ``generate_filename(flow_id, title, fmt)`` — async; canonical
    ``report_flow_{id}_{slug}_{timestamp14}.{ext}`` pattern.
  * ``render_html(markdown, *, include_css=True)`` — markdown → HTML with
    raw-HTML escaping (XSS-safe) and an optional ``<style>`` block.
  * ``export_report(flow_id, fmt, *, provider=None)`` — async; returns the
    report content as ``bytes``.

The provider, when supplied, is an async *data* provider exposing
``get_flow(flow_id)``, ``list_tasks(flow_id)`` and ``list_subtasks(task_id)``.
A provider exposing ``complete_async(prompt, *, system=None)`` is also
supported as a fallback to *generate* the markdown body. When ``provider`` is
``None`` a minimal template is rendered from ``flow_id`` alone.
"""
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from .markdown import generate_report_markdown
from .pdf import render_to_pdf_bytes

# Canonical format names. NOTE: "markdown" (not "md") is the public name.
SUPPORTED_FORMATS: tuple[str, ...] = ("markdown", "pdf", "html", "json")

# Explicit ``__all__`` so ``from elengenix.reports.export import *`` also
# exposes the underscore-prefixed slugifier (used by the brutal test suite
# and the verification snippet).
__all__ = [
    "SUPPORTED_FORMATS",
    "_slugify_title",
    "generate_filename",
    "render_html",
    "export_report",
]

# Filename extension map (public format name → file extension).
_EXT_MAP: dict[str, str] = {
    "markdown": "md",
    "pdf": "pdf",
    "html": "html",
    "json": "json",
}

# Default CSS injected when ``render_html(include_css=True)``.
_DEFAULT_CSS = """<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #222; line-height: 1.5; }
h1 { font-size: 1.9rem; border-bottom: 2px solid #ddd; padding-bottom: 0.3rem; }
h2 { font-size: 1.5rem; margin-top: 1.8rem; }
h3 { font-size: 1.2rem; margin-top: 1.4rem; }
code { background: #f4f4f4; padding: 0.1rem 0.35rem; border-radius: 3px; font-family: "SFMono-Regular", Consolas, monospace; }
pre { background: #f6f8fa; padding: 0.9rem; border-radius: 6px; overflow-x: auto; }
pre code { background: none; padding: 0; }
blockquote { border-left: 4px solid #ccc; margin: 0; padding: 0.2rem 1rem; color: #555; }
table { border-collapse: collapse; margin: 1rem 0; }
th, td { border: 1px solid #ddd; padding: 0.4rem 0.7rem; }
th { background: #f0f0f0; }
a { color: #0366d6; }
</style>"""


def _slugify_title(title: str) -> str:
    """Convert a title to a filesystem-safe, underscore-joined slug.

    Rules:
      * lowercase
      * strip path separators (``/`` and ``\\``) entirely
      * drop any character that is not a word char or whitespace
      * collapse whitespace runs into a single ``_``
      * collapse repeated ``_``
      * strip leading/trailing ``_``
      * cap at 150 characters
    """
    if not title:
        return ""
    s = title.lower()
    # Strip path separators completely (never converted to a separator).
    s = s.replace("/", "").replace("\\", "")
    # Drop any char that is not a word char (\w includes underscore) or whitespace.
    s = re.sub(r"[^\w\s]", "", s)
    # Whitespace runs → single underscore.
    s = re.sub(r"\s+", "_", s)
    # Collapse repeated underscores.
    s = re.sub(r"_+", "_", s)
    # Trim leading/trailing underscores.
    s = s.strip("_")
    # Hard cap at 150 characters.
    return s[:150]


async def generate_filename(flow_id: int, title: str, fmt: str) -> str:
    """Build the canonical export filename.

    Pattern: ``report_flow_{id}_{slug}_{YYYYMMDDHHMMSS}.{ext}``

    The extension is derived from the public format name
    (``markdown`` → ``md``, ``pdf`` → ``pdf``, …). Unknown formats fall back
    to ``.txt``.
    """
    slug = _slugify_title(title)
    # 14-digit UTC timestamp (YYYYMMDDHHMMSS).
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    ext = _EXT_MAP.get(fmt.lower().lstrip("."), "txt")
    return f"report_flow_{flow_id}_{slug}_{timestamp}.{ext}"


def _escape_html(text: str) -> str:
    """Escape ``&``, ``<``, ``>`` and ``"`` for safe HTML insertion."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _fallback_markdown_to_html(markdown: str) -> str:
    """Minimal, XSS-safe markdown → HTML used when ``markdown_it`` is absent.

    All raw text is HTML-escaped *first*, so any ``<script>`` / ``<img>`` /
    ``javascript:`` payload is neutralised before markdown transforms run.
    """
    in_code_block = False
    out: list[str] = []

    for raw_line in markdown.split("\n"):
        if raw_line.startswith("```"):
            if in_code_block:
                out.append("</code></pre>")
                in_code_block = False
            else:
                out.append("<pre><code>")
                in_code_block = True
            continue
        if in_code_block:
            out.append(_escape_html(raw_line))
            continue

        line = _escape_html(raw_line)
        if line.startswith("### "):
            out.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("## "):
            out.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("&gt; "):
            out.append(f"<blockquote>{line[5:]}</blockquote>")
        elif line.startswith("- ") or line.startswith("* "):
            out.append(f"<li>{line[2:]}</li>")
        elif line.strip():
            clean = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
            clean = re.sub(r"\*(.+?)\*", r"<em>\1</em>", clean)
            clean = re.sub(r"`(.+?)`", r"<code>\1</code>", clean)
            out.append(f"<p>{clean}</p>")
        else:
            out.append("")
    return "\n".join(out)


def render_html(markdown: str, *, include_css: bool = True) -> str:
    """Render markdown to a standalone, XSS-safe HTML page.

    Raw HTML in the markdown is escaped (no active ``<script>`` / ``<img>`` /
    ``javascript:`` payloads survive). When ``include_css`` is ``True`` a
    ``<style>`` block with basic typography is injected into ``<head>``.
    """
    try:
        from markdown_it import MarkdownIt

        # ``html=False`` causes raw HTML to be escaped (markdown-it-py behaviour).
        md_it = MarkdownIt("commonmark", {"html": False})
        body_html = md_it.render(markdown)
    except Exception:  # pragma: no cover — graceful degradation
        body_html = _fallback_markdown_to_html(markdown)

    css_block = _DEFAULT_CSS if include_css else ""
    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "<title>Report</title>\n"
        f"{css_block}\n"
        "</head>\n"
        "<body>\n"
        f"{body_html}\n"
        "</body>\n"
        "</html>\n"
    )


class _DummyFlow:
    """Minimal flow stand-in used when no provider is supplied."""

    def __init__(self, flow_id: int) -> None:
        self.id = flow_id
        self.title = f"Flow {flow_id}"
        self.status = "finished"


async def _gather_flow_data(
    flow_id: int, provider: Any
) -> tuple[Any, Sequence[Any], Sequence[Any]]:
    """Resolve (flow, tasks, subtasks) from the provider, or a default."""
    if provider is None:
        return _DummyFlow(flow_id), [], []

    # Data-provider shape: get_flow / list_tasks / list_subtasks.
    has_data_iface = hasattr(provider, "get_flow") and hasattr(
        provider, "list_tasks"
    )
    if has_data_iface:
        flow = await provider.get_flow(flow_id)
        tasks = list(await provider.list_tasks(flow_id) or [])
        subtasks: list[Any] = []
        if tasks and hasattr(provider, "list_subtasks"):
            # Gather subtasks concurrently for speed (stress test <1s/100 tasks).
            task_ids = [getattr(t, "id", idx) for idx, t in enumerate(tasks)]
            subtask_lists = await asyncio.gather(
                *(provider.list_subtasks(tid) for tid in task_ids)
            )
            for sts in subtask_lists:
                if sts:
                    subtasks.extend(sts)
        return flow, tasks, subtasks

    # Fallback: no data interface — caller may use complete_async instead.
    return _DummyFlow(flow_id), [], []


async def _build_markdown(
    flow_id: int,
    flow: Any,
    tasks: Sequence[Any],
    subtasks: Sequence[Any],
    provider: Any,
) -> str:
    """Produce the markdown body.

    If the provider exposes ``complete_async`` *and* there are no tasks to
    serialise, delegate markdown generation to the LLM provider; otherwise
    assemble deterministically from flow/task/subtask data; otherwise emit a
    minimal template from ``flow_id`` alone.
    """
    if tasks or subtasks:
        return generate_report_markdown(flow, tasks, subtasks)

    if provider is not None and hasattr(provider, "complete_async"):
        try:
            prompt = (
                f"Generate a concise markdown security report for flow {flow_id}"
                f" (title: {getattr(flow, 'title', '')!s})."
            )
            md = await provider.complete_async(
                prompt, system="You are a security report generator."
            )
            if md:
                return md
        except Exception:
            pass

    # Minimal deterministic template (no tasks, no LLM provider).
    title = getattr(flow, "title", f"Flow {flow_id}") or f"Flow {flow_id}"
    return f"# {title}\n\n_No tasks recorded for flow {flow_id}._\n"


def _build_json_payload(
    flow_id: int,
    flow: Any,
    tasks: Sequence[Any],
    subtasks: Sequence[Any],
) -> dict[str, Any]:
    """Assemble the structured JSON export payload."""
    return {
        "flow": {
            "id": getattr(flow, "id", flow_id),
            "title": getattr(flow, "title", "") or "",
            "status": str(getattr(flow, "status", "") or ""),
        },
        "tasks": [
            {
                "id": getattr(t, "id", None),
                "title": getattr(t, "title", "") or "",
                "input": getattr(t, "input", "") or "",
                "result": getattr(t, "result", "") or "",
                "status": str(getattr(t, "status", "") or ""),
            }
            for t in tasks
        ],
        "subtasks": [
            {
                "id": getattr(st, "id", None),
                "title": getattr(st, "title", "") or "",
                "description": getattr(st, "description", "") or "",
                "result": getattr(st, "result", "") or "",
                "status": str(getattr(st, "status", "") or ""),
                "task_id": getattr(st, "task_id", None),
            }
            for st in subtasks
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


async def export_report(
    flow_id: int, fmt: str, *, provider: Optional[Any] = None
) -> bytes:
    """Export a report for ``flow_id`` in the requested ``fmt``.

    Args:
        flow_id: Identifier of the flow to export.
        fmt: Output format — one of :data:`SUPPORTED_FORMATS`.
        provider: Optional async data provider (``get_flow`` /
            ``list_tasks`` / ``list_subtasks``) or LLM provider
            (``complete_async``). When ``None`` a minimal template is rendered.

    Returns:
        Report content as ``bytes``.

    Raises:
        ValueError: if ``fmt`` is not in :data:`SUPPORTED_FORMATS`.
    """
    fmt_norm = fmt.lower().lstrip(".")
    if fmt_norm not in SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported format: {fmt!r}. Supported: {SUPPORTED_FORMATS}"
        )

    flow, tasks, subtasks = await _gather_flow_data(flow_id, provider)

    if fmt_norm == "markdown":
        md = await _build_markdown(flow_id, flow, tasks, subtasks, provider)
        return md.encode("utf-8")

    if fmt_norm == "html":
        md = await _build_markdown(flow_id, flow, tasks, subtasks, provider)
        return render_html(md, include_css=True).encode("utf-8")

    if fmt_norm == "pdf":
        md = await _build_markdown(flow_id, flow, tasks, subtasks, provider)
        return render_to_pdf_bytes(md)

    if fmt_norm == "json":
        payload = _build_json_payload(flow_id, flow, tasks, subtasks)
        return json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")

    # Unreachable — guarded by the SUPPORTED_FORMATS check above.
    raise ValueError(f"Unsupported format: {fmt!r}")  # pragma: no cover

"""Multi-format report export: markdown / html / json / pdf."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from typing import Any, AsyncIterable, Dict, List, Sequence

from elengenix.reports.markdown import generate_report_markdown
from elengenix.reports.pdf import render_to_pdf_bytes

__all__ = [
    "SUPPORTED_FORMATS",
    "export_report",
    "generate_filename",
    "render_html",
    "_slugify_title",
]

SUPPORTED_FORMATS = ("markdown", "html", "json", "pdf")

_FORMAT_EXTENSIONS = {
    "markdown": "md",
    "html": "html",
    "json": "json",
    "pdf": "pdf",
}


def _slugify_title(title: str) -> str:
    """Lowercase ASCII slug with underscores, used inside filenames."""
    import re

    slug = re.sub(r"[^a-z0-9]+", "_", title.lower())
    return slug.strip("_") or "report"


def render_html(md_text: str, include_css: bool = True, title: str = "Report") -> str:
    """Render markdown to a full HTML document (pygments-highlighted code)."""
    from markdown_it import MarkdownIt
    from pygments import highlight
    from pygments.formatters import HtmlFormatter
    from pygments.lexers import get_lexer_by_name
    from pygments.util import ClassNotFound

    def _highlight(code: str, lang: str, _) -> str:
        try:
            lexer = get_lexer_by_name(lang or "text", stripall=False)
        except ClassNotFound:
            lexer = get_lexer_by_name("text", stripall=False)
        formatter = HtmlFormatter(nowrap=False)
        return highlight(code, lexer, formatter)

    md = MarkdownIt("commonmark", {"highlight": _highlight, "html": False})
    try:
        md.enable("table")
    except Exception:  # pragma: no cover - table rule always exists
        pass
    body = md.render(md_text)

    css = ""
    if include_css:
        formatter = HtmlFormatter()
        css = (
            "<style>\n"
            + formatter.get_style_defs(".highlight")
            + "\nbody { font-family: sans-serif; margin: 2rem auto; max-width: 60rem; "
            + "padding: 0 1rem; line-height: 1.5; }\n"
            + "pre { background: #f4f4f4; padding: 0.75rem; border-radius: 4px; overflow-x: auto; }\n"
            + "code { font-family: monospace; }\n"
            + "table { border-collapse: collapse; }\n"
            + "th, td { border: 1px solid #999; padding: 0.3rem 0.6rem; }\n"
            + "</style>"
        )

    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        f"<title>{title}</title>\n{css}\n</head>\n<body>\n{body}\n</body>\n</html>\n"
    )


def _record(obj: Any) -> Dict[str, Any]:
    """Serialize a flow/task/subtask (dataclass or duck-typed) to a dict."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, dict):
        return dict(obj)
    out: Dict[str, Any] = {}
    for name in ("id", "title", "status", "input", "result", "description",
                 "task_id", "flow_id", "user_id", "model", "created_at"):
        if hasattr(obj, name):
            value = getattr(obj, name)
            out[name] = getattr(value, "value", value)
    return out


async def export_report(flow_id: int, fmt: str, provider: Any) -> bytes:
    """Export a flow report in the requested format as bytes.

    ``provider`` must expose ``get_flow(flow_id)``, ``list_tasks(flow_id)``
    and ``list_subtasks(task_id)`` coroutines.
    """
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(
            f"unsupported report format: {fmt!r} (supported: {', '.join(SUPPORTED_FORMATS)})"
        )

    flow = await provider.get_flow(flow_id)
    tasks: List[Any] = list(await provider.list_tasks(flow_id))
    subtasks: List[Any] = []
    for task in tasks:
        subtasks.extend(await provider.list_subtasks(getattr(task, "id", task)))

    md_text = generate_report_markdown(flow, tasks, subtasks)

    if fmt == "markdown":
        return md_text.encode("utf-8")
    if fmt == "html":
        return render_html(md_text, include_css=True).encode("utf-8")
    if fmt == "json":
        payload = {
            "flow": _record(flow),
            "tasks": [_record(t) for t in tasks],
            "subtasks": [_record(s) for s in subtasks],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return json.dumps(payload, indent=2, default=str).encode("utf-8")
    # fmt == "pdf"
    return render_to_pdf_bytes(md_text)


async def generate_filename(flow_id: int, title: str, fmt: str) -> str:
    """Canonical report filename: report_flow_{id}_{slug}_{timestamp}.{ext}."""
    ext = _FORMAT_EXTENSIONS.get(fmt, "txt")
    slug = _slugify_title(title)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"report_flow_{flow_id}_{slug}_{timestamp}.{ext}"

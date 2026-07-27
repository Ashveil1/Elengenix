"""elengenix.reports.export — Multi-format report export."""
from __future__ import annotations

import json
import re
from typing import Any, Sequence

from .markdown import generate_report_markdown, slugify_github
from .pdf import render_to_pdf_bytes

SUPPORTED_FORMATS = ("md", "pdf", "html", "json")


def _slugify_title(title: str) -> str:
    """Convert a title to a filesystem-safe slug."""
    return slugify_github(title)


def generate_filename(title: str, fmt: str) -> str:
    """Generate a filename from a title and format."""
    slug = _slugify_title(title)
    return f"{slug}.{fmt}"


def render_html(markdown: str) -> str:
    """Convert markdown to a simple HTML page."""
    # Minimal markdown → HTML conversion
    html_lines = ["<!DOCTYPE html>", "<html>", "<head><meta charset='UTF-8'><title>Report</title></head>", "<body>"]

    in_code_block = False
    for line in markdown.split("\n"):
        if line.startswith("```"):
            if in_code_block:
                html_lines.append("</code></pre>")
                in_code_block = False
            else:
                html_lines.append("<pre><code>")
                in_code_block = True
            continue

        if in_code_block:
            html_lines.append(line)
            continue

        # Headers
        if line.startswith("# "):
            html_lines.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("> "):
            html_lines.append(f"<blockquote>{line[2:]}</blockquote>")
        elif line.startswith("- "):
            html_lines.append(f"<li>{line[2:]}</li>")
        elif line.strip():
            # Bold and italic
            clean = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
            clean = re.sub(r"\*(.+?)\*", r"<em>\1</em>", clean)
            clean = re.sub(r"`(.+?)`", r"<code>\1</code>", clean)
            html_lines.append(f"<p>{clean}</p>")
        else:
            html_lines.append("<br>")

    html_lines.append("</body></html>")
    return "\n".join(html_lines)


def export_report(
    flow: Any,
    tasks: Sequence[Any],
    subtasks: Sequence[Any] | None = None,
    fmt: str = "md",
) -> bytes:
    """Export a report in the specified format.

    Args:
        flow: Flow object with .title attribute
        tasks: Sequence of task objects with .title, .input, .result
        subtasks: Optional sequence of subtask objects
        fmt: Output format — one of SUPPORTED_FORMATS

    Returns:
        Report content as bytes
    """
    subtasks = subtasks or []
    fmt = fmt.lower().lstrip(".")

    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format: {fmt}. Supported: {SUPPORTED_FORMATS}")

    # Generate markdown first (base format)
    md = generate_report_markdown(flow, tasks, subtasks)

    if fmt == "md":
        return md.encode("utf-8")

    if fmt == "pdf":
        return render_to_pdf_bytes(md)

    if fmt == "html":
        return render_html(md).encode("utf-8")

    if fmt == "json":
        # Structured JSON export
        data = {
            "flow": {
                "id": getattr(flow, "id", None),
                "title": getattr(flow, "title", ""),
                "status": str(getattr(flow, "status", "")),
            },
            "tasks": [
                {
                    "id": getattr(t, "id", None),
                    "title": getattr(t, "title", ""),
                    "input": getattr(t, "input", ""),
                    "result": getattr(t, "result", ""),
                    "status": str(getattr(t, "status", "")),
                }
                for t in tasks
            ],
            "subtasks": [
                {
                    "id": getattr(st, "id", None),
                    "title": getattr(st, "title", ""),
                    "description": getattr(st, "description", ""),
                    "result": getattr(st, "result", ""),
                    "status": str(getattr(st, "status", "")),
                    "task_id": getattr(st, "task_id", None),
                }
                for st in subtasks
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")

    # Should never reach here
    return md.encode("utf-8")

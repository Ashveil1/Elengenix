"""Markdown report assembly: flows/tasks/subtasks → canonical markdown."""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, Iterable, List, Sequence

__all__ = [
    "DEFAULT_STATUS_EMOJI",
    "STATUS_EMOJI",
    "status_emoji",
    "slugify_github",
    "generate_anchors",
    "shift_markdown_headers",
    "generate_report_markdown",
]

DEFAULT_STATUS_EMOJI = "\U0001F4DD"  # 📝

STATUS_EMOJI = {
    "created": "\U0001F4DD",  # 📝
    "running": "\u26A1",      # ⚡
    "finished": "\u2705",     # ✅
    "failed": "\u274C",       # ❌
    "waiting": "\u23F3",      # ⏳
}


def status_emoji(status: Any) -> str:
    """Return the status glyph for a status value (str or enum); default 📝."""
    if status is None:
        return DEFAULT_STATUS_EMOJI
    key = getattr(status, "value", status)
    return STATUS_EMOJI.get(str(key).lower(), DEFAULT_STATUS_EMOJI)


def slugify_github(text: str) -> str:
    """GitHub-compatible anchor slug (github-slugger behaviour for ASCII).

    Lowercase, spaces → hyphens, drop every non ``[a-z0-9_-]`` character
    (emoji and accented letters are dropped, not transliterated), collapse
    consecutive hyphens and strip leading/trailing hyphens.
    """
    if not text:
        return ""
    slug = text.lower().replace(" ", "-")
    slug = re.sub(r"[^a-z0-9_\-]", "", slug)
    slug = re.sub(r"-{2,}", "-", slug)
    return slug.strip("-")


def generate_anchors(headings: Sequence[str]) -> Dict[str, str]:
    """Map heading text → anchor slug, disambiguating duplicates with -1/-2/…

    When the same heading appears multiple times, the dict keeps the LAST
    occurrence's anchor (dict overwrite semantics).
    """
    anchors: Dict[str, str] = {}
    counts: Dict[str, int] = {}
    for heading in headings:
        base = slugify_github(heading)
        n = counts.get(heading, 0)
        counts[heading] = n + 1
        anchors[heading] = base if n == 0 else f"{base}-{n}"
    return anchors


def shift_markdown_headers(text: str, shift: int) -> str:
    """Shift every ATX heading in ``text`` down by ``shift`` levels (cap H6)."""
    if not text or shift == 0:
        return text
    out: List[str] = []
    for line in text.split("\n"):
        match = re.match(r"^(#{1,6})(\s|$)", line)
        if match:
            level = min(len(match.group(1)) + shift, 6)
            out.append("#" * level + line[len(match.group(1)):])
        else:
            out.append(line)
    return "\n".join(out)


def _field(obj: Any, name: str, default: Any = "") -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _status_text(status: Any) -> str:
    key = getattr(status, "value", status)
    return str(key).lower() if key is not None else ""


def _render_task_section(
    task: Any,
    subtasks: Sequence[Any],
    anchor: str,
    lines: List[str],
) -> None:
    title = str(_field(task, "title", f"Task {_field(task, 'id', '?')}"))
    status = _field(task, "status", None)
    lines.append(f'### <a id="{anchor}"></a>{status_emoji(status)} {title}')
    lines.append("")

    task_input = str(_field(task, "input", "") or "")
    if task_input.strip():
        lines.append("#### Input")
        lines.append("")
        lines.append(shift_markdown_headers(task_input, 3))
        lines.append("")

    task_result = str(_field(task, "result", "") or "")
    if task_result.strip():
        lines.append("#### Result")
        lines.append("")
        lines.append(task_result)
        lines.append("")

    if subtasks:
        lines.append("#### Subtasks")
        lines.append("")
        for sub in subtasks:
            sub_title = str(_field(sub, "title", f"Subtask {_field(sub, 'id', '?')}"))
            sub_status = _field(sub, "status", None)
            lines.append(f"##### {status_emoji(sub_status)} {sub_title}")
            lines.append("")
            description = str(_field(sub, "description", "") or "")
            if description.strip():
                lines.append(description)
                lines.append("")
            sub_result = str(_field(sub, "result", "") or "")
            if sub_result.strip():
                lines.append("Result:")
                lines.append("")
                lines.append(shift_markdown_headers(sub_result, 5))
                lines.append("")


def generate_report_markdown(flow: Any, tasks: Iterable[Any], subtasks: Iterable[Any]) -> str:
    """Assemble the canonical markdown report for a flow.

    Layout: H1 title → Table of Contents (bullet links) → per-task H3
    sections with the task input (headers shifted by 3 so H1 → H4), the
    result, and its subtasks.
    """
    task_list = list(tasks)
    subtask_list = list(subtasks)

    flow_id = _field(flow, "id", "")
    title = str(_field(flow, "title", "") or f"Flow {flow_id}")

    lines: List[str] = [f"# {title}", ""]

    created = _field(flow, "created_at", None)
    if created:
        lines.append(f"*Created: {created}*")
        lines.append("")

    lines.append("## Table of Contents")
    lines.append("")

    if not task_list:
        lines.append("No tasks available.")
        lines.append("")
        lines.append("---")
        return "\n".join(lines)

    anchors = generate_anchors(
        [str(_field(t, "title", f"Task {_field(t, 'id', '?')}")) for t in task_list]
    )

    for task in task_list:
        task_title = str(_field(task, "title", f"Task {_field(task, 'id', '?')}"))
        lines.append(f"- [{task_title}](#{anchors[task_title]})")
    lines.append("")
    lines.append("---")
    lines.append("")

    by_task: Dict[Any, List[Any]] = {}
    for sub in subtask_list:
        by_task.setdefault(_field(sub, "task_id", None), []).append(sub)

    for task in task_list:
        task_title = str(_field(task, "title", f"Task {_field(task, 'id', '?')}"))
        task_subtasks = by_task.get(_field(task, "id", None), [])
        _render_task_section(task, task_subtasks, anchors[task_title], lines)
        lines.append("---")
        lines.append("")

    return "\n".join(lines)

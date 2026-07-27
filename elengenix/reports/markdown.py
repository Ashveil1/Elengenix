"""elengenix.reports.markdown — Markdown report assembly from flow/task/subtask data."""
from __future__ import annotations

import re
from typing import Any, Sequence

DEFAULT_STATUS_EMOJI: dict[str, str] = {
    "finished": "✅",
    "running": "🔄",
    "pending": "⏳",
    "failed": "❌",
    "cancelled": "🚫",
    "todo": "📋",
}


def status_emoji(status: Any) -> str:
    """Return emoji for a status value (case-insensitive)."""
    key = str(status).lower() if status else ""
    return DEFAULT_STATUS_EMOJI.get(key, "📋")


def slugify_github(text: str) -> str:
    """GitHub-compatible slug: lowercase, hyphens, strip special chars."""
    slug = text.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    slug = slug.strip("-")
    return slug


def generate_anchors(title: str) -> str:
    """Generate a GitHub-style markdown anchor from a heading title."""
    return f"#{slugify_github(title)}"


def shift_markdown_headers(md: str, levels: int = 1) -> str:
    """Shift all markdown headers down by `levels` (e.g., # -> ##)."""
    if levels <= 0:
        return md
    prefix = "#" * levels
    lines = md.split("\n")
    shifted = []
    for line in lines:
        if re.match(r"^#{1,6}\s", line):
            shifted.append(prefix + line)
        else:
            shifted.append(line)
    return "\n".join(shifted)


def generate_report_markdown(
    flow: Any,
    tasks: Sequence[Any],
    subtasks: Sequence[Any] | None = None,
) -> str:
    """Assemble a full markdown report from a flow, its tasks, and subtasks.

    The report structure:
    1. # Flow Title
    2. ## Task sections (one per task)
    3. ### Subtask sections (nested under their parent task)
    """
    subtasks = subtasks or []

    # Build subtask lookup by task_id
    subtask_map: dict[int, list[Any]] = {}
    for st in subtasks:
        tid = getattr(st, "task_id", None) or 0
        subtask_map.setdefault(tid, []).append(st)

    lines: list[str] = []
    flow_title = getattr(flow, "title", "Untitled Flow") or "Untitled Flow"
    lines.append(f"# {flow_title}")
    lines.append("")

    for task in tasks:
        task_title = getattr(task, "title", "Untitled Task") or "Untitled Task"
        task_input = getattr(task, "input", "") or ""
        task_result = getattr(task, "result", "") or ""
        task_status = getattr(task, "status", "finished")
        emoji = status_emoji(task_status)

        lines.append(f"## {emoji} {task_title}")
        lines.append("")

        if task_input:
            lines.append("**Input:**")
            lines.append("```")
            lines.append(task_input)
            lines.append("```")
            lines.append("")

        if task_result:
            lines.append("**Result:**")
            lines.append(task_result)
            lines.append("")

        # Add subtasks for this task
        task_id = getattr(task, "id", 0) or 0
        task_subtasks = subtask_map.get(task_id, [])
        for st in task_subtasks:
            st_title = getattr(st, "title", "Untitled Subtask") or "Untitled Subtask"
            st_desc = getattr(st, "description", "") or ""
            st_result = getattr(st, "result", "") or ""
            st_status = getattr(st, "status", "finished")
            st_emoji = status_emoji(st_status)

            lines.append(f"### {st_emoji} {st_title}")
            lines.append("")

            if st_desc:
                lines.append(st_desc)
                lines.append("")

            if st_result:
                lines.append(f"> {st_result}")
                lines.append("")

    return "\n".join(lines)

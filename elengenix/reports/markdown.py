"""elengenix.reports.markdown — Markdown report assembly from flow/task/subtask data.

This module is the canonical source for the report markdown that the
``elengenix.reports.export`` / ``elengenix.reports.pdf`` pipelines consume.
It implements:

* ``DEFAULT_STATUS_EMOJI`` — the **string** glyph used when a status is
  unknown / unrecognised (``"📝"``).
* ``STATUS_EMOJI_MAP`` — explicit status → emoji mapping for known statuses.
* ``status_emoji`` — case-insensitive lookup with a safe default.
* ``slugify_github`` — GitHub-slugger-compatible anchor slug (ASCII only).
* ``generate_anchors`` — batch anchor generation with -1, -2, … suffixes for
  duplicate headings (dict-overwrite semantics: last occurrence wins).
* ``shift_markdown_headers`` — header-level shifter capped at H6.
* ``generate_report_markdown`` — full report assembler with H1 title, TOC,
  H3 task sections, H4 subtask sections, and +3-level shifted task input.

No ``yaml.load`` / ``eval`` / ``exec`` is used anywhere in this module.
"""
from __future__ import annotations

import re
from typing import Any, Sequence

# ---------------------------------------------------------------------------
# Status emoji configuration
# ---------------------------------------------------------------------------

#: The default emoji used for unknown / None / unrecognised statuses.
#: It is a *string* (not a dict) so callers can use it directly without a
#: lookup. The brutal test contract asserts ``DEFAULT_STATUS_EMOJI == "📝"``.
DEFAULT_STATUS_EMOJI: str = "📝"

#: Explicit mapping of known status → emoji glyph. Statuses not present in
#: this map fall back to :data:`DEFAULT_STATUS_EMOJI`.
#:
#: The exact glyphs are dictated by the brutal test contract
#: (``test_generate_report_markdown_status_emojis``) — note that ``created``
#: maps to ``📝`` (not ``🆕``) and ``running`` maps to ``⚡`` (not ``🔄``) so
#: the documented behaviour matches what the test-suite asserts.
STATUS_EMOJI_MAP: dict[str, str] = {
    "finished": "✅",
    "running": "⚡",
    "pending": "⏳",
    "failed": "❌",
    "cancelled": "🚫",
    "created": "📝",
    "waiting": "⏳",
    "todo": "📋",
}


def status_emoji(status: Any) -> str:
    """Return the emoji glyph for ``status`` (case-insensitive).

    Unknown / None / empty statuses fall back to :data:`DEFAULT_STATUS_EMOJI`.
    """
    key = str(status).lower() if status else ""
    return STATUS_EMOJI_MAP.get(key, DEFAULT_STATUS_EMOJI)


# ---------------------------------------------------------------------------
# Slug + anchor helpers
# ---------------------------------------------------------------------------

#: Regex used to strip non-word characters from a slug. The ``re.ASCII`` flag
#: is critical: it restricts ``\w`` to ``[a-zA-Z0-9_]`` so non-ASCII glyphs
#: (CJK characters, emoji, accented letters like ``é``) are dropped instead
#: of being kept by Python's default Unicode-aware ``\w`` behaviour.
_NON_WORD_RE = re.compile(r"[^\w\s-]", flags=re.ASCII)
_WHITESPACE_RE = re.compile(r"[\s_]+")
_DASH_RE = re.compile(r"-+")


def slugify_github(text: str) -> str:
    """GitHub-compatible anchor slug.

    Algorithm (mirrors ``github-slugger``):

    1. lowercase + strip surrounding whitespace
    2. drop any char that is not an ASCII word char, whitespace, or hyphen
       (this removes emoji, CJK, and accented letters)
    3. collapse runs of whitespace / underscores into a single ``-``
    4. collapse runs of hyphens
    5. trim leading / trailing hyphens
    """
    slug = text.lower().strip()
    slug = _NON_WORD_RE.sub("", slug)
    slug = _WHITESPACE_RE.sub("-", slug)
    slug = _DASH_RE.sub("-", slug)
    slug = slug.strip("-")
    return slug


def generate_anchors(titles: list[str]) -> dict[str, str]:
    """Generate GitHub-style markdown anchors for a list of titles.

    Returns a dict mapping ``title → anchor`` (anchor has no leading ``#`` —
    callers add it themselves when emitting markdown links).

    Duplicate titles are disambiguated by appending ``-1``, ``-2``, … to the
    *subsequent* occurrences' anchors. Because the returned dict maps the
    raw title string to its anchor, dict-overwrite semantics mean the **last**
    occurrence's anchor wins for duplicate titles — e.g.::

        generate_anchors(["Intro", "Intro", "Intro", "Outro"])
        # → {"Intro": "intro-2", "Outro": "outro"}
    """
    anchors: dict[str, str] = {}
    seen: dict[str, int] = {}  # slug → count of occurrences so far
    for title in titles:
        slug = slugify_github(title)
        if slug in seen:
            seen[slug] += 1
            anchor = f"{slug}-{seen[slug]}"
        else:
            seen[slug] = 0
            anchor = slug
        anchors[title] = anchor  # last occurrence wins (dict overwrite)
    return anchors


# ---------------------------------------------------------------------------
# Header shifting
# ---------------------------------------------------------------------------

#: Regex matching an ATX header line (1–6 ``#`` followed by whitespace).
_HEADER_RE = re.compile(r"^(#{1,6})\s")


def shift_markdown_headers(md: str, levels: int = 1) -> str:
    """Shift every ATX header in ``md`` down by ``levels`` positions.

    ``#`` becomes ``##`` (for ``levels=1``), ``##`` becomes ``#####`` (for
    ``levels=3``), etc. The result is **capped at H6** (the maximum ATX
    level) — so shifting H1 by 6 produces H6, not H7.

    Non-header lines are left untouched. ``levels <= 0`` returns ``md``
    unchanged.
    """
    if levels <= 0 or not md:
        return md
    shifted_lines: list[str] = []
    for line in md.split("\n"):
        m = _HEADER_RE.match(line)
        if m:
            current_level = len(m.group(1))
            new_level = min(current_level + levels, 6)
            # Reuse everything after the original ``#``-run.
            rest = line[current_level:]
            shifted_lines.append("#" * new_level + rest)
        else:
            shifted_lines.append(line)
    return "\n".join(shifted_lines)


# ---------------------------------------------------------------------------
# Full report assembly
# ---------------------------------------------------------------------------

def generate_report_markdown(
    flow: Any,
    tasks: Sequence[Any],
    subtasks: Sequence[Any] | None = None,
) -> str:
    """Assemble a full markdown report from a flow, its tasks, and subtasks.

    Structure::

        # {flow.title}

        ## Table of Contents

        - [{task1.title}](#{anchor1})
        - [{task2.title}](#{anchor2})

        ---

        ### {emoji1} {task1.title}

        {shift_markdown_headers(task1.input, 3)}

        **Result:**
        {task1.result}

        #### {emoji} {subtask.title}

        {subtask.description}

        > {subtask.result}

    If ``tasks`` is empty, the function short-circuits and returns the
    canonical ``"# {flow.title}\\n\\nNo tasks available.\\n"`` payload.
    """
    subtasks = subtasks or []
    flow_title = getattr(flow, "title", "Untitled Flow") or "Untitled Flow"

    # Empty-tasks short-circuit (canonical "No tasks available" payload).
    if not tasks:
        return f"# {flow_title}\n\nNo tasks available.\n"

    # Group subtasks by their parent task_id for O(1) lookup per task.
    subtask_map: dict[int, list[Any]] = {}
    for st in subtasks:
        tid = getattr(st, "task_id", None) or 0
        subtask_map.setdefault(tid, []).append(st)

    # Pre-compute anchors for every task title (handles duplicates).
    task_titles = [getattr(t, "title", "") or "" for t in tasks]
    anchors = generate_anchors(task_titles)

    lines: list[str] = []

    # 1. Flow title (H1).
    lines.append(f"# {flow_title}")
    lines.append("")

    # 2. Table of Contents with one bullet link per task.
    lines.append("## Table of Contents")
    lines.append("")
    for task in tasks:
        t_title = getattr(task, "title", "") or ""
        anchor = anchors.get(t_title, slugify_github(t_title))
        lines.append(f"- [{t_title}](#{anchor})")
    lines.append("")

    # 3. Separator between TOC and body.
    lines.append("---")
    lines.append("")

    # 4. Task sections (H3) + nested subtask sections (H4).
    for task in tasks:
        task_title = getattr(task, "title", "Untitled Task") or "Untitled Task"
        task_input = getattr(task, "input", "") or ""
        task_result = getattr(task, "result", "") or ""
        task_status = getattr(task, "status", "finished")
        emoji = status_emoji(task_status)

        lines.append(f"### {emoji} {task_title}")
        lines.append("")

        if task_input:
            # Shift task input headers by +3 so an H1 inside the input
            # slots underneath the H3 task title (H1 + 3 = H4).
            shifted_input = shift_markdown_headers(task_input, 3)
            lines.append(shifted_input)
            lines.append("")

        if task_result:
            lines.append("**Result:**")
            lines.append(task_result)
            lines.append("")

        # Subtasks for this task (H4).
        task_id = getattr(task, "id", 0) or 0
        task_subtasks = subtask_map.get(task_id, [])
        for st in task_subtasks:
            st_title = getattr(st, "title", "Untitled Subtask") or "Untitled Subtask"
            st_desc = getattr(st, "description", "") or ""
            st_result = getattr(st, "result", "") or ""
            st_status = getattr(st, "status", "finished")
            st_emoji = status_emoji(st_status)

            lines.append(f"#### {st_emoji} {st_title}")
            lines.append("")

            if st_desc:
                lines.append(st_desc)
                lines.append("")

            if st_result:
                lines.append(f"> {st_result}")
                lines.append("")

    return "\n".join(lines)

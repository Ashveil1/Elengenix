"""Regression guard for the prompt-interpolation bug class.

Background
----------
A refactor stripped the ``f`` prefix from many prompt templates, leaving plain
triple-quoted strings such as ``'Target: {target}'`` (inside triple quotes)
that were sent verbatim to the LLM.  The model received the literal text
``{target}`` / ``{self.base_prompt}`` instead of the interpolated values,
crippling the agent in its primary paths (including the default TUI loop).
20 such bugs were fixed by converting the templates to f-strings.

This test re-detects that exact bug pattern in the files that were fixed, so a
future edit cannot silently reintroduce it. The detector flags an assignment to a
triple-quoted string that:

  * is NOT an f-string (no ``f``/``rf``/``fr`` prefix), AND
  * contains a ``{identifier...}`` placeholder (single brace, identifier-start), AND
  * is NOT consumed by a nearby ``.format(`` call.

Legitimate ``.format()`` templates and data strings whose braces start with a
non-identifier character (e.g. ``{"target": "domain.com"}``) are intentionally
NOT flagged.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Files that were converted from broken plain strings to f-strings in Phase 1.
FIXED_FILES = [
    "core/brain.py",
    "agents/agent_universal.py",
    "agents/agent_conversation.py",
    "agents/agent_planner.py",
    "tools/cvss_calculator.py",
    "tools/memory_profile.py",
    "tools/multi_agent.py",
    "tools/autonomous_agent.py",
    "tools/ai_tool_creator.py",
]

# `name = """` or `user="""` (and the single-quote triple variant), capturing any
# prefix letters immediately before the quotes so we can tell f-strings apart.
_ASSIGN_RE = re.compile(r'([A-Za-z_]\w*)\s*=\s*([A-Za-z]*)("{3}|\'{3})')

# A placeholder must start with an identifier char right after `{` -- this skips
# JSON data like {"target": ...} while still catching {target}, {self.x}, {a.b[0]}.
_PLACEHOLDER_RE = re.compile(r"\{[A-Za-z_][\w\.\[\]\(\)'\" +]*\}")


def _find_uninterpolated_templates(text: str):
    """Return a list of (line_no, var_name) for plain templates with placeholders."""
    hits = []
    for m in _ASSIGN_RE.finditer(text):
        var_name, prefix, quote = m.group(1), m.group(2), m.group(3)
        is_fstring = prefix.lower() in ("f", "rf", "fr", "rb", "fb")
        if is_fstring:
            continue
        body_start = m.end(3)
        body_end = text.find(quote, body_start)
        if body_end == -1:
            continue
        body = text[body_start:body_end]
        if not _PLACEHOLDER_RE.search(body):
            continue
        # Doubled braces are escaped literals, not placeholders -- strip them and
        # re-check so a pure {{...}} example block isn't flagged.
        stripped = body.replace("{{", "").replace("}}", "")
        if not _PLACEHOLDER_RE.search(stripped):
            continue
        # Allow legitimate .format() templates: a .format( within ~200 chars.
        trailing = text[body_end : body_end + 200]
        if ".format(" in trailing:
            continue
        line_no = text[: m.start()].count("\n") + 1
        hits.append((line_no, var_name))
    return hits


@pytest.mark.parametrize("rel_path", FIXED_FILES)
def test_no_uninterpolated_prompt_templates(rel_path):
    """Every prompt template in a fixed file must be an f-string or a .format() template."""
    path = PROJECT_ROOT / rel_path
    assert path.exists(), f"expected fixed file missing: {rel_path}"
    text = path.read_text(encoding="utf-8")
    hits = _find_uninterpolated_templates(text)
    assert not hits, (
        f"{rel_path}: found plain (non-f) prompt template(s) with un-interpolated "
        f"placeholders -- the prompt-interpolation bug has regressed at: "
        + ", ".join(f"line {ln} (var '{name}')" for ln, name in hits)
    )


def test_detector_catches_the_original_bug():
    """Sanity-check: the detector must flag the original broken pattern and pass a fixed one."""
    broken = 'prompt = """Target: {target}\nObjective: {objective}"""\n'
    fixed = 'prompt = f"""Target: {target}\nObjective: {objective}"""\n'
    fmt_template = 'PLAN = """Target: {target}"""\nx = PLAN.format(target="a")\n'
    data_string = 'actions = """Params: {"target": "domain.com"}"""\n'

    assert _find_uninterpolated_templates(broken), "detector should flag the broken pattern"
    assert not _find_uninterpolated_templates(fixed), "detector must not flag f-strings"
    assert not _find_uninterpolated_templates(
        fmt_template
    ), "detector must not flag .format templates"
    assert not _find_uninterpolated_templates(
        data_string
    ), "detector must not flag JSON data strings"

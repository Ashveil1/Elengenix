# `elengenix.reports` — Current Implementation Reference

This document catalogs every function signature in the `elengenix.reports`
subsystem, located at `/home/z/my-project/elengenix-ci-fix/elengenix/reports/`.

For each function we capture: name, parameters (with type + default), return
type, and a brief description of current behavior. Module-level constants and
dataclass / enum definitions are listed at the end of each section for
completeness.

---

## 1. `elengenix/reports/__init__.py`

**Purpose:** Package marker with a module-level docstring describing the
subsystem (cvss, markdown, pdf, export, templates).

**Functions:** None.

**Exports:** None explicitly defined (submodules must be imported directly,
e.g. `from elengenix.reports import cvss`).

---

## 2. `elengenix/reports/cvss.py`

**Purpose:** CVSS v3.1 vector parsing, base-score calculation, and severity
labeling per the FIRST.org specification.

### Functions

#### `parse_cvss_vector(vector_string: str) -> CVSSVector`
- **Parameters:**
  - `vector_string: str` — required, no default.
- **Return type:** `CVSSVector`
- **Behavior:** Parses a CVSS v3.1 vector string (accepts both
  `CVSS:3.1/AV:N/...` and bare `AV:N/...` forms, also tolerates `CVSS:3.0/`).
  Splits on `/`, then `:`. Missing metrics fall back to defaults (`AV:N`,
  `AC:L`, `PR:N`, `UI:N`, `S:U`, `C:N`, `I:N`, `A:N`). Raises `ValueError`
  for empty strings or unrecognized metric values (caught `KeyError`).

#### `format_cvss_vector(v: CVSSVector) -> str`
- **Parameters:**
  - `v: CVSSVector` — required.
- **Return type:** `str`
- **Behavior:** Serializes a `CVSSVector` to the canonical
  `CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...` string using
  reverse-lookup tables (`_AV_REV`, `_AC_REV`, etc.).

#### `calculate_cvss_score(v: CVSSVector) -> float`
- **Parameters:**
  - `v: CVSSVector` — required.
- **Return type:** `float`
- **Behavior:** Computes the CVSS v3.1 base score:
  1. ISC base = `1 - (1-c)(1-i)(1-a)` using `_IMPACT_WEIGHTS`.
  2. Impact: `7.52*(isc-0.029) - 3.25*(isc-0.02)^15` for Changed scope,
     `6.42*isc` for Unchanged.
  3. Exploitability: `8.22 * AV * AC * PR * UI` (PR weight chosen by scope).
  4. Returns `0.0` if impact ≤ 0; else `min(1.08*(impact+expl), 10)` for
     Changed scope, `min(impact+expl, 10)` for Unchanged.
  Result is rounded UP to 1 decimal via `math.ceil(score*10)/10.0`.

#### `cvss_severity(score: float) -> str`
- **Parameters:**
  - `score: float` — required.
- **Return type:** `str`
- **Behavior:** Maps score to label per FIRST.org:
  - `0.0` → `"Info"`
  - `< 4.0` → `"Low"`
  - `< 7.0` → `"Medium"`
  - `< 9.0` → `"High"`
  - `≥ 9.0` → `"Critical"`

#### `cvss_result(v: CVSSVector) -> CVSSResult`
- **Parameters:**
  - `v: CVSSVector` — required.
- **Return type:** `CVSSResult`
- **Behavior:** Recomputes subscores (impact, exploitability) inline, then
  delegates to `calculate_cvss_score` for the base score and
  `cvss_severity` for the label, and `format_cvss_vector` for the string.
  Returns a populated `CVSSResult` dataclass. Note: this duplicates the
  subscore math from `calculate_cvss_score` rather than reusing it.

### Module-level definitions

- **Enums** (all `str, Enum`):
  - `AttackVector` — `NETWORK="N"`, `ADJACENT="A"`, `LOCAL="L"`, `PHYSICAL="P"`
  - `AttackComplexity` — `LOW="L"`, `HIGH="H"`
  - `PrivilegesRequired` — `NONE="N"`, `LOW="L"`, `HIGH="H"`
  - `UserInteraction` — `NONE="N"`, `REQUIRED="R"`
  - `Scope` — `UNCHANGED="U"`, `CHANGED="C"`
  - `CIAImpact` — `NONE="N"`, `LOW="L"`, `MEDIUM="L"` (alias, duplicates LOW
    value — potential bug), `HIGH="H"`

- **Dataclasses:**
  - `CVSSVector` — all 8 base metrics with defaults (Network/Low/None/None/
    Unchanged/None/None/None).
  - `CVSSResult` — `base_score: float`, `severity: str`, `vector_string: str`,
    `impact_subscore: float`, `exploitability_subscore: float`.

- **Lookup tables (private):** `_AV_VALUES`, `_AC_VALUES`, `_PR_VALUES`,
  `_UI_VALUES`, `_S_VALUES`, `_CIA_VALUES` and reverse maps `_AV_REV`,
  `_AC_REV`, `_PR_REV`, `_UI_REV`, `_S_REV`, `_CIA_REV`.
- **Weight tables (private):** `_IMPACT_WEIGHTS`, `_EXPLOITABILITY_WEIGHTS`,
  `_AC_WEIGHTS`, `_UI_WEIGHTS`, `_PR_WEIGHTS_SAME`, `_PR_WEIGHTS_CHANGED`.

---

## 3. `elengenix/reports/markdown.py`

**Purpose:** Markdown report assembly from flow/task/subtask data, plus
heading-anchor and header-shift helpers.

### Functions

#### `status_emoji(status: Any) -> str`
- **Parameters:**
  - `status: Any` — required; coerced via `str(...).lower()`.
- **Return type:** `str`
- **Behavior:** Returns the emoji for a status value using
  `DEFAULT_STATUS_EMOJI` (case-insensitive lookup). Falls back to `"📋"`
  for unknown or falsy status.

#### `slugify_github(text: str) -> str`
- **Parameters:**
  - `text: str` — required.
- **Return type:** `str`
- **Behavior:** Lowercases, strips non-`[\w\s-]` characters, collapses
  whitespace/underscores to single hyphens, strips leading/trailing hyphens.

#### `generate_anchors(title: str) -> str`
- **Parameters:**
  - `title: str` — required.
- **Return type:** `str`
- **Behavior:** Returns `"#" + slugify_github(title)` for use as a
  GitHub-style markdown heading anchor.

#### `shift_markdown_headers(md: str, levels: int = 1) -> str`
- **Parameters:**
  - `md: str` — required.
  - `levels: int = 1` — number of `#` to prepend to each heading.
- **Return type:** `str`
- **Behavior:** If `levels <= 0`, returns `md` unchanged. Otherwise prepends
  `levels` `#` characters to every line matching `^#{1,6}\s`. Does NOT
  cap at 6 levels, so shifting can produce `#######` headings.

#### `generate_report_markdown(flow: Any, tasks: Sequence[Any], subtasks: Sequence[Any] | None = None) -> str`
- **Parameters:**
  - `flow: Any` — required; expects `.title`.
  - `tasks: Sequence[Any]` — required; each expects `.title`, `.input`,
    `.result`, `.status`, `.id`.
  - `subtasks: Sequence[Any] | None = None` — optional; each expects
    `.task_id`, `.title`, `.description`, `.result`, `.status`.
- **Return type:** `str`
- **Behavior:** Builds a markdown report:
  1. Groups subtasks by `task_id` into `subtask_map`.
  2. Emits `# {flow.title}` (defaults to "Untitled Flow").
  3. For each task: `## {emoji} {title}`, optional `**Input:**` fenced
     block, optional `**Result:**` paragraph.
  4. For each subtask belonging to that task (matched by `task.id`):
     `### {emoji} {title}`, optional description, optional `> {result}`
     blockquote.

### Module-level constants

- `DEFAULT_STATUS_EMOJI: dict[str, str]` — maps status → emoji:
  finished ✅, running 🔄, pending ⏳, failed ❌, cancelled 🚫, todo 📋.

---

## 4. `elengenix/reports/pdf.py`

**Purpose:** Minimal dependency-free PDF generator that renders markdown
content to a single-page PDF 1.4 document.

### Functions

#### `substitute_emojis(text: str) -> str`
- **Parameters:**
  - `text: str` — required.
- **Return type:** `str`
- **Behavior:** Replaces each emoji in `EMOJI_SUBSTITUTIONS` with its
  ASCII placeholder (e.g. `✅` → `[OK]`). Note: the dict has a duplicate
  key `🔧` appearing twice — the second value `[CONFIG]` silently
  overwrites the first `[TOOL]`.

#### `split_by_cjk(text: str) -> list[str]`
- **Parameters:**
  - `text: str` — required.
- **Return type:** `list[str]`
- **Behavior:** Splits text into runs at CJK/Latin boundaries. CJK ranges
  detected: U+4E00–U+9FFF, U+3400–U+4DBF, U+3040–U+30FF (Japanese),
  U+AC00–U+D7AF (Korean). Each contiguous same-script run becomes one
  segment. NOTE: this function is defined but NEVER CALLED by
  `render_to_pdf_bytes` — dead code / unused feature.

#### `render_to_pdf_bytes(markdown: str) -> bytes`
- **Parameters:**
  - `markdown: str` — required.
- **Return type:** `bytes`
- **Behavior:**
  1. Strips markdown formatting per line (headers `^#{1,6}\s+`, bold
     `**..**`, italic `*..*`, inline code `` `..` ``, blockquote `^>\s+`)
     and runs `substitute_emojis`.
  2. Builds PDF text-show commands `BT /F1 10 Tf 72 {y} Td ({safe}) Tj ET`
     with y stepping from 750 down by 12 per line.
  3. Encodes content stream as latin-1 (replace on errors).
  4. Assembles a 5-object PDF: Catalog (1), Pages (2), Page (3) with
     MediaBox `[0 0 612 792]`, content stream (4), Helvetica font (5).
  5. Appends xref table (`0 6` entries), trailer, `startxref`, `%%EOF`.
  Limitations: single page only, no wrapping (lines beyond ~62 will run
  off the page bottom), no font for CJK, no heading-size variation despite
  `HEADING_FONT_SIZES` being defined.

### Module-level constants

- `HEADING_FONT_SIZES: dict[int, float]` — H1 24pt … H6 11pt (defined but
  UNUSED by `render_to_pdf_bytes`).
- `EMOJI_SUBSTITUTIONS: dict[str, str]` — ~30 emoji → ASCII placeholders.
  Contains a duplicate `🔧` key (`[TOOL]` overwritten by `[CONFIG]`).

---

## 5. `elengenix/reports/export.py`

**Purpose:** Multi-format report export dispatcher (md, pdf, html, json)
built on top of `markdown.generate_report_markdown` and
`pdf.render_to_pdf_bytes`.

### Functions

#### `_slugify_title(title: str) -> str` *(private)*
- **Parameters:**
  - `title: str` — required.
- **Return type:** `str`
- **Behavior:** Thin wrapper around `slugify_github(title)` (re-exported
  from `markdown`).

#### `generate_filename(title: str, fmt: str) -> str`
- **Parameters:**
  - `title: str` — required.
  - `fmt: str` — required (e.g. `"md"`, `"pdf"`).
- **Return type:** `str`
- **Behavior:** Returns `f"{slugify_github(title)}.{fmt}"`. Does NOT
  validate `fmt` against `SUPPORTED_FORMATS` and does NOT strip a leading
  dot from `fmt` (caller responsibility).

#### `render_html(markdown: str) -> str`
- **Parameters:**
  - `markdown: str` — required.
- **Return type:** `str`
- **Behavior:** Minimal markdown → HTML converter. Handles:
  - Fenced code blocks ``` ``` ``` toggling `<pre><code>`.
  - `# `/`## `/`### ` → `<h1>`/`<h2>`/`<h3>`.
  - `> ` → `<blockquote>`.
  - `- ` → `<li>` (no wrapping `<ul>`).
  - Inline `**bold**`, `*italic*`, `` `code` `` substitutions.
  - Empty lines → `<br>`.
  - Wraps output in `<!DOCTYPE html><html>...<body>...</body></html>`.
  Limitations: no H4–H6, no nested lists, no table support, list items
  not wrapped in `<ul>`.

#### `export_report(flow: Any, tasks: Sequence[Any], subtasks: Sequence[Any] | None = None, fmt: str = "md") -> bytes`
- **Parameters:**
  - `flow: Any` — required; expects `.id`, `.title`, `.status`.
  - `tasks: Sequence[Any]` — required; each expects `.id`, `.title`,
    `.input`, `.result`, `.status`.
  - `subtasks: Sequence[Any] | None = None` — optional; each expects
    `.id`, `.title`, `.description`, `.result`, `.status`, `.task_id`.
  - `fmt: str = "md"` — output format; lowercased and leading-dot-stripped.
- **Return type:** `bytes`
- **Behavior:** Validates `fmt` against `SUPPORTED_FORMATS` (raises
  `ValueError` otherwise). Always generates the base markdown first via
  `generate_report_markdown`. Then dispatches:
  - `"md"` → UTF-8 encoded markdown bytes.
  - `"pdf"` → `render_to_pdf_bytes(md)`.
  - `"html"` → `render_html(md).encode("utf-8")`.
  - `"json"` → Structured dict with `flow`, `tasks`, `subtasks` keys
    (each field accessed defensively via `getattr(obj, name, default)`),
    serialized with `json.dumps(..., indent=2, ensure_ascii=False)` and
    UTF-8 encoded.

### Module-level constants

- `SUPPORTED_FORMATS = ("md", "pdf", "html", "json")`.

---

## 6. `elengenix/reports/templates.py`

**Purpose:** Jinja2-compatible template strings (rendered via `str.format`)
for executive summaries, technical reports, vulnerability reports, and
compliance reports.

### Functions

#### `render_template(template: str, **kwargs: Any) -> str`
- **Parameters:**
  - `template: str` — required, positional.
  - `**kwargs: Any` — arbitrary keyword substitutions.
- **Return type:** `str`
- **Behavior:** First attempts `template.format(**kwargs)`. If a `KeyError`
  is raised (missing key), falls back to a safe partial render: iterates
  over `kwargs` and does `template.replace("{" + key + "}", str(value))`
  for each. Missing placeholders remain literally in the output. Note:
  the fallback does NOT handle format-spec placeholders like `{score:.1f}`
  — those will trigger `KeyError` only if the key is missing, but if the
  key IS present the initial `format()` call handles spec correctly.

### Module-level template strings

- `EXECUTIVE_SUMMARY_TEMPLATE` — placeholders: `title`, `overview`,
  `findings`, `recommendations`, `risk_assessment`.
- `TECHNICAL_REPORT_TEMPLATE` — placeholders: `title`, `scope`,
  `methodology`, `findings`, `technical_details`, `remediation`.
- `VULNERABILITY_TEMPLATE` — placeholders: `title`, `cvss_score`,
  `severity`, `cvss_vector`, `description`, `affected`, `poc`,
  `remediation`, `references`.
- `COMPLIANCE_REPORT_TEMPLATE` — placeholders: `title`, `status`,
  `controls`, `findings`, `gap_analysis`, `remediation_plan`.

---

## Summary of all function signatures

| File | Function | Signature |
|------|----------|-----------|
| cvss.py | `parse_cvss_vector` | `(vector_string: str) -> CVSSVector` |
| cvss.py | `format_cvss_vector` | `(v: CVSSVector) -> str` |
| cvss.py | `calculate_cvss_score` | `(v: CVSSVector) -> float` |
| cvss.py | `cvss_severity` | `(score: float) -> str` |
| cvss.py | `cvss_result` | `(v: CVSSVector) -> CVSSResult` |
| markdown.py | `status_emoji` | `(status: Any) -> str` |
| markdown.py | `slugify_github` | `(text: str) -> str` |
| markdown.py | `generate_anchors` | `(title: str) -> str` |
| markdown.py | `shift_markdown_headers` | `(md: str, levels: int = 1) -> str` |
| markdown.py | `generate_report_markdown` | `(flow: Any, tasks: Sequence[Any], subtasks: Sequence[Any] \| None = None) -> str` |
| pdf.py | `substitute_emojis` | `(text: str) -> str` |
| pdf.py | `split_by_cjk` | `(text: str) -> list[str]` |
| pdf.py | `render_to_pdf_bytes` | `(markdown: str) -> bytes` |
| export.py | `_slugify_title` | `(title: str) -> str` |
| export.py | `generate_filename` | `(title: str, fmt: str) -> str` |
| export.py | `render_html` | `(markdown: str) -> str` |
| export.py | `export_report` | `(flow: Any, tasks: Sequence[Any], subtasks: Sequence[Any] \| None = None, fmt: str = "md") -> bytes` |
| templates.py | `render_template` | `(template: str, **kwargs: Any) -> str` |

**Total: 18 functions** (5 cvss + 5 markdown + 3 pdf + 4 export + 1 templates),
plus 6 enums, 2 dataclasses, and 4 template strings.

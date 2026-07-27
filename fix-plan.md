# Elengenix CI Fix Plan — Phase 2d

> **Repo:** `/home/z/my-project/elengenix-ci-fix` (branch `fix/async-pytest-v2`, HEAD `7784855`)
> **Goal:** Take the CI matrix (3.11 / 3.12 / 3.13 + `Run Tests` job) from
> **45 failed → 0 failed**.
> **Source-of-truth tests (do not modify):**
> `tests/brutal/test_integration_security_brutal.py` (44 tests) +
> `tests/brutal/test_agents_brutal.py` (1 test).
> **Source-of-truth analysis:** `ci-failures.md` (Phase 1) and `local-test-results.md` (Phase 2).

---

## 0. Summary table

| # | Category | Tests | Fix type | File(s) to modify |
|---|----------|-------|----------|--------------------|
| 1 | Missing dep `fastapi` | 3 | **CI fix** | `pyproject.toml`, `.github/workflows/ci.yml`, `.github/workflows/test.yml` |
| 2 | Missing dep `pyjwt` | 4 | **CI fix** | `pyproject.toml`, `.github/workflows/ci.yml`, `.github/workflows/test.yml` |
| 3 | `export_report` signature | 8 | **Code fix** | `elengenix/reports/export.py` |
| 4 | `render_html` signature | 5 | **Code fix** | `elengenix/reports/export.py` |
| 5 | `generate_filename` arity | 2 | **Code fix** | `elengenix/reports/export.py` |
| 6 | `render_template` arity | 1 | **Code fix** | `elengenix/reports/templates.py` |
| 7 | `CVSSVector` field aliases | 1 | **Code fix** | `elengenix/reports/cvss.py` |
| 8 | `parse_cvss_vector` validation | 1 | **Code fix** | `elengenix/reports/cvss.py` |
| 9 | Markdown behavior (TOC/slug/emoji/empty/anchors) | 8 | **Code fix** | `elengenix/reports/markdown.py` (+ `export.py` for `generate_anchors` use) |
| 10 | PDF rendering + `split_by_cjk` | 4 + 3 | **Code fix + CI fix** | `elengenix/reports/pdf.py`, `pyproject.toml` (add `reportlab`) |
| 11 | Template placeholders | 4 | **Code fix** | `elengenix/reports/templates.py` |
| 12 | Async event loop | 1 | **CI fix (test infra)** | `tests/brutal/conftest.py` (or `tests/conftest.py`) |
|   | **Total** | **45** | | |

Fixes are independent and can be applied in any order. Recommended execution order:
**1 → 2 → 10(pip) → 12 → 3 → 4 → 5 → 6 → 7 → 8 → 11 → 9 → 10(code)**.

---

## 1. Missing dependency — `fastapi` (3 tests)

**Fix type:** CI fix (add to deps + workflows).

**Tests fixed:**
- `TestEndToEndIntegration::test_rest_api_plus_flow_integration_post_flows_route_exists`
- `TestEndToEndIntegration::test_rest_api_plus_flow_integration_post_input_route_exists`
- `TestEndToEndIntegration::test_rest_api_plus_flow_integration_get_report_route_exists`

**Root cause:** `elengenix/api/app.py::create_app()` lazy-imports `fastapi`; `pyproject.toml [project.dependencies]` doesn't list it and the CI `pip install` line doesn't add it. Collection succeeds (the `elengenix.api.routes.flows.router` is constructable without FastAPI at import time only if FastAPI is installed; otherwise the route module import itself fails inside the test).

**File 1 — `pyproject.toml`:**
Add to `[project.dependencies]` (alphabetical inside the "Core" block is fine):
```toml
    "fastapi>=0.110.0",
    "uvicorn[standard]>=0.27.0",
```

**File 2 — `.github/workflows/ci.yml` (line 30):**
```diff
-          pip install pytest pytest-asyncio pytest-timeout rich itsdangerous strawberry-graphql
+          pip install pytest pytest-asyncio pytest-timeout rich itsdangerous strawberry-graphql fastapi "uvicorn[standard]" pyjwt reportlab
```

**File 3 — `.github/workflows/test.yml` (line 28):** identical change.

**Alternative (cleaner):** add an `[project.optional-dependencies].brutal` extra and `pip install -e .[brutal]` in CI; but adding to the install line is the lowest-risk one-liner.

---

## 2. Missing dependency — `pyjwt` (4 tests)

**Fix type:** CI fix (add to deps + workflows).

**Tests fixed:**
- `TestEndToEndIntegration::test_auth_api_integration_bearer_token_validates`
- `TestSecurity::test_jwt_alg_none_attack_blocked`
- `TestSecurity::test_jwt_expired_token_rejected`
- `TestSecurity::test_jwt_tampered_signature_rejected`

**Root cause:** `elengenix/auth/tokens.py` does a guarded `import jwt` and raises a friendly `ImportError`. `pyjwt` is not in `pyproject.toml` deps nor installed in CI.

**File 1 — `pyproject.toml`:**
Add to `[project.dependencies]`:
```toml
    "pyjwt>=2.8.0",
```

**File 2 & 3 — `.github/workflows/ci.yml` and `test.yml`:**
Already covered by the install-line change in category 1 (the new install line includes `pyjwt`).

**Notes:**
- Do **not** confuse `pyjwt` (the `jwt` module) with `python-jose` — the brutal tests use plain `jwt.encode/decode`, so `pyjwt` is correct.
- The existing `elengenix/auth/tokens.py` guard can stay as a defense-in-depth, but with `pyjwt` installed it will no longer raise.

---

## 3. `export_report` signature (8 tests)

**Fix type:** Code fix.

**Tests fixed (8):**
- `TestEndToEndIntegration::test_report_generation_multi_format_export`
- `TestReports::test_export_report_markdown_format`
- `TestReports::test_export_report_html_format`
- `TestReports::test_export_report_json_format`
- `TestReports::test_export_report_pdf_format`
- `TestReports::test_report_export_unsupported_format_raises_value_error`
- `TestStressPerformance::test_reports_export_markdown_under_1s_for_100_tasks`
- `TestStressPerformance::test_reports_export_json_under_1s_for_100_tasks`

**File:** `elengenix/reports/export.py`

**Current signature (line 69-74):**
```python
def export_report(
    flow: Any,
    tasks: Sequence[Any],
    subtasks: Sequence[Any] | None = None,
    fmt: str = "md",
) -> bytes:
```

**Call sites (all in the brutal suite):**
```python
data = await export_report(11, fmt, provider=_Provider())       # fmt ∈ SUPPORTED_FORMATS
data = await export_report(1, "markdown", provider=_P())
data = await export_report(1, "html",    provider=_P())
data = await export_report(1, "json",    provider=_P())
data = await export_report(1, "pdf",     provider=_P())
await export_report(1, "docx", provider=_P())                    # must raise ValueError
```
where each `_P()` exposes async methods `get_flow(flow_id)`, `list_tasks(flow_id)`, `list_subtasks(task_id)`.

**New signature (must be `async`):**
```python
async def export_report(
    flow_id: int,
    fmt: str = "md",
    *,
    provider: Any = None,
) -> bytes:
```

**Behavior:**
1. Normalize `fmt`: accept both abbreviations and full names —
   `_FMT_ALIASES = {"md": "md", "markdown": "md", "html": "html", "htm": "html",
                    "pdf": "pdf", "json": "json"}`.
   If `fmt.lower().lstrip(".")` is not in `_FMT_ALIASES` → `raise ValueError(f"Unsupported format: {fmt}")`.
2. If `provider is None` → `raise ValueError("export_report requires a provider with get_flow/list_tasks/list_subtasks")`.
3. `flow = await provider.get_flow(flow_id)`
4. `tasks = await provider.list_tasks(flow_id)`
5. Collect subtasks: `subtasks = []`; for each `t` in tasks, `subtasks.extend(await provider.list_subtasks(getattr(t, "id", None)))`.
6. Generate base markdown via `generate_report_markdown(flow, tasks, subtasks)`.
7. Branch on canonical fmt:
   - `"md"` → `md.encode("utf-8")`
   - `"html"` → `render_html(md, include_css=False).encode("utf-8")`
   - `"pdf"` → `render_to_pdf_bytes(md)`
   - `"json"` → JSON-encode `{"flow": {...}, "tasks": [...], "subtasks": [...], "generated_at": datetime.now(timezone.utc).isoformat()}` with `ensure_ascii=False, indent=2` → `.encode("utf-8")`. **`generated_at` is asserted by the JSON test.**

**SUPPORTED_FORMATS:** keep the existing `("md", "pdf", "html", "json")` tuple — the multi-format test iterates over it.

---

## 4. `render_html` signature (5 tests)

**Fix type:** Code fix.

**Tests fixed (5):**
- `TestReports::test_report_render_html_with_pygments_highlight`
- `TestSecurity::test_xss_script_tag_in_input_is_escaped_in_html_export`
- `TestSecurity::test_xss_img_onerror_in_input_is_escaped_in_html_export`
- `TestSecurity::test_xss_javascript_url_in_markdown_link_is_not_active`
- `TestStressPerformance::test_stress_500_render_html_calls_under_3s`

**File:** `elengenix/reports/export.py`

**Current signature (line 25):**
```python
def render_html(markdown: str) -> str:
```

**New signature:**
```python
def render_html(markdown: str, include_css: bool = True) -> str:
```

**Required behaviors (from the brutal tests):**

1. **`include_css=True`** → emit a `<style>` block in `<head>` (assertion: `"<style>" in html`).
   Add e.g.:
   ```html
   <style>
     body { font-family: -apple-system, sans-serif; line-height: 1.5; padding: 2rem; }
     pre { background: #f4f4f4; padding: 1rem; overflow-x: auto; }
     code { font-family: monospace; }
     h1 { font-size: 1.6rem; } h2 { font-size: 1.3rem; } h3 { font-size: 1.1rem; }
   </style>
   ```

2. **HTML-escape raw HTML in markdown body** (XSS tests, `include_css=False`):
   - `<script>alert(1)</script>` → must NOT appear verbatim; `"<script>" not in html`.
   - `<img src=x onerror=alert(1)>` → must NOT appear; `"&lt;img" in html`.
   - `[click](javascript:alert(1))` → must NOT produce `<a href="javascript:alert(1)">`.
   Implementation: when emitting any non-code-block content, first HTML-escape `&`, `<`, `>` (`&amp;`, `&lt;`, `&gt;`), then apply inline markdown transforms (`**bold**`, `*italic*`, `` `code` ``, `[text](url)` links).
   For links, validate the URL scheme — only allow `http`, `https`, `mailto` and relative URLs; if the scheme is `javascript:`, `data:`, etc., emit the link text without an `<a>` tag (or escape the entire `[...](...)` form).
   Inside fenced code blocks (` ``` `), keep content raw but **also** HTML-escape `<` / `>` / `&` so `<script>` tags in code are shown literally, not interpreted.

3. **Performance:** 500 calls in <3 s — the current line-by-line regex approach already meets this; just don't add heavy deps (no `markdown-it-py` needed). If you do pull in `markdown-it-py`, profile first.

**Note:** the existing code at lines 28-66 is mostly salvageable — wrap the inline transforms in an HTML-escape step first, add the optional `<style>` block, and handle the link-scheme filter.

---

## 5. `generate_filename` arity (2 tests)

**Fix type:** Code fix.

**Tests fixed (2):**
- `TestReports::test_generate_filename_pattern`
- `TestReports::test_generate_filename_unknown_format_defaults_txt`

**File:** `elengenix/reports/export.py`

**Current signature (line 19):**
```python
def generate_filename(title: str, fmt: str) -> str:
    slug = _slugify_title(title)
    return f"{slug}.{fmt}"
```

**Call sites:**
```python
name = await generate_filename(42, "Pentest Report!", "pdf")
assert re.match(r"^report_flow_42_pentest_report_\d{14}\.pdf$", name)

name = await generate_filename(1, "title", "docx")
assert name.endswith(".txt")
```

**New signature (must be `async`):**
```python
async def generate_filename(flow_id: int, title: str, fmt: str) -> str:
```

**Behavior:**
1. `slug = _slugify_title(title)` (uses `slugify_github` → after category 9 fix this strips non-ASCII; for `"Pentest Report!"` → `"pentest_report"`).
2. Canonical extension: `_EXT_ALIASES = {"md": "md", "markdown": "md", "html": "html", "htm": "html", "pdf": "pdf", "json": "json"}`. Unknown formats → `"txt"`.
3. `timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")` (14 digits).
4. Return `f"report_flow_{flow_id}_{slug}_{timestamp}.{ext}"`.

**Verification:** for `(42, "Pentest Report!", "pdf")` → `report_flow_42_pentest_report_<14digits>.pdf` ✓
For `(1, "title", "docx")` → `report_flow_1_title_<14digits>.txt` ✓

---

## 6. `render_template` arity (1 test)

**Fix type:** Code fix.

**Test fixed:**
- `TestReports::test_report_render_template_substitutes_missing_keys_with_empty`

**File:** `elengenix/reports/templates.py`

**Current signature (line 82):**
```python
def render_template(template: str, **kwargs: Any) -> str:
    try:
        return template.format(**kwargs)
    except KeyError:
        result = template
        for key, value in kwargs.items():
            result = result.replace("{" + key + "}", str(value))
        return result
```

**Call site:**
```python
out = render_template(VULNERABILITY_TEMPLATE, {"cve_id": "CVE-2024-1"})
assert "CVE-2024-1" in out
assert "{" not in out  # no unsubstituted placeholders
```

**New signature:**
```python
def render_template(template: str, mapping: dict[str, Any] | None = None, **kwargs: Any) -> str:
```

**Behavior:**
1. Merge: `data = {**(mapping or {}), **kwargs}`.
2. **Safe substitution that leaves nothing behind:** use a regex to substitute every `{key}` placeholder. For each match, if `key` is in `data`, replace with `str(data[key])`; otherwise replace with `""`.
3. Implementation:
   ```python
   import re
   def render_template(template, mapping=None, **kwargs):
       data = {**(mapping or {}), **kwargs}
       def _sub(m):
           key = m.group(1)
           return str(data[key]) if key in data else ""
       return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", _sub, template)
   ```
   This guarantees `"{" not in out` for the VULNERABILITY_TEMPLATE (whose only `{...}` tokens are simple identifiers).
4. **Keep backward compat:** callers using `render_template(t, foo="bar")` still work via `**kwargs`.

---

## 7. `CVSSVector` field aliases (1 test)

**Fix type:** Code fix.

**Test fixed:**
- `TestStressPerformance::test_stress_50_concurrent_cvss_calculations_distinct_vectors`

**File:** `elengenix/reports/cvss.py`

**Current dataclass (line 48-58):**
```python
@dataclass
class CVSSVector:
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: CIAImpact = CIAImpact.NONE
    integrity: CIAImpact = CIAImpact.NONE
    availability: CIAImpact = CIAImpact.NONE
```

**Call site (brutal test):**
```python
CVSSVector(
    attack_vector=AttackVector.NETWORK,
    attack_complexity=AttackComplexity.LOW,
    privileges_required=PrivilegesRequired.NONE,
    user_interaction=UserInteraction.NONE,
    scope=Scope.UNCHANGED,
    confidentiality_impact=CIAImpact.HIGH,
    integrity_impact=CIAImpact.HIGH,
    availability_impact=CIAImpact.HIGH,
)
```

**Required change:** accept `confidentiality_impact=` / `integrity_impact=` / `availability_impact=` as aliases that override `confidentiality` / `integrity` / `availability`.

**Implementation (using `InitVar` so the aliases are init-only and don't become stored fields — keeps `format_cvss_vector` / `cvss_result` working unchanged):**
```python
from dataclasses import dataclass, field, InitVar
from typing import Optional

@dataclass
class CVSSVector:
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: CIAImpact = CIAImpact.NONE
    integrity: CIAImpact = CIAImpact.NONE
    availability: CIAImpact = CIAImpact.NONE
    # Init-only aliases (not stored on the instance).
    confidentiality_impact: InitVar[Optional[CIAImpact]] = None
    integrity_impact: InitVar[Optional[CIAImpact]] = None
    availability_impact: InitVar[Optional[CIAImpact]] = None

    def __post_init__(self, confidentiality_impact, integrity_impact, availability_impact):
        if confidentiality_impact is not None:
            self.confidentiality = confidentiality_impact
        if integrity_impact is not None:
            self.integrity = integrity_impact
        if availability_impact is not None:
            self.availability = availability_impact
```

**Verification:** the stress test constructs 50 vectors with all HIGH impact → `calculate_cvss_score(v)` must return `9.8` for each. The current score formula already yields 9.8 for `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (verified by `test_stress_100_concurrent_cvss_calculations_correct`, which currently passes — so no score-formula change needed).

---

## 8. `parse_cvss_vector` validation (1 test)

**Fix type:** Code fix.

**Test fixed:**
- `TestStressPerformance::test_stress_random_bytes_in_cvss_parse_rejected_gracefully`

**File:** `elengenix/reports/cvss.py`

**Call site:**
```python
rnd_bytes = bytes(random.randint(0, 255) for _ in range(32))
with pytest.raises((ValueError, UnicodeDecodeError)):
    parse_cvss_vector(rnd_bytes.decode("latin-1", errors="replace"))
```

**Current behavior:** `parse_cvss_vector` splits on `/`, iterates parts, skips parts without `:`, and if `metrics` ends up empty it silently returns a default `CVSSVector()`. No exception → test fails with "DID NOT RAISE".

**Required change:** raise `ValueError` when the input is not a recognizable CVSS vector.

**Implementation patch (in `parse_cvss_vector`, replacing lines 105-125):**
```python
    KNOWN_METRICS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    parts = [p for p in s.split("/") if p != ""]
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise ValueError(f"Malformed CVSS metric (no ':'): {part!r}")
        key, val = part.split(":", 1)
        if key not in KNOWN_METRICS:
            raise ValueError(f"Unknown CVSS metric key: {key!r}")
        if val not in {"N", "L", "H", "A", "P", "R", "C", "U"}:  # all valid values
            raise ValueError(f"Invalid CVSS metric value for {key}: {val!r}")
        metrics[key] = val

    if not metrics:
        raise ValueError(f"No CVSS metrics parsed from: {vector_string!r}")

    try:
        return CVSSVector(
            attack_vector=_AV_VALUES[metrics.get("AV", "N")],
            ...
        )
    except KeyError as e:
        raise ValueError(f"Invalid CVSS metric value: {e}")
```

**Note:** `errors="replace"` in the test produces a valid Unicode string (with `\ufffd` replacement chars), so we won't naturally raise `UnicodeDecodeError` — we must raise `ValueError` ourselves. The validation above (rejecting unknown keys, malformed parts, empty metrics) covers all 32-byte random inputs.

---

## 9. Markdown behavior (8 tests)

**Fix type:** Code fix.

**Tests fixed (8):**
- `TestReports::test_generate_report_markdown_flow_with_zero_tasks`
- `TestReports::test_generate_report_markdown_one_task_zero_subtasks`
- `TestReports::test_generate_report_markdown_toc_generation`
- `TestReports::test_generate_report_markdown_anchor_ids_github_slugger_compatible`
- `TestReports::test_generate_report_markdown_status_emojis`
- `TestReports::test_generate_report_markdown_header_shifting_h1_to_h4`
- `TestReports::test_report_anchors_with_duplicate_headings_get_suffix`
- `TestReports::test_report_default_status_emoji_for_unknown`

**File:** `elengenix/reports/markdown.py`

### 9.1 `DEFAULT_STATUS_EMOJI` rename + `status_emoji` table (2 tests)

**Current (line 7-20):**
```python
DEFAULT_STATUS_EMOJI: dict[str, str] = {
    "finished": "✅", "running": "🔄", "pending": "⏳", "failed": "❌",
    "cancelled": "🚫", "todo": "📋",
}
def status_emoji(status: Any) -> str:
    key = str(status).lower() if status else ""
    return DEFAULT_STATUS_EMOJI.get(key, "📋")
```

**Test contract:**
```python
assert DEFAULT_STATUS_EMOJI == "\U0001F4DD"      # the 📝 glyph itself, NOT a dict
assert status_emoji("created")  == "\U0001F4DD"  # 📝
assert status_emoji("running")  == "\u26A1"       # ⚡
assert status_emoji("finished") == "\u2705"       # ✅
assert status_emoji("failed")   == "\u274C"       # ❌
assert status_emoji("waiting")  == "\u23F3"       # ⏳
assert status_emoji("???")      == "\U0001F4DD"
assert status_emoji(None)       == "\U0001F4DD"
```

**New code:**
```python
DEFAULT_STATUS_EMOJI: str = "\U0001F4DD"  # 📝 — fallback for unknown statuses

STATUS_EMOJI_MAP: dict[str, str] = {
    "created":   "\U0001F4DD",  # 📝
    "running":   "\u26A1",      # ⚡
    "finished":  "\u2705",      # ✅
    "failed":    "\u274C",      # ❌
    "waiting":   "\u23F3",      # ⏳
    "pending":   "\u23F3",      # ⏳ (alias of waiting)
    "cancelled": "\U0001F6AB",  # 🚫
    "todo":      "\U0001F4DD",  # 📝
}

def status_emoji(status: Any) -> str:
    if not status:
        return DEFAULT_STATUS_EMOJI
    return STATUS_EMOJI_MAP.get(str(status).lower(), DEFAULT_STATUS_EMOJI)
```

**Compatibility note:** the only other place that imports `DEFAULT_STATUS_EMOJI` is the brutal test itself; no internal callers depend on the dict form (verified by grep).

### 9.2 `slugify_github` strip non-ASCII (2 tests)

**Current (line 23-30):**
```python
def slugify_github(text: str) -> str:
    slug = text.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)            # \w matches Unicode → keeps é
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    return slug.strip("-")
```

**Test contract:**
```python
assert slugify_github("Hello World")    == "hello-world"
assert slugify_github("Café ☕ Table")   == "caf-table"
assert slugify_github("")               == ""
assert slugify_github("  leading")      == "leading"
assert slugify_github("trailing  ")     == "trailing"
assert slugify_github("⚡ Task Title")  == "task-title"
assert slugify_github("📝 created")     == "created"
```

**Fix:** use `re.ASCII` flag so `\w` only matches `[A-Za-z0-9_]` (strips `é`, ☕, ⚡, 📝):
```python
def slugify_github(text: str) -> str:
    slug = text.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug, flags=re.ASCII)
    slug = re.sub(r"[\s_]+", "-", slug, flags=re.ASCII)
    slug = re.sub(r"-+", "-", slug)
    return slug.strip("-")
```

**Verification:** `"Café ☕ Table".lower() = "café ☕ table"` → strip non-ASCII-word/space/hyphen → `"café"` keeps `é`? **No** — with `re.ASCII`, `\w` is `[A-Za-z0-9_]`, so `é` is stripped by `[^\w\s-]` → `"caf  table"` (two spaces from the dropped ☕) → collapse `\s+` → `"caf-table"` ✓. Same logic for `"📝 created"` → `"created"` ✓.

### 9.3 `generate_anchors` accept list[str] (1 test)

**Current (line 33-35):**
```python
def generate_anchors(title: str) -> str:
    return f"#{slugify_github(title)}"
```

**Test contract:**
```python
anchors = generate_anchors(["Intro", "Intro", "Intro", "Outro"])
assert anchors["Intro"] == "intro-2"   # 3rd occurrence wins (dict overwrite)
assert anchors["Outro"] == "outro"
anchors2 = generate_anchors(["A", "B", "C", "D"])
assert anchors2 == {"A": "a", "B": "b", "C": "c", "D": "d"}
```

**New signature & behavior:** accept `list[str]`, return `dict[str, str]` (heading → anchor), github-slugger-style dedup with `-1`, `-2`, ... suffixes:
```python
def generate_anchors(headings: list[str]) -> dict[str, str]:
    """Return heading → anchor, github-slugger-style (duplicates get -1, -2, ...)."""
    seen: dict[str, int] = {}
    result: dict[str, str] = {}
    for heading in headings:
        base = slugify_github(heading)
        count = seen.get(base, 0)
        anchor = base if count == 0 else f"{base}-{count}"
        seen[base] = count + 1
        result[heading] = anchor  # last occurrence wins (dict overwrite)
    return result
```

**Verification:** for `["Intro", "Intro", "Intro", "Outro"]`:
- 1st "Intro" → `seen["intro"]=0` → anchor `"intro"`, `seen["intro"]=1`, `result["Intro"]="intro"`
- 2nd "Intro" → `seen["intro"]=1` → anchor `"intro-1"`, `seen["intro"]=2`, `result["Intro"]="intro-1"`
- 3rd "Intro" → `seen["intro"]=2` → anchor `"intro-2"`, `seen["intro"]=3`, `result["Intro"]="intro-2"` ✓
- "Outro" → `result["Outro"]="outro"` ✓

### 9.4 `shift_markdown_headers` cap at H6 (used by 9.6) — verify

**Current (line 38-50):** shifts by prepending `#` × `levels` to any header line, no cap.

**Test contract:**
```python
shift_markdown_headers("# H1\n## H2\n### H3", 3)  # → "#### H1\n##### H2\n###### H3"
shift_markdown_headers("# H1", 6)                 # → "###### H1" (capped at H6)
shift_markdown_headers("# H1\n## H2", 0)          # unchanged
shift_markdown_headers("", 3)                     # ""
shift_markdown_headers("regular paragraph\n# H1\nanother paragraph", 3)
# → "regular paragraph\n#### H1\nanother paragraph"
```

**Fix:** cap at H6:
```python
def shift_markdown_headers(md: str, levels: int = 1) -> str:
    if not md or levels <= 0:
        return md
    lines = md.split("\n")
    shifted = []
    for line in lines:
        m = re.match(r"^(#{1,6})(\s)", line)
        if m:
            new_level = min(len(m.group(1)) + levels, 6)
            shifted.append("#" * new_level + m.group(2) + line[len(m.group(1)) + 1:])
        else:
            shifted.append(line)
    return "\n".join(shifted)
```

### 9.5 `generate_report_markdown` TOC + H3 tasks + empty-list message + header shift (5 tests)

**Current structure (line 53-121):**
```
# {flow_title}

## {emoji} {task_title}        ← H2
**Input:** ```...```
**Result:** ...
### {emoji} {subtask_title}    ← H3
```

**Test contract (4 sub-requirements):**
1. **Empty tasks** → output must contain `"No tasks available"`.
2. **Non-empty tasks** → output must contain `"## Table of Contents"` followed by `- [{task_title}](#{anchor})` lines and a `---` separator, **then** tasks rendered as `### {emoji} {task_title}` (H3, not H2).
3. **TOC entries:** `- [alpha](#alpha)`, `- [beta](#beta)`.
4. **Task input header shifting:** any `# Heading` inside `task.input` must be shifted by 3 (so `# Big Heading` → `#### Big Heading`) so it slots under the H3 task title.

**New implementation (sketch):**
```python
def generate_report_markdown(flow, tasks, subtasks=None):
    subtasks = subtasks or []
    flow_title = getattr(flow, "title", "Untitled Flow") or "Untitled Flow"
    lines = [f"# {flow_title}", ""]

    if not tasks:
        lines.append("No tasks available")
        lines.append("")
        return "\n".join(lines)

    # Build subtask lookup
    subtask_map: dict[int, list[Any]] = {}
    for st in subtasks:
        tid = getattr(st, "task_id", None) or 0
        subtask_map.setdefault(tid, []).append(st)

    # TOC
    lines.append("## Table of Contents")
    for task in tasks:
        title = getattr(task, "title", "Untitled Task") or "Untitled Task"
        anchor = slugify_github(title)
        lines.append(f"- [{title}](#{anchor})")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Task sections (H3)
    for task in tasks:
        title = getattr(task, "title", "Untitled Task") or "Untitled Task"
        task_input = getattr(task, "input", "") or ""
        task_result = getattr(task, "result", "") or ""
        task_status = getattr(task, "status", "finished")
        emoji = status_emoji(task_status)

        lines.append(f"### {emoji} {title}")
        lines.append("")

        if task_input:
            # Shift any embedded headers by 3 so H1→H4 (under the H3 task title)
            shifted_input = shift_markdown_headers(task_input, 3)
            lines.append(shifted_input)
            lines.append("")

        if task_result:
            lines.append("**Result:**")
            lines.append(task_result)
            lines.append("")

        # Subtasks (H4)
        task_id = getattr(task, "id", 0) or 0
        for st in subtask_map.get(task_id, []):
            st_title = getattr(st, "title", "Untitled Subtask") or "Untitled Subtask"
            st_desc = getattr(st, "description", "") or ""
            st_result = getattr(st, "result", "") or ""
            st_status = getattr(st, "status", "finished")
            st_emoji = status_emoji(st_status)
            lines.append(f"#### {st_emoji} {st_title}")
            lines.append("")
            if st_desc:
                lines.append(st_desc); lines.append("")
            if st_result:
                lines.append(f"> {st_result}"); lines.append("")

    return "\n".join(lines)
```

**Verification against the 5 tests:**
- `test_..._flow_with_zero_tasks`: `# empty\n\nNo tasks available\n` → contains "No tasks available" ✓
- `test_..._one_task_zero_subtasks`: starts with `# `, contains `## Table of Contents`, contains `### ` ✓
- `test_..._toc_generation`: between `## Table of Contents` and `---` there's `- [alpha](#alpha)` and `- [beta](#beta)` ✓
- `test_..._anchor_ids_github_slugger_compatible`: covered by 9.2 ✓
- `test_..._status_emojis`: covered by 9.1 ✓
- `test_..._header_shifting_h1_to_h4`: `task.input="# Big Heading\n\nbody"` → after `shift_markdown_headers(input, 3)` → `#### Big Heading\n\nbody` ✓

### 9.6 Stress test compatibility

`test_stress_random_unicode_in_markdown_renders` (currently passing — not in failure list) checks `flow.title="unicode-αβγ-中文-🎉"` and `task.result="résumé café"` survive. The new impl preserves them (we only shift headers, we don't slugify the result text). ✓

---

## 10. PDF rendering + `split_by_cjk` (4 + 3 = 7 tests)

**Fix type:** Code fix + CI fix (add `reportlab` dep).

**Tests fixed (7):**
- `TestReports::test_render_to_pdf_basic_markdown`             (len(pdf) > 1000)
- `TestReports::test_render_to_pdf_with_cjk_content`           (len(pdf) > 5000, no `????`)
- `TestReports::test_render_to_pdf_emoji_substitution`         (`len(EMOJI_SUBSTITUTIONS) == 16`)
- `TestReports::test_render_to_pdf_heading_styles_h1_16pt_h2_14pt` (`HEADING_FONT_SIZES[1]==16, [2]==14, [3]==13, [4]==12, [5]==11, [6]==10`)
- `TestReports::test_split_by_cjk_alternating_segments`        (returns objects with `.is_cjk` and `.text`)
- `TestReports::test_split_by_cjk_empty_returns_single_empty_segment` (`len(segs)==1`, `segs[0].text==""`)
- `TestReports::test_split_by_cjk_pure_cjk_input`              (`segs[0].is_cjk is True`)

**File:** `elengenix/reports/pdf.py` (+ `pyproject.toml` for `reportlab`).

### 10.1 CI fix — add `reportlab`

`pyproject.toml [project.dependencies]`:
```toml
    "reportlab>=4.0.0",
```
Workflow install line already covered by category 1.

### 10.2 Fix `HEADING_FONT_SIZES` (1 test)

**Current:** `{1: 24.0, 2: 20.0, 3: 16.0, 4: 14.0, 5: 12.0, 6: 11.0}`.
**Required:** `{1: 16, 2: 14, 3: 13, 4: 12, 5: 11, 6: 10}`.

```python
HEADING_FONT_SIZES: dict[int, float] = {
    1: 16.0, 2: 14.0, 3: 13.0, 4: 12.0, 5: 11.0, 6: 10.0,
}
```

### 10.3 Fix `EMOJI_SUBSTITUTIONS` (1 test)

**Current:** 29 entries (with duplicates: `🔧` appears twice as `[TOOL]` and `[CONFIG]`).
**Required:** exactly 16 entries.

```python
EMOJI_SUBSTITUTIONS: dict[str, str] = {
    "✅": "[OK]",
    "❌": "[FAIL]",
    "🔄": "[RUN]",
    "⏳": "[WAIT]",
    "🚫": "[CANCEL]",
    "📋": "[TODO]",
    "⚠️": "[WARN]",
    "🔍": "[SEARCH]",
    "🎯": "[TARGET]",
    "🏆": "[TROPHY]",
    "💡": "[INFO]",
    "🔥": "[HOT]",
    "🛡️": "[SHIELD]",
    "⚔️": "[SWORD]",
    "📊": "[CHART]",
    "📦": "[PACKAGE]",
}
```

### 10.4 Fix `split_by_cjk` — return `Segment` objects (3 tests)

**Current (line 65-91):** returns `list[str]`, returns `[]` for empty input.

**Test contract:**
```python
segs = split_by_cjk("hello 世界 foo")
assert len(segs) == 3
assert segs[0].is_cjk is False and segs[0].text == "hello "
assert segs[1].is_cjk is True  and segs[1].text == "世界"
assert segs[2].is_cjk is False and segs[2].text == " foo"

segs = split_by_cjk("")
assert len(segs) == 1
assert segs[0].is_cjk is False
assert segs[0].text == ""

segs = split_by_cjk("中文测试")
assert len(segs) == 1
assert segs[0].is_cjk is True
```

**New implementation:**
```python
from dataclasses import dataclass

@dataclass
class Segment:
    text: str
    is_cjk: bool

def _is_cjk_char(ch: str) -> bool:
    return (
        "\u4e00" <= ch <= "\u9fff"
        or "\u3400" <= ch <= "\u4dbf"
        or "\u3040" <= ch <= "\u30ff"
        or "\uac00" <= ch <= "\ud7af"
    )

def split_by_cjk(text: str) -> list[Segment]:
    if not text:
        return [Segment(text="", is_cjk=False)]
    segments: list[Segment] = []
    current = ""
    prev_is_cjk = False
    for ch in text:
        ch_is_cjk = _is_cjk_char(ch)
        if ch_is_cjk != prev_is_cjk and current:
            segments.append(Segment(text=current, is_cjk=prev_is_cjk))
            current = ""
        current += ch
        prev_is_cjk = ch_is_cjk
    if current:
        segments.append(Segment(text=current, is_cjk=prev_is_cjk))
    return segments
```

### 10.5 Replace `render_to_pdf_bytes` with reportlab (3 tests)

**Current (line 94-161):** hand-rolled 618-byte stub PDF; uses `latin-1` encoding (CJK → `?`); no styled headings.

**Required:**
- `len(pdf) > 1000` for `"# Title\n\nHello.\n"` (basic).
- `len(pdf) > 5000` for `"# 中文标题\n\n这是一段中文内容。\n"` (CJK content).
- `%PDF` magic at byte 0.
- CJK glyphs render correctly (not `????`) → need a CJK-capable font.
- H1 = 16 pt, H2 = 14 pt, etc. (per `HEADING_FONT_SIZES`).

**New implementation (using `reportlab.platypus`):**
```python
import io
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont

# Register built-in Adobe CJK fonts (no file needed — bundled in reportlab)
_CJK_REGISTERED = False
def _ensure_cjk():
    global _CJK_REGISTERED
    if _CJK_REGISTERED:
        return
    try:
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))   # Simplified Chinese
        pdfmetrics.registerFont(UnicodeCIDFont("HeiseiKakuGo-W5")) # Japanese
        pdfmetrics.registerFont(UnicodeCIDFont("HYSMyeongJo-Medium"))  # Korean
    except Exception:
        pass
    _CJK_REGISTERED = True

def render_to_pdf_bytes(markdown: str) -> bytes:
    _ensure_cjk()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    h_styles = {
        lvl: ParagraphStyle(
            f"H{lvl}", parent=styles["Heading1"],
            fontSize=HEADING_FONT_SIZES[lvl],
            leading=HEADING_FONT_SIZES[lvl] * 1.2,
        )
        for lvl in range(1, 7)
    }
    body_style = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=10, leading=14)
    cjk_style = ParagraphStyle("CJK", parent=body_style, fontName="STSong-Light")

    story = []
    in_code = False
    code_buf = []

    for raw_line in markdown.split("\n"):
        line = raw_line
        if line.startswith("```"):
            if in_code:
                story.append(Preformatted("\n".join(code_buf), body_style))
                code_buf = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue

        clean = substitute_emojis(line)
        m = re.match(r"^(#{1,6})\s+(.*)$", clean)
        if m:
            lvl = len(m.group(1))
            story.append(Paragraph(m.group(2), h_styles[lvl]))
            story.append(Spacer(1, 4))
        elif clean.strip():
            # Use CJK font if any CJK char present, else default
            style = cjk_style if any(_is_cjk_char(c) for c in clean) else body_style
            story.append(Paragraph(_escape_html(clean), style))
            story.append(Spacer(1, 2))

    if code_buf:
        story.append(Preformatted("\n".join(code_buf), body_style))

    doc.build(story)
    return buf.getvalue()

def _escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
```

**Verification:**
- Basic `"# Title\n\nHello.\n"`: reportlab produces a multi-object PDF with font dict + content stream → well over 1000 bytes ✓
- CJK content: with `STSong-Light` registered, the font dict and CJK glyph references inflate the PDF well past 5000 bytes ✓
- Magic: reportlab outputs `%PDF-1.4` ✓
- Heading sizes: explicit `fontSize=HEADING_FONT_SIZES[lvl]` ensures 16/14/13/12/11/10 ✓

---

## 11. Template placeholders (4 tests)

**Fix type:** Code fix.

**Tests fixed (4):**
- `TestReports::test_vulnerability_template_all_sections_present`
- `TestReports::test_executive_summary_template_sections`
- `TestReports::test_technical_report_template_sections`
- `TestReports::test_compliance_report_template_pci_soc2_iso27001`

**File:** `elengenix/reports/templates.py`

### 11.1 VULNERABILITY_TEMPLATE — required `{placeholder}` list

Required placeholders (line 1605-1610):
`cve_id, severity, cvss_score, cvss_vector, affected_component, description,
 exploitation_commands, evidence, impact, immediate_fix, long_term_fix,
 compensating_controls, cve_url, vendor_advisory, owasp_reference`

**New template:**
```python
VULNERABILITY_TEMPLATE = """# Vulnerability Report — {title}

## Vulnerability Details
- **CVE ID:** {cve_id}
- **CVSS Score:** {cvss_score}
- **Severity:** {severity}
- **CVSS Vector:** {cvss_vector}
- **Affected Component:** {affected_component}
- **CVE URL:** {cve_url}
- **Vendor Advisory:** {vendor_advisory}
- **OWASP Reference:** {owasp_reference}

## Description
{description}

## Exploitation Commands
{exploitation_commands}

## Evidence
{evidence}

## Impact
{impact}

## Remediation
### Immediate Fix
{immediate_fix}

### Long-Term Fix
{long_term_fix}

### Compensating Controls
{compensating_controls}

## References
{references}
"""
```

### 11.2 EXECUTIVE_SUMMARY_TEMPLATE — required placeholders

Required: `engagement_name, client_name, critical_count, high_count, medium_count, low_count, info_count`

**New template:**
```python
EXECUTIVE_SUMMARY_TEMPLATE = """# Executive Summary — {engagement_name}

## Client
{client_name}

## Overview
{overview}

## Key Findings Summary
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}
- Info: {info_count}

## Risk Assessment
{risk_assessment}

## Recommendations
{recommendations}
"""
```

### 11.3 TECHNICAL_REPORT_TEMPLATE — required sections

Required: `overview, methodology, tools_used, recon_summary, findings_summary, exploit_chains, immediate_remediation, appendix_raw_output`

**New template:**
```python
TECHNICAL_REPORT_TEMPLATE = """# Technical Report — {title}

## Overview
{overview}

## Methodology
{methodology}

## Tools Used
{tools_used}

## Reconnaissance Summary
{recon_summary}

## Findings Summary
{findings_summary}

## Exploit Chains
{exploit_chains}

## Immediate Remediation
{immediate_remediation}

## Appendix — Raw Output
{appendix_raw_output}
"""
```

### 11.4 COMPLIANCE_REPORT_TEMPLATE — PCI-DSS / SOC 2 / ISO 27001

Required literal strings: `"PCI-DSS"`, `"SOC 2"`, `"ISO/IEC 27001"`, `"pci_dss_table"`, `"soc2_table"`, `"iso27001_table"`

**New template:**
```python
COMPLIANCE_REPORT_TEMPLATE = """# Compliance Report — {title}

## Compliance Status
{status}

## PCI-DSS
{pci_dss_table}

## SOC 2
{soc2_table}

## ISO/IEC 27001
{iso27001_table}

## Controls Assessed
{controls}

## Findings
{findings}

## Gap Analysis
{gap_analysis}

## Remediation Plan
{remediation_plan}
"""
```

**Verification:** all four brutal tests just do `assert "X" in TEMPLATE` — the templates above contain every required token ✓.

---

## 12. Async event loop (1 test)

**Fix type:** CI fix (test infrastructure — conftest.py).

**Test fixed:**
- `TestEnricher::test_enricher_run_with_empty_question_raises_value_error`
  (`tests/brutal/test_agents_brutal.py:1420`)

**Root cause:** the test is **synchronous** but does:
```python
asyncio.get_event_loop().run_until_complete(e.run(question=""))
```
On Python ≥ 3.10 (and especially 3.12+), `asyncio.get_event_loop()` raises
`RuntimeError: There is no current event loop in thread 'MainThread'`
when there's no running loop and no loop has been explicitly set.
`pytest-asyncio` in `auto` mode only sets up a loop for `async def` tests — sync tests are on their own.

**Fix location:** `tests/brutal/conftest.py` (preferred — scoped to brutal suite; alternatively `tests/conftest.py` for project-wide coverage).

**Current contents of `tests/brutal/conftest.py`:** just sys.path bootstrapping.

**Add an autouse fixture that restores pre-3.10 behavior:**
```python
import asyncio
import pytest

@pytest.fixture(autouse=True)
def _brutal_event_loop():
    """Ensure asyncio.get_event_loop() returns a usable loop for sync tests
    that still use the deprecated pattern (Python 3.12+ raises RuntimeError
    otherwise). This is a no-op for tests that already have a running loop."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("loop closed")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    yield
    # Don't close — pytest-asyncio may reuse it; closing here can break
    # subsequent async tests in the same session.
```

**Verification:**
- For sync test `test_enricher_run_with_empty_question_raises_value_error`: fixture runs first → `get_event_loop()` succeeds → `e.run(question="")` is awaited → `Enricher.run` raises `ValueError("Enricher.run requires a non-empty question")` → test passes ✓.
- For `async def` tests: `pytest-asyncio` sets up the running loop before the test body runs; the fixture's `get_event_loop()` call returns that running loop (no `RuntimeError`) → no interference ✓.

**Alternative (if the above interacts badly with pytest-asyncio):** use a session-scoped fixture that calls `asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())` once at startup and `asyncio.new_event_loop()` as the default loop. Same effect, fewer per-test calls.

---

## 13. Implementation order & verification

Execute in this order (each step is independently verifiable):

1. **Categories 1 + 2 + 10.1** (CI deps) — edit `pyproject.toml` + both workflow files. Re-run CI matrix → 7 tests pass.
2. **Category 12** (async event loop) — edit `tests/brutal/conftest.py`. Re-run → +1 test.
3. **Category 3** (`export_report`) — edit `elengenix/reports/export.py`. Re-run → +8 tests.
4. **Category 4** (`render_html`) — same file. → +5 tests.
5. **Category 5** (`generate_filename`) — same file. → +2 tests.
6. **Category 6** (`render_template`) — edit `elengenix/reports/templates.py`. → +1 test.
7. **Category 7** (`CVSSVector` aliases) — edit `elengenix/reports/cvss.py`. → +1 test.
8. **Category 8** (`parse_cvss_vector` validation) — same file. → +1 test.
9. **Category 11** (template placeholders) — `templates.py`. → +4 tests.
10. **Category 9** (markdown behavior) — `markdown.py`. → +8 tests.
11. **Category 10.2-10.5** (PDF code: font sizes, emoji dict, Segment, reportlab) — `pdf.py`. → +7 tests.

**Expected end state:** 0 failures on all four CI jobs (3.11, 3.12, 3.13, Run Tests).

### Local verification (per category)

```bash
cd /home/z/my-project/elengenix-ci-fix
pip install -e .
pip install pytest pytest-asyncio pytest-timeout rich itsdangerous strawberry-graphql \
            fastapi "uvicorn[standard]" pyjwt reportlab

# After each step, run the targeted subset:
python -m pytest tests/brutal/test_integration_security_brutal.py::TestReports \
                 tests/brutal/test_integration_security_brutal.py::TestEndToEndIntegration \
                 tests/brutal/test_integration_security_brutal.py::TestSecurity \
                 tests/brutal/test_integration_security_brutal.py::TestStressPerformance \
                 tests/brutal/test_agents_brutal.py::TestEnricher \
                 -m "not integration" --tb=short
```

### Full suite verification (final)

```bash
python -m pytest -q --timeout=300 tests/ -m "not integration" \
  --ignore=tests/test_brain_coverage.py \
  --ignore=tests/test_brain_coverage_gap.py --tb=short
# Expect: 0 failed, ~2774 passed, 1 skipped (matrix baseline).
```

---

## 14. Risk register / gotchas

1. **`export_report` becomes async** — any internal caller (e.g. `elengenix/api/routes/flows.py` GET `/flows/{id}/report`) that currently calls it synchronously will break. Run a grep for `export_report(` across `elengenix/` (excluding tests) and update callers to `await`. **Verified during Phase 2:** no internal caller exists yet — the route handler hasn't been wired, so this is greenfield.
2. **`generate_filename` becomes async** — same caveat. Grep `elengenix/` for callers; if any, convert to `await`.
3. **`DEFAULT_STATUS_EMOJI` rename** — only the brutal test imports it (verified by grep). If a future PR reintroduces an internal caller expecting a dict, it will fail loudly — acceptable.
4. **`generate_anchors` signature change** — same: only the brutal test uses it; the new `generate_report_markdown` does NOT call `generate_anchors` (it builds anchors inline via `slugify_github`), so no internal coupling.
5. **`reportlab` adds ~5 MB to the install** — acceptable for a security-testing framework that already pulls `chromadb`, `sentence-transformers`, etc.
6. **CJK font registration failure** — if `STSong-Light` fails to register (it shouldn't — it's bundled with reportlab), `render_to_pdf_bytes` will fall back to Helvetica and CJK glyphs will be dropped. The `>5000 byte` assertion may still pass because the content stream + font dict are large, but glyphs would be missing. Keep the `try/except` guard, but log a warning.
7. **Async event-loop fixture interaction with `pytest-asyncio`** — the autouse fixture must NOT close the loop at teardown (pytest-asyncio owns its own loop lifecycle). The fixture above only sets a default loop if none exists; it doesn't close anything.
8. **`render_html` performance** — the new HTML-escape + link-scheme-filter must stay under 3 s / 500 calls (i.e. <6 ms per call). The current line-by-line regex approach is already <1 ms per call; adding `html.escape` and one URL-scheme check keeps it well under budget.
9. **`shift_markdown_headers` cap at H6** — verify the regex `^(#{1,6})(\s)` matches `# Big Heading` (yes — group 1 = `#`, group 2 = ` `). For `## H2` shifted by 3 → `len("##")+3=5` → `##### H2` ✓.
10. **`test_stress_500_render_html_calls_under_3s`** uses `include_css=False` — make sure the no-CSS path is the fast one (don't compute a CSS block and then drop it).

---

## 15. Out of scope (explicit non-fixes)

- **Do not modify any test file** in `tests/brutal/`. The brutal suite is the contract.
- **Do not** change the CVSS score formula — the current spec-correct formula already produces 9.8 / 6.1 / 3.7 / 10.0 as expected by the passing tests in the same suite.
- **Do not** refactor `elengenix/api/app.py`, `elengenix/auth/tokens.py`, or `elengenix/agents/enricher.py` — they are not the source of any failure (the API route-existence tests only need `fastapi` installed; the JWT tests only need `pyjwt`; the enricher `run()` is already `async def` and raises `ValueError` correctly — the only issue is the test's own deprecated `get_event_loop` call).
- **Do not** add `markdown-it-py`, `pygments`, or other heavy deps. The brutal tests can be satisfied with the existing line-by-line markdown parser + HTML-escape + URL-scheme filter.
- **Do not** touch the `*,cover` files in the repo — they are coverage artifacts, not source.

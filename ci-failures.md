# CI Failures Report — PR #6 (`fix/async-pytest-v2`)

> **Repo:** `Ashveil1/Elengenix` (upstream) / fork `moussa12345678/Elengenix`
> **Branch:** `fix/async-pytest-v2`
> **Commit (HEAD):** `7784855` — *Add elengenix.reports subpackage (cvss, markdown, pdf, export, templates)*
> **PR title:** *Fix: async pytest support + create elengenix.reports module + CI workflow fixes*
> **Generated:** 2026-07-27

---

## 1. Summary

| # | Workflow | Run ID | Python | Result | Failed | Passed | Skipped | Duration |
|---|----------|--------|--------|--------|--------|--------|---------|----------|
| 1 | `CI` (matrix) | [30283608586](https://github.com/Ashveil1/Elengenix/actions/runs/30283608586) | 3.11 | ❌ failure | **45** | 2729 | 1 | 50.43s |
| 2 | `CI` (matrix) | [30283608586](https://github.com/Ashveil1/Elengenix/actions/runs/30283608586) | 3.12 | ❌ failure | **45** | 2729 | 1 | 51.22s |
| 3 | `CI` (matrix) | [30283608586](https://github.com/Ashveil1/Elengenix/actions/runs/30283608586) | 3.13 | ❌ failure | **45** | 2729 | 1 | 46.06s |
| 4 | `Run Tests` | [30283608963](https://github.com/Ashveil1/Elengenix/actions/runs/30283608963) | 3.12 | ❌ failure | **45** | 2843 | 1 | 45.02s |

**Both** workflows failed. Every job in the matrix failed with the **identical set of 45 tests**
(verified via `diff` — the 3.11, 3.12, 3.13 and run-tests failure lists are byte-for-byte identical).

**There are NO Python-version-specific failures.** 3.11, 3.12, and 3.13 fail on exactly the same
tests. The failures are 100 % version-agnostic and stem from:
1. the newly-added `elengenix.reports` subpackage exposing an API/behaviour that does **not** match
   the `tests/brutal/test_integration_security_brutal.py` expectations, and
2. two optional runtime dependencies (`fastapi`, `pyjwt`) not being installed in CI.

The only Python-version difference is cosmetic: the `Run Tests` job passes 2843 vs the CI matrix's
2729 because `test.yml` ignores a different (smaller) set of files than `ci.yml`, not because any
version behaves differently.

---

## 2. Python-version-specific failures

**None.** The diff of failing test IDs across all four jobs is empty:

```
3.11  vs 3.12  → IDENTICAL (45 == 45)
3.11  vs 3.13  → IDENTICAL (45 == 45)
3.11  vs run-tests → IDENTICAL (45 == 45)
```

Runtime differences (all within noise, no timeouts):
- 3.11 → 50.43 s
- 3.12 → 51.22 s
- 3.13 → 46.06 s
- run-tests (3.12) → 45.02 s

No `--timeout=300` trip, no segfault, no import-time `SyntaxError` on any version. The branch's
stated goal — "async pytest support" — is partially met: `pytest-asyncio` is now installed and
`asyncio_mode = auto` is set, but **one** async test still fails (see §4 category F).

---

## 3. Failure categories (12 root causes → 45 tests)

All 45 failures live in two files:
- `tests/brutal/test_agents_brutal.py` — **1** test
- `tests/brutal/test_integration_security_brutal.py` — **44** tests

| Cat | Category | Error type | # tests | Root cause |
|-----|----------|------------|--------|------------|
| A | Missing dep: **fastapi** | `ModuleNotFoundError: No module named 'fastapi'` | 3 | `fastapi` not in `pyproject.toml` deps nor installed in CI; brutal tests import `create_app()` |
| B | Missing dep: **PyJWT** | `ModuleNotFoundError: No module named 'jwt'` / `ImportError: …requires PyJWT` | 4 | `pyjwt` not in deps nor installed; `elengenix.auth.tokens` raises `ImportError` |
| C | API mismatch: `export_report(provider=…)` | `TypeError: export_report() got an unexpected keyword argument 'provider'` | 8 | Impl sig `export_report(flow, tasks, subtasks=None, fmt="md")` — no `provider` param |
| D | API mismatch: `render_html(include_css=…)` | `TypeError: render_html() got an unexpected keyword argument 'include_css'` | 5 | Impl sig `render_html(markdown: str)` — no `include_css` param |
| E | API mismatch: `generate_filename()` arity | `TypeError: generate_filename() takes 2 positional arguments but 3 were given` | 2 | Impl sig `generate_filename(title, fmt)` — tests pass 3 args |
| E' | API mismatch: `render_template()` arity | `TypeError: render_template() takes 1 positional argument but 2 were given` | 1 | Impl sig `render_template(template, **kwargs)` — tests pass a positional mapping |
| E'' | API mismatch: `CVSSVector(confidentiality_impact=…)` | `TypeError: CVSSVector.__init__() got an unexpected keyword argument 'confidentiality_impact'` | 1 | Impl uses `confidentiality`/`integrity`/`availability`, not `*_impact` |
| F | **Async / event-loop** | `RuntimeError: There is no current event loop in thread 'MainThread'` | 1 | Enricher test calls `asyncio.get_event_loop()` w/o a running loop (the very issue PR title claims fixed) |
| G | Markdown report behaviour | `AssertionError` (TOC / headers / status emoji / slugify / empty-tasks msg) | 8 | `elengenix/reports/markdown.py` output diverges from brutal spec |
| H | PDF rendering | `AssertionError` (tiny PDF, `????` CJK, emoji dict size 29≠16, 24pt≠16pt) | 4 | `elengenix/reports/pdf.py` ships a 618-byte stub PDF, no `reportlab`, no CJK font |
| H' | `split_by_cjk()` return shape | `AttributeError: 'str' object has no attribute 'is_cjk'` | 3 | Impl returns `list[str]`; tests expect objects with `.is_cjk` attribute |
| I | Report templates | `AssertionError: missing {cve_id|engagement_name|overview|PCI-DSS}` | 4 | `elengenix/reports/templates.py` placeholders don't match the brutal contract |
| J | CVSS input validation | `Failed: DID NOT RAISE <ValueError|UnicodeDecodeError>` | 1 | `parse_cvss_vector` doesn't reject random bytes |

**Totals:** 3 + 4 + 8 + 5 + 2 + 1 + 1 + 1 + 8 + 4 + 3 + 4 + 1 = **45** ✅

---

## 4. Complete list of 45 failures (grouped by category)

### A. Missing dependency — `fastapi` (3 tests)

```
FAILED tests/brutal/test_integration_security_brutal.py::TestEndToEndIntegration::test_rest_api_plus_flow_integration_post_flows_route_exists     - ModuleNotFoundError: No module named 'fastapi'
FAILED tests/brutal/test_integration_security_brutal.py::TestEndToEndIntegration::test_rest_api_plus_flow_integration_post_input_route_exists   - ModuleNotFoundError: No module named 'fastapi'
FAILED tests/brutal/test_integration_security_brutal.py::TestEndToEndIntegration::test_rest_api_plus_flow_integration_get_report_route_exists   - ModuleNotFoundError: No module named 'fastapi'
```
**Cause:** `pyproject.toml [project.dependencies]` does not list `fastapi`; the CI step
`pip install -e .` + `pip install pytest pytest-asyncio pytest-timeout rich itsdangerous strawberry-graphql`
never installs it. `elengenix/api/app.py` lazy-imports FastAPI inside `create_app()`, so collection
succeeds but the route-existence tests blow up at call time.

### B. Missing dependency — `PyJWT` (4 tests)

```
FAILED tests/brutal/test_integration_security_brutal.py::TestEndToEndIntegration::test_auth_api_integration_bearer_token_validates - ImportError: elengenix.auth.tokens requires PyJWT — install with 'pip install pyjwt'
FAILED tests/brutal/test_integration_security_brutal.py::TestSecurity::test_jwt_alg_none_attack_blocked        - ModuleNotFoundError: No module named 'jwt'
FAILED tests/brutal/test_integration_security_brutal.py::TestSecurity::test_jwt_expired_token_rejected         - ImportError: elengenix.auth.tokens requires PyJWT — install with 'pip install pyjwt'
FAILED tests/brutal/test_integration_security_brutal.py::TestSecurity::test_jwt_tampered_signature_rejected    - ImportError: elengenix.auth.tokens requires PyJWT — install with 'pip install pyjwt'
```
**Cause:** `pyjwt` is not a declared dependency. `elengenix/auth/tokens.py` does a guarded
`import jwt` and raises a helpful `ImportError`, which the brutal tests surface verbatim.

### C. API mismatch — `export_report()` has no `provider` kwarg (8 tests)

```
FAILED tests/brutal/test_integration_security_brutal.py::TestEndToEndIntegration::test_report_generation_multi_format_export        - TypeError: export_report() got an unexpected keyword argument 'provider'
FAILED tests/brutal/test_integration_security_brutal.py::TestReports::test_export_report_markdown_format                            - TypeError: export_report() got an unexpected keyword argument 'provider'
FAILED tests/brutal/test_integration_security_brutal.py::TestReports::test_export_report_html_format                                - TypeError: export_report() got an unexpected keyword argument 'provider'
FAILED tests/brutal/test_integration_security_brutal.py::TestReports::test_export_report_json_format                                 - TypeError: export_report() got an unexpected keyword argument 'provider'
FAILED tests/brutal/test_integration_security_brutal.py::TestReports::test_export_report_pdf_format                                  - TypeError: export_report() got an unexpected keyword argument 'provider'
FAILED tests/brutal/test_integration_security_brutal.py::TestReports::test_report_export_unsupported_format_raises_value_error       - TypeError: export_report() got an unexpected keyword argument 'provider'
FAILED tests/brutal/test_integration_security_brutal.py::TestStressPerformance::test_reports_export_markdown_under_1s_for_100_tasks  - TypeError: export_report() got an unexpected keyword argument 'provider'
FAILED tests/brutal/test_integration_security_brutal.py::TestStressPerformance::test_reports_export_json_under_1s_for_100_tasks      - TypeError: export_report() got an unexpected keyword argument 'provider'
```
**Cause:** `elengenix/reports/export.py:69` signature is
`export_report(flow, tasks, subtasks=None, fmt="md")`. The brutal tests call
`export_report(flow, tasks, fmt=…, provider="openai")`. Fix = accept (and ignore or wire) a
`provider` keyword.

### D. API mismatch — `render_html()` has no `include_css` kwarg (5 tests)

```
FAILED tests/brutal/test_integration_security_brutal.py::TestReports::test_report_render_html_with_pygments_highlight - TypeError: render_html() got an unexpected keyword argument 'include_css'
FAILED tests/brutal/test_integration_security_brutal.py::TestSecurity::test_xss_script_tag_in_input_is_escaped_in_html_export        - TypeError: render_html() got an unexpected keyword argument 'include_css'
FAILED tests/brutal/test_integration_security_brutal.py::TestSecurity::test_xss_img_onerror_in_input_is_escaped_in_html_export        - TypeError: render_html() got an unexpected keyword argument 'include_css'
FAILED tests/brutal/test_integration_security_brutal.py::TestSecurity::test_xss_javascript_url_in_markdown_link_is_not_active         - TypeError: render_html() got an unexpected keyword argument 'include_css'
FAILED tests/brutal/test_integration_security_brutal.py::TestStressPerformance::test_stress_500_render_html_calls_under_3s           - TypeError: render_html() got an unexpected keyword argument 'include_css'
```
**Cause:** `elengenix/reports/export.py:25` signature is `render_html(markdown: str)`. The brutal
tests call `render_html(md, include_css=True)`. Note: the XSS tests aren't actually XSS
vulnerabilities — they fail at the function call before the escaping logic runs.

### E. API mismatch — `generate_filename()` / `render_template()` / `CVSSVector()` arity (4 tests)

```
FAILED tests/brutal/test_integration_security_brutal.py::TestReports::test_generate_filename_pattern                 - TypeError: generate_filename() takes 2 positional arguments but 3 were given
FAILED tests/brutal/test_integration_security_brutal.py::TestReports::test_generate_filename_unknown_format_defaults_txt - TypeError: generate_filename() takes 2 positional arguments but 3 were given
FAILED tests/brutal/test_integration_security_brutal.py::TestReports::test_report_render_template_substitutes_missing_keys_with_empty - TypeError: render_template() takes 1 positional argument but 2 were given
FAILED tests/brutal/test_integration_security_brutal.py::TestStressPerformance::test_stress_50_concurrent_cvss_calculations_distinct_vectors - TypeError: CVSSVector.__init__() got an unexpected keyword argument 'confidentiality_impact'
```
**Cause:**
- `generate_filename(title, fmt)` — tests pass a 3rd positional (likely `flow`/`provider`).
- `render_template(template, **kwargs)` (templates.py:82) — tests call `render_template(template, mapping)`.
- `CVSSVector` is a dataclass with fields `confidentiality / integrity / availability`; the stress
  test constructs it with `confidentiality_impact=…`.

### F. Async / event-loop (1 test)  ← the bug the PR title claims to fix

```
FAILED tests/brutal/test_agents_brutal.py::TestEnricher::test_enricher_run_with_empty_question_raises_value_error
  tests/brutal/test_agents_brutal.py:1424: in test_enricher_run_with_empty_question_raises_value_error
  raise RuntimeError('There is no current event loop in thread %r.'
  E   RuntimeError: There is no current event loop in thread 'MainThread'.
```
**Cause:** Under Python ≥3.10 (and especially 3.12+) `asyncio.get_event_loop()` raises when there
is no running loop. Either the `Enricher.run()` path (or the test's helper) calls
`asyncio.get_event_loop().run_until_complete(...)` instead of `asyncio.run(...)` /
`asyncio.new_event_loop()`. `pytest-asyncio` is installed and `asyncio_mode=auto` is set, so the
infra is right — the *product code* still uses the deprecated loop-acquisition pattern.

### G. Markdown report behaviour (8 tests)

```
FAILED …::TestReports::test_generate_report_markdown_flow_with_zero_tasks          - AssertionError: assert 'No tasks available' in '# empty\n'
FAILED …::TestReports::test_generate_report_markdown_one_task_zero_subtasks        - AssertionError: assert '## Table of Contents' in '# one\n\n## 📋 only\n\n**Input:**\n```\ni\n```\n\n**Result:**\nr\n'
FAILED …::TestReports::test_generate_report_markdown_toc_generation                - AssertionError: assert '- [' in ''
FAILED …::TestReports::test_generate_report_markdown_anchor_ids_github_slugger_compatible - AssertionError: assert 'café-table' == 'caf-table'
FAILED …::TestReports::test_generate_report_markdown_status_emojis                 - AssertionError: assert '📋' == '📝'
FAILED …::TestReports::test_generate_report_markdown_header_shifting_h1_to_h4      - AssertionError: assert '#### Big Heading' in '# shift\n\n## 📋 t\n\n**Input:**\n```\n# Big Heading\n\nbody\n```\n'
FAILED …::TestReports::test_report_anchors_with_duplicate_headings_get_suffix      - AttributeError: 'list' object has no attribute 'lower'
FAILED …::TestReports::test_report_default_status_emoji_for_unknown               - AssertionError: assert {'finished': '✅', 'running': '🔄', 'pending': '⏳', 'failed': '❌', …} == '📝'
```
**Cause:** `elengenix/reports/markdown.py` diverges from the brutal spec in five ways:
1. Empty task list should emit a literal `No tasks available` line; impl emits `# empty`.
2. A `## Table of Contents` section with `- [title](#anchor)` entries is never generated.
3. `slugify_github()` keeps accented letters (`café-table`) because `re.sub(r"[^\w\s-]", …)`
   matches `é` under `re.UNICODE`; GitHub Slugger strips non-ASCII → expects `caf-table`.
4. `status_emoji("created")` falls through to the default `📋`; the brutal suite wants `📝`
   (and `"created"` must be a key in `DEFAULT_STATUS_EMOJI`).
5. `shift_markdown_headers(md, levels=1)` defaults to +1; the test shifts `# Big Heading` →
   `#### Big Heading` (needs `levels=3` or an explicit call).
6. `generate_anchors()` (or a helper) is being called on a `list`, hence
   `'list' object has no attribute 'lower'`.

### H. PDF rendering (4 tests) + H'. `split_by_cjk()` shape (3 tests)

```
FAILED …::TestReports::test_render_to_pdf_basic_markdown            - AssertionError: assert 618 > 1000
FAILED …::TestReports::test_render_to_pdf_with_cjk_content          - AssertionError: assert 620 > 5000   (CJK renders as '????')
FAILED …::TestReports::test_render_to_pdf_emoji_substitution        - AssertionError: assert 29 == 16    (EMOJI_SUBSTITUTIONS dict has 29 entries)
FAILED …::TestReports::test_render_to_pdf_heading_styles_h1_16pt_h2_14pt - assert 24.0 == 16             (heading font size 24 pt vs expected 16 pt)
FAILED …::TestReports::test_split_by_cjk_alternating_segments       - AttributeError: 'str' object has no attribute 'is_cjk'
FAILED …::TestReports::test_split_by_cjk_empty_returns_single_empty_segment - assert 0 == 1  (len([]) vs expected len([''))
FAILED …::TestReports::test_split_by_cjk_pure_cjk_input             - AttributeError: 'str' object has no attribute 'is_cjk'
```
**Cause:** `elengenix/reports/pdf.py::render_to_pdf_bytes()` writes a **hand-rolled 618-byte
stub PDF** (no `reportlab`, no real layout, no CJK font → `????`, no styled headings). The brutal
suite expects:
- a real rendered PDF (>1000 bytes basic, >5000 bytes with CJK),
- CJK glyphs rendered correctly (needs a CJK-capable font),
- exactly **16** emoji substitutions (the dict currently has 29),
- H1 = 16 pt / H2 = 14 pt (impl uses 24 pt or none).

`split_by_cjk()` returns `list[str]`; the tests iterate and call `segment.is_cjk`, i.e. they
expect **segment objects** carrying an `.is_cjk` boolean (e.g. a small `Segment(text, is_cjk)`
dataclass), and an empty input must return `['']` (one empty segment), not `[]`.

### I. Report templates (4 tests)

```
FAILED …::TestReports::test_vulnerability_template_all_sections_present   - AssertionError: missing cve_id
FAILED …::TestReports::test_executive_summary_template_sections           - AssertionError: assert 'engagement_name' in '…'
FAILED …::TestReports::test_technical_report_template_sections            - AssertionError: assert 'overview' in '…'
FAILED …::TestReports::test_compliance_report_template_pci_soc2_iso27001  - AssertionError: assert 'PCI-DSS' in '…'
```
**Cause:** `elengenix/reports/templates.py` placeholders don't match the brutal contract:
- vulnerability template lacks `{cve_id}`,
- executive-summary template lacks `{engagement_name}`,
- technical-report template uses a different key than `{overview}`,
- compliance template lacks `PCI-DSS` / `SOC2` / `ISO27001` framework identifiers.

### J. CVSS input validation (1 test)

```
FAILED …::TestStressPerformance::test_stress_random_bytes_in_cvss_parse_rejected_gracefully - Failed: DID NOT RAISE any of (ValueError, UnicodeDecodeError)
```
**Cause:** `parse_cvss_vector()` does not reject random bytes — it should raise `ValueError`
(or `UnicodeDecodeError`) on garbage input instead of silently producing a default vector.

---

## 5. Dependency / environment context

CI install step (identical in `ci.yml` and `test.yml`):
```bash
pip install -e .
pip install pytest pytest-asyncio pytest-timeout rich itsdangerous strawberry-graphql
```

`pyproject.toml [project.dependencies]` (excerpt) does **not** include:
- `fastapi`  → categories A (3 tests)
- `pyjwt`    → category B (4 tests)
- `reportlab`→ contributes to category H (PDF stub instead of real render)

`reportlab` is not strictly required by the brutal suite's *assertions* (they only check byte
size / font size), but producing a >1000-byte real PDF practically needs it (or a heavier fallback).

`pytest-asyncio` ✅ installed, `asyncio_mode = auto` ✅ set in both `pytest.ini` and
`pyproject.toml [tool.pytest.ini_options]` — so the async infrastructure is correct; the lone
async failure (category F) is product-code-side.

---

## 6. Reproduction (local)

```bash
cd /home/z/my-project/elengenix-ci-fix
pip install -e .
pip install pytest pytest-asyncio pytest-timeout rich itsdangerous strawberry-graphql
python -m pytest -q --timeout=300 tests/ -m "not integration" \
  --ignore=tests/test_brain_coverage.py --ignore=tests/test_brain_coverage_gap.py --tb=short
# expect: 45 failed, ~2729 passed, 1 skipped
```

To reproduce only the brutal suite (the 45 failures):
```bash
python -m pytest tests/brutal/test_integration_security_brutal.py tests/brutal/test_agents_brutal.py \
  -m "not integration" --tb=short
```

---

## 7. Next actions (recommended fix order — biggest-bang-first)

1. **CI deps (closes 7 tests instantly).** Add to the CI install line (or to an `[project.optional-dependencies].brutal` extra and `pip install -e .[brutal]`):
   `fastapi pyjwt uvicorn[standard] reportlab`
   → fixes categories **A (3)** + **B (4)**.
2. **`reports/export.py` signature shim (closes 15 tests).**
   - `export_report(..., fmt="md", provider: str | None = None)` (accept & ignore/store `provider`),
   - `render_html(markdown: str, include_css: bool = True) -> str` (emit a `<style>` block when `True`),
   - `generate_filename(title, fmt, flow=None)` (3rd positional optional),
   - `render_template(template, mapping=None, **kwargs)` (accept a positional mapping).
   → fixes categories **C (8) + D (5) + E (2) + E′ (1)**.
3. **`reports/cvss.py` alias (closes 1).** Accept `confidentiality_impact` / `integrity_impact` /
   `availability_impact` as aliases for `confidentiality` / `integrity` / `availability` in
   `CVSSVector.__init__`, and make `parse_cvss_vector()` raise `ValueError` on undecodable bytes.
   → fixes **E″ (1) + J (1)**.
4. **`reports/pdf.py` (closes 7).** Switch `render_to_pdf_bytes()` to `reportlab` (real layout,
   16-pt→16 pt headings, CJK font registration, 16-entry emoji map), and change `split_by_cjk()`
   to return `list[Segment]` (dataclass with `.text` + `.is_cjk`), returning `['']`→`[Segment('', False)]`
   for empty input. → fixes **H (4) + H′ (3)**.
5. **`reports/markdown.py` (closes 8).** Add `## Table of Contents` + `- [title](#anchor)` entries,
   emit `No tasks available` for empty task lists, make `slugify_github()` strip non-ASCII
   (`re.sub(r"[^\w\s-]", "", slug, flags=re.ASCII)`), add `created`→`📝` to
   `DEFAULT_STATUS_EMOJI`, fix header-shift levels, and guard `generate_anchors()` against `list`
   inputs. → fixes **G (8)**.
6. **`reports/templates.py` (closes 4).** Add `{cve_id}`, `{engagement_name}`, `{overview}`, and
   `PCI-DSS` / `SOC2` / `ISO27001` framework markers to the respective templates. → fixes **I (4)**.
7. **Async event-loop (closes 1).** Replace `asyncio.get_event_loop().run_until_complete(...)` in
   the Enricher path (and the test helper at `test_agents_brutal.py:1424`) with `asyncio.run(...)`
   or `asyncio.new_event_loop()` + explicit close. → fixes **F (1)** — the one failure the PR title
   explicitly promises to resolve.

Executing items 1–7 should take the matrix from **45 failed → 0 failed** on all of 3.11/3.12/3.13
and the `Run Tests` job.

---

## 8. Artifacts

- Clone: `/home/z/my-project/elengenix-ci-fix` (branch `fix/async-pytest-v2`, HEAD `7784855`)
- Raw CI logs (zips): `/tmp/elengenix-logs/ci-run-30283608586.zip`,
  `/tmp/elengenix-logs/run-tests-30283608963.zip`
  (copy also at `/tmp/elengenix-ci-logs.zip` per task step 4)
- Extracted logs: `/tmp/elengenix-logs/ci/` and `/tmp/elengenix-logs/run-tests/`
- Per-version FAILED-ID lists (identical): `/tmp/fails-3.11.txt`, `/tmp/fails-3.12.txt`,
  `/tmp/fails-3.13.txt`, `/tmp/fails-runtests.txt`
- Structured analysis dump: `/tmp/analysis_full.txt`

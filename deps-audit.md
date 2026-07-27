# Dependency Audit — Brutal Test Suite

> Phase 2c deliverable. Audits `pyproject.toml` and CI install lines against
> the deps the `tests/brutal/*` suite and the `elengenix.{api,auth,graphql,
> reports}` subpackages actually need.
>
> Reference: `ci-failures.md` (45-failure root-cause analysis).

---

## 0. TL;DR

| # | Dep | In `pyproject`? | In CI install line? | Used by (test / module) | Recommended fix |
|---|-----|-----------------|---------------------|--------------------------|-----------------|
| 1 | `fastapi`              | ❌ no  | ❌ no  | `tests/brutal/test_api_auth_brutal.py`, `test_integration_security_brutal.py` (cat A, 3 tests) | Add to `[brutal]` extra + CI line |
| 2 | `pyjwt` (PyJWT)        | ❌ no  | ❌ no  | `elengenix/auth/tokens.py`; cat B (4 tests) | Add to `[brutal]` extra + CI line |
| 3 | `itsdangerous`         | ❌ no  | ✅ yes | `elengenix/auth/sessions.py`; `test_api_auth_brutal.py` | Add to `[brutal]` extra (already in CI line) |
| 4 | `strawberry-graphql`   | ❌ no  | ✅ yes | `elengenix/graphql/schema.py` (eager `import strawberry`) | Add to `[brutal]` extra (already in CI line) |
| 5 | `pydantic`             | ❌ no  | ❌ no  | `elengenix/auth/models.py` (lazy), `test_agents_brutal.py` (eager `from pydantic import ValidationError`) | Add to `[brutal]` extra + CI line |
| 6 | `httpx`                | ❌ no  | ❌ no  | `elengenix/auth/oauth.py` (lazy), `test_kg_flows_providers_brutal.py` (mocks `httpx.AsyncClient`) | Add to `[brutal]` extra + CI line |
| 7 | `authlib`              | ❌ no  | ❌ no  | `elengenix/auth/oauth.py` (lazy); `test_api_auth_brutal.py` | Add to `[brutal]` extra + CI line |
| 8 | `reportlab`            | ❌ no  | ❌ no  | `elengenix/reports/pdf.py` (NOT currently used — but brutal tests expect >1000/>5000-byte real PDFs) | Add to `[brutal]` extra + CI line **and** refactor `pdf.py` to use it |

**Current `pyproject.toml [project.optional-dependencies]`** only defines a
`dev` extra (pytest, pytest-asyncio, black, isort, flake8, mypy, ruff). There
is **no** `brutal` extra.

**Current CI install lines** (identical in `.github/workflows/ci.yml` line 30
and `.github/workflows/test.yml` line 28):
```bash
pip install -e .
pip install pytest pytest-asyncio pytest-timeout rich itsdangerous strawberry-graphql
```

---

## 1. Per-dep detail

### 1.1 `fastapi`  ❌ missing

* **Used by (tests):**
  - `tests/brutal/test_api_auth_brutal.py:47` — `pytest.importorskip("fastapi")`
    (skips entire module cleanly when fastapi is absent).
  - `tests/brutal/test_api_auth_brutal.py:53` — `from fastapi.testclient import TestClient`.
  - `tests/brutal/test_integration_security_brutal.py` — 3 tests in `TestEndToEndIntegration`
    (category A in `ci-failures.md`) that call `create_app()` → lazy
    `import fastapi` inside `elengenix/api/app.py` raises `ModuleNotFoundError`.
* **Used by (product code):**
  - `elengenix/api/app.py` — `from fastapi import FastAPI` *inside* `create_app()`.
  - `elengenix/api/_auth.py`, `elengenix/api/routes/*.py`, `elengenix/auth/middleware.py`
    — all lazy-import `fastapi` / `starlette`.
* **Lazy pattern:** `elengenix/api/__init__.py` uses `__getattr__` so
  `import elengenix.api` succeeds without fastapi (only `create_app` access
  triggers the import). This is intentional — keeps CLI / AST-inspection paths
  fastapi-free.
* **Recommendation:** **optional `[brutal]` extra** (not core dep). The lazy
  import design makes fastapi a soft runtime requirement; only the API server
  surface and the brutal API tests need it. CI line install is sufficient.

### 1.2 `pyjwt` (a.k.a. `PyJWT`, importable as `jwt`)  ❌ missing

* **Used by (tests):**
  - `tests/brutal/test_api_auth_brutal.py:48` — `pytest.importorskip("jwt")`.
  - `tests/brutal/test_integration_security_brutal.py` — 4 tests in `TestSecurity`
    + `TestEndToEndIntegration` (category B in `ci-failures.md`). These tests
    do **not** use `importorskip` and surface the helpful `ImportError` from
    `tokens.py` verbatim (`"elengenix.auth.tokens requires PyJWT — install with
    'pip install pyjwt'"`).
* **Used by (product code):**
  - `elengenix/auth/tokens.py:329` — `import jwt` *inside* `issue_token()`.
  - `elengenix/auth/tokens.py:399` — `import jwt` *inside* `validate_token()`.
* **Lazy pattern:** Yes — guarded `try/except ImportError as exc: raise
  ImportError("…requires PyJWT — install with 'pip install pyjwt'") from exc`.
  No silent fallback.
* **Recommendation:** **optional `[brutal]` extra**. The lazy import is
  intentional for CLI-only environments. CI line install is sufficient.
  Alternatively, also add `pytest.importorskip("jwt")` at the top of
  `test_integration_security_brutal.py` (which currently lacks it) to make
  the skip graceful instead of erroring — but installing PyJWT is the
  recommended primary fix (closes 4 real test failures, not skips them).

### 1.3 `itsdangerous`  ❌ missing from pyproject, ✅ in CI line

* **Used by (tests):**
  - `tests/brutal/test_api_auth_brutal.py:49` — `pytest.importorskip("itsdangerous")`.
* **Used by (product code):**
  - `elengenix/auth/sessions.py:114` — `from itsdangerous import URLSafeTimedSerializer`
    inside `_get_serializer()`.
  - `elengenix/auth/sessions.py:225` — `from itsdangerous import BadSignature, SignatureExpired`
    inside `validate_session_cookie()`.
* **Lazy pattern:** Yes — guarded `try/except ImportError` raising a helpful
  `ImportError("…requires itsdangerous — install with 'pip install
  itsdangerous'")`. No silent fallback (functions fail loud on call).
* **CI status:** Already installed in both `ci.yml` line 30 and `test.yml`
  line 28. Tests run green in CI today for this dep.
* **Recommendation:** Add to `[brutal]` extra for local-repro consistency
  (`pip install -e .[brutal]` should suffice without remembering the
  hand-maintained CI line). CI install is currently sufficient.

### 1.4 `strawberry-graphql`  ❌ missing from pyproject, ✅ in CI line

* **Used by (tests):**
  - No brutal test imports strawberry directly. The brutal suites avoid
    GraphQL surface coverage.
* **Used by (product code):**
  - `elengenix/graphql/schema.py:32` — **eager** `import strawberry` at module
    top (NOT lazy).
  - `elengenix/graphql/__init__.py` — `__getattr__` lazy pattern; defers
    `from .queries import Query` etc. so `import elengenix.graphql` succeeds
    without strawberry. `get_schema()` does the lazy `import strawberry`.
  - `elengenix/graphql/{queries,mutations,subscriptions,types}.py` — all
    `import strawberry` at module top.
* **Lazy pattern:** Partial — `__init__.py` is lazy, but the leaf modules are
  eager. Importing `elengenix.graphql.schema` directly will fail without
  strawberry.
* **CI status:** Already installed in both CI lines. No failures attributable
  to strawberry in `ci-failures.md`.
* **Recommendation:** Add to `[brutal]` extra for reproducibility. CI install
  is currently sufficient.

### 1.5 `pydantic`  ❌ missing

* **Used by (tests):**
  - `tests/brutal/test_agents_brutal.py:35` — **eager module-level**
    `from pydantic import ValidationError`. If pydantic is missing,
    collection of this 200-test file fails entirely (not just individual
    tests). **This is a collection-time hazard.**
* **Used by (product code):**
  - `elengenix/auth/models.py:74` — lazy `from pydantic import BaseModel,
    Field` inside a function, raises helpful `ImportError` if missing.
  - `elengenix/api/_models.py` — Pydantic v2 `BaseModel` schemas (the
    `__init__.py` docstring claims "All schemas use Pydantic v2").
  - `elengenix/agents/base.py`, `elengenix/flows/models.py`, etc. — Pydantic
    models.
* **Lazy pattern:** Inconsistent — `auth/models.py` is lazy; `_models.py` and
  `flows/models.py` are likely eager.
* **CI status:** Not installed explicitly. However, `chromadb`, `tiktoken`,
  `sentence-transformers`, and `textual` (all in `[project.dependencies]`)
  transitively pull in pydantic, so `pip install -e .` currently satisfies
  pydantic as a **transitive** dependency. This is fragile — if any of those
  deps ever drops pydantic, the brutal suite breaks at collection time.
* **Recommendation:** Add to `[brutal]` extra (or even to core
  `[project.dependencies]` as an explicit pin, since elengenix uses Pydantic
  v2 `BaseModel` directly). CI install line should also list it explicitly
  for defense against transitive-dep churn.

### 1.6 `httpx`  ❌ missing

* **Used by (tests):**
  - `tests/brutal/test_api_auth_brutal.py:51` — `pytest.importorskip("httpx")`.
  - `tests/brutal/test_kg_flows_providers_brutal.py` — mocks
    `httpx.AsyncClient` via `unittest.mock.patch`; does NOT importorskip, but
    does monkey-patch `httpx.AsyncClient`. If httpx is absent, the patch
    target doesn't resolve at test-time (collection may still pass because
    the `patch("httpx.AsyncClient", …)` target is resolved lazily).
* **Used by (product code):**
  - `elengenix/auth/oauth.py:791` — `import httpx` inside
    `resolve_email()` for GitHub email resolution.
* **Lazy pattern:** Yes — guarded `try/except ImportError` raising a helpful
  `ImportError("…requires httpx for GitHub email resolution — install with
  'pip install httpx'")`.
* **Recommendation:** **optional `[brutal]` extra**. CI install is sufficient.
  Also: `fastapi.testclient.TestClient` uses `httpx` under the hood, so once
  fastapi is installed httpx usually comes transitively — but pinning it
  explicitly removes ambiguity.

### 1.7 `authlib`  ❌ missing

* **Used by (tests):**
  - `tests/brutal/test_api_auth_brutal.py:50` — `pytest.importorskip("authlib")`.
* **Used by (product code):**
  - `elengenix/auth/oauth.py:379` — `from authlib.integrations.starlette_client
    import OAuth` inside `_build_authlib_oauth()`.
  - `elengenix/auth/oauth.py:852` — `from authlib.jose import errors as
    jose_errors; from authlib.oidc.core import IDToken; …` for Google OIDC
    verification.
* **Lazy pattern:** Yes — guarded `try/except ImportError` raising a helpful
  `ImportError("…requires authlib — install with 'pip install \"authlib>=1.0\"'")`.
* **Recommendation:** **optional `[brutal]` extra**. CI install is sufficient.
  Note: authlib is only needed if GitHub/Google OAuth is exercised; the
  `importorskip` already correctly skips the relevant tests when absent.

### 1.8 `reportlab`  ❌ missing

* **Used by (tests):**
  - `tests/brutal/test_integration_security_brutal.py` — 4 PDF tests in
    `TestReports` (category H in `ci-failures.md`):
    `test_render_to_pdf_basic_markdown` (expects `len(pdf) > 1000`),
    `test_render_to_pdf_with_cjk_content` (expects `len(pdf) > 5000`),
    `test_render_to_pdf_emoji_substitution`,
    `test_render_to_pdf_heading_styles_h1_16pt_h2_14pt`.
  - Also 1 e2e PDF test at line 484 (`test_report_generation_pdf_rendering`)
    expects `pdf_bytes[:4] == b"%PDF"` only — passes today with the stub.
* **Used by (product code):**
  - `elengenix/reports/pdf.py` — does **NOT** use reportlab today. It
    hand-rolls a ~618-byte stub PDF (see `ci-failures.md` §4 category H).
    `HEADING_FONT_SIZES[1] = 24.0` (brutal expects 16.0).
    `EMOJI_SUBSTITUTIONS` has 29 entries (brutal expects 16).
* **Lazy pattern:** N/A — reportlab is not imported anywhere yet.
* **Recommendation:** Add to `[brutal]` extra **and** refactor
  `elengenix/reports/pdf.py::render_to_pdf_bytes()` to use reportlab (real
  layout, CJK font registration, 16/14-pt headings, 16-entry emoji map).
  Per `ci-failures.md` §7 item 4, this closes categories H (4) + H′ (3) = 7
  tests. CI install is sufficient *after* the refactor; merely installing
  reportlab does nothing without the code change.

---

## 2. Graceful-fallback audit (lazy-import patterns)

### 2.1 `elengenix/api/__init__.py` — fastapi

* **Does it use `pytest.importorskip`?** No — it is a product module, not a
  test. It uses the `__getattr__` lazy-attribute pattern instead:
  ```python
  def __getattr__(name: str) -> Any:
      if name == "create_app":
          from .app import create_app as _create_app
          return _create_app
      raise AttributeError(...)
  ```
* **Effect:** `import elengenix.api` succeeds without fastapi. Only accessing
  `elengenix.api.create_app` triggers `from .app import create_app`, which in
  turn imports fastapi inside the function body.
* **Verdict:** ✅ Graceful. The package is importable for AST inspection and
  CLI-only environments. The brutal `test_api_auth_brutal.py` file
  additionally guards with `pytest.importorskip("fastapi")` at module top.

### 2.2 `elengenix/auth/sessions.py` — itsdangerous

* **Does it have a graceful fallback?** Partial. Two functions lazy-import
  itsdangerous and raise a *helpful* `ImportError` (not silent):
  - `_get_serializer()` (line 113):
    ```python
    try:
        from itsdangerous import URLSafeTimedSerializer
    except ImportError as exc:
        raise ImportError(
            "elengenix.auth.sessions requires itsdangerous — install with "
            "'pip install itsdangerous'"
        ) from exc
    ```
  - `validate_session_cookie()` (line 225): same pattern with `BadSignature,
    SignatureExpired`.
* **Effect:** `import elengenix.auth.sessions` succeeds without
  itsdangerous (no module-level import). Calling any function that needs the
  serializer raises the helpful `ImportError`.
* **Verdict:** ✅ Graceful (loud, not silent). The brutal
  `test_api_auth_brutal.py` additionally guards with
  `pytest.importorskip("itsdangerous")` at module top, so the entire 200-test
  file skips cleanly when itsdangerous is absent — no spurious failures.

### 2.3 `elengenix/auth/tokens.py` — PyJWT

* **Does it have a graceful fallback?** Partial. Two functions lazy-import
  `jwt` and raise a *helpful* `ImportError`:
  - `issue_token()` (line 328):
    ```python
    try:
        import jwt
    except ImportError as exc:
        raise ImportError(
            "elengenix.auth.tokens requires PyJWT — install with "
            "'pip install pyjwt'"
        ) from exc
    ```
  - `validate_token()` (line 398): same pattern.
* **Effect:** `import elengenix.auth.tokens` succeeds without PyJWT (no
  module-level `import jwt`). Calling `issue_token()` or `validate_token()`
  raises the helpful `ImportError`.
* **Caveat:** `tests/brutal/test_integration_security_brutal.py` does **NOT**
  use `pytest.importorskip("jwt")` at module top — it relies on the
  helpful `ImportError` surfacing as a test failure (4 tests in category B).
  This is intentional (the tests assert JWT security properties; skipping
  would hide regressions), but it means **installing PyJWT is required** to
  make CI green.
* **Verdict:** ✅ Graceful (loud, not silent). For `test_api_auth_brutal.py`
  the `pytest.importorskip("jwt")` at line 48 makes the file skip cleanly;
  for `test_integration_security_brutal.py` the tests fail loud, which is the
  desired signal once PyJWT is installed.

---

## 3. Recommended fix — minimal pyproject change

Add a new `[brutal]` extra to `[project.optional-dependencies]`:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-asyncio",
    "black",
    "isort",
    "flake8",
    "mypy",
    "ruff",
]
brutal = [
    # REST API + auth stack (lazy-imported by product code)
    "fastapi>=0.100.0",
    "pydantic>=2.0",            # transitively pulled today; pin explicitly
    "pyjwt>=2.0",               # `import jwt`
    "itsdangerous>=2.0",
    "authlib>=1.0",
    "httpx>=0.24.0",
    # GraphQL (eager import in elengenix/graphql/schema.py)
    "strawberry-graphql>=0.200.0",
    # PDF reports (required after reports/pdf.py refactor)
    "reportlab>=4.0",
    # Test runner (already in CI line; consolidate)
    "pytest>=7.0.0",
    "pytest-asyncio",
    "pytest-timeout",
]
```

Then update both CI install lines to:

```bash
pip install -e ".[brutal]"
```

This replaces the current fragile hand-maintained line
(`pip install pytest pytest-asyncio pytest-timeout rich itsdangerous strawberry-graphql`)
and adds the four missing deps (`fastapi`, `pyjwt`, `pydantic`, `httpx`,
`authlib`, `reportlab`) in one shot.

---

## 4. CI-install sufficiency per missing dep

| Dep | Install in CI `pip install` line sufficient? | Notes |
|-----|-----------------------------------------------|-------|
| `fastapi`            | ✅ Yes | No compile-time / native deps; pure Python wheel. |
| `pyjwt`              | ✅ Yes | Pure Python. |
| `itsdangerous`       | ✅ Yes | Already installed. |
| `strawberry-graphql` | ✅ Yes | Already installed; pure Python. |
| `pydantic`           | ✅ Yes | `pydantic>=2` ships pre-built wheels (incl. `pydantic-core` Rust ext). No system deps. |
| `httpx`              | ✅ Yes | Pure Python (pulls `httpcore`, `h11`, `certifi`, `anyio`). |
| `authlib`            | ✅ Yes | Pure Python (pulls `cryptography` — has pre-built wheels on all supported CPython versions). |
| `reportlab`          | ✅ Yes | Ships pre-built manylinux + macOS + Windows wheels. No system deps for the basic PDF API. (CJK font registration needs a TTF file — see `reports/pdf.py` refactor note below.) |

For all eight deps, the `pip install` line in CI is sufficient. **No
apt/brew/system-package prerequisite** is required for any of them. The only
non-trivial follow-up is refactoring `elengenix/reports/pdf.py` to actually
*call* reportlab (installing it alone does not close category H tests — see
`ci-failures.md` §7 item 4).

---

## 5. Action checklist

1. **Add `[brutal]` extra to `pyproject.toml`** (section 3 above).
2. **Update both CI install lines** (`.github/workflows/ci.yml` line 30,
   `.github/workflows/test.yml` line 28) to `pip install -e ".[brutal]"`.
3. **Refactor `elengenix/reports/pdf.py`** to use `reportlab` (real layout,
   16/14-pt headings, CJK font, 16-entry emoji map, `Segment(text, is_cjk)`
   return shape for `split_by_cjk`). — closes category H (4) + H′ (3).
4. **(Optional, defensive)** Add `pytest.importorskip("jwt")` at the top of
   `tests/brutal/test_integration_security_brutal.py` to make the skip
   graceful if PyJWT is ever absent again (turns 4 hard failures into 4
   skips). Not required once PyJWT is in the `[brutal]` extra, but is a
   good defence-in-depth move.
5. **(Optional)** Pin `pydantic>=2.0` in `[project.dependencies]` (not just
   `[brutal]`) since `elengenix/api/_models.py` and `elengenix/flows/models.py`
   use `BaseModel` directly — relying on the transitive pull from chromadb /
   textual is fragile.

Executing items 1–3 closes the 7 dep-related failures in `ci-failures.md`
(category A: 3 + category B: 4 = 7) and unblocks the 7 PDF-rendering failures
(category H + H′) once the `pdf.py` refactor lands.

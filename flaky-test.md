# Flaky-Test Investigation — Phase 2e

> **Task title:** "Read test_scanning_tui_game"
> **Task body path:** `/home/z/my-project/elengenix-ci-fix/tests/test_agent_tools.py`
> **Date:** 2026-07-27

---

## 0. Premise check — multiple contradictions in the request

The request contains three internally contradictory premises, none of which
matches the actual repository state. I document them up front so the next
agent doesn't chase a phantom.

| # | Premise in the request | Actual reality | Verdict |
|---|------------------------|----------------|---------|
| 1 | "find the 1 flaky test that fails with `--timeout=60` but passes with `--timeout=300`" in `test_agent_tools.py` | No test in `test_agent_tools.py` (or `test_scanning_tui_game.py`) is anywhere near the 60 s mark. **All 63 tests across both files pass with `--timeout=60` in 12.5 s total.** | ❌ Premise false |
| 2 | "the CI log showed `1 failed, 1708 passed` on Run #4 for the `test.yml` workflow" | `ci-failures.md` (the authoritative record for this branch) shows the actual `Run Tests` (`test.yml`) result was **45 failed, 2843 passed, 1 skipped** — see line 18. Grep for `1708`, `Run #4`, `1 failed` across the repo's docs returns **zero** hits. | ❌ Premise false |
| 3 | "Was that the terrain test? If so, it should already be fixed." | The 45 failures are all in `tests/brutal/test_integration_security_brutal.py` (44) + `tests/brutal/test_agents_brutal.py` (1). **None** are the terrain test. The terrain test isn't flaky in the first place (see §3). | ❌ Premise false |

**The title says "test_scanning_tui_game" but the body says "test_agent_tools.py".**
Both files exist; I read both. They are unrelated:

- `tests/test_agent_tools.py` — unit tests for `elengenix/agent/vuln_agent.py` (file/shell/python/delegate tools).
- `tests/test_scanning_tui_game.py` — unit tests for `elengenix/scanning/tui_game.py` (the `ObbyGame` platformer).

The closing question about "the terrain test" can only refer to
`test_scanning_tui_game.py::TestObbyGameInit::test_terrain_generation`, so the
title is the more accurate pointer. The body path appears to be a copy-paste typo.

---

## 1. File read — `tests/test_agent_tools.py`

358 lines, 10 test classes, all unit tests with **explicit short per-call
timeouts** (5–15 s) passed into `_tool_run_command` / `_tool_run_python` /
`_tool_delegate`. None of these tests do anything that could approach pytest's
`--timeout` of 60 s.

### /tmp usage in this file

Only two tests reference `/tmp`:

```python
# TestReadFile.test_read_nonexistent_file (line 49-52)
r = _tool_read_file("/tmp/nonexistent_xyzzy.txt")
assert not r["success"]
assert "not found" in r["error"].lower()

# TestSearchFiles.test_search_no_match (line 109-112)
r = _tool_search_files("ZZZZ_XYZZY_NONEXISTENT_99999", path="/tmp")
assert r["success"]
assert r.get("total_matches", 0) == 0 or "No matches" in r["output"]
```

Both are deterministic and fast (the first just stats a non-existent path;
the second walks `/tmp` for a pattern that won't match). Neither holds state
across runs, and neither could plausibly trip a 60 s wall-clock.

### The only shared-state in `test_agent_tools.py`

`TestEditOwnTool` (lines 286-357) mutates `~/.elengenix/tools/test_edit_target.py`
(home dir, **not** `/tmp`) and the module-global `_dynamic_tools` / `AVAILABLE_TOOLS`
lists. Its `setup_method` and explicit cleanups in each test are designed to
make this idempotent. There's no /tmp dependence and no timeout dependence.

**Verdict for `test_agent_tools.py`: no flaky test, no /tmp-state bug, no timeout bug.**

---

## 2. File read — `tests/test_scanning_tui_game.py` (the title's actual target)

332 lines, 9 test classes covering `ObbyGame` init / jump / tick / render / constants.

The "terrain test" the closing question asks about:

```python
# TestObbyGameInit.test_terrain_generation (lines 41-50)
def test_terrain_generation(self):
    mock_app = Mock()
    game = ObbyGame(mock_app)
    # Terrain length may vary slightly due to generation loop
    assert len(game.terrain) >= 400
    assert len(game.terrain) <= 410
    # First 12 should be safe ground
    assert all(t == "█" for t in game.terrain[:12])
```

### Is it flaky? No.

The terrain generator (`elengenix/scanning/tui_game.py:49-63`) loops
`while pos < TERRAIN_SEGMENTS (400)`, adding one platform (length 3–8 at
max difficulty) and optionally one gap (length 1–2) per iteration. Since
`len(terrain) == pos` is invariant, the final length is bounded above by
`399 (last entry) + 8 (max plat) = 407`, with no gap added in the final
iteration (the `if pos < TERRAIN_SEGMENTS` guard prevents it).

Empirical check over 2000 random seeds:

```
min: 400   max: 407   mean: 401.98
below 400: 0 / 2000
above 410: 0 / 2000
in [400,410]: 2000 / 2000
```

Re-running the test 10× in isolation: **10/10 pass**, ~2.6 s each (mostly
import overhead; the assertion itself is microseconds).

**Verdict for `test_scanning_tui_game.py::test_terrain_generation`: not flaky, not timeout-dependent, does not depend on /tmp state. There is nothing to fix.**

---

## 3. Is the claimed flakiness a real bug or just a timeout issue?

**Neither.** There is no flaky test in either file. The empirical run
(`pytest tests/test_agent_tools.py tests/test_scanning_tui_game.py --timeout=60`)
returns **63 passed in 12.5 s**. There is no `--timeout=60 vs --timeout=300`
divergence to explain, because nothing approaches the 60 s wall-clock.

The 45 actual CI failures recorded in `ci-failures.md` are all in
`tests/brutal/` and have unrelated root causes:
missing deps (`fastapi`, `pyjwt`), API-signature mismatches in the new
`elengenix.reports` subpackage, an async event-loop bug in `Enricher.run()`,
and a hand-rolled stub PDF where the brutal suite expects real `reportlab`
output. None of these are in `test_agent_tools.py` or `test_scanning_tui_game.py`,
and none are timeout-related.

---

## 4. Does CI use `--timeout=300`?

Two workflows exist in `.github/workflows/`:

| Workflow | Per-test `--timeout` flag? | Job-level `timeout-minutes`? |
|----------|----------------------------|------------------------------|
| `ci.yml` (line 34) | ✅ `--timeout=300` | — |
| `test.yml` (lines 12, 30-41) | ❌ **No `--timeout` flag at all** | `timeout-minutes: 15` (job-level) |

**Confirmed:** `ci.yml` uses `--timeout=300` as the request expected.
`test.yml` does **not** — it only has the GitHub Actions job-level
`timeout-minutes: 15`. This is the only real, actionable discrepancy I found
in this phase. If a per-test timeout is desired for `test.yml`, add
`--timeout=300` to the `python -m pytest` invocation at line 32.

(`pytest-timeout` *is* installed in both workflows via the explicit
`pip install pytest pytest-asyncio pytest-timeout …` step, so the flag would
work immediately if added.)

---

## 5. Was the "1 failed, 1708 passed" CI log the terrain test?

**No**, because that CI log line doesn't exist anywhere in this repository's
records. The authoritative `ci-failures.md` (line 18) records the actual
`test.yml` result as **45 failed, 2843 passed, 1 skipped**, with all 45
failures in `tests/brutal/test_integration_security_brutal.py` (44) and
`tests/brutal/test_agents_brutal.py` (1). A grep for `1708`, `Run #4`, and
`1 failed` across `ci-failures.md`, `FIX_NOTES.md`, `local-test-results.md`,
and `workflow-analysis.md` returns **zero matches**.

So even if we generously assume "Run #4" refers to the 4th CI matrix entry
in `ci-failures.md` (the `Run Tests` job, line 18), the failure set is the
brutal/reports suite, not the terrain test. And as shown in §2, the terrain
test isn't flaky to begin with, so there's no fix to apply.

---

## 6. Recommended next actions

1. **Do NOT "fix" `test_terrain_generation`** — it isn't broken. The
   `[400, 410]` bound has 3–7 tiles of headroom on the upper end (empirical
   max 407) and is exactly tight on the lower end (loop terminates at
   `pos >= 400`). If a future change to `tui_game.py` increases max platform
   length or max gap length, revisit the upper bound.
2. **Add `--timeout=300` to `test.yml`** at `.github/workflows/test.yml:32`
   for parity with `ci.yml`. Low-risk, one-line change.
3. **Stop chasing the phantom "1 failed, 1708 passed / Run #4" log** — it
   does not appear anywhere in the repo's documentation. If a real CI log
   with those numbers exists, it is from a different branch/run and should
   be re-downloaded into `/tmp/elengenix-logs/` before further analysis.
4. **Reconcile the task title vs body path mismatch** before the next phase.
   The title (`test_scanning_tui_game`) and body path (`test_agent_tools.py`)
   point to different files; only the title aligns with the closing question
   about the terrain test.

---

## 7. Summary (3 lines)

No test in `test_agent_tools.py` or `test_scanning_tui_game.py` is flaky at
`--timeout=60`; all 63 pass in 12.5 s, the terrain test is bounded to
[400, 407] over 2000 seeds, and `test_terrain_generation` has no /tmp
dependence and nothing to fix. `ci.yml` does use `--timeout=300`; `test.yml`
does **not** (it has only a job-level `timeout-minutes: 15`) — that's the
only real discrepancy found. The "1 failed, 1708 passed on Run #4 of test.yml"
log doesn't exist anywhere in the repo's records; the actual recorded result
is 45 failed / 2843 passed, all in `tests/brutal/` (reports-subpackage API
mismatches + missing `fastapi`/`pyjwt` deps + one async event-loop bug),
none in either file investigated here.

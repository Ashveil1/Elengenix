# AGENTS.md — Elengenix

## Setup

```bash
pip install -e ".[dev]"   # editable + pytest/black/isort/flake8/mypy/ruff
elengenix doctor          # or: python3 main.py doctor
```

Python ≥3.10 (CI matrix: 3.11–3.13). Keys via `~/.elengenix/.env`, never committed.
Env/config lookup order: `$ELENGENIX_ENV`/`$ELENGENIX_CONFIG` → `~/.elengenix/` → cwd (see `elengenix/paths.py`).

## Where code lives

- Entry: `main.py` (CLI router) → `commands/`, `cli/`, `tui/`.
- Live code: `elengenix/scanning/` (ScanLoop, planner, decision engine, prompt builder, verification) and `elengenix/agent/` (VulnAgent + memory/skills).
- `elengenix/providers/` is the preferred LLM path (`Provider` Protocol: `call`/`call_ex`/`call_with_tools`); `tools/universal_ai_client.py` is the legacy fallback. `elengenix/scanning/provider_bridge.py` prefers Stack A, falls back to Stack B.
- **Do not extend `agents/` or `core/`** — both are deprecated shims re-exporting from `elengenix.*` with `DeprecationWarning` (pytest config ignores it). Keep them working, don't add modules there.
- `mcp/` is a compact JSON-RPC 2.0 implementation (stdio + HTTP); use it for new external tools.
- Runtime state lives under `~/.elengenix/` (`reports/`, `data/memory.json`, `data/skills.json`, `data/benchmark_results/`). Use `elengenix/paths.py` getters (`get_data_dir`, `get_reports_path`); never write user data into the repo checkout.
- `benchmark/runner.py` spins up `tests/vulnerable_target/app.py` and runs the canonical `ScanLoop`; `benchmark/grading.py` grades 10 planted vulns.

## Verify (CI is truth: `.github/workflows/ci.yml`)

```bash
python3 -m pytest tests/ -m "not integration" --ignore=tests/test_brain_coverage.py --ignore=tests/test_brain_coverage_gap.py -q
python3 -m pytest tests/test_scanning_scan_loop.py -q        # one file
python3 -m pytest tests/test_x.py::TestY::test_z -q          # one test
python3 -m pytest tests/test_benchmark_grading.py tests/test_benchmark_sweep.py -q  # offline/hermetic
```

- `@pytest.mark.integration` = needs network; always deselect locally with `-m "not integration"`.
- `tests/brutal/` is a separate expensive subset — exclude from default runs.
- Format/lint: `black --line-length=100` (pre-commit enforces this + trailing whitespace only), `isort` (profile=black), `flake8`/`ruff check`/`mypy` per `pyproject.toml`.

## Benchmark

```bash
python3 benchmark/run_benchmark.py --json              # stealth (default, honest mode)
python3 benchmark/run_benchmark.py --loud              # easy smoke-test mode only
python3 benchmark/run_benchmark.py --models a,b --repeat 3
python3 benchmark/run_benchmark.py --history
```

Exit codes: `0` = recall>0, `1` = ran but found nothing, `2` = infra failure (no key, target down, legacy mode). Never conflate 1 and 2. Needs a real provider key or exit is 2. See `benchmark/README.md`.

## Conventions (repo-specific)

- 4-space indent, type hints everywhere, `rich` for terminal UI.
- No emoji in output/logs/comments — use `[OK]` `[FAIL]` `[WARN]` `[INFO]` `[RUN]` `[SKIP]`.
- Every shell command goes through governance: `governance.gate(mission_id, target, action)` → `needs_approval` prompts, `deny` blocks.
- Every scan target must pass `validate_target()` + `is_in_scope()` (`elengenix/scope.py`) before any probing; only scan targets you own/have permission for.

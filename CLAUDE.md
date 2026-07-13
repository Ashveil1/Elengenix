# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Elengenix is an **autonomous AI security research framework** that performs vulnerability discovery through AI reasoning — not just running checklists. It builds attack trees, selects tools, interprets findings, and adapts strategy in real-time like a penetration tester.

**Entry point:** `main.py` → `elengenix` command (via `pip install -e .`)

---

## Common Development Commands

### Install & Setup
```bash
# Development install (editable)
pip install -e ".[dev]"

# Or run setup script (handles system deps)
./setup.sh

# Verify installation
elengenix doctor
```

### Testing
```bash
# Full test suite (379+ tests)
python3 -m pytest tests/ -v

# Stable suite (no network dependencies)
python3 -m pytest tests/test_tui.py tests/test_security.py tests/test_core_modules.py -v

# New modules
python3 -m pytest tests/test_scan_context.py tests/test_prompt_builder.py tests/test_post_processor.py tests/test_decision_engine.py tests/test_scan_loop.py -v

# Pipeline tests
python3 -m pytest tests/test_scope.py tests/test_phase_registry.py tests/test_unified_pipeline.py -v

# Skip integration tests (require network)
python3 -m pytest tests/ -m "not integration" -v
```

### Code Quality
```bash
# Format
black .
isort .

# Lint
flake8 .
mypy .
ruff check .
```

### Run CLI
```bash
# Health check
elengenix doctor

# Configure AI providers
elengenix configure

# Start scan
elengenix scan example.com

# TUI mode
elengenix tui

# Shortcuts
elengenix bb        # BOLA testing
elengenix check     # Quick recon
elengenix test      # WAF detection
elengenix hack      # AI chat mode
```

---

## Architecture (Big Picture)

```
main.py (CLI entry)
    │
    ├── core/brain.py          # AI reasoning engine (Strategist, Recon Lead, Exploit Analyst)
    ├── core/orchestrator.py   # Pipeline engine (6 phases)
    ├── core/agent.py          # Agent singleton
    ├── core/scan_engine.py    # Smart scan engine
    │
    ├── agents/                # Agent subsystem
    │   ├── scan_context.py    # Central state object (ScanContext)
    │   ├── prompt_builder.py  # AI prompt assembly
    │   ├── decision_engine.py # AI decision making
    │   ├── post_processor.py  # Result processing
    │   └── scan_loop.py       # Main execution loop
    │
    ├── pipeline/              # Configurable phase pipeline
    │   ├── scope.py           # Target validation (ScopeManager)
    │   ├── phase_registry.py  # Phase definitions
    │   └── unified.py         # Unified pipeline entry
    │
    ├── mcp/                   # Model Context Protocol
    │   ├── server.py          # MCP server
    │   ├── client.py          # MCP client
    │   ├── config.py          # MCP configuration
    │   └── manager.py         # MCP lifecycle
    │
    ├── tools/                 # 120+ security tools (nmap, sqlmap, ffuf, etc.)
    ├── commands/              # CLI commands (scan, configure, doctor, tui)
    ├── cli/                   # UI components (rich, textual)
    └── tui/                   # Textual TUI application
```

**Key data flow:** `ScanContext` (state) → `DecisionEngine` (AI chooses next action) → `ToolExecutor` (runs tool via governance) → `PostProcessor` (analyzes results) → updates `ScanContext` → loop.

---

## Critical Working Rules (from AGENTS.md)

### MCP Thinking Tools — MANDATORY
**Call these BEFORE writing any code:**

| Tool | When to Use |
|------|-------------|
| `sequential-thinking` | New task, uncertain problem, choosing between options, complex bug |
| `chain-of-recursive-thoughts` | Deep analysis, root cause, large refactor |
| `mcp-structured-thinking` | Planning steps, breaking down work, estimation |

### Workflow Protocol
1. **Think** — MCP thinking tools analyze first
2. **Explore** — Read relevant files before editing
3. **Plan** — Decide what to change
4. **Implement** — One file at a time
5. **Test** — Run tests after every change
6. **Verify** — Check no regressions elsewhere

### Iron Rules
- **Never edit without reading first** — `Read` before `Edit`
- **Never skip tests** — Run tests after every change
- **One file at a time** — Edit, test, verify, then next
- **Don't guess** — `grep`/`search` for answers
- **Never skip MCP thinking** — Required before every task

---

## Configuration Files

| File | Purpose |
|------|---------|
| `pyproject.toml` | Build config, dependencies, pytest/black/isort/flake8 settings |
| `mcp.json` | MCP server configs (copied from `mcp.json.example`) |
| `.env` | API keys, model preferences (copied from `.env.example`) |
| `.mcp.json` | Project-scoped MCP servers |
| `config.yaml.example` | Main config template |
| `AGENTS.md` | Working protocols (this file references it) |

---

## Key Patterns in Codebase

### Lazy Imports (for optional deps)
```python
try:
    from optional_module import Something
except ImportError:
    Something = None
```

### Safe Operations (graceful failure)
```python
def _safe_operation(name, fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        logger.debug(f"{name} failed: {e}")
```

### Governance Check (ALL shell commands)
```python
gate = governance.gate(mission_id, target, action)
if gate.decision == "needs_approval":
    # prompt user
elif gate.decision == "deny":
    # block
```

### Type Hints — Required Everywhere
```python
def func(param: Type) -> ReturnType:
    ...
```

---

## Testing Guidelines

- **Test location:** `tests/` mirroring source structure
- **Markers:** `@pytest.mark.integration` for network tests
- **Run stable tests locally:** `pytest tests/test_tui.py tests/test_security.py tests/test_core_modules.py -v`
- **CI runs full suite** including integration

---

## Important Notes for Future Agents

1. **This is a security tool** — all targets must pass `validate_target()` and `is_in_scope()` before scanning
2. **Governance is non-negotiable** — every shell command goes through the governance layer
3. **MCP servers require npm/node** — sequential-thinking, memory, filesystem servers are external
4. **Cross-session memory** uses ChromaDB + SQLite FTS5 (in `~/.elengenix/data/`)
5. **AGENTS.md is the source of truth** for working protocols — read it first
6. **379+ tests exist** — they're comprehensive; run them
7. **CLI uses `rich` + `textual`** for TUI; `questionary` for prompts
8. **AI providers are optional** — framework runs without them (pre-flight scanner only)

---

## Useful grep Targets

```bash
# Find governance checks
grep -r "governance.gate" --include="*.py"

# Find MCP tool calls
grep -r "mcp__" --include="*.py"

# Find decision engine usage
grep -r "DecisionEngine" --include="*.py"

# Find scan context usage
grep -r "ScanContext" --include="*.py"
```

---

## License
GPL-3.0-only — see `LICENSE`
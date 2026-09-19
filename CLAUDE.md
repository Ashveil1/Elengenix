# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Elengenix is an **autonomous AI security research framework** that performs vulnerability discovery through AI reasoning — not just running checklists. It builds attack trees, selects tools, interprets findings, and adapts strategy in real-time like a penetration tester.

**Entry point:** `main.py` → `elengenix` command (via `pip install -e .`)

All canonical code lives under `elengenix/`. The former legacy trees (`core/`, `agents/`, `pipeline/`, `redteam_agent/`) have been fully removed — do not reference them. The multi-agent crew lives at `elengenix/agent/crew/` (the old `elengenix/agents/` path remains only as a deprecation shim that re-exports it).

---

## Common Development Commands

### Install & Setup
```bash
# Development install (editable, includes test deps)
pip install -e ".[dev]"

# Optional extras
pip install -e ".[api]"      # FastAPI/uvicorn API server
pip install -e ".[graphql]"  # Strawberry GraphQL layer
pip install -e ".[pdf]"      # PDF report export (reportlab)

# Verify installation
elengenix doctor
```

### Testing
```bash
# Full test suite (3,150+ tests, ~5 min)
python3 -m pytest tests/ -v

# Brutal integration/security/stress suite
python3 -m pytest tests/brutal/ -v

# Skip network-dependent integration tests
python3 -m pytest tests/ -m "not integration" -v

# Scanning subsystem tests
python3 -m pytest tests/test_scanning_decision_engine.py tests/test_scanning_scan_loop.py -v

# Single file
python3 -m pytest tests/test_tui.py -v
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
elengenix bb        # bounty mode
elengenix check     # quick check
elengenix hack      # AI chat mode
```

---

## Architecture (Big Picture)

```
main.py (CLI entry)
    │
    ├── elengenix/               # Canonical package
    │   ├── agent/               # VulnAgent (true AI agent) + memory + skills
    │   │   ├── vuln_agent.py    # Main agent + tool selection
    │   │   ├── agent_memory.py  # JSON-backed memory store
    │   │   ├── agent_skills.py  # JSON-backed skill store
    │   │   ├── compat.py        # Scan wrappers over VulnAgent (ex-orchestrator)
    │   │   └── crew/            # PentAGI-ported multi-agent crew (15 specialists)
    │   ├── chat/                # Interactive chat agent
    │   │   ├── brain.py         # Chat brain (recon/exploit reasoning)
    │   │   ├── agent.py         # ElengenixAgent singleton
    │   │   └── smart_orchestrator.py
    │   ├── scanning/            # Scanning subsystem
    │   │   ├── scan_context.py  # Central state object (ScanContext)
    │   │   ├── prompt_builder.py# AI prompt assembly
    │   │   ├── decision_engine.py # AI decision making
    │   │   ├── post_processor.py  # Result processing
    │   │   └── scan_loop.py     # Main execution loop
    │   ├── reports/             # Report generation
    │   │   ├── markdown.py      # Markdown rendering (task/finding sections)
    │   │   ├── cvss.py          # CVSS v3.1 base score math (Roundup)
    │   │   ├── templates.py     # Report templates
    │   │   ├── export.py        # Markdown/HTML export (XSS-safe)
    │   │   └── pdf.py           # PDF export (reportlab, CJK-capable)
    │   ├── scope.py             # Target validation & scope
    │   ├── governance.py        # Governance layer
    │   ├── brain.py             # Planning engine
    │   ├── loop.py              # Main agent loop
    │   ├── api/ + auth/ + graphql/  # API server, sessions, GraphQL
    │   └── flows/ + knowledge_graph/
    │
    ├── mcp/                     # Model Context Protocol
    │   ├── server.py            # MCP server
    │   ├── client.py            # MCP client
    │   ├── config.py            # MCP configuration
    │   └── manager.py           # MCP lifecycle
    │
    ├── tools/                   # 140+ security tool modules (nmap, sqlmap, ffuf, etc.)
    ├── commands/                # CLI command handlers (scan, system, worldclass)
    ├── cli/                     # UI components (rich, textual), wizard, doctor
    ├── tui/                     # Textual TUI application
    ├── integrations/            # Telegram bot gateway
    └── tests/                   # 3,150+ tests (tests/brutal/ = security/stress suite)
```

**Key data flow:** `ScanContext` (state) → `DecisionEngine` (AI chooses next action) → executor (runs tool via governance) → `PostProcessor` (analyzes results) → updates `ScanContext` → loop.

---

## Critical Working Rules (from AGENTS.md)

### Workflow Protocol
1. **Explore** — Read relevant files before editing
2. **Plan** — Decide what to change
3. **Implement** — One file at a time
4. **Test** — Run tests after every change
5. **Verify** — Check no regressions elsewhere

### Iron Rules
- **Never edit without reading first** — `Read` before `Edit`
- **Never skip tests** — Run tests after every change
- **One file at a time** — Edit, test, verify, then next
- **Don't guess** — `grep`/`search` for answers

---

## Configuration Files

| File | Purpose |
|------|---------|
| `pyproject.toml` | Build config, dependencies, pytest/black/isort/flake8 settings |
| `mcp.json.example` | MCP server config template (auto-copied to `~/.elengenix/mcp.json`) |
| `.env.example` | Template for API keys (real `.env` is git-ignored) |
| `config.yaml.example` | Main config template |
| `AGENTS.md` | Working protocols |

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

- **Test location:** `tests/` mirroring source structure; `tests/brutal/` for integration/security/stress
- **Markers:** `@pytest.mark.integration` for network tests (deselect with `-m "not integration"`)
- **Runtime:** full suite takes ~5 minutes; pytest timeout is 300s per test
- **CI runs the full suite** including brutal tests

---

## Important Notes for Future Agents

1. **This is a security tool** — all targets must pass `validate_target()` and `is_in_scope()` (in `elengenix/scope.py`) before scanning
2. **Governance is non-negotiable** — every shell command goes through the governance layer
3. **MCP servers require npm/node** — sequential-thinking, memory, filesystem servers are external
4. **Cross-session memory** uses ChromaDB + SQLite FTS5 (in `~/.elengenix/data/`)
5. **3,150+ tests exist** — they're comprehensive; run them
6. **CLI uses `rich` + `textual`** for TUI; `questionary` for prompts
7. **AI providers are optional** — framework runs without them (pre-flight scanner only)
8. **PDF reports** need the `[pdf]` extra (reportlab); CJK text uses a bundled fallback font

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

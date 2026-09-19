<div align="center">

<img src="assets/elengenix.png" alt="Elengenix" width="700">

<img src="assets/typing-animation.svg" alt="Terminal" width="700">

### Autonomous AI Security Research Framework

*Reasoning-driven vulnerability discovery that thinks like a penetration tester.*

[![Python](https://img.shields.io/badge/Python-3.10+-white?style=for-the-badge&logo=python&logoColor=red)](https://python.org)
[![License](https://img.shields.io/badge/License-GPL_3.0-red?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-3150%2B%20passing-white?style=for-the-badge)](https://github.com/Ashveil1/Elengenix/actions)
[![MCP](https://img.shields.io/badge/MCP-Supported-red?style=for-the-badge)](https://modelcontextprotocol.io)
[![Security](https://img.shields.io/badge/Security-Governance-red?style=for-the-badge)](https://github.com/Ashveil1/Elengenix)

</div>

<img src="assets/red-divider.svg" width="100%">

## What is Elengenix?

Elengenix is a **true autonomous AI agent** for security research. It doesn't follow checklists or script chains — it **reasons** about targets, **chooses** its own tools, **pivots** when stuck, and **writes new tools** when existing ones aren't enough.

```text
User: "Find vulnerabilities in example.com"
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  VulnAgent — True AI Agent (free will, 25 tools)             │
│  ├── Reasons about target and builds strategy                │
│  ├── Selects tools from AVAILABLE_TOOLS (freedom to skip)    │
│  ├── Creates new tools on the fly (edit_own_tool)            │
│  ├── Learns from cross-session memory (ChromaDB + Skills)    │
│  └── Pivots freely — no locked phases or forced ordering     │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  Governance Layer                                            │
│  ├── SAFE → Execute immediately                              │
│  ├── PRIVILEGED → Ask user approval                          │
│  └── DESTRUCTIVE → Block with popup                          │
└──────────────────────────────────────────────────────────────┘
    │
    ▼
Reports: findings, CVSS scores, AI analysis
```

Unlike "script chaining with an AI on top", Elengenix gives the AI **genuine autonomy** — it decides what to do, in what order, and how to adapt when a path fails.

<img src="assets/red-divider.svg" width="100%">

## Quick Start

### Prerequisites

- **Python 3.10 or newer** (`python3 --version` to check) and `pip`
- **An AI provider key** — at least one of: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
  `GEMINI_API_KEY`, `GROQ_API_KEY`, `DEEPSEEK_API_KEY`… or a local
  [Ollama](https://ollama.com) install (no key needed)
- *Optional:* [Node.js](https://nodejs.org) ≥ 18 if you want the default
  npm-based MCP servers (Elengenix works fine without them)

### Install

```bash
pip install elengenix            # from PyPI
# or, from a source checkout:
pip install .
```

That's it. The install takes a few minutes (ChromaDB + sentence-transformers
are the heavy parts). User config, memory, and reports all live under
`~/.elengenix/`.

### Scan a target in 3 lines

```bash
elengenix configure              # one-line setup: pick a provider, paste your key
elengenix doctor                 # sanity-check the installation
elengenix scan example.com       # autonomous AI vulnerability hunt
```

Skip the wizard entirely by exporting a key instead:

```bash
export OPENAI_API_KEY=sk-...     # or ANTHROPIC_API_KEY / GROQ_API_KEY / ...
elengenix scan example.com
```

> **Only scan targets you own or have written permission to test.**
> Every potentially intrusive action is gated by the Governance layer and
> asks for your approval first (`--mode strict` blocks it outright).

### Terminal Demo

```text
┌─────────────────────────────────────────────────────────────┐
│  $ elengenix scan example.com                                │
│                                                              │
│  ╔═══════════════════════════════════════════════════════╗   │
│  ║  ELENGENIX — Autonomous AI Vulnerability Hunter        ║   │
│  ╚═══════════════════════════════════════════════════════╝   │
│                                                              │
│  [INFO] Target validated: example.com                        │
│  [INFO] Cross-session memory: ACTIVE                         │
│                                                              │
│  VulnAgent uses 25 available tools...                        │
│  ├── Reasoning: Reconnaissance needed first                  │
│  ├── Scanning subdomains...                                  │
│  ├── Testing endpoints for common vulnerabilities...         │
│  ├── [FOUND] SQL injection at /api/users?id=                 │
│  ├── Creating custom exploit script...                       │
│  └── Report generated with findings                          │
│                                                              │
│  [OK] Hunt complete!                                         │
│  [OK] Report: ~/.elengenix/reports/hunt_example_com.md       │
└─────────────────────────────────────────────────────────────┘
```

*(Illustrative session; your output depends on the target.)*

### Try it without a real target

A deliberately vulnerable test app ships with the repo. Point Elengenix at
localhost, or run the offline benchmark (real precision/recall/F1 numbers
against 10 planted vulnerabilities — no external target needed):

```bash
python3 benchmark/run_benchmark.py --json      # single benchmark run
python3 benchmark/run_benchmark.py --history   # past results
```

<img src="assets/red-divider.svg" width="100%">

## Features

### True AI Agent Architecture

Elengenix uses **VulnAgent** — a genuine autonomous AI agent with **free will** over tool selection and execution flow:

```
┌──────────────────────────────────────────────────────────────┐
│                    AI REASONING CYCLE                         │
│                                                              │
│   [REASON] ──► [TOOL SELECT] ──► [EXECUTE] ──► [ADAPT]     │
│      │                                          │            │
│      └──────────────────────────────────────────┘            │
│                    (continuous loop)                          │
└──────────────────────────────────────────────────────────────┘
```

- **No script chains** — AI decides every step, no locked phase ordering
- **25 built-in tools** — from port scanning to fuzzing, all described for AI consumption
- **`edit_own_tool`** — AI can create and modify its own tools at runtime
- **`create_tool`** — AI can author arbitrary Python tools on the fly
- **Cross-session Memory** — Remembers what worked (ChromaDB + Skills JSON store)
- **MCP Auto-start** — MCP server boots in background with every command

### Memory & Skills

Elengenix maintains two persistent stores:

| Store | Format | What it does |
|:-----:|:------:|--------------|
| **Memory** | `~/.elengenix/data/memory.json` | Saves findings, strategies, target patterns across sessions |
| **Skills** | `~/.elengenix/data/skills.json` | Stores reusable tool scripts, exploits, and techniques |

The AI can `memorize()`, `recall()`, `forget()`, `save_skill()`, `recall_skill()`, and `list_skills()` — building up a personal knowledge base over time.

### Safety by Design

Every command passes through a **Governance Layer** before execution:

| Risk Level | Action | Example |
|:----------:|--------|---------|
| **SAFE** | Execute immediately | `nmap`, `curl`, `python3` |
| **PRIVILEGED** | Ask user approval | `sudo apt install`, `pip install` |
| **DESTRUCTIVE** | Show popup (Allow/Allow Always/Deny) | `rm -rf /`, `dd`, `mkfs` |

### MCP Integration

Full support for Model Context Protocol — auto-starts in the background on every command:

```
elengenix scan example.com
    │
    ▼
main() ──► show_banner() ──► start_mcp_if_enabled() ──► MCPServer (2 transports)
                                                                │
                                                     ┌──────────┴──────────┐
                                                     ▼                     ▼
                                              stdio (Claude Desktop)   HTTP (port 8080)
                                              25 dynamic tools         REST API
```

Configure MCP servers via:
```bash
# Via TUI (Ctrl+, → MCP Servers)
# Or edit mcp.json directly
```

Default MCP servers included:
- `sequential-thinking` — Structured problem-solving
- `chain-of-recursive-thoughts` — Deep recursive analysis
- `mcp-structured-thinking` — Step-by-step planning
- `memory` — Cross-session memory

<img src="assets/red-divider.svg" width="100%">

## CLI Commands

### Core

```bash
elengenix hunt <target>       # Autonomous AI vulnerability hunt (VulnAgent)
elengenix scan <target>        # AI-driven scan (equivalent to hunt)
elengenix vuln-hunt <target>   # Full autonomous vulnerability hunting
elengenix tui                  # Textual TUI (chat interface)
elengenix configure            # Setup wizard
elengenix doctor               # System health check
```

**All scan/hunt commands now use VulnAgent** — the same true AI agent with 25 tools, memory, and free will. No script chains, no forced phases.

### Multi-target

```bash
elengenix hunt "example.com, api.example.com"
```

### Shortcuts

| Shortcut | Expands to | Description |
|:--------:|------------|-------------|
| `bb` | `scan --phase bola` | BOLA testing *(deprecated — redirects to VulnAgent)* |
| `check` | `scan --phase recon` | Quick recon *(deprecated — redirects to VulnAgent)* |
| `test` | `scan --phase waf` | WAF detection *(deprecated — redirects to VulnAgent)* |

<img src="assets/red-divider.svg" width="100%">

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                        main.py                               │
│                    (CLI Entry Point)                          │
│  ┌─ MCP auto-start (every boot)                              │
└──────────────────────────┬───────────────────────────────────┘
                           │
          ┌────────────────┴────────────────┐
          ▼                                 ▼
┌─────────────────────┐          ┌─────────────────────────┐
│  VulnAgent           │          │  MCP Server              │
│  (True AI Agent)     │          │  (Background daemon)     │
│                      │          │                          │
│   AVAILABLE_TOOLS    │          │  stdio transport         │
│   ├─ 17 builtin     │          │  HTTP transport          │
│   ├─ 4 memory/skill │          │  25 dynamic tools        │
│   ├─ create_tool    │          └──────────────────────────┘
│   └─ edit_own_tool  │
└──────────┬───────────┘
           │
           ▼
┌─────────────────────┐
│  AgentMemory         │
│  ├─ ChromaDB (FTS5) │
│  └─ JSON stores     │
└─────────────────────┘
```

The old script-driven pipeline (`pipeline/phase_registry`, `pipeline/unified`, `core/brain.py`) has been **fully removed**. Elengenix now runs on a pure AI agent architecture.

<img src="assets/red-divider.svg" width="100%">

## Configuration

### MCP Servers (mcp.json)

```json
{
  "mcpServers": {
    "sequential-thinking": {
      "type": "local",
      "command": ["npx", "-y", "@modelcontextprotocol/server-sequential-thinking"]
    },
    "memory": {
      "type": "local",
      "command": ["npx", "-y", "@modelcontextprotocol/server-memory"]
    }
  }
}
```

Auto-copied from `mcp.json.example` on first run. User config overrides project config.

### AI Providers

Supported: OpenAI, Anthropic, Google Gemini, Groq, DeepSeek, Ollama (local), and more.

```bash
elengenix configure  # Interactive setup wizard
```

Or set the key directly and skip the wizard: `export OPENAI_API_KEY=sk-...`
(any of `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY`,
`DEEPSEEK_API_KEY` works too). Put keys in `~/.elengenix/.env` for
persistence — never commit them.

<img src="assets/red-divider.svg" width="100%">

## Common Issues

**`No AI provider configured` / scan exits immediately.**
Run `elengenix configure` or export a key (`export OPENAI_API_KEY=...`).
No key at all? Use local models: install [Ollama](https://ollama.com),
`ollama pull qwen2.5-coder`, then select Ollama in the wizard.

**`429` / provider rate-limit errors.**
The provider is throttling you. Lower the request rate
(`elengenix scan example.com --rate-limit 2`), wait for the quota window to
reset, or switch providers with `elengenix configure`.

**`Target not reachable` / every probe times out.**
Check the hostname resolves (`ping -c1 example.com`), try the full URL
(`elengenix scan https://example.com`), and confirm you're not behind a
proxy/VPN blocking outbound traffic. Host-only scopes mean the target must
pass `elengenix doctor`'s network check.

**MCP servers fail to start (`npx: command not found`).**
Optional. Install Node.js ≥ 18, or edit `~/.elengenix/mcp.json` and remove
the npm-based entries — Elengenix runs fine with MCP disabled.

**First run hangs on a welcome wizard / download.**
The wizard only runs once; answer it or press Ctrl-C and run
`elengenix configure` manually. Model downloads (sentence-transformers,
~100 MB) happen once and are cached.

**`pip install elengenix` fails to build a dependency.**
Use Python 3.10–3.13 and a venv:
`python3 -m venv .venv && . .venv/bin/activate && pip install elengenix`.
Very new interpreters (3.14+) work but some wheels build from source —
install your distro's `python3-dev` / build tools if so.

**Reports or memory missing.**
Everything lives under `~/.elengenix/` (`reports/`, `data/memory.json`,
`data/skills.json`) — check there, not the source checkout.

<img src="assets/red-divider.svg" width="100%">

## Testing

```bash
# Full test suite (3,150+ tests, ~5 min)
python3 -m pytest tests/ -v

# Brutal integration/security/stress suite
python3 -m pytest tests/brutal/ -v

# Skip network-dependent integration tests
python3 -m pytest tests/ -m "not integration" -v
```

**3,150+ tests** covering: governance, shell execution, target validation, MCP protocol, VulnAgent tools, agent memory, agent skills, report generation (Markdown/HTML/PDF with CVSS v3.1 scoring), and the brutal integration/security/stress suite.

<img src="assets/red-divider.svg" width="100%">

## Project Structure

```text
Elengenix/
├── main.py                 # CLI entry point
├── commands/               # CLI command handlers
│   ├── scan.py             # AI-driven scan (VulnAgent)
│   └── mcp_runner.py       # MCP auto-start helper
├── elengenix/              # Canonical module location
│   ├── agent/              # True AI agent (VulnAgent)
│   │   ├── __init__.py     # Exports VulnAgent
│   │   ├── vuln_agent.py   # Main agent + tool selection
│   │   ├── agent_memory.py # JSON-backed memory store
│   │   ├── agent_skills.py # JSON-backed skill store
│   │   ├── memory.py       # ChromaDB + FTS5 memory
│   │   ├── compat.py       # Scan wrappers over VulnAgent
│   │   └── crew/           # PentAGI-ported multi-agent crew (PrimaryAgent + 15 specialists)
│   ├── chat/               # Interactive chat agent (brain, agent, orchestrator)
│   ├── scanning/           # Scanning subsystems (context, decision engine, loop)
│   ├── reports/            # Report generation (Markdown, HTML, PDF, CVSS v3.1)
│   ├── scope.py            # Target validation & scope
│   ├── paths.py            # Path resolution
│   ├── governance.py       # Governance layer
│   ├── brain.py            # Planning engine
│   └── loop.py             # Main agent loop
├── mcp/                    # MCP integration
│   ├── server.py           # MCP server (25 dynamic tools)
│   ├── client.py           # MCP client
│   ├── config.py           # MCP configuration
│   └── manager.py          # MCP lifecycle
├── tools/                  # 140+ tool modules
├── cli/                    # UI components + TUI (textual.py)
├── tui/                    # Textual TUI application
└── tests/                  # 3,150+ tests (tests/brutal/ = security suite)
```

<img src="assets/red-divider.svg" width="100%">

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Core rules:**
- 4-space indentation
- Type hints everywhere
- Shell commands only behind Governance
- API keys in `.env` only
- AI agents get genuine autonomy — no forced tool ordering

<img src="assets/red-divider.svg" width="100%">

## License

GPL-3.0 — see [LICENSE](LICENSE)

<img src="assets/red-divider.svg" width="100%">

<div align="center">

**Built for the open-source security community.**

[![GitHub Stars](https://img.shields.io/github/stars/Ashveil1/Elengenix?style=for-the-badge&color=red)](https://github.com/Ashveil1/Elengenix)

</div>

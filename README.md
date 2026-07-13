<div align="center">

<img src="assets/elengenix.png" alt="Elengenix" width="700">

<img src="assets/typing-animation.svg" alt="Terminal" width="700">

### Autonomous AI Security Research Framework

*Reasoning-driven vulnerability discovery that thinks like a penetration tester.*

[![Python](https://img.shields.io/badge/Python-3.10+-white?style=for-the-badge&logo=python&logoColor=red)](https://python.org)
[![License](https://img.shields.io/badge/License-GPL_3.0-red?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-334%20passing-white?style=for-the-badge)](https://github.com/Ashveil1/Elengenix/actions)
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

### Install

```bash
pip install elengenix
```

### First Run

```bash
# System health check
elengenix doctor

# Configure AI providers
elengenix configure

# Start an autonomous vulnerability hunt
elengenix hunt example.com
```

### Terminal Demo

```text
┌─────────────────────────────────────────────────────────────┐
│  $ elengenix hunt example.com                                │
│                                                              │
│  ╔═══════════════════════════════════════════════════════╗   │
│  ║  ELENGENIX HUNT — Autonomous AI Vulnerability Hunter   ║   │
│  ╚═══════════════════════════════════════════════════════╝   │
│                                                              │
│  [INFO] Starting autonomous AI hunt...                       │
│  [INFO] Target: example.com                                  │
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
│  [OK] Report: ~/.elengenix/reports/hunt_example_com.md         │
└─────────────────────────────────────────────────────────────┘
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

<img src="assets/red-divider.svg" width="100%">

## Testing

```bash
# Full test suite
python3 -m pytest tests/ -v

# Stable suite (no network)
python3 -m pytest tests/test_tui.py tests/test_security.py tests/test_core_modules.py -v
```

**334 tests** covering: governance, shell execution, target validation, MCP protocol, VulnAgent tools, agent memory, agent skills, and more.

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
│   │   ├── vuln_agent.py   # Main agent + 25 tools
│   │   ├── agent_memory.py # JSON-backed memory store
│   │   ├── agent_skills.py # JSON-backed skill store
│   │   ├── memory.py       # ChromaDB + FTS5 memory
│   │   └── report.py       # Report generation
│   ├── scope.py            # Target validation & scope
│   ├── paths.py            # Path resolution
│   ├── governance.py       # Governance layer
│   ├── scanning/           # Scanning subsystems
│   ├── brain.py            # Hybrid brain (deprecated)
│   └── loop.py             # Main agent loop
├── mcp/                    # MCP integration
│   ├── server.py           # MCP server (25 dynamic tools)
│   ├── client.py           # MCP client
│   ├── config.py           # MCP configuration
│   └── manager.py          # MCP lifecycle
├── tools/                  # 100+ tool modules
├── cli/                    # UI components + TUI (textual.py)
├── core/                   # Legacy (deprecated stubs)
├── pipeline/               # LEGACY: only scope.py remains
├── tests/                  # 334 tests
└── dist/                   # Built wheel
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

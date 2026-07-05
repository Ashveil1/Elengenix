<div align="center">

<img src="assets/color-cycle.svg" alt="Elengenix" width="700">

<img src="assets/typing-animation.svg" alt="Terminal" width="700">

### Autonomous AI Security Research Framework

*Reasoning-driven vulnerability discovery that thinks like a penetration tester.*

[![Python](https://img.shields.io/badge/Python-3.10+-white?style=for-the-badge&logo=python&logoColor=red)](https://python.org)
[![License](https://img.shields.io/badge/License-GPL_3.0-red?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-379%20passing-white?style=for-the-badge)](https://github.com/Ashveil1/Elengenix/actions)
[![MCP](https://img.shields.io/badge/MCP-Supported-red?style=for-the-badge)](https://modelcontextprotocol.io)
[![Security](https://img.shields.io/badge/Security-Governance-red?style=for-the-badge)](https://github.com/Ashveil1/Elengenix)

</div>

---

## What is Elengenix?

Elengenix is an **autonomous AI agent** that performs security research by *thinking* through problems — not by following checklists. It reads a target, builds an attack tree, selects tools, interprets findings, and adapts its strategy in real-time, just like a skilled penetration tester.

```
User: "Find vulnerabilities in example.com"
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  AI Reasoning Engine                                     │
│  ├── Strategic Planning (Attack Tree Generation)        │
│  ├── Tool Selection (120+ security tools)               │
│  ├── Finding Analysis (CVSS, CVE matching)              │
│  └── Strategy Adaptation (real-time re-planning)        │
└─────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Governance Layer                                       │
│  ├── SAFE → Execute immediately                         │
│  ├── PRIVILEGED → Ask user approval                     │
│  └── DESTRUCTIVE → Block with popup                     │
└─────────────────────────────────────────────────────────┘
    │
    ▼
Reports: findings.json, CVSS scores, CVE references
```

---

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

# Start scanning
elengenix scan example.com
```

### Terminal Demo

```
┌─────────────────────────────────────────────────────────────┐
│  $ elengenix scan example.com                               │
│                                                             │
│  [Phase 0] Pre-flight Scan                                 │
│  [OK] Recon: 42 endpoints, 3 ports, 12 subdomains          │
│  [OK] WAF: Cloudflare (conf=0.95)                          │
│  [OK] Fuzz: 128 tests, 3 interesting                       │
│                                                             │
│  [Phase 1] AI-Driven Analysis                              │
│  [AI] Detected: PHP 8.2, MySQL 8.0, WordPress 6.4         │
│  [AI] Attack tree: SQLi → XSS → SSRF → LFI                 │
│  [AI] Testing SQL injection on /api/users...                │
│  [FOUND] Critical: SQL Injection at /api/users?id=          │
│  [FOUND] High: Reflected XSS at /search?q=                 │
│                                                             │
│  [Report] reports/example_com_2024/                         │
│  - elengenix_findings.json (5 findings)                     │
│  - cvss_scores.json (2 Critical, 1 High)                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Features

### AI-Powered Reasoning

Elengenix doesn't just run tools — it **thinks** about what to do next:

```
┌─────────────────────────────────────────────────────────────┐
│                    AI REASONING CYCLE                        │
│                                                             │
│   [PLAN] ──► [EXECUTE] ──► [ANALYZE] ──► [ADAPT]          │
│      │                                         │            │
│      └─────────────────────────────────────────┘            │
│                    (continuous loop)                         │
└─────────────────────────────────────────────────────────────┘
```

- **Attack Tree Planning** — Generates strategic attack plans based on detected tech stack
- **Dynamic Re-planning** — Adapts strategy based on findings and coverage gaps
- **Cross-session Memory** — Remembers what worked on past targets (ChromaDB + SQLite FTS5)
- **Multi-model Team** — Up to 3 AI models collaborate (Strategist, Recon Lead, Exploit Analyst)

### Safety by Design

Every command passes through a **Governance Layer** before execution:

| Risk Level | Action | Example |
|:----------:|--------|---------|
| **SAFE** | Execute immediately | `nmap`, `curl`, `python3` |
| **PRIVILEGED** | Ask user approval | `sudo apt install`, `pip install` |
| **DESTRUCTIVE** | Show popup (Allow/Allow Always/Deny) | `rm -rf /`, `dd`, `mkfs` |

### Pre-flight Scanner (No AI Required)

Even without AI providers, Elengenix produces actionable findings:

| Phase | Module | What it does |
|:-----:|--------|--------------|
| 1 | `PythonRecon` | HTTP probe, directory discovery, port scan, subdomain enum |
| 2 | `SmartWAFDetector` | WAF detection + evasion suggestions |
| 3 | `ActiveFuzzer` | XSS / SQLi / SSTI payload testing |
| 4 | `BOLATester` | Differential IDOR testing |
| 5 | `LearningEngine` | Records findings to SQLite |
| 6 | `CoverageAnalyzer` | Tracks endpoint coverage |

### MCP Integration

Full support for Model Context Protocol — configure MCP servers via:

```bash
# Via TUI (Ctrl+, → MCP Servers)
# Via configure wizard
elengenix configure  # → option 6

# Or edit mcp.json directly
```

Default MCP servers included:
- `sequential-thinking` — Structured problem-solving
- `chain-of-recursive-thoughts` — Deep recursive analysis
- `mcp-structured-thinking` — Step-by-step planning
- `memory` — Cross-session memory

---

## CLI Commands

### Core

```bash
elengenix scan <target>                    # Full automated scan
elengenix scan <target> --phase recon      # Run specific phase only
elengenix scan <target> --interactive bola # Interactive mode (advanced)
elengenix tui                              # Textual TUI
elengenix configure                        # Setup wizard
elengenix doctor                           # System health check
```

### Multi-target

```bash
elengenix scan "example.com, api.example.com, admin.example.com"
```

### Shortcuts

| Shortcut | Expands to | Description |
|:--------:|------------|-------------|
| `bb` | `scan --phase bola` | BOLA testing |
| `check` | `scan --phase recon` | Quick recon |
| `test` | `scan --phase waf` | WAF detection |
| `hack` | `ai` | AI chat mode |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        main.py                               │
│                    (CLI Entry Point)                          │
└──────────────────────────┬───────────────────────────────────┘
                           │
          ┌────────────────┴────────────────┐
          ▼                                 ▼
┌─────────────────────┐          ┌─────────────────────┐
│   core/brain.py     │          │  core/orchestrator.py│
│   (AI Reasoning)    │          │  (Pipeline Engine)   │
└─────────┬───────────┘          └──────────┬──────────┘
          │                                  │
          ▼                                  ▼
┌─────────────────────┐          ┌─────────────────────┐
│  DecisionEngine     │          │  PhaseRegistry       │
│  (AI chooses next)  │          │  (6-phase pipeline)  │
└─────────┬───────────┘          └──────────┬──────────┘
          │                                  │
          ▼                                  ▼
┌─────────────────────┐          ┌─────────────────────┐
│  PostProcessor      │          │  ScopeManager        │
│  (Analyze results)  │          │  (Target validation) │
└─────────┬───────────┘          └──────────┬──────────┘
          │                                  │
          └────────────────┬─────────────────┘
                           ▼
                  ┌─────────────────┐
                  │  Tool Registry  │
                  │  (120+ tools)   │
                  └─────────────────┘
```

---

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

Auto-copied from `mcp.json.example` on first run.

### AI Providers

Supported: OpenAI, Anthropic, Google Gemini, NVIDIA NIM, Groq, DeepSeek, Ollama (local)

```bash
elengenix configure  # Interactive setup wizard
```

---

## Testing

```bash
# Full test suite
python3 -m pytest tests/ -v

# Stable suite (no network)
python3 -m pytest tests/test_tui.py tests/test_security.py tests/test_core_modules.py -v
```

**379+ tests** covering: governance, shell execution, target validation, MCP protocol, scan pipeline, and more.

---

## Project Structure

```
Elengenix/
├── main.py                 # CLI entry point
├── core/                   # Core engine
│   ├── brain.py            # AI reasoning engine
│   ├── orchestrator.py     # Pipeline orchestrator
│   ├── agent.py            # Agent singleton
│   └── scan_engine.py      # Smart scan engine
├── agents/                 # Agent subsystem
│   ├── scan_context.py     # Central state object
│   ├── prompt_builder.py   # AI prompt assembly
│   ├── decision_engine.py  # AI decision making
│   ├── post_processor.py   # Result processing
│   └── scan_loop.py        # Main execution loop
├── pipeline/               # Pipeline modules
│   ├── scope.py            # Target validation
│   ├── phase_registry.py   # Configurable phases
│   └── unified.py          # Unified pipeline entry
├── mcp/                    # MCP integration
│   ├── server.py           # MCP server
│   ├── client.py           # MCP client
│   ├── config.py           # MCP configuration
│   └── manager.py          # MCP lifecycle
├── tools/                  # 120+ security tools
├── cli/                    # UI components
├── tui/                    # Textual TUI
├── commands/               # CLI commands
└── tests/                  # 379+ tests
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Core rules:**
- 4-space indentation
- Type hints everywhere
- Shell commands only behind Governance
- API keys in `.env` only
- Use MCP thinking tools before coding

---

## License

GPL-3.0 — see [LICENSE](LICENSE)

---

<div align="center">

**Built for the open-source security community.**

[![GitHub Stars](https://img.shields.io/github/stars/Ashveil1/Elengenix?style=for-the-badge&color=red)](https://github.com/Ashveil1/Elengenix)

</div>

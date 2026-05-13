<div align="center">

# ELENGENIX v99999 (god nine is the best)

**The Universal AI Agent for Bug Bounty and Security Research**

[![Python](https://img.shields.io/badge/Python-3.10%2B-ff4444?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/License-GPL-ff4444?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-99999-ff4444?style=flat-square)]()

> AI ที่คิดเอง วางแผนเอง เลือก tools เอง — ไม่มีแผนตายตัว ไม่มี whitelist
> แค่ 3 กฎ: SAFE→รัน PRIVILEGED→ถาม DESTRUCTIVE→บล็อก

---

</div>

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Multi-Agent Team](#multi-agent-team)
- [Security Model](#security-model)
- [Project Structure](#project-structure)
- [Commands](#commands)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core AI

| Feature | Description |
|---------|-------------|
| **Autonomous Agent** | AI decides what to do. Recon → scan → exploit → report. Or skip straight to exploit. No fixed methodology. |
| **Universal Mode** | Beyond security — code review, script writing, web research, file editing, package management. |
| **Multi-Agent Team** | Up to 3 AI models collaborate in real-time. Share intel, confirm findings, assign tasks. |
| **Governance System** | SAFE→run immediately, PRIVILEGED→ask user, DESTRUCTIVE→blocked. No whitelist needed. |
| **Self-Writing Tools** | If no tool fits, AI writes a Python script, tests it, fixes it, uses it. |

### Security Arsenal

| Category | Tools |
|----------|-------|
| **Reconnaissance** | subfinder, httpx, naabu, katana, waybackurls, gau, amass |
| **Vulnerability Scan** | nuclei (10,000+ templates), dalfox, ffuf, arjun |
| **Secrets Detection** | trufflehog, github-intel |
| **Exploitation** | SSRF scanner, CORS checker, injection tester, race condition tester |
| **Analysis** | CVSS 3.1/4.0 scoring, exploit chain builder, bounty predictor |
| **Cloud** | AWS/GCP/Azure misconfiguration scanner |
| **Mobile** | Mobile API security testing |
| **ICS/IoT** | Protocol analyzer (MQTT, Modbus, BACnet) |

### Memory & Persistence

| Feature | Backend |
|---------|---------|
| **Vector Memory** | ChromaDB (or SQLite FTS5 fallback, zero deps) |
| **Cross-Session Recall** | Automatic. Recall past findings, conversations, decisions. |
| **Session Manager** | Save/load/resume sessions. Auto-save on exit. |
| **Conversation Compression** | Auto-compress when context exceeds 80% window. |

### UI

| Interface | Description |
|-----------|-------------|
| **Textual TUI v6** | Full terminal UI. Sidebar, governance bar, multi-agent display, mouse support. |
| **Rich CLI** | Interactive chat mode with slash commands. |
| **Settings Overlay** | Ctrl+E floating modal. Change providers, models, rate limits live. |
| **Dashboard** | Web-based scan dashboard (HTML). |

### Integrations

| Service | Purpose |
|---------|---------|
| **OpenAI** | GPT-4o, GPT-4o-mini |
| **Anthropic** | Claude 3.5 Sonnet, 3 Opus, 3 Haiku |
| **Google Gemini** | 1.5 Flash, 1.5 Pro |
| **Groq** | Llama 3, Mixtral (fast inference) |
| **NVIDIA NIM** | Nemotron, Llama on NVIDIA hardware |
| **DeepSeek / Mistral / Perplexity / OpenRouter** | OpenAI-compatible |
| **Ollama** | Local models (llama3, mistral, etc.) |
| **Telegram** | Remote control + notifications |
| **HackerOne** | Bounty program intel |
| **VulnCheck** | CVE intelligence |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      USER INPUT                                  │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     GOVERNANCE GATE                              │
│  classify(command) → DESTRUCTIVE | PRIVILEGED | SAFE             │
│                     │            │           │                    │
│               BLOCKED        ASK USER      RUN                   │
└──────────────────────────────┼──────────────┘                    │
                               │                                   │
                               ▼                                   │
┌─────────────────────────────────────────────────────────────────┐
│                      ELENGENIX AGENT                             │
│  ┌─────────────┐  ┌──────────┐  ┌─────────────────────────┐     │
│  │   Strategic  │  │   Tool   │  │    Analysis Pipeline      │     │
│  │   Planner    │  │ Registry │  │  ┌──────────────────┐   │     │
│  │  (AI plans)  │  │ (90+     │  │  │ Business Logic    │   │     │
│  └─────────────┘  │  tools)  │  │  │ BOLA Bridge       │   │     │
│                   └──────────┘  │  │ WAF Evasion       │   │     │
│  ┌─────────────┐                │  │ SOC Analyzer      │   │     │
│  │ Multi-Agent │                │  │ Exploit Chain     │   │     │
│  │ (Team Aegis)│                │  │ Bounty Predictor  │   │     │
│  └─────────────┘                │  └──────────────────┘   │     │
└─────────────────────────────────────────────────────────────────┘
```

### Agent Freedom Model

```
AI Command ──→ Governance.classify()
                  │
                  ├─ DESTRUCTIVE ───→ ❌ BLOCKED
                  │    rm -rf /, dd, mkfs, fork bomb
                  │
                  ├─ PRIVILEGED ───→ ⏳ ASK USER
                  │    sudo, pip install, go install,
                  │    chmod, write to /etc, apt install
                  │
                  └─ SAFE ─────────→ ✅ RUN IMMEDIATELY
                       curl, nuclei, python3, subfinder,
                       echo, ls, git, nmap, ffuf, ...
```

---

## Quick Start

### Prerequisites

```bash
# Required
python3 --version    # 3.10+
go version           # 1.20+
git --version

# Optional (recommended)
gcc --version        # for CGO-based tools like katana
```

### Installation

```bash
# Clone
git clone https://github.com/Ashveil1/Elengenix.git
cd Elengenix

# Linux / Ubuntu
chmod +x setup.sh
./setup.sh

# Termux (Android)
chmod +x termux_setup.sh
./termux_setup.sh

# Or manual (Python only)
pip install -r requirements.txt
```

### Verify Installation

```bash
elengenix doctor
```

---

## Configuration

### Interactive Wizard

```bash
elengenix configure
```

The wizard guides you through:

1. **AI Providers** — Add API keys for OpenAI, Gemini, Claude, Groq, NVIDIA, etc.
2. **Model Selection** — Choose specific models per provider.
3. **Integrations** — Telegram Bot, HackerOne API, Tavily AI, VulnCheck.
4. **Rate Limits** — Global requests-per-minute per model.
5. **Default Target** — Set a primary target for automated scans.
6. **Health Check** — Verify all security tools are installed.

### Manual `.env`

```env
# ── AI Provider (pick one or more) ──────────────────────
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...
ANTHROPIC_API_KEY=...
GROQ_API_KEY=...
NVIDIA_API_KEY=...

# ── Active provider & models ────────────────────────────
ACTIVE_AI_PROVIDER=openai
ACTIVE_MODELS=openai/gpt-4o-mini,gemini/gemini-1.5-flash

# ── Telegram (optional) ─────────────────────────────────
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...

# ── RPM limits (optional) ───────────────────────────────
RPM_GPT4=40
RPM_CLAUDE=30
```

---

## Usage

### Launch TUI (recommended)

```bash
elengenix cli
```

Full terminal UI with:
- Chat area (scrollable, mouse support)
- Sidebar (target, models, scan stats, context usage)
- Governance bar (shows what AI is doing)
- Settings overlay (Ctrl+E)
- Multi-agent display

### Interactive CLI

```bash
elengenix ai
```

### Full Scan

```bash
elengenix scan example.com
elengenix scan example.com --smart-scan       # Smart orchestrator
```

### Single Commands

| Command | Description |
|---------|-------------|
| `elenginx doctor` | System health check |
| `elenginx configure` | Configuration wizard |
| `elenginx arsenal` | Browse available tools |
| `elenginx mission <target>` | Start a mission |
| `elenginx sast <path>` | Static code analysis |
| `elenginx research <cve>` | CVE/vulnerability research |
| `elenginx bounty <program>` | HackerOne program intel |
| `elenginx report` | View last scan report |
| `elenginx cve-update` | Update CVE database |
| `elenginx watchman` | Start 24/7 monitoring |

### TUI Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+R` | Toggle research mode |
| `Ctrl+B` | Toggle scan mode |
| `Ctrl+T` | Toggle thinking (NVIDIA) |
| `Ctrl+P` | Show active model |
| `Ctrl+G` | Help |
| `Ctrl+E` | Settings overlay |
| `Ctrl+U` | Scroll up |
| `Ctrl+D` | Scroll down |
| `↑` / `↓` | Input history |

### TUI Slash Commands

| Command | Description |
|---------|-------------|
| `/help` | Show help |
| `/clear` | Clear chat |
| `/reset` | Reset conversation |
| `/mode <x>` | Set mode: auto, research, scan, casual |
| `/target <x>` | Set target domain |
| `/talk <n>` | Talk to agent 1, 2, 3, or all |
| `/session` | Show session info |
| `/session new` | New session (auto-save) |
| `/session list` | List saved sessions |
| `/stats` | Memory statistics |
| `/team` | Show active team |
| `/quit` | Exit |

---

## Multi-Agent Team

Up to 3 AI models work together as a security research team.

### Setup

```bash
export ACTIVE_MODELS="openai/gpt-4o,anthropic/claude-3-sonnet,gemini/gemini-1.5-flash"
elengenix cli
```

### How It Works

```
Round 1:
  Elengix 1: "Running subfinder on target..."
  Elengix 2: "I'll scan with nuclei in parallel"
  Elengix 3: "Searching for CVE intel"

  ▶ SAFE subfinder -d target.com
  ▶ SAFE nuclei -u target.com

Round 2:
  Elengix 1: "Found XSS at /search — needs confirmation"
  Elengix 2: "Confirmed XSS at /search — WAF bypass possible"
  Elengix 3: "Found API key in JS — critical"

  ▶ PRIVILEGED go install dalfox... (asks user)
```

### Talk to Specific Agent

```
/talk 1     →  Talk to Elengix 1
/talk 2     →  Talk to Elengix 2
/talk 3     →  Talk to Elengix 3
/talk all   →  Back to full team mode
```

---

## Security Model

Elengenix uses a **Governance-based security model** — no whitelists, no fixed allowlists.

### Three Risk Levels

| Level | Examples | Action |
|-------|----------|--------|
| **DESTRUCTIVE** | `rm -rf /`, `dd if=/dev/zero`, `mkfs.ext4`, fork bomb | **Blocked** — cannot be executed |
| **PRIVILEGED** | `sudo`, `pip install`, `go install`, `chmod`, write to `/etc` | **Ask user** — command is shown before execution |
| **SAFE** | `curl`, `nuclei`, `python3`, `ls`, `echo`, `git`, `nmap` | **Run immediately** — no questions asked |

### Defense Layers

```
Layer 1: Governance.classify(command)   → DESTRUCTIVE / PRIVILEGED / SAFE
Layer 2: safe_exec.execute_safely()     → shell=False + metacharacter blocking
Layer 3: subprocess.run(..., shell=False)→ OS-level execve, no shell injection
```

### What Changed from v3 to v99999

| Aspect | Before | Now |
|--------|--------|-----|
| Tool allowlist | 19 tools whitelist | **Removed** — any binary allowed |
| Command allowlist | 50 commands | **Removed** — governance handles it |
| Binary allowlist | `ALLOWED_BINARIES` | **Removed** — empty sentinel |
| Agent planning | 5-phase fixed methodology | **AI decides** — no fixed plan |
| Binary path check | `os.path.basename()` only | `shutil.which()` resolves full PATH |
| Event loop | New loop per tool call | Shared persistent loop |
| Memory fallback | Single summary blob | SQLite FTS5 full-text search |
| UI theme | Basic colors | Minimal theme (black/red/white/gray/orange) |

---

## Project Structure

```
├── main.py                 # CLI entry point — argparse command router
├── agent_brain.py          # ElengenixAgent — core AI engine
├── cli_textual.py          # Textual TUI v6 — Catppuccin minimal theme
├── cli.py                  # Legacy interactive CLI mode
├── orchestrator.py         # Tool pipeline orchestrator + scope management
├── ui_components.py        # Shared UI components (colors, banners, tables)
├── agent.py                # Agent factory bridge
├── dependency_manager.py   # Go tool installer (subfinder, nuclei, etc.)
├── knowledge_loader.py     # Secure knowledge base loader
│
├── tools/
│   ├── governance.py           # Risk classification engine
│   ├── analysis_pipeline.py    # 13 post-finding analyzers
│   ├── universal_ai_client.py  # OpenAI-compatible AI client
│   ├── universal_executor.py   # Universal shell executor
│   ├── safe_exec.py            # Metacharacter-safe execution
│   ├── vector_memory.py        # ChromaDB / SQLite FTS5 memory
│   ├── token_counter.py        # tiktoken token counting
│   ├── multi_agent.py          # Team Aegis engine
│   ├── tool_registry.py        # Plugin system (90+ tools)
│   ├── session_manager.py      # Session save/load/resume
│   ├── context_compressor.py   # Conversation compression
│   ├── mission_state.py        # Mission state graph
│   ├── cvss_calculator.py      # CVSS 3.1/4.0 scoring
│   ├── cve_database.py         # Local CVE database
│   ├── bounty_reporter.py      # Bug bounty report generator
│   ├── bounty_predictor.py     # ML-based payout prediction
│   ├── exploit_chain_builder.py# Attack path discovery
│   ├── soc_analyzer.py         # Sigma rule generation
│   ├── sast_engine.py          # Static code analysis
│   ├── cloud_scanner.py        # Cloud misconfiguration scanner
│   ├── mobile_api_tester.py    # Mobile API security testing
│   ├── protocol_analyzer.py    # IoT/ICS protocol analyzer
│   ├── config_wizard.py        # Configuration wizard
│   ├── welcome_wizard.py       # First-run wizard
│   ├── autonomous_agent.py     # Full autonomous mode
│   ├── swarm_controller.py     # Multi-target parallel execution
│   └── ... (80+ more modules)
│
├── prompts/
│   └── system_prompt.txt       # AI system instruction
│
├── knowledge/
│   └── methodology.md          # Bug bounty methodology
│
├── tests/
│   ├── test_security.py        # Security path tests
│   ├── test_overlay.py         # Settings overlay tests
│   ├── test_skill_team.py      # Multi-agent skill tests
│   └── conftest.py
│
├── data/
│   ├── vector_memory/          # ChromaDB persistent storage
│   ├── cot_logs/               # Chain-of-thought logs
│   ├── missions/               # Mission state snapshots
│   ├── scan_state/             # Smart scan state cache
│   └── sessions/               # Saved sessions (gitignored)
│
├── setup.sh                    # Linux / Ubuntu installer
├── termux_setup.sh             # Termux (Android) installer
├── requirements.txt            # Python dependencies
├── config.yaml.example         # Configuration template
└── .env.example                # Environment template
```

---

## Testing

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific test file
python3 -m pytest tests/test_security.py -v

# Run with coverage (if pytest-cov installed)
python3 -m pytest tests/ --cov=. --cov-report=term
```

---

## Commands Reference

### System

```bash
elengenix doctor                # Full system health check
elenginx configure              # Configuration wizard
elenginx update                 # Update dependencies
elenginx cve-update             # Update CVE database
```

### Scanning

```bash
elengenix scan <target>         # Full scan pipeline
elenginx scan <target> --smart-scan  # With smart orchestrator
elenginx autonomous <target>    # Full autonomous mode
elenginx arsenal                # Browse/run tools
```

### Analysis

```bash
elenginx research <cve>         # CVE/vulnerability research
elenginx sast <path>            # Static code analysis
elenginx cloud <path>           # Cloud config scan
elenginx mobile <target>        # Mobile API testing
elenginx memory                 # View memory stats
```

### Reporting

```bash
elenginx report                 # View last report
elenginx pdf <target>           # Generate PDF report
elenginx bounty <program>       # Bounty program intel
```

### Monitoring

```bash
elenginx watchman               # Start 24/7 monitoring daemon
elenginx gateway                # Start Telegram gateway
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v99999 | 2026 | God Nine Edition. Governance security model, multi-agent, FTS5 memory, Textual TUI v6. |
| v5.0 | 2026 | Universal agent mode, analysis pipeline, Team Aegis. |
| v3.0 | 2025 | Tool registry, CVSS scoring, vector memory. |
| v2.0 | 2025 | CLI rewrite, agent bridge, Telegram gateway. |
| v1.0 | 2024 | Initial release. |

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Rules

- 4-space indentation (no tabs)
- Type hints on all function signatures
- Docstrings on modules, classes, and public functions
- API keys go in `.env`, never in `config.yaml`

---

## License

GPL License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Developed by Ashveil1**

*"god nine is the best"*

</div>

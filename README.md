# ELENGENIX v99999 (god nine is the best)

**The Universal AI Agent for Bug Bounty and Security Research.**

Elengenix is a next-generation security framework that combines the reasoning capabilities of Large Language Models (LLMs) with a professional-grade security toolchain. AI plans, executes, and adapts — no fixed methodology, full autonomy.

---

## Key Features

- **Autonomous AI Agent** — AI thinks, plans, and executes. No fixed methodology. Full shell access. Writes its own tools.
- **Multi-Agent Team (Team Aegis)** — Up to 3 AI models collaborate in real-time. Share findings, confirm vulnerabilities, assign tasks.
- **Governance System** — Commands classified as SAFE (auto), PRIVILEGED (ask user), DESTRUCTIVE (blocked).
- **Security Arsenal** — 90+ integrated tools: Subfinder, Nuclei, Httpx, Katana, Dalfox, FFUF, Naabu, TruffleHog, Arjun, and more.
- **Permanent Memory** — ChromaDB vector memory (SQLite FTS5 fallback, zero deps). Cross-session recall.
- **CVSS Scoring** — All findings auto-scored with CVSS 3.1/4.0, CVE database lookup, exploit chain analysis.
- **Telegram Gateway** — Remote control and monitoring via Telegram bot.
- **Watchman Daemon** — 24/7 continuous target monitoring with change detection and AI analysis.
- **Professional TUI** — Textual v6.0 interface with sidebar, governance bar, multi-agent display.
- **Tool Auto-Install** — Detects missing tools and asks user before installing.

---

## Hardware & Backend Support

| Provider | Status |
|----------|--------|
| OpenAI (GPT-4o, GPT-4o-mini) | Full |
| Anthropic (Claude 3.5 Sonnet, 3 Opus) | Full |
| Google Gemini (1.5 Flash, 1.5 Pro) | Full |
| Groq (Llama 3, Mixtral) | Full |
| NVIDIA NIM (Nemotron, Llama) | Full |
| DeepSeek, Mistral, Perplexity, OpenRouter | Full |
| Ollama (local, all models) | Full |
| AMD ROCm | In Progress |

---

## Quick Start

### Prerequisites

- Python 3.10+
- Go 1.20+ (for security tool compilation)
- Git

### Installation

```bash
git clone https://github.com/Ashveil1/Elengenix.git
cd Elengenix

# Linux/Ubuntu:
chmod +x setup.sh && ./setup.sh

# Termux (Android):
chmod +x termux_setup.sh && ./termux_setup.sh

# Or just Python deps:
pip install -r requirements.txt
```

---

## Configuration

```bash
elengenix configure
```

Interactive wizard for:
1. **AI Providers** — API keys for OpenAI, Gemini, Anthropic, Groq, NVIDIA, etc.
2. **Model Selection** — Choose specific models per provider.
3. **Integrations** — Telegram Bot, HackerOne API, Tavily AI, VulnCheck.
4. **Rate Limits** — Global RPM limits per model.
5. **System Health** — Verify all security tools are installed.

### Manual `.env`

```env
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...
ANTHROPIC_API_KEY=...
TELEGRAM_BOT_TOKEN=...
ACTIVE_MODELS=openai/gpt-4o-mini,gemini/gemini-1.5-flash,anthropic/claude-3-haiku
```

---

## Usage

### Full-Scale Scan

```bash
elengenix scan example.com
elengenix scan example.com --smart-scan      # Smart Orchestrator
```

### AI Chat (TUI)

```bash
elengenix cli                               # Textual TUI (recommended)
elenginx ai                                 # AI partner mode
```

### Multi-Agent Team

```bash
export ACTIVE_MODELS="openai/gpt-4o,anthropic/claude-3-sonnet,gemini/gemini-1.5-pro"
elenginx cli
# Then: /talk 1  /talk 2  /talk 3  /talk all
```

### Single Commands

| Command | Description |
|---------|-------------|
| `elenginx doctor` | System health check |
| `elenginx mission <target>` | Start a mission |
| `elenginx arsenal` | Browse security tools |
| `elenginx sast <path>` | Static code analysis |
| `elenginx research <cve>` | Vulnerability research |
| `elenginx bounty <program>` | Bounty program intel |
| `elenginx report` | View last scan report |
| `elenginx help` | Show all commands |

### TUI Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+R` | Toggle research mode |
| `Ctrl+B` | Toggle scan mode |
| `Ctrl+T` | Toggle thinking mode |
| `Ctrl+P` | Show active model |
| `Ctrl+G` | Help |
| `Ctrl+E` | Settings overlay |
| `Ctrl+U/D` | Scroll up/down |
| `↑/↓` | Input history |

---

## Architecture

```
main.py ───── CLI Entry Point
  ├─ route → orchestrator.py (scan pipeline)
  │            └─ ToolRegistry → BaseTool.execute() → shell=False
  ├─ route → cli_textual.py (Textual TUI v6)
  │            └─ agent_brain.py (ElengenixAgent)
  │                 ├─ AIClientManager (universal_ai_client)
  │                 ├─ Governance (SAFE/PRIVILEGED/DESTRUCTIVE)
  │                 ├─ ToolRegistry (90+ plugins)
  │                 ├─ AnalysisPipeline (13 analyzers)
  │                 └─ VectorMemory (ChromaDB / FTS5)
  └─ route → multi_agent.py (Team Aegis)
               └─ 3 AI agents: discuss, share intel, confirm findings
```

### Agent Freedom Model

```
User Input
  └─ Governance.gate(command)
       ├─ DESTRUCTIVE (rm -rf /, dd, mkfs, fork bomb) → DENY
       ├─ PRIVILEGED (sudo, pip install, go install) → ASK USER
       └─ SAFE (everything else: curl, nuclei, python3, ...) → RUN
```

---

## Project Structure

```
├── main.py                 # CLI entry point, command router
├── agent_brain.py          # ElengenixAgent — core AI engine (2450 lines)
├── cli_textual.py          # Textual TUI v6 (Catppuccin theme)
├── cli.py                  # Legacy CLI mode
├── orchestrator.py         # Tool pipeline orchestrator
├── ui_components.py        # Shared UI components (Catppuccin theme)
├── tools/
│   ├── analysis_pipeline.py    # 13 post-finding analyzers
│   ├── governance.py           # Risk classification engine
│   ├── universal_ai_client.py  # OpenAI-compatible AI client
│   ├── universal_executor.py   # Universal shell executor
│   ├── safe_exec.py            # Metacharacter-safe execution
│   ├── vector_memory.py        # ChromaDB / FTS5 memory
│   ├── token_counter.py        # tiktoken token counting
│   ├── multi_agent.py          # Team Aegis engine
│   ├── tool_registry.py        # Plugin system (90+ tools)
│   ├── session_manager.py      # Session persistence
│   └── ... (80+ more tool modules)
├── prompts/
│   └── system_prompt.txt       # AI system prompt
├── data/                       # Runtime data, logs, memory
├── tests/                      # pytest test suite
├── setup.sh                    # Linux installer
├── termux_setup.sh             # Termux (Android) installer
└── requirements.txt            # Python dependencies
```

---

## Test

```bash
python3 -m pytest tests/ -v
```

---

## License

GPL License — see [LICENSE](LICENSE).

---

Developed by Ashveil1.

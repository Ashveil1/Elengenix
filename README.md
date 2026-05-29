<div align="center">

# ELENGENIX

### Autonomous AI Agent Framework for Security Research

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)](https://python.org)
[![Go](https://img.shields.io/badge/Go-1.20%2B-00ADD8?style=flat-square)](https://golang.org)
[![License](https://img.shields.io/badge/License-GPL-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen?style=flat-square)]()

</div>

---

## What is Elengenix?

Elengenix is an open-source framework that turns security research into a reasoning problem. Rather than scripting fixed attack sequences, it deploys an AI agent that reads a target, builds an attack tree, selects tools, interprets findings, and adapts its strategy in real-time — the same way a skilled penetration tester thinks.

It is designed to be **provider-agnostic**, **mobile-deployable** (Termux), and **safe by design**: every command passes through a governance engine that blocks destructive operations without limiting research flexibility.

---

## Why It Exists

The current state of security tooling has a fundamental gap: tools are powerful, but brittle. They require deep expertise to chain together, produce unfiltered noise, and cannot reason about what a finding actually means in the context of a target's architecture.

Elengenix exists to close this gap — to give researchers a collaborator that understands both the technical and business dimensions of a vulnerability, can estimate its exploitability and payout value, and documents the full chain of evidence automatically.

---

## Core Design Principles

- **Reasoning over rules** — The agent dynamically constructs its attack plan from a live understanding of the target, not a predefined checklist.
- **Multi-model collaboration** — Up to 3 AI models work as a team (Strategist, Recon Lead, Exploit Analyst), cross-validating findings and sharing context.
- **Safety without friction** — A governance layer classifies every action as SAFE, PRIVILEGED, or DESTRUCTIVE. Dangerous commands are blocked; sensitive ones require user confirmation; safe ones execute immediately.
- **Memory across sessions** — Findings, decisions, and context persist across sessions via semantic vector memory (ChromaDB / SQLite FTS5 fallback).

---

## Quick Start

**Prerequisites:** Python 3.10+, Go 1.20+

```bash
git clone https://github.com/Ashveil1/Elengenix.git && cd Elengenix

# Install dependencies (Python + Go security tools)
chmod +x setup.sh && ./setup.sh

# Verify environment
elengenix doctor

# Configure AI providers
elengenix configure
```

*Supports Android via Termux: `chmod +x termux_setup.sh && ./termux_setup.sh`*

---

## Usage

### Terminal UI
```bash
elengenix tui
```

Two operational modes:
- **CHILL** — Safe research, chat, code review. Tool execution disabled.
- **HUNT** — Full autonomous vulnerability hunting.

| Key | Action |
|-----|--------|
| `Ctrl+M` | Toggle CHILL / HUNT |
| `Ctrl+S` | Settings overlay |
| `Ctrl+G` | Help |

### Slash Commands
```
/target <domain>        Set target scope
/mode <chill|hunt>      Switch mode
/talk <1|2|3|all>       Route to specific agent in the team
/session <new|list|load> Manage sessions
/stats                  Memory & scan statistics
```

### CLI Commands
```bash
elengenix scan <target>       # Full automated scan pipeline
elengenix autonomous <target> # Fully autonomous mode
elengenix sast <path>         # Static code analysis
elengenix research <cve>      # CVE / exploit research
elengenix watchman            # 24/7 monitoring daemon
```

---

## Architecture

```
User Input ──► Governance Gate ──► AI Reasoning Engine
                                          │
                     ┌────────────────────┼────────────────────┐
                     ▼                    ▼                    ▼
               Attack Planner      Tool Registry         Analysis Pipeline
               (Dynamic tree)      (90+ tools)           (BOLA, CVSS, WAF,
                                                          SOC, Exploit Chain)
                                          │
                                   Vector Memory
                                   (Cross-session recall)
```

---

## AI Providers Supported

OpenAI · Anthropic · Google Gemini · Groq · NVIDIA NIM · Mistral · DeepSeek · Perplexity · OpenRouter · Ollama (local)

---

## Testing

```bash
python3 -m pytest tests/ -v
```

Test coverage includes: governance enforcement, metacharacter injection prevention, target validation, multi-agent coordination, and session management.

---

## Project Structure

```
main.py              # CLI router
agent_brain.py       # Core AI reasoning engine
cli_textual.py       # Terminal UI (Textual)
tools/
  governance.py      # Risk classification engine
  multi_agent.py     # Team Aegis collaboration (up to 3 models)
  analysis_pipeline.py  # Post-finding analysis (CVSS, BOLA, chains)
  vector_memory.py   # Semantic memory (ChromaDB / SQLite FTS5)
  safe_exec.py       # Metacharacter-safe subprocess execution
tests/               # pytest test suite
knowledge/           # Security methodology documentation
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for code standards, logging conventions, and security rules.

**Core rules:** 4-space indent · type hints everywhere · no `shell=True` · API keys in `.env` only

---

## License

GPL License — see [LICENSE](LICENSE).

---

## ⚡ Compute Sponsorship & API Integration

We are incredibly grateful to the **AMD AI Cloud** program for sponsoring the high-performance compute infrastructure powered by **AMD Instinct™ MI300X** accelerators.

Rather than competing with general-purpose frontier models, Elengenix is built on a **hybrid-intelligence model**:
- **Downstream Utility Specialization** — We leverage local AMD accelerators to pre-process large security data sets, run high-frequency log parsing, and train specialized, lightweight helper models (e.g., 7B/8B parameter models) for specific local formatting and regex extraction tasks.
- **Frontier API Orchestration** — The main strategic planners, multi-agent consensus logic, and high-level reasoning systems are designed to consume frontier APIs like Claude and GPT. These models act as the master orchestrators that direct our local utilities.

---

<div align="center">

*Built by independent security researchers, for the open-source security community.*

</div>

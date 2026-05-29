# Changelog

All notable changes to Elengenix will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/).

---

## [1.0.0] — 2026-05-29

### Core
- Autonomous AI reasoning engine with dynamic attack tree planning
- Multi-model collaboration (Team Aegis — up to 3 agents)
- Governance security gate (SAFE / PRIVILEGED / DESTRUCTIVE classification)
- Cross-session semantic vector memory (ChromaDB + SQLite FTS5 fallback)
- Session save, load, and resume system

### Terminal UI
- Textual-based TUI with CHILL and HUNT operational modes
- Sidebar with live stats, rolling counters, and mode animations
- Settings overlay, help overlay, and slash-command autocomplete
- Responsive sidebar auto-collapse on compact screens (< 95 columns)

### Security Tools
- 90+ integrated tool modules (subfinder, nuclei, httpx, ffuf, dalfox, etc.)
- Analysis pipeline: CVSS scoring, BOLA/IDOR probing, exploit chain builder, SOC analyzer, bounty predictor
- Static analysis engine (Python, JS, Go, Java, PHP)
- Cloud/IaC scanner (Terraform, AWS, GCP, Azure)

### Integrations
- Provider-agnostic LLM client (OpenAI, Anthropic, Gemini, Groq, NVIDIA, Mistral, Ollama, etc.)
- Telegram bot gateway for remote control and notifications
- HackerOne bounty program intelligence
- VulnCheck CVE database integration

### Platform Support
- Linux / Ubuntu auto-installer (`setup.sh`)
- Android / Termux auto-installer (`termux_setup.sh`)

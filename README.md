# Elengenix

An AI-powered framework for automated bug bounty hunting and security research.
Autonomous reconnaissance, multi-model LLM support, and real-time reporting via Telegram and CLI.

> **Status**: Active development. Core pipeline works. AI agent loop and memory system being improved.

---

## Features

- **Multi-Model AI**: Gemini, OpenAI, Claude, Groq, OpenRouter, and local LLMs via Ollama
- **Autonomous Pipeline**: Recon → Scan → JS Analysis → Parameter Mining → Reporting
- **Telegram Integration**: Control scans and receive findings directly on your phone
- **Self-Healing**: Auto-detects and installs missing tools
- **Secret Discovery**: Extracts API keys and secrets from JavaScript files in real time
- **Continuous Learning**: Remembers findings per target to improve future scans

---

## Quick Start

### Linux / macOS / WSL

```bash
git clone https://github.com/Ashveil1/Elengenix.git
cd Elengenix
bash setup.sh
elengenix
```

### Termux (Android)

```bash
git clone https://github.com/Ashveil1/Elengenix.git
cd Elengenix
bash termux_setup.sh
python main.py
```

---

## Built-in Tools

| Tool | Purpose |
|------|---------|
| subfinder | Subdomain enumeration |
| httpx | Live host discovery |
| nuclei | Vulnerability scanning (5,000+ templates) |
| katana / waybackurls | Advanced crawling |
| js_analyzer, param_miner, cors_checker | Deep analysis |

---

## Knowledge Base

Drop any bug bounty write-ups or methodology files into the `knowledge/` directory.
The AI will load and apply them during future scans.

---

## License

MIT — see `LICENSE` for details.
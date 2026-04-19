# 🛡️ ELENGENIX AI AGENT

**Elengenix** is a modern, AI-powered Bug Bounty Framework designed for autonomous security research. It bridges the gap between classic automation and intelligent decision-making, providing a personal "Bug Hunter Partner" right in your terminal and Telegram.

---

## ✨ Key Features

- **🧠 Multi-Model AI Partner**: Support for Gemini, OpenAI, Claude, Groq, OpenRouter, and **Local LLMs (Ollama)**.
- **🚀 Autonomous Pipeline**: Recon -> Scan -> Deep JS Analysis -> Parameter Mining -> Reporting.
- **📱 Telegram Command Center**: Control your scans and receive real-time alerts with detailed findings directly to your phone.
- **🛠️ Self-Healing Dependencies**: Automatically detects and offers to install missing tools like `subfinder`, `nuclei`, `httpx`, `katana`, and `waybackurls`.
- **🔑 Real-time Secret Discovery**: Extracts API keys and secrets from JavaScript files and notifies you instantly with beautiful Terminal panels.
- **💾 Continuous Learning**: AI remembers previous findings and improves its strategy every time it hunts.

---

## 🚀 Quick Start

### For Linux / macOS / WSL:
1. **Clone and Install:**
```bash
git clone https://github.com/Ashveil1/Elengenix.git
cd Elengenix
bash setup.sh
```
2. **Start Hunting:**
```bash
elengenix
```

### For Termux (Android):
1. **Clone and Install:**
```bash
git clone https://github.com/Ashveil1/Elengenix.git
cd Elengenix
bash termux_setup.sh
```
2. **Start Hunting:**
```bash
python main.py
```

---

## 🛠️ Built-in Tools & Arsenal
- **Vertical Recon**: `subfinder`
- **Live Host Discovery**: `httpx`
- **Vulnerability Scanner**: `nuclei` (5,000+ templates)
- **Advanced Crawling**: `katana`, `waybackurls`
- **Specialized Analysis**: `js_analyzer`, `api_finder`, `param_miner`, `cors_checker`

---

## 📚 Knowledge Base
Elengenix comes with a built-in `knowledge/` directory. Add any bug bounty write-ups or methodologies, and the AI will learn and apply them to future scans.

---

## ⚖️ License
Distributed under the MIT License. See `LICENSE` for more information.

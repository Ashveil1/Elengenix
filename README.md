# 🛡️ Elengenix AI Agent

**Elengenix** is a modern, AI-powered Bug Bounty Framework designed for autonomous security research. It bridges the gap between classic automation and intelligent decision-making, providing a personal "Bug Hunter Partner" right in your terminal and Telegram.

---

## ✨ Key Features

- **🧠 Multi-Model AI Partner**: Support for Gemini, OpenAI, Claude, Groq, and **Local LLMs (Ollama)**.
- **🚀 Autonomous Pipeline**: Recon -> Scan -> Deep JS Analysis -> Parameter Mining -> Reporting.
- **📱 Telegram Command Center**: Control your scans and receive real-time alerts with detailed findings directly to your phone.
- **🛠️ Self-Healing Dependencies**: Automatically detects and offers to install missing tools like `subfinder`, `nuclei`, `httpx`, `katana`, and `waybackurls`.
- **🔑 Real-time Secret Discovery**: Extracts API keys and secrets from JavaScript files and notifies you instantly with beautiful Terminal panels.
- **📦 Custom Script Generation**: AI can write and execute its own scripts to exploit unique situations.

---

## 🚀 Quick Start

1. **Clone and Install:**
```bash
git clone https://github.com/YOUR_USERNAME/Elengenix.git
cd Elengenix
bash setup.sh
```

2. **Start Hunting:**
Just type one command from anywhere:
```bash
elengenix
```

---

## 🛠️ Built-in Tools
- **Vertical Recon**: `subfinder`
- **Live Host Discovery**: `httpx`
- **Vulnerability Scanner**: `nuclei`
- **Advanced Crawling**: `katana`, `waybackurls`
- **Specialized Analysis**: `js_analyzer`, `param_miner`, `cors_checker`

---

## 📚 Knowledge Base
Elengenix comes with a built-in `knowledge/` directory. Add any bug bounty write-ups or methodologies, and the AI will learn and apply them to future scans.

---

## ⚖️ License
Distributed under the MIT License. See `LICENSE` for more information.

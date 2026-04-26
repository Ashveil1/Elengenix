# ELENGENIX AI v2.0.0
## Universal AI Agent for Bug Bounty & Security Research

**Version:** 2.0.0 (Universal Agent Edition)  
**Platforms:** Linux, macOS, Android (Termux)  
**License:** GNU GPL v3 (Ethical Use Only)

---

## 🎯 What is Elengenix?

Elengenix is a **Universal AI Agent** that combines the flexibility of Claude Code with deep penetration testing expertise. It doesn't just run tools—it **thinks strategically**, adapts to findings, and remembers everything across sessions.

### Key Capabilities:
- **Universal Agent Mode:** File editing, package management, script development
- **Bug Bounty Specialist:** 4-phase methodology with strategic planning
- **Persistent Memory:** Vector database remembers all past sessions
- **Real-time Monitoring:** Tmux split-screen shows every action
- **8+ Security Tools:** Fully integrated recon-to-exploitation pipeline

---

## ✨ What's New in v2.0.0

### 🆕 Universal Agent Mode
- Read/write/edit files like Claude Code
- Install packages (pip, npm, apt, go, gem)
- Execute shell commands with safety filtering
- Search web for CVEs and exploits
- Generate custom exploit scripts

### 🆕 Strategic Planning Engine
- AI generates Attack Trees automatically
- 4-phase methodology: Recon → Enum → Scanning → Exploitation
- Adaptive strategy that adds steps based on findings
- Chain of Thought logging for full audit trail

### 🆕 Vector Memory System
- **ChromaDB** for semantic memory (remembers meaning, not just words)
- Cross-session persistence (restart and continue)
- SQLite fallback for lightweight environments
- Recall related memories automatically

### 🆕 Tmux Split-Screen Mode
- Left pane: Chat with AI
- Right pane: Real-time activity monitor
- See every tool execution, thought, and result live
- Auto-detection with user prompt

### 🆕 CVSS Calculator
- Automatic severity scoring (CVSS 3.1/4.0)
- AI-assisted impact analysis
- Priority-based exploitation paths

---

## 🚀 Quick Start

### Installation

**Linux/macOS:**
```bash
git clone https://github.com/Ashveil1/Elengenix.git
cd Elengenix
chmod +x setup.sh
./setup.sh
```

**Android (Termux):**
```bash
git clone https://github.com/Ashveil1/Elengenix.git
cd Elengenix
chmod +x termux_setup.sh
./termux_setup.sh
```

### Configuration
```bash
cp .env.example .env
# Edit .env with your API keys:
# - GEMINI_API_KEY (or OPENAI_API_KEY, ANTHROPIC_API_KEY)
# - TELEGRAM_BOT_TOKEN (optional)
# - TELEGRAM_CHAT_ID (optional)
```

### Launch
```bash
elengenix                    # Interactive menu
elengenix ai                 # AI Partner (auto tmux)
elengenix universal          # Universal Agent (auto tmux)
elengenix scan example.com   # Automated scan
```

---

## 📖 Usage Guide

### 1. AI Partner Mode (Recommended)
```bash
elengenix ai
```
- **Auto-detects tmux:** Asks if you want split-screen
- **Auto-selects mode:** Universal for general tasks, Bug Bounty for security
- **Commands:**
  - `/help` - Show commands
  - `/mode` - Switch agent type
  - `/target example.com` - Set target
  - `/exit` - Quit

### 2. Universal Agent Mode
```bash
elengenix universal
```
**Example interactions:**
```
You: Install requests and create a script to test SQL injection
→ Agent installs requests, writes script, runs it

You: Search for CVE-2024-XXXX exploits
→ Agent searches web, finds PoCs, analyzes them

You: Edit config.yaml to add new API key
→ Agent reads file, locates section, edits it
```

### 3. Bug Bounty Mode
```bash
elengenix ai
You: scan example.com for vulnerabilities
```
**What happens:**
1. Strategy Generation: AI creates 8-step attack tree
2. Recon: subfinder → naabu → httpx
3. Enumeration: ffuf → arjun → trufflehog
4. Scanning: nuclei
5. Exploitation: dalfox
6. Report: CVSS scores + findings summary

### 4. Manual Tool Arsenal
```bash
elengenix arsenal
```
Select individual tools:
- Omni-Scan (full pipeline)
- Recon (subdomain enumeration)
- Vuln Scanner (Nuclei)
- API Hunter
- JS Analyzer
- Param Miner
- Google Dorking
- AI Research

### 5. Memory Management
```bash
elengenix memory
```
- View memory statistics
- Search past sessions
- List known targets
- Clear specific target memories

### 6. Health Check
```bash
elengenix doctor
# or with auto-repair:
elengenix doctor --fix
```

---

## 🛠️ Integrated Security Tools

| Tool | Purpose | Category |
|------|---------|----------|
| **subfinder** | Subdomain discovery | Recon |
| **httpx** | HTTP prober + tech detection | Recon |
| **naabu** | Port scanner | Recon |
| **katana** | Web crawler | Enumeration |
| **ffuf** | Directory fuzzer | Enumeration |
| **arjun** | Parameter discovery | Enumeration |
| **trufflehog** | Secret/credential detection | Enumeration |
| **nuclei** | Vulnerability scanner (CVEs) | Scanning |
| **dalfox** | XSS scanner with PoC | Exploitation |

All tools auto-install via `setup.sh` or `termux_setup.sh`.

---

## 🧠 Memory System

### How It Works
1. **Every interaction stored:** Questions, findings, strategies, decisions
2. **Semantic search:** Find related memories by meaning, not just keywords
3. **Cross-session:** Restart Elengenix, it still remembers
4. **Persistent storage:** `data/vector_memory/` (ChromaDB) + `data/elengenix.db` (SQLite)

### Example
```
Session 1: You scanned example.com, found admin panel at /admin
Session 2: You ask "check that admin panel I found before"
→ Agent recalls: "Previously found admin panel at /admin on example.com"
```

---

## 📺 Tmux Split-Screen

When you run `elengenix ai` or `elengenix universal`:

```
Tmux detected! Split-screen mode available.
Use split-screen mode? (y/N): y
```

**Result:**
```
┌────────────────────────┬────────────────────────┐
│  [Left] Chat           │  [Right] Live Monitor  │
│                        │                        │
│  You: scan example.com │  Step 2/25             │
│  → Running: subfinder  │  Tool: httpx           │
│  ✓ 10 findings         │  [████░░░░] 40%        │
│                        │                        │
│  Response:             │  14:32:01 ▶ subfinder  │
│  Found 10 subdomains   │  14:32:05 ✓ 10 found   │
│  ...                   │  14:32:06 → httpx      │
└────────────────────────┴────────────────────────┘
```

**Navigation:**
- `Ctrl+B ←` - Go to chat pane
- `Ctrl+B →` - Go to logs pane
- `Ctrl+B x` - Close current pane

---

## 📊 Architecture

```
Elengenix v2.0.0
├── Core Systems
│   ├── Strategic Planner (Attack Tree generation)
│   ├── Tool Registry (Plugin system)
│   ├── Vector Memory (ChromaDB + SQLite)
│   ├── CVSS Calculator (AI-assisted scoring)
│   └── Chain of Thought (Audit logging)
├── AI Modes
│   ├── Universal Agent (Claude Code style)
│   └── Bug Bounty Specialist (Security focused)
├── UI/UX
│   ├── Clean CLI (minimal emojis)
│   ├── Tmux Integration (split-screen)
│   └── Live Display (real-time monitor)
└── Tools (8+ integrated)
    ├── Recon: subfinder, httpx, naabu
    ├── Enum: ffuf, arjun, trufflehog
    ├── Scan: nuclei, katana
    └── Exploit: dalfox
```

---

## 🔧 Advanced Configuration

### `config.yaml` Example
```yaml
ai:
  active_provider: gemini  # or openai, anthropic, groq
  max_steps: 25
  enable_planning: true
  enable_cot_logging: true

providers:
  gemini:
    model: gemini-1.5-flash-latest
    api_key: ${GEMINI_API_KEY}
  openai:
    model: gpt-4
    api_key: ${OPENAI_API_KEY}
```

### Environment Variables
```bash
# Required (at least one)
export GEMINI_API_KEY="your-key"
export OPENAI_API_KEY="your-key"
export ANTHROPIC_API_KEY="your-key"

# Optional (for Telegram notifications)
export TELEGRAM_BOT_TOKEN="your-token"
export TELEGRAM_CHAT_ID="your-chat-id"
```

---

## 📝 Example Workflows

### Workflow 1: Quick Scan
```bash
elengenix ai
You: scan example.com
→ Agent runs full pipeline, generates report
```

### Workflow 2: Custom Exploit Development
```bash
elengenix universal
You: Research CVE-2024-XXXX, create Python exploit
→ Agent searches web, writes exploit.py, tests it
```

### Workflow 3: Deep Recon with Strategy
```bash
elengenix ai
You: Find all vulnerabilities on api.example.com, focus on auth bypass
→ Agent creates custom attack tree for auth testing
```

### Workflow 4: Continuous Monitoring
```bash
elengenix scan example.com --rate-limit 10
# Results saved to reports/
# Findings logged to memory
```

---

## 🐛 Troubleshooting

### "elengenix: command not found"
```bash
source ~/.bashrc  # or ~/.zshrc
# Or add to PATH manually:
export PATH="$PATH:/path/to/Elengenix"
```

### "Missing tools detected"
```bash
elengenix doctor --fix
# Or manually:
./setup.sh
```

### "API key not set"
```bash
cp .env.example .env
nano .env  # Add your keys
```

### Tmux issues
```bash
# Ensure tmux is installed
apt install tmux  # Debian/Ubuntu
brew install tmux # macOS
pkg install tmux  # Termux
```

---

## 🎓 Best Practices

1. **Always verify target scope** before scanning
2. **Use rate limiting** (`--rate-limit 5`) for production targets
3. **Review CVSS scores** before reporting
4. **Check Chain of Thought logs** for audit trails: `data/cot_logs/`
5. **Update regularly:** `git pull && ./setup.sh`

---

## ⚖️ Legal & Ethics

**Elengenix is for authorized security testing only.**

- Always obtain written permission before testing
- Respect rate limits and scope boundaries
- Do not use for destructive testing (DoS, data deletion)
- Report findings responsibly

**By using this tool, you agree to:**
1. Follow responsible disclosure practices
2. Comply with all applicable laws
3. Use only on systems you own or have explicit permission to test

---

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

### Areas for contribution:
- New tool integrations
- Additional AI providers
- UI/UX improvements
- Documentation
- Bug fixes

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/Ashveil1/Elengenix/issues)
- **Discussions:** [GitHub Discussions](https://github.com/Ashveil1/Elengenix/discussions)
- **Telegram:** (If configured in .env)

---

## 🌟 Acknowledgments

Built with:
- [ProjectDiscovery](https://projectdiscovery.io/) tools (subfinder, httpx, nuclei, naabu, katana)
- [ChromaDB](https://www.trychroma.com/) for vector storage
- [Rich](https://rich.readthedocs.io/) for beautiful CLI
- Multiple AI providers (Gemini, OpenAI, Anthropic, Groq)

---

## 📜 Changelog

### v2.0.0 (Universal Agent Edition) - 2024
- **NEW:** Universal Agent Mode (file editing, package mgmt, shell exec)
- **NEW:** Strategic Planning Engine with Attack Trees
- **NEW:** Vector Memory System (ChromaDB + semantic search)
- **NEW:** Tmux Split-Screen Mode
- **NEW:** CVSS Calculator with AI assistance
- **NEW:** Chain of Thought Logging
- **NEW:** 5 additional tools (dalfox, arjun, naabu, ffuf, trufflehog)
- **IMPROVED:** Clean, professional UI
- **IMPROVED:** Activity monitoring in real-time

### v1.5.x - Previous stable release
- Core tool integrations
- Basic AI agent
- Telegram notifications
- Setup automation

---

**Made with ❤️ for the security community.**

Developed by: Ashveil1
Version: 2.0.0 (Universal Agent Edition)


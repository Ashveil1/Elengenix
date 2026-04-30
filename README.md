# Elengenix AI Framework

**The Universal AI Agent for Bug Bounty and Security Research.**

Elengenix is a next-generation security framework that combines the reasoning capabilities of Large Language Models (LLMs) with a professional-grade security toolchain. Built for speed, modularity, and professional automation.

---

## Key Features

- **Autonomous Agent**: Intelligent reasoning for multi-step security missions.
- **Universal Mode**: A versatile interface for any task beyond security.
- **Security Arsenal**: Integrated tools including Subfinder, Nuclei, Httpx, Katana, and more.
- **Permanent Memory**: Vector-based semantic memory for recalling past findings and interactions.
- **Telegram Gateway**: Remote control and monitoring via secure Telegram bot.
- **Watchman Daemon**: 24/7 continuous target monitoring with change detection.
- **Professional UI**: Clean, text-based terminal interface using the Rich library.

---

## Quick Start

### Prerequisites

- Python 3.10+
- Go 1.20+ (for security tools)
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/Elengenix.git
cd Elengenix

# Run the setup script
chmod +x setup.sh
./setup.sh
```

### Configuration

1. Create a `.env` file in the root directory.
2. Add your API keys:
   ```env
   GEMINI_API_KEY=your_google_ai_key
   TELEGRAM_BOT_TOKEN=your_bot_token
   TELEGRAM_CHAT_ID=your_chat_id
   ```

3. Run the system health check:
   ```bash
   python3 main.py doctor
   ```

---

## Usage

### Launching the CLI
```bash
python3 elengenix_launcher.py
```

### Common Commands

- **System Health**: `elengenix doctor`
- **Start Mission**: `elengenix mission example.com`
- **AI Chat**: `elengenix ai`
- **Security Arsenal**: `elengenix arsenal`
- **24/7 Monitor**: `elengenix watchman`

---

## Project Structure

- `main.py`: Core CLI entry point and command router.
- `agent_brain.py`: Autonomous reasoning engine.
- `orchestrator.py`: Tool execution and pipeline management.
- `ui_components.py`: Standardized UI elements and design tokens.
- `tools/`: Modular security tool integrations.
- `data/`: Local logs, state, and vector databases.

---

## Contributing

We welcome contributions from the security and AI community. Please refer to [CONTRIBUTING.md](CONTRIBUTING.md) for our coding standards and development guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Developed by the Elengenix Project Team.**

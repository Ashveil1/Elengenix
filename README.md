# Elengenix AI Framework

The Universal AI Agent for Bug Bounty and Security Research.

Elengenix is a next-generation security framework that combines the reasoning capabilities of Large Language Models (LLMs) with a professional-grade security toolchain. Built for speed, modularity, and professional automation.

Current Status: Intensive R&D Phase. Focus on core agent orchestration and security module integration.

---

## Key Features

- Autonomous Agent: Intelligent reasoning for multi-step security missions.
- Universal Mode: A versatile interface for any task beyond security.
- Security Arsenal: Integrated tools including Subfinder, Nuclei, Httpx, Katana, and more.
- Permanent Memory: Vector-based semantic memory for recalling past findings and interactions.
- Telegram Gateway: Remote control and monitoring via secure Telegram bot.
- Watchman Daemon: 24/7 continuous target monitoring with change detection.
- Professional UI: Clean, text-based terminal interface using the Rich library.

---

## Quick Start

### Prerequisites

- Python 3.10+
- Go 1.20+ (for security tools)
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/Ashveil1/Elengenix.git
cd Elengenix

# For Linux/Ubuntu users:
chmod +x setup.sh
./setup.sh

# For Termux (Android) users:
chmod +x termux_setup.sh
./termux_setup.sh
```

---

## Configuration

Elengenix provides an interactive configuration wizard to manage your AI providers, API keys, and system preferences.

### Using the Configuration Wizard

Run the following command to start the interactive setup:
```bash
elengenix configure
```
*Note: If the global command is not set, use `python3 main.py configure`.*

The wizard allows you to:
1. **Manage AI Providers**: Add or update API keys for NVIDIA NIM, Google Gemini, OpenAI, Anthropic, Groq, and more.
2. **Select Models**: Choose specific models (e.g., GPT-4o, Claude 3.5 Sonnet, Llama 3.3) for each provider.
3. **Manage Integrations**: Setup third-party services like Telegram Bots, HackerOne API, Tavily AI, and VulnCheck.
4. **Set Default Target**: Define a primary target for automated scans.
5. **Configure Rate Limits**: Set global request-per-minute (RPM) limits to avoid being blocked.
6. **System Health Check**: Run a comprehensive diagnostic to ensure all security tools are correctly installed.

### Manual Configuration
Alternatively, you can manually create a `.env` file in the root directory:
```env
NVIDIA_API_KEY=your_nvidia_key
GEMINI_API_KEY=your_google_ai_key
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

---

## Usage

### 1. Launching the CLI Launcher
Use the launcher to access the primary interactive menu:
```bash
python3 elengenix_launcher.py
```

### 2. Common CLI Commands
You can run specific modules directly via the main entry point:
- **System Check**: `elengenix doctor`
- **Start Mission**: `elengenix mission <target>`
- **AI Chat**: `elengenix ai`
- **Security Tools**: `elengenix arsenal`
- **24/7 Monitoring**: `elengenix watchman`
- **SAST Scan**: `elengenix sast <path>`

---

## Upgrade Guide

To keep Elengenix updated with the latest security modules and AI capabilities:

1. **Update Source Code**:
   ```bash
   git pull origin main
   ```

2. **Update Dependencies**:
   ```bash
   pip install -r requirements.txt --upgrade
   ```

3. **Verify Components**:
   Run the doctor command to ensure all tools and dependencies are operational:
   ```bash
   elengenix doctor
   ```

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

We welcome contributions from the security and AI community. Please refer to CONTRIBUTING.md for our coding standards and development guidelines.

## License

This project is licensed under the GPL License - see the LICENSE file for details.

---

Developed by Ashveil1.

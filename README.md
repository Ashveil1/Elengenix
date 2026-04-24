# ELENGENIX AI
### The Professional AI-Powered Bug Bounty Framework

Version: 2.0.0 (Ultimate Edition)
Platform Support: Linux, macOS, Android (Termux)

---

## 1. Prerequisites

Before installing Elengenix, ensure your system meets the following requirements:

- Python: 3.10 or higher
- Go: Required for compiling security tools (subfinder, nuclei, etc.)
- Git: Required for cloning and updating the framework
- Virtual Environment: Python 'venv' module must be available

---

## 2. Installation Instructions

### A. Desktop / Server (Linux and macOS)
The professional installer handles system dependencies, creates a virtual environment, and links the global 'elengenix' command.

1. Clone the repository:
   ```bash
   git clone https://github.com/Ashveil1/Elengenix.git
   cd Elengenix
   ```

2. Run the indestructible installer:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

### B. Mobile (Android via Termux)
Optimized for mobile environments with automatic PATH verification.

1. Clone the repository:
   ```bash
   git clone https://github.com/Ashveil1/Elengenix.git
   cd Elengenix
   ```

2. Run the mobile-specific installer:
   ```bash
   chmod +x termux_setup.sh
   ./termux_setup.sh
   ```

---

## 3. Configuration

Elengenix prioritizes security by using Environment Variables for API keys.

1. Create your environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit the `.env` file with your preferred text editor and fill in your keys:
   - GEMINI_API_KEY
   - TELEGRAM_BOT_TOKEN
   - TELEGRAM_CHAT_ID

3. (Optional) Configure advanced settings in `config.yaml`.

---

## 4. Usage and Verification

### Launching the Framework
Once installed, you can launch Elengenix from any directory:
```bash
elengenix
```

### System Health Check
Use the built-in doctor tool to verify that all tools and dependencies are correctly installed and configured:
```bash
elengenix doctor
```

### Quick Commands
- AI Mission: `elengenix ai`
- Automated Scan: `elengenix scan example.com`
- Tools Arsenal: `elengenix arsenal`
- Remote Gateway: `elengenix gateway`

---

## 5. Troubleshooting PATH Issues

If the 'elengenix' command is not recognized after installation:

1. Ensure the project directory is in your PATH. Add the following to your ~/.bashrc or ~/.zshrc:
   ```bash
   export PATH="$PATH:/path/to/your/Elengenix"
   ```

2. For Termux users, ensure your environment is refreshed:
   ```bash
   source ~/.bashrc
   ```

---

## Ethics and Legal Notice

This framework is for authorized security testing and ethical research only. Users must obtain written permission from target organizations before performing any security assessment. Unauthorized use of this tool is strictly prohibited and may be illegal.

---
Developed for professional security researchers.

# ELENGENIX (v1.2)

Elengenix is a command-line AI agent designed to assist in bug bounty hunting and security research. It orchestrates established security tools with large language models (LLMs) to perform automated reconnaissance and assisted vulnerability analysis.

---

## 🛑 IMPORTANT: ETHICAL USAGE WARNING

**DO NOT USE THIS TOOL FOR ILLEGAL PURPOSES.**

Elengenix is created for **Educational** and **Authorized Security Testing** only. Unauthorized access to computer systems is a crime.
- **NEVER** use this tool on a target without explicit written permission.
- **NEVER** use this tool for cyber-attacks or data theft.
- **ALWAYS** act within the laws of your jurisdiction and the scope of the bug bounty program.

---

## LEGAL AND ETHICAL DISCLAIMER

IMPORTANT: THIS SOFTWARE IS FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING PURPOSES ONLY.

The use of Elengenix for interacting with targets without prior explicit and mutual consent is strictly prohibited. The end user is solely responsible for compliance with all applicable laws. The developers assume no liability for misuse or damage caused by this program.

---

## CORE CAPABILITIES

- Tool Orchestration: Automates the execution of subfinder, nuclei, katana, and other security utilities.
- LLM-Assisted Analysis: Uses AI reasoning to interpret tool outputs and suggest potential attack vectors.
- Multi-Model Support: Compatible with Claude 3.5, Gemini 2.5, GPT-4o, Groq, and local models.
- Real-time Notifications: Delivers findings and status updates via Telegram bot integration.
- Persistent Memory: SQLite-backed system to track discoveries and improve strategy across sessions.
- Security Hardening: Command allowlisting and argument validation for safer autonomous execution.

---

## QUICK START

### For Linux / macOS / WSL
1. git clone https://github.com/Ashveil1/Elengenix.git
2. cd Elengenix
3. bash setup.sh
4. elengenix

### For Termux (Android)
1. git clone https://github.com/Ashveil1/Elengenix.git
2. cd Elengenix
3. bash termux_setup.sh
4. elengenix

---

## ARSENAL OVERVIEW

- Reconnaissance: subfinder, httpx, katana, waybackurls
- Scanning: nuclei (comprehensive vulnerability templates)
- Analysis: js_analyzer, api_finder, param_miner
- Research: Integrated web search and documentation retrieval

---

## LICENSE

This project is licensed under the MIT License. See the LICENSE file for details.

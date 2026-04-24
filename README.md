# ELENGENIX AI
### The Professional AI-Powered Bug Bounty Framework

Version: 2.0.0
Python: 3.10+
License: MIT

The ultimate autonomous security hunting framework.

---

## Welcome to v2.0.0 (Ultimate Edition)

Elengenix v2.0.0 is the culmination of architectural hardening and high-intensity security logic. It combines a robust, async-safe core with specialized tools for deep reconnaissance and vulnerability analysis.

### Key Upgrades in v2.0:
- Intelligent Brain: Isolated mission states and robust JSON extraction.
- Secure Core: No shell=True, strict binary allowlisting, and PII scrubbing.
- High-Intensity Tools: Sophisticated logic for api_finder, js_analyzer, and reporter.
- Watchman Daemon: 24/7 monitoring with SHA256 change detection.
- Universal Support: Indestructible installers for Linux, macOS, and Termux.

---

## Installation

### Automatic Install (Recommended)
```bash
chmod +x setup.sh && ./setup.sh
```

### Mobile (Termux)
```bash
chmod +x termux_setup.sh && ./termux_setup.sh
```

---

## Quick Start

1. Configure: Create a .env file with your API keys (see .env.example).
2. Launch: Use the global command or the local launcher:
   ```bash
   elengenix
   # OR
   ./sentinel
   ```

---

## Tools Arsenal

| Tool | Capability |
|------|------------|
| Omni-Scan | Full-scale automated mission (Dorking -> Recon -> Nuclei). |
| API Hunter | Concurrent probing for Swagger/OpenAPI endpoints. |
| JS Analyzer | Regex-based secret extraction (AWS, Google, GitHub, etc.). |
| Watchman | 24/7 target monitoring and AI-assisted alerting. |

---

## Ethics and Legal

This framework is for authorized security testing only. The user is responsible for obtaining all necessary permissions. Unauthorized use is strictly prohibited.

---
Built for hunters, by hunters.

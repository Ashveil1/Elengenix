# AGENTS.md — Elengenix Codebase Handbook for AI Agents

## Overview

Elengenix is a Python-based CLI framework for autonomous security research, bug bounty hunting, and penetration testing. It wraps Go security tools (Subfinder, Nuclei, Httpx, etc.) behind an AI agent that plans attack trees, executes tools, scores findings with CVSS, and generates reports. Dual-language: UI primarily English, AI agent responds in Thai or English.

**Python 3.10+ required**, Go 1.20+ for tool compilation.

---

## Essential Commands

### Install
```bash
./setup.sh                          # Linux/Ubuntu (installs Go tools + Python deps)
pip install -r requirements.txt     # Python deps only
```

### Run
```bash
python3 main.py <command> [target]  # CLI entry point
python3 main.py cli                 # Interactive AI chat
python3 main.py menu                # Interactive menu
python3 main.py doctor              # System health check
python3 main.py configure           # API key / provider setup wizard
```

### Test
```bash
python3 -m pytest tests/ -v                           # All tests
python3 -m pytest tests/test_security.py -v           # Specific test file
```

### Update
```bash
git pull && ./setup.sh
```

---

## Code Organization

```
main.py                  # CLI entry point — argparse command router
├── agent.py             # Bridge: imports & configures ElengenixAgent
├── agent_brain.py       # ElengenixAgent — core AI reasoning engine
│                        #   - StrategicPlanner (attack tree generation)
│                        #   - ChainOfThoughtLogger (audit trail)
│                        #   - Tool execution via registry or subprocess
├── orchestrator.py      # Pipeline orchestrator — scope management, tool chains
├── llm_client.py        # LLMClient — native SDKs (Gemini, Anthropic, Cohere, etc.)
├── cli.py               # Interactive CLI mode (AI Partner)
├── ui_components.py     # Centralized Rich UI — shared Console, colors, markers
├── dependency_manager.py # Go tool installer (subfinder, nuclei, etc.)
├── knowledge_loader.py  # Securely loads knowledge/*.md files for agent context
├── bot.py / bot_utils.py # Telegram gateway for remote control
├── watchman.py          # 24/7 monitoring daemon
├── tools/               # ~60+ modular security tool modules
├── prompts/             # AI system prompts (system_prompt.txt)
├── knowledge/           # Methodology documentation (loaded by knowledge_loader)
├── data/                # Runtime data: logs, CoT logs, CVE cache, vector DB
├── tests/               # Unit tests (pytest)
└── config.yaml.example  # Template config (secrets go in .env, NEVER here)
```

---

## Application Architecture & Data Flow

### Command Dispatch Flow (main.py)
```
elengenix <command> <target>
    │
    ├─ AutoDetector.detect(target) → routes to correct module
    ├─ CommandSimplifier.simplify(cmd) → resolves aliases (bb→bounty, etc.)
    └─ elif chain dispatches to specific handler
        ├─ "universal" → cli.py (interactive AI chat)
        ├─ "scan" → orchestrator.run_standard_scan()
        ├─ "autonomous" → AutonomousAgent / TeamAegis
        ├─ "ai" → cli.py (default)
        ├─ "bola/waf/recon/mission/..." → specific module handlers
        └─ profile shortcuts (quick/deep/stealth) → ProfileManager.expand_profile()
```

### Agent Reasoning Loop (agent_brain.py)
```
User input → _analyze_intent() → [casual|research|scan|security_chat]
    │
    ├─ casual/security_chat (no target) → direct AI response + memory recall
    └─ scan → MissionState created → for step in max_steps:
        ├─ StrategicPlanner.generate_attack_tree() (if planning enabled)
        ├─ Tool selection (from attack tree or AI dynamic planning)
        ├─ Governance.gate() — risk-based approval before execution
        ├─ _execute_tool_registry() → async ToolResult
        ├─ Findings piped to:
        │   ├─ CVSSCalculator (scoring)
        │   ├─ CVE database lookup (similar vulns)
        │   ├─ BusinessLogicAnalyzer (authZ hypotheses)
        │   ├─ BOLABridge (differential access tests)
        │   ├─ PayloadMutator (XSS variants, non-executing)
        │   ├─ WAFEvasionEngine (governance-gated)
        │   ├─ SmartReconEngine (asset correlation)
        │   ├─ SOCAnalyzer (detection rules)
        │   ├─ SASTEngine (static analysis)
        │   ├─ CloudScanner (IaC review)
        │   ├─ ExploitChainBuilder (multi-stage paths)
        │   └─ BountyPredictor (payout estimates)
        ├─ VectorMemory.remember() → ChromaDB (cross-session recall)
        └─ ChainOfThoughtLogger.save_session() → data/cot_logs/
```

### Two AI Client Systems
- **`LLMClient`** (`llm_client.py`) — Uses native vendor SDKs (google-generativeai, anthropic, cohere, etc.). Sync wrapper over async via shared persistent event loop.
- **`UniversalAIClient`** (`tools/universal_ai_client.py`) — OpenAI-compatible HTTP API. Works with any provider that supports `/v1/chat/completions`. **This is what the agent uses for chat.**

### Tool Execution Path
1. `ElengenixAgent._execute_tool_registry()` → preferred path
2. Falls back to `_execute_tool_subprocess()` if registry fails
3. Legacy direct subprocess in `_execute_tool()` — only for allowlisted binaries

---

## Critical Conventions & Gotchas

### Security (HARD RULES)
- **`shell=True` is NEVER allowed** in any `subprocess` call. Always use list form.
- **Tool allowlist**: `ElengenixAgent.ALLOWED_TOOLS` — only binaries in this set can be executed via the agent's `_execute_tool()`. New tools must be added explicitly.
- **Metacharacter blocking**: `|`, `&`, `;`, `` ` ``, `$(` , `>`, `<`, `\` are rejected in agent commands.
- **API keys go in `.env`**, NEVER in `config.yaml`. Both files are gitignored.
- **Target validation**: `validate_target()` in main.py and `is_valid_target()` in orchestrator must pass before any scan.
- **Scope enforcement**: `orchestrator.is_in_scope()` checks against `scope.txt` or `ELENGENIX_SCOPE` env var.

### UI Rules (DO NOT DEVIATE)
- **NO emoji** in terminal output, log messages, or code comments — ever.
- Use text markers: `[OK]`, `[FAIL]`, `[WARN]`, `[INFO]`, `[RUN]`, `[SKIP]`
- **Always import from `ui_components.py`** for console/messages — never create your own `Console()`:
  ```python
  # Correct
  from ui_components import console, print_success, print_error, confirm
  # Incorrect
  console = Console()  # DO NOT DO THIS
  ```
- Color scheme: primary=`red`, secondary=`grey70`, success=`white`, error=`red`

### Code Style
- **4-space indentation** (no tabs, no 2-space)
- **Docstrings on every module, class, and public function** with Args/Returns format
- **Type hints on all function signatures**
- Module-specific loggers: `logger = logging.getLogger("elengenix.{module_name}")`
- Use `[OK]`/`[FAIL]` prefixes in log messages for structured parsing

### Module Imports
- Many tools use **optional imports** with graceful fallbacks:
  ```python
  try:
      from dotenv import load_dotenv
  except ImportError:
      pass
  ```
- `nest_asyncio.apply()` is called in many modules for nested event loop compatibility (Telegram bot).
- The project uses both blocking imports (for core) and late imports (for tools to avoid circular deps).

### Shared State
- `LLMClient._shared_loop` — a persistent event loop shared across all LLMClient instances via class-level state. This prevents "Future attached to different loop" errors with gRPC-based SDKs (Gemini, Anthropic).
- `ui_components.console` — the one shared Rich Console instance.
- `tools.tool_registry.registry` — global singleton for tool registration.

### Memory / Persistence
- **Vector memory**: ChromaDB (`data/vector_memory/`) — cross-session semantic recall via `remember()` / `recall()` from `tools/vector_memory.py`
- **Structured memory**: SQLite in `data/elengenix.db` — missions, findings, token usage, program cache
- **User profile**: `MEMORY.md` (gitignored, auto-generated) — read by `tools/memory_profile.py`
- **State**: Mission state JSON in `data/missions/`

### Configuration Files
| File | Git | Purpose |
|------|:---:|---------|
| `config.yaml.example` | Yes | Template |
| `config.yaml` | No | Active config (no secrets) |
| `.env.example` | Yes | Template |
| `.env` | No | API keys |
| `MEMORY.md.example` | Yes | Template |
| `MEMORY.md` | No | User profile |

---

## Testing Strategy

Tests live in `tests/` (currently one file: `test_security.py`). Focus is on security-critical paths:
- Tool allowlist enforcement
- Shell metacharacter blocking
- Target validation and normalization

Use `_lightweight_agent()` pattern to create test instances without full initialization overhead.

---

## Adding a New Tool

1. Create `tools/your_tool.py` with standard interface (see `tools/tool_registry.py` for `BaseTool` ABC)
2. Register it in `tools/tool_registry.py`
3. If it wraps a Go binary, add the install command to `dependency_manager.py`
4. If it needs governance gating, add a gate check in `agent_brain.py`'s process loop
5. Add CLI command handling in `main.py`'s elif chain

# AGENTS.md — Elengenix Codebase Handbook for AI Agents

## Overview

Elengenix is a Python-based CLI framework for autonomous security research, bug bounty hunting, and penetration testing. It's a pure Python AI agent that plans attack trees, executes built-in scanners, scores findings with CVSS, and generates reports.

**Python 3.10+ required** (currently 3.12.3). No external Go tools required.

---

## Essential Commands

### Install
```bash
./setup.sh                          # Linux/Ubuntu (installs Python deps)
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
python3 -m pytest tests/ -v                                # All tests (some timeout on network)
python3 -m pytest tests/test_security.py -v                # Specific file
python3 -m pytest tests/test_tui.py tests/test_security.py tests/test_core_modules.py tests/test_new_scanners.py tests/test_critical_modules.py -v  # Stable suite
```

**Warning**: `test_orchestrator_modules.py` and `test_hunt_engine.py` (`test_hunt_engine_live_httpbin`) hit live network endpoints and will timeout without internet. This is expected — they are integration tests, not failures.

### Update
```bash
git pull && ./setup.sh
```

---

## Code Organization

```
main.py                  # CLI entry point — argparse command router (2200+ lines)
├── agent.py             # Bridge: imports & configures ElengenixAgent
├── agent_brain.py       # ElengenixAgent — core AI reasoning engine (1800+ lines)
├── agents/              # Agent subsystem modules (18 files)
│   ├── agent_planner.py     # StrategicPlanner, TargetFingerprinter
│   ├── agent_executor.py    # Tool execution (registry, subprocess, shell)
│   ├── agent_intent.py      # Intent classification
│   ├── agent_logger.py      # Chain-of-thought logging
│   ├── agent_helpers.py     # Shared helpers (target extraction, _safe_operation)
│   ├── agent_dataclasses.py # AttackTree and shared data structures
│   ├── agent_universal.py   # Universal mode processor
│   ├── agent_conversation.py # ConversationManager (extracted from agent_brain)
│   ├── agent_modes.py       # ModeProcessor (extracted from agent_brain)
│   ├── hybrid_agent.py      # Hybrid mode (redteam + structured analysis)
│   ├── agent_council.py     # Multi-agent council deliberation
│   ├── worker_base.py       # Base class for council workers
│   ├── strategist_agent.py  # Strategist role for council
│   ├── specialist_agent.py  # Specialist role for council
│   └── critic_agent.py      # Critic role for council
├── orchestrator.py      # Pipeline orchestrator — scope management, tool chains
├── cli.py               # Interactive CLI mode (AI Partner)
├── ui_components.py     # Centralized Rich UI — shared Console, colors, markers
├── commands/            # CLI command modules (scan, worldclass, registry, system)
├── tui/                 # Textual-based TUI (themes, dashboard, visualizations)
│   ├── themes.py            # 9 themes: DEFAULT, CYBERPUNK, MATRIX, STEALTH, SYNTHWAVE, OCEAN, FOREST, SUNSET, ARCTIC
│   ├── dashboard.py         # ThreatDashboard Textual widget
│   ├── visualizations.py    # RiskGauge, SeverityChart, VulnerabilityHeatmap, etc.
│   ├── welcome.py           # WelcomeScreen, ascii_logo, MissionBriefing
│   ├── hunt_view.py         # Hunt result dashboard, launcher layout
│   ├── findings_display.py  # Sortable, filterable findings display
│   ├── scan_progress.py     # Real-time scan progress with phases
│   ├── keyboard_shortcuts.py # Keyboard shortcuts system
│   ├── main_menu.py         # Interactive main menu system
│   └── export.py            # HTML/JSON/Markdown export capabilities
├── tools/               # 120+ modular security tool modules
│   ├── tool_registry.py     # BaseTool ABC, ToolRegistry, 17 registered tools
│   ├── governance.py        # Risk classification (DESTRUCTIVE/PRIVILEGED/SAFE)
│   ├── universal_ai_client.py # OpenAI-compatible HTTP API client
│   ├── vector_memory.py     # ChromaDB semantic recall
│   ├── cvss_calculator.py   # CVSS 3.1 scoring
│   ├── cve_database.py      # CVE lookup and similarity search
│   ├── mission_state.py     # Mission graph, facts, ledger (SQLite)
│   ├── payload_mutation.py  # Payload mutation engine
│   ├── active_fuzzer.py     # Live fuzzing with response delta scoring
│   ├── ssrf_scanner.py      # Server-Side Request Forgery testing
│   ├── ssti_scanner.py      # Server-Side Template Injection testing
│   ├── xxe_scanner.py       # XML External Entity testing
│   ├── deserialization_scanner.py # Insecure deserialization testing
│   ├── graphql_scanner.py   # GraphQL API vulnerabilities
│   ├── race_condition_tester.py # Race condition vulnerabilities
│   ├── api_schema_diff.py   # Schema drift detection
│   ├── supply_chain_analyzer.py # Dependency vulnerability analysis
│   ├── logic_flaw_engine.py # Business logic flaw detection
│   ├── cors_checker.py      # CORS misconfiguration testing
│   ├── jwt_tester.py        # JWT security vulnerabilities
│   └── ...                  # 100+ more modules
├── prompts/             # AI system prompts (system_prompt.txt)
├── knowledge/           # Methodology documentation (loaded by knowledge_loader)
├── data/                # Runtime data: logs, CoT logs, CVE cache, vector DB
├── tests/               # 42+ test files (pytest)
├── commands/scan.py     # Extracted scan command handler
├── scan_engine_upgrade.py # SmartOrchestrator for upgraded scan engine
├── live_display.py      # Live activity display for chat mode
├── config.yaml.example  # Template config (secrets go in .env, NEVER here)
└── ...
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
        ├─ Findings piped to 13+ analyzers via AnalysisPipeline
        ├─ VectorMemory.remember() → ChromaDB (cross-session recall)
        └─ ChainOfThoughtLogger.save_session() → data/cot_logs/
```

### Two AI Client Systems
- **`LLMClient`** (`llm_client.py`) — Uses native vendor SDKs (google-generativeai, anthropic, cohere, etc.). Sync wrapper over async via shared persistent event loop.
- **`UniversalAIClient`** (`tools/universal_ai_client.py`) — OpenAI-compatible HTTP API. Works with any provider that supports `/v1/chat/completions`. **This is what the agent uses for chat.**

### Tool Execution Path
1. `ElengenixAgent._execute_tool_registry()` → preferred path (async)
2. Falls back to `_execute_tool_subprocess()` if registry fails
3. Shell-capable executor path in `_execute_tool()` — all raw shell commands must pass through `tools.governance.Governance` before `tools.safe_exec.execute_safely()`

### Tool Registry Auto-Discovery
`tools/tool_registry.py` auto-discovers all `*.py` files in `tools/` on import. Modules using `@register_tool(ToolMetadata(...))` decorator self-register. Currently 17 tools registered:
- **Python scanners**: waf_detector, active_fuzzer, python_recon, ssrf_scanner, ssti_scanner, xxe_scanner, deserialization_scanner, graphql_scanner, race_condition_tester, api_schema_diff, supply_chain_analyzer, logic_flaw_engine, cors_checker, jwt_tester
- **API testing**: arjun, dynamic_waf_mutator
- **Secret detection**: trufflehog

Most modules are standalone and used directly by agent_brain.py, not through the registry.

---

## Critical Conventions & Gotchas

### Security (HARD RULES)
- **Raw shell execution is intentional but gated**: `shell=True` is allowed only in the dedicated shell runners (`tools/safe_exec.py`, `tools/universal_executor.py`) after `Governance.gate()` has classified the command.
- **Governance is the execution policy source of truth**: `DESTRUCTIVE` commands are denied, `PRIVILEGED` commands require approval, and `SAFE` commands run freely.
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
- Exception: `main.py` fallback when `ui_components` fails to import (line 44).
- Exception: TUI modules (`tui/dashboard.py`, `tui/hunt_view.py`) import `console as shared_console` for Textual widget context.
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

Tests live in `tests/` (42+ test files). Focus areas:
- **Governance enforcement** (`test_security.py`, `test_integration.py`): destructive/privileged shell commands blocked correctly
- **Tool modules** (`test_waf_detector.py`, `test_active_fuzzer.py`, `test_hunt_engine.py`, etc.)
- **TUI rendering** (`test_tui.py`): themes, visualizations, dashboard, welcome, hunt_view
- **Core modules** (`test_core_modules.py`): CVSS, governance, mission state, CVE DB, vector memory, tool registry
- **Agent council** (`test_agent_council.py`): multi-agent deliberation
- **Semantic planning** (`test_semantic_planner.py`): attack tree generation
- **New scanners** (`test_new_scanners.py`): SSRF, SSTI, XXE, Deserialization, GraphQL, Race Condition, API Schema Diff, CORS, JWT
- **Critical modules** (`test_critical_modules.py`): Comprehensive tests for all critical modules

Use `_lightweight_agent()` pattern in `test_security.py` to create test instances without full initialization overhead.

**Stable test command** (no network required):
```bash
python3 -m pytest tests/test_tui.py tests/test_security.py tests/test_core_modules.py tests/test_new_scanners.py tests/test_critical_modules.py -v
```

**Note**: Stable suite has 160+ tests.

---

## Adding a New Tool

1. Create `tools/your_tool.py` with standard interface (see `tools/tool_registry.py` for `BaseTool` ABC)
2. Register it using `@register_tool(ToolMetadata(...))` decorator — it will auto-discover on import
3. If it wraps a Go binary, add the install command to `dependency_manager.py`
4. If it needs governance gating, add a gate check in `agent_brain.py`'s process loop
5. Add CLI command handling in `main.py`'s elif chain

# API Reference for Test Writing

Generated from source analysis of three modules.

---

## 1. `orchestrator.py` (926 lines)

### Imports
```
asyncio, ipaddress, json, logging, os, re, pathlib.Path
typing.{Any, Dict, List, Optional, Set, Tuple}
urllib.parse.urlparse
tools.perf.{FastHTTP, SmartCache, Timer, cached}
nest_asyncio (optional import)
rich.panel.Panel
bot_utils.send_telegram_notification
scan_engine_upgrade.SmartOrchestrator
tools.active_fuzzer.ActiveFuzzer
tools.bola_tester.BOLATester
tools.coverage_analyzer.CoverageAnalyzer
tools.cvss_calculator.CVSSCalculator
tools.learning_engine.{ExploitRecord, LearningEngine}
tools.python_recon.PythonRecon
tools.tool_registry.{ToolCategory, ToolResult, registry}
tools.waf_detector.SmartWAFDetector
ui_components.console
```

### Module-Level Constants / Globals
- `logger` — `logging.getLogger("elengenix.orchestrator")`
- `ALLOWED_DOMAINS: Set[str]` — computed at import via `load_allowed_domains()`
- `_cve_scache = SmartCache(max_size=128, default_ttl=3600)`
- `_cached_http = FastHTTP(timeout=10.0, max_connections=50, use_cache=True)`

### Scope Management Functions

#### `load_allowed_domains(scope_file: str = "scope.txt") -> Set[str]`
- **I/O**: reads env var `ELENGENIX_SCOPE` (comma-separated), reads `scope.txt` file
- Returns lowercase set of domains
- Lines starting with `#` in scope.txt are skipped

#### `normalize_target(target: str) -> str`
- Pure logic
- Strips scheme (http/https), port, lowercases, removes trailing dots
- Returns empty string for falsy input

#### `is_valid_target(target: str) -> bool`
- Pure logic
- Rejects: empty, private IPs, loopback IPs, len>253, no dots
- Validates each label against `^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`
- IP addresses must be non-private and non-loopback

#### `is_in_scope(target: str) -> bool`
- Calls `normalize_target()` then `is_valid_target()`
- If `ALLOWED_DOMAINS` is empty (no scope configured), returns `True` for any valid target
- Otherwise checks exact match or subdomain match (endswith `.domain`)

#### `sanitize_path(target: str) -> str`
- Replaces `[^a-zA-Z0-9.-]` with `_`, truncates to 100 chars

### Registry Pipeline Functions

#### `get_recommended_tool_chain(target_type: str = "web") -> List[Any]`
- Pure delegation to `registry.get_recommended_chain(target_type)`

#### `async run_tool_with_registry(tool_name: str, target: str, report_dir: Path, semaphore: asyncio.Semaphore) -> ToolResult`
- **I/O**: network (via tool.execute)
- Returns failure ToolResult if tool not found or not available
- Wraps exceptions into failure ToolResult

#### `async run_registry_pipeline(target: str, report_dir: Path, rate_limit: int = 5, tool_filter: Optional[List[str]] = None) -> List[ToolResult]`
- **I/O**: network — runs tools concurrently via semaphore
- If `tool_filter` provided, runs only those; otherwise uses recommended chain
- Prints results via `console.print`

#### `_suggest_missing_tools(tools: List[Any], target: str = "") -> None`
- Private helper, prints missing tools to console

#### `_manual_cmd(tool_name: str) -> str`
- Returns a static string about built-in modules

### CVSS and Findings

#### `calculate_cvss_for_results(results: List[ToolResult]) -> List[Dict[str, Any]]`
- Creates `CVSSCalculator(use_ai=False)` (deterministic scoring)
- Each result finding gets scored; returns list of dicts with keys: `tool`, `finding`, `cvss_score`, `severity`, `vector`
- Sorted by severity: Critical(0) > High(1) > Medium(2) > Low(3) > Informational(4)

#### `print_findings_summary(results: List[ToolResult]) -> None`
- Groups findings by severity (Critical/High/Medium/Low/Informational)
- `Info` severity is mapped to `Informational`
- Pure console output

### Cached HTTP / CVE Check

#### `http_get_cached(url: str, timeout: float = 10.0) -> Optional[str]`
- **I/O**: network via `_cached_http.get()`
- Returns response text or None on failure

#### `_check_cves_for_tech_cached(base_url: str, techs: tuple, server: str) -> List[Dict[str, Any]]`
- Decorated with `@cached(cache=_cve_scache, ttl=3600)`
- **I/O**: imports `tools.vuln_engine.{KNOWN_CVES, severity_from_cvss}` at runtime
- Matches tech fingerprints against CVE database
- Returns list of finding dicts with keys: `tool`, `type`, `severity`, `cvss`, `url`, `title`, `details`, `cve`, `cwe`, `matched_tech`

#### `_check_cves_for_tech(recon_result: Dict[str, Any], base_url: str) -> List[Dict[str, Any]]`
- Extracts `http_probe.tech` and `http_probe.headers.Server` from recon_result
- Delegates to `_check_cves_for_tech_cached()`
- Returns empty list if no techs or server info

#### `_recon_to_findings(recon_result: Dict[str, Any], base_url: str) -> List[Dict[str, Any]]`
- Pure logic — converts PythonRecon output to finding dicts
- Handles: http_probe, directories, ports, subdomains, parameters (only `is_interesting=True`)
- Also calls `_check_cves_for_tech()` for CVE enrichment
- Finding types: `recon_http`, `endpoint`, `port`, `subdomain`, `param_discovery`

### 6-Phase Elengenix Pipeline

#### `async _run_phase1_recon(target, base_url, report_dir, timeout) -> Dict[str, Any]`
- **I/O**: network (PythonRecon.full_recon), file write (recon report JSON)
- Uses `quick=True` mode
- Returns recon_result dict or empty dict on failure

#### `async _run_phase2_waf(base_url) -> List[Dict[str, Any]]`
- **I/O**: network (SmartWAFDetector.probe via asyncio.to_thread, http_get_cached)
- Timeout: 15s for WAF probe
- Returns list of WAF finding dicts or empty list

#### `async _run_phase3_fuzz(recon_result, base_url) -> List[Dict[str, Any]]`
- **I/O**: network (ActiveFuzzer.fuzz_parameter via asyncio.to_thread)
- XSS payloads: `<script>`, `%3Cscript%3E`, `'"><svg onload=>`, `javascript:alert(1)`
- SQLi payloads: `'`, `1' OR '1'='1`, `1' AND SLEEP(2)--`, `%27`
- Targets from Phase 1 interesting params, fallback to `{base_url}/get?q`
- Limits to top 3 params
- Concurrent fuzzing via asyncio.gather
- Finding types: `xss` (High), `sqli` (Critical)

#### `async _run_phase4_bola(recon_result, base_url) -> List[Dict[str, Any]]`
- **I/O**: network (BOLATester via asyncio.to_thread)
- Timeout: 10s
- Registers two sessions (user_a, user_b)
- Searches recon endpoints for `api` + `user/account/profile` patterns
- Tests IDs: `["1", "2", "3", "admin"]`

#### `async _run_phase5_learning(findings, target, report_dir) -> List[Dict[str, Any]]`
- **I/O**: file (LearningEngine SQLite DB at `report_dir/learning.db`)
- Records all findings as ExploitRecords
- Always returns empty list (no new findings)

#### `async _run_phase6_coverage(findings, report_dir) -> List[Dict[str, Any]]`
- **I/O**: file (CoverageAnalyzer SQLite DB at `report_dir/coverage.db`)
- Records URLs from findings
- Always returns empty list (no new findings)

#### `async run_elengenix_modules(target, report_dir, timeout=300) -> List[Dict[str, Any]]`
- Orchestrator for the 6 phases
- Phase 1+2 run in parallel (asyncio.gather)
- Phase 3+4 run in parallel (both depend on recon_result)
- Phase 5+6 run in parallel (both depend on accumulated findings)
- Creates `report_dir` if needed
- Handles KeyboardInterrupt gracefully at each stage

### Core Entry Point

#### `async run_standard_scan(target, rate_limit=5, timeout=600, use_registry=True, tool_filter=None, use_smart_scan=False) -> Optional[str]`
- **I/O**: network, file writes, telegram notification
- Returns report directory path (str) on success, None on failure/scope violation
- Scope check first via `is_in_scope()`
- Always runs Elengenix 6-phase pipeline first (timeout=min(timeout,300))
- Then either SmartScan or Registry pipeline based on `use_smart_scan` and `use_registry`
- Saves: `elengenix_findings.json`, `cvss_scores.json`
- Sends telegram notifications at start, completion, and timeout

---

## 2. `tools/config_wizard.py` (1312 lines)

### Imports
```
from __future__ import annotations
logging, os, dataclasses.dataclass, pathlib.Path
typing.{Dict, List, Optional}
ui_components.{console, print_error, print_info, print_success, print_warning}
```
Lazy imports inside methods: `rich.table.Table`, `requests`, `yaml`, `tools.universal_ai_client.AIClientManager`, `tools.doctor.check_health`, `cli.show_model_selector`

### Data Classes

#### `AIProviderConfig` (dataclass)
Fields:
- `name: str` — display name (e.g. "NVIDIA")
- `env_key: str` — env var for API key (e.g. "NVIDIA_API_KEY"), empty for Ollama
- `base_url: str` — API base URL
- `signup_url: str` — registration URL
- `is_free: bool`
- `notes: str`
- `api_type: str = "openai"` — one of "openai", "native", "azure"

### `ConfigWizard` Class

#### Constructor
```python
def __init__(self, config_dir: Path = Path("."))
```
- Sets `self.config_dir`, `self.env_file` (config_dir / ".env")
- If `.env` exists, sets permissions to 0o600

#### Class-Level Constants

`AI_PROVIDERS: List[AIProviderConfig]` — 14 providers:
1. NVIDIA (free, openai type)
2. Gemini/Google (free, native)
3. OpenAI/GPT-4 (paid, openai)
4. Anthropic/Claude (paid, native)
5. Groq (free, openai)
6. Cohere (free, native)
7. Hugging Face (free, native)
8. Together AI (free, openai)
9. Replicate (free, native)
10. Mistral (free, openai)
11. DeepSeek (free, openai)
12. Perplexity (free, openai)
13. OpenRouter (free, openai)
14. Ollama/Local (free, no env_key)

`DEFAULT_MODELS: Dict[str, List[str]]` — preset model lists per provider display name (e.g. "Gemini (Google)" -> ["gemini-3.1-flash-lite-preview", ...])

`PRIORITY_ORDER: List[str]` — fallback priority: nvidia, gemini, openai, anthropic, groq, deepseek, mistral, openrouter, together, perplexity, cohere, huggingface, replicate, ollama

`_PROVIDER_KEY_MAP: Dict[str, str]` — maps display name to lowercase key (e.g. "OpenAI (GPT-4)" -> "openai")

`INTEGRATIONS: List[Dict]` — 5 integrations: Telegram Bot, HackerOne, Tavily AI, VulnCheck, GitHub. Each has `name`, `keys` (list of env var names), `desc`.

#### Public Methods

##### `run() -> None`
- Main wizard loop (interactive, reads from console.input)
- Menu: [1] Manage AI Providers, [2] Team Aegis, [3] Integrations, [4] Default Target, [5] Rate Limits, [6] Status, [7] Health Check, [0] Exit
- **I/O**: console input/output throughout

#### Private Methods (all do I/O)

##### `_manage_all_providers() -> None`
- Shows Rich table of all providers with status
- Detects active provider via `AIClientManager.get_active_provider()`
- Detects team members from `ACTIVE_MODELS` env var
- Sub-actions: configure single provider, [A] all, [T] team builder, [D] delete key

##### `_manage_integrations() -> None`
- Shows integration table, allows setting env vars for each

##### `_configure_provider(provider: AIProviderConfig) -> None`
- Special-cases Ollama (no key needed, checks localhost:11434)
- For others: prompts for API key, saves to `.env`, selects model, tests connection
- **I/O**: network (Ollama health check via `requests.get`), env file write

##### `_fetch_remote_models(provider: AIProviderConfig, api_key: str) -> List[str]`
- **I/O**: network — GETs `{base_url}/models` with Bearer auth
- Filters out embedding/whisper/tts/dall-e/moderation models
- Returns empty list for Anthropic (doesn't support /models endpoint)
- Timeout: 5s

##### `_select_model(provider: AIProviderConfig) -> None`
- Combines remote-fetched models with local defaults
- NVIDIA special case: prompts for param mode (auto/nemotron/disable/enable/none)
- Saves selected model to env var `{PROVIDER}_MODEL`

##### `_test_provider(provider: AIProviderConfig, api_key: str, model: Optional[str] = None) -> bool`
- **I/O**: network — POSTs to `{base_url}/chat/completions` with test message
- Timeout: 30s
- NVIDIA special handling: adds `chat_template_kwargs` based on `NVIDIA_PARAM_MODE`
- Returns True on status 200 or timeout (soft success)

##### `_setup_telegram() -> None`
- Prompts for TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID

##### `_setup_hackerone() -> None`
- Prompts for HACKERONE_API_KEY and HACKERONE_API_USER

##### `_setup_default_target() -> None`
- Saves ELENGENIX_DEFAULT_TARGET env var

##### `_setup_rate_limits() -> None`
- Saves ELENGENIX_RATE_LIMIT env var (validated as int)

##### `_show_status() -> None`
- Rich table of all providers + integrations + other settings
- Detects active provider/model from AIClientManager

##### `_health_check() -> None`
- Delegates to `tools.doctor.check_health()`

##### `_save_env_var(key: str, value: str) -> None`
- **I/O**: file write — reads/writes `.env`, sets `os.environ[key]`
- Sets file permissions to 0o600

##### `_remove_env_var(key: str) -> None`
- **I/O**: file write — removes key from `.env` and `os.environ`

##### `_load_yaml_config() -> dict`
- **I/O**: file read — reads `config.yaml` or falls back to `config.yaml.example`

##### `_save_yaml_config(config: dict) -> None`
- **I/O**: file write — writes `config.yaml`

##### `_save_team_to_yaml(final_team: list) -> None`
- Loads YAML config, writes `team_aegis` section with strategist/specialist/critic roles

##### `_manage_team_aegis() -> None`
- Interactive Team Aegis configuration dashboard
- Toggle 3-AI mode, configure each role, quick-build preset, reset

##### `_configure_team_role(role_key: str, role_name: str, config: dict) -> None`
- Interactive provider+model selection for a specific team role
- Updates `ACTIVE_MODELS` env var and config.yaml

### Module-Level Function

#### `run_config_wizard() -> None`
- Entry point: creates `ConfigWizard()` and calls `.run()`

---

## 3. `tools/autonomous_agent.py` (2290 lines)

### Imports
```
from __future__ import annotations
json, logging, time, dataclasses.{dataclass, field}
datetime.{datetime, timezone}
pathlib.Path, typing.{Any, Dict, List, Optional}, urllib.parse.urlparse
tools.user_memory.{get_target_summary, save_target_learning} (optional)
live_display.display_in_chat_mode
ui_components.console as _ui_console
```
Lazy imports inside functions: `requests`, `tools.smart_recon.SmartReconEngine`, `tools.waf_signatures.detect_waf_from_response`, `tools.wordlist_manager.{WordlistConfig, WordlistManager}`, `tools.research_tool.research_target`, `tools.vulncheck_tool.get_target_intel`, `tools.wayback_tool.gather_historical_intel`, `tools.github_intel.hunt_leaks`, `tools.js_analyzer.analyze_js`, `tools.param_miner.mine_parameters`, `tools.cors_checker.check_cors`, `tools.injection_tester.run_all_injection_tests`, `tools.subdomain_takeover.check_subdomains`, `tools.waf_evasion.WAFEvasionEngine`, `tools.ai_tool_creator.AIToolCreator`, `tools.ssrf_scanner.SSRFScanner`, `tools.graphql_scanner.scan_graphql`, `tools.race_condition_tester.scan_race_conditions`, `tools.auth_tester.run_auth_tests`, `tools.multi_agent.{TeamAegis, TeamMessage}`, `tools.universal_ai_client.{AIClientManager, AIMessage, UniversalAIClient}`, `tools.universal_executor.get_universal_executor`, `tools.bounty_predictor.BountyPredictor`, `tools.pdf_report_generator.{PDFReportGenerator, ReportMetadata}`, `tools.mission_state.MissionState`, `zapv2.ZAPv2` (optional), `subprocess` (for ZAP daemon)

### Module-Level Helper

#### `_display(msg, level="info") -> None`
- Routes through `display_in_chat_mode()` with fallback to `console._display()`

### Data Classes

#### `AgentAction` (dataclass)
- `name: str` — action identifier (e.g. "recon", "xss_hunt", "done")
- `target: str` — URL or domain
- `params: Dict[str, Any] = field(default_factory=dict)`
- `reasoning: str = ""`

#### `AgentState` (dataclass)
- `root_target: str`
- `goal: str`
- `findings: List[Dict[str, Any]] = field(default_factory=list)`
- `assets: Dict[str, Any] = field(default_factory=dict)` — stores subdomains, endpoints, tech, auth_headers, discovered_params, etc.
- `action_history: List[str] = field(default_factory=list)` — format "action_name:target_url"
- `iteration: int = 0`

#### `ScanResult` (dataclass)
- `target: str`
- `start_time: datetime`
- `end_time: Optional[datetime]`
- `findings: List[Dict[str, Any]]`
- `bounty_predictions: List[Dict[str, Any]]`
- `tools_created: List[str]`
- `ai_decisions: List[AgentAction]`
- `report_path: Optional[Path]`
- `success: bool`
- `summary: str`

#### `AutonomousDecision` (dataclass) — backward compat
- `decision_type: str`
- `reasoning: str`
- `action_plan: Dict[str, Any]`
- `expected_outcome: str`
- `risk_level: str`
- `auto_approved: bool = False`

### Pure Helper Functions

#### `_to_domain(target: str) -> str`
- Strips URL to bare hostname (removes scheme, port, path)

#### `_ai_call(ai_client, system: str, user: str, temperature: float = 0.3) -> str`
- **I/O**: network (AI API call)
- Wraps `ai_client.chat()` with AIMessage list
- Returns response content or empty string on error

#### `_parse_json(text: str) -> dict`
- Pure logic — delegates to `agents.agent_helpers.extract_json(text, expect="object")`
- Returns `{}` on failure

#### `_build_headers(state: AgentState, extra: dict = None) -> dict`
- Pure logic — merges User-Agent, auth_headers from state, and extra dict

### Action Executor Functions (all return `List[Dict]`)

Each executor takes `(action: AgentAction, state: AgentState)` and optionally `ai_client`. Each appends to `state.assets` as a side effect.

| Function | Action Name | I/O Type | Key Behavior |
|----------|-------------|----------|--------------|
| `_exec_recon` | `recon` | Network (SmartReconEngine) | DNS/subdomain discovery, stores assets by type |
| `_exec_http_probe` | `http_probe` | Network (requests.get) | Checks security headers (HSTS, X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy), stores server fingerprint |
| `_exec_waf_detect` | `waf_detect` | Network (requests x2) | Clean probe + attack probe, uses `waf_signatures.detect_waf_from_response` |
| `_exec_endpoint_fuzz` | `endpoint_fuzz` | Network (requests per wordlist) | Uses `WordlistManager.get_smart_wordlist()`, falls back to `[/api, /admin, /login, /.env, /config]` |
| `_exec_bola_probe` | `bola_probe` | Network (requests x8) | Tests `/api/users/{1,2}`, `/api/orders/{1,2}`, etc. unauthenticated |
| `_exec_header_audit` | `header_audit` | Network (requests.options) | CORS wildcard + reflection test with `Origin: https://evil.com` |
| `_exec_osint_research` | `osint_research` | Network (Tavily via research_target) | 3 results, summarized |
| `_exec_vuln_intel` | `vuln_intel` | Network (VulnCheck via get_target_intel) | Exploit/CVE intelligence |
| `_exec_wayback_recon` | `wayback_recon` | Network (Wayback/OTX) | Historical URLs, params; stores in `wayback_paths`/`wayback_params` |
| `_exec_github_dork` | `github_dork` | Network (GitHub API) | Leak hunting; severity: credentials/aws_keys/private_keys=critical, env_files/internal_ips=high |
| `_exec_js_recon` | `js_recon` | Network (requests + js_analyzer) | Analyzes up to 10 JS files for secrets, API endpoints |
| `_exec_param_mine` | `param_mine` | Network (param_miner) | Hidden parameter discovery; uses wayback_params as hints |
| `_exec_cors_scan` | `cors_scan` | Network (cors_checker.check_cors) | Deep CORS misconfiguration testing |
| `_exec_injection_test` | `injection_test` | Network (injection_tester) | XSS/SQLi/SSTI/LFI/Open Redirect on discovered params + wayback URLs |
| `_exec_subdomain_takeover` | `subdomain_takeover` | Network (subdomain_takeover.check_subdomains) | Checks discovered subdomains for takeover |
| `_exec_waf_bypass` | `waf_bypass` | Network (WAFEvasionEngine) | Detects WAF, tests 3 base payloads with mutations, max 8 attempts each |
| `_exec_request_auth` | `request_auth` | stdin (input()) | Pauses scan, prompts human for Cookie/Authorization header, stores in state.assets |
| `_exec_create_custom_tool` | `create_custom_tool` | Network (AIToolCreator) | AI writes Python exploit, executes with self-healing retry (max 2 retries) |
| `_exec_vuln_scan` | `vuln_scan` | Network (requests x10 paths) | Tests /.env, /.git, /admin, /robots.txt, /server-status, etc. |
| `_exec_xss_hunt` | `xss_hunt` | Network (requests) | Tests 4 XSS payloads on up to 5 discovered params |
| `_exec_zap_active_scan` | `zap_active_scan` | Network (ZAP API) | OWASP ZAP active scan; starts daemon if needed; polls progress |
| `_exec_ssrf_scan_ex` | `ssrf_scan` | Network (SSRFScanner) | SSRF testing |
| `_exec_graphql_ex` | `graphql_introspect` | Network (scan_graphql) | GraphQL introspection |
| `_exec_race_condition_ex` | `race_condition` | Network (scan_race_conditions) | Race condition testing |
| `_exec_auth_test_ex` | `auth_test` | Network (run_auth_tests) | JWT/OAuth/session testing |

### AI Analysis Functions

#### `_exec_analyze_findings(new_findings, action, state, ai_client) -> str`
- **I/O**: network (AI call)
- After each action, AI analyzes new findings
- Applies severity upgrades to existing findings
- Stores pivot targets in `state.assets["ai_pivots"]`
- Stores recommendation in `state.assets["ai_last_recommendation"]`
- Returns key insight string

#### `_ai_reflect_on_action(action, state, ai_client) -> tuple[bool, str, str]`
- **I/O**: network (AI call)
- Pre-action safety reflection
- Returns (approved: bool, reflection: str, risk_level: str)
- Auto-approves `threat_model` and `analyze` actions
- Temperature: 0.1 (very deterministic)

#### `_ai_decide_next(ai_client, state: AgentState) -> AgentAction`
- **I/O**: network (AI call)
- Main decision engine — AI picks next action from 24 available actions
- Fallback sequence (no AI): runs all actions sequentially in predefined order
- Defines action descriptions in 4 phases: Intelligence Gathering, Active Probing, Exploitation, Advanced/Custom
- Also includes: request_auth, auth_test, threat_model, analyze, done
- Temperature: 0.2

### `AutonomousAgent` Class

#### Constants
- `MAX_ITERATIONS = 25`

#### Constructor
```python
def __init__(self, governance_mode: str = "ask", ai_client=None)
```
- `governance_mode`: "ask" or "auto" — controls whether AI reflection is applied
- `ai_client`: optional; if None, creates `AIClientManager()`
- Creates `self.tool_creator` (AIToolCreator) if available
- Creates `self.abort_event` (threading.Event) for cancellation
- `self.decision_history: List[AgentAction]`

#### `run_autonomous_scan(target: str, goal: str = None) -> ScanResult`
- **I/O**: network, file (report, JSON export), telegram
- Main agentic loop, up to `MAX_ITERATIONS` iterations
- Each iteration: AI decides -> optional reflection -> execute -> analyze findings -> persist
- Initializes `MissionState` for tracking
- Saves findings to `user_memory` if available
- Rate limits: 1.5s sleep between iterations
- Handles `self.abort_event` and `KeyboardInterrupt`
- Generates bounty predictions, PDF report, JSON export

#### `_export_json(target, state, predictions, duration) -> None`
- **I/O**: file write to `data/scans/{domain}_{timestamp}.json`
- Excludes assets starting with "auth" from export

#### `_execute_action(action, state) -> List[Dict]`
- Dispatch table maps action names to executor functions
- Special handling for `threat_model`, `create_custom_tool`, `endpoint_fuzz` (pass ai_client)
- Returns empty list on unknown action or exception

#### `_predict_bounties(findings) -> List[Dict]`
- **I/O**: network (BountyPredictor)
- Returns list of `{finding_title, bounty_score, payout_range}`

#### `_generate_report(target, findings, predictions) -> Optional[Path]`
- **I/O**: file (PDFReportGenerator)
- Returns path to PDF or HTML report, or None

#### `_build_summary(target, state, duration) -> str`
- Pure logic — builds multiline summary string with severity counts and asset counts

#### `run_team_scan(target, goal=None) -> ScanResult`
- **I/O**: network, file
- Team Aegis mode: requires 2+ models in `ACTIVE_MODELS` env var
- Falls back to `run_autonomous_scan()` if insufficient models
- Creates `UniversalAIClient` per model, forms `TeamAegis`
- Runs `team.run_full_engagement(executor=executor)`
- Converts team findings to standard format
- Returns ScanResult

---

## Testing Notes

### Key Testable Behaviors per Module

**orchestrator.py:**
- `normalize_target` edge cases: empty, scheme stripping, port removal, trailing dots
- `is_valid_target`: private IP rejection, loopback rejection, domain label validation, length limit
- `is_in_scope`: empty ALLOWED_DOMAINS = all pass; subdomain matching
- `calculate_cvss_for_results`: severity ordering, empty results
- `_recon_to_findings`: various recon_result structures, missing fields
- `_check_cves_for_tech`: empty tech list, known CVE matches
- `run_elengenix_modules`: phase ordering, KeyboardInterrupt handling

**config_wizard.py:**
- `AIProviderConfig` dataclass construction
- `ConfigWizard.__init__`: .env permission setting
- `_save_env_var` / `_remove_env_var`: .env file manipulation
- `_load_yaml_config` / `_save_yaml_config`: YAML round-trip
- `_fetch_remote_models`: response parsing, Anthropic exclusion, model filtering
- `_test_provider`: NVIDIA param mode, timeout handling

**autonomous_agent.py:**
- Data class construction and defaults
- `_to_domain` URL parsing edge cases
- `_parse_json` fence stripping and error recovery
- `_build_headers` merging logic
- `_execute_action` dispatch completeness (24 actions)
- `AutonomousAgent.__init__`: fallback AI client creation
- `_ai_decide_next` fallback sequence (no AI)
- `_build_summary` output format

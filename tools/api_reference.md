# API Reference: universal_executor.py and tool_registry.py

## universal_executor.py

### Imports
`logging`, `re`, `shlex`, `subprocess` from stdlib. `dataclasses.dataclass`. `datetime.datetime` + `datetime.timezone`. `pathlib.Path`. `typing.{Any, Dict, List, Optional}`.

### Module-level globals
- `logger` — logger named `"elengenix.universal"`
- `_universal_executor` — lazy singleton, initially `None`
- `get_universal_executor(base_dir=None) -> UniversalExecutor` — returns the singleton, creating it on first call

### ExecutionResult (dataclass)
Fields: `success: bool`, `output: str`, `error: str`, `action_type: str`, `metadata: Dict[str, Any]`. No methods — pure data.

### FileEditor
Constructor: `__init__(self, base_dir: str = None)`. Resolves `base_dir` or defaults to `Path.cwd()`. Maintains `edit_history` list.

Private:
- `_validate_path(file_path: str) -> Optional[Path]` — resolves and checks the path stays within `base_dir`. Returns None on failure. Pure logic, no I/O.

Public methods (all return `ExecutionResult`):

1. `read_file(file_path: str, offset: int = 1, limit: int = 100)` — File I/O. Blocks seven sensitive filenames (`.env`, `.env.local`, `.env.production`, `config.yaml`, `config.yml`, `secrets.json`, `credentials.json`). Reads UTF-8 with `errors='replace'`. Returns line-numbered slice. Metadata: `total_lines`, `showing` range string, `truncated` bool.

2. `write_file(file_path: str, content: str, overwrite: bool = False)` — File I/O. Creates parent directories. Refuses to overwrite unless `overwrite=True`. Appends to `edit_history` with timestamp and char count.

3. `edit_file(file_path: str, old_string: str, new_string: str)` — File I/O (read then write). Fails with count=0 or count>1 for `old_string`. Exactly one occurrence gets replaced via `str.replace(old, new, 1)`.

4. `search_in_file(file_path: str, pattern: str)` — File read only. Regex with `re.IGNORECASE`. Returns matches with 2-line context above/below each hit.

5. `list_directory(dir_path: str = ".", max_depth: int = 2)` — Filesystem traversal. Shows file sizes in bytes. Recurses one level into subdirectories when `max_depth > 1`.

### PackageManager
No constructor args. Class-level `MANAGERS` dict mapping five package managers (`pip`, `npm`, `apt`, `go`, `gem`) to action→command-template dicts.

1. `execute(manager: str, action: str, package: str = None)` — Subprocess I/O. Validates manager and action exist in `MANAGERS`. Formats template with `str.format`, splits via `shlex.split`, runs with `subprocess.run(shell=False, timeout=300)`. Output capped at 5000 chars. Handles `TimeoutExpired`.

### UniversalExecutor
Constructor: `__init__(self, base_dir: str = None)`. Composes a `FileEditor`, a `PackageManager`, and a `Governance(require_approval_high_risk=True)`. Maintains `execution_history`.

Private:
- `_approve_shell_command(command: str) -> tuple[bool, str]` — Subprocess + interactive I/O. Runs `Governance.gate()`. If decision is `needs_approval`, calls `_prompt_approval` from `agent_executor` for interactive user consent. Can enable `auto_approve_privileged` on the governance object.

Public methods:

1. `is_safe_command(command: str) -> tuple[bool, str]` — Pure logic. Delegates to `Governance.gate()` and `shlex.split` parse check. Returns `(False, reason)` for empty commands, denied commands, or parse errors. Returns `(True, "")` otherwise.

2. `execute_shell(command: str, timeout: int = 300, cwd: str = None, agent_id: int = -1)` — Subprocess I/O. Calls `_approve_shell_command` first. When `agent_id >= 0` and no `cwd`, creates an isolated workspace under `data/team_workspaces/agent_{id}`. Uses `subprocess.run(shell=True)`. Output capped at 10000 chars. Logs to `execution_history`.

3. `execute_action(action: Dict[str, Any])` — Central dispatcher. Routes by `action["type"]` to the appropriate handler. Supported types and their I/O characteristics:

   - `read_file` → FileEditor.read_file (file read)
   - `write_file` → FileEditor.write_file (file write)
   - `edit_file` → FileEditor.edit_file (file read+write)
   - `search_file` → FileEditor.search_in_file (file read)
   - `list_dir` → FileEditor.list_directory (filesystem)
   - `shell` → execute_shell (subprocess)
   - `run_tool` → Async tool registry execution (subprocess via tool). Supports parallel execution when `params["tools"]` is a list (up to 5 concurrent via semaphore). Single tool uses semaphore of 3.
   - `package` → PackageManager.execute (subprocess)
   - `search_web` → research_tool.search_web + extract_and_summarize (network)
   - `bounty_intel` → BountyIntelligence.discover_programs_public (network)
   - `github_search` → github_intel.search_code (network)
   - `cve_lookup` → CVE database get/search (local DB)
   - `js_analyze` → js_analyzer.analyze_js (network)
   - `check_takeover` → subdomain_takeover.check_single_subdomain (network)
   - `ask_user` → interactive stdin input or getpass (interactive I/O). Also sends Telegram notifications and saves to vector memory.
   - `submit_findings` → vector_memory.remember for each finding (memory write)
   - `web_search` → alias for `search_web`

4. `get_capabilities() -> str` — Pure logic. Returns a markdown string describing all supported action types.

---

## tool_registry.py

### Imports
`asyncio`, `logging`, `shutil` from stdlib. `abc.{ABC, abstractmethod}`. `dataclasses.{dataclass, field}`. `enum.Enum`. `pathlib.Path`. `typing.{Any, Callable, Dict, List, Optional, Type, Union}`. `rich.progress.{Progress, SpinnerColumn, TextColumn}`. `ui_components.console`.

### Module-level globals
- `logger` — logger named `"elengenix.tools"`
- `registry` — singleton `ToolRegistry()` instance, created at module load
- `discoveries` — result of `auto_discover_tools()` run at import time

### ToolCategory (Enum)
Values: `RECON="reconnaissance"`, `SCANNER="vulnerability_scanner"`, `EXPLOITATION="exploitation"`, `FUZZING="fuzzing"`, `SECRETS="secret_detection"`, `API="api_testing"`, `NETWORK="network_scanning"`, `REPORTING="reporting"`, `UTILITY="utility"`

### ToolPriority (Enum)
Values: `CRITICAL=1`, `HIGH=2`, `MEDIUM=3`, `LOW=4`

### ToolResult (dataclass)
Fields: `success: bool`, `tool_name: str`, `category: ToolCategory`, `output: str = ""`, `findings: List[Dict[str, Any]] = field(default_factory=list)`, `execution_time: float = 0.0`, `error_message: Optional[str] = None`, `raw_output_file: Optional[Path] = None`.

Methods:
- `to_dict() -> Dict[str, Any]` — Serializes to dict. Truncates `output` to 500 chars. Includes `findings_count` instead of full findings list.

### ToolMetadata (dataclass)
Fields: `name: str`, `category: ToolCategory`, `priority: ToolPriority`, `binary_name: str`, `description: str`, `requires_target: bool = True`, `supports_list_input: bool = False`, `timeout_seconds: int = 300`, `extra_args: Dict[str, Any] = field(default_factory=dict)`.

### BaseTool (ABC)
Constructor: `__init__(self, metadata: ToolMetadata)`. Calls `_check_binary()` on init.

Properties:
- `is_available -> bool` — calls `_check_binary()`

Private:
- `_check_binary() -> bool` — uses `shutil.which()` to verify the binary exists in PATH

Abstract method:
- `async execute(target: Union[str, List[str]], report_dir: Path, semaphore: asyncio.Semaphore, **kwargs) -> ToolResult` — must be implemented by subclasses

Other methods:
- `_build_command(target, output_file, extra_flags=None) -> List[str]` — raises `NotImplementedError` by default; override in subclasses
- `async _run_subprocess(cmd: List[str], timeout: Optional[int] = None, semaphore: Optional[asyncio.Semaphore] = None) -> tuple` — Subprocess I/O. Uses `asyncio.create_subprocess_exec` with `shell=False`. Respects semaphore for concurrency limiting. Returns `(stdout, stderr, return_code)`. Handles `TimeoutError` (kills process), `FileNotFoundError`, and `OSError`.

### ToolRegistry (Singleton)
Class-level: `_instance`, `_tools: Dict[str, BaseTool]`, `_categories: Dict[ToolCategory, List[str]]`. Singleton via `__new__`.

Constructor: `__init__()` — only runs once (guarded by `_initialized` flag). Calls `load_dynamic_tools()`.

Public methods:

1. `register(tool: BaseTool) -> None` — Adds tool to `_tools` dict and `_categories` index.

2. `unregister(name: str) -> None` — Removes from both `_tools` and `_categories`.

3. `load_dynamic_tools(ai_tools_dir: Union[str, Path] = "tools/ai_generated") -> None` — Filesystem I/O + dynamic import. Globs `*.py` in the given directory, imports each via `importlib.util.spec_from_file_location`. Silently skips on import failure.

4. `get_tool(name: str) -> Optional[BaseTool]` — Dict lookup.

5. `get_tools_by_category(category: ToolCategory) -> List[BaseTool]` — Filters by category, preserves registration order.

6. `list_available_tools() -> Dict[str, Dict[str, Any]]` — Returns all tools with their `available` status, `category`, `priority`, and `description`.

7. `get_recommended_chain(target_type: str = "web") -> List[BaseTool]` — Returns ordered tool list for a given target type. Three presets: `"web"` (RECON→NETWORK→API→SECRETS→SCANNER→EXPLOITATION), `"api"` (RECON→API→SECRETS→FUZZING), `"network"` (NETWORK→RECON→SCANNER). Falls back to `"web"` for unknown types. Within each category, tools are sorted by priority value.

8. `async execute_chain(tools: List[BaseTool], target: str, report_dir: Path, rate_limit: int = 5, progress_callback: Optional[Callable] = None) -> List[ToolResult]` — Async I/O. Runs tools sequentially (not in parallel), each with a shared semaphore. Skips unavailable tools. Shows Rich progress spinner. Calls `progress_callback(result)` after each tool. Returns list of `ToolResult` including failures.

### register_tool decorator
`register_tool(metadata: ToolMetadata)` — Decorator factory. Validates the decorated class is a `BaseTool` subclass. Instantiates it with the metadata and registers with the global `registry`. Returns the original class unchanged.

### Built-in registered tools (17 total)
All subclass `BaseTool`, all override `_check_binary` to always return `True` (they're pure Python), all share the same `execute` signature pattern: instantiate the underlying scanner, call its scan/fuzz/check method, convert results to `findings` list, return `ToolResult`.

| Registry Name | Class | Category | Priority | Timeout |
|---|---|---|---|---|
| `waf_detector` | WAFDetectorTool | SCANNER | HIGH | 120s |
| `active_fuzzer` | ActiveFuzzerTool | FUZZING | HIGH | 300s |
| `python_recon` | PythonReconTool | RECON | MEDIUM | 180s |
| `ssrf_scanner` | SSRFScannerTool | SCANNER | HIGH | 300s |
| `ssti_scanner` | SSTIScannerTool | SCANNER | HIGH | 300s |
| `xxe_scanner` | XXEScannerTool | SCANNER | HIGH | 300s |
| `deserialization_scanner` | DeserializationScannerTool | SCANNER | HIGH | 300s |
| `graphql_scanner` | GraphQLScannerTool | API | HIGH | 300s |
| `race_condition_tester` | RaceConditionTesterTool | SCANNER | HIGH | 300s |
| `api_schema_diff` | APISchemaDiffTool | API | MEDIUM | 120s |
| `supply_chain_analyzer` | SupplyChainAnalyzerTool | SCANNER | MEDIUM | 120s |
| `logic_flaw_engine` | LogicFlawEngineTool | SCANNER | HIGH | 300s |
| `cors_checker` | CORSCheckerTool | SCANNER | MEDIUM | 120s |
| `jwt_tester` | JWTTesterTool | SCANNER | HIGH | 300s |

Note: `auto_discover_tools()` runs at import time and attempts to `__import__` every `*.py` in `tools/`. This means any module-level code (including `@register_tool` decorators) executes during the import of `tool_registry.py` itself.

### auto_discover_tools() -> List[str]
Filesystem I/O + dynamic import. Scans `tools/` for `.py` files, skips `tool_registry`, `__init__`, `__pycache__`. Returns list of successfully imported module names. Errors are logged at debug level and silently skipped.

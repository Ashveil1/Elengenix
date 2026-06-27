"""
tools/universal_executor.py — Universal AI Agent Executor
- Flexible like Claude Code, Gemini CLI, OpenClaw
- File operations: read, edit, write, search
- Package management: pip, npm, apt, gem, etc.
- Shell execution with intelligent allowlist
- Multi-turn conversation support
- Bug Bounty specialized reasoning
"""

from __future__ import annotations

import logging
import re
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.universal")


@dataclass
class ExecutionResult:
    """Standard result format for all operations."""

    success: bool
    output: str
    error: str
    action_type: str
    metadata: Dict[str, Any]


class FileEditor:
    """Intelligent file editor like Claude Code."""

    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir).resolve() if base_dir else Path.cwd().resolve()
        self.edit_history: List[Dict] = []

    def _validate_path(self, file_path: str) -> Optional[Path]:
        """Validate and resolve path within base directory."""
        try:
            path = Path(file_path).resolve()
            # Security: Must be within project directory
            if not str(path).startswith(str(self.base_dir)):
                logger.warning(f"Path outside base dir blocked: {file_path}")
                return None
            return path
        except Exception as e:
            logger.error(f"Invalid path: {e}")
            return None

    def read_file(self, file_path: str, offset: int = 1, limit: int = 100) -> ExecutionResult:
        """Read file with line numbers."""
        # Prevent accidental secret disclosure
        sensitive_names = {
            ".env",
            ".env.local",
            ".env.production",
            "config.yaml",
            "config.yml",
            "secrets.json",
            "credentials.json",
        }
        try:
            if Path(file_path).name in sensitive_names:
                return ExecutionResult(
                    False,
                    "",
                    f"Access denied for sensitive file: {Path(file_path).name}",
                    "read",
                    {"file": file_path, "blocked": True},
                )
        except Exception:
            pass

        path = self._validate_path(file_path)
        if not path:
            return ExecutionResult(False, "", "Invalid or unsafe path", "read", {})

        if not path.exists():
            return ExecutionResult(False, "", f"File not found: {file_path}", "read", {})

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            lines = content.split("\n")

            # Get requested range
            start_idx = max(0, offset - 1)
            end_idx = min(len(lines), offset - 1 + limit)
            selected_lines = lines[start_idx:end_idx]

            # Format with line numbers
            numbered = []
            for i, line in enumerate(selected_lines, start_idx + 1):
                numbered.append(f"{i:4d} | {line}")

            output = "\n".join(numbered)
            total_lines = len(lines)

            return ExecutionResult(
                True,
                output,
                "",
                "read",
                {
                    "file": str(path),
                    "total_lines": total_lines,
                    "showing": f"{offset}-{min(end_idx, total_lines)}",
                    "truncated": limit < total_lines,
                },
            )
        except Exception as e:
            return ExecutionResult(False, "", str(e), "read", {})

    def write_file(self, file_path: str, content: str, overwrite: bool = False) -> ExecutionResult:
        """Write content to file."""
        path = self._validate_path(file_path)
        if not path:
            return ExecutionResult(False, "", "Invalid or unsafe path", "write", {})

        if path.exists() and not overwrite:
            return ExecutionResult(
                False,
                "",
                "File exists. Use overwrite=True to replace.",
                "write",
                {"file": str(path)},
            )

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

            # Log edit
            self.edit_history.append(
                {
                    "action": "write",
                    "file": str(path),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "chars": len(content),
                }
            )

            return ExecutionResult(
                True,
                f"Written {len(content)} chars to {path}",
                "",
                "write",
                {"file": str(path), "chars": len(content)},
            )
        except Exception as e:
            return ExecutionResult(False, "", str(e), "write", {})

    def edit_file(self, file_path: str, old_string: str, new_string: str) -> ExecutionResult:
        """Strategic file edit - replace old with new (like Claude Code)."""
        path = self._validate_path(file_path)
        if not path:
            return ExecutionResult(False, "", "Invalid or unsafe path", "edit", {})

        if not path.exists():
            return ExecutionResult(False, "", f"File not found: {file_path}", "edit", {})

        try:
            content = path.read_text(encoding="utf-8", errors="replace")

            # Count occurrences
            count = content.count(old_string)
            if count == 0:
                return ExecutionResult(
                    False,
                    "",
                    "String not found in file. Use search first to verify.",
                    "edit",
                    {"file": str(path), "attempted": old_string[:50]},
                )

            if count > 1:
                return ExecutionResult(
                    False,
                    "",
                    f"Found {count} occurrences. Be more specific with unique context.",
                    "edit",
                    {"file": str(path), "count": count},
                )

            # Perform edit
            new_content = content.replace(old_string, new_string, 1)
            path.write_text(new_content, encoding="utf-8")

            # Log edit
            self.edit_history.append(
                {
                    "action": "edit",
                    "file": str(path),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "old_len": len(old_string),
                    "new_len": len(new_string),
                }
            )

            return ExecutionResult(
                True,
                f"Edited {path}: {len(old_string)} chars → {len(new_string)} chars",
                "",
                "edit",
                {
                    "file": str(path),
                    "replaced_chars": len(old_string),
                    "new_chars": len(new_string),
                    "total_chars": len(new_content),
                },
            )
        except Exception as e:
            return ExecutionResult(False, "", str(e), "edit", {})

    def search_in_file(self, file_path: str, pattern: str) -> ExecutionResult:
        """Search pattern in file with context."""
        path = self._validate_path(file_path)
        if not path:
            return ExecutionResult(False, "", "Invalid or unsafe path", "search", {})

        if not path.exists():
            return ExecutionResult(False, "", f"File not found: {file_path}", "search", {})

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            lines = content.split("\n")

            matches = []
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Get context (2 lines before and after)
                    start = max(0, i - 3)
                    end = min(len(lines), i + 2)
                    context = lines[start:end]

                    matches.append(
                        {
                            "line": i,
                            "match": line.strip(),
                            "context": "\n".join(
                                [f"{j+1:4d} | {l}" for j, l in enumerate(context, start)]
                            ),
                        }
                    )

            if not matches:
                return ExecutionResult(
                    True,
                    f"No matches for '{pattern}'",
                    "",
                    "search",
                    {"file": str(path), "pattern": pattern, "matches": 0},
                )

            output = f"Found {len(matches)} matches for '{pattern}':\n\n"
            for m in matches:
                output += f"Line {m['line']}:\n{m['context']}\n{'─' * 40}\n"

            return ExecutionResult(
                True,
                output,
                "",
                "search",
                {"file": str(path), "pattern": pattern, "matches": len(matches)},
            )
        except Exception as e:
            return ExecutionResult(False, "", str(e), "search", {})

    def list_directory(self, dir_path: str = ".", max_depth: int = 2) -> ExecutionResult:
        """List directory structure."""
        path = self._validate_path(dir_path)
        if not path:
            return ExecutionResult(False, "", "Invalid or unsafe path", "list", {})

        if not path.is_dir():
            return ExecutionResult(False, "", f"Not a directory: {dir_path}", "list", {})

        try:
            files = []
            for item in sorted(path.iterdir()):
                rel_path = item.relative_to(self.base_dir)
                if item.is_dir():
                    files.append(f" {rel_path}/")
                    if max_depth > 1:
                        for sub in sorted(item.iterdir()):
                            if sub.is_file():
                                files.append(f"    {sub.relative_to(self.base_dir)}")
                else:
                    size = item.stat().st_size
                    files.append(f" {rel_path} ({size:,} bytes)")

            output = f"Contents of {path.relative_to(self.base_dir)}:\n" + "\n".join(files)
            return ExecutionResult(
                True, output, "", "list", {"dir": str(path), "items": len(files)}
            )
        except Exception as e:
            return ExecutionResult(False, "", str(e), "list", {})


class PackageManager:
    """Universal package manager for multiple ecosystems."""

    MANAGERS = {
        "pip": {
            "install": "pip install {package} --quiet",
            "uninstall": "pip uninstall {package} -y",
            "search": "pip search {package}",
            "list": "pip list",
            "update": "pip install --upgrade {package}",
        },
        "npm": {
            "install": "npm install {package} --silent",
            "uninstall": "npm uninstall {package}",
            "search": "npm search {package}",
            "list": "npm list",
            "update": "npm update {package}",
        },
        "apt": {
            "install": "apt-get install -y {package}",
            "uninstall": "apt-get remove -y {package}",
            "search": "apt-cache search {package}",
            "list": "dpkg -l",
            "update": "apt-get upgrade -y {package}",
        },
        "go": {
            "install": "go install {package}@latest",
            "uninstall": "rm $(which {binary})",
            "list": "go list -m all",
        },
        "gem": {
            "install": "gem install {package} --no-document",
            "uninstall": "gem uninstall {package}",
            "list": "gem list",
        },
    }

    def execute(self, manager: str, action: str, package: str = None) -> ExecutionResult:
        """Execute package manager command."""
        if manager not in self.MANAGERS:
            return ExecutionResult(
                False,
                "",
                f"Unknown package manager: {manager}. Supported: {list(self.MANAGERS.keys())}",
                "package",
                {},
            )

        if action not in self.MANAGERS[manager]:
            return ExecutionResult(
                False, "", f"Action '{action}' not supported for {manager}", "package", {}
            )

        cmd_template = self.MANAGERS[manager][action]
        safe_package = (package or "").strip()
        # Build command using list form — NOT string formatting — to prevent injection.
        cmd_str = cmd_template.format(
            package=safe_package,
            binary=(
                safe_package.split()[-1]
                if safe_package and " " not in safe_package
                else safe_package
            ),
        )
        args = shlex.split(cmd_str)

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=300, shell=False)

            output = result.stdout if result.stdout else result.stderr
            success = result.returncode == 0

            return ExecutionResult(
                success,
                output[:5000],  # Limit output size
                "" if success else f"Exit code: {result.returncode}",
                "package",
                {
                    "manager": manager,
                    "action": action,
                    "package": package,
                    "exit_code": result.returncode,
                },
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(False, "", "Command timed out after 300s", "package", {})
        except Exception as e:
            return ExecutionResult(False, "", str(e), "package", {})


class UniversalExecutor:
    """
    Universal AI Agent Executor.
    Combines file editing, package management, and flexible shell execution.
    """

    def __init__(self, base_dir: str = None):
        self.file_editor = FileEditor(base_dir)
        self.package_manager = PackageManager()
        self.execution_history: List[Dict] = []
        from tools.governance import Governance

        self._governance = Governance(require_approval_high_risk=True)

    def is_safe_command(self, command: str) -> tuple[bool, str]:
        """Check if command is safe to execute.

        Uses canonical Governance classification:
          DESTRUCTIVE → blocked
          PRIVILEGED  → needs interactive approval (handled by caller)
          SAFE        → allowed
        """
        if not command or not command.strip():
            return False, "Empty command"

        # Delegate to canonical Governance (single source of truth)
        action = {"type": "run_shell", "command": command}
        result = self._governance.gate(
            mission_id="universal_executor",
            target="unknown",
            action=action,
        )

        if result.decision == "deny":
            return False, result.rationale

        try:
            shlex.split(command.strip())
        except ValueError as e:
            return False, f"Parse error: {e}"

        # SAFE or needs_approval — caller gates privileged
        return True, ""

    def _approve_shell_command(self, command: str) -> tuple[bool, str]:
        """Apply canonical Governance gating before shell execution."""
        gate = self._governance.gate(
            mission_id="universal_executor",
            target="unknown",
            action={"type": "run_shell", "command": command},
        )

        if gate.decision == "deny":
            return False, gate.rationale

        if gate.decision == "needs_approval":
            try:
                from agents.agent_executor import _prompt_approval

                approved, enable_auto = _prompt_approval(
                    cmd=command,
                    risk_level=gate.risk_level,
                    purpose="UniversalExecutor shell command",
                    governance=self._governance,
                )
            except Exception:
                approved, enable_auto = False, False

            if enable_auto:
                self._governance.auto_approve_privileged = True
            if not approved:
                return False, "Command rejected by user."

        try:
            shlex.split(command.strip())
        except ValueError as e:
            return False, f"Parse error: {e}"

        return True, ""

    def execute_shell(
        self, command: str, timeout: int = 300, cwd: str = None, agent_id: int = -1
    ) -> ExecutionResult:
        """Execute shell command with native shell support (shell=True).

        Uses shell=True for full pipeline and scripting flexibility.
        When agent_id is provided, creates an isolated working directory
        to prevent multi-agent file conflicts.

        Args:
            command: Shell command string (supports pipes, redirects, etc.)
            timeout: Maximum execution time in seconds
            cwd: Working directory override
            agent_id: Agent identifier for workspace isolation (-1 = no isolation)
        """
        approved, reason = self._approve_shell_command(command)
        if not approved:
            return ExecutionResult(False, "", reason, "shell", {"command": command})

        # Agent workspace isolation: each agent gets its own temp dir
        work_dir = cwd
        if agent_id >= 0 and not cwd:
            from pathlib import Path

            agent_dir = Path("data") / "team_workspaces" / f"agent_{agent_id}"
            agent_dir.mkdir(parents=True, exist_ok=True)
            work_dir = str(agent_dir)

        # Transparent execution markers for CLI
        if "sudo " in command or "apt " in command or "pip " in command:
            print("\n[THOUGHT] Agent is executing a system-level action")
            print(f"[COMMAND] {command}")
            if "sudo " in command:
                print(
                    "[RUN]     Privileged action (sudo) requested. Please provide your password if prompted:\n"
                )

        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout, shell=True, cwd=work_dir
            )

            output = result.stdout
            if result.stderr and result.returncode != 0:
                output += f"\n[STDERR]: {result.stderr}"

            # Log execution
            self.execution_history.append(
                {
                    "command": command,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "success": result.returncode == 0,
                    "exit_code": result.returncode,
                    "agent_id": agent_id,
                }
            )

            return ExecutionResult(
                result.returncode == 0,
                output[:10000],  # Limit output
                result.stderr if result.returncode != 0 else "",
                "shell",
                {
                    "command": command,
                    "exit_code": result.returncode,
                    "duration": timeout,
                    "agent_id": agent_id,
                },
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                False, "", f"Timeout after {timeout}s", "shell", {"command": command}
            )
        except Exception as e:
            return ExecutionResult(False, "", str(e), "shell", {"command": command})

    # NOTE: _execute_pipeline is no longer needed — shell=True handles
    # pipes, redirects, and command chaining natively.

    def execute_action(self, action: Dict[str, Any]) -> ExecutionResult:
        """
        Execute a structured action from AI.

        Action format:
        {
            "type": "read_file|write_file|edit_file|search_file|list_dir|shell|package|search_web",
            "params": {...}
        }
        """
        action_type = action.get("type", "")
        params = action.get("params", {})

        if action_type == "read_file":
            return self.file_editor.read_file(
                params.get("path"), params.get("offset", 1), params.get("limit", 100)
            )

        elif action_type == "write_file":
            return self.file_editor.write_file(
                params.get("path"), params.get("content"), params.get("overwrite", False)
            )

        elif action_type == "edit_file":
            return self.file_editor.edit_file(
                params.get("path"), params.get("old_string"), params.get("new_string")
            )

        elif action_type == "search_file":
            return self.file_editor.search_in_file(params.get("path"), params.get("pattern"))

        elif action_type == "list_dir":
            return self.file_editor.list_directory(
                params.get("path", "."), params.get("max_depth", 2)
            )

        elif action_type == "shell":
            return self.execute_shell(
                params.get("command"),
                params.get("timeout", 300),
                params.get("cwd"),
                agent_id=params.get("agent_id", -1),
            )

        elif action_type == "run_tool":
            import asyncio
            import time
            from pathlib import Path

            from tools.tool_registry import ToolResult, registry

            tool_name = params.get("tool", "")
            tool_target = params.get("target", "")
            params.get("args", "")
            tool_list = params.get("tools", [])

            # Support parallel execution: if "tools" is a list, run all concurrently
            if tool_list:
                targets = [tool_target] * len(tool_list) if tool_target else [""] * len(tool_list)

                async def _run_parallel():
                    sem = asyncio.Semaphore(5)

                    async def _run_one(name, tgt):
                        t = registry.get_tool(name)
                        if not t or not t.is_available:
                            return ToolResult(False, name, error_message=f"{name} not available")
                        rd = Path("reports") / f"run_{name}_{int(time.time())}"
                        rd.mkdir(parents=True, exist_ok=True)
                        return await t.execute(tgt, rd, sem)

                    results = await asyncio.gather(
                        *[_run_one(n, t) for n, t in zip(tool_list, targets)]
                    )
                    lines = [f"[{r.tool_name}] {len(r.findings)} findings" for r in results]
                    total = sum(len(r.findings) for r in results)
                    return "\n".join(lines), total

                try:
                    output, total_findings = asyncio.run(_run_parallel())
                    return ExecutionResult(
                        True,
                        output,
                        "",
                        "run_tool",
                        {"tools": tool_list, "total_findings": total_findings},
                    )
                except Exception as e:
                    return ExecutionResult(False, "", str(e), "run_tool", params)

            # Single tool execution
            if not tool_name:
                return ExecutionResult(False, "", "No tool specified", "run_tool", params)
            tool = registry.get_tool(tool_name)
            if not tool or not tool.is_available:
                return ExecutionResult(
                    False, "", f"Tool '{tool_name}' not available", "run_tool", params
                )
            report_dir = Path("reports") / f"run_{tool_name}_{int(time.time())}"
            report_dir.mkdir(parents=True, exist_ok=True)
            try:

                async def _run():
                    sem = asyncio.Semaphore(3)
                    return await tool.execute(tool_target, report_dir, sem)

                result = asyncio.run(_run())
                output = result.output or f"{len(result.findings)} findings"
                return ExecutionResult(
                    result.success,
                    output[:5000],
                    result.error_message or "",
                    "run_tool",
                    {"tool": tool_name, "findings": len(result.findings), "target": tool_target},
                )
            except Exception as e:
                return ExecutionResult(False, "", str(e), "run_tool", params)

        elif action_type == "package":
            return self.package_manager.execute(
                params.get("manager", "pip"), params.get("action", "install"), params.get("package")
            )

        elif action_type == "search_web":
            from tools.research_tool import extract_and_summarize, search_web

            query = params.get("query", "")
            num = params.get("num_results", 5)

            # Get search results
            results = search_web(query, num)

            # Extract content from top results for better context
            enriched_results = []
            for r in results[:3]:  # Top 3 results
                url = r.get("url", "")
                title = r.get("title", "")
                content = r.get("content", "")

                # If no content, try to extract from URL
                if not content and url:
                    try:
                        extracted = extract_and_summarize(url, max_chars=1000)
                        content = extracted.get("text", "")[:800]
                    except Exception as e:
                        logger.debug(f"Could not extract content from {url}: {e}")

                enriched_results.append(
                    {
                        "url": url,
                        "title": title,
                        "content": content[:1000] if content else "[Visit URL for full content]",
                    }
                )

            output_text = f"Search results for '{query}':\n\n"
            for i, r in enumerate(enriched_results, 1):
                output_text += f"[{i}] {r['title']}\n"
                output_text += f"URL: {r['url']}\n"
                output_text += f"Content: {r['content'][:500]}...\n\n"

            return ExecutionResult(
                True,
                output_text,
                "",
                "search_web",
                {"query": query, "results": len(enriched_results)},
            )

        elif action_type == "bounty_intel":
            from tools.bounty_intelligence import BountyIntelligence

            program = params.get("program", "")
            result = []
            try:
                bi = BountyIntelligence()
                if program:
                    programs = bi.discover_programs_public(limit=20)
                    result = [p for p in programs if program.lower() in p.name.lower()][:5]
                else:
                    result = bi.discover_programs_public(limit=10)
                output = "\n".join(
                    [f"  - {p.name}: ${p.min_bounty}-${p.max_bounty} ({p.state})" for p in result]
                )
                return ExecutionResult(
                    True, output or "No programs found.", "", "bounty_intel", {"count": len(result)}
                )
            except Exception as e:
                return ExecutionResult(False, "", str(e), "bounty_intel", params)

        elif action_type == "github_search":
            from tools.github_intel import search_code

            query = params.get("query", "")
            if not query:
                return ExecutionResult(False, "", "No query specified", "github_search", params)
            try:
                results = search_code(query)
                output = "\n".join(
                    [f"  - {r.get('repo', '?')}: {r.get('file', '?')}" for r in results[:10]]
                )
                return ExecutionResult(
                    True, output or "No results.", "", "github_search", {"count": len(results)}
                )
            except Exception as e:
                return ExecutionResult(False, "", str(e), "github_search", params)

        elif action_type == "cve_lookup":
            from tools.cve_database import get_cve_database

            cve_id = params.get("cve_id", "")
            keyword = params.get("keyword", "")
            try:
                db = get_cve_database()
                if cve_id:
                    entry = db.get_cve(cve_id)
                    output = f"{entry.cve_id}: {entry.description[:200]}" if entry else "Not found."
                elif keyword:
                    results = db.search_cves(keyword, limit=5)
                    output = "\n".join([f"  - {r.cve_id}: {r.description[:100]}" for r in results])
                else:
                    output = "Specify cve_id or keyword."
                return ExecutionResult(True, output, "", "cve_lookup", {})
            except Exception as e:
                return ExecutionResult(False, "", str(e), "cve_lookup", params)

        elif action_type == "js_analyze":
            from tools.js_analyzer import analyze_js

            url = params.get("url", "")
            if not url:
                return ExecutionResult(False, "", "No URL specified", "js_analyze", params)
            try:
                result = analyze_js(url)
                secrets = result.get("secrets", [])
                endpoints = result.get("endpoints", [])
                lines = [f"Found {len(secrets)} secrets, {len(endpoints)} endpoints"]
                for s in secrets[:5]:
                    lines.append(f"  [SECRET] {s.get('type', '?')}: {str(s.get('value', ''))[:80]}")
                for e in endpoints[:5]:
                    lines.append(f"  [ENDPOINT] {e}")
                return ExecutionResult(
                    True,
                    "\n".join(lines),
                    "",
                    "js_analyze",
                    {"secrets": len(secrets), "endpoints": len(endpoints)},
                )
            except Exception as e:
                return ExecutionResult(False, "", str(e), "js_analyze", params)

        elif action_type == "check_takeover":
            from tools.subdomain_takeover import check_single_subdomain

            subdomain = params.get("subdomain", "")
            if not subdomain:
                return ExecutionResult(
                    False, "", "No subdomain specified", "check_takeover", params
                )
            try:
                result = check_single_subdomain(subdomain)
                if result:
                    vuln = result.get("vulnerable", False)
                    service = result.get("service", "unknown")
                    output = f"TAKEOVER {'YES' if vuln else 'NO'} — {subdomain} → {service}"
                else:
                    output = f"No takeover risk detected for {subdomain}"
                return ExecutionResult(
                    True, output, "", "check_takeover", {"vulnerable": bool(result)}
                )
            except Exception as e:
                return ExecutionResult(False, "", str(e), "check_takeover", params)

        elif action_type == "ask_user":
            question = params.get("question", "")
            input_type = params.get("input_type", "confirm")

            if not question:
                return ExecutionResult(False, "", "No question provided", "ask_user", params)

            # Send Telegram notification first
            try:
                from bot_utils import send_telegram_notification

                send_telegram_notification(f"[ASK_USER] {question}")
            except Exception:
                pass  # Telegram optional

            # Check if running in non-interactive mode
            import sys

            if not sys.stdin.isatty():
                return ExecutionResult(
                    False, "", "Non-interactive mode - cannot ask user", "ask_user", params
                )

            # Format the question for user
            if input_type == "confirm":
                prompt = f"\n[?] {question} [y/N]: "
            elif input_type == "password":
                import getpass

                prompt = f"\n[?] {question}: "
                answer = getpass.getpass(prompt)
                # Save to memory
                from tools.vector_memory import remember

                remember(f"User provided password for: {question}", "system", "user_input")
                # Notify via Telegram
                try:
                    from bot_utils import send_telegram_notification

                    send_telegram_notification("[ASK_USER] Password received (hidden)")
                except Exception:
                    pass
                return ExecutionResult(
                    True, "Password received (hidden)", "", "ask_user", {"question": question}
                )
            else:
                prompt = f"\n[?] {question}: "

            # Get user input
            try:
                answer = input(prompt).strip()
            except EOFError:
                return ExecutionResult(False, "", "EOF reading input", "ask_user", params)
            except Exception as e:
                return ExecutionResult(False, "", f"Input error: {e}", "ask_user", params)

            # Save to memory
            from tools.vector_memory import remember

            remember(f"User answered: {answer} to question: {question}", "system", "user_input")

            # Notify Telegram of answer
            try:
                from bot_utils import send_telegram_notification

                send_telegram_notification(f"[USER_REPLY] {answer}")
            except Exception:
                pass

            return ExecutionResult(
                True, answer, "", "ask_user", {"question": question, "answer": answer}
            )

        elif action_type == "submit_findings":
            findings = params.get("findings", [])
            target = params.get("target", "")

            if not findings:
                return ExecutionResult(False, "", "No findings provided", "submit_findings", params)

            # Save each finding to memory
            from tools.vector_memory import remember

            saved_count = 0
            for finding in findings:
                finding_type = finding.get("type", "unknown")
                endpoint = finding.get("endpoint", "")
                severity = finding.get("severity", "unknown")
                description = finding.get("description", "")

                remember(
                    f"Finding: {finding_type} at {endpoint} - {description}",
                    target,
                    "finding",
                    severity=severity,
                )
                saved_count += 1

            return ExecutionResult(
                True,
                f"Saved {saved_count} findings to memory",
                "",
                "submit_findings",
                {"count": saved_count, "target": target},
            )

        elif action_type == "web_search":
            query = params.get("query", "")
            if not query:
                return ExecutionResult(False, "", "No query specified", "web_search", params)
            # Map web_search to search_web
            return self.execute_action({"type": "search_web", "params": params})

        else:
            return ExecutionResult(False, "", f"Unknown action type: {action_type}", "unknown", {})

    def get_capabilities(self) -> str:
        """Return capabilities description for AI prompt."""
        return """
## Universal Agent Capabilities

You can perform these actions:

### File Operations
- `read_file`: Read file with line numbers
- `write_file`: Create/edit file content
- `search_file`: Search within files using regex

### Shell & Tools
- `shell`: Execute any command (respects security restrictions)
- `run_tool`: Run a security tool from the registry (_ext_recon)
- `package`: Install/uninstall packages via pip, npm, apt, go

### Web & Intelligence
- `search_web`: Search the live internet (Google/DuckDuckGo/Tavily)
- `bounty_intel`: Look up bug bounty programs (HackerOne)
- `github_search`: Search GitHub for leaked secrets, credentials, or code
- `cve_lookup`: Search the local CVE database by CVE ID or keyword

### Finish
- `finish`: Complete the task with a summary
"""


# Global instance
_universal_executor = None


def get_universal_executor(base_dir: str = None) -> UniversalExecutor:
    """Get singleton UniversalExecutor instance."""
    global _universal_executor
    if _universal_executor is None:
        _universal_executor = UniversalExecutor(base_dir)
    return _universal_executor


if __name__ == "__main__":
    # Test
    print("Testing Universal Executor...")
    executor = UniversalExecutor()

    # Test file operations
    test_file = "/tmp/test_universal.txt"
    r1 = executor.file_editor.write_file(test_file, "Hello World\nLine 2\nLine 3")
    print(f"Write: {r1.success}")

    r2 = executor.file_editor.read_file(test_file)
    print(f"Read:\n{r2.output}")

    r3 = executor.file_editor.edit_file(test_file, "Line 2", "Line 2 MODIFIED")
    print(f"Edit: {r3.success}")

    r4 = executor.file_editor.read_file(test_file)
    print(f"After edit:\n{r4.output}")

    # Test shell
    r5 = executor.execute_shell("echo 'Universal Executor Working!'")
    print(f"Shell: {r5.output}")

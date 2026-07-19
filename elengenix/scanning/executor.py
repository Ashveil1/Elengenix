"""agents/agent_executor.py — Execution layer extracted from agent_brain.py.

Handles tool execution, user interaction, and governance-gated shell commands.
Reduces agent_brain.py by ~260 lines.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from tools.governance import Governance
from tools.safe_exec import execute_safely, execute_safely_streaming, execute_safely_interactive
from tools.tool_registry import ToolCategory, ToolResult, registry
from tools.vector_memory import remember

logger = logging.getLogger("elengenix.agent")


def execute_tool(
    action_data: Dict[str, Any],
    governance: Governance,
    max_output_len: int = 100000,
    callback: Optional[Callable] = None,
) -> str:
    """Execute a command with Governance-based security.

    Delegates to specialized handlers based on action type:
      run_shell   → execute_shell_command()
      ask_user    → handle_ask_user()
      web_search  → search web
      save_memory → persist to vector memory
      finish      → signal completion
    """
    action_val = action_data.get("action", "")
    if isinstance(action_val, dict):
        params = action_val.get("params", {})
        if isinstance(params, dict):
            action_data.update(params)
        action_val = action_val.get("type", "")
    action = str(action_val).lower()

    # Normalize action name aliases so AI output variations all work
    _ACTION_ALIASES = {
        "shell": "run_shell",
        "bash": "run_shell",
        "exec": "run_shell",
        "execute": "run_shell",
        "command": "run_shell",
        "run_command": "run_shell",
        "run_bash": "run_shell",
        "search": "web_search",
        "google": "web_search",
        "search_web": "web_search",
        "internet_search": "web_search",
        "remember": "save_memory",
        "memorize": "save_memory",
        "store_memory": "save_memory",
        "done": "finish",
        "complete": "finish",
        "end": "finish",
        "exit": "finish",
        "create_tool": "create_ai_tool",
        "run_tool": "run_ai_tool",
        "write_and_run": "write_script",
        "write_and_exec": "write_script",
        "script": "write_script",
        "install": "install_tool",
        "install_package": "install_tool",
        "install_binary": "install_tool",
    }
    action = _ACTION_ALIASES.get(action, action)

    cmd_raw = action_data.get("command", "")

    if action == "finish":
        return "__FINISH__"

    if action == "save_memory":
        remember(
            action_data.get("learning", ""),
            action_data.get("target", "global"),
            action_data.get("category", "general"),
        )
        return "Finding recorded in memory."

    if action == "ask_user":
        return handle_ask_user(action_data, callback)

    if action == "web_search":
        query = action_data.get("query", "")
        if not query:
            return "Error: web_search requires a 'query' parameter."
        try:
            from tools.research_tool import search_web

            results = search_web(query, num_results=5)
            return json.dumps(results, indent=2, ensure_ascii=False)
        except Exception as e:
            return f"Error executing web_search: {e}"

    if action == "create_ai_tool":
        try:
            from tools.ai_tool_creator import AIToolCreator, ToolSpec

            creator = AIToolCreator()
            spec = ToolSpec(
                name=action_data.get("name", "custom_tool"),
                purpose=action_data.get("purpose", ""),
                code=action_data.get("code", ""),
                dependencies=action_data.get("dependencies", []),
                ai_reasoning=action_data.get("ai_reasoning", ""),
            )
            success = creator.create_tool(spec)
            return "Tool created successfully." if success else "Failed to create tool."
        except Exception as e:
            return f"Error creating tool: {e}"

    if action == "run_ai_tool":
        try:
            from tools.ai_tool_creator import AIToolCreator

            creator = AIToolCreator()
            tool_name = action_data.get("name", "")
            kwargs = action_data.get("kwargs", {})
            result = creator.execute_tool(tool_name, **kwargs)
            return json.dumps(
                {
                    "success": result.success,
                    "output": result.output,
                    "error": result.error,
                    "findings": result.findings,
                },
                indent=2,
            )
        except Exception as e:
            return f"Error running tool: {e}"

    if action == "write_script":
        return execute_write_script(action_data, governance, max_output_len, callback)

    if action == "install_tool":
        return execute_install_tool(action_data, governance, max_output_len, callback)

    if action == "run_batch":
        return execute_batch(action_data, governance, max_output_len, callback)

    if action != "run_shell":
        return (
            f"Error: Unknown action '{action}'. "
            "Use: run_shell, run_batch, write_script, install_tool, ask_user, web_search, "
            "save_memory, create_ai_tool, run_ai_tool, or finish."
        )
    if not cmd_raw or not isinstance(cmd_raw, str):
        return "Error: Invalid or empty command."

    return execute_shell_command(
        cmd_raw,
        governance,
        max_output_len,
        callback,
        purpose=action_data.get("purpose", ""),
        thought=action_data.get("thought", ""),
    )


def execute_shell_command(
    cmd_raw: str,
    governance: Governance,
    max_output_len: int = 100000,
    callback: Optional[Callable] = None,
    purpose: str = "",
    thought: str = "",
) -> str:
    """Run a shell command through the Governance gate.

    Args:
        cmd_raw: Raw shell command string.
        governance: Governance instance for risk classification.
        max_output_len: Maximum characters to return from output.
        callback: Optional streaming callback.
        purpose: AI-stated reason for this command (shown in approval prompt).
        thought: AI's internal reasoning (shown in approval prompt).

    Returns:
        Command output or error message.
    """
    gate = governance.gate(
        mission_id="cli_tool_exec",
        target="local",
        action={"action": "run_shell", "command": cmd_raw},
        callback=callback,
    )

    if gate.decision == "deny":
        return f"[WARN] Command blocked by governance: {gate.rationale}"

    if gate.decision == "needs_approval":
        approved, enable_auto = _prompt_approval(
            cmd=cmd_raw,
            risk_level=gate.risk_level,
            purpose=purpose,
            thought=thought,
            governance=governance,
        )
        if enable_auto:
            governance.auto_approve_privileged = True
            logger.info("[OK] Auto-approve mode enabled for this session.")
        if not approved:
            return "[SKIP] Command rejected by user."

    try:
        import time as _time

        _t0 = _time.perf_counter()
        
        # Use streaming execution when callback is available (interactive mode)
        if callback:
            import json as _json
            
            # Collect all output lines
            all_lines = []
            
            def stream_callback(line):
                all_lines.append(line)
                # Stream each line to callback in real-time
                callback(
                    "exec_stream:"
                    + _json.dumps(
                        {
                            "cmd": cmd_raw,
                            "line": line,
                            "purpose": purpose,
                            "thought": thought,
                        }
                    )
                )
            
            # Execute with streaming
            safe_result = execute_safely_interactive(
                cmd_raw, timeout=300, line_callback=stream_callback
            )
            elapsed = _time.perf_counter() - _t0

            success = safe_result["success"]
            output = safe_result["stdout"]
            if safe_result.get("stderr"):
                output += "\n" + safe_result["stderr"]
            output = output[:max_output_len]

            # Final summary callback (backward-compatible with TUI consumers
            # that expect a single "exec:" message with the full output).
            # TUI implementations can opt-in to per-line streaming by also
            # handling the "exec_stream:" prefix.
            callback(
                "exec:"
                + _json.dumps(
                    {
                        "cmd": cmd_raw,
                        "output": output,
                        "success": success,
                        "elapsed": round(elapsed, 2),
                        "purpose": purpose,
                        "thought": thought,
                    }
                )
            )
        else:
            # Non-streaming execution for non-interactive mode
            safe_result = execute_safely(cmd_raw, timeout=300)
            elapsed = _time.perf_counter() - _t0

            success = safe_result["success"]
            output = safe_result["stdout"]
            if safe_result["stderr"]:
                output += "\n" + safe_result["stderr"]
            
            # Display in terminal mode
            from cli.ui_components import show_command_execution
            show_command_execution(
                cmd=cmd_raw,
                result=output,
                success=success,
                purpose=purpose,
                thought=thought,
                elapsed=elapsed,
            )

        if not success:
            err = safe_result["error"] or safe_result["stderr"][:500]

            # Check if failure is due to missing tool
            if "not found" in err.lower() or "command not found" in err.lower():
                install_result = detect_and_install_missing_tool(cmd_raw, governance, callback)
                if install_result is not None:
                    # Tool was installed — retry the command
                    try:
                        retry_result = execute_safely(cmd_raw, timeout=300)
                        if retry_result["success"]:
                            return retry_result["stdout"][:max_output_len]
                    except Exception:
                        pass

            return f"[FAIL] Command failed: {err}"
        return output

    except subprocess.TimeoutExpired:
        return "[FAIL] Error: Command timed out after 300 seconds."
    except ValueError as e:
        return f"[FAIL] Error: Invalid command syntax: {e}"
    except Exception as e:
        return f"[FAIL] Error executing tool: {str(e)}"


def _prompt_approval(
    cmd: str,
    risk_level: str = "PRIVILEGED",
    purpose: str = "",
    thought: str = "",
    governance: Optional[Any] = None,
) -> tuple[bool, bool]:
    """Display a 3-choice approval prompt for privileged commands.

    Choices:
        y  — Allow (this command only)
        a  — Allow Auto (this command + all future PRIVILEGED in this session)
        n  — Deny

    Args:
        cmd: The shell command to run.
        risk_level: Governance risk classification string.
        purpose: AI's stated purpose for running this command.
        thought: AI's internal chain-of-thought (optional).
        governance: Governance instance (used to check current auto-approve state).

    Returns:
        Tuple (approved: bool, enable_auto: bool).
        enable_auto is True only when the user selects Allow Auto.
    """
    from rich.panel import Panel

    from cli.ui_components import console

    label_color = "yellow" if risk_level == "PRIVILEGED" else "red"

    lines = []
    if thought:
        lines.append(f"[grey70]Thought : {thought}[/grey70]")
    if purpose:
        lines.append(f"[white]Purpose : {purpose}[/white]")
    lines.append("")
    lines.append(f"[{label_color}]Command :[/{label_color}]")
    lines.append(f"  [bold white]{cmd}[/bold white]")

    console.print(
        Panel(
            "\n".join(lines),
            title=f"[{label_color}][{risk_level}] Agent Wants to Run a System Command[/{label_color}]",
            border_style=label_color,
            expand=False,
        )
    )

    # Show 3-choice prompt
    console.print(
        "  [bold][[green]y[/green]][/bold] Allow  "
        "[bold][[cyan]a[/cyan]][/bold] Allow Auto (skip prompts this session)  "
        "[bold][[red]n[/red]][/bold] Deny"
    )

    try:
        raw = input("  Choice [y/a/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        raw = "n"

    if raw == "a":
        console.print(
            "  [cyan][INFO] Auto-approve enabled — PRIVILEGED commands will run without prompts this session.[/cyan]"
        )
        return True, True
    if raw == "y":
        return True, False
    return False, False


def execute_batch(
    action_data: Dict[str, Any],
    governance: Governance,
    max_output_len: int = 100000,
    callback: Optional[Callable] = None,
) -> str:
    """Execute a batch of independent shell actions in PARALLEL.

    The AI uses the ``run_batch`` action when it has multiple commands
    that do not depend on each other (e.g. nmap + whatweb + subfinder
    during recon). Results are merged into a single structured string
    so the next decision turn sees all of them at once, exactly like a
    human pentester who fires off several terminals in parallel.

    Args:
        action_data: Dict with key "actions" -> list of action dicts.
            Each sub-action is a run_shell dict: {"command": "...", "purpose": "..."}.
        governance: Governance instance (gates every command).
        max_output_len: Per-command output cap.
        callback: Optional streaming callback.

    Returns:
        JSON string with per-action results + a merged summary.
    """
    actions = action_data.get("actions", []) or []
    if not isinstance(actions, list) or not actions:
        return "Error: run_batch requires a non-empty 'actions' list."

    # Cap concurrency to avoid spawning too many subprocesses. 5 is a
    # reasonable default that mirrors a human running a few terminals.
    max_concurrent = min(8, max(1, len(actions)))

    def _run_one(sub: Dict[str, Any]) -> Dict[str, Any]:
        cmd = sub.get("command", "") if isinstance(sub, dict) else ""
        purpose = sub.get("purpose", "") if isinstance(sub, dict) else ""
        if not cmd or not isinstance(cmd, str):
            return {"command": str(cmd), "purpose": purpose, "success": False,
                    "output": "", "error": "Invalid or empty command"}
        try:
            output = execute_shell_command(
                cmd, governance,
                max_output_len=max_output_len,
                callback=callback,
                purpose=purpose,
                thought="",
            )
            success = not output.startswith("[FAIL]") and not output.startswith("Error:")
            return {"command": cmd, "purpose": purpose, "success": success, "output": output}
        except Exception as e:
            return {"command": cmd, "purpose": purpose, "success": False,
                    "output": "", "error": str(e)}

    import concurrent.futures

    results: List[Dict[str, Any]] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as pool:
            futures = [pool.submit(_run_one, sub) for sub in actions]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:
                    results.append({"command": "?", "purpose": "",
                                    "success": False, "output": "", "error": str(e)})
    except Exception as e:
        # Fallback: run serially if thread pool fails (rare)
        logger.warning(f"parallel batch failed, falling back to serial: {e}")
        for sub in actions:
            results.append(_run_one(sub))

    # Preserve input order in the merged output (better for AI comprehension).
    order = {id(sub): i for i, sub in enumerate(actions)}
    results.sort(key=lambda r: r.get("command", ""))

    # Build a single merged summary string the AI can reason about.
    parts = [f"[BATCH x{len(results)} — parallel execution]"]
    for i, r in enumerate(results, 1):
        status = "OK" if r.get("success") else "FAIL"
        parts.append(f"\n── action {i}/{len(results)} [{status}] ──")
        parts.append(f"command: {r.get('command', '?')}")
        if r.get("purpose"):
            parts.append(f"purpose: {r['purpose']}")
        out = r.get("output", "") or r.get("error", "")
        if out:
            # Per-action cap so one verbose command doesn't drown the others.
            parts.append("output:\n" + out[:max_output_len // max(1, len(results))])
    summary = "\n".join(parts)

    # Notify callback once for the whole batch (backward-compat with TUI).
    if callback:
        try:
            callback(f"batch_done:{len(results)} actions executed in parallel")
        except Exception:
            pass

    return summary


def execute_write_script(
    action_data: Dict[str, Any],
    governance: Governance,
    max_output_len: int = 100000,
    callback: Optional[Callable] = None,
) -> str:
    """Write a script file and execute it immediately.

    Lets the AI create a Python/Bash/Go script on the fly and run it without
    resorting to shell escaping tricks like ``echo '...' > file.py && python3 file.py``.

    Expected action_data keys:
        filename (str): e.g. "exploit.py" or "scanner.sh" — written to data/scripts/
        code     (str): Full script source code.
        runner   (str): Interpreter — "python3", "bash", "go run", etc. Default: auto-detect.
        args     (str): Extra CLI arguments to pass to the script.
        purpose  (str): AI's reason for writing this script.
        thought  (str): AI's internal reasoning.

    Args:
        action_data: Action payload from the AI.
        governance: Governance instance for risk classification.
        max_output_len: Maximum output length.
        callback: Streaming callback.

    Returns:
        Script execution output or error message.
    """
    from pathlib import Path as _Path

    filename = action_data.get("filename", "agent_script.py").strip()
    code = action_data.get("code", "").strip()
    runner = action_data.get("runner", "").strip()
    args = action_data.get("args", "").strip()
    purpose = action_data.get("purpose", "")
    thought = action_data.get("thought", "")

    if not code:
        return "[FAIL] write_script: 'code' field is required."

    # Auto-detect runner from filename extension
    if not runner:
        ext = _Path(filename).suffix.lower()
        runner = {
            ".py": "python3",
            ".sh": "bash",
            ".rb": "ruby",
            ".go": "go run",
            ".js": "node",
            ".ts": "ts-node",
        }.get(ext, "python3")

    # Write to data/scripts/ (persistent) so AI can inspect them later
    scripts_dir = _Path(__file__).parent.parent / "data" / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    script_path = scripts_dir / filename

    try:
        script_path.write_text(code, encoding="utf-8")
        logger.info(f"[OK] Script written: {script_path}")
    except Exception as e:
        return f"[FAIL] Failed to write script: {e}"

    # Verify: read back the file and confirm content matches what was intended.
    # This prevents silent failures where the write appeared to succeed but
    # the disk content is wrong (e.g. test pollution, encoding issues).
    try:
        written_content = script_path.read_text(encoding="utf-8")
        if written_content.strip() != code.strip():
            logger.warning(f"[WARN] Write verification failed for {script_path}")
            return (
                f"[FAIL] File was written to {script_path} but content verification failed.\n"
                f"Expected:\n{code}\n\nActual on disk:\n{written_content}"
            )
    except Exception as e:
        return f"[FAIL] Could not verify written file {script_path}: {e}"

    cmd = f"{runner} {script_path} {args}".strip()

    # Route info messages through callback (TUI) or console.print (terminal)
    if callback:
        import json as _json

        callback(
            "exec:"
            + _json.dumps(
                {
                    "cmd": f"write_script {script_path}",
                    "output": f"Successfully wrote script to {script_path}",
                    "success": True,
                    "elapsed": 0.0,
                    "purpose": purpose,
                    "thought": thought,
                }
            )
        )
    else:
        from cli.ui_components import console

        console.print(f"\n[grey70][INFO] AI wrote script: {script_path}[/grey70]")
        if purpose:
            console.print(f"[grey70][INFO] Purpose: {purpose}[/grey70]")
        console.print(f"[grey70][RUN]  {cmd}[/grey70]\n")

    shell_output = execute_shell_command(
        cmd,
        governance,
        max_output_len,
        callback,
        purpose=purpose,
        thought=thought,
    )
    # Prepend the absolute path so the AI always knows where the file lives
    # and does not confuse relative-path shell lookups with the actual file.
    return f"[OK] File saved at: {script_path}\n{shell_output}"


def execute_install_tool(
    action_data: Dict[str, Any],
    governance: Governance,
    max_output_len: int = 100000,
    callback: Optional[Callable] = None,
) -> str:
    """Install a tool/package with a clear user approval prompt.

    Constructs the appropriate install command based on the package manager
    (go, pip, apt, cargo, npm, gem) and routes it through Governance so the
    user sees exactly what will be installed before anything runs.

    Expected action_data keys:
        name      (str): Tool/package name, e.g. "_ext_recon".
        manager   (str): Package manager — "go", "pip", "apt", "cargo", "npm", "gem".
                         If omitted, the AI should specify the install_cmd directly.
        version   (str): Optional version specifier (e.g. "@latest", "==2.1.0").
        install_cmd (str): Full install command if manager is unknown or custom.
        purpose   (str): Why this tool is needed.
        thought   (str): AI reasoning.

    Args:
        action_data: Action payload from the AI.
        governance: Governance instance.
        max_output_len: Maximum output length.
        callback: Streaming callback.

    Returns:
        Installation output or error message.
    """
    name = action_data.get("name", "").strip()
    manager = action_data.get("manager", "").strip().lower()
    version = action_data.get("version", "").strip()
    install_cmd = action_data.get("install_cmd", "").strip()
    purpose = action_data.get("purpose", f"Install {name} for security testing")
    thought = action_data.get("thought", "")

    if not install_cmd:
        if not name:
            return "[FAIL] install_tool: 'name' or 'install_cmd' is required."

        # Build install command for known managers
        _MANAGERS = {
            "go": f"go install github.com/{name}{version or '@latest'}",
            "pip": f"pip install {name}{version}",
            "pip3": f"pip3 install {name}{version}",
            "apt": f"sudo apt-get install -y {name}",
            "cargo": f"cargo install {name}",
            "npm": f"npm install -g {name}",
            "gem": f"gem install {name}",
            "brew": f"brew install {name}",
        }
        install_cmd = _MANAGERS.get(manager, f"pip install {name}{version}")

    return execute_shell_command(
        install_cmd,
        governance,
        max_output_len,
        callback,
        purpose=purpose,
        thought=thought,
    )


def detect_and_install_missing_tool(
    cmd: str,
    governance: Governance,
    callback: Optional[Callable] = None,
) -> Optional[str]:
    """Detect if a tool is missing and offer to install it.

    When AI tries to run a command that fails because a tool is not installed,
    this function checks if the tool can be installed and shows a popup.

    Args:
        cmd: The failed command.
        governance: Governance instance.
        callback: Optional callback.

    Returns:
        Installation output if installed, None if skipped or not applicable.
    """
    from shutil import which

    # Extract the first word (the tool name)
    parts = cmd.strip().split()
    if not parts:
        return None

    tool_name = parts[0].split("/")[-1]  # Handle paths like /usr/bin/nmap

    # Skip common non-tool commands
    skip_commands = {"python", "python3", "bash", "sh", "echo", "cd", "ls", "cat", "grep"}
    if tool_name in skip_commands:
        return None

    # Check if tool exists
    if which(tool_name):
        return None  # Tool exists, no need to install

    # Tool is missing — show popup
    from rich.panel import Panel
    from cli.ui_components import console

    console.print(
        Panel(
            f"[white]Tool [bold]{tool_name}[/bold] is not installed.[/white]\n\n"
            f"[grey70]Command that failed: {cmd}[/grey70]",
            title="[yellow]Tool Not Found[/yellow]",
            border_style="yellow",
            expand=False,
        )
    )

    # Ask user if they want to install
    console.print(
        "  [bold][[green]y[/green]][/bold] Install tool  " "[bold][[red]n[/red]][/bold] Skip"
    )

    try:
        choice = input("  Choice [y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        choice = "n"

    if choice != "y":
        return None

    # Ask for sudo password if needed
    sudo_password = None
    if tool_name not in {"pip", "pip3", "npm", "cargo", "go"}:
        console.print("  [dim]Enter sudo password (or press Enter to skip sudo):[/dim]")
        try:
            import getpass

            sudo_password = getpass.getpass("  Sudo password: ")
        except (EOFError, KeyboardInterrupt):
            sudo_password = None

    # Build install command
    install_cmd = _build_install_command(tool_name, sudo_password)

    if not install_cmd:
        console.print(
            f"  [red]Don't know how to install {tool_name}. Please install manually.[/red]"
        )
        return None

    console.print(f"  [dim]Running: {install_cmd}[/dim]")

    # Execute installation
    try:
        from tools.safe_exec import execute_safely, execute_safely_streaming, execute_safely_interactive

        result = execute_safely(install_cmd, timeout=120)
        if result.get("success"):
            console.print(f"  [green][OK] {tool_name} installed successfully[/green]")
            return result.get("stdout", "")
        else:
            console.print(f"  [red][FAIL] Installation failed: {result.get('stderr', '')}[/red]")
            return None
    except Exception as e:
        console.print(f"  [red][FAIL] Installation error: {e}[/red]")
        return None


def _build_install_command(tool_name: str, sudo_password: Optional[str] = None) -> Optional[str]:
    """Build install command for a tool.

    Args:
        tool_name: Name of the tool to install.
        sudo_password: Optional sudo password.

    Returns:
        Install command string or None if unknown.
    """
    # Common tool → package mappings
    _TOOL_PACKAGES = {
        "nmap": "nmap",
        "nikto": "nikto",
        "dirb": "dirb",
        "gobuster": "gobuster",
        "enum4linux": "enum4linux",
        "sslscan": "sslscan",
        "hydra": "hydra",
        "sqlmap": "sqlmap",
        "whatweb": "whatweb",
        "wpscan": "wpscan",
        "subfinder": "subfinder",
        "httpx": "httpx",
        "nuclei": "nuclei",
        "amass": "amass",
        "ffuf": "ffuf",
        "ffuf": "ffuf",
        "masscan": "masscan",
        "zmap": "zmap",
        "crackmapexec": "crackmapexec",
        "smbclient": "smbclient",
        "snmpwalk": "snmpwalk",
        "onesixtyone": "onesixtyone",
    }

    package = _TOOL_PACKAGES.get(tool_name)

    if package:
        if sudo_password:
            # Use echo to pipe password to sudo
            return f"echo '{sudo_password}' | sudo -S apt-get install -y {package}"
        else:
            return f"sudo apt-get install -y {package}"

    # Try pip for Python tools
    if tool_name.endswith("-py") or tool_name.startswith("python-"):
        pip_name = tool_name.replace("-py", "").replace("python-", "")
        return f"pip install {pip_name}"

    # Unknown tool — return None
    return None


def handle_ask_user(
    action_data: Dict[str, Any],
    callback: Optional[Callable] = None,
) -> str:
    """Handle the ask_user action: prompt for confirmation, password, or text."""
    question = action_data.get("question", action_data.get("message", ""))
    if not question:
        return "Error: ask_user requires a 'question' field."

    input_type = action_data.get("input_type", "confirm").lower()

    if callback:
        callback(
            f"**Action Required:** Please return to the server terminal to answer:\n_{question}_"
        )

    try:
        if input_type == "confirm":
            from cli.ui_components import confirm

            approved = confirm(question, default=False)
            return "yes" if approved else "no"

        elif input_type == "password":
            import getpass

            return getpass.getpass(f"  {question}: ")

        else:
            from prompt_toolkit import prompt as pt_prompt

            try:
                user_text = pt_prompt("  > ")
            except (EOFError, KeyboardInterrupt):
                return "User cancelled input."
            return user_text.strip() if user_text else "No input provided."

    except Exception as e:
        logger.warning(f"ask_user failed: {e}")
        return f"Error getting user input: {e}"


def execute_tool_registry(
    tool_name: str,
    target: str,
    report_dir: Path,
    get_shared_loop: Optional[Callable] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
) -> ToolResult:
    """Execute tool via Tool Registry; fallback to subprocess."""
    tool = registry.get_tool(tool_name)
    if tool and tool.is_available:
        try:

            async def _run() -> ToolResult:
                s = semaphore or asyncio.Semaphore(5)
                return await tool.execute(target, report_dir, s)

            if get_shared_loop:
                loop = get_shared_loop()
                future = asyncio.run_coroutine_threadsafe(_run(), loop)
                timeout = getattr(getattr(tool, "metadata", None), "timeout_seconds", 180)
                return future.result(timeout=timeout)

            # No shared loop — run directly
            import asyncio as _asyncio

            return _asyncio.run(_run())

        except Exception as e:
            logger.warning(f"Tool registry execution failed: {e}")

    return execute_tool_subprocess(tool_name, target)


def execute_tool_subprocess(tool_name: str, target: str) -> ToolResult:
    """Fallback subprocess with PATH verification and known templates."""
    import shutil as _shutil

    resolved = _shutil.which(tool_name)
    if resolved is None:
        return ToolResult(
            success=False,
            tool_name=tool_name,
            category=ToolCategory.UTILITY,
            error_message=f"Tool '{tool_name}' not found in PATH",
        )

    commands = {
        "dns_lookup": ["dig", target, "ANY"],
        "http_probe": ["curl", "-s", "-I", f"https://{target}"],
        "port_scan": [
            "python3",
            "-c",
            f"import socket; [print(p) for p in range(1,1024) if socket.socket().connect_ex(({repr(target)}, p)) == 0]",
        ],
    }

    cmd = commands.get(tool_name)
    if cmd is None:
        return ToolResult(
            success=False,
            tool_name=tool_name,
            category=ToolCategory.UTILITY,
            error_message=f"Tool '{tool_name}' has no known command template",
        )

    try:
        result = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        return ToolResult(
            success=result.returncode == 0,
            tool_name=tool_name,
            category=ToolCategory.RECON,
            output=result.stdout + result.stderr,
        )
    except Exception as e:
        return ToolResult(
            success=False,
            tool_name=tool_name,
            category=ToolCategory.RECON,
            error_message=str(e),
        )

"""agents/agent_executor.py — Execution layer extracted from agent_brain.py.

Handles tool execution, user interaction, and governance-gated shell commands.
Reduces agent_brain.py by ~260 lines.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from tools.governance import Governance
from tools.tool_registry import registry, ToolResult, ToolCategory
from tools.safe_exec import execute_safely
from tools.vector_memory import remember

logger = logging.getLogger("elengenix.agent")


def execute_tool(
    action_data: Dict[str, Any],
    governance: Governance,
    max_output_len: int = 5000,
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
                ai_reasoning=action_data.get("ai_reasoning", "")
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
            return json.dumps({
                "success": result.success,
                "output": result.output,
                "error": result.error,
                "findings": result.findings
            }, indent=2)
        except Exception as e:
            return f"Error running tool: {e}"

    if action != "run_shell":
        return (
            f"Error: Unknown action '{action}'. "
            "Use: run_shell, ask_user, web_search, save_memory, create_ai_tool, run_ai_tool, or finish."
        )
    if not cmd_raw or not isinstance(cmd_raw, str):
        return "Error: Invalid or empty command."

    return execute_shell_command(cmd_raw, governance, max_output_len, callback)


def execute_shell_command(
    cmd_raw: str,
    governance: Governance,
    max_output_len: int = 5000,
    callback: Optional[Callable] = None,
) -> str:
    """Run a shell command through the Governance gate."""
    gate = governance.gate(
        mission_id="cli_tool_exec",
        target="local",
        action={"action": "run_shell", "command": cmd_raw},
        callback=callback,
    )

    if gate.decision == "deny":
        return f"Command blocked by governance: {gate.rationale}"

    if gate.decision == "needs_approval":
        from ui_components import confirm
        try:
            approved = confirm("Run this command?", default=False)
        except Exception:
            approved = False
        if not approved:
            return "Command rejected by user."

    try:
        import shutil as _shutil
        try:
            parts = shlex.split(cmd_raw)
            if parts:
                binary = os.path.basename(parts[0])
                _shutil.which(binary)
        except Exception:
            pass

        safe_result = execute_safely(cmd_raw, timeout=300)
        if not safe_result["success"]:
            err = safe_result["error"] or safe_result["stderr"][:500]
            return f"Command failed: {err}"
        output = safe_result["stdout"]
        if safe_result["stderr"]:
            output += "\n" + safe_result["stderr"]
        return output[:max_output_len]

    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 300 seconds."
    except ValueError as e:
        return f"Error: Invalid command syntax: {e}"
    except Exception as e:
        return f"Error executing tool: {str(e)}"


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
            from ui_components import confirm
            approved = confirm(question, default=False)
            return "yes" if approved else "no"

        elif input_type == "password":
            import getpass
            return getpass.getpass(f"  {question}: ")

        else:
            from prompt_toolkit import prompt as pt_prompt
            try:
                user_text = pt_prompt(f"  > ")
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
        "subfinder": ["subfinder", "-d", target, "-silent"],
        "httpx": ["httpx", "-u", target, "-silent"],
        "nuclei": ["nuclei", "-u", target, "-silent", "-severity", "critical,high,medium"],
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

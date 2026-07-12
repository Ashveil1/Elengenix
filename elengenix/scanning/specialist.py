"""agents/specialist_agent.py — SpecialistAgent for TeamAegis v2.

The Specialist uses AI model #2 (default: Claude) to:
- Interpret tasks from the Council and decide which tool/command to run.
- Execute security tools via ToolRegistry or shell.
- Extract structured findings from tool output.

Sub-workers:
- ExploitWorker  — validates potential exploits (PoC verification).
- FuzzerWorker   — runs parameter fuzzing using built-in Python scanners.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from elengenix.scanning.worker import BaseWorker, WorkerResult
from tools.universal_ai_client import AIMessage

if TYPE_CHECKING:
    from elengenix.scanning.agent_council import SharedInbox

logger = logging.getLogger("elengenix.specialist")


# ── Sub-Workers ────────────────────────────────────────────────────────────────


class ExploitWorker(BaseWorker):
    """Verifies potential exploits with minimal, safe PoC requests.

    Args:
        timeout_seconds: Max execution time.
    """

    def __init__(self, timeout_seconds: int = 60) -> None:
        super().__init__(
            name="ExploitWorker",
            description="Safe PoC verification for potential exploits",
            timeout_seconds=timeout_seconds,
        )

    def run(self, target: str, params: Optional[Dict[str, Any]] = None) -> WorkerResult:
        """Send a safe probe request to verify a potential vulnerability.

        Args:
            target: URL to probe.
            params: Dict with optional keys: "payload", "method", "headers".

        Returns:
            WorkerResult with verification finding.
        """
        params = params or {}
        payload = params.get("payload", "")
        method = params.get("method", "GET").upper()

        if not payload:
            return WorkerResult(
                success=False,
                worker_name=self.name,
                error="No payload provided for exploit verification",
            )

        try:
            cmd = ["curl", "-si", "--max-time", "10", "-X", method, target]
            if payload:
                cmd += ["-d", payload]

            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            output = result.stdout + result.stderr
            findings = []
            if any(
                sig in output.lower() for sig in ["error", "exception", "traceback", "sql", "debug"]
            ):
                findings.append(
                    {
                        "type": "exploit_indicator",
                        "severity": "high",
                        "title": "Potential exploit confirmed",
                        "target": target,
                        "description": "Response contains suspicious patterns",
                        "evidence": output[:500],
                    }
                )
            return WorkerResult(
                success=True,
                worker_name=self.name,
                output=output[:1000],
                findings=findings,
            )
        except Exception as exc:
            return WorkerResult(
                success=False,
                worker_name=self.name,
                error=str(exc),
            )


class FuzzerWorker(BaseWorker):
    """Runs parameter/path fuzzing using Python-based scanners.

    Args:
        timeout_seconds: Max execution time.
        wordlist_path: Path to wordlist file for fuzzing.
    """

    def __init__(
        self,
        timeout_seconds: int = 120,
        wordlist_path: str = "/usr/share/wordlists/dirb/common.txt",
    ) -> None:
        super().__init__(
            name="FuzzerWorker",
            description="Directory and parameter fuzzing",
            timeout_seconds=timeout_seconds,
        )
        self.wordlist_path = wordlist_path

    def run(self, target: str, params: Optional[Dict[str, Any]] = None) -> WorkerResult:
        """Run directory fuzzing on target URL using Python.

        Args:
            target: Base URL to fuzz.
            params: Optional dict with "wordlist" override.

        Returns:
            WorkerResult with discovered paths.
        """
        import requests

        params = params or {}

        # Ensure target has protocol
        if not target.startswith("http"):
            target = f"https://{target}"

        findings = []

        # Common paths to check
        common_paths = [
            "/",
            "/admin",
            "/login",
            "/api",
            "/api/v1",
            "/api/v2",
            "/robots.txt",
            "/sitemap.xml",
            "/.env",
            "/.git",
            "/wp-admin",
            "/wp-login.php",
            "/phpmyadmin",
            "/backup",
            "/config",
            "/database",
            "/db",
            "/debug",
            "/test",
            "/staging",
            "/dev",
        ]

        for path in common_paths:
            try:
                url = f"{target.rstrip('/')}{path}"
                response = requests.get(url, timeout=5, verify=False)

                if response.status_code in [200, 301, 302, 403]:
                    findings.append(
                        {
                            "type": "directory_found",
                            "severity": "low",
                            "title": f"Path found: {path}",
                            "url": url,
                            "target": target,
                            "description": f"Status: {response.status_code}",
                        }
                    )
            except Exception:
                continue

        return WorkerResult(
            success=True,
            worker_name=self.name,
            output=f"Checked {len(common_paths)} paths",
            findings=findings,
        )


# ── SpecialistAgent ─────────────────────────────────────────────────────────────


class SpecialistAgent:
    """AI agent responsible for task execution via tools and shell commands.

    Uses AI model #2 (Claude by default) to interpret tasks and decide which
    tool or command to run. Results are returned to the Council.

    Args:
        client: AIClientManager-compatible client.
        model_label: Human-readable label for display.
        governance: Governance instance for safety gating.
        enable_workers: If True, ExploitWorker and FuzzerWorker are active.
        max_retries: How many times to retry a failed AI decision.
    """

    EXECUTE_PROMPT = """You are an elite security specialist. Execute the given task precisely.

Task: {task_description}
Target: {target}
Phase: {phase}
Risk: {risk}

Available tools: {available_tools}

Decide ONE action:
1. Run registered tool: {{"action": "run_tool", "tool": "dns_lookup", "target": "{target}", "purpose": "..."}}
2. Run shell command: {{"action": "run_shell", "command": "curl -si https://{target}/", "purpose": "..."}}
3. Skip (not applicable): {{"action": "skip", "reason": "..."}}

Context from recent history:
{history_context}

Respond ONLY with valid JSON. No extra text."""

    def __init__(
        self,
        client: Any,
        model_label: str = "Specialist AI",
        governance: Any = None,
        enable_workers: bool = True,
        max_retries: int = 2,
    ) -> None:
        self.client = client
        self.model_label = model_label
        self.governance = governance
        self.enable_workers = enable_workers
        self.max_retries = max_retries
        self.total_tokens_used: int = 0

        self._history: List[str] = []
        self._all_findings: List[Dict[str, Any]] = []

        # Sub-workers
        self.exploit_worker = ExploitWorker()
        self.fuzzer_worker = FuzzerWorker()

    def execute_task(
        self,
        task: Dict[str, Any],
        target: str,
        inbox: "SharedInbox",
    ) -> WorkerResult:
        """Interpret and execute a single task from the Council.

        Args:
            task: Task dict (description, phase, risk, tool_hint).
            target: Primary target.
            inbox: SharedInbox for posting result messages.

        Returns:
            WorkerResult with findings and output.
        """
        from elengenix.scanning.agent_council import CouncilMessage, MessageType
        from tools.tool_registry import registry

        description = task.get("description", "")
        phase = task.get("phase", "unknown")
        risk = task.get("risk", "low")
        tool_hint = task.get("tool_hint", "")

        # Get available tools
        available = registry.list_available_tools()
        tool_list = ", ".join([n for n, i in available.items() if i.get("available")])

        # History context
        history_ctx = "\n".join(self._history[-4:]) if self._history else "(none)"

        prompt = self.EXECUTE_PROMPT.format(
            task_description=description,
            target=target,
            phase=phase,
            risk=risk,
            available_tools=tool_list or tool_hint or "python_scanner, dns_lookup, http_probe",
            history_context=history_ctx,
        )

        # Get AI decision
        decision = self._ai_decide(prompt)
        if not decision:
            return WorkerResult(
                success=False, worker_name="SpecialistAgent", error="AI decision failed"
            )

        action = decision.get("action", "skip")

        if action == "skip":
            self._history.append(f"[SKIP] {description}: {decision.get('reason', '')}")
            inbox.post(
                CouncilMessage(
                    msg_type=MessageType.STATUS,
                    sender="specialist",
                    recipient="council",
                    payload={"status": "skipped", "task": description},
                )
            )
            return WorkerResult(success=True, worker_name="SpecialistAgent", output="Skipped")

        # Execute
        result = self._dispatch(action, decision, target, description)

        # Track history
        self._history.append(f"[{action.upper()}] {description}: {len(result.findings)} findings")
        self._all_findings.extend(result.findings)

        # Post result to inbox
        inbox.post(
            CouncilMessage(
                msg_type=MessageType.RESULT,
                sender="specialist",
                recipient="council",
                payload=result.to_dict(),
            )
        )

        return result

    def _dispatch(
        self,
        action: str,
        decision: Dict[str, Any],
        target: str,
        description: str,
    ) -> WorkerResult:
        """Route AI decision to appropriate execution path.

        Args:
            action: Action type ("run_tool", "run_shell").
            decision: Full decision dict from AI.
            target: Primary target.
            description: Human-readable task description.

        Returns:
            WorkerResult.
        """
        if action == "run_tool":
            return self._run_tool(decision, target)
        elif action == "run_shell":
            return self._run_shell(decision, target, description)
        elif action in ("fuzz", "fuzzing"):
            return self.fuzzer_worker.execute(target)
        elif action in ("exploit", "verify_exploit"):
            return self.exploit_worker.execute(
                decision.get("target", target),
                {"payload": decision.get("payload", ""), "method": decision.get("method", "GET")},
            )
        else:
            return WorkerResult(
                success=False,
                worker_name="SpecialistAgent",
                error=f"Unknown action: {action}",
            )

    def _run_tool(self, decision: Dict[str, Any], target: str) -> WorkerResult:
        """Execute via ToolRegistry.

        Args:
            decision: AI decision dict with "tool" and "target".
            target: Fallback target if not in decision.

        Returns:
            WorkerResult.
        """
        import asyncio
        from pathlib import Path

        from tools.tool_registry import registry

        tool_name = decision.get("tool", "")
        cmd_target = decision.get("target", target)

        tool = registry.get_tool(tool_name)
        if not tool or not tool.is_available:
            # Fallback to shell
            return self._run_shell(
                {"command": f"{tool_name} {cmd_target}", "purpose": decision.get("purpose", "")},
                description=f"Fallback shell for {tool_name}",
            )

        report_dir = Path("reports") / f"specialist_{tool_name}_{int(time.time())}"
        report_dir.mkdir(parents=True, exist_ok=True)

        try:
            try:
                from tools.event_loop import get_shared_loop

                loop = get_shared_loop()
                sem = asyncio.Semaphore(3)
                future = asyncio.run_coroutine_threadsafe(
                    tool.execute(cmd_target, report_dir, sem), loop
                )
                timeout = getattr(getattr(tool, "metadata", None), "timeout_seconds", 180)
                tool_result = future.result(timeout=timeout)
            except Exception:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                sem = asyncio.Semaphore(3)
                tool_result = loop.run_until_complete(
                    tool.execute(cmd_target, report_dir, asyncio.Semaphore(3))
                )
                loop.close()

            return WorkerResult(
                success=tool_result.success,
                worker_name="SpecialistAgent",
                output=tool_result.output[:4000],
                findings=tool_result.findings or [],
                error=tool_result.error_message or "",
                metadata={"tool": tool_name},
            )
        except Exception as exc:
            return WorkerResult(
                success=False,
                worker_name="SpecialistAgent",
                error=str(exc),
                metadata={"tool": tool_name},
            )

    def _run_shell(self, decision: Dict[str, Any], target: str, description: str) -> WorkerResult:
        """Execute a shell command with governance gating.

        Args:
            decision: AI decision dict with "command".
            target: Primary target for governance check.
            description: Human-readable task description for logging.

        Returns:
            WorkerResult.
        """
        from tools.safe_exec import execute_safely

        command = decision.get("command", "")
        if not command:
            return WorkerResult(
                success=False,
                worker_name="SpecialistAgent",
                error="Empty command",
            )

        # Governance check
        if self.governance:
            gate = self.governance.gate(
                mission_id="specialist",
                target=target,
                action={"type": "run_shell", "command": command},
            )
            if not gate.allowed:
                return WorkerResult(
                    success=False,
                    worker_name="SpecialistAgent",
                    error=f"Blocked by governance: {gate.rationale}",
                )

        try:
            result = execute_safely(command, timeout=300)
            output = result.get("stdout", "") + result.get("stderr", "")
            findings = _heuristic_findings(output, command)
            return WorkerResult(
                success=result.get("success", False),
                worker_name="SpecialistAgent",
                output=output[:4000],
                findings=findings,
                error=result.get("error", "") if not result.get("success") else "",
            )
        except Exception as exc:
            return WorkerResult(
                success=False,
                worker_name="SpecialistAgent",
                error=str(exc),
            )

    def _ai_decide(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Ask AI for a JSON action decision.

        Args:
            prompt: System prompt for the decision.

        Returns:
            Parsed decision dict or None on failure.
        """
        if not self.client:
            return None
        for attempt in range(self.max_retries + 1):
            try:
                response = (
                    self.client.chat(
                        [
                            AIMessage(role="user", content=prompt),
                        ],
                        temperature=0.3,
                    ).content
                    or ""
                )
                self.total_tokens_used += len(response) // 4
                return _parse_json(response)
            except Exception as exc:
                logger.warning(f"[Specialist] AI call attempt {attempt + 1} failed: {exc}")
                time.sleep(0.5)
        return None


# ── Helpers ────────────────────────────────────────────────────────────────────


def _parse_json(text: str) -> Optional[Dict[str, Any]]:
    """Parse first JSON object from text.

    Delegates to the unified hardened extractor in agent_helpers.

    Args:
        text: Raw string possibly containing JSON.

    Returns:
        Dict or None.
    """
    from elengenix.scanning.helpers import extract_json

    result = extract_json(text, expect="object")
    return result if isinstance(result, dict) else None


def _heuristic_findings(output: str, command: str) -> List[Dict[str, Any]]:
    """Extract findings from raw shell output heuristically.

    Args:
        output: Raw stdout+stderr from a shell command.
        command: The command that was run (for context).

    Returns:
        List of finding dicts.
    """
    findings = []
    if not output:
        return findings

    # Look for secrets
    secrets = re.findall(
        r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN|APIKEY)[=:]\s*\S+",
        output,
        re.IGNORECASE,
    )
    if secrets:
        findings.append(
            {
                "type": "potential_secret",
                "severity": "high",
                "title": f"Potential secret found ({len(secrets)} matches)",
                "description": "Credentials or API keys detected in output",
                "evidence": str(secrets[:3]),
            }
        )

    # Look for URLs
    urls = re.findall(r"https?://[^\s\"'<>]+", output)
    if urls:
        findings.append(
            {
                "type": "urls_extracted",
                "severity": "info",
                "title": f"{len(urls)} URLs found",
                "description": "Extracted URLs from tool output",
                "evidence": "\n".join(urls[:10]),
            }
        )

    # Look for SQL errors
    sql_errors = re.findall(
        r"(?:sql|mysql|ora-\d+|syntax error|unclosed quotation)", output, re.IGNORECASE
    )
    if sql_errors:
        findings.append(
            {
                "type": "sql_error_detected",
                "severity": "high",
                "title": "Potential SQL injection indicator",
                "description": "SQL-related error messages detected in response",
                "evidence": str(sql_errors[:3]),
            }
        )

    return findings

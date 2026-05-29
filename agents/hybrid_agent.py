"""agents/hybrid_agent.py — Hybrid Agent combining redteam_agent flexibility with Elengenix structure.

Strategist (AI 1) plans at a high level.
Specialist (AI 2) executes actions in a loop with full shell flexibility.
Every result feeds into Elengenix's analysis pipeline, memory, and reporting.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import time
from typing import Any, Callable, Dict, List, Optional

from tools.tool_registry import registry, ToolResult, ToolCategory
from tools.universal_executor import UniversalExecutor
from tools.governance import Governance
from tools.vector_memory import remember, get_context_for_ai
from tools.analysis_pipeline import AnalysisPipeline
from tools.mission_state import MissionState, GraphNode, GraphEdge
from tools.cvss_calculator import CVSSCalculator
from tools.agent_reflection import get_reflection
from tools.universal_ai_client import AIMessage
from ui_components import console
from agents.hybrid_prompts import (
    HYBRID_STRATEGIST_PROMPT,
    HYBRID_SPECIALIST_PROMPT,
    HYBRID_GOVERNANCE_RULES,
)

logger = logging.getLogger("elengenix.hybrid")


def _extract_json(text: str):
    """Extract JSON object or array from LLM response."""
    # Try markdown fence first
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    candidate = match.group(1).strip() if match else text.strip()
    # Try parsing as-is
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    # Find outermost { ... } or [ ... ]
    for s, e in [("{", "}"), ("[", "]")]:
        si = candidate.find(s)
        ei = candidate.rfind(e)
        if si != -1 and ei > si:
            try:
                return json.loads(candidate[si:ei + 1])
            except json.JSONDecodeError:
                continue
    raise ValueError(f"No valid JSON in response:\n{text[:500]}")


_SIMPLE_COMMANDS = re.compile(
    r"^\s*(ls|cat|echo|pwd|cd|which|head|tail|wc|whoami|id|date|uptime|env|set)\b"
)


class HybridAgent:
    """Combines redteam_agent's flexible AI-driven execution loop with
    Elengenix's structured pipeline (tool registry, analyzers, memory, CVSS)."""

    def __init__(
        self,
        client: Any = None,  # AIClientManager-like, must have .chat()
        governance: Governance = None,
        target: str = "",
        max_steps: int = 50,
        strategist_interval: int = 5,
        enable_analysis: bool = True,
        enable_memory: bool = True,
        loop_threshold: int = 4,
        callback: Optional[Callable] = None,
    ):
        self.client = client
        self.governance = governance or Governance(require_approval_high_risk=True)
        self.target = target
        self.max_steps = max_steps
        self.strategist_interval = strategist_interval
        self.enable_analysis = enable_analysis
        self.enable_memory = enable_memory
        self.loop_threshold = loop_threshold
        self.callback = callback

        # Shared infrastructure
        self.executor = UniversalExecutor(base_dir=".")
        self.cvss_calc = CVSSCalculator(use_ai=False)
        self.reflection = get_reflection()

        # Runtime state
        self.mission_state: Optional[MissionState] = None
        self.mission_key: str = ""
        self.objective: str = ""
        self.action_history: List[Dict] = []  # rolling action dedup
        self.all_findings: List[Dict] = []
        self.tasks: List[Dict] = []  # from Strategist
        self.missing_tools: set = set()
        self.start_time: float = 0.0

    # ── Public Entry ────────────────────────────────────────────────────

    def run(self, objective: str) -> str:
        """Main entry: Strategist → Specialist loop. Returns final report."""
        self.objective = objective
        self.start_time = time.time()

        self._log(f"[Hybrid] Mission started: {objective[:120]}")

        # 1. Strategist generates initial plan
        self._run_strategist()
        self._log(f"[Strategist] Plan: {len(self.tasks)} tasks")

        # 2. Specialist execution loop
        keep_going = True
        cycle = 0
        while keep_going and cycle < self.max_steps:
            cycle += 1

            # Re-invoke Strategist periodically
            if cycle > 1 and (cycle - 1) % self.strategist_interval == 0:
                self._run_strategist()
                self._log(f"[Strategist] Re-plan at cycle {cycle}")

            # Check for deadlock
            if self._is_deadlocked():
                self._log("[Hybrid] Deadlock detected — terminating loop")
                break

            # Run one Specialist cycle
            keep_going = self._run_specialist_cycle(cycle)

        # 3. Finalize
        return self._finalize_mission()

    # ── Strategist ──────────────────────────────────────────────────────

    def _run_strategist(self):
        """Invoke Strategist AI to generate/refresh task plan."""
        if not self.client:
            return

        # Build context from memory and tools
        semantic_context = ""
        if self.enable_memory and self.target:
            semantic_context = get_context_for_ai(
                self.objective, self.target, max_memories=8
            )

        available_tools = registry.list_available_tools()
        tool_summary = "\n".join([
            f"  {name} ({info['category']}) — {'✓' if info['available'] else '✗ not installed'}"
            for name, info in sorted(available_tools.items())
        ]) or "  (no tools registered)"

        plan_context = (
            f"Mission Objective: {self.objective}\n"
            f"Target: {self.target or 'not specified'}\n\n"
            f"Registered tools:\n{tool_summary}\n"
        )
        if semantic_context:
            plan_context += f"\nPast mission context:\n{semantic_context[:800]}\n"

        prompt = f"{HYBRID_STRATEGIST_PROMPT}\n\n{plan_context}"

        try:
            response = self.client.chat([
                AIMessage(role="system", content=prompt),
                AIMessage(role="user", content="Generate updated task plan."),
            ]).content or ""
            tasks = _extract_json(response)
            if isinstance(tasks, list):
                self.tasks = tasks
                self._log(f"[Strategist] {len(tasks)} tasks planned")
        except (ValueError, json.JSONDecodeError) as e:
            self._log(f"[Strategist] Parse error: {e}")
        except Exception as e:
            self._log(f"[Strategist] Error: {e}")

    # ── Specialist ─────────────────────────────────────────────────────

    def _run_specialist_cycle(self, cycle: int) -> bool:
        """One Specialist cycle. Returns True to keep looping, False to pause/complete."""
        decision = self._ai_decide_action(cycle)
        if not decision:
            return True  # retry

        thought = decision.get("thought", "")
        if thought:
            console.print(f"  [dim]├─ {thought}[/dim]")

        action = decision.get("action", "")
        self.action_history.append({"action": action, **decision})

        if action == "run_tool":
            self._handle_run_tool(decision, cycle)
        elif action == "run_command":
            self._handle_run_command(decision, cycle)
        elif action == "read_file":
            self._handle_read_file(decision)
        elif action == "update_intel":
            self._handle_update_intel(decision)
        elif action == "search_web":
            self._handle_search_web(decision)
        elif action == "message":
            self._handle_message(decision)
            return False
        elif action == "complete_mission":
            return False
        else:
            console.print(f"  [yellow]├─ Unknown action: {action}[/yellow]")

        return True

    def _ai_decide_action(self, cycle: int) -> Optional[Dict]:
        """Ask AI what action to take next. Returns decision dict or None."""
        if not self.client:
            return None

        # Build mission state summary
        state_text = f"Objective: {self.objective}\nTarget: {self.target or 'N/A'}\n"
        state_text += f"Cycle: {cycle}/{self.max_steps}\n"

        if self.tasks:
            state_text += "\n[Tasks]\n"
            for i, t in enumerate(self.tasks):
                state_text += f"  {i}. [{t.get('status','pending').upper()}] {t.get('description','')}\n"

        if self.all_findings:
            state_text += f"\n[Findings so far: {len(self.all_findings)}]\n"

        # Recent action history (last 5)
        recent = self.action_history[-5:] if self.action_history else []
        if recent:
            state_text += "\n[Recent actions]\n"
            for r in recent:
                purpose = r.get("purpose", r.get("action", ""))
                state_text += f"  - {r.get('action')}: {purpose[:80]}\n"

        # Available tools
        available = registry.list_available_tools()
        tool_line = ", ".join([
            n for n, i in available.items() if i["available"]
        ]) or "none installed"
        tool_summary = f"Available: {tool_line}"

        prompt = HYBRID_SPECIALIST_PROMPT.format(
            state_summary=state_text,
            tool_list=tool_summary,
            target=self.target or "target",
            governance_rules=HYBRID_GOVERNANCE_RULES,
        )

        try:
            response = self.client.chat([
                AIMessage(role="user", content=prompt),
            ], temperature=0.4).content or ""
            return _extract_json(response)
        except ValueError as e:
            self._log(f"[Specialist] JSON parse error, retrying: {e}")
            # Retry with stricter prompt
            retry_prompt = (
                "Respond ONLY with valid JSON. No markdown, no extra text.\n"
                '{"action": "run_command", "command": "echo retrying", "purpose": "retry"}'
            )
            try:
                response = self.client.chat([
                    AIMessage(role="user", content=prompt + "\n\n" + retry_prompt),
                ], temperature=0.2).content or ""
                return _extract_json(response)
            except Exception:
                return None
        except Exception as e:
            self._log(f"[Specialist] AI error: {e}")
            return None

    # ── Action Handlers ────────────────────────────────────────────────

    def _handle_run_tool(self, decision: Dict, cycle: int):
        """Execute a tool — prefer ToolRegistry, fall back to shell."""
        tool_name = decision.get("tool", "")
        cmd_target = decision.get("target", self.target or "")

        if not tool_name:
            console.print("  [yellow]├─ No tool specified[/yellow]")
            return

        # Try ToolRegistry first
        tool = registry.get_tool(tool_name)
        if tool and tool.is_available:
            self._execute_registry_tool(tool, tool_name, cmd_target, cycle)
            return

        # Try auto-install if tool is known but missing/unavailable
        try:
            import shutil
            if not shutil.which(tool_name):
                from dependency_manager import TOOLS as INSTALLABLE_TOOLS, run_with_streaming, verify_and_advise
                if tool_name in INSTALLABLE_TOOLS:
                    console.print(f"  [cyan]├─ [INSTALL] Missing '{tool_name}'. Attempting auto-installation...[/cyan]")
                    if run_with_streaming(INSTALLABLE_TOOLS[tool_name]):
                        if verify_and_advise(tool_name):
                            console.print(f"  [white][OK] '{tool_name}' successfully installed and integrated[/white]")
                            # Refresh registry/tool status if possible
                            tool = registry.get_tool(tool_name)
                            if tool and tool.is_available:
                                self._execute_registry_tool(tool, tool_name, cmd_target, cycle)
                                return
        except Exception as e:
            logger.debug(f"Auto-installation of tool '{tool_name}' failed: {e}")

        # Tool not registered — note it and try shell
        if tool_name not in self.missing_tools:
            self.missing_tools.add(tool_name)

        # Fall back to shell
        cmd = f"{tool_name} {cmd_target}"
        self._execute_shell_command(cmd, cycle)

    def _handle_run_command(self, decision: Dict, cycle: int):
        """Execute an arbitrary shell command."""
        command = decision.get("command", "")
        if not command:
            console.print("  [yellow]├─ No command specified[/yellow]")
            return

        # Check if command starts with a registered tool name
        tokens = shlex.split(command)
        if tokens:
            first = tokens[0]
            tool = registry.get_tool(first)
            if tool and tool.is_available:
                # Route through registry for structured output
                self._execute_registry_tool(tool, first, self.target or "", cycle)
                return

        self._execute_shell_command(command, cycle)

    def _handle_read_file(self, decision: Dict):
        """Read a file and display contents."""
        file_path = decision.get("file_path", "")
        if not file_path:
            return
        try:
            result = self.executor.file_editor.read_file(file_path, limit=80)
            if result.success:
                console.print(f"  [cyan]├─ File: {file_path}[/cyan]")
                console.print(f"  {result.output[:600]}")
            else:
                console.print(f"  [red]├─ {result.error}[/red]")
        except Exception as e:
            console.print(f"  [red]├─ File error: {e}[/red]")

    def _handle_update_intel(self, decision: Dict):
        """Save discovered intelligence to vector memory."""
        intel = decision.get("intel", {})
        if not intel or not self.enable_memory:
            return
        for key, val in intel.items():
            remember(
                f"Intel: {key} = {val}",
                self.target or "hybrid",
                "hybrid_intel",
                session_type="hybrid",
            )
        console.print(f"  [magenta]├─ Intel saved: {list(intel.keys())}[/magenta]")

    def _handle_search_web(self, decision: Dict):
        """Search the web for information."""
        query = decision.get("query", "")
        if not query:
            return
        result = self.executor.execute_action({
            "type": "search_web",
            "params": {"query": query, "num_results": 5},
        })
        if result.success:
            console.print(f"  [blue]├─ Web: {query[:80]}[/blue]")
            console.print(f"  {result.output[:500]}")
        else:
            console.print(f"  [red]├─ Search error: {result.error}[/red]")

    def _handle_message(self, decision: Dict):
        """Display a message to the user and wait."""
        msg = decision.get("message", "")
        purpose = decision.get("purpose", "")
        if purpose:
            console.print(f"  [bold]├─ [{purpose}][/bold]")
        console.print(f"\n  [green]├─ AI: {msg}[/green]")

    # ── Execution Backends ──────────────────────────────────────────────

    def _execute_registry_tool(
        self, tool: Any, tool_name: str, cmd_target: str, cycle: int
    ):
        """Execute via ToolRegistry using the shared persistent event loop.

        Uses asyncio.run_coroutine_threadsafe() against the shared loop from
        tools/event_loop.py so we never create/teardown a loop per tool call.
        """
        import asyncio
        from pathlib import Path

        console.print(f"  [cyan]├─ [{tool_name}] via ToolRegistry[/cyan]")

        report_dir = (
            Path("reports") / f"hybrid_{tool_name}_{int(time.time())}"
        )
        report_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Prefer the shared persistent event loop (avoids per-call loop cost)
            from tools.event_loop import get_shared_loop
            loop = get_shared_loop()
            sem = asyncio.Semaphore(3)
            timeout = getattr(getattr(tool, "metadata", None), "timeout_seconds", 180)
            future = asyncio.run_coroutine_threadsafe(
                tool.execute(cmd_target, report_dir, sem), loop
            )
            result = future.result(timeout=timeout)
        except Exception as e:
            # Fallback: isolated event loop if shared loop unavailable
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                sem = asyncio.Semaphore(3)
                result = loop.run_until_complete(tool.execute(cmd_target, report_dir, sem))
                loop.close()
            except Exception as inner_e:
                result = ToolResult(
                    success=False,
                    tool_name=tool_name,
                    category=ToolCategory.UTILITY,
                    error_message=str(inner_e),
                )

        self._process_tool_result(result, tool_name, cmd_target, cycle)



    def _execute_shell_command(self, command: str, cycle: int):
        """Execute shell command with Governance gating."""
        # Governance check
        gate = self.governance.gate(
            mission_id=self.mission_key or "hybrid",
            target=self.target or "unknown",
            action={"type": "run_shell", "command": command},
        )

        if not gate.allowed:
            if gate.risk_level == "DESTRUCTIVE":
                console.print(
                    f"  [red]├─ BLOCKED: {gate.rationale}[/red]"
                )
            else:
                console.print(
                    f"  [yellow]├─ Requires approval: {command[:80]}[/yellow]"
                )
            return

        safe_name = command.split()[0] if command.split() else "shell"
        console.print(
            f"  [dim]├─ [{safe_name}] via shell[/dim]"
        )

        result = self.executor.execute_shell(command, timeout=300)

        if result.success:
            snippet = result.output[:300].strip()
            if snippet:
                console.print(f"  [dim]│  {snippet}[/dim]")
        else:
            console.print(
                f"  [red]├─ FAIL ({result.error[:100]})[/red]"
            )

        # Convert to ToolResult-like for analysis
        tool_result = ToolResult(
            success=result.success,
            tool_name=safe_name,
            category=ToolCategory.UTILITY,
            output=result.output[:5000],
            findings=self._extract_findings(result.output, command),
            error_message=result.error,
        )
        self._process_tool_result(tool_result, safe_name, command, cycle)

    # ── Results & Analysis ─────────────────────────────────────────────

    def _process_tool_result(
        self, result: ToolResult, tool_name: str, target_str: str, cycle: int
    ):
        """Post-process a tool result: store findings, run analysis."""
        # Collect findings
        for f in result.findings:
            f["_tool"] = tool_name
            self.all_findings.append(f)

        if result.findings:
            console.print(
                f"  [green]├─ {len(result.findings)} findings[/green]"
            )

        # Persist to MissionState
        if self.mission_state and result.findings:
            for f in result.findings[:10]:
                node_id = f"{tool_name}:{hash(str(f)) % 1000000:06x}"
                self.mission_state.upsert_node(
                    GraphNode(
                        node_id=node_id,
                        node_type="finding",
                        props={"tool": tool_name, **f},
                    )
                )
                self.mission_state.upsert_edge(
                    GraphEdge(
                        edge_id=f"{self.target}:{node_id}",
                        src_id=self.target or "target",
                        dst_id=node_id,
                        edge_type="has_finding",
                        props={"tool": tool_name},
                    )
                )

        # Vector memory
        if self.enable_memory and result.findings:
            for f in result.findings[:5]:
                remember(
                    f"Finding [{tool_name}]: {json.dumps(f, ensure_ascii=False)[:200]}",
                    self.target or "hybrid",
                    "hybrid_finding",
                    session_type="hybrid",
                )

        # Analysis pipeline
        if not self.enable_analysis:
            return
        if self._should_run_analysis(target_str if isinstance(target_str, str) else ""):
            self._run_analysis(result, tool_name, cycle)

    def _run_analysis(self, result: ToolResult, tool_name: str, step: int):
        """Run Elenginx's 13-analyzer pipeline on a tool result."""
        if not self.mission_state:
            return
        try:
            pipeline = AnalysisPipeline(self._agent_ref())
            pipeline.run_all(
                result=result,
                tool_name=tool_name,
                target=self.target or "unknown",
                step=step,
                mission_key=self.mission_key,
                mission_state=self.mission_state,
                callback=None,
            )
        except Exception as e:
            logger.debug(f"Analysis pipeline error: {e}")

    def _should_run_analysis(self, command: str) -> bool:
        """Skip analysis for trivial commands."""
        if not command:
            return False
        if _SIMPLE_COMMANDS.match(command):
            return False
        return True

    @staticmethod
    def _extract_findings(output: str, command: str) -> List[Dict]:
        """Heuristic and structured extraction of potential findings from shell output.

        Attempts to parse structured JSON / JSON-Lines outputs from security tools
        (Nuclei, Httpx, Subfinder, etc.) and falls back to regex patterns for raw text.
        """
        findings = []
        if not output or not output.strip():
            return findings

        # Clean command for reference
        cmd_lower = command.lower() if command else ""

        # ── 1. Try JSON / JSONL Parsing ──────────────────────────────────────
        json_lines = []
        for line in output.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    json_lines.append(json.loads(line_str))
                except Exception:
                    pass

        # Try to parse entire output as single JSON array/object if no lines parsed
        if not json_lines and output.strip().startswith(("[", "{")):
            try:
                parsed = json.loads(output.strip())
                if isinstance(parsed, list):
                    json_lines.extend(parsed)
                elif isinstance(parsed, dict):
                    json_lines.append(parsed)
            except Exception:
                pass

        # Process parsed JSON objects
        if json_lines:
            for item in json_lines:
                if not isinstance(item, dict):
                    continue

                # A. Nuclei JSON Format
                if "template-id" in item or "template" in item:
                    info = item.get("info", {})
                    severity = info.get("severity", item.get("severity", "info")).lower()
                    findings.append({
                        "type": "nuclei",
                        "severity": severity,
                        "title": f"Nuclei: {info.get('name', item.get('template-id', 'finding'))}",
                        "target": item.get("matched-at", item.get("host", "")),
                        "url": item.get("matched-at", ""),
                        "description": f"Template: {item.get('template-id')}. Matched: {item.get('matched-at') or item.get('host')}",
                        "evidence": item.get("extracted-results", item.get("matcher-name", "")),
                    })

                # B. Httpx JSON Format
                elif "webserver" in item or "status-code" in item or "tech" in item:
                    findings.append({
                        "type": "httpx_probe",
                        "severity": "info",
                        "title": f"Httpx: {item.get('url', 'host')} [{item.get('status-code', '')}]",
                        "target": item.get("url", item.get("host", "")),
                        "url": item.get("url", ""),
                        "description": f"Server: {item.get('webserver', 'unknown')}. Tech: {', '.join(item.get('tech', []))}",
                        "evidence": f"Title: {item.get('title', '')} | Status: {item.get('status-code')}",
                    })

                # C. Generic security finding
                elif any(k in item for k in ("vuln", "vulnerability", "finding", "issue", "severity")):
                    severity = item.get("severity", "medium").lower()
                    findings.append({
                        "type": item.get("type", "generic_finding"),
                        "severity": severity,
                        "title": item.get("title", item.get("name", "Security Finding")),
                        "target": item.get("target", item.get("url", "")),
                        "url": item.get("url", ""),
                        "description": item.get("description", item.get("message", "")),
                        "evidence": json.dumps(item),
                    })

            if findings:
                return findings

        # ── 2. Fallback to Regex Heuristics (for plain text shell output) ─────
        # Look for subdomains/hosts lists (e.g. from subfinder or simple list commands)
        if "subfinder" in cmd_lower or "assetfinder" in cmd_lower:
            hosts = []
            for line in output.splitlines():
                line_str = line.strip()
                if line_str and not line_str.startswith("[") and "." in line_str:
                    hosts.append(line_str)
            if hosts:
                findings.append({
                    "type": "subdomains_discovered",
                    "severity": "info",
                    "title": f"Discovered {len(hosts)} subdomains",
                    "description": f"Found: {', '.join(hosts[:10])}...",
                    "evidence": "\n".join(hosts),
                })
                return findings

        # Look for URLs in output
        urls = re.findall(r"https?://[^\s\"'>]+", output)
        if urls:
            findings.append({
                "type": "extracted_url",
                "urls": urls[:20],
                "count": len(urls),
                "severity": "info",
            })

        # Look for potential credentials/keys
        keys = re.findall(
            r"(?:API[_-]?KEY|SECRET|PASSWORD|TOKEN)[=:]\s*\S+",
            output,
            re.IGNORECASE,
        )
        if keys:
            findings.append({
                "type": "potential_secret",
                "matches": keys[:5],
                "severity": "high",
            })

        return findings

    # ── Loop Protection ────────────────────────────────────────────────

    def _is_deadlocked(self) -> bool:
        """Check if the same action repeats too many times."""
        if len(self.action_history) < self.loop_threshold:
            return False

        recent = self.action_history[-self.loop_threshold:]
        signatures = [
            (a.get("action", ""), str(a.get("command", a.get("tool", ""))))
            for a in recent
        ]
        if len(set(signatures)) == 1:
            return True

        return False

    # ── Finalization ───────────────────────────────────────────────────

    def _finalize_mission(self) -> str:
        """Generate final report with CVSS + findings summary."""
        elapsed = time.time() - self.start_time

        # CVSS scoring
        scored = []
        for f in self.all_findings:
            try:
                score = self.cvss_calc.from_finding(
                    f.get("type", "unknown"),
                    f.get("url", ""),
                    json.dumps(f)[:200],
                    {},
                )
                scored.append({
                    "tool": f.get("_tool", "?"),
                    "type": f.get("type", "unknown"),
                    "severity": score.severity.value,
                    "cvss": score.base_score,
                    "vector": score.vector_string,
                })
            except Exception:
                scored.append({
                    "tool": f.get("_tool", "?"),
                    "type": f.get("type", "unknown"),
                    "severity": f.get("severity", "info"),
                    "cvss": 0,
                })

        # Sort by severity
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        scored.sort(key=lambda s: sev_order.get(s["severity"], 5))

        # Build report
        lines = [
            f"# Hybrid Mission Report: {self.objective[:80]}",
            f"**Target**: {self.target or 'N/A'}",
            f"**Duration**: {elapsed:.0f}s ({elapsed / 60:.1f}m)",
            f"**Total Actions**: {len(self.action_history)}",
            f"**Total Findings**: {len(self.all_findings)}",
            f"**Tools Used**: {len(self.missing_tools)} missing (noted)",
            "",
            "## CVSS-Scored Findings",
        ]

        if scored:
            lines.append("")
            lines.append("| Severity | Type | CVSS | Source |")
            lines.append("|----------|------|------|--------|")
            for s in scored:
                lines.append(
                    f"| {s['severity']} | {s['type']} | {s['cvss']:.1f} | {s['tool']} |"
                )
        else:
            lines.append("\nNo structured findings recorded.")

        # Count per severity
        if scored:
            counts = {}
            for s in scored:
                counts[s["severity"]] = counts.get(s["severity"], 0) + 1
            lines.append("\n## Summary")
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                if counts.get(sev):
                    lines.append(f"- **{sev}**: {counts[sev]}")

        # Action log
        lines.append("\n## Action Log")
        for i, a in enumerate(self.action_history, 1):
            purpose = a.get("purpose", a.get("action", ""))
            a.get("tool", a.get("command", ""))
            lines.append(f"  {i}. [{a.get('action', '?')}] {purpose[:100]}")

        if self.missing_tools:
            lines.append("\n## Tools Not Available (could install)")
            for t in sorted(self.missing_tools):
                lines.append(f"  - {t}")

        lines.append("\n---\n*Generated by Elengenix Hybrid Agent*")
        return "\n".join(lines)

    # ── Helpers ────────────────────────────────────────────────────────

    def _log(self, msg: str):
        """Log and optionally callback."""
        logger.info(msg)
        if self.callback:
            self.callback(msg)

    def _agent_ref(self):
        """Return a minimal reference for AnalysisPipeline compatibility."""
        class _AgentRef:
            governance = self.governance
            payload_mutator = None
            logic_analyzer = None
            activity_logger = None
        ref = _AgentRef()
        try:
            from tools.payload_mutation import PayloadMutator
            ref.payload_mutator = PayloadMutator()
        except Exception:
            pass
        try:
            from tools.logic_analyzer import BusinessLogicAnalyzer
            ref.logic_analyzer = BusinessLogicAnalyzer(mission_state=self.mission_state)
        except Exception:
            pass
        try:
            from live_display import get_activity_logger
            ref.activity_logger = get_activity_logger()
        except Exception:
            pass
        return ref

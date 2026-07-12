"""
elengenix/agent/vuln_agent.py — Autonomous Vulnerability Hunting Agent

Architecture:
  THINK → ACT → ANALYZE → REPEAT

Unlike a script-chain or phase-locked scanner, this agent:
  - Reasons about the target autonomously
  - Generates and tests vulnerability hypotheses
  - Pivots freely based on findings
  - Decides when it has enough evidence to conclude
  - Produces a structured vulnerability report

Each turn the AI receives full context (target profile, findings,
hypotheses, scan history) and can call any tool with any arguments.
The agent does NOT force a linear phase sequence.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.agent.vuln")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single vulnerability or observation discovered during the hunt."""

    title: str
    description: str
    severity: str  # critical / high / medium / low / info
    target: str
    evidence: str = ""
    remediation: str = ""
    source_tool: str = ""
    confidence: float = 0.5  # 0.0–1.0


@dataclass
class Hypothesis:
    """A testable hypothesis about the target."""

    description: str
    rationale: str
    status: str = "pending"  # pending / testing / confirmed / rejected
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.3


@dataclass
class ScanStep:
    """A single step in the scan history."""

    step: int
    reasoning: str
    tool: str
    arguments: Dict[str, Any]
    result_summary: str
    timestamp: float = 0.0


@dataclass
class VulnReport:
    """Final vulnerability report produced when the agent concludes."""

    target: str
    scan_duration: float = 0.0
    total_steps: int = 0
    findings: List[Finding] = field(default_factory=list)
    hypotheses_tested: int = 0
    hypotheses_confirmed: int = 0
    summary: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_duration_seconds": self.scan_duration,
            "total_steps": self.total_steps,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
            "hypotheses_tested": self.hypotheses_tested,
            "hypotheses_confirmed": self.hypotheses_confirmed,
            "summary": self.summary,
            "open_ports": self.open_ports,
            "services": self.services,
            "recommendations": self.recommendations,
        }


# ---------------------------------------------------------------------------
# Tool definitions (self-contained for this agent)
# ---------------------------------------------------------------------------

# Each tool is a dict with: name, description, parameters (JSON schema), handler


def _tool_port_scan(target: str, ports: str = "common") -> Dict[str, Any]:
    """Scan target for open ports and running services."""
    try:
        from tools.tool_registry import registry

        tool = registry.get_tool("nmap")
        if tool and hasattr(tool, "is_available") and tool.is_available:
            result = tool.handler(target)
            return {"success": True, "output": result.output if hasattr(result, "output") else str(result), "port_count": 0}

        # Fallback: use omni_scan
        from tools.omni_scan import run_scan

        result = run_scan(target, scan_type="port")
        return {"success": True, "output": str(result), "port_count": 0}
    except Exception as exc:
        logger.debug("port scan failed: %s", exc)
        return {"success": False, "error": str(exc)}


def _tool_web_recon(target: str, path: str = "/") -> Dict[str, Any]:
    """Perform web recon on target (HTTP headers, technologies, endpoints)."""
    try:
        from tools.omni_scan import run_scan

        result = run_scan(target, scan_type="web")
        return {"success": True, "output": str(result)}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def _tool_vuln_scan(target: str, scan_type: str = "general") -> Dict[str, Any]:
    """Run vulnerability scanner against target."""
    try:
        from tools.tool_registry import registry

        tool = registry.get_tool(scan_type) or registry.get_tool("nikto")
        if tool and tool.is_available:
            result = tool.handler(target)
            return {"success": True, "output": result.output if hasattr(result, "output") else str(result)}
        else:
            return {"success": False, "error": f"No {scan_type} tool available"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def _tool_search_cve(service: str, version: str = "") -> Dict[str, Any]:
    """Search for known CVEs affecting a service/version."""
    try:
        from tools.nvd_cve import search_cve

        results = search_cve(f"{service} {version}".strip())
        return {"success": True, "cves": str(results)[:2000]}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def _tool_analyze_target(target: str) -> Dict[str, Any]:
    """Gather initial target intelligence (DNS, whois, technologies)."""
    try:
        from tools.omni_scan import run_scan

        result = run_scan(target, scan_type="recon")
        return {"success": True, "output": str(result)}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# Registered tool list for the agent
# NOTE: handler_name is a string (not a function reference) so that
# unittest.mock.patch works correctly at runtime.
AVAILABLE_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "port_scan",
        "description": "Scan target for open ports and running services. Returns port numbers and service names.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or domain"},
                "ports": {
                    "type": "string",
                    "description": "Port range: 'common' (top 1000), 'all', or '80,443,8080'",
                    "default": "common",
                },
            },
            "required": ["target"],
        },
        "handler_name": "_tool_port_scan",
    },
    {
        "name": "web_recon",
        "description": "Probe web server: HTTP headers, technologies, directories, endpoints.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or domain"},
                "path": {
                    "type": "string",
                    "description": "Base path to scan (default: /)",
                    "default": "/",
                },
            },
            "required": ["target"],
        },
        "handler_name": "_tool_web_recon",
    },
    {
        "name": "vuln_scan",
        "description": "Run vulnerability scanner against target to find known vulnerabilities.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or domain"},
                "scan_type": {
                    "type": "string",
                    "description": "Scanner type: 'general', 'web', 'network'",
                    "default": "general",
                },
            },
            "required": ["target"],
        },
        "handler_name": "_tool_vuln_scan",
    },
    {
        "name": "search_cve",
        "description": "Search for known CVEs affecting a specific software or service version.",
        "parameters": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "Service name (e.g., 'apache', 'nginx', 'openssh')"},
                "version": {
                    "type": "string",
                    "description": "Version string (optional, e.g. '2.4.49')",
                    "default": "",
                },
            },
            "required": ["service"],
        },
        "handler_name": "_tool_search_cve",
    },
    {
        "name": "analyze_target",
        "description": "Initial intelligence gathering: DNS records, WHOIS, technology stack detection.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain or IP"}
            },
            "required": ["target"],
        },
        "handler_name": "_tool_analyze_target",
    },
]

TOOL_DEFS_TEXT: str = json.dumps(
    [
        {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}
        for t in AVAILABLE_TOOLS
    ],
    indent=2,
)


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_TEMPLATE = """You are Elengenix — an autonomous AI security research agent purpose-built for vulnerability discovery.

Your mission: thoroughly investigate the target and find security vulnerabilities.
You have complete autonomy over HOW you do this. There are no forced phases or sequences.

## CONTRACT

1. **Think before you act.** Explain your reasoning for each step.
2. **Call ONE tool per turn.** When you have results, analyze them.
3. **Build hypotheses.** "Port 80 open → likely Apache → try known CVEs"
4. **Pivot on evidence.** A finding changes direction. Follow it.
5. **Conclude when ready.** When you have enough evidence to report findings, summarize.

## Current state

Target: {target}
Target type: {target_type}
Steps used: {step_count}/{max_steps}

### Target profile accumulated
{target_profile}

### Current hypotheses
{hypotheses}

### Findings so far
{findings}

### Recent scan history
{scan_history}

## Available tools

{TOOL_DEFS_TEXT}

## Response format

Respond with your reasoning, then call ONE tool:

Reasoning: <what you're thinking and why>

```json
{{
  "tool": "<tool_name>",
  "arguments": {{ ... }}
}}
```

Or if you have enough evidence, produce the final report:

```json
{{
  "conclude": true,
  "summary": "...",
  "findings": [...]
}}
```"""


# ---------------------------------------------------------------------------
# Vulnerability Agent
# ---------------------------------------------------------------------------


class VulnAgent:
    """Autonomous vulnerability hunting agent.

    The agent runs a reasoning loop where the AI thinks, picks a tool,
    executes it, analyzes results, and repeats. No forced sequence.
    """

    def __init__(
        self,
        client: Any,
        target: str,
        max_steps: int = 25,
        governance: Any = None,
        report_dir: Optional[Path] = None,
    ):
        self.client = client
        self.target = target
        self.max_steps = max_steps
        self.governance = governance
        self.report_dir = report_dir or Path("reports")

        # Runtime state
        self.step = 0
        self.start_time: float = 0.0
        self.profile: Dict[str, Any] = {}
        self.findings: List[Finding] = []
        self.hypotheses: List[Hypothesis] = []
        self.scan_history: List[ScanStep] = []
        self.conversation: List[Dict[str, str]] = []
        self._conclusion: str = ""

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def hunt(self) -> VulnReport:
        """Execute the autonomous hunting loop.

        Returns a VulnReport with all findings.
        """
        logger.info("Hunt started: target=%s", self.target)
        self.start_time = time.time()
        self.step = 0

        while self.step < self.max_steps:
            self.step += 1
            logger.info("Step %d/%d", self.step, self.max_steps)

            # 1. REASON — AI decides what to do
            action = self._reason_step()
            if action is None:
                logger.warning("No action from AI, concluding")
                break

            # 2. If AI wants to conclude, stop the loop
            if action.get("conclude"):
                logger.info("AI concluded hunt")
                self._record_conclusion(action)
                break

            # 3. ACT — execute the chosen tool
            result = self._execute_step(action)

            # 4. ANALYZE — record and feed back next iteration
            self._record_step(action, result)

        return self._generate_report()

    # ------------------------------------------------------------------
    # Core loop
    # ------------------------------------------------------------------

    def _convert_messages(self, messages: List[Dict[str, str]]) -> List:
        """Convert dict messages to client's expected format.

        UniversalAIClient requires AIMessage dataclass objects.
        Mock/test clients accept plain dicts.
        Graceful fallback if AIMessage is unavailable.
        """
        try:
            from tools.universal_ai_client import AIMessage

            return [AIMessage(role=m["role"], content=m["content"]) for m in messages]
        except ImportError:
            return messages

    def _reason_step(self) -> Optional[Dict[str, Any]]:
        """Ask the AI what to do next. Returns parsed action dict."""
        prompt = self._build_turn_prompt()

        self.conversation.append({"role": "user", "content": prompt})
        try:
            messages = self._convert_messages(self.conversation)
            response = self.client.chat(messages)
            content = response.content.strip() if response else ""
        except Exception as exc:
            logger.error("AI call failed: %s", exc)
            return {"conclude": True, "summary": f"AI error: {exc}"}

        self.conversation.append({"role": "assistant", "content": content})

        # Parse JSON from the response
        action = self._extract_action(content)
        return action

    def _resolve_handler(self, tool_name: str) -> Optional[Callable]:
        """Resolve a tool handler by name at call time.

        Uses getattr on the current module so unittest.mock.patch
        works correctly — handler_name is a string, not a cached ref.
        """
        import sys

        module = sys.modules[__name__]
        for t in AVAILABLE_TOOLS:
            if t["name"] == tool_name:
                handler_name = t.get("handler_name", "")
                return getattr(module, handler_name, None)
        return None

    def _execute_step(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool call and return the result."""
        tool_name = action.get("tool", "")
        arguments = action.get("arguments", {})

        handler = self._resolve_handler(tool_name)
        if not handler:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}

        # Governance gate
        if self.governance:
            gate = self.governance.gate(
                mission_id="vuln-hunt",
                target=self.target,
                action=tool_name,
            )
            if hasattr(gate, "decision") and gate.decision in ("deny",):
                return {"success": False, "error": f"Blocked by governance: {gate.rationale}"}

        logger.info("Executing: %s(%s)", tool_name, arguments)
        try:
            result = handler(**arguments)
            return result
        except Exception as exc:
            logger.error("Tool execution failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _record_step(self, action: Dict[str, Any], result: Dict[str, Any]) -> None:
        """Record the step in history and extract findings."""
        step_record = ScanStep(
            step=self.step,
            reasoning=action.get("reasoning", ""),
            tool=action.get("tool", ""),
            arguments=action.get("arguments", {}),
            result_summary=str(result)[:300],
            timestamp=time.time(),
        )
        self.scan_history.append(step_record)

        # If successful, extract knowledge
        if result.get("success"):
            self._update_profile(result)
            self._maybe_generate_hypothesis(result)

    def _record_conclusion(self, action: Dict[str, Any]) -> None:
        """Record the final conclusion."""
        self._conclusion = action.get("summary", "")
        self.conversation.append(
            {
                "role": "assistant",
                "content": f"# HUNT COMPLETE\n\n{self._conclusion}",
            }
        )

    # ------------------------------------------------------------------
    # Knowledge management
    # ------------------------------------------------------------------

    def _update_profile(self, result: Dict[str, Any]) -> None:
        """Update target profile with new knowledge."""
        output = result.get("output", "")
        if not output:
            return

        # Pattern: opened ports
        import re

        ports = re.findall(r"(?:port|)\s*(\d+)\/(?:tcp|udp)", output, re.I)
        if ports:
            existing = set(self.profile.get("open_ports", []))
            for p in ports:
                existing.add(int(p))
            self.profile["open_ports"] = sorted(existing)

        # Service names
        services = re.findall(r"(\w+)\s+(\d+\.\d+(?:\.\d+)?)", output)
        for svc, ver in services:
            svc_lower = svc.lower()
            if svc_lower not in ("http", "https", "running"):
                self.profile.setdefault("services", {})[svc_lower] = ver

    def _maybe_generate_hypothesis(self, result: Dict[str, Any]) -> None:
        """Generate a hypothesis based on new findings."""
        output = result.get("output", "")
        if not output:
            return

        import re

        # Known patterns that suggest testing
        patterns = [
            (r"apache[\s/]*(\d+\.\d+(?:\.\d+)?)", "Apache version detected, possible vuln"),
            (r"nginx[\s/]*(\d+\.\d+(?:\.\d+)?)", "nginx version detected, possible vuln"),
            (r"openssh[\s/]*(\d+\.\d+(?:\.\d+)?)", "SSH version detected, check auth bypass"),
            (r"port\s+80", "HTTP service → explore web endpoints"),
            (r"port\s+443", "HTTPS service → explore web endpoints"),
            (r"port\s+22", "SSH access → check version and auth"),
            (r"port\s+3306", "MySQL exposed → potential database access"),
            (r"port\s+6379", "Redis exposed → potential RCE"),
            (r"port\s+27017", "MongoDB exposed → potential data leak"),
        ]

        for pattern, desc in patterns:
            if re.search(pattern, output, re.I):
                hyp = Hypothesis(
                    description=desc,
                    rationale=f"Found via pattern match: {pattern}",
                    status="pending",
                )
                # Avoid duplicates
                if not any(h.description == hyp.description for h in self.hypotheses):
                    self.hypotheses.append(hyp)

    # ------------------------------------------------------------------
    # Prompts
    # ------------------------------------------------------------------

    def _build_turn_prompt(self) -> str:
        """Build the prompt for the current turn."""
        profile_text = json.dumps(self.profile, indent=2) if self.profile else "(nothing yet)"
        hypotheses_text = self._format_hypotheses()
        findings_text = self._format_findings()
        history_text = self._format_history()
        target_type = "IP" if self.target.replace(".", "").isdigit() else "domain"

        return SYSTEM_PROMPT_TEMPLATE.format(
            target=self.target,
            target_type=target_type,
            step_count=self.step,
            max_steps=self.max_steps,
            target_profile=profile_text,
            hypotheses=hypotheses_text,
            findings=findings_text,
            scan_history=history_text,
            TOOL_DEFS_TEXT=TOOL_DEFS_TEXT,
        )

    def _format_hypotheses(self) -> str:
        if not self.hypotheses:
            return "No hypotheses yet."
        lines = []
        for h in self.hypotheses:
            status_mark = "🔄" if h.status == "testing" else "⏳" if h.status == "pending" else "✅" if h.status == "confirmed" else "❌"
            lines.append(f"- [{status_mark}] ({h.status}) {h.description} (conf: {h.confidence:.1f})")
            if h.evidence:
                lines.append(f"  Evidence: {h.evidence[-1][:100]}")
        return "\n".join(lines)

    def _format_findings(self) -> str:
        if not self.findings:
            return "No findings yet."
        lines = []
        for f in self.findings:
            sev_mark = "🔴" if f.severity == "critical" else "🟠" if f.severity == "high" else "🟡" if f.severity == "medium" else "🔵"
            lines.append(f"- [{sev_mark}] [{f.severity.upper()}] {f.title} (via {f.source_tool})")
        return "\n".join(lines)

    def _format_history(self) -> str:
        if not self.scan_history:
            return "(no steps yet)"
        lines = []
        for s in self.scan_history[-5:]:  # last 5 steps
            lines.append(f"  Step {s.step}: {s.tool}({s.arguments}) → {s.result_summary[:80]}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _extract_action(self, content: str) -> Dict[str, Any]:
        """Extract a JSON action block from the AI response."""
        import re

        # 1) Try JSON code fence first
        m = re.search(r"```json\s*\n(.*?)\n```", content, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass

        # 2) Try bare JSON with brace matching
        # Find every '{' and try to parse from there with matched braces
        for idx, ch in enumerate(content):
            if ch != "{":
                continue
            depth = 1
            for end in range(idx + 1, len(content)):
                c = content[end]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        blob = content[idx : end + 1]
                        if '"tool"' in blob or '"conclude"' in blob:
                            try:
                                return json.loads(blob)
                            except json.JSONDecodeError:
                                pass
                        break

        # 3) Try conclude pattern
        m = re.search(r"conclude.*?(?:true|yes)", content, re.I)
        if m:
            return {"conclude": True, "summary": content[:500]}

        # 4) Fallback
        return {"conclude": True, "summary": content[:500]}

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def _generate_report(self) -> VulnReport:
        """Generate the final vulnerability report."""
        duration = time.time() - self.start_time
        confirmed = [h for h in self.hypotheses if h.status == "confirmed"]
        tested = [h for h in self.hypotheses if h.status in ("confirmed", "rejected")]

        report = VulnReport(
            target=self.target,
            scan_duration=duration,
            total_steps=self.step,
            findings=self.findings,
            hypotheses_tested=len(tested),
            hypotheses_confirmed=len(confirmed),
            open_ports=self.profile.get("open_ports", []),
            services=self.profile.get("services", {}),
            summary=self._build_summary(),
            recommendations=self._build_recommendations(),
        )

        # Save report
        self.report_dir.mkdir(parents=True, exist_ok=True)
        report_path = self.report_dir / f"vuln_report_{self.target}_{int(self.start_time)}.json"
        try:
            report_path.write_text(json.dumps(report.to_dict(), indent=2))
            logger.info("Report saved: %s", report_path)
        except Exception as exc:
            logger.warning("Failed to save report: %s", exc)

        return report

    def _build_summary(self) -> str:
        """Build a natural-language summary of findings."""
        # Use AI's conclusion if available
        if self._conclusion:
            return f"# Vulnerability Report: {self.target}\n\n{self._conclusion}"

        parts = [f"# Vulnerability Report: {self.target}"]
        if self.findings:
            by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in self.findings:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            parts.append(f"\n## Summary")
            parts.append(f"Found {len(self.findings)} vulnerabilities:")
            for sev, count in by_sev.items():
                if count:
                    parts.append(f"  - {sev}: {count}")
        else:
            parts.append("\nNo vulnerabilities found.")

        if self.profile.get("open_ports"):
            ports = ", ".join(str(p) for p in self.profile["open_ports"][:20])
            parts.append(f"\nOpen ports: {ports}")

        return "\n".join(parts)

    def _build_recommendations(self) -> List[str]:
        """Build remediation recommendations from findings."""
        recs = []
        for f in self.findings:
            if f.remediation:
                recs.append(f.remediation)
        if self.profile.get("open_ports"):
            recs.append("Review and close unnecessary open ports")
        return recs or ["No specific recommendations generated"]

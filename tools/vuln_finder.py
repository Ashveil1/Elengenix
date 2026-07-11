"""tools/vuln_finder.py — Core Adaptive Vulnerability Finder Engine.

Integrates all components: Knowledge Graph, Escalation, Chaining, Verification,
and Adaptive Planning into a single cohesive engine.

Public API:
    VulnFinder - Main vulnerability finder class
    MissionState - Mission state data class
    MissionStatus - Mission status enum
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from tools.adaptive_planner import AdaptivePlanner, ActionType
from tools.chaining_engine import ChainingEngine
from tools.escalation_engine import EscalationEngine
from tools.knowledge_graph import KnowledgeGraph
from tools.verification_engine import VerificationEngine

# Lazy imports for memory systems
_vector_memory = None
_mission_state_module = None

logger = logging.getLogger("elengenix.vuln_finder")


def _get_vector_memory():
    global _vector_memory
    if _vector_memory is None:
        try:
            from tools import vector_memory

            _vector_memory = vector_memory
        except ImportError:
            _vector_memory = None
    return _vector_memory


def _get_mission_state_module():
    global _mission_state_module
    if _mission_state_module is None:
        try:
            from tools import mission_state

            _mission_state_module = mission_state
        except ImportError:
            _mission_state_module = None
    return _mission_state_module


class MissionStatus(Enum):
    """Status of a vulnerability finding mission."""

    INIT = "init"
    RECON = "recon"
    PLANNING = "planning"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class MissionState:
    """State of a vulnerability finding mission.

    Attributes:
        target: The target to scan.
        status: Current mission status.
        findings: List of findings discovered.
        assets: Discovered assets dictionary.
        tried_paths: List of attack paths already tried.
        start_time: Mission start timestamp.
        steps: Number of steps taken.
        tokens_used: Tokens consumed.
        cost: Estimated cost in dollars.
    """

    target: str
    status: MissionStatus = MissionStatus.INIT
    findings: List[Dict[str, Any]] = field(default_factory=list)
    assets: Dict[str, Any] = field(default_factory=dict)
    tried_paths: List[str] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    steps: int = 0
    tokens_used: int = 0
    cost: float = 0.0


class VulnFinder:
    """Core Adaptive Vulnerability Finder Engine.

    This engine integrates all components to provide autonomous vulnerability
    finding with escalation, chaining, and verification.

    Based on Mythos research:
    - Simple prompt + isolation container
    - File ranking by bug likelihood
    - Parallel agents on different files
    - Verification agent confirms findings

    Example:
        finder = VulnFinder(target="http://example.com")
        assets = finder.recon()
        plan = finder.plan()
        # ... execute and find vulnerabilities
    """

    def __init__(
        self,
        target: str,
        max_steps: int = 100,
        budget_limit: float = 50.0,
    ) -> None:
        """Initialize VulnFinder.

        Args:
            target: Target URL or domain to scan.
            max_steps: Maximum number of steps per mission.
            budget_limit: Maximum cost limit in dollars.
        """
        self.target = target
        self.max_steps = max_steps
        self.budget_limit = budget_limit

        self.state = MissionState(target=target)
        self.kg = KnowledgeGraph()
        self.escalation = EscalationEngine()
        self.chaining = ChainingEngine()
        self.verification = VerificationEngine()
        self.planner = AdaptivePlanner()

        # Tool registry for execute()
        from tools.tool_registry import registry

        self.registry = registry

    def recon(self, quick: bool = False) -> Dict[str, Any]:
        """Perform reconnaissance on target using python_recon module.

        Runs subdomain enumeration, HTTP probing for tech stack fingerprint,
        directory brute-force, parameter discovery, and port scanning.

        Args:
            quick: If True, use smaller wordlists and skip slow passes.

        Returns:
            Dictionary with discovered assets (subdomains, endpoints, tech, ports).
        """
        self.state.status = MissionStatus.RECON
        self.state.steps += 1
        start_time = time.time()

        try:
            from tools.python_recon import PythonRecon

            recon = PythonRecon()
            result = recon.full_recon(self.target, quick=quick)

            # Build assets dict from recon results
            http_probe = result.get("http_probe", {})
            assets = {
                "target": self.target,
                "domain": result.get("domain", self.target),
                "subdomains": [s.get("subdomain", "") for s in result.get("subdomains", [])],
                "endpoints": [d.get("url", "") for d in result.get("directories", [])],
                "tech_stack": http_probe.get("tech", []),
                "server": http_probe.get("headers", {}).get("Server", ""),
                "title": http_probe.get("title", ""),
                "waf_status": None,
                "open_ports": [
                    {"port": p.get("port"), "service": p.get("service", "")}
                    for p in result.get("ports", [])
                ],
                "parameters": [
                    {
                        "param": p.get("param", ""),
                        "method": p.get("method", ""),
                        "delta_pct": p.get("delta_pct", 0),
                    }
                    for p in result.get("parameters", [])
                    if p.get("is_interesting")
                ],
                "http_status": http_probe.get("status", 0),
                "final_url": http_probe.get("final_url", ""),
            }

            self.state.assets = assets

            # Add discovered assets to knowledge graph
            self.kg.add_asset(self.target, {"type": "target", "domain": assets["domain"]})
            for sub in assets["subdomains"]:
                self.kg.add_asset(sub, {"type": "subdomain"})
                self.kg.add_edge(self.target, "has", sub)
            for ep in assets["endpoints"]:
                self.kg.add_asset(ep, {"type": "endpoint"})
                self.kg.add_edge(self.target, "has", ep)
            for port_info in assets["open_ports"]:
                port_id = f"{assets['domain']}:{port_info['port']}"
                self.kg.add_asset(port_id, {"type": "port", **port_info})
                self.kg.add_edge(self.target, "has", port_id)

            # Estimate recon cost (low token usage, mostly network I/O)
            self._track_cost(tokens=500, step_label="recon")

            elapsed = time.time() - start_time
            logger.info(
                f"Recon completed for {self.target}: "
                f"{len(assets['subdomains'])} subdomains, "
                f"{len(assets['endpoints'])} endpoints, "
                f"{len(assets['open_ports'])} open ports, "
                f"tech={assets['tech_stack']}, "
                f"{elapsed:.1f}s"
            )
            return assets

        except Exception as e:
            logger.error(f"Recon failed for {self.target}: {e}")
            assets = {
                "target": self.target,
                "subdomains": [],
                "endpoints": [],
                "tech_stack": [],
                "waf_status": None,
                "open_ports": [],
                "parameters": [],
                "error": str(e),
            }
            self.state.assets = assets
            return assets

    def plan(self) -> List[Dict[str, Any]]:
        """Create attack plan based on assets.

        Returns:
            List of ranked attack targets.
        """
        self.state.status = MissionStatus.PLANNING
        targets = [
            {"url": ep, "type": "api_endpoint"} for ep in self.state.assets.get("endpoints", [])
        ]
        ranked = self.planner.rank_targets(targets)
        logger.info(f"Planned {len(ranked)} attack paths")
        return ranked

    def execute(self, attack_path: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single attack path via the tool registry.

        Accepts an attack path dict with target URL and tool name, executes
        the tool through the registry, and returns actual results. Tracks
        findings in the knowledge graph.

        Args:
            attack_path: Dict with keys:
                - url (str): Target URL to scan.
                - tool (str): Registered tool name (e.g. "waf_detector", "ssrf_scanner").
                - kwargs (dict, optional): Extra arguments passed to the tool.

        Returns:
            Execution result dictionary with success, output, findings, and cost info.
        """
        self.state.status = MissionStatus.EXECUTING
        self.state.steps += 1
        start_time = time.time()

        target_url = attack_path.get("url", self.target)
        tool_name = attack_path.get("tool", "")
        extra_kwargs = attack_path.get("kwargs", {})

        # Deduplicate tried paths
        path_key = f"{tool_name}:{target_url}"
        if path_key not in self.state.tried_paths:
            self.state.tried_paths.append(path_key)

        result = {
            "path": attack_path,
            "success": False,
            "finding": None,
            "output": "",
            "tool": tool_name,
            "target": target_url,
            "execution_time": 0.0,
        }

        if not tool_name:
            result["output"] = "No tool specified in attack path"
            logger.warning("execute() called with no tool name")
            return result

        # Look up the tool in the registry
        tool = self.registry.get_tool(tool_name)
        if tool is None:
            result["output"] = f"Tool '{tool_name}' not found in registry"
            logger.warning(f"Tool '{tool_name}' not registered")
            return result

        if not tool.is_available:
            result["output"] = f"Tool '{tool_name}' binary not available"
            logger.warning(f"Tool '{tool_name}' not available (binary missing)")
            return result

        # Execute the tool via the registry (async under the hood)
        import asyncio
        from pathlib import Path

        report_dir = Path("data/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        semaphore = asyncio.Semaphore(1)

        try:
            # Try to get existing event loop, or create one
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                # We're inside an async context — run in a new thread
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(
                        asyncio.run, tool.execute(target_url, report_dir, semaphore, **extra_kwargs)
                    )
                    tool_result = future.result(timeout=tool.metadata.timeout_seconds)
            else:
                # Not in async context — safe to use asyncio.run
                tool_result = asyncio.run(
                    tool.execute(target_url, report_dir, semaphore, **extra_kwargs)
                )

            result["success"] = tool_result.success
            result["output"] = tool_result.output
            result["execution_time"] = tool_result.execution_time
            result["tool"] = tool_result.tool_name
            result["category"] = tool_result.category.value

            # Process findings
            if tool_result.findings:
                result["findings"] = tool_result.findings
                for finding in tool_result.findings:
                    self.add_finding(finding)
                    # Also add to knowledge graph with tool relationship
                    finding_id = f"finding-{len(self.state.findings)}"
                    self.kg.add_edge(self.target, "found_by", tool_name)

            if tool_result.error_message:
                result["error"] = tool_result.error_message
                logger.warning(f"Tool {tool_name} error: {tool_result.error_message}")

            # Track cost based on execution time (proxy for token usage)
            estimated_tokens = max(200, int(tool_result.execution_time * 100))
            self._track_cost(tokens=estimated_tokens, step_label=tool_name)

            logger.info(
                f"Executed {tool_name} on {target_url}: "
                f"success={tool_result.success}, "
                f"findings={len(tool_result.findings)}, "
                f"{tool_result.execution_time:.1f}s"
            )

        except Exception as e:
            result["output"] = f"Execution failed: {e}"
            result["error"] = str(e)
            logger.error(f"Tool {tool_name} execution failed: {e}")

        return result

    def escalate(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Try to escalate a finding to higher severity.

        Args:
            finding: The finding to escalate.

        Returns:
            Escalation result or None if not escalable.
        """
        path = self.escalation.can_escalate(finding)
        if path:
            return {
                "original": finding,
                "escalation_path": path.next_steps,
                "expected_severity": path.expected_severity,
            }
        return None

    def chain(self, findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Try to chain multiple findings.

        Args:
            findings: List of findings to chain.

        Returns:
            Chain result or None if not chainable.
        """
        chain = self.chaining.analyze_chain(findings)
        if chain:
            return {
                "findings": chain.findings,
                "combined_severity": chain.combined_severity,
                "impact": chain.impact_description,
            }
        return None

    def verify(
        self,
        finding: Dict[str, Any],
        model_a: str,
        model_b: str,
    ):
        """Verify a finding with dual-model verification.

        Args:
            finding: The finding to verify.
            model_a: Response from model A.
            model_b: Response from model B.

        Returns:
            VerificationResult.
        """
        return self.verification.verify(finding, model_a, model_b)

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding to the mission state and persist to memory.

        Args:
            finding: The finding to add.
        """
        self.state.findings.append(finding)
        self.kg.add_finding(
            f"finding-{len(self.state.findings)}",
            finding,
        )

        # Persist to vector memory for cross-session recall
        vm = _get_vector_memory()
        if vm:
            try:
                vm.remember(
                    content=f"FINDING: {finding.get('type', 'unknown')} "
                    f"at {finding.get('url', 'unknown')} "
                    f"(severity: {finding.get('severity', 'unknown')})",
                    target=self.target,
                    category="finding",
                )
            except Exception as e:
                logger.debug(f"Could not persist finding to vector memory: {e}")

        logger.info(f"Added finding: {finding.get('type', 'Unknown')}")

    def recall_similar_findings(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Recall similar findings from vector memory.

        Args:
            query: Search query.
            n_results: Number of results to return.

        Returns:
            List of similar findings from memory.
        """
        vm = _get_vector_memory()
        if not vm:
            return []
        try:
            return vm.recall(query=query, target=self.target, n_results=n_results)
        except Exception as e:
            logger.debug(f"Could not recall from vector memory: {e}")
            return []

    def save_mission_state(self) -> None:
        """Save mission state to SQLite for persistence."""
        ms = _get_mission_state_module()
        if not ms:
            return
        try:
            mission = ms.MissionState(
                mission_id=f"vulnfinder:{self.target}:{int(self.state.start_time)}",
                target=self.target,
                objective=f"Vulnerability scan of {self.target}",
            )
            for finding in self.state.findings:
                mission.add_fact(
                    fact_id=f"finding:{finding.get('type', 'unknown')}:{len(self.state.findings)}",
                    category="finding",
                    statement=f"{finding.get('type', 'unknown')} at {finding.get('url', 'unknown')}",
                    confidence=0.8,
                    evidence=finding,
                )
            logger.info(f"Saved mission state to SQLite")
        except Exception as e:
            logger.debug(f"Could not save mission state: {e}")

    def generate_report(self, format: str = "markdown") -> str:
        """Generate a vulnerability report.

        Args:
            format: Report format ('markdown', 'html', 'json').

        Returns:
            Report content string.
        """
        findings_by_severity = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }
        for finding in self.state.findings:
            severity = finding.get("severity", "INFO").upper()
            if severity in findings_by_severity:
                findings_by_severity[severity].append(finding)
            else:
                findings_by_severity["INFO"].append(finding)

        if format == "json":
            return json.dumps(
                {
                    "target": self.target,
                    "status": self.state.status.value,
                    "findings": self.state.findings,
                    "findings_by_severity": {k: len(v) for k, v in findings_by_severity.items()},
                    "total_findings": len(self.state.findings),
                    "steps": self.state.steps,
                    "cost": self.state.cost,
                },
                indent=2,
            )

        # Markdown report
        report = f"""# Vulnerability Report: {self.target}

**Status:** {self.state.status.value}
**Total Findings:** {len(self.state.findings)}
**Steps Taken:** {self.state.steps}
**Estimated Cost:** ${self.state.cost:.4f}

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | {len(findings_by_severity['CRITICAL'])} |
| HIGH | {len(findings_by_severity['HIGH'])} |
| MEDIUM | {len(findings_by_severity['MEDIUM'])} |
| LOW | {len(findings_by_severity['LOW'])} |
| INFO | {len(findings_by_severity['INFO'])} |

"""
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if findings_by_severity[severity]:
                report += f"## {severity} Findings\n\n"
                for i, finding in enumerate(findings_by_severity[severity], 1):
                    report += f"### {i}. {finding.get('type', 'Unknown')}\n"
                    report += f"- **URL:** {finding.get('url', 'N/A')}\n"
                    report += f"- **Parameter:** {finding.get('parameter', 'N/A')}\n"
                    report += f"- **Evidence:** {finding.get('evidence', 'N/A')}\n"
                    report += f"- **Impact:** {finding.get('impact', 'N/A')}\n"
                    report += f"- **Remediation:** {finding.get('remediation', 'N/A')}\n\n"

        return report

    def should_continue(self) -> bool:
        """Check if mission should continue.

        Returns:
            True if mission should continue.
        """
        if self.state.steps >= self.max_steps:
            return False
        if self.state.cost >= self.budget_limit:
            return False
        budget_remaining = 1.0 - (self.state.cost / self.budget_limit)
        return budget_remaining > 0.1

    def _track_cost(self, tokens: int = 0, step_label: str = "") -> None:
        """Track token usage and estimated cost for a step.

        Uses approximate pricing: $0.002 per 1K tokens (avg across providers).

        Args:
            tokens: Number of tokens consumed in this step.
            step_label: Label for the step (for logging).
        """
        self.state.tokens_used += tokens
        # Estimated cost: $0.002 per 1K tokens
        step_cost = (tokens / 1000) * 0.002
        self.state.cost += step_cost
        logger.debug(
            f"Cost tracking [{step_label}]: +{tokens} tokens, "
            f"+${step_cost:.6f}, total={self.state.tokens_used} tokens, "
            f"${self.state.cost:.6f}"
        )

    def get_status(self) -> Dict[str, Any]:
        """Get current mission status.

        Returns:
            Status dictionary.
        """
        return {
            "target": self.state.target,
            "status": self.state.status.value,
            "findings_count": len(self.state.findings),
            "steps": self.state.steps,
            "cost": self.state.cost,
            "budget_remaining": 1.0 - (self.state.cost / self.budget_limit),
        }

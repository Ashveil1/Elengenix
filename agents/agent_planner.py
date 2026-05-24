"""agents/agent_planner.py — Strategic planning module extracted from agent_brain.py."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from tools.universal_ai_client import AIClientManager, AIMessage
from tools.cvss_calculator import CVSSCalculator
from tools.tool_registry import ToolResult
from agents.agent_dataclasses import AttackPhase, AttackStep, AttackTree
from agents.agent_helpers import _extract_json_object

logger = logging.getLogger("elengenix.agent")


class StrategicPlanner:
    """Generates and manages attack strategies."""

    def __init__(self, client: AIClientManager):
        self.client = client
        self.cvss_calc = CVSSCalculator(use_ai=True)

    def generate_attack_tree(
        self,
        target: str,
        objective: str = "discover vulnerabilities",
    ) -> AttackTree:
        tree = AttackTree(target=target, objective=objective)

        planning_prompt = f"""You are a penetration testing strategist.

TARGET: {target}
OBJECTIVE: {objective}

Generate an attack tree as JSON with this structure:
{{
    "reasoning": "strategic analysis of the target",
    "phases": [
        {{
            "phase": "recon|scanning|enumeration|exploitation",
            "tools": ["tool_name"],
            "purpose": "what we want to achieve",
            "priority": 1
        }}
    ]
}}

Available tools: subfinder, httpx, naabu, nuclei, dalfox, arjun, ffuf, trufflehog, katana

Respond with valid JSON only."""

        try:
            response = self.client.chat([
                AIMessage(role="system", content="Generate penetration testing strategy"),
                AIMessage(role="user", content=planning_prompt),
            ]).content

            plan_data = _extract_json_object(response)
            if plan_data:
                tree.reasoning = plan_data.get("reasoning", "")
                for phase_data in plan_data.get("phases", []):
                    phase = AttackPhase(phase_data.get("phase", "recon"))
                    for tool_name in phase_data.get("tools", []):
                        tree.steps.append(AttackStep(
                            phase=phase,
                            tool_name=tool_name,
                            target=target,
                            purpose=phase_data.get("purpose", ""),
                        ))

        except Exception as e:
            logger.warning(f"AI planning failed: {e}, using default strategy")
            tree = self._default_attack_tree(target, objective)

        return tree

    def _default_attack_tree(self, target: str, objective: str) -> AttackTree:
        tree = AttackTree(
            target=target,
            objective=objective,
            reasoning="Default reconnaissance-to-exploitation pipeline",
        )
        default_steps = [
            AttackStep(AttackPhase.RECONNAISSANCE, "subfinder", target, "Discover subdomains"),
            AttackStep(AttackPhase.RECONNAISSANCE, "naabu", target, "Port scan discovered hosts"),
            AttackStep(AttackPhase.SCANNING, "httpx", target, "Probe live web services"),
            AttackStep(AttackPhase.ENUMERATION, "trufflehog", target, "Find secrets in code"),
            AttackStep(AttackPhase.ENUMERATION, "ffuf", target, "Discover hidden directories"),
            AttackStep(AttackPhase.EXPLOITATION, "nuclei", target, "Scan for CVEs and misconfigurations"),
            AttackStep(AttackPhase.EXPLOITATION, "dalfox", target, "Test for XSS vulnerabilities"),
            AttackStep(AttackPhase.ENUMERATION, "arjun", target, "Discover hidden parameters"),
        ]
        tree.steps = default_steps
        return tree

    def select_next_tool(self, tree: AttackTree, previous_results: List[ToolResult]) -> Optional[str]:
        for result in previous_results:
            if not result.success:
                continue
            for finding in result.findings:
                severity = finding.get("severity", "info")
                finding_type = finding.get("type", "")
                if finding_type == "secret" and severity in ["critical", "high"]:
                    return "trufflehog"
                if finding_type == "open_port" and finding.get("port") in [3306, 5432, 6379, 27017]:
                    return "nuclei"
                if finding_type == "open_port" and finding.get("port") in [80, 443, 8080, 3000]:
                    return "ffuf"
                if finding_type == "xss":
                    return "dalfox"
        for step in tree.steps:
            if not step.completed:
                return step.tool_name
        return None

    def adapt_strategy(self, tree: AttackTree, new_finding: Dict[str, Any]) -> List[AttackStep]:
        additional_steps = []
        finding_type = new_finding.get("type", "")
        if finding_type == "api_endpoint":
            additional_steps.append(AttackStep(
                phase=AttackPhase.ENUMERATION,
                tool_name="arjun",
                target=new_finding.get("url", tree.target),
                purpose="Discover API parameters",
                depends_on=[],
            ))
        elif finding_type == "subdomain":
            subdomain = new_finding.get("subdomain", "")
            if subdomain:
                additional_steps.append(AttackStep(
                    phase=AttackPhase.SCANNING,
                    tool_name="httpx",
                    target=subdomain,
                    purpose=f"Probe new subdomain: {subdomain}",
                    depends_on=["subfinder"],
                ))
        elif finding_type == "hidden_parameter":
            additional_steps.append(AttackStep(
                phase=AttackPhase.EXPLOITATION,
                tool_name="dalfox",
                target=new_finding.get("url", tree.target),
                purpose="Test discovered parameters for XSS",
                depends_on=["arjun"],
            ))
        tree.steps.extend(additional_steps)
        return additional_steps

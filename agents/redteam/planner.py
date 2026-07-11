"""
agents/redteam/planner.py — REDTEAM Planner Agent (Strategist)

The Planner Agent generates attack strategies:
- Generates MITRE ATT&CK-aligned attack trees
- Maps tech stack to CWE IDs and ATT&CK techniques
- Prioritizes attack paths by risk/impact
- Adapts strategy based on findings
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .base import (
    AgentRole,
    MessageBus,
    MessageType,
    MissionPhase,
    RedTeamAgent,
    AgentMessage,
    MissionContext,
)

logger = logging.getLogger("elengenix.redteam.planner")


@dataclass
class AttackStep:
    """Single step in an attack tree"""
    technique_id: str  # MITRE ATT&CK technique ID (e.g., T1190)
    technique_name: str
    tactic: str  # MITRE tactic (e.g., initial-access)
    cwe_ids: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    expected_outcome: str = ""
    confidence: float = 0.5  # 0-1
    risk_level: str = "medium"  # low, medium, high, critical


@dataclass
class AttackTree:
    """Complete attack tree for a target"""
    target: str
    tech_stack: Dict[str, Any]
    steps: List[AttackStep] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    high_value_targets: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


# MITRE ATT&CK v16 Web Application Mapping
ATTACK_WEBAPP_MAPPING = {
    # Initial Access
    "T1190": {  # Exploit Public-Facing Application
        "name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "cwes": ["CWE-89", "CWE-79", "CWE-94", "CWE-502", "CWE-611", "CWE-22"],
        "tech_stack_triggers": {
            "php": ["CWE-89", "CWE-79", "CWE-94", "CWE-502"],
            "aspnet": ["CWE-89", "CWE-79", "CWE-502"],
            "java": ["CWE-89", "CWE-79", "CWE-502", "CWE-611"],
            "python": ["CWE-89", "CWE-79", "CWE-502", "CWE-611"],
            "node": ["CWE-89", "CWE-79", "CWE-1321"],
            "ruby": ["CWE-89", "CWE-79", "CWE-502"],
            "go": ["CWE-89", "CWE-22"],
        }
    },
    "T1199": {  # Trusted Relationship
        "name": "Trusted Relationship",
        "tactic": "initial-access",
        "cwes": ["CWE-287", "CWE-295"],
        "tech_stack_triggers": {
            "cloudflare": ["origin_verification"],
            "api_gateway": ["jwt_validation"],
        }
    },

    # Execution
    "T1059.007": {  # Command and Scripting Interpreter: JavaScript/JScript
        "name": "JavaScript/JScript",
        "tactic": "execution",
        "cwes": ["CWE-94", "CWE-1321"],
        "tech_stack_triggers": {
            "node": ["prototype_pollution", "deserialization"],
            "express": ["template_injection"],
        }
    },

    # Persistence
    "T1505.003": {  # Web Shell
        "name": "Web Shell",
        "tactic": "persistence",
        "cwes": ["CWE-94", "CWE-434"],
        "tech_stack_triggers": {
            "php": ["file_upload", "rce"],
            "aspnet": ["file_upload", "deserialization"],
            "java": ["file_upload", "deserialization"],
        }
    },

    # Privilege Escalation
    "T1068": {  # Exploitation for Privilege Escalation
        "name": "Exploitation for Privilege Escalation",
        "tactic": "privilege-escalation",
        "cwes": ["CWE-269", "CWE-250"],
        "tech_stack_triggers": {
            "linux": ["kernel_exploit", "sudo_misconfig"],
            "windows": ["token_impersonation", "bypass_uac"],
        }
    },

    # Defense Evasion
    "T1027": {  # Obfuscated Files or Information
        "name": "Obfuscated Files or Information",
        "tactic": "defense-evasion",
        "cwes": ["CWE-1032"],
        "tech_stack_triggers": {
            "waf": ["encoding", "fragmentation", "case_variation"],
            "ids": ["fragmentation", "ttl_manipulation"],
        }
    },

    # Credential Access
    "T1555": {  # Credentials from Password Stores
        "name": "Credentials from Password Stores",
        "tactic": "credential-access",
        "cwes": ["CWE-256", "CWE-257"],
        "tech_stack_triggers": {
            "browser": ["credential_dump"],
            "config_files": ["hardcoded_secrets"],
            "env_vars": ["exposed_secrets"],
        }
    },

    # Discovery
    "T1083": {  # File and Directory Discovery
        "name": "File and Directory Discovery",
        "tactic": "discovery",
        "cwes": ["CWE-22"],
        "tech_stack_triggers": {
            "web": ["directory_enum", "backup_files", "git_exposure"],
        }
    },

    # Lateral Movement
    "T1021.004": {  # Pass the Hash
        "name": "Pass the Hash",
        "tactic": "lateral-movement",
        "cwes": ["CWE-287"],
        "tech_stack_triggers": {
            "windows": ["ntlm_hash", "pth"],
            "kerberos": ["delegation"],
        }
    },

    # Collection
    "T1005": {  # Data from Local System
        "name": "Data from Local System",
        "tactic": "collection",
        "cwes": ["CWE-200"],
        "tech_stack_triggers": {
            "database": ["sql_injection", "misconfig"],
            "file_storage": ["path_traversal", "misconfig"],
        }
    },

    # Command and Control
    "T1071.001": {  # Web Protocols
        "name": "Web Protocols",
        "tactic": "command-and-control",
        "cwes": ["CWE-79", "CWE-94"],
        "tech_stack_triggers": {
            "web": ["websocket", "sse", "long_polling"],
            "dns": ["dns_tunneling"],
        }
    },

    # Exfiltration
    "T1041": {  # Exfiltration Over Web Service
        "name": "Exfiltration Over Web Service",
        "tactic": "exfiltration",
        "cwes": ["CWE-200"],
        "tech_stack_triggers": {
            "api": ["data_exfil", "idor"],
            "cloud": ["s3_exfil", "blob_exfil"],
        }
    },

    # Impact
    "T1485": {  # Data Destruction
        "name": "Data Destruction",
        "tactic": "impact",
        "cwes": ["CWE-367"],
        "tech_stack_triggers": {
            "database": ["sql_injection_drop", "truncate"],
            "filesystem": ["rce_rm", "wiper"],
        }
    },
}


class PlannerAgent:
    """Strategic Planner - generates attack trees and adapts strategy"""

    def __init__(self, message_bus: MessageBus):
        self.name = "planner"
        self.role = AgentRole.PLANNER
        self.bus = message_bus
        self.state: Dict[str, Any] = {}
        self.metrics: Dict[str, float] = {}
        self._shutdown_event = asyncio.Event()

        self.bus.subscribe(self.name, self._handle_message)
        self.bus.subscribe("all", self._handle_message)

        # Current attack tree
        self.current_tree: Optional[AttackTree] = None
        self.executed_steps: set = set()
        self.failed_steps: set = set()

    async def initialize(self, mission_context: MissionContext):
        """Initialize with mission context"""
        self.mission_context = mission_context
        logger.info(f"[{self.name}] Initialized for mission: {mission_context.mission_id}")

    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a planning task"""
        task_type = task.get("type", "unknown")

        if task_type == "generate_attack_tree":
            return await self._generate_attack_tree(task)
        elif task_type == "adapt_strategy":
            return await self._adapt_strategy(task)
        elif task_type == "prioritize_targets":
            return await self._prioritize_targets(task)
        elif task_type == "assess_chain_potential":
            return await self._assess_chain_potential(task)
        elif task_type == "recommend_next_step":
            return await self._recommend_next_step(task)
        else:
            return {"error": f"Unknown task type: {task_type}"}

    async def _generate_attack_tree(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate attack tree from tech stack fingerprint"""
        tech_stack = task.get("tech_stack", {})
        target = task.get("target", self.mission_context.target if self.mission_context else "unknown")

        logger.info(f"[{self.name}] Generating attack tree for {target}")

        tree = AttackTree(target=target, tech_stack=task.get("tech_stack", {}))

        # Extract technologies
        technologies = task.get("technologies", {})
        tech_list = []

        # Extract from fingerprint results
        if "technologies" in task:
            for host, tech in task["technologies"].items():
                if isinstance(tech, dict):
                    for key in ["server", "framework", "cms", "language", "db", "cms"]:
                        if tech.get(key):
                            tech_list.append(tech[key].lower())

        # Also check flat tech list
        if "tech_list" in task:
            tech_list.extend([t.lower() for t in task["tech_list"]])

        # Deduplicate
        tech_list = list(set(tech_list))

        # Generate attack steps from mapping
        steps = []
        seen_techniques = set()

        for tech in tech_list:
            for technique_id, mapping in ATTACK_WEBAPP_MAPPING.items():
                triggers = mapping.get("tech_stack_triggers", {})
                if tech in triggers or any(t in tech for t in triggers):
                    for cwe in mapping.get("cwes", []):
                        if (technique_id, cwe) not in seen_techniques:
                            seen_techniques.add((technique_id, cwe))

                            # Determine tools
                            tools = self._get_tools_for_technique(technique_id, cwe)

                            step = AttackStep(
                                technique_id=technique_id,
                                technique_name=mapping["name"],
                                tactic=mapping["tactic"],
                                cwe_ids=[cwe],
                                tools=tools,
                                expected_outcome=f"Exploit {cwe} via {mapping['name']}",
                                confidence=0.7,
                                risk_level=self._assess_risk(cwe)
                            )
                            steps.append(step)

        # Sort by tactic order and risk
        tactic_order = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact"
        ]

        tactic_priority = {t: i for i, t in enumerate(tactic_order)}
        steps.sort(key=lambda s: (tactic_priority.get(s.tactic, 99), -self._risk_score(s.risk_level)))

        # Create attack tree
        tree = AttackTree(
            target=self.mission_context.target if self.mission_context else "unknown",
            tech_stack=task.get("tech_stack", {}),
            steps=steps[:30],  # Limit to top 30
            entry_points=self._identify_entry_points(task),
            high_value_targets=self._identify_high_value_targets(task)
        )

        self.current_tree = tree

        # Share with other agents
        await self._share_attack_tree(tree)

        return {
            "status": "completed",
            "tree": {
                "target": tree.target,
                "steps_count": len(tree.steps),
                "tactics_covered": list(set(s.tactic for s in tree.steps)),
                "entry_points": tree.entry_points,
                "high_value_targets": tree.high_value_targets,
                "steps": [
                    {
                        "technique_id": s.technique_id,
                        "name": s.technique_name,
                        "tactic": s.tactic,
                        "cwe_ids": s.cwe_ids,
                        "tools": s.tools,
                        "confidence": s.confidence,
                        "risk": s.risk_level
                    }
                    for s in tree.steps
                ]
            }
        }

    def _get_tools_for_technique(self, technique_id: str, cwe: str) -> List[str]:
        """Map ATT&CK technique + CWE to Elengenix tools"""
        tool_map = {
            ("T1190", "CWE-89"): ["sqli_test", "active_fuzzer", "sqlmap"],
            ("T1190", "CWE-79"): ["xss_test", "active_fuzzer", "dalfox"],
            ("T1190", "CWE-94"): ["rce_test", "active_fuzzer"],
            ("T1190", "CWE-502"): ["deser_test", "active_fuzzer"],
            ("T1190", "CWE-611"): ["xxe_test", "active_fuzzer"],
            ("T1190", "CWE-22"): ["lfi_test", "active_fuzzer", "path_traversal"],
            ("T1059.007", "CWE-1321"): ["proto_pollution_test"],
            ("T1505.003", "CWE-94"): ["webshell_test", "file_upload_test"],
            ("T1068", "CWE-269"): ["priv_esc_test", "linpeas", "winpeas"],
            ("T1027", "CWE-1032"): ["waf_bypass", "encoding_test"],
            ("T1555", "CWE-256"): ["secret_scan", "trufflehog", "gitleaks"],
            ("T1083", "CWE-22"): ["dir_enum", "feroxbuster", "ffuf"],
            ("T1005", "CWE-200"): ["data_exfil_test", "api_enum"],
            ("T1071.001", "CWE-79"): ["ws_test", "sse_test"],
            ("T1041", "CWE-200"): ["exfil_test", "dns_exfil_test"],
            ("T1485", "CWE-367"): ["destructive_test"],  # Careful!
        }
        return tool_map.get((technique_id, cwe), ["active_fuzzer", "custom_probe"])

    def _risk_score(self, risk_level: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(risk_level, 2)

    def _assess_risk(self, cwe: str) -> str:
        critical_cwes = ["CWE-89", "CWE-94", "CWE-502", "CWE-78", "CWE-79"]
        high_cwes = ["CWE-22", "CWE-611", "CWE-502", "CWE-1321", "CWE-287", "CWE-269"]
        medium_cwes = ["CWE-79", "CWE-611", "CWE-200", "CWE-284"]

        if cwe in critical_cwes:
            return "critical"
        elif cwe in high_cwes:
            return "high"
        elif cwe in medium_cwes:
            return "medium"
        return "low"

    def _identify_entry_points(self, task: Dict) -> List[str]:
        """Identify likely entry points from tech stack"""
        entry_points = []
        tech = task.get("technologies", {})

        for host, tech_info in tech.items():
            if isinstance(tech_info, dict):
                if tech_info.get("cms") in ["wordpress", "drupal", "joomla", "magento"]:
                    entry_points.append(f"{host}/wp-admin")
                    entry_points.append(f"{host}/administrator")
                if tech_info.get("framework") in ["django", "flask", "rails", "laravel", "express"]:
                    entry_points.append(f"{host}/api")
                    entry_points.append(f"{host}/admin")
                if tech_info.get("language") in ["php", "aspnet", "java"]:
                    entry_points.append(f"{host}/upload")
                    entry_points.append(f"{host}/api")

        return list(set(entry_points))[:20]

    def _identify_high_value_targets(self, task: Dict) -> List[str]:
        """Identify high-value targets"""
        targets = []
        tech = task.get("technologies", {})

        for host, tech_info in tech.items():
            if isinstance(tech_info, dict):
                # Databases
                if tech_info.get("db") in ["mysql", "postgres", "mssql", "oracle", "mongodb", "redis"]:
                    targets.append(f"{host}:database")
                # Admin panels
                if tech_info.get("cms") or tech_info.get("framework") in ["django", "rails", "laravel"]:
                    targets.append(f"{host}:admin_panel")
                # APIs
                if "api" in str(tech_info).lower() or tech_info.get("framework") in ["express", "fastapi", "spring"]:
                    targets.append(f"{host}:api")

        return targets[:10]

    async def _share_attack_tree(self, tree: AttackTree):
        """Share attack tree with other agents"""
        await self.bus.publish(AgentMessage(
            from_agent=self.name,
            to_agent="all",
            message_type=MessageType.INTEL,
            payload={
                "type": "attack_tree",
                "tree": {
                    "target": tree.target,
                    "steps_count": len(tree.steps),
                    "tactics": list(set(s.tactic for s in tree.steps)),
                    "entry_points": tree.entry_points,
                    "high_value_targets": tree.high_value_targets,
                    "steps": [
                        {
                            "technique_id": s.technique_id,
                            "name": s.technique_name,
                            "tactic": s.tactic,
                            "cwe_ids": s.cwe_ids,
                            "tools": s.tools,
                            "confidence": s.confidence,
                            "risk": s.risk_level,
                            "expected_outcome": s.expected_outcome
                        }
                        for s in tree.steps
                    ]
                },
                "broadcast": True
            },
            priority=1
        ))

    async def _adapt_strategy(self, task: Dict) -> Dict:
        """Adapt strategy based on new findings"""
        findings = task.get("findings", [])
        current_tree = self.current_tree

        if not current_tree:
            return {"error": "No attack tree to adapt"}

        # Analyze findings for new attack vectors
        new_steps = self._derive_new_steps(findings)

        # Add to tree
        for step in new_steps:
            current_tree.steps.append(step)

        current_tree.updated_at = time.time()

        # Re-prioritize
        await self._share_attack_tree(self.current_tree)

        return {
            "status": "adapted",
            "new_steps_added": len(new_steps),
            "total_steps": len(self.current_tree.steps)
        }

    def _derive_new_steps(self, findings: List[Dict]) -> List[AttackStep]:
        """Derive new attack steps from findings"""
        new_steps = []

        for finding in findings:
            ftype = finding.get("type", "").lower()

            # Chain potential
            if ftype == "sqli" and "file_upload" in str(findings):
                new_steps.append(AttackStep(
                    technique_id="T1505.003",
                    technique_name="Web Shell via SQLi + File Upload",
                    tactic="persistence",
                    cwe_ids=["CWE-94", "CWE-434"],
                    tools=["webshell_test", "file_upload_test"],
                    expected_outcome="Achieve persistent RCE via SQLi + file upload chain",
                    confidence=0.8,
                    risk_level="critical"
                ))

            elif ftype == "xss" and "auth_bypass" in str(findings):
                new_steps.append(AttackStep(
                    technique_id="T1556",
                    technique_name="Session Hijacking via XSS",
                    tactic="credential-access",
                    cwe_ids=["CWE-79", "CWE-287"],
                    tools=["session_hijack_test", "xss_test"],
                    expected_outcome="Steal admin session via stored XSS",
                    confidence=0.75,
                    risk_level="high"
                ))

        return new_steps

    async def _prioritize_targets(self, task: Dict) -> Dict:
        """Prioritize targets based on attack tree"""
        if not self.current_tree:
            return {"error": "No attack tree available"}

        targets = task.get("targets", [])
        prioritized = []

        for target in targets:
            score = self._score_target(target)
            prioritized.append({"target": target, "score": score})

        prioritized.sort(key=lambda x: x["score"], reverse=True)

        return {
            "prioritized": prioritized[:10],
            "reasoning": "Scored by attack tree alignment, tech stack match, and finding potential"
        }

    def _score_target(self, target: str) -> float:
        """Score a target based on attack tree alignment"""
        if not self.current_tree:
            return 0.5

        score = 0.0
        target_lower = target.lower()

        for step in self.current_tree.steps:
            # Check if target matches entry points
            for ep in self.current_tree.entry_points:
                if ep.lower() in target_lower:
                    score += step.confidence * 0.5

            # Check if target hosts high-value services
            for hv in self.current_tree.high_value_targets:
                if hv.split(":")[0] in target_lower:
                    score += step.confidence * 0.3

        return min(score, 1.0)

    async def _assess_chain_potential(self, task: Dict) -> Dict:
        """Assess exploit chain potential"""
        findings = task.get("findings", [])

        chain_map = {
            ("sqli", "file_upload"): "sqli_to_rce",
            ("xss", "auth_bypass"): "xss_to_session_hijack",
            ("ssrf", "deserialization"): "ssrf_to_rce",
            ("auth_bypass", "file_upload"): "auth_bypass_to_rce",
            ("lfi", "log_poisoning"): "lfi_to_rce",
        }

        ftypes = {f.get("type", "").lower() for f in findings}
        chains = []

        for (a, b), chain_name in chain_map.items():
            if a in ftypes and b in ftypes:
                chains.append({
                    "chain": chain_name,
                    "components": [a, b],
                    "confidence": 0.85
                })

        return {
            "chains": chains,
            "total_potential": len(chains)
        }

    async def _recommend_next_step(self, task: Dict) -> Dict:
        """Recommend next action based on current state"""
        if not self.current_tree:
            return {"recommendation": "generate_attack_tree_first"}

        # Find unexecuted high-priority steps
        for step in self.current_tree.steps:
            step_key = f"{step.technique_id}:{step.cwe_ids[0] if step.cwe_ids else ''}"
            if step_key not in self.executed_steps and step_key not in self.failed_steps:
                return {
                    "recommendation": "execute_step",
                    "step": {
                        "technique_id": step.technique_id,
                        "name": step.technique_name,
                        "tactic": step.tactic,
                        "tools": step.tools,
                        "cwe_ids": step.cwe_ids,
                        "confidence": step.confidence
                    }
                }

        return {"recommendation": "all_steps_exhausted", "action": "verify_or_report"}

    # Message handling
    async def _handle_message(self, msg):
        pass

    async def process_intel(self, intel: Dict):
        intel_type = intel.get("type")
        if intel_type == "finding":
            # Trigger strategy adaptation
            await self._adapt_strategy({"type": "adapt_strategy", "findings": [intel]})
        elif intel_type == "attack_tree":
            logger.info(f"[{self.name}] Received attack tree update")

    async def _share_attack_tree(self, tree: AttackTree):
        await self.bus.publish(AgentMessage(
            from_agent=self.name,
            to_agent="all",
            message_type=MessageType.INTEL,
            payload={"type": "attack_tree_update", "tree_steps": len(tree.steps)},
            priority=2
        ))
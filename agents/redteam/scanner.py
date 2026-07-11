"""
agents/redteam/scanner.py — REDTEAM Scanner Agent (Prober)

The Scanner Agent performs active vulnerability scanning:
- Modular vulnerability probes
- WAF-aware payload delivery
- Rate-limited and stealthy scanning
- Finding classification and reporting
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .base import (
    AgentRole,
    MessageBus,
    MessageType,
    RedTeamAgent,
    AgentMessage,
    MissionContext,
)

logger = logging.getLogger("elengenix.redteam.scanner")


@dataclass
class ScanTask:
    """Individual scan task"""
    target: str
    vuln_type: str
    technique_id: str
    tools: List[str]
    priority: int = 3
    payload_variants: List[str] = field(default_factory=list)
    completed: bool = False
    findings: List[Dict] = field(default_factory=list)


@dataclass
class ScanResult:
    """Result of a scan task"""
    task: ScanTask
    success: bool
    findings: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0


class ScannerAgent:
    """Vulnerability Scanner Agent - Prober for the REDTEAM"""

    def __init__(self, message_bus: MessageBus):
        self.name = "scanner"
        self.role = AgentRole.SCANNER
        self.bus = message_bus
        self.state: Dict[str, Any] = {}
        self.metrics: Dict[str, float] = {}
        self._shutdown_event = asyncio.Event()

        self.bus.subscribe(self.name, self._handle_message)
        self.bus.subscribe("all", self._handle_message)

        # Scan state
        self.target = ""
        self.scope: List[str] = []
        self.attack_tree = None
        self.scan_queue: List[ScanTask] = []
        self.completed_scans: List[ScanTask] = []
        self.findings: List[Dict] = []
        self.rate_limiter = asyncio.Semaphore(5)  # Max 5 concurrent scans

        # WAF detection
        self.waf_detected = False
        self.waf_type = "unknown"
        self.blocked_payloads: Set[str] = set()

    async def initialize(self, mission_context: MissionContext):
        """Initialize with mission context"""
        self.target = mission_context.target
        self.scope = mission_context.scope
        self.state["mission_id"] = mission_context.mission_id
        logger.info(f"[SCANNER] Initialized for target: {self.target}")

    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a scanning task"""
        task_type = task.get("type", "unknown")

        if task_type == "scan_target":
            return await self._scan_target(task)
        elif task_type == "scan_vuln_type":
            return await self._scan_vuln_type(task)
        elif task_type == "waf_bypass":
            return await self._attempt_waf_bypass(task)
        elif task_type == "validate_finding":
            return await self._validate_finding(task)
        elif task_type == "chain_exploit":
            return await self._chain_exploit(task)
        else:
            return {"error": f"Unknown task type: {task_type}"}

    async def _scan_target(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a target for multiple vulnerability types"""
        target = task.get("target", self.target)
        vuln_types = task.get("vuln_types", ["sqli", "xss", "ssrf", "lfi", "rce", "idor"])
        technique_map = task.get("technique_map", {})

        logger.info(f"[{self.name}] Scanning target: {target} for {len(vuln_types)} vuln types")

        # Build scan queue
        self._build_scan_queue(target, vuln_types, technique_map)

        # Execute scans with rate limiting
        results = await self._execute_scan_queue()

        # Send findings to verifier
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)

        if all_findings:
            await self._submit_findings(all_findings)

        return {
            "status": "completed",
            "target": target,
            "scans_completed": len(results),
            "findings_count": len(all_findings),
            "findings": all_findings
        }

    def _build_scan_queue(self, target: str, vuln_types: List[str], technique_map: Dict):
        """Build prioritized scan queue from attack tree"""
        self.scan_queue = []

        for vuln_type in vuln_types:
            technique_id = technique_map.get(vuln_type, "T1190")
            tools = self._get_tools_for_vuln(vuln_type)

            # Generate payload variants
            payload_variants = self._generate_payload_variants(vuln_type)

            priority = self._calculate_priority(vuln_type)

            task = ScanTask(
                target=target,
                vuln_type=vuln_type,
                technique_id=technique_id,
                tools=tools,
                priority=priority,
                payload_variants=payload_variants
            )
            self.scan_queue.append(task)

        # Sort by priority
        self.scan_queue.sort(key=lambda t: t.priority)

    def _calculate_priority(self, vuln_type: str) -> int:
        """Calculate scan priority based on vuln type"""
        priority_map = {
            "rce": 1,
            "sqli": 2,
            "ssrf": 2,
            "lfi": 3,
            "rfi": 3,
            "xss": 3,
            "idor": 4,
            "ssti": 4,
            "xxe": 5,
            "proto_pollution": 5,
        }
        return priority_map.get(vuln_type, 5)

    def _get_tools_for_vuln(self, vuln_type: str) -> List[str]:
        """Map vuln type to Elengenix tools"""
        tool_map = {
            "sqli": ["active_fuzzer", "sqli_test", "sqlmap"],
            "xss": ["active_fuzzer", "xss_test", "dalfox"],
            "ssrf": ["active_fuzzer", "ssrf_test", "gopherus"],
            "lfi": ["active_fuzzer", "lfi_test", "path_traversal"],
            "rfi": ["active_fuzzer", "rfi_test"],
            "rce": ["active_fuzzer", "rce_test", "deser_test"],
            "idor": ["active_fuzzer", "bola_test"],
            "ssti": ["active_fuzzer", "ssti_test"],
            "xxe": ["active_fuzzer", "xxe_test"],
            "proto_pollution": ["proto_pollution_test"],
        }
        return tool_map.get(vuln_type, ["active_fuzzer"])

    def _generate_payload_variants(self, vuln_type: str) -> List[str]:
        """Generate payload variants for a vulnerability type"""
        base_payloads = {
            "sqli": ["'", "\"", "' OR '1'='1", "' UNION SELECT NULL--", "1; WAITFOR DELAY '0:0:5'--"],
            "xss": ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "javascript:alert(1)", "<img src=x onerror=alert(1)>"],
            "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://localhost:8080", "http://127.0.0.1:22", "file:///etc/passwd"],
            "lfi": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "/etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
            "rce": [";id", "`id`", "|id", "$(id)", "||id"],
            "idor": ["1", "2", "admin", "test", "user"],
            "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>"],
            "xxe": ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
            "proto_pollution": ['{"__proto__":{"polluted":"yes"}}', '{"constructor":{"prototype":{"polluted":"yes"}}}'],
        }

        payloads = base_payloads.get(vuln_type, ["test"])

        # Add encoding variants
        variants = []
        for p in payloads:
            variants.append(p)
            variants.append(p.replace(" ", "/**/"))  # Comment evasion
            variants.append(p.replace(" ", "%20"))  # URL encoding
            variants.append(p.replace("<", "%3C").replace(">", "%3E"))  # HTML encoding

        return variants

    async def _execute_scan_queue(self) -> List[ScanResult]:
        """Execute scan queue with rate limiting"""
        results = []

        async def scan_task(task: ScanTask) -> ScanResult:
            async with self.rate_limiter:
                start = time.time()
                findings = []

                for payload in task.payload_variants[:10]:  # Limit variants per task
                    if self._shutdown_event.is_set():
                        break

                    # Check if payload was blocked by WAF
                    if payload in self.blocked_payloads:
                        continue

                    # Execute each tool for this payload
                    for tool in task.tools:
                        try:
                            finding = await self._execute_tool(tool, task.target, payload, task.vuln_type)
                            if finding:
                                findings.append(finding)
                        except Exception as e:
                            logger.debug(f"[{self.name}] Tool {tool} failed: {e}")

                return ScanResult(
                    task=task,
                    success=len(findings) > 0,
                    findings=findings,
                    duration=time.time() - start
                )

        # Execute in parallel with semaphore
        tasks = [scan_task(t) for t in self.scan_queue[:50]]  # Limit queue
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results = [r for r in results if isinstance(r, ScanResult)]
        self.completed_scans.extend(valid_results)

        return valid_results

    async def _execute_tool(self, tool: str, target: str, payload: str, vuln_type: str) -> Optional[Dict]:
        """Execute a specific tool with a payload"""
        # This would integrate with Elengenix's tool registry
        # For now, return mock finding structure
        return None

    def _check_waf_response(self, response: Any) -> bool:
        """Check if response indicates WAF block"""
        if hasattr(response, 'status_code'):
            if response.status_code in [403, 406, 501, 999]:
                return True
        if hasattr(response, 'text'):
            waf_signatures = ["blocked", "firewall", "waf", "cloudflare", "akamai", "imperva", "mod_security"]
            text = str(response.text).lower()
            if any(sig in text for sig in waf_signatures):
                return True
        return False

    async def _attempt_waf_bypass(self, task: Dict) -> Dict:
        """Attempt WAF bypass with encoding/fragmentation"""
        payload = task.get("payload", "")
        waf_type = task.get("waf_type", "unknown")

        bypasses = []

        if waf_type.lower() in ["cloudflare", "akamai"]:
            bypasses = [
                payload.replace(" ", "/**/"),
                payload.replace(" ", "%20"),
                payload.replace("<", "%3C").replace(">", "%3E"),
                payload.replace("'", "%27"),
            ]
        elif "modsecurity" in waf_type.lower():
            bypasses = [
                payload.replace(" ", "\t"),
                payload.replace("UNION", "UN/**/ION"),
                payload.replace("SELECT", "SEL/**/ECT"),
            ]
        else:
            bypasses = [
                payload.replace(" ", "%20"),
                payload.replace(" ", "%09"),
                payload.replace("=", "%3D"),
            ]

        for bypass in bypasses:
            if bypass not in self.blocked_payloads:
                bypasses.append(bypass)

        return {"bypasses": bypasses, "waf_type": waf_type}

    async def _validate_finding(self, task: Dict) -> Dict:
        """Validate a potential finding"""
        finding = task.get("finding", {})
        # Would call verification engine
        return {"validated": True, "confidence": 0.8}

    async def _chain_exploit(self, task: Dict) -> Dict:
        """Attempt exploit chaining"""
        findings = task.get("findings", [])
        return {"chained": False, "reason": "no_chainable_findings"}

    async def _handle_message(self, msg):
        """Handle incoming messages"""
        pass

    async def process_intel(self, intel: Dict):
        """Process intelligence from other agents"""
        intel_type = intel.get("type", "unknown")

        if intel_type == "attack_tree":
            # Update scan priorities based on attack tree
            pass
        elif intel_type == "waf_detected":
            self.waf_detected = True
            self.waf_type = intel.get("waf_type", "unknown")
            logger.info(f"[{self.name}] WAF detected: {self.waf_type}")
        elif intel_type == "tech_stack":
            # Update tool selection
            pass
        elif intel_type == "finding":
            # Add to validation queue
            pass

    async def _submit_findings(self, findings: List[Dict]):
        """Submit findings to verifier"""
        await self.bus.publish(AgentMessage(
            from_agent=self.name,
            to_agent="verifier",
            message_type=MessageType.TASK,
            payload={
                "type": "verify_findings",
                "findings": findings
            },
            priority=2
        ))

        # Also share as intel
        await self.bus.publish(AgentMessage(
            from_agent=self.name,
            to_agent="all",
            message_type=MessageType.INTEL,
            payload={
                "type": "findings",
                "count": len(findings),
                "severity_distribution": self._get_severity_dist(findings)
            },
            priority=2
        ))

    def _get_severity_dist(self, findings: List[Dict]) -> Dict[str, int]:
        """Get severity distribution of findings"""
        dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in dist:
                dist[sev] += 1
        return dist
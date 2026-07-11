"""
agents/redteam/recon.py — REDTEAM Recon Agent (Scout)

The Recon Agent performs reconnaissance:
- Passive OSINT (DNS, SSL certs, search engines, threat intel)
- Active enumeration (subdomains, directories, tech fingerprinting)
- Asset inventory and attack surface mapping
- Threat intelligence correlation
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from agents.redteam.base import (
    AgentRole,
    MessageBus,
    MessageType,
    RedTeamAgent,
    AgentMessage,
    MissionContext,
)

logger = logging.getLogger("elengenix.redteam.recon")


@dataclass
class ReconResult:
    """Results from reconnaissance"""
    subdomains: List[str] = field(default_factory=list)
    technologies: Dict[str, Any] = field(default_factory=dict)
    open_ports: Dict[int, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    threat_intel: Dict[str, Any] = field(default_factory=dict)
    assets: List[Dict[str, Any]] = field(default_factory=list)
    attack_surface: Dict[str, Any] = field(default_factory=dict)


class ReconAgent:
    """Reconnaissance Agent - Scout for the REDTEAM"""

    def __init__(self, message_bus: MessageBus):
        self.name = "recon"
        self.role = AgentRole.RECON
        self.bus = message_bus
        self.state: Dict[str, Any] = {}
        self.metrics: Dict[str, float] = {}
        self._shutdown_event = asyncio.Event()

        # Subscribe to messages
        self.bus.subscribe(self.name, self._handle_message)
        self.bus.subscribe("all", self._handle_message)

        # Recon state
        self.target = ""
        self.scope: List[str] = []
        self.results = ReconResult()
        self.discovered_urls: Set[str] = set()
        self.fingerprinted_hosts: Dict[str, Dict] = {}

    async def initialize(self, mission_context: MissionContext):
        """Initialize with mission context"""
        self.target = mission_context.target
        self.scope = mission_context.scope
        self.state["mission_id"] = mission_context.mission_id
        logger.info(f"[RECON] Initialized for target: {self.target}")

    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a recon task"""
        task_type = task.get("type", "unknown")

        if task_type == "passive_recon":
            return await self._passive_recon()
        elif task_type == "subdomain_enum":
            return await self._subdomain_enum()
        elif task_type == "tech_fingerprint":
            return await self._tech_fingerprint(task.get("urls", []))
        elif task_type == "port_scan":
            return await self._port_scan(task.get("hosts", []))
        elif task_type == "dns_enum":
            return await self._dns_enum()
        elif task_type == "threat_intel":
            return await self._threat_intel()
        elif task_type == "ssl_analysis":
            return await self._ssl_analysis()
        elif task_type == "full_recon":
            return await self._full_recon()
        else:
            return {"error": f"Unknown task type: {task_type}"}

    # ==================== Passive Recon ====================

    async def _passive_recon(self) -> Dict[str, Any]:
        """Passive OSINT - no direct target interaction"""
        logger.info(f"[{self.name}] Starting passive reconnaissance")

        tasks = [
            self._dns_recon(),
            self._ssl_cert_analysis(),
            self._search_engine_recon(),
            self._threat_intel_lookup(),
            self._whois_lookup(),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        for result in results:
            if isinstance(result, dict):
                self._merge_results(result)

        return {"status": "completed", "results": self.results.__dict__}

    async def _dns_recon(self) -> Dict[str, Any]:
        """DNS reconnaissance"""
        logger.debug(f"[{self.name}] DNS reconnaissance")
        # DNS records, zone transfer attempts, etc.
        return {"dns_records": self.results.dns_records}

    async def _ssl_cert_analysis(self) -> Dict[str, Any]:
        """Analyze SSL certificates for subdomains/hosts"""
        logger.debug(f"[{self.name}] SSL certificate analysis")
        try:
            hostname = urlparse(self.target).hostname or self.target
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    self.results.ssl_info = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "serial_number": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "san": [x[1] for x in cert.get("subjectAltName", [])],
                    }
        except Exception as e:
            logger.debug(f"SSL analysis failed: {e}")
        return {"ssl_info": self.results.ssl_info}

    async def _search_engine_recon(self) -> Dict[str, Any]:
        """Search engine reconnaissance (Google, Bing, DuckDuckGo dorks)"""
        logger.debug(f"[{self.name}] Search engine reconnaissance")
        # Use dorks to find interesting pages
        return {}

    async def _threat_intel_lookup(self) -> Dict[str, Any]:
        """Threat intelligence lookup"""
        logger.debug(f"[{self.name}] Threat intelligence lookup")
        # Check known threat feeds, VT, AlienVault, etc.
        return {}

    async def _whois_lookup(self) -> Dict[str, Any]:
        """WHOIS lookup for target domain"""
        logger.debug(f"[{self.name}] WHOIS lookup")
        return {}

    # ==================== Active Recon ====================

    async def _subdomain_enum(self) -> Dict[str, Any]:
        """Subdomain enumeration using multiple sources"""
        logger.info(f"[{self.name}] Subdomain enumeration")

        sources = [
            self._crt_sh_enum(),
            self._dns_bruteforce(),
            self._search_engine_subdomains(),
            self._dns_zone_transfer(),
        ]

        results = await asyncio.gather(*sources, return_exceptions=True)

        all_subdomains = set()
        for result in results:
            if isinstance(result, set):
                all_subdomains.update(result)

        self.results.subdomains = list(all_subdomains)
        logger.info(f"[{self.name}] Found {len(all_subdomains)} subdomains")

        # Fingerprint each subdomain
        if all_subdomains:
            await self._fingerprint_hosts(list(all_subdomains)[:50])  # Limit for speed

        return {"subdomains": self.results.subdomains}

    async def _crt_sh_enum(self) -> Set[str]:
        """Certificate Transparency log enumeration via crt.sh"""
        # Implementation would query crt.sh API
        return set()

    async def _dns_bruteforce(self) -> Set[str]:
        """DNS brute force with common wordlists"""
        # Use common subdomain wordlists
        return set()

    async def _search_engine_subdomains(self) -> Set[str]:
        """Search engine subdomain discovery"""
        return set()

    async def _dns_zone_transfer(self) -> Set[str]:
        """Attempt DNS zone transfer"""
        return set()

    async def _fingerprint_hosts(self, hosts: List[str]):
        """Technology fingerprinting for discovered hosts"""
        logger.info(f"[{self.name}] Fingerprinting {len(hosts)} hosts")

        semaphore = asyncio.Semaphore(10)  # Limit concurrency

        async def fingerprint(host):
            async with semaphore:
                tech = await self._fingerprint_single(host)
                if tech:
                    self.fingerprinted_hosts[host] = tech
                    self.results.technologies[host] = tech

        await asyncio.gather(*[fingerprint(h) for h in hosts], return_exceptions=True)

    async def _fingerprint_single(self, host: str) -> Optional[Dict]:
        """Fingerprint a single host"""
        try:
            # HTTP headers, body analysis, etc.
            return {"server": "unknown", "framework": "unknown", "cms": "unknown"}
        except Exception:
            return None

    async def _tech_fingerprint(self, urls: List[str]) -> Dict[str, Any]:
        """Technology fingerprinting for specific URLs"""
        logger.info(f"[{self.name}] Technology fingerprinting for {len(urls)} URLs")
        return {}

    async def _port_scan(self, hosts: List[str]) -> Dict[str, Any]:
        """Port scanning for discovered hosts"""
        logger.info(f"[{self.name}] Port scanning {len(hosts)} hosts")

        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

        open_ports = {}
        for host in hosts[:20]:  # Limit for speed
            for port in common_ports:
                if await self._check_port(host, port):
                    open_ports[port] = open_ports.get(port, []) + [host]

        self.results.open_ports = open_ports
        return {"open_ports": open_ports}

    async def _check_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a port is open"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    # ==================== Full Recon Pipeline ====================

    async def _full_recon(self) -> Dict[str, Any]:
        """Complete reconnaissance pipeline"""
        logger.info(f"[{self.name}] Starting full reconnaissance pipeline")

        pipeline = [
            ("passive_recon", self._passive_recon),
            ("subdomain_enum", self._subdomain_enum),
            ("port_scan", lambda: self._port_scan(self.results.subdomains[:20])),
            ("tech_fingerprint", lambda: self._tech_fingerprint([f"https://{h}" for h in self.results.subdomains[:20]])),
            ("dns_enum", self._dns_enum),
            ("ssl_analysis", self._ssl_analysis),
            ("threat_intel", self._threat_intel_lookup),
        ]

        for name, func in pipeline:
            logger.info(f"[{self.name}] Running {name}")
            try:
                await func()
            except Exception as e:
                logger.error(f"[{self.name}] {name} failed: {e}")

        # Send intel to other agents
        await self._share_intel()

        return {"status": "completed", "results": self.results.__dict__}

    async def _share_intel(self):
        """Share discovered intelligence with other agents"""
        intel = {
            "type": "recon_complete",
            "target": self.target,
            "subdomains": self.results.subdomains,
            "technologies": self.results.technologies,
            "open_ports": self.results.open_ports,
            "fingerprinted_hosts": self.fingerprinted_hosts,
            "attack_surface": self._calculate_attack_surface(),
            "broadcast": True
        }
        await self.bus.publish(AgentMessage(
            from_agent=self.name,
            to_agent="all",
            message_type=MessageType.INTEL,
            payload=intel,
            priority=1
        ))

    def _calculate_attack_surface(self) -> Dict[str, Any]:
        """Calculate and categorize attack surface"""
        return {
            "web_apps": len([h for h in self.fingerprinted_hosts if "web" in str(self.fingerprinted_hosts[h])]),
            "api_endpoints": 0,
            "databases_exposed": len([p for p in self.results.open_ports if p in [3306, 5432, 27017, 1433]]),
            "admin_panels": 0,
            "file_uploads": 0,
            "auth_mechanisms": [],
            "interesting_findings": []
        }

    def _merge_results(self, new_results: Dict[str, Any]):
        """Merge new results into existing"""
        for key, value in new_results.items():
            if hasattr(self.results, key) and isinstance(value, dict):
                getattr(self.results, key).update(value)
            elif hasattr(self.results, key) and isinstance(value, list):
                getattr(self.results, key).extend(value)

    async def _handle_message(self, msg):
        """Handle incoming messages"""
        pass

    async def process_intel(self, intel: Dict[str, Any]):
        """Process intelligence from other agents"""
        intel_type = intel.get("type", "unknown")
        logger.debug(f"[{self.name}] Received intel: {intel_type}")

    # Placeholder implementations
    async def _dns_enum(self) -> Dict[str, Any]:
        return {}

    async def _ssl_analysis(self) -> Dict[str, Any]:
        return {}
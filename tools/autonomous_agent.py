"""tools/autonomous_agent.py

Elengenix Autonomous Agent v3.0 — True Agentic Loop.

Instead of a fixed pipeline, the AI decides what to do next at each
iteration based on what it has discovered so far:

  loop:
    1. Build context (findings, assets, history)
    2. Ask AI: what is the NEXT best action?
    3. Execute that action
    4. Update state
    5. If action == "done" or max iterations → stop

Available actions the AI can choose:
  - recon        : Subdomain/DNS/HTTP fingerprinting
  - http_probe   : Deep probe a specific URL/domain
  - waf_detect   : WAF detection on a URL
  - bola_probe   : Unauthenticated BOLA/IDOR surface check
  - endpoint_fuzz: Common endpoint wordlist discovery
  - header_audit : Security header analysis
  - analyze      : AI deep-analysis of current findings
  - done         : Finished — generate report
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    from tools.user_memory import save_target_learning, get_target_summary
except Exception:
    save_target_learning = None
    get_target_summary = None

logger = logging.getLogger("elengenix.autonomous")


# ──────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────

@dataclass
class AgentAction:
    name: str
    target: str
    params: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""


@dataclass
class AgentState:
    root_target: str
    goal: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    assets: Dict[str, Any] = field(default_factory=dict)   # subdomains, endpoints, tech
    action_history: List[str] = field(default_factory=list)
    iteration: int = 0


@dataclass
class ScanResult:
    target: str
    start_time: datetime
    end_time: Optional[datetime]
    findings: List[Dict[str, Any]]
    bounty_predictions: List[Dict[str, Any]]
    tools_created: List[str]
    ai_decisions: List[AgentAction]
    report_path: Optional[Path]
    success: bool
    summary: str


# ──────────────────────────────────────────────────────────
# AutonomousDecision (kept for backward compat)
# ──────────────────────────────────────────────────────────

@dataclass
class AutonomousDecision:
    decision_type: str
    reasoning: str
    action_plan: Dict[str, Any]
    expected_outcome: str
    risk_level: str
    auto_approved: bool = False


# ──────────────────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────────────────

def _to_domain(target: str) -> str:
    """Strip URL to bare hostname."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.netloc or parsed.path
    return host.split(":")[0].strip("/")


def _ai_call(ai_client, system: str, user: str, temperature: float = 0.3) -> str:
    """Wrapper around AIClientManager.chat()."""
    try:
        from tools.universal_ai_client import AIMessage
        messages = [
            AIMessage(role="system", content=system),
            AIMessage(role="user", content=user),
        ]
        response = ai_client.chat(messages, temperature=temperature)
        return response.content
    except Exception as e:
        logger.warning(f"AI call failed: {e}")
        return ""


def _parse_json(text: str) -> dict:
    """Extract JSON from markdown code fences or raw."""
    for fence in ["```json", "```"]:
        if fence in text:
            try:
                return json.loads(text.split(fence)[1].split("```")[0].strip())
            except Exception:
                pass
    try:
        # find first { ... }
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            return json.loads(m.group())
    except Exception:
        pass
    return {}


def _build_headers(state: AgentState, extra: dict = None) -> dict:
    """Build HTTP headers with auth credentials if available."""
    h = {"User-Agent": "Mozilla/5.0 (Elengenix/3.0)"}
    auth = state.assets.get("auth_headers", {})
    if auth:
        h.update(auth)
    if extra:
        h.update(extra)
    return h


# ──────────────────────────────────────────────────────────
# Action executors
# ──────────────────────────────────────────────────────────

def _exec_recon(action: AgentAction, state: AgentState) -> List[Dict]:
    """Run SmartReconEngine on a domain."""
    findings = []
    try:
        from tools.smart_recon import SmartReconEngine
        domain = _to_domain(action.target)
        engine = SmartReconEngine(target_domain=domain)
        result = engine.run_full_recon()

        # Store discovered assets
        for node in result.nodes:
            t = node.asset_type
            if t not in state.assets:
                state.assets[t] = []
            if node.value not in state.assets[t]:
                state.assets[t].append(node.value)

        for f in result.findings:
            findings.append({
                "type": f.get("type", "info"),
                "severity": f.get("severity", "info"),
                "title": f.get("title", "Recon Finding"),
                "target": f.get("target", domain),
                "description": f.get("description", ""),
                "source": "recon",
            })

        print(f"  [recon] {result.stats.get('domains',0)} domains, "
              f"{result.stats.get('endpoints',0)} endpoints, "
              f"{len(result.findings)} findings")
    except Exception as e:
        logger.warning(f"Recon error: {e}")
        print(f"  [recon] error: {e}")
    return findings


def _exec_http_probe(action: AgentAction, state: AgentState) -> List[Dict]:
    """Probe a URL for headers, status, tech stack."""
    import requests
    findings = []
    url = action.target
    if "://" not in url:
        url = f"https://{url}"
    try:
        r = requests.get(url, timeout=15, allow_redirects=True,
                         headers=_build_headers(state),
                         verify=False)
        headers = dict(r.headers)

        # Security header audit
        missing = []
        for h in ["Strict-Transport-Security", "X-Frame-Options",
                  "Content-Security-Policy", "X-Content-Type-Options",
                  "Referrer-Policy"]:
            if h.lower() not in {k.lower() for k in headers}:
                missing.append(h)

        if missing:
            findings.append({
                "type": "missing_security_headers",
                "severity": "low",
                "title": f"Missing security headers on {url}",
                "target": url,
                "description": f"Missing: {', '.join(missing)}",
                "source": "http_probe",
            })

        # Server fingerprint
        server = headers.get("Server", "") or headers.get("X-Powered-By", "")
        if server:
            findings.append({
                "type": "server_fingerprint",
                "severity": "info",
                "title": f"Server: {server}",
                "target": url,
                "description": f"Server header reveals: {server}",
                "source": "http_probe",
            })

        # Store endpoint
        state.assets.setdefault("live_endpoints", [])
        if url not in state.assets["live_endpoints"]:
            state.assets["live_endpoints"].append(url)

        print(f"  [http_probe] {url} → {r.status_code}, {len(missing)} missing headers")
    except Exception as e:
        logger.warning(f"HTTP probe error: {e}")
        print(f"  [http_probe] error: {e}")
    return findings


def _exec_waf_detect(action: AgentAction, state: AgentState) -> List[Dict]:
    """Basic WAF detection via response analysis."""
    import requests
    findings = []
    url = action.target
    if "://" not in url:
        url = f"https://{url}"

    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cloudflare"],
        "AWS WAF":    ["x-amzn-requestid", "awselb"],
        "Akamai":     ["akamaighost", "x-akamai"],
        "Sucuri":     ["x-sucuri-id", "sucuri"],
        "Imperva":    ["x-iinfo", "incapsula"],
    }

    try:
        # Probe with benign + suspicious payload
        r_clean = requests.get(url, timeout=10, verify=False,
                               headers=_build_headers(state))
        r_attack = requests.get(
            url + "?q=<script>alert(1)</script>&id=1 OR 1=1--",
            timeout=10, verify=False,
            headers=_build_headers(state, {"User-Agent": "sqlmap/1.0"}),
        )

        header_str = " ".join(
            f"{k}:{v}" for k, v in r_clean.headers.items()
        ).lower()

        waf_found = None
        for waf_name, sigs in WAF_SIGNATURES.items():
            if any(s in header_str for s in sigs):
                waf_found = waf_name
                break

        blocked = r_attack.status_code in (403, 406, 429, 503)

        if waf_found:
            findings.append({
                "type": "waf_detected",
                "severity": "info",
                "title": f"WAF Detected: {waf_found}",
                "target": url,
                "description": f"{waf_found} WAF detected. Attack probe blocked={blocked}",
                "source": "waf_detect",
            })
        elif not blocked:
            findings.append({
                "type": "no_waf",
                "severity": "medium",
                "title": "No WAF detected — attack probe not blocked",
                "target": url,
                "description": "Malicious payload not filtered. May lack WAF protection.",
                "source": "waf_detect",
            })

        print(f"  [waf_detect] {url} → WAF={waf_found}, blocked={blocked}")
    except Exception as e:
        logger.warning(f"WAF detect error: {e}")
        print(f"  [waf_detect] error: {e}")
    return findings


def _exec_endpoint_fuzz(action: AgentAction, state: AgentState, ai_client=None) -> List[Dict]:
    """Discover common endpoints via smart wordlist with AI augmentation."""
    import requests
    findings = []
    base = action.target.rstrip("/")
    if "://" not in base:
        base = f"https://{base}"

    # Use smart wordlist manager
    from tools.wordlist_manager import WordlistManager, WordlistConfig
    
    wm = WordlistManager()
    config = WordlistConfig(
        category=action.params.get("wordlist_category", "default"),
        custom_paths=action.params.get("custom_paths", []),
        tech_stack=state.assets.get("tech_stack", []),
        max_paths=action.params.get("max_paths", 100),
        enable_ai_generation=action.params.get("enable_ai", True),
        ai_budget=action.params.get("ai_budget", 5),
        prioritize_bounty=action.params.get("prioritize_bounty", True),
    )
    
    wordlist = wm.get_smart_wordlist(config, state, ai_client)
    
    if not wordlist:
        logger.warning("No wordlist generated, using fallback")
        wordlist = ["/api", "/admin", "/login", "/.env", "/config"]
    
    print(f"  [endpoint_fuzz] Loaded {len(wordlist)} paths (AI calls: {wm.ai_calls_made})")

    interesting = []
    for path in wordlist:
        try:
            r = requests.get(
                base + path, timeout=8, allow_redirects=False,
                headers=_build_headers(state),
                verify=False,
            )
            if r.status_code in (200, 201, 301, 302, 401, 403):
                interesting.append((path, r.status_code, len(r.content)))
                time.sleep(0.3)
        except Exception:
            pass

    for path, status, size in interesting:
        sev = "info"
        if any(x in path for x in ["admin", ".env", "backup", "actuator", "debug"]):
            sev = "medium" if status in (200, 201) else "low"
        findings.append({
            "type": "endpoint_found",
            "severity": sev,
            "title": f"Endpoint: {path} [{status}]",
            "target": base + path,
            "description": f"Status {status}, size {size} bytes",
            "source": "endpoint_fuzz",
        })
        state.assets.setdefault("discovered_paths", [])
        if path not in state.assets["discovered_paths"]:
            state.assets["discovered_paths"].append(path)

    print(f"  [endpoint_fuzz] {base} → {len(interesting)}/{len(wordlist)} paths found")
    return findings


def _exec_bola_probe(action: AgentAction, state: AgentState) -> List[Dict]:
    """Unauthenticated BOLA surface probe — check common object endpoints."""
    import requests
    findings = []
    base = action.target.rstrip("/")
    if "://" not in base:
        base = f"https://{base}"

    object_paths = [
        "/api/users/1", "/api/users/2",
        "/api/orders/1", "/api/orders/2",
        "/api/accounts/1", "/api/accounts/2",
        "/api/v1/users/1", "/api/v1/orders/1",
    ]

    for path in object_paths:
        try:
            r = requests.get(
                base + path, timeout=8, allow_redirects=False,
                headers=_build_headers(state),
                verify=False,
            )
            if r.status_code == 200 and len(r.content) > 20:
                findings.append({
                    "type": "bola_surface",
                    "severity": "medium",
                    "title": f"Object endpoint accessible without auth: {path}",
                    "target": base + path,
                    "description": (
                        f"Returned HTTP 200 with {len(r.content)} bytes unauthenticated. "
                        "Likely BOLA/IDOR surface — requires authenticated differential test."
                    ),
                    "source": "bola_probe",
                })
            time.sleep(0.25)
        except Exception:
            pass

    print(f"  [bola_probe] {base} → {len(findings)} potential surfaces")
    return findings


def _exec_header_audit(action: AgentAction, state: AgentState) -> List[Dict]:
    """Full security header + CORS audit."""
    import requests
    findings = []
    url = action.target
    if "://" not in url:
        url = f"https://{url}"

    try:
        r = requests.options(
            url, timeout=10, verify=False,
            headers=_build_headers(state, {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "GET",
            }),
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "false")

        if acao == "*":
            findings.append({
                "type": "cors_wildcard",
                "severity": "medium",
                "title": "CORS wildcard origin allowed",
                "target": url,
                "description": "Access-Control-Allow-Origin: * — any origin can read responses.",
                "source": "header_audit",
            })
        elif acao == "https://evil.com":
            sev = "high" if acac.lower() == "true" else "medium"
            findings.append({
                "type": "cors_reflection",
                "severity": sev,
                "title": "CORS reflects arbitrary origin" + (" with credentials" if sev == "high" else ""),
                "target": url,
                "description": f"Origin reflected back: {acao}, credentials={acac}",
                "source": "header_audit",
            })

        print(f"  [header_audit] {url} → ACAO={acao or 'none'}, creds={acac}")
    except Exception as e:
        logger.warning(f"Header audit error: {e}")
        print(f"  [header_audit] error: {e}")
    return findings


def _exec_osint_research(action: AgentAction, state: AgentState) -> List[Dict]:
    """Gather external OSINT about the target using Tavily."""
    from tools.research_tool import research_target
    findings = []
    target = action.target
    print(f"  [osint] researching: {target}")
    
    results = research_target(target, num_results=3, summarize=True)
    for res in results:
        if res.get("text"):
            findings.append({
                "title": f"OSINT: {res.get('url')}",
                "description": res.get("text")[:500] + "...",
                "severity": "info",
                "source": "osint",
                "url": res.get("url")
            })
    return findings


def _exec_vuln_intel(action: AgentAction, state: AgentState) -> List[Dict]:
    """Gather vulnerability and exploit intelligence using VulnCheck."""
    from tools.vulncheck_tool import get_target_intel
    findings = []
    target = action.target
    print(f"  [vuln_intel] checking intelligence for: {target}")
    
    intel = get_target_intel(target)
    for exp in intel.get("exploits", []):
        findings.append({
            "title": f"Known Exploit: {exp.get('cve', 'N/A')}",
            "description": f"Found known exploit in VulnCheck: {exp.get('description', 'No description')}",
            "severity": "high",
            "source": "vuln_intel",
            "cve": exp.get("cve")
        })
    return findings


def _exec_wayback_recon(action: AgentAction, state: AgentState) -> List[Dict]:
    """Fetch historical URLs from Wayback Machine & OTX."""
    from tools.wayback_tool import gather_historical_intel
    from urllib.parse import urlparse

    findings = []
    target = action.target
    # Extract domain from URL if needed
    if "://" in target:
        target = urlparse(target).hostname or target
    target = target.replace("www.", "")

    intel = gather_historical_intel(target)

    # Store discovered paths and params in state for later use
    state.assets.setdefault("wayback_paths", [])
    state.assets["wayback_paths"].extend(intel.get("unique_paths", []))
    state.assets.setdefault("wayback_params", [])
    state.assets["wayback_params"].extend(intel.get("unique_params", []))

    # High-interest URLs become findings
    for url in intel.get("high_interest", [])[:15]:
        findings.append({
            "title": f"Archived endpoint: {url}",
            "description": f"High-interest historical URL found via Wayback/OTX.",
            "severity": "info",
            "source": "wayback",
            "url": url,
            "target": target,
        })

    # Summary finding
    if intel["total_urls"] > 0:
        findings.append({
            "title": f"Wayback Intelligence Summary for {target}",
            "description": (
                f"Total archived URLs: {intel['total_urls']} "
                f"(high: {len(intel['high_interest'])}, "
                f"medium: {len(intel['medium_interest'])})\n"
                f"Unique paths: {len(intel['unique_paths'])}\n"
                f"Unique params: {', '.join(intel['unique_params'][:20])}"
            ),
            "severity": "info",
            "source": "wayback",
            "target": target,
        })

    print(f"  [wayback_recon] {intel['total_urls']} archived URLs, "
          f"{len(intel['high_interest'])} high-interest")
    return findings


def _exec_github_dork(action: AgentAction, state: AgentState) -> List[Dict]:
    """Hunt for leaked credentials and code on GitHub."""
    from tools.github_intel import hunt_leaks
    from urllib.parse import urlparse

    findings = []
    target = action.target
    if "://" in target:
        target = urlparse(target).hostname or target
    target = target.replace("www.", "")

    intel = hunt_leaks(target)

    for leak in intel.get("findings", []):
        sev = "info"
        cat = leak.get("category", "")
        if cat in ("credentials", "aws_keys", "private_keys"):
            sev = "critical"
        elif cat in ("env_files", "internal_ips", "org_secrets"):
            sev = "high"
        elif cat in ("config_files", "docker", "api_endpoints"):
            sev = "medium"

        findings.append({
            "title": f"GitHub Leak ({cat}): {leak['file']}",
            "description": (
                f"Found in repo: {leak['repo']}\n"
                f"Path: {leak['path']}\n"
                f"URL: {leak['url']}"
            ),
            "severity": sev,
            "source": "github_dork",
            "url": leak["url"],
            "target": target,
        })

    print(f"  [github_dork] {intel['total_findings']} leaks found "
          f"(critical: {intel['critical_count']}, high: {intel['high_count']})")
    return findings


def _exec_threat_model(action: AgentAction, state: AgentState,
                       ai_client=None) -> List[Dict]:
    """AI generates a strategic attack plan based on all gathered intel."""
    findings = []

    # Build context from everything gathered so far
    context = json.dumps({
        "target": state.root_target,
        "goal": state.goal,
        "iteration": state.iteration,
        "total_findings": len(state.findings),
        "findings_by_severity": {
            sev: len([f for f in state.findings if f.get("severity") == sev])
            for sev in ["critical", "high", "medium", "low", "info"]
        },
        "assets": {
            k: (v[:10] if isinstance(v, list) else v)
            for k, v in state.assets.items()
        },
        "actions_taken": state.action_history,
        "recent_findings": [
            {"title": f.get("title"), "severity": f.get("severity"),
             "source": f.get("source")}
            for f in state.findings[-30:]
        ],
    }, indent=2)

    if ai_client:
        content = _ai_call(
            ai_client,
            system=(
                "You are an expert penetration tester creating a strategic attack plan. "
                "Analyze all gathered intelligence and produce an actionable plan. "
                "Focus on the most promising attack vectors with highest bounty potential."
            ),
            user=f"""Based on this intelligence, create a threat model and attack plan:

{context}

Return JSON:
{{
  "attack_plan": [
    {{"priority": 1, "target": "url/endpoint", "attack_type": "type", "reasoning": "why"}},
    ...
  ],
  "key_weaknesses": ["weakness1", "weakness2"],
  "recommended_tools": ["tool1", "tool2"],
  "risk_assessment": "overall assessment"
}}""",
            temperature=0.2,
        )

        data = _parse_json(content)
        plan = data.get("attack_plan", [])
        weaknesses = data.get("key_weaknesses", [])
        assessment = data.get("risk_assessment", "")

        # Store plan in state
        state.assets["attack_plan"] = plan
        state.assets["key_weaknesses"] = weaknesses

        # Add pivot targets from attack plan
        for step in plan:
            t = step.get("target", "")
            if t:
                state.assets.setdefault("ai_pivots", [])
                if t not in state.assets["ai_pivots"]:
                    state.assets["ai_pivots"].append(t)

        findings.append({
            "title": f"Threat Model for {state.root_target}",
            "description": (
                f"Attack plan ({len(plan)} steps):\n"
                + "\n".join(
                    f"  {s.get('priority', '?')}. [{s.get('attack_type')}] {s.get('target')} — {s.get('reasoning')}"
                    for s in plan[:8]
                )
                + f"\n\nKey weaknesses: {', '.join(weaknesses[:5])}"
                + f"\nRisk: {assessment}"
            ),
            "severity": "info",
            "source": "threat_model",
            "target": state.root_target,
        })

        print(f"  [threat_model] Generated {len(plan)}-step attack plan")
        if weaknesses:
            print(f"  [threat_model] Key weaknesses: {', '.join(weaknesses[:3])}")
    else:
        print("  [threat_model] Skipped (no AI client)")

    return findings


def _exec_js_recon(action: AgentAction, state: AgentState) -> List[Dict]:
    """Analyze JavaScript files for secrets, API keys, and hidden endpoints."""
    from tools.js_analyzer import analyze_js
    findings = []
    target = action.target
    print(f"  [js_recon] Analyzing JS files for: {target}")

    # Collect JS URLs from state assets or try common paths
    js_urls = state.assets.get("js_files", [])
    if not js_urls:
        # Try common JS paths
        base = target.rstrip("/")
        common_js = [
            f"{base}/main.js", f"{base}/app.js", f"{base}/bundle.js",
            f"{base}/vendor.js", f"{base}/chunk.js",
            f"{base}/static/js/main.js", f"{base}/assets/js/app.js",
            f"{base}/dist/bundle.js",
        ]
        js_urls = common_js

    analyzed_count = 0
    for js_url in js_urls[:10]:  # Cap at 10 files
        try:
            results = analyze_js(js_url)
            if results and "error" not in results:
                analyzed_count += 1
                for category, matches in results.items():
                    for match in matches[:5]:
                        sev = match.get("severity", "INFO").lower()
                        if sev == "critical":
                            sev = "critical"
                        elif sev == "high":
                            sev = "high"
                        else:
                            sev = "medium" if sev == "medium" else "info"

                        findings.append({
                            "title": f"JS Secret: {category}",
                            "description": (
                                f"Found in: {js_url}\n"
                                f"Match: {match['match'][:100]}"
                            ),
                            "severity": sev,
                            "source": "js_recon",
                            "url": js_url,
                            "target": target,
                        })

                        # Store API endpoints in state for injection testing
                        if category == "API Endpoint":
                            state.assets.setdefault("api_endpoints", [])
                            state.assets["api_endpoints"].append(match["match"])
        except Exception:
            continue

    print(f"  [js_recon] Analyzed {analyzed_count} JS files, "
          f"found {len(findings)} secrets/endpoints")
    return findings


def _exec_param_mine(action: AgentAction, state: AgentState) -> List[Dict]:
    """Discover hidden parameters in target endpoints."""
    from tools.param_miner import mine_parameters
    findings = []
    target = action.target
    print(f"  [param_mine] Mining hidden parameters: {target}")

    # Use wayback params if available for smarter mining
    extra_params = state.assets.get("wayback_params", [])[:20]

    try:
        results = mine_parameters(target, extra_params=extra_params)
        for r in results:
            sev = "high" if r.get("reflected") else "medium"
            findings.append({
                "title": f"Hidden Parameter: ?{r['param']}=",
                "description": (
                    f"Discovered hidden parameter '{r['param']}' on {target}\n"
                    f"Status: {r['status']} (baseline: {r['base_status']})\n"
                    f"Length delta: {r['length_delta']} bytes\n"
                    f"Reflected: {'YES — possible XSS' if r['reflected'] else 'No'}"
                ),
                "severity": sev,
                "source": "param_mine",
                "param": r["param"],
                "reflected": r.get("reflected", False),
                "url": r["url"],
                "target": target,
            })

            # Store discovered params for injection testing
            state.assets.setdefault("discovered_params", [])
            state.assets["discovered_params"].append(r["param"])

    except Exception as e:
        logger.warning(f"param_mine error: {e}")
        print(f"  [param_mine] error: {e}")

    print(f"  [param_mine] Found {len(findings)} hidden parameters")
    return findings


def _exec_cors_scan(action: AgentAction, state: AgentState) -> List[Dict]:
    """Deep CORS misconfiguration testing."""
    from tools.cors_checker import check_cors
    findings = []
    target = action.target
    print(f"  [cors_scan] Testing CORS: {target}")

    try:
        result = check_cors(target)

        for issue in result.get("issues", []):
            sev = issue["severity"].lower()
            findings.append({
                "title": f"CORS Misconfiguration ({issue['severity']})",
                "description": (
                    f"Origin tested: {issue['origin']}\n"
                    f"Reason: {issue['reason']}\n"
                    f"Headers: {issue.get('headers', {})}"
                ),
                "severity": sev,
                "source": "cors_scan",
                "url": target,
                "target": target,
            })
    except Exception as e:
        logger.warning(f"CORS scan error: {e}")
        print(f"  [cors_scan] error: {e}")

    print(f"  [cors_scan] Found {len(findings)} CORS issues")
    return findings


def _exec_injection_test(action: AgentAction, state: AgentState) -> List[Dict]:
    """Test endpoints for XSS, SQLi, SSTI, LFI, Open Redirect."""
    from tools.injection_tester import run_all_injection_tests
    findings = []
    target = action.target
    print(f"  [injection_test] Testing injections: {target}")

    # Collect parameters to test from state
    params_to_test = list(set(
        state.assets.get("discovered_params", []) +
        state.assets.get("wayback_params", [])[:10]
    ))

    try:
        results = run_all_injection_tests(
            url=target,
            params=params_to_test if params_to_test else None,
        )
        findings.extend(results)

        # Also test high-interest wayback URLs
        for wb_url in state.assets.get("wayback_paths", [])[:5]:
            if "?" in wb_url or any(kw in wb_url for kw in
                                     ["/api/", "file=", "id=", "page="]):
                base = target.rstrip("/")
                full_url = f"{base}{wb_url}" if wb_url.startswith("/") else wb_url
                try:
                    extra = run_all_injection_tests(url=full_url)
                    findings.extend(extra)
                except Exception:
                    continue

    except Exception as e:
        logger.warning(f"Injection test error: {e}")
        print(f"  [injection_test] error: {e}")

    print(f"  [injection_test] Found {len(findings)} injection vulnerabilities")
    return findings


def _exec_subdomain_takeover(action: AgentAction, state: AgentState) -> List[Dict]:
    """Check discovered subdomains for takeover vulnerabilities."""
    from tools.subdomain_takeover import check_subdomains
    findings = []
    print(f"  [subdomain_takeover] Checking for takeover opportunities...")

    # Collect all discovered subdomains from state
    subdomains = state.assets.get("subdomains", [])

    if not subdomains:
        # Try to extract from root target
        from urllib.parse import urlparse
        target = action.target
        if "://" in target:
            target = urlparse(target).hostname or target
        subdomains = [target]

    try:
        results = check_subdomains(subdomains)
        findings.extend(results)
    except Exception as e:
        logger.warning(f"Subdomain takeover error: {e}")
        print(f"  [subdomain_takeover] error: {e}")

    print(f"  [subdomain_takeover] Checked {len(subdomains)} subdomains, "
          f"found {len(findings)} takeover opportunities")
    return findings


def _exec_waf_bypass(action: AgentAction, state: AgentState) -> List[Dict]:
    """Adaptive WAF bypass testing using mutation engine."""
    from tools.waf_evasion import WAFEvasionEngine
    findings = []
    target = action.target
    print(f"  [waf_bypass] Testing WAF bypass: {target}")

    try:
        engine = WAFEvasionEngine(base_url=target)

        # Detect WAF first
        waf_type, confidence = engine.detect_waf(target)
        if waf_type:
            print(f"  [waf_bypass] Detected WAF: {waf_type} (confidence: {confidence:.0%})")

            # Test bypass with common payloads
            test_payloads = [
                '<script>alert(1)</script>',
                "' OR 1=1--",
                '{{7*7}}',
            ]

            for base_payload in test_payloads:
                results = engine.test_bypass(
                    target_url=target,
                    base_payload=base_payload,
                    waf_type=waf_type,
                    max_attempts=8,
                )

                best = engine.get_best_bypass(results)
                if best and not best.blocked:
                    findings.append({
                        "title": f"WAF Bypass Found ({waf_type})",
                        "description": (
                            f"Successfully bypassed {waf_type} WAF.\n"
                            f"Original payload: {base_payload}\n"
                            f"Bypass payload: {best.payload[:150]}\n"
                            f"Techniques: {', '.join(best.techniques)}\n"
                            f"Status: {best.status_code}"
                        ),
                        "severity": "high",
                        "source": "waf_bypass",
                        "waf_type": waf_type,
                        "techniques": best.techniques,
                        "url": target,
                        "target": target,
                    })

            # Store learned strategies in state
            strategies = engine.export_learned_strategies()
            if strategies:
                state.assets["waf_strategies"] = strategies

        else:
            print("  [waf_bypass] No WAF detected, skipping bypass testing")
            findings.append({
                "title": "No WAF Detected",
                "description": f"No WAF detected on {target}. Direct testing possible.",
                "severity": "info",
                "source": "waf_bypass",
                "target": target,
            })

    except Exception as e:
        logger.warning(f"WAF bypass error: {e}")
        print(f"  [waf_bypass] error: {e}")

    print(f"  [waf_bypass] Found {len(findings)} bypass techniques")
    return findings


def _exec_request_auth(action: AgentAction, state: AgentState) -> List[Dict]:
    """
    Pause the scan and ask the human operator for authentication credentials.
    The AI calls this when it detects 401/403 barriers or login pages.
    Credentials are stored in state.assets['auth_headers'] and automatically
    injected into all subsequent HTTP requests.
    """
    findings = []
    target = action.target
    print(f"\n  {'='*60}")
    print(f"  [AUTH REQUIRED] Target: {target}")
    print(f"  {'='*60}")
    print(f"  AI detected an authentication barrier on this target.")
    print(f"  Please provide ONE of the following:\n")
    print(f"  Option 1 — Cookie header:")
    print(f"    Example: session=abc123; token=xyz")
    print(f"  Option 2 — Authorization header:")
    print(f"    Example: Bearer eyJhbGciOiJI...")
    print(f"  Option 3 — Type 'skip' to continue without auth\n")

    try:
        user_input = input("  🔑 Paste credential: ").strip()
    except (EOFError, KeyboardInterrupt):
        user_input = "skip"

    if not user_input or user_input.lower() == "skip":
        print("  [AUTH] Skipped — continuing unauthenticated scan")
        findings.append({
            "title": "Authentication Barrier Detected (Skipped)",
            "description": (
                f"Target {target} requires authentication but user chose to skip.\n"
                f"Findings behind login may be missed."
            ),
            "severity": "info",
            "source": "request_auth",
            "target": target,
        })
        return findings

    # Detect credential type and build headers
    auth_headers = {}
    if user_input.lower().startswith("bearer ") or user_input.lower().startswith("basic "):
        auth_headers["Authorization"] = user_input
        cred_type = "Authorization Token"
    else:
        # Treat as Cookie
        auth_headers["Cookie"] = user_input
        cred_type = "Cookie"

    # Store in state for ALL future tools to use
    state.assets["auth_headers"] = auth_headers
    state.assets["auth_type"] = cred_type
    state.assets["authenticated"] = True

    print(f"  [AUTH] {cred_type} saved! All future requests will be authenticated.")
    print(f"  [AUTH] Resuming scan...\n")

    findings.append({
        "title": f"Authentication Acquired ({cred_type})",
        "description": (
            f"User provided {cred_type} for {target}.\n"
            f"All subsequent tools (injection_test, bola_probe, param_mine, etc.) "
            f"will automatically include these credentials in HTTP headers."
        ),
        "severity": "info",
        "source": "request_auth",
        "target": target,
    })

    return findings


def _exec_create_custom_tool(action: AgentAction, state: AgentState,
                             ai_client=None) -> List[Dict]:
    """
    AI writes a custom Python exploit script on-the-fly, executes it,
    and collects findings. If the script fails, AI will self-heal (debug
    and retry) up to 2 times.
    """
    from tools.ai_tool_creator import AIToolCreator
    findings = []
    target = action.target
    purpose = action.params.get("purpose", "Custom security test")

    print(f"  [create_custom_tool] AI is writing a custom tool...")
    print(f"  [create_custom_tool] Purpose: {purpose}")
    print(f"  [create_custom_tool] Target: {target}")

    try:
        creator = AIToolCreator(governance_mode="ask", ai_client=ai_client)

        # Gather context for AI to write better code
        target_info = {
            "target": target,
            "tech_stack": state.assets.get("tech_stack", "unknown"),
            "discovered_endpoints": state.assets.get("api_endpoints", [])[:10],
            "discovered_params": state.assets.get("discovered_params", [])[:10],
            "known_vulns": [
                f.get("title") for f in state.findings[-10:]
                if f.get("severity") in ("high", "critical")
            ],
            "auth_available": state.assets.get("authenticated", False),
            "purpose": purpose,
        }

        # AI plans and creates the tool
        planned_tools = creator.analyze_target_and_plan(target, target_info)

        if not planned_tools:
            print("  [create_custom_tool] AI decided no custom tool is needed")
            return findings

        for tool_spec in planned_tools[:2]:  # Max 2 tools per iteration
            print(f"  [create_custom_tool] Creating: {tool_spec.name}")
            print(f"  [create_custom_tool] Reasoning: {tool_spec.ai_reasoning}")

            if not creator.create_tool(tool_spec):
                print(f"  [create_custom_tool] Tool creation declined or failed")
                continue

            # Execute with self-healing retry loop
            max_retries = 2
            for attempt in range(max_retries + 1):
                kwargs = {"target": target}

                # Inject auth headers if available
                if state.assets.get("auth_headers"):
                    kwargs["headers"] = state.assets["auth_headers"]

                result = creator.execute_tool(tool_spec.name, **kwargs)

                if result.success:
                    print(f"  [create_custom_tool] {tool_spec.name} executed OK "
                          f"({result.execution_time:.1f}s)")
                    findings.extend(result.findings)
                    break
                else:
                    if attempt < max_retries:
                        print(f"  [create_custom_tool] Error: {result.error}")
                        print(f"  [create_custom_tool] Self-healing attempt "
                              f"{attempt + 1}/{max_retries}...")
                        # AI fixes its own code
                        creator.improve_tool(
                            tool_spec.name,
                            feedback=f"Error: {result.error}"
                        )
                    else:
                        print(f"  [create_custom_tool] {tool_spec.name} failed "
                              f"after {max_retries} retries: {result.error}")
                        findings.append({
                            "title": f"Custom Tool Failed: {tool_spec.name}",
                            "description": (
                                f"AI-created tool '{tool_spec.name}' failed: "
                                f"{result.error}\n"
                                f"Purpose: {tool_spec.purpose}"
                            ),
                            "severity": "info",
                            "source": "create_custom_tool",
                            "target": target,
                        })

    except Exception as e:
        logger.warning(f"create_custom_tool error: {e}")
        print(f"  [create_custom_tool] error: {e}")

    print(f"  [create_custom_tool] Generated {len(findings)} findings")
    return findings


def _exec_nuclei_scan(action: AgentAction, state: AgentState) -> List[Dict]:
    """Run Nuclei template-based vulnerability scanner."""
    import subprocess
    findings = []
    target = action.target
    if "://" not in target:
        target = f"https://{target}"
    print(f"  [nuclei_scan] Running Nuclei on: {target}")

    try:
        cmd = ["nuclei", "-u", target, "-severity", "critical,high,medium",
               "-silent", "-jsonl", "-timeout", "15"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        for line in result.stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                sev = entry.get("info", {}).get("severity", "info").lower()
                findings.append({
                    "title": f"Nuclei: {entry.get('info', {}).get('name', 'Unknown')}",
                    "description": (
                        f"Template: {entry.get('template-id', 'N/A')}\n"
                        f"Matched: {entry.get('matched-at', target)}\n"
                        f"Matcher: {entry.get('matcher-name', 'N/A')}"
                    ),
                    "severity": sev,
                    "source": "nuclei_scan",
                    "target": entry.get("matched-at", target),
                    "template": entry.get("template-id"),
                })
            except json.JSONDecodeError:
                continue

        print(f"  [nuclei_scan] Found {len(findings)} vulnerabilities")
    except FileNotFoundError:
        print("  [nuclei_scan] Nuclei not installed — skipping")
    except subprocess.TimeoutExpired:
        print("  [nuclei_scan] Timeout (120s) — partial results")
    except Exception as e:
        logger.warning(f"nuclei_scan error: {e}")
        print(f"  [nuclei_scan] error: {e}")
    return findings


def _exec_xss_hunt(action: AgentAction, state: AgentState) -> List[Dict]:
    """Run Dalfox for advanced XSS hunting."""
    import subprocess
    findings = []
    target = action.target
    if "://" not in target:
        target = f"https://{target}"
    print(f"  [xss_hunt] Running Dalfox on: {target}")

    # Collect params from state for smarter scanning
    params = state.assets.get("discovered_params", [])
    wayback_params = state.assets.get("wayback_params", [])[:10]
    all_params = list(set(params + wayback_params))

    try:
        cmd = ["dalfox", "url", target, "--silence", "--format", "json",
               "--timeout", "10"]
        if all_params:
            cmd += ["--data", "&".join(f"{p}=FUZZ" for p in all_params[:5])]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        for line in result.stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                findings.append({
                    "title": f"XSS Found: {entry.get('type', 'Reflected XSS')}",
                    "description": (
                        f"URL: {entry.get('proof_url', target)}\n"
                        f"Param: {entry.get('param', 'N/A')}\n"
                        f"Payload: {entry.get('payload', 'N/A')[:150]}\n"
                        f"Type: {entry.get('type', 'N/A')}"
                    ),
                    "severity": "high",
                    "source": "xss_hunt",
                    "target": entry.get("proof_url", target),
                    "param": entry.get("param"),
                })
            except json.JSONDecodeError:
                continue

        print(f"  [xss_hunt] Found {len(findings)} XSS vulnerabilities")
    except FileNotFoundError:
        print("  [xss_hunt] Dalfox not installed — skipping")
    except subprocess.TimeoutExpired:
        print("  [xss_hunt] Timeout (120s) — partial results")
    except Exception as e:
        logger.warning(f"xss_hunt error: {e}")
        print(f"  [xss_hunt] error: {e}")
    return findings


def _exec_zap_active_scan(action: AgentAction, state: AgentState) -> List[Dict]:
    """Run OWASP ZAP active scan via API (headless daemon)."""
    findings = []
    target = action.target
    if "://" not in target:
        target = f"https://{target}"
    print(f"  [zap_active_scan] Starting ZAP scan on: {target}")

    try:
        from zapv2 import ZAPv2
    except ImportError:
        print("  [zap_active_scan] zaproxy not installed — falling back to built-in tools")
        return findings

    zap_api_key = "elengenix-zap-key"
    zap_proxy = "http://127.0.0.1:8080"

    try:
        zap = ZAPv2(apikey=zap_api_key, proxies={"http": zap_proxy, "https": zap_proxy})

        # Check if ZAP daemon is running
        try:
            zap.core.version
        except Exception:
            # Try to start ZAP daemon
            import subprocess
            zap_path = Path("tools/external/zap/zap.sh")
            if zap_path.exists():
                subprocess.Popen(
                    [str(zap_path), "-daemon", "-port", "8080",
                     "-config", f"api.key={zap_api_key}"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                print("  [zap_active_scan] Starting ZAP daemon...")
                time.sleep(15)  # Wait for daemon to initialize
            else:
                print("  [zap_active_scan] ZAP not found — skipping")
                return findings

        # Inject auth headers if available
        auth_headers = state.assets.get("auth_headers", {})
        for hdr_name, hdr_val in auth_headers.items():
            zap.replacer.add_rule(
                description=f"Auth-{hdr_name}",
                enabled="true",
                matchtype="REQ_HEADER",
                matchstring=hdr_name,
                replacement=hdr_val,
            )

        # Open target URL in ZAP
        print(f"  [zap_active_scan] Accessing target: {target}")
        zap.urlopen(target)
        time.sleep(3)

        # Active scan
        print("  [zap_active_scan] Running active scan...")
        scan_id = zap.ascan.scan(target)

        # Poll progress
        while int(zap.ascan.status(scan_id)) < 100:
            progress = zap.ascan.status(scan_id)
            print(f"  [zap_active_scan] Progress: {progress}%")
            time.sleep(10)

        # Collect alerts
        alerts = zap.core.alerts(baseurl=target, start=0, count=100)
        for alert in alerts:
            sev_map = {"Informational": "info", "Low": "low",
                       "Medium": "medium", "High": "high"}
            sev = sev_map.get(alert.get("risk", ""), "info")
            findings.append({
                "title": f"ZAP: {alert.get('alert', 'Unknown')}",
                "description": (
                    f"Risk: {alert.get('risk')}\n"
                    f"URL: {alert.get('url', target)}\n"
                    f"Param: {alert.get('param', 'N/A')}\n"
                    f"Evidence: {alert.get('evidence', 'N/A')[:200]}\n"
                    f"Solution: {alert.get('solution', 'N/A')[:200]}"
                ),
                "severity": sev,
                "source": "zap_active_scan",
                "target": alert.get("url", target),
                "cwe": alert.get("cweid"),
            })

        print(f"  [zap_active_scan] Found {len(findings)} vulnerabilities")

    except Exception as e:
        logger.warning(f"ZAP scan error: {e}")
        print(f"  [zap_active_scan] error: {e}")

    return findings


def _exec_analyze_findings(new_findings: List[Dict], action: AgentAction,
                           state: AgentState, ai_client) -> str:
    """
    After each action, ask AI to analyze the new findings and update state:
    - Upgrade severities
    - Identify pivot opportunities
    - Suggest tactics for the next iteration
    Returns a short AI insight string.
    """
    if not ai_client or not new_findings:
        return ""

    findings_text = json.dumps(new_findings[:10], indent=2)
    assets_text = json.dumps(
        {k: v[:5] if isinstance(v, list) else v for k, v in state.assets.items()},
        indent=2
    )

    content = _ai_call(
        ai_client,
        system=(
            "You are an expert bug bounty analyst. Analyze findings after each tool run. "
            "Be concise and strategic."
        ),
        user=f"""Action just completed: {action.name} on {action.target}

New findings:
{findings_text}

Discovered assets so far:
{assets_text}

Analyze and respond in JSON:
{{
  "key_insight": "one sentence summary of what this means",
  "severity_upgrades": [
    {{"title": "finding title", "new_severity": "high", "reason": "why"}}
  ],
  "pivot_targets": ["url or domain worth investigating next"],
  "recommended_next": "action_name on target — e.g. endpoint_fuzz on api.example.com"
}}""",
        temperature=0.2,
    )

    data = _parse_json(content)

    # Apply severity upgrades
    for upg in data.get("severity_upgrades", []):
        for f in state.findings:
            if upg.get("title", "") in f.get("title", ""):
                f["severity"] = upg.get("new_severity", f["severity"])
                f["ai_reasoning"] = upg.get("reason", "")

    # Store pivot targets
    for pt in data.get("pivot_targets", []):
        state.assets.setdefault("ai_pivots", [])
        if pt and pt not in state.assets["ai_pivots"]:
            state.assets["ai_pivots"].append(pt)

    # Store AI recommendation for next iteration context
    if data.get("recommended_next"):
        state.assets["ai_last_recommendation"] = data["recommended_next"]

    insight = data.get("key_insight", "")
    if insight:
        print(f"  [AI insight] {insight}")

    return insight


def _ai_reflect_on_action(action: AgentAction, state: AgentState, ai_client) -> tuple[bool, str, str]:
    """AI evaluates the potential impact of an action before executing it."""
    if not ai_client or action.name in ("threat_model", "analyze"):
        return True, "Safe analysis step", "low"

    content = _ai_call(
        ai_client,
        system=(
            "You are an offensive security AI with explicit authorization to aggressively test this target for a bug bounty program. "
            "Evaluate the proposed action for effectiveness. You must be aggressive and accept moderate operational risks (like WAF blocks or temporary rate limits) in order to discover critical vulnerabilities like SQLi, RCE, and BOLA/IDOR. "
            "ONLY reject the action if it is guaranteed to cause irreversible permanent damage or catastrophic database deletion. Otherwise, approve it."
        ),
        user=f"""Proposed action: {action.name} on {action.target}
Reasoning: {action.reasoning}

Assess the potential consequences. Is this a wise and safe choice for a bug bounty scan?
Reply ONLY in JSON format:
{{
  "reflection": "your thought process regarding safety and impact",
  "risk_level": "high/medium/low",
  "decision": "approve/reject"
}}""",
        temperature=0.1,
    )
    
    data = _parse_json(content)
    decision = data.get("decision", "approve").lower()
    reflection = data.get("reflection", "No reflection provided")
    risk = data.get("risk_level", "unknown")
    
    return (decision == "approve"), reflection, risk


# ──────────────────────────────────────────────────────────
# AI decision engine
# ──────────────────────────────────────────────────────────

def _ai_decide_next(ai_client, state: AgentState) -> AgentAction:
    """Ask AI what the next action should be."""

    context = json.dumps({
        "root_target": state.root_target,
        "goal": state.goal,
        "iteration": state.iteration,
        "assets_discovered": {k: v[:10] if isinstance(v, list) else v
                              for k, v in state.assets.items()},
        "findings_summary": [
            {"title": f.get("title"), "severity": f.get("severity"),
             "type": f.get("type"), "target": f.get("target")}
            for f in state.findings[-20:]
        ],
        "actions_taken": state.action_history[-10:],
    }, indent=2)

    available_actions = """
Available actions (Phase 1 — Intelligence Gathering):
  - recon              : DNS/subdomain discovery, fingerprinting. Params: {"target": "domain.com"}
  - wayback_recon      : Historical URL & parameter discovery from Wayback Machine/OTX. Params: {"target": "domain.com"}
  - github_dork        : Search GitHub for leaked credentials, config files. Params: {"target": "domain.com"}
  - osint_research     : Web research for tech stack, leaked info (Tavily). Params: {"target": "domain.com"}
  - vuln_intel         : Real-time vulnerability and exploit intelligence (VulnCheck). Params: {"target": "domain.com"}
  - js_recon           : Extract secrets, API keys, endpoints from JavaScript files. Params: {"target": "https://..."}

Available actions (Phase 2 — Active Probing):
  - http_probe         : Deep HTTP probe a URL. Params: {"target": "https://..."}
  - waf_detect         : WAF detection. Params: {"target": "https://..."}
  - endpoint_fuzz      : Common path discovery. Params: {"target": "https://..."}
  - param_mine         : Discover hidden/undocumented parameters. Params: {"target": "https://..."}
  - cors_scan          : Deep CORS misconfiguration testing. Params: {"target": "https://..."}
  - header_audit       : Security header audit. Params: {"target": "https://..."}
  - subdomain_takeover : Check subdomains for cloud resource takeover. Params: {"target": "domain.com"}

Available actions (Phase 2.5 — Authentication):
  - request_auth       : Ask the human operator for Cookie/Token when you hit 401/403 login barriers. Use this BEFORE exploitation if the target requires login. Params: {"target": "https://..."}

Available actions (Phase 3 — Exploitation):
  - injection_test     : Test for XSS, SQLi, SSTI, LFI, Open Redirect. Params: {"target": "https://..."}
  - bola_probe         : BOLA/IDOR vulnerability check. Params: {"target": "https://..."}
  - waf_bypass         : Adaptive WAF bypass with payload mutation. Params: {"target": "https://..."}
  - nuclei_scan        : Run Nuclei template-based vulnerability scanner (CVE probing, misconfigurations). Params: {"target": "https://..."}
  - xss_hunt           : Run Dalfox advanced XSS scanner with smart parameter fuzzing. Params: {"target": "https://..."}

Available actions (Phase 4 — Advanced / Custom):
  - zap_active_scan    : Run OWASP ZAP active scan via headless daemon (if installed). Falls back gracefully if ZAP is not available. Params: {"target": "https://..."}
  - create_custom_tool : Write a custom Python exploit script on-the-fly when existing tools cannot handle a specific CVE or unusual vulnerability. Params: {"target": "https://...", "purpose": "description of what the tool should do"}

Available actions (Strategic):
  - threat_model       : Analyze all intel and create a strategic attack plan.
  - analyze            : AI analysis of current findings.
  - done               : Finished scanning, generate report.
"""

    if not ai_client:
        # Fallback sequence when no AI available
        taken = set(a.split(":")[0] for a in state.action_history)
        for action_name in ["wayback_recon", "recon", "osint_research",
                            "github_dork", "vuln_intel", "js_recon",
                            "threat_model",
                            "http_probe", "waf_detect",
                            "endpoint_fuzz", "param_mine", "cors_scan",
                            "header_audit", "subdomain_takeover",
                            "request_auth",
                            "injection_test", "bola_probe", "waf_bypass",
                            "nuclei_scan", "xss_hunt",
                            "create_custom_tool",
                            "done"]:
            if action_name not in taken or action_name == "done":
                t = state.root_target
                return AgentAction(
                    name=action_name,
                    target=t if "://" in t else f"https://{t}",
                    reasoning="Fallback sequential mode (no AI client)",
                )

    content = _ai_call(
        ai_client,
        system=(
            "You are an autonomous bug bounty hunter AI. "
            "Decide the single best next action to find high-value vulnerabilities. "
            "Strategy guidelines:\n"
            "- Phase 1: Gather intelligence (recon, wayback, github, osint, vuln_intel, js_recon).\n"
            "- When you have enough intel: use threat_model to create an attack plan.\n"
            "- Phase 2: Execute active probing based on your plan.\n"
            "- AUTH: If you encounter HTTP 401/403 or login pages, use request_auth to ask the human for credentials BEFORE exploitation.\n"
            "- Phase 3: After auth (if needed), run exploitation tools (injection_test, bola_probe, waf_bypass).\n"
            "- Phase 4: If existing tools cannot handle a specific CVE or unusual target, use create_custom_tool to write a custom Python exploit.\n"
            "- CRITICAL RULE: DO NOT repeat the exact same action on the exact same target URL more than once. Look at the 'actions_taken' list. If you see 'bola_probe:https://api.1win.com' there, DO NOT run it again.\n"
            "- CRITICAL RULE: If you have exhausted all logical attacks for the current attack surface and have no NEW targets/subdomains to pivot to, you MUST select the 'done' action to finish the scan. Do not waste iterations doing nothing.\n"
            "- Pivot to new subdomains/endpoints when interesting assets are found.\n"
            "- Focus on findings with highest bounty potential."
        ),
        user=f"""{available_actions}

Current scan state:
{context}

Choose the BEST next action. Return JSON only:
{{
  "action": "action_name",
  "target": "https://specific-target.com/or/path",
  "params": {{}},
  "reasoning": "why this action now"
}}""",
        temperature=0.2,
    )

    data = _parse_json(content)

    action_name = data.get("action", "done")
    target = data.get("target", state.root_target)
    reasoning = data.get("reasoning", "")
    params = data.get("params", {})

    # Ensure target has scheme
    if action_name != "done" and "://" not in target:
        target = f"https://{target}"

    return AgentAction(name=action_name, target=target,
                       params=params, reasoning=reasoning)


# ──────────────────────────────────────────────────────────
# Main AutonomousAgent
# ──────────────────────────────────────────────────────────

class AutonomousAgent:
    """
    Autonomous AI agent for bug bounty — true agentic loop.
    AI decides what to do next at every step.
    """

    MAX_ITERATIONS = 25

    def __init__(self, governance_mode: str = "ask", ai_client=None):
        import threading as _threading
        self.governance_mode = governance_mode
        self.abort_event = _threading.Event()
        if ai_client is None:
            try:
                from tools.universal_ai_client import AIClientManager
                self.ai_client = AIClientManager()
            except Exception:
                self.ai_client = None
        else:
            self.ai_client = ai_client

        try:
            from tools.ai_tool_creator import AIToolCreator
            self.tool_creator = AIToolCreator(governance_mode=governance_mode)
        except Exception:
            self.tool_creator = None

        self.decision_history: List[AgentAction] = []
        logger.info(f"AutonomousAgent v4.0 initialized (mode: {governance_mode}, "
                    f"ai={'yes' if self.ai_client else 'fallback'})")

    def run_autonomous_scan(self, target: str, goal: str = None) -> ScanResult:
        start_time = datetime.utcnow()

        print(f"\n[Autonomous Mode] Starting scan on: {target}")
        print(f"[Governance] Mode: {self.governance_mode}")

        goal = goal or "Find high-value security vulnerabilities for bug bounty"
        print(f"[Goal] {goal}\n")

        # Init state
        state = AgentState(
            root_target=target,
            goal=goal,
        )

        # Init mission state
        try:
            from tools.mission_state import MissionState
            mission = MissionState(
                mission_id=f"auto_{int(time.time())}",
                target=target,
                objective=f"{goal} | governance={self.governance_mode}",
            )
        except Exception:
            mission = None

        try:
            for i in range(self.MAX_ITERATIONS):
                # ── Abort check ─────────────────────────────────────
                if self.abort_event.is_set():
                    print("\n[ABORTED] Scan stopped by user (ESC)")
                    break

                state.iteration = i + 1
                elapsed = int((datetime.utcnow() - start_time).total_seconds())

                # ── Progress indicator with severity breakdown ──────
                sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                for f in state.findings:
                    s = f.get("severity", "info").lower()
                    sev_counts[s] = sev_counts.get(s, 0) + 1
                print(f"\n[Iteration {state.iteration}/{self.MAX_ITERATIONS}] "
                      f"⏱ {elapsed}s | "
                      f"🔴{sev_counts['critical']} 🟠{sev_counts['high']} "
                      f"🟡{sev_counts['medium']} 🟢{sev_counts['low'] + sev_counts['info']}")

                # AI decides next action
                action = _ai_decide_next(self.ai_client, state)
                self.decision_history.append(action)
                state.action_history.append(f"{action.name}:{action.target}")

                print(f"  → AI chose: [{action.name}] {action.target}")
                if action.reasoning:
                    print(f"  → Reason: {action.reasoning}")

                if action.name == "done":
                    print("\n[AI] Scan complete — generating report...")
                    break

                # ── AI Self-Reflection ───────────────────────────────
                if self.governance_mode != "auto" and action.name not in ("threat_model", "analyze"):
                    print(f"  [Reflection] AI is evaluating the consequences of this action...")
                    is_safe, reflection, risk = _ai_reflect_on_action(action, state, self.ai_client)
                    print(f"  [Reflection] Risk: {risk.upper()} | {reflection}")
                    
                    if not is_safe:
                        print(f"  [Reflection] ❌ Action self-rejected by AI. Skipping...")
                        state.findings.append({
                            "title": f"AI Self-Rejected: {action.name}",
                            "description": f"AI decided not to execute {action.name} due to high risk or low value.\nReflection: {reflection}",
                            "severity": "info",
                            "source": "reflection"
                        })
                        continue
                    print(f"  [Reflection] ✅ Action approved. Executing...")
                # ────────────────────────────────────────────────────────

                # Execute chosen action
                new_findings = self._execute_action(action, state)

                # ── Per-action AI analysis ──────────────────────────────
                _exec_analyze_findings(new_findings, action, state, self.ai_client)
                # ────────────────────────────────────────────────────────

                state.findings.extend(new_findings)

                if mission and new_findings:
                    mission.add_finding()

                # Persist new findings to cross-session target memory
                if save_target_learning:
                    for f in new_findings:
                        save_target_learning(
                            target=state.root_target,
                            learning=(
                                f"[{f.get('severity','info').upper()}] "
                                f"{f.get('title','Finding')}: "
                                f"{f.get('description','')[:300]}"
                            ),
                            category=f.get("source", "scan"),
                        )

                # ── Rate limiting between iterations ────────────────
                if i < self.MAX_ITERATIONS - 1:
                    time.sleep(1.5)

        except KeyboardInterrupt:
            print("\n[Interrupted] Generating partial report...")

        end_time = datetime.utcnow()
        duration = (end_time - start_time).seconds

        # Bounty predictions
        predictions = self._predict_bounties(state.findings)

        # Report
        report_path = self._generate_report(target, state.findings, predictions)

        summary = self._build_summary(target, state, duration)
        print(f"\n[Complete] {duration}s | {len(state.findings)} findings | "
              f"{state.iteration} iterations")

        # ── Auto-export JSON ────────────────────────────────────
        self._export_json(target, state, predictions, duration)

        return ScanResult(
            target=target,
            start_time=start_time,
            end_time=end_time,
            findings=state.findings,
            bounty_predictions=predictions,
            tools_created=[],
            ai_decisions=self.decision_history,
            report_path=report_path,
            success=True,
            summary=summary,
        )

    def _export_json(self, target: str, state: AgentState,
                     predictions: List[Dict], duration: int):
        """Auto-save scan results to data/scans/ as JSON."""
        try:
            scans_dir = Path("data/scans")
            scans_dir.mkdir(parents=True, exist_ok=True)
            domain = _to_domain(target)
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            out_path = scans_dir / f"{domain}_{ts}.json"
            payload = {
                "target": target,
                "duration_seconds": duration,
                "iterations": state.iteration,
                "total_findings": len(state.findings),
                "findings": state.findings,
                "bounty_predictions": predictions,
                "assets": {
                    k: v for k, v in state.assets.items()
                    if not k.startswith("auth")
                },
                "action_history": state.action_history,
            }
            out_path.write_text(json.dumps(payload, indent=2, default=str),
                                encoding="utf-8")
            print(f"[Export] Saved to {out_path}")
        except Exception as e:
            logger.warning(f"JSON export failed: {e}")

    def _execute_action(self, action: AgentAction, state: AgentState) -> List[Dict]:
        dispatch = {
            "recon":              _exec_recon,
            "http_probe":         _exec_http_probe,
            "waf_detect":         _exec_waf_detect,
            "endpoint_fuzz":      _exec_endpoint_fuzz,
            "bola_probe":         _exec_bola_probe,
            "header_audit":       _exec_header_audit,
            "osint_research":     _exec_osint_research,
            "vuln_intel":         _exec_vuln_intel,
            "wayback_recon":      _exec_wayback_recon,
            "github_dork":        _exec_github_dork,
            "js_recon":           _exec_js_recon,
            "param_mine":         _exec_param_mine,
            "cors_scan":          _exec_cors_scan,
            "injection_test":     _exec_injection_test,
            "subdomain_takeover": _exec_subdomain_takeover,
            "waf_bypass":         _exec_waf_bypass,
            "request_auth":       _exec_request_auth,
            "nuclei_scan":        _exec_nuclei_scan,
            "xss_hunt":           _exec_xss_hunt,
            "zap_active_scan":    _exec_zap_active_scan,
        }

        # Actions that need ai_client, handle separately
        if action.name == "threat_model":
            try:
                return _exec_threat_model(action, state, ai_client=self.ai_client)
            except Exception as e:
                logger.warning(f"threat_model failed: {e}")
                print(f"  [!] threat_model error: {e}")
                return []

        if action.name == "create_custom_tool":
            try:
                return _exec_create_custom_tool(
                    action, state, ai_client=self.ai_client
                )
            except Exception as e:
                logger.warning(f"create_custom_tool failed: {e}")
                print(f"  [!] create_custom_tool error: {e}")
                return []

        if action.name == "endpoint_fuzz":
            try:
                return _exec_endpoint_fuzz(
                    action, state, ai_client=self.ai_client
                )
            except Exception as e:
                logger.warning(f"endpoint_fuzz failed: {e}")
                print(f"  [!] endpoint_fuzz error: {e}")
                return []

        fn = dispatch.get(action.name)
        if fn:
            try:
                return fn(action, state)
            except Exception as e:
                logger.warning(f"Action {action.name} failed: {e}")
                print(f"  [!] {action.name} error: {e}")
        return []

    def _predict_bounties(self, findings: List[Dict]) -> List[Dict]:
        try:
            from tools.bounty_predictor import BountyPredictor
            predictor = BountyPredictor()
            out = []
            for f in findings:
                try:
                    p = predictor.predict(f)
                    out.append({
                        "finding_title": f.get("title"),
                        "bounty_score": p.bounty_score,
                        "payout_range": p.payout_range,
                    })
                except Exception:
                    pass
            return out
        except Exception:
            return []

    def _generate_report(self, target: str, findings: List[Dict],
                         predictions: List[Dict]) -> Optional[Path]:
        try:
            from tools.pdf_report_generator import PDFReportGenerator, ReportMetadata
            meta = ReportMetadata(
                title=f"Autonomous Security Assessment — {target}",
                target=target,
                author="Elengenix Autonomous AI v5.0",
                date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            )
            gen = PDFReportGenerator()
            paths = gen.generate_from_findings(findings, meta)
            return paths.get("pdf") or paths.get("html")
        except Exception as e:
            logger.debug(f"Report generation failed: {e}")
            return None

    def _build_summary(self, target: str, state: AgentState, duration: int) -> str:
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in state.findings:
            s = f.get("severity", "info").lower()
            by_sev[s] = by_sev.get(s, 0) + 1

        lines = [
            f"Autonomous scan complete for {target}",
            f"Duration: {duration}s | Iterations: {state.iteration}",
            f"AI decisions: {len(self.decision_history)}",
            "",
            "Findings:",
            f"  Critical: {by_sev['critical']}",
            f"  High:     {by_sev['high']}",
            f"  Medium:   {by_sev['medium']}",
            f"  Low/Info: {by_sev['low'] + by_sev['info']}",
            "",
            "Assets discovered:",
        ]
        for k, v in state.assets.items():
            if isinstance(v, list):
                lines.append(f"  {k}: {len(v)}")
        return "\n".join(lines)

    def run_team_scan(self, target: str, goal: str = None) -> ScanResult:
        """
        TEAM AEGIS MODE for Autonomous Agent.
        
        When multiple AI models are available (ACTIVE_MODELS env),
        runs a collaborative multi-agent scan using Team Aegis.
        The team discusses strategy and uses autonomous agent's
        built-in action executors for tool operations.
        """
        import os
        from datetime import datetime
        
        active_models_str = os.environ.get("ACTIVE_MODELS", "")
        active_models = [m.strip() for m in active_models_str.split(",") if m.strip()]
        
        if len(active_models) < 2:
            # Not enough models for team mode — fall back to single agent
            print("[Team Aegis] Not enough models selected. Using single-agent mode.")
            return self.run_autonomous_scan(target, goal=goal)
        
        start_time = datetime.utcnow()
        goal = goal or "Find high-value security vulnerabilities for bug bounty"
        
        print(f"\n{'='*60}")
        print(f" TEAM AEGIS — Autonomous Collaborative Scan")
        print(f" Target: {target}")
        print(f" Goal: {goal}")
        print(f" Models: {', '.join(active_models)}")
        print(f"{'='*60}\n")
        
        # Build team clients
        try:
            from tools.universal_ai_client import UniversalAIClient
            from tools.multi_agent import TeamAegis, TeamMessage
            from tools.universal_executor import get_universal_executor
            
            team_clients = []
            
            for model_str in active_models:
                try:
                    if "/" in model_str:
                        provider, model_name = model_str.split("/", 1)
                    else:
                        provider = os.environ.get("ACTIVE_AI_PROVIDER", "auto")
                        model_name = model_str
                        
                    new_client = UniversalAIClient(
                        provider=provider,
                        model=model_name
                    )
                    if new_client.is_available():
                        team_clients.append(new_client)
                except Exception as e:
                    logger.warning(f"Failed to load team client {model_name}: {e}")
                    

            if len(team_clients) < 2:
                print("[Team Aegis] Could not form a team. Falling back to single agent.")
                return self.run_autonomous_scan(target, goal=goal)
            
            # Create executor for tool operations
            executor = get_universal_executor()
            
            # Create Team Aegis with live output
            def live_callback(msg):
                print(msg)
            
            team = TeamAegis(
                clients=team_clients[:3],
                target=target,
                callback=live_callback,
                max_rounds=30,
            )
            
            # Add mission briefing
            team.discussion.append(TeamMessage(
                round=0,
                agent_id=-1,
                agent_role="Operator",
                model_name="human",
                content=f"Mission briefing: {goal}\nTarget: {target}\n"
                        f"Available actions: recon, http_probe, waf_detect, nuclei_scan, "
                        f"endpoint_fuzz, bola_probe, header_audit, xss_hunt, cors_scan, "
                        f"injection_test, subdomain_takeover, param_mine, js_recon, "
                        f"wayback_recon, threat_model, create_custom_tool",
                msg_type="discussion"
            ))
            
            # Run the team engagement
            report = team.run_full_engagement(executor=executor)
            
            end_time = datetime.utcnow()
            duration = (end_time - start_time).seconds
            
            # Convert team findings to our format
            findings = []
            for f in team.findings:
                findings.append({
                    "title": f.description[:100],
                    "description": f.description,
                    "severity": f.severity,
                    "source": f"team_aegis/{f.source_agent}",
                    "evidence": f.evidence,
                })
            
            # Generate predictions and report
            predictions = self._predict_bounties(findings)
            report_path = self._generate_report(target, findings, predictions)
            
            # Build state for summary
            state = AgentState(
                root_target=target,
                goal=goal,
                findings=findings,
                iteration=team.round,
            )
            summary = (
                f"Team Aegis collaborative scan complete for {target}\n"
                f"Duration: {duration}s | Rounds: {team.round}\n"
                f"Team size: {team.team_size} agents\n"
                f"Findings: {len(findings)} | Actions: {len(team.tasks)}\n\n"
                f"{report}"
            )
            
            # Export JSON
            self._export_json(target, state, predictions, duration)
            
            print(f"\n[Team Aegis] Complete: {duration}s | {len(findings)} findings | "
                  f"{team.round} rounds")
            
            return ScanResult(
                target=target,
                start_time=start_time,
                end_time=end_time,
                findings=findings,
                bounty_predictions=predictions,
                tools_created=[],
                ai_decisions=self.decision_history,
                report_path=report_path,
                success=True,
                summary=summary,
            )
            
        except Exception as e:
            logger.error(f"Team Aegis failed: {e}")
            print(f"[Team Aegis] Error: {e}. Falling back to single agent.")
            return self.run_autonomous_scan(target, goal=goal)

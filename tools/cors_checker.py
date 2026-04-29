"""
tools/cors_checker.py — CORS Misconfiguration Detector (v2.0.0)
- Tests multiple attack origins
- Detects wildcard, reflected-origin, and credential combos
- Returns structured severity-tagged results
"""

from __future__ import annotations

import logging
from typing import Dict, List

import requests

logger = logging.getLogger("elengenix.cors_checker")

_TEST_ORIGINS: List[str] = [
 "https://evil.com",
 "https://attacker.com",
 "null",
 "https://elengenix-test.com",
]

_TIMEOUT = 8

def check_cors(url: str) -> Dict:
 """
 Probe CORS configuration of the target URL.
 Returns a dict with: vulnerable, severity, details list.
 """
 if not url.startswith(("http://", "https://")):
 url = f"https://{url}"

 session = requests.Session()
 session.headers["User-Agent"] = "Elengenix-Security-Scanner/2.0"

 issues: List[Dict] = []

 for origin in _TEST_ORIGINS:
 try:
 r = session.get(
 url,
 headers={"Origin": origin},
 timeout=_TIMEOUT,
 verify=False,
 allow_redirects=True,
 )
 except Exception as e:
 logger.debug(f"CORS probe error ({origin}): {e}")
 continue

 acao = r.headers.get("Access-Control-Allow-Origin", "")
 acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
 acam = r.headers.get("Access-Control-Allow-Methods", "")

 if acao == "*" and acac == "true":
 issues.append({
 "origin": origin,
 "severity": "CRITICAL",
 "reason": "Wildcard ACAO + Allow-Credentials: true — credentials exposed to any origin.",
 "headers": {"ACAO": acao, "ACAC": acac},
 })
 elif acao == origin and acac == "true":
 issues.append({
 "origin": origin,
 "severity": "HIGH",
 "reason": "Reflected origin + credentials allowed — classic CORS exploit.",
 "headers": {"ACAO": acao, "ACAC": acac, "ACAM": acam},
 })
 elif acao == origin:
 issues.append({
 "origin": origin,
 "severity": "MEDIUM",
 "reason": "Reflected origin without credentials — limited risk.",
 "headers": {"ACAO": acao},
 })
 elif acao == "*":
 issues.append({
 "origin": origin,
 "severity": "LOW",
 "reason": "Wildcard ACAO — acceptable for public APIs only.",
 "headers": {"ACAO": acao},
 })

 vulnerable = any(i["severity"] in ("HIGH", "CRITICAL") for i in issues)
 top_sev = "CRITICAL" if any(i["severity"] == "CRITICAL" for i in issues) \
 else "HIGH" if vulnerable else "LOW" if issues else "NONE"

 return {
 "url": url,
 "vulnerable": vulnerable,
 "severity": top_sev,
 "issues": issues,
 }

if __name__ == "__main__":
 import sys, json
 if len(sys.argv) > 1:
 print(json.dumps(check_cors(sys.argv[1]), indent=2))

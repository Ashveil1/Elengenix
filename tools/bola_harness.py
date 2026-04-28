"""tools/bola_harness.py

BOLA/IDOR Differential Harness for Bug Bounty (Web/API).

This module is designed for safe, evidence-first testing:
- You provide two sessions (Account A and Account B) as headers.
- Harness discovers likely identity fields (user_id/account_id) using common endpoints.
- Harness runs differential access checks against common object endpoints.

Important:
- This does not exploit anything automatically.
- It only performs GET requests and compares access boundaries.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

logger = logging.getLogger("elengenix.bola")

@dataclass
class BOLAResult:
 success: bool
 findings: List[Dict[str, Any]]
 notes: List[str]

class BOLAHarness:
 def __init__(self, base_url: str, timeout: int = 15, rate_limit_rps: float = 1.5):
 self.base_url = base_url.rstrip("/") + "/"
 self.timeout = timeout
 self.rate_limit_rps = max(0.1, float(rate_limit_rps))
 self._last_req_ts = 0.0

 def _sleep_rate_limit(self) -> None:
 min_interval = 1.0 / self.rate_limit_rps
 now = time.time()
 dt = now - self._last_req_ts
 if dt < min_interval:
 time.sleep(min_interval - dt)
 self._last_req_ts = time.time()

 def _get(self, path: str, headers: Dict[str, str]) -> Tuple[int, str, Dict[str, Any]]:
 self._sleep_rate_limit()
 url = urljoin(self.base_url, path.lstrip("/"))
 r = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=False)
 text = r.text or ""
 parsed: Dict[str, Any] = {}
 ctype = (r.headers.get("content-type") or "").lower()
 if "application/json" in ctype:
 try:
 parsed = r.json() if r.text else {}
 except Exception:
 parsed = {}
 return r.status_code, text, parsed

 def _extract_ids(self, obj: Any) -> Dict[str, str]:
 """Extract common identity fields from JSON-like objects."""
 found: Dict[str, str] = {}
 if isinstance(obj, dict):
 for k, v in obj.items():
 lk = str(k).lower()
 if lk in {"id", "user_id", "userid", "uid", "account_id", "accountid", "customer_id", "tenant_id"}:
 if isinstance(v, (str, int)):
 found[lk] = str(v)
 # shallow recursion for common wrappers
 if isinstance(v, dict) and lk in {"data", "user", "account", "profile", "result"}:
 found.update(self._extract_ids(v))
 return found

 def discover_identities(self, headers_a: Dict[str, str], headers_b: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, str], List[str]]:
 notes: List[str] = []
 candidates = [
 "/api/me",
 "/me",
 "/api/profile",
 "/profile",
 "/api/v1/me",
 "/api/v1/profile",
 "/api/user",
 "/user",
 ]

 ids_a: Dict[str, str] = {}
 ids_b: Dict[str, str] = {}

 for path in candidates:
 try:
 sa, ta, ja = self._get(path, headers_a)
 sb, tb, jb = self._get(path, headers_b)
 except Exception as e:
 notes.append(f"Identity fetch failed at {path}: {e}")
 continue

 if sa in (200, 201) and ja:
 ids_a.update(self._extract_ids(ja))
 if sb in (200, 201) and jb:
 ids_b.update(self._extract_ids(jb))

 if ids_a or ids_b:
 notes.append(f"Identity hints found via {path}")

 return ids_a, ids_b, notes

 def run_common_idor_checks(
 self,
 headers_a: Dict[str, str],
 headers_b: Dict[str, str],
 ids_a: Dict[str, str],
 ids_b: Dict[str, str],
 ) -> BOLAResult:
 notes: List[str] = []
 findings: List[Dict[str, Any]] = []

 # Prefer explicit IDs
 user_id_a = ids_a.get("user_id") or ids_a.get("userid") or ids_a.get("id")
 user_id_b = ids_b.get("user_id") or ids_b.get("userid") or ids_b.get("id")
 acct_id_a = ids_a.get("account_id") or ids_a.get("accountid")
 acct_id_b = ids_b.get("account_id") or ids_b.get("accountid")

 # If we don't have IDs, still try generic endpoints (might return list)
 tests: List[Tuple[str, Optional[str], Optional[str], str]] = []

 # User object endpoints
 if user_id_a and user_id_b and user_id_a != user_id_b:
 tests.extend(
 [
 (f"/api/users/{user_id_a}", user_id_a, "self", "user_object"),
 (f"/api/users/{user_id_b}", user_id_b, "cross", "user_object"),
 (f"/users/{user_id_a}", user_id_a, "self", "user_object"),
 (f"/users/{user_id_b}", user_id_b, "cross", "user_object"),
 ]
 )

 # Account object endpoints
 if acct_id_a and acct_id_b and acct_id_a != acct_id_b:
 tests.extend(
 [
 (f"/api/accounts/{acct_id_a}", acct_id_a, "self", "account_object"),
 (f"/api/accounts/{acct_id_b}", acct_id_b, "cross", "account_object"),
 ]
 )

 # Orders/invoices are common multi-tenant objects
 tests.extend(
 [
 ("/api/orders", None, "list", "order_list"),
 ("/api/invoices", None, "list", "invoice_list"),
 ]
 )

 # Dedup tests
 seen = set()
 uniq_tests = []
 for t in tests:
 if t[0] not in seen:
 seen.add(t[0])
 uniq_tests.append(t)

 def score_suspect(status_a: int, status_b: int, body_a: str, body_b: str) -> float:
 # Simple heuristic:
 # - If both 200 and responses are similar length, suspicious.
 # - If A is 403/404 but B is 200, suspicious for missing access control symmetry.
 if status_a == 200 and status_b == 200:
 la, lb = len(body_a), len(body_b)
 if la == 0 or lb == 0:
 return 0.2
 ratio = min(la, lb) / max(la, lb)
 return 0.6 + (0.3 * ratio)
 if status_a in (403, 404) and status_b == 200:
 return 0.75
 return 0.2

 for path, obj_id, mode, kind in uniq_tests:
 try:
 sa, ta, _ = self._get(path, headers_a)
 sb, tb, _ = self._get(path, headers_b)
 except Exception as e:
 notes.append(f"Request failed {path}: {e}")
 continue

 conf = score_suspect(sa, sb, ta, tb)

 # Only emit findings when we have notable signals
 if conf >= 0.75 or (conf >= 0.7 and mode == "cross"):
 findings.append(
 {
 "type": "idor",
 "severity": "high" if conf >= 0.8 else "medium",
 "confidence": round(conf, 2),
 "url": urljoin(self.base_url, path.lstrip("/")),
 "evidence": {
 "path": path,
 "mode": mode,
 "kind": kind,
 "account_a": {"status": sa, "body_len": len(ta)},
 "account_b": {"status": sb, "body_len": len(tb)},
 "object_id": obj_id,
 },
 "notes": "Differential access signal suggests possible BOLA/IDOR. Verify with proper tenant boundary test and sensitive field leakage.",
 }
 )

 if not findings:
 notes.append("No strong differential signals detected with common paths. Consider providing a known object endpoint pattern or add endpoint seeds.")

 return BOLAResult(success=True, findings=findings, notes=notes)

 def run_seeded_checks(
 self,
 headers_a: Dict[str, str],
 headers_b: Dict[str, str],
 ids_a: Dict[str, str],
 ids_b: Dict[str, str],
 endpoint_seeds: List[str],
 ) -> BOLAResult:
 notes: List[str] = []
 findings: List[Dict[str, Any]] = []

 if not endpoint_seeds:
 return BOLAResult(success=True, findings=[], notes=["No endpoint seeds provided"])

 user_id_a = ids_a.get("user_id") or ids_a.get("userid") or ids_a.get("id")
 user_id_b = ids_b.get("user_id") or ids_b.get("userid") or ids_b.get("id")
 acct_id_a = ids_a.get("account_id") or ids_a.get("accountid")
 acct_id_b = ids_b.get("account_id") or ids_b.get("accountid")

 repl = {
 "{id}": (user_id_a, user_id_b),
 "{user_id}": (user_id_a, user_id_b),
 "{account_id}": (acct_id_a, acct_id_b),
 }

 def normalize_seed(s: str) -> str:
 s = s.strip()
 if not s:
 return ""
 if s.startswith("http://") or s.startswith("https://"):
 if s.startswith(self.base_url):
 return "/" + s[len(self.base_url):].lstrip("/")
 return s
 return s if s.startswith("/") else "/" + s

 def score_suspect(status_a: int, status_b: int, body_a: str, body_b: str) -> float:
 if status_a == 200 and status_b == 200:
 la, lb = len(body_a), len(body_b)
 if la == 0 or lb == 0:
 return 0.2
 ratio = min(la, lb) / max(la, lb)
 return 0.55 + (0.35 * ratio)
 if status_a in (403, 404) and status_b == 200:
 return 0.75
 return 0.2

 seeds = []
 for s in endpoint_seeds:
 ns = normalize_seed(s)
 if ns:
 seeds.append(ns)

 seen = set()
 for seed in seeds:
 if seed in seen:
 continue
 seen.add(seed)

 expanded: List[Tuple[str, str]] = []
 expanded.append((seed, "seed"))

 for token, (va, vb) in repl.items():
 if token in seed and va and vb and va != vb:
 expanded.append((seed.replace(token, va), f"seed:{token}:self"))
 expanded.append((seed.replace(token, vb), f"seed:{token}:cross"))

 # If seed already contains an obvious numeric id, attempt to swap with other id (best-effort)
 if user_id_a and user_id_b and user_id_a != user_id_b:
 if re.search(r"/\d+(?:/|$)", seed):
 expanded.append((re.sub(r"/\d+(?:/|$)", f"/{user_id_a}/", seed), "seed:numeric:self"))
 expanded.append((re.sub(r"/\d+(?:/|$)", f"/{user_id_b}/", seed), "seed:numeric:cross"))

 for path, mode in expanded[:6]:
 try:
 sa, ta, _ = self._get(path, headers_a)
 sb, tb, _ = self._get(path, headers_b)
 except Exception as e:
 notes.append(f"Seed request failed {path}: {e}")
 continue

 conf = score_suspect(sa, sb, ta, tb)
 if conf >= 0.75:
 findings.append(
 {
 "type": "idor",
 "severity": "high" if conf >= 0.82 else "medium",
 "confidence": round(conf, 2),
 "url": urljoin(self.base_url, path.lstrip("/")),
 "evidence": {
 "seed": seed,
 "expanded_mode": mode,
 "account_a": {"status": sa, "body_len": len(ta)},
 "account_b": {"status": sb, "body_len": len(tb)},
 },
 "notes": "Seeded differential access suggests possible BOLA/IDOR. Validate with sensitive field leakage and tenant boundary confirmation.",
 }
 )

 if not findings:
 notes.append("No strong differential signals detected in seeded endpoints.")

 return BOLAResult(success=True, findings=findings, notes=notes)

def parse_headers_input(raw: str) -> Dict[str, str]:
 """Parse simple multi-line header input: 'Header: value' per line."""
 headers: Dict[str, str] = {}
 if not raw:
 return headers

 for line in raw.splitlines():
 line = line.strip()
 if not line or ":" not in line:
 continue
 k, v = line.split(":", 1)
 headers[k.strip()] = v.strip()

 # Reasonable defaults
 headers.setdefault("User-Agent", "Elengenix-BOLAHarness/2.0")
 headers.setdefault("Accept", "application/json, text/plain;q=0.9, */*;q=0.8")
 return headers

"""tools/object_id_permuter.py

Object ID Permuter for safe BOLA/IDOR testing via Access Control Matrix.

Purpose:
- Take endpoints with placeholders like {id}, {user_id}, {order_id}, {account_id}
- Permute using actual object IDs discovered for Account A and Account B
- Generate safe test matrix: A's ID vs B's ID on same endpoint pattern

Safety:
- GET-only execution (even in non-dry-run)
- DRY-RUN by default; execution requires explicit confirmation
- Rate-limited
- No destructive operations
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

logger = logging.getLogger("elengenix.object_id_permuter")

@dataclass
class PermutationCase:
 endpoint_template: str
 placeholder: str
 value_a: str
 value_b: str
 description: str

@dataclass
class PermutationResult:
 url_a: str
 url_b: str
 status_a: int
 status_b: int
 len_a: int
 len_b: int
 signal: str # ok / idor_suspect / error
 notes: str

class ObjectIDPermuter:
 """
 Generates permutations of endpoints using discovered object IDs.
 """

 # Common ID placeholder patterns seen in APIs
 ID_PATTERNS = [
 r"\{id\}",
 r"\{user_id\}",
 r"\{account_id\}",
 r"\{order_id\}",
 r"\{org_id\}",
 r"\{team_id\}",
 r"\{project_id\}",
 r"\{document_id\}",
 r"\{resource_id\}",
 r"\{item_id\}",
 ]

 def __init__(self, base_url: str, rate_limit_rps: float = 1.0, timeout: int = 15):
 self.base_url = base_url.rstrip("/") + "/"
 self.rate_limit_rps = max(0.2, float(rate_limit_rps))
 self.timeout = timeout
 self._last_ts = 0.0

 def _sleep(self) -> None:
 dt = time.time() - self._last_ts
 min_dt = 1.0 / self.rate_limit_rps
 if dt < min_dt:
 time.sleep(min_dt - dt)
 self._last_ts = time.time()

 def discover_identities(
 self, headers: Dict[str, str], seed_endpoints: Optional[List[str]] = None
 ) -> Dict[str, str]:
 """
 Light identity discovery via common endpoints.
 Returns best-effort mapping of id/user_id/account_id.
 """
 # Lazy import to avoid circular deps
 try:
 from tools.bola_harness import BOLAHarness

 harness = BOLAHarness(
 base_url=self.base_url,
 rate_limit_rps=self.rate_limit_rps,
 timeout=self.timeout,
 )
 ids, _, _ = harness.discover_identities(headers, headers)
 return ids
 except Exception as e:
 logger.debug(f"Identity discovery failed: {e}")
 return {}

 def find_placeholders(self, endpoint: str) -> List[str]:
 """Find placeholder patterns in an endpoint template."""
 found = []
 for pattern in self.ID_PATTERNS:
 if re.search(pattern, endpoint):
 # Normalize to {placeholder_name}
 ph = pattern.replace(r"\{", "{").replace(r"\}", "}")
 found.append(ph)
 return found

 def generate_permutations(
 self,
 endpoint_template: str,
 ids_a: Dict[str, str],
 ids_b: Dict[str, str],
 ) -> List[PermutationCase]:
 """
 Generate permutation cases for an endpoint template.
 For each placeholder found, create A vs B permutations.
 """
 cases: List[PermutationCase] = []
 placeholders = self.find_placeholders(endpoint_template)

 for ph in placeholders:
 # Map placeholder to discovered keys
 key = ph.strip("{}")
 val_a = ids_a.get(key) or ids_a.get("id") or ids_a.get("user_id")
 val_b = ids_b.get(key) or ids_b.get("id") or ids_b.get("user_id")

 if val_a and val_b:
 cases.append(
 PermutationCase(
 endpoint_template=endpoint_template,
 placeholder=ph,
 value_a=val_a,
 value_b=val_b,
 description=f"Test {ph} with A={val_a} vs B={val_b}",
 )
 )
 return cases

 def execute_permutation(
 self,
 case: PermutationCase,
 headers_a: Dict[str, str],
 headers_b: Dict[str, str],
 dry_run: bool = True,
 ) -> Optional[PermutationResult]:
 """
 Execute a single permutation case safely.
 - Request A accesses endpoint with value_a using headers_a
 - Request B accesses endpoint with value_b using headers_b
 - Then cross-test: A tries B's ID (potential IDOR)
 """
 if dry_run:
 return None

 url_a = case.endpoint_template.replace(case.placeholder, str(case.value_a))
 url_b = case.endpoint_template.replace(case.placeholder, str(case.value_b))
 if not url_a.startswith("http"):
 url_a = urljoin(self.base_url, url_a.lstrip("/"))
 if not url_b.startswith("http"):
 url_b = urljoin(self.base_url, url_b.lstrip("/"))

 # Cross-attempt: A tries to access B's resource (potential IDOR)
 url_cross = case.endpoint_template.replace(case.placeholder, str(case.value_b))
 if not url_cross.startswith("http"):
 url_cross = urljoin(self.base_url, url_cross.lstrip("/"))

 def fetch(url: str, hdr: Dict[str, str]) -> Tuple[int, str]:
 self._sleep()
 try:
 r = requests.get(
 url, headers=hdr, timeout=self.timeout, allow_redirects=False
 )
 return r.status_code, r.text or ""
 except Exception as e:
 return 0, str(e)

 sa, ta = fetch(url_a, headers_a)
 sb, tb = fetch(url_b, headers_b)
 la, lb = len(ta), len(tb)

 # Cross attempt: A accessing B's ID
 sc, tc = fetch(url_cross, headers_a)

 signal = "ok"
 notes = ""

 # IDOR heuristic: A can access B's resource (cross-success while self also success)
 if sa == 200 and sc == 200 and case.value_a != case.value_b:
 signal = "idor_suspect"
 notes = f"IDOR/BOLA suspected: Account A can access B's {case.placeholder} ({case.value_b}) at {url_cross}"

 # Also flag if B can access A (we can detect by checking B vs A cross too, but keep simple)
 return PermutationResult(
 url_a=url_a,
 url_b=url_b,
 status_a=sa,
 status_b=sb,
 len_a=la,
 len_b=lb,
 signal=signal,
 notes=notes,
 )

 def run_matrix_on_endpoints(
 self,
 endpoint_templates: List[str],
 headers_a: Dict[str, str],
 headers_b: Dict[str, str],
 dry_run: bool = True,
 ) -> Tuple[List[PermutationCase], List[PermutationResult]]:
 """
 Run full matrix: discover IDs for A and B, generate permutations, execute.
 Returns (cases, results).
 """
 ids_a = self.discover_identities(headers_a)
 ids_b = self.discover_identities(headers_b)

 all_cases: List[PermutationCase] = []
 all_results: List[PermutationResult] = []

 for tmpl in endpoint_templates:
 cases = self.generate_permutations(tmpl, ids_a, ids_b)
 all_cases.extend(cases)

 if dry_run:
 return all_cases, []

 for case in all_cases:
 res = self.execute_permutation(case, headers_a, headers_b, dry_run=False)
 if res:
 all_results.append(res)

 return all_cases, all_results

def format_permutation_cases(cases: List[PermutationCase]) -> str:
 lines: List[str] = []
 lines.append(f"Generated {len(cases)} permutation cases:")
 for c in cases:
 lines.append(f"- {c.endpoint_template} [{c.placeholder}] A={c.value_a} B={c.value_b}")
 return "\n".join(lines)

def format_permutation_results(results: List[PermutationResult]) -> str:
 lines: List[str] = []
 lines.append(f"Executed {len(results)} permutations:")
 for r in results:
 lines.append(f"- [{r.signal}] A={r.status_a}({r.len_a}) vs B={r.status_b}({r.len_b})")
 if r.notes:
 lines.append(f" ! {r.notes}")
 return "\n".join(lines)

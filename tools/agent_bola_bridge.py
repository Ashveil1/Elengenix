"""tools/agent_bola_bridge.py

Bridge between ElengenixAgent and BOLAHarness for autonomous BOLA/IDOR testing.

Purpose:
- Consume MissionState hypotheses (authz/idor/bola tags)
- Propose differential test plans to agent
- Execute via governance-gated approval
- Store results back to MissionState as findings

Safety:
- All BOLA tests are GET-only and rate-limited
- Requires governance approval before execution
- Audit trail via MissionState ledger
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from tools.bola_harness import BOLAHarness, parse_headers_input
from tools.mission_state import MissionState

logger = logging.getLogger("elengenix.agent_bola_bridge")

class AgentBOLABridge:
 """Bridge to run BOLA harness from agent loop with governance."""

 def __init__(self, base_url: str, headers_a: Dict[str, str], headers_b: Dict[str, str], rate_limit_rps: float = 1.0):
 self.base_url = base_url
 self.headers_a = headers_a
 self.headers_b = headers_b
 self.harness = BOLAHarness(base_url=base_url, rate_limit_rps=rate_limit_rps)

 def propose_plan_from_hypotheses(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
 """
 Inspect MissionState hypotheses and propose a BOLA test plan.
 Returns plan dict if actionable hypotheses found, else None.
 """
 hyps = snapshot.get("hypotheses", [])
 if not hyps:
 return None

 # Collect endpoint hints from hypotheses
 seeds: List[str] = []
 tags_hit = False

 for h in hyps:
 tags = h.get("tags", [])
 if isinstance(tags, str):
 tags = json.loads(tags) if tags.startswith("[") else tags.split(",")
 tag_set = set([t.lower().strip() for t in tags])
 if tag_set & {"authz", "idor", "bola", "user_object", "account_object"}:
 tags_hit = True
 # Try to extract suggested_tests from evidence
 ev = h.get("evidence", {})
 if isinstance(ev, str):
 try:
 ev = json.loads(ev)
 except Exception:
 ev = {}
 tests = ev.get("suggested_tests", [])
 for t in tests:
 if isinstance(t, dict):
 # Prefer endpoints from suggestions
 tgt = t.get("target", "")
 if tgt and tgt.startswith("http"):
 seeds.append(tgt)
 elif tgt:
 seeds.append(f"/api/{tgt.strip('/')}")

 if not tags_hit:
 return None

 # Build seeds list
 default_seeds = [
 "/api/users/{user_id}",
 "/api/accounts/{account_id}",
 "/api/orders",
 "/api/invoices",
 ]
 for s in default_seeds:
 if s not in seeds:
 seeds.append(s)

 if not seeds:
 return None

 return {
 "type": "bola_differential",
 "description": "Differential access test between Account A and Account B using seeded endpoints",
 "seeds": seeds,
 "estimated_requests": len(seeds) * 2 * 2, # seeds * accounts * expansions rough
 "risk": "medium", # GET only, but active scanning
 }

 def execute_plan(
 self,
 mission_state: MissionState,
 plan: Dict[str, Any],
 ) -> Dict[str, Any]:
 """
 Execute BOLA plan and store results to MissionState.
 Returns summary dict.
 """
 seeds = plan.get("seeds", [])

 # Discover identities first
 ids_a, ids_b, notes = self.harness.discover_identities(self.headers_a, self.headers_b)
 for n in notes:
 try:
 mission_state.add_ledger_entry(
 entry_id=f"bola:discover:{n[:40]}",
 kind="bola_discover",
 action={"note": n},
 result={},
 )
 except Exception as e:
 logger.debug(f"BOLA ledger note failed: {e}")

 # Run seeded checks
 result = self.harness.run_seeded_checks(
 self.headers_a, self.headers_b, ids_a, ids_b, seeds
 )

 # Store findings as facts and ledger entries
 for i, finding in enumerate(result.findings):
 try:
 mission_state.add_fact(
 fact_id=f"bola:finding:{i}",
 category="idor",
 statement=f"{finding.get('type','idor')} at {finding.get('url','')} (conf={finding.get('confidence')})",
 confidence=finding.get("confidence", 0.5),
 evidence=finding.get("evidence", {}),
 )
 except Exception as e:
 logger.debug(f"BOLA fact add failed: {e}")

 summary = {
 "seeds_tested": len(seeds),
 "findings_count": len(result.findings),
 "notes": result.notes,
 }

 try:
 mission_state.add_ledger_entry(
 entry_id="bola:execute:summary",
 kind="bola_execute",
 action=plan,
 result=summary,
 )
 except Exception as e:
 logger.debug(f"BOLA ledger summary failed: {e}")

 return summary

def extract_headers_from_mission_state(snapshot: Dict[str, Any]) -> tuple:
 """
 Attempt to extract headers for Account A/B from mission state.
 Returns (headers_a, headers_b) or (None, None) if not found.
 """
 # This is a placeholder: in real scenario, headers would be provided via UI or env
 # For now, we return None to signal that manual CLI flow is preferred
 return (None, None)

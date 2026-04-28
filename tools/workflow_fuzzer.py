"""tools/workflow_fuzzer.py

Workflow / Business-Logic Fuzzer (Stateful) for web apps.

Goal:
- Model common bug bounty workflows as small state machines
- Generate and execute SAFE test plans (GET by default)
- Detect business-logic anomalies (double-spend patterns, coupon abuse hints, role transitions)

Safety:
- Default mode is DRY-RUN (no requests)
- If execution is enabled, it is GET-only unless explicitly allowed
- Intended to be driven by governance/HITL approvals
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

logger = logging.getLogger("elengenix.workflow_fuzzer")


@dataclass
class WorkflowStep:
    name: str
    method: str
    path: str
    params: Dict[str, Any] = field(default_factory=dict)
    note: str = ""


@dataclass
class WorkflowPlan:
    plan_id: str
    title: str
    description: str
    steps: List[WorkflowStep]
    risk: str  # low/medium/high
    assumptions: List[str] = field(default_factory=list)


@dataclass
class WorkflowResult:
    success: bool
    observations: List[Dict[str, Any]]
    anomalies: List[Dict[str, Any]]
    notes: List[str]


class WorkflowFuzzer:
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

    def propose_common_plans(self) -> List[WorkflowPlan]:
        """Return generic workflow plans (you can edit endpoints/paths)."""
        ts = int(time.time())
        plans: List[WorkflowPlan] = []

        plans.append(
            WorkflowPlan(
                plan_id=f"coupon-{ts}",
                title="Coupon / Discount Abuse Probe (Safe)",
                description="Look for coupon validation inconsistencies and repeated apply/remove flows (GET-only probe by default).",
                risk="medium",
                assumptions=["You will replace paths with real endpoints", "GET endpoints exist for viewing cart/quote"],
                steps=[
                    WorkflowStep("view_cart", "GET", "/cart"),
                    WorkflowStep("view_checkout_quote", "GET", "/checkout/quote"),
                    WorkflowStep("view_coupon_endpoint_hint", "GET", "/api/coupons"),
                ],
            )
        )

        plans.append(
            WorkflowPlan(
                plan_id=f"order-{ts}",
                title="Order State Transition Probe (Safe)",
                description="Detect inconsistent order state exposure and privilege boundaries (GET-only).",
                risk="medium",
                assumptions=["Order endpoints exist (e.g., /api/orders/{id})"],
                steps=[
                    WorkflowStep("list_orders", "GET", "/api/orders"),
                    WorkflowStep("order_detail_template", "GET", "/api/orders/{id}"),
                ],
            )
        )

        plans.append(
            WorkflowPlan(
                plan_id=f"invite-{ts}",
                title="Invite / Role Transition Probe (Safe)",
                description="Check if invite/role endpoints leak tokens or allow unauthorized role change (read-only probe).",
                risk="medium",
                assumptions=["Endpoints exist for team/org management"],
                steps=[
                    WorkflowStep("list_orgs", "GET", "/api/orgs"),
                    WorkflowStep("list_members", "GET", "/api/orgs/{id}/members"),
                ],
            )
        )

        return plans

    def execute_plan(
        self,
        plan: WorkflowPlan,
        headers: Dict[str, str],
        allow_non_get: bool = False,
        dry_run: bool = True,
        template_vars: Optional[Dict[str, str]] = None,
    ) -> WorkflowResult:
        template_vars = template_vars or {}
        observations: List[Dict[str, Any]] = []
        anomalies: List[Dict[str, Any]] = []
        notes: List[str] = []

        for step in plan.steps:
            method = step.method.upper()
            path = step.path
            for k, v in template_vars.items():
                path = path.replace("{" + k + "}", str(v))

            url = urljoin(self.base_url, path.lstrip("/"))

            if method != "GET" and not allow_non_get:
                notes.append(f"Skipped non-GET step '{step.name}' ({method} {path})")
                continue

            if dry_run:
                observations.append(
                    {
                        "step": step.name,
                        "method": method,
                        "url": url,
                        "dry_run": True,
                        "params": step.params,
                        "note": step.note,
                    }
                )
                continue

            self._sleep()
            try:
                r = requests.request(
                    method,
                    url,
                    headers=headers,
                    params=step.params if method == "GET" else None,
                    json=step.params if method != "GET" else None,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                body = (r.text or "")[:800]
                observations.append(
                    {
                        "step": step.name,
                        "method": method,
                        "url": url,
                        "status": r.status_code,
                        "len": len(r.text or ""),
                        "body_snip": body,
                    }
                )

                # Simple anomaly heuristics
                if r.status_code >= 500:
                    anomalies.append(
                        {
                            "type": "server_error",
                            "step": step.name,
                            "url": url,
                            "status": r.status_code,
                            "note": "Potential workflow edge-case causing server error.",
                        }
                    )
                if "coupon" in path.lower() and r.status_code == 200 and "error" not in body.lower():
                    # weak heuristic
                    anomalies.append(
                        {
                            "type": "coupon_logic_hint",
                            "step": step.name,
                            "url": url,
                            "status": r.status_code,
                            "note": "Coupon endpoint responded OK; validate business rules (reuse, stacking, expiry).",
                        }
                    )

            except Exception as e:
                anomalies.append(
                    {
                        "type": "request_error",
                        "step": step.name,
                        "url": url,
                        "error": str(e),
                    }
                )

        return WorkflowResult(success=True, observations=observations, anomalies=anomalies, notes=notes)


def format_workflow_plans(plans: List[WorkflowPlan]) -> str:
    lines: List[str] = []
    for i, p in enumerate(plans, 1):
        lines.append(f"{i}. {p.title} [risk={p.risk}] (id={p.plan_id})")
        lines.append(f"   {p.description}")
        for s in p.steps:
            lines.append(f"   - {s.method} {s.path}  ({s.name})")
        lines.append("")
    return "\n".join(lines)

"""tools/logic_flaw_engine.py — Business Logic Vulnerability Analyzer.

A multi-detector engine that finds business-logic flaws by static analysis
of endpoint definitions (and optional dynamic race-condition bursts).

Public API (tested by tests/test_logic_flaw_engine.py):
    Severity, DetectorCategory, Evidence, LogicFinding, LogicFlawConfig
    normalize_endpoint, is_price_endpoint, is_discount_endpoint,
    is_auth_endpoint, is_workflow_endpoint
    UUIDV1Decoder
    PriceManipulationDetector, RaceConditionDetector,
    StateMachineBypassDetector, AuthLogicDetector,
    AuthorizationDetector, WorkflowIntegrityDetector,
    BusinessConstraintDetector
    InferenceEngine, CorrelationEngine
    LogicFlawEngine

Backward-compatible aliases: LogicFlaw, LogicFlawResult
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("elengenix.logic_flaw_engine")


# ═══════════════════════════════════════════════════════════════════════════
# Severity
# ═══════════════════════════════════════════════════════════════════════════


class Severity(Enum):
    """Severity level with an associated numeric weight."""

    INFO = ("info", 1)
    LOW = ("low", 2)
    MEDIUM = ("medium", 5)
    HIGH = ("high", 10)
    CRITICAL = ("critical", 20)

    def __init__(self, value: str, weight: int) -> None:
        self._value_ = value
        self.weight = weight


# ═══════════════════════════════════════════════════════════════════════════
# DetectorCategory
# ═══════════════════════════════════════════════════════════════════════════


class DetectorCategory(Enum):
    """Logical grouping of detectors."""

    PRICE_MANIPULATION = "price_manipulation"
    RACE_CONDITION = "race_condition"
    STATE_MACHINE_BYPASS = "state_machine_bypass"
    AUTH_LOGIC = "auth_logic"
    AUTHORIZATION = "authorization"
    WORKFLOW_INTEGRITY = "workflow_integrity"
    BUSINESS_CONSTRAINT = "business_constraint"


# Default CWE mapping per category
_CATEGORY_CWES: Dict[DetectorCategory, List[str]] = {
    DetectorCategory.PRICE_MANIPULATION: ["CWE-20", "CWE-841"],
    DetectorCategory.RACE_CONDITION: ["CWE-362", "CWE-367"],
    DetectorCategory.STATE_MACHINE_BYPASS: ["CWE-838", "CWE-639"],
    DetectorCategory.AUTH_LOGIC: ["CWE-287", "CWE-384", "CWE-640"],
    DetectorCategory.AUTHORIZATION: ["CWE-284", "CWE-639", "CWE-285"],
    DetectorCategory.WORKFLOW_INTEGRITY: ["CWE-837", "CWE-697"],
    DetectorCategory.BUSINESS_CONSTRAINT: ["CWE-20", "CWE-841"],
}


# ═══════════════════════════════════════════════════════════════════════════
# Evidence
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class Evidence:
    """One piece of evidence supporting a finding."""

    kind: str
    description: str
    data: Dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════
# LogicFinding
# ═══════════════════════════════════════════════════════════════════════════


def _gen_finding_id() -> str:
    """Generate a unique finding ID: LFE- + 12 hex chars."""
    return "LFE-" + secrets.token_hex(6)


@dataclass
class LogicFinding:
    """A single business-logic vulnerability finding."""

    title: str
    target: str
    endpoint: str
    description: str = ""
    impact: str = ""
    remediation: str = ""
    category: DetectorCategory = DetectorCategory.BUSINESS_CONSTRAINT
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    parameter: str = ""
    tags: List[str] = field(default_factory=list)
    cwe: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    finding_id: str = ""
    discovered_at: float = 0.0
    novelty: float = 0.5
    impact_score: float = 0.0
    reproducibility: float = 0.5
    risk_score: float = 0.0

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = _gen_finding_id()
        if not self.discovered_at:
            self.discovered_at = time.time()
        if not self.cwe:
            self.cwe = list(_CATEGORY_CWES.get(self.category, ["CWE-20"]))

    def add_evidence(
        self, kind: str, description: str, data: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add a piece of evidence to this finding."""
        self.evidence.append(Evidence(kind=kind, description=description, data=data or {}))

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "target": self.target,
            "endpoint": self.endpoint,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "parameter": self.parameter,
            "tags": list(self.tags),
            "cwe": list(self.cwe),
            "evidence": [
                {"kind": e.kind, "description": e.description, "data": e.data}
                for e in self.evidence
            ],
            "discovered_at": self.discovered_at,
            "novelty": self.novelty,
            "impact_score": self.impact_score,
            "reproducibility": self.reproducibility,
            "risk_score": self.risk_score,
        }


# ═══════════════════════════════════════════════════════════════════════════
# LogicFlawConfig
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class LogicFlawConfig:
    """Configuration for the logic flaw engine."""

    min_confidence: float = 0.0
    min_risk_score: float = 0.0
    http_timeout_seconds: float = 5.0
    race_default_concurrency: int = 8
    race_default_attempts: int = 3
    enable_dynamic_race: bool = True
    enable_inference: bool = True
    enable_correlation: bool = True


# ═══════════════════════════════════════════════════════════════════════════
# Endpoint normalisation
# ═══════════════════════════════════════════════════════════════════════════


def normalize_endpoint(ep: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Normalise an endpoint definition to a standard dict.

    Accepts either a URL string or a dict with url/method/params/body/headers.
    """
    if isinstance(ep, str):
        parsed = urlparse(ep)
        qs = parse_qs(parsed.query)
        params: Dict[str, Any] = {}
        for k, v in qs.items():
            params[k] = v[0] if len(v) == 1 else v
        return {
            "url": ep,
            "method": "GET",
            "params": params,
            "body": {},
            "headers": {},
        }

    url = ep.get("url", "")
    method = ep.get("method", "GET").upper()
    params = dict(ep.get("params", {}))
    body = dict(ep.get("body", {}))
    headers = dict(ep.get("headers", {}))

    # Parse query params from URL if no explicit params
    if not params and "?" in url:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for k, v in qs.items():
            params[k] = v[0] if len(v) == 1 else v

    return {
        "url": url,
        "method": method,
        "params": params,
        "body": body,
        "headers": headers,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Helper keyword predicates
# ═══════════════════════════════════════════════════════════════════════════


_PRICE_KEYWORDS = {
    "price",
    "amount",
    "cost",
    "total",
    "pay",
    "charge",
    "transfer",
    "deposit",
    "withdraw",
    "order",
    "cart",
}
_DISCOUNT_KEYWORDS = {"coupon", "discount", "promo", "voucher", "redeem"}
_AUTH_KEYWORDS = {
    "login",
    "auth",
    "signin",
    "token",
    "password",
    "reset",
    "2fa",
    "otp",
    "session",
    "oauth",
    "remember",
}
_WORKFLOW_KEYWORDS = {"step", "stage", "phase", "onboard", "wizard", "flow"}


def _ep_url_lower(ep: Dict[str, Any]) -> str:
    return ep.get("url", "").lower()


def _ep_body_keys_lower(ep: Dict[str, Any]) -> set:
    body = ep.get("body", {})
    return {str(k).lower() for k in body.keys()} if isinstance(body, dict) else set()


def _ep_param_keys_lower(ep: Dict[str, Any]) -> set:
    params = ep.get("params", {})
    return {str(k).lower() for k in params.keys()} if isinstance(params, dict) else set()


def is_price_endpoint(ep: Union[str, Dict[str, Any]]) -> bool:
    """Check if an endpoint is price/payment related."""
    ep = normalize_endpoint(ep)
    url = _ep_url_lower(ep)
    body_keys = _ep_body_keys_lower(ep)
    all_keys = body_keys | _ep_param_keys_lower(ep)
    return any(kw in url or kw in all_keys for kw in _PRICE_KEYWORDS)


def is_discount_endpoint(ep: Union[str, Dict[str, Any]]) -> bool:
    """Check if an endpoint is discount/coupon related."""
    ep = normalize_endpoint(ep)
    url = _ep_url_lower(ep)
    all_keys = _ep_body_keys_lower(ep) | _ep_param_keys_lower(ep)
    return any(kw in url or kw in all_keys for kw in _DISCOUNT_KEYWORDS)


def is_auth_endpoint(ep: Union[str, Dict[str, Any]]) -> bool:
    """Check if an endpoint is authentication related."""
    ep = normalize_endpoint(ep)
    url = _ep_url_lower(ep)
    return any(kw in url for kw in _AUTH_KEYWORDS)


def is_workflow_endpoint(ep: Union[str, Dict[str, Any]]) -> bool:
    """Check if an endpoint is workflow/multi-step related."""
    ep = normalize_endpoint(ep)
    url = _ep_url_lower(ep)
    return any(kw in url for kw in _WORKFLOW_KEYWORDS)


# ═══════════════════════════════════════════════════════════════════════════
# UUID v1 Decoder
# ═══════════════════════════════════════════════════════════════════════════


class UUIDV1Decoder:
    """Utility to detect and decode UUID v1 timestamps."""

    # UUID v1 epoch: 1582-10-15 00:00:00 UTC in 100ns intervals
    _UUID_EPOCH = 0x01B21DD213814000
    _UUID_RE = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )

    @staticmethod
    def is_uuid_v1(uuid_str: str) -> bool:
        """Check if a string is a UUID v1."""
        if not UUIDV1Decoder._UUID_RE.match(uuid_str):
            return False
        try:
            u = uuid.UUID(uuid_str)
            return u.version == 1
        except (ValueError, AttributeError):
            return False

    @staticmethod
    def extract_timestamp_ms(uuid_str: str) -> Optional[int]:
        """Extract a Unix timestamp (ms) from a UUID v1.

        Returns None if the UUID is not version 1.
        """
        if not UUIDV1Decoder.is_uuid_v1(uuid_str):
            return None
        try:
            u = uuid.UUID(uuid_str)
            # The time field is in 100ns intervals since 1582-10-15
            ts_100ns = u.time
            # Convert to Unix epoch (ms)
            ts_ms = (ts_100ns - UUIDV1Decoder._UUID_EPOCH) // 10000
            return ts_ms
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════════
# Base detector
# ═══════════════════════════════════════════════════════════════════════════


class BaseDetector:
    """Base class for all logic-flaw detectors."""

    category: DetectorCategory = DetectorCategory.BUSINESS_CONSTRAINT

    def __init__(self, config: Optional[LogicFlawConfig] = None) -> None:
        self.config = config or LogicFlawConfig()
        self._client: Any = None

    async def detect(
        self, target: str, endpoints: List[Union[str, Dict[str, Any]]]
    ) -> List[LogicFinding]:
        """Run detection. Subclasses must implement this."""
        raise NotImplementedError

    @staticmethod
    def _normalize_all(endpoints: List[Union[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
        return [normalize_endpoint(ep) for ep in endpoints]


# ═══════════════════════════════════════════════════════════════════════════
# Price manipulation detector (detectors[0])
# ═══════════════════════════════════════════════════════════════════════════


_ZERO_DECIMAL_CURRENCIES = {"JPY", "KRW", "VND", "CLP", "ISK"}


class PriceManipulationDetector(BaseDetector):
    """Detects price/amount manipulation vulnerabilities."""

    category = DetectorCategory.PRICE_MANIPULATION

    async def detect(
        self, target: str, endpoints: List[Union[str, Dict[str, Any]]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        for ep in self._normalize_all(endpoints):
            if not (is_price_endpoint(ep) or is_discount_endpoint(ep)):
                continue
            findings.extend(self._check_endpoint(ep, target))
        return findings

    def _check_endpoint(self, ep: Dict[str, Any], target: str) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        url = ep.get("url", "")
        body = ep.get("body", {})
        params = ep.get("params", {})
        all_fields = {**params, **body}

        # Negative amount / price
        for param_name in ("amount", "price", "cost", "total"):
            if param_name in all_fields:
                val = all_fields[param_name]
                if isinstance(val, (int, float)) and val >= 0:
                    findings.append(
                        LogicFinding(
                            title=f"Negative {param_name} accepted",
                            target=target,
                            endpoint=url,
                            description=f"Endpoint accepts negative {param_name} via parameter '{param_name}'.",
                            category=self.category,
                            severity=Severity.HIGH,
                            confidence=0.7,
                            parameter=param_name,
                            tags=["negative_amount", "price_manipulation"],
                            remediation=f"Validate that {param_name} cannot be negative.",
                        )
                    )
                    findings[-1].add_evidence(
                        "static_pattern",
                        f"Parameter '{param_name}' present with value {val}",
                        {"parameter": param_name, "value": val},
                    )

        # Quantity zero / overflow
        for param_name in ("quantity", "qty", "count"):
            if param_name in all_fields:
                val = all_fields[param_name]
                findings.append(
                    LogicFinding(
                        title=f"Quantity validation missing for '{param_name}'",
                        target=target,
                        endpoint=url,
                        description=f"Endpoint accepts arbitrary quantity via '{param_name}' — "
                        f"zero, negative, or overflow values may be accepted.",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        parameter=param_name,
                        tags=["quantity_manipulation"],
                        remediation="Validate quantity against stock limits and positive range.",
                    )
                )
                findings[-1].add_evidence(
                    "static_pattern",
                    f"Quantity parameter '{param_name}' found",
                    {"parameter": param_name, "value": val},
                )

        # Integer overflow payloads
        if any(p in all_fields for p in ("amount", "price", "cost", "total")):
            param_name = next(p for p in ("amount", "price", "cost", "total") if p in all_fields)
            overflow_payloads = [2**31 - 1, 2**63 - 1, 10**10, 10**12, 999999999999]
            findings.append(
                LogicFinding(
                    title=f"Integer overflow risk on '{param_name}'",
                    target=target,
                    endpoint=url,
                    description=f"Parameter '{param_name}' may be vulnerable to integer overflow.",
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=0.5,
                    parameter=param_name,
                    tags=["integer_overflow"],
                    remediation="Use safe integer parsing and range validation.",
                )
            )
            findings[-1].add_evidence(
                "static_pattern",
                "Overflow payloads generated",
                {"payloads": overflow_payloads, "parameter": param_name},
            )

        # Currency confusion
        currency = all_fields.get("currency", "")
        if isinstance(currency, str) and currency.upper() in _ZERO_DECIMAL_CURRENCIES:
            findings.append(
                LogicFinding(
                    title=f"Currency confusion: {currency.upper()} treated as decimal currency",
                    target=target,
                    endpoint=url,
                    description=f"Currency '{currency.upper()}' is a zero-decimal currency. "
                    f"If amounts are in cents, sending raw values may bypass validation.",
                    category=self.category,
                    severity=Severity.CRITICAL,
                    confidence=0.7,
                    parameter="currency",
                    tags=["currency_confusion", "decimal_mismatch"],
                    remediation="Normalize all amounts to the smallest currency unit before validation.",
                )
            )

        # Discount stacking
        if is_discount_endpoint(ep) or "coupon" in all_fields:
            findings.append(
                LogicFinding(
                    title="Coupon discount stacking / reuse not enforced",
                    target=target,
                    endpoint=url,
                    description="Endpoint accepts coupon codes without single-use enforcement, "
                    "allowing stacking or reuse abuse.",
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=0.6,
                    parameter="coupon",
                    tags=["discount_stacking", "coupon_reuse"],
                    remediation="Track coupon usage server-side and enforce single-use per user.",
                )
            )

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# Race condition detector (detectors[1])
# ═══════════════════════════════════════════════════════════════════════════


class RaceConditionDetector(BaseDetector):
    """Detects race conditions in business flows."""

    category = DetectorCategory.RACE_CONDITION

    _RACE_KEYWORDS = {
        "transfer",
        "withdraw",
        "deposit",
        "payment",
        "coupon",
        "refund",
        "checkout",
        "apply",
    }

    async def detect(
        self, target: str, endpoints: List[Union[str, Dict[str, Any]]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        for ep in self._normalize_all(endpoints):
            method = ep.get("method", "GET").upper()
            if method == "GET":
                continue
            url = ep.get("url", "").lower()
            if not any(kw in url for kw in self._RACE_KEYWORDS):
                continue
            findings.append(
                LogicFinding(
                    title=f"Race condition risk on {ep.get('url', '')}",
                    target=target,
                    endpoint=ep.get("url", ""),
                    description="Endpoint performs a financial/state mutation without atomicity guarantees. "
                    "Concurrent requests may exploit TOCTOU windows.",
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=0.6,
                    tags=["race", "toctou"],
                    remediation="Use database-level locking, atomic operations, or idempotency keys.",
                )
            )
            findings[-1].add_evidence(
                "static_pattern",
                "Race-prone endpoint detected by keyword heuristic",
                {"url": ep.get("url", ""), "method": method},
            )

        # Dynamic burst if enabled and client available
        if self.config.enable_dynamic_race and self._client:
            for ep in self._normalize_all(endpoints):
                method = ep.get("method", "GET").upper()
                if method == "GET":
                    continue
                url = ep.get("url", "").lower()
                if any(kw in url for kw in self._RACE_KEYWORDS):
                    try:
                        await self._burst_test(ep, target, findings)
                    except Exception as e:
                        logger.debug("Burst test failed: %s", e)

        return findings

    async def _burst_test(
        self, ep: Dict[str, Any], target: str, findings: List[LogicFinding]
    ) -> None:
        """Send concurrent requests to detect race conditions."""
        import aiohttp

        url = ep.get("url", "")
        if not url.startswith("http"):
            return

        body = ep.get("body", {})
        concurrency = self.config.race_default_concurrency
        attempts = self.config.race_default_attempts

        async def _single(session: aiohttp.ClientSession) -> int:
            try:
                async with session.post(
                    url,
                    json=body,
                    timeout=aiohttp.ClientTimeout(total=self.config.http_timeout_seconds),
                ) as resp:
                    return resp.status
            except Exception:
                return -1

        async with aiohttp.ClientSession() as session:
            for _ in range(attempts):
                tasks = [_single(session) for _ in range(concurrency)]
                results = await asyncio.gather(*tasks)
                if results.count(200) > 1:
                    f = LogicFinding(
                        title=f"Dynamic race condition confirmed on {url}",
                        target=target,
                        endpoint=url,
                        description=f"Sent {concurrency} concurrent requests, "
                        f"got {results.count(200)} successful responses.",
                        category=self.category,
                        severity=Severity.CRITICAL,
                        confidence=0.8,
                        tags=["race", "toctou", "dynamic"],
                        remediation="Implement server-side locking or idempotency.",
                    )
                    f.add_evidence(
                        "burst_response",
                        f"Concurrent burst: {results}",
                        {"samples": len(results), "successes": results.count(200)},
                    )
                    findings.append(f)
                    break


# ═══════════════════════════════════════════════════════════════════════════
# State machine bypass detector (detectors[2])
# ═══════════════════════════════════════════════════════════════════════════


class StateMachineBypassDetector(BaseDetector):
    """Detects state-machine / workflow bypass vulnerabilities."""

    category = DetectorCategory.STATE_MACHINE_BYPASS

    async def detect(
        self, target: str, endpoints: List[Union[str, Dict[str, Any]]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        eps = self._normalize_all(endpoints)

        for ep in eps:
            url = ep.get("url", "")
            url_lower = url.lower()
            params = ep.get("params", {})

            # Skip step via query param
            if "step" in params or "state" in params:
                step_val = params.get("step", params.get("state", ""))
                findings.append(
                    LogicFinding(
                        title=f"State-skip risk: step/state controllable via query param",
                        target=target,
                        endpoint=url,
                        description=f"Endpoint accepts 'step'/'state' as a client-controlled parameter "
                        f"(value={step_val}). Users may skip workflow steps.",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=0.7,
                        tags=["state_skip", "workflow_bypass"],
                        remediation="Track workflow state server-side, never trust client-supplied step values.",
                    )
                )

            # Deep-linkable steps
            step_match = re.search(r"/(?:onboard|wizard|flow|step)[/-](\d+)", url_lower)
            if step_match:
                step_num = int(step_match.group(1))
                if step_num > 1:
                    findings.append(
                        LogicFinding(
                            title=f"Deep-linkable workflow step {step_num}",
                            target=target,
                            endpoint=url,
                            description=f"Step {step_num} is accessible via direct URL, bypassing earlier steps.",
                            category=self.category,
                            severity=Severity.MEDIUM,
                            confidence=0.6,
                            tags=["deep_link", "workflow_bypass"],
                            remediation="Validate that previous steps were completed before allowing access to later steps.",
                        )
                    )

            # Admin path
            if "/admin" in url_lower:
                findings.append(
                    LogicFinding(
                        title=f"Admin path accessible without auth check",
                        target=target,
                        endpoint=url,
                        description="Admin endpoint is reachable — verify authorization is enforced.",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=0.6,
                        tags=["admin", "privilege_escalation"],
                        remediation="Enforce strict authorization on all admin paths.",
                    )
                )

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# Auth logic detector (detectors[3])
# ═══════════════════════════════════════════════════════════════════════════


class AuthLogicDetector(BaseDetector):
    """Detects authentication logic flaws."""

    category = DetectorCategory.AUTH_LOGIC

    async def detect(
        self, target: str, endpoints: List[Union[str, Dict[str, Any]]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        for ep in self._normalize_all(endpoints):
            url = ep.get("url", "").lower()
            body = ep.get("body", {})
            params = ep.get("params", {})
            all_fields = {**params, **body}

            # Reset token / forgot password
            if "forgot" in url or "reset" in url:
                findings.append(
                    LogicFinding(
                        title="Password reset token entropy / predictability risk",
                        target=target,
                        endpoint=ep.get("url", ""),
                        description="Password reset endpoint — verify token is high-entropy and time-limited.",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=0.6,
                        tags=["reset_token", "weak_entropy"],
                        remediation="Use cryptographically-secure random tokens with expiration.",
                    )
                )

            # 2FA bypass
            if "2fa" in url or "otp" in url or "verify" in url:
                findings.append(
                    LogicFinding(
                        title="2FA verification bypass risk",
                        target=target,
                        endpoint=ep.get("url", ""),
                        description="2FA endpoint — verify that empty/missing codes are rejected and "
                        "brute-force protection is in place.",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=0.6,
                        tags=["2fa_bypass"],
                        remediation="Require non-empty code, enforce rate limiting, and verify server-side.",
                    )
                )

            # Session fixation (login without session rotation)
            if "login" in url or "signin" in url:
                findings.append(
                    LogicFinding(
                        title="Session fixation: no session rotation on login",
                        target=target,
                        endpoint=ep.get("url", ""),
                        description="Login endpoint — verify the session ID is rotated after successful login.",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=0.6,
                        tags=["session_fixation"],
                        remediation="Always regenerate the session ID after authentication.",
                    )
                )

            # OAuth open redirect
            if "oauth" in url or "authorize" in url:
                redirect_uri = all_fields.get("redirect_uri", "")
                state = all_fields.get("state", None)
                if isinstance(redirect_uri, str) and redirect_uri:
                    # Check if redirect_uri points to a different host
                    try:
                        target_host = urlparse(ep.get("url", "")).hostname or ""
                        redirect_host = urlparse(redirect_uri).hostname or ""
                        if redirect_host and redirect_host != target_host:
                            findings.append(
                                LogicFinding(
                                    title=f"OAuth open redirect to {redirect_host}",
                                    target=target,
                                    endpoint=ep.get("url", ""),
                                    description=f"redirect_uri points to external host '{redirect_host}', "
                                    f"enabling redirect-based attacks.",
                                    category=self.category,
                                    severity=Severity.CRITICAL,
                                    confidence=0.8,
                                    tags=["oauth", "open_redirect"],
                                    remediation="Validate redirect_uri against an allowlist of trusted domains.",
                                )
                            )
                    except Exception:
                        pass

                # Missing state parameter (CSRF)
                if not state:
                    findings.append(
                        LogicFinding(
                            title="OAuth missing state parameter (CSRF)",
                            target=target,
                            endpoint=ep.get("url", ""),
                            description="OAuth authorization request lacks 'state' parameter, "
                            "enabling CSRF attacks on the flow.",
                            category=self.category,
                            severity=Severity.HIGH,
                            confidence=0.7,
                            tags=["oauth", "csrf", "missing_state"],
                            remediation="Always include a random 'state' parameter and validate it on callback.",
                        )
                    )

            # Remember-me
            if "remember" in url or "remember" in all_fields:
                findings.append(
                    LogicFinding(
                        title="Remember-me token risk",
                        target=target,
                        endpoint=ep.get("url", ""),
                        description="Remember-me functionality — verify token is not guessable and has expiration.",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        tags=["remember_me", "persistent_auth"],
                        remediation="Use random, expiring tokens bound to user-agent and IP.",
                    )
                )

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# Authorization detector (detectors[4]) — BOLA / BFLA
# ═══════════════════════════════════════════════════════════════════════════


class AuthorizationDetector(BaseDetector):
    """Detects Broken Object Level Authorization (BOLA) and BFLA."""

    category = DetectorCategory.AUTHORIZATION

    async def detect(
        self, target: str, endpoints: List[Union[str, Dict[str, Any]]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        eps = self._normalize_all(endpoints)

        # BOLA: sequential IDs
        id_endpoints: List[Tuple[str, str]] = []
        for ep in eps:
            url = ep.get("url", "")
            m = re.search(r"/(\d+)(?:/|$|\?)", url)
            if m:
                id_endpoints.append((url, m.group(1)))

        if len(id_endpoints) >= 2:
            ids = [int(oid) for _, oid in id_endpoints]
            if max(ids) - min(ids) <= 10:
                findings.append(
                    LogicFinding(
                        title="Sequential ID enumeration (BOLA)",
                        target=target,
                        endpoint=id_endpoints[0][0],
                        description=f"Endpoints use sequential integer IDs ({ids}). "
                        f"Users may access other users' resources by incrementing the ID.",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=0.8,
                        tags=["bola", "sequential_id", "idor"],
                        remediation="Use UUIDs or enforce per-resource authorization checks.",
                    )
                )

        # UUID v1 leak
        for ep in eps:
            url = ep.get("url", "")
            m = re.search(
                r"/([0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12})",
                url,
                re.IGNORECASE,
            )
            if m:
                uuid_val = m.group(1)
                ts_ms = UUIDV1Decoder.extract_timestamp_ms(uuid_val)
                findings.append(
                    LogicFinding(
                        title=f"UUID v1 timestamp leak in resource ID",
                        target=target,
                        endpoint=url,
                        description=f"Resource ID '{uuid_val}' is a UUID v1, which embeds a "
                        f"creation timestamp. This leaks information about object creation time.",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        tags=["uuid_v1", "info_leak"],
                        remediation="Use UUID v4 (random) instead of UUID v1.",
                    )
                )
                findings[-1].add_evidence(
                    "static_pattern",
                    "UUID v1 detected in URL path",
                    {"uuid": uuid_val, "extracted_timestamp_ms": ts_ms},
                )

        # Role param (BFLA)
        for ep in eps:
            all_fields = {**ep.get("params", {}), **ep.get("body", {})}
            if "role" in all_fields or "admin" in all_fields or "is_admin" in all_fields:
                findings.append(
                    LogicFinding(
                        title="Role parameter accepted (BFLA)",
                        target=target,
                        endpoint=ep.get("url", ""),
                        description="Endpoint accepts a 'role' or 'admin' parameter from the client, "
                        "enabling privilege escalation.",
                        category=self.category,
                        severity=Severity.CRITICAL,
                        confidence=0.8,
                        tags=["bfla", "role_param", "privilege_escalation"],
                        remediation="Never trust client-supplied role parameters for authorization decisions.",
                    )
                )

        # Admin path
        for ep in eps:
            url = ep.get("url", "").lower()
            if "/admin" in url:
                findings.append(
                    LogicFinding(
                        title="Admin endpoint accessible (BFLA)",
                        target=target,
                        endpoint=ep.get("url", ""),
                        description="Admin endpoint is reachable. Verify strict role-based authorization.",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=0.7,
                        tags=["admin", "bfla"],
                        remediation="Enforce RBAC on all admin endpoints.",
                    )
                )

        # Multi-tenant boundary
        for ep in eps:
            url = ep.get("url", "").lower()
            if any(kw in url for kw in ("/workspace", "/tenant", "/org/", "/organization/")):
                findings.append(
                    LogicFinding(
                        title="Multi-tenant boundary not enforced",
                        target=target,
                        endpoint=ep.get("url", ""),
                        description="Multi-tenant endpoint — verify tenant isolation and cross-tenant access prevention.",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=0.6,
                        tags=["multi_tenant", "boundary"],
                        remediation="Enforce tenant isolation at the data layer for every query.",
                    )
                )

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# Workflow integrity detector (detectors[5])
# ═══════════════════════════════════════════════════════════════════════════


class WorkflowIntegrityDetector(BaseDetector):
    """Detects workflow integrity issues (idempotency, order of operations)."""

    category = DetectorCategory.WORKFLOW_INTEGRITY

    _MUTATION_KEYWORDS = {"pay", "transfer", "refund", "withdraw", "charge", "order", "checkout"}

    async def detect(
        self, target: str, endpoints: List[Union[str, Dict[str, Any]]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        for ep in self._normalize_all(endpoints):
            method = ep.get("method", "GET").upper()
            if method == "GET":
                continue
            url = ep.get("url", "").lower()
            body = ep.get("body", {})
            params = ep.get("params", {})
            all_fields = {**params, **body}

            if not any(kw in url for kw in self._MUTATION_KEYWORDS):
                continue

            # Missing idempotency key
            has_idempotency = any(
                "idempot" in k.lower()
                or k.lower() in ("idempotency_key", "request_id", "x-idempotency-key")
                for k in all_fields.keys()
            )
            if not has_idempotency:
                findings.append(
                    LogicFinding(
                        title="Missing idempotency key on mutation endpoint",
                        target=target,
                        endpoint=ep.get("url", ""),
                        description="Endpoint performs a financial mutation without an idempotency key. "
                        "Retries or network issues may cause double-charging.",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=0.6,
                        tags=["idempotency", "double_spend"],
                        remediation="Require an idempotency key header/parameter on all mutation endpoints.",
                    )
                )

            # Force param (order of operations bypass)
            if "force" in all_fields or "bypass" in all_fields or "skip" in all_fields:
                findings.append(
                    LogicFinding(
                        title="Order-of-operations bypass via 'force' parameter",
                        target=target,
                        endpoint=ep.get("url", ""),
                        description="Endpoint accepts a 'force'/'bypass'/'skip' parameter that may "
                        "override business rules or validation steps.",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=0.7,
                        tags=["order_of_ops", "force_param"],
                        remediation="Remove force/bypass parameters or restrict them to admin roles.",
                    )
                )

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# Business constraint detector (detectors[6])
# ═══════════════════════════════════════════════════════════════════════════


class BusinessConstraintDetector(BaseDetector):
    """Detects business constraint violations."""

    category = DetectorCategory.BUSINESS_CONSTRAINT

    async def detect(
        self, target: str, endpoints: List[Union[str, Dict[str, Any]]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        for ep in self._normalize_all(endpoints):
            url = ep.get("url", "")
            body = ep.get("body", {})
            params = ep.get("params", {})
            all_fields = {**params, **body}

            # Client-controlled time param
            if any(k in all_fields for k in ("timestamp", "ts", "time", "created_at", "date")):
                findings.append(
                    LogicFinding(
                        title="Client-controlled timestamp parameter",
                        target=target,
                        endpoint=url,
                        description="Endpoint accepts a client-supplied timestamp, which may allow "
                        "back-dating or future-dating transactions.",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        tags=["time", "client_time"],
                        remediation="Use server-side timestamps for all time-sensitive operations.",
                    )
                )

            # Geo param
            if any(k in all_fields for k in ("country", "region", "geo", "location", "locale")):
                findings.append(
                    LogicFinding(
                        title="Client-controlled geographic parameter",
                        target=target,
                        endpoint=url,
                        description="Endpoint accepts a client-supplied geographic parameter, "
                        "which may bypass geo-restrictions.",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        tags=["geo"],
                        remediation="Determine geographic location server-side (e.g., via IP geolocation).",
                    )
                )

            # KYC / AML
            if any(k in all_fields for k in ("tier", "verified", "kyc", "aml", "accredited")):
                findings.append(
                    LogicFinding(
                        title="KYC/AML verification status client-controllable",
                        target=target,
                        endpoint=url,
                        description="Endpoint accepts verification/tier parameters from the client, "
                        "potentially bypassing KYC/AML checks.",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=0.6,
                        tags=["kyc", "aml"],
                        remediation="Store and enforce KYC/AML status server-side only.",
                    )
                )

            # Trial abuse
            if any(k in all_fields for k in ("is_trial", "trial", "is_premium", "plan")):
                findings.append(
                    LogicFinding(
                        title="Trial/premium status client-controllable",
                        target=target,
                        endpoint=url,
                        description="Endpoint accepts trial/plan parameters from the client, "
                        "enabling trial abuse or privilege escalation.",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        tags=["trial", "plan_abuse"],
                        remediation="Manage subscription status server-side only.",
                    )
                )

            # Min/max amount
            if "amount" in all_fields:
                findings.append(
                    LogicFinding(
                        title="Missing min/max amount validation",
                        target=target,
                        endpoint=url,
                        description="Endpoint accepts 'amount' without visible min/max constraints. "
                        "Very small or very large amounts may be accepted.",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        tags=["min_max", "amount_validation"],
                        remediation="Enforce min/max amount limits server-side.",
                    )
                )

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# Inference engine
# ═══════════════════════════════════════════════════════════════════════════


_HIGH_IMPACT_CATS = {
    DetectorCategory.AUTH_LOGIC,
    DetectorCategory.AUTHORIZATION,
    DetectorCategory.RACE_CONDITION,
}


class InferenceEngine:
    """Scores findings for novelty, impact, reproducibility, and risk."""

    def __init__(self, config: Optional[LogicFlawConfig] = None) -> None:
        self.config = config or LogicFlawConfig()

    def score(self, finding: LogicFinding, all_findings: List[LogicFinding]) -> None:
        """Score a finding in-place."""
        # Novelty: unique endpoints among all findings get higher novelty
        same_endpoint = sum(1 for f in all_findings if f.endpoint == finding.endpoint)
        if same_endpoint <= 1:
            finding.novelty = max(finding.novelty, 0.7)
        else:
            finding.novelty = min(finding.novelty, 0.3)

        # Impact score: higher for high-impact categories
        if finding.category in _HIGH_IMPACT_CATS:
            finding.impact_score = max(finding.impact_score, 0.8)
        else:
            finding.impact_score = max(finding.impact_score, 0.4)

        # Reproducibility: higher if dynamic evidence present
        has_dynamic = any(
            e.kind in ("burst_response", "dynamic", "http_response") for e in finding.evidence
        )
        if has_dynamic:
            finding.reproducibility = max(finding.reproducibility, 0.8)
        else:
            finding.reproducibility = min(finding.reproducibility, 0.5)

        # Risk score: severity * confidence * impact * reproducibility * novelty * 100
        finding.risk_score = round(
            finding.severity.weight
            * finding.confidence
            * finding.impact_score
            * finding.reproducibility
            * finding.novelty
            * 10,
            2,
        )


# ═══════════════════════════════════════════════════════════════════════════
# Correlation engine
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class FindingChain:
    """A chain of correlated findings."""

    title: str
    finding_ids: List[str] = field(default_factory=list)
    description: str = ""
    tags: List[str] = field(default_factory=list)


class CorrelationEngine:
    """Correlates findings into attack chains."""

    def correlate(self, findings: List[LogicFinding]) -> List[FindingChain]:
        """Find correlated finding chains."""
        chains: List[FindingChain] = []

        if not findings:
            return chains

        # Race + BOLA chain
        race_findings = [f for f in findings if "race" in f.tags]
        bola_findings = [f for f in findings if "bola" in f.tags or "sequential_id" in f.tags]
        if race_findings and bola_findings:
            chains.append(
                FindingChain(
                    title="Race condition + BOLA exploitation chain",
                    finding_ids=[f.finding_id for f in race_findings + bola_findings],
                    description="Race conditions on endpoints with sequential IDs can enable "
                    "mass data exfiltration via concurrent enumeration.",
                    tags=["race", "bola", "mass_exploitation"],
                )
            )
        elif race_findings:
            chains.append(
                FindingChain(
                    title="Race condition mass-exploitation chain",
                    finding_ids=[f.finding_id for f in race_findings],
                    description="Multiple race conditions found — concurrent exploitation may "
                    "cause widespread financial damage.",
                    tags=["race", "mass_exploitation"],
                )
            )

        # Currency confusion + negative amount chain
        currency_findings = [f for f in findings if "currency_confusion" in f.tags]
        negative_findings = [f for f in findings if "negative_amount" in f.tags]
        if currency_findings and negative_findings:
            chains.append(
                FindingChain(
                    title="Currency confusion + arbitrary negative amount chain",
                    finding_ids=[f.finding_id for f in currency_findings + negative_findings],
                    description="Zero-decimal currency handling combined with negative amount "
                    "acceptance enables arbitrary financial manipulation.",
                    tags=["currency", "negative_amount", "financial_fraud"],
                )
            )
        elif currency_findings:
            chains.append(
                FindingChain(
                    title="Currency confusion exploitation chain",
                    finding_ids=[f.finding_id for f in currency_findings],
                    description="Zero-decimal currency handling may enable amount manipulation.",
                    tags=["currency", "decimal_mismatch"],
                )
            )

        # BFLA + admin path
        bfla_findings = [f for f in findings if "bfla" in f.tags or "role_param" in f.tags]
        admin_findings = [f for f in findings if "admin" in f.tags]
        if bfla_findings and admin_findings:
            chains.append(
                FindingChain(
                    title="Privilege escalation chain (BFLA + admin path)",
                    finding_ids=[f.finding_id for f in bfla_findings + admin_findings],
                    description="Role parameter injection combined with accessible admin paths "
                    "enables full privilege escalation.",
                    tags=["bfla", "admin", "privilege_escalation"],
                )
            )

        return chains


# ═══════════════════════════════════════════════════════════════════════════
# LogicFlawEngine — main orchestrator
# ═══════════════════════════════════════════════════════════════════════════


class LogicFlawEngine:
    """Multi-detector business logic vulnerability engine.

    Runs 7 specialized detectors, scores findings with InferenceEngine,
    and correlates them into attack chains with CorrelationEngine.

    Example:
        engine = LogicFlawEngine()
        findings = asyncio.run(engine.analyze("api.com", endpoints))
    """

    def __init__(self, config: Optional[LogicFlawConfig] = None) -> None:
        """Initialize with optional configuration."""
        self.config = config or LogicFlawConfig()
        self.http: Any = None
        self._closed = False
        # Backward compat: old API exposed .timeout and .verify_ssl
        self.timeout: float = self.config.http_timeout_seconds
        self.verify_ssl: bool = False

        self.detectors: List[BaseDetector] = [
            PriceManipulationDetector(self.config),
            RaceConditionDetector(self.config),
            StateMachineBypassDetector(self.config),
            AuthLogicDetector(self.config),
            AuthorizationDetector(self.config),
            WorkflowIntegrityDetector(self.config),
            BusinessConstraintDetector(self.config),
        ]

        # Share HTTP client across detectors
        for det in self.detectors:
            det._client = True  # marker — detectors check for truthy _client

        self.inference = InferenceEngine(self.config)
        self.correlation = CorrelationEngine()

    async def analyze(
        self,
        target: str,
        endpoints: List[Union[str, Dict[str, Any]]],
    ) -> List[LogicFinding]:
        """Run all detectors and return scored, sorted findings.

        Args:
            target: The target host/identifier.
            endpoints: List of endpoint definitions (URL strings or dicts).

        Returns:
            List of LogicFinding objects sorted by risk_score descending.
        """
        all_findings: List[LogicFinding] = []

        for detector in self.detectors:
            try:
                detector_findings = await detector.detect(target, endpoints)
                all_findings.extend(detector_findings)
            except Exception as e:
                logger.debug("Detector %s failed: %s", detector.__class__.__name__, e)

        # Score findings
        if self.config.enable_inference:
            for f in all_findings:
                self.inference.score(f, all_findings)

        # Correlate
        if self.config.enable_correlation:
            chains = self.correlation.correlate(all_findings)
            for chain in chains:
                logger.debug("Chain: %s (%d findings)", chain.title, len(chain.finding_ids))

        # Filter by min confidence and risk score
        filtered = [
            f
            for f in all_findings
            if f.confidence >= self.config.min_confidence
            and f.risk_score >= self.config.min_risk_score
        ]

        # Sort by risk_score descending
        filtered.sort(key=lambda f: -f.risk_score)

        return filtered

    async def aclose(self) -> None:
        """Close any resources. Safe to call multiple times."""
        if self._closed:
            return
        self._closed = True
        if self.http:
            try:
                await self.http.close()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════
# Backward compatibility
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class LogicFlaw:
    """Legacy finding type (backward compatibility)."""

    flaw_type: str
    endpoint: str
    description: str
    evidence: str = ""
    severity: str = "High"
    confidence: float = 0.0
    remediation: str = ""


@dataclass
class LogicFlawResult:
    """Legacy result type (backward compatibility)."""

    target: str
    flaws: List[LogicFlaw] = field(default_factory=list)
    total_tests: int = 0
    duration: float = 0.0

    @property
    def is_vulnerable(self) -> bool:
        return len(self.flaws) > 0

    def summary(self) -> Dict[str, Any]:
        severity_counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for flaw in self.flaws:
            if flaw.severity in severity_counts:
                severity_counts[flaw.severity] += 1
        return {
            "target": self.target,
            "is_vulnerable": self.is_vulnerable,
            "total_flaws": len(self.flaws),
            "severity_counts": severity_counts,
            "duration": self.duration,
        }

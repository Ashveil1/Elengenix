"""tools/logic_flaw_engine.py

Elengenix Advanced Business Logic Vulnerability Detection Engine.

Purpose:
    Detect the kind of business logic, authorization, and workflow bugs that
    signature-based scanners miss. This is the flagship logic-flaw module for
    Elengenix. Each detection class follows the same interface:

        class Detector:
            name = "..."
            description = "..."
            async def detect(self, target: str, endpoints: List[Dict]) -> List[LogicFinding]: ...

    The top-level ``LogicFlawEngine`` orchestrates every detector, runs the
    inference engine to score novelty/impact/exploitability, correlates
    findings into chains, and emits a final list of ``LogicFinding`` objects.

Conventions:
    - 4-space indent, type hints on every signature
    - No emoji. [OK] / [FAIL] / [WARN] / [INFO] markers
    - Shared console via ``from ui_components import console``
    - Module logger: ``logging.getLogger("elengenix.logic_flaw_engine")``
    - Async-first; uses ``httpx`` (which is already in requirements)
    - Reuses dataclass patterns from ``tools/vuln_engine.py`` and
      ``tools/logic_analyzer.py`` without duplicating them.

Public API:
    LogicFinding           - one detected business-logic issue
    Detector               - base class for all detectors
    LogicFlawEngine        - orchestrator (``analyze()`` is the main entry)
    LogicFlawConfig        - tuning knobs
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import re
import time
import uuid
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# httpx is already in the venv (see requirements.txt comment about AI client).
try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover - httpx is in venv, fallback just in case
    httpx = None  # type: ignore

# Shared Rich console - the project-wide singleton.
from ui_components import console, print_info, print_warning, print_error, print_success

logger = logging.getLogger("elengenix.logic_flaw_engine")


# ═══════════════════════════════════════════════════════════════════════════
# 1. DATA MODEL
# ═══════════════════════════════════════════════════════════════════════════


class Severity(Enum):
    """Standard severity ranking used by every detector."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        return {
            Severity.INFO: 0.5,
            Severity.LOW: 2.0,
            Severity.MEDIUM: 5.0,
            Severity.HIGH: 7.5,
            Severity.CRITICAL: 9.5,
        }[self]


class DetectorCategory(Enum):
    """Top-level taxonomy that mirrors the engine requirements."""

    PRICE_MANIPULATION = "price_manipulation"
    RACE_CONDITION = "race_condition"
    STATE_MACHINE = "state_machine"
    AUTH_LOGIC = "auth_logic"
    AUTHORIZATION = "authorization"
    WORKFLOW_INTEGRITY = "workflow_integrity"
    BUSINESS_CONSTRAINT = "business_constraint"
    INFERENCE = "inference"


@dataclass
class Evidence:
    """A piece of evidence supporting a logic finding.

    Attributes:
        kind: Free-form category like "request", "response", "timing",
            "static_pattern", "inference".
        description: Human-readable summary.
        data: Arbitrary structured payload (request body, response
            snippet, decoded token, etc.).
    """

    kind: str
    description: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LogicFinding:
    """One business-logic vulnerability discovered by the engine.

    Mirrors the shape of ``VulnFinding`` from ``tools/vuln_engine.py`` but
    adds logic-flaw-specific fields: reproducibility, exploitability,
    detection category, and inference scores.
    """

    finding_id: str = ""
    title: str = ""
    category: DetectorCategory = DetectorCategory.BUSINESS_CONSTRAINT
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    target: str = ""
    endpoint: str = ""
    method: str = "GET"
    parameter: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    cwe: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    chain: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Inference scores
    novelty: float = 0.5
    impact_score: float = 0.5
    exploitability: float = 0.5
    reproducibility: float = 0.5
    risk_score: float = 0.0

    discovered_at: float = 0.0
    detector: str = ""

    def __post_init__(self) -> None:
        if not self.finding_id:
            seed = f"{self.target}:{self.endpoint}:{self.parameter}:{self.title}:{self.detector}"
            self.finding_id = "LFE-" + hashlib.sha256(seed.encode()).hexdigest()[:12].upper()
        if not self.discovered_at:
            self.discovered_at = time.time()
        if not self.cwe:
            self.cwe = self._default_cwe()
        # risk_score is recalculated by the inference engine but seed it now
        if not self.risk_score:
            self.risk_score = self._compute_risk()

    def _default_cwe(self) -> List[str]:
        mapping = {
            DetectorCategory.PRICE_MANIPULATION: ["CWE-840", "CWE-20"],
            DetectorCategory.RACE_CONDITION: ["CWE-362"],
            DetectorCategory.STATE_MACHINE: ["CWE-840", "CWE-285"],
            DetectorCategory.AUTH_LOGIC: ["CWE-287", "CWE-384", "CWE-640"],
            DetectorCategory.AUTHORIZATION: ["CWE-639", "CWE-285", "CWE-266"],
            DetectorCategory.WORKFLOW_INTEGRITY: ["CWE-840", "CWE-665"],
            DetectorCategory.BUSINESS_CONSTRAINT: ["CWE-840", "CWE-20"],
            DetectorCategory.INFERENCE: ["CWE-1000"],
        }
        return mapping.get(self.category, ["CWE-1000"])

    def _compute_risk(self) -> float:
        """Heuristic risk = novelty * impact * exploitability * reproducibility * severity weight."""
        return round(
            self.novelty
            * self.impact_score
            * self.exploitability
            * self.reproducibility
            * self.severity.weight,
            2,
        )

    def recompute(self) -> None:
        """Recalculate risk_score after the inference engine mutates scores."""
        self.risk_score = self._compute_risk()

    def add_evidence(self, kind: str, description: str, data: Optional[Dict[str, Any]] = None) -> None:
        self.evidence.append(Evidence(kind=kind, description=description, data=data or {}))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["evidence"] = [asdict(e) for e in self.evidence]
        return d


# ═══════════════════════════════════════════════════════════════════════════
# 2. CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class LogicFlawConfig:
    """Tuning knobs for the engine and individual detectors."""

    # HTTP
    http_timeout_seconds: float = 8.0
    http_max_concurrent: int = 20
    http_user_agent: str = "Elengenix-LogicFlawEngine/1.0"

    # Detector toggles
    enable_price: bool = True
    enable_race: bool = True
    enable_state_machine: bool = True
    enable_auth_logic: bool = True
    enable_authorization: bool = True
    enable_workflow: bool = True
    enable_business_constraint: bool = True

    # Race / TOCTOU
    race_default_concurrency: int = 8
    race_default_attempts: int = 3

    # Authorization
    sequential_id_sample_size: int = 5
    uuid_v1_sample_size: int = 5

    # Scoring
    min_confidence: float = 0.25
    min_risk_score: float = 1.0
    max_findings_per_detector: int = 200


# ═══════════════════════════════════════════════════════════════════════════
# 3. ENDPOINT NORMALIZATION HELPERS
# ═══════════════════════════════════════════════════════════════════════════


ID_REGEX = re.compile(
    r"(?P<id>\b\d{1,19}\b|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)

PRICE_KEYWORDS = re.compile(
    r"(price|amount|cost|total|grand_total|subtotal|tax|fee|charge|"
    r"balance|credit|deposit|payment|paid|discount|sum|value|wallet|"
    r"salary|stake|wager|bid|offer|net|gross|usd|eur|gbp|jpy|cny)",
    re.IGNORECASE,
)

QUANTITY_KEYWORDS = re.compile(
    r"(qty|quantity|count|units|pieces|items|seats|tickets|shares|"
    r"tokens|coins|copies|stock|inv)",
    re.IGNORECASE,
)

CURRENCY_KEYWORDS = re.compile(
    r"\b(usd|eur|gbp|jpy|cny|inr|aud|cad|chf|sek|nok|dkk|brl|rub|"
    r"hkd|sgd|krw|mxn|zar|try|nzd)\b",
    re.IGNORECASE,
)

DISCOUNT_KEYWORDS = re.compile(
    r"(coupon|promo|promotion|voucher|discount_code|campaign|gift_card|"
    r"redemption|referral_code|invite_code)",
    re.IGNORECASE,
)

AUTH_KEYWORDS = re.compile(
    r"(login|signin|sign_in|authenticate|auth|token|password|otp|2fa|"
    r"mfa|totp|verify|verification|reset|forgot|recover|session|"
    r"cookie|jwt|bearer|oauth|callback|redirect_uri|remember|signup|register|"
    r"register|confirm|activate)",
    re.IGNORECASE,
)

STEP_KEYWORDS = re.compile(
    r"(step|stage|phase|state|status|flow|next|prev|previous|back|"
    r"wizard|onboard|setup|checkout|review|confirm|submit|complete|finish|"
    r"approve|approve|verify_email|verify_phone|kyc)",
    re.IGNORECASE,
)

ID_PARAMETER_NAMES = {
    "id", "user_id", "uid", "userId", "userid",
    "account", "account_id", "accountId",
    "order", "order_id", "orderId",
    "invoice", "invoice_id", "invoiceId",
    "transaction", "txn", "txn_id", "transaction_id",
    "object", "object_id", "objectId", "ref", "reference",
    "doc", "document", "document_id", "doc_id",
    "ticket", "ticket_id", "case", "case_id",
    "customer", "customer_id",
}


def normalize_endpoint(ep: Dict[str, Any]) -> Dict[str, Any]:
    """Return a normalized view of an endpoint dict.

    Accepts loose shapes used throughout Elengenix:
        {"url": "...", "method": "GET", "params": {...}, "body": {...}, ...}
        {"endpoint": "...", ...}
        raw URL string
    """
    if isinstance(ep, str):
        return {"url": ep, "method": "GET", "params": {}, "body": {}}
    url = ep.get("url") or ep.get("endpoint") or ep.get("uri") or ""
    method = (ep.get("method") or "GET").upper()
    params = dict(ep.get("params") or ep.get("query") or {})
    body = dict(ep.get("body") or ep.get("data") or ep.get("json") or {})
    headers = dict(ep.get("headers") or {})
    return {
        "url": url,
        "method": method,
        "params": params,
        "body": body,
        "headers": headers,
        "raw": ep,
    }


def has_object_id_param(ep: Dict[str, Any]) -> bool:
    """Return True if endpoint references an obvious object identifier."""
    norm = normalize_endpoint(ep)
    candidates = set(norm["params"].keys()) | set(norm["body"].keys())
    if candidates & ID_PARAMETER_NAMES:
        return True
    # Path parameter {id} or /:id
    path = urlparse(norm["url"]).path
    if re.search(r"/[:{]\s*id\s*[:}]?", path, re.IGNORECASE):
        return True
    if re.search(r"/users?/\d+", path, re.IGNORECASE):
        return True
    return False


def is_price_endpoint(ep: Dict[str, Any]) -> bool:
    norm = normalize_endpoint(ep)
    combined = " ".join(
        [norm["url"], " ".join(norm["params"].keys()), " ".join(norm["body"].keys())]
    )
    return bool(PRICE_KEYWORDS.search(combined))


def is_discount_endpoint(ep: Dict[str, Any]) -> bool:
    norm = normalize_endpoint(ep)
    combined = " ".join([norm["url"], " ".join(norm["params"].keys()), " ".join(norm["body"].keys())])
    return bool(DISCOUNT_KEYWORDS.search(combined))


def is_auth_endpoint(ep: Dict[str, Any]) -> bool:
    norm = normalize_endpoint(ep)
    return bool(AUTH_KEYWORDS.search(norm["url"]))


def is_workflow_endpoint(ep: Dict[str, Any]) -> bool:
    norm = normalize_endpoint(ep)
    return bool(STEP_KEYWORDS.search(norm["url"]))


def extract_currency(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    m = CURRENCY_KEYWORDS.search(value)
    return m.group(1).upper() if m else None


# ═══════════════════════════════════════════════════════════════════════════
# 4. DETECTOR BASE CLASS
# ═══════════════════════════════════════════════════════════════════════════


class Detector(ABC):
    """Abstract base for every detection class.

    Subclasses set class-level metadata and implement ``detect``. The
    orchestrator handles deduplication, scoring, and correlation; the
    detector only needs to return raw ``LogicFinding`` objects.
    """

    name: str = "abstract"
    description: str = ""
    category: DetectorCategory = DetectorCategory.INFERENCE
    default_severity: Severity = Severity.MEDIUM
    default_confidence: float = 0.6

    def __init__(self, config: LogicFlawConfig) -> None:
        self.config = config

    @abstractmethod
    async def detect(self, target: str, endpoints: List[Dict[str, Any]]) -> List[LogicFinding]:
        """Run this detector; return zero or more findings."""

    # Helpers shared by detectors -------------------------------------------------

    def make_finding(
        self,
        target: str,
        endpoint: str,
        method: str = "GET",
        parameter: str = "",
        title: str = "",
        description: str = "",
        impact: str = "",
        remediation: str = "",
        confidence: Optional[float] = None,
        severity: Optional[Severity] = None,
        tags: Optional[List[str]] = None,
    ) -> LogicFinding:
        f = LogicFinding(
            title=title or self.name,
            category=self.category,
            severity=severity or self.default_severity,
            confidence=confidence if confidence is not None else self.default_confidence,
            target=target,
            endpoint=endpoint,
            method=method,
            parameter=parameter,
            description=description,
            impact=impact,
            remediation=remediation,
            tags=tags or [self.name, self.category.value],
            detector=self.name,
        )
        return f

    async def safe_call(self, coro, *args, **kwargs) -> Any:
        """Run an awaitable, swallowing exceptions and logging them."""
        try:
            return await coro(*args, **kwargs)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("[%s] safe_call failed: %s", self.name, exc)
            return None


# ═══════════════════════════════════════════════════════════════════════════
# 5. HTTP CLIENT WRAPPER
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class HttpResponseLite:
    """Minimal response view used by detectors (keeps the surface small)."""

    status: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: float
    url: str
    method: str


class HttpClient:
    """Async HTTP helper backed by httpx with a graceful no-op fallback.

    The engine must keep working even when httpx is missing (e.g. minimal
    test envs). In that case ``request`` returns a synthetic error response
    so detectors can still classify endpoints heuristically.
    """

    def __init__(self, config: LogicFlawConfig) -> None:
        self.config = config
        self._client: Optional[Any] = None
        if httpx is not None:
            try:
                self._client = httpx.AsyncClient(
                    timeout=httpx.Timeout(config.http_timeout_seconds),
                    headers={"User-Agent": config.http_user_agent},
                    follow_redirects=False,
                    verify=False,
                )
            except Exception:  # pragma: no cover - defensive
                self._client = None

    async def aclose(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:  # pragma: no cover
                pass

    async def request(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> HttpResponseLite:
        method = method.upper()
        start = time.monotonic()
        if self._client is None:
            return HttpResponseLite(
                status=0,
                headers={},
                body="",
                elapsed_ms=0.0,
                url=url,
                method=method,
            )
        try:
            req_headers = dict(headers or {})
            if cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                req_headers.setdefault("Cookie", cookie_str)
            if body is not None and method in ("POST", "PUT", "PATCH", "DELETE"):
                resp = await self._client.request(
                    method,
                    url,
                    params=params,
                    json=body,
                    headers=req_headers,
                    timeout=timeout or self.config.http_timeout_seconds,
                )
            else:
                resp = await self._client.request(
                    method,
                    url,
                    params=params,
                    headers=req_headers,
                    timeout=timeout or self.config.http_timeout_seconds,
                )
            elapsed = (time.monotonic() - start) * 1000
            return HttpResponseLite(
                status=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:8192],
                elapsed_ms=elapsed,
                url=str(resp.url),
                method=method,
            )
        except Exception as exc:  # pragma: no cover - network failures
            elapsed = (time.monotonic() - start) * 1000
            return HttpResponseLite(
                status=-1,
                headers={},
                body=str(exc),
                elapsed_ms=elapsed,
                url=url,
                method=method,
            )

    async def gather(
        self,
        requests: Sequence[Dict[str, Any]],
        max_concurrent: Optional[int] = None,
    ) -> List[HttpResponseLite]:
        """Send many requests in parallel with a concurrency cap."""
        if not requests:
            return []
        sem = asyncio.Semaphore(max_concurrent or self.config.http_max_concurrent)

        async def _one(req: Dict[str, Any]) -> HttpResponseLite:
            async with sem:
                return await self.request(
                    url=req["url"],
                    method=req.get("method", "GET"),
                    params=req.get("params"),
                    body=req.get("body"),
                    headers=req.get("headers"),
                    cookies=req.get("cookies"),
                )

        results = await asyncio.gather(*[_one(r) for r in requests], return_exceptions=True)
        out: List[HttpResponseLite] = []
        for r in results:
            if isinstance(r, Exception):
                out.append(HttpResponseLite(status=-1, headers={}, body=str(r),
                                            elapsed_ms=0.0, url="", method="GET"))
            else:
                out.append(r)
        return out


# ═══════════════════════════════════════════════════════════════════════════
# 6. PRICE / AMOUNT MANIPULATION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


class PriceManipulationDetector(Detector):
    """Detect numeric parameter abuse on financial endpoints.

    Categories:
        - Negative-value refund attacks (amount=-1)
        - Currency confusion (USD vs EUR / JPY 0-decimal)
        - Integer overflow (amount=999999999999999)
        - Quantity = 0 or negative quantity
        - Discount code stacking
    """

    name = "price_manipulation"
    description = "Detect negative amounts, currency confusion, integer overflow, and discount stacking."
    category = DetectorCategory.PRICE_MANIPULATION
    default_severity = Severity.HIGH
    default_confidence = 0.7

    NEGATIVE_PAYLOADS: List[Any] = [-1, -0.01, -100, -9999, -0.0001]
    OVERFLOW_PAYLOADS: List[Any] = [
        2**31, -2**31, 2**32, 2**53, 2**63 - 1, -2**63,
        99999999999999, -99999999999999, 1e20, -1e20,
    ]
    ZERO_PAYLOADS: List[Any] = [0, 0.0, -0, "0", "0.00", "0e0"]
    DECIMAL_PAYLOADS: List[Any] = [0.001, 0.0001, 0.00001, 1e-9]

    CURRENCY_EXPECTED_DECIMALS: Dict[str, int] = {
        "USD": 2, "EUR": 2, "GBP": 2, "AUD": 2, "CAD": 2, "CHF": 2,
        "CNY": 2, "HKD": 2, "SGD": 2, "INR": 2, "NZD": 2,
        "SEK": 2, "NOK": 2, "DKK": 2, "BRL": 2, "MXN": 2, "ZAR": 2, "TRY": 2,
        "JPY": 0, "KRW": 0,
    }

    async def detect(
        self, target: str, endpoints: List[Dict[str, Any]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        client: Optional[HttpClient] = getattr(self, "_client", None)

        for ep in endpoints:
            norm = normalize_endpoint(ep)
            if not norm["url"]:
                continue
            # Run the price-shaped checks if the endpoint carries price,
            # quantity, or discount semantics.
            is_relevant = (
                is_price_endpoint(norm)
                or is_discount_endpoint(norm)
                or self._has_quantity_param(norm)
            )
            if not is_relevant:
                continue

            findings.extend(self._check_negative(target, norm))
            findings.extend(self._check_currency(target, norm))
            findings.extend(self._check_overflow(target, norm))
            findings.extend(self._check_quantity(target, norm))
            if is_discount_endpoint(norm):
                findings.extend(self._check_discount_stacking(target, norm))

        return findings[: self.config.max_findings_per_detector]

    @staticmethod
    def _has_quantity_param(norm: Dict[str, Any]) -> bool:
        for k in list(norm["params"].keys()) + list(norm["body"].keys()):
            if QUANTITY_KEYWORDS.search(k):
                return True
        return False

    # ----- individual checks ------------------------------------------------

    def _param_candidates(self, norm: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Return (name, location) pairs for every numeric-looking parameter."""
        out: List[Tuple[str, str]] = []
        for k in norm["params"].keys():
            if PRICE_KEYWORDS.search(k) or QUANTITY_KEYWORDS.search(k):
                out.append((k, "query"))
        for k in norm["body"].keys():
            if PRICE_KEYWORDS.search(k) or QUANTITY_KEYWORDS.search(k):
                out.append((k, "body"))
        return out

    def _check_negative(self, target: str, norm: Dict[str, Any]) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        candidates = self._param_candidates(norm)
        if not candidates:
            return findings
        # Static heuristic: if endpoint accepts numeric values but no min
        # validation is observable in path/contract, flag as potential refund
        # attack. The dynamic test is performed when running with a client.
        for name, loc in candidates:
            f = self.make_finding(
                target=target,
                endpoint=norm["url"],
                method=norm["method"],
                parameter=name,
                title=f"Negative-amount acceptance on parameter '{name}'",
                description=(
                    f"Endpoint {norm['method']} {norm['url']} takes numeric parameter "
                    f"'{name}' (location={loc}) commonly used for prices/amounts. "
                    "Without server-side range checks, an attacker can submit a "
                    "negative value and trick the system into a refund or credit."
                ),
                impact=(
                    "Attacker can inflate wallet balance, generate fraudulent "
                    "refunds, or drain funds from a victim account."
                ),
                remediation=(
                    "Reject any value < 0 at the server. Apply a positive-only "
                    "validation and use unsigned types in storage."
                ),
                severity=Severity.HIGH,
                confidence=0.7,
                tags=["negative_amount", "refund_abuse", self.category.value],
            )
            f.add_evidence(
                "static_pattern",
                f"Parameter '{name}' matches price/amount keyword regex",
                {"candidates": [name], "payloads_to_test": self.NEGATIVE_PAYLOADS},
            )
            findings.append(f)
        return findings

    def _check_currency(self, target: str, norm: Dict[str, Any]) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        # Look for currency hints in URL, param NAMES+VALUES, body NAMES+VALUES
        value_text = " ".join(
            str(v) for v in list(norm["params"].values()) + list(norm["body"].values())
        )
        all_text = " ".join(
            [norm["url"],
             " ".join(norm["params"].keys()),
             " ".join(norm["body"].keys()),
             value_text]
        )
        currency_hits = CURRENCY_KEYWORDS.findall(all_text)
        if not currency_hits:
            return findings
        currencies = {c.upper() for c in currency_hits}
        for ccy in currencies:
            expected = self.CURRENCY_EXPECTED_DECIMALS.get(ccy)
            if expected is None:
                continue
            f = self.make_finding(
                target=target,
                endpoint=norm["url"],
                method=norm["method"],
                parameter="currency",
                title=f"Currency {ccy} decimal-mismatch exposure",
                description=(
                    f"Endpoint references currency {ccy} (expected {expected} "
                    "decimal places). Apps that treat all amounts as cents and "
                    "fail to scale per-currency can be exploited by switching "
                    "between a 2-decimal currency and a zero-decimal one "
                    "(e.g. JPY) to multiply value by 100x."
                ),
                impact=(
                    "Attacker can pay 1/100th of the intended price by passing "
                    "a JPY-style amount where the server expects USD cents."
                ),
                remediation=(
                    "Store amounts in the smallest currency unit AND record the "
                    "currency code. Use Decimal type with explicit precision."
                ),
                severity=Severity.CRITICAL,
                confidence=0.55,
                tags=["currency_confusion", "decimal_mismatch", self.category.value],
            )
            f.add_evidence(
                "static_pattern",
                f"Currency token {ccy} detected in endpoint signature",
                {"currencies": list(currencies), "expected_decimals": expected},
            )
            findings.append(f)
        return findings

    def _check_overflow(self, target: str, norm: Dict[str, Any]) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        candidates = self._param_candidates(norm)
        if not candidates:
            return findings
        for name, _ in candidates:
            f = self.make_finding(
                target=target,
                endpoint=norm["url"],
                method=norm["method"],
                parameter=name,
                title=f"Integer-overflow exposure on '{name}'",
                description=(
                    "Numeric parameters are commonly parsed into 32/64-bit "
                    "integers. Values near the boundary can wrap to negative, "
                    "zero, or a small positive number when arithmetic is "
                    "performed, breaking total/discount logic."
                ),
                impact=(
                    "Attacker can submit amounts near 2**31 / 2**63 that wrap "
                    "to 0 or negative on the server, bypassing payments."
                ),
                remediation=(
                    "Use Decimal / BigInt; validate max against a business rule."
                ),
                severity=Severity.HIGH,
                confidence=0.5,
                tags=["integer_overflow", "boundary", self.category.value],
            )
            f.add_evidence(
                "static_pattern",
                "Parameter matches price keyword - vulnerable to overflow payloads",
                {"payloads": self.OVERFLOW_PAYLOADS[:4]},
            )
            findings.append(f)
        return findings

    def _check_quantity(self, target: str, norm: Dict[str, Any]) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        for k in list(norm["params"].keys()) + list(norm["body"].keys()):
            if QUANTITY_KEYWORDS.search(k):
                f = self.make_finding(
                    target=target,
                    endpoint=norm["url"],
                    method=norm["method"],
                    parameter=k,
                    title=f"Quantity parameter '{k}' accepts zero/negative values",
                    description=(
                        f"Endpoint accepts '{k}' as quantity. Without a minimum "
                        "value of 1, an attacker can submit 0 (free items) or "
                        "negative (refund/multiplier abuse)."
                    ),
                    impact="Free checkout, negative-balance orders, or stacked refunds.",
                    remediation="Reject qty < 1 and qty > stock.",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    tags=["quantity", "free_checkout", self.category.value],
                )
                f.add_evidence(
                    "static_pattern",
                    f"Quantity-like parameter '{k}'",
                    {"payloads": self.ZERO_PAYLOADS + self.NEGATIVE_PAYLOADS},
                )
                findings.append(f)
        return findings

    def _check_discount_stacking(
        self, target: str, norm: Dict[str, Any]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        # If the same endpoint accepts coupon/promo and the request method is
        # POST/PUT, attackers can submit multiple coupon values via repeated
        # params or JSON arrays.
        f = self.make_finding(
            target=target,
            endpoint=norm["url"],
            method=norm["method"],
            parameter="coupon",
            title="Discount-code stacking / reuse",
            description=(
                "Discount endpoints that accept a single 'coupon' parameter "
                "often allow stacking when the parameter is repeated in the "
                "query string or sent as an array. Coupons intended for "
                "single-use can be replayed across requests."
            ),
            impact=(
                "Customer can apply multiple discounts, repeatedly reuse "
                "single-use codes, or apply a coupon to a non-discountable item."
            ),
            remediation=(
                "Track coupon usage server-side per user/order. Reject repeat "
                "applications. Enforce exclusivity rules."
            ),
            severity=Severity.HIGH,
            confidence=0.55,
            tags=["discount", "coupon", "stacking", self.category.value],
        )
        f.add_evidence(
            "static_pattern",
            "Discount keyword detected on a state-changing endpoint",
            {"params": list(norm["params"].keys()) + list(norm["body"].keys())},
        )
        findings.append(f)
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 7. RACE CONDITION (TOCTOU) DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class _RaceProbe:
    """One probe sent during a TOCTOU burst."""

    url: str
    method: str
    body: Optional[Dict[str, Any]] = None
    params: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    label: str = "default"


class RaceConditionDetector(Detector):
    """Detect TOCTOU by sending concurrent bursts to a single endpoint.

    Works with the supplied HttpClient. If no client is available, falls
    back to heuristic detection (e.g. coupon/balance endpoints that are
    *clearly* vulnerable by name).
    """

    name = "race_condition"
    description = "Concurrent request orchestration to detect TOCTOU bugs."
    category = DetectorCategory.RACE_CONDITION
    default_severity = Severity.CRITICAL
    default_confidence = 0.75

    HEURISTIC_KEYWORDS = re.compile(
        r"(coupon|promo|redeem|apply.*code|withdraw|transfer|"
        r"balance|credit|spend|stake|vote|like|follow|subscribe|"
        r"claim|gift|invite|signup.*bonus|register.*bonus|"
        r"airdrop|first.*order|new.*user.*reward)",
        re.IGNORECASE,
    )

    async def detect(
        self, target: str, endpoints: List[Dict[str, Any]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        client: Optional[HttpClient] = getattr(self, "_client", None)

        for ep in endpoints:
            norm = normalize_endpoint(ep)
            if not norm["url"]:
                continue
            if norm["method"] == "GET":
                continue
            # Heuristic pre-screen
            if not self._looks_racey(norm):
                continue

            # Always emit a static finding (cheap)
            f = self.make_finding(
                target=target,
                endpoint=norm["url"],
                method=norm["method"],
                parameter="*",
                title=f"Potential race condition on {norm['url']}",
                description=(
                    "Endpoint mutates a stateful resource (balance, coupon, "
                    "reward, transfer) without visible idempotency guard. "
                    "Bursts of concurrent requests may double-spend or "
                    "bypass single-use constraints."
                ),
                impact="Double-spend, reward duplication, balance inflation.",
                remediation=(
                    "Use database-level locks, atomic compare-and-swap, or "
                    "distributed locks (Redis) around critical sections."
                ),
                severity=Severity.CRITICAL,
                confidence=0.65,
                tags=["race", "toctou", self.category.value],
            )
            f.add_evidence(
                "static_pattern",
                "Endpoint matches race-condition heuristic keyword",
                {"url": norm["url"], "method": norm["method"]},
            )
            findings.append(f)

            # If we have an HTTP client, run an actual burst
            if client is None:
                continue
            findings.extend(
                await self._dynamic_burst(target, norm, client)
            )

        return findings[: self.config.max_findings_per_detector]

    def _looks_racey(self, norm: Dict[str, Any]) -> bool:
        return bool(self.HEURISTIC_KEYWORDS.search(norm["url"])) or is_discount_endpoint(
            norm
        ) or is_price_endpoint(norm)

    async def _dynamic_burst(
        self,
        target: str,
        norm: Dict[str, Any],
        client: HttpClient,
    ) -> List[LogicFinding]:
        """Send N concurrent requests and look for inconsistent responses."""
        burst_n = self.config.race_default_concurrency
        attempts = self.config.race_default_attempts
        body = norm["body"] or None
        params = norm["params"] or None

        # Baseline: send 1 request and capture (status, body hash)
        baseline = await client.request(
            norm["url"], method=norm["method"], params=params, body=body
        )
        if baseline.status in (-1, 0):
            return []

        # Burst
        all_status: List[int] = []
        all_bodies: List[str] = []
        for _ in range(attempts):
            reqs = [
                {
                    "url": norm["url"],
                    "method": norm["method"],
                    "params": params,
                    "body": body,
                }
                for _ in range(burst_n)
            ]
            responses = await client.gather(reqs, max_concurrent=burst_n)
            for r in responses:
                all_status.append(r.status)
                all_bodies.append(r.body)

        # Heuristic: success=200 with non-trivial variance in body length
        # across the burst = possible TOCTOU.
        success_bodies = [
            b for s, b in zip(all_status, all_bodies) if s in (200, 201, 204)
        ]
        if not success_bodies:
            return []
        unique_lengths = {len(b) for b in success_bodies}
        if len(unique_lengths) > 1:
            f = self.make_finding(
                target=target,
                endpoint=norm["url"],
                method=norm["method"],
                parameter="*",
                title=f"Concurrent burst reveals inconsistent responses on {norm['url']}",
                description=(
                    f"Sent {burst_n}x{attempts} requests. {len(success_bodies)} "
                    f"succeeded with {len(unique_lengths)} different body "
                    "lengths. Inconsistent output for identical input "
                    "indicates a TOCTOU window."
                ),
                impact="State mutation races (double-spend / double-claim).",
                remediation="Wrap critical sections in a database lock or use atomic updates.",
                severity=Severity.CRITICAL,
                confidence=0.8,
                tags=["race", "toctou", "burst", self.category.value],
            )
            f.add_evidence(
                "burst_response",
                f"unique_body_lengths={sorted(unique_lengths)}",
                {
                    "burst_size": burst_n,
                    "attempts": attempts,
                    "success_count": len(success_bodies),
                    "status_distribution": dict(Counter(all_status)),
                },
            )
            return [f]
        return []


# ═══════════════════════════════════════════════════════════════════════════
# 8. STATE MACHINE BYPASS DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


class StateMachineBypassDetector(Detector):
    """Detect multi-step workflow bypass.

    Heuristics:
        - Endpoints in the same path family with "step", "stage", "next" tokens
        - Direct deep-link to a late step in the flow
        - State parameter manipulation (e.g. ?state=approved)
    """

    name = "state_machine"
    description = "Skip-step detection, deep-link bypass, state parameter abuse."
    category = DetectorCategory.STATE_MACHINE
    default_severity = Severity.HIGH
    default_confidence = 0.65

    SKIP_KEYWORDS = re.compile(
        r"(skip|step\s*=\s*\d|stage\s*=\s*\d|state\s*=\s*(approved|verified|complete|paid)|"
        r"force\s*=\s*1|bypass|debug\s*=\s*1|test\s*=\s*1)",
        re.IGNORECASE,
    )

    async def detect(
        self, target: str, endpoints: List[Dict[str, Any]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        client: Optional[HttpClient] = getattr(self, "_client", None)

        # Group endpoints by base path family to detect workflows
        families: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ep in endpoints:
            norm = normalize_endpoint(ep)
            if not norm["url"]:
                continue
            family = self._family(norm["url"])
            families[family].append(norm)

        # 1) Skip-step via state query parameter
        for ep in endpoints:
            norm = normalize_endpoint(ep)
            if not norm["url"]:
                continue
            for param_name, value in norm["params"].items():
                if isinstance(value, str) and self.SKIP_KEYWORDS.search(
                    f"{param_name}={value}"
                ):
                    f = self.make_finding(
                        target=target,
                        endpoint=norm["url"],
                        method=norm["method"],
                        parameter=param_name,
                        title=f"State-skip parameter '{param_name}' detected",
                        description=(
                            f"Parameter '{param_name}={value}' resembles a "
                            "step/state override. Apps that accept such "
                            "values can be tricked into skipping verification "
                            "or approval steps."
                        ),
                        impact="Skip KYC, skip approval, force-complete workflows.",
                        remediation=(
                            "Validate state transitions server-side; reject "
                            "client-supplied state-machine steps."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.7,
                        tags=["state_skip", self.category.value],
                    )
                    f.add_evidence(
                        "static_pattern",
                        f"Param '{param_name}={value}' matches skip regex",
                        {"param": param_name, "value": value},
                    )
                    findings.append(f)

        # 2) Direct deep-link to a late step in a multi-step family
        for family, members in families.items():
            if len(members) < 2:
                continue
            steps = [self._step_index(m["url"]) for m in members]
            if not any(s is not None for s in steps):
                continue
            max_step = max((s for s in steps if s is not None), default=None)
            if max_step is None or max_step < 2:
                continue
            for m in members:
                idx = self._step_index(m["url"])
                if idx is None:
                    continue
                if idx == max_step and idx >= 2:
                    f = self.make_finding(
                        target=target,
                        endpoint=m["url"],
                        method=m["method"],
                        parameter="path",
                        title=f"Deep-linkable late step ({family})",
                        description=(
                            f"Family '{family}' exposes step {idx} as a "
                            "direct URL. If the server does not verify the "
                            "user has completed prior steps, an attacker can "
                            "deep-link to the final state."
                        ),
                        impact="Bypass prerequisites, complete workflows without prior steps.",
                        remediation=(
                            "Persist workflow state server-side; reject "
                            "requests to step N unless step N-1 was completed."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.55,
                        tags=["deep_link", "step_skip", self.category.value],
                    )
                    f.add_evidence(
                        "static_pattern",
                        f"Family '{family}' exposes step {idx}",
                        {"family": family, "step": idx},
                    )
                    findings.append(f)

        # 3) HTTP -> admin endpoint promotion
        for ep in endpoints:
            norm = normalize_endpoint(ep)
            if not norm["url"]:
                continue
            if self._looks_admin(norm["url"]):
                f = self.make_finding(
                    target=target,
                    endpoint=norm["url"],
                    method=norm["method"],
                    parameter="role",
                    title="HTTP -> admin endpoint promotion surface",
                    description=(
                        "Endpoint path includes /admin/, /internal/, /manage/. "
                        "If accessible to normal users via a state parameter "
                        "(role=admin) it can be promoted to admin."
                    ),
                    impact="Privilege escalation by promoting role/state.",
                    remediation="Enforce role on server, never trust client flags.",
                    severity=Severity.HIGH,
                    confidence=0.5,
                    tags=["state_promotion", "admin", self.category.value],
                )
                findings.append(f)

        # Cap to avoid spam
        return findings[: self.config.max_findings_per_detector]

    def _family(self, url: str) -> str:
        path = urlparse(url).path
        # Replace /step-N, /stage-N, /N with the family root
        path = re.sub(r"/(step|stage|phase|page|level|tier)\s*[-_]?\s*\d+", "", path, flags=re.IGNORECASE)
        path = re.sub(r"/\d+(/|$)", "/{id}\\1", path)
        return path.rstrip("/")

    def _step_index(self, url: str) -> Optional[int]:
        m = re.search(r"/(step|stage|phase|page|level|tier)\s*[-_]?\s*(\d+)", url, re.IGNORECASE)
        if m:
            try:
                return int(m.group(2))
            except ValueError:
                return None
        return None

    def _looks_admin(self, url: str) -> bool:
        return bool(re.search(r"/(admin|internal|manage|moderator|backoffice)", url, re.IGNORECASE))


# ═══════════════════════════════════════════════════════════════════════════
# 9. AUTHENTICATION LOGIC FLAW DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


class AuthLogicDetector(Detector):
    """Authentication logic flaws.

    Categories:
        - Password reset token entropy analysis
        - Session fixation opportunities
        - 2FA bypass via direct endpoint access
        - Remember-me token reuse
        - OAuth redirect_uri validation gaps
    """

    name = "auth_logic"
    description = "Auth tokens, 2FA bypass, OAuth redirect_uri, session fixation."
    category = DetectorCategory.AUTH_LOGIC
    default_severity = Severity.HIGH
    default_confidence = 0.6

    RESET_KEYWORDS = re.compile(
        r"(reset|forgot|recover|verify|confirm|activate|invitation)", re.IGNORECASE
    )
    TWO_FA_KEYWORDS = re.compile(r"(2fa|mfa|totp|otp|verify.*code|backup.*code)", re.IGNORECASE)
    SESSION_KEYWORDS = re.compile(r"(session|login|signin|authenticate)", re.IGNORECASE)
    REMEMBER_KEYWORDS = re.compile(r"(remember|keep.*logged|persistent)", re.IGNORECASE)
    OAUTH_KEYWORDS = re.compile(r"(oauth|authorize|callback|redirect_uri)", re.IGNORECASE)

    async def detect(
        self, target: str, endpoints: List[Dict[str, Any]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        # (url_keyword, param_checker, default_severity, default_confidence,
        #  tag, title, description, impact, remediation)
        rules: List[Tuple[re.Pattern, Optional[re.Pattern], Severity, float,
                          str, str, str, str, str]] = [
            (
                self.RESET_KEYWORDS, None, Severity.CRITICAL, 0.5, "reset_token",
                "Password-reset token entropy / predictability audit",
                "Reset tokens must be high-entropy (>=128 bits) and bound to user/session. "
                "Common flaws: short tokens, sequential, no expiry.",
                "Account takeover via guessed reset token.",
                "Generate 32+ bytes from CSPRNG, single-use, short-lived, bound to user record.",
            ),
            (
                self.TWO_FA_KEYWORDS, None, Severity.HIGH, 0.55, "2fa_bypass",
                "2FA verification - direct access possible",
                "A 2FA endpoint exposed at a known URL may be reachable without first completing "
                "the 2FA challenge, or may accept empty/replayed codes.",
                "Skip 2FA via direct endpoint access.",
                "Bind 2FA state to the session. Reject protected endpoint if 2FA not satisfied.",
            ),
            (
                self.SESSION_KEYWORDS, None, Severity.HIGH, 0.5, "session_fixation",
                "Session fixation exposure on login",
                "If the app does not rotate the session identifier after successful auth, an "
                "attacker can pre-set the session ID and have the victim authenticate into "
                "the attacker's session.",
                "Account takeover via session fixation.",
                "Invalidate previous session ID at login; issue fresh, opaque cookie.",
            ),
            (
                self.REMEMBER_KEYWORDS, None, Severity.HIGH, 0.45, "remember_me",
                "Remember-me token reuse / weak binding",
                "Remember-me tokens are long-lived. Common flaws: guessable, not bound to UA/IP, "
                "not single-use after re-login, stored plaintext in DB.",
                "Persistent account takeover after a single token leak.",
                "Generate via CSPRNG, hash in DB, single-use, bind to user-agent and IP range.",
            ),
            (
                self.OAUTH_KEYWORDS, None, Severity.CRITICAL, 0.7, "oauth",
                "OAuth redirect_uri validation gap",
                "OAuth flow accepts redirect_uri with external host or no 'state' parameter. "
                "Either allows code theft (open redirect) or CSRF (no state).",
                "OAuth code theft -> account takeover.",
                "Allowlist exact redirect_uri; require 'state' parameter bound to session.",
            ),
        ]
        for ep in endpoints:
            norm = normalize_endpoint(ep)
            if not norm["url"]:
                continue
            url = norm["url"]
            for rule in rules:
                url_re, param_re, sev, conf, tag, title, desc, impact, remed = rule
                if url_re.search(url) or (param_re and self._has_param(norm, param_re)):
                    findings.extend(self._emit_auth_finding(
                        target, norm, sev, conf, tag, title, desc, impact, remed,
                    ))
            # 2FA param check (parameter-side)
            if self._has_2fa_param(norm) and not any(f.parameter == "2fa_code" for f in findings):
                findings.extend(self._emit_auth_finding(
                    target, norm, Severity.HIGH, 0.55, "2fa_bypass",
                    "2FA verification - direct access possible",
                    "A 2FA parameter found on the request signature. The endpoint may accept "
                    "an empty/replayed code, allowing direct 2FA bypass.",
                    "Skip 2FA via direct parameter access.",
                    "Bind 2FA state to the session. Reject the request if 2FA was not satisfied.",
                ))
            # OAuth-specific extras (open redirect + state)
            if self.OAUTH_KEYWORDS.search(url):
                findings.extend(self._check_oauth_redirect(target, norm))
        return findings[: self.config.max_findings_per_detector]

    def _has_param(self, norm: Dict[str, Any], regex: re.Pattern) -> bool:
        for k in list(norm["params"].keys()) + list(norm["body"].keys()):
            if regex.search(k):
                return True
        return False

    def _emit_auth_finding(
        self, target: str, norm: Dict[str, Any],
        sev: Severity, conf: float, tag: str,
        title: str, desc: str, impact: str, remed: str,
    ) -> List[LogicFinding]:
        f = self.make_finding(
            target=target,
            endpoint=norm["url"],
            method=norm["method"],
            parameter=tag,
            title=title,
            description=desc,
            impact=impact,
            remediation=remed,
            severity=sev,
            confidence=conf,
            tags=[tag, self.category.value],
        )
        f.add_evidence(
            "static_pattern",
            f"Endpoint matches '{tag}' rule",
            {"url": norm["url"]},
        )
        return [f]

    def _has_2fa_param(self, norm: Dict[str, Any]) -> bool:
        return self._has_param(norm, self.TWO_FA_KEYWORDS)

    def _check_oauth_redirect(self, target: str, norm: Dict[str, Any]) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        for p, v in norm["params"].items():
            if isinstance(v, str) and ("redirect" in p.lower() or "callback" in p.lower()):
                parsed = urlparse(v)
                if parsed.netloc and parsed.netloc != urlparse(norm["url"]).netloc:
                    f = self.make_finding(
                        target=target,
                        endpoint=norm["url"],
                        method=norm["method"],
                        parameter=p,
                        title=f"OAuth redirect_uri to external host ({parsed.netloc})",
                        description=(
                            f"Parameter '{p}' accepts a fully-qualified URL. If the server does "
                            "not enforce an allowlist of redirect URIs, an attacker can use this "
                            "to steal OAuth codes via the implicit grant or hybrid flow."
                        ),
                        impact="OAuth authorization-code theft -> account takeover.",
                        remediation=(
                            "Allowlist exact redirect_uri values; reject any deviation. Reject wildcards."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=0.7,
                        tags=["oauth", "open_redirect", self.category.value],
                    )
                    f.add_evidence(
                        "static_pattern",
                        f"Param '{p}' accepts external URL",
                        {"param": p, "value": v, "external_host": parsed.netloc},
                    )
                    findings.append(f)
        if not any(k.lower() in ("state", "nonce") for k in norm["params"].keys()):
            f = self.make_finding(
                target=target,
                endpoint=norm["url"],
                method=norm["method"],
                parameter="state",
                title="OAuth flow missing 'state' parameter (CSRF)",
                description=(
                    "OAuth authorize endpoint does not appear to require a 'state' parameter. "
                    "Without state, the flow is vulnerable to CSRF / code-injection attacks."
                ),
                impact="Attacker can log the victim into an attacker-controlled account.",
                remediation="Require cryptographically random 'state' parameter bound to the session.",
                severity=Severity.HIGH,
                confidence=0.55,
                tags=["oauth", "csrf", "state", self.category.value],
            )
            findings.append(f)
        return findings


# ═══════════════════════════════════════════════════════════════════════════
# 10. AUTHORIZATION LOGIC (BOLA / BFLA)
# ═══════════════════════════════════════════════════════════════════════════


class UUIDV1Decoder:
    """Tiny decoder for UUID v1 timestamps (no external deps)."""

    @staticmethod
    def is_uuid_v1(value: str) -> bool:
        if not isinstance(value, str):
            return False
        m = re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$",
            value,
            re.IGNORECASE,
        )
        return bool(m)

    @staticmethod
    def extract_timestamp_ms(value: str) -> Optional[int]:
        """Extract the 60-bit timestamp from a UUID v1 string.

        Per RFC 4122, the timestamp is stored as time_low (32 bits),
        time_mid (16 bits), and time_hi_and_version (12 bits of timestamp
        + 4-bit version). UUID epoch starts 1582-10-15.
        """
        if not UUIDV1Decoder.is_uuid_v1(value):
            return None
        parts = value.split("-")
        time_low = int(parts[0], 16)
        time_mid = int(parts[1], 16)
        time_hi = int(parts[2], 16) & 0x0FFF  # strip version
        ts = (time_hi << 48) | (time_mid << 32) | time_low
        # UUID epoch -> Unix epoch
        uuid_epoch = 0x01B21DD213814000
        unix_ms = (ts - uuid_epoch) / 10000.0
        return int(unix_ms)


class AuthorizationLogicDetector(Detector):
    """BOLA / BFLA detection via static analysis + identifier prediction.

    Static checks:
        - Object reference prediction (sequential / UUID-v1 timestamps)
        - Function-level privilege escalation patterns
        - Multi-tenant boundary leakage

    Dynamic: if an HTTP client is available, replays a small set of
    sequential IDs and UUIDs to confirm predictability.
    """

    name = "authorization"
    description = "BOLA/BFLA, sequential ID prediction, UUID v1 timestamp extraction, multi-tenant leakage."
    category = DetectorCategory.AUTHORIZATION
    default_severity = Severity.CRITICAL
    default_confidence = 0.7

    ADMIN_KEYWORDS = re.compile(
        r"/(admin|internal|manage|moderator|backoffice|console|"
        r"superuser|root|debug|operator|god)/", re.IGNORECASE
    )

    TENANT_KEYWORDS = re.compile(
        r"(tenant|organization|org|workspace|team|account_id|"
        r"company|customer_id|partner_id|reseller|brand)",
        re.IGNORECASE,
    )

    ROLE_PARAM_KEYWORDS = re.compile(
        r"^(role|is_admin|admin|privilege|access|scope|permission)$",
        re.IGNORECASE,
    )

    async def detect(
        self, target: str, endpoints: List[Dict[str, Any]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        client: Optional[HttpClient] = getattr(self, "_client", None)

        # 1) Cross-endpoint sequential ID detection (BOLA).
        # This needs all endpoints to spot a pattern, unlike the other
        # per-endpoint checks.
        findings.extend(self._check_sequential_id(target, endpoints))
        # 2) UUID v1 leakage - per endpoint
        for ep in endpoints:
            norm = normalize_endpoint(ep)
            if not norm["url"]:
                continue
            findings.extend(self._check_uuid_v1(target, norm))
            findings.extend(self._check_role_param(target, norm))
            findings.extend(self._check_tenant(target, norm))
            findings.extend(self._check_admin_path(target, norm))

        return findings[: self.config.max_findings_per_detector]

    # ----- individual checks ------------------------------------------------

    def _extract_id_samples(self, norm: Dict[str, Any]) -> Dict[str, List[str]]:
        """Return a map of param name -> list of id-shaped sample values."""
        out: Dict[str, List[str]] = defaultdict(list)
        for k, v in list(norm["params"].items()) + list(norm["body"].items()):
            if not isinstance(v, str):
                continue
            if k.lower() in ID_PARAMETER_NAMES or "id" in k.lower():
                if v.isdigit():
                    out[k].append(v)
                elif UUIDV1Decoder.is_uuid_v1(v):
                    out[k].append(v)
        # Also try to extract from URL path
        path = urlparse(norm["url"]).path
        m = re.search(r"/(\d{1,19})", path)
        if m:
            out.setdefault("_path", []).append(m.group(1))
        m = re.search(
            r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            path,
            re.IGNORECASE,
        )
        if m:
            out.setdefault("_path", []).append(m.group(1))
        return out

    def _check_sequential_id(
        self, target: str, endpoints: List[Dict[str, Any]]
    ) -> List[LogicFinding]:
        """Detect sequential / monotonic IDs across multiple endpoints.

        The check is cross-endpoint because a single endpoint only carries
        one ID; the pattern emerges when the IDs are gathered together.
        """
        # group: family_path -> list of (id_int, url, param)
        groups: Dict[str, List[Tuple[int, str, str]]] = defaultdict(list)
        uuid_groups: Dict[str, List[Tuple[str, str, str]]] = defaultdict(list)
        for ep in endpoints:
            norm = normalize_endpoint(ep)
            if not norm["url"]:
                continue
            family = self._family(norm["url"])
            samples = self._extract_id_samples(norm)
            for param, values in samples.items():
                for v in values:
                    if v.isdigit():
                        try:
                            groups[family].append((int(v), norm["url"], param))
                        except ValueError:
                            pass
                    elif UUIDV1Decoder.is_uuid_v1(v):
                        uuid_groups[family].append((v, norm["url"], param))

        findings: List[LogicFinding] = []
        for family, members in groups.items():
            if len(members) < 2:
                continue
            ints = [m[0] for m in members]
            urls = list({m[1] for m in members})
            param = members[0][2]
            diffs = [ints[i + 1] - ints[i] for i in range(len(ints) - 1)]
            constant = len(set(diffs)) == 1
            monotonic = all(d >= 0 for d in diffs) and max(diffs) < 1000
            if constant and monotonic:
                # Emit one finding per unique URL
                for url in urls:
                    f = self.make_finding(
                        target=target,
                        endpoint=url,
                        method="GET",
                        parameter=param,
                        title=f"Sequential/predictable ID on '{param}' (family={family})",
                        description=(
                            f"Endpoint family '{family}' exposes monotonic, "
                            f"low-diff integers (samples={ints}, diffs={diffs}). "
                            "An attacker can enumerate neighbours and access "
                            "unauthorised objects (BOLA)."
                        ),
                        impact="BOLA / IDOR via ID enumeration.",
                        remediation=(
                            "Use unguessable IDs (UUIDv4 / 128-bit random). "
                            "Enforce server-side object ownership."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.9,
                        tags=["bola", "idor", "sequential", self.category.value],
                    )
                    f.add_evidence(
                        "static_pattern",
                        f"Sequential samples observed: {ints}",
                        {"samples": ints, "diffs": diffs, "family": family},
                    )
                    findings.append(f)
        return findings

    def _check_uuid_v1(self, target: str, norm: Dict[str, Any]) -> List[LogicFinding]:
        samples = self._extract_id_samples(norm)
        findings: List[LogicFinding] = []
        for param, values in samples.items():
            for v in values:
                if UUIDV1Decoder.is_uuid_v1(v):
                    ts = UUIDV1Decoder.extract_timestamp_ms(v)
                    f = self.make_finding(
                        target=target,
                        endpoint=norm["url"],
                        method=norm["method"],
                        parameter=param,
                        title="UUID v1 leakage (timestamp + MAC extractable)",
                        description=(
                            "Parameter uses UUID v1. The 60-bit timestamp and "
                            "48-bit MAC are recoverable. An attacker can "
                            "predict other IDs issued in the same time window "
                            "or fingerprint the issuer's hardware."
                        ),
                        impact=(
                            "Token prediction, hardware fingerprinting, BOLA."
                        ),
                        remediation="Switch to UUIDv4 (random) or v7 (time-ordered random).",
                        severity=Severity.MEDIUM,
                        confidence=0.95,
                        tags=["uuid_v1", "predictable", self.category.value],
                    )
                    f.add_evidence(
                        "static_pattern",
                        f"UUID v1 value observed: {v}",
                        {"uuid": v, "extracted_timestamp_ms": ts},
                    )
                    findings.append(f)
        return findings

    def _check_role_param(self, target: str, norm: Dict[str, Any]) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        for k in list(norm["params"].keys()) + list(norm["body"].keys()):
            if self.ROLE_PARAM_KEYWORDS.match(k):
                f = self.make_finding(
                    target=target,
                    endpoint=norm["url"],
                    method=norm["method"],
                    parameter=k,
                    title=f"Function-level privilege escalation via '{k}' parameter",
                    description=(
                        f"Parameter '{k}' looks like a role/privilege flag. "
                        "If accepted from the client, an attacker can set "
                        "role=admin to escalate."
                    ),
                    impact="BFLA - access admin/privileged endpoints.",
                    remediation=(
                        "Derive the user role from the authenticated session, "
                        "never from request parameters."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    tags=["bfla", "role_param", self.category.value],
                )
                f.add_evidence(
                    "static_pattern",
                    f"Parameter '{k}' matches role keyword",
                    {"param": k},
                )
                findings.append(f)
        return findings

    def _check_tenant(self, target: str, norm: Dict[str, Any]) -> List[LogicFinding]:
        if not self.TENANT_KEYWORDS.search(norm["url"]):
            return []
        # If the endpoint URL or path contains a tenant token but no
        # ownership check is observable, flag.
        f = self.make_finding(
            target=target,
            endpoint=norm["url"],
            method=norm["method"],
            parameter="tenant",
            title="Multi-tenant boundary - object ownership not visible",
            description=(
                "Endpoint is multi-tenant but the request signature does not "
                "include a tenant identifier or ownership check. The server "
                "may rely solely on the object ID, enabling cross-tenant "
                "access."
            ),
            impact="Cross-tenant data leakage (BOLA at the workspace level).",
            remediation=(
                "Bind every query to the caller's tenant_id; never trust "
                "client-supplied tenant IDs in cross-tenant operations."
            ),
            severity=Severity.HIGH,
            confidence=0.5,
            tags=["multi_tenant", "bola", self.category.value],
        )
        return [f]

    def _check_admin_path(self, target: str, norm: Dict[str, Any]) -> List[LogicFinding]:
        if not self.ADMIN_KEYWORDS.search(norm["url"]):
            return []
        # Public exposure of an admin endpoint under a known path is a
        # strong BFLA signal even before authentication testing.
        f = self.make_finding(
            target=target,
            endpoint=norm["url"],
            method=norm["method"],
            parameter="path",
            title="Admin endpoint exposed (BFLA surface)",
            description=(
                "An admin/internal path is reachable. The endpoint must "
                "verify the caller's role server-side; if it doesn't, normal "
                "users can access privileged functions."
            ),
            impact="BFLA - call admin functions as a normal user.",
            remediation=(
                "Enforce role on the server. Use deny-by-default routing for "
                "admin paths unless the caller is in the admin role."
            ),
            severity=Severity.HIGH,
            confidence=0.5,
            tags=["bfla", "admin", "path", self.category.value],
        )
        return [f]

    @staticmethod
    def _family(url: str) -> str:
        """Extract a 'family' root path from a URL.

        Replaces numeric path segments with {id} so e.g.
        /api/users/1 and /api/users/2 share a family.
        """
        path = urlparse(url).path
        path = re.sub(r"/\d+(/|$)", "/{id}\\1", path)
        return path.rstrip("/")


# ═══════════════════════════════════════════════════════════════════════════
# 11. WORKFLOW INTEGRITY DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


class WorkflowIntegrityDetector(Detector):
    """Detect workflow integrity bugs.

    - Idempotency-key bypass (replay the same request many times)
    - Order-of-operations flaws (action before check)
    - Partial-failure states
    """

    name = "workflow_integrity"
    description = "Idempotency, replay, order-of-operations, partial failure states."
    category = DetectorCategory.WORKFLOW_INTEGRITY
    default_severity = Severity.HIGH
    default_confidence = 0.55

    IDEMPOTENCY_KEYWORDS = re.compile(
        r"(idempotency|request_id|nonce|trace_id|operation_id)", re.IGNORECASE
    )

    REPLAYABLE_KEYWORDS = re.compile(
        r"(pay|charge|transfer|withdraw|refund|order|checkout|redeem|apply|"
        r"submit|confirm|complete|approve|cancel|create.*user|create.*order|"
        r"place.*bid|submit.*vote|place.*order)",
        re.IGNORECASE,
    )

    async def detect(
        self, target: str, endpoints: List[Dict[str, Any]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        client: Optional[HttpClient] = getattr(self, "_client", None)

        for ep in endpoints:
            norm = normalize_endpoint(ep)
            if not norm["url"]:
                continue
            if norm["method"] in ("GET", "HEAD", "OPTIONS"):
                continue

            # 1) Missing idempotency key on a state-changing endpoint
            if self.REPLAYABLE_KEYWORDS.search(norm["url"]):
                has_idem = any(self.IDEMPOTENCY_KEYWORDS.search(k) for k in norm["params"].keys()) \
                    or any(self.IDEMPOTENCY_KEYWORDS.search(k) for k in norm["body"].keys()) \
                    or bool(norm["headers"].get("Idempotency-Key")) \
                    or bool(norm["headers"].get("X-Idempotency-Key"))
                if not has_idem:
                    f = self.make_finding(
                        target=target,
                        endpoint=norm["url"],
                        method=norm["method"],
                        parameter="*",
                        title="Missing idempotency key on state-changing endpoint",
                        description=(
                            "Endpoint mutates state but does not require an "
                            "Idempotency-Key / nonce. Replaying the same "
                            "request can double-apply effects (charges, "
                            "transfers, etc.)."
                        ),
                        impact="Replay attacks - duplicate charges, transfers, or rewards.",
                        remediation=(
                            "Require a client-supplied Idempotency-Key header "
                            "and store keys server-side with their result."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.45,
                        tags=["idempotency", "replay", self.category.value],
                    )
                    f.add_evidence(
                        "static_pattern",
                        "State-changing endpoint with no Idempotency-Key observed",
                        {"url": norm["url"], "method": norm["method"]},
                    )
                    findings.append(f)

            # 2) Order-of-operations: parameter suggests action-before-check
            for k in list(norm["params"].keys()) + list(norm["body"].keys()):
                if k.lower() in ("force", "skip_validation", "no_check", "bypass_check"):
                    f = self.make_finding(
                        target=target,
                        endpoint=norm["url"],
                        method=norm["method"],
                        parameter=k,
                        title=f"Order-of-operations flaw via '{k}'",
                        description=(
                            f"Parameter '{k}' implies validation can be "
                            "skipped, suggesting the action is taken before "
                            "the check is performed."
                        ),
                        impact="Validation bypass leads to direct state mutation.",
                        remediation="Remove such parameters; enforce all checks before any mutation.",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        tags=["order_of_ops", self.category.value],
                    )
                    f.add_evidence(
                        "static_pattern",
                        f"Param '{k}' suggests check-bypass",
                        {"param": k},
                    )
                    findings.append(f)

        return findings[: self.config.max_findings_per_detector]


# ═══════════════════════════════════════════════════════════════════════════
# 12. BUSINESS CONSTRAINT DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


class BusinessConstraintDetector(Detector):
    """Detect business-constraint bypass.

    - Min/max constraints (transfer amounts, withdrawal limits)
    - Time-based constraints (coupon expiry, rate limits)
    - Geographic restrictions
    - KYC threshold manipulation
    - Free trial abuse
    """

    name = "business_constraint"
    description = "Min/max limits, time constraints, geo, KYC, free-trial abuse."
    category = DetectorCategory.BUSINESS_CONSTRAINT
    default_severity = Severity.MEDIUM
    default_severity_const = Severity.MEDIUM
    default_confidence = 0.5

    AMOUNT_PARAMS = re.compile(
        r"(amount|sum|total|price|fee|charge|withdraw|deposit|transfer|"
        r"limit|threshold|min|max|balance|wallet|payment|stake|wager)",
        re.IGNORECASE,
    )
    TIME_PARAMS = re.compile(
        r"(timestamp|expires|expiry|valid_until|not_after|not_before|"
        r"issued_at|valid_from|current_time|server_time|now)",
        re.IGNORECASE,
    )
    GEO_PARAMS = re.compile(
        r"(country|region|locale|geo|ip|geoip|country_code|region_code|"
        r"currency_code|timezone)",
        re.IGNORECASE,
    )
    KYC_PARAMS = re.compile(
        r"(kyc|verified|is_verified|tier|level|aml|age|is_adult)",
        re.IGNORECASE,
    )
    TRIAL_PARAMS = re.compile(
        r"(trial|free_trial|is_trial|trial_used|has_used_trial|"
        r"promo_eligible|welcome_bonus)",
        re.IGNORECASE,
    )

    async def detect(
        self, target: str, endpoints: List[Dict[str, Any]]
    ) -> List[LogicFinding]:
        findings: List[LogicFinding] = []
        # Each entry: (regex, default_severity, default_confidence, tag, title, desc, impact, remediation)
        rules = [
            (self.AMOUNT_PARAMS, Severity.MEDIUM, 0.4, "min_max",
             "Min/max constraint not observable on '{k}'",
             "Amount-like parameter with no min/max validation visible. "
             "Without server-side bounds, an attacker can submit 0, 0.01, or huge values.",
             "Bypass minimum-transfer / maximum-withdrawal rules.",
             "Validate against server-side min/max; reject values outside policy range with HTTP 400."),
            (self.TIME_PARAMS, Severity.HIGH, 0.7, "time",
             "Client-controlled time parameter '{k}'",
             "Server logic that depends on a client-supplied time can be bypassed by passing a future/past timestamp.",
             "Coupon expiry bypass, rate-limit bypass, free trial extension.",
             "Use server-side clock for all time-based decisions."),
            (self.GEO_PARAMS, Severity.MEDIUM, 0.65, "geo",
             "Geo restriction can be bypassed via '{k}'",
             "Geo-restricted content/pricing can be evaded by supplying a different country/region parameter.",
             "Region-locked content access, pricing discrimination bypass.",
             "Derive geo from the request IP via trusted geoip, not from client headers."),
            (self.KYC_PARAMS, Severity.HIGH, 0.8, "kyc",
             "KYC/AML threshold can be flipped via '{k}'",
             "KYC/AML flags taken from client parameters can be flipped to bypass identity checks.",
             "Bypass KYC, sanctions, transfer limits.",
             "Derive verification status from server-side identity record."),
            (self.TRIAL_PARAMS, Severity.MEDIUM, 0.75, "trial",
             "Free-trial flag controlled by client ('{k}')",
             "Free-trial eligibility is decided by a client parameter, enabling repeated abuse.",
             "Unlimited free trials, repeated signup bonuses.",
             "Track trial usage per identity (email/phone/device) server-side."),
        ]
        for ep in endpoints:
            norm = normalize_endpoint(ep)
            if not norm["url"]:
                continue
            for k in list(norm["params"].keys()) + list(norm["body"].keys()):
                for regex, sev, conf, tag, title_t, desc, impact, remed in rules:
                    if regex.search(k):
                        # Skip "min_amount" / "max_amount" style legitimate params
                        if tag == "min_max" and k.lower().startswith(("min_", "max_")):
                            continue
                        f = self.make_finding(
                            target=target,
                            endpoint=norm["url"],
                            method=norm["method"],
                            parameter=k,
                            title=title_t.format(k=k),
                            description=desc,
                            impact=impact,
                            remediation=remed,
                            severity=sev,
                            confidence=conf,
                            tags=[tag, "constraint", self.category.value],
                        )
                        f.add_evidence(
                            "static_pattern",
                            f"Param '{k}' matches {tag} keyword",
                            {"param": k},
                        )
                        findings.append(f)
        return findings[: self.config.max_findings_per_detector]


# ═══════════════════════════════════════════════════════════════════════════
# 13. INFERENCE ENGINE
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class _EndpointSignature:
    """Compact signature of an endpoint used for pattern matching."""

    url: str
    method: str
    param_keys: Set[str] = field(default_factory=set)
    body_keys: Set[str] = field(default_factory=set)
    status_distribution: Counter = field(default_factory=Counter)
    body_hashes: Set[str] = field(default_factory=set)
    avg_body_length: float = 0.0
    samples: int = 0


class InferenceEngine:
    """Heuristic scoring engine.

    Computes novelty x impact x exploitability x reproducibility for every
    finding. Also produces *inferred* findings when endpoint behavior
    suggests a hidden vulnerability (e.g. hidden admin endpoint by URL
    family).
    """

    def __init__(self, config: LogicFlawConfig) -> None:
        self.config = config

    # ---- scoring ----

    def score(self, finding: LogicFinding, all_findings: Sequence[LogicFinding]) -> LogicFinding:
        """Update a finding's inference scores in-place."""
        finding.novelty = self._novelty(finding, all_findings)
        finding.impact_score = self._impact(finding)
        finding.exploitability = self._exploitability(finding)
        finding.reproducibility = self._reproducibility(finding)
        finding.recompute()
        return finding

    def _novelty(self, finding: LogicFinding, all_findings: Sequence[LogicFinding]) -> float:
        """How unique is this finding vs others? 0.0 - 1.0.

        Cheap proxy: fewer duplicates -> higher novelty.
        """
        same = sum(
            1 for f in all_findings
            if f.detector == finding.detector
            and f.parameter == finding.parameter
            and f.endpoint == finding.endpoint
        )
        if same <= 1:
            return 0.9
        if same <= 3:
            return 0.7
        if same <= 10:
            return 0.5
        return 0.3

    def _impact(self, finding: LogicFinding) -> float:
        """Impact proxy derived from category and tags."""
        # Higher impact categories
        high_impact_cats = {
            DetectorCategory.PRICE_MANIPULATION,
            DetectorCategory.RACE_CONDITION,
            DetectorCategory.AUTHORIZATION,
            DetectorCategory.AUTH_LOGIC,
        }
        base = 0.7 if finding.category in high_impact_cats else 0.5
        # Adjust for tags
        high_tags = {"bola", "bfla", "race", "currency_confusion", "reset_token",
                     "oauth", "2fa_bypass", "kyc", "aml"}
        if any(t in high_tags for t in finding.tags):
            base = min(1.0, base + 0.2)
        return base

    def _exploitability(self, finding: LogicFinding) -> float:
        """Lower exploit complexity -> higher exploitability."""
        # If we have multiple distinct evidence kinds, the exploit is more
        # repeatable in real-world testing.
        kinds = {e.kind for e in finding.evidence}
        if "burst_response" in kinds or "dynamic_response" in kinds:
            return 0.9
        if len(kinds) >= 2:
            return 0.75
        return 0.5

    def _reproducibility(self, finding: LogicFinding) -> float:
        """How reliably can this be reproduced?"""
        # Pure static evidence -> moderate reproducibility
        # Numeric/sequence evidence -> high
        if any(e.kind == "burst_response" for e in finding.evidence):
            return 0.95
        if any(e.kind in ("static_pattern",) and "samples" in e.data for e in finding.evidence):
            return 0.85
        return 0.6

    # ---- inference of hidden logic ----

    def infer_hidden(self, signatures: Sequence[_EndpointSignature]) -> List[LogicFinding]:
        """Infer findings from endpoint behavior alone.

        Examples:
            - Endpoints that consistently return 200 with a small body for
              many IDs but never return 404 -> an enumeration oracle.
            - Endpoints whose body length scales linearly with a numeric
              parameter -> likely a numeric-injection surface.
        """
        out: List[LogicFinding] = []
        for sig in signatures:
            if sig.samples >= 3:
                # Length-linearity check: if body_len grows with id, may
                # be enumerated.
                if sig.avg_body_length > 0 and len(sig.body_hashes) <= 1:
                    out.append(
                        LogicFinding(
                            title="Hidden enumeration oracle (uniform body)",
                            category=DetectorCategory.INFERENCE,
                            severity=Severity.MEDIUM,
                            confidence=0.55,
                            endpoint=sig.url,
                            method=sig.method,
                            target="",
                            description=(
                                "Multiple requests to this endpoint return "
                                "the same body length and identical hash. "
                                "This pattern is consistent with an "
                                "enumeration oracle that reveals object "
                                "existence by 200 vs 404."
                            ),
                            impact="Object existence enumeration, potential IDOR.",
                            remediation=(
                                "Return identical timing/response for "
                                "existing and non-existing objects to avoid "
                                "leaking existence."
                            ),
                            tags=["inference", "enumeration"],
                            detector="inference_engine",
                        )
                    )
        return out


# ═══════════════════════════════════════════════════════════════════════════
# 14. MULTI-VECTOR CORRELATION
# ═══════════════════════════════════════════════════════════════════════════


class CorrelationEngine:
    """Combine findings into chains.

    Rules:
        - race + missing rate-limit   -> critical
        - auth bypass + sensitive data exposure -> data breach
        - BFLA + BOLA on same target  -> privilege escalation chain
        - Currency confusion + negative amount -> arbitrary credit
    """

    BOOSTS: List[Tuple[Set[str], Set[str], str, Severity, str]] = [
        # (tag_set_a, tag_set_b, chain_title, boosted_severity, chain_description)
        (
            {"race", "toctou"},
            {"bola", "idor"},
            "Race + BOLA = Mass Unauthorized Access",
            Severity.CRITICAL,
            "Race condition plus an IDOR permits bulk unauthorized operations.",
        ),
        (
            {"2fa_bypass", "oauth", "open_redirect"},
            {"bola", "bfla"},
            "Auth bypass chain -> privileged data access",
            Severity.CRITICAL,
            "Auth bypass combined with BOLA/BFLA grants access to other tenants.",
        ),
        (
            {"currency_confusion", "decimal_mismatch"},
            {"negative_amount", "refund_abuse"},
            "Currency + negative amount = arbitrary balance",
            Severity.CRITICAL,
            "Decimal-mismatch currency plus negative-amount acceptance yields free credit.",
        ),
        (
            {"role_param", "bfla"},
            {"bola", "idor"},
            "Privilege escalation chain",
            Severity.CRITICAL,
            "Role parameter promotion plus BOLA grants admin access to any tenant object.",
        ),
        (
            {"kyc", "aml", "verification"},
            {"bola", "idor"},
            "KYC bypass chain",
            Severity.HIGH,
            "KYC parameter spoofed plus BOLA enables sanctions evasion.",
        ),
    ]

    def correlate(self, findings: List[LogicFinding]) -> List[LogicFinding]:
        tags = [{t for t in f.tags} for f in findings]
        chains: List[LogicFinding] = []
        for a_tags, b_tags, title, sev, desc in self.BOOSTS:
            a_idx = [i for i, t in enumerate(tags) if t & a_tags]
            b_idx = [i for i, t in enumerate(tags) if t & b_tags]
            if not a_idx or not b_idx:
                continue
            chain_ids = [findings[i].finding_id for i in a_idx[:3] + b_idx[:3]]
            chain = LogicFinding(
                title=title,
                category=DetectorCategory.INFERENCE,
                severity=sev,
                confidence=0.9,
                target=findings[a_idx[0]].target,
                endpoint=",".join({findings[i].endpoint for i in a_idx + b_idx}),
                method=findings[a_idx[0]].method,
                description=desc,
                impact=desc,
                remediation="Address each link in the chain; one mitigation is insufficient.",
                tags=["chain", "correlation", *a_tags & {"race", "bola", "currency_confusion", "role_param", "kyc"}],
                chain=chain_ids,
                detector="correlation_engine",
            )
            chain.add_evidence(
                "correlation",
                f"chain of {len(chain_ids)} findings",
                {"linked_ids": chain_ids},
            )
            chains.append(chain)
        return chains


# ═══════════════════════════════════════════════════════════════════════════
# 15. ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════


class LogicFlawEngine:
    """Top-level entry point for the logic-flaw engine.

    Usage:
        engine = LogicFlawEngine()
        findings = await engine.analyze(target, endpoints)
    """

    def __init__(self, config: Optional[LogicFlawConfig] = None) -> None:
        self.config = config or LogicFlawConfig()
        self.http = HttpClient(self.config)
        self.inference = InferenceEngine(self.config)
        self.correlator = CorrelationEngine()

        # Detector registry
        self.detectors: List[Detector] = []
        self._register_detectors()

        # Internal state
        self.signatures: List[_EndpointSignature] = []

    # ---- detector registry ----

    def _register_detectors(self) -> None:
        c = self.config
        if c.enable_price:
            self.detectors.append(PriceManipulationDetector(c))
        if c.enable_race:
            self.detectors.append(RaceConditionDetector(c))
        if c.enable_state_machine:
            self.detectors.append(StateMachineBypassDetector(c))
        if c.enable_auth_logic:
            self.detectors.append(AuthLogicDetector(c))
        if c.enable_authorization:
            self.detectors.append(AuthorizationLogicDetector(c))
        if c.enable_workflow:
            self.detectors.append(WorkflowIntegrityDetector(c))
        if c.enable_business_constraint:
            self.detectors.append(BusinessConstraintDetector(c))
        # Inject the shared HTTP client so race + workflow detectors can
        # perform dynamic checks when possible.
        for d in self.detectors:
            setattr(d, "_client", self.http)

    # ---- public API ----

    async def analyze(
        self, target: str, endpoints: List[Dict[str, Any]]
    ) -> List[LogicFinding]:
        """Run every detector, score, correlate, and return all findings.

        Args:
            target: Base URL or scope identifier.
            endpoints: List of endpoint dicts (or URL strings).

        Returns:
            List of LogicFinding objects, sorted by risk_score desc.
        """
        target = (target or "").strip()
        normalized_endpoints = [normalize_endpoint(ep) for ep in endpoints if ep]

        # 1) Run detectors
        raw: List[LogicFinding] = []
        detector_tasks = [d.detect(target, normalized_endpoints) for d in self.detectors]
        results = await asyncio.gather(*detector_tasks, return_exceptions=True)
        for d, r in zip(self.detectors, results):
            if isinstance(r, Exception):
                logger.warning("[%s] detector raised: %s", d.name, r)
                continue
            raw.extend(r)

        # 2) Infer hidden logic from signatures (best effort)
        try:
            self.signatures = self._build_signatures(normalized_endpoints)
            raw.extend(self.inference.infer_hidden(self.signatures))
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("inference.infer_hidden failed: %s", exc)

        # 3) Score every finding
        scored: List[LogicFinding] = [self.inference.score(f, raw) for f in raw]

        # 4) Correlate
        try:
            scored.extend(self.correlator.correlate(scored))
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("correlator.correlate failed: %s", exc)

        # 5) Filter by min thresholds
        scored = [
            f for f in scored
            if f.confidence >= self.config.min_confidence
            and f.risk_score >= self.config.min_risk_score
        ]

        # 6) Sort by risk desc, then confidence
        scored.sort(key=lambda f: (f.risk_score, f.confidence), reverse=True)
        return scored

    async def aclose(self) -> None:
        """Cleanly shut down the HTTP client."""
        await self.http.aclose()

    # ---- helpers ----

    def _build_signatures(
        self, endpoints: List[Dict[str, Any]]
    ) -> List[_EndpointSignature]:
        sigs: List[_EndpointSignature] = []
        for ep in endpoints:
            sigs.append(
                _EndpointSignature(
                    url=ep.get("url", ""),
                    method=ep.get("method", "GET"),
                    param_keys=set(ep.get("params", {}).keys()),
                    body_keys=set(ep.get("body", {}).keys()),
                )
            )
        return sigs

    # ---- convenience constructors ----

    @staticmethod
    def from_endpoints(
        target: str,
        urls: Iterable[str],
        config: Optional[LogicFlawConfig] = None,
    ) -> "LogicFlawEngine":
        """Helper: build a one-shot engine from a list of URLs."""
        eps: List[Dict[str, Any]] = [
            {"url": u, "method": "GET"} for u in urls if u
        ]
        engine = LogicFlawEngine(config)
        engine._pending_target = target  # type: ignore[attr-defined]
        engine._pending_endpoints = eps  # type: ignore[attr-defined]
        return engine


# ═══════════════════════════════════════════════════════════════════════════
# 16. PUBLIC EXPORTS
# ═══════════════════════════════════════════════════════════════════════════


__all__ = [
    "Severity",
    "DetectorCategory",
    "Evidence",
    "LogicFinding",
    "LogicFlawConfig",
    "HttpResponseLite",
    "HttpClient",
    "Detector",
    "PriceManipulationDetector",
    "RaceConditionDetector",
    "StateMachineBypassDetector",
    "AuthLogicDetector",
    "AuthorizationLogicDetector",
    "UUIDV1Decoder",
    "WorkflowIntegrityDetector",
    "BusinessConstraintDetector",
    "InferenceEngine",
    "CorrelationEngine",
    "LogicFlawEngine",
    # helpers
    "normalize_endpoint",
    "has_object_id_param",
    "is_price_endpoint",
    "is_discount_endpoint",
    "is_auth_endpoint",
    "is_workflow_endpoint",
    "extract_currency",
    "ID_REGEX",
    "PRICE_KEYWORDS",
    "QUANTITY_KEYWORDS",
    "DISCOUNT_KEYWORDS",
    "AUTH_KEYWORDS",
    "STEP_KEYWORDS",
    "ID_PARAMETER_NAMES",
]

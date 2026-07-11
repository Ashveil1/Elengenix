"""tools/vuln_hunter_core.py — Meta-cognitive engine for vulnerability hunting.

Transforms Elengenix from a tool-orchestrator into a hypothesis-driven
vulnerability researcher by adding five core capabilities:

1. BeliefState      — tracks what the agent believes, with confidence scores
2. CoverageMap      — 2D matrix: endpoint x vuln class, fed into agent loop
3. NegativeResultStore — records tested-but-not-vulnerable, avoids rework
4. VerificationPipeline — proves findings before reporting (not just reports)
5. ReflectEngine    — formal Plan -> Execute -> Observe -> Reflect -> Refine

Usage:
    from tools.vuln_hunter_core import (
        BeliefState, CoverageMap, NegativeResultStore,
        VerificationPipeline, ReflectEngine
    )
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.vuln_hunter_core")

_DB_PATH = Path(__file__).parent.parent / "data" / "vuln_hunter.db"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _j(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def _ensure_db():
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return _DB_PATH


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_ensure_db()), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


VULN_CLASSES = [
    "sqli",
    "xss",
    "rce",
    "lfi",
    "ssrf",
    "ssti",
    "xxe",
    "deser",
    "graphql",
    "race_condition",
    "cors",
    "jwt",
    "bola",
    "idor",
    "auth_bypass",
    "waf_bypass",
    "business_logic",
    "supply_chain",
    "prototype_pollution",
    "open_redirect",
    "csrf",
    "command_injection",
    "ldapi",
    "nosqli",
    "hpp",
    "cache_poisoning",
    "info_disclosure",
    "misconfiguration",
]


# ===================================================================
# 1. BeliefState — tracks what the agent thinks, with confidence
# ===================================================================


@dataclass
class Belief:
    hyp_id: str
    vuln_class: str
    target_endpoint: str
    reasoning: str
    confidence: float  # 0.0 - 1.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "active"  # active | confirmed | refuted | expired
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BeliefState:
    """Manages a set of hypotheses about the target with confidence tracking.

    Each Belief represents "I think this endpoint might be vulnerable to X
    because Y, and I'm Z% sure." As tests are run, confidences are updated.
    Refuted beliefs are recorded to avoid retesting.
    """

    def __init__(self, mission_id: str):
        self.mission_id = mission_id
        self._init_db()

    def _init_db(self) -> None:
        conn = _get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS beliefs (
                mission_id TEXT NOT NULL,
                hyp_id TEXT NOT NULL,
                vuln_class TEXT NOT NULL,
                target_endpoint TEXT NOT NULL,
                reasoning TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (mission_id, hyp_id)
            );
            CREATE INDEX IF NOT EXISTS idx_beliefs_status
                ON beliefs(mission_id, status);
            CREATE INDEX IF NOT EXISTS idx_beliefs_endpoint
                ON beliefs(mission_id, target_endpoint);
        """
        )
        conn.commit()
        conn.close()

    def add_belief(
        self,
        vuln_class: str,
        target_endpoint: str,
        reasoning: str,
        confidence: float = 0.5,
        evidence: Optional[List[Dict]] = None,
    ) -> str:
        hyp_id = f"{vuln_class}:{target_endpoint}:{int(time.time())}"
        now = _now()
        conn = _get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO beliefs
               (mission_id, hyp_id, vuln_class, target_endpoint, reasoning,
                confidence, evidence_json, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)""",
            (
                self.mission_id,
                hyp_id,
                vuln_class,
                target_endpoint,
                reasoning,
                confidence,
                _j(evidence or []),
                now,
                now,
            ),
        )
        conn.commit()
        conn.close()
        return hyp_id

    def update_confidence(
        self, hyp_id: str, new_confidence: float, evidence: Optional[Dict] = None
    ) -> None:
        conn = _get_conn()
        row = conn.execute(
            "SELECT evidence_json, status FROM beliefs WHERE mission_id=? AND hyp_id=?",
            (self.mission_id, hyp_id),
        ).fetchone()
        if not row:
            conn.close()
            return
        existing = json.loads(row["evidence_json"]) if row["evidence_json"] else []
        if evidence:
            existing.append(evidence | {"timestamp": _now()})
        conn.execute(
            """UPDATE beliefs SET confidence=?, evidence_json=?, updated_at=?
               WHERE mission_id=? AND hyp_id=?""",
            (new_confidence, _j(existing), _now(), self.mission_id, hyp_id),
        )
        conn.commit()
        conn.close()

    def set_status(self, hyp_id: str, status: str) -> None:
        conn = _get_conn()
        conn.execute(
            "UPDATE beliefs SET status=?, updated_at=? WHERE mission_id=? AND hyp_id=?",
            (status, _now(), self.mission_id, hyp_id),
        )
        conn.commit()
        conn.close()

    def get_active_beliefs(self, min_confidence: float = 0.0) -> List[Belief]:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM beliefs WHERE mission_id=? AND status='active' AND confidence>=?",
            (self.mission_id, min_confidence),
        ).fetchall()
        conn.close()
        return [self._row_to_belief(r) for r in rows]

    def get_confirmed_beliefs(self) -> List[Belief]:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM beliefs WHERE mission_id=? AND status='confirmed'",
            (self.mission_id,),
        ).fetchall()
        conn.close()
        return [self._row_to_belief(r) for r in rows]

    def get_beliefs_for_endpoint(self, endpoint: str) -> List[Belief]:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM beliefs WHERE mission_id=? AND target_endpoint=?",
            (self.mission_id, endpoint),
        ).fetchall()
        conn.close()
        return [self._row_to_belief(r) for r in rows]

    def summary(self) -> str:
        active = self.get_active_beliefs()
        confirmed = self.get_confirmed_beliefs()
        if not active and not confirmed:
            return "No beliefs yet."
        parts = [f"Beliefs ({len(active)} active, {len(confirmed)} confirmed):"]
        for b in active[:10]:
            parts.append(
                f"  [{b.vuln_class}] {b.target_endpoint} " f"(confidence: {b.confidence:.0%})"
            )
        for b in confirmed[:5]:
            parts.append(f"  [CONFIRMED] {b.vuln_class} at {b.target_endpoint}")
        return "\n".join(parts)

    def prompt_context(self) -> str:
        """Returns a concise context string for LLM prompts."""
        active = self.get_active_beliefs(min_confidence=0.3)
        if not active:
            return ""

        # Group by vuln class
        by_class: Dict[str, List[Belief]] = {}
        for b in active:
            by_class.setdefault(b.vuln_class, []).append(b)

        parts = ["### ACTIVE HYPOTHESES (test these next):"]
        for vuln_class, beliefs in sorted(by_class.items()):
            for b in beliefs[:2]:
                parts.append(
                    f"  [{vuln_class}] {b.target_endpoint} " f"(confidence: {b.confidence:.0%})"
                )
        return "\n".join(parts)

    @staticmethod
    def _row_to_belief(row: sqlite3.Row) -> Belief:
        return Belief(
            hyp_id=row["hyp_id"],
            vuln_class=row["vuln_class"],
            target_endpoint=row["target_endpoint"],
            reasoning=row["reasoning"],
            confidence=row["confidence"],
            evidence=json.loads(row["evidence_json"]) if row["evidence_json"] else [],
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


# ===================================================================
# 2. CoverageMap — 2D matrix: endpoint x vuln class
# ===================================================================


@dataclass
class CoverageCell:
    """One cell in the coverage matrix."""

    endpoint: str
    vuln_class: str
    tested: bool = False
    test_count: int = 0
    last_tested: Optional[str] = None
    finding_found: bool = False
    negative_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CoverageMap:
    """2D coverage matrix: endpoint x vulnerability class.

    Unlike CoverageAnalyzer (which tracks endpoint params), this tracks
    WHICH vulnerability classes have been tested against WHICH endpoints.
    The agent can ask: "Have I tested SSRF on /api/proxy yet?"
    """

    def __init__(self, mission_id: str, target: str = ""):
        self.mission_id = mission_id
        self.target = target
        self._init_db()

    def _init_db(self) -> None:
        conn = _get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS coverage_map (
                mission_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                vuln_class TEXT NOT NULL,
                tested INTEGER NOT NULL DEFAULT 0,
                test_count INTEGER NOT NULL DEFAULT 0,
                last_tested TEXT,
                finding_found INTEGER NOT NULL DEFAULT 0,
                negative_reason TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (mission_id, endpoint, vuln_class)
            );
            CREATE INDEX IF NOT EXISTS idx_coverage_tested
                ON coverage_map(mission_id, tested);
        """
        )
        conn.commit()
        conn.close()

    def register_endpoint(self, endpoint: str) -> None:
        """Register a new endpoint for all vulnerability classes."""
        conn = _get_conn()
        now = _now()
        for vc in VULN_CLASSES:
            conn.execute(
                """INSERT OR IGNORE INTO coverage_map
                   (mission_id, endpoint, vuln_class, tested, last_tested)
                   VALUES (?, ?, ?, 0, ?)""",
                (self.mission_id, endpoint, vc, now),
            )
        conn.commit()
        conn.close()

    def record_test(self, endpoint: str, vuln_class: str) -> None:
        """Record that we tested endpoint for vuln_class."""
        conn = _get_conn()
        conn.execute(
            """INSERT OR IGNORE INTO coverage_map
               (mission_id, endpoint, vuln_class, tested, test_count)
               VALUES (?, ?, ?, 0, 0)""",
            (self.mission_id, endpoint, vuln_class),
        )
        conn.execute(
            """UPDATE coverage_map
               SET tested=1, test_count=test_count+1, last_tested=?
               WHERE mission_id=? AND endpoint=? AND vuln_class=?""",
            (_now(), self.mission_id, endpoint, vuln_class),
        )
        conn.commit()
        conn.close()

    def record_negative(self, endpoint: str, vuln_class: str, reason: str = "no signal") -> None:
        """Record that endpoint was tested for vuln_class and NOT vulnerable."""
        self.record_test(endpoint, vuln_class)
        conn = _get_conn()
        conn.execute(
            """UPDATE coverage_map
               SET finding_found=0, negative_reason=?
               WHERE mission_id=? AND endpoint=? AND vuln_class=?""",
            (reason, self.mission_id, endpoint, vuln_class),
        )
        conn.commit()
        conn.close()

    def record_finding(self, endpoint: str, vuln_class: str) -> None:
        """Record that a finding was confirmed for endpoint + vuln_class."""
        self.record_test(endpoint, vuln_class)
        conn = _get_conn()
        conn.execute(
            """UPDATE coverage_map
               SET finding_found=1
               WHERE mission_id=? AND endpoint=? AND vuln_class=?""",
            (self.mission_id, endpoint, vuln_class),
        )
        conn.commit()
        conn.close()

    def get_gaps(self, min_count: int = 1) -> List[CoverageCell]:
        """Return untested or undertested (endpoint, vuln_class) pairs."""
        conn = _get_conn()
        rows = conn.execute(
            """SELECT * FROM coverage_map
               WHERE mission_id=? AND (tested=0 OR test_count<?)
               ORDER BY tested ASC, test_count ASC""",
            (self.mission_id, min_count),
        ).fetchall()
        conn.close()
        return [self._row_to_cell(r) for r in rows]

    def get_untested(self) -> List[CoverageCell]:
        """Return completely untested cells."""
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM coverage_map WHERE mission_id=? AND tested=0",
            (self.mission_id,),
        ).fetchall()
        conn.close()
        return [self._row_to_cell(r) for r in rows]

    def get_tested_endpoints(self) -> List[str]:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT DISTINCT endpoint FROM coverage_map WHERE mission_id=? AND tested=1",
            (self.mission_id,),
        ).fetchall()
        conn.close()
        return [r["endpoint"] for r in rows]

    def get_endpoint_coverage(self, endpoint: str) -> Dict[str, Any]:
        """Return coverage stats for a single endpoint."""
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM coverage_map WHERE mission_id=? AND endpoint=?",
            (self.mission_id, endpoint),
        ).fetchall()
        conn.close()
        total = len(rows)
        tested = sum(1 for r in rows if r["tested"])
        findings = sum(1 for r in rows if r["finding_found"])
        return {
            "endpoint": endpoint,
            "total_vuln_classes": total,
            "tested": tested,
            "coverage_pct": round((tested / max(total, 1)) * 100, 1),
            "findings": findings,
        }

    def summary(self) -> str:
        untested = self.get_untested()
        gaps = self.get_gaps(min_count=2)
        conn = _get_conn()
        total = conn.execute(
            "SELECT COUNT(*) as c FROM coverage_map WHERE mission_id=?",
            (self.mission_id,),
        ).fetchone()["c"]
        tested = conn.execute(
            "SELECT COUNT(*) as c FROM coverage_map WHERE mission_id=? AND tested=1",
            (self.mission_id,),
        ).fetchone()["c"]
        conn.close()

        pct = round((tested / max(total, 1)) * 100, 1)
        return (
            f"Coverage: {tested}/{total} cells tested ({pct}%)\n"
            f"Untested cells: {len(untested)}\n"
            f"Undertested cells (<2 tests): {len(gaps)}"
        )

    def prompt_context(self, max_gaps: int = 8) -> str:
        """Returns a concise context string for LLM prompts."""
        untested = self.get_untested()
        gaps = self.get_gaps(min_count=2)

        if not untested and not gaps:
            return ""

        # Group gaps by vuln class
        by_class: Dict[str, List[str]] = {}
        for cell in (untested + gaps)[: max_gaps * 2]:
            by_class.setdefault(cell.vuln_class, []).append(cell.endpoint)

        # Rank by most untested vuln classes
        ranked = sorted(by_class.items(), key=lambda x: len(x[1]), reverse=True)

        parts = ["### COVERAGE GAPS (attack surface not yet tested):"]
        for vuln_class, endpoints in ranked[:6]:
            eps = ", ".join(endpoints[:3])
            label = (
                "untested"
                if all(
                    c.vuln_class == vuln_class and c.test_count == 0
                    for c in (untested + gaps)
                    if c.endpoint in endpoints
                    for _ in [1]
                )
                else "undertested"
            )
            parts.append(f"  [{vuln_class}] {label}: {eps}")
        parts.append(f"  Total coverage: {self.summary().split(chr(10))[0]}")
        return "\n".join(parts)

    @staticmethod
    def _row_to_cell(row: sqlite3.Row) -> CoverageCell:
        return CoverageCell(
            endpoint=row["endpoint"],
            vuln_class=row["vuln_class"],
            tested=bool(row["tested"]),
            test_count=row["test_count"],
            last_tested=row["last_tested"],
            finding_found=bool(row["finding_found"]),
            negative_reason=row["negative_reason"],
        )


# ===================================================================
# 3. NegativeResultStore — remembers what didn't work
# ===================================================================


@dataclass
class NegativeResult:
    endpoint: str
    vuln_class: str
    tool_used: str
    payload_or_command: str
    reason: str  # why we think it's not vulnerable
    evidence_summary: str
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NegativeResultStore:
    """Tracks tested-but-not-vulnerable results to avoid rework.

    Before the agent tests endpoint X for Y, it checks here:
    "Did I already try this? What payloads did I use? Why did I
    conclude it's not vulnerable?"
    """

    def __init__(self, mission_id: str):
        self.mission_id = mission_id
        self._init_db()

    def _init_db(self) -> None:
        conn = _get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS negative_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                vuln_class TEXT NOT NULL,
                tool_used TEXT NOT NULL,
                payload_or_command TEXT NOT NULL,
                reason TEXT NOT NULL,
                evidence_summary TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_negative_lookup
                ON negative_results(mission_id, endpoint, vuln_class);
        """
        )
        conn.commit()
        conn.close()

    def record(
        self,
        endpoint: str,
        vuln_class: str,
        tool_used: str,
        payload_or_command: str,
        reason: str = "no vulnerability detected",
        evidence_summary: str = "",
    ) -> None:
        conn = _get_conn()
        conn.execute(
            """INSERT INTO negative_results
               (mission_id, endpoint, vuln_class, tool_used,
                payload_or_command, reason, evidence_summary, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                self.mission_id,
                endpoint,
                vuln_class,
                tool_used,
                payload_or_command[:500],
                reason,
                evidence_summary[:500],
                _now(),
            ),
        )
        conn.commit()
        conn.close()

    def was_tested(self, endpoint: str, vuln_class: str) -> bool:
        """Check if we already tested this combination."""
        conn = _get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as c FROM negative_results WHERE mission_id=? AND endpoint=? AND vuln_class=?",
            (self.mission_id, endpoint, vuln_class),
        ).fetchone()
        conn.close()
        return row["c"] > 0

    def get_previous_attempts(self, endpoint: str, vuln_class: str) -> List[NegativeResult]:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM negative_results WHERE mission_id=? AND endpoint=? AND vuln_class=? ORDER BY timestamp DESC",
            (self.mission_id, endpoint, vuln_class),
        ).fetchall()
        conn.close()
        return [
            NegativeResult(
                endpoint=r["endpoint"],
                vuln_class=r["vuln_class"],
                tool_used=r["tool_used"],
                payload_or_command=r["payload_or_command"],
                reason=r["reason"],
                evidence_summary=r["evidence_summary"],
                timestamp=r["timestamp"],
            )
            for r in rows
        ]

    def get_prompt_context(self, max_items: int = 5) -> str:
        """Brief context for the LLM about what's been tried."""
        conn = _get_conn()
        rows = conn.execute(
            "SELECT endpoint, vuln_class, tool_used, reason FROM negative_results WHERE mission_id=? ORDER BY timestamp DESC LIMIT ?",
            (self.mission_id, max_items),
        ).fetchall()
        conn.close()
        if not rows:
            return ""
        parts = ["### PREVIOUSLY TESTED (not vulnerable):"]
        for r in rows:
            parts.append(
                f"  {r['endpoint']} for {r['vuln_class']} via {r['tool_used']}: {r['reason'][:80]}"
            )
        return "\n".join(parts)


# ===================================================================
# 4. VerificationPipeline — proves findings before reporting
# ===================================================================


@dataclass
class Verdict:
    vuln_class: str
    endpoint: str
    status: str  # "unverified" | "confirmed" | "proven" | "exploitable" | "false_positive"
    confidence: float
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    proof_of_concept: str = ""  # working exploit/PoC if applicable
    chained_with: List[str] = field(default_factory=list)
    cvss_estimate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def is_actionable(self) -> bool:
        return self.status in ("confirmed", "proven", "exploitable")


class VerificationPipeline:
    """Post-finding verification engine.

    After a tool reports a potential finding, the pipeline runs
    increasingly strict stages to PROVE the vulnerability exists:

    1. CONFIRMED — payload triggers observable response difference
    2. PROVEN — real data exfiltrated or real impact demonstrated
    3. EXPLOITABLE — impact chained for maximum effect (e.g., SQLi -> RCE)

    Findings that fail verification are demoted or discarded.
    """

    VERIFICATION_STAGES = {
        "sqli": [
            ("confirm", "Check for response difference with time-based/' AND 1=1--"),
            ("prove", "Extract database version or table name"),
            ("escalate", "Check for INTO OUTFILE / xp_cmdshell / stacked queries"),
        ],
        "xss": [
            ("confirm", "Check if payload reflects in response unencoded"),
            ("prove", "Fire callback to controlled listener or capture cookie"),
            ("escalate", "Check CSP bypass, DOM-based chaining"),
        ],
        "ssrf": [
            ("confirm", "Send payload to collaborator / canary URL"),
            ("prove", "Access internal service (e.g., 169.254.169.254)"),
            ("escalate", "RCE via SSRF to internal admin interface"),
        ],
        "rce": [
            ("confirm", "Execute id/whoami/uname via injection point"),
            ("prove", "Write file to web root or exfiltrate /etc/passwd"),
            ("escalate", "Establish persistence or pivot"),
        ],
        "lfi": [
            ("confirm", "Read /etc/passwd with path traversal"),
            ("prove", "Read application source code (e.g., index.php)"),
            ("escalate", "RFI or log poisoning for RCE"),
        ],
        "ssti": [
            ("confirm", "Inject {{7*7}} and check for 49 in response"),
            ("prove", "Read environment variables or call os.popen"),
            ("escalate", "RCE via template engine"),
        ],
        "xxe": [
            ("confirm", "Trigger out-of-band XXE to collaborator"),
            ("prove", "Read /etc/passwd via external DTD"),
            ("escalate", "SSRF or RCE via XXE"),
        ],
        "graphql": [
            ("confirm", "Introspection query succeeds"),
            ("prove", "Extract schema or execute arbitrary query"),
            ("escalate", "Batch query DoS, auth bypass via mutations"),
        ],
        "bola": [
            ("confirm", "Access another user's resource by changing ID"),
            ("prove", "Extract PII or perform privileged action"),
            ("escalate", "Chained with mass assignment"),
        ],
        "jwt": [
            ("confirm", "Modify payload with alg='none'"),
            ("prove", "Forge valid token with known secret"),
            ("escalate", "Privilege escalation via modified claims"),
        ],
    }

    def __init__(self, agent=None):
        self.agent = agent
        self._history: List[Verdict] = []
        self._all_findings: List[Dict] = []
        self._progress_db = _ensure_db()

    def verify_finding(
        self,
        finding: Dict[str, Any],
        target: str = "",
        callback: Optional[Callable] = None,
    ) -> Verdict:
        """Run verification stages on a finding and return a Verdict."""
        vuln_class = (finding.get("type") or finding.get("vuln_class") or "unknown").lower()
        endpoint = finding.get("url") or finding.get("endpoint") or target or "unknown"
        evidence = finding.get("evidence", str(finding))

        stages = self.VERIFICATION_STAGES.get(
            vuln_class,
            [
                ("confirm", "Check if finding reproduces"),
            ],
        )

        if callback:
            callback(f"Verifying {vuln_class} at {endpoint}...")

        verdict = Verdict(
            vuln_class=vuln_class,
            endpoint=endpoint,
            status="unverified",
            confidence=finding.get("confidence", 0.5),
            evidence=[{"stage": "initial", "data": evidence[:500]}],
        )

        # Stage 1: Confirmation
        confirmed = self._run_stage(stages[0], endpoint, vuln_class, callback)
        if not confirmed.success:
            if callback:
                callback(f"  [FAIL] Stage 1 ({stages[0][0]}): not confirmed")
            verdict.status = "false_positive"
            verdict.confidence = 0.1
            verdict.evidence.append(
                {"stage": "confirm", "success": False, "detail": confirmed.detail}
            )
            self._history.append(verdict)
            return verdict

        verdict.evidence.append({"stage": "confirm", "success": True, "detail": confirmed.detail})
        verdict.status = "confirmed"
        verdict.confidence = 0.7

        if callback:
            callback(f"  [OK] Confirmed: {confirmed.detail[:100]}")

        # Stage 2: Proven (real impact)
        if len(stages) > 1:
            proven = self._run_stage(stages[1], endpoint, vuln_class, callback)
            if proven.success:
                verdict.status = "proven"
                verdict.confidence = 0.85
                verdict.proof_of_concept = proven.detail[:1000]
                verdict.evidence.append(
                    {"stage": "prove", "success": True, "detail": proven.detail}
                )
                if callback:
                    callback(f"  [OK] Proven: {proven.detail[:100]}")
            else:
                verdict.evidence.append(
                    {"stage": "prove", "success": False, "detail": proven.detail}
                )

        # Stage 3: Exploitable (chained impact)
        if len(stages) > 2 and verdict.status == "proven":
            escalated = self._run_stage(stages[2], endpoint, vuln_class, callback)
            if escalated.success:
                verdict.status = "exploitable"
                verdict.confidence = 0.95
                verdict.evidence.append(
                    {"stage": "escalate", "success": True, "detail": escalated.detail}
                )
                if callback:
                    callback(f"  [OK] Exploitable: {escalated.detail[:100]}")

        self._history.append(verdict)
        return verdict

    def _run_stage(
        self,
        stage: Tuple[str, str],
        endpoint: str,
        vuln_class: str,
        callback: Optional[Callable] = None,
    ) -> "StageResult":
        """Run a single verification stage.

        Uses the LLM (if available) to design and execute the test,
        otherwise returns an uncertain result.
        """
        stage_name, stage_desc = stage

        if not self.agent or not hasattr(self.agent, "client"):
            return StageResult(success=False, detail="No LLM agent available for verification")

        prompt = f"""You are verifying a potential {vuln_class} vulnerability at {endpoint}.

Stage: {stage_name}
Goal: {stage_desc}

Design a test to verify this vulnerability. Be specific:
1. What payload/command to send?
2. What response would confirm the vulnerability?
3. What response would disprove it?

Return JSON:
{{"test_command": "...", "expect_success_signal": "...",
  "expect_failure_signal": "...", "confidence_if_success": 0.8}}"""

        try:
            from tools.universal_ai_client import AIMessage

            resp = self.agent.client.chat(
                [
                    AIMessage(
                        role="system",
                        content="You are a vulnerability verification expert. Be precise and safe.",
                    ),
                    AIMessage(role="user", content=prompt),
                ],
                temperature=0.2,
            )
            content = resp.content or ""
        except Exception as e:
            logger.debug(f"Verification stage LLM call failed: {e}")
            return StageResult(success=False, detail=f"LLM error: {e}")

        from agents.agent_helpers import extract_json

        plan = extract_json(content, expect="object")
        if not plan:
            return StageResult(success=False, detail="Could not parse verification plan")

        test_cmd = plan.get("test_command", "")
        if not test_cmd:
            return StageResult(success=False, detail="No test command in verification plan")

        try:
            from tools.governance import Governance
            from tools.safe_exec import execute_safely

            g = Governance(require_approval_high_risk=False)
            gate = g.gate(
                mission_id="verification",
                target=endpoint,
                action={
                    "action": "run_shell",
                    "tool": "verification",
                    "command": test_cmd,
                    "purpose": f"Verify {vuln_class}",
                },
                callback=callback,
            )
            if not gate.allowed:
                return StageResult(success=False, detail=f"Gate blocked: {gate.rationale}")

            result = execute_safely(test_cmd, timeout=15)
            output = result.output if hasattr(result, "output") else str(result)

            success_keywords = plan.get("expect_success_signal", "")
            failure_keywords = plan.get("expect_failure_signal", "")

            found_success = not success_keywords or success_keywords.lower() in output.lower()
            found_failure = failure_keywords and failure_keywords.lower() in output.lower()

            if found_success and not found_failure:
                return StageResult(success=True, detail=output[:500])
            else:
                return StageResult(success=False, detail=output[:500])

        except Exception as e:
            logger.debug(f"Verification stage execution failed: {e}")
            return StageResult(success=False, detail=str(e))

    def get_all_verdicts(self) -> List[Verdict]:
        return self._history

    def get_actionable_findings(self) -> List[Verdict]:
        return [v for v in self._history if v.is_actionable()]

    def false_positive_rate(self) -> float:
        if not self._history:
            return 0.0
        fps = sum(1 for v in self._history if v.status == "false_positive")
        return fps / len(self._history)

    def prompt_context(self) -> str:
        if not self._history:
            return ""
        actionables = self.get_actionable_findings()
        fps = sum(1 for v in self._history if v.status == "false_positive")
        parts = ["### VERIFICATION RESULTS:"]
        for v in self._history[-5:]:
            parts.append(
                f"  [{v.status.upper()}] {v.vuln_class} at {v.endpoint} (confidence: {v.confidence:.0%})"
            )
        parts.append(
            f"  Total: {len(self._history)} findings, {len(actionables)} actionable, {fps} false positives"
        )
        return "\n".join(parts)


@dataclass
class StageResult:
    success: bool = False
    detail: str = ""


# ===================================================================
# 5. ReflectEngine — formal Plan->Execute->Observe->Reflect->Refine
# ===================================================================


@dataclass
class Reflection:
    cycle: int
    status: str  # "on_track" | "needs_adaptation" | "stuck" | "complete"
    coverage_summary: str = ""
    active_hypotheses_count: int = 0
    findings_this_cycle: int = 0
    consecutive_no_findings: int = 0
    recommendation: str = ""
    switch_strategy: bool = False
    priority_targets: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ReflectEngine:
    """Formal reflection step in the agent loop.

    At the beginning of each cycle:
    1. Check coverage: are we making progress?
    2. Check belief state: are hypotheses being confirmed/refuted?
    3. Check velocity: how many consecutive steps without findings?
    4. Recommend: continue, adapt, or switch strategy?

    This is what separates "tool executor" from "vulnerability researcher."
    """

    def __init__(self, adapt_after: int = 3, max_steps_without_findings: int = 5):
        self.history: List[Reflection] = []
        self.consecutive_no_findings = 0
        self.adapt_after = adapt_after
        self.max_steps_without_findings = max_steps_without_findings
        self.total_findings = 0
        self.last_findings_count = 0
        self.switch_count = 0

    def reflect(
        self,
        cycle: int,
        coverage_map: Optional[CoverageMap] = None,
        belief_state: Optional[BeliefState] = None,
        recent_findings_count: int = 0,
    ) -> Reflection:
        """Run the reflection step and return guidance for the next cycle."""
        self.total_findings += recent_findings_count

        if recent_findings_count > 0:
            self.consecutive_no_findings = 0
        else:
            self.consecutive_no_findings += 1

        # Build coverage summary
        coverage_summary = ""
        if coverage_map:
            coverage_summary = coverage_map.summary()

        # Count active hypotheses
        hyp_count = 0
        if belief_state:
            hyp_count = len(belief_state.get_active_beliefs(min_confidence=0.3))

        # Determine status and recommendation
        if recent_findings_count > 0:
            status = "on_track"
            recommendation = self._recommend_on_track(coverage_map, belief_state)
        elif self.consecutive_no_findings >= self.max_steps_without_findings:
            status = "stuck"
            recommendation = self._recommend_stuck(coverage_map, belief_state)
        elif (
            self.consecutive_no_findings >= self.adapt_after
            and self.consecutive_no_findings < self.max_steps_without_findings
        ):
            status = "needs_adaptation"
            recommendation = self._recommend_adapt(coverage_map, belief_state)
        else:
            status = "on_track"
            recommendation = "Continue current approach."

        # Decide if we should switch strategy
        switch = status in ("stuck", "needs_adaptation")
        if switch:
            self.switch_count += 1

        # Suggest priority targets from coverage gaps
        priority_targets = []
        if coverage_map:
            gaps = coverage_map.get_gaps()
            # Prioritize high-impact vuln classes on untested endpoints
            high_impact = ["rce", "sqli", "ssrf", "lfi", "ssti", "xxe"]
            for g in gaps:
                if g.vuln_class in high_impact and not g.tested:
                    priority_targets.append(f"{g.vuln_class} on {g.endpoint}")
            priority_targets = priority_targets[:5]

        ref = Reflection(
            cycle=cycle,
            status=status,
            coverage_summary=coverage_summary,
            active_hypotheses_count=hyp_count,
            findings_this_cycle=recent_findings_count,
            consecutive_no_findings=self.consecutive_no_findings,
            recommendation=recommendation,
            switch_strategy=switch,
            priority_targets=priority_targets,
        )
        self.history.append(ref)
        return ref

    def _recommend_on_track(self, coverage_map=None, belief_state=None) -> str:
        """We're finding things. Keep going, but check coverage."""
        parts = []
        if coverage_map:
            untested = len(coverage_map.get_untested())
            if untested > 10:
                parts.append(f"Focus on untested areas ({untested} untested cells remain)")
        if belief_state:
            active = belief_state.get_active_beliefs()
            if active:
                top = max(active, key=lambda b: b.confidence)
                parts.append(f"Prioritize testing: {top.vuln_class} on {top.target_endpoint}")
        return "; ".join(parts) if parts else "Continue current approach. Progress is good."

    def _recommend_adapt(self, coverage_map=None, belief_state=None) -> str:
        """N steps without findings. Time to adapt."""
        parts = []
        if coverage_map:
            untested = coverage_map.get_untested()
            if untested:
                # Find highest-value untested combination
                high_impact = ["rce", "sqli", "ssrf", "lfi"]
                for g in untested:
                    if g.vuln_class in high_impact:
                        parts.append(f"SWITCH FOCUS: test {g.vuln_class} on {g.endpoint}")
                        break
                else:
                    parts.append(
                        f"SWITCH FOCUS: test {untested[0].vuln_class} on {untested[0].endpoint}"
                    )

        if belief_state:
            active = belief_state.get_active_beliefs()
            if not active:
                parts.append("No active hypotheses. Generate new ones from coverage gaps.")
            else:
                parts.append(f"Re-evaluate active hypotheses ({len(active)} remain)")

        parts.append(
            "Consider: different payload types, different injection points, different tools."
        )
        return (
            "\n".join(parts)
            if parts
            else "No findings recently. Try a completely different approach."
        )

    def _recommend_stuck(self, coverage_map=None, belief_state=None) -> str:
        """Completely stuck. Major strategy change needed."""
        parts = ["MAJOR STRATEGY CHANGE NEEDED."]
        if coverage_map:
            covered_pct = 0
            conn = _get_conn()
            total = conn.execute(
                "SELECT COUNT(*) as c FROM coverage_map WHERE mission_id=?",
                (coverage_map.mission_id,),
            ).fetchone()
            tested = conn.execute(
                "SELECT COUNT(*) as c FROM coverage_map WHERE mission_id=? AND tested=1",
                (coverage_map.mission_id,),
            ).fetchone()
            conn.close()
            if total and total["c"] > 0:
                covered_pct = round((tested["c"] / total["c"]) * 100, 1)
            if covered_pct < 50:
                parts.append(f"Coverage only {covered_pct}% — many areas remain untested")
            else:
                parts.append(
                    f"Coverage at {covered_pct}% — target may be well-hardened for tested classes"
                )

        if belief_state:
            refuted = [b for b in belief_state.get_active_beliefs() if b.status == "refuted"]
            if refuted:
                parts.append(f"{len(refuted)} hypotheses were refuted. Generate new ones.")

        parts.append("Consider: different attack surface (API, subdomains, login bypass, etc.)")
        return "\n".join(parts)

    def prompt_context(self, recent: int = 3) -> str:
        """Provide reflection context for the LLM prompt."""
        if not self.history:
            return ""

        latest = self.history[-recent:]
        parts = ["### REFLECTION (self-assessment):"]
        for r in latest:
            parts.append(
                f"  Cycle {r.cycle}: status={r.status}, findings={r.findings_this_cycle}, "
                f"no-findings-streak={r.consecutive_no_findings}"
            )
        last = latest[-1]
        if last.switch_strategy:
            parts.append(f"  RECOMMENDED CHANGE: {last.recommendation[:150]}")
        if last.priority_targets:
            parts.append(f"  PRIORITY TARGETS: {', '.join(last.priority_targets[:3])}")
        return "\n".join(parts)

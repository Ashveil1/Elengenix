"""tools/coverage_analyzer.py — M6: Coverage Analyzer.

Tracks every endpoint, parameter, HTTP method, and header that the
agent has touched during a mission, then computes:
  - coverage % (tested param combos / known param combos)
  - untested endpoints (known but never hit)
  - tested-but-uninteresting endpoints (always 200, no signal)
  - undertested parameter slots (tested once but worth retrying)
  - attack-surface expansion (subdomains, hidden paths discovered)

This is what makes "I scanned the target" auditable. Without it, the
agent is just spraying payloads blindly; with it, you can see exactly
which parameters were tested, which weren't, and which need more work.

Public API:
    EndpointRecord  - one URL + method + params + headers known
    TestRecord      - one fuzz/tool run against an endpoint
    CoverageReport  - summary stats + untested list
    CoverageAnalyzer:
        record_endpoint(url, method, params, headers)
        record_test(url, method, tool, payload, response)
        get_untested_endpoints() -> List[EndpointRecord]
        get_undertested_params(min_tests=2) -> List[(url, param)]
        get_coverage_report() -> CoverageReport
        get_endpoint_coverage(url) -> Dict
        suggest_next_targets(limit=10) -> List[Dict]
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse

logger = logging.getLogger("elengenix.coverage_analyzer")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class EndpointRecord:
    """One URL + method + parameters known from reconnaissance."""

    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    headers: List[str] = field(default_factory=list)
    first_seen: float = 0.0
    source: str = "unknown"  # "subfinder", "wayback", "katana", "manual"

    def endpoint_key(self) -> str:
        """Unique key for endpoint+method (ignores query string)."""
        parsed = urlparse(self.url)
        # Normalize path
        path = parsed.path or "/"
        return f"{self.method.upper()} {parsed.scheme}://{parsed.netloc}{path}"


@dataclass
class TestRecord:
    """One tool/fuzz run against an endpoint."""

    url: str
    method: str
    tool: str
    injection_point: str  # "param:q", "path", "header:User-Agent"
    payload: str
    status: int
    response_size: int
    is_interesting: bool
    timestamp: float = 0.0
    notes: str = ""


@dataclass
class CoverageReport:
    """Summary stats for a coverage analyzer session."""

    total_endpoints: int
    total_param_slots: int  # sum of (param count) across endpoints
    tested_param_slots: int
    coverage_pct: float  # tested / total
    untested_endpoints: int
    undertested_params: int  # tested 0 or 1 times
    interesting_findings: int
    total_tests: int
    unique_tools_used: int
    endpoints_by_source: Dict[str, int]
    attack_surface_growth: int  # endpoints discovered this session

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Coverage analyzer
# ---------------------------------------------------------------------------


class CoverageAnalyzer:
    """Tracks attack-surface discovery and test coverage.

    Backed by SQLite for persistence across sessions.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path("data/coverage.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        self._session_start = time.time()
        self._endpoints_at_start = self._count_endpoints()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS endpoints (
                endpoint_key TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                method TEXT NOT NULL,
                params_json TEXT,
                headers_json TEXT,
                first_seen REAL,
                source TEXT,
                last_tested REAL
            );
            CREATE TABLE IF NOT EXISTS tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                method TEXT NOT NULL,
                tool TEXT NOT NULL,
                injection_point TEXT,
                payload TEXT,
                status INTEGER,
                response_size INTEGER,
                is_interesting INTEGER,
                timestamp REAL,
                notes TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_tests_url_param
                ON tests(url, injection_point);
            CREATE INDEX IF NOT EXISTS idx_tests_interesting
                ON tests(is_interesting);
        """
        )
        self._conn.commit()

    def _count_endpoints(self) -> int:
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM endpoints")
        return cur.fetchone()[0]

    # ── Endpoint discovery ──

    def record_endpoint(
        self,
        url: str,
        method: str = "GET",
        params: Optional[List[str]] = None,
        headers: Optional[List[str]] = None,
        source: str = "manual",
    ) -> EndpointRecord:
        """Record a newly discovered endpoint.

        If already known, returns existing record. Otherwise creates one.
        """
        record = EndpointRecord(
            url=url,
            method=method.upper(),
            params=list(params or []),
            headers=list(headers or []),
            first_seen=time.time(),
            source=source,
        )

        cur = self._conn.cursor()
        cur.execute("SELECT * FROM endpoints WHERE endpoint_key = ?", (record.endpoint_key(),))
        existing = cur.fetchone()
        if existing:
            # Update params list (might have discovered more)
            cur.execute(
                "UPDATE endpoints SET params_json=?, headers_json=?, source=? WHERE endpoint_key=?",
                (
                    json.dumps(record.params),
                    json.dumps(record.headers),
                    record.source,
                    record.endpoint_key(),
                ),
            )
            record.first_seen = existing["first_seen"]
        else:
            cur.execute(
                "INSERT INTO endpoints (endpoint_key, url, method, params_json, headers_json, first_seen, source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    record.endpoint_key(),
                    record.url,
                    record.method,
                    json.dumps(record.params),
                    json.dumps(record.headers),
                    record.first_seen,
                    record.source,
                ),
            )
        self._conn.commit()
        return record

    def discover_from_url(self, url: str, source: str = "unknown") -> List[EndpointRecord]:
        """Extract endpoints from a URL string (parses query params).

        Useful for ingesting subfinder/katana output.
        """
        records = []
        parsed = urlparse(url)
        params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]

        rec = self.record_endpoint(
            url=url,
            method="GET",
            params=params,
            source=source,
        )
        records.append(rec)
        return records

    # ── Test recording ──

    def record_test(
        self,
        url: str,
        method: str,
        tool: str,
        injection_point: str,
        payload: str,
        status: int,
        response_size: int,
        is_interesting: bool = False,
        notes: str = "",
    ) -> TestRecord:
        """Record a single test/fuzz iteration."""
        record = TestRecord(
            url=url,
            method=method.upper(),
            tool=tool,
            injection_point=injection_point,
            payload=payload,
            status=status,
            response_size=response_size,
            is_interesting=is_interesting,
            timestamp=time.time(),
            notes=notes,
        )
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO tests (url, method, tool, injection_point, payload, status, "
            "response_size, is_interesting, timestamp, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.url,
                record.method,
                record.tool,
                record.injection_point,
                record.payload[:500],
                record.status,
                record.response_size,
                int(record.is_interesting),
                record.timestamp,
                record.notes,
            ),
        )
        # Update last_tested
        cur.execute(
            "UPDATE endpoints SET last_tested=? WHERE endpoint_key=?",
            (
                record.timestamp,
                f"{record.method} {urlparse(url).scheme}://{urlparse(url).netloc}{urlparse(url).path or '/'}",
            ),
        )
        self._conn.commit()
        return record

    # ── Coverage queries ──

    def _load_endpoints(self) -> List[EndpointRecord]:
        cur = self._conn.cursor()
        rows = cur.execute("SELECT * FROM endpoints").fetchall()
        return [
            EndpointRecord(
                url=r["url"],
                method=r["method"],
                params=json.loads(r["params_json"] or "[]"),
                headers=json.loads(r["headers_json"] or "[]"),
                first_seen=r["first_seen"],
                source=r["source"],
            )
            for r in rows
        ]

    def _count_tests_for(self, url: str, injection_point: str) -> int:
        cur = self._conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM tests WHERE url=? AND injection_point=?",
            (url, injection_point),
        )
        return cur.fetchone()[0]

    def get_untested_endpoints(self) -> List[EndpointRecord]:
        """Find endpoints that have never been tested."""
        cur = self._conn.cursor()
        rows = cur.execute(
            """
            SELECT e.* FROM endpoints e
            LEFT JOIN tests t ON e.url = t.url
            WHERE t.id IS NULL
            ORDER BY e.first_seen DESC
        """
        ).fetchall()
        return [
            EndpointRecord(
                url=r["url"],
                method=r["method"],
                params=json.loads(r["params_json"] or "[]"),
                headers=json.loads(r["headers_json"] or "[]"),
                first_seen=r["first_seen"],
                source=r["source"],
            )
            for r in rows
        ]

    def get_undertested_params(self, min_tests: int = 2) -> List[Tuple[str, str]]:
        """Find (url, param) pairs tested fewer than `min_tests` times.

        Returns a list of (url, injection_point) tuples.
        """
        cur = self._conn.cursor()
        # Get all param-style tests grouped
        rows = cur.execute(
            """
            SELECT t.url, t.injection_point, COUNT(*) as cnt
            FROM tests t
            WHERE t.injection_point LIKE 'param:%'
            GROUP BY t.url, t.injection_point
            HAVING cnt < ?
            ORDER BY cnt ASC
        """,
            (min_tests,),
        ).fetchall()
        return [(r["url"], r["injection_point"]) for r in rows]

    def get_endpoint_coverage(self, url: str) -> Dict[str, Any]:
        """Per-endpoint coverage stats."""
        cur = self._conn.cursor()
        endpoint_key = (
            f"GET {urlparse(url).scheme}://{urlparse(url).netloc}{urlparse(url).path or '/'}"
        )
        ep_row = cur.execute(
            "SELECT * FROM endpoints WHERE endpoint_key=?", (endpoint_key,)
        ).fetchone()
        if not ep_row:
            return {"url": url, "known": False}

        params = json.loads(ep_row["params_json"] or "[]")
        param_coverage = {}
        for param in params:
            tests = self._count_tests_for(url, f"param:{param}")
            param_coverage[param] = tests

        test_rows = cur.execute(
            "SELECT COUNT(*) as total, SUM(is_interesting) as interesting FROM tests WHERE url=?",
            (url,),
        ).fetchone()
        return {
            "url": url,
            "known": True,
            "params": params,
            "param_coverage": param_coverage,
            "total_tests": test_rows["total"] or 0,
            "interesting_tests": test_rows["interesting"] or 0,
            "coverage_pct": (sum(1 for v in param_coverage.values() if v > 0) / max(len(params), 1))
            * 100,
            "last_tested": ep_row["last_tested"],
        }

    def get_coverage_report(self) -> CoverageReport:
        """Generate full coverage report for the session."""
        cur = self._conn.cursor()
        endpoints = self._load_endpoints()

        total_param_slots = sum(len(e.params) for e in endpoints)
        tested_param_slots = 0
        for e in endpoints:
            for param in e.params:
                if self._count_tests_for(e.url, f"param:{param}") > 0:
                    tested_param_slots += 1

        coverage_pct = (tested_param_slots / max(total_param_slots, 1)) * 100

        untested = self.get_untested_endpoints()
        undertested = self.get_undertested_params(min_tests=2)

        test_stats = cur.execute(
            """
            SELECT COUNT(*) as total,
                   SUM(is_interesting) as interesting,
                   COUNT(DISTINCT tool) as unique_tools
            FROM tests
        """
        ).fetchone()

        source_stats = cur.execute(
            """
            SELECT source, COUNT(*) as cnt FROM endpoints GROUP BY source
        """
        ).fetchall()
        endpoints_by_source = {r["source"]: r["cnt"] for r in source_stats}

        current_endpoint_count = self._count_endpoints()
        attack_surface_growth = current_endpoint_count - self._endpoints_at_start

        return CoverageReport(
            total_endpoints=len(endpoints),
            total_param_slots=total_param_slots,
            tested_param_slots=tested_param_slots,
            coverage_pct=round(coverage_pct, 1),
            untested_endpoints=len(untested),
            undertested_params=len(undertested),
            interesting_findings=test_stats["interesting"] or 0,
            total_tests=test_stats["total"] or 0,
            unique_tools_used=test_stats["unique_tools"] or 0,
            endpoints_by_source=endpoints_by_source,
            attack_surface_growth=attack_surface_growth,
        )

    def suggest_next_targets(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Suggest what to test next based on coverage gaps.

        Priority order:
        1. Untested endpoints (param slot never tested)
        2. Undertested params (< 2 tests)
        3. High-value params (id, user_id, file, path, q) not yet tested
        """
        suggestions: List[Dict[str, Any]] = []
        cur = self._conn.cursor()

        # 1. Untested param slots
        rows = cur.execute(
            """
            SELECT e.url, e.params_json, e.source
            FROM endpoints e
            WHERE e.url NOT IN (SELECT DISTINCT url FROM tests)
            ORDER BY e.first_seen DESC
            LIMIT ?
        """,
            (limit,),
        ).fetchall()
        for r in rows:
            params = json.loads(r["params_json"] or "[]")
            for param in params:
                suggestions.append(
                    {
                        "type": "untested_param",
                        "url": r["url"],
                        "param": param,
                        "priority": 1,
                        "reason": f"parameter '{param}' on {r['url']} never tested",
                    }
                )

        # 2. Undertested (< 2 tests)
        rows = cur.execute(
            """
            SELECT t.url, t.injection_point, COUNT(*) as cnt
            FROM tests t
            WHERE t.injection_point LIKE 'param:%'
            GROUP BY t.url, t.injection_point
            HAVING cnt < 2
            ORDER BY cnt ASC
            LIMIT ?
        """,
            (limit,),
        ).fetchall()
        for r in rows:
            suggestions.append(
                {
                    "type": "undertested_param",
                    "url": r["url"],
                    "param": r["injection_point"].replace("param:", ""),
                    "test_count": r["cnt"],
                    "priority": 2,
                    "reason": f"param '{r['injection_point']}' only tested {r['cnt']}x",
                }
            )

        # 3. High-value params never tested
        high_value = [
            "id",
            "user_id",
            "uid",
            "file",
            "path",
            "q",
            "url",
            "redirect",
            "next",
            "return",
        ]
        placeholders = ",".join("?" * len(high_value))
        rows = cur.execute(
            """
            SELECT e.url, e.params_json FROM endpoints e
            WHERE e.params_json LIKE '%"id"%'
               OR e.params_json LIKE '%"file"%'
               OR e.params_json LIKE '%"path"%'
               OR e.params_json LIKE '%"url"%'
               OR e.params_json LIKE '%"redirect"%'
            LIMIT ?
        """,
            (limit,),
        ).fetchall()
        for r in rows:
            params = json.loads(r["params_json"] or "[]")
            for param in params:
                if param.lower() in high_value:
                    if self._count_tests_for(r["url"], f"param:{param}") == 0:
                        suggestions.append(
                            {
                                "type": "high_value_param",
                                "url": r["url"],
                                "param": param,
                                "priority": 0,
                                "reason": f"high-value param '{param}' on {r['url']} never tested",
                            }
                        )

        # Dedupe and sort
        seen = set()
        deduped = []
        for s in sorted(suggestions, key=lambda x: x["priority"]):
            key = (s["url"], s["param"])
            if key not in seen:
                seen.add(key)
                deduped.append(s)
        return deduped[:limit]

    def reset(self) -> None:
        """Drop all data (for tests)."""
        cur = self._conn.cursor()
        cur.executescript("DELETE FROM endpoints; DELETE FROM tests;")
        self._conn.commit()

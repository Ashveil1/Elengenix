"""tools/access_control_matrix.py

Access-Control Matrix Tester (ACM) for web/API.

Goal:
- Differential authorization testing across roles/sessions
- Build a matrix: endpoints x methods x account
- Highlight mismatches (e.g., B can access A's resources)

Safety:
- GET-only by default
- Requires two sessions/headers (Account A and Account B)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

logger = logging.getLogger("elengenix.acm")


@dataclass
class MatrixCell:
    method: str
    url: str
    status_a: int
    status_b: int
    len_a: int
    len_b: int
    signal: str  # ok/mismatch/suspect/error


@dataclass
class ACMResult:
    success: bool
    cells: List[MatrixCell]
    findings: List[Dict[str, Any]]
    notes: List[str]


class AccessControlMatrixTester:
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

    def _get(self, path: str, headers: Dict[str, str]) -> Tuple[int, str]:
        self._sleep()
        url = path
        if not url.startswith("http://") and not url.startswith("https://"):
            url = urljoin(self.base_url, path.lstrip("/"))
        r = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=False)
        return r.status_code, r.text or ""

    def run(
        self,
        headers_a: Dict[str, str],
        headers_b: Dict[str, str],
        endpoints: List[str],
        methods: Optional[List[str]] = None,
        dry_run: bool = True,
    ) -> ACMResult:
        methods = methods or ["GET"]
        methods = [m.upper() for m in methods]
        notes: List[str] = []
        cells: List[MatrixCell] = []
        findings: List[Dict[str, Any]] = []

        for ep in endpoints:
            for m in methods:
                if m != "GET":
                    notes.append(f"Skipping non-GET method {m} for {ep}")
                    continue

                url = ep if ep.startswith("http") else urljoin(self.base_url, ep.lstrip("/"))

                if dry_run:
                    cells.append(MatrixCell(method=m, url=url, status_a=-1, status_b=-1, len_a=0, len_b=0, signal="dry_run"))
                    continue

                try:
                    sa, ta = self._get(ep, headers_a)
                    sb, tb = self._get(ep, headers_b)
                    la, lb = len(ta), len(tb)

                    signal = "ok"
                    # suspect: A forbidden but B OK
                    if sa in (401, 403, 404) and sb == 200:
                        signal = "mismatch"
                    # suspect: both 200 but very different lengths
                    elif sa == 200 and sb == 200:
                        ratio = min(la, lb) / max(la, lb) if max(la, lb) else 1.0
                        if ratio < 0.6:
                            signal = "suspect"

                    cells.append(MatrixCell(method=m, url=url, status_a=sa, status_b=sb, len_a=la, len_b=lb, signal=signal))

                    if signal in ("mismatch", "suspect"):
                        findings.append(
                            {
                                "type": "access_control_matrix",
                                "severity": "high" if signal == "mismatch" else "medium",
                                "confidence": 0.8 if signal == "mismatch" else 0.6,
                                "url": url,
                                "evidence": {
                                    "account_a": {"status": sa, "len": la},
                                    "account_b": {"status": sb, "len": lb},
                                    "signal": signal,
                                },
                                "notes": "Differential access suggests potential Broken Access Control. Validate object ownership & role boundary.",
                            }
                        )

                except Exception as e:
                    cells.append(MatrixCell(method=m, url=url, status_a=0, status_b=0, len_a=0, len_b=0, signal="error"))
                    notes.append(f"Request failed for {url}: {e}")

        return ACMResult(success=True, cells=cells, findings=findings, notes=notes)


def format_acm_result(res: ACMResult, max_rows: int = 30) -> str:
    lines: List[str] = []
    lines.append(f"Matrix cells: {len(res.cells)} | Findings: {len(res.findings)}")
    for c in res.cells[:max_rows]:
        lines.append(f"- {c.method} {c.url} :: A={c.status_a}({c.len_a}) B={c.status_b}({c.len_b}) [{c.signal}]")
    if len(res.cells) > max_rows:
        lines.append(f"... ({len(res.cells) - max_rows} more)")
    return "\n".join(lines)

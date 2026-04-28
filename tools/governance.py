"""tools/governance.py

Governance & permission gates for autonomous security operations.

Goal:
- Prevent unsafe actions without explicit approval
- Provide audit trail for decisions

This is intentionally lightweight and Termux-friendly.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("elengenix.governance")

_DB_PATH = Path(__file__).parent.parent / "data" / "governance_audit.db"


def _now() -> str:
    return datetime.utcnow().isoformat()


def _db_path() -> Path:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return _DB_PATH


def init_db() -> None:
    conn = sqlite3.connect(str(_db_path()), timeout=10)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                mission_id TEXT,
                target TEXT,
                action_type TEXT NOT NULL,
                tool TEXT,
                command TEXT,
                risk_level TEXT NOT NULL,
                decision TEXT NOT NULL,
                rationale TEXT,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


@dataclass
class GateDecision:
    allowed: bool
    risk_level: str
    decision: str  # allow|deny|needs_approval
    rationale: str = ""


class Governance:
    """Policy engine to gate actions."""

    def __init__(self, require_approval_high_risk: bool = True):
        self.require_approval_high_risk = require_approval_high_risk
        init_db()

    def classify_risk(self, action: Dict[str, Any]) -> str:
        """
        Classify risk based on tool and command intent.

        This is intentionally conservative. Anything ambiguous becomes high.
        """
        tool = (action.get("tool") or "").lower().strip()
        cmd = (action.get("command") or "").lower()

        # Pure read-only / discovery tools
        low_tools = {"subfinder", "httpx", "katana", "waybackurls", "gau", "whois", "dig"}

        # Active scanners / fuzzers (can stress target)
        medium_tools = {"naabu", "nmap", "ffuf", "arjun", "nuclei"}

        # Exploitation-style tools
        high_tools = {"dalfox", "trufflehog"}

        if tool in low_tools:
            return "low"
        if tool in medium_tools:
            return "medium"
        if tool in high_tools:
            return "high"

        # Heuristics for explicit exploit intent
        if any(x in cmd for x in ["exploit", "reverse", "shell", "payload", "rce", "deserial", "xss", "sqli"]):
            return "high"

        # Unknown tool/action => high
        return "high"

    def gate(
        self,
        mission_id: str,
        target: str,
        action: Dict[str, Any],
        callback: Optional[Any] = None,
    ) -> GateDecision:
        """Return whether an action is allowed; request approval if needed."""
        risk = self.classify_risk(action)

        # Low/medium allowed by default
        if risk in {"low", "medium"}:
            decision = GateDecision(allowed=True, risk_level=risk, decision="allow", rationale="Policy: low/medium risk")
            self.audit(mission_id, target, action, decision)
            return decision

        # High risk
        if not self.require_approval_high_risk:
            decision = GateDecision(allowed=True, risk_level=risk, decision="allow", rationale="Policy: approvals disabled")
            self.audit(mission_id, target, action, decision)
            return decision

        # If callback available, ask user; otherwise block
        if callback:
            callback("Approval required: high-risk action requested")

        decision = GateDecision(
            allowed=False,
            risk_level=risk,
            decision="needs_approval",
            rationale="High-risk action requires human approval",
        )
        self.audit(mission_id, target, action, decision)
        return decision

    def audit(self, mission_id: str, target: str, action: Dict[str, Any], decision: GateDecision) -> None:
        try:
            conn = sqlite3.connect(str(_db_path()), timeout=10)
            try:
                conn.execute(
                    """
                    INSERT INTO audit (ts, mission_id, target, action_type, tool, command, risk_level, decision, rationale, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        _now(),
                        mission_id,
                        target,
                        (action.get("action") or "").lower(),
                        action.get("tool"),
                        action.get("command"),
                        decision.risk_level,
                        decision.decision,
                        decision.rationale,
                        json.dumps(action, ensure_ascii=False),
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"Governance audit write failed: {e}")

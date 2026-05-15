"""tools/governance.py

Governance & permission gates for autonomous security operations.

Risk classification (v99999 (god nine is the best)):
  DESTRUCTIVE  → Blocked unconditionally (rm -rf /, dd, mkfs, fork bomb)
  PRIVILEGED   → Requires user approval  (sudo, install, write to /etc, /usr)
  SAFE         → Always allowed          (everything else)

The default is full freedom.  Only truly dangerous patterns are denied.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("elengenix.governance")

_DB_PATH = Path(__file__).parent.parent / "data" / "governance_audit.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    risk_level: str        # destructive | privileged | safe
    decision: str          # allow | deny | needs_approval
    rationale: str = ""

    def __post_init__(self) -> None:
        self.risk_level = self.risk_level.upper()


class Governance:
    """Policy engine to gate actions.

    Rules:
      DESTRUCTIVE → ``decision = "deny"``, never executed.
      PRIVILEGED  → ``decision = "needs_approval"`` unless
                    ``require_approval_high_risk`` is ``False``.
      SAFE        → ``decision = "allow"``, always.
    """

    # ── Patterns: if matched → DESTRUCTIVE (blocked) ──────────────────
    _DESTRUCTIVE = re.compile(
        r"rm\s+(-rf|--recursive)\s+/"
        r"|rm\s+(.*-rf.*|.*--recursive.*)"
        r"|rm\s+\S"
        r"|rmdir\s+"
        r"|unlink\s+"
        r"|dd\s+if=.*of=\/dev"
        r"|mkfs\.[a-z0-9]+\s+/dev"
        r"|>\s*/dev/sd"
        r"|:\s*\(\s*\)\s*\{\s*:\|:\&\s*\};"
        r"|chmod\s+777\s+/\s*$"
        r"|chown\s+.*\s+/\s*$"
        r"|shutdown\s+-[rh]\s+now"
        r"|reboot\s*$"
        r"|halt\s*$"
        r"|dd\s+if=/dev/urandom"
        r"|fdisk\s+/dev"
        r"|parted\s+/dev"
        r"|mkswap\s+/dev"
        , re.IGNORECASE,
    )

    # ── Patterns: if matched → PRIVILEGED (needs approval) ────────────
    _PRIVILEGED = re.compile(
        r"^\s*sudo\s"
        r"|^\s*pkexec\s"
        r"|^\s*doas\s"
        r"|pip\s+install"
        r"|pip3\s+install"
        r"|npm\s+install\s+-g"
        r"|apt\s+install"
        r"|apt-get\s+install"
        r"|dnf\s+install"
        r"|yum\s+install"
        r"|brew\s+install"
        r"|pacman\s+-S"
        r"|go\s+install"
        r"|cargo\s+install"
        r"|gem\s+install"
        r"|chmod\s+[0-7]"
        r"|chown\s+"
        r"|>[/\"]"
        r"|>>[/\"]"
        r"|curl.*-o\s+/"
        r"|wget.*-O\s+/"
        r"|mv\s+.*\s+/usr"
        r"|mv\s+.*\s+/etc"
        r"|cp\s+.*\s+/usr"
        r"|cp\s+.*\s+/etc"
        r"|rm\s+/"
        r"|kill\s+-9"
        r"|useradd\s"
        r"|passwd\s"
        r"|usermod\s"
        r"|systemctl\s+(stop|disable|mask)"
        r"|service\s+\w+\s+stop"
        , re.IGNORECASE,
    )

    def __init__(self, require_approval_high_risk: bool = True):
        self.require_approval_high_risk = require_approval_high_risk
        init_db()

    def classify_risk(self, action: Dict[str, Any]) -> str:
        """Return ``DESTRUCTIVE``, ``PRIVILEGED``, or ``SAFE``."""
        cmd = (action.get("command") or "").strip()
        if not cmd:
            return "SAFE"

        if self._DESTRUCTIVE.search(cmd):
            return "DESTRUCTIVE"
        if self._PRIVILEGED.search(cmd):
            return "PRIVILEGED"
        return "SAFE"

    def gate(
        self,
        mission_id: str,
        target: str,
        action: Dict[str, Any],
        callback: Optional[Any] = None,
    ) -> GateDecision:
        """Return a decision for *action*.

        DESTRUCTIVE commands are unconditionally denied.
        PRIVILEGED commands require interactive user approval.
        SAFE commands are always allowed.
        """
        risk = self.classify_risk(action)

        if risk == "DESTRUCTIVE":
            decision = GateDecision(
                allowed=False,
                risk_level=risk,
                decision="deny",
                rationale="Destructive command blocked by governance policy.",
            )
            self.audit(mission_id, target, action, decision)
            return decision

        if risk == "PRIVILEGED":
            if not self.require_approval_high_risk:
                decision = GateDecision(
                    allowed=True,
                    risk_level=risk,
                    decision="allow",
                    rationale="Policy: approvals disabled.",
                )
                self.audit(mission_id, target, action, decision)
                return decision

            decision = GateDecision(
                allowed=False,
                risk_level=risk,
                decision="needs_approval",
                rationale="Privileged action requires human approval.",
            )
            self.audit(mission_id, target, action, decision)
            return decision

        # SAFE
        decision = GateDecision(
            allowed=True,
            risk_level=risk,
            decision="allow",
            rationale="Safe action allowed by policy.",
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

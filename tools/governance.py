"""tools/governance.py

Governance & permission gates for autonomous security operations.

Risk classification:
  DESTRUCTIVE  → Requires user approval (rm -rf /, dd, mkfs, fork bomb)
  PRIVILEGED   → Requires user approval (sudo, install, write to /etc, /usr)
  SAFE         → Always allowed (everything else)

All non-SAFE commands show a popup for user approval.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from elengenix.paths import get_data_path

logger = logging.getLogger("elengenix.governance")

_DB_PATH = get_data_path("governance_audit.db")


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
    risk_level: str  # destructive | privileged | safe
    decision: str  # allow | deny | needs_approval
    rationale: str = ""

    def __post_init__(self) -> None:
        self.risk_level = self.risk_level.upper()


class Governance:
    """Policy engine to gate actions.

    Rules:
      DESTRUCTIVE → ``decision = "needs_approval"``, user must confirm.
      PRIVILEGED  → ``decision = "needs_approval"`` unless
                    ``require_approval_high_risk`` is ``False``.
      SAFE        → ``decision = "allow"``, always.
    """

    _SYSTEM_PATHS = (
        "/",
        "/etc",
        "/boot",
        "/usr",
        "/var",
        "/lib",
        "/bin",
        "/sbin",
        "/sys",
        "/proc",
        "/dev",
    )
    _SYSTEM_WRITE_PATHS = (
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
    )

    # ── Patterns: if matched → DESTRUCTIVE (requires approval) ──────────
    _DESTRUCTIVE = re.compile(
        r"\brm\b[^\n;&|]*(?:-[^\n;&|]*[rf][^\n;&|]*)[^\n;&|]*(?:\s|=)(/|/\*|\*|/etc|/boot|/usr|/var|/lib|/bin|/sbin|/sys|/proc|/dev)(?:\s|$)"
        r"|\b(?:shred|wipe|srm)\b[^\n;&|]*(?:\s|=)(/|/\*|\*|/etc|/boot|/usr|/var|/lib|/bin|/sbin|/sys|/proc|/dev)(?:\s|$)"
        r"|dd\s+if=.*of=\/dev"
        r"|dd\s+if=/dev/urandom"
        r"|dd\s+if=/dev/zero"
        r"|mkfs\.[a-z0-9]+\s+/dev"
        r"|>\s*/dev/[sh]d"
        r"|fdisk\s+/dev"
        r"|parted\s+/dev"
        r"|mkswap\s+/dev"
        r"|:\s*\(\s*\)\s*\{\s*:\|:\ &\s*\};"
        r"|chmod\s+777\s+/\s*$"
        r"|chown\s+.*\s+/\s*$"
        r"|shutdown\s+-[rh]\s+now"
        r"|\breboot\s*$"
        r"|\bhalt\s*$",
        re.IGNORECASE,
    )

    # ── Patterns: if matched → PRIVILEGED (needs approval) ────────────
    _PRIVILEGED = re.compile(
        r"^\s*sudo\s"
        r"|pip\s+install"
        r"|pip3\s+install"
        r"|npm\s+install\s+-g"
        r"|apt\s+install"
        r"|apt-get\s+install"
        r"|dnf\s+install"
        r"|yum\s+install"
        r"|pacman\s+-S"
        r"|go\s+install"
        r"|cargo\s+install"
        r"|brew\s+install"
        r"|gem\s+install"
        r"|curl\s+.*\|\s*(ba?sh|sh|zsh|python3?|ruby|perl)"
        r"|wget\s+.*\|\s*(ba?sh|sh|zsh|python3?|ruby|perl)"
        r"|(?:^|[\s;&|])(?:tee|cat|echo|printf|cp|mv|install)\b[^\n]*(?:>\s*)?/(?:etc|usr|bin|sbin|boot|dev|proc|sys)(?:/|\s|$)"
        r"|(?:>|>>)\s*/(?:etc|usr|bin|sbin|boot|dev|proc|sys)(?:/|\s|$)",
        re.IGNORECASE,
    )

    def __init__(self, require_approval_high_risk: bool = True):
        self.require_approval_high_risk = require_approval_high_risk
        #  Session-level auto-approve toggle.
        #  When True, PRIVILEGED/DESTRUCTIVE commands are allowed without prompting
        #  for the remainder of the current process session.
        self.auto_approve_privileged: bool = False
        init_db()

    def classify_risk(self, action: Dict[str, Any]) -> str:
        """Return ``DESTRUCTIVE``, ``PRIVILEGED``, or ``SAFE``."""
        cmd = self._normalize_command(action.get("command") or "")
        if not cmd:
            return "SAFE"

        if self._is_destructive_command(cmd):
            return "DESTRUCTIVE"
        if self._is_privileged_command(cmd):
            return "PRIVILEGED"
        return "SAFE"

    @staticmethod
    def _normalize_command(command: str) -> str:
        """Normalize command text for policy matching without changing semantics."""
        return re.sub(r"\s+", " ", str(command).strip())

    def _is_destructive_command(self, command: str) -> bool:
        """Return True for commands that should never be executed."""
        if self._DESTRUCTIVE.search(command):
            return True

        for tokens in self._command_token_groups(command):
            tokens = self._strip_leading_wrappers(tokens)
            if not tokens:
                continue

            name = Path(tokens[0]).name
            args = tokens[1:]

            if name == "rm" and self._rm_targets_protected_path(args):
                return True

            if name in {"shred", "wipe", "srm"} and self._has_protected_path(args):
                return True

            if name == "dd" and self._dd_targets_device(args):
                return True

            if (
                name.startswith("mkfs.") or name in {"fdisk", "parted", "mkswap"}
            ) and self._has_device_path(args):
                return True

            if name in {"shutdown", "reboot", "halt"}:
                return True

            if name == "chmod" and any(arg == "777" for arg in args) and self._has_exact_root(args):
                return True

            if name == "chown" and self._has_exact_root(args):
                return True

        return False

    def _is_privileged_command(self, command: str) -> bool:
        """Return True for commands that require explicit human approval."""
        if self._PRIVILEGED.search(command):
            return True

        for tokens in self._command_token_groups(command):
            tokens = self._strip_leading_wrappers(tokens)
            if not tokens:
                continue

            name = Path(tokens[0]).name
            args = tokens[1:]
            if name == "sudo":
                return True
            if name in {"pip", "pip3"} and args[:1] == ["install"]:
                return True
            if name == "npm" and "install" in args and "-g" in args:
                return True
            if (
                name in {"apt", "apt-get", "dn", "yum", "brew", "gem", "cargo"}
                and "install" in args
            ):
                return True
            if name == "go" and args[:1] == ["install"]:
                return True
            if self._writes_system_path(tokens):
                return True

        return False

    @staticmethod
    def _command_token_groups(command: str) -> list[list[str]]:
        """Split a shell command into simple token groups for policy checks."""
        groups: list[list[str]] = []
        for segment in re.split(r"\s*(?:&&|\|\||;|\n)\s*", command):
            if not segment.strip():
                continue
            try:
                groups.append(shlex.split(segment, posix=True))
            except ValueError:
                groups.append(segment.split())
        return groups

    @staticmethod
    def _strip_leading_wrappers(tokens: list[str]) -> list[str]:
        """Remove simple env/sudo wrappers so the real command can be classified."""
        stripped = list(tokens)
        while stripped:
            name = Path(stripped[0]).name
            if name == "sudo":
                stripped = stripped[1:]
                while stripped and stripped[0].startswith("-"):
                    stripped = stripped[1:]
                continue
            if name == "env":
                stripped = stripped[1:]
                while stripped and ("=" in stripped[0] or stripped[0].startswith("-")):
                    stripped = stripped[1:]
                continue
            break
        return stripped

    def _rm_targets_protected_path(self, args: list[str]) -> bool:
        has_recursive_or_force = any(
            arg.startswith("-") and ("r" in arg.lower() or "f" in arg.lower()) for arg in args
        )
        return has_recursive_or_force and self._has_protected_path(args)

    def _has_protected_path(self, args: list[str]) -> bool:
        return any(self._is_protected_path(arg) for arg in args)

    @staticmethod
    def _has_exact_root(args: list[str]) -> bool:
        return any(arg.rstrip("/") == "" for arg in args if arg.startswith("/"))

    @staticmethod
    def _has_device_path(args: list[str]) -> bool:
        return any(arg.startswith("/dev/") for arg in args)

    @staticmethod
    def _dd_targets_device(args: list[str]) -> bool:
        return any(arg.startswith("of=/dev/") for arg in args)

    def _writes_system_path(self, tokens: list[str]) -> bool:
        for index, token in enumerate(tokens):
            if token in {">", ">>"} and index + 1 < len(tokens):
                if self._is_system_write_path(tokens[index + 1]):
                    return True
            if token.startswith(">") and self._is_system_write_path(token.lstrip(">")):
                return True
        return False

    def _is_protected_path(self, value: str) -> bool:
        candidate = value.strip().rstrip("/")
        if candidate in {"", "*"} and value.strip().startswith("/"):
            return True
        for protected in self._SYSTEM_PATHS:
            base = protected.rstrip("/")
            if protected == "/" and value.strip() in {"/", "/*"}:
                return True
            if base and (candidate == base or candidate.startswith(f"{base}/")):
                return True
        return value.strip() == "*"

    def _is_system_write_path(self, value: str) -> bool:
        candidate = value.strip()
        return any(
            candidate == path or candidate.startswith(f"{path}/")
            for path in self._SYSTEM_WRITE_PATHS
        )

    def gate(
        self,
        mission_id: str,
        target: str,
        action: Dict[str, Any],
        callback: Optional[Any] = None,
    ) -> GateDecision:
        """Return a decision for *action*.

        DESTRUCTIVE commands require user approval (popup).
        PRIVILEGED commands require user approval (popup).
        SAFE commands are always allowed.
        """
        risk = self.classify_risk(action)

        if risk == "DESTRUCTIVE":
            # DESTRUCTIVE commands are blocked unconditionally — auto-approve
            # must never bypass them (user safety invariant).
            decision = GateDecision(
                allowed=False,
                risk_level=risk,
                decision="deny",
                rationale="Destructive command is blocked unconditionally.",
            )
            self.audit(mission_id, target, action, decision)
            return decision

        if risk == "PRIVILEGED":
            # Auto-approve mode: user granted blanket approval this session
            if self.auto_approve_privileged:
                decision = GateDecision(
                    allowed=True,
                    risk_level=risk,
                    decision="allow",
                    rationale="Auto-approve mode active (user granted session-wide approval).",
                )
                self.audit(mission_id, target, action, decision)
                return decision

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

    def audit(
        self, mission_id: str, target: str, action: Dict[str, Any], decision: GateDecision
    ) -> None:
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

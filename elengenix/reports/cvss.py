"""elengenix.reports.cvss — CVSS v3.1 vector parsing and score calculation.

Implements the FIRST.org CVSS v3.1 specification:
https://www.first.org/cvss/v3.1/specification-document

Public surface (importable via ``from elengenix.reports.cvss import *``):
    Enums:        AttackVector, AttackComplexity, PrivilegesRequired,
                  UserInteraction, Scope, CIAImpact
    Models:       CVSSVector, CVSSResult
    Functions:    parse_cvss_vector, format_cvss_vector, calculate_cvss_score,
                  cvss_severity, cvss_result
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums (CVSS v3.1 base-metric values)
# ---------------------------------------------------------------------------


class AttackVector(str, Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(str, Enum):
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(str, Enum):
    NONE = "N"
    REQUIRED = "R"


class Scope(str, Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class CIAImpact(str, Enum):
    NONE = "N"
    LOW = "L"
    MEDIUM = "L"  # backward-compatible alias of LOW (same value)
    HIGH = "H"


# ---------------------------------------------------------------------------
# CVSSVector model
# ---------------------------------------------------------------------------


@dataclass(init=False)
class CVSSVector:
    """CVSS v3.1 vector with all 8 base metrics.

    Canonical field names use the ``*_impact`` suffix
    (``confidentiality_impact`` / ``integrity_impact`` / ``availability_impact``).
    The legacy short names (``confidentiality`` / ``integrity`` / ``availability``)
    are kept as backward-compatible aliases — usable both as constructor keyword
    arguments and as attribute accessors.
    """

    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality_impact: CIAImpact = CIAImpact.NONE
    integrity_impact: CIAImpact = CIAImpact.NONE
    availability_impact: CIAImpact = CIAImpact.NONE

    def __init__(
        self,
        attack_vector: AttackVector = AttackVector.NETWORK,
        attack_complexity: AttackComplexity = AttackComplexity.LOW,
        privileges_required: PrivilegesRequired = PrivilegesRequired.NONE,
        user_interaction: UserInteraction = UserInteraction.NONE,
        scope: Scope = Scope.UNCHANGED,
        confidentiality_impact: CIAImpact = CIAImpact.NONE,
        integrity_impact: CIAImpact = CIAImpact.NONE,
        availability_impact: CIAImpact = CIAImpact.NONE,
        *,
        confidentiality: Optional[CIAImpact] = None,
        integrity: Optional[CIAImpact] = None,
        availability: Optional[CIAImpact] = None,
    ) -> None:
        self.attack_vector = attack_vector
        self.attack_complexity = attack_complexity
        self.privileges_required = privileges_required
        self.user_interaction = user_interaction
        self.scope = scope
        self.confidentiality_impact = (
            confidentiality if confidentiality is not None else confidentiality_impact
        )
        self.integrity_impact = (
            integrity if integrity is not None else integrity_impact
        )
        self.availability_impact = (
            availability if availability is not None else availability_impact
        )

    # -- backward-compatible aliases (old names → new names) ---------------

    @property
    def confidentiality(self) -> CIAImpact:
        return self.confidentiality_impact

    @confidentiality.setter
    def confidentiality(self, value: CIAImpact) -> None:
        self.confidentiality_impact = value

    @property
    def integrity(self) -> CIAImpact:
        return self.integrity_impact

    @integrity.setter
    def integrity(self, value: CIAImpact) -> None:
        self.integrity_impact = value

    @property
    def availability(self) -> CIAImpact:
        return self.availability_impact

    @availability.setter
    def availability(self, value: CIAImpact) -> None:
        self.availability_impact = value


# ---------------------------------------------------------------------------
# Metric lookup tables (CVSS v3.1 spec)
# ---------------------------------------------------------------------------

_AV_VALUES = {
    "N": AttackVector.NETWORK,
    "A": AttackVector.ADJACENT,
    "L": AttackVector.LOCAL,
    "P": AttackVector.PHYSICAL,
}
_AC_VALUES = {"L": AttackComplexity.LOW, "H": AttackComplexity.HIGH}
_PR_VALUES = {
    "N": PrivilegesRequired.NONE,
    "L": PrivilegesRequired.LOW,
    "H": PrivilegesRequired.HIGH,
}
_UI_VALUES = {"N": UserInteraction.NONE, "R": UserInteraction.REQUIRED}
_S_VALUES = {"U": Scope.UNCHANGED, "C": Scope.CHANGED}
_CIA_VALUES = {"N": CIAImpact.NONE, "L": CIAImpact.LOW, "H": CIAImpact.HIGH}

# Reverse lookup for formatting
_AV_REV = {v: k for k, v in _AV_VALUES.items()}
_AC_REV = {v: k for k, v in _AC_VALUES.items()}
_PR_REV = {v: k for k, v in _PR_VALUES.items()}
_UI_REV = {v: k for k, v in _UI_VALUES.items()}
_S_REV = {v: k for k, v in _S_VALUES.items()}
_CIA_REV = {v: k for k, v in _CIA_VALUES.items()}

# Metric value weights (from CVSS v3.1 spec)
_IMPACT_WEIGHTS = {CIAImpact.NONE: 0.0, CIAImpact.LOW: 0.22, CIAImpact.HIGH: 0.56}
_EXPLOITABILITY_WEIGHTS = {
    AttackVector.NETWORK: 0.85,
    AttackVector.ADJACENT: 0.62,
    AttackVector.LOCAL: 0.55,
    AttackVector.PHYSICAL: 0.2,
}
_AC_WEIGHTS = {AttackComplexity.LOW: 0.77, AttackComplexity.HIGH: 0.44}
_UI_WEIGHTS = {UserInteraction.NONE: 0.85, UserInteraction.REQUIRED: 0.62}
_PR_WEIGHTS_SAME = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.62,
    PrivilegesRequired.HIGH: 0.27,
}
_PR_WEIGHTS_CHANGED = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.68,
    PrivilegesRequired.HIGH: 0.5,
}

# Maps the short metric keys used in vector strings to the field names.
_METRIC_KEY_MAP = {
    "AV": "attack_vector",
    "AC": "attack_complexity",
    "PR": "privileges_required",
    "UI": "user_interaction",
    "S": "scope",
    "C": "confidentiality_impact",
    "I": "integrity_impact",
    "A": "availability_impact",
}

# Regex matching the optional ``CVSS:3.x/`` prefix.
_PREFIX_RE = re.compile(r"^CVSS:3\.\d+/?")
# Regex matching a single ``KEY:VALUE`` metric segment.
_SEGMENT_RE = re.compile(r"^([A-Za-z]+):([A-Za-z]+)$")


# ---------------------------------------------------------------------------
# CVSS v3.1 Roundup (spec-compliant)
# ---------------------------------------------------------------------------


def _roundup(score: float) -> float:
    """CVSS v3.1 Roundup function (ceil to 1 decimal place, FP-safe)."""
    int_input = round(score * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0


# ---------------------------------------------------------------------------
# Parsing / formatting
# ---------------------------------------------------------------------------


def parse_cvss_vector(vector_string: str) -> CVSSVector:
    """Parse a CVSS v3.1 vector string into a :class:`CVSSVector` object.

    Accepts both the canonical ``CVSS:3.1/AV:N/...`` form and the bare
    ``AV:N/...`` form.

    Raises:
        ValueError: for empty strings, non-string input, or any segment that
            is not a recognised ``KEY:VALUE`` metric pair (e.g. ``"garbage"``,
            ``"AV:Z"``).
    """
    if not isinstance(vector_string, str) or not vector_string.strip():
        raise ValueError(f"Invalid CVSS vector string: {vector_string!r}")

    s = vector_string.strip()
    # Strip optional ``CVSS:3.x/`` prefix.
    s = _PREFIX_RE.sub("", s, count=1)

    parts = [p for p in s.split("/") if p]
    if not parts:
        raise ValueError(f"Invalid CVSS vector string: {vector_string!r}")

    metrics: dict[str, str] = {}
    for part in parts:
        match = _SEGMENT_RE.match(part)
        if not match:
            raise ValueError(
                f"Invalid CVSS metric segment {part!r} in {vector_string!r}"
            )
        key, val = match.group(1), match.group(2)
        if key not in _METRIC_KEY_MAP:
            raise ValueError(
                f"Unknown CVSS metric key {key!r} in {vector_string!r}"
            )
        metrics[key] = val

    try:
        return CVSSVector(
            attack_vector=_AV_VALUES[metrics.get("AV", "N")],
            attack_complexity=_AC_VALUES[metrics.get("AC", "L")],
            privileges_required=_PR_VALUES[metrics.get("PR", "N")],
            user_interaction=_UI_VALUES[metrics.get("UI", "N")],
            scope=_S_VALUES[metrics.get("S", "U")],
            confidentiality_impact=_CIA_VALUES[metrics.get("C", "N")],
            integrity_impact=_CIA_VALUES[metrics.get("I", "N")],
            availability_impact=_CIA_VALUES[metrics.get("A", "N")],
        )
    except KeyError as exc:
        raise ValueError(f"Invalid CVSS metric value: {exc}") from exc


def format_cvss_vector(v: CVSSVector) -> str:
    """Format a :class:`CVSSVector` into the canonical ``CVSS:3.1/...`` string."""
    return (
        f"CVSS:3.1/AV:{_AV_REV[v.attack_vector]}"
        f"/AC:{_AC_REV[v.attack_complexity]}"
        f"/PR:{_PR_REV[v.privileges_required]}"
        f"/UI:{_UI_REV[v.user_interaction]}"
        f"/S:{_S_REV[v.scope]}"
        f"/C:{_CIA_REV[v.confidentiality_impact]}"
        f"/I:{_CIA_REV[v.integrity_impact]}"
        f"/A:{_CIA_REV[v.availability_impact]}"
    )


# ---------------------------------------------------------------------------
# Score calculation
# ---------------------------------------------------------------------------


def _impact_and_exploitability(v: CVSSVector) -> tuple[float, float]:
    """Return ``(impact, exploitability)`` sub-scores for a vector."""
    c_impact = _IMPACT_WEIGHTS[v.confidentiality_impact]
    i_impact = _IMPACT_WEIGHTS[v.integrity_impact]
    a_impact = _IMPACT_WEIGHTS[v.availability_impact]
    isc_base = 1 - ((1 - c_impact) * (1 - i_impact) * (1 - a_impact))

    if v.scope == Scope.CHANGED:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    av_weight = _EXPLOITABILITY_WEIGHTS[v.attack_vector]
    ac_weight = _AC_WEIGHTS[v.attack_complexity]
    ui_weight = _UI_WEIGHTS[v.user_interaction]
    pr_weight = (
        _PR_WEIGHTS_CHANGED[v.privileges_required]
        if v.scope == Scope.CHANGED
        else _PR_WEIGHTS_SAME[v.privileges_required]
    )
    exploitability = 8.22 * av_weight * ac_weight * pr_weight * ui_weight
    return impact, exploitability


def calculate_cvss_score(v: CVSSVector) -> float:
    """Calculate the CVSS v3.1 base score.

    Follows the FIRST.org specification exactly:
      1. Calculate the Impact Sub-Score (ISC) base.
      2. Calculate Impact (scope-dependent).
      3. Calculate Exploitability.
      4. Calculate the Base Score (scope-dependent), then Roundup.

    Score table (verified):
      POODLE  AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N → 3.7
      XSS     AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N → 6.1
      High    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
      Crit    AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0
    """
    impact, exploitability = _impact_and_exploitability(v)

    if impact <= 0:
        return 0.0

    if v.scope == Scope.CHANGED:
        base_score = min(1.08 * (impact + exploitability), 10.0)
    else:
        base_score = min(impact + exploitability, 10.0)

    return _roundup(base_score)


def cvss_severity(score: float) -> str:
    """Return the severity label for a CVSS base score.

    Thresholds (per FIRST.org):
      0.0          → Info
      0.1 – 3.9    → Low
      4.0 – 6.9    → Medium
      7.0 – 8.9    → High
      9.0 – 10.0   → Critical
    """
    if score <= 0.0:
        return "Info"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# ---------------------------------------------------------------------------
# CVSSResult model
# ---------------------------------------------------------------------------


@dataclass
class CVSSResult:
    """Complete CVSS assessment result."""

    base_score: float
    severity: str
    vector_string: str
    impact_subscore: float
    exploitability_subscore: float


def cvss_result(v: CVSSVector) -> CVSSResult:
    """Calculate a full :class:`CVSSResult` from a :class:`CVSSVector`."""
    impact, exploitability = _impact_and_exploitability(v)
    score = calculate_cvss_score(v)
    return CVSSResult(
        base_score=score,
        severity=cvss_severity(score),
        vector_string=format_cvss_vector(v),
        impact_subscore=round(max(0.0, impact), 1),
        exploitability_subscore=round(exploitability, 1),
    )

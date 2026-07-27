"""elengenix.reports.cvss — CVSS v3.1 vector parsing and score calculation.

Implements the FIRST.org CVSS v3.1 specification:
https://www.first.org/cvss/v3.1/specification-document
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


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
    MEDIUM = "L"  # alias
    HIGH = "H"


@dataclass
class CVSSVector:
    """CVSS v3.1 vector with all 8 base metrics."""
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: CIAImpact = CIAImpact.NONE
    integrity: CIAImpact = CIAImpact.NONE
    availability: CIAImpact = CIAImpact.NONE


# Metric lookup tables
_AV_VALUES = {"N": AttackVector.NETWORK, "A": AttackVector.ADJACENT, "L": AttackVector.LOCAL, "P": AttackVector.PHYSICAL}
_AC_VALUES = {"L": AttackComplexity.LOW, "H": AttackComplexity.HIGH}
_PR_VALUES = {"N": PrivilegesRequired.NONE, "L": PrivilegesRequired.LOW, "H": PrivilegesRequired.HIGH}
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
    AttackVector.NETWORK: 0.85, AttackVector.ADJACENT: 0.62,
    AttackVector.LOCAL: 0.55, AttackVector.PHYSICAL: 0.2,
}
_AC_WEIGHTS = {AttackComplexity.LOW: 0.77, AttackComplexity.HIGH: 0.44}
_UI_WEIGHTS = {UserInteraction.NONE: 0.85, UserInteraction.REQUIRED: 0.62}
_PR_WEIGHTS_SAME = {PrivilegesRequired.NONE: 0.85, PrivilegesRequired.LOW: 0.62, PrivilegesRequired.HIGH: 0.27}
_PR_WEIGHTS_CHANGED = {PrivilegesRequired.NONE: 0.85, PrivilegesRequired.LOW: 0.68, PrivilegesRequired.HIGH: 0.5}


def parse_cvss_vector(vector_string: str) -> CVSSVector:
    """Parse a CVSS v3.1 vector string into a CVSSVector object.

    Accepts both 'CVSS:3.1/AV:N/...' and bare 'AV:N/...' forms.
    Raises ValueError for empty strings or invalid metric values.
    """
    if not vector_string or not vector_string.strip():
        raise ValueError("Empty CVSS vector string")

    s = vector_string.strip()
    # Strip optional prefix
    if s.startswith("CVSS:3.1/"):
        s = s[len("CVSS:3.1/"):]
    elif s.startswith("CVSS:3.0/"):
        s = s[len("CVSS:3.0/"):]

    parts = s.split("/")
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        metrics[key] = val

    try:
        return CVSSVector(
            attack_vector=_AV_VALUES[metrics.get("AV", "N")],
            attack_complexity=_AC_VALUES[metrics.get("AC", "L")],
            privileges_required=_PR_VALUES[metrics.get("PR", "N")],
            user_interaction=_UI_VALUES[metrics.get("UI", "N")],
            scope=_S_VALUES[metrics.get("S", "U")],
            confidentiality=_CIA_VALUES[metrics.get("C", "N")],
            integrity=_CIA_VALUES[metrics.get("I", "N")],
            availability=_CIA_VALUES[metrics.get("A", "N")],
        )
    except KeyError as e:
        raise ValueError(f"Invalid CVSS metric value: {e}")


def format_cvss_vector(v: CVSSVector) -> str:
    """Format a CVSSVector into canonical 'CVSS:3.1/AV:N/...' string."""
    return (
        f"CVSS:3.1/AV:{_AV_REV[v.attack_vector]}/AC:{_AC_REV[v.attack_complexity]}"
        f"/PR:{_PR_REV[v.privileges_required]}/UI:{_UI_REV[v.user_interaction]}"
        f"/S:{_S_REV[v.scope]}/C:{_CIA_REV[v.confidentiality]}"
        f"/I:{_CIA_REV[v.integrity]}/A:{_CIA_REV[v.availability]}"
    )


def calculate_cvss_score(v: CVSSVector) -> float:
    """Calculate the CVSS v3.1 base score.

    Follows the FIRST.org specification exactly:
    1. Calculate Impact Subscore (ISC)
    2. Calculate Exploitability Subscore
    3. Calculate Impact (depends on Scope)
    4. Calculate Base Score (depends on Scope and Impact)
    """
    # Step 1: ISCBase
    c_impact = _IMPACT_WEIGHTS[v.confidentiality]
    i_impact = _IMPACT_WEIGHTS[v.integrity]
    a_impact = _IMPACT_WEIGHTS[v.availability]
    isc_base = 1 - ((1 - c_impact) * (1 - i_impact) * (1 - a_impact))

    # Step 2: Impact (depends on Scope)
    if v.scope == Scope.CHANGED:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    # Step 3: Exploitability
    av_weight = _EXPLOITABILITY_WEIGHTS[v.attack_vector]
    ac_weight = _AC_WEIGHTS[v.attack_complexity]
    ui_weight = _UI_WEIGHTS[v.user_interaction]
    pr_weight = _PR_WEIGHTS_CHANGED[v.privileges_required] if v.scope == Scope.CHANGED else _PR_WEIGHTS_SAME[v.privileges_required]
    exploitability = 8.22 * av_weight * ac_weight * pr_weight * ui_weight

    # Step 4: Base Score
    if impact <= 0:
        return 0.0

    if v.scope == Scope.CHANGED:
        base_score = min(1.08 * (impact + exploitability), 10.0)
    else:
        base_score = min(impact + exploitability, 10.0)

    # Round to 1 decimal place using CVSS Roundup (ceil to 1 decimal)
    import math
    return math.ceil(base_score * 10) / 10.0


def cvss_severity(score: float) -> str:
    """Return severity label for a CVSS score.

    Per FIRST.org:
    - 0.0: Info (None)
    - 0.1-3.9: Low
    - 4.0-6.9: Medium
    - 7.0-8.9: High
    - 9.0-10.0: Critical
    """
    if score == 0.0:
        return "Info"
    elif score < 4.0:
        return "Low"
    elif score < 7.0:
        return "Medium"
    elif score < 9.0:
        return "High"
    else:
        return "Critical"


@dataclass
class CVSSResult:
    """Complete CVSS assessment result."""
    base_score: float
    severity: str
    vector_string: str
    impact_subscore: float
    exploitability_subscore: float


def cvss_result(v: CVSSVector) -> CVSSResult:
    """Calculate full CVSSResult from a CVSSVector."""
    # Calculate subscores
    c_impact = _IMPACT_WEIGHTS[v.confidentiality]
    i_impact = _IMPACT_WEIGHTS[v.integrity]
    a_impact = _IMPACT_WEIGHTS[v.availability]
    isc_base = 1 - ((1 - c_impact) * (1 - i_impact) * (1 - a_impact))

    if v.scope == Scope.CHANGED:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    av_weight = _EXPLOITABILITY_WEIGHTS[v.attack_vector]
    ac_weight = _AC_WEIGHTS[v.attack_complexity]
    ui_weight = _UI_WEIGHTS[v.user_interaction]
    pr_weight = _PR_WEIGHTS_CHANGED[v.privileges_required] if v.scope == Scope.CHANGED else _PR_WEIGHTS_SAME[v.privileges_required]
    exploitability = 8.22 * av_weight * ac_weight * pr_weight * ui_weight

    score = calculate_cvss_score(v)
    return CVSSResult(
        base_score=score,
        severity=cvss_severity(score),
        vector_string=format_cvss_vector(v),
        impact_subscore=max(0.0, impact),
        exploitability_subscore=exploitability,
    )

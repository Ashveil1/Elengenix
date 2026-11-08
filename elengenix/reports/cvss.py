"""CVSS v3.1 parsing, scoring and severity classification.

Implements the FIRST CVSS v3.1 specification formulas:
https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Dict

__all__ = [
    "AttackVector",
    "AttackComplexity",
    "PrivilegesRequired",
    "UserInteraction",
    "Scope",
    "CIAImpact",
    "CVSSVector",
    "CVSSResult",
    "parse_cvss_vector",
    "format_cvss_vector",
    "calculate_cvss_score",
    "cvss_severity",
    "cvss_result",
]


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
    HIGH = "H"


# Metric weight tables (CVSS v3.1 §8.1).
_AV_WEIGHT: Dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC_WEIGHT: Dict[str, float] = {"L": 0.77, "H": 0.44}
_PR_WEIGHT_UNCHANGED: Dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHT_CHANGED: Dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI_WEIGHT: Dict[str, float] = {"N": 0.85, "R": 0.62}
_CIA_WEIGHT: Dict[str, float] = {"N": 0.0, "L": 0.22, "H": 0.56}

# metric abbreviation → (enum type, CVSSVector field name)
_METRIC_FIELDS = {
    "AV": (AttackVector, "attack_vector"),
    "AC": (AttackComplexity, "attack_complexity"),
    "PR": (PrivilegesRequired, "privileges_required"),
    "UI": (UserInteraction, "user_interaction"),
    "S": (Scope, "scope"),
    "C": (CIAImpact, "confidentiality_impact"),
    "I": (CIAImpact, "integrity_impact"),
    "A": (CIAImpact, "availability_impact"),
}


@dataclass
class CVSSVector:
    """A CVSS v3.1 base metric vector. Defaults: the null vector (score 0)."""

    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality_impact: CIAImpact = CIAImpact.NONE
    integrity_impact: CIAImpact = CIAImpact.NONE
    availability_impact: CIAImpact = CIAImpact.NONE
    version: str = "3.1"


@dataclass
class CVSSResult:
    """Full CVSS v3.1 scoring result for a vector."""

    base_score: float
    severity: str
    vector_string: str
    impact_subscore: float
    exploitability_subscore: float
    version: str = "3.1"


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest number with one decimal >= value."""
    # Guard against float noise (e.g. 4.0 arriving as 4.000000001) while
    # keeping true ceiling semantics (3.6335... -> 3.7).
    return math.ceil(round(value * 10, 6)) / 10


def parse_cvss_vector(vector: str) -> CVSSVector:
    """Parse a CVSS vector string (with or without the ``CVSS:3.1/`` prefix).

    Raises ValueError on empty input, unknown metrics or invalid values.
    """
    if not vector or not vector.strip():
        raise ValueError("empty CVSS vector string")
    parts = [p.strip() for p in vector.strip().split("/") if p.strip()]

    version = "3.1"
    if parts and parts[0].upper().startswith("CVSS:"):
        version = parts[0].split(":", 1)[1] or "3.1"
        parts = parts[1:]

    values = {
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "confidentiality_impact": CIAImpact.NONE,
        "integrity_impact": CIAImpact.NONE,
        "availability_impact": CIAImpact.NONE,
    }
    seen = set()
    for part in parts:
        if ":" not in part:
            raise ValueError(f"malformed CVSS metric: {part!r}")
        abbr, val = part.split(":", 1)
        abbr = abbr.upper()
        if abbr not in _METRIC_FIELDS:
            raise ValueError(f"unknown CVSS metric: {abbr!r}")
        enum_type, field_name = _METRIC_FIELDS[abbr]
        try:
            values[field_name] = enum_type(val.upper())
        except ValueError as exc:
            raise ValueError(f"invalid value {val!r} for CVSS metric {abbr}") from exc
        seen.add(abbr)

    missing = set(_METRIC_FIELDS) - seen
    if missing:
        raise ValueError(f"missing CVSS metrics: {', '.join(sorted(missing))}")

    vec = CVSSVector(version=version)
    for field_name, val in values.items():
        setattr(vec, field_name, val)
    return vec


def format_cvss_vector(vector: CVSSVector) -> str:
    """Format a CVSSVector back into its canonical vector string."""
    return (
        f"CVSS:{vector.version}"
        f"/AV:{vector.attack_vector.value}"
        f"/AC:{vector.attack_complexity.value}"
        f"/PR:{vector.privileges_required.value}"
        f"/UI:{vector.user_interaction.value}"
        f"/S:{vector.scope.value}"
        f"/C:{vector.confidentiality_impact.value}"
        f"/I:{vector.integrity_impact.value}"
        f"/A:{vector.availability_impact.value}"
    )


def _impact_subscore(vector: CVSSVector) -> float:
    iss = 1.0 - (
        (1.0 - _CIA_WEIGHT[vector.confidentiality_impact.value])
        * (1.0 - _CIA_WEIGHT[vector.integrity_impact.value])
        * (1.0 - _CIA_WEIGHT[vector.availability_impact.value])
    )
    if vector.scope == Scope.UNCHANGED:
        return 6.42 * iss
    return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15


def _exploitability_subscore(vector: CVSSVector) -> float:
    pr_weight = (
        _PR_WEIGHT_CHANGED
        if vector.scope == Scope.CHANGED
        else _PR_WEIGHT_UNCHANGED
    )[vector.privileges_required.value]
    return (
        8.22
        * _AV_WEIGHT[vector.attack_vector.value]
        * _AC_WEIGHT[vector.attack_complexity.value]
        * pr_weight
        * _UI_WEIGHT[vector.user_interaction.value]
    )


def calculate_cvss_score(vector: CVSSVector) -> float:
    """Compute the CVSS v3.1 base score for a vector."""
    impact = _impact_subscore(vector)
    exploitability = _exploitability_subscore(vector)
    if impact <= 0:
        return 0.0
    if vector.scope == Scope.UNCHANGED:
        return _roundup(min(impact + exploitability, 10.0))
    return _roundup(min(1.08 * (impact + exploitability), 10.0))


def cvss_severity(score: float) -> str:
    """Map a numeric CVSS score to its qualitative severity rating."""
    if score <= 0.0:
        return "Info"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def cvss_result(vector: CVSSVector) -> CVSSResult:
    """Score a vector and return the full CVSSResult."""
    return CVSSResult(
        base_score=calculate_cvss_score(vector),
        severity=cvss_severity(calculate_cvss_score(vector)),
        vector_string=format_cvss_vector(vector),
        impact_subscore=_roundup(_impact_subscore(vector)),
        exploitability_subscore=_roundup(_exploitability_subscore(vector)),
        version=vector.version,
    )

"""tools/supply_chain_analyzer.py — Supply Chain Vulnerability Analyzer.

A comprehensive supply-chain security analyzer that works entirely offline
using an embedded CVE database and heuristic detection.  No network calls.

Public API (tested by tests/test_supply_chain_analyzer.py):
    Version            — semantic version with pre-release support
    Component          — one dependency (name, version, ecosystem, ...)
    Severity           — INFO / LOW / MEDIUM / HIGH / CRITICAL
    Finding            — one detected issue
    SupplyChainReport  — end-to-end analysis result
    SupplyChainAnalyzer — class wrapper with async support

    analyze(path)                        → SupplyChainReport
    quick_scan(path)                     → dict
    version_in_range(version, spec)      → bool
    parse_requirements_txt(path)         → List[Component]
    parse_pyproject_toml(path)           → List[Component]
    parse_package_json(path)             → List[Component]
    parse_package_lock(path)             → List[Component]
    parse_go_mod(path)                   → List[Component]
    parse_cargo_toml(path)               → List[Component]
    parse_spdx(license_str)              → List[str]
    to_cyclonedx_sbom(components, name)  → dict
    find_typosquats(name, threshold)      → List[Tuple[str, float]]
    detect_dependency_confusion(comps)   → List[Finding]
    lookup_cves(comps)                   → List[Finding]
    check_license(license_str, context)  → List[Finding]
    check_unmaintained(comps)            → List[Finding]
    compute_risk_score(findings, comps)  → Tuple[float, Severity]
    scan_package_json_scripts(path)      → List[Finding]
    scan_setup_py(path)                  → List[Finding]
"""

from __future__ import annotations

import ast
import asyncio
import base64
import json
import logging
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("elengenix.supply_chain_analyzer")


# ═══════════════════════════════════════════════════════════════════════════
# Severity
# ═══════════════════════════════════════════════════════════════════════════


class Severity:
    """Severity levels (string constants for easy JSON serialisation)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    _ORDER = [INFO, LOW, MEDIUM, HIGH, CRITICAL]

    @classmethod
    def rank(cls, sev: str) -> int:
        try:
            return cls._ORDER.index(sev)
        except ValueError:
            return 0

    @classmethod
    def max(cls, *sevs: str) -> str:
        best = cls.INFO
        for s in sevs:
            if cls.rank(s) > cls.rank(best):
                best = s
        return best


# ═══════════════════════════════════════════════════════════════════════════
# Version
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Version:
    """A semantic version (major.minor.patch with optional pre-release)."""

    major: int = 0
    minor: int = 0
    patch: int = 0
    pre: str = ""

    # -- parsing --------------------------------------------------
    _PARSE_RE = re.compile(
        r"v?(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?" r"(?:-(?P<pre>[^\s]+))?"
    )

    @classmethod
    def parse(cls, raw: str) -> "Version":
        m = cls._PARSE_RE.match(raw.strip())
        if not m:
            raise ValueError(f"Cannot parse version: {raw!r}")
        return cls(
            major=int(m.group("major") or 0),
            minor=int(m.group("minor") or 0),
            patch=int(m.group("patch") or 0),
            pre=m.group("pre") or "",
        )

    # -- comparison ----------------------------------------------
    def _cmp_key(self) -> tuple:
        # Pre-release sorts *before* release (1.0.0-beta < 1.0.0)
        return (self.major, self.minor, self.patch, 0 if self.pre else 1, self.pre)

    def __lt__(self, other: "Version") -> bool:
        return self._cmp_key() < other._cmp_key()

    def __le__(self, other: "Version") -> bool:
        return self._cmp_key() <= other._cmp_key()

    def __gt__(self, other: "Version") -> bool:
        return self._cmp_key() > other._cmp_key()

    def __ge__(self, other: "Version") -> bool:
        return self._cmp_key() >= other._cmp_key()

    def __str__(self) -> str:
        s = f"{self.major}.{self.minor}.{self.patch}"
        if self.pre:
            s += f"-{self.pre}"
        return s


# ═══════════════════════════════════════════════════════════════════════════
# Component & Finding
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class Component:
    """A single dependency / package."""

    name: str
    version: str = ""
    ecosystem: str = "pypi"  # pypi, npm, go, maven, cargo
    direct: bool = True
    source_file: str = ""
    license: str = ""

    def purl(self) -> str:
        return (
            f"pkg:{self.ecosystem}/{self.name}@{self.version}"
            if self.version
            else f"pkg:{self.ecosystem}/{self.name}"
        )


@dataclass
class Finding:
    """One detected supply-chain issue."""

    category: str
    severity: str
    component: str
    version: str
    title: str
    details: str = ""
    cve_id: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# Version range matching
# ═══════════════════════════════════════════════════════════════════════════


def version_in_range(actual: str, spec: str) -> bool:
    """Check whether *actual* version satisfies *spec*.

    Supported operators: ==, >=, <=, >, <, !=, ~=, *, latest.
    """
    spec = spec.strip()
    if not spec or spec == "*":
        return True
    if spec.lower() == "latest":
        return True

    # Comma-separated constraints are ANDed
    if "," in spec:
        return all(version_in_range(actual, s.strip()) for s in spec.split(",") if s.strip())

    # ~= is "compatible release" — same major (or same major.minor for 0.x)
    if spec.startswith("~="):
        target = Version.parse(spec[2:].strip())
        v = Version.parse(actual)
        if v.major != target.major:
            return False
        if target.major == 0 and v.minor != target.minor:
            return False
        return v >= target

    for op in ("==", ">=", "<=", "!=", ">", "<"):
        if spec.startswith(op):
            target = Version.parse(spec[len(op) :].strip())
            v = Version.parse(actual)
            if op == "==":
                return v == target
            if op == "!=":
                return v != target
            if op == ">=":
                return v >= target
            if op == "<=":
                return v <= target
            if op == ">":
                return v > target
            if op == "<":
                return v < target

    # Bare version → exact match
    try:
        return Version.parse(actual) == Version.parse(spec)
    except ValueError:
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Manifest parsers
# ═══════════════════════════════════════════════════════════════════════════


def _strip_version_spec(raw: str) -> str:
    """Return a clean version string from a spec like '>=2.31,<5.0' or '^4.17.21'."""
    raw = raw.strip()
    if not raw:
        return ""
    # Remove range operators and take first constraint
    for sep in (",", "||", " "):
        if sep in raw:
            raw = raw.split(sep)[0].strip()
    raw = raw.lstrip("=<>!~^")
    # Remove prerelease/build qualifiers we don't care about
    return raw


def parse_requirements_txt(path: Union[str, Path]) -> List[Component]:
    """Parse a requirements.txt file."""
    path = Path(path)
    comps: List[Component] = []
    if not path.exists():
        return comps
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip environment markers
        line = line.split(";")[0].strip()
        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*(.*)", line)
        if not m:
            continue
        name = m.group(1)
        spec = m.group(2).strip()
        version = _strip_version_spec(spec)
        comps.append(Component(name=name, version=version, ecosystem="pypi", source_file=path.name))
    return comps


def parse_pyproject_toml(path: Union[str, Path]) -> List[Component]:
    """Parse a pyproject.toml for dependencies (PEP-621 + Poetry)."""
    path = Path(path)
    if not path.exists():
        return []
    content = path.read_text()
    comps: List[Component] = []

    # Try tomllib first (Python 3.11+)
    try:
        import tomllib

        data = tomllib.loads(content)
    except Exception:
        # Fallback: regex extraction
        data = None

    if data:
        # PEP-621 [project] dependencies
        for dep in data.get("project", {}).get("dependencies", []):
            m = re.match(r"^([a-zA-Z0-9_.-]+)\s*(.*)", dep.strip())
            if m:
                name = m.group(1)
                if name.lower() == "python":
                    continue
                comps.append(
                    Component(
                        name=name,
                        version=_strip_version_spec(m.group(2)),
                        ecosystem="pypi",
                        source_file=path.name,
                    )
                )
        # Poetry [tool.poetry.dependencies]
        for name, spec in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
            if name.lower() == "python":
                continue
            version = ""
            if isinstance(spec, str):
                version = _strip_version_spec(spec)
            elif isinstance(spec, dict):
                version = _strip_version_spec(spec.get("version", ""))
            comps.append(
                Component(name=name, version=version, ecosystem="pypi", source_file=path.name)
            )
    else:
        # Regex fallback for [project.dependencies]
        m = re.search(r"\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]", content)
        if m:
            for dm in re.finditer(r'["\']([a-zA-Z0-9_.-]+)[\s]*([^"\']*)["\']', m.group(1)):
                name = dm.group(1)
                if name.lower() == "python":
                    continue
                comps.append(
                    Component(
                        name=name,
                        version=_strip_version_spec(dm.group(2)),
                        ecosystem="pypi",
                        source_file=path.name,
                    )
                )
        # Regex for [tool.poetry.dependencies]
        m2 = re.search(r"\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\[|$)", content)
        if m2:
            for dm in re.finditer(
                r'^([a-zA-Z0-9_.-]+)\s*=\s*["\']?([^"\n\]}]+)', m2.group(1), re.MULTILINE
            ):
                name = dm.group(1)
                if name.lower() == "python":
                    continue
                comps.append(
                    Component(
                        name=name,
                        version=_strip_version_spec(dm.group(2)),
                        ecosystem="pypi",
                        source_file=path.name,
                    )
                )

    return comps


def parse_package_json(path: Union[str, Path]) -> List[Component]:
    """Parse a package.json file."""
    path = Path(path)
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    comps: List[Component] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, spec in data.get(section, {}).items():
            # spec like "^4.17.21" or "git+https://..."
            version = spec if not spec.startswith(("git", "file:", "link:")) else ""
            comps.append(
                Component(
                    name=name,
                    version=_strip_version_spec(version) if version else "",
                    ecosystem="npm",
                    source_file=path.name,
                )
            )
    return comps


def parse_package_lock(path: Union[str, Path]) -> List[Component]:
    """Parse a package-lock.json file (v2/v3 format)."""
    path = Path(path)
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    comps: List[Component] = []
    packages = data.get("packages", {})
    for pkg_path, info in packages.items():
        if not pkg_path or pkg_path == "":
            continue  # root package
        name = pkg_path.replace("node_modules/", "")
        # Only take top-level (no nested scopes)
        if "/" in name and not name.startswith("@"):
            continue
        version = info.get("version", "")
        comps.append(
            Component(
                name=name,
                version=version,
                ecosystem="npm",
                direct=False,
                source_file=path.name,
            )
        )
    return comps


def parse_go_mod(path: Union[str, Path]) -> List[Component]:
    """Parse a go.mod file."""
    path = Path(path)
    if not path.exists():
        return []
    comps: List[Component] = []
    in_require = False
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if line == ")" and in_require:
            in_require = False
            continue
        if in_require or line.startswith("require "):
            parts = line.replace("require ", "").split()
            if len(parts) >= 2:
                comps.append(
                    Component(
                        name=parts[0],
                        version=parts[1],
                        ecosystem="go",
                        source_file=path.name,
                    )
                )
    return comps


def parse_cargo_toml(path: Union[str, Path]) -> List[Component]:
    """Parse a Cargo.toml file."""
    path = Path(path)
    if not path.exists():
        return []
    content = path.read_text()
    comps: List[Component] = []

    try:
        import tomllib

        data = tomllib.loads(content)
        for name, spec in data.get("dependencies", {}).items():
            version = ""
            if isinstance(spec, str):
                version = _strip_version_spec(spec)
            elif isinstance(spec, dict):
                version = _strip_version_spec(spec.get("version", ""))
            comps.append(
                Component(name=name, version=version, ecosystem="cargo", source_file=path.name)
            )
    except Exception:
        # Regex fallback
        in_deps = False
        for line in content.splitlines():
            line = line.strip()
            if line == "[dependencies]":
                in_deps = True
                continue
            if line.startswith("[") and in_deps:
                in_deps = False
                continue
            if in_deps:
                m = re.match(r"^([a-zA-Z0-9_-]+)\s*=\s*(.+)", line)
                if m:
                    name = m.group(1)
                    spec = m.group(2).strip()
                    if spec.startswith('"'):
                        version = _strip_version_spec(spec.strip('"'))
                    else:
                        vm = re.search(r'version\s*=\s*"([^"]+)"', spec)
                        version = vm.group(1) if vm else ""
                    comps.append(
                        Component(
                            name=name, version=version, ecosystem="cargo", source_file=path.name
                        )
                    )
    return comps


# ═══════════════════════════════════════════════════════════════════════════
# SPDX / License parsing
# ═══════════════════════════════════════════════════════════════════════════


def parse_spdx(license_str: str) -> List[str]:
    """Parse an SPDX license expression into a list of license IDs."""
    if not license_str:
        return []
    cleaned = license_str.strip()
    # Remove outer parens
    cleaned = cleaned.strip("()")
    # Split on AND / OR
    parts = re.split(r"\s+(?:AND|OR)\s+", cleaned)
    return [p.strip().strip("()").strip() for p in parts if p.strip()]


# ═══════════════════════════════════════════════════════════════════════════
# SBOM (CycloneDX)
# ═══════════════════════════════════════════════════════════════════════════


def to_cyclonedx_sbom(components: List[Component], project_name: str = "project") -> dict:
    """Convert a list of Components to a CycloneDX 1.5 SBOM dict."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {
                "name": project_name,
                "type": "application",
            },
        },
        "components": [
            {
                "name": c.name,
                "version": c.version,
                "purl": c.purl(),
                "type": "library",
                "ecosystem": c.ecosystem,
            }
            for c in components
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════
# Typosquatting detection
# ═══════════════════════════════════════════════════════════════════════════


# A curated list of popular package names for similarity comparison
_POPULAR_PACKAGES = {
    "pypi": [
        "requests",
        "urllib3",
        "django",
        "flask",
        "fastapi",
        "numpy",
        "pandas",
        "scipy",
        "matplotlib",
        "scikit-learn",
        "tensorflow",
        "torch",
        "pillow",
        "sqlalchemy",
        "celery",
        "redis",
        "pytest",
        "pyyaml",
        "click",
        "rich",
        "python-dateutil",
        "six",
        "setuptools",
        "pip",
        "wheel",
        "boto3",
        "aiohttp",
        "httpx",
        "cryptography",
        "jinja2",
        "werkzeug",
    ],
    "npm": [
        "lodash",
        "express",
        "react",
        "vue",
        "axios",
        "chalk",
        "commander",
        "moment",
        "webpack",
        "typescript",
        "jest",
        "eslint",
        "babel",
        "async",
        "debug",
        "minimist",
        "request",
        "underscore",
        "bluebird",
        "fs-extra",
        "glob",
        "yargs",
        "cheerio",
        "uuid",
    ],
}


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j + 1] + 1, cur[j] + 1, prev[j] + cost))
        prev = cur
    return prev[-1]


def _similarity(a: str, b: str) -> float:
    """Normalised similarity score in [0, 1]."""
    a = a.lower()
    b = b.lower()
    if a == b:
        return 1.0
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 0.0
    dist = _levenshtein(a, b)
    return 1.0 - (dist / max_len)


def find_typosquats(
    name: str, threshold: float = 0.8, ecosystem: str = "pypi"
) -> List[Tuple[str, float]]:
    """Find likely typosquats of *name* among popular packages.

    Returns a list of (popular_name, similarity_score) for packages whose
    similarity to *name* is >= *threshold* (excluding exact matches).
    """
    results: List[Tuple[str, float]] = []
    candidates = _POPULAR_PACKAGES.get(
        ecosystem, _POPULAR_PACKAGES["pypi"] + _POPULAR_PACKAGES["npm"]
    )
    name_lower = name.lower()
    for popular in candidates:
        if popular.lower() == name_lower:
            continue
        score = _similarity(name, popular)
        if score >= threshold:
            results.append((popular, score))
    results.sort(key=lambda x: -x[1])
    return results


# ═══════════════════════════════════════════════════════════════════════════
# Dependency confusion
# ═══════════════════════════════════════════════════════════════════════════


def detect_dependency_confusion(components: List[Component]) -> List[Finding]:
    """Detect potential dependency confusion attacks.

    Flags packages that look private (scoped, company-prefixed, or similar
    to a popular package) and could be hijacked.
    """
    findings: List[Finding] = []
    for comp in components:
        name = comp.name.lower()
        # Scoped npm packages (@company/pkg) or company-prefixed names
        looks_private = (name.startswith("@") and "/" in comp.name) or any(
            name.startswith(prefix)
            for prefix in ("company-", "corp-", "internal-", "private-", "my-")
        )
        # Also flag if name is very similar to a popular package
        typos = find_typosquats(comp.name, threshold=0.85)
        if looks_private or typos:
            popular_str = typos[0][0] if typos else "a popular package"
            findings.append(
                Finding(
                    category="dependency_confusion",
                    severity=Severity.HIGH,
                    component=comp.name,
                    version=comp.version,
                    title=f"Potential dependency confusion: {comp.name}",
                    details=f"Package '{comp.name}' may be private but is similar to popular '{popular_str}'. "
                    f"Ensure it is registered in your private registry to prevent confusion attacks.",
                )
            )
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# CVE lookup (embedded offline database)
# ═══════════════════════════════════════════════════════════════════════════


# A small embedded CVE database for offline lookups.
# Each entry: (ecosystem, package_name_lower, version_range_spec, cve_id, severity, title)
_EMBEDDED_CVES: List[Tuple[str, str, str, str, str, str]] = [
    # Log4j
    (
        "maven",
        "log4j-core",
        "<2.15.0",
        "CVE-2021-44228",
        "critical",
        "Log4Shell — Remote Code Execution via JNDI lookup",
    ),
    (
        "maven",
        "log4j",
        "<2.15.0",
        "CVE-2021-44228",
        "critical",
        "Log4Shell — Remote Code Execution via JNDI lookup",
    ),
    # Pillow
    (
        "pypi",
        "pillow",
        "<9.0.0",
        "CVE-2021-23437",
        "high",
        "Pillow arbitrary code execution via crafted image",
    ),
    # Django
    (
        "pypi",
        "django",
        ">=3.0,<3.2.16",
        "CVE-2024-41991",
        "high",
        "Django denial of service via large Accept-Language header",
    ),
    (
        "pypi",
        "django",
        ">=4.0,<4.2.16",
        "CVE-2024-41991",
        "high",
        "Django denial of service via large Accept-Language header",
    ),
    # Requests
    (
        "pypi",
        "requests",
        "<2.32.0",
        "CVE-2024-35195",
        "medium",
        "Requests cert verification bypass when using proxies",
    ),
    # Axios
    ("npm", "axios", "<1.7.4", "CVE-2024-39338", "high", "Axios SSRF via protocol-relative URL"),
    # Lodash
    (
        "npm",
        "lodash",
        "<4.17.21",
        "CVE-2021-23337",
        "high",
        "Lodash command injection via template",
    ),
    # urllib3
    ("pypi", "urllib3", "<1.26.17", "CVE-2023-43804", "high", "urllib3 cookie leak via redirect"),
    # PyYAML
    (
        "pypi",
        "pyyaml",
        "<6.0",
        "CVE-2020-14343",
        "high",
        "PyYAML arbitrary code execution via yaml.load",
    ),
]


def lookup_cves(components: List[Component]) -> List[Finding]:
    """Look up known CVEs for a list of components (offline, embedded DB)."""
    findings: List[Finding] = []
    for comp in components:
        name_lower = comp.name.lower()
        for eco, pkg, vspec, cve_id, sev, title in _EMBEDDED_CVES:
            if eco != comp.ecosystem or pkg != name_lower:
                continue
            if not comp.version:
                continue
            try:
                if version_in_range(comp.version, vspec):
                    findings.append(
                        Finding(
                            category="known_vulnerability",
                            severity=sev,
                            component=comp.name,
                            version=comp.version,
                            title=title,
                            details=f"{comp.name} {comp.version} is affected by {cve_id}. "
                            f"Upgrade to a version outside {vspec}.",
                            cve_id=cve_id,
                        )
                    )
            except (ValueError, Exception):
                pass
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# License compliance
# ═══════════════════════════════════════════════════════════════════════════


_COPYLEFT_LICENSES = {
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "CDDL-1.0",
    "EPL-1.0",
    "EPL-2.0",
}


def check_license(license_str: str, context: str = "proprietary") -> List[Finding]:
    """Check license compliance.

    Args:
        license_str: SPDX license identifier or expression.
        context: "proprietary" or "open-source" — copyleft is a concern only
            in proprietary contexts.

    Returns:
        List of Findings (empty if compliant).
    """
    findings: List[Finding] = []
    if not license_str or not license_str.strip():
        findings.append(
            Finding(
                category="license",
                severity=Severity.LOW,
                component="*",
                version="*",
                title="No license specified",
                details="The license could not be determined. "
                "Using an unlicensed dependency is legally risky.",
            )
        )
        return findings

    licenses = parse_spdx(license_str)
    if context == "proprietary":
        for lic in licenses:
            if lic.upper() in {l.upper() for l in _COPYLEFT_LICENSES}:
                findings.append(
                    Finding(
                        category="license",
                        severity=Severity.HIGH,
                        component="*",
                        version="*",
                        title=f"Copyleft license: {lic}",
                        details=f"License '{lic}' is a copyleft license. "
                        f"Using it in a proprietary project may require "
                        f"disclosing your source code.",
                    )
                )
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Unmaintained packages
# ═══════════════════════════════════════════════════════════════════════════


_DEPRECATED_PACKAGES = {
    ("npm", "node-uuid"),
    ("npm", "request"),
    ("npm", "bower"),
    ("npm", "gulp-util"),
    ("npm", "phantomjs"),
    ("pypi", "distutils"),
    ("pypi", "pathlib2"),
    ("pypi", "ipaddress"),
}


def check_unmaintained(components: List[Component]) -> List[Finding]:
    """Detect known unmaintained / deprecated packages."""
    findings: List[Finding] = []
    for comp in components:
        key = (comp.ecosystem, comp.name.lower())
        if key in _DEPRECATED_PACKAGES:
            findings.append(
                Finding(
                    category="unmaintained",
                    severity=Severity.MEDIUM,
                    component=comp.name,
                    version=comp.version,
                    title=f"Unmaintained package: {comp.name}",
                    details=f"{comp.name} is deprecated or no longer maintained. "
                    f"Replace with a supported alternative.",
                )
            )
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Malicious install hooks
# ═══════════════════════════════════════════════════════════════════════════


_SUSPICIOUS_SCRIPT_PATTERNS = [
    (re.compile(r"base64", re.IGNORECASE), "Base64 encoded payload in install hook"),
    (re.compile(r"child_process"), "child_process usage in install hook"),
    (re.compile(r"require\s*\(.*child_process"), "child_process require in install hook"),
    (re.compile(r"curl\s+http|wget\s+http"), "Network fetch in install hook"),
    (re.compile(r"eval\s*\("), "eval() in install hook"),
    (re.compile(r"\.exec\s*\("), "exec() in install hook"),
    (re.compile(r"powershell", re.IGNORECASE), "PowerShell invocation in install hook"),
    (re.compile(r"node\s+-e"), "node -e eval in install hook"),
]

_B64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


def scan_package_json_scripts(path: Union[str, Path]) -> List[Finding]:
    """Scan package.json scripts for malicious install hooks."""
    path = Path(path)
    if not path.exists():
        return []
    findings: List[Finding] = []
    data = json.loads(path.read_text())
    scripts = data.get("scripts", {})
    for hook_name in ("preinstall", "postinstall", "prepublish", "prepare"):
        script = scripts.get(hook_name, "")
        if not script:
            continue
        for pattern, desc in _SUSPICIOUS_SCRIPT_PATTERNS:
            if pattern.search(script):
                findings.append(
                    Finding(
                        category="malicious_install_hook",
                        severity=Severity.HIGH,
                        component=str(path.name),
                        version="*",
                        title=f"Suspicious {hook_name} hook: {desc}",
                        details=f"Script content: {script[:200]}",
                    )
                )
                break
        # Long base64 strings are a strong signal
        if _B64_RE.search(script):
            findings.append(
                Finding(
                    category="malicious_install_hook",
                    severity=Severity.HIGH,
                    component=str(path.name),
                    version="*",
                    title=f"Base64 payload in {hook_name} hook",
                    details=f"Long base64 string detected in install script.",
                )
            )
    return findings


def scan_setup_py(path: Union[str, Path]) -> List[Finding]:
    """Scan setup.py for malicious code in install hooks."""
    path = Path(path)
    if not path.exists():
        return []
    findings: List[Finding] = []
    content = path.read_text()
    try:
        tree = ast.parse(content)
    except SyntaxError:
        # Can't parse — flag as suspicious if it contains dangerous calls
        if re.search(r"os\.system|subprocess\.(call|run|Popen)", content):
            findings.append(
                Finding(
                    category="malicious_install_hook",
                    severity=Severity.HIGH,
                    component=str(path.name),
                    version="*",
                    title="Dangerous system call in setup.py",
                    details="setup.py contains os.system or subprocess calls at top level.",
                )
            )
        return findings

    for node in ast.walk(tree):
        # Look for os.system(...) or subprocess.(call|run|Popen)(...) at module level
        if isinstance(node, ast.Call):
            func = node.func
            func_name = ""
            if isinstance(func, ast.Attribute):
                func_name = func.attr
            elif isinstance(func, ast.Name):
                func_name = func.id
            if func_name in ("system", "call", "run", "Popen", "exec", "eval"):
                findings.append(
                    Finding(
                        category="malicious_install_hook",
                        severity=Severity.HIGH,
                        component=str(path.name),
                        version="*",
                        title=f"Dangerous call: {func_name}() in setup.py",
                        details=f"setup.py executes {func_name}() which can run arbitrary code.",
                    )
                )
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Risk scoring
# ═══════════════════════════════════════════════════════════════════════════


_SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 10,
    Severity.HIGH: 12,
    Severity.CRITICAL: 25,
}

_CATEGORY_BONUSES = {
    "malicious_install_hook": 15,
    "dependency_confusion": 10,
}


def compute_risk_score(findings: List[Finding], components: List[Component]) -> Tuple[float, str]:
    """Compute an overall risk score in [0, 100] and a Severity level."""
    score = 0.0
    max_sev = Severity.INFO
    for f in findings:
        score += _SEVERITY_WEIGHTS.get(f.severity, 0)
        score += _CATEGORY_BONUSES.get(f.category, 0)
        if Severity.rank(f.severity) > Severity.rank(max_sev):
            max_sev = f.severity
    score = min(score, 100.0)

    if score >= 50 or max_sev == Severity.CRITICAL:
        level = Severity.CRITICAL
    elif score >= 25 or max_sev == Severity.HIGH:
        level = Severity.HIGH
    elif score >= 10 or max_sev == Severity.MEDIUM:
        level = Severity.MEDIUM
    elif score > 0 or max_sev == Severity.LOW:
        level = Severity.LOW
    else:
        level = Severity.INFO
    return score, level


# ═══════════════════════════════════════════════════════════════════════════
# SupplyChainReport
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class SupplyChainReport:
    """Full analysis report."""

    components: List[Component] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = Severity.INFO
    sbom: Dict[str, Any] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.by_severity:
            self.by_severity = {
                Severity.INFO: 0,
                Severity.LOW: 0,
                Severity.MEDIUM: 0,
                Severity.HIGH: 0,
                Severity.CRITICAL: 0,
            }
            for f in self.findings:
                self.by_severity[f.severity] = self.by_severity.get(f.severity, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "components": [
                {"name": c.name, "version": c.version, "ecosystem": c.ecosystem}
                for c in self.components
            ],
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "component": f.component,
                    "cve_id": f.cve_id,
                    "title": f.title,
                }
                for f in self.findings
            ],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "by_severity": self.by_severity,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Analyzer class & convenience functions
# ═══════════════════════════════════════════════════════════════════════════


class SupplyChainAnalyzer:
    """Supply chain vulnerability analyzer with sync and async support."""

    def __init__(self, **kwargs: Any) -> None:
        self.check_vulnerabilities = kwargs.get("check_vulnerabilities", True)
        self.check_licenses = kwargs.get("check_licenses", True)

    def analyze(self, directory: Union[str, Path]) -> SupplyChainReport:
        """Analyze a project directory end-to-end."""
        return _do_analyze(Path(directory))

    async def aanalyze(self, directory: Union[str, Path]) -> SupplyChainReport:
        """Async wrapper for analyze()."""
        return await asyncio.get_event_loop().run_in_executor(None, _do_analyze, Path(directory))

    # Back-compat with old API
    def analyze_directory(self, directory: str) -> SupplyChainReport:
        return self.analyze(Path(directory))

    def analyze_package_list(
        self,
        packages: List[Dict[str, str]],
        ecosystem: str = "pypi",
    ) -> "SupplyChainResult":
        """Analyze a list of packages (backward-compatible API).

        Returns an old-style SupplyChainResult with ``dependencies`` and
        ``total_dependencies`` attributes.
        """
        components: List[Component] = []
        for pkg in packages:
            components.append(
                Component(
                    name=pkg.get("name", ""),
                    version=pkg.get("version", ""),
                    ecosystem=ecosystem,
                )
            )
        findings = lookup_cves(components)
        findings.extend(detect_dependency_confusion(components))
        findings.extend(check_unmaintained(components))
        return SupplyChainResult(
            target=f"{ecosystem} packages",
            dependencies=components,
            total_dependencies=len(components),
        )


def _do_analyze(directory: Path) -> SupplyChainReport:
    """Internal: perform full analysis on a directory."""
    components: List[Component] = []
    findings: List[Finding] = []

    # Parse all manifest files we can find
    req_file = directory / "requirements.txt"
    if req_file.exists():
        components.extend(parse_requirements_txt(req_file))

    pyproject = directory / "pyproject.toml"
    if pyproject.exists():
        components.extend(parse_pyproject_toml(pyproject))

    pkg_json = directory / "package.json"
    if pkg_json.exists():
        components.extend(parse_package_json(pkg_json))
        findings.extend(scan_package_json_scripts(pkg_json))

    pkg_lock = directory / "package-lock.json"
    if pkg_lock.exists():
        components.extend(parse_package_lock(pkg_lock))

    go_mod = directory / "go.mod"
    if go_mod.exists():
        components.extend(parse_go_mod(go_mod))

    cargo = directory / "Cargo.toml"
    if cargo.exists():
        components.extend(parse_cargo_toml(cargo))

    setup_py = directory / "setup.py"
    if setup_py.exists():
        findings.extend(scan_setup_py(setup_py))

    # Deduplicate components (same name+ecosystem, keep first)
    seen = set()
    deduped: List[Component] = []
    for c in components:
        key = (c.name.lower(), c.ecosystem)
        if key not in seen:
            seen.add(key)
            deduped.append(c)
    components = deduped

    # Run all detectors
    findings.extend(lookup_cves(components))
    findings.extend(detect_dependency_confusion(components))
    findings.extend(check_unmaintained(components))

    # License check (basic — if we can detect a license)
    # For now, we don't have license metadata from parsers, so skip unless
    # the component has one
    for c in components:
        if c.license:
            findings.extend(check_license(c.license, context="proprietary"))

    # Compute risk
    score, level = compute_risk_score(findings, components)

    # Build SBOM
    project_name = directory.name or "project"
    sbom = to_cyclonedx_sbom(components, project_name)

    return SupplyChainReport(
        components=components,
        findings=findings,
        risk_score=score,
        risk_level=level,
        sbom=sbom,
    )


def analyze(directory: Union[str, Path]) -> SupplyChainReport:
    """Convenience function: analyze a project directory."""
    return _do_analyze(Path(directory))


def quick_scan(directory: Union[str, Path]) -> Dict[str, Any]:
    """Quick scan returning a JSON-serialisable summary."""
    report = analyze(directory)
    critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
    high = [f for f in report.findings if f.severity == Severity.HIGH]
    return {
        "components": len(report.components),
        "findings_total": len(report.findings),
        "critical": [
            {"component": f.component, "cve": f.cve_id, "title": f.title} for f in critical
        ],
        "high": [{"component": f.component, "cve": f.cve_id, "title": f.title} for f in high],
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Backward compatibility aliases
# ═══════════════════════════════════════════════════════════════════════════


# Backward compatibility aliases
# Keep the old API working for existing callers
Dependency = Component  # type: ignore[misc,assignment]


@dataclass
class SupplyChainResult:
    """Legacy result type for analyze_package_list (backward compat)."""

    target: str = ""
    dependencies: List[Component] = field(default_factory=list)
    total_dependencies: int = 0
    private_packages: List[str] = field(default_factory=list)
    unpinned_versions: List[str] = field(default_factory=list)
    suspicious_packages: List[str] = field(default_factory=list)
    typosquatting_detected: List[Tuple[str, str]] = field(default_factory=list)
    total_tests: int = 0
    duration: float = 0.0

    @property
    def is_vulnerable(self) -> bool:
        return bool(
            self.suspicious_packages or self.typosquatting_detected or self.unpinned_versions
        )

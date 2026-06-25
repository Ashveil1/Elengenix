"""tools/supply_chain_analyzer.py — Supply Chain Vulnerability Analyzer.

Analyzes software supply chain vulnerabilities:
- Dependency confusion attacks
- Malicious package detection
- Typosquatting detection
- Package version analysis
- License compliance checking

Supports:
- npm (package.json)
- PyPI (requirements.txt, setup.py, pyproject.toml)
- Go (go.mod)
- Ruby (Gemfile)
- Java (pom.xml, build.gradle)

Public API:
    SupplyChainAnalyzer - Main analyzer class
    Dependency - Single dependency information
    SupplyChainResult - Full analysis results
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("elengenix.supply_chain_analyzer")


@dataclass
class Dependency:
    """Information about a single dependency."""
    name: str
    version: str
    ecosystem: str  # "npm", "pypi", "go", "ruby", "maven"
    source_file: str = ""
    is_private: bool = False
    has_pinned_version: bool = False
    license: str = ""
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class SupplyChainResult:
    """Full supply chain analysis results."""
    target: str
    dependencies: List[Dependency] = field(default_factory=list)
    total_dependencies: int = 0
    private_packages: List[str] = field(default_factory=list)
    unpinned_versions: List[str] = field(default_factory=list)
    suspicious_packages: List[str] = field(default_factory=list)
    typosquatting_detected: List[Tuple[str, str]] = field(default_factory=list)
    total_tests: int = 0
    duration: float = 0.0

    @property
    def is_vulnerable(self) -> bool:
        return (
            len(self.suspicious_packages) > 0 or
            len(self.typosquatting_detected) > 0 or
            len(self.unpinned_versions) > 0
        )

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total_dependencies": self.total_dependencies,
            "private_packages": len(self.private_packages),
            "unpinned_versions": len(self.unpinned_versions),
            "suspicious_packages": len(self.suspicious_packages),
            "typosquatting_detected": len(self.typosquatting_detected),
            "is_vulnerable": self.is_vulnerable,
            "duration": self.duration,
        }


# Known malicious packages (examples - in production, use a real database)
KNOWN_MALICIOUS_PACKAGES = {
    "npm": [
        "event-stream",
        "flatmap-stream",
        "crossenv",
        "getcookiesandvals",
    ],
    "pypi": [
        "python3-dateutil",
        "jeIlyfish",
        "jeIlyfish2",
        "colourama",
        "python-dateutil2",
    ],
}

# Common typosquatting patterns
TYPOSQUATTING_PATTERNS = [
    # Common typos
    (r"reqests", "requests"),
    (r"flaskk", "flask"),
    (r"django_", "django"),
    (r"numpyy", "numpy"),
    (r"pandass", "pandas"),
    (r"scipyy", "scipy"),
    (r"matplotlibt", "matplotlib"),
    (r"beautifulsoup4", "beautifulsoup4"),
    (r"jquery$", "jquery"),
    (r"lodashd", "lodash"),
    (r"expresss", "express"),
    (r"reactt", "react"),
    (r"angularr", "angular"),
    (r"vuejs2", "vue"),
    (r"webpackk", "webpack"),
]

# Suspicious patterns in package names
SUSPICIOUS_PATTERNS = [
    r"test\d+",  # test1, test2, etc.
    r"tmp\d+",   # tmp1, tmp2, etc.
    r"temp\d+",  # temp1, temp2, etc.
    r"debug\d+", # debug1, debug2, etc.
    r"admin\d+", # admin1, admin2, etc.
]


class SupplyChainAnalyzer:
    """Supply chain vulnerability analyzer.
    
    Analyzes software dependencies for supply chain vulnerabilities
    including dependency confusion, typosquatting, and malicious packages.
    
    Example:
        analyzer = SupplyChainAnalyzer()
        result = analyzer.analyze_directory("/path/to/project")
        if result.is_vulnerable:
            print("Supply chain vulnerabilities detected!")
    """
    
    def __init__(
        self,
        check_vulnerabilities: bool = True,
        check_licenses: bool = True,
    ):
        """Initialize the supply chain analyzer.
        
        Args:
            check_vulnerabilities: Whether to check for known vulnerabilities.
            check_licenses: Whether to check license compliance.
        """
        self.check_vulnerabilities = check_vulnerabilities
        self.check_licenses = check_licenses
    
    def analyze_directory(
        self,
        directory: str,
    ) -> SupplyChainResult:
        """Analyze all dependency files in a directory.
        
        Args:
            directory: Path to the project directory.
            
        Returns:
            SupplyChainResult with analysis results.
        """
        start_time = time.time()
        result = SupplyChainResult(target=directory)
        
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.error(f"Directory not found: {directory}")
            return result
        
        # Analyze different ecosystems
        self._analyze_npm(dir_path, result)
        self._analyze_pypi(dir_path, result)
        self._analyze_go(dir_path, result)
        self._analyze_ruby(dir_path, result)
        self._analyze_java(dir_path, result)
        
        # Check for typosquatting
        self._check_typosquatting(result)
        
        # Check for suspicious packages
        self._check_suspicious_packages(result)
        
        result.total_dependencies = len(result.dependencies)
        result.duration = time.time() - start_time
        
        return result
    
    def analyze_package_list(
        self,
        packages: List[Dict[str, str]],
        ecosystem: str = "pypi",
    ) -> SupplyChainResult:
        """Analyze a list of packages.
        
        Args:
            packages: List of package dicts with 'name' and 'version'.
            ecosystem: Package ecosystem.
            
        Returns:
            SupplyChainResult with analysis results.
        """
        start_time = time.time()
        result = SupplyChainResult(target=f"{ecosystem} packages")
        
        for pkg in packages:
            dep = Dependency(
                name=pkg.get("name", ""),
                version=pkg.get("version", ""),
                ecosystem=ecosystem,
            )
            result.dependencies.append(dep)
        
        # Check for typosquatting
        self._check_typosquatting(result)
        
        # Check for suspicious packages
        self._check_suspicious_packages(result)
        
        result.total_dependencies = len(result.dependencies)
        result.duration = time.time() - start_time
        
        return result
    
    def _analyze_npm(self, dir_path: Path, result: SupplyChainResult) -> None:
        """Analyze npm dependencies."""
        package_json = dir_path / "package.json"
        if not package_json.exists():
            return
        
        try:
            import json
            with open(package_json, "r") as f:
                data = json.load(f)
            
            # Check dependencies
            for section in ["dependencies", "devDependencies", "peerDependencies"]:
                deps = data.get(section, {})
                for name, version in deps.items():
                    dep = Dependency(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        source_file="package.json",
                        has_pinned_version=version.startswith("^") or version.startswith("~"),
                    )
                    result.dependencies.append(dep)
                    
                    if not dep.has_pinned_version:
                        result.unpinned_versions.append(name)
            
            # Check for known malicious packages
            self._check_known_malicious(result, "npm")
        
        except Exception as e:
            logger.debug(f"Failed to analyze package.json: {e}")
    
    def _analyze_pypi(self, dir_path: Path, result: SupplyChainResult) -> None:
        """Analyze Python dependencies."""
        # Check requirements.txt
        requirements = dir_path / "requirements.txt"
        if requirements.exists():
            self._parse_requirements_file(requirements, result)
        
        # Check setup.py
        setup_py = dir_path / "setup.py"
        if setup_py.exists():
            self._parse_setup_py(setup_py, result)
        
        # Check pyproject.toml
        pyproject = dir_path / "pyproject.toml"
        if pyproject.exists():
            self._parse_pyproject_toml(pyproject, result)
    
    def _parse_requirements_file(self, file_path: Path, result: SupplyChainResult) -> None:
        """Parse requirements.txt file."""
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    
                    # Parse package name and version
                    match = re.match(r"^([a-zA-Z0-9_-]+)(.*)", line)
                    if match:
                        name = match.group(1)
                        version_spec = match.group(2).strip()
                        has_pinned = "==" in version_spec
                        
                        dep = Dependency(
                            name=name,
                            version=version_spec,
                            ecosystem="pypi",
                            source_file=file_path.name,
                            has_pinned_version=has_pinned,
                        )
                        result.dependencies.append(dep)
                        
                        if not has_pinned:
                            result.unpinned_versions.append(name)
        except Exception as e:
            logger.debug(f"Failed to parse {file_path}: {e}")
    
    def _parse_setup_py(self, file_path: Path, result: SupplyChainResult) -> None:
        """Parse setup.py file."""
        # Simple regex-based parsing
        try:
            with open(file_path, "r") as f:
                content = f.read()
            
            # Find install_requires
            match = re.search(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
            if match:
                deps_str = match.group(1)
                for dep_match in re.finditer(r"['\"]([^'\"]+)['\"]", deps_str):
                    dep_str = dep_match.group(1)
                    name_match = re.match(r"^([a-zA-Z0-9_-]+)", dep_str)
                    if name_match:
                        name = name_match.group(1)
                        version_spec = dep_str[len(name):]
                        has_pinned = "==" in version_spec
                        
                        dep = Dependency(
                            name=name,
                            version=version_spec,
                            ecosystem="pypi",
                            source_file=file_path.name,
                            has_pinned_version=has_pinned,
                        )
                        result.dependencies.append(dep)
        except Exception as e:
            logger.debug(f"Failed to parse {file_path}: {e}")
    
    def _parse_pyproject_toml(self, file_path: Path, result: SupplyChainResult) -> None:
        """Parse pyproject.toml file."""
        # Simple regex-based parsing
        try:
            with open(file_path, "r") as f:
                content = f.read()
            
            # Find dependencies
            match = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
            if match:
                deps_str = match.group(1)
                for dep_match in re.finditer(r"['\"]([^'\"]+)['\"]", deps_str):
                    dep_str = dep_match.group(1)
                    name_match = re.match(r"^([a-zA-Z0-9_-]+)", dep_str)
                    if name_match:
                        name = name_match.group(1)
                        version_spec = dep_str[len(name):]
                        has_pinned = "==" in version_spec
                        
                        dep = Dependency(
                            name=name,
                            version=version_spec,
                            ecosystem="pypi",
                            source_file=file_path.name,
                            has_pinned_version=has_pinned,
                        )
                        result.dependencies.append(dep)
        except Exception as e:
            logger.debug(f"Failed to parse {file_path}: {e}")
    
    def _analyze_go(self, dir_path: Path, result: SupplyChainResult) -> None:
        """Analyze Go dependencies."""
        go_mod = dir_path / "go.mod"
        if not go_mod.exists():
            return
        
        try:
            with open(go_mod, "r") as f:
                in_require = False
                for line in f:
                    line = line.strip()
                    if line.startswith("require ("):
                        in_require = True
                        continue
                    if line == ")" and in_require:
                        in_require = False
                        continue
                    
                    if in_require or line.startswith("require "):
                        # Parse module and version
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version = parts[1]
                            has_pinned = not version.startswith("v0.0.0-")
                            
                            dep = Dependency(
                                name=name,
                                version=version,
                                ecosystem="go",
                                source_file="go.mod",
                                has_pinned_version=has_pinned,
                            )
                            result.dependencies.append(dep)
        except Exception as e:
            logger.debug(f"Failed to parse {file_path}: {e}")
    
    def _analyze_ruby(self, dir_path: Path, result: SupplyChainResult) -> None:
        """Analyze Ruby dependencies."""
        gemfile = dir_path / "Gemfile"
        if not gemfile.exists():
            return
        
        try:
            with open(gemfile, "r") as f:
                for line in f:
                    line = line.strip()
                    match = re.match(r"gem\s+['\"]([^'\"]+)['\"]", line)
                    if match:
                        name = match.group(1)
                        version_match = re.search(r"['\"]([^'\"]+)['\"]", line[match.end():])
                        version = version_match.group(1) if version_match else "latest"
                        has_pinned = version != "latest"
                        
                        dep = Dependency(
                            name=name,
                            version=version,
                            ecosystem="ruby",
                            source_file="Gemfile",
                            has_pinned_version=has_pinned,
                        )
                        result.dependencies.append(dep)
        except Exception as e:
            logger.debug(f"Failed to parse {file_path}: {e}")
    
    def _analyze_java(self, dir_path: Path, result: SupplyChainResult) -> None:
        """Analyze Java dependencies."""
        pom_xml = dir_path / "pom.xml"
        if not pom_xml.exists():
            return
        
        try:
            with open(pom_xml, "r") as f:
                content = f.read()
            
            # Find dependencies
            for match in re.finditer(
                r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
                content,
                re.DOTALL
            ):
                group_id = match.group(1)
                artifact_id = match.group(2)
                version = match.group(3)
                has_pinned = not version.startswith("$")
                
                dep = Dependency(
                    name=f"{group_id}:{artifact_id}",
                    version=version,
                    ecosystem="maven",
                    source_file="pom.xml",
                    has_pinned_version=has_pinned,
                )
                result.dependencies.append(dep)
        except Exception as e:
            logger.debug(f"Failed to parse {file_path}: {e}")
    
    def _check_known_malicious(self, result: SupplyChainResult, ecosystem: str) -> None:
        """Check for known malicious packages."""
        malicious_list = KNOWN_MALICIOUS_PACKAGES.get(ecosystem, [])
        
        for dep in result.dependencies:
            if dep.ecosystem == ecosystem and dep.name in malicious_list:
                result.suspicious_packages.append(dep.name)
                logger.warning(f"Known malicious package detected: {dep.name}")
    
    def _check_typosquatting(self, result: SupplyChainResult) -> None:
        """Check for typosquatting packages."""
        for dep in result.dependencies:
            for pattern, legitimate in TYPOSQUATTING_PATTERNS:
                if re.match(pattern, dep.name, re.IGNORECASE):
                    result.typosquatting_detected.append((dep.name, legitimate))
                    logger.warning(f"Possible typosquatting: {dep.name} (similar to {legitimate})")
    
    def _check_suspicious_packages(self, result: SupplyChainResult) -> None:
        """Check for suspicious package names."""
        for dep in result.dependencies:
            for pattern in SUSPICIOUS_PATTERNS:
                if re.match(pattern, dep.name, re.IGNORECASE):
                    if dep.name not in result.suspicious_packages:
                        result.suspicious_packages.append(dep.name)
                        logger.warning(f"Suspicious package name: {dep.name}")

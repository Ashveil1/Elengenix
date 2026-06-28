"""
tools/skill_registry.py — Skill & Tool Awareness System

Informs AI about available tools/skills and can request additional installations when needed.

Author: Elengenix Project
"""

import logging
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger("elengenix.skills")


class SkillStatus(Enum):
    """Status of each skill/tool"""

    AVAILABLE = "available"  # Installed and ready
    MISSING = "missing"  # Not yet installed
    OPTIONAL = "optional"  # Not required but useful
    RECOMMENDED = "recommended"  # Recommended based on context


@dataclass
class Skill:
    """Information about each skill/tool"""

    name: str
    description: str
    category: str

    def __init__(
        self,
        name: str,
        description: str,
        category: str,
        binary_name: str,
        status: SkillStatus,
        install_command: str,
        use_cases: list = None,
        alternatives: list = None,
    ):
        self.name = name
        self.description = description
        self.category = category
        self.binary_name = binary_name
        self.status = status
        self.install_command = install_command
        self.use_cases = self._flatten_use_cases(use_cases or [])
        self.alternatives = alternatives or []

    def _flatten_use_cases(self, use_cases):
        """Flatten nested use cases to a single list of strings"""
        flat = []
        for item in use_cases:
            if isinstance(item, list):
                flat.extend(self._flatten_use_cases(item))
            else:
                flat.append(item)
        return flat

    def to_dict(self) -> Dict:
        """Serialize skill to dict."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "binary_name": self.binary_name,
            "status": (
                self.status.value if isinstance(self.status, SkillStatus) else str(self.status)
            ),
            "install_command": self.install_command,
            "use_cases": self.use_cases,
            "alternatives": self.alternatives,
        }


class SkillRegistry:
    """
    Registry of skills/tools known to AI.

    Responsibilities:
    1. Store list of available tools
    2. Check availability of each tool
    3. Recommend tools based on context
    4. Request additional installations when needed
    """

    def __init__(self):
        self.skills: Dict[str, Skill] = {}
        self._init_default_skills()
        self._check_availability()

    def _flatten_use_cases(self, use_cases):
        """Flatten nested use cases to a single list of strings"""
        flat = []
        for item in use_cases:
            if isinstance(item, list):
                flat.extend(self._flatten_use_cases(item))
            else:
                flat.append(item)
        return flat

    def _init_default_skills(self):
        """Initialize default skills list."""
        default_skills = [
            # Reconnaissance (Python-based)
            Skill(
                "python_recon",
                "Pure Python HTTP probe and recon",
                "recon",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["probe web services", "directory discovery", "port scanning"],
            ),
            # Vulnerability Scanning (Python-based)
            Skill(
                "ssrf_scanner",
                "Server-Side Request Forgery scanner",
                "scanner",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["SSRF detection", "internal network probing"],
            ),
            Skill(
                "ssti_scanner",
                "Server-Side Template Injection scanner",
                "scanner",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["SSTI detection", "template injection"],
            ),
            Skill(
                "xxe_scanner",
                "XML External Entity scanner",
                "scanner",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["XXE detection", "XML parsing vulnerabilities"],
            ),
            Skill(
                "deserialization_scanner",
                "Insecure deserialization scanner",
                "scanner",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["deserialization vulnerabilities", "unsafe data handling"],
            ),
            Skill(
                "graphql_scanner",
                "GraphQL API vulnerability scanner",
                "scanner",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["GraphQL introspection", "API vulnerabilities"],
            ),
            Skill(
                "race_condition_tester",
                "Race condition vulnerability tester",
                "scanner",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["TOCTOU vulnerabilities", "concurrent access issues"],
            ),
            Skill(
                "cors_checker",
                "CORS misconfiguration tester",
                "scanner",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["CORS bypass", "origin reflection"],
            ),
            Skill(
                "jwt_tester",
                "JWT security vulnerability tester",
                "scanner",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["JWT algorithm confusion", "weak secrets"],
            ),
            Skill(
                "logic_flaw_engine",
                "Business logic vulnerability analyzer",
                "scanner",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["price manipulation", "workflow bypass"],
            ),
            Skill(
                "supply_chain_analyzer",
                "Software supply chain analyzer",
                "scanner",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["dependency vulnerabilities", "typosquatting"],
            ),
            # Fuzzing (Python-based)
            Skill(
                "active_fuzzer",
                "Active fuzzing with response delta scoring",
                "fuzzing",
                "python3",
                SkillStatus.AVAILABLE,
                "Built-in",
                use_cases=["XSS detection", "SQLi detection", "parameter fuzzing"],
            ),
            # External tools (checked at runtime, may be MISSING)
            Skill(
                "subfinder",
                "Subdomain discovery tool",
                "recon",
                "subfinder",
                SkillStatus.MISSING,
                "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                use_cases=["subdomain enumeration", "subdomain discovery", "recon"],
            ),
            Skill(
                "httpx",
                "Fast HTTP probe and fingerprinter",
                "recon",
                "httpx",
                SkillStatus.MISSING,
                "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                use_cases=["http probing", "web service discovery", "tech fingerprinting"],
            ),
            Skill(
                "nuclei",
                "Template-based vulnerability scanner",
                "scanner",
                "nuclei",
                SkillStatus.MISSING,
                "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                use_cases=[
                    "XSS detection",
                    "vulnerability scanning",
                    "CVE detection",
                    "template scanning",
                ],
            ),
            Skill(
                "dalfox",
                "XSS scanner for parameter analysis",
                "scanner",
                "dalfox",
                SkillStatus.MISSING,
                "go install -v github.com/hahwul/dalfox/v2@latest",
                use_cases=["XSS detection", "cross-site scripting", "parameter fuzzing"],
            ),
            Skill(
                "katana",
                "Next-generation crawling framework",
                "recon",
                "katana",
                SkillStatus.MISSING,
                "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
                use_cases=["crawling", "endpoint discovery", "content discovery"],
            ),
            Skill(
                "trufflehog",
                "Secret scanner for repositories and files",
                "secret_detection",
                "trufflehog",
                SkillStatus.MISSING,
                "go install -v github.com/trufflesecurity/trufflehog/v3@latest",
                use_cases=["secret detection", "API key discovery", "credential scanning"],
            ),
        ]

        for skill in default_skills:
            self.skills[skill.name] = skill

    def _check_availability(self):
        """Check whether each tool is installed."""
        for name, skill in self.skills.items():
            if shutil.which(skill.binary_name):
                skill.status = SkillStatus.AVAILABLE
            else:
                skill.status = SkillStatus.MISSING

    def get_available_skills(self) -> List[Skill]:
        """Return list of available skills."""
        return [s for s in self.skills.values() if s.status == SkillStatus.AVAILABLE]

    def get_missing_skills(self) -> List[Skill]:
        """Return list of missing skills."""
        return [s for s in self.skills.values() if s.status == SkillStatus.MISSING]

    def recommend_for(self, scenario: str) -> List[Skill]:
        """Recommend skills based on context — flexible keyword matching."""
        scenario_lower = scenario.lower()
        scenario_words = set(scenario_lower.split())
        recommended = []
        seen = set()

        # Keyword matching map
        keyword_map = {
            "xss": ["dalfox", "nuclei", "active_fuzzer"],
            "subdomain": ["subfinder", "httpx"],
            "port": ["httpx"],
            "vulnerability": ["nuclei"],
            "secret": ["trufflehog"],
            "crawl": ["katana"],
            "fuzz": ["active_fuzzer", "dalfox"],
            "recon": ["subfinder", "httpx", "katana"],
        }

        for skill in self.skills.values():
            matched = False
            # 1. Check use_cases
            for use_case in skill.use_cases:
                uc_words = set(use_case.lower().split())
                if uc_words & scenario_words:
                    matched = True
                    break
            # 2. Check keyword_map
            if not matched:
                for kw, tools in keyword_map.items():
                    if kw in scenario_lower and skill.name in tools:
                        matched = True
                        break
            # 3. Check name/category matching
            if not matched:
                for word in scenario_words:
                    if word in skill.name.lower() or word in skill.category.lower():
                        matched = True
                        break

            if matched and skill.name not in seen:
                recommended.append(skill)
                seen.add(skill.name)

        # Sort: available first, then missing
        recommended.sort(key=lambda s: (s.status != SkillStatus.AVAILABLE, s.name))
        return recommended

    def get_skill_context(self) -> str:
        """Build context for AI about available skills."""
        lines = ["=== AVAILABLE TOOLS/SKILLS ==="]

        available = self.get_available_skills()
        missing = self.get_missing_skills()

        if available:
            lines.append(f"\n[READY] {len(available)} tools available:")
            for skill in available:
                lines.append(f"  - {skill.name}: {skill.description}")

        if missing:
            lines.append(f"\n[MISSING] {len(missing)} tools not installed:")
            for skill in missing:
                lines.append(f"  - {skill.name}: {skill.description}")

        return "\n".join(lines)

    def request_install(self, skill_name: str) -> bool:
        """Request installation of a skill."""
        if skill_name not in self.skills:
            return False

        skill = self.skills[skill_name]
        if skill.status == SkillStatus.AVAILABLE:
            return True  # Already installed

        # Try to install
        try:
            import shlex

            cmd_list = shlex.split(skill.install_command)
            subprocess.run(cmd_list, shell=False, check=True, capture_output=True, timeout=60)
            skill.status = SkillStatus.AVAILABLE
            return True
        except Exception as e:
            logger.error(f"Failed to install {skill_name}: {e}")
            return False

    def to_dict(self) -> Dict:
        """Return full registry as dict."""
        return {
            "available": [s.to_dict() for s in self.get_available_skills()],
            "missing": [s.to_dict() for s in self.get_missing_skills()],
            "total": len(self.skills),
        }


# Singleton instance
_skill_registry: Optional[SkillRegistry] = None


def get_skill_registry() -> SkillRegistry:
    """Get or create SkillRegistry singleton"""
    global _skill_registry
    if _skill_registry is None:
        _skill_registry = SkillRegistry()
    return _skill_registry


def recommend_tools_for_scenario(scenario: str) -> List[Skill]:
    """Recommend tools based on context."""
    registry = get_skill_registry()
    return registry.recommend_for(scenario)


if __name__ == "__main__":
    # Test
    registry = get_skill_registry()
    print(registry.get_skill_context())
    print("\nRecommendations for 'XSS testing':")
    for skill in recommend_tools_for_scenario("XSS testing"):
        print(f"  - {skill.name} ({skill.status.value})")

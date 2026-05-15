"""
tools/skill_registry.py — Skill & Tool Awareness System (v99999 (god nine is the best))

ให้ AI รู้ว่ามี tools/skills อะไรบ้างที่พร้อมใช้
และสามารถขอติดตั้งเพิ่มได้เมื่อจำเป็น

Author: Elengenix Project
"""

import os
import subprocess
import shutil
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from enum import Enum
from pathlib import Path

logger = logging.getLogger("elengenix.skills")


class SkillStatus(Enum):
    """สถานะของแต่ละ skill/tool"""
    AVAILABLE = "available"      # ติดตั้งแล้ว พร้อมใช้
    MISSING = "missing"          # ยังไม่ติดตั้ง
    OPTIONAL = "optional"        # ไม่จำเป็น แต่มีประโยชน์
    RECOMMENDED = "recommended"  # ควรมีตามสถานการณ์


@dataclass
class Skill:
    """ข้อมูลของแต่ละ skill/tool"""
    name: str
    description: str
    category: str
    def __init__(self, name: str, description: str, category: str,
                 binary_name: str, status: SkillStatus, install_command: str,
                 use_cases: list = None, alternatives: list = None):
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
            "status": self.status.value if isinstance(self.status, SkillStatus) else str(self.status),
            "install_command": self.install_command,
            "use_cases": self.use_cases,
            "alternatives": self.alternatives,
        }


class SkillRegistry:
    """
    Registry ของ skills/tools ที่ AI รู้จัก
    
    หน้าที่:
    1. เก็บรายการ tools ที่มี
    2. Check availability ของแต่ละ tool
    3. แนะนำ tools ตามสถานการณ์
    4. ขอติดตั้งเพิ่มเมื่อจำเป็น
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
        """สร้างรายการ skills เริ่มต้น"""
        default_skills = [
            # Reconnaissance
            Skill("subfinder", "Subdomain enumeration", "recon", 
                  "subfinder", SkillStatus.MISSING,
                  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                  use_cases=["discover subdomains", "expand attack surface"],
                  alternatives=["amass", "findomain"]),
            
            Skill("httpx", "Fast HTTP prober", "recon",
                  "httpx", SkillStatus.MISSING,
                  "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
                  use_cases=["probe web services", "detect technologies"],
                  alternatives=[["curl", "wget"]]),
            
            Skill("naabu", "Port scanner", "recon",
                  "naabu", SkillStatus.MISSING,
                  "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
                  use_cases=["port scanning", "service discovery"],
                  alternatives=["nmap", "masscan"]),
            
            # Vulnerability Scanning
            Skill("nuclei", "Template-based vulnerability scanner", "scanner",
                  "nuclei", SkillStatus.MISSING,
                  "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
                  use_cases=["CVE scanning", "misconfiguration detection"],
                  alternatives=[["nmap", "openvas"]]),
            
            Skill("dalfox", "XSS scanner", "scanner",
                  "dalfox", SkillStatus.MISSING,
                  "go install github.com/hahwul/dalfox/v2@latest",
                  use_cases=["XSS detection", "parameter fuzzing"],
                  alternatives=["xsstrike", "xsser"]),
            
            # Fuzzing
            Skill("ffuf", "Fast web fuzzer", "fuzzing",
                  "ffuf", SkillStatus.MISSING,
                  "go install github.com/ffuf/ffuf@latest",
                  use_cases=["directory brute force", "parameter fuzzing"],
                  alternatives=["gobuster", "dirbuster"]),
            
            Skill("arjun", "HTTP parameter discovery", "fuzzing",
                  "arjun", SkillStatus.MISSING,
                  "pip install arjun",
                  use_cases=["parameter discovery", "API testing"],
                  alternatives=["paramminer", "mantra"]),
            
            # Secret Detection
            Skill("trufflehog", "Secret scanner", "secrets",
                  "trufflehog", SkillStatus.MISSING,
                  "go install github.com/trufflesecurity/trufflehog@latest",
                  use_cases=["API key detection", "secret exposure"],
                  alternatives=["git-secrets", "detect-secrets"]),
            
            # Exploitation
            Skill("katana", "Web crawler", "exploitation",
                  "katana", SkillStatus.MISSING,
                  "go install github.com/projectdiscovery/katana/cmd/katana@latest",
                  use_cases=[["web crawling", "JS endpoint discovery"]],
                  alternatives=["gau", "hakrawler"]),
        ]
        
        for skill in default_skills:
            self.skills[skill.name] = skill
    
    def _check_availability(self):
        """Check ว่าแต่ละ tool ติดตั้งแล้วหรือยัง"""
        for name, skill in self.skills.items():
            if shutil.which(skill.binary_name):
                skill.status = SkillStatus.AVAILABLE
            else:
                skill.status = SkillStatus.MISSING
    
    def get_available_skills(self) -> List[Skill]:
        """คืนค่า list ของ skills ที่พร้อมใช้"""
        return [s for s in self.skills.values() if s.status == SkillStatus.AVAILABLE]
    
    def get_missing_skills(self) -> List[Skill]:
        """คืนค่า list ของ skills ที่ยังไม่ติดตั้ง"""
        return [s for s in self.skills.values() if s.status == SkillStatus.MISSING]
    
    def recommend_for(self, scenario: str) -> List[Skill]:
        """แนะนำ skills ตามสถานการณ์ — keyword matching ที่ยืดหยุ่นกว่า"""
        scenario_lower = scenario.lower()
        scenario_words = set(scenario_lower.split())
        recommended = []
        seen = set()
        
        # Keyword จับคู่สำคัญ
        keyword_map = {
            "xss": ["dalfox", "nuclei"],
            "subdomain": ["subfinder", "httpx"],
            "port": ["naabu", "nuclei"],
            "vulnerability": ["nuclei", "dalfox"],
            "secret": ["trufflehog"],
            "crawl": ["katana"],
            "fuzz": ["ffuf", "arjun"],
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
        """สร้าง context ให้ AI รู้ว่ามี skills อะไรบ้าง"""
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
        """ขอติดตั้ง skill เพิ่ม"""
        if skill_name not in self.skills:
            return False
        
        skill = self.skills[skill_name]
        if skill.status == SkillStatus.AVAILABLE:
            return True  # Already installed
        
        # Try to install
        try:
            import shlex
            cmd_list = shlex.split(skill.install_command)
            subprocess.run(
                cmd_list,
                shell=False,
                check=True,
                capture_output=True,
                timeout=60
            )
            skill.status = SkillStatus.AVAILABLE
            return True
        except Exception as e:
            logger.error(f"Failed to install {skill_name}: {e}")
            return False
    
    def to_dict(self) -> Dict:
        """คืนค่า full registry เป็น dict"""
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
    """แนะนำ tools ตามสถานการณ์"""
    registry = get_skill_registry()
    return registry.recommend_for(scenario)


if __name__ == "__main__":
    # Test
    registry = get_skill_registry()
    print(registry.get_skill_context())
    print("\nRecommendations for 'XSS testing':")
    for skill in recommend_tools_for_scenario("XSS testing"):
        print(f"  - {skill.name} ({skill.status.value})")

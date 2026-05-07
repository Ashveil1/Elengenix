"""
tools/install_request.py — AI Tool Installation Request System (v1.0.0)

เมื่อ AI คิดว่าควรใช้ tool ไหน แต่ยังไม่ติดตั้ง → ขอให้ผู้ใช้ยืนยัน
แล้ว auto-install ให้

Author: Elengenix Project
"""

import logging
from typing import Optional, Callable, Dict, List
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("elengenix.install")


@dataclass
class InstallRequest:
    """A request from AI to install a missing tool."""
    tool_name: str
    description: str
    install_command: str
    reason: str
    confirmed: bool = False
    installed: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "tool_name": self.tool_name,
            "description": self.description,
            "install_command": self.install_command,
            "reason": self.reason,
            "confirmed": self.confirmed,
            "installed": self.installed,
        }


class InstallManager:
    """
    จัดการคำขอติดตั้ง tools จาก AI
    
    Flow:
    1. AI ขอติดตั้ง tool
    2. ผู้ใช้ยืนยัน (yes/no)
    3. ติดตั้งอัตโนมัติ
    4. รายงานผล
    """
    
    def __init__(self):
        self.requests: List[InstallRequest] = []
        self.installed: List[str] = []
    
    def request(self, tool_name: str, description: str, 
                install_command: str, reason: str = "") -> InstallRequest:
        """
        สร้างคำขอติดตั้ง
        
        Args:
            tool_name: ชื่อ tool
            description: คำอธิบาย
            install_command: คำสั่งติดตั้ง
            reason: เหตุผลที่ต้องติดตั้ง
            
        Returns:
            InstallRequest object
        """
        req = InstallRequest(
            tool_name=tool_name,
            description=description,
            install_command=install_command,
            reason=reason,
        )
        self.requests.append(req)
        logger.info(f"Install request: {tool_name} — {reason}")
        return req
    
    def confirm_install(self, req: InstallRequest) -> bool:
        """ยืนยันและติดตั้ง tool (ลบออกจาก pending หลังยืนยัน)"""
        from tools.skill_registry import get_skill_registry
        
        req.confirmed = True
        # Remove this request from pending list after processing
        if req in self.requests:
            self.requests.remove(req)
        
        # Try to install using skill registry
        registry = get_skill_registry()
        success = registry.request_install(req.tool_name)
        
        if success:
            req.installed = True
            self.installed.append(req.tool_name)
            logger.info(f"Successfully installed: {req.tool_name}")
        else:
            logger.error(f"Failed to install: {req.tool_name}")
        
        return success
    
    def get_pending_requests(self) -> List[InstallRequest]:
        """คืนค่า requests ที่ยังไม่ confirm"""
        return [r for r in self.requests if not r.confirmed]
    
    def get_installed(self) -> List[str]:
        """คืนค่า tools ที่ติดตั้งแล้ว"""
        return self.installed
    
    def format_pending_for_display(self) -> str:
        """จัดรูปแบบ pending requests สำหรับแสดงใน UI"""
        pending = self.get_pending_requests()
        if not pending:
            return ""
        
        lines = ["Pending tool installations:"]
        for i, req in enumerate(pending, 1):
            lines.append(f"  [{i}] {req.tool_name}: {req.reason}")
            lines.append(f"      Command: {req.install_command}")
        
        return "\n".join(lines)


# Singleton
_install_manager: Optional[InstallManager] = None

def get_install_manager() -> InstallManager:
    """Get or create InstallManager singleton"""
    global _install_manager
    if _install_manager is None:
        _install_manager = InstallManager()
    return _install_manager


def request_tool_install(tool_name: str, reason: str = "") -> InstallRequest:
    """Shortcut for requesting a tool installation"""
    from tools.skill_registry import get_skill_registry
    
    registry = get_skill_registry()
    skill = registry.skills.get(tool_name)
    
    if not skill:
        raise ValueError(f"Unknown tool: {tool_name}")
    
    if skill.status == skill.status.AVAILABLE:
        raise ValueError(f"Tool already installed: {tool_name}")
    
    manager = get_install_manager()
    return manager.request(
        tool_name=tool_name,
        description=skill.description,
        install_command=skill.install_command,
        reason=reason,
    )


if __name__ == "__main__":
    # Test
    req = request_tool_install("trufflehog", "Need to scan for exposed secrets")
    print(f"Requested: {req.tool_name} — {req.reason}")
    print(f"Pending: {len(get_install_manager().get_pending_requests())}")
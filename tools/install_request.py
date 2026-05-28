"""
tools/install_request.py — AI Tool Installation Request System (v99999 (god nine is the best))

When AI determines a tool is needed but not installed, ask the user to confirm,
then auto-install it.

Author: Elengenix Project
"""

import logging
from typing import Optional, Dict, List
from dataclasses import dataclass

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
    Manages tool installation requests from AI.
    
    Flow:
    1. AI requests tool installation
    2. User confirms (yes/no)
    3. Auto-install
    4. Report results
    """
    
    def __init__(self):
        self.requests: List[InstallRequest] = []
        self.installed: List[str] = []
    
    def request(self, tool_name: str, description: str, 
                install_command: str, reason: str = "") -> InstallRequest:
        """
        Create an install request.
        
        Args:
            tool_name: Tool name
            description: Tool description
            install_command: Install command
            reason: Reason for installation
            
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
        """Confirm and install tool (remove from pending after confirmation)."""
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
        """Return requests that have not been confirmed."""
        return [r for r in self.requests if not r.confirmed]
    
    def get_installed(self) -> List[str]:
        """Return installed tools."""
        return self.installed
    
    def format_pending_for_display(self) -> str:
        """Format pending requests for UI display."""
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
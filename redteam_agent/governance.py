"""
redteam_agent/governance.py — Delegates to the canonical Governance in tools/governance.py.

Kept as a thin re-export wrapper so existing imports in redteam_agent/ continue to work.
"""

import re
from tools.governance import Governance as _CanonicalGovernance


class Governance(_CanonicalGovernance):
    """Lightweight redteam_agent Governance — delegates to tools/governance.py.

    Adds verify_and_prompt() for the redteam_agent ShellExecutor flow.
    """

    def verify_and_prompt(self, command: str) -> bool:
        """
        Verify the command and prompt the user for permission if it is privileged.
        Returns True if allowed, False if blocked or rejected.
        """
        action = {"type": "run_shell", "command": command}
        result = self.gate(mission_id="redteam", target="unknown", action=action)

        if result.decision == "allow":
            return True

        if result.decision == "deny":
            print(f"\n[WARN] Dangerous command blocked: {command}")
            return False

        # needs_approval
        print(f"\n[WARN] Privileged command detected: {command}")
        try:
            choice = input("Do you want to run this? [y/N]: ").strip().lower()
            return choice == "y"
        except (KeyboardInterrupt, EOFError):
            print("\nExecution aborted.")
            return False

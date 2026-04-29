"""tools/telegram_bridge.py

Phase 3: Telegram Bridge - Real-time notifications and mission control.

Purpose:
    pass  # TODO: Implement
- Send real-time notifications to Telegram during missions
- Control missions via Telegram commands
- Notification templates for different events
- Two-way sync between CLI and Telegram

Features:
    pass  # TODO: Implement
- Mission control commands (/bounty, /status, /pause, /resume, /findings, /programs)
- Notification templates (mission started, phase completed, finding discovered, token warning)
- Real-time sync from CLI to Telegram
- URGENT notifications for critical findings

Usage:
    from tools.telegram_bridge import TelegramBridge
    
    bridge = TelegramBridge(bot_token="your_token", chat_id="your_chat_id")
    
    # Send notification
    bridge.notify_mission_started(mission_id, target)
    bridge.notify_phase_completed(mission_id, phase_name)
    bridge.notify_finding(mission_id, finding)
    
    # In smart_scanner.py, integrate notifications
    scanner = SmartScanner(target=target, telegram_bridge=bridge)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.telegram_bridge")


@dataclass
class TelegramConfig:
    """Telegram bot configuration."""
    bot_token: str
    chat_id: str
    enabled: bool = True


class TelegramBridge:
    """
    Bridge for Telegram notifications and mission control.
    
    Features:
        pass  # TODO: Implement
    - Send notifications for mission events
    - Control missions via Telegram commands
    - Formatted message templates
    """
    
    def __init__(self, config: TelegramConfig = None):
        """
        Initialize Telegram bridge.
        
        Args:
            config: Telegram configuration
        """
        self.config = config
        self.enabled = config and config.enabled if config else False
        
        if self.enabled:
            try:
                from telegram import Bot
                self.bot = Bot(token=config.bot_token)
                self.chat_id = config.chat_id
                logger.info("Telegram bridge initialized")
            except ImportError:
                logger.warning("python-telegram-bot not installed, notifications disabled")
                self.enabled = False
            except Exception as e:
                logger.warning(f"Failed to initialize Telegram: {e}")
                self.enabled = False
    
    def _send_message(self, message: str, parse_mode: str = "Markdown") -> bool:
        """Send message to Telegram."""
        if not self.enabled:
            return False
        
        try:
            self.bot.send_message(
                chat_id=self.chat_id,
                text=message,
                parse_mode=parse_mode,
                disable_web_page_preview=True
            )
            return True
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return False
    
    def notify_mission_started(self, mission_id: str, target: str) -> bool:
        """Notify that a mission has started."""
        message = (
            f"*Mission Started*\n\n"
            f"ID: `{mission_id}`\n"
            f"Target: `{target}`\n"
            f"Time: {datetime.utcnow().strftime('%H:%M UTC')}\n\n"
            f"Use `/status {mission_id}` to track progress"
        )
        return self._send_message(message)
    
    def notify_phase_completed(self, mission_id: str, phase_name: str,
                             summary: str = "", findings_count: int = 0) -> bool:
        """Notify that a phase has completed."""
        emoji = "[OK]"
        if phase_name == "discovery":
            emoji = "[D]"
        elif phase_name == "vulnerability_scan":
            emoji = "[V]"
        elif phase_name == "exploit_verification":
            emoji = "[E]"
        elif phase_name == "report_generation":
            emoji = "[R]"
        
        message = (
            f"{emoji} *Phase Completed: {phase_name}*\n\n"
            f"Mission: `{mission_id}`\n"
            f"Summary: {summary}\n"
        )
        
        if findings_count > 0:
            message += f"Findings: {findings_count}\n"
        
        return self._send_message(message)
    
    def notify_finding(self, mission_id: str, finding: Dict[str, Any],
                       urgent: bool = False) -> bool:
        """Notify about a discovered finding."""
        severity = finding.get("severity", "info").upper()
        vuln_type = finding.get("type", "Unknown")
        endpoint = finding.get("endpoint", finding.get("value", "Unknown"))
        
        # Emoji based on severity
        emoji_map = {
            "CRITICAL": "[CRIT]",
            "HIGH": "[HIGH]",
            "MEDIUM": "[MED]",
            "LOW": "[LOW]",
            "INFO": "[INFO]",
        }
        emoji = emoji_map.get(severity, "[INFO]")
        
        if urgent:
            message = (
                f"{emoji} *URGENT: Finding Discovered*\n\n"
                f"Mission: `{mission_id}`\n"
                f"Severity: *{severity}*\n"
                f"Type: {vuln_type}\n"
                f"Endpoint: `{endpoint}`\n"
                f"Description: {finding.get('description', 'N/A')}\n\n"
                f"Use `/findings {mission_id}` for details"
            )
        else:
            message = (
                f"{emoji} *Finding Discovered*\n\n"
                f"Mission: `{mission_id}`\n"
                f"Severity: {severity}\n"
                f"Type: {vuln_type}\n"
                f"Endpoint: `{endpoint}`"
            )
        
        return self._send_message(message)
    
    def notify_token_warning(self, mission_id: str, threshold: float,
                            spent: float, budget: float) -> bool:
        """Notify about token budget warning."""
        message = (
            f"*Token Budget Warning*\n\n"
            f"Mission: `{mission_id}`\n"
            f"Threshold: {threshold:.0%}\n"
            f"Spent: ${spent:.2f} / ${budget:.2f}\n\n"
            f"Mission will pause at 90% budget"
        )
        return self._send_message(message)
    
    def notify_mission_paused(self, mission_id: str, reason: str) -> bool:
        """Notify that mission was paused."""
        message = (
            f"*Mission Paused*\n\n"
            f"Mission: `{mission_id}`\n"
            f"Reason: {reason}\n\n"
            f"Use `/resume {mission_id}` to continue"
        )
        return self._send_message(message)
    
    def notify_mission_completed(self, mission_id: str, findings_count: int,
                               tokens_used: int, duration_seconds: float) -> bool:
        """Notify that mission completed."""
        duration_min = duration_seconds / 60
        
        message = (
            f"*Mission Completed*\n\n"
            f"Mission: `{mission_id}`\n"
            f"Findings: {findings_count}\n"
            f"Tokens used: {tokens_used:,}\n"
            f"Duration: {duration_min:.1f} min\n\n"
            f"Use `/findings {mission_id}` to view results"
        )
        return self._send_message(message)
    
    def notify_mission_failed(self, mission_id: str, error: str) -> bool:
        """Notify that mission failed."""
        message = (
            f"*Mission Failed*\n\n"
            f"Mission: `{mission_id}`\n"
            f"Error: {error[:200]}\n\n"
            f"Check logs for details"
        )
        return self._send_message(message)
    
    def notify_programs_list(self, programs: List[Dict[str, Any]]) -> bool:
        """Notify about available programs."""
        if not programs:
            return self._send_message("No programs found")
        
        lines = ["*Top Bug Bounty Programs*\n\n"]
        
        for i, prog in enumerate(programs[:5], 1):
            lines.append(f"{i}. *{prog['name']}*")
            lines.append(f"   Reward: {prog['bounty_range']}")
            lines.append(f"   URL: {prog['url']}")
            lines.append("")
        
        lines.append("Use `/bounty <program_name>` to start scanning")
        
        return self._send_message("\n".join(lines))
    
    def notify_mission_status(self, mission_id: str, status: Dict[str, Any]) -> bool:
        """Notify current mission status."""
        lines = [
            f"*Mission Status*\n\n",
            f"ID: `{mission_id}`\n",
            f"Status: {status.get('status', 'unknown')}\n",
            f"Phase: {status.get('current_phase', 'unknown')}\n",
            f"Findings: {status.get('findings_count', 0)}\n",
            f"Tokens used: {status.get('tokens_used', 0):,}\n",
        ]
        
        if status.get('paused_at'):
            lines.append(f"Paused at: {status['paused_at']}\n")
        
        return self._send_message("\n".join(lines))
    
    def notify_findings_list(self, mission_id: str, findings: List[Dict[str, Any]]) -> bool:
        """Notify about findings list."""
        if not findings:
            return self._send_message(f"No findings for mission `{mission_id}`")
        
        lines = [f"*Findings for {mission_id}*\n\n"]
        
        for i, finding in enumerate(findings[:10], 1):
            severity = finding.get("severity", "info").upper()
            vuln_type = finding.get("type", "Unknown")
            lines.append(f"{i}. *{severity}* - {vuln_type}")
            lines.append(f"   {finding.get('description', 'N/A')[:100]}")
            lines.append("")
        
        if len(findings) > 10:
            lines.append(f"... and {len(findings) - 10} more")
        
        return self._send_message("\n".join(lines))


def get_telegram_bridge() -> Optional[TelegramBridge]:
    """Get configured Telegram bridge instance."""
    import os
    
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    
    if not bot_token or not chat_id:
        logger.debug("Telegram not configured (missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID)")
        return None
    
    config = TelegramConfig(
        bot_token=bot_token,
        chat_id=chat_id,
        enabled=True,
    )
    
    return TelegramBridge(config)


def run_cli():
    """CLI for testing Telegram bridge."""
    import sys
    
    bridge = get_telegram_bridge()
    
    if not bridge:
        print("Telegram not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")
        sys.exit(1)
    
    if len(sys.argv) < 2:
        print("Usage: telegram_bridge [test|status]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "test":
        success = bridge._send_message("Test message from Elengenix")
        if success:
            print("[OK] Test message sent")
        else:
            print("[ERR] Failed to send test message")
    
    elif command == "status":
        if bridge.enabled:
            print("[OK] Telegram bridge enabled")
            print(f"  Chat ID: {bridge.chat_id}")
        else:
            print("[OFF] Telegram bridge disabled")
    
    else:
        print(f"Unknown command: {command}")


if __name__ == "__main__":
    run_cli()

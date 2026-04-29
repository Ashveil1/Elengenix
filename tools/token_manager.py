"""tools/token_manager.py

Phase 2: Token Manager - Track and control AI token usage.

Purpose:
    pass  # TODO: Implement
- Track token usage per AI provider
- Enforce spending limits to prevent burn
- Alert at thresholds (50%, 75%, 90%)
- Auto-switch providers when exhausted
- Daily/monthly budget tracking

Features:
    pass  # TODO: Implement
- Real-time token tracking
- Multi-provider support (OpenAI, Anthropic, etc.)
- Cost estimation per provider
- Pause recommendations
- Historical usage analytics

Usage:
    from tools.token_manager import TokenManager
    
    # Initialize with budget
    tm = TokenManager(daily_budget_usd=20.0)
    
    # Record token usage
    tm.record_usage(
        provider="openai",
        model="gpt-4",
        tokens_input=1000,
        tokens_output=500
    )
    
    # Check if can proceed
    if tm.can_proceed():
        # Make API call
        pass
    
    # Get status
    status = tm.get_status()
    print(f"Spent: ${status['spent_today']:.2f} / ${status['daily_budget']:.2f}")
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.token_manager")


@dataclass
class TokenUsage:
    """Single token usage record."""
    provider: str
    model: str
    tokens_input: int
    tokens_output: int
    cost_usd: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    mission_id: Optional[str] = None


@dataclass
class ProviderConfig:
    """Configuration for an AI provider."""
    name: str
    # Cost per 1M tokens (approximate)
    cost_per_1m_input: float
    cost_per_1m_output: float
    default_model: str
    # Provider-specific limits
    max_tokens_per_minute: int = 0  # 0 = no limit
    max_tokens_per_day: int = 0


# Provider cost configurations (as of 2024)
PROVIDER_CONFIGS = {
    "openai": ProviderConfig(
        name="OpenAI",
        cost_per_1m_input=30.0,  # GPT-4
        cost_per_1m_output=60.0,
        default_model="gpt-4",
        max_tokens_per_minute=150000,
        max_tokens_per_day=0,
    ),
    "anthropic": ProviderConfig(
        name="Anthropic",
        cost_per_1m_input=15.0,  # Claude 3 Opus
        cost_per_1m_output=75.0,
        default_model="claude-3-opus",
        max_tokens_per_minute=0,
        max_tokens_per_day=0,
    ),
    "ollama": ProviderConfig(
        name="Ollama",
        cost_per_1m_input=0.0,  # Free (local)
        cost_per_1m_output=0.0,
        default_model="llama2",
        max_tokens_per_minute=0,
        max_tokens_per_day=0,
    ),
    "groq": ProviderConfig(
        name="Groq",
        cost_per_1m_input=0.0,  # Free tier
        cost_per_1m_output=0.0,
        default_model="llama3-70b",
        max_tokens_per_minute=0,
        max_tokens_per_day=0,
    ),
}


class TokenManager:
    """
    Manage token usage and enforce budget limits.
    
    Features:
        pass  # TODO: Implement
    - Real-time tracking per provider
    - Cost estimation
    - Threshold alerts
    - Auto-switch recommendations
    - Historical analytics
    """
    
    DB_PATH = Path(".config/elengenix/token_usage.db")
    
    # Default thresholds
    ALERT_THRESHOLD_1 = 0.50  # 50%
    ALERT_THRESHOLD_2 = 0.75  # 75%
    ALERT_THRESHOLD_3 = 0.90  # 90%
    
    def __init__(self, 
                 daily_budget_usd: float = 20.0,
                 monthly_budget_usd: float = 100.0,
                 provider_configs: Dict[str, ProviderConfig] = None):
                     pass  # TODO: Implement
        """
        Initialize token manager.
        
        Args:
            daily_budget_usd: Maximum spend per day
            monthly_budget_usd: Maximum spend per month
            provider_configs: Custom provider configurations
        """
        self.daily_budget = daily_budget_usd
        self.monthly_budget = monthly_budget_usd
        self.provider_configs = provider_configs or PROVIDER_CONFIGS.copy()
        
        self._ensure_db()
        self._alerted_thresholds = set()  # Track which alerts shown
    
    def _ensure_db(self) -> None:
        """Ensure database exists with proper schema."""
        self.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS token_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT,
                model TEXT,
                tokens_input INTEGER,
                tokens_output INTEGER,
                cost_usd REAL,
                timestamp TEXT,
                mission_id TEXT
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_token_usage_timestamp 
            ON token_usage(timestamp)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_token_usage_provider 
            ON token_usage(provider)
        """)
        
        conn.commit()
        conn.close()
    
    def calculate_cost(self, provider: str, 
                      tokens_input: int, 
                      tokens_output: int,
                      model: str = None) -> float:
                          pass  # TODO: Implement
        """
        Calculate cost for token usage.
        
        Args:
            provider: Provider name (openai, anthropic, etc.)
            tokens_input: Input tokens
            tokens_output: Output tokens
            model: Model name (optional, uses default if not specified)
            
        Returns:
            Cost in USD
        """
        config = self.provider_configs.get(provider)
        if not config:
            logger.warning(f"Unknown provider: {provider}, assuming free")
            return 0.0
        
        cost_input = (tokens_input / 1_000_000) * config.cost_per_1m_input
        cost_output = (tokens_output / 1_000_000) * config.cost_per_1m_output
        
        return cost_input + cost_output
    
    def record_usage(self, 
                    provider: str,
                    model: str,
                    tokens_input: int,
                    tokens_output: int,
                    mission_id: str = None) -> TokenUsage:
                        pass  # TODO: Implement
        """
        Record token usage.
        
        Args:
            provider: Provider name
            model: Model name
            tokens_input: Input tokens used
            tokens_output: Output tokens used
            mission_id: Optional mission ID for tracking
            
        Returns:
            TokenUsage record
        """
        cost = self.calculate_cost(provider, tokens_input, tokens_output, model)
        
        usage = TokenUsage(
            provider=provider,
            model=model,
            tokens_input=tokens_input,
            tokens_output=tokens_output,
            cost_usd=cost,
            mission_id=mission_id,
        )
        
        # Save to database
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO token_usage 
            (provider, model, tokens_input, tokens_output, cost_usd, timestamp, mission_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            usage.provider,
            usage.model,
            usage.tokens_input,
            usage.tokens_output,
            usage.cost_usd,
            usage.timestamp,
            usage.mission_id,
        ))
        
        conn.commit()
        conn.close()
        
        logger.debug(f"Recorded usage: {provider} {model} - ${cost:.4f}")
        
        return usage
    
    def get_usage_today(self) -> Dict[str, float]:
        """Get total usage for today."""
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT provider, SUM(cost_usd), SUM(tokens_input + tokens_output)
            FROM token_usage
            WHERE timestamp >= ?
            GROUP BY provider
        """, (today_start.isoformat(),))
        
        results = cursor.fetchall()
        conn.close()
        
        usage = {}
        for provider, cost, tokens in results:
            usage[provider] = {
                "cost_usd": cost or 0.0,
                "tokens": tokens or 0,
            }
        
        return usage
    
    def get_usage_month(self) -> Dict[str, float]:
        """Get total usage for this month."""
        month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT provider, SUM(cost_usd), SUM(tokens_input + tokens_output)
            FROM token_usage
            WHERE timestamp >= ?
            GROUP BY provider
        """, (month_start.isoformat(),))
        
        results = cursor.fetchall()
        conn.close()
        
        usage = {}
        for provider, cost, tokens in results:
            usage[provider] = {
                "cost_usd": cost or 0.0,
                "tokens": tokens or 0,
            }
        
        return usage
    
    def get_status(self) -> Dict:
        """Get current status summary."""
        today_usage = self.get_usage_today()
        month_usage = self.get_usage_month()
        
        spent_today = sum(u["cost_usd"] for u in today_usage.values())
        spent_month = sum(u["cost_usd"] for u in month_usage.values())
        
        daily_ratio = spent_today / self.daily_budget if self.daily_budget > 0 else 0
        monthly_ratio = spent_month / self.monthly_budget if self.monthly_budget > 0 else 0
        
        return {
            "spent_today": spent_today,
            "daily_budget": self.daily_budget,
            "daily_ratio": daily_ratio,
            "spent_month": spent_month,
            "monthly_budget": self.monthly_budget,
            "monthly_ratio": monthly_ratio,
            "today_by_provider": today_usage,
            "month_by_provider": month_usage,
        }
    
    def can_proceed(self, 
                    estimated_cost: float = 0.0,
                    check_daily: bool = True,
                    check_monthly: bool = True) -> Tuple[bool, str]:
                        pass  # TODO: Implement
        """
        Check if operation can proceed based on budget.
        
        Args:
            estimated_cost: Estimated cost for upcoming operation
            check_daily: Check daily budget
            check_monthly: Check monthly budget
            
        Returns:
            (can_proceed, reason) tuple
        """
        status = self.get_status()
        
        if check_daily:
            projected_daily = status["spent_today"] + estimated_cost
            if projected_daily > self.daily_budget:
                return False, f"Daily budget exceeded: ${projected_daily:.2f} > ${self.daily_budget:.2f}"
        
        if check_monthly:
            projected_monthly = status["spent_month"] + estimated_cost
            if projected_monthly > self.monthly_budget:
                return False, f"Monthly budget exceeded: ${projected_monthly:.2f} > ${self.monthly_budget:.2f}"
        
        return True, "OK"
    
    def check_alerts(self) -> List[str]:
        """
        Check if any threshold alerts should be shown.
        
        Returns:
            List of alert messages
        """
        alerts = []
        status = self.get_status()
        
        # Daily alerts
        daily_ratio = status["daily_ratio"]
        
        if daily_ratio >= self.ALERT_THRESHOLD_3 and "daily_90" not in self._alerted_thresholds:
            alerts.append(f"⚠️ 90% daily budget used: ${status['spent_today']:.2f} / ${self.daily_budget:.2f}")
            self._alerted_thresholds.add("daily_90")
        elif daily_ratio >= self.ALERT_THRESHOLD_2 and "daily_75" not in self._alerted_thresholds:
            alerts.append(f"⚠️ 75% daily budget used: ${status['spent_today']:.2f} / ${self.daily_budget:.2f}")
            self._alerted_thresholds.add("daily_75")
        elif daily_ratio >= self.ALERT_THRESHOLD_1 and "daily_50" not in self._alerted_thresholds:
            alerts.append(f"⚠️ 50% daily budget used: ${status['spent_today']:.2f} / ${self.daily_budget:.2f}")
            self._alerted_thresholds.add("daily_50")
        
        # Monthly alerts
        monthly_ratio = status["monthly_ratio"]
        
        if monthly_ratio >= self.ALERT_THRESHOLD_3 and "monthly_90" not in self._alerted_thresholds:
            alerts.append(f"⚠️ 90% monthly budget used: ${status['spent_month']:.2f} / ${self.monthly_budget:.2f}")
            self._alerted_thresholds.add("monthly_90")
        elif monthly_ratio >= self.ALERT_THRESHOLD_2 and "monthly_75" not in self._alerted_thresholds:
            alerts.append(f"⚠️ 75% monthly budget used: ${status['spent_month']:.2f} / ${self.monthly_budget:.2f}")
            self._alerted_thresholds.add("monthly_75")
        
        return alerts
    
    def should_pause(self) -> Tuple[bool, str]:
        """
        Check if should pause operations.
        
        Returns:
            (should_pause, reason) tuple
        """
        status = self.get_status()
        
        # Pause at 90% daily budget
        if status["daily_ratio"] >= 0.90:
            return True, "Daily budget at 90%, pausing to prevent overspend"
        
        # Pause at 95% monthly budget
        if status["monthly_ratio"] >= 0.95:
            return True, "Monthly budget at 95%, pausing to prevent overspend"
        
        return False, ""
    
    def recommend_provider(self, 
                          current_provider: str,
                          estimated_tokens: int = 1000) -> Optional[str]:
                              pass  # TODO: Implement
        """
        Recommend alternative provider if current is expensive or exhausted.
        
        Args:
            current_provider: Current provider being used
            estimated_tokens: Estimated tokens for operation
            
        Returns:
            Recommended provider or None
        """
        # If current is free (Ollama, Groq), no need to switch
        if current_provider in ["ollama", "groq"]:
            return None
        
        # If we have free providers available, recommend them
        free_providers = [p for p in self.provider_configs.keys() 
                         if self.provider_configs[p].cost_per_1m_input == 0]
        
        if free_providers:
            return free_providers[0]
        
        # Otherwise, recommend cheapest
        cheapest = min(
            self.provider_configs.items(),
            key=lambda x: x[1].cost_per_1m_input
        )
        
        if cheapest[0] != current_provider:
            return cheapest[0]
        
        return None
    
    def get_mission_cost(self, mission_id: str) -> Dict:
        """Get total cost for a specific mission."""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT provider, SUM(cost_usd), SUM(tokens_input + tokens_output)
            FROM token_usage
            WHERE mission_id = ?
            GROUP BY provider
        """, (mission_id,))
        
        results = cursor.fetchall()
        conn.close()
        
        cost_by_provider = {}
        total_cost = 0.0
        total_tokens = 0
        
        for provider, cost, tokens in results:
            cost_by_provider[provider] = {
                "cost_usd": cost or 0.0,
                "tokens": tokens or 0,
            }
            total_cost += cost or 0.0
            total_tokens += tokens or 0
        
        return {
            "total_cost_usd": total_cost,
            "total_tokens": total_tokens,
            "by_provider": cost_by_provider,
        }
    
    def reset_alerts(self) -> None:
        """Reset alert tracking (e.g., for new day)."""
        self._alerted_thresholds.clear()
    
    def format_status(self) -> str:
        """Format status for display."""
        status = self.get_status()
        
        lines = []
        lines.append("\n  Token Usage Status:")
        lines.append("  " + "─" * 50)
        
        # Daily
        daily_pct = status["daily_ratio"] * 100
        lines.append(f"\n  Today:")
        lines.append(f"    Spent: ${status['spent_today']:.2f} / ${status['daily_budget']:.2f} ({daily_pct:.1f}%)")
        
        # Progress bar
        bar_length = 20
        filled = int(bar_length * status["daily_ratio"])
        bar = "█" * filled + "░" * (bar_length - filled)
        lines.append(f"    [{bar}]")
        
        # By provider today
        if status["today_by_provider"]:
            lines.append(f"\n    By provider:")
            for provider, data in status["today_by_provider"].items():
                lines.append(f"      {provider}: ${data['cost_usd']:.2f} ({data['tokens']:,} tokens)")
        
        # Monthly
        monthly_pct = status["monthly_ratio"] * 100
        lines.append(f"\n  This Month:")
        lines.append(f"    Spent: ${status['spent_month']:.2f} / ${status['monthly_budget']:.2f} ({monthly_pct:.1f}%)")
        
        # Alerts
        alerts = self.check_alerts()
        if alerts:
            lines.append(f"\n  Alerts:")
            for alert in alerts:
                lines.append(f"    {alert}")
        
        lines.append("\n  " + "─" * 50)
        
        return "\n".join(lines)


def get_token_manager(daily_budget: float = 20.0) -> TokenManager:
    """Get singleton token manager instance."""
    if not hasattr(get_token_manager, "_instance"):
        get_token_manager._instance = TokenManager(daily_budget_usd=daily_budget)
    return get_token_manager._instance


def run_cli():
    """CLI for token management."""
    import sys
    
    tm = get_token_manager()
    
    if len(sys.argv) < 2:
        print(tm.format_status())
        sys.exit(0)
    
    command = sys.argv[1]
    
    if command == "status":
        print(tm.format_status())
    
    elif command == "reset":
        tm.reset_alerts()
        print("Alerts reset.")
    
    elif command == "check":
        can_proceed, reason = tm.can_proceed()
        if can_proceed:
            print("✓ Can proceed with operations")
        else:
            print(f"✗ Cannot proceed: {reason}")
    
    elif command == "mission":
        if len(sys.argv) < 3:
            print("Usage: token mission <mission_id>")
            sys.exit(1)
        
        mission_id = sys.argv[2]
        cost = tm.get_mission_cost(mission_id)
        
        print(f"\n  Mission Cost: {mission_id}")
        print(f"  Total: ${cost['total_cost_usd']:.2f} ({cost['total_tokens']:,} tokens)")
        
        if cost["by_provider"]:
            print(f"\n  By provider:")
            for provider, data in cost["by_provider"].items():
                print(f"    {provider}: ${data['cost_usd']:.2f}")
    
    else:
        print(f"Unknown command: {command}")
        print("Usage: token [status|reset|check|mission]")


if __name__ == "__main__":
    run_cli()

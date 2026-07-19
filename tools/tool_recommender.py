"""tools/tool_recommender.py -- LLM Empowerment: Tool Recommendation

Recommends tools based on success rates from past scans.
Uses LearningEngine data to suggest the best tools for specific contexts.

Philosophy: Give LLM tool recommendations -> LLM chooses the best one
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.tool_recommender")


class ToolRecommender:
    """Recommends tools based on historical success rates."""

    # Default tool capabilities (used when no learning data available)
    TOOL_CAPABILITIES = {
        "nuclei": {
            "description": "Vulnerability scanner with templates",
            "best_for": ["xss", "ssrf", "misconfiguration", "info_disclosure"],
            "tech_support": ["php", "python", "java", "node", "nginx", "apache"],
        },
        "sqlmap": {
            "description": "SQL injection detection and exploitation",
            "best_for": ["sqli"],
            "tech_support": ["mysql", "postgresql", "mssql", "oracle", "sqlite"],
        },
        "nikto": {
            "description": "Web server scanner",
            "best_for": ["misconfiguration", "info_disclosure"],
            "tech_support": ["apache", "nginx", "iis"],
        },
        "dirb": {
            "description": "Directory brute-forcer",
            "best_for": ["info_disclosure"],
            "tech_support": ["php", "python", "java", "node"],
        },
        "ffuf": {
            "description": "Web fuzzer",
            "best_for": ["sqli", "xss", "ssrf", "rce"],
            "tech_support": ["php", "python", "java", "node"],
        },
        "subfinder": {
            "description": "Subdomain discovery",
            "best_for": ["recon"],
            "tech_support": ["*"],
        },
        "httpx": {
            "description": "HTTP probing",
            "best_for": ["recon"],
            "tech_support": ["*"],
        },
        "dalfox": {
            "description": "XSS scanner",
            "best_for": ["xss"],
            "tech_support": ["php", "python", "java", "node"],
        },
        "httpie": {
            "description": "HTTP client for manual testing",
            "best_for": ["manual_testing"],
            "tech_support": ["*"],
        },
        "curl": {
            "description": "HTTP client (universal)",
            "best_for": ["manual_testing", "recon"],
            "tech_support": ["*"],
        },
        "nmap": {
            "description": "Network scanner",
            "best_for": ["recon", "port_scan"],
            "tech_support": ["*"],
        },
        "whatweb": {
            "description": "Web technology fingerprinter",
            "best_for": ["recon"],
            "tech_support": ["*"],
        },
        "wpscan": {
            "description": "WordPress vulnerability scanner",
            "best_for": ["wordpress_vulns"],
            "tech_support": ["wordpress"],
        },
        "joomscan": {
            "description": "Joomla vulnerability scanner",
            "best_for": ["joomla_vulns"],
            "tech_support": ["joomla"],
        },
        "wapiti": {
            "description": "Web application vulnerability scanner",
            "best_for": ["sqli", "xss", "ssrf", "rce", "lfi"],
            "tech_support": ["php", "python", "java"],
        },
    }

    def __init__(self):
        self._learning_engine = None

    @property
    def learning_engine(self):
        """Lazy load LearningEngine."""
        if self._learning_engine is None:
            try:
                from tools.learning_engine import LearningEngine
                self._learning_engine = LearningEngine()
            except Exception as e:
                logger.debug(f"Could not load LearningEngine: {e}")
        return self._learning_engine

    def recommend(
        self,
        tech_stack: Optional[List[str]] = None,
        vuln_class: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Recommend tools based on context.

        Combines:
        1. Historical success rates from LearningEngine
        2. Tool capabilities (static knowledge)
        3. Tech stack compatibility

        Args:
            tech_stack: List of technologies (e.g., ["php", "mysql"])
            vuln_class: Specific vulnerability class to scan for
            limit: Max recommendations to return

        Returns:
            List of tool recommendations with scores
        """
        recommendations = []

        # 1. Get historical success rates
        historical_rankings = self._get_historical_rankings(tech_stack, vuln_class)

        # 2. Get capability-based recommendations
        capability_rankings = self._get_capability_rankings(tech_stack, vuln_class)

        # 3. Merge and rank
        seen_tools = set()

        # Add historical recommendations first (they have real data)
        for tool_info in historical_rankings:
            tool_name = tool_info["tool"]
            if tool_name not in seen_tools:
                seen_tools.add(tool_name)
                recommendations.append({
                    "name": tool_name,
                    "source": "historical",
                    "success_rate": tool_info["success_rate"],
                    "samples": tool_info["samples"],
                    "score": tool_info["success_rate"] * 1.5,  # Weight historical data higher
                })

        # Add capability-based recommendations
        for tool_info in capability_rankings:
            tool_name = tool_info["name"]
            if tool_name not in seen_tools:
                seen_tools.add(tool_name)
                recommendations.append({
                    "name": tool_name,
                    "source": "capability",
                    "description": tool_info.get("description", ""),
                    "best_for": tool_info.get("best_for", []),
                    "score": tool_info.get("score", 0.5),
                })

        # Sort by score
        recommendations.sort(key=lambda x: x.get("score", 0), reverse=True)

        return recommendations[:limit]

    def _get_historical_rankings(
        self,
        tech_stack: Optional[List[str]] = None,
        vuln_class: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get tool rankings from LearningEngine."""
        if not self.learning_engine:
            return []

        try:
            rankings = self.learning_engine.rank_tools(
                tech_stack=tech_stack,
                vuln_class=vuln_class,
                limit=10,
            )
            return [
                {
                    "tool": tool,
                    "success_rate": rate,
                    "samples": samples,
                }
                for tool, rate, samples in rankings
            ]
        except Exception as e:
            logger.debug(f"Error getting historical rankings: {e}")
            return []

    def _get_capability_rankings(
        self,
        tech_stack: Optional[List[str]] = None,
        vuln_class: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get tool recommendations based on capabilities."""
        recommendations = []

        for tool_name, capabilities in self.TOOL_CAPABILITIES.items():
            score = 0.0

            # Check tech stack compatibility
            if tech_stack:
                compatible = any(
                    t in capabilities.get("tech_support", [])
                    or "*" in capabilities.get("tech_support", [])
                    for t in tech_stack
                )
                if compatible:
                    score += 0.3

            # Check vuln class match
            if vuln_class:
                if vuln_class in capabilities.get("best_for", []):
                    score += 0.5

            # Base score for having capabilities
            if capabilities.get("best_for"):
                score += 0.2

            if score > 0:
                recommendations.append({
                    "name": tool_name,
                    "description": capabilities.get("description", ""),
                    "best_for": capabilities.get("best_for", []),
                    "tech_support": capabilities.get("tech_support", []),
                    "score": score,
                })

        return recommendations

    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed info about a specific tool."""
        return self.TOOL_CAPABILITIES.get(tool_name)

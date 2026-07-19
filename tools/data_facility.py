"""tools/data_facility.py -- LLM Empowerment: Data Facility

Provides comprehensive data to LLM for informed decision-making.
Instead of constraining the LLM, this facility enriches it with:
- Past scan results and patterns
- Tech stack information
- Vulnerability knowledge (CVE, CWE, OWASP)
- Tool success rates and recommendations
- Payload suggestions

Philosophy: Give LLM data -> LLM decides -> Better results
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.data_facility")


class DataFacility:
    """Aggregates all relevant data for LLM decision-making.

    This facility does NOT constrain the LLM -- it provides data
    that helps the LLM make better decisions on its own.
    """

    def __init__(self):
        self._learning_engine = None
        self._vuln_knowledge = None
        self._tool_recommender = None

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

    @property
    def vuln_knowledge(self):
        """Lazy load VulnerabilityKnowledge."""
        if self._vuln_knowledge is None:
            try:
                from tools.vuln_knowledge import VulnerabilityKnowledge
                self._vuln_knowledge = VulnerabilityKnowledge()
            except Exception as e:
                logger.debug(f"Could not load VulnerabilityKnowledge: {e}")
        return self._vuln_knowledge

    @property
    def tool_recommender(self):
        """Lazy load ToolRecommender."""
        if self._tool_recommender is None:
            try:
                from tools.tool_recommender import ToolRecommender
                self._tool_recommender = ToolRecommender()
            except Exception as e:
                logger.debug(f"Could not load ToolRecommender: {e}")
        return self._tool_recommender

    def get_full_context(self, target: str, tech_stack: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get comprehensive data context for LLM.

        This is the main entry point -- call this before asking LLM to decide.

        Args:
            target: Target system (URL, IP, domain)
            tech_stack: Optional tech stack info (e.g., ["php", "mysql"])

        Returns:
            Dict with all relevant data for LLM decision-making
        """
        context = {
            "target": target,
            "data_sections": {},
        }

        # 1. Past scan knowledge
        context["data_sections"]["past_knowledge"] = self._get_past_knowledge(target, tech_stack)

        # 2. Tool recommendations
        context["data_sections"]["tool_recommendations"] = self._get_tool_recommendations(tech_stack)

        # 3. Vulnerability knowledge
        context["data_sections"]["vuln_knowledge"] = self._get_vuln_knowledge(tech_stack)

        # 4. Payload suggestions
        context["data_sections"]["payload_suggestions"] = self._get_payload_suggestions()

        # 5. Target summary
        context["data_sections"]["target_summary"] = self._get_target_summary(target)

        return context

    def get_prompt_context(self, target: str, tech_stack: Optional[List[str]] = None) -> str:
        """Get formatted context string for LLM prompt.

        Args:
            target: Target system
            tech_stack: Optional tech stack info

        Returns:
            Formatted string ready for prompt injection
        """
        context = self.get_full_context(target, tech_stack)
        return self._format_for_prompt(context)

    def _get_past_knowledge(self, target: str, tech_stack: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get knowledge from past scans."""
        result = {
            "similar_targets": [],
            "successful_tools": [],
            "successful_payloads": [],
        }

        if not self.learning_engine:
            return result

        try:
            # Similar past targets
            if tech_stack:
                similar = self.learning_engine.recall_similar(
                    tech_stack=tech_stack,
                    limit=5,
                )
                result["similar_targets"] = [
                    {
                        "target": r.target,
                        "vuln_class": r.vuln_class,
                        "tool": r.tool,
                        "success": r.success,
                    }
                    for r in similar
                ]

            # Successful tools
            rankings = self.learning_engine.rank_tools(limit=5)
            result["successful_tools"] = [
                {"tool": tool, "success_rate": rate, "samples": samples}
                for tool, rate, samples in rankings
            ]

            # Successful payloads
            for vuln_class in ["sqli", "xss", "ssrf", "rce", "lfi"]:
                payloads = self.learning_engine.suggest_payloads(vuln_class, n=3)
                if payloads:
                    result["successful_payloads"].append({
                        "vuln_class": vuln_class,
                        "payloads": payloads,
                    })

        except Exception as e:
            logger.debug(f"Error getting past knowledge: {e}")

        return result

    def _get_tool_recommendations(self, tech_stack: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get tool recommendations based on context."""
        result = {
            "recommended_tools": [],
            "tool_details": {},
        }

        if not self.tool_recommender:
            return result

        try:
            recommendations = self.tool_recommender.recommend(
                tech_stack=tech_stack,
                limit=10,
            )
            result["recommended_tools"] = recommendations
        except Exception as e:
            logger.debug(f"Error getting tool recommendations: {e}")

        return result

    def _get_vuln_knowledge(self, tech_stack: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get vulnerability knowledge for the tech stack."""
        result = {
            "owasp_top_10": [],
            "common_cwes": [],
            "tech_specific_vulns": [],
        }

        if not self.vuln_knowledge:
            return result

        try:
            if tech_stack:
                for tech in tech_stack:
                    vulns = self.vuln_knowledge.get_tech_vulns(tech)
                    if vulns:
                        result["tech_specific_vulns"].extend(vulns)

            result["owasp_top_10"] = self.vuln_knowledge.get_owasp_top_10()
            result["common_cwes"] = self.vuln_knowledge.get_common_cwes()
        except Exception as e:
            logger.debug(f"Error getting vuln knowledge: {e}")

        return result

    def _get_payload_suggestions(self) -> Dict[str, Any]:
        """Get payload suggestions for common vulnerability types."""
        result = {}

        if not self.learning_engine:
            return result

        try:
            for vuln_class in ["sqli", "xss", "ssrf", "rce", "lfi", "ssti"]:
                payloads = self.learning_engine.suggest_payloads(vuln_class, n=5)
                if payloads:
                    result[vuln_class] = payloads
        except Exception as e:
            logger.debug(f"Error getting payload suggestions: {e}")

        return result

    def _get_target_summary(self, target: str) -> Dict[str, Any]:
        """Get summary of what we know about the target."""
        result = {
            "target": target,
            "known_endpoints": [],
            "known_vulns": [],
            "scan_history": [],
        }

        # TODO: Integrate with existing target knowledge systems
        # This is a placeholder for future integration

        return result

    def _format_for_prompt(self, context: Dict[str, Any]) -> str:
        """Format context dict into prompt-friendly string."""
        lines = []
        lines.append("### AVAILABLE DATA FOR DECISION-MAKING:")
        lines.append("")

        # Track whether any data was added
        added = False

        # Past knowledge
        past = context.get("data_sections", {}).get("past_knowledge", {})
        if past.get("successful_tools"):
            added = True
            lines.append("**Successful Tools from Past Scans:**")
            for t in past["successful_tools"][:5]:
                lines.append(f"  - {t['tool']}: {t['success_rate']:.0%} success rate ({t['samples']} samples)")
            lines.append("")

        if past.get("successful_payloads"):
            added = True
            lines.append("**Payloads That Worked Before:**")
            for p in past["successful_payloads"][:5]:
                lines.append(f"  - {p['vuln_class']}: {', '.join(p['payloads'][:3])}")
            lines.append("")

        # Tool recommendations
        tools = context.get("data_sections", {}).get("tool_recommendations", {})
        if tools.get("recommended_tools"):
            added = True
            lines.append("**Recommended Tools:**")
            for t in tools["recommended_tools"][:5]:
                if isinstance(t, dict):
                    lines.append(f"  - {t.get('name', t.get('tool', 'unknown'))}")
                else:
                    lines.append(f"  - {t}")
            lines.append("")

        # Vulnerability knowledge
        vulns = context.get("data_sections", {}).get("vuln_knowledge", {})
        if vulns.get("owasp_top_10"):
            added = True
            lines.append("**OWASP Top 10 (relevant):**")
            for v in vulns["owasp_top_10"][:5]:
                lines.append(f"  - {v}")
            lines.append("")

        if vulns.get("tech_specific_vulns"):
            added = True
            lines.append("**Tech-Specific Vulnerabilities:**")
            for v in vulns["tech_specific_vulns"][:10]:
                lines.append(f"  - {v}")
            lines.append("")

        # Payload suggestions
        payloads = context.get("data_sections", {}).get("payload_suggestions", {})
        if payloads:
            added = True
            lines.append("**Suggested Payloads:**")
            for vuln_class, payload_list in list(payloads.items())[:5]:
                lines.append(f"  - {vuln_class}: {', '.join(payload_list[:3])}")
            lines.append("")

        if not added:
            lines.append("(No additional data available yet -- first scan on this target)")

        return "\n".join(lines)

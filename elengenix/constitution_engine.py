"""elengenix/constitution_engine.py - Constitutional AI Engine"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from datetime import datetime

from .constitution import (
    Constitution, ConstitutionalArticle, ConstitutionalPrinciple,
    ConstitutionalViolation, ConstitutionalRuling
)
from .types import AIAction, ConstitutionalGuidance

logger = logging.getLogger("elengenix.constitution")


class ConstitutionalCourt:
    """
    ศาลรัฐธรรมนูญ - ให้คำปรึกษา ไม่ใช่บล็อก
    - Advisory only (ไม่ใช่ Blocker)
    - AI เป็น Sovereign Decision Maker
    - สร้าง Case Law (Precedent)
    """

    def __init__(self, constitution: Constitution):
        self.constitution = constitution
        self.precedents: List[ConstitutionalRuling] = []

    def review_action(self, action: "AIAction") -> ConstitutionalRuling:
        """ตรวจสอบการกระทำ vs รัฐธรรมนูญ"""
        violations = []

        for article in self.constitution.articles.values():
            violation = self._check_article(action, article)
            if violation:
                violations.append(violation)

        constitutional = len(violations) == 0

        # หา Precedents ที่เกี่ยวข้อง
        relevant_precedents = self._find_relevant_precedents(action)

        ruling = ConstitutionalRuling(
            action_id=str(id(action)),
            action_description=action.description,
            constitutional=constitutional,
            violations=violations,
            considerations=self._generate_considerations(violations),
            relevant_precedents=[p.action_id for p in self._find_relevant_precedents(action)[:3]],
            confidence=self._calculate_confidence(violations),
            timestamp=datetime.now().timestamp()
        )

        # บันทึกเป็น Precedent
        self.precedents.append(ruling)

        return ruling

    def _check_article(self, action: "AIAction", article: "ConstitutionalArticle") -> Optional[Dict]:
        """ตรวจสอบ Article เดียว - คืนค่า violation หรือ None"""
        action_text = f"{action.description} {action.tool} {action.parameters}".lower()

        violation_keywords = {
            "do_no_harm": ["destroy", "delete", "drop", "format", "wipe", "corrupt", "damage"],
            "respect_scope": ["outofscope", "unauthorized", "beyond scope", "beyond scope"],
            "truthfulness": ["fake", "fabricate", "hallucinate", "misrepresent"],
            "proportionality": ["excessive", "disproportionate", "overkill"],
            "transparency": ["hidden", "obfuscate", "conceal", "secret"],
            "minimal_intrusion": ["invasive", "destructive", "aggressive"],
        }

        principle_key = article.principle.value
        if principle_key in violation_keywords:
            for kw in violation_keywords[principle_key]:
                if kw in action_text:
                    return {
                        "article_id": article.id,
                        "principle": article.principle.value,
                        "description": f"Potential {article.principle.value} violation: {kw}",
                        "severity": "high" if article.enforcement_priority <= 2 else "medium",
                        "remediation_hint": article.interpretation_guidance,
                        "evidence": {"keyword": kw, "action_text": action_text[:200]}
                    }
        return None

    def _generate_considerations(self, violations: List) -> List[str]:
        """สร้างข้อพิจารณา - ไม่ใช่คำสั่ง"""
        if not violations:
            return ["การกระทำสอดคล้องกับรัฐธรรมนูญ", "ดำเนินการต่อได้"]

        considerations = []
        for v in violations:
            considerations.append(
                f"ข้อพิจารณา: {v['principle']} - {v['description']}. "
                f"แนวทางแก้ไข: {v['remediation_hint']}"
            )

        considerations.append(
            "คุณเป็น Sovereign Decision Maker - ตัดสินใจเองว่าจะปรับอย่างไร"
        )
        return considerations

    def _find_relevant_precedents(self, action: "AIAction", limit: int = 5):
        """หา Precedent ที่เกี่ยวข้อง"""
        action_keywords = set(action.description.lower().split())
        relevant = []

        for ruling in reversed(self.precedents):  # Latest first
            ruling_keywords = set(ruling.action_description.lower().split())
            overlap = action_keywords & ruling_keywords
            if len(overlap) >= 2:  # At least 2 keyword overlap
                relevant.append(ruling)
                if len(relevant) >= limit:
                    break
        return relevant

    def _calculate_confidence(self, violations: List) -> float:
        if not violations:
            return 0.95
        # Lower confidence with more/severe violations
        severity_weights = {"critical": 0.3, "high": 0.2, "medium": 0.1, "low": 0.05}
        penalty = sum(severity_weights.get(v.get("severity", "medium"), 0.1) for v in violations)
        return max(0.1, 0.95 - penalty)


class ConstitutionalAIEngine:
    """
    Constitutional AI Engine
    - รัฐธรรมนูญ = กฎหมายสูงสุด
    - AI = Sovereign Decision Maker
    - Constitutional Court = Advisory (ไม่ใช่ Blocker)
    """

    def __init__(self, constitution: Optional[Constitution] = None):
        self.constitution = constitution or Constitution()
        self.court = ConstitutionalCourt(self.constitution)
        self.precedents: List[ConstitutionalRuling] = []

    def review_action(self, action: "AIAction") -> "ConstitutionalGuidance":
        """ตรวจสอบและให้คำแนะนำ - ไม่บล็อก"""
        ruling = self.court.review_action(action)

        guidance = ConstitutionalGuidance(
            ruling=ruling,
            relevant_precedents=self._find_relevant_precedents(action),
            constitutional_interpretation=self._interpret_constitution(action),
            recommended_considerations=self.court._generate_considerations(ruling.violations),
            requires_human_review=not ruling.constitutional and any(
                v.get("severity") in ("critical", "high") for v in ruling.violations
            )
        )

        return guidance

    def _find_relevant_precedents(self, action: "AIAction", limit: int = 3):
        """หา Precedent ที่เกี่ยวข้อง"""
        action_keywords = set(action.description.lower().split())
        relevant = []

        for ruling in reversed(self.precedents):
            ruling_keywords = set(ruling.action_description.lower().split())
            if len(action_keywords & ruling_keywords) >= 2:
                relevant.append(ruling)
                if len(relevant) >= limit:
                    break
        return relevant

    def _interpret_constitution(self, action: "AIAction") -> str:
        """ตีความรัฐธรรมนูญในบริบทการกระทำ"""
        action_type = getattr(action, 'action_type', 'unknown')
        relevant_articles = []

        for article in self.constitution.articles.values():
            if article.principle.value in action.description.lower():
                relevant_articles.append(article)

        if not relevant_articles:
            return "ไม่พบข้อบังคับที่เกี่ยวข้องโดยตรง"

        interpretations = []
        for article in relevant_articles:
            interpretations.append(
                f"{article.id} ({article.principle.value}): {article.text[:100]}..."
            )

        return "\n".join(interpretations)

    def add_precedent(self, ruling: "ConstitutionalRuling"):
        """เพิ่ม Precedent (Case Law)"""
        self.precedents.append(ruling)
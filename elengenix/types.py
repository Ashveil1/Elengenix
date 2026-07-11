"""elengenix/types.py - Core Types & Enums"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class RiskLevel(Enum):
    """ระดับความเสี่ยง"""
    SAFE = "safe"
    PRIVILEGED = "privileged"
    DESTRUCTIVE = "destructive"
    EXISTENTIAL = "existential"


class ActionType(Enum):
    """ประเภทการกระทำ"""
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    VERIFICATION = "verification"
    REPORTING = "reporting"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    RESEARCH = "research"
    PLANNING = "planning"
    DECISION = "decision"
    COMMUNICATION = "communication"
    LEARNING = "learning"


class AgentRole(Enum):
    """บทบาท Agent"""
    CAPTAIN = "captain"
    STRATEGIST = "strategist"
    RECON = "recon"
    SCANNER = "scanner"
    EXPLOITER = "exploiter"
    VERIFIER = "verifier"
    REPORTER = "reporter"
    INTEL = "intel"
    SPECIALIST = "specialist"


class MissionPhase(Enum):
    """Phase ของภารกิจ"""
    INIT = "init"
    RECON = "recon"
    PLANNING = "planning"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    VERIFICATION = "verification"
    REPORTING = "reporting"
    COMPLETE = "complete"
    ABORTED = "aborted"


@dataclass
class AIAction:
    """การกระทำของ AI Agent"""
    action_id: str = field(default_factory=lambda: str(uuid4()))
    action_type: str = "recon"
    tool: str = ""
    target: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    purpose: str = ""
    risk_level: str = "safe"
    prerequisites: List[str] = field(default_factory=list)
    expected_outcome: str = ""
    constitutional_guidance: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())


@dataclass
class AgentMessage:
    """ACP Message"""
    message_id: str = field(default_factory=lambda: str(uuid4()))
    correlation_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    priority: int = 3
    requires_response: bool = False
    from_agent: str = ""
    to_agent: str = ""
    message_type: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)


class MessageType(Enum):
    TASK = "task"
    RESULT = "result"
    INTEL = "intel"
    ALERT = "alert"
    DECISION = "decision"
    HEARTBEAT = "heartbeat"
    PHASE_CHANGE = "phase_change"


@dataclass
class ToolResult:
    """ผลลัพธ์จาก Tool"""
    success: bool
    tool_name: str
    category: str
    output: Any = None
    findings: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0
    metadata: Dict = field(default_factory=dict)


@dataclass
class Finding:
    """Finding/ช่องโหว่ที่พบ"""
    finding_id: str = field(default_factory=lambda: str(uuid4()))
    type: str = ""
    severity: str = "info"
    title: str = ""
    description: str = ""
    evidence: Dict = field(default_factory=dict)
    location: str = ""
    parameter: str = ""
    payload: str = ""
    evidence_raw: str = ""
    confidence: float = 0.0
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    verified: bool = False
    verification_details: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())


@dataclass
class MissionContext:
    """บริบทภารกิจ"""
    mission_id: str = field(default_factory=lambda: str(uuid4()))
    target: str = ""
    scope: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    objectives: List[str] = field(default_factory=list)
    max_duration: int = 86400
    max_cost: float = 100.0
    start_time: float = field(default_factory=lambda: datetime.now().timestamp())
    metadata: Dict = field(default_factory=dict)


@dataclass
class MissionResult:
    """ผลลัพธ์ภารกิจ"""
    mission_id: str
    target: str
    duration_seconds: float
    phases_completed: List[str]
    findings: List = field(default_factory=list)
    verified_findings: List = field(default_factory=list)
    false_positives: List = field(default_factory=list)
    coverage_score: float = 0.0
    risk_score: float = 0.0
    report_paths: Dict[str, str] = field(default_factory=dict)
    status: str = "completed"
    summary: str = ""
    metadata: Dict = field(default_factory=dict)


@dataclass
class AttackTree:
    """Attack Tree Structure"""
    tree_id: str = field(default_factory=lambda: str(uuid4()))
    target: str = ""
    objective: str = ""
    tech_stack: List[str] = field(default_factory=list)
    steps: List = field(default_factory=list)


@dataclass
class AttackStep:
    """Attack Step"""
    step_id: str = field(default_factory=lambda: str(uuid4()))
    phase: str = ""
    technique: str = ""
    tool: str = ""
    target: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    expected_result: str = ""
    risk_level: str = "medium"
    dependencies: List[str] = field(default_factory=list)


class AttackPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    VERIFICATION = "verification"
    REPORTING = "reporting"


class ConstitutionalGuidance:
    """คำแนะนำจากศาลรัฐธรรมนูญ"""
    def __init__(self, ruling: Any = None):
        self.ruling = ruling
        self.relevant_precedents = []
        self.constitutional_interpretation = ""
        self.recommended_considerations = []
        self.requires_human_review = False

    @property
    def is_constitutional(self) -> bool:
        return getattr(self.ruling, 'constitutional', False)

    @property
    def confidence(self) -> float:
        return getattr(self.ruling, 'confidence', 0.0)

    def to_dict(self) -> dict:
        return {
            "constitutional": self.is_constitutional,
            "confidence": self.confidence,
            "violations": getattr(self.ruling, 'violations', []),
            "considerations": getattr(self.ruling, 'considerations', []),
            "precedents": len(getattr(self, 'relevant_precedents', [])),
            "requires_human_review": self.requires_human_review,
            "interpretation": getattr(self, 'constitutional_interpretation', '')
        }


class RiskAssessment:
    level: str
    factors: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LoopConfig:
    """การตั้งค่าลูป"""
    max_steps: int = 100
    max_duration: int = 86400  # 24 hours
    replan_threshold: float = 0.3
    reflection_interval: int = 10
    constitutional_check: bool = True
    auto_replan: bool = True
    max_consecutive_failures: int = 3


class GovernanceDecision(Enum):
    """Governance Decision"""
    ALLOW = "allow"
    NEEDS_APPROVAL = "needs_approval"
    DENY = "deny"


@dataclass
class GovernanceGate:
    """ผลการตัดสินใจของ Governance"""
    decision: "GovernanceDecision"
    rationale: str
    risk_level: str
    requires_human: bool = False
    auto_approve_conditions: List[str] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)


@dataclass
class GovernancePolicy:
    """นโยบายการกำกับดูแล"""
    name: str
    description: str
    risk_levels: List[str]
    allowed_actions: List[str]
    blocked_actions: List[str]
    requires_approval: List[str]
    auto_approve_conditions: List[str] = field(default_factory=list)
    max_concurrent: int = 5
    rate_limit_rps: float = 10.0


@dataclass
class RiskAssessment:
    level: str
    factors: Dict[str, Any] = field(default_factory=dict)
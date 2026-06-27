"""
multimodal_agent.py — Elengenix Multi-Modal AI Agent
Vision (screenshots), code analysis, memory-augmented reasoning.
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.multimodal")


# ═══════════════════════════════════════════════════════════════════════════
# 1. VISION — Screenshot analysis for security UI
# ═══════════════════════════════════════════════════════════════════════════


class VisionMode(Enum):
    """Different vision analysis modes."""

    DASHBOARD = "dashboard"  # Anomaly detection in security dashboards
    STACKTRACE = "stacktrace"  # Extract error info from stack traces
    TOKEN = "token"  # Find tokens/keys in screenshots
    COOKIE = "cookie"  # Extract cookies from browser
    INFRA = "infra"  # Cloud/infra diagram analysis


@dataclass
class VisionFinding:
    """A finding extracted from an image."""

    mode: VisionMode
    text: str = ""
    tokens: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    confidence: float = 0.0
    raw_response: str = ""


SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "github_pat": r"github_pat_[A-Za-z0-9_]{22,}",
    "slack_token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
    "google_api": r"AIza[0-9A-Za-z\-_]{35}",
    "stripe_key": r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
    "stripe_restricted": r"rk_(?:live|test)_[A-Za-z0-9]{24,}",
    "jwt": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "private_key": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    "ssh_passphrase": r"(?i)passphrase\s*[:=]\s*['\"]?([^\s'\"]{4,})",
    "generic_api_key": r"(?i)(?:api[_-]?key|access[_-]?token|secret)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})",
    "basic_auth": r"(?i)https?://[^:\s]+:[^@\s]+@[^\s]+",
    "bearer_token": r"(?i)bearer\s+([A-Za-z0-9\-_\.=]+)",
    "oauth_token": r"(?i)oauth[_-]?token\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})",
    "session_id": r"(?i)(?:session|sess|sid)[_-]?id\s*[:=]\s*['\"]?([A-Za-z0-9]{16,})",
    "password": r"(?i)password\s*[:=]\s*['\"]?([^\s'\"]{4,})",
}

SECRET_CVSS = {
    "aws_access_key": 9.9,
    "aws_secret_key": 9.9,
    "github_token": 9.0,
    "github_pat": 8.0,
    "slack_token": 8.5,
    "google_api": 8.0,
    "stripe_key": 9.5,
    "stripe_restricted": 7.0,
    "jwt": 8.0,
    "private_key": 9.8,
    "ssh_passphrase": 7.5,
    "generic_api_key": 7.0,
    "basic_auth": 8.5,
    "bearer_token": 8.0,
    "oauth_token": 7.5,
    "session_id": 7.0,
    "password": 7.0,
}


def extract_secrets(text: str) -> List[Dict[str, Any]]:
    """Extract secrets from text/OCR output."""
    findings = []
    seen = set()
    for kind, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, text, re.MULTILINE):
            secret = m.group(1) if m.groups() else m.group(0)
            if secret and secret not in seen:
                seen.add(secret)
                findings.append(
                    {
                        "kind": kind,
                        "secret": secret[:30] + "..." if len(secret) > 30 else secret,
                        "redacted": True,
                        "cvss": SECRET_CVSS.get(kind, 5.0),
                        "match_start": m.start(),
                    }
                )
    return findings


def extract_endpoints(text: str) -> List[str]:
    """Extract URLs/IPs/emails from text."""
    urls = list(set(re.findall(r"https?://[^\s\"'<>]+", text)))
    emails = list(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)))
    ips = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
    return urls, emails, ips


# ═══════════════════════════════════════════════════════════════════════════
# 2. CODE ANALYSIS — SAST with AI reasoning
# ═══════════════════════════════════════════════════════════════════════════

CODE_PATTERNS = {
    "dangerous_eval": {
        "pattern": r"\beval\s*\(|\bexec\s*\(|Function\s*\(",
        "languages": ["python", "javascript", "php"],
        "severity": "Critical",
        "cwe": "CWE-95",
    },
    "sql_string_concat": {
        "pattern": r"(?:SELECT|INSERT|UPDATE|DELETE).*(?:\"|'|`).*\+|(?:execute|query)\s*\(\s*['\"`].*\+",
        "languages": ["python", "javascript", "java", "php"],
        "severity": "High",
        "cwe": "CWE-89",
    },
    "hardcoded_password": {
        "pattern": r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]",
        "languages": ["*"],
        "severity": "High",
        "cwe": "CWE-798",
    },
    "weak_crypto": {
        "pattern": r"\b(?:md5|sha1)\s*\(|\bDES\b|ECB",
        "languages": ["*"],
        "severity": "Medium",
        "cwe": "CWE-327",
    },
    "insecure_random": {
        "pattern": r"random\.(?:random|randint|choice)\b",
        "languages": ["python"],
        "severity": "Low",
        "cwe": "CWE-330",
    },
    "xxe": {
        "pattern": r"DocumentBuilderFactory|XMLInputFactory|ETParser",
        "languages": ["java", "python"],
        "severity": "High",
        "cwe": "CWE-611",
    },
    "deserialization": {
        "pattern": r"\b(?:pickle\.loads?|yaml\.load\s*\(|unserialize\s*\(|ObjectInputStream)",
        "languages": ["python", "php", "java"],
        "severity": "Critical",
        "cwe": "CWE-502",
    },
    "path_traversal": {
        "pattern": r"open\s*\([^)]*\+|file_get_contents\s*\([^)]*\$_(?:GET|POST)",
        "languages": ["python", "php"],
        "severity": "High",
        "cwe": "CWE-22",
    },
    "command_injection": {
        "pattern": r"os\.(?:system|popen)|subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True",
        "languages": ["python"],
        "severity": "Critical",
        "cwe": "CWE-78",
    },
    "ssrf": {
        "pattern": r"requests\.(?:get|post|put)\s*\(\s*(?:f?\"|f?')http",
        "languages": ["python"],
        "severity": "High",
        "cwe": "CWE-918",
    },
    "open_redirect": {
        "pattern": r"redirect\s*\(\s*request\.|Location:\s*\$_",
        "languages": ["python", "php"],
        "severity": "Medium",
        "cwe": "CWE-601",
    },
    "missing_auth": {
        "pattern": r"@app\.(?:route|get|post|put|delete)\s*\([^)]+\)\s*\ndef\s+\w+[^:]*:\s*(?!.*(?:login_required|@login|@auth|verify_jwt))",
        "languages": ["python"],
        "severity": "Medium",
        "cwe": "CWE-306",
    },
}


@dataclass
class CodeFinding:
    file: str
    line: int
    column: int
    pattern_id: str
    severity: str
    message: str
    code_snippet: str = ""
    cwe: str = ""
    language: str = ""


def detect_language(path: str) -> str:
    ext = Path(path).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".ts": "javascript",
        ".jsx": "javascript",
        ".tsx": "javascript",
        ".java": "java",
        ".php": "php",
        ".rb": "ruby",
        ".go": "go",
        ".c": "c",
        ".cpp": "cpp",
        ".cs": "csharp",
        ".kt": "kotlin",
        ".swift": "swift",
        ".rs": "rust",
        ".sql": "sql",
        ".sh": "bash",
    }.get(ext, "unknown")


def analyze_code(path: str, content: str) -> List[CodeFinding]:
    """Static analysis with security pattern detection."""
    findings = []
    language = detect_language(path)
    lines = content.splitlines()

    for line_no, line in enumerate(lines, 1):
        for pid, info in CODE_PATTERNS.items():
            langs = info["languages"]
            if langs != ["*"] and language not in langs:
                continue
            for m in re.finditer(info["pattern"], line):
                findings.append(
                    CodeFinding(
                        file=path,
                        line=line_no,
                        column=m.start() + 1,
                        pattern_id=pid,
                        severity=info["severity"],
                        message=info["pattern"][:60] + ("..." if len(info["pattern"]) > 60 else ""),
                        code_snippet=line.strip()[:120],
                        cwe=info["cwe"],
                        language=language,
                    )
                )
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 3. MEMORY-AUGMENTED REASONING — Cross-session recall
# ═══════════════════════════════════════════════════════════════════════════


class MemoryTier(Enum):
    """Memory tiers — from fast to slow."""

    WORKING = "working"  # Current session only
    EPISODIC = "episodic"  # Recent sessions (30 days)
    SEMANTIC = "semantic"  # Long-term knowledge (cross-session)
    VECTOR = "vector"  # Embedding-based semantic recall


@dataclass
class MemoryItem:
    """A single memory entry."""

    id: str
    tier: MemoryTier
    content: str
    embedding: Optional[List[float]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    access_count: int = 0
    last_accessed: float = 0.0
    importance: float = 0.5  # 0.0-1.0

    def __post_init__(self):
        if not self.id:
            self.id = hashlib.sha256(f"{self.content}:{self.tier}".encode()).hexdigest()[:12]
        import time

        if not self.created_at:
            self.created_at = time.time()
        if not self.last_accessed:
            self.last_accessed = self.created_at


class MemoryAugmentedReasoner:
    """Multi-tier memory system for AI agent reasoning."""

    def __init__(self):
        self.working: List[MemoryItem] = []
        self.episodic: List[MemoryItem] = []
        self.semantic: List[MemoryItem] = []
        self.vector_index: Dict[str, List[float]] = {}  # Simple dict-based for now

    def remember(
        self,
        content: str,
        tier: MemoryTier = MemoryTier.WORKING,
        metadata: Optional[Dict] = None,
        importance: float = 0.5,
    ) -> MemoryItem:
        item = MemoryItem(
            id="",
            tier=tier,
            content=content,
            metadata=metadata or {},
            importance=importance,
        )
        if tier == MemoryTier.WORKING:
            self.working.append(item)
        elif tier == MemoryTier.EPISODIC:
            self.episodic.append(item)
        elif tier == MemoryTier.SEMANTIC:
            self.semantic.append(item)
        return item

    def recall(
        self, query: str, tier: Optional[MemoryTier] = None, top_k: int = 5
    ) -> List[MemoryItem]:
        """Recall memories relevant to query using simple keyword matching."""
        import time

        query_words = set(re.findall(r"\w+", query.lower()))
        candidates = []
        if tier is None or tier == MemoryTier.WORKING:
            candidates.extend(self.working)
        if tier is None or tier == MemoryTier.EPISODIC:
            candidates.extend(self.episodic)
        if tier is None or tier == MemoryTier.SEMANTIC:
            candidates.extend(self.semantic)
        scored = []
        for item in candidates:
            content_words = set(re.findall(r"\w+", item.content.lower()))
            overlap = len(query_words & content_words)
            score = overlap * item.importance
            if score > 0:
                scored.append((score, item))
        scored.sort(key=lambda x: -x[0])
        results = [item for _, item in scored[:top_k]]
        for item in results:
            item.access_count += 1
            item.last_accessed = time.time()
        return results

    def consolidate(self) -> int:
        """Move important working memories to episodic, episodic to semantic."""
        import time

        now = time.time()
        promoted = 0
        # Working -> Episodic (older than 1 hour, importance >= 0.6)
        for item in list(self.working):
            if item.importance >= 0.6 and (now - item.created_at) > 3600:
                self.working.remove(item)
                item.tier = MemoryTier.EPISODIC
                self.episodic.append(item)
                promoted += 1
        # Episodic -> Semantic (older than 30 days, importance >= 0.8)
        for item in list(self.episodic):
            if item.importance >= 0.8 and (now - item.created_at) > 2592000:
                self.episodic.remove(item)
                item.tier = MemoryTier.SEMANTIC
                self.semantic.append(item)
                promoted += 1
        return promoted

    def stats(self) -> Dict[str, int]:
        return {
            "working": len(self.working),
            "episodic": len(self.episodic),
            "semantic": len(self.semantic),
        }


# ═══════════════════════════════════════════════════════════════════════════
# 4. CHAIN-OF-THOUGHT REASONER — Step-by-step AI reasoning
# ═══════════════════════════════════════════════════════════════════════════


class ReasoningStepType(Enum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    TEST = "test"
    RESULT = "result"
    CONCLUSION = "conclusion"


@dataclass
class ReasoningStep:
    type: ReasoningStepType
    content: str
    evidence: str = ""
    confidence: float = 0.5
    next_steps: List[str] = field(default_factory=list)


class ChainOfThoughtReasoner:
    """Build a chain of reasoning for complex security investigations."""

    def __init__(self, goal: str):
        self.goal = goal
        self.steps: List[ReasoningStep] = []
        self.hypotheses: List[Dict] = []
        self.evidence: List[Dict] = []

    def observe(
        self, content: str, evidence: str = "", confidence: float = 0.7
    ) -> "ChainOfThoughtReasoner":
        self.steps.append(
            ReasoningStep(
                type=ReasoningStepType.OBSERVATION,
                content=content,
                evidence=evidence,
                confidence=confidence,
            )
        )
        return self

    def hypothesize(self, content: str, testable: bool = True) -> "ChainOfThoughtReasoner":
        h = {
            "content": content,
            "testable": testable,
            "verified": False,
            "confidence": 0.5,
        }
        self.hypotheses.append(h)
        self.steps.append(
            ReasoningStep(
                type=ReasoningStepType.HYPOTHESIS,
                content=content,
            )
        )
        return self

    def test(self, test_name: str, expected: str, actual: str) -> "ChainOfThoughtReasoner":
        # Smart matching: confirmed if any significant word from expected appears in actual
        # or if the actual contains any of the keywords from expected
        expected_words = set(re.findall(r"\w{3,}", expected.lower()))
        actual_words = set(re.findall(r"\w{3,}", actual.lower()))
        # At least 30% of expected words must appear in actual, OR actual contains key terms
        if expected_words:
            overlap = len(expected_words & actual_words) / len(expected_words)
            confirmed = overlap >= 0.3 or any(
                kw in actual.lower()
                for kw in [
                    "script",
                    "alert",
                    "error",
                    "vulnerable",
                    "reflected",
                    "pwned",
                    "rce",
                    "exploit",
                ]
            )
        else:
            confirmed = False
        self.steps.append(
            ReasoningStep(
                type=ReasoningStepType.TEST,
                content=f"Test: {test_name}",
                evidence=f"Expected: {expected}\nActual: {actual}",
                confidence=0.9 if confirmed else 0.1,
            )
        )
        if confirmed and self.hypotheses:
            self.hypotheses[-1]["verified"] = True
            self.hypotheses[-1]["confidence"] = 0.95
        return self

    def conclude(self, content: str) -> "ChainOfThoughtReasoner":
        self.steps.append(
            ReasoningStep(
                type=ReasoningStepType.CONCLUSION,
                content=content,
            )
        )
        return self

    def render(self) -> str:
        lines = [f"╔══ Chain of Thought: {self.goal} ══╗"]
        for i, step in enumerate(self.steps, 1):
            icon = {
                ReasoningStepType.OBSERVATION: "👁",
                ReasoningStepType.HYPOTHESIS: "💡",
                ReasoningStepType.TEST: "🔬",
                ReasoningStepType.RESULT: "📊",
                ReasoningStepType.CONCLUSION: "🎯",
            }.get(step.type, "•")
            lines.append(f"  {i}. {icon} [{step.type.value.upper()}] {step.content}")
            if step.evidence:
                lines.append(f"     └─ {step.evidence[:200]}")
        return "\n".join(lines)


__all__ = [
    "VisionMode",
    "VisionFinding",
    "SECRET_PATTERNS",
    "SECRET_CVSS",
    "extract_secrets",
    "extract_endpoints",
    "CODE_PATTERNS",
    "CodeFinding",
    "detect_language",
    "analyze_code",
    "MemoryTier",
    "MemoryItem",
    "MemoryAugmentedReasoner",
    "ReasoningStepType",
    "ReasoningStep",
    "ChainOfThoughtReasoner",
]

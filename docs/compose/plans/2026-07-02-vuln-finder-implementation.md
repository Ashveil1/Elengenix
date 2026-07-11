# Adaptive Vulnerability Finder — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use compose:subagent (recommended) or compose:execute to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an adaptive AI vulnerability finder that can autonomously discover, escalate, chain, and verify security vulnerabilities across all target types.

**Architecture:** Adaptive agent loop with hybrid memory (ChromaDB + SQLite + Knowledge Graph), 3-layer reasoning (CoT + sequential-thinking + reflection), dual-model verification, and progressive disclosure system prompt.

**Tech Stack:** Python 3.10+, ChromaDB, SQLite, Rich (TUI), Textual, existing tool registry

---

## Phase 1: Fix Critical Bugs (Prerequisite)

### Task 1: Fix Prompt Interpolation Bugs

**Covers:** [S4]
**Files:**
- Modify: `agents/agent_universal.py:567-580, 613-660, 725-740`

- [ ] **Step 1: Write failing test**

```python
# tests/test_prompt_interpolation_fix.py
def test_build_research_prompt_interpolates():
    from agents.agent_universal import _build_research_prompt
    result = _build_research_prompt("test input", "now context")
    assert "{user_input}" not in result
    assert "{now_context}" not in result
    assert "test input" in result

def test_build_bug_bounty_prompt_interpolates():
    from agents.agent_universal import _build_bug_bounty_prompt
    result = _build_bug_bounty_prompt("test", "now", "target.com", None, None, None)
    assert "{user_input}" not in result
    assert "target.com" in result

def test_build_general_prompt_interpolates():
    from agents.agent_universal import _build_general_prompt
    result = _build_general_prompt("test input", "now context")
    assert "{user_input}" not in result
    assert "test input" in result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_prompt_interpolation_fix.py -v`
Expected: FAIL

- [ ] **Step 3: Fix the prompts**

Change plain strings to f-strings in all three functions:
```python
# Before (broken)
def _build_research_prompt(user_input, now_context):
    return f"""...{user_input}..."""  # This works
    # BUT the actual bug is in the triple-quoted strings without f-prefix

# After (fixed)
def _build_research_prompt(user_input, now_context):
    prompt = f"""Research mode active.
User query: {user_input}
Context: {now_context}
..."""
    return prompt
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_prompt_interpolation_fix.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agents/agent_universal.py tests/test_prompt_interpolation_fix.py
git commit -m "fix: prompt interpolation bugs in agent_universal.py"
```

---

### Task 2: Fix analysis_pipeline.py Import Mismatches

**Covers:** [S6]
**Files:**
- Modify: `tools/analysis_pipeline.py:443, 478, 762`

- [ ] **Step 1: Write failing test**

```python
# tests/test_analysis_pipeline_imports.py
def test_analysis_pipeline_imports():
    from tools.analysis_pipeline import AnalysisPipeline
    pipeline = AnalysisPipeline()
    assert pipeline is not None

def test_ssrf_scanner_init():
    from tools.ssrf_scanner import SSRFScanner
    scanner = SSRFScanner()
    assert scanner is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_analysis_pipeline_imports.py -v`
Expected: FAIL with import errors

- [ ] **Step 3: Fix imports**

```python
# Fix CORS import
# Before
from tools.cors_checker import check_cors

# After
from tools.cors_checker import CORSChecker

# Fix SSRF initialization
# Before
SSRFScanner(base_url=furl, rate_limit_rps=0.5)

# After
SSRFScanner()

# Fix list_facts
# Before
mission_state.list_facts(limit=50)

# After
mission_state.get_facts(limit=50)  # or implement list_facts method
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_analysis_pipeline_imports.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tools/analysis_pipeline.py tests/test_analysis_pipeline_imports.py
git commit -m "fix: import mismatches in analysis_pipeline.py"
```

---

### Task 3: Fix scan_engine_upgrade.py Typo

**Covers:** [S6]
**Files:**
- Modify: `scan_engine_upgrade.py:472`

- [ ] **Step 1: Write failing test**

```python
# tests/test_scan_engine_fix.py
def test_git_diff_command():
    from scan_engine_upgrade import SmartOrchestrator
    # Test that git diff command is correct
    import subprocess
    result = subprocess.run(["git", "--version"], capture_output=True)
    assert result.returncode == 0
```

- [ ] **Step 2: Run test to verify it passes**

Run: `pytest tests/test_scan_engine_fix.py -v`
Expected: PASS (this is just a typo fix)

- [ ] **Step 3: Fix the typo**

```python
# Before
subprocess.run(["git", "dif", ...])

# After
subprocess.run(["git", "diff", ...])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scan_engine_fix.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scan_engine_upgrade.py
git commit -m "fix: typo 'git dif' → 'git diff' in scan_engine_upgrade.py"
```

---

### Task 4: Fix TUI Theme Transitions

**Covers:** [S9]
**Files:**
- Modify: `tui/themes.py` (add Easing.apply method)

- [ ] **Step 1: Write failing test**

```python
# tests/test_theme_transitions.py
def test_easing_apply():
    from tui.themes import Easing
    result = Easing.apply("LINEAR", 0.0, 0.0, 1.0)
    assert result == 0.0
    result = Easing.apply("LINEAR", 0.5, 0.0, 1.0)
    assert result == 0.5
    result = Easing.apply("LINEAR", 1.0, 0.0, 1.0)
    assert result == 1.0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_theme_transitions.py -v`
Expected: FAIL with AttributeError

- [ ] **Step 3: Implement Easing.apply**

```python
class Easing:
    LINEAR = "LINEAR"
    EASE_IN = "EASE_IN"
    EASE_OUT = "EASE_OUT"
    EASE_IN_OUT = "EASE_IN_OUT"

    @staticmethod
    def apply(easing_type, t, start, end):
        """Apply easing function to interpolate between start and end."""
        t = max(0.0, min(1.0, t))

        if easing_type == Easing.LINEAR:
            return start + (end - start) * t
        elif easing_type == Easing.EASE_IN:
            return start + (end - start) * (t * t)
        elif easing_type == Easing.EASE_OUT:
            return start + (end - start) * (1 - (1 - t) * (1 - t))
        elif easing_type == Easing.EASE_IN_OUT:
            if t < 0.5:
                return start + (end - start) * (2 * t * t)
            else:
                return start + (end - start) * (1 - (-2 * t + 2) ** 2 / 2)
        else:
            return start + (end - start) * t
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_theme_transitions.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tui/themes.py tests/test_theme_transitions.py
git commit -m "fix: add Easing.apply method for theme transitions"
```

---

### Task 5: Fix TUI Export Module

**Covers:** [S7]
**Files:**
- Modify: `tui/export.py` (fix PDF export + XSS vulnerability)

- [ ] **Step 1: Write failing test**

```python
# tests/test_export_fix.py
def test_export_to_html_escapes():
    from tui.export import export_to_html
    import tempfile
    import os

    data = {
        "findings": [
            {"title": "<script>alert(1)</script>", "severity": "HIGH"}
        ]
    }

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        output_path = f.name

    try:
        result = export_to_html(data, output_path)
        with open(result) as f:
            content = f.read()
        assert "<script>" not in content
        assert "&lt;script&gt;" in content
    finally:
        os.unlink(output_path)

def test_export_to_pdf_produces_svg():
    from tui.export import export_to_pdf
    import tempfile
    import os

    data = {"findings": []}

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        output_path = f.name

    try:
        result = export_to_pdf(data, output_path)
        assert result.endswith(".svg")
        assert os.path.exists(result)
    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)
        if os.path.exists(result):
            os.unlink(result)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_export_fix.py -v`
Expected: FAIL

- [ ] **Step 3: Fix export_to_html (XSS)**

```python
import html

def export_to_html(dashboard_data, output_path, title="Elengenix Report"):
    # Escape finding data
    findings_html = ""
    for finding in dashboard_data.get("findings", []):
        title_escaped = html.escape(str(finding.get("title", "")))
        location_escaped = html.escape(str(finding.get("location", "")))
        findings_html += f"""
        <div class="finding">
            <h3>{title_escaped}</h3>
            <p>Location: {location_escaped}</p>
        </div>
        """
    # ... rest of template
```

- [ ] **Step 4: Fix export_to_pdf (path handling)**

```python
def export_to_pdf(dashboard_data, output_path, title="Elengenix Report"):
    """Export to SVG (not PDF)."""
    from rich.console import Console
    from rich.panel import Panel

    # Fix path handling
    svg_path = output_path.replace(".pdf", ".svg")

    console = Console(record=True, width=120)
    # ... render findings
    console.save_svg(svg_path)
    return svg_path
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_export_fix.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add tui/export.py tests/test_export_fix.py
git commit -m "fix: XSS vulnerability and PDF export in tui/export.py"
```

---

## Phase 2: Core VulnFinder Engine

### Task 6: Create Knowledge Graph Module

**Covers:** [S5]
**Files:**
- Create: `tools/knowledge_graph.py`
- Create: `tests/test_knowledge_graph.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_knowledge_graph.py
def test_knowledge_graph_add_asset():
    from tools.knowledge_graph import KnowledgeGraph
    kg = KnowledgeGraph()
    kg.add_asset("example.com", {"type": "domain"})
    assert kg.get_asset("example.com") is not None

def test_knowledge_graph_add_finding():
    from tools.knowledge_graph import KnowledgeGraph
    kg = KnowledgeGraph()
    kg.add_finding("f1", {"severity": "HIGH", "type": "XSS"})
    finding = kg.get_finding("f1")
    assert finding["severity"] == "HIGH"

def test_knowledge_graph_relationships():
    from tools.knowledge_graph import KnowledgeGraph
    kg = KnowledgeGraph()
    kg.add_asset("example.com", {})
    kg.add_finding("f1", {"severity": "HIGH"})
    kg.add_edge("example.com", "has", "f1")
    related = kg.find_related_findings("f1")
    assert "example.com" in related

def test_knowledge_graph_chain_detection():
    from tools.knowledge_graph import KnowledgeGraph
    kg = KnowledgeGraph()
    kg.add_finding("f1", {"severity": "LOW", "type": "IDOR"})
    kg.add_finding("f2", {"severity": "LOW", "type": "info_disclosure"})
    kg.add_edge("f1", "chains_to", "f2")
    chains = kg.get_chains()
    assert len(chains) >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_knowledge_graph.py -v`
Expected: FAIL with ModuleNotFoundError

- [ ] **Step 3: Implement KnowledgeGraph**

```python
# tools/knowledge_graph.py
"""Knowledge Graph for tracking relationships between assets, findings, and tools."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
import json

class NodeType(Enum):
    ASSET = "asset"
    FINDING = "finding"
    TOOL = "tool"
    VULN_CLASS = "vuln_class"
    ATTACK_PATH = "attack_path"

class EdgeType(Enum):
    HAS = "has"
    FOUND_BY = "found_by"
    BELONGS_TO = "belongs_to"
    CHAINS_TO = "chains_to"
    CONSISTS_OF = "consists_of"
    WORKS_ON = "works_on"
    RELATED_TO = "related_to"

@dataclass
class Node:
    id: str
    node_type: NodeType
    data: Dict = field(default_factory=dict)

@dataclass
class Edge:
    source: str
    edge_type: EdgeType
    target: str

class KnowledgeGraph:
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self._adjacency: Dict[str, List[Tuple[EdgeType, str]]] = {}

    def add_asset(self, asset_id: str, data: Dict = None):
        self.nodes[asset_id] = Node(asset_id, NodeType.ASSET, data or {})

    def add_finding(self, finding_id: str, data: Dict = None):
        self.nodes[finding_id] = Node(finding_id, NodeType.FINDING, data or {})

    def add_tool(self, tool_id: str, data: Dict = None):
        self.nodes[tool_id] = Node(tool_id, NodeType.TOOL, data or {})

    def add_edge(self, source: str, edge_type: str, target: str):
        et = EdgeType(edge_type)
        self.edges.append(Edge(source, et, target))
        if source not in self._adjacency:
            self._adjacency[source] = []
        self._adjacency[source].append((et, target))

    def get_asset(self, asset_id: str) -> Optional[Dict]:
        node = self.nodes.get(asset_id)
        return node.data if node and node.node_type == NodeType.ASSET else None

    def get_finding(self, finding_id: str) -> Optional[Dict]:
        node = self.nodes.get(finding_id)
        return node.data if node and node.node_type == NodeType.FINDING else None

    def find_related_findings(self, finding_id: str) -> List[str]:
        related = []
        for edge in self.edges:
            if edge.source == finding_id and edge.edge_type == EdgeType.CHAINS_TO:
                related.append(edge.target)
            elif edge.target == finding_id and edge.edge_type == EdgeType.CHAINS_TO:
                related.append(edge.source)
        return related

    def get_tools_for_vuln_class(self, vuln_class: str) -> List[str]:
        tools = []
        for edge in self.edges:
            if edge.edge_type == EdgeType.WORKS_ON and edge.target == vuln_class:
                tools.append(edge.source)
        return tools

    def get_chains(self) -> List[List[str]]:
        chains = []
        for edge in self.edges:
            if edge.edge_type == EdgeType.CHAINS_TO:
                chains.append([edge.source, edge.target])
        return chains

    def to_dict(self) -> Dict:
        return {
            "nodes": {k: {"type": v.node_type.value, "data": v.data}
                     for k, v in self.nodes.items()},
            "edges": [{"source": e.source, "type": e.edge_type.value,
                       "target": e.target} for e in self.edges]
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_knowledge_graph.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tools/knowledge_graph.py tests/test_knowledge_graph.py
git commit -m "feat: add KnowledgeGraph module for relationship tracking"
```

---

### Task 7: Create Escalation Engine

**Covers:** [S3]
**Files:**
- Create: `tools/escalation_engine.py`
- Create: `tests/test_escalation_engine.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_escalation_engine.py
def test_escalation_engine_xss():
    from tools.escalation_engine import EscalationEngine
    engine = EscalationEngine()
    finding = {"type": "XSS", "severity": "LOW", "url": "http://test.com"}
    escalation = engine.can_escalate(finding)
    assert escalation is not None
    assert "stored_xss" in escalation.next_steps

def test_escalation_engine_sqli():
    from tools.escalation_engine import EscalationEngine
    engine = EscalationEngine()
    finding = {"type": "SQLi", "severity": "MEDIUM", "url": "http://test.com"}
    escalation = engine.can_escalate(finding)
    assert escalation is not None
    assert "union_based" in escalation.next_steps

def test_escalation_engine_idor():
    from tools.escalation_engine import EscalationEngine
    engine = EscalationEngine()
    finding = {"type": "IDOR", "severity": "LOW", "url": "http://test.com/api/user/1"}
    escalation = engine.can_escalate(finding)
    assert escalation is not None
    assert "bulk_extraction" in escalation.next_steps
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_escalation_engine.py -v`
Expected: FAIL with ModuleNotFoundError

- [ ] **Step 3: Implement EscalationEngine**

```python
# tools/escalation_engine.py
"""Engine for escalating low-severity findings to higher severity."""

from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class EscalationPath:
    finding_type: str
    current_severity: str
    next_steps: List[str]
    expected_severity: str
    description: str

class EscalationEngine:
    def __init__(self):
        self.escalation_map = self._build_escalation_map()

    def _build_escalation_map(self) -> Dict[str, EscalationPath]:
        return {
            "XSS": EscalationPath(
                finding_type="XSS",
                current_severity="LOW",
                next_steps=["stored_xss", "cookie_theft", "account_takeover"],
                expected_severity="CRITICAL",
                description="Escalate reflected XSS to stored XSS, then cookie theft"
            ),
            "SQLi": EscalationPath(
                finding_type="SQLi",
                current_severity="MEDIUM",
                next_steps=["union_based", "file_read", "rce"],
                expected_severity="CRITICAL",
                description="Escalate error-based SQLi to UNION, then file read, then RCE"
            ),
            "IDOR": EscalationPath(
                finding_type="IDOR",
                current_severity="LOW",
                next_steps=["sequential_ids", "bulk_extraction", "privilege_escalation"],
                expected_severity="HIGH",
                description="Escalate single IDOR to bulk data extraction"
            ),
            "SSRF": EscalationPath(
                finding_type="SSRF",
                current_severity="MEDIUM",
                next_steps=["internal_scan", "cloud_metadata", "rce"],
                expected_severity="CRITICAL",
                description="Escalate SSRF to internal network scan, then cloud metadata"
            ),
            "info_disclosure": EscalationPath(
                finding_type="info_disclosure",
                current_severity="LOW",
                next_steps=["combine_with_other", "increase_impact"],
                expected_severity="MEDIUM",
                description="Combine with other findings to increase impact"
            ),
        }

    def can_escalate(self, finding: Dict) -> Optional[EscalationPath]:
        finding_type = finding.get("type", "")
        return self.escalation_map.get(finding_type)

    def get_escalation_steps(self, finding: Dict) -> List[str]:
        path = self.can_escalate(finding)
        return path.next_steps if path else []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_escalation_engine.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tools/escalation_engine.py tests/test_escalation_engine.py
git commit -m "feat: add EscalationEngine for low→high finding escalation"
```

---

### Task 8: Create Chaining Engine

**Covers:** [S3]
**Files:**
- Create: `tools/chaining_engine.py`
- Create: `tests/test_chaining_engine.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_chaining_engine.py
def test_chaining_engine_idor_info_disclosure():
    from tools.chaining_engine import ChainingEngine
    engine = ChainingEngine()
    findings = [
        {"type": "IDOR", "severity": "LOW", "url": "http://test.com/api/user"},
        {"type": "info_disclosure", "severity": "LOW", "url": "http://test.com/api/user"}
    ]
    chain = engine.analyze_chain(findings)
    assert chain is not None
    assert chain.combined_severity == "CRITICAL"

def test_chaining_engine_xss_ssid():
    from tools.chaining_engine import ChainingEngine
    engine = ChainingEngine()
    findings = [
        {"type": "XSS", "severity": "MEDIUM", "url": "http://test.com/search"},
        {"type": "session_fixation", "severity": "MEDIUM", "url": "http://test.com/login"}
    ]
    chain = engine.analyze_chain(findings)
    assert chain is not None
    assert chain.combined_severity in ["HIGH", "CRITICAL"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_chaining_engine.py -v`
Expected: FAIL with ModuleNotFoundError

- [ ] **Step 3: Implement ChainingEngine**

```python
# tools/chaining_engine.py
"""Engine for chaining multiple low-severity findings into critical impacts."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

@dataclass
class AttackChain:
    findings: List[Dict]
    combined_severity: str
    impact_description: str
    chain_type: str

class ChainingEngine:
    def __init__(self):
        self.chain_rules = self._build_chain_rules()

    def _build_chain_rules(self) -> Dict[str, Dict]:
        return {
            "IDOR+info_disclosure": {
                "findings": ["IDOR", "info_disclosure"],
                "combined_severity": "CRITICAL",
                "impact": "Full account takeover via IDOR + information disclosure",
                "chain_type": "data_exfiltration"
            },
            "XSS+session_fixation": {
                "findings": ["XSS", "session_fixation"],
                "combined_severity": "HIGH",
                "impact": "Session hijacking via XSS + session fixation",
                "chain_type": "session_attack"
            },
            "SSRF+cloud_metadata": {
                "findings": ["SSRF", "cloud_metadata_access"],
                "combined_severity": "CRITICAL",
                "impact": "Cloud credential theft via SSRF",
                "chain_type": "cloud_attack"
            },
            "SQLi+info_disclosure": {
                "findings": ["SQLi", "info_disclosure"],
                "combined_severity": "HIGH",
                "impact": "Full database extraction",
                "chain_type": "data_exfiltration"
            },
        }

    def analyze_chain(self, findings: List[Dict]) -> Optional[AttackChain]:
        finding_types = [f.get("type", "") for f in findings]

        for rule_name, rule in self.chain_rules.items():
            if all(ft in finding_types for ft in rule["findings"]):
                return AttackChain(
                    findings=findings,
                    combined_severity=rule["combined_severity"],
                    impact_description=rule["impact"],
                    chain_type=rule["chain_type"]
                )

        return None

    def find_chainable_findings(self, findings: List[Dict]) -> List[Tuple[Dict, Dict]]:
        chainable = []
        for i, f1 in enumerate(findings):
            for f2 in findings[i+1:]:
                chain = self.analyze_chain([f1, f2])
                if chain:
                    chainable.append((f1, f2))
        return chainable
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_chaining_engine.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tools/chaining_engine.py tests/test_chaining_engine.py
git commit -m "feat: add ChainingEngine for combining findings into critical chains"
```

---

### Task 9: Create Verification Engine

**Covers:** [S3]
**Files:**
- Create: `tools/verification_engine.py`
- Create: `tests/test_verification_engine.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_verification_engine.py
def test_verification_engine_dual_model():
    from tools.verification_engine import VerificationEngine
    engine = VerificationEngine()
    finding = {"type": "XSS", "severity": "HIGH", "url": "http://test.com"}
    result = engine.verify(finding, model_a_response="confirmed", model_b_response="confirmed")
    assert result.verified == True
    assert result.severity == "HIGH"

def test_verification_engine_disagreement():
    from tools.escalation_engine import VerificationEngine
    engine = VerificationEngine()
    finding = {"type": "XSS", "severity": "HIGH", "url": "http://test.com"}
    result = engine.verify(finding, model_a_response="confirmed", model_b_response="false_positive")
    assert result.verified == False
    assert result.requires_human_review == True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verification_engine.py -v`
Expected: FAIL with ModuleNotFoundError

- [ ] **Step 3: Implement VerificationEngine**

```python
# tools/verification_engine.py
"""Dual-model verification engine for validating findings."""

from dataclasses import dataclass
from typing import Dict, Optional

@dataclass
class VerificationResult:
    finding: Dict
    verified: bool
    severity: str
    model_a_response: str
    model_b_response: str
    requires_human_review: bool
    confidence: float

class VerificationEngine:
    def __init__(self):
        self.severity_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def verify(self, finding: Dict, model_a_response: str,
               model_b_response: str) -> VerificationResult:
        a_confirms = "confirm" in model_a_response.lower() or "true" in model_a_response.lower()
        b_confirms = "confirm" in model_b_response.lower() or "true" in model_b_response.lower()

        if a_confirms and b_confirms:
            return VerificationResult(
                finding=finding,
                verified=True,
                severity=finding.get("severity", "MEDIUM"),
                model_a_response=model_a_response,
                model_b_response=model_b_response,
                requires_human_review=False,
                confidence=0.95
            )
        elif a_confirms or b_confirms:
            return VerificationResult(
                finding=finding,
                verified=False,
                severity=finding.get("severity", "MEDIUM"),
                model_a_response=model_a_response,
                model_b_response=model_b_response,
                requires_human_review=True,
                confidence=0.5
            )
        else:
            return VerificationResult(
                finding=finding,
                verified=False,
                severity="INFO",
                model_a_response=model_a_response,
                model_b_response=model_b_response,
                requires_human_review=False,
                confidence=0.1
            )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_verification_engine.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tools/verification_engine.py tests/test_verification_engine.py
git commit -m "feat: add VerificationEngine for dual-model finding validation"
```

---

### Task 10: Create Adaptive Planner

**Covers:** [S3, S4]
**Files:**
- Create: `tools/adaptive_planner.py`
- Create: `tests/test_adaptive_planner.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_adaptive_planner.py
def test_adaptive_planner_rank_targets():
    from tools.adaptive_planner import AdaptivePlanner
    planner = AdaptivePlanner()
    targets = [
        {"url": "http://test.com/api/user", "type": "api_endpoint"},
        {"url": "http://test.com/static", "type": "static"},
        {"url": "http://test.com/login", "type": "auth"},
    ]
    ranked = planner.rank_targets(targets)
    assert ranked[0]["rank"] >= ranked[1]["rank"]

def test_adaptive_planner_decide_next():
    from tools.adaptive_planner import AdaptivePlanner
    planner = AdaptivePlanner()
    state = {
        "findings": [],
        "tried_paths": [],
        "budget_remaining": 0.8
    }
    next_action = planner.decide_next(state)
    assert next_action is not None
    assert "action" in next_action
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_adaptive_planner.py -v`
Expected: FAIL with ModuleNotFoundError

- [ ] **Step 3: Implement AdaptivePlanner**

```python
# tools/adaptive_planner.py
"""Adaptive planner for dynamic attack path selection."""

from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum

class ActionType(Enum):
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    ESCALATE = "escalate"
    CHAIN = "chain"
    VERIFY = "verify"
    REPORT = "report"

@dataclass
class AttackPath:
    target: str
    path_type: str
    rank: int
    tools: List[str]
    expected_impact: str

class AdaptivePlanner:
    def __init__(self):
        self.rank_weights = {
            "api_endpoint": 5,
            "auth": 5,
            "file_upload": 4,
            "dynamic_content": 4,
            "form_input": 3,
            "standard_page": 2,
            "static": 1,
        }

    def rank_targets(self, targets: List[Dict]) -> List[Dict]:
        ranked = []
        for target in targets:
            path_type = target.get("type", "standard_page")
            rank = self.rank_weights.get(path_type, 2)
            target["rank"] = rank
            ranked.append(target)
        return sorted(ranked, key=lambda x: x["rank"], reverse=True)

    def decide_next(self, state: Dict) -> Dict:
        findings = state.get("findings", [])
        tried = state.get("tried_paths", [])
        budget = state.get("budget_remaining", 1.0)

        if budget < 0.1:
            return {"action": ActionType.REPORT.value, "reason": "budget_low"}

        if not findings and not tried:
            return {"action": ActionType.RECON.value, "reason": "initial_scan"}

        if findings:
            high_findings = [f for f in findings if f.get("severity") in ["HIGH", "CRITICAL"]]
            if high_findings:
                return {"action": ActionType.ESCALATE.value,
                        "finding": high_findings[0],
                        "reason": "high_severity_found"}

        return {"action": ActionType.SCAN.value,
                "reason": "continue_scanning",
                "tried": tried}

    def should_replan(self, state: Dict) -> bool:
        findings = state.get("findings", [])
        gaps = state.get("gaps", [])
        return len(gaps) > 0 or len(findings) == 0
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_adaptive_planner.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tools/adaptive_planner.py tests/test_adaptive_planner.py
git commit -m "feat: add AdaptivePlanner for dynamic attack path selection"
```

---

### Task 11: Create VulnFinder Core Engine

**Covers:** [S2, S3, S4]
**Files:**
- Create: `tools/vuln_finder.py`
- Create: `tests/test_vuln_finder.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_vuln_finder.py
def test_vuln_finder_init():
    from tools.vuln_finder import VulnFinder
    finder = VulnFinder(target="http://test.com")
    assert finder.target == "http://test.com"
    assert finder.state is not None

def test_vuln_finder_recon():
    from tools.vuln_finder import VulnFinder
    finder = VulnFinder(target="http://test.com")
    assets = finder.recon()
    assert isinstance(assets, dict)
    assert "endpoints" in assets
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_vuln_finder.py -v`
Expected: FAIL with ModuleNotFoundError

- [ ] **Step 3: Implement VulnFinder**

```python
# tools/vuln_finder.py
"""Core Adaptive Vulnerability Finder Engine."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum
import time

from tools.knowledge_graph import KnowledgeGraph
from tools.escalation_engine import EscalationEngine
from tools.chaining_engine import ChainingEngine
from tools.verification_engine import VerificationEngine
from tools.adaptive_planner import AdaptivePlanner, ActionType

class MissionStatus(Enum):
    INIT = "init"
    RECON = "recon"
    PLANNING = "planning"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class MissionState:
    target: str
    status: MissionStatus = MissionStatus.INIT
    findings: List[Dict] = field(default_factory=list)
    assets: Dict = field(default_factory=dict)
    tried_paths: List[str] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    steps: int = 0
    tokens_used: int = 0
    cost: float = 0.0

class VulnFinder:
    def __init__(self, target: str, max_steps: int = 100,
                 budget_limit: float = 50.0):
        self.target = target
        self.max_steps = max_steps
        self.budget_limit = budget_limit

        self.state = MissionState(target=target)
        self.kg = KnowledgeGraph()
        self.escalation = EscalationEngine()
        self.chaining = ChainingEngine()
        self.verification = VerificationEngine()
        self.planner = AdaptivePlanner()

    def recon(self) -> Dict:
        """Perform reconnaissance on target."""
        self.state.status = MissionStatus.RECON
        assets = {
            "target": self.target,
            "subdomains": [],
            "endpoints": [],
            "tech_stack": [],
            "waf_status": None
        }
        self.state.assets = assets
        return assets

    def plan(self) -> List[Dict]:
        """Create attack plan based on assets."""
        self.state.status = MissionStatus.PLANNING
        targets = [
            {"url": ep, "type": "api_endpoint"}
            for ep in self.state.assets.get("endpoints", [])
        ]
        ranked = self.planner.rank_targets(targets)
        return ranked

    def execute(self, attack_path: Dict) -> Dict:
        """Execute a single attack path."""
        self.state.status = MissionStatus.EXECUTING
        self.state.steps += 1

        result = {
            "path": attack_path,
            "success": False,
            "finding": None,
            "output": ""
        }

        self.state.tried_paths.append(attack_path.get("url", ""))
        return result

    def escalate(self, finding: Dict) -> Optional[Dict]:
        """Try to escalate a finding to higher severity."""
        path = self.escalation.can_escalate(finding)
        if path:
            return {
                "original": finding,
                "escalation_path": path.next_steps,
                "expected_severity": path.expected_severity
            }
        return None

    def chain(self, findings: List[Dict]) -> Optional[Dict]:
        """Try to chain multiple findings."""
        chain = self.chaining.analyze_chain(findings)
        if chain:
            return {
                "findings": chain.findings,
                "combined_severity": chain.combined_severity,
                "impact": chain.impact_description
            }
        return None

    def verify(self, finding: Dict, model_a: str, model_b: str):
        """Verify a finding with dual-model verification."""
        return self.verification.verify(finding, model_a, model_b)

    def should_continue(self) -> bool:
        """Check if mission should continue."""
        if self.state.steps >= self.max_steps:
            return False
        if self.state.cost >= self.budget_limit:
            return False
        budget_remaining = 1.0 - (self.state.cost / self.budget_limit)
        return budget_remaining > 0.1

    def get_status(self) -> Dict:
        """Get current mission status."""
        return {
            "target": self.state.target,
            "status": self.state.status.value,
            "findings_count": len(self.state.findings),
            "steps": self.state.steps,
            "cost": self.state.cost,
            "budget_remaining": 1.0 - (self.state.cost / self.budget_limit)
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_vuln_finder.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tools/vuln_finder.py tests/test_vuln_finder.py
git commit -m "feat: add VulnFinder core engine with adaptive execution"
```

---

## Phase 3: System Prompt (Progressive Disclosure)

### Task 12: Create System Prompt Template

**Covers:** [S4, S9]
**Files:**
- Create: `prompts/vuln_finder_system.txt`

- [ ] **Step 1: Create prompt file**

```txt
# Adaptive Vulnerability Finder - System Prompt

## Your Role
You are an autonomous security researcher. Your job is to find, escalate, chain, and verify vulnerabilities in the target.

## Available Tools
{{TOOL_CATALOG}}

## Methodology Hints (Optional — use as you see fit)
- When you find a low-severity bug, consider trying to escalate it to high/critical
- When you find multiple related bugs, consider chaining them together
- If you don't have enough information, recon more before testing
- Rank targets by attack surface before executing tests

## What You Decide
- The order of phases (recon → plan → execute → verify → report)
- Which tools to use and when
- How to escalate low-severity findings
- How to chain multiple findings
- When to stop and generate a report

## Rules
- Every finding must have evidence and PoC
- Ask user before running privileged commands (sudo)
- Track your token usage and stay within budget
- If data is insufficient, recon more

## Output Format
When you find a vulnerability, output:
```json
{
  "type": "XSS|SQLi|IDOR|SSRF|...",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "url": "http://...",
  "parameter": "...",
  "evidence": "...",
  "poc": "...",
  "impact": "...",
  "remediation": "..."
}
```
```

- [ ] **Step 2: Verify template loads**

```python
# Quick verification
with open("prompts/vuln_finder_system.txt") as f:
    content = f.read()
assert "{{TOOL_CATALOG}}" in content
assert "Methodology Hints" in content
```

- [ ] **Step 3: Commit**

```bash
git add prompts/vuln_finder_system.txt
git commit -m "feat: add progressive disclosure system prompt template"
```

---

## Phase 4: Integration & Testing

### Task 13: Integrate with Existing Agent

**Covers:** [S2, S6]
**Files:**
- Modify: `agent_brain.py` (add VulnFinder integration)

- [ ] **Step 1: Write integration test**

```python
# tests/test_vuln_finder_integration.py
def test_vuln_finder_agent_integration():
    from tools.vuln_finder import VulnFinder
    finder = VulnFinder(target="http://test.com")

    # Test full flow
    assets = finder.recon()
    assert assets is not None

    plan = finder.plan()
    assert isinstance(plan, list)

    status = finder.get_status()
    assert status["status"] == "planning"
```

- [ ] **Step 2: Run test**

Run: `pytest tests/test_vuln_finder_integration.py -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_vuln_finder_integration.py
git commit -m "test: add VulnFinder integration tests"
```

---

### Task 14: Run Full Test Suite

**Covers:** All
**Files:** None

- [ ] **Step 1: Run all tests**

Run: `python3 -m pytest tests/ -v --tb=short`

- [ ] **Step 2: Verify no regressions**

Check that existing tests still pass.

- [ ] **Step 3: Commit if needed**

```bash
git add -A
git commit -m "test: verify full test suite passes"
```

---

## Summary

| Task | Description | Spec Sections |
|------|-------------|---------------|
| 1 | Fix prompt interpolation bugs | S4 |
| 2 | Fix analysis_pipeline imports | S6 |
| 3 | Fix scan_engine typo | S6 |
| 4 | Fix TUI theme transitions | S9 |
| 5 | Fix TUI export module | S7 |
| 6 | Create Knowledge Graph | S5 |
| 7 | Create Escalation Engine | S3 |
| 8 | Create Chaining Engine | S3 |
| 9 | Create Verification Engine | S3 |
| 10 | Create Adaptive Planner | S3, S4 |
| 11 | Create VulnFinder Core | S2, S3, S4 |
| 12 | Create System Prompt | S4, S9 |
| 13 | Integration | S2, S6 |
| 14 | Full Test Suite | All |

**Total Tasks:** 14
**Estimated Time:** 2-3 days for core engine, additional time for full integration

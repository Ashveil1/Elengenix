"""tools/autonomous_agent.py

Fully Autonomous AI Agent - No Restrictions, Maximum Capability.

Purpose:
    pass  # TODO: Implement
- AI has full autonomy to achieve bug bounty goals
- Can create tools, install dependencies, use external resources
- Self-directed: AI decides what to do, not constrained by predefined workflows
- Self-improving: Learns from each target, improves over time
- Goal-oriented: Find bugs, maximize bounty payouts

Governance Modes:
    pass  # TODO: Implement
- "strict": Ask for everything (safest)
- "ask": Ask for dangerous/suspicious operations (balanced)
- "auto": Auto-approve everything (maximum speed, requires trust)

Key Features:
    pass  # TODO: Implement
1. AI plans entire attack strategy autonomously
2. Creates custom tools as needed
3. Installs external security tools automatically
4. Learns from results and adapts
5. Generates professional reports automatically

Usage:
    # Start autonomous mode
    agent = AutonomousAgent(governance_mode="ask")
    
    # AI takes over completely
    result = agent.run_autonomous_scan("https://target.com")
    
    # Or with specific goal
    agent.set_goal("Find IDOR vulnerabilities in API endpoints")
    agent.run_on_target("https://api.target.com")
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tools.ai_tool_creator import AIToolCreator, ToolExecutionResult
from tools.mission_state import MissionState

logger = logging.getLogger("elengenix.autonomous")


@dataclass
class AutonomousDecision:
    """A decision made by the AI."""
    decision_type: str  # scan, create_tool, install_dep, analyze, report
    reasoning: str
    action_plan: Dict[str, Any]
    expected_outcome: str
    risk_level: str  # low/medium/high/critical
    auto_approved: bool = False


@dataclass
class ScanResult:
    """Result from autonomous scan."""
    target: str
    start_time: datetime
    end_time: Optional[datetime]
    findings: List[Dict[str, Any]]
    bounty_predictions: List[Dict[str, Any]]
    tools_created: List[str]
    ai_decisions: List[AutonomousDecision]
    report_path: Optional[Path]
    success: bool
    summary: str


class AutonomousAgent:
    """
    Fully autonomous AI agent for bug bounty hunting.
    
    This agent has no predefined workflows. AI decides:
        pass  # TODO: Implement
    - What to scan
    - How to scan it
    - What tools to use/create
    - How to analyze results
    - What to report
    
    The user just provides a target, AI does the rest.
    """
    
    def __init__(self, governance_mode: str = "ask", ai_client=None):
        """
        Initialize autonomous agent.
        
        Args:
            governance_mode: strict/ask/auto
            ai_client: AI client for decision making
        """
        self.governance_mode = governance_mode
        self.ai_client = ai_client
        self.tool_creator = AIToolCreator(governance_mode=governance_mode)
        
        self.current_mission: Optional[MissionState] = None
        self.decision_history: List[AutonomousDecision] = []
        
        # Statistics for self-improvement
        self.session_stats = {
            "targets_scanned": 0,
            "tools_created": 0,
            "findings_found": 0,
            "false_positives": 0,
        }
        
        logger.info(f"AutonomousAgent initialized (mode: {governance_mode})")
    
    def run_autonomous_scan(self, target: str, goal: str = None) -> ScanResult:
        """
        Run completely autonomous scan on target.
        
        AI controls everything:
            pass  # TODO: Implement
        1. Reconnaissance planning
        2. Tool selection/creation
        3. Vulnerability discovery
        4. Exploitation attempts
        5. Report generation
        
        Args:
            target: Target URL/domain
            goal: Optional specific goal (e.g., "Find IDORs")
            
        Returns:
            Complete scan result with findings and report
        """
        start_time = datetime.utcnow()
        
        print(f"\n[Autonomous Mode] Starting scan on: {target}")
        print(f"[Governance] Mode: {self.governance_mode}")
        if goal:
            print(f"[Goal] {goal}")
        print("")
        
        # Initialize mission
        self.current_mission = MissionState(
            mission_id=f"auto_{int(time.time())}",
            target=target,
            config={"autonomous": True, "governance": self.governance_mode}
        )
        
        findings = []
        tools_created = []
        
        try:
            # Phase 1: AI Planning
            print("[Phase 1] AI analyzing target and planning strategy...")
            strategy = self._ai_plan_strategy(target, goal)
            
            print(f"[AI Strategy] {strategy.get('approach', 'Unknown')}")
            print(f"[Planned Steps] {len(strategy.get('steps', []))}")
            
            # Phase 2: Create necessary tools
            print("\n[Phase 2] Creating specialized tools...")
            for tool_plan in strategy.get("tools_needed", []):
                if self._should_create_tool(tool_plan):
                    spec = self.tool_creator.analyze_target_and_plan(target, tool_plan)
                    if spec:
                        for s in spec:
                            if self.tool_creator.create_tool(s):
                                tools_created.append(s.name)
                                # Execute immediately
                                result = self.tool_creator.execute_tool(s.name, target=target)
                                if result.success and result.findings:
                                    findings.extend(result.findings)
            
            # Phase 3: Use existing tools with AI guidance
            print("\n[Phase 3] Running vulnerability discovery...")
            existing_findings = self._run_ai_guided_discovery(target, strategy)
            findings.extend(existing_findings)
            
            # Phase 4: AI analysis of findings
            print("\n[Phase 4] AI analyzing findings...")
            analyzed_findings = self._ai_analyze_findings(findings)
            
            # Phase 5: Bounty prediction
            print("\n[Phase 5] Predicting bounty values...")
            bounty_predictions = self._predict_bounties(analyzed_findings)
            
            # Phase 6: Generate report
            print("\n[Phase 6] Generating report...")
            report_path = self._generate_autonomous_report(
                target, analyzed_findings, bounty_predictions, strategy
            )
            
            end_time = datetime.utcnow()
            
            # Build summary
            summary = self._generate_summary(
                target, analyzed_findings, tools_created, strategy
            )
            
            print(f"\n[Complete] Scan finished in {(end_time - start_time).seconds}s")
            print(f"[Results] {len(analyzed_findings)} findings, {len(tools_created)} tools created")
            
            return ScanResult(
                target=target,
                start_time=start_time,
                end_time=end_time,
                findings=analyzed_findings,
                bounty_predictions=bounty_predictions,
                tools_created=tools_created,
                ai_decisions=self.decision_history,
                report_path=report_path,
                success=True,
                summary=summary,
            )
            
        except Exception as e:
            logger.exception("Autonomous scan failed")
            return ScanResult(
                target=target,
                start_time=start_time,
                end_time=datetime.utcnow(),
                findings=findings,
                bounty_predictions=[],
                tools_created=tools_created,
                ai_decisions=self.decision_history,
                report_path=None,
                success=False,
                summary=f"Failed: {str(e)}",
            )
    
    def _ai_plan_strategy(self, target: str, goal: str = None) -> Dict[str, Any]:
        """
        AI plans complete scanning strategy.
        
        Returns:
            Strategy dict with approach, steps, tools needed
        """
        if not self.ai_client:
            # Fallback to basic strategy
            return {
                "approach": "Standard reconnaissance",
                "steps": ["recon", "scan", "analyze"],
                "tools_needed": [],
            }
        
        prompt = f"""You are an autonomous bug bounty AI. Plan a complete attack strategy.

Target: {target}
Goal: {goal or 'Find high-value security vulnerabilities'}

Your task:
    pass  # TODO: Implement
1. Analyze what type of target this is (web app, API, cloud, etc.)
2. Determine the best approach to find vulnerabilities
3. Decide what specialized tools might be needed
4. Plan the sequence of actions

Respond in JSON:
    pass  # TODO: Implement
{{
    "target_type": "web_app/api/cloud/etc",
    "approach": "brief description of approach",
    "steps": ["step1", "step2", ...],
    "tools_needed": [
        {{
            "purpose": "what this tool should do",
            "specialization": "what makes this tool specialized for this target"
        }}
    ],
    "priority_vuln_types": ["idor", "sqli", "rce", ...],
    "estimated_time": "e.g., 10-15 minutes"
}}
"""
        
        try:
            from tools.universal_ai_client import AIClientManager, AIMessage
            
            manager = AIClientManager()
            messages = [
                AIMessage(role="system", content="You are an expert bug bounty hunter."),
                AIMessage(role="user", content=prompt),
            ]
            
            response = manager.chat(messages, temperature=0.3)
            
            # Parse JSON from response
            content = response.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            strategy = json.loads(content.strip())
            
            # Record decision
            self.decision_history.append(AutonomousDecision(
                decision_type="strategy_planning",
                reasoning=f"Planned approach for {target}",
                action_plan=strategy,
                expected_outcome="Find vulnerabilities efficiently",
                risk_level="low",
            ))
            
            return strategy
            
        except Exception as e:
            logger.error(f"Strategy planning failed: {e}")
            return {"approach": "Fallback", "steps": [], "tools_needed": []}
    
    def _should_create_tool(self, tool_plan: Dict) -> bool:
        """Determine if AI should create a new tool."""
        # AI decides based on specialization needed
        specialization = tool_plan.get("specialization", "").lower()
        
        # Check if existing tools can handle this
        specialized_needs = [
            "custom protocol",
            "specific framework",
            "unusual endpoint structure",
            "custom authentication",
        ]
        
        for need in specialized_needs:
            if need in specialization:
                return True
        
        return False
    
    def _run_ai_guided_discovery(self, target: str, strategy: Dict) -> List[Dict]:
        """Run discovery with AI guidance on what to focus on."""
        findings = []
        
        # Let AI guide which existing tools to use
        priority_vulns = strategy.get("priority_vuln_types", [])
        
        # Run BOLA/IDOR if prioritized
        if any(v in priority_vulns for v in ["idor", "bola", "auth"]):
            print("  [AI] Prioritizing access control testing...")
            try:
                from tools.bola_idor_harness import BOLAHarness
                # Note: Would need actual headers for real test
                # This is simplified
            except Exception as e:
                logger.debug(f"BOLA harness not available: {e}")
        
        # Run recon if needed
        if "recon" in strategy.get("steps", []):
            print("  [AI] Running reconnaissance...")
            try:
                from tools.smart_recon import SmartReconEngine
                engine = SmartReconEngine(target=target)
                recon_result = engine.run_full_recon()
                
                # Convert recon findings
                for finding in recon_result.findings:
                    findings.append({
                        "type": finding.get("type", "info"),
                        "severity": "info",
                        "target": target,
                        "description": str(finding),
                    })
            except Exception as e:
                logger.debug(f"Recon failed: {e}")
        
        return findings
    
    def _ai_analyze_findings(self, findings: List[Dict]) -> List[Dict]:
        """AI analyzes and enriches findings."""
        if not self.ai_client or not findings:
            return findings
        
        enriched = []
        
        for finding in findings:
            # AI determines if this is a real vulnerability
            prompt = f"""Analyze this security finding:

Finding: {json.dumps(finding, indent=2)}

Determine:
    pass  # TODO: Implement
1. Is this a real vulnerability or false positive?
2. What is the severity (critical/high/medium/low)?
3. What is the business impact?
4. How to reproduce it?

Respond in JSON:
    pass  # TODO: Implement
{{
    "is_valid": true/false,
    "severity": "critical/high/medium/low",
    "impact": "description",
    "reproduction_steps": ["step1", "step2"],
    "confidence": 0.0-1.0
}}
"""
            
            try:
                from tools.universal_ai_client import AIClientManager, AIMessage
                
                manager = AIClientManager()
                messages = [
                    AIMessage(role="system", content="You are a security analyst."),
                    AIMessage(role="user", content=prompt),
                ]
                
                response = manager.chat(messages, temperature=0.2)
                analysis = json.loads(response.content)
                
                if analysis.get("is_valid", True):
                    finding["ai_analysis"] = analysis
                    finding["severity"] = analysis.get("severity", finding.get("severity", "medium"))
                    enriched.append(finding)
                else:
                    print(f"  [AI Filtered] False positive: {finding.get('type', 'unknown')}")
                    
            except Exception as e:
                logger.debug(f"Analysis failed: {e}")
                enriched.append(finding)
        
        return enriched
    
    def _predict_bounties(self, findings: List[Dict]) -> List[Dict]:
        """Predict bounty values for findings."""
        try:
            from tools.bounty_predictor import BountyPredictor
            
            predictor = BountyPredictor()
            predictions = []
            
            for finding in findings:
                pred = predictor.predict(finding)
                predictions.append({
                    "finding_id": finding.get("id", "unknown"),
                    "bounty_score": pred.bounty_score,
                    "payout_range": pred.payout_range,
                    "triage_speed": pred.triage_speed,
                    "suggestions": pred.suggestions,
                })
            
            return predictions
            
        except Exception as e:
            logger.debug(f"Bounty prediction failed: {e}")
            return []
    
    def _generate_autonomous_report(self, target: str, 
                                    findings: List[Dict],
                                    bounty_predictions: List[Dict],
                                    strategy: Dict) -> Optional[Path]:
                                        pass  # TODO: Implement
        """Generate comprehensive report."""
        try:
            from tools.pdf_report_generator import PDFReportGenerator, ReportMetadata
            
            metadata = ReportMetadata(
                title=f"Autonomous Security Assessment - {target}",
                target=target,
                author="Elengenix Autonomous AI",
                date=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            )
            
            # Enrich findings with bounty predictions
            for i, finding in enumerate(findings):
                if i < len(bounty_predictions):
                    finding["bounty_prediction"] = bounty_predictions[i]
            
            generator = PDFReportGenerator()
            report_paths = generator.generate_from_findings(findings, metadata)
            
            return report_paths.get("pdf") or report_paths.get("html")
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return None
    
    def _generate_summary(self, target: str, 
                         findings: List[Dict],
                         tools_created: List[str],
                         strategy: Dict) -> str:
                             pass  # TODO: Implement
        """Generate human-readable summary."""
        critical = len([f for f in findings if f.get("severity") == "critical"])
        high = len([f for f in findings if f.get("severity") == "high"])
        medium = len([f for f in findings if f.get("severity") == "medium"])
        
        lines = [
            f"Autonomous scan complete for {target}",
            f"AI Strategy: {strategy.get('approach', 'Standard')}",
            f"",
            f"Findings Summary:",
            f"  Critical: {critical}",
            f"  High: {high}",
            f"  Medium: {medium}",
            f"  Low/Info: {len(findings) - critical - high - medium}",
            f"",
            f"Tools Created: {len(tools_created)}",
        ]
        
        if tools_created:
            lines.append(f"  {', '.join(tools_created)}")
        
        lines.append(f"\nAI Decisions Made: {len(self.decision_history)}")
        
        return "\n".join(lines)


def run_autonomous_cli():
    """CLI for autonomous mode."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python autonomous_agent.py <target> [--mode {strict|ask|auto}]")
        print("Examples:")
        print("  python autonomous_agent.py https://target.com")
        print("  python autonomous_agent.py https://target.com --mode auto")
        sys.exit(1)
    
    target = sys.argv[1]
    mode = "ask"
    
    if "--mode" in sys.argv:
        mode_idx = sys.argv.index("--mode")
        if mode_idx + 1 < len(sys.argv):
            mode = sys.argv[mode_idx + 1]
    
    print(f"[Elengenix Autonomous Agent]")
    print(f"Target: {target}")
    print(f"Governance: {mode}")
    print("")
    
    agent = AutonomousAgent(governance_mode=mode)
    result = agent.run_autonomous_scan(target)
    
    print("\n" + "="*60)
    print(result.summary)
    print("="*60)
    
    if result.report_path:
        print(f"\n[Report] {result.report_path}")
    
    if result.success:
        print("\n[Status] SUCCESS")
    else:
        print("\n[Status] FAILED")
        print(f"[Error] {result.summary}")


if __name__ == "__main__":
    run_autonomous_cli()

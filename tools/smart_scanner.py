"""tools/smart_scanner.py

Phase 2: Smart Scanner - Phased scanning with token optimization.

Purpose:
- Execute security scans in phases (recon → scan → exploit → report)
- Token-efficient scanning with checkpoints
- Auto-pause when budget exceeded
- Resume from exact checkpoint
- Smart phase selection based on findings

Features:
- 4-phase scanning strategy
- Checkpoint after each phase
- Token tracking and budget enforcement
- Auto-pause on budget limits
- Resume capability
- Progress display integration

Usage:
    from tools.smart_scanner import SmartScanner
    
    scanner = SmartScanner(target="api.target.com")
    scanner.run()
    
    # Pause manually
    scanner.pause()
    
    # Resume
    scanner = SmartScanner.load(mission_id="...")
    scanner.resume()
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from tools.mission_state import MissionState, open_mission
from tools.token_manager import TokenManager, get_token_manager
from tools.progress_display import ProgressDisplay, ScanPhase
from tools.telegram_bridge import TelegramBridge, get_telegram_bridge

logger = logging.getLogger("elengenix.smart_scanner")


@dataclass
class ScanPhaseConfig:
    """Configuration for a scan phase."""
    name: str
    description: str
    estimated_tokens: int
    estimated_duration_minutes: int
    required_tools: List[str] = field(default_factory=list)
    is_critical: bool = False  # Critical phases cannot be skipped


# Phase configurations
PHASES = [
    ScanPhaseConfig(
        name="discovery",
        description="Reconnaissance - discover assets and endpoints",
        estimated_tokens=5000,
        estimated_duration_minutes=10,
        required_tools=["smart_recon"],
        is_critical=True,
    ),
    ScanPhaseConfig(
        name="vulnerability_scan",
        description="Vulnerability scanning - find potential issues",
        estimated_tokens=20000,
        estimated_duration_minutes=20,
        required_tools=["bola_harness", "waf_evasion"],
        is_critical=True,
    ),
    ScanPhaseConfig(
        name="exploit_verification",
        description="Exploit verification - confirm vulnerabilities",
        estimated_tokens=50000,
        estimated_duration_minutes=30,
        required_tools=["autonomous_agent"],
        is_critical=False,  # Skip if no findings
    ),
    ScanPhaseConfig(
        name="report_generation",
        description="Report generation - create professional report",
        estimated_tokens=10000,
        estimated_duration_minutes=5,
        required_tools=["pdf_report_generator"],
        is_critical=False,  # Skip if no findings
    ),
]


class SmartScanner:
    """
    Smart scanner with phased execution and token optimization.
    
    Features:
    - 4-phase scanning strategy
    - Checkpoint after each phase
    - Token budget enforcement
    - Auto-pause on limits
    - Resume capability
    """
    
    def __init__(self, 
                 target: str,
                 mission_id: str = None,
                 token_manager: TokenManager = None,
                 telegram_bridge: TelegramBridge = None,
                 auto_pause: bool = True,
                 pause_after_hours: int = 3):
        """
        Initialize smart scanner.
        
        Args:
            target: Target to scan
            mission_id: Existing mission ID (for resume)
            token_manager: Token manager instance
            telegram_bridge: Telegram bridge for notifications
            auto_pause: Auto-pause on budget limits
            pause_after_hours: Auto-pause if no findings after N hours
        """
        self.target = target
        self.mission_id = mission_id or f"mission-{uuid.uuid4().hex[:8]}"
        self.token_manager = token_manager or get_token_manager()
        self.telegram_bridge = telegram_bridge or get_telegram_bridge()
        self.auto_pause = auto_pause
        self.pause_after_hours = pause_after_hours
        
        # Initialize mission state
        if mission_id:
            self.mission = open_mission(mission_id)
            if not self.mission:
                raise ValueError(f"Mission not found: {mission_id}")
        else:
            self.mission = MissionState(
                mission_id=self.mission_id,
                target=target,
                objective="Autonomous security scanning"
            )
        
        # Progress display
        self.progress = ProgressDisplay(target=target)
        
        # Findings tracking
        self.findings: List[Dict] = []
        self.phase_results: Dict[str, Any] = {}
        
        # Timing
        self.start_time = datetime.utcnow()
        self.last_finding_time = datetime.utcnow()
    
    def run(self, start_phase: int = 0) -> Dict[str, Any]:
        """
        Run the smart scanner.
        
        Args:
            start_phase: Phase index to start from (for resume)
            
        Returns:
            Scan results summary
        """
        logger.info(f"Starting smart scanner for {self.target}")
        
        # Notify mission started
        if self.telegram_bridge:
            self.telegram_bridge.notify_mission_started(self.mission_id, self.target)
        
        # Initialize progress display
        scan_phases = [
            ScanPhase(p.name, p.description, [])
            for p in PHASES[start_phase:]
        ]
        self.progress.start(scan_phases)
        
        results = {
            "mission_id": self.mission_id,
            "target": self.target,
            "phases_completed": [],
            "findings": [],
            "tokens_used": 0,
            "duration_seconds": 0,
            "status": "completed",
        }
        
        try:
            # Run each phase
            for i, phase_config in enumerate(PHASES[start_phase:], start=start_phase):
                phase_name = phase_config.name
                
                # Check if should skip non-critical phase
                if not phase_config.is_critical and not self.findings:
                    logger.info(f"Skipping {phase_name} (no findings)")
                    self.progress.complete(phase_name, "Skipped (no findings)")
                    continue
                
                # Check token budget before phase
                can_proceed, reason = self.token_manager.can_proceed(
                    estimated_cost=self._estimate_phase_cost(phase_config)
                )
                
                if not can_proceed and self.auto_pause:
                    logger.warning(f"Cannot proceed: {reason}")
                    self._pause_mission(reason)
                    results["status"] = "paused"
                    results["pause_reason"] = reason
                    return results
                
                # Run phase
                logger.info(f"Starting phase: {phase_name}")
                self.mission.update_phase(phase_name, i)
                
                phase_result = self._run_phase(phase_config)
                self.phase_results[phase_name] = phase_result
                
                # Update progress
                self.progress.complete(phase_name, f"Completed - {phase_result.get('summary', 'Done')}")
                
                # Notify phase completed
                if self.telegram_bridge:
                    self.telegram_bridge.notify_phase_completed(
                        self.mission_id,
                        phase_name,
                        phase_result.get("summary", "Done"),
                        len(phase_result.get("findings", []))
                    )
                
                # Record token usage
                tokens_used = phase_result.get("tokens_used", 0)
                self.mission.add_tokens(tokens_used)
                results["tokens_used"] += tokens_used
                
                # Check for findings
                if phase_result.get("findings"):
                    new_findings = phase_result["findings"]
                    self.findings.extend(new_findings)
                    self.mission.add_finding()
                    self.last_finding_time = datetime.utcnow()
                    self.progress.add_finding(len(new_findings))
                    
                    # Notify about findings
                    if self.telegram_bridge:
                        for finding in new_findings:
                            severity = finding.get("severity", "info")
                            is_urgent = severity.upper() in ["CRITICAL", "HIGH"]
                            self.telegram_bridge.notify_finding(
                                self.mission_id,
                                finding,
                                urgent=is_urgent
                            )
                
                # Checkpoint after phase
                self._checkpoint()
                
                # Check if should pause (no findings for too long)
                if self._should_pause():
                    self._pause_mission("No findings for too long")
                    results["status"] = "paused"
                    results["pause_reason"] = "No findings timeout"
                    return results
            
            # Complete mission
            self.mission.update_phase("completed")
            results["findings"] = self.findings
            results["phases_completed"] = list(self.phase_results.keys())
            results["duration_seconds"] = (datetime.utcnow() - self.start_time).total_seconds()
            
            self.progress.finish(f"Scan complete - {len(self.findings)} findings")
            
            # Notify mission completed
            if self.telegram_bridge:
                self.telegram_bridge.notify_mission_completed(
                    self.mission_id,
                    len(self.findings),
                    results["tokens_used"],
                    results["duration_seconds"]
                )
            
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
            self._pause_mission("User interrupted")
            results["status"] = "paused"
            results["pause_reason"] = "User interrupted"
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.mission.update_phase("failed")
            results["status"] = "failed"
            results["error"] = str(e)
            
            # Notify mission failed
            if self.telegram_bridge:
                self.telegram_bridge.notify_mission_failed(self.mission_id, str(e))
        
        return results
    
    def _run_phase(self, phase_config: ScanPhaseConfig) -> Dict[str, Any]:
        """
        Run a single phase.
        
        Args:
            phase_config: Phase configuration
            
        Returns:
            Phase results
        """
        phase_name = phase_config.name
        
        # Update progress
        self.progress.update(phase_name, 0, f"Starting {phase_name}...")
        
        # Simulate phase execution (replace with actual tool calls)
        # This is a placeholder - in production, call actual tools
        
        if phase_name == "discovery":
            result = self._run_discovery_phase()
        elif phase_name == "vulnerability_scan":
            result = self._run_vulnerability_scan_phase()
        elif phase_name == "exploit_verification":
            result = self._run_exploit_verification_phase()
        elif phase_name == "report_generation":
            result = self._run_report_generation_phase()
        else:
            result = {"summary": "Unknown phase", "tokens_used": 0}
        
        return result
    
    def _run_discovery_phase(self) -> Dict[str, Any]:
        """Run discovery phase (reconnaissance) using SmartReconEngine."""
        findings = []
        tokens_used = 5000

        try:
            from tools.smart_recon import SmartReconEngine, format_recon_for_display
            engine = SmartReconEngine(
                target_domain=self.target,
                rate_limit_rps=2.0,
                max_workers=10,
            )
            result = engine.run_full_recon()

            for node in result.nodes:
                t = node.asset_type
                if t not in self.mission.assets:
                    self.mission.assets[t] = []
                if node.value not in self.mission.assets[t]:
                    self.mission.assets[t].append(node.value)

            for f in result.findings:
                findings.append({
                    "type": f.get("type", "info"),
                    "severity": f.get("severity", "info"),
                    "title": f.get("title", "Recon Finding"),
                    "target": f.get("target", self.target),
                    "description": f.get("description", ""),
                    "source": "recon",
                })

            summary = (
                f"Found {result.stats.get('domains', 0)} domains, "
                f"{result.stats.get('ips', 0)} IPs, "
                f"{result.stats.get('endpoints', 0)} endpoints"
            )
        except Exception as e:
            logger.warning(f"Discovery phase error: {e}")
            summary = f"Discovery phase error: {e}"

        return {
            "summary": summary,
            "tokens_used": tokens_used,
            "findings": findings,
        }
    
    def _run_vulnerability_scan_phase(self) -> Dict[str, Any]:
        """Run vulnerability scan phase using orchestrator pipeline + BOLA/WAF tools."""
        findings = []
        tokens_used = 20000

        try:
            import asyncio
            from orchestrator import run_standard_scan
            report_dir = asyncio.run(run_standard_scan(self.target, rate_limit=5))
            if report_dir:
                from pathlib import Path
                import json
                cvss_file = Path(report_dir) / "cvss_scores.json"
                if cvss_file.exists():
                    for item in json.loads(cvss_file.read_text()):
                        f = item.get("finding", {})
                        f["tool"] = item.get("tool", "unknown")
                        f["cvss_score"] = item.get("cvss_score", 0)
                        f["cvss_severity"] = item.get("severity", "Unknown")
                        findings.append(f)
                summary = f"Orchestrator pipeline found {len(findings)} findings"
            else:
                summary = "Orchestrator pipeline completed with no report"
        except Exception as e:
            logger.warning(f"Vulnerability scan phase error: {e}")
            summary = f"Vulnerability scan error: {e}"

        return {
            "summary": summary,
            "tokens_used": tokens_used,
            "findings": findings,
        }
    
    def _run_exploit_verification_phase(self) -> Dict[str, Any]:
        """Run exploit verification phase using autonomous agent for deep testing."""
        findings = []
        tokens_used = 50000

        try:
            from tools.autonomous_agent import AutonomousAgent, AgentAction, AgentState
            agent = AutonomousAgent(governance_mode="ask")
            state = AgentState(
                root_target=self.target,
                goal="Verify and confirm discovered vulnerabilities",
            )
            if self.mission and hasattr(self.mission, 'assets'):
                state.assets = dict(self.mission.assets)

            action = AgentAction(
                name="injection_test",
                target=f"https://{self.target}",
                reasoning="Verify findings from vulnerability scan phase",
            )
            from tools.autonomous_agent import _exec_injection_test
            findings = _exec_injection_test(action, state)

            confirmed = [f for f in findings if f.get("severity") in ("critical", "high")]
            summary = f"Verified {len(confirmed)} high-severity findings out of {len(findings)} total"
        except Exception as e:
            logger.warning(f"Exploit verification phase error: {e}")
            summary = f"Exploit verification error: {e}"

        return {
            "summary": summary,
            "tokens_used": tokens_used,
            "findings": findings,
        }
    
    def _run_report_generation_phase(self) -> Dict[str, Any]:
        """Run report generation phase using PDF report generator."""
        tokens_used = 10000

        try:
            from tools.pdf_report_generator import PDFReportGenerator, ReportMetadata
            from datetime import datetime as _dt
            meta = ReportMetadata(
                title=f"Security Assessment — {self.target}",
                target=self.target,
                author="Elengenix Smart Scanner",
                date=_dt.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            )
            gen = PDFReportGenerator()
            report_paths = gen.generate_from_findings(self.findings, meta)
            summary = f"Report generated: {report_paths.get('html', 'N/A')}"
        except Exception as e:
            logger.warning(f"Report generation phase error: {e}")
            summary = f"Report generation error: {e}"

        return {
            "summary": summary,
            "tokens_used": tokens_used,
            "findings": [],
        }
    
    def _estimate_phase_cost(self, phase_config: ScanPhaseConfig) -> float:
        """Estimate cost for a phase."""
        # Use token manager to calculate cost
        return self.token_manager.calculate_cost(
            provider="openai",
            tokens_input=phase_config.estimated_tokens,
            tokens_output=phase_config.estimated_tokens // 2,
        )
    
    def _should_pause(self) -> bool:
        """Check if should pause (no findings for too long)."""
        if not self.pause_after_hours:
            return False
        
        time_since_finding = (datetime.utcnow() - self.last_finding_time).total_seconds() / 3600
        return time_since_finding >= self.pause_after_hours
    
    def _pause_mission(self, reason: str) -> None:
        """Pause the mission."""
        logger.info(f"Pausing mission: {reason}")
        self.mission.pause_mission()
        self.progress.finish(f"Paused: {reason}")
        
        # Notify via Telegram
        if self.telegram_bridge:
            self.telegram_bridge.notify_mission_paused(self.mission_id, reason)
    
    def _checkpoint(self) -> None:
        """Save checkpoint."""
        # Mission state is already saved to SQLite
        # This is for any additional checkpoint logic
        logger.debug("Checkpoint saved")
    
    def pause(self) -> None:
        """Manually pause the scan."""
        self._pause_mission("Manual pause")
    
    def resume(self) -> Dict[str, Any]:
        """Resume a paused scan."""
        status = self.mission.get_status()
        
        if status.get("status") != "paused":
            logger.warning(f"Mission is not paused: {status.get('status')}")
            return {"error": "Mission not paused"}
        
        logger.info("Resuming mission")
        self.mission.resume_mission()
        
        # Get current phase
        current_phase = status.get("current_phase", "discovery")
        phase_index = status.get("phase_index", 0)
        
        # Resume from next phase
        return self.run(start_phase=phase_index + 1)
    
    @classmethod
    def load(cls, mission_id: str) -> Optional["SmartScanner"]:
        """Load an existing mission."""
        mission = open_mission(mission_id)
        if not mission:
            return None
        
        return cls(
            target=mission.target,
            mission_id=mission_id,
        )
    
    def get_status(self) -> Dict[str, Any]:
        """Get current scan status."""
        mission_status = self.mission.get_status()
        token_status = self.token_manager.get_status()
        
        return {
            "mission_id": self.mission_id,
            "target": self.target,
            "status": mission_status.get("status"),
            "current_phase": mission_status.get("current_phase"),
            "phase_index": mission_status.get("phase_index"),
            "findings_count": mission_status.get("findings_count"),
            "tokens_used": mission_status.get("tokens_used"),
            "token_budget": token_status["daily_budget"],
            "token_spent": token_status["spent_today"],
        }


def run_cli():
    """CLI for smart scanner."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: smart_scanner <target> [resume <mission_id>]")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if len(sys.argv) >= 3 and sys.argv[2] == "resume":
        mission_id = sys.argv[3]
        scanner = SmartScanner.load(mission_id)
        if not scanner:
            print(f"Mission not found: {mission_id}")
            sys.exit(1)
        results = scanner.resume()
    else:
        scanner = SmartScanner(target=target)
        results = scanner.run()
    
    print(f"\nScan Results:")
    print(f"  Status: {results['status']}")
    print(f"  Findings: {len(results.get('findings', []))}")
    print(f"  Tokens used: {results['tokens_used']}")
    print(f"  Duration: {results['duration_seconds']:.0f}s")


if __name__ == "__main__":
    run_cli()

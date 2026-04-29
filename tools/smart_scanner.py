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
                 auto_pause: bool = True,
                 pause_after_hours: int = 3):
        """
        Initialize smart scanner.
        
        Args:
            target: Target to scan
            mission_id: Existing mission ID (for resume)
            token_manager: Token manager instance
            auto_pause: Auto-pause on budget limits
            pause_after_hours: Auto-pause if no findings after N hours
        """
        self.target = target
        self.mission_id = mission_id or f"mission-{uuid.uuid4().hex[:8]}"
        self.token_manager = token_manager or get_token_manager()
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
        """Run discovery phase (reconnaissance)."""
        # Placeholder: Call smart_recon tool
        # For now, simulate
        
        time.sleep(2)  # Simulate work
        
        # Simulate findings
        findings = [
            {
                "type": "subdomain",
                "value": "api.target.com",
                "severity": "info",
            },
            {
                "type": "endpoint",
                "value": "/api/v1/users",
                "severity": "info",
            },
        ]
        
        return {
            "summary": "Found 2 subdomains, 15 endpoints",
            "tokens_used": 5000,
            "findings": findings,
        }
    
    def _run_vulnerability_scan_phase(self) -> Dict[str, Any]:
        """Run vulnerability scan phase."""
        # Placeholder: Call bola_harness, waf_evasion tools
        
        time.sleep(3)
        
        # Simulate findings
        findings = [
            {
                "type": "BOLA",
                "endpoint": "/api/v1/orders/{id}",
                "severity": "high",
                "description": "Potential IDOR vulnerability",
            },
        ]
        
        return {
            "summary": "Found 1 potential BOLA vulnerability",
            "tokens_used": 20000,
            "findings": findings,
        }
    
    def _run_exploit_verification_phase(self) -> Dict[str, Any]:
        """Run exploit verification phase."""
        # Placeholder: Call autonomous_agent
        
        time.sleep(2)
        
        # Simulate verification
        findings = [
            {
                "type": "BOLA_CONFIRMED",
                "endpoint": "/api/v1/orders/{id}",
                "severity": "high",
                "description": "Confirmed IDOR - can access other users' orders",
                "cvss_score": 7.5,
            },
        ]
        
        return {
            "summary": "Confirmed 1 vulnerability",
            "tokens_used": 50000,
            "findings": findings,
        }
    
    def _run_report_generation_phase(self) -> Dict[str, Any]:
        """Run report generation phase."""
        # Placeholder: Call pdf_report_generator
        
        time.sleep(1)
        
        return {
            "summary": "Report generated",
            "tokens_used": 10000,
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

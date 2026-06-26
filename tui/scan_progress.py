"""tui/scan_progress.py - Enhanced scan progress visualization.

Provides:
    * :class:`ScanProgressWidget` - Real-time scan progress with phase tracking
    * :func:`render_scan_progress` - Standalone Rich renderable for scan progress

Features:
    - Animated progress bar with phase indicators
    - Real-time findings count
    - ETA calculation with accuracy tracking
    - Phase-by-phase progress (recon, scanning, enumeration, exploitation)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from rich.align import Align
from rich.box import ROUNDED, SIMPLE
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


@dataclass
class ScanPhase:
    """A single phase in the scan process."""

    name: str
    status: str = "pending"  # pending, running, completed, failed
    progress: float = 0.0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    findings_count: int = 0

    @property
    def duration(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.completed_at or time.time()
        return end - self.started_at

    @property
    def eta(self) -> float:
        if self.progress <= 0 or self.status != "running":
            return 0.0
        elapsed = self.duration
        if elapsed <= 0:
            return 0.0
        return elapsed / self.progress - elapsed


@dataclass
class ScanProgress:
    """Complete scan progress information."""

    scan_id: str
    target: str
    scan_type: str = "Full Scan"
    started_at: float = field(default_factory=time.time)
    phases: List[ScanPhase] = field(default_factory=list)
    total_findings: int = 0
    current_phase: str = ""
    status: str = "running"  # running, paused, completed, failed

    @property
    def overall_progress(self) -> float:
        if not self.phases:
            return 0.0
        completed = sum(p.progress for p in self.phases)
        return completed / len(self.phases)

    @property
    def elapsed(self) -> float:
        return time.time() - self.started_at

    @property
    def eta(self) -> float:
        progress = self.overall_progress
        if progress <= 0:
            return 0.0
        return self.elapsed / progress - self.elapsed


# Phase definitions for a typical security scan
SCAN_PHASES = [
    ("Recon", "DNS lookup, HTTP probe"),
    ("Port Scan", "Port discovery"),
    ("Directory", "Path enumeration"),
    ("Vulnerability", "Security scanning"),
    ("Exploitation", "Vulnerability verification"),
    ("Report", "generate findings"),
]


class ScanProgressWidget:
    """Enhanced scan progress visualization with phase tracking.

    Features:
        - Animated progress bar with phase indicators
        - Real-time findings count
        - ETA calculation with accuracy tracking
        - Phase-by-phase progress display

    Example:
        widget = ScanProgressWidget()
        widget.start_scan("example.com", "Full Scan")
        widget.update_phase("Recon", progress=0.5, findings=3)
        print(widget.render())
    """

    def __init__(self):
        self.scan: Optional[ScanProgress] = None
        self._start_time: Optional[float] = None

    def start_scan(
        self,
        target: str,
        scan_type: str = "Full Scan",
        phases: Optional[List[Tuple[str, str]]] = None,
    ) -> None:
        """Start a new scan progress tracking.

        Args:
            target: Target being scanned.
            scan_type: Type of scan being performed.
            phases: List of (phase_name, description) tuples.
        """
        phases = phases or SCAN_PHASES

        self.scan = ScanProgress(
            scan_id=f"scan_{int(time.time())}",
            target=target,
            scan_type=scan_type,
            phases=[ScanPhase(name=name) for name, _ in phases],
        )
        self._start_time = time.time()

    def update_phase(
        self,
        phase_name: str,
        progress: float = 0.0,
        findings: int = 0,
        status: str = "running",
    ) -> None:
        """Update a scan phase.

        Args:
            phase_name: Name of the phase to update.
            progress: Progress value (0.0 to 1.0).
            findings: Number of findings in this phase.
            status: Phase status (pending, running, completed, failed).
        """
        if not self.scan:
            return

        for phase in self.scan.phases:
            if phase.name == phase_name:
                if phase.status == "pending" and status == "running":
                    phase.started_at = time.time()
                phase.progress = min(1.0, max(0.0, progress))
                phase.findings_count = findings
                phase.status = status
                if status in ("completed", "failed"):
                    phase.completed_at = time.time()
                break

        # Update current phase
        for phase in self.scan.phases:
            if phase.status == "running":
                self.scan.current_phase = phase.name
                break

        # Update total findings
        self.scan.total_findings = sum(p.findings_count for p in self.scan.phases)

    def complete_scan(self, status: str = "completed") -> None:
        """Mark the scan as completed.

        Args:
            status: Final status (completed or failed).
        """
        if self.scan:
            self.scan.status = status
            for phase in self.scan.phases:
                if phase.status == "running":
                    phase.status = status
                    phase.completed_at = time.time()
                    phase.progress = 1.0 if status == "completed" else phase.progress

    def render(
        self,
        primary: str = "#ff2222",
        text_color: str = "#ffffff",
        muted: str = "#888888",
        width: int = 80,
    ) -> Panel:
        """Render the scan progress as a Rich Panel.

        Args:
            primary: Primary theme color.
            text_color: Main text color.
            muted: Muted text color.
            width: Panel width.

        Returns:
            Rich Panel with scan progress.
        """
        if not self.scan:
            return Panel(
                Text("No active scan", style=muted),
                title="[bold]SCAN PROGRESS[/bold]",
                border_style=muted,
                box=ROUNDED,
            )

        # Header
        header = Text()
        header.append(f" {self.scan.scan_type} ", style=f"bold {primary}")
        header.append(f"  Target: ", style=muted)
        header.append(self.scan.target, style=f"bold {text_color}")

        # Overall progress bar
        overall = self.scan.overall_progress
        pct = int(overall * 100)
        bar_width = 40
        filled = int(overall * bar_width)
        empty = bar_width - filled

        progress_bar = Text()
        progress_bar.append("  [", style=muted)
        progress_bar.append("\u2588" * filled, style=f"bold {primary}")
        progress_bar.append("\u2591" * empty, style=muted)
        progress_bar.append(f"] {pct:3d}%", style=f"bold {text_color}")

        # Time info
        time_text = Text()
        elapsed = self.scan.elapsed
        time_text.append(f"  Elapsed: ", style=muted)
        time_text.append(f"{int(elapsed):d}s", style=f"bold {text_color}")
        if self.scan.status == "running":
            eta = self.scan.eta
            time_text.append(f"  ETA: ", style=muted)
            time_text.append(f"{int(eta):d}s", style=f"bold {primary}")

        # Findings
        findings_text = Text()
        findings_text.append(f"  Findings: ", style=muted)
        findings_text.append(str(self.scan.total_findings), style=f"bold {text_color}")
        if self.scan.current_phase:
            findings_text.append(f"  Phase: ", style=muted)
            findings_text.append(self.scan.current_phase, style=f"bold {primary}")

        # Phase details table
        phase_table = Table(
            show_header=True,
            header_style=f"bold {primary}",
            box=SIMPLE,
            padding=(0, 0),
            expand=True,
            show_edge=False,
        )
        phase_table.add_column("Phase", style=f"bold {text_color}", width=15)
        phase_table.add_column("Progress", width=20)
        phase_table.add_column("Status", width=10, justify="center")
        phase_table.add_column("Findings", width=8, justify="right")

        for phase in self.scan.phases:
            # Status indicator
            status_icon = {
                "pending": f"[{muted}]\u25cb[/{muted}]",
                "running": f"[{primary}]\u25cf[/{primary}]",
                "completed": f"[#81C784]\u2713[/#81C784]",
                "failed": f"[#ff5500]\u2717[/#ff5500]",
            }.get(phase.status, f"[{muted}]\u25cb[/{muted}]")

            # Progress bar
            pct = int(phase.progress * 100)
            bar_w = 12
            filled = int(phase.progress * bar_w)
            phase_bar = (
                f"[{primary}]" + "\u2588" * filled + f"[{muted}]" + "\u2591" * (bar_w - filled)
            )

            phase_table.add_row(
                phase.name,
                phase_bar + f" {pct:3d}%",
                status_icon,
                str(phase.findings_count) if phase.findings_count > 0 else "-",
            )

        # Assemble
        body = Group(
            header,
            progress_bar,
            time_text,
            findings_text,
            Text(""),
            phase_table,
        )

        # Status indicator
        status_color = {
            "running": primary,
            "paused": "#ffb300",
            "completed": "#81C784",
            "failed": "#ff5500",
        }.get(self.scan.status, muted)

        return Panel(
            body,
            title=f"[bold {status_color}]SCAN {self.scan.status.upper()}[/bold {status_color}]",
            border_style=status_color,
            box=ROUNDED,
            padding=(0, 1),
            width=width,
        )


def render_scan_progress(
    target: str,
    scan_type: str = "Full Scan",
    progress: float = 0.0,
    phases: Optional[List[Tuple[str, float, int]]] = None,
    findings_total: int = 0,
    elapsed: float = 0.0,
    primary: str = "#ff2222",
    text_color: str = "#ffffff",
    muted: str = "#888888",
) -> Panel:
    """Render scan progress as a standalone Rich Panel.

    Args:
        target: Target being scanned.
        scan_type: Type of scan.
        progress: Overall progress (0.0 to 1.0).
        phases: List of (phase_name, progress, findings) tuples.
        findings_total: Total findings count.
        elapsed: Elapsed time in seconds.
        primary: Primary theme color.
        text_color: Main text color.
        muted: Muted text color.

    Returns:
        Rich Panel with scan progress.
    """
    widget = ScanProgressWidget()
    widget.start_scan(target, scan_type)

    if phases:
        for phase_name, phase_progress, phase_findings in phases:
            status = (
                "completed"
                if phase_progress >= 1.0
                else "running"
                if phase_progress > 0
                else "pending"
            )
            widget.update_phase(phase_name, phase_progress, phase_findings, status)

    widget.scan.total_findings = findings_total
    widget.scan.started_at = time.time() - elapsed

    return widget.render(primary=primary, text_color=text_color, muted=muted)

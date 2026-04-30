"""tools/progress_display.py

Beautiful Progress Display - Apple-Inspired Progress Indicators.

Purpose:
- Show scan progress with beautiful visual indicators
- Real-time updates without cluttering output
- Multiple progress formats (bars, spinners, trees)
- Contextual status messages
- Clean, minimal, delightful

Philosophy:
- Apple: Beautiful animations, clean aesthetics
- Wozniak: Just works, no configuration needed
- Friction-free: Informative without being distracting

Features:
1. Tree-style progress (phases with sub-tasks)
2. Compact progress bars with ETA
3. Spinner animations for indeterminate tasks
4. Status panels with key metrics
5. Auto-complete and success/failure states

Usage:
    from tools.progress_display import ProgressDisplay, ScanPhase
    
    # Create display
    progress = ProgressDisplay(target="target.com")
    
    # Define phases
    phases = [
        ScanPhase("recon", "Reconnaissance", ["DNS", "Subdomains", "Endpoints"]),
        ScanPhase("scan", "Vulnerability Scan", ["BOLA", "SQLi", "XSS"]),
        ScanPhase("analyze", "AI Analysis", ["Processing", "Correlation", "Ranking"]),
    ]
    
    progress.start(phases)
    
    # Update progress
    progress.update("recon", 50, "Found 12 subdomains...")
    
    # Complete
    progress.complete("recon", "Found 45 assets")
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ScanPhase:
    """A phase in the scanning process."""
    id: str
    name: str
    subtasks: List[str]
    status: str = "pending"  # pending, running, complete, failed
    progress: float = 0.0
    current_task: str = ""
    result_summary: str = ""
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    @property
    def duration(self) -> float:
        """Get duration in seconds."""
        if self.start_time:
            end = self.end_time or time.time()
            return end - self.start_time
        return 0.0


@dataclass
class ProgressMetrics:
    """Overall progress metrics."""
    target: str
    start_time: float
    phases: Dict[str, ScanPhase]
    findings_count: int = 0
    requests_made: int = 0
    errors: int = 0
    
    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time
    
    @property
    def overall_progress(self) -> float:
        if not self.phases:
            return 0.0
        total = sum(p.progress for p in self.phases.values())
        return total / len(self.phases)


class ProgressDisplay:
    """
    Beautiful progress display for Elengenix scans.
    
    Features:
    - Tree-style phase display
    - Animated progress bars
    - Real-time metrics
    - Auto-updates in background thread
    """
    
    # Unicode box drawing characters (clean, professional)
    TREE_BRANCH = "├──"
    TREE_END = "└──"
    TREE_VERT = "│"
    TREE_SPACE = "   "
    
    # Progress bar characters
    BAR_FILL = "█"
    BAR_EMPTY = "░"
    BAR_WIDTH = 20
    
    def __init__(self, target: str, use_rich: bool = True):
        self.target = target
        self.metrics: Optional[ProgressMetrics] = None
        self.phases: Dict[str, ScanPhase] = {}
        self.use_rich = use_rich
        
        self._running = False
        self._update_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        # Try to import rich for better display
        try:
            from rich.console import Console
            from rich.live import Live
            from rich.table import Table
            from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
            self._rich_available = True
            self._console = Console()
        except ImportError:
            self._rich_available = False
            self._console = None
    
    def start(self, phases: List[ScanPhase]) -> None:
        """Start progress display with defined phases."""
        self.phases = {p.id: p for p in phases}
        self.metrics = ProgressMetrics(
            target=self.target,
            start_time=time.time(),
            phases=self.phases,
        )
        
        self._running = True
        
        # Print initial display
        self._print_header()
        self._render()
    
    def update(self, phase_id: str, progress: float, message: str = "") -> None:
        """Update progress for a phase."""
        with self._lock:
            if phase_id in self.phases:
                phase = self.phases[phase_id]
                phase.progress = progress
                if message:
                    phase.current_task = message
                
                if phase.status == "pending" and progress > 0:
                    phase.status = "running"
                    phase.start_time = time.time()
                
                if progress >= 100:
                    phase.status = "complete"
                    phase.end_time = time.time()
        
        self._render()
    
    def complete(self, phase_id: str, result: str = "") -> None:
        """Mark a phase as complete."""
        with self._lock:
            if phase_id in self.phases:
                phase = self.phases[phase_id]
                phase.status = "complete"
                phase.progress = 100.0
                phase.end_time = time.time()
                if result:
                    phase.result_summary = result
        
        self._render()
    
    def fail(self, phase_id: str, error: str) -> None:
        """Mark a phase as failed."""
        with self._lock:
            if phase_id in self.phases:
                phase = self.phases[phase_id]
                phase.status = "failed"
                phase.end_time = time.time()
                phase.result_summary = f"Error: {error}"
        
        self._render()
    
    def add_finding(self, severity: str = "info") -> None:
        """Record a finding."""
        with self._lock:
            if self.metrics:
                self.metrics.findings_count += 1
        
        self._render()
    
    def finish(self, summary: str = "") -> None:
        """Finish and show final summary."""
        self._running = False
        
        # Clear and show final state
        if self._rich_available:
            self._console.print()  # New line after live display
        
        self._render_final(summary)
    
    def _print_header(self) -> None:
        """Print scan header."""
        width = 60
        print()
        print(f"┌{'─' * width}┐")
        print(f"│  {'Elengenix Security Scan':<{width-3}}│")
        print(f"│  {'Target: ' + self.target:<{width-3}}│")
        print(f"└{'─' * width}┘")
        print()
    
    def _render(self) -> None:
        """Render current progress state."""
        if self._rich_available and self._console:
            self._render_rich()
        else:
            self._render_simple()
    
    def _render_rich(self) -> None:
        """Render using Rich library for better visuals."""
        from rich.table import Table
        from rich import box
        
        table = Table(
            show_header=False,
            box=box.SIMPLE,
            padding=(0, 2),
            width=70,
        )
        
        table.add_column("Status", width=3)
        table.add_column("Phase", width=20)
        table.add_column("Progress", width=25)
        table.add_column("Info", width=20)
        
        for phase in self.phases.values():
            status_icon = self._get_status_icon(phase.status)
            progress_bar = self._make_progress_bar(phase.progress)
            
            # Current task or result
            info = phase.current_task if phase.status == "running" else phase.result_summary
            if len(info) > 18:
                info = info[:15] + "..."
            
            table.add_row(
                status_icon,
                phase.name,
                progress_bar,
                info or "",
            )
        
        # Add metrics row
        if self.metrics:
            elapsed = self._format_duration(self.metrics.elapsed)
            table.add_row(
                "",
                "[dim]Elapsed[/dim]",
                f"[dim]{elapsed}[/dim]",
                f"[dim]Findings: {self.metrics.findings_count}[/dim]",
            )
        
        self._console.print(table)
    
    def _render_simple(self) -> None:
        """Render using simple ASCII (fallback)."""
        # Clear previous lines (hack for simple terminals)
        print(f"\033[{len(self.phases) + 2}A", end="")
        
        for i, phase in enumerate(self.phases.values()):
            is_last = (i == len(self.phases) - 1)
            branch = self.TREE_END if is_last else self.TREE_BRANCH
            
            status_icon = self._get_status_icon_ascii(phase.status)
            progress_bar = self._make_progress_bar(phase.progress)
            
            print(f"\r  {branch} {status_icon} {phase.name:18} {progress_bar}")
            
            # Show current task if running
            if phase.current_task and phase.status == "running":
                indent = self.TREE_SPACE if is_last else self.TREE_VERT + "  "
                task = phase.current_task[:40]
                print(f"  {indent}   {task}")
        
        # Show metrics
        if self.metrics:
            elapsed = self._format_duration(self.metrics.elapsed)
            print(f"\n  Elapsed: {elapsed} | Findings: {self.metrics.findings_count}")
        
        sys.stdout.flush()
    
    def _render_final(self, summary: str = "") -> None:
        """Render final summary."""
        print()
        print("=" * 60)
        print("  Scan Complete")
        print("=" * 60)
        
        for phase in self.phases.values():
            status = "" if phase.status == "complete" else "" if phase.status == "failed" else "○"
            duration = self._format_duration(phase.duration)
            result = phase.result_summary or f"{phase.progress:.0f}%"
            
            print(f"  {status} {phase.name:20} [{duration:>8}] {result}")
        
        if self.metrics:
            print()
            print(f"  Total time: {self._format_duration(self.metrics.elapsed)}")
            print(f"  Findings: {self.metrics.findings_count}")
        
        if summary:
            print()
            print(f"  {summary}")
        
        print("=" * 60)
    
    def _get_status_icon(self, status: str) -> str:
        """Get status icon for Rich display."""
        icons = {
            "pending": "○",
            "running": "◐",
            "complete": "",
            "failed": "",
        }
        return icons.get(status, "?")
    
    def _get_status_icon_ascii(self, status: str) -> str:
        """Get status icon for ASCII display."""
        icons = {
            "pending": "[ ]",
            "running": "[>]",
            "complete": "[OK]",
            "failed": "[XX]",
        }
        return icons.get(status, "[?]")
    
    def _make_progress_bar(self, percent: float, width: int = None) -> str:
        """Create a progress bar string."""
        width = width or self.BAR_WIDTH
        filled = int(width * percent / 100)
        empty = width - filled
        
        bar = self.BAR_FILL * filled + self.BAR_EMPTY * empty
        return f"{bar} {percent:5.1f}%"
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable form."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"


class Spinner:
    """Simple spinner for indeterminate progress."""
    
    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    def __init__(self, message: str = "Loading..."):
        self.message = message
        self._running = False
        self._thread: Optional[threading.Thread] = None
    
    def start(self) -> None:
        """Start spinner animation."""
        self._running = True
        self._thread = threading.Thread(target=self._animate)
        self._thread.daemon = True
        self._thread.start()
    
    def stop(self, final_message: str = None) -> None:
        """Stop spinner."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        
        # Clear line and show final message
        print(f"\r   {final_message or self.message}")
    
    def _animate(self) -> None:
        """Animation loop."""
        i = 0
        while self._running:
            frame = self.FRAMES[i % len(self.FRAMES)]
            print(f"\r  {frame} {self.message}", end="", flush=True)
            time.sleep(0.1)
            i += 1


class CompactProgress:
    """Compact single-line progress for simple operations."""
    
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
    
    def update(self, n: int = 1) -> None:
        """Update progress."""
        self.current += n
        self._render()
    
    def finish(self) -> None:
        """Finish progress."""
        self.current = self.total
        self._render(final=True)
        print()  # New line
    
    def _render(self, final: bool = False) -> None:
        """Render progress line."""
        percent = 100 * self.current / self.total if self.total > 0 else 0
        elapsed = time.time() - self.start_time
        
        # Calculate ETA
        if self.current > 0:
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate if rate > 0 else 0
            eta = f"{remaining:.0f}s"
        else:
            eta = "?"
        
        bar = self._make_bar(percent)
        status = "" if final else ">"
        
        print(f"\r  {status} {self.description} {bar} {self.current}/{self.total} ETA: {eta}", end="")
        sys.stdout.flush()
    
    def _make_bar(self, percent: float, width: int = 15) -> str:
        """Make mini progress bar."""
        filled = int(width * percent / 100)
        return "█" * filled + "░" * (width - filled)


def demo():
    """Demo of progress display features."""
    print("\n  Progress Display Demo")
    print("  " + "=" * 50)
    
    # Tree-style progress
    print("\n  1. Tree-style Progress:")
    progress = ProgressDisplay(target="demo.target.com")
    
    phases = [
        ScanPhase("recon", "Reconnaissance", ["DNS", "Subdomains", "Endpoints"]),
        ScanPhase("scan", "Vulnerability Scan", ["BOLA", "SQLi", "XSS"]),
        ScanPhase("analyze", "AI Analysis", ["Processing", "Correlation"]),
    ]
    
    progress.start(phases)
    
    # Simulate progress
    import time
    for i in range(0, 101, 20):
        progress.update("recon", i, f"Found {i//2} assets...")
        time.sleep(0.3)
    
    progress.complete("recon", "Found 45 assets")
    
    progress.update("scan", 50, "Testing BOLA endpoints...")
    time.sleep(0.5)
    progress.add_finding("high")
    progress.update("scan", 100, "Found 2 issues")
    progress.complete("scan")
    
    progress.finish("Scan complete - 1 high severity finding")
    
    # Compact progress
    print("\n  2. Compact Progress:")
    compact = CompactProgress(total=50, description="Testing endpoints")
    for i in range(50):
        compact.update()
        time.sleep(0.05)
    compact.finish()
    
    # Spinner
    print("\n  3. Spinner:")
    spinner = Spinner(message="Connecting to AI...")
    spinner.start()
    time.sleep(2)
    spinner.stop("Connected to Gemini")
    
    print("\n  Demo complete!")
    print("  " + "=" * 50)


if __name__ == "__main__":
    demo()

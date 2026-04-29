"""
live_display.py — Real-time Log & Activity Monitor (v1.0.0)
- Displays agent thoughts, tool execution, and progress
- Rich Live display for beautiful real-time updates
- Can run standalone or in tmux split pane
"""

import sys
import time
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from collections import deque

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn

# Setup logging to capture agent activity
LOG_DIR = Path("data")
LOG_DIR.mkdir(exist_ok=True)
ACTIVITY_LOG = LOG_DIR / "activity.log"

@dataclass
class AgentActivity:
 """Record of agent activity for display."""
 timestamp: str
 type: str # thought, action, result, error
 content: str
 step: int = 0
 tool: str = ""
 target: str = ""

class ActivityLogger:
 """Logs agent activities for live display."""
 
 def __init__(self, max_history: int = 100):
 self.max_history = max_history
 self.history: deque = deque(maxlen=max_history)
 self.current_step = 0
 
 def log_thought(self, thought: str, step: int = 0):
 """Log agent thought process."""
 activity = AgentActivity(
 timestamp=datetime.now().strftime("%H:%M:%S"),
 type="thought",
 content=thought,
 step=step
 )
 self.history.append(activity)
 self._write_to_file(activity)
 
 def log_action(self, action: str, tool: str = "", target: str = "", step: int = 0):
 """Log action execution."""
 activity = AgentActivity(
 timestamp=datetime.now().strftime("%H:%M:%S"),
 type="action",
 content=action,
 tool=tool,
 target=target,
 step=step
 )
 self.history.append(activity)
 self._write_to_file(activity)
 
 def log_result(self, result: str, success: bool = True, step: int = 0):
 """Log action result."""
 activity = AgentActivity(
 timestamp=datetime.now().strftime("%H:%M:%S"),
 type="result" if success else "error",
 content=result,
 step=step
 )
 self.history.append(activity)
 self._write_to_file(activity)
 
 def _write_to_file(self, activity: AgentActivity):
 """Write activity to log file."""
 try:
 with open(ACTIVITY_LOG, "a", encoding="utf-8") as f:
 f.write(json.dumps(asdict(activity)) + "\n")
 except:
 
 def get_recent(self, n: int = 20) -> List[AgentActivity]:
 """Get recent n activities."""
 return list(self.history)[-n:]

class LiveDisplay:
 """
 Real-time display for agent activities.
 Shows:
 - Current step / progress
 - Recent agent thoughts
 - Tool execution status
 - System metrics
 """
 
 def __init__(self):
 self.console = Console()
 self.activity_logger = ActivityLogger()
 self.running = False
 self.current_mode = "chat" # chat, logs, or full
 
 # For progress tracking
 self.current_tool = ""
 self.current_target = ""
 self.step_count = 0
 self.max_steps = 50
 
 def create_layout(self) -> Layout:
 """Create Rich layout for display."""
 layout = Layout()
 
 # Split into header, main, footer
 layout.split_column(
 Layout(name="header", size=3),
 Layout(name="main"),
 Layout(name="footer", size=3)
 )
 
 # Main area splits into left (activity) and right (stats)
 layout["main"].split_row(
 Layout(name="activity", ratio=3),
 Layout(name="stats", ratio=1)
 )
 
 return layout
 
 def render_header(self) -> Panel:
 """Render header with current status."""
 status_text = f"Step {self.step_count}/{self.max_steps}"
 if self.current_tool:
 status_text += f" | Tool: {self.current_tool}"
 if self.current_target:
 status_text += f" | Target: {self.current_target}"
 
 return Panel(
 Text(status_text, style="cyan"),
 title="[bold cyan]Agent Activity Monitor[/bold cyan]",
 border_style="cyan"
 )
 
 def render_activity_log(self) -> Panel:
 """Render recent activity log."""
 activities = self.activity_logger.get_recent(15)
 
 if not activities:
 return Panel(
 "[dim]Waiting for activity...[/dim]",
 title="[bold]Activity Log[/bold]",
 border_style="dim"
 )
 
 lines = []
 for act in activities:
 time_str = f"[dim]{act.timestamp}[/dim]"
 
 if act.type == "thought":
 content = f"[blue][/blue] {act.content[:60]}..."
 elif act.type == "action":
 tool_str = f" ([cyan]{act.tool}[/cyan])" if act.tool else ""
 content = f"[yellow][/yellow] {act.content[:50]}{tool_str}"
 elif act.type == "result":
 content = f"[green][/green] {act.content[:60]}"
 elif act.type == "error":
 content = f"[red][/red] {act.content[:60]}"
 else:
 content = act.content[:60]
 
 lines.append(f"{time_str} {content}")
 
 return Panel(
 "\n".join(lines),
 title="[bold]Recent Activity[/bold]",
 border_style="blue"
 )
 
 def render_stats(self) -> Panel:
 """Render system stats panel."""
 stats = []
 
 # Tool execution stats
 activities = list(self.activity_logger.history)
 thoughts = len([a for a in activities if a.type == "thought"])
 actions = len([a for a in activities if a.type == "action"])
 results = len([a for a in activities if a.type == "result"])
 errors = len([a for a in activities if a.type == "error"])
 
 stats.append(f"[cyan]Thoughts:[/cyan] {thoughts}")
 stats.append(f"[yellow]Actions:[/yellow] {actions}")
 stats.append(f"[green]Results:[/green] {results}")
 if errors > 0:
 stats.append(f"[red]Errors:[/red] {errors}")
 
 # Progress bar
 if self.max_steps > 0:
 progress_pct = min(100, (self.step_count / self.max_steps) * 100)
 bar_len = 20
 filled = int((progress_pct / 100) * bar_len)
 bar = "" * filled + "" * (bar_len - filled)
 stats.append(f"\n[cyan]Progress:[/cyan]")
 stats.append(f"[{bar}] {progress_pct:.0f}%")
 
 return Panel(
 "\n".join(stats),
 title="[bold]Statistics[/bold]",
 border_style="green"
 )
 
 def render_footer(self) -> Panel:
 """Render footer with shortcuts."""
 shortcuts = [
 "[dim]Press Ctrl+C to exit[/dim]",
 "[dim]Logs: data/activity.log[/dim]"
 ]
 return Panel(
 " | ".join(shortcuts),
 border_style="dim"
 )
 
 def update_display(self) -> Group:
 """Generate complete display."""
 layout = self.create_layout()
 
 layout["header"].update(self.render_header())
 layout["activity"].update(self.render_activity_log())
 layout["stats"].update(self.render_stats())
 layout["footer"].update(self.render_footer())
 
 return layout
 
 def run_live(self, duration: Optional[int] = None):
 """Run live display with updates."""
 self.running = True
 start_time = time.time()
 
 with Live(self.update_display(), console=self.console, refresh_per_second=2) as live:
 try:
 while self.running:
 # Check duration limit
 if duration and (time.time() - start_time) > duration:
 break
 
 # Update display
 live.update(self.update_display())
 time.sleep(0.5)
 
 except KeyboardInterrupt:
 self.running = False
 self.console.print("\n[dim]Live display stopped[/dim]")
 
 def log_and_display(self, message: str, msg_type: str = "info"):
 """Log message and update display immediately."""
 if msg_type == "thought":
 self.activity_logger.log_thought(message, self.step_count)
 elif msg_type == "action":
 self.activity_logger.log_action(message, self.current_tool, self.current_target, self.step_count)
 elif msg_type == "result":
 self.activity_logger.log_result(message, True, self.step_count)
 elif msg_type == "error":
 self.activity_logger.log_result(message, False, self.step_count)

# Global instance for easy access
_live_display = None
_activity_logger = None

def get_live_display() -> LiveDisplay:
 """Get or create LiveDisplay singleton."""
 global _live_display
 if _live_display is None:
 _live_display = LiveDisplay()
 return _live_display

def get_activity_logger() -> ActivityLogger:
 """Get or create ActivityLogger singleton."""
 global _activity_logger
 if _activity_logger is None:
 _activity_logger = ActivityLogger()
 return _activity_logger

def display_in_chat_mode(message: str, msg_type: str = "info"):
 """
 Display message in chat mode (simple console output).
 This is used when not in tmux or live display mode.
 """
 console = Console()
 
 if msg_type == "thought":
 console.print(f"[dim blue]• {message}[/dim blue]")
 elif msg_type == "action":
 console.print(f"[cyan]→ {message}[/cyan]")
 elif msg_type == "result":
 console.print(f"[green] {message}[/green]")
 elif msg_type == "error":
 console.print(f"[red] {message}[/red]")
 else:
 console.print(message)

def main():
 """Main entry point for live display."""
 import argparse
 import os
 
 # Detect if running in tmux
 in_tmux = os.environ.get("ELENGENIX_IN_TMUX") == "1" or os.environ.get("TMUX") is not None
 
 parser = argparse.ArgumentParser()
 parser.add_argument("--mode", choices=["logs", "full", "status"], default="logs")
 parser.add_argument("--duration", type=int, default=None, help="Duration in seconds")
 args = parser.parse_args()
 
 display = get_live_display()
 
 if args.mode == "logs":
 # Simple log tail mode
 console = Console()
 
 if in_tmux:
 console.print("[bold cyan]Agent Activity Monitor[/bold cyan] [dim](tmux mode)[/dim]\n")
 else:
 console.print("[bold cyan]Agent Activity Log[/bold cyan]\n")
 
 # Check if activity log exists and has content
 if ACTIVITY_LOG.exists():
 try:
 with open(ACTIVITY_LOG, 'r') as f:
 lines = f.readlines()
 # Load last activities
 for line in lines[-20:]:
 try:
 data = json.loads(line)
 activity = AgentActivity(**data)
 display.activity_logger.history.append(activity)
 except:
 except:
 
 # Start live display
 display.run_live(duration=args.duration)
 
 elif args.mode == "status":
 # Quick status display
 console = Console()
 stats = {
 "mode": "Universal Agent",
 "step": 5,
 "current_tool": "nuclei",
 "target": "example.com"
 }
 console.print(Panel(
 f"Mode: [cyan]{stats['mode']}[/cyan]\n"
 f"Step: [yellow]{stats['step']}[/yellow]\n"
 f"Tool: [green]{stats['current_tool']}[/green]\n"
 f"Target: [blue]{stats['target']}[/blue]",
 title="Status",
 border_style="cyan"
 ))

if __name__ == "__main__":
 main()

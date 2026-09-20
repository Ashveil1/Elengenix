"""
cli/help_text.py — Plain-English `elengenix --help` text.

Goal: a first-time user should be able to copy-paste a working command
for the four most common tasks without knowing any jargon. Rendered via
the shared Rich console.
"""

from __future__ import annotations

from cli.ui_components import console

HELP_TEXT = """
[bold #ffffff]ELENGENIX — Universal AI & Bug Bounty Agent[/bold #ffffff]

[bold]Common tasks[/bold] [dim](copy-paste these):[/dim]

  [bold #ffffff]Hunt a target[/bold]
    elengenix hunt example.com        [dim]# full AI-driven vulnerability hunt[/dim]
    elengenix example.com             [dim]# shorthand — auto-detects what to do[/dim]

  [bold #ffffff]Self-test / benchmark[/bold]
    elengenix doctor                  [dim]# check setup: keys, packages, ports[/dim]
    python3 benchmark/run_benchmark.py --json   [dim]# run the offline benchmark[/dim]

  [bold #ffffff]See which AI providers are set up[/bold]
    elengenix configure               [dim]# interactive setup: shows provider, model, key status[/dim]

  [bold #ffffff]Interactive chat / TUI[/bold]
    elengenix tui                     [dim]# full-screen terminal UI (default)[/dim]
    elengenix hack                    [dim]# AI chat assistant (same brain as TUI)[/dim]

[bold]Options[/bold]
  -h, --help       Show this help
  --quiet, -q      Only show the final summary
  --mode MODE      Governance mode: strict | ask | auto
  --rate-limit N   Max requests per second (default 5)

[bold]Something went wrong?[/bold]
  Logs live in [bold]~/.elengenix/data/logs/[/bold] — check the newest file.
  Run [bold]elengenix doctor[/bold] to diagnose setup problems step by step.
"""


def show_help() -> None:
    """Print the plain-English help panel."""
    console.print(HELP_TEXT)

"""
commands/ — Elengenix Command Registry Package
================================================
World-class command dispatch system for 30+ CLI commands.
Each command is a self-contained module with a register() function.
"""

from commands.registry import CommandRegistry, command

__all__ = ["CommandRegistry", "command"]
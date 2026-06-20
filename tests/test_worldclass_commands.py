"""tests/test_worldclass_commands.py

Integration tests for the new world-class CLI commands:
    zero-day, logic, supply-chain, hypothesis, world.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _args(**kw):
    """Build a minimal argparse-like Namespace."""
    import argparse
    base = {"target": None, "format": None, "output": None,
            "max_probes": 5, "endpoints": None}
    base.update(kw)
    return argparse.Namespace(**base)


def test_world_class_commands_registered() -> None:
    """All 5 world-class commands must be registered."""
    import commands.worldclass  # noqa: F401
    from commands.registry import CommandRegistry
    reg = CommandRegistry()
    world_cmds = [c for c in reg.list_all() if c.category == "world-class"]
    names = {c.name for c in world_cmds}
    assert {"zero-day", "logic", "supply-chain", "hypothesis", "world"} <= names


def test_supply_chain_command_runs(tmp_path: Path) -> None:
    """Supply-chain command runs end-to-end on a fixture project."""
    # Create a fixture with a vulnerable dependency
    (tmp_path / "requirements.txt").write_text(
        "django==3.0.0\n"   # CVE-2020-13254
        "requests==2.20.0\n"  # CVE-2018-18074
    )
    # Run via import + dispatch
    import commands.worldclass as wc
    args = _args(target=str(tmp_path), format="summary")
    rc = asyncio.run(wc.cmd_supply_chain(args))
    assert rc == 0
    # Reports should be generated
    reports = list((ROOT / "reports").glob("supply_chain_*/"))
    assert len(reports) >= 1
    # SBOM file should exist in the latest report
    latest = sorted(reports)[-1]
    assert (latest / "sbom.json").exists()
    assert (latest / "findings.json").exists()


def test_world_command_renders() -> None:
    """World TUI command must produce non-empty output without crashing."""
    import commands.worldclass as wc
    args = _args(target="example.com")
    rc = asyncio.run(wc.cmd_world(args))
    assert rc == 0


def test_world_command_no_target() -> None:
    """World command should work even without a target."""
    import commands.worldclass as wc
    args = _args(target=None)
    rc = asyncio.run(wc.cmd_world(args))
    assert rc == 0


def test_supply_chain_handles_missing_dir(tmp_path: Path) -> None:
    """Supply-chain should not crash on an empty/non-existent project path."""
    empty = tmp_path / "empty_proj"
    empty.mkdir()
    import commands.worldclass as wc
    args = _args(target=str(empty), format="summary")
    rc = asyncio.run(wc.cmd_supply_chain(args))
    assert rc == 0


def test_zero_day_command_real_target() -> None:
    """Zero-day command should run without crashing against a real target."""
    import commands.worldclass as wc
    args = _args(target="httpbin.org", max_probes=2)
    rc = asyncio.run(wc.cmd_zero_day(args))
    assert rc == 0


def test_logic_command_runs() -> None:
    """Logic command should run end-to-end."""
    import commands.worldclass as wc
    args = _args(target="httpbin.org", endpoints=None)
    rc = asyncio.run(wc.cmd_logic_flaw(args))
    assert rc == 0


def test_hypothesis_command_runs() -> None:
    """Hypothesis command should run end-to-end."""
    import commands.worldclass as wc
    args = _args(target="httpbin.org")
    rc = asyncio.run(wc.cmd_hypothesis(args))
    assert rc == 0


def test_command_aliases_resolve() -> None:
    """Aliases (e.g. 'sbom' -> 'supply-chain') must resolve."""
    from commands.registry import CommandRegistry
    reg = CommandRegistry()
    cmd = reg.get("sbom")
    assert cmd is not None
    assert cmd.name == "supply-chain"
    cmd = reg.get("0day")
    assert cmd is not None
    assert cmd.name == "zero-day"

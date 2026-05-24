#!/usr/bin/env python3
"""
run.py — Launcher for Red Team Agent Framework.
Can be run from either the redteam_agent/ directory or the parent directory.
"""
import sys
from pathlib import Path

# Support both: python3 run.py (from redteam_agent/) and python3 run.py (from parent)
this_dir = Path(__file__).resolve().parent
parent_dir = this_dir.parent

# If this file lives inside the package dir, add the parent so imports work
if (this_dir / "__init__.py").exists():
    sys.path.insert(0, str(parent_dir))
else:
    sys.path.insert(0, str(this_dir))

from redteam_agent.main import main

if __name__ == "__main__":
    run_config = len(sys.argv) > 1 and sys.argv[1].lower() in ["config", "--config", "setup"]
    main(run_config=run_config)

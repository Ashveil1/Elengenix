#!/usr/bin/env python3
"""
run.py — Standalone launcher for Red Team Agent Framework.
Place this file at the same level as the redteam_agent/ folder.

Directory structure:
  your_project/
  ├── run.py            ← this file
  ├── .env              ← your API keys
  └── redteam_agent/
      ├── __init__.py
      ├── main.py
      └── ...
"""
import sys
from pathlib import Path

# Ensure this file's directory (the project root) is on the path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

from redteam_agent.main import main

if __name__ == "__main__":
    main()

"""Conftest for brutal tests — ensures the elengenix package root is on sys.path.

This mirrors the project-root ``tests/conftest.py`` so the ``tests/brutal``
subdirectory can discover the package even when pytest is invoked from a
sub-directory.
"""
import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

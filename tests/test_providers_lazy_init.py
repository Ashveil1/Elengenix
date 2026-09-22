"""Lazy package-init guarantees for ``elengenix`` and ``elengenix.providers``.

Locks in the import-weight fix: importing the packages must stay cheap
(no pydantic/boto3/httpx/openai stack pulled in), while every name the
original eager ``__init__`` exported still resolves through PEP 562
``__getattr__`` with identical semantics.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

HEAVY_MODULES = ("pydantic", "boto3", "httpx", "openai", "anthropic")

SNIPPET_BARE = (
    "import sys, time; sys.path.insert(0, {root!r});\n"
    "t = time.perf_counter()\n"
    "{stmt}\n"
    "print(f'ELAPSED={{(time.perf_counter()-t)*1000:.0f}}')\n"
    "print('HEAVY=', [m for m in {heavy!r} if m in sys.modules])\n"
)


def _run_snippet(stmt: str) -> tuple[float, list[str]]:
    code = SNIPPET_BARE.format(root=str(REPO_ROOT), stmt=stmt, heavy=HEAVY_MODULES)
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stderr[-1500:]
    lines = dict(
        ln.split("=", 1) for ln in proc.stdout.strip().splitlines() if "=" in ln
    )
    return float(lines["ELAPSED"]), eval(lines["HEAVY"])


class TestProvidersLazyInit:
    def test_bare_import_is_light(self):
        elapsed, heavy = _run_snippet("import elengenix.providers")
        assert heavy == [], f"bare import pulled heavy deps: {heavy}"
        assert elapsed < 1000, f"bare import too slow: {elapsed:.0f}ms"

    def test_bare_import_does_not_load_submodules(self):
        """Only stdlib helpers should live in the module namespace at import."""
        code = (
            "import sys; sys.path.insert(0, {root!r});\n"
            "import elengenix.providers as m\n"
            "submods = [k for k, v in vars(m).items()\n"
            "           if not k.startswith('_') and k != 'annotations'\n"
            "           and type(v).__name__ == 'module']\n"
            "print('SUBMODS=', submods)\n"
        ).format(root=str(REPO_ROOT))
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
        )
        assert proc.returncode == 0, proc.stderr[-1500:]
        submods = eval(proc.stdout.strip().split("=", 1)[1])
        assert submods == []

    def test_every_lazy_name_resolves(self):
        """All mapped re-exports resolve via __getattr__ (and get cached)."""
        code = (
            "import sys; sys.path.insert(0, {root!r});\n"
            "import elengenix.providers as m\n"
            "for name in m._LAZY_MAP:\n"
            "    getattr(m, name)\n"
            "print('RESOLVED=', len(m._LAZY_MAP))\n"
        ).format(root=str(REPO_ROOT))
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=300
        )
        assert proc.returncode == 0, proc.stderr[-1500:]
        resolved = int(proc.stdout.strip().split("=", 1)[1])
        assert resolved >= 120  # full provider surface (125 at time of writing)

    def test_unknown_attribute_raises_attributeerror(self):
        code = (
            "import sys; sys.path.insert(0, {root!r});\n"
            "import elengenix.providers as m\n"
            "try:\n"
            "    m.DoesNotExist\n"
            "except AttributeError as e:\n"
            "    print('OK=')\n"
            "else:\n"
            "    print('FAIL=')\n"
        ).format(root=str(REPO_ROOT))
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
        )
        assert proc.returncode == 0, proc.stderr[-1500:]
        assert "OK=" in proc.stdout

    def test_catalog_is_stdlonly(self):
        """catalog must import without any heavy third-party dependency."""
        elapsed, heavy = _run_snippet(
            "from elengenix.providers.catalog import ProviderSpec, iter_specs"
        )
        assert heavy == []
        assert elapsed < 500


class TestPackageRootLazyInit:
    def test_elengenix_bare_import_no_chromadb(self):
        """`import elengenix` must not drag brain→memory→chromadb."""
        code = (
            "import sys; sys.path.insert(0, {root!r});\n"
            "import elengenix\n"
            "print('HEAVY=', [m for m in ('chromadb', 'sentence_transformers')\n"
            "                 if m in sys.modules])\n"
        ).format(root=str(REPO_ROOT))
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
        )
        assert proc.returncode == 0, proc.stderr[-1500:]
        heavy = eval(proc.stdout.strip().split("=", 1)[1])
        assert heavy == []

    def test_lazy_brain_loop_resolve(self):
        code = (
            "import sys; sys.path.insert(0, {root!r});\n"
            "import elengenix\n"
            "print('BRAIN=', elengenix.TrueAIBrain.__name__)\n"
            "print('LOOP=', elengenix.TrueAgenticLoop.__name__)\n"
        ).format(root=str(REPO_ROOT))
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=300
        )
        assert proc.returncode == 0, proc.stderr[-1500:]
        out = proc.stdout
        assert "BRAIN= TrueAIBrain" in out and "LOOP= TrueAgenticLoop" in out

"""
cli/doctor.py — `elengenix doctor` system health check.

Prints pass/fail per item with a concrete fix hint, so non-technical users
can self-serve setup problems. Purely read-only checks — no network calls
beyond an optional socket probe, no state mutation.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import socket
import sys
from typing import Any, Dict, List, Tuple

from cli.ui_components import console, create_doctor_table

# Packages the CLI/TUI actually imports at runtime.
_KEY_PACKAGES = ["rich", "textual", "yaml", "requests", "prompt_toolkit"]


def _check_python_version() -> Tuple[str, str, str]:
    v = sys.version_info
    txt = f"Python {v.major}.{v.minor}.{v.micro}"
    if v >= (3, 10):
        return ("ok", txt, "")
    return ("fail", txt, "Elengenix needs Python 3.10+ — install a newer Python.")


def _check_key_packages() -> Tuple[str, str, str]:
    missing = [p for p in _KEY_PACKAGES if importlib.util.find_spec(p) is None]
    if not missing:
        return ("ok", f"{len(_KEY_PACKAGES)}/{len(_KEY_PACKAGES)} key packages installed", "")
    return (
        "fail",
        f"missing: {', '.join(missing)}",
        f"pip install {' '.join(missing)}",
    )


def _check_provider_configured() -> Tuple[str, str, str]:
    try:
        from tools.ai_config import describe_provider_setup

        info: Dict[str, Any] = describe_provider_setup()
    except Exception as e:
        return ("fail", f"provider check error: {e}", "run: elengenix configure")

    if info.get("ok") and info.get("key_set"):
        return (
            "ok",
            f"provider '{info.get('active')}' key set ({info.get('key_source', 'env')})",
            "",
        )
    if info.get("ok"):
        return (
            "warn",
            "a provider is marked usable but the active one has no key",
            "set an API key env var or run: elengenix configure",
        )
    return (
        "fail",
        "no AI provider configured",
        "set e.g. GEMINI_API_KEY, or run: elengenix configure",
    )


def _check_home_writable() -> Tuple[str, str, str]:
    from elengenix.paths import ELENGENIX_HOME

    try:
        ELENGENIX_HOME.mkdir(parents=True, exist_ok=True)
        probe = ELENGENIX_HOME / ".doctor_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return ("ok", f"{ELENGENIX_HOME} writable", "")
    except Exception as e:
        return (
            "fail",
            f"{ELENGENIX_HOME} not writable: {e}",
            f"fix permissions: mkdir -p {ELENGENIX_HOME} && chmod u+rwx {ELENGENIX_HOME}",
        )


def _check_oob_port() -> Tuple[str, str, str]:
    """OOB/listener port availability check.

    Uses ELENGENIX_OOB_PORT (default 0 = any free port). We bind+close to
    confirm the OS will hand us a listener at scan time.
    """
    port_env = os.getenv("ELENGENIX_OOB_PORT", "0").strip()
    try:
        port = int(port_env)
    except ValueError:
        return ("fail", f"invalid ELENGENIX_OOB_PORT={port_env!r}", "unset it or set a number")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            actual = s.getsockname()[1]
        return ("ok", f"OOB listener port available (:{actual})", "")
    except OSError as e:
        return (
            "fail",
            f"port {port or 'auto'} unavailable: {e}",
            "pick another ELENGENIX_OOB_PORT or free the port",
        )


_CHECKS = [
    ("Python version", _check_python_version),
    ("Key packages", _check_key_packages),
    ("AI provider + key", _check_provider_configured),
    ("~/.elengenix writable", _check_home_writable),
    ("OOB port available", _check_oob_port),
]


def run_doctor() -> bool:
    """Run all health checks and render a pass/fail table.

    Returns:
        True when every check passed (warnings allowed), False otherwise.
    """
    rows: List[Dict[str, str]] = []
    any_fail = False
    any_warn = False
    for name, fn in _CHECKS:
        try:
            status, details, fix = fn()
        except Exception as e:  # a broken check reports as failure, not crash
            status, details, fix = "fail", f"{type(e).__name__}: {e}", ""
        if status == "fail":
            any_fail = True
        elif status == "warn":
            any_warn = True
        if fix:
            details = f"{details}\n[dim]fix: {fix}[/dim]"
        rows.append({"name": name, "status": status, "details": details})

    console.print()
    console.print(create_doctor_table(rows))
    if any_fail:
        console.print(
            "\n[bold #888888][WARN] Some checks failed.[/bold #888888] "
            "[dim]Apply the 'fix:' hints above, then re-run[/dim] [bold]elengenix doctor[/bold]"
        )
    elif any_warn:
        console.print(
            "\n[dim][WARN] Passed with warnings — review the WARN rows above.[/dim]"
        )
    else:
        console.print(
            "\n[bold #ffffff][OK] All checks passed — you're ready to hunt.[/bold #ffffff]"
        )
    console.print()
    return not any_fail


if __name__ == "__main__":
    sys.exit(0 if run_doctor() else 1)

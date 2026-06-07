"""
tools/doctor.py — Elengenix Framework Health Check
- Checks Python version, config, and core library dependencies that BUILD Elengenix
- Checks AI provider connectivity
- Auto-repair mode: guides/installs missing libraries via pip
- Does NOT check third-party security tools (nuclei, subfinder, etc.).
  Those are external — the AI can discover them via shell or request user to install.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import yaml
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger("elengenix.doctor")

# Python libraries that BUILD Elengenix itself: (import_name, pip_name, is_required)
# These are the framework's own dependencies, not third-party security tools.
PYTHON_LIBRARIES: List[Tuple[str, str, bool]] = [
    ("rich", "rich", True),
    ("yaml", "PyYAML", True),
    ("questionary", "questionary", True),
    ("dotenv", "python-dotenv", True),
    ("requests", "requests", True),
    ("textual", "textual", True),
    ("chromadb", "chromadb", True),
    # Heavy ML deps are OPTIONAL — only required for vector memory embeddings.
    # The core framework runs without them; memory will use keyword fallback.
    ("sentence_transformers", "sentence-transformers", False),
    ("tiktoken", "tiktoken", False),
]

PYTHON_MIN = (3, 10)


def _in_virtualenv() -> bool:
    """Return True when the current Python interpreter is running inside a venv."""
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def _project_root() -> Path:
    """Return the project root directory based on this module location."""
    return Path(__file__).resolve().parent.parent


def _venv_candidates() -> List[Path]:
    """Return supported virtual environment directories in priority order."""
    root = _project_root()
    candidates: List[Path] = []
    active_venv = os.environ.get("VIRTUAL_ENV", "").strip()
    if active_venv:
        candidates.append(Path(active_venv))
    candidates.extend([root / "venv", root / ".venv"])
    return candidates


def _resolve_venv_python(venv_dir: Path) -> Optional[Path]:
    """Return the best available Python executable inside a venv."""
    bin_dir = venv_dir / "bin"
    direct_candidates = [
        bin_dir / "python",
        bin_dir / "python3",
    ]
    for candidate in direct_candidates:
        if candidate.exists():
            return candidate

    versioned = sorted(bin_dir.glob("python3.*"), reverse=True)
    for candidate in versioned:
        if candidate.exists():
            return candidate
    return None


def _venv_needs_repair(venv_dir: Path) -> bool:
    """Return True when a venv directory exists but does not contain a usable Python."""
    return venv_dir.exists() and _resolve_venv_python(venv_dir) is None


def _find_project_venv() -> Optional[Path]:
    """Return the project virtual environment directory if one already exists."""
    for candidate in _venv_candidates():
        if _resolve_venv_python(candidate) is not None:
            return candidate
    return None


def _project_python() -> Path:
    """Return the Python executable that should be used for checks and installs."""
    project_venv = _find_project_venv()
    if project_venv:
        python_executable = _resolve_venv_python(project_venv)
        if python_executable is not None:
            return python_executable
    return Path(sys.executable)


def _ensure_project_venv() -> Tuple[Optional[Path], str]:
    """Ensure the project venv exists and return (python_path, output)."""
    existing = _find_project_venv()
    if existing:
        python_executable = _resolve_venv_python(existing)
        if python_executable is not None:
            return python_executable, ""

    target_dir = _project_root() / "venv"
    venv_args = [sys.executable, "-m", "venv"]
    if _venv_needs_repair(target_dir):
        venv_args.append("--clear")
    venv_args.append(str(target_dir))
    proc = subprocess.run(
        venv_args,
        capture_output=True,
        text=True,
        cwd=_project_root(),
    )
    output = "\n".join(part for part in [proc.stdout, proc.stderr] if part).strip()
    python_path = _resolve_venv_python(target_dir)
    if proc.returncode == 0 and python_path is not None:
        return python_path, output
    return None, output


def _check_python(python_executable: Path) -> Tuple[bool, str]:
    """Check the version of the Python interpreter used by Elengenix."""
    proc = subprocess.run(
        [str(python_executable), "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"],
        capture_output=True,
        text=True,
    )
    version = (proc.stdout or "").strip() or "unknown"
    parts = version.split(".")
    try:
        parsed: tuple = tuple(int(part) for part in parts[:3])
    except ValueError:
        parsed = (0, 0, 0)
    ok = parsed >= PYTHON_MIN
    return ok, version


def _check_library(import_name: str, python_executable: Path) -> Tuple[bool, str]:
    """Check if a Python library is importable from the runtime interpreter.

    Uses a hard 10s timeout per import. Heavy ML libraries (sentence_transformers,
    torch, tiktoken) can take 30-60s to import on first run, so we cap the
    subprocess to avoid hanging the health check.
    """
    try:
        proc = subprocess.run(
            [str(python_executable), "-c", f"import {import_name}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0, "Installed" if proc.returncode == 0 else "Not found"
    except subprocess.TimeoutExpired:
        return False, "Import timed out (>10s)"
    except Exception as e:
        return False, f"Check failed: {type(e).__name__}"


def _check_config() -> Tuple[bool, str]:
    """Validate configuration: checks config.yaml, .env file, and environment variables."""
    config_path = Path("config.yaml")
    if not config_path.exists():
        return False, "config.yaml not found"
    try:
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f)
        if not cfg or "ai" not in cfg:
            return False, "config.yaml missing 'ai' section"
        provider = cfg["ai"].get("active_provider", "")

        # Priority check: ENV var > .env file > config.yaml
        env_key_name = f"{provider.upper()}_API_KEY"
        api_key = os.getenv(env_key_name, "")

        # Fallback: check .env file directly if env var is empty
        if not api_key:
            env_path = Path(".env")
            if env_path.exists():
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith(f"{env_key_name}="):
                        api_key = line.split("=", 1)[1].strip()
                        break

        # Fallback: check config.yaml (not recommended, but supported)
        if not api_key:
            api_key = cfg["ai"].get("providers", {}).get(provider, {}).get("api_key", "")

        if not api_key or "YOUR" in str(api_key).upper() or api_key.startswith("sk-..."):
            return False, (
                f"API key for '{provider}' not set. "
                f"Set {env_key_name} in .env or as an environment variable"
            )
        return True, f"OK (provider: {provider})"
    except Exception as e:
        return False, f"Parse error: {e}"


def _install_python_packages(packages: List[str]) -> Tuple[bool, str]:
    """Install Python packages into the project venv and return (success, combined_output)."""
    python_executable = _project_python()
    venv_output = ""

    if _find_project_venv() is None:
        python_executable, venv_output = _ensure_project_venv()
        if python_executable is None:
            return False, venv_output

    upgrade = subprocess.run(
        [str(python_executable), "-m", "pip", "install", "--upgrade", "pip"],
        capture_output=True,
        text=True,
        cwd=_project_root(),
    )
    install = subprocess.run(
        [str(python_executable), "-m", "pip", "install", *packages],
        capture_output=True,
        text=True,
        cwd=_project_root(),
    )
    output = "\n".join(
        part for part in [venv_output, upgrade.stdout, upgrade.stderr, install.stdout, install.stderr] if part
    ).strip()
    return install.returncode == 0, output


def check_health(interactive: bool = True) -> bool:
    """
    Full system health check.
    If interactive=True, prompts the user to fix issues dynamically.
    Returns True if system is healthy.
    """
    from ui_components import console, print_error, print_success, print_warning, confirm
    
    console.print("\n[bold red]System Health Check[/bold red] [dim]1.0.0[/dim]\n")
    all_ok = True
    runtime_python = _project_python()
    project_venv = _find_project_venv()

    # ── Python Version ─────────────────────────────────────────────────────────
    py_ok, py_ver = _check_python(runtime_python)
    console.print("[bold red]Python Runtime[/bold red]")
    status = "[bold white]OK[/bold white]" if py_ok else "[bold red]FAIL[/bold red]"
    detail = py_ver + (f" (need >={PYTHON_MIN[0]}.{PYTHON_MIN[1]})" if not py_ok else "")
    console.print(f"  Version: {status} {detail}")
    if project_venv:
        console.print(f"  Runtime: [bold white]venv[/bold white] [dim]({runtime_python})[/dim]")
    elif _in_virtualenv():
        console.print(f"  Runtime: [bold white]active virtualenv[/bold white] [dim]({runtime_python})[/dim]")
    else:
        console.print(f"  Runtime: [bold white]system python[/bold white] [dim]({runtime_python})[/dim]")
    if not py_ok:
        all_ok = False
    console.print()

    # ── Config ─────────────────────────────────────────────────────────────────
    cfg_ok, cfg_msg = _check_config()
    console.print("[bold red]Configuration[/bold red]")
    status = "[bold white]OK[/bold white]" if cfg_ok else "[bold red]FAIL[/bold red]"
    console.print(f"  config.yaml: {status} {cfg_msg}")
    if not cfg_ok:
        all_ok = False
        if interactive and confirm("API Keys not configured. Run configuration wizard now?", default=True):
            console.print("\n[grey70]Launching Configuration Wizard...[/grey70]")
            try:
                import wizard
                wizard.main()
                # Re-check config after wizard
                cfg_ok, cfg_msg = _check_config()
                if cfg_ok:
                    all_ok = True
                    console.print(f"  [bold white]New config:[/bold white] {cfg_msg}")
            except Exception as e:
                logger.error(f"Wizard failed: {e}")
    console.print()

    # ── Python Libraries ─────────────────────────────────────────────────────────
    console.print("[bold red]Python Libraries[/bold red]")
    
    missing_required: List[str] = []
    missing_optional: List[str] = []
    
    for import_name, pip_name, is_required in PYTHON_LIBRARIES:
        ok, info = _check_library(import_name, runtime_python)
        if ok:
            status = "[bold white]OK[/bold white]"
            console.print(f"  {pip_name}: {status}")
        else:
            if is_required:
                status = "[bold red]Missing (Required)[/bold red]"
                missing_required.append(pip_name)
                all_ok = False
            else:
                status = "[bold yellow]Missing (Optional)[/bold yellow]"
                missing_optional.append(pip_name)
            console.print(f"  {pip_name}: {status}")
            
    console.print()

    # Auto-repair / instructions for missing libraries
    if missing_required or missing_optional:
        if missing_required:
            print_error(f"Missing required libraries: {', '.join(missing_required)}")
        if missing_optional:
            print_warning(f"Missing optional libraries: {', '.join(missing_optional)}")
            
        if interactive:
            try:
                import questionary
                choices = []
                if missing_required:
                    choices.append("Install missing required libraries")
                if missing_optional:
                    choices.append("Install missing optional libraries")
                choices.append("Skip for now")
                
                choice = questionary.select(
                    "Missing python libraries detected. What would you like to do?",
                    choices=choices
                ).ask()
                
                if choice == "Install missing required libraries":
                    to_install = [name for import_name, name, req in PYTHON_LIBRARIES if req and name in missing_required]
                    console.print(f"[*] Installing required libraries: {', '.join(to_install)}...")
                    success, output = _install_python_packages(to_install)
                    if success:
                        console.print("[bold white][OK][/bold white] Dependencies installed into project venv")
                        all_ok = check_health(interactive=False)
                        return all_ok
                    print_error("Automatic installation failed")
                    if output:
                        console.print(f"[dim]{output[-1200:]}[/dim]")
                    return False
                elif choice == "Install missing optional libraries":
                    to_install = [name for import_name, name, req in PYTHON_LIBRARIES if not req and name in missing_optional]
                    console.print(f"[*] Installing optional libraries: {', '.join(to_install)}...")
                    success, output = _install_python_packages(to_install)
                    if success:
                        console.print("[bold white][OK][/bold white] Dependencies installed into project venv")
                        all_ok = check_health(interactive=False)
                        return all_ok
                    print_error("Automatic installation failed")
                    if output:
                        console.print(f"[dim]{output[-1200:]}[/dim]")
                    return False
            except ImportError:
                print_warning("questionary module missing. Run setup.sh to install core dependencies.")
            except Exception as e:
                logger.error(f"Error during library installation prompt: {e}")

    # ── Note about external tools ───────────────────────────────────────────────
    # Elengenix does NOT bundle or check third-party security tools (scanners, fuzzers, etc.).
    # The AI agent discovers tools via shell (`which`, `command -v`) and can request
    # the user to install a tool when needed. See `install_tool` action in the system prompt.
    console.print("[dim]Note: External security tools are not checked here. The AI agent discovers and requests them on demand.[/dim]")
    console.print()

    # ── Final Verdict ──────────────────────────────────────────────────────────
    console.print()
    if all_ok:
        print_success("System is healthy and ready for use")
    else:
        print_warning("System still has some unresolved issues. Run 'elengenix doctor' again later.")
    console.print()

    return all_ok


if __name__ == "__main__":
    import sys
    import os
    # Ensure the root directory is in sys.path so we can import root modules like ui_components
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    check_health(interactive="--no-interactive" not in sys.argv)

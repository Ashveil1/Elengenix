import sys
import subprocess
import os

# 🚀 Bulletproof Dependency Checker
def ensure_dependencies():
    required_libs = {
        "yaml": "pyyaml",
        "rich": "rich",
        "questionary": "questionary",
        "requests": "requests",
        "google.generativeai": "google-generativeai",
        "openai": "openai",
        "anthropic": "anthropic",
        "trafilatura": "trafilatura"
    }
    
    missing = []
    for module, package in required_libs.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"[*] Missing libraries detected: {', '.join(missing)}")
        print("[*] Attempting to install missing dependencies automatically...")
        try:
            # Added --break-system-packages for Termux compatibility
            cmd = [sys.executable, "-m", "pip", "install"] + missing + ["--break-system-packages"]
            subprocess.run(cmd, check=True)
            print("[*] Successfully installed dependencies. Restarting...\n")
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as e:
            # Fallback if the flag itself is not supported in older pip versions
            try:
                cmd = [sys.executable, "-m", "pip", "install"] + missing
                subprocess.run(cmd, check=True)
                os.execv(sys.executable, [sys.executable] + sys.argv)
            except:
                print(f"[❌] Auto-installation failed. Please run manually: pip install {' '.join(missing)} --break-system-packages")
                sys.exit(1)

ensure_dependencies()

# (Rest of main.py content follows...)
import argparse
import yaml
import questionary
from rich.console import Console
from rich.panel import Panel

# Safety imports
try:
    from dependency_manager import check_and_install_dependencies
    from tools.doctor import check_health
    from tools_menu import show_tools_menu
    from tools.omni_scan import run_omni_scan
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from dependency_manager import check_and_install_dependencies
    from tools.doctor import check_health
    from tools_menu import show_tools_menu
    from tools.omni_scan import run_omni_scan
...

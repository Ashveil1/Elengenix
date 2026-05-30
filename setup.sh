#!/usr/bin/env bash

# ============================================================
#   Elengenix - Indestructible Professional Installer
#   Supports: Debian, Arch, Fedora, macOS
#   Version: 1.0.0
#   Optimized: Installs only Python dependencies
# ============================================================

set -e

# --- Color definitions ---
RED='\033[0;31m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

run_with_spinner() {
    local msg="$1"
    shift
    echo -n -e "${RED}[INFO]${NC} $msg "
    "$@" >/dev/null 2>&1 &
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf "[%c]" "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b"
    done
    wait $pid
    local status=$?
    if [ $status -eq 0 ]; then
        echo -e "\r${WHITE}[OK]${NC} $msg   "
    else
        echo -e "\r${RED}[FAIL]${NC} $msg   "
    fi
    return $status
}

#  ERROR TRAP
trap 'echo -e "\n${RED}[!] Error occurred at line $LINENO. Installation failed.${NC}";' ERR

# Verify we're in the right directory
if [ ! -f "sentinel" ] && [ ! -f "main.py" ]; then
    error "Please run this script from the Elengenix project directory (where 'sentinel' or 'main.py' is located)"
fi

[ -t 1 ] && clear || true
echo -e "${RED}"
echo " ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗"
echo " ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝"
echo " █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ "
echo " ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ "
echo " ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗"
echo " ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}Professional Installation Hub"
echo -e "  ${GRAY}Universal Agent + Bug Bounty Specialist (Python Only)${NC}"
echo -e "  ${GRAY}──────────────────────────────────────────────${NC}"
echo ""

# 1. Privilege & Platform Detection
OS="$(uname -s)"
info "Detecting Platform: ${BOLD}$OS${NC}"

if [[ "$OS" == "Linux" ]]; then
    if [[ "$EUID" -ne 0 ]]; then
        info "Checking sudo access..."
        if ! sudo -n true 2>/dev/null; then
            warning "This script requires sudo privileges to install system packages. You may be prompted for password."
            sudo -v
        fi
    fi
fi

# 2. System Dependencies (Python only)
info "STEP 1/4: Installing system dependencies..."
if [[ "$OS" == "Linux" ]]; then
    if [ -f /etc/debian_version ]; then
        sudo apt-get update -qq
        sudo apt-get install -y python3 python3-pip python3-venv git curl libyaml-dev build-essential
    elif [ -f /etc/arch-release ]; then
        sudo pacman -Sy --noconfirm python python-pip git curl libyaml base-devel
    elif [ -f /etc/fedora-release ]; then
        sudo dnf install -y python3 python3-pip git curl libyaml-devel gcc
    fi
elif [[ "$OS" == "Darwin" ]]; then
    if ! command -v brew >/dev/null 2>&1; then
        error "Homebrew not found. Install it from https://brew.sh/"
    fi
    brew install python git curl libyaml
fi
success "System dependencies installed."

# 3. Virtual Environment
info "STEP 2/4: Setting up isolated Virtual Environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    success "Created venv"
fi
source venv/bin/activate
VENV_PYTHON="$(pwd)/venv/bin/python"
info "Installing Python requirements..."
if [ ! -f "requirements.txt" ]; then
    error "requirements.txt not found. Ensure you're in the Elengenix directory."
fi
if ! "$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel --quiet; then error "Failed to upgrade pip"; fi
if ! "$VENV_PYTHON" -m pip install -r requirements.txt --quiet; then error "Failed to install requirements.txt"; fi

success "Python environment secured."

# 4. Global Command Creation
info "STEP 3/4: Creating global command 'elengenix'..."
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_PATH="$PROJECT_DIR/sentinel"

chmod +x "$SENTINEL_PATH"
WRAPPER_PATH="/usr/local/bin/elengenix"

if sudo ln -sf "$SENTINEL_PATH" "$WRAPPER_PATH" 2>/dev/null; then
    success "Global command 'elengenix' linked at $WRAPPER_PATH"
else
    warning "Permission denied. Please add this to your .bashrc:"
    echo -e "export PATH=\"\$PATH:$PROJECT_DIR\""
fi

# 5. Configuration
info "STEP 4/4: Finalizing Configuration..."
if [ -f "wizard.py" ]; then
    "$VENV_PYTHON" wizard.py || warning "Wizard issues detected."
else
    warning "wizard.py not found."
fi

echo ""
echo -e "${RED}══════════════════════════════════════════${NC}"
echo -e "${WHITE}   INSTALLATION SUCCESSFUL!${NC}"
echo -e "${RED}══════════════════════════════════════════${NC}"
echo ""
echo -e "   ${BOLD}Start hunting with:${NC}"
if command -v elengenix >/dev/null 2>&1; then
    echo -e "      elengenix           - Launch interactive menu"
    echo -e "      elengenix doctor    - Check tool installation"
    echo -e "      elengenix scan <target>  - Run full scan"
fi
echo ""
echo -e "  ${RED}Note:${NC} If commands are not found, restart your terminal or run:"
echo -e "      source ~/.bashrc"
echo ""

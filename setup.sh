#!/bin/bash

# ============================================================
#   Elengenix - Indestructible Professional Installer
#   Supports: Debian, Arch, Fedora, macOS
#   Version: 1.5.1
# ============================================================

set -e

# --- Color definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# 🛡️ ERROR TRAP
trap 'echo -e "\n${RED}[!] Error occurred at line $LINENO. Installation failed.${NC}";' ERR

clear
echo -e "${CYAN}"
echo "  ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗"
echo "  ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝"
echo "  █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ "
echo "  ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ "
echo "  ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗"
echo "  ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}Professional Installation Hub v1.5.1${NC}"
echo "  ──────────────────────────────────────────────"
echo ""

# 1. Privilege & Platform Detection
OS="$(uname -s)"
info "Detecting Platform: ${BOLD}$OS${NC}"

if [[ "$OS" == "Linux" ]]; then
    if [[ "$EUID" -ne 0 ]]; then
        info "Checking sudo access..."
        if ! sudo -n true 2>/dev/null; then
            warning "This script requires sudo privileges. You may be prompted for password."
            sudo -v
        fi
    fi
fi

# 2. System Dependencies
info "STEP 1/5: Installing system dependencies..."
if [[ "$OS" == "Linux" ]]; then
    if [ -f /etc/debian_version ]; then
        sudo apt-get update -qq
        sudo apt-get install -y python3 python3-pip python3-venv golang git curl libyaml-dev build-essential
    elif [ -f /etc/arch-release ]; then
        sudo pacman -Sy --noconfirm python python-pip go git curl libyaml base-devel
    elif [ -f /etc/fedora-release ]; then
        sudo dnf install -y python3 python3-pip golang git curl libyaml-devel gcc
    fi
elif [[ "$OS" == "Darwin" ]]; then
    if ! command -v brew >/dev/null 2>&1; then
        error "Homebrew not found. Install it from https://brew.sh/"
    fi
    brew install python go git curl libyaml
fi
success "System dependencies installed."

# 3. Virtual Environment
info "STEP 2/5: Setting up isolated Virtual Environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    success "Created venv"
fi
source venv/bin/activate
info "Installing Python requirements..."
if ! pip install --upgrade pip --quiet; then error "Failed to upgrade pip"; fi
if ! pip install -r requirements.txt --quiet; then error "Failed to install requirements.txt"; fi
success "Python environment secured."

# 4. Security Tools
info "STEP 3/5: Installing Go-based Security Tools..."
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

declare -A TOOLS=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
)

for tool in "${!TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        info "Installing $tool..."
        go install -v "${TOOLS[$tool]}" > /dev/null 2>&1 || warning "Could not install $tool"
    fi
    if command -v "$tool" >/dev/null 2>&1 || [ -f "$GOPATH/bin/$tool" ]; then
        success "$tool verified."
    fi
done

# 5. Global Command Creation
info "STEP 4/5: Integrating global command 'elengenix'..."
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

# 6. Configuration
info "STEP 5/5: Finalizing Configuration..."
if [ -f "wizard.py" ]; then
    python3 wizard.py || warning "Wizard issues detected."
else
    warning "wizard.py not found."
fi

echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ INSTALLATION SUCCESSFUL!${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
if command -v elengenix >/dev/null 2>&1; then
    echo -e "  🚀 Start hunting with: ${BOLD}elengenix${NC}"
else
    echo -e "  🚀 Run manually: ${BOLD}./sentinel${NC}"
fi
echo ""

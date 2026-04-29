#!/bin/bash

# ============================================================
#   Elengenix - Indestructible Professional Installer
#   Supports: Debian, Arch, Fedora, macOS
#   Version: 2.0.0 (Universal Agent Edition)
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

# Verify we're in the right directory
if [ ! -f "sentinel" ] && [ ! -f "main.py" ]; then
    error "Please run this script from the Elengenix project directory (where 'sentinel' or 'main.py' is located)"
fi

clear
echo -e "${CYAN}"
echo "  ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗"
echo "  ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝"
echo "  █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ "
echo "  ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ "
echo "  ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗"
echo "  ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}Professional Installation Hub v2.0.0${NC}"
echo -e "  ${CYAN}Universal Agent + Bug Bounty Specialist${NC}"
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
if [ ! -f "requirements.txt" ]; then
    error "requirements.txt not found. Ensure you're in the Elengenix directory."
fi
if ! pip install --upgrade pip --quiet; then error "Failed to upgrade pip"; fi
if ! pip install -r requirements.txt --quiet; then error "Failed to install requirements.txt"; fi

# 3.5 Vector Memory Dependencies (ChromaDB + Sentence Transformers)
info "Installing Vector Memory system (ChromaDB)..."
if pip install chromadb sentence-transformers --quiet 2>/dev/null; then
    success "Vector Memory system installed"
else
    warning "ChromaDB installation had issues (optional - will use SQLite fallback)"
fi

# 3.6 AI Provider Dependencies (Comprehensive support)
info "Installing AI provider dependencies..."
AI_DEPS="openai anthropic google-generativeai cohere huggingface-hub replicate"
for dep in $AI_DEPS; do
    info "  Installing $dep..."
    pip install "$dep" --quiet 2>/dev/null || warning "  $dep install had issues (continuing)"
done
success "AI providers installed (set API keys in config to use)"

success "Python environment secured."

# 4. Security Tools
info "STEP 3/5: Installing Security Tools..."
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:/usr/local/bin"

# 4.1 Go-based Tools (ProjectDiscovery + Additional)
declare -A GO_TOOLS=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
    ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
    ["ffuf"]="github.com/ffuf/ffuf@latest"
)

info "Installing Go-based security tools..."
for tool in "${!GO_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        info "  Installing $tool..."
        if go install -v "${GO_TOOLS[$tool]}" 2>/dev/null; then
            success "  $tool installed"
        else
            warning "  Could not install $tool (may require manual installation)"
        fi
    else
        success "  $tool already installed"
    fi
done

# Ensure Go bin is in PATH for tool verification
export PATH="$PATH:$GOPATH/bin"

# 4.2 Python-based Tools
info "Installing Python-based security tools..."

# Arjun - Parameter discovery
if ! command -v arjun >/dev/null 2>&1; then
    info "  Installing arjun..."
    if pip install arjun 2>/dev/null; then
        success "  arjun installed"
    else
        warning "  Could not install arjun"
    fi
else
    success "  arjun already installed"
fi

# 4.3 TruffleHog - Secret Detection
if ! command -v trufflehog >/dev/null 2>&1; then
    info "Installing TruffleHog (secret scanner)..."
    info "  Downloading TruffleHog installer..."
    
    # Try official installer first
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null; then
        success "  TruffleHog installed to /usr/local/bin"
    else
        # Fallback: manual download latest release
        info "  Trying manual download..."
        TRUFFLE_URL=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep "browser_download_url.*linux_amd64" | cut -d '"' -f 4)
        if [ -n "$TRUFFLE_URL" ]; then
            curl -sL "$TRUFFLE_URL" -o /tmp/trufflehog.tar.gz
            tar -xzf /tmp/trufflehog.tar.gz -C /tmp/
            sudo mv /tmp/trufflehog /usr/local/bin/trufflehog 2>/dev/null || mv /tmp/trufflehog "$GOPATH/bin/trufflehog"
            chmod +x /usr/local/bin/trufflehog 2>/dev/null || chmod +x "$GOPATH/bin/trufflehog"
            success "  TruffleHog installed"
        else
            warning "  Could not install TruffleHog (manual installation required)"
        fi
    fi
else
    success "  TruffleHog already installed"
fi

# 4.4 Verify all critical tools
info "Verifying tool installation..."
MISSING_TOOLS=()
for tool in subfinder httpx nuclei naabu katana dalfox ffuf; do
    if command -v "$tool" >/dev/null 2>&1 || [ -f "$GOPATH/bin/$tool" ]; then
        success "  ✓ $tool"
    else
        MISSING_TOOLS+=("$tool")
        warning "  ✗ $tool not in PATH"
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    warning "Some tools may need manual installation or PATH configuration"
    info "Add this to your ~/.bashrc or ~/.zshrc:"
    echo "export PATH=\"\$PATH:$GOPATH/bin\""
fi

# 5. Global Command Creation
info "STEP 4/5: Creating global command 'elengenix'..."
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
echo -e "  🛠️  ${BOLD}Installed Security Tools:${NC}"
echo ""

# Show installed tools status
for tool in subfinder httpx nuclei naabu dalfox ffuf katana arjun trufflehog; do
    if command -v "$tool" >/dev/null 2>&1 || [ -f "$GOPATH/bin/$tool" ] || [ -f "$HOME/.local/bin/$tool" ]; then
        echo -e "    ${GREEN}✓${NC} $tool"
    else
        echo -e "    ${YELLOW}○${NC} $tool (optional/manual install)"
    fi
done

echo ""
echo -e "  🚀 ${BOLD}Start hunting with:${NC}"
if command -v elengenix >/dev/null 2>&1; then
    echo -e "      elengenix           - Launch interactive menu"
    echo -e "      elengenix doctor    - Check tool installation"
    echo -e "      elengenix scan <target>  - Run full scan"
else
    echo -e "      ./sentinel          - Launch manually"
fi
echo ""
echo -e "  ${CYAN}Note:${NC} If tools are not found, restart your terminal or run:"
echo -e "      source ~/.bashrc"
echo ""

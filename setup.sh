#!/usr/bin/env bash

# ============================================================
#   Elengenix - Indestructible Professional Installer
#   Supports: Debian, Arch, Fedora, macOS
#   Version: v99999
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

# --- Smart install detection (idempotent — safe to re-run) ---

is_cmd_available() {
    command -v "$1" >/dev/null 2>&1
}

is_python_pkg_installed() {
    "$VENV_PYTHON" -m pip show "$1" >/dev/null 2>&1
}

is_system_pkg_installed() {
    case "$OS" in
        Linux)
            if [ -f /etc/debian_version ]; then
                dpkg -s "$1" >/dev/null 2>&1
            elif [ -f /etc/arch-release ]; then
                pacman -Qi "$1" >/dev/null 2>&1
            elif [ -f /etc/fedora-release ]; then
                rpm -q "$1" >/dev/null 2>&1
            else
                return 1
            fi
            ;;
        Darwin)
            brew list "$1" >/dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

# Filter a list of packages: keep only those NOT already installed
# Usage: filter_missing_python_pkgs pkg1 pkg2 ... → echoes missing ones
filter_missing_python_pkgs() {
    for pkg in "$@"; do
        if is_python_pkg_installed "$pkg"; then
            info "  [skip] python: $pkg (already installed)"
        else
            echo "$pkg"
        fi
    done
}

filter_missing_system_pkgs() {
    for pkg in "$@"; do
        if is_system_pkg_installed "$pkg"; then
            info "  [skip] system: $pkg (already installed)"
        else
            echo "$pkg"
        fi
    done
}

# Extract bare package name from requirements.txt line (strips version specifiers)
extract_pkg_name() {
    echo "$1" | sed -E 's/[><=!~].*//; s/^[[:space:]]+//; s/[[:space:]]+$//' | grep -v '^#' | grep -v '^$'
}

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
trap 'echo -e "\n${RED}[!] Error occurred at line ${BASH_LINENO[0]}. Installation failed.${NC}";' ERR

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

# 2. System Dependencies (Python only) — smart install, skip if already present
info "STEP 1/4: Installing system dependencies..."
if [[ "$OS" == "Linux" ]]; then
    if [ -f /etc/debian_version ]; then
        sudo apt-get update -qq || true
        MISSING_SYS=$(filter_missing_system_pkgs python3 python3-pip python3-venv git curl libyaml-dev build-essential)
        if [ -n "$MISSING_SYS" ]; then
            info "  Installing missing: $MISSING_SYS"
            sudo apt-get install -y $MISSING_SYS
        fi
    elif [ -f /etc/arch-release ]; then
        MISSING_SYS=$(filter_missing_system_pkgs python python-pip git curl libyaml base-devel)
        if [ -n "$MISSING_SYS" ]; then
            info "  Installing missing: $MISSING_SYS"
            sudo pacman -Sy --noconfirm $MISSING_SYS
        fi
    elif [ -f /etc/fedora-release ]; then
        MISSING_SYS=$(filter_missing_system_pkgs python3 python3-pip git curl libyaml-devel gcc)
        if [ -n "$MISSING_SYS" ]; then
            info "  Installing missing: $MISSING_SYS"
            sudo dnf install -y $MISSING_SYS
        fi
    fi
elif [[ "$OS" == "Darwin" ]]; then
    if ! command -v brew >/dev/null 2>&1; then
        error "Homebrew not found. Install it from https://brew.sh/"
    fi
    MISSING_SYS=$(filter_missing_system_pkgs python git curl libyaml)
    if [ -n "$MISSING_SYS" ]; then
        info "  Installing missing: $MISSING_SYS"
        brew install $MISSING_SYS
    fi
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

# 3. Smart Python install — skip packages already present in venv
info "Checking Python dependencies (skipping installed)..."
# Parse requirements.txt → list of bare package names
ALL_PY_PKGS=()
while IFS= read -r line; do
    pkg=$(extract_pkg_name "$line")
    [ -n "$pkg" ] && ALL_PY_PKGS+=("$pkg")
done < requirements.txt

# Build a clean requirements file with ONLY the missing packages (preserves version specifiers)
MISSING_REQ="_missing_requirements.txt"
: > "$MISSING_REQ"
while IFS= read -r line; do
    pkg=$(extract_pkg_name "$line")
    if [ -n "$pkg" ] && ! is_python_pkg_installed "$pkg"; then
        info "  [need] python: $pkg"
        echo "$line" >> "$MISSING_REQ"
    elif [ -n "$pkg" ]; then
        info "  [skip] python: $pkg (already installed)"
    fi
done < requirements.txt

if [ -s "$MISSING_REQ" ]; then
    info "Installing $(grep -cv '^#\|^$' "$MISSING_REQ" 2>/dev/null || echo 0) missing Python packages..."
    "$VENV_PYTHON" -m pip install --default-timeout=120 --no-cache-dir -r "$MISSING_REQ" --quiet || {
        warning "Some packages failed to install. Retrying with longer timeout..."
        "$VENV_PYTHON" -m pip install --default-timeout=300 --no-cache-dir -r "$MISSING_REQ" --quiet || {
            warning "Second attempt also failed. Trying individual core packages..."
            # Last resort: install core packages individually
            CORE_PKGS=(pyyaml requests python-dotenv rich questionary prompt-toolkit
                textual nest-asyncio tenacity
                openai google-generativeai anthropic cohere huggingface-hub replicate
                python-telegram-bot
                tiktoken trafilatura duckduckgo-search googlesearch-python
                pytest pytest-asyncio)
            MISSING_CORE=$(filter_missing_python_pkgs "${CORE_PKGS[@]}")
            if [ -n "$MISSING_CORE" ]; then
                "$VENV_PYTHON" -m pip install --default-timeout=300 --no-cache-dir --quiet $MISSING_CORE \
                    || error "Failed to install core packages"
            else
                info "  All core packages already installed."
            fi
        }
    }
    rm -f "$MISSING_REQ"
else
    success "All Python dependencies already installed."
fi

# Try to install heavy packages separately so the script can still complete
# even if chromadb/sentence-transformers fail (they need rust + compilation)
HEAVY_PKGS=(chromadb sentence-transformers)
MISSING_HEAVY=$(filter_missing_python_pkgs "${HEAVY_PKGS[@]}")
if [ -n "$MISSING_HEAVY" ]; then
    info "Installing optional heavy packages: $MISSING_HEAVY"
    "$VENV_PYTHON" -m pip install --default-timeout=300 --no-cache-dir --quiet $MISSING_HEAVY \
        2>/dev/null || warning "Vector memory packages not installed (optional — run 'pip install chromadb sentence-transformers' manually if needed)"
else
    info "  [skip] heavy: chromadb, sentence-transformers (already installed)"
fi

success "Python environment secured."

# 4. Global Command Creation
info "STEP 3/4: Creating global command 'elengenix'..."
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_PATH="$PROJECT_DIR/sentinel"
WRAPPER_PATH="/usr/local/bin/elengenix"

if [ -f "$SENTINEL_PATH" ]; then
    chmod +x "$SENTINEL_PATH"
else
    error "sentinel file not found at $SENTINEL_PATH"
fi

if [ -L "$WRAPPER_PATH" ] || [ ! -e "$WRAPPER_PATH" ]; then
    if sudo ln -sf "$SENTINEL_PATH" "$WRAPPER_PATH" 2>/dev/null; then
        success "Global command 'elengenix' linked at $WRAPPER_PATH"
    else
        warning "Permission denied. Please add this to your .bashrc:"
        echo -e "export PATH=\"\$PATH:$PROJECT_DIR\""
    fi
else
    warning "A file already exists at $WRAPPER_PATH and is not a symlink. Skipping."
    echo -e "export PATH=\"\$PATH:$PROJECT_DIR\""
fi

# 5. Configuration
info "STEP 4/4: Finalizing Configuration..."
if "$VENV_PYTHON" -c "from tools.config_wizard import run_config_wizard" 2>/dev/null; then
    "$VENV_PYTHON" -c "from tools.config_wizard import run_config_wizard; run_config_wizard()" || warning "Wizard issues detected."
else
    warning "tools/config_wizard not found. Skipping configuration wizard."
fi

# Post-install verification
info "Pre-fetching heavy AI models (ChromaDB embedding, ~79MB)..."
# This avoids a 15-25 minute first-scan delay
VENV_PYTHON_ABS="$(pwd)/venv/bin/python"
if "$VENV_PYTHON_ABS" -c "import chromadb" 2>/dev/null; then
    "$VENV_PYTHON_ABS" -c "
import chromadb
try:
    c = chromadb.PersistentClient(path='data/vector_memory')
    coll = c.get_or_create_collection('prefetch_setup')
    coll.add(documents=['setup prefetch'], ids=['s1'])
    coll.query(query_texts=['prefetch'], n_results=1)
    try: c.delete_collection('prefetch_setup')
    except: pass
    print('  [OK] ChromaDB model cached')
except Exception as e:
    print(f'  [WARN] Prefetch failed: {type(e).__name__}: {str(e)[:60]}')
" 2>&1 | grep -E "OK|WARN" || warning "ChromaDB prefetch skipped"
else
    info "  [skip] chromadb not installed — skipping model prefetch"
fi

info "Verifying installation..."
VERIFY_OK=true
for module in yaml rich requests dotenv openai; do
    if ! "$VENV_PYTHON" -c "import $module" 2>/dev/null; then
        warning "Module not importable: $module"
        VERIFY_OK=false
    fi
done
if [ "$VERIFY_OK" = true ]; then
    success "Core modules verified."
else
    warning "Some modules missing — run 'elengenix doctor' for full report"
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
echo -e "  ${GREEN}Run 'elengenix doctor' to verify everything is set up correctly.${NC}"
echo ""
echo -e "  ${RED}Note:${NC} If commands are not found, restart your terminal or run:"
echo -e "      source ~/.bashrc"
echo ""

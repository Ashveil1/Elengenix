#!/data/data/com.termux/files/usr/bin/bash

# ============================================================
#   Elengenix - Professional Termux Mobile Installer
#   Optimized for Android / Mobile Security Research
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

# --- Utility functions ---
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

# Verify we're in the right directory
if [ ! -f "sentinel" ] && [ ! -f "main.py" ]; then
    error "Please run this script from the Elengenix project directory"
fi

# Python binary detection
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    error "Python is not installed in this Termux environment."
fi

clear
echo -e "${RED}"
echo " ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗"
echo " ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝"
echo " █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ "
echo " ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ "
echo " ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗"
echo " ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}Termux Mobile Hunter Setup"
echo -e "  ${GRAY}Universal Agent + Mobile Security (Python Only)${NC}"
echo -e "  ${GRAY}──────────────────────────────────────────────${NC}"
echo ""

# 1. Sequential System Installation
info "STEP 1/4: Installing system packages..."
pkg update -y
PKGS=(
    python git curl wget openssl libxml2 libxslt
    libyaml libffi clang make pkg-config binutils
    rust libjpeg-turbo zlib xz-utils sqlite
)
for pkg in "${PKGS[@]}"; do
    pkg install -y "$pkg" || warning "Could not install $pkg. Proceeding..."
done
success "System packages installed."

# 2. Virtual Environment
info "STEP 2/4: Creating isolated Python environment..."
if [ ! -d "venv" ]; then
    "$PYTHON_BIN" -m venv venv
    success "Created venv."
fi
source venv/bin/activate
VENV_PYTHON="$(pwd)/venv/bin/python"
info "Installing dependencies..."
if [ ! -f "requirements.txt" ]; then
    error "requirements.txt not found. Ensure you're in the Elengenix directory."
fi

info "Filtering heavy dependencies for Termux..."
grep -vE "^(chromadb|sentence-transformers|tiktoken|trafilatura)" requirements.txt > requirements_termux.txt

run_with_spinner "Upgrading pip/setuptools/wheel..." "$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel || error "Failed to upgrade pip/setuptools/wheel"
run_with_spinner "Installing Python requirements..." "$VENV_PYTHON" -m pip install -r requirements_termux.txt || error "Failed to install requirements.txt"
success "Python dependencies secured."

# 3. Global Command Integration
info "STEP 3/4: Creating global command 'elengenix'..."
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SENTINEL_PATH="$PROJECT_DIR/sentinel"
WRAPPER_PATH="${PREFIX}/bin/elengenix"

if [ -f "$SENTINEL_PATH" ]; then
    chmod +x "$SENTINEL_PATH"
    ln -sf "$SENTINEL_PATH" "$WRAPPER_PATH"
    success "Symlink created: $WRAPPER_PATH"
elif [ -f "$PROJECT_DIR/main.py" ]; then
    cat > "$WRAPPER_PATH" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
exec "$PROJECT_DIR/venv/bin/python" "$PROJECT_DIR/main.py" "\$@"
EOF
    chmod +x "$WRAPPER_PATH"
    success "Wrapper created: $WRAPPER_PATH"
else
    error "Launcher not found (missing sentinel and main.py)."
fi

# SMART PATH CHECK
if ! echo "$PATH" | grep -q "$PREFIX/bin"; then
    info "Fixing PATH: Adding $PREFIX/bin to ~/.bashrc..."
    echo "export PATH=\$PATH:$PREFIX/bin" >> ~/.bashrc
    success "PATH updated in ~/.bashrc"
fi

# 4. Final Config
info "STEP 4/4: Running Configuration..."
if [ -f "wizard.py" ]; then
    "$VENV_PYTHON" wizard.py || warning "Wizard issues detected."
else
    warning "wizard.py not found."
fi

echo ""
echo -e "${RED}══════════════════════════════════════════${NC}"
echo -e "${WHITE}   SETUP COMPLETE — HAPPY HUNTING${NC}"
echo -e "${RED}══════════════════════════════════════════${NC}"
echo ""
echo -e "   ${BOLD}Start hunting with:${NC}"
echo -e "      elengenix           - Launch interactive menu"
echo -e "      elengenix doctor    - Check tool installation"
echo -e "      elengenix scan <target>  - Run full scan"
echo ""
echo -e "  ${WHITE}Note:${NC} Restart Termux or run 'source ~/.bashrc' if commands not found"
echo ""

# Launch configuration wizard
echo -e "${RED}══════════════════════════════════════════${NC}"
echo -e "${WHITE}    CONFIGURATION WIZARD${NC}"
echo -e "${RED}══════════════════════════════════════════${NC}"
echo ""
echo -e "  Configure your API keys and settings now?"
echo -e "  (AI providers, Telegram, HackerOne)"
echo ""
read -p "  Run configuration wizard? [Y/n]: " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    echo ""
    info "Launching configuration wizard..."
    "$VENV_PYTHON" -c "from tools.config_wizard import run_config_wizard; run_config_wizard()" || warning "Configuration wizard had issues"
    echo ""
    success "Configuration complete!"
else
    warning "Skipped configuration."
    echo -e "  Run 'elengenix configure' anytime to set up API keys"
fi
echo ""

exit 0

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

# --- Smart install detection (idempotent — safe to re-run) ---

is_cmd_available() {
    command -v "$1" >/dev/null 2>&1
}

is_python_pkg_installed() {
    "$VENV_PYTHON" -m pip show "$1" >/dev/null 2>&1
}

is_system_pkg_installed() {
    # Termux uses 'pkg' (not dpkg) for package management
    pkg list-installed "$1" 2>/dev/null | grep -q "^$1/"
}

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

# 1. Sequential System Installation — smart install, skip if already present
info "STEP 1/4: Installing system packages..."
pkg update -y
PKGS=(
    python python-pip git curl wget openssl libxml2 libxslt
    libyaml libffi clang make pkg-config binutils
    rust libjpeg-turbo zlib xz-utils sqlite
)
MISSING_PKGS=$(filter_missing_system_pkgs "${PKGS[@]}")
if [ -n "$MISSING_PKGS" ]; then
    info "Installing missing system packages: $MISSING_PKGS"
    for pkg in $MISSING_PKGS; do
        pkg install -y "$pkg" || warning "Could not install $pkg. Proceeding..."
    done
else
    success "All system packages already installed."
fi
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

info "Filtering heavy native-compile dependencies for Termux (will install via separate step)..."
grep -vE "^(chromadb|sentence-transformers|tiktoken|trafilatura)" requirements.txt > requirements_termux.txt || cp requirements.txt requirements_termux.txt

# Smart install: only install pip/setuptools/wheel if not present
if ! "$VENV_PYTHON" -m pip --version >/dev/null 2>&1; then
    run_with_spinner "Upgrading pip/setuptools/wheel..." "$VENV_PYTHON" -m pip install --no-cache-dir --upgrade pip setuptools wheel || error "Failed to upgrade pip/setuptools/wheel"
else
    info "  [skip] pip already functional"
fi

# Build list of missing Python packages from requirements_termux.txt
MISSING_TERMUX_REQ="_missing_termux_requirements.txt"
: > "$MISSING_TERMUX_REQ"
while IFS= read -r line; do
    pkg=$(extract_pkg_name "$line")
    if [ -n "$pkg" ] && ! is_python_pkg_installed "$pkg"; then
        info "  [need] python: $pkg"
        echo "$line" >> "$MISSING_TERMUX_REQ"
    elif [ -n "$pkg" ]; then
        info "  [skip] python: $pkg (already installed)"
    fi
done < requirements_termux.txt

if [ -s "$MISSING_TERMUX_REQ" ]; then
    run_with_spinner "Installing missing Python packages..." "$VENV_PYTHON" -m pip install --no-cache-dir -r "$MISSING_TERMUX_REQ" || error "Failed to install requirements.txt"
    rm -f "$MISSING_TERMUX_REQ"
else
    success "All Python requirements already installed."
fi

# Try heavy native packages separately — these are the ones that may fail
# on Termux because of long compile times. If they fail, vector memory and
# web extraction will be disabled at runtime (not a fatal error).
HEAVY_PKGS=(chromadb sentence-transformers tiktoken trafilatura)
MISSING_HEAVY=$(filter_missing_python_pkgs "${HEAVY_PKGS[@]}")
if [ -n "$MISSING_HEAVY" ]; then
    info "Installing heavy native packages: $MISSING_HEAVY"
    "$VENV_PYTHON" -m pip install --no-cache-dir --default-timeout=600 $MISSING_HEAVY \
        2>/dev/null || warning "Heavy native packages not installed — vector memory / web extract will be disabled"
else
    info "  [skip] heavy: chromadb, sentence-transformers, tiktoken, trafilatura (already installed)"
fi

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

# Post-install verification
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

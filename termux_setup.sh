#!/data/data/com.termux/files/usr/bin/bash

# ============================================================
#   Elengenix - Professional Termux Mobile Installer
#   Optimized for Android / Mobile Security Research
# ============================================================

set -e

# --- Color definitions (Improved Escape) ---
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

clear
echo -e "${CYAN}"
echo "  ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗"
echo "  ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝"
echo "  █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ "
echo "  ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ "
echo "  ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗"
echo "  ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}Termux Mobile Hunter Setup — Professional Edition${NC}"
echo "  ──────────────────────────────────────────────"
echo ""

# 1. Environment Check
if [ ! -d "/data/data/com.termux" ]; then
    error "This script is intended for Termux only."
fi

# 2. Sequential System Installation
info "STEP 1/5: Installing core dependencies..."
pkg update -y
PKGS=(python golang git curl wget nmap ninja build-essential cmake libffi openssl libxml2 libxslt libyaml clang make python-venv)
for pkg in "${PKGS[@]}"; do
    info "Installing $pkg..."
    pkg install -y "$pkg" || warning "Failed to install $pkg. Some features may fail."
done

# 3. Virtual Environment (Security fix)
info "STEP 2/5: Creating isolated Python environment..."
if [ ! -d "venv" ]; then
    python -m venv venv
    success "Created venv."
fi
source venv/bin/activate
pip install --upgrade pip setuptools wheel --quiet
pip install -r requirements.txt --quiet
success "Python dependencies secured."

# 4. PATH and Compilation Optimization
export LDFLAGS="-L${PREFIX}/lib"
export CFLAGS="-I${PREFIX}/include"
export CPPFLAGS="-I${PREFIX}/include"

# 5. Global Command Wrapper (Robust Path Fix)
info "STEP 4/5: Creating global command 'elengenix'..."
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
WRAPPER_PATH="${PREFIX}/bin/elengenix"

cat > "$WRAPPER_PATH" << EOF
#!/data/data/com.termux/files/usr/bin/bash
source $PROJECT_DIR/venv/bin/activate
python $PROJECT_DIR/main.py "\$@"
EOF
chmod +x "$WRAPPER_PATH"
success "Command 'elengenix' is now globally available."

# 6. Final Config
info "STEP 5/5: Running Configuration Wizard..."
python wizard.py

echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  SETUP COMPLETE — HAPPY HUNTING${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo "  Usage: elengenix"
echo ""

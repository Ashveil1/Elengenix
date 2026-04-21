#!/data/data/com.termux/files/usr/bin/bash

# ============================================================
#   Elengenix - Professional Termux Mobile Installer
#   Version: 1.4.3 (10/10 Roadmap)
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
trap 'echo -e "\n${RED}[!] Termux installation interrupted or failed.${NC}";' ERR

clear
echo -e "${CYAN}"
echo "  ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗"
echo "  ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝"
echo "  █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ "
echo "  ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ "
echo "  ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗"
echo "  ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}Termux Mobile Hunter Setup v1.4.3${NC}"
echo "  ──────────────────────────────────────────────"
echo ""

# 1. Sequential System Installation
info "STEP 1/5: Installing system packages..."
pkg update -y
PKGS=(python golang git curl wget nmap ninja build-essential cmake libffi openssl libxml2 libxslt libyaml clang make python-venv)
for pkg in "${PKGS[@]}"; do
    pkg install -y "$pkg" || warning "Could not install $pkg. Proceeding..."
done

# 2. Virtual Environment (Security fix)
info "STEP 2/5: Creating isolated Python environment..."
if [ ! -d "venv" ]; then
    python -m venv venv
    success "Created venv."
fi
source venv/bin/activate
info "Installing dependencies..."
if ! pip install --upgrade pip setuptools wheel --quiet; then error "Pip upgrade failed"; fi
if ! pip install -r requirements.txt --quiet; then error "Requirements installation failed"; fi
success "Python dependencies secured."

# 3. Path & Logic Fix for Wrapper
info "STEP 4/5: Creating global command 'elengenix'..."
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
WRAPPER_PATH="${PREFIX}/bin/elengenix"

cat > "$WRAPPER_PATH" << EOF
#!/data/data/com.termux/files/usr/bin/bash
# Auto-generated launcher for Elengenix (Termux)
PROJECT_DIR="$PROJECT_DIR"
VENV_ACTIVATE="\$PROJECT_DIR/venv/bin/activate"

if [[ -f "\$VENV_ACTIVATE" ]]; then
    source "\$VENV_ACTIVATE"
fi

exec python "\$PROJECT_DIR/main.py" "\$@"
EOF

chmod +x "$WRAPPER_PATH"
success "Command 'elengenix' is now globally available."

# 4. Final Config (Wizard Check)
info "STEP 5/5: Running Configuration..."
if [ -f "wizard.py" ]; then
    python wizard.py || warning "Wizard issues detected."
else
    warning "Configure config.yaml manually."
fi

echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  SETUP COMPLETE — HAPPY HUNTING${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo "  Usage: elengenix"
echo ""

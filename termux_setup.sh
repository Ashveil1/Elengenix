#!/data/data/com.termux/files/usr/bin/bash

# ============================================================
#   Elengenix - Termux Mobile Hunter Setup (Professional)
#   Optimized for Android / Mobile Security Research
# ============================================================

set -e

# Color definitions for output
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

# 1. Platform Check
if [ ! -d "/data/data/com.termux" ]; then
    error "This script is intended for Termux environment only."
fi

# 2. System Dependencies
info "STEP 1/5: Installing system dependencies and security tools..."
pkg update -y
pkg install -y python golang git curl wget nmap ninja build-essential cmake libffi openssl libxml2 libxslt libyaml clang make 2>/dev/null

# 3. Virtual Environment Setup
info "STEP 2/5: Setting up Python Virtual Environment..."
if [ ! -d "elengenix_env" ]; then
    python -m venv elengenix_env
    success "Created elengenix_env"
fi
source elengenix_env/bin/activate
success "Virtual Environment activated"

# 4. Environment Variables for Compilation
info "STEP 3/5: Configuring environment variables for compilation..."
export LDFLAGS="-L${PREFIX}/lib"
export CFLAGS="-I${PREFIX}/include"
export CPPFLAGS="-I${PREFIX}/include"

# 5. Python Libraries
info "STEP 4/5: Installing Python libraries inside venv..."
pip install --upgrade pip setuptools wheel --quiet
pip install -r requirements.txt --quiet
success "Python libraries installed successfully"

# 6. Global Command Wrapper
info "STEP 5/5: Creating global command 'elengenix'..."
WRAPPER_PATH="${PREFIX}/bin/elengenix"
cat > "$WRAPPER_PATH" << EOF
#!/data/data/com.termux/files/usr/bin/bash
source $PWD/elengenix_env/bin/activate
python $PWD/main.py "\$@"
EOF
chmod +x "$WRAPPER_PATH"
success "Global command created: elengenix"

# ── Important Notifications ──
echo ""
echo -e "${YELLOW}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  IMPORTANT NOTICES FOR MOBILE HUNTERS${NC}"
echo -e "${YELLOW}══════════════════════════════════════════${NC}"
echo "1. Port Scanning: nmap SYN Scan (-sS) requires ROOT. Using TCP Connect Scan (-sT) as default."
echo "2. Storage: Please run 'termux-setup-storage' to allow file access."
echo "3. Go Tools: Tools like subfinder/nuclei should be installed via 'aegishunter update'."
echo "4. Environment: Always activate venv using 'source elengenix_env/bin/activate' if running manually."
echo ""
echo -e "${GREEN}Setup Complete! Type 'elengenix' to begin your mission.${NC}"
echo ""

#!/data/data/com.termux/files/usr/bin/bash

# ============================================================
#   Elengenix - Professional Termux Mobile Installer
#   Optimized for Android / Mobile Security Research
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

# 🛡️ ERROR TRAP - Only trap critical errors
# Don't trap for optional tool failures
trap 'echo -e "\n${RED}[!] Critical error during installation.${NC}";' ERR

# Verify we're in the right directory
if [ ! -f "sentinel" ] && [ ! -f "main.py" ]; then
    error "Please run this script from the Elengenix project directory"
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
echo -e "  ${BOLD}Termux Mobile Hunter Setup v2.0.0${NC}"
echo -e "  ${CYAN}Universal Agent + Mobile Security${NC}"
echo "  ──────────────────────────────────────────────"
echo ""

# 1. Sequential System Installation
info "STEP 1/5: Installing system packages..."
pkg update -y
PKGS=(python golang git curl wget nmap openssl libxml2 libxslt libyaml clang make)
# Note: python-venv not needed - Termux python includes venv
for pkg in "${PKGS[@]}"; do
    pkg install -y "$pkg" || warning "Could not install $pkg. Proceeding..."
done
success "System packages installed."

# 2. Virtual Environment
info "STEP 2/5: Creating isolated Python environment..."
if [ ! -d "venv" ]; then
    python -m venv venv
    success "Created venv."
fi
source venv/bin/activate
info "Installing dependencies..."
if [ ! -f "requirements.txt" ]; then
    error "requirements.txt not found. Ensure you're in the Elengenix directory."
fi
if ! pip install --upgrade pip setuptools wheel --quiet; then warning "Pip upgrade had issues (continuing)"; fi

# Install core dependencies (required)
info "Installing core dependencies..."
CORE_DEPS="pyyaml requests python-dotenv rich tenacity nest-asyncio"
for dep in $CORE_DEPS; do
    pip install "$dep" --quiet 2>/dev/null || warning "  $dep install had issues (continuing)"
done

# Install AI providers (all providers installed automatically)
info "Installing AI providers (OpenAI, Anthropic, Google, Cohere, Hugging Face, Replicate)..."
# Install all providers - user can choose which to use via environment variables
AI_DEPS="openai anthropic google-generativeai cohere huggingface-hub replicate"
for dep in $AI_DEPS; do
    info "  Installing $dep..."
    pip install "$dep" 2>/dev/null || warning "  $dep install had issues (continuing)"
done
success "AI providers installed (set API keys in config to use)"

# Install optional dependencies (may fail on mobile, that's OK)
info "Installing optional dependencies..."
OPTIONAL_DEPS="python-telegram-bot questionary trafilatura googlesearch-python"
for dep in $OPTIONAL_DEPS; do
    pip install "$dep" --quiet 2>/dev/null || warning "  $dep skipped (optional)"
done

success "Python dependencies secured."

# 2.5 Vector Memory (Lightweight for mobile)
info "Installing Vector Memory system..."
# Note: ChromaDB requires onnxruntime which is not available on Android/Termux
# We skip ChromaDB on mobile and use SQLite fallback instead (already built-in)
info "Note: Using SQLite fallback for memory (ChromaDB not available on mobile)"
info "Vector memory will work perfectly with SQLite backend"

# 3. Security Tools for Mobile
info "STEP 3/5: Installing Security Tools (Mobile-Optimized)..."
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:$PREFIX/bin"

# 3.1 Core Go Tools (Lightweight for mobile)
declare -A GO_TOOLS=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
)

info "Installing lightweight Go tools..."
for tool in "${!GO_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        info "  Installing $tool..."
        if go install -v "${GO_TOOLS[$tool]}" 2>/dev/null; then
            success "  $tool installed"
        else
            warning "  Could not install $tool (skipping)"
        fi
    else
        success "  $tool already installed"
    fi
done

# 3.2 Optional Heavy Tools (with warnings)
info "Installing optional tools (may take longer on mobile)..."

# naabu - Port scanner (optional on mobile due to resource usage)
if ! command -v naabu >/dev/null 2>&1; then
    info "  Installing naabu (port scanner)..."
    if go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null; then
        success "  naabu installed"
    else
        warning "  naabu installation failed (optional)"
    fi
else
    success "  naabu already installed"
fi

# ffuf - Fuzzer (optional on mobile)
if ! command -v ffuf >/dev/null 2>&1; then
    info "  Installing ffuf (web fuzzer)..."
    if go install -v github.com/ffuf/ffuf@latest 2>/dev/null; then
        success "  ffuf installed"
    else
        warning "  ffuf installation failed (optional)"
    fi
else
    success "  ffuf already installed"
fi

# dalfox - XSS scanner (lightweight enough for mobile)
if ! command -v dalfox >/dev/null 2>&1; then
    info "  Installing dalfox (XSS scanner)..."
    if go install -v github.com/hahwul/dalfox/v2@latest 2>/dev/null; then
        success "  dalfox installed"
    else
        warning "  dalfox installation failed (optional)"
    fi
else
    success "  dalfox already installed"
fi

# 3.3 Python-based Tools
info "Installing Python security tools..."

# Arjun - Parameter discovery (lightweight)
if ! command -v arjun >/dev/null 2>&1; then
    info "  Installing arjun..."
    if pip install arjun 2>/dev/null; then
        success "  arjun installed"
    else
        warning "  arjun installation failed"
    fi
else
    success "  arjun already installed"
fi

# 3.4 TruffleHog - Optional for mobile (resource intensive)
info "Checking TruffleHog (secret scanner - heavy for mobile)..."
if ! command -v trufflehog >/dev/null 2>&1; then
    warning "  TruffleHog not installed (resource intensive for mobile)"
    info "  To install manually later, run:"
    echo "      curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh"
else
    success "  TruffleHog already installed"
fi

# 3.5 Ensure PATH includes Go binaries
if [ -d "$GOPATH/bin" ]; then
    info "Adding Go tools to PATH..."
    if ! grep -q "$GOPATH/bin" ~/.bashrc 2>/dev/null; then
        echo "export PATH=\"\$PATH:$GOPATH/bin\"" >> ~/.bashrc
        success "  Added to ~/.bashrc"
    fi
fi

# 3.6 Verify tools
info "Verifying installed tools..."
VERIFIED=0
for tool in subfinder httpx katana; do
    if command -v "$tool" >/dev/null 2>&1 || [ -f "$GOPATH/bin/$tool" ]; then
        success "  ✓ $tool"
        ((VERIFIED++))
    else
        warning "  ✗ $tool (may need PATH update or manual install)"
    fi
done

if [ $VERIFIED -eq 0 ]; then
    warning "No Go tools verified. Try: export PATH=\$PATH:\$HOME/go/bin"
else
    success "$VERIFIED core tools verified"
fi

# 4. Global Command Integration
info "STEP 4/5: Creating global command 'elengenix'..."
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SENTINEL_PATH="$PROJECT_DIR/sentinel"
WRAPPER_PATH="${PREFIX}/bin/elengenix"

chmod +x "$SENTINEL_PATH"
ln -sf "$SENTINEL_PATH" "$WRAPPER_PATH"
success "Symlink created: $WRAPPER_PATH"

# 🛡️ SMART PATH CHECK
if ! echo "$PATH" | grep -q "$PREFIX/bin"; then
    info "Fixing PATH: Adding $PREFIX/bin to ~/.bashrc..."
    echo "export PATH=\$PATH:$PREFIX/bin" >> ~/.bashrc
    success "PATH updated in ~/.bashrc"
fi

# 5. Final Config
info "STEP 5/5: Running Configuration..."
if [ -f "wizard.py" ]; then
    python3 wizard.py || warning "Wizard issues detected."
else
    warning "wizard.py not found."
fi

echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  ✅ SETUP COMPLETE — HAPPY HUNTING${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo -e "  🛠️  ${BOLD}Installed Security Tools:${NC}"
echo ""

# Show installed tools status
for tool in subfinder httpx katana naabu dalfox ffuf arjun; do
    if command -v "$tool" >/dev/null 2>&1 || [ -f "$GOPATH/bin/$tool" ]; then
        echo -e "    ${GREEN}✓${NC} $tool"
    else
        echo -e "    ${YELLOW}○${NC} $tool (optional)"
    fi
done

# TruffleHog special message for mobile
if command -v trufflehog >/dev/null 2>&1; then
    echo -e "    ${GREEN}✓${NC} trufflehog"
else
    echo -e "    ${YELLOW}○${NC} trufflehog (heavy for mobile - install manually if needed)"
fi

echo ""
echo -e "  🚀 ${BOLD}Start hunting with:${NC}"
echo -e "      elengenix           - Launch interactive menu"
echo -e "      elengenix doctor    - Check tool installation"
echo -e "      elengenix scan <target>  - Run full scan"
echo ""
echo -e "  ${CYAN}Note:${NC} Restart Termux or run 'source ~/.bashrc' if commands not found"
echo ""

# Launch configuration wizard
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  ⚙️  CONFIGURATION WIZARD${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""
echo -e "  Configure your API keys and settings now?"
echo -e "  (AI providers, Telegram, HackerOne)"
echo ""
read -p "  Run configuration wizard? [Y/n]: " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    echo ""
    echo -e "${GREEN}Launching configuration wizard...${NC}"
    python3 -c "from tools.config_wizard import run_config_wizard; run_config_wizard()" || warning "Configuration wizard had issues"
    echo ""
    echo -e "${GREEN}Configuration complete!${NC}"
else
    echo -e "${YELLOW}Skipped configuration.${NC}"
    echo -e "  Run 'elengenix configure' anytime to set up API keys"
fi
echo ""

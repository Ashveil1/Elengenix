#!/bin/bash
# ============================================================
#   Elengenix - Linux / macOS Setup Script (Fixed & Improved)
#   Based on original by Ashveil1 (MIT License)
#   Fixes: broken pip syntax, missing file checks,
#          macOS support, error handling, sentinel check
# ============================================================

set -e

# ── Color output ──────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[]${NC} $1"; exit 1; }

# ── Header ───────────────────────────────────────────────────
clear
echo -e "${CYAN}"
echo "  ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗"
echo "  ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝"
echo "  █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ "
echo "  ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ "
echo "  ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗"
echo "  ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}Professional Installation — Linux / macOS${NC}"
echo "  ──────────────────────────────────────────────"
echo ""

# ── ตรวจสอบ OS ───────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
    Linux*)   PLATFORM="linux" ;;
    Darwin*)  PLATFORM="macos" ;;
    *)        error "Unsupported OS: $OS (รองรับแค่ Linux และ macOS)" ;;
esac
info "Platform detected: ${BOLD}$OS${NC}"

# ── Ensuring correct working directory ─────────────────────────
if [ ! -f "requirements.txt" ] || [ ! -f "main.py" ]; then
    error "Please run setup.sh from within the Elengenix folder only"
fi

# ── STEP 1: Core Dependencies ────────────────────────────────
echo ""
info "STEP 1/5: Installing core dependencies..."

if [ "$PLATFORM" = "linux" ]; then
    # ตรวจว่ามี sudo หรือเปล่า
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        SUDO=""
        warning "ไม่พบ sudo — จะติดตั้งโดยไม่Using sudo (ต้องเป็น root)"
    fi

    # ตรวจ package manager
    if command -v apt-get >/dev/null 2>&1; then
        info "  Using apt (Debian/Ubuntu/Kali)..."
        $SUDO apt-get update -qq
        $SUDO apt-get install -y python3 python3-pip golang git curl libyaml-dev build-essential 2>/dev/null \
            && success "  Core packages installed successfully" \
            || warning "  Some packages failed to install"

    elif command -v pacman >/dev/null 2>&1; then
        info "  Using pacman (Arch/BlackArch)..."
        $SUDO pacman -Sy --noconfirm python python-pip go git curl libyaml base-devel 2>/dev/null \
            && success "  Core packages installed successfully" \
            || warning "  Some packages failed to install"

    elif command -v dnf >/dev/null 2>&1; then
        info "  Using dnf (Fedora/RHEL)..."
        $SUDO dnf install -y python3 python3-pip golang git curl libyaml-devel gcc 2>/dev/null \
            && success "  Core packages installed successfully" \
            || warning "  Some packages failed to install"
    else
        warning "ไม่รู้จัก package manager — Skippingการติดตั้ง system packages"
    fi

elif [ "$PLATFORM" = "macos" ]; then
    # ตรวจว่ามี Homebrew
    if ! command -v brew >/dev/null 2>&1; then
        warning "ไม่พบ Homebrew — Installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
            && success "  Homebrew installed successfully" \
            || error "ติดตั้ง Homebrew ไม่สำเร็จ — ติดตั้งเองที่ https://brew.sh แล้วรันใหม่"
    fi
    info "  Using Homebrew (macOS)..."
    brew install python go git curl libyaml 2>/dev/null \
        && success "  Core packages installed successfully" \
        || warning "  Some packages failed to install"
fi

# ── STEP 2: Python Libraries ──────────────────────────────────
echo ""
info "STEP 2/5: Installing Python libraries..."

# ตรวจ python command (python3 vs python)
if command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
    PIP="pip3"
elif command -v python >/dev/null 2>&1; then
    PYTHON="python"
    PIP="pip"
else
    error "ไม่พบ Python — กรุณาติดตั้ง Python 3.8+ ก่อน"
fi
success "  Using $PYTHON ($(${PYTHON} --version 2>&1))"

# อัพเกรด pip ก่อน (แก้ bug เดิมที่ syntax ผิด)
$PIP install --upgrade pip --quiet 2>/dev/null || warning "Failed to upgrade pip, skipping"

# แก้ bug เดิม: อ่าน requirements.txt อย่างถูกต้อง กรอง comment และบรรทัดว่าง
PIP_ARGS=""
# macOS Using --break-system-packages ด้วยเช่นกันใน Python 3.12+
if $PYTHON -c "import sys; exit(0 if sys.version_info >= (3,12) else 1)" 2>/dev/null; then
    PIP_ARGS="--break-system-packages"
fi

FAILED_PKGS=()
while IFS= read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    pkg_display=$(echo "$line" | sed 's/[>=<!].*//')
    info "  Installing $pkg_display..."
    if $PIP install "$line" --quiet $PIP_ARGS 2>/dev/null; then
        success "  $pkg_display "
    else
        warning "  $pkg_display Installation failed"
        FAILED_PKGS+=("$pkg_display")
    fi
done < requirements.txt

if [ ${#FAILED_PKGS[@]} -gt 0 ]; then
    warning "Package ที่Installation failed: ${FAILED_PKGS[*]}"
    warning "ลองรันด้วยตนเอง: $PIP install ${FAILED_PKGS[*]}"
fi

# ── STEP 3: Go Security Tools ────────────────────────────────
echo ""
info "STEP 3/5: Installing Go Security Tools..."

if ! command -v go >/dev/null 2>&1; then
    error "ไม่พบ Go — กรุณาติดตั้ง Go 1.21+ จาก https://go.dev/dl/ แล้วรันใหม่"
fi
success "  พบ Go: $(go version)"

export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

# เพิ่มใน shell config ที่เหมาะสม
SHELL_RC="$HOME/.bashrc"
if [ "$PLATFORM" = "macos" ]; then
    # macOS มักUsing zsh เป็น default
    if [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ]; then
        SHELL_RC="$HOME/.zshrc"
    fi
fi

if ! grep -q 'go/bin' "$SHELL_RC" 2>/dev/null; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> "$SHELL_RC"
    success "  เพิ่ม Go path ใน $SHELL_RC แล้ว"
fi

declare -A GO_TOOLS=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
    ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
)

for tool in "${!GO_TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        success "  $tool is already installed"
    else
        echo -ne "${YELLOW}  ติดตั้ง $tool? [Y/n]: ${NC}"
        read -r choice
        choice="${choice:-Y}"
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            info "  Installing $tool (อาจUsingเวลา 1-3 นาที)..."
            if go install -v "${GO_TOOLS[$tool]}" 2>/dev/null; then
                success "  $tool installed successfully"
            else
                warning "  $tool Installation failed — บาง feature อาจไม่ทำงาน"
            fi
        else
            warning "  Skipping $tool"
        fi
    fi
done

# ── STEP 4: Global Command ───────────────────────────────────
echo ""
info "STEP 4/5: Setting up 'elengenix' command..."

SENTINEL_PATH="$PWD/sentinel"
INSTALL_DIR="/usr/local/bin"

# macOS homebrew อาจUsing path ต่างกัน
if [ "$PLATFORM" = "macos" ] && [ -d "/opt/homebrew/bin" ]; then
    INSTALL_DIR="/opt/homebrew/bin"
fi

LINK_PATH="$INSTALL_DIR/elengenix"

# แก้ bug เดิม: ตรวจว่า sentinel มีอยู่จริงก่อน
if [ -f "$SENTINEL_PATH" ]; then
    chmod +x "$SENTINEL_PATH"
    if [ -w "$INSTALL_DIR" ]; then
        ln -sf "$SENTINEL_PATH" "$LINK_PATH"
    else
        ${SUDO:-sudo} ln -sf "$SENTINEL_PATH" "$LINK_PATH"
    fi
    success "  สร้างคำสั่ง 'elengenix' ที่ $LINK_PATH"
else
    warning "  Sentinel file missing - creating wrapper script instead"
    WRAPPER=$(cat << EOF
#!/bin/bash
cd "$(dirname "$(readlink -f "$0")")" 2>/dev/null || cd "$PWD"
$PYTHON main.py "\$@"
EOF
)
    if [ -w "$INSTALL_DIR" ]; then
        echo "$WRAPPER" > "$LINK_PATH"
        chmod +x "$LINK_PATH"
    else
        echo "$WRAPPER" | ${SUDO:-sudo} tee "$LINK_PATH" > /dev/null
        ${SUDO:-sudo} chmod +x "$LINK_PATH"
    fi
    success "  สร้าง wrapper script สำรองที่ $LINK_PATH"
fi

# ── STEP 5: Configuration Wizard ────────────────────────────
echo ""
info "STEP 5/5: Launching Configuration Wizard..."

if [ -f "wizard.py" ]; then
    $PYTHON wizard.py
else
    warning "wizard.py not found - please edit config.yaml manually"
fi

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo "  วิธีUsing:"
echo -e "    ${CYAN}elengenix${NC}            — Start program"
echo -e "    ${CYAN}$PYTHON main.py${NC}   — Start with fallback mode"
echo ""
echo "  If Go commands fail, run:"
echo -e "    ${CYAN}source $SHELL_RC${NC}"
echo ""

if [ ${#FAILED_PKGS[@]} -gt 0 ]; then
    echo -e "  ${YELLOW} Python packages ที่ยังInstallation failed:${NC}"
    echo -e "    ${YELLOW}$PIP install ${FAILED_PKGS[*]}${NC}"
    echo ""
fi

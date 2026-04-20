#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#   Elengenix - Termux Setup Script (Fixed & Improved)
#   Based on original by Ashveil1 (MIT License)
#   Fixes: pip loop bug, missing file check, error handling
# ============================================================

set -e  # หยุดทันทีถ้ามี error

# ── Color output ──────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[]${NC} $1"; }

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
echo "  📱 Termux Mobile Hunter Setup"
echo "  ──────────────────────────────────────────"
echo ""

# ── Ensuring Termux environment ────────────────────────────────
if [ ! -d "/data/data/com.termux" ]; then
    error "This script is for Termux only!"
    exit 1
fi

# ── STEP 1: Core Dependencies ────────────────────────────────
info "STEP 1/5: Updating and installing core dependencies..."

# แยก update กับ upgrade เพื่อ handle error ได้ดีกว่า
pkg update -y 2>/dev/null || warning "pkg update encountered issues, skipping"
pkg upgrade -y 2>/dev/null || warning "pkg upgrade encountered issues, skipping"

CORE_PKGS="python golang git curl libpcap make clang libyaml"
for pkg_name in $CORE_PKGS; do
    if ! command -v "$pkg_name" >/dev/null 2>&1; then
        info "  Installing $pkg_name..."
        pkg install -y "$pkg_name" 2>/dev/null || warning "Failed to install"
    else
        success "  $pkg_name already exists"
    fi
done

# ── STEP 2: Python Libraries ──────────────────────────────────
info "STEP 2/5: Installing Python libraries..."

# ตรวจว่าไฟล์ requirements.txt มีอยู่จริง
if [ ! -f "requirements.txt" ]; then
    error "requirements.txt not found - Please run from Elengenix folder"
    exit 1
fi

# Fix: Filter comments and empty lines
while IFS= read -r line; do
    # ข้าม comment (#) และบรรทัดว่าง
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue

    # ตัด version specifier ออกเพื่อแสดงชื่อ package อย่างเดียว
    pkg_display=$(echo "$line" | sed 's/[>=<].*//')

    info "  Installing $pkg_display..."
    pip install "$line" --quiet --break-system-packages 2>/dev/null \
        && success "  $pkg_display installed successfully" \
        || warning "  $pkg_display failed to install (skipping)"

done < requirements.txt

# ── STEP 3: Go Security Tools ────────────────────────────────
info "STEP 3/5: Installing Go Security Tools..."

# ตั้งค่า GOPATH
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

# เพิ่มใน .bashrc ถ้ายังไม่มี
if ! grep -q 'go/bin' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> "$HOME/.bashrc"
    success "  Added Go path to .bashrc"
fi

# ตรวจว่า Go ติดตั้งอยู่จริงก่อน
if ! command -v go >/dev/null 2>&1; then
    error "ไม่พบ Go — Failed to install"
    warning "Try: pkg install golang and run setup again"
else
    # map ชื่อ tool -> คำสั่ง install
    declare -A GO_TOOLS=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
    )

    for tool in "${!GO_TOOLS[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            success "  $tool already exists"
        else
            echo -ne "${YELLOW}  ติดตั้ง $tool? [Y/n]: ${NC}"
            read -r choice
            choice="${choice:-Y}"
            if [[ "$choice" =~ ^[Yy]$ ]]; then
                info "  Installing $tool (อาจใช้เวลา 1-3 นาที)..."
                if go install -v "${GO_TOOLS[$tool]}" 2>/dev/null; then
                    success "  $tool installed successfully"
                else
                    warning "  $tool ติดตั้งไม่สำเร็จ — บาง feature อาจไม่ทำงาน"
                fi
            else
                warning "  ข้าม $tool"
            fi
        fi
    done
fi

# ── STEP 4: Global Command ───────────────────────────────────
info "STEP 4/5: Setting up 'elengenix' command..."

SENTINEL_PATH="$PWD/sentinel"
LINK_PATH="/data/data/com.termux/files/usr/bin/elengenix"

# แก้ bug เดิม: ตรวจว่าไฟล์ sentinel มีอยู่จริงก่อน symlink
if [ -f "$SENTINEL_PATH" ]; then
    chmod +x "$SENTINEL_PATH"
    ln -sf "$SENTINEL_PATH" "$LINK_PATH"
    success "  สร้างคำสั่ง 'elengenix' สำเร็จ"
else
    warning "  sentinel file missing - using fallback"
    # สร้าง wrapper script แทน
    cat > "$LINK_PATH" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd "$(dirname "$(readlink -f "$0")")" 2>/dev/null || true
python main.py "$@"
EOF
    chmod +x "$LINK_PATH"
    success "  Created fallback wrapper script"
fi

# ── STEP 5: Configuration Wizard ────────────────────────────
info "STEP 5/5: Launching Configuration Wizard..."
echo ""

if [ -f "wizard.py" ]; then
    python wizard.py
else
    warning "wizard.py not found - skipping auto-config"
    warning "Please edit config.yaml manually"
fi

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo "  Usage:"
echo -e "    ${CYAN}elengenix${NC}          — Start program (if sentinel is ready)"
echo -e "    ${CYAN}python main.py${NC}     — Start in fallback mode"
echo ""
echo "  If Go commands fail, run:"
echo -e "    ${CYAN}source ~/.bashrc${NC}"
echo ""

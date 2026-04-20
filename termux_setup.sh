#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#   Elengenix - Termux Setup Script (Fixed & Improved)
#   Based on original by Ashveil1 (MIT License)
#   Fixes: pip loop bug, missing file check, error handling
# ============================================================

set -e  # หยุดทันทีถ้ามี error

# ── สีสำหรับ output ──────────────────────────────────────────
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

# ── ตรวจว่ารันใน Termux จริงๆ ────────────────────────────────
if [ ! -d "/data/data/com.termux" ]; then
    error "Script นี้ใช้สำหรับ Termux เท่านั้น!"
    exit 1
fi

# ── STEP 1: Core Dependencies ────────────────────────────────
info "STEP 1/5: อัพเดตและติดตั้ง core dependencies..."

# แยก update กับ upgrade เพื่อ handle error ได้ดีกว่า
pkg update -y 2>/dev/null || warning "pkg update มีปัญหาบางส่วน ข้ามต่อไป"
pkg upgrade -y 2>/dev/null || warning "pkg upgrade มีปัญหาบางส่วน ข้ามต่อไป"

CORE_PKGS="python golang git curl libpcap make clang libyaml"
for pkg_name in $CORE_PKGS; do
    if ! command -v "$pkg_name" >/dev/null 2>&1; then
        info "  กำลังติดตั้ง $pkg_name..."
        pkg install -y "$pkg_name" 2>/dev/null || warning "ไม่สามารถติดตั้ง $pkg_name ได้"
    else
        success "  $pkg_name มีอยู่แล้ว"
    fi
done

# ── STEP 2: Python Libraries ──────────────────────────────────
info "STEP 2/5: ติดตั้ง Python libraries..."

# ตรวจว่าไฟล์ requirements.txt มีอยู่จริง
if [ ! -f "requirements.txt" ]; then
    error "ไม่พบไฟล์ requirements.txt — กรุณารันจากโฟลเดอร์ Elengenix"
    exit 1
fi

# แก้ bug เดิม: กรอง comment และบรรทัดว่างออกก่อน
while IFS= read -r line; do
    # ข้าม comment (#) และบรรทัดว่าง
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue

    # ตัด version specifier ออกเพื่อแสดงชื่อ package อย่างเดียว
    pkg_display=$(echo "$line" | sed 's/[>=<].*//')

    info "  กำลังติดตั้ง $pkg_display..."
    pip install "$line" --quiet --break-system-packages 2>/dev/null \
        && success "  $pkg_display ติดตั้งสำเร็จ" \
        || warning "  $pkg_display ติดตั้งไม่สำเร็จ (ข้ามต่อไป)"

done < requirements.txt

# ── STEP 3: Go Security Tools ────────────────────────────────
info "STEP 3/5: ติดตั้ง Go Security Tools..."

# ตั้งค่า GOPATH
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

# เพิ่มใน .bashrc ถ้ายังไม่มี
if ! grep -q 'go/bin' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> "$HOME/.bashrc"
    success "  เพิ่ม Go path ใน .bashrc แล้ว"
fi

# ตรวจว่า Go ติดตั้งอยู่จริงก่อน
if ! command -v go >/dev/null 2>&1; then
    error "ไม่พบ Go — ไม่สามารถติดตั้ง security tools ได้"
    warning "ลองรัน: pkg install golang แล้วรัน setup อีกครั้ง"
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
            success "  $tool มีอยู่แล้ว"
        else
            echo -ne "${YELLOW}  ติดตั้ง $tool? [Y/n]: ${NC}"
            read -r choice
            choice="${choice:-Y}"
            if [[ "$choice" =~ ^[Yy]$ ]]; then
                info "  กำลังติดตั้ง $tool (อาจใช้เวลา 1-3 นาที)..."
                if go install -v "${GO_TOOLS[$tool]}" 2>/dev/null; then
                    success "  $tool ติดตั้งสำเร็จ"
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
info "STEP 4/5: ตั้งค่าคำสั่ง 'elengenix'..."

SENTINEL_PATH="$PWD/sentinel"
LINK_PATH="/data/data/com.termux/files/usr/bin/elengenix"

# แก้ bug เดิม: ตรวจว่าไฟล์ sentinel มีอยู่จริงก่อน symlink
if [ -f "$SENTINEL_PATH" ]; then
    chmod +x "$SENTINEL_PATH"
    ln -sf "$SENTINEL_PATH" "$LINK_PATH"
    success "  สร้างคำสั่ง 'elengenix' สำเร็จ"
else
    warning "  ไม่พบไฟล์ sentinel — จะใช้ 'python main.py' แทน"
    # สร้าง wrapper script แทน
    cat > "$LINK_PATH" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd "$(dirname "$(readlink -f "$0")")" 2>/dev/null || true
python main.py "$@"
EOF
    chmod +x "$LINK_PATH"
    success "  สร้าง wrapper script สำรองแทนสำเร็จ"
fi

# ── STEP 5: Configuration Wizard ────────────────────────────
info "STEP 5/5: เปิด Configuration Wizard..."
echo ""

if [ -f "wizard.py" ]; then
    python wizard.py
else
    warning "ไม่พบ wizard.py — ข้ามการตั้งค่าอัตโนมัติ"
    warning "กรุณาแก้ไข config.yaml ด้วยตนเอง"
fi

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup เสร็จสมบูรณ์!${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo "  วิธีใช้:"
echo -e "    ${CYAN}elengenix${NC}          — เปิดโปรแกรม (ถ้า sentinel พร้อม)"
echo -e "    ${CYAN}python main.py${NC}     — เปิดแบบ fallback เสมอ"
echo ""
echo "  หากคำสั่ง Go ยังไม่ทำงาน ให้รัน:"
echo -e "    ${CYAN}source ~/.bashrc${NC}"
echo ""

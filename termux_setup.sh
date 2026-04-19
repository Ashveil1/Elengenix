#!/data/data/com.termux/files/usr/bin/bash

clear
echo "📱 Elengenix AI - Termux Mobile Hunter Setup"
echo "------------------------------------------"
echo "Preparing your mobile bug hunting environment..."
echo ""

# 1. Essential Core Dependencies
echo "[*] Installing essential core dependencies..."
pkg update && pkg upgrade -y
pkg install -y python golang git curl libpcap make clang

# 2. Python Requirements
echo ""
echo "[*] Installing Python libraries for Elengenix..."
pip install -r requirements.txt --quiet
echo "  ✅ Python libraries installed."

# 3. Bug Bounty Power Tools (The Interactive Part)
echo ""
echo "------------------------------------------"
echo "🚀 STEP 1: BUG BOUNTY TOOLS SETUP"
echo "Select which professional tools you want to install."
echo "------------------------------------------"

declare -A TOOLS_CMD
TOOLS_CMD=(
    ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
)

# Set PATH for Go
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
if ! grep -q 'go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
fi

for tool in subfinder nuclei httpx; do
    echo "❓ Tool: $tool"
    read -p "   Do you want to install $tool on your phone? [Y/n]: " choice
    choice=${choice:-Y}
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        echo "   ⏳ Installing $tool... This may take a while on mobile."
        eval ${TOOLS_CMD[$tool]} > /dev/null 2>&1
        echo "   ✅ Done."
    else
        echo "   ⚠️ Skipping $tool."
    fi
done

# 4. Launch Configuration Wizard
echo ""
echo "------------------------------------------"
echo "🚀 STEP 2: AI & TELEGRAM CONFIGURATION"
echo "------------------------------------------"
python wizard.py

echo ""
echo "------------------------------------------"
echo "✅ Termux Setup Complete! Mobile Hunter Ready."
echo "🚀 Type: python main.py to start."
echo "------------------------------------------"

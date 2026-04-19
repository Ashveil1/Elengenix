#!/bin/bash

clear
echo "🛡️  Elengenix AI - Professional Installation"
echo "------------------------------------------"
echo "Initializing the ultimate bug hunting environment..."
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 1. Core Dependencies
echo "[*] Checking core dependencies..."
for cmd in python3 pip3 go git curl; do
    if ! command_exists "$cmd"; then
        echo "  ❌ $cmd is missing. Installing..."
        sudo apt-get update && sudo apt-get install -y "$cmd"
    fi
done

# 2. Python Requirements
echo "[*] Installing required Python libraries..."
pip3 install -r requirements.txt --quiet

# 3. Security Tools Setup (Interactive)
echo ""
echo "------------------------------------------"
echo "🚀 STEP 1: SECURITY TOOLS INSTALLATION"
echo "------------------------------------------"

declare -A TOOLS_CMD
TOOLS_CMD=(
    ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["katana"]="go install github.com/projectdiscovery/katana/cmd/katana@latest"
    ["waybackurls"]="go install github.com/tomnomnom/waybackurls@latest"
)

# Set PATH for Go
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
if ! grep -q 'go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
fi

for tool in subfinder nuclei httpx katana waybackurls; do
    if ! command_exists "$tool"; then
        echo "❓ Tool '$tool' is missing."
        read -p "   Install $tool? (Recommended for full features) [Y/n]: " choice
        choice=${choice:-Y}
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            echo "   ⏳ Installing $tool..."
            eval ${TOOLS_CMD[$tool]} > /dev/null 2>&1
        fi
    else
        echo "✅ $tool is already installed."
    fi
done

# 4. Launch Configuration Wizard
echo ""
echo "------------------------------------------"
echo "🚀 STEP 2: AI & TELEGRAM CONFIGURATION"
echo "------------------------------------------"
python3 wizard.py

# 5. Create Global Command (The Easiest Way)
echo "[*] Creating global command: 'elengenix'..."
chmod +x sentinel
sudo ln -sf "$PWD/sentinel" /usr/local/bin/elengenix

echo ""
echo "------------------------------------------"
echo "✅ Elengenix AI Setup Complete!"
echo "🚀 Type 'elengenix' to start your first hunt."
echo "------------------------------------------"


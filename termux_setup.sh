#!/data/data/com.termux/files/usr/bin/bash

clear
echo "📱 Elengenix AI - Termux Mobile Hunter Setup"
echo "------------------------------------------"
echo "Checking your environment..."
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 1. Essential Core Dependencies
echo "[*] Checking core dependencies..."
for cmd in python golang git curl; do
    if command_exists "$cmd"; then
        echo "  ✅ $cmd is already installed."
    else
        echo "  ❌ $cmd is missing. Installing..."
        pkg install "$cmd" -y
    fi
done

# 2. Python Requirements
echo ""
echo "[*] Installing Python libraries for Elengenix..."
pip install -r requirements.txt --quiet
echo "  ✅ Python libraries installed."

# 3. Bug Bounty Power Tools
echo ""
echo "------------------------------------------"
echo "🚀 BUG BOUNTY TOOLS SETUP"
echo "------------------------------------------"

# Set PATH for Go
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
if ! grep -q 'go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
fi

# Define tools and their installation paths
declare -A TOOLS_CMD
TOOLS_CMD=(
    ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
)

for tool in subfinder nuclei httpx; do
    if command_exists "$tool"; then
        echo "✅ $tool is already installed."
    else
        echo "❓ Tool '$tool' is missing."
        read -p "   Do you want to install it on your phone? [Y/n]: " choice
        choice=${choice:-Y}
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            echo "   ⏳ Installing $tool... Please wait."
            eval ${TOOLS_CMD[$tool]} > /dev/null 2>&1
            echo "   ✅ Done."
        fi
    fi
done

# 4. Global Command & Wizard
echo "[*] Creating global command: 'elengenix'..."
chmod +x sentinel
ln -sf "$PWD/sentinel" /data/data/com.termux/files/usr/bin/elengenix

python wizard.py

echo ""
echo "------------------------------------------"
echo "✅ Setup Complete! Mobile Hunter Ready."
echo "🚀 Just type: elengenix"
echo "------------------------------------------"

#!/bin/bash

clear
echo "🛡️  Elengenix AI - Professional Installation"
echo "------------------------------------------"

# 1. Essential Core Dependencies
echo "[*] Checking core dependencies..."
sudo apt-get update && sudo apt-get install -y python3 python3-pip golang git curl libyaml-dev

# 2. Python Requirements (Crucial Fix)
echo "[*] Installing Python libraries for Elengenix..."
# Using --upgrade and --no-cache-dir to ensure clean install
python3 -m pip install --upgrade pip --quiet
python3 -m pip install -r requirements.txt --quiet

# 3. Security Tools Setup
echo ""
echo "------------------------------------------"
echo "🚀 STEP 1: SECURITY TOOLS INSTALLATION"
echo "------------------------------------------"

export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

for tool in subfinder nuclei httpx katana waybackurls; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "❓ Tool '$tool' is missing. Install? [Y/n]: "
        read choice
        choice=${choice:-Y}
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            echo "   ⏳ Installing $tool..."
            if [ "$tool" == "subfinder" ]; then go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest > /dev/null 2>&1; fi
            if [ "$tool" == "nuclei" ]; then go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest > /dev/null 2>&1; fi
            if [ "$tool" == "httpx" ]; then go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest > /dev/null 2>&1; fi
            if [ "$tool" == "katana" ]; then go install github.com/projectdiscovery/katana/cmd/katana@latest > /dev/null 2>&1; fi
            if [ "$tool" == "waybackurls" ]; then go install github.com/tomnomnom/waybackurls@latest > /dev/null 2>&1; fi
        fi
    else
        echo "✅ $tool is already installed."
    fi
done

# 4. Global Command
chmod +x sentinel
sudo ln -sf "$PWD/sentinel" /usr/local/bin/elengenix

# 5. Configuration Wizard
python3 wizard.py

echo "✅ Setup Complete! Type 'elengenix' to start."

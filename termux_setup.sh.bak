#!/data/data/com.termux/files/usr/bin/bash

clear
echo "📱 Elengenix AI - Termux Mobile Hunter Setup (Fixed)"
echo "------------------------------------------"

# 1. Essential Core Dependencies
echo "[*] Installing core dependencies (Termux)..."
pkg update && pkg upgrade -y
pkg install -y python golang git curl libpcap make clang libyaml

# 2. Python Requirements (Fixed for Termux Policy)
echo ""
echo "[*] Installing Python libraries for Elengenix..."
# We remove the pip upgrade line as it's forbidden, and add --break-system-packages
for req in $(cat requirements.txt); do echo "[*] Installing $req..."; pip install $req --quiet --break-system-packages; done
echo "  ✅ Python libraries installed."

# 3. Security Tools Setup
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
if ! grep -q 'go/bin' ~/.bashrc; then echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc; fi

for tool in subfinder nuclei httpx; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "❓ Install $tool? [Y/n]: "
        read choice
        choice=${choice:-Y}
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            echo "   ⏳ Installing $tool..."
            if [ "$tool" == "subfinder" ]; then go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest > /dev/null 2>&1; fi
            if [ "$tool" == "nuclei" ]; then go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest > /dev/null 2>&1; fi
            if [ "$tool" == "httpx" ]; then go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest > /dev/null 2>&1; fi
        fi
    else
        echo "✅ $tool is already installed."
    fi
done

# 4. Global Command for Termux
echo "[*] Creating global command: 'elengenix'..."
chmod +x sentinel
ln -sf "$PWD/sentinel" /data/data/com.termux/files/usr/bin/elengenix

# 5. Configuration Wizard
python wizard.py

echo ""
echo "✅ Setup Complete! Now you can type: elengenix"
echo "------------------------------------------"

#!/data/data/com.termux/files/usr/bin/bash

clear
echo "📱 Elengenix AI - Termux Mobile Hunter Setup"
echo "------------------------------------------"
echo "Preparing your mobile bug hunting environment..."
echo ""

# (Essential core dependencies and Python requirements are same...)
pkg update && pkg upgrade -y
pkg install -y python golang git curl libpcap make clang
pip install -r requirements.txt --quiet

# (Security tools setup is same...)
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

for tool in subfinder nuclei httpx; do
    echo "❓ Install $tool? [Y/n]: "
    read choice
    choice=${choice:-Y}
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        go install -v github.com/projectdiscovery/${tool}/v2/cmd/${tool}@latest > /dev/null 2>&1
    fi
done

# 🚀 THE MAGIC PART: Create Global Command for Termux
echo "[*] Creating global command: 'elengenix'..."
chmod +x sentinel
ln -sf "$PWD/sentinel" /data/data/com.termux/files/usr/bin/elengenix

# Launch Wizard
python wizard.py

echo ""
echo "------------------------------------------"
echo "✅ Setup Complete! Now you can type 'elengenix' from anywhere!"
echo "🚀 Try it now: elengenix"
echo "------------------------------------------"

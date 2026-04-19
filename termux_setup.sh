#!/data/data/com.termux/files/usr/bin/bash

echo "📱 Elengenix - Termux Mobile Hunter Setup"
echo "------------------------------------------"

# 1. Update Termux Packages
echo "[*] Updating packages..."
pkg update && pkg upgrade -y
pkg install -y python golang git curl libpcap make clang

# 2. Install Python Requirements
echo "[*] Installing Python libraries..."
# Fixed path here
pip install -r requirements.txt

# 3. Install Security Tools (Go-based)
echo "[*] Installing Go-based security tools..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "------------------------------------------"
echo "✅ Termux Setup Complete! Mobile Hunter Ready."
echo "🚀 Run: python main.py"

#!/bin/bash

# ============================================================
#   Elengenix - Universal Setup Script
#   Supports: Debian, Arch, Fedora, macOS, Termux
# ============================================================

set -e

echo "Professional Installation for Elengenix"
echo "------------------------------------------"
echo "NOTE: System packages may be installed. You might be prompted for your password."
echo ""

# 1. Platform Detection
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [ -f /etc/debian_version ]; then
        INSTALL_CMD="sudo apt-get install -y"
        UPDATE_CMD="sudo apt-get update"
    elif [ -f /etc/arch-release ]; then
        INSTALL_CMD="sudo pacman -S --noconfirm"
        UPDATE_CMD="sudo pacman -Sy"
    elif [ -f /etc/fedora-release ]; then
        INSTALL_CMD="sudo dnf install -y"
        UPDATE_CMD="sudo dnf check-update"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    if ! command -v brew >/dev/null 2>&1; then
        echo "[!] Homebrew not found. Please install it from https://brew.sh/"
        exit 1
    fi
    INSTALL_CMD="brew install"
    UPDATE_CMD="brew update"
elif [ -d "/data/data/com.termux" ]; then
    INSTALL_CMD="pkg install -y"
    UPDATE_CMD="pkg update"
fi

# 2. Run Updates and Core Install
echo "[*] Updating system repositories..."
$UPDATE_CMD > /dev/null 2>&1

echo "[*] Installing core dependencies..."
$INSTALL_CMD python3 python3-pip golang git curl libyaml-dev > /dev/null 2>&1

# 3. Python Venv & Requirements
echo "[*] Setting up Python environment..."
python3 -m pip install --upgrade pip --quiet --break-system-packages 2>/dev/null || true
python3 -m pip install -r requirements.txt --quiet --break-system-packages

# 4. Config Safety Check
if [ -f "config.yaml" ]; then
    echo "[*] Hardening config.yaml permissions (chmod 600)..."
    chmod 600 config.yaml
fi

# 5. Global Command Creation
chmod +x sentinel
if [[ "$OSTYPE" != "darwin"* ]] && [ ! -d "/data/data/com.termux" ]; then
    sudo ln -sf "$PWD/sentinel" /usr/local/bin/elengenix
else
    # Mac/Termux often handle symlinks differently
    ln -sf "$PWD/sentinel" /usr/local/bin/elengenix 2>/dev/null || true
fi

echo "------------------------------------------"
echo "Setup Complete! Start hunting with: elengenix"

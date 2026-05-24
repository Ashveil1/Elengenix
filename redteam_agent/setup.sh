#!/bin/bash
# setup.sh — First-time setup for Red Team Agent Framework
set -e

echo "=== Red Team Agent Setup ==="

# 1. Create .env from example if not exists
if [ ! -f ".env" ]; then
    if [ -f "redteam_agent/.env.example" ]; then
        cp redteam_agent/.env.example .env
        echo "[OK] Created .env from template"
        echo "     Edit .env and add your API keys before running."
    fi
else
    echo "[OK] .env already exists"
fi

# 2. Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install -r redteam_agent/requirements.txt --quiet
echo "[OK] Dependencies installed"

# 3. Create log directories
mkdir -p logs/raw
echo "[OK] Log directories created"

echo ""
echo "Setup complete. To start:"
echo "  python3 run.py"

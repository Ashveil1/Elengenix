#!/bin/bash
# setup.sh — First-time setup for Red Team Agent Framework
set -e

# Get the directory where setup.sh is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Detect the project root directory
if [[ "$(basename "$SCRIPT_DIR")" == "redteam_agent" ]]; then
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
else
    PROJECT_ROOT="$SCRIPT_DIR"
fi

cd "$PROJECT_ROOT"

echo "=== Red Team Agent Setup ==="

# 1. Create .env from example if not exists
if [ ! -f ".env" ]; then
    if [ -f "redteam_agent/.env.example" ]; then
        cp redteam_agent/.env.example .env
        echo "[OK] Created .env from template"
        echo "     Edit .env and add your API keys before running."
    elif [ -f ".env.example" ]; then
        cp .env.example .env
        echo "[OK] Created .env from template"
        echo "     Edit .env and add your API keys before running."
    fi
else
    echo "[OK] .env already exists"
fi

# 2. Install Python dependencies
echo ""
echo "Installing Python dependencies..."
if [ -f "redteam_agent/requirements.txt" ]; then
    pip install -r redteam_agent/requirements.txt --quiet
elif [ -f "requirements.txt" ]; then
    pip install -r requirements.txt --quiet
fi
echo "[OK] Dependencies installed"

# 3. Create log directories
mkdir -p logs/raw
echo "[OK] Log directories created"

echo ""
echo "Setup complete. To start:"
echo "  python3 run.py"

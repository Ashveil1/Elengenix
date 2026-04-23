#!/bin/bash
# ... (ส่วนต้นของสคริปต์เหมือนเดิม) ...

# ── STEP 4/5: Global Command Integration ──────────────────────────────────────
info "STEP 4/5: Integrating global command 'elengenix'..."
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_PATH="$PROJECT_ROOT/sentinel"

# Make sure sentinel is executable
chmod +x "$SENTINEL_PATH"

if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS approach
    WRAPPER_PATH="/usr/local/bin/elengenix"
    if sudo ln -sf "$SENTINEL_PATH" "$WRAPPER_PATH" 2>/dev/null; then
        success "Global command 'elengenix' linked at $WRAPPER_PATH"
    else
        warning "Could not create symlink. Add this to your ~/.zshrc:"
        echo -e "   ${BOLD}export PATH=\"\$PATH:$PROJECT_DIR\"${NC}"
    fi
else
    # Linux approach
    WRAPPER_PATH="/usr/local/bin/elengenix"
    if sudo ln -sf "$SENTINEL_PATH" "$WRAPPER_PATH" 2>/dev/null; then
        success "Global command 'elengenix' linked at $WRAPPER_PATH"
    else
        warning "Permission denied. Adding to local PATH instead..."
        # Check if local bin exists, if not, suggest PATH update
        echo -e "\n${YELLOW}Action Required:${NC} Add this line to your ${BOLD}~/.bashrc${NC}:"
        echo -e "export PATH=\"\$PATH:$PROJECT_DIR\""
    fi
fi

# ... (ส่วนท้ายของสคริปต์เหมือนเดิม) ...

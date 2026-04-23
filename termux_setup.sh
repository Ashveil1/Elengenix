#!/data/data/com.termux/files/usr/bin/bash
# ... (ส่วนต้นเหมือนเดิม) ...

# ── STEP 3/4: Global Command Integration (Termux Style) ──────────────────────
info "STEP 3/4: Creating global command 'elengenix'..."
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SENTINEL_PATH="$PROJECT_DIR/sentinel"
WRAPPER_PATH="${PREFIX}/bin/elengenix"

# Make sentinel executable
chmod +x "$SENTINEL_PATH"

# Create symlink to sentinel
ln -sf "$SENTINEL_PATH" "$WRAPPER_PATH"
success "Symlink created: $WRAPPER_PATH -> sentinel"

# 🛡️ SMART PATH CHECK (As suggested by user)
if ! echo "$PATH" | grep -q "$PREFIX/bin"; then
    info "Fixing PATH: Adding $PREFIX/bin to ~/.bashrc..."
    echo "export PATH=\$PATH:$PREFIX/bin" >> ~/.bashrc
    success "PATH updated in ~/.bashrc"
fi

# ── STEP 4/4: Final Config ... (ส่วนท้ายเหมือนเดิม) ...

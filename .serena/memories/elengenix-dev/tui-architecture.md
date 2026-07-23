# Elengenix TUI Architecture

## Key Insight
Elengenix's actual user-facing TUI is **`cli/textual.py`** (1900+ lines) — a Textual chat app (like Claude in terminal). The `tui/` directory contains only **static Rich renderables** used by `elengenix hunt` and dashboard widgets, NOT the main interactive interface.

## Entry Points
- `elengenix tui` → runs `cli/textual.py:ElengenixTextualApp` (chat interface)
- `elengenix hunt <target>` → uses `tui/hunt_view.py:run_launcher` (static dashboard)
- `elengenix` (no args) → `main.py` CLI

## cli/textual.py Structure
- **Color palette**: constants at top (BASE, MANTLE, CRUST, SURFACE, TEXT, MUTED, DIM, GRAY)
  - Two themes: CHILL (neutral) + HUNT (red accent, H_* prefix)
  - Refined to Tokyo Night / GitHub Dark palette (soft black, blue-grey) on 2026-07-18
- **Main app**: `ElengenixTextualApp` (App subclass) at line ~580
  - `compose()`: header + main_row (chat_col + dashboard_col + sidebar) + overlays
  - `on_mount()`: registers chill/hunt themes, starts 30fps animation
  - `_build_header()`: brand + mode pills + target + hint
  - `_run_boot_sequence()`: typewriter banner animation (uses `line.format(color=, dim=, muted=)`)
  - `action_toggle_mode()`: CHILL↔HUNT with cinematic transition
- **Widgets**: Sidebar, ThinkingWidget, Scanline, GlitchFlash, StatusBar, ProgressBar
- **ASCII_BANNER**: has `{color}`, `{dim}`, `{muted}` placeholders — ALL must be passed to `.format()`

## tui/ Directory (static widgets, NOT main UI)
- `welcome.py` — welcome screen renderables (used by hunt command)
- `dashboard.py` — ThreatDashboard widget
- `themes.py` — 12 themes (CYBERPUNK, MATRIX, OBSIDIAN, etc.) + ThemeManager
- `ui_kit.py` — design system helpers (mini_bar, status_pill, keycap, rule, segment_bar)
- `main_menu.py`, `hunt_view.py`, `visualizations.py`, etc.

## Testing TUI
```python
async with app.run_test() as pilot:
    await pilot.pause()
```
- Use `app.query_one('#header')` to check widgets
- `Static.renderable` does NOT exist — use other checks

## Common Pitfalls
- `ASCII_BANNER.format()` needs ALL placeholders (color, dim, muted) or KeyError
- `replace_symbol_body` may lose indentation — always verify after edit
- LSP errors about `_progress_*`, `governance`, `ThemeManager` are pre-existing (type issues)

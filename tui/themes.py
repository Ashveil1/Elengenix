"""tui/themes.py - Theme system and palette definitions for Elengenix.

Provides four premium themes:

    * ``CYBERPUNK`` - neon pink / cyan, electric energy
    * ``MATRIX``    - green on black, classic hacker
    * ``STEALTH``   - subtle monochrome greys, low-profile
    * ``SYNTHWAVE`` - purple / orange gradient, retro-futuristic

Each theme is a flat dictionary of colour tokens (CSS hex strings).
The :class:`ThemeManager` handles live switching and smooth colour
transitions between themes. Widgets can either query the manager for
the current colours or watch for transition updates.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from rich.style import Style
from rich.text import Text

from textual.reactive import reactive

from .animations import Easing

logger = logging.getLogger("elengenix.tui.themes")

# ---------------------------------------------------------------------------
# Theme token contract - every theme must provide these keys
# ---------------------------------------------------------------------------

THEME_TOKENS: Tuple[str, ...] = (
    # Surfaces
    "bg_dark", "bg_panel", "bg_card", "bg_overlay", "bg_input",
    # Text
    "text", "muted", "dim", "inverse_text", "inverse_bg",
    # Brand
    "primary", "secondary", "accent", "highlight",
    # Semantic
    "success", "warning", "error", "info",
    # Severity
    "critical", "high", "medium", "low",
    # Borders
    "border", "border_strong", "border_glow",
    # Gradients (two-stop)
    "gradient_1", "gradient_2", "gradient_3",
)


def _validate(theme: Dict[str, str], name: str) -> Dict[str, str]:
    """Fill in any missing tokens with sensible defaults and warn."""
    missing = [k for k in THEME_TOKENS if k not in theme]
    if missing:
        logger.warning("Theme '%s' missing tokens: %s - using defaults", name, missing)
        for k in missing:
            theme[k] = "#ffffff"
    return theme


# ---------------------------------------------------------------------------
# CYBERPUNK - neon pink / cyan
# ---------------------------------------------------------------------------

CYBERPUNK: Dict[str, str] = _validate({
    "bg_dark":       "#0a0014",
    "bg_panel":      "#14002a",
    "bg_card":       "#1f0038",
    "bg_overlay":    "#2a0050",
    "bg_input":      "#0d001a",
    "text":          "#f5f5ff",
    "muted":         "#b89cdb",
    "dim":           "#6a4c93",
    "inverse_text":  "#0a0014",
    "inverse_bg":    "#ff007a",
    "primary":       "#ff007a",  # hot pink
    "secondary":     "#00f0ff",  # electric cyan
    "accent":        "#ffea00",  # acid yellow
    "highlight":     "#ff77ff",  # magenta highlight
    "success":       "#00ff9c",  # neon mint
    "warning":       "#ffb300",  # amber
    "error":         "#ff003c",  # laser red
    "info":          "#00b8ff",  # sky cyan
    "critical":      "#ff003c",
    "high":          "#ff5500",
    "medium":        "#ffb300",
    "low":           "#00ff9c",
    "border":        "#ff007a",
    "border_strong": "#ff77ff",
    "border_glow":   "#00f0ff",
    "gradient_1":    "#ff007a",
    "gradient_2":    "#00f0ff",
    "gradient_3":    "#ffea00",
}, "CYBERPUNK")


# ---------------------------------------------------------------------------
# MATRIX - green on black
# ---------------------------------------------------------------------------

MATRIX: Dict[str, str] = _validate({
    "bg_dark":       "#000000",
    "bg_panel":      "#031003",
    "bg_card":       "#061a06",
    "bg_overlay":    "#0a260a",
    "bg_input":      "#010801",
    "text":          "#c8ffc8",
    "muted":         "#3faa3f",
    "dim":           "#1f5c1f",
    "inverse_text":  "#000000",
    "inverse_bg":    "#00ff66",
    "primary":       "#00ff66",  # matrix green
    "secondary":     "#33ff99",  # pale green
    "accent":        "#aaffaa",  # bright white-green
    "highlight":     "#ddffdd",
    "success":       "#00ff66",
    "warning":       "#ffcc00",
    "error":         "#ff3344",
    "info":          "#66ffaa",
    "critical":      "#ff3344",
    "high":          "#ffaa00",
    "medium":        "#ccff00",
    "low":           "#00ff66",
    "border":        "#00ff66",
    "border_strong": "#aaffaa",
    "border_glow":   "#33ff99",
    "gradient_1":    "#003300",
    "gradient_2":    "#00ff66",
    "gradient_3":    "#ddffdd",
}, "MATRIX")


# ---------------------------------------------------------------------------
# STEALTH - subtle monochrome
# ---------------------------------------------------------------------------

STEALTH: Dict[str, str] = _validate({
    "bg_dark":       "#0a0a0a",
    "bg_panel":      "#121212",
    "bg_card":       "#1a1a1a",
    "bg_overlay":    "#222222",
    "bg_input":      "#101010",
    "text":          "#d0d0d0",
    "muted":         "#888888",
    "dim":           "#555555",
    "inverse_text":  "#0a0a0a",
    "inverse_bg":    "#cccccc",
    "primary":       "#cccccc",  # light grey
    "secondary":     "#888888",  # mid grey
    "accent":        "#ffffff",  # white accent
    "highlight":     "#e8e8e8",
    "success":       "#bbbbbb",
    "warning":       "#999999",
    "error":         "#ff2222",  # red still pops for errors
    "info":          "#aaaaaa",
    "critical":      "#ff2222",
    "high":          "#dddddd",
    "medium":        "#aaaaaa",
    "low":           "#777777",
    "border":        "#444444",
    "border_strong": "#888888",
    "border_glow":   "#cccccc",
    "gradient_1":    "#222222",
    "gradient_2":    "#888888",
    "gradient_3":    "#dddddd",
}, "STEALTH")


# ---------------------------------------------------------------------------
# SYNTHWAVE - purple / orange gradient
# ---------------------------------------------------------------------------

SYNTHWAVE: Dict[str, str] = _validate({
    "bg_dark":       "#0f0721",
    "bg_panel":      "#1a0a3a",
    "bg_card":       "#241155",
    "bg_overlay":    "#321a6e",
    "bg_input":      "#0a0418",
    "text":          "#fff0f5",
    "muted":         "#c2a4ff",
    "dim":           "#7e57c2",
    "inverse_text":  "#0f0721",
    "inverse_bg":    "#ff7e5f",
    "primary":       "#ff7e5f",  # sunset orange
    "secondary":     "#9d4edd",  # electric purple
    "accent":        "#feb47b",  # warm gold
    "highlight":     "#ffb3c6",  # pink
    "success":       "#80ffdb",  # mint
    "warning":       "#ffd166",
    "error":         "#ff006e",  # hot pink-red
    "info":          "#9d4edd",
    "critical":      "#ff006e",
    "high":          "#ff7e5f",
    "medium":        "#feb47b",
    "low":           "#80ffdb",
    "border":        "#9d4edd",
    "border_strong": "#ff7e5f",
    "border_glow":   "#feb47b",
    "gradient_1":    "#9d4edd",
    "gradient_2":    "#ff7e5f",
    "gradient_3":    "#feb47b",
}, "SYNTHWAVE")


# Default theme (Elengenix signature: monochrome with red accent).
DEFAULT: Dict[str, str] = _validate({
    "bg_dark":       "#000000",
    "bg_panel":      "#0d0d0d",
    "bg_card":       "#1a1a1a",
    "bg_overlay":    "#222222",
    "bg_input":      "#0a0a0a",
    "text":          "#ffffff",
    "muted":         "#888888",
    "dim":           "#555555",
    "inverse_text":  "#000000",
    "inverse_bg":    "#ff2222",
    "primary":       "#ff2222",  # signature red
    "secondary":     "#888888",  # grey70
    "accent":        "#ffffff",
    "highlight":     "#ff5555",
    "success":       "#ffffff",
    "warning":       "#ffb300",
    "error":         "#ff2222",
    "info":          "#ffffff",
    "critical":      "#ff2222",
    "high":          "#ff5555",
    "medium":        "#cccccc",
    "low":           "#81c784",
    "border":        "#444444",
    "border_strong": "#888888",
    "border_glow":   "#ff2222",
    "gradient_1":    "#888888",
    "gradient_2":    "#ffffff",
    "gradient_3":    "#ff2222",
}, "DEFAULT")


THEMES: Dict[str, Dict[str, str]] = {
    "DEFAULT":   DEFAULT,
    "CYBERPUNK": CYBERPUNK,
    "MATRIX":    MATRIX,
    "STEALTH":   STEALTH,
    "SYNTHWAVE": SYNTHWAVE,
}


# ---------------------------------------------------------------------------
# Colour utilities
# ---------------------------------------------------------------------------


def _hex_to_rgb(value: str) -> Tuple[int, int, int]:
    """Convert ``"#rrggbb"`` (or short form) to an ``(r, g, b)`` tuple."""
    v = value.strip().lstrip("#")
    if len(v) == 3:
        v = "".join(c * 2 for c in v)
    if len(v) != 6:
        return (255, 255, 255)
    try:
        return (int(v[0:2], 16), int(v[2:4], 16), int(v[4:6], 16))
    except ValueError:
        return (255, 255, 255)


def _rgb_to_hex(rgb: Tuple[int, int, int]) -> str:
    """Convert an ``(r, g, b)`` tuple to ``"#rrggbb"``."""
    r, g, b = (max(0, min(255, round(c))) for c in rgb)
    return f"#{r:02x}{g:02x}{b:02x}"


def lerp_color(a: str, b: str, t: float) -> str:
    """Linearly interpolate between two hex colours.

    Args:
        a: First colour as ``"#rrggbb"``.
        b: Second colour as ``"#rrggbb"``.
        t: Interpolation factor ``[0, 1]`` (will be clamped).

    Returns:
        Interpolated colour as ``"#rrggbb"``.
    """
    t = max(0.0, min(1.0, float(t)))
    ra, ga, ba = _hex_to_rgb(a)
    rb, gb, bb = _hex_to_rgb(b)
    r = ra + (rb - ra) * t
    g = ga + (gb - ga) * t
    bch = ba + (bb - ba) * t
    return _rgb_to_hex((r, g, bch))


def gradient_stops(
    colors: List[str], steps: int
) -> List[str]:
    """Generate a list of interpolated colours across the given stops.

    Args:
        colors: List of colour stops (e.g. ``["#ff007a", "#00f0ff"]``).
        steps: Number of output colours (including both endpoints).

    Returns:
        List of ``steps`` colour strings evenly sampled across the gradient.
    """
    if not colors:
        return ["#ffffff"] * steps
    if len(colors) == 1:
        return [colors[0]] * steps
    if steps <= 0:
        return []
    if steps == 1:
        return [colors[0]]
    out: List[str] = []
    n_segments = len(colors) - 1
    for i in range(steps):
        seg = min(n_segments - 1, int((i / (steps - 1)) * n_segments))
        local_t = (i / (steps - 1)) * n_segments - seg
        out.append(lerp_color(colors[seg], colors[seg + 1], local_t))
    return out


# ---------------------------------------------------------------------------
# ThemeManager - live theme switching with smooth transitions
# ---------------------------------------------------------------------------


class ThemeManager:
    """Manages the active theme and smooth colour transitions.

    The manager is a singleton-style object: instantiate once per app and
    pass it to widgets that need to read the current colour tokens.

    Transitions are linear interpolations between the source and target
    themes, advanced by a timer set up via :meth:`start_transition`. Any
    widget that calls :meth:`current` (or reads the reactive
    :attr:`current_colors`) will see interpolated values while the
    transition is in flight.

    Example:
        mgr = ThemeManager("CYBERPUNK")
        mgr.transition_to("MATRIX", duration=1.0)
        # ... later, in a widget render:
        color = mgr.current("primary")
    """

    def __init__(self, theme: str = "DEFAULT") -> None:
        self._active_name: str = theme if theme in THEMES else "DEFAULT"
        self._from_colors: Dict[str, str] = dict(THEMES[self._active_name])
        self._to_colors: Dict[str, str] = dict(THEMES[self._active_name])
        self._transitioning: bool = False
        self._transition_start: float = 0.0
        self._transition_duration: float = 0.5
        self._easing: str = "ease_in_out_cubic"
        self._listeners: List[callable] = []
        self._last_colors: Dict[str, str] = dict(self._from_colors)

    # -- Public API --------------------------------------------------------

    @property
    def active(self) -> str:
        """The name of the target theme (post-transition)."""
        return self._active_name

    @property
    def current_colors(self) -> Dict[str, str]:
        """The interpolated colour dict at the current transition point."""
        if not self._transitioning:
            return dict(self._to_colors)
        t = self._transition_progress()
        eased = Easing.apply(self._easing, t)
        return {
            k: lerp_color(self._from_colors.get(k, "#ffffff"),
                          self._to_colors.get(k, "#ffffff"),
                          eased)
            for k in THEME_TOKENS
        }

    def current(self, token: str) -> str:
        """Get the current value of a single colour token.

        Args:
            token: Token name (e.g. ``"primary"``, ``"bg_dark"``).

        Returns:
            Current hex colour for the token.
        """
        return self.current_colors.get(token, "#ffffff")

    def list_themes(self) -> List[str]:
        """Return the names of all registered themes."""
        return list(THEMES.keys())

    def register_listener(self, callback: callable) -> None:
        """Register a callable to be invoked on every transition tick.

        The callback receives ``(manager: ThemeManager)`` and may be a
        sync function. Listeners are not awaited; they should not block.
        """
        self._listeners.append(callback)

    # -- Transitions -------------------------------------------------------

    def transition_to(
        self,
        name: str,
        duration: float = 0.6,
        easing: str = "ease_in_out_cubic",
    ) -> None:
        """Start a smooth transition to the named theme.

        Args:
            name: Target theme name (must be in :data:`THEMES`).
            duration: Transition duration in seconds.
            easing: Easing function name.
        """
        if name not in THEMES:
            logger.warning("Unknown theme '%s' - transition ignored", name)
            return
        self._from_colors = self.current_colors
        self._to_colors = dict(THEMES[name])
        self._active_name = name
        self._transition_duration = max(0.01, float(duration))
        self._easing = easing
        self._transition_start = time.monotonic()
        self._transitioning = True

    def set_theme(self, name: str) -> None:
        """Set the theme instantly (no transition)."""
        if name not in THEMES:
            logger.warning("Unknown theme '%s' - set ignored", name)
            return
        self._to_colors = dict(THEMES[name])
        self._from_colors = dict(THEMES[name])
        self._active_name = name
        self._transitioning = False
        self._notify()

    def tick(self) -> bool:
        """Advance the in-flight transition by one frame.

        Returns:
            ``True`` if a transition is still in progress, ``False`` if it
            has completed (or none was running).
        """
        if not self._transitioning:
            return False
        t = self._transition_progress()
        if t >= 1.0:
            self._transitioning = False
            self._from_colors = dict(self._to_colors)
            self._notify()
            return False
        self._notify()
        return True

    def _transition_progress(self) -> float:
        elapsed = time.monotonic() - self._transition_start
        if self._transition_duration <= 0:
            return 1.0
        return max(0.0, min(1.0, elapsed / self._transition_duration))

    def _notify(self) -> None:
        """Call all registered listeners with the current state."""
        colors = self.current_colors
        self._last_colors = colors
        for cb in list(self._listeners):
            try:
                cb(self)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Theme listener raised: %s", exc)

    # -- Rich style helpers -----------------------------------------------

    def style(self, token: str) -> Style:
        """Return a Rich ``Style`` for the given token at the current state."""
        return Style(color=self.current(token))

    def render_styled(
        self,
        text: str,
        token: str = "text",
        bold: bool = False,
        dim: bool = False,
    ) -> Text:
        """Render ``text`` as a Rich ``Text`` using the given token."""
        style = Style(color=self.current(token), bold=bold, dim=dim)
        return Text(text, style=style)

    def gradient_text(
        self,
        text: str,
        tokens: Optional[Tuple[str, ...]] = None,
        bold: bool = True,
    ) -> Text:
        """Render ``text`` with a per-character gradient across the given tokens.

        Args:
            text: Source text.
            tokens: Tuple of theme tokens (default: ``("gradient_1", "gradient_2", "gradient_3")``).
            bold: Apply bold weight to the rendered text.

        Returns:
            Rich ``Text`` with each character coloured along the gradient.
        """
        if tokens is None:
            tokens = ("gradient_1", "gradient_2", "gradient_3")
        colors = [self.current(t) for t in tokens]
        n = max(1, len(text))
        stops = gradient_stops(colors, n)
        out = Text()
        for ch, col in zip(text, stops):
            out.append(ch, style=Style(color=col, bold=bold))
        return out


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_default_manager: Optional[ThemeManager] = None


def get_manager() -> ThemeManager:
    """Return the process-wide default :class:`ThemeManager`.

    Lazily creates one on first access.
    """
    global _default_manager
    if _default_manager is None:
        _default_manager = ThemeManager("DEFAULT")
    return _default_manager


def get_theme(name: str) -> Dict[str, str]:
    """Return a copy of the named theme's colour tokens."""
    if name not in THEMES:
        logger.warning("Unknown theme '%s', returning DEFAULT", name)
        name = "DEFAULT"
    return dict(THEMES[name])


__all__ = [
    "THEMES",
    "THEME_TOKENS",
    "CYBERPUNK",
    "MATRIX",
    "STEALTH",
    "SYNTHWAVE",
    "DEFAULT",
    "ThemeManager",
    "get_manager",
    "get_theme",
    "lerp_color",
    "gradient_stops",
]

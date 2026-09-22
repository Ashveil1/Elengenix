"""tui/motion.py - Unified animation/motion engine for Elengenix.

Single source of truth for easing + frame primitives used by both the
Rich CLI path and the Textual TUI. Honors reduced-motion preferences:

    ELENGENIX_NO_ANIMATION=1 / ELENGENIX_REDUCED_MOTION=1 / NO_COLOR=1
    -> all animations collapse to their end state instantly.
"""

from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass
from typing import Callable, List, Optional

from .themes import Easing, animations_enabled

SPINNER_DOTS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
SPINNER_ARC = ["◐", "◓", "◑", "◒"]
SPINNER_BAR = ["█ ", "▓ ", "▒ ", "░ ", "▒ ", "▓ "]
THINKING_DOTS_STEPS = ["", ".", "..", "..."]


def eased_progress(t: float, easing: str = "ease_in_out") -> float:
    """Eased 0..1 progress for a linear time value."""
    return Easing.apply(easing, t, 0.0, 1.0)


def animate_value(
    from_value: float,
    to_value: float,
    duration: float = 0.6,
    easing: str = "ease_in_out",
    on_frame: Optional[Callable[[float], None]] = None,
    fps: int = 30,
) -> float:
    """Blocking helper for Rich/CLI animations. Returns the end value.

    When motion is disabled, calls on_frame once with the end value.
    """
    if duration <= 0 or not animations_enabled():
        if on_frame is not None:
            on_frame(to_value)
        return to_value
    steps = max(1, int(duration * fps))
    for i in range(steps + 1):
        t = i / steps
        value = Easing.apply(easing, t, from_value, to_value)
        if on_frame is not None:
            on_frame(value)
        if i < steps:
            time.sleep(duration / steps)
    return to_value


def spinner_frame(kind: str, index: int) -> str:
    """Frame string for a named spinner at an integer tick."""
    if kind == "arc":
        frames = SPINNER_ARC
    elif kind == "bar":
        frames = SPINNER_BAR
    else:
        frames = SPINNER_DOTS
    return frames[index % len(frames)]


def thinking_label(index: int, base: str = "THINKING") -> str:
    """Animated thinking label with cycling dots."""
    dots = THINKING_DOTS_STEPS[(index // 2) % len(THINKING_DOTS_STEPS)]
    return f"{base}{dots}"


@dataclass
class Transition:
    """Declarative color/number transition driven by a Textual timer.

    The caller advances via poll() inside set_interval(); on_frame receives
    the eased 0..1 value. When motion is disabled the transition completes
    on the first poll.
    """

    duration: float = 0.6
    easing: str = "ease_in_out"
    _start: Optional[float] = None

    def start(self) -> None:
        """(Re)start the transition clock."""
        self._start = time.monotonic()

    def poll(self, on_frame: Callable[[float], None]) -> bool:
        """Advance one frame. Returns True while still running."""
        if not animations_enabled():
            on_frame(1.0)
            return False
        if self._start is None:
            self.start()
        assert self._start is not None
        elapsed = time.monotonic() - self._start
        t = min(1.0, elapsed / max(0.01, self.duration))
        on_frame(Easing.apply(self.easing, t, 0.0, 1.0))
        return t < 1.0


def smooth_approach(current: float, target: float, factor: float = 0.2) -> float:
    """Frame-rate independent smoothing for counters/progress bars."""
    factor = max(0.0, min(1.0, factor))
    return current + (target - current) * factor


def ema_eta(elapsed: float, progress: float, prev_eta: Optional[float] = None) -> float:
    """Stable ETA: raw estimate smoothed with previous value."""
    if progress <= 0.01:
        return 0.0
    raw = elapsed / max(0.01, progress) - elapsed
    raw = max(0.0, raw)
    if prev_eta is None:
        return raw
    return prev_eta * 0.7 + raw * 0.3


def counter_steps(current: int, target: int, max_step: int = 0) -> List[int]:
    """Intermediate counter values for animated counting (no sleep)."""
    if target <= current:
        return [target]
    if max_step <= 0:
        max_step = max(1, (target - current + 9) // 10)
    out: List[int] = []
    value = current
    while value < target:
        value = min(target, value + max_step)
        out.append(value)
    return out


def motion_allowed() -> bool:
    """Whether full motion is allowed (False in CI/pipes/reduced-motion)."""
    if os.environ.get("ELENGENIX_NO_ANIMATION", "") == "1":
        return False
    if os.environ.get("NO_COLOR", "") == "1":
        return False
    try:
        import sys

        if not sys.stdout.isatty():
            return False
    except Exception:
        return False
    return animations_enabled()


_SPARK_CHARS = "▁▂▃▄▅▆▇█"


def sparkline(values, width: int = 24) -> str:
    """Tiny block sparkline for sidebar stats (token history, findings, ...)."""
    vals = list(values)[-width:] if values else []
    if not vals:
        return ""
    lo, hi = min(vals), max(vals)
    if hi <= lo:
        return _SPARK_CHARS[0] * len(vals)
    return "".join(_SPARK_CHARS[min(7, int((v - lo) / (hi - lo) * 8))] for v in vals)


def shimmer_text(text: str, tick: int, base: str = "#5a5a5a", hi: str = "#ffffff", width: int = 12):
    """Rich Text with a bright band sweeping across (banner shimmer sweeps).

    Pure function — no timers. The caller advances ``tick`` per frame.
    Respects nothing by itself; callers must gate on animations_enabled().
    """
    from rich.text import Text

    from .themes import lerp_color

    out = Text()
    n = len(text)
    if n == 0:
        return out
    pos = tick % (n + width)
    for i, ch in enumerate(text):
        if ch in (" ", "\n"):
            out.append(ch)
            continue
        d = abs(i - pos)
        t = max(0.0, 1.0 - d / width) ** 2
        out.append(ch, style=f"bold {lerp_color(base, hi, t)}")
    return out


__all__ = [
    "SPINNER_DOTS",
    "SPINNER_ARC",
    "SPINNER_BAR",
    "eased_progress",
    "animate_value",
    "spinner_frame",
    "thinking_label",
    "Transition",
    "smooth_approach",
    "ema_eta",
    "counter_steps",
    "motion_allowed",
    "sparkline",
    "shimmer_text",
]

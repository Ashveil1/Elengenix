"""tui/animations.py - Premium TUI animation primitives for Elengenix.

Provides:
    * Easing functions (linear, quad, cubic, bounce, elastic, back, expo).
    * AnimatedCounter - Textual widget that smoothly animates numeric values.
    * AnimatedProgress - Textual widget for eased progress bars.
    * ParticleField - background particle effects (matrix, glitch, snow, ...).
    * FadeTransition - smooth text fade in/out (dim-based).
    * GlitchEffect - randomized character scrambling for a hacker aesthetic.
    * WaveAnimation - sine-wave style text reveal.

All animations are timer-driven via Textual's reactive system and do not block
the event loop. Smoothness is achieved by running tick callbacks at ~60 FPS.
Every public class is also usable as a pure-Rich renderable (e.g.
``GlitchEffect.render(text, t)``) so it can be embedded in panels, RichLog,
or any Rich console.
"""

from __future__ import annotations

import logging
import math
import random
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from rich.console import Console, Group, RenderResult
from rich.panel import Panel
from rich.text import Text

from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static

from ui_components import console as shared_console

logger = logging.getLogger("elengenix.tui.animations")

# Default frame interval (seconds) for smooth 60 FPS animation ticks.
DEFAULT_FRAME_INTERVAL = 1.0 / 60.0
# Slower default for particle effects (less CPU, still smooth).
PARTICLE_FRAME_INTERVAL = 1.0 / 15.0


# ---------------------------------------------------------------------------
# Easing Functions
# ---------------------------------------------------------------------------


class Easing:
    """Collection of pure easing functions.

    Every function accepts a normalised time value ``t`` in ``[0, 1]`` and
    returns a value typically in ``[0, 1]``. Some functions (bounce, elastic,
    back) intentionally overshoot. Use :meth:`apply` to call an easing by
    name (string lookup), which is convenient for configuration files.
    """

    _REGISTRY: Dict[str, Callable[[float], float]] = {}

    # Names that look like easings but are actually utility methods - skip
    # them when auto-building the name registry.
    _SKIP = frozenset({"apply", "register", "names", "lerp"})

    @classmethod
    def _register(cls) -> None:
        """Lazily build a name -> function registry on first use."""
        if cls._REGISTRY:
            return
        for name in dir(cls):
            if name.startswith("_") or name in cls._SKIP:
                continue
            fn = getattr(cls, name, None)
            if callable(fn):
                cls._REGISTRY[name] = fn

    @classmethod
    def names(cls) -> List[str]:
        """Return the list of registered easing names."""
        cls._register()
        return sorted(cls._REGISTRY)

    @staticmethod
    def linear(t: float) -> float:
        """Linear interpolation - constant velocity."""
        return t

    @staticmethod
    def ease_in_quad(t: float) -> float:
        """Quadratic ease-in (slow start, fast end)."""
        return t * t

    @staticmethod
    def ease_out_quad(t: float) -> float:
        """Quadratic ease-out (fast start, slow end)."""
        return 1 - (1 - t) * (1 - t)

    @staticmethod
    def ease_in_out_quad(t: float) -> float:
        """Quadratic ease-in-out (slow start and end)."""
        if t < 0.5:
            return 2 * t * t
        return 1 - ((-2 * t + 2) ** 2) / 2

    @staticmethod
    def ease_in_cubic(t: float) -> float:
        """Cubic ease-in - accelerates sharply."""
        return t ** 3

    @staticmethod
    def ease_out_cubic(t: float) -> float:
        """Cubic ease-out - decelerates smoothly (premium feel)."""
        return 1 - (1 - t) ** 3

    @staticmethod
    def ease_in_out_cubic(t: float) -> float:
        """Cubic ease-in-out - the default for most Elengenix animations."""
        if t < 0.5:
            return 4 * t ** 3
        return 1 - ((-2 * t + 2) ** 3) / 2

    @staticmethod
    def ease_out_bounce(t: float) -> float:
        """Bouncy ease-out - settles with a playful bounce."""
        n1, d1 = 7.5625, 2.75
        if t < 1 / d1:
            return n1 * t * t
        if t < 2 / d1:
            t -= 1.5 / d1
            return n1 * t * t + 0.75
        if t < 2.5 / d1:
            t -= 2.25 / d1
            return n1 * t * t + 0.9375
        t -= 2.625 / d1
        return n1 * t * t + 0.984375

    @staticmethod
    def ease_in_bounce(t: float) -> float:
        """Inverse of :meth:`ease_out_bounce`."""
        return 1 - Easing.ease_out_bounce(1 - t)

    @staticmethod
    def ease_out_elastic(t: float) -> float:
        """Elastic ease-out - springy overshoot, then settle."""
        c4 = (2 * math.pi) / 3
        if t == 0 or t == 1:
            return t
        return 2 ** (-10 * t) * math.sin((t * 10 - 0.75) * c4) + 1

    @staticmethod
    def ease_in_elastic(t: float) -> float:
        """Inverse of :meth:`ease_out_elastic`."""
        c4 = (2 * math.pi) / 3
        if t == 0 or t == 1:
            return t
        return -(2 ** (10 * t - 10)) * math.sin((t * 10 - 10.75) * c4)

    @staticmethod
    def ease_in_out_expo(t: float) -> float:
        """Exponential ease-in-out - dramatic transitions."""
        if t == 0 or t == 1:
            return t
        if t < 0.5:
            return 2 ** (20 * t - 10) / 2
        return (2 - 2 ** (-20 * t + 10)) / 2

    @staticmethod
    def ease_out_back(t: float) -> float:
        """Back ease-out - slight overshoot for a punchy feel."""
        c1 = 1.70158
        c3 = c1 + 1
        return 1 + c3 * (t - 1) ** 3 + c1 * (t - 1) ** 2

    @staticmethod
    def ease_in_out_back(t: float) -> float:
        """Back ease-in-out - overshoots at both ends."""
        c1 = 1.70158
        c2 = c1 * 1.525
        if t < 0.5:
            return ((2 * t) ** 2 * ((c2 + 1) * 2 * t - c2)) / 2
        return ((2 * t - 2) ** 2 * ((c2 + 1) * (t * 2 - 2) + c2) + 2) / 2

    @staticmethod
    def apply(name: str, t: float) -> float:
        """Look up and apply an easing by name.

        Args:
            name: Name of the easing (e.g. ``"ease_in_out_cubic"``).
            t: Time value, will be clamped to ``[0, 1]``.

        Returns:
            Eased value (typically in ``[0, 1]``, may overshoot for
            bounce/elastic/back variants).
        """
        t = max(0.0, min(1.0, float(t)))
        Easing._register()
        fn = Easing._REGISTRY.get(name)
        if fn is None:
            logger.warning("Unknown easing '%s', falling back to linear", name)
            return t
        return fn(t)

    @staticmethod
    def lerp(a: float, b: float, t: float, easing: str = "linear") -> float:
        """Linearly interpolate from ``a`` to ``b`` using the given easing.

        Args:
            a: Start value.
            b: End value.
            t: Normalised time ``[0, 1]``.
            easing: Easing function name.

        Returns:
            Interpolated value.
        """
        return a + (b - a) * Easing.apply(easing, t)


# ---------------------------------------------------------------------------
# AnimatedCounter - smooth numeric transitions
# ---------------------------------------------------------------------------


class AnimatedCounter(Static):
    """A Textual widget that animates between numeric values using easing.

    The counter is also usable as a static Rich renderable via the
    :meth:`render_value` class method, which makes it embeddable in
    RichLog, panels, or any Rich container.

    Example:
        counter = AnimatedCounter(target=100, duration=1.5)
        await counter.mount(parent)
        counter.set_target(250)
    """

    DEFAULT_CSS = """
    AnimatedCounter {
        height: auto;
        width: auto;
    }
    """

    value = reactive(0.0)
    target = reactive(0.0)
    duration = reactive(1.0)
    easing = reactive("ease_in_out_cubic")
    precision = reactive(0)

    def __init__(
        self,
        value: float = 0,
        target: float = 0,
        duration: float = 1.0,
        easing: str = "ease_in_out_cubic",
        precision: int = 0,
        prefix: str = "",
        suffix: str = "",
        color: str = "#ffffff",
        dim_color: Optional[str] = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._value = float(value)
        self._target = float(target)
        self.duration = float(duration)
        self.easing = easing
        self.precision = int(precision)
        self.prefix = prefix
        self.suffix = suffix
        self.color = color
        self.dim_color = dim_color
        self._start_value = float(value)
        self._start_time: Optional[float] = None
        self._timer = None

    def on_mount(self) -> None:
        """Start animation if a target is set."""
        if abs(self._target - self._value) > 1e-9:
            self._start_animation()

    def _start_animation(self) -> None:
        """Begin animating from the current value to the target."""
        self._start_value = self._value
        self._start_time = time.monotonic()
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        self._timer = self.set_interval(DEFAULT_FRAME_INTERVAL, self._tick)

    def _tick(self) -> None:
        """Advance the animation by one frame."""
        if self._start_time is None:
            return
        elapsed = time.monotonic() - self._start_time
        t = min(1.0, elapsed / self.duration) if self.duration > 0 else 1.0
        eased = Easing.apply(self.easing, t)
        self._value = self._start_value + (self._target - self._start_value) * eased
        self.value = self._value
        if t >= 1.0:
            self._value = self._target
            self.value = self._value
            if self._timer is not None:
                self._timer.stop()
                self._timer = None

    def set_target(self, target: float, duration: Optional[float] = None) -> None:
        """Animate from the current value to a new target.

        Args:
            target: New target value.
            duration: Optional override for the animation duration.
        """
        self._target = float(target)
        if duration is not None:
            self.duration = float(duration)
        self._start_animation()

    def set_value(self, value: float) -> None:
        """Set the counter to an exact value (no animation)."""
        self._value = float(value)
        self._target = float(value)
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        self.value = self._value
        self.refresh()

    @classmethod
    def render_value(
        cls,
        value: float,
        color: str = "#ffffff",
        prefix: str = "",
        suffix: str = "",
        precision: int = 0,
        dim_color: Optional[str] = None,
    ) -> Text:
        """Render a counter value as a Rich Text (no widget needed).

        Args:
            value: Numeric value.
            color: Foreground colour.
            prefix: Optional leading text (e.g. ``"$"``).
            suffix: Optional trailing text (e.g. ``"%"``).
            precision: Decimal places to show.
            dim_color: If set, render trailing decimals in this dim colour.

        Returns:
            Rich ``Text`` ready to be printed.
        """
        if precision == 0:
            formatted = f"{int(round(value))}"
        else:
            formatted = f"{value:.{precision}f}"
        text = Text()
        if prefix:
            text.append(prefix, style=color)
        # Split integer / fractional part so we can dim the decimals.
        if precision > 0 and "." in formatted:
            int_part, dec_part = formatted.split(".", 1)
            text.append(int_part, style=f"bold {color}")
            if dim_color:
                text.append(f".{dec_part}", style=dim_color)
            else:
                text.append(f".{dec_part}", style=f"dim {color}")
        else:
            text.append(formatted, style=f"bold {color}")
        if suffix:
            text.append(suffix, style=color)
        return text

    def render(self) -> Text:
        """Render the current value as styled Rich Text."""
        return self.render_value(
            self._value,
            color=self.color,
            prefix=self.prefix,
            suffix=self.suffix,
            precision=self.precision,
            dim_color=self.dim_color,
        )


# ---------------------------------------------------------------------------
# AnimatedProgress - progress bar with easing
# ---------------------------------------------------------------------------


class AnimatedProgress(Static):
    """Progress bar that smoothly animates to its target value.

    Example:
        bar = AnimatedProgress(value=0.0, color="#ff2222")
        bar.set_progress(0.42)
    """

    DEFAULT_CSS = """
    AnimatedProgress {
        height: 1;
        width: 100%;
    }
    """

    progress = reactive(0.0)
    target = reactive(0.0)
    duration = reactive(0.5)
    easing = reactive("ease_out_cubic")

    # Block elements used to draw the filled portion - gradient from light to
    # full so the bar has texture even in monochrome mode.
    BLOCKS = " \u2591\u2592\u2593\u2588"  # space, light shade to full block

    def __init__(
        self,
        value: float = 0.0,
        duration: float = 0.5,
        easing: str = "ease_out_cubic",
        color: str = "#ffffff",
        empty_color: str = "#444444",
        show_percent: bool = True,
        show_label: bool = True,
        label: str = "",
        width: Optional[int] = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._value = max(0.0, min(1.0, float(value)))
        self._target = self._value
        self.duration = float(duration)
        self.easing = easing
        self.color = color
        self.empty_color = empty_color
        self.show_percent = show_percent
        self.show_label = show_label
        self.label = label
        self.width = width
        self._start_value = self._value
        self._start_time: Optional[float] = None
        self._timer = None

    def on_mount(self) -> None:
        """Begin animating if there is a pending target."""
        if abs(self._target - self._value) > 1e-6:
            self._start_animation()

    def _start_animation(self) -> None:
        self._start_value = self._value
        self._start_time = time.monotonic()
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        self._timer = self.set_interval(DEFAULT_FRAME_INTERVAL, self._tick)

    def _tick(self) -> None:
        if self._start_time is None:
            return
        elapsed = time.monotonic() - self._start_time
        t = min(1.0, elapsed / self.duration) if self.duration > 0 else 1.0
        eased = Easing.apply(self.easing, t)
        self._value = self._start_value + (self._target - self._start_value) * eased
        self.progress = self._value
        if t >= 1.0:
            self._value = self._target
            self.progress = self._value
            if self._timer is not None:
                self._timer.stop()
                self._timer = None

    def set_progress(self, value: float, duration: Optional[float] = None) -> None:
        """Animate to a new progress value (0..1)."""
        self._target = max(0.0, min(1.0, float(value)))
        if duration is not None:
            self.duration = float(duration)
        self._start_animation()

    def render(self) -> Text:
        """Render the bar as Rich Text."""
        # Determine width: explicit or current container width.
        bar_w = self.width
        if bar_w is None:
            try:
                bar_w = max(10, (self.size.width or 60))
            except Exception:
                bar_w = 40
        # Reserve space for the percentage label.
        pct_w = 6 if self.show_percent else 0
        label_w = (len(self.label) + 2) if (self.show_label and self.label) else 0
        bar_inner = max(4, bar_w - pct_w - label_w)
        filled = self._value * bar_inner
        full_blocks = int(filled)
        partial_index = int((filled - full_blocks) * (len(self.BLOCKS) - 1))
        partial_index = max(0, min(len(self.BLOCKS) - 1, partial_index))

        text = Text()
        if self.show_label and self.label:
            text.append(self.label + " ", style=self.color)
        text.append(self.BLOCKS[-1] * full_blocks, style=f"bold {self.color}")
        if full_blocks < bar_inner:
            text.append(self.BLOCKS[partial_index], style=f"bold {self.color}")
            remaining = bar_inner - full_blocks - 1
            text.append(self.BLOCKS[0] * remaining, style=self.empty_color)
        if self.show_percent:
            text.append(f" {int(round(self._value * 100)):3d}%", style=self.color)
        return text


# ---------------------------------------------------------------------------
# ParticleField - background particle effects
# ---------------------------------------------------------------------------


@dataclass
class _Particle:
    """Internal particle state for :class:`ParticleField`."""

    x: int = 0
    y: float = 0.0
    length: int = 5
    speed: float = 0.5
    char: str = "*"
    age: int = 0
    max_age: int = 50
    vx: float = 0.0
    vy: float = 0.0


class ParticleField(Static):
    """Background particle effect widget.

    Supports multiple visual modes:
        * ``matrix``  - vertical streams of random characters
        * ``rain``    - sparse falling characters
        * ``glitch``  - shifting rows of random characters
        * ``snow``    - slow drift down
        * ``stars``   - static-ish twinkling
        * ``fire``    - rising embers
        * ``scan``    - sweeping radar line
        * ``pulse``   - concentric ripples from a point

    The widget is self-contained: a timer drives the simulation, and a
    static :meth:`render_particles` helper produces the current frame as a
    Rich ``Text`` for use outside the widget.
    """

    DEFAULT_CSS = """
    ParticleField {
        height: 100%;
        width: 100%;
    }
    """

    mode = reactive("matrix")
    density = reactive(0.15)
    speed = reactive(1.0)
    color = reactive("#ffffff")
    accent = reactive("#888888")

    def __init__(
        self,
        mode: str = "matrix",
        width: int = 60,
        height: int = 18,
        density: float = 0.15,
        speed: float = 1.0,
        color: str = "#ffffff",
        accent: str = "#888888",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.mode = mode
        self._w = max(4, int(width))
        self._h = max(2, int(height))
        self.density = density
        self.speed = speed
        self.color = color
        self.accent = accent
        self._particles: List[_Particle] = []
        self._frame: int = 0
        self._timer = None
        self._last_grid: Optional[List[List[Tuple[str, str]]]] = None

    def on_mount(self) -> None:
        """Initialise particles and start the simulation timer."""
        self._init_particles()
        self._timer = self.set_interval(PARTICLE_FRAME_INTERVAL, self._tick)

    def on_unmount(self) -> None:
        """Stop the timer when the widget is removed."""
        if self._timer is not None:
            self._timer.stop()
            self._timer = None

    # -- Initialisation -----------------------------------------------------

    def _init_particles(self) -> None:
        """Populate the particle list for the current mode."""
        self._particles = []
        if self.mode == "matrix":
            self._init_matrix()
        elif self.mode == "rain":
            self._init_rain()
        elif self.mode == "glitch":
            self._init_glitch()
        elif self.mode == "snow":
            self._init_snow()
        elif self.mode == "stars":
            self._init_stars()
        elif self.mode == "fire":
            self._init_fire()
        elif self.mode == "scan":
            self._init_scan()
        elif self.mode == "pulse":
            self._init_pulse()
        else:
            self._init_matrix()

    def _init_matrix(self) -> None:
        for x in range(self._w):
            self._particles.append(
                _Particle(
                    x=x,
                    y=random.uniform(-self._h, self._h),
                    length=random.randint(4, 14),
                    speed=random.uniform(0.4, 1.2) * self.speed,
                )
            )

    def _init_rain(self) -> None:
        for _ in range(max(1, int(self._w * self._h * 0.03))):
            self._particles.append(
                _Particle(
                    x=random.randint(0, self._w - 1),
                    y=random.uniform(0, self._h),
                    speed=random.uniform(1.0, 2.0) * self.speed,
                    char=random.choice("|/\\."),
                )
            )

    def _init_glitch(self) -> None:
        for _ in range(self._h):
            self._particles.append(
                _Particle(
                    x=0,
                    y=random.randint(0, self._h - 1),
                    length=random.randint(2, self._w // 2),
                    char=random.choice("\u2588\u2593\u2592\u2591\u2580\u2584"),
                )
            )

    def _init_snow(self) -> None:
        for _ in range(max(1, int(self._w * 0.5))):
            self._particles.append(
                _Particle(
                    x=random.randint(0, self._w - 1),
                    y=random.randint(0, self._h - 1),
                    speed=random.uniform(0.05, 0.25) * self.speed,
                    char=random.choice(".*+"),
                )
            )

    def _init_stars(self) -> None:
        for _ in range(max(1, int(self._w * self._h * 0.04))):
            self._particles.append(
                _Particle(
                    x=random.randint(0, self._w - 1),
                    y=random.randint(0, self._h - 1),
                    max_age=random.randint(20, 80),
                    char=random.choice(".*+"),
                )
            )

    def _init_fire(self) -> None:
        for x in range(self._w):
            self._particles.append(
                _Particle(
                    x=x,
                    y=self._h + random.uniform(0, 4),
                    speed=random.uniform(0.3, 0.8) * self.speed,
                    char=random.choice("^':;,"),
                )
            )

    def _init_scan(self) -> None:
        # Radar: a sweeping line plus a few blips.
        self._particles.append(_Particle(x=0, y=0, speed=1.5 * self.speed))
        for _ in range(3):
            self._particles.append(
                _Particle(
                    x=random.uniform(0, self._w - 1),
                    y=random.uniform(0, self._h - 1),
                    max_age=random.randint(40, 100),
                )
            )

    def _init_pulse(self) -> None:
        # Concentric ripples emanating from the centre.
        cx, cy = self._w / 2.0, self._h / 2.0
        for _ in range(3):
            self._particles.append(
                _Particle(
                    x=int(cx),
                    y=cy,
                    length=0,
                    speed=random.uniform(0.5, 1.0) * self.speed,
                )
            )

    # -- Per-frame update ---------------------------------------------------

    def _tick(self) -> None:
        """Advance the simulation by one frame."""
        self._frame += 1
        if self.mode == "matrix":
            self._update_matrix()
        elif self.mode == "rain":
            self._update_rain()
        elif self.mode == "glitch":
            self._update_glitch()
        elif self.mode == "snow":
            self._update_snow()
        elif self.mode == "stars":
            self._update_stars()
        elif self.mode == "fire":
            self._update_fire()
        elif self.mode == "scan":
            self._update_scan()
        elif self.mode == "pulse":
            self._update_pulse()
        self.refresh()

    def _update_matrix(self) -> None:
        for p in self._particles:
            p.y += p.speed
            if p.y - p.length > self._h + 2:
                p.y = random.uniform(-p.length, 0)
                p.length = random.randint(4, 14)
                p.speed = random.uniform(0.4, 1.2) * self.speed

    def _update_rain(self) -> None:
        for p in self._particles:
            p.y += p.speed
            if p.y > self._h:
                p.y = random.uniform(-2, 0)
                p.x = random.randint(0, self._w - 1)
                p.speed = random.uniform(1.0, 2.0) * self.speed

    def _update_glitch(self) -> None:
        for p in self._particles:
            if random.random() < 0.18:
                p.x = random.randint(0, max(0, self._w - p.length))
                p.char = random.choice("\u2588\u2593\u2592\u2591\u2580\u2584#=+")

    def _update_snow(self) -> None:
        for p in self._particles:
            p.y += p.speed
            p.x += random.choice([-0.2, 0, 0, 0, 0.2])
            if p.y > self._h:
                p.y = -1
                p.x = random.randint(0, self._w - 1)

    def _update_stars(self) -> None:
        for p in self._particles:
            p.age += 1
            if p.age >= p.max_age:
                p.age = 0
                p.x = random.randint(0, self._w - 1)
                p.y = random.randint(0, self._h - 1)
                p.char = random.choice(".*+")

    def _update_fire(self) -> None:
        for p in self._particles:
            p.y -= p.speed
            p.x += random.choice([-0.3, 0, 0.3])
            if p.y < -2:
                p.y = self._h + random.uniform(0, 2)
                p.x = random.randint(0, self._w - 1)

    def _update_scan(self) -> None:
        # First particle is the sweep line, others are blips.
        sweep = self._particles[0]
        sweep.y += sweep.speed
        if sweep.y > self._h:
            sweep.y = 0
        for p in self._particles[1:]:
            p.age += 1
            if p.age >= p.max_age:
                p.age = 0
                p.x = random.uniform(0, self._w - 1)
                p.y = random.uniform(0, self._h - 1)

    def _update_pulse(self) -> None:
        for p in self._particles:
            p.length += p.speed
            if p.length > max(self._w, self._h):
                p.length = 0

    # -- Render -------------------------------------------------------------

    _GLITCH_CHARS = "\u2588\u2593\u2592\u2591#=+*"

    def _build_grid(self) -> List[List[Tuple[str, str]]]:
        """Build the current frame as a 2D list of (char, style) tuples."""
        grid: List[List[Tuple[str, str]]] = [
            [(" ", "")] * self._w for _ in range(self._h)
        ]

        if self.mode == "matrix":
            for p in self._particles:
                head_y = int(p.y)
                for i in range(p.length):
                    y = head_y - i
                    if 0 <= y < self._h and 0 <= p.x < self._w:
                        # Head is bright, tail dims out.
                        if i == 0:
                            grid[y][p.x] = (random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ@#$"), f"bold {self.color}")
                        elif i < 3:
                            grid[y][p.x] = (random.choice("0123456789<>|/\\"), self.color)
                        else:
                            grid[y][p.x] = (random.choice(".:'`,;"), self.accent)

        elif self.mode == "rain":
            for p in self._particles:
                y = int(p.y)
                if 0 <= y < self._h and 0 <= p.x < self._w:
                    grid[y][p.x] = (p.char, self.color)

        elif self.mode == "glitch":
            for p in self._particles:
                y = int(p.y)
                if 0 <= y < self._h and 0 <= p.x < self._w:
                    for k in range(p.length):
                        x = p.x + k
                        if 0 <= x < self._w:
                            grid[y][x] = (p.char, self.color if k == 0 else self.accent)

        elif self.mode == "snow":
            for p in self._particles:
                x = int(p.x) % self._w
                y = int(p.y)
                if 0 <= y < self._h:
                    grid[y][x] = (p.char, self.color)

        elif self.mode == "stars":
            for p in self._particles:
                if 0 <= int(p.x) < self._w and 0 <= int(p.y) < self._h:
                    intensity = 1.0 - (p.age / p.max_age)
                    style = self.color if intensity > 0.6 else self.accent
                    grid[int(p.y)][int(p.x)] = (p.char, style)

        elif self.mode == "fire":
            for p in self._particles:
                y = int(p.y)
                if 0 <= y < self._h and 0 <= int(p.x) < self._w:
                    grid[y][int(p.x)] = (p.char, f"bold {self.color}")
                    # Glow trail below
                    if y + 1 < self._h:
                        grid[y + 1][int(p.x)] = (":", self.color)
                    if y + 2 < self._h:
                        grid[y + 2][int(p.x)] = (".", self.accent)

        elif self.mode == "scan":
            sweep = self._particles[0]
            sweep_y = int(sweep.y)
            if 0 <= sweep_y < self._h:
                for x in range(self._w):
                    grid[sweep_y][x] = ("\u2588", f"bold {self.color}")
                # Brighter head at the right edge
                grid[sweep_y][-1] = ("\u2588", f"bold {self.color}")
            for p in self._particles[1:]:
                if 0 <= int(p.x) < self._w and 0 <= int(p.y) < self._h:
                    grid[int(p.y)][int(p.x)] = ("X", f"bold {self.color}")

        elif self.mode == "pulse":
            cx, cy = self._w / 2.0, self._h / 2.0
            for p in self._particles:
                radius = p.length
                # Trace a circle of that radius.
                steps = max(8, int(2 * math.pi * radius))
                for s in range(steps):
                    angle = (2 * math.pi * s) / steps
                    x = int(cx + radius * math.cos(angle))
                    y = int(cy + radius * math.sin(angle) * 0.5)  # squashed
                    if 0 <= x < self._w and 0 <= y < self._h:
                        grid[y][x] = ("*", f"bold {self.color}")

        return grid

    def render(self) -> Text:
        """Render the current frame as a Rich ``Text``."""
        grid = self._build_grid()
        self._last_grid = grid
        text = Text()
        for y, row in enumerate(grid):
            for ch, style in row:
                if ch == " ":
                    text.append(" ", style="")
                else:
                    text.append(ch, style=style or self.color)
            if y < len(grid) - 1:
                text.append("\n")
        return text

    # -- Standalone helper --------------------------------------------------

    @classmethod
    def render_particles(
        cls,
        mode: str,
        frame: int,
        width: int = 60,
        height: int = 18,
        color: str = "#ffffff",
        accent: str = "#888888",
        rng: Optional[random.Random] = None,
    ) -> Text:
        """Render a single frame of a particle effect (stateless helper).

        Args:
            mode: One of the supported particle modes.
            frame: Frame number (used for time-varying effects).
            width: Frame width in characters.
            height: Frame height in characters.
            color: Primary colour.
            accent: Secondary/accent colour.
            rng: Optional pre-seeded ``random.Random`` for determinism.

        Returns:
            Rich ``Text`` representing one frame.
        """
        rnd = rng or random
        # We build a small instance and step the seed via the frame number.
        field = cls(
            mode=mode,
            width=width,
            height=height,
            color=color,
            accent=accent,
        )
        # Re-seed internal particle lists deterministically-ish.
        field._init_particles()
        for _ in range(max(0, frame)):
            field._tick.__wrapped__ = None  # noop, just to be explicit
        # Step the simulation ``frame`` times without using a Timer.
        for _ in range(max(0, frame)):
            if mode == "matrix":
                field._update_matrix()
            elif mode == "rain":
                field._update_rain()
            elif mode == "glitch":
                field._update_glitch()
            elif mode == "snow":
                field._update_snow()
            elif mode == "stars":
                field._update_stars()
            elif mode == "fire":
                field._update_fire()
            elif mode == "scan":
                field._update_scan()
            elif mode == "pulse":
                field._update_pulse()
        return field.render()


# ---------------------------------------------------------------------------
# FadeTransition
# ---------------------------------------------------------------------------


class FadeTransition:
    """Smooth text fade in/out (terminals lack real alpha, so we fake it).

    Use :meth:`render` to obtain a Rich ``Text`` whose visibility reflects
    the given normalised time ``t`` (0 = invisible, 1 = fully shown).
    """

    @staticmethod
    def render(text: str, t: float, color: str = "#ffffff", placeholder: str = " ") -> Text:
        """Render text with a fade effect.

        Args:
            text: Source text.
            t: Time in ``[0, 1]`` (0 invisible, 1 fully visible).
            color: Foreground colour when fully visible.
            placeholder: Character used to mask hidden portions (use ``" "`` for
                smooth reveal, or a low-intensity glyph for typewriter effect).

        Returns:
            Rich ``Text`` representing the fade.
        """
        t = max(0.0, min(1.0, float(t)))
        if t <= 0.0:
            return Text(placeholder * len(text), style="")
        if t >= 1.0:
            return Text(text, style=color)

        # Choose reveal position: at low t, only a few chars are visible.
        reveal_count = int(math.ceil(t * len(text)))
        visible = text[:reveal_count]
        hidden = placeholder * (len(text) - reveal_count)
        # Use dim style on the leading edge to fake alpha.
        out = Text()
        if visible:
            # The most recently revealed char is dim, earlier ones are bright.
            if len(visible) > 1:
                out.append(visible[:-1], style=color)
            out.append(visible[-1], style=f"dim {color}")
        if hidden:
            out.append(hidden, style="")
        return out

    @classmethod
    def render_panel(
        cls, title: str, body: str, t: float, color: str = "#ffffff"
    ) -> Panel:
        """Render a panel whose title fades in along with its body.

        Args:
            title: Panel title.
            body: Panel body text.
            t: Fade time in ``[0, 1]``.
            color: Foreground colour.
        """
        return Panel(
            cls.render(body, t, color=color),
            title=cls.render(title, t, color=color),
            border_style=color if t > 0.5 else f"dim {color}",
        )


# ---------------------------------------------------------------------------
# GlitchEffect
# ---------------------------------------------------------------------------


class GlitchEffect:
    """Randomised text scrambling for a glitched / hacker look.

    Pure static helpers - the effect is parameterised by time, so it can
    be called from any animation timer without state.
    """

    GLITCH_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?/\\~`"
    SCRAMBLE_CHARS = "\u2588\u2593\u2592\u2591\u2580\u2584#=+*"

    @classmethod
    def render(
        cls,
        text: str,
        t: float = 1.0,
        intensity: float = 0.3,
        seed: Optional[int] = None,
        color: str = "#ffffff",
        accent: str = "#888888",
    ) -> Text:
        """Render text with a glitch effect.

        Args:
            text: Source text.
            t: Time in ``[0, 1]`` controlling overall glitch frequency.
            intensity: Probability per character of being glitched
                (clamped to ``[0, 1]``).
            seed: Optional RNG seed for deterministic glitches.
            color: Foreground colour for unglitched characters.
            accent: Colour for the glitched glyphs.

        Returns:
            Rich ``Text`` with scrambled characters.
        """
        rng = random.Random(seed) if seed is not None else random
        intensity = max(0.0, min(1.0, float(intensity)))
        # Glitch frequency is higher mid-animation.
        dynamic = intensity * (0.5 + 0.5 * math.sin(t * math.pi * 4))
        out = Text()
        for ch in text:
            if ch == " " or ch == "\n":
                out.append(ch, style="")
                continue
            roll = rng.random()
            if roll < dynamic * 0.6:
                out.append(rng.choice(cls.GLITCH_CHARS), style=f"bold {accent}")
            elif roll < dynamic:
                out.append(rng.choice(cls.SCRAMBLE_CHARS), style=accent)
            else:
                out.append(ch, style=color)
        return out

    @classmethod
    def jitter(
        cls,
        text: str,
        intensity: float = 0.05,
        seed: Optional[int] = None,
    ) -> str:
        """Return a string with a few characters randomly shifted/replaced.

        Args:
            text: Source text.
            intensity: Probability of jittering any character.
            seed: Optional RNG seed.

        Returns:
            New string with subtle glitching.
        """
        rng = random.Random(seed) if seed is not None else random
        chars = list(text)
        for i, ch in enumerate(chars):
            if ch == " " or ch == "\n":
                continue
            if rng.random() < intensity:
                chars[i] = rng.choice(cls.GLITCH_CHARS)
        return "".join(chars)


# ---------------------------------------------------------------------------
# WaveAnimation
# ---------------------------------------------------------------------------


class WaveAnimation:
    """Reveal text in a sine-wave pattern.

    Pure helpers - no widget state. Use :meth:`render` to get the current
    Rich ``Text`` for a given time.
    """

    @classmethod
    def render(
        cls,
        text: str,
        t: float,
        amplitude: float = 0.15,
        frequency: float = 2.0,
        revealed_color: str = "#ffffff",
        unrevealed_color: str = "#444444",
        placeholder: str = " ",
    ) -> Text:
        """Render text following a sine-wave reveal.

        Args:
            text: Source text.
            t: Time in ``[0, 1]``.
            amplitude: Vertical wave amplitude (in character rows of offset).
            frequency: Wave frequency (full cycles across the line).
            revealed_color: Colour of revealed characters.
            unrevealed_color: Colour of the placeholder chars.
            placeholder: Character to use for unrevealed positions.

        Returns:
            Rich ``Text`` showing the wave-revealed state.
        """
        t = max(0.0, min(1.0, float(t)))
        n = len(text)
        if n == 0:
            return Text("")
        out = Text()
        for i, ch in enumerate(text):
            # Wave threshold for this column.
            phase = (i / n) * frequency * 2 * math.pi
            threshold = i / n - amplitude * math.sin(phase + t * 4 * math.pi)
            if t > threshold:
                if ch == "\n":
                    out.append("\n")
                else:
                    out.append(ch, style=revealed_color)
            else:
                if ch == "\n":
                    out.append("\n")
                else:
                    out.append(placeholder, style=unrevealed_color)
        return out

    @classmethod
    def render_multiline(
        cls,
        lines: Sequence[str],
        t: float,
        **kwargs: object,
    ) -> Group:
        """Apply :meth:`render` to each line and group the result.

        Args:
            lines: Sequence of text lines.
            t: Time in ``[0, 1]``.
            **kwargs: Forwarded to :meth:`render`.

        Returns:
            Rich ``Group`` of Text renderables.
        """
        renderables = [cls.render(line, t, **kwargs) for line in lines]
        return Group(*renderables)


# ---------------------------------------------------------------------------
# Helpers - build a single composite Rich renderable from any animation
# ---------------------------------------------------------------------------


def animated_text(
    text: str,
    t: float,
    style: str = "wave",
    color: str = "#ffffff",
    accent: str = "#888888",
    **kwargs: object,
) -> Text:
    """Pick a text animation by name and render the result.

    Args:
        text: Source text.
        t: Time in ``[0, 1]``.
        style: One of ``"wave"``, ``"fade"``, ``"glitch"``, ``"plain"``.
        color: Primary colour.
        accent: Secondary colour.
        **kwargs: Forwarded to the chosen animation.

    Returns:
        Rich ``Text`` representing the animated state.
    """
    if style == "wave":
        return WaveAnimation.render(text, t, revealed_color=color, unrevealed_color=accent, **kwargs)
    if style == "fade":
        return FadeTransition.render(text, t, color=color, **kwargs)
    if style == "glitch":
        return GlitchEffect.render(text, t, color=color, accent=accent, **kwargs)
    return Text(text, style=color)


__all__ = [
    "Easing",
    "AnimatedCounter",
    "AnimatedProgress",
    "ParticleField",
    "FadeTransition",
    "GlitchEffect",
    "WaveAnimation",
    "animated_text",
    "DEFAULT_FRAME_INTERVAL",
    "PARTICLE_FRAME_INTERVAL",
]

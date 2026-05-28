"""agents/tui_game.py — Mini 2D platformer (Obby) for Elengenix TUI.

Simple side-scroller: press SPACE to jump over pits.
Falling = game over. Score = distance survived.
"""

from __future__ import annotations

import random
import logging
from typing import Any

logger = logging.getLogger("elengenix.game")

# ── Constants ───────────────────────────────────────────────────────────
VIEWPORT_W = 40
GROUND_Y = 9
PLAYER_X = 6
GRAVITY = 8
JUMP_VEL = -4
TERRAIN_SEGMENTS = 200  # pre-generate

PLAYER_SPRITES = {
    "run": ["◻◻◻", " ◻◻"],
    "jump": [" ◻◻", "◻◻◻"],
    "dead": ["×××", " ××"],
}

ENEMY_SPRITES = ["░░", "██"]


class ObbyGame:
    """Minimal 2D platformer — jump or die."""

    def __init__(self, app: Any, on_exit: callable = None):
        self.app = app
        self.on_exit = on_exit
        self.running = False
        self.game_over = False
        self.paused = False
        self.countdown = 0
        self.score = 0
        self.offset = 0.0
        self.player_y = float(GROUND_Y)
        self.player_vy = 0.0
        self.jumping = False
        self.frame_count = 0
        self.death_frame = 0

        # Pre-generate terrain
        self.terrain = self._generate_terrain()

    def _generate_terrain(self) -> list[str]:
        """Generate terrain: safe start area, then progressive difficulty."""
        terrain = ["█"] * 15  # Safe flat area to start
        pos = 15
        difficulty = 0.0
        while pos < TERRAIN_SEGMENTS:
            difficulty = min(1.0, pos / 60)  # ramps up over first 60 tiles
            plat_len = max(3, int(random.randint(4, 12) * (1.0 - difficulty * 0.4)))
            gap_len = max(1, int(random.randint(1, 3) * difficulty))
            terrain.extend(["█"] * plat_len)
            pos += plat_len
            if pos < TERRAIN_SEGMENTS:
                terrain.extend([" "] * gap_len)
                pos += gap_len
        return terrain

    def get_tile(self, x: int) -> str:
        """Get terrain tile at world position x."""
        if 0 <= x < len(self.terrain):
            return self.terrain[x]
        return "█"

    def start(self):
        """Start the game loop."""
        self.running = True
        self.game_over = False
        self.countdown = 90  # 90 frames @ 30fps ≈ 3s
        self.score = 0
        self.offset = 0.0
        self.player_y = float(GROUND_Y)
        self.player_vy = 0.0
        self.jumping = False
        self.frame_count = 0

    def jump(self):
        """Player jumps — only if on ground."""
        if not self.jumping and not self.game_over:
            self.jumping = True
            self.player_vy = JUMP_VEL

    def tick(self) -> str | None:
        """Advance one frame. Returns rendered frame or None if running."""
        if not self.running or self.game_over:
            return None

        self.frame_count += 1

        # Countdown phase
        if self.countdown > 0:
            self.countdown -= 1
            return self._render_countdown()

        # Physics: gravity
        if self.jumping:
            self.player_vy += GRAVITY
            self.player_y += self.player_vy

            # Check landing
            tile_x = int(self.offset + PLAYER_X)
            if self.player_y >= GROUND_Y:
                self.player_y = float(GROUND_Y)
                self.player_vy = 0.0
                self.jumping = False

                # Check if we landed on a pit
                if self.get_tile(tile_x) == " ":
                    return self._die()
        else:
            # Running — check for pit ahead
            tile_x = int(self.offset + PLAYER_X)
            if self.get_tile(tile_x) == " ":
                # Oops, stepping into pit
                self.player_y += 0.5
                if self.player_y > GROUND_Y + 2:
                    return self._die()

        # Scroll
        speed = 0.5 + min(0.6, self.score * 0.003)
        self.offset += speed
        self.score = int(self.offset)

        return self._render()

    def _die(self) -> str:
        """Trigger game over."""
        self.game_over = True
        self.running = False
        self.death_frame = 0
        return self._render_death()

    def _render_countdown(self) -> str:
        """Render countdown screen."""
        remaining = self.countdown // 30
        nums = {3: "  READY?", 2: "    3", 1: "    2", 0: "    1\n\n   GO!"}
        label = nums.get(remaining, "   GO!")
        return f"\n\n\n\n{label}\n\n   SPACE to jump | Q to quit"

    def _render(self) -> str:
        """Render current frame to string."""
        lines = [""] * (GROUND_Y + 4)

        # Sky with distant clouds
        for y in range(GROUND_Y + 1):
            lines[y] = lines[y].ljust(VIEWPORT_W, ' ')

        # Ground layer (solid)
        ground_line = ""
        for x in range(VIEWPORT_W):
            world_x = int(self.offset + x)
            tile = self.get_tile(world_x)
            ground_line += ("▄" if tile != " " else " ")
        lines[GROUND_Y] = ground_line

        # Ground base
        base_line = ""
        for x in range(VIEWPORT_W):
            world_x = int(self.offset + x)
            tile = self.get_tile(world_x)
            base_line += ("█" if tile != " " else " ")
        lines[GROUND_Y + 1] = base_line

        # Pit indicators (inverse colors for contrast)
        pit_line = ""
        for x in range(VIEWPORT_W):
            world_x = int(self.offset + x)
            tile = self.get_tile(world_x)
            if tile == " ":
                pit_line += "⬇"
            else:
                pit_line += " "

        # Player — y = GROUND_Y = ground, y = 3 = peak jump
        py = int(self.player_y)
        y_draw = max(0, py - 2)  # head row
        head = "▐█"
        body = "▐▌"
        if y_draw < GROUND_Y - 1:
            lines[y_draw]          = lines[y_draw][:PLAYER_X]          + head + lines[y_draw][PLAYER_X + 2:]
            lines[y_draw + 1]      = lines[y_draw + 1][:PLAYER_X]      + body + lines[y_draw + 1][PLAYER_X + 2:]
        else:
            lines[GROUND_Y - 1] = lines[GROUND_Y - 1][:PLAYER_X] + head + lines[GROUND_Y - 1][PLAYER_X + 2:]
            lines[GROUND_Y]    = lines[GROUND_Y][:PLAYER_X]    + body + lines[GROUND_Y][PLAYER_X + 2:]

        # Score bar
        top = f"🎮 OBBY  SCORE: {self.score:05d}  [SPACE] jump  [Q] quit"
        result = top + "\n" + "\n".join(lines)
        return result

    def _render_death(self) -> str:
        """Render game over screen."""
        lines = []
        for _ in range(5):
            lines.append("")

        # Dead player
        py = int(self.player_y)
        if py < GROUND_Y - 1:
            pass

        lines.append("")
        lines.append("       💀  GAME OVER  💀")
        lines.append(f"       SCORE: {self.score:05d}")
        lines.append("")
        lines.append("   [SPACE]  Play again")
        lines.append("   [Q]      Quit")

        return "\n".join(lines)

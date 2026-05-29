"""agents/tui_game.py — Mini 2D platformer (Obby) for Elengenix TUI.

Simple side-scroller: press SPACE to jump over pits.
Falling = game over. Score = distance survived.
"""

from __future__ import annotations

import random
import logging
import sys
from typing import Any

logger = logging.getLogger("elengenix.game")

# ── Constants ───────────────────────────────────────────────────────────
VIEWPORT_W = 34
GROUND_Y = 9
PLAYER_X = 5
GRAVITY = 0.15  # Lower gravity for a smaller, tighter jump
JUMP_VEL = -1.1  # Lower jump impulse to prevent jumping too high
TERRAIN_SEGMENTS = 400  # Longer terrain for high speeds

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
        self.falling_down_hole = False
        self.frame_count = 0
        self.death_frame = 0

        # Terrain & Security Tokens
        self.terrain = self._generate_terrain()
        self.tokens = self._generate_tokens()
        self.collected_tokens = set()

    def _generate_terrain(self) -> list[str]:
        """Generate terrain: safe start area, then progressive difficulty."""
        terrain = ["█"] * 12
        pos = 12
        difficulty = 0.0
        while pos < TERRAIN_SEGMENTS:
            difficulty = min(1.0, pos / 120)
            plat_len = max(3, int(random.randint(5, 12) * (1.0 - difficulty * 0.3)))
            gap_len = max(1, int(random.randint(1, 2) * difficulty))
            terrain.extend(["█"] * plat_len)
            pos += plat_len
            if pos < TERRAIN_SEGMENTS:
                terrain.extend([" "] * gap_len)
                pos += gap_len
        return terrain

    def _generate_tokens(self) -> dict[int, int]:
        """Generate token positions (world_x -> height_y)."""
        tokens = {}
        pos = 15
        while pos < TERRAIN_SEGMENTS - 10:
            if self.get_tile(pos) == "█" and self.get_tile(pos+1) == "█":
                # Tokens can be collected by lower jumps (GROUND_Y - 1 or -2)
                tokens[pos] = random.choice([GROUND_Y - 1, GROUND_Y - 2])
                pos += random.randint(8, 18)
            else:
                pos += 1
        return tokens

    def get_tile(self, x: int) -> str:
        """Get terrain tile at world position x."""
        if 0 <= x < len(self.terrain):
            return self.terrain[x]
        return "█"

    def start(self):
        """Start the game loop."""
        self.running = True
        self.game_over = False
        self.countdown = 60  # 60 frames @ 30fps ≈ 2s
        self.score = 0
        self.offset = 0.0
        self.player_y = float(GROUND_Y)
        self.player_vy = 0.0
        self.jumping = False
        self.falling_down_hole = False
        self.frame_count = 0
        self.collected_tokens.clear()
        self.tokens = self._generate_tokens()

    def jump(self):
        """Player jumps — only if on ground and not falling."""
        if not self.jumping and not self.falling_down_hole and not self.game_over:
            self.jumping = True
            self.player_vy = JUMP_VEL
            sys.stdout.write("\a")
            sys.stdout.flush()

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
        self.falling_down_hole = False

        if not self.jumping:
            tile_x = int(self.offset + PLAYER_X)
            if self.get_tile(tile_x) == " ":
                self.falling_down_hole = True
                # Align offset so the player falls exactly down the center of the gap
                self.offset = float(tile_x - PLAYER_X)
                self.player_y += 0.25  # Slower fall speed down the pit for better visual tracking
                if self.player_y >= GROUND_Y + 6.0:
                    return self._die()

        if self.jumping:
            self.player_vy += GRAVITY
            self.player_y += self.player_vy

            # Check landing
            tile_x = int(self.offset + PLAYER_X)
            if self.player_y >= GROUND_Y:
                if self.get_tile(tile_x) == "█":
                    self.player_y = float(GROUND_Y)
                    self.player_vy = 0.0
                    self.jumping = False
                else:
                    # Landing on a pit
                    self.jumping = False
                    self.player_vy = 0.0
                    self.falling_down_hole = True
                    self.offset = float(tile_x - PLAYER_X)

        # Check token collection (only if not falling)
        if not self.falling_down_hole:
            player_world_x = int(self.offset + PLAYER_X)
            if player_world_x in self.tokens and player_world_x not in self.collected_tokens:
                token_y = self.tokens[player_world_x]
                if abs(self.player_y - token_y) < 1.5:
                    self.collected_tokens.add(player_world_x)
                    self.score += 50
                    sys.stdout.write("\a")
                    sys.stdout.flush()

            # Scroll speed starts very slow (0.2) and gets progressively faster (up to 0.9)
            speed = 0.2 + min(0.7, self.score * 0.0006)
            self.offset += speed
            self.score += 1

        return self._render()

    def _die(self) -> str:
        """Trigger game over."""
        self.game_over = True
        self.running = False
        sys.stdout.write("\a\a")
        sys.stdout.flush()
        return self._render_death()

    def _render_countdown(self) -> str:
        """Render countdown screen."""
        remaining = self.countdown // 20
        nums = {2: "READY?", 1: "  3", 0: "  2", -1: "  1"}
        label = nums.get(remaining, "  GO!")
        return f"\n\n\n\n     {label}\n\n   SPACE jump | Q quit"

    def _render(self) -> str:
        """Render current frame to string."""
        lines = [""] * (GROUND_Y + 3)

        # Initialize background grid with spaces
        for y in range(len(lines)):
            lines[y] = " " * VIEWPORT_W

        # Draw tokens
        for world_x, token_y in self.tokens.items():
            if world_x not in self.collected_tokens:
                screen_x = int(world_x - self.offset)
                if 0 <= screen_x < VIEWPORT_W:
                    y_draw = int(token_y)
                    if 0 <= y_draw < len(lines):
                        line = lines[y_draw]
                        lines[y_draw] = line[:screen_x] + "$" + line[screen_x + 1:]

        # Draw player
        py = int(self.player_y)
        if self.falling_down_hole:
            head = "x"
            body = "v"
        else:
            head = "o"
            body = "▲"
        
        y_head = py - 1
        y_body = py
        
        if 0 <= y_head < len(lines):
            line = lines[y_head]
            lines[y_head] = line[:PLAYER_X] + head + line[PLAYER_X + 1:]
        if 0 <= y_body < len(lines):
            line = lines[y_body]
            lines[y_body] = line[:PLAYER_X] + body + line[PLAYER_X + 1:]

        # Ground layer
        ground_line = ""
        for x in range(VIEWPORT_W):
            world_x = int(self.offset + x)
            tile = self.get_tile(world_x)
            ground_line += ("█" if tile != " " else " ")
        if GROUND_Y + 1 < len(lines):
            lines[GROUND_Y + 1] = ground_line

        # Under ground layer
        under_line = ""
        for x in range(VIEWPORT_W):
            world_x = int(self.offset + x)
            tile = self.get_tile(world_x)
            under_line += ("▒" if tile != " " else " ")
        if GROUND_Y + 2 < len(lines):
            lines[GROUND_Y + 2] = under_line

        top = f"🎮 SCORE: {self.score:05d}"
        return top + "\n" + "\n".join(lines)

    def _render_death(self) -> str:
        """Render game over screen."""
        lines = [
            "\n\n",
            "    💀 GAME OVER 💀",
            f"     SCORE: {self.score:05d}",
            "\n",
            "   [SPACE] Play again",
            "   [Q] Quit game"
        ]
        return "\n".join(lines)

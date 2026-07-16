"""Tests for elengenix/scanning/tui_game.py — ObbyGame platformer."""

from __future__ import annotations

import pytest
from unittest.mock import Mock, patch, MagicMock
from elengenix.scanning.tui_game import ObbyGame


class TestObbyGameInit:
    """Tests for ObbyGame initialization."""

    def test_init_sets_attributes(self):
        """Init should set all game attributes."""
        mock_app = Mock()
        game = ObbyGame(mock_app)

        assert game.app == mock_app
        assert game.running is False
        assert game.game_over is False
        assert game.paused is False
        assert game.countdown == 0
        assert game.score == 0
        assert game.offset == 0.0
        assert game.player_y == 9.0  # GROUND_Y
        assert game.player_vy == 0.0
        assert game.jumping is False
        assert game.falling_down_hole is False
        assert game.frame_count == 0
        assert game.death_frame == 0
        assert game.on_exit is None

    def test_init_with_on_exit_callback(self):
        """Init should store on_exit callback."""
        mock_app = Mock()
        mock_on_exit = Mock()
        game = ObbyGame(mock_app, on_exit=mock_on_exit)

        assert game.on_exit == mock_on_exit

    def test_terrain_generation(self):
        """Terrain should be generated with correct length."""
        mock_app = Mock()
        game = ObbyGame(mock_app)

        # Terrain length may vary slightly due to generation loop
        assert len(game.terrain) >= 400
        assert len(game.terrain) <= 405
        # First 12 should be safe ground
        assert all(t == "█" for t in game.terrain[:12])

    def test_token_generation(self):
        """Tokens should be generated on solid ground."""
        mock_app = Mock()
        game = ObbyGame(mock_app)

        # All tokens should be on solid ground
        for pos, y in game.tokens.items():
            assert game.get_tile(pos) == "█"
            assert y in (8, 7)  # GROUND_Y - 1 or GROUND_Y - 2


class TestObbyGameGetTile:
    """Tests for get_tile method."""

    def test_get_tile_within_bounds(self):
        """Should return correct tile within bounds."""
        game = ObbyGame(Mock())
        # First 12 are ground
        assert game.get_tile(0) == "█"
        assert game.get_tile(11) == "█"

    def test_get_tile_out_of_bounds(self):
        """Should return ground for out of bounds."""
        game = ObbyGame(Mock())
        assert game.get_tile(-1) == "█"
        assert game.get_tile(1000) == "█"


class TestObbyGameStart:
    """Tests for start method."""

    def test_start_resets_state(self):
        """Start should reset all game state."""
        game = ObbyGame(Mock())
        game.score = 100
        game.game_over = True
        game.running = True
        game.player_y = 0.0
        game.offset = 50.0

        game.start()

        assert game.running is True
        assert game.game_over is False
        assert game.countdown == 60
        assert game.score == 0
        assert game.offset == 0.0
        assert game.player_y == 9.0  # GROUND_Y
        assert game.player_vy == 0.0
        assert game.jumping is False
        assert game.falling_down_hole is False
        assert game.frame_count == 0
        assert len(game.collected_tokens) == 0


class TestObbyGameJump:
    """Tests for jump method."""

    def test_jump_sets_state(self):
        """Jump should set jumping state and velocity."""
        game = ObbyGame(Mock())
        game.jumping = False
        game.falling_down_hole = False
        game.game_over = False

        game.jump()

        assert game.jumping is True
        assert game.player_vy == -1.1  # JUMP_VEL

    def test_jump_noop_when_already_jumping(self):
        """Jump should be no-op when already jumping."""
        game = ObbyGame(Mock())
        game.jumping = True
        game.player_vy = -0.5

        game.jump()

        # Should not change velocity
        assert game.player_vy == -0.5

    def test_jump_noop_when_falling(self):
        """Jump should be no-op when falling down hole."""
        game = ObbyGame(Mock())
        game.jumping = False
        game.falling_down_hole = True

        game.jump()

        assert game.jumping is False

    def test_jump_noop_when_game_over(self):
        """Jump should be no-op when game over."""
        game = ObbyGame(Mock())
        game.game_over = True

        game.jump()

        assert game.jumping is False


class TestObbyGameTick:
    """Tests for tick method."""

    def test_tick_returns_none_when_not_running(self):
        """Should return None when not running."""
        game = ObbyGame(Mock())
        game.running = False

        result = game.tick()
        assert result is None

    def test_tick_returns_none_when_game_over(self):
        """Should return None when game over."""
        game = ObbyGame(Mock())
        game.running = True
        game.game_over = True

        result = game.tick()
        assert result is None

    def test_tick_countdown_phase(self):
        """Should render countdown when countdown > 0."""
        game = ObbyGame(Mock())
        game.running = True
        game.countdown = 30

        with patch.object(game, "_render_countdown", return_value="countdown screen"):
            result = game.tick()
            assert result == "countdown screen"
            assert game.countdown == 29

    def test_tick_gravity_when_not_jumping(self):
        """Should apply gravity when not jumping."""
        game = ObbyGame(Mock())
        game.running = True
        game.countdown = 0
        game.jumping = False
        game.game_over = False
        game.offset = 0.0
        game.player_y = 9.0
        game.terrain = [" "] * 400  # All holes

        with patch.object(game, "_die", return_value="dead"):
            result = game.tick()
            # First tick sets falling_down_hole = True and aligns offset
            # Second tick would call _die when player_y >= GROUND_Y + 6.0
            # We only call tick once so falling_down_hole is set
            assert game.falling_down_hole is True
            # Result is the rendered frame since player_y hasn't reached death threshold yet
            assert isinstance(result, str)


class TestObbyGameDie:
    """Tests for _die method."""

    def test_die_sets_game_over(self):
        """_die should set game_over and running to False."""
        game = ObbyGame(Mock())
        game.running = True
        game.game_over = False

        with patch("sys.stdout.write") as mock_write:
            with patch("sys.stdout.flush") as mock_flush:
                result = game._die()

        assert game.game_over is True
        assert game.running is False
        mock_write.assert_called()
        mock_flush.assert_called()


class TestObbyGameRenderCountdown:
    """Tests for _render_countdown method."""

    def test_render_countdown_ready(self):
        """Should show READY? at countdown 40-49."""
        game = ObbyGame(Mock())
        game.countdown = 45

        result = game._render_countdown()
        assert "READY?" in result

    def test_render_countdown_numbers(self):
        """Should show countdown numbers."""
        game = ObbyGame(Mock())
        game.countdown = 19

        result = game._render_countdown()
        assert "3" in result or "2" in result or "1" in result


class TestObbyGameRender:
    """Tests for _render method."""

    def test_render_returns_string(self):
        """Should return rendered frame as string."""
        game = ObbyGame(Mock())
        game.running = True
        game.countdown = 0
        game.game_over = False
        game.score = 0
        game.offset = 0.0
        game.player_y = 9.0
        game.jumping = False
        game.falling_down_hole = False

        result = game._render()

        assert isinstance(result, str)
        assert "SCORE: 00000" in result
        assert "█" in result  # Ground should be drawn

    def test_render_contains_player(self):
        """Render should contain player character."""
        game = ObbyGame(Mock())
        game.running = True
        game.countdown = 0
        game.game_over = False
        game.player_y = 9.0
        game.jumping = False
        game.falling_down_hole = False
        game.offset = 0.0
        game.score = 0

        result = game._render()

        assert "o" in result  # Player head


class TestObbyGameRenderDeath:
    """Tests for _render_death method."""

    def test_render_death_shows_score(self):
        """Death screen should show score."""
        game = ObbyGame(Mock())
        game.score = 1234

        result = game._render_death()
        assert "1234" in result
        assert "GAME OVER" in result
        assert "Play again" in result


class TestObbyGameConstants:
    """Tests for game constants."""

    def test_viewport_w(self):
        """VIEWPORT_W should be 34."""
        from elengenix.scanning.tui_game import VIEWPORT_W
        assert VIEWPORT_W == 34

    def test_ground_y(self):
        """GROUND_Y should be 9."""
        from elengenix.scanning.tui_game import GROUND_Y
        assert GROUND_Y == 9

    def test_player_x(self):
        """PLAYER_X should be 5."""
        from elengenix.scanning.tui_game import PLAYER_X
        assert PLAYER_X == 5

    def test_gravity(self):
        """GRAVITY should be 0.15."""
        from elengenix.scanning.tui_game import GRAVITY
        assert GRAVITY == 0.15

    def test_jump_vel(self):
        """JUMP_VEL should be -1.1."""
        from elengenix.scanning.tui_game import JUMP_VEL
        assert JUMP_VEL == -1.1

    def test_terrain_segments(self):
        """TERRAIN_SEGMENTS should be 400."""
        from elengenix.scanning.tui_game import TERRAIN_SEGMENTS
        assert TERRAIN_SEGMENTS == 400


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
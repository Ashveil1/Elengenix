"""tests/test_config_wizard.py — Comprehensive tests for ConfigWizard class configuration management."""

import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from tools.config_wizard import ConfigWizard


class TestConfigWizardYaml:
    """Test ConfigWizard's config.yaml saving and loading functionality."""

    @pytest.fixture(autouse=True)
    def setup_temp_dir(self):
        # Create a temporary directory for config.yaml and .env testing
        self.test_dir = Path(tempfile.mkdtemp())
        self.env_file = self.test_dir / ".env"
        self.config_file = self.test_dir / "config.yaml"

        # Instantiate ConfigWizard pointing to this temporary directory
        self.wizard = ConfigWizard(config_dir=self.test_dir)

        yield

        # Clean up temporary directory
        shutil.rmtree(self.test_dir)

    def test_load_yaml_config_empty(self):
        """Test loading when config.yaml does not exist."""
        config = self.wizard._load_yaml_config()
        assert isinstance(config, dict)
        assert len(config) == 0

    def test_load_yaml_config_fallback_to_example(self):
        """Test loading config falls back to config.yaml.example if config.yaml is missing."""
        example_data = {
            "team_aegis": {
                "enabled": False,
                "strategist": {"provider": "gemini", "model": "gemini-1.5-flash"},
            }
        }
        example_file = self.test_dir / "config.yaml.example"
        example_file.write_text(yaml.dump(example_data))

        # Check fallback
        config = self.wizard._load_yaml_config()
        assert config["team_aegis"]["enabled"] is False
        assert config["team_aegis"]["strategist"]["provider"] == "gemini"

    def test_load_yaml_config_invalid_syntax_returns_empty_dict(self):
        """Test that loading an invalid YAML file gracefully logs and returns an empty dict."""
        self.config_file.write_text("invalid_key: {unclosed_brace")
        config = self.wizard._load_yaml_config()
        assert isinstance(config, dict)
        assert len(config) == 0

    def test_save_and_load_yaml_config(self):
        """Test saving and then loading a config.yaml file."""
        test_data = {
            "agent": {"max_steps": 10},
            "team_aegis": {
                "enabled": True,
                "strategist": {"provider": "gemini", "model": "gemini-2.0-flash"},
            },
        }
        self.wizard._save_yaml_config(test_data)

        # Load and verify
        loaded = self.wizard._load_yaml_config()
        assert loaded["agent"]["max_steps"] == 10
        assert loaded["team_aegis"]["enabled"] is True
        assert loaded["team_aegis"]["strategist"]["provider"] == "gemini"

    def test_save_team_to_yaml(self):
        """Test _save_team_to_yaml helper updates team_aegis correctly."""
        final_team = [
            {"provider": "gemini", "model": "gemini-2.0-flash", "rpm": "40"},
            {"provider": "anthropic", "model": "claude-3-5-haiku-20241022", "rpm": "30"},
            {"provider": "openai", "model": "gpt-4o-mini", "rpm": "20"},
        ]

        self.wizard._save_team_to_yaml(final_team)

        # Load and verify
        loaded = self.wizard._load_yaml_config()
        assert loaded["team_aegis"]["enabled"] is True
        assert loaded["team_aegis"]["strategist"]["provider"] == "gemini"
        assert loaded["team_aegis"]["strategist"]["model"] == "gemini-2.0-flash"
        assert loaded["team_aegis"]["specialist"]["provider"] == "anthropic"
        assert loaded["team_aegis"]["critic"]["provider"] == "openai"


class TestConfigWizardRoleSetup:
    """Test ConfigWizard's interactive configuration flows and synchronizations."""

    @pytest.fixture(autouse=True)
    def setup_temp_dir(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.wizard = ConfigWizard(config_dir=self.test_dir)

        # Backup original env
        self.original_env = dict(os.environ)

        yield

        # Clean up
        shutil.rmtree(self.test_dir)
        os.environ.clear()
        os.environ.update(self.original_env)

    @patch("tools.config_wizard.ConfigWizard._fetch_remote_models", return_value=[])
    @patch("tools.config_wizard.console.input")
    def test_configure_team_role_gemini_provider_and_model(self, mock_input, mock_fetch):
        """Test interactive role configuration simulation for Gemini provider."""
        # index 2 = Gemini (Google), index 2 = gemini-3.1-pro
        mock_input.side_effect = ["2", "2"]

        config = {}
        self.wizard._configure_team_role(
            role_key="strategist", role_name="Strategist AI", config=config
        )

        # Verify YAML configuration saved
        assert config["team_aegis"]["strategist"]["provider"] == "gemini"
        assert config["team_aegis"]["strategist"]["model"] == "gemini-3.1-pro"

        # Verify environment variable sync
        assert "gemini/gemini-3.1-pro" in os.environ.get("ACTIVE_MODELS", "")

    @patch("tools.config_wizard.ConfigWizard._fetch_remote_models", return_value=[])
    @patch("tools.config_wizard.console.input")
    def test_configure_team_role_custom_model_identifier(self, mock_input, mock_fetch):
        """Test interactive role configuration using a custom model name identifier."""
        # index 3 = OpenAI (GPT-4), Custom Model index (7), custom model identifier
        mock_input.side_effect = ["3", "7", "gpt-custom-model"]

        config = {}
        self.wizard._configure_team_role(role_key="critic", role_name="Critic AI", config=config)

        assert config["team_aegis"]["critic"]["provider"] == "openai"
        assert config["team_aegis"]["critic"]["model"] == "gpt-custom-model"
        assert "openai/gpt-custom-model" in os.environ.get("ACTIVE_MODELS", "")

    @patch("tools.config_wizard.console.input")
    def test_configure_team_role_cancel_stops_execution(self, mock_input):
        """Test that selecting cancel (0) terminates interactive flow immediately."""
        # Provider selection = 0 (Cancel)
        mock_input.side_effect = ["0"]

        config = {}
        self.wizard._configure_team_role(
            role_key="specialist", role_name="Specialist AI", config=config
        )

        # config should remain empty
        assert len(config) == 0


class TestConfigWizardEnvSync:
    """Test ConfigWizard's .env parsing, updating, and removal logic."""

    @pytest.fixture(autouse=True)
    def setup_temp_dir(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.wizard = ConfigWizard(config_dir=self.test_dir)
        yield
        shutil.rmtree(self.test_dir)

    def test_save_env_var_writes_valid_line_and_restricts_permissions(self):
        """Test save_env_var updates existing entries and restricts .env permissions."""
        self.wizard._save_env_var("TEST_KEY_ONE", "value_one")
        assert self.wizard.env_file.exists()

        # Verify content
        content = self.wizard.env_file.read_text()
        assert "TEST_KEY_ONE=value_one" in content

        # Verify permissions (0o600 -> owner read/write only)
        mode = self.wizard.env_file.stat().st_mode
        assert (mode & 0o777) == 0o600

    def test_remove_env_var_deletes_entry_from_file_and_session(self):
        """Test remove_env_var deletes the key from both file and current os.environ session."""
        os.environ["TEST_REMOVE_KEY"] = "temp"
        self.wizard._save_env_var("TEST_REMOVE_KEY", "temp")

        # Perform removal
        self.wizard._remove_env_var("TEST_REMOVE_KEY")

        assert "TEST_REMOVE_KEY" not in os.environ
        content = self.wizard.env_file.read_text()
        assert "TEST_REMOVE_KEY" not in content

"""Contract tests for the AI provider catalog (single source of truth).

Five modules used to hand-maintain their own provider catalogs and drift:
wizards offered providers the runtime could not resolve (cohere /
huggingface / replicate were missing from tools.ai_config), default models
differed per file, and overlay_menu guessed env keys (breaking replicate's
``REPLICATE_API_TOKEN``).

These tests lock every consumer to ``elengenix/providers/catalog.py``.
"""

from __future__ import annotations

import pytest

from elengenix.providers import catalog


class TestCatalogInvariants:
    def test_provider_count_and_unique_ids(self):
        ids = [p.id for p in catalog.PROVIDERS]
        assert len(ids) == 15
        assert len(ids) == len(set(ids))
        assert catalog.PROVIDER_IDS == tuple(ids)

    def test_env_keys_unique_and_conventional(self):
        keys = [p.env_key for p in catalog.PROVIDERS if p.env_key]
        assert len(keys) == len(set(keys))
        for p in catalog.PROVIDERS:
            if p.key_free:
                assert p.env_key is None
            elif p.id == "replicate":
                assert p.env_key == "REPLICATE_API_TOKEN"
            else:
                assert p.env_key == f"{p.id.upper()}_API_KEY", p.id

    def test_priorities_unique_and_sorted(self):
        prios = [p.priority for p in catalog.PROVIDERS]
        assert len(prios) == len(set(prios))
        assert catalog.priority_order() == tuple(
            p.id for p in sorted(catalog.PROVIDERS, key=lambda p: p.priority)
        )

    def test_special_custom_sentinel(self):
        assert "custom" in catalog.SPECIAL_IDS
        assert catalog.env_key_for("custom") == "CUSTOM_API_KEY"
        assert catalog.spec("custom") is None  # not a real provider

    def test_helper_shapes(self):
        assert catalog.provider_defaults("openai") == {
            "base_url": "https://api.openai.com/v1",
            "env_key": "OPENAI_API_KEY",
            "default_model": "gpt-4o-mini",
        }
        assert catalog.provider_defaults("nope") is None
        assert catalog.get_provider_config("nope") == {}
        assert catalog.spec("ollama").key_free is True
        assert catalog.env_key_for("ollama") is None


class TestAiConfigDerived:
    def test_known_prefixes_match_catalog(self):
        from tools.ai_config import _KNOWN_PROVIDER_PREFIXES

        assert _KNOWN_PROVIDER_PREFIXES == set(catalog.PROVIDER_IDS)

    def test_env_key_mapping_matches_catalog(self):
        from tools.ai_config import _default_env_key_for

        for p in catalog.PROVIDERS:
            assert _default_env_key_for(p.id) == p.env_key, p.id
        assert _default_env_key_for("custom") == "CUSTOM_API_KEY"
        assert _default_env_key_for("unknown-x") is None

    def test_key_free_providers_match_catalog(self):
        from tools.ai_config import _KEY_FREE_PROVIDERS

        assert _KEY_FREE_PROVIDERS == {p.id for p in catalog.PROVIDERS if p.key_free}


class TestUniversalClientDerived:
    def test_client_configs_match_catalog(self):
        from tools.universal_ai_client import UniversalAIClient

        configs = UniversalAIClient.PROVIDER_CONFIGS
        assert set(configs) == set(catalog.PROVIDER_IDS)
        for p in catalog.PROVIDERS:
            cfg = configs[p.id]
            assert cfg["base_url"] == p.base_url, p.id
            assert cfg["env_key"] == p.env_key, p.id
            assert cfg["default_model"] == p.default_model, p.id
        # anthropic keeps its adapter flag; nothing else gained one
        assert configs["anthropic"].get("custom_format") is True
        flagged = [k for k, v in configs.items() if v.get("custom_format")]
        assert flagged == ["anthropic"]


class TestConfigWizardDerived:
    def test_menu_matches_catalog(self):
        from tools.config_wizard import ConfigWizard

        specs = list(catalog.iter_specs())
        assert [p.name for p in ConfigWizard.AI_PROVIDERS] == [s.display for s in specs]
        assert [p.env_key for p in ConfigWizard.AI_PROVIDERS] == [
            s.env_key or "" for s in specs
        ]
        assert [p.base_url for p in ConfigWizard.AI_PROVIDERS] == [s.base_url for s in specs]

    def test_priority_and_keymap_match_catalog(self):
        from tools.config_wizard import ConfigWizard

        assert ConfigWizard.PRIORITY_ORDER == list(catalog.priority_order())
        assert ConfigWizard._PROVIDER_KEY_MAP == {
            s.display: s.id for s in catalog.iter_specs()
        }

    def test_default_models_match_catalog(self):
        from tools.config_wizard import ConfigWizard

        assert ConfigWizard.DEFAULT_MODELS == {
            s.display: list(s.models) for s in catalog.iter_specs()
        }


class TestWelcomeWizardDerived:
    def test_preferences_match_catalog_free_first(self):
        from tools.welcome_wizard import WelcomeWizard

        prefs = WelcomeWizard.AI_PREFERENCES
        displays = [p[0] for p in prefs]
        assert displays == [s.display for s in catalog.iter_specs()] or set(displays) == {
            s.display for s in catalog.iter_specs()
        }
        # free tiers come before paid ones
        free_flags = [catalog.spec(WelcomeWizard._PROVIDER_ALIASES[d.lower()]).is_free for d in displays]
        assert free_flags == sorted(free_flags, reverse=True)

        for disp, env_key, _tag, model in prefs:
            spec = catalog.spec(WelcomeWizard._PROVIDER_ALIASES[disp.lower()])
            assert env_key == (spec.env_key or "")
            assert model == (spec.recommended_model or spec.default_model)

    def test_provider_aliases_cover_all_displays(self):
        from tools.welcome_wizard import WelcomeWizard

        assert WelcomeWizard._PROVIDER_ALIASES == {
            s.display.lower(): s.id for s in catalog.iter_specs()
        }


class TestOverlayDerived:
    def test_provider_list_matches_catalog(self):
        from tools.overlay_menu import SettingsOverlay

        assert SettingsOverlay.ALL_PROVIDERS == catalog.PROVIDER_IDS

    def test_env_key_helper_matches_catalog(self):
        from tools.overlay_menu import SettingsOverlay

        for pid in catalog.PROVIDER_IDS:
            assert SettingsOverlay._provider_env_key(pid) == catalog.env_key_for(pid)


class TestAddProviderOnePlace:
    def test_new_provider_reachable_everywhere(self, monkeypatch):
        """Adding a provider to the catalog must be enough: every consumer
        picks it up automatically (the old five-catalog drift is dead)."""
        from tools.ai_config import _KNOWN_PROVIDER_PREFIXES
        from tools.config_wizard import ConfigWizard
        from tools.universal_ai_client import UniversalAIClient
        from tools.welcome_wizard import WelcomeWizard
        from tools.overlay_menu import SettingsOverlay

        # gemini has been in every historical catalog at some point — if a
        # re-introduced provider (e.g. a future "acme") is added to the
        # catalog only, these all must include it without further edits.
        assert "gemini" in _KNOWN_PROVIDER_PREFIXES
        assert "gemini" in UniversalAIClient.PROVIDER_CONFIGS
        assert "gemini" in ConfigWizard._PROVIDER_KEY_MAP.values()
        assert "gemini" in {WelcomeWizard._PROVIDER_ALIASES[d.lower()] for d, *_ in WelcomeWizard.AI_PREFERENCES}
        assert "gemini" in SettingsOverlay.ALL_PROVIDERS

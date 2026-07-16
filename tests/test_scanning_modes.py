"""Tests for elengenix/scanning/modes.py — ModeProcessor."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch, Mock
from pathlib import Path
from elengenix.scanning.modes import ModeProcessor


class TestModeProcessorInit:
    """Tests for ModeProcessor initialization."""

    def test_init_with_all_params(self):
        """Init with all optional params."""
        mock_client = Mock()
        mock_governance = Mock()
        mock_cvss = Mock()
        mock_cve = Mock()

        processor = ModeProcessor(
            client=mock_client,
            governance=mock_governance,
            cvss_calc=mock_cvss,
            cve_db=mock_cve,
            enable_memory=True,
        )

        assert processor.client == mock_client
        assert processor.governance == mock_governance
        assert processor.cvss_calc == mock_cvss
        assert processor.cve_db == mock_cve
        assert processor.enable_memory is True

    def test_init_with_required_only(self):
        """Init with only required client param."""
        mock_client = Mock()
        processor = ModeProcessor(client=mock_client)

        assert processor.client == mock_client
        assert processor.governance is None
        assert processor.cvss_calc is None
        assert processor.cve_db is None
        assert processor.enable_memory is True  # default


class TestProcessUniversal:
    """Tests for process_universal method."""

    def test_calls_universal_process(self):
        """Should call the universal processor with correct args."""
        mock_client = Mock()
        processor = ModeProcessor(client=mock_client)

        with patch("elengenix.scanning.universal.process_universal") as mock_universal:
            mock_universal.return_value = "Universal result"
            result = processor.process_universal(
                user_input="scan test.com",
                conversation_history=[{"role": "user", "content": "hi"}],
                base_prompt="System prompt",
                callback=None,
                target="test.com",
                mode="auto",
                preflight_findings=[{"vuln": "xss"}],
            )

            assert result == "Universal result"
            mock_universal.assert_called_once()
            call_kwargs = mock_universal.call_args[1]
            assert call_kwargs["user_input"] == "scan test.com"
            assert call_kwargs["target"] == "test.com"
            assert call_kwargs["mode"] == "auto"
            assert call_kwargs["preflight_findings"] == [{"vuln": "xss"}]

    def test_passes_all_parameters(self):
        """All parameters should be passed through."""
        mock_client = Mock()
        processor = ModeProcessor(client=mock_client)

        with patch("elengenix.scanning.universal.process_universal") as mock_universal:
            mock_universal.return_value = "done"
            mock_callback = Mock()

            processor.process_universal(
                user_input="test",
                conversation_history=[],
                base_prompt="prompt",
                callback=mock_callback,
                target="example.com",
                mode="test",
                preflight_findings=[],
            )

            call_kwargs = mock_universal.call_args[1]
            assert call_kwargs["callback"] == mock_callback
            assert call_kwargs["client"] == mock_client
            assert call_kwargs["governance"] is None


class TestProcessHybrid:
    """Tests for process_hybrid method."""

    def test_returns_error_when_no_target(self):
        """Should return error message when no target provided."""
        mock_client = Mock()
        processor = ModeProcessor(client=mock_client)

        # Mock _extract_target_from_text to return None (no target in input)
        with patch("elengenix.scanning.helpers._extract_target_from_text", return_value=None):
            with patch("elengenix.scanning.hybrid_agent.HybridAgent") as mock_hybrid:
                result = processor.process_hybrid(
                    user_input="help me",
                    target="",
                    team_aegis_clients={},
                )

                assert "No target specified" in result
                mock_hybrid.assert_not_called()

    def test_infers_target_from_input(self):
        """Should infer target from user input when not provided."""
        mock_client = Mock()
        processor = ModeProcessor(client=mock_client)

        with patch("elengenix.scanning.helpers._extract_target_from_text", return_value="example.com"):
            with patch("elengenix.scanning.hybrid_agent.HybridAgent") as mock_hybrid:
                mock_instance = Mock()
                mock_instance.run.return_value = "Hybrid result"
                mock_instance.all_findings = []
                mock_hybrid.return_value = mock_instance

                # Mock get_reports_path in the modes module (where it's imported)
                with patch("elengenix.scanning.modes.get_reports_path") as mock_reports:
                    mock_path = Mock()
                    mock_path.parent = Mock()
                    mock_path.write_text = Mock()
                    mock_reports.return_value = mock_path

                    result = processor.process_hybrid(
                        user_input="hunt example.com",
                        target="",  # empty, should be inferred
                        team_aegis_clients={},
                    )

        assert result == "Hybrid result"
        mock_hybrid.assert_called_once()
        call_kwargs = mock_hybrid.call_args[1]
        assert call_kwargs["target"] == "example.com"

    def test_initializes_hybrid_agent(self):
        """Should create HybridAgent with correct config."""
        mock_client = Mock()
        mock_governance = Mock()
        mock_cvss = Mock()
        mock_cve = Mock()
        processor = ModeProcessor(
            client=mock_client,
            governance=mock_governance,
            cvss_calc=mock_cvss,
            cve_db=mock_cve,
        )

        ta_clients = {
            "strategist_client": Mock(),
            "specialist_client": Mock(),
            "critic_client": Mock(),
            "strategist_label": "Strat",
            "specialist_label": "Spec",
            "critic_label": "Crit",
        }

        with patch("elengenix.scanning.helpers._extract_target_from_text", return_value="target.com"):
            with patch("elengenix.scanning.hybrid_agent.HybridAgent") as mock_hybrid:
                mock_instance = Mock()
                mock_instance.run.return_value = "Hybrid result"
                mock_instance.all_findings = []
                mock_hybrid.return_value = mock_instance

                # Mock get_reports_path to avoid filesystem access
                with patch("elengenix.scanning.modes.get_reports_path") as mock_reports:
                    mock_path = Mock()
                    mock_path.parent = Mock()
                    mock_path.write_text = Mock()
                    mock_reports.return_value = mock_path

                    with patch("elengenix.scanning.modes.MissionState") as mock_mission:
                        mock_mission.return_value = Mock(mission_id="test:123")
                        processor.process_hybrid(
                            user_input="scan target.com",
                            target="",
                            team_aegis_clients=ta_clients,
                        )

                # Check HybridAgent was created with right params
                mock_hybrid.assert_called_once()
                call_kwargs = mock_hybrid.call_args[1]
                assert call_kwargs["client"] == mock_client
                assert call_kwargs["governance"] == mock_governance
                assert call_kwargs["target"] == "target.com"
                assert call_kwargs["strategist_client"] == ta_clients["strategist_client"]
                assert call_kwargs["strategist_label"] == "Strat"

    def test_wires_mission_state(self):
        """Should wire up mission_state, cvss_calc, cve_db."""
        mock_client = Mock()
        mock_cvss = Mock()
        mock_cve = Mock()
        processor = ModeProcessor(
            client=mock_client,
            cvss_calc=mock_cvss,
            cve_db=mock_cve,
        )

        with patch("elengenix.scanning.helpers._extract_target_from_text", return_value="t.com"):
            with patch("elengenix.scanning.hybrid_agent.HybridAgent") as mock_hybrid:
                mock_instance = Mock()
                mock_instance.run.return_value = "result"
                mock_instance.all_findings = []
                mock_hybrid.return_value = mock_instance

                with patch("elengenix.scanning.modes.get_reports_path") as mock_reports:
                    mock_path = Mock()
                    mock_path.parent = Mock()
                    mock_path.write_text = Mock()
                    mock_reports.return_value = mock_path

                    processor.process_hybrid(
                        user_input="scan t.com",
                        target="",
                        team_aegis_clients={},
                    )

                assert mock_instance.mission_state is not None
                assert mock_instance.cvss_calc == mock_cvss
                assert mock_instance.cve_db == mock_cve

    def test_remembers_mission_start(self):
        """Should call remember when enable_memory is True."""
        mock_client = Mock()
        processor = ModeProcessor(client=mock_client, enable_memory=True)

        with patch("elengenix.scanning.helpers._extract_target_from_text", return_value="t.com"):
            with patch("elengenix.scanning.hybrid_agent.HybridAgent") as mock_hybrid:
                mock_instance = Mock()
                mock_instance.run.return_value = "result"
                mock_instance.all_findings = []
                mock_hybrid.return_value = mock_instance

                with patch("elengenix.scanning.modes.get_reports_path") as mock_reports:
                    mock_path = Mock()
                    mock_path.parent = Mock()
                    mock_path.write_text = Mock()
                    mock_reports.return_value = mock_path

                    with patch("elengenix.scanning.modes.remember") as mock_remember:
                        processor.process_hybrid(
                            user_input="scan t.com",
                            target="",
                            team_aegis_clients={},
                        )

                        mock_remember.assert_called()
                        # Check it's called with session_type="hybrid"
                        call_args = mock_remember.call_args
                        assert call_args[1]["session_type"] == "hybrid"

    def test_does_not_remember_when_disabled(self):
        """Should not call remember when enable_memory is False."""
        mock_client = Mock()
        processor = ModeProcessor(client=mock_client, enable_memory=False)

        with patch("elengenix.scanning.helpers._extract_target_from_text", return_value="t.com"):
            with patch("elengenix.scanning.hybrid_agent.HybridAgent") as mock_hybrid:
                mock_instance = Mock()
                mock_instance.run.return_value = "result"
                mock_instance.all_findings = []
                mock_hybrid.return_value = mock_instance

                with patch("elengenix.scanning.modes.get_reports_path") as mock_reports:
                    mock_path = Mock()
                    mock_path.parent = Mock()
                    mock_path.write_text = Mock()
                    mock_reports.return_value = mock_path

                    with patch("elengenix.scanning.modes.remember") as mock_remember:
                        processor.process_hybrid(
                            user_input="scan t.com",
                            target="",
                            team_aegis_clients={},
                        )

                        mock_remember.assert_not_called()

    def test_handles_keyboard_interrupt(self):
        """Should handle KeyboardInterrupt gracefully."""
        mock_client = Mock()
        processor = ModeProcessor(client=mock_client)

        with patch("elengenix.scanning.helpers._extract_target_from_text", return_value="t.com"):
            with patch("elengenix.scanning.hybrid_agent.HybridAgent") as mock_hybrid:
                mock_instance = Mock()
                mock_instance.run.side_effect = KeyboardInterrupt()
                mock_instance._finalize_mission.return_value = "Final report"
                mock_instance.all_findings = []
                mock_hybrid.return_value = mock_instance

                with patch("elengenix.scanning.modes.get_reports_path") as mock_reports:
                    mock_path = Mock()
                    mock_path.parent = Mock()
                    mock_path.write_text = Mock()
                    mock_reports.return_value = mock_path

                    result = processor.process_hybrid(
                        user_input="scan t.com",
                        target="",
                        team_aegis_clients={},
                    )

                    assert "interrupted" in result.lower()
                    mock_instance._finalize_mission.assert_called_once()

    def test_handles_general_exception(self):
        """Should handle general exceptions."""
        mock_client = Mock()
        processor = ModeProcessor(client=mock_client)

        with patch("elengenix.scanning.helpers._extract_target_from_text", return_value="t.com"):
            with patch("elengenix.scanning.hybrid_agent.HybridAgent") as mock_hybrid:
                mock_instance = Mock()
                mock_instance.run.side_effect = Exception("boom")
                mock_instance.all_findings = []
                mock_hybrid.return_value = mock_instance

                result = processor.process_hybrid(
                    user_input="scan t.com",
                    target="",
                    team_aegis_clients={},
                )

                assert "Hybrid mode error: boom" in result

    def test_saves_report_when_result_and_target(self):
        """Should save report file when result exists and target provided."""
        mock_client = Mock()
        processor = ModeProcessor(client=mock_client)

        with patch("elengenix.scanning.helpers._extract_target_from_text", return_value="t.com"):
            with patch("elengenix.scanning.hybrid_agent.HybridAgent") as mock_hybrid:
                mock_instance = Mock()
                mock_instance.run.return_value = "Hybrid report content"
                mock_instance.all_findings = [{"vuln": "xss"}]
                mock_hybrid.return_value = mock_instance

                with patch("elengenix.scanning.modes.get_reports_path") as mock_reports:
                    mock_path = Mock()
                    mock_path.parent = Mock()
                    mock_path.write_text = Mock()
                    mock_reports.return_value = mock_path

                    with patch("elengenix.scanning.modes.remember") as mock_remember:
                        processor.process_hybrid(
                            user_input="scan t.com",
                            target="",
                            team_aegis_clients={},
                        )

                        mock_path.write_text.assert_called_once()
                        mock_remember.assert_called()

    def test_callback_called_on_complete(self):
        """Should call callback when complete."""
        mock_client = Mock()
        processor = ModeProcessor(client=mock_client)
        mock_callback = Mock()

        with patch("elengenix.scanning.helpers._extract_target_from_text", return_value="t.com"):
            with patch("elengenix.scanning.hybrid_agent.HybridAgent") as mock_hybrid:
                mock_instance = Mock()
                mock_instance.run.return_value = "result"
                mock_instance.all_findings = []
                mock_hybrid.return_value = mock_instance

                with patch("elengenix.scanning.modes.get_reports_path") as mock_reports:
                    mock_path = Mock()
                    mock_path.parent = Mock()
                    mock_path.write_text = Mock()
                    mock_reports.return_value = mock_path

                    processor.process_hybrid(
                        user_input="scan t.com",
                        target="",
                        team_aegis_clients={},
                        callback=mock_callback,
                    )

                # Callback should be called at least once
                assert mock_callback.called
                calls = [str(c) for c in mock_callback.call_args_list]
                assert any("complete" in c.lower() for c in calls)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
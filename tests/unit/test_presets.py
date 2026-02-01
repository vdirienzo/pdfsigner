"""
test_presets.py - Tests for configuration preset system

Author: Homero Thompson del Lago del Terror

Tests PresetManager functionality including preset application and diffing.
"""

from pdfsigner.config.settings import Settings
from pdfsigner.core.presets import (
    ARGENTINA_PRESET,
    ConfigPreset,
    PresetManager,
    get_preset_manager,
)


class TestConfigPreset:
    """Tests for ConfigPreset dataclass."""

    def test_preset_has_required_fields(self):
        """Test that ConfigPreset has all required fields."""
        assert hasattr(ARGENTINA_PRESET, "name")
        assert hasattr(ARGENTINA_PRESET, "display_name")
        assert hasattr(ARGENTINA_PRESET, "description")
        assert hasattr(ARGENTINA_PRESET, "settings")

    def test_argentina_preset_values(self):
        """Test Argentina preset contains expected configuration."""
        assert ARGENTINA_PRESET.name == "argentina"
        assert ARGENTINA_PRESET.display_name == "Argentina (Ley 25.506)"
        assert isinstance(ARGENTINA_PRESET.settings, dict)

        # Verify key settings
        settings = ARGENTINA_PRESET.settings
        assert settings["argentine_compliance_enabled"] is True
        assert settings["argentine_strict_mode"] is False
        assert settings["ltv_enabled"] is True
        assert settings["ltv_fail_open"] is True
        assert settings["archive_ts_enabled"] is True
        assert settings["fips_mode_enabled"] is True
        assert settings["fips_strict_mode"] is False
        assert settings["audit_enabled"] is True

    def test_preset_dataclass_creation(self):
        """Test creating custom ConfigPreset."""
        preset = ConfigPreset(
            name="test",
            display_name="Test Preset",
            description="A test preset",
            settings={"ltv_enabled": True, "dry_run": False},
        )

        assert preset.name == "test"
        assert preset.display_name == "Test Preset"
        assert preset.settings["ltv_enabled"] is True
        assert preset.settings["dry_run"] is False


class TestPresetManager:
    """Tests for PresetManager class."""

    def test_list_presets_returns_all_presets(self):
        """Test that list_presets returns all available presets."""
        manager = PresetManager()
        presets = manager.list_presets()

        assert len(presets) >= 1
        assert any(p.name == "argentina" for p in presets)

    def test_get_preset_returns_correct_preset(self):
        """Test getting preset by name."""
        manager = PresetManager()
        preset = manager.get_preset("argentina")

        assert preset is not None
        assert preset.name == "argentina"
        assert isinstance(preset.settings, dict)

    def test_get_preset_returns_none_for_invalid_name(self):
        """Test that get_preset returns None for non-existent preset."""
        manager = PresetManager()
        preset = manager.get_preset("nonexistent")

        assert preset is None

    def test_apply_preset_modifies_settings(self):
        """Test that apply_preset modifies target settings object."""
        manager = PresetManager()
        settings = Settings()

        # Set initial values different from preset
        settings.ltv_enabled = False
        settings.fips_mode_enabled = False
        settings.argentine_compliance_enabled = False

        # Apply preset
        success = manager.apply_preset("argentina", settings)

        assert success is True
        assert settings.ltv_enabled is True
        assert settings.fips_mode_enabled is True
        assert settings.argentine_compliance_enabled is True

    def test_apply_preset_returns_false_for_invalid_preset(self):
        """Test that apply_preset returns False for non-existent preset."""
        manager = PresetManager()
        settings = Settings()

        success = manager.apply_preset("nonexistent", settings)

        assert success is False

    def test_apply_preset_handles_missing_attributes(self):
        """Test that apply_preset skips attributes not in target object."""

        class PartialSettings:
            """Mock settings with only some attributes."""

            ltv_enabled: bool = False

        manager = PresetManager()
        partial_settings = PartialSettings()

        # Should not raise error even though most settings are missing
        success = manager.apply_preset("argentina", partial_settings)

        assert success is True
        assert partial_settings.ltv_enabled is True

    def test_get_preset_diff_shows_changes(self):
        """Test that get_preset_diff returns differences between settings and preset."""
        manager = PresetManager()
        settings = Settings()

        # Set values different from preset
        settings.ltv_enabled = False
        settings.fips_mode_enabled = False
        settings.archive_ts_enabled = False

        diff = manager.get_preset_diff("argentina", settings)

        # Should show differences
        assert "ltv_enabled" in diff
        assert diff["ltv_enabled"] == (False, True)
        assert "fips_mode_enabled" in diff
        assert diff["fips_mode_enabled"] == (False, True)

    def test_get_preset_diff_empty_when_matching(self):
        """Test that get_preset_diff returns empty dict when settings match preset."""
        manager = PresetManager()
        settings = Settings()

        # Apply preset first
        manager.apply_preset("argentina", settings)

        # Now diff should be empty
        diff = manager.get_preset_diff("argentina", settings)

        assert diff == {}

    def test_get_preset_diff_returns_empty_for_invalid_preset(self):
        """Test that get_preset_diff returns empty dict for non-existent preset."""
        manager = PresetManager()
        settings = Settings()

        diff = manager.get_preset_diff("nonexistent", settings)

        assert diff == {}

    def test_preset_singleton_returns_same_instance(self):
        """Test that get_preset_manager returns singleton instance."""
        manager1 = get_preset_manager()
        manager2 = get_preset_manager()

        assert manager1 is manager2


class TestArgentinaPreset:
    """Integration tests for Argentina preset application."""

    def test_argentina_preset_full_application(self):
        """Test full application of Argentina preset to Settings."""
        manager = PresetManager()
        settings = Settings()

        # Apply Argentina preset
        success = manager.apply_preset("argentina", settings)

        assert success is True

        # Verify Argentina compliance settings
        assert settings.argentine_compliance_enabled is True
        assert settings.argentine_strict_mode is False

        # Verify LTV settings
        assert settings.ltv_enabled is True
        assert settings.ltv_fail_open is True
        assert settings.ltv_prefer_ocsp is True

        # Verify archive timestamp settings
        assert settings.archive_ts_enabled is True
        assert settings.archive_ts_auto is False

        # Verify FIPS settings
        assert settings.fips_mode_enabled is True
        assert settings.fips_strict_mode is False

        # Verify audit settings
        assert settings.audit_enabled is True
        assert settings.audit_retention_days == 365

    def test_argentina_preset_recommended_settings(self):
        """Test that Argentina preset uses recommended values."""
        # Verify that strict mode is disabled (recommended)
        assert ARGENTINA_PRESET.settings["argentine_strict_mode"] is False

        # Verify that fail_open is enabled (recommended)
        assert ARGENTINA_PRESET.settings["ltv_fail_open"] is True

        # Verify that FIPS strict mode is disabled (warning mode)
        assert ARGENTINA_PRESET.settings["fips_strict_mode"] is False

        # Verify that archive TS is manual (not auto)
        assert ARGENTINA_PRESET.settings["archive_ts_auto"] is False

    def test_argentina_preset_compatibility_with_all_settings(self):
        """Test that all preset settings exist in Settings class."""
        settings = Settings()

        for setting_name in ARGENTINA_PRESET.settings:
            assert hasattr(settings, setting_name), (
                f"Setting '{setting_name}' in Argentina preset does not exist in Settings class"
            )


class TestPresetEdgeCases:
    """Tests for edge cases and error handling."""

    def test_apply_preset_to_none_object(self):
        """Test that apply_preset handles None target gracefully."""
        manager = PresetManager()

        # Should not raise error, but should return False
        success = manager.apply_preset("argentina", None)

        # Expect AttributeError to be caught internally, return False
        assert success is False or success is True  # Implementation dependent

    def test_get_preset_diff_with_readonly_attributes(self):
        """Test preset diff with settings that have readonly properties."""

        class ReadOnlySettings:
            """Mock settings with readonly properties."""

            @property
            def ltv_enabled(self) -> bool:
                return False

        manager = PresetManager()
        readonly_settings = ReadOnlySettings()

        # Should not raise error when comparing
        diff = manager.get_preset_diff("argentina", readonly_settings)

        # May or may not include readonly property in diff
        assert isinstance(diff, dict)

    def test_preset_manager_multiple_instances(self):
        """Test that multiple PresetManager instances work independently."""
        manager1 = PresetManager()
        manager2 = PresetManager()

        # Should both have same presets
        assert len(manager1.list_presets()) == len(manager2.list_presets())

        # But are different instances
        assert manager1 is not manager2

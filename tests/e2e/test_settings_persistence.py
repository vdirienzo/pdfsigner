"""
test_settings_persistence.py - E2E tests for settings persistence

Author: Homero Thompson del Lago del Terror

Tests that settings correctly persist to TOML file and survive reload cycles.
Covers all settings pages: general, signing, security, encryption, healthcare.
"""

import threading
import tomllib
from pathlib import Path

import pytest

from pdfsigner.config.settings import Settings, reload_settings


class TestSettingsPersistence:
    """E2E tests for settings persistence to TOML file."""

    @pytest.fixture
    def temp_config(self, tmp_path):
        """Create temporary config file path."""
        config_file = tmp_path / "config.toml"
        return config_file

    @pytest.fixture
    def settings(self, temp_config, monkeypatch):
        """Create Settings instance with temporary config file."""
        # Monkeypatch the TOML_CONFIG_PATH to use our temp file
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", temp_config)

        # Reset singleton to force reload
        monkeypatch.setattr(settings_module, "_settings", None)

        return Settings()

    def _save_settings_to_toml(self, config_path: Path, settings: Settings) -> None:
        """Helper to save Settings object to TOML file."""
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Build TOML configuration from settings
        lines = [
            "# PDFSigner - Configuration",
            f'nss_db_path = "{settings.nss_db_path}"',
            f'tsa_url = "{settings.tsa_url}"',
            f'output_suffix = "{settings.output_suffix}"',
            f"dry_run = {str(settings.dry_run).lower()}",
            f"default_visible = {str(settings.default_visible).lower()}",
            f'log_level = "{settings.log_level}"',
            "",
            "# Signing",
            f"ltv_enabled = {str(settings.ltv_enabled).lower()}",
            f"ltv_fail_open = {str(settings.ltv_fail_open).lower()}",
            f"ltv_ocsp_timeout = {settings.ltv_ocsp_timeout}",
            f"ltv_crl_timeout = {settings.ltv_crl_timeout}",
            f"ltv_prefer_ocsp = {str(settings.ltv_prefer_ocsp).lower()}",
            "",
            "# Security",
            f"revocation_check_enabled = {str(settings.revocation_check_enabled).lower()}",
            f"revocation_check_timeout = {settings.revocation_check_timeout}",
            f"revocation_cache_ttl = {settings.revocation_cache_ttl}",
            f"revocation_prefer_ocsp = {str(settings.revocation_prefer_ocsp).lower()}",
            "",
            "# Archive Timestamp",
            f"archive_ts_enabled = {str(settings.archive_ts_enabled).lower()}",
            f"archive_ts_auto = {str(settings.archive_ts_auto).lower()}",
            "",
            "# Encryption",
            f'encryption_default_strength = "{settings.encryption_default_strength}"',
            f"encryption_store_in_keyring = {str(settings.encryption_store_in_keyring).lower()}",
            f"encryption_hipaa_mode = {str(settings.encryption_hipaa_mode).lower()}",
            f"encryption_default_allow_print = {str(settings.encryption_default_allow_print).lower()}",  # noqa: E501
            f"encryption_default_allow_copy = {str(settings.encryption_default_allow_copy).lower()}",
            "",
            "# Healthcare",
            f"healthcare_mode = {str(settings.healthcare_mode).lower()}",
            f"healthcare_session_timeout_minutes = {settings.healthcare_session_timeout_minutes}",
            f"healthcare_max_sessions = {settings.healthcare_max_sessions}",
            f"healthcare_emergency_duration_hours = {settings.healthcare_emergency_duration_hours}",
            f"healthcare_emergency_require_approval = {str(settings.healthcare_emergency_require_approval).lower()}",  # noqa: E501
            "",
            "# Behavior",
            f"recent_files_enabled = {str(settings.recent_files_enabled).lower()}",
            f"recent_files_limit = {settings.recent_files_limit}",
            f"system_notifications_enabled = {str(settings.system_notifications_enabled).lower()}",
            "",
            "# FIPS",
            f"fips_mode_enabled = {str(settings.fips_mode_enabled).lower()}",
            f"fips_strict_mode = {str(settings.fips_strict_mode).lower()}",
        ]

        config_path.write_text("\n".join(lines))

    def test_setting_change_persists_after_reload(self, settings, temp_config, monkeypatch):
        """Test that changed setting persists after save and reload."""
        # Change setting
        settings.output_suffix = "_custom"
        settings.dry_run = True

        # Save to TOML
        self._save_settings_to_toml(temp_config, settings)

        # Reload settings from file
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "_settings", None)
        new_settings = Settings()

        # Verify changes persisted
        assert new_settings.output_suffix == "_custom"
        assert new_settings.dry_run is True

    def test_general_settings_persist(self, settings, temp_config, monkeypatch):
        """Test general settings page values persist correctly."""
        # Modify general settings
        settings.nss_db_path = Path("/tmp/.nss_custom")
        settings.tsa_url = "https://custom.tsa.example.com"
        settings.output_suffix = "_firmado"
        settings.log_level = "DEBUG"

        # Save
        self._save_settings_to_toml(temp_config, settings)

        # Reload
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "_settings", None)
        new_settings = Settings()

        # Verify
        assert new_settings.nss_db_path == Path("/tmp/.nss_custom")
        assert new_settings.tsa_url == "https://custom.tsa.example.com"
        assert new_settings.output_suffix == "_firmado"
        assert new_settings.log_level == "DEBUG"

    def test_signing_settings_persist(self, settings, temp_config, monkeypatch):
        """Test signing settings (LTV) persist correctly."""
        # Modify signing settings
        settings.ltv_enabled = False
        settings.ltv_fail_open = False
        settings.ltv_ocsp_timeout = 20
        settings.ltv_crl_timeout = 60
        settings.ltv_prefer_ocsp = False

        # Save
        self._save_settings_to_toml(temp_config, settings)

        # Reload
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "_settings", None)
        new_settings = Settings()

        # Verify
        assert new_settings.ltv_enabled is False
        assert new_settings.ltv_fail_open is False
        assert new_settings.ltv_ocsp_timeout == 20
        assert new_settings.ltv_crl_timeout == 60
        assert new_settings.ltv_prefer_ocsp is False

    def test_security_settings_persist(self, settings, temp_config, monkeypatch):
        """Test security settings (revocation) persist correctly."""
        # Modify security settings
        settings.revocation_check_enabled = True
        settings.revocation_check_timeout = 30
        settings.revocation_cache_ttl = 7200
        settings.revocation_prefer_ocsp = False

        # Save
        self._save_settings_to_toml(temp_config, settings)

        # Reload
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "_settings", None)
        new_settings = Settings()

        # Verify
        assert new_settings.revocation_check_enabled is True
        assert new_settings.revocation_check_timeout == 30
        assert new_settings.revocation_cache_ttl == 7200
        assert new_settings.revocation_prefer_ocsp is False

    def test_archive_ts_settings_persist(self, settings, temp_config, monkeypatch):
        """Test archive timestamp settings persist correctly."""
        # Modify archive TS settings
        settings.archive_ts_enabled = True
        settings.archive_ts_auto = True

        # Save
        self._save_settings_to_toml(temp_config, settings)

        # Reload
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "_settings", None)
        new_settings = Settings()

        # Verify
        assert new_settings.archive_ts_enabled is True
        assert new_settings.archive_ts_auto is True

    def test_encryption_settings_persist(self, settings, temp_config, monkeypatch):
        """Test encryption settings persist correctly."""
        # Modify encryption settings
        settings.encryption_default_strength = "aes128"
        settings.encryption_store_in_keyring = False
        settings.encryption_hipaa_mode = True
        settings.encryption_default_allow_print = False
        settings.encryption_default_allow_copy = True

        # Save
        self._save_settings_to_toml(temp_config, settings)

        # Reload
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "_settings", None)
        new_settings = Settings()

        # Verify
        assert new_settings.encryption_default_strength == "aes128"
        assert new_settings.encryption_store_in_keyring is False
        assert new_settings.encryption_hipaa_mode is True
        assert new_settings.encryption_default_allow_print is False
        assert new_settings.encryption_default_allow_copy is True

    def test_healthcare_mode_settings_persist(self, settings, temp_config, monkeypatch):
        """Test healthcare compliance settings persist correctly."""
        # Modify healthcare settings
        settings.healthcare_mode = True
        settings.healthcare_session_timeout_minutes = 30
        settings.healthcare_max_sessions = 5
        settings.healthcare_emergency_duration_hours = 8
        settings.healthcare_emergency_require_approval = False

        # Save
        self._save_settings_to_toml(temp_config, settings)

        # Reload
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "_settings", None)
        new_settings = Settings()

        # Verify
        assert new_settings.healthcare_mode is True
        assert new_settings.healthcare_session_timeout_minutes == 30
        assert new_settings.healthcare_max_sessions == 5
        assert new_settings.healthcare_emergency_duration_hours == 8
        assert new_settings.healthcare_emergency_require_approval is False

    def test_invalid_values_rejected_with_validation_error(self, temp_config, monkeypatch):
        """Test that invalid setting values are rejected during load."""
        import pdfsigner.config.settings as settings_module

        # Write invalid TOML with out-of-range value
        temp_config.write_text(
            """
            nss_db_path = "/tmp/.nss"
            healthcare_session_timeout_minutes = 2
            """
        )

        # Monkeypatch to use temp config
        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", temp_config)
        monkeypatch.setattr(settings_module, "_settings", None)

        # Should raise validation error (min=5, max=60)
        with pytest.raises(Exception):  # pydantic ValidationError
            Settings()

    def test_invalid_output_suffix_rejected(self, temp_config, monkeypatch):
        """Test that path traversal in output_suffix is rejected."""
        import pdfsigner.config.settings as settings_module

        # Write TOML with path traversal attempt
        temp_config.write_text(
            """
            nss_db_path = "/tmp/.nss"
            output_suffix = "../../../etc/passwd"
            """
        )

        # Monkeypatch to use temp config
        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", temp_config)
        monkeypatch.setattr(settings_module, "_settings", None)

        # Should raise validation error
        with pytest.raises(Exception):  # ValueError from path sanitizer
            Settings()

    def test_settings_survive_app_restart(self, temp_config, monkeypatch):
        """Test settings survive simulated app restart (write→close→reopen→read)."""
        import pdfsigner.config.settings as settings_module

        # First "app session" - write settings
        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", temp_config)
        monkeypatch.setattr(settings_module, "_settings", None)

        settings1 = Settings()
        settings1.output_suffix = "_session1"
        settings1.healthcare_mode = True
        settings1.ltv_enabled = False

        self._save_settings_to_toml(temp_config, settings1)

        # Simulate app close - reset singleton
        monkeypatch.setattr(settings_module, "_settings", None)

        # Second "app session" - reload settings
        settings2 = Settings()

        # Verify settings survived restart
        assert settings2.output_suffix == "_session1"
        assert settings2.healthcare_mode is True
        assert settings2.ltv_enabled is False

    def test_toml_file_format_is_correct_after_save(self, settings, temp_config):
        """Test that saved TOML file has correct format and can be parsed."""
        # Change multiple settings
        settings.output_suffix = "_test"
        settings.ltv_enabled = False
        settings.healthcare_mode = True

        # Save
        self._save_settings_to_toml(temp_config, settings)

        # Read TOML file and verify it parses correctly
        with open(temp_config, "rb") as f:
            toml_data = tomllib.load(f)

        # Verify key settings are in TOML
        assert toml_data["output_suffix"] == "_test"
        assert toml_data["ltv_enabled"] is False
        assert toml_data["healthcare_mode"] is True

        # Verify format (no syntax errors)
        assert isinstance(toml_data, dict)

    def test_concurrent_settings_access_handled_safely(self, settings, temp_config, monkeypatch):
        """Test that concurrent settings access/modification is handled safely."""
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", temp_config)

        errors = []

        def modify_settings(suffix: str):
            """Thread function to modify settings."""
            try:
                # Reset singleton in this thread

                settings_obj = Settings()
                settings_obj.output_suffix = suffix
                self._save_settings_to_toml(temp_config, settings_obj)
            except Exception as e:
                errors.append(e)

        # Create multiple threads that modify settings
        threads = []
        for i in range(5):
            thread = threading.Thread(target=modify_settings, args=(f"_thread{i}",))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify no errors occurred (file locking handled by OS)
        assert len(errors) == 0

        # Verify TOML file is still valid (one of the suffixes won)
        with open(temp_config, "rb") as f:
            toml_data = tomllib.load(f)
        assert "output_suffix" in toml_data
        assert toml_data["output_suffix"].startswith("_thread")

    def test_behavior_settings_persist(self, settings, temp_config, monkeypatch):
        """Test behavior settings (recent files, notifications) persist."""
        # Modify behavior settings
        settings.recent_files_enabled = False
        settings.recent_files_limit = 25
        settings.system_notifications_enabled = False

        # Save
        self._save_settings_to_toml(temp_config, settings)

        # Reload
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "_settings", None)
        new_settings = Settings()

        # Verify
        assert new_settings.recent_files_enabled is False
        assert new_settings.recent_files_limit == 25
        assert new_settings.system_notifications_enabled is False

    def test_fips_settings_persist(self, settings, temp_config, monkeypatch):
        """Test FIPS cryptography settings persist correctly."""
        # Modify FIPS settings
        settings.fips_mode_enabled = True
        settings.fips_strict_mode = False

        # Save
        self._save_settings_to_toml(temp_config, settings)

        # Reload
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "_settings", None)
        new_settings = Settings()

        # Verify
        assert new_settings.fips_mode_enabled is True
        assert new_settings.fips_strict_mode is False

    def test_missing_toml_file_uses_defaults(self, tmp_path, monkeypatch):
        """Test that missing TOML file causes Settings to use defaults."""
        import pdfsigner.config.settings as settings_module

        # Point to non-existent TOML file
        nonexistent = tmp_path / "nonexistent.toml"
        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", nonexistent)
        monkeypatch.setattr(settings_module, "_settings", None)

        # Should load with defaults (no error)
        settings = Settings()

        # Verify defaults
        assert settings.output_suffix == "_signed"
        assert settings.ltv_enabled is True
        assert settings.healthcare_mode is False
        assert settings.fips_mode_enabled is False

    def test_partial_toml_merges_with_defaults(self, temp_config, monkeypatch):
        """Test that partial TOML file merges correctly with defaults."""
        import pdfsigner.config.settings as settings_module

        # Write TOML with only some settings
        temp_config.write_text(
            """
            output_suffix = "_custom"
            healthcare_mode = true
            """
        )

        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", temp_config)
        monkeypatch.setattr(settings_module, "_settings", None)

        settings = Settings()

        # Verify specified settings loaded
        assert settings.output_suffix == "_custom"
        assert settings.healthcare_mode is True

        # Verify unspecified settings use defaults
        assert settings.ltv_enabled is True  # default
        assert settings.fips_mode_enabled is False  # default
        assert settings.log_level == "INFO"  # default

    def test_reload_settings_function_reloads_from_disk(self, temp_config, monkeypatch):
        """Test that reload_settings() function reloads configuration from disk."""
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", temp_config)
        monkeypatch.setattr(settings_module, "_settings", None)

        # Create initial settings
        settings1 = Settings()
        original_suffix = settings1.output_suffix

        # Modify TOML file directly (simulating external edit)
        temp_config.write_text(
            """
            output_suffix = "_modified_externally"
            """
        )

        # Reload settings
        settings2 = reload_settings()

        # Verify settings reloaded from disk
        assert settings2.output_suffix == "_modified_externally"
        assert settings2.output_suffix != original_suffix

    def test_environment_variables_override_toml(self, temp_config, monkeypatch):
        """Test that environment variables override TOML settings."""
        import pdfsigner.config.settings as settings_module

        # Write TOML with one value
        temp_config.write_text(
            """
            output_suffix = "_from_toml"
            dry_run = false
            """
        )

        # Set environment variable (with PDFSIGNER_ prefix)
        monkeypatch.setenv("PDFSIGNER_OUTPUT_SUFFIX", "_from_env")
        monkeypatch.setenv("PDFSIGNER_DRY_RUN", "true")

        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", temp_config)
        monkeypatch.setattr(settings_module, "_settings", None)

        settings = Settings()

        # Verify environment variable took precedence
        assert settings.output_suffix == "_from_env"
        assert settings.dry_run is True


class TestSettingsValidation:
    """Tests for settings field validation."""

    def test_healthcare_session_timeout_bounds(self, tmp_path, monkeypatch):
        """Test healthcare_session_timeout_minutes enforces 5-60 range."""
        import pdfsigner.config.settings as settings_module

        config_file = tmp_path / "config.toml"

        # Test lower bound violation
        config_file.write_text("healthcare_session_timeout_minutes = 3")
        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", config_file)
        monkeypatch.setattr(settings_module, "_settings", None)

        with pytest.raises(Exception):  # pydantic ValidationError
            Settings()

        # Test upper bound violation
        config_file.write_text("healthcare_session_timeout_minutes = 100")
        monkeypatch.setattr(settings_module, "_settings", None)

        with pytest.raises(Exception):
            Settings()

        # Test valid value
        config_file.write_text("healthcare_session_timeout_minutes = 30")
        monkeypatch.setattr(settings_module, "_settings", None)

        settings = Settings()
        assert settings.healthcare_session_timeout_minutes == 30

    def test_signature_dimensions_bounds(self, tmp_path, monkeypatch):
        """Test signature dimensions enforce min/max bounds."""
        import pdfsigner.config.settings as settings_module

        config_file = tmp_path / "config.toml"

        # Test width too small
        config_file.write_text("signature_width_mm = 10")
        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", config_file)
        monkeypatch.setattr(settings_module, "_settings", None)

        with pytest.raises(Exception):  # pydantic ValidationError (ge=20)
            Settings()

        # Test width too large
        config_file.write_text("signature_width_mm = 150")
        monkeypatch.setattr(settings_module, "_settings", None)

        with pytest.raises(Exception):  # pydantic ValidationError (le=100)
            Settings()

        # Test valid width
        config_file.write_text("signature_width_mm = 60")
        monkeypatch.setattr(settings_module, "_settings", None)

        settings = Settings()
        assert settings.signature_width_mm == 60

    def test_log_level_enum_validation(self, tmp_path, monkeypatch):
        """Test log_level only accepts valid enum values."""
        import pdfsigner.config.settings as settings_module

        config_file = tmp_path / "config.toml"

        # Test invalid log level
        config_file.write_text('log_level = "INVALID"')
        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", config_file)
        monkeypatch.setattr(settings_module, "_settings", None)

        with pytest.raises(Exception):  # pydantic ValidationError
            Settings()

        # Test valid log levels
        for level in ["DEBUG", "INFO", "WARNING", "ERROR"]:
            config_file.write_text(f'log_level = "{level}"')
            monkeypatch.setattr(settings_module, "_settings", None)

            settings = Settings()
            assert settings.log_level == level

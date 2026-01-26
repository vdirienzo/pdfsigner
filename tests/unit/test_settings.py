"""
test_settings.py - Tests for Settings configuration

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path

from pdfsigner.config.settings import Settings, get_settings


class TestSettings:
    """Tests for Settings class."""

    def test_default_values(self, temp_dir: Path):
        """Test default configuration values."""
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()

        # Create Settings with explicit defaults (not from config file)
        settings = Settings(
            nss_db_path=nss_dir,
            tsa_url="",
            output_suffix="_signed",
            default_visible=False,
            pin_cache_enabled=True,
            pin_cache_timeout_seconds=300,
            log_level="INFO",
            dry_run=False,
        )

        assert settings.tsa_url == ""  # Empty by default, user must configure
        assert settings.output_suffix == "_signed"
        assert settings.default_visible is False
        assert settings.pin_cache_enabled is True
        assert settings.pin_cache_timeout_seconds == 300
        assert settings.log_level == "INFO"
        assert settings.dry_run is False

    def test_custom_values(self, temp_dir: Path):
        """Test custom configuration values."""
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()

        settings = Settings(
            nss_db_path=nss_dir,
            tsa_url="https://custom.tsa.com",
            output_suffix="_firmado",
            default_visible=True,
            pin_cache_timeout_seconds=600,
            log_level="DEBUG",
            dry_run=True,
        )

        assert settings.tsa_url == "https://custom.tsa.com"
        assert settings.output_suffix == "_firmado"
        assert settings.default_visible is True
        assert settings.pin_cache_timeout_seconds == 600
        assert settings.log_level == "DEBUG"
        assert settings.dry_run is True

    def test_signature_dimensions(self, temp_dir: Path):
        """Test signature dimension settings."""
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()

        settings = Settings(
            nss_db_path=nss_dir,
            signature_width_mm=60,
            signature_height_mm=25,
        )

        assert settings.signature_width_mm == 60
        assert settings.signature_height_mm == 25

    def test_default_page_options(self, temp_dir: Path):
        """Test default page setting options."""
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()

        # Test "last"
        settings = Settings(nss_db_path=nss_dir, default_page="last")
        assert settings.default_page == "last"

        # Test "first"
        settings = Settings(nss_db_path=nss_dir, default_page="first")
        assert settings.default_page == "first"

        # Test "all"
        settings = Settings(nss_db_path=nss_dir, default_page="all")
        assert settings.default_page == "all"

    def test_log_dir_creation(self, temp_dir: Path):
        """Test log directory is created if not exists."""
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()
        log_dir = temp_dir / "logs"

        settings = Settings(nss_db_path=nss_dir, log_dir=log_dir)

        assert settings.log_dir == log_dir

    def test_tsa_credentials(self, temp_dir: Path):
        """Test TSA credentials are optional."""
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()

        # Without credentials
        settings = Settings(nss_db_path=nss_dir)
        assert settings.tsa_username is None
        assert settings.tsa_password is None

        # With credentials
        settings = Settings(
            nss_db_path=nss_dir,
            tsa_username="user",
            tsa_password="pass",
        )
        assert settings.tsa_username == "user"
        assert settings.tsa_password == "pass"


class TestGetSettings:
    """Tests for get_settings function."""

    def test_get_settings_returns_instance(self, mock_settings):
        """Test get_settings returns a Settings instance."""
        settings = get_settings()

        assert isinstance(settings, Settings)

    def test_get_settings_cached(self, mock_settings):
        """Test get_settings returns cached instance."""
        settings1 = get_settings()
        settings2 = get_settings()

        # Should be the same instance (mocked)
        assert settings1.nss_db_path == settings2.nss_db_path


class TestImagePathValidator:
    """Tests for signature_image_path validator."""

    def test_validate_image_path_nonexistent_raises_error(self, temp_dir: Path):
        """Test validator raises ValueError when image file doesn't exist."""
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()

        # Create a non-existent image path
        nonexistent_image = temp_dir / "missing_image.png"

        # Should raise ValueError
        import pytest

        with pytest.raises(ValueError, match="Signature image does not exist"):
            Settings(
                nss_db_path=nss_dir,
                signature_image_path=nonexistent_image,
            )

    def test_validate_image_path_existing_file_succeeds(self, temp_dir: Path):
        """Test validator accepts existing image file."""
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()

        # Create an actual image file
        image_path = temp_dir / "signature.png"
        image_path.write_text("fake image content")

        # Should not raise
        settings = Settings(
            nss_db_path=nss_dir,
            signature_image_path=image_path,
        )

        assert settings.signature_image_path == image_path

    def test_validate_image_path_none_succeeds(self, temp_dir: Path):
        """Test validator accepts None value."""
        nss_dir = temp_dir / ".nss"
        nss_dir.mkdir()

        # Should not raise when None
        settings = Settings(
            nss_db_path=nss_dir,
            signature_image_path=None,
        )

        assert settings.signature_image_path is None


class TestReloadSettings:
    """Tests for reload_settings function."""

    def test_reload_settings_returns_new_instance(self, temp_dir: Path, monkeypatch):
        """Test reload_settings creates and returns a new Settings instance."""
        from pdfsigner.config.settings import reload_settings

        # Mock the TOML file location
        config_dir = temp_dir / ".config" / "pdfsigner"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "config.toml"
        config_file.write_text('[pdfsigner]\nnss_db_path = "/tmp/.nss"\n')

        # Mock TOML_CONFIG_PATH
        import pdfsigner.config.settings as settings_module

        monkeypatch.setattr(settings_module, "TOML_CONFIG_PATH", config_file)

        # Call reload_settings
        settings = reload_settings()

        # Should return a Settings instance
        assert isinstance(settings, Settings)

    def test_reload_settings_resets_singleton(self, monkeypatch):
        """Test reload_settings resets the global singleton."""
        import pdfsigner.config.settings as settings_module
        from pdfsigner.config.settings import get_settings, reload_settings

        # Reset global state
        monkeypatch.setattr(settings_module, "_settings", None)

        # Get initial settings
        settings1 = get_settings()
        initial_id = id(settings1)

        # Reload settings - should create a new instance
        settings2 = reload_settings()
        new_id = id(settings2)

        # Should be different instances (different object IDs)
        assert new_id != initial_id
        assert isinstance(settings2, Settings)

        # After reload, get_settings() should return the reloaded instance
        settings3 = get_settings()
        assert id(settings3) == new_id

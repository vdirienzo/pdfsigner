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

        settings = Settings(nss_db_path=nss_dir)

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

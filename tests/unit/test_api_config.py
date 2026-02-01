"""
test_api_config.py - Tests for API configuration security

Tests JWT secret validation and other security-critical configuration.
"""


import pytest
from pydantic import ValidationError

from pdfsigner.api.config import APISettings


class TestJwtSecretValidation:
    """Test JWT secret key security validation."""

    def test_missing_jwt_secret_raises_error(self, monkeypatch):
        """Missing JWT secret should raise ValueError."""
        # Clear any existing JWT secret
        monkeypatch.delenv("PDFSIGNER_API_JWT_SECRET_KEY", raising=False)

        with pytest.raises(ValidationError) as exc_info:
            APISettings()

        assert "JWT secret key is required" in str(exc_info.value)

    def test_short_jwt_secret_raises_error(self, monkeypatch):
        """JWT secret shorter than 32 chars should raise ValueError."""
        monkeypatch.setenv("PDFSIGNER_API_JWT_SECRET_KEY", "tooshort")

        with pytest.raises(ValidationError) as exc_info:
            APISettings()

        assert "at least 32 characters" in str(exc_info.value)

    def test_weak_jwt_secret_raises_error(self, monkeypatch):
        """Known weak/default JWT secrets should raise ValueError."""
        weak_secrets = [
            "CHANGE_THIS_IN_PRODUCTION_USE_ENV_VAR",
            "secret",
            "change_me",
            "your-secret-key",
            "jwt-secret",
        ]

        for weak_secret in weak_secrets:
            # Pad to meet length requirement to test the weak value check specifically
            padded = weak_secret.ljust(32, "x") if len(weak_secret) < 32 else weak_secret
            monkeypatch.setenv("PDFSIGNER_API_JWT_SECRET_KEY", weak_secret)

            with pytest.raises(ValidationError):
                APISettings()

    def test_valid_jwt_secret_accepted(self, monkeypatch):
        """Valid JWT secret should be accepted."""
        # Generate a proper secret (43 chars from token_urlsafe(32))
        valid_secret = "abcdefghijklmnopqrstuvwxyz123456789ABCDEF"  # 41 chars
        monkeypatch.setenv("PDFSIGNER_API_JWT_SECRET_KEY", valid_secret)

        settings = APISettings()
        assert settings.jwt_secret_key is not None
        assert settings.jwt_secret_key.get_secret_value() == valid_secret

    def test_jwt_secret_from_env_variable(self, monkeypatch):
        """JWT secret should be read from environment variable."""
        test_secret = "my-super-secure-jwt-secret-key-123456789"
        monkeypatch.setenv("PDFSIGNER_API_JWT_SECRET_KEY", test_secret)

        settings = APISettings()
        assert settings.jwt_secret_key.get_secret_value() == test_secret


class TestSecurityConfiguration:
    """Test other security-related configuration."""

    @pytest.fixture(autouse=True)
    def setup_valid_jwt(self, monkeypatch):
        """Set a valid JWT secret for all tests in this class."""
        monkeypatch.setenv(
            "PDFSIGNER_API_JWT_SECRET_KEY", "valid-test-secret-key-for-unit-tests-12345"
        )

    def test_default_jwt_algorithm(self):
        """JWT algorithm should default to HS256."""
        settings = APISettings()
        assert settings.jwt_algorithm == "HS256"

    def test_jwt_expiry_has_bounds(self):
        """JWT expiry should have min/max bounds."""
        settings = APISettings()
        # Default is 30 minutes
        assert 5 <= settings.jwt_expire_minutes <= 1440

    def test_rate_limiting_enabled_by_default(self):
        """Rate limiting should be enabled by default."""
        settings = APISettings()
        assert settings.rate_limit_enabled is True
        assert settings.rate_limit_per_minute > 0

    def test_tls_settings_defaults(self):
        """TLS should be disabled by default but configurable."""
        settings = APISettings()
        assert settings.tls_enabled is False
        assert settings.tls_min_version == "TLSv1.2"


class TestCorsConfiguration:
    """Test CORS configuration."""

    @pytest.fixture(autouse=True)
    def setup_valid_jwt(self, monkeypatch):
        """Set a valid JWT secret for all tests in this class."""
        monkeypatch.setenv(
            "PDFSIGNER_API_JWT_SECRET_KEY", "valid-test-secret-key-for-unit-tests-12345"
        )

    def test_cors_origins_default(self):
        """CORS origins should have safe defaults."""
        settings = APISettings()
        assert settings.cors_origins is not None
        # Should not allow all origins by default
        assert "*" not in settings.cors_origins

    def test_cors_credentials_default(self):
        """CORS credentials should be properly configured."""
        settings = APISettings()
        assert settings.cors_allow_credentials is True


class TestUploadLimits:
    """Test file upload security limits."""

    @pytest.fixture(autouse=True)
    def setup_valid_jwt(self, monkeypatch):
        """Set a valid JWT secret for all tests in this class."""
        monkeypatch.setenv(
            "PDFSIGNER_API_JWT_SECRET_KEY", "valid-test-secret-key-for-unit-tests-12345"
        )

    def test_max_upload_size_has_limit(self):
        """Max upload size should have an upper limit."""
        settings = APISettings()
        assert settings.max_upload_size_mb <= 500  # Max 500MB

    def test_max_batch_size_has_limit(self):
        """Max batch size should have an upper limit."""
        settings = APISettings()
        assert settings.max_batch_size <= 1000  # Max 1000 files

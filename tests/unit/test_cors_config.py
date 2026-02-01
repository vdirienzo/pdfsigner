"""
Tests for CORS configuration security.

Validates that:
1. Default CORS config avoids insecure wildcards
2. Validators warn when wildcards are explicitly configured
3. Secure explicit values work correctly
"""

import warnings
from unittest.mock import patch

from pdfsigner.api.config import APISettings


class TestCORSDefaults:
    """Test default CORS configuration values."""

    def test_default_cors_methods_no_wildcard(self) -> None:
        """Default cors_allow_methods should not contain wildcard."""
        with patch.dict("os.environ", {"PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32}, clear=True):
            settings = APISettings()

        assert "*" not in settings.cors_allow_methods
        assert "GET" in settings.cors_allow_methods
        assert "POST" in settings.cors_allow_methods
        assert "PUT" in settings.cors_allow_methods
        assert "DELETE" in settings.cors_allow_methods
        assert "OPTIONS" in settings.cors_allow_methods

    def test_default_cors_headers_no_wildcard(self) -> None:
        """Default cors_allow_headers should not contain wildcard."""
        with patch.dict("os.environ", {"PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32}, clear=True):
            settings = APISettings()

        assert "*" not in settings.cors_allow_headers
        assert "Content-Type" in settings.cors_allow_headers
        assert "Authorization" in settings.cors_allow_headers
        assert "X-CSRF-Token" in settings.cors_allow_headers
        assert "X-API-Key" in settings.cors_allow_headers

    def test_default_cors_methods_exact_list(self) -> None:
        """Verify exact default methods list."""
        with patch.dict("os.environ", {"PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32}, clear=True):
            settings = APISettings()

        expected_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        assert settings.cors_allow_methods == expected_methods

    def test_default_cors_headers_exact_list(self) -> None:
        """Verify exact default headers list."""
        with patch.dict("os.environ", {"PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32}, clear=True):
            settings = APISettings()

        expected_headers = ["Content-Type", "Authorization", "X-CSRF-Token", "X-API-Key"]
        assert settings.cors_allow_headers == expected_headers


class TestCORSValidatorWarnings:
    """Test CORS validator warnings for insecure wildcard usage."""

    def test_wildcard_methods_triggers_warning(self) -> None:
        """Using wildcard in cors_allow_methods should trigger warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            with patch.dict(
                "os.environ",
                {
                    "PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32,
                    "PDFSIGNER_API_CORS_ALLOW_METHODS": '["*"]',
                },
                clear=True,
            ):
                settings = APISettings()

            # Verify warning was raised
            assert len(w) == 1
            assert issubclass(w[0].category, UserWarning)
            assert "wildcard '*'" in str(w[0].message).lower()
            assert "cors" in str(w[0].message).lower()
            assert "methods" in str(w[0].message).lower()

            # Verify value is still set (warning doesn't block)
            assert settings.cors_allow_methods == ["*"]

    def test_wildcard_headers_triggers_warning(self) -> None:
        """Using wildcard in cors_allow_headers should trigger warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            with patch.dict(
                "os.environ",
                {
                    "PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32,
                    "PDFSIGNER_API_CORS_ALLOW_HEADERS": '["*"]',
                },
                clear=True,
            ):
                settings = APISettings()

            # Verify warning was raised
            assert len(w) == 1
            assert issubclass(w[0].category, UserWarning)
            assert "wildcard '*'" in str(w[0].message).lower()
            assert "cors" in str(w[0].message).lower()
            assert "headers" in str(w[0].message).lower()

            # Verify value is still set (warning doesn't block)
            assert settings.cors_allow_headers == ["*"]

    def test_wildcard_mixed_with_explicit_methods_triggers_warning(self) -> None:
        """Wildcard mixed with explicit methods should trigger warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            with patch.dict(
                "os.environ",
                {
                    "PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32,
                    "PDFSIGNER_API_CORS_ALLOW_METHODS": '["GET", "POST", "*"]',
                },
                clear=True,
            ):
                settings = APISettings()

            # Warning should still be raised
            assert len(w) == 1
            assert "wildcard '*'" in str(w[0].message).lower()
            assert settings.cors_allow_methods == ["GET", "POST", "*"]

    def test_wildcard_mixed_with_explicit_headers_triggers_warning(self) -> None:
        """Wildcard mixed with explicit headers should trigger warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            with patch.dict(
                "os.environ",
                {
                    "PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32,
                    "PDFSIGNER_API_CORS_ALLOW_HEADERS": '["Content-Type", "*"]',
                },
                clear=True,
            ):
                settings = APISettings()

            # Warning should still be raised
            assert len(w) == 1
            assert "wildcard '*'" in str(w[0].message).lower()
            assert settings.cors_allow_headers == ["Content-Type", "*"]

    def test_both_wildcards_trigger_two_warnings(self) -> None:
        """Using wildcard in both methods and headers should trigger two warnings."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            with patch.dict(
                "os.environ",
                {
                    "PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32,
                    "PDFSIGNER_API_CORS_ALLOW_METHODS": '["*"]',
                    "PDFSIGNER_API_CORS_ALLOW_HEADERS": '["*"]',
                },
                clear=True,
            ):
                _ = APISettings()

            # Should have two warnings (one for methods, one for headers)
            assert len(w) == 2
            warning_messages = [str(warning.message).lower() for warning in w]
            assert any("methods" in msg for msg in warning_messages)
            assert any("headers" in msg for msg in warning_messages)


class TestCORSExplicitConfiguration:
    """Test explicit CORS configuration without wildcards."""

    def test_explicit_methods_no_warning(self) -> None:
        """Explicit methods list should not trigger warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            with patch.dict(
                "os.environ",
                {
                    "PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32,
                    "PDFSIGNER_API_CORS_ALLOW_METHODS": '["GET", "POST"]',
                },
                clear=True,
            ):
                settings = APISettings()

            # No warnings should be raised
            assert len(w) == 0
            assert settings.cors_allow_methods == ["GET", "POST"]

    def test_explicit_headers_no_warning(self) -> None:
        """Explicit headers list should not trigger warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            with patch.dict(
                "os.environ",
                {
                    "PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32,
                    "PDFSIGNER_API_CORS_ALLOW_HEADERS": '["Content-Type", "Authorization"]',
                },
                clear=True,
            ):
                settings = APISettings()

            # No warnings should be raised
            assert len(w) == 0
            assert settings.cors_allow_headers == ["Content-Type", "Authorization"]

    def test_custom_methods_work_correctly(self) -> None:
        """Custom methods configuration should work correctly."""
        with patch.dict(
            "os.environ",
            {
                "PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32,
                "PDFSIGNER_API_CORS_ALLOW_METHODS": '["GET", "POST", "PATCH"]',
            },
            clear=True,
        ):
            settings = APISettings()

        assert settings.cors_allow_methods == ["GET", "POST", "PATCH"]

    def test_custom_headers_work_correctly(self) -> None:
        """Custom headers configuration should work correctly."""
        with patch.dict(
            "os.environ",
            {
                "PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32,
                "PDFSIGNER_API_CORS_ALLOW_HEADERS": '["Content-Type", "X-Custom-Header"]',
            },
            clear=True,
        ):
            settings = APISettings()

        assert settings.cors_allow_headers == ["Content-Type", "X-Custom-Header"]

    def test_empty_methods_list_no_warning(self) -> None:
        """Empty methods list should not trigger warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            with patch.dict(
                "os.environ",
                {
                    "PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32,
                    "PDFSIGNER_API_CORS_ALLOW_METHODS": "[]",
                },
                clear=True,
            ):
                settings = APISettings()

            # No warnings for empty list
            assert len(w) == 0
            assert settings.cors_allow_methods == []

    def test_empty_headers_list_no_warning(self) -> None:
        """Empty headers list should not trigger warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            with patch.dict(
                "os.environ",
                {
                    "PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32,
                    "PDFSIGNER_API_CORS_ALLOW_HEADERS": "[]",
                },
                clear=True,
            ):
                settings = APISettings()

            # No warnings for empty list
            assert len(w) == 0
            assert settings.cors_allow_headers == []


class TestCORSSecurityBestPractices:
    """Test CORS configuration follows security best practices."""

    def test_default_config_is_secure(self) -> None:
        """Default configuration should follow security best practices."""
        with patch.dict("os.environ", {"PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32}, clear=True):
            settings = APISettings()

        # No wildcards in default config
        assert "*" not in settings.cors_allow_methods
        assert "*" not in settings.cors_allow_headers

        # Contains only necessary methods
        assert all(
            method in ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"]
            for method in settings.cors_allow_methods
        )

        # Contains only necessary headers
        assert all(
            ":" not in header  # Headers should not contain colons
            for header in settings.cors_allow_headers
        )

    def test_credentials_enabled_by_default(self) -> None:
        """CORS credentials should be enabled by default for auth."""
        with patch.dict("os.environ", {"PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32}, clear=True):
            settings = APISettings()

        assert settings.cors_allow_credentials is True

    def test_origins_are_explicit_not_wildcard(self) -> None:
        """CORS origins should be explicit, not wildcard."""
        with patch.dict("os.environ", {"PDFSIGNER_API_JWT_SECRET_KEY": "x" * 32}, clear=True):
            settings = APISettings()

        assert "*" not in settings.cors_origins
        assert all(origin.startswith(("http://", "https://")) for origin in settings.cors_origins)

"""
test_exceptions.py - Tests for custom exceptions

Author: Homero Thompson del Lago del Terror
"""

import pytest

from pdfsigner.exceptions import (
    CertificateError,
    CertificateExpiredError,
    CertificateNotFoundError,
    ConfigurationError,
    NSSConfigError,
    PDFCorruptedError,
    PDFError,
    PDFProtectedError,
    PDFSignerError,
    SigningError,
    TimestampError,
    TokenAuthenticationError,
    TokenError,
    TokenNotFoundError,
    TSAConnectionError,
    TSAResponseError,
)


class TestPDFSignerError:
    """Tests for base PDFSignerError."""

    def test_base_exception(self):
        """Test base exception can be raised."""
        with pytest.raises(PDFSignerError) as exc_info:
            raise PDFSignerError("Base error")

        assert str(exc_info.value) == "Base error"

    def test_inheritance_hierarchy(self):
        """Test exception inheritance hierarchy."""
        # Token errors
        assert issubclass(TokenError, PDFSignerError)
        assert issubclass(TokenNotFoundError, TokenError)
        assert issubclass(TokenAuthenticationError, TokenError)

        # Certificate errors
        assert issubclass(CertificateError, PDFSignerError)
        assert issubclass(CertificateNotFoundError, CertificateError)
        assert issubclass(CertificateExpiredError, CertificateError)

        # Signing errors
        assert issubclass(SigningError, PDFSignerError)
        assert issubclass(PDFError, SigningError)
        assert issubclass(PDFCorruptedError, PDFError)
        assert issubclass(PDFProtectedError, PDFError)

        # Timestamp errors
        assert issubclass(TimestampError, SigningError)
        assert issubclass(TSAConnectionError, TimestampError)
        assert issubclass(TSAResponseError, TimestampError)

        # Configuration errors
        assert issubclass(ConfigurationError, PDFSignerError)
        assert issubclass(NSSConfigError, ConfigurationError)


class TestTokenErrors:
    """Tests for token-related errors."""

    def test_token_not_found_default_message(self):
        """Test TokenNotFoundError default message."""
        error = TokenNotFoundError()

        assert "token" in str(error).lower()

    def test_token_not_found_custom_message(self):
        """Test TokenNotFoundError custom message."""
        error = TokenNotFoundError("Custom message")

        assert str(error) == "Custom message"

    def test_token_authentication_error_default_message(self):
        """Test TokenAuthenticationError default message."""
        error = TokenAuthenticationError()

        assert "pin" in str(error).lower() or "auth" in str(error).lower()

    def test_token_authentication_error_custom_message(self):
        """Test TokenAuthenticationError custom message."""
        error = TokenAuthenticationError("Wrong PIN entered")

        assert "Wrong PIN" in str(error)


class TestCertificateErrors:
    """Tests for certificate-related errors."""

    def test_certificate_not_found_default_message(self):
        """Test CertificateNotFoundError default message."""
        error = CertificateNotFoundError()

        assert "certificate" in str(error).lower()

    def test_certificate_expired_error(self):
        """Test CertificateExpiredError with cert info."""
        error = CertificateExpiredError("John Doe", "2023-01-01")

        error_str = str(error)
        assert "John Doe" in error_str
        assert "2023-01-01" in error_str


class TestPDFErrors:
    """Tests for PDF-related errors."""

    def test_pdf_corrupted_error(self):
        """Test PDFCorruptedError with filename."""
        error = PDFCorruptedError("document.pdf")

        error_str = str(error)
        assert "document.pdf" in error_str
        assert "corrupt" in error_str.lower() or "invalid" in error_str.lower()

    def test_pdf_protected_error(self):
        """Test PDFProtectedError with filename."""
        error = PDFProtectedError("protected.pdf")

        error_str = str(error)
        assert "protected.pdf" in error_str
        assert "protect" in error_str.lower()


class TestTimestampErrors:
    """Tests for timestamp-related errors."""

    def test_tsa_connection_error(self):
        """Test TSAConnectionError with URL."""
        error = TSAConnectionError("https://tsa.example.com")

        error_str = str(error)
        assert "tsa.example.com" in error_str

    def test_tsa_response_error_default_message(self):
        """Test TSAResponseError default message."""
        error = TSAResponseError()

        assert "timestamp" in str(error).lower()

    def test_tsa_response_error_custom_message(self):
        """Test TSAResponseError custom message."""
        error = TSAResponseError("Invalid timestamp token")

        assert "Invalid timestamp token" in str(error)


class TestConfigurationErrors:
    """Tests for configuration-related errors."""

    def test_nss_config_error(self):
        """Test NSSConfigError with path."""
        error = NSSConfigError("/invalid/path/.nss")

        error_str = str(error)
        assert "/invalid/path/.nss" in error_str

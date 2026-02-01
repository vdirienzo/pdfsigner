"""
test_ca_detector.py - Tests for Argentine CA Auto-Detection

Tests the automatic detection of Argentine certification authorities from
PKCS#11 token certificates.
"""

from unittest.mock import Mock, patch

import pytest

from pdfsigner.core.argentina.ca_detector import (
    ArgentineCADetector,
    CADetectionResult,
    get_ca_detector,
)
from pdfsigner.core.argentina.ca_registry import (
    ArgentineCertifier,
    CertifierStatus,
    CertifierType,
)
from pdfsigner.core.token.nss_handler import CertificateInfo
from pdfsigner.exceptions import (
    CertificateNotFoundError,
    TokenAuthenticationError,
)


@pytest.fixture
def detector():
    """Create CA detector instance."""
    return ArgentineCADetector()


@pytest.fixture
def mock_afip_cert():
    """Create mock AFIP certificate info."""
    return CertificateInfo(
        label="AFIP Certificate",
        subject="CN=Juan Perez,O=Test Company",
        issuer="CN=AC AFIP,O=AFIP,C=AR",
        serial_number="1234567890abcdef",
        not_before="2024-01-01T00:00:00Z",
        not_after="2025-01-01T00:00:00Z",
        can_sign=True,
        pkcs11_id=b"\x01\x02\x03\x04",
    )


@pytest.fixture
def mock_renaper_cert():
    """Create mock RENAPER certificate info."""
    return CertificateInfo(
        label="RENAPER Certificate",
        subject="CN=Maria Garcia,O=Citizen",
        issuer="CN=AC RENAPER,O=RENAPER,C=AR",
        serial_number="fedcba0987654321",
        not_before="2024-01-01T00:00:00Z",
        not_after="2025-01-01T00:00:00Z",
        can_sign=True,
        pkcs11_id=b"\x05\x06\x07\x08",
    )


@pytest.fixture
def mock_unknown_cert():
    """Create mock certificate from unknown CA."""
    return CertificateInfo(
        label="Unknown Certificate",
        subject="CN=Test User,O=Test Org",
        issuer="CN=Unknown CA,O=Unknown,C=US",
        serial_number="1111111111111111",
        not_before="2024-01-01T00:00:00Z",
        not_after="2025-01-01T00:00:00Z",
        can_sign=True,
        pkcs11_id=b"\x09\x0a\x0b\x0c",
    )


@pytest.fixture
def mock_nss_handler():
    """Create mock NSSHandler."""
    handler = Mock()
    handler.initialize = Mock()
    handler.connect_token = Mock()
    handler.authenticate = Mock()
    handler.close = Mock()
    return handler


class TestArgentineCADetector:
    """Tests for ArgentineCADetector class."""

    def test_detector_initialization(self, detector):
        """Test detector initializes with registry."""
        assert detector.registry is not None
        assert len(detector.registry.get_all_certifiers()) > 0

    def test_detect_afip_certificate_returns_argentine_ca(self, detector, mock_afip_cert):
        """Test detection of AFIP certificate."""
        result = detector._detect_from_certificate(mock_afip_cert)

        assert result.is_argentine_ca is True
        assert result.certifier is not None
        assert result.certifier.name == "AFIP"
        assert result.certifier.certifier_type == CertifierType.GOVERNMENTAL
        assert result.certificate == mock_afip_cert
        assert result.error is None

    def test_detect_renaper_certificate_returns_argentine_ca(self, detector, mock_renaper_cert):
        """Test detection of RENAPER certificate."""
        result = detector._detect_from_certificate(mock_renaper_cert)

        assert result.is_argentine_ca is True
        assert result.certifier is not None
        assert result.certifier.name == "RENAPER"
        assert result.certifier.certifier_type == CertifierType.GOVERNMENTAL
        assert result.certificate == mock_renaper_cert
        assert result.error is None

    def test_detect_unknown_certificate_returns_not_argentine_ca(self, detector, mock_unknown_cert):
        """Test detection of unknown CA certificate."""
        result = detector._detect_from_certificate(mock_unknown_cert)

        assert result.is_argentine_ca is False
        assert result.certifier is None
        assert result.certificate == mock_unknown_cert
        assert result.error is None

    def test_detect_from_pkcs11_with_afip_cert_returns_detection_result(
        self, detector, mock_nss_handler, mock_afip_cert
    ):
        """Test detection from PKCS#11 handler with AFIP certificate."""
        mock_nss_handler.list_certificates = Mock(return_value=[mock_afip_cert])

        results = detector.detect_from_pkcs11(mock_nss_handler)

        assert len(results) == 1
        assert results[0].is_argentine_ca is True
        assert results[0].certifier.name == "AFIP"

    def test_detect_from_pkcs11_with_multiple_certs_returns_all_results(
        self, detector, mock_nss_handler, mock_afip_cert, mock_renaper_cert, mock_unknown_cert
    ):
        """Test detection from multiple certificates."""
        mock_nss_handler.list_certificates = Mock(
            return_value=[mock_afip_cert, mock_renaper_cert, mock_unknown_cert]
        )

        results = detector.detect_from_pkcs11(mock_nss_handler)

        assert len(results) == 3
        assert results[0].is_argentine_ca is True
        assert results[0].certifier.name == "AFIP"
        assert results[1].is_argentine_ca is True
        assert results[1].certifier.name == "RENAPER"
        assert results[2].is_argentine_ca is False
        assert results[2].certifier is None

    def test_detect_from_pkcs11_with_no_certificates_returns_error(
        self, detector, mock_nss_handler
    ):
        """Test detection when no certificates found."""
        mock_nss_handler.list_certificates = Mock(return_value=[])

        results = detector.detect_from_pkcs11(mock_nss_handler)

        assert len(results) == 1
        assert results[0].is_argentine_ca is False
        assert results[0].certifier is None
        assert results[0].certificate is None
        assert "No certificates found" in results[0].error

    def test_detect_from_pkcs11_with_authentication_error_returns_error(
        self, detector, mock_nss_handler
    ):
        """Test detection with authentication error."""
        mock_nss_handler.list_certificates = Mock(
            side_effect=TokenAuthenticationError("PIN required")
        )

        results = detector.detect_from_pkcs11(mock_nss_handler)

        assert len(results) == 1
        assert results[0].is_argentine_ca is False
        assert results[0].error is not None
        assert "authentication required" in results[0].error.lower()

    def test_detect_from_pkcs11_with_certificate_not_found_error_returns_error(
        self, detector, mock_nss_handler
    ):
        """Test detection with certificate not found error."""
        mock_nss_handler.list_certificates = Mock(side_effect=CertificateNotFoundError())

        results = detector.detect_from_pkcs11(mock_nss_handler)

        assert len(results) == 1
        assert results[0].is_argentine_ca is False
        assert "Certificate not found" in results[0].error

    def test_detect_from_pkcs11_with_generic_exception_returns_error(
        self, detector, mock_nss_handler
    ):
        """Test detection with generic exception."""
        mock_nss_handler.list_certificates = Mock(side_effect=Exception("Unexpected error"))

        results = detector.detect_from_pkcs11(mock_nss_handler)

        assert len(results) == 1
        assert results[0].is_argentine_ca is False
        assert "Detection error" in results[0].error

    def test_get_certifier_info_with_argentine_ca_returns_details(self, detector, mock_afip_cert):
        """Test getting certifier info for Argentine CA."""
        result = detector._detect_from_certificate(mock_afip_cert)
        info = detector.get_certifier_info(result)

        assert info["status"] == "argentine_ca_detected"
        assert info["name"] == "AFIP"
        assert info["type"] == "governmental"
        assert info["cost"] == "Gratis"
        assert "website" in info
        assert "modality" in info
        assert info["license_status"] == "active"

    def test_get_certifier_info_with_unknown_ca_returns_not_detected(
        self, detector, mock_unknown_cert
    ):
        """Test getting certifier info for unknown CA."""
        result = detector._detect_from_certificate(mock_unknown_cert)
        info = detector.get_certifier_info(result)

        assert info["status"] == "not_argentine_ca"
        assert "not issued by recognized Argentine CA" in info["message"]

    @patch("pdfsigner.core.argentina.ca_detector.NSSHandler")
    def test_detect_from_token_label_with_pin_authenticates_and_detects(
        self, mock_handler_class, detector, mock_afip_cert
    ):
        """Test detection from token label with PIN authentication."""
        mock_handler = Mock()
        mock_handler.list_certificates = Mock(return_value=[mock_afip_cert])
        mock_handler_class.return_value = mock_handler

        results = detector.detect_from_token_label(token_label="Test Token", pin="123456")

        mock_handler.initialize.assert_called_once()
        mock_handler.connect_token.assert_called_once_with("Test Token")
        mock_handler.authenticate.assert_called_once_with("123456")
        mock_handler.close.assert_called_once()

        assert len(results) == 1
        assert results[0].is_argentine_ca is True

    @patch("pdfsigner.core.argentina.ca_detector.NSSHandler")
    def test_detect_from_token_label_without_pin_returns_error(self, mock_handler_class, detector):
        """Test detection from token label without PIN."""
        mock_handler = Mock()
        mock_handler_class.return_value = mock_handler

        results = detector.detect_from_token_label(token_label="Test Token", pin=None)

        mock_handler.initialize.assert_called_once()
        mock_handler.connect_token.assert_called_once_with("Test Token")
        mock_handler.authenticate.assert_not_called()
        mock_handler.close.assert_called_once()

        assert len(results) == 1
        assert results[0].is_argentine_ca is False
        assert "PIN required" in results[0].error

    @patch("pdfsigner.core.argentina.ca_detector.NSSHandler")
    def test_detect_from_token_label_closes_handler_on_exception(
        self, mock_handler_class, detector
    ):
        """Test that handler is closed even when exception occurs."""
        mock_handler = Mock()
        mock_handler.authenticate = Mock(side_effect=TokenAuthenticationError("Bad PIN"))
        mock_handler_class.return_value = mock_handler

        results = detector.detect_from_token_label(token_label="Test Token", pin="wrong")

        mock_handler.close.assert_called_once()
        # Verify error result is returned
        assert len(results) == 1
        assert results[0].is_argentine_ca is False
        assert "Authentication failed" in results[0].error


class TestCADetectorSingleton:
    """Tests for CA detector singleton."""

    def test_get_ca_detector_returns_singleton(self):
        """Test that get_ca_detector returns singleton instance."""
        detector1 = get_ca_detector()
        detector2 = get_ca_detector()

        assert detector1 is detector2

    def test_singleton_has_registry(self):
        """Test that singleton detector has registry."""
        detector = get_ca_detector()
        assert detector.registry is not None


class TestCADetectionResult:
    """Tests for CADetectionResult dataclass."""

    def test_detection_result_with_argentine_ca(self):
        """Test detection result for Argentine CA."""
        certifier = ArgentineCertifier(
            name="AFIP",
            certifier_type=CertifierType.GOVERNMENTAL,
            status=CertifierStatus.ACTIVE,
            issuer_dns=["CN=AC AFIP"],
            website="https://afip.gob.ar",
            cost="Gratis",
            modality="Token",
            description="Test certifier",
        )

        cert_info = CertificateInfo(
            label="Test",
            subject="CN=Test",
            issuer="CN=AC AFIP",
            serial_number="123",
            not_before="2024-01-01T00:00:00Z",
            not_after="2025-01-01T00:00:00Z",
            can_sign=True,
            pkcs11_id=b"\x01",
        )

        result = CADetectionResult(
            is_argentine_ca=True,
            certifier=certifier,
            certificate=cert_info,
            error=None,
        )

        assert result.is_argentine_ca is True
        assert result.certifier.name == "AFIP"
        assert result.certificate.label == "Test"
        assert result.error is None

    def test_detection_result_with_error(self):
        """Test detection result with error."""
        result = CADetectionResult(
            is_argentine_ca=False,
            certifier=None,
            certificate=None,
            error="Test error message",
        )

        assert result.is_argentine_ca is False
        assert result.certifier is None
        assert result.certificate is None
        assert result.error == "Test error message"

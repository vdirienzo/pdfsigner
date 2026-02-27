"""
test_revocation_checker.py - Tests for certificate revocation checking

Author: Homero Thompson del Lago del Terror

Comprehensive tests for OCSP and CRL revocation checking with mocks.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest
import requests
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    CRLEntryExtensionOID,
    ExtensionOID,
    NameOID,
)

from pdfsigner.core.certificate.revocation_checker import (
    CRLChecker,
    OCSPChecker,
    RevocationChecker,
    RevocationResult,
    RevocationStatus,
)


class TestRevocationStatus:
    """Tests for RevocationStatus enum."""

    def test_good_status_value(self):
        """Test GOOD status has correct value."""
        assert RevocationStatus.GOOD.value == "good"

    def test_revoked_status_value(self):
        """Test REVOKED status has correct value."""
        assert RevocationStatus.REVOKED.value == "revoked"

    def test_unknown_status_value(self):
        """Test UNKNOWN status has correct value."""
        assert RevocationStatus.UNKNOWN.value == "unknown"

    def test_error_status_value(self):
        """Test ERROR status has correct value."""
        assert RevocationStatus.ERROR.value == "error"


class TestRevocationResult:
    """Tests for RevocationResult dataclass."""

    def test_creation_minimal(self):
        """Test creating RevocationResult with minimal fields."""
        result = RevocationResult(status=RevocationStatus.GOOD)
        assert result.status == RevocationStatus.GOOD
        assert isinstance(result.checked_at, datetime)
        assert result.method == ""
        assert result.responder_url == ""
        assert result.error_message is None

    def test_creation_full(self):
        """Test creating RevocationResult with all fields."""
        checked_at = datetime.now(UTC)
        revoked_at = datetime.now(UTC) - timedelta(days=10)

        result = RevocationResult(
            status=RevocationStatus.REVOKED,
            checked_at=checked_at,
            method="OCSP",
            responder_url="http://ocsp.example.com",
            error_message=None,
            revocation_time=revoked_at,
            revocation_reason="keyCompromise",
        )

        assert result.status == RevocationStatus.REVOKED
        assert result.checked_at == checked_at
        assert result.method == "OCSP"
        assert result.responder_url == "http://ocsp.example.com"
        assert result.revocation_time == revoked_at
        assert result.revocation_reason == "keyCompromise"

    def test_is_valid_property_true(self):
        """Test is_valid returns True for GOOD status."""
        result = RevocationResult(status=RevocationStatus.GOOD)
        assert result.is_valid is True

    def test_is_valid_property_false(self):
        """Test is_valid returns False for REVOKED status."""
        result = RevocationResult(status=RevocationStatus.REVOKED)
        assert result.is_valid is False

    def test_is_revoked_property_true(self):
        """Test is_revoked returns True for REVOKED status."""
        result = RevocationResult(status=RevocationStatus.REVOKED)
        assert result.is_revoked is True

    def test_is_revoked_property_false(self):
        """Test is_revoked returns False for GOOD status."""
        result = RevocationResult(status=RevocationStatus.GOOD)
        assert result.is_revoked is False


class TestOCSPChecker:
    """Tests for OCSPChecker class."""

    @pytest.fixture
    def mock_cert(self):
        """Create a mock certificate with OCSP URL."""
        cert = Mock(spec=x509.Certificate)
        cert.serial_number = 123456789
        cert.subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate")])

        # Mock extensions to return OCSP URL
        mock_aia_ext = Mock()
        mock_access_desc = Mock()
        mock_access_desc.access_method = AuthorityInformationAccessOID.OCSP
        mock_access_desc.access_location.value = "http://ocsp.example.com"
        mock_aia_ext.value = [mock_access_desc]

        cert.extensions.get_extension_for_oid.return_value = mock_aia_ext

        return cert

    @pytest.fixture
    def mock_issuer_cert(self):
        """Create a mock issuer certificate."""
        issuer = Mock(spec=x509.Certificate)
        issuer.subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        return issuer

    @pytest.fixture
    def ocsp_checker(self):
        """Create OCSPChecker instance."""
        return OCSPChecker(timeout=5, cache_ttl_seconds=60)

    def test_initialization(self):
        """Test OCSPChecker initialization."""
        checker = OCSPChecker(timeout=15, cache_ttl_seconds=300)
        assert checker.timeout == 15
        assert checker.cache_ttl_seconds == 300
        assert isinstance(checker._cache, dict)
        assert len(checker._cache) == 0

    def test_check_no_ocsp_url(self, ocsp_checker, mock_issuer_cert):
        """Test check returns UNKNOWN when certificate has no OCSP URL."""
        cert = Mock(spec=x509.Certificate)
        cert.extensions.get_extension_for_oid.side_effect = x509.ExtensionNotFound(
            "Not found", ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )

        result = ocsp_checker.check(cert, mock_issuer_cert)

        assert result.status == RevocationStatus.UNKNOWN
        assert result.method == "OCSP"
        assert "No OCSP responder URL" in result.error_message

    @patch("pdfsigner.core.security.url_validator.validate_ocsp_url", side_effect=lambda url: url)
    @patch("pdfsigner.core.certificate.ocsp_checker.requests.post")
    @patch("pdfsigner.core.certificate.ocsp_checker.ocsp.OCSPRequestBuilder")
    def test_check_ocsp_good_status(
        self, mock_builder, mock_post, _mock_validate, ocsp_checker, mock_cert, mock_issuer_cert
    ):
        """Test check returns GOOD status from OCSP response."""
        # Mock OCSP request building
        mock_request = Mock()
        mock_request.public_bytes.return_value = b"ocsp_request_data"
        mock_builder_instance = Mock()
        mock_builder_instance.add_certificate.return_value = mock_builder_instance
        mock_builder_instance.build.return_value = mock_request
        mock_builder.return_value = mock_builder_instance

        # Mock OCSP response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.content = b"ocsp_response_data"
        mock_post.return_value = mock_response

        # Mock OCSP response parsing
        mock_ocsp_response = Mock()
        mock_ocsp_response.response_status = ocsp.OCSPResponseStatus.SUCCESSFUL
        mock_ocsp_response.certificate_status = ocsp.OCSPCertStatus.GOOD

        with patch(
            "pdfsigner.core.certificate.ocsp_checker.ocsp.load_der_ocsp_response",
            return_value=mock_ocsp_response,
        ):
            result = ocsp_checker.check(mock_cert, mock_issuer_cert)

        assert result.status == RevocationStatus.GOOD
        assert result.method == "OCSP"
        assert result.responder_url == "http://ocsp.example.com"
        assert result.error_message is None

    @patch("pdfsigner.core.security.url_validator.validate_ocsp_url", side_effect=lambda url: url)
    @patch("pdfsigner.core.certificate.ocsp_checker.requests.post")
    @patch("pdfsigner.core.certificate.ocsp_checker.ocsp.OCSPRequestBuilder")
    def test_check_ocsp_revoked_status(
        self, mock_builder, mock_post, _mock_validate, ocsp_checker, mock_cert, mock_issuer_cert
    ):
        """Test check returns REVOKED status from OCSP response."""
        # Mock OCSP request building
        mock_request = Mock()
        mock_request.public_bytes.return_value = b"ocsp_request_data"
        mock_builder_instance = Mock()
        mock_builder_instance.add_certificate.return_value = mock_builder_instance
        mock_builder_instance.build.return_value = mock_request
        mock_builder.return_value = mock_builder_instance

        # Mock HTTP response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.content = b"ocsp_response_data"
        mock_post.return_value = mock_response

        # Mock OCSP response with REVOKED status
        mock_ocsp_response = Mock()
        mock_ocsp_response.response_status = ocsp.OCSPResponseStatus.SUCCESSFUL
        mock_ocsp_response.certificate_status = ocsp.OCSPCertStatus.REVOKED
        mock_ocsp_response.revocation_time = datetime.now(UTC) - timedelta(days=5)
        mock_ocsp_response.revocation_reason = "keyCompromise"

        with patch(
            "pdfsigner.core.certificate.ocsp_checker.ocsp.load_der_ocsp_response",
            return_value=mock_ocsp_response,
        ):
            result = ocsp_checker.check(mock_cert, mock_issuer_cert)

        assert result.status == RevocationStatus.REVOKED
        assert result.method == "OCSP"
        assert result.responder_url == "http://ocsp.example.com"
        assert result.revocation_time is not None
        assert result.revocation_reason == "keyCompromise"

    @patch("pdfsigner.core.security.url_validator.validate_ocsp_url", side_effect=lambda url: url)
    @patch("pdfsigner.core.certificate.ocsp_checker.requests.post")
    @patch("pdfsigner.core.certificate.ocsp_checker.ocsp.OCSPRequestBuilder")
    def test_check_ocsp_timeout(
        self, mock_builder, mock_post, _mock_validate, ocsp_checker, mock_cert, mock_issuer_cert
    ):
        """Test check handles OCSP timeout correctly."""
        # Mock OCSP request building
        mock_request = Mock()
        mock_request.public_bytes.return_value = b"ocsp_request_data"
        mock_builder_instance = Mock()
        mock_builder_instance.add_certificate.return_value = mock_builder_instance
        mock_builder_instance.build.return_value = mock_request
        mock_builder.return_value = mock_builder_instance

        # Mock timeout
        mock_post.side_effect = requests.exceptions.Timeout("Connection timeout")

        result = ocsp_checker.check(mock_cert, mock_issuer_cert)

        assert result.status == RevocationStatus.ERROR
        assert result.method == "OCSP"
        assert "timeout" in result.error_message.lower()

    @patch("pdfsigner.core.security.url_validator.validate_ocsp_url", side_effect=lambda url: url)
    @patch("pdfsigner.core.certificate.ocsp_checker.requests.post")
    @patch("pdfsigner.core.certificate.ocsp_checker.ocsp.OCSPRequestBuilder")
    @patch("pdfsigner.core.certificate.ocsp_checker.ocsp.load_der_ocsp_response")
    def test_check_cache_hit(
        self,
        mock_load_ocsp,
        mock_builder,
        mock_post,
        _mock_validate,
        ocsp_checker,
        mock_cert,
        mock_issuer_cert,
    ):
        """Test check uses cached response when available."""
        # Mock OCSP request building
        mock_request = Mock()
        mock_request.public_bytes.return_value = b"ocsp_request_data"
        mock_builder_instance = Mock()
        mock_builder_instance.add_certificate.return_value = mock_builder_instance
        mock_builder_instance.build.return_value = mock_request
        mock_builder.return_value = mock_builder_instance

        # Mock HTTP response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.content = b"ocsp_response_data"
        mock_post.return_value = mock_response

        # Mock OCSP response
        mock_ocsp_response = Mock()
        mock_ocsp_response.response_status = ocsp.OCSPResponseStatus.SUCCESSFUL
        mock_ocsp_response.certificate_status = ocsp.OCSPCertStatus.GOOD
        mock_load_ocsp.return_value = mock_ocsp_response

        # First call - cache miss, should make HTTP request
        result1 = ocsp_checker.check(mock_cert, mock_issuer_cert)

        # Verify first call made HTTP request
        assert mock_post.call_count == 1

        # Second call - should use cache, no new HTTP request
        result2 = ocsp_checker.check(mock_cert, mock_issuer_cert)

        assert result1.status == RevocationStatus.GOOD
        assert result2.status == RevocationStatus.GOOD
        # Still only 1 call - second used cache
        assert mock_post.call_count == 1

    def test_clear_cache(self, ocsp_checker):
        """Test clear_cache empties the cache."""
        # Add dummy entry to cache
        ocsp_checker._cache["test_key"] = Mock()
        assert len(ocsp_checker._cache) > 0

        ocsp_checker.clear_cache()

        assert len(ocsp_checker._cache) == 0


class TestCRLChecker:
    """Tests for CRLChecker class."""

    @pytest.fixture
    def mock_cert_with_crl(self):
        """Create a mock certificate with CRL distribution point."""
        cert = Mock(spec=x509.Certificate)
        cert.serial_number = 987654321
        cert.subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate")])

        # Mock CRL distribution points
        mock_crl_ext = Mock()
        mock_dist_point = Mock()
        mock_dist_point.full_name = [
            Mock(value="http://crl.example.com/test.crl", spec=x509.UniformResourceIdentifier)
        ]
        mock_crl_ext.value = [mock_dist_point]

        cert.extensions.get_extension_for_oid.return_value = mock_crl_ext

        return cert

    @pytest.fixture
    def crl_checker(self):
        """Create CRLChecker instance."""
        return CRLChecker(timeout=20)

    def test_initialization(self):
        """Test CRLChecker initialization."""
        checker = CRLChecker(timeout=45)
        assert checker.timeout == 45
        assert isinstance(checker._cache, dict)
        assert len(checker._cache) == 0

    def test_check_no_crl_urls(self, crl_checker):
        """Test check returns UNKNOWN when certificate has no CRL URLs."""
        cert = Mock(spec=x509.Certificate)
        cert.extensions.get_extension_for_oid.side_effect = x509.ExtensionNotFound(
            "Not found", ExtensionOID.CRL_DISTRIBUTION_POINTS
        )

        result = crl_checker.check(cert)

        assert result.status == RevocationStatus.UNKNOWN
        assert result.method == "CRL"
        assert "No CRL distribution points" in result.error_message

    @patch("pdfsigner.core.security.url_validator.validate_crl_url", side_effect=lambda url: url)
    @patch("pdfsigner.core.certificate.crl_checker.requests.get")
    @patch("pdfsigner.core.certificate.crl_checker.x509.load_der_x509_crl")
    def test_check_crl_good_status(
        self, mock_load_crl, mock_get, _mock_validate, crl_checker, mock_cert_with_crl
    ):
        """Test check returns GOOD when certificate not in CRL."""
        # Mock HTTP response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.content = b"crl_data"
        mock_get.return_value = mock_response

        # Mock CRL
        mock_crl = Mock()
        mock_crl.next_update_utc = datetime.now(UTC) + timedelta(days=1)
        mock_crl.get_revoked_certificate_by_serial_number.return_value = None
        mock_load_crl.return_value = mock_crl

        result = crl_checker.check(mock_cert_with_crl)

        assert result.status == RevocationStatus.GOOD
        assert result.method == "CRL"
        assert result.responder_url == "http://crl.example.com/test.crl"

    @patch("pdfsigner.core.security.url_validator.validate_crl_url", side_effect=lambda url: url)
    @patch("pdfsigner.core.certificate.crl_checker.requests.get")
    @patch("pdfsigner.core.certificate.crl_checker.x509.load_der_x509_crl")
    def test_check_crl_revoked_status(
        self, mock_load_crl, mock_get, _mock_validate, crl_checker, mock_cert_with_crl
    ):
        """Test check returns REVOKED when certificate is in CRL."""
        # Mock HTTP response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.content = b"crl_data"
        mock_get.return_value = mock_response

        # Mock revoked certificate entry
        mock_revoked_cert = Mock()
        mock_revoked_cert.revocation_date_utc = datetime.now(UTC) - timedelta(days=7)
        mock_revoked_cert.extensions.get_extension_for_oid.side_effect = x509.ExtensionNotFound(
            "Not found", CRLEntryExtensionOID.CRL_REASON
        )

        # Mock CRL
        mock_crl = Mock()
        mock_crl.next_update_utc = datetime.now(UTC) + timedelta(days=1)
        mock_crl.get_revoked_certificate_by_serial_number.return_value = mock_revoked_cert
        mock_load_crl.return_value = mock_crl

        result = crl_checker.check(mock_cert_with_crl)

        assert result.status == RevocationStatus.REVOKED
        assert result.method == "CRL"
        assert result.revocation_time is not None

    @patch("pdfsigner.core.security.url_validator.validate_crl_url", side_effect=lambda url: url)
    @patch("pdfsigner.core.certificate.crl_checker.requests.get")
    @patch("pdfsigner.core.certificate.crl_checker.x509.load_der_x509_crl")
    def test_check_crl_cache_hit(
        self, mock_load_crl, mock_get, _mock_validate, crl_checker, mock_cert_with_crl
    ):
        """Test check uses cached CRL when available."""
        # Mock HTTP response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.content = b"crl_data"
        mock_get.return_value = mock_response

        # Mock CRL
        mock_crl = Mock()
        mock_crl.next_update_utc = datetime.now(UTC) + timedelta(days=1)
        mock_crl.get_revoked_certificate_by_serial_number.return_value = None
        mock_load_crl.return_value = mock_crl

        # First call - cache miss
        result1 = crl_checker.check(mock_cert_with_crl)

        # Verify first call made HTTP request
        assert mock_get.call_count == 1

        # Second call - should use cache
        result2 = crl_checker.check(mock_cert_with_crl)

        assert result1.status == RevocationStatus.GOOD
        assert result2.status == RevocationStatus.GOOD
        # Still only 1 call - second used cache
        assert mock_get.call_count == 1

    @patch("pdfsigner.core.security.url_validator.validate_crl_url", side_effect=lambda url: url)
    @patch("pdfsigner.core.certificate.crl_checker.requests.get")
    def test_check_crl_download_error(
        self, mock_get, _mock_validate, crl_checker, mock_cert_with_crl
    ):
        """Test check handles CRL download errors."""
        mock_get.side_effect = requests.exceptions.RequestException("Network error")

        result = crl_checker.check(mock_cert_with_crl)

        assert result.status == RevocationStatus.ERROR
        assert result.method == "CRL"
        assert "failed" in result.error_message.lower()

    def test_clear_cache(self, crl_checker):
        """Test clear_cache empties the cache."""
        # Add dummy entry to cache
        crl_checker._cache["test_url"] = Mock()
        assert len(crl_checker._cache) > 0

        crl_checker.clear_cache()

        assert len(crl_checker._cache) == 0


class TestRevocationChecker:
    """Tests for main RevocationChecker class."""

    @pytest.fixture
    def revocation_checker(self):
        """Create RevocationChecker instance."""
        return RevocationChecker(
            ocsp_timeout=10, crl_timeout=30, ocsp_cache_ttl=600, prefer_ocsp=True
        )

    @pytest.fixture
    def mock_cert(self):
        """Create a mock certificate."""
        cert = Mock(spec=x509.Certificate)
        cert.serial_number = 123456789
        cert.subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate")])
        return cert

    @pytest.fixture
    def mock_issuer(self):
        """Create a mock issuer certificate."""
        issuer = Mock(spec=x509.Certificate)
        issuer.subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        return issuer

    def test_initialization(self):
        """Test RevocationChecker initialization."""
        checker = RevocationChecker(
            ocsp_timeout=15, crl_timeout=45, ocsp_cache_ttl=1800, prefer_ocsp=False
        )

        assert checker.prefer_ocsp is False
        assert isinstance(checker.ocsp_checker, OCSPChecker)
        assert isinstance(checker.crl_checker, CRLChecker)
        assert checker.ocsp_checker.timeout == 15
        assert checker.crl_checker.timeout == 45

    def test_check_revocation_ocsp_first_success(self, revocation_checker, mock_cert, mock_issuer):
        """Test check_revocation tries OCSP first and succeeds."""
        # Mock OCSP checker to return GOOD
        revocation_checker.ocsp_checker.check = Mock(
            return_value=RevocationResult(
                status=RevocationStatus.GOOD, method="OCSP", responder_url="http://ocsp.test"
            )
        )
        revocation_checker.crl_checker.check = Mock()

        result = revocation_checker.check_revocation(mock_cert, mock_issuer)

        assert result.status == RevocationStatus.GOOD
        assert result.method == "OCSP"
        # CRL should not be called
        revocation_checker.crl_checker.check.assert_not_called()

    def test_check_revocation_ocsp_fails_fallback_crl(
        self, revocation_checker, mock_cert, mock_issuer
    ):
        """Test check_revocation falls back to CRL when OCSP fails."""
        # Mock OCSP checker to return ERROR
        revocation_checker.ocsp_checker.check = Mock(
            return_value=RevocationResult(
                status=RevocationStatus.ERROR,
                method="OCSP",
                error_message="OCSP timeout",
            )
        )
        # Mock CRL checker to return GOOD
        revocation_checker.crl_checker.check = Mock(
            return_value=RevocationResult(
                status=RevocationStatus.GOOD, method="CRL", responder_url="http://crl.test"
            )
        )

        result = revocation_checker.check_revocation(mock_cert, mock_issuer)

        assert result.status == RevocationStatus.GOOD
        assert result.method == "CRL"
        # Both should be called
        revocation_checker.ocsp_checker.check.assert_called_once()
        revocation_checker.crl_checker.check.assert_called_once()

    def test_check_revocation_no_issuer_skips_ocsp(self, revocation_checker, mock_cert):
        """Test check_revocation skips OCSP when no issuer cert provided."""
        revocation_checker.ocsp_checker.check = Mock()
        revocation_checker.crl_checker.check = Mock(
            return_value=RevocationResult(
                status=RevocationStatus.GOOD, method="CRL", responder_url="http://crl.test"
            )
        )

        result = revocation_checker.check_revocation(mock_cert, issuer_cert=None)

        assert result.status == RevocationStatus.GOOD
        assert result.method == "CRL"
        # OCSP should not be called without issuer
        revocation_checker.ocsp_checker.check.assert_not_called()
        revocation_checker.crl_checker.check.assert_called_once()

    def test_check_revocation_both_fail_returns_unknown(
        self, revocation_checker, mock_cert, mock_issuer
    ):
        """Test check_revocation returns UNKNOWN when both OCSP and CRL fail."""
        revocation_checker.ocsp_checker.check = Mock(
            return_value=RevocationResult(
                status=RevocationStatus.ERROR,
                method="OCSP",
                error_message="OCSP failed",
            )
        )
        revocation_checker.crl_checker.check = Mock(
            return_value=RevocationResult(
                status=RevocationStatus.ERROR,
                method="CRL",
                error_message="CRL failed",
            )
        )

        result = revocation_checker.check_revocation(mock_cert, mock_issuer)

        assert result.status == RevocationStatus.UNKNOWN
        assert "Both OCSP and CRL" in result.error_message

    def test_check_revocation_prefer_crl_first(self, mock_cert, mock_issuer):
        """Test check_revocation tries CRL first when prefer_ocsp=False."""
        checker = RevocationChecker(prefer_ocsp=False)

        checker.crl_checker.check = Mock(
            return_value=RevocationResult(
                status=RevocationStatus.GOOD, method="CRL", responder_url="http://crl.test"
            )
        )
        checker.ocsp_checker.check = Mock()

        result = checker.check_revocation(mock_cert, mock_issuer)

        assert result.status == RevocationStatus.GOOD
        assert result.method == "CRL"
        # OCSP should not be called when CRL succeeds
        checker.ocsp_checker.check.assert_not_called()

    def test_clear_caches(self, revocation_checker):
        """Test clear_caches clears both OCSP and CRL caches."""
        revocation_checker.ocsp_checker.clear_cache = Mock()
        revocation_checker.crl_checker.clear_cache = Mock()

        revocation_checker.clear_caches()

        revocation_checker.ocsp_checker.clear_cache.assert_called_once()
        revocation_checker.crl_checker.clear_cache.assert_called_once()

    def test_check_revocation_returns_revoked_from_ocsp(
        self, revocation_checker, mock_cert, mock_issuer
    ):
        """Test check_revocation correctly returns REVOKED status from OCSP."""
        revocation_checker.ocsp_checker.check = Mock(
            return_value=RevocationResult(
                status=RevocationStatus.REVOKED,
                method="OCSP",
                responder_url="http://ocsp.test",
                revocation_time=datetime.now(UTC) - timedelta(days=3),
                revocation_reason="keyCompromise",
            )
        )

        result = revocation_checker.check_revocation(mock_cert, mock_issuer)

        assert result.status == RevocationStatus.REVOKED
        assert result.is_revoked is True
        assert result.is_valid is False
        assert result.revocation_time is not None
        assert result.revocation_reason == "keyCompromise"

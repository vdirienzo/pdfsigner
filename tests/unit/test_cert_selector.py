"""
test_cert_selector.py - Tests for certificate selection and filtering

Tests certificate validation, expiration checks, and selection logic.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from pdfsigner.core.token.cert_selector import CertificateSelector, ValidCertificate
from pdfsigner.core.token.nss_handler import CertificateInfo
from pdfsigner.exceptions import CertificateExpiredError, CertificateNotFoundError


def make_cert_info(
    label: str = "Test Cert",
    subject: str = "CN=Test User,O=Test Org",
    can_sign: bool = True,
    days_from_now: int = 365,
) -> CertificateInfo:
    """Helper to create CertificateInfo objects for testing."""
    not_before = datetime.now(UTC) - timedelta(days=30)
    not_after = datetime.now(UTC) + timedelta(days=days_from_now)

    return CertificateInfo(
        label=label,
        subject=subject,
        issuer="CN=Test CA",
        serial_number="123456",
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        can_sign=can_sign,
        pkcs11_id=b"test_cert_id",
    )


@pytest.fixture
def mock_nss():
    """Create mock NSSHandler."""
    return MagicMock()


class TestValidCertificate:
    """Tests for ValidCertificate dataclass."""

    def test_display_name_extracts_cn(self):
        """Display name should extract CN from subject."""
        cert_info = make_cert_info(
            label="my-cert",
            subject="CN=John A. Smith,O=Acme Corp,C=US",
        )
        valid_cert = ValidCertificate(
            info=cert_info,
            days_until_expiry=365,
            is_expiring_soon=False,
        )

        assert valid_cert.display_name == "John A. Smith"

    def test_display_name_fallback_to_label(self):
        """Display name should fallback to label if no CN."""
        cert_info = make_cert_info(
            label="my-cert-label",
            subject="O=Acme Corp,C=US",  # No CN
        )
        valid_cert = ValidCertificate(
            info=cert_info,
            days_until_expiry=365,
            is_expiring_soon=False,
        )

        assert valid_cert.display_name == "my-cert-label"

    def test_display_name_complex_subject(self):
        """Display name should handle complex subject strings."""
        cert_info = make_cert_info(
            label="cert",
            subject="CN=Mary O'Connor,OU=IT,O=Acme Corp,C=US",
        )
        valid_cert = ValidCertificate(
            info=cert_info,
            days_until_expiry=100,
            is_expiring_soon=False,
        )

        assert valid_cert.display_name == "Mary O'Connor"


class TestCertificateSelectorFilterExpired:
    """Tests for filtering expired certificates."""

    def test_filter_expired_certificates(self, mock_nss):
        """Expired certificates should be excluded."""
        mock_nss.list_certificates.return_value = [
            make_cert_info(label="valid", days_from_now=100),
            make_cert_info(label="expired", days_from_now=-1),  # Expired
            make_cert_info(label="also_valid", days_from_now=200),
        ]

        selector = CertificateSelector(mock_nss)
        valid_certs = selector.get_valid_certificates()

        labels = [c.info.label for c in valid_certs]
        assert "valid" in labels
        assert "also_valid" in labels
        assert "expired" not in labels

    def test_filter_expired_just_expired(self, mock_nss):
        """Certificate expired today should be excluded."""
        mock_nss.list_certificates.return_value = [
            make_cert_info(label="just_expired", days_from_now=0),
        ]

        selector = CertificateSelector(mock_nss)

        with pytest.raises(CertificateNotFoundError):
            selector.get_valid_certificates()


class TestCertificateSelectorFilterKeyUsage:
    """Tests for filtering by key usage."""

    def test_filter_invalid_key_usage(self, mock_nss):
        """Certificates without signing capability should be excluded."""
        mock_nss.list_certificates.return_value = [
            make_cert_info(label="can_sign", can_sign=True),
            make_cert_info(label="cannot_sign", can_sign=False),
            make_cert_info(label="also_can_sign", can_sign=True),
        ]

        selector = CertificateSelector(mock_nss)
        valid_certs = selector.get_valid_certificates()

        labels = [c.info.label for c in valid_certs]
        assert "can_sign" in labels
        assert "also_can_sign" in labels
        assert "cannot_sign" not in labels

    def test_filter_all_without_signing_raises(self, mock_nss):
        """Should raise if no certificates can sign."""
        mock_nss.list_certificates.return_value = [
            make_cert_info(label="enc_only", can_sign=False),
            make_cert_info(label="auth_only", can_sign=False),
        ]

        selector = CertificateSelector(mock_nss)

        with pytest.raises(CertificateNotFoundError, match="No valid certificates"):
            selector.get_valid_certificates()


class TestCertificateSelectorSorting:
    """Tests for certificate sorting."""

    def test_certificates_sorted_by_expiry(self, mock_nss):
        """Certificates should be sorted by expiration date (furthest first)."""
        mock_nss.list_certificates.return_value = [
            make_cert_info(label="short", days_from_now=30),
            make_cert_info(label="long", days_from_now=365),
            make_cert_info(label="medium", days_from_now=180),
        ]

        selector = CertificateSelector(mock_nss)
        valid_certs = selector.get_valid_certificates()

        # First should be the one with longest validity
        assert valid_certs[0].info.label == "long"
        assert valid_certs[1].info.label == "medium"
        assert valid_certs[2].info.label == "short"


class TestCertificateSelectorExpiringSoon:
    """Tests for expiring soon detection."""

    def test_marks_expiring_soon_certificates(self, mock_nss):
        """Certificates expiring within 30 days should be flagged."""
        mock_nss.list_certificates.return_value = [
            make_cert_info(label="expiring", days_from_now=15),
            make_cert_info(label="safe", days_from_now=60),
        ]

        selector = CertificateSelector(mock_nss)
        valid_certs = selector.get_valid_certificates()

        expiring = next(c for c in valid_certs if c.info.label == "expiring")
        safe = next(c for c in valid_certs if c.info.label == "safe")

        assert expiring.is_expiring_soon is True
        assert safe.is_expiring_soon is False

    def test_expiring_soon_threshold(self, mock_nss):
        """30 days should be marked as expiring soon, 32+ days should not."""
        mock_nss.list_certificates.return_value = [
            make_cert_info(label="at_threshold", days_from_now=30),
            make_cert_info(label="safely_over", days_from_now=35),  # Well beyond threshold
        ]

        selector = CertificateSelector(mock_nss)
        valid_certs = selector.get_valid_certificates()

        at_threshold = next(c for c in valid_certs if c.info.label == "at_threshold")
        safely_over = next(c for c in valid_certs if c.info.label == "safely_over")

        assert at_threshold.is_expiring_soon is True
        assert safely_over.is_expiring_soon is False


class TestGetDefaultCertificate:
    """Tests for get_default_certificate method."""

    def test_get_default_certificate(self, mock_nss):
        """Should return certificate with longest validity."""
        mock_nss.list_certificates.return_value = [
            make_cert_info(label="short", days_from_now=30),
            make_cert_info(label="longest", days_from_now=500),
            make_cert_info(label="medium", days_from_now=180),
        ]

        selector = CertificateSelector(mock_nss)
        default = selector.get_default_certificate()

        assert default.info.label == "longest"

    def test_get_default_certificate_no_certs_raises(self, mock_nss):
        """Should raise if no valid certificates."""
        mock_nss.list_certificates.return_value = []

        selector = CertificateSelector(mock_nss)

        with pytest.raises(CertificateNotFoundError):
            selector.get_default_certificate()


class TestSelectByLabel:
    """Tests for select_by_label method."""

    def test_select_by_label_success(self, mock_nss):
        """Should find certificate by its label."""
        mock_nss.list_certificates.return_value = [
            make_cert_info(label="cert_a", days_from_now=100),
            make_cert_info(label="cert_b", days_from_now=200),
            make_cert_info(label="cert_c", days_from_now=150),
        ]

        selector = CertificateSelector(mock_nss)
        selected = selector.select_by_label("cert_b")

        assert selected.info.label == "cert_b"

    def test_select_by_label_not_found_raises(self, mock_nss):
        """Should raise if label not found."""
        mock_nss.list_certificates.return_value = [
            make_cert_info(label="cert_a", days_from_now=100),
        ]

        selector = CertificateSelector(mock_nss)

        with pytest.raises(CertificateNotFoundError, match="not found"):
            selector.select_by_label("nonexistent")

    def test_select_by_label_expired_excluded(self, mock_nss):
        """Expired certificate should not be selectable by label."""
        mock_nss.list_certificates.return_value = [
            make_cert_info(label="expired_cert", days_from_now=-10),
            make_cert_info(label="valid_cert", days_from_now=100),
        ]

        selector = CertificateSelector(mock_nss)

        with pytest.raises(CertificateNotFoundError):
            selector.select_by_label("expired_cert")


class TestValidateCertificate:
    """Tests for validate_certificate method."""

    def test_validate_certificate_valid(self, mock_nss):
        """Valid certificate should pass validation."""
        cert_info = make_cert_info(days_from_now=100, can_sign=True)
        valid_cert = ValidCertificate(
            info=cert_info,
            days_until_expiry=100,
            is_expiring_soon=False,
        )

        selector = CertificateSelector(mock_nss)
        # Should not raise
        selector.validate_certificate(valid_cert)

    def test_validate_certificate_expired_raises(self, mock_nss):
        """Expired certificate should raise CertificateExpiredError."""
        cert_info = make_cert_info(days_from_now=-1, can_sign=True)
        expired_cert = ValidCertificate(
            info=cert_info,
            days_until_expiry=-1,
            is_expiring_soon=True,
        )

        selector = CertificateSelector(mock_nss)

        with pytest.raises(CertificateExpiredError):
            selector.validate_certificate(expired_cert)

    def test_validate_certificate_expiring_soon_allowed(self, mock_nss):
        """Expiring soon should be allowed by default."""
        cert_info = make_cert_info(days_from_now=15, can_sign=True)
        expiring_cert = ValidCertificate(
            info=cert_info,
            days_until_expiry=15,
            is_expiring_soon=True,
        )

        selector = CertificateSelector(mock_nss)
        # Should not raise with allow_expiring=True (default)
        selector.validate_certificate(expiring_cert, allow_expiring=True)

    def test_validate_certificate_expiring_soon_disallowed(self, mock_nss):
        """Expiring soon should raise when disallowed."""
        cert_info = make_cert_info(days_from_now=15, can_sign=True)
        expiring_cert = ValidCertificate(
            info=cert_info,
            days_until_expiry=15,
            is_expiring_soon=True,
        )

        selector = CertificateSelector(mock_nss)

        with pytest.raises(CertificateExpiredError):
            selector.validate_certificate(expiring_cert, allow_expiring=False)

    def test_validate_certificate_cannot_sign_raises(self, mock_nss):
        """Certificate without signing capability should raise."""
        cert_info = make_cert_info(days_from_now=100, can_sign=False)
        non_signing_cert = ValidCertificate(
            info=cert_info,
            days_until_expiry=100,
            is_expiring_soon=False,
        )

        selector = CertificateSelector(mock_nss)

        with pytest.raises(CertificateNotFoundError, match="signing permission"):
            selector.validate_certificate(non_signing_cert)


class TestCertificateSelectorEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_certificate_list(self, mock_nss):
        """Empty certificate list should raise error."""
        mock_nss.list_certificates.return_value = []

        selector = CertificateSelector(mock_nss)

        with pytest.raises(CertificateNotFoundError, match="No valid certificates"):
            selector.get_valid_certificates()

    def test_invalid_date_format_skipped(self, mock_nss):
        """Certificates with invalid dates should be skipped."""
        valid = make_cert_info(label="valid", days_from_now=100)
        invalid = make_cert_info(label="invalid", days_from_now=100)
        # Corrupt the date
        invalid.not_after = "invalid-date-format"

        mock_nss.list_certificates.return_value = [valid, invalid]

        selector = CertificateSelector(mock_nss)
        valid_certs = selector.get_valid_certificates()

        labels = [c.info.label for c in valid_certs]
        assert "valid" in labels
        assert "invalid" not in labels

    def test_timezone_aware_dates(self, mock_nss):
        """Should handle timezone-aware dates correctly."""
        cert_info = CertificateInfo(
            label="tz_aware",
            subject="CN=Test",
            issuer="CN=CA",
            serial_number="123",
            not_before=(datetime.now(UTC) - timedelta(days=30)).isoformat(),
            not_after=(datetime.now(UTC) + timedelta(days=100)).isoformat(),
            can_sign=True,
            pkcs11_id=b"id",
        )

        mock_nss.list_certificates.return_value = [cert_info]

        selector = CertificateSelector(mock_nss)
        valid_certs = selector.get_valid_certificates()

        assert len(valid_certs) == 1
        assert valid_certs[0].days_until_expiry == pytest.approx(100, abs=1)

    def test_naive_datetime_conversion(self, mock_nss):
        """Should handle naive datetime strings (no timezone)."""
        naive_time = datetime.now() + timedelta(days=50)
        cert_info = CertificateInfo(
            label="naive",
            subject="CN=Test",
            issuer="CN=CA",
            serial_number="123",
            not_before=datetime.now().isoformat(),
            not_after=naive_time.isoformat(),  # No timezone info
            can_sign=True,
            pkcs11_id=b"id",
        )

        mock_nss.list_certificates.return_value = [cert_info]

        selector = CertificateSelector(mock_nss)
        valid_certs = selector.get_valid_certificates()

        assert len(valid_certs) == 1

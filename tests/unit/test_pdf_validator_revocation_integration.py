"""
test_pdf_validator_revocation_integration.py - RevocationChecker integration tests

Author: Homero Thompson del Lago del Terror

Tests for the integration between PDFValidator and RevocationChecker,
focusing on the _check_revocation_status method and its integration
with validate_signatures.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from pdfsigner.core.certificate import ChainStatus, ChainValidationResult
from pdfsigner.core.certificate.revocation_checker import (
    RevocationResult,
    RevocationStatus,
)
from pdfsigner.core.validator.pdf_validator import (
    PDFValidator,
    SignatureStatus,
)


class TestCheckRevocationStatus:
    """Tests for _check_revocation_status method."""

    @pytest.fixture
    def validator(self):
        """Create PDFValidator instance."""
        return PDFValidator()

    @pytest.fixture
    def mock_cert(self):
        """Create a mock certificate."""
        cert = Mock(spec=x509.Certificate)
        cert.serial_number = 123456789
        cert.subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test User")])
        return cert

    @pytest.fixture
    def mock_issuer_cert(self):
        """Create a mock issuer certificate."""
        issuer = Mock(spec=x509.Certificate)
        issuer.subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        return issuer

    def test_check_revocation_status_disabled(self, validator, mock_cert, mock_issuer_cert):
        """Test _check_revocation_status returns None when disabled in settings."""
        with patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings:
            mock_settings.return_value.revocation_check_enabled = False

            status, message = validator._check_revocation_status(mock_cert, mock_issuer_cert)

            assert status is None
            assert message is None

    def test_check_revocation_status_with_valid_certificate(
        self, validator, mock_cert, mock_issuer_cert
    ):
        """Test _check_revocation_status with valid (GOOD) certificate."""
        with (
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
        ):
            # Enable revocation check
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = True
            mock_settings.return_value.revocation_check_timeout = 10
            mock_settings.return_value.revocation_cache_ttl = 300

            # Mock RevocationChecker to return GOOD status
            mock_checker = Mock()
            mock_result = RevocationResult(
                status=RevocationStatus.GOOD,
                method="OCSP",
                responder_url="http://ocsp.example.com",
            )
            mock_checker.check_revocation.return_value = mock_result
            mock_checker_class.return_value = mock_checker

            status, message = validator._check_revocation_status(mock_cert, mock_issuer_cert)

            assert status == "valid"
            assert message == "Valid (OCSP)"
            mock_checker.check_revocation.assert_called_once_with(mock_cert, mock_issuer_cert)

    def test_check_revocation_status_with_revoked_certificate(
        self, validator, mock_cert, mock_issuer_cert
    ):
        """Test _check_revocation_status with revoked certificate."""
        with (
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
        ):
            # Enable revocation check
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = True
            mock_settings.return_value.revocation_check_timeout = 10
            mock_settings.return_value.revocation_cache_ttl = 300

            # Mock RevocationChecker to return REVOKED status
            revocation_time = datetime.now(UTC) - timedelta(days=5)
            mock_checker = Mock()
            mock_result = RevocationResult(
                status=RevocationStatus.REVOKED,
                method="OCSP",
                responder_url="http://ocsp.example.com",
                revocation_time=revocation_time,
                revocation_reason="keyCompromise",
            )
            mock_checker.check_revocation.return_value = mock_result
            mock_checker_class.return_value = mock_checker

            status, message = validator._check_revocation_status(mock_cert, mock_issuer_cert)

            assert status == "revoked"
            assert "REVOKED on" in message
            assert "keyCompromise" in message

    def test_check_revocation_status_with_revoked_no_reason(
        self, validator, mock_cert, mock_issuer_cert
    ):
        """Test _check_revocation_status with revoked certificate without reason."""
        with (
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
        ):
            # Enable revocation check
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = True
            mock_settings.return_value.revocation_check_timeout = 10
            mock_settings.return_value.revocation_cache_ttl = 300

            # Mock RevocationChecker to return REVOKED status without reason
            revocation_time = datetime.now(UTC) - timedelta(days=3)
            mock_checker = Mock()
            mock_result = RevocationResult(
                status=RevocationStatus.REVOKED,
                method="CRL",
                responder_url="http://crl.example.com/test.crl",
                revocation_time=revocation_time,
                revocation_reason=None,
            )
            mock_checker.check_revocation.return_value = mock_result
            mock_checker_class.return_value = mock_checker

            status, message = validator._check_revocation_status(mock_cert, mock_issuer_cert)

            assert status == "revoked"
            assert "REVOKED on" in message
            # Should not include reason in parentheses
            assert "(" not in message or message.endswith(")")

    def test_check_revocation_status_with_unknown_status(
        self, validator, mock_cert, mock_issuer_cert
    ):
        """Test _check_revocation_status with unknown status (no OCSP/CRL endpoints)."""
        with (
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
        ):
            # Enable revocation check
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = True
            mock_settings.return_value.revocation_check_timeout = 10
            mock_settings.return_value.revocation_cache_ttl = 300

            # Mock RevocationChecker to return UNKNOWN status
            mock_checker = Mock()
            mock_result = RevocationResult(
                status=RevocationStatus.UNKNOWN,
                method="",
                error_message="No OCSP or CRL endpoints found",
            )
            mock_checker.check_revocation.return_value = mock_result
            mock_checker_class.return_value = mock_checker

            status, message = validator._check_revocation_status(mock_cert, mock_issuer_cert)

            assert status == "unknown"
            assert message == "No OCSP/CRL endpoints"

    def test_check_revocation_status_timeout_handling(self, validator, mock_cert, mock_issuer_cert):
        """Test _check_revocation_status handles timeout errors correctly."""
        with (
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
        ):
            # Enable revocation check
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = True
            mock_settings.return_value.revocation_check_timeout = 5
            mock_settings.return_value.revocation_cache_ttl = 300

            # Mock RevocationChecker to return ERROR status (timeout)
            mock_checker = Mock()
            mock_result = RevocationResult(
                status=RevocationStatus.ERROR,
                method="OCSP",
                error_message="Connection timeout after 5 seconds",
            )
            mock_checker.check_revocation.return_value = mock_result
            mock_checker_class.return_value = mock_checker

            status, message = validator._check_revocation_status(mock_cert, mock_issuer_cert)

            assert status == "error"
            assert "timeout" in message.lower()

    def test_check_revocation_status_network_error(self, validator, mock_cert, mock_issuer_cert):
        """Test _check_revocation_status handles network errors."""
        with (
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
        ):
            # Enable revocation check
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = True
            mock_settings.return_value.revocation_check_timeout = 10
            mock_settings.return_value.revocation_cache_ttl = 300

            # Mock RevocationChecker to return ERROR status
            mock_checker = Mock()
            mock_result = RevocationResult(
                status=RevocationStatus.ERROR,
                method="OCSP",
                error_message="Network unreachable",
            )
            mock_checker.check_revocation.return_value = mock_result
            mock_checker_class.return_value = mock_checker

            status, message = validator._check_revocation_status(mock_cert, mock_issuer_cert)

            assert status == "error"
            assert message == "Network unreachable"

    def test_check_revocation_status_exception_handling(
        self, validator, mock_cert, mock_issuer_cert
    ):
        """Test _check_revocation_status handles exceptions gracefully."""
        with (
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
        ):
            # Enable revocation check
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = True
            mock_settings.return_value.revocation_check_timeout = 10
            mock_settings.return_value.revocation_cache_ttl = 300

            # Mock RevocationChecker to raise exception
            mock_checker = Mock()
            mock_checker.check_revocation.side_effect = RuntimeError("Unexpected error")
            mock_checker_class.return_value = mock_checker

            status, message = validator._check_revocation_status(mock_cert, mock_issuer_cert)

            assert status == "error"
            assert message == "Unexpected error"

    def test_check_revocation_status_no_issuer_cert(self, validator, mock_cert):
        """Test _check_revocation_status when issuer cert is None."""
        with (
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
        ):
            # Enable revocation check
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = True
            mock_settings.return_value.revocation_check_timeout = 10
            mock_settings.return_value.revocation_cache_ttl = 300

            # Mock RevocationChecker - should be called with None issuer
            mock_checker = Mock()
            mock_result = RevocationResult(
                status=RevocationStatus.GOOD,
                method="CRL",
                responder_url="http://crl.example.com",
            )
            mock_checker.check_revocation.return_value = mock_result
            mock_checker_class.return_value = mock_checker

            status, message = validator._check_revocation_status(mock_cert, None)

            assert status == "valid"
            assert message == "Valid (CRL)"
            mock_checker.check_revocation.assert_called_once_with(mock_cert, None)

    def test_check_revocation_status_checker_initialization(
        self, validator, mock_cert, mock_issuer_cert
    ):
        """Test _check_revocation_status passes correct settings to RevocationChecker."""
        with (
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
        ):
            # Configure specific settings
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = False
            mock_settings.return_value.revocation_check_timeout = 25
            mock_settings.return_value.revocation_cache_ttl = 600

            # Mock RevocationChecker
            mock_checker = Mock()
            mock_result = RevocationResult(status=RevocationStatus.GOOD, method="CRL")
            mock_checker.check_revocation.return_value = mock_result
            mock_checker_class.return_value = mock_checker

            validator._check_revocation_status(mock_cert, mock_issuer_cert)

            # Verify RevocationChecker was initialized with correct parameters
            mock_checker_class.assert_called_once_with(
                prefer_ocsp=False,
                ocsp_timeout=25,
                crl_timeout=25,
                ocsp_cache_ttl=600,
            )


class TestValidateSignaturesWithRevocation:
    """Integration tests for validate_signatures with revocation checking."""

    @pytest.fixture
    def validator(self):
        """Create PDFValidator instance."""
        return PDFValidator()

    def test_validate_signature_with_revocation_check_enabled(self, validator, temp_dir: Path):
        """Test validate signature integrates revocation check when enabled."""
        from unittest.mock import mock_open

        pdf_path = temp_dir / "signed.pdf"

        # Create mock signature
        mock_sig = MagicMock()
        mock_sig.field_name = "Signature1"

        mock_cert = MagicMock()
        mock_cert.subject.human_friendly = "CN=Test User"
        mock_cert.issuer.human_friendly = "CN=Test CA"
        mock_cert.serial_number = 12345
        mock_cert.not_valid_before = datetime(2024, 1, 1)
        mock_cert.not_valid_after = datetime(2025, 1, 1)
        mock_cert.extensions = []
        mock_cert.dump.return_value = b"cert_bytes"
        mock_sig.signer_cert = mock_cert

        # Mock validation status
        mock_status = MagicMock()
        mock_status.valid = True
        mock_status.intact = True
        mock_status.timestamp_validity = None
        mock_status.coverage.value = 2
        mock_status.modification_level = None

        # Create mock crypto cert for chain validation
        mock_crypto_cert = Mock(spec=x509.Certificate)
        mock_crypto_issuer = Mock(spec=x509.Certificate)

        # Mock chain validation result
        mock_chain_result = ChainValidationResult(
            status=ChainStatus.VALID, chain=[mock_crypto_cert, mock_crypto_issuer]
        )

        with (
            patch("builtins.open", mock_open(read_data=b"%PDF-1.4")),
            patch("pdfsigner.core.validator.pdf_validator.PdfFileReader") as mock_reader_class,
            patch(
                "pdfsigner.core.validator.pdf_validator.validate_pdf_signature",
                return_value=mock_status,
            ),
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
            patch(
                "pdfsigner.core.validator.pdf_validator.x509.load_der_x509_certificate"
            ) as mock_load_cert,
        ):
            # Setup reader
            mock_reader = MagicMock()
            mock_reader.embedded_signatures = [mock_sig]
            mock_reader_class.return_value = mock_reader

            # Mock certificate loading
            mock_load_cert.return_value = mock_crypto_cert

            # Mock chain validator
            validator.chain_validator.validate_chain = Mock(return_value=mock_chain_result)

            # Enable revocation check
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = True
            mock_settings.return_value.revocation_check_timeout = 10
            mock_settings.return_value.revocation_cache_ttl = 300

            # Mock RevocationChecker
            mock_checker = Mock()
            mock_result = RevocationResult(
                status=RevocationStatus.GOOD,
                method="OCSP",
                responder_url="http://ocsp.example.com",
            )
            mock_checker.check_revocation.return_value = mock_result
            mock_checker_class.return_value = mock_checker

            result = validator.validate(pdf_path)

            assert result.is_signed is True
            assert len(result.signatures) == 1
            sig_info = result.signatures[0]
            assert sig_info.status == SignatureStatus.VALID
            assert sig_info.revocation_status == "valid"
            assert sig_info.revocation_message == "Valid (OCSP)"

    def test_validate_signature_with_revocation_check_disabled(self, validator, temp_dir: Path):
        """Test validate signature skips revocation check when disabled."""
        from unittest.mock import mock_open

        pdf_path = temp_dir / "signed.pdf"

        # Create mock signature
        mock_sig = MagicMock()
        mock_sig.field_name = "Signature1"

        mock_cert = MagicMock()
        mock_cert.subject.human_friendly = "CN=Test User"
        mock_cert.issuer.human_friendly = "CN=Test CA"
        mock_cert.serial_number = 12345
        mock_cert.not_valid_before = datetime(2024, 1, 1)
        mock_cert.not_valid_after = datetime(2025, 1, 1)
        mock_cert.extensions = []
        mock_cert.dump.return_value = b"cert_bytes"
        mock_sig.signer_cert = mock_cert

        # Mock validation status
        mock_status = MagicMock()
        mock_status.valid = True
        mock_status.intact = True
        mock_status.timestamp_validity = None
        mock_status.coverage.value = 2
        mock_status.modification_level = None

        with (
            patch("builtins.open", mock_open(read_data=b"%PDF-1.4")),
            patch("pdfsigner.core.validator.pdf_validator.PdfFileReader") as mock_reader_class,
            patch(
                "pdfsigner.core.validator.pdf_validator.validate_pdf_signature",
                return_value=mock_status,
            ),
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
        ):
            # Setup reader
            mock_reader = MagicMock()
            mock_reader.embedded_signatures = [mock_sig]
            mock_reader_class.return_value = mock_reader

            # Disable revocation check
            mock_settings.return_value.revocation_check_enabled = False

            result = validator.validate(pdf_path)

            assert result.is_signed is True
            assert len(result.signatures) == 1
            sig_info = result.signatures[0]
            assert sig_info.status == SignatureStatus.VALID
            # Revocation status should be None when disabled
            assert sig_info.revocation_status is None
            assert sig_info.revocation_message is None

    def test_validate_signature_with_revoked_certificate(self, validator, temp_dir: Path):
        """Test validate signature reports revoked certificate correctly."""
        from unittest.mock import mock_open

        pdf_path = temp_dir / "signed_revoked.pdf"

        # Create mock signature
        mock_sig = MagicMock()
        mock_sig.field_name = "Signature1"

        mock_cert = MagicMock()
        mock_cert.subject.human_friendly = "CN=Revoked User"
        mock_cert.issuer.human_friendly = "CN=Test CA"
        mock_cert.serial_number = 99999
        mock_cert.not_valid_before = datetime(2024, 1, 1)
        mock_cert.not_valid_after = datetime(2025, 1, 1)
        mock_cert.extensions = []
        mock_cert.dump.return_value = b"revoked_cert_bytes"
        mock_sig.signer_cert = mock_cert

        # Mock validation status (signature itself is valid, but cert is revoked)
        mock_status = MagicMock()
        mock_status.valid = True
        mock_status.intact = True
        mock_status.timestamp_validity = None
        mock_status.coverage.value = 2
        mock_status.modification_level = None

        revocation_time = datetime(2024, 6, 15, 10, 30, 0, tzinfo=UTC)

        # Create mock crypto cert for chain validation
        mock_crypto_cert = Mock(spec=x509.Certificate)
        mock_crypto_issuer = Mock(spec=x509.Certificate)

        # Mock chain validation result
        mock_chain_result = ChainValidationResult(
            status=ChainStatus.VALID, chain=[mock_crypto_cert, mock_crypto_issuer]
        )

        with (
            patch("builtins.open", mock_open(read_data=b"%PDF-1.4")),
            patch("pdfsigner.core.validator.pdf_validator.PdfFileReader") as mock_reader_class,
            patch(
                "pdfsigner.core.validator.pdf_validator.validate_pdf_signature",
                return_value=mock_status,
            ),
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
            patch(
                "pdfsigner.core.validator.pdf_validator.x509.load_der_x509_certificate"
            ) as mock_load_cert,
        ):
            # Setup reader
            mock_reader = MagicMock()
            mock_reader.embedded_signatures = [mock_sig]
            mock_reader_class.return_value = mock_reader

            # Mock certificate loading
            mock_load_cert.return_value = mock_crypto_cert

            # Mock chain validator
            validator.chain_validator.validate_chain = Mock(return_value=mock_chain_result)

            # Enable revocation check
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = True
            mock_settings.return_value.revocation_check_timeout = 10
            mock_settings.return_value.revocation_cache_ttl = 300

            # Mock RevocationChecker to return REVOKED
            mock_checker = Mock()
            mock_result = RevocationResult(
                status=RevocationStatus.REVOKED,
                method="OCSP",
                responder_url="http://ocsp.example.com",
                revocation_time=revocation_time,
                revocation_reason="certificateHold",
            )
            mock_checker.check_revocation.return_value = mock_result
            mock_checker_class.return_value = mock_checker

            result = validator.validate(pdf_path)

            assert result.is_signed is True
            assert len(result.signatures) == 1
            sig_info = result.signatures[0]
            # Signature is cryptographically valid
            assert sig_info.status == SignatureStatus.VALID
            # But certificate is revoked
            assert sig_info.revocation_status == "revoked"
            assert "REVOKED on" in sig_info.revocation_message
            assert "certificateHold" in sig_info.revocation_message

    def test_validate_multiple_signatures_mixed_revocation(self, validator, temp_dir: Path):
        """Test validate multiple signatures with mixed revocation statuses."""
        from unittest.mock import mock_open

        pdf_path = temp_dir / "multi_signed.pdf"

        # Create two mock signatures
        mock_sig1 = MagicMock()
        mock_sig1.field_name = "Signature1"
        mock_cert1 = MagicMock()
        mock_cert1.subject.human_friendly = "CN=Valid User"
        mock_cert1.issuer.human_friendly = "CN=Test CA"
        mock_cert1.serial_number = 11111
        mock_cert1.not_valid_before = datetime(2024, 1, 1)
        mock_cert1.not_valid_after = datetime(2025, 1, 1)
        mock_cert1.extensions = []
        mock_cert1.dump.return_value = b"cert1_bytes"
        mock_sig1.signer_cert = mock_cert1

        mock_sig2 = MagicMock()
        mock_sig2.field_name = "Signature2"
        mock_cert2 = MagicMock()
        mock_cert2.subject.human_friendly = "CN=Revoked User"
        mock_cert2.issuer.human_friendly = "CN=Test CA"
        mock_cert2.serial_number = 22222
        mock_cert2.not_valid_before = datetime(2024, 1, 1)
        mock_cert2.not_valid_after = datetime(2025, 1, 1)
        mock_cert2.extensions = []
        mock_cert2.dump.return_value = b"cert2_bytes"
        mock_sig2.signer_cert = mock_cert2

        # Mock validation statuses
        mock_status1 = MagicMock()
        mock_status1.valid = True
        mock_status1.intact = True
        mock_status1.timestamp_validity = None
        mock_status1.coverage.value = 2
        mock_status1.modification_level = None

        mock_status2 = MagicMock()
        mock_status2.valid = True
        mock_status2.intact = True
        mock_status2.timestamp_validity = None
        mock_status2.coverage.value = 2
        mock_status2.modification_level = None

        # Create mock crypto certs for chain validation
        mock_crypto_cert1 = Mock(spec=x509.Certificate)
        mock_crypto_issuer1 = Mock(spec=x509.Certificate)
        mock_crypto_cert2 = Mock(spec=x509.Certificate)
        mock_crypto_issuer2 = Mock(spec=x509.Certificate)

        # Mock chain validation results
        mock_chain_result1 = ChainValidationResult(
            status=ChainStatus.VALID, chain=[mock_crypto_cert1, mock_crypto_issuer1]
        )
        mock_chain_result2 = ChainValidationResult(
            status=ChainStatus.VALID, chain=[mock_crypto_cert2, mock_crypto_issuer2]
        )

        with (
            patch("builtins.open", mock_open(read_data=b"%PDF-1.4")),
            patch("pdfsigner.core.validator.pdf_validator.PdfFileReader") as mock_reader_class,
            patch("pdfsigner.core.validator.pdf_validator.validate_pdf_signature") as mock_validate,
            patch("pdfsigner.core.validator.pdf_validator.get_settings") as mock_settings,
            patch("pdfsigner.core.validator.pdf_validator.RevocationChecker") as mock_checker_class,
            patch(
                "pdfsigner.core.validator.pdf_validator.x509.load_der_x509_certificate"
            ) as mock_load_cert,
        ):
            # Setup reader
            mock_reader = MagicMock()
            mock_reader.embedded_signatures = [mock_sig1, mock_sig2]
            mock_reader_class.return_value = mock_reader

            # Return different status for each signature
            mock_validate.side_effect = [mock_status1, mock_status2]

            # Mock certificate loading - return different certs for each call
            mock_load_cert.side_effect = [mock_crypto_cert1, mock_crypto_cert2]

            # Mock chain validator - return different results per call
            validator.chain_validator.validate_chain = Mock(
                side_effect=[mock_chain_result1, mock_chain_result2]
            )

            # Enable revocation check
            mock_settings.return_value.revocation_check_enabled = True
            mock_settings.return_value.revocation_prefer_ocsp = True
            mock_settings.return_value.revocation_check_timeout = 10
            mock_settings.return_value.revocation_cache_ttl = 300

            # Mock RevocationChecker - return different results per call
            mock_checker = Mock()
            mock_result_good = RevocationResult(
                status=RevocationStatus.GOOD,
                method="OCSP",
                responder_url="http://ocsp.example.com",
            )
            mock_result_revoked = RevocationResult(
                status=RevocationStatus.REVOKED,
                method="OCSP",
                responder_url="http://ocsp.example.com",
                revocation_time=datetime.now(UTC) - timedelta(days=2),
                revocation_reason="keyCompromise",
            )
            mock_checker.check_revocation.side_effect = [mock_result_good, mock_result_revoked]
            mock_checker_class.return_value = mock_checker

            result = validator.validate(pdf_path)

            assert result.is_signed is True
            assert len(result.signatures) == 2

            # First signature - valid and not revoked
            sig1 = result.signatures[0]
            assert sig1.status == SignatureStatus.VALID
            assert sig1.revocation_status == "valid"
            assert sig1.revocation_message == "Valid (OCSP)"

            # Second signature - valid but revoked
            sig2 = result.signatures[1]
            assert sig2.status == SignatureStatus.VALID
            assert sig2.revocation_status == "revoked"
            assert "REVOKED on" in sig2.revocation_message
            assert "keyCompromise" in sig2.revocation_message

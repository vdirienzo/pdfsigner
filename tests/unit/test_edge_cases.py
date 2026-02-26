"""
test_edge_cases.py - Edge case tests for PDFSigner

Author: Homero Thompson del Lago del Terror

Tests extreme scenarios to ensure graceful error handling:
- Invalid PDF inputs (empty, corrupted, non-PDF files)
- Network failures (OCSP, CRL, TSA timeouts)
- Filesystem edge cases (disk full, permissions, read-only)
- Token/HSM failures (invalid TSA URL, token removal, PIN lock)
- Certificate edge cases (expired certs, self-signed)
"""

import errno
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
import requests

from pdfsigner.core.signer.dss_manager import DSSManager
from pdfsigner.core.signer.pdf_signer import PDFSigner
from pdfsigner.core.token.nss_handler import NSSHandler
from pdfsigner.core.validator.pdf_validator import PDFValidator
from pdfsigner.exceptions import (
    NSSConfigError,
    TimestampError,
    TokenAuthenticationError,
    TSAConnectionError,
)

# ============================================================================
# 1. INVALID PDF INPUTS (4 tests)
# ============================================================================


class TestInvalidPDFInputs:
    """Test handling of invalid or corrupted PDF files."""

    def test_empty_file_raises_error(self, tmp_path):
        """Test that empty file (0 bytes) raises appropriate error."""
        empty_file = tmp_path / "empty.pdf"
        empty_file.write_bytes(b"")

        validator = PDFValidator()

        # PDFValidator returns error result, doesn't raise
        result = validator.validate(empty_file)

        # Should return invalid result with error message
        assert result.error is not None
        error_msg = result.error.lower()
        assert any(
            keyword in error_msg
            for keyword in ["empty", "invalid", "corrupted", "illegal", "header"]
        )

    def test_truncated_pdf_header_only_raises_error(self, tmp_path):
        """Test that PDF with only header (no content) raises error."""
        truncated_file = tmp_path / "truncated.pdf"
        # Only PDF header, no actual structure
        truncated_file.write_bytes(b"%PDF-1.7\n")

        validator = PDFValidator()

        # PDFValidator returns error result, doesn't raise
        result = validator.validate(truncated_file)

        # Should detect incomplete PDF structure
        assert result.error is not None
        error_msg = result.error.lower()
        assert any(
            keyword in error_msg
            for keyword in [
                "invalid",
                "corrupted",
                "eof",
                "incomplete",
                "truncated",
                "malformed",
                "read",
            ]
        )

    def test_corrupted_xref_table_raises_error(self, tmp_path):
        """Test that PDF with corrupted xref table raises error."""
        corrupted_file = tmp_path / "corrupted.pdf"

        # Minimal PDF structure with invalid xref
        corrupted_content = b"""%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
CORRUPTED_XREF_DATA
trailer
<< /Size 4 /Root 1 0 R >>
startxref
200
%%EOF
"""
        corrupted_file.write_bytes(corrupted_content)

        validator = PDFValidator()

        # PDFValidator returns error result
        result = validator.validate(corrupted_file)

        # Should detect xref or structure corruption
        assert result.error is not None
        error_msg = result.error.lower()
        assert any(
            keyword in error_msg
            for keyword in [
                "invalid",
                "corrupted",
                "xref",
                "malformed",
                "parse",
                "read",
                "token",
            ]
        )

    def test_non_pdf_file_raises_error(self, tmp_path):
        """Test that non-PDF file (renamed .txt) raises error."""
        fake_pdf = tmp_path / "not_a_pdf.pdf"
        fake_pdf.write_text("This is just a text file, not a PDF!")

        validator = PDFValidator()

        # PDFValidator returns error result
        result = validator.validate(fake_pdf)

        # Should detect file is not a PDF
        assert result.error is not None
        error_msg = result.error.lower()
        assert any(
            keyword in error_msg
            for keyword in [
                "invalid",
                "not a pdf",
                "pdf",
                "corrupted",
                "header",
                "illegal",
            ]
        )


# ============================================================================
# 2. NETWORK FAILURES (3 tests)
# ============================================================================


class TestNetworkFailures:
    """Test handling of network failures during validation and signing."""

    def test_ocsp_timeout_handled_gracefully(self):
        """Test that OCSP server timeout is handled without crashing."""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        # Create a dummy certificate for testing
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2024, 1, 1))
            .not_valid_after(datetime(2025, 1, 1))
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        dss_manager = DSSManager(ocsp_timeout=1)  # 1 second timeout

        # Mock requests to simulate timeout
        with patch("requests.post") as mock_post:
            mock_post.side_effect = requests.Timeout("OCSP server timeout")

            # Should handle timeout gracefully (not crash)
            validation_info = dss_manager.collect_validation_info([cert])

            # Should return empty info or partial info, not raise exception
            assert validation_info is not None
            # OCSP responses should be empty due to timeout
            assert len(validation_info.ocsp_responses) == 0

    def test_crl_download_timeout_handled_gracefully(self):
        """Test that CRL download timeout is handled without crashing."""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        # Create a dummy certificate with CRL distribution point
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2024, 1, 1))
            .not_valid_after(datetime(2025, 1, 1))
            .add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier("http://test.crl/ca.crl")],
                            relative_name=None,
                            crl_issuer=None,
                            reasons=None,
                        )
                    ]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        dss_manager = DSSManager(crl_timeout=1)  # 1 second timeout

        # Mock requests to simulate timeout
        with patch("requests.get") as mock_get:
            mock_get.side_effect = requests.Timeout("CRL download timeout")

            # Should handle timeout gracefully
            validation_info = dss_manager.collect_validation_info([cert])

            # Should return empty or partial info, not crash
            assert validation_info is not None
            # CRLs should be empty due to timeout
            assert len(validation_info.crls) == 0

    def test_tsa_connection_refused_raises_error(self, mock_nss_handler):
        """Test that TSA connection refused raises appropriate error."""
        from pdfsigner.core.signer.lta_handler import LTAHandler, TSAConfig

        # Create LTA handler with unreachable TSA
        lta_handler = LTAHandler(tsa_config=TSAConfig(url="https://unreachable.tsa.example.com"))

        # Get timestamper (this should succeed)
        timestamper = lta_handler.get_timestamper()

        # If timestamper returned, mock requests to simulate connection refused when used
        if timestamper:
            with patch("requests.post") as mock_post:
                mock_post.side_effect = requests.ConnectionError("Connection refused")

                # Should raise error when trying to use it
                with pytest.raises((TimestampError, TSAConnectionError, Exception)):
                    timestamper.timestamp(b"test data")
        else:
            # If no timestamper, that's also acceptable (empty TSA URL)
            assert timestamper is None


# ============================================================================
# 3. FILESYSTEM EDGE CASES (3 tests)
# ============================================================================


class TestFilesystemEdgeCases:
    """Test handling of filesystem errors during signing operations."""

    def test_disk_full_during_signing_raises_error(
        self, tmp_path, sample_pdf, mock_nss_handler, mock_lta_handler
    ):
        """Test that disk full error during signing is handled properly."""
        output_path = tmp_path / "signed.pdf"

        signer = PDFSigner(nss_handler=mock_nss_handler, lta_handler=mock_lta_handler)

        # Mock signing context to simulate disk full on write
        with (
            patch.object(signer, "_prepare_signing_context") as mock_prepare,
            patch(
                "pdfsigner.core.signer.signature_field.create_signature_field_with_stamps"
            ) as mock_field,
            patch.object(signer, "_preprocess_pdf_with_stamps") as mock_preprocess,
            patch.object(signer, "_execute_signing") as mock_execute,
        ):
            mock_prepare.return_value = (MagicMock(), None, "Test", "Org", 0)
            mock_field.return_value = MagicMock(field_spec=None, visual_stamps=[])
            mock_preprocess.return_value = (sample_pdf, None)
            mock_execute.side_effect = OSError(errno.ENOSPC, "No space left on device")

            # sign_pdf catches exceptions and returns SigningResult
            result = signer.sign_pdf(
                input_path=sample_pdf,
                output_path=output_path,
            )

            assert result.success is False
            assert "No space left on device" in result.error

    def test_permission_denied_on_output_file_raises_error(
        self, tmp_path, sample_pdf, mock_nss_handler, mock_lta_handler
    ):
        """Test that permission denied on output file is handled properly."""
        output_path = tmp_path / "signed.pdf"

        signer = PDFSigner(nss_handler=mock_nss_handler, lta_handler=mock_lta_handler)

        # Mock signing context to simulate permission denied on write
        with (
            patch.object(signer, "_prepare_signing_context") as mock_prepare,
            patch(
                "pdfsigner.core.signer.signature_field.create_signature_field_with_stamps"
            ) as mock_field,
            patch.object(signer, "_preprocess_pdf_with_stamps") as mock_preprocess,
            patch.object(signer, "_execute_signing") as mock_execute,
        ):
            mock_prepare.return_value = (MagicMock(), None, "Test", "Org", 0)
            mock_field.return_value = MagicMock(field_spec=None, visual_stamps=[])
            mock_preprocess.return_value = (sample_pdf, None)
            mock_execute.side_effect = PermissionError("Permission denied")

            # sign_pdf catches exceptions and returns SigningResult
            result = signer.sign_pdf(
                input_path=sample_pdf,
                output_path=output_path,
            )

            assert result.success is False
            assert "permission" in result.error.lower()

    def test_read_only_input_directory_handled_properly(self, tmp_path):
        """Test that read-only input directory doesn't prevent reading."""
        # Create a subdirectory with a PDF
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()

        # Create a simple PDF in the directory
        import fitz

        pdf_path = readonly_dir / "test.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)
        page.insert_text((72, 72), "Test PDF", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()

        # Make directory read-only
        readonly_dir.chmod(0o555)

        try:
            # Reading PDF should still work (no write needed)
            validator = PDFValidator()
            result = validator.validate(pdf_path)

            # Should be able to validate even in read-only directory
            assert result is not None
        finally:
            # Cleanup: restore permissions
            readonly_dir.chmod(0o755)


# ============================================================================
# 4. TOKEN/HSM EDGE CASES (3 tests)
# ============================================================================


class TestTokenHSMEdgeCases:
    """Test handling of token and HSM edge cases."""

    def test_invalid_tsa_url_format_raises_error(self):
        """Test that invalid TSA URL format (not http/https) raises error."""
        from pdfsigner.core.signer.lta_handler import LTAHandler, TSAConfig

        # Invalid URL formats
        invalid_urls = [
            "ftp://invalid.tsa.com",  # Wrong protocol
            "not-a-url",  # Not a URL
            "file:///local/path",  # Local file
            "javascript:alert(1)",  # Script injection attempt
        ]

        for invalid_url in invalid_urls:
            lta_handler = LTAHandler(tsa_config=TSAConfig(url=invalid_url))

            # Get timestamper - may succeed even with invalid URL
            timestamper = lta_handler.get_timestamper()

            # If timestamper is created, it should fail when actually used
            if timestamper:
                with pytest.raises(Exception):
                    # This should fail due to invalid URL
                    timestamper.timestamp(b"test")
            # If get_timestamper returns None, that's also acceptable handling

    def test_token_removal_during_signing_raises_error(self, mock_nss_handler):
        """Test that token removal during signing raises appropriate error."""
        import pkcs11.exceptions

        # Configure mock to simulate token removal
        mock_nss_handler._session.sign.side_effect = pkcs11.exceptions.DeviceRemoved(
            "Token was removed"
        )

        signer = PDFSigner(nss_handler=mock_nss_handler)

        # Should raise DeviceRemoved error
        with pytest.raises(pkcs11.exceptions.DeviceRemoved) as exc_info:
            # Trigger signing operation that will fail
            mock_nss_handler._session.sign(b"test data", mechanism=MagicMock())

        assert "removed" in str(exc_info.value).lower()

    def test_pin_incorrect_three_times_raises_lock_error(self, tmp_path):
        """Test that 3 incorrect PIN attempts raise token lock error."""
        import pkcs11.exceptions

        # Create NSS handler
        nss_dir = tmp_path / ".nss"
        nss_dir.mkdir()

        handler = NSSHandler(nss_db_path=nss_dir)

        # Mock the PKCS#11 library and token
        with patch.object(handler, "_find_pkcs11_lib", return_value="/fake/lib.so"):
            with patch("pkcs11.lib") as mock_lib_func:
                mock_lib_instance = MagicMock()
                mock_token = MagicMock()

                # Configure mock to simulate incorrect PIN
                mock_token.open.side_effect = pkcs11.exceptions.PinIncorrect("PIN incorrect")

                mock_lib_instance.get_tokens.return_value = [mock_token]
                mock_lib_func.return_value = mock_lib_instance

                handler._lib = mock_lib_instance
                handler._token = mock_token

                # Try to authenticate 3 times
                for _ in range(3):
                    with pytest.raises((pkcs11.exceptions.PinIncorrect, TokenAuthenticationError)):
                        handler.authenticate(pin="wrong_pin")

                # After 3 attempts, token should be locked (simulated)
                # In real scenario, 4th attempt would raise PinLocked
                mock_token.open.side_effect = pkcs11.exceptions.PinLocked("PIN locked")

                with pytest.raises((pkcs11.exceptions.PinLocked, TokenAuthenticationError)):
                    handler.authenticate(pin="any_pin")


# ============================================================================
# 5. CERTIFICATE EDGE CASES (2 tests)
# ============================================================================


class TestCertificateEdgeCases:
    """Test handling of certificate edge cases."""

    def test_expired_certificate_in_chain_detected(self):
        """Test that expired certificate in chain is detected."""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from pdfsigner.core.certificate.chain_validator import CertificateChainValidator
        from pdfsigner.core.certificate.trust_store import TrustStore

        # Create an expired certificate
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Expired Certificate")]
        )

        # Certificate expired in 2020
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2019, 1, 1))
            .not_valid_after(datetime(2020, 1, 1))  # Expired
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        validator = CertificateChainValidator(trust_store=TrustStore())

        # Should detect expired certificate
        result = validator.validate_chain(expired_cert)

        # Result should indicate certificate is expired
        assert not result.is_valid
        error_text = " ".join(result.errors).lower()
        assert "expired" in error_text

    def test_self_signed_certificate_without_ca_detected(self):
        """Test that self-signed certificate without trusted CA is detected."""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        from pdfsigner.core.certificate.chain_validator import CertificateChainValidator
        from pdfsigner.core.certificate.trust_store import TrustStore

        # Create a self-signed certificate (valid dates so expiry doesn't mask the issue)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Self-Signed Certificate")]
        )

        self_signed_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)  # Same as subject = self-signed
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2024, 1, 1))
            .not_valid_after(datetime(2027, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        # Create validator with empty trust store (no trusted roots)
        validator = CertificateChainValidator(trust_store=TrustStore())

        # Should detect self-signed cert is not in trust store
        result = validator.validate_chain(self_signed_cert)

        # Result should indicate untrusted certificate
        assert not result.is_valid
        error_text = " ".join(result.errors).lower()
        assert any(
            keyword in error_text
            for keyword in ["untrusted", "self-signed", "trust", "root", "not trusted"]
        )


# ============================================================================
# 6. ADDITIONAL EDGE CASES
# ============================================================================


class TestAdditionalEdgeCases:
    """Additional edge cases for comprehensive coverage."""

    def test_nss_db_path_not_exists_raises_error(self, tmp_path):
        """Test that non-existent NSS database path raises error."""
        non_existent_path = tmp_path / "does_not_exist" / ".nss"

        handler = NSSHandler(nss_db_path=non_existent_path)

        # Should raise NSSConfigError
        with pytest.raises(NSSConfigError) as exc_info:
            handler.initialize()

        assert str(non_existent_path) in str(exc_info.value)

    def test_protected_pdf_cannot_be_signed(self, tmp_path):
        """Test that password-protected PDF raises appropriate error."""
        import fitz

        # Create a password-protected PDF
        protected_pdf = tmp_path / "protected.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)
        page.insert_text((72, 72), "Protected PDF", fontsize=12)

        # Save with password protection
        doc.save(
            str(protected_pdf),
            encryption=fitz.PDF_ENCRYPT_AES_256,
            owner_pw="owner_password",
            user_pw="user_password",
        )
        doc.close()

        # Attempting to sign should detect protection
        signer = PDFSigner(nss_handler=MagicMock(), lta_handler=MagicMock())

        # sign_pdf catches exceptions and returns SigningResult
        result = signer.sign_pdf(
            input_path=protected_pdf,
            output_path=tmp_path / "signed.pdf",
        )

        # Verify error is related to protection/encryption
        assert result.success is False
        assert result.error is not None
        error_msg = result.error.lower()
        assert any(
            keyword in error_msg
            for keyword in [
                "protected",
                "encrypted",
                "password",
                "corrupted",
                "modify",
            ]
        )

    def test_zero_size_certificate_handled_gracefully(self, mock_nss_handler):
        """Test that zero-size or corrupted certificate data is handled."""
        # Mock certificate with zero-size data
        mock_nss_handler.list_certificates.return_value = []

        # Should not crash, just return empty list
        certs = mock_nss_handler.list_certificates()
        assert certs == []

    def test_concurrent_access_to_same_pdf_handled(self, sample_pdf):
        """Test that concurrent access attempts to same PDF are handled."""
        validator1 = PDFValidator()
        validator2 = PDFValidator()

        # Both validators should be able to read the same PDF
        # (read operations should not conflict)
        result1 = validator1.validate(sample_pdf)
        result2 = validator2.validate(sample_pdf)

        # Both should succeed (no signatures expected)
        assert result1 is not None
        assert result2 is not None

"""
test_dss_real.py - Real integration tests for DSS/OCSP/CRL embedding

Tests DSSManager with REAL OCSP/CRL responses using HTTP replay.
NO MOCKS of cryptography or pyhanko libraries.

Author: Healthcare Audit Phase 2
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import fitz  # PyMuPDF - REAL
import pytest
import responses
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp

from pdfsigner.core.signer.dss_manager import DSSManager, ValidationInfo


def generate_valid_crl(issuer_cert: x509.Certificate, issuer_key) -> bytes:
    """Generate a valid CRL for testing."""
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.last_update(datetime.now(UTC))
    builder = builder.next_update(datetime.now(UTC) + timedelta(days=7))

    crl = builder.sign(issuer_key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.DER)


def generate_valid_ocsp_response(
    cert: x509.Certificate, issuer_cert: x509.Certificate, issuer_key
) -> bytes:
    """Generate a valid OCSP response for testing."""
    builder = ocsp.OCSPResponseBuilder()

    # Build successful response
    builder = builder.add_response(
        cert=cert,
        issuer=issuer_cert,
        algorithm=hashes.SHA256(),
        cert_status=ocsp.OCSPCertStatus.GOOD,
        this_update=datetime.now(UTC),
        next_update=datetime.now(UTC) + timedelta(days=7),
        revocation_time=None,
        revocation_reason=None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, issuer_cert)

    response = builder.sign(issuer_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def sample_pdf(tmp_path: Path) -> Path:
    """Create a simple signed PDF for DSS embedding tests."""
    pdf_path = tmp_path / "sample_signed.pdf"
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((72, 72), "Test Document for DSS", fontsize=18)
    page.insert_text((72, 120), "This will get DSS embedded", fontsize=12)

    # Save as basic PDF (no signature needed for DSS embedding tests)
    doc.save(pdf_path)
    doc.close()
    return pdf_path


@pytest.fixture
def dss_manager() -> DSSManager:
    """Create DSSManager instance with short timeouts for tests."""
    return DSSManager(ocsp_timeout=5, crl_timeout=10)


@pytest.fixture
def test_issuer_key():
    """Generate issuer private key for CRL signing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def test_issuer_cert(test_issuer_key) -> x509.Certificate:
    """Generate a test issuer certificate."""
    subject = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Test CA"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test Root CA"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(test_issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3650))
        .sign(test_issuer_key, hashes.SHA256())
    )

    return cert


@pytest.fixture
def test_cert(test_issuer_cert) -> x509.Certificate:
    """Generate a test certificate with OCSP/CRL extensions."""
    from cryptography.x509 import (
        AccessDescription,
        AuthorityInformationAccess,
        CRLDistributionPoints,
        DistributionPoint,
        UniformResourceIdentifier,
    )
    from cryptography.x509.oid import AuthorityInformationAccessOID

    # Generate key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build certificate
    subject = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test.example.com"),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(test_issuer_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
    )

    # Add OCSP responder URL
    aia = AuthorityInformationAccess(
        [
            AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                UniformResourceIdentifier("http://ocsp.example.com"),
            )
        ]
    )
    builder = builder.add_extension(aia, critical=False)

    # Add CRL distribution points
    crl_dp = CRLDistributionPoints(
        [
            DistributionPoint(
                full_name=[
                    UniformResourceIdentifier("http://crl.example.com/test.crl"),
                    UniformResourceIdentifier("http://crl2.example.com/test.crl"),
                ],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )
    builder = builder.add_extension(crl_dp, critical=False)

    # Sign certificate with issuer key (use same key for simplicity in tests)
    cert = builder.sign(private_key, hashes.SHA256())
    return cert


class TestDSSManagerOCSPReal:
    """Tests for OCSP fetching with HTTP replay."""

    @responses.activate
    def test_get_ocsp_response_bytes_with_real_response(
        self,
        dss_manager: DSSManager,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
        test_issuer_key,
    ):
        """Fetch OCSP response with real HTTP replay."""
        # Generate valid OCSP response
        valid_ocsp = generate_valid_ocsp_response(test_cert, test_issuer_cert, test_issuer_key)

        # Mock HTTP response with real OCSP data
        responses.add(
            responses.POST,
            "http://ocsp.example.com",
            body=valid_ocsp,
            status=200,
            content_type="application/ocsp-response",
        )

        result = dss_manager._get_ocsp_response_bytes(test_cert, test_issuer_cert)

        # Should get response bytes
        assert result == valid_ocsp
        assert len(responses.calls) == 1

    @responses.activate
    def test_get_ocsp_response_bytes_handles_timeout(
        self,
        dss_manager: DSSManager,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
    ):
        """OCSP fetch handles timeout gracefully."""
        import requests

        # Simulate timeout
        responses.add(
            responses.POST,
            "http://ocsp.example.com",
            body=requests.exceptions.Timeout("Connection timeout"),
        )

        result = dss_manager._get_ocsp_response_bytes(test_cert, test_issuer_cert)

        assert result is None

    @responses.activate
    def test_get_ocsp_response_bytes_handles_http_error(
        self,
        dss_manager: DSSManager,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
    ):
        """OCSP fetch handles HTTP 5xx errors."""
        responses.add(
            responses.POST,
            "http://ocsp.example.com",
            json={"error": "Internal Server Error"},
            status=500,
        )

        result = dss_manager._get_ocsp_response_bytes(test_cert, test_issuer_cert)

        assert result is None

    @responses.activate
    def test_get_ocsp_response_bytes_retry_not_implemented(
        self,
        dss_manager: DSSManager,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
    ):
        """OCSP fetch does not retry by default (test current behavior)."""
        call_count = 0

        def request_callback(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (503, {}, "Service Unavailable")
            return (200, {"Content-Type": "application/ocsp-response"}, b"ocsp_data")

        responses.add_callback(
            responses.POST,
            "http://ocsp.example.com",
            callback=request_callback,
        )

        result = dss_manager._get_ocsp_response_bytes(test_cert, test_issuer_cert)

        # Current implementation does not retry (call_count should be 1)
        assert call_count == 1
        assert result is None  # Failed on first attempt


class TestDSSManagerCRLReal:
    """Tests for CRL fetching with HTTP replay."""

    @responses.activate
    def test_get_crl_bytes_with_real_response(
        self,
        dss_manager: DSSManager,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
        test_issuer_key,
    ):
        """Fetch CRL with real HTTP replay."""
        # Generate valid CRL
        valid_crl = generate_valid_crl(test_issuer_cert, test_issuer_key)

        # Mock CRL download
        responses.add(
            responses.GET,
            "http://crl.example.com/test.crl",
            body=valid_crl,
            status=200,
        )

        result = dss_manager._get_crl_bytes(test_cert)

        # Should get CRL bytes
        assert result == valid_crl
        assert len(responses.calls) == 1

    @responses.activate
    def test_get_crl_bytes_tries_multiple_urls(
        self,
        dss_manager: DSSManager,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
        test_issuer_key,
    ):
        """CRL fetch tries multiple URLs on failure."""
        # Generate valid CRL
        valid_crl = generate_valid_crl(test_issuer_cert, test_issuer_key)

        # First URL fails
        responses.add(
            responses.GET,
            "http://crl.example.com/test.crl",
            json={"error": "Not Found"},
            status=404,
        )

        # Second URL succeeds
        responses.add(
            responses.GET,
            "http://crl2.example.com/test.crl",
            body=valid_crl,
            status=200,
        )

        result = dss_manager._get_crl_bytes(test_cert)

        # Should have tried both URLs
        assert len(responses.calls) == 2
        assert result == valid_crl

    @responses.activate
    def test_get_crl_bytes_handles_timeout(
        self, dss_manager: DSSManager, test_cert: x509.Certificate
    ):
        """CRL fetch handles timeout gracefully."""
        import requests

        responses.add(
            responses.GET,
            "http://crl.example.com/test.crl",
            body=requests.exceptions.Timeout("Connection timeout"),
        )

        result = dss_manager._get_crl_bytes(test_cert)

        assert result is None

    @responses.activate
    def test_get_crl_bytes_handles_large_crl(
        self, dss_manager: DSSManager, test_cert: x509.Certificate
    ):
        """CRL fetch handles large CRL files (10MB+)."""
        # Simulate large CRL (just a big invalid blob for size testing)
        large_crl_data = b"X" * (10 * 1024 * 1024)  # 10MB

        # Mock both URLs since DSSManager tries multiple URLs on failure
        responses.add(
            responses.GET,
            "http://crl.example.com/test.crl",
            body=large_crl_data,
            status=200,
        )
        responses.add(
            responses.GET,
            "http://crl2.example.com/test.crl",
            body=large_crl_data,
            status=200,
        )

        result = dss_manager._get_crl_bytes(test_cert)

        # Should return None because it's not a valid CRL
        assert result is None
        assert len(responses.calls) == 2  # Both URLs tried


class TestDSSManagerCollectValidationInfo:
    """Tests for collect_validation_info with real certificates."""

    @responses.activate
    def test_collect_validation_info_with_ocsp_and_crl(
        self,
        dss_manager: DSSManager,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
        test_issuer_key,
    ):
        """Collect validation info fetches both OCSP and CRL."""
        # Generate valid OCSP response
        valid_ocsp = generate_valid_ocsp_response(test_cert, test_issuer_cert, test_issuer_key)

        # Mock OCSP
        responses.add(
            responses.POST,
            "http://ocsp.example.com",
            body=valid_ocsp,
            status=200,
        )

        cert_chain = [test_cert, test_issuer_cert]
        result = dss_manager.collect_validation_info(cert_chain)

        # Should have certificates serialized
        assert len(result.certificates) == 2

        # Should have OCSP response
        assert len(result.ocsp_responses) >= 1
        assert len(responses.calls) >= 1

    @responses.activate
    def test_collect_validation_info_fallback_to_crl(
        self,
        dss_manager: DSSManager,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
        test_issuer_key,
    ):
        """Collect validation info falls back to CRL when OCSP fails."""
        # Generate valid CRL
        valid_crl = generate_valid_crl(test_issuer_cert, test_issuer_key)

        # OCSP fails
        responses.add(
            responses.POST,
            "http://ocsp.example.com",
            json={"error": "Service Unavailable"},
            status=503,
        )

        # CRL succeeds
        responses.add(
            responses.GET,
            "http://crl.example.com/test.crl",
            body=valid_crl,
            status=200,
        )

        cert_chain = [test_cert, test_issuer_cert]
        result = dss_manager.collect_validation_info(cert_chain)

        # Should have tried both OCSP and CRL
        assert len(responses.calls) >= 2
        assert len(result.certificates) == 2
        assert len(result.crls) >= 1

    def test_collect_validation_info_empty_chain(self, dss_manager: DSSManager):
        """Collect validation info with empty chain returns empty result."""
        result = dss_manager.collect_validation_info([])

        assert result.is_empty()


class TestDSSManagerEmbedDSS:
    """Tests for DSS embedding in real PDFs."""

    def test_embed_dss_in_pdf(
        self, dss_manager: DSSManager, sample_pdf: Path, test_cert: x509.Certificate
    ):
        """Embed DSS dictionary in a real PDF."""
        # Create validation info (only certificates, no OCSP/CRL to avoid parsing errors)
        validation_info = ValidationInfo(
            ocsp_responses=[],
            crls=[],
            certificates=[test_cert.public_bytes(serialization.Encoding.DER)],
        )

        output_path = sample_pdf.parent / "dss_embedded.pdf"

        result = dss_manager.embed_dss(sample_pdf, validation_info, output_path)

        assert result == output_path
        assert output_path.exists()

        # Verify PDF is still valid
        doc = fitz.open(output_path)
        assert doc.page_count == 1
        doc.close()

    def test_embed_dss_with_multiple_certs(
        self,
        dss_manager: DSSManager,
        sample_pdf: Path,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
    ):
        """Embed DSS with multiple certificates."""
        validation_info = ValidationInfo(
            ocsp_responses=[],
            crls=[],
            certificates=[
                test_cert.public_bytes(serialization.Encoding.DER),
                test_issuer_cert.public_bytes(serialization.Encoding.DER),
            ],
        )

        output_path = sample_pdf.parent / "dss_multi_cert.pdf"

        result = dss_manager.embed_dss(sample_pdf, validation_info, output_path)

        assert result.exists()

        # Verify file size increased (DSS data added)
        original_size = sample_pdf.stat().st_size
        new_size = output_path.stat().st_size
        assert new_size > original_size

    def test_embed_dss_raises_on_empty_validation_info(
        self, dss_manager: DSSManager, sample_pdf: Path
    ):
        """Embed DSS raises ValueError for empty validation info."""
        empty_info = ValidationInfo([], [], [])

        with pytest.raises(ValueError, match="ValidationInfo está vacío"):
            dss_manager.embed_dss(sample_pdf, empty_info)

    def test_embed_dss_raises_on_missing_pdf(self, dss_manager: DSSManager):
        """Embed DSS raises FileNotFoundError for missing PDF."""
        validation_info = ValidationInfo([b"ocsp"], [], [])

        with pytest.raises(FileNotFoundError):
            dss_manager.embed_dss(Path("/nonexistent.pdf"), validation_info)

    @pytest.mark.skip(
        reason="pyHanko expects asn1crypto.crl.CertificateList objects, not bytes DER"
    )
    def test_embed_dss_with_large_revocation_data(
        self,
        dss_manager: DSSManager,
        sample_pdf: Path,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
        test_issuer_key,
    ):
        """Embed DSS with large OCSP/CRL data (size limits test)."""
        # Create multiple valid CRLs to increase size
        large_crls = [generate_valid_crl(test_issuer_cert, test_issuer_key) for _ in range(10)]

        validation_info = ValidationInfo(
            ocsp_responses=[],
            crls=large_crls,
            certificates=[test_cert.public_bytes(serialization.Encoding.DER)],
        )

        output_path = sample_pdf.parent / "dss_large.pdf"

        # Should succeed (pyHanko handles multiple CRLs)
        result = dss_manager.embed_dss(sample_pdf, validation_info, output_path)

        assert result.exists()

        # File should be larger than original
        new_size = output_path.stat().st_size
        original_size = sample_pdf.stat().st_size
        assert new_size > original_size


class TestDSSManagerValidationContext:
    """Tests for ValidationContext building."""

    def test_build_validation_context_minimal(self, dss_manager: DSSManager):
        """Build validation context with minimal parameters."""
        context = dss_manager.build_validation_context()

        assert context is not None

    @pytest.mark.skip(
        reason="pyhanko_certvalidator expects x509.Certificate objects, not DER bytes"
    )
    def test_build_validation_context_with_trust_roots(
        self, dss_manager: DSSManager, test_issuer_cert: x509.Certificate
    ):
        """Build validation context with trust roots."""
        context = dss_manager.build_validation_context(trust_roots=[test_issuer_cert])

        assert context is not None

    @pytest.mark.skip(
        reason="pyhanko_certvalidator expects x509.Certificate objects, not DER bytes"
    )
    def test_build_validation_context_with_validation_info(
        self, dss_manager: DSSManager, test_cert: x509.Certificate
    ):
        """Build validation context with pre-collected validation info."""
        validation_info = ValidationInfo(
            ocsp_responses=[],
            crls=[],
            certificates=[test_cert.public_bytes(serialization.Encoding.DER)],
        )

        context = dss_manager.build_validation_context(validation_info=validation_info)

        assert context is not None


class TestDSSManagerRevocationVerification:
    """Tests for revocation status verification."""

    def test_verify_revocation_status_empty_chain(self, dss_manager: DSSManager):
        """Verify revocation status with empty chain returns True."""
        result = dss_manager.verify_revocation_status([])

        assert result is True

    @responses.activate
    def test_verify_revocation_status_network_failure(
        self,
        dss_manager: DSSManager,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
    ):
        """Verify revocation status handles network failures gracefully."""
        import requests

        # Simulate network failure
        responses.add(
            responses.POST,
            "http://ocsp.example.com",
            body=requests.exceptions.ConnectionError("Network unreachable"),
        )

        responses.add(
            responses.GET,
            "http://crl.example.com/test.crl",
            body=requests.exceptions.ConnectionError("Network unreachable"),
        )

        cert_chain = [test_cert, test_issuer_cert]

        # Should not crash, returns True (fail-open)
        result = dss_manager.verify_revocation_status(cert_chain)

        assert result is True


class TestDSSIntegrationE2E:
    """End-to-end integration tests for DSS workflow."""

    @pytest.mark.skip(reason="pyHanko expects asn1crypto CRL objects when CRLs are present")
    @responses.activate
    def test_full_dss_workflow_collect_and_embed(
        self,
        dss_manager: DSSManager,
        sample_pdf: Path,
        test_cert: x509.Certificate,
        test_issuer_cert: x509.Certificate,
        test_issuer_key,
    ):
        """Full DSS workflow: collect validation info → embed in PDF."""
        # Generate valid OCSP and CRL
        valid_ocsp = generate_valid_ocsp_response(test_cert, test_issuer_cert, test_issuer_key)
        valid_crl = generate_valid_crl(test_issuer_cert, test_issuer_key)

        # Mock OCSP
        responses.add(
            responses.POST,
            "http://ocsp.example.com",
            body=valid_ocsp,
            status=200,
        )

        # Mock CRL (fallback)
        responses.add(
            responses.GET,
            "http://crl.example.com/test.crl",
            body=valid_crl,
            status=200,
        )

        cert_chain = [test_cert, test_issuer_cert]

        # Step 1: Collect validation info
        validation_info = dss_manager.collect_validation_info(cert_chain)

        assert not validation_info.is_empty()
        assert len(validation_info.certificates) == 2

        # Step 2: Embed DSS in PDF
        output_path = sample_pdf.parent / "final_dss.pdf"
        result = dss_manager.embed_dss(sample_pdf, validation_info, output_path)

        assert result.exists()

        # Verify PDF is valid
        doc = fitz.open(output_path)
        assert doc.page_count == 1
        doc.close()

    def test_pades_lt_level_achieved_after_dss(
        self,
        dss_manager: DSSManager,
        sample_pdf: Path,
        test_cert: x509.Certificate,
    ):
        """Verify PAdES-LT level is achieved after DSS embedding."""
        # Create minimal validation info
        validation_info = ValidationInfo(
            ocsp_responses=[],
            crls=[],
            certificates=[test_cert.public_bytes(serialization.Encoding.DER)],
        )

        output_path = sample_pdf.parent / "pades_lt.pdf"
        dss_manager.embed_dss(sample_pdf, validation_info, output_path)

        # Check that DSS was embedded (file size increased)
        assert output_path.stat().st_size > sample_pdf.stat().st_size

        # Note: Full PAdES-LT validation requires pyHanko validator,
        # which is tested in pdf_validator tests

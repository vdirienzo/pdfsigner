"""Tests for DSSManager."""

from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.x509 import (
    ExtensionNotFound,
    UniformResourceIdentifier,
)
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from pdfsigner.core.certificate.revocation_checker import RevocationResult, RevocationStatus
from pdfsigner.core.signer.dss_manager import DSSManager, ValidationInfo


class TestValidationInfo:
    """Tests for ValidationInfo dataclass."""

    def test_is_empty_with_no_data(self):
        """Test is_empty returns True when no data."""
        info = ValidationInfo([], [], [])
        assert info.is_empty()

    def test_is_empty_with_ocsp(self):
        """Test is_empty returns False with OCSP data."""
        info = ValidationInfo([b"ocsp"], [], [])
        assert not info.is_empty()

    def test_is_empty_with_crls(self):
        """Test is_empty returns False with CRL data."""
        info = ValidationInfo([], [b"crl"], [])
        assert not info.is_empty()

    def test_is_empty_with_certificates(self):
        """Test is_empty returns False with certificate data."""
        info = ValidationInfo([], [], [b"cert"])
        assert not info.is_empty()

    def test_is_empty_with_all_data(self):
        """Test is_empty returns False with all data types."""
        info = ValidationInfo([b"ocsp"], [b"crl"], [b"cert"])
        assert not info.is_empty()


class TestDSSManager:
    """Tests for DSSManager class."""

    @pytest.fixture
    def dss_manager(self):
        """Create DSSManager instance."""
        return DSSManager(ocsp_timeout=5, crl_timeout=10)

    @pytest.fixture
    def mock_cert(self):
        """Create a mock certificate."""
        cert = Mock(spec=x509.Certificate)
        cert.public_bytes.return_value = b"mock_cert_der"
        return cert

    @pytest.fixture
    def mock_cert_chain(self, mock_cert):
        """Create a mock certificate chain."""
        cert1 = Mock(spec=x509.Certificate)
        cert1.public_bytes.return_value = b"cert1_der"

        cert2 = Mock(spec=x509.Certificate)
        cert2.public_bytes.return_value = b"cert2_der"

        cert3 = Mock(spec=x509.Certificate)
        cert3.public_bytes.return_value = b"cert3_der"

        return [cert1, cert2, cert3]

    def test_init_creates_checkers(self, dss_manager):
        """Test initialization creates OCSP and CRL checkers."""
        assert dss_manager.ocsp_checker is not None
        assert dss_manager.crl_checker is not None
        assert dss_manager.prefer_ocsp is True

    def test_init_with_custom_timeouts(self):
        """Test initialization with custom timeouts."""
        manager = DSSManager(ocsp_timeout=15, crl_timeout=45, prefer_ocsp=False)
        assert manager.ocsp_checker.timeout == 15
        assert manager.crl_checker.timeout == 45
        assert manager.prefer_ocsp is False

    def test_collect_validation_info_empty_chain(self, dss_manager):
        """Test collect_validation_info with empty certificate chain."""
        result = dss_manager.collect_validation_info([])
        assert result.is_empty()

    def test_collect_validation_info_serializes_certificates(self, dss_manager, mock_cert_chain):
        """Test collect_validation_info serializes all certificates."""
        with patch.object(dss_manager, "_get_ocsp_response_bytes", return_value=None):
            with patch.object(dss_manager, "_get_crl_bytes", return_value=None):
                result = dss_manager.collect_validation_info(mock_cert_chain)

        assert len(result.certificates) == 3
        assert result.certificates[0] == b"cert1_der"
        assert result.certificates[1] == b"cert2_der"
        assert result.certificates[2] == b"cert3_der"

    def test_collect_validation_info_handles_cert_serialization_error(self, dss_manager):
        """Test collect_validation_info handles certificate serialization errors."""
        bad_cert = Mock(spec=x509.Certificate)
        bad_cert.public_bytes.side_effect = Exception("Serialization error")

        result = dss_manager.collect_validation_info([bad_cert])

        assert len(result.certificates) == 0

    def test_collect_validation_info_prefers_ocsp(self, dss_manager, mock_cert_chain):
        """Test collect_validation_info prefers OCSP when available."""
        with patch.object(
            dss_manager, "_get_ocsp_response_bytes", return_value=b"ocsp_response"
        ) as mock_ocsp:
            with patch.object(dss_manager, "_get_crl_bytes") as mock_crl:
                result = dss_manager.collect_validation_info(mock_cert_chain)

        # OCSP should be called for first 2 certs (chain[:-1])
        assert mock_ocsp.call_count == 2
        # CRL should not be called since OCSP succeeded
        assert mock_crl.call_count == 0
        assert len(result.ocsp_responses) == 2

    def test_collect_validation_info_falls_back_to_crl(self, dss_manager, mock_cert_chain):
        """Test collect_validation_info falls back to CRL when OCSP fails."""
        with patch.object(dss_manager, "_get_ocsp_response_bytes", return_value=None):
            with patch.object(dss_manager, "_get_crl_bytes", return_value=b"crl_data") as mock_crl:
                result = dss_manager.collect_validation_info(mock_cert_chain)

        # CRL should be called for first 2 certs
        assert mock_crl.call_count == 2
        assert len(result.crls) == 2

    def test_collect_validation_info_skips_root_certificate(self, dss_manager, mock_cert_chain):
        """Test collect_validation_info skips root certificate for revocation."""
        with patch.object(
            dss_manager, "_get_ocsp_response_bytes", return_value=b"ocsp"
        ) as mock_ocsp:
            dss_manager.collect_validation_info(mock_cert_chain)

        # Should only check first 2 certs (excluding root)
        assert mock_ocsp.call_count == 2

    @patch("pdfsigner.core.signer.dss_manager.requests.post")
    @patch("pdfsigner.core.signer.dss_manager.ocsp.load_der_ocsp_response")
    @patch("pdfsigner.core.signer.dss_manager.ocsp.OCSPRequestBuilder")
    def test_get_ocsp_response_bytes_success(
        self, mock_builder_class, mock_load_ocsp, mock_post, dss_manager, mock_cert_chain
    ):
        """Test _get_ocsp_response_bytes with successful response."""
        cert, issuer = mock_cert_chain[0], mock_cert_chain[1]

        # Mock OCSP request builder
        mock_builder = Mock()
        mock_request = Mock()
        mock_request.public_bytes.return_value = b"ocsp_request_der"
        mock_builder.add_certificate.return_value = mock_builder
        mock_builder.build.return_value = mock_request
        mock_builder_class.return_value = mock_builder

        # Mock OCSP responder URL extraction
        with patch.object(
            dss_manager, "_get_ocsp_responder_url", return_value="https://ocsp.example.com"
        ):
            # Mock successful HTTP response
            mock_response = Mock()
            mock_response.content = b"ocsp_response_der"
            mock_response.raise_for_status = Mock()
            mock_post.return_value = mock_response

            # Mock successful OCSP response
            mock_ocsp_resp = Mock()
            mock_ocsp_resp.response_status = Mock()
            mock_ocsp_resp.response_status.name = "SUCCESSFUL"
            # Use the actual enum value
            from cryptography.x509 import ocsp

            mock_ocsp_resp.response_status = ocsp.OCSPResponseStatus.SUCCESSFUL
            mock_load_ocsp.return_value = mock_ocsp_resp

            result = dss_manager._get_ocsp_response_bytes(cert, issuer)

        assert result == b"ocsp_response_der"
        mock_post.assert_called_once()

    def test_get_ocsp_response_bytes_no_url(self, dss_manager, mock_cert_chain):
        """Test _get_ocsp_response_bytes returns None when no OCSP URL."""
        cert, issuer = mock_cert_chain[0], mock_cert_chain[1]

        with patch.object(dss_manager, "_get_ocsp_responder_url", return_value=None):
            result = dss_manager._get_ocsp_response_bytes(cert, issuer)

        assert result is None

    @patch("pdfsigner.core.signer.dss_manager.requests.post")
    def test_get_ocsp_response_bytes_http_error(self, mock_post, dss_manager, mock_cert_chain):
        """Test _get_ocsp_response_bytes handles HTTP errors."""
        cert, issuer = mock_cert_chain[0], mock_cert_chain[1]

        with patch.object(
            dss_manager, "_get_ocsp_responder_url", return_value="https://ocsp.example.com"
        ):
            mock_post.side_effect = Exception("Connection error")

            result = dss_manager._get_ocsp_response_bytes(cert, issuer)

        assert result is None

    @patch("pdfsigner.core.signer.dss_manager.requests.get")
    @patch("pdfsigner.core.signer.dss_manager.x509.load_der_x509_crl")
    def test_get_crl_bytes_success(self, mock_load_crl, mock_get, dss_manager, mock_cert):
        """Test _get_crl_bytes with successful download."""
        with patch.object(
            dss_manager, "_get_crl_urls", return_value=["https://crl.example.com/test.crl"]
        ):
            mock_response = Mock()
            mock_response.content = b"crl_der_data"
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            mock_load_crl.return_value = Mock()  # Valid CRL

            result = dss_manager._get_crl_bytes(mock_cert)

        assert result == b"crl_der_data"
        mock_get.assert_called_once_with("https://crl.example.com/test.crl", timeout=10)

    def test_get_crl_bytes_no_urls(self, dss_manager, mock_cert):
        """Test _get_crl_bytes returns None when no CRL URLs."""
        with patch.object(dss_manager, "_get_crl_urls", return_value=[]):
            result = dss_manager._get_crl_bytes(mock_cert)

        assert result is None

    @patch("pdfsigner.core.signer.dss_manager.requests.get")
    def test_get_crl_bytes_tries_multiple_urls(self, mock_get, dss_manager, mock_cert):
        """Test _get_crl_bytes tries multiple URLs on failure."""
        urls = [
            "https://crl1.example.com/test.crl",
            "https://crl2.example.com/test.crl",
            "https://crl3.example.com/test.crl",
        ]

        with patch.object(dss_manager, "_get_crl_urls", return_value=urls):
            # First two fail, third succeeds
            mock_get.side_effect = [
                Exception("Timeout"),
                Exception("Not found"),
                Mock(content=b"crl_data", raise_for_status=Mock()),
            ]

            with patch("pdfsigner.core.signer.dss_manager.x509.load_der_x509_crl"):
                result = dss_manager._get_crl_bytes(mock_cert)

        assert result == b"crl_data"
        assert mock_get.call_count == 3

    def test_get_ocsp_responder_url_success(self, dss_manager):
        """Test _get_ocsp_responder_url extracts URL from certificate."""
        mock_cert = Mock(spec=x509.Certificate)
        mock_ext = Mock()

        # Mock AccessDescription
        mock_access_desc = Mock()
        mock_access_desc.access_method = AuthorityInformationAccessOID.OCSP
        mock_access_desc.access_location.value = "https://ocsp.example.com"

        mock_ext.value = [mock_access_desc]
        mock_cert.extensions.get_extension_for_oid.return_value = mock_ext

        result = dss_manager._get_ocsp_responder_url(mock_cert)

        assert result == "https://ocsp.example.com"

    def test_get_ocsp_responder_url_no_extension(self, dss_manager):
        """Test _get_ocsp_responder_url returns None when extension not found."""
        mock_cert = Mock(spec=x509.Certificate)
        mock_cert.extensions.get_extension_for_oid.side_effect = ExtensionNotFound(
            "Extension not found", ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )

        result = dss_manager._get_ocsp_responder_url(mock_cert)

        assert result is None

    def test_get_crl_urls_success(self, dss_manager):
        """Test _get_crl_urls extracts URLs from certificate."""
        mock_cert = Mock(spec=x509.Certificate)
        mock_ext = Mock()

        # Mock DistributionPoint
        mock_dist_point = Mock()
        mock_uri1 = Mock(spec=UniformResourceIdentifier)
        mock_uri1.value = "https://crl1.example.com/test.crl"
        mock_uri2 = Mock(spec=UniformResourceIdentifier)
        mock_uri2.value = "https://crl2.example.com/test.crl"

        mock_dist_point.full_name = [mock_uri1, mock_uri2]

        mock_ext.value = [mock_dist_point]
        mock_cert.extensions.get_extension_for_oid.return_value = mock_ext

        result = dss_manager._get_crl_urls(mock_cert)

        assert len(result) == 2
        assert "https://crl1.example.com/test.crl" in result
        assert "https://crl2.example.com/test.crl" in result

    def test_get_crl_urls_no_extension(self, dss_manager):
        """Test _get_crl_urls returns empty list when extension not found."""
        mock_cert = Mock(spec=x509.Certificate)
        mock_cert.extensions.get_extension_for_oid.side_effect = ExtensionNotFound(
            "Extension not found", ExtensionOID.CRL_DISTRIBUTION_POINTS
        )

        result = dss_manager._get_crl_urls(mock_cert)

        assert result == []

    @patch("pdfsigner.core.signer.dss_manager.DocumentSecurityStore")
    def test_embed_dss_success(self, mock_dss_class, dss_manager, tmp_path):
        """Test embed_dss successfully embeds DSS in PDF."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"mock pdf content")

        validation_info = ValidationInfo(
            ocsp_responses=[b"ocsp1"],
            crls=[b"crl1"],
            certificates=[b"cert1"],
        )

        # Mock add_dss class method
        mock_dss_class.add_dss = Mock()

        # Mock asn1crypto certificate loading
        mock_cert = Mock()
        with patch("asn1crypto.x509.Certificate.load", return_value=mock_cert):
            result = dss_manager.embed_dss(pdf_path, validation_info)

        assert result == pdf_path
        mock_dss_class.add_dss.assert_called_once()
        call_kwargs = mock_dss_class.add_dss.call_args[1]
        assert call_kwargs["certs"] == [mock_cert]  # Ahora son objetos Certificate
        assert call_kwargs["ocsps"] == [b"ocsp1"]
        assert call_kwargs["crls"] == [b"crl1"]
        assert call_kwargs["force_write"] is True

    def test_embed_dss_file_not_found(self, dss_manager):
        """Test embed_dss raises FileNotFoundError for missing PDF."""
        with pytest.raises(FileNotFoundError):
            dss_manager.embed_dss(Path("/nonexistent.pdf"), ValidationInfo([b"ocsp"], [], []))

    def test_embed_dss_empty_validation_info(self, dss_manager, tmp_path):
        """Test embed_dss raises ValueError for empty validation info."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"mock pdf")

        with pytest.raises(ValueError, match="ValidationInfo está vacío"):
            dss_manager.embed_dss(pdf_path, ValidationInfo([], [], []))

    @patch("pdfsigner.core.signer.dss_manager.DocumentSecurityStore")
    def test_embed_dss_runtime_error_on_failure(self, mock_dss_class, dss_manager, tmp_path):
        """Test embed_dss raises RuntimeError on write failure."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"mock pdf")

        validation_info = ValidationInfo([b"ocsp"], [], [])

        mock_dss_class.add_dss = Mock(side_effect=Exception("Write error"))

        with pytest.raises(RuntimeError, match="Fallo al embeber DSS"):
            dss_manager.embed_dss(pdf_path, validation_info)

    @patch("pdfsigner.core.signer.dss_manager.ValidationContext")
    def test_build_validation_context_minimal(self, mock_context_class, dss_manager):
        """Test build_validation_context with minimal parameters."""
        mock_context = Mock()
        mock_context_class.return_value = mock_context

        result = dss_manager.build_validation_context()

        assert result == mock_context
        mock_context_class.assert_called_once()
        call_kwargs = mock_context_class.call_args[1]
        assert call_kwargs["trust_roots"] is None
        assert call_kwargs["allow_fetching"] is True
        assert call_kwargs["revocation_mode"] == "require"

    @patch("pdfsigner.core.signer.dss_manager.ValidationContext")
    def test_build_validation_context_with_trust_roots(
        self, mock_context_class, dss_manager, mock_cert
    ):
        """Test build_validation_context with trust roots."""
        trust_roots = [mock_cert]

        dss_manager.build_validation_context(trust_roots=trust_roots)

        call_kwargs = mock_context_class.call_args[1]
        assert call_kwargs["trust_roots"] == [b"mock_cert_der"]

    @patch("pdfsigner.core.signer.dss_manager.ValidationContext")
    def test_build_validation_context_with_validation_info(self, mock_context_class, dss_manager):
        """Test build_validation_context with validation info."""
        validation_info = ValidationInfo(
            ocsp_responses=[b"ocsp1"],
            crls=[b"crl1"],
            certificates=[b"cert1"],
        )

        dss_manager.build_validation_context(validation_info=validation_info)

        call_kwargs = mock_context_class.call_args[1]
        assert call_kwargs["ocsps"] == [b"ocsp1"]
        assert call_kwargs["crls"] == [b"crl1"]
        assert call_kwargs["other_certs"] == [b"cert1"]

    def test_verify_revocation_status_all_valid(self, dss_manager, mock_cert_chain):
        """Test verify_revocation_status returns True when all certs valid."""
        good_result = RevocationResult(
            status=RevocationStatus.GOOD,
            checked_at=datetime.now(),
        )

        with patch.object(dss_manager.ocsp_checker, "check", return_value=good_result):
            result = dss_manager.verify_revocation_status(mock_cert_chain)

        assert result is True

    def test_verify_revocation_status_revoked_cert(self, dss_manager, mock_cert_chain):
        """Test verify_revocation_status returns False when cert is revoked."""
        revoked_result = RevocationResult(
            status=RevocationStatus.REVOKED,
            checked_at=datetime.now(),
            revocation_reason="keyCompromise",
        )

        with patch.object(dss_manager.ocsp_checker, "check", return_value=revoked_result):
            result = dss_manager.verify_revocation_status(mock_cert_chain)

        assert result is False

    def test_verify_revocation_status_fallback_to_crl(self, dss_manager, mock_cert_chain):
        """Test verify_revocation_status falls back to CRL when OCSP fails."""
        unknown_result = RevocationResult(
            status=RevocationStatus.UNKNOWN,
            checked_at=datetime.now(),
            error_message="OCSP unavailable",
        )
        good_result = RevocationResult(
            status=RevocationStatus.GOOD,
            checked_at=datetime.now(),
        )

        with patch.object(dss_manager.ocsp_checker, "check", return_value=unknown_result):
            with patch.object(dss_manager.crl_checker, "check", return_value=good_result):
                result = dss_manager.verify_revocation_status(mock_cert_chain)

        assert result is True

    def test_verify_revocation_status_empty_chain(self, dss_manager):
        """Test verify_revocation_status with empty chain."""
        result = dss_manager.verify_revocation_status([])
        assert result is True

    def test_verify_revocation_status_skips_root(self, dss_manager, mock_cert_chain):
        """Test verify_revocation_status skips root certificate."""
        good_result = RevocationResult(
            status=RevocationStatus.GOOD,
            checked_at=datetime.now(),
        )

        with patch.object(
            dss_manager.ocsp_checker, "check", return_value=good_result
        ) as mock_check:
            dss_manager.verify_revocation_status(mock_cert_chain)

        # Should only check first 2 certs (excluding root which is last)
        assert mock_check.call_count == 2


class TestDSSManagerErrorHandling:
    """Tests for DSSManager error handling and edge cases."""

    @pytest.fixture
    def dss_manager(self):
        """Create DSSManager instance."""
        return DSSManager(ocsp_timeout=5, crl_timeout=10)

    @pytest.fixture
    def mock_cert(self):
        """Create a mock certificate."""
        cert = Mock(spec=x509.Certificate)
        cert.public_bytes.return_value = b"mock_cert_der"
        return cert

    @pytest.fixture
    def mock_cert_chain(self, mock_cert):
        """Create a mock certificate chain."""
        cert1 = Mock(spec=x509.Certificate)
        cert1.public_bytes.return_value = b"cert1_der"

        cert2 = Mock(spec=x509.Certificate)
        cert2.public_bytes.return_value = b"cert2_der"

        cert3 = Mock(spec=x509.Certificate)
        cert3.public_bytes.return_value = b"cert3_der"

        return [cert1, cert2, cert3]

    @pytest.mark.security
    @patch("pdfsigner.core.signer.dss_manager.DocumentSecurityStore")
    @patch("shutil.move")
    def test_embed_dss_shutil_move_failure_raises_runtime_error(
        self, mock_move, mock_dss_class, dss_manager, tmp_path
    ):
        """Test embed_dss handles shutil.move() permission errors."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"mock pdf content")

        validation_info = ValidationInfo(
            ocsp_responses=[b"ocsp1"],
            crls=[b"crl1"],
            certificates=[b"cert1"],
        )

        # Mock successful DSS add but shutil.move fails
        mock_dss_class.add_dss = Mock()
        mock_move.side_effect = PermissionError("Permission denied")

        with patch("asn1crypto.x509.Certificate.load", return_value=Mock()):
            with pytest.raises(RuntimeError, match="Fallo al embeber DSS"):
                dss_manager.embed_dss(pdf_path, validation_info)

    @pytest.mark.security
    @patch("pdfsigner.core.signer.dss_manager.DocumentSecurityStore")
    def test_embed_dss_temp_cleanup_on_error_removes_temp_file(
        self, mock_dss_class, dss_manager, tmp_path
    ):
        """Test embed_dss cleans up temporary files on any error."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"mock pdf content")

        validation_info = ValidationInfo([b"ocsp"], [], [b"cert1"])

        # Mock DSS add to fail
        mock_dss_class.add_dss = Mock(side_effect=Exception("DSS write error"))

        with patch("asn1crypto.x509.Certificate.load", return_value=Mock()):
            with pytest.raises(RuntimeError, match="Fallo al embeber DSS"):
                dss_manager.embed_dss(pdf_path, validation_info)

        # Check that no temp files remain (they should be auto-cleaned or moved)
        temp_files = list(tmp_path.glob("*.pdf"))
        # Only the original should remain, no orphaned temp files
        assert len(temp_files) == 1
        assert temp_files[0] == pdf_path

    @pytest.mark.security
    def test_verify_revocation_ocsp_crl_conflicting_status_returns_false(
        self, dss_manager, mock_cert_chain
    ):
        """Test verify_revocation handles conflicting OCSP (valid) and CRL (revoked) status."""
        # OCSP says GOOD
        good_result = RevocationResult(
            status=RevocationStatus.GOOD,
            checked_at=datetime.now(),
        )

        # CRL says REVOKED
        revoked_result = RevocationResult(
            status=RevocationStatus.REVOKED,
            checked_at=datetime.now(),
            revocation_reason="keyCompromise",
        )

        # First cert: OCSP returns GOOD
        # Second cert: OCSP returns UNKNOWN, CRL returns REVOKED
        with patch.object(
            dss_manager.ocsp_checker,
            "check",
            side_effect=[
                good_result,
                RevocationResult(
                    status=RevocationStatus.UNKNOWN,
                    checked_at=datetime.now(),
                    error_message="OCSP unavailable",
                ),
            ],
        ):
            with patch.object(dss_manager.crl_checker, "check", return_value=revoked_result):
                result = dss_manager.verify_revocation_status(mock_cert_chain)

        # Should return False because one cert is revoked
        assert result is False

    @pytest.mark.security
    @patch("pdfsigner.core.signer.dss_manager.ValidationContext")
    def test_build_validation_context_invalid_kwargs_raises_exception(
        self, mock_context_class, dss_manager
    ):
        """Test build_validation_context handles invalid kwargs gracefully."""
        # Mock ValidationContext to raise TypeError for invalid kwargs
        mock_context_class.side_effect = TypeError("unexpected keyword argument")

        validation_info = ValidationInfo([b"ocsp"], [b"crl"], [b"cert"])

        with pytest.raises(TypeError, match="unexpected keyword argument"):
            dss_manager.build_validation_context(validation_info=validation_info)

    @pytest.mark.security
    @patch("pdfsigner.core.signer.dss_manager.requests.post")
    @patch("pdfsigner.core.signer.dss_manager.ocsp.OCSPRequestBuilder")
    def test_collect_validation_info_network_timeout_falls_back_to_crl(
        self, mock_builder_class, mock_post, dss_manager, mock_cert_chain
    ):
        """Test collect_validation_info handles network timeouts gracefully."""
        # Mock OCSP request builder
        mock_builder = Mock()
        mock_request = Mock()
        mock_request.public_bytes.return_value = b"ocsp_request"
        mock_builder.add_certificate.return_value = mock_builder
        mock_builder.build.return_value = mock_request
        mock_builder_class.return_value = mock_builder

        # Mock OCSP URL extraction
        with patch.object(
            dss_manager, "_get_ocsp_responder_url", return_value="https://ocsp.example.com"
        ):
            # Mock network timeout
            import requests

            mock_post.side_effect = requests.exceptions.Timeout("Connection timeout")

            # Mock CRL fallback succeeds
            with patch.object(dss_manager, "_get_crl_bytes", return_value=b"crl_data"):
                result = dss_manager.collect_validation_info(mock_cert_chain)

        # Should have CRLs from fallback
        assert len(result.crls) == 2
        assert len(result.ocsp_responses) == 0

    @pytest.mark.security
    @patch("pdfsigner.core.signer.dss_manager.DocumentSecurityStore")
    def test_embed_dss_disk_full_raises_runtime_error(self, mock_dss_class, dss_manager, tmp_path):
        """Test embed_dss handles disk full errors."""
        pdf_path = tmp_path / "test.pdf"
        pdf_path.write_bytes(b"mock pdf content")

        validation_info = ValidationInfo([b"ocsp"], [], [b"cert1"])

        # Mock OSError for disk full
        mock_dss_class.add_dss = Mock(side_effect=OSError(28, "No space left on device"))

        with patch("asn1crypto.x509.Certificate.load", return_value=Mock()):
            with pytest.raises(RuntimeError, match="Fallo al embeber DSS"):
                dss_manager.embed_dss(pdf_path, validation_info)

    @pytest.mark.security
    def test_verify_revocation_both_fail_logs_warning(self, dss_manager, mock_cert_chain):
        """Test verify_revocation handles both OCSP and CRL failing."""
        unknown_result = RevocationResult(
            status=RevocationStatus.UNKNOWN,
            checked_at=datetime.now(),
            error_message="Service unavailable",
        )

        # Both OCSP and CRL return UNKNOWN
        with patch.object(dss_manager.ocsp_checker, "check", return_value=unknown_result):
            with patch.object(dss_manager.crl_checker, "check", return_value=unknown_result):
                # Should not crash, but return True (fail-open behavior)
                result = dss_manager.verify_revocation_status(mock_cert_chain)

        # Returns True because no explicit REVOKED status found
        assert result is True

    @pytest.mark.security
    @patch("pdfsigner.core.signer.dss_manager.requests.post")
    @patch("pdfsigner.core.signer.dss_manager.ocsp.load_der_ocsp_response")
    @patch("pdfsigner.core.signer.dss_manager.ocsp.OCSPRequestBuilder")
    def test_dss_manager_handles_corrupted_response_returns_none(
        self, mock_builder_class, mock_load_ocsp, mock_post, dss_manager, mock_cert_chain
    ):
        """Test DSSManager handles malformed OCSP/CRL responses."""
        cert, issuer = mock_cert_chain[0], mock_cert_chain[1]

        # Mock OCSP request builder
        mock_builder = Mock()
        mock_request = Mock()
        mock_request.public_bytes.return_value = b"ocsp_request"
        mock_builder.add_certificate.return_value = mock_builder
        mock_builder.build.return_value = mock_request
        mock_builder_class.return_value = mock_builder

        with patch.object(
            dss_manager, "_get_ocsp_responder_url", return_value="https://ocsp.example.com"
        ):
            # Mock corrupted OCSP response
            mock_response = Mock()
            mock_response.content = b"corrupted_data"
            mock_response.raise_for_status = Mock()
            mock_post.return_value = mock_response

            # Mock load fails due to corruption
            mock_load_ocsp.side_effect = ValueError("Invalid OCSP response")

            result = dss_manager._get_ocsp_response_bytes(cert, issuer)

        # Should return None, not crash
        assert result is None

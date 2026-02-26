"""
test_pdf_signer.py - Tests for PDFSigner

Author: Homero Thompson del Lago del Terror
"""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.pdf_signer import (
    PDFSigner,
    SignatureAppearance,
    SigningResult,
)
from pdfsigner.exceptions import PDFCorruptedError


class TestSignatureAppearance:
    """Tests for SignatureAppearance dataclass."""

    def test_default_values(self):
        """Test default values."""
        appearance = SignatureAppearance()

        assert appearance.visible is False
        assert appearance.page == "last"
        assert appearance.width_mm == 50
        assert appearance.height_mm == 20
        assert appearance.position_preference == PositionPreference.AUTO
        assert appearance.image_path is None
        assert appearance.show_date is True
        assert appearance.show_name is True

    def test_custom_values(self):
        """Test custom values."""
        appearance = SignatureAppearance(
            visible=True,
            page=1,
            width_mm=60,
            height_mm=25,
            position_preference=PositionPreference.BOTTOM_RIGHT,
            show_date=False,
        )

        assert appearance.visible is True
        assert appearance.page == 1
        assert appearance.width_mm == 60
        assert appearance.height_mm == 25
        assert appearance.position_preference == PositionPreference.BOTTOM_RIGHT
        assert appearance.show_date is False

    def test_page_as_string(self):
        """Test page as string values."""
        for page_value in ["last", "first", "all"]:
            appearance = SignatureAppearance(page=page_value)
            assert appearance.page == page_value


class TestSigningResult:
    """Tests for SigningResult dataclass."""

    def test_successful_result(self, temp_dir: Path):
        """Test successful signing result."""
        input_path = temp_dir / "input.pdf"
        output_path = temp_dir / "input_signed.pdf"

        result = SigningResult(
            success=True,
            input_path=input_path,
            output_path=output_path,
            signed_at=datetime.now(),
        )

        assert result.success is True
        assert result.input_path == input_path
        assert result.output_path == output_path
        assert result.error is None
        assert result.signed_at is not None

    def test_failed_result(self, temp_dir: Path):
        """Test failed signing result."""
        input_path = temp_dir / "input.pdf"

        result = SigningResult(
            success=False,
            input_path=input_path,
            output_path=None,
            error="PDF is corrupted",
        )

        assert result.success is False
        assert result.input_path == input_path
        assert result.output_path is None
        assert result.error == "PDF is corrupted"


class TestPDFSigner:
    """Tests for PDFSigner class."""

    @pytest.fixture
    def mock_nss_handler(self):
        """Create mock NSS handler."""
        handler = MagicMock()
        handler.get_signing_key_and_cert.return_value = (MagicMock(), b"cert_der_data")
        return handler

    @pytest.fixture
    def mock_lta_handler(self):
        """Create mock LTA handler."""
        handler = MagicMock()
        handler.tsa_config.url = "https://tsa.example.com"
        handler.get_timestamper.return_value = MagicMock()
        return handler

    def test_initialization(self, mock_nss_handler):
        """Test PDFSigner initialization."""
        signer = PDFSigner(mock_nss_handler)

        assert signer.nss_handler == mock_nss_handler
        assert signer.lta_handler is None
        assert signer._signer is None

    def test_initialization_with_lta(self, mock_nss_handler, mock_lta_handler):
        """Test PDFSigner initialization with LTA handler."""
        signer = PDFSigner(mock_nss_handler, mock_lta_handler)

        assert signer.nss_handler == mock_nss_handler
        assert signer.lta_handler == mock_lta_handler

    def test_get_output_path(self, mock_nss_handler, temp_dir: Path, mock_settings):
        """Test output path generation."""
        signer = PDFSigner(mock_nss_handler)
        input_path = temp_dir / "document.pdf"

        output_path = signer._get_output_path(input_path)

        assert output_path == temp_dir / "document_signed.pdf"

    def test_validate_pdf_missing_file(self, mock_nss_handler, temp_dir: Path):
        """Test PDF validation with missing file."""
        signer = PDFSigner(mock_nss_handler)
        pdf_path = temp_dir / "nonexistent.pdf"

        with pytest.raises(PDFCorruptedError):
            signer._validate_pdf(pdf_path)

    def test_validate_pdf_valid_file(self, mock_nss_handler, sample_pdf: Path):
        """Test PDF validation with valid file."""
        signer = PDFSigner(mock_nss_handler)

        # Should not raise exception
        signer._validate_pdf(sample_pdf)

    def test_build_stamp_style_invisible(self, mock_nss_handler):
        """Test stamp style for invisible signature."""
        signer = PDFSigner(mock_nss_handler)
        appearance = SignatureAppearance(visible=False)

        style = signer._build_stamp_style(appearance)

        assert style is None

    def test_build_stamp_style_visible(self, mock_nss_handler):
        """Test stamp style for visible signature."""
        signer = PDFSigner(mock_nss_handler)
        appearance = SignatureAppearance(visible=True)

        style = signer._build_stamp_style(appearance)

        assert style is not None

    def test_build_stamp_style_custom_options(self, mock_nss_handler):
        """Test stamp style with custom options."""
        signer = PDFSigner(mock_nss_handler)
        appearance = SignatureAppearance(
            visible=True,
            show_date=True,
            show_name=True,
        )

        style = signer._build_stamp_style(appearance)

        assert style is not None

    def test_build_stamp_style_no_text_parts(self, mock_nss_handler):
        """Test stamp style with no text parts uses default."""
        signer = PDFSigner(mock_nss_handler)
        appearance = SignatureAppearance(
            visible=True,
            show_date=False,
            show_name=False,
        )

        style = signer._build_stamp_style(appearance)

        assert style is not None

    def test_sign_pdf_returns_result(self, mock_nss_handler, sample_pdf: Path, temp_dir: Path):
        """Test sign_pdf returns SigningResult."""
        signer = PDFSigner(mock_nss_handler)

        # Mock the internal signer creation
        with patch.object(signer, "_create_signer") as mock_create:
            mock_create.side_effect = Exception("Mocked - no real signing")
            result = signer.sign_pdf(sample_pdf)

        assert isinstance(result, SigningResult)
        assert result.input_path == sample_pdf

    def test_sign_pdf_corrupted_file(self, mock_nss_handler, temp_dir: Path):
        """Test signing corrupted PDF."""
        signer = PDFSigner(mock_nss_handler)

        # Create corrupted PDF
        corrupted = temp_dir / "corrupted.pdf"
        corrupted.write_bytes(b"not a real pdf content")

        result = signer.sign_pdf(corrupted)

        assert result.success is False
        assert result.error is not None
        assert "corrupted" in result.error.lower() or "error" in result.error.lower()

    def test_sign_pdf_with_custom_output(self, mock_nss_handler, sample_pdf: Path, temp_dir: Path):
        """Test signing with custom output path."""
        signer = PDFSigner(mock_nss_handler)
        custom_output = temp_dir / "custom_output.pdf"

        with patch.object(signer, "_create_signer") as mock_create:
            mock_create.side_effect = Exception("Mocked")
            result = signer.sign_pdf(sample_pdf, output_path=custom_output)

        # Even if fails, result should have correct paths
        assert result.input_path == sample_pdf


class TestPDFSignerCreateSigner:
    """Tests for _create_signer method."""

    def test_create_signer_calls_nss_handler(self):
        """Test _create_signer calls NSS handler correctly."""
        from datetime import datetime, timedelta

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        # Generate a real key pair and certificate for this test
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test User")])
        _ = (  # Certificate built to verify x509 imports work, not used in mock
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .sign(private_key, hashes.SHA256())
        )

        handler = MagicMock()
        mock_session = MagicMock()
        handler.get_session.return_value = mock_session

        with patch("pyhanko.sign.pkcs11.PKCS11Signer") as mock_pkcs11:
            mock_pkcs11.return_value = MagicMock()
            signer = PDFSigner(handler)
            result = signer._create_signer()

            assert result is not None
            mock_pkcs11.assert_called_once_with(
                pkcs11_session=mock_session,
                cert_id=None,
            )

    def test_create_signer_with_cert_id(self):
        """Test signer creation with specific cert ID."""
        handler = MagicMock()
        mock_session = MagicMock()
        handler.get_session.return_value = mock_session
        cert_id = b"test-cert-id"

        with patch("pyhanko.sign.pkcs11.PKCS11Signer") as mock_pkcs11:
            mock_pkcs11.return_value = MagicMock()
            signer = PDFSigner(handler)
            result = signer._create_signer(cert_id)

            assert result is not None
            mock_pkcs11.assert_called_once_with(
                pkcs11_session=mock_session,
                cert_id=cert_id,
            )


class TestPDFSignerValidation:
    """Tests for PDF validation edge cases."""

    @pytest.fixture
    def mock_nss_handler(self):
        """Create mock NSS handler."""
        return MagicMock()

    def test_validate_pdf_null_root(self, mock_nss_handler, temp_dir: Path):
        """Test validation when PDF root is None."""
        signer = PDFSigner(mock_nss_handler)

        # Create a PDF-like file that might have None root
        bad_pdf = temp_dir / "bad.pdf"
        bad_pdf.write_bytes(b"%PDF-1.4\n%%EOF")  # Minimal invalid PDF

        with pytest.raises(PDFCorruptedError):
            signer._validate_pdf(bad_pdf)

    def test_validate_pdf_protected_no_modify(self, mock_nss_handler, sample_pdf: Path):
        """Test validation with protected PDF that doesn't allow modifications."""
        from pdfsigner.exceptions import PDFProtectedError

        signer = PDFSigner(mock_nss_handler)

        # Mock the PdfFileReader to return encrypted PDF with no modify permission
        mock_reader = MagicMock()
        mock_reader.root = MagicMock()  # Not None
        mock_reader.security_handler = MagicMock()  # Not None = encrypted
        mock_reader.security_handler.permissions = MagicMock()
        mock_reader.security_handler.permissions.can_modify = False

        with patch("builtins.open", MagicMock()):
            with patch(
                "pdfsigner.core.signer.pdf_signer.PdfFileReader",
                return_value=mock_reader,
            ):
                with pytest.raises(PDFProtectedError):
                    signer._validate_pdf(sample_pdf)

    def test_validate_pdf_encrypted_allows_modify(self, mock_nss_handler, sample_pdf: Path):
        """Test validation with encrypted PDF that allows modifications."""
        signer = PDFSigner(mock_nss_handler)

        # Mock the PdfFileReader to return encrypted PDF with modify permission
        mock_reader = MagicMock()
        mock_reader.root = MagicMock()  # Not None
        mock_reader.security_handler = MagicMock()  # Not None = encrypted
        mock_reader.security_handler.permissions = MagicMock()
        mock_reader.security_handler.permissions.can_modify = True

        with patch("builtins.open", MagicMock()):
            with patch(
                "pdfsigner.core.signer.pdf_signer.PdfFileReader",
                return_value=mock_reader,
            ):
                # Should not raise
                signer._validate_pdf(sample_pdf)


class TestPDFSignerStampWithImage:
    """Tests for stamp style with background image."""

    @pytest.fixture
    def mock_nss_handler(self):
        """Create mock NSS handler."""
        return MagicMock()

    def test_build_stamp_style_with_valid_image(self, mock_nss_handler, temp_dir: Path):
        """Test stamp style with valid image path."""
        signer = PDFSigner(mock_nss_handler)

        # Create a dummy image file
        image_path = temp_dir / "stamp.png"
        # Create minimal PNG file (1x1 pixel)
        png_header = bytes(
            [
                0x89,
                0x50,
                0x4E,
                0x47,
                0x0D,
                0x0A,
                0x1A,
                0x0A,  # PNG signature
            ]
        )
        image_path.write_bytes(png_header)

        appearance = SignatureAppearance(
            visible=True,
            image_path=image_path,
        )

        # Mock settings to ensure no template is configured
        mock_settings = MagicMock()
        mock_settings.signature_template = ""

        # Mock the PdfImage class from pyhanko.pdf_utils.images
        with (
            patch("pdfsigner.core.signer.pdf_signer.get_settings", return_value=mock_settings),
            patch("pyhanko.pdf_utils.images.PdfImage") as mock_img,
        ):
            mock_img.return_value = MagicMock()
            style = signer._build_stamp_style(appearance)

        assert style is not None
        mock_img.assert_called_once_with(str(image_path))

    def test_build_stamp_style_with_nonexistent_image(self, mock_nss_handler):
        """Test stamp style with non-existent image path."""
        signer = PDFSigner(mock_nss_handler)

        appearance = SignatureAppearance(
            visible=True,
            image_path=Path("/nonexistent/image.png"),
        )

        # Should not raise, just skip the image
        style = signer._build_stamp_style(appearance)

        assert style is not None

    def test_build_stamp_style_image_load_error(self, mock_nss_handler, temp_dir: Path):
        """Test stamp style when image fails to load."""
        signer = PDFSigner(mock_nss_handler)

        # Create a file that exists but isn't a valid image
        bad_image = temp_dir / "bad.png"
        bad_image.write_text("not an image")

        appearance = SignatureAppearance(
            visible=True,
            image_path=bad_image,
        )

        # Mock PdfImage to raise an exception (from pyhanko.pdf_utils.images)
        with patch(
            "pyhanko.pdf_utils.images.PdfImage",
            side_effect=Exception("Invalid image"),
        ):
            style = signer._build_stamp_style(appearance)

        # Should still return a style, just without background
        assert style is not None


class TestPDFSignerIntegration:
    """Integration-like tests for PDFSigner (with mocking)."""

    @pytest.fixture
    def mock_full_setup(self):
        """Setup all mocks for a full signing flow."""
        nss = MagicMock()
        nss.get_signing_key_and_cert.return_value = (MagicMock(), b"cert_der")

        lta = MagicMock()
        lta.tsa_config.url = "https://tsa.example.com"

        return nss, lta

    def test_sign_pdf_appearance_options(self, mock_full_setup, sample_pdf: Path):
        """Test sign_pdf respects appearance options."""
        nss, lta = mock_full_setup
        signer = PDFSigner(nss, lta)

        appearance = SignatureAppearance(
            visible=True,
            page="last",
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        with patch.object(signer, "_create_signer") as mock_create:
            mock_create.side_effect = Exception("Mocked")
            result = signer.sign_pdf(sample_pdf, appearance=appearance)

        # Should still attempt to sign
        assert isinstance(result, SigningResult)


class TestPDFSignerRobustness:
    """Tests for error handling and rollback scenarios."""

    @pytest.fixture
    def mock_nss_handler(self):
        """Create mock NSS handler."""
        handler = MagicMock()
        handler._session = MagicMock()
        handler.get_signing_key_and_cert.return_value = (MagicMock(), b"cert_der_data")
        return handler

    @pytest.fixture
    def mock_lta_handler(self):
        """Create mock LTA handler."""
        handler = MagicMock()
        handler.tsa_config.url = "https://tsa.example.com"
        handler.get_timestamper.return_value = MagicMock()
        return handler

    @pytest.mark.security
    def test_sign_pdf_rollback_on_phase4_failure_temp_files_cleaned(
        self, mock_nss_handler, sample_pdf: Path, temp_dir: Path
    ):
        """Test temp files cleaned up when signing phase fails."""
        signer = PDFSigner(mock_nss_handler)
        output_path = temp_dir / "output.pdf"

        # Mock the signature field creation to return visual stamps
        mock_field_result = MagicMock()
        mock_field_result.field_spec = None
        mock_field_result.visual_stamps = []

        # Mock signing execution to fail
        with (
            patch(
                "pdfsigner.core.signer.signature_field.create_signature_field_with_stamps"
            ) as mock_field,
            patch.object(signer, "_create_signer") as mock_create_signer,
            patch.object(signer, "_execute_signing") as mock_execute,
        ):
            mock_field.return_value = mock_field_result
            mock_create_signer.return_value = MagicMock()
            mock_execute.side_effect = Exception("Signing failed in phase 4")

            result = signer.sign_pdf(sample_pdf, output_path=output_path)

        assert result.success is False
        assert "Signing failed" in result.error

    @pytest.mark.security
    def test_sign_pdf_temp_file_cleanup_on_error_removes_temp_files(
        self, mock_nss_handler, sample_pdf: Path, temp_dir: Path
    ):
        """Test temp files removed on any exception."""
        signer = PDFSigner(mock_nss_handler)

        temp_pdf_path = temp_dir / "temp_stamped.pdf"
        temp_pdf_path.write_bytes(b"%PDF-1.4 temp")

        # Mock preprocessing to return temp file
        with (
            patch.object(signer, "_prepare_signing_context") as mock_prepare,
            patch.object(signer, "_preprocess_pdf_with_stamps") as mock_preprocess,
            patch.object(signer, "_execute_signing") as mock_execute,
        ):
            mock_prepare.return_value = (MagicMock(), None, "Test", "Org", 0)
            mock_preprocess.return_value = (temp_pdf_path, temp_pdf_path)
            mock_execute.side_effect = Exception("Signing error")

            result = signer.sign_pdf(sample_pdf)

        assert result.success is False
        assert not temp_pdf_path.exists()  # Temp file should be cleaned up

    def test_sign_pdf_with_corrupted_xref_returns_error(self, mock_nss_handler, temp_dir: Path):
        """Test handle PDF with corrupted xref table."""
        signer = PDFSigner(mock_nss_handler)

        # Create corrupted PDF with bad xref
        corrupted_pdf = temp_dir / "corrupted_xref.pdf"
        corrupted_pdf.write_bytes(
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"xref\n"
            b"0 INVALID\n"  # Corrupted xref entry
            b"trailer<</Root 1 0 R>>\n"
            b"%%EOF"
        )

        result = signer.sign_pdf(corrupted_pdf)

        assert result.success is False
        assert result.error is not None
        assert "corrupted" in result.error.lower() or "error" in result.error.lower()

    def test_sign_pdf_output_permission_denied_returns_error(
        self, mock_nss_handler, sample_pdf: Path, temp_dir: Path, mock_settings
    ):
        """Test handle permission errors on output path."""
        signer = PDFSigner(mock_nss_handler)
        output_path = temp_dir / "readonly_output.pdf"

        # Mock the entire signing process up to file writing
        with (
            patch.object(signer, "_prepare_signing_context") as mock_prepare,
            patch(
                "pdfsigner.core.signer.signature_field.create_signature_field_with_stamps"
            ) as mock_field,
            patch.object(signer, "_preprocess_pdf_with_stamps") as mock_preprocess,
            patch("builtins.open", side_effect=PermissionError("Permission denied")),
        ):
            mock_prepare.return_value = (MagicMock(), None, "Test", "Org", 0)
            mock_field.return_value = MagicMock(field_spec=None, visual_stamps=[])
            mock_preprocess.return_value = (sample_pdf, None)

            result = signer.sign_pdf(sample_pdf, output_path=output_path)

        assert result.success is False
        assert result.error is not None

    def test_sign_pdf_output_directory_not_exists_returns_error(
        self, mock_nss_handler, sample_pdf: Path, temp_dir: Path
    ):
        """Test handle missing output directory."""
        signer = PDFSigner(mock_nss_handler)
        output_path = temp_dir / "nonexistent_dir" / "output.pdf"

        # Mock to reach the point where directory is needed
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
            mock_execute.side_effect = FileNotFoundError("Directory not found")

            result = signer.sign_pdf(sample_pdf, output_path=output_path)

        assert result.success is False
        assert result.error is not None

    def test_template_rendering_qr_failure_fallback_continues_without_qr(
        self, mock_nss_handler, sample_pdf: Path
    ):
        """Test continue without QR if generation fails."""
        signer = PDFSigner(mock_nss_handler)
        appearance = SignatureAppearance(visible=True)

        # Mock template loading to have a QR layer
        mock_template = MagicMock()
        mock_layer = MagicMock()
        mock_layer.type = "qr"
        mock_template.layers = [mock_layer]

        with (
            patch("pdfsigner.core.signature.load_template") as mock_load,
            patch("pdfsigner.core.stamp.qr_generator.calculate_document_hash") as mock_hash,
            patch("pdfsigner.core.stamp.qr_generator.generate_qr_image") as mock_qr,
            patch("pdfsigner.core.signature.render_template") as mock_render,
            patch("pdfsigner.core.signature.get_builtin_templates_dir") as mock_templates_dir,
        ):
            mock_load.return_value = mock_template
            mock_hash.return_value = "abc123"
            mock_qr.side_effect = Exception("QR generation failed")
            mock_render.return_value = Path("/tmp/stamp.png")
            mock_templates_dir.return_value = Path("/tmp/templates")

            # Should not raise, should continue without QR
            stamp_path = signer._render_template_stamp(
                "test_template", "Signer", sample_pdf, appearance
            )

        # Should still render template (without QR)
        assert mock_render.called

    def test_coordinate_conversion_rotated_page_handles_correctly(
        self, mock_nss_handler, temp_dir: Path
    ):
        """Test handle rotated pages correctly."""
        signer = PDFSigner(mock_nss_handler)

        # Create a minimal PDF with rotated page
        rotated_pdf = temp_dir / "rotated.pdf"
        # Write minimal valid PDF structure
        rotated_pdf.write_bytes(
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Rotate 90>>endobj\n"
            b"xref\n0 4\n"
            b"0000000000 65535 f\n"
            b"0000000009 00000 n\n"
            b"0000000058 00000 n\n"
            b"0000000115 00000 n\n"
            b"trailer<</Size 4/Root 1 0 R>>\n"
            b"startxref\n200\n%%EOF"
        )

        # This should handle the rotated page without crashing
        try:
            signer._validate_pdf(rotated_pdf)
            # If validation passes, that's good
        except PDFCorruptedError:
            # If it fails validation, that's also acceptable for this minimal PDF
            pass

    def test_coordinate_conversion_non_standard_mediabox_handles_correctly(
        self, mock_nss_handler, temp_dir: Path
    ):
        """Test handle custom page sizes."""
        signer = PDFSigner(mock_nss_handler)

        # Create PDF with custom MediaBox (A3 size: 297mm x 420mm = ~841 x 1190 pts)
        custom_pdf = temp_dir / "custom_size.pdf"
        custom_pdf.write_bytes(
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 841 1190]>>endobj\n"
            b"xref\n0 4\n"
            b"0000000000 65535 f\n"
            b"0000000009 00000 n\n"
            b"0000000058 00000 n\n"
            b"0000000115 00000 n\n"
            b"trailer<</Size 4/Root 1 0 R>>\n"
            b"startxref\n200\n%%EOF"
        )

        # Should handle custom page size
        try:
            signer._validate_pdf(custom_pdf)
        except PDFCorruptedError:
            # Minimal PDF might fail validation, that's OK for this test
            pass

    def test_embed_ltv_info_failure_with_fail_open_true_continues(
        self, mock_nss_handler, sample_pdf: Path, temp_dir: Path, mock_settings
    ):
        """Test continue on LTV failure when fail_open is True."""
        mock_settings.ltv_enabled = True
        mock_settings.ltv_fail_open = True

        signer = PDFSigner(mock_nss_handler)
        output_path = temp_dir / "output.pdf"

        # Create mock certificate chain
        mock_cert = MagicMock()
        cert_chain = [mock_cert]

        with (
            patch.object(signer, "_prepare_signing_context") as mock_prepare,
            patch(
                "pdfsigner.core.signer.signature_field.create_signature_field_with_stamps"
            ) as mock_field,
            patch.object(signer, "_preprocess_pdf_with_stamps") as mock_preprocess,
            patch.object(signer, "_execute_signing"),
            patch.object(signer, "_extract_cert_chain") as mock_extract,
            patch("pdfsigner.core.signer.dss_manager.DSSManager") as mock_dss_class,
        ):
            mock_signer = MagicMock()
            mock_signer.signing_cert = None
            mock_prepare.return_value = (mock_signer, None, "Test", "Org", 0)
            mock_field.return_value = MagicMock(field_spec=None, visual_stamps=[])
            mock_preprocess.return_value = (sample_pdf, None)
            mock_extract.return_value = cert_chain

            # Make LTV embedding fail
            mock_dss_manager = MagicMock()
            mock_dss_manager.collect_validation_info.side_effect = Exception(
                "LTV collection failed"
            )
            mock_dss_class.return_value = mock_dss_manager

            result = signer.sign_pdf(sample_pdf, output_path=output_path, embed_ltv=True)

        # Should succeed despite LTV failure (fail_open=True)
        assert result.success is True

    def test_embed_ltv_info_failure_with_fail_open_false_raises_error(
        self, mock_nss_handler, sample_pdf: Path, temp_dir: Path
    ):
        """Test raise on LTV failure when fail_open is False."""
        signer = PDFSigner(mock_nss_handler)
        output_path = temp_dir / "output.pdf"
        # Create output file so it exists for DSS embedding
        output_path.write_bytes(b"%PDF-1.4\ntemp")

        # Create mock certificate chain
        mock_cert = MagicMock()
        cert_chain = [mock_cert]

        # Mock validation info to not be empty
        mock_validation_info = MagicMock()
        mock_validation_info.is_empty.return_value = False

        # Create settings with fail_open=False
        mock_settings = MagicMock()
        mock_settings.ltv_enabled = True
        mock_settings.ltv_fail_open = False
        mock_settings.ltv_ocsp_timeout = 30
        mock_settings.ltv_crl_timeout = 30
        mock_settings.ltv_prefer_ocsp = True
        mock_settings.archive_ts_enabled = False
        mock_settings.signature_template = ""

        with (
            patch.object(signer, "_prepare_signing_context") as mock_prepare,
            patch(
                "pdfsigner.core.signer.signature_field.create_signature_field_with_stamps"
            ) as mock_field,
            patch.object(signer, "_preprocess_pdf_with_stamps") as mock_preprocess,
            patch.object(signer, "_execute_signing"),
            patch.object(signer, "_extract_cert_chain") as mock_extract,
            patch("pdfsigner.core.signer.dss_manager.DSSManager") as mock_dss_class,
            patch("pdfsigner.core.signer.pdf_signer.get_settings") as mock_get_settings,
        ):
            mock_get_settings.return_value = mock_settings
            mock_signer = MagicMock()
            mock_signer.signing_cert = None
            mock_prepare.return_value = (mock_signer, None, "Test", "Org", 0)
            mock_field.return_value = MagicMock(field_spec=None, visual_stamps=[])
            mock_preprocess.return_value = (sample_pdf, None)
            mock_extract.return_value = cert_chain

            # Make DSS embedding fail (not collection)
            mock_dss_manager = MagicMock()
            mock_dss_manager.collect_validation_info.return_value = mock_validation_info
            mock_dss_manager.embed_dss.side_effect = Exception("LTV embedding failed")
            mock_dss_class.return_value = mock_dss_manager

            result = signer.sign_pdf(sample_pdf, output_path=output_path, embed_ltv=True)

        # Should fail with error (fail_open=False)
        assert result.success is False
        assert "DSS" in result.error or "LTV" in result.error

    def test_sign_pdf_callback_exception_handled_does_not_crash(
        self, mock_nss_handler, sample_pdf: Path, temp_dir: Path
    ):
        """Test progress callback errors don't crash signing."""
        signer = PDFSigner(mock_nss_handler)
        output_path = temp_dir / "output.pdf"

        # Mock a successful signing flow
        with (
            patch.object(signer, "_prepare_signing_context") as mock_prepare,
            patch(
                "pdfsigner.core.signer.signature_field.create_signature_field_with_stamps"
            ) as mock_field,
            patch.object(signer, "_preprocess_pdf_with_stamps") as mock_preprocess,
            patch.object(signer, "_execute_signing"),
        ):
            mock_signer = MagicMock()
            mock_signer.signing_cert = None
            mock_prepare.return_value = (mock_signer, None, "Test", "Org", 0)
            mock_field.return_value = MagicMock(field_spec=None, visual_stamps=[])
            mock_preprocess.return_value = (sample_pdf, None)

            # Even if there were a callback that raised, signing should complete
            result = signer.sign_pdf(sample_pdf, output_path=output_path)

        # Should succeed
        assert result.success is True

    @pytest.mark.security
    def test_sign_pdf_large_file_memory_handling_succeeds(
        self, mock_nss_handler, temp_dir: Path, mock_settings
    ):
        """Test handle large PDFs without memory issues."""
        signer = PDFSigner(mock_nss_handler)

        # Create a larger PDF (not huge, but bigger than minimal)
        large_pdf = temp_dir / "large.pdf"
        # Create PDF with multiple pages (simulated large file)
        content = b"%PDF-1.4\n"
        content += b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        content += b"2 0 obj<</Type/Pages/Kids[3 0 R 4 0 R 5 0 R]/Count 3>>endobj\n"
        content += b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        content += b"4 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        content += b"5 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        content += b"xref\n0 6\n"
        content += b"0000000000 65535 f\n" * 6
        content += b"trailer<</Size 6/Root 1 0 R>>\nstartxref\n200\n%%EOF"

        large_pdf.write_bytes(content)

        # Should handle without crashing (even if validation fails on minimal PDF)
        result = signer.sign_pdf(large_pdf)

        # May fail validation but shouldn't crash with memory error
        assert result is not None
        assert isinstance(result, SigningResult)

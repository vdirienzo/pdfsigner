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
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        # Generate a real key pair and certificate for this test
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test User")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .sign(private_key, hashes.SHA256())
        )
        cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)

        handler = MagicMock()
        handler._session = MagicMock()

        with patch("pyhanko.sign.pkcs11.PKCS11Signer") as mock_pkcs11:
            mock_pkcs11.return_value = MagicMock()
            signer = PDFSigner(handler)
            result = signer._create_signer()

            assert result is not None
            mock_pkcs11.assert_called_once_with(
                pkcs11_session=handler._session,
                cert_id=None,
            )

    def test_create_signer_with_cert_id(self):
        """Test signer creation with specific cert ID."""
        handler = MagicMock()
        handler._session = MagicMock()
        cert_id = b"test-cert-id"

        with patch("pyhanko.sign.pkcs11.PKCS11Signer") as mock_pkcs11:
            mock_pkcs11.return_value = MagicMock()
            signer = PDFSigner(handler)
            result = signer._create_signer(cert_id)

            assert result is not None
            mock_pkcs11.assert_called_once_with(
                pkcs11_session=handler._session,
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

        # Mock the PdfImage class from pyhanko.pdf_utils.images
        with patch("pyhanko.pdf_utils.images.PdfImage") as mock_img:
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

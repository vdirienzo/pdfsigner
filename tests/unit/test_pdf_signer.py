"""
test_pdf_signer.py - Tests for PDFSigner

Author: Homero Thompson del Lago del Terror
"""

from datetime import datetime
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

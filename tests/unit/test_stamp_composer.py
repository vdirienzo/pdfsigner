"""
test_stamp_composer.py - Tests for stamp composition

Author: Homero Thompson del Lago del Terror
"""

from datetime import UTC, datetime

from PIL import Image

from pdfsigner.core.stamp.qr_generator import QRData
from pdfsigner.core.stamp.stamp_composer import (
    compose_stamp_text_only,
    compose_stamp_with_qr,
)


class TestComposeStampWithQR:
    """Tests for stamp composition with QR code."""

    def test_creates_temp_file(self):
        """Test that a temporary PNG file is created."""
        qr_data = QRData(
            document_hash="a" * 64,
            signer_name="Test User",
        )

        result = compose_stamp_with_qr(
            signer_name="Test User",
            timestamp=datetime.now(UTC),
            qr_data=qr_data,
        )

        assert result.exists()
        assert result.suffix == ".png"
        assert "pdfsigner_stamp_" in result.name

    def test_image_dimensions(self):
        """Test default image dimensions."""
        qr_data = QRData(
            document_hash="b" * 64,
            signer_name="Test",
        )

        result = compose_stamp_with_qr(
            signer_name="Test",
            timestamp=datetime.now(UTC),
            qr_data=qr_data,
        )

        img = Image.open(result)
        assert img.size[0] == 200  # Default width
        assert img.size[1] == 70  # Default height

    def test_custom_dimensions(self):
        """Test custom image dimensions."""
        qr_data = QRData(
            document_hash="c" * 64,
            signer_name="Test",
        )

        result = compose_stamp_with_qr(
            signer_name="Test",
            timestamp=datetime.now(UTC),
            qr_data=qr_data,
            width_px=300,
            height_px=100,
        )

        img = Image.open(result)
        assert img.size == (300, 100)

    def test_qr_position_left(self):
        """Test QR on left side (default)."""
        qr_data = QRData(
            document_hash="d" * 64,
            signer_name="Test",
        )

        result = compose_stamp_with_qr(
            signer_name="Test",
            timestamp=datetime.now(UTC),
            qr_data=qr_data,
            qr_position="left",
        )

        assert result.exists()
        # Visual test would require inspecting the image

    def test_qr_position_right(self):
        """Test QR on right side."""
        qr_data = QRData(
            document_hash="e" * 64,
            signer_name="Test",
        )

        result = compose_stamp_with_qr(
            signer_name="Test",
            timestamp=datetime.now(UTC),
            qr_data=qr_data,
            qr_position="right",
        )

        assert result.exists()

    def test_long_signer_name_truncated(self):
        """Test that long signer names are truncated."""
        long_name = "A" * 100
        qr_data = QRData(
            document_hash="f" * 64,
            signer_name=long_name,
        )

        result = compose_stamp_with_qr(
            signer_name=long_name,
            timestamp=datetime.now(UTC),
            qr_data=qr_data,
        )

        # Should not raise, and file should be created
        assert result.exists()

    def test_image_is_rgb(self):
        """Test that output image is RGB."""
        qr_data = QRData(
            document_hash="0" * 64,
            signer_name="Test",
        )

        result = compose_stamp_with_qr(
            signer_name="Test",
            timestamp=datetime.now(UTC),
            qr_data=qr_data,
        )

        img = Image.open(result)
        assert img.mode == "RGB"


class TestComposeStampTextOnly:
    """Tests for text-only stamp composition."""

    def test_creates_temp_file(self):
        """Test that a temporary PNG file is created."""
        result = compose_stamp_text_only(
            signer_name="Test User",
            timestamp=datetime.now(UTC),
        )

        assert result.exists()
        assert result.suffix == ".png"

    def test_default_dimensions(self):
        """Test default image dimensions."""
        result = compose_stamp_text_only(
            signer_name="Test",
            timestamp=datetime.now(UTC),
        )

        img = Image.open(result)
        assert img.size[0] == 200  # Default width
        assert img.size[1] == 70  # Default height

    def test_custom_dimensions(self):
        """Test custom dimensions."""
        result = compose_stamp_text_only(
            signer_name="Test",
            timestamp=datetime.now(UTC),
            width_px=250,
            height_px=80,
        )

        img = Image.open(result)
        assert img.size == (250, 80)

    def test_long_name_truncated(self):
        """Test that long names are handled."""
        long_name = "B" * 100

        result = compose_stamp_text_only(
            signer_name=long_name,
            timestamp=datetime.now(UTC),
        )

        assert result.exists()


class TestCleanup:
    """Tests for temporary file handling."""

    def test_temp_files_are_deletable(self):
        """Test that temp files can be deleted."""
        qr_data = QRData(
            document_hash="1" * 64,
            signer_name="Test",
        )

        result = compose_stamp_with_qr(
            signer_name="Test",
            timestamp=datetime.now(UTC),
            qr_data=qr_data,
        )

        # Should be able to delete
        result.unlink()
        assert not result.exists()

"""
test_qr_generator.py - Tests for QR code generation

Author: Homero Thompson del Lago del Terror
"""

from datetime import UTC, datetime
from pathlib import Path

from pdfsigner.core.stamp.qr_generator import (
    QRData,
    calculate_document_hash,
    generate_qr_bytes,
    generate_qr_image,
)


class TestQRData:
    """Tests for QRData dataclass."""

    def test_to_json_basic(self):
        """Test JSON serialization with basic data."""
        qr_data = QRData(
            document_hash="a" * 64,
            signer_name="Test User",
            timestamp=datetime(2025, 1, 15, 10, 30, 0, tzinfo=UTC),
        )

        json_str = qr_data.to_json()

        assert "aaaaaaaaaaaaaaaa..." in json_str  # Truncated hash
        assert "Test User" in json_str
        assert "2025-01-15T10:30:00Z" in json_str

    def test_to_json_contains_required_fields(self):
        """Test JSON contains all required signature data."""
        qr_data = QRData(
            document_hash="b" * 64,
            signer_name="Signer Name",
        )

        json_str = qr_data.to_json()

        assert "hash" in json_str
        assert "signer" in json_str
        assert "ts" in json_str


class TestCalculateDocumentHash:
    """Tests for document hash calculation."""

    def test_hash_pdf_file(self, tmp_path: Path):
        """Test hashing a PDF file."""
        # Create test file
        test_file = tmp_path / "test.pdf"
        test_file.write_bytes(b"%PDF-1.4 test content")

        result = calculate_document_hash(test_file)

        assert len(result) == 64  # SHA-256 hex
        assert all(c in "0123456789abcdef" for c in result)

    def test_same_content_same_hash(self, tmp_path: Path):
        """Test that same content produces same hash."""
        content = b"Same PDF content"

        file1 = tmp_path / "file1.pdf"
        file2 = tmp_path / "file2.pdf"
        file1.write_bytes(content)
        file2.write_bytes(content)

        hash1 = calculate_document_hash(file1)
        hash2 = calculate_document_hash(file2)

        assert hash1 == hash2

    def test_different_content_different_hash(self, tmp_path: Path):
        """Test that different content produces different hash."""
        file1 = tmp_path / "file1.pdf"
        file2 = tmp_path / "file2.pdf"
        file1.write_bytes(b"Content A")
        file2.write_bytes(b"Content B")

        hash1 = calculate_document_hash(file1)
        hash2 = calculate_document_hash(file2)

        assert hash1 != hash2


class TestGenerateQRImage:
    """Tests for QR image generation."""

    def test_generates_image(self):
        """Test that QR image is generated."""
        qr_data = QRData(
            document_hash="e" * 64,
            signer_name="Test",
        )

        img = generate_qr_image(qr_data)

        assert img is not None
        assert img.size == (150, 150)  # Default size

    def test_custom_size(self):
        """Test QR with custom size."""
        qr_data = QRData(
            document_hash="f" * 64,
            signer_name="Test",
        )

        img = generate_qr_image(qr_data, size_px=200)

        assert img.size == (200, 200)

    def test_image_is_black_and_white(self):
        """Test that QR image is primarily black and white."""
        qr_data = QRData(
            document_hash="0" * 64,
            signer_name="Test",
        )

        img = generate_qr_image(qr_data).convert("RGB")

        # Sample some pixels - should be black or white
        pixels = list(img.getdata())
        white_count = sum(1 for p in pixels if p == (255, 255, 255))
        black_count = sum(1 for p in pixels if p == (0, 0, 0))

        # Most pixels should be black or white
        total = len(pixels)
        assert (white_count + black_count) / total > 0.95


class TestGenerateQRBytes:
    """Tests for QR bytes generation."""

    def test_generates_png_bytes(self):
        """Test that PNG bytes are generated."""
        qr_data = QRData(
            document_hash="1" * 64,
            signer_name="Test",
        )

        data = generate_qr_bytes(qr_data)

        # PNG magic bytes
        assert data[:8] == b"\x89PNG\r\n\x1a\n"

    def test_bytes_can_be_saved(self, tmp_path: Path):
        """Test that bytes can be saved to file."""
        qr_data = QRData(
            document_hash="2" * 64,
            signer_name="Test",
        )

        data = generate_qr_bytes(qr_data)
        output_file = tmp_path / "qr.png"
        output_file.write_bytes(data)

        assert output_file.exists()
        assert output_file.stat().st_size > 0

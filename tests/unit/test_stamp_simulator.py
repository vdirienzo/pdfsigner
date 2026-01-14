"""
test_stamp_simulator.py - Tests for StampSimulator (dry-run mode)

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path

import fitz
import pytest

from pdfsigner.core.mock.stamp_simulator import (
    get_stamp_rect,
    parse_page_spec,
)


class TestParsePageSpec:
    """Tests for parse_page_spec function."""

    def test_parse_last(self):
        """Test parsing 'last' page spec."""
        result = parse_page_spec("last", total_pages=5)
        assert result == [4]  # 0-indexed

    def test_parse_first(self):
        """Test parsing 'first' page spec."""
        result = parse_page_spec("first", total_pages=5)
        assert result == [0]

    def test_parse_all(self):
        """Test parsing 'all' page spec."""
        result = parse_page_spec("all", total_pages=5)
        assert result == [0, 1, 2, 3, 4]

    def test_parse_integer(self):
        """Test parsing integer page spec."""
        result = parse_page_spec(3, total_pages=5)
        assert result == [3]

    def test_parse_integer_exceeds_pages(self):
        """Test integer exceeding total pages."""
        result = parse_page_spec(10, total_pages=5)
        assert result == [4]  # Should clamp to last page

    def test_parse_single_number_string(self):
        """Test parsing single number as string."""
        result = parse_page_spec("3", total_pages=5)
        assert result == [2]  # 1-indexed to 0-indexed

    def test_parse_comma_separated(self):
        """Test parsing comma-separated list."""
        result = parse_page_spec("1,3,5", total_pages=5)
        assert result == [0, 2, 4]

    def test_parse_range(self):
        """Test parsing range specification."""
        result = parse_page_spec("2-4", total_pages=5)
        assert result == [1, 2, 3]

    def test_parse_invalid_returns_last(self):
        """Test invalid spec returns last page."""
        result = parse_page_spec("invalid", total_pages=5)
        assert result == [4]

    def test_parse_filters_out_of_range(self):
        """Test out of range pages are filtered."""
        result = parse_page_spec("1,10,20", total_pages=5)
        assert result == [0]  # Only page 1 is valid


class TestGetStampRect:
    """Tests for get_stamp_rect function."""

    def test_bottom_right_position(self):
        """Test bottom-right positioning."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="bottom_right",
            stamp_width=140,
            stamp_height=50,
        )

        # Should be near bottom-right corner
        assert rect.x1 < 612  # Within page width
        assert rect.y1 < 792  # Within page height
        assert rect.x0 > 400  # In right half
        assert rect.y0 > 700  # Near bottom

    def test_bottom_left_position(self):
        """Test bottom-left positioning."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="bottom_left",
            stamp_width=140,
            stamp_height=50,
        )

        # Should be near bottom-left corner
        assert rect.x0 < 100  # In left portion
        assert rect.y0 > 700  # Near bottom

    def test_top_right_position(self):
        """Test top-right positioning."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="top_right",
            stamp_width=140,
            stamp_height=50,
        )

        # Should be near top-right corner
        assert rect.x0 > 400  # In right half
        assert rect.y0 < 100  # Near top

    def test_top_left_position(self):
        """Test top-left positioning."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="top_left",
            stamp_width=140,
            stamp_height=50,
        )

        # Should be near top-left corner
        assert rect.x0 < 100  # In left portion
        assert rect.y0 < 100  # Near top

    def test_auto_position(self):
        """Test auto positioning defaults to bottom-right."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="auto",
            stamp_width=140,
            stamp_height=50,
        )

        # Auto should default to bottom-right
        assert rect.x0 > 400
        assert rect.y0 > 700

    def test_stamp_dimensions(self):
        """Test stamp has correct dimensions."""
        rect = get_stamp_rect(
            page_width=612,
            page_height=792,
            position="bottom_right",
            stamp_width=140,
            stamp_height=50,
        )

        assert rect.width == 140
        assert rect.height == 50


class TestCreateDemoStampImage:
    """Tests for _create_demo_stamp_image function."""

    def test_creates_png_bytes_with_qr(self):
        """Test creates PNG bytes when QR is enabled."""
        import io
        from datetime import UTC, datetime

        from PIL import Image

        from pdfsigner.core.mock.stamp_simulator import (
            STAMP_HEIGHT_PX,
            STAMP_WIDTH_PX,
            _create_demo_stamp_image,
        )

        result = _create_demo_stamp_image(
            document_hash="a" * 64,
            timestamp=datetime.now(UTC),
            qr_enabled=True,
        )

        assert isinstance(result, bytes)
        # Verify it's a valid PNG
        img = Image.open(io.BytesIO(result))
        assert img.format == "PNG"
        assert img.size == (STAMP_WIDTH_PX, STAMP_HEIGHT_PX)

    def test_creates_smaller_image_without_qr(self):
        """Test creates smaller image when QR is disabled."""
        import io
        from datetime import UTC, datetime

        from PIL import Image

        from pdfsigner.core.mock.stamp_simulator import _create_demo_stamp_image

        result = _create_demo_stamp_image(
            document_hash="b" * 64,
            timestamp=datetime.now(UTC),
            qr_enabled=False,
        )

        img = Image.open(io.BytesIO(result))
        assert img.size == (380, 130)  # Smaller without QR (150 DPI)


class TestCalculateDemoHash:
    """Tests for _calculate_demo_hash function."""

    def test_calculates_sha256_hash(self):
        """Test calculates SHA-256 hash of file."""
        import tempfile

        from pdfsigner.core.mock.stamp_simulator import _calculate_demo_hash

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test content")
            f.flush()
            path = Path(f.name)

        result = _calculate_demo_hash(path)
        path.unlink()

        assert len(result) == 64  # SHA-256 hex is 64 chars
        assert result.isalnum()


class TestAddStampToPdf:
    """Tests for add_stamp_to_pdf function."""

    @pytest.fixture
    def sample_pdf(self):
        """Create a sample PDF for testing."""
        import tempfile

        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Test document")

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            doc.save(f.name)
            doc.close()
            yield Path(f.name)

        Path(f.name).unlink(missing_ok=True)

    def test_adds_stamp_with_qr(self, sample_pdf):
        """Test adds stamp image with QR code."""
        import tempfile

        output = Path(tempfile.mktemp(suffix="_signed.pdf"))

        try:
            from pdfsigner.core.mock.stamp_simulator import add_stamp_to_pdf

            add_stamp_to_pdf(
                input_path=sample_pdf,
                output_path=output,
                visible=True,
                qr_enabled=True,
            )

            assert output.exists()

            # Verify image was inserted
            doc = fitz.open(str(output))
            images = doc[0].get_images()
            assert len(images) == 1

            # Verify dimensions (QR mode at 150 DPI)
            xref = images[0][0]
            img = doc.extract_image(xref)
            from pdfsigner.core.mock.stamp_simulator import (
                STAMP_HEIGHT_PX,
                STAMP_WIDTH_PX,
            )

            assert img["width"] == STAMP_WIDTH_PX
            assert img["height"] == STAMP_HEIGHT_PX
            doc.close()
        finally:
            output.unlink(missing_ok=True)

    def test_adds_stamp_without_qr(self, sample_pdf):
        """Test adds stamp image without QR code."""
        import tempfile

        output = Path(tempfile.mktemp(suffix="_signed.pdf"))

        try:
            from pdfsigner.core.mock.stamp_simulator import add_stamp_to_pdf

            add_stamp_to_pdf(
                input_path=sample_pdf,
                output_path=output,
                visible=True,
                qr_enabled=False,
            )

            assert output.exists()

            # Verify image was inserted
            doc = fitz.open(str(output))
            images = doc[0].get_images()
            assert len(images) == 1

            # Verify dimensions (no QR, 150 DPI)
            xref = images[0][0]
            img = doc.extract_image(xref)
            assert img["width"] == 380
            assert img["height"] == 130
            doc.close()
        finally:
            output.unlink(missing_ok=True)

    def test_invisible_signature_just_copies(self, sample_pdf):
        """Test invisible signature just copies file."""
        import tempfile

        output = Path(tempfile.mktemp(suffix="_signed.pdf"))

        try:
            from pdfsigner.core.mock.stamp_simulator import add_stamp_to_pdf

            add_stamp_to_pdf(
                input_path=sample_pdf,
                output_path=output,
                visible=False,
            )

            assert output.exists()

            # Should be a copy without images
            doc = fitz.open(str(output))
            images = doc[0].get_images()
            assert len(images) == 0
            doc.close()
        finally:
            output.unlink(missing_ok=True)

    def test_stamps_multiple_pages(self, sample_pdf):
        """Test stamps all pages when specified."""
        import tempfile

        # Create multi-page PDF
        doc = fitz.open()
        for i in range(3):
            page = doc.new_page()
            page.insert_text((72, 72), f"Page {i + 1}")

        multi_pdf = Path(tempfile.mktemp(suffix=".pdf"))
        doc.save(str(multi_pdf))
        doc.close()

        output = Path(tempfile.mktemp(suffix="_signed.pdf"))

        try:
            from pdfsigner.core.mock.stamp_simulator import add_stamp_to_pdf

            add_stamp_to_pdf(
                input_path=multi_pdf,
                output_path=output,
                page_spec="all",
                visible=True,
                qr_enabled=True,
            )

            doc = fitz.open(str(output))
            for i in range(3):
                images = doc[i].get_images()
                assert len(images) == 1, f"Page {i} should have stamp"
            doc.close()
        finally:
            multi_pdf.unlink(missing_ok=True)
            output.unlink(missing_ok=True)

"""
test_signing_e2e.py - End-to-end tests for PDF signing workflow

Author: Homero Thompson del Lago del Terror

Tests the complete signing workflow using dry-run mode.
Covers all combinations of:
- Page selection: first, last, all, specific pages, ranges
- Position: all 5 positions + AUTO
- Templates: default, minimal, corporate, with_qr, none
- QR codes: enabled/disabled
- Single vs batch signing
"""

import shutil
import tempfile
from pathlib import Path

import fitz  # PyMuPDF
import pytest

from pdfsigner.core.mock.mock_batch import MockBatchManager
from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
from pdfsigner.core.signer.pdf_signer import SignatureAppearance

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    tmp = tempfile.mkdtemp(prefix="pdfsigner_e2e_")
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def sample_pdf_1page(temp_dir: Path) -> Path:
    """Create a simple 1-page PDF for testing."""
    pdf_path = temp_dir / "sample_1page.pdf"
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)  # A4
    page.insert_text((72, 72), "Test Document - Page 1", fontsize=24)
    page.insert_text((72, 120), "This is a sample PDF for E2E testing.", fontsize=12)
    doc.save(pdf_path)
    doc.close()
    return pdf_path


@pytest.fixture
def sample_pdf_3pages(temp_dir: Path) -> Path:
    """Create a 3-page PDF for testing multi-page signing."""
    pdf_path = temp_dir / "sample_3pages.pdf"
    doc = fitz.open()
    for i in range(1, 4):
        page = doc.new_page(width=595, height=842)  # A4
        page.insert_text((72, 72), f"Test Document - Page {i}", fontsize=24)
        page.insert_text((72, 120), f"Content for page {i} of the test PDF.", fontsize=12)
        # Add some content in different areas to test position detection
        page.insert_text((72, 750), f"Footer content on page {i}", fontsize=10)
    doc.save(pdf_path)
    doc.close()
    return pdf_path


@pytest.fixture
def sample_pdf_10pages(temp_dir: Path) -> Path:
    """Create a 10-page PDF for testing large documents and ranges."""
    pdf_path = temp_dir / "sample_10pages.pdf"
    doc = fitz.open()
    for i in range(1, 11):
        page = doc.new_page(width=595, height=842)  # A4
        page.insert_text((72, 72), f"Document Page {i}/10", fontsize=24)
        page.insert_text((72, 120), f"This is page {i} of a 10-page document.", fontsize=12)
    doc.save(pdf_path)
    doc.close()
    return pdf_path


@pytest.fixture
def batch_pdfs(temp_dir: Path) -> list[Path]:
    """Create multiple PDFs for batch signing tests."""
    pdfs = []
    for i in range(1, 4):
        pdf_path = temp_dir / f"batch_doc_{i}.pdf"
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)
        page.insert_text((72, 72), f"Batch Document {i}", fontsize=24)
        doc.save(pdf_path)
        doc.close()
        pdfs.append(pdf_path)
    return pdfs


# ============================================================================
# Test Classes
# ============================================================================


class TestSinglePageSigning:
    """Tests for signing on a single page (first, last, specific)."""

    def test_sign_last_page_default(self, sample_pdf_1page: Path, temp_dir: Path):
        """Sign on last page with default settings."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="last",
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_1page],
            appearance=appearance,
        )

        assert result.all_successful
        assert result.successful == 1
        assert result.failed == 0
        assert len(result.results) == 1
        assert result.results[0].output_path.exists()

    def test_sign_first_page(self, sample_pdf_3pages: Path, temp_dir: Path):
        """Sign on first page of multi-page document."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="first",
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_3pages],
            appearance=appearance,
        )

        assert result.all_successful
        # Verify output exists
        output_path = result.results[0].output_path
        assert output_path.exists()
        # Verify it's still a valid PDF with 3 pages
        doc = fitz.open(output_path)
        assert len(doc) == 3
        doc.close()

    def test_sign_specific_page_number(self, sample_pdf_3pages: Path, temp_dir: Path):
        """Sign on specific page number (page 2)."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page=1,  # 0-indexed, so page 2
            position_preference=PositionPreference.BOTTOM_CENTER,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_3pages],
            appearance=appearance,
        )

        assert result.all_successful
        assert result.results[0].output_path.exists()


class TestMultiPageSigning:
    """Tests for signing on multiple pages (all, ranges)."""

    def test_sign_all_pages(self, sample_pdf_3pages: Path, temp_dir: Path):
        """Sign on all pages."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="all",
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_3pages],
            appearance=appearance,
        )

        assert result.all_successful
        output_path = result.results[0].output_path
        assert output_path.exists()

        # Verify all 3 pages have visual stamps
        doc = fitz.open(output_path)
        assert len(doc) == 3
        # Check that each page has been modified (has images from stamps)
        for page in doc:
            images = page.get_images()
            assert len(images) > 0, f"Page {page.number + 1} should have stamp image"
        doc.close()

    def test_sign_page_range(self, sample_pdf_10pages: Path, temp_dir: Path):
        """Sign on specific page range (pages 2-5)."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="2-5",  # Pages 2, 3, 4, 5 (1-based in user input)
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_10pages],
            appearance=appearance,
        )

        assert result.all_successful
        output_path = result.results[0].output_path
        assert output_path.exists()

        # Verify 10 pages still exist
        doc = fitz.open(output_path)
        assert len(doc) == 10
        doc.close()

    def test_sign_comma_separated_pages(self, sample_pdf_10pages: Path, temp_dir: Path):
        """Sign on comma-separated pages (1, 5, 10)."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="1,5,10",
            position_preference=PositionPreference.TOP_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_10pages],
            appearance=appearance,
        )

        assert result.all_successful


class TestPositionPreferences:
    """Tests for all position preference options."""

    @pytest.mark.parametrize(
        "position",
        [
            PositionPreference.BOTTOM_RIGHT,
            PositionPreference.BOTTOM_LEFT,
            PositionPreference.BOTTOM_CENTER,
            PositionPreference.TOP_RIGHT,
            PositionPreference.TOP_LEFT,
            PositionPreference.AUTO,
        ],
    )
    def test_all_positions(self, sample_pdf_1page: Path, position: PositionPreference):
        """Test all position preferences."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="last",
            position_preference=position,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_1page],
            appearance=appearance,
        )

        assert result.all_successful, f"Position {position.value} failed"
        assert result.results[0].output_path.exists()

    def test_position_on_all_pages(self, sample_pdf_3pages: Path):
        """Test that position is respected on all pages when using 'all'."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="all",
            position_preference=PositionPreference.TOP_LEFT,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_3pages],
            appearance=appearance,
        )

        assert result.all_successful


class TestTemplates:
    """Tests for different signature templates."""

    @pytest.mark.parametrize(
        "template_name",
        [
            "default",
            "minimal",
            "corporate",
            "with_qr",
        ],
    )
    def test_builtin_templates(self, sample_pdf_1page: Path, template_name: str):
        """Test all built-in templates."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="last",
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_1page],
            appearance=appearance,
            template_override=template_name,
        )

        assert result.all_successful, f"Template '{template_name}' failed"

    def test_invisible_signature(self, sample_pdf_1page: Path):
        """Test invisible signature (no visual stamp)."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=False,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_1page],
            appearance=appearance,
        )

        assert result.all_successful
        # Output should exist but be essentially a copy (no visual changes)
        assert result.results[0].output_path.exists()


class TestQRCodes:
    """Tests for QR code functionality."""

    def test_qr_enabled(self, sample_pdf_1page: Path):
        """Test signing with QR code enabled."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="last",
            position_preference=PositionPreference.BOTTOM_RIGHT,
            qr_enabled=True,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_1page],
            appearance=appearance,
        )

        assert result.all_successful

    def test_qr_with_template(self, sample_pdf_1page: Path):
        """Test QR code with with_qr template."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="last",
            position_preference=PositionPreference.BOTTOM_RIGHT,
            qr_enabled=True,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_1page],
            appearance=appearance,
            template_override="with_qr",
        )

        assert result.all_successful


class TestBatchSigning:
    """Tests for batch signing multiple files."""

    def test_batch_multiple_files(self, batch_pdfs: list[Path]):
        """Test signing multiple files in batch."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="last",
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=batch_pdfs,
            appearance=appearance,
        )

        assert result.all_successful
        assert result.successful == 3
        assert result.failed == 0
        assert len(result.results) == 3

        # Verify all outputs exist
        for res in result.results:
            assert res.output_path.exists()

    def test_batch_with_progress_callback(self, batch_pdfs: list[Path]):
        """Test batch signing with progress callback."""
        progress_updates = []

        def progress_callback(progress):
            progress_updates.append(
                {
                    "current": progress.current,
                    "total": progress.total,
                    "status": progress.status,
                }
            )

        manager = MockBatchManager()
        appearance = SignatureAppearance(visible=True, page="last")

        result = manager.sign_batch(
            pdf_files=batch_pdfs,
            appearance=appearance,
            progress_callback=progress_callback,
        )

        assert result.all_successful
        # Should have progress updates for each file
        assert len(progress_updates) >= len(batch_pdfs)

    def test_batch_empty_list(self):
        """Test batch signing with empty file list."""
        manager = MockBatchManager()

        result = manager.sign_batch(pdf_files=[])

        assert result.all_successful
        assert result.successful == 0
        assert result.failed == 0


class TestSignatureDimensions:
    """Tests for different signature dimensions."""

    @pytest.mark.parametrize(
        "width_mm,height_mm",
        [
            (50, 20),  # Default
            (60, 25),  # Larger
            (30, 15),  # Smaller
            (80, 30),  # Wide
            (40, 40),  # Square
        ],
    )
    def test_various_dimensions(self, sample_pdf_1page: Path, width_mm: float, height_mm: float):
        """Test various signature dimensions."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="last",
            width_mm=width_mm,
            height_mm=height_mm,
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_1page],
            appearance=appearance,
        )

        assert result.all_successful


class TestCombinations:
    """Tests for combinations of settings."""

    def test_all_pages_top_left_with_qr(self, sample_pdf_3pages: Path):
        """Test: all pages + top_left + QR enabled."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="all",
            position_preference=PositionPreference.TOP_LEFT,
            qr_enabled=True,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_3pages],
            appearance=appearance,
            template_override="with_qr",
        )

        assert result.all_successful

    def test_page_range_bottom_center_corporate(self, sample_pdf_10pages: Path):
        """Test: page range + bottom_center + corporate template."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="1,3,5,7,9",
            position_preference=PositionPreference.BOTTOM_CENTER,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_10pages],
            appearance=appearance,
            template_override="corporate",
        )

        assert result.all_successful

    def test_batch_all_pages_minimal_template(self, batch_pdfs: list[Path]):
        """Test: batch + all pages + minimal template."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="all",
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=batch_pdfs,
            appearance=appearance,
            template_override="minimal",
        )

        assert result.all_successful
        assert result.successful == 3


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_single_page_with_all(self, sample_pdf_1page: Path):
        """Test 'all' pages on a single-page document."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="all",
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_1page],
            appearance=appearance,
        )

        assert result.all_successful

    def test_page_number_exceeds_total(self, sample_pdf_1page: Path):
        """Test page number that exceeds document pages."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page=99,  # Way beyond single page
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_1page],
            appearance=appearance,
        )

        # Should handle gracefully (use last page)
        assert result.all_successful

    def test_invalid_page_range_fallback(self, sample_pdf_3pages: Path):
        """Test invalid page range falls back gracefully."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(
            visible=True,
            page="invalid-range",
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )

        result = manager.sign_batch(
            pdf_files=[sample_pdf_3pages],
            appearance=appearance,
        )

        # Should fall back to last page
        assert result.all_successful


class TestOutputVerification:
    """Tests that verify output PDF properties."""

    def test_output_has_correct_suffix(self, sample_pdf_1page: Path):
        """Test that output file has _signed suffix."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(visible=True, page="last")

        result = manager.sign_batch(
            pdf_files=[sample_pdf_1page],
            appearance=appearance,
        )

        output_path = result.results[0].output_path
        assert "_signed" in output_path.stem

    def test_output_is_valid_pdf(self, sample_pdf_1page: Path):
        """Test that output is a valid, readable PDF."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(visible=True, page="last")

        result = manager.sign_batch(
            pdf_files=[sample_pdf_1page],
            appearance=appearance,
        )

        output_path = result.results[0].output_path

        # Should be openable by PyMuPDF
        doc = fitz.open(output_path)
        assert len(doc) > 0
        doc.close()

    def test_output_preserves_page_count(self, sample_pdf_3pages: Path):
        """Test that signing preserves original page count."""
        manager = MockBatchManager()
        appearance = SignatureAppearance(visible=True, page="all")

        result = manager.sign_batch(
            pdf_files=[sample_pdf_3pages],
            appearance=appearance,
        )

        # Original has 3 pages
        doc_orig = fitz.open(sample_pdf_3pages)
        orig_count = len(doc_orig)
        doc_orig.close()

        # Output should also have 3 pages
        doc_out = fitz.open(result.results[0].output_path)
        out_count = len(doc_out)
        doc_out.close()

        assert out_count == orig_count


# ============================================================================
# Main entry point for running standalone
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

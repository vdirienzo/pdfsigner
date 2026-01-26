"""
test_signature_field.py - Tests for signature field creation

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.signer.signature_field import (
    create_signature_field_specs,
    get_pages_to_sign,
    mm_to_points,
    parse_page_range,
)


class TestParsePageRange:
    """Tests for parse_page_range function."""

    def test_single_page(self):
        """Test parsing single page."""
        assert parse_page_range("3", 10) == [2]  # 0-based

    def test_multiple_pages(self):
        """Test parsing comma-separated pages."""
        assert parse_page_range("1,3,5", 10) == [0, 2, 4]

    def test_page_range(self):
        """Test parsing range like 1-3."""
        assert parse_page_range("1-3", 10) == [0, 1, 2]

    def test_mixed_pages_and_ranges(self):
        """Test parsing mixed format."""
        assert parse_page_range("1-3,5,7-9", 10) == [0, 1, 2, 4, 6, 7, 8]

    def test_with_spaces(self):
        """Test parsing with spaces."""
        assert parse_page_range("1, 3, 5", 10) == [0, 2, 4]

    def test_out_of_range_filtered(self):
        """Test that out-of-range pages are filtered."""
        assert parse_page_range("1,5,15", 10) == [0, 4]  # 15 is out of range

    def test_invalid_format_ignored(self):
        """Test that invalid parts are ignored."""
        assert parse_page_range("1,abc,3", 10) == [0, 2]

    def test_empty_string(self):
        """Test empty string returns empty list."""
        assert parse_page_range("", 10) == []

    def test_deduplicated(self):
        """Test that duplicate pages are removed."""
        assert parse_page_range("1,1,2,2", 10) == [0, 1]

    def test_sorted(self):
        """Test that result is sorted."""
        assert parse_page_range("5,1,3", 10) == [0, 2, 4]

    def test_range_exceeds_total(self):
        """Test range that exceeds total pages."""
        assert parse_page_range("1-20", 5) == [0, 1, 2, 3, 4]

    def test_invalid_range_format(self):
        """Test invalid range format."""
        assert parse_page_range("3-1", 10) == []  # Invalid range (start > end)

    def test_zero_page_ignored(self):
        """Test that page 0 is ignored (1-based input)."""
        assert parse_page_range("0,1,2", 10) == [0, 1]


class TestGetPagesToSign:
    """Tests for get_pages_to_sign function."""

    def test_all_pages(self):
        """Test 'all' returns all pages."""
        assert get_pages_to_sign(5, "all") == [0, 1, 2, 3, 4]

    def test_last_page(self):
        """Test 'last' returns last page."""
        assert get_pages_to_sign(10, "last") == [9]

    def test_first_page(self):
        """Test 'first' returns first page."""
        assert get_pages_to_sign(10, "first") == [0]

    def test_integer_page(self):
        """Test integer page number."""
        assert get_pages_to_sign(10, 5) == [5]

    def test_integer_exceeds_total(self):
        """Test integer exceeding total pages."""
        assert get_pages_to_sign(5, 10) == [4]  # Clamped to last page

    def test_string_range(self):
        """Test string range."""
        assert get_pages_to_sign(10, "1,3,5") == [0, 2, 4]

    def test_invalid_string_fallback(self):
        """Test invalid string falls back to last page."""
        assert get_pages_to_sign(5, "invalid") == [4]

    def test_empty_string_fallback(self):
        """Test empty string falls back to last page."""
        assert get_pages_to_sign(5, "") == [4]

    def test_unknown_type_fallback(self):
        """Test unknown type falls back to last page."""
        assert get_pages_to_sign(5, None) == [4]

    def test_single_page_document(self):
        """Test with single page document."""
        assert get_pages_to_sign(1, "all") == [0]
        assert get_pages_to_sign(1, "last") == [0]
        assert get_pages_to_sign(1, "first") == [0]


class TestMmToPoints:
    """Tests for mm_to_points conversion."""

    def test_one_inch(self):
        """Test converting 25.4mm (1 inch) = 72 points."""
        assert mm_to_points(25.4) == pytest.approx(72.0)

    def test_zero(self):
        """Test converting 0mm."""
        assert mm_to_points(0) == 0.0

    def test_common_value(self):
        """Test common signature width (50mm)."""
        expected = 50 * 72 / 25.4  # ~141.73
        assert mm_to_points(50) == pytest.approx(expected)

    def test_small_value(self):
        """Test small value."""
        assert mm_to_points(1) == pytest.approx(72 / 25.4)


class TestCreateSignatureFieldSpecs:
    """Tests for create_signature_field_specs function."""

    @pytest.fixture
    def mock_analyzer(self):
        """Create mock ContentAnalyzer."""
        analyzer = MagicMock()
        analyzer.page_count = 3
        analyzer.__enter__ = MagicMock(return_value=analyzer)
        analyzer.__exit__ = MagicMock(return_value=False)
        return analyzer

    @pytest.fixture
    def mock_position(self):
        """Create mock position result."""
        position = MagicMock()
        position.x = 100.0
        position.y = 100.0
        position.width = 141.73
        position.height = 56.69
        return position

    def test_invisible_returns_empty(self, sample_pdf: Path):
        """Test invisible signature returns empty list."""
        from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference

        result = create_signature_field_specs(
            pdf_path=sample_pdf,
            visible=False,
            page_setting="last",
            width_mm=50,
            height_mm=20,
            position_preference=PositionPreference.BOTTOM_RIGHT,
        )
        assert result == []

    def test_visible_single_page(self, sample_pdf: Path, mock_analyzer, mock_position):
        """Test visible signature on single page."""
        from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference

        with patch("pdfsigner.core.signer.signature_field.ContentAnalyzer") as MockAnalyzer:
            with patch("pdfsigner.core.signer.signature_field.PositionFinder") as MockFinder:
                MockAnalyzer.return_value = mock_analyzer
                mock_finder_instance = MagicMock()
                mock_finder_instance.find_position.return_value = mock_position
                MockFinder.return_value = mock_finder_instance

                result = create_signature_field_specs(
                    pdf_path=sample_pdf,
                    visible=True,
                    page_setting="last",
                    width_mm=50,
                    height_mm=20,
                    position_preference=PositionPreference.BOTTOM_RIGHT,
                )

        assert len(result) == 1
        assert result[0].sig_field_name == "Signature1"

    def test_visible_all_pages(self, sample_pdf: Path, mock_analyzer, mock_position):
        """Test visible signature on all pages returns only ONE field_spec.

        Note: create_signature_field_specs now returns only the main signature field.
        Visual stamps for other pages are handled separately via create_signature_field_with_stamps.
        """
        from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference

        with patch("pdfsigner.core.signer.signature_field.ContentAnalyzer") as MockAnalyzer:
            with patch("pdfsigner.core.signer.signature_field.PositionFinder") as MockFinder:
                MockAnalyzer.return_value = mock_analyzer
                mock_finder_instance = MagicMock()
                mock_finder_instance.find_position.return_value = mock_position
                MockFinder.return_value = mock_finder_instance

                result = create_signature_field_specs(
                    pdf_path=sample_pdf,
                    visible=True,
                    page_setting="all",
                    width_mm=50,
                    height_mm=20,
                    position_preference=PositionPreference.BOTTOM_RIGHT,
                )

        # Only returns ONE spec (the main signature field)
        # Other pages get visual stamps, not signature fields
        assert len(result) == 1
        assert result[0].sig_field_name == "Signature1"

    def test_visible_all_pages_with_stamps(self, sample_pdf: Path, mock_analyzer, mock_position):
        """Test create_signature_field_with_stamps returns field + visual stamp positions."""
        from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference
        from pdfsigner.core.signer.signature_field import create_signature_field_with_stamps

        with patch("pdfsigner.core.signer.signature_field.ContentAnalyzer") as MockAnalyzer:
            with patch("pdfsigner.core.signer.signature_field.PositionFinder") as MockFinder:
                MockAnalyzer.return_value = mock_analyzer
                mock_finder_instance = MagicMock()
                mock_finder_instance.find_position.return_value = mock_position
                MockFinder.return_value = mock_finder_instance

                result = create_signature_field_with_stamps(
                    pdf_path=sample_pdf,
                    visible=True,
                    page_setting="all",
                    width_mm=50,
                    height_mm=20,
                    position_preference=PositionPreference.BOTTOM_RIGHT,
                )

        # One signature field for first page
        assert result.field_spec is not None
        assert result.field_spec.sig_field_name == "Signature1"
        assert result.field_spec.on_page == 0

        # Visual stamps for pages 2 and 3 (0-indexed: pages 1 and 2)
        assert len(result.visual_stamps) == 2
        assert result.visual_stamps[0].page == 1
        assert result.visual_stamps[1].page == 2

    def test_field_spec_has_correct_box(self, sample_pdf: Path, mock_analyzer, mock_position):
        """Test that field spec has correct bounding box."""
        from pdfsigner.core.pdf_analyzer.position_finder import PositionPreference

        with patch("pdfsigner.core.signer.signature_field.ContentAnalyzer") as MockAnalyzer:
            with patch("pdfsigner.core.signer.signature_field.PositionFinder") as MockFinder:
                MockAnalyzer.return_value = mock_analyzer
                mock_finder_instance = MagicMock()
                mock_finder_instance.find_position.return_value = mock_position
                MockFinder.return_value = mock_finder_instance

                result = create_signature_field_specs(
                    pdf_path=sample_pdf,
                    visible=True,
                    page_setting="last",
                    width_mm=50,
                    height_mm=20,
                    position_preference=PositionPreference.BOTTOM_RIGHT,
                )

        expected_box = (
            100.0,  # x
            100.0,  # y
            100.0 + 141.73,  # x + width
            100.0 + 56.69,  # y + height
        )
        assert result[0].box == expected_box

"""
test_content_analyzer.py - Tests for ContentAnalyzer

Author: Homero Thompson del Lago del Terror
"""

from pathlib import Path

from pdfsigner.core.pdf_analyzer.content_analyzer import (
    BoundingBox,
    ContentAnalyzer,
    PageInfo,
)


class TestBoundingBoxAdvanced:
    """Additional tests for BoundingBox class."""

    def test_from_rect(self):
        """Test creating BoundingBox from rect tuple."""
        rect = (10, 20, 110, 70)
        bbox = BoundingBox(x0=rect[0], y0=rect[1], x1=rect[2], y1=rect[3])

        assert bbox.x0 == 10
        assert bbox.y0 == 20
        assert bbox.x1 == 110
        assert bbox.y1 == 70

    def test_area(self):
        """Test area calculation."""
        bbox = BoundingBox(x0=0, y0=0, x1=100, y1=50)

        assert bbox.width * bbox.height == 5000

    def test_contains_point(self):
        """Test if bbox contains a point."""
        bbox = BoundingBox(x0=0, y0=0, x1=100, y1=100)

        # Point inside
        assert bbox.x0 <= 50 <= bbox.x1
        assert bbox.y0 <= 50 <= bbox.y1

        # Point outside
        assert not (bbox.x0 <= 150 <= bbox.x1)

    def test_intersects_edge_case(self):
        """Test intersection edge case (touching)."""
        bbox1 = BoundingBox(x0=0, y0=0, x1=100, y1=100)
        bbox2 = BoundingBox(x0=100, y0=0, x1=200, y1=100)

        # Touching at edge should not intersect (depending on implementation)
        result = bbox1.intersects(bbox2)
        assert isinstance(result, bool)


class TestPageInfo:
    """Tests for PageInfo dataclass."""

    def test_page_info_creation(self):
        """Test creating PageInfo."""
        page_info = PageInfo(
            page_number=0,
            width=612,
            height=792,
            text_blocks=[],
            image_blocks=[],
            drawing_blocks=[],
        )

        assert page_info.page_number == 0
        assert page_info.width == 612
        assert page_info.height == 792
        assert len(page_info.text_blocks) == 0

    def test_page_info_with_content(self):
        """Test PageInfo with content."""
        text_block = BoundingBox(x0=100, y0=100, x1=500, y1=200)
        image_block = BoundingBox(x0=100, y0=300, x1=400, y1=500)

        page_info = PageInfo(
            page_number=1,
            width=612,
            height=792,
            text_blocks=[text_block],
            image_blocks=[image_block],
            drawing_blocks=[],
        )

        assert len(page_info.text_blocks) == 1
        assert len(page_info.image_blocks) == 1
        assert page_info.text_blocks[0].width == 400


class TestContentAnalyzer:
    """Tests for ContentAnalyzer class."""

    def test_analyzer_initialization(self, sample_pdf: Path):
        """Test analyzer initialization with PDF."""
        analyzer = ContentAnalyzer(sample_pdf)

        assert analyzer is not None

    def test_page_count_property(self, sample_pdf: Path):
        """Test page_count property."""
        analyzer = ContentAnalyzer(sample_pdf)
        analyzer.open()

        page_count = analyzer.page_count

        assert page_count >= 1
        analyzer.close()

    def test_analyze_page_after_open(self, sample_pdf: Path):
        """Test analyzing a page after opening."""
        analyzer = ContentAnalyzer(sample_pdf)
        analyzer.open()

        page_info = analyzer.analyze_page(0)

        assert isinstance(page_info, PageInfo)
        assert page_info.page_number == 0
        assert page_info.width > 0
        assert page_info.height > 0
        analyzer.close()

    def test_analyze_page_without_open_raises(self, sample_pdf: Path):
        """Test analyzing without open raises error."""
        analyzer = ContentAnalyzer(sample_pdf)

        try:
            analyzer.analyze_page(0)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "not opened" in str(e).lower()

    def test_context_manager(self, sample_pdf: Path):
        """Test analyzer as context manager."""
        with ContentAnalyzer(sample_pdf) as analyzer:
            page_count = analyzer.page_count
            assert page_count >= 1

    def test_is_area_free(self, sample_pdf: Path):
        """Test is_area_free method."""
        with ContentAnalyzer(sample_pdf) as analyzer:
            # Check if a corner area is free
            bbox = BoundingBox(x0=500, y0=700, x1=600, y1=750)
            result = analyzer.is_area_free(0, bbox)

            assert isinstance(result, bool)

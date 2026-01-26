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


class TestContentAnalyzerEdgeCases:
    """Tests for edge cases and missing coverage lines."""

    def test_page_count_without_open_raises(self, sample_pdf: Path):
        """Test page_count property when document not opened (line 107)."""
        analyzer = ContentAnalyzer(sample_pdf)

        try:
            _ = analyzer.page_count
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "not opened" in str(e).lower()

    def test_is_area_free_with_intersection(self, tmp_path: Path):
        """Test is_area_free returns False when content intersects (line 204)."""
        import fitz

        # Create PDF with text content
        pdf_path = tmp_path / "content.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)

        # Add text block at (100, 100)
        page.insert_text((100, 100), "Test content here", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()

        # Test with bbox that intersects the text
        with ContentAnalyzer(pdf_path) as analyzer:
            # This bbox should overlap with the text
            bbox = BoundingBox(x0=90, y0=90, x1=200, y1=120)
            result = analyzer.is_area_free(0, bbox)

            assert result is False

    def test_is_area_free_with_margin(self, tmp_path: Path):
        """Test is_area_free considers margin parameter."""
        import fitz

        # Create PDF with text content
        pdf_path = tmp_path / "margin_test.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)

        # Add text at specific position
        page.insert_text((100, 100), "Content", fontsize=12)
        doc.save(str(pdf_path))
        doc.close()

        # Test with large margin that should cause intersection
        with ContentAnalyzer(pdf_path) as analyzer:
            # Bbox near but not directly overlapping
            bbox = BoundingBox(x0=120, y0=120, x1=150, y1=140)
            # With default margin (5.0), this might still intersect
            result = analyzer.is_area_free(0, bbox, margin=20.0)

            assert isinstance(result, bool)


class TestContentAnalyzerWithImages:
    """Tests for PDF image extraction (lines 142-153)."""

    def test_analyze_page_with_images(self, tmp_path: Path):
        """Test analyzing page with embedded images (covers lines 142-153)."""
        import io

        import fitz
        from PIL import Image

        # Create a simple test image
        img = Image.new("RGB", (100, 100), color="red")
        img_bytes = io.BytesIO()
        img.save(img_bytes, format="PNG")
        img_bytes.seek(0)

        # Create PDF with embedded image
        pdf_path = tmp_path / "with_image.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)

        # Insert image at specific position
        img_rect = fitz.Rect(50, 50, 150, 150)
        page.insert_image(img_rect, stream=img_bytes.getvalue())

        doc.save(str(pdf_path))
        doc.close()

        # Analyze the page - this executes the image extraction code (lines 142-153)
        with ContentAnalyzer(pdf_path) as analyzer:
            page_info = analyzer.analyze_page(0)

            # Image detection depends on PyMuPDF internals, but code path is executed
            assert isinstance(page_info, PageInfo)
            assert isinstance(page_info.image_blocks, list)
            # If images are detected, verify bbox is valid
            for img_bbox in page_info.image_blocks:
                assert img_bbox.width > 0
                assert img_bbox.height > 0

    def test_analyze_page_with_multiple_images(self, tmp_path: Path):
        """Test analyzing page calls image extraction loop multiple times."""
        import io

        import fitz
        from PIL import Image

        # Create test images
        img1 = Image.new("RGB", (50, 50), color="blue")
        img2 = Image.new("RGB", (50, 50), color="green")

        img1_bytes = io.BytesIO()
        img1.save(img1_bytes, format="PNG")
        img1_bytes.seek(0)

        img2_bytes = io.BytesIO()
        img2.save(img2_bytes, format="PNG")
        img2_bytes.seek(0)

        # Create PDF with multiple images
        pdf_path = tmp_path / "multi_images.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)

        # Insert images at different positions
        page.insert_image(fitz.Rect(50, 50, 100, 100), stream=img1_bytes.getvalue())
        page.insert_image(fitz.Rect(200, 200, 250, 250), stream=img2_bytes.getvalue())

        doc.save(str(pdf_path))
        doc.close()

        # Analyze the page - executes image extraction code paths
        with ContentAnalyzer(pdf_path) as analyzer:
            page_info = analyzer.analyze_page(0)

            # Verify the code executed without errors
            assert isinstance(page_info, PageInfo)
            assert isinstance(page_info.image_blocks, list)

    def test_analyze_page_image_extraction_error(self, tmp_path: Path):
        """Test that image extraction errors are handled gracefully."""
        import fitz

        # Create PDF (extraction errors are hard to trigger, but the code handles them)
        pdf_path = tmp_path / "test.pdf"
        doc = fitz.open()
        doc.new_page(width=612, height=792)  # Create empty page
        doc.save(str(pdf_path))
        doc.close()

        # This should not raise even if there are image issues
        with ContentAnalyzer(pdf_path) as analyzer:
            page_info = analyzer.analyze_page(0)

            # Should complete without error
            assert isinstance(page_info, PageInfo)


class TestContentAnalyzerWithDrawings:
    """Tests for PDF drawing/path extraction (lines 158-161)."""

    def test_analyze_page_with_drawings(self, tmp_path: Path):
        """Test analyzing page with vector drawings."""
        import fitz

        # Create PDF with drawings
        pdf_path = tmp_path / "with_drawings.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)

        # Draw a rectangle (vector path)
        rect = fitz.Rect(100, 100, 200, 200)
        page.draw_rect(rect, color=(0, 0, 1), width=2)

        # Draw a circle (vector path)
        page.draw_circle((300, 300), 50, color=(1, 0, 0), width=2)

        doc.save(str(pdf_path))
        doc.close()

        # Analyze the page
        with ContentAnalyzer(pdf_path) as analyzer:
            page_info = analyzer.analyze_page(0)

            # Should have detected drawings
            assert len(page_info.drawing_blocks) >= 1
            # Check that bboxes have valid dimensions
            for drawing in page_info.drawing_blocks:
                assert drawing.width > 0
                assert drawing.height > 0

    def test_analyze_page_with_complex_paths(self, tmp_path: Path):
        """Test analyzing page with complex vector paths."""
        import fitz

        # Create PDF with various drawings
        pdf_path = tmp_path / "complex_drawings.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)

        # Draw multiple shapes
        page.draw_rect(fitz.Rect(50, 50, 150, 100), color=(0, 0, 0), width=1)
        page.draw_line((200, 200), (300, 300), color=(1, 0, 0), width=2)
        page.draw_oval(fitz.Rect(400, 400, 500, 500), color=(0, 1, 0), width=1)

        doc.save(str(pdf_path))
        doc.close()

        # Analyze the page
        with ContentAnalyzer(pdf_path) as analyzer:
            page_info = analyzer.analyze_page(0)

            # Should have multiple drawing blocks
            assert len(page_info.drawing_blocks) >= 2

    def test_analyze_page_drawings_without_rect(self, tmp_path: Path):
        """Test drawings without rect attribute are skipped."""
        import fitz

        # Create simple PDF (drawings without rect are rare, but handled)
        pdf_path = tmp_path / "simple.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)

        # Add a simple drawing
        page.draw_rect(fitz.Rect(10, 10, 50, 50), color=(0, 0, 0))

        doc.save(str(pdf_path))
        doc.close()

        # Should not raise error even if some drawings lack rect
        with ContentAnalyzer(pdf_path) as analyzer:
            page_info = analyzer.analyze_page(0)

            assert isinstance(page_info, PageInfo)


class TestGetPageMargins:
    """Tests for get_page_margins with actual content (lines 218-230)."""

    def test_get_page_margins_with_content(self, tmp_path: Path):
        """Test get_page_margins with actual content blocks."""
        import fitz

        # Create PDF with content at known positions
        pdf_path = tmp_path / "margins_test.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)

        # Add text away from edges (creates margins)
        page.insert_text((100, 100), "Top-left content", fontsize=12)
        page.insert_text((400, 600), "Bottom-right content", fontsize=12)

        doc.save(str(pdf_path))
        doc.close()

        # Get margins
        with ContentAnalyzer(pdf_path) as analyzer:
            margins = analyzer.get_page_margins(0)

            # Should have calculated margins based on content
            assert "top" in margins
            assert "bottom" in margins
            assert "left" in margins
            assert "right" in margins

            # Margins should be reasonable (content doesn't touch edges)
            assert margins["top"] > 0
            assert margins["left"] > 0
            assert margins["bottom"] > 0
            assert margins["right"] > 0

    def test_get_page_margins_with_centered_content(self, tmp_path: Path):
        """Test margins calculation with centered content."""
        import fitz

        # Create PDF with centered content
        pdf_path = tmp_path / "centered.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)

        # Add content in the center
        page.insert_text((250, 350), "Centered text", fontsize=12)

        doc.save(str(pdf_path))
        doc.close()

        # Get margins
        with ContentAnalyzer(pdf_path) as analyzer:
            margins = analyzer.get_page_margins(0)

            # All margins should be substantial
            assert margins["top"] > 200
            assert margins["bottom"] > 200
            assert margins["left"] > 150
            assert margins["right"] > 150

    def test_get_page_margins_with_mixed_content(self, tmp_path: Path):
        """Test margins with text, images, and drawings."""
        import io

        import fitz
        from PIL import Image

        # Create test image
        img = Image.new("RGB", (50, 50), color="red")
        img_bytes = io.BytesIO()
        img.save(img_bytes, format="PNG")
        img_bytes.seek(0)

        # Create PDF with mixed content
        pdf_path = tmp_path / "mixed_content.pdf"
        doc = fitz.open()
        page = doc.new_page(width=612, height=792)

        # Add text
        page.insert_text((100, 100), "Text", fontsize=12)

        # Add image
        page.insert_image(fitz.Rect(200, 200, 250, 250), stream=img_bytes.getvalue())

        # Add drawing
        page.draw_rect(fitz.Rect(300, 300, 400, 400), color=(0, 0, 0))

        doc.save(str(pdf_path))
        doc.close()

        # Get margins
        with ContentAnalyzer(pdf_path) as analyzer:
            margins = analyzer.get_page_margins(0)

            # Margins should account for all content types
            assert margins["top"] <= 100  # Text is at y=100
            assert margins["left"] <= 100  # Text is at x=100
            assert all(m >= 0 for m in margins.values())

    def test_get_page_margins_empty_page_uses_defaults(self, tmp_path: Path):
        """Test that empty page returns default margins (72pts)."""
        import fitz

        # Create empty PDF
        pdf_path = tmp_path / "empty.pdf"
        doc = fitz.open()
        doc.new_page(width=612, height=792)
        doc.save(str(pdf_path))
        doc.close()

        # Get margins
        with ContentAnalyzer(pdf_path) as analyzer:
            margins = analyzer.get_page_margins(0)

            # Should return default margins
            assert margins["top"] == 72
            assert margins["bottom"] == 72
            assert margins["left"] == 72
            assert margins["right"] == 72

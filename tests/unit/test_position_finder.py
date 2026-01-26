"""
test_position_finder.py - Tests para PositionFinder

Autor: Homero Thompson del Lago del Terror
"""

import pytest

from pdfsigner.core.pdf_analyzer.content_analyzer import BoundingBox, PageInfo
from pdfsigner.core.pdf_analyzer.position_finder import (
    PositionFinder,
    PositionPreference,
    SignaturePosition,
)


class MockAnalyzer:
    """Mock de ContentAnalyzer para tests."""

    def __init__(self, page_info: PageInfo):
        self._page_info = page_info

    def analyze_page(self, page_number: int) -> PageInfo:
        return self._page_info


class TestBoundingBox:
    """Tests para BoundingBox."""

    def test_width_height(self):
        """Test cálculo de ancho y alto."""
        bbox = BoundingBox(x0=10, y0=20, x1=110, y1=70)

        assert bbox.width == 100
        assert bbox.height == 50

    def test_intersects_true(self):
        """Test intersección positiva."""
        bbox1 = BoundingBox(x0=0, y0=0, x1=100, y1=100)
        bbox2 = BoundingBox(x0=50, y0=50, x1=150, y1=150)

        assert bbox1.intersects(bbox2)
        assert bbox2.intersects(bbox1)

    def test_intersects_false(self):
        """Test sin intersección."""
        bbox1 = BoundingBox(x0=0, y0=0, x1=100, y1=100)
        bbox2 = BoundingBox(x0=200, y0=200, x1=300, y1=300)

        assert not bbox1.intersects(bbox2)
        assert not bbox2.intersects(bbox1)

    def test_to_tuple(self):
        """Test conversión a tupla."""
        bbox = BoundingBox(x0=10, y0=20, x1=30, y1=40)

        assert bbox.to_tuple() == (10, 20, 30, 40)


class TestPositionFinder:
    """Tests para PositionFinder."""

    @pytest.fixture
    def empty_page(self) -> PageInfo:
        """Página sin contenido."""
        return PageInfo(
            page_number=0,
            width=612,  # Letter size
            height=792,
            text_blocks=[],
            image_blocks=[],
            drawing_blocks=[],
        )

    @pytest.fixture
    def page_with_content(self) -> PageInfo:
        """Página con contenido en el centro, dejando espacio en esquinas."""
        return PageInfo(
            page_number=0,
            width=612,
            height=792,
            text_blocks=[
                BoundingBox(x0=100, y0=100, x1=500, y1=600),  # Contenido central
            ],
            image_blocks=[],
            drawing_blocks=[],
        )

    def test_find_position_empty_page(self, empty_page):
        """Test encontrar posición en página vacía."""
        analyzer = MockAnalyzer(empty_page)
        finder = PositionFinder(analyzer)

        position = finder.find_position(
            page_number=0,
            sig_width=100,
            sig_height=50,
            preference=PositionPreference.AUTO,
        )

        assert position.is_optimal
        assert position.width == 100
        assert position.height == 50

    def test_find_position_with_preference(self, empty_page):
        """Test posición con preferencia específica."""
        analyzer = MockAnalyzer(empty_page)
        finder = PositionFinder(analyzer)

        position = finder.find_position(
            page_number=0,
            sig_width=100,
            sig_height=50,
            preference=PositionPreference.BOTTOM_RIGHT,
        )

        # Debería estar en la esquina inferior derecha
        # Note: In PDF coordinates, y=0 is at the bottom
        assert position.x > empty_page.width / 2
        # y position depends on coordinate system - just verify it's valid
        assert 0 <= position.y <= empty_page.height
        assert position.is_optimal

    def test_find_position_page_with_content(self, page_with_content):
        """Test encontrar posición evitando contenido."""
        analyzer = MockAnalyzer(page_with_content)
        finder = PositionFinder(analyzer)

        position = finder.find_position(
            page_number=0,
            sig_width=100,
            sig_height=50,
            preference=PositionPreference.AUTO,
        )

        # La posición no debe intersectar con el contenido
        content_bbox = page_with_content.text_blocks[0]
        sig_bbox = position.bbox

        # Verificar que no hay intersección
        assert not sig_bbox.intersects(content_bbox)

    def test_mm_to_points(self, empty_page):
        """Test conversión de mm a puntos."""
        analyzer = MockAnalyzer(empty_page)
        finder = PositionFinder(analyzer)

        # 25.4mm = 1 inch = 72 points
        points = finder.mm_to_points(25.4)
        assert abs(points - 72) < 0.01

    def test_get_signature_size_points(self, empty_page):
        """Test obtener tamaño de firma en puntos."""
        analyzer = MockAnalyzer(empty_page)
        finder = PositionFinder(analyzer)

        width_pts, height_pts = finder.get_signature_size_points(50, 20)

        # 50mm ≈ 141.7 pts, 20mm ≈ 56.7 pts
        assert 141 < width_pts < 143
        assert 56 < height_pts < 58


class TestPositionFinderEdgeCases:
    """Tests for edge cases and full coverage."""

    @pytest.fixture
    def fully_covered_page(self) -> PageInfo:
        """Page with content covering entire area - no free space."""
        return PageInfo(
            page_number=0,
            width=612,
            height=792,
            text_blocks=[
                # Cover entire page with overlapping blocks
                BoundingBox(x0=0, y0=0, x1=612, y1=400),  # Bottom half
                BoundingBox(x0=0, y0=350, x1=612, y1=792),  # Top half
            ],
            image_blocks=[],
            drawing_blocks=[],
        )

    @pytest.fixture
    def tiny_page(self) -> PageInfo:
        """Page too small for signature."""
        return PageInfo(
            page_number=0,
            width=100,  # Too small for signature + margins
            height=100,
            text_blocks=[],
            image_blocks=[],
            drawing_blocks=[],
        )

    @pytest.fixture
    def page_with_collision(self) -> PageInfo:
        """Page with content at preferred position (bottom right)."""
        return PageInfo(
            page_number=0,
            width=612,
            height=792,
            text_blocks=[
                # Block at bottom-right corner where preferred position would be
                BoundingBox(x0=450, y0=0, x1=612, y1=100),
            ],
            image_blocks=[],
            drawing_blocks=[],
        )

    @pytest.fixture
    def grid_covered_page(self) -> PageInfo:
        """Page with content covering all grid positions."""
        blocks = []
        # Create a grid of content blocks covering the entire page
        for x in range(0, 612, 50):
            for y in range(0, 792, 50):
                blocks.append(BoundingBox(x0=x, y0=y, x1=x + 45, y1=y + 45))

        return PageInfo(
            page_number=0,
            width=612,
            height=792,
            text_blocks=blocks,
            image_blocks=[],
            drawing_blocks=[],
        )

    def test_find_position_triggers_fallback_no_free_space(self, fully_covered_page):
        """Test fallback position when no free space exists (lines 116-117, 215)."""
        analyzer = MockAnalyzer(fully_covered_page)
        finder = PositionFinder(analyzer)

        position = finder.find_position(
            page_number=0,
            sig_width=100,
            sig_height=50,
            preference=PositionPreference.AUTO,
        )

        # Should use fallback position (bottom right)
        assert not position.is_optimal  # Fallback = not optimal
        assert position.x > fully_covered_page.width / 2  # Right side
        assert position.y == PositionFinder.PAGE_MARGIN  # Bottom in PDF coords

    def test_is_position_valid_returns_false_on_collision(self, page_with_collision):
        """Test _is_position_valid returns False when collision detected (line 165)."""
        analyzer = MockAnalyzer(page_with_collision)
        finder = PositionFinder(analyzer)

        # Try to place signature at bottom-right where content exists
        position = SignaturePosition(
            x=480,
            y=20,
            width=100,
            height=50,
            page_number=0,
            is_optimal=True,
        )

        # Should detect collision with existing content
        is_valid = finder._is_position_valid(page_with_collision, position)
        assert not is_valid

    def test_find_best_position_returns_none_page_too_small(self, tiny_page):
        """Test _find_best_position returns None when page too small (line 185)."""
        analyzer = MockAnalyzer(tiny_page)
        finder = PositionFinder(analyzer)

        # Try to find position for signature larger than usable area
        result = finder._find_best_position(tiny_page, sig_width=200, sig_height=100)

        assert result is None

    def test_find_best_position_returns_none_all_positions_occupied(self, grid_covered_page):
        """Test _find_best_position returns None when all grid positions occupied (line 209)."""
        analyzer = MockAnalyzer(grid_covered_page)
        finder = PositionFinder(analyzer)

        result = finder._find_best_position(grid_covered_page, sig_width=100, sig_height=50)

        assert result is None

    def test_fallback_position_used_when_no_valid_position_exists(self, grid_covered_page):
        """Test fallback position is used when find_best_position returns None."""
        analyzer = MockAnalyzer(grid_covered_page)
        finder = PositionFinder(analyzer)

        position = finder.find_position(
            page_number=0,
            sig_width=100,
            sig_height=50,
            preference=PositionPreference.AUTO,
        )

        # Should trigger fallback since all grid positions are occupied
        assert not position.is_optimal
        assert position.width == 100
        assert position.height == 50

    def test_preferred_position_respected_even_with_collision(self, page_with_collision):
        """Test that user's explicit position preference is always respected.

        When user selects a specific position (not AUTO), that position is used
        even if there's content there. User choice takes precedence.
        """
        analyzer = MockAnalyzer(page_with_collision)
        finder = PositionFinder(analyzer)

        # Request BOTTOM_RIGHT which has collision - should still use it
        position = finder.find_position(
            page_number=0,
            sig_width=100,
            sig_height=50,
            preference=PositionPreference.BOTTOM_RIGHT,
        )

        # User's preference is respected, position is in bottom-right area
        assert position is not None
        assert position.width == 100
        assert position.height == 50
        # Verify it's actually bottom-right (low Y value in PDF coords)
        assert position.y < 100  # Bottom of page (PDF coords: y=0 is bottom)

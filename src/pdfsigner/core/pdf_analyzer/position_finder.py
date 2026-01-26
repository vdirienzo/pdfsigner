"""
position_finder.py - Optimal signature position finder

Author: Homero Thompson del Lago del Terror

Implements free space search algorithm in PDF pages
to place visible signature without obstructing content.
"""

from dataclasses import dataclass
from enum import Enum

from loguru import logger

from pdfsigner.core.pdf_analyzer.content_analyzer import (
    BoundingBox,
    ContentAnalyzer,
    PageInfo,
)


class PositionPreference(Enum):
    """Position preference for signature."""

    BOTTOM_RIGHT = "bottom_right"
    BOTTOM_LEFT = "bottom_left"
    BOTTOM_CENTER = "bottom_center"
    TOP_RIGHT = "top_right"
    TOP_LEFT = "top_left"
    AUTO = "auto"  # Search for best position automatically


@dataclass
class SignaturePosition:
    """Calculated position for signature."""

    x: float
    y: float
    width: float
    height: float
    page_number: int
    is_optimal: bool  # True if found free space, False if fallback

    @property
    def bbox(self) -> BoundingBox:
        """Return as BoundingBox."""
        return BoundingBox(
            x0=self.x,
            y0=self.y,
            x1=self.x + self.width,
            y1=self.y + self.height,
        )


class PositionFinder:
    """
    Optimal position finder for visible signature.

    Analyzes page content and finds the best place
    to place signature without obstructing text or images.
    """

    # Minimum margin from page edges (in points)
    PAGE_MARGIN = 36  # 0.5 inch

    # Margin between signature and existing content
    CONTENT_MARGIN = 10

    # Grid size for search (cells per dimension)
    GRID_SIZE = 20

    def __init__(self, analyzer: ContentAnalyzer):
        """
        Initialize finder.

        Args:
            analyzer: PDF content analyzer
        """
        self.analyzer = analyzer

    def find_position(
        self,
        page_number: int,
        sig_width: float,
        sig_height: float,
        preference: PositionPreference = PositionPreference.AUTO,
    ) -> SignaturePosition:
        """
        Find best position for signature.

        Args:
            page_number: Page number (0-indexed)
            sig_width: Signature width in points
            sig_height: Signature height in points
            preference: Position preference

        Returns:
            Calculated position for signature
        """
        page_info = self.analyzer.analyze_page(page_number)

        # If user selected a specific position (not AUTO), respect it always
        # User's explicit choice takes precedence over content avoidance
        if preference != PositionPreference.AUTO:
            pos = self._get_preferred_position(page_info, sig_width, sig_height, preference)
            if self._is_position_valid(page_info, pos):
                logger.debug(f"Using preferred position: {preference.value}")
            else:
                logger.debug(f"Using preferred position {preference.value} (may overlap content)")
            return pos

        # AUTO mode: search for best position avoiding content
        best_pos = self._find_best_position(page_info, sig_width, sig_height)
        if best_pos:
            logger.debug(f"Optimal position found: ({best_pos.x:.1f}, {best_pos.y:.1f})")
            return best_pos

        # Fallback for AUTO mode: bottom right corner
        logger.warning("No free space found, using default position (bottom right)")
        return self._get_fallback_position(page_info, sig_width, sig_height)

    def _get_preferred_position(
        self,
        page_info: PageInfo,
        sig_width: float,
        sig_height: float,
        preference: PositionPreference,
    ) -> SignaturePosition:
        """Calculate position according to preference.

        PDF coordinate system: origin (0,0) at BOTTOM-LEFT, Y increases upward.
        So low Y = bottom of page, high Y = top of page.
        """
        w, h = page_info.width, page_info.height
        m = self.PAGE_MARGIN

        # Y coordinates: m = bottom, h - m - sig_height = top
        positions = {
            PositionPreference.BOTTOM_RIGHT: (w - m - sig_width, m),
            PositionPreference.BOTTOM_LEFT: (m, m),
            PositionPreference.BOTTOM_CENTER: ((w - sig_width) / 2, m),
            PositionPreference.TOP_RIGHT: (w - m - sig_width, h - m - sig_height),
            PositionPreference.TOP_LEFT: (m, h - m - sig_height),
        }

        x, y = positions.get(preference, positions[PositionPreference.BOTTOM_RIGHT])

        return SignaturePosition(
            x=x,
            y=y,
            width=sig_width,
            height=sig_height,
            page_number=page_info.page_number,
            is_optimal=True,
        )

    def _is_position_valid(self, page_info: PageInfo, pos: SignaturePosition) -> bool:
        """Check if a position doesn't collide with content."""
        sig_bbox = BoundingBox(
            x0=pos.x - self.CONTENT_MARGIN,
            y0=pos.y - self.CONTENT_MARGIN,
            x1=pos.x + pos.width + self.CONTENT_MARGIN,
            y1=pos.y + pos.height + self.CONTENT_MARGIN,
        )

        for content_bbox in page_info.all_content_blocks:
            if sig_bbox.intersects(content_bbox):
                return False

        return True

    def _find_best_position(
        self, page_info: PageInfo, sig_width: float, sig_height: float
    ) -> SignaturePosition | None:
        """
        Search for best position using grid search.

        Prioritizes positions at bottom of page.
        """
        w, h = page_info.width, page_info.height
        m = self.PAGE_MARGIN

        # Usable area
        usable_width = w - 2 * m - sig_width
        usable_height = h - 2 * m - sig_height

        if usable_width <= 0 or usable_height <= 0:
            return None

        # Create search grid
        cell_width = usable_width / self.GRID_SIZE
        cell_height = usable_height / self.GRID_SIZE

        # Search from bottom to top, right to left
        for row in range(self.GRID_SIZE - 1, -1, -1):
            for col in range(self.GRID_SIZE - 1, -1, -1):
                x = m + col * cell_width
                y = m + row * cell_height

                pos = SignaturePosition(
                    x=x,
                    y=y,
                    width=sig_width,
                    height=sig_height,
                    page_number=page_info.page_number,
                    is_optimal=True,
                )

                if self._is_position_valid(page_info, pos):
                    return pos

        return None

    def _get_fallback_position(
        self, page_info: PageInfo, sig_width: float, sig_height: float
    ) -> SignaturePosition:
        """Fallback position when there's no free space (bottom right)."""
        return SignaturePosition(
            x=page_info.width - self.PAGE_MARGIN - sig_width,
            y=self.PAGE_MARGIN,  # Bottom of page in PDF coordinates
            width=sig_width,
            height=sig_height,
            page_number=page_info.page_number,
            is_optimal=False,
        )

    def mm_to_points(self, mm: float) -> float:
        """Convert millimeters to PDF points."""
        return mm * 72 / 25.4

    def get_signature_size_points(self, width_mm: float, height_mm: float) -> tuple[float, float]:
        """
        Convert signature dimensions from mm to points.

        Args:
            width_mm: Width in millimeters
            height_mm: Height in millimeters

        Returns:
            Tuple (width_pts, height_pts)
        """
        return (self.mm_to_points(width_mm), self.mm_to_points(height_mm))

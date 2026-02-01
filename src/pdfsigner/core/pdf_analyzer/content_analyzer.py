"""
content_analyzer.py - PDF content analyzer

Author: Homero Thompson del Lago del Terror

Uses PyMuPDF to analyze PDF page content
and create occupancy maps for signature positioning.
"""

from dataclasses import dataclass
from pathlib import Path

import fitz  # PyMuPDF
from loguru import logger


@dataclass
class BoundingBox:
    """Bounding box."""

    x0: float
    y0: float
    x1: float
    y1: float

    @property
    def width(self) -> float:
        """Rectangle width."""
        return self.x1 - self.x0

    @property
    def height(self) -> float:
        """Rectangle height."""
        return self.y1 - self.y0

    def intersects(self, other: "BoundingBox") -> bool:
        """Check if it intersects with another rectangle."""
        return not (
            self.x1 < other.x0 or self.x0 > other.x1 or self.y1 < other.y0 or self.y0 > other.y1
        )

    def to_tuple(self) -> tuple[float, float, float, float]:
        """Convert to tuple (x0, y0, x1, y1)."""
        return (self.x0, self.y0, self.x1, self.y1)


@dataclass
class PageInfo:
    """PDF page information."""

    page_number: int
    width: float
    height: float
    text_blocks: list[BoundingBox]
    image_blocks: list[BoundingBox]
    drawing_blocks: list[BoundingBox]

    @property
    def all_content_blocks(self) -> list[BoundingBox]:
        """All content blocks."""
        return self.text_blocks + self.image_blocks + self.drawing_blocks


class ContentAnalyzer:
    """
    PDF page content analyzer.

    Detects areas occupied by text, images and drawings
    to find free space for signature.
    """

    def __init__(self, pdf_path: Path | str):
        """
        Initialize analyzer.

        Args:
            pdf_path: Path to PDF file
        """
        self.pdf_path = Path(pdf_path)
        self._doc: fitz.Document | None = None

    def open(self) -> None:
        """Open PDF document."""
        self._doc = fitz.open(str(self.pdf_path))
        logger.debug(f"PDF opened: {self.pdf_path.name} ({len(self._doc)} pages)")

    def close(self) -> None:
        """Close PDF document."""
        if self._doc:
            self._doc.close()
            self._doc = None

    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False

    @property
    def page_count(self) -> int:
        """Number of PDF pages."""
        if self._doc is None:
            raise ValueError("Document not opened")
        return len(self._doc)

    def analyze_page(self, page_number: int) -> PageInfo:
        """
        Analyze page content.

        Args:
            page_number: Page number (0-indexed)

        Returns:
            Page information with occupied areas
        """
        if self._doc is None:
            raise ValueError("Document not opened")

        page = self._doc[page_number]
        rect = page.rect

        # Extract text blocks
        text_blocks = []
        text_dict = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)
        for block in text_dict.get("blocks", []):
            if block.get("type") == 0:  # Text
                bbox = BoundingBox(
                    x0=block["bbox"][0],
                    y0=block["bbox"][1],
                    x1=block["bbox"][2],
                    y1=block["bbox"][3],
                )
                text_blocks.append(bbox)

        # Extract images
        image_blocks = []
        for img in page.get_images():
            try:
                img_rect = page.get_image_bbox(img)
                if img_rect:
                    bbox = BoundingBox(
                        x0=img_rect.x0,
                        y0=img_rect.y0,
                        x1=img_rect.x1,
                        y1=img_rect.y1,
                    )
                    image_blocks.append(bbox)
            except Exception as e:
                logger.debug(f"Could not extract image bbox: {e}")
                continue

        # Extract drawings (paths)
        drawing_blocks = []
        for drawing in page.get_drawings():
            if drawing.get("rect"):
                r = drawing["rect"]
                bbox = BoundingBox(x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1)
                drawing_blocks.append(bbox)

        logger.debug(
            f"Page {page_number + 1}: "
            f"{len(text_blocks)} texts, "
            f"{len(image_blocks)} images, "
            f"{len(drawing_blocks)} drawings"
        )

        return PageInfo(
            page_number=page_number,
            width=rect.width,
            height=rect.height,
            text_blocks=text_blocks,
            image_blocks=image_blocks,
            drawing_blocks=drawing_blocks,
        )

    def is_area_free(self, page_number: int, bbox: BoundingBox, margin: float = 5.0) -> bool:
        """
        Check if an area is free of content.

        Args:
            page_number: Page number
            bbox: Rectangle to check
            margin: Additional margin around area

        Returns:
            True if area is free
        """
        page_info = self.analyze_page(page_number)

        # Expand bbox with margin
        check_bbox = BoundingBox(
            x0=bbox.x0 - margin,
            y0=bbox.y0 - margin,
            x1=bbox.x1 + margin,
            y1=bbox.y1 + margin,
        )

        # Check intersection with any content
        for content_bbox in page_info.all_content_blocks:
            if check_bbox.intersects(content_bbox):
                return False

        return True

    def get_page_margins(self, page_number: int) -> dict[str, float]:
        """
        Estimate page margins.

        Args:
            page_number: Page number

        Returns:
            Dict with estimated margins (top, bottom, left, right)
        """
        page_info = self.analyze_page(page_number)

        if not page_info.all_content_blocks:
            # No content, use default margins (72 pts = 1 inch)
            return {"top": 72, "bottom": 72, "left": 72, "right": 72}

        # Find content extremes
        min_x = min(b.x0 for b in page_info.all_content_blocks)
        max_x = max(b.x1 for b in page_info.all_content_blocks)
        min_y = min(b.y0 for b in page_info.all_content_blocks)
        max_y = max(b.y1 for b in page_info.all_content_blocks)

        return {
            "top": min_y,
            "bottom": page_info.height - max_y,
            "left": min_x,
            "right": page_info.width - max_x,
        }

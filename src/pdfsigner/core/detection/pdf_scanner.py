"""
PDF text extraction with coordinate tracking for PII detection.

Uses PyMuPDF (fitz) to extract text from PDFs while maintaining
positional information for each detected PII instance.
"""

from dataclasses import dataclass
from pathlib import Path

import fitz  # PyMuPDF

from pdfsigner.core.detection.pii_detector import get_pii_detector
from pdfsigner.core.detection.pii_types import PIIMatch


@dataclass
class TextBlock:
    """
    Represents a block of text extracted from PDF.

    Attributes:
        text: Extracted text content
        page: Page number (0-indexed)
        bbox: Bounding box coordinates (x1, y1, x2, y2)
        start_pos: Character position in full document text
        end_pos: End character position in full document text
    """

    text: str
    page: int
    bbox: tuple[float, float, float, float]
    start_pos: int
    end_pos: int


class PDFScanner:
    """
    PDF text extraction and PII scanning with coordinate tracking.

    Extracts text from PDF documents using PyMuPDF and tracks
    the position and bounding box of each detected PII instance.
    """

    def __init__(self):
        """Initialize PDF scanner."""
        self.detector = get_pii_detector()

    def scan_pdf(self, pdf_path: str | Path) -> list[PIIMatch]:
        """
        Scan PDF for PII/PHI with coordinate tracking.

        Args:
            pdf_path: Path to PDF file

        Returns:
            List of PIIMatch objects with page numbers and bounding boxes

        Raises:
            FileNotFoundError: If PDF file doesn't exist
            RuntimeError: If PDF cannot be opened or read
        """
        pdf_path = Path(pdf_path)

        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")

        try:
            # Extract text blocks with positions
            text_blocks = self.extract_text_with_positions(pdf_path)

            # Get full document text
            full_text = "".join(block.text for block in text_blocks)

            # Detect PII in full text
            pii_matches = self.detector.scan_text(full_text)

            # Map PII matches to text blocks to get page/bbox info
            pii_matches_with_positions = self._map_matches_to_blocks(pii_matches, text_blocks)

            return pii_matches_with_positions

        except Exception as e:
            raise RuntimeError(f"Failed to scan PDF: {e}") from e

    def extract_text_with_positions(self, pdf_path: str | Path) -> list[TextBlock]:
        """
        Extract text from PDF with position tracking.

        Args:
            pdf_path: Path to PDF file

        Returns:
            List of TextBlock objects with text and coordinates

        Raises:
            RuntimeError: If PDF cannot be opened or read
        """
        pdf_path = Path(pdf_path)
        text_blocks: list[TextBlock] = []
        char_position = 0

        try:
            doc = fitz.open(pdf_path)

            for page_num in range(len(doc)):
                page = doc[page_num]

                # Extract text with bounding boxes
                # Use "blocks" mode to get text blocks with coordinates
                blocks = page.get_text("blocks")

                for block in blocks:
                    # Block format: (x0, y0, x1, y1, "text", block_no, block_type)
                    x0, y0, x1, y1, text, *_ = block

                    # Skip empty blocks
                    if not text or not text.strip():
                        continue

                    bbox = (float(x0), float(y0), float(x1), float(y1))
                    start_pos = char_position
                    end_pos = char_position + len(text)

                    text_blocks.append(
                        TextBlock(
                            text=text,
                            page=page_num,
                            bbox=bbox,
                            start_pos=start_pos,
                            end_pos=end_pos,
                        )
                    )

                    char_position = end_pos

            doc.close()

            return text_blocks

        except Exception as e:
            raise RuntimeError(f"Failed to extract text from PDF: {e}") from e

    def _map_matches_to_blocks(
        self, matches: list[PIIMatch], text_blocks: list[TextBlock]
    ) -> list[PIIMatch]:
        """
        Map PII matches to text blocks to get page/bbox information.

        Args:
            matches: List of PIIMatch objects from text detection
            text_blocks: List of TextBlock objects from PDF extraction

        Returns:
            Updated list of PIIMatch objects with page and bbox set
        """
        updated_matches: list[PIIMatch] = []

        for match in matches:
            # Find which text block contains this match
            block = self._find_containing_block(match, text_blocks)

            if block:
                # Update match with page and bbox from containing block
                match.page = block.page
                match.bbox = block.bbox

            updated_matches.append(match)

        return updated_matches

    def _find_containing_block(
        self, match: PIIMatch, text_blocks: list[TextBlock]
    ) -> TextBlock | None:
        """
        Find the text block that contains a PII match.

        Args:
            match: PIIMatch object
            text_blocks: List of TextBlock objects

        Returns:
            TextBlock containing the match, or None if not found
        """
        for block in text_blocks:
            # Check if match is within this block's character range
            if block.start_pos <= match.start_pos < block.end_pos:
                return block

        return None

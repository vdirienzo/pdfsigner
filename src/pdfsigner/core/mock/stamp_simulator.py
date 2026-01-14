"""
stamp_simulator.py - Visual stamp simulation for dry-run mode

Author: Homero Thompson del Lago del Terror

Adds visual stamps to PDFs to simulate signature placement.
"""

import shutil
from datetime import datetime
from pathlib import Path

import fitz  # PyMuPDF
from loguru import logger


def parse_page_spec(page_spec: str | int, total_pages: int) -> list[int]:
    """
    Parses page specification into list of page numbers.

    Args:
        page_spec: Page specification ("last", "all", int, or "1,2,3")
        total_pages: Total number of pages in document

    Returns:
        List of 0-indexed page numbers
    """
    if isinstance(page_spec, int):
        return [min(page_spec, total_pages - 1)]

    if page_spec == "last":
        return [total_pages - 1]

    if page_spec == "first":
        return [0]

    if page_spec == "all":
        return list(range(total_pages))

    # Parse comma-separated list or ranges
    try:
        pages: list[int] = []
        for part in str(page_spec).replace(" ", "").split(","):
            if "-" in part:
                start, end = part.split("-", 1)
                pages.extend(range(int(start) - 1, int(end)))
            else:
                pages.append(int(part) - 1)
        return [p for p in pages if 0 <= p < total_pages]
    except ValueError:
        logger.warning(f"[DRY-RUN] Invalid page spec: {page_spec}, using last page")
        return [total_pages - 1]


def get_stamp_rect(
    page_width: float,
    page_height: float,
    position: str,
    stamp_width: float = 140,
    stamp_height: float = 50,
    margin: float = 10,
) -> fitz.Rect:
    """
    Calculates stamp rectangle based on position preference.

    PyMuPDF uses (0,0) at TOP-LEFT with Y increasing downward.
    So: low Y = top, high Y = bottom.

    Args:
        page_width: Page width in points
        page_height: Page height in points
        position: Position preference (bottom_right, top_left, etc.)
        stamp_width: Stamp width
        stamp_height: Stamp height
        margin: Margin from page edge

    Returns:
        fitz.Rect for stamp placement
    """
    positions = {
        "bottom_right": (
            page_width - margin - stamp_width,
            page_height - margin - stamp_height,
        ),
        "bottom_left": (margin, page_height - margin - stamp_height),
        "bottom_center": (
            (page_width - stamp_width) / 2,
            page_height - margin - stamp_height,
        ),
        "top_right": (page_width - margin - stamp_width, margin),
        "top_left": (margin, margin),
        "top_center": ((page_width - stamp_width) / 2, margin),
        "auto": (
            page_width - margin - stamp_width,
            page_height - margin - stamp_height,
        ),  # Default to bottom_right
    }

    x, y = positions.get(position, positions["bottom_right"])
    return fitz.Rect(x, y, x + stamp_width, y + stamp_height)


def add_stamp_to_pdf(
    input_path: Path,
    output_path: Path,
    page_spec: str | int = "last",
    visible: bool = True,
    position: str = "bottom_right",
) -> None:
    """
    Adds visual stamp to PDF in dry-run mode.

    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        page_spec: Page specification
        visible: Whether to add visible stamp
        position: Position preference (bottom_right, top_left, etc.)
    """
    if not visible:
        # Just copy if no visible signature
        shutil.copy2(input_path, output_path)
        logger.info("[DRY-RUN] Invisible signature - copied without stamp")
        return

    doc = fitz.open(input_path)
    stamp_text = f"SIGNATURE (SIMULATED)\n{datetime.now().strftime('%Y-%m-%d %H:%M')}"

    pages_to_stamp = parse_page_spec(page_spec, len(doc))

    for page_num in pages_to_stamp:
        if page_num < len(doc):
            page = doc[page_num]
            # Get stamp rectangle based on position preference
            rect = get_stamp_rect(page.rect.width, page.rect.height, position)
            # Draw blue border
            page.draw_rect(rect, color=(0, 0, 0.5), width=1)
            # Insert text
            page.insert_textbox(
                rect,
                stamp_text,
                fontsize=8,
                align=fitz.TEXT_ALIGN_CENTER,
                color=(0, 0, 0.5),
            )

    doc.save(output_path)
    doc.close()
    logger.info(f"[DRY-RUN] Added stamp at '{position}' to {len(pages_to_stamp)} page(s)")

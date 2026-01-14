"""
signature_field.py - Signature field creation logic

Author: Homero Thompson del Lago del Terror

Handles signature field positioning and creation for PDF signing.
"""

from pathlib import Path

from pyhanko.sign.fields import SigFieldSpec

from pdfsigner.core.pdf_analyzer.content_analyzer import ContentAnalyzer
from pdfsigner.core.pdf_analyzer.position_finder import (
    PositionFinder,
    PositionPreference,
)


def parse_page_range(page_str: str, total_pages: int) -> list[int]:
    """
    Parses a page range string into a list of page indices.

    Supports formats:
    - "1,3,4" -> pages 1, 3, 4
    - "1-3" -> pages 1, 2, 3
    - "1-3,5,7-9" -> pages 1, 2, 3, 5, 7, 8, 9

    Args:
        page_str: Page range string (1-based)
        total_pages: Total number of pages

    Returns:
        List of page indices (0-based), sorted and deduplicated
    """
    pages = set()

    for part in page_str.replace(" ", "").split(","):
        if not part:
            continue

        if "-" in part:
            # Range like "1-3"
            try:
                start, end = part.split("-", 1)
                start_num = int(start)
                end_num = int(end)
                for p in range(start_num, end_num + 1):
                    if 1 <= p <= total_pages:
                        pages.add(p - 1)  # Convert to 0-based
            except ValueError:
                continue
        else:
            # Single page like "3"
            try:
                p = int(part)
                if 1 <= p <= total_pages:
                    pages.add(p - 1)  # Convert to 0-based
            except ValueError:
                continue

    return sorted(pages)


def get_pages_to_sign(
    total_pages: int,
    page_setting: int | str,
) -> list[int]:
    """
    Determines which pages should have visible signature stamps.

    Args:
        total_pages: Total number of pages in the PDF
        page_setting: "last", "first", "all", page number, or range "1,3,4" / "1-3"

    Returns:
        List of page indices (0-based)
    """
    if page_setting == "all":
        return list(range(total_pages))
    elif page_setting == "last":
        return [total_pages - 1]
    elif page_setting == "first":
        return [0]
    elif isinstance(page_setting, int):
        return [min(page_setting, total_pages - 1)]
    elif isinstance(page_setting, str):
        # Try to parse as custom range "1,3,4" or "1-3"
        parsed = parse_page_range(page_setting, total_pages)
        if parsed:
            return parsed
        # Fallback to last page
        return [total_pages - 1]
    else:
        return [total_pages - 1]


def mm_to_points(mm: float) -> float:
    """Converts millimeters to PDF points."""
    return mm * 72 / 25.4


def create_signature_field_specs(
    pdf_path: Path,
    visible: bool,
    page_setting: int | str,
    width_mm: float,
    height_mm: float,
    position_preference: PositionPreference,
) -> list[SigFieldSpec]:
    """
    Creates visible signature field specifications.

    For "all" pages, creates a stamp on every page.
    The first field is the actual signature field,
    others are visual stamps referencing it.

    Args:
        pdf_path: Path to the PDF
        visible: Whether signature should be visible
        page_setting: Page specification ("last", "first", "all", number, or range)
        width_mm: Signature width in millimeters
        height_mm: Signature height in millimeters
        position_preference: Position preference strategy

    Returns:
        List of SigFieldSpec (empty if invisible signature)
    """
    if not visible:
        return []

    field_specs = []

    with ContentAnalyzer(pdf_path) as analyzer:
        total_pages = analyzer.page_count
        pages_to_sign = get_pages_to_sign(total_pages, page_setting)

        finder = PositionFinder(analyzer)
        sig_width = mm_to_points(width_mm)
        sig_height = mm_to_points(height_mm)

        for idx, page_num in enumerate(pages_to_sign):
            # Find optimal position for this page
            position = finder.find_position(
                page_num,
                sig_width,
                sig_height,
                position_preference,
            )

            box = (
                position.x,
                position.y,
                position.x + position.width,
                position.y + position.height,
            )

            # First field is the main signature, others are visual copies
            field_name = "Signature1" if idx == 0 else f"SignatureStamp{idx}"

            field_specs.append(
                SigFieldSpec(
                    sig_field_name=field_name,
                    on_page=page_num,
                    box=box,
                )
            )

    return field_specs

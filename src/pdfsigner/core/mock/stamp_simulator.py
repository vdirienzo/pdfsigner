"""
stamp_simulator.py - Visual stamp simulation for dry-run mode

Author: Homero Thompson del Lago del Terror

Adds visual stamps to PDFs to simulate signature placement.
Now includes real QR code generation for demo purposes.
"""

import io
import shutil
from datetime import UTC, datetime
from pathlib import Path

import fitz  # PyMuPDF
from loguru import logger
from PIL import Image, ImageDraw, ImageFont

from pdfsigner.core.stamp.qr_generator import QRData, generate_qr_image

# Demo signer data for realistic simulation
DEMO_SIGNER_NAME = "John Smith (DEMO)"
DEMO_ORGANIZATION = "Acme Corp (DEMO)"
DEMO_SERIAL = "1234567890ABCDEF"

# Stamp dimensions in pixels (150 DPI for high quality)
# Physical size: ~3" x 1.1" at 150 DPI
STAMP_WIDTH_PX = 460
STAMP_HEIGHT_PX = 170
QR_SIZE_PX = 140
PADDING_PX = 10


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


def _get_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Try to load a system font, fallback to default."""
    font_names = [
        "DejaVuSans.ttf",
        "DejaVuSans-Bold.ttf",
        "FreeSans.ttf",
        "Arial.ttf",
        "LiberationSans-Regular.ttf",
    ]
    for font_name in font_names:
        try:
            return ImageFont.truetype(font_name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _create_demo_stamp_image(
    document_hash: str,
    timestamp: datetime,
    qr_enabled: bool = False,
    qr_position: str = "left",
) -> bytes:
    """
    Creates a demo stamp image with realistic signature appearance at 150 DPI.

    Args:
        document_hash: SHA-256 hash of the document
        timestamp: Signing timestamp
        qr_enabled: Whether to include QR code
        qr_position: "left" or "right" for QR placement

    Returns:
        PNG image bytes
    """
    # Determine dimensions (150 DPI)
    if qr_enabled:
        width = STAMP_WIDTH_PX
        height = STAMP_HEIGHT_PX
    else:
        width = 380  # ~2.5" at 150 DPI
        height = 130  # ~0.9" at 150 DPI

    # Create canvas with white background
    stamp = Image.new("RGB", (width, height), color="white")
    draw = ImageDraw.Draw(stamp)

    # Draw border (dark blue like real signatures)
    border_color = (0, 0, 128)  # Dark blue
    draw.rectangle([(0, 0), (width - 1, height - 1)], outline=border_color, width=3)

    # Load fonts (scaled for 150 DPI)
    font_header = _get_font(18)
    font_large = _get_font(22)
    font_medium = _get_font(16)
    font_small = _get_font(14)

    # Text colors
    text_color = (0, 0, 100)
    gray_color = (80, 80, 80)

    if qr_enabled:
        # Generate real QR code with demo data
        qr_data = QRData(
            document_hash=document_hash,
            signer_name=DEMO_SIGNER_NAME,
            timestamp=timestamp,
        )
        qr_img = generate_qr_image(qr_data, size_px=QR_SIZE_PX, border=1)

        # Position QR
        if qr_position == "left":
            qr_x = PADDING_PX + 5
            text_x = QR_SIZE_PX + PADDING_PX + 20
        else:
            qr_x = width - QR_SIZE_PX - PADDING_PX - 5
            text_x = PADDING_PX + 10

        qr_y = (height - QR_SIZE_PX) // 2
        stamp.paste(qr_img, (qr_x, qr_y))

        # Draw text to the side of QR
        text_y = PADDING_PX + 8

        # Header
        draw.text((text_x, text_y), "Digitally Signed", fill=text_color, font=font_header)
        text_y += 24

        # Signer name
        display_name = DEMO_SIGNER_NAME
        if len(display_name) > 25:
            display_name = display_name[:22] + "..."
        draw.text((text_x, text_y), display_name, fill=text_color, font=font_large)
        text_y += 28

        # Organization
        draw.text((text_x, text_y), DEMO_ORGANIZATION, fill=gray_color, font=font_medium)
        text_y += 22

        # Timestamp
        ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        draw.text((text_x, text_y), ts_str, fill=gray_color, font=font_small)
        text_y += 20

        # Demo indicator
        draw.text((text_x, text_y), "[DEMO MODE]", fill=(200, 0, 0), font=font_small)

    else:
        # Text-only stamp (no QR)
        text_x = PADDING_PX + 15
        text_y = PADDING_PX + 8

        # Header
        draw.text((text_x, text_y), "Digitally Signed", fill=text_color, font=font_header)
        text_y += 26

        # Signer name
        draw.text((text_x, text_y), DEMO_SIGNER_NAME, fill=text_color, font=font_large)
        text_y += 30

        # Organization
        draw.text((text_x, text_y), DEMO_ORGANIZATION, fill=gray_color, font=font_medium)
        text_y += 24

        # Timestamp
        ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        draw.text((text_x, text_y), ts_str, fill=gray_color, font=font_small)

    # Convert to bytes
    img_bytes = io.BytesIO()
    stamp.save(img_bytes, format="PNG")
    img_bytes.seek(0)
    return img_bytes.getvalue()


def _calculate_demo_hash(pdf_path: Path) -> str:
    """Calculate a demo hash for the PDF (first 64 chars of SHA-256)."""
    import hashlib

    hasher = hashlib.sha256()
    with open(pdf_path, "rb") as f:
        # Read in chunks for large files
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def add_stamp_to_pdf(
    input_path: Path,
    output_path: Path,
    page_spec: str | int = "last",
    visible: bool = True,
    position: str = "bottom_right",
    qr_enabled: bool = False,
) -> None:
    """
    Adds visual stamp to PDF in dry-run mode at 150 DPI quality.

    Creates a realistic signature appearance with:
    - Real QR code (if enabled) containing document hash, signer, timestamp
    - Demo signer information
    - High quality rendering

    Args:
        input_path: Input PDF path
        output_path: Output PDF path
        page_spec: Page specification
        visible: Whether to add visible stamp
        position: Position preference (bottom_right, top_left, etc.)
        qr_enabled: Include QR verification code in stamp
    """
    if not visible:
        # Just copy if no visible signature
        shutil.copy2(input_path, output_path)
        logger.info("[DRY-RUN] Invisible signature - copied without stamp")
        return

    doc = fitz.open(input_path)
    try:
        timestamp = datetime.now(UTC)

        # Calculate document hash for QR
        doc_hash = _calculate_demo_hash(input_path)

        # Create stamp image at 150 DPI
        stamp_image_bytes = _create_demo_stamp_image(
            document_hash=doc_hash,
            timestamp=timestamp,
            qr_enabled=qr_enabled,
            qr_position="left",  # QR on left side
        )

        # Determine stamp dimensions in PDF points (72 DPI)
        # Our image is 150 DPI, so we scale down for PDF placement
        if qr_enabled:
            # 460x170 px at 150 DPI = ~3.07" x 1.13" = 221 x 82 points
            stamp_width = 221
            stamp_height = 82
        else:
            # 380x130 px at 150 DPI = ~2.53" x 0.87" = 182 x 63 points
            stamp_width = 182
            stamp_height = 63

        pages_to_stamp = parse_page_spec(page_spec, len(doc))

        for page_num in pages_to_stamp:
            if page_num < len(doc):
                page = doc[page_num]

                # Get stamp rectangle based on position preference
                rect = get_stamp_rect(
                    page.rect.width,
                    page.rect.height,
                    position,
                    stamp_width=stamp_width,
                    stamp_height=stamp_height,
                )

                # Insert the stamp image
                page.insert_image(rect, stream=stamp_image_bytes)

        doc.save(output_path)
    finally:
        doc.close()

    qr_info = " with QR" if qr_enabled else ""
    logger.info(f"[DRY-RUN] Added stamp{qr_info} at '{position}' to {len(pages_to_stamp)} page(s)")

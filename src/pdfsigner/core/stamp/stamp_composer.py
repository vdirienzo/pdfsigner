"""
stamp_composer.py - Compose signature stamp with QR code

Author: Homero Thompson del Lago del Terror

Composes a visual signature stamp combining text information
and QR verification code into a single PNG image.
"""

import tempfile
from datetime import datetime
from pathlib import Path

from loguru import logger
from PIL import Image, ImageDraw, ImageFont

from pdfsigner.core.stamp.qr_generator import QRData, generate_qr_image

# Default stamp dimensions in pixels (at 300 DPI for high quality print)
# PDF uses 72 DPI, so we use 4x scale factor (300/72 ≈ 4.17)
SCALE_FACTOR = 4
DEFAULT_WIDTH_PX = 200 * SCALE_FACTOR  # 800px
DEFAULT_HEIGHT_PX = 70 * SCALE_FACTOR  # 280px
QR_SIZE_PX = 60 * SCALE_FACTOR  # 240px
PADDING_PX = 5 * SCALE_FACTOR  # 20px

# Common system fonts to try
SYSTEM_FONTS = ["DejaVuSans.ttf", "Arial.ttf", "FreeSans.ttf"]


def _load_fonts(
    font_size: int, small_font_size: int
) -> tuple[
    ImageFont.FreeTypeFont | ImageFont.ImageFont, ImageFont.FreeTypeFont | ImageFont.ImageFont
]:
    """
    Load system fonts with fallback to default.

    Args:
        font_size: Main font size in pixels
        small_font_size: Small font size in pixels

    Returns:
        Tuple of (font, small_font)
    """
    font: ImageFont.FreeTypeFont | ImageFont.ImageFont = ImageFont.load_default()
    small_font: ImageFont.FreeTypeFont | ImageFont.ImageFont = font

    for font_name in SYSTEM_FONTS:
        try:
            font = ImageFont.truetype(font_name, font_size)
            small_font = ImageFont.truetype(font_name, small_font_size)
            break
        except OSError:
            continue

    return font, small_font


def compose_stamp_with_qr(
    signer_name: str,
    timestamp: datetime,
    qr_data: QRData,
    width_px: int = DEFAULT_WIDTH_PX,
    height_px: int = DEFAULT_HEIGHT_PX,
    qr_position: str = "left",
) -> Path:
    """
    Compose a signature stamp image with embedded QR code.

    Creates a PNG image with:
    - QR code on left or right side
    - Signer name and timestamp text

    Args:
        signer_name: Name of the signer (from certificate CN)
        timestamp: Signing timestamp
        qr_data: Data for QR code generation
        width_px: Total stamp width in pixels
        height_px: Total stamp height in pixels
        qr_position: "left" or "right" for QR placement

    Returns:
        Path to temporary PNG file with composed stamp
    """
    # Calculate QR size based on stamp height
    qr_size = min(height_px - 2 * PADDING_PX, QR_SIZE_PX)

    # Generate QR code
    qr_img = generate_qr_image(qr_data, size_px=qr_size)

    # Create stamp canvas with white background
    stamp = Image.new("RGB", (width_px, height_px), color="white")
    draw = ImageDraw.Draw(stamp)

    # Draw border
    draw.rectangle(
        [(0, 0), (width_px - 1, height_px - 1)],
        outline="black",
        width=1,
    )

    # Position QR code
    if qr_position == "left":
        qr_x = PADDING_PX
        text_x = qr_size + 2 * PADDING_PX
    else:
        qr_x = width_px - qr_size - PADDING_PX
        text_x = PADDING_PX

    qr_y = (height_px - qr_size) // 2
    stamp.paste(qr_img, (qr_x, qr_y))

    # Load fonts (scaled for 300 DPI)
    font_size = 10 * SCALE_FACTOR  # 40px
    small_font_size = 8 * SCALE_FACTOR  # 32px
    font, small_font = _load_fonts(font_size, small_font_size)

    # Draw text
    text_y = PADDING_PX + 2 * SCALE_FACTOR

    # "Digitally Signed" header
    draw.text((text_x, text_y), "Digitally Signed", fill="#666666", font=small_font)
    text_y += small_font_size + 2 * SCALE_FACTOR

    # Signer name (truncate if too long)
    display_name = signer_name
    if len(display_name) > 25:
        display_name = display_name[:22] + "..."
    draw.text((text_x, text_y), display_name, fill="black", font=font)
    text_y += font_size + 2 * SCALE_FACTOR

    # Timestamp
    ts_str = timestamp.strftime("%Y-%m-%d %H:%M")
    draw.text((text_x, text_y), ts_str, fill="#888888", font=small_font)

    # Save to temporary file with 300 DPI metadata
    temp_file = tempfile.NamedTemporaryFile(
        suffix=".png",
        delete=False,
        prefix="pdfsigner_stamp_",
    )
    stamp.save(temp_file.name, "PNG", dpi=(300, 300))
    temp_file.close()

    logger.debug(f"Composed stamp saved to: {temp_file.name}")

    return Path(temp_file.name)


def compose_stamp_text_only(
    signer_name: str,
    timestamp: datetime,
    width_px: int = DEFAULT_WIDTH_PX,
    height_px: int = DEFAULT_HEIGHT_PX,
) -> Path:
    """
    Compose a signature stamp image without QR code.

    Creates a PNG image with only text (for when QR is disabled).

    Args:
        signer_name: Name of the signer
        timestamp: Signing timestamp
        width_px: Total stamp width in pixels
        height_px: Total stamp height in pixels

    Returns:
        Path to temporary PNG file with composed stamp
    """
    # Create stamp canvas with white background
    stamp = Image.new("RGB", (width_px, height_px), color="white")
    draw = ImageDraw.Draw(stamp)

    # Draw border
    draw.rectangle(
        [(0, 0), (width_px - 1, height_px - 1)],
        outline="black",
        width=1,
    )

    # Load fonts (scaled for 300 DPI)
    font_size = 12 * SCALE_FACTOR  # 48px
    small_font_size = 10 * SCALE_FACTOR  # 40px
    font, small_font = _load_fonts(font_size, small_font_size)

    # Center text vertically
    text_x = PADDING_PX + 5 * SCALE_FACTOR
    text_y = PADDING_PX + 5 * SCALE_FACTOR

    # "Digitally Signed" header
    draw.text((text_x, text_y), "Digitally Signed", fill="#666666", font=small_font)
    text_y += small_font_size + 4 * SCALE_FACTOR

    # Signer name
    display_name = signer_name
    if len(display_name) > 30:
        display_name = display_name[:27] + "..."
    draw.text((text_x, text_y), display_name, fill="black", font=font)
    text_y += font_size + 4 * SCALE_FACTOR

    # Timestamp
    ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    draw.text((text_x, text_y), ts_str, fill="#888888", font=small_font)

    # Save to temporary file with 300 DPI metadata
    temp_file = tempfile.NamedTemporaryFile(
        suffix=".png",
        delete=False,
        prefix="pdfsigner_stamp_",
    )
    stamp.save(temp_file.name, "PNG", dpi=(300, 300))
    temp_file.close()

    logger.debug(f"Composed text stamp saved to: {temp_file.name}")

    return Path(temp_file.name)

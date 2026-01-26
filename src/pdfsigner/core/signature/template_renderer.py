"""
template_renderer.py - Render signature templates to PNG

Author: Homero Thompson del Lago del Terror

Renders Template objects to PNG images using PIL,
with variable substitution and 300 DPI for print quality.
"""

from __future__ import annotations

import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger
from PIL import Image, ImageDraw, ImageFont

if TYPE_CHECKING:
    from pdfsigner.core.signature.template import Layer, Template

# 300 DPI for high-quality print (PDF uses 72 DPI internally)
DPI = 300
MM_TO_INCH = 25.4


def _mm_to_px(mm: float) -> int:
    """Convert millimeters to pixels at 300 DPI."""
    return int((mm / MM_TO_INCH) * DPI)


def _load_font(family: str, size_px: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """
    Load a TrueType font with fallback to default.

    Args:
        family: Font family name (sans-serif, serif, mono)
        size_px: Font size in pixels

    Returns:
        PIL font object
    """
    # Map generic families to common system fonts
    font_map = {
        "sans-serif": ["DejaVuSans.ttf", "FreeSans.ttf", "Arial.ttf", "Liberation Sans"],
        "serif": ["DejaVuSerif.ttf", "FreeSerif.ttf", "Times.ttf", "Liberation Serif"],
        "mono": ["DejaVuSansMono.ttf", "FreeMono.ttf", "Courier.ttf", "Liberation Mono"],
    }

    font_names = font_map.get(family, font_map["sans-serif"])

    for font_name in font_names:
        try:
            return ImageFont.truetype(font_name, size_px)
        except OSError:
            continue

    # Fallback to default
    logger.warning(f"Could not load font family '{family}', using default")
    return ImageFont.load_default()


def _parse_color(color: str | None, default: str = "#000000") -> tuple[int, int, int, int]:
    """
    Parse hex color string to RGBA tuple.

    Args:
        color: Hex color string (e.g., "#ff0000" or "#ff0000ff")
        default: Default color if None provided

    Returns:
        RGBA tuple (0-255 each)
    """
    if not color:
        color = default

    # Remove # prefix
    color = color.lstrip("#")

    # Parse RGB or RGBA
    if len(color) == 6:
        r, g, b = int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
        return (r, g, b, 255)
    elif len(color) == 8:
        r, g, b = int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
        a = int(color[6:8], 16)
        return (r, g, b, a)
    else:
        return (0, 0, 0, 255)


def _substitute_variables(text: str, variables: dict[str, str]) -> str:
    """
    Replace {variable} placeholders with values.

    Args:
        text: Text with {variable} placeholders
        variables: Dictionary of variable names to values

    Returns:
        Text with variables substituted
    """
    result = text
    for key, value in variables.items():
        result = result.replace(f"{{{key}}}", value)

    # Remove any remaining unresolved variables
    result = re.sub(r"\{[^}]+\}", "", result)
    return result


def _render_layer(
    draw: ImageDraw.ImageDraw,
    layer: Layer,
    width_px: int,
    height_px: int,
    variables: dict[str, str],
    templates_dir: Path | None = None,
    base_image: Image.Image | None = None,
) -> Image.Image | None:
    """
    Render a single layer onto the image.

    Args:
        draw: PIL ImageDraw object
        layer: Layer to render
        width_px: Total stamp width in pixels
        height_px: Total stamp height in pixels
        variables: Variables for text substitution
        templates_dir: Directory containing template assets (images)
        base_image: Base image for compositing (for image layers)

    Returns:
        Modified base image if image layer, None otherwise
    """
    # Calculate absolute positions
    x = int(layer.x / 100 * width_px)
    y = int(layer.y / 100 * height_px)

    layer_w = int(layer.width / 100 * width_px) if layer.width else None
    layer_h = int(layer.height / 100 * height_px) if layer.height else None

    if layer.type == "background":
        color = _parse_color(layer.color, "#ffffff")
        color_with_opacity = (*color[:3], int(color[3] * layer.opacity))
        draw.rectangle([(0, 0), (width_px, height_px)], fill=color_with_opacity)

    elif layer.type == "border":
        color = _parse_color(layer.color, "#333333")
        color_with_opacity = (*color[:3], int(color[3] * layer.opacity))
        # Draw border inside the image bounds
        for i in range(layer.border_width):
            draw.rectangle(
                [(i, i), (width_px - 1 - i, height_px - 1 - i)],
                outline=color_with_opacity,
            )

    elif layer.type == "text" and layer.text:
        text = _substitute_variables(layer.text, variables)
        if not text:
            return base_image

        # Scale font size for 300 DPI (font_size is in points at 72 DPI)
        font_size_px = int(layer.font_size * DPI / 72)
        font = _load_font(layer.font_family, font_size_px)

        color = _parse_color(layer.color, "#000000")
        color_with_opacity = (*color[:3], int(color[3] * layer.opacity))

        # Handle text alignment
        if layer.alignment == "center" and layer_w:
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            x = x + (layer_w - text_width) // 2
        elif layer.alignment == "right" and layer_w:
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            x = x + layer_w - text_width

        draw.text((x, y), text, fill=color_with_opacity, font=font)

    elif layer.type == "image" and layer.image_path and templates_dir:
        image_path = templates_dir / layer.image_path
        if image_path.exists():
            try:
                img = Image.open(image_path).convert("RGBA")

                # Resize if dimensions specified
                if layer_w and layer_h:
                    img = img.resize((layer_w, layer_h), Image.Resampling.LANCZOS)
                elif layer_w:
                    ratio = layer_w / img.width
                    img = img.resize((layer_w, int(img.height * ratio)), Image.Resampling.LANCZOS)
                elif layer_h:
                    ratio = layer_h / img.height
                    img = img.resize((int(img.width * ratio), layer_h), Image.Resampling.LANCZOS)

                # Apply opacity
                if layer.opacity < 1.0:
                    alpha = img.split()[3]
                    alpha = alpha.point(lambda p: int(p * layer.opacity))
                    img.putalpha(alpha)

                # Paste onto base image
                if base_image:
                    base_image.paste(img, (x, y), img)
                    return base_image
            except Exception as e:
                logger.warning(f"Could not load image {image_path}: {e}")
        else:
            logger.warning(f"Image not found: {image_path}")

    elif layer.type == "qr":
        # QR code generation requires document hash, handled separately
        # For preview, draw a placeholder
        if layer_w and layer_h:
            qr_size = min(layer_w, layer_h)
            draw.rectangle(
                [(x, y), (x + qr_size, y + qr_size)],
                outline="#666666",
                width=1,
            )
            # Draw QR placeholder pattern
            small_font = _load_font("mono", int(8 * DPI / 72))
            draw.text((x + 2, y + 2), "QR", fill="#666666", font=small_font)

    return base_image


def render_template(
    template: Template,
    variables: dict[str, str] | None = None,
    templates_dir: Path | None = None,
    qr_image: Image.Image | None = None,
) -> Path:
    """
    Render a template to a PNG image.

    Args:
        template: Template to render
        variables: Variable substitutions (signer_name, date, org)
        templates_dir: Directory containing template assets
        qr_image: Pre-generated QR code image (if template has QR layer)

    Returns:
        Path to temporary PNG file
    """
    variables = variables or {}

    # Add default variables if not provided
    if "date" not in variables:
        variables["date"] = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Calculate dimensions in pixels (300 DPI)
    width_px = _mm_to_px(template.width_mm)
    height_px = _mm_to_px(template.height_mm)

    # Create RGBA image for transparency support
    image = Image.new("RGBA", (width_px, height_px), (255, 255, 255, 255))
    draw = ImageDraw.Draw(image)

    # Render layers in order (bottom to top)
    for layer in template.layers:
        if layer.type == "qr" and qr_image:
            # Handle QR layer with provided image
            x = int(layer.x / 100 * width_px)
            y = int(layer.y / 100 * height_px)
            layer_w = int(layer.width / 100 * width_px) if layer.width else qr_image.width
            layer_h = int(layer.height / 100 * height_px) if layer.height else qr_image.height

            qr_size = min(layer_w, layer_h)
            qr_resized = qr_image.resize((qr_size, qr_size), Image.Resampling.LANCZOS)

            if qr_resized.mode != "RGBA":
                qr_resized = qr_resized.convert("RGBA")

            image.paste(qr_resized, (x, y), qr_resized)
        else:
            result = _render_layer(
                draw, layer, width_px, height_px, variables, templates_dir, image
            )
            if result:
                image = result
                draw = ImageDraw.Draw(image)

    # Convert to RGB for PNG (drop alpha if fully opaque)
    final_image = image.convert("RGB")

    # Save to temporary file
    temp_file = tempfile.NamedTemporaryFile(
        suffix=".png",
        delete=False,
        prefix="pdfsigner_template_",
    )
    final_image.save(temp_file.name, "PNG", dpi=(DPI, DPI))
    temp_file.close()

    logger.debug(f"Rendered template '{template.name}' to: {temp_file.name}")

    return Path(temp_file.name)


def render_preview(
    template: Template,
    width_px: int = 400,
    height_px: int | None = None,
    templates_dir: Path | None = None,
) -> Image.Image:
    """
    Render a preview image of the template at specified size.

    Used for UI previews (lower resolution than print).

    Args:
        template: Template to preview
        width_px: Preview width in pixels
        height_px: Preview height (calculated from aspect ratio if None)
        templates_dir: Directory containing template assets

    Returns:
        PIL Image object
    """
    # Calculate height maintaining aspect ratio
    if height_px is None:
        aspect = template.height_mm / template.width_mm
        height_px = int(width_px * aspect)

    # Sample variables for preview
    variables = {
        "signer_name": "Juan P\u00e9rez Garc\u00eda",
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "org": "Empresa S.A.",
    }

    # Create preview image
    image = Image.new("RGBA", (width_px, height_px), (255, 255, 255, 255))
    draw = ImageDraw.Draw(image)

    # Scale factor for preview
    full_width = _mm_to_px(template.width_mm)
    scale = width_px / full_width

    # Render layers with scaled font sizes
    for layer in template.layers:
        if layer.type == "background":
            color = _parse_color(layer.color, "#ffffff")
            draw.rectangle([(0, 0), (width_px, height_px)], fill=color[:3])

        elif layer.type == "border":
            color = _parse_color(layer.color, "#333333")
            border_w = max(1, int(layer.border_width * scale))
            for i in range(border_w):
                draw.rectangle(
                    [(i, i), (width_px - 1 - i, height_px - 1 - i)],
                    outline=color[:3],
                )

        elif layer.type == "text" and layer.text:
            text = _substitute_variables(layer.text, variables)
            if not text:
                continue

            x = int(layer.x / 100 * width_px)
            y = int(layer.y / 100 * height_px)

            # Scale font size
            font_size_px = max(8, int(layer.font_size * scale * DPI / 72))
            font = _load_font(layer.font_family, font_size_px)

            color = _parse_color(layer.color, "#000000")
            draw.text((x, y), text, fill=color[:3], font=font)

        elif layer.type == "qr":
            # Draw QR placeholder in preview
            x = int(layer.x / 100 * width_px)
            y = int(layer.y / 100 * height_px)
            w = int((layer.width or 20) / 100 * width_px)
            h = int((layer.height or 20) / 100 * height_px)
            qr_size = min(w, h)

            draw.rectangle([(x, y), (x + qr_size, y + qr_size)], outline="#666666")
            # Simple QR pattern
            cell = qr_size // 5
            for i in range(5):
                for j in range(5):
                    if (i + j) % 2 == 0:
                        draw.rectangle(
                            [
                                (x + i * cell, y + j * cell),
                                (x + (i + 1) * cell, y + (j + 1) * cell),
                            ],
                            fill="#333333",
                        )

        elif layer.type == "image" and layer.image_path and templates_dir:
            image_path = templates_dir / layer.image_path
            if image_path.exists():
                try:
                    img = Image.open(image_path).convert("RGBA")
                    x = int(layer.x / 100 * width_px)
                    y = int(layer.y / 100 * height_px)
                    w = int((layer.width or 20) / 100 * width_px) if layer.width else None
                    h = int((layer.height or 20) / 100 * height_px) if layer.height else None

                    if w and h:
                        img = img.resize((w, h), Image.Resampling.LANCZOS)

                    image.paste(img, (x, y), img)
                except Exception as e:
                    logger.warning(f"Preview: could not load image {image_path}: {e}")

    return image.convert("RGB")

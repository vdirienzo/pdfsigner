"""
template_renderer.py - Render signature templates to PNG

Renders Template objects to PNG images using PIL,
with variable substitution and 300 DPI for print quality.
Includes path sanitization to prevent path traversal attacks.
"""

from __future__ import annotations

import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger
from PIL import Image, ImageDraw, ImageFont

from pdfsigner.core.security.path_sanitizer import PathTraversalError, sanitize_path

if TYPE_CHECKING:
    from pdfsigner.core.signature.template import Layer, Template

# 300 DPI for high-quality print (PDF uses 72 DPI internally)
DPI = 300
MM_TO_INCH = 25.4


def _mm_to_px(mm: float) -> int:
    """Convert millimeters to pixels at 300 DPI."""
    return int((mm / MM_TO_INCH) * DPI)


def _load_font(family: str, size_px: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Load a TrueType font with fallback to default."""
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
    """Parse hex color string (#rrggbb or #rrggbbaa) to RGBA tuple."""
    if not color:
        color = default
    color = color.lstrip("#")
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
    """Replace {variable} placeholders with values, removing unresolved ones."""
    result = text
    for key, value in variables.items():
        result = result.replace(f"{{{key}}}", value)
    return re.sub(r"\{[^}]+\}", "", result)


def _sanitize_image_path(image_path: str, templates_dir: Path) -> Path | None:
    """Sanitize and validate an image path, returning None if invalid."""
    try:
        return sanitize_path(
            image_path,
            base_dir=templates_dir,
            must_exist=True,
            path_description="template image",
        )
    except (PathTraversalError, FileNotFoundError) as e:
        logger.warning(f"Invalid image path in template: {e}")
        return None


def _calc_layer_geometry(
    layer: Layer, width_px: int, height_px: int
) -> tuple[int, int, int | None, int | None]:
    """Calculate absolute position and size from percentage-based layer values."""
    x = int(layer.x / 100 * width_px)
    y = int(layer.y / 100 * height_px)
    layer_w = int(layer.width / 100 * width_px) if layer.width else None
    layer_h = int(layer.height / 100 * height_px) if layer.height else None
    return x, y, layer_w, layer_h


def _render_text_layer(
    draw: ImageDraw.ImageDraw,
    layer: Layer,
    x: int,
    y: int,
    layer_w: int | None,
    variables: dict[str, str],
) -> None:
    """Render a text layer with alignment and variable substitution."""
    text = _substitute_variables(layer.text, variables)
    if not text:
        return

    font_size_px = int(layer.font_size * DPI / 72)
    font = _load_font(layer.font_family, font_size_px)

    color = _parse_color(layer.color, "#000000")
    color_with_opacity = (*color[:3], int(color[3] * layer.opacity))

    if layer.alignment == "center" and layer_w:
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        x = int(x + (layer_w - text_width) // 2)
    elif layer.alignment == "right" and layer_w:
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        x = int(x + layer_w - text_width)

    draw.text((x, y), text, fill=color_with_opacity, font=font)


def _render_image_layer(
    layer: Layer,
    x: int,
    y: int,
    layer_w: int | None,
    layer_h: int | None,
    templates_dir: Path,
    base_image: Image.Image | None,
) -> Image.Image | None:
    """Render an image layer onto the base image."""
    image_path = _sanitize_image_path(layer.image_path, templates_dir)
    if image_path is None:
        return base_image

    try:
        img = Image.open(image_path).convert("RGBA")

        if layer_w and layer_h:
            img = img.resize((layer_w, layer_h), Image.Resampling.LANCZOS)
        elif layer_w:
            ratio = layer_w / img.width
            img = img.resize((layer_w, int(img.height * ratio)), Image.Resampling.LANCZOS)
        elif layer_h:
            ratio = layer_h / img.height
            img = img.resize((int(img.width * ratio), layer_h), Image.Resampling.LANCZOS)

        if layer.opacity < 1.0:
            alpha = img.split()[3]
            alpha = alpha.point(lambda p: int(p * layer.opacity))
            img.putalpha(alpha)

        if base_image:
            base_image.paste(img, (x, y), img)
            return base_image
    except Exception as e:
        logger.warning(f"Could not load image {image_path}: {e}")

    return base_image


def _render_qr_placeholder(
    draw: ImageDraw.ImageDraw, x: int, y: int, layer_w: int | None, layer_h: int | None
) -> None:
    """Render a QR code placeholder rectangle."""
    if layer_w and layer_h:
        qr_size = min(layer_w, layer_h)
        draw.rectangle([(x, y), (x + qr_size, y + qr_size)], outline="#666666", width=1)
        small_font = _load_font("mono", int(8 * DPI / 72))
        draw.text((x + 2, y + 2), "QR", fill="#666666", font=small_font)


def _render_layer(
    draw: ImageDraw.ImageDraw,
    layer: Layer,
    width_px: int,
    height_px: int,
    variables: dict[str, str],
    templates_dir: Path | None = None,
    base_image: Image.Image | None = None,
) -> Image.Image | None:
    """Render a single layer onto the image, returning modified base_image if applicable."""
    x, y, layer_w, layer_h = _calc_layer_geometry(layer, width_px, height_px)

    if layer.type == "background":
        color = _parse_color(layer.color, "#ffffff")
        color_with_opacity = (*color[:3], int(color[3] * layer.opacity))
        draw.rectangle([(0, 0), (width_px, height_px)], fill=color_with_opacity)

    elif layer.type == "border":
        color = _parse_color(layer.color, "#333333")
        color_with_opacity = (*color[:3], int(color[3] * layer.opacity))
        for i in range(layer.border_width):
            draw.rectangle(
                [(i, i), (width_px - 1 - i, height_px - 1 - i)],
                outline=color_with_opacity,
            )

    elif layer.type == "text" and layer.text:
        _render_text_layer(draw, layer, x, y, layer_w, variables)

    elif layer.type == "image" and layer.image_path and templates_dir:
        return _render_image_layer(layer, x, y, layer_w, layer_h, templates_dir, base_image)

    elif layer.type == "qr":
        _render_qr_placeholder(draw, x, y, layer_w, layer_h)

    return base_image


def render_template(
    template: Template,
    variables: dict[str, str] | None = None,
    templates_dir: Path | None = None,
    qr_image: Image.Image | None = None,
) -> Path:
    """Render a template to a PNG image file, returning path to temp file."""
    variables = variables or {}

    # Add default variables if not provided
    if "date" not in variables:
        variables["date"] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")

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


def _render_preview_qr(
    draw: ImageDraw.ImageDraw, layer: Layer, width_px: int, height_px: int
) -> None:
    """Render a QR checkerboard pattern for preview."""
    x = int(layer.x / 100 * width_px)
    y = int(layer.y / 100 * height_px)
    w = int((layer.width or 20) / 100 * width_px)
    h = int((layer.height or 20) / 100 * height_px)
    qr_size = min(w, h)

    draw.rectangle([(x, y), (x + qr_size, y + qr_size)], outline="#666666")
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


def _render_preview_image(
    layer: Layer, width_px: int, height_px: int, templates_dir: Path, image: Image.Image
) -> None:
    """Render an image layer for the preview."""
    safe_image_path = _sanitize_image_path(layer.image_path, templates_dir)
    if safe_image_path is None:
        return

    try:
        img = Image.open(safe_image_path).convert("RGBA")
        img_x = int(layer.x / 100 * width_px)
        img_y = int(layer.y / 100 * height_px)
        img_w: int | None = int((layer.width or 20) / 100 * width_px) if layer.width else None
        img_h: int | None = int((layer.height or 20) / 100 * height_px) if layer.height else None

        if img_w and img_h:
            img = img.resize((img_w, img_h), Image.Resampling.LANCZOS)

        image.paste(img, (img_x, img_y), img)
    except Exception as e:
        logger.warning(f"Preview: could not load image {safe_image_path}: {e}")


def render_preview(
    template: Template,
    width_px: int = 400,
    height_px: int | None = None,
    templates_dir: Path | None = None,
) -> Image.Image:
    """Render a low-res preview image of the template for UI display."""
    # Calculate height maintaining aspect ratio
    if height_px is None:
        aspect = template.height_mm / template.width_mm
        height_px = int(width_px * aspect)

    # Sample variables for preview
    variables = {
        "signer_name": "John A. Smith",
        "date": datetime.now(UTC).strftime("%Y-%m-%d %H:%M"),
        "org": "Acme Corp",
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

            font_size_px = max(8, int(layer.font_size * scale * DPI / 72))
            font = _load_font(layer.font_family, font_size_px)

            color = _parse_color(layer.color, "#000000")
            draw.text((x, y), text, fill=color[:3], font=font)

        elif layer.type == "qr":
            _render_preview_qr(draw, layer, width_px, height_px)

        elif layer.type == "image" and layer.image_path and templates_dir:
            _render_preview_image(layer, width_px, height_px, templates_dir, image)

    return image.convert("RGB")

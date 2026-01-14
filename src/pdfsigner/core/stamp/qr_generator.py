"""
qr_generator.py - QR code generation for signature verification

Author: Homero Thompson del Lago del Terror

Generates QR codes containing document hash, signer info, and timestamp.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import qrcode
from loguru import logger
from PIL import Image


@dataclass
class QRData:
    """Data to encode in verification QR code."""

    document_hash: str
    signer_name: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_json(self) -> str:
        """Serialize QR data to compact JSON string."""
        data = {
            "hash": self.document_hash[:16] + "...",  # Truncated for QR size
            "signer": self.signer_name,
            "ts": self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return json.dumps(data, separators=(",", ":"))


def calculate_document_hash(pdf_path: Path) -> str:
    """
    Calculate SHA-256 hash of PDF content.

    Args:
        pdf_path: Path to PDF file

    Returns:
        Hex-encoded SHA-256 hash
    """
    sha256 = hashlib.sha256()
    with open(pdf_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_qr_image(
    qr_data: QRData,
    size_px: int = 150,
    border: int = 2,
) -> Image.Image:
    """
    Generate QR code image from verification data.

    Args:
        qr_data: Data to encode in QR
        size_px: Target size in pixels
        border: Border modules around QR

    Returns:
        PIL Image containing QR code
    """
    content = qr_data.to_json()

    logger.debug(f"Generating QR with content length: {len(content)}")

    # Create QR code with auto version selection
    qr = qrcode.QRCode(
        version=None,  # Auto-select smallest version that fits
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=border,
    )
    qr.add_data(content)
    qr.make(fit=True)

    # Generate image
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to PIL Image and resize to target
    if hasattr(img, "get_image"):
        pil_img = img.get_image()
    else:
        pil_img = img

    # Resize to target size maintaining aspect ratio
    pil_img = pil_img.resize((size_px, size_px), Image.Resampling.LANCZOS)

    return pil_img


def generate_qr_bytes(qr_data: QRData, size_px: int = 150) -> bytes:
    """
    Generate QR code as PNG bytes.

    Args:
        qr_data: Data to encode in QR
        size_px: Target size in pixels

    Returns:
        PNG image bytes
    """
    img = generate_qr_image(qr_data, size_px)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()

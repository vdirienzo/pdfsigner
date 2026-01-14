"""
stamp - QR code and stamp composition module

Author: Homero Thompson del Lago del Terror

Provides QR code generation and stamp image composition
for visible digital signatures with verification codes.
"""

from pdfsigner.core.stamp.qr_generator import QRData, generate_qr_image
from pdfsigner.core.stamp.stamp_composer import compose_stamp_with_qr

__all__ = ["QRData", "generate_qr_image", "compose_stamp_with_qr"]

"""
Validator - Módulo de validación de firmas PDF

Autor: Homero Thompson del Lago del Terror
"""

from pdfsigner.core.validator.pdf_validator import PDFValidator
from pdfsigner.core.validator.validator_types import (
    LTVInfo,
    PAdESLevel,
    SignatureInfo,
    SignatureStatus,
    ValidationResult,
)

__all__ = [
    "PDFValidator",
    "SignatureInfo",
    "SignatureStatus",
    "PAdESLevel",
    "LTVInfo",
    "ValidationResult",
]

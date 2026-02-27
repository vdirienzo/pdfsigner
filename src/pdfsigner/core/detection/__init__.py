"""
PHI/PII Detection Engine for HIPAA/GDPR compliance.

This module provides detection of Protected Health Information (PHI)
and Personally Identifiable Information (PII) in PDF documents.

Key components:
- PIIDetector: Main detection engine with pattern matching
- PDFScanner: PDF text extraction with coordinate tracking
- PIIType: Enumeration of supported PII types
- PIIMatch: Detection result with confidence scoring

Usage:
    from pdfsigner.core.detection import get_pii_detector

    detector = get_pii_detector()
    matches = detector.scan_text("SSN: 123-45-6789")
    risk_score = detector.get_risk_score(matches)

Author: Homero Thompson del Lago del Terror
"""

from pdfsigner.core.detection.pdf_scanner import PDFScanner, TextBlock
from pdfsigner.core.detection.pii_detector import PIIDetector, get_pii_detector
from pdfsigner.core.detection.pii_types import PIIMatch, PIIType, RedactionRegion
from pdfsigner.core.detection.redaction_types import RedactionResult
from pdfsigner.core.detection.redactor import PDFRedactor, get_pdf_redactor

__all__ = [
    "PIIType",
    "PIIMatch",
    "RedactionRegion",
    "PIIDetector",
    "get_pii_detector",
    "PDFScanner",
    "TextBlock",
    "PDFRedactor",
    "RedactionResult",
    "get_pdf_redactor",
]

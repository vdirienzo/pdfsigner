"""
PHI detection module for PDFSigner.

Provides automated detection of Protected Health Information (PHI)
in PDF documents per HIPAA §164.514 de-identification requirements.

Usage:
    from pdfsigner.core.phi import PHIScanner, get_phi_scanner, PHIType

    # Scan a PDF
    scanner = get_phi_scanner()
    result = scanner.scan_pdf(Path("document.pdf"))

    if result.has_phi:
        print(f"Found {result.total_matches} PHI instances")
        for match in result.matches:
            print(f"  {match.phi_type}: {match.value} on page {match.page}")

    # Scan text only
    matches = scanner.scan_text("SSN: 123-45-6789")
"""

from pdfsigner.core.phi.patterns import (
    HIPAA_PATTERNS,
    PHIPattern,
    PHIType,
    get_enabled_patterns,
    get_high_confidence_patterns,
    get_patterns_by_type,
)
from pdfsigner.core.phi.scanner import (
    Confidence,
    PHIMatch,
    PHIScanner,
    PHIScanResult,
    get_phi_scanner,
)

__all__ = [
    # Scanner
    "PHIScanner",
    "get_phi_scanner",
    # Results
    "PHIMatch",
    "PHIScanResult",
    "Confidence",
    # Patterns
    "PHIType",
    "PHIPattern",
    "HIPAA_PATTERNS",
    # Pattern utilities
    "get_enabled_patterns",
    "get_patterns_by_type",
    "get_high_confidence_patterns",
]

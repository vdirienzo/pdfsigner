"""
scanner.py - PHI detection scanner for PDFs

Scans PDF documents for Protected Health Information using
pattern matching against HIPAA §164.514 identifiers.

Author: Homero Thompson del Lago del Terror
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from loguru import logger

from pdfsigner.core.phi.patterns import HIPAA_PATTERNS, PHIPattern, PHIType

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None


class Confidence(str, Enum):
    """Confidence level for PHI detection."""

    LOW = "low"  # 0.0-0.59
    MEDIUM = "medium"  # 0.60-0.84
    HIGH = "high"  # 0.85-1.0


@dataclass
class PHIMatch:
    """
    A detected instance of PHI in a document.

    Attributes:
        phi_type: Type of PHI detected
        value: Matched text (masked for security)
        page: Page number (0-indexed)
        position: Bounding box (x0, y0, x1, y1)
        confidence: Confidence level of detection
        pattern_used: Description of pattern that matched
    """

    phi_type: PHIType
    value: str  # Masked value
    page: int
    position: tuple[float, float, float, float]
    confidence: Confidence
    pattern_used: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "phi_type": self.phi_type.value,
            "value": self.value,
            "page": self.page,
            "position": list(self.position),
            "confidence": self.confidence.value,
            "pattern_used": self.pattern_used,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PHIMatch":
        """Create PHIMatch from dictionary."""
        return cls(
            phi_type=PHIType(data["phi_type"]),
            value=data["value"],
            page=data["page"],
            position=tuple(data["position"]),
            confidence=Confidence(data["confidence"]),
            pattern_used=data["pattern_used"],
        )


@dataclass
class PHIScanResult:
    """
    Result of PHI scan operation.

    Attributes:
        has_phi: Whether any PHI was detected
        matches: List of all detected PHI instances
        total_matches: Total count of matches
        by_type: Count of matches by PHI type
        overall_confidence: Overall confidence of scan
        scan_time_ms: Time taken for scan in milliseconds
        pages_scanned: Number of pages scanned
        error: Error message if scan failed
    """

    has_phi: bool
    matches: list[PHIMatch] = field(default_factory=list)
    total_matches: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    overall_confidence: Confidence = Confidence.LOW
    scan_time_ms: float = 0.0
    pages_scanned: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "has_phi": self.has_phi,
            "matches": [m.to_dict() for m in self.matches],
            "total_matches": self.total_matches,
            "by_type": self.by_type,
            "overall_confidence": self.overall_confidence.value,
            "scan_time_ms": self.scan_time_ms,
            "pages_scanned": self.pages_scanned,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PHIScanResult":
        """Create PHIScanResult from dictionary."""
        return cls(
            has_phi=data["has_phi"],
            matches=[PHIMatch.from_dict(m) for m in data["matches"]],
            total_matches=data["total_matches"],
            by_type=data["by_type"],
            overall_confidence=Confidence(data["overall_confidence"]),
            scan_time_ms=data["scan_time_ms"],
            pages_scanned=data["pages_scanned"],
            error=data.get("error"),
        )


class PHIScanner:
    """
    Scanner for detecting PHI in PDF documents.

    Uses regex patterns to identify HIPAA identifiers in text
    extracted from PDFs.
    """

    def __init__(self, patterns: list[PHIPattern] | None = None) -> None:
        """
        Initialize PHI scanner.

        Args:
            patterns: List of patterns to use (defaults to HIPAA_PATTERNS)
        """
        self._patterns = patterns or HIPAA_PATTERNS
        self._compiled_patterns: list[tuple[PHIPattern, re.Pattern[str]]] = []
        self._compile_patterns()

        logger.debug(f"PHI scanner initialized with {len(self._patterns)} patterns")

    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficiency."""
        self._compiled_patterns = []
        for pattern in self._patterns:
            if pattern.enabled:
                try:
                    compiled = re.compile(pattern.pattern, re.IGNORECASE)
                    self._compiled_patterns.append((pattern, compiled))
                except re.error as e:
                    logger.warning(f"Failed to compile pattern for {pattern.phi_type}: {e}")

    def scan_pdf(self, pdf_path: Path) -> PHIScanResult:
        """
        Scan PDF document for PHI.

        Args:
            pdf_path: Path to PDF file

        Returns:
            PHIScanResult with detected PHI instances
        """
        if fitz is None:
            logger.error("PyMuPDF (fitz) not available for PHI scanning")
            return PHIScanResult(
                has_phi=False,
                error="PyMuPDF not available",
            )

        start_time = time.time()

        try:
            # Open PDF
            doc = fitz.open(pdf_path)
            try:
                # Check if encrypted
                if doc.is_encrypted:
                    logger.warning(f"PDF is encrypted, cannot scan: {pdf_path}")
                    return PHIScanResult(
                        has_phi=False,
                        error="PDF is encrypted",
                    )

                # Scan all pages
                all_matches: list[PHIMatch] = []
                page_count = len(doc)

                for page_num in range(page_count):
                    page = doc[page_num]
                    text = page.get_text("text")

                    # Scan text with position tracking
                    page_matches = self._scan_text_with_positions(text, page_num, page)
                    all_matches.extend(page_matches)
            finally:
                doc.close()

            # Calculate statistics
            by_type = self._count_by_type(all_matches)
            overall_confidence = self._calculate_overall_confidence(all_matches)

            scan_time_ms = (time.time() - start_time) * 1000

            logger.info(
                f"PHI scan complete: {len(all_matches)} matches in "
                f"{page_count} pages ({scan_time_ms:.1f}ms)"
            )

            return PHIScanResult(
                has_phi=len(all_matches) > 0,
                matches=all_matches,
                total_matches=len(all_matches),
                by_type=by_type,
                overall_confidence=overall_confidence,
                scan_time_ms=scan_time_ms,
                pages_scanned=page_count,
            )

        except Exception as e:
            logger.error(f"Error scanning PDF: {e}")
            return PHIScanResult(
                has_phi=False,
                error=str(e),
            )

    def scan_text(self, text: str) -> list[PHIMatch]:
        """
        Scan raw text for PHI (for testing/validation).

        Args:
            text: Text to scan

        Returns:
            List of detected PHI matches
        """
        matches: list[PHIMatch] = []

        for pattern, compiled in self._compiled_patterns:
            for match in compiled.finditer(text):
                matched_value = match.group(0)
                masked_value = self._mask_value(matched_value, pattern.phi_type)

                confidence = self._determine_confidence(pattern.confidence_weight)

                phi_match = PHIMatch(
                    phi_type=pattern.phi_type,
                    value=masked_value,
                    page=0,
                    position=(0.0, 0.0, 0.0, 0.0),
                    confidence=confidence,
                    pattern_used=pattern.description,
                )
                matches.append(phi_match)

        return matches

    def _scan_text_with_positions(self, text: str, page_num: int, page: Any) -> list[PHIMatch]:
        """
        Scan text and find positions of matches on page.

        Args:
            text: Extracted text from page
            page_num: Page number (0-indexed)
            page: PyMuPDF page object

        Returns:
            List of PHI matches with positions
        """
        matches: list[PHIMatch] = []

        for pattern, compiled in self._compiled_patterns:
            for match in compiled.finditer(text):
                matched_value = match.group(0)
                masked_value = self._mask_value(matched_value, pattern.phi_type)

                confidence = self._determine_confidence(pattern.confidence_weight)

                # Try to find position on page
                # PyMuPDF search returns list of Rect objects
                rects = page.search_for(matched_value)
                if rects:
                    # Use first match position
                    rect = rects[0]
                    position = (rect.x0, rect.y0, rect.x1, rect.y1)
                else:
                    # No position found, use zero
                    position = (0.0, 0.0, 0.0, 0.0)

                phi_match = PHIMatch(
                    phi_type=pattern.phi_type,
                    value=masked_value,
                    page=page_num,
                    position=position,
                    confidence=confidence,
                    pattern_used=pattern.description,
                )
                matches.append(phi_match)

        return matches

    def _mask_value(self, value: str, phi_type: PHIType) -> str:
        """
        Mask sensitive data for security.

        Shows only last 4 characters for most types,
        or masks appropriately for each PHI type.

        Args:
            value: Original matched value
            phi_type: Type of PHI

        Returns:
            Masked value safe for logging/display
        """
        if len(value) <= 4:
            return "*" * len(value)

        # Special masking for different PHI types
        if phi_type == PHIType.SSN:
            # SSN: ***-**-6789
            if "-" in value:
                parts = value.split("-")
                if len(parts) == 3:
                    return f"***-**-{parts[-1]}"
            # Without dashes: *****6789
            return "*" * (len(value) - 4) + value[-4:]

        elif phi_type == PHIType.EMAIL:
            # Email: j***@example.com
            if "@" in value:
                local, domain = value.split("@", 1)
                if len(local) > 1:
                    return f"{local[0]}***@{domain}"
                return f"***@{domain}"

        elif phi_type == PHIType.PHONE or phi_type == PHIType.FAX:
            # Phone: (***) ***-1234
            digits = "".join(c for c in value if c.isdigit())
            if len(digits) >= 4:
                return f"***-***-{digits[-4:]}"

        elif phi_type == PHIType.NAME:
            # Name: J*** D***
            parts = value.split()
            if len(parts) >= 2:
                return " ".join(f"{p[0]}***" if len(p) > 0 else "***" for p in parts)

        # Default: show last 4 characters
        return "*" * (len(value) - 4) + value[-4:]

    def _determine_confidence(self, weight: float) -> Confidence:
        """
        Determine confidence level from pattern weight.

        Args:
            weight: Pattern confidence weight (0.0-1.0)

        Returns:
            Confidence level
        """
        if weight >= 0.85:
            return Confidence.HIGH
        elif weight >= 0.60:
            return Confidence.MEDIUM
        else:
            return Confidence.LOW

    def _count_by_type(self, matches: list[PHIMatch]) -> dict[str, int]:
        """
        Count matches by PHI type.

        Args:
            matches: List of PHI matches

        Returns:
            Dictionary mapping phi_type to count
        """
        counts: dict[str, int] = {}
        for match in matches:
            phi_type = match.phi_type.value
            counts[phi_type] = counts.get(phi_type, 0) + 1
        return counts

    def _calculate_overall_confidence(self, matches: list[PHIMatch]) -> Confidence:
        """
        Calculate overall confidence from all matches.

        Uses highest confidence level found in any match.

        Args:
            matches: List of PHI matches

        Returns:
            Overall confidence level
        """
        if not matches:
            return Confidence.LOW

        # Count confidence levels
        high_count = sum(1 for m in matches if m.confidence == Confidence.HIGH)
        medium_count = sum(1 for m in matches if m.confidence == Confidence.MEDIUM)

        # Overall confidence based on highest confidence matches
        if high_count > 0:
            return Confidence.HIGH
        elif medium_count > 0:
            return Confidence.MEDIUM
        else:
            return Confidence.LOW


# Singleton instance
_phi_scanner: PHIScanner | None = None


def get_phi_scanner() -> PHIScanner:
    """
    Get singleton PHI scanner instance.

    Returns:
        Shared PHIScanner instance
    """
    global _phi_scanner
    if _phi_scanner is None:
        _phi_scanner = PHIScanner()
    return _phi_scanner

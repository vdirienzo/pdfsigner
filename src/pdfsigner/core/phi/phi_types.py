"""
phi_types.py - Data types for PHI detection results

Defines the core data structures used by the PHI scanner:
- Confidence: Detection confidence levels
- PHIMatch: A single PHI detection instance
- PHIScanResult: Aggregated scan results

Author: Homero Thompson del Lago del Terror
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pdfsigner.core.phi.patterns import PHIType


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

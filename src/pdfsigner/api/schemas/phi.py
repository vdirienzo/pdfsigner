"""Schemas for PHI/PII scanning endpoints.

This module contains response models for PHI/PII detection operations:
- PIIMatchResponse: Information about a single PII detection
- PIIScanResponse: Complete scan result with all matches
"""

from pydantic import BaseModel, Field


class PIIMatchResponse(BaseModel):
    """Information about a single PII/PHI match.

    Attributes:
        pii_type: Type of PII detected (ssn, credit_card, email, etc.)
        pii_type_display: Human-readable display name
        redacted_value: Redacted value (e.g., "***-**-1234" for SSN)
        confidence: Detection confidence (0.0-1.0)
        start_pos: Character start position in text
        end_pos: Character end position in text
        page: Page number (0-indexed, null if not from PDF)
        bbox: Bounding box coordinates [x1, y1, x2, y2] (null if not from PDF)
        context: Surrounding text context
    """

    pii_type: str = Field(..., max_length=64)
    pii_type_display: str = Field(..., max_length=255)
    redacted_value: str = Field(..., max_length=255)
    confidence: float
    start_pos: int
    end_pos: int
    page: int | None = None
    bbox: list[float] | None = None
    context: str = Field(default="", max_length=4096)


class PIIScanResponse(BaseModel):
    """Response from PII/PHI scanning operation.

    Attributes:
        filename: Name of scanned file
        has_pii: Whether any PII was detected in the document
        total_matches: Total count of PII instances detected
        risk_score: Overall risk score (0.0-1.0)
        by_type: Dictionary mapping PII type to count
        matches: List of individual PII matches (redacted values)
        scan_time_ms: Time taken for scan in milliseconds
        pages_scanned: Number of pages scanned in document
        error: Error message if scan failed (null on success)
    """

    filename: str = Field(..., max_length=255)
    has_pii: bool
    total_matches: int
    risk_score: float
    by_type: dict[str, int] = Field(default_factory=dict)
    matches: list[PIIMatchResponse] = Field(default_factory=list)
    scan_time_ms: float
    pages_scanned: int = 0
    error: str | None = Field(None, max_length=4096)


# Backwards compatibility aliases
PHIMatchResponse = PIIMatchResponse
PHIScanResponse = PIIScanResponse

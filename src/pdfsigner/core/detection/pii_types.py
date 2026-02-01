"""
PII type definitions and match data structures.

Defines the types of PII that can be detected and the data structure
for storing detection results with confidence scores.
"""

from dataclasses import dataclass
from enum import Enum


class PIIType(str, Enum):
    """Types of Protected Health Information and Personally Identifiable Information."""

    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE = "phone"
    DOB = "date_of_birth"
    MEDICAL_RECORD = "medical_record_number"
    HEALTH_PLAN_ID = "health_plan_id"
    DIAGNOSIS_CODE = "diagnosis_code"
    PRESCRIPTION = "prescription"

    @property
    def display_name(self) -> str:
        """Get human-readable display name."""
        return {
            PIIType.SSN: "Social Security Number",
            PIIType.CREDIT_CARD: "Credit Card Number",
            PIIType.EMAIL: "Email Address",
            PIIType.PHONE: "Phone Number",
            PIIType.DOB: "Date of Birth",
            PIIType.MEDICAL_RECORD: "Medical Record Number",
            PIIType.HEALTH_PLAN_ID: "Health Plan ID",
            PIIType.DIAGNOSIS_CODE: "Diagnosis Code",
            PIIType.PRESCRIPTION: "Prescription",
        }[self]

    @property
    def sensitivity_weight(self) -> float:
        """Get sensitivity weight for risk calculation (0.0-1.0)."""
        return {
            PIIType.SSN: 1.0,
            PIIType.CREDIT_CARD: 1.0,
            PIIType.MEDICAL_RECORD: 0.9,
            PIIType.HEALTH_PLAN_ID: 0.9,
            PIIType.DIAGNOSIS_CODE: 0.85,
            PIIType.PRESCRIPTION: 0.85,
            PIIType.DOB: 0.7,
            PIIType.PHONE: 0.5,
            PIIType.EMAIL: 0.4,
        }[self]


@dataclass
class PIIMatch:
    """
    Represents a detected PII instance in text.

    Attributes:
        pii_type: Type of PII detected
        value: The detected value (may be partially redacted)
        redacted_value: Fully redacted version for display
        confidence: Detection confidence (0.0-1.0)
        start_pos: Character start position in text
        end_pos: Character end position in text
        page: Page number (0-indexed, None if not from PDF)
        bbox: Bounding box coordinates [x1, y1, x2, y2] (None if not from PDF)
        context: Surrounding text context (±20 chars)
    """

    pii_type: PIIType
    value: str
    redacted_value: str
    confidence: float
    start_pos: int
    end_pos: int
    page: int | None = None
    bbox: tuple[float, float, float, float] | None = None
    context: str = ""

    def to_dict(self) -> dict:
        """Convert match to dictionary for serialization."""
        return {
            "pii_type": self.pii_type.value,
            "pii_type_display": self.pii_type.display_name,
            "redacted_value": self.redacted_value,
            "confidence": round(self.confidence, 3),
            "start_pos": self.start_pos,
            "end_pos": self.end_pos,
            "page": self.page,
            "bbox": list(self.bbox) if self.bbox else None,
            "context": self.context,
        }

    def to_redaction_region(
        self,
        fill_color: tuple[float, float, float] = (0, 0, 0),
        replacement_text: str | None = None,
    ) -> "RedactionRegion":
        """Convert PIIMatch to RedactionRegion for redaction."""
        if self.bbox is None or self.page is None:
            raise ValueError("Cannot convert to RedactionRegion: missing bbox or page")

        x0, y0, x1, y1 = self.bbox
        if replacement_text is None:
            replacement_text = self.redacted_value

        return RedactionRegion(
            page=self.page,
            x0=x0,
            y0=y0,
            x1=x1,
            y1=y1,
            fill_color=fill_color,
            replacement_text=replacement_text,
        )


@dataclass
class RedactionRegion:
    """
    A region to be redacted in a PDF.

    Attributes:
        page: Zero-indexed page number
        x0, y0, x1, y1: Bounding box in PDF coordinates (bottom-left origin)
        fill_color: RGB color tuple (0-1 range) for redaction fill
        replacement_text: Optional text to display over redaction
    """

    page: int
    x0: float
    y0: float
    x1: float
    y1: float
    fill_color: tuple[float, float, float] = (0, 0, 0)  # Black
    replacement_text: str | None = None

    def __post_init__(self):
        """Validate coordinates and color."""
        if self.x0 >= self.x1 or self.y0 >= self.y1:
            raise ValueError(f"Invalid coordinates: ({self.x0},{self.y0}) -> ({self.x1},{self.y1})")

        # Validate color values
        for component in self.fill_color:
            if not 0 <= component <= 1:
                raise ValueError(f"Color components must be in range 0-1: {self.fill_color}")

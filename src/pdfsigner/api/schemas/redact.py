"""
Schemas for redaction endpoints.

This module contains request/response models for PDF redaction operations:
- RedactionRegionSchema: Single region to redact
- RedactRegionsRequest: Manual redaction by coordinates
- RedactByPatternRequest: Automatic PII detection and redaction
- RedactionResponse: Result of redaction operation
- PreviewRequest: Request for redaction preview
"""

from pydantic import BaseModel, Field, field_validator


class RedactionRegionSchema(BaseModel):
    """
    A rectangular region to redact in a PDF.

    Attributes:
        page: Zero-indexed page number
        x0: Left X coordinate (PDF coordinate system, bottom-left origin)
        y0: Bottom Y coordinate
        x1: Right X coordinate
        y1: Top Y coordinate
        fill_color: RGB color tuple (0-1 range) for redaction fill
        replacement_text: Optional text to display over redaction (e.g., "[REDACTED]")
    """

    page: int = Field(..., ge=0, description="Zero-indexed page number")
    x0: float = Field(..., description="Left X coordinate")
    y0: float = Field(..., description="Bottom Y coordinate")
    x1: float = Field(..., description="Right X coordinate")
    y1: float = Field(..., description="Top Y coordinate")
    fill_color: tuple[float, float, float] = Field(
        default=(0, 0, 0), description="RGB color for redaction (0-1 range)"
    )
    replacement_text: str | None = Field(
        default=None, description="Optional replacement text to display"
    )

    @field_validator("fill_color")
    @classmethod
    def validate_color(cls, v: tuple[float, float, float]) -> tuple[float, float, float]:
        """Validate color components are in 0-1 range."""
        if len(v) != 3:
            raise ValueError("Color must be RGB tuple with 3 components")
        for component in v:
            if not 0 <= component <= 1:
                raise ValueError(f"Color components must be 0-1, got {v}")
        return v

    @field_validator("x1")
    @classmethod
    def validate_x1(cls, v: float, values) -> float:
        """Ensure x1 > x0."""
        if "x0" in values.data and v <= values.data["x0"]:
            raise ValueError(f"x1 ({v}) must be greater than x0 ({values.data['x0']})")
        return v

    @field_validator("y1")
    @classmethod
    def validate_y1(cls, v: float, values) -> float:
        """Ensure y1 > y0."""
        if "y0" in values.data and v <= values.data["y0"]:
            raise ValueError(f"y1 ({v}) must be greater than y0 ({values.data['y0']})")
        return v


class RedactRegionsRequest(BaseModel):
    """
    Request to redact specific regions in a PDF.

    Attributes:
        regions: List of RedactionRegionSchema objects defining areas to redact
        output_filename: Optional custom filename for redacted PDF
            If not provided, will use input filename with "_redacted" suffix
    """

    regions: list[RedactionRegionSchema] = Field(
        ..., min_length=1, description="Regions to redact (at least one required)"
    )
    output_filename: str | None = Field(
        default=None, description="Custom output filename (optional)"
    )


class RedactByPatternRequest(BaseModel):
    """
    Request to auto-detect and redact PII by type.

    Uses the PII detector to automatically find and redact
    specified types of sensitive information.

    Attributes:
        pii_types: List of PII types to detect and redact
            Valid values: "ssn", "credit_card", "email", "phone", "dob",
            "medical_record_number", "health_plan_id", "diagnosis_code", "prescription"
        min_confidence: Minimum confidence threshold for detection (0.0-1.0)
            Only matches with confidence >= this value will be redacted
        output_filename: Optional custom filename for redacted PDF
    """

    pii_types: list[str] = Field(
        ...,
        min_length=1,
        description="PII types to detect (ssn, credit_card, email, phone, etc.)",
    )
    min_confidence: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Minimum confidence threshold (0.0-1.0)",
    )
    output_filename: str | None = Field(
        default=None, description="Custom output filename (optional)"
    )

    @field_validator("pii_types")
    @classmethod
    def validate_pii_types(cls, v: list[str]) -> list[str]:
        """Validate PII types are recognized."""
        valid_types = {
            "ssn",
            "credit_card",
            "email",
            "phone",
            "dob",
            "date_of_birth",
            "medical_record_number",
            "health_plan_id",
            "diagnosis_code",
            "prescription",
        }
        for pii_type in v:
            if pii_type not in valid_types:
                raise ValueError(
                    f"Invalid PII type '{pii_type}'. Valid types: {', '.join(sorted(valid_types))}"
                )
        return v


class RedactionResponse(BaseModel):
    """
    Response from redaction operation.

    Attributes:
        success: Whether redaction completed successfully
        output_path: Path to redacted PDF file (relative to work directory)
        redaction_count: Number of regions that were redacted
        pages_affected: List of page numbers with redactions (zero-indexed)
        errors: List of error messages if any issues occurred
        download_url: URL to download the redacted PDF
        message: Summary message
    """

    success: bool
    output_path: str | None = None
    redaction_count: int = Field(default=0, ge=0)
    pages_affected: list[int] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    download_url: str | None = None
    message: str | None = None


class PreviewRequest(BaseModel):
    """
    Request for redaction preview.

    Generates a preview image showing redaction regions
    without actually applying them.

    Attributes:
        regions: Regions to preview
        page: Page number to preview (zero-indexed)
        dpi: Resolution for preview image (default: 150)
    """

    regions: list[RedactionRegionSchema] = Field(..., min_length=1)
    page: int = Field(default=0, ge=0, description="Page to preview (zero-indexed)")
    dpi: int = Field(default=150, ge=72, le=300, description="Preview resolution (72-300)")

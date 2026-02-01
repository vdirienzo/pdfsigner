"""Schemas for electronic seal endpoints.

This module contains request/response models for PDF sealing operations:
- OrganizationInfoSchema: Organization details for seal
- SealRequest: Parameters for sealing a PDF document
- SealResponse: Immediate response after seal job submission
- SealJobStatus: Detailed status of a sealing job
- SealValidationResponse: Seal validation results

Electronic seals are for organizations (legal persons) per eIDAS Article 35-40.
"""

from pydantic import BaseModel, Field


class OrganizationInfoSchema(BaseModel):
    """Organization information for electronic seal.

    Attributes:
        name: Organization legal name
        country: ISO 3166-1 alpha-2 country code (e.g., "DE", "FR", "ES")
        organization_id: Organization identifier (VAT, LEI, or other)
        department: Department within organization (optional)
        address: Organization address (optional)
        email: Contact email (optional)
        website: Organization website (optional)
    """

    name: str = Field(..., description="Organization legal name", min_length=1, max_length=200)
    country: str = Field(..., description="ISO 3166-1 alpha-2 country code", pattern="^[A-Z]{2}$")
    organization_id: str = Field(
        "", description="Organization identifier (VAT, LEI, etc.)", max_length=100
    )
    department: str = Field("", description="Department name", max_length=100)
    address: str = Field("", description="Organization address", max_length=500)
    email: str = Field("", description="Contact email", max_length=100)
    website: str = Field("", description="Organization website", max_length=200)


class SealRequest(BaseModel):
    """Request to seal a PDF document.

    Attributes:
        organization: Organization information
        seal_type: Type of electronic seal (basic, advanced, qualified)
        appearance: Visual appearance (invisible, stamp, banner, logo)
        reason: Reason for sealing (e.g., "Official company seal")
        location: Geographic location where sealing occurred
        page: Page number for seal (1-indexed, -1 for last page)
        position: Position in mm from bottom-left [x, y]
        size: Size in mm [width, height]
        include_timestamp: Whether to include trusted timestamp
        tsa_url: Custom TSA URL (uses default if not provided)
        background_color: Background color (hex, e.g., "#1a365d")
        text_color: Text color (hex, e.g., "#ffffff")
    """

    organization: OrganizationInfoSchema
    seal_type: str = Field(
        "advanced",
        description="Seal type: basic, advanced, qualified",
        pattern="^(basic|advanced|qualified)$",
    )
    appearance: str = Field(
        "stamp",
        description="Visual appearance: invisible, stamp, banner, logo",
        pattern="^(invisible|stamp|banner|logo)$",
    )
    reason: str = Field("Organization seal", description="Reason for sealing", max_length=200)
    location: str = Field("", description="Sealing location", max_length=200)
    page: int = Field(1, description="Page number (1-indexed, -1 for last)", ge=-1)
    position: list[float] = Field(
        [50.0, 50.0],
        description="Position in mm from bottom-left [x, y]",
        min_length=2,
        max_length=2,
    )
    size: list[float] = Field(
        [40.0, 40.0], description="Size in mm [width, height]", min_length=2, max_length=2
    )
    include_timestamp: bool = Field(True, description="Include trusted timestamp")
    tsa_url: str = Field("", description="Custom TSA URL (optional)", max_length=500)
    background_color: str = Field(
        "#1a365d", description="Background color (hex)", pattern="^#[0-9a-fA-F]{6}$"
    )
    text_color: str = Field("#ffffff", description="Text color (hex)", pattern="^#[0-9a-fA-F]{6}$")


class SealResponse(BaseModel):
    """Response from seal operation.

    Attributes:
        job_id: Unique identifier for tracking this sealing job
        status: Current job status (usually "pending" on submission)
        organization: Organization name that created the seal
        seal_type: Type of seal applied
        message: Optional informational message
        download_url: URL to download sealed PDF (available when status="completed")
    """

    job_id: str = Field(..., max_length=64)
    status: str = Field(..., max_length=64)
    organization: str = Field(..., max_length=255)
    seal_type: str = Field(..., max_length=64)
    message: str | None = Field(None, max_length=4096)
    download_url: str | None = Field(None, max_length=1024)


class SealJobStatus(BaseModel):
    """Detailed status of a sealing job.

    Attributes:
        job_id: Unique identifier for this job
        status: Current job status (pending, processing, completed, failed)
        filename: Original PDF filename being sealed
        organization: Organization that created the seal
        seal_type: Type of seal being applied
        created_at: ISO 8601 timestamp when job was created
        completed_at: ISO 8601 timestamp when job finished (if applicable)
        error: Error message if status is "failed"
        download_url: URL to download sealed PDF (available when completed)
        signature_id: Signature field identifier in PDF
    """

    job_id: str = Field(..., max_length=64)
    status: str = Field(..., max_length=64)
    filename: str | None = Field(None, max_length=255)
    organization: str = Field(..., max_length=255)
    seal_type: str = Field(..., max_length=64)
    created_at: str = Field(..., max_length=64)
    completed_at: str | None = Field(None, max_length=64)
    error: str | None = Field(None, max_length=4096)
    download_url: str | None = Field(None, max_length=1024)
    signature_id: str | None = Field(None, max_length=64)


class SealValidationResponse(BaseModel):
    """Response from seal validation.

    Attributes:
        valid: Overall validation result
        seal_type: Type of seal detected
        organization: Organization information from seal
        sealed_at: ISO 8601 timestamp when seal was created
        certificate_valid: Whether seal certificate is valid
        timestamp_valid: Whether timestamp is valid (if present)
        integrity_intact: Whether document integrity is intact
        issues: List of validation issues (empty if valid)
    """

    valid: bool
    seal_type: str = Field(..., max_length=64)
    organization: OrganizationInfoSchema
    sealed_at: str = Field(..., max_length=64)
    certificate_valid: bool
    timestamp_valid: bool
    integrity_intact: bool
    issues: list[str] = Field(default_factory=list, description="Validation issues")

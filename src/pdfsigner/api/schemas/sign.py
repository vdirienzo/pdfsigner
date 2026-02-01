"""Schemas for signing endpoints.

This module contains request/response models for PDF signing operations:
- SignRequest: Parameters for signing a PDF document
- SignResponse: Immediate response after signing job submission
- SignJobStatus: Detailed status of a signing job

All visible signature parameters follow pyHanko conventions.
"""

from pydantic import BaseModel, Field


class SignRequest(BaseModel):
    """Request to sign a PDF document.

    Attributes:
        reason: Reason for signing (e.g., "Approval", "Review")
        location: Geographic location where signing occurred
        contact_info: Contact information of the signer (email, phone)
        visible_signature: Whether to add a visible signature stamp on the page
        signature_page: Page placement for visible signature:
            - "first": First page
            - "last": Last page (default)
            - "all": All pages
            - "<number>": Specific page number (1-indexed)
        tsa_url: URL of Time Stamp Authority for timestamping
            If None, uses default TSA from configuration
        embed_ltv: Whether to embed Long-Term Validation data (DSS):
            - Includes OCSP responses
            - Includes CRL data
            - Required for B-LT level
        add_archive_ts: Whether to add archive timestamp for B-LTA level
            Requires embed_ltv=True
    """

    reason: str | None = Field(None, description="Reason for signing")
    location: str | None = Field(None, description="Signing location")
    contact_info: str | None = Field(None, description="Signer contact info")
    visible_signature: bool = Field(False, description="Add visible signature stamp")
    signature_page: str = Field(
        "last", description="Page for signature: first, last, all, or number"
    )
    tsa_url: str | None = Field(None, description="Custom TSA URL (uses default if not set)")
    embed_ltv: bool = Field(True, description="Embed LTV validation info (DSS)")
    add_archive_ts: bool = Field(False, description="Add archive timestamp (B-LTA)")


class SignResponse(BaseModel):
    """Response from signing operation.

    Attributes:
        job_id: Unique identifier for tracking this signing job
        status: Current job status (usually "pending" on submission)
        message: Optional informational message
        download_url: URL to download signed PDF (available when status="completed")
    """

    job_id: str
    status: str
    message: str | None = None
    download_url: str | None = None


class SignJobStatus(BaseModel):
    """Detailed status of a signing job.

    Attributes:
        job_id: Unique identifier for this job
        status: Current job status (pending, processing, completed, failed)
        filename: Original PDF filename being signed
        created_at: ISO 8601 timestamp when job was created
        completed_at: ISO 8601 timestamp when job finished (if applicable)
        error: Error message if status is "failed"
        download_url: URL to download signed PDF (available when completed)
        pades_level: Achieved PAdES conformance level (B-B, B-T, B-LT, B-LTA)
    """

    job_id: str
    status: str
    filename: str | None = None
    created_at: str
    completed_at: str | None = None
    error: str | None = None
    download_url: str | None = None
    pades_level: str | None = None

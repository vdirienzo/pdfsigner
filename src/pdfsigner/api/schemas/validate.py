"""Schemas for validation endpoints.

This module contains response models for PDF signature validation:
- SignatureInfo: Details about a single signature
- LTVInfo: Long-Term Validation information (DSS, OCSP, CRL, archive timestamps)
- ValidateResponse: Validation result for a single PDF
- BatchValidateResponse: Results for multiple PDFs

Validation follows ETSI EN 319 122 standards for PAdES validation.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class SignatureInfo(BaseModel):
    """Information about a single digital signature.

    Attributes:
        signer_name: Common name from certificate subject
        signer_email: Email address from certificate (if present)
        signing_time: Claimed signing time from signature
        reason: Reason for signing (if provided)
        location: Location where signing occurred (if provided)
        is_valid: Whether the signature is cryptographically valid
        validation_errors: List of validation errors/warnings
        has_timestamp: Whether signature includes a timestamp token
        timestamp_time: Time from TSA timestamp (if present)
        pades_level: PAdES conformance level (B-B, B-T, B-LT, B-LTA)
    """

    signer_name: str | None = None
    signer_email: str | None = None
    signing_time: datetime | None = None
    reason: str | None = None
    location: str | None = None
    is_valid: bool
    validation_errors: list[str] = Field(default_factory=list)
    has_timestamp: bool = False
    timestamp_time: datetime | None = None
    pades_level: str = "B-B"


class LTVInfo(BaseModel):
    """Long-Term Validation information from Document Security Store (DSS).

    Attributes:
        has_dss: Whether PDF contains a DSS dictionary
        has_ocsp: Whether DSS contains OCSP responses
        has_crl: Whether DSS contains CRL data
        has_archive_timestamp: Whether PDF has archive timestamps (B-LTA)
        archive_timestamp_count: Number of archive timestamps found
    """

    has_dss: bool = False
    has_ocsp: bool = False
    has_crl: bool = False
    has_archive_timestamp: bool = False
    archive_timestamp_count: int = 0


class ValidateResponse(BaseModel):
    """Response from PDF signature validation.

    Attributes:
        filename: Name of validated PDF file
        is_signed: Whether PDF contains any signatures
        is_valid: Whether all signatures are valid
        signature_count: Number of signatures found
        signatures: Detailed information for each signature
        ltv_info: LTV/DSS information (if present)
        pades_level: Highest PAdES level achieved across all signatures
        errors: List of validation errors (for unsigned or invalid PDFs)
    """

    filename: str
    is_signed: bool
    is_valid: bool
    signature_count: int
    signatures: list[SignatureInfo] = Field(default_factory=list)
    ltv_info: LTVInfo | None = None
    pades_level: str = "unknown"
    errors: list[str] = Field(default_factory=list)


class BatchValidateResponse(BaseModel):
    """Response from batch validation of multiple PDFs.

    Attributes:
        total: Total number of PDFs validated
        valid: Number of PDFs with all valid signatures
        invalid: Number of PDFs with invalid or missing signatures
        results: Individual validation results for each PDF
    """

    total: int
    valid: int
    invalid: int
    results: list[ValidateResponse]

"""
Compliance API schemas.

Pydantic models for HIPAA compliance monitoring API endpoints.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class ComplianceCheckResponse(BaseModel):
    """Response model for a single compliance check."""

    name: str = Field(..., max_length=255, description="Name of the compliance check")
    category: str = Field(
        ..., max_length=64, description="Category (encryption, audit_controls, etc.)"
    )
    status: str = Field(
        ..., max_length=64, description="Status (compliant, warning, non_compliant)"
    )
    hipaa_reference: str = Field(
        ..., max_length=64, description="HIPAA regulation reference (e.g., §164.312(b))"
    )
    description: str = Field(..., max_length=4096, description="Brief description of the control")
    details: str = Field(..., max_length=4096, description="Detailed status information")
    remediation: str | None = Field(
        None, max_length=4096, description="How to fix if non-compliant"
    )
    last_checked: datetime = Field(..., description="When the check was performed")

    model_config = {
        "json_schema_extra": {
            "example": {
                "name": "PDF Encryption",
                "category": "encryption",
                "status": "compliant",
                "hipaa_reference": "§164.312(a)(2)(iv)",
                "description": "Encryption and decryption capability",
                "details": "AES-256 encryption enabled (HIPAA compliant)",
                "remediation": None,
                "last_checked": "2026-02-01T10:30:00Z",
            }
        }
    }


class ComplianceReportResponse(BaseModel):
    """Response model for full compliance report."""

    checks: list[ComplianceCheckResponse] = Field(..., description="List of all compliance checks")
    overall_status: str = Field(
        ..., max_length=64, description="Overall status (compliant, warning, non_compliant)"
    )
    compliant_count: int = Field(..., description="Number of compliant checks")
    warning_count: int = Field(..., description="Number of warnings")
    non_compliant_count: int = Field(..., description="Number of non-compliant checks")
    is_hipaa_compliant: bool = Field(
        ..., description="True if all checks are compliant (no non-compliant checks)"
    )
    generated_at: datetime = Field(..., description="When the report was generated")

    model_config = {
        "json_schema_extra": {
            "example": {
                "checks": [
                    {
                        "name": "PDF Encryption",
                        "category": "encryption",
                        "status": "compliant",
                        "hipaa_reference": "§164.312(a)(2)(iv)",
                        "description": "Encryption and decryption capability",
                        "details": "AES-256 encryption enabled (HIPAA compliant)",
                        "remediation": None,
                        "last_checked": "2026-02-01T10:30:00Z",
                    }
                ],
                "overall_status": "compliant",
                "compliant_count": 7,
                "warning_count": 0,
                "non_compliant_count": 0,
                "is_hipaa_compliant": True,
                "generated_at": "2026-02-01T10:30:00Z",
            }
        }
    }


class ReportGenerationRequest(BaseModel):
    """Request model for generating compliance reports."""

    format: str = Field(
        ..., description="Report format (pdf, json, csv, cef)", pattern="^(pdf|json|csv|cef)$"
    )
    standards: list[str] = Field(
        default=["all"], description="Standards to include in report (default: all)"
    )
    include_evidence: bool = Field(default=True, description="Include evidence in report")
    include_recommendations: bool = Field(
        default=True, description="Include recommendations in report"
    )
    executive_summary: bool = Field(
        default=True, description="Include executive summary (PDF only)"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "format": "pdf",
                "standards": ["all"],
                "include_evidence": True,
                "include_recommendations": True,
                "executive_summary": True,
            }
        }
    }


class GeneratedReportResponse(BaseModel):
    """Response model for generated compliance report."""

    report_id: str = Field(..., description="Unique report identifier")
    format: str = Field(..., description="Report format (pdf, json, csv, cef)")
    size_bytes: int = Field(..., description="Report size in bytes")
    generated_at: datetime = Field(..., description="When the report was generated")
    checksum: str = Field(..., description="SHA-256 checksum for integrity verification")
    download_url: str = Field(..., description="URL to download the report")

    model_config = {
        "json_schema_extra": {
            "example": {
                "report_id": "20260201_103000_pdf",
                "format": "pdf",
                "size_bytes": 45678,
                "generated_at": "2026-02-01T10:30:00Z",
                "checksum": "a1b2c3d4e5f6...",
                "download_url": "/api/v1/compliance/report/20260201_103000_pdf",
            }
        }
    }


class AvailableStandardsResponse(BaseModel):
    """Response model for available compliance standards."""

    standards: list[str] = Field(..., description="List of available standards")

    model_config = {
        "json_schema_extra": {"example": {"standards": ["HIPAA", "NIST", "eIDAS", "GDPR"]}}
    }


__all__ = [
    "ComplianceCheckResponse",
    "ComplianceReportResponse",
    "ReportGenerationRequest",
    "GeneratedReportResponse",
    "AvailableStandardsResponse",
]

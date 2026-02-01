"""
evidence.py - API schemas for SOC 2 evidence collection

Pydantic models for evidence collection and SOC 2 reporting endpoints.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class EvidenceRequest(BaseModel):
    """Request model for evidence collection."""

    category: str | None = Field(
        None,
        max_length=64,
        description="Filter by evidence category (cc1, cc2, etc.). If None, collect all.",
    )
    period_start: datetime = Field(..., description="Start of observation period")
    period_end: datetime = Field(..., description="End of observation period")

    model_config = {
        "json_schema_extra": {
            "example": {
                "category": "cc6",
                "period_start": "2026-01-01T00:00:00Z",
                "period_end": "2026-03-31T23:59:59Z",
            }
        }
    }


class EvidenceItemResponse(BaseModel):
    """Response model for a single evidence item."""

    id: str = Field(..., max_length=64, description="Unique evidence identifier")
    category: str = Field(..., max_length=64, description="SOC 2 category (cc1-cc9)")
    evidence_type: str = Field(..., max_length=64, description="Type of evidence")
    title: str = Field(..., max_length=255, description="Evidence title")
    description: str = Field(..., max_length=4096, description="Evidence description")
    collected_at: datetime = Field(..., description="Collection timestamp")
    period_start: datetime = Field(..., description="Period start")
    period_end: datetime = Field(..., description="Period end")
    file_path: str | None = Field(None, max_length=1024, description="Path to evidence file")
    checksum: str | None = Field(None, max_length=64, description="SHA-256 checksum")

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "category": "cc6",
                "evidence_type": "access_log",
                "title": "Access Logs (2026-01-01 to 2026-03-31)",
                "description": "System access logs showing 1234 events from 45 users",
                "collected_at": "2026-02-01T10:30:00Z",
                "period_start": "2026-01-01T00:00:00Z",
                "period_end": "2026-03-31T23:59:59Z",
                "file_path": None,
                "checksum": None,
            }
        }
    }


class EvidenceCollectionResponse(BaseModel):
    """Response model for evidence collection."""

    evidence_items: list[EvidenceItemResponse] = Field(..., description="Collected evidence items")
    summary: dict = Field(..., description="Collection summary statistics")
    period_start: datetime = Field(..., description="Period start")
    period_end: datetime = Field(..., description="Period end")
    collected_at: datetime = Field(..., description="Collection timestamp")

    model_config = {
        "json_schema_extra": {
            "example": {
                "evidence_items": [
                    {
                        "id": "123e4567-e89b-12d3-a456-426614174000",
                        "category": "cc6",
                        "evidence_type": "access_log",
                        "title": "Access Logs (2026-01-01 to 2026-03-31)",
                        "description": "System access logs showing 1234 events from 45 users",
                        "collected_at": "2026-02-01T10:30:00Z",
                        "period_start": "2026-01-01T00:00:00Z",
                        "period_end": "2026-03-31T23:59:59Z",
                        "file_path": None,
                        "checksum": None,
                    }
                ],
                "summary": {
                    "total_evidence": 5,
                    "by_category": {"cc5": 1, "cc6": 2, "cc7": 1, "cc9": 1},
                    "by_type": {"access_log": 1, "audit_log": 1, "config_snapshot": 1},
                },
                "period_start": "2026-01-01T00:00:00Z",
                "period_end": "2026-03-31T23:59:59Z",
                "collected_at": "2026-02-01T10:30:00Z",
            }
        }
    }


class SOC2ReportRequest(BaseModel):
    """Request model for SOC 2 report generation."""

    period_start: datetime = Field(..., description="Start of observation period")
    period_end: datetime = Field(..., description="End of observation period")
    include_evidence: bool = Field(default=True, description="Include detailed evidence in report")

    model_config = {
        "json_schema_extra": {
            "example": {
                "period_start": "2026-01-01T00:00:00Z",
                "period_end": "2026-03-31T23:59:59Z",
                "include_evidence": True,
            }
        }
    }


class ControlAssessmentResponse(BaseModel):
    """Response model for control assessment."""

    control_id: str = Field(..., max_length=64, description="Control ID (e.g., CC6.1)")
    control_name: str = Field(..., max_length=255, description="Control name")
    category: str = Field(..., max_length=64, description="SOC 2 category")
    status: str = Field(..., max_length=64, description="Implementation status")
    description: str = Field(..., max_length=4096, description="Control description")
    implementation: str = Field(..., max_length=4096, description="How it's implemented")
    evidence_ids: list[str] = Field(default_factory=list, description="Supporting evidence IDs")
    gaps: list[str] = Field(default_factory=list, description="Identified gaps")
    notes: str = Field(default="", max_length=4096, description="Additional notes")

    model_config = {
        "json_schema_extra": {
            "example": {
                "control_id": "CC6.1",
                "control_name": "Logical Access Controls",
                "category": "cc6",
                "status": "implemented",
                "description": "Restrict logical access through use of access control software",
                "implementation": "PDFSigner implements RBAC with certificate-based authentication",
                "evidence_ids": ["123e4567-e89b-12d3-a456-426614174000"],
                "gaps": [],
                "notes": "",
            }
        }
    }


class SOC2ReportResponse(BaseModel):
    """Response model for SOC 2 report."""

    period_start: datetime = Field(..., description="Period start")
    period_end: datetime = Field(..., description="Period end")
    generated_at: datetime = Field(..., description="Generation timestamp")
    controls: list[ControlAssessmentResponse] = Field(..., description="Control assessments")
    summary: dict = Field(..., description="Executive summary")
    recommendations: list[str] = Field(default_factory=list, description="Recommendations")

    model_config = {
        "json_schema_extra": {
            "example": {
                "period_start": "2026-01-01T00:00:00Z",
                "period_end": "2026-03-31T23:59:59Z",
                "generated_at": "2026-02-01T10:30:00Z",
                "controls": [
                    {
                        "control_id": "CC6.1",
                        "control_name": "Logical Access Controls",
                        "category": "cc6",
                        "status": "implemented",
                        "description": "Restrict logical access",
                        "implementation": "RBAC with certificates",
                        "evidence_ids": ["123e4567-e89b-12d3-a456-426614174000"],
                        "gaps": [],
                        "notes": "",
                    }
                ],
                "summary": {
                    "total_controls": 9,
                    "implemented": 8,
                    "partial": 1,
                    "not_implemented": 0,
                    "coverage_percentage": 94.4,
                },
                "recommendations": ["CC7.1: No automated vulnerability scanning in production"],
            }
        }
    }


class SOC2ExportResponse(BaseModel):
    """Response model for SOC 2 export (ZIP)."""

    filename: str = Field(..., max_length=255, description="Generated ZIP filename")
    size_bytes: int = Field(..., description="File size in bytes")
    generated_at: datetime = Field(..., description="Generation timestamp")
    checksum: str = Field(..., max_length=64, description="SHA-256 checksum")
    download_url: str = Field(..., max_length=1024, description="Download URL")

    model_config = {
        "json_schema_extra": {
            "example": {
                "filename": "soc2_report_20260201_103000.zip",
                "size_bytes": 245678,
                "generated_at": "2026-02-01T10:30:00Z",
                "checksum": "a1b2c3d4e5f6...",
                "download_url": (
                    "/api/v1/compliance/evidence/export/soc2_report_20260201_103000.zip"
                ),
            }
        }
    }


__all__ = [
    "EvidenceRequest",
    "EvidenceItemResponse",
    "EvidenceCollectionResponse",
    "SOC2ReportRequest",
    "ControlAssessmentResponse",
    "SOC2ReportResponse",
    "SOC2ExportResponse",
]

"""
Vulnerability management schemas.

Request/response models for vulnerability management endpoints:
- Vulnerability information
- Scan triggers
- Status updates
- Reporting

NIST: RA-5 - Vulnerability management
"""

from datetime import datetime

from pydantic import BaseModel, Field


class VulnerabilityResponse(BaseModel):
    """Vulnerability information response."""

    id: str = Field(..., max_length=64, description="Unique vulnerability ID")
    title: str = Field(..., max_length=500, description="Vulnerability title")
    description: str = Field(..., max_length=4096, description="Detailed description")
    severity: str = Field(
        ..., max_length=64, description="Severity level (info, low, medium, high, critical)"
    )
    status: str = Field(
        ...,
        max_length=64,
        description="Status (open, in_progress, resolved, accepted, false_positive)",
    )
    source: str = Field(
        ..., max_length=64, description="Discovery source (semgrep, pip_audit, manual, pentest)"
    )
    file_path: str | None = Field(None, max_length=1024, description="Affected file path")
    line_number: int | None = Field(None, description="Line number in file")
    cwe_id: str | None = Field(None, max_length=64, description="CWE identifier (e.g., CWE-79)")
    cvss_score: float | None = Field(None, description="CVSS v3 score (0.0-10.0)")
    discovered_at: datetime = Field(..., description="Discovery timestamp")
    resolved_at: datetime | None = Field(None, description="Resolution timestamp")
    assignee: str | None = Field(None, max_length=255, description="Assigned user")
    remediation: str | None = Field(None, max_length=4096, description="Remediation guidance")

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "title": "SQL Injection vulnerability",
                "description": "User input is directly concatenated into SQL query",
                "severity": "high",
                "status": "open",
                "source": "semgrep",
                "file_path": "src/pdfsigner/api/routes/users.py",
                "line_number": 142,
                "cwe_id": "CWE-89",
                "cvss_score": 8.5,
                "discovered_at": "2024-01-15T10:30:00Z",
                "resolved_at": None,
                "assignee": "security-team",
                "remediation": "Use parameterized queries instead of string concatenation",
            }
        }
    }


class VulnerabilityCreate(BaseModel):
    """Manual vulnerability creation request."""

    title: str = Field(..., min_length=1, max_length=500, description="Vulnerability title")
    description: str = Field(..., min_length=1, description="Detailed description")
    severity: str = Field(
        ...,
        pattern="^(info|low|medium|high|critical)$",
        description="Severity level",
    )
    file_path: str | None = Field(None, description="Affected file path")
    line_number: int | None = Field(None, ge=1, description="Line number")
    cwe_id: str | None = Field(None, pattern="^CWE-[0-9]+$", description="CWE identifier")
    cvss_score: float | None = Field(None, ge=0.0, le=10.0, description="CVSS score")
    assignee: str | None = Field(None, description="Assign to user")
    remediation: str | None = Field(None, description="Remediation guidance")

    model_config = {
        "json_schema_extra": {
            "example": {
                "title": "Hardcoded credentials in configuration",
                "description": "Database password is hardcoded in config.py",
                "severity": "critical",
                "file_path": "src/pdfsigner/config/settings.py",
                "line_number": 42,
                "cwe_id": "CWE-798",
                "cvss_score": 9.8,
                "assignee": "security-team",
                "remediation": "Move credentials to environment variables or secret manager",
            }
        }
    }


class VulnerabilityUpdate(BaseModel):
    """Vulnerability update request."""

    status: str | None = Field(
        None,
        pattern="^(open|in_progress|resolved|accepted|false_positive)$",
        description="New status",
    )
    assignee: str | None = Field(None, description="Assign to user")
    notes: str | None = Field(None, description="Update notes")

    model_config = {
        "json_schema_extra": {
            "example": {
                "status": "in_progress",
                "assignee": "john.doe",
                "notes": "Working on fix, ETA 2 days",
            }
        }
    }


class VulnerabilityListResponse(BaseModel):
    """Vulnerability list response with pagination."""

    vulnerabilities: list[VulnerabilityResponse] = Field(..., description="List of vulnerabilities")
    total: int = Field(..., description="Total vulnerabilities matching filters")

    model_config = {
        "json_schema_extra": {
            "example": {
                "vulnerabilities": [
                    {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "title": "SQL Injection",
                        "description": "User input in SQL query",
                        "severity": "high",
                        "status": "open",
                        "source": "semgrep",
                        "file_path": "src/api/routes.py",
                        "line_number": 142,
                        "cwe_id": "CWE-89",
                        "cvss_score": 8.5,
                        "discovered_at": "2024-01-15T10:30:00Z",
                        "resolved_at": None,
                        "assignee": "security-team",
                        "remediation": "Use parameterized queries",
                    }
                ],
                "total": 1,
            }
        }
    }


class ScanRequest(BaseModel):
    """Vulnerability scan request."""

    scan_type: str = Field(
        "all",
        pattern="^(all|semgrep|pip_audit)$",
        description="Type of scan to run",
    )
    path: str | None = Field(None, description="Path to scan (for Semgrep)")
    semgrep_config: str = Field(
        "auto",
        description="Semgrep config (auto, p/security-audit, p/owasp-top-ten)",
    )
    auto_import: bool = Field(
        True,
        description="Automatically import results to vulnerability tracker",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "scan_type": "all",
                "path": "src/",
                "semgrep_config": "p/security-audit",
                "auto_import": True,
            }
        }
    }


class ScanResponse(BaseModel):
    """Vulnerability scan response."""

    scan_type: str = Field(..., description="Type of scan executed")
    vulnerabilities_found: int = Field(..., description="Number of vulnerabilities found")
    imported: bool = Field(..., description="Whether results were imported to tracker")
    import_stats: dict | None = Field(None, description="Import statistics")

    model_config = {
        "json_schema_extra": {
            "example": {
                "scan_type": "all",
                "vulnerabilities_found": 12,
                "imported": True,
                "import_stats": {
                    "total_scanned": 12,
                    "new": 5,
                    "updated": 3,
                    "resolved": 0,
                },
            }
        }
    }


class VulnerabilityReport(BaseModel):
    """Vulnerability report response."""

    timestamp: datetime = Field(..., description="Report generation timestamp")
    summary: dict = Field(..., description="Summary statistics")
    by_severity: dict = Field(..., description="Counts by severity")
    by_status: dict = Field(..., description="Counts by status")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score (0-100)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "timestamp": "2024-01-20T15:30:00Z",
                "summary": {
                    "total_vulnerabilities": 45,
                    "open": 12,
                    "resolved": 30,
                    "high_critical_open": 3,
                    "overdue_30_days": 5,
                },
                "by_severity": {
                    "critical": 2,
                    "high": 5,
                    "medium": 15,
                    "low": 18,
                    "info": 5,
                },
                "by_status": {
                    "open": 8,
                    "in_progress": 4,
                    "resolved": 30,
                    "accepted": 2,
                    "false_positive": 1,
                },
                "risk_score": 45,
            }
        }
    }


__all__ = [
    "VulnerabilityResponse",
    "VulnerabilityCreate",
    "VulnerabilityUpdate",
    "VulnerabilityListResponse",
    "ScanRequest",
    "ScanResponse",
    "VulnerabilityReport",
]

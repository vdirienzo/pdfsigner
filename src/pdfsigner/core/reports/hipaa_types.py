"""
hipaa_types.py - HIPAA report data types and configuration

Pure data definitions for HIPAA compliance reports.
Dataclasses, enums, and configuration used by the report generator.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from pdfsigner.core.types.report_format import ReportFormat


class ReportSection(str, Enum):
    """Sections available in HIPAA report."""

    SUMMARY = "summary"
    USER_ACCESS = "user_access"
    ENCRYPTION_USAGE = "encryption_usage"
    EMERGENCY_ACCESS = "emergency_access"
    PHI_ACCESS = "phi_access"
    AUDIT_INTEGRITY = "audit_integrity"


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    start_date: datetime
    end_date: datetime
    sections: list[ReportSection] = field(default_factory=list)
    format: ReportFormat = ReportFormat.PDF
    include_details: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "start_date": self.start_date.isoformat(),
            "end_date": self.end_date.isoformat(),
            "sections": [s.value for s in self.sections],
            "format": self.format.value,
            "include_details": self.include_details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReportConfig":
        """Create from dictionary."""
        return cls(
            start_date=datetime.fromisoformat(data["start_date"]),
            end_date=datetime.fromisoformat(data["end_date"]),
            sections=[ReportSection(s) for s in data.get("sections", [])],
            format=ReportFormat(data.get("format", "pdf")),
            include_details=data.get("include_details", True),
        )


@dataclass
class UserAccessSummary:
    """Summary of user access for the report period."""

    total_users: int
    active_users: int
    logins: int
    failed_logins: int
    sessions_created: int
    sessions_terminated: int
    unique_documents_accessed: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UserAccessSummary":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class EncryptionSummary:
    """Summary of encryption operations."""

    documents_encrypted: int
    documents_decrypted: int
    encryption_method: str  # aes256
    phi_documents_encrypted: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EncryptionSummary":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class EmergencyAccessSummary:
    """Summary of emergency access (break-glass)."""

    requests_made: int
    requests_approved: int
    requests_denied: int
    documents_accessed: int
    unique_users: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EmergencyAccessSummary":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class PHIAccessSummary:
    """Summary of PHI detection and access."""

    documents_scanned: int
    documents_with_phi: int
    phi_types_detected: dict[str, int]  # {ssn: 5, email: 10, ...}
    blocked_operations: int  # Operations blocked due to PHI

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PHIAccessSummary":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class HIPAAReport:
    """Complete HIPAA audit report."""

    report_id: str
    title: str
    organization: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime

    # Sections
    user_access: UserAccessSummary | None = None
    encryption: EncryptionSummary | None = None
    emergency_access: EmergencyAccessSummary | None = None
    phi_access: PHIAccessSummary | None = None

    # Compliance status
    compliance_status: str = "unknown"  # compliant, warning, non_compliant
    compliance_checks: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        # Convert datetime objects
        data["generated_at"] = self.generated_at.isoformat()
        data["period_start"] = self.period_start.isoformat()
        data["period_end"] = self.period_end.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HIPAAReport":
        """Create from dictionary."""
        # Convert datetime strings
        data["generated_at"] = datetime.fromisoformat(data["generated_at"])
        data["period_start"] = datetime.fromisoformat(data["period_start"])
        data["period_end"] = datetime.fromisoformat(data["period_end"])

        # Convert nested dataclasses
        if data.get("user_access"):
            data["user_access"] = UserAccessSummary.from_dict(data["user_access"])
        if data.get("encryption"):
            data["encryption"] = EncryptionSummary.from_dict(data["encryption"])
        if data.get("emergency_access"):
            data["emergency_access"] = EmergencyAccessSummary.from_dict(data["emergency_access"])
        if data.get("phi_access"):
            data["phi_access"] = PHIAccessSummary.from_dict(data["phi_access"])

        return cls(**data)

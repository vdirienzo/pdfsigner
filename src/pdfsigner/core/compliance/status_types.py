"""
status_types.py - Compliance status data types

Author: Homero Thompson del Lago del Terror

Type definitions for HIPAA compliance status monitoring:
- ComplianceStatus: Status levels (compliant/warning/non_compliant/unknown)
- ComplianceCategory: HIPAA control categories
- ComplianceCheck: Individual compliance check result
- ComplianceReport: Full compliance status report
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ComplianceStatus(str, Enum):
    """Status levels for compliance checks."""

    COMPLIANT = "compliant"  # Green - all good
    WARNING = "warning"  # Yellow - needs attention
    NON_COMPLIANT = "non_compliant"  # Red - action required
    UNKNOWN = "unknown"  # Gray - cannot determine


class ComplianceCategory(str, Enum):
    """Categories of HIPAA compliance controls."""

    ENCRYPTION = "encryption"
    AUDIT_CONTROLS = "audit_controls"
    ACCESS_CONTROL = "access_control"
    SESSION_MANAGEMENT = "session_management"
    TEMP_FILE_SECURITY = "temp_file_security"
    PHI_DETECTION = "phi_detection"
    EMERGENCY_ACCESS = "emergency_access"


@dataclass
class ComplianceCheck:
    """Result of a single compliance check."""

    name: str
    category: ComplianceCategory
    status: ComplianceStatus
    hipaa_reference: str  # e.g., "§164.312(a)(2)(iv)"
    description: str
    details: str
    remediation: str | None = None  # How to fix if non-compliant
    last_checked: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        Returns:
            Dictionary with all fields, converting enum and datetime to strings
        """
        data = asdict(self)
        data["category"] = self.category.value
        data["status"] = self.status.value
        data["last_checked"] = self.last_checked.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ComplianceCheck":
        """
        Create ComplianceCheck from dictionary.

        Args:
            data: Dictionary with check fields

        Returns:
            ComplianceCheck instance
        """
        # Convert enum strings
        if "category" in data:
            data["category"] = ComplianceCategory(data["category"])
        if "status" in data:
            data["status"] = ComplianceStatus(data["status"])

        # Convert datetime string
        if "last_checked" in data and isinstance(data["last_checked"], str):
            data["last_checked"] = datetime.fromisoformat(data["last_checked"])

        return cls(**data)


@dataclass
class ComplianceReport:
    """Full compliance status report."""

    checks: list[ComplianceCheck]
    overall_status: ComplianceStatus
    compliant_count: int
    warning_count: int
    non_compliant_count: int
    generated_at: datetime = field(default_factory=datetime.now)

    @property
    def is_hipaa_compliant(self) -> bool:
        """
        Check if system is HIPAA compliant.

        Returns:
            True if no non-compliant checks, False otherwise
        """
        return self.non_compliant_count == 0

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        Returns:
            Dictionary with all report fields
        """
        return {
            "checks": [c.to_dict() for c in self.checks],
            "overall_status": self.overall_status.value,
            "compliant_count": self.compliant_count,
            "warning_count": self.warning_count,
            "non_compliant_count": self.non_compliant_count,
            "is_hipaa_compliant": self.is_hipaa_compliant,
            "generated_at": self.generated_at.isoformat(),
        }

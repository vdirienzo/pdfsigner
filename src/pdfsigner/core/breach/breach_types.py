"""
breach_types.py - Data breach type definitions

Defines breach incident data structures for GDPR and HIPAA compliance.
"""

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class BreachSeverity(str, Enum):
    """Breach severity levels."""

    LOW = "low"  # Minimal risk to individuals
    MEDIUM = "medium"  # Moderate risk, requires notification
    HIGH = "high"  # High risk, immediate action required
    CRITICAL = "critical"  # Severe risk, urgent escalation


class BreachStatus(str, Enum):
    """Breach incident status."""

    DETECTED = "detected"  # Breach detected, investigation starting
    INVESTIGATING = "investigating"  # Under investigation
    CONTAINED = "contained"  # Breach contained, cleanup in progress
    RESOLVED = "resolved"  # Breach resolved
    NOTIFIED = "notified"  # Authorities/users notified


class BreachType(str, Enum):
    """Types of data breach incidents."""

    MASS_EXPORT = "mass_data_export"  # Bulk data export detected
    FAILED_AUTH = "multiple_failed_auth"  # Multiple failed login attempts
    BULK_PHI_ACCESS = "bulk_phi_access"  # Mass PHI/PII access
    EMERGENCY_ACCESS = "emergency_access_used"  # Emergency access triggered
    UNUSUAL_HOURS = "unusual_access_hours"  # Access outside normal hours
    PRIVILEGE_ESCALATION = "privilege_escalation"  # Unauthorized privilege change


@dataclass
class BreachIncident:
    """
    Data breach incident record.

    Represents a detected or reported data breach incident with
    full context for investigation and notification.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    breach_type: BreachType = BreachType.MASS_EXPORT
    severity: BreachSeverity = BreachSeverity.MEDIUM
    status: BreachStatus = BreachStatus.DETECTED

    # Timestamps
    detected_at: datetime = field(default_factory=datetime.now)
    resolved_at: datetime | None = None
    notified_at: datetime | None = None

    # Description
    description: str = ""

    # Impact
    affected_users: int = 0
    affected_records: int = 0

    # Source information
    source_ip: str | None = None
    user_id: str | None = None

    # Additional context
    metadata: dict[str, Any] = field(default_factory=dict)

    # Status history
    status_history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        Returns:
            Dictionary with all fields, converting enums and datetimes to strings
        """
        data = asdict(self)
        data["breach_type"] = self.breach_type.value
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        data["detected_at"] = self.detected_at.isoformat()
        data["resolved_at"] = self.resolved_at.isoformat() if self.resolved_at else None
        data["notified_at"] = self.notified_at.isoformat() if self.notified_at else None
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BreachIncident":
        """
        Create BreachIncident from dictionary.

        Args:
            data: Dictionary with incident fields

        Returns:
            BreachIncident instance
        """
        # Convert enum strings
        if "breach_type" in data:
            data["breach_type"] = BreachType(data["breach_type"])
        if "severity" in data:
            data["severity"] = BreachSeverity(data["severity"])
        if "status" in data:
            data["status"] = BreachStatus(data["status"])

        # Convert datetime strings
        for field_name in ["detected_at", "resolved_at", "notified_at"]:
            if field_name in data and isinstance(data[field_name], str):
                data[field_name] = datetime.fromisoformat(data[field_name])

        return cls(**data)

    def update_status(self, new_status: BreachStatus, note: str = "") -> None:
        """
        Update incident status and record in history.

        Args:
            new_status: New status to set
            note: Optional note about status change
        """
        old_status = self.status
        self.status = new_status

        # Add to history
        self.status_history.append(
            {
                "from_status": old_status.value,
                "to_status": new_status.value,
                "timestamp": datetime.now(UTC).isoformat(),
                "note": note,
            }
        )

        # Update resolved/notified timestamps
        if new_status == BreachStatus.RESOLVED:
            self.resolved_at = datetime.now(UTC)
        elif new_status == BreachStatus.NOTIFIED:
            self.notified_at = datetime.now(UTC)

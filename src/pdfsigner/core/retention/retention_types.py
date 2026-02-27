"""
retention_types.py - Data retention type definitions

Data models for retention policies and results.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class RetentionTarget(str, Enum):
    """What type of data the policy applies to."""

    AUDIT_LOGS = "audit_logs"
    TEMP_FILES = "temp_files"
    SESSION_DATA = "session_data"
    REPORTS = "reports"


class RetentionAction(str, Enum):
    """What to do when retention period expires."""

    DELETE = "delete"  # Permanently delete
    ARCHIVE = "archive"  # Move to archive storage
    ANONYMIZE = "anonymize"  # Remove PII, keep statistics


@dataclass
class RetentionPolicy:
    """Defines a data retention policy."""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    target: RetentionTarget = RetentionTarget.TEMP_FILES
    retention_days: int = 30  # How long to keep data
    action: RetentionAction = RetentionAction.DELETE
    enabled: bool = True
    hipaa_reference: str = ""  # e.g., "SS164.530(j)" for 6 year requirement
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "target": self.target.value,
            "retention_days": self.retention_days,
            "action": self.action.value,
            "enabled": self.enabled,
            "hipaa_reference": self.hipaa_reference,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RetentionPolicy":
        """Create policy from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            target=RetentionTarget(data["target"]),
            retention_days=data["retention_days"],
            action=RetentionAction(data["action"]),
            enabled=data.get("enabled", True),
            hipaa_reference=data.get("hipaa_reference", ""),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if data.get("created_at")
                else datetime.now(UTC)
            ),
        )


@dataclass
class RetentionResult:
    """Result of a retention cleanup operation."""

    policy_id: str
    policy_name: str
    target: RetentionTarget
    action: RetentionAction
    items_processed: int
    items_deleted: int
    items_archived: int
    items_failed: int
    started_at: datetime
    completed_at: datetime
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        """Calculate operation duration in seconds."""
        return (self.completed_at - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "target": self.target.value,
            "action": self.action.value,
            "items_processed": self.items_processed,
            "items_deleted": self.items_deleted,
            "items_archived": self.items_archived,
            "items_failed": self.items_failed,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
        }

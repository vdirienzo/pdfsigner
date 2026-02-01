"""
evidence_types.py - SOC 2 evidence type definitions

Defines evidence categories, types, and data structures for SOC 2 Type II
compliance evidence collection.

SOC 2 Trust Services Criteria:
- CC1: Control Environment
- CC2: Communication and Information
- CC3: Risk Assessment
- CC4: Monitoring Activities
- CC5: Control Activities
- CC6: Logical and Physical Access Controls
- CC7: System Operations
- CC8: Change Management
- CC9: Risk Mitigation
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class EvidenceCategory(str, Enum):
    """
    SOC 2 Trust Services Criteria categories.

    Maps to Common Criteria (CC) from the AICPA Trust Services framework.
    """

    CC1_CONTROL_ENVIRONMENT = "cc1"
    CC2_COMMUNICATION = "cc2"
    CC3_RISK_ASSESSMENT = "cc3"
    CC4_MONITORING = "cc4"
    CC5_CONTROL_ACTIVITIES = "cc5"
    CC6_LOGICAL_ACCESS = "cc6"
    CC7_SYSTEM_OPERATIONS = "cc7"
    CC8_CHANGE_MANAGEMENT = "cc8"
    CC9_RISK_MITIGATION = "cc9"


class EvidenceType(str, Enum):
    """
    Types of evidence that can be collected.

    Each type corresponds to a specific kind of documentation or audit artifact.
    """

    ACCESS_LOG = "access_log"
    AUDIT_LOG = "audit_log"
    CONFIG_SNAPSHOT = "config_snapshot"
    USER_ACCESS_REVIEW = "user_access_review"
    INCIDENT_LOG = "incident_log"
    CHANGE_RECORD = "change_record"
    POLICY_DOCUMENT = "policy_document"
    SCAN_RESULT = "scan_result"
    SESSION_LOG = "session_log"
    ENCRYPTION_LOG = "encryption_log"


@dataclass
class Evidence:
    """
    Single piece of evidence for SOC 2 compliance.

    Attributes:
        id: Unique evidence identifier (UUID)
        category: SOC 2 Trust Services Criteria category
        evidence_type: Type of evidence (log, config, etc.)
        title: Human-readable title
        description: Detailed description of what this evidence shows
        collected_at: Timestamp when evidence was collected
        period_start: Start of observation period
        period_end: End of observation period
        data: Evidence data (structured dict)
        file_path: Optional path to evidence file
        metadata: Additional metadata (tags, collector info, etc.)
        checksum: SHA-256 checksum for integrity verification
    """

    id: str
    category: EvidenceCategory
    evidence_type: EvidenceType
    title: str
    description: str
    collected_at: datetime
    period_start: datetime
    period_end: datetime
    data: dict[str, Any]
    file_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    checksum: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """
        Convert evidence to dictionary.

        Returns:
            Dictionary representation suitable for JSON serialization
        """
        return {
            "id": self.id,
            "category": self.category.value,
            "evidence_type": self.evidence_type.value,
            "title": self.title,
            "description": self.description,
            "collected_at": self.collected_at.isoformat(),
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "data": self.data,
            "file_path": self.file_path,
            "metadata": self.metadata,
            "checksum": self.checksum,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        """
        Create evidence from dictionary.

        Args:
            data: Dictionary with evidence fields

        Returns:
            Evidence instance
        """
        return cls(
            id=data["id"],
            category=EvidenceCategory(data["category"]),
            evidence_type=EvidenceType(data["evidence_type"]),
            title=data["title"],
            description=data["description"],
            collected_at=datetime.fromisoformat(data["collected_at"]),
            period_start=datetime.fromisoformat(data["period_start"]),
            period_end=datetime.fromisoformat(data["period_end"]),
            data=data["data"],
            file_path=data.get("file_path"),
            metadata=data.get("metadata", {}),
            checksum=data.get("checksum"),
        )


@dataclass
class EvidenceCollection:
    """
    Collection of evidence for a specific period.

    Groups multiple evidence items together for a compliance report.
    """

    period_start: datetime
    period_end: datetime
    collected_at: datetime
    evidence_items: list[Evidence] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence to collection."""
        self.evidence_items.append(evidence)

    def get_by_category(self, category: EvidenceCategory) -> list[Evidence]:
        """Get all evidence for a specific category."""
        return [e for e in self.evidence_items if e.category == category]

    def get_by_type(self, evidence_type: EvidenceType) -> list[Evidence]:
        """Get all evidence of a specific type."""
        return [e for e in self.evidence_items if e.evidence_type == evidence_type]

    def to_dict(self) -> dict[str, Any]:
        """Convert collection to dictionary."""
        return {
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "collected_at": self.collected_at.isoformat(),
            "evidence_items": [e.to_dict() for e in self.evidence_items],
            "summary": self.summary,
        }


__all__ = [
    "EvidenceCategory",
    "EvidenceType",
    "Evidence",
    "EvidenceCollection",
]

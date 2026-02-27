"""
emergency_types.py - Emergency access data models

Data models for emergency access (break-glass) procedures.
HIPAA: SS164.312(a)(2)(ii) - Emergency access procedure.
"""

from datetime import UTC, datetime
from enum import Enum


class EmergencyAccessStatus(str, Enum):
    """Status of emergency access request."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


class EmergencyAccessRequest:
    """
    Emergency access request with approval workflow.

    Represents a request for temporary elevated access during emergencies.
    Requires admin approval unless auto-approve is configured.
    """

    def __init__(
        self,
        id: str,
        requester_id: str,
        reason: str,
        status: EmergencyAccessStatus,
        requested_at: datetime,
        approved_by: str | None = None,
        approved_at: datetime | None = None,
        expires_at: datetime | None = None,
        revoked_by: str | None = None,
        revoked_at: datetime | None = None,
        documents_accessed: list[str] | None = None,
    ):
        """
        Initialize emergency access request.

        Args:
            id: Unique request ID (UUID)
            requester_id: User ID requesting emergency access
            reason: Justification for emergency access
            status: Current status of the request
            requested_at: Timestamp when request was created
            approved_by: User ID who approved the request
            approved_at: Timestamp when request was approved
            expires_at: Timestamp when access expires
            revoked_by: User ID who revoked the access
            revoked_at: Timestamp when access was revoked
            documents_accessed: List of document paths accessed using this emergency access
        """
        self.id = id
        self.requester_id = requester_id
        self.reason = reason
        self.status = status
        self.requested_at = requested_at
        self.approved_by = approved_by
        self.approved_at = approved_at
        self.expires_at = expires_at
        self.revoked_by = revoked_by
        self.revoked_at = revoked_at
        self.documents_accessed = documents_accessed or []

    @property
    def is_active(self) -> bool:
        """Check if emergency access is currently active."""
        if self.status != EmergencyAccessStatus.APPROVED:
            return False
        if self.expires_at and datetime.now(UTC) > self.expires_at:
            return False
        return True

    @property
    def is_expired(self) -> bool:
        """Check if emergency access has expired."""
        return self.expires_at is not None and datetime.now(UTC) > self.expires_at

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "requester_id": self.requester_id,
            "reason": self.reason,
            "status": self.status.value,
            "requested_at": self.requested_at.isoformat(),
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_by": self.revoked_by,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "documents_accessed": self.documents_accessed,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EmergencyAccessRequest":
        """Create request from dictionary."""

        def parse_datetime(val: str | None) -> datetime | None:
            return datetime.fromisoformat(val) if val else None

        return cls(
            id=data["id"],
            requester_id=data["requester_id"],
            reason=data["reason"],
            status=EmergencyAccessStatus(data["status"]),
            requested_at=datetime.fromisoformat(data["requested_at"]),
            approved_by=data.get("approved_by"),
            approved_at=parse_datetime(data.get("approved_at")),
            expires_at=parse_datetime(data.get("expires_at")),
            revoked_by=data.get("revoked_by"),
            revoked_at=parse_datetime(data.get("revoked_at")),
            documents_accessed=data.get("documents_accessed", []),
        )

    def __repr__(self) -> str:
        return (
            f"EmergencyAccessRequest(id={self.id}, requester={self.requester_id}, "
            f"status={self.status.value})"
        )

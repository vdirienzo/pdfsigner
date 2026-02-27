"""
session_types.py - Session data models for healthcare compliance

Data models for user session management.
HIPAA: SS164.312(a)(2)(iii) - Automatic logoff.
"""

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass
class Session:
    """
    User session for healthcare compliance.

    Tracks user activity with automatic timeout and expiration.
    """

    id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    ip_address: str | None = None
    user_agent: str | None = None

    @property
    def is_active(self) -> bool:
        """Check if session is still active (not expired)."""
        return datetime.now(UTC) < self.expires_at

    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return not self.is_active

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        """Create session from dictionary."""
        return cls(
            id=data["id"],
            user_id=data["user_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            last_activity=datetime.fromisoformat(data["last_activity"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
        )

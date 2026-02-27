"""
key_types.py - Key type definitions for cryptographic key management.

Provides enums and dataclasses used across key management modules.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class KeyType(str, Enum):
    """Type of cryptographic key."""

    SYMMETRIC = "symmetric"
    ASYMMETRIC_PRIVATE = "asymmetric_private"
    ASYMMETRIC_PUBLIC = "asymmetric_public"
    HMAC = "hmac"


class KeyStatus(str, Enum):
    """Status of a cryptographic key."""

    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class KeyInfo:
    """Information about a cryptographic key."""

    key_id: str
    key_type: KeyType
    algorithm: str
    status: KeyStatus
    created_at: datetime
    expires_at: datetime | None
    rotated_from: str | None  # Previous key ID if rotated
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "algorithm": self.algorithm,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotated_from": self.rotated_from,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KeyInfo":
        """Create from dictionary."""
        return cls(
            key_id=data["key_id"],
            key_type=KeyType(data["key_type"]),
            algorithm=data["algorithm"],
            status=KeyStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=(
                datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None
            ),
            rotated_from=data.get("rotated_from"),
            metadata=data.get("metadata", {}),
        )

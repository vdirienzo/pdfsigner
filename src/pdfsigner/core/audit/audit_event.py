"""
audit_event.py - Audit event data structures

Author: Homero Thompson del Lago del Terror

Defines audit event types and data structure for security
and compliance tracking in PDFSigner.
"""

import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class AuditEventType(Enum):
    """Types of audit events tracked in the system."""

    SIGN_SUCCESS = "sign_success"
    SIGN_FAILURE = "sign_failure"
    VALIDATE_SUCCESS = "validate_success"
    VALIDATE_FAILURE = "validate_failure"
    CONFIG_CHANGE = "config_change"
    TOKEN_LOGIN = "token_login"  # nosec B105 - not a password, event type identifier
    TOKEN_LOGOUT = "token_logout"  # nosec B105 - not a password, event type identifier
    CERTIFICATE_SELECTED = "certificate_selected"


@dataclass
class AuditEvent:
    """
    Audit event with complete context.

    Represents a security or operational event in PDFSigner for audit trail.
    Serializable to JSON for storage in JSON Lines format.
    """

    event_type: AuditEventType
    timestamp: datetime = field(default_factory=datetime.now)
    event_id: str = field(default_factory=lambda: str(uuid4()))

    # Context
    user_cn: str | None = None  # Certificate CN if available
    hostname: str = field(default_factory=lambda: socket.gethostname())

    # Document info
    document_path: str | None = None
    document_hash_sha256: str | None = None

    # Certificate info
    certificate_serial: str | None = None
    certificate_issuer: str | None = None

    # Result
    status: str = "SUCCESS"  # SUCCESS, FAILURE, ERROR
    error_message: str | None = None

    # Additional details
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        Returns:
            Dictionary with all fields, converting enum and datetime to strings
        """
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["timestamp"] = self.timestamp.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEvent":
        """
        Create AuditEvent from dictionary.

        Args:
            data: Dictionary with event fields

        Returns:
            AuditEvent instance
        """
        # Convert event_type string to enum
        if "event_type" in data:
            data["event_type"] = AuditEventType(data["event_type"])

        # Convert timestamp string to datetime
        if "timestamp" in data and isinstance(data["timestamp"], str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])

        return cls(**data)

"""
user_model.py - User and role models for HIPAA compliance

Defines user entities with unique identification for audit trails.
HIPAA: §164.312(a)(2)(i) - Unique user identification
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class UserRole(str, Enum):
    """User roles for RBAC."""

    VIEWER = "viewer"  # Can view and validate documents
    SIGNER = "signer"  # Can sign documents
    ADMIN = "admin"  # Full administrative access
    AUDITOR = "auditor"  # Can view audit logs
    EMERGENCY = "emergency"  # Emergency access role


class UserStatus(str, Enum):
    """User account status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    PENDING = "pending"


@dataclass
class Department:
    """Department/organizational unit."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    code: str = ""  # Short code (e.g., "HR", "IT", "MED")
    description: str = ""
    parent_id: str | None = None  # For hierarchical departments
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "code": self.code,
            "description": self.description,
            "parent_id": self.parent_id,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Department":
        """Create from dictionary."""
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", ""),
            code=data.get("code", ""),
            description=data.get("description", ""),
            parent_id=data.get("parent_id"),
            created_at=created_at or datetime.now(UTC),
        )


@dataclass
class User:
    """
    User entity for unique identification.

    Each user has a unique ID that is used in audit trails
    to track who performed what actions (HIPAA requirement).
    """

    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    username: str = ""
    display_name: str = ""
    email: str = ""

    # Role and access
    role: UserRole = UserRole.VIEWER
    department_id: str | None = None

    # Status
    status: UserStatus = UserStatus.ACTIVE

    # Timestamps
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_login_at: datetime | None = None

    # Security
    failed_login_attempts: int = 0
    locked_until: datetime | None = None
    password_changed_at: datetime | None = None

    # Certificate binding (PKCS#11)
    certificate_serial: str | None = None
    certificate_issuer: str | None = None
    certificate_cn: str | None = None  # Common Name from certificate

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        """Check if user is active and not locked."""
        if self.status != UserStatus.ACTIVE:
            return False
        if self.locked_until and self.locked_until > datetime.now(UTC):
            return False
        return True

    @property
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == UserRole.ADMIN

    def lock(self, duration_minutes: int = 30) -> None:
        """Lock user account."""
        from datetime import timedelta

        self.status = UserStatus.LOCKED
        self.locked_until = datetime.now(UTC) + timedelta(minutes=duration_minutes)
        self.updated_at = datetime.now(UTC)

    def unlock(self) -> None:
        """Unlock user account."""
        self.status = UserStatus.ACTIVE
        self.locked_until = None
        self.failed_login_attempts = 0
        self.updated_at = datetime.now(UTC)

    def record_login(self, success: bool) -> None:
        """Record login attempt."""
        if success:
            self.last_login_at = datetime.now(UTC)
            self.failed_login_attempts = 0
        else:
            self.failed_login_attempts += 1
            # Auto-lock after 5 failed attempts
            if self.failed_login_attempts >= 5:
                self.lock(duration_minutes=30)
        self.updated_at = datetime.now(UTC)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name,
            "email": self.email,
            "role": self.role.value,
            "department_id": self.department_id,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "failed_login_attempts": self.failed_login_attempts,
            "locked_until": self.locked_until.isoformat() if self.locked_until else None,
            "password_changed_at": self.password_changed_at.isoformat()
            if self.password_changed_at
            else None,
            "certificate_serial": self.certificate_serial,
            "certificate_issuer": self.certificate_issuer,
            "certificate_cn": self.certificate_cn,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "User":
        """Create user from dictionary."""

        def parse_datetime(val: str | datetime | None) -> datetime | None:
            if val is None:
                return None
            if isinstance(val, datetime):
                return val
            return datetime.fromisoformat(val)

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            username=data.get("username", ""),
            display_name=data.get("display_name", ""),
            email=data.get("email", ""),
            role=UserRole(data.get("role", "viewer")),
            department_id=data.get("department_id"),
            status=UserStatus(data.get("status", "active")),
            created_at=parse_datetime(data.get("created_at")) or datetime.now(UTC),
            updated_at=parse_datetime(data.get("updated_at")) or datetime.now(UTC),
            last_login_at=parse_datetime(data.get("last_login_at")),
            failed_login_attempts=data.get("failed_login_attempts", 0),
            locked_until=parse_datetime(data.get("locked_until")),
            password_changed_at=parse_datetime(data.get("password_changed_at")),
            certificate_serial=data.get("certificate_serial"),
            certificate_issuer=data.get("certificate_issuer"),
            certificate_cn=data.get("certificate_cn"),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_certificate(
        cls,
        serial: str,
        issuer: str,
        common_name: str,
        email: str | None = None,
    ) -> "User":
        """
        Create user from certificate information.

        Used for automatic user creation on first certificate use.
        """
        return cls(
            username=common_name.lower().replace(" ", "."),
            display_name=common_name,
            email=email or "",
            role=UserRole.SIGNER,
            certificate_serial=serial,
            certificate_issuer=issuer,
            certificate_cn=common_name,
        )

    def __str__(self) -> str:
        return f"User({self.username}, role={self.role.value}, status={self.status.value})"

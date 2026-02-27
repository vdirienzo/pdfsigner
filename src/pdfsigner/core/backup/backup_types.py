"""
backup_types.py - Type definitions for backup and recovery.

Defines enums and data classes used across the backup module.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class BackupType(str, Enum):
    """Types of backups that can be created."""

    FULL = "full"  # Everything
    CONFIG = "config"  # Configuration only
    AUDIT = "audit"  # Audit logs only
    DATABASE = "database"  # All databases


class BackupStatus(str, Enum):
    """Status of a backup operation."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class BackupMetadata:
    """Metadata about a backup."""

    backup_id: str = field(default_factory=lambda: str(uuid4()))
    backup_type: BackupType = BackupType.FULL
    status: BackupStatus = BackupStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None
    size_bytes: int = 0
    file_count: int = 0
    encrypted: bool = False
    backup_path: str = ""
    error: str | None = None

    # Included items
    includes_config: bool = True
    includes_audit: bool = True
    includes_databases: bool = True

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Returns:
            Dictionary representation of backup metadata
        """
        return {
            "backup_id": self.backup_id,
            "backup_type": self.backup_type.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "size_bytes": self.size_bytes,
            "file_count": self.file_count,
            "encrypted": self.encrypted,
            "backup_path": self.backup_path,
            "error": self.error,
            "includes_config": self.includes_config,
            "includes_audit": self.includes_audit,
            "includes_databases": self.includes_databases,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BackupMetadata":
        """
        Create BackupMetadata from dictionary.

        Args:
            data: Dictionary with backup metadata fields

        Returns:
            BackupMetadata instance
        """
        return cls(
            backup_id=data["backup_id"],
            backup_type=BackupType(data["backup_type"]),
            status=BackupStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            completed_at=datetime.fromisoformat(data["completed_at"])
            if data.get("completed_at")
            else None,
            size_bytes=data.get("size_bytes", 0),
            file_count=data.get("file_count", 0),
            encrypted=data.get("encrypted", False),
            backup_path=data.get("backup_path", ""),
            error=data.get("error"),
            includes_config=data.get("includes_config", True),
            includes_audit=data.get("includes_audit", True),
            includes_databases=data.get("includes_databases", True),
        )

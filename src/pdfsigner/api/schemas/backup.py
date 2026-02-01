"""Backup management schemas.

This module contains data models for backup and recovery operations:
- Backup creation requests and responses
- Backup listing and metadata
- Restore operations

All schemas are based on Pydantic BaseModel for validation and serialization.
"""

from datetime import datetime

from pydantic import BaseModel, Field

from pdfsigner.core.backup import BackupMetadata, BackupType


class BackupCreateRequest(BaseModel):
    """Request to create a new backup.

    Attributes:
        backup_type: Type of backup (full, config, audit, database)
        encrypt: Whether to encrypt the backup
        password: Password for encryption (required if encrypt=True)
    """

    backup_type: BackupType = Field(
        default=BackupType.FULL,
        description="Type of backup to create",
    )
    encrypt: bool = Field(default=False, description="Whether to encrypt backup")
    password: str | None = Field(
        default=None, max_length=255, description="Password for encryption"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "backup_type": "full",
                "encrypt": True,
                "password": "secure_password_123",
            }
        }
    }


class BackupResponse(BaseModel):
    """Backup information response.

    Attributes:
        backup_id: Unique backup identifier
        backup_type: Type of backup
        status: Current backup status
        created_at: When backup was created
        completed_at: When backup completed (if finished)
        size_bytes: Size of backup file in bytes
        file_count: Number of files in backup
        encrypted: Whether backup is encrypted
        backup_path: Path to backup file
        error: Error message if backup failed
        includes_config: Whether config was backed up
        includes_audit: Whether audit logs were backed up
        includes_databases: Whether databases were backed up
    """

    backup_id: str = Field(..., max_length=64, description="Backup ID")
    backup_type: str = Field(..., max_length=64, description="Backup type")
    status: str = Field(..., max_length=64, description="Backup status")
    created_at: datetime = Field(..., description="Creation timestamp")
    completed_at: datetime | None = Field(None, description="Completion timestamp")
    size_bytes: int = Field(..., description="Backup size in bytes")
    file_count: int = Field(..., description="Number of files")
    encrypted: bool = Field(..., description="Whether backup is encrypted")
    backup_path: str = Field(..., max_length=1024, description="Path to backup file")
    error: str | None = Field(None, max_length=4096, description="Error message if failed")
    includes_config: bool = Field(..., description="Config included")
    includes_audit: bool = Field(..., description="Audit logs included")
    includes_databases: bool = Field(..., description="Databases included")

    @classmethod
    def from_metadata(cls, metadata: BackupMetadata) -> "BackupResponse":
        """
        Create BackupResponse from BackupMetadata.

        Args:
            metadata: BackupMetadata object

        Returns:
            BackupResponse with all backup details
        """
        return cls(
            backup_id=metadata.backup_id,
            backup_type=metadata.backup_type.value,
            status=metadata.status.value,
            created_at=metadata.created_at,
            completed_at=metadata.completed_at,
            size_bytes=metadata.size_bytes,
            file_count=metadata.file_count,
            encrypted=metadata.encrypted,
            backup_path=metadata.backup_path,
            error=metadata.error,
            includes_config=metadata.includes_config,
            includes_audit=metadata.includes_audit,
            includes_databases=metadata.includes_databases,
        )

    model_config = {
        "json_schema_extra": {
            "example": {
                "backup_id": "550e8400-e29b-41d4-a716-446655440000",
                "backup_type": "full",
                "status": "completed",
                "created_at": "2026-02-01T10:00:00",
                "completed_at": "2026-02-01T10:05:00",
                "size_bytes": 10485760,
                "file_count": 42,
                "encrypted": True,
                "backup_path": "/home/user/.local/share/pdfsigner/backups/backup.tar.gz.enc",
                "error": None,
                "includes_config": True,
                "includes_audit": True,
                "includes_databases": True,
            }
        }
    }


class BackupListResponse(BaseModel):
    """Response for listing backups.

    Attributes:
        backups: List of available backups
        total: Total number of backups
    """

    backups: list[BackupResponse] = Field(..., description="List of backups")
    total: int = Field(..., description="Total backup count")


class BackupRestoreRequest(BaseModel):
    """Request to restore from a backup.

    Attributes:
        backup_id: ID of backup to restore
        password: Password if backup is encrypted
        restore_config: Whether to restore configuration
        restore_audit: Whether to restore audit logs
        restore_databases: Whether to restore databases
    """

    backup_id: str = Field(..., max_length=64, description="Backup ID to restore")
    password: str | None = Field(
        default=None, max_length=255, description="Password for encrypted backup"
    )
    restore_config: bool = Field(default=True, description="Restore configuration")
    restore_audit: bool = Field(default=True, description="Restore audit logs")
    restore_databases: bool = Field(default=True, description="Restore databases")

    model_config = {
        "json_schema_extra": {
            "example": {
                "backup_id": "550e8400-e29b-41d4-a716-446655440000",
                "password": "secure_password_123",
                "restore_config": True,
                "restore_audit": True,
                "restore_databases": True,
            }
        }
    }


class BackupRestoreResponse(BaseModel):
    """Response for backup restoration.

    Attributes:
        success: Whether restoration succeeded
        message: Status message
        backup_id: ID of restored backup
    """

    success: bool = Field(..., description="Whether restore succeeded")
    message: str = Field(..., max_length=4096, description="Status message")
    backup_id: str = Field(..., max_length=64, description="Restored backup ID")


class BackupDeleteResponse(BaseModel):
    """Response for backup deletion.

    Attributes:
        success: Whether deletion succeeded
        message: Status message
        backup_id: ID of deleted backup
    """

    success: bool = Field(..., description="Whether delete succeeded")
    message: str = Field(..., max_length=4096, description="Status message")
    backup_id: str = Field(..., max_length=64, description="Deleted backup ID")

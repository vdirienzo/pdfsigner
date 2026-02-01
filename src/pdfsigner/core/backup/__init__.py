"""
Backup and Recovery module for PDFSigner.

This module provides backup and recovery functionality to comply with
HIPAA §164.308(a)(7) - Contingency plan requirements.

Exports:
    - BackupType: Enum of backup types
    - BackupStatus: Enum of backup status
    - BackupMetadata: Backup metadata dataclass
    - BackupManager: Main backup manager
    - get_backup_manager: Get singleton instance
    - restore_backup: Convenience function for restoration
"""

from pdfsigner.core.backup.backup_manager import (
    BackupManager,
    BackupMetadata,
    BackupStatus,
    BackupType,
    get_backup_manager,
    restore_backup,
)

__all__ = [
    "BackupType",
    "BackupStatus",
    "BackupMetadata",
    "BackupManager",
    "get_backup_manager",
    "restore_backup",
]

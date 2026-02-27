"""
Backup and Recovery module for PDFSigner.

This module provides backup and recovery functionality to comply with
HIPAA S164.308(a)(7) - Contingency plan requirements.

Exports:
    - BackupType: Enum of backup types
    - BackupStatus: Enum of backup status
    - BackupMetadata: Backup metadata dataclass
    - BackupManager: Main backup manager
    - BackupStorage: Storage layer for backup I/O
    - get_backup_manager: Get singleton instance
    - restore_backup: Convenience function for restoration
"""

from pdfsigner.core.backup.backup_manager import (
    BackupManager,
    get_backup_manager,
    restore_backup,
)
from pdfsigner.core.backup.backup_storage import BackupStorage
from pdfsigner.core.backup.backup_types import (
    BackupMetadata,
    BackupStatus,
    BackupType,
)

__all__ = [
    "BackupType",
    "BackupStatus",
    "BackupMetadata",
    "BackupManager",
    "BackupStorage",
    "get_backup_manager",
    "restore_backup",
]

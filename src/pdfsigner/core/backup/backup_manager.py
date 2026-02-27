"""
backup_manager.py - Backup orchestration for HIPAA compliance.

Author: Homero Thompson del Lago del Terror

Implements backup and recovery procedures per HIPAA S164.308(a)(7)
Contingency plan requirements. Delegates storage operations to BackupStorage.
"""

import atexit
import json
import tarfile
import threading
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.backup.backup_storage import BackupStorage
from pdfsigner.core.backup.backup_types import (
    BackupMetadata,
    BackupStatus,
    BackupType,
)


class BackupManager:
    """Manages backups and recovery for PDFSigner."""

    def __init__(self, backup_dir: Path | None = None):
        """
        Initialize BackupManager.

        Args:
            backup_dir: Directory to store backups (default: ~/.local/share/pdfsigner/backups)
        """
        if backup_dir is None:
            backup_dir = Path.home() / ".local" / "share" / "pdfsigner" / "backups"

        backup_dir.mkdir(parents=True, exist_ok=True)

        config_dir = Path.home() / ".config" / "pdfsigner"
        data_dir = Path.home() / ".local" / "share" / "pdfsigner"

        self.storage = BackupStorage(
            backup_dir=backup_dir,
            config_dir=config_dir,
            data_dir=data_dir,
        )

        self._timer: threading.Timer | None = None
        self._running = False
        self._lock = threading.Lock()

        atexit.register(self.stop)

    # --- Properties for backward compatibility with tests ---

    @property
    def backup_dir(self) -> Path:
        """Backup directory path."""
        return self.storage.backup_dir

    @backup_dir.setter
    def backup_dir(self, value: Path) -> None:
        self.storage.backup_dir = value

    @property
    def _config_dir(self) -> Path:
        """Config directory path."""
        return self.storage._config_dir

    @_config_dir.setter
    def _config_dir(self, value: Path) -> None:
        self.storage._config_dir = value

    @property
    def _data_dir(self) -> Path:
        """Data directory path."""
        return self.storage._data_dir

    @_data_dir.setter
    def _data_dir(self, value: Path) -> None:
        self.storage._data_dir = value

    # --- Backup orchestration ---

    def create_backup(
        self,
        backup_type: BackupType = BackupType.FULL,
        encrypt: bool = False,
        password: str | None = None,
    ) -> BackupMetadata:
        """
        Create a new backup.

        Args:
            backup_type: Type of backup to create
            encrypt: Whether to encrypt the backup
            password: Password for encryption (required if encrypt=True)

        Returns:
            BackupMetadata with backup information

        Raises:
            ValueError: If encryption requested but password not provided
        """
        if encrypt and not password:
            raise ValueError("Password required for encrypted backup")

        metadata = BackupMetadata(
            backup_type=backup_type,
            encrypted=encrypt,
            includes_config=backup_type in (BackupType.FULL, BackupType.CONFIG),
            includes_audit=backup_type in (BackupType.FULL, BackupType.AUDIT),
            includes_databases=backup_type in (BackupType.FULL, BackupType.DATABASE),
        )

        # Generate backup filename
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        backup_name = f"pdfsigner_backup_{backup_type.value}_{timestamp}"
        backup_path = self.backup_dir / f"{backup_name}.tar.gz"

        metadata.status = BackupStatus.IN_PROGRESS
        metadata.backup_path = str(backup_path)

        try:
            with tarfile.open(backup_path, "w:gz") as tar:
                file_count = 0

                if metadata.includes_config:
                    file_count += self.storage.backup_config(tar)

                if metadata.includes_audit:
                    file_count += self.storage.backup_audit(tar)

                if metadata.includes_databases:
                    file_count += self.storage.backup_databases(tar)

                # Add metadata file
                metadata_json = json.dumps(metadata.to_dict(), indent=2)
                self.storage.add_string_to_tar(tar, "backup_metadata.json", metadata_json)
                file_count += 1

                metadata.file_count = file_count

            # Get backup size
            metadata.size_bytes = backup_path.stat().st_size

            # Encrypt if requested
            if encrypt and password:
                encrypted_path = self.storage.encrypt_backup(backup_path, password)
                backup_path.unlink()  # Remove unencrypted
                metadata.backup_path = str(encrypted_path)
                metadata.size_bytes = encrypted_path.stat().st_size

                # Save metadata sidecar for encrypted backups
                metadata_path = encrypted_path.with_suffix(".meta.json")
                metadata_path.write_text(json.dumps(metadata.to_dict(), indent=2))

            metadata.status = BackupStatus.COMPLETED
            metadata.completed_at = datetime.now(UTC)

            logger.info(
                f"Backup created: {metadata.backup_id} "
                f"({metadata.size_bytes} bytes, {metadata.file_count} files)"
            )

            self._log_backup_to_audit(metadata)

        except Exception as e:
            metadata.status = BackupStatus.FAILED
            metadata.error = str(e)
            logger.error(f"Backup failed: {e}")

        return metadata

    def restore_backup(
        self,
        backup_path: Path,
        password: str | None = None,
        restore_config: bool = True,
        restore_audit: bool = True,
        restore_databases: bool = True,
    ) -> bool:
        """
        Restore from a backup file.

        Args:
            backup_path: Path to backup file
            password: Password if backup is encrypted
            restore_config: Whether to restore configuration
            restore_audit: Whether to restore audit logs
            restore_databases: Whether to restore databases

        Returns:
            True if restore succeeded, False otherwise
        """
        try:
            original_path = backup_path
            temp_decrypted = None

            # Decrypt if encrypted
            if backup_path.suffix == ".enc":
                if not password:
                    raise ValueError("Password required for encrypted backup")
                backup_path = self.storage.decrypt_backup(backup_path, password)
                temp_decrypted = backup_path

            with tarfile.open(backup_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.startswith("config/") and restore_config:
                        rel_path = member.name[7:]  # Remove "config/" prefix
                        target = self._config_dir / rel_path
                        target.parent.mkdir(parents=True, exist_ok=True)

                        extracted = tar.extractfile(member)
                        if extracted:
                            target.write_bytes(extracted.read())

                    elif member.name.startswith("audit/") and restore_audit:
                        rel_path = member.name[6:]  # Remove "audit/" prefix
                        target = self._data_dir / "audit" / rel_path
                        target.parent.mkdir(parents=True, exist_ok=True)

                        extracted = tar.extractfile(member)
                        if extracted:
                            target.write_bytes(extracted.read())

                    elif member.name.startswith("databases/") and restore_databases:
                        db_name = member.name[10:]  # Remove "databases/" prefix
                        target = self._config_dir / db_name
                        target.parent.mkdir(parents=True, exist_ok=True)

                        extracted = tar.extractfile(member)
                        if extracted:
                            target.write_bytes(extracted.read())

            # Cleanup temporary decrypted file
            if temp_decrypted:
                temp_decrypted.unlink()

            logger.info(f"Backup restored: {original_path}")
            return True

        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False

    def list_backups(self) -> list[BackupMetadata]:
        """
        List all available backups.

        Returns:
            List of BackupMetadata for all backups, sorted by date (newest first)
        """
        return self.storage.list_backups()

    def delete_backup(self, backup_id: str) -> bool:
        """
        Delete a backup by ID.

        Args:
            backup_id: ID of backup to delete

        Returns:
            True if backup was deleted, False otherwise
        """
        return self.storage.delete_backup(backup_id)

    # --- Audit logging ---

    def _log_backup_to_audit(self, metadata: BackupMetadata) -> None:
        """
        Log backup operation to audit trail.

        Args:
            metadata: Backup metadata to log
        """
        try:
            from pdfsigner.core.audit import AuditEvent, AuditEventType, get_audit_logger

            audit = get_audit_logger()
            event = AuditEvent(
                event_type=AuditEventType.SYSTEM_BACKUP,
                details={
                    "backup_id": metadata.backup_id,
                    "backup_type": metadata.backup_type.value,
                    "size_bytes": metadata.size_bytes,
                    "encrypted": metadata.encrypted,
                },
            )
            audit.log_event(event)
        except Exception as e:
            logger.warning(f"Failed to log backup to audit: {e}")

    # --- Scheduling ---

    def start(self, interval_hours: int = 24) -> None:
        """
        Start scheduled backups.

        Args:
            interval_hours: Hours between automatic backups
        """
        if self._running:
            return

        self._running = True
        self._schedule_next(interval_hours)
        logger.info(f"Backup scheduler started (interval: {interval_hours}h)")

    def stop(self) -> None:
        """Stop scheduled backups."""
        self._running = False
        if self._timer:
            self._timer.cancel()
            self._timer = None

    def _schedule_next(self, interval_hours: int) -> None:
        """
        Schedule next backup.

        Args:
            interval_hours: Hours until next backup
        """
        if not self._running:
            return

        self._timer = threading.Timer(
            interval_hours * 3600,
            self._run_scheduled_backup,
            args=[interval_hours],
        )
        self._timer.daemon = True
        self._timer.start()

    def _run_scheduled_backup(self, interval_hours: int) -> None:
        """
        Run scheduled backup.

        Args:
            interval_hours: Hours between backups (for rescheduling)
        """
        with self._lock:
            self.create_backup(backup_type=BackupType.FULL)
        self._schedule_next(interval_hours)


# Singleton
_backup_manager: BackupManager | None = None


def get_backup_manager() -> BackupManager:
    """
    Get singleton BackupManager instance.

    Returns:
        BackupManager singleton
    """
    global _backup_manager
    if _backup_manager is None:
        _backup_manager = BackupManager()
    return _backup_manager


def restore_backup(backup_path: Path, password: str | None = None) -> bool:
    """
    Convenience function to restore a backup.

    Args:
        backup_path: Path to backup file
        password: Password if backup is encrypted

    Returns:
        True if restore succeeded, False otherwise
    """
    manager = get_backup_manager()
    return manager.restore_backup(backup_path, password)

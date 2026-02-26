"""
backup_manager.py - Backup and recovery management for HIPAA compliance.

Author: Homero Thompson del Lago del Terror

Implements backup and recovery procedures per HIPAA §164.308(a)(7)
Contingency plan requirements.
"""

import atexit
import io
import json
import os
import tarfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from loguru import logger


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


class BackupManager:
    """Manages backups and recovery for PDFSigner."""

    # Encryption constants
    _SALT_LENGTH = 16
    _NONCE_LENGTH = 12
    _PBKDF2_ITERATIONS = 480000

    def __init__(self, backup_dir: Path | None = None):
        """
        Initialize BackupManager.

        Args:
            backup_dir: Directory to store backups (default: ~/.local/share/pdfsigner/backups)
        """
        if backup_dir is None:
            backup_dir = Path.home() / ".local" / "share" / "pdfsigner" / "backups"

        self.backup_dir = backup_dir
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        self._config_dir = Path.home() / ".config" / "pdfsigner"
        self._data_dir = Path.home() / ".local" / "share" / "pdfsigner"

        self._timer: threading.Timer | None = None
        self._running = False
        self._lock = threading.Lock()

        atexit.register(self.stop)

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

                # Backup configuration
                if metadata.includes_config:
                    file_count += self._backup_config(tar)

                # Backup audit logs
                if metadata.includes_audit:
                    file_count += self._backup_audit(tar)

                # Backup databases
                if metadata.includes_databases:
                    file_count += self._backup_databases(tar)

                # Add metadata file
                metadata_json = json.dumps(metadata.to_dict(), indent=2)
                self._add_string_to_tar(tar, "backup_metadata.json", metadata_json)
                file_count += 1

                metadata.file_count = file_count

            # Get backup size
            metadata.size_bytes = backup_path.stat().st_size

            # Encrypt if requested
            if encrypt and password:
                encrypted_path = self._encrypt_backup(backup_path, password)
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

            # Log to audit
            self._log_backup_to_audit(metadata)

        except Exception as e:
            metadata.status = BackupStatus.FAILED
            metadata.error = str(e)
            logger.error(f"Backup failed: {e}")

        return metadata

    def _backup_config(self, tar: tarfile.TarFile) -> int:
        """
        Backup configuration files.

        Args:
            tar: Open tarfile to add files to

        Returns:
            Number of files backed up
        """
        count = 0
        if self._config_dir.exists():
            for item in self._config_dir.rglob("*"):
                if item.is_file():
                    arcname = f"config/{item.relative_to(self._config_dir)}"
                    tar.add(item, arcname=arcname)
                    count += 1
        return count

    def _backup_audit(self, tar: tarfile.TarFile) -> int:
        """
        Backup audit logs.

        Args:
            tar: Open tarfile to add files to

        Returns:
            Number of files backed up
        """
        count = 0
        audit_dir = self._data_dir / "audit"
        if audit_dir.exists():
            for item in audit_dir.rglob("*.jsonl"):
                if item.is_file():
                    arcname = f"audit/{item.relative_to(audit_dir)}"
                    tar.add(item, arcname=arcname)
                    count += 1
        return count

    def _backup_databases(self, tar: tarfile.TarFile) -> int:
        """
        Backup SQLite databases using sqlite3.backup() for WAL consistency.

        Args:
            tar: Open tarfile to add files to

        Returns:
            Number of files backed up
        """
        import sqlite3

        count = 0
        db_files = ["users.db", "sessions.db", "retention.db", "emergency.db"]

        for db_name in db_files:
            db_path = self._config_dir / db_name
            if db_path.exists():
                backup_path = db_path.with_suffix(".db.backup")
                try:
                    source = sqlite3.connect(str(db_path))
                    dest = sqlite3.connect(str(backup_path))
                    source.backup(dest)
                    dest.close()
                    source.close()
                    tar.add(str(backup_path), arcname=f"databases/{db_name}")
                    count += 1
                except sqlite3.DatabaseError:
                    # Fallback: direct copy for non-SQLite files
                    tar.add(str(db_path), arcname=f"databases/{db_name}")
                    count += 1
                finally:
                    backup_path.unlink(missing_ok=True)

        return count

    def _add_string_to_tar(self, tar: tarfile.TarFile, name: str, content: str) -> None:
        """
        Add a string as a file to tar archive.

        Args:
            tar: Open tarfile to add to
            name: Name of file in archive
            content: String content to add
        """
        data = content.encode("utf-8")
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    def _derive_backup_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2.

        Args:
            password: Password to derive key from
            salt: Random salt for key derivation

        Returns:
            32-byte derived key
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self._PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode())

    def _encrypt_backup(self, backup_path: Path, password: str) -> Path:
        """
        Encrypt backup file using AES-256.

        Args:
            backup_path: Path to unencrypted backup
            password: Password for encryption

        Returns:
            Path to encrypted backup file
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Derive key from password
        salt = os.urandom(self._SALT_LENGTH)
        key = self._derive_backup_key(password, salt)

        # Encrypt
        aesgcm = AESGCM(key)
        nonce = os.urandom(self._NONCE_LENGTH)

        plaintext = backup_path.read_bytes()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Write encrypted file (salt + nonce + ciphertext)
        encrypted_path = backup_path.with_suffix(".tar.gz.enc")
        with open(encrypted_path, "wb") as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

        return encrypted_path

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
                backup_path = self._decrypt_backup(backup_path, password)
                temp_decrypted = backup_path

            with tarfile.open(backup_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.startswith("config/") and restore_config:
                        # Extract relative path
                        rel_path = member.name[7:]  # Remove "config/" prefix
                        target = self._config_dir / rel_path
                        target.parent.mkdir(parents=True, exist_ok=True)

                        # Extract file content
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

    def _decrypt_backup(self, encrypted_path: Path, password: str) -> Path:
        """
        Decrypt backup file.

        Args:
            encrypted_path: Path to encrypted backup
            password: Password for decryption

        Returns:
            Path to decrypted backup file
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        with open(encrypted_path, "rb") as f:
            salt = f.read(self._SALT_LENGTH)
            nonce = f.read(self._NONCE_LENGTH)
            ciphertext = f.read()

        # Derive key
        key = self._derive_backup_key(password, salt)

        # Decrypt
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        # Write decrypted file
        decrypted_path = encrypted_path.with_suffix("")  # Remove .enc
        decrypted_path.write_bytes(plaintext)

        return decrypted_path

    def list_backups(self) -> list[BackupMetadata]:
        """
        List all available backups.

        Returns:
            List of BackupMetadata for all backups, sorted by date (newest first)
        """
        backups = []

        for backup_file in self.backup_dir.glob("pdfsigner_backup_*.tar.gz*"):
            try:
                if backup_file.suffix == ".enc":
                    # Encrypted backup - try to read from unencrypted sibling metadata file
                    # or create limited metadata from file stats
                    metadata_path = backup_file.with_suffix(".meta.json")

                    if metadata_path.exists():
                        # Read metadata from sidecar file
                        with open(metadata_path) as f:
                            metadata = BackupMetadata.from_dict(json.loads(f.read()))
                            metadata.backup_path = str(backup_file)
                    else:
                        # Limited metadata from file stats
                        metadata = BackupMetadata(
                            backup_path=str(backup_file),
                            encrypted=True,
                            size_bytes=backup_file.stat().st_size,
                            created_at=datetime.fromtimestamp(backup_file.stat().st_mtime, tz=UTC),
                            status=BackupStatus.COMPLETED,
                        )
                else:
                    # Read metadata from backup
                    with tarfile.open(backup_file, "r:gz") as tar:
                        meta_file = tar.extractfile("backup_metadata.json")
                        if meta_file:
                            metadata = BackupMetadata.from_dict(json.loads(meta_file.read()))
                        else:
                            continue

                backups.append(metadata)
            except Exception as e:
                logger.warning(f"Could not read backup {backup_file}: {e}")

        # Sort by creation date (newest first)
        backups.sort(key=lambda b: b.created_at, reverse=True)
        return backups

    def delete_backup(self, backup_id: str) -> bool:
        """
        Delete a backup by ID.

        Args:
            backup_id: ID of backup to delete

        Returns:
            True if backup was deleted, False otherwise
        """
        for backup in self.list_backups():
            if backup.backup_id == backup_id:
                try:
                    Path(backup.backup_path).unlink()
                    logger.info(f"Deleted backup: {backup_id}")
                    return True
                except Exception as e:
                    logger.error(f"Failed to delete backup: {e}")
                    return False
        return False

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

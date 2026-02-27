"""
backup_storage.py - Storage layer for backup and recovery.

Handles file I/O, encryption/decryption, listing, and deletion of backups.
Separated from orchestration logic in BackupManager.
"""

import io
import json
import os
import tarfile
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.backup.backup_types import BackupMetadata, BackupStatus


class BackupStorage:
    """Handles backup file I/O, encryption, listing, and cleanup."""

    # Encryption constants
    _SALT_LENGTH = 16
    _NONCE_LENGTH = 12
    _PBKDF2_ITERATIONS = 480000

    def __init__(
        self,
        backup_dir: Path,
        config_dir: Path,
        data_dir: Path,
    ):
        """
        Initialize BackupStorage.

        Args:
            backup_dir: Directory to store backups
            config_dir: Application config directory
            data_dir: Application data directory
        """
        self.backup_dir = backup_dir
        self._config_dir = config_dir
        self._data_dir = data_dir

    def backup_config(self, tar: tarfile.TarFile) -> int:
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

    def backup_audit(self, tar: tarfile.TarFile) -> int:
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

    def backup_databases(self, tar: tarfile.TarFile) -> int:
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

    def add_string_to_tar(self, tar: tarfile.TarFile, name: str, content: str) -> None:
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

    def encrypt_backup(self, backup_path: Path, password: str) -> Path:
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

    def decrypt_backup(self, encrypted_path: Path, password: str) -> Path:
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
                    # Encrypted backup - try sidecar metadata file
                    metadata_path = backup_file.with_suffix(".meta.json")

                    if metadata_path.exists():
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

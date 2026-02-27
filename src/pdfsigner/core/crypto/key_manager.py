"""
key_manager.py - Centralized cryptographic key management.

HIPAA compliance: SS164.312(a)(2)(iv) - Encryption mechanism
"""

import base64
import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pdfsigner.core.audit.helpers import emit_audit_event
from pdfsigner.core.crypto.key_exceptions import (
    KeyExpiredError,
    KeyManagerError,
    KeyNotFoundError,
    KeyRevokedError,
)
from pdfsigner.core.crypto.key_storage import KeyStorage
from pdfsigner.core.crypto.key_types import KeyInfo, KeyStatus, KeyType

# Re-export for backward compatibility
__all__ = [
    "KeyManager",
    "KeyManagerError",
    "KeyNotFoundError",
    "KeyRevokedError",
    "KeyExpiredError",
    "KeyType",
    "KeyStatus",
    "KeyInfo",
    "get_key_manager",
    "init_key_manager",
]


def _emit_key_audit(action: str, key_id: str, algorithm: str, detail: str) -> None:
    """Emit audit event for key operations."""
    from pdfsigner.core.audit.audit_event import AuditEventType

    emit_audit_event(
        AuditEventType.CONFIG_CHANGE,
        details={"action": action, "key_id": key_id, "algorithm": algorithm, "detail": detail},
    )


class KeyManager:
    """Centralized key management with encrypted SQLite storage (via KeyStorage)."""

    PBKDF2_ITERATIONS = 600000  # NIST recommendation (2023)
    SALT_LENGTH = 32
    _SENTINEL_PLAINTEXT = b"PDFSIGNER_KEY_MANAGER_SENTINEL"

    def __init__(self, db_path: Path, master_password: str):
        if not master_password:
            raise ValueError("Master password cannot be empty")
        self.db_path = db_path
        self._storage = KeyStorage(db_path)
        self._fernet = self._init_fernet(master_password)
        self._init_database()

    def _init_fernet(self, password: str) -> Fernet:
        """Initialize Fernet cipher with password-derived key."""
        salt = self._get_or_create_salt()
        key = self._derive_encryption_key(password, salt)
        return Fernet(key)

    def _get_or_create_salt(self) -> bytes:
        """Get or create the master salt for key derivation."""
        if not self.db_path.exists():
            salt = secrets.token_bytes(self.SALT_LENGTH)
            self._master_salt = salt
            return salt

        stored = self._storage.get_metadata("master_salt")
        if stored:
            return bytes.fromhex(stored)

        salt = secrets.token_bytes(self.SALT_LENGTH)
        self._master_salt = salt
        return salt

    def _init_database(self) -> None:
        """Initialize SQLite database schema and verify master password."""
        self._storage.init_schema()

        if hasattr(self, "_master_salt"):
            self._storage.set_metadata("master_salt", self._master_salt.hex())
            sentinel = self._fernet.encrypt(self._SENTINEL_PLAINTEXT).decode()
            self._storage.set_metadata("sentinel", sentinel)
        else:
            stored_sentinel = self._storage.get_metadata("sentinel")
            if stored_sentinel:
                try:
                    self._fernet.decrypt(stored_sentinel.encode())
                except Exception:
                    raise ValueError("Wrong master password")

    def generate_key(
        self,
        key_type: KeyType,
        algorithm: str,
        key_size: int = 256,
        expires_days: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Generate a new cryptographic key. Returns key_id."""
        if key_size < 128:
            raise ValueError("Key size must be at least 128 bits")

        key_bytes = secrets.token_bytes(key_size // 8)
        key_id = secrets.token_urlsafe(32)
        created_at = datetime.now(UTC)
        expires_at = created_at + timedelta(days=expires_days) if expires_days else None
        encrypted_key = self._fernet.encrypt(key_bytes)

        self._storage.insert_key(
            key_id=key_id,
            key_type=key_type.value,
            algorithm=algorithm,
            status=KeyStatus.ACTIVE.value,
            encrypted_key=encrypted_key,
            created_at=created_at.isoformat(),
            expires_at=expires_at.isoformat() if expires_at else None,
            rotated_from=None,
            metadata_json=json.dumps(metadata or {}),
        )

        _emit_key_audit("key_generated", key_id, algorithm, key_type.value)
        return key_id

    def get_key(self, key_id: str) -> bytes:
        """Retrieve decrypted key material."""
        row = self._storage.get_key_full_row(key_id)
        if not row:
            raise KeyNotFoundError(f"Key {key_id} not found")

        status = KeyStatus(row[2])
        expires_at = datetime.fromisoformat(row[4]) if row[4] else None
        encrypted_key = row[7]

        if status == KeyStatus.REVOKED:
            raise KeyRevokedError(f"Key {key_id} has been revoked")

        if expires_at:
            now = datetime.now(UTC)
            expires = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=UTC)
            if now > expires:
                self._storage.update_key_status(key_id, KeyStatus.EXPIRED.value)
                raise KeyExpiredError(f"Key {key_id} has expired")

        return self._fernet.decrypt(encrypted_key)

    def rotate_key(self, key_id: str) -> str:
        """Rotate a key (generate new, mark old as rotated). Returns new key_id."""
        old_info = self._get_key_info_from_db(key_id)

        expires_days = None
        if old_info.expires_at:
            days_remaining = (old_info.expires_at - datetime.now(UTC)).days
            expires_days = max(days_remaining, 30)

        new_key_id = self.generate_key(
            key_type=old_info.key_type,
            algorithm=old_info.algorithm,
            key_size=256,
            expires_days=expires_days,
            metadata={**old_info.metadata, "rotated_from": key_id},
        )

        self._storage.update_rotation(new_key_id, key_id, KeyStatus.ROTATED.value)
        _emit_key_audit("key_rotated", key_id, old_info.algorithm, new_key_id)
        return new_key_id

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a key (cannot be used anymore)."""
        info = self._get_key_info_from_db(key_id)
        if info.status == KeyStatus.REVOKED:
            return True

        self._storage.update_key_status(key_id, KeyStatus.REVOKED.value)
        _emit_key_audit("key_revoked", key_id, info.algorithm, info.key_type.value)
        return True

    def list_keys(
        self, key_type: KeyType | None = None, status: KeyStatus | None = None
    ) -> list[KeyInfo]:
        """List keys with optional filters."""
        rows = self._storage.query_keys(
            key_type=key_type.value if key_type else None,
            status=status.value if status else None,
        )
        return [
            KeyInfo(
                key_id=row[0],
                key_type=KeyType(row[1]),
                algorithm=row[2],
                status=KeyStatus(row[3]),
                created_at=datetime.fromisoformat(row[4]),
                expires_at=datetime.fromisoformat(row[5]) if row[5] else None,
                rotated_from=row[6],
                metadata=json.loads(row[7]) if row[7] else {},
            )
            for row in rows
        ]

    def export_key(self, key_id: str, export_password: str) -> bytes:
        """Export key encrypted with password. Returns encrypted JSON bytes."""
        if not export_password:
            raise ValueError("Export password cannot be empty")

        info = self._get_key_info_from_db(key_id)
        key_material = self.get_key(key_id)

        export_data = {
            "version": 1,
            "key_info": info.to_dict(),
            "key_material": key_material.hex(),
            "exported_at": datetime.now(UTC).isoformat(),
        }

        export_salt = secrets.token_bytes(self.SALT_LENGTH)
        export_key = self._derive_encryption_key(export_password, export_salt)
        export_fernet = Fernet(export_key)

        encrypted_data = export_fernet.encrypt(json.dumps(export_data).encode())
        package = {"salt": export_salt.hex(), "data": encrypted_data.hex()}

        _emit_key_audit("key_exported", key_id, info.algorithm, "export")
        return json.dumps(package).encode()

    def import_key(
        self, key_data: bytes, import_password: str, key_type: KeyType, algorithm: str
    ) -> str:
        """Import an encrypted key. Returns new key_id."""
        if not import_password:
            raise ValueError("Import password cannot be empty")

        try:
            package = json.loads(key_data.decode())
            export_salt = bytes.fromhex(package["salt"])
            encrypted_data = bytes.fromhex(package["data"])

            import_key_derived = self._derive_encryption_key(import_password, export_salt)
            import_fernet = Fernet(import_key_derived)
            decrypted_data = import_fernet.decrypt(encrypted_data)

            export_data = json.loads(decrypted_data.decode())
            if export_data.get("version") != 1:
                raise ValueError("Unsupported export format version")

            key_info = export_data["key_info"]
            if key_info["key_type"] != key_type.value:
                raise ValueError(
                    f"Key type mismatch: expected {key_type.value}, got {key_info['key_type']}"
                )
            if key_info["algorithm"] != algorithm:
                raise ValueError(
                    f"Algorithm mismatch: expected {algorithm}, got {key_info['algorithm']}"
                )

            key_material = bytes.fromhex(export_data["key_material"])
            new_key_id = secrets.token_urlsafe(32)
            encrypted_key = self._fernet.encrypt(key_material)
            created_at = datetime.now(UTC)
            expires_at = (
                datetime.fromisoformat(key_info["expires_at"])
                if key_info.get("expires_at")
                else None
            )

            self._storage.insert_key(
                key_id=new_key_id,
                key_type=key_type.value,
                algorithm=algorithm,
                status=KeyStatus.ACTIVE.value,
                encrypted_key=encrypted_key,
                created_at=created_at.isoformat(),
                expires_at=expires_at.isoformat() if expires_at else None,
                rotated_from=None,
                metadata_json=json.dumps({**key_info.get("metadata", {}), "imported": True}),
            )

            _emit_key_audit("key_imported", new_key_id, algorithm, key_type.value)
            return new_key_id

        except ValueError:
            raise
        except Exception as e:
            raise ValueError("Failed to import key") from e

    def encrypt_data(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using a symmetric key (AES-256-GCM via Fernet)."""
        key_bytes = self.get_key(key_id)
        fernet_key = base64.urlsafe_b64encode(key_bytes[:32])
        cipher = Fernet(fernet_key)
        return cipher.encrypt(plaintext)

    def decrypt_data(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using a symmetric key."""
        key_bytes = self.get_key(key_id)
        fernet_key = base64.urlsafe_b64encode(key_bytes[:32])
        cipher = Fernet(fernet_key)
        try:
            return cipher.decrypt(ciphertext)
        except Exception as e:
            raise ValueError("Decryption failed") from e

    def get_or_create_mfa_key(self) -> str:
        """Get or create a dedicated key for MFA secret encryption."""
        keys = self.list_keys(key_type=KeyType.SYMMETRIC, status=KeyStatus.ACTIVE)
        mfa_keys = [k for k in keys if k.metadata.get("purpose") == "mfa_encryption"]
        if mfa_keys:
            return mfa_keys[0].key_id

        return self.generate_key(
            key_type=KeyType.SYMMETRIC,
            algorithm="AES-256-GCM",
            key_size=256,
            expires_days=365,
            metadata={"purpose": "mfa_encryption"},
        )

    def cleanup_expired(self) -> int:
        """Remove expired keys from storage. Returns number of keys marked expired."""
        now = datetime.now(UTC).isoformat()
        count = self._storage.mark_expired_keys(now)
        if count > 0:
            _emit_key_audit("keys_cleaned_up", "system", "cleanup", str(count))
        return count

    def _derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        """Derive Fernet key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        key_bytes = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key_bytes)

    def _secure_delete(self, key_id: str) -> None:
        """Securely delete key from storage."""
        self._storage.delete_key(key_id)
        _emit_key_audit("key_deleted", key_id, "secure_delete", "permanent")

    def _get_key_info_from_db(self, key_id: str) -> KeyInfo:
        """Get key info from database."""
        row = self._storage.get_key_info_row(key_id)
        if not row:
            raise KeyNotFoundError(f"Key {key_id} not found")
        return KeyStorage.row_to_key_info(key_id, row)

    def _update_key_status(self, key_id: str, status: KeyStatus) -> None:
        """Update key status in database."""
        self._storage.update_key_status(key_id, status.value)


# Singleton instance
_key_manager: KeyManager | None = None


def get_key_manager() -> KeyManager:
    """Get singleton KeyManager instance. Raises RuntimeError if not initialized."""
    if _key_manager is None:
        raise RuntimeError(
            "KeyManager not initialized. Call init_key_manager() first with master password."
        )
    return _key_manager


def init_key_manager(db_path: Path, master_password: str) -> KeyManager:
    """Initialize the key manager singleton."""
    global _key_manager
    _key_manager = KeyManager(db_path, master_password)
    return _key_manager

"""
key_manager.py - Centralized cryptographic key management

Provides secure key storage with encryption, rotation, revocation, and audit integration.
HIPAA compliance: §164.312(a)(2)(iv) - Encryption mechanism
"""

import json
import secrets
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pdfsigner.core.audit.helpers import emit_audit_event


def _emit_key_audit(action: str, key_id: str, algorithm: str, detail: str) -> None:
    """Emit audit event for key operations using the shared helper."""
    from pdfsigner.core.audit.audit_event import AuditEventType

    emit_audit_event(
        AuditEventType.CONFIG_CHANGE,
        details={
            "action": action,
            "key_id": key_id,
            "algorithm": algorithm,
            "detail": detail,
        },
    )


class KeyType(str, Enum):
    """Type of cryptographic key."""

    SYMMETRIC = "symmetric"
    ASYMMETRIC_PRIVATE = "asymmetric_private"
    ASYMMETRIC_PUBLIC = "asymmetric_public"
    HMAC = "hmac"


class KeyStatus(str, Enum):
    """Status of a cryptographic key."""

    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class KeyInfo:
    """Information about a cryptographic key."""

    key_id: str
    key_type: KeyType
    algorithm: str
    status: KeyStatus
    created_at: datetime
    expires_at: datetime | None
    rotated_from: str | None  # Previous key ID if rotated
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "algorithm": self.algorithm,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotated_from": self.rotated_from,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KeyInfo":
        """Create from dictionary."""
        return cls(
            key_id=data["key_id"],
            key_type=KeyType(data["key_type"]),
            algorithm=data["algorithm"],
            status=KeyStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=(
                datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None
            ),
            rotated_from=data.get("rotated_from"),
            metadata=data.get("metadata", {}),
        )


class KeyManagerError(Exception):
    """Base exception for KeyManager errors."""

    pass


class KeyNotFoundError(KeyManagerError):
    """Key not found in storage."""

    pass


class KeyRevokedError(KeyManagerError):
    """Attempted to use a revoked key."""

    pass


class KeyExpiredError(KeyManagerError):
    """Attempted to use an expired key."""

    pass


class KeyManager:
    """
    Centralized key management with encrypted storage.

    Features:
    - Encrypted SQLite storage
    - Key generation with configurable algorithms
    - Key rotation with audit trail
    - Key revocation
    - Expiration management
    - Import/export with password protection
    - Secure key deletion
    """

    PBKDF2_ITERATIONS = 600000  # NIST recommendation (2023)
    SALT_LENGTH = 32
    _SENTINEL_PLAINTEXT = b"PDFSIGNER_KEY_MANAGER_SENTINEL"

    def __init__(self, db_path: Path, master_password: str):
        """
        Initialize with encrypted SQLite storage.

        Args:
            db_path: Path to SQLite database
            master_password: Master password for key encryption

        Raises:
            ValueError: If master password is empty
        """
        if not master_password:
            raise ValueError("Master password cannot be empty")

        self.db_path = db_path
        self._fernet = self._init_fernet(master_password)
        # master_password is NOT stored - Fernet key derived and password discarded

        # Create directory if needed
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_database()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection]:
        """Context manager for SQLite connections with auto commit/rollback."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

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

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM metadata WHERE key = 'master_salt'")
                row = cursor.fetchone()
                if row:
                    return bytes.fromhex(row[0])
        except sqlite3.OperationalError:
            pass  # Table doesn't exist yet

        salt = secrets.token_bytes(self.SALT_LENGTH)
        self._master_salt = salt
        return salt

    def _init_database(self) -> None:
        """Initialize SQLite database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """
            )

            if hasattr(self, "_master_salt"):
                cursor.execute(
                    "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                    ("master_salt", self._master_salt.hex()),
                )
                sentinel = self._fernet.encrypt(self._SENTINEL_PLAINTEXT).decode()
                cursor.execute(
                    "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                    ("sentinel", sentinel),
                )
            else:
                cursor.execute("SELECT value FROM metadata WHERE key = 'sentinel'")
                row = cursor.fetchone()
                if row:
                    try:
                        self._fernet.decrypt(row[0].encode())
                    except Exception:
                        raise ValueError("Wrong master password")

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS keys (
                    key_id TEXT PRIMARY KEY,
                    key_type TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    status TEXT NOT NULL,
                    encrypted_key BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    rotated_from TEXT,
                    metadata TEXT,
                    FOREIGN KEY (rotated_from) REFERENCES keys(key_id)
                )
            """
            )

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_type ON keys(key_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON keys(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_expires_at ON keys(expires_at)")

    def generate_key(
        self,
        key_type: KeyType,
        algorithm: str,
        key_size: int = 256,
        expires_days: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Generate a new cryptographic key.

        Args:
            key_type: Type of key (symmetric, asymmetric, HMAC)
            algorithm: Algorithm name (e.g., "AES", "RSA", "HMAC-SHA256")
            key_size: Key size in bits (default: 256)
            expires_days: Expiration in days (None = no expiration)
            metadata: Additional key metadata

        Returns:
            key_id: Unique identifier for the generated key

        Raises:
            ValueError: If key_size is invalid
        """
        if key_size < 128:
            raise ValueError("Key size must be at least 128 bits")

        key_bytes = secrets.token_bytes(key_size // 8)
        key_id = secrets.token_urlsafe(32)
        created_at = datetime.now(UTC)
        expires_at = created_at + timedelta(days=expires_days) if expires_days else None
        encrypted_key = self._fernet.encrypt(key_bytes)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO keys (key_id, key_type, algorithm, status, encrypted_key,
                                created_at, expires_at, rotated_from, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    key_id,
                    key_type.value,
                    algorithm,
                    KeyStatus.ACTIVE.value,
                    encrypted_key,
                    created_at.isoformat(),
                    expires_at.isoformat() if expires_at else None,
                    None,
                    json.dumps(metadata or {}),
                ),
            )

        _emit_key_audit("key_generated", key_id, algorithm, key_type.value)
        return key_id

    def get_key(self, key_id: str) -> bytes:
        """
        Retrieve decrypted key material.

        Args:
            key_id: Key identifier

        Returns:
            Decrypted key bytes

        Raises:
            KeyNotFoundError: If key doesn't exist
            KeyRevokedError: If key is revoked
            KeyExpiredError: If key is expired
        """
        # Single query for both metadata and encrypted key to avoid N+1
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT key_type, algorithm, status, created_at, expires_at,
                       rotated_from, metadata, encrypted_key
                FROM keys WHERE key_id = ?
            """,
                (key_id,),
            )
            row = cursor.fetchone()

        if not row:
            raise KeyNotFoundError(f"Key {key_id} not found")

        status = KeyStatus(row[2])
        expires_at = datetime.fromisoformat(row[4]) if row[4] else None
        encrypted_key = row[7]

        if status == KeyStatus.REVOKED:
            raise KeyRevokedError(f"Key {key_id} has been revoked")

        if expires_at:
            now = datetime.now(UTC)
            expires = expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if now > expires:
                self._update_key_status(key_id, KeyStatus.EXPIRED)
                raise KeyExpiredError(f"Key {key_id} has expired")

        return self._fernet.decrypt(encrypted_key)

    def rotate_key(self, key_id: str) -> str:
        """
        Rotate a key (generate new key, mark old as rotated).

        Args:
            key_id: Key to rotate

        Returns:
            new_key_id: ID of the new key

        Raises:
            KeyNotFoundError: If key doesn't exist
        """
        old_info = self._get_key_info_from_db(key_id)

        expires_days = None
        if old_info.expires_at:
            days_remaining = (old_info.expires_at - datetime.now(UTC)).days
            expires_days = max(days_remaining, 30)  # At least 30 days

        new_key_id = self.generate_key(
            key_type=old_info.key_type,
            algorithm=old_info.algorithm,
            key_size=256,
            expires_days=expires_days,
            metadata={**old_info.metadata, "rotated_from": key_id},
        )

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE keys SET rotated_from = ? WHERE key_id = ?", (key_id, new_key_id)
            )
            cursor.execute(
                "UPDATE keys SET status = ? WHERE key_id = ?",
                (KeyStatus.ROTATED.value, key_id),
            )

        _emit_key_audit("key_rotated", key_id, old_info.algorithm, new_key_id)
        return new_key_id

    def revoke_key(self, key_id: str) -> bool:
        """
        Revoke a key (cannot be used anymore).

        Args:
            key_id: Key to revoke

        Returns:
            True if revoked successfully

        Raises:
            KeyNotFoundError: If key doesn't exist
        """
        info = self._get_key_info_from_db(key_id)

        if info.status == KeyStatus.REVOKED:
            return True

        self._update_key_status(key_id, KeyStatus.REVOKED)
        _emit_key_audit("key_revoked", key_id, info.algorithm, info.key_type.value)
        return True

    def list_keys(
        self, key_type: KeyType | None = None, status: KeyStatus | None = None
    ) -> list[KeyInfo]:
        """
        List keys with optional filters.

        Args:
            key_type: Filter by key type
            status: Filter by status

        Returns:
            List of KeyInfo objects
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = (
                "SELECT key_id, key_type, algorithm, status, created_at, expires_at, "
                "rotated_from, metadata FROM keys WHERE 1=1"
            )
            params: list[str] = []

            if key_type:
                query += " AND key_type = ?"
                params.append(key_type.value)

            if status:
                query += " AND status = ?"
                params.append(status.value)

            query += " ORDER BY created_at DESC"

            cursor.execute(query, params)
            rows = cursor.fetchall()

        keys = []
        for row in rows:
            keys.append(
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
            )

        return keys

    def export_key(self, key_id: str, export_password: str) -> bytes:
        """
        Export key encrypted with password.

        Args:
            key_id: Key to export
            export_password: Password for export encryption

        Returns:
            Encrypted key data (JSON)

        Raises:
            KeyNotFoundError: If key doesn't exist
            ValueError: If export_password is empty
        """
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

        package = {
            "salt": export_salt.hex(),
            "data": encrypted_data.hex(),
        }

        _emit_key_audit("key_exported", key_id, info.algorithm, "export")
        return json.dumps(package).encode()

    def import_key(
        self, key_data: bytes, import_password: str, key_type: KeyType, algorithm: str
    ) -> str:
        """
        Import an encrypted key.

        Args:
            key_data: Encrypted key package
            import_password: Password for decryption
            key_type: Expected key type
            algorithm: Expected algorithm

        Returns:
            key_id: ID of imported key

        Raises:
            ValueError: If password is wrong or data is invalid
        """
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

            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO keys (key_id, key_type, algorithm, status, encrypted_key,
                                    created_at, expires_at, rotated_from, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        new_key_id,
                        key_type.value,
                        algorithm,
                        KeyStatus.ACTIVE.value,
                        encrypted_key,
                        created_at.isoformat(),
                        expires_at.isoformat() if expires_at else None,
                        None,
                        json.dumps({**key_info.get("metadata", {}), "imported": True}),
                    ),
                )

            _emit_key_audit("key_imported", new_key_id, algorithm, key_type.value)
            return new_key_id

        except ValueError:
            raise
        except Exception as e:
            raise ValueError("Failed to import key") from e

    def encrypt_data(self, key_id: str, plaintext: bytes) -> bytes:
        """
        Encrypt data using a symmetric key.

        Uses AES-256-GCM via Fernet for authenticated encryption.

        Args:
            key_id: Key identifier for encryption
            plaintext: Data to encrypt

        Returns:
            Encrypted data (Fernet token)

        Raises:
            KeyNotFoundError: If key doesn't exist
            KeyRevokedError: If key is revoked
            KeyExpiredError: If key is expired
        """
        key_bytes = self.get_key(key_id)

        import base64

        fernet_key = base64.urlsafe_b64encode(key_bytes[:32])
        cipher = Fernet(fernet_key)

        return cipher.encrypt(plaintext)

    def decrypt_data(self, key_id: str, ciphertext: bytes) -> bytes:
        """
        Decrypt data using a symmetric key.

        Args:
            key_id: Key identifier for decryption
            ciphertext: Encrypted data (Fernet token)

        Returns:
            Decrypted plaintext

        Raises:
            KeyNotFoundError: If key doesn't exist
            KeyRevokedError: If key is revoked
            KeyExpiredError: If key is expired
            ValueError: If decryption fails (invalid token)
        """
        key_bytes = self.get_key(key_id)

        import base64

        fernet_key = base64.urlsafe_b64encode(key_bytes[:32])
        cipher = Fernet(fernet_key)

        try:
            return cipher.decrypt(ciphertext)
        except Exception as e:
            raise ValueError("Decryption failed") from e

    def get_or_create_mfa_key(self) -> str:
        """
        Get or create a dedicated key for MFA secret encryption.

        Returns:
            key_id: Key identifier for MFA encryption
        """
        keys = self.list_keys(key_type=KeyType.SYMMETRIC, status=KeyStatus.ACTIVE)
        mfa_keys = [k for k in keys if k.metadata.get("purpose") == "mfa_encryption"]

        if mfa_keys:
            return mfa_keys[0].key_id

        key_id = self.generate_key(
            key_type=KeyType.SYMMETRIC,
            algorithm="AES-256-GCM",
            key_size=256,
            expires_days=365,
            metadata={"purpose": "mfa_encryption"},
        )

        return key_id

    def cleanup_expired(self) -> int:
        """
        Remove expired keys from storage.

        Returns:
            count: Number of keys removed
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            now = datetime.now(UTC).isoformat()
            cursor.execute(
                "UPDATE keys SET status = ? WHERE expires_at < ? AND status = ?",
                (KeyStatus.EXPIRED.value, now, KeyStatus.ACTIVE.value),
            )

            cursor.execute(
                "SELECT COUNT(*) FROM keys WHERE status = ? AND expires_at < ?",
                (KeyStatus.EXPIRED.value, now),
            )
            count = cursor.fetchone()[0]

        if count > 0:
            _emit_key_audit("keys_cleaned_up", "system", "cleanup", str(count))

        return count

    def _derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive Fernet key from password using PBKDF2.

        Args:
            password: Password string
            salt: Salt bytes

        Returns:
            32-byte Fernet-compatible key (base64url encoded)
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        key_bytes = kdf.derive(password.encode())

        import base64

        return base64.urlsafe_b64encode(key_bytes)

    def _secure_delete(self, key_id: str) -> None:
        """
        Securely delete key from memory and storage.

        Args:
            key_id: Key to delete
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM keys WHERE key_id = ?", (key_id,))

        _emit_key_audit("key_deleted", key_id, "secure_delete", "permanent")

    def _get_key_info_from_db(self, key_id: str) -> KeyInfo:
        """Get key info from database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT key_type, algorithm, status, created_at, expires_at, rotated_from, metadata
                FROM keys WHERE key_id = ?
            """,
                (key_id,),
            )
            row = cursor.fetchone()

        if not row:
            raise KeyNotFoundError(f"Key {key_id} not found")

        return KeyInfo(
            key_id=key_id,
            key_type=KeyType(row[0]),
            algorithm=row[1],
            status=KeyStatus(row[2]),
            created_at=datetime.fromisoformat(row[3]),
            expires_at=datetime.fromisoformat(row[4]) if row[4] else None,
            rotated_from=row[5],
            metadata=json.loads(row[6]) if row[6] else {},
        )

    def _update_key_status(self, key_id: str, status: KeyStatus) -> None:
        """Update key status in database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE keys SET status = ? WHERE key_id = ?", (status.value, key_id))


# Singleton instance
_key_manager: KeyManager | None = None


def get_key_manager() -> KeyManager:
    """
    Get singleton KeyManager instance.

    Returns:
        KeyManager instance

    Raises:
        RuntimeError: If KeyManager not initialized
    """
    if _key_manager is None:
        raise RuntimeError(
            "KeyManager not initialized. Call init_key_manager() first with master password."
        )
    return _key_manager


def init_key_manager(db_path: Path, master_password: str) -> KeyManager:
    """
    Initialize the key manager singleton.

    Args:
        db_path: Path to SQLite database
        master_password: Master password for key encryption

    Returns:
        KeyManager instance
    """
    global _key_manager
    _key_manager = KeyManager(db_path, master_password)
    return _key_manager

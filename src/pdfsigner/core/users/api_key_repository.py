"""
api_key_repository.py - API Key persistence with SQLite

Provides secure API key management with user binding.
NIST: IA-5(1) - Password-based authentication → adapted for API keys
"""

import hashlib
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from loguru import logger

from pdfsigner.core.base_repository import BaseSQLiteRepository


class APIKey:
    """API Key model."""

    def __init__(
        self,
        id: str,
        user_id: str,
        key_hash: str,
        name: str,
        created_at: datetime,
        last_used_at: datetime | None = None,
        expires_at: datetime | None = None,
        revoked: bool = False,
    ):
        self.id = id
        self.user_id = user_id
        self.key_hash = key_hash
        self.name = name
        self.created_at = created_at
        self.last_used_at = last_used_at
        self.expires_at = expires_at
        self.revoked = revoked

    @property
    def is_valid(self) -> bool:
        """Check if API key is valid (not revoked and not expired)."""
        if self.revoked:
            return False
        if self.expires_at and datetime.now(UTC) > self.expires_at:
            return False
        return True

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked": self.revoked,
        }


class APIKeyRepository(BaseSQLiteRepository):
    """
    SQLite-based API key repository.

    Stores API keys with secure hashing (SHA-256).
    Thread-safe with connection-per-operation pattern.
    """

    def __init__(self, db_path: Path | None = None):
        super().__init__(db_path=db_path, default_db_name="users.db")

    def _init_schema(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    key_hash TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    expires_at TEXT,
                    revoked INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
                CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
            """)

    @staticmethod
    def generate_api_key() -> str:
        """
        Generate a new API key.

        Format: pds_{32-byte-urlsafe-token}

        Returns:
            API key string (plaintext - shown only once)
        """
        token = secrets.token_urlsafe(32)
        return f"pds_{token}"

    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """
        Hash API key using SHA-256.

        Args:
            api_key: Plaintext API key

        Returns:
            Hex-encoded SHA-256 hash
        """
        return hashlib.sha256(api_key.encode()).hexdigest()

    def create_api_key(
        self,
        user_id: str,
        name: str,
        expires_in_days: int | None = None,
    ) -> tuple[APIKey, str]:
        """
        Create new API key for user.

        Args:
            user_id: User ID
            name: Descriptive name for the key (e.g., "CI/CD Pipeline")
            expires_in_days: Optional expiration in days (None = never expires)

        Returns:
            Tuple of (APIKey object, plaintext key)
            Plaintext key is returned only once - must be stored by client

        Raises:
            ValueError: If user not found
        """
        # Generate key
        plaintext_key = self.generate_api_key()
        key_hash = self.hash_api_key(plaintext_key)
        key_id = secrets.token_urlsafe(16)

        now = datetime.now(UTC)
        expires_at = now + timedelta(days=expires_in_days) if expires_in_days else None

        with self._get_connection() as conn:
            # Verify user exists
            user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
            if not user:
                raise ValueError(f"User not found: {user_id}")

            # Insert key
            conn.execute(
                """
                INSERT INTO api_keys (
                    id, user_id, key_hash, name, created_at, expires_at, revoked
                ) VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    key_id,
                    user_id,
                    key_hash,
                    name,
                    now.isoformat(),
                    expires_at.isoformat() if expires_at else None,
                ),
            )

        api_key = APIKey(
            id=key_id,
            user_id=user_id,
            key_hash=key_hash,
            name=name,
            created_at=now,
            expires_at=expires_at,
            revoked=False,
        )

        logger.info(f"Created API key '{name}' for user {user_id} (id={key_id})")
        return api_key, plaintext_key

    def get_by_hash(self, key_hash: str) -> APIKey | None:
        """
        Get API key by hash.

        Args:
            key_hash: SHA-256 hash of API key

        Returns:
            APIKey object or None if not found
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
            return self._row_to_api_key(row) if row else None

    def get_by_id(self, key_id: str) -> APIKey | None:
        """Get API key by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
            return self._row_to_api_key(row) if row else None

    def list_for_user(self, user_id: str, include_revoked: bool = False) -> list[APIKey]:
        """
        List all API keys for user.

        Args:
            user_id: User ID
            include_revoked: Include revoked keys in results

        Returns:
            List of API keys (sorted by created_at desc)
        """
        query = "SELECT * FROM api_keys WHERE user_id = ?"
        params = [user_id]

        if not include_revoked:
            query += " AND revoked = 0"

        query += " ORDER BY created_at DESC"

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_api_key(row) for row in rows]

    def revoke(self, key_id: str, user_id: str) -> bool:
        """
        Revoke API key.

        Args:
            key_id: API key ID to revoke
            user_id: User ID (for authorization - user can only revoke their own keys)

        Returns:
            True if revoked, False if not found or not owned by user
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?",
                (key_id, user_id),
            )
            success = cursor.rowcount > 0

        if success:
            logger.info(f"Revoked API key {key_id} for user {user_id}")
        return success

    def update_last_used(self, key_hash: str) -> bool:
        """
        Update last_used_at timestamp for API key.

        Args:
            key_hash: SHA-256 hash of API key

        Returns:
            True if updated, False if not found
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?",
                (datetime.now(UTC).isoformat(), key_hash),
            )
            return cursor.rowcount > 0

    def count_for_user(self, user_id: str) -> int:
        """Count active (non-revoked) API keys for user."""
        with self._get_connection() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM api_keys WHERE user_id = ? AND revoked = 0",
                (user_id,),
            ).fetchone()[0]

    def _row_to_api_key(self, row: sqlite3.Row) -> APIKey:
        """Convert database row to APIKey object."""
        return APIKey(
            id=row["id"],
            user_id=row["user_id"],
            key_hash=row["key_hash"],
            name=row["name"],
            created_at=datetime.fromisoformat(row["created_at"]),
            last_used_at=datetime.fromisoformat(row["last_used_at"])
            if row["last_used_at"]
            else None,
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            revoked=bool(row["revoked"]),
        )


# Singleton instance
_api_key_repository: APIKeyRepository | None = None


def get_api_key_repository() -> APIKeyRepository:
    """Get singleton API key repository."""
    global _api_key_repository
    if _api_key_repository is None:
        _api_key_repository = APIKeyRepository()
    return _api_key_repository

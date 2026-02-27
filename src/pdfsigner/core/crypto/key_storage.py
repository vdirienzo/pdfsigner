"""
key_storage.py - SQLite persistence layer for cryptographic key management.

Encapsulates all database operations for key storage, retrieval, and lifecycle.
"""

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from pdfsigner.core.crypto.key_types import KeyInfo, KeyStatus, KeyType


class KeyStorage:
    """
    SQLite storage backend for cryptographic keys.

    Handles all database operations: schema initialization, key CRUD,
    metadata management, and cleanup queries.
    """

    def __init__(self, db_path: Path):
        """
        Initialize storage with database path.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)

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

    def init_schema(self) -> None:
        """Create database tables and indexes if they don't exist."""
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

    def get_metadata(self, key: str) -> str | None:
        """Get a metadata value by key, or None if not found."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM metadata WHERE key = ?", (key,))
                row = cursor.fetchone()
                return row[0] if row else None
        except sqlite3.OperationalError:
            return None  # Table doesn't exist yet

    def set_metadata(self, key: str, value: str) -> None:
        """Set a metadata key-value pair (upsert)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (key, value),
            )

    def insert_key(
        self,
        key_id: str,
        key_type: str,
        algorithm: str,
        status: str,
        encrypted_key: bytes,
        created_at: str,
        expires_at: str | None,
        rotated_from: str | None,
        metadata_json: str,
    ) -> None:
        """Insert a new key record into the database."""
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
                    key_type,
                    algorithm,
                    status,
                    encrypted_key,
                    created_at,
                    expires_at,
                    rotated_from,
                    metadata_json,
                ),
            )

    def get_key_full_row(self, key_id: str) -> tuple[Any, ...] | None:
        """
        Get full key row including encrypted material.

        Returns tuple: (key_type, algorithm, status, created_at, expires_at,
                        rotated_from, metadata, encrypted_key) or None.
        """
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
            return cursor.fetchone()

    def get_key_info_row(self, key_id: str) -> tuple[Any, ...] | None:
        """
        Get key info row without encrypted material.

        Returns tuple: (key_type, algorithm, status, created_at, expires_at,
                        rotated_from, metadata) or None.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT key_type, algorithm, status, created_at, expires_at,
                       rotated_from, metadata
                FROM keys WHERE key_id = ?
            """,
                (key_id,),
            )
            return cursor.fetchone()

    def update_key_status(self, key_id: str, status: str) -> None:
        """Update key status in database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE keys SET status = ? WHERE key_id = ?", (status, key_id))

    def update_rotation(self, new_key_id: str, old_key_id: str, old_new_status: str) -> None:
        """Update rotation references: set rotated_from on new key, mark old key."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE keys SET rotated_from = ? WHERE key_id = ?",
                (old_key_id, new_key_id),
            )
            cursor.execute(
                "UPDATE keys SET status = ? WHERE key_id = ?",
                (old_new_status, old_key_id),
            )

    def query_keys(
        self, key_type: str | None = None, status: str | None = None
    ) -> list[tuple[Any, ...]]:
        """
        Query keys with optional filters.

        Returns list of tuples: (key_id, key_type, algorithm, status,
                                  created_at, expires_at, rotated_from, metadata).
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
                params.append(key_type)

            if status:
                query += " AND status = ?"
                params.append(status)

            query += " ORDER BY created_at DESC"

            cursor.execute(query, params)
            return cursor.fetchall()

    def mark_expired_keys(self, now_iso: str) -> int:
        """
        Mark expired active keys and return total expired count.

        Args:
            now_iso: Current timestamp in ISO format

        Returns:
            Number of expired keys in database
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE keys SET status = ? WHERE expires_at < ? AND status = ?",
                (KeyStatus.EXPIRED.value, now_iso, KeyStatus.ACTIVE.value),
            )

            cursor.execute(
                "SELECT COUNT(*) FROM keys WHERE status = ? AND expires_at < ?",
                (KeyStatus.EXPIRED.value, now_iso),
            )
            return cursor.fetchone()[0]

    def delete_key(self, key_id: str) -> None:
        """Delete a key record from the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM keys WHERE key_id = ?", (key_id,))

    @staticmethod
    def row_to_key_info(key_id: str, row: tuple[Any, ...]) -> KeyInfo:
        """
        Convert a key info row tuple to a KeyInfo dataclass.

        Args:
            key_id: The key identifier
            row: Tuple of (key_type, algorithm, status, created_at, expires_at,
                          rotated_from, metadata)
        """
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

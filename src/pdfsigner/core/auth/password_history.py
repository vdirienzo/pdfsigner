"""
password_history.py - Password history storage

SQLite-backed password history repository for preventing password reuse.
Supports NIST 800-53 IA-5(1)(e) compliance.

Author: Homero Thompson del Lago del Terror
"""

import sqlite3
from pathlib import Path

from loguru import logger

from pdfsigner.core.base_repository import BaseSQLiteRepository


class PasswordHistoryRepository(BaseSQLiteRepository):
    """
    SQLite-based password history storage.

    Stores hashed passwords for history checking to prevent
    password reuse within the configured history window.

    Thread-safe with connection-per-operation pattern.
    """

    def __init__(self, db_path: Path | None = None):
        super().__init__(db_path=db_path, default_db_name="password_history.db")

    def _init_schema(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(user_id, password_hash)
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_password_history_user "
                "ON password_history(user_id, created_at DESC)"
            )

    def add_password(self, user_id: str, password_hash: str) -> None:
        """
        Add password hash to history.

        Args:
            user_id: User ID
            password_hash: Argon2 hash of password
        """
        from datetime import UTC, datetime

        with self._get_connection() as conn:
            try:
                conn.execute(
                    "INSERT INTO password_history (user_id, password_hash, created_at) "
                    "VALUES (?, ?, ?)",
                    (user_id, password_hash, datetime.now(UTC).isoformat()),
                )
                logger.debug(f"Added password to history for user: {user_id}")
            except sqlite3.IntegrityError:
                # Duplicate hash for user - already in history
                logger.debug(f"Password already in history for user: {user_id}")

    def get_history(self, user_id: str, limit: int) -> list[str]:
        """
        Get recent password hashes for user.

        Args:
            user_id: User ID
            limit: Maximum number of passwords to return

        Returns:
            List of password hashes (most recent first)
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT password_hash FROM password_history WHERE user_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
            return [row["password_hash"] for row in rows]

    def clear_history(self, user_id: str) -> int:
        """
        Clear password history for user.

        Args:
            user_id: User ID

        Returns:
            Number of records deleted
        """
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM password_history WHERE user_id = ?", (user_id,))
            deleted = cursor.rowcount
            if deleted > 0:
                logger.info(f"Cleared {deleted} password history records for user: {user_id}")
            return deleted

"""
session_storage.py - SQLite storage for session data

Handles all database operations for session management.
Thread-safe with connection-per-operation pattern.
"""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.session.session_types import Session


class SessionStorage:
    """
    SQLite-based storage for user sessions.

    Handles CRUD operations and cleanup for session records.
    Thread-safe with connection-per-operation pattern.
    """

    def __init__(self, db_path: Path):
        """
        Initialize session storage.

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get database connection with automatic cleanup."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_activity TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
            """)

    def insert_session(self, session: Session) -> None:
        """
        Insert a new session into the database.

        Args:
            session: Session to insert
        """
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO sessions (
                    id, user_id, created_at, last_activity, expires_at, ip_address, user_agent
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.id,
                    session.user_id,
                    session.created_at.isoformat(),
                    session.last_activity.isoformat(),
                    session.expires_at.isoformat(),
                    session.ip_address,
                    session.user_agent,
                ),
            )

    def insert_session_with_limit_check(self, session: Session, max_sessions: int) -> int:
        """
        Atomically check active session count and insert a new session.

        Uses BEGIN IMMEDIATE to prevent TOCTOU race conditions.

        Args:
            session: Session to insert
            max_sessions: Maximum allowed active sessions

        Returns:
            Current active session count before insert

        Raises:
            ValueError: If active session count >= max_sessions
        """
        now_iso = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            active_count = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND expires_at > ?",
                (session.user_id, now_iso),
            ).fetchone()[0]
            if active_count >= max_sessions:
                raise ValueError(
                    f"User {session.user_id} has {active_count} active sessions. "
                    f"Maximum allowed: {max_sessions}."
                )

            conn.execute(
                """
                INSERT INTO sessions (
                    id, user_id, created_at, last_activity, expires_at, ip_address, user_agent
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.id,
                    session.user_id,
                    session.created_at.isoformat(),
                    session.last_activity.isoformat(),
                    session.expires_at.isoformat(),
                    session.ip_address,
                    session.user_agent,
                ),
            )
        return active_count

    def get_session(self, session_id: str) -> Session | None:
        """
        Get session by ID.

        Args:
            session_id: Session ID

        Returns:
            Session if found, None otherwise
        """
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
            if not row:
                return None
            return Session.from_dict(dict(row))

    def update_activity(
        self, session_id: str, last_activity: datetime, expires_at: datetime
    ) -> None:
        """
        Update session last activity and expiration.

        Args:
            session_id: Session ID
            last_activity: New last activity timestamp
            expires_at: New expiration timestamp
        """
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE sessions
                SET last_activity = ?, expires_at = ?
                WHERE id = ?
                """,
                (last_activity.isoformat(), expires_at.isoformat(), session_id),
            )

    def delete_session(self, session_id: str) -> bool:
        """
        Delete session by ID.

        Args:
            session_id: Session ID

        Returns:
            True if session was deleted
        """
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            return cursor.rowcount > 0

    def delete_user_sessions(self, user_id: str) -> int:
        """
        Delete all sessions for a user.

        Args:
            user_id: User ID

        Returns:
            Number of sessions deleted
        """
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            return cursor.rowcount

    def get_user_sessions(self, user_id: str) -> list[Session]:
        """
        Get all sessions for a user.

        Args:
            user_id: User ID

        Returns:
            List of sessions ordered by creation time (newest first)
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
            ).fetchall()
            return [Session.from_dict(dict(row)) for row in rows]

    def delete_expired(self) -> int:
        """
        Delete all expired sessions.

        Returns:
            Number of sessions deleted
        """
        now = datetime.now(UTC).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            count = cursor.rowcount

        if count > 0:
            logger.info(f"Cleaned up {count} expired sessions")
        return count

    def replace_session(self, old_session_id: str, new_session: Session) -> None:
        """
        Atomically insert a new session and delete an old one.

        Args:
            old_session_id: ID of the session to delete
            new_session: New session to insert
        """
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO sessions (
                    id, user_id, created_at, last_activity, expires_at, ip_address, user_agent
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_session.id,
                    new_session.user_id,
                    new_session.created_at.isoformat(),
                    new_session.last_activity.isoformat(),
                    new_session.expires_at.isoformat(),
                    new_session.ip_address,
                    new_session.user_agent,
                ),
            )
            conn.execute("DELETE FROM sessions WHERE id = ?", (old_session_id,))

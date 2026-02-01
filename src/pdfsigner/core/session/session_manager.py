"""
session_manager.py - Session management for healthcare compliance

Manages user sessions with automatic timeout and maximum session limits.
HIPAA: §164.312(a)(2)(iii) - Automatic logoff
"""

import sqlite3
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from loguru import logger

from pdfsigner.config.settings import get_settings
from pdfsigner.exceptions import SessionExpiredError


@dataclass
class Session:
    """
    User session for healthcare compliance.

    Tracks user activity with automatic timeout and expiration.
    """

    id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    ip_address: str | None = None
    user_agent: str | None = None

    @property
    def is_active(self) -> bool:
        """Check if session is still active (not expired)."""
        return datetime.now() < self.expires_at

    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return not self.is_active

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        """Create session from dictionary."""
        return cls(
            id=data["id"],
            user_id=data["user_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            last_activity=datetime.fromisoformat(data["last_activity"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
        )


class SessionManager:
    """
    SQLite-based session manager for healthcare compliance.

    Features:
    - Automatic session timeout (configurable)
    - Maximum concurrent sessions per user
    - Session cleanup and validation
    - Thread-safe with connection-per-operation pattern

    Only enforced when healthcare_mode=True in settings.
    """

    def __init__(self, db_path: Path | None = None):
        """
        Initialize session manager.

        Args:
            db_path: Path to SQLite database. Default: ~/.config/pdfsigner/sessions.db
        """
        if db_path is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / "sessions.db"

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

    def _is_healthcare_mode(self) -> bool:
        """Check if healthcare mode is enabled."""
        return get_settings().healthcare_mode

    def _get_timeout_minutes(self) -> int:
        """Get session timeout from settings."""
        return get_settings().healthcare_session_timeout_minutes

    def _get_max_sessions(self) -> int:
        """Get max sessions per user from settings."""
        return get_settings().healthcare_max_sessions

    def create_session(
        self, user_id: str, ip_address: str | None = None, user_agent: str | None = None
    ) -> Session:
        """
        Create new session for user.

        Args:
            user_id: User ID
            ip_address: Client IP address (optional)
            user_agent: Client user agent (optional)

        Returns:
            Created session

        Note:
            If healthcare_mode=False, session is still created but not enforced.
            Enforces maximum concurrent sessions if healthcare_mode=True.
        """
        now = datetime.now()
        timeout_minutes = self._get_timeout_minutes()
        expires_at = now + timedelta(minutes=timeout_minutes)

        session = Session(
            id=str(uuid.uuid4()),
            user_id=user_id,
            created_at=now,
            last_activity=now,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Enforce max sessions if healthcare mode is enabled
        if self._is_healthcare_mode():
            self.enforce_max_sessions(user_id)

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

        logger.info(
            f"Created session {session.id} for user {user_id} "
            f"(expires: {expires_at.isoformat()}, healthcare_mode={self._is_healthcare_mode()})"
        )
        return session

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
            return self._row_to_session(row)

    def validate_session(self, session_id: str) -> bool:
        """
        Validate session is active and not expired.

        Args:
            session_id: Session ID

        Returns:
            True if session is valid, False otherwise

        Note:
            If healthcare_mode=False, always returns True (no enforcement).
        """
        # No validation when healthcare mode is disabled
        if not self._is_healthcare_mode():
            return True

        session = self.get_session(session_id)
        if not session:
            logger.warning(f"Session {session_id} not found")
            return False

        if session.is_expired:
            logger.warning(f"Session {session_id} expired at {session.expires_at.isoformat()}")
            return False

        return True

    def touch_session(self, session_id: str) -> None:
        """
        Update session last activity and extend expiration.

        Args:
            session_id: Session ID

        Raises:
            SessionExpiredError: If session is expired
        """
        # No-op when healthcare mode is disabled
        if not self._is_healthcare_mode():
            return

        session = self.get_session(session_id)
        if not session:
            raise SessionExpiredError(session_id)

        if session.is_expired:
            raise SessionExpiredError(session_id)

        now = datetime.now()
        timeout_minutes = self._get_timeout_minutes()
        new_expires_at = now + timedelta(minutes=timeout_minutes)

        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE sessions
                SET last_activity = ?, expires_at = ?
                WHERE id = ?
                """,
                (now.isoformat(), new_expires_at.isoformat(), session_id),
            )

        logger.debug(f"Extended session {session_id} until {new_expires_at.isoformat()}")

    def terminate_session(self, session_id: str) -> None:
        """
        Terminate (delete) session.

        Args:
            session_id: Session ID
        """
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            deleted = cursor.rowcount > 0

        if deleted:
            logger.info(f"Terminated session {session_id}")

    def terminate_user_sessions(self, user_id: str) -> int:
        """
        Terminate all sessions for a user.

        Args:
            user_id: User ID

        Returns:
            Number of sessions terminated
        """
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            count = cursor.rowcount

        if count > 0:
            logger.info(f"Terminated {count} sessions for user {user_id}")
        return count

    def get_user_sessions(self, user_id: str) -> list[Session]:
        """
        Get all active sessions for a user.

        Args:
            user_id: User ID

        Returns:
            List of sessions (may include expired ones)
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
            ).fetchall()
            return [self._row_to_session(row) for row in rows]

    def cleanup_expired(self) -> int:
        """
        Delete all expired sessions.

        Returns:
            Number of sessions deleted
        """
        now = datetime.now().isoformat()

        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            count = cursor.rowcount

        if count > 0:
            logger.info(f"Cleaned up {count} expired sessions")
        return count

    def enforce_max_sessions(self, user_id: str) -> None:
        """
        Enforce maximum concurrent sessions for user.

        Terminates oldest sessions if limit is exceeded.

        Args:
            user_id: User ID
        """
        # No enforcement when healthcare mode is disabled
        if not self._is_healthcare_mode():
            return

        max_sessions = self._get_max_sessions()
        sessions = self.get_user_sessions(user_id)

        # Remove expired sessions first
        active_sessions = [s for s in sessions if s.is_active]

        # If still over limit, terminate oldest sessions
        if len(active_sessions) >= max_sessions:
            # Sort by created_at ascending (oldest first)
            sorted_sessions = sorted(active_sessions, key=lambda s: s.created_at)
            # Terminate oldest sessions to make room for new one
            to_terminate = sorted_sessions[: len(sorted_sessions) - max_sessions + 1]
            for session in to_terminate:
                self.terminate_session(session.id)
                logger.info(
                    f"Terminated oldest session {session.id} for user {user_id} "
                    f"(max_sessions={max_sessions})"
                )

    def _row_to_session(self, row: sqlite3.Row) -> Session:
        """Convert database row to Session object."""
        return Session.from_dict(dict(row))


# Singleton instance
_session_manager: SessionManager | None = None


def get_session_manager() -> SessionManager:
    """Get singleton session manager."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager

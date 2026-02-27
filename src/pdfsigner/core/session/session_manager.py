"""
session_manager.py - Session management orchestrator for healthcare compliance

Orchestrates session lifecycle with automatic timeout and maximum session limits.
HIPAA: SS164.312(a)(2)(iii) - Automatic logoff.
"""

import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from loguru import logger

from pdfsigner.config.settings import get_settings
from pdfsigner.core.session.session_storage import SessionStorage
from pdfsigner.core.session.session_types import Session
from pdfsigner.exceptions import MaxSessionsExceededError, SessionExpiredError

# Re-export for backward compatibility
__all__ = ["Session", "SessionManager", "get_session_manager"]


class SessionManager:
    """
    Session management orchestrator for healthcare compliance.

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

        self._storage = SessionStorage(db_path)
        # Expose db_path for backward compatibility
        self.db_path = db_path
        # Expose _get_connection for tests that need direct DB access
        self._get_connection = self._storage._get_connection

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
        now = datetime.now(UTC)
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

        if self._is_healthcare_mode():
            max_sessions = self._get_max_sessions()
            try:
                self._storage.insert_session_with_limit_check(session, max_sessions)
            except ValueError:
                active_count = self.get_active_session_count(user_id)
                raise MaxSessionsExceededError(
                    max_sessions=max_sessions,
                    message=(
                        f"User {user_id} has {active_count} active sessions. "
                        f"Maximum allowed: {max_sessions}. "
                        "Please terminate an existing session first."
                    ),
                )
        else:
            self._storage.insert_session(session)

        logger.info(
            f"Created session {session.id[:8]}... for user {user_id} "
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
        return self._storage.get_session(session_id)

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
        if not self._is_healthcare_mode():
            return True

        session = self._storage.get_session(session_id)
        if not session:
            logger.warning(f"Session {session_id[:8]}... not found")
            return False

        if session.is_expired:
            logger.warning(
                f"Session {session_id[:8]}... expired at {session.expires_at.isoformat()}"
            )
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
        if not self._is_healthcare_mode():
            return

        session = self._storage.get_session(session_id)
        if not session:
            raise SessionExpiredError(session_id)

        if session.is_expired:
            raise SessionExpiredError(session_id)

        now = datetime.now(UTC)
        timeout_minutes = self._get_timeout_minutes()
        new_expires_at = now + timedelta(minutes=timeout_minutes)

        self._storage.update_activity(session_id, now, new_expires_at)
        logger.debug(f"Extended session {session_id[:8]}... until {new_expires_at.isoformat()}")

    def regenerate_session_id(self, old_session_id: str) -> Session:
        """
        Regenerate session ID to prevent Session Fixation attacks.

        Creates a new session with a new ID, copying data from the old session.
        The old session is invalidated/deleted.

        Args:
            old_session_id: ID of the existing session to regenerate

        Returns:
            New session with fresh ID and copied data

        Raises:
            ValueError: If old session does not exist
        """
        old_session = self._storage.get_session(old_session_id)
        if not old_session:
            raise ValueError(f"Session {old_session_id} not found")

        now = datetime.now(UTC)
        timeout_minutes = self._get_timeout_minutes()
        expires_at = now + timedelta(minutes=timeout_minutes)

        new_session = Session(
            id=str(uuid.uuid4()),
            user_id=old_session.user_id,
            created_at=now,
            last_activity=now,
            expires_at=expires_at,
            ip_address=old_session.ip_address,
            user_agent=old_session.user_agent,
        )

        self._storage.replace_session(old_session_id, new_session)

        logger.info(
            f"Regenerated session for user {new_session.user_id}: "
            f"{old_session_id[:8]}... -> {new_session.id[:8]}... (Session Fixation prevention)"
        )

        return new_session

    def terminate_session(self, session_id: str) -> None:
        """
        Terminate (delete) session.

        Args:
            session_id: Session ID
        """
        deleted = self._storage.delete_session(session_id)
        if deleted:
            logger.info(f"Terminated session {session_id[:8]}...")

    def terminate_user_sessions(self, user_id: str) -> int:
        """
        Terminate all sessions for a user.

        Args:
            user_id: User ID

        Returns:
            Number of sessions terminated
        """
        count = self._storage.delete_user_sessions(user_id)
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
        return self._storage.get_user_sessions(user_id)

    def get_active_session_count(self, user_id: str) -> int:
        """
        Get count of active (non-expired) sessions for a user.

        Args:
            user_id: User ID

        Returns:
            Number of active sessions
        """
        sessions = self._storage.get_user_sessions(user_id)
        return len([s for s in sessions if s.is_active])

    def cleanup_expired(self) -> int:
        """
        Delete all expired sessions.

        Returns:
            Number of sessions deleted
        """
        return self._storage.delete_expired()

    def enforce_max_sessions(self, user_id: str) -> None:
        """
        Enforce maximum concurrent sessions for user.

        Terminates oldest sessions if limit is exceeded.

        Args:
            user_id: User ID
        """
        if not self._is_healthcare_mode():
            return

        max_sessions = self._get_max_sessions()
        sessions = self._storage.get_user_sessions(user_id)
        active_sessions = [s for s in sessions if s.is_active]

        if len(active_sessions) >= max_sessions:
            sorted_sessions = sorted(active_sessions, key=lambda s: s.created_at)
            to_terminate = sorted_sessions[: len(sorted_sessions) - max_sessions + 1]
            for session in to_terminate:
                self.terminate_session(session.id)
                logger.info(
                    f"Terminated oldest session {session.id[:8]}... for user {user_id} "
                    f"(max_sessions={max_sessions})"
                )


# Singleton instance
_session_manager: SessionManager | None = None
_session_manager_lock = threading.Lock()


def get_session_manager() -> SessionManager:
    """Get singleton session manager."""
    global _session_manager
    with _session_manager_lock:
        if _session_manager is None:
            _session_manager = SessionManager()
        return _session_manager

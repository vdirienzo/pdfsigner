"""
JWT blacklist for token revocation.

Provides SQLite-backed token blacklist for real logout functionality.
When a user logs out, their JWT is added to the blacklist and subsequent
requests with that token are rejected.
"""

import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

from loguru import logger


class JWTBlacklist:
    """
    JWT token blacklist with SQLite storage.

    Stores revoked tokens (by JTI) with their expiration times.
    Automatically cleans up expired tokens to prevent unbounded growth.

    Thread-safe using a lock for all database operations.
    """

    def __init__(self, db_path: Path | str | None = None):
        """
        Initialize JWT blacklist.

        Args:
            db_path: Path to SQLite database file (defaults to ~/.config/pdfsigner/jwt_blacklist.db)
        """
        if db_path is None:
            db_path = Path.home() / ".config" / "pdfsigner" / "jwt_blacklist.db"
        else:
            db_path = Path(db_path)

        self.db_path = db_path
        self._lock = Lock()

        # Ensure directory exists
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_db()

    def _init_db(self) -> None:
        """Create blacklist table if it doesn't exist."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS jwt_blacklist (
                        jti TEXT PRIMARY KEY,
                        expires_at TEXT NOT NULL,
                        revoked_at TEXT NOT NULL,
                        reason TEXT
                    )
                    """
                )
                # Index for efficient expiration queries
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_expires_at
                    ON jwt_blacklist(expires_at)
                    """
                )
                conn.commit()

    def add_token(
        self,
        jti: str,
        expires_at: datetime,
        reason: str = "logout",
    ) -> None:
        """
        Add token to blacklist.

        Args:
            jti: JWT ID (unique token identifier)
            expires_at: Token expiration time (UTC)
            reason: Reason for revocation (default: "logout")

        Example:
            >>> blacklist = JWTBlacklist()
            >>> blacklist.add_token("abc123", datetime.now(UTC) + timedelta(hours=1))
        """
        revoked_at = datetime.now(UTC)

        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                try:
                    conn.execute(
                        """
                        INSERT INTO jwt_blacklist (jti, expires_at, revoked_at, reason)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            jti,
                            expires_at.isoformat(),
                            revoked_at.isoformat(),
                            reason,
                        ),
                    )
                    conn.commit()
                    logger.info(f"Added token {jti[:8]}... to blacklist (reason: {reason})")
                except sqlite3.IntegrityError:
                    # Token already blacklisted (idempotent)
                    logger.debug(f"Token {jti[:8]}... already in blacklist")

    def is_blacklisted(self, jti: str) -> bool:
        """
        Check if token is blacklisted.

        Args:
            jti: JWT ID to check

        Returns:
            True if token is blacklisted and not expired, False otherwise

        Example:
            >>> blacklist = JWTBlacklist()
            >>> if blacklist.is_blacklisted("abc123"):
            ...     raise HTTPException(status_code=401, detail="Token revoked")
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """
                    SELECT expires_at FROM jwt_blacklist
                    WHERE jti = ?
                    """,
                    (jti,),
                )
                row = cursor.fetchone()

                if row is None:
                    return False

                # Check if token is expired (no longer needs blacklisting)
                expires_at = datetime.fromisoformat(row[0])
                if expires_at < datetime.now(UTC):
                    # Token expired naturally, can be cleaned up
                    return False

                return True

    def cleanup_expired(self) -> int:
        """
        Remove expired tokens from blacklist.

        Tokens that have passed their expiration time can be safely removed
        as they would be rejected by JWT validation anyway.

        Returns:
            Number of tokens removed

        Example:
            >>> blacklist = JWTBlacklist()
            >>> count = blacklist.cleanup_expired()
            >>> print(f"Cleaned up {count} expired tokens")
        """
        now = datetime.now(UTC).isoformat()

        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """
                    DELETE FROM jwt_blacklist
                    WHERE expires_at < ?
                    """,
                    (now,),
                )
                count = cursor.rowcount
                conn.commit()

                if count > 0:
                    logger.info(f"Cleaned up {count} expired tokens from blacklist")

                return count

    def get_stats(self) -> dict[str, Any]:
        """
        Get blacklist statistics.

        Returns:
            Dictionary with total_tokens, active_tokens, and expired_tokens counts

        Example:
            >>> blacklist = JWTBlacklist()
            >>> stats = blacklist.get_stats()
            >>> print(f"Active blacklisted tokens: {stats['active_tokens']}")
        """
        now = datetime.now(UTC).isoformat()

        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                # Total tokens
                cursor = conn.execute("SELECT COUNT(*) FROM jwt_blacklist")
                total = cursor.fetchone()[0]

                # Active tokens (not yet expired)
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM jwt_blacklist WHERE expires_at >= ?",
                    (now,),
                )
                active = cursor.fetchone()[0]

                expired = total - active

                return {
                    "total_tokens": total,
                    "active_tokens": active,
                    "expired_tokens": expired,
                }

    def clear_all(self) -> int:
        """
        Clear all tokens from blacklist.

        WARNING: This removes all blacklisted tokens, including active ones.
        Use with caution (mainly for testing).

        Returns:
            Number of tokens removed
        """
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("DELETE FROM jwt_blacklist")
                count = cursor.rowcount
                conn.commit()

                logger.warning(f"Cleared all {count} tokens from blacklist")
                return count


# --- Singleton Instance ---

_blacklist_instance: JWTBlacklist | None = None
_blacklist_lock = Lock()


def get_jwt_blacklist() -> JWTBlacklist:
    """
    Get singleton JWT blacklist instance.

    Returns:
        Global JWTBlacklist instance

    Example:
        >>> from pdfsigner.core.auth.jwt_blacklist import get_jwt_blacklist
        >>> blacklist = get_jwt_blacklist()
        >>> blacklist.add_token("abc123", datetime.now(UTC) + timedelta(hours=1))
    """
    global _blacklist_instance

    if _blacklist_instance is None:
        with _blacklist_lock:
            if _blacklist_instance is None:
                _blacklist_instance = JWTBlacklist()

    return _blacklist_instance


def generate_jti() -> str:
    """
    Generate unique JWT ID.

    Returns:
        Random UUID string for use as JTI

    Example:
        >>> jti = generate_jti()
        >>> # Use in JWT claims: {"jti": jti, "sub": "user123", ...}
    """
    return str(uuid.uuid4())


# --- Public Exports ---

__all__ = [
    "JWTBlacklist",
    "get_jwt_blacklist",
    "generate_jti",
]

"""
emergency_access.py - Emergency access (break-glass) data models and repository

Implements HIPAA §164.312(a)(2)(ii) emergency access procedure.
Allows authorized users to request temporary elevated access during emergencies.
"""

import json
import sqlite3
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from loguru import logger


class EmergencyAccessStatus(str, Enum):
    """Status of emergency access request."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


class EmergencyAccessRequest:
    """
    Emergency access request with approval workflow.

    Represents a request for temporary elevated access during emergencies.
    Requires admin approval unless auto-approve is configured.
    """

    def __init__(
        self,
        id: str,
        requester_id: str,
        reason: str,
        status: EmergencyAccessStatus,
        requested_at: datetime,
        approved_by: str | None = None,
        approved_at: datetime | None = None,
        expires_at: datetime | None = None,
        revoked_by: str | None = None,
        revoked_at: datetime | None = None,
        documents_accessed: list[str] | None = None,
    ):
        """
        Initialize emergency access request.

        Args:
            id: Unique request ID (UUID)
            requester_id: User ID requesting emergency access
            reason: Justification for emergency access
            status: Current status of the request
            requested_at: Timestamp when request was created
            approved_by: User ID who approved the request
            approved_at: Timestamp when request was approved
            expires_at: Timestamp when access expires
            revoked_by: User ID who revoked the access
            revoked_at: Timestamp when access was revoked
            documents_accessed: List of document paths accessed using this emergency access
        """
        self.id = id
        self.requester_id = requester_id
        self.reason = reason
        self.status = status
        self.requested_at = requested_at
        self.approved_by = approved_by
        self.approved_at = approved_at
        self.expires_at = expires_at
        self.revoked_by = revoked_by
        self.revoked_at = revoked_at
        self.documents_accessed = documents_accessed or []

    @property
    def is_active(self) -> bool:
        """Check if emergency access is currently active."""
        if self.status != EmergencyAccessStatus.APPROVED:
            return False
        if self.expires_at and datetime.now(UTC) > self.expires_at:
            return False
        return True

    @property
    def is_expired(self) -> bool:
        """Check if emergency access has expired."""
        return self.expires_at is not None and datetime.now(UTC) > self.expires_at

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "requester_id": self.requester_id,
            "reason": self.reason,
            "status": self.status.value,
            "requested_at": self.requested_at.isoformat(),
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_by": self.revoked_by,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "documents_accessed": self.documents_accessed,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EmergencyAccessRequest":
        """Create request from dictionary."""

        def parse_datetime(val: str | None) -> datetime | None:
            return datetime.fromisoformat(val) if val else None

        return cls(
            id=data["id"],
            requester_id=data["requester_id"],
            reason=data["reason"],
            status=EmergencyAccessStatus(data["status"]),
            requested_at=datetime.fromisoformat(data["requested_at"]),
            approved_by=data.get("approved_by"),
            approved_at=parse_datetime(data.get("approved_at")),
            expires_at=parse_datetime(data.get("expires_at")),
            revoked_by=data.get("revoked_by"),
            revoked_at=parse_datetime(data.get("revoked_at")),
            documents_accessed=data.get("documents_accessed", []),
        )

    def __repr__(self) -> str:
        return (
            f"EmergencyAccessRequest(id={self.id}, requester={self.requester_id}, "
            f"status={self.status.value})"
        )


class EmergencyAccessRepository:
    """
    SQLite-based repository for emergency access requests.

    Stores and manages emergency access requests with full audit trail.
    Thread-safe with connection-per-operation pattern.
    """

    def __init__(self, db_path: Path | None = None):
        """
        Initialize repository.

        Args:
            db_path: Path to SQLite database. Default: ~/.config/pdfsigner/emergency.db
        """
        if db_path is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / "emergency.db"

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
                CREATE TABLE IF NOT EXISTS emergency_requests (
                    id TEXT PRIMARY KEY,
                    requester_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    requested_at TEXT NOT NULL,
                    approved_by TEXT,
                    approved_at TEXT,
                    expires_at TEXT,
                    revoked_by TEXT,
                    revoked_at TEXT,
                    documents_accessed TEXT DEFAULT '[]'
                );

                CREATE INDEX IF NOT EXISTS idx_emergency_requester
                ON emergency_requests(requester_id);

                CREATE INDEX IF NOT EXISTS idx_emergency_status
                ON emergency_requests(status);

                CREATE INDEX IF NOT EXISTS idx_emergency_expires
                ON emergency_requests(expires_at);
            """)

    def create_request(self, requester_id: str, reason: str) -> EmergencyAccessRequest:
        """
        Create new emergency access request.

        Args:
            requester_id: User ID requesting access
            reason: Justification for emergency access

        Returns:
            Created EmergencyAccessRequest
        """
        request = EmergencyAccessRequest(
            id=str(uuid.uuid4()),
            requester_id=requester_id,
            reason=reason,
            status=EmergencyAccessStatus.PENDING,
            requested_at=datetime.now(UTC),
        )

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO emergency_requests (
                    id, requester_id, reason, status, requested_at,
                    approved_by, approved_at, expires_at, revoked_by,
                    revoked_at, documents_accessed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.id,
                    request.requester_id,
                    request.reason,
                    request.status.value,
                    request.requested_at.isoformat(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    json.dumps([]),
                ),
            )

        logger.info(f"Created emergency access request: {request.id} by {requester_id}")
        return request

    def get_request(self, request_id: str) -> EmergencyAccessRequest | None:
        """
        Get emergency access request by ID.

        Args:
            request_id: Request ID to retrieve

        Returns:
            EmergencyAccessRequest or None if not found
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM emergency_requests WHERE id = ?", (request_id,)
            ).fetchone()
            return self._row_to_request(row) if row else None

    def get_pending_requests(self) -> list[EmergencyAccessRequest]:
        """
        Get all pending emergency access requests.

        Returns:
            List of pending requests, ordered by request time (oldest first)
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM emergency_requests
                WHERE status = ?
                ORDER BY requested_at ASC
                """,
                (EmergencyAccessStatus.PENDING.value,),
            ).fetchall()
            return [self._row_to_request(row) for row in rows]

    def get_user_requests(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[EmergencyAccessRequest]:
        """
        Get all emergency access requests for a user.

        Args:
            user_id: User ID to filter by
            limit: Maximum number of requests to return
            offset: Pagination offset

        Returns:
            List of user's requests, ordered by request time (newest first)
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM emergency_requests
                WHERE requester_id = ?
                ORDER BY requested_at DESC
                LIMIT ? OFFSET ?
                """,
                (user_id, limit, offset),
            ).fetchall()
            return [self._row_to_request(row) for row in rows]

    def update_request(self, request: EmergencyAccessRequest) -> None:
        """
        Update existing emergency access request.

        Args:
            request: EmergencyAccessRequest to update
        """
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE emergency_requests SET
                    status = ?,
                    approved_by = ?,
                    approved_at = ?,
                    expires_at = ?,
                    revoked_by = ?,
                    revoked_at = ?,
                    documents_accessed = ?
                WHERE id = ?
                """,
                (
                    request.status.value,
                    request.approved_by,
                    request.approved_at.isoformat() if request.approved_at else None,
                    request.expires_at.isoformat() if request.expires_at else None,
                    request.revoked_by,
                    request.revoked_at.isoformat() if request.revoked_at else None,
                    json.dumps(request.documents_accessed),
                    request.id,
                ),
            )

        logger.debug(f"Updated emergency request: {request.id} (status={request.status.value})")

    def get_active_request(self, user_id: str) -> EmergencyAccessRequest | None:
        """
        Get active emergency access request for user.

        An active request is one that is approved and not expired.

        Args:
            user_id: User ID to check

        Returns:
            Active EmergencyAccessRequest or None
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM emergency_requests
                WHERE requester_id = ?
                AND status = ?
                AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY approved_at DESC
                LIMIT 1
                """,
                (user_id, EmergencyAccessStatus.APPROVED.value, datetime.now(UTC).isoformat()),
            ).fetchall()

            if not rows:
                return None

            request = self._row_to_request(rows[0])
            # Double-check it's still active
            return request if request.is_active else None

    def cleanup_expired_requests(self) -> int:
        """
        Update status of expired requests.

        Finds approved requests with expires_at in the past and updates
        their status to EXPIRED.

        Returns:
            Number of requests marked as expired
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE emergency_requests
                SET status = ?
                WHERE status = ?
                AND expires_at IS NOT NULL
                AND expires_at < ?
                """,
                (
                    EmergencyAccessStatus.EXPIRED.value,
                    EmergencyAccessStatus.APPROVED.value,
                    datetime.now(UTC).isoformat(),
                ),
            )
            count = cursor.rowcount

        if count > 0:
            logger.info(f"Marked {count} emergency requests as expired")

        return count

    def _row_to_request(self, row: sqlite3.Row) -> EmergencyAccessRequest:
        """Convert database row to EmergencyAccessRequest object."""
        data = dict(row)
        # Parse JSON documents_accessed
        docs = data.get("documents_accessed", "[]")
        data["documents_accessed"] = json.loads(docs) if isinstance(docs, str) else docs
        return EmergencyAccessRequest.from_dict(data)


# Singleton instance
_emergency_repository: EmergencyAccessRepository | None = None


def get_emergency_repository() -> EmergencyAccessRepository:
    """Get singleton emergency access repository."""
    global _emergency_repository
    if _emergency_repository is None:
        _emergency_repository = EmergencyAccessRepository()
    return _emergency_repository

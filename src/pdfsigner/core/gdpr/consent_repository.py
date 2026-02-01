"""
consent_repository.py - Consent record persistence with SQLite

Provides CRUD operations for GDPR consent records.
GDPR Article 7: Requirements for consent.
"""

import sqlite3
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.gdpr.consent_types import ConsentType


@dataclass
class ConsentRecord:
    """
    User consent record.

    Attributes:
        id: Unique consent record ID (UUID)
        user_id: User ID who gave/withdrew consent
        consent_type: Type of consent (processing, analytics, etc.)
        granted: Whether consent is granted (True) or withdrawn (False)
        granted_at: Timestamp when consent was granted
        withdrawn_at: Timestamp when consent was withdrawn (None if still active)
        ip_address: IP address when consent was recorded
        user_agent: User agent string when consent was recorded
        policy_version: Version of privacy policy accepted
    """

    id: str
    user_id: str
    consent_type: ConsentType
    granted: bool
    granted_at: datetime
    withdrawn_at: datetime | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    policy_version: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "consent_type": self.consent_type.value,
            "granted": self.granted,
            "granted_at": self.granted_at.isoformat(),
            "withdrawn_at": self.withdrawn_at.isoformat() if self.withdrawn_at else None,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "policy_version": self.policy_version,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ConsentRecord":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            user_id=data["user_id"],
            consent_type=ConsentType(data["consent_type"]),
            granted=data["granted"],
            granted_at=datetime.fromisoformat(data["granted_at"]),
            withdrawn_at=(
                datetime.fromisoformat(data["withdrawn_at"]) if data.get("withdrawn_at") else None
            ),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            policy_version=data.get("policy_version"),
        )


class ConsentRepository:
    """
    SQLite-based consent record repository.

    Stores user consent records with full audit trail.
    Thread-safe with connection-per-operation pattern.
    """

    def __init__(self, db_path: Path | None = None):
        """
        Initialize consent repository.

        Args:
            db_path: Path to SQLite database. Default: ~/.config/pdfsigner/consents.db
        """
        if db_path is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / "consents.db"

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
                CREATE TABLE IF NOT EXISTS consents (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    consent_type TEXT NOT NULL,
                    granted INTEGER NOT NULL,
                    granted_at TEXT NOT NULL,
                    withdrawn_at TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    policy_version TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_consents_user_id
                ON consents(user_id);

                CREATE INDEX IF NOT EXISTS idx_consents_user_type
                ON consents(user_id, consent_type);

                CREATE INDEX IF NOT EXISTS idx_consents_granted_at
                ON consents(granted_at);
            """)

    def save_consent(self, consent: ConsentRecord) -> ConsentRecord:
        """
        Save consent record to database.

        Args:
            consent: ConsentRecord to save

        Returns:
            Saved consent record
        """
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO consents (
                    id, user_id, consent_type, granted, granted_at,
                    withdrawn_at, ip_address, user_agent, policy_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    consent.id,
                    consent.user_id,
                    consent.consent_type.value,
                    1 if consent.granted else 0,
                    consent.granted_at.isoformat(),
                    consent.withdrawn_at.isoformat() if consent.withdrawn_at else None,
                    consent.ip_address,
                    consent.user_agent,
                    consent.policy_version,
                ),
            )

        logger.debug(
            f"Saved consent: user={consent.user_id}, type={consent.consent_type.value}, "
            f"granted={consent.granted}"
        )
        return consent

    def get_user_consents(self, user_id: str, active_only: bool = False) -> list[ConsentRecord]:
        """
        Get all consent records for a user.

        Args:
            user_id: User ID to get consents for
            active_only: If True, only return currently active (not withdrawn) consents

        Returns:
            List of consent records, ordered by granted_at descending
        """
        query = """
            SELECT * FROM consents
            WHERE user_id = ?
        """
        params: list = [user_id]

        if active_only:
            query += " AND granted = 1 AND withdrawn_at IS NULL"

        query += " ORDER BY granted_at DESC"

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_consent(row) for row in rows]

    def get_consent_history(self, user_id: str, consent_type: ConsentType) -> list[ConsentRecord]:
        """
        Get complete history of a specific consent type for a user.

        Includes all grants and withdrawals in chronological order.

        Args:
            user_id: User ID
            consent_type: Type of consent to get history for

        Returns:
            List of consent records, ordered by granted_at descending
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM consents
                WHERE user_id = ? AND consent_type = ?
                ORDER BY granted_at DESC
                """,
                (user_id, consent_type.value),
            ).fetchall()
            return [self._row_to_consent(row) for row in rows]

    def get_latest_consent(self, user_id: str, consent_type: ConsentType) -> ConsentRecord | None:
        """
        Get the most recent consent record for a specific type.

        Args:
            user_id: User ID
            consent_type: Type of consent

        Returns:
            Latest consent record, or None if no record exists
        """
        with self._get_connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM consents
                WHERE user_id = ? AND consent_type = ?
                ORDER BY granted_at DESC
                LIMIT 1
                """,
                (user_id, consent_type.value),
            ).fetchone()
            return self._row_to_consent(row) if row else None

    def withdraw_consent(
        self,
        user_id: str,
        consent_type: ConsentType,
        withdrawn_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> ConsentRecord:
        """
        Withdraw user consent by creating a new record with granted=False.

        GDPR Article 7(3): Consent can be withdrawn at any time.

        Args:
            user_id: User ID withdrawing consent
            consent_type: Type of consent to withdraw
            withdrawn_at: Timestamp of withdrawal
            ip_address: IP address when withdrawal was recorded
            user_agent: User agent when withdrawal was recorded

        Returns:
            New consent record with granted=False
        """
        withdrawal_record = ConsentRecord(
            id=str(uuid.uuid4()),
            user_id=user_id,
            consent_type=consent_type,
            granted=False,
            granted_at=withdrawn_at,
            withdrawn_at=withdrawn_at,
            ip_address=ip_address,
            user_agent=user_agent,
            policy_version=None,
        )

        return self.save_consent(withdrawal_record)

    def _row_to_consent(self, row: sqlite3.Row) -> ConsentRecord:
        """Convert database row to ConsentRecord object."""
        data = dict(row)
        data["granted"] = bool(data["granted"])
        return ConsentRecord.from_dict(data)


# Singleton instance
_consent_repository: ConsentRepository | None = None


def get_consent_repository() -> ConsentRepository:
    """Get singleton consent repository."""
    global _consent_repository
    if _consent_repository is None:
        _consent_repository = ConsentRepository()
    return _consent_repository


__all__ = ["ConsentRecord", "ConsentRepository", "get_consent_repository"]

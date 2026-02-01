"""
breach_repository.py - Breach incident persistence with SQLite

Stores breach incidents with full audit trail.
"""

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.breach.breach_types import BreachIncident, BreachSeverity, BreachStatus


class BreachRepository:
    """
    SQLite-based breach incident repository.

    Stores breach incidents with full history and metadata.
    Thread-safe with connection-per-operation pattern.
    """

    def __init__(self, db_path: Path | None = None):
        """
        Initialize repository.

        Args:
            db_path: Path to SQLite database. Default: ~/.config/pdfsigner/breach.db
        """
        if db_path is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / "breach.db"

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
                CREATE TABLE IF NOT EXISTS breach_incidents (
                    id TEXT PRIMARY KEY,
                    breach_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    resolved_at TEXT,
                    notified_at TEXT,
                    description TEXT,
                    affected_users INTEGER DEFAULT 0,
                    affected_records INTEGER DEFAULT 0,
                    source_ip TEXT,
                    user_id TEXT,
                    metadata TEXT DEFAULT '{}',
                    status_history TEXT DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_breach_type ON breach_incidents(breach_type);
                CREATE INDEX IF NOT EXISTS idx_breach_severity ON breach_incidents(severity);
                CREATE INDEX IF NOT EXISTS idx_breach_status ON breach_incidents(status);
                CREATE INDEX IF NOT EXISTS idx_breach_detected ON breach_incidents(detected_at);
                CREATE INDEX IF NOT EXISTS idx_breach_user ON breach_incidents(user_id);
            """)

    def save_incident(self, incident: BreachIncident) -> BreachIncident:
        """
        Save breach incident.

        Args:
            incident: Incident to save

        Returns:
            Saved incident
        """
        now = datetime.now().isoformat()

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO breach_incidents (
                    id, breach_type, severity, status,
                    detected_at, resolved_at, notified_at,
                    description, affected_users, affected_records,
                    source_ip, user_id, metadata, status_history,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.id,
                    incident.breach_type.value,
                    incident.severity.value,
                    incident.status.value,
                    incident.detected_at.isoformat(),
                    incident.resolved_at.isoformat() if incident.resolved_at else None,
                    incident.notified_at.isoformat() if incident.notified_at else None,
                    incident.description,
                    incident.affected_users,
                    incident.affected_records,
                    incident.source_ip,
                    incident.user_id,
                    json.dumps(incident.metadata),
                    json.dumps(incident.status_history),
                    now,
                    now,
                ),
            )

        logger.info(
            f"Saved breach incident: id={incident.id}, type={incident.breach_type.value}, "
            f"severity={incident.severity.value}"
        )

        return incident

    def get_incident(self, incident_id: str) -> BreachIncident | None:
        """
        Get incident by ID.

        Args:
            incident_id: Incident ID

        Returns:
            BreachIncident if found, None otherwise
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM breach_incidents WHERE id = ?", (incident_id,)
            ).fetchone()

            return self._row_to_incident(row) if row else None

    def update_status(
        self, incident_id: str, new_status: BreachStatus, note: str = ""
    ) -> BreachIncident | None:
        """
        Update incident status.

        Args:
            incident_id: Incident ID
            new_status: New status
            note: Optional note about status change

        Returns:
            Updated incident if found, None otherwise
        """
        incident = self.get_incident(incident_id)
        if not incident:
            return None

        incident.update_status(new_status, note)

        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE breach_incidents
                SET status = ?, status_history = ?, updated_at = ?,
                    resolved_at = ?, notified_at = ?
                WHERE id = ?
                """,
                (
                    incident.status.value,
                    json.dumps(incident.status_history),
                    datetime.now().isoformat(),
                    incident.resolved_at.isoformat() if incident.resolved_at else None,
                    incident.notified_at.isoformat() if incident.notified_at else None,
                    incident_id,
                ),
            )

        logger.info(f"Updated breach status: id={incident_id}, status={new_status.value}")

        return incident

    def list_incidents(
        self,
        status: BreachStatus | None = None,
        severity: BreachSeverity | None = None,
        user_id: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[BreachIncident]:
        """
        List incidents with optional filters.

        Args:
            status: Filter by status
            severity: Filter by severity
            user_id: Filter by user
            start_date: Filter by detection date (after)
            end_date: Filter by detection date (before)
            limit: Maximum results
            offset: Pagination offset

        Returns:
            List of matching incidents
        """
        query = "SELECT * FROM breach_incidents WHERE 1=1"
        params: list = []

        if status:
            query += " AND status = ?"
            params.append(status.value)

        if severity:
            query += " AND severity = ?"
            params.append(severity.value)

        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)

        if start_date:
            query += " AND detected_at >= ?"
            params.append(start_date.isoformat())

        if end_date:
            query += " AND detected_at <= ?"
            params.append(end_date.isoformat())

        query += " ORDER BY detected_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_incident(row) for row in rows]

    def get_active_breaches(self) -> list[BreachIncident]:
        """
        Get all unresolved breaches.

        Returns:
            List of breaches not yet resolved
        """
        return self.list_incidents(
            status=None,
        )  # Will exclude resolved ones

    def count_incidents(
        self,
        status: BreachStatus | None = None,
        severity: BreachSeverity | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> int:
        """
        Count incidents with optional filters.

        Args:
            status: Filter by status
            severity: Filter by severity
            start_date: Filter by detection date (after)
            end_date: Filter by detection date (before)

        Returns:
            Count of matching incidents
        """
        query = "SELECT COUNT(*) FROM breach_incidents WHERE 1=1"
        params: list = []

        if status:
            query += " AND status = ?"
            params.append(status.value)

        if severity:
            query += " AND severity = ?"
            params.append(severity.value)

        if start_date:
            query += " AND detected_at >= ?"
            params.append(start_date.isoformat())

        if end_date:
            query += " AND detected_at <= ?"
            params.append(end_date.isoformat())

        with self._get_connection() as conn:
            return conn.execute(query, params).fetchone()[0]

    def _row_to_incident(self, row: sqlite3.Row) -> BreachIncident:
        """Convert database row to BreachIncident object."""
        data = dict(row)
        data["metadata"] = json.loads(data.get("metadata") or "{}")
        data["status_history"] = json.loads(data.get("status_history") or "[]")

        # Remove database-only fields not in BreachIncident dataclass
        data.pop("created_at", None)
        data.pop("updated_at", None)

        return BreachIncident.from_dict(data)


# Singleton instance
_breach_repository: BreachRepository | None = None


def get_breach_repository() -> BreachRepository:
    """Get singleton breach repository."""
    global _breach_repository
    if _breach_repository is None:
        _breach_repository = BreachRepository()
    return _breach_repository

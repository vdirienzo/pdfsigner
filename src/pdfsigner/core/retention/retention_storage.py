"""
retention_storage.py - SQLite storage for retention policies and history

Handles all database operations for retention management.
"""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from pdfsigner.core.retention.retention_types import (
    RetentionAction,
    RetentionPolicy,
    RetentionResult,
    RetentionTarget,
)


class RetentionStorage:
    """
    SQLite-based storage for retention policies and cleanup history.

    Thread-safe with connection-per-operation pattern.
    """

    def __init__(self, db_path: Path):
        """
        Initialize retention storage.

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
                CREATE TABLE IF NOT EXISTS retention_policies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    target TEXT NOT NULL,
                    retention_days INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    hipaa_reference TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS retention_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_id TEXT NOT NULL,
                    items_processed INTEGER,
                    items_deleted INTEGER,
                    items_archived INTEGER,
                    items_failed INTEGER,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    errors TEXT,
                    FOREIGN KEY (policy_id) REFERENCES retention_policies(id)
                );

                CREATE INDEX IF NOT EXISTS idx_history_policy ON retention_history(policy_id);
                CREATE INDEX IF NOT EXISTS idx_history_date ON retention_history(completed_at);
            """)

    def count_policies(self) -> int:
        """Get total number of policies."""
        with self._get_connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM retention_policies").fetchone()[0]

    def add_policy(self, policy: RetentionPolicy) -> None:
        """Insert a new retention policy."""
        with self._get_connection() as conn:
            conn.execute(
                """INSERT INTO retention_policies
                   (id, name, description, target, retention_days, action,
                    enabled, hipaa_reference, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    policy.id,
                    policy.name,
                    policy.description,
                    policy.target.value,
                    policy.retention_days,
                    policy.action.value,
                    1 if policy.enabled else 0,
                    policy.hipaa_reference,
                    policy.created_at.isoformat(),
                ),
            )

    def get_policy(self, policy_id: str) -> RetentionPolicy | None:
        """Get a policy by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM retention_policies WHERE id = ?", (policy_id,)
            ).fetchone()
            return self._row_to_policy(row) if row else None

    def list_policies(self, enabled_only: bool = False) -> list[RetentionPolicy]:
        """List all retention policies."""
        with self._get_connection() as conn:
            query = "SELECT * FROM retention_policies"
            if enabled_only:
                query += " WHERE enabled = 1"
            rows = conn.execute(query).fetchall()
            return [self._row_to_policy(row) for row in rows]

    def update_policy(self, policy: RetentionPolicy) -> None:
        """Update an existing policy."""
        with self._get_connection() as conn:
            conn.execute(
                """UPDATE retention_policies SET
                   name = ?, description = ?, target = ?, retention_days = ?,
                   action = ?, enabled = ?, hipaa_reference = ?
                   WHERE id = ?""",
                (
                    policy.name,
                    policy.description,
                    policy.target.value,
                    policy.retention_days,
                    policy.action.value,
                    1 if policy.enabled else 0,
                    policy.hipaa_reference,
                    policy.id,
                ),
            )

    def delete_policy(self, policy_id: str) -> None:
        """Delete a policy by ID."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM retention_policies WHERE id = ?", (policy_id,))

    def record_result(self, result: RetentionResult) -> None:
        """Record cleanup result in history."""
        with self._get_connection() as conn:
            conn.execute(
                """INSERT INTO retention_history
                   (policy_id, items_processed, items_deleted, items_archived,
                    items_failed, started_at, completed_at, errors)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.policy_id,
                    result.items_processed,
                    result.items_deleted,
                    result.items_archived,
                    result.items_failed,
                    result.started_at.isoformat(),
                    result.completed_at.isoformat(),
                    ",".join(result.errors) if result.errors else None,
                ),
            )

    def get_history(self, policy_id: str | None = None, limit: int = 100) -> list[dict]:
        """Get retention cleanup history."""
        with self._get_connection() as conn:
            if policy_id:
                query = """SELECT * FROM retention_history
                           WHERE policy_id = ?
                           ORDER BY completed_at DESC LIMIT ?"""
                rows = conn.execute(query, (policy_id, limit)).fetchall()
            else:
                query = """SELECT * FROM retention_history
                           ORDER BY completed_at DESC LIMIT ?"""
                rows = conn.execute(query, (limit,)).fetchall()

            return [dict(row) for row in rows]

    def _row_to_policy(self, row: sqlite3.Row) -> RetentionPolicy:
        """Convert database row to RetentionPolicy object."""
        return RetentionPolicy(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            target=RetentionTarget(row["target"]),
            retention_days=row["retention_days"],
            action=RetentionAction(row["action"]),
            enabled=bool(row["enabled"]),
            hipaa_reference=row["hipaa_reference"] or "",
            created_at=datetime.fromisoformat(row["created_at"]),
        )

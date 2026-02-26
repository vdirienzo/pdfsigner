"""
retention_manager.py - Data retention policy manager

Manages automated data retention and cleanup for HIPAA compliance.
"""

import atexit
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from loguru import logger


class RetentionTarget(str, Enum):
    """What type of data the policy applies to."""

    AUDIT_LOGS = "audit_logs"
    TEMP_FILES = "temp_files"
    SESSION_DATA = "session_data"
    REPORTS = "reports"


class RetentionAction(str, Enum):
    """What to do when retention period expires."""

    DELETE = "delete"  # Permanently delete
    ARCHIVE = "archive"  # Move to archive storage
    ANONYMIZE = "anonymize"  # Remove PII, keep statistics


@dataclass
class RetentionPolicy:
    """Defines a data retention policy."""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    target: RetentionTarget = RetentionTarget.TEMP_FILES
    retention_days: int = 30  # How long to keep data
    action: RetentionAction = RetentionAction.DELETE
    enabled: bool = True
    hipaa_reference: str = ""  # e.g., "§164.530(j)" for 6 year requirement
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "target": self.target.value,
            "retention_days": self.retention_days,
            "action": self.action.value,
            "enabled": self.enabled,
            "hipaa_reference": self.hipaa_reference,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RetentionPolicy":
        """Create policy from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            target=RetentionTarget(data["target"]),
            retention_days=data["retention_days"],
            action=RetentionAction(data["action"]),
            enabled=data.get("enabled", True),
            hipaa_reference=data.get("hipaa_reference", ""),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if data.get("created_at")
                else datetime.now(UTC)
            ),
        )


@dataclass
class RetentionResult:
    """Result of a retention cleanup operation."""

    policy_id: str
    policy_name: str
    target: RetentionTarget
    action: RetentionAction
    items_processed: int
    items_deleted: int
    items_archived: int
    items_failed: int
    started_at: datetime
    completed_at: datetime
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        """Calculate operation duration in seconds."""
        return (self.completed_at - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "target": self.target.value,
            "action": self.action.value,
            "items_processed": self.items_processed,
            "items_deleted": self.items_deleted,
            "items_archived": self.items_archived,
            "items_failed": self.items_failed,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
        }


class RetentionManager:
    """Manages data retention policies and cleanup."""

    HIPAA_AUDIT_RETENTION_DAYS = 2190  # 6 years

    def __init__(self, db_path: Path | None = None):
        """
        Initialize retention manager.

        Args:
            db_path: Path to SQLite database. Default: ~/.config/pdfsigner/retention.db
        """
        if db_path is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / "retention.db"

        self.db_path = db_path
        self._init_schema()
        self._ensure_default_policies()

        self._timer: threading.Timer | None = None
        self._running = False
        self._lock = threading.Lock()

        # Register exit handler
        atexit.register(self.stop)

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

    def _ensure_default_policies(self) -> None:
        """Ensure HIPAA-required default policies exist."""
        with self._get_connection() as conn:
            existing = conn.execute("SELECT COUNT(*) FROM retention_policies").fetchone()[0]
            if existing > 0:
                return

        # Create default policies
        defaults = [
            RetentionPolicy(
                name="HIPAA Audit Log Retention",
                description="Retain audit logs for 6 years per HIPAA requirements",
                target=RetentionTarget.AUDIT_LOGS,
                retention_days=self.HIPAA_AUDIT_RETENTION_DAYS,
                action=RetentionAction.ARCHIVE,
                hipaa_reference="§164.530(j)",
            ),
            RetentionPolicy(
                name="Temporary File Cleanup",
                description="Delete temporary files after 24 hours",
                target=RetentionTarget.TEMP_FILES,
                retention_days=1,
                action=RetentionAction.DELETE,
                hipaa_reference="§164.310(d)(1)",
            ),
            RetentionPolicy(
                name="Session Data Cleanup",
                description="Delete expired session data after 7 days",
                target=RetentionTarget.SESSION_DATA,
                retention_days=7,
                action=RetentionAction.DELETE,
            ),
            RetentionPolicy(
                name="Report Retention",
                description="Archive reports after 90 days",
                target=RetentionTarget.REPORTS,
                retention_days=90,
                action=RetentionAction.ARCHIVE,
            ),
        ]

        for policy in defaults:
            self.add_policy(policy)

        logger.info(f"Created {len(defaults)} default retention policies")

    def add_policy(self, policy: RetentionPolicy) -> RetentionPolicy:
        """
        Add a new retention policy.

        Args:
            policy: RetentionPolicy to add

        Returns:
            Added policy
        """
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
        logger.info(f"Added retention policy: {policy.name}")
        return policy

    def get_policy(self, policy_id: str) -> RetentionPolicy | None:
        """
        Get a policy by ID.

        Args:
            policy_id: Policy ID

        Returns:
            RetentionPolicy if found, None otherwise
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM retention_policies WHERE id = ?", (policy_id,)
            ).fetchone()
            return self._row_to_policy(row) if row else None

    def list_policies(self, enabled_only: bool = False) -> list[RetentionPolicy]:
        """
        List all retention policies.

        Args:
            enabled_only: Only return enabled policies

        Returns:
            List of RetentionPolicy objects
        """
        with self._get_connection() as conn:
            query = "SELECT * FROM retention_policies"
            if enabled_only:
                query += " WHERE enabled = 1"
            rows = conn.execute(query).fetchall()
            return [self._row_to_policy(row) for row in rows]

    def update_policy(self, policy: RetentionPolicy) -> RetentionPolicy:
        """
        Update an existing policy.

        Args:
            policy: RetentionPolicy with updated values

        Returns:
            Updated policy
        """
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
        logger.info(f"Updated retention policy: {policy.name}")
        return policy

    def delete_policy(self, policy_id: str) -> bool:
        """
        Delete a policy (if not HIPAA-required).

        Args:
            policy_id: Policy ID to delete

        Returns:
            True if deleted, False if HIPAA-required policy
        """
        policy = self.get_policy(policy_id)
        if policy and policy.hipaa_reference:
            logger.warning(f"Cannot delete HIPAA-required policy: {policy.name}")
            return False

        with self._get_connection() as conn:
            conn.execute("DELETE FROM retention_policies WHERE id = ?", (policy_id,))
        logger.info(f"Deleted retention policy: {policy_id}")
        return True

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

    def run_cleanup(self, policy_id: str | None = None) -> list[RetentionResult]:
        """
        Run retention cleanup for one or all policies.

        Args:
            policy_id: Specific policy ID to run, or None for all enabled policies

        Returns:
            List of RetentionResult objects
        """
        if policy_id:
            policies = [self.get_policy(policy_id)]
            policies = [p for p in policies if p]
        else:
            policies = self.list_policies(enabled_only=True)

        results = []
        for policy in policies:
            result = self._execute_policy(policy)
            results.append(result)
            self._record_result(result)

        return results

    def _execute_policy(self, policy: RetentionPolicy) -> RetentionResult:
        """
        Execute a single retention policy.

        Args:
            policy: RetentionPolicy to execute

        Returns:
            RetentionResult with operation details
        """
        started_at = datetime.now(UTC)
        errors: list[str] = []
        deleted = 0
        archived = 0
        failed = 0
        processed = 0

        cutoff_date = datetime.now(UTC) - timedelta(days=policy.retention_days)

        try:
            if policy.target == RetentionTarget.AUDIT_LOGS:
                processed, deleted, archived, failed, errors = self._cleanup_audit_logs(
                    policy, cutoff_date
                )
            elif policy.target == RetentionTarget.TEMP_FILES:
                processed, deleted, archived, failed, errors = self._cleanup_temp_files(
                    policy, cutoff_date
                )
            elif policy.target == RetentionTarget.SESSION_DATA:
                processed, deleted, archived, failed, errors = self._cleanup_session_data(
                    policy, cutoff_date
                )
            elif policy.target == RetentionTarget.REPORTS:
                processed, deleted, archived, failed, errors = self._cleanup_reports(
                    policy, cutoff_date
                )
        except Exception as e:
            errors.append(str(e))
            logger.error(f"Error executing policy {policy.name}: {e}")

        completed_at = datetime.now(UTC)

        result = RetentionResult(
            policy_id=policy.id,
            policy_name=policy.name,
            target=policy.target,
            action=policy.action,
            items_processed=processed,
            items_deleted=deleted,
            items_archived=archived,
            items_failed=failed,
            started_at=started_at,
            completed_at=completed_at,
            errors=errors,
        )

        logger.info(
            f"Retention cleanup '{policy.name}': "
            f"processed={processed}, deleted={deleted}, archived={archived}, failed={failed}"
        )

        return result

    def _cleanup_audit_logs(
        self, policy: RetentionPolicy, cutoff: datetime
    ) -> tuple[int, int, int, int, list[str]]:
        """
        Cleanup old audit logs.

        Args:
            policy: Retention policy
            cutoff: Cutoff date

        Returns:
            Tuple of (processed, deleted, archived, failed, errors)
        """
        # For HIPAA compliance, we archive rather than delete
        try:
            from pdfsigner.core.audit import get_audit_logger

            audit = get_audit_logger()

            # Audit logs should be archived, not deleted
            if policy.action == RetentionAction.ARCHIVE:
                # Archive logs older than cutoff
                archived = audit.cleanup_old_logs()
                return archived, 0, archived, 0, []
            elif policy.action == RetentionAction.DELETE:
                # Only delete if explicitly requested AND past HIPAA requirement
                if policy.retention_days >= self.HIPAA_AUDIT_RETENTION_DAYS:
                    deleted = audit.cleanup_old_logs()
                    return deleted, deleted, 0, 0, []
                else:
                    return (
                        0,
                        0,
                        0,
                        0,
                        ["Cannot delete audit logs before HIPAA retention period (6 years)"],
                    )
        except Exception as e:
            return 0, 0, 0, 0, [str(e)]

        return 0, 0, 0, 0, []

    def _cleanup_temp_files(
        self, policy: RetentionPolicy, cutoff: datetime
    ) -> tuple[int, int, int, int, list[str]]:
        """
        Cleanup old temporary files.

        Args:
            policy: Retention policy
            cutoff: Cutoff date

        Returns:
            Tuple of (processed, deleted, archived, failed, errors)
        """
        try:
            from pdfsigner.core.security.cleanup_scheduler import get_cleanup_scheduler

            scheduler = get_cleanup_scheduler()
            deleted = scheduler.cleanup_expired()
            return deleted, deleted, 0, 0, []
        except Exception as e:
            return 0, 0, 0, 0, [str(e)]

    def _cleanup_session_data(
        self, policy: RetentionPolicy, cutoff: datetime
    ) -> tuple[int, int, int, int, list[str]]:
        """
        Cleanup old session data.

        Args:
            policy: Retention policy
            cutoff: Cutoff date

        Returns:
            Tuple of (processed, deleted, archived, failed, errors)
        """
        try:
            from pdfsigner.core.session import get_session_manager

            manager = get_session_manager()
            deleted = manager.cleanup_expired()
            return deleted, deleted, 0, 0, []
        except Exception as e:
            return 0, 0, 0, 0, [str(e)]

    def _cleanup_reports(
        self, policy: RetentionPolicy, cutoff: datetime
    ) -> tuple[int, int, int, int, list[str]]:
        """
        Cleanup old reports.

        Args:
            policy: Retention policy
            cutoff: Cutoff date

        Returns:
            Tuple of (processed, deleted, archived, failed, errors)
        """
        # Reports are typically files in a directory
        reports_dir = Path.home() / ".local" / "share" / "pdfsigner" / "reports"
        if not reports_dir.exists():
            return 0, 0, 0, 0, []

        processed = 0
        deleted = 0
        archived = 0
        failed = 0
        errors = []

        cutoff_ts = cutoff.timestamp()

        for report_file in reports_dir.glob("*.pdf"):
            processed += 1
            try:
                if report_file.stat().st_mtime < cutoff_ts:
                    if policy.action == RetentionAction.DELETE:
                        report_file.unlink()
                        deleted += 1
                    elif policy.action == RetentionAction.ARCHIVE:
                        archive_dir = reports_dir / "archive"
                        archive_dir.mkdir(exist_ok=True)
                        report_file.rename(archive_dir / report_file.name)
                        archived += 1
            except Exception as e:
                failed += 1
                errors.append(f"{report_file.name}: {e}")

        return processed, deleted, archived, failed, errors

    def _record_result(self, result: RetentionResult) -> None:
        """
        Record cleanup result in history.

        Args:
            result: RetentionResult to record
        """
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
        """
        Get retention cleanup history.

        Args:
            policy_id: Filter by policy ID, or None for all policies
            limit: Maximum number of records to return

        Returns:
            List of history records as dictionaries
        """
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

    def start(self, interval_hours: int = 24) -> None:
        """
        Start scheduled retention cleanup.

        Args:
            interval_hours: Hours between cleanup runs
        """
        if self._running:
            return

        self._running = True
        self._schedule_next(interval_hours)
        logger.info(f"Retention scheduler started (interval: {interval_hours}h)")

    def stop(self) -> None:
        """Stop scheduled retention cleanup."""
        self._running = False
        if self._timer:
            self._timer.cancel()
            self._timer = None
        logger.info("Retention scheduler stopped")

    def _schedule_next(self, interval_hours: int) -> None:
        """
        Schedule the next cleanup run.

        Args:
            interval_hours: Hours until next run
        """
        if not self._running:
            return

        self._timer = threading.Timer(
            interval_hours * 3600, self._run_scheduled, args=[interval_hours]
        )
        self._timer.daemon = True
        self._timer.start()

    def _run_scheduled(self, interval_hours: int) -> None:
        """
        Run scheduled cleanup and reschedule.

        Args:
            interval_hours: Hours until next run
        """
        with self._lock:
            self.run_cleanup()
        self._schedule_next(interval_hours)


# Singleton
_retention_manager: RetentionManager | None = None


def get_retention_manager() -> RetentionManager:
    """Get singleton retention manager."""
    global _retention_manager
    if _retention_manager is None:
        _retention_manager = RetentionManager()
    return _retention_manager

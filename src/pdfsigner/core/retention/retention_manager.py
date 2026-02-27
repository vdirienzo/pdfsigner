"""
retention_manager.py - Data retention policy orchestrator

Manages automated data retention and cleanup for HIPAA compliance.
"""

import atexit
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from loguru import logger

from pdfsigner.core.retention.retention_storage import RetentionStorage
from pdfsigner.core.retention.retention_types import (
    RetentionAction,
    RetentionPolicy,
    RetentionResult,
    RetentionTarget,
)

# Re-export types for backward compatibility
__all__ = [
    "RetentionAction",
    "RetentionManager",
    "RetentionPolicy",
    "RetentionResult",
    "RetentionTarget",
    "get_retention_manager",
]


class RetentionManager:
    """Manages data retention policies and cleanup."""

    HIPAA_AUDIT_RETENTION_DAYS = 2190  # 6 years

    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / "retention.db"

        self.db_path = db_path
        self._storage = RetentionStorage(db_path)
        self._ensure_default_policies()

        self._timer: threading.Timer | None = None
        self._running = False
        self._lock = threading.Lock()

        atexit.register(self.stop)

    def _ensure_default_policies(self) -> None:
        """Ensure HIPAA-required default policies exist."""
        if self._storage.count_policies() > 0:
            return

        defaults = [
            RetentionPolicy(
                name="HIPAA Audit Log Retention",
                description="Retain audit logs for 6 years per HIPAA requirements",
                target=RetentionTarget.AUDIT_LOGS,
                retention_days=self.HIPAA_AUDIT_RETENTION_DAYS,
                action=RetentionAction.ARCHIVE,
                hipaa_reference="SS164.530(j)",
            ),
            RetentionPolicy(
                name="Temporary File Cleanup",
                description="Delete temporary files after 24 hours",
                target=RetentionTarget.TEMP_FILES,
                retention_days=1,
                action=RetentionAction.DELETE,
                hipaa_reference="SS164.310(d)(1)",
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
        """Add a new retention policy."""
        self._storage.add_policy(policy)
        logger.info(f"Added retention policy: {policy.name}")
        return policy

    def get_policy(self, policy_id: str) -> RetentionPolicy | None:
        """Get a policy by ID."""
        return self._storage.get_policy(policy_id)

    def list_policies(self, enabled_only: bool = False) -> list[RetentionPolicy]:
        """List all retention policies."""
        return self._storage.list_policies(enabled_only=enabled_only)

    def update_policy(self, policy: RetentionPolicy) -> RetentionPolicy:
        """Update an existing policy."""
        self._storage.update_policy(policy)
        logger.info(f"Updated retention policy: {policy.name}")
        return policy

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy (if not HIPAA-required)."""
        policy = self._storage.get_policy(policy_id)
        if policy and policy.hipaa_reference:
            logger.warning(f"Cannot delete HIPAA-required policy: {policy.name}")
            return False

        self._storage.delete_policy(policy_id)
        logger.info(f"Deleted retention policy: {policy_id}")
        return True

    def run_cleanup(self, policy_id: str | None = None) -> list[RetentionResult]:
        """Run retention cleanup for one or all policies."""
        if policy_id:
            policy = self._storage.get_policy(policy_id)
            if policy is None:
                raise ValueError(f"Retention policy not found: {policy_id}")
            policies = [policy]
        else:
            policies = self._storage.list_policies(enabled_only=True)

        results = []
        for policy in policies:
            result = self._execute_policy(policy)
            results.append(result)
            self._storage.record_result(result)

        return results

    def _execute_policy(self, policy: RetentionPolicy) -> RetentionResult:
        """Execute a single retention policy."""
        started_at = datetime.now(UTC)
        errors: list[str] = []
        deleted = 0
        archived = 0
        failed = 0
        processed = 0

        cutoff_date = datetime.now(UTC) - timedelta(days=policy.retention_days)

        try:
            cleanup_map = {
                RetentionTarget.AUDIT_LOGS: self._cleanup_audit_logs,
                RetentionTarget.TEMP_FILES: self._cleanup_temp_files,
                RetentionTarget.SESSION_DATA: self._cleanup_session_data,
                RetentionTarget.REPORTS: self._cleanup_reports,
            }
            handler = cleanup_map.get(policy.target)
            if handler:
                processed, deleted, archived, failed, errors = handler(policy, cutoff_date)
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
        """Cleanup old audit logs."""
        try:
            from pdfsigner.core.audit import get_audit_logger

            audit = get_audit_logger()

            if policy.action == RetentionAction.ARCHIVE:
                archived = audit.cleanup_old_logs()
                return archived, 0, archived, 0, []
            elif policy.action == RetentionAction.DELETE:
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
        """Cleanup old temporary files."""
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
        """Cleanup old session data."""
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
        """Cleanup old reports."""
        reports_dir = Path.home() / ".local" / "share" / "pdfsigner" / "reports"
        if not reports_dir.exists():
            return 0, 0, 0, 0, []

        processed = 0
        deleted = 0
        archived = 0
        failed = 0
        errors: list[str] = []
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

    def get_history(self, policy_id: str | None = None, limit: int = 100) -> list[dict]:
        """Get retention cleanup history."""
        return self._storage.get_history(policy_id=policy_id, limit=limit)

    def start(self, interval_hours: int = 24) -> None:
        """Start scheduled retention cleanup."""
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
        """Schedule the next cleanup run."""
        if not self._running:
            return
        self._timer = threading.Timer(
            interval_hours * 3600, self._run_scheduled, args=[interval_hours]
        )
        self._timer.daemon = True
        self._timer.start()

    def _run_scheduled(self, interval_hours: int) -> None:
        """Run scheduled cleanup and reschedule."""
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

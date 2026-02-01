"""
cleanup_scheduler.py - Automatic temporary file cleanup

Author: Homero Thompson del Lago del Terror

Provides scheduled cleanup of temporary files with configurable retention
periods and audit logging for HIPAA compliance.
"""

import atexit
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from loguru import logger


@dataclass
class CleanupTask:
    """A scheduled cleanup task."""

    path: Path
    created_at: datetime = field(default_factory=datetime.now)
    retention_hours: int = 24

    @property
    def expires_at(self) -> datetime:
        """Get expiration time for this task."""
        return self.created_at + timedelta(hours=self.retention_hours)

    @property
    def is_expired(self) -> bool:
        """Check if task has expired."""
        return datetime.now() >= self.expires_at


class CleanupScheduler:
    """
    Manages periodic cleanup of temporary files.

    Features:
    - Configurable retention period
    - Periodic background cleanup
    - Immediate cleanup on application exit
    - Audit logging of all cleanup operations
    - Thread-safe operation

    Usage:
        scheduler = get_cleanup_scheduler()
        scheduler.start()
        scheduler.register(temp_file_path, retention_hours=24)
    """

    def __init__(
        self,
        check_interval_minutes: int = 15,
        default_retention_hours: int = 24,
    ):
        """
        Initialize cleanup scheduler.

        Args:
            check_interval_minutes: Minutes between cleanup checks (default: 15)
            default_retention_hours: Default retention period in hours (default: 24)
        """
        self._check_interval = check_interval_minutes * 60  # Convert to seconds
        self._default_retention = default_retention_hours
        self._tasks: list[CleanupTask] = []
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._running = False

        # Register exit handler
        atexit.register(self._cleanup_on_exit)

    def start(self) -> None:
        """Start the background cleanup scheduler."""
        if self._running:
            return

        self._running = True
        self._schedule_next_cleanup()
        logger.info(f"Cleanup scheduler started (interval: {self._check_interval}s)")

    def stop(self) -> None:
        """Stop the background cleanup scheduler."""
        self._running = False
        if self._timer:
            self._timer.cancel()
            self._timer = None
        logger.info("Cleanup scheduler stopped")

    def register(self, path: Path, retention_hours: int | None = None) -> None:
        """
        Register a path for scheduled cleanup.

        Args:
            path: Path to file or directory to clean up
            retention_hours: Hours to retain file (default: 24)
        """
        retention = retention_hours or self._default_retention
        task = CleanupTask(path=path, retention_hours=retention)

        with self._lock:
            self._tasks.append(task)

        logger.debug(f"Registered for cleanup: {path.name} (expires in {retention}h)")

    def cleanup_expired(self) -> int:
        """
        Clean up all expired files.

        Returns:
            Number of files cleaned
        """
        cleaned = 0

        # Get expired tasks
        with self._lock:
            expired_tasks = [t for t in self._tasks if t.is_expired]
            self._tasks = [t for t in self._tasks if not t.is_expired]

        # Clean up expired files
        for task in expired_tasks:
            if self._cleanup_path(task.path):
                cleaned += 1
                self._log_cleanup(task)

        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} expired temp files")

        return cleaned

    def cleanup_all(self) -> int:
        """
        Force cleanup of all registered files.

        Returns:
            Number of files cleaned
        """
        with self._lock:
            tasks = list(self._tasks)
            self._tasks = []

        cleaned = 0
        for task in tasks:
            if self._cleanup_path(task.path):
                cleaned += 1

        logger.info(f"Force cleaned {cleaned} temp files")
        return cleaned

    def _cleanup_path(self, path: Path) -> bool:
        """
        Securely delete a path (file or directory).

        Args:
            path: Path to delete

        Returns:
            True if cleanup succeeded, False otherwise
        """
        if not path.exists():
            return False

        try:
            if path.is_file():
                from pdfsigner.core.security.secure_temp import SecureTempFile

                SecureTempFile()._secure_delete(path)
            elif path.is_dir():
                from pdfsigner.core.security.secure_temp import SecureTempDirectory

                SecureTempDirectory()._secure_delete_directory(path)
            return True
        except Exception as e:
            logger.error(f"Failed to cleanup {path}: {e}")
            return False

    def _log_cleanup(self, task: CleanupTask) -> None:
        """
        Log cleanup operation to audit trail.

        Args:
            task: The cleanup task being logged
        """
        try:
            from pdfsigner.core.audit import AuditEvent, AuditEventType, get_audit_logger

            audit = get_audit_logger()
            event = AuditEvent(
                event_type=AuditEventType.SYSTEM_CLEANUP,
                details={
                    "path": str(task.path),
                    "created_at": task.created_at.isoformat(),
                    "retention_hours": task.retention_hours,
                },
            )
            audit.log_event(event)
        except Exception as e:
            logger.warning(f"Failed to log cleanup to audit: {e}")

    def _schedule_next_cleanup(self) -> None:
        """Schedule the next cleanup run."""
        if not self._running:
            return

        self._timer = threading.Timer(self._check_interval, self._run_cleanup)
        self._timer.daemon = True
        self._timer.start()

    def _run_cleanup(self) -> None:
        """Run cleanup and schedule next."""
        try:
            self.cleanup_expired()
        except Exception as e:
            logger.error(f"Error during scheduled cleanup: {e}")
        finally:
            self._schedule_next_cleanup()

    def _cleanup_on_exit(self) -> None:
        """Clean up all files on application exit."""
        self.stop()
        cleaned = self.cleanup_all()
        if cleaned > 0:
            logger.info(f"Exit cleanup: removed {cleaned} temp files")


# Singleton
_cleanup_scheduler: CleanupScheduler | None = None
_scheduler_lock = threading.Lock()


def get_cleanup_scheduler() -> CleanupScheduler:
    """
    Get singleton CleanupScheduler instance.

    Returns:
        The global CleanupScheduler instance
    """
    global _cleanup_scheduler

    if _cleanup_scheduler is None:
        with _scheduler_lock:
            if _cleanup_scheduler is None:
                _cleanup_scheduler = CleanupScheduler()

    return _cleanup_scheduler

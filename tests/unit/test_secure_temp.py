"""
test_secure_temp.py - Tests for secure temporary file handling

Author: Homero Thompson del Lago del Terror

Tests secure temp file/directory creation, deletion, and cleanup scheduling
with HIPAA compliance verification.
"""

import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from pdfsigner.core.audit import AuditEventType
from pdfsigner.core.security import (
    CleanupScheduler,
    CleanupTask,
    SecureTempDirectory,
    SecureTempFile,
    TempFileInfo,
    get_cleanup_scheduler,
    secure_temp_directory,
    secure_temp_file,
)


class TestTempFileInfo:
    """Tests for TempFileInfo dataclass."""

    def test_temp_file_info_creation(self):
        """Test TempFileInfo creation with defaults."""
        path = Path("/tmp/test.pdf")
        info = TempFileInfo(path=path)

        assert info.path == path
        assert isinstance(info.created_at, datetime)
        assert info.size_bytes == 0
        assert info.secure_deleted is False

    def test_temp_file_info_to_dict(self):
        """Test TempFileInfo serialization to dict."""
        path = Path("/tmp/test.pdf")
        created_at = datetime(2024, 1, 15, 10, 30, 0)
        info = TempFileInfo(
            path=path,
            created_at=created_at,
            size_bytes=1024,
            secure_deleted=True,
        )

        result = info.to_dict()

        assert result["path"] == str(path)
        assert result["created_at"] == "2024-01-15T10:30:00"
        assert result["size_bytes"] == 1024
        assert result["secure_deleted"] is True


class TestSecureTempFile:
    """Tests for SecureTempFile context manager."""

    def test_secure_temp_file_creates_file(self):
        """Test that SecureTempFile creates a file."""
        with SecureTempFile(suffix=".pdf", prefix="test_") as temp_path:
            assert temp_path.exists()
            assert temp_path.is_file()
            assert temp_path.suffix == ".pdf"
            assert temp_path.name.startswith("test_")

    def test_secure_temp_file_deletes_on_exit(self):
        """Test that SecureTempFile deletes file on exit."""
        temp_path = None
        with SecureTempFile(suffix=".txt") as path:
            temp_path = path
            path.write_text("test data")
            assert path.exists()

        # File should be deleted after exiting context
        assert not temp_path.exists()

    def test_secure_temp_file_restricted_permissions(self):
        """Test that SecureTempFile creates file with restricted permissions (600)."""
        with SecureTempFile() as temp_path:
            stat_info = temp_path.stat()
            # Get file permissions (last 3 octal digits)
            mode = stat_info.st_mode & 0o777
            assert mode == 0o600  # Owner read/write only

    def test_secure_temp_file_no_delete(self):
        """Test SecureTempFile with delete=False."""
        temp_path = None
        with SecureTempFile(delete=False) as path:
            temp_path = path
            path.write_text("persistent data")

        # File should still exist
        assert temp_path.exists()

        # Clean up manually
        temp_path.unlink()

    def test_secure_delete_overwrites_content(self):
        """Test that secure delete overwrites file content before deletion."""
        secure_file = SecureTempFile()
        temp_path = Path(secure_file._get_secure_temp_dir()) / "test_delete.txt"

        # Write test data
        test_data = b"sensitive data" * 100
        temp_path.write_bytes(test_data)

        # Spy on file writes during secure delete
        with patch("builtins.open", wraps=open) as mock_open:
            secure_file._secure_delete(temp_path)

            # Should have opened file in r+b mode for overwriting
            mock_open.assert_called()

        # File should be deleted
        assert not temp_path.exists()

    def test_secure_delete_handles_nonexistent_file(self):
        """Test that secure delete handles non-existent files gracefully."""
        secure_file = SecureTempFile()
        nonexistent = Path("/tmp/nonexistent_file.txt")

        # Should not raise exception
        secure_file._secure_delete(nonexistent)

    def test_secure_delete_handles_empty_file(self):
        """Test that secure delete handles empty files."""
        secure_file = SecureTempFile()
        temp_path = Path(secure_file._get_secure_temp_dir()) / "empty.txt"
        temp_path.touch()

        assert temp_path.stat().st_size == 0

        secure_file._secure_delete(temp_path)
        assert not temp_path.exists()

    def test_get_secure_temp_dir_creates_directory(self):
        """Test that _get_secure_temp_dir creates directory if needed."""
        secure_file = SecureTempFile()
        temp_dir = secure_file._get_secure_temp_dir()

        assert temp_dir.exists()
        assert temp_dir.is_dir()
        assert "pdfsigner" in str(temp_dir)

        # Check permissions (700 = owner only)
        stat_info = temp_dir.stat()
        mode = stat_info.st_mode & 0o777
        assert mode == 0o700

    def test_get_secure_temp_dir_uses_xdg_runtime(self):
        """Test that _get_secure_temp_dir prefers XDG_RUNTIME_DIR."""
        with patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"}):
            secure_file = SecureTempFile()
            temp_dir = secure_file._get_secure_temp_dir()

            assert "/run/user/1000/pdfsigner" in str(temp_dir)

    def test_secure_temp_file_functional_interface(self):
        """Test secure_temp_file functional interface."""
        with secure_temp_file(suffix=".json", prefix="config_") as temp_path:
            assert temp_path.exists()
            assert temp_path.suffix == ".json"
            assert temp_path.name.startswith("config_")
            temp_path.write_text('{"test": true}')

        assert not temp_path.exists()

    def test_secure_temp_file_exception_still_deletes(self):
        """Test that SecureTempFile deletes file even if exception occurs."""
        temp_path = None
        try:
            with SecureTempFile() as path:
                temp_path = path
                raise ValueError("Test exception")
        except ValueError:
            pass

        # File should still be deleted
        assert not temp_path.exists()

    def test_secure_temp_file_random_names(self):
        """Test that SecureTempFile generates cryptographically random names."""
        paths = []
        for _ in range(10):
            with SecureTempFile(delete=False) as path:
                paths.append(path)

        # All paths should be unique
        assert len(set(paths)) == len(paths)

        # Clean up
        for path in paths:
            if path.exists():
                path.unlink()


class TestSecureTempDirectory:
    """Tests for SecureTempDirectory context manager."""

    def test_secure_temp_directory_creates_dir(self):
        """Test that SecureTempDirectory creates a directory."""
        with SecureTempDirectory(prefix="test_") as temp_dir:
            assert temp_dir.exists()
            assert temp_dir.is_dir()
            assert temp_dir.name.startswith("test_")

            # Check permissions (700 = owner only)
            stat_info = temp_dir.stat()
            mode = stat_info.st_mode & 0o777
            assert mode == 0o700

    def test_secure_temp_directory_deletes_on_exit(self):
        """Test that SecureTempDirectory deletes directory on exit."""
        temp_dir_path = None
        with SecureTempDirectory() as temp_dir:
            temp_dir_path = temp_dir
            (temp_dir / "file.txt").write_text("test")
            assert temp_dir.exists()

        # Directory should be deleted
        assert not temp_dir_path.exists()

    def test_secure_temp_directory_cleans_recursively(self):
        """Test that SecureTempDirectory recursively deletes all contents."""
        temp_dir_path = None
        file_paths = []

        with SecureTempDirectory() as temp_dir:
            temp_dir_path = temp_dir

            # Create nested structure
            (temp_dir / "file1.txt").write_text("data1")
            subdir = temp_dir / "subdir"
            subdir.mkdir()
            (subdir / "file2.txt").write_text("data2")
            nested = subdir / "nested"
            nested.mkdir()
            (nested / "file3.txt").write_text("data3")

            file_paths = [
                temp_dir / "file1.txt",
                subdir / "file2.txt",
                nested / "file3.txt",
            ]

            # All should exist
            assert all(f.exists() for f in file_paths)

        # All should be deleted
        assert not temp_dir_path.exists()
        assert all(not f.exists() for f in file_paths)

    def test_secure_temp_directory_functional_interface(self):
        """Test secure_temp_directory functional interface."""
        with secure_temp_directory(prefix="work_") as temp_dir:
            assert temp_dir.exists()
            assert temp_dir.name.startswith("work_")
            (temp_dir / "work.txt").write_text("work data")

        assert not temp_dir.exists()

    def test_secure_temp_directory_exception_still_deletes(self):
        """Test that SecureTempDirectory deletes even if exception occurs."""
        temp_dir_path = None
        try:
            with SecureTempDirectory() as temp_dir:
                temp_dir_path = temp_dir
                (temp_dir / "file.txt").write_text("data")
                raise RuntimeError("Test error")
        except RuntimeError:
            pass

        # Directory should still be deleted
        assert not temp_dir_path.exists()


class TestCleanupTask:
    """Tests for CleanupTask dataclass."""

    def test_cleanup_task_creation(self):
        """Test CleanupTask creation."""
        path = Path("/tmp/test.pdf")
        task = CleanupTask(path=path, retention_hours=12)

        assert task.path == path
        assert isinstance(task.created_at, datetime)
        assert task.retention_hours == 12

    def test_cleanup_task_expires_at(self):
        """Test CleanupTask.expires_at calculation."""
        created_at = datetime(2024, 1, 15, 10, 0, 0)
        task = CleanupTask(
            path=Path("/tmp/test.pdf"),
            created_at=created_at,
            retention_hours=24,
        )

        expected = datetime(2024, 1, 16, 10, 0, 0)
        assert task.expires_at == expected

    def test_cleanup_task_is_expired(self):
        """Test CleanupTask.is_expired property."""
        # Create task that expired 1 hour ago
        created_at = datetime.now(UTC) - timedelta(hours=25)
        task = CleanupTask(
            path=Path("/tmp/test.pdf"),
            created_at=created_at,
            retention_hours=24,
        )

        assert task.is_expired is True

    def test_cleanup_task_not_expired(self):
        """Test CleanupTask.is_expired for non-expired task."""
        # Create task that expires in 23 hours
        created_at = datetime.now(UTC) - timedelta(hours=1)
        task = CleanupTask(
            path=Path("/tmp/test.pdf"),
            created_at=created_at,
            retention_hours=24,
        )

        assert task.is_expired is False


class TestCleanupScheduler:
    """Tests for CleanupScheduler."""

    def test_cleanup_scheduler_initialization(self):
        """Test CleanupScheduler initialization."""
        scheduler = CleanupScheduler(
            check_interval_minutes=10,
            default_retention_hours=48,
        )

        assert scheduler._check_interval == 600  # 10 * 60 seconds
        assert scheduler._default_retention == 48
        assert scheduler._running is False
        assert len(scheduler._tasks) == 0

    def test_cleanup_scheduler_start_stop(self):
        """Test starting and stopping scheduler."""
        scheduler = CleanupScheduler()

        assert scheduler._running is False

        scheduler.start()
        assert scheduler._running is True
        assert scheduler._timer is not None

        scheduler.stop()
        assert scheduler._running is False

    def test_cleanup_scheduler_start_idempotent(self):
        """Test that starting scheduler multiple times is safe."""
        scheduler = CleanupScheduler()

        scheduler.start()
        timer1 = scheduler._timer

        scheduler.start()
        timer2 = scheduler._timer

        # Should be the same timer
        assert timer1 is timer2

        scheduler.stop()

    def test_cleanup_scheduler_registers_tasks(self):
        """Test registering cleanup tasks."""
        scheduler = CleanupScheduler()

        path1 = Path("/tmp/file1.txt")
        path2 = Path("/tmp/file2.txt")

        scheduler.register(path1, retention_hours=12)
        scheduler.register(path2, retention_hours=24)

        assert len(scheduler._tasks) == 2
        assert scheduler._tasks[0].path == path1
        assert scheduler._tasks[0].retention_hours == 12
        assert scheduler._tasks[1].path == path2
        assert scheduler._tasks[1].retention_hours == 24

    def test_cleanup_scheduler_uses_default_retention(self):
        """Test that scheduler uses default retention if not specified."""
        scheduler = CleanupScheduler(default_retention_hours=48)

        path = Path("/tmp/file.txt")
        scheduler.register(path)

        assert scheduler._tasks[0].retention_hours == 48

    def test_cleanup_scheduler_cleans_expired(self):
        """Test cleanup of expired files."""
        scheduler = CleanupScheduler()

        # Create temp files
        with SecureTempFile(delete=False) as expired_file:
            expired_file.write_text("expired")

        with SecureTempFile(delete=False) as active_file:
            active_file.write_text("active")

        # Register with different expiration times
        expired_task = CleanupTask(
            path=expired_file,
            created_at=datetime.now(UTC) - timedelta(hours=25),
            retention_hours=24,
        )
        active_task = CleanupTask(
            path=active_file,
            created_at=datetime.now(UTC),
            retention_hours=24,
        )

        scheduler._tasks = [expired_task, active_task]

        # Run cleanup
        cleaned = scheduler.cleanup_expired()

        # Only expired file should be cleaned
        assert cleaned == 1
        assert not expired_file.exists()
        assert active_file.exists()

        # Only active task should remain
        assert len(scheduler._tasks) == 1
        assert scheduler._tasks[0].path == active_file

        # Clean up
        active_file.unlink()

    def test_cleanup_scheduler_ignores_not_expired(self):
        """Test that non-expired files are not cleaned."""
        scheduler = CleanupScheduler()

        # Create temp file
        with SecureTempFile(delete=False) as temp_file:
            temp_file.write_text("active")

        # Register with future expiration
        task = CleanupTask(
            path=temp_file,
            created_at=datetime.now(UTC),
            retention_hours=24,
        )
        scheduler._tasks = [task]

        # Run cleanup
        cleaned = scheduler.cleanup_expired()

        # Nothing should be cleaned
        assert cleaned == 0
        assert temp_file.exists()
        assert len(scheduler._tasks) == 1

        # Clean up
        temp_file.unlink()

    def test_cleanup_scheduler_cleanup_all(self):
        """Test forcing cleanup of all files."""
        scheduler = CleanupScheduler()

        # Create temp files
        files = []
        for i in range(3):
            with SecureTempFile(delete=False, prefix=f"test{i}_") as temp_file:
                temp_file.write_text(f"data{i}")
                files.append(temp_file)

        # Register all
        for f in files:
            scheduler.register(f, retention_hours=24)

        assert len(scheduler._tasks) == 3

        # Force cleanup all
        cleaned = scheduler.cleanup_all()

        # All should be cleaned
        assert cleaned == 3
        assert all(not f.exists() for f in files)
        assert len(scheduler._tasks) == 0

    def test_cleanup_scheduler_handles_missing_files(self):
        """Test that scheduler handles missing files gracefully."""
        scheduler = CleanupScheduler()

        # Register non-existent file
        nonexistent = Path("/tmp/nonexistent_file.txt")
        scheduler.register(nonexistent, retention_hours=0)

        # Should not raise exception
        cleaned = scheduler.cleanup_expired()
        assert cleaned == 0

    def test_cleanup_on_exit(self):
        """Test that scheduler cleans up on exit."""
        scheduler = CleanupScheduler()

        # Create temp files
        with SecureTempFile(delete=False) as temp_file:
            temp_file.write_text("test")

        scheduler.register(temp_file)
        assert temp_file.exists()

        # Simulate exit
        scheduler._cleanup_on_exit()

        # File should be cleaned
        assert not temp_file.exists()
        assert scheduler._running is False

    def test_cleanup_logs_to_audit(self):
        """Test that cleanup operations are logged to audit trail."""
        scheduler = CleanupScheduler()

        # Create and register temp file
        with SecureTempFile(delete=False) as temp_file:
            temp_file.write_text("test")

        task = CleanupTask(
            path=temp_file,
            created_at=datetime.now(UTC) - timedelta(hours=25),
            retention_hours=24,
        )

        # Mock audit logger
        with patch("pdfsigner.core.audit.get_audit_logger") as mock_get:
            mock_logger = MagicMock()
            mock_get.return_value = mock_logger

            scheduler._tasks = [task]
            scheduler.cleanup_expired()

            # Should have logged cleanup event
            mock_logger.log_event.assert_called_once()
            # Check the AuditEvent object passed
            call_args = mock_logger.log_event.call_args
            event = call_args[0][0]  # First positional argument
            assert event.event_type == AuditEventType.SYSTEM_CLEANUP
            assert "path" in event.details
            assert "retention_hours" in event.details

    def test_cleanup_scheduler_thread_safety(self):
        """Test that scheduler is thread-safe."""
        scheduler = CleanupScheduler()

        # Create multiple temp files
        files = []
        for i in range(10):
            with SecureTempFile(delete=False, prefix=f"thread{i}_") as temp_file:
                temp_file.write_text(f"data{i}")
                files.append(temp_file)

        # Register from multiple threads
        threads = []
        for f in files:
            t = threading.Thread(target=scheduler.register, args=(f,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(scheduler._tasks) == 10

        # Clean up
        for f in files:
            if f.exists():
                f.unlink()

    def test_get_cleanup_scheduler_singleton(self):
        """Test that get_cleanup_scheduler returns singleton."""
        scheduler1 = get_cleanup_scheduler()
        scheduler2 = get_cleanup_scheduler()

        assert scheduler1 is scheduler2

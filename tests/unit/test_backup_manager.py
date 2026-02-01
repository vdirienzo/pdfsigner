"""
Tests for backup and recovery module.

Tests BackupManager, BackupMetadata, and related functionality for
HIPAA §164.308(a)(7) compliance.
"""

import json
import tarfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.backup import (
    BackupManager,
    BackupMetadata,
    BackupStatus,
    BackupType,
    get_backup_manager,
    restore_backup,
)


class TestBackupType:
    """Tests for BackupType enum."""

    def test_backup_type_values(self):
        """Test BackupType enum has expected values."""
        assert BackupType.FULL.value == "full"
        assert BackupType.CONFIG.value == "config"
        assert BackupType.AUDIT.value == "audit"
        assert BackupType.DATABASE.value == "database"

    def test_backup_type_is_str_enum(self):
        """Test BackupType inherits from str."""
        assert isinstance(BackupType.FULL, str)
        assert BackupType.FULL == "full"


class TestBackupStatus:
    """Tests for BackupStatus enum."""

    def test_backup_status_values(self):
        """Test BackupStatus enum has expected values."""
        assert BackupStatus.PENDING.value == "pending"
        assert BackupStatus.IN_PROGRESS.value == "in_progress"
        assert BackupStatus.COMPLETED.value == "completed"
        assert BackupStatus.FAILED.value == "failed"

    def test_backup_status_is_str_enum(self):
        """Test BackupStatus inherits from str."""
        assert isinstance(BackupStatus.COMPLETED, str)
        assert BackupStatus.COMPLETED == "completed"


class TestBackupMetadata:
    """Tests for BackupMetadata dataclass."""

    def test_backup_metadata_creation(self):
        """Test creating BackupMetadata with default values."""
        metadata = BackupMetadata()
        assert metadata.backup_type == BackupType.FULL
        assert metadata.status == BackupStatus.PENDING
        assert isinstance(metadata.backup_id, str)
        assert isinstance(metadata.created_at, datetime)
        assert metadata.completed_at is None
        assert metadata.size_bytes == 0
        assert metadata.file_count == 0
        assert metadata.encrypted is False

    def test_backup_metadata_with_values(self):
        """Test creating BackupMetadata with specific values."""
        now = datetime.now()
        metadata = BackupMetadata(
            backup_id="test-id",
            backup_type=BackupType.CONFIG,
            status=BackupStatus.COMPLETED,
            created_at=now,
            size_bytes=1024,
            file_count=5,
            encrypted=True,
        )
        assert metadata.backup_id == "test-id"
        assert metadata.backup_type == BackupType.CONFIG
        assert metadata.status == BackupStatus.COMPLETED
        assert metadata.created_at == now
        assert metadata.size_bytes == 1024
        assert metadata.file_count == 5
        assert metadata.encrypted is True

    def test_backup_metadata_to_dict(self):
        """Test serialization of BackupMetadata to dict."""
        now = datetime.now()
        metadata = BackupMetadata(
            backup_id="test-id",
            backup_type=BackupType.AUDIT,
            status=BackupStatus.COMPLETED,
            created_at=now,
            completed_at=now,
            size_bytes=2048,
            file_count=10,
        )
        data = metadata.to_dict()

        assert data["backup_id"] == "test-id"
        assert data["backup_type"] == "audit"
        assert data["status"] == "completed"
        assert data["created_at"] == now.isoformat()
        assert data["completed_at"] == now.isoformat()
        assert data["size_bytes"] == 2048
        assert data["file_count"] == 10

    def test_backup_metadata_from_dict(self):
        """Test deserialization of BackupMetadata from dict."""
        now = datetime.now()
        data = {
            "backup_id": "test-id",
            "backup_type": "database",
            "status": "completed",
            "created_at": now.isoformat(),
            "completed_at": now.isoformat(),
            "size_bytes": 4096,
            "file_count": 3,
            "encrypted": True,
            "backup_path": "/path/to/backup.tar.gz",
            "error": None,
            "includes_config": True,
            "includes_audit": True,
            "includes_databases": True,
        }
        metadata = BackupMetadata.from_dict(data)

        assert metadata.backup_id == "test-id"
        assert metadata.backup_type == BackupType.DATABASE
        assert metadata.status == BackupStatus.COMPLETED
        assert metadata.size_bytes == 4096
        assert metadata.file_count == 3
        assert metadata.encrypted is True


class TestBackupManager:
    """Tests for BackupManager."""

    @pytest.fixture
    def temp_backup_dir(self, tmp_path: Path) -> Path:
        """Create temporary backup directory."""
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        return backup_dir

    @pytest.fixture
    def temp_config_dir(self, tmp_path: Path) -> Path:
        """Create temporary config directory with test files."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "config.toml").write_text("[settings]\ntest = true")
        (config_dir / "users.db").write_bytes(b"fake db content")
        return config_dir

    @pytest.fixture
    def temp_data_dir(self, tmp_path: Path) -> Path:
        """Create temporary data directory with audit logs."""
        data_dir = tmp_path / "data"
        audit_dir = data_dir / "audit"
        audit_dir.mkdir(parents=True)
        (audit_dir / "2026-02.jsonl").write_text('{"event": "test"}\n')
        return data_dir

    @pytest.fixture
    def manager(
        self,
        temp_backup_dir: Path,
        temp_config_dir: Path,
        temp_data_dir: Path,
    ) -> BackupManager:
        """Create BackupManager with temporary directories."""
        manager = BackupManager(backup_dir=temp_backup_dir)
        manager._config_dir = temp_config_dir
        manager._data_dir = temp_data_dir
        return manager

    def test_backup_manager_initialization(self, temp_backup_dir: Path):
        """Test BackupManager initialization creates backup directory."""
        manager = BackupManager(backup_dir=temp_backup_dir)
        assert manager.backup_dir == temp_backup_dir
        assert temp_backup_dir.exists()
        assert manager._running is False

    def test_create_backup_full(self, manager: BackupManager):
        """Test creating full backup."""
        metadata = manager.create_backup(backup_type=BackupType.FULL)

        assert metadata.backup_type == BackupType.FULL
        assert metadata.status == BackupStatus.COMPLETED
        assert metadata.completed_at is not None
        assert metadata.size_bytes > 0
        assert metadata.file_count > 0
        assert metadata.includes_config is True
        assert metadata.includes_audit is True
        assert metadata.includes_databases is True

        # Verify backup file exists
        backup_path = Path(metadata.backup_path)
        assert backup_path.exists()
        assert backup_path.suffix == ".gz"

    def test_create_backup_config_only(self, manager: BackupManager):
        """Test creating config-only backup."""
        metadata = manager.create_backup(backup_type=BackupType.CONFIG)

        assert metadata.backup_type == BackupType.CONFIG
        assert metadata.status == BackupStatus.COMPLETED
        assert metadata.includes_config is True
        assert metadata.includes_audit is False
        assert metadata.includes_databases is False

    def test_create_backup_audit_only(self, manager: BackupManager):
        """Test creating audit-only backup."""
        metadata = manager.create_backup(backup_type=BackupType.AUDIT)

        assert metadata.backup_type == BackupType.AUDIT
        assert metadata.includes_config is False
        assert metadata.includes_audit is True
        assert metadata.includes_databases is False

    def test_create_backup_database_only(self, manager: BackupManager):
        """Test creating database-only backup."""
        metadata = manager.create_backup(backup_type=BackupType.DATABASE)

        assert metadata.backup_type == BackupType.DATABASE
        assert metadata.includes_config is False
        assert metadata.includes_audit is False
        assert metadata.includes_databases is True

    def test_backup_includes_databases(self, manager: BackupManager):
        """Test backup includes database files."""
        # Create additional database files
        (manager._config_dir / "sessions.db").write_bytes(b"sessions data")
        (manager._config_dir / "retention.db").write_bytes(b"retention data")
        (manager._config_dir / "emergency.db").write_bytes(b"emergency data")

        metadata = manager.create_backup(backup_type=BackupType.DATABASE)

        assert metadata.status == BackupStatus.COMPLETED
        assert metadata.file_count >= 4  # All 4 database files

        # Verify databases are in backup
        backup_path = Path(metadata.backup_path)
        with tarfile.open(backup_path, "r:gz") as tar:
            names = tar.getnames()
            assert "databases/users.db" in names
            assert "databases/sessions.db" in names
            assert "databases/retention.db" in names
            assert "databases/emergency.db" in names

    def test_backup_includes_metadata(self, manager: BackupManager):
        """Test backup includes metadata file."""
        metadata = manager.create_backup(backup_type=BackupType.FULL)
        backup_path = Path(metadata.backup_path)

        with tarfile.open(backup_path, "r:gz") as tar:
            # Verify metadata file exists
            assert "backup_metadata.json" in tar.getnames()

            # Extract and verify metadata content
            meta_file = tar.extractfile("backup_metadata.json")
            assert meta_file is not None
            meta_data = json.loads(meta_file.read())
            assert meta_data["backup_id"] == metadata.backup_id

    def test_backup_encryption(self, manager: BackupManager):
        """Test creating encrypted backup."""
        password = "test_password_123"
        metadata = manager.create_backup(
            backup_type=BackupType.CONFIG,
            encrypt=True,
            password=password,
        )

        assert metadata.encrypted is True
        assert metadata.status == BackupStatus.COMPLETED

        # Verify encrypted file exists
        backup_path = Path(metadata.backup_path)
        assert backup_path.exists()
        assert backup_path.suffix == ".enc"

    def test_backup_encryption_requires_password(self, manager: BackupManager):
        """Test encrypted backup requires password."""
        with pytest.raises(ValueError, match="Password required"):
            manager.create_backup(backup_type=BackupType.FULL, encrypt=True, password=None)

    def test_list_backups(self, manager: BackupManager):
        """Test listing available backups."""
        # Create multiple backups
        metadata1 = manager.create_backup(backup_type=BackupType.CONFIG)
        metadata2 = manager.create_backup(backup_type=BackupType.AUDIT)

        # List backups
        backups = manager.list_backups()

        assert len(backups) >= 2
        backup_ids = [b.backup_id for b in backups]
        assert metadata1.backup_id in backup_ids
        assert metadata2.backup_id in backup_ids

        # Verify sorted by date (newest first)
        if len(backups) >= 2:
            assert backups[0].created_at >= backups[1].created_at

    def test_list_backups_includes_encrypted(self, manager: BackupManager):
        """Test listing includes encrypted backups."""
        metadata = manager.create_backup(
            backup_type=BackupType.FULL,
            encrypt=True,
            password="test_pass",
        )

        backups = manager.list_backups()
        encrypted_backup = next((b for b in backups if b.backup_id == metadata.backup_id), None)

        assert encrypted_backup is not None
        assert encrypted_backup.encrypted is True

    def test_restore_backup(self, manager: BackupManager, tmp_path: Path):
        """Test restoring from backup."""
        # Create backup
        metadata = manager.create_backup(backup_type=BackupType.FULL)

        # Clear config directory
        for file in manager._config_dir.iterdir():
            if file.is_file():
                file.unlink()

        # Restore backup
        backup_path = Path(metadata.backup_path)
        success = manager.restore_backup(backup_path, restore_config=True)

        assert success is True

        # Verify files restored
        assert (manager._config_dir / "config.toml").exists()
        assert (manager._config_dir / "users.db").exists()

    def test_restore_backup_selective(self, manager: BackupManager):
        """Test selective restore of backup components."""
        # Create full backup
        metadata = manager.create_backup(backup_type=BackupType.FULL)

        # Clear directories
        for file in manager._config_dir.iterdir():
            if file.is_file():
                file.unlink()
        for file in (manager._data_dir / "audit").iterdir():
            if file.is_file():
                file.unlink()

        # Restore only config
        backup_path = Path(metadata.backup_path)
        success = manager.restore_backup(
            backup_path,
            restore_config=True,
            restore_audit=False,
            restore_databases=False,
        )

        assert success is True
        assert (manager._config_dir / "config.toml").exists()

    def test_restore_encrypted_backup(self, manager: BackupManager):
        """Test restoring encrypted backup."""
        password = "secure_password_456"

        # Create encrypted backup
        metadata = manager.create_backup(
            backup_type=BackupType.CONFIG,
            encrypt=True,
            password=password,
        )

        # Clear config
        for file in manager._config_dir.iterdir():
            if file.is_file():
                file.unlink()

        # Restore with password
        backup_path = Path(metadata.backup_path)
        success = manager.restore_backup(backup_path, password=password)

        assert success is True
        assert (manager._config_dir / "config.toml").exists()

    def test_restore_encrypted_backup_requires_password(self, manager: BackupManager):
        """Test restoring encrypted backup without password fails."""
        # Create encrypted backup
        metadata = manager.create_backup(
            backup_type=BackupType.CONFIG,
            encrypt=True,
            password="test_pass",
        )

        # Try restore without password - should return False
        backup_path = Path(metadata.backup_path)
        success = manager.restore_backup(backup_path, password=None)
        assert success is False

    def test_delete_backup(self, manager: BackupManager):
        """Test deleting backup."""
        # Create backup
        metadata = manager.create_backup(backup_type=BackupType.CONFIG)
        backup_path = Path(metadata.backup_path)
        assert backup_path.exists()

        # Delete backup
        success = manager.delete_backup(metadata.backup_id)

        assert success is True
        assert not backup_path.exists()

    def test_delete_nonexistent_backup(self, manager: BackupManager):
        """Test deleting non-existent backup returns False."""
        success = manager.delete_backup("nonexistent-id")
        assert success is False

    @patch("pdfsigner.core.audit.get_audit_logger")
    def test_backup_logs_to_audit(self, mock_get_audit: MagicMock, manager: BackupManager):
        """Test backup operation is logged to audit trail."""
        mock_audit = MagicMock()
        mock_get_audit.return_value = mock_audit

        # Create backup
        metadata = manager.create_backup(backup_type=BackupType.FULL)

        # Verify audit logging
        mock_audit.log_event.assert_called_once()
        call_args = mock_audit.log_event.call_args[0]
        event = call_args[0]
        assert event.details["backup_id"] == metadata.backup_id
        assert event.details["backup_type"] == "full"

    def test_backup_manager_start_stop(self, manager: BackupManager):
        """Test starting and stopping backup scheduler."""
        manager.start(interval_hours=1)
        assert manager._running is True
        assert manager._timer is not None

        manager.stop()
        assert manager._running is False

    def test_backup_manager_start_twice(self, manager: BackupManager):
        """Test starting scheduler twice has no effect."""
        manager.start(interval_hours=1)
        first_timer = manager._timer

        manager.start(interval_hours=1)
        # Timer should not change
        assert manager._timer is first_timer

        manager.stop()


class TestBackupManagerSingleton:
    """Tests for BackupManager singleton."""

    def test_singleton_pattern(self):
        """Test get_backup_manager returns same instance."""
        manager1 = get_backup_manager()
        manager2 = get_backup_manager()

        assert manager1 is manager2

    def test_restore_backup_convenience_function(self, tmp_path: Path):
        """Test restore_backup convenience function."""
        # Create manager and backup
        manager = BackupManager(backup_dir=tmp_path / "backups")
        manager._config_dir = tmp_path / "config"
        manager._data_dir = tmp_path / "data"

        # Create test files
        manager._config_dir.mkdir()
        (manager._config_dir / "test.txt").write_text("test")

        # Create backup
        metadata = manager.create_backup(backup_type=BackupType.CONFIG)

        # Use convenience function
        backup_path = Path(metadata.backup_path)
        success = restore_backup(backup_path)

        # Should delegate to manager
        assert success is True


class TestBackupManagerEdgeCases:
    """Tests for edge cases and error handling."""

    def test_backup_with_empty_directories(self, tmp_path: Path):
        """Test backup with empty directories."""
        manager = BackupManager(backup_dir=tmp_path / "backups")
        manager._config_dir = tmp_path / "config"
        manager._data_dir = tmp_path / "data"

        # Create empty directories
        manager._config_dir.mkdir()
        (manager._data_dir / "audit").mkdir(parents=True)

        # Should create backup without error
        metadata = manager.create_backup(backup_type=BackupType.FULL)
        assert metadata.status == BackupStatus.COMPLETED
        assert metadata.file_count >= 1  # At least metadata file

    def test_backup_handles_missing_databases(self, tmp_path: Path):
        """Test backup continues when some databases missing."""
        manager = BackupManager(backup_dir=tmp_path / "backups")
        manager._config_dir = tmp_path / "config"
        manager._data_dir = tmp_path / "data"

        # Create only one database
        manager._config_dir.mkdir()
        (manager._config_dir / "users.db").write_bytes(b"data")

        # Should succeed with available files
        metadata = manager.create_backup(backup_type=BackupType.DATABASE)
        assert metadata.status == BackupStatus.COMPLETED

    def test_restore_handles_missing_target_directories(self, tmp_path: Path):
        """Test restore creates missing target directories."""
        manager = BackupManager(backup_dir=tmp_path / "backups")
        manager._config_dir = tmp_path / "config"
        manager._data_dir = tmp_path / "data"

        # Create source directories
        manager._config_dir.mkdir()
        (manager._config_dir / "test.txt").write_text("test")

        # Create backup
        metadata = manager.create_backup(backup_type=BackupType.CONFIG)

        # Use new target directories
        new_config_dir = tmp_path / "new_config"
        manager._config_dir = new_config_dir

        # Restore should create directories
        backup_path = Path(metadata.backup_path)
        success = manager.restore_backup(backup_path)

        assert success is True
        assert new_config_dir.exists()
        assert (new_config_dir / "test.txt").exists()

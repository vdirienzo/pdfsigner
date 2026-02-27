"""
test_audit_logger.py - Tests for audit logger module

Author: Homero Thompson del Lago del Terror

Comprehensive tests for audit event logging, querying, and management.
"""

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from pdfsigner.core.audit import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    log_certificate_selection,
    log_config_change,
    log_signing_event,
    log_token_event,
    log_validation_event,
)


@pytest.fixture
def temp_audit_dir():
    """Provide temporary directory for audit logs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def audit_logger(temp_audit_dir):
    """Provide audit logger instance with temp directory."""
    # Reset singleton for testing
    AuditLogger._instance = None
    logger = AuditLogger(log_dir=temp_audit_dir, enabled=True, retention_days=90)
    yield logger
    # Cleanup singleton
    AuditLogger._instance = None


class TestAuditEvent:
    """Tests for AuditEvent data structure."""

    def test_create_audit_event_with_defaults(self):
        """Test creating audit event with default values."""
        # Arrange & Act
        event = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS)

        # Assert
        assert event.event_type == AuditEventType.SIGN_SUCCESS
        assert event.status == "SUCCESS"
        assert event.event_id is not None
        assert event.timestamp is not None
        assert event.hostname is not None

    def test_audit_event_to_dict_converts_types(self):
        """Test that to_dict() converts enum and datetime to strings."""
        # Arrange
        event = AuditEvent(
            event_type=AuditEventType.VALIDATE_FAILURE,
            user_cn="Test User",
            status="FAILURE",
        )

        # Act
        data = event.to_dict()

        # Assert
        assert isinstance(data["event_type"], str)
        assert data["event_type"] == "validate_failure"
        assert isinstance(data["timestamp"], str)
        assert "T" in data["timestamp"]  # ISO format

    def test_audit_event_from_dict_restores_types(self):
        """Test that from_dict() restores enum and datetime types."""
        # Arrange
        data = {
            "event_type": "sign_success",
            "timestamp": "2024-01-15T10:30:00",
            "event_id": "test-123",
            "user_cn": "Test User",
            "hostname": "localhost",
            "document_path": None,
            "document_hash_sha256": None,
            "certificate_serial": None,
            "certificate_issuer": None,
            "status": "SUCCESS",
            "error_message": None,
            "details": {},
        }

        # Act
        event = AuditEvent.from_dict(data)

        # Assert
        assert isinstance(event.event_type, AuditEventType)
        assert event.event_type == AuditEventType.SIGN_SUCCESS
        assert isinstance(event.timestamp, datetime)
        assert event.user_cn == "Test User"


class TestAuditLogger:
    """Tests for AuditLogger class."""

    def test_singleton_returns_same_instance(self, temp_audit_dir):
        """Test that get_instance() returns singleton."""
        # Arrange
        AuditLogger._instance = None

        # Act
        instance1 = AuditLogger.get_instance(log_dir=temp_audit_dir)
        instance2 = AuditLogger.get_instance(log_dir=temp_audit_dir)

        # Assert
        assert instance1 is instance2

        # Cleanup
        AuditLogger._instance = None

    def test_log_event_creates_file(self, audit_logger):
        """Test that log_event() creates log file."""
        # Arrange
        event = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS)

        # Act
        audit_logger.log_event(event)

        # Assert
        log_file = audit_logger._get_log_file_path(event.timestamp)
        assert log_file.exists()

    def test_log_event_writes_json_line(self, audit_logger):
        """Test that log_event() writes valid JSON line."""
        # Arrange
        event = AuditEvent(
            event_type=AuditEventType.SIGN_SUCCESS,
            user_cn="Test User",
            document_path="/tmp/test.pdf",
        )

        # Act
        audit_logger.log_event(event)

        # Assert
        log_file = audit_logger._get_log_file_path(event.timestamp)
        with open(log_file) as f:
            line = f.readline()
            data = json.loads(line)
            assert data["event_type"] == "sign_success"
            assert data["user_cn"] == "Test User"

    def test_log_event_disabled_does_not_write(self, temp_audit_dir):
        """Test that disabled logger doesn't write events."""
        # Arrange
        logger = AuditLogger(log_dir=temp_audit_dir, enabled=False)
        event = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS)

        # Act
        logger.log_event(event)

        # Assert
        log_files = list(temp_audit_dir.glob("*.jsonl"))
        assert len(log_files) == 0

    def test_get_events_returns_all_events(self, audit_logger):
        """Test that get_events() returns all logged events."""
        # Arrange
        event1 = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS)
        event2 = AuditEvent(event_type=AuditEventType.VALIDATE_SUCCESS)
        audit_logger.log_event(event1)
        audit_logger.log_event(event2)

        # Act
        events = audit_logger.get_events()

        # Assert
        assert len(events) == 2
        assert events[0].event_type == AuditEventType.SIGN_SUCCESS
        assert events[1].event_type == AuditEventType.VALIDATE_SUCCESS

    def test_get_events_filters_by_date(self, audit_logger):
        """Test that get_events() filters by date range."""
        # Arrange
        now = datetime.now()
        yesterday = now - timedelta(days=1)
        tomorrow = now + timedelta(days=1)

        event1 = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS, timestamp=yesterday)
        event2 = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS, timestamp=now)
        event3 = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS, timestamp=tomorrow)

        audit_logger.log_event(event1)
        audit_logger.log_event(event2)
        audit_logger.log_event(event3)

        # Act
        events = audit_logger.get_events(start_date=now, end_date=tomorrow)

        # Assert
        assert len(events) == 2
        assert all(e.timestamp >= now for e in events)

    def test_get_events_filters_by_type(self, audit_logger):
        """Test that get_events() filters by event type."""
        # Arrange
        event1 = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS)
        event2 = AuditEvent(event_type=AuditEventType.VALIDATE_SUCCESS)
        event3 = AuditEvent(event_type=AuditEventType.SIGN_FAILURE)

        audit_logger.log_event(event1)
        audit_logger.log_event(event2)
        audit_logger.log_event(event3)

        # Act
        events = audit_logger.get_events(
            event_types=[AuditEventType.SIGN_SUCCESS, AuditEventType.SIGN_FAILURE]
        )

        # Assert
        assert len(events) == 2
        assert all(
            e.event_type in (AuditEventType.SIGN_SUCCESS, AuditEventType.SIGN_FAILURE)
            for e in events
        )

    def test_cleanup_old_logs_deletes_old_files(self, temp_audit_dir):
        """Test that cleanup_old_logs() removes old files."""
        # Arrange
        logger = AuditLogger(log_dir=temp_audit_dir, enabled=True, retention_days=30)

        # Create old log file (2 months ago)
        old_date = datetime.now() - timedelta(days=60)
        old_log_file = temp_audit_dir / f"audit_{old_date.strftime('%Y-%m')}.jsonl"
        old_log_file.write_text('{"test": "data"}\n')

        # Create recent log file
        recent_date = datetime.now()
        recent_log_file = temp_audit_dir / f"audit_{recent_date.strftime('%Y-%m')}.jsonl"
        recent_log_file.write_text('{"test": "data"}\n')

        # Act
        deleted = logger.cleanup_old_logs()

        # Assert
        assert deleted == 1
        assert not old_log_file.exists()
        assert recent_log_file.exists()

    def test_export_csv_generates_valid_csv(self, audit_logger):
        """Test that export_csv() generates valid CSV."""
        # Arrange
        event1 = AuditEvent(
            event_type=AuditEventType.SIGN_SUCCESS,
            user_cn="Test User",
            document_path="/tmp/test.pdf",
        )
        event2 = AuditEvent(
            event_type=AuditEventType.VALIDATE_SUCCESS,
            user_cn="Validator",
        )

        events = [event1, event2]

        # Act
        csv_output = audit_logger.export_csv(events)

        # Assert
        lines = csv_output.strip().split("\n")
        assert len(lines) == 3  # Header + 2 events
        assert "Event ID" in lines[0]
        assert "Test User" in lines[1]
        assert "Validator" in lines[2]

    def test_export_csv_empty_events_returns_empty(self, audit_logger):
        """Test that export_csv() handles empty events list."""
        # Arrange
        events = []

        # Act
        csv_output = audit_logger.export_csv(events)

        # Assert
        assert csv_output == ""

    def test_monthly_rotation_creates_separate_files(self, audit_logger, temp_audit_dir):
        """Test that events in different months create separate files."""
        # Arrange
        january = datetime(2024, 1, 15)
        february = datetime(2024, 2, 15)

        event1 = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS, timestamp=january)
        event2 = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS, timestamp=february)

        # Act
        audit_logger.log_event(event1)
        audit_logger.log_event(event2)

        # Assert
        jan_file = temp_audit_dir / "audit_2024-01.jsonl"
        feb_file = temp_audit_dir / "audit_2024-02.jsonl"
        assert jan_file.exists()
        assert feb_file.exists()

    def test_thread_safety_concurrent_writes(self, audit_logger):
        """Test that concurrent writes are thread-safe."""
        import threading

        # Arrange
        events_to_write = []
        for i in range(10):
            events_to_write.append(
                AuditEvent(
                    event_type=AuditEventType.SIGN_SUCCESS,
                    user_cn=f"User {i}",
                )
            )

        # Act
        threads = []
        for event in events_to_write:
            thread = threading.Thread(target=audit_logger.log_event, args=(event,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Assert
        retrieved_events = audit_logger.get_events()
        assert len(retrieved_events) == 10


class TestWriteEventErrorPropagation:
    """Tests for _write_event error propagation (HIPAA §164.312(b))."""

    def test_write_event_raises_on_unwritable_directory(self, temp_audit_dir):
        """Test that _write_event raises OSError when log dir is not writable.

        HIPAA §164.312(b) requires audit events to never be silently lost.
        If disk write fails, the caller must know so it can handle the
        compliance violation.
        """
        # Arrange
        AuditLogger._instance = None
        audit_log = AuditLogger(log_dir=temp_audit_dir, enabled=True)
        event = AuditEvent(event_type=AuditEventType.SIGN_SUCCESS)

        # Make the log directory read-only so file creation/append fails
        import os

        os.chmod(temp_audit_dir, 0o444)

        try:
            # Act & Assert
            with pytest.raises(OSError):
                audit_log._write_event(event)
        finally:
            # Restore permissions for cleanup
            os.chmod(temp_audit_dir, 0o755)
            AuditLogger._instance = None

    def test_write_event_succeeds_under_normal_conditions(self, audit_logger):
        """Test that _write_event still works normally when no errors occur."""
        # Arrange
        event = AuditEvent(
            event_type=AuditEventType.SIGN_SUCCESS,
            user_cn="Normal User",
        )

        # Act (should not raise)
        audit_logger._write_event(event)

        # Assert
        events = audit_logger.get_events()
        assert len(events) == 1
        assert events[0].user_cn == "Normal User"


class TestHelperFunctions:
    """Tests for helper functions in audit module."""

    def test_log_signing_event_success(self, audit_logger, temp_audit_dir):
        """Test log_signing_event() for successful signing."""
        # Arrange
        from pdfsigner.config.settings import Settings

        # Mock settings for test
        settings = Settings(audit_enabled=True, audit_retention_days=90)
        settings_backup = None

        # Create temp PDF
        temp_pdf = temp_audit_dir / "test.pdf"
        temp_pdf.write_bytes(b"%PDF-1.4\ntest content")

        # Temporarily replace singleton
        from pdfsigner import config

        settings_backup = config.settings._settings
        config.settings._settings = settings

        # Reset audit logger singleton
        AuditLogger._instance = audit_logger

        try:
            # Act
            log_signing_event(
                document_path=temp_pdf,
                certificate_serial="abc123",
                certificate_issuer="Test CA",
                user_cn="Test User",
                success=True,
            )

            # Assert
            events = audit_logger.get_events()
            assert len(events) == 1
            assert events[0].event_type == AuditEventType.SIGN_SUCCESS
            assert events[0].certificate_serial == "abc123"
            assert events[0].user_cn == "Test User"

        finally:
            # Restore
            config.settings._settings = settings_backup
            AuditLogger._instance = None

    def test_log_validation_event_failure(self, audit_logger, temp_audit_dir):
        """Test log_validation_event() for failed validation."""
        # Arrange
        from pdfsigner.config.settings import Settings

        settings = Settings(audit_enabled=True, audit_retention_days=90)
        temp_pdf = temp_audit_dir / "test.pdf"
        temp_pdf.write_bytes(b"%PDF-1.4\ntest content")

        from pdfsigner import config

        settings_backup = config.settings._settings
        config.settings._settings = settings
        AuditLogger._instance = audit_logger

        try:
            # Act
            log_validation_event(
                document_path=temp_pdf,
                signature_count=1,
                all_valid=False,
                error="Invalid signature",
            )

            # Assert
            events = audit_logger.get_events()
            assert len(events) == 1
            assert events[0].event_type == AuditEventType.VALIDATE_FAILURE
            assert events[0].error_message == "Invalid signature"

        finally:
            config.settings._settings = settings_backup
            AuditLogger._instance = None

    def test_log_token_event_login(self, audit_logger):
        """Test log_token_event() for token login."""
        # Arrange
        from pdfsigner.config.settings import Settings

        settings = Settings(audit_enabled=True, audit_retention_days=90)

        from pdfsigner import config

        settings_backup = config.settings._settings
        config.settings._settings = settings
        AuditLogger._instance = audit_logger

        try:
            # Act
            log_token_event(
                event_type=AuditEventType.TOKEN_LOGIN,
                user_cn="Test User",
                success=True,
            )

            # Assert
            events = audit_logger.get_events()
            assert len(events) == 1
            assert events[0].event_type == AuditEventType.TOKEN_LOGIN
            assert events[0].user_cn == "Test User"

        finally:
            config.settings._settings = settings_backup
            AuditLogger._instance = None

    def test_log_certificate_selection_records_selection(self, audit_logger):
        """Test log_certificate_selection() records selection."""
        # Arrange
        from pdfsigner.config.settings import Settings

        settings = Settings(audit_enabled=True, audit_retention_days=90)

        from pdfsigner import config

        settings_backup = config.settings._settings
        config.settings._settings = settings
        AuditLogger._instance = audit_logger

        try:
            # Act
            log_certificate_selection(
                certificate_serial="def456",
                certificate_issuer="Test CA",
                user_cn="Test User",
                details={"slot": 0},
            )

            # Assert
            events = audit_logger.get_events()
            assert len(events) == 1
            assert events[0].event_type == AuditEventType.CERTIFICATE_SELECTED
            assert events[0].certificate_serial == "def456"
            assert events[0].details["slot"] == 0

        finally:
            config.settings._settings = settings_backup
            AuditLogger._instance = None

    def test_log_config_change_tracks_changes(self, audit_logger):
        """Test log_config_change() tracks setting changes."""
        # Arrange
        from pdfsigner.config.settings import Settings

        settings = Settings(audit_enabled=True, audit_retention_days=90)

        from pdfsigner import config

        settings_backup = config.settings._settings
        config.settings._settings = settings
        AuditLogger._instance = audit_logger

        try:
            # Act
            log_config_change(
                setting_name="tsa_url",
                old_value="https://old-tsa.com",
                new_value="https://new-tsa.com",
                user_cn="Admin User",
            )

            # Assert
            events = audit_logger.get_events()
            assert len(events) == 1
            assert events[0].event_type == AuditEventType.CONFIG_CHANGE
            assert events[0].details["setting_name"] == "tsa_url"
            assert events[0].details["new_value"] == "https://new-tsa.com"

        finally:
            config.settings._settings = settings_backup
            AuditLogger._instance = None

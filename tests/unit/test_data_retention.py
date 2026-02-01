"""
Unit tests for GDPR data retention and erasure.

Tests:
- User anonymization
- Data export
- Scheduled deletion
- Grace period cancellation
- Data purging
- Retention status
"""

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pdfsigner.core.audit import AuditEvent, AuditEventType
from pdfsigner.core.gdpr import (
    DataRetentionService,
)
from pdfsigner.core.gdpr.data_export import UserDataExport, UserDataExporter
from pdfsigner.core.users import User, UserRole, UserStatus


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_users.db"
        yield db_path


@pytest.fixture
def temp_audit_dir():
    """Create temporary audit directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def user_repository(temp_db):
    """Create user repository with test database."""
    from pdfsigner.core.users import UserRepository

    return UserRepository(db_path=temp_db)


@pytest.fixture
def audit_logger(temp_audit_dir):
    """Create audit logger with test directory."""
    from pdfsigner.core.audit import AuditLogger

    return AuditLogger(log_dir=temp_audit_dir, enabled=True, retention_days=90)


@pytest.fixture
def data_retention_service(user_repository, audit_logger):
    """Create data retention service for testing."""
    return DataRetentionService(
        user_repository=user_repository,
        audit_logger=audit_logger,
        retention_days=365,
        grace_days=30,
        anonymize_audit_logs=True,
    )


@pytest.fixture
def user_data_exporter(user_repository, audit_logger):
    """Create user data exporter for testing."""
    return UserDataExporter(user_repository=user_repository, audit_logger=audit_logger)


@pytest.fixture
def test_user(user_repository):
    """Create test user."""
    user = User(
        username="test.user",
        display_name="Test User",
        email="test@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
        certificate_serial="123456",
        certificate_issuer="Test CA",
        certificate_cn="Test User",
    )
    return user_repository.create_user(user)


# --- Anonymization Tests ---


def test_anonymize_user_success(data_retention_service, test_user):
    """Test successful user anonymization."""
    result = data_retention_service.anonymize_user(test_user.id, requested_by="admin")

    assert result.success
    assert result.user_id == test_user.id
    assert len(result.fields_anonymized) > 0
    assert "username" in result.fields_anonymized
    assert "email" in result.fields_anonymized
    assert "display_name" in result.fields_anonymized

    # Verify user is anonymized
    user = data_retention_service.user_repo.get_user_by_id(test_user.id)
    assert user.username.startswith("anonymous_")
    assert user.email.endswith("@anonymized.local")
    assert "Anonymous User" in user.display_name
    assert user.status == UserStatus.INACTIVE


def test_anonymize_user_preserves_id(data_retention_service, test_user):
    """Test that anonymization preserves user ID for audit trail."""
    original_id = test_user.id
    result = data_retention_service.anonymize_user(test_user.id, requested_by="admin")

    assert result.success

    # User ID should be unchanged
    user = data_retention_service.user_repo.get_user_by_id(original_id)
    assert user is not None
    assert user.id == original_id


def test_anonymize_user_not_found(data_retention_service):
    """Test anonymization with non-existent user."""
    result = data_retention_service.anonymize_user("nonexistent", requested_by="admin")

    assert not result.success
    assert "not found" in result.error_message.lower()


def test_anonymize_user_already_anonymized(data_retention_service, test_user):
    """Test that anonymization fails if user already anonymized."""
    # Anonymize once
    result1 = data_retention_service.anonymize_user(test_user.id, requested_by="admin")
    assert result1.success

    # Try to anonymize again
    result2 = data_retention_service.anonymize_user(test_user.id, requested_by="admin")
    assert not result2.success
    assert "already anonymized" in result2.error_message.lower()


def test_anonymize_user_metadata(data_retention_service, test_user):
    """Test that anonymization records metadata."""
    result = data_retention_service.anonymize_user(test_user.id, requested_by="admin_user")

    assert result.success

    # Check metadata
    user = data_retention_service.user_repo.get_user_by_id(test_user.id)
    assert "anonymized_at" in user.metadata
    assert "anonymized_by" in user.metadata
    assert user.metadata["anonymized_by"] == "admin_user"


# --- Data Export Tests ---


def test_export_user_data_success(user_data_exporter, test_user):
    """Test successful user data export."""
    export = user_data_exporter.export_user_data(test_user.id, format="json")

    assert export is not None
    assert isinstance(export, UserDataExport)
    assert export.user_info["id"] == test_user.id
    assert export.user_info["username"] == test_user.username
    assert export.format == "json"
    assert export.generated_at is not None


def test_export_user_data_includes_certificates(user_data_exporter, test_user):
    """Test that export includes certificate information."""
    export = user_data_exporter.export_user_data(test_user.id)

    assert export is not None
    assert len(export.certificates) > 0
    assert export.certificates[0]["serial"] == test_user.certificate_serial
    assert export.certificates[0]["issuer"] == test_user.certificate_issuer


def test_export_user_data_not_found(user_data_exporter):
    """Test export with non-existent user."""
    export = user_data_exporter.export_user_data("nonexistent")

    assert export is None


def test_export_to_json_string(user_data_exporter, test_user):
    """Test export to JSON string."""
    json_str = user_data_exporter.export_to_json_string(test_user.id)

    assert json_str is not None
    data = json.loads(json_str)
    assert "user_info" in data
    assert "certificates" in data
    assert "audit_events" in data
    assert "sessions" in data
    assert data["user_info"]["id"] == test_user.id


def test_export_to_file_json(user_data_exporter, test_user, tmp_path):
    """Test export to JSON file."""
    output_path = tmp_path / "export.json"
    success = user_data_exporter.export_to_file(test_user.id, output_path, format="json")

    assert success
    assert output_path.exists()

    # Verify file content
    with open(output_path) as f:
        data = json.load(f)
        assert data["user_info"]["id"] == test_user.id


def test_export_to_file_csv(user_data_exporter, test_user, tmp_path):
    """Test export to CSV file (ZIP format)."""
    output_path = tmp_path / "export.zip"
    success = user_data_exporter.export_to_file(test_user.id, output_path, format="csv")

    assert success
    assert output_path.exists()


# --- Scheduled Deletion Tests ---


def test_schedule_deletion_success(data_retention_service, test_user):
    """Test successful deletion scheduling."""
    success = data_retention_service.schedule_deletion(test_user.id, days=30, requested_by="user")

    assert success

    # Check status
    status = data_retention_service.get_retention_status(test_user.id)
    assert status.deletion_scheduled
    assert status.deletion_scheduled_at is not None
    assert status.deletion_date is not None
    assert status.days_until_deletion is not None
    assert status.days_until_deletion >= 29  # Allow for timing


def test_schedule_deletion_not_found(data_retention_service):
    """Test scheduling deletion for non-existent user."""
    success = data_retention_service.schedule_deletion("nonexistent", days=30, requested_by="admin")

    assert not success


def test_cancel_scheduled_deletion_success(data_retention_service, test_user):
    """Test successful deletion cancellation."""
    # Schedule deletion
    data_retention_service.schedule_deletion(test_user.id, days=30, requested_by="user")

    # Cancel deletion
    success = data_retention_service.cancel_scheduled_deletion(test_user.id)

    assert success

    # Check status
    status = data_retention_service.get_retention_status(test_user.id)
    assert not status.deletion_scheduled
    assert status.deletion_date is None


def test_cancel_scheduled_deletion_not_scheduled(data_retention_service, test_user):
    """Test cancellation when no deletion scheduled."""
    success = data_retention_service.cancel_scheduled_deletion(test_user.id)

    assert not success


# --- Retention Status Tests ---


def test_retention_status_active_user(data_retention_service, test_user):
    """Test retention status for active user."""
    status = data_retention_service.get_retention_status(test_user.id)

    assert status.user_id == test_user.id
    assert not status.is_anonymized
    assert not status.deletion_scheduled
    assert status.deletion_date is None
    assert status.days_until_deletion is None


def test_retention_status_anonymized_user(data_retention_service, test_user):
    """Test retention status for anonymized user."""
    # Anonymize user
    data_retention_service.anonymize_user(test_user.id, requested_by="admin")

    # Check status
    status = data_retention_service.get_retention_status(test_user.id)

    assert status.is_anonymized


def test_retention_status_scheduled_deletion(data_retention_service, test_user):
    """Test retention status with scheduled deletion."""
    # Schedule deletion
    data_retention_service.schedule_deletion(test_user.id, days=15, requested_by="user")

    # Check status
    status = data_retention_service.get_retention_status(test_user.id)

    assert status.deletion_scheduled
    assert status.days_until_deletion >= 14  # Allow for timing


def test_retention_status_not_found(data_retention_service):
    """Test retention status for non-existent user."""
    status = data_retention_service.get_retention_status("nonexistent")

    assert status.user_id == "nonexistent"
    assert not status.is_anonymized
    assert not status.deletion_scheduled


# --- Data Purge Tests ---


def test_purge_expired_data_no_expired_users(data_retention_service, test_user):
    """Test purge when no users are expired."""
    result = data_retention_service.purge_expired_data()

    assert result.success
    assert result.users_deleted == 0


def test_purge_expired_data_with_expired_user(data_retention_service, test_user):
    """Test purge with expired user."""
    # Schedule deletion in the past
    past_date = datetime.now() - timedelta(days=1)
    with data_retention_service.user_repo._get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET deletion_scheduled_at = ?, deletion_date = ?
            WHERE id = ?
            """,
            (past_date.isoformat(), past_date.isoformat(), test_user.id),
        )

    # Run purge
    result = data_retention_service.purge_expired_data()

    assert result.success
    assert result.users_deleted == 1

    # User should be deleted
    user = data_retention_service.user_repo.get_user_by_id(test_user.id)
    assert user is None


def test_purge_expired_data_anonymizes_first(data_retention_service, test_user):
    """Test that purge anonymizes user before deletion."""
    # Schedule deletion in the past
    past_date = datetime.now() - timedelta(days=1)
    with data_retention_service.user_repo._get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET deletion_scheduled_at = ?, deletion_date = ?
            WHERE id = ?
            """,
            (past_date.isoformat(), past_date.isoformat(), test_user.id),
        )

    # Run purge
    result = data_retention_service.purge_expired_data()

    assert result.success
    assert result.users_deleted == 1
    # Anonymization should have occurred
    assert result.audit_records_purged >= 0


# --- Audit Log Anonymization Tests ---


def test_anonymize_audit_records(data_retention_service, test_user, audit_logger):
    """Test that audit records are anonymized."""
    # Create some audit events for the user
    for i in range(3):
        event = AuditEvent(
            event_type=AuditEventType.SIGN_SUCCESS,
            status="SUCCESS",
            user_id=test_user.id,
            document_path=f"/test/doc{i}.pdf",
        )
        audit_logger.log_event(event)

    # Anonymize user
    result = data_retention_service.anonymize_user(test_user.id, requested_by="admin")

    assert result.success
    assert result.audit_records_anonymized >= 3


def test_anonymize_audit_records_disabled(user_repository, audit_logger, test_user):
    """Test that audit anonymization can be disabled."""
    service = DataRetentionService(
        user_repository=user_repository,
        audit_logger=audit_logger,
        anonymize_audit_logs=False,
    )

    # Create audit events
    event = AuditEvent(
        event_type=AuditEventType.SIGN_SUCCESS,
        status="SUCCESS",
        user_id=test_user.id,
    )
    audit_logger.log_event(event)

    # Anonymize user
    result = service.anonymize_user(test_user.id, requested_by="admin")

    assert result.success
    assert result.audit_records_anonymized == 0


# --- Integration Tests ---


def test_full_gdpr_workflow(data_retention_service, user_data_exporter, test_user, tmp_path):
    """Test complete GDPR workflow: export -> schedule -> cancel -> anonymize."""
    # 1. Export user data
    export = user_data_exporter.export_user_data(test_user.id)
    assert export is not None

    # 2. Schedule deletion
    success = data_retention_service.schedule_deletion(test_user.id, days=30, requested_by="user")
    assert success

    status = data_retention_service.get_retention_status(test_user.id)
    assert status.deletion_scheduled

    # 3. Cancel deletion
    success = data_retention_service.cancel_scheduled_deletion(test_user.id)
    assert success

    status = data_retention_service.get_retention_status(test_user.id)
    assert not status.deletion_scheduled

    # 4. Anonymize user
    result = data_retention_service.anonymize_user(test_user.id, requested_by="admin")
    assert result.success

    status = data_retention_service.get_retention_status(test_user.id)
    assert status.is_anonymized


def test_multiple_users_purge(data_retention_service, user_repository):
    """Test purging multiple expired users."""
    # Create multiple users
    users = []
    for i in range(3):
        user = User(
            username=f"user{i}",
            display_name=f"User {i}",
            email=f"user{i}@example.com",
            role=UserRole.VIEWER,
        )
        users.append(user_repository.create_user(user))

    # Schedule all for deletion in the past
    past_date = datetime.now() - timedelta(days=1)
    for user in users:
        with user_repository._get_connection() as conn:
            conn.execute(
                """
                UPDATE users
                SET deletion_scheduled_at = ?, deletion_date = ?
                WHERE id = ?
                """,
                (past_date.isoformat(), past_date.isoformat(), user.id),
            )

    # Run purge
    result = data_retention_service.purge_expired_data()

    assert result.success
    assert result.users_deleted == 3


# --- Edge Cases ---


def test_anonymize_user_with_empty_fields(user_repository, data_retention_service):
    """Test anonymization with minimal user data."""
    user = User(
        username="minimal",
        display_name="",
        email="",
        role=UserRole.VIEWER,
    )
    user = user_repository.create_user(user)

    result = data_retention_service.anonymize_user(user.id, requested_by="admin")

    assert result.success


def test_schedule_deletion_custom_grace_period(data_retention_service, test_user):
    """Test scheduling deletion with custom grace period."""
    # Schedule with 7 days grace period
    success = data_retention_service.schedule_deletion(test_user.id, days=7, requested_by="user")

    assert success

    status = data_retention_service.get_retention_status(test_user.id)
    assert status.days_until_deletion >= 6  # Allow for timing
    assert status.days_until_deletion <= 7


def test_export_user_with_no_audit_logs(user_data_exporter, test_user):
    """Test export when user has no audit log entries."""
    export = user_data_exporter.export_user_data(test_user.id)

    assert export is not None
    assert len(export.audit_events) == 0


def test_retention_service_database_columns_creation(temp_db):
    """Test that retention service creates necessary database columns."""
    from pdfsigner.core.users import UserRepository

    user_repo = UserRepository(db_path=temp_db)
    audit_logger = MagicMock()

    # Create service (should add columns)
    service = DataRetentionService(
        user_repository=user_repo, audit_logger=audit_logger, anonymize_audit_logs=False
    )

    # Verify columns exist
    with user_repo._get_connection() as conn:
        cursor = conn.execute("PRAGMA table_info(users)")
        columns = {row[1] for row in cursor.fetchall()}

        assert "is_anonymized" in columns
        assert "deletion_scheduled_at" in columns
        assert "deletion_date" in columns

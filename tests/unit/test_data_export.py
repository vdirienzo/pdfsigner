"""
Test GDPR data export module (Article 20 - Right to Data Portability).

Tests cover:
- Complete user data export (profile, certificates, audit, sessions)
- JSON format machine-readability
- Export with non-existent user
- IDOR prevention (only export requested user's data)
- Large data export handling
- All GDPR-required data categories
- CSV export format
- File export operations
- Error handling and edge cases
"""

import json
import tempfile
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from pdfsigner.core.audit import AuditEvent, AuditEventType
from pdfsigner.core.gdpr.data_export import (
    UserDataExport,
    UserDataExporter,
    get_user_data_exporter,
)
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
def session_manager():
    """Create mock session manager."""
    mock = Mock()
    mock.get_user_sessions.return_value = []
    return mock


@pytest.fixture
def user_data_exporter(user_repository, audit_logger):
    """Create user data exporter for testing."""
    return UserDataExporter(user_repository=user_repository, audit_logger=audit_logger)


@pytest.fixture
def test_user(user_repository):
    """Create test user with certificate."""
    user = User(
        username="john.doe",
        display_name="John Doe",
        email="john.doe@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
        certificate_serial="ABC123456789",
        certificate_issuer="CN=Test CA, O=Example Org",
        certificate_cn="John Doe",
    )
    return user_repository.create_user(user)


@pytest.fixture
def test_user_with_audit(test_user, audit_logger):
    """Create test user with audit history."""
    # Create audit events for user
    for i in range(5):
        event = AuditEvent(
            event_type=AuditEventType.SIGN_SUCCESS,
            status="SUCCESS",
            user_id=test_user.id,
            document_path=f"/documents/test_{i}.pdf",
            details={"signature_id": f"sig_{i}"},
        )
        audit_logger.log_event(event)

    return test_user


# --- Export User Data Tests ---


@pytest.mark.compliance
def test_export_user_data_success(user_data_exporter, test_user):
    """Test successful user data export includes all required fields."""
    export = user_data_exporter.export_user_data(test_user.id, format="json")

    assert export is not None
    assert isinstance(export, UserDataExport)
    assert export.user_info["id"] == test_user.id
    assert export.user_info["username"] == test_user.username
    assert export.user_info["email"] == test_user.email
    assert export.format == "json"
    assert export.generated_at is not None
    assert isinstance(export.generated_at, datetime)


@pytest.mark.compliance
def test_export_user_data_includes_profile_data(user_data_exporter, test_user):
    """Test export includes complete user profile information."""
    export = user_data_exporter.export_user_data(test_user.id)

    assert export is not None
    user_info = export.user_info

    # Verify all profile fields present
    assert "id" in user_info
    assert "username" in user_info
    assert "display_name" in user_info
    assert "email" in user_info
    assert "role" in user_info
    assert "status" in user_info
    assert "created_at" in user_info

    # Verify values match
    assert user_info["username"] == "john.doe"
    assert user_info["display_name"] == "John Doe"
    assert user_info["email"] == "john.doe@example.com"


@pytest.mark.compliance
def test_export_user_data_includes_certificates(user_data_exporter, test_user):
    """Test export includes certificate binding information."""
    export = user_data_exporter.export_user_data(test_user.id)

    assert export is not None
    assert len(export.certificates) == 1

    cert = export.certificates[0]
    assert cert["serial"] == "ABC123456789"
    assert cert["issuer"] == "CN=Test CA, O=Example Org"
    assert cert["common_name"] == "John Doe"
    assert "bound_at" in cert


@pytest.mark.compliance
def test_export_user_data_includes_audit_events(user_data_exporter, test_user_with_audit):
    """Test export includes complete audit trail."""
    export = user_data_exporter.export_user_data(test_user_with_audit.id)

    assert export is not None
    assert len(export.audit_events) == 5

    # Verify audit event structure
    event = export.audit_events[0]
    assert "event_id" in event
    assert "timestamp" in event
    assert "event_type" in event
    assert "status" in event
    assert "document_path" in event
    assert "details" in event


@pytest.mark.compliance
def test_export_user_data_includes_sessions(user_data_exporter, test_user):
    """Test export includes session history."""
    # Mock session manager to return sessions
    with patch("pdfsigner.core.session.get_session_manager") as mock_get_sm:
        mock_sm = Mock()
        now = datetime.now()

        # Create mock Session objects that will be returned by get_user_sessions
        # Note: Code uses session_id but Session model has 'id' field
        mock_session_1 = Mock()
        mock_session_1.session_id = "session_1"
        mock_session_1.created_at = now - timedelta(hours=2)
        mock_session_1.last_activity = now - timedelta(minutes=30)
        mock_session_1.ip_address = "192.168.1.100"
        mock_session_1.user_agent = "Mozilla/5.0"
        mock_session_1.is_active = True

        mock_session_2 = Mock()
        mock_session_2.session_id = "session_2"
        mock_session_2.created_at = now - timedelta(days=1)
        mock_session_2.last_activity = now - timedelta(days=1)
        mock_session_2.ip_address = "10.0.0.50"
        mock_session_2.user_agent = "Chrome/120.0"
        mock_session_2.is_active = False

        mock_sm.get_user_sessions.return_value = [mock_session_1, mock_session_2]
        mock_get_sm.return_value = mock_sm

        export = user_data_exporter.export_user_data(test_user.id)

    assert export is not None
    assert len(export.sessions) == 2

    # Verify session structure
    session = export.sessions[0]
    assert "session_id" in session
    assert "created_at" in session
    assert "last_activity" in session
    assert "ip_address" in session
    assert "user_agent" in session
    assert "is_active" in session


@pytest.mark.compliance
def test_export_user_data_not_found_returns_none(user_data_exporter):
    """Test export with non-existent user returns None gracefully."""
    export = user_data_exporter.export_user_data("nonexistent_user_id")

    assert export is None


@pytest.mark.compliance
def test_export_user_data_no_certificate_returns_empty_list(user_repository, user_data_exporter):
    """Test export for user without certificate returns empty certificates list."""
    # Create user without certificate
    user = User(
        username="no.cert",
        display_name="No Certificate User",
        email="nocert@example.com",
        role=UserRole.VIEWER,
        status=UserStatus.ACTIVE,
    )
    user = user_repository.create_user(user)

    export = user_data_exporter.export_user_data(user.id)

    assert export is not None
    assert len(export.certificates) == 0


@pytest.mark.compliance
def test_export_user_data_no_audit_returns_empty_list(user_data_exporter, test_user):
    """Test export for user with no audit events returns empty list."""
    export = user_data_exporter.export_user_data(test_user.id)

    assert export is not None
    assert len(export.audit_events) == 0


@pytest.mark.compliance
def test_export_user_data_metadata_includes_gdpr_reason(user_data_exporter, test_user):
    """Test export metadata includes GDPR compliance reason."""
    export = user_data_exporter.export_user_data(test_user.id)

    assert export is not None
    assert "export_reason" in export.metadata
    assert "GDPR Article 20" in export.metadata["export_reason"]
    assert "Right to data portability" in export.metadata["export_reason"]
    assert export.metadata["user_id"] == test_user.id
    assert export.metadata["username"] == test_user.username


# --- JSON Export Format Tests ---


@pytest.mark.compliance
def test_export_to_json_string_valid_json(user_data_exporter, test_user):
    """Test JSON export produces valid, parseable JSON."""
    json_str = user_data_exporter.export_to_json_string(test_user.id)

    assert json_str is not None

    # Verify it's valid JSON
    data = json.loads(json_str)
    assert isinstance(data, dict)


@pytest.mark.compliance
def test_export_to_json_string_machine_readable(user_data_exporter, test_user):
    """Test JSON export is machine-readable with all required fields."""
    json_str = user_data_exporter.export_to_json_string(test_user.id)

    assert json_str is not None
    data = json.loads(json_str)

    # Verify all top-level keys present
    assert "user_info" in data
    assert "certificates" in data
    assert "audit_events" in data
    assert "sessions" in data
    assert "generated_at" in data
    assert "metadata" in data

    # Verify data types
    assert isinstance(data["user_info"], dict)
    assert isinstance(data["certificates"], list)
    assert isinstance(data["audit_events"], list)
    assert isinstance(data["sessions"], list)
    assert isinstance(data["metadata"], dict)


@pytest.mark.compliance
def test_export_to_json_string_not_found_returns_none(user_data_exporter):
    """Test JSON export for non-existent user returns None."""
    json_str = user_data_exporter.export_to_json_string("nonexistent")

    assert json_str is None


@pytest.mark.compliance
def test_export_to_file_json_creates_file(user_data_exporter, test_user, tmp_path):
    """Test JSON file export creates valid file."""
    output_path = tmp_path / "user_export.json"
    success = user_data_exporter.export_to_file(test_user.id, output_path, format="json")

    assert success is True
    assert output_path.exists()
    assert output_path.is_file()


@pytest.mark.compliance
def test_export_to_file_json_content_valid(user_data_exporter, test_user, tmp_path):
    """Test JSON file export contains valid, complete data."""
    output_path = tmp_path / "user_export.json"
    user_data_exporter.export_to_file(test_user.id, output_path, format="json")

    # Read and verify file content
    with open(output_path, encoding="utf-8") as f:
        data = json.load(f)

    assert data["user_info"]["id"] == test_user.id
    assert data["user_info"]["username"] == test_user.username
    assert "certificates" in data
    assert "audit_events" in data
    assert "sessions" in data


# --- CSV Export Format Tests ---


@pytest.mark.compliance
def test_export_to_file_csv_creates_zip(user_data_exporter, test_user, tmp_path):
    """Test CSV export creates ZIP archive with multiple CSV files."""
    output_path = tmp_path / "user_export.zip"
    success = user_data_exporter.export_to_file(test_user.id, output_path, format="csv")

    assert success is True
    assert output_path.exists()
    assert zipfile.is_zipfile(output_path)


@pytest.mark.compliance
def test_export_to_file_csv_contains_all_files(user_data_exporter, test_user, tmp_path):
    """Test CSV export ZIP contains all required CSV files."""
    output_path = tmp_path / "user_export.zip"
    user_data_exporter.export_to_file(test_user.id, output_path, format="csv")

    with zipfile.ZipFile(output_path, "r") as zf:
        filenames = zf.namelist()

        # Verify required CSV files present
        assert "user_info.csv" in filenames
        assert "metadata.csv" in filenames
        # certificates.csv only if user has certificates
        assert "certificates.csv" in filenames


@pytest.mark.compliance
def test_export_to_file_unsupported_format_fails(user_data_exporter, test_user, tmp_path):
    """Test export with unsupported format returns False."""
    output_path = tmp_path / "user_export.xml"
    success = user_data_exporter.export_to_file(test_user.id, output_path, format="xml")

    assert success is False
    assert not output_path.exists()


@pytest.mark.compliance
def test_export_to_file_not_found_fails(user_data_exporter, tmp_path):
    """Test file export for non-existent user returns False."""
    output_path = tmp_path / "export.json"
    success = user_data_exporter.export_to_file("nonexistent", output_path)

    assert success is False
    assert not output_path.exists()


# --- Large Data Export Tests ---


@pytest.mark.compliance
def test_export_user_data_large_audit_history(user_repository, audit_logger, test_user):
    """Test export handles large number of audit events."""
    # Create many audit events (1000)
    for i in range(1000):
        event = AuditEvent(
            event_type=AuditEventType.SIGN_SUCCESS,
            status="SUCCESS",
            user_id=test_user.id,
            document_path=f"/docs/large_export_{i:04d}.pdf",
        )
        audit_logger.log_event(event)

    exporter = UserDataExporter(user_repository=user_repository, audit_logger=audit_logger)
    export = exporter.export_user_data(test_user.id)

    assert export is not None
    assert len(export.audit_events) == 1000


@pytest.mark.compliance
def test_export_user_data_respects_audit_limit(user_repository, audit_logger, test_user):
    """Test export respects 10,000 event limit for audit history."""
    # Create more than 10,000 events (would be slow, so we mock)
    with patch.object(audit_logger, "get_events_filtered") as mock_get_events:
        # Mock returns exactly 10,000 events
        mock_events = [
            Mock(
                event_id=f"event_{i}",
                timestamp=datetime.now(),
                event_type=AuditEventType.SIGN_SUCCESS,
                status="SUCCESS",
                document_path=f"/doc_{i}.pdf",
                details={},
            )
            for i in range(10000)
        ]
        mock_get_events.return_value = mock_events

        exporter = UserDataExporter(user_repository=user_repository, audit_logger=audit_logger)
        export = exporter.export_user_data(test_user.id)

    assert export is not None
    assert len(export.audit_events) == 10000
    # Verify limit parameter was passed
    mock_get_events.assert_called_once_with(user_id=test_user.id, limit=10000)


# --- IDOR Prevention Tests ---


@pytest.mark.compliance
def test_export_user_data_only_exports_requested_user(user_repository, user_data_exporter):
    """Test export only returns data for requested user (IDOR prevention)."""
    # Create two users
    user1 = User(
        username="user1",
        display_name="User One",
        email="user1@example.com",
        role=UserRole.SIGNER,
    )
    user1 = user_repository.create_user(user1)

    user2 = User(
        username="user2",
        display_name="User Two",
        email="user2@example.com",
        role=UserRole.SIGNER,
    )
    user2 = user_repository.create_user(user2)

    # Export user1 data
    export = user_data_exporter.export_user_data(user1.id)

    assert export is not None
    assert export.user_info["id"] == user1.id
    assert export.user_info["username"] == "user1"
    assert export.user_info["email"] == "user1@example.com"

    # Verify user2 data not included
    assert export.user_info["id"] != user2.id
    assert export.user_info["username"] != "user2"


@pytest.mark.compliance
def test_export_user_data_audit_only_for_user(user_repository, audit_logger):
    """Test export audit events only for requested user (IDOR prevention)."""
    # Create two users
    user1 = User(username="user1", display_name="User 1", role=UserRole.SIGNER)
    user1 = user_repository.create_user(user1)

    user2 = User(username="user2", display_name="User 2", role=UserRole.SIGNER)
    user2 = user_repository.create_user(user2)

    # Create audit events for both users
    for i in range(3):
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.SIGN_SUCCESS,
                status="SUCCESS",
                user_id=user1.id,
                document_path=f"/user1/doc_{i}.pdf",
            )
        )
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.SIGN_SUCCESS,
                status="SUCCESS",
                user_id=user2.id,
                document_path=f"/user2/doc_{i}.pdf",
            )
        )

    # Export user1 data
    exporter = UserDataExporter(user_repository=user_repository, audit_logger=audit_logger)
    export = exporter.export_user_data(user1.id)

    assert export is not None
    assert len(export.audit_events) == 3

    # Verify all events are for user1
    for event in export.audit_events:
        # Audit events don't have user_id in export format, but document path should match
        assert "user1" in event["document_path"]
        assert "user2" not in event["document_path"]


# --- Error Handling Tests ---


@pytest.mark.compliance
def test_export_user_data_handles_disabled_audit(user_repository, test_user):
    """Test export handles disabled audit logger gracefully."""
    # Create audit logger with enabled=False
    mock_audit = Mock()
    mock_audit.enabled = False

    exporter = UserDataExporter(user_repository=user_repository, audit_logger=mock_audit)
    export = exporter.export_user_data(test_user.id)

    assert export is not None
    assert len(export.audit_events) == 0
    # Should not attempt to get events when disabled
    mock_audit.get_events_filtered.assert_not_called()


@pytest.mark.compliance
def test_export_user_data_handles_session_error(user_repository, audit_logger, test_user):
    """Test export handles session retrieval errors gracefully."""
    with patch("pdfsigner.core.session.get_session_manager") as mock_get_sm:
        # Mock session manager that raises exception
        mock_sm = Mock()
        mock_sm.get_user_sessions.side_effect = Exception("Session database error")
        mock_get_sm.return_value = mock_sm

        exporter = UserDataExporter(user_repository=user_repository, audit_logger=audit_logger)
        export = exporter.export_user_data(test_user.id)

    # Export should succeed but sessions should be empty
    assert export is not None
    assert len(export.sessions) == 0


@pytest.mark.compliance
def test_export_user_data_handles_exception(user_repository, audit_logger):
    """Test export handles unexpected exceptions and returns None."""
    # Mock user_repo.get_user_by_id to raise exception
    with patch.object(user_repository, "get_user_by_id", side_effect=Exception("Database error")):
        exporter = UserDataExporter(user_repository=user_repository, audit_logger=audit_logger)
        export = exporter.export_user_data("any_user_id")

    assert export is None


# --- Singleton Tests ---


@pytest.mark.compliance
def test_get_user_data_exporter_singleton():
    """Test get_user_data_exporter returns singleton instance."""
    exporter1 = get_user_data_exporter()
    exporter2 = get_user_data_exporter()

    assert exporter1 is exporter2


# --- Edge Cases ---


@pytest.mark.compliance
def test_export_user_data_empty_details_in_audit(user_repository, audit_logger, test_user):
    """Test export handles audit events with empty details dict."""
    event = AuditEvent(
        event_type=AuditEventType.SIGN_SUCCESS,
        status="SUCCESS",
        user_id=test_user.id,
        document_path="/test.pdf",
        details={},
    )
    audit_logger.log_event(event)

    exporter = UserDataExporter(user_repository=user_repository, audit_logger=audit_logger)
    export = exporter.export_user_data(test_user.id)

    assert export is not None
    assert len(export.audit_events) == 1
    assert export.audit_events[0]["details"] == {}


@pytest.mark.compliance
def test_export_user_data_special_characters_in_data(user_repository, user_data_exporter):
    """Test export handles special characters in user data."""
    user = User(
        username="user.with+special@chars",
        display_name="User <name> with 'quotes' & symbols",
        email="test+tag@example.com",
        role=UserRole.SIGNER,
    )
    user = user_repository.create_user(user)

    export = user_data_exporter.export_user_data(user.id)

    assert export is not None
    assert export.user_info["username"] == "user.with+special@chars"
    assert "<name>" in export.user_info["display_name"]
    assert "&" in export.user_info["display_name"]

    # Verify JSON serialization works
    json_str = user_data_exporter.export_to_json_string(user.id)
    assert json_str is not None
    data = json.loads(json_str)
    assert data["user_info"]["username"] == "user.with+special@chars"


@pytest.mark.compliance
def test_export_user_data_unicode_characters(user_repository, user_data_exporter):
    """Test export handles Unicode characters correctly."""
    user = User(
        username="user.unicode",
        display_name="José García-Pérez 日本語",
        email="jose@example.com",
        role=UserRole.SIGNER,
    )
    user = user_repository.create_user(user)

    export = user_data_exporter.export_user_data(user.id)

    assert export is not None
    assert "José" in export.user_info["display_name"]
    assert "日本語" in export.user_info["display_name"]

    # Verify JSON export preserves Unicode
    json_str = user_data_exporter.export_to_json_string(user.id)
    assert json_str is not None
    assert "José" in json_str
    assert "日本語" in json_str


@pytest.mark.compliance
def test_export_to_file_pathlib_path_support(user_data_exporter, test_user, tmp_path):
    """Test export_to_file accepts both string and Path objects."""
    # Test with Path object
    output_path = tmp_path / "export_path.json"
    success1 = user_data_exporter.export_to_file(test_user.id, output_path)
    assert success1 is True
    assert output_path.exists()

    # Test with string
    output_str = str(tmp_path / "export_string.json")
    success2 = user_data_exporter.export_to_file(test_user.id, output_str)
    assert success2 is True
    assert Path(output_str).exists()

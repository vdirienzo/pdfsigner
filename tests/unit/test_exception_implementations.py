"""
test_exception_implementations.py - Tests for exception logic implementations

Tests MaxSessionsExceededError and HIPAAComplianceError logic.
"""

import tempfile
from pathlib import Path

import pytest

from pdfsigner.core.encryption.encryption_validator import EncryptionValidator
from pdfsigner.core.session.session_manager import SessionManager
from pdfsigner.exceptions import HIPAAComplianceError, MaxSessionsExceededError


class TestMaxSessionsExceeded:
    """Tests for MaxSessionsExceededError in SessionManager."""

    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = Path(f.name)
        yield db_path
        if db_path.exists():
            db_path.unlink()

    @pytest.fixture
    def session_manager(self, temp_db):
        """Create SessionManager instance with temp database."""
        return SessionManager(db_path=temp_db)

    @pytest.fixture
    def mock_healthcare_settings(self, monkeypatch):
        """Mock healthcare settings for testing."""
        from unittest.mock import MagicMock

        mock_settings = MagicMock()
        mock_settings.healthcare_mode = True
        mock_settings.healthcare_session_timeout_minutes = 15
        mock_settings.healthcare_max_sessions = 3

        def mock_get_settings():
            return mock_settings

        monkeypatch.setattr(
            "pdfsigner.core.session.session_manager.get_settings", mock_get_settings
        )
        return mock_settings

    def test_max_sessions_raises_error(self, session_manager, mock_healthcare_settings):
        """Test that creating session beyond max raises MaxSessionsExceededError."""
        user_id = "test_user"

        # Create max sessions (3)
        for i in range(3):
            session_manager.create_session(
                user_id, ip_address=f"192.168.1.{i}", user_agent=f"TestAgent{i}"
            )

        # Verify we have 3 active sessions
        assert session_manager.get_active_session_count(user_id) == 3

        # Try to create 4th session - should raise error
        with pytest.raises(MaxSessionsExceededError) as exc_info:
            session_manager.create_session(
                user_id, ip_address="192.168.1.100", user_agent="TestAgent4"
            )

        # Verify error message
        error_msg = str(exc_info.value)
        assert "test_user" in error_msg
        assert "3 active sessions" in error_msg
        assert "Maximum allowed: 3" in error_msg
        assert "terminate an existing session" in error_msg.lower()

    def test_max_sessions_error_message_includes_count(
        self, session_manager, mock_healthcare_settings
    ):
        """Test that error message includes correct session count."""
        user_id = "user_with_max_sessions"

        # Create 3 sessions
        for i in range(3):
            session_manager.create_session(user_id)

        # Attempt to create 4th session
        with pytest.raises(MaxSessionsExceededError) as exc_info:
            session_manager.create_session(user_id)

        error_msg = str(exc_info.value)
        assert "3 active sessions" in error_msg
        assert "Maximum allowed: 3" in error_msg

    def test_allows_session_after_terminating_old_one(
        self, session_manager, mock_healthcare_settings
    ):
        """Test that new session can be created after terminating an old one."""
        user_id = "test_user"

        # Create max sessions
        sessions = []
        for i in range(3):
            session = session_manager.create_session(user_id)
            sessions.append(session)

        # Terminate oldest session
        session_manager.terminate_session(sessions[0].id)

        # Now should be able to create new session
        new_session = session_manager.create_session(user_id)
        assert new_session.user_id == user_id
        assert session_manager.get_active_session_count(user_id) == 3

    def test_no_error_when_healthcare_mode_disabled(self, session_manager, monkeypatch):
        """Test that max sessions is not enforced when healthcare_mode=False."""
        from unittest.mock import MagicMock

        mock_settings = MagicMock()
        mock_settings.healthcare_mode = False
        mock_settings.healthcare_session_timeout_minutes = 15
        mock_settings.healthcare_max_sessions = 3

        monkeypatch.setattr(
            "pdfsigner.core.session.session_manager.get_settings",
            lambda: mock_settings,
        )

        user_id = "test_user"

        # Should be able to create more than max sessions when healthcare_mode=False
        for i in range(5):
            session = session_manager.create_session(user_id)
            assert session.user_id == user_id

        # Verify we have 5 sessions (no enforcement)
        assert session_manager.get_active_session_count(user_id) == 5

    def test_get_active_session_count_excludes_expired(
        self, session_manager, mock_healthcare_settings, monkeypatch
    ):
        """Test that get_active_session_count excludes expired sessions."""
        from datetime import UTC, datetime, timedelta

        user_id = "test_user"

        # Create 2 sessions
        session1 = session_manager.create_session(user_id)
        session2 = session_manager.create_session(user_id)

        # Manually expire session1 by updating expires_at in DB

        with session_manager._get_connection() as conn:
            past_time = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
            conn.execute(
                "UPDATE sessions SET expires_at = ? WHERE id = ?",
                (past_time, session1.id),
            )

        # Active count should be 1 (session2 only)
        assert session_manager.get_active_session_count(user_id) == 1

        # Should be able to create 2 more sessions (1 active + 2 new = 3 total)
        session_manager.create_session(user_id)
        session_manager.create_session(user_id)

        assert session_manager.get_active_session_count(user_id) == 3


class TestHIPAACompliance:
    """Tests for HIPAAComplianceError in EncryptionValidator."""

    @pytest.fixture
    def validator(self):
        """Create EncryptionValidator instance."""
        return EncryptionValidator()

    def test_aes128_raises_hipaa_error(self, validator):
        """Test that AES-128 raises HIPAA error (AES-256 required)."""
        with pytest.raises(HIPAAComplianceError) as exc_info:
            validator.validate_hipaa_settings(
                encryption_strength="aes128",
                allow_print=False,
                encryption_enabled=True,
            )

        error_msg = str(exc_info.value)
        assert "aes-256" in error_msg.lower()

    def test_print_allowed_raises_hipaa_error(self, validator):
        """Test that allowing print raises HIPAA error."""
        with pytest.raises(HIPAAComplianceError) as exc_info:
            validator.validate_hipaa_settings(
                encryption_strength="aes256",
                allow_print=True,
                encryption_enabled=True,
            )

        error_msg = str(exc_info.value)
        assert "print" in error_msg.lower()
        assert "disabled" in error_msg.lower()

    def test_encryption_disabled_raises_hipaa_error(self, validator):
        """Test that disabled encryption raises HIPAA error."""
        with pytest.raises(HIPAAComplianceError) as exc_info:
            validator.validate_hipaa_settings(
                encryption_strength="aes256",
                allow_print=False,
                encryption_enabled=False,
            )

        error_msg = str(exc_info.value)
        assert "encryption" in error_msg.lower()
        assert "enabled" in error_msg.lower()

    def test_multiple_violations_combined_in_error(self, validator):
        """Test that multiple violations are combined in error message."""
        with pytest.raises(HIPAAComplianceError) as exc_info:
            validator.validate_hipaa_settings(
                encryption_strength="aes128",
                allow_print=True,
                encryption_enabled=False,
            )

        error_msg = str(exc_info.value)
        # All 3 violations should be mentioned
        assert "encryption" in error_msg.lower()
        assert "aes-256" in error_msg.lower()
        assert "print" in error_msg.lower()

    def test_valid_hipaa_settings_pass(self, validator):
        """Test that valid HIPAA settings don't raise error."""
        # Should not raise any exception
        validator.validate_hipaa_settings(
            encryption_strength="aes256",
            allow_print=False,
            encryption_enabled=True,
        )

    def test_aes256_with_encryption_disabled_raises_error(self, validator):
        """Test that even AES-256 with disabled encryption raises error."""
        with pytest.raises(HIPAAComplianceError) as exc_info:
            validator.validate_hipaa_settings(
                encryption_strength="aes256",
                allow_print=False,
                encryption_enabled=False,
            )

        error_msg = str(exc_info.value)
        assert "enabled" in error_msg.lower()

    def test_error_message_format(self, validator):
        """Test that error message is properly formatted."""
        with pytest.raises(HIPAAComplianceError) as exc_info:
            validator.validate_hipaa_settings(
                encryption_strength="aes128",
                allow_print=True,
                encryption_enabled=True,
            )

        error_msg = str(exc_info.value)
        # Should contain "HIPAA compliance error:" prefix
        assert "hipaa compliance error:" in error_msg.lower()
        # Multiple errors separated by semicolon
        assert ";" in error_msg


class TestExceptionConstructors:
    """Tests for exception constructors."""

    def test_max_sessions_exceeded_with_message(self):
        """Test MaxSessionsExceededError with custom message."""
        exc = MaxSessionsExceededError(max_sessions=5, message="Custom error message")
        assert str(exc) == "Custom error message"

    def test_max_sessions_exceeded_without_message(self):
        """Test MaxSessionsExceededError with default message."""
        exc = MaxSessionsExceededError(max_sessions=3)
        assert "Maximum concurrent sessions (3) exceeded" in str(exc)

    def test_hipaa_compliance_error(self):
        """Test HIPAAComplianceError constructor."""
        exc = HIPAAComplianceError("Test reason")
        assert "HIPAA compliance error: Test reason" in str(exc)

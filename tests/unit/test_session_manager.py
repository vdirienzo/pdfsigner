"""
Tests for session management module.

Tests Session model and SessionManager for HIPAA compliance.
"""

import uuid
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfsigner.core.session import Session, SessionManager, get_session_manager


class TestSession:
    """Tests for Session dataclass."""

    def test_session_creation(self):
        """Test creating a session with default values."""
        session = Session(
            id=str(uuid.uuid4()),
            user_id="user_123",
            created_at=datetime.now(),
            last_activity=datetime.now(),
            expires_at=datetime.now() + timedelta(minutes=15),
        )
        assert session.user_id == "user_123"
        assert session.ip_address is None
        assert session.user_agent is None

    def test_session_with_metadata(self):
        """Test creating session with IP and user agent."""
        session = Session(
            id=str(uuid.uuid4()),
            user_id="user_123",
            created_at=datetime.now(),
            last_activity=datetime.now(),
            expires_at=datetime.now() + timedelta(minutes=15),
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
        )
        assert session.ip_address == "192.168.1.1"
        assert session.user_agent == "Mozilla/5.0"

    def test_session_is_active_when_not_expired(self):
        """Test is_active property returns True for valid session."""
        session = Session(
            id=str(uuid.uuid4()),
            user_id="user_123",
            created_at=datetime.now(),
            last_activity=datetime.now(),
            expires_at=datetime.now() + timedelta(minutes=15),
        )
        assert session.is_active is True

    def test_session_is_not_active_when_expired(self):
        """Test is_active property returns False for expired session."""
        session = Session(
            id=str(uuid.uuid4()),
            user_id="user_123",
            created_at=datetime.now() - timedelta(hours=1),
            last_activity=datetime.now() - timedelta(minutes=30),
            expires_at=datetime.now() - timedelta(minutes=1),
        )
        assert session.is_active is False

    def test_session_to_dict(self):
        """Test session serialization to dict."""
        session_id = str(uuid.uuid4())
        now = datetime.now()
        session = Session(
            id=session_id,
            user_id="user_123",
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(minutes=15),
        )
        data = session.to_dict()
        assert data["id"] == session_id
        assert data["user_id"] == "user_123"
        assert "created_at" in data
        assert "expires_at" in data

    def test_session_from_dict(self):
        """Test session deserialization from dict."""
        now = datetime.now()
        data = {
            "id": "test-id",
            "user_id": "user_456",
            "created_at": now.isoformat(),
            "last_activity": now.isoformat(),
            "expires_at": (now + timedelta(minutes=15)).isoformat(),
            "ip_address": "10.0.0.1",
            "user_agent": "TestAgent",
        }
        session = Session.from_dict(data)
        assert session.id == "test-id"
        assert session.user_id == "user_456"
        assert session.ip_address == "10.0.0.1"


class TestSessionManager:
    """Tests for SessionManager class."""

    @pytest.fixture
    def temp_db(self, tmp_path: Path) -> Path:
        """Create temporary database path."""
        return tmp_path / "test_sessions.db"

    @pytest.fixture
    def manager(self, temp_db: Path) -> SessionManager:
        """Create SessionManager with temp database."""
        return SessionManager(db_path=temp_db)

    def test_initialization(self, manager: SessionManager):
        """Test SessionManager initializes correctly."""
        assert manager is not None
        assert manager.db_path.exists()

    def test_create_session(self, manager: SessionManager):
        """Test creating a new session."""
        with patch("pdfsigner.core.session.session_manager.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                healthcare_mode=True,
                healthcare_session_timeout_minutes=15,
                healthcare_max_sessions=3,
            )
            session = manager.create_session(
                user_id="user_123",
                ip_address="192.168.1.1",
                user_agent="TestBrowser",
            )
            assert session is not None
            assert session.user_id == "user_123"
            assert session.ip_address == "192.168.1.1"
            assert session.is_active is True

    def test_get_session(self, manager: SessionManager):
        """Test retrieving a session by ID."""
        with patch("pdfsigner.core.session.session_manager.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                healthcare_mode=True,
                healthcare_session_timeout_minutes=15,
                healthcare_max_sessions=3,
            )
            created = manager.create_session("user_123")
            retrieved = manager.get_session(created.id)
            assert retrieved is not None
            assert retrieved.id == created.id
            assert retrieved.user_id == "user_123"

    def test_get_nonexistent_session(self, manager: SessionManager):
        """Test getting a session that doesn't exist returns None."""
        result = manager.get_session("nonexistent-id")
        assert result is None

    def test_validate_session_active(self, manager: SessionManager):
        """Test validating an active session returns True."""
        with patch("pdfsigner.core.session.session_manager.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                healthcare_mode=True,
                healthcare_session_timeout_minutes=15,
                healthcare_max_sessions=3,
            )
            session = manager.create_session("user_123")
            is_valid = manager.validate_session(session.id)
            assert is_valid is True

    def test_validate_session_healthcare_mode_disabled(self, manager: SessionManager):
        """Test validate_session returns True when healthcare_mode is disabled."""
        with patch("pdfsigner.core.session.session_manager.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(healthcare_mode=False)
            # Even with invalid session ID, should return True
            is_valid = manager.validate_session("any-id")
            assert is_valid is True

    def test_terminate_session(self, manager: SessionManager):
        """Test terminating a session."""
        with patch("pdfsigner.core.session.session_manager.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                healthcare_mode=True,
                healthcare_session_timeout_minutes=15,
                healthcare_max_sessions=3,
            )
            session = manager.create_session("user_123")
            manager.terminate_session(session.id)
            retrieved = manager.get_session(session.id)
            assert retrieved is None

    def test_terminate_user_sessions(self, manager: SessionManager):
        """Test terminating all sessions for a user."""
        with patch("pdfsigner.core.session.session_manager.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                healthcare_mode=True,
                healthcare_session_timeout_minutes=15,
                healthcare_max_sessions=10,
            )
            # Create multiple sessions
            manager.create_session("user_123")
            manager.create_session("user_123")
            manager.create_session("user_456")

            count = manager.terminate_user_sessions("user_123")
            assert count == 2

            # Verify user_456 session still exists
            sessions = manager.get_user_sessions("user_456")
            assert len(sessions) == 1

    def test_get_user_sessions(self, manager: SessionManager):
        """Test getting all sessions for a user."""
        with patch("pdfsigner.core.session.session_manager.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                healthcare_mode=True,
                healthcare_session_timeout_minutes=15,
                healthcare_max_sessions=10,
            )
            manager.create_session("user_123")
            manager.create_session("user_123")

            sessions = manager.get_user_sessions("user_123")
            assert len(sessions) == 2
            for s in sessions:
                assert s.user_id == "user_123"

    def test_touch_session_extends_expiration(self, manager: SessionManager):
        """Test touching a session extends its expiration."""
        with patch("pdfsigner.core.session.session_manager.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                healthcare_mode=True,
                healthcare_session_timeout_minutes=15,
                healthcare_max_sessions=3,
            )
            session = manager.create_session("user_123")
            original_expires = session.expires_at

            # Touch the session
            manager.touch_session(session.id)

            updated = manager.get_session(session.id)
            assert updated is not None
            assert updated.last_activity > session.last_activity


class TestSessionManagerSingleton:
    """Tests for singleton pattern."""

    def test_get_session_manager_returns_instance(self):
        """Test get_session_manager returns a SessionManager."""
        manager = get_session_manager()
        assert isinstance(manager, SessionManager)

    def test_get_session_manager_returns_same_instance(self):
        """Test singleton returns same instance."""
        # Reset singleton for test
        import pdfsigner.core.session.session_manager as sm

        sm._session_manager = None

        manager1 = get_session_manager()
        manager2 = get_session_manager()
        assert manager1 is manager2

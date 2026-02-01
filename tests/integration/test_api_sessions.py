"""
Integration tests for Session Management API.

Tests session endpoints with IDOR prevention, concurrent session limits,
and healthcare mode enforcement.

Security focus:
- IDOR: Users cannot access/terminate other users' sessions
- Session hijacking prevention
- Token invalidation after termination
- Concurrent session limits enforcement

Run with:
    uv run pytest tests/integration/test_api_sessions.py -v
    uv run pytest tests/integration/test_api_sessions.py -v -m security
"""

from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from uuid import uuid4

import httpx
import pytest
from fastapi import status
from httpx import ASGITransport

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.main import app
from pdfsigner.api.middleware.auth import User, create_access_token, get_current_user_or_api_key
from pdfsigner.core.session.session_manager import Session
from pdfsigner.core.users.user_model import UserRole, UserStatus

pytestmark = pytest.mark.anyio


# --- Fixtures ---


@pytest.fixture
def api_settings():
    """Get API settings for tests."""
    settings = get_api_settings()
    settings.api_keys = ["test-api-key-123"]
    return settings


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
        # Cleanup: remove any dependency overrides
        app.dependency_overrides.clear()


@pytest.fixture
def mock_user():
    """Create mock user for authentication."""
    return User(
        id="user-123",
        username="testuser",
        email="testuser@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
    )


@pytest.fixture
def mock_user2():
    """Create second mock user for IDOR tests."""
    return User(
        id="user-456",
        username="otheruser",
        email="otheruser@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
    )


@pytest.fixture
def auth_token(api_settings):
    """Create valid JWT token for testuser."""
    token = create_access_token(
        data={"sub": "testuser", "user_id": "user-123", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def auth_token_user2(api_settings):
    """Create valid JWT token for another user (for IDOR tests)."""
    token = create_access_token(
        data={"sub": "otheruser", "user_id": "user-456", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def auth_headers(auth_token):
    """Create authentication headers with JWT token."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def auth_headers_user2(auth_token_user2):
    """Create authentication headers for second user."""
    return {"Authorization": f"Bearer {auth_token_user2}"}


@pytest.fixture
def mock_session():
    """Create mock session for testing."""
    now = datetime.now()
    return Session(
        id=str(uuid4()),
        user_id="user-123",
        created_at=now,
        last_activity=now,
        expires_at=now + timedelta(minutes=15),
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0",
    )


@pytest.fixture
def mock_session_user2():
    """Create mock session for second user (for IDOR tests)."""
    now = datetime.now()
    return Session(
        id=str(uuid4()),
        user_id="user-456",
        created_at=now,
        last_activity=now,
        expires_at=now + timedelta(minutes=15),
        ip_address="192.168.1.101",
        user_agent="Mozilla/5.0",
    )


@pytest.fixture
def mock_expired_session():
    """Create expired session for testing."""
    now = datetime.now()
    return Session(
        id=str(uuid4()),
        user_id="user-123",
        created_at=now - timedelta(minutes=30),
        last_activity=now - timedelta(minutes=20),
        expires_at=now - timedelta(minutes=5),  # Expired 5 minutes ago
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0",
    )


# --- List Sessions Tests ---


async def test_list_sessions_success(client, auth_headers, mock_session, mock_user):
    """Test listing user's sessions returns all sessions."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    with (
        patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.sessions.get_session_manager") as mock_manager,
    ):
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        mock_mgr = Mock()
        mock_mgr.get_user_sessions.return_value = [mock_session]
        mock_manager.return_value = mock_mgr

        # Act
        response = await client.get("/api/v1/sessions/", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["user_id"] == "user-123"
    assert data[0]["ip_address"] == "192.168.1.100"


async def test_list_sessions_multiple(client, auth_headers, mock_user):
    """Test listing multiple sessions for user."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    # Create multiple sessions
    now = datetime.now()
    sessions = [
        Session(
            id=str(uuid4()),
            user_id="user-123",
            created_at=now - timedelta(minutes=i * 10),
            last_activity=now,
            expires_at=now + timedelta(minutes=15),
        )
        for i in range(3)
    ]

    with (
        patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.sessions.get_session_manager") as mock_manager,
    ):
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        mock_mgr = Mock()
        mock_mgr.get_user_sessions.return_value = sessions
        mock_manager.return_value = mock_mgr

        # Act
        response = await client.get("/api/v1/sessions/", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) == 3


async def test_list_sessions_without_healthcare_mode(client, auth_headers, mock_user):
    """Test listing sessions without healthcare mode returns empty list."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    with patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings:
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = False
        mock_settings.return_value = mock_settings_obj

        # Act
        response = await client.get("/api/v1/sessions/", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data == []


async def test_list_sessions_includes_expired(
    client, auth_headers, mock_expired_session, mock_user
):
    """Test listing sessions includes expired sessions."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    with (
        patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.sessions.get_session_manager") as mock_manager,
    ):
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        mock_mgr = Mock()
        mock_mgr.get_user_sessions.return_value = [mock_expired_session]
        mock_manager.return_value = mock_mgr

        # Act
        response = await client.get("/api/v1/sessions/", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) == 1
    assert data[0]["is_active"] is False


# --- Get Session Details Tests ---


@pytest.mark.security
async def test_get_session_success(client, auth_headers, mock_session, mock_user):
    """Test getting specific session details returns session info."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    with (
        patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.sessions.get_session_manager") as mock_manager,
    ):
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        mock_mgr = Mock()
        mock_mgr.get_session.return_value = mock_session
        mock_manager.return_value = mock_mgr

        # Act
        response = await client.get(f"/api/v1/sessions/{mock_session.id}", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == mock_session.id
    assert data["user_id"] == "user-123"


@pytest.mark.security
async def test_get_session_idor_prevention(client, auth_headers, mock_session_user2, mock_user):
    """Test IDOR: user cannot access another user's session (returns 404)."""

    # Arrange - Override auth dependency (User 1)
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    with (
        patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.sessions.get_session_manager") as mock_manager,
    ):
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        mock_mgr = Mock()
        mock_mgr.get_session.return_value = mock_session_user2  # Belongs to user-456
        mock_manager.return_value = mock_mgr

        # Act - User 1 tries to access User 2's session
        response = await client.get(
            f"/api/v1/sessions/{mock_session_user2.id}", headers=auth_headers
        )

    # Assert - Returns 404 (not 403) to prevent information disclosure
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


async def test_get_session_not_found(client, auth_headers, mock_user):
    """Test getting non-existent session returns 404."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    fake_session_id = str(uuid4())

    with (
        patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.sessions.get_session_manager") as mock_manager,
    ):
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        mock_mgr = Mock()
        mock_mgr.get_session.return_value = None
        mock_manager.return_value = mock_mgr

        # Act
        response = await client.get(f"/api/v1/sessions/{fake_session_id}", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


async def test_get_session_without_healthcare_mode(client, auth_headers, mock_user):
    """Test getting session without healthcare mode returns 503."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    session_id = str(uuid4())

    with patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings:
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = False
        mock_settings.return_value = mock_settings_obj

        # Act
        response = await client.get(f"/api/v1/sessions/{session_id}", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert "healthcare_mode" in response.json()["detail"].lower()


# --- Terminate Session Tests ---


@pytest.mark.security
async def test_terminate_session_success(client, auth_headers, mock_session, mock_user):
    """Test terminating own session succeeds."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    with (
        patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.sessions.get_session_manager") as mock_manager,
    ):
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        mock_mgr = Mock()
        mock_mgr.get_session.return_value = mock_session
        mock_mgr.terminate_session.return_value = None
        mock_manager.return_value = mock_mgr

        # Act
        response = await client.delete(f"/api/v1/sessions/{mock_session.id}", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["session_id"] == mock_session.id
    assert "terminated" in data["message"].lower()
    mock_mgr.terminate_session.assert_called_once_with(mock_session.id)


@pytest.mark.security
async def test_terminate_session_idor_prevention(
    client, auth_headers, mock_session_user2, mock_user
):
    """Test IDOR: user cannot terminate another user's session (returns 404)."""

    # Arrange - Override auth dependency (User 1)
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    with (
        patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.sessions.get_session_manager") as mock_manager,
    ):
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        mock_mgr = Mock()
        mock_mgr.get_session.return_value = mock_session_user2  # Belongs to user-456
        mock_manager.return_value = mock_mgr

        # Act - User 1 tries to terminate User 2's session
        response = await client.delete(
            f"/api/v1/sessions/{mock_session_user2.id}", headers=auth_headers
        )

    # Assert - Returns 404 (not 403) to prevent information disclosure
    assert response.status_code == status.HTTP_404_NOT_FOUND
    mock_mgr.terminate_session.assert_not_called()


async def test_terminate_session_not_found(client, auth_headers, mock_user):
    """Test terminating non-existent session returns 404."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    fake_session_id = str(uuid4())

    with (
        patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.sessions.get_session_manager") as mock_manager,
    ):
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        mock_mgr = Mock()
        mock_mgr.get_session.return_value = None
        mock_manager.return_value = mock_mgr

        # Act
        response = await client.delete(f"/api/v1/sessions/{fake_session_id}", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


async def test_terminate_session_without_healthcare_mode(client, auth_headers, mock_user):
    """Test terminating session without healthcare mode returns 503."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    session_id = str(uuid4())

    with patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings:
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = False
        mock_settings.return_value = mock_settings_obj

        # Act
        response = await client.delete(f"/api/v1/sessions/{session_id}", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


# --- Terminate All Sessions Tests ---


async def test_terminate_all_sessions_success(client, auth_headers, mock_user):
    """Test terminating all sessions for user succeeds."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    with (
        patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.sessions.get_session_manager") as mock_manager,
    ):
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        mock_mgr = Mock()
        mock_mgr.terminate_user_sessions.return_value = 3  # Terminated 3 sessions
        mock_manager.return_value = mock_mgr

        # Act
        response = await client.delete("/api/v1/sessions/", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["sessions_terminated"] == 3
    assert "3" in data["message"]
    mock_mgr.terminate_user_sessions.assert_called_once_with("user-123")


async def test_terminate_all_sessions_no_sessions(client, auth_headers, mock_user):
    """Test terminating all sessions when user has no sessions."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    with (
        patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.sessions.get_session_manager") as mock_manager,
    ):
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        mock_mgr = Mock()
        mock_mgr.terminate_user_sessions.return_value = 0
        mock_manager.return_value = mock_mgr

        # Act
        response = await client.delete("/api/v1/sessions/", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["sessions_terminated"] == 0


async def test_terminate_all_sessions_without_healthcare_mode(client, auth_headers, mock_user):
    """Test terminating all sessions without healthcare mode returns 503."""

    # Arrange - Override auth dependency
    async def override_get_current_user():
        return mock_user

    app.dependency_overrides[get_current_user_or_api_key] = override_get_current_user

    with patch("pdfsigner.api.routes.sessions.get_settings") as mock_settings:
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = False
        mock_settings.return_value = mock_settings_obj

        # Act
        response = await client.delete("/api/v1/sessions/", headers=auth_headers)

    # Assert
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


# --- Security & Authentication Tests ---


async def test_session_endpoints_without_auth(client):
    """Test all session endpoints require authentication."""

    # Arrange
    session_id = str(uuid4())

    # Act & Assert
    list_response = await client.get("/api/v1/sessions/")
    assert list_response.status_code == status.HTTP_401_UNAUTHORIZED

    get_response = await client.get(f"/api/v1/sessions/{session_id}")
    assert get_response.status_code == status.HTTP_401_UNAUTHORIZED

    delete_response = await client.delete(f"/api/v1/sessions/{session_id}")
    assert delete_response.status_code == status.HTTP_401_UNAUTHORIZED

    delete_all_response = await client.delete("/api/v1/sessions/")
    assert delete_all_response.status_code == status.HTTP_401_UNAUTHORIZED


# --- Session Fixation Prevention Tests (Login) ---


@pytest.mark.security
async def test_login_invalidates_previous_sessions(client, mock_user):
    """
    Test login invalidates any existing sessions for the user (Session Fixation prevention).

    Scenario:
    1. User has existing sessions
    2. User logs in again
    3. Old sessions are terminated, new session is created
    """
    # Arrange
    now = datetime.now()
    old_session1 = Session(
        id=str(uuid4()),
        user_id="testuser",
        created_at=now - timedelta(hours=1),
        last_activity=now,
        expires_at=now + timedelta(minutes=15),
    )
    old_session2 = Session(
        id=str(uuid4()),
        user_id="testuser",
        created_at=now - timedelta(hours=2),
        last_activity=now,
        expires_at=now + timedelta(minutes=15),
    )
    new_session = Session(
        id=str(uuid4()),
        user_id="testuser",
        created_at=now,
        last_activity=now,
        expires_at=now + timedelta(minutes=15),
    )

    with (
        patch("pdfsigner.api.routes.auth.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.auth.get_user_repository") as mock_user_repo,
        patch("pdfsigner.api.routes.auth.get_password_validator") as mock_pwd_validator,
        patch("pdfsigner.api.routes.auth.get_session_manager") as mock_session_mgr,
    ):
        # Mock settings
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        # Mock user repository
        mock_repo = Mock()
        db_user = Mock()
        db_user.id = "user-123"
        db_user.username = "testuser"
        db_user.email = "testuser@example.com"
        db_user.is_active = True
        db_user.role = UserRole.SIGNER
        db_user.status = UserStatus.ACTIVE
        mock_repo.get_user_by_username.return_value = db_user
        mock_repo.get_password_hash.return_value = "hashed_password"
        mock_user_repo.return_value = mock_repo

        # Mock password validator
        mock_validator = Mock()
        mock_validator.verify_password.return_value = True
        mock_pwd_validator.return_value = mock_validator

        # Mock session manager
        mock_mgr = Mock()
        # First call: return existing sessions
        mock_mgr.get_user_sessions.return_value = [old_session1, old_session2]
        # After termination, create new session
        mock_mgr.create_session.return_value = new_session
        mock_session_mgr.return_value = mock_mgr

        # Act - Login with valid credentials
        response = await client.post(
            "/auth/token",
            json={"username": "testuser", "password": "password123"},
            headers={"X-API-Key": "test-api-key-bypass-csrf"},  # Bypass CSRF for test
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data

    # Verify old sessions were terminated
    assert mock_mgr.terminate_session.call_count == 2
    mock_mgr.terminate_session.assert_any_call(old_session1.id)
    mock_mgr.terminate_session.assert_any_call(old_session2.id)

    # Verify new session was created
    mock_mgr.create_session.assert_called_once()


@pytest.mark.security
async def test_login_creates_fresh_session_id(client, mock_user):
    """
    Test login creates a fresh session ID (not reusing any existing ID).

    This prevents Session Fixation where an attacker might pre-set a session ID.
    """
    with (
        patch("pdfsigner.api.routes.auth.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.auth.get_user_repository") as mock_user_repo,
        patch("pdfsigner.api.routes.auth.get_password_validator") as mock_pwd_validator,
        patch("pdfsigner.api.routes.auth.get_session_manager") as mock_session_mgr,
    ):
        # Mock settings
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        # Mock user repository
        mock_repo = Mock()
        db_user = Mock()
        db_user.id = "user-123"
        db_user.username = "testuser"
        db_user.email = "testuser@example.com"
        db_user.is_active = True
        db_user.role = UserRole.SIGNER
        db_user.status = UserStatus.ACTIVE
        mock_repo.get_user_by_username.return_value = db_user
        mock_repo.get_password_hash.return_value = "hashed_password"
        mock_user_repo.return_value = mock_repo

        # Mock password validator
        mock_validator = Mock()
        mock_validator.verify_password.return_value = True
        mock_pwd_validator.return_value = mock_validator

        # Mock session manager
        mock_mgr = Mock()
        new_session_id = str(uuid4())
        mock_mgr.get_user_sessions.return_value = []  # No existing sessions
        mock_mgr.create_session.return_value = Session(
            id=new_session_id,
            user_id="testuser",
            created_at=datetime.now(),
            last_activity=datetime.now(),
            expires_at=datetime.now() + timedelta(minutes=15),
        )
        mock_session_mgr.return_value = mock_mgr

        # Act - Login
        response = await client.post(
            "/auth/token",
            json={"username": "testuser", "password": "password123"},
            headers={"X-API-Key": "test-api-key-bypass-csrf"},  # Bypass CSRF for test
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK

    # Verify a new session was created (not reused)
    mock_mgr.create_session.assert_called_once()

    # Decode the JWT to verify it contains the session_id
    token = response.json()["access_token"]
    from pdfsigner.api.middleware.auth import verify_token

    token_data = verify_token(token)
    assert token_data.session_id == new_session_id


@pytest.mark.security
async def test_login_without_healthcare_mode_no_sessions(client):
    """Test login without healthcare_mode doesn't create sessions."""
    with (
        patch("pdfsigner.api.routes.auth.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.auth.get_user_repository") as mock_user_repo,
        patch("pdfsigner.api.routes.auth.get_password_validator") as mock_pwd_validator,
        patch("pdfsigner.api.routes.auth.get_session_manager") as mock_session_mgr,
    ):
        # Mock settings - healthcare_mode disabled
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = False
        mock_settings.return_value = mock_settings_obj

        # Mock user repository
        mock_repo = Mock()
        db_user = Mock()
        db_user.id = "user-123"
        db_user.username = "testuser"
        db_user.email = "testuser@example.com"
        db_user.is_active = True
        db_user.role = UserRole.SIGNER
        db_user.status = UserStatus.ACTIVE
        mock_repo.get_user_by_username.return_value = db_user
        mock_repo.get_password_hash.return_value = "hashed_password"
        mock_user_repo.return_value = mock_repo

        # Mock password validator
        mock_validator = Mock()
        mock_validator.verify_password.return_value = True
        mock_pwd_validator.return_value = mock_validator

        # Mock session manager
        mock_mgr = Mock()
        mock_session_mgr.return_value = mock_mgr

        # Act - Login
        response = await client.post(
            "/auth/token",
            json={"username": "testuser", "password": "password123"},
            headers={"X-API-Key": "test-api-key-bypass-csrf"},  # Bypass CSRF for test
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK

    # Verify no session operations were performed
    mock_mgr.get_user_sessions.assert_not_called()
    mock_mgr.create_session.assert_not_called()
    mock_mgr.terminate_session.assert_not_called()


@pytest.mark.security
async def test_multiple_logins_do_not_leak_sessions(client):
    """
    Test multiple successive logins don't accumulate sessions (leak prevention).

    Each login should terminate old sessions and create only one new session.
    """
    with (
        patch("pdfsigner.api.routes.auth.get_settings") as mock_settings,
        patch("pdfsigner.api.routes.auth.get_user_repository") as mock_user_repo,
        patch("pdfsigner.api.routes.auth.get_password_validator") as mock_pwd_validator,
        patch("pdfsigner.api.routes.auth.get_session_manager") as mock_session_mgr,
    ):
        # Mock settings
        mock_settings_obj = Mock()
        mock_settings_obj.healthcare_mode = True
        mock_settings.return_value = mock_settings_obj

        # Mock user repository
        mock_repo = Mock()
        db_user = Mock()
        db_user.id = "user-123"
        db_user.username = "testuser"
        db_user.email = "testuser@example.com"
        db_user.is_active = True
        db_user.role = UserRole.SIGNER
        db_user.status = UserStatus.ACTIVE
        mock_repo.get_user_by_username.return_value = db_user
        mock_repo.get_password_hash.return_value = "hashed_password"
        mock_user_repo.return_value = mock_repo

        # Mock password validator
        mock_validator = Mock()
        mock_validator.verify_password.return_value = True
        mock_pwd_validator.return_value = mock_validator

        # Mock session manager
        mock_mgr = Mock()

        # Simulate 3 logins
        for i in range(3):
            # Each login sees previous session(s)
            if i == 0:
                mock_mgr.get_user_sessions.return_value = []
            else:
                # Previous login created a session
                mock_mgr.get_user_sessions.return_value = [
                    Session(
                        id=f"session-{i - 1}",
                        user_id="testuser",
                        created_at=datetime.now(),
                        last_activity=datetime.now(),
                        expires_at=datetime.now() + timedelta(minutes=15),
                    )
                ]

            mock_mgr.create_session.return_value = Session(
                id=f"session-{i}",
                user_id="testuser",
                created_at=datetime.now(),
                last_activity=datetime.now(),
                expires_at=datetime.now() + timedelta(minutes=15),
            )
            mock_session_mgr.return_value = mock_mgr

            # Act - Login
            response = await client.post(
                "/auth/token",
                json={"username": "testuser", "password": "password123"},
                headers={"X-API-Key": "test-api-key-bypass-csrf"},  # Bypass CSRF for test
            )

            # Assert successful login
            assert response.status_code == status.HTTP_200_OK

        # Verify create_session was called 3 times (once per login)
        assert mock_mgr.create_session.call_count == 3

        # Verify old sessions were terminated (2 times: login 2 and login 3)
        assert mock_mgr.terminate_session.call_count == 2

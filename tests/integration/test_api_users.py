"""
Integration tests for User Management API routes.

Tests all user management endpoints with authentication, authorization,
and security scenarios (IDOR, privilege escalation, mass assignment).

Run with:
    uv run pytest tests/integration/test_api_users.py -v -m security
    uv run pytest tests/integration/test_api_users.py -v --cov=src/pdfsigner/api/routes/users
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import httpx
import pytest
from fastapi import status
from httpx import ASGITransport

from pdfsigner.api.main import app
from pdfsigner.api.middleware.auth import create_access_token
from pdfsigner.core.users import User, UserRole, UserStatus

# Mark all tests in this module as anyio (use anyio for async support)
pytestmark = [pytest.mark.anyio, pytest.mark.security]


# --- Fixtures ---


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def enable_healthcare_mode():
    """Enable healthcare mode for RBAC testing."""
    from pdfsigner.config.settings import get_settings

    settings = get_settings()
    original_mode = settings.healthcare_mode
    settings.healthcare_mode = True
    yield
    settings.healthcare_mode = original_mode


@pytest.fixture
def regular_user_token():
    """Create valid JWT token for regular user (signer role)."""
    token = create_access_token(
        data={"sub": "user123", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def regular_user_headers(regular_user_token):
    """Create authentication headers for regular user."""
    return {
        "Authorization": f"Bearer {regular_user_token}",
        "X-API-Key": "test-bypass-csrf",
    }


@pytest.fixture
def another_user_token():
    """Create valid JWT token for another regular user."""
    token = create_access_token(
        data={"sub": "user456", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def another_user_headers(another_user_token):
    """Create authentication headers for another user."""
    return {
        "Authorization": f"Bearer {another_user_token}",
        "X-API-Key": "test-bypass-csrf",
    }


@pytest.fixture
def admin_token():
    """Create valid admin JWT token for testing."""
    token = create_access_token(
        data={"sub": "admin123", "role": "admin"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def admin_headers(admin_token):
    """Create authentication headers with admin JWT token."""
    return {
        "Authorization": f"Bearer {admin_token}",
        "X-API-Key": "test-bypass-csrf",
    }


@pytest.fixture
def viewer_token():
    """Create valid JWT token for viewer role (least privileges)."""
    token = create_access_token(
        data={"sub": "viewer123", "role": "viewer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def viewer_headers(viewer_token):
    """Create authentication headers for viewer."""
    return {
        "Authorization": f"Bearer {viewer_token}",
        "X-API-Key": "test-bypass-csrf",
    }


@pytest.fixture
def mock_user():
    """Create mock user for testing."""
    return User(
        id="user123",
        username="john.doe",
        display_name="John Doe",
        email="john.doe@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
        created_at=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
        last_login_at=datetime(2024, 1, 20, 14, 22, 0, tzinfo=UTC),
        certificate_serial="ABC123",
        certificate_issuer="CN=TestCA",
    )


@pytest.fixture
def mock_admin():
    """Create mock admin user for testing."""
    return User(
        id="admin123",
        username="jane.admin",
        display_name="Jane Admin",
        email="jane.admin@example.com",
        role=UserRole.ADMIN,
        status=UserStatus.ACTIVE,
        created_at=datetime(2024, 1, 10, 9, 0, 0, tzinfo=UTC),
        last_login_at=datetime(2024, 1, 21, 8, 15, 0, tzinfo=UTC),
        certificate_serial="DEF456",
        certificate_issuer="CN=TestCA",
    )


@pytest.fixture
def mock_another_user():
    """Create another mock user for IDOR testing."""
    return User(
        id="user456",
        username="bob.smith",
        display_name="Bob Smith",
        email="bob.smith@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
        created_at=datetime(2024, 1, 18, 11, 45, 0, tzinfo=UTC),
        last_login_at=datetime(2024, 1, 22, 9, 30, 0, tzinfo=UTC),
        certificate_serial="GHI789",
        certificate_issuer="CN=TestCA",
    )


# --- GET /api/v1/users/me Tests ---


async def test_get_current_user_info_success(client, regular_user_headers):
    """Test getting current user info returns authenticated user data."""
    # Act
    response = await client.get("/api/v1/users/me", headers=regular_user_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == "user123"  # ID comes from token's "sub" field
    assert data["username"] == "user123"  # Username also from "sub"
    assert data["email"] == "user123@example.com"  # Mock email
    assert data["role"] == "signer"
    assert data["status"] == "active"


async def test_get_current_user_info_without_auth(client):
    """Test getting current user info fails without authentication."""
    # Act
    response = await client.get("/api/v1/users/me")

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- GET /api/v1/users/ Tests (Admin Only) ---


async def test_list_users_success_as_admin(client, admin_headers, mock_user, mock_admin):
    """Test admin can list all users successfully."""
    # Arrange
    with (
        patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo,
    ):
        mock_auth.return_value = mock_admin
        mock_repository = Mock()
        mock_repository.list_users.return_value = [mock_user, mock_admin]
        mock_repository.count_users.return_value = 2
        mock_repo.return_value = mock_repository

        # Act
        response = await client.get("/api/v1/users/", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 2
    assert len(data["users"]) == 2
    assert data["users"][0]["username"] == "john.doe"
    assert data["users"][1]["username"] == "jane.admin"


async def test_list_users_forbidden_for_regular_user(
    client, regular_user_headers, mock_user, enable_healthcare_mode
):
    """Test regular user cannot list users (403 Forbidden)."""
    # Arrange - Mock auth middleware to return user directly
    with patch("pdfsigner.api.middleware.auth.get_current_user", return_value=mock_user):
        # Act
        response = await client.get("/api/v1/users/", headers=regular_user_headers)

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_list_users_forbidden_for_viewer(client, viewer_headers, enable_healthcare_mode):
    """Test viewer role cannot list users (403 Forbidden)."""
    # Arrange
    mock_viewer = User(
        id="viewer123",
        username="viewer.user",
        display_name="Viewer User",
        email="viewer@example.com",
        role=UserRole.VIEWER,
        status=UserStatus.ACTIVE,
        created_at=datetime.now(UTC),
        certificate_serial="VWR111",
        certificate_issuer="CN=TestCA",
    )

    with patch("pdfsigner.api.middleware.auth.get_current_user", return_value=mock_viewer):
        # Act
        response = await client.get("/api/v1/users/", headers=viewer_headers)

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_list_users_with_filters(client, admin_headers, mock_admin):
    """Test listing users with status and role filters."""
    # Arrange
    with (
        patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo,
    ):
        mock_auth.return_value = mock_admin
        mock_repository = Mock()
        mock_repository.list_users.return_value = [mock_admin]
        mock_repository.count_users.return_value = 1
        mock_repo.return_value = mock_repository

        # Act
        response = await client.get(
            "/api/v1/users/",
            params={"status": "active", "role": "admin", "limit": 50, "offset": 0},
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 1
    mock_repository.list_users.assert_called_once()


async def test_list_users_invalid_status_filter(
    client, admin_headers, mock_admin, enable_healthcare_mode
):
    """Test listing users with invalid status returns 400."""
    # Arrange
    with patch("pdfsigner.api.middleware.auth.get_current_user", return_value=mock_admin):
        # Act
        response = await client.get(
            "/api/v1/users/",
            params={"status": "invalid_status"},
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid status" in response.json()["detail"]


async def test_list_users_invalid_role_filter(
    client, admin_headers, mock_admin, enable_healthcare_mode
):
    """Test listing users with invalid role returns 400."""
    # Arrange
    with patch("pdfsigner.api.middleware.auth.get_current_user", return_value=mock_admin):
        # Act
        response = await client.get(
            "/api/v1/users/",
            params={"role": "superadmin"},
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid role" in response.json()["detail"]


# --- GET /api/v1/users/{id} Tests (IDOR Prevention) ---


async def test_get_user_by_id_success_own_profile(client, regular_user_headers, mock_user):
    """Test user can view their own profile."""
    # Arrange
    with (
        patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo,
    ):
        mock_auth.return_value = mock_user
        mock_repository = Mock()
        mock_repository.get_user_by_id.return_value = mock_user
        mock_repo.return_value = mock_repository

        # Act
        response = await client.get(f"/api/v1/users/{mock_user.id}", headers=regular_user_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == "user123"
    assert data["username"] == "john.doe"


async def test_get_user_by_id_idor_prevention(
    client, regular_user_headers, mock_user, mock_another_user
):
    """Test user cannot view another user's profile (IDOR prevention - 403 Forbidden)."""
    # Arrange
    with patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth:
        mock_auth.return_value = mock_user

        # Act - Try to access another user's profile
        response = await client.get(
            f"/api/v1/users/{mock_another_user.id}", headers=regular_user_headers
        )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "only view your own profile" in response.json()["detail"]


async def test_get_user_by_id_admin_can_view_any_user(client, admin_headers, mock_admin, mock_user):
    """Test admin can view any user's profile."""
    # Arrange
    with (
        patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo,
    ):
        mock_auth.return_value = mock_admin
        mock_repository = Mock()
        mock_repository.get_user_by_id.return_value = mock_user
        mock_repo.return_value = mock_repository

        # Act - Admin viewing another user
        response = await client.get(f"/api/v1/users/{mock_user.id}", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == "user123"
    assert data["username"] == "john.doe"


async def test_get_user_by_id_not_found(client, admin_headers, mock_admin):
    """Test getting non-existent user returns 404."""
    # Arrange
    with (
        patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo,
    ):
        mock_auth.return_value = mock_admin
        mock_repository = Mock()
        mock_repository.get_user_by_id.return_value = None
        mock_repo.return_value = mock_repository

        # Act
        response = await client.get("/api/v1/users/nonexistent-id", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "User not found" in response.json()["detail"]


# --- PUT /api/v1/users/{id} Tests (Admin Only, Mass Assignment) ---


async def test_update_user_success_as_admin(client, admin_headers, mock_admin, mock_user):
    """Test admin can update user information."""
    # Arrange
    update_data = {
        "display_name": "John Updated Doe",
        "email": "john.updated@example.com",
        "role": "admin",
    }

    with (
        patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo,
    ):
        mock_auth.return_value = mock_admin
        mock_repository = Mock()
        updated_user = User(**mock_user.__dict__)
        updated_user.display_name = update_data["display_name"]
        updated_user.email = update_data["email"]
        updated_user.role = UserRole.ADMIN
        mock_repository.get_user_by_id.return_value = mock_user
        mock_repository.update_user.return_value = updated_user
        mock_repo.return_value = mock_repository

        # Act
        response = await client.put(
            f"/api/v1/users/{mock_user.id}",
            json=update_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["display_name"] == "John Updated Doe"
    assert data["email"] == "john.updated@example.com"
    assert data["role"] == "admin"


async def test_update_user_forbidden_for_regular_user(
    client, regular_user_headers, mock_user, enable_healthcare_mode
):
    """Test regular user cannot update users (403 Forbidden)."""
    # Arrange
    update_data = {"display_name": "New Name"}

    with patch("pdfsigner.api.middleware.auth.get_current_user", return_value=mock_user):
        # Act
        response = await client.put(
            f"/api/v1/users/{mock_user.id}",
            json=update_data,
            headers=regular_user_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_update_user_invalid_role(client, admin_headers, mock_admin, mock_user):
    """Test updating user with invalid role returns 422 (Pydantic validation)."""
    # Arrange
    update_data = {"role": "superadmin"}  # Invalid role

    with patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth:
        mock_auth.return_value = mock_admin

        # Act
        response = await client.put(
            f"/api/v1/users/{mock_user.id}",
            json=update_data,
            headers=admin_headers,
        )

    # Assert - Pydantic validates schema before business logic
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data = response.json()
    assert "detail" in data


async def test_update_user_not_found(client, admin_headers, mock_admin):
    """Test updating non-existent user returns 404."""
    # Arrange
    update_data = {"display_name": "New Name"}

    with (
        patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo,
    ):
        mock_auth.return_value = mock_admin
        mock_repository = Mock()
        mock_repository.get_user_by_id.return_value = None
        mock_repo.return_value = mock_repository

        # Act
        response = await client.put(
            "/api/v1/users/nonexistent-id",
            json=update_data,
            headers=admin_headers,
        )

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


# --- DELETE /api/v1/users/{id} Tests (Self-Deletion Prevention) ---


async def test_deactivate_user_success_as_admin(client, admin_headers, mock_admin, mock_user):
    """Test admin can deactivate another user."""
    # Arrange
    with (
        patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo,
    ):
        mock_auth.return_value = mock_admin
        mock_repository = Mock()
        mock_repository.get_user_by_id.return_value = mock_user
        mock_repository.deactivate_user.return_value = True
        mock_repo.return_value = mock_repository

        # Act
        response = await client.delete(f"/api/v1/users/{mock_user.id}", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "deactivated successfully" in data["message"]
    assert data["user_id"] == "user123"


async def test_deactivate_user_self_deletion_prevention(client, admin_headers, mock_admin):
    """Test admin cannot deactivate their own account (self-deletion prevention)."""
    # Arrange
    with patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth:
        mock_auth.return_value = mock_admin

        # Act - Admin trying to deactivate themselves
        response = await client.delete(f"/api/v1/users/{mock_admin.id}", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "cannot deactivate your own account" in response.json()["detail"]


async def test_deactivate_user_forbidden_for_regular_user(
    client, regular_user_headers, mock_user, mock_another_user, enable_healthcare_mode
):
    """Test regular user cannot deactivate users (403 Forbidden)."""
    # Arrange
    with patch("pdfsigner.api.middleware.auth.get_current_user", return_value=mock_user):
        # Act
        response = await client.delete(
            f"/api/v1/users/{mock_another_user.id}", headers=regular_user_headers
        )

    # Assert
    assert response.status_code == status.HTTP_403_FORBIDDEN


async def test_deactivate_user_not_found(client, admin_headers, mock_admin):
    """Test deactivating non-existent user returns 404."""
    # Arrange
    with (
        patch("pdfsigner.api.routes.users.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo,
    ):
        mock_auth.return_value = mock_admin
        mock_repository = Mock()
        mock_repository.get_user_by_id.return_value = None
        mock_repo.return_value = mock_repository

        # Act
        response = await client.delete("/api/v1/users/nonexistent-id", headers=admin_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND

"""
Integration tests for API Key Management routes.

Tests API key creation, listing, revocation, and authentication.

Run with:
    uv run pytest tests/integration/test_api_keys.py -v
    uv run pytest tests/integration/test_api_keys.py -v --cov=src/pdfsigner/api/routes/api_keys
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, Mock, patch

import httpx
import pytest
from fastapi import status
from httpx import ASGITransport

from pdfsigner.api.main import app
from pdfsigner.api.middleware.auth import create_access_token
from pdfsigner.api.middleware.csrf import CSRF_COOKIE_NAME, CSRF_HEADER_NAME
from pdfsigner.core.users import User, UserRole, UserStatus
from pdfsigner.core.users.api_key_repository import APIKey

# Mark all tests in this module as anyio
pytestmark = [pytest.mark.anyio]


# --- Helper Functions ---


async def get_csrf_token(client) -> tuple[str, dict]:
    """
    Get CSRF token from server.

    Returns:
        Tuple of (csrf_token, cookies_dict)
    """
    response = await client.get("/health")
    csrf_token = response.cookies.get(CSRF_COOKIE_NAME)
    return csrf_token, {CSRF_COOKIE_NAME: csrf_token}


# --- Fixtures ---


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def regular_user():
    """Create mock regular user."""
    return User(
        id="user123",
        username="john.doe",
        display_name="John Doe",
        email="john.doe@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
        created_at=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
    )


@pytest.fixture
def regular_user_token(regular_user):
    """Create valid JWT token for regular user."""
    token = create_access_token(
        data={"sub": regular_user.username, "user_id": regular_user.id, "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def regular_user_headers(regular_user_token):
    """Create authentication headers for regular user."""
    return {"Authorization": f"Bearer {regular_user_token}"}


@pytest.fixture
def mock_api_key(regular_user):
    """Create mock API key."""
    return APIKey(
        id="key123",
        user_id=regular_user.id,
        key_hash="abc123hash",
        name="CI/CD Pipeline",
        created_at=datetime(2024, 1, 20, 10, 0, 0, tzinfo=UTC),
        last_used_at=None,
        expires_at=None,
        revoked=False,
    )


# --- POST /api/v1/api-keys/ Tests ---


async def test_create_api_key_success(client, regular_user_headers, regular_user):
    """Test creating API key returns plaintext key once."""
    # Arrange
    mock_api_key = APIKey(
        id="key456",
        user_id=regular_user.id,
        key_hash="newhash",
        name="Test Key",
        created_at=datetime.now(UTC),
        expires_at=None,
        revoked=False,
    )
    plaintext_key = "pds_generatedkey123456789"

    # Get CSRF token
    csrf_token, csrf_cookies = await get_csrf_token(client)
    headers = {**regular_user_headers, CSRF_HEADER_NAME: csrf_token}

    with (
        patch("pdfsigner.api.routes.api_keys.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.api_keys.get_api_key_repository") as mock_repo,
    ):
        mock_auth.return_value = regular_user
        mock_repository = Mock()
        mock_repository.create_api_key.return_value = (mock_api_key, plaintext_key)
        mock_repo.return_value = mock_repository

        # Act
        response = await client.post(
            "/api/v1/api-keys/",
            json={"name": "Test Key", "expires_in_days": None},
            headers=headers,
            cookies=csrf_cookies,
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["id"] == "key456"
    assert data["name"] == "Test Key"
    assert data["api_key"] == plaintext_key  # Plaintext key returned only once
    assert "api_key" in data


async def test_create_api_key_with_expiration(client, regular_user_headers, regular_user):
    """Test creating API key with expiration."""
    # Arrange
    expires_at = datetime.now(UTC) + timedelta(days=90)
    mock_api_key = APIKey(
        id="key789",
        user_id=regular_user.id,
        key_hash="expiryhash",
        name="Temp Key",
        created_at=datetime.now(UTC),
        expires_at=expires_at,
        revoked=False,
    )
    plaintext_key = "pds_tempkey999"

    # Get CSRF token
    csrf_token, csrf_cookies = await get_csrf_token(client)
    headers = {**regular_user_headers, CSRF_HEADER_NAME: csrf_token}

    with (
        patch("pdfsigner.api.routes.api_keys.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.api_keys.get_api_key_repository") as mock_repo,
    ):
        mock_auth.return_value = regular_user
        mock_repository = Mock()
        mock_repository.create_api_key.return_value = (mock_api_key, plaintext_key)
        mock_repo.return_value = mock_repository

        # Act
        response = await client.post(
            "/api/v1/api-keys/",
            json={"name": "Temp Key", "expires_in_days": 90},
            headers=headers,
            cookies=csrf_cookies,
        )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["expires_at"] is not None


async def test_create_api_key_without_auth(client):
    """Test creating API key fails without authentication."""
    # Act
    response = await client.post(
        "/api/v1/api-keys/",
        json={"name": "Test Key"},
    )

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_create_api_key_invalid_name(client, regular_user_headers):
    """Test creating API key with empty name returns 422."""
    # Act
    response = await client.post(
        "/api/v1/api-keys/",
        json={"name": ""},  # Empty name
        headers=regular_user_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_create_api_key_invalid_expiration(client, regular_user_headers):
    """Test creating API key with invalid expiration returns 422."""
    # Act
    response = await client.post(
        "/api/v1/api-keys/",
        json={"name": "Test Key", "expires_in_days": 400},  # Max 365 days
        headers=regular_user_headers,
    )

    # Assert
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# --- GET /api/v1/api-keys/ Tests ---


async def test_list_api_keys_success(client, regular_user_headers, regular_user, mock_api_key):
    """Test listing user's API keys."""
    # Arrange
    with (
        patch("pdfsigner.api.routes.api_keys.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.api_keys.get_api_key_repository") as mock_repo,
    ):
        mock_auth.return_value = regular_user
        mock_repository = Mock()
        mock_repository.list_for_user.return_value = [mock_api_key]
        mock_repo.return_value = mock_repository

        # Act
        response = await client.get("/api/v1/api-keys/", headers=regular_user_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 1
    assert len(data["api_keys"]) == 1
    assert data["api_keys"][0]["id"] == "key123"
    assert data["api_keys"][0]["name"] == "CI/CD Pipeline"
    assert "api_key" not in data["api_keys"][0]  # Plaintext key not included in list


async def test_list_api_keys_empty(client, regular_user_headers, regular_user):
    """Test listing when user has no API keys."""
    # Arrange
    with (
        patch("pdfsigner.api.routes.api_keys.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.api_keys.get_api_key_repository") as mock_repo,
    ):
        mock_auth.return_value = regular_user
        mock_repository = Mock()
        mock_repository.list_for_user.return_value = []
        mock_repo.return_value = mock_repository

        # Act
        response = await client.get("/api/v1/api-keys/", headers=regular_user_headers)

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total"] == 0
    assert len(data["api_keys"]) == 0


async def test_list_api_keys_without_auth(client):
    """Test listing API keys fails without authentication."""
    # Act
    response = await client.get("/api/v1/api-keys/")

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- DELETE /api/v1/api-keys/{id} Tests ---


async def test_revoke_api_key_success(client, regular_user_headers, regular_user, mock_api_key):
    """Test revoking API key."""
    # Arrange
    with (
        patch("pdfsigner.api.routes.api_keys.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.api_keys.get_api_key_repository") as mock_repo,
    ):
        mock_auth.return_value = regular_user
        mock_repository = Mock()
        mock_repository.get_by_id.return_value = mock_api_key
        mock_repository.revoke.return_value = True
        mock_repo.return_value = mock_repository

        # Act
        response = await client.delete(
            f"/api/v1/api-keys/{mock_api_key.id}", headers=regular_user_headers
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "revoked successfully" in data["message"]
    assert data["key_id"] == "key123"


async def test_revoke_api_key_not_found(client, regular_user_headers, regular_user):
    """Test revoking non-existent API key returns 404."""
    # Arrange
    with (
        patch("pdfsigner.api.routes.api_keys.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.api_keys.get_api_key_repository") as mock_repo,
    ):
        mock_auth.return_value = regular_user
        mock_repository = Mock()
        mock_repository.get_by_id.return_value = None
        mock_repo.return_value = mock_repository

        # Act
        response = await client.delete("/api/v1/api-keys/nonexistent", headers=regular_user_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND


async def test_revoke_api_key_not_owned(client, regular_user_headers, regular_user):
    """Test user cannot revoke another user's API key."""
    # Arrange
    other_user_key = APIKey(
        id="key999",
        user_id="other_user_id",  # Different user
        key_hash="otherhash",
        name="Other User Key",
        created_at=datetime.now(UTC),
        expires_at=None,
        revoked=False,
    )

    with (
        patch("pdfsigner.api.routes.api_keys.get_current_user_or_api_key") as mock_auth,
        patch("pdfsigner.api.routes.api_keys.get_api_key_repository") as mock_repo,
    ):
        mock_auth.return_value = regular_user
        mock_repository = Mock()
        mock_repository.get_by_id.return_value = other_user_key
        mock_repo.return_value = mock_repository

        # Act
        response = await client.delete("/api/v1/api-keys/key999", headers=regular_user_headers)

    # Assert
    assert response.status_code == status.HTTP_404_NOT_FOUND  # Don't leak existence


async def test_revoke_api_key_without_auth(client):
    """Test revoking API key fails without authentication."""
    # Act
    response = await client.delete("/api/v1/api-keys/key123")

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# --- API Key Authentication Tests ---


async def test_authenticate_with_api_key_success(client, regular_user, mock_api_key):
    """Test API key can be used for authentication."""
    # Arrange
    plaintext_key = "pds_testkey123"
    key_hash = "hashoftestkey"

    with (
        patch("pdfsigner.api.middleware.auth.get_api_key_repository") as mock_repo,
        patch("pdfsigner.api.middleware.auth.UserRepository") as mock_user_repo_class,
    ):
        # Mock API key repository
        mock_repository = Mock()
        mock_api_key_obj = MagicMock()
        mock_api_key_obj.is_valid = True
        mock_api_key_obj.user_id = regular_user.id
        mock_api_key_obj.id = "key123"
        mock_repository.get_by_hash.return_value = mock_api_key_obj
        mock_repository.update_last_used.return_value = True
        mock_repo.return_value = mock_repository

        # Mock user repository
        mock_user_repo = Mock()
        mock_user_repo.get_user_by_id.return_value = regular_user
        mock_user_repo_class.return_value = mock_user_repo

        # Act - Use API key header
        response = await client.get(
            "/api/v1/users/me",
            headers={"X-API-Key": plaintext_key},
        )

    # Assert
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == regular_user.id
    assert data["username"] == regular_user.username


async def test_authenticate_with_revoked_api_key(client):
    """Test revoked API key cannot be used for authentication."""
    # Arrange
    plaintext_key = "pds_revokedkey"

    with patch("pdfsigner.api.middleware.auth.get_api_key_repository") as mock_repo:
        mock_repository = Mock()
        mock_api_key_obj = MagicMock()
        mock_api_key_obj.is_valid = False  # Revoked
        mock_api_key_obj.revoked = True
        mock_repository.get_by_hash.return_value = mock_api_key_obj
        mock_repo.return_value = mock_repository

        # Act
        response = await client.get(
            "/api/v1/users/me",
            headers={"X-API-Key": plaintext_key},
        )

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "revoked or expired" in response.json()["detail"]


async def test_authenticate_with_expired_api_key(client):
    """Test expired API key cannot be used for authentication."""
    # Arrange
    plaintext_key = "pds_expiredkey"

    with patch("pdfsigner.api.middleware.auth.get_api_key_repository") as mock_repo:
        mock_repository = Mock()
        mock_api_key_obj = MagicMock()
        mock_api_key_obj.is_valid = False  # Expired
        mock_api_key_obj.revoked = False
        mock_api_key_obj.expires_at = datetime.now(UTC) - timedelta(days=1)
        mock_repository.get_by_hash.return_value = mock_api_key_obj
        mock_repo.return_value = mock_repository

        # Act
        response = await client.get(
            "/api/v1/users/me",
            headers={"X-API-Key": plaintext_key},
        )

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


async def test_authenticate_with_invalid_api_key(client):
    """Test invalid API key returns 401."""
    # Arrange
    with patch("pdfsigner.api.middleware.auth.get_api_key_repository") as mock_repo:
        mock_repository = Mock()
        mock_repository.get_by_hash.return_value = None  # Key not found
        mock_repo.return_value = mock_repository

        # Act
        response = await client.get(
            "/api/v1/users/me",
            headers={"X-API-Key": "pds_invalidkey"},
        )

    # Assert
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

"""
Integration tests for admin user protection.

Tests that the system prevents deactivation of the last admin user,
ensuring there is always at least one active admin in the system.

Run with:
    uv run pytest tests/integration/test_admin_protection.py -v
"""

from datetime import timedelta
from unittest.mock import Mock, patch

import httpx
import pytest
from fastapi import status
from httpx import ASGITransport

from pdfsigner.api.main import app
from pdfsigner.api.middleware.auth import create_access_token
from pdfsigner.core.users import User, UserRole, UserStatus

pytestmark = [pytest.mark.anyio, pytest.mark.security]


# --- Fixtures ---


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def admin_token():
    """Create valid admin JWT token."""
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
        "X-API-Key": "test-api-key-bypass-csrf",  # Bypass CSRF for tests
    }


@pytest.fixture
def mock_admin_user():
    """Create mock admin user."""
    return User(
        id="admin456",
        username="admin_target",
        display_name="Target Admin",
        email="target@example.com",
        role=UserRole.ADMIN,
        status=UserStatus.ACTIVE,
    )


@pytest.fixture
def mock_regular_user():
    """Create mock regular user."""
    return User(
        id="user789",
        username="regular_user",
        display_name="Regular User",
        email="user@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
    )


# --- Tests ---


@pytest.mark.security
async def test_cannot_deactivate_last_admin(client, admin_headers, mock_admin_user):
    """
    Test that the last active admin user cannot be deactivated.

    Security: Prevents system lockout by ensuring at least one admin exists.
    """
    with (
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo_factory,
    ):
        mock_repo = Mock()
        mock_repo_factory.return_value = mock_repo

        # Mock: Only 1 active admin in the system (the one we're trying to deactivate)
        mock_repo.get_user_by_id.return_value = mock_admin_user
        mock_repo.count_admins.return_value = 1

        # Attempt to deactivate the last admin
        response = await client.delete(
            f"/api/v1/users/{mock_admin_user.id}",
            headers=admin_headers,
        )

        # Should be rejected with 400 Bad Request
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Cannot deactivate the last admin user" in response.json()["detail"]

        # Verify deactivate was never called
        mock_repo.deactivate_user.assert_not_called()


@pytest.mark.security
async def test_can_deactivate_admin_when_multiple_exist(client, admin_headers, mock_admin_user):
    """
    Test that an admin can be deactivated when multiple active admins exist.

    This ensures the protection only applies when there's a single admin.
    """
    with (
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo_factory,
    ):
        mock_repo = Mock()
        mock_repo_factory.return_value = mock_repo

        # Mock: 2 active admins in the system
        mock_repo.get_user_by_id.return_value = mock_admin_user
        mock_repo.count_admins.return_value = 2
        mock_repo.deactivate_user.return_value = True

        # Deactivate one admin (another still remains)
        response = await client.delete(
            f"/api/v1/users/{mock_admin_user.id}",
            headers=admin_headers,
        )

        # Should succeed
        assert response.status_code == status.HTTP_200_OK
        assert "deactivated successfully" in response.json()["message"]

        # Verify deactivate was called
        mock_repo.deactivate_user.assert_called_once_with(mock_admin_user.id)


@pytest.mark.security
async def test_can_deactivate_non_admin_user(client, admin_headers, mock_regular_user):
    """
    Test that non-admin users can always be deactivated.

    The admin protection only applies to admin users, not regular users.
    """
    with (
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo_factory,
    ):
        mock_repo = Mock()
        mock_repo_factory.return_value = mock_repo

        # Mock: Regular user (not admin)
        mock_repo.get_user_by_id.return_value = mock_regular_user
        mock_repo.deactivate_user.return_value = True

        # Deactivate regular user
        response = await client.delete(
            f"/api/v1/users/{mock_regular_user.id}",
            headers=admin_headers,
        )

        # Should succeed (no admin count check needed)
        assert response.status_code == status.HTTP_200_OK
        assert "deactivated successfully" in response.json()["message"]

        # Verify count_admins was never called (not needed for non-admins)
        mock_repo.count_admins.assert_not_called()

        # Verify deactivate was called
        mock_repo.deactivate_user.assert_called_once_with(mock_regular_user.id)


@pytest.mark.security
async def test_can_deactivate_inactive_admin(client, admin_headers, mock_admin_user):
    """
    Test that an already inactive admin can be deactivated without restriction.

    The protection only applies to active admins, not inactive ones.
    """
    # Set admin to inactive status
    mock_admin_user.status = UserStatus.INACTIVE

    with (
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo_factory,
    ):
        mock_repo = Mock()
        mock_repo_factory.return_value = mock_repo

        # Mock: Only 1 active admin in system, but this one is already inactive
        mock_repo.get_user_by_id.return_value = mock_admin_user
        mock_repo.count_admins.return_value = 1
        mock_repo.deactivate_user.return_value = True

        # Deactivate already inactive admin
        response = await client.delete(
            f"/api/v1/users/{mock_admin_user.id}",
            headers=admin_headers,
        )

        # Should succeed (inactive admins don't affect the count)
        assert response.status_code == status.HTTP_200_OK
        assert "deactivated successfully" in response.json()["message"]

        # Verify count_admins was never called (user is already inactive)
        mock_repo.count_admins.assert_not_called()

        # Verify deactivate was called
        mock_repo.deactivate_user.assert_called_once_with(mock_admin_user.id)


@pytest.mark.security
async def test_admin_protection_different_user(client, admin_headers, mock_admin_user):
    """
    Test that admin protection works correctly when the requesting user
    is different from the user being deactivated.
    """
    with (
        patch("pdfsigner.api.routes.users.get_user_repository") as mock_repo_factory,
    ):
        mock_repo = Mock()
        mock_repo_factory.return_value = mock_repo

        # Mock: Only 1 active admin (the one being deactivated)
        # Note: admin123 (requesting user) is different from admin456 (target user)
        mock_repo.get_user_by_id.return_value = mock_admin_user
        mock_repo.count_admins.return_value = 1

        # Admin123 tries to deactivate admin456 (last admin)
        response = await client.delete(
            f"/api/v1/users/{mock_admin_user.id}",
            headers=admin_headers,
        )

        # Should be rejected (still the last admin, even if different user)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Cannot deactivate the last admin user" in response.json()["detail"]

        # Verify deactivate was never called
        mock_repo.deactivate_user.assert_not_called()

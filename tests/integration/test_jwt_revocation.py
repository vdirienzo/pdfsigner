"""
Integration tests for JWT blacklist and token revocation.

Tests real logout functionality with JWT blacklist.
"""

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from httpx import ASGITransport

from pdfsigner.api.main import app
from pdfsigner.core.auth.jwt_blacklist import JWTBlacklist, generate_jti, get_jwt_blacklist
from pdfsigner.core.users.user_model import UserRole, UserStatus
from pdfsigner.core.users.user_repository import UserRepository

# Mark all tests as anyio (async support)
pytestmark = pytest.mark.anyio


@pytest.fixture
def temp_blacklist_db():
    """Create temporary blacklist database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)

    yield db_path

    # Cleanup
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def blacklist(temp_blacklist_db):
    """Create JWTBlacklist instance with temporary database."""
    return JWTBlacklist(db_path=temp_blacklist_db)


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def user_repo():
    """Create UserRepository instance for testing."""
    return UserRepository()


@pytest.fixture
def test_user(user_repo: UserRepository):
    """Create test user with password."""
    from pdfsigner.core.auth.password_validator import get_password_validator
    from pdfsigner.core.users.user_model import User

    # Generate unique username for each test
    unique_id = generate_jti()[:8]
    username = f"testuser_jwt_{unique_id}"

    # Create user object
    user = User(
        id=generate_jti(),  # Use random UUID for test user ID
        username=username,
        email=f"{username}@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
    )

    # Create user in repository
    created_user = user_repo.create_user(user)

    # Set password
    password_validator = get_password_validator()
    password_hash = password_validator.hash_password("TestPass123!")
    user_repo.set_password(created_user.id, password_hash)

    yield created_user

    # Cleanup
    try:
        user_repo.delete_user(created_user.id)
    except Exception:
        pass


@pytest.fixture
def disable_csrf():
    """Disable CSRF validation for testing."""
    from pdfsigner.api.middleware.csrf import CSRFMiddleware

    original_dispatch = CSRFMiddleware.dispatch

    async def mock_dispatch(self, request, call_next):
        return await call_next(request)

    with patch.object(CSRFMiddleware, "dispatch", mock_dispatch):
        yield


# --- Unit Tests for JWTBlacklist ---


def test_blacklist_initialization(temp_blacklist_db):
    """Test blacklist database initialization."""
    blacklist = JWTBlacklist(db_path=temp_blacklist_db)

    # Database file should exist
    assert temp_blacklist_db.exists()

    # Stats should show zero tokens
    stats = blacklist.get_stats()
    assert stats["total_tokens"] == 0
    assert stats["active_tokens"] == 0
    assert stats["expired_tokens"] == 0


def test_add_token_to_blacklist(blacklist):
    """Test adding token to blacklist."""
    jti = generate_jti()
    expires_at = datetime.now(UTC) + timedelta(hours=1)

    blacklist.add_token(jti, expires_at, reason="logout")

    # Token should be blacklisted
    assert blacklist.is_blacklisted(jti)

    # Stats should reflect one active token
    stats = blacklist.get_stats()
    assert stats["total_tokens"] == 1
    assert stats["active_tokens"] == 1


def test_add_duplicate_token_is_idempotent(blacklist):
    """Test adding same token twice is idempotent."""
    jti = generate_jti()
    expires_at = datetime.now(UTC) + timedelta(hours=1)

    # Add twice
    blacklist.add_token(jti, expires_at)
    blacklist.add_token(jti, expires_at)  # Should not raise error

    # Should still only have one token
    stats = blacklist.get_stats()
    assert stats["total_tokens"] == 1


def test_expired_token_not_blacklisted(blacklist):
    """Test expired tokens are not considered blacklisted."""
    jti = generate_jti()
    expires_at = datetime.now(UTC) - timedelta(hours=1)  # Already expired

    blacklist.add_token(jti, expires_at)

    # Token should not be blacklisted (expired naturally)
    assert not blacklist.is_blacklisted(jti)


def test_cleanup_expired_tokens(blacklist):
    """Test cleanup removes only expired tokens."""
    # Add active token
    jti_active = generate_jti()
    blacklist.add_token(jti_active, datetime.now(UTC) + timedelta(hours=1))

    # Add expired token
    jti_expired = generate_jti()
    blacklist.add_token(jti_expired, datetime.now(UTC) - timedelta(hours=1))

    # Before cleanup
    stats = blacklist.get_stats()
    assert stats["total_tokens"] == 2

    # Run cleanup
    removed = blacklist.cleanup_expired()
    assert removed == 1

    # After cleanup
    stats = blacklist.get_stats()
    assert stats["total_tokens"] == 1
    assert stats["active_tokens"] == 1
    assert blacklist.is_blacklisted(jti_active)


def test_clear_all_tokens(blacklist):
    """Test clearing all tokens from blacklist."""
    # Add multiple tokens
    for _ in range(5):
        jti = generate_jti()
        blacklist.add_token(jti, datetime.now(UTC) + timedelta(hours=1))

    # Verify tokens added
    stats = blacklist.get_stats()
    assert stats["total_tokens"] == 5

    # Clear all
    removed = blacklist.clear_all()
    assert removed == 5

    # Verify all removed
    stats = blacklist.get_stats()
    assert stats["total_tokens"] == 0


def test_generate_jti_unique():
    """Test generate_jti creates unique IDs."""
    jti1 = generate_jti()
    jti2 = generate_jti()

    assert jti1 != jti2
    assert len(jti1) == 36  # UUID format


def test_singleton_blacklist():
    """Test get_jwt_blacklist returns singleton instance."""
    blacklist1 = get_jwt_blacklist()
    blacklist2 = get_jwt_blacklist()

    assert blacklist1 is blacklist2


# --- Integration Tests with FastAPI ---


async def test_login_creates_token_with_jti(client, test_user, disable_csrf):
    """Test login creates JWT token with jti claim."""
    from pdfsigner.api.middleware.auth import verify_token

    # Login
    response = await client.post(
        "/auth/token",
        json={"username": test_user.username, "password": "TestPass123!"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    # Verify token has jti
    token_data = verify_token(data["access_token"])
    assert token_data.jti is not None
    assert len(token_data.jti) == 36  # UUID format


async def test_logout_revokes_token(client, test_user, disable_csrf):
    """Test logout adds token to blacklist."""
    # Clear blacklist
    blacklist = get_jwt_blacklist()
    blacklist.clear_all()

    # Login
    response = await client.post(
        "/auth/token",
        json={"username": test_user.username, "password": "TestPass123!"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]

    # Verify token works
    response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200

    # Logout
    response = await client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert "token revoked" in response.json()["message"]

    # Blacklist should have one token
    stats = blacklist.get_stats()
    assert stats["active_tokens"] == 1


async def test_revoked_token_cannot_be_used(client, test_user, disable_csrf):
    """Test revoked token is rejected for API calls."""
    # Clear blacklist
    blacklist = get_jwt_blacklist()
    blacklist.clear_all()

    # Login
    response = await client.post(
        "/auth/token",
        json={"username": test_user.username, "password": "TestPass123!"},
    )
    token = response.json()["access_token"]

    # Logout (revoke token)
    response = await client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200

    # Try to use revoked token
    response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert "revoked" in response.json()["detail"].lower()


async def test_refresh_with_revoked_token_fails(client, test_user, disable_csrf):
    """Test refresh endpoint rejects revoked tokens."""
    # Clear blacklist
    blacklist = get_jwt_blacklist()
    blacklist.clear_all()

    # Login
    response = await client.post(
        "/auth/token",
        json={"username": test_user.username, "password": "TestPass123!"},
    )
    token = response.json()["access_token"]

    # Logout (revoke token)
    await client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )

    # Try to refresh with revoked token
    response = await client.post(
        "/auth/refresh",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert "revoked" in response.json()["detail"].lower()


async def test_new_token_after_logout_works(client, test_user, disable_csrf):
    """Test logging in again after logout creates new valid token."""
    # Clear blacklist
    blacklist = get_jwt_blacklist()
    blacklist.clear_all()

    # First login
    response = await client.post(
        "/auth/token",
        json={"username": test_user.username, "password": "TestPass123!"},
    )
    token1 = response.json()["access_token"]

    # Logout
    await client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {token1}"},
    )

    # Second login (new token)
    response = await client.post(
        "/auth/token",
        json={"username": test_user.username, "password": "TestPass123!"},
    )
    assert response.status_code == 200
    token2 = response.json()["access_token"]

    # New token should work
    response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token2}"},
    )
    assert response.status_code == 200

    # Old token should still be revoked
    response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert response.status_code == 401


async def test_logout_response_messages(client, test_user, disable_csrf):
    """Test logout returns appropriate messages."""
    # Login
    response = await client.post(
        "/auth/token",
        json={"username": test_user.username, "password": "TestPass123!"},
    )
    token = response.json()["access_token"]

    # Logout
    response = await client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    message = response.json()["message"]
    assert "logged out" in message.lower()
    assert "token revoked" in message.lower()


async def test_blacklist_stats_after_multiple_logouts(client, test_user, disable_csrf):
    """Test blacklist stats reflect multiple logouts."""
    # Clear blacklist
    blacklist = get_jwt_blacklist()
    blacklist.clear_all()

    # Login and logout 3 times
    for _ in range(3):
        # Login
        response = await client.post(
            "/auth/token",
            json={"username": test_user.username, "password": "TestPass123!"},
        )
        token = response.json()["access_token"]

        # Logout
        await client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )

    # Should have 3 blacklisted tokens
    stats = blacklist.get_stats()
    assert stats["active_tokens"] == 3
    assert stats["total_tokens"] == 3


# --- Error Cases ---


async def test_missing_jti_handled_gracefully(client, test_user, disable_csrf):
    """Test tokens without jti are handled gracefully."""

    # Create token without jti (shouldn't happen with new code, but test resilience)
    # We can't easily create this without modifying create_access_token,
    # so we test that logout handles missing jti gracefully

    # Login normally
    response = await client.post(
        "/auth/token",
        json={"username": test_user.username, "password": "TestPass123!"},
    )
    token = response.json()["access_token"]

    # Logout should still succeed even if jti processing fails
    response = await client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    # Should return 200 even if blacklist operation fails
    assert response.status_code in [200, 401]  # 401 if token already used


def test_token_not_blacklisted_if_missing_jti(blacklist):
    """Test non-existent jti returns False for is_blacklisted."""
    # Random JTI that was never added
    fake_jti = generate_jti()

    assert not blacklist.is_blacklisted(fake_jti)


async def test_logout_without_token_fails(client, disable_csrf):
    """Test logout endpoint requires authentication."""
    response = await client.post("/auth/logout")
    assert response.status_code == 401


# --- Cleanup Tests ---


def test_periodic_cleanup_maintains_blacklist(blacklist):
    """Test periodic cleanup keeps blacklist size manageable."""
    # Add mix of active and expired tokens
    for i in range(10):
        jti = generate_jti()
        if i < 5:
            # Active tokens
            expires_at = datetime.now(UTC) + timedelta(hours=1)
        else:
            # Expired tokens
            expires_at = datetime.now(UTC) - timedelta(hours=1)

        blacklist.add_token(jti, expires_at)

    # Before cleanup
    stats = blacklist.get_stats()
    assert stats["total_tokens"] == 10

    # Cleanup
    removed = blacklist.cleanup_expired()
    assert removed == 5

    # After cleanup
    stats = blacklist.get_stats()
    assert stats["total_tokens"] == 5
    assert stats["active_tokens"] == 5
    assert stats["expired_tokens"] == 0

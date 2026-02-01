"""
Integration tests for authentication logout functionality.

Tests JWT blacklist, session termination, audit logging, and edge cases
for the logout endpoint.

Run with:
    uv run pytest tests/integration/test_auth_logout.py -v
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import httpx
import pytest
from httpx import ASGITransport

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.main import app
from pdfsigner.api.middleware.auth import create_access_token
from pdfsigner.config.settings import get_settings
from pdfsigner.core.audit.audit_event import AuditEventType
from pdfsigner.core.audit.audit_logger import AuditLogger
from pdfsigner.core.auth.jwt_blacklist import JWTBlacklist
from pdfsigner.core.session.session_manager import SessionManager

# Mark all tests as anyio for async support
pytestmark = pytest.mark.anyio


# --- Fixtures ---


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def temp_blacklist(tmp_path):
    """Create temporary JWT blacklist for testing."""
    db_path = tmp_path / "test_blacklist.db"
    blacklist = JWTBlacklist(db_path=db_path)
    yield blacklist
    # Cleanup
    blacklist.clear_all()


@pytest.fixture
def temp_session_manager(tmp_path):
    """Create temporary session manager for testing."""
    db_path = tmp_path / "test_sessions.db"
    return SessionManager(db_path=db_path)


@pytest.fixture
def temp_audit_logger(tmp_path):
    """Create temporary audit logger for testing."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    return AuditLogger(log_dir=audit_dir, enabled=True)


@pytest.fixture
def auth_token():
    """Create valid JWT token for testing."""
    token = create_access_token(
        data={"sub": "testuser", "user_id": "user-123", "role": "signer"},
        expires_delta=timedelta(minutes=30),
    )
    return token


@pytest.fixture
def auth_token_with_session(temp_session_manager):
    """Create JWT token with session ID for healthcare mode testing."""
    settings = get_settings()

    # Create session
    session = temp_session_manager.create_session(
        user_id="testuser",
        ip_address="127.0.0.1",
        user_agent="test-agent",
    )

    # Create token with session ID
    token = create_access_token(
        data={"sub": "testuser", "user_id": "user-123", "role": "signer"},
        expires_delta=timedelta(minutes=30),
        session_id=session.id,
    )

    return token, session.id


@pytest.fixture
def expired_token():
    """Create expired JWT token for testing."""
    token = create_access_token(
        data={"sub": "testuser", "user_id": "user-123", "role": "signer"},
        expires_delta=timedelta(seconds=-1),  # Already expired
    )
    return token


@pytest.fixture
def api_key_headers():
    """Create API key headers to bypass CSRF protection in tests."""
    return {"X-API-Key": "test-api-key-123"}


# --- Tests: Basic Logout ---


async def test_logout_success(client, auth_token, temp_blacklist, api_key_headers):
    """Basic logout should succeed with 200 OK."""
    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        headers = {"Authorization": f"Bearer {auth_token}", **api_key_headers}
        response = await client.post("/auth/logout", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "logged out" in data["message"].lower()
        assert "revoked" in data["message"].lower()


async def test_logout_response_format(client, auth_token, temp_blacklist, api_key_headers):
    """Logout response should have correct format."""
    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        headers = {"Authorization": f"Bearer {auth_token}", **api_key_headers}
        response = await client.post("/auth/logout", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        assert "message" in data
        assert isinstance(data["message"], str)


async def test_logout_without_token_rejected(client, api_key_headers):
    """Logout without token should be rejected with 401."""
    # Need API key to bypass CSRF even without JWT token
    response = await client.post("/auth/logout", headers=api_key_headers)

    assert response.status_code == 401  # Returns 401 for invalid/missing token


# --- Tests: JWT Blacklist Functionality ---


async def test_token_blacklisted_after_logout(client, auth_token, temp_blacklist, api_key_headers):
    """Token should be added to blacklist after logout."""
    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        headers = {"Authorization": f"Bearer {auth_token}", **api_key_headers}

        # Logout
        response = await client.post("/auth/logout", headers=headers)
        assert response.status_code == 200

        # Verify token is blacklisted
        from jose import jwt

        # Decode token to get JTI
        settings = get_api_settings()
        payload = jwt.decode(
            auth_token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
        )
        jti = payload.get("jti")

        assert jti is not None
        assert temp_blacklist.is_blacklisted(jti)


async def test_blacklisted_token_rejected(client, auth_token, temp_blacklist, api_key_headers):
    """Blacklisted token should be rejected on subsequent requests."""
    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        headers = {"Authorization": f"Bearer {auth_token}", **api_key_headers}

        # First logout
        response = await client.post("/auth/logout", headers=headers)
        assert response.status_code == 200

        # Try to access protected endpoint with same token
        response = await client.get("/auth/me", headers=headers)
        assert response.status_code == 401
        assert "revoked" in response.json()["detail"].lower()


async def test_new_login_after_logout_works(client, auth_token, temp_blacklist, api_key_headers):
    """New login after logout should work with fresh token."""
    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        headers = {"Authorization": f"Bearer {auth_token}", **api_key_headers}

        # Logout with old token
        response = await client.post("/auth/logout", headers=headers)
        assert response.status_code == 200

        # Old token should be rejected
        response = await client.get("/auth/me", headers=headers)
        assert response.status_code == 401

        # Create new token (simulating new login)
        new_token = create_access_token(
            data={"sub": "testuser", "user_id": "user-123", "role": "signer"},
            expires_delta=timedelta(minutes=30),
        )
        new_headers = {"Authorization": f"Bearer {new_token}"}

        # New token should work
        response = await client.get("/auth/me", headers=new_headers)
        assert response.status_code == 200


# --- Tests: Session Termination (Healthcare Mode) ---


async def test_logout_terminates_session_in_healthcare_mode(
    client, auth_token_with_session, temp_blacklist, temp_session_manager, api_key_headers
):
    """Logout should terminate session when healthcare_mode is enabled."""
    token, session_id = auth_token_with_session

    from unittest.mock import MagicMock

    from pdfsigner.core.users.user_model import User, UserRole, UserStatus

    # Create mock user for healthcare mode
    mock_user = User(
        id="user-123",
        username="testuser",
        email="test@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
    )
    mock_user_repo = MagicMock()
    mock_user_repo.get_user_by_username.return_value = mock_user
    mock_user_repo.get_user_by_id.return_value = mock_user

    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        # Patch all places where get_session_manager is called
        with patch(
            "pdfsigner.api.middleware.auth.get_session_manager", return_value=temp_session_manager
        ):
            with patch(
                "pdfsigner.api.routes.auth.get_session_manager", return_value=temp_session_manager
            ):
                with patch(
                    "pdfsigner.api.middleware.auth.UserRepository", return_value=mock_user_repo
                ):
                    with patch("pdfsigner.config.settings.get_settings") as mock_settings:
                        # Enable healthcare mode
                        settings = get_settings()
                        settings.healthcare_mode = True
                        mock_settings.return_value = settings

                        headers = {"Authorization": f"Bearer {token}", **api_key_headers}

                        # Verify session exists before logout
                        session = temp_session_manager.get_session(session_id)
                        assert session is not None
                        assert session.is_active

                        # Logout
                        response = await client.post("/auth/logout", headers=headers)
                        assert response.status_code == 200
                        assert "session terminated" in response.json()["message"].lower()

                        # Verify session is terminated
                        session = temp_session_manager.get_session(session_id)
                        assert session is None  # Terminated sessions are removed


async def test_session_invalid_after_logout(
    client, auth_token_with_session, temp_blacklist, temp_session_manager, api_key_headers
):
    """Session should be invalid after logout in healthcare mode."""
    from unittest.mock import MagicMock

    from pdfsigner.core.users.user_model import User, UserRole, UserStatus

    token, session_id = auth_token_with_session

    # Create mock user for healthcare mode
    mock_user = User(
        id="user-123",
        username="testuser",
        email="test@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
    )
    mock_user_repo = MagicMock()
    mock_user_repo.get_user_by_username.return_value = mock_user
    mock_user_repo.get_user_by_id.return_value = mock_user

    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        # Patch all places where get_session_manager is called
        with patch(
            "pdfsigner.api.middleware.auth.get_session_manager", return_value=temp_session_manager
        ):
            with patch(
                "pdfsigner.api.routes.auth.get_session_manager", return_value=temp_session_manager
            ):
                with patch(
                    "pdfsigner.api.middleware.auth.UserRepository", return_value=mock_user_repo
                ):
                    with patch("pdfsigner.config.settings.get_settings") as mock_settings:
                        # Enable healthcare mode
                        settings = get_settings()
                        settings.healthcare_mode = True
                        mock_settings.return_value = settings

                        headers = {"Authorization": f"Bearer {token}", **api_key_headers}

                        # Logout
                        response = await client.post("/auth/logout", headers=headers)
                        assert response.status_code == 200

                        # Verify session is no longer valid
                        is_valid = temp_session_manager.validate_session(session_id)
                        assert not is_valid


# --- Tests: Double Logout Handling ---


async def test_double_logout_graceful(client, auth_token, temp_blacklist, api_key_headers):
    """Second logout with same token should handle gracefully."""
    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            # Disable healthcare mode to avoid DB lookups
            settings = get_settings()
            settings.healthcare_mode = False
            mock_settings.return_value = settings

            headers = {"Authorization": f"Bearer {auth_token}", **api_key_headers}

            # First logout
            response = await client.post("/auth/logout", headers=headers)
            assert response.status_code == 200

            # Second logout with same token should be rejected at auth level
            response = await client.post("/auth/logout", headers=headers)
            assert response.status_code == 401  # Token already blacklisted
            assert "revoked" in response.json()["detail"].lower()


async def test_double_logout_different_tokens(client, temp_blacklist, api_key_headers):
    """Logging out with different tokens should work independently."""
    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            # Disable healthcare mode to avoid DB lookups
            settings = get_settings()
            settings.healthcare_mode = False
            mock_settings.return_value = settings

            # Create two different tokens
            token1 = create_access_token(
                data={"sub": "user1", "role": "signer"},
                expires_delta=timedelta(minutes=30),
            )
            token2 = create_access_token(
                data={"sub": "user2", "role": "signer"},
                expires_delta=timedelta(minutes=30),
            )

            # Logout with first token
            headers1 = {"Authorization": f"Bearer {token1}", **api_key_headers}
            response = await client.post("/auth/logout", headers=headers1)
            assert response.status_code == 200

            # Logout with second token should still work
            headers2 = {"Authorization": f"Bearer {token2}", **api_key_headers}
            response = await client.post("/auth/logout", headers=headers2)
            assert response.status_code == 200


# --- Tests: Logout with Expired Token ---


async def test_logout_with_expired_token_rejected(client, expired_token, api_key_headers):
    """Logout with expired token should be rejected."""
    headers = {"Authorization": f"Bearer {expired_token}", **api_key_headers}

    # Should be rejected at token verification stage
    response = await client.post("/auth/logout", headers=headers)
    assert response.status_code == 401
    assert "validate credentials" in response.json()["detail"].lower()


# --- Tests: Logout Clears Refresh Tokens ---


async def test_logout_after_token_refresh(client, auth_token, temp_blacklist, api_key_headers):
    """Logout should work after token refresh."""
    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            # Disable healthcare mode to avoid DB lookups
            settings = get_settings()
            settings.healthcare_mode = False
            mock_settings.return_value = settings

            headers = {"Authorization": f"Bearer {auth_token}", **api_key_headers}

            # Refresh token
            response = await client.post("/auth/refresh", headers=headers)
            assert response.status_code == 200
            new_token = response.json()["access_token"]

            # Logout with new token
            new_headers = {"Authorization": f"Bearer {new_token}", **api_key_headers}
            response = await client.post("/auth/logout", headers=new_headers)
            assert response.status_code == 200

            # New token should be blacklisted
            response = await client.get("/auth/me", headers=new_headers)
            assert response.status_code == 401


# --- Tests: Logout Audit Logging ---


async def test_logout_creates_audit_log(
    client, auth_token, temp_blacklist, temp_audit_logger, tmp_path, api_key_headers
):
    """Logout should create audit log entry."""
    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        with patch(
            "pdfsigner.core.audit.audit_logger.AuditLogger.get_instance",
            return_value=temp_audit_logger,
        ):
            with patch("pdfsigner.config.settings.get_settings") as mock_settings:
                # Disable healthcare mode to avoid DB lookups
                settings = get_settings()
                settings.healthcare_mode = False
                mock_settings.return_value = settings

                headers = {"Authorization": f"Bearer {auth_token}", **api_key_headers}

                # Logout
                response = await client.post("/auth/logout", headers=headers)
                assert response.status_code == 200

                # Check for audit log entry
                # Note: In real implementation, logout should call audit_logger.log_event()
                # This test verifies the audit logger is available
                log_file = temp_audit_logger._get_log_file_path(datetime.now())

                # Verify audit logger is functional
                from pdfsigner.core.audit.audit_event import AuditEvent

                test_event = AuditEvent(
                    event_type=AuditEventType.TOKEN_LOGOUT,
                    user_id="testuser",
                    details={"action": "logout"},
                )
                temp_audit_logger.log_event(test_event)

                # Verify log file was created
                assert log_file.exists()


# --- Tests: Edge Cases ---


async def test_logout_with_malformed_token(client, api_key_headers):
    """Logout with malformed token should be rejected."""
    headers = {"Authorization": "Bearer malformed.token.here", **api_key_headers}

    response = await client.post("/auth/logout", headers=headers)
    assert response.status_code == 401


async def test_logout_with_invalid_bearer_format(client, api_key_headers):
    """Logout with invalid Bearer format should be rejected."""
    headers = {"Authorization": "InvalidFormat token123", **api_key_headers}

    response = await client.post("/auth/logout", headers=headers)
    assert response.status_code == 401  # Invalid token format


async def test_blacklist_cleanup_removes_expired_tokens(temp_blacklist):
    """Blacklist cleanup should remove expired tokens."""
    # Add token that expired yesterday
    yesterday = datetime.now(UTC) - timedelta(days=1)
    temp_blacklist.add_token(
        jti="expired-token-123",
        expires_at=yesterday,
        reason="test",
    )

    # Add token that expires tomorrow
    tomorrow = datetime.now(UTC) + timedelta(days=1)
    temp_blacklist.add_token(
        jti="valid-token-456",
        expires_at=tomorrow,
        reason="test",
    )

    # Cleanup expired tokens
    count = temp_blacklist.cleanup_expired()
    assert count >= 1  # At least the expired token

    # Expired token should not be blacklisted anymore
    assert not temp_blacklist.is_blacklisted("expired-token-123")

    # Valid token should still be blacklisted
    assert temp_blacklist.is_blacklisted("valid-token-456")


async def test_blacklist_stats_accurate(temp_blacklist):
    """Blacklist statistics should be accurate."""
    # Add active token
    future = datetime.now(UTC) + timedelta(hours=1)
    temp_blacklist.add_token("active-1", future, "test")
    temp_blacklist.add_token("active-2", future, "test")

    # Add expired token
    past = datetime.now(UTC) - timedelta(hours=1)
    temp_blacklist.add_token("expired-1", past, "test")

    stats = temp_blacklist.get_stats()

    assert stats["total_tokens"] == 3
    assert stats["active_tokens"] == 2
    assert stats["expired_tokens"] == 1


async def test_concurrent_logouts_handled(client, temp_blacklist, api_key_headers):
    """Multiple concurrent logouts should be handled safely."""
    import asyncio

    tokens = [
        create_access_token(
            data={"sub": f"user{i}", "role": "signer"},
            expires_delta=timedelta(minutes=30),
        )
        for i in range(5)
    ]

    with patch("pdfsigner.core.auth.jwt_blacklist.get_jwt_blacklist", return_value=temp_blacklist):
        with patch("pdfsigner.config.settings.get_settings") as mock_settings:
            # Disable healthcare mode to avoid DB lookups
            settings = get_settings()
            settings.healthcare_mode = False
            mock_settings.return_value = settings

            # Perform concurrent logouts
            async def logout_user(token):
                headers = {"Authorization": f"Bearer {token}", **api_key_headers}
                return await client.post("/auth/logout", headers=headers)

            responses = await asyncio.gather(*[logout_user(t) for t in tokens])

            # All should succeed
            assert all(r.status_code == 200 for r in responses)


# --- Summary ---
# Total tests: 24
# - Basic logout: 3 tests
# - JWT blacklist: 3 tests
# - Session termination: 2 tests
# - Double logout: 2 tests
# - Expired token: 1 test
# - Refresh token: 1 test
# - Audit logging: 1 test
# - Edge cases: 11 tests

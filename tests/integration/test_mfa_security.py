"""
Integration tests for MFA security features.

Tests password verification when disabling MFA.
"""

import pytest

from pdfsigner.api.middleware.auth import create_access_token
from pdfsigner.core.auth.mfa import get_mfa_manager
from pdfsigner.core.auth.password_validator import get_password_validator
from pdfsigner.core.users.user_model import User, UserRole, UserStatus
from pdfsigner.core.users.user_repository import UserRepository

# Mark all tests in this module as anyio
pytestmark = pytest.mark.anyio


@pytest.fixture
def test_user_with_password(tmp_path):
    """Create a test user with password set."""
    # Create user repository
    user_repo = UserRepository(db_path=tmp_path / "users.db")

    # Create user
    user = User(
        username="mfatestuser",
        display_name="MFA Test User",
        email="mfatest@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
    )
    created_user = user_repo.create_user(user)

    # Set password
    password_validator = get_password_validator()
    password_hash = password_validator.hash_password("TestPassword123!")
    user_repo.set_password(created_user.id, password_hash)

    return created_user, "TestPassword123!"


@pytest.fixture
def mfa_enabled_user(test_user_with_password):
    """Create a test user with MFA enabled."""
    user, password = test_user_with_password
    mfa_manager = get_mfa_manager()

    # Enroll MFA
    enrollment = mfa_manager.enroll(user.id, user.email or user.username)

    # Generate a TOTP code and verify to activate MFA
    import pyotp

    totp = pyotp.TOTP(enrollment.secret)
    code = totp.now()
    mfa_manager.verify_and_activate(user.id, code)

    return user, password


@pytest.fixture
def user_auth_headers(mfa_enabled_user):
    """Create authentication headers with JWT token for the test user."""
    user, password = mfa_enabled_user
    token = create_access_token({"sub": user.username, "user_id": user.id, "role": user.role.value})
    return {"Authorization": f"Bearer {token}", "X-API-Key": "test-api-key-123"}


class TestMFADisableSecurity:
    """Test MFA disable security features."""

    async def test_disable_mfa_requires_password(self, client, user_auth_headers, mfa_enabled_user):
        """Test that disabling MFA requires a password."""
        user, password = mfa_enabled_user

        # Try to disable MFA without password (should fail with 422 validation error)
        response = await client.post(
            "/api/v1/mfa/disable",
            json={},
            headers=user_auth_headers,
        )
        assert response.status_code == 422  # Validation error

    async def test_disable_mfa_with_correct_password(
        self, client, user_auth_headers, mfa_enabled_user
    ):
        """Test that disabling MFA succeeds with correct password."""
        user, password = mfa_enabled_user

        # Disable MFA with correct password
        response = await client.post(
            "/api/v1/mfa/disable",
            json={"current_password": password},
            headers=user_auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "disabled successfully" in data["message"].lower()

        # Verify MFA is disabled
        mfa_manager = get_mfa_manager()
        status = mfa_manager.get_status(user.id)
        assert status.enabled is False

    async def test_disable_mfa_with_incorrect_password(
        self, client, user_auth_headers, mfa_enabled_user
    ):
        """Test that disabling MFA fails with incorrect password."""
        user, password = mfa_enabled_user

        # Try to disable MFA with wrong password
        response = await client.post(
            "/api/v1/mfa/disable",
            json={"current_password": "WrongPassword123!"},
            headers=user_auth_headers,
        )
        assert response.status_code == 401
        data = response.json()
        assert "incorrect password" in data["detail"].lower()

        # Verify MFA is still enabled
        mfa_manager = get_mfa_manager()
        status = mfa_manager.get_status(user.id)
        assert status.enabled is True

    async def test_disable_mfa_without_password_set(self, client, tmp_path):
        """Test that disabling MFA fails if user has no password set."""
        # Create user without password
        user_repo = UserRepository(db_path=tmp_path / "users_no_pw.db")
        user = User(
            username="nopwuser",
            display_name="No Password User",
            email="nopw@example.com",
            role=UserRole.SIGNER,
            status=UserStatus.ACTIVE,
        )
        created_user = user_repo.create_user(user)

        # Enable MFA
        mfa_manager = get_mfa_manager()
        enrollment = mfa_manager.enroll(
            created_user.id, created_user.email or created_user.username
        )

        import pyotp

        totp = pyotp.TOTP(enrollment.secret)
        code = totp.now()
        mfa_manager.verify_and_activate(created_user.id, code)

        # Create JWT token for user
        token = create_access_token(
            {
                "sub": created_user.username,
                "user_id": created_user.id,
                "role": created_user.role.value,
            }
        )

        # Try to disable MFA
        response = await client.post(
            "/api/v1/mfa/disable",
            json={"current_password": "anypassword"},
            headers={"Authorization": f"Bearer {token}", "X-API-Key": "test-api-key-123"},
        )
        assert response.status_code == 401
        data = response.json()
        assert "does not have a password set" in data["detail"].lower()

    async def test_disable_mfa_logs_failed_attempts(
        self, client, user_auth_headers, mfa_enabled_user, caplog
    ):
        """Test that failed password attempts are logged."""
        user, password = mfa_enabled_user

        # Try to disable MFA with wrong password
        with caplog.at_level("WARNING"):
            response = await client.post(
                "/api/v1/mfa/disable",
                json={"current_password": "WrongPassword123!"},
                headers=user_auth_headers,
            )

        assert response.status_code == 401

        # Check that the failure was logged
        assert any(
            "Failed MFA disable attempt" in record.message and user.username in record.message
            for record in caplog.records
        )

    async def test_disable_mfa_when_not_enabled(self, client, test_user_with_password):
        """Test that disabling MFA fails when MFA is not enabled."""
        user, password = test_user_with_password

        # Create JWT token for user
        token = create_access_token(
            {"sub": user.username, "user_id": user.id, "role": user.role.value}
        )

        # Try to disable MFA when it's not enabled
        response = await client.post(
            "/api/v1/mfa/disable",
            json={"current_password": password},
            headers={"Authorization": f"Bearer {token}", "X-API-Key": "test-api-key-123"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "not enabled" in data["detail"].lower()


class TestMFADisableFieldValidation:
    """Test field validation for MFA disable request."""

    async def test_current_password_is_required(self, client, user_auth_headers, mfa_enabled_user):
        """Test that current_password field is required."""
        user, password = mfa_enabled_user

        # Try without current_password field
        response = await client.post(
            "/api/v1/mfa/disable",
            json={},
            headers=user_auth_headers,
        )
        assert response.status_code == 422
        data = response.json()
        assert "current_password" in str(data["detail"]).lower()

    async def test_current_password_must_be_string(
        self, client, user_auth_headers, mfa_enabled_user
    ):
        """Test that current_password must be a string."""
        user, password = mfa_enabled_user

        # Try with non-string current_password
        response = await client.post(
            "/api/v1/mfa/disable",
            json={"current_password": 123456},
            headers=user_auth_headers,
        )
        assert response.status_code == 422

    async def test_current_password_cannot_be_null(
        self, client, user_auth_headers, mfa_enabled_user
    ):
        """Test that current_password cannot be null."""
        user, password = mfa_enabled_user

        # Try with null current_password
        response = await client.post(
            "/api/v1/mfa/disable",
            json={"current_password": None},
            headers=user_auth_headers,
        )
        assert response.status_code == 422

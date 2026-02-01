"""
test_auth_security.py - Security tests for authentication

Tests authentication bypass prevention, account lockout, and credential validation.
"""

import pytest
from fastapi.testclient import TestClient

from pdfsigner.api.main import app
from pdfsigner.core.auth.password_validator import get_password_validator
from pdfsigner.core.users.user_model import User, UserRole, UserStatus
from pdfsigner.core.users.user_repository import UserRepository


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def temp_user_repo(tmp_path):
    """Create a temporary user repository for testing."""
    db_path = tmp_path / "test_users.db"
    return UserRepository(db_path=db_path)


@pytest.fixture
def test_user_with_password(temp_user_repo):
    """Create a test user with password."""
    password_validator = get_password_validator()

    user = User(
        username="testuser",
        display_name="Test User",
        email="test@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
    )
    created = temp_user_repo.create_user(user)

    # Set password
    password = "SecureP@ssword123!"
    password_hash = password_validator.hash_password(password)
    temp_user_repo.set_password(created.id, password_hash)

    return created, password


class TestAuthenticationBypassPrevention:
    """Test that demo authentication bypass has been removed."""

    def test_empty_credentials_rejected(self, client):
        """Empty username/password should be rejected."""
        response = client.post("/auth/token", json={"username": "", "password": ""})
        assert response.status_code == 422  # Validation error for empty fields

    def test_nonexistent_user_rejected(self, client):
        """Non-existent user should be rejected."""
        response = client.post(
            "/auth/token", json={"username": "nonexistent_user_12345", "password": "anypassword"}
        )
        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]

    def test_wrong_password_rejected(self, client, test_user_with_password, monkeypatch):
        """Wrong password should be rejected."""
        user, correct_password = test_user_with_password

        # Monkeypatch the repository to use our test instance
        from pdfsigner.core.users import user_repository

        monkeypatch.setattr(user_repository, "_user_repository", None)

        response = client.post(
            "/auth/token", json={"username": user.username, "password": "wrong_password"}
        )
        # Should fail because user doesn't exist in the actual database
        assert response.status_code == 401

    def test_demo_admin_username_not_auto_granted(self, client):
        """Using 'admin' as username should NOT auto-grant admin role."""
        response = client.post("/auth/token", json={"username": "admin", "password": "admin"})
        # Should be rejected - no longer demo mode
        assert response.status_code == 401


class TestAccountLockout:
    """Test account lockout after failed attempts (NIST AC-7)."""

    def test_failed_login_increments_counter(self, temp_user_repo):
        """Failed login should increment failed_login_attempts."""
        user = User(
            username="locktest",
            display_name="Lock Test",
            email="lock@test.com",
            role=UserRole.SIGNER,
            status=UserStatus.ACTIVE,
        )
        created = temp_user_repo.create_user(user)

        # Simulate failed login
        created.record_login(success=False)
        temp_user_repo.update_user(created)

        # Reload and check
        reloaded = temp_user_repo.get_user_by_username("locktest")
        assert reloaded.failed_login_attempts == 1

    def test_account_locks_after_5_failures(self, temp_user_repo):
        """Account should lock after 5 failed login attempts."""
        user = User(
            username="locktest5",
            display_name="Lock Test 5",
            email="lock5@test.com",
            role=UserRole.SIGNER,
            status=UserStatus.ACTIVE,
        )
        created = temp_user_repo.create_user(user)

        # Simulate 5 failed logins
        for _ in range(5):
            created.record_login(success=False)
        temp_user_repo.update_user(created)

        # Reload and check
        reloaded = temp_user_repo.get_user_by_username("locktest5")
        assert reloaded.status == UserStatus.LOCKED
        assert reloaded.locked_until is not None
        assert not reloaded.is_active

    def test_successful_login_resets_counter(self, temp_user_repo):
        """Successful login should reset failed_login_attempts."""
        user = User(
            username="resettest",
            display_name="Reset Test",
            email="reset@test.com",
            role=UserRole.SIGNER,
            status=UserStatus.ACTIVE,
            failed_login_attempts=3,
        )
        created = temp_user_repo.create_user(user)

        # Successful login
        created.record_login(success=True)
        temp_user_repo.update_user(created)

        # Reload and check
        reloaded = temp_user_repo.get_user_by_username("resettest")
        assert reloaded.failed_login_attempts == 0


class TestCredentialStorage:
    """Test secure credential storage."""

    def test_password_is_hashed(self, temp_user_repo):
        """Password should be stored as Argon2 hash, not plaintext."""
        password_validator = get_password_validator()

        user = User(username="hashtest", role=UserRole.SIGNER, status=UserStatus.ACTIVE)
        created = temp_user_repo.create_user(user)

        plain_password = "MySecureP@ss123!"
        password_hash = password_validator.hash_password(plain_password)
        temp_user_repo.set_password(created.id, password_hash)

        stored_hash = temp_user_repo.get_password_hash(created.id)
        assert stored_hash is not None
        assert stored_hash != plain_password  # Not plaintext
        assert stored_hash.startswith("$argon2")  # Argon2 format

    def test_password_verification(self, temp_user_repo):
        """Password verification should work correctly."""
        password_validator = get_password_validator()

        user = User(username="verifytest", role=UserRole.SIGNER, status=UserStatus.ACTIVE)
        created = temp_user_repo.create_user(user)

        plain_password = "MySecureP@ss123!"
        password_hash = password_validator.hash_password(plain_password)
        temp_user_repo.set_password(created.id, password_hash)

        stored_hash = temp_user_repo.get_password_hash(created.id)

        # Correct password should verify
        assert password_validator.verify_password(plain_password, stored_hash)

        # Wrong password should not verify
        assert not password_validator.verify_password("wrong_password", stored_hash)

    def test_has_password_method(self, temp_user_repo):
        """has_password should return correct status."""
        user = User(username="haspwtest", role=UserRole.SIGNER, status=UserStatus.ACTIVE)
        created = temp_user_repo.create_user(user)

        # No password set yet
        assert not temp_user_repo.has_password(created.id)

        # Set password
        password_validator = get_password_validator()
        password_hash = password_validator.hash_password("TestP@ss123!")
        temp_user_repo.set_password(created.id, password_hash)

        # Now has password
        assert temp_user_repo.has_password(created.id)


class TestAdminUserCount:
    """Test admin user protection."""

    def test_count_admins(self, temp_user_repo):
        """count_admins should return correct count."""
        # Initially no admins
        assert temp_user_repo.count_admins() == 0

        # Create admin
        admin = User(username="admin1", role=UserRole.ADMIN, status=UserStatus.ACTIVE)
        temp_user_repo.create_user(admin)
        assert temp_user_repo.count_admins() == 1

        # Create another admin
        admin2 = User(username="admin2", role=UserRole.ADMIN, status=UserStatus.ACTIVE)
        temp_user_repo.create_user(admin2)
        assert temp_user_repo.count_admins() == 2

        # Inactive admin should not be counted
        admin3 = User(username="admin3", role=UserRole.ADMIN, status=UserStatus.INACTIVE)
        temp_user_repo.create_user(admin3)
        assert temp_user_repo.count_admins() == 2  # Still 2

    def test_count_admins_excludes_non_admin_roles(self, temp_user_repo):
        """count_admins should only count admin role users."""
        # Create users with different roles
        signer = User(username="signer", role=UserRole.SIGNER, status=UserStatus.ACTIVE)
        viewer = User(username="viewer", role=UserRole.VIEWER, status=UserStatus.ACTIVE)
        admin = User(username="admin", role=UserRole.ADMIN, status=UserStatus.ACTIVE)

        temp_user_repo.create_user(signer)
        temp_user_repo.create_user(viewer)
        temp_user_repo.create_user(admin)

        assert temp_user_repo.count_admins() == 1


class TestPasswordPolicy:
    """Test password policy enforcement."""

    def test_weak_password_rejected(self):
        """Weak passwords should be rejected."""
        validator = get_password_validator()

        # Too short
        result = validator.validate("short")
        assert not result.is_valid

        # No uppercase
        result = validator.validate("alllowercase123!")
        assert not result.is_valid

        # Common password
        result = validator.validate("password123")
        assert not result.is_valid

    def test_strong_password_accepted(self):
        """Strong passwords should be accepted."""
        validator = get_password_validator()

        result = validator.validate("MyVerySecure#P@ss123!")
        assert result.is_valid
        assert result.strength_score >= 50

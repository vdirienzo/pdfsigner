"""Tests for user models."""

from datetime import datetime, timedelta

from pdfsigner.core.users import (
    Department,
    User,
    UserRole,
    UserStatus,
)


class TestUserRole:
    """Tests for UserRole enum."""

    def test_all_roles_defined(self):
        """Test all expected roles exist."""
        assert UserRole.VIEWER.value == "viewer"
        assert UserRole.SIGNER.value == "signer"
        assert UserRole.ADMIN.value == "admin"
        assert UserRole.AUDITOR.value == "auditor"
        assert UserRole.EMERGENCY.value == "emergency"

    def test_role_count(self):
        """Test number of roles."""
        assert len(UserRole) == 5


class TestUserStatus:
    """Tests for UserStatus enum."""

    def test_all_statuses_defined(self):
        """Test all expected statuses exist."""
        assert UserStatus.ACTIVE.value == "active"
        assert UserStatus.INACTIVE.value == "inactive"
        assert UserStatus.LOCKED.value == "locked"
        assert UserStatus.PENDING.value == "pending"


class TestUser:
    """Tests for User dataclass."""

    def test_create_user_defaults(self):
        """Test user creation with defaults."""
        user = User(username="testuser")

        assert user.username == "testuser"
        assert user.role == UserRole.VIEWER
        assert user.status == UserStatus.ACTIVE
        assert user.id is not None
        assert len(user.id) == 36  # UUID format

    def test_user_is_active_when_active_status(self):
        """Test is_active returns True for active user."""
        user = User(username="test", status=UserStatus.ACTIVE)

        assert user.is_active is True

    def test_user_is_not_active_when_inactive(self):
        """Test is_active returns False for inactive user."""
        user = User(username="test", status=UserStatus.INACTIVE)

        assert user.is_active is False

    def test_user_is_not_active_when_locked(self):
        """Test is_active returns False when locked."""
        user = User(
            username="test",
            status=UserStatus.LOCKED,
            locked_until=datetime.now() + timedelta(hours=1),
        )

        assert user.is_active is False

    def test_user_is_admin(self):
        """Test is_admin property."""
        admin = User(username="admin", role=UserRole.ADMIN)
        user = User(username="user", role=UserRole.VIEWER)

        assert admin.is_admin is True
        assert user.is_admin is False

    def test_lock_user(self):
        """Test user lock functionality."""
        user = User(username="test")
        user.lock(duration_minutes=60)

        assert user.status == UserStatus.LOCKED
        assert user.locked_until is not None
        assert user.locked_until > datetime.now()

    def test_unlock_user(self):
        """Test user unlock functionality."""
        user = User(username="test", status=UserStatus.LOCKED)
        user.lock()
        user.unlock()

        assert user.status == UserStatus.ACTIVE
        assert user.locked_until is None
        assert user.failed_login_attempts == 0

    def test_record_login_success(self):
        """Test successful login recording."""
        user = User(username="test", failed_login_attempts=3)
        user.record_login(success=True)

        assert user.last_login_at is not None
        assert user.failed_login_attempts == 0

    def test_record_login_failure_increments_attempts(self):
        """Test failed login increments counter."""
        user = User(username="test")
        user.record_login(success=False)

        assert user.failed_login_attempts == 1

    def test_auto_lock_after_5_failures(self):
        """Test automatic lock after 5 failed attempts."""
        user = User(username="test")

        for _ in range(5):
            user.record_login(success=False)

        assert user.failed_login_attempts == 5
        assert user.status == UserStatus.LOCKED
        assert user.locked_until is not None

    def test_to_dict_serialization(self):
        """Test user serialization to dict."""
        user = User(
            username="testuser",
            display_name="Test User",
            email="test@example.com",
            role=UserRole.SIGNER,
        )

        data = user.to_dict()

        assert data["username"] == "testuser"
        assert data["role"] == "signer"
        assert data["status"] == "active"
        assert "id" in data
        assert "created_at" in data

    def test_from_dict_deserialization(self):
        """Test user deserialization from dict."""
        data = {
            "username": "restored",
            "display_name": "Restored User",
            "role": "admin",
            "status": "active",
        }

        user = User.from_dict(data)

        assert user.username == "restored"
        assert user.role == UserRole.ADMIN
        assert user.status == UserStatus.ACTIVE

    def test_from_certificate_factory(self):
        """Test user creation from certificate."""
        user = User.from_certificate(
            serial="ABC123",
            issuer="CN=Test CA",
            common_name="John Doe",
            email="john@example.com",
        )

        assert user.username == "john.doe"
        assert user.display_name == "John Doe"
        assert user.certificate_serial == "ABC123"
        assert user.certificate_issuer == "CN=Test CA"
        assert user.role == UserRole.SIGNER


class TestDepartment:
    """Tests for Department dataclass."""

    def test_create_department(self):
        """Test department creation."""
        dept = Department(name="IT", code="IT")

        assert dept.name == "IT"
        assert dept.code == "IT"
        assert dept.id is not None

    def test_to_dict_serialization(self):
        """Test department serialization."""
        dept = Department(name="HR", code="HR", description="Human Resources")

        data = dept.to_dict()

        assert data["name"] == "HR"
        assert data["code"] == "HR"
        assert data["description"] == "Human Resources"

    def test_from_dict_deserialization(self):
        """Test department deserialization."""
        data = {"name": "Finance", "code": "FIN"}

        dept = Department.from_dict(data)

        assert dept.name == "Finance"
        assert dept.code == "FIN"

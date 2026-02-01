"""Tests for certificate binding service."""

import pytest

from pdfsigner.core.users import (
    CertificateBindingService,
    User,
    UserRepository,
    UserRole,
)


class TestCertificateBindingService:
    """Tests for CertificateBindingService."""

    @pytest.fixture
    def repo(self, tmp_path):
        """Create test repository."""
        return UserRepository(db_path=tmp_path / "test.db")

    @pytest.fixture
    def service(self, repo):
        """Create binding service with test repo."""
        return CertificateBindingService(repository=repo)

    def test_get_user_by_certificate_not_found(self, service):
        """Test get user returns None when not found."""
        user = service.get_user_by_certificate("nonexistent", "issuer")

        assert user is None

    def test_bind_certificate_to_user(self, service, repo):
        """Test binding certificate to existing user."""
        # Create user first
        user = User(username="testuser")
        repo.create_user(user)

        # Bind certificate
        updated = service.bind_certificate_to_user(
            user_id=user.id,
            serial="CERT123",
            issuer="CN=TestCA",
            common_name="Test User",
        )

        assert updated is not None
        assert updated.certificate_serial == "CERT123"
        assert updated.certificate_issuer == "CN=TestCA"

    def test_bind_certificate_user_not_found(self, service):
        """Test binding fails if user not found."""
        result = service.bind_certificate_to_user(
            user_id="nonexistent",
            serial="CERT",
            issuer="CA",
            common_name="Test",
        )

        assert result is None

    def test_unbind_certificate(self, service, repo):
        """Test unbinding certificate from user."""
        user = User.from_certificate("CERT", "CA", "Test")
        repo.create_user(user)

        success = service.unbind_certificate(user.id)

        assert success is True

        updated = repo.get_user_by_id(user.id)
        assert updated.certificate_serial is None

    def test_get_or_create_user_existing(self, service, repo):
        """Test get_or_create returns existing user."""
        existing = User.from_certificate("CERT123", "CA", "Existing")
        repo.create_user(existing)

        user = service.get_or_create_user_for_certificate(
            serial="CERT123",
            issuer="CA",
            common_name="Existing",
        )

        assert user is not None
        assert user.id == existing.id

    def test_get_or_create_user_creates_new(self, service, repo):
        """Test get_or_create creates new user."""
        user = service.get_or_create_user_for_certificate(
            serial="NEWCERT",
            issuer="CN=NewCA",
            common_name="New User",
            email="new@example.com",
        )

        assert user is not None
        assert user.certificate_serial == "NEWCERT"
        assert user.role == UserRole.SIGNER

        # Verify persisted
        found = repo.get_user_by_id(user.id)
        assert found is not None

    def test_get_or_create_no_auto_create(self, service):
        """Test get_or_create with auto_create=False."""
        user = service.get_or_create_user_for_certificate(
            serial="CERT",
            issuer="CA",
            common_name="Test",
            auto_create=False,
        )

        assert user is None

    def test_generate_unique_username(self, service, repo):
        """Test unique username generation."""
        repo.create_user(User(username="john.doe"))

        user = service.get_or_create_user_for_certificate(
            serial="CERT",
            issuer="CA",
            common_name="John Doe",
        )

        assert user.username == "john.doe1"

    def test_record_login_success(self, service, repo):
        """Test recording successful login."""
        user = User.from_certificate("CERT", "CA", "Test")
        repo.create_user(user)

        updated = service.record_login_for_certificate("CERT", "CA", success=True)

        assert updated is not None
        assert updated.last_login_at is not None
        assert updated.failed_login_attempts == 0

    def test_record_login_failure(self, service, repo):
        """Test recording failed login."""
        user = User.from_certificate("CERT", "CA", "Test")
        repo.create_user(user)

        updated = service.record_login_for_certificate("CERT", "CA", success=False)

        assert updated.failed_login_attempts == 1

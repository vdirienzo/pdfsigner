"""Tests for user repository."""


import pytest

from pdfsigner.core.users import (
    Department,
    User,
    UserRepository,
    UserRole,
    UserStatus,
)


class TestUserRepository:
    """Tests for UserRepository class."""

    @pytest.fixture
    def repo(self, tmp_path):
        """Create repository with temp database."""
        db_path = tmp_path / "test_users.db"
        return UserRepository(db_path=db_path)

    @pytest.fixture
    def sample_user(self):
        """Create sample user."""
        return User(
            username="testuser",
            display_name="Test User",
            email="test@example.com",
            role=UserRole.SIGNER,
        )

    def test_create_user_success(self, repo, sample_user):
        """Test successful user creation."""
        created = repo.create_user(sample_user)

        assert created.id == sample_user.id
        assert created.username == "testuser"

    def test_create_user_duplicate_username_fails(self, repo, sample_user):
        """Test duplicate username raises error."""
        repo.create_user(sample_user)

        duplicate = User(username="testuser")
        with pytest.raises(ValueError, match="already exists"):
            repo.create_user(duplicate)

    def test_get_user_by_id(self, repo, sample_user):
        """Test get user by ID."""
        repo.create_user(sample_user)

        found = repo.get_user_by_id(sample_user.id)

        assert found is not None
        assert found.username == "testuser"

    def test_get_user_by_id_not_found(self, repo):
        """Test get non-existent user returns None."""
        found = repo.get_user_by_id("nonexistent")

        assert found is None

    def test_get_user_by_username(self, repo, sample_user):
        """Test get user by username."""
        repo.create_user(sample_user)

        found = repo.get_user_by_username("testuser")

        assert found is not None
        assert found.id == sample_user.id

    def test_get_user_by_certificate(self, repo):
        """Test get user by certificate."""
        user = User.from_certificate(
            serial="ABC123",
            issuer="CN=Test",
            common_name="Cert User",
        )
        repo.create_user(user)

        found = repo.get_user_by_certificate("ABC123", "CN=Test")

        assert found is not None
        assert found.certificate_cn == "Cert User"

    def test_update_user(self, repo, sample_user):
        """Test user update."""
        repo.create_user(sample_user)

        sample_user.display_name = "Updated Name"
        sample_user.role = UserRole.ADMIN
        repo.update_user(sample_user)

        found = repo.get_user_by_id(sample_user.id)
        assert found.display_name == "Updated Name"
        assert found.role == UserRole.ADMIN

    def test_delete_user(self, repo, sample_user):
        """Test user deletion."""
        repo.create_user(sample_user)

        deleted = repo.delete_user(sample_user.id)

        assert deleted is True
        assert repo.get_user_by_id(sample_user.id) is None

    def test_deactivate_user(self, repo, sample_user):
        """Test user deactivation (soft delete)."""
        repo.create_user(sample_user)

        repo.deactivate_user(sample_user.id)

        found = repo.get_user_by_id(sample_user.id)
        assert found.status == UserStatus.INACTIVE

    def test_list_users_all(self, repo):
        """Test list all users."""
        for i in range(3):
            repo.create_user(User(username=f"user{i}"))

        users = repo.list_users()

        assert len(users) == 3

    def test_list_users_filter_by_role(self, repo):
        """Test list users filtered by role."""
        repo.create_user(User(username="admin1", role=UserRole.ADMIN))
        repo.create_user(User(username="user1", role=UserRole.VIEWER))
        repo.create_user(User(username="admin2", role=UserRole.ADMIN))

        admins = repo.list_users(role=UserRole.ADMIN)

        assert len(admins) == 2
        assert all(u.role == UserRole.ADMIN for u in admins)

    def test_list_users_pagination(self, repo):
        """Test list users with pagination."""
        for i in range(10):
            repo.create_user(User(username=f"user{i}"))

        page1 = repo.list_users(limit=5, offset=0)
        page2 = repo.list_users(limit=5, offset=5)

        assert len(page1) == 5
        assert len(page2) == 5

    def test_count_users(self, repo):
        """Test user count."""
        for i in range(5):
            repo.create_user(User(username=f"user{i}"))

        count = repo.count_users()

        assert count == 5


class TestDepartmentRepository:
    """Tests for department operations."""

    @pytest.fixture
    def repo(self, tmp_path):
        """Create repository."""
        return UserRepository(db_path=tmp_path / "test.db")

    def test_create_department(self, repo):
        """Test department creation."""
        dept = Department(name="IT", code="IT")

        created = repo.create_department(dept)

        assert created.id == dept.id

    def test_get_department_by_id(self, repo):
        """Test get department."""
        dept = Department(name="HR", code="HR")
        repo.create_department(dept)

        found = repo.get_department_by_id(dept.id)

        assert found is not None
        assert found.name == "HR"

    def test_list_departments(self, repo):
        """Test list departments."""
        repo.create_department(Department(name="IT", code="IT"))
        repo.create_department(Department(name="HR", code="HR"))

        depts = repo.list_departments()

        assert len(depts) == 2

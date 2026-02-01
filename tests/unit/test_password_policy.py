"""Tests for password policy and validation."""

import pytest

from pdfsigner.core.auth import (
    PasswordHistoryRepository,
    PasswordPolicy,
    PasswordValidator,
    ValidationResult,
)


class TestPasswordPolicy:
    """Tests for PasswordPolicy configuration."""

    def test_default_policy_creation(self):
        """Test creating policy with default values."""
        policy = PasswordPolicy()

        assert policy.min_length == 12
        assert policy.max_length == 128
        assert policy.require_uppercase is True
        assert policy.require_lowercase is True
        assert policy.require_digits is True
        assert policy.require_special is True
        assert policy.max_age_days == 90
        assert policy.history_count == 12
        assert policy.lockout_threshold == 5
        assert policy.lockout_duration_minutes == 30
        assert policy.min_unique_chars == 8

    def test_custom_policy_creation(self):
        """Test creating policy with custom values."""
        policy = PasswordPolicy(
            min_length=16,
            max_age_days=60,
            history_count=24,
            lockout_threshold=3,
        )

        assert policy.min_length == 16
        assert policy.max_age_days == 60
        assert policy.history_count == 24
        assert policy.lockout_threshold == 3

    def test_policy_min_length_validation_fails(self):
        """Test policy validation fails for invalid min_length."""
        with pytest.raises(ValueError, match="min_length must be at least 8"):
            PasswordPolicy(min_length=6)

    def test_policy_max_length_validation_fails(self):
        """Test policy validation fails when max_length < min_length."""
        with pytest.raises(ValueError, match="max_length must be >= min_length"):
            PasswordPolicy(min_length=20, max_length=10)

    def test_policy_max_age_validation_fails(self):
        """Test policy validation fails for negative max_age_days."""
        with pytest.raises(ValueError, match="max_age_days must be positive"):
            PasswordPolicy(max_age_days=0)

    def test_policy_history_count_validation_fails(self):
        """Test policy validation fails for negative history_count."""
        with pytest.raises(ValueError, match="history_count cannot be negative"):
            PasswordPolicy(history_count=-1)

    def test_policy_lockout_threshold_validation_fails(self):
        """Test policy validation fails for invalid lockout_threshold."""
        with pytest.raises(ValueError, match="lockout_threshold must be positive"):
            PasswordPolicy(lockout_threshold=0)


class TestPasswordValidator:
    """Tests for PasswordValidator class."""

    @pytest.fixture
    def validator(self, tmp_path):
        """Create validator with temp database."""
        db_path = tmp_path / "test_password_history.db"
        repo = PasswordHistoryRepository(db_path=db_path)
        policy = PasswordPolicy()
        return PasswordValidator(policy=policy, history_repo=repo)

    @pytest.fixture
    def lenient_validator(self, tmp_path):
        """Create validator with lenient policy (for testing specific rules)."""
        db_path = tmp_path / "test_password_history.db"
        repo = PasswordHistoryRepository(db_path=db_path)
        policy = PasswordPolicy(
            min_length=8,
            require_uppercase=False,
            require_lowercase=False,
            require_digits=False,
            require_special=False,
            min_unique_chars=4,
        )
        return PasswordValidator(policy=policy, history_repo=repo)

    def test_validate_strong_password_success(self, validator):
        """Test validation of strong password succeeds."""
        result = validator.validate("MyStr0ng!P@ssw0rd")

        assert result.is_valid is True
        assert len(result.errors) == 0
        assert result.strength_score > 60

    def test_validate_too_short_fails(self, validator):
        """Test validation fails for password too short."""
        result = validator.validate("Short1!")

        assert result.is_valid is False
        assert any("at least 12 characters" in err for err in result.errors)

    def test_validate_too_long_fails(self, validator):
        """Test validation fails for password too long."""
        long_password = "A" * 200
        result = validator.validate(long_password)

        assert result.is_valid is False
        assert any("must not exceed 128 characters" in err for err in result.errors)

    def test_validate_missing_uppercase_fails(self, validator):
        """Test validation fails when uppercase is missing."""
        result = validator.validate("mypassword123!")

        assert result.is_valid is False
        assert any("uppercase letter" in err for err in result.errors)

    def test_validate_missing_lowercase_fails(self, validator):
        """Test validation fails when lowercase is missing."""
        result = validator.validate("MYPASSWORD123!")

        assert result.is_valid is False
        assert any("lowercase letter" in err for err in result.errors)

    def test_validate_missing_digit_fails(self, validator):
        """Test validation fails when digit is missing."""
        result = validator.validate("MyPassword!@#")

        assert result.is_valid is False
        assert any("digit" in err for err in result.errors)

    def test_validate_missing_special_fails(self, validator):
        """Test validation fails when special character is missing."""
        result = validator.validate("MyPassword123")

        assert result.is_valid is False
        assert any("special character" in err for err in result.errors)

    def test_validate_insufficient_unique_chars_fails(self, validator):
        """Test validation fails with insufficient unique characters."""
        result = validator.validate("AAaa11!!AAaa")  # Only 4 unique chars

        assert result.is_valid is False
        assert any("unique characters" in err for err in result.errors)

    def test_validate_common_password_fails(self, validator):
        """Test validation fails for common passwords."""
        result = validator.validate("Password123!")

        assert result.is_valid is False
        assert any("too common" in err for err in result.errors)

    def test_check_common_passwords_exact_match(self, validator):
        """Test common password detection with exact match."""
        assert validator.check_common_passwords("password") is True
        assert validator.check_common_passwords("123456") is True
        assert validator.check_common_passwords("qwerty") is True

    def test_check_common_passwords_with_suffix(self, validator):
        """Test common password detection with numeric suffix."""
        assert validator.check_common_passwords("password123") is True
        assert validator.check_common_passwords("qwerty999!") is True

    def test_check_common_passwords_case_insensitive(self, validator):
        """Test common password detection is case insensitive."""
        assert validator.check_common_passwords("PASSWORD") is True
        assert validator.check_common_passwords("PaSsWoRd") is True

    def test_check_common_passwords_unique_password(self, validator):
        """Test unique password is not flagged as common."""
        assert validator.check_common_passwords("Xk9#mP2$qL5@wN8") is False

    def test_calculate_strength_empty_password(self, validator):
        """Test strength calculation for empty password."""
        score = validator.calculate_strength("")

        assert score == 0

    def test_calculate_strength_weak_password(self, validator):
        """Test strength calculation for weak password."""
        score = validator.calculate_strength("abc123")

        assert score < 40

    def test_calculate_strength_medium_password(self, validator):
        """Test strength calculation for medium strength password."""
        score = validator.calculate_strength("MyPass123!")

        assert 40 <= score < 70

    def test_calculate_strength_strong_password(self, validator):
        """Test strength calculation for strong password."""
        score = validator.calculate_strength("MyV3ry$ecur3P@ssw0rd2024!")

        assert score >= 65  # Strong passwords should score at least 65

    def test_calculate_strength_penalizes_repeated_chars(self, validator):
        """Test strength score is penalized for repeated characters."""
        score_with_repeat = validator.calculate_strength("AAA123abc!@#")
        score_without_repeat = validator.calculate_strength("Abc123xyz!@#")

        assert score_with_repeat < score_without_repeat

    def test_calculate_strength_penalizes_sequences(self, validator):
        """Test strength score is penalized for sequential characters."""
        score_with_seq = validator.calculate_strength("Abcdef123!@#")
        score_without_seq = validator.calculate_strength("Axbyc1z23!@#")

        assert score_with_seq < score_without_seq

    def test_hash_password_success(self, validator):
        """Test password hashing succeeds."""
        password = "MySecurePassword123!"
        hashed = validator.hash_password(password)

        assert hashed is not None
        assert hashed != password
        assert hashed.startswith("$argon2")

    def test_verify_password_correct(self, validator):
        """Test password verification with correct password."""
        password = "MySecurePassword123!"
        hashed = validator.hash_password(password)

        assert validator.verify_password(password, hashed) is True

    def test_verify_password_incorrect(self, validator):
        """Test password verification with incorrect password."""
        password = "MySecurePassword123!"
        wrong_password = "WrongPassword456!"
        hashed = validator.hash_password(password)

        assert validator.verify_password(wrong_password, hashed) is False

    def test_validate_with_suggestions_for_weak_password(self, validator):
        """Test validation provides suggestions for weak password."""
        result = validator.validate("weak")

        assert not result.is_valid
        assert len(result.suggestions) > 0
        assert any("characters" in s.lower() for s in result.suggestions)

    def test_validate_unicode_password(self, lenient_validator):
        """Test validation handles unicode characters."""
        result = lenient_validator.validate("P@ssw0rd日本語")

        # Should handle unicode without crashing
        assert isinstance(result, ValidationResult)

    def test_validate_empty_password(self, validator):
        """Test validation of empty password."""
        result = validator.validate("")

        assert result.is_valid is False
        assert len(result.errors) > 0


class TestPasswordHistoryRepository:
    """Tests for PasswordHistoryRepository class."""

    @pytest.fixture
    def repo(self, tmp_path):
        """Create repository with temp database."""
        db_path = tmp_path / "test_password_history.db"
        return PasswordHistoryRepository(db_path=db_path)

    @pytest.fixture
    def validator(self, tmp_path):
        """Create validator for hashing passwords."""
        db_path = tmp_path / "test_history.db"
        repo = PasswordHistoryRepository(db_path=db_path)
        return PasswordValidator(history_repo=repo)

    def test_add_password_to_history(self, repo, validator):
        """Test adding password hash to history."""
        user_id = "user123"
        password_hash = validator.hash_password("MyPassword123!")

        repo.add_password(user_id, password_hash)

        history = repo.get_history(user_id, limit=10)
        assert len(history) == 1
        assert history[0] == password_hash

    def test_add_duplicate_password_to_history(self, repo, validator):
        """Test adding duplicate password hash is handled gracefully."""
        user_id = "user123"
        password_hash = validator.hash_password("MyPassword123!")

        repo.add_password(user_id, password_hash)
        repo.add_password(user_id, password_hash)  # Should not fail

        history = repo.get_history(user_id, limit=10)
        assert len(history) == 1  # Only one entry

    def test_get_history_respects_limit(self, repo, validator):
        """Test get_history respects limit parameter."""
        user_id = "user123"

        # Add 10 passwords
        for i in range(10):
            password_hash = validator.hash_password(f"Password{i}!")
            repo.add_password(user_id, password_hash)

        history = repo.get_history(user_id, limit=5)
        assert len(history) == 5

    def test_get_history_returns_most_recent_first(self, repo, validator):
        """Test get_history returns most recent passwords first."""
        user_id = "user123"

        # Add passwords in sequence
        hashes = []
        for i in range(3):
            password_hash = validator.hash_password(f"Password{i}!")
            repo.add_password(user_id, password_hash)
            hashes.append(password_hash)

        history = repo.get_history(user_id, limit=10)

        # Most recent (last added) should be first
        assert history[0] == hashes[2]
        assert history[1] == hashes[1]
        assert history[2] == hashes[0]

    def test_get_history_empty_for_new_user(self, repo):
        """Test get_history returns empty list for new user."""
        history = repo.get_history("newuser", limit=10)

        assert len(history) == 0

    def test_clear_history_removes_all_records(self, repo, validator):
        """Test clear_history removes all password records."""
        user_id = "user123"

        # Add multiple passwords
        for i in range(5):
            password_hash = validator.hash_password(f"Password{i}!")
            repo.add_password(user_id, password_hash)

        deleted = repo.clear_history(user_id)

        assert deleted == 5
        assert len(repo.get_history(user_id, limit=10)) == 0

    def test_clear_history_returns_zero_for_empty(self, repo):
        """Test clear_history returns 0 when no records exist."""
        deleted = repo.clear_history("nonexistent_user")

        assert deleted == 0

    def test_history_isolated_between_users(self, repo, validator):
        """Test password history is isolated between different users."""
        user1_id = "user1"
        user2_id = "user2"

        hash1 = validator.hash_password("User1Password!")
        hash2 = validator.hash_password("User2Password!")

        repo.add_password(user1_id, hash1)
        repo.add_password(user2_id, hash2)

        user1_history = repo.get_history(user1_id, limit=10)
        user2_history = repo.get_history(user2_id, limit=10)

        assert len(user1_history) == 1
        assert len(user2_history) == 1
        assert user1_history[0] == hash1
        assert user2_history[0] == hash2


class TestPasswordValidatorWithHistory:
    """Tests for password validation with history checking."""

    @pytest.fixture
    def validator_with_history(self, tmp_path):
        """Create validator with history tracking enabled."""
        db_path = tmp_path / "test_history.db"
        repo = PasswordHistoryRepository(db_path=db_path)
        policy = PasswordPolicy(history_count=3)
        return PasswordValidator(policy=policy, history_repo=repo)

    def test_validate_detects_password_in_history(self, validator_with_history):
        """Test validation detects password reuse from history."""
        user_id = "user123"
        password = "MyPassword123!"

        # Add password to history
        password_hash = validator_with_history.hash_password(password)
        validator_with_history.history_repo.add_password(user_id, password_hash)

        # Validate same password
        result = validator_with_history.validate(password, user_id=user_id)

        assert result.is_valid is False
        assert any("used recently" in err for err in result.errors)

    def test_validate_allows_password_not_in_history(self, validator_with_history):
        """Test validation allows password not in history."""
        user_id = "user123"
        old_password = "OldPassword123!"
        new_password = "NewPassword456!"

        # Add old password to history
        old_hash = validator_with_history.hash_password(old_password)
        validator_with_history.history_repo.add_password(user_id, old_hash)

        # Validate new password
        result = validator_with_history.validate(new_password, user_id=user_id)

        # Should not have history error (may have other errors)
        assert not any("used recently" in err for err in result.errors)

    def test_check_history_without_user_id(self, validator_with_history):
        """Test validation without user_id skips history check."""
        password = "MyPassword123!"

        # Add password to history for some user
        password_hash = validator_with_history.hash_password(password)
        validator_with_history.history_repo.add_password("other_user", password_hash)

        # Validate without user_id (history check skipped)
        result = validator_with_history.validate(password, user_id=None)

        # Should not have history error
        assert not any("used recently" in err for err in result.errors)

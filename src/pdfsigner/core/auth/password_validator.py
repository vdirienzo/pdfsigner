"""
password_validator.py - Password validation and strength checking

Validates passwords against policy rules, checks history and common passwords,
and provides password hashing using Argon2.

Author: Homero Thompson del Lago del Terror

NIST 800-53 IA-5 Compliance:
- IA-5(1)(a): Password composition and complexity requirements
- IA-5(1)(e): Password history and reuse prevention
- IA-5(1)(h): Protection of password storage
"""

import re
from pathlib import Path

from loguru import logger

from pdfsigner.core.auth.common_passwords import COMMON_PASSWORDS
from pdfsigner.core.auth.password_history import PasswordHistoryRepository
from pdfsigner.core.auth.password_policy import PasswordPolicy
from pdfsigner.core.auth.password_types import ValidationResult

# Re-export for backward compatibility
__all__ = [
    "COMMON_PASSWORDS",
    "PasswordHistoryRepository",
    "PasswordValidator",
    "ValidationResult",
    "get_password_validator",
]

# Argon2 password hasher (NIST recommended)
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    _ARGON2_AVAILABLE = True
except ImportError:
    _ARGON2_AVAILABLE = False
    logger.warning("argon2-cffi not available, password hashing will not work")


class PasswordValidator:
    """
    Password validation and hashing service.

    Validates passwords against policy rules, checks common passwords
    and password history, calculates strength scores, and provides
    secure password hashing using Argon2.

    Thread-safe singleton pattern recommended via get_password_validator().
    """

    def __init__(
        self,
        policy: PasswordPolicy | None = None,
        history_repo: PasswordHistoryRepository | None = None,
    ):
        """
        Initialize password validator.

        Args:
            policy: Password policy to enforce (default: PasswordPolicy())
            history_repo: Password history repository (default: auto-created)
        """
        self.policy = policy or PasswordPolicy()

        if history_repo is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            history_repo = PasswordHistoryRepository(config_dir / "password_history.db")

        self.history_repo = history_repo

        # Initialize Argon2 hasher if available
        if _ARGON2_AVAILABLE:
            self._hasher = PasswordHasher()
        else:
            self._hasher = None

    def validate(self, password: str, user_id: str | None = None) -> ValidationResult:
        """
        Validate password against policy.

        Checks length, complexity requirements, common passwords,
        and password history if user_id is provided.

        Args:
            password: Password to validate
            user_id: User ID for history checking (optional)

        Returns:
            ValidationResult with validity, errors, score, and suggestions
        """
        errors = []
        suggestions = []

        # Length checks
        if len(password) < self.policy.min_length:
            errors.append(f"Password must be at least {self.policy.min_length} characters")
            suggestions.append(f"Add more characters (minimum {self.policy.min_length})")

        if len(password) > self.policy.max_length:
            errors.append(f"Password must not exceed {self.policy.max_length} characters")

        # Complexity checks
        if self.policy.require_uppercase and not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")
            suggestions.append("Add an uppercase letter (A-Z)")

        if self.policy.require_lowercase and not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")
            suggestions.append("Add a lowercase letter (a-z)")

        if self.policy.require_digits and not re.search(r"[0-9]", password):
            errors.append("Password must contain at least one digit")
            suggestions.append("Add a digit (0-9)")

        if self.policy.require_special:
            special_pattern = f"[{re.escape(self.policy.special_characters)}]"
            if not re.search(special_pattern, password):
                errors.append("Password must contain at least one special character")
                suggestions.append(
                    f"Add a special character ({self.policy.special_characters[:20]}...)"
                )

        # Unique characters check
        unique_chars = len(set(password))
        if unique_chars < self.policy.min_unique_chars:
            errors.append(
                f"Password must contain at least {self.policy.min_unique_chars} unique characters"
            )
            suggestions.append("Use more variety in characters")

        # Common password check
        if self.check_common_passwords(password):
            errors.append("Password is too common and easily guessable")
            suggestions.append("Choose a more unique password")

        # History check
        if user_id and self.check_history(user_id, password):
            errors.append(
                f"Password was used recently (last {self.policy.history_count} passwords "
                "cannot be reused)"
            )
            suggestions.append("Choose a password you haven't used before")

        # Calculate strength score
        strength_score = self.calculate_strength(password)

        # Add strength-based suggestions
        if strength_score < 40:
            suggestions.append("Password is weak - consider using a passphrase")
        elif strength_score < 70:
            suggestions.append("Password strength is moderate - add more length or complexity")

        is_valid = len(errors) == 0

        return ValidationResult(
            is_valid=is_valid,
            errors=errors,
            strength_score=strength_score,
            suggestions=suggestions,
        )

    def check_history(self, user_id: str, password: str) -> bool:
        """
        Check if password was used recently.

        Args:
            user_id: User ID to check history for
            password: Password to check

        Returns:
            True if password is in recent history, False otherwise
        """
        if not self._hasher:
            logger.warning("Argon2 not available, skipping history check")
            return False

        recent_hashes = self.history_repo.get_history(user_id, self.policy.history_count)

        for old_hash in recent_hashes:
            try:
                self._hasher.verify(old_hash, password)
                return True  # Password matches a recent hash
            except VerifyMismatchError:
                continue  # Try next hash
            except Exception as e:
                logger.warning(f"Error verifying password history: {e}")
                continue

        return False

    def check_common_passwords(self, password: str) -> bool:
        """
        Check if password is in common passwords list.

        Args:
            password: Password to check

        Returns:
            True if password is common, False otherwise
        """
        # Check exact match (case-insensitive)
        if password.lower() in COMMON_PASSWORDS:
            return True

        # Check if password is just a common password with numbers appended
        base = password.rstrip("0123456789!@#$%")
        if base.lower() in COMMON_PASSWORDS:
            return True

        return False

    def calculate_strength(self, password: str) -> int:
        """
        Calculate password strength score.

        Uses multiple factors:
        - Length (longer is better)
        - Character variety (upper, lower, digits, special)
        - Unique character ratio
        - Pattern detection (sequences, repeats)

        Args:
            password: Password to score

        Returns:
            Strength score from 0-100
        """
        if not password:
            return 0

        score = 0

        # Length scoring (max 40 points)
        length = len(password)
        if length >= 20:
            score += 40
        elif length >= 16:
            score += 35
        elif length >= 12:
            score += 30
        elif length >= 8:
            score += 20
        else:
            score += 10

        # Character variety (max 30 points)
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"[0-9]", password))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

        variety_count = sum([has_lower, has_upper, has_digit, has_special])
        score += variety_count * 7  # Up to 28 points

        # Unique character ratio (max 20 points)
        unique_ratio = len(set(password)) / len(password)
        score += int(unique_ratio * 20)

        # Penalties for patterns
        # Repeated characters (e.g., "aaa", "111")
        if re.search(r"(.)\1{2,}", password):
            score -= 10

        # Sequential characters (e.g., "abc", "123")
        if re.search(
            r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
            password.lower(),
        ):
            score -= 5
        if re.search(r"(012|123|234|345|456|567|678|789)", password):
            score -= 5

        # Common substitutions (e.g., "P@ssw0rd")
        if re.search(r"[@]", password) and re.search(r"[0]", password):
            if "password" in password.lower().replace("@", "a").replace("0", "o"):
                score -= 15

        # Clamp to 0-100
        return max(0, min(100, score))

    def hash_password(self, password: str) -> str:
        """
        Hash password using Argon2.

        Args:
            password: Plain text password

        Returns:
            Argon2 hash string

        Raises:
            RuntimeError: If Argon2 is not available
        """
        if not self._hasher:
            raise RuntimeError("Argon2 not available - install argon2-cffi")

        return self._hasher.hash(password)

    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify password against hash.

        Args:
            password: Plain text password
            hashed: Argon2 hash to verify against

        Returns:
            True if password matches hash, False otherwise

        Raises:
            RuntimeError: If Argon2 is not available
        """
        if not self._hasher:
            raise RuntimeError("Argon2 not available - install argon2-cffi")

        try:
            self._hasher.verify(hashed, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception as e:
            logger.error(f"Error verifying password: {e}")
            return False


# Singleton instance
_password_validator: PasswordValidator | None = None


def get_password_validator(
    policy: PasswordPolicy | None = None,
    history_repo: PasswordHistoryRepository | None = None,
) -> PasswordValidator:
    """
    Get singleton password validator instance.

    Args:
        policy: Password policy (only used on first call)
        history_repo: History repository (only used on first call)

    Returns:
        PasswordValidator singleton instance
    """
    global _password_validator
    if _password_validator is None:
        _password_validator = PasswordValidator(policy=policy, history_repo=history_repo)
    return _password_validator

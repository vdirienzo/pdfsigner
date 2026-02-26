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
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from pdfsigner.core.auth.password_policy import PasswordPolicy

if TYPE_CHECKING:
    pass

# Argon2 password hasher (NIST recommended)
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    _ARGON2_AVAILABLE = True
except ImportError:
    _ARGON2_AVAILABLE = False
    logger.warning("argon2-cffi not available, password hashing will not work")


# Top 100 most common passwords (abbreviated from top 1000)
# Source: NCSC/Have I Been Pwned common passwords list
COMMON_PASSWORDS = {
    p.lower()
    for p in {
        "123456",
        "password",
        "123456789",
        "12345678",
        "12345",
        "1234567",
        "password1",
        "123123",
        "1234567890",
        "000000",
        "qwerty",
        "abc123",
        "million2",
        "1234",
        "iloveyou",
        "aaron431",
        "password123",
        "princess",
        "monkey",
        "123321",
        "qwertyuiop",
        "123456a",
        "superman",
        "asdfghjkl",
        "654321",
        "letmein",
        "666666",
        "welcome",
        "starwars",
        "baseball",
        "dragon",
        "master",
        "hello",
        "freedom",
        "whatever",
        "qazwsx",
        "trustno1",
        "jordan23",
        "harley",
        "Robert",
        "matthew",
        "jordan",
        "asshole",
        "daniel",
        "andrew",
        "lakers",
        "andrea",
        "buster",
        "joshua",
        "teste",
        "ferrari",
        "peaches",
        "cheese",
        "121212",
        "11111111",
        "passw0rd",
        "shadow",
        "michael",
        "Jennifer",
        "sunshine",
        "computer",
        "tigger",
        "cookie",
        "zxcvbnm",
        "hunter",
        "summer",
        "soccer",
        "thomas",
        "killer",
        "charlie",
        "jessica",
        "cowboys",
        "michelle",
        "love",
        "ranger",
        "pepper",
        "ginger",
        "princess1",
        "hockey",
        "silver",
        "richard",
        "maggie",
        "william",
        "jessica1",
        "purple",
        "justin",
        "orange",
        "thunder",
        "golden",
        "dallas",
        "compaq",
        "scooter",
        "112233",
        "yellow",
        "phoenix",
        "creative",
        "nicole",
        "george",
        "florida",
        "coffee",
        "Chelsea",
    }
}


@dataclass
class ValidationResult:
    """
    Result of password validation.

    Attributes:
        is_valid: Whether password meets all policy requirements
        errors: List of validation error messages
        strength_score: Password strength score (0-100)
        suggestions: List of suggestions to improve password
    """

    is_valid: bool
    errors: list[str] = field(default_factory=list)
    strength_score: int = 0
    suggestions: list[str] = field(default_factory=list)


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
        history_repo: "PasswordHistoryRepository | None" = None,
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


class PasswordHistoryRepository:
    """
    SQLite-based password history storage.

    Stores hashed passwords for history checking to prevent
    password reuse within the configured history window.

    Thread-safe with connection-per-operation pattern.
    """

    def __init__(self, db_path: Path | None = None):
        """
        Initialize password history repository.

        Args:
            db_path: Path to SQLite database (default: ~/.config/pdfsigner/password_history.db)
        """
        if db_path is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / "password_history.db"

        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get database connection with automatic cleanup."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(user_id, password_hash)
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_password_history_user "
                "ON password_history(user_id, created_at DESC)"
            )

    def add_password(self, user_id: str, password_hash: str) -> None:
        """
        Add password hash to history.

        Args:
            user_id: User ID
            password_hash: Argon2 hash of password
        """
        from datetime import UTC, datetime

        with self._get_connection() as conn:
            try:
                conn.execute(
                    "INSERT INTO password_history (user_id, password_hash, created_at) "
                    "VALUES (?, ?, ?)",
                    (user_id, password_hash, datetime.now(UTC).isoformat()),
                )
                logger.debug(f"Added password to history for user: {user_id}")
            except sqlite3.IntegrityError:
                # Duplicate hash for user - already in history
                logger.debug(f"Password already in history for user: {user_id}")

    def get_history(self, user_id: str, limit: int) -> list[str]:
        """
        Get recent password hashes for user.

        Args:
            user_id: User ID
            limit: Maximum number of passwords to return

        Returns:
            List of password hashes (most recent first)
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT password_hash FROM password_history WHERE user_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
            return [row["password_hash"] for row in rows]

    def clear_history(self, user_id: str) -> int:
        """
        Clear password history for user.

        Args:
            user_id: User ID

        Returns:
            Number of records deleted
        """
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM password_history WHERE user_id = ?", (user_id,))
            deleted = cursor.rowcount
            if deleted > 0:
                logger.info(f"Cleared {deleted} password history records for user: {user_id}")
            return deleted


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

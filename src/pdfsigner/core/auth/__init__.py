"""
Authentication and password policy components.

Provides password validation, policy enforcement, and password history tracking
to meet NIST 800-53 IA-5 requirements.
"""

from pdfsigner.core.auth.password_history import PasswordHistoryRepository
from pdfsigner.core.auth.password_policy import PasswordPolicy
from pdfsigner.core.auth.password_types import ValidationResult
from pdfsigner.core.auth.password_validator import (
    PasswordValidator,
    get_password_validator,
)

__all__ = [
    "PasswordHistoryRepository",
    "PasswordPolicy",
    "PasswordValidator",
    "ValidationResult",
    "get_password_validator",
]

"""
Authentication and password policy components.

Provides password validation, policy enforcement, and password history tracking
to meet NIST 800-53 IA-5 requirements.
"""

from pdfsigner.core.auth.password_policy import PasswordPolicy
from pdfsigner.core.auth.password_validator import (
    PasswordHistoryRepository,
    PasswordValidator,
    ValidationResult,
    get_password_validator,
)

__all__ = [
    "PasswordPolicy",
    "PasswordValidator",
    "ValidationResult",
    "PasswordHistoryRepository",
    "get_password_validator",
]

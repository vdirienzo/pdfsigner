"""
password_policy.py - Password policy configuration

Defines password complexity and lifecycle requirements for NIST 800-53 IA-5 compliance.

Author: Homero Thompson del Lago del Terror
"""

from dataclasses import dataclass


@dataclass
class PasswordPolicy:
    """
    Password policy configuration.

    Defines requirements for password complexity, lifecycle, and security.
    Follows NIST 800-53 IA-5 guidelines for password-based authentication.

    Attributes:
        min_length: Minimum password length (NIST recommends 12+)
        max_length: Maximum password length (prevent DOS attacks)
        require_uppercase: Require at least one uppercase letter
        require_lowercase: Require at least one lowercase letter
        require_digits: Require at least one digit
        require_special: Require at least one special character
        special_characters: Valid special characters for passwords
        max_age_days: Password expiration period (90 days typical)
        history_count: Number of previous passwords to prevent reuse
        lockout_threshold: Failed login attempts before account lockout
        lockout_duration_minutes: Duration of account lockout
        min_unique_chars: Minimum unique characters (prevent simple patterns)
    """

    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    special_characters: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    max_age_days: int = 90
    history_count: int = 12
    lockout_threshold: int = 5
    lockout_duration_minutes: int = 30
    min_unique_chars: int = 8

    def __post_init__(self) -> None:
        """Validate policy settings."""
        if self.min_length < 8:
            raise ValueError("min_length must be at least 8")
        if self.max_length < self.min_length:
            raise ValueError("max_length must be >= min_length")
        if self.max_age_days < 1:
            raise ValueError("max_age_days must be positive")
        if self.history_count < 0:
            raise ValueError("history_count cannot be negative")
        if self.lockout_threshold < 1:
            raise ValueError("lockout_threshold must be positive")
        if self.lockout_duration_minutes < 1:
            raise ValueError("lockout_duration_minutes must be positive")
        if self.min_unique_chars < 1:
            raise ValueError("min_unique_chars must be positive")

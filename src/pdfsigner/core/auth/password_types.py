"""
password_types.py - Password validation result types

Data classes used by the password validation subsystem.

Author: Homero Thompson del Lago del Terror
"""

from dataclasses import dataclass, field


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

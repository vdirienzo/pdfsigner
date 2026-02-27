"""
mfa_types.py - MFA data types and status models

Defines dataclasses used across MFA enrollment, verification, and status queries.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class MFAEnrollment:
    """MFA enrollment data for user setup."""

    secret: str
    qr_code_base64: str
    provisioning_uri: str
    backup_codes: list[str]


@dataclass
class MFAStatus:
    """MFA status for a user."""

    enabled: bool
    enrolled_at: datetime | None
    last_used_at: datetime | None
    backup_codes_remaining: int


# Public exports
__all__ = ["MFAEnrollment", "MFAStatus"]

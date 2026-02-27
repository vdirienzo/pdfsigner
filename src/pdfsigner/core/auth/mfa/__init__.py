"""
MFA (Multi-Factor Authentication) module.

Provides TOTP-based two-factor authentication compatible with
Google Authenticator and other TOTP apps.
"""

from pdfsigner.core.auth.mfa.backup_codes import BackupCodeManager
from pdfsigner.core.auth.mfa.mfa_enrollment import MFAEnrollmentService
from pdfsigner.core.auth.mfa.mfa_manager import (
    MFAManager,
    get_mfa_manager,
)
from pdfsigner.core.auth.mfa.mfa_types import MFAEnrollment, MFAStatus
from pdfsigner.core.auth.mfa.mfa_verification import MFAVerificationService
from pdfsigner.core.auth.mfa.totp_provider import TOTPConfig, TOTPProvider

__all__ = [
    "MFAManager",
    "MFAEnrollment",
    "MFAEnrollmentService",
    "MFAStatus",
    "MFAVerificationService",
    "TOTPProvider",
    "TOTPConfig",
    "BackupCodeManager",
    "get_mfa_manager",
]

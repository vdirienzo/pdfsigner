"""
MFA (Multi-Factor Authentication) service.

Business logic for MFA enrollment, verification,
backup codes, and disable operations.
"""

from loguru import logger

from pdfsigner.api.schemas.mfa import (
    MFABackupCodeResponse,
    MFADisableResponse,
    MFAEnrollResponse,
    MFARegenerateBackupCodesResponse,
    MFAStatusResponse,
    MFAVerifyResponse,
)
from pdfsigner.core.auth.mfa import get_mfa_manager


def enroll_mfa(user_id: str, account_name: str, username: str) -> MFAEnrollResponse:
    """Start MFA enrollment for a user.

    Args:
        user_id: User ID
        account_name: Account name (email or username) for QR code
        username: Username for logging

    Returns:
        MFAEnrollResponse with QR code and backup codes

    Raises:
        ValueError: If user already has MFA enabled
    """
    mfa_manager = get_mfa_manager()

    mfa_status = mfa_manager.get_status(user_id)
    if mfa_status.enabled:
        raise ValueError("MFA is already enabled for this user")

    enrollment = mfa_manager.enroll(user_id=user_id, account_name=account_name)

    logger.info(f"MFA enrollment started for user {username}")

    return MFAEnrollResponse(
        qr_code_base64=enrollment.qr_code_base64,
        provisioning_uri=enrollment.provisioning_uri,
        secret=enrollment.secret,
        backup_codes=enrollment.backup_codes,
    )


def verify_and_activate(user_id: str, code: str, username: str) -> MFAVerifyResponse:
    """Verify TOTP code and activate MFA.

    Args:
        user_id: User ID
        code: TOTP code to verify
        username: Username for logging

    Returns:
        MFAVerifyResponse with success status

    Raises:
        ValueError: If MFA not enrolled
    """
    mfa_manager = get_mfa_manager()
    success = mfa_manager.verify_and_activate(user_id, code)

    if success:
        return MFAVerifyResponse(success=True, message="MFA activated successfully")
    else:
        return MFAVerifyResponse(success=False, message="Invalid TOTP code")


def verify_backup_code(user_id: str, code: str, username: str) -> MFABackupCodeResponse:
    """Verify a backup code for MFA authentication.

    Args:
        user_id: User ID
        code: Backup code to verify
        username: Username for logging

    Returns:
        MFABackupCodeResponse with result and remaining codes

    Raises:
        PermissionError: If MFA not enabled
    """
    mfa_manager = get_mfa_manager()

    mfa_status = mfa_manager.get_status(user_id)
    if not mfa_status.enabled:
        raise PermissionError("MFA is not enabled for this user")

    success = mfa_manager.verify(user_id, code, is_backup=True)

    if success:
        updated_status = mfa_manager.get_status(user_id)
        return MFABackupCodeResponse(
            success=True,
            message="Backup code verified",
            remaining_codes=updated_status.backup_codes_remaining,
        )
    else:
        return MFABackupCodeResponse(
            success=False,
            message="Invalid or already used backup code",
            remaining_codes=mfa_status.backup_codes_remaining,
        )


def get_status(user_id: str) -> MFAStatusResponse:
    """Get MFA status for a user.

    Args:
        user_id: User ID

    Returns:
        MFAStatusResponse with enrollment status
    """
    mfa_manager = get_mfa_manager()
    mfa_status = mfa_manager.get_status(user_id)

    return MFAStatusResponse(
        enabled=mfa_status.enabled,
        enrolled_at=mfa_status.enrolled_at,
        last_used_at=mfa_status.last_used_at,
        backup_codes_remaining=mfa_status.backup_codes_remaining,
    )


def disable_mfa(user_id: str, current_password: str, username: str) -> MFADisableResponse:
    """Disable MFA for a user.

    Args:
        user_id: User ID
        current_password: User's current password for confirmation
        username: Username for logging

    Returns:
        MFADisableResponse with success status

    Raises:
        ValueError: If MFA not enabled
        PermissionError: If password is incorrect or not set
        RuntimeError: If disable operation fails
    """
    from pdfsigner.core.auth.password_validator import get_password_validator
    from pdfsigner.core.users.user_repository import UserRepository

    mfa_manager = get_mfa_manager()

    mfa_status = mfa_manager.get_status(user_id)
    if not mfa_status.enabled:
        raise ValueError("MFA is not enabled for this user")

    # Verify password
    user_repo = UserRepository()
    password_hash = user_repo.get_password_hash(user_id)

    if not password_hash:
        raise PermissionError("User does not have a password set")

    password_validator = get_password_validator()
    if not password_validator.verify_password(current_password, password_hash):
        logger.warning(f"Failed MFA disable attempt for user {username}: incorrect password")
        raise PermissionError("Incorrect password")

    success = mfa_manager.disable(user_id)

    if not success:
        raise RuntimeError("Failed to disable MFA")

    return MFADisableResponse(success=True, message="MFA disabled successfully")


def regenerate_backup_codes(user_id: str, username: str) -> MFARegenerateBackupCodesResponse:
    """Regenerate backup codes for a user.

    Args:
        user_id: User ID
        username: Username for logging

    Returns:
        MFARegenerateBackupCodesResponse with new codes

    Raises:
        PermissionError: If MFA not enabled
        ValueError: If regeneration fails
    """
    mfa_manager = get_mfa_manager()

    mfa_status = mfa_manager.get_status(user_id)
    if not mfa_status.enabled:
        raise PermissionError("MFA is not enabled for this user")

    backup_codes = mfa_manager.regenerate_backup_codes(user_id)

    return MFARegenerateBackupCodesResponse(
        backup_codes=backup_codes,
        message="Backup codes regenerated successfully. Previous codes are now invalid.",
    )


__all__ = [
    "disable_mfa",
    "enroll_mfa",
    "get_status",
    "regenerate_backup_codes",
    "verify_and_activate",
    "verify_backup_code",
]

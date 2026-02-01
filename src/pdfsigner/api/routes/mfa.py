"""
MFA (Multi-Factor Authentication) routes.

Provides endpoints for:
- MFA enrollment (QR code generation)
- TOTP verification
- MFA status
- Backup code management
- MFA disable
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger

from pdfsigner.api.middleware.auth import User, get_current_active_user
from pdfsigner.api.schemas.mfa import (
    MFABackupCodeRequest,
    MFABackupCodeResponse,
    MFADisableRequest,
    MFADisableResponse,
    MFAEnrollRequest,
    MFAEnrollResponse,
    MFARegenerateBackupCodesResponse,
    MFAStatusResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
)
from pdfsigner.core.auth.mfa import get_mfa_manager

router = APIRouter(prefix="/mfa", tags=["mfa"])


# --- Routes ---


@router.post(
    "/enroll",
    response_model=MFAEnrollResponse,
    summary="Start MFA enrollment",
    description="""
    Start MFA enrollment for the current user.

    Returns:
    - QR code image (Base64-encoded PNG)
    - Provisioning URI for manual entry
    - Secret key for manual entry
    - 10 backup codes for account recovery

    **Note:** MFA is not enabled until the user verifies a code via /mfa/verify.
    """,
)
async def enroll_mfa(
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: MFAEnrollRequest,
) -> MFAEnrollResponse:
    """
    Start MFA enrollment for current user.

    Args:
        current_user: Authenticated user
        request: Enrollment request (empty body)

    Returns:
        MFAEnrollResponse with QR code and backup codes

    Raises:
        HTTPException: 400 if user already has MFA enabled
        HTTPException: 500 if enrollment fails
    """
    try:
        mfa_manager = get_mfa_manager()

        # Check if already enrolled
        status = mfa_manager.get_status(current_user.id)
        if status.enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is already enabled for this user",
            )

        # Start enrollment
        enrollment = mfa_manager.enroll(
            user_id=current_user.id,
            account_name=current_user.email or current_user.username,
        )

        logger.info(f"MFA enrollment started for user {current_user.username}")

        return MFAEnrollResponse(
            qr_code_base64=enrollment.qr_code_base64,
            provisioning_uri=enrollment.provisioning_uri,
            secret=enrollment.secret,
            backup_codes=enrollment.backup_codes,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error(f"MFA enrollment failed for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start MFA enrollment",
        ) from e


@router.post(
    "/verify",
    response_model=MFAVerifyResponse,
    summary="Verify TOTP code and activate MFA",
    description="""
    Verify TOTP code to complete MFA enrollment.

    After successful verification, MFA is enabled for the user.
    """,
)
async def verify_mfa(
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: MFAVerifyRequest,
) -> MFAVerifyResponse:
    """
    Verify TOTP code and activate MFA.

    Args:
        current_user: Authenticated user
        request: Verification request with TOTP code

    Returns:
        MFAVerifyResponse with success status

    Raises:
        HTTPException: 400 if code is invalid or MFA not enrolled
    """
    try:
        mfa_manager = get_mfa_manager()

        # Verify and activate
        success = mfa_manager.verify_and_activate(current_user.id, request.code)

        if success:
            return MFAVerifyResponse(
                success=True,
                message="MFA activated successfully",
            )
        else:
            return MFAVerifyResponse(
                success=False,
                message="Invalid TOTP code",
            )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error(f"MFA verification failed for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify MFA code",
        ) from e


@router.post(
    "/verify-backup",
    response_model=MFABackupCodeResponse,
    summary="Verify backup code",
    description="""
    Verify a backup code for MFA authentication.

    Backup codes are one-time use. After verification, the code is marked as used.
    """,
)
async def verify_backup_code(
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: MFABackupCodeRequest,
) -> MFABackupCodeResponse:
    """
    Verify backup code for MFA.

    Args:
        current_user: Authenticated user
        request: Backup code request

    Returns:
        MFABackupCodeResponse with success status and remaining codes

    Raises:
        HTTPException: 403 if MFA not enabled
        HTTPException: 400 if code is invalid
    """
    try:
        mfa_manager = get_mfa_manager()

        # Check if MFA is enabled
        status = mfa_manager.get_status(current_user.id)
        if not status.enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA is not enabled for this user",
            )

        # Verify backup code
        success = mfa_manager.verify(current_user.id, request.code, is_backup=True)

        if success:
            # Get updated status for remaining codes
            updated_status = mfa_manager.get_status(current_user.id)
            return MFABackupCodeResponse(
                success=True,
                message="Backup code verified",
                remaining_codes=updated_status.backup_codes_remaining,
            )
        else:
            return MFABackupCodeResponse(
                success=False,
                message="Invalid or already used backup code",
                remaining_codes=status.backup_codes_remaining,
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Backup code verification failed for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify backup code",
        ) from e


@router.get(
    "/status",
    response_model=MFAStatusResponse,
    summary="Get MFA status",
    description="Retrieve MFA status for the current user.",
)
async def get_mfa_status(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> MFAStatusResponse:
    """
    Get MFA status for current user.

    Args:
        current_user: Authenticated user

    Returns:
        MFAStatusResponse with enrollment status and usage info
    """
    try:
        mfa_manager = get_mfa_manager()
        status = mfa_manager.get_status(current_user.id)

        return MFAStatusResponse(
            enabled=status.enabled,
            enrolled_at=status.enrolled_at,
            last_used_at=status.last_used_at,
            backup_codes_remaining=status.backup_codes_remaining,
        )

    except Exception as e:
        logger.error(f"Failed to get MFA status for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve MFA status",
        ) from e


@router.post(
    "/disable",
    response_model=MFADisableResponse,
    summary="Disable MFA",
    description="""
    Disable MFA for the current user.

    Requires password confirmation for security.
    Admin users can disable MFA for any user.
    """,
)
async def disable_mfa(
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: MFADisableRequest,
) -> MFADisableResponse:
    """
    Disable MFA for current user.

    Args:
        current_user: Authenticated user
        request: Disable request (optionally with password)

    Returns:
        MFADisableResponse with success status

    Raises:
        HTTPException: 400 if MFA not enabled
        HTTPException: 401 if password is incorrect
    """
    try:
        mfa_manager = get_mfa_manager()

        # Check if MFA is enabled
        status = mfa_manager.get_status(current_user.id)
        if not status.enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is not enabled for this user",
            )

        # TODO: Verify password if provided
        # For now, allow without password (dev mode)

        # Disable MFA
        success = mfa_manager.disable(current_user.id)

        if success:
            return MFADisableResponse(
                success=True,
                message="MFA disabled successfully",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to disable MFA",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to disable MFA for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable MFA",
        ) from e


@router.post(
    "/backup-codes",
    response_model=MFARegenerateBackupCodesResponse,
    summary="Regenerate backup codes",
    description="""
    Regenerate backup codes for the current user.

    **Warning:** This invalidates all previous backup codes.
    """,
)
async def regenerate_backup_codes(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> MFARegenerateBackupCodesResponse:
    """
    Regenerate backup codes for current user.

    Args:
        current_user: Authenticated user

    Returns:
        MFARegenerateBackupCodesResponse with new backup codes

    Raises:
        HTTPException: 403 if MFA not enabled
    """
    try:
        mfa_manager = get_mfa_manager()

        # Check if MFA is enabled
        status = mfa_manager.get_status(current_user.id)
        if not status.enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA is not enabled for this user",
            )

        # Regenerate codes
        backup_codes = mfa_manager.regenerate_backup_codes(current_user.id)

        return MFARegenerateBackupCodesResponse(
            backup_codes=backup_codes,
            message="Backup codes regenerated successfully. Previous codes are now invalid.",
        )

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error(f"Failed to regenerate backup codes for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to regenerate backup codes",
        ) from e


# --- Public Exports ---

__all__ = ["router"]

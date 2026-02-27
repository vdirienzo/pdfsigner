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
from pdfsigner.api.services import mfa_service

router = APIRouter(prefix="/mfa", tags=["mfa"])


@router.post(
    "/enroll",
    response_model=MFAEnrollResponse,
    summary="Start MFA enrollment",
    description="Start MFA enrollment for the current user.",
)
async def enroll_mfa(
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: MFAEnrollRequest,
) -> MFAEnrollResponse:
    """Start MFA enrollment for current user."""
    try:
        return mfa_service.enroll_mfa(
            user_id=current_user.id,
            account_name=current_user.email or current_user.username,
            username=current_user.username,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
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
    description="Verify TOTP code to complete MFA enrollment.",
)
async def verify_mfa(
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: MFAVerifyRequest,
) -> MFAVerifyResponse:
    """Verify TOTP code and activate MFA."""
    try:
        return mfa_service.verify_and_activate(current_user.id, request.code, current_user.username)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
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
    description="Verify a backup code for MFA authentication.",
)
async def verify_backup_code(
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: MFABackupCodeRequest,
) -> MFABackupCodeResponse:
    """Verify backup code for MFA."""
    try:
        return mfa_service.verify_backup_code(current_user.id, request.code, current_user.username)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
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
    """Get MFA status for current user."""
    try:
        return mfa_service.get_status(current_user.id)
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
    description="Disable MFA for the current user. Requires password confirmation.",
)
async def disable_mfa(
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: MFADisableRequest,
) -> MFADisableResponse:
    """Disable MFA for current user."""
    try:
        return mfa_service.disable_mfa(
            current_user.id, request.current_password, current_user.username
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e
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
    description="Regenerate backup codes for the current user. Invalidates previous codes.",
)
async def regenerate_backup_codes(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> MFARegenerateBackupCodesResponse:
    """Regenerate backup codes for current user."""
    try:
        return mfa_service.regenerate_backup_codes(current_user.id, current_user.username)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Failed to regenerate backup codes for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to regenerate backup codes",
        ) from e


__all__ = ["router"]

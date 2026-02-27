"""
GDPR compliance routes.

Provides endpoints for:
- User data export (GDPR Article 20 - Right to data portability)
- User anonymization (GDPR Article 17 - Right to erasure)
- Scheduled deletion with grace period
- Retention status queries
- Data purging (admin only)
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.api.schemas.gdpr import (
    AnonymizeUserRequest,
    AnonymizeUserResponse,
    CancelDeletionResponse,
    DataExportResponse,
    PurgeExpiredDataResponse,
    RetentionStatusResponse,
    ScheduleDeletionRequest,
    ScheduleDeletionResponse,
)
from pdfsigner.api.services import gdpr_service
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users import UserRole

router = APIRouter(prefix="/api/v1/gdpr", tags=["gdpr"])


@router.get(
    "/export/{user_id}",
    response_model=DataExportResponse,
    summary="Export user data",
    description="Export all user data in JSON format (GDPR Article 20).",
)
async def export_user_data(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> DataExportResponse:
    """Export user data (GDPR Article 20)."""
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only export your own data",
        )

    try:
        return gdpr_service.export_user_data(user_id, current_user.username)
    except LookupError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/anonymize",
    response_model=AnonymizeUserResponse,
    summary="Anonymize user",
    description="Anonymize user data (GDPR Article 17, admin only).",
)
async def anonymize_user(
    request: AnonymizeUserRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> AnonymizeUserResponse:
    """Anonymize user (admin only)."""
    try:
        return gdpr_service.anonymize_user(request.user_id, current_user.id, current_user.username)
    except LookupError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/delete/{user_id}",
    response_model=ScheduleDeletionResponse,
    summary="Schedule user deletion",
    description="Schedule user deletion with grace period.",
)
async def schedule_user_deletion(
    user_id: str,
    request: ScheduleDeletionRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> ScheduleDeletionResponse:
    """Schedule user deletion with grace period."""
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only delete your own account",
        )

    try:
        return gdpr_service.schedule_deletion(
            user_id, request.grace_days, current_user.id, current_user.username
        )
    except LookupError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.delete(
    "/delete/{user_id}",
    response_model=CancelDeletionResponse,
    summary="Cancel scheduled deletion",
    description="Cancel pending user deletion.",
)
async def cancel_user_deletion(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> CancelDeletionResponse:
    """Cancel scheduled user deletion."""
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only cancel your own account deletion",
        )

    try:
        gdpr_service.cancel_deletion(user_id, current_user.username)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return CancelDeletionResponse(
        success=True,
        user_id=user_id,
        message="Scheduled deletion cancelled successfully",
    )


@router.get(
    "/status/{user_id}",
    response_model=RetentionStatusResponse,
    summary="Get retention status",
    description="Get user data retention status.",
)
async def get_retention_status(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> RetentionStatusResponse:
    """Get user retention status."""
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only check your own retention status",
        )

    return gdpr_service.get_retention_status(user_id)


@router.post(
    "/purge",
    response_model=PurgeExpiredDataResponse,
    summary="Purge expired data",
    description="Purge all data past retention period (admin only).",
)
async def purge_expired_data(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> PurgeExpiredDataResponse:
    """Purge expired data (admin only)."""
    return gdpr_service.purge_expired_data(current_user.username)


__all__ = ["router"]

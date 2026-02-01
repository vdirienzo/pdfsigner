"""
GDPR compliance routes.

Provides endpoints for:
- User data export (GDPR Article 20 - Right to data portability)
- User anonymization (GDPR Article 17 - Right to erasure)
- Consent management (GDPR Article 7 - Conditions for consent)
- Scheduled deletion with grace period
- Retention status queries
- Data purging (admin only)
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger

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
from pdfsigner.core.gdpr import get_data_retention_service
from pdfsigner.core.gdpr.data_export import get_user_data_exporter
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users import UserRole

router = APIRouter(prefix="/api/v1/gdpr", tags=["gdpr"])


# --- Data Export (GDPR Article 20) ---


@router.get(
    "/export/{user_id}",
    response_model=DataExportResponse,
    summary="Export user data",
    description="""
    Export all user data in JSON format (GDPR Article 20 - Right to data portability).

    **Permissions:**
    - Users can export their own data
    - Admins can export any user's data

    **Exported data includes:**
    - User profile information
    - Certificate bindings
    - Audit trail (actions performed by user)
    - Session history
    """,
)
async def export_user_data(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> DataExportResponse:
    """
    Export user data (GDPR Article 20).

    Args:
        user_id: User ID to export
        current_user: Authenticated user

    Returns:
        User data export in JSON format

    Raises:
        HTTPException: 403 if user tries to export another user's data
        HTTPException: 404 if user not found
    """
    # Check permissions: users can export their own data, admins can export anyone
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only export your own data",
        )

    # Export data
    exporter = get_user_data_exporter()
    export = exporter.export_user_data(user_id, format="json")

    if not export:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {user_id}",
        )

    logger.info(f"User data exported: {user_id} (requested by {current_user.username})")

    return DataExportResponse(
        user_id=user_id,
        format=export.format,
        generated_at=export.generated_at,
        data={
            "user_info": export.user_info,
            "certificates": export.certificates,
            "audit_events": export.audit_events,
            "sessions": export.sessions,
            "metadata": export.metadata,
        },
    )


# --- User Anonymization (GDPR Article 17) ---


@router.post(
    "/anonymize",
    response_model=AnonymizeUserResponse,
    summary="Anonymize user",
    description="""
    Anonymize user data (GDPR Article 17 - Right to erasure).

    **Requires:** Admin role

    **Anonymization process:**
    1. Replace username with "anonymous_[hash]"
    2. Replace email with "[hash]@anonymized.local"
    3. Set display name to "Anonymous User [hash]"
    4. Clear optional fields
    5. Mark user as inactive
    6. Anonymize references in audit logs

    **Note:** User ID is preserved for audit trail integrity.
    """,
)
async def anonymize_user(
    request: AnonymizeUserRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> AnonymizeUserResponse:
    """
    Anonymize user (admin only).

    Args:
        request: Anonymization request with user ID
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        Anonymization result

    Raises:
        HTTPException: 404 if user not found
        HTTPException: 400 if user already anonymized
    """
    service = get_data_retention_service()
    result = service.anonymize_user(request.user_id, requested_by=current_user.id)

    if not result.success:
        if "not found" in result.error_message.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=result.error_message,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message,
            )

    logger.info(
        f"User anonymized: {request.user_id} "
        f"(by {current_user.username}, fields={len(result.fields_anonymized)})"
    )

    return AnonymizeUserResponse(
        success=result.success,
        user_id=result.user_id,
        fields_anonymized=result.fields_anonymized,
        audit_records_anonymized=result.audit_records_anonymized,
        error_message=result.error_message,
    )


# --- Scheduled Deletion ---


@router.post(
    "/delete/{user_id}",
    response_model=ScheduleDeletionResponse,
    summary="Schedule user deletion",
    description="""
    Schedule user deletion with grace period.

    **Permissions:**
    - Users can schedule deletion of their own account
    - Admins can schedule deletion of any user

    **Process:**
    1. User deletion is scheduled with configurable grace period (default 30 days)
    2. User can cancel deletion before the date
    3. After grace period, user is anonymized and then deleted
    4. Deletion can be cancelled using DELETE /gdpr/delete/{user_id}
    """,
)
async def schedule_user_deletion(
    user_id: str,
    request: ScheduleDeletionRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> ScheduleDeletionResponse:
    """
    Schedule user deletion with grace period.

    Args:
        user_id: User ID to schedule for deletion
        request: Deletion request with grace period
        current_user: Authenticated user

    Returns:
        Deletion schedule confirmation

    Raises:
        HTTPException: 403 if user tries to delete another user
        HTTPException: 404 if user not found
    """
    # Check permissions: users can delete themselves, admins can delete anyone
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only delete your own account",
        )

    # Schedule deletion
    service = get_data_retention_service()
    success = service.schedule_deletion(
        user_id, days=request.grace_days, requested_by=current_user.id
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {user_id}",
        )

    # Get deletion date
    status_info = service.get_retention_status(user_id)

    logger.info(
        f"User deletion scheduled: {user_id} "
        f"(by {current_user.username}, date={status_info.deletion_date})"
    )

    return ScheduleDeletionResponse(
        success=True,
        user_id=user_id,
        deletion_date=status_info.deletion_date,
        grace_days=request.grace_days,
        message=f"User deletion scheduled for {status_info.deletion_date.date()}. "
        f"You can cancel before this date.",
    )


@router.delete(
    "/delete/{user_id}",
    response_model=CancelDeletionResponse,
    summary="Cancel scheduled deletion",
    description="""
    Cancel pending user deletion.

    **Permissions:**
    - Users can cancel deletion of their own account
    - Admins can cancel deletion of any user
    """,
)
async def cancel_user_deletion(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> CancelDeletionResponse:
    """
    Cancel scheduled user deletion.

    Args:
        user_id: User ID to cancel deletion for
        current_user: Authenticated user

    Returns:
        Cancellation confirmation

    Raises:
        HTTPException: 403 if user tries to cancel another user's deletion
        HTTPException: 400 if no deletion scheduled
    """
    # Check permissions
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only cancel your own account deletion",
        )

    # Cancel deletion
    service = get_data_retention_service()
    success = service.cancel_scheduled_deletion(user_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No deletion scheduled for this user",
        )

    logger.info(f"User deletion cancelled: {user_id} (by {current_user.username})")

    return CancelDeletionResponse(
        success=True,
        user_id=user_id,
        message="Scheduled deletion cancelled successfully",
    )


# --- Retention Status ---


@router.get(
    "/status/{user_id}",
    response_model=RetentionStatusResponse,
    summary="Get retention status",
    description="""
    Get user data retention status.

    **Permissions:**
    - Users can check their own status
    - Admins can check any user's status

    **Returns:**
    - Whether user is anonymized
    - Whether deletion is scheduled
    - Deletion date and days remaining
    """,
)
async def get_retention_status(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> RetentionStatusResponse:
    """
    Get user retention status.

    Args:
        user_id: User ID to check
        current_user: Authenticated user

    Returns:
        Retention status information

    Raises:
        HTTPException: 403 if user tries to check another user's status
    """
    # Check permissions
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only check your own retention status",
        )

    # Get status
    service = get_data_retention_service()
    status_info = service.get_retention_status(user_id)

    return RetentionStatusResponse(
        user_id=status_info.user_id,
        is_anonymized=status_info.is_anonymized,
        deletion_scheduled=status_info.deletion_scheduled,
        deletion_scheduled_at=status_info.deletion_scheduled_at,
        deletion_date=status_info.deletion_date,
        days_until_deletion=status_info.days_until_deletion,
    )


# --- Admin: Purge Expired Data ---


@router.post(
    "/purge",
    response_model=PurgeExpiredDataResponse,
    summary="Purge expired data",
    description="""
    Purge all data past retention period (admin only).

    **Requires:** Admin role

    **Process:**
    1. Find users with deletion_date in the past
    2. Anonymize user data if not already done
    3. Delete user account (hard delete)
    4. Optionally purge audit records

    **Note:** This should be run periodically (e.g., daily cron job).
    """,
)
async def purge_expired_data(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> PurgeExpiredDataResponse:
    """
    Purge expired data (admin only).

    Args:
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        Purge operation results
    """
    service = get_data_retention_service()
    result = service.purge_expired_data()

    logger.info(
        f"Data purge completed by {current_user.username}: "
        f"users={result.users_deleted}, audit_records={result.audit_records_purged}"
    )

    return PurgeExpiredDataResponse(
        success=result.success,
        users_deleted=result.users_deleted,
        audit_records_purged=result.audit_records_purged,
        documents_deleted=result.documents_deleted,
        error_message=result.error_message,
    )


# --- Public Exports ---

__all__ = ["router"]

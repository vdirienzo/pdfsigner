"""
GDPR compliance service.

Business logic for user data export, anonymization,
scheduled deletion, and data purging.
GDPR Articles 7, 17, 20.
"""

from loguru import logger

from pdfsigner.api.schemas.gdpr import (
    AnonymizeUserResponse,
    DataExportResponse,
    PurgeExpiredDataResponse,
    RetentionStatusResponse,
    ScheduleDeletionResponse,
)
from pdfsigner.core.gdpr import get_data_retention_service
from pdfsigner.core.gdpr.data_export import get_user_data_exporter


def export_user_data(user_id: str, requester_username: str) -> DataExportResponse:
    """Export all user data in JSON format (GDPR Article 20).

    Args:
        user_id: User ID to export
        requester_username: Username of the requester

    Returns:
        DataExportResponse with exported data

    Raises:
        LookupError: If user not found
    """
    exporter = get_user_data_exporter()
    export = exporter.export_user_data(user_id, format="json")

    if not export:
        raise LookupError(f"User not found: {user_id}")

    logger.info(f"User data exported: {user_id} (requested by {requester_username})")

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


def anonymize_user(
    user_id: str, requested_by: str, requester_username: str
) -> AnonymizeUserResponse:
    """Anonymize user data (GDPR Article 17).

    Args:
        user_id: User ID to anonymize
        requested_by: ID of user requesting anonymization
        requester_username: Username of the requester

    Returns:
        AnonymizeUserResponse

    Raises:
        LookupError: If user not found
        ValueError: If user already anonymized or other error
    """
    service = get_data_retention_service()
    result = service.anonymize_user(user_id, requested_by=requested_by)

    if not result.success:
        if "not found" in (result.error_message or "").lower():
            raise LookupError(result.error_message)
        else:
            raise ValueError(result.error_message)

    logger.info(
        f"User anonymized: {user_id} "
        f"(by {requester_username}, fields={len(result.fields_anonymized)})"
    )

    return AnonymizeUserResponse(
        success=result.success,
        user_id=result.user_id,
        fields_anonymized=result.fields_anonymized,
        audit_records_anonymized=result.audit_records_anonymized,
        error_message=result.error_message,
    )


def schedule_deletion(
    user_id: str, grace_days: int, requested_by: str, requester_username: str
) -> ScheduleDeletionResponse:
    """Schedule user deletion with grace period.

    Args:
        user_id: User ID to schedule for deletion
        grace_days: Number of grace days
        requested_by: ID of user requesting deletion
        requester_username: Username of the requester

    Returns:
        ScheduleDeletionResponse

    Raises:
        LookupError: If user not found
        RuntimeError: If scheduling fails
    """
    service = get_data_retention_service()
    success = service.schedule_deletion(user_id, days=grace_days, requested_by=requested_by)

    if not success:
        raise LookupError(f"User not found: {user_id}")

    status_info = service.get_retention_status(user_id)

    logger.info(
        f"User deletion scheduled: {user_id} "
        f"(by {requester_username}, date={status_info.deletion_date})"
    )

    if not status_info.deletion_date:
        raise RuntimeError("Deletion scheduling failed - no date set")

    return ScheduleDeletionResponse(
        success=True,
        user_id=user_id,
        deletion_date=status_info.deletion_date,
        grace_days=grace_days,
        message=f"User deletion scheduled for {status_info.deletion_date.date()}. "
        f"You can cancel before this date.",
    )


def cancel_deletion(user_id: str, requester_username: str) -> None:
    """Cancel scheduled user deletion.

    Args:
        user_id: User ID to cancel deletion for
        requester_username: Username of the requester

    Raises:
        ValueError: If no deletion scheduled
    """
    service = get_data_retention_service()
    success = service.cancel_scheduled_deletion(user_id)

    if not success:
        raise ValueError("No deletion scheduled for this user")

    logger.info(f"User deletion cancelled: {user_id} (by {requester_username})")


def get_retention_status(user_id: str) -> RetentionStatusResponse:
    """Get user data retention status.

    Args:
        user_id: User ID to check

    Returns:
        RetentionStatusResponse
    """
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


def purge_expired_data(requester_username: str) -> PurgeExpiredDataResponse:
    """Purge all data past retention period.

    Args:
        requester_username: Username of the requester

    Returns:
        PurgeExpiredDataResponse
    """
    service = get_data_retention_service()
    result = service.purge_expired_data()

    logger.info(
        f"Data purge completed by {requester_username}: "
        f"users={result.users_deleted}, audit_records={result.audit_records_purged}"
    )

    return PurgeExpiredDataResponse(
        success=result.success,
        users_deleted=result.users_deleted,
        audit_records_purged=result.audit_records_purged,
        documents_deleted=result.documents_deleted,
        error_message=result.error_message,
    )


__all__ = [
    "anonymize_user",
    "cancel_deletion",
    "export_user_data",
    "get_retention_status",
    "purge_expired_data",
    "schedule_deletion",
]

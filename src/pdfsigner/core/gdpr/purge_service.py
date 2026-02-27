"""
purge_service.py - GDPR data purge operations

Extracted from data_retention.py to reduce file size.
Contains purge_expired_data logic for removing data past retention period.

GDPR: Article 17 - Right to erasure ("right to be forgotten")
"""

from datetime import UTC, datetime

from loguru import logger

from pdfsigner.core.audit import AuditEventType
from pdfsigner.core.gdpr.data_retention_types import PurgeResult


def purge_expired_users(
    user_repo,
    audit_logger,
    anonymize_user_fn,
    is_user_anonymized_fn,
) -> PurgeResult:
    """
    Remove data past retention period.

    Deletes users whose deletion_date has passed.
    Optionally anonymizes audit logs before deletion.

    Args:
        user_repo: UserRepository instance for DB access.
        audit_logger: AuditLogger instance for event logging.
        anonymize_user_fn: Callable(user_id, requested_by) -> AnonymizationResult.
        is_user_anonymized_fn: Callable(user_id) -> bool.

    Returns:
        PurgeResult with counts of deleted items.
    """
    logger.info("Starting purge of expired data")

    try:
        users_deleted = 0
        audit_records_purged = 0
        documents_deleted = 0
        failed_users: list[str] = []

        # Find users with deletion_date in the past
        with user_repo._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, username FROM users
                WHERE deletion_date IS NOT NULL
                AND deletion_date <= ?
                """,
                (datetime.now(UTC).isoformat(),),
            )
            expired_users = cursor.fetchall()

        logger.info(f"Found {len(expired_users)} users to purge")

        # Delete each user
        for row in expired_users:
            user_id = row[0]
            username = row[1]

            try:
                # Anonymize first if not already done
                if not is_user_anonymized_fn(user_id):
                    result = anonymize_user_fn(user_id, "system")
                    if result.success:
                        audit_records_purged += result.audit_records_anonymized

                # Hard delete user
                if user_repo.delete_user(user_id):
                    users_deleted += 1
                    logger.info(f"Purged user: {username} (id={user_id})")

            except Exception as e:
                logger.error(f"Failed to purge user {user_id}: {e}")
                failed_users.append(user_id)

        # Log purge event
        _log_purge_event(audit_logger, users_deleted, audit_records_purged, failed_users)

        logger.info(
            f"Data purge completed: {users_deleted} users, {audit_records_purged} audit records"
        )

        return PurgeResult(
            success=True,
            users_deleted=users_deleted,
            audit_records_purged=audit_records_purged,
            documents_deleted=documents_deleted,
            failed_users=failed_users if failed_users else None,
        )

    except Exception as e:
        logger.error(f"Failed to purge expired data: {e}")
        return PurgeResult(
            success=False,
            users_deleted=0,
            audit_records_purged=0,
            documents_deleted=0,
            error_message=str(e),
        )


def _log_purge_event(
    audit_logger,
    users_deleted: int,
    audit_records_purged: int,
    failed_users: list[str],
) -> None:
    """Log the purge event to the audit trail."""
    from pdfsigner.core.audit import AuditEvent

    event = AuditEvent(
        event_type=AuditEventType.SYSTEM_EVENT,
        status="SUCCESS",
        user_id="system",
        details={
            "action": "purge_expired_data",
            "users_deleted": users_deleted,
            "audit_records_purged": audit_records_purged,
            "failed_users": failed_users,
        },
    )
    audit_logger.log_event(event)

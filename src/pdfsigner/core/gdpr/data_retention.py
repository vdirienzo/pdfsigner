"""
data_retention.py - GDPR data retention and erasure service

Implements:
- User anonymization (pseudonymization per GDPR Article 17)
- Scheduled deletion with grace period
- Automatic purging of expired data
- Retention policy enforcement

GDPR: Article 17 - Right to erasure ("right to be forgotten")
"""

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from loguru import logger

from pdfsigner.core.audit import AuditEventType, get_audit_logger
from pdfsigner.core.users import UserStatus, get_user_repository


@dataclass
class AnonymizationResult:
    """Result of user anonymization operation."""

    success: bool
    user_id: str
    fields_anonymized: list[str]
    audit_records_anonymized: int
    error_message: str | None = None


@dataclass
class PurgeResult:
    """Result of data purge operation."""

    success: bool
    users_deleted: int
    audit_records_purged: int
    documents_deleted: int
    error_message: str | None = None


@dataclass
class RetentionStatus:
    """User data retention status."""

    user_id: str
    is_anonymized: bool
    deletion_scheduled: bool
    deletion_scheduled_at: datetime | None
    deletion_date: datetime | None
    days_until_deletion: int | None


class DataRetentionService:
    """
    GDPR-compliant data retention and erasure service.

    Provides user anonymization, scheduled deletion, and automated
    data purging based on retention policies.
    """

    def __init__(
        self,
        user_repository=None,
        audit_logger=None,
        retention_days: int = 365,
        grace_days: int = 30,
        anonymize_audit_logs: bool = True,
    ):
        """
        Initialize data retention service.

        Args:
            user_repository: UserRepository instance (default: singleton)
            audit_logger: AuditLogger instance (default: singleton)
            retention_days: Days to retain user data after deletion request
            grace_days: Grace period before actual deletion
            anonymize_audit_logs: Whether to anonymize audit logs on deletion
        """

        self.user_repo = user_repository or get_user_repository()
        self.audit_logger = audit_logger or get_audit_logger()
        self.retention_days = retention_days
        self.grace_days = grace_days
        self.anonymize_audit_logs = anonymize_audit_logs

        # Ensure deletion tracking columns exist
        self._ensure_deletion_columns()

    def _ensure_deletion_columns(self) -> None:
        """Add deletion tracking columns to users table if not exist."""
        try:
            with self.user_repo._get_connection() as conn:
                # Check if columns exist
                cursor = conn.execute("PRAGMA table_info(users)")
                columns = {row[1] for row in cursor.fetchall()}

                # Add missing columns
                if "is_anonymized" not in columns:
                    conn.execute("ALTER TABLE users ADD COLUMN is_anonymized INTEGER DEFAULT 0")
                    logger.info("Added is_anonymized column to users table")

                if "deletion_scheduled_at" not in columns:
                    conn.execute("ALTER TABLE users ADD COLUMN deletion_scheduled_at TEXT")
                    logger.info("Added deletion_scheduled_at column to users table")

                if "deletion_date" not in columns:
                    conn.execute("ALTER TABLE users ADD COLUMN deletion_date TEXT")
                    logger.info("Added deletion_date column to users table")

        except sqlite3.Error as e:
            logger.error(f"Failed to add deletion tracking columns: {e}")

    def anonymize_user(self, user_id: str, requested_by: str) -> AnonymizationResult:
        """
        Anonymize user data (pseudonymization per GDPR Article 17).

        Replaces personally identifiable information with pseudonyms while
        preserving user ID for audit trail integrity.

        Args:
            user_id: User ID to anonymize
            requested_by: User ID of person requesting anonymization

        Returns:
            AnonymizationResult with operation details
        """
        logger.info(f"Starting user anonymization: {user_id} (requested by {requested_by})")

        try:
            # Get user
            user = self.user_repo.get_user_by_id(user_id)
            if not user:
                return AnonymizationResult(
                    success=False,
                    user_id=user_id,
                    fields_anonymized=[],
                    audit_records_anonymized=0,
                    error_message=f"User not found: {user_id}",
                )

            # Check if already anonymized
            if self._is_user_anonymized(user_id):
                return AnonymizationResult(
                    success=False,
                    user_id=user_id,
                    fields_anonymized=[],
                    audit_records_anonymized=0,
                    error_message="User is already anonymized",
                )

            # Create hash for pseudonymization
            user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:8]

            # Track anonymized fields
            fields_anonymized = []

            # Anonymize user data
            original_username = user.username
            user.username = f"anonymous_{user_hash}"
            user.display_name = f"Anonymous User [{user_hash}]"
            user.email = f"{user_hash}@anonymized.local"
            user.status = UserStatus.INACTIVE
            fields_anonymized.extend(["username", "display_name", "email", "status"])

            # Clear optional fields
            if user.certificate_cn:
                user.certificate_cn = None
                fields_anonymized.append("certificate_cn")

            # Update metadata
            user.metadata["anonymized_at"] = datetime.now(UTC).isoformat()
            user.metadata["anonymized_by"] = requested_by
            user.metadata["original_username"] = original_username
            fields_anonymized.append("metadata")

            # Save changes to database
            self.user_repo.update_user(user)

            # Mark as anonymized in database
            self._mark_user_anonymized(user_id)

            # Anonymize audit log entries if enabled
            audit_records_anonymized = 0
            if self.anonymize_audit_logs:
                audit_records_anonymized = self._anonymize_audit_records(user_id, user_hash)

            # Log anonymization event
            from pdfsigner.core.audit import AuditEvent

            event = AuditEvent(
                event_type=AuditEventType.USER_DELETE,  # Closest event type
                status="SUCCESS",
                user_id=requested_by,
                details={
                    "action": "anonymize_user",
                    "target_user_id": user_id,
                    "fields_anonymized": fields_anonymized,
                    "audit_records_anonymized": audit_records_anonymized,
                },
            )
            self.audit_logger.log_event(event)

            logger.info(
                f"User anonymized: {user_id} "
                f"(fields={len(fields_anonymized)}, audit_records={audit_records_anonymized})"
            )

            return AnonymizationResult(
                success=True,
                user_id=user_id,
                fields_anonymized=fields_anonymized,
                audit_records_anonymized=audit_records_anonymized,
            )

        except Exception as e:
            logger.error(f"Failed to anonymize user {user_id}: {e}")
            return AnonymizationResult(
                success=False,
                user_id=user_id,
                fields_anonymized=[],
                audit_records_anonymized=0,
                error_message=str(e),
            )

    def schedule_deletion(self, user_id: str, days: int, requested_by: str) -> bool:
        """
        Schedule user deletion with grace period.

        User can cancel deletion before the deletion date.

        Args:
            user_id: User ID to schedule for deletion
            days: Days until deletion (overrides default grace_days)
            requested_by: User ID of person requesting deletion

        Returns:
            True if scheduling succeeded
        """
        logger.info(f"Scheduling user deletion: {user_id} in {days} days (by {requested_by})")

        try:
            # Get user
            user = self.user_repo.get_user_by_id(user_id)
            if not user:
                logger.error(f"Cannot schedule deletion: User not found: {user_id}")
                return False

            # Calculate deletion date
            scheduled_at = datetime.now(UTC)
            deletion_date = scheduled_at + timedelta(days=days)

            # Update database
            with self.user_repo._get_connection() as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET deletion_scheduled_at = ?, deletion_date = ?
                    WHERE id = ?
                    """,
                    (scheduled_at.isoformat(), deletion_date.isoformat(), user_id),
                )

            # Log event
            from pdfsigner.core.audit import AuditEvent

            event = AuditEvent(
                event_type=AuditEventType.USER_DELETE,
                status="SUCCESS",
                user_id=requested_by,
                details={
                    "action": "schedule_deletion",
                    "target_user_id": user_id,
                    "scheduled_at": scheduled_at.isoformat(),
                    "deletion_date": deletion_date.isoformat(),
                    "grace_days": days,
                },
            )
            self.audit_logger.log_event(event)

            logger.info(f"User deletion scheduled: {user_id} on {deletion_date.date()}")
            return True

        except Exception as e:
            logger.error(f"Failed to schedule deletion for user {user_id}: {e}")
            return False

    def cancel_scheduled_deletion(self, user_id: str) -> bool:
        """
        Cancel pending deletion.

        Args:
            user_id: User ID to cancel deletion for

        Returns:
            True if cancellation succeeded
        """
        logger.info(f"Cancelling scheduled deletion: {user_id}")

        try:
            # Check if deletion is scheduled
            status = self.get_retention_status(user_id)
            if not status.deletion_scheduled:
                logger.warning(f"No deletion scheduled for user: {user_id}")
                return False

            # Clear deletion schedule
            with self.user_repo._get_connection() as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET deletion_scheduled_at = NULL, deletion_date = NULL
                    WHERE id = ?
                    """,
                    (user_id,),
                )

            # Log event
            from pdfsigner.core.audit import AuditEvent

            event = AuditEvent(
                event_type=AuditEventType.USER_UPDATE,
                status="SUCCESS",
                user_id=user_id,
                details={
                    "action": "cancel_scheduled_deletion",
                    "target_user_id": user_id,
                },
            )
            self.audit_logger.log_event(event)

            logger.info(f"Scheduled deletion cancelled: {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to cancel deletion for user {user_id}: {e}")
            return False

    def purge_expired_data(self) -> PurgeResult:
        """
        Remove data past retention period.

        Deletes users whose deletion_date has passed.
        Optionally anonymizes audit logs.

        Returns:
            PurgeResult with counts of deleted items
        """
        logger.info("Starting purge of expired data")

        try:
            users_deleted = 0
            audit_records_purged = 0
            documents_deleted = 0

            # Find users with deletion_date in the past
            with self.user_repo._get_connection() as conn:
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
                    if not self._is_user_anonymized(user_id):
                        result = self.anonymize_user(user_id, "system")
                        if result.success:
                            audit_records_purged += result.audit_records_anonymized

                    # Hard delete user
                    if self.user_repo.delete_user(user_id):
                        users_deleted += 1
                        logger.info(f"Purged user: {username} (id={user_id})")

                except Exception as e:
                    logger.error(f"Failed to purge user {user_id}: {e}")

            # Log purge event
            from pdfsigner.core.audit import AuditEvent

            event = AuditEvent(
                event_type=AuditEventType.SYSTEM_EVENT,
                status="SUCCESS",
                user_id="system",
                details={
                    "action": "purge_expired_data",
                    "users_deleted": users_deleted,
                    "audit_records_purged": audit_records_purged,
                },
            )
            self.audit_logger.log_event(event)

            logger.info(
                f"Data purge completed: {users_deleted} users, {audit_records_purged} audit records"
            )

            return PurgeResult(
                success=True,
                users_deleted=users_deleted,
                audit_records_purged=audit_records_purged,
                documents_deleted=documents_deleted,
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

    def get_retention_status(self, user_id: str) -> RetentionStatus:
        """
        Get user data retention status.

        Args:
            user_id: User ID to check

        Returns:
            RetentionStatus with deletion schedule information
        """
        try:
            with self.user_repo._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT is_anonymized, deletion_scheduled_at, deletion_date
                    FROM users WHERE id = ?
                    """,
                    (user_id,),
                )
                row = cursor.fetchone()

                if not row:
                    # User not found - return empty status
                    return RetentionStatus(
                        user_id=user_id,
                        is_anonymized=False,
                        deletion_scheduled=False,
                        deletion_scheduled_at=None,
                        deletion_date=None,
                        days_until_deletion=None,
                    )

                is_anonymized = bool(row[0])
                deletion_scheduled_at = row[1]
                deletion_date = row[2]

                # Parse dates
                deletion_scheduled = deletion_date is not None
                deletion_date_obj = None
                days_until_deletion = None

                if deletion_date:
                    deletion_date_obj = datetime.fromisoformat(deletion_date)
                    days_until_deletion = (deletion_date_obj - datetime.now(UTC)).days

                scheduled_at_obj = None
                if deletion_scheduled_at:
                    scheduled_at_obj = datetime.fromisoformat(deletion_scheduled_at)

                return RetentionStatus(
                    user_id=user_id,
                    is_anonymized=is_anonymized,
                    deletion_scheduled=deletion_scheduled,
                    deletion_scheduled_at=scheduled_at_obj,
                    deletion_date=deletion_date_obj,
                    days_until_deletion=days_until_deletion,
                )

        except Exception as e:
            logger.error(f"Failed to get retention status for user {user_id}: {e}")
            return RetentionStatus(
                user_id=user_id,
                is_anonymized=False,
                deletion_scheduled=False,
                deletion_scheduled_at=None,
                deletion_date=None,
                days_until_deletion=None,
            )

    def _is_user_anonymized(self, user_id: str) -> bool:
        """Check if user is already anonymized."""
        try:
            with self.user_repo._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT is_anonymized FROM users WHERE id = ?",
                    (user_id,),
                )
                row = cursor.fetchone()
                return bool(row[0]) if row else False
        except Exception:
            return False

    def _mark_user_anonymized(self, user_id: str) -> None:
        """Mark user as anonymized in database."""
        try:
            with self.user_repo._get_connection() as conn:
                conn.execute(
                    "UPDATE users SET is_anonymized = 1 WHERE id = ?",
                    (user_id,),
                )
        except Exception as e:
            logger.error(f"Failed to mark user as anonymized: {e}")

    def _anonymize_audit_records(self, user_id: str, user_hash: str) -> int:
        """
        Anonymize user references in audit logs.

        Replaces user_id with anonymized identifier in all audit records.

        Args:
            user_id: Original user ID
            user_hash: Anonymized hash to use

        Returns:
            Number of records anonymized
        """
        if not self.audit_logger.enabled:
            return 0

        try:
            anonymized_count = 0
            audit_dir = Path(self.audit_logger.log_dir)

            # Process all audit log files
            for log_file in audit_dir.glob("audit_*.jsonl"):
                try:
                    # Read all lines
                    with open(log_file, encoding="utf-8") as f:
                        lines = f.readlines()

                    # Replace user references
                    modified = False
                    new_lines = []
                    for line in lines:
                        if user_id in line:
                            # Replace user_id with anonymized version
                            line = line.replace(user_id, f"anonymized_{user_hash}")
                            modified = True
                            anonymized_count += 1
                        new_lines.append(line)

                    # Write back if modified
                    if modified:
                        with open(log_file, "w", encoding="utf-8") as f:
                            f.writelines(new_lines)

                except Exception as e:
                    logger.warning(f"Failed to anonymize audit log {log_file.name}: {e}")

            logger.debug(f"Anonymized {anonymized_count} audit records for user {user_id}")
            return anonymized_count

        except Exception as e:
            logger.error(f"Failed to anonymize audit records: {e}")
            return 0


# Singleton instance
_data_retention_service: DataRetentionService | None = None


def get_data_retention_service() -> DataRetentionService:
    """Get singleton data retention service."""
    global _data_retention_service
    if _data_retention_service is None:
        from pdfsigner.config.settings import get_settings

        settings = get_settings()
        _data_retention_service = DataRetentionService(
            retention_days=settings.gdpr_retention_days,
            grace_days=settings.gdpr_deletion_grace_days,
            anonymize_audit_logs=settings.gdpr_anonymize_audit_logs,
        )
    return _data_retention_service

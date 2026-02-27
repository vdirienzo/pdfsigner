"""
anonymization_service.py - GDPR user anonymization service

Implements user data anonymization (pseudonymization per GDPR Article 17).
Replaces PII with pseudonyms while preserving user ID for audit trail integrity.

GDPR: Article 17 - Right to erasure ("right to be forgotten")
"""

import hashlib
from pathlib import Path

from loguru import logger

from pdfsigner.core.audit import AuditEventType
from pdfsigner.core.gdpr.data_retention_types import AnonymizationResult
from pdfsigner.core.users import UserStatus


class AnonymizationService:
    """
    Handles user data anonymization (pseudonymization).

    Replaces personally identifiable information with pseudonyms while
    preserving user ID for audit trail integrity.
    """

    def __init__(self, user_repository, audit_logger, anonymize_audit_logs: bool = True):
        """
        Initialize anonymization service.

        Args:
            user_repository: UserRepository instance
            audit_logger: AuditLogger instance
            anonymize_audit_logs: Whether to anonymize audit logs on deletion
        """
        self.user_repo = user_repository
        self.audit_logger = audit_logger
        self.anonymize_audit_logs = anonymize_audit_logs

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

            # Anonymize user fields
            fields_anonymized = self._anonymize_user_fields(user, user_hash, requested_by)

            # Save changes to database
            self.user_repo.update_user(user)

            # Mark as anonymized in database
            self._mark_user_anonymized(user_id)

            # Anonymize audit log entries if enabled
            audit_records_anonymized = 0
            if self.anonymize_audit_logs:
                audit_records_anonymized = self._anonymize_audit_records(user_id, user_hash)

            # Log anonymization event
            self._log_anonymization_event(
                user_id, requested_by, fields_anonymized, audit_records_anonymized
            )

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

    def _anonymize_user_fields(self, user, user_hash: str, requested_by: str) -> list[str]:
        """
        Replace PII fields with pseudonymized values.

        Args:
            user: User object to anonymize (modified in place)
            user_hash: Hash for pseudonymization
            requested_by: User ID of person requesting anonymization

        Returns:
            List of field names that were anonymized
        """
        from datetime import UTC, datetime

        fields_anonymized = []

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

        return fields_anonymized

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
        """Mark user as anonymized in database.

        Raises:
            sqlite3.Error: If the database update fails. Propagated to caller
                so anonymize_user() can report failure (GDPR Art. 17 compliance).
        """
        with self.user_repo._get_connection() as conn:
            conn.execute(
                "UPDATE users SET is_anonymized = 1 WHERE id = ?",
                (user_id,),
            )

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

    def _log_anonymization_event(
        self,
        user_id: str,
        requested_by: str,
        fields_anonymized: list[str],
        audit_records_anonymized: int,
    ) -> None:
        """Log the anonymization event to the audit trail."""
        from pdfsigner.core.audit import AuditEvent

        event = AuditEvent(
            event_type=AuditEventType.USER_DELETE,
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

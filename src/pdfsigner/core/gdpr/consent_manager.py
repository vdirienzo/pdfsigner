"""
consent_manager.py - GDPR consent management orchestration

Implements GDPR Article 7 consent requirements with audit trail.
"""

from datetime import datetime

from loguru import logger

from pdfsigner.core.audit import get_audit_logger
from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType
from pdfsigner.core.gdpr.consent_repository import (
    ConsentRecord,
    get_consent_repository,
)
from pdfsigner.core.gdpr.consent_types import ConsentType


class ConsentManager:
    """
    Manage user consent for GDPR Article 7 compliance.

    Orchestrates consent operations with audit trail integration.
    All consent actions (grant, withdraw) are logged for compliance.
    """

    def __init__(self, consent_repository=None, audit_logger=None):
        """
        Initialize consent manager.

        Args:
            consent_repository: ConsentRepository instance (default: singleton)
            audit_logger: AuditLogger instance (default: singleton)
        """
        self.consent_repo = consent_repository or get_consent_repository()
        self.audit_logger = audit_logger or get_audit_logger()

    def grant_consent(
        self,
        user_id: str,
        consent_type: ConsentType,
        ip_address: str | None = None,
        user_agent: str | None = None,
        policy_version: str | None = None,
    ) -> ConsentRecord:
        """
        Record user consent grant.

        GDPR Article 7(1): Consent must be freely given, specific, informed, and unambiguous.

        Args:
            user_id: User ID granting consent
            consent_type: Type of consent being granted
            ip_address: IP address when consent was granted
            user_agent: User agent when consent was granted
            policy_version: Version of privacy policy accepted

        Returns:
            New consent record
        """
        import uuid

        consent = ConsentRecord(
            id=str(uuid.uuid4()),
            user_id=user_id,
            consent_type=consent_type,
            granted=True,
            granted_at=datetime.now(),
            withdrawn_at=None,
            ip_address=ip_address,
            user_agent=user_agent,
            policy_version=policy_version,
        )

        # Save to database
        saved_consent = self.consent_repo.save_consent(consent)

        # Log audit event
        if self.audit_logger.enabled:
            event = AuditEvent(
                event_type=AuditEventType.SYSTEM_EVENT,
                status="SUCCESS",
                user_id=user_id,
                details={
                    "action": "consent_granted",
                    "consent_type": consent_type.value,
                    "consent_id": saved_consent.id,
                    "policy_version": policy_version,
                    "ip_address": ip_address,
                },
            )
            self.audit_logger.log_event(event)

        logger.info(f"Consent granted: user={user_id}, type={consent_type.value}")
        return saved_consent

    def withdraw_consent(
        self,
        user_id: str,
        consent_type: ConsentType,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> ConsentRecord:
        """
        Withdraw user consent.

        GDPR Article 7(3): Withdrawal of consent must be as easy as giving consent.

        Args:
            user_id: User ID withdrawing consent
            consent_type: Type of consent to withdraw
            ip_address: IP address when consent was withdrawn
            user_agent: User agent when consent was withdrawn

        Returns:
            New consent record with granted=False

        Raises:
            ValueError: If no active consent exists to withdraw
        """
        # Check if there's an active consent to withdraw
        latest = self.consent_repo.get_latest_consent(user_id, consent_type)
        if not latest or not latest.granted or latest.withdrawn_at is not None:
            raise ValueError(
                f"No active consent found for user={user_id}, type={consent_type.value}"
            )

        # Record withdrawal
        withdrawn_at = datetime.now()
        withdrawal_record = self.consent_repo.withdraw_consent(
            user_id=user_id,
            consent_type=consent_type,
            withdrawn_at=withdrawn_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Log audit event
        if self.audit_logger.enabled:
            event = AuditEvent(
                event_type=AuditEventType.SYSTEM_EVENT,
                status="SUCCESS",
                user_id=user_id,
                details={
                    "action": "consent_withdrawn",
                    "consent_type": consent_type.value,
                    "consent_id": withdrawal_record.id,
                    "original_consent_id": latest.id,
                    "ip_address": ip_address,
                },
            )
            self.audit_logger.log_event(event)

        logger.info(f"Consent withdrawn: user={user_id}, type={consent_type.value}")
        return withdrawal_record

    def get_active_consents(self, user_id: str) -> list[ConsentRecord]:
        """
        Get all currently active consents for a user.

        Active consent = granted=True and withdrawn_at=None.

        Args:
            user_id: User ID to get consents for

        Returns:
            List of active consent records
        """
        all_consents = self.consent_repo.get_user_consents(user_id, active_only=False)

        # Get latest record for each consent type
        active_consents = []
        seen_types = set()

        for consent in all_consents:
            if consent.consent_type in seen_types:
                continue

            # This is the latest record for this type
            if consent.granted and consent.withdrawn_at is None:
                active_consents.append(consent)

            seen_types.add(consent.consent_type)

        return active_consents

    def get_consent_audit_trail(self, user_id: str) -> list[ConsentRecord]:
        """
        Get complete consent audit trail for a user.

        Returns all consent actions (grants and withdrawals) for all types.

        Args:
            user_id: User ID to get audit trail for

        Returns:
            List of all consent records, ordered by granted_at descending
        """
        return self.consent_repo.get_user_consents(user_id, active_only=False)

    def has_consent(self, user_id: str, consent_type: ConsentType) -> bool:
        """
        Check if user has active consent for a specific type.

        Args:
            user_id: User ID to check
            consent_type: Type of consent to check

        Returns:
            True if user has active consent, False otherwise
        """
        latest = self.consent_repo.get_latest_consent(user_id, consent_type)
        if not latest:
            return False

        return latest.granted and latest.withdrawn_at is None

    def get_consent_summary(self, user_id: str) -> dict[ConsentType, bool]:
        """
        Get summary of all consent types and their current status.

        Args:
            user_id: User ID to get summary for

        Returns:
            Dictionary mapping consent types to their active status
        """
        active = self.get_active_consents(user_id)
        active_types = {c.consent_type for c in active}

        return {consent_type: consent_type in active_types for consent_type in ConsentType}


# Singleton instance
_consent_manager: ConsentManager | None = None


def get_consent_manager() -> ConsentManager:
    """Get singleton consent manager."""
    global _consent_manager
    if _consent_manager is None:
        _consent_manager = ConsentManager()
    return _consent_manager


__all__ = ["ConsentManager", "get_consent_manager"]

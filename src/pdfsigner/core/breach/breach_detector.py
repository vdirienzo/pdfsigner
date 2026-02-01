"""
breach_detector.py - Breach detection rules and thresholds

Implements detection rules for various data breach scenarios.
"""

from datetime import datetime
from uuid import uuid4

from loguru import logger

from pdfsigner.core.breach.breach_types import (
    BreachIncident,
    BreachSeverity,
    BreachStatus,
    BreachType,
)


class BreachDetector:
    """
    Detects potential data breaches based on configurable thresholds.

    Monitors system events and activity patterns to identify
    potential security incidents requiring investigation.
    """

    def __init__(
        self,
        mass_export_threshold: int = 1000,
        failed_auth_threshold: int = 10,
        bulk_phi_threshold: int = 100,
        unusual_hour_start: int = 22,
        unusual_hour_end: int = 6,
    ):
        """
        Initialize detector with thresholds.

        Args:
            mass_export_threshold: Records exported to trigger alert
            failed_auth_threshold: Failed auth attempts to trigger alert
            bulk_phi_threshold: PHI records accessed to trigger alert
            unusual_hour_start: Hour when unusual access period starts (24h)
            unusual_hour_end: Hour when unusual access period ends (24h)
        """
        self.mass_export_threshold = mass_export_threshold
        self.failed_auth_threshold = failed_auth_threshold
        self.bulk_phi_threshold = bulk_phi_threshold
        self.unusual_hour_start = unusual_hour_start
        self.unusual_hour_end = unusual_hour_end

    def check_mass_export(
        self,
        records_count: int,
        user_id: str | None = None,
        source_ip: str | None = None,
        metadata: dict | None = None,
    ) -> BreachIncident | None:
        """
        Check for mass data export breach.

        Args:
            records_count: Number of records exported
            user_id: User performing export
            source_ip: Source IP address
            metadata: Additional context

        Returns:
            BreachIncident if threshold exceeded, None otherwise
        """
        if records_count > self.mass_export_threshold:
            severity = self._calculate_export_severity(records_count)

            logger.warning(
                f"Mass export detected: {records_count} records by user={user_id}, ip={source_ip}"
            )

            return BreachIncident(
                id=str(uuid4()),
                breach_type=BreachType.MASS_EXPORT,
                severity=severity,
                status=BreachStatus.DETECTED,
                description=f"Mass export of {records_count} records detected",
                affected_users=0,  # Will be determined during investigation
                affected_records=records_count,
                source_ip=source_ip,
                user_id=user_id,
                metadata=metadata or {},
            )

        return None

    def check_failed_auth(
        self,
        attempts: int,
        window_minutes: int = 60,
        user_id: str | None = None,
        source_ip: str | None = None,
        metadata: dict | None = None,
    ) -> BreachIncident | None:
        """
        Check for multiple failed authentication attempts.

        Args:
            attempts: Number of failed attempts
            window_minutes: Time window for attempts
            user_id: Target user ID
            source_ip: Source IP address
            metadata: Additional context

        Returns:
            BreachIncident if threshold exceeded, None otherwise
        """
        if attempts > self.failed_auth_threshold:
            # Higher severity for attacks from multiple IPs or targeting multiple users
            severity = BreachSeverity.HIGH if attempts > 50 else BreachSeverity.MEDIUM

            logger.warning(
                f"Multiple failed auth attempts: {attempts} in {window_minutes}min, "
                f"user={user_id}, ip={source_ip}"
            )

            return BreachIncident(
                id=str(uuid4()),
                breach_type=BreachType.FAILED_AUTH,
                severity=severity,
                status=BreachStatus.DETECTED,
                description=(
                    f"{attempts} failed authentication attempts in {window_minutes} minutes"
                ),
                affected_users=1 if user_id else 0,
                affected_records=0,
                source_ip=source_ip,
                user_id=user_id,
                metadata={
                    **(metadata or {}),
                    "window_minutes": window_minutes,
                    "attempts": attempts,
                },
            )

        return None

    def check_bulk_phi_access(
        self,
        records: int,
        window_minutes: int = 60,
        user_id: str | None = None,
        source_ip: str | None = None,
        metadata: dict | None = None,
    ) -> BreachIncident | None:
        """
        Check for bulk PHI/PII access.

        Args:
            records: Number of PHI records accessed
            window_minutes: Time window for access
            user_id: User accessing PHI
            source_ip: Source IP address
            metadata: Additional context

        Returns:
            BreachIncident if threshold exceeded, None otherwise
        """
        if records > self.bulk_phi_threshold:
            severity = self._calculate_phi_severity(records)

            logger.warning(
                f"Bulk PHI access detected: {records} records in {window_minutes}min, "
                f"user={user_id}, ip={source_ip}"
            )

            return BreachIncident(
                id=str(uuid4()),
                breach_type=BreachType.BULK_PHI_ACCESS,
                severity=severity,
                status=BreachStatus.DETECTED,
                description=f"Bulk access to {records} PHI records in {window_minutes} minutes",
                affected_users=0,  # Will be determined from records
                affected_records=records,
                source_ip=source_ip,
                user_id=user_id,
                metadata={**(metadata or {}), "window_minutes": window_minutes},
            )

        return None

    def check_unusual_hours(
        self,
        access_time: datetime,
        user_id: str | None = None,
        source_ip: str | None = None,
        action: str = "access",
        metadata: dict | None = None,
    ) -> BreachIncident | None:
        """
        Check for access during unusual hours.

        Args:
            access_time: Time of access
            user_id: User performing access
            source_ip: Source IP address
            action: Action performed
            metadata: Additional context

        Returns:
            BreachIncident if outside normal hours, None otherwise
        """
        hour = access_time.hour

        # Check if outside normal hours (default: 10PM - 6AM)
        is_unusual = hour >= self.unusual_hour_start or hour < self.unusual_hour_end

        if is_unusual:
            logger.warning(
                f"Unusual hours access: {access_time.isoformat()}, user={user_id}, "
                f"ip={source_ip}, action={action}"
            )

            return BreachIncident(
                id=str(uuid4()),
                breach_type=BreachType.UNUSUAL_HOURS,
                severity=BreachSeverity.MEDIUM,
                status=BreachStatus.DETECTED,
                description=(
                    f"Access during unusual hours: {access_time.strftime('%Y-%m-%d %H:%M')}"
                ),
                affected_users=0,
                affected_records=0,
                source_ip=source_ip,
                user_id=user_id,
                metadata={
                    **(metadata or {}),
                    "access_time": access_time.isoformat(),
                    "action": action,
                },
            )

        return None

    def check_emergency_access(
        self,
        user_id: str | None = None,
        source_ip: str | None = None,
        reason: str = "",
        metadata: dict | None = None,
    ) -> BreachIncident | None:
        """
        Check emergency (break-glass) access usage.

        Emergency access always generates an incident for audit trail.

        Args:
            user_id: User using emergency access
            source_ip: Source IP address
            reason: Justification for emergency access
            metadata: Additional context

        Returns:
            BreachIncident for tracking
        """
        logger.warning(f"Emergency access used: user={user_id}, ip={source_ip}, reason={reason}")

        return BreachIncident(
            id=str(uuid4()),
            breach_type=BreachType.EMERGENCY_ACCESS,
            severity=BreachSeverity.HIGH,  # Always high for audit trail
            status=BreachStatus.DETECTED,
            description=f"Emergency access used: {reason}",
            affected_users=0,
            affected_records=0,
            source_ip=source_ip,
            user_id=user_id,
            metadata={**(metadata or {}), "reason": reason},
        )

    def check_privilege_escalation(
        self,
        user_id: str,
        old_role: str,
        new_role: str,
        admin_id: str | None = None,
        source_ip: str | None = None,
        metadata: dict | None = None,
    ) -> BreachIncident | None:
        """
        Check for privilege escalation events.

        Args:
            user_id: User whose privileges changed
            old_role: Previous role
            new_role: New role
            admin_id: Admin who made the change
            source_ip: Source IP address
            metadata: Additional context

        Returns:
            BreachIncident if escalation detected (especially to admin)
        """
        # Role hierarchy: viewer < signer < auditor < admin
        role_levels = {"viewer": 0, "signer": 1, "auditor": 2, "admin": 3}

        old_level = role_levels.get(old_role.lower(), 0)
        new_level = role_levels.get(new_role.lower(), 0)

        if new_level > old_level:
            # Escalation to admin is always flagged
            severity = BreachSeverity.HIGH if new_role.lower() == "admin" else BreachSeverity.MEDIUM

            logger.warning(
                f"Privilege escalation: user={user_id}, {old_role}->{new_role}, "
                f"by_admin={admin_id}, ip={source_ip}"
            )

            return BreachIncident(
                id=str(uuid4()),
                breach_type=BreachType.PRIVILEGE_ESCALATION,
                severity=severity,
                status=BreachStatus.DETECTED,
                description=f"Privilege escalation from {old_role} to {new_role}",
                affected_users=1,
                affected_records=0,
                source_ip=source_ip,
                user_id=user_id,
                metadata={
                    **(metadata or {}),
                    "old_role": old_role,
                    "new_role": new_role,
                    "admin_id": admin_id,
                },
            )

        return None

    def detect_anomaly(self, event_type: str, **kwargs) -> BreachIncident | None:
        """
        Generic anomaly detection dispatcher.

        Args:
            event_type: Type of event to check
            **kwargs: Event-specific parameters

        Returns:
            BreachIncident if anomaly detected, None otherwise
        """
        handlers = {
            "mass_export": self.check_mass_export,
            "failed_auth": self.check_failed_auth,
            "bulk_phi_access": self.check_bulk_phi_access,
            "unusual_hours": self.check_unusual_hours,
            "emergency_access": self.check_emergency_access,
            "privilege_escalation": self.check_privilege_escalation,
        }

        handler = handlers.get(event_type)
        if handler:
            return handler(**kwargs)

        logger.debug(f"No handler for event type: {event_type}")
        return None

    # --- Private helpers ---

    def _calculate_export_severity(self, records: int) -> BreachSeverity:
        """Calculate severity based on number of records exported."""
        if records > 10000:
            return BreachSeverity.CRITICAL
        elif records > 5000:
            return BreachSeverity.HIGH
        elif records > 2000:
            return BreachSeverity.MEDIUM
        else:
            return BreachSeverity.LOW

    def _calculate_phi_severity(self, records: int) -> BreachSeverity:
        """Calculate severity based on PHI records accessed."""
        if records > 5000:
            return BreachSeverity.CRITICAL
        elif records > 1000:
            return BreachSeverity.HIGH
        elif records > 500:
            return BreachSeverity.MEDIUM
        else:
            return BreachSeverity.LOW

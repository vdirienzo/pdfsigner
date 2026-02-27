"""
breach_manager.py - Breach incident orchestration

Manages breach detection, investigation, and notification workflow.
"""

from datetime import datetime

from loguru import logger

from pdfsigner.core.audit import get_audit_logger
from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType
from pdfsigner.core.breach.breach_detector import BreachDetector
from pdfsigner.core.breach.breach_repository import BreachRepository, get_breach_repository
from pdfsigner.core.breach.breach_types import (
    BreachIncident,
    BreachSeverity,
    BreachStatus,
    BreachType,
)
from pdfsigner.exceptions import PDFSignerError


class BreachManagerError(PDFSignerError):
    """Breach manager specific errors."""

    pass


class BreachManager:
    """
    Orchestrates breach detection, tracking, and response.

    Integrates breach detection, storage, and audit logging to provide
    complete incident management workflow.
    """

    def __init__(
        self,
        repository: BreachRepository | None = None,
        detector: BreachDetector | None = None,
    ):
        """
        Initialize breach manager.

        Args:
            repository: Breach repository (default: singleton)
            detector: Breach detector (default: new instance with defaults)
        """
        self.repository = repository or get_breach_repository()
        self.detector = detector or BreachDetector()
        self.audit_logger = get_audit_logger()

    def report_breach(
        self,
        breach_type: BreachType,
        severity: BreachSeverity,
        description: str,
        affected_users: int = 0,
        affected_records: int = 0,
        user_id: str | None = None,
        source_ip: str | None = None,
        metadata: dict | None = None,
    ) -> BreachIncident:
        """
        Report a data breach incident.

        Args:
            breach_type: Type of breach
            severity: Severity level
            description: Detailed description
            affected_users: Number of affected users
            affected_records: Number of affected records
            user_id: User associated with breach
            source_ip: Source IP address
            metadata: Additional context

        Returns:
            Created breach incident

        Raises:
            BreachManagerError: If breach reporting fails
        """
        try:
            # Create incident
            incident = BreachIncident(
                breach_type=breach_type,
                severity=severity,
                status=BreachStatus.DETECTED,
                description=description,
                affected_users=affected_users,
                affected_records=affected_records,
                user_id=user_id,
                source_ip=source_ip,
                metadata=metadata or {},
            )

            # Save to repository
            incident = self.repository.save_incident(incident)

            # Log to audit trail
            self._log_breach_event(
                event_type=AuditEventType.SYSTEM_EVENT,
                incident=incident,
                status="DETECTED",
            )

            logger.warning(
                f"Breach reported: id={incident.id}, type={breach_type.value}, "
                f"severity={severity.value}, affected_records={affected_records}"
            )

            return incident

        except Exception as e:
            logger.error(f"Failed to report breach: {e}")
            raise BreachManagerError(f"Failed to report breach: {e}") from e

    def update_breach_status(
        self,
        incident_id: str,
        new_status: BreachStatus,
        note: str = "",
    ) -> BreachIncident:
        """
        Update breach incident status.

        Args:
            incident_id: Incident ID
            new_status: New status
            note: Optional note about status change

        Returns:
            Updated incident

        Raises:
            BreachManagerError: If incident not found or update fails
        """
        try:
            incident = self.repository.update_status(incident_id, new_status, note)

            if not incident:
                raise BreachManagerError(f"Breach incident not found: {incident_id}")

            # Log status change
            self._log_breach_event(
                event_type=AuditEventType.SYSTEM_EVENT,
                incident=incident,
                status=new_status.value.upper(),
            )

            logger.info(
                f"Breach status updated: id={incident_id}, status={new_status.value}, note={note}"
            )

            return incident

        except Exception as e:
            if isinstance(e, BreachManagerError):
                raise
            logger.error(f"Failed to update breach status: {e}")
            raise BreachManagerError(f"Failed to update breach status: {e}") from e

    def get_active_breaches(self) -> list[BreachIncident]:
        """
        Get all active (unresolved) breach incidents.

        Returns:
            List of active breach incidents
        """
        try:
            # Get all incidents that are not resolved
            all_incidents = self.repository.list_incidents(limit=1000)
            active = [
                inc
                for inc in all_incidents
                if inc.status not in [BreachStatus.RESOLVED, BreachStatus.NOTIFIED]
            ]

            logger.debug(f"Retrieved {len(active)} active breach incidents")
            return active

        except Exception as e:
            logger.error(f"Failed to get active breaches: {e}")
            return []

    def get_breach_timeline(self, incident_id: str) -> list[dict]:
        """
        Get status change timeline for an incident.

        Args:
            incident_id: Incident ID

        Returns:
            List of status changes with timestamps

        Raises:
            BreachManagerError: If incident not found
        """
        try:
            incident = self.repository.get_incident(incident_id)

            if not incident:
                raise BreachManagerError(f"Breach incident not found: {incident_id}")

            return incident.status_history

        except Exception as e:
            if isinstance(e, BreachManagerError):
                raise
            logger.error(f"Failed to get breach timeline: {e}")
            raise BreachManagerError(f"Failed to get breach timeline: {e}") from e

    def detect_and_report(self, event_type: str, **kwargs) -> BreachIncident | None:
        """
        Detect potential breach and auto-report if found.

        Args:
            event_type: Type of event to check
            **kwargs: Event-specific parameters

        Returns:
            Created breach incident if detected, None otherwise
        """
        try:
            # Run detection
            incident = self.detector.detect_anomaly(event_type, **kwargs)

            if incident:
                # Save and log
                incident = self.repository.save_incident(incident)

                self._log_breach_event(
                    event_type=AuditEventType.SYSTEM_EVENT,
                    incident=incident,
                    status="DETECTED",
                )

                logger.warning(
                    f"Breach auto-detected: id={incident.id}, type={incident.breach_type.value}"
                )

            return incident

        except Exception as e:
            logger.error(f"Failed to detect and report breach: {e}")
            return None

    def get_incident(self, incident_id: str) -> BreachIncident | None:
        """
        Get breach incident by ID.

        Args:
            incident_id: Incident ID

        Returns:
            BreachIncident if found, None otherwise
        """
        return self.repository.get_incident(incident_id)

    def list_incidents(
        self,
        status: BreachStatus | None = None,
        severity: BreachSeverity | None = None,
        user_id: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[BreachIncident]:
        """
        List incidents with filters.

        Args:
            status: Filter by status
            severity: Filter by severity
            user_id: Filter by user
            start_date: Filter by detection date (after)
            end_date: Filter by detection date (before)
            limit: Maximum results
            offset: Pagination offset

        Returns:
            List of matching incidents
        """
        return self.repository.list_incidents(
            status=status,
            severity=severity,
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
        )

    def _log_breach_event(
        self,
        event_type: AuditEventType,
        incident: BreachIncident,
        status: str,
    ) -> None:
        """
        Log breach event to audit trail.

        Args:
            event_type: Audit event type
            incident: Breach incident
            status: Event status
        """
        event = AuditEvent(
            event_type=event_type,
            user_id=incident.user_id,
            status=status,
            details={
                "breach_id": incident.id,
                "breach_type": incident.breach_type.value,
                "severity": incident.severity.value,
                "affected_users": incident.affected_users,
                "affected_records": incident.affected_records,
                "description": incident.description,
            },
        )

        self.audit_logger.log_event(event)


# Singleton instance
_breach_manager: BreachManager | None = None


def get_breach_manager() -> BreachManager:
    """Get singleton breach manager."""
    global _breach_manager
    if _breach_manager is None:
        _breach_manager = BreachManager()
    return _breach_manager

"""
Breach notification service.

Business logic for breach detection, tracking, notification,
and reporting per GDPR Art. 33-34 and HIPAA.
"""

from datetime import UTC, datetime

from loguru import logger

from pdfsigner.api.schemas.breach import (
    BreachIncidentResponse,
    BreachNotificationResponse,
    BreachSummaryResponse,
)
from pdfsigner.core.breach import (
    BreachSeverity,
    BreachStatus,
    BreachType,
    generate_summary_report,
    get_breach_manager,
)
from pdfsigner.core.breach.breach_manager import BreachManagerError
from pdfsigner.core.breach.notification_service import (
    NotificationChannel,
    NotificationService,
)


def incident_to_response(incident) -> BreachIncidentResponse:
    """Convert BreachIncident to API response model."""
    return BreachIncidentResponse(
        id=incident.id,
        breach_type=incident.breach_type.value,
        severity=incident.severity.value,
        status=incident.status.value,
        detected_at=incident.detected_at,
        resolved_at=incident.resolved_at,
        notified_at=incident.notified_at,
        description=incident.description,
        affected_users=incident.affected_users,
        affected_records=incident.affected_records,
        source_ip=incident.source_ip,
        user_id=incident.user_id,
        metadata=incident.metadata,
        status_history=incident.status_history,
    )


def report_breach(
    breach_type: str,
    severity: str,
    description: str,
    affected_users: int,
    affected_records: int,
    user_id: str | None,
    source_ip: str | None,
    metadata: dict | None,
    reporter_username: str,
) -> BreachIncidentResponse:
    """Report a data breach incident.

    Args:
        breach_type: Type of breach
        severity: Severity level
        description: Breach description
        affected_users: Number of affected users
        affected_records: Number of affected records
        user_id: Related user ID
        source_ip: Source IP address
        metadata: Additional metadata
        reporter_username: Username of the reporter

    Returns:
        BreachIncidentResponse

    Raises:
        ValueError: If invalid breach data
        BreachManagerError: If reporting fails
    """
    breach_type_enum = BreachType(breach_type)
    severity_enum = BreachSeverity(severity)

    manager = get_breach_manager()
    incident = manager.report_breach(
        breach_type=breach_type_enum,
        severity=severity_enum,
        description=description,
        affected_users=affected_users,
        affected_records=affected_records,
        user_id=user_id,
        source_ip=source_ip,
        metadata=metadata,
    )

    logger.info(
        f"Breach reported via API: id={incident.id}, type={breach_type_enum.value}, "
        f"by={reporter_username}"
    )

    return incident_to_response(incident)


def list_breaches(
    status_filter: str | None,
    severity_filter: str | None,
    user_id: str | None,
    start_date: datetime | None,
    end_date: datetime | None,
    limit: int,
    offset: int,
    requester_username: str,
) -> tuple[list, int]:
    """List breach incidents with filters.

    Args:
        status_filter: Filter by status
        severity_filter: Filter by severity
        user_id: Filter by user ID
        start_date: Filter by detection date (after)
        end_date: Filter by detection date (before)
        limit: Maximum results
        offset: Pagination offset
        requester_username: Username of the requester

    Returns:
        Tuple of (incidents list as responses, total count)

    Raises:
        ValueError: If invalid filter values
    """
    status_obj = BreachStatus(status_filter) if status_filter else None
    severity_obj = BreachSeverity(severity_filter) if severity_filter else None

    manager = get_breach_manager()
    incidents = manager.list_incidents(
        status=status_obj,
        severity=severity_obj,
        user_id=user_id,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
    )

    total = manager.repository.count_incidents(
        status=status_obj,
        severity=severity_obj,
        start_date=start_date,
        end_date=end_date,
    )

    logger.debug(
        f"Listed {len(incidents)} breach incidents (total={total}) for user={requester_username}"
    )

    return [incident_to_response(inc) for inc in incidents], total


def get_breach_by_id(incident_id: str):
    """Get breach incident by ID.

    Args:
        incident_id: Incident ID

    Returns:
        BreachIncidentResponse

    Raises:
        LookupError: If incident not found
    """
    manager = get_breach_manager()
    incident = manager.get_incident(incident_id)

    if not incident:
        raise LookupError(f"Breach incident not found: {incident_id}")

    return incident_to_response(incident)


def update_breach_status(
    incident_id: str, new_status: str, note: str | None, updater_username: str
) -> BreachIncidentResponse:
    """Update breach incident status.

    Args:
        incident_id: Incident ID
        new_status: New status value
        note: Optional note
        updater_username: Username of the updater

    Returns:
        Updated BreachIncidentResponse

    Raises:
        ValueError: If invalid status
        BreachManagerError: If update fails
        LookupError: If incident not found
    """
    status_enum = BreachStatus(new_status)

    manager = get_breach_manager()
    try:
        incident = manager.update_breach_status(
            incident_id=incident_id,
            new_status=status_enum,
            note=note,
        )
    except BreachManagerError as e:
        if "not found" in str(e):
            raise LookupError(str(e)) from e
        raise

    logger.info(
        f"Breach status updated: id={incident_id}, status={status_enum.value}, "
        f"by={updater_username}"
    )

    return incident_to_response(incident)


def send_notifications(
    incident_id: str,
    channels: list[str],
    recipients: list[str] | None,
    message: str | None,
    sender_username: str,
) -> BreachNotificationResponse:
    """Send breach notifications through specified channels.

    Args:
        incident_id: Incident ID
        channels: List of notification channel names
        recipients: Optional list of recipients
        message: Optional custom message
        sender_username: Username of the sender

    Returns:
        BreachNotificationResponse with delivery results

    Raises:
        LookupError: If incident not found
        ValueError: If invalid channel
    """
    manager = get_breach_manager()
    incident = manager.get_incident(incident_id)

    if not incident:
        raise LookupError(f"Breach incident not found: {incident_id}")

    parsed_channels = [NotificationChannel(ch) for ch in channels]

    notification_service = NotificationService()
    results = notification_service.send_notification(
        incident=incident,
        channels=parsed_channels,
        recipients=recipients,
        message=message,
    )

    # Update incident status to notified if all successful
    all_successful = all(r.get("success", False) for r in results.values())
    if all_successful:
        manager.update_breach_status(
            incident_id=incident_id,
            new_status=BreachStatus.NOTIFIED,
            note=f"Notifications sent by {sender_username}",
        )

    logger.info(
        f"Breach notifications sent: id={incident_id}, "
        f"channels={[ch.value for ch in parsed_channels]}, by={sender_username}"
    )

    return BreachNotificationResponse(
        incident_id=incident_id,
        results=results,
        sent_at=datetime.now(UTC),
    )


def get_summary(
    start_date: datetime, end_date: datetime, requester_username: str
) -> BreachSummaryResponse:
    """Generate breach summary report.

    Args:
        start_date: Start of reporting period
        end_date: End of reporting period
        requester_username: Username of requester

    Returns:
        BreachSummaryResponse with statistics
    """
    report = generate_summary_report(start_date=start_date, end_date=end_date)

    logger.info(
        f"Generated breach summary report: {start_date.date()} to {end_date.date()}, "
        f"by={requester_username}"
    )

    return BreachSummaryResponse(**report)


__all__ = [
    "get_breach_by_id",
    "get_summary",
    "incident_to_response",
    "list_breaches",
    "report_breach",
    "send_notifications",
    "update_breach_status",
]

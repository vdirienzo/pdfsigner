"""
Breach notification API routes.

Provides endpoints for breach detection, tracking, and notification
per GDPR Art. 33-34 and HIPAA §164.404, §164.408.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from loguru import logger

from pdfsigner.api.middleware.auth import get_current_user_or_api_key
from pdfsigner.api.schemas.breach import (
    BreachIncidentCreate,
    BreachIncidentResponse,
    BreachListResponse,
    BreachNotificationRequest,
    BreachNotificationResponse,
    BreachStatusUpdate,
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
from pdfsigner.core.breach.notification_service import NotificationChannel, NotificationService
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users.user_model import User

router = APIRouter(prefix="/api/v1/breach", tags=["breach"])


def _incident_to_response(incident) -> BreachIncidentResponse:
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


@router.post(
    "/report",
    response_model=BreachIncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Report data breach",
    description="""
    Report a data breach incident manually.

    **Admin only** - Requires admin permissions.

    Creates a new breach incident record for tracking and notification.
    This endpoint is for manual reporting; automated detection happens
    via system monitoring.
    """,
)
async def report_breach(
    breach_data: BreachIncidentCreate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> BreachIncidentResponse:
    """
    Report a data breach incident.

    Args:
        breach_data: Breach details
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        Created breach incident

    Raises:
        HTTPException: 400 if breach reporting fails
        HTTPException: 403 if user lacks permission
    """
    try:
        # Parse enums
        breach_type = BreachType(breach_data.breach_type)
        severity = BreachSeverity(breach_data.severity)

        # Report breach
        manager = get_breach_manager()
        incident = manager.report_breach(
            breach_type=breach_type,
            severity=severity,
            description=breach_data.description,
            affected_users=breach_data.affected_users,
            affected_records=breach_data.affected_records,
            user_id=breach_data.user_id,
            source_ip=breach_data.source_ip,
            metadata=breach_data.metadata,
        )

        logger.info(
            f"Breach reported via API: id={incident.id}, type={breach_type.value}, "
            f"by={current_user.username}"
        )

        return _incident_to_response(incident)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid breach data: {e}",
        ) from e
    except BreachManagerError as e:
        logger.error(f"Failed to report breach: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e


@router.get(
    "/",
    response_model=BreachListResponse,
    summary="List breach incidents",
    description="""
    List breach incidents with optional filters.

    **Admin/Auditor only** - Requires elevated permissions.

    Supports filtering by status, severity, user, and date range.
    """,
)
async def list_breaches(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
    status_filter: str | None = Query(None, alias="status"),
    severity_filter: str | None = Query(None, alias="severity"),
    user_id: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
) -> BreachListResponse:
    """
    List breach incidents.

    Args:
        current_user: Authenticated user
        _perm: Permission check dependency
        status_filter: Filter by status
        severity_filter: Filter by severity
        user_id: Filter by user ID
        start_date: Filter by detection date (after)
        end_date: Filter by detection date (before)
        limit: Maximum results
        offset: Pagination offset

    Returns:
        List of breach incidents

    Raises:
        HTTPException: 400 if invalid filter values
        HTTPException: 403 if user lacks permission
    """
    try:
        # Parse optional enums
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

        # Get total count
        total = manager.repository.count_incidents(
            status=status_obj,
            severity=severity_obj,
            start_date=start_date,
            end_date=end_date,
        )

        logger.debug(
            f"Listed {len(incidents)} breach incidents (total={total}) "
            f"for user={current_user.username}"
        )

        return BreachListResponse(
            incidents=[_incident_to_response(inc) for inc in incidents],
            total=total,
            limit=limit,
            offset=offset,
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid filter value: {e}",
        ) from e


@router.get(
    "/{incident_id}",
    response_model=BreachIncidentResponse,
    summary="Get breach incident",
    description="""
    Get detailed information about a specific breach incident.

    **Admin/Auditor only** - Requires elevated permissions.
    """,
)
async def get_breach(
    incident_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> BreachIncidentResponse:
    """
    Get breach incident details.

    Args:
        incident_id: Incident ID
        current_user: Authenticated user
        _perm: Permission check dependency

    Returns:
        Breach incident details

    Raises:
        HTTPException: 404 if incident not found
        HTTPException: 403 if user lacks permission
    """
    manager = get_breach_manager()
    incident = manager.get_incident(incident_id)

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Breach incident not found: {incident_id}",
        )

    return _incident_to_response(incident)


@router.patch(
    "/{incident_id}/status",
    response_model=BreachIncidentResponse,
    summary="Update breach status",
    description="""
    Update the status of a breach incident.

    **Admin only** - Requires admin permissions.

    Valid status transitions:
    - detected → investigating
    - investigating → contained
    - contained → resolved
    - resolved → notified
    """,
)
async def update_breach_status(
    incident_id: str,
    status_update: BreachStatusUpdate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> BreachIncidentResponse:
    """
    Update breach incident status.

    Args:
        incident_id: Incident ID
        status_update: New status and optional note
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        Updated breach incident

    Raises:
        HTTPException: 404 if incident not found
        HTTPException: 400 if invalid status or update fails
        HTTPException: 403 if user lacks permission
    """
    try:
        new_status = BreachStatus(status_update.status)

        manager = get_breach_manager()
        incident = manager.update_breach_status(
            incident_id=incident_id,
            new_status=new_status,
            note=status_update.note,
        )

        logger.info(
            f"Breach status updated: id={incident_id}, status={new_status.value}, "
            f"by={current_user.username}"
        )

        return _incident_to_response(incident)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status: {e}",
        ) from e
    except BreachManagerError as e:
        if "not found" in str(e):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e),
            ) from e
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e


@router.post(
    "/{incident_id}/notify",
    response_model=BreachNotificationResponse,
    summary="Send breach notifications",
    description="""
    Send breach notifications through specified channels.

    **Admin only** - Requires admin permissions.

    Sends notifications to authorities and/or affected individuals
    per GDPR and HIPAA requirements.

    Supports multiple channels: email, webhook, SMS
    """,
)
async def send_notifications(
    incident_id: str,
    notification_request: BreachNotificationRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> BreachNotificationResponse:
    """
    Send breach notifications.

    Args:
        incident_id: Incident ID
        notification_request: Notification channels and recipients
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        Notification delivery results

    Raises:
        HTTPException: 404 if incident not found
        HTTPException: 400 if invalid channel or delivery fails
        HTTPException: 403 if user lacks permission
    """
    try:
        # Get incident
        manager = get_breach_manager()
        incident = manager.get_incident(incident_id)

        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Breach incident not found: {incident_id}",
            )

        # Parse channels
        channels = [NotificationChannel(ch) for ch in notification_request.channels]

        # Send notifications
        notification_service = NotificationService()
        results = notification_service.send_notification(
            incident=incident,
            channels=channels,
            recipients=notification_request.recipients,
            message=notification_request.message,
        )

        # Update incident status to notified if all successful
        all_successful = all(r.get("success", False) for r in results.values())
        if all_successful:
            manager.update_breach_status(
                incident_id=incident_id,
                new_status=BreachStatus.NOTIFIED,
                note=f"Notifications sent by {current_user.username}",
            )

        logger.info(
            f"Breach notifications sent: id={incident_id}, "
            f"channels={[ch.value for ch in channels]}, by={current_user.username}"
        )

        return BreachNotificationResponse(
            incident_id=incident_id,
            results=results,
            sent_at=datetime.now(UTC),
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid notification channel: {e}",
        ) from e


@router.get(
    "/reports/summary",
    response_model=BreachSummaryResponse,
    summary="Get breach summary report",
    description="""
    Generate aggregate breach statistics for a time period.

    **Admin/Auditor only** - Requires elevated permissions.

    Provides trends, breakdowns by severity/type/status, and
    performance metrics.
    """,
)
async def get_summary_report(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
    start_date: datetime = Query(..., description="Start of reporting period"),
    end_date: datetime = Query(..., description="End of reporting period"),
) -> BreachSummaryResponse:
    """
    Generate breach summary report.

    Args:
        current_user: Authenticated user
        _perm: Permission check dependency
        start_date: Start of reporting period
        end_date: End of reporting period

    Returns:
        Aggregate breach statistics

    Raises:
        HTTPException: 400 if date range invalid
        HTTPException: 403 if user lacks permission
    """
    if start_date >= end_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_date must be before end_date",
        )

    try:
        report = generate_summary_report(start_date=start_date, end_date=end_date)

        logger.info(
            f"Generated breach summary report: {start_date.date()} to {end_date.date()}, "
            f"by={current_user.username}"
        )

        return BreachSummaryResponse(**report)

    except Exception as e:
        logger.error(f"Failed to generate summary report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate summary report",
        ) from e


# --- Public Exports ---

__all__ = ["router"]

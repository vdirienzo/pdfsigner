"""
Breach notification API routes.

Provides endpoints for breach detection, tracking, and notification
per GDPR Art. 33-34 and HIPAA §164.404, §164.408.
"""

from datetime import datetime
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
from pdfsigner.api.services import breach_service
from pdfsigner.core.breach.breach_manager import BreachManagerError
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users.user_model import User

router = APIRouter(prefix="/api/v1/breach", tags=["breach"])


@router.post(
    "/report",
    response_model=BreachIncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Report data breach",
    description="Report a data breach incident manually (admin only).",
)
async def report_breach(
    breach_data: BreachIncidentCreate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> BreachIncidentResponse:
    """Report a data breach incident."""
    try:
        return breach_service.report_breach(
            breach_type=breach_data.breach_type,
            severity=breach_data.severity,
            description=breach_data.description,
            affected_users=breach_data.affected_users,
            affected_records=breach_data.affected_records,
            user_id=breach_data.user_id,
            source_ip=breach_data.source_ip,
            metadata=breach_data.metadata,
            reporter_username=current_user.username,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid breach data: {e}",
        ) from e
    except BreachManagerError as e:
        logger.error(f"Failed to report breach: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.get(
    "/",
    response_model=BreachListResponse,
    summary="List breach incidents",
    description="List breach incidents with optional filters (admin/auditor only).",
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
    """List breach incidents."""
    try:
        incidents, total = breach_service.list_breaches(
            status_filter=status_filter,
            severity_filter=severity_filter,
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
            requester_username=current_user.username,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid filter value: {e}",
        ) from e

    return BreachListResponse(
        incidents=incidents,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{incident_id}",
    response_model=BreachIncidentResponse,
    summary="Get breach incident",
    description="Get detailed information about a specific breach incident.",
)
async def get_breach(
    incident_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> BreachIncidentResponse:
    """Get breach incident details."""
    try:
        return breach_service.get_breach_by_id(incident_id)
    except LookupError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.patch(
    "/{incident_id}/status",
    response_model=BreachIncidentResponse,
    summary="Update breach status",
    description="Update the status of a breach incident (admin only).",
)
async def update_breach_status(
    incident_id: str,
    status_update: BreachStatusUpdate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> BreachIncidentResponse:
    """Update breach incident status."""
    try:
        return breach_service.update_breach_status(
            incident_id=incident_id,
            new_status=status_update.status,
            note=status_update.note,
            updater_username=current_user.username,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status: {e}",
        ) from e
    except LookupError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except BreachManagerError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.post(
    "/{incident_id}/notify",
    response_model=BreachNotificationResponse,
    summary="Send breach notifications",
    description="Send breach notifications through specified channels (admin only).",
)
async def send_notifications(
    incident_id: str,
    notification_request: BreachNotificationRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> BreachNotificationResponse:
    """Send breach notifications."""
    try:
        return breach_service.send_notifications(
            incident_id=incident_id,
            channels=notification_request.channels,
            recipients=notification_request.recipients,
            message=notification_request.message,
            sender_username=current_user.username,
        )
    except LookupError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid notification channel: {e}",
        ) from e


@router.get(
    "/reports/summary",
    response_model=BreachSummaryResponse,
    summary="Get breach summary report",
    description="Generate aggregate breach statistics for a time period.",
)
async def get_summary_report(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
    start_date: datetime = Query(..., description="Start of reporting period"),
    end_date: datetime = Query(..., description="End of reporting period"),
) -> BreachSummaryResponse:
    """Generate breach summary report."""
    if start_date >= end_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_date must be before end_date",
        )

    try:
        return breach_service.get_summary(start_date, end_date, current_user.username)
    except Exception as e:
        logger.error(f"Failed to generate summary report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate summary report",
        ) from e


__all__ = ["router"]

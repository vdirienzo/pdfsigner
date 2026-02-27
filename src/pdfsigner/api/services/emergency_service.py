"""
emergency_service.py - Emergency access API service layer

Bridges API routes with core emergency access (break-glass) logic.
Converts domain errors to HTTP exceptions.
"""

from fastapi import HTTPException, status
from loguru import logger

from pdfsigner.core.emergency import get_break_glass_service
from pdfsigner.core.emergency.emergency_types import EmergencyAccessRequest
from pdfsigner.core.users.user_model import User, UserRole
from pdfsigner.exceptions import EmergencyAccessError


def require_admin(user: User) -> None:
    """
    Check if user has admin role.

    Args:
        user: User to check

    Raises:
        HTTPException: 403 if user is not admin
    """
    if user.role != UserRole.ADMIN:
        logger.warning(
            f"Emergency admin operation denied: user={user.username}, role={user.role.value}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required for this operation",
        )


def create_emergency_request(username: str, reason: str) -> EmergencyAccessRequest:
    """
    Create a new emergency access request.

    Args:
        username: Requester's username
        reason: Justification for emergency access

    Returns:
        Created EmergencyAccessRequest

    Raises:
        HTTPException: 400 if healthcare mode disabled or validation fails
    """
    try:
        service = get_break_glass_service()
        request = service.request_emergency_access(
            requester_id=username,
            reason=reason,
        )

        logger.info(
            f"Emergency access requested: id={request.id}, user={username}, "
            f"status={request.status.value}"
        )
        return request

    except EmergencyAccessError as e:
        logger.error(f"Emergency access request failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e


def list_pending() -> list[EmergencyAccessRequest]:
    """
    Get all pending emergency access requests.

    Returns:
        List of pending requests

    Raises:
        HTTPException: 500 if retrieval fails
    """
    try:
        service = get_break_glass_service()
        requests = service.get_pending_requests()
        logger.debug(f"Retrieved {len(requests)} pending emergency requests for admin review")
        return requests

    except Exception as e:
        logger.error(f"Failed to list pending requests: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve pending requests",
        ) from e


def approve(request_id: str, admin_username: str) -> EmergencyAccessRequest:
    """
    Approve an emergency access request.

    Args:
        request_id: ID of request to approve
        admin_username: Admin's username

    Returns:
        Updated EmergencyAccessRequest

    Raises:
        HTTPException: 404 if not found, 400 if wrong status
    """
    return _execute_admin_action(
        action_fn=lambda svc: svc.approve_request(request_id=request_id, admin_id=admin_username),
        request_id=request_id,
        admin_username=admin_username,
        action_name="approved",
    )


def deny(request_id: str, admin_username: str, reason: str = "") -> EmergencyAccessRequest:
    """
    Deny an emergency access request.

    Args:
        request_id: ID of request to deny
        admin_username: Admin's username
        reason: Optional denial reason

    Returns:
        Updated EmergencyAccessRequest

    Raises:
        HTTPException: 404 if not found, 400 if wrong status
    """
    return _execute_admin_action(
        action_fn=lambda svc: svc.deny_request(
            request_id=request_id, admin_id=admin_username, reason=reason
        ),
        request_id=request_id,
        admin_username=admin_username,
        action_name="denied",
    )


def revoke(request_id: str, admin_username: str) -> EmergencyAccessRequest:
    """
    Revoke active emergency access.

    Args:
        request_id: ID of request to revoke
        admin_username: Admin's username

    Returns:
        Updated EmergencyAccessRequest

    Raises:
        HTTPException: 404 if not found, 400 if wrong status
    """
    return _execute_admin_action(
        action_fn=lambda svc: svc.revoke_access(
            request_id=request_id, admin_id=admin_username, reason="Revoked by admin"
        ),
        request_id=request_id,
        admin_username=admin_username,
        action_name="revoked",
    )


def check_user_status(username: str) -> dict:
    """
    Check if user has active emergency access.

    Args:
        username: User's username

    Returns:
        Dict with has_active_access, active_request_id, expires_at

    Raises:
        HTTPException: 500 if check fails
    """
    try:
        service = get_break_glass_service()

        service.repository.cleanup_expired_requests()
        active_request = service.repository.get_active_request(username)

        if active_request and active_request.is_active:
            logger.debug(f"User {username} has active emergency access: {active_request.id}")
            return {
                "has_active_access": True,
                "active_request_id": active_request.id,
                "expires_at": active_request.expires_at,
            }
        else:
            return {
                "has_active_access": False,
                "active_request_id": None,
                "expires_at": None,
            }

    except Exception as e:
        logger.error(f"Failed to check emergency status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check emergency access status",
        ) from e


def _execute_admin_action(
    action_fn,
    request_id: str,
    admin_username: str,
    action_name: str,
) -> EmergencyAccessRequest:
    """
    Execute an admin action on an emergency request with error handling.

    Args:
        action_fn: Callable that takes BreakGlassService and performs the action
        request_id: ID of the request
        admin_username: Admin's username
        action_name: Human-readable action name for logging

    Returns:
        Updated EmergencyAccessRequest

    Raises:
        HTTPException: 404 if not found, 400 if wrong status
    """
    try:
        service = get_break_glass_service()
        request = action_fn(service)

        logger.info(f"Emergency access {action_name}: id={request_id}, admin={admin_username}")
        return request

    except EmergencyAccessError as e:
        if "not found" in str(e):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Emergency request not found: {request_id}",
            ) from e
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e

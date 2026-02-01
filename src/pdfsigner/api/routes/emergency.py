"""
Emergency access (break-glass) routes.

Provides endpoints for:
- Requesting emergency access
- Viewing pending requests (admin only)
- Approving/denying requests (admin only)
- Revoking active access (admin only)
- Checking access status

HIPAA Compliance:
    - §164.312(a)(2)(ii) - Emergency access procedure
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger

from pdfsigner.api.middleware.auth import get_current_user_or_api_key
from pdfsigner.api.schemas.emergency import (
    EmergencyDenyRequest,
    EmergencyRequestCreate,
    EmergencyRequestResponse,
    EmergencyStatusResponse,
)
from pdfsigner.core.emergency import get_break_glass_service
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users.user_model import User, UserRole
from pdfsigner.exceptions import EmergencyAccessError

router = APIRouter(prefix="/api/v1/emergency", tags=["emergency"])


def _request_to_response(request) -> EmergencyRequestResponse:
    """Convert EmergencyAccessRequest to API response model."""
    return EmergencyRequestResponse(
        id=request.id,
        requester_id=request.requester_id,
        reason=request.reason,
        status=request.status.value,
        requested_at=request.requested_at,
        approved_by=request.approved_by,
        approved_at=request.approved_at,
        expires_at=request.expires_at,
        revoked_by=request.revoked_by,
        revoked_at=request.revoked_at,
    )


def _require_admin(user: User) -> None:
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


@router.post(
    "/request",
    response_model=EmergencyRequestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Request emergency access",
    description="""
    Request temporary emergency access (break-glass).

    Creates a new emergency access request that requires admin approval
    (unless auto-approval is enabled in settings).

    Requires authentication but no special permissions.
    """,
)
async def request_emergency_access(
    request_data: EmergencyRequestCreate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> EmergencyRequestResponse:
    """
    Request emergency access.

    Args:
        request_data: Request details with justification
        current_user: Authenticated user making the request

    Returns:
        Created emergency access request

    Raises:
        HTTPException: 400 if healthcare mode is disabled or request fails
    """
    try:
        service = get_break_glass_service()
        request = service.request_emergency_access(
            requester_id=current_user.username,
            reason=request_data.reason,
        )

        logger.info(
            f"Emergency access requested: id={request.id}, user={current_user.username}, "
            f"status={request.status.value}"
        )

        return _request_to_response(request)

    except EmergencyAccessError as e:
        logger.error(f"Emergency access request failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e


@router.get(
    "/pending",
    response_model=list[EmergencyRequestResponse],
    summary="List pending requests",
    description="""
    Get all pending emergency access requests.

    **Admin only** - Requires admin role.

    Used by administrators to review and process emergency access requests.
    """,
)
async def list_pending_requests(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> list[EmergencyRequestResponse]:
    """
    List all pending emergency access requests.

    Args:
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        List of pending emergency access requests

    Raises:
        HTTPException: 403 if user is not admin
    """
    _require_admin(current_user)

    try:
        service = get_break_glass_service()
        requests = service.get_pending_requests()

        logger.debug(f"Retrieved {len(requests)} pending emergency requests for admin review")

        return [_request_to_response(req) for req in requests]

    except Exception as e:
        logger.error(f"Failed to list pending requests: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve pending requests",
        ) from e


@router.post(
    "/{request_id}/approve",
    response_model=EmergencyRequestResponse,
    summary="Approve emergency request",
    description="""
    Approve pending emergency access request.

    **Admin only** - Requires admin role.

    Sets expiration time based on configured duration (default 12 hours).
    """,
)
async def approve_request(
    request_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> EmergencyRequestResponse:
    """
    Approve emergency access request.

    Args:
        request_id: ID of request to approve
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        Updated emergency access request

    Raises:
        HTTPException: 403 if user is not admin
        HTTPException: 404 if request not found
        HTTPException: 400 if request cannot be approved (wrong status)
    """
    _require_admin(current_user)

    try:
        service = get_break_glass_service()
        request = service.approve_request(
            request_id=request_id,
            admin_id=current_user.username,
        )

        logger.info(
            f"Emergency access approved: id={request_id}, admin={current_user.username}, "
            f"expires={request.expires_at}"
        )

        return _request_to_response(request)

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


@router.post(
    "/{request_id}/deny",
    response_model=EmergencyRequestResponse,
    summary="Deny emergency request",
    description="""
    Deny pending emergency access request.

    **Admin only** - Requires admin role.

    Optional denial reason can be provided for audit trail.
    """,
)
async def deny_request(
    request_id: str,
    deny_data: EmergencyDenyRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> EmergencyRequestResponse:
    """
    Deny emergency access request.

    Args:
        request_id: ID of request to deny
        deny_data: Optional denial reason
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        Updated emergency access request

    Raises:
        HTTPException: 403 if user is not admin
        HTTPException: 404 if request not found
        HTTPException: 400 if request cannot be denied (wrong status)
    """
    _require_admin(current_user)

    try:
        service = get_break_glass_service()
        request = service.deny_request(
            request_id=request_id,
            admin_id=current_user.username,
            reason=deny_data.reason or "",
        )

        logger.info(
            f"Emergency access denied: id={request_id}, admin={current_user.username}, "
            f"reason={deny_data.reason or 'not specified'}"
        )

        return _request_to_response(request)

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


@router.post(
    "/{request_id}/revoke",
    response_model=EmergencyRequestResponse,
    summary="Revoke emergency access",
    description="""
    Revoke active emergency access before expiration.

    **Admin only** - Requires admin role.

    Used to terminate emergency access early if it's no longer needed
    or if misuse is detected.
    """,
)
async def revoke_access(
    request_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> EmergencyRequestResponse:
    """
    Revoke active emergency access.

    Args:
        request_id: ID of request to revoke
        current_user: Authenticated admin user
        _perm: Permission check dependency

    Returns:
        Updated emergency access request

    Raises:
        HTTPException: 403 if user is not admin
        HTTPException: 404 if request not found
        HTTPException: 400 if request cannot be revoked (not approved)
    """
    _require_admin(current_user)

    try:
        service = get_break_glass_service()
        request = service.revoke_access(
            request_id=request_id,
            admin_id=current_user.username,
            reason="Revoked by admin",
        )

        logger.info(f"Emergency access revoked: id={request_id}, admin={current_user.username}")

        return _request_to_response(request)

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


@router.get(
    "/status",
    response_model=EmergencyStatusResponse,
    summary="Check emergency access status",
    description="""
    Check if current user has active emergency access.

    Returns active status, request ID, and expiration time if access is granted.

    Requires authentication but no special permissions.
    """,
)
async def check_status(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> EmergencyStatusResponse:
    """
    Check if user has active emergency access.

    Args:
        current_user: Authenticated user

    Returns:
        Emergency access status with details if active
    """
    try:
        service = get_break_glass_service()

        # Cleanup expired requests
        service.repository.cleanup_expired_requests()

        # Get active request
        active_request = service.repository.get_active_request(current_user.username)

        if active_request and active_request.is_active:
            logger.debug(
                f"User {current_user.username} has active emergency access: {active_request.id}"
            )
            return EmergencyStatusResponse(
                has_active_access=True,
                active_request_id=active_request.id,
                expires_at=active_request.expires_at,
            )
        else:
            return EmergencyStatusResponse(
                has_active_access=False,
                active_request_id=None,
                expires_at=None,
            )

    except Exception as e:
        logger.error(f"Failed to check emergency status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check emergency access status",
        ) from e


# --- Public Exports ---

__all__ = ["router"]

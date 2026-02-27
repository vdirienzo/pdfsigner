"""
Emergency access (break-glass) routes.

Provides endpoints for:
- Requesting emergency access
- Viewing pending requests (admin only)
- Approving/denying requests (admin only)
- Revoking active access (admin only)
- Checking access status

HIPAA Compliance:
    - SS164.312(a)(2)(ii) - Emergency access procedure
"""

from typing import Annotated

from fastapi import APIRouter, Depends, status

from pdfsigner.api.middleware.auth import get_current_user_or_api_key
from pdfsigner.api.schemas.emergency import (
    EmergencyDenyRequest,
    EmergencyRequestCreate,
    EmergencyRequestResponse,
    EmergencyStatusResponse,
)
from pdfsigner.api.services import emergency_service
from pdfsigner.core.rbac import Permission, check_permission
from pdfsigner.core.users.user_model import User

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


@router.post(
    "/request",
    response_model=EmergencyRequestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Request emergency access",
)
async def request_emergency_access(
    request_data: EmergencyRequestCreate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> EmergencyRequestResponse:
    """Request emergency access (break-glass)."""
    request = emergency_service.create_emergency_request(
        username=current_user.username,
        reason=request_data.reason,
    )
    return _request_to_response(request)


@router.get(
    "/pending",
    response_model=list[EmergencyRequestResponse],
    summary="List pending requests",
)
async def list_pending_requests(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> list[EmergencyRequestResponse]:
    """List all pending emergency access requests. Admin only."""
    emergency_service.require_admin(current_user)
    requests = emergency_service.list_pending()
    return [_request_to_response(req) for req in requests]


@router.post(
    "/{request_id}/approve",
    response_model=EmergencyRequestResponse,
    summary="Approve emergency request",
)
async def approve_request(
    request_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> EmergencyRequestResponse:
    """Approve emergency access request. Admin only."""
    emergency_service.require_admin(current_user)
    request = emergency_service.approve(request_id, current_user.username)
    return _request_to_response(request)


@router.post(
    "/{request_id}/deny",
    response_model=EmergencyRequestResponse,
    summary="Deny emergency request",
)
async def deny_request(
    request_id: str,
    deny_data: EmergencyDenyRequest,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> EmergencyRequestResponse:
    """Deny emergency access request. Admin only."""
    emergency_service.require_admin(current_user)
    request = emergency_service.deny(request_id, current_user.username, deny_data.reason or "")
    return _request_to_response(request)


@router.post(
    "/{request_id}/revoke",
    response_model=EmergencyRequestResponse,
    summary="Revoke emergency access",
)
async def revoke_access(
    request_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.ADMIN_USERS))],
) -> EmergencyRequestResponse:
    """Revoke active emergency access. Admin only."""
    emergency_service.require_admin(current_user)
    request = emergency_service.revoke(request_id, current_user.username)
    return _request_to_response(request)


@router.get(
    "/status",
    response_model=EmergencyStatusResponse,
    summary="Check emergency access status",
)
async def check_status(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> EmergencyStatusResponse:
    """Check if current user has active emergency access."""
    result = emergency_service.check_user_status(current_user.username)
    return EmergencyStatusResponse(
        has_active_access=result["has_active_access"],
        active_request_id=result["active_request_id"],
        expires_at=result["expires_at"],
    )


# --- Public Exports ---

__all__ = ["router"]

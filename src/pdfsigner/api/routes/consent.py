"""
Consent management routes.

GDPR Article 7 consent management endpoints:
- Grant consent
- Withdraw consent
- View active consents
- View consent audit trail
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from loguru import logger

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.api.schemas.consent import (
    ConsentAuditResponse,
    ConsentRequest,
    ConsentResponse,
    ConsentSummaryResponse,
)
from pdfsigner.core.gdpr import ConsentType, get_consent_manager
from pdfsigner.core.rbac import Permission, check_permission

router = APIRouter(prefix="/api/v1/consent", tags=["consent"])


# --- Helper Functions ---


def _consent_to_response(consent) -> ConsentResponse:
    """
    Convert ConsentRecord to ConsentResponse schema.

    Args:
        consent: ConsentRecord domain model

    Returns:
        ConsentResponse schema for API response
    """
    return ConsentResponse(
        id=consent.id,
        user_id=consent.user_id,
        consent_type=consent.consent_type.value,
        granted=consent.granted,
        granted_at=consent.granted_at,
        withdrawn_at=consent.withdrawn_at,
        ip_address=consent.ip_address,
        policy_version=consent.policy_version,
    )


def _get_client_ip(request: Request) -> str | None:
    """Extract client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_user_agent(request: Request) -> str | None:
    """Extract user agent from request."""
    return request.headers.get("User-Agent")


# --- Routes ---


@router.get(
    "/{user_id}",
    response_model=list[ConsentResponse],
    summary="Get active consents",
    description="""
    Get all currently active consents for a user.

    **Permissions:**
    - Admins can view any user's consents
    - Users can only view their own consents
    """,
)
async def get_user_consents(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> list[ConsentResponse]:
    """
    Get active consents for a user.

    Args:
        user_id: User ID to get consents for
        current_user: Authenticated user

    Returns:
        List of active consent records

    Raises:
        HTTPException: 403 if user tries to view another user's consents
    """
    # Check permissions
    from pdfsigner.core.users import UserRole

    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own consents",
        )

    # Get active consents
    consent_manager = get_consent_manager()
    consents = consent_manager.get_active_consents(user_id)

    logger.debug(f"Retrieved {len(consents)} active consents for user={user_id}")

    return [_consent_to_response(c) for c in consents]


@router.post(
    "/{user_id}",
    response_model=ConsentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Grant consent",
    description="""
    Record user consent grant (GDPR Article 7).

    **Permissions:**
    - Users can grant their own consent
    - Admins can grant consent on behalf of users

    **Body:** ConsentRequest with consent_type and optional policy_version
    """,
)
async def grant_consent(
    user_id: str,
    consent_request: ConsentRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> ConsentResponse:
    """
    Record user consent grant.

    Args:
        user_id: User ID granting consent
        consent_request: Consent details (type, policy version)
        request: HTTP request (for IP and user agent)
        current_user: Authenticated user

    Returns:
        Created consent record

    Raises:
        HTTPException: 403 if user tries to grant consent for another user
        HTTPException: 400 if invalid consent type
    """
    # Check permissions
    from pdfsigner.core.users import UserRole

    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only grant your own consent",
        )

    # Validate consent type
    try:
        consent_type = ConsentType(consent_request.consent_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid consent type: {consent_request.consent_type}",
        )

    # Extract request metadata
    ip_address = _get_client_ip(request)
    user_agent = _get_user_agent(request)

    # Grant consent
    consent_manager = get_consent_manager()
    consent = consent_manager.grant_consent(
        user_id=user_id,
        consent_type=consent_type,
        ip_address=ip_address,
        user_agent=user_agent,
        policy_version=consent_request.policy_version,
    )

    logger.info(f"Consent granted: user={user_id}, type={consent_type.value}")

    return _consent_to_response(consent)


@router.delete(
    "/{user_id}/{consent_type}",
    response_model=ConsentResponse,
    summary="Withdraw consent",
    description="""
    Withdraw user consent (GDPR Article 7.3).

    **Permissions:**
    - Users can withdraw their own consent
    - Admins can withdraw consent on behalf of users

    Withdrawal must be as easy as granting consent.
    """,
)
async def withdraw_consent(
    user_id: str,
    consent_type: str,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> ConsentResponse:
    """
    Withdraw user consent.

    Args:
        user_id: User ID withdrawing consent
        consent_type: Type of consent to withdraw
        request: HTTP request (for IP and user agent)
        current_user: Authenticated user

    Returns:
        Withdrawal record (consent with granted=False)

    Raises:
        HTTPException: 403 if user tries to withdraw another user's consent
        HTTPException: 400 if invalid consent type or no active consent
        HTTPException: 404 if no active consent found
    """
    # Check permissions
    from pdfsigner.core.users import UserRole

    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only withdraw your own consent",
        )

    # Validate consent type
    try:
        consent_type_enum = ConsentType(consent_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid consent type: {consent_type}",
        )

    # Extract request metadata
    ip_address = _get_client_ip(request)
    user_agent = _get_user_agent(request)

    # Withdraw consent
    consent_manager = get_consent_manager()
    try:
        withdrawal = consent_manager.withdraw_consent(
            user_id=user_id,
            consent_type=consent_type_enum,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    logger.info(f"Consent withdrawn: user={user_id}, type={consent_type}")

    return _consent_to_response(withdrawal)


@router.get(
    "/audit/{user_id}",
    response_model=ConsentAuditResponse,
    summary="Get consent audit trail",
    description="""
    Get complete consent audit trail for a user (all grants and withdrawals).

    **Permissions:**
    - Admins and auditors can view any user's audit trail
    - Users can view their own audit trail
    """,
)
async def get_consent_audit_trail(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
    _perm: Annotated[None, Depends(check_permission(Permission.AUDIT_VIEW))],
) -> ConsentAuditResponse:
    """
    Get complete consent audit trail for a user.

    Args:
        user_id: User ID to get audit trail for
        current_user: Authenticated user
        _perm: Permission check (admin or auditor required)

    Returns:
        All consent records (grants and withdrawals) with total count

    Raises:
        HTTPException: 403 if insufficient permissions
    """
    # Get audit trail
    consent_manager = get_consent_manager()
    consents = consent_manager.get_consent_audit_trail(user_id)

    logger.debug(f"Retrieved consent audit trail: user={user_id}, records={len(consents)}")

    return ConsentAuditResponse(
        consents=[_consent_to_response(c) for c in consents],
        total_records=len(consents),
    )


@router.get(
    "/summary/{user_id}",
    response_model=ConsentSummaryResponse,
    summary="Get consent summary",
    description="""
    Get summary of all consent types and their current status.

    **Permissions:**
    - Admins can view any user's summary
    - Users can only view their own summary
    """,
)
async def get_consent_summary(
    user_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> ConsentSummaryResponse:
    """
    Get consent summary for a user.

    Args:
        user_id: User ID to get summary for
        current_user: Authenticated user

    Returns:
        Summary with all consent types and their status

    Raises:
        HTTPException: 403 if user tries to view another user's summary
    """
    # Check permissions
    from pdfsigner.core.users import UserRole

    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own consent summary",
        )

    # Get summary
    consent_manager = get_consent_manager()
    summary = consent_manager.get_consent_summary(user_id)

    # Get last update timestamp
    trail = consent_manager.get_consent_audit_trail(user_id)
    last_updated = trail[0].granted_at if trail else None

    return ConsentSummaryResponse(
        user_id=user_id,
        consents={k.value: v for k, v in summary.items()},
        last_updated=last_updated,
    )


# --- Public Exports ---

__all__ = ["router"]

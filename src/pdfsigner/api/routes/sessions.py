"""
Session management routes.

Provides endpoints for:
- Listing user sessions
- Getting specific session details
- Terminating sessions (single or all)
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.api.schemas.sessions import SessionDeleteResponse, SessionResponse
from pdfsigner.config.settings import get_settings
from pdfsigner.core.session import get_session_manager

router = APIRouter(prefix="/api/v1/sessions", tags=["sessions"])


# --- Routes ---


@router.get(
    "/",
    response_model=list[SessionResponse],
    summary="List user sessions",
    description="""
    Get all sessions for the current authenticated user.

    Returns active and expired sessions ordered by creation time (newest first).

    **Healthcare Mode:** Only enforced when healthcare_mode=True in settings.
    When disabled, returns empty list since sessions are not tracked.
    """,
)
async def list_sessions(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> list[SessionResponse]:
    """
    List all sessions for current user.

    Args:
        current_user: Authenticated user from JWT or API key

    Returns:
        List of SessionResponse objects for the user
    """
    settings = get_settings()

    # Sessions only tracked in healthcare mode
    if not settings.healthcare_mode:
        logger.debug("Sessions not tracked (healthcare_mode=False)")
        return []

    manager = get_session_manager()
    sessions = manager.get_user_sessions(current_user.id)

    logger.info(f"Retrieved {len(sessions)} sessions for user {current_user.username}")

    return [SessionResponse.from_session(s) for s in sessions]


@router.get(
    "/{session_id}",
    response_model=SessionResponse,
    summary="Get session details",
    description="""
    Retrieve details for a specific session.

    **Permissions:**
    - Users can only view their own sessions
    - Admins can view any session (TODO)

    Returns 404 if session not found or doesn't belong to user.
    """,
)
async def get_session(
    session_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> SessionResponse:
    """
    Get specific session details.

    Args:
        session_id: Session ID to retrieve
        current_user: Authenticated user

    Returns:
        SessionResponse with session details

    Raises:
        HTTPException: 404 if session not found or doesn't belong to user
        HTTPException: 503 if healthcare mode disabled
    """
    settings = get_settings()

    if not settings.healthcare_mode:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Session management not available (healthcare_mode=False)",
        )

    manager = get_session_manager()
    session = manager.get_session(session_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )

    # Verify session belongs to current user
    if session.user_id != current_user.id:
        logger.warning(
            f"User {current_user.username} attempted to access session {session_id} "
            f"belonging to user {session.user_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )

    return SessionResponse.from_session(session)


@router.delete(
    "/{session_id}",
    response_model=SessionDeleteResponse,
    summary="Terminate session",
    description="""
    Terminate a specific session by ID.

    **Permissions:**
    - Users can only terminate their own sessions
    - Admins can terminate any session (TODO)

    **Note:** This will invalidate the JWT token associated with this session.
    If you terminate your current session, you will need to re-authenticate.
    """,
)
async def terminate_session(
    session_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> SessionDeleteResponse:
    """
    Terminate specific session.

    Args:
        session_id: Session ID to terminate
        current_user: Authenticated user

    Returns:
        SessionDeleteResponse with success message

    Raises:
        HTTPException: 404 if session not found or doesn't belong to user
        HTTPException: 503 if healthcare mode disabled
    """
    settings = get_settings()

    if not settings.healthcare_mode:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Session management not available (healthcare_mode=False)",
        )

    manager = get_session_manager()
    session = manager.get_session(session_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )

    # Verify session belongs to current user
    if session.user_id != current_user.id:
        logger.warning(
            f"User {current_user.username} attempted to terminate session {session_id} "
            f"belonging to user {session.user_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )

    manager.terminate_session(session_id)
    logger.info(f"User {current_user.username} terminated session {session_id}")

    return SessionDeleteResponse(
        message="Session terminated successfully",
        session_id=session_id,
    )


@router.delete(
    "/",
    response_model=SessionDeleteResponse,
    summary="Terminate all sessions",
    description="""
    Terminate all sessions for the current user (logout from all devices).

    **Use case:** User wants to logout from all devices, e.g., after password change
    or when a device is lost.

    **Note:** This will invalidate ALL JWT tokens for the user, including the current one.
    You will need to re-authenticate after calling this endpoint.
    """,
)
async def terminate_all_sessions(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> SessionDeleteResponse:
    """
    Terminate all sessions for current user.

    Args:
        current_user: Authenticated user

    Returns:
        SessionDeleteResponse with count of terminated sessions

    Raises:
        HTTPException: 503 if healthcare mode disabled
    """
    settings = get_settings()

    if not settings.healthcare_mode:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Session management not available (healthcare_mode=False)",
        )

    manager = get_session_manager()
    count = manager.terminate_user_sessions(current_user.id)

    logger.info(f"User {current_user.username} terminated all {count} sessions")

    return SessionDeleteResponse(
        message=f"Successfully terminated {count} session(s)",
        sessions_terminated=count,
    )


# --- Public Exports ---

__all__ = ["router"]

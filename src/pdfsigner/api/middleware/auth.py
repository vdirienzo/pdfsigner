"""
Authentication middleware for API.

Provides JWT and API key authentication for FastAPI routes.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, status

# Re-export for backward compatibility
from fastapi.security import APIKeyHeader as _APIKeyHeader  # noqa: F401
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger

from pdfsigner.api.middleware.api_key_auth import (
    api_key_header_scheme,
    verify_api_key,
)
from pdfsigner.api.middleware.token_service import (
    TokenData,
    create_access_token,
    verify_token,
)
from pdfsigner.config.settings import get_settings
from pdfsigner.core.session import get_session_manager
from pdfsigner.core.users.user_model import User, UserRole, UserStatus
from pdfsigner.core.users.user_repository import UserRepository

# Security schemes
http_bearer = HTTPBearer(auto_error=False)


# --- Authentication Dependencies ---


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(http_bearer)] = None,
) -> User:
    """
    Get current user from JWT token.

    When healthcare_mode is enabled, validates session and fetches user from UserRepository.
    Otherwise, creates a mock user from token data.

    Args:
        credentials: HTTP Bearer token from request header

    Returns:
        Authenticated User object

    Raises:
        HTTPException: 401 if no token or invalid token
        HTTPException: 401 if session expired (healthcare mode)
        HTTPException: 404 if user not found (healthcare_mode only)
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = verify_token(credentials.credentials)
    settings = get_settings()

    # Validate and touch session if healthcare_mode
    if settings.healthcare_mode and token_data.session_id:
        session_mgr = get_session_manager()
        if not session_mgr.validate_session(token_data.session_id):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Sliding window: extend session on activity
        session_mgr.touch_session(token_data.session_id)

    # If healthcare mode is enabled, fetch user from repository
    if settings.healthcare_mode:
        user_repo = UserRepository()
        # Try to fetch by user_id if available in token
        if token_data.user_id:
            user = user_repo.get_user_by_id(token_data.user_id)
            if user:
                return user

        # Fallback: fetch by username
        user = user_repo.get_user_by_username(token_data.username)
        if user:
            return user

        # User not found in repository
        logger.warning("JWT-authenticated user not found in repository")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        # Healthcare mode disabled: create mock user from token data
        try:
            role = UserRole(token_data.role)
        except ValueError:
            role = UserRole.VIEWER

        return User(
            id=token_data.user_id or token_data.username,
            username=token_data.username,
            email="",
            role=role,
            status=UserStatus.ACTIVE,
        )


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """
    Get current active (non-disabled) user.

    Args:
        current_user: User from get_current_user dependency

    Returns:
        Active User object

    Raises:
        HTTPException: 403 if user is inactive or locked
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive or locked",
        )
    return current_user


async def require_admin_user(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    """
    Require admin role for protected routes.

    Args:
        current_user: Active user from get_current_active_user

    Returns:
        Admin User object

    Raises:
        HTTPException: 403 if user is not admin
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


async def require_mfa_verified(
    current_user: Annotated[User, Depends(get_current_active_user)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(http_bearer)] = None,
) -> User:
    """
    Require MFA verification for protected routes.

    Args:
        current_user: Active user from get_current_active_user
        credentials: JWT credentials to check MFA verification status

    Returns:
        User object if MFA requirements are satisfied

    Raises:
        HTTPException: 403 if MFA required but not verified
    """
    settings = get_settings()

    # Check if MFA is globally enabled
    if not settings.mfa_enabled:
        return current_user

    # Check if MFA is required for user's role
    if current_user.role.value.upper() not in [r.upper() for r in settings.mfa_required_for_roles]:
        return current_user

    # Check if user has MFA enabled
    try:
        from pdfsigner.core.auth.mfa import get_mfa_manager

        mfa_manager = get_mfa_manager()
        mfa_status = mfa_manager.get_status(current_user.id)

        if not mfa_status.enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA is required but not enabled for your account",
                headers={"X-MFA-Required": "true", "X-MFA-Status": "not_enrolled"},
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA check failed, denying access (fail-closed): {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MFA verification service unavailable",
        ) from e

    # Verify token has MFA verification flag
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA verification required",
        )
    token_data = verify_token(credentials.credentials)
    if not token_data.mfa_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA verification required",
            headers={"X-MFA-Required": "true", "X-MFA-Status": "not_verified"},
        )

    return current_user


# --- Combined Authentication ---


async def get_current_user_or_api_key(
    jwt_credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(http_bearer)] = None,
    api_key: Annotated[str | None, Depends(api_key_header_scheme)] = None,
) -> User:
    """
    Authenticate using JWT token OR API key.

    Tries JWT first, then API key. Useful for routes that accept both auth methods.

    Args:
        jwt_credentials: Optional JWT Bearer token
        api_key: Optional API key from X-API-Key header

    Returns:
        Authenticated User object

    Raises:
        HTTPException: 401 if neither auth method succeeds
    """
    # Try JWT first
    if jwt_credentials is not None:
        try:
            return await get_current_user(jwt_credentials)
        except HTTPException:
            logger.warning("JWT auth failed, falling back to API key")

    # Try API key
    if api_key is not None:
        try:
            return await verify_api_key(api_key)
        except HTTPException:
            logger.warning("API key auth failed")

    # Neither auth method worked
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required (JWT token or API key)",
        headers={"WWW-Authenticate": "Bearer"},
    )


# --- Public Exports ---

__all__ = [
    "User",
    "TokenData",
    "create_access_token",
    "verify_token",
    "get_current_user",
    "get_current_active_user",
    "require_admin_user",
    "require_mfa_verified",
    "verify_api_key",
    "get_current_user_or_api_key",
    "http_bearer",
]

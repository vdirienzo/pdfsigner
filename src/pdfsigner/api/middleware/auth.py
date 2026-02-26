"""
Authentication middleware for API.

Provides JWT and API key authentication for FastAPI routes.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from loguru import logger
from pydantic import BaseModel

from pdfsigner.api.config import get_api_settings
from pdfsigner.config.settings import get_settings
from pdfsigner.core.session import get_session_manager
from pdfsigner.core.users.user_model import User, UserRole, UserStatus
from pdfsigner.core.users.user_repository import UserRepository

# Security schemes
http_bearer = HTTPBearer(auto_error=False)
api_key_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


# --- Models ---


class TokenData(BaseModel):
    """JWT token payload data."""

    username: str
    user_id: str | None = None
    role: str = "viewer"
    exp: datetime | None = None
    session_id: str | None = None
    mfa_verified: bool = False  # Whether MFA was verified for this token
    jti: str | None = None  # JWT ID for revocation


# --- JWT Functions ---


def create_access_token(
    data: dict[str, str | datetime | bool],
    expires_delta: timedelta | None = None,
    session_id: str | None = None,
    mfa_verified: bool = False,
) -> str:
    """
    Create JWT access token.

    Args:
        data: Payload data to encode (must include 'sub' for username,
              optionally 'user_id' and 'role')
        expires_delta: Token expiration time (default from settings)
        session_id: Optional session ID to embed in token (for healthcare mode)
        mfa_verified: Whether MFA was verified for this token

    Returns:
        Encoded JWT token string

    Example:
        >>> token = create_access_token({"sub": "user123", "user_id": "uuid", "role": "signer"})
        >>> token = create_access_token({"sub": "admin"}, timedelta(hours=1), mfa_verified=True)
    """
    from pdfsigner.core.auth.jwt_blacklist import generate_jti

    settings = get_api_settings()
    to_encode = data.copy()

    # Add unique JWT ID for revocation support
    to_encode["jti"] = generate_jti()

    # Add session_id to claims if provided
    if session_id:
        to_encode["session_id"] = session_id

    # Add MFA verification status
    to_encode["mfa_verified"] = mfa_verified

    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=settings.jwt_expire_minutes)

    to_encode["exp"] = expire
    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )
    return encoded_jwt


def verify_token(token: str) -> TokenData:
    """
    Verify and decode JWT token.

    Args:
        token: JWT token string to verify

    Returns:
        TokenData with username, user_id, role, expiration, optional session_id, and jti

    Raises:
        HTTPException: 401 if token is invalid, expired, or blacklisted
    """
    from pdfsigner.core.auth.jwt_blacklist import get_jwt_blacklist

    settings = get_api_settings()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
        )
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception

        user_id: str | None = payload.get("user_id")
        role: str = payload.get("role", "viewer")
        exp_timestamp: int | None = payload.get("exp")
        exp = datetime.fromtimestamp(exp_timestamp, tz=UTC) if exp_timestamp else None
        session_id: str | None = payload.get("session_id")
        mfa_verified: bool = payload.get("mfa_verified", False)
        jti: str | None = payload.get("jti")

        # Check if token is blacklisted (revoked)
        if jti:
            blacklist = get_jwt_blacklist()
            if blacklist.is_blacklisted(jti):
                logger.info(f"Rejected blacklisted token {jti[:8]}... for user {username}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        return TokenData(
            username=username,
            user_id=user_id,
            role=role,
            exp=exp,
            session_id=session_id,
            mfa_verified=mfa_verified,
            jti=jti,
        )
    except JWTError as e:
        raise credentials_exception from e


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
        logger.warning(
            f"User '{token_data.username}' authenticated via JWT but not found in repository"
        )
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
            email=f"{token_data.username}@example.com",
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

    Checks if user has MFA enabled and if token includes MFA verification.
    If MFA is required but not verified, returns 403 with mfa_required flag.

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
            # MFA required but not enrolled
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
    if credentials:
        token_data = verify_token(credentials.credentials)
        if not token_data.mfa_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA verification required",
                headers={"X-MFA-Required": "true", "X-MFA-Status": "not_verified"},
            )

    return current_user


# --- API Key Authentication ---


async def verify_api_key(
    api_key: Annotated[str | None, Security(api_key_header_scheme)] = None,
) -> User:
    """
    Verify API key and return associated user.

    Args:
        api_key: API key from X-API-Key header

    Returns:
        User object for API key owner

    Raises:
        HTTPException: 401 if no API key or invalid API key
    """
    settings = get_api_settings()

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Check legacy config-based API keys first (backward compatibility)
    if settings.api_keys and api_key in settings.api_keys:
        # Legacy API key from config - return generic user
        return User(
            id=f"apikey_{api_key[:8]}",
            username=f"apikey_{api_key[:8]}",
            email=None,
            role=UserRole.SIGNER,
            status=UserStatus.ACTIVE,
        )

    # Check database-backed API keys
    try:
        from pdfsigner.core.users.api_key_repository import (
            APIKeyRepository,
            get_api_key_repository,
        )

        api_key_repo = get_api_key_repository()
        key_hash = APIKeyRepository.hash_api_key(api_key)
        api_key_obj = api_key_repo.get_by_hash(key_hash)

        if not api_key_obj:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        # Validate key (check revoked, expiration)
        if not api_key_obj.is_valid:
            logger.warning(
                f"Rejected API key: id={api_key_obj.id}, "
                f"revoked={api_key_obj.revoked}, "
                f"expired={api_key_obj.expires_at}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key is revoked or expired",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        # Update last_used_at timestamp (fire and forget, don't block on failure)
        try:
            api_key_repo.update_last_used(key_hash)
        except Exception as e:
            logger.warning(f"Failed to update last_used_at for API key: {e}")

        # Fetch user associated with API key
        user_repo = UserRepository()
        user = user_repo.get_user_by_id(api_key_obj.user_id)

        if not user:
            logger.error(f"User not found for API key: user_id={api_key_obj.user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found for API key",
            )

        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive or locked",
            )

        logger.debug(f"API key authenticated: user={user.username}, key_id={api_key_obj.id}")
        return user

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API key verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        ) from e


# --- Combined Authentication ---


async def get_current_user_or_api_key(
    jwt_credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(http_bearer)] = None,
    api_key: Annotated[str | None, Security(api_key_header_scheme)] = None,
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
        except HTTPException as e:
            logger.warning(f"JWT auth failed (falling back to API key): {e.detail}")

    # Try API key
    if api_key is not None:
        try:
            return await verify_api_key(api_key)
        except HTTPException as e:
            logger.warning(f"API key auth failed: {e.detail}")

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

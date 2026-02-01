"""
Authentication middleware for API.

Provides JWT and API key authentication for FastAPI routes.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from pdfsigner.api.config import get_api_settings

# Security schemes
http_bearer = HTTPBearer(auto_error=False)
api_key_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


# --- Models ---


class User(BaseModel):
    """User model for authentication."""

    username: str
    email: str | None = None
    role: str = "user"  # "user" or "admin"
    disabled: bool = False


class TokenData(BaseModel):
    """JWT token payload data."""

    username: str
    role: str = "user"
    exp: datetime | None = None


# --- JWT Functions ---


def create_access_token(
    data: dict[str, str | datetime],
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create JWT access token.

    Args:
        data: Payload data to encode (must include 'sub' for username)
        expires_delta: Token expiration time (default from settings)

    Returns:
        Encoded JWT token string

    Example:
        >>> token = create_access_token({"sub": "user123"})
        >>> token = create_access_token({"sub": "admin"}, timedelta(hours=1))
    """
    settings = get_api_settings()
    to_encode = data.copy()

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
        TokenData with username, role, and expiration

    Raises:
        HTTPException: 401 if token is invalid or expired
    """
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

        role: str = payload.get("role", "user")
        exp_timestamp: int | None = payload.get("exp")
        exp = datetime.fromtimestamp(exp_timestamp, tz=UTC) if exp_timestamp else None

        return TokenData(username=username, role=role, exp=exp)
    except JWTError as e:
        raise credentials_exception from e


# --- Authentication Dependencies ---


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(http_bearer)] = None,
) -> User:
    """
    Get current user from JWT token.

    Args:
        credentials: HTTP Bearer token from request header

    Returns:
        Authenticated User object

    Raises:
        HTTPException: 401 if no token or invalid token
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = verify_token(credentials.credentials)

    # In production, fetch user from database
    # For now, create user from token data
    user = User(
        username=token_data.username,
        email=f"{token_data.username}@example.com",
        role=token_data.role,
        disabled=False,
    )

    return user


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
        HTTPException: 400 if user is disabled
    """
    if current_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
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
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
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

    if not settings.api_keys or api_key not in settings.api_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # In production, fetch user associated with API key from database
    # For now, return a generic API user
    return User(
        username=f"apikey_{api_key[:8]}",
        email=None,
        role="user",
        disabled=False,
    )


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
        except HTTPException:
            pass  # Fall through to API key

    # Try API key
    if api_key is not None:
        try:
            return await verify_api_key(api_key)
        except HTTPException:
            pass  # Fall through to error

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
    "verify_api_key",
    "get_current_user_or_api_key",
]

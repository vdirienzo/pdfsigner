"""
Authentication routes.

Provides endpoints for:
- Login (get JWT token)
- Token refresh
- User info
- Logout
"""

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.middleware.auth import (
    User,
    create_access_token,
    get_current_active_user,
    http_bearer,
    verify_token,
)
from pdfsigner.config.settings import get_settings
from pdfsigner.core.auth.password_validator import get_password_validator
from pdfsigner.core.session import get_session_manager
from pdfsigner.core.users.user_repository import get_user_repository

router = APIRouter(prefix="/auth", tags=["authentication"])


# --- Authentication Service ---


def authenticate_user(username: str, password: str) -> User | None:
    """
    Authenticate user with username and password.

    Validates credentials against database and checks user status.
    Implements account lockout after 5 failed attempts (NIST AC-7).

    Args:
        username: Username to authenticate
        password: Password to verify

    Returns:
        User object if authenticated, None otherwise
    """
    if not username or not password:
        return None

    user_repo = get_user_repository()
    password_validator = get_password_validator()

    # Get user from database
    db_user = user_repo.get_user_by_username(username)
    if db_user is None:
        return None

    # Check if user is locked
    if not db_user.is_active:
        return None

    # Get password hash from credentials table
    password_hash = user_repo.get_password_hash(db_user.id)
    if password_hash is None:
        return None

    # Verify password
    if not password_validator.verify_password(password, password_hash):
        # Record failed login attempt
        db_user.record_login(success=False)
        user_repo.update_user(db_user)
        return None

    # Record successful login
    db_user.record_login(success=True)
    user_repo.update_user(db_user)

    return User(
        id=db_user.id,
        username=db_user.username,
        email=db_user.email or "",
        role=db_user.role,
        status=db_user.status,
    )


# --- Request/Response Models ---


class TokenRequest(BaseModel):
    """Login request with username and password."""

    username: str = Field(..., min_length=1, description="Username")
    password: str = Field(..., min_length=1, description="Password")

    model_config = {"json_schema_extra": {"example": {"username": "user", "password": "pass"}}}


class TokenResponse(BaseModel):
    """JWT token response."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")

    model_config = {
        "json_schema_extra": {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
            }
        }
    }


class UserInfoResponse(BaseModel):
    """Current user information."""

    username: str = Field(..., description="Username")
    email: str | None = Field(None, description="Email address")
    role: str = Field(..., description="User role (user or admin)")
    disabled: bool = Field(..., description="Whether user is disabled")

    model_config = {
        "json_schema_extra": {
            "example": {
                "username": "user",
                "email": "user@example.com",
                "role": "user",
                "disabled": False,
            }
        }
    }


class LogoutResponse(BaseModel):
    """Logout response."""

    message: str = Field(..., description="Logout status message")


# --- Routes ---


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Login for JWT token",
    description="""
    Get JWT access token with username and password.

    Validates credentials against user database with Argon2 password hashing.
    Implements account lockout after 5 failed attempts (NIST AC-7).

    When healthcare_mode is enabled, creates a session with sliding window expiration.
    """,
)
async def login_for_access_token(form_data: TokenRequest, request: Request) -> TokenResponse:
    """
    Authenticate and get JWT token.

    Args:
        form_data: Login credentials (username and password)
        request: FastAPI request object (for IP and user agent)

    Returns:
        JWT token with expiration info

    Raises:
        HTTPException: 401 if authentication fails
    """
    user = authenticate_user(form_data.username, form_data.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    settings = get_api_settings()
    app_settings = get_settings()
    session_id = None

    # Create session if healthcare_mode is enabled
    if app_settings.healthcare_mode:
        session_mgr = get_session_manager()
        # Get IP and user agent from request
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        # Security: Invalidate any existing sessions for the user before creating new one
        # This prevents Session Fixation attacks by ensuring a fresh session ID after login
        existing_sessions = session_mgr.get_user_sessions(user.username)
        if existing_sessions:
            for old_session in existing_sessions:
                session_mgr.terminate_session(old_session.id)

        # Create new session with fresh ID
        session = session_mgr.create_session(
            user_id=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        session_id = session.id

    # Create JWT token with optional session_id
    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id, "role": user.role.value},
        expires_delta=timedelta(minutes=settings.jwt_expire_minutes),
        session_id=session_id,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.jwt_expire_minutes * 60,  # Convert to seconds
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh JWT token",
    description="Get a new JWT token using current valid token. Extends session time.",
)
async def refresh_token(
    current_user: Annotated[User, Depends(get_current_active_user)],
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
) -> TokenResponse:
    """
    Refresh JWT token for current user.

    Args:
        current_user: Authenticated user from token
        credentials: Current JWT credentials

    Returns:
        New JWT token with extended expiration
    """
    settings = get_api_settings()

    # Extract session_id from current token if present
    token_data = verify_token(credentials.credentials)
    session_id = token_data.session_id if token_data else None

    access_token = create_access_token(
        data={
            "sub": current_user.username,
            "user_id": current_user.id,
            "role": current_user.role.value,
        },
        expires_delta=timedelta(minutes=settings.jwt_expire_minutes),
        session_id=session_id,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.jwt_expire_minutes * 60,
    )


@router.get(
    "/me",
    response_model=UserInfoResponse,
    summary="Get current user info",
    description="Retrieve information about the currently authenticated user.",
)
async def get_current_user_info(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> UserInfoResponse:
    """
    Get current authenticated user information.

    Args:
        current_user: Authenticated user from token

    Returns:
        User information (username, email, role, status)
    """
    return UserInfoResponse(
        username=current_user.username,
        email=current_user.email,
        role=current_user.role.value,
        disabled=not current_user.is_active,
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Logout",
    description="Revoke JWT token and terminate session. "
    "Token is added to blacklist for real logout. "
    "When healthcare_mode is enabled, also terminates the associated session.",
)
async def logout(
    current_user: Annotated[User, Depends(get_current_active_user)],
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
) -> LogoutResponse:
    """
    Logout and revoke token.

    Adds JWT token to blacklist to prevent further use (real logout).
    When healthcare_mode is enabled, also terminates the session associated with the JWT token.

    Args:
        current_user: Authenticated user from token
        credentials: JWT credentials

    Returns:
        Logout status message
    """
    from pdfsigner.core.auth.jwt_blacklist import get_jwt_blacklist

    settings = get_settings()
    token_data = verify_token(credentials.credentials)

    # Add token to blacklist for real logout
    if token_data.jti and token_data.exp:
        blacklist = get_jwt_blacklist()
        blacklist.add_token(
            jti=token_data.jti,
            expires_at=token_data.exp,
            reason="logout",
        )

    # Also terminate session if healthcare_mode is enabled
    if settings.healthcare_mode and token_data.session_id:
        session_mgr = get_session_manager()
        session_mgr.terminate_session(token_data.session_id)
        return LogoutResponse(
            message="Successfully logged out, token revoked, and session terminated"
        )

    return LogoutResponse(message="Successfully logged out and token revoked")


# --- Public Exports ---

__all__ = ["router"]

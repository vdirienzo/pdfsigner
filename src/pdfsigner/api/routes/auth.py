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
from pdfsigner.core.session import get_session_manager
from pdfsigner.core.users.user_model import UserRole, UserStatus

router = APIRouter(prefix="/auth", tags=["authentication"])


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


# --- Helper Functions ---


def authenticate_user(username: str, password: str) -> User | None:
    """
    Authenticate user with username and password.

    **NOTE:** This is a DEMO implementation that accepts any username/password.
    In production, this MUST:
    - Query user database
    - Verify password hash (bcrypt/argon2)
    - Check user status
    - Return None for invalid credentials

    Args:
        username: Username to authenticate
        password: Password to verify

    Returns:
        User object if authenticated, None otherwise
    """
    # DEMO: Accept any non-empty username/password
    # In production, check against database with proper password hashing
    if not username or not password:
        return None

    # DEMO: Create user with role based on username
    role = UserRole.ADMIN if username == "admin" else UserRole.SIGNER

    return User(
        id=username,
        username=username,
        email=f"{username}@example.com",
        role=role,
        status=UserStatus.ACTIVE,
    )


# --- Routes ---


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Login for JWT token",
    description="""
    Get JWT access token with username and password.

    **DEMO MODE:** Currently accepts any username/password.
    In production, this would validate against a real user database.

    Use 'admin' as username to get admin role, any other username gets user role.

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
    description="Terminate session and invalidate token. "
    "Only has effect when healthcare_mode is enabled.",
)
async def logout(
    current_user: Annotated[User, Depends(get_current_active_user)],
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(http_bearer)],
) -> LogoutResponse:
    """
    Logout and terminate session.

    When healthcare_mode is enabled, terminates the session associated with the JWT token.
    When healthcare_mode is disabled, this is a no-op but returns success.

    Args:
        current_user: Authenticated user from token
        credentials: JWT credentials

    Returns:
        Logout status message
    """
    settings = get_settings()

    if settings.healthcare_mode:
        token_data = verify_token(credentials.credentials)
        if token_data.session_id:
            session_mgr = get_session_manager()
            session_mgr.terminate_session(token_data.session_id)
            return LogoutResponse(message="Successfully logged out and session terminated")
        return LogoutResponse(message="Successfully logged out (no session found)")

    return LogoutResponse(message="Successfully logged out (healthcare mode disabled)")


# --- Public Exports ---

__all__ = ["router"]

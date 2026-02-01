"""
Authentication routes.

Provides endpoints for:
- Login (get JWT token)
- Token refresh
- User info
"""

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from pdfsigner.api.config import get_api_settings
from pdfsigner.api.middleware.auth import (
    User,
    create_access_token,
    get_current_active_user,
)

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
    role = "admin" if username == "admin" else "user"

    return User(
        username=username,
        email=f"{username}@example.com",
        role=role,
        disabled=False,
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
    """,
)
async def login_for_access_token(form_data: TokenRequest) -> TokenResponse:
    """
    Authenticate and get JWT token.

    Args:
        form_data: Login credentials (username and password)

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
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=timedelta(minutes=settings.jwt_expire_minutes),
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
) -> TokenResponse:
    """
    Refresh JWT token for current user.

    Args:
        current_user: Authenticated user from token

    Returns:
        New JWT token with extended expiration
    """
    settings = get_api_settings()
    access_token = create_access_token(
        data={"sub": current_user.username, "role": current_user.role},
        expires_delta=timedelta(minutes=settings.jwt_expire_minutes),
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
        role=current_user.role,
        disabled=current_user.disabled,
    )


# --- Public Exports ---

__all__ = ["router"]

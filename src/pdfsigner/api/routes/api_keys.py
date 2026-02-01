"""
API Key management routes.

Provides endpoints for:
- Create API key (returns plaintext key only once)
- List user's API keys
- Revoke API key
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi import status as http_status
from loguru import logger
from pydantic import BaseModel, Field

from pdfsigner.api.middleware.auth import User, get_current_user_or_api_key
from pdfsigner.core.users.api_key_repository import APIKey, get_api_key_repository

router = APIRouter(prefix="/api/v1/api-keys", tags=["api-keys"])


# --- Schemas ---


class APIKeyCreate(BaseModel):
    """Request schema for creating API key."""

    name: str = Field(..., min_length=1, max_length=100, description="Descriptive name for the key")
    expires_in_days: int | None = Field(
        None,
        ge=1,
        le=365,
        description="Expiration in days (1-365). None = never expires",
    )


class APIKeyResponse(BaseModel):
    """Response schema for API key (without plaintext key)."""

    id: str
    name: str
    created_at: str
    last_used_at: str | None
    expires_at: str | None
    revoked: bool


class APIKeyCreateResponse(BaseModel):
    """Response schema for creating API key (includes plaintext key ONCE)."""

    id: str
    name: str
    api_key: str = Field(..., description="Plaintext API key - save this, it won't be shown again")
    created_at: str
    expires_at: str | None


class APIKeyListResponse(BaseModel):
    """Response schema for listing API keys."""

    api_keys: list[APIKeyResponse]
    total: int


# --- Helper Functions ---


def _api_key_to_response(api_key: APIKey) -> APIKeyResponse:
    """
    Convert APIKey model to APIKeyResponse schema.

    Args:
        api_key: APIKey domain model

    Returns:
        APIKeyResponse schema for API response
    """
    return APIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        created_at=api_key.created_at.isoformat(),
        last_used_at=api_key.last_used_at.isoformat() if api_key.last_used_at else None,
        expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
        revoked=api_key.revoked,
    )


# --- Routes ---


@router.post(
    "/",
    response_model=APIKeyCreateResponse,
    status_code=http_status.HTTP_201_CREATED,
    summary="Create API key",
    description="""
    Create a new API key for the authenticated user.

    **Important:** The plaintext API key is returned ONLY ONCE.
    Store it securely - it cannot be retrieved again.

    **Authentication:** JWT Bearer token required (API keys cannot create API keys)

    **Example:**
    ```json
    {
        "name": "CI/CD Pipeline",
        "expires_in_days": 90
    }
    ```
    """,
)
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> APIKeyCreateResponse:
    """
    Create new API key for current user.

    Args:
        key_data: API key creation data (name, expiration)
        current_user: Authenticated user

    Returns:
        Created API key with plaintext key (shown only once)

    Raises:
        HTTPException: 500 if key creation fails
    """
    api_key_repo = get_api_key_repository()

    try:
        api_key, plaintext_key = api_key_repo.create_api_key(
            user_id=current_user.id,
            name=key_data.name,
            expires_in_days=key_data.expires_in_days,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    logger.info(
        f"API key created: '{key_data.name}' for user {current_user.username} (id={api_key.id})"
    )

    return APIKeyCreateResponse(
        id=api_key.id,
        name=api_key.name,
        api_key=plaintext_key,
        created_at=api_key.created_at.isoformat(),
        expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
    )


@router.get(
    "/",
    response_model=APIKeyListResponse,
    summary="List API keys",
    description="""
    List all API keys for the authenticated user.

    Returns both active and revoked keys.
    """,
)
async def list_api_keys(
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> APIKeyListResponse:
    """
    List all API keys for current user.

    Args:
        current_user: Authenticated user

    Returns:
        List of user's API keys
    """
    api_key_repo = get_api_key_repository()
    keys = api_key_repo.list_for_user(current_user.id, include_revoked=True)

    logger.debug(f"Listed {len(keys)} API keys for user {current_user.username}")

    return APIKeyListResponse(
        api_keys=[_api_key_to_response(k) for k in keys],
        total=len(keys),
    )


@router.delete(
    "/{key_id}",
    response_model=dict,
    summary="Revoke API key",
    description="""
    Revoke an API key.

    Revoked keys cannot be used for authentication.
    Users can only revoke their own API keys.
    """,
)
async def revoke_api_key(
    key_id: str,
    current_user: Annotated[User, Depends(get_current_user_or_api_key)],
) -> dict:
    """
    Revoke API key.

    Args:
        key_id: API key ID to revoke
        current_user: Authenticated user

    Returns:
        Success message

    Raises:
        HTTPException: 404 if key not found or not owned by user
    """
    api_key_repo = get_api_key_repository()

    # Verify key exists and belongs to user
    api_key = api_key_repo.get_by_id(key_id)
    if not api_key:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"API key not found: {key_id}",
        )

    if api_key.user_id != current_user.id:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"API key not found: {key_id}",  # Don't leak existence
        )

    # Revoke
    success = api_key_repo.revoke(key_id, current_user.id)

    if not success:
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke API key",
        )

    logger.info(f"API key revoked: '{api_key.name}' (id={key_id}) by {current_user.username}")

    return {
        "message": f"API key '{api_key.name}' revoked successfully",
        "key_id": key_id,
    }


# --- Public Exports ---

__all__ = ["router"]

"""
api_key_auth.py - API key authentication

Handles verification of API keys (both legacy config-based and database-backed).
"""

import hashlib
import hmac
from typing import Annotated

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from loguru import logger

from pdfsigner.api.config import get_api_settings
from pdfsigner.core.users.user_model import User, UserRole, UserStatus
from pdfsigner.core.users.user_repository import UserRepository

# Security scheme
api_key_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


def _hash_api_key_id(api_key: str) -> str:
    """Generate a safe, non-reversible identifier from an API key."""
    return f"apikey_{hashlib.sha256(api_key.encode()).hexdigest()[:12]}"


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
    if settings.api_keys and any(
        hmac.compare_digest(api_key, valid_key) for valid_key in settings.api_keys
    ):
        _api_key_id = _hash_api_key_id(api_key)
        return User(
            id=_api_key_id,
            username=_api_key_id,
            email="",
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
            logger.warning("Rejected API key: revoked or expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key is revoked or expired",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        # Update last_used_at timestamp (fire and forget)
        try:
            api_key_repo.update_last_used(key_hash)
        except Exception as e:
            logger.warning(f"Failed to update last_used_at for API key: {e}")

        # Fetch user associated with API key
        user_repo = UserRepository()
        user = user_repo.get_user_by_id(api_key_obj.user_id)

        if not user:
            logger.error("User not found for API key")
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

        logger.debug("API key authentication successful")
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

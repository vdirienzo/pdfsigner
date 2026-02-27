"""
token_service.py - JWT token creation and verification

Handles JWT token lifecycle: creation, verification, and blacklist checking.
"""

from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from jose import JWTError, jwt
from loguru import logger
from pydantic import BaseModel

from pdfsigner.api.config import get_api_settings


class TokenData(BaseModel):
    """JWT token payload data."""

    username: str
    user_id: str | None = None
    role: str = "viewer"
    exp: datetime | None = None
    session_id: str | None = None
    mfa_verified: bool = False  # Whether MFA was verified for this token
    jti: str | None = None  # JWT ID for revocation


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
    """
    from pdfsigner.core.auth.jwt_blacklist import generate_jti

    settings = get_api_settings()
    if not settings.jwt_secret_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT secret key not configured",
        )
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
    if not settings.jwt_secret_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT secret key not configured",
        )
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
        if not jti:
            raise credentials_exception  # Reject tokens without JTI
        blacklist = get_jwt_blacklist()
        if blacklist.is_blacklisted(jti):
            logger.debug("Rejected blacklisted token for user")
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

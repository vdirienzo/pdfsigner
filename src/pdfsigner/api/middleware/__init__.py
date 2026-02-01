"""
API middleware components.

This package contains custom middleware for:
- Rate limiting
- Request logging
- Authentication
- Error handling
"""

from pdfsigner.api.middleware.auth import (
    TokenData,
    User,
    create_access_token,
    get_current_active_user,
    get_current_user,
    get_current_user_or_api_key,
    require_admin_user,
    verify_api_key,
    verify_token,
)

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

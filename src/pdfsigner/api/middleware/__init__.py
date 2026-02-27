"""
API middleware components.

This package contains custom middleware for:
- Rate limiting
- Request logging
- Authentication
- Error handling
"""

from pdfsigner.api.middleware.api_key_auth import verify_api_key
from pdfsigner.api.middleware.auth import (
    get_current_active_user,
    get_current_user,
    get_current_user_or_api_key,
    require_admin_user,
)
from pdfsigner.api.middleware.token_service import (
    TokenData,
    create_access_token,
    verify_token,
)
from pdfsigner.core.users.user_model import User

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

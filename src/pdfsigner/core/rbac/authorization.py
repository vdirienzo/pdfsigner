"""
authorization.py - Authorization service and decorators

Provides permission checking logic and FastAPI integration for RBAC.
HIPAA: §164.308(a)(4)(ii)(B) - Access authorization
"""

from collections.abc import Callable
from functools import wraps

from fastapi import Depends, HTTPException, status
from loguru import logger

from pdfsigner.config.settings import get_settings
from pdfsigner.core.rbac.permissions import ROLE_PERMISSIONS, Permission
from pdfsigner.core.users.user_model import User
from pdfsigner.exceptions import PermissionDeniedError


class AuthorizationService:
    """
    Service for checking user permissions.

    Enforces role-based access control (RBAC) when healthcare_mode is enabled.
    When healthcare_mode is disabled, all permission checks pass through.
    """

    def __init__(self) -> None:
        """Initialize authorization service."""
        self._settings = get_settings()

    def has_permission(self, user: User, permission: Permission) -> bool:
        """
        Check if user has a specific permission.

        Args:
            user: User to check permissions for
            permission: Permission to check

        Returns:
            True if user has permission or healthcare_mode is disabled
        """
        # If healthcare mode is disabled, allow all operations
        if not self._settings.healthcare_mode:
            logger.debug(
                f"Permission check bypassed (healthcare_mode=False): "
                f"user={user.username}, permission={permission.value}"
            )
            return True

        # Check if user's role grants the permission
        allowed_permissions = ROLE_PERMISSIONS.get(user.role, set())
        has_perm = permission in allowed_permissions

        logger.debug(
            f"Permission check: user={user.username}, role={user.role.value}, "
            f"permission={permission.value}, granted={has_perm}"
        )

        return has_perm

    def require_permissions(self, user: User, *permissions: Permission) -> None:
        """
        Require user to have all specified permissions.

        Args:
            user: User to check permissions for
            permissions: One or more permissions required

        Raises:
            PermissionDeniedError: If user lacks any required permission
        """
        # If healthcare mode is disabled, allow all operations
        if not self._settings.healthcare_mode:
            return

        # Check all required permissions
        missing_permissions = [perm for perm in permissions if not self.has_permission(user, perm)]

        if missing_permissions:
            perm_names = ", ".join(p.value for p in missing_permissions)
            logger.warning(
                f"Permission denied: user={user.username}, role={user.role.value}, "
                f"missing={perm_names}"
            )
            raise PermissionDeniedError(
                f"User '{user.username}' lacks required permissions: {perm_names}"
            )

    def get_user_permissions(self, user: User) -> set[Permission]:
        """
        Get all permissions granted to a user.

        Args:
            user: User to get permissions for

        Returns:
            Set of permissions granted to the user
        """
        # If healthcare mode is disabled, return all permissions
        if not self._settings.healthcare_mode:
            return set(Permission)

        return ROLE_PERMISSIONS.get(user.role, set())


# Singleton instance
_authorization_service: AuthorizationService | None = None


def get_authorization_service() -> AuthorizationService:
    """
    Get authorization service singleton.

    Returns:
        AuthorizationService instance
    """
    global _authorization_service
    if _authorization_service is None:
        _authorization_service = AuthorizationService()
    return _authorization_service


# --- FastAPI Dependencies and Decorators ---


def _get_current_user_dynamic() -> Callable:
    """
    Dynamically import get_current_user_or_api_key to avoid circular imports.

    Returns:
        The get_current_user_or_api_key function from api.middleware.auth
    """
    from pdfsigner.api.middleware.auth import get_current_user_or_api_key

    return get_current_user_or_api_key


def check_permission(permission: Permission) -> Callable:
    """
    FastAPI dependency for checking a single permission.

    This dependency automatically obtains the current user and checks permissions.
    Uses dynamic import to avoid circular dependencies with api.middleware.auth.

    Usage:
        @router.get("/documents")
        async def list_documents(
            current_user: Annotated[User, Depends(get_current_user_or_api_key)],
            _perm: Annotated[None, Depends(check_permission(Permission.VIEW))]
        ):
            ...

    Args:
        permission: Permission to check

    Returns:
        Dependency function for FastAPI
    """

    async def check_perm(
        current_user: User = Depends(_get_current_user_dynamic()),
    ) -> None:
        """Check permission for current user."""
        auth_service = get_authorization_service()
        if not auth_service.has_permission(current_user, permission):
            logger.warning(
                f"API permission denied: user={current_user.username}, "
                f"permission={permission.value}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value} required",
            )

    return check_perm


def require_permission(*permissions: Permission) -> Callable:
    """
    Decorator for FastAPI endpoints requiring specific permissions.

    Usage:
        @router.post("/sign")
        @require_permission(Permission.SIGN)
        async def sign_document(user: Annotated[User, Depends(get_current_user)]):
            ...

    Args:
        permissions: One or more required permissions

    Returns:
        Decorator function
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user from kwargs (injected by Depends)
            user = kwargs.get("user") or kwargs.get("current_user")
            if user is None:
                # Try to find user in args (less common pattern)
                for arg in args:
                    if isinstance(arg, User):
                        user = arg
                        break

            if user is None:
                logger.error("require_permission decorator: no User found in arguments")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            # Check permissions
            auth_service = get_authorization_service()
            try:
                auth_service.require_permissions(user, *permissions)
            except PermissionDeniedError as e:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=str(e),
                ) from e

            return await func(*args, **kwargs)

        return wrapper

    return decorator

"""
RBAC module for healthcare compliance.

Provides role-based access control (RBAC) for PDFSigner when healthcare_mode
is enabled. When healthcare_mode is disabled, all permission checks pass through.

HIPAA Compliance:
    - §164.308(a)(4) - Information access management
    - §164.308(a)(4)(ii)(B) - Access authorization

Usage:
    from pdfsigner.core.rbac import (
        Permission,
        ROLE_PERMISSIONS,
        AuthorizationService,
        get_authorization_service,
        require_permission,
        check_permission,
    )

    # Check permissions programmatically
    auth_service = get_authorization_service()
    if auth_service.has_permission(user, Permission.SIGN):
        # Allow signing
        pass

    # Use in FastAPI endpoints
    @router.post("/sign")
    @require_permission(Permission.SIGN)
    async def sign_document(user: Annotated[User, Depends(get_current_user)]):
        ...
"""

from pdfsigner.core.rbac.authorization import (
    AuthorizationService,
    check_permission,
    get_authorization_service,
    require_permission,
)
from pdfsigner.core.rbac.permissions import ROLE_PERMISSIONS, Permission

__all__ = [
    "Permission",
    "ROLE_PERMISSIONS",
    "AuthorizationService",
    "get_authorization_service",
    "require_permission",
    "check_permission",
]

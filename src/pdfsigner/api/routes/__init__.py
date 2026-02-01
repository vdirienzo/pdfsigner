"""
API route handlers.

This package contains FastAPI routers for:
- /auth - Authentication endpoints
- /certificates - Certificate management endpoints
- /sign - PDF signing endpoints
- /validate - PDF validation endpoints
- /tokens - Token management endpoints
- /templates - Signature template endpoints
"""

from pdfsigner.api.routes.auth import router as auth_router
from pdfsigner.api.routes.certificates import router as certificates_router
from pdfsigner.api.routes.sign import router as sign_router
from pdfsigner.api.routes.validate import router as validate_router

__all__ = ["auth_router", "certificates_router", "sign_router", "validate_router"]
